<#
.SYNOPSIS
    Tells the story of one evidence-pack run in plain English: how many
    records were collected and fingerprinted, that they are in the locked
    evidence store and for how long, and where to see them. The technical
    details sit folded underneath.

.DESCRIPTION
    The last step of .github/workflows/evidence-pack.yml. Its audience is
    someone who is not an identity engineer: the top of the summary reads

        ## Evidence pack filed (em dash) 7 records, each fingerprinted
        | Record | What it shows | Entries | ...
        Stored in the locked evidence store: nobody can change or delete
        these files for 2190 days.
        [Open the evidence store in the Azure portal](...)

    INPUTS
      -ManifestPath       Export-EvidencePack.ps1's manifest.json (what was
                          collected, each file's SHA-256 and entry count).
                          Missing = the export never finished.
      -PublishResultPath  Publish-EvidencePack.ps1 -ResultPath (what was
                          stored, read back, and the store's retention lock).
                          Missing = the upload never started.

    A file that was stored but whose read-back never finished (time-out,
    expired sign-in) is "could not be checked", never "filed": Publish fails
    the run (outcome failed, kind read-back) and the summary says the files
    are in the store but unconfirmed.

    "N days" comes from the store itself: the earliest retention expiry the
    store reported on the uploaded files. When the lock is still Unlocked the
    summary says so in one plain sentence; when the store reported none, it
    says the lock could not be confirmed (never a guessed number).

    PRIVACY
      Counts only. Never a name, UPN, object id, error text from Microsoft
      (it can quote a user) or a token. The MFA line is the aggregate
      "38 of 40 accounts (95%)" from the export's own summary row.

    EXIT CODE
      0 (the steps before it carry the run's result).

.EXAMPLE
    ./Write-EvidencePackSummary.ps1 -ManifestPath ./pack/manifest.json -PublishResultPath ./published.json -SummaryPath ./summary.md
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ManifestPath = '',

    [Parameter()]
    [string]$PublishResultPath = '',

    [Parameter()]
    [string]$SummaryPath = $env:GITHUB_STEP_SUMMARY,

    # The azure/login step's outcome (success / failure / skipped).
    [Parameter()]
    [string]$SignInOutcome = '',

    # Repository variables the one-time setup has not set yet (comma separated).
    [Parameter()]
    [string]$MissingSetup = '',

    # Set when the run was refused before signing in: not-main.
    [Parameter()]
    [ValidateSet('', 'not-main')]
    [string]$Refused = '',

    # One-line context for the details block, e.g. "manual run on main (abc1234), run 123".
    [Parameter()]
    [string]$TriggerText = '',

    # For the Azure portal link to the store (identifiers, not secrets).
    [Parameter()]
    [string]$TenantId = '',

    [Parameter()]
    [string]$SubscriptionId = '',

    [Parameter()]
    [string]$ResourceGroupName = 'rg-identity-lab',

    # "Now" for the days-left arithmetic (tests).
    [Parameter()]
    [datetime]$Now = [datetime]::UtcNow
)

# Operator console output. Write-Host on purpose; every script-level line
# goes through here, so the analyzer suppression is scoped to this function.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The summary's typography, built from code points so this file stays ASCII.
$Dash = [string][char]0x2014

# =============================================================================
# PURE HELPERS (tests/EvidencePackPipeline.Tests.ps1)
# =============================================================================
function Get-EvidenceRecordInfo {
    # The seven collected records, in pack order, with a plain name and what
    # each one shows (Export-EvidencePack.ps1 artifacts 1-7).
    @(
        [pscustomobject]@{ File = 'pim_activation_history.json'; Name = 'Admin rights switched on'; Shows = 'every time someone turned on admin rights for a short time (just-in-time), with the reason they gave' }
        [pscustomobject]@{ File = 'pim_active_assignments.json'; Name = 'Admin rights live now'; Shows = 'who holds admin rights at this moment, standing or time-limited' }
        [pscustomobject]@{ File = 'pim_activation_activities.json'; Name = 'Audit trail of those switches'; Shows = 'Microsoft''s own log entries behind each admin switch' }
        [pscustomobject]@{ File = 'access_review_decisions.json'; Name = 'Access review decisions'; Shows = 'keep-or-remove decisions on who still needs access' }
        [pscustomobject]@{ File = 'conditional_access_policies.json'; Name = 'Sign-in rules'; Shows = 'every sign-in rule (Conditional Access), whether it is on, and that the emergency accounts are left out' }
        [pscustomobject]@{ File = 'mfa_registration_coverage.json'; Name = 'Multi-factor sign-in set up'; Shows = 'how many accounts have set up a second sign-in step' }
        [pscustomobject]@{ File = 'privileged_role_assignments.json'; Name = 'Everyone with a powerful role'; Shows = 'every holder of a privileged admin role, emergency accounts marked' }
    )
}

function Get-CollectFailureText {
    # A failed artifact's error -> a short plain reason (never the raw text:
    # it can quote a user or a group).
    param([AllowEmptyString()][string]$ErrorText = '')
    if ($ErrorText -match '\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges') { return 'not collected: the EVIDENCE identity is missing a read permission' }
    if ($ErrorText -match '(?i)licen[cs]e|premium|AadPremium|P2') { return 'not collected: needs an Entra licence the tenant does not have' }
    if ($ErrorText -match 'isPrivileged|privileged-role') { return 'not collected: the list of privileged roles could not be read' }
    return 'not collected (see the export step''s log)'
}

function Get-RetentionInfo {
    # Uploaded files -> the store's retention lock in plain words. Days =
    # whole days until the EARLIEST reported expiry; Mode = Locked /
    # Unlocked as the store reported it ('' = not reported).
    param([AllowEmptyCollection()][object[]]$Files = @(), [Parameter(Mandatory)][datetime]$Now)
    $up = @($Files | Where-Object { $_ -and $_['uploaded'] })
    $exp = @($up | Where-Object { $_['immutabilityExpiry'] } | ForEach-Object {
            $v = $_['immutabilityExpiry']
            if ($v -is [datetime]) { $v.ToUniversalTime() } else { [datetime]::Parse([string]$v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
        } | Sort-Object)
    $modes = @($up | Where-Object { $_['policyMode'] } | ForEach-Object { ([string]$_['policyMode']).ToLowerInvariant() } | Sort-Object -Unique)
    $mode = if ($modes -contains 'unlocked') { 'Unlocked' } elseif ($modes -contains 'locked') { 'Locked' } else { '' }
    if (-not $exp -or $exp.Count -lt $up.Count) { return [pscustomobject]@{ Days = $null; Until = $null; Mode = $mode; Reported = $exp.Count; Uploaded = $up.Count } }
    $first = $exp[0]
    $days = [int][math]::Round(($first - $Now.ToUniversalTime()).TotalDays)
    return [pscustomobject]@{ Days = $days; Until = $first; Mode = $mode; Reported = $exp.Count; Uploaded = $up.Count }
}

function Test-ReadBackUnchecked {
    # One Publish-EvidencePack.ps1 file row -> stored, but the read-back that
    # compares it with its fingerprint never finished ('read-back failed: ...'
    # in error). Not a mismatch ('read-back: the stored copy ...'), and not
    # -SkipReadBack (no error at all). The error text itself is never printed.
    param($File)
    return [bool]($File -and $File['uploaded'] -and -not $File['verified'] -and ([string]$File['error']) -like 'read-back failed*')
}

function Get-StoreLink {
    # The evidence account's Containers page in the Azure portal (the viewer
    # then opens the container and the run's folder). Generic storage list
    # when the subscription is not known.
    param([string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroupName, [string]$Account)
    if ($SubscriptionId -and $ResourceGroupName -and $Account) {
        $t = if ($TenantId) { "@$TenantId" } else { '' }
        return "https://portal.azure.com/#$t/resource/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$Account/containersList"
    }
    return 'https://portal.azure.com/#browse/Microsoft.Storage%2FStorageAccounts'
}

function Get-Field {
    # Key from a hashtable (ConvertFrom-Json -AsHashtable), $null-safe under StrictMode.
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($p in $Path) {
        if ($cur -isnot [System.Collections.IDictionary] -or -not $cur.Contains($p)) { return $null }
        $cur = $cur[$p]
    }
    return $cur
}

# =============================================================================
# 1. LOAD
# =============================================================================
$manifest = if ($ManifestPath -and (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -AsHashtable } else { $null }
$result = if ($PublishResultPath -and (Test-Path -LiteralPath $PublishResultPath -PathType Leaf)) { Get-Content -LiteralPath $PublishResultPath -Raw | ConvertFrom-Json -AsHashtable } else { $null }
$outcome = [string](Get-Field $result 'outcome')
$refusal = [string](Get-Field $result 'refusal', 'kind')
$pubFiles = @(@(Get-Field $result 'files') | Where-Object { $_ })
$account = [string](Get-Field $result 'account')
$container = [string](Get-Field $result 'container')
$prefix = [string](Get-Field $result 'prefix')
$unchecked = @($pubFiles | Where-Object { Test-ReadBackUnchecked $_ }).Count

$records = @(Get-EvidenceRecordInfo)
$artifacts = @(@(Get-Field $manifest 'artifacts') | Where-Object { $_ })
$byFile = @{}; foreach ($a in $artifacts) { if (-not (Get-Field $a 'source')) { $byFile[[string]$a['file']] = $a } }
$present = @($records | Where-Object { $byFile.ContainsKey($_.File) })
$collected = @($present | Where-Object { [string]$byFile[$_.File]['status'] -eq 'ok' })

function Get-EntriesText {
    # The "Entries" cell: a count, the MFA aggregate, or why it is missing.
    param([Parameter(Mandatory)]$Record)
    $a = $byFile[$Record.File]
    if ([string]$a['status'] -ne 'ok') { return (Get-CollectFailureText ([string](Get-Field $a 'error'))) }
    if ($Record.File -eq 'mfa_registration_coverage.json' -and $ManifestPath) {
        $p = Join-Path (Split-Path -Parent $ManifestPath) $Record.File
        try {
            $s = @(Get-Content -LiteralPath $p -Raw | ConvertFrom-Json -AsHashtable) | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('_summary') } | Select-Object -First 1
            if ($s) { return ('{0} of {1} accounts ({2}%)' -f $s['mfaRegistered'], $s['totalUsers'], $s['coveragePercent']) }
        }
        catch { Write-Verbose "MFA summary row not readable: $($_.Exception.Message)" }
    }
    $n = Get-Field $a 'recordCount'
    return $(if ($null -ne $n) { [string]$n } else { '-' })
}

# =============================================================================
# 2. THE STORY
# =============================================================================
$md = [System.Collections.Generic.List[string]]::new()
$link = Get-StoreLink -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -Account $account
$filedLike = $outcome -in 'filed', 'partial'

if ($Refused -eq 'not-main') {
    $md.Add('## Evidence pack not filed: it is filed from main only')
    $md.Add(''); $md.Add('Evidence comes from reviewed code only, so this workflow runs on the `main` branch (the EVIDENCE sign-in trusts nothing else). Run it again and pick `main`. Nothing was collected or stored.')
}
elseif ($MissingSetup) {
    $md.Add('## Evidence pack not filed: the one-time setup is not finished')
    $md.Add(''); $md.Add("GitHub does not know who to sign in as or where to file the pack yet. Missing repository variable(s): **$MissingSetup** (Settings > Secrets and variables > Actions > Variables). The steps are in ``lab/evidence/README.md``, ""Evidence pack from GitHub Actions"". Nothing was collected or stored.")
}
elseif ($SignInOutcome -eq 'failure') {
    $md.Add('## Evidence pack not filed: GitHub could not sign in to Microsoft')
    $md.Add(''); $md.Add('The sign-in as EVIDENCE (GitHub OIDC, no password) was refused, so nothing was collected. Its one-time setup is in `lab/evidence/README.md`, "Evidence pack from GitHub Actions". Re-running is safe once it is done.')
}
elseif (-not $manifest) {
    $md.Add('## Evidence pack not filed: the export from Microsoft Entra stopped')
    $md.Add(''); $md.Add('The step that collects the records stopped before it wrote its fingerprint list (see its log). Nothing was stored. Re-running is safe.')
}
elseif (-not $result -and $present -and -not $collected) {
    $md.Add('## Evidence pack not filed: no record could be collected')
    $md.Add(''); $md.Add("EVIDENCE could not read any of the $($present.Count) records from Microsoft Entra, most likely because its read permissions are not granted (admin consent) yet. Nothing was stored. Re-running is safe once that is fixed.")
}
elseif (-not $result) {
    $md.Add("## Evidence pack collected but not filed $Dash $($present.Count) records fingerprinted")
    $md.Add(''); $md.Add('The records were collected, but the upload to the locked evidence store never started (see the steps above). They were not kept anywhere else: the runner is wiped when the job ends. Re-running is safe.')
}
elseif ($outcome -eq 'refused' -or $outcome -eq 'invalid' -or $outcome -eq 'failed') {
    $md.Add($(switch ($refusal) {
                'network' { '## Evidence pack not filed: the evidence store refused the connection' }
                'permission' { '## Evidence pack not filed: the evidence store refused the upload' }
                'sign-in' { '## Evidence pack not filed: no sign-in for the evidence store' }
                'exists' { '## Evidence pack not filed: these file names are already in the store' }
                'not-found' { '## Evidence pack not filed: the evidence store was not found' }
                'fingerprint-mismatch' { '## Evidence pack not filed: a file changed after it was fingerprinted' }
                'read-back' { '## Evidence pack not filed: the stored files could not be checked' }
                default { '## Evidence pack not filed' }
            }))
    $md.Add('')
    $md.Add($(switch ($refusal) {
                'network' { 'Its firewall only lets in the lab operator''s network, and the GitHub computer that ran this is outside it. The records were collected and fingerprinted but not stored, and not kept anywhere else. Run it from an allowed network (see "Evidence pack from GitHub Actions" in `lab/evidence/README.md`).' }
                'permission' { 'EVIDENCE is not allowed to add files to the evidence container yet (its one-time grant), or the store refused a write it is never allowed to make. Nothing was stored.' }
                'sign-in' { 'The Azure sign-in had expired or was missing when the upload started. Nothing was stored; re-running is safe.' }
                'exists' { 'The store already holds files with these names, and it never replaces a file. Nothing was overwritten; run the workflow again to file a new copy under a new folder.' }
                'not-found' { 'The storage account or its evidence container does not exist under the configured name (`TF_EVIDENCE_STORAGE_ACCOUNT_NAME`). Nothing was stored.' }
                'fingerprint-mismatch' { 'Before upload, every file is checked against the fingerprint list, and one did not match. Nothing was stored. Re-run the workflow to collect a fresh pack.' }
                'read-back' { "All $($pubFiles.Count) files were uploaded to the locked evidence store, but $unchecked of them could not be downloaded again to check them against their fingerprints (most often a time-out or a sign-in that expired during the run). A file nobody has checked does not count as filed. What was stored stays and cannot be changed or removed; re-run the workflow to file a checked copy in a new folder." }
                default { 'The upload did not complete (see the upload step''s log). Nothing that was stored can be changed or removed; re-running files a new copy.' }
            }))
}
elseif ($outcome -eq 'dry-run') {
    $md.Add("## Evidence pack preview (dry run: nothing was stored) $Dash $($present.Count) records fingerprinted")
}
elseif ($filedLike) {
    $headCount = if ($collected.Count -eq $present.Count) { "$($present.Count) records, each fingerprinted" } else { "$($collected.Count) of $($present.Count) records collected, each fingerprinted" }
    $md.Add($(if ($outcome -eq 'filed') { "## Evidence pack filed $Dash $headCount" } else { "## Evidence pack partly filed $Dash $headCount" }))
    $md.Add('')
    $md.Add("These records were read from Microsoft Entra just now (read-only). Each file got a fingerprint (a SHA-256 hash), so changing even one character would show.")
}

if ($manifest -and $present -and ($filedLike -or $outcome -eq 'dry-run')) {
    $md.Add('')
    $md.Add('| Record | What it shows | Entries |')
    $md.Add('|---|---|---|')
    foreach ($r in $present) { $md.Add("| $($r.Name) | $($r.Shows) | $(Get-EntriesText $r) |") }
}

if ($filedLike) {
    $ret = Get-RetentionInfo -Files $pubFiles -Now $Now
    $stored = @($pubFiles | Where-Object { $_['uploaded'] }).Count
    $md.Add('')
    if ($null -ne $ret.Days) {
        $md.Add("Stored in the locked evidence store: nobody can change or delete these files for $($ret.Days) days.")
        if ($ret.Mode -eq 'Unlocked') { $md.Add(''); $md.Add('_The lock is still in its trial setting: an Azure administrator could shorten it. The lab makes it permanent in a separate, reviewed change._') }
    }
    else {
        $md.Add('Stored in the evidence store as new files that cannot be replaced. The store did not report its retention lock for them, so check it before relying on it.')
    }
    if ($outcome -eq 'partial') { $md.Add(''); $md.Add("**$stored of $($pubFiles.Count) files were stored.** The rest were refused (details below); what was stored stays. Re-run the workflow to file a complete copy.") }
    if ($unchecked) { $md.Add(''); $md.Add("**$unchecked of the stored files could not be checked:** reading them back to compare with their fingerprints did not finish. They stay in the store, unchanged, but are not confirmed.") }
    $md.Add('')
    $md.Add("[Open the evidence store in the Azure portal]($link), then the **$container** container and the folder **$($prefix.TrimEnd('/'))**.")
}

# Technical details, folded.
$md.Add('')
$md.Add('<details><summary>Technical details</summary>')
$md.Add('')
if ($TriggerText) { $md.Add("- **Trigger:** $TriggerText") }
if ($Refused -or $MissingSetup) { $md.Add('- **Sign-in:** not attempted') }
else { $md.Add("- **Signed in as:** EVIDENCE over GitHub OIDC, no stored secret; Microsoft Graph application permissions, read-only (sign-in: $(if ($SignInOutcome) { $SignInOutcome } else { 'not attempted' }))") }
if ($manifest) {
    $comp = @($artifacts | Where-Object { [string](Get-Field $_ 'source') -eq 'companion' })
    # generatedBy names the pipeline run; a delegated (laptop) pack names a
    # person's UPN, which this summary never prints.
    $by = [string](Get-Field $manifest 'evidencePack', 'generatedBy')
    if ($by -match '@') { $by = 'a signed-in administrator (delegated)' }
    $when = Get-Field $manifest 'evidencePack', 'generatedUtc'
    $when = if ($when -is [datetime]) { $when.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$when }
    $md.Add("- **Collected:** $($collected.Count) of $($present.Count) records; manifest generated $when$(if ($by) { " by $by" })")
    $md.Add("- **Companion evidence from the repository:** $(@($comp | Where-Object { $_['status'] -eq 'ok' }).Count) file(s) hashed into the manifest; $(@($comp | Where-Object { $_['status'] -eq 'absent' }).Count) kind(s) not captured yet")
}
if ($result) {
    $verified = @($pubFiles | Where-Object { $_['verified'] }).Count
    $md.Add("- **Store:** ``$account`` / ``$container`` / ``$prefix`` $Dash $(@($pubFiles | Where-Object { $_['uploaded'] }).Count) of $($pubFiles.Count) file(s) uploaded as new blobs (overwrite refused), $verified read back and matched$(if ($unchecked) { ", $unchecked could not be checked" }) (outcome ``$outcome``$(if ($refusal) { ", $refusal" }))")
    if ($filedLike) {
        $ret = Get-RetentionInfo -Files $pubFiles -Now $Now
        $md.Add("- **Retention lock (as the store reported it):** $(if ($ret.Until) { "until $($ret.Until.ToString('yyyy-MM-dd')) (earliest of $($ret.Reported) file(s))" } else { "reported for $($ret.Reported) of $($ret.Uploaded) file(s)" }), policy mode $(if ($ret.Mode) { $ret.Mode } else { 'not reported' })")
    }
    $md.Add('- **Fingerprints (SHA-256):**')
    foreach ($f in $pubFiles) {
        $state = if ($f['verified']) { 'stored, read back' } elseif (Test-ReadBackUnchecked $f) { 'stored, could not be checked' } elseif ($f['uploaded']) { 'stored' } else { 'not stored' }
        $md.Add("  - ``$($f['file'])`` ``$($f['sha256'])`` ($state)")
    }
}
elseif ($manifest) {
    $md.Add('- **Fingerprints (SHA-256):**')
    foreach ($r in $present) { $md.Add("  - ``$($r.File)`` ``$(([string]$byFile[$r.File]['sha256']).ToLowerInvariant())``") }
}
$md.Add('- **Path:** Microsoft Entra (Graph, read-only) -> GitHub runner (memory and temp folder only, wiped after the job) -> WORM evidence container (new files only)')
$md.Add('')
$md.Add('</details>')

$text = ($md -join "`n") + "`n"
if ($SummaryPath) { Add-Content -LiteralPath $SummaryPath -Value $text -Encoding utf8NoBOM }
Write-Console $text
exit 0
