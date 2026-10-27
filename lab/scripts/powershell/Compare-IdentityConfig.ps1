<#
.SYNOPSIS
    Reconciles an Export-IdentityConfig.ps1 snapshot against the committed
    baseline (lab/config-baseline/identity-config.json) and against the
    intent declared in code (lab/terraform/envs/dev/lab.tfvars), classifies
    every difference High / Medium / Low, honours the time-boxed exceptions in
    lab/config-baseline/drift-exceptions.json, and exits non-zero on open
    High or Medium drift. Writes JSON findings and a Markdown summary fit for
    a GitHub issue. No tenant, no network: two files in, two files out.

.DESCRIPTION
    THE LOOP: Sentinel's real-time rules (lab/kql/ca-policy-changed.kql and
    its neighbours) catch a change as it is made; this nightly compare
    (.github/workflows/config-drift.yml) catches what they missed and what
    nobody acted on. An exception needs an owner and an expiry
    (lab/docs/standards/exception-process.md): when it expires, the finding
    comes back by itself.

    THREE SOURCES OF FINDINGS
      1. BASELINE: a deep diff of every section of the snapshot against the
         same section of the baseline (both normalised by the export, so a
         stable diff). Objects are matched by display name (policies,
         locations, strengths), by group + role (PIM for Groups) or by role
         name (directory roles), never by position.
      2. INTENT (cheap checks of code against tenant, no baseline needed):
         * ca_policy_states in lab.tfvars: a policy whose tenant state is not
           the declared state (enabled in the tenant, report-only in code -
           or the reverse) is High. A declared policy that does not exist is
           not drift: its staging flag may be off.
         * blocked_countries in lab.tfvars against the "Blocked Countries"
           named location: a declared country missing from the tenant list
           is Medium (CA004 is hollowed out), an extra one Low.
         * break-glass invariants from the snapshot's facts: group found,
           at least two enabled members, holds Global Administrator,
           excluded from EVERY Conditional Access policy
           (01-Verify-Baseline.ps1 [2/7]-[4/7]) - each High.
      3. UNREAD: a section the export recorded as failed is a Medium finding
         ("could not verify"), never silence. A failed read is never
         "nothing there".

    SEVERITY (the exception standard's scale: High = Tier 0 or every user)
      High    Conditional Access policy state, user scope / exclusions, a
              policy missing; break-glass invariants; PIM activation rules
              (*_EndUser_Assignment: duration, MFA / justification / ticket,
              approval, authentication context); the authentication methods
              policy; an authentication strength's combinations or AAGUIDs
      Medium  other Conditional Access fields (grant / session controls,
              apps, platforms, locations), named locations, other PIM rules
              (eligibility expiry, admin assignment), consent / app-management
              / cross-tenant policies, a section that could not be read
      Low     an object added that the baseline does not know (a new policy
              is reviewed, not alarmed), display names and descriptions, PIM
              notification rules
    Exit code: 2 if any High finding is open, 1 if any Medium is open, 0 if
    only Low or nothing is open, 3 if the inputs cannot be used (snapshot or
    baseline unreadable, public/non-public mismatch). Never read 3 as "3
    findings".

    EXCEPTIONS (drift-exceptions.json, "exceptions": [...])
      { "id": "E12", "finding": "<finding key, * wildcards allowed>",
        "owner": "...", "approver": "...", "approved": "2026-10-20",
        "expires": "2027-01-18", "reason": "...", "compensatingControls": "..." }
      A matching, unexpired exception marks the finding 'excepted': listed,
      not counted in the exit code. Valid through the whole of its expiry
      date; the day after, the finding is open again with the expired id
      noted. An entry without owner, approved or expires, or whose term
      exceeds the standard (90 days for a High finding, 180 for Medium / Low,
      measured from approved), is IGNORED with a warning and listed under
      "exceptions ignored" - a malformed exception never hides drift.

    BASELINE PLACEHOLDER: until the first tenant export is committed, the
    baseline file is { "status": "no-baseline" }. Then only INTENT and UNREAD
    findings are produced, the output says "no baseline yet", and the exit
    code still follows the findings. The workflow turns that into a notice
    rather than a failure.

    PUBLIC-SAFE: the export already scrubbed UPNs / mailboxes and (with
    -Public) hashed every id; this script adds no identifier of its own and
    refuses to compare a public snapshot with a non-public baseline (the
    hashes would differ everywhere). Before writing a Markdown or JSON file
    from a public snapshot it checks the text once more
    (Test-PublicRecordSafe) and refuses to write if an identifier slipped.

.PARAMETER SnapshotPath
    The snapshot to check (Export-IdentityConfig.ps1 output).

.PARAMETER BaselinePath
    Default lab/config-baseline/identity-config.json.

.PARAMETER ExceptionsPath
    Default lab/config-baseline/drift-exceptions.json.

.PARAMETER TfVarsPath
    Default lab/terraform/envs/dev/lab.tfvars. -SkipIntent turns the tfvars
    checks off (the break-glass invariants still run).

.PARAMETER MarkdownPath
    Write the Markdown summary (GitHub issue body / step summary) here.

.PARAMETER JsonPath
    Write the findings (schema contoso-identity-drift/v1) here.

.PARAMETER AsOf
    Date exceptions are judged against. Default: now (UTC).

.PARAMETER PolicyNamePrefix
    Conditional Access display-name prefix (modules/conditional-access
    policy_name_prefix). Default CA.

.PARAMETER BlockedNamedLocationName
    Default "Blocked Countries" (modules/conditional-access blocked_named_location_name).

.EXAMPLE
    ./Export-IdentityConfig.ps1 -Offline -OutputDirectory ../../evidence/out/config-snapshots
    ./Compare-IdentityConfig.ps1 -SnapshotPath ../../evidence/out/config-snapshots/<UTC>.json -MarkdownPath ../../evidence/out/drift.md
    # no tenant: the fixture against the placeholder baseline and lab.tfvars

.EXAMPLE
    ./Compare-IdentityConfig.ps1 -SnapshotPath ../../evidence/config-snapshots/<UTC>.json -JsonPath drift.json -MarkdownPath drift.md; $LASTEXITCODE

.OUTPUTS
    The findings object (also written as JSON with -JsonPath).

.NOTES
    TENANT-TIME: nothing here has run against a tenant snapshot.
    verify: the first two nightly snapshots of an unchanged tenant produce
      zero baseline findings (if a field moves between identical reads it
      belongs in Export-IdentityConfig.ps1 Get-VolatileFieldName).
    verify: Microsoft-managed Conditional Access policies appear as Low
      "added" findings on the first run and are then committed into the
      baseline, or excepted, by the owner's choice.
    The tfvars reader is a regex over two blocks (ca_policy_states,
    blocked_countries), not an HCL parser; tests/Compare-IdentityConfig.Tests.ps1
    reads the real lab.tfvars through it.

.WHAT IT DEMONSTRATES
    Drift detection that triggers remediation: a classified finding with an
    owner (through the exception register or the issue), a severity that
    gates the job, and an expiry that puts the control back by itself.
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SnapshotPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BaselinePath = (Join-Path $PSScriptRoot '..' '..' 'config-baseline' 'identity-config.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExceptionsPath = (Join-Path $PSScriptRoot '..' '..' 'config-baseline' 'drift-exceptions.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TfVarsPath = (Join-Path $PSScriptRoot '..' '..' 'terraform' 'envs' 'dev' 'lab.tfvars'),

    [Parameter()]
    [switch]$SkipIntent,

    [Parameter()]
    [string]$MarkdownPath = '',

    [Parameter()]
    [string]$JsonPath = '',

    [Parameter()]
    [datetime]$AsOf = (Get-Date).ToUniversalTime(),

    [Parameter()]
    [ValidatePattern('^[A-Za-z]{1,8}$')]
    [string]$PolicyNamePrefix = 'CA',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BlockedNamedLocationName = 'Blocked Countries'
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# PURE FUNCTIONS - no I/O. Unit-tested in tests/Compare-IdentityConfig.Tests.ps1,
# which loads them from this file's syntax tree without running the script.
# =============================================================================

function Get-Field {
    # Index-walk nested dictionaries; a missing key is $null.
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { if (-not $cur.Contains($p)) { return $null }; $cur = $cur[$p] }
        else { $prop = $cur.PSObject.Properties[$p]; if (-not $prop) { return $null }; $cur = $prop.Value }
    }
    return $cur
}

function ConvertTo-IsoString {
    # ConvertFrom-Json turns ISO dates into DateTime; a public record and a
    # Markdown line want the ISO text back, never a locale rendering.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

function ConvertTo-CompactJson {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    return (ConvertTo-Json -InputObject $Value -Depth 30 -Compress)
}

function Get-ItemIdentity {
    # The stable name of one list item: what the export sorts by and what a
    # finding names. Position is never an identity.
    param($Item)
    if (-not ($Item -is [System.Collections.IDictionary])) { return $null }
    if ($Item.Contains('displayName') -and $Item['displayName']) { return [string]$Item['displayName'] }
    if ($Item.Contains('groupMailNickname') -and $Item['groupMailNickname']) { return "$($Item['groupMailNickname']):$($Item['roleDefinitionId'])" }
    if ($Item.Contains('roleDisplayName') -and $Item['roleDisplayName']) { return [string]$Item['roleDisplayName'] }
    if ($Item.Contains('id') -and $Item['id']) { return [string]$Item['id'] }
    return $null
}

function Compare-ConfigNode {
    # Deep diff of two normalised nodes. Rows: Path (segments joined by '/'),
    # Kind (changed | added | removed), Before, After. Dictionaries by key;
    # lists of named objects by identity (Get-ItemIdentity), so a policy
    # renamed shows as removed + added and a policy reordered shows nothing;
    # every other list as one value.
    param($Before, $After, [string]$Path = '')
    $rows = [System.Collections.Generic.List[object]]::new()
    $bIsDict = $Before -is [System.Collections.IDictionary]; $aIsDict = $After -is [System.Collections.IDictionary]
    if ($bIsDict -and $aIsDict) {
        foreach ($k in @(@($Before.Keys) + @($After.Keys) | Sort-Object -Unique -Culture 'en-US' -CaseSensitive)) {
            $p = if ($Path) { "$Path/$k" } else { [string]$k }
            if (-not $After.Contains($k)) { $rows.Add([pscustomobject]@{ Path = $p; Kind = 'removed'; Before = $Before[$k]; After = $null }); continue }
            if (-not $Before.Contains($k)) { $rows.Add([pscustomobject]@{ Path = $p; Kind = 'added'; Before = $null; After = $After[$k] }); continue }
            foreach ($r in (Compare-ConfigNode -Before $Before[$k] -After $After[$k] -Path $p)) { $rows.Add($r) }
        }
        return $rows.ToArray()
    }
    $bIsList = ($Before -is [System.Collections.IEnumerable]) -and ($Before -isnot [string]) -and -not $bIsDict
    $aIsList = ($After -is [System.Collections.IEnumerable]) -and ($After -isnot [string]) -and -not $aIsDict
    if ($bIsList -and $aIsList) {
        $bItems = @($Before); $aItems = @($After)
        $bNamed = @{}; $aNamed = @{}; $named = $true
        foreach ($i in $bItems) { $n = Get-ItemIdentity $i; if ($null -eq $n -or $bNamed.ContainsKey($n)) { $named = $false; break }; $bNamed[$n] = $i }
        if ($named) { foreach ($i in $aItems) { $n = Get-ItemIdentity $i; if ($null -eq $n -or $aNamed.ContainsKey($n)) { $named = $false; break }; $aNamed[$n] = $i } }
        if ($named -and ($bItems.Count -or $aItems.Count)) {
            foreach ($n in @(@($bNamed.Keys) + @($aNamed.Keys) | Sort-Object -Unique -Culture 'en-US' -CaseSensitive)) {
                $p = if ($Path) { "$Path/$n" } else { $n }
                if (-not $aNamed.ContainsKey($n)) { $rows.Add([pscustomobject]@{ Path = $p; Kind = 'removed'; Before = $bNamed[$n]; After = $null }); continue }
                if (-not $bNamed.ContainsKey($n)) { $rows.Add([pscustomobject]@{ Path = $p; Kind = 'added'; Before = $null; After = $aNamed[$n] }); continue }
                foreach ($r in (Compare-ConfigNode -Before $bNamed[$n] -After $aNamed[$n] -Path $p)) { $rows.Add($r) }
            }
            return $rows.ToArray()
        }
        if ((ConvertTo-CompactJson $bItems) -ne (ConvertTo-CompactJson $aItems)) { $rows.Add([pscustomobject]@{ Path = $Path; Kind = 'changed'; Before = $bItems; After = $aItems }) }
        return $rows.ToArray()
    }
    if ((ConvertTo-CompactJson $Before) -ne (ConvertTo-CompactJson $After)) { $rows.Add([pscustomobject]@{ Path = $Path; Kind = 'changed'; Before = $Before; After = $After }) }
    return $rows.ToArray()
}

function Get-TwinDetection {
    # The real-time rule that would have fired when the change was made.
    # Empty = no real-time twin: the nightly compare is the only control.
    param([Parameter(Mandatory)][string]$Section)
    switch ($Section) {
        'conditionalAccessPolicies' { return 'lab/kql/ca-policy-changed.kql' }
        'namedLocations' { return 'lab/kql/ca-policy-changed.kql' }
        'authenticationStrengths' { return 'lab/kql/ca-policy-changed.kql' }
        'breakGlass' { return 'lab/kql/ca-policy-changed.kql (ExclusionsChanged), lab/kql/break-glass-signin.kql' }
        'consentPolicy' { return 'lab/kql/app-consent-granted.kql (grants, not the policy)' }
        'pimDirectoryRolePolicies' { return 'lab/kql/role-assigned-outside-pim.kql (assignments, not the policy)' }
        'pimGroupPolicies' { return 'lab/kql/pim-group-member-added-outside-pim.kql (members, not the policy)' }
        default { return '' }
    }
}

function Get-DriftSeverity {
    # The classification table in .DESCRIPTION, as code. Object = the list
    # item the row belongs to ('' for a section-level or singleton policy
    # row), Attribute = the path inside it, Kind = changed | added | removed.
    param([Parameter(Mandatory)][string]$Section, [AllowEmptyString()][string]$Object, [AllowEmptyString()][string]$Attribute, [Parameter(Mandatory)][string]$Kind)
    $objectLevel = ($Object -and -not $Attribute)
    $cosmetic = ($Attribute -match '^(displayName|description)$')
    switch ($Section) {
        'conditionalAccessPolicies' {
            if ($objectLevel) { return $(if ($Kind -eq 'removed') { 'High' } else { 'Low' }) }
            if ($Attribute -eq 'state' -or $Attribute -like 'conditions/users*') { return 'High' }
            if ($cosmetic) { return 'Low' }
            return 'Medium'
        }
        'breakGlass' { return 'High' }
        'authenticationMethodsPolicy' { return 'High' }
        'authenticationStrengths' {
            if ($objectLevel) { return $(if ($Kind -eq 'removed') { 'High' } else { 'Low' }) }
            if ($Attribute -like 'allowedCombinations*' -or $Attribute -like 'combinationConfigurations*' -or $Attribute -eq 'requirementsSatisfied') { return 'High' }
            if ($cosmetic) { return 'Low' }
            return 'Medium'
        }
        'namedLocations' {
            if ($objectLevel) { return $(if ($Kind -eq 'removed') { 'Medium' } else { 'Low' }) }
            if ($cosmetic) { return 'Low' }
            return 'Medium'
        }
        { $_ -in 'pimDirectoryRolePolicies', 'pimGroupPolicies' } {
            if ($objectLevel) { return $(if ($Kind -eq 'removed') { 'High' } else { 'Low' }) }
            if ($Attribute -like 'policy/rules/*_EndUser_Assignment*' -and $Attribute -notlike 'policy/rules/Notification_*') { return 'High' }
            if ($Attribute -like 'policy/rules/Notification_*') { return 'Low' }
            if ($cosmetic -or $Attribute -like 'policy/displayName' -or $Attribute -like 'policy/description') { return 'Low' }
            return 'Medium'
        }
        default {
            if ($cosmetic -or $Attribute -like '*/displayName' -or $Attribute -like '*/description') { return 'Low' }
            return 'Medium'
        }
    }
}

function Get-FindingObject {
    # Splits a diff path inside a section into (object, attribute): for a
    # list section ('items/<identity>/<rest>') the identity and the rest;
    # for a singleton ('policy/<rest>', 'facts/<rest>', 'authorizationPolicy/<rest>')
    # no object and the whole path.
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^items/([^/]+)(?:/(.*))?$') { return @([string]$Matches[1], [string]$(if ($Matches.Count -gt 2) { $Matches[2] } else { '' })) }
    return @('', $Path)
}

function Get-BaselineFinding {
    # Source 1: baseline vs snapshot, section by section, classified.
    param([Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Snapshot)
    $out = [System.Collections.Generic.List[object]]::new()
    $bSections = Get-Field $Baseline @('sections'); $sSections = Get-Field $Snapshot @('sections')
    if (-not $bSections -or -not $sSections) { return $out.ToArray() }
    foreach ($name in @(@($bSections.Keys) + @($sSections.Keys) | Sort-Object -Unique -Culture 'en-US' -CaseSensitive)) {
        $b = $(if ($bSections.Contains($name)) { $bSections[$name] } else { $null })
        $s = $(if ($sSections.Contains($name)) { $sSections[$name] } else { $null })
        # A section that failed (either side) is reported by Get-UnreadFinding; its content cannot be compared.
        if (-not $s -or [string](Get-Field $s @('status')) -ne 'ok') { continue }
        if (-not $b -or [string](Get-Field $b @('status')) -ne 'ok') {
            $out.Add([ordered]@{ key = "section/$name/no-baseline"; severity = 'Low'; section = $name; object = ''; attribute = ''; kind = 'added'; before = $null; after = 'section present in the snapshot, absent or failed in the baseline'
                    message = "section $name has no usable baseline; commit this snapshot's section to the baseline after review"; twin = (Get-TwinDetection $name) })
            continue
        }
        foreach ($row in (Compare-ConfigNode -Before $b -After $s)) {
            if ($row.Path -in 'status', 'count', 'error') { continue }   # consequences of the rows below, not findings
            # The break-glass exclusion lists are derived from the policies: the invariant finding
            # (Get-IntentFinding) and the policy's own excludeGroups row already name the policy.
            if ($name -eq 'breakGlass' -and $row.Path -in 'facts/excludedFromPolicies', 'facts/notExcludedFromPolicies') { continue }
            $obj, $attr = Get-FindingObject -Path $row.Path
            $sev = Get-DriftSeverity -Section $name -Object $obj -Attribute $attr -Kind $row.Kind
            $key = if ($obj) { "$name/$obj/$(if ($attr) { $attr } else { $row.Kind })" } else { "$name/$($row.Path)" }
            $what = switch ($row.Kind) { 'removed' { "removed from the tenant" } 'added' { "added in the tenant (not in the baseline)" } default { "changed" } }
            $out.Add([ordered]@{ key = $key; severity = $sev; section = $name; object = $obj; attribute = $attr; kind = $row.Kind
                    before = $(if ($row.Kind -eq 'added') { $null } else { $row.Before }); after = $(if ($row.Kind -eq 'removed') { $null } else { $row.After })
                    message = "$(if ($obj) { "$obj" } else { $name })$(if ($attr) { ": $attr" }) $what"; twin = (Get-TwinDetection $name) })
        }
    }
    return $out.ToArray()
}

function ConvertFrom-LabTfVarFile {
    # The two blocks of lab.tfvars this compare reads: ca_policy_states
    # (CAnnn = "state") and blocked_countries (["KP", ...]). A regex, not
    # an HCL parser; comments after # are ignored.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $states = [ordered]@{}
    $m = [regex]::Match($Text, '(?ms)^\s*ca_policy_states\s*=\s*\{(.*?)^\s*\}')
    if ($m.Success) {
        foreach ($line in ($m.Groups[1].Value -split "`n")) {
            $l = ($line -replace '#.*$', '').Trim()
            if ($l -match '^([A-Za-z]+\d{3})\s*=\s*"([A-Za-z]+)"$') { $states[$Matches[1]] = $Matches[2] }
        }
    }
    $countries = @()
    $c = [regex]::Match($Text, '(?m)^\s*blocked_countries\s*=\s*\[([^\]]*)\]')
    if ($c.Success) { $countries = @([regex]::Matches($c.Groups[1].Value, '"([A-Z]{2})"') | ForEach-Object { $_.Groups[1].Value }) }
    return @{ CaPolicyStates = $states; BlockedCountries = $countries; HasCaPolicyStates = $m.Success; HasBlockedCountries = $c.Success }
}

function Get-IntentFinding {
    # Source 2: declared intent vs the snapshot. $TfVars = ConvertFrom-LabTfVarFile output ($null = -SkipIntent).
    param([Parameter(Mandatory)]$Snapshot, $TfVars, [string]$Prefix = 'CA', [string]$BlockedLocationName = 'Blocked Countries')
    $out = [System.Collections.Generic.List[object]]::new()
    $ca = Get-Field $Snapshot @('sections', 'conditionalAccessPolicies')
    if ($TfVars -and $ca -and [string]$ca['status'] -eq 'ok') {
        $byKey = @{}
        foreach ($p in @($ca['items'])) {
            $n = [string](Get-Field $p @('displayName'))
            if ($n -match "^($([regex]::Escape($Prefix))\d{3})(\s|$|-)") { $byKey[$Matches[1]] = $p }
        }
        foreach ($k in $TfVars.CaPolicyStates.Keys) {
            if (-not $byKey.ContainsKey($k)) { continue }   # flag off: not drift
            $declared = [string]$TfVars.CaPolicyStates[$k]; $actual = [string](Get-Field $byKey[$k] @('state'))
            if ($declared -ne $actual) {
                $out.Add([ordered]@{ key = "intent/ca/$k/state"; severity = 'High'; section = 'conditionalAccessPolicies'; object = [string]$byKey[$k]['displayName']; attribute = 'state'; kind = 'intent'
                        before = $declared; after = $actual; message = "$k is '$actual' in the tenant but lab.tfvars declares '$declared' (a graduation or a rollback happened outside a pull request)"; twin = (Get-TwinDetection 'conditionalAccessPolicies') })
            }
        }
    }
    $nl = Get-Field $Snapshot @('sections', 'namedLocations')
    if ($TfVars -and $TfVars.HasBlockedCountries -and $nl -and [string]$nl['status'] -eq 'ok') {
        $loc = @(@($nl['items']) | Where-Object { [string](Get-Field $_ @('displayName')) -eq $BlockedLocationName }) | Select-Object -First 1
        if ($loc) {
            $have = @(Get-Field $loc @('countriesAndRegions')); $want = @($TfVars.BlockedCountries)
            $missing = @($want | Where-Object { $_ -notin $have } | Sort-Object); $extra = @($have | Where-Object { $_ -notin $want } | Sort-Object)
            if ($missing.Count) {
                $out.Add([ordered]@{ key = "intent/namedLocation/$BlockedLocationName/countries-missing"; severity = 'Medium'; section = 'namedLocations'; object = $BlockedLocationName; attribute = 'countriesAndRegions'; kind = 'intent'
                        before = $want; after = $have; message = "declared blocked countries missing from the tenant list: $($missing -join ', ') (CA004 no longer blocks them)"; twin = (Get-TwinDetection 'namedLocations') })
            }
            if ($extra.Count) {
                $out.Add([ordered]@{ key = "intent/namedLocation/$BlockedLocationName/countries-extra"; severity = 'Low'; section = 'namedLocations'; object = $BlockedLocationName; attribute = 'countriesAndRegions'; kind = 'intent'
                        before = $want; after = $have; message = "countries blocked in the tenant that lab.tfvars does not declare: $($extra -join ', ')"; twin = (Get-TwinDetection 'namedLocations') })
            }
        }
    }
    # Break-glass invariants: from the snapshot's facts, baseline or not.
    $bg = Get-Field $Snapshot @('sections', 'breakGlass')
    if ($bg -and [string]$bg['status'] -eq 'ok') {
        $f = $bg['facts']; $twin = Get-TwinDetection 'breakGlass'
        if (-not (Get-Field $f @('groupFound'))) {
            $out.Add([ordered]@{ key = 'breakGlass/group/missing'; severity = 'High'; section = 'breakGlass'; object = 'group'; attribute = 'groupFound'; kind = 'invariant'; before = $true; after = $false; message = "break-glass group '$($bg['groupMailNickname'])' not found"; twin = $twin })
        }
        else {
            $enabled = [int](Get-Field $f @('enabledMemberCount'))
            if ($enabled -lt 2) { $out.Add([ordered]@{ key = 'breakGlass/members/too-few'; severity = 'High'; section = 'breakGlass'; object = 'group'; attribute = 'enabledMemberCount'; kind = 'invariant'; before = 2; after = $enabled; message = "break-glass group has $enabled enabled member(s); keep at least two"; twin = $twin }) }
            if (-not (Get-Field $f @('holdsGlobalAdministrator'))) { $out.Add([ordered]@{ key = 'breakGlass/global-administrator/missing'; severity = 'High'; section = 'breakGlass'; object = 'group'; attribute = 'holdsGlobalAdministrator'; kind = 'invariant'; before = $true; after = $false; message = 'break-glass group no longer holds a standing Global Administrator assignment'; twin = $twin }) }
            foreach ($p in @(Get-Field $f @('notExcludedFromPolicies'))) {
                if (-not $p) { continue }
                $out.Add([ordered]@{ key = "breakGlass/$p/not-excluded"; severity = 'High'; section = 'breakGlass'; object = [string]$p; attribute = 'excludeGroups'; kind = 'invariant'; before = 'excluded'; after = 'not excluded'; message = "Conditional Access policy '$p' does not exclude the break-glass group (lockout risk)"; twin = $twin })
            }
        }
    }
    return $out.ToArray()
}

function Get-UnreadFinding {
    # Source 3: every section the export could not read.
    param([Parameter(Mandatory)]$Snapshot)
    $out = [System.Collections.Generic.List[object]]::new()
    $sections = Get-Field $Snapshot @('sections')
    if (-not $sections) { return $out.ToArray() }
    foreach ($name in @($sections.Keys)) {
        $s = $sections[$name]
        if ([string](Get-Field $s @('status')) -eq 'ok') { continue }
        $out.Add([ordered]@{ key = "section/$name/unread"; severity = 'Medium'; section = $name; object = ''; attribute = 'status'; kind = 'unread'; before = 'ok'; after = [string](Get-Field $s @('status'))
                message = "section $name could not be read ($([string](Get-Field $s @('error')))); its drift is unknown, not absent"; twin = (Get-TwinDetection $name) })
    }
    return $out.ToArray()
}

function ConvertTo-UtcDate {
    param([Parameter(Mandatory)]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().Date }
    return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal).Date
}

function Test-DriftException {
    # Every reason an exception entry must not be honoured; empty = valid.
    # The term limit is the standard's: 90 days (High) / 180 days (Medium,
    # Low) from the approval date, judged against the FINDING's severity.
    param([Parameter(Mandatory)]$Exception, [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low')][string]$Severity)
    $why = @()
    foreach ($f in 'id', 'finding', 'owner', 'approved', 'expires') { if ([string]::IsNullOrWhiteSpace([string](Get-Field $Exception @($f)))) { $why += "$f missing" } }
    if ([string](Get-Field $Exception @('id')) -notmatch '^E\d+$') { $why += 'id must look like E12 (exception-process.md register)' }
    $approved = $null; $expires = $null
    try { if (Get-Field $Exception @('approved')) { $approved = ConvertTo-UtcDate (Get-Field $Exception @('approved')) } } catch { $why += 'approved is not a date' }
    try { if (Get-Field $Exception @('expires')) { $expires = ConvertTo-UtcDate (Get-Field $Exception @('expires')) } } catch { $why += 'expires is not a date' }
    if ($approved -and $expires) {
        $max = if ($Severity -eq 'High') { 90 } else { 180 }
        if ($expires -lt $approved) { $why += 'expires before approved' }
        elseif (($expires - $approved).TotalDays -gt $max) { $why += "term exceeds the standard's $max days for a $Severity finding" }
    }
    return @($why)
}

function Resolve-DriftException {
    # Applies the register to the findings. Each finding gets status 'open'
    # or 'excepted' and an 'exception' note; ignored (invalid) entries come
    # back separately so the summary can list them.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings, [AllowEmptyCollection()][object[]]$Exceptions = @(), [Parameter(Mandatory)][datetime]$AsOf)
    $ignored = [System.Collections.Generic.List[object]]::new()
    $today = $AsOf.ToUniversalTime().Date
    foreach ($f in $Findings) {
        $f['status'] = 'open'; $f['exception'] = ''
        foreach ($x in $Exceptions) {
            if (-not $x) { continue }
            $pattern = [string](Get-Field $x @('finding'))
            if (-not $pattern -or -not ($f['key'] -like $pattern)) { continue }
            $problems = @(Test-DriftException -Exception $x -Severity $f['severity'])
            $xid = [string](Get-Field $x @('id'))
            if ($problems.Count) { $ignored.Add([ordered]@{ id = $xid; finding = $pattern; reasons = $problems }); $f['exception'] = "$xid ignored: $($problems -join '; ')"; continue }
            $exp = ConvertTo-UtcDate (Get-Field $x @('expires'))
            if ($today -le $exp) { $f['status'] = 'excepted'; $f['exception'] = "$xid (owner $([string](Get-Field $x @('owner'))), expires $($exp.ToString('yyyy-MM-dd')))"; break }
            $f['exception'] = "$xid expired $($exp.ToString('yyyy-MM-dd')): the control is back in force"
        }
    }
    return @{ Findings = @($Findings); Ignored = $ignored.ToArray() }
}

function Get-DriftExitCode {
    # 2 High open, 1 Medium open, else 0. (3 = unusable input, set by the caller.)
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $open = @($Findings | Where-Object { $_['status'] -eq 'open' })
    if (@($open | Where-Object { $_['severity'] -eq 'High' }).Count) { return 2 }
    if (@($open | Where-Object { $_['severity'] -eq 'Medium' }).Count) { return 1 }
    return 0
}

function ConvertTo-MarkdownCell {
    param($Value, [int]$Max = 160)
    $s = if ($null -eq $Value) { '' } elseif ($Value -is [string]) { $Value } else { ConvertTo-CompactJson $Value }
    $s = $s -replace '\|', '\|' -replace "[`r`n]+", ' '
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max - 1) + '...' }
    return $s
}

function ConvertTo-DriftMarkdown {
    # The GitHub issue body / step summary. Carries only what the findings
    # carry (names, states, hashed ids); the caller checks it is public-safe.
    param([Parameter(Mandatory)]$Report)
    $f = @($Report['findings']); $sum = $Report['summary']
    $L = [System.Collections.Generic.List[string]]::new()
    $L.Add("## Identity configuration drift - $($Report['generatedAtUtc'].Substring(0, 10)) (UTC)")
    $L.Add('')
    $base = $Report['baseline']
    $L.Add("Snapshot ``$($Report['snapshot']['file'])`` ($($Report['snapshot']['source']), $($Report['snapshot']['identifiers'])) against " +
        $(if ($base['status'] -eq 'ok') { "baseline ``$($base['file'])`` (exported $($base['generatedAtUtc']))" } else { '**no baseline yet** (placeholder: intent and unread checks only)' }) +
        $(if ($Report['intent']['checked']) { " and ``$($Report['intent']['tfvars'])``." } else { '.' }))
    $L.Add('')
    $L.Add('| Severity | Open | Excepted |'); $L.Add('|---|---|---|')
    foreach ($sev in 'High', 'Medium', 'Low') { $L.Add("| $sev | $($sum['open'][$sev]) | $($sum['excepted'][$sev]) |") }
    $L.Add('')
    $L.Add("Exit code **$($sum['exitCode'])** (2 = High open, 1 = Medium open, 0 = clean or Low only). " +
        'Real-time twins fire in Sentinel when the change is made; this nightly compare (`.github/workflows/config-drift.yml`) is the reconcile. ' +
        'Remediate through a pull request (the code is the source of truth), or register a time-boxed exception in `lab/config-baseline/drift-exceptions.json` (`lab/docs/standards/exception-process.md`).')
    foreach ($sev in 'High', 'Medium', 'Low') {
        $rows = @($f | Where-Object { $_['status'] -eq 'open' -and $_['severity'] -eq $sev })
        if (-not $rows.Count) { continue }
        $L.Add(''); $L.Add("### $sev ($($rows.Count))"); $L.Add('')
        $L.Add('| Finding | What | Before | After | Real-time twin | Exception |'); $L.Add('|---|---|---|---|---|---|')
        foreach ($r in $rows) { $L.Add("| ``$(ConvertTo-MarkdownCell $r['key'])`` | $(ConvertTo-MarkdownCell $r['message']) | $(ConvertTo-MarkdownCell $r['before'] 80) | $(ConvertTo-MarkdownCell $r['after'] 80) | $(ConvertTo-MarkdownCell $r['twin'])$(if (-not $r['twin']) { 'none: nightly only' }) | $(ConvertTo-MarkdownCell $r['exception']) |") }
    }
    $exc = @($f | Where-Object { $_['status'] -eq 'excepted' })
    if ($exc.Count) {
        $L.Add(''); $L.Add("### Excepted ($($exc.Count))"); $L.Add('')
        $L.Add('| Finding | Severity | Exception |'); $L.Add('|---|---|---|')
        foreach ($r in $exc) { $L.Add("| ``$(ConvertTo-MarkdownCell $r['key'])`` | $($r['severity']) | $(ConvertTo-MarkdownCell $r['exception']) |") }
    }
    $ign = @($Report['exceptionsIgnored'])
    if ($ign.Count) {
        $L.Add(''); $L.Add("### Exceptions ignored ($($ign.Count))"); $L.Add('')
        foreach ($x in $ign) { $L.Add("- ``$($x['id'])`` for ``$($x['finding'])``: $($x['reasons'] -join '; ')") }
    }
    $unread = @($f | Where-Object { $_['kind'] -eq 'unread' })
    if ($unread.Count) { $L.Add(''); $L.Add("_$($unread.Count) section(s) could not be read; their drift is unknown, not absent._") }
    if (-not $f.Count) { $L.Add(''); $L.Add('No drift found.') }
    return (($L -join "`n") + "`n")
}

function Test-PublicRecordSafe {
    # Same rule as Export-IdentityConfig.ps1 / 09-SoD-Report.ps1.
    param([string]$Json)
    $bad = @()
    foreach ($p in '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', '\b\d{1,3}(\.\d{1,3}){3}\b', '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '(?i)onmicrosoft\.com') {
        foreach ($m in [regex]::Matches($Json, $p)) { $bad += $m.Value }
    }
    return @($bad | Sort-Object -Unique)
}

# =============================================================================
# RUN
# =============================================================================
function Read-JsonFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$What)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$What not found: $Path" }
    $o = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 50
    if (-not ($o -is [System.Collections.IDictionary])) { throw "$What is not a JSON object: $Path" }
    return $o
}
$sha = { param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }

try {
    $snapshot = Read-JsonFile -Path $SnapshotPath -What 'Snapshot'
    if ([string](Get-Field $snapshot @('schema')) -ne 'contoso-identity-config/v1') { throw "Snapshot schema is '$(Get-Field $snapshot @('schema'))', expected contoso-identity-config/v1." }
    $baseline = Read-JsonFile -Path $BaselinePath -What 'Baseline'
    $baselineStatus = if ([string](Get-Field $baseline @('status')) -eq 'no-baseline') { 'no-baseline' }
    elseif ([string](Get-Field $baseline @('schema')) -eq 'contoso-identity-config/v1' -and (Get-Field $baseline @('sections'))) { 'ok' }
    else { throw "Baseline $BaselinePath is neither a contoso-identity-config/v1 snapshot nor the { status: no-baseline } placeholder." }
    if ($baselineStatus -eq 'ok' -and ([bool](Get-Field $baseline @('public')) -ne [bool](Get-Field $snapshot @('public')))) {
        throw 'Baseline and snapshot differ in -Public (hashed vs object ids): every id would differ. Export both the same way.'
    }
    $exceptions = @()
    if (Test-Path -LiteralPath $ExceptionsPath -PathType Leaf) { $exceptions = @((Read-JsonFile -Path $ExceptionsPath -What 'Exceptions file')['exceptions'] | Where-Object { $null -ne $_ }) }
    else { Write-Warning "Exceptions file not found ($ExceptionsPath): no exception applies." }
    $tfVars = $null
    if (-not $SkipIntent) {
        if (-not (Test-Path -LiteralPath $TfVarsPath -PathType Leaf)) { throw "lab.tfvars not found: $TfVarsPath (use -SkipIntent to compare without the declared intent)" }
        $tfVars = ConvertFrom-LabTfVarFile -Text (Get-Content -LiteralPath $TfVarsPath -Raw)
        if (-not $tfVars.HasCaPolicyStates) { throw "ca_policy_states block not found in $TfVarsPath (the tfvars reader needs updating, or the file moved)" }
    }
}
catch {
    Write-Console "Compare FAILED (exit 3): $($_.Exception.Message)" -ForegroundColor Red
    exit 3
}

Write-Console "Comparing $(Split-Path -Leaf $SnapshotPath) ($(Get-Field $snapshot @('source'))) against $(if ($baselineStatus -eq 'ok') { Split-Path -Leaf $BaselinePath } else { 'NO BASELINE YET (placeholder)' })$(if ($tfVars) { " and $(Split-Path -Leaf $TfVarsPath)" })..." -ForegroundColor Cyan
if ($baselineStatus -ne 'ok') { Write-Console 'no baseline yet: commit the first reviewed tenant export to lab/config-baseline/identity-config.json; until then only intent and unread findings are produced.' -ForegroundColor DarkYellow }

$findings = [System.Collections.Generic.List[object]]::new()
if ($baselineStatus -eq 'ok') { foreach ($x in (Get-BaselineFinding -Baseline $baseline -Snapshot $snapshot)) { $findings.Add($x) } }
foreach ($x in (Get-IntentFinding -Snapshot $snapshot -TfVars $tfVars -Prefix $PolicyNamePrefix -BlockedLocationName $BlockedNamedLocationName)) { $findings.Add($x) }
foreach ($x in (Get-UnreadFinding -Snapshot $snapshot)) { $findings.Add($x) }
$resolved = Resolve-DriftException -Findings $findings.ToArray() -Exceptions $exceptions -AsOf $AsOf
$all = @($resolved.Findings | Sort-Object -Culture 'en-US' -CaseSensitive -Property @{ Expression = { switch ($_['severity']) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } }, @{ Expression = { $_['key'] } })
$exitCode = Get-DriftExitCode -Findings $all

$summary = [ordered]@{ open = [ordered]@{}; excepted = [ordered]@{}; exitCode = $exitCode; findings = $all.Count; exceptionsIgnored = @($resolved.Ignored).Count }
foreach ($sev in 'High', 'Medium', 'Low') {
    $summary['open'][$sev] = @($all | Where-Object { $_['status'] -eq 'open' -and $_['severity'] -eq $sev }).Count
    $summary['excepted'][$sev] = @($all | Where-Object { $_['status'] -eq 'excepted' -and $_['severity'] -eq $sev }).Count
}
$report = [ordered]@{
    schema            = 'contoso-identity-drift/v1'
    generatedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
    generator         = 'lab/scripts/powershell/Compare-IdentityConfig.ps1'
    asOf              = $AsOf.ToUniversalTime().ToString('yyyy-MM-dd')
    snapshot          = [ordered]@{ file = (Split-Path -Leaf $SnapshotPath); sha256 = (& $sha $SnapshotPath); generatedAtUtc = (ConvertTo-IsoString (Get-Field $snapshot @('generatedAtUtc'))); source = [string](Get-Field $snapshot @('source')); public = [bool](Get-Field $snapshot @('public')); identifiers = [string](Get-Field $snapshot @('identifiers')) }
    baseline          = [ordered]@{ status = $baselineStatus; file = (Split-Path -Leaf $BaselinePath); sha256 = (& $sha $BaselinePath); generatedAtUtc = $(if ($baselineStatus -eq 'ok') { ConvertTo-IsoString (Get-Field $baseline @('generatedAtUtc')) } else { $null }) }
    intent            = [ordered]@{ checked = [bool]$tfVars; tfvars = $(if ($tfVars) { 'lab/terraform/envs/dev/lab.tfvars' } else { $null }); caPolicyStates = $(if ($tfVars) { $tfVars.CaPolicyStates } else { $null }); blockedCountries = $(if ($tfVars) { @($tfVars.BlockedCountries) } else { $null }) }
    exceptionsFile    = $(if (Test-Path -LiteralPath $ExceptionsPath -PathType Leaf) { [ordered]@{ file = (Split-Path -Leaf $ExceptionsPath); sha256 = (& $sha $ExceptionsPath); entries = $exceptions.Count } } else { $null })
    summary           = $summary
    findings          = $all
    exceptionsIgnored = @($resolved.Ignored)
}

# Console
foreach ($r in $all) {
    $colour = switch ($r['severity']) { 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'DarkGray' } }
    if ($r['status'] -eq 'excepted') { $colour = 'DarkGray' }
    Write-Console ("  {0,-8} {1,-9} {2}" -f $r['severity'], $r['status'], $r['key']) -ForegroundColor $colour
    Write-Console ("           {0}$(if ($r['exception']) { "  [$($r['exception'])]" })" -f $r['message']) -ForegroundColor DarkGray
}
foreach ($x in @($resolved.Ignored)) { Write-Warning "Exception $($x['id']) for '$($x['finding'])' ignored: $($x['reasons'] -join '; ')" }
Write-Console ("`nOpen: High {0}, Medium {1}, Low {2}; excepted {3}; exit {4}." -f $summary['open']['High'], $summary['open']['Medium'], $summary['open']['Low'], ($summary['excepted']['High'] + $summary['excepted']['Medium'] + $summary['excepted']['Low']), $exitCode) -ForegroundColor $(if ($exitCode -eq 0) { 'Green' } else { 'Red' })

# Files
$json = (ConvertTo-Json -InputObject $report -Depth 30) -replace "`r`n", "`n"
$md = ConvertTo-DriftMarkdown -Report $report
if ([bool](Get-Field $snapshot @('public'))) {
    foreach ($pair in @(@('JSON findings', $json), @('Markdown summary', $md))) {
        $unsafe = @(Test-PublicRecordSafe -Json $pair[1])
        if ($unsafe.Count) { Write-Console "$($pair[0]) from a public snapshot still carries an identifier ($($unsafe.Count) string(s)); nothing written (exit 3). First: $($unsafe[0])" -ForegroundColor Red; exit 3 }
    }
}
foreach ($pair in @(@($JsonPath, $json), @($MarkdownPath, $md))) {
    if (-not $pair[0]) { continue }
    $dir = Split-Path -Parent ([System.IO.Path]::GetFullPath($pair[0]))
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($pair[0]), $pair[1] + $(if ($pair[1].EndsWith("`n")) { '' } else { "`n" }), [System.Text.UTF8Encoding]::new($false))
    Write-Console "Wrote $($pair[0])" -ForegroundColor DarkGray
}

[pscustomobject]$report
exit $exitCode
