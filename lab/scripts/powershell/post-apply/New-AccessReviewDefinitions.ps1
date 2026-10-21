<#
.SYNOPSIS
    Creates the standalone access reviews Terraform renders but cannot create:
    the quarterly PRIVILEGED (ADR 0012 T1) reviews - every PIM-governed admin
    group (eligible + active members) and the direct Global Administrator
    eligibility from modules/pim - and the INACTIVE-USER review. Idempotent.

.DESCRIPTION
    azuread 3.10 has no accessReviewScheduleDefinition resource, so
    modules/entitlement (reviews.tf) renders the exact Graph v1.0 request
    bodies from real object ids into the output access_review_definitions,
    and this script POSTs the ones that do not exist yet. The DEFINITION stays
    code-reviewed in Terraform; only the HTTP call happens here.

    Inputs: modules/entitlement output access_review_definitions, which
    already merges modules/pim's pim_eligible_review_bodies while
    enable_access_reviews_privileged is on. A full `terraform output -json`
    that also carries pim_eligible_review_bodies on its own (or several files,
    -DefinitionsPath a.json,b.json) is merged here too: one key with two
    different bodies, or two keys with one displayName, stops the run before
    anything is sent.

    Per body (key "privileged:<group>", "privileged:Global Administrator
    (eligible)", "inactive:<group>", ...):
      0. CONTRACT (never weaken a gate): default decision Deny, auto-apply on,
         justification required, a reviewer AND a fallback reviewer, and a
         displayName starting "Privileged access review:" or "Inactive users
         review:". A body that fails is not POSTed and fails the run.
      1. Already exists (matched by displayName)?  -> [=] skip. The script
         NEVER edits an existing review series: to change one, stop and
         delete it in the portal, then re-run. Settings drift (decision
         policy, duration, recurrence) is REPORTED, not fixed.
      2. recurrence.range.startDate null -> today (UTC) or -StartDate.
      3. Self-review guard (privileged only): warns about anyone who is both
         ELIGIBLE for the reviewed group - or, for a role-scoped body, for the
         reviewed directory role - and a member of the reviewer group. Nobody
         should certify their own standing to activate an admin role.
      4. POST /identityGovernance/accessReviews/definitions with the body
         exactly as Terraform rendered it (only startDate filled in).

    Why deny-by-default is safe here: Terraform refuses to render a review
    without a reviewer AND a fallback group (output preconditions), so there
    is always someone who can answer before silence removes access.

    Evidence:
      * lab/evidence/access-reviews/definitions-<yyyyMMdd>.json (+ .sha256):
        PUBLIC-SAFE summary - key, displayName, status, created date. No ids,
        no UPNs (refused if one slips in): lab/ is published.
      * lab/evidence/out/access-reviews/definitions-<yyyyMMdd>.json (gitignored):
        the full record including definition ids, for the WORM evidence store.

    TENANT-TIME. Nothing here has run against a tenant. verify: a
    Graph-created review of a PIM-managed group includes ELIGIBLE members
    (Learn documents it for the portal flow; still labelled preview), and the
    licence (Entra ID Governance) - modules/entitlement/README.md.
    verify: GET /roleManagement/directory/roleEligibilitySchedules filtered
    on roleDefinitionId returns principalId for the role-scoped self-review
    guard (RoleEligibilitySchedule.Read.Directory); if it does not, the guard
    warns that it could not run - it never blocks or passes silently.

.PREREQUISITES
    * envs/dev applied with enable_premium + enable_governance and the
      review flags (enable_access_reviews_privileged for T1,
      enable_access_reviews_inactive for the stale-account review; the
      deprecated enable_access_reviews means both), plus enable_pim_tiers /
      enable_pim_azure_resources for the tier and Azure groups.
    * terraform -chdir=lab/terraform/envs/dev output -json access_review_definitions > reviews.json
    * Role: Identity Governance Administrator. Reviews of PIM-for-Groups need
      Global Administrator, Identity Governance Administrator or Privileged
      Role Administrator.

.GRAPH SCOPES  (delegated; admin-consent)
    AccessReview.ReadWrite.All                       create / read definitions
    Group.Read.All                                   reviewer group members
    PrivilegedEligibilitySchedule.Read.AzureADGroup  who is eligible (self-review guard)
    RoleEligibilitySchedule.Read.Directory           who is eligible for a directory
                                                     role (only when a role-scoped body is present)

.PARAMETER DefinitionsPath
    JSON written by `terraform output -json access_review_definitions`: a map
    of key -> JSON STRING (so each value is parsed twice). A full
    `terraform output -json` file is accepted too (the access_review_definitions
    and pim_eligible_review_bodies entries are unwrapped and merged). Several
    files may be given; they are merged the same way.

.PARAMETER StartDate
    yyyy-MM-dd used where Terraform left startDate null. Default: today (UTC).

.PARAMETER FailOnDrift
    Exit 1 when an existing definition's decision settings differ from the
    Terraform body (default: report only).

.EXAMPLE
    terraform -chdir=lab/terraform/envs/dev output -json access_review_definitions > reviews.json
    Connect-MgGraph -Scopes 'AccessReview.ReadWrite.All','Group.Read.All','PrivilegedEligibilitySchedule.Read.AzureADGroup'
    ./New-AccessReviewDefinitions.ps1 -DefinitionsPath ./reviews.json -WhatIf
    ./New-AccessReviewDefinitions.ps1 -DefinitionsPath ./reviews.json
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string[]]$DefinitionsPath,

    [Parameter()]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$StartDate = ([datetime]::UtcNow.ToString('yyyy-MM-dd')),

    [Parameter()]
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..' '..' '..' 'evidence' 'access-reviews'),

    [Parameter()]
    [string]$DetailDirectory = (Join-Path $PSScriptRoot '..' '..' '..' 'evidence' 'out' 'access-reviews'),

    [Parameter()]
    [switch]$FailOnDrift
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

$graph = 'https://graph.microsoft.com/v1.0'

# =============================================================================
# Pure helpers (unit-tested without a tenant)
# =============================================================================
function Read-ReviewDefinitionFile {
    # Returns an ordered map key -> body (ordered hashtable). Accepts the
    # single-output JSON (key -> JSON string) or a full `terraform output -json`
    # (access_review_definitions and, when present on its own,
    # pim_eligible_review_bodies are unwrapped and merged).
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if ($null -eq $raw) { return [ordered]@{} }
    $maps = @()
    $isFullOutput = $false
    foreach ($name in 'access_review_definitions', 'pim_eligible_review_bodies') {
        if ($raw.Contains($name) -and $raw[$name] -is [System.Collections.IDictionary] -and $raw[$name].Contains('value')) {
            $isFullOutput = $true
            if ($raw[$name]['value'] -is [System.Collections.IDictionary]) { $maps += , $raw[$name]['value'] }
        }
    }
    if (-not $isFullOutput) { $maps = @(, $raw) }
    $out = [ordered]@{}
    foreach ($m in $maps) {
        foreach ($k in @($m.Keys | Sort-Object)) {
            $v = $m[$k]
            # Terraform renders strings (the scope shapes differ); tolerate an
            # already-parsed object too.
            $body = if ($v -is [string]) { $v | ConvertFrom-Json -AsHashtable } else { $v }
            if ($out.Contains($k)) {
                if (($out[$k] | ConvertTo-Json -Depth 20 -Compress) -cne ($body | ConvertTo-Json -Depth 20 -Compress)) { throw "Review key '$k' appears twice with different bodies ($Path). Nothing was sent." }
                continue
            }
            $out[$k] = $body
        }
    }
    return $out
}

function Read-ReviewDefinitionSet {
    # Several definition files -> one ordered map. The same key twice must be
    # the same body; two keys must never share a displayName (idempotency is
    # by displayName, so a second one would be skipped as 'exists').
    param([Parameter(Mandatory)][string[]]$Path)
    $out = [ordered]@{}
    foreach ($p in $Path) {
        $one = Read-ReviewDefinitionFile -Path $p
        foreach ($k in $one.Keys) {
            if ($out.Contains($k)) {
                if (($out[$k] | ConvertTo-Json -Depth 20 -Compress) -cne ($one[$k] | ConvertTo-Json -Depth 20 -Compress)) { throw "Review key '$k' appears in two inputs with different bodies. Nothing was sent." }
                continue
            }
            $out[$k] = $one[$k]
        }
    }
    $names = @{}
    foreach ($k in $out.Keys) {
        $n = [string]$out[$k]['displayName']
        if ($names.ContainsKey($n)) { throw "Review keys '$($names[$n])' and '$k' share the displayName '$n'. Give each series one key (modules/entitlement output precondition). Nothing was sent." }
        $names[$n] = $k
    }
    return $out
}

function Test-ReviewBodyContract {
    # ADR 0012: every standalone review this script creates is deny-by-default
    # with auto-apply and a fallback reviewer. Returns the reasons a body must
    # not be POSTed; empty = OK. Bodies from modules/pim are held to the same
    # rule as reviews.tf's, so no input can weaken the gate.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Body)
    $why = [System.Collections.Generic.List[string]]::new()
    $name = [string]$Body['displayName']
    if (-not ($name.StartsWith('Privileged access review:') -or $name.StartsWith('Inactive users review:'))) { $why.Add("displayName '$name' must start 'Privileged access review:' or 'Inactive users review:' (10-Review-KPIs.ps1 tiers reviews by it)") }
    $st = if ($Body.Contains('settings') -and $Body['settings'] -is [System.Collections.IDictionary]) { $Body['settings'] } else { @{} }
    if ($st['defaultDecisionEnabled'] -ne $true -or [string]$st['defaultDecision'] -ne 'Deny') { $why.Add('no answer must mean Deny (defaultDecisionEnabled true, defaultDecision Deny)') }
    if ($st['autoApplyDecisionsEnabled'] -ne $true) { $why.Add('decisions must auto-apply (autoApplyDecisionsEnabled true)') }
    if ($st['justificationRequiredOnApproval'] -ne $true) { $why.Add('approvals must carry a justification (justificationRequiredOnApproval true)') }
    if (@($Body['reviewers'] | Where-Object { $_ }).Count -lt 1) { $why.Add('no reviewers') }
    if (@($Body['fallbackReviewers'] | Where-Object { $_ }).Count -lt 1) { $why.Add('no fallback reviewers (mandatory: deny-by-default without one removes everything)') }
    return $why.ToArray()
}

function Get-RoleIdFromQuery {
    # Role-scoped review queries -> directory role (template) id:
    #   /roleManagement/directory/roleEligibilityScheduleInstances?...roleDefinitionId eq '<id>'...
    #   /roleManagement/directory/roleDefinitions/<id>
    param([string]$Query)
    if ($Query -match "roleDefinitionId eq '([0-9a-fA-F-]{36})'") { return $Matches[1] }
    if ($Query -match '/roleManagement/directory/roleDefinitions/([0-9a-fA-F-]{36})') { return $Matches[1] }
    return $null
}

function Complete-ReviewBody {
    # Fills a null recurrence.range.startDate; changes nothing else, so the
    # POST equals the Terraform-rendered body.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Body, [Parameter(Mandatory)][string]$StartDate)
    $range = $Body['settings']['recurrence']['range']
    if ($null -eq $range['startDate'] -or [string]::IsNullOrWhiteSpace([string]$range['startDate'])) { $range['startDate'] = $StartDate }
    return $Body
}

function Get-GroupIdFromQuery {
    # "/groups/<id>/transitiveMembers" -> <id>
    param([string]$Query)
    if ($Query -match '^/groups/([0-9a-fA-F-]{36})/') { return $Matches[1] }
    return $null
}

function Compare-ReviewSetting {
    # Lists the decision settings that differ between the Terraform body and
    # what exists in the tenant (drift is reported, never patched).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Desired, [Parameter(Mandatory)][System.Collections.IDictionary]$Actual)
    $diffs = @()
    $d = $Desired['settings']; $a = if ($Actual.Contains('settings')) { $Actual['settings'] } else { @{} }
    foreach ($k in 'defaultDecisionEnabled', 'defaultDecision', 'autoApplyDecisionsEnabled', 'instanceDurationInDays', 'justificationRequiredOnApproval', 'recommendationsEnabled') {
        $dv = if ($d.Contains($k)) { [string]$d[$k] } else { '' }
        $av = if ($a -and $a.Contains($k)) { [string]$a[$k] } else { '' }
        if ($dv -ne $av) { $diffs += "$k (terraform '$dv', tenant '$av')" }
    }
    $dp = $d['recurrence']['pattern']
    $ap = if ($a -and $a.Contains('recurrence') -and $a['recurrence']) { $a['recurrence']['pattern'] } else { $null }
    foreach ($k in 'type', 'interval') {
        $dv = [string]$dp[$k]; $av = if ($ap -and $ap.Contains($k)) { [string]$ap[$k] } else { '' }
        if ($dv -ne $av) { $diffs += "recurrence.pattern.$k (terraform '$dv', tenant '$av')" }
    }
    return , $diffs
}

function Test-PublicRecordSafe {
    # Same rule as Invoke-BreakGlassDrill.ps1: a public record must not carry
    # an email/UPN, IP address, GUID or onmicrosoft domain. Emits the
    # offending strings; nothing = safe.
    param([string]$Json)
    $bad = @()
    foreach ($p in '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', '\b\d{1,3}(\.\d{1,3}){3}\b', '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '(?i)onmicrosoft\.com') {
        foreach ($m in [regex]::Matches($Json, $p)) { $bad += $m.Value }
    }
    return @($bad | Sort-Object -Unique)
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    # Unrolled on purpose: callers wrap the call in @() (a comma-return here
    # would nest the whole page list inside @() as ONE element).
    return $items.ToArray()
}

# =============================================================================
# Main
# =============================================================================
$definitions = Read-ReviewDefinitionSet -Path $DefinitionsPath
if ($definitions.Count -eq 0) {
    Write-Warning "No review definitions in $($DefinitionsPath -join ', '). Are enable_access_reviews_privileged / enable_access_reviews_inactive on in lab.tfvars (and applied)?"
    exit 1
}

$requiredScopes = @('AccessReview.ReadWrite.All', 'Group.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
if (@($definitions.Values | Where-Object { Get-RoleIdFromQuery ([string]$_['scope']['query']) }).Count) { $requiredScopes += 'RoleEligibilitySchedule.Read.Directory' }
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx -and -not $WhatIfPreference) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
if ($ctx) {
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }
}

Write-Console "Access review definitions: $($definitions.Count) rendered by Terraform" -ForegroundColor Cyan
$failures = 0; $drifted = 0
$records = [System.Collections.Generic.List[object]]::new()

foreach ($key in $definitions.Keys) {
    $body = Complete-ReviewBody -Body $definitions[$key] -StartDate $StartDate
    $name = [string]$body['displayName']
    $escaped = $name.Replace("'", "''")

    # 0. Contract: never create a review that keeps access on silence.
    $broken = @(Test-ReviewBodyContract -Body $body)
    if ($broken.Count) {
        Write-Warning "  [!] $key - refused, not sent: $($broken -join '; ')."
        $failures++
        continue
    }

    # 1. Idempotency: match by displayName. A failed READ is a failure, never
    #    "does not exist" - creating a duplicate series is worse than stopping.
    $existing = $null
    if ($ctx) {
        try {
            $found = @(Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions?`$filter=displayName eq '$escaped'")
            if ($found.Count -gt 0) { $existing = $found[0] }
        }
        catch {
            Write-Warning "  [!] $key - could not read existing definitions: $($_.Exception.Message)"
            $failures++
            continue
        }
    }
    if ($existing) {
        $diffs = Compare-ReviewSetting -Desired $body -Actual $existing
        if ($diffs.Count) {
            $drifted++
            Write-Warning "  [~] '$name' exists ($($existing['id'])) but differs from Terraform: $($diffs -join '; '). Not changed - stop + delete it in the portal and re-run to replace it."
        }
        else { Write-Console "  [=] '$name' already exists ($($existing['status']))." -ForegroundColor DarkGray }
        $records.Add([ordered]@{ key = $key; id = $existing['id']; displayName = $name; status = [string]$existing['status']; createdDateTime = [string]$existing['createdDateTime']; action = 'exists'; drift = @($diffs) })
        continue
    }

    # 2. Self-review guard for privileged reviews: eligible AND a reviewer.
    #    Group scope -> PIM-for-Groups eligibility; role scope (modules/pim's
    #    direct Global Administrator review) -> directory role eligibility.
    if (($key -like 'privileged*' -or $name.StartsWith('Privileged access review:')) -and $ctx) {
        $targetId = Get-GroupIdFromQuery ([string]$body['scope']['query'])
        $roleId = if (-not $targetId) { Get-RoleIdFromQuery ([string]$body['scope']['query']) } else { $null }
        $reviewerId = Get-GroupIdFromQuery ([string]$body['reviewers'][0]['query'])
        if (($targetId -or $roleId) -and $reviewerId) {
            try {
                $reviewers = @(Get-GraphCollection -Uri "$graph/groups/$reviewerId/transitiveMembers?`$select=id,userPrincipalName")
                $eligibleUri = if ($targetId) { "$graph/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$targetId'" }
                else { "$graph/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$roleId'" }
                $eligible = @(Get-GraphCollection -Uri $eligibleUri)
                $eligibleIds = @($eligible | ForEach-Object { $_['principalId'] })
                $both = @($reviewers | Where-Object { $_['id'] -in $eligibleIds })
                $what = if ($targetId) { 'group' } else { 'directory role' }
                if ($both.Count) {
                    Write-Warning "  [!] '$name': $($both.Count) reviewer(s) are also ELIGIBLE for the reviewed $what ($(@($both | ForEach-Object { $_['userPrincipalName'] }) -join ', ')). Remove them from the reviewer group - no self-certification of privilege."
                }
            }
            catch { Write-Warning "  [!] '$name': self-review check could not run ($($_.Exception.Message)); review the reviewer group by hand." }
        }
        elseif (-not $reviewerId) { Write-Warning "  [!] '$name': reviewers are not a group query - self-review check skipped; review the reviewers by hand." }
    }

    # 3. Create.
    $json = $body | ConvertTo-Json -Depth 20 -Compress
    if ($PSCmdlet.ShouldProcess($name, 'POST /identityGovernance/accessReviews/definitions')) {
        try {
            $created = Invoke-MgGraphRequest -Method POST -Uri "$graph/identityGovernance/accessReviews/definitions" -Body $json -ContentType 'application/json' -OutputType HashTable
            Write-Console "  [+] '$name' created ($($created['id']), status $($created['status']))." -ForegroundColor Green
            $records.Add([ordered]@{ key = $key; id = $created['id']; displayName = $name; status = [string]$created['status']; createdDateTime = [string]$created['createdDateTime']; action = 'created'; drift = @() })
        }
        catch {
            Write-Warning "  [!] '$name' not created: $($_.Exception.Message)"
            $failures++
        }
    }
    else {
        Write-Console "  [?] would POST '$name':" -ForegroundColor Yellow
        Write-Console ($body | ConvertTo-Json -Depth 20) -ForegroundColor DarkGray
    }
}

# =============================================================================
# Evidence (skipped under -WhatIf and when nothing was read or created)
# =============================================================================
if ($records.Count -and -not $WhatIfPreference) {
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd')
    foreach ($dir in $EvidenceDirectory, $DetailDirectory) { if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } }

    $detailFile = Join-Path $DetailDirectory "definitions-$stamp.json"
    ($records | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $detailFile -Encoding utf8NoBOM

    $public = [ordered]@{
        generatedUtc = [datetime]::UtcNow.ToString('o')
        source       = 'tenant'
        definitions  = @($records | ForEach-Object {
                [ordered]@{ key = $_.key; displayName = $_.displayName; status = $_.status; createdDate = if ($_.createdDateTime) { ([datetime]$_.createdDateTime).ToUniversalTime().ToString('yyyy-MM-dd') } else { '' }; action = $_.action; drift = @($_.drift).Count -gt 0 }
            })
    }
    $publicJson = $public | ConvertTo-Json -Depth 6
    $leaks = @(Test-PublicRecordSafe -Json $publicJson)
    if ($leaks.Count) {
        Write-Warning "Public summary NOT written: it would contain $($leaks.Count) identifying value(s). Full record: $detailFile"
        $failures++
    }
    else {
        $publicFile = Join-Path $EvidenceDirectory "definitions-$stamp.json"
        $publicJson | Set-Content -LiteralPath $publicFile -Encoding utf8NoBOM
        $hash = (Get-FileHash -LiteralPath $publicFile -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  definitions-$stamp.json" | Set-Content -LiteralPath "$publicFile.sha256" -Encoding utf8NoBOM
        Write-Console "`nEvidence: $publicFile (sha256 $hash); detail (gitignored): $detailFile" -ForegroundColor Cyan
    }
}

if ($failures) { Write-Warning "$failures definition(s) failed."; exit 1 }
if ($drifted -and $FailOnDrift) { Write-Warning "$drifted definition(s) drifted from Terraform."; exit 1 }
Write-Console "`nVerify: Entra -> Identity Governance -> Access reviews (each series 'Privileged access review: ...' / 'Inactive users review: ...'). Birthright (T3) access never appears here (ADR 0012)." -ForegroundColor Cyan
