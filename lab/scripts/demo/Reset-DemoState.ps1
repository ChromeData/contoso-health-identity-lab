<#
.SYNOPSIS
    Recording re-take tool. Puts the lab back into the state it was in right
    BEFORE a video segment (Joiner, Mover or Leaver) so the segment can be
    filmed again: edits Dana Okafor's and Marcus Bello's rows in the mock HR
    feed, re-pushes just those two rows through inbound provisioning
    (HR -> AD -> Cloud Sync), and reconciles their access-package assignments
    in Entra with Microsoft Graph.

.DESCRIPTION
    STAND-IN NOTE: the "HR system" this script edits is the lab's mock HR feed
    (lab/scripts/mock-hr/hr_feed.csv + Invoke-InboundProvisioning.ps1), which
    replaces Workday / SAP SuccessFactors. In production a re-take like this
    would be an HR-side correction in the HRIS; everything downstream (the
    Entra API-driven inbound provisioning endpoint, AD, Cloud Sync, access
    packages) is the real product.

    WHY IT EXISTS
      Segments are recorded separately and re-taken often. Each take changes
      real tenant state (Dana disabled, packages removed, Marcus moved to ICU).
      Rebuilding that by hand between takes is slow and error-prone; this does
      it in one command, in the right order, with -WhatIf.

    DESIRED STATE PER SEGMENT (the moment before the segment starts)
      Segment  Dana (100492)                          Marcus (100310)
      -------  -------------------------------------  -------------------------------------
      Joiner   status=joiner, Nursing, no packages    active, Nursing, Nurse - Clinical Apps
      Mover    status=active, Nursing, Nurse pkg      active, Nursing, Nurse pkg (no ICU)
      Leaver   status=active, Nursing, Nurse pkg      active, ICU,     ICU - Critical Care Apps
               (endDate cleared, account re-enabled
                through HR -> AD, never a cloud write)
      Managed packages: Nurse, ICU, Pharmacy - by their assignment model in
      lab/iga/access-catalog.json (ADR 0012):
        automatic (T3 birthright: Nurse, ICU)  NEVER adminAdd / adminRemove.
          They follow the HR attributes this script resets (department, job
          title, enabled, hire date): the automatic policy adds them while
          the rule matches and removes them after its grace period
          (gracePeriodBeforeAccessRemoval) once it stops. Readiness lists
          them as HR-driven, not as a reset target - a re-take inside the
          grace period can still show the old birthright package.
        request (T2: Pharmacy)  reconciled directly: an assignment not in
          the table is removed (adminRemove); a missing one is added
          (adminAdd) through the REQUEST policy.
      Packages outside that set are never touched.

    HYBRID RULE (same as 03-Mover / 04-Leaver)
      Department, job title and enabled/disabled are owned by HR -> AD and
      flow up through Cloud Sync; Entra rejects cloud writes to them on synced
      users. So this script NEVER writes accountEnabled or department in
      Entra. "Re-enable Dana" = her HR row goes back to active, the provisioning
      job sets AD accountDisabled = false, Cloud Sync carries it up. Access
      packages and licenses are cloud-side and are set with Graph directly.

    ORDER (deliberate)
      0. Connect to Graph ONCE with every scope the run needs (real runs
         only), before anything changes - otherwise the provisioning script
         would connect first with its single scope and steps 3-6 would 403.
      1. Edit hr_feed.csv - ONLY the two rows; every other line (comments,
         other workers) is left byte-for-byte as it was. Start/end dates are
         untouched except endDate, which is cleared.
      2. Re-push the two rows through ../mock-hr/Invoke-InboundProvisioning.ps1
         (a temporary two-row copy of the feed, so other workers are not
         re-sent and the provisioning log stays readable).
      3. Remove packages that should not be there (safe immediately).
      4. Optionally wait (-WaitForSyncSeconds) for the HR change to land in
         Entra (department / enabled), then add the missing packages.
      5. Optionally re-assign a license (-LicenseSkuPartNumber) - the
         Lifecycle Workflow leaver removes licenses.
      6. Readiness table: expected vs actual for each person. READY means
         you can roll the camera.

    NOT RESET (see README.md "What it does not reset")
      AD object deletion (a true "Create" in the provisioning log), provisioning
      / sign-in / Lifecycle Workflow history, revoked sessions, SCIM state in
      ServiceNow / AWS (follows the packages on the next cycle), Okta JIT users.

.PREREQUISITES
    * The lab is built through Cloud Sync (lab/scripts/dc/README.md, step 6)
      and the API-driven provisioning app (lab/scripts/mock-hr/README.md,
      One-time setup), and Terraform envs/dev with
      enable_governance = true (the three packages exist).
    * Cloud Sync scope includes OU=Disabled (lab/scripts/dc/README.md,
      step 6). If it does not, a leaver take
      soft-deletes Dana in Entra and the re-take creates a NEW Entra object.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated; admin-consent)
    EntitlementManagement.ReadWrite.All   read assignments; adminAdd / adminRemove
    User.Read.All                         read Dana / Marcus
    User.ReadWrite.All, Organization.Read.All   only with -LicenseSkuPartNumber
    SynchronizationData-User.Upload       only when provisioning runs (the
                                          bulkUpload permission;
                                          lab/scripts/mock-hr/README.md)

.PARAMETER Segment
    Joiner | Mover | Leaver - the segment you are about to (re-)record.

.PARAMETER ServicePrincipalId
    Object id of the API-driven provisioning app's service principal (same
    value Invoke-InboundProvisioning.ps1 takes). Required unless
    -SkipProvisioning or -WhatIf.

.PARAMETER JobId
    Synchronization job id of that provisioning app. Required unless
    -SkipProvisioning or -WhatIf.

.PARAMETER UpnDomain
    Workforce UPN domain; Dana / Marcus are given.surname@<UpnDomain>.

.PARAMETER CsvPath
    The HR feed to edit. Default ../mock-hr/hr_feed.csv.

.PARAMETER ProvisioningScriptPath
    Default ../mock-hr/Invoke-InboundProvisioning.ps1.

.PARAMETER NursePackageName
.PARAMETER IcuPackageName
.PARAMETER PharmacyPackageName
    Display names of the three managed packages (Terraform contract names).

.PARAMETER CatalogPath
    lab/iga/access-catalog.json: which managed packages are birthright
    (automatic - HR-driven, never reset here) and which are requestable.

.PARAMETER LicenseSkuPartNumber
    Optional SKU part number (e.g. SPE_E5) to make sure both people hold - a
    leaver take via Lifecycle Workflows removes licenses. Default: not touched.

.PARAMETER UsageLocation
    Set when the user has none and a license must be assigned. Default US.

.PARAMETER WaitForSyncSeconds
    0 (default) = do not wait; print the readiness table once. >0 = poll Entra
    until the HR-owned attributes match (then add packages) and the packages
    are delivered, or the time runs out. Cloud Sync provisions users roughly
    every 10-20 minutes, so 1500 is a realistic value without Provision on
    demand.

.PARAMETER SkipProvisioning
    Edit the CSV (and fix packages) but do not re-push HR rows.

.PARAMETER SkipCloud
    Do not touch Entra (packages / license / readiness). CSV (+ provisioning) only.

.PARAMETER WhatIf
    Standard. Prints the CSV diff, the exact SCIM payload the provisioning
    script would send, and the package changes. Writes nothing. Works with no
    tenant at all (the cloud part is then described from the table above).

.EXAMPLE
    # Dry run, no tenant needed:
    ./Reset-DemoState.ps1 -Segment Leaver -WhatIf

.EXAMPLE
    Connect-MgGraph -Scopes 'EntitlementManagement.ReadWrite.All','User.Read.All','SynchronizationData-User.Upload'
    ./Reset-DemoState.ps1 -Segment Mover -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain>

.EXAMPLE
    # Leaver re-take, wait for Cloud Sync, re-license Dana:
    ./Reset-DemoState.ps1 -Segment Leaver -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain> `
        -LicenseSkuPartNumber SPE_E5 -WaitForSyncSeconds 1500

.OUTPUTS
    [pscustomobject] rows: Step, Target, Action, Status.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Joiner', 'Mover', 'Leaver')]
    [string]$Segment,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', ErrorMessage = 'ServicePrincipalId must be a GUID.')]
    [string]$ServicePrincipalId = '00000000-0000-0000-0000-000000000000',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$JobId = 'REPLACE_WITH_SYNC_JOB_ID',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
    [string]$UpnDomain = 'contosohealth.io',

    [Parameter()]
    [string]$CsvPath = (Join-Path $PSScriptRoot '../mock-hr/hr_feed.csv'),

    [Parameter()]
    [string]$ProvisioningScriptPath = (Join-Path $PSScriptRoot '../mock-hr/Invoke-InboundProvisioning.ps1'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NursePackageName = 'Nurse - Clinical Apps',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$IcuPackageName = 'ICU - Critical Care Apps',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PharmacyPackageName = 'Pharmacy - Controlled Substances Apps',

    [Parameter()]
    [string]$LicenseSkuPartNumber = '',

    [Parameter()]
    [ValidatePattern('^[A-Z]{2}$')]
    [string]$UsageLocation = 'US',

    [Parameter()]
    [ValidateRange(0, 7200)]
    [int]$WaitForSyncSeconds = 0,

    [Parameter()]
    [switch]$SkipProvisioning,

    [Parameter()]
    [switch]$SkipCloud,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'access-catalog.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graph = 'https://graph.microsoft.com/v1.0'
$em = "$graph/identityGovernance/entitlementManagement"
$activeStates = @('delivered', 'delivering', 'partiallyDelivered')

$report = [System.Collections.Generic.List[object]]::new()
$failures = 0
function Add-Report {
    param([string]$Step, [string]$Target, [string]$Action, [string]$Status)
    $report.Add([pscustomobject]@{ Step = $Step; Target = $Target; Action = $Action; Status = $Status })
}

# =============================================================================
# 0. DESIRED STATE (see .DESCRIPTION table)
# =============================================================================
$people = [ordered]@{
    Dana   = @{ EmployeeId = '100492'; Upn = "dana.okafor@$UpnDomain".ToLowerInvariant() }
    Marcus = @{ EmployeeId = '100310'; Upn = "marcus.bello@$UpnDomain".ToLowerInvariant() }
}
$desiredBySegment = @{
    Joiner = @{
        Dana   = @{ status = 'joiner'; dept = 'Nursing'; jobTitle = 'Registered Nurse'; endDate = ''; packages = @() }
        Marcus = @{ status = 'active'; dept = 'Nursing'; jobTitle = 'Registered Nurse'; endDate = ''; packages = @('nurse') }
    }
    Mover  = @{
        Dana   = @{ status = 'active'; dept = 'Nursing'; jobTitle = 'Registered Nurse'; endDate = ''; packages = @('nurse') }
        Marcus = @{ status = 'active'; dept = 'Nursing'; jobTitle = 'Registered Nurse'; endDate = ''; packages = @('nurse') }
    }
    Leaver = @{
        Dana   = @{ status = 'active'; dept = 'Nursing'; jobTitle = 'Registered Nurse'; endDate = ''; packages = @('nurse') }
        Marcus = @{ status = 'active'; dept = 'ICU'; jobTitle = 'Registered Nurse'; endDate = ''; packages = @('icu') }
    }
}
$desired = $desiredBySegment[$Segment]
$packageNames = [ordered]@{ nurse = $NursePackageName; icu = $IcuPackageName; pharmacy = $PharmacyPackageName }
# Assignment model per managed package (lab/iga/access-catalog.json). An
# automatic (birthright) package is HR-driven and never requested or removed
# here; a package missing from the catalog stops the run (never guessed).
if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) { throw "Access catalog not found: $CatalogPath" }
$catalogEntries = @((Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json -AsHashtable)['accessPackages'])
$birthright = @{}
foreach ($key in $packageNames.Keys) {
    $e = @($catalogEntries | Where-Object { $_ -and [string]$_['name'] -eq $packageNames[$key] }) | Select-Object -First 1
    if (-not $e) { throw "Access package '$($packageNames[$key])' is not in $CatalogPath." }
    $birthright[$key] = ([string]$e['assignment'] -eq 'automatic')
}

Write-Host "Reset to the moment BEFORE the '$Segment' segment." -ForegroundColor Cyan
foreach ($p in $people.Keys) {
    $d = $desired[$p]
    $pk = if ($d.packages) { ($d.packages | ForEach-Object { $packageNames[$_] }) -join ', ' } else { '(none)' }
    Write-Host ("  {0,-6} status={1}, dept={2}, packages={3}" -f $p, $d.status, $d.dept, $pk) -ForegroundColor DarkGray
}

# Fail before changing anything if a real run has no provisioning target.
$placeholderIds = ($ServicePrincipalId -eq '00000000-0000-0000-0000-000000000000' -or $JobId -eq 'REPLACE_WITH_SYNC_JOB_ID')
if (-not $SkipProvisioning -and -not $WhatIfPreference -and $placeholderIds) {
    throw 'Pass -ServicePrincipalId and -JobId of the API-driven provisioning app (see ../mock-hr/README.md), or -SkipProvisioning to edit the CSV only.'
}
if (-not $SkipProvisioning -and -not (Test-Path -LiteralPath $ProvisioningScriptPath -PathType Leaf)) {
    throw "Provisioning script not found at '$ProvisioningScriptPath'."
}
if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) { throw "HR feed not found at '$CsvPath'." }

# ---- Graph connection: ONE context with every scope this run needs ---------
# Connect here, before anything changes, and not later: the provisioning
# script (step 2) calls Connect-MgGraph with ONLY SynchronizationData-User.Upload
# when it finds no context, and steps 3-6 would then silently reuse that
# one-scope context and 403 on every entitlement-management call.
$requiredScopes = @()
if (-not $SkipCloud) {
    $requiredScopes += 'EntitlementManagement.ReadWrite.All', 'User.Read.All'
    if ($LicenseSkuPartNumber) { $requiredScopes += 'User.ReadWrite.All', 'Organization.Read.All' }
}
if (-not $SkipProvisioning) { $requiredScopes += 'SynchronizationData-User.Upload' }

$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx -and $requiredScopes -and -not $WhatIfPreference) {
    # -WhatIf never connects: with no context it describes the cloud side
    # offline (step 3-6), with an existing one it reads the tenant.
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Yellow
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $ctx = Get-MgContext
}
if ($ctx) {
    # Soft check: app-only tokens list roles, not scopes, so warn - do not fail.
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }
}

# =============================================================================
# 1. EDIT hr_feed.csv - Dana + Marcus rows only
# =============================================================================
Write-Host "`n[1/6] HR feed: $CsvPath" -ForegroundColor Cyan
$raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $CsvPath).ProviderPath)
$nl = if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" }
$lines = $raw -split [regex]::Escape($nl)   # a trailing newline yields a final '' and is preserved on re-join

$headerIndex = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i].Trim() -and -not $lines[$i].TrimStart().StartsWith('#')) { $headerIndex = $i; break }
}
if ($headerIndex -lt 0) { throw "No header row found in '$CsvPath'." }
$header = $lines[$headerIndex].Split(',')
$col = @{}
for ($i = 0; $i -lt $header.Count; $i++) { $col[$header[$i].Trim()] = $i }
foreach ($c in 'employeeId', 'status', 'dept', 'jobTitle', 'endDate') {
    if (-not $col.ContainsKey($c)) { throw "hr_feed.csv header is missing column '$c' (contract: lab/scripts/mock-hr/hr_feed.csv header comment)." }
}

$idToPerson = @{}
foreach ($p in $people.Keys) { $idToPerson[$people[$p].EmployeeId] = $p }
$matchCount = @{}
$newRows = @{}
$changed = $false
for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if (-not $line.Trim() -or $line.TrimStart().StartsWith('#')) { continue }
    $fields = $line.Split(',')
    $eid = $fields[$col['employeeId']].Trim()
    if (-not $idToPerson.ContainsKey($eid)) { continue }   # every other worker: untouched
    $person = $idToPerson[$eid]
    if ($line.Contains('"')) { throw "Row $eid uses CSV quoting; this tool only edits plain rows. Edit it by hand." }
    if ($fields.Count -ne $header.Count) { throw "Row $eid has $($fields.Count) fields, header has $($header.Count)." }
    $matchCount[$eid] = 1 + [int]($matchCount[$eid])

    $want = $desired[$person]
    $fields[$col['status']] = $want.status
    $fields[$col['dept']] = $want.dept
    $fields[$col['jobTitle']] = $want.jobTitle
    $fields[$col['endDate']] = $want.endDate
    $newLine = $fields -join ','
    $newRows[$person] = $newLine
    if ($newLine -ne $line) {
        Write-Host "  - $line" -ForegroundColor Red
        Write-Host "  + $newLine" -ForegroundColor Green
        $lines[$i] = $newLine
        $changed = $true
    }
}
foreach ($p in $people.Keys) {
    $eid = $people[$p].EmployeeId
    if (-not $matchCount.ContainsKey($eid)) { throw "employeeId $eid ($p) not found in '$CsvPath'." }
    if ($matchCount[$eid] -ne 1) { throw "employeeId $eid ($p) appears $($matchCount[$eid]) times in '$CsvPath'." }
}

if (-not $changed) {
    Write-Host '  [=] Both rows already match this segment.' -ForegroundColor DarkGray
    Add-Report 'HR feed' 'hr_feed.csv' 'edit Dana + Marcus rows' 'already-correct'
}
elseif ($PSCmdlet.ShouldProcess($CsvPath, "edit rows 100492 (Dana) and 100310 (Marcus) for segment $Segment")) {
    [System.IO.File]::WriteAllText((Resolve-Path -LiteralPath $CsvPath).ProviderPath, ($lines -join $nl), [System.Text.UTF8Encoding]::new($false))
    Write-Host '  [+] hr_feed.csv updated (other rows untouched). Restore the committed copy later with: git checkout -- lab/scripts/mock-hr/hr_feed.csv' -ForegroundColor Green
    Add-Report 'HR feed' 'hr_feed.csv' 'edit Dana + Marcus rows' 'updated'
}
else { Add-Report 'HR feed' 'hr_feed.csv' 'edit Dana + Marcus rows' 'whatif' }

# =============================================================================
# 2. RE-PUSH THE TWO ROWS: HR -> AD (Cloud Sync carries it to Entra)
# =============================================================================
Write-Host "`n[2/6] Inbound provisioning (HR -> AD)" -ForegroundColor Cyan
if ($SkipProvisioning) {
    Write-Host '  [skip] -SkipProvisioning: AD keeps its current values until the next HR push.' -ForegroundColor DarkGray
    Add-Report 'Provisioning' 'Dana + Marcus' 'bulkUpload' 'skipped'
}
else {
    # Temporary two-row feed: header + the edited rows. Written even under
    # -WhatIf (scratch file in the temp folder, deleted below) so the child
    # script can print the exact SCIM payload it would send.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("hr_feed_reset_{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
        $tmpBody = @($lines[$headerIndex], $newRows['Marcus'], $newRows['Dana']) -join $nl
        [System.IO.File]::WriteAllText($tmp, $tmpBody + $nl, [System.Text.UTF8Encoding]::new($false))
        $childArgs = @{
            ServicePrincipalId = $ServicePrincipalId
            JobId              = $JobId
            CsvPath            = $tmp
            StatusFilter       = 'all'
            UpnDomain          = $UpnDomain
        }
        if ($WhatIfPreference) {
            & $ProvisioningScriptPath @childArgs -WhatIf
            Add-Report 'Provisioning' 'Dana + Marcus' 'bulkUpload' 'whatif'
        }
        elseif ($PSCmdlet.ShouldProcess('Dana + Marcus HR rows', 'POST SCIM bulkUpload (HR -> AD)')) {
            # Already confirmed here; do not ask a second time in the child.
            & $ProvisioningScriptPath @childArgs -Confirm:$false
            Add-Report 'Provisioning' 'Dana + Marcus' 'bulkUpload' 'submitted (async)'
        }
        else { Add-Report 'Provisioning' 'Dana + Marcus' 'bulkUpload' 'declined' }
    }
    catch {
        Write-Warning "  Inbound provisioning failed: $($_.Exception.Message)"
        Add-Report 'Provisioning' 'Dana + Marcus' 'bulkUpload' 'FAILED'
        $failures++
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            # -WhatIf:$false - the scratch file must be cleaned up on dry runs too.
            try { Remove-Item -LiteralPath $tmp -Force -WhatIf:$false -Confirm:$false }
            catch { Write-Warning "  Could not delete temp feed '$tmp': $($_.Exception.Message)" }
        }
    }
}

# =============================================================================
# 3-6. CLOUD SIDE (Graph): packages, license, readiness
# =============================================================================
if ($SkipCloud) {
    Write-Host "`n[3-6] Cloud side skipped (-SkipCloud)." -ForegroundColor DarkGray
    $report | Format-Table -AutoSize | Out-Host
    if ($failures) { Write-Warning "$failures step(s) failed."; exit 1 }
    return $report
}

# $ctx was established (or deliberately left empty under -WhatIf) before step 1.
if (-not $ctx -and $WhatIfPreference) {
    # Offline dry run: describe the cloud-side intent without reading the tenant.
    Write-Host "`n[3-6] No Graph connection (-WhatIf): cloud-side intent only." -ForegroundColor DarkYellow
    foreach ($p in $people.Keys) {
        $keep = @($desired[$p].packages | Where-Object { -not $birthright[$_] } | ForEach-Object { $packageNames[$_] })
        $drop = @($packageNames.Keys | Where-Object { $_ -notin $desired[$p].packages -and -not $birthright[$_] } | ForEach-Object { $packageNames[$_] })
        $hr = @($desired[$p].packages | Where-Object { $birthright[$_] } | ForEach-Object { $packageNames[$_] })
        Write-Host "  $p <$($people[$p].Upn)>: ensure [$($keep -join ', ')]; adminRemove any of [$($drop -join ', ')]; birthright (HR-driven, not reset) expected [$($hr -join ', ')]$(if ($LicenseSkuPartNumber) { "; ensure license $LicenseSkuPartNumber" })." -ForegroundColor DarkYellow
        Add-Report 'Packages' $p 'reconcile' 'whatif-offline'
    }
    $report | Format-Table -AutoSize | Out-Host
    return $report
}
if (-not $ctx) { throw 'No Microsoft Graph context for the cloud steps (Connect-MgGraph did not produce one).' }

function Invoke-Graph {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body
    )
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
        $params.ContentType = 'application/json'
    }
    return Invoke-MgGraphRequest @params
}
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-Graph -Method GET -Uri $next
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    # Items are emitted one by one; callers wrap the call in @() for array semantics.
    return $items.ToArray()
}
function Get-Person {
    param([Parameter(Mandatory)][string]$Upn)
    return Invoke-Graph -Method GET -Uri "$graph/users/$([uri]::EscapeDataString($Upn))?`$select=id,displayName,department,jobTitle,accountEnabled,onPremisesSyncEnabled,usageLocation,assignedLicenses"
}
function Get-ActiveAssignment {
    param([Parameter(Mandatory)][string]$UserId)
    $f = [uri]::EscapeDataString("target/objectId eq '$UserId'")
    return , @(Get-GraphCollection -Uri "$em/assignments?`$filter=$f&`$expand=accessPackage" |
            Where-Object { [string]$_['state'] -in $activeStates })
}

# ---- Resolve the three managed packages (+ the policy used for adminAdd) ----
$pkg = [ordered]@{}
foreach ($key in $packageNames.Keys) {
    $name = $packageNames[$key]
    $f = [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'")
    $found = @(Get-GraphCollection -Uri "$em/accessPackages?`$filter=$f")
    if ($found.Count -ne 1) { throw "Expected exactly one access package named '$name', found $($found.Count). Apply Terraform envs/dev with enable_governance = true." }
    $id = [string]$found[0]['id']
    $full = Invoke-Graph -Method GET -Uri "$em/accessPackages/$id`?`$expand=assignmentPolicies"
    # REQUEST policies only: an automatic (birthright) policy is never used
    # for adminAdd (it carries automaticRequestSettings).
    $pols = @(@($full['assignmentPolicies']) | Where-Object { $null -ne $_ -and -not ($_.Contains('automaticRequestSettings') -and $null -ne $_['automaticRequestSettings']) })
    # Terraform names its request policy "<package> - <N> day"; prefer that if
    # someone added more policies in the portal.
    if ($pols.Count -gt 1) { $pols = @($pols | Where-Object { [string]$_['displayName'] -like "$name - * day" }) }
    $polId = if ($pols.Count -eq 1) { [string]$pols[0]['id'] } else { $null }
    $pkg[$key] = @{ Name = $name; Id = $id; PolicyId = $polId }
    Write-Verbose "Package $key = $name ($id), policy $polId"
}

# ---- Resolve the two people -----------------------------------------------
$state = [ordered]@{}
foreach ($p in $people.Keys) {
    try { $state[$p] = Get-Person -Upn $people[$p].Upn }
    catch { throw "$p <$($people[$p].Upn)> not found in Entra ($($_.Exception.Message)). Run inbound provisioning + Cloud Sync first (lab/scripts/mock-hr/README.md, lab/scripts/dc/README.md)." }
}

# =============================================================================
# 3. REMOVE packages that should not be there (safe to do immediately)
# =============================================================================
Write-Host "`n[3/6] Remove extra access packages" -ForegroundColor Cyan
foreach ($p in $people.Keys) {
    $uid = [string]$state[$p]['id']
    foreach ($a in (Get-ActiveAssignment -UserId $uid)) {
        $apId = [string]$a['accessPackage']['id']
        $key = @($pkg.Keys | Where-Object { $pkg[$_].Id -eq $apId }) | Select-Object -First 1
        if (-not $key) { continue }                                # outside the managed set: never touched
        if ($key -in $desired[$p].packages) { continue }           # wanted
        if ($birthright[$key]) {
            # HR-driven: the reset HR attributes make the automatic policy
            # remove it after its grace period. Never adminRemove.
            Write-Host "  [i] $p - '$($pkg[$key].Name)' is birthright: it leaves when the HR attributes stop matching its rule (after the grace period). Not removed here." -ForegroundColor DarkGray
            Add-Report 'Packages' $p "remove $($pkg[$key].Name)" 'birthright-hr-driven'
            continue
        }
        $apName = $pkg[$key].Name
        if ($PSCmdlet.ShouldProcess("$p <$($people[$p].Upn)>", "adminRemove '$apName'")) {
            try {
                $req = Invoke-Graph -Method POST -Uri "$em/assignmentRequests" -Body @{ requestType = 'adminRemove'; assignment = @{ id = [string]$a['id'] } }
                Write-Host "  [+] $p - adminRemove '$apName' (request $($req['id']))." -ForegroundColor Green
                Add-Report 'Packages' $p "remove $apName" 'requested'
            }
            catch {
                $msg = $_.Exception.Message
                # A re-run minutes after the previous one finds the assignment
                # still 'delivered' while its first adminRemove is processing.
                # verify: the exact error code Graph returns for a second
                # request on an assignment with an open request (matched
                # loosely, same as the adminAdd path below).
                if ($msg -match 'ExistingOpenRequest|already has|pending') {
                    Write-Host "  [=] $p - a removal of '$apName' is already in progress." -ForegroundColor DarkGray
                    Add-Report 'Packages' $p "remove $apName" 'already-pending'
                }
                else {
                    Write-Warning "  $p - adminRemove '$apName' failed: $msg"
                    Add-Report 'Packages' $p "remove $apName" 'FAILED'
                    $failures++
                }
            }
        }
        else { Add-Report 'Packages' $p "remove $apName" 'whatif' }
    }
}

# =============================================================================
# 4. (optional) WAIT for the HR change to reach Entra, then ADD packages
# =============================================================================
function Test-HrAttribute {
    param([string]$Person, [System.Collections.IDictionary]$User)
    $want = $desired[$Person]
    $wantEnabled = ($want.status -ne 'leaver')
    return ([string]$User['department'] -eq $want.dept) -and ([bool]$User['accountEnabled'] -eq $wantEnabled)
}

$deadline = (Get-Date).AddSeconds($WaitForSyncSeconds)
if ($WaitForSyncSeconds -gt 0 -and -not $WhatIfPreference) {
    Write-Host "`n[4/6] Waiting up to $WaitForSyncSeconds s for HR -> AD -> Cloud Sync (department / enabled)..." -ForegroundColor Cyan
    while ($true) {
        foreach ($p in $people.Keys) { $state[$p] = Get-Person -Upn $people[$p].Upn }
        $pending = @($people.Keys | Where-Object { -not (Test-HrAttribute -Person $_ -User $state[$_]) })
        if (-not $pending) { Write-Host '  [+] HR-owned attributes have landed in Entra.' -ForegroundColor Green; break }
        if ((Get-Date) -ge $deadline) { Write-Warning "  Timed out; still pending: $($pending -join ', '). Use Cloud sync -> Provision on demand."; break }
        Write-Host "  [i] Pending: $($pending -join ', ') - next check in 30 s." -ForegroundColor DarkGray
        Start-Sleep -Seconds 30
    }
}
else { Write-Host "`n[4/6] Not waiting for Cloud Sync (-WaitForSyncSeconds 0)." -ForegroundColor DarkGray }

Write-Host "`n[4/6] Add missing access packages" -ForegroundColor Cyan
foreach ($p in $people.Keys) {
    $uid = [string]$state[$p]['id']
    $haveIds = @((Get-ActiveAssignment -UserId $uid) | ForEach-Object { [string]$_['accessPackage']['id'] })
    foreach ($key in $desired[$p].packages) {
        $target = $pkg[$key]
        if ($birthright[$key]) {
            # HR-driven: delivered by the automatic policy once the reset HR
            # attributes match its rule. Never adminAdd.
            $st = if ($target.Id -in $haveIds) { 'birthright-held' } else { 'birthright-pending-hr' }
            Write-Host "  [i] $p - '$($target.Name)' is birthright ($st): the automatic policy assigns it from HR attributes. Not requested here." -ForegroundColor DarkGray
            Add-Report 'Packages' $p "add $($target.Name)" $st
            continue
        }
        if ($target.Id -in $haveIds) {
            Write-Host "  [=] $p already holds '$($target.Name)'." -ForegroundColor DarkGray
            Add-Report 'Packages' $p "add $($target.Name)" 'already-assigned'
            continue
        }
        if (-not $target.PolicyId) {
            Write-Warning "  '$($target.Name)' has no single assignment policy to request through. Fix the package policies, then re-run."
            Add-Report 'Packages' $p "add $($target.Name)" 'FAILED-no-policy'
            $failures++
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("$p <$($people[$p].Upn)>", "adminAdd '$($target.Name)'")) {
            Add-Report 'Packages' $p "add $($target.Name)" 'whatif'
            continue
        }
        try {
            $req = Invoke-Graph -Method POST -Uri "$em/assignmentRequests" -Body @{
                requestType = 'adminAdd'
                assignment  = @{ targetId = $uid; assignmentPolicyId = $target.PolicyId; accessPackageId = $target.Id }
            }
            Write-Host "  [+] $p - adminAdd '$($target.Name)' (request $($req['id']))." -ForegroundColor Green
            Add-Report 'Packages' $p "add $($target.Name)" 'requested'
        }
        catch {
            $msg = $_.Exception.Message
            # verify: exact error code for an already-open request (loose match).
            if ($msg -match 'ExistingOpenRequest|already has|pending') {
                Write-Host "  [=] $p - a request for '$($target.Name)' is already open." -ForegroundColor DarkGray
                Add-Report 'Packages' $p "add $($target.Name)" 'already-pending'
            }
            else {
                $hint = if ($state[$p]['accountEnabled'] -eq $false) { ' The account is still disabled in Entra - wait for Cloud Sync (or -WaitForSyncSeconds) and re-run.' } else { '' }
                Write-Warning "  $p - adminAdd '$($target.Name)' failed: $msg$hint"
                Add-Report 'Packages' $p "add $($target.Name)" 'FAILED'
                $failures++
            }
        }
    }
}

# =============================================================================
# 5. (optional) LICENSE - cloud-side, so a direct Graph write is correct here
# =============================================================================
Write-Host "`n[5/6] License" -ForegroundColor Cyan
if (-not $LicenseSkuPartNumber) {
    Write-Host '  [skip] No -LicenseSkuPartNumber; licenses not touched.' -ForegroundColor DarkGray
}
else {
    $sku = @(Get-GraphCollection -Uri "$graph/subscribedSkus" | Where-Object { [string]$_['skuPartNumber'] -eq $LicenseSkuPartNumber }) | Select-Object -First 1
    if (-not $sku) {
        Write-Warning "  SKU '$LicenseSkuPartNumber' is not owned by this tenant (GET /subscribedSkus)."
        Add-Report 'License' 'tenant' $LicenseSkuPartNumber 'FAILED-sku-not-found'
        $failures++
    }
    else {
        foreach ($p in $people.Keys) {
            $u = $state[$p]
            $has = @(@($u['assignedLicenses']) | Where-Object { $null -ne $_ -and [string]$_['skuId'] -eq [string]$sku['skuId'] })
            if ($has) { Add-Report 'License' $p $LicenseSkuPartNumber 'already-assigned'; continue }
            if (-not $PSCmdlet.ShouldProcess("$p <$($people[$p].Upn)>", "assign license $LicenseSkuPartNumber")) {
                Add-Report 'License' $p $LicenseSkuPartNumber 'whatif'
                continue
            }
            try {
                if (-not $u['usageLocation']) {
                    # Cloud-side attribute (not synced by Cloud Sync here), same as 02-Joiner.ps1.
                    Invoke-Graph -Method PATCH -Uri "$graph/users/$($u['id'])" -Body @{ usageLocation = $UsageLocation } | Out-Null
                }
                Invoke-Graph -Method POST -Uri "$graph/users/$($u['id'])/assignLicense" -Body @{
                    addLicenses    = @(@{ skuId = [string]$sku['skuId']; disabledPlans = @() })
                    removeLicenses = @()
                } | Out-Null
                Write-Host "  [+] $p - assigned $LicenseSkuPartNumber." -ForegroundColor Green
                Add-Report 'License' $p $LicenseSkuPartNumber 'assigned'
            }
            catch {
                Write-Warning "  $p - license assignment failed: $($_.Exception.Message)"
                Add-Report 'License' $p $LicenseSkuPartNumber 'FAILED'
                $failures++
            }
        }
    }
}

# =============================================================================
# 6. READINESS - expected vs actual (polls until the deadline if waiting)
# =============================================================================
Write-Host "`n[6/6] Readiness for the '$Segment' segment" -ForegroundColor Cyan
do {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $people.Keys) {
        $u = Get-Person -Upn $people[$p].Upn
        $want = $desired[$p]
        $haveKeys = @((Get-ActiveAssignment -UserId ([string]$u['id'])) |
                ForEach-Object { $apId = [string]$_['accessPackage']['id']; @($pkg.Keys | Where-Object { $pkg[$_].Id -eq $apId }) } |
                Where-Object { $_ } | Sort-Object -Unique)
        # Requestable packages are reset here and must match; birthright ones
        # follow HR and are listed for information (Ok = $true, Check says so).
        $wantReq = @($want.packages | Where-Object { -not $birthright[$_] } | Sort-Object -Unique)
        $haveReq = @($haveKeys | Where-Object { -not $birthright[$_] })
        $wantBr = @($want.packages | Where-Object { $birthright[$_] } | Sort-Object -Unique)
        $haveBr = @($haveKeys | Where-Object { $birthright[$_] })
        $rows.Add([pscustomobject]@{ Person = $p; Check = 'department'; Expected = $want.dept; Actual = [string]$u['department']; Ok = ([string]$u['department'] -eq $want.dept) })
        $rows.Add([pscustomobject]@{ Person = $p; Check = 'accountEnabled'; Expected = "$($want.status -ne 'leaver')"; Actual = "$($u['accountEnabled'])"; Ok = ([bool]$u['accountEnabled'] -eq ($want.status -ne 'leaver')) })
        $rows.Add([pscustomobject]@{ Person = $p; Check = 'requested packages'; Expected = ($wantReq -join ','); Actual = ($haveReq -join ','); Ok = (($wantReq -join ',') -eq ($haveReq -join ',')) })
        $rows.Add([pscustomobject]@{ Person = $p; Check = 'birthright (HR-driven, info)'; Expected = ($wantBr -join ','); Actual = ($haveBr -join ','); Ok = $true })
    }
    $notReady = @($rows | Where-Object { -not $_.Ok })
    $keepWaiting = $notReady -and $WaitForSyncSeconds -gt 0 -and -not $WhatIfPreference -and (Get-Date) -lt $deadline
    if ($keepWaiting) { Write-Host "  [i] $($notReady.Count) check(s) pending - next check in 30 s." -ForegroundColor DarkGray; Start-Sleep -Seconds 30 }
} while ($keepWaiting)

$rows | Format-Table -AutoSize | Out-Host
if (-not $notReady) {
    Write-Host "READY - roll the camera for '$Segment'." -ForegroundColor Green
    Add-Report 'Readiness' 'Dana + Marcus' $Segment 'READY'
}
else {
    Write-Warning ("NOT READY: $($notReady.Count) check(s) differ. HR-owned values (department / accountEnabled) arrive via Cloud Sync " +
        '(~10-20 min per cycle; use Cloud sync -> Provision on demand), package changes take a few minutes to deliver. Re-run this script to re-check.')
    Add-Report 'Readiness' 'Dana + Marcus' $Segment 'NOT-READY'
}

$report | Format-Table -AutoSize | Out-Host
if ($failures) { Write-Warning "$failures step(s) failed - see the table."; exit 1 }
return $report
