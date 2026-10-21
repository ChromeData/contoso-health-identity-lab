<#
.SYNOPSIS
    VERIFIES a MOVER (and is the fallback for requestable access): a worker
    whose department/title changed. Confirms the new department has landed
    (HR -> AD -> Cloud Sync for hybrid users), then confirms the old
    birthright package is on its way out and the new one has arrived - both
    driven by the HR attribute through automatic assignment policies. Only a
    REQUESTABLE (T2) package is removed / requested by this script.

.DESCRIPTION
    A "mover" is not a status flag in the HR feed; it is an *active* worker whose
    dept/title now differs from what the directory holds (see ../mock-hr/README.md).
    Default subject is Marcus Bello, who ships in hr_feed.csv as Nursing; the
    demo edits his row to ICU and re-runs inbound provisioning.

    WHO OWNS THE ATTRIBUTE (hybrid-aware)
      * Synced user (onPremisesSyncEnabled = true) -- the lab default. HR is the
        source of truth: the department change flows HR feed -> AD -> Cloud Sync
        -> Entra. Entra REJECTS cloud edits to on-prem-mastered attributes, so
        this script does NOT write department; it WAITS for the synced value.
      * Cloud-only user -- there is no upstream, so the script writes the
        department itself (Update-MgUser).

    THE MOVER IS DRIVEN BY THE HR ATTRIBUTE (ADR 0012, T3 birthright)
      Nurse and ICU packages are automatic: their assignment policies
      (post-apply/Set-AutoAssignmentPolicies.ps1, lab/iga/birthright-rules.json)
      assign the package while the department/title rule matches and remove
      it after the grace period once it stops matching. So the department
      change alone moves the access. This script never adminRemoves or
      adminAdds an automatic package (lab/iga/access-catalog.json decides);
      it verifies, and falls back to requests only for T2 packages.

    STEPS
      1. ATTRIBUTE -- confirm (synced) or set (cloud-only) the new department.
         This single change re-drives everything attribute-based: All-Nurses
         drops the user, All-ICU picks them up, and the birthright packages
         follow. No manual group or package churn.
      2. OLD ACCESS
           automatic  verify: not held, or still held inside the grace period
                      (gracePeriodBeforeAccessRemoval) - the policy removes it.
           request    fallback: adminRemove the delivered assignment.
      3. NEW ACCESS
           automatic  verify: wait (-WaitForAssignmentSeconds) for the new
                      package to be Delivered by its automatic policy.
           request    fallback: adminAdd through the package's REQUEST policy.

    Net effect: least privilege is preserved across the move -- old-role access
    is removed by the policy (or, for requested access, by this script), not
    left to accumulate (the classic "access creep" audit finding). The closing
    line states what each step actually found or did; anything short of that
    is a warning and exit 1, never "complete".

.PREREQUISITES
    * Terraform envs/dev applied with enable_premium + enable_governance (both
      packages + All-Nurses/All-ICU exist).
    * For a synced user: hr_feed.csv row edited and
      ../mock-hr/Invoke-InboundProvisioning.ps1 -StatusFilter active re-run.
    * Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
      Microsoft.Graph.Identity.Governance.

.GRAPH SCOPES  (delegated; admin-consent)
    User.ReadWrite.All                   read user; write department (cloud-only users)
    EntitlementManagement.ReadWrite.All  read assignments; adminRemove / adminAdd (T2 only)
    Directory.Read.All                   reads

.PARAMETER UserPrincipalName
    The mover. Defaults to the roster mover marcus.bello@contosohealth.io.

.PARAMETER NewDepartment
    The department the user is moving into. Default 'ICU'.

.PARAMETER NewJobTitle
    Optional new title (cloud-only users; for synced users it comes from HR).

.PARAMETER OldAccessPackageName
    The old role's package. Default 'Nurse - Clinical Apps' (automatic:
    verified, never removed by this script).

.PARAMETER NewAccessPackageName
    The new role's package. Default 'ICU - Critical Care Apps' (automatic:
    verified, never requested by this script).

.PARAMETER CatalogPath
    lab/iga/access-catalog.json (automatic vs request per package).

.PARAMETER WaitForAssignmentSeconds
    Automatic new package: how long to wait for delivery. Default 900.

.PARAMETER PollSeconds
    Poll interval while waiting. Default 30.

.PARAMETER WaitForSyncSeconds
    Synced users only: how long to poll for the new department to arrive from
    AD before giving up. Default 1500 (Cloud Sync provisions users roughly every
    10-20 minutes per Microsoft's Cloud Sync FAQ; use
    "Provision on demand" to skip the wait on camera).

.PARAMETER WhatIf
    Standard. Prints intended changes, performs none.

.EXAMPLE
    # 1) edit Marcus's row in hr_feed.csv to dept=ICU, then:
    ../mock-hr/Invoke-InboundProvisioning.ps1 -ServicePrincipalId <sp> -JobId <job> -StatusFilter active
    # 2) re-evaluate access:
    Connect-MgGraph -Scopes 'User.ReadWrite.All','EntitlementManagement.ReadWrite.All','Directory.Read.All'
    ./03-Mover.ps1 -UserPrincipalName 'marcus.bello@contosohealth.io' -NewDepartment 'ICU'

.WHAT IT DEMONSTRATES
    Attribute-driven re-provisioning with a single source of truth: one HR
    change cascades through AD, dynamic groups and automatic access-package
    policies - and the script PROVES the old access goes and the new access
    arrives, instead of hand-moving packages.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN/email.')]
    [string]$UserPrincipalName = 'marcus.bello@contosohealth.io',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NewDepartment = 'ICU',

    [Parameter()]
    [string]$NewJobTitle,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OldAccessPackageName = 'Nurse - Clinical Apps',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NewAccessPackageName = 'ICU - Critical Care Apps',

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$WaitForSyncSeconds = 1500,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'access-catalog.json'),

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$WaitForAssignmentSeconds = 900,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 30
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

# Pure helpers - identical copies in 02-Joiner.ps1 (parity-tested).
function Get-PackageAssignmentModel {
    # 'automatic' | 'request' for a package in lab/iga/access-catalog.json.
    # A package the catalog does not know is an error: guessing "request"
    # would adminAdd a birthright package, guessing "automatic" would wait
    # for an assignment nothing creates.
    param([Parameter(Mandatory)][string]$CatalogPath, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) { throw "Access catalog not found: $CatalogPath" }
    $cat = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json -AsHashtable
    $e = @(@($cat['accessPackages']) | Where-Object { $_ -and [string]$_['name'] -eq $Name }) | Select-Object -First 1
    if (-not $e) { throw "Access package '$Name' is not in $CatalogPath; add it there (tier + assignment) first." }
    $m = [string]$e['assignment']
    if ($m -notin 'automatic', 'request') { throw "Access package '$Name' has assignment '$m' in the catalog (expected automatic or request)." }
    return $m
}

function Test-IsAutomaticPolicy {
    # True for an automatic (attribute-rule) assignment policy: it carries
    # automaticRequestSettings. Works on SDK objects and Graph hashtables.
    param($Policy)
    if ($null -eq $Policy) { return $false }
    if ($Policy -is [System.Collections.IDictionary]) { return [bool]($Policy.Contains('automaticRequestSettings') -and $null -ne $Policy['automaticRequestSettings']) }
    $p = $Policy.PSObject.Properties['AutomaticRequestSettings']
    if ($p -and $null -ne $p.Value) { return $true }
    $ap = $Policy.PSObject.Properties['AdditionalProperties']
    return [bool]($ap -and $ap.Value -is [System.Collections.IDictionary] -and $ap.Value.Contains('automaticRequestSettings') -and $null -ne $ap.Value['automaticRequestSettings'])
}

# Both models are read up front: an unknown package stops the run before anything changes.
$oldModel = Get-PackageAssignmentModel -CatalogPath $CatalogPath -Name $OldAccessPackageName
$newModel = Get-PackageAssignmentModel -CatalogPath $CatalogPath -Name $NewAccessPackageName

$requiredScopes = @('User.ReadWrite.All', 'EntitlementManagement.ReadWrite.All', 'Directory.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 and lookups may report 'not found' (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

$userProps = 'id,displayName,department,jobTitle,onPremisesSyncEnabled'
$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property $userProps -ErrorAction SilentlyContinue
if (-not $user) { throw "User '$UserPrincipalName' not found." }
$isSynced = [bool]$user.OnPremisesSyncEnabled
Write-Console "Mover: $($user.DisplayName) <$UserPrincipalName> ($(if ($isSynced) { 'synced from AD - HR owns department' } else { 'cloud-only' }))" -ForegroundColor Cyan
Write-Console "  department now '$($user.Department)' -> target '$NewDepartment'" -ForegroundColor Cyan

# ===========================================================================
# 1. ATTRIBUTE (confirm for synced users; set for cloud-only users)
# ===========================================================================
Write-Console "`n[1/3] Department attribute" -ForegroundColor Cyan
$attributeLanded = $false
if ($user.Department -eq $NewDepartment -and (-not $NewJobTitle -or $user.JobTitle -eq $NewJobTitle)) {
    Write-Console "  [=] Already '$NewDepartment'$(if ($NewJobTitle) { " / '$NewJobTitle'" })." -ForegroundColor DarkGray
    $attributeLanded = $true
}
elseif ($isSynced) {
    # Entra rejects writes to on-prem-mastered attributes. The change must come
    # from HR -> AD; we only wait for Cloud Sync to deliver it.
    if ($WhatIfPreference) {
        Write-Console "  [whatif] Would wait up to $WaitForSyncSeconds s for department '$NewDepartment' to sync from AD." -ForegroundColor DarkYellow
    }
    else {
        Write-Console "  [i] Waiting up to $WaitForSyncSeconds s for HR -> AD -> Cloud Sync to deliver '$NewDepartment'..." -ForegroundColor Yellow
        $deadline = (Get-Date).AddSeconds($WaitForSyncSeconds)
        while ((Get-Date) -lt $deadline) {
            $user = Get-MgUser -UserId $user.Id -Property $userProps
            if ($user.Department -eq $NewDepartment) { $attributeLanded = $true; break }
            Start-Sleep -Seconds 30
        }
        if ($attributeLanded) { Write-Console "  [+] Department '$NewDepartment' arrived from AD." -ForegroundColor Green }
        else {
            Write-Warning "  Department is still '$($user.Department)'. Did you edit hr_feed.csv and re-run Invoke-InboundProvisioning.ps1? Use Cloud sync -> Provision on demand to skip the 10-20 minute cycle. Birthright packages follow the attribute, so they cannot move until it arrives; requestable packages are still swapped (access must follow the HR decision)."
        }
    }
}
elseif ($PSCmdlet.ShouldProcess($UserPrincipalName, "set department='$NewDepartment'$(if($NewJobTitle){", title='$NewJobTitle'"})")) {
    $patch = @{ Department = $NewDepartment }
    if ($NewJobTitle) { $patch.JobTitle = $NewJobTitle }
    Update-MgUser -UserId $user.Id -BodyParameter $patch
    $attributeLanded = $true
    Write-Console "  [+] Updated (cloud-only user). Dynamic groups re-evaluate asynchronously (All-Nurses drops; All-ICU adds)." -ForegroundColor Green
}

# ===========================================================================
# 2. OLD ACCESS  (automatic: verify; request: adminRemove fallback)
# ===========================================================================
Write-Console "`n[2/3] Old access package ('$OldAccessPackageName', $oldModel)" -ForegroundColor Cyan
# Each step records what actually happened; the closing line is built from
# these, so the script never claims a removal or request it did not make.
# Lookups use -ErrorAction Stop: a failed query must not read as "none held".
$getHeld = {
    param([string]$PackageId)
    @(Get-MgEntitlementManagementAssignment -All `
            -Filter "accessPackage/id eq '$PackageId' and target/objectId eq '$($user.Id)'" -ExpandProperty 'target', 'accessPackage' -ErrorAction Stop |
            Where-Object { $_ -and $_.State -in 'delivered', 'delivering', 'partiallyDelivered' })
}
$removeState = 'package-missing'
$oldAp = Get-MgEntitlementManagementAccessPackage -Filter "displayName eq '$OldAccessPackageName'" -ErrorAction Stop
if (-not $oldAp) {
    Write-Warning "  Old package '$OldAccessPackageName' not found; cannot confirm the user no longer holds it."
}
else {
    # v1.0 filters on the accessPackage/id navigation path (an accessPackageId
    # filter is beta-only). verify: filter shape is from the v1.0
    # list-assignments docs; not yet run against a live tenant.
    $assignment = & $getHeld $oldAp.Id | Select-Object -First 1
    if (-not $assignment) {
        Write-Console "  [=] No active '$OldAccessPackageName' assignment." -ForegroundColor DarkGray
        $removeState = 'none-held'
    }
    elseif ($oldModel -eq 'automatic') {
        # BIRTHRIGHT: the automatic policy removes it once the rule stops
        # matching, after its grace period. Never adminRemove (the HR
        # attribute is the control; a manual removal would be re-added while
        # the rule still matches, or race the policy).
        $note = if ($attributeLanded) { 'the rule no longer matches; the automatic policy removes it after its grace period (gracePeriodBeforeAccessRemoval, lab/iga/birthright-rules.json)' } else { 'the department has NOT changed in Entra yet, so the rule still matches - it stays until HR -> AD -> Cloud Sync delivers the move' }
        Write-Console "  [i] Still held ($($assignment.State)): $note. Nothing sent." -ForegroundColor Yellow
        $removeState = if ($attributeLanded -or $WhatIfPreference) { 'auto-pending' } else { 'auto-blocked' }
    }
    elseif ($PSCmdlet.ShouldProcess($UserPrincipalName, "adminRemove '$OldAccessPackageName' (requestable access)")) {
        # FALLBACK for requested (T2) access: adminRemove references the
        # ASSIGNMENT id (not the package id).
        $removeReq = New-MgEntitlementManagementAssignmentRequest -BodyParameter @{
            requestType = 'adminRemove'
            assignment  = @{ id = $assignment.Id }
        }
        Write-Console "  [+] Submitted adminRemove request $($removeReq.Id) (state: $($removeReq.State))." -ForegroundColor Green
        $removeState = 'submitted'
    }
    else { $removeState = 'skipped' }
}

# ===========================================================================
# 3. NEW ACCESS  (automatic: verify delivery; request: adminAdd fallback)
# ===========================================================================
Write-Console "`n[3/3] New access package ('$NewAccessPackageName', $newModel)" -ForegroundColor Cyan
$addState = 'package-missing'
$newAp = Get-MgEntitlementManagementAccessPackage -Filter "displayName eq '$NewAccessPackageName'" -ErrorAction Stop
if (-not $newAp) {
    Write-Warning "  New package '$NewAccessPackageName' not found. Apply Terraform envs/dev with enable_governance = true, then re-run."
}
else {
    # Policies via the package (accessPackages/{id}?$expand=assignmentPolicies),
    # the documented v1.0 path that also works for catalog-scoped admins.
    $policies = @(@((Get-MgEntitlementManagementAccessPackage -AccessPackageId $newAp.Id -ExpandProperty 'assignmentPolicies' -ErrorAction Stop).AssignmentPolicies) | Where-Object { $null -ne $_ })
    $already = & $getHeld $newAp.Id
    if ($already) {
        Write-Console "  [=] User already has '$NewAccessPackageName' ($($already[0].State))$(if ($newModel -eq 'automatic') { ' - delivered by the automatic (birthright) policy' })." -ForegroundColor Green
        $addState = 'already-held'
    }
    elseif ($newModel -eq 'automatic') {
        if (-not @($policies | Where-Object { Test-IsAutomaticPolicy $_ })) {
            Write-Warning "  '$NewAccessPackageName' is birthright but has no automatic policy. Run post-apply/Set-AutoAssignmentPolicies.ps1. No request was sent."
            $addState = 'no-policy'
        }
        elseif ($WhatIfPreference) {
            Write-Console "  [whatif] Birthright package: would wait up to $WaitForAssignmentSeconds s for the automatic policy to deliver it. No request is ever sent." -ForegroundColor DarkYellow
            $addState = 'skipped'
        }
        else {
            # Bounded by attempts, not the clock.
            $attempts = if ($attributeLanded) { [int][math]::Ceiling($WaitForAssignmentSeconds / $PollSeconds) } else { 0 }
            for ($i = 0; -not $already -and $i -lt $attempts; $i++) {
                Write-Console "  [i] Waiting for the automatic (birthright) assignment - next check in $PollSeconds s." -ForegroundColor DarkGray
                Start-Sleep -Seconds $PollSeconds
                $already = & $getHeld $newAp.Id
            }
            if ($already) { Write-Console "  [+] '$NewAccessPackageName' $($already[0].State) by the automatic (birthright) policy." -ForegroundColor Green; $addState = 'auto-delivered' }
            else {
                Write-Warning "  '$NewAccessPackageName' not delivered$(if ($attributeLanded) { " within $WaitForAssignmentSeconds s" } else { ' (the department has not arrived, so its rule cannot match yet)' }). Check department / job title against lab/iga/birthright-rules.json and that employeeHireDate is set. No adminAdd is sent for a birthright package."
                $addState = 'auto-not-delivered'
            }
        }
    }
    else {
        # FALLBACK for requestable (T2) access: adminAdd through the REQUEST policy.
        $policy = @($policies | Where-Object { -not (Test-IsAutomaticPolicy $_) }) | Select-Object -First 1
        if (-not $policy) {
            Write-Warning "  No request policy for '$NewAccessPackageName'."
            $addState = 'no-policy'
        }
        elseif ($PSCmdlet.ShouldProcess($UserPrincipalName, "adminAdd '$NewAccessPackageName' (requestable access)")) {
            $addReq = New-MgEntitlementManagementAssignmentRequest -BodyParameter @{
                requestType = 'adminAdd'
                assignment  = @{
                    targetId           = $user.Id
                    accessPackageId    = $newAp.Id
                    assignmentPolicyId = $policy.Id
                }
            }
            Write-Console "  [+] Submitted adminAdd request $($addReq.Id) (state: $($addReq.State))." -ForegroundColor Green
            $addState = 'submitted'
        }
        else { $addState = 'skipped' }
    }
}

# Closing line reports the recorded outcomes. Anything short of "removal
# submitted / none held" + "request submitted / already held" exits 1
# (a -WhatIf dry run, which skips both by design, is the only exception).
$removeText = @{
    'submitted' = 'removal submitted'; 'none-held' = 'none held'
    'auto-pending' = 'birthright removal pending (automatic policy, grace period)'
    'auto-blocked' = 'STILL HELD (department not synced, birthright rule still matches)'
    'skipped' = 'NOT removed (WhatIf/declined)'; 'package-missing' = 'NOT verified (old package not found)'
}[$removeState]
$addText = @{
    'submitted' = 'request submitted'; 'already-held' = 'already held'; 'auto-delivered' = 'delivered by the birthright policy'
    'auto-not-delivered' = 'NOT delivered (birthright rule has not matched)'
    'skipped' = 'NOT requested (WhatIf/declined)'; 'package-missing' = 'NOT requested (new package not found)'
    'no-policy' = 'NOT delivered (no usable assignment policy)'
}[$addState]
$attrNote = if ($attributeLanded -or $WhatIfPreference) { '' } else { ' (department NOT yet synced - recheck All-ICU membership later)' }
$summary = "Old-role access: $removeText; new-role access: $addText$attrNote."
$removeOk = ($removeState -in 'submitted', 'none-held', 'auto-pending') -or ($WhatIfPreference -and $removeState -eq 'skipped')
$addOk = ($addState -in 'submitted', 'already-held', 'auto-delivered') -or ($WhatIfPreference -and $addState -eq 'skipped')
if ($removeOk -and $addOk) {
    Write-Console "`nMover $(if ($WhatIfPreference) { 'dry run' } else { 'complete' }) for $UserPrincipalName. $summary" -ForegroundColor Cyan
}
else {
    Write-Warning "Mover INCOMPLETE for $UserPrincipalName. $summary"
    exit 1
}
