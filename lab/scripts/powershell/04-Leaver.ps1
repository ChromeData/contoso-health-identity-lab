<#
.SYNOPSIS
    Processes a LEAVER (default: Dana Okafor on termination). Confirms the
    account is disabled (HR -> AD -> Cloud Sync for hybrid users), revokes all
    sessions, removes every access package, strips remaining group + app
    assignments, optionally forces deprovisioning in SCIM apps, hands the apps
    and service principals the leaver OWNS to their manager, and emits a
    per-system timestamped offboarding report.

.DESCRIPTION
    Video segment 7, "Leaver". Offboarding is the step most orgs do by hand and
    get wrong, so this script makes every downstream revocation explicit and
    timestamped -- which is exactly what a HIPAA/SOX auditor asks to see.

    WHO OWNS "DISABLED" (hybrid-aware)
      * Synced user (onPremisesSyncEnabled = true) -- the lab default. HR marks
        the worker 'leaver'; inbound provisioning disables the AD account;
        Cloud Sync carries accountEnabled=false to Entra. Entra REJECTS a cloud
        write to accountEnabled on a synced user, so this script WAITS for it.
      * Cloud-only user -- the script disables the account itself.

    ACTIONS (in deliberate order -- contain first, then clean up)
      1. CONTAIN   -- confirm (synced) or set (cloud-only) accountEnabled=false.
      2. REVOKE    -- revokeSignInSessions: kills EXISTING refresh tokens and
                      session cookies so an already-signed-in browser/app stops
                      working. Runs even if step 1 is still pending.
      3. PACKAGES  -- adminRemove EVERY delivered access-package assignment
                      (the governed revocation, recorded in the audit log).
      4. GROUPS    -- remove any remaining ASSIGNED cloud group memberships
                      (dynamic groups drop on the accountEnabled rule; groups
                      synced from AD are owned by AD and skipped).
      5. APPS      -- delete direct app-role assignments.
      6. SCIM      -- optional: "provision on demand" in each named enterprise
                      app so ServiceNow / AWS can disable the user NOW instead
                      of on the next ~40-minute provisioning cycle. The API
                      returns 200 even when it skips, so the report records the
                      real result (success:<action> / SKIPPED:<code> / FAILED-*).
                      verify: provision on demand for a user who is both
                      unassigned AND already disabled in Entra -- Microsoft lists
                      on-demand disable of Entra-disabled users as a known
                      limitation (learn.microsoft.com/entra/identity/
                      app-provisioning/provision-on-demand#known-limitations).
                      Dry-run it in the tenant before recording.
      7. NHI       -- non-human identities the leaver OWNS (ownedObjects: app
                      registrations, service principals, Agent ID blueprints
                      and agent identities). An NHI's owners are the only
                      people who rotate its credentials, so a leaver who owns
                      one leaves an orphan (OWASP NHI1; nhi-standard N9).
                      DEFAULT (-NhiHandoff FlagOnly): report what the leaver
                      owns, change nothing, need no extra Graph scope.
                      Opt-in (-NhiHandoff ReassignToManager, once NHI
                      governance is on): the new owner (the leaver's manager,
                      or -NhiNewOwnerUserPrincipalName) is ADDED first and the
                      leaver REMOVED second, so no object is ever ownerless -
                      but ONLY for low-privilege NHIs. An owner can add a
                      secret and act as the app, so an app with a Tier-0
                      Graph permission or any directory role is never handed
                      to a (possibly non-technical) manager: it is FLAGGED
                      FLAGGED-privileged-owner-review for the app-governance
                      owners (the OwnerOfTierZeroApp path Find-ShadowAdmins.ps1
                      reports). A privilege check that cannot complete also
                      flags (fail closed). No manager -> FLAGGED, never guessed. An NHI holding a
                      secret or certificate is FLAGGED for rotation (the leaver
                      could have seen it). Owned GROUPS are flagged for review,
                      not changed (a role-assignable group's owner is a shadow
                      admin, see Find-ShadowAdmins.ps1). This runs after SCIM:
                      containment already happened in steps 1-2, and SCIM
                      stays step 6 with its timing unchanged.
      8. REPORT    -- one row per action with a UTC timestamp and the elapsed
                      time first-to-last; optional CSV for the evidence pack.

    IDEMPOTENT: each step checks current state; re-running a completed leaver is
    a no-op that still reports timestamps for what is already done.

.PREREQUISITES
    * Synced users: hr_feed.csv row set to status=leaver and
      ../mock-hr/Invoke-InboundProvisioning.ps1 -StatusFilter leaver re-run.
    * Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
      Microsoft.Graph.Users.Actions (Revoke-MgUserSignInSession),
      Microsoft.Graph.Groups (Remove-MgGroupMemberDirectoryObjectByRef),
      Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance.

.GRAPH SCOPES  (delegated; admin-consent)
    User.ReadWrite.All                    read user; disable (cloud-only users)
    User.RevokeSessions.All               revokeSignInSessions
    GroupMember.ReadWrite.All             remove group memberships
    AppRoleAssignment.ReadWrite.All       delete app-role assignments
    Application.Read.All                  resolve enterprise apps
    EntitlementManagement.ReadWrite.All   adminRemove access packages
    Synchronization.ReadWrite.All         provision on demand (only with -ProvisionOnDemandApps)
    Application.ReadWrite.All             add/remove owners on owned apps + service
                                          principals (step 7; ONLY with the opt-in
                                          -NhiHandoff ReassignToManager - not
                                          requested by default). Delegated, so the
                                          signed-in admin's role (Cloud Application
                                          Administrator) still bounds it.
                                          verify: least-privileged scope for owner $ref
    Directory.Read.All                    reads (incl. ownedObjects + manager)

.PARAMETER UserPrincipalName
    The leaver. Defaults to dana.okafor@contosohealth.io.

.PARAMETER WaitForDisableSeconds
    Synced users only: how long to poll for accountEnabled=false to arrive from
    AD. Default 1500 (Cloud Sync's user cycle is ~10-20 min). Use Cloud sync ->
    Provision on demand to skip the wait.

.PARAMETER ProvisionOnDemandApps
    Display names of SCIM/provisioning-enabled enterprise apps to deprovision
    immediately, e.g. 'ServiceNow','AWS IAM Identity Center'. Default: none.

.PARAMETER NhiHandoff
    Step 7. FlagOnly (default): report what the leaver owns and change nothing
    (no Application.ReadWrite.All needed). ReassignToManager (opt-in, with the
    NHI governance flag on): add the new owner, then remove the leaver - for
    low-privilege NHIs only; Tier-0 / role-holding ones are always flagged.

.PARAMETER NhiNewOwnerUserPrincipalName
    Step 7 new owner. Default: the leaver's manager in Entra (from HR).

.PARAMETER ReportPath
    Optional CSV path for the timestamped report (keep it under the gitignored
    lab/evidence/out/ - it contains tenant data).

.PARAMETER WhatIf
    Standard. Prints intended revocations (and a dry-run report), changes nothing.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.ReadWrite.All','User.RevokeSessions.All','GroupMember.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Application.Read.All','EntitlementManagement.ReadWrite.All','Synchronization.ReadWrite.All','Directory.Read.All'
    ./04-Leaver.ps1 -WhatIf
    ./04-Leaver.ps1 -ProvisionOnDemandApps 'ServiceNow','AWS IAM Identity Center' -ReportPath ../../evidence/out/leaver_dana.csv

.OUTPUTS
    [pscustomobject] rows: System, Action, Status, TimestampUtc.

.WHAT IT DEMONSTRATES
    Minutes-not-days offboarding with a single source of truth (HR), covering
    every downstream system with a defensible, timestamped audit trail -- the
    concrete HIPAA/SOX least-privilege-on-exit control -- and no workload
    identity left without an accountable owner.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN/email.')]
    [string]$UserPrincipalName = 'dana.okafor@contosohealth.io',

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$WaitForDisableSeconds = 1500,

    [Parameter()]
    [string[]]$ProvisionOnDemandApps = @(),

    [Parameter()]
    [ValidateSet('ReassignToManager', 'FlagOnly')]
    [string]$NhiHandoff = 'FlagOnly',

    [Parameter()]
    [string]$NhiNewOwnerUserPrincipalName = '',

    [Parameter()]
    [string]$ReportPath = ''
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

$requiredScopes = @(
    'User.ReadWrite.All', 'User.RevokeSessions.All', 'GroupMember.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All', 'Application.Read.All',
    'EntitlementManagement.ReadWrite.All', 'Directory.Read.All'
)
if ($ProvisionOnDemandApps) { $requiredScopes += 'Synchronization.ReadWrite.All' }
if ($NhiHandoff -eq 'ReassignToManager') { $requiredScopes += 'Application.ReadWrite.All' }
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = $requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes }
if ($missingScopes) { Write-Warning "Connected context is missing scope(s): $($missingScopes -join ', '). Revocation reads/writes may fail with 403 (recorded as FAILED in the report)." }

$userProps = 'id,displayName,accountEnabled,onPremisesSyncEnabled'
$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property $userProps -ErrorAction SilentlyContinue
if (-not $user) { throw "User '$UserPrincipalName' not found." }
$isSynced = [bool]$user.OnPremisesSyncEnabled
Write-Console "Leaver: $($user.DisplayName) <$UserPrincipalName> ($(if ($isSynced) { 'synced from AD - HR owns account state' } else { 'cloud-only' }))" -ForegroundColor Cyan

# Collect per-system results for the offboarding report.
$report = [System.Collections.Generic.List[object]]::new()
function Add-Report {
    param([string]$System, [string]$Action, [string]$Status)
    $report.Add([pscustomobject]@{
        System       = $System
        Action       = $Action
        Status       = $Status
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    })
}

# ===========================================================================
# 1. CONTAIN: ACCOUNT DISABLED
# ===========================================================================
Write-Console "`n[1/8] Account disabled" -ForegroundColor Cyan
if ($user.AccountEnabled -eq $false) {
    Write-Console "  [=] Already disabled$(if ($isSynced) { ' (arrived from AD via Cloud Sync)' })." -ForegroundColor Green
    Add-Report 'Entra ID' 'Disable account' $(if ($isSynced) { 'disabled-by-hr-sync' } else { 'already-disabled' })
}
elseif ($isSynced) {
    if ($WhatIfPreference) {
        Write-Console "  [whatif] Would wait up to $WaitForDisableSeconds s for HR -> AD -> Cloud Sync to disable the account." -ForegroundColor DarkYellow
        Add-Report 'Entra ID' 'Disable account' 'whatif'
    }
    else {
        Write-Console "  [i] Waiting up to $WaitForDisableSeconds s for the HR-driven disable to sync from AD..." -ForegroundColor Yellow
        $deadline = (Get-Date).AddSeconds($WaitForDisableSeconds)
        while ((Get-Date) -lt $deadline) {
            $user = Get-MgUser -UserId $user.Id -Property $userProps
            if ($user.AccountEnabled -eq $false) { break }
            Start-Sleep -Seconds 15
        }
        if ($user.AccountEnabled -eq $false) {
            Write-Console "  [+] Disabled (HR -> AD -> Cloud Sync)." -ForegroundColor Green
            Add-Report 'Entra ID' 'Disable account' 'disabled-by-hr-sync'
        }
        else {
            Write-Warning "  STILL ENABLED. Set Dana's hr_feed.csv row to status=leaver, run Invoke-InboundProvisioning.ps1 -StatusFilter leaver, then Cloud sync -> Provision on demand. Continuing to revoke sessions and access now (contain what we can)."
            Add-Report 'Entra ID' 'Disable account' 'PENDING-HR-SYNC'
        }
    }
}
elseif ($PSCmdlet.ShouldProcess($UserPrincipalName, 'disable account')) {
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    Write-Console "  [+] Account disabled (cloud-only user)." -ForegroundColor Green
    Add-Report 'Entra ID' 'Disable account' 'disabled'
}
else { Add-Report 'Entra ID' 'Disable account' 'whatif' }

# ===========================================================================
# 2. REVOKE SESSIONS  (kill existing tokens)
# ===========================================================================
Write-Console "`n[2/8] Revoke sessions" -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'revoke all sign-in sessions / refresh tokens')) {
    # POST /users/{id}/revokeSignInSessions (needs User.RevokeSessions.All).
    # Resets signInSessionsValidFromDateTime, so every refresh token and
    # session cookie issued before now is rejected at next use.
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    Write-Console "  [+] Sessions/refresh tokens revoked." -ForegroundColor Green
    Add-Report 'Entra ID' 'Revoke sessions' 'revoked'
}
else { Add-Report 'Entra ID' 'Revoke sessions' 'whatif' }

# ===========================================================================
# 3. REMOVE EVERY ACCESS PACKAGE ASSIGNMENT  (adminRemove)
# ===========================================================================
Write-Console "`n[3/8] Remove access packages" -ForegroundColor Cyan
# Reads in steps 3-6 use -ErrorAction Stop: a failed query (e.g. 403) must not
# read as "nothing held" in the audit report. It is recorded as FAILED-read.
$assignments = @(); $readOk = $true
try {
    $assignments = @(Get-MgEntitlementManagementAssignment -Filter "target/objectId eq '$($user.Id)'" `
            -ExpandProperty 'target,accessPackage' -All -ErrorAction Stop |
        Where-Object { $_.State -in 'delivered', 'delivering', 'partiallyDelivered' })
}
catch {
    $readOk = $false
    Write-Warning "  Could not read access-package assignments: $($_.Exception.Message)"
    Add-Report 'Entitlement Mgmt' 'adminRemove' 'FAILED-read'
}
if ($readOk -and $assignments.Count -eq 0) {
    Write-Console "  [=] No active access-package assignments." -ForegroundColor DarkGray
    Add-Report 'Entitlement Mgmt' 'adminRemove' 'none-active'
}
foreach ($a in $assignments) {
    $apName = if ($a.AccessPackage) { [string]$a.AccessPackage.DisplayName } else { [string]$a.Id }
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "adminRemove '$apName'")) {
        $removeReq = New-MgEntitlementManagementAssignmentRequest -BodyParameter @{
            requestType = 'adminRemove'
            assignment  = @{ id = $a.Id }
        }
        Write-Console "  [+] adminRemove '$apName' -> request $($removeReq.Id)." -ForegroundColor Green
        Add-Report "AccessPackage:$apName" 'adminRemove' "requested:$($removeReq.Id)"
    }
    else { Add-Report "AccessPackage:$apName" 'adminRemove' 'whatif' }
}

# ===========================================================================
# 4. REMOVE REMAINING ASSIGNED CLOUD GROUP MEMBERSHIPS
# ===========================================================================
Write-Console "`n[4/8] Remove remaining group memberships" -ForegroundColor Cyan
$memberships = @(); $readOk = $true
try {
    $memberships = @(Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction Stop |
        Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' })
}
catch {
    $readOk = $false
    Write-Warning "  Could not read group memberships: $($_.Exception.Message)"
    Add-Report 'Groups' 'Remove membership' 'FAILED-read'
}
if ($readOk -and $memberships.Count -eq 0) {
    Write-Console "  [=] No group memberships." -ForegroundColor DarkGray
    Add-Report 'Groups' 'Remove membership' 'none'
}
foreach ($m in $memberships) {
    $gName  = [string]$m.AdditionalProperties['displayName']
    $gTypes = @($m.AdditionalProperties['groupTypes'])
    $gSynced = $m.AdditionalProperties.ContainsKey('onPremisesSyncEnabled') -and [bool]$m.AdditionalProperties['onPremisesSyncEnabled']
    if ($gTypes -contains 'DynamicMembership') {
        # Cannot hand-remove from a dynamic group; the accountEnabled rule drops it.
        Write-Console "  [skip] '$gName' is DYNAMIC -- drops automatically." -ForegroundColor DarkGray
        Add-Report "Group:$gName" 'Remove membership' 'skipped-dynamic'
        continue
    }
    if ($gSynced) {
        Write-Console "  [skip] '$gName' is synced from AD -- AD owns its membership." -ForegroundColor DarkGray
        Add-Report "Group:$gName" 'Remove membership' 'skipped-ad-owned'
        continue
    }
    if ($PSCmdlet.ShouldProcess("group '$gName'", "remove $UserPrincipalName")) {
        try {
            Remove-MgGroupMemberDirectoryObjectByRef -GroupId $m.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Console "  [+] Removed from '$gName'." -ForegroundColor Green
            Add-Report "Group:$gName" 'Remove membership' 'removed'
        }
        catch {
            # The package removal in step 3 is asynchronous and may have just
            # removed this membership itself - a 404 here is success, not failure.
            if ($_.Exception.Message -match 'does not exist|404|NotFound') {
                Write-Console "  [=] '$gName' already removed (access package revocation)." -ForegroundColor DarkGray
                Add-Report "Group:$gName" 'Remove membership' 'removed-by-package'
            }
            else {
                Write-Warning "  Could not remove from '$gName': $($_.Exception.Message)"
                Add-Report "Group:$gName" 'Remove membership' 'FAILED'
            }
        }
    }
    else { Add-Report "Group:$gName" 'Remove membership' 'whatif' }
}

# ===========================================================================
# 5. REMOVE DIRECT APP-ROLE ASSIGNMENTS
# ===========================================================================
Write-Console "`n[5/8] Remove direct app assignments" -ForegroundColor Cyan
$appAssignments = @(); $readOk = $true
try { $appAssignments = @(Get-MgUserAppRoleAssignment -UserId $user.Id -All -ErrorAction Stop) }
catch {
    $readOk = $false
    Write-Warning "  Could not read app-role assignments: $($_.Exception.Message)"
    Add-Report 'Apps' 'Remove assignment' 'FAILED-read'
}
if ($readOk -and $appAssignments.Count -eq 0) {
    Write-Console "  [=] No direct app-role assignments (apps are assigned via groups)." -ForegroundColor DarkGray
    Add-Report 'Apps' 'Remove assignment' 'none'
}
foreach ($a in $appAssignments) {
    $appName = [string]$a.ResourceDisplayName
    if ($PSCmdlet.ShouldProcess("app '$appName'", "remove assignment for $UserPrincipalName")) {
        Remove-MgUserAppRoleAssignment -UserId $user.Id -AppRoleAssignmentId $a.Id -ErrorAction Stop
        Write-Console "  [+] Removed from '$appName'." -ForegroundColor Green
        Add-Report "App:$appName" 'Remove assignment' 'removed'
    }
    else { Add-Report "App:$appName" 'Remove assignment' 'whatif' }
}

# ===========================================================================
# 6. FORCE SCIM DEPROVISIONING  (provision on demand)
# ===========================================================================
Write-Console "`n[6/8] Deprovision in SCIM apps" -ForegroundColor Cyan
if (-not $ProvisionOnDemandApps) {
    Write-Console "  [skip] No -ProvisionOnDemandApps given; apps deprovision on their next cycle (~40 min)." -ForegroundColor DarkGray
}
else {
    # Provision-on-demand only DISABLES the user downstream once they are out
    # of the app's assignment scope, i.e. after the package removal above has
    # completed. Wait for that first (bounded).
    if (-not $WhatIfPreference) {
        $deadline = (Get-Date).AddSeconds(300)
        $stillDelivered = 0
        do {
            try {
                $stillDelivered = @(Get-MgEntitlementManagementAssignment -Filter "target/objectId eq '$($user.Id)'" -ExpandProperty target -All -ErrorAction Stop |
                    Where-Object { $_.State -in 'delivered', 'delivering', 'partiallyDelivered' }).Count
            }
            catch {
                # A failed read is not "no deliveries left".
                Write-Warning "  Could not re-read access-package assignments: $($_.Exception.Message)"
                Add-Report 'Entitlement Mgmt' 'Await removal' 'FAILED-read'
                $stillDelivered = -1
                break
            }
            if ($stillDelivered -eq 0) { break }
            Write-Console "  [i] Waiting for $stillDelivered package removal(s) to complete..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
        } while ((Get-Date) -lt $deadline)
        if ($stillDelivered -gt 0) {
            Write-Warning "  $stillDelivered package removal(s) still pending after 300 s; the user may still be in app scope, so provision on demand may not disable them yet."
            Add-Report 'Entitlement Mgmt' 'Await removal' "FAILED-timeout:$stillDelivered"
        }
    }
    foreach ($appName in $ProvisionOnDemandApps) {
        $sp = Get-MgServicePrincipal -Filter "displayName eq '$appName'" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $sp) {
            Write-Warning "  Enterprise app '$appName' not found."
            Add-Report "SCIM:$appName" 'Provision on demand' 'FAILED-app-not-found'
            continue
        }
        if (-not $PSCmdlet.ShouldProcess("app '$appName'", "provision on demand (deprovision $UserPrincipalName)")) {
            Add-Report "SCIM:$appName" 'Provision on demand' 'whatif'
            continue
        }
        try {
            $base = "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/synchronization/jobs"
            # Select-Object -First 1, not @(...)[0]: under StrictMode an empty
            # list throws IndexOutOfRange and hides the real reason below.
            $job = @((Invoke-MgGraphRequest -Method GET -Uri $base).value) | Select-Object -First 1
            if (-not $job) { throw 'no provisioning job configured on this app' }
            $schema = Invoke-MgGraphRequest -Method GET -Uri "$base/$($job.id)/schema"
            # Gallery SaaS apps expose one user rule; take it.
            $rule = @($schema.synchronizationRules) | Select-Object -First 1
            if (-not $rule) { throw 'provisioning job has no synchronization rule' }
            $ruleId = $rule.id
            $body = @{
                parameters = @(@{
                    ruleId   = $ruleId
                    subjects = @(@{ objectId = $user.Id; objectTypeName = 'User' })
                })
            } | ConvertTo-Json -Depth 6
            $resp = Invoke-MgGraphRequest -Method POST -Uri "$base/$($job.id)/provisionOnDemand" -Body $body -ContentType 'application/json'
            # 200 OK does NOT mean the user was disabled: the outcome is in the
            # response. 'key' is JSON {result: Success|Skipped|..., details:
            # {errorCode, errorMessage}}; 'value' is JSON with 'action' (e.g.
            # Disable/Update/Other). Never print 'value' - it holds user attributes.
            # The response's 'key' is a type name, not JSON; the outcome is in
            # 'value': a JSON array of provisioning-log entries with
            # statusInfo {status, errorCode, reason} and the steps taken.
            # Never print 'value' whole - it holds user attributes.
            $items = if ($resp['value']) { @([string]$resp['value'] | ConvertFrom-Json) } else { @() }
            $first = $items | Select-Object -First 1
            $podResult = if ($first -and $first.PSObject.Properties['statusInfo'] -and $first.statusInfo.PSObject.Properties['status']) { [string]$first.statusInfo.status } else { 'Unknown' }
            $podAction = ''
            if ($first -and $first.PSObject.Properties['action'] -and $first.action) { $podAction = [string]$first.action }
            elseif ($first -and $first.PSObject.Properties['provisioningSteps']) { $last = @($first.provisioningSteps) | Select-Object -Last 1; if ($last -and $last.PSObject.Properties['name']) { $podAction = [string]$last.name } }
            $podCode = ''; $podWhy = ''
            if ($first -and $first.PSObject.Properties['statusInfo']) {
                if ($first.statusInfo.PSObject.Properties['errorCode']) { $podCode = [string]$first.statusInfo.errorCode }
                if ($first.statusInfo.PSObject.Properties['reason']) { $podWhy = ([string]$first.statusInfo.reason) -replace '\s+', ' ' }
            }
            $podDetail = (@($podCode, $podWhy) | Where-Object { $_ }) -join ': '
            switch ($podResult) {
                'Success' {
                    Write-Console "  [+] '$appName': provision on demand Success$(if ($podAction) { " (action: $podAction)" })." -ForegroundColor Green
                    Add-Report "SCIM:$appName" 'Provision on demand' "success$(if ($podAction) { ":$podAction" })"
                }
                'Skipped' {
                    # verify: Microsoft lists on-demand disable of users already
                    # disabled in Entra as a known limitation; a skip here means
                    # the app is NOT confirmed disabled until the next cycle.
                    Write-Warning "  '$appName': provision on demand SKIPPED ($podDetail). User NOT confirmed disabled in the app; the next provisioning cycle (~40 min) handles it - check the app's provisioning log."
                    Add-Report "SCIM:$appName" 'Provision on demand' "SKIPPED:$podCode"
                }
                default {
                    Write-Warning "  '$appName': provision on demand result '$podResult' ($podDetail) - check the app's provisioning log."
                    Add-Report "SCIM:$appName" 'Provision on demand' "FAILED-result:$podResult"
                }
            }
        }
        catch {
            Write-Warning "  '$appName' provision on demand failed: $($_.Exception.Message)"
            Add-Report "SCIM:$appName" 'Provision on demand' 'FAILED'
        }
    }
}

# ===========================================================================
# 7. NHI OWNERSHIP HAND-OFF  (apps / service principals the leaver owns)
# ===========================================================================
Write-Console "`n[7/8] Hand off owned apps and service principals" -ForegroundColor Cyan
$graphV1 = 'https://graph.microsoft.com/v1.0'
$ownedNhi = @(); $ownedGroups = @(); $readOk = $true
try {
    # ownedObjects mixes applications, service principals (incl. Agent ID
    # types) and groups. No $select: the default sets carry the credential
    # lists used for the rotation flag below.
    $uri = "$graphV1/users/$($user.Id)/ownedObjects"
    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($o in @($page['value'])) {
            $odataType = "$($o['@odata.type'])"
            if ($odataType -match '^#microsoft\.graph\.(application|servicePrincipal|agentIdentity\w*)$') { $ownedNhi += $o }
            elseif ($odataType -eq '#microsoft.graph.group') { $ownedGroups += $o }
        }
        $uri = $page['@odata.nextLink']
    } while ($uri)
}
catch {
    # A failed read is not "owns nothing".
    $readOk = $false
    Write-Warning "  Could not read owned objects: $($_.Exception.Message)"
    Add-Report 'NHI' 'Hand off ownership' 'FAILED-read'
}
if ($readOk -and -not $ownedNhi.Count -and -not $ownedGroups.Count) {
    Write-Console "  [=] Owns no apps, service principals or groups." -ForegroundColor DarkGray
    Add-Report 'NHI' 'Hand off ownership' 'none-owned'
}

# Resolve the new owner once: explicit UPN, else the manager from HR. Only an
# ENABLED user qualifies; anything else is flagged, never guessed.
$newOwner = $null
if ($ownedNhi.Count -and $NhiHandoff -eq 'ReassignToManager') {
    try {
        if ($NhiNewOwnerUserPrincipalName) {
            $cand = Get-MgUser -Filter "userPrincipalName eq '$($NhiNewOwnerUserPrincipalName.Replace("'", "''"))'" -Property 'id,userPrincipalName,accountEnabled' -ErrorAction Stop | Select-Object -First 1
        }
        else {
            $mgr = Invoke-MgGraphRequest -Method GET -Uri "$graphV1/users/$($user.Id)/manager?`$select=id" -ErrorAction Stop
            $cand = Get-MgUser -UserId ([string]$mgr['id']) -Property 'id,userPrincipalName,accountEnabled' -ErrorAction Stop
        }
        if ($cand -and $cand.AccountEnabled -and $cand.Id -ne $user.Id) { $newOwner = $cand }
        else { Write-Warning "  New owner candidate '$(if ($cand) { $cand.UserPrincipalName })' is missing, disabled or the leaver; owned NHIs will be FLAGGED." }
    }
    catch { Write-Warning "  No manager / new owner resolved ($($_.Exception.Message)); owned NHIs will be FLAGGED for a human to assign." }
}

# Tier-0 Graph application permissions: an app holding one can make itself
# (or anyone) Global Admin, take over accounts or switch off controls. Same
# list as Find-ShadowAdmins.ps1 -TierZeroPermissions and the ITDR consent
# rule (app-consent-granted.kql HighRiskPermissions).
$Tier0GraphPermissions = @(
    'RoleManagement.ReadWrite.Directory', 'Directory.ReadWrite.All', 'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All', 'RoleAssignmentSchedule.ReadWrite.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup',
    'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
    'RoleManagementPolicy.ReadWrite.Directory', 'UserAuthenticationMethod.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
    'Policy.ReadWrite.PermissionGrant', 'Domain.ReadWrite.All', 'User-PasswordProfile.ReadWrite.All',
    'Organization.ReadWrite.All', 'EntitlementManagement.ReadWrite.All'
)
$graphAppRoleValue = $null   # appRoleId -> permission name, loaded once on demand

function Get-NhiPrivilege {
    # What makes this NHI dangerous to hand to a new owner: Tier-0 Graph
    # permissions held by its service principal, and directory roles it
    # holds. Returns a short reason, '' for low-privilege. Throws on a read
    # failure - the caller flags (fail closed), never assumes "harmless".
    param([hashtable]$Object)
    $type = "$($Object['@odata.type'])"
    $spId = if ($type -match 'servicePrincipal$|agentIdentity$') { [string]$Object['id'] }
    else {
        # An app registration acts through its service principal.
        $appId = [string]$Object['appId']
        if (-not $appId) { return '' }
        $sp = @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/servicePrincipals?`$filter=appId eq '$appId'&`$select=id" -ErrorAction Stop)['value'])
        if (-not $sp.Count) { return '' }   # no SP in this tenant: holds nothing here
        [string]$sp[0]['id']
    }
    $reasons = @()
    if (-not $script:graphAppRoleValue) {
        $g = @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" -ErrorAction Stop)['value'])[0]
        $script:graphAppRoleValue = @{}
        foreach ($r in @($g['appRoles'])) { $script:graphAppRoleValue[[string]$r['id']] = [string]$r['value'] }
    }
    foreach ($a in @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/servicePrincipals/$spId/appRoleAssignments" -ErrorAction Stop)['value'])) {
        $perm = $script:graphAppRoleValue[[string]$a['appRoleId']]
        if ($perm -and $perm -in $Tier0GraphPermissions) { $reasons += "Graph:$perm" }
    }
    foreach ($r in @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/servicePrincipals/$spId/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName" -ErrorAction Stop)['value'])) {
        $reasons += "Role:$([string]$r['displayName'])"
    }
    return ($reasons -join ';')
}

foreach ($o in $ownedNhi) {
    $name = [string]$o['displayName']
    $odataType = "$($o['@odata.type'])"
    $path = if ($odataType -match 'application$|agentIdentityBlueprint$') { 'applications' } else { 'servicePrincipals' }
    $system = "NHI:$name"
    $privileged = ''
    if ($NhiHandoff -eq 'ReassignToManager' -and $newOwner) {
        try { $privileged = Get-NhiPrivilege -Object $o }
        catch { $privileged = "check-failed:$($_.Exception.Message)" }
    }
    if ($NhiHandoff -eq 'FlagOnly') {
        Write-Console "  [flag] '$name' ($($odataType -replace '^#microsoft\.graph\.')) is owned by the leaver (-NhiHandoff FlagOnly)." -ForegroundColor Yellow
        Add-Report $system 'Hand off ownership' 'FLAGGED-review'
    }
    elseif (-not $newOwner) {
        Add-Report $system 'Hand off ownership' 'FLAGGED-no-new-owner'
    }
    elseif ($privileged) {
        # Never hand a Tier-0 / role-holding workload identity to a manager:
        # its owner can add a credential and act as it (shadow admin).
        Write-Warning "  '$name' is PRIVILEGED ($privileged): NOT reassigned to $($newOwner.UserPrincipalName); app-governance owners must take it."
        Add-Report $system 'Hand off ownership' 'FLAGGED-privileged-owner-review'
    }
    elseif ($PSCmdlet.ShouldProcess("$path '$name'", "add owner $($newOwner.UserPrincipalName), then remove $UserPrincipalName")) {
        try {
            $current = @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/$path/$($o['id'])/owners?`$select=id" -ErrorAction Stop)['value'] | ForEach-Object { [string]$_['id'] })
            if ($newOwner.Id -notin $current) {
                $ref = @{ '@odata.id' = "$graphV1/directoryObjects/$($newOwner.Id)" } | ConvertTo-Json
                Invoke-MgGraphRequest -Method POST -Uri "$graphV1/$path/$($o['id'])/owners/`$ref" -Body $ref -ContentType 'application/json' -ErrorAction Stop | Out-Null
            }
            # Only reached when the new owner is in place: never ownerless.
            Invoke-MgGraphRequest -Method DELETE -Uri "$graphV1/$path/$($o['id'])/owners/$($user.Id)/`$ref" -ErrorAction Stop | Out-Null
            Write-Console "  [+] '$name': owner -> $($newOwner.UserPrincipalName) (leaver removed)." -ForegroundColor Green
            Add-Report $system 'Hand off ownership' "reassigned:$($newOwner.UserPrincipalName)"
        }
        catch {
            Write-Warning "  '$name' ownership hand-off failed: $($_.Exception.Message). The leaver is still an owner."
            Add-Report $system 'Hand off ownership' 'FAILED'
        }
    }
    else { Add-Report $system 'Hand off ownership' 'whatif' }

    # Credentials the leaver could have seen must be rotated (nhi-standard section 3).
    $credCount = @($o['passwordCredentials'] | Where-Object { $_ }).Count + @($o['keyCredentials'] | Where-Object { $_ }).Count
    if ($credCount) {
        Write-Warning "  '$name' holds $credCount secret/certificate(s) the leaver could have copied: rotate them."
        Add-Report $system 'Rotate credentials' "FLAGGED-rotate:$credCount"
    }
}

# Owned groups: report only. Group ownership is access control, and a
# role-assignable group's owner can grant a directory role.
foreach ($g in $ownedGroups) {
    $gName = [string]$g['displayName']
    $roleAssignable = $g.ContainsKey('isAssignableToRole') -and [bool]$g['isAssignableToRole']
    if ($roleAssignable) { Write-Warning "  Leaver owns ROLE-ASSIGNABLE group '$gName' (shadow-admin path): reassign or remove ownership now." }
    Add-Report "OwnedGroup:$gName" 'Owner review' $(if ($roleAssignable) { 'FLAGGED-role-assignable' } else { 'FLAGGED-review' })
}

# ===========================================================================
# 8. REPORT
# ===========================================================================
Write-Console "`n[8/8] Offboarding report for $UserPrincipalName" -ForegroundColor Cyan
$report | Format-Table -AutoSize | Out-Host
if ($report.Count -gt 1) {
    $elapsed = [datetime]$report[-1].TimestampUtc - [datetime]$report[0].TimestampUtc
    Write-Console ("First to last action: {0:mm\:ss} (mm:ss)" -f $elapsed) -ForegroundColor Cyan
}
$failed = @($report | Where-Object { $_.Status -like 'FAILED*' -or $_.Status -clike 'SKIPPED:*' -or $_.Status -eq 'PENDING-HR-SYNC' -or $_.Status -clike 'FLAGGED*' })
if ($failed) { Write-Warning "$($failed.Count) action(s) need attention - see report." }
if ($ReportPath -and -not $WhatIfPreference) {
    $report | Export-Csv -LiteralPath $ReportPath -NoTypeInformation
    Write-Console "Report written to $ReportPath" -ForegroundColor DarkGray
}

# Return the structured report so callers / the evidence pack can consume it.
return $report
