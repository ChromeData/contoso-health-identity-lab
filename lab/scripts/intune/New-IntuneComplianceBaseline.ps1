<#
.SYNOPSIS
    Creates (idempotently) the Contoso Health Windows 10/11 Intune COMPLIANCE
    baseline - Secure Boot, code integrity, minimum OS build, and optionally
    BitLocker - and assigns it to the CA005-Pilot-CompliantDevice group, so the
    Windows 11 lab VM (modules/intune-vm) can become the "compliant device"
    CA005 requires.

.DESCRIPTION
    Not a stand-in: this is real Microsoft Intune, driven through Microsoft
    Graph v1.0. Only the "corporate laptop" is an Azure VM.

    Video segment 4 (Conditional Access), CA005: "admin portals require a
    compliant device". Conditional Access cannot judge a device on its own -
    it asks Intune "is this device compliant?". This script defines what
    compliant MEANS for the lab and who it applies to; Terraform owns the CA
    policy (modules/conditional-access, CA005) and the pilot group
    (modules/groups). Intune is not in the azuread/azurerm providers, so -
    like PIM eligibility and access-package SoD - it is a post-apply script.

    STEPS (deliberate order; every step is get-then-create, so re-running is a
    no-op that just reports state)
      1. RESOLVE  the pilot group by its stable mailNickname.
      2. POLICY   find the windows10CompliancePolicy by display name.
                  Missing  -> POST it, INCLUDING the required
                              scheduledActionsForRule block (one "block"
                              action; Graph rejects a create without it).
                  Present  -> compare ONLY the settings this script manages and
                              PATCH the drifted ones (anything else an admin
                              added in the portal is left alone).
      3. ASSIGN   ensure the pilot group is an assignment target. Graph's
                  /assign REPLACES the whole assignment set, so existing
                  targets are re-sent unchanged alongside the new one.
      4. MEMBERS  optional (-PilotMemberUserPrincipalNames): add pilot users to
                  the ASSIGNED pilot group (Terraform ignores member drift).
      5. STATUS   optional (-ShowDeviceCompliance): list Windows managed
                  devices and their compliance state.

    SETTINGS (only properties that exist on windows10CompliancePolicy in v1.0)
      secureBootEnabled     Device Health Attestation: Secure Boot on   (default)
      codeIntegrityEnabled  Device Health Attestation: code integrity on (default)
      bitLockerEnabled      Device Health Attestation: BitLocker on      (OPT-IN)
      osMinimumVersion      Default 10.0.26100 = Windows 11 24H2, which is also
                            the minimum the Entra-login VM extension supports
      The health-attestation checks are measured AT BOOT: after the VM enrolls
      (or after you turn BitLocker on) it needs a RESTART before Intune can
      report it compliant. The Trusted Launch VM's vTPM + Secure Boot are what
      these checks read.

      WHY BITLOCKER IS OPT-IN: an Azure VM does not ship with BitLocker on
      (Azure encrypts the disk with server-side encryption instead), and
      Microsoft's Windows 365 known-issues page - Cloud PCs are Azure VMs -
      says "Require BitLocker" may report Not Compliant there. Requiring it by
      default would make the CA005 demo depend on an unverified in-guest step.
      Add it with -HealthChecks SecureBoot,CodeIntegrity,BitLocker after
      enabling BitLocker in the VM (README step 3b).

      NOT SET HERE: Defender antimalware / real-time protection / firewall /
      antivirus / TPM-required. Those compliance settings exist in the Intune
      portal and in Graph /beta (defenderEnabled, rtpEnabled,
      activeFirewallRequired, antivirusRequired, tpmRequired) but NOT in the
      v1.0 windows10CompliancePolicy schema this repo standardises on. Add them
      in the portal (Devices -> Compliance -> this policy -> Properties ->
      System Security) if you want them; this script never removes them.

.PREREQUISITES
    * Tenant has an active Intune licence (Microsoft 365 E5 trial) - the
      Graph Intune APIs return errors without one.
    * Terraform envs/dev applied with enable_premium = true (creates
      CA005-Pilot-CompliantDevice) - and enable_intune_vm = true for the VM.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated; admin-consent)
    DeviceManagementConfiguration.ReadWrite.All  create / update / assign the compliance policy
    Group.Read.All                               resolve the pilot group
    User.Read.All, GroupMember.ReadWrite.All     only with -PilotMemberUserPrincipalNames
    DeviceManagementManagedDevices.Read.All      only with -ShowDeviceCompliance

.PARAMETER PolicyDisplayName
    Natural key of the compliance policy. Default
    'Contoso Health - Windows compliance baseline'.

.PARAMETER GroupMailNickname
    The pilot group. Default ca005-pilot-compliantdevice (Terraform contract).

.PARAMETER MinimumOsVersion
    major.minor.build[.revision]. Default 10.0.26100 (Windows 11 24H2).

.PARAMETER HealthChecks
    Which Device Health Attestation checks to require. Default SecureBoot,
    CodeIntegrity (zero-touch: nothing to do inside the VM). Add BitLocker
    (-HealthChecks SecureBoot,CodeIntegrity,BitLocker) only after turning it
    on inside the VM (README step 3b) - see "WHY BITLOCKER IS OPT-IN" above.
    A check left out is "not configured" (not evaluated); re-running with a
    different set converges the policy.

.PARAMETER GracePeriodHours
    Hours a failing device stays "in grace period" before it is marked
    non-compliant (0-8760). Default 0 = immediately, which is what makes the
    CA005 demo deterministic.

.PARAMETER PilotMemberUserPrincipalNames
    Optional. UPNs to add to the pilot group (e.g. grace.mwangi@<your-domain>).
    Pilot members: (a) are the ONLY users CA005 applies to, (b) receive this
    compliance policy, (c) may RDP into the Intune VM with Entra credentials.
    Never add your everyday admin account - it administers from a Mac that
    will never be compliant.

.PARAMETER ShowDeviceCompliance
    Optional. Print Windows managed devices (filtered by -DeviceName) with
    compliance state + last sync.

.PARAMETER DeviceName
    Device filter for -ShowDeviceCompliance. Default CH-WIN11-01 (the
    modules/intune-vm hostname). Empty = all Windows devices.

.PARAMETER WhatIf
    Standard. Reads and reports; creates, patches, assigns and adds nothing.

.EXAMPLE
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All','User.Read.All','GroupMember.ReadWrite.All','DeviceManagementManagedDevices.Read.All'
    ./New-IntuneComplianceBaseline.ps1 -PilotMemberUserPrincipalNames 'grace.mwangi@<your-domain>' -WhatIf
    ./New-IntuneComplianceBaseline.ps1 -PilotMemberUserPrincipalNames 'grace.mwangi@<your-domain>'

.EXAMPLE
    # After turning BitLocker on inside the VM (README step 3b), tighten the
    # policy (PATCHes only bitLockerEnabled), then check the VM:
    ./New-IntuneComplianceBaseline.ps1 -HealthChecks SecureBoot,CodeIntegrity,BitLocker
    ./New-IntuneComplianceBaseline.ps1 -ShowDeviceCompliance

.OUTPUTS
    [pscustomobject] summary: PolicyId, PolicyName, PolicyAction,
    GroupId, AssignmentAction, MembersAdded, Failures.

.WHAT IT DEMONSTRATES
    Device trust as a Zero Trust signal: "admin portals only from a managed,
    healthy device", rolled out to a pilot group first, report-only first -
    the same staged pattern as every other CA policy in this lab.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyDisplayName = 'Contoso Health - Windows compliance baseline',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupMailNickname = 'ca005-pilot-compliantdevice',

    [Parameter()]
    [ValidatePattern('^\d+\.\d+\.\d+(\.\d+)?$', ErrorMessage = 'Use major.minor.build[.revision], e.g. 10.0.26100')]
    [string]$MinimumOsVersion = '10.0.26100',

    [Parameter()]
    [ValidateSet('BitLocker', 'SecureBoot', 'CodeIntegrity')]
    [string[]]$HealthChecks = @('SecureBoot', 'CodeIntegrity'),

    [Parameter()]
    [ValidateRange(0, 8760)]
    [int]$GracePeriodHours = 0,

    [Parameter()]
    [ValidateScript({ $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' }, ErrorMessage = "'{0}' is not a valid UPN.")]
    [string[]]$PilotMemberUserPrincipalNames = @(),

    [Parameter()]
    [switch]$ShowDeviceCompliance,

    [Parameter()]
    [string]$DeviceName = 'CH-WIN11-01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graph = 'https://graph.microsoft.com/v1.0'
$policyType = '#microsoft.graph.windows10CompliancePolicy'

# ---------------------------------------------------------------------------
# Connect (only the scopes this run needs).
# ---------------------------------------------------------------------------
$requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')
if ($PilotMemberUserPrincipalNames) { $requiredScopes += 'User.Read.All', 'GroupMember.ReadWrite.All' }
if ($ShowDeviceCompliance) { $requiredScopes += 'DeviceManagementManagedDevices.Read.All' }

$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) {
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Yellow
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $ctx = Get-MgContext
}
# An existing session may lack a scope this run needs - say so up front rather
# than failing half-way with a 403.
$granted = @($ctx.Scopes)
$missing = @($requiredScopes | Where-Object { $granted -notcontains $_ })
if ($missing -and $ctx.AuthType -eq 'Delegated') {
    Write-Warning "Current Graph session lacks: $($missing -join ', '). Re-run Connect-MgGraph -Scopes with them if a step fails with 403."
}

# ---------------------------------------------------------------------------
# Graph helpers. Invoke-MgGraphRequest returns hashtables; under StrictMode a
# missing key must be read with the indexer ($h['key']), never $h.key.
# ---------------------------------------------------------------------------
function Invoke-Graph {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body = $null
    )
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($null -ne $Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
        $params['ContentType'] = 'application/json'
    }
    Invoke-MgGraphRequest @params
}

function Get-GraphCollection {
    # Follows @odata.nextLink; emits each item (callers wrap in @()).
    param([Parameter(Mandatory)][string]$Uri)
    $next = $Uri
    while ($next) {
        $page = Invoke-Graph -Method GET -Uri $next
        foreach ($item in @($page['value'])) { if ($null -ne $item) { $item } }
        $next = $page['@odata.nextLink']
    }
}

function ConvertTo-ODataLiteral {
    # OData string literal: single quotes are escaped by doubling them.
    param([Parameter(Mandatory)][string]$Value)
    $Value.Replace("'", "''")
}

$failures = 0
$summary = [ordered]@{
    PolicyId         = $null
    PolicyName       = $PolicyDisplayName
    PolicyAction     = 'none'
    GroupId          = $null
    AssignmentAction = 'none'
    MembersAdded     = 0
    Failures         = 0
}

# ===========================================================================
# 1. RESOLVE THE PILOT GROUP
# ===========================================================================
Write-Host "`n[1/5] Pilot group" -ForegroundColor Cyan
$nick = ConvertTo-ODataLiteral $GroupMailNickname
$group = @(Get-GraphCollection "$graph/groups?`$filter=mailNickname eq '$nick'&`$select=id,displayName") | Select-Object -First 1
if (-not $group) { throw "Group '$GroupMailNickname' not found. Apply Terraform envs/dev with enable_premium = true first." }
$summary.GroupId = $group['id']
Write-Host "  [=] $($group['displayName']) ($($group['id']))" -ForegroundColor DarkGray

# ===========================================================================
# 2. COMPLIANCE POLICY (get -> create, or converge managed settings)
# ===========================================================================
Write-Host "`n[2/5] Compliance policy '$PolicyDisplayName'" -ForegroundColor Cyan

# The settings this script owns. $false means "not configured" in Intune
# (not evaluated) - so dropping a check from -HealthChecks relaxes it.
$desired = [ordered]@{
    bitLockerEnabled     = $HealthChecks -contains 'BitLocker'
    secureBootEnabled    = $HealthChecks -contains 'SecureBoot'
    codeIntegrityEnabled = $HealthChecks -contains 'CodeIntegrity'
    osMinimumVersion     = $MinimumOsVersion
}
Write-Host ("  Desired: BitLocker={0} SecureBoot={1} CodeIntegrity={2} MinOS={3} Grace={4}h" -f `
        $desired.bitLockerEnabled, $desired.secureBootEnabled, $desired.codeIntegrityEnabled, $MinimumOsVersion, $GracePeriodHours) -ForegroundColor DarkGray

$matches_ = @()
try {
    $matches_ = @(Get-GraphCollection "$graph/deviceManagement/deviceCompliancePolicies" |
        Where-Object { $_['@odata.type'] -eq $policyType -and $_['displayName'] -eq $PolicyDisplayName })
}
catch {
    throw "Could not list Intune compliance policies ($($_.Exception.Message)). Check the tenant has an active Intune licence (M365 E5 trial) and the session has DeviceManagementConfiguration.ReadWrite.All."
}
if ($matches_.Count -gt 1) {
    throw "$($matches_.Count) Windows compliance policies are named '$PolicyDisplayName' - delete the duplicates in Intune so the name is a unique key again."
}

$policyId = $null
if ($matches_.Count -eq 1) {
    $policyId = $matches_[0]['id']
    # Re-read the single policy: the list view is not guaranteed to carry
    # every derived-type property.
    $current = Invoke-Graph -Method GET -Uri "$graph/deviceManagement/deviceCompliancePolicies/$policyId"
    $drift = [ordered]@{}
    foreach ($k in $desired.Keys) {
        if ([string]$current[$k] -ne [string]$desired[$k]) { $drift[$k] = $desired[$k] }
    }
    if ($drift.Count -eq 0) {
        Write-Host "  [=] Exists ($policyId), managed settings already match." -ForegroundColor DarkGray
        $summary.PolicyAction = 'unchanged'
    }
    elseif ($PSCmdlet.ShouldProcess($PolicyDisplayName, "update $($drift.Keys -join ', ')")) {
        $patch = @{ '@odata.type' = $policyType }
        foreach ($k in $drift.Keys) { $patch[$k] = $drift[$k] }
        try {
            Invoke-Graph -Method PATCH -Uri "$graph/deviceManagement/deviceCompliancePolicies/$policyId" -Body $patch | Out-Null
            Write-Host "  [~] Updated drifted settings: $($drift.Keys -join ', ')." -ForegroundColor Green
            $summary.PolicyAction = 'updated'
        }
        catch {
            Write-Warning "  PATCH failed: $($_.Exception.Message)"
            $summary.PolicyAction = 'FAILED-update'
            $failures++
        }
    }
    else { $summary.PolicyAction = 'whatif-update' }
}
elseif ($PSCmdlet.ShouldProcess($PolicyDisplayName, 'create Windows 10/11 compliance policy')) {
    $body = @{
        '@odata.type' = $policyType
        displayName   = $PolicyDisplayName
        description   = "Contoso Health identity lab: device health + minimum OS for CA005 (compliant device for admin portals). Managed by lab/scripts/intune/New-IntuneComplianceBaseline.ps1."
        # REQUIRED on create: exactly one 'block' scheduled action. ruleName is
        # always PasswordRequired (Graph: scheduled actions are per policy, not
        # per rule). gracePeriodHours = how long a failing device stays in grace.
        scheduledActionsForRule = @(
            @{
                ruleName                      = 'PasswordRequired'
                scheduledActionConfigurations = @(
                    @{
                        actionType                = 'block'
                        gracePeriodHours          = $GracePeriodHours
                        notificationTemplateId    = ''
                        notificationMessageCCList = @()
                    }
                )
            }
        )
    }
    foreach ($k in $desired.Keys) { $body[$k] = $desired[$k] }
    try {
        $created = Invoke-Graph -Method POST -Uri "$graph/deviceManagement/deviceCompliancePolicies" -Body $body
        $policyId = $created['id']
        Write-Host "  [+] Created ($policyId)." -ForegroundColor Green
        $summary.PolicyAction = 'created'
    }
    catch {
        Write-Warning "  Create failed: $($_.Exception.Message)"
        $summary.PolicyAction = 'FAILED-create'
        $failures++
    }
}
else {
    Write-Host '  [whatif] Would create the policy (with one block action, grace as above).' -ForegroundColor DarkYellow
    $summary.PolicyAction = 'whatif-create'
}
$summary.PolicyId = $policyId

# ===========================================================================
# 3. ASSIGN TO THE PILOT GROUP (assign REPLACES the set - keep existing ones)
# ===========================================================================
Write-Host "`n[3/5] Assignment -> $($group['displayName'])" -ForegroundColor Cyan
if (-not $policyId) {
    Write-Host '  [skip] No policy id yet (WhatIf create or create failed).' -ForegroundColor DarkGray
    $summary.AssignmentAction = if ($WhatIfPreference) { 'whatif' } else { 'skipped-no-policy' }
}
else {
    $assignments = @(Get-GraphCollection "$graph/deviceManagement/deviceCompliancePolicies/$policyId/assignments")
    $alreadyTargeted = @($assignments | Where-Object {
            $t = $_['target']
            $null -ne $t -and $t['@odata.type'] -eq '#microsoft.graph.groupAssignmentTarget' -and $t['groupId'] -eq $group['id']
        }).Count -gt 0
    if ($alreadyTargeted) {
        Write-Host '  [=] Already assigned to the pilot group.' -ForegroundColor DarkGray
        $summary.AssignmentAction = 'unchanged'
    }
    elseif ($PSCmdlet.ShouldProcess($PolicyDisplayName, "assign to group $($group['displayName']) (keeping $($assignments.Count) existing assignment(s))")) {
        $targets = [System.Collections.Generic.List[object]]::new()
        foreach ($a in $assignments) { if ($null -ne $a['target']) { $targets.Add(@{ target = $a['target'] }) } }
        $targets.Add(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $group['id'] } })
        try {
            Invoke-Graph -Method POST -Uri "$graph/deviceManagement/deviceCompliancePolicies/$policyId/assign" -Body @{ assignments = $targets.ToArray() } | Out-Null
            Write-Host "  [+] Assigned ($($targets.Count) target(s) total)." -ForegroundColor Green
            $summary.AssignmentAction = 'assigned'
        }
        catch {
            Write-Warning "  Assign failed: $($_.Exception.Message)"
            $summary.AssignmentAction = 'FAILED'
            $failures++
        }
    }
    else { $summary.AssignmentAction = 'whatif' }
}

# ===========================================================================
# 4. PILOT MEMBERS (optional)
# ===========================================================================
Write-Host "`n[4/5] Pilot members" -ForegroundColor Cyan
if (-not $PilotMemberUserPrincipalNames) {
    Write-Host '  [skip] No -PilotMemberUserPrincipalNames given.' -ForegroundColor DarkGray
}
else {
    $memberIds = @(Get-GraphCollection "$graph/groups/$($group['id'])/members?`$select=id" | ForEach-Object { $_['id'] })
    foreach ($upn in $PilotMemberUserPrincipalNames) {
        $lit = ConvertTo-ODataLiteral $upn
        $user = @(Get-GraphCollection "$graph/users?`$filter=userPrincipalName eq '$lit'&`$select=id,displayName") | Select-Object -First 1
        if (-not $user) {
            Write-Warning "  '$upn' not found - run HR inbound provisioning first."
            $failures++
            continue
        }
        if ($memberIds -contains $user['id']) {
            Write-Host "  [=] $upn is already a pilot member." -ForegroundColor DarkGray
            continue
        }
        if ($PSCmdlet.ShouldProcess($upn, "add to $($group['displayName'])")) {
            try {
                Invoke-Graph -Method POST -Uri "$graph/groups/$($group['id'])/members/`$ref" `
                    -Body @{ '@odata.id' = "$graph/directoryObjects/$($user['id'])" } | Out-Null
                Write-Host "  [+] $upn added." -ForegroundColor Green
                $summary.MembersAdded++
            }
            catch {
                Write-Warning "  Could not add ${upn}: $($_.Exception.Message)"
                $failures++
            }
        }
    }
}

# ===========================================================================
# 5. DEVICE COMPLIANCE (optional, read-only)
# ===========================================================================
Write-Host "`n[5/5] Device compliance" -ForegroundColor Cyan
if (-not $ShowDeviceCompliance) {
    Write-Host '  [skip] Pass -ShowDeviceCompliance to list Windows devices.' -ForegroundColor DarkGray
}
else {
    try {
        $devices = @(Get-GraphCollection "$graph/deviceManagement/managedDevices" | Where-Object {
                $_['operatingSystem'] -eq 'Windows' -and (-not $DeviceName -or $_['deviceName'] -eq $DeviceName)
            })
        if (-not $devices) {
            Write-Warning "  No Windows managed device$(if ($DeviceName) { " named '$DeviceName'" }) yet. Check the MDM user scope, that a pilot member has signed in to the VM, and Intune -> Devices -> Windows."
        }
        $devices | ForEach-Object {
            [pscustomobject]@{
                DeviceName      = $_['deviceName']
                ComplianceState = $_['complianceState']
                LastSync        = $_['lastSyncDateTime']
                User            = $_['userPrincipalName']
                EntraDeviceId   = $_['azureADDeviceId']
            }
        } | Format-Table -AutoSize | Out-Host
    }
    catch {
        Write-Warning "  Could not read managed devices: $($_.Exception.Message) (needs DeviceManagementManagedDevices.Read.All)."
        $failures++
    }
}

$summary.Failures = $failures
$result = [pscustomobject]$summary
$result | Format-List | Out-Host
if ($failures) {
    Write-Warning "$failures step(s) failed - see warnings above."
    exit 1
}
Write-Host "Done. Verify: Intune admin center -> Devices -> Compliance -> '$PolicyDisplayName' -> Device status; then CA005 in the pilot user's sign-in logs (Report-only tab)." -ForegroundColor Cyan
return $result
