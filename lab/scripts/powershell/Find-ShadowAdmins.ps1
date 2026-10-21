<#
.SYNOPSIS
    Finds shadow admins: principals that hold no privileged role themselves
    but can get one in a single step. Owners of role-assignable groups, owners
    of Tier-0 apps, Application / Cloud Application Administrators who can add
    a credential to a Tier-0 app, workloads whose Graph app permissions amount
    to directory write, and PIM-eligible principals who ALSO hold the same role
    permanently. Each path carries a MITRE ATT&CK technique and a fix.

.DESCRIPTION
    01-Verify-Baseline and 05-Reports answer "who holds a privileged role?"
    Attackers ask a different question: "who can GIVE themselves one?" This
    script answers the attacker's question for the lab's design. That design
    puts every admin role on a role-assignable group (Break-Glass-Admins,
    Privileged-IAM-Admins, the PIM-Tier* groups) and keeps a Tier-0 pipeline
    identity. Both are exactly where shadow-admin paths hide:

      PATH (Technique)                    WHY IT IS AN ADMIN                      MITRE ATT&CK
      OwnerOfRoleAssignableGroup          an owner can add members to a           T1098.003 Additional
                                          role-assignable group, including         Cloud Roles
                                          themselves, outside PIM
      EligibleOwnerOfRoleAssignableGroup  PIM-for-Groups eligible OWNER: the      T1098.003
                                          same path, but JIT-gated
      OwnerOfTierZeroApp                  an app owner can add a certificate or   T1098.001 Additional
                                          federated credential and sign in as      Cloud Credentials
                                          the app (secrets may be blocked by
                                          Set-AppGovernancePolicy; certs aren't)
      AppAdminOverTierZeroApp             Application / Cloud Application         T1098.001
                                          Administrators can do the same to ANY
                                          app, so a Tier-0 app makes them Tier 0
      TierZeroWorkload                    a service principal whose Graph app     T1078.004 Cloud
                                          permissions (RoleManagement.ReadWrite.   Accounts
                                          Directory, Directory.ReadWrite.All, ...)
                                          equal directory write. It has no role,
                                          so role reports never show it.
      EligibleAndPermanent                eligible for a role AND holding it      T1078.004
                                          permanently: the JIT control exists
                                          on paper only

    Known, accepted paths are not hidden. -AcceptedRisk maps a principal to an
    exception-register ID (default: the APPLY pipeline identity -> E1 in
    lab/docs/standards/exception-process.md). Accepted rows stay in the output
    marked 'accepted:<id>' and don't count towards -FailOnFinding.

    STATUS: written and tested OFFLINE only; it has not run against a tenant.
    -Offline runs the same path analysis on a built-in mock tenant (the lab's
    role-assignable groups and pipeline identities plus seeded bad paths) and
    writes to lab/evidence/out/offline-mock/.

    OUT OF SCOPE (say so on camera): Azure RBAC paths (Owner / User Access
    Administrator on subscriptions), on-premises AD paths (BloodHound territory),
    administrative-unit-scoped roles, and Exchange/SharePoint app permissions.

    NEVER SILENT: every data source is recorded as ok or FAILED; a failed source
    makes the result INCOMPLETE (exit 1), never clean.

.PREREQUISITES
    * Modules: Microsoft.Graph.Authentication (raw REST via Invoke-MgGraphRequest).
    * Entra ID P2 for the PIM schedule-instance reads (in the E5 trial).

.GRAPH SCOPES  (delegated; admin-consent -- all READ-ONLY)
    RoleManagement.Read.Directory                    role definitions, assignment +
                                                     eligibility schedule instances
    Group.Read.All                                   role-assignable groups + owners
    PrivilegedEligibilitySchedule.Read.AzureADGroup  PIM for Groups eligibility
    PrivilegedAssignmentSchedule.Read.AzureADGroup   PIM for Groups active assignments
    Application.Read.All                             apps, SPs, owners, Graph app roles
    Directory.Read.All                               principal lookups

.PARAMETER OutputDirectory
    Default lab/evidence/out (gitignored); -Offline defaults to
    lab/evidence/out/offline-mock.

.PARAMETER TierZeroPermissions
    Graph application permissions that equal Tier-0 control. Keep this in step
    with 06-NHI-Inventory.ps1.

.PARAMETER AcceptedRisk
    Hashtable: principal display name (or UPN) -> exception-register ID.

.PARAMETER Offline
    No Graph connection; analyse the built-in mock tenant.

.PARAMETER FailOnFinding
    Exit 2 when any UNACCEPTED Critical or High path exists (scheduled job / CI).

.PARAMETER PrivilegedIdsPath
    Also write a JSON array of the USER object ids that hold privilege: an
    active or eligible privileged directory role (directly or through a
    role-assignable group), or an eligible / permanent member or owner of a
    PIM-governed group. It feeds the ITDR detections that must judge a target
    by membership, not by name - auth-method-changed-by-admin.kql via
    Terraform privileged_user_object_ids (TF_PRIVILEGED_USER_OBJECT_IDS) and
    the Splunk lookup contoso_privileged_identities.csv. Object ids only, no
    names. Refresh it on the same schedule as this report.

.EXAMPLE
    ./Find-ShadowAdmins.ps1 -Offline

.EXAMPLE
    Connect-MgGraph -Scopes 'RoleManagement.Read.Directory','Group.Read.All','PrivilegedEligibilitySchedule.Read.AzureADGroup','PrivilegedAssignmentSchedule.Read.AzureADGroup','Application.Read.All','Directory.Read.All'
    ./Find-ShadowAdmins.ps1 -FailOnFinding

.OUTPUTS
    shadow_admins.csv and shadow_admins.json (paths, summary, dataSources).
    Returns the same structure as a [pscustomobject].

.WHAT IT DEMONSTRATES
    Attack-path thinking applied to a zero-standing-admin design: the control
    isn't "nobody holds Global Admin", it's "nobody can get Global Admin
    without going through PIM". It's also the evidence behind the threat-model
    row for privilege escalation through group or app ownership.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$OutputDirectory = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$TierZeroPermissions = @(
        'RoleManagement.ReadWrite.Directory', 'Directory.ReadWrite.All', 'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All', 'RoleAssignmentSchedule.ReadWrite.Directory',
        'RoleEligibilitySchedule.ReadWrite.Directory', 'PrivilegedAccess.ReadWrite.AzureADGroup',
        'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
        'RoleManagementPolicy.ReadWrite.Directory', 'UserAuthenticationMethod.ReadWrite.All',
        'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
        'Policy.ReadWrite.PermissionGrant', 'Domain.ReadWrite.All',
        'User-PasswordProfile.ReadWrite.All', 'Organization.ReadWrite.All', 'EntitlementManagement.ReadWrite.All'
    ),

    [Parameter()]
    [hashtable]$AcceptedRisk = @{ 'gh-oidc-entra-apply (write)' = 'E1' },

    [Parameter()]
    [switch]$Offline,

    [Parameter()]
    [string]$PrivilegedIdsPath = '',

    [Parameter()]
    [switch]$FailOnFinding
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

# ===========================================================================
# 0. CONSTANTS AND HELPERS
# ===========================================================================
$Now = (Get-Date).ToUniversalTime()
$Source = if ($Offline) { 'offline-mock' } else { 'tenant' }
if (-not $OutputDirectory) {
    $evidenceOut = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../evidence/out'))
    $OutputDirectory = if ($Offline) { Join-Path $evidenceOut 'offline-mock' } else { $evidenceOut }
}
$GraphAppId = '00000003-0000-0000-c000-000000000000'

# Roles that let the holder take over the tenant outright: a path to one of
# these is Critical; a path to any other privileged role is High.
$CrownJewelRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
}
# Roles that can add credentials to any application.
$AppAdminRoles = @{
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
}
# Fallback privileged set when beta isPrivileged can't be read (same list as
# 06-NHI-Inventory.ps1). verify: Microsoft's privileged-roles page.
$StaticPrivilegedRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    'fdd7a751-b60b-444a-984c-02652fe8fa1c' = 'Groups Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'
}
$Mitre = @{
    'OwnerOfRoleAssignableGroup'         = 'T1098.003 Account Manipulation: Additional Cloud Roles'
    'EligibleOwnerOfRoleAssignableGroup' = 'T1098.003 Account Manipulation: Additional Cloud Roles'
    'OwnerOfTierZeroApp'                 = 'T1098.001 Account Manipulation: Additional Cloud Credentials'
    'AppAdminOverTierZeroApp'            = 'T1098.001 Account Manipulation: Additional Cloud Credentials'
    'TierZeroWorkload'                   = 'T1078.004 Valid Accounts: Cloud Accounts'
    'EligibleAndPermanent'               = 'T1078.004 Valid Accounts: Cloud Accounts'
}
$Fix = @{
    'OwnerOfRoleAssignableGroup'         = 'Remove the owner. Role-assignable groups should be owned by nobody beyond break-glass/PIM administrators; membership changes go through PIM.'
    'EligibleOwnerOfRoleAssignableGroup' = 'Confirm the eligible owner needs to manage membership; otherwise remove the eligibility. Activation is logged (pim-activation detection).'
    'OwnerOfTierZeroApp'                 = 'Remove the owner, or move the Tier-0 permission to a dedicated identity with no human owners and record a risk acceptance.'
    'AppAdminOverTierZeroApp'            = 'Make the role eligible-only with approval, or scope it to an administrative unit; Tier-0 apps make App Admins Tier 0.'
    'TierZeroWorkload'                   = 'Remove the permission or record a risk acceptance with compensating controls (federated-only credential, gated environment, detection on its sign-ins).'
    'EligibleAndPermanent'               = 'Remove the permanent assignment; keep the eligible one. Permanent + eligible means the JIT control is bypassed.'
}
$SeverityRank = @{ 'Info' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Critical' = 4 }
$TierZeroSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$TierZeroPermissions, [System.StringComparer]::OrdinalIgnoreCase)
# Accepted risks keyed case-insensitively (UPNs and display names vary in case).
$Accepted = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($k in $AcceptedRisk.Keys) { $Accepted[[string]$k] = [string]$AcceptedRisk[$k] }

function Get-Value($Object, [string[]]$Path) {
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$p] }
        elseif ($cur.PSObject.Properties[$p]) { $cur = $cur.$p }
        else { return $null }
    }
    return $cur
}

$dataSources = [System.Collections.Generic.List[object]]::new()
function Add-DataSource([string]$Name, [string]$Status, [string]$Detail = '') {
    $dataSources.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
    if ($Status -like 'FAILED*') { Write-Warning "Data source '$Name' FAILED: $Detail -- paths that depend on it are UNKNOWN, not absent." }
}

function Invoke-GraphGetAll([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        if ($page -is [System.Collections.IDictionary] -and $page.Contains('value')) {
            foreach ($v in @($page['value'])) { $items.Add($v) }
            $next = if ($page.Contains('@odata.nextLink')) { [string]$page['@odata.nextLink'] } else { $null }
        }
        else { $items.Add($page); $next = $null }
    }
    return $items.ToArray()
}

# ===========================================================================
# 1. COLLECT  (tenant or mock; same shape, so section 2 is identical)
# ===========================================================================
#   Principals  : id -> @{ Type = user|group|servicePrincipal; Label }
#   RoleNames   : roleDefinitionId -> display name (privileged roles only)
#   Active      : @{ PrincipalId; RoleId; Permanent } (assignmentType 'Assigned')
#   Eligible    : @{ PrincipalId; RoleId }
#   Groups      : role-assignable groups @{ Id; Name; Owners = ids }
#   GroupPim    : groupId -> @{ EligibleMembers; EligibleOwners; PermanentMembers }
#   TierZeroApps: @{ SpId; Name; Permissions; Owners = ids (SP + app owners) }

function Get-MockTenant {
    $p = @{}
    foreach ($u in @(
            @('mock-user-operator', 'user', 'lab-operator@contosohealth.io'),
            @('mock-user-grace', 'user', 'grace.mwangi@contosohealth.io'),
            @('mock-user-marcus', 'user', 'marcus.bello@contosohealth.io'),
            @('mock-user-omar', 'user', 'omar.haddad@contosohealth.io'),
            @('mock-user-daniel', 'user', 'daniel.osei@contosohealth.io'),
            @('mock-sp-apply', 'servicePrincipal', 'gh-oidc-entra-apply (write)'),
            @('mock-sp-legacy', 'servicePrincipal', 'legacy-report-exporter'),
            @('mock-grp-bg', 'group', 'Break-Glass-Admins'),
            @('mock-grp-iam', 'group', 'Privileged-IAM-Admins'),
            @('mock-grp-t0ca', 'group', 'PIM-Tier0-CA-Admins'),
            @('mock-grp-t1hd', 'group', 'PIM-Tier1-Helpdesk'))) {
        $p[$u[0]] = @{ Type = $u[1]; Label = $u[2] }
    }
    $ga = '62e90394-69f5-4237-9190-012177145e10'; $ua = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
    $caa = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; $hd = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
    $cloudApp = '158c047a-c907-4556-b7ef-446551a6b5f7'
    return @{
        TenantId     = 'mock-tenant-contosohealth'
        Principals   = $p
        RoleNames    = $StaticPrivilegedRoles
        # The lab design: each admin role sits on a role-assignable group;
        # Daniel's standing Cloud App Admin is the seeded bad example.
        Active       = @(
            @{ PrincipalId = 'mock-grp-bg'; RoleId = $ga; Permanent = $true },
            @{ PrincipalId = 'mock-grp-iam'; RoleId = $ua; Permanent = $true },
            @{ PrincipalId = 'mock-grp-t0ca'; RoleId = $caa; Permanent = $true },
            @{ PrincipalId = 'mock-grp-t1hd'; RoleId = $hd; Permanent = $true },
            @{ PrincipalId = 'mock-user-daniel'; RoleId = $cloudApp; Permanent = $true })
        Eligible     = @(@{ PrincipalId = 'mock-user-daniel'; RoleId = $cloudApp })
        # Terraform creates groups as the APPLY identity, and the azuread
        # provider makes the caller the owner when owners aren't set
        # (verify: azuread_group 'owners' default), hence apply -> Break-Glass.
        Groups       = @(
            @{ Id = 'mock-grp-bg'; Name = 'Break-Glass-Admins'; Owners = @('mock-sp-apply') },
            @{ Id = 'mock-grp-iam'; Name = 'Privileged-IAM-Admins'; Owners = @('mock-user-operator') },
            @{ Id = 'mock-grp-t0ca'; Name = 'PIM-Tier0-CA-Admins'; Owners = @('mock-user-marcus') },
            @{ Id = 'mock-grp-t1hd'; Name = 'PIM-Tier1-Helpdesk'; Owners = @() })
        GroupPim     = @{
            'mock-grp-iam'  = @{ EligibleMembers = @('mock-user-grace'); EligibleOwners = @(); PermanentMembers = @() }
            'mock-grp-t1hd' = @{ EligibleMembers = @('mock-user-grace'); EligibleOwners = @('mock-user-omar'); PermanentMembers = @('mock-user-grace') }
        }
        TierZeroApps = @(
            @{ SpId = 'mock-sp-apply'; Name = 'gh-oidc-entra-apply (write)'; Permissions = @('RoleManagement.ReadWrite.Directory'); Owners = @() },
            @{ SpId = 'mock-sp-legacy'; Name = 'legacy-report-exporter'; Permissions = @('Directory.ReadWrite.All'); Owners = @('mock-user-omar') })
    }
}

function Get-OnlineTenant {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    $graph = 'https://graph.microsoft.com'
    $requiredScopes = @('RoleManagement.Read.Directory', 'Group.Read.All', 'PrivilegedEligibilitySchedule.Read.AzureADGroup',
        'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'Application.Read.All', 'Directory.Read.All')
    $ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
    if (-not $ctx) { Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Reads needing them fail and are recorded as FAILED sources." }

    $t = @{ TenantId = [string]$ctx.TenantId; Principals = @{}; RoleNames = @{}; Active = @(); Eligible = @(); Groups = @(); GroupPim = @{}; TierZeroApps = @() }
    function Add-Principal($Obj) {
        if (-not $Obj) { return }
        $id = [string](Get-Value $Obj @('id'))
        if (-not $id -or $t.Principals.ContainsKey($id)) { return }
        $type = ("$(Get-Value $Obj @('@odata.type'))" -replace '^#microsoft\.graph\.', '')
        $label = if (Get-Value $Obj @('userPrincipalName')) { [string](Get-Value $Obj @('userPrincipalName')) } else { [string](Get-Value $Obj @('displayName')) }
        $t.Principals[$id] = @{ Type = $type; Label = $label }
    }

    # Privileged role set: Microsoft's isPrivileged flag (beta), else static.
    try {
        $defs = @(Invoke-GraphGetAll "$graph/beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,displayName")
        foreach ($d in $defs) { $t.RoleNames[[string]$d['id']] = [string]$d['displayName'] }
        Add-DataSource 'privileged role definitions (beta isPrivileged)' 'ok' "$($defs.Count) roles"
    }
    catch {
        $t.RoleNames = $StaticPrivilegedRoles
        Add-DataSource 'privileged role definitions (beta isPrivileged)' 'fallback' "static list used: $($_.Exception.Message)"
    }

    # Directory roles: active (assignmentType Assigned = not a JIT activation;
    # endDateTime null = permanent) and eligible instances, with principals.
    try {
        foreach ($i in (Invoke-GraphGetAll "$graph/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=assignmentType eq 'Assigned'&`$expand=principal")) {
            if (-not $t.RoleNames.ContainsKey([string]$i['roleDefinitionId'])) { continue }
            Add-Principal $i['principal']
            $t.Active += @{ PrincipalId = [string]$i['principalId']; RoleId = [string]$i['roleDefinitionId']; Permanent = (-not (Get-Value $i @('endDateTime'))) }
        }
        Add-DataSource 'roleAssignmentScheduleInstances' 'ok'
    }
    catch { Add-DataSource 'roleAssignmentScheduleInstances' 'FAILED' $_.Exception.Message }
    try {
        foreach ($i in (Invoke-GraphGetAll "$graph/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal")) {
            if (-not $t.RoleNames.ContainsKey([string]$i['roleDefinitionId'])) { continue }
            Add-Principal $i['principal']
            $t.Eligible += @{ PrincipalId = [string]$i['principalId']; RoleId = [string]$i['roleDefinitionId'] }
        }
        Add-DataSource 'roleEligibilityScheduleInstances' 'ok'
    }
    catch { Add-DataSource 'roleEligibilityScheduleInstances' 'FAILED' $_.Exception.Message }

    # Role-assignable groups + owners + PIM-for-Groups state.
    # verify: $filter on isAssignableToRole without ConsistencyLevel: eventual.
    try {
        foreach ($g in (Invoke-GraphGetAll "$graph/v1.0/groups?`$filter=isAssignableToRole eq true&`$select=id,displayName")) {
            $gid = [string]$g['id']
            Add-Principal (@{ id = $gid; '@odata.type' = '#microsoft.graph.group'; displayName = $g['displayName'] })
            $owners = @(Invoke-GraphGetAll "$graph/v1.0/groups/$gid/owners")
            foreach ($o in $owners) { Add-Principal $o }
            $t.Groups += @{ Id = $gid; Name = [string]$g['displayName']; Owners = @($owners | ForEach-Object { [string]$_['id'] }) }
            try {
                $elig = @(Invoke-GraphGetAll "$graph/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$gid'")
                $act = @(Invoke-GraphGetAll "$graph/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$gid'")
                $t.GroupPim[$gid] = @{
                    EligibleMembers  = @($elig | Where-Object { $_['accessId'] -eq 'member' } | ForEach-Object { [string]$_['principalId'] })
                    EligibleOwners   = @($elig | Where-Object { $_['accessId'] -eq 'owner' } | ForEach-Object { [string]$_['principalId'] })
                    PermanentMembers = @($act | Where-Object { $_['accessId'] -eq 'member' -and "$($_['assignmentType'])" -eq 'assigned' -and -not (Get-Value $_ @('endDateTime')) } |
                            ForEach-Object { [string]$_['principalId'] })
                }
            }
            catch { Add-DataSource "PIM for Groups: $($g['displayName'])" 'FAILED' $_.Exception.Message }
        }
        Add-DataSource 'role-assignable groups + owners' 'ok' "$($t.Groups.Count) groups"
    }
    catch { Add-DataSource 'role-assignable groups + owners' 'FAILED' $_.Exception.Message }

    # Tier-0 apps: Graph app-role holders + SPs holding privileged roles.
    try {
        $graphSp = Invoke-MgGraphRequest -Method GET -Uri "$graph/v1.0/servicePrincipals(appId='$GraphAppId')?`$select=id,appRoles" -ErrorAction Stop
        $roleValue = @{}; foreach ($r in @($graphSp['appRoles'])) { $roleValue[[string]$r['id']] = [string]$r['value'] }
        $bySp = @{}
        foreach ($a in (Invoke-GraphGetAll "$graph/v1.0/servicePrincipals/$($graphSp['id'])/appRoleAssignedTo")) {
            $v = $roleValue[[string]$a['appRoleId']]
            if ("$($a['principalType'])" -ne 'ServicePrincipal' -or -not $v -or -not $TierZeroSet.Contains($v)) { continue }
            $sid = [string]$a['principalId']
            if (-not $bySp.ContainsKey($sid)) { $bySp[$sid] = @{ Name = [string]$a['principalDisplayName']; Perms = @() } }
            $bySp[$sid].Perms += $v
        }
        foreach ($sid in $bySp.Keys) {
            $sp = Invoke-MgGraphRequest -Method GET -Uri "$graph/v1.0/servicePrincipals/$($sid)?`$select=id,appId,displayName" -ErrorAction Stop
            Add-Principal (@{ id = $sid; '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = $sp['displayName'] })
            $owners = @(Invoke-GraphGetAll "$graph/v1.0/servicePrincipals/$sid/owners")
            # Owners of the backing app registration can add credentials too.
            $app = @(Invoke-GraphGetAll "$graph/v1.0/applications?`$filter=appId eq '$($sp['appId'])'&`$select=id") | Select-Object -First 1
            if ($app) { $owners += @(Invoke-GraphGetAll "$graph/v1.0/applications/$($app['id'])/owners") }
            foreach ($o in $owners) { Add-Principal $o }
            $t.TierZeroApps += @{ SpId = $sid; Name = [string]$sp['displayName']; Permissions = @($bySp[$sid].Perms | Sort-Object -Unique)
                Owners = @($owners | ForEach-Object { [string]$_['id'] } | Sort-Object -Unique) }
        }
        Add-DataSource 'Tier-0 apps + owners' 'ok' "$($t.TierZeroApps.Count) apps"
    }
    catch { Add-DataSource 'Tier-0 apps + owners' 'FAILED' $_.Exception.Message }
    return $t
}

if ($Offline) {
    Write-Console 'OFFLINE: analysing the built-in MOCK tenant. Nothing here is tenant evidence.' -ForegroundColor DarkYellow
    $tenant = Get-MockTenant
    foreach ($n in 'privileged role definitions', 'roleAssignmentScheduleInstances', 'roleEligibilityScheduleInstances',
        'role-assignable groups + owners', 'Tier-0 apps + owners') { Add-DataSource $n 'ok (mock)' }
}
else { $tenant = Get-OnlineTenant }

# ===========================================================================
# 2. PATH ANALYSIS
# ===========================================================================
$paths = [System.Collections.Generic.List[object]]::new()
$seen = @{}
function Get-Label([string]$Id) { if ($tenant.Principals.ContainsKey($Id)) { $tenant.Principals[$Id].Label } else { $Id } }
function Get-PrincipalType([string]$Id) { if ($tenant.Principals.ContainsKey($Id)) { $tenant.Principals[$Id].Type } else { 'unknown' } }
function Get-RoleLabel([string]$RoleId) { if ($tenant.RoleNames.ContainsKey($RoleId)) { $tenant.RoleNames[$RoleId] } else { $RoleId } }

function Add-Path([string]$PrincipalId, [string]$Technique, [string]$Severity, [string]$Target, [string]$Privilege, [string]$Path) {
    $key = "$PrincipalId|$Technique|$Target"
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = $true
    $label = Get-Label $PrincipalId
    $status = if ($Accepted.ContainsKey($label)) { "accepted:$($Accepted[$label])" } else { 'open' }
    $paths.Add([pscustomobject]@{
            Source        = $Source
            Severity      = $Severity
            Status        = $status
            Principal     = $label
            PrincipalType = Get-PrincipalType $PrincipalId
            PrincipalId   = $PrincipalId
            Technique     = $Technique
            Target        = $Target
            Privilege     = $Privilege
            Path          = $Path
            Mitre         = $Mitre[$Technique]
            Remediation   = $Fix[$Technique]
        })
}

# Roles held (active or eligible) by each principal.
$rolesByPrincipal = @{}
foreach ($a in @($tenant.Active) + @($tenant.Eligible | ForEach-Object { @{ PrincipalId = $_.PrincipalId; RoleId = $_.RoleId; Permanent = $false; Eligible = $true } })) {
    if (-not $rolesByPrincipal.ContainsKey($a.PrincipalId)) { $rolesByPrincipal[$a.PrincipalId] = [System.Collections.Generic.List[object]]::new() }
    $rolesByPrincipal[$a.PrincipalId].Add($a)
}
function Get-PathSeverity([string[]]$RoleIds) { if (@($RoleIds | Where-Object { $CrownJewelRoles.ContainsKey($_) }).Count) { 'Critical' } else { 'High' } }

# 2a. Owners of role-assignable groups that hold a privileged role.
foreach ($g in $tenant.Groups) {
    $held = @()
    if ($rolesByPrincipal.ContainsKey($g.Id)) { $held = @($rolesByPrincipal[$g.Id]) }
    if (-not $held.Count) { continue }
    $roleIds = @($held | ForEach-Object { $_.RoleId } | Sort-Object -Unique)
    $roleText = (@($held | ForEach-Object { "$(Get-RoleLabel $_.RoleId) ($(if ($_.Contains('Eligible')) { 'eligible' } else { 'active' }))" } | Sort-Object -Unique) -join ', ')
    foreach ($o in @($g.Owners)) {
        Add-Path $o 'OwnerOfRoleAssignableGroup' (Get-PathSeverity $roleIds) $g.Name $roleText `
            "owns role-assignable group '$($g.Name)' -> can add any member, incl. itself, outside PIM -> $roleText"
    }
    $pim = if ($tenant.GroupPim.ContainsKey($g.Id)) { $tenant.GroupPim[$g.Id] } else { $null }
    if ($pim) {
        foreach ($o in @($pim.EligibleOwners)) {
            Add-Path $o 'EligibleOwnerOfRoleAssignableGroup' 'Medium' $g.Name $roleText `
                "PIM-eligible OWNER of '$($g.Name)' -> after activation can add members -> $roleText"
        }
        # PIM for Groups: eligible AND permanent member of the same group.
        foreach ($m in @($pim.EligibleMembers | Where-Object { $_ -in @($pim.PermanentMembers) })) {
            Add-Path $m 'EligibleAndPermanent' (Get-PathSeverity $roleIds) $g.Name $roleText `
                "eligible member of '$($g.Name)' AND a permanent member -> $roleText without activation"
        }
    }
}

# 2b. Tier-0 workloads, their owners, and the App Admins who can act as them.
foreach ($app in $tenant.TierZeroApps) {
    $perm = @($app.Permissions) -join ', '
    Add-Path $app.SpId 'TierZeroWorkload' 'Critical' $app.Name $perm "holds Graph application permission(s) $perm -> directory write without any directory role"
    foreach ($o in @($app.Owners)) {
        Add-Path $o 'OwnerOfTierZeroApp' 'Critical' $app.Name $perm "owns '$($app.Name)' -> adds a certificate or federated credential -> signs in as it -> $perm"
    }
}
if (@($tenant.TierZeroApps).Count) {
    $t0Names = (@($tenant.TierZeroApps | ForEach-Object { $_.Name }) -join ', ')
    foreach ($principalId in @($rolesByPrincipal.Keys)) {
        $appAdmin = @($rolesByPrincipal[$principalId] | Where-Object { $AppAdminRoles.ContainsKey($_.RoleId) })
        foreach ($roleId in @($appAdmin | ForEach-Object { $_.RoleId } | Sort-Object -Unique)) {
            # One row per principal + role; holding it actively is the worse case.
            $isActive = @($appAdmin | Where-Object { $_.RoleId -eq $roleId -and -not $_.Contains('Eligible') }).Count -gt 0
            $roleName = $AppAdminRoles[$roleId]
            Add-Path $principalId 'AppAdminOverTierZeroApp' $(if ($isActive) { 'High' } else { 'Medium' }) $roleName "$roleName -> Tier-0 app(s)" `
                "$roleName ($(if ($isActive) { 'active' } else { 'eligible' })) can add credentials to any app, incl. Tier-0: $t0Names"
        }
    }
}

# 2c. Directory roles: eligible AND permanently active for the same role.
foreach ($e in @($tenant.Eligible)) {
    $dup = @($tenant.Active | Where-Object { $_.PrincipalId -eq $e.PrincipalId -and $_.RoleId -eq $e.RoleId -and $_.Permanent })
    if ($dup.Count) {
        $rn = Get-RoleLabel $e.RoleId
        Add-Path $e.PrincipalId 'EligibleAndPermanent' (Get-PathSeverity @($e.RoleId)) $rn $rn "eligible for $rn AND holds it permanently -> no activation, approval or MFA step"
    }
}

# ===========================================================================
# 3. OUTPUT
# ===========================================================================
$rows = @($paths | Sort-Object @{ Expression = { $SeverityRank[$_.Severity] }; Descending = $true }, Technique, Principal)
$open = @($rows | Where-Object Status -eq 'open')
$summary = [ordered]@{
    paths            = $rows.Count
    openPaths        = $open.Count
    acceptedPaths    = @($rows | Where-Object Status -like 'accepted:*').Count
    openCriticalHigh = @($open | Where-Object { $_.Severity -in 'Critical', 'High' }).Count
    byTechnique      = [ordered]@{}
    shadowPrincipals = @($open | Select-Object -ExpandProperty Principal -Unique).Count
}
foreach ($grp in ($rows | Group-Object Technique | Sort-Object Name)) { $summary.byTechnique[$grp.Name] = $grp.Count }
$result = [pscustomobject]@{
    SchemaVersion  = 1
    GeneratedAtUtc = $Now.ToString('o')
    Source         = $Source
    TenantId       = [string]$tenant.TenantId
    DataSources    = $dataSources.ToArray()
    Summary        = $summary
    Paths          = $rows
}

Write-Console "`n==== Shadow-admin paths ($Source): $($rows.Count) ($($summary.openPaths) open, $($summary.acceptedPaths) accepted) ====" -ForegroundColor Cyan
if ($rows.Count) { $rows | Select-Object Severity, Status, Principal, Technique, Target, Privilege | Format-Table -AutoSize | Out-Host }
else { Write-Console '  No paths found.' -ForegroundColor Green }

if ($PSCmdlet.ShouldProcess($OutputDirectory, 'write shadow_admins.csv, shadow_admins.json')) {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    if ($rows.Count) { $rows | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'shadow_admins.csv') -NoTypeInformation }
    else { Set-Content -LiteralPath (Join-Path $OutputDirectory 'shadow_admins.csv') -Value '"Source","Severity","Status","Principal","Technique"' }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'shadow_admins.json') -Encoding utf8
    Write-Console "Written to $OutputDirectory" -ForegroundColor DarkGray
}

# Privileged USER ids for the ITDR detections (-PrivilegedIdsPath). Users
# only - groups and service principals are judged by their own rules - and
# both direct role holders and members of role-holding / PIM groups.
if ($PrivilegedIdsPath) {
    $privIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $roleGroups = @{}
    foreach ($a in @($tenant.Active) + @($tenant.Eligible)) {
        $pid_ = [string]$a.PrincipalId
        $type = Get-PrincipalType $pid_
        if ($type -eq 'user') { [void]$privIds.Add($pid_) }
        elseif ($type -eq 'group') { $roleGroups[$pid_] = $true }
    }
    foreach ($gid in @($tenant.GroupPim.Keys)) {
        $pim = $tenant.GroupPim[$gid]
        foreach ($m in @($pim.EligibleMembers) + @($pim.EligibleOwners) + @($pim.PermanentMembers)) {
            if ($m -and (Get-PrincipalType ([string]$m)) -eq 'user') { [void]$privIds.Add([string]$m) }
        }
    }
    $list = @($privIds | Sort-Object)
    if ($PSCmdlet.ShouldProcess($PrivilegedIdsPath, "write $($list.Count) privileged user object id(s)")) {
        ConvertTo-Json -InputObject @($list) -Compress | Set-Content -LiteralPath $PrivilegedIdsPath -Encoding utf8
        Write-Console "Privileged user ids ($($list.Count)) written to $PrivilegedIdsPath - feed TF_PRIVILEGED_USER_OBJECT_IDS / contoso_privileged_identities.csv" -ForegroundColor DarkGray
    }
}

$failedSources = @($dataSources | Where-Object { $_.Status -like 'FAILED*' })
if ($failedSources.Count) {
    Write-Console "`n$($failedSources.Count) data source(s) FAILED: $(@($failedSources | ForEach-Object Name) -join ', ') -- result INCOMPLETE, not clean." -ForegroundColor Red
    $result
    exit 1
}
if ($FailOnFinding -and $summary.openCriticalHigh) {
    Write-Console "$($summary.openCriticalHigh) open Critical/High path(s) (-FailOnFinding)." -ForegroundColor Red
    $result
    exit 2
}
return $result
