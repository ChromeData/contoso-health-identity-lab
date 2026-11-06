<#
.SYNOPSIS
  Maps the three role names used in intended-state.json to CyberArk safe
  member permissions. The ONLY place that translation lives.

.DESCRIPTION
  WHY: a CyberArk safe membership is 22 separate yes/no permissions. Hand that
  to whoever edits the state file and two people who both mean "auditor" tick
  different boxes. So the state file speaks in three roles, and every script
  that writes a membership (Invoke-SafeReconcile.ps1, New-LabSafe.ps1) gets
  its permissions from here.

  The earlier lab (psPAS-PAM-Automation) had a second, hand-written role map
  inside New-LabSafe.ps1 that disagreed with this one: its 'audit' had no
  ViewSafeMembers, its 'use' had no ViewAuditLog, ViewSafeMembers or
  InitiateCPMAccountManagementOperations, and its 'full' lacked 11 of the
  permissions below. A safe created by New-LabSafe.ps1 was then reported as
  drift by the reconciler on its first run. Tests now pin that both scripts
  write exactly what this module returns.

    audit - can see that an account exists and read the log. Cannot retrieve
            a credential: ListAccounts feels harmless, RetrieveAccounts is the
            real line between oversight and access.
    use   - can retrieve and connect, and ask the CPM to change a password.
            Cannot manage the safe or its members, cannot delete.
    full  - administers the safe and its membership. It does NOT get:
              * RequestsAuthorizationLevel1/2 (approving access requests), so
                an administrator cannot approve their own request;
              * AccessWithoutConfirmation (skip dual control). The earlier lab
                granted it to 'full', which made the "cannot self-approve"
                line meaningless: a member who never needs approval has
                nothing to self-approve. Removed while porting; the lab's
                Tier-0 dual control (two approvers) depends on it.

  Permission names are psPAS 8.2.0's Add-PASSafeMember / Set-PASSafeMember
  Gen2 [boolean] parameters (pspete/psPAS, psPAS/Public/SafeMembers/*.ps1,
  read 2026-11-06). $script:AllPermissions is that list; a test fails if a
  role uses a name outside it.
#>

Set-StrictMode -Version Latest

$script:AllPermissions = @(
    'UseAccounts', 'RetrieveAccounts', 'ListAccounts', 'AddAccounts',
    'UpdateAccountContent', 'UpdateAccountProperties',
    'InitiateCPMAccountManagementOperations', 'SpecifyNextAccountContent',
    'RenameAccounts', 'DeleteAccounts', 'UnlockAccounts', 'ManageSafe',
    'ManageSafeMembers', 'BackupSafe', 'ViewAuditLog', 'ViewSafeMembers',
    'requestsAuthorizationLevel1', 'requestsAuthorizationLevel2',
    'AccessWithoutConfirmation', 'CreateFolders', 'DeleteFolders',
    'MoveAccountsAndFolders'
)

$script:RoleDefinitions = @{

    audit = @{
        ListAccounts    = $true
        ViewAuditLog    = $true
        ViewSafeMembers = $true
    }

    use = @{
        UseAccounts                            = $true
        RetrieveAccounts                       = $true
        ListAccounts                           = $true
        ViewAuditLog                           = $true
        ViewSafeMembers                        = $true
        InitiateCPMAccountManagementOperations = $true
    }

    full = @{
        UseAccounts                            = $true
        RetrieveAccounts                       = $true
        ListAccounts                           = $true
        AddAccounts                            = $true
        UpdateAccountContent                   = $true
        UpdateAccountProperties                = $true
        InitiateCPMAccountManagementOperations = $true
        SpecifyNextAccountContent              = $true
        RenameAccounts                         = $true
        DeleteAccounts                         = $true
        UnlockAccounts                         = $true
        ManageSafe                             = $true
        ManageSafeMembers                      = $true
        BackupSafe                             = $true
        ViewAuditLog                           = $true
        ViewSafeMembers                        = $true
    }
}

function Get-LabPermissionName {
    <#
    .SYNOPSIS
      Every safe member permission the scripts know (psPAS 8.2.0 Gen2 names).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return , $script:AllPermissions.Clone()
}

function Get-LabRoleName {
    <#
    .SYNOPSIS
      The valid role names. Used to validate the state file before any write.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($script:RoleDefinitions.Keys | Sort-Object)
}

function Get-LabRolePermission {
    <#
    .SYNOPSIS
      The permissions a role GRANTS (only the true ones), as a hashtable copy.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Role)

    if (-not $script:RoleDefinitions.ContainsKey($Role)) {
        throw "Unknown role '$Role'. Valid roles: $((Get-LabRoleName) -join ', ')"
    }
    # A copy, so a caller cannot change the definition for everyone else.
    return $script:RoleDefinitions[$Role].Clone()
}

function Get-LabRolePermissionSet {
    <#
    .SYNOPSIS
      The COMPLETE permission set for a role: every known permission, true if
      the role grants it, false otherwise. Splat it into Add-PASSafeMember or
      Set-PASSafeMember.

    .DESCRIPTION
      WHY every permission, not just the true ones: a reset to a role must take
      away what the role does not grant. The earlier reconciler sent only the
      true ones to Set-PASSafeMember and relied on the API treating anything
      not sent as "remove" - an assumption nobody had checked against a vault.
      Sending false explicitly makes the reset mean the same thing whatever the
      API does with omitted fields.

    .EXAMPLE
      $p = Get-LabRolePermissionSet -Role audit
      Add-PASSafeMember -SafeName CH-Tier0-Admins -MemberName CH-PAM-Auditors @p
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Role)

    $granted = Get-LabRolePermission -Role $Role
    $set = @{}
    foreach ($name in $script:AllPermissions) { $set[$name] = [bool]$granted[$name] }
    return $set
}

function Compare-LabRolePermission {
    <#
    .SYNOPSIS
      Compares a live member's permissions with what their role grants.

    .DESCRIPTION
      Two kinds of mismatch, not equally urgent:
        Extra   - the member holds a permission the role does not grant.
                  Privilege creep: the finding that matters.
        Missing - the role grants it, the member lacks it. Usually a broken
                  workflow, not a security problem.
      Property names are matched without regard to case (psPAS Gen2 returns
      camelCase, e.g. listAccounts); non-boolean properties are ignored.

    .OUTPUTS
      PSCustomObject with Permission, Expected, Actual, Kind
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Role,
        [Parameter(Mandatory)][AllowNull()]$ActualPermissions
    )

    $expected = Get-LabRolePermission -Role $Role
    $results = [System.Collections.Generic.List[object]]::new()

    $actual = @{}   # @{} is case-insensitive: listAccounts == ListAccounts
    if ($null -ne $ActualPermissions) {
        $props = if ($ActualPermissions -is [System.Collections.IDictionary]) {
            $ActualPermissions.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name = $_.Key; Value = $_.Value } }
        } else { $ActualPermissions.PSObject.Properties }
        foreach ($p in $props) {
            if ($p.Value -is [bool]) { $actual[[string]$p.Name] = $p.Value }
        }
    }

    foreach ($name in $expected.Keys) {
        if (-not ($actual.ContainsKey($name) -and $actual[$name])) {
            $results.Add([pscustomobject]@{ Permission = $name; Expected = $true; Actual = $false; Kind = 'Missing' })
        }
    }
    foreach ($name in $actual.Keys) {
        if ($actual[$name] -and -not $expected.ContainsKey($name)) {
            $results.Add([pscustomobject]@{ Permission = $name; Expected = $false; Actual = $true; Kind = 'Extra' })
        }
    }
    return $results
}

Export-ModuleMember -Function Get-LabPermissionName, Get-LabRoleName, Get-LabRolePermission,
Get-LabRolePermissionSet, Compare-LabRolePermission
