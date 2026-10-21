# Pester 5 tests for 04-Leaver.ps1 - every Graph call is mocked; no tenant.
# The leaver runs with ConfirmImpact High, so each run passes -Confirm:$false.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, Microsoft.Graph.Groups,
        Microsoft.Graph.Identity.Governance, Microsoft.Graph.Applications -ErrorAction Stop
    $script:Leaver = Get-LabScriptPath '04-Leaver.ps1'

    function New-MemberOfRow {
        # Get-MgUserMemberOf returns directoryObjects; group details live in AdditionalProperties.
        param([string]$Id, [string]$Name, [switch]$Dynamic, [switch]$Synced)
        $ap = @{ '@odata.type' = '#microsoft.graph.group'; displayName = $Name; groupTypes = @(if ($Dynamic) { 'DynamicMembership' }) }
        if ($Synced) { $ap['onPremisesSyncEnabled'] = $true }
        return [pscustomobject]@{ Id = $Id; AdditionalProperties = $ap }
    }

    function Set-LeaverMocks {
        param(
            [bool]$Synced = $false,
            [bool]$Enabled = $true,
            [object[]]$Owned = @(),
            [bool]$HasManager = $true,
            [switch]$AssignmentReadFails,
            [string[]]$SpGraphPermissions = @(),
            [string[]]$SpDirectoryRoles = @(),
            [switch]$PrivilegeReadFails
        )
        # Mock bodies run inside the script under test, so state is global.
        $global:LeaverTest = @{ Synced = $Synced; Enabled = $Enabled; Owned = $Owned; HasManager = $HasManager; Calls = [System.Collections.Generic.List[string]]::new()
            SpGraphPermissions = $SpGraphPermissions; SpDirectoryRoles = $SpDirectoryRoles; PrivilegeReadFails = [bool]$PrivilegeReadFails }
        Mock Write-Host {}
        Mock Out-Host {}
        Mock Start-Sleep {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('User.ReadWrite.All', 'User.RevokeSessions.All', 'GroupMember.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
                'Application.Read.All', 'Application.ReadWrite.All', 'EntitlementManagement.ReadWrite.All', 'Directory.Read.All', 'Synchronization.ReadWrite.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Get-MgUser { [pscustomobject]@{ Id = 'u-dana'; DisplayName = 'Dana Okafor'; AccountEnabled = $global:LeaverTest.Enabled; OnPremisesSyncEnabled = $global:LeaverTest.Synced } } -ParameterFilter { $Filter }
        Mock Get-MgUser { [pscustomobject]@{ Id = 'u-grace'; UserPrincipalName = 'grace.mwangi@contoso.test'; AccountEnabled = $true } } -ParameterFilter { $UserId -eq 'u-grace' }
        Mock Update-MgUser { $global:LeaverTest.Calls.Add('disable') }
        Mock Revoke-MgUserSignInSession { $global:LeaverTest.Calls.Add('revoke'); $true }
        if ($AssignmentReadFails) { Mock Get-MgEntitlementManagementAssignment { throw 'Forbidden' } }
        else {
            Mock Get-MgEntitlementManagementAssignment {
                @([pscustomobject]@{ Id = 'asg-1'; State = 'delivered'; AccessPackage = [pscustomobject]@{ DisplayName = 'Nurse - Clinical Apps' } })
            }
        }
        Mock New-MgEntitlementManagementAssignmentRequest { $global:LeaverTest.Calls.Add("adminRemove:$($BodyParameter.RequestType)"); [pscustomobject]@{ Id = 'req-1'; State = 'submitted' } }
        Mock Get-MgUserMemberOf {
            @(
                (New-MemberOfRow -Id 'g-nurses' -Name 'All-Nurses' -Dynamic),
                (New-MemberOfRow -Id 'g-ad' -Name 'AD-Clinical-Share' -Synced),
                (New-MemberOfRow -Id 'g-snow' -Name 'App-ServiceNow-Users')
            )
        }
        Mock Remove-MgGroupMemberDirectoryObjectByRef { $global:LeaverTest.Calls.Add("removeGroup:$GroupId") }
        Mock Get-MgUserAppRoleAssignment { @([pscustomobject]@{ Id = 'ara-1'; ResourceDisplayName = 'Legacy Rostering' }) }
        Mock Remove-MgUserAppRoleAssignment { $global:LeaverTest.Calls.Add("removeApp:$AppRoleAssignmentId") }
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*/ownedObjects*') { return @{ value = @($global:LeaverTest.Owned) } }
            if ($Uri -like '*/manager*') { if ($global:LeaverTest.HasManager) { return @{ id = 'u-grace' } } else { throw 'Resource not found: manager' } }
            if ($Method -eq 'GET' -and $Uri -like '*/owners?*') { return @{ value = @(@{ id = 'u-dana' }) } }
            if ($Method -eq 'POST' -and $Uri -like '*/owners/$ref') { $global:LeaverTest.Calls.Add('addOwner'); return $null }
            if ($Method -eq 'DELETE' -and $Uri -like '*/owners/u-dana/$ref') { $global:LeaverTest.Calls.Add('removeLeaverOwner'); return $null }
            # Privilege check (opt-in ReassignToManager only): the app's SP, Graph's app roles,
            # the SP's app-role assignments and directory roles.
            if ($global:LeaverTest.PrivilegeReadFails -and $Uri -like '*/servicePrincipals*') { throw 'Forbidden' }
            if ($Uri -like "*/servicePrincipals?*appId eq '00000003-0000-0000-c000-000000000000'*") {
                return @{ value = @(@{ id = 'sp-graph'; appRoles = @(@{ id = 'ar-rm'; value = 'RoleManagement.ReadWrite.Directory' }, @{ id = 'ar-ur'; value = 'User.Read.All' }) }) }
            }
            if ($Uri -like '*/servicePrincipals?*appId eq*') { return @{ value = @(@{ id = 'sp-app-1' }) } }
            if ($Uri -like '*/servicePrincipals/sp-app-1/appRoleAssignments*') {
                $map = @{ 'RoleManagement.ReadWrite.Directory' = 'ar-rm'; 'User.Read.All' = 'ar-ur' }
                return @{ value = @($global:LeaverTest.SpGraphPermissions | ForEach-Object { @{ appRoleId = $map[$_]; resourceId = 'sp-graph' } }) }
            }
            if ($Uri -like '*/servicePrincipals/sp-app-1/transitiveMemberOf*') { return @{ value = @($global:LeaverTest.SpDirectoryRoles | ForEach-Object { @{ displayName = $_ } }) } }
            throw "unexpected Graph call in test: $Method $Uri"
        }
    }

    function Get-Status($Report, [string]$System, [string]$Action) {
        return @($Report | Where-Object { $_.System -eq $System -and $_.Action -eq $Action } | ForEach-Object Status)
    }
}

AfterAll { Remove-Variable -Name LeaverTest -Scope Global -ErrorAction SilentlyContinue }

Describe '04-Leaver.ps1' {
    It 'cloud-only leaver: contains first, then revokes, removes packages, assigned groups and app assignments' {
        Set-LeaverMocks
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -Confirm:$false -WarningAction SilentlyContinue)
        $calls = @($global:LeaverTest.Calls)
        $calls[0] | Should -Be 'disable'      # contain first
        $calls[1] | Should -Be 'revoke'
        Get-Status $r 'Entra ID' 'Disable account' | Should -Be 'disabled'
        Get-Status $r 'Entra ID' 'Revoke sessions' | Should -Be 'revoked'
        Get-Status $r 'AccessPackage:Nurse - Clinical Apps' 'adminRemove' | Should -Be 'requested:req-1'
        # Dynamic groups drop on their own; AD-synced groups belong to AD.
        Get-Status $r 'Group:All-Nurses' 'Remove membership' | Should -Be 'skipped-dynamic'
        Get-Status $r 'Group:AD-Clinical-Share' 'Remove membership' | Should -Be 'skipped-ad-owned'
        Get-Status $r 'Group:App-ServiceNow-Users' 'Remove membership' | Should -Be 'removed'
        Should -Invoke Remove-MgGroupMemberDirectoryObjectByRef -Times 1 -Exactly -ParameterFilter { $GroupId -eq 'g-snow' }
        Get-Status $r 'App:Legacy Rostering' 'Remove assignment' | Should -Be 'removed'
        Get-Status $r 'NHI' 'Hand off ownership' | Should -Be 'none-owned'
        $r | ForEach-Object { $_.TimestampUtc | Should -Match '^\d{4}-\d{2}-\d{2}T' }
    }

    It 'synced leaver already disabled by HR: no cloud write to accountEnabled' {
        Set-LeaverMocks -Synced $true -Enabled $false
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -Confirm:$false -WarningAction SilentlyContinue)
        Should -Invoke Update-MgUser -Times 0
        Get-Status $r 'Entra ID' 'Disable account' | Should -Be 'disabled-by-hr-sync'
    }

    It 'synced leaver still enabled after the wait: records PENDING-HR-SYNC but still revokes' {
        Set-LeaverMocks -Synced $true -Enabled $true
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -WaitForDisableSeconds 0 -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'Entra ID' 'Disable account' | Should -Be 'PENDING-HR-SYNC'
        Should -Invoke Revoke-MgUserSignInSession -Times 1 -Exactly
    }

    It 'a failed assignment read is FAILED-read, never "none-active"' {
        Set-LeaverMocks -AssignmentReadFails
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'Entitlement Mgmt' 'adminRemove' | Should -Be 'FAILED-read'
        Should -Invoke New-MgEntitlementManagementAssignmentRequest -Times 0
    }

    It 'a 404 on group removal (the package already removed it) is success, not failure' {
        Set-LeaverMocks
        Mock Remove-MgGroupMemberDirectoryObjectByRef { throw 'Resource does not exist (404)' }
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'Group:App-ServiceNow-Users' 'Remove membership' | Should -Be 'removed-by-package'
    }

    It 'by DEFAULT (FlagOnly) reports owned NHIs, changes nothing and asks for no extra scope' {
        $app = @{ '@odata.type' = '#microsoft.graph.application'; id = 'app-1'; appId = 'appid-1'; displayName = 'Rostering Sync'; passwordCredentials = @(); keyCredentials = @() }
        Set-LeaverMocks -Owned @($app)
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'NHI:Rostering Sync' 'Hand off ownership' | Should -Be 'FLAGGED-review'
        @($global:LeaverTest.Calls) | Should -Not -Contain 'addOwner'
        @($global:LeaverTest.Calls) | Should -Not -Contain 'removeLeaverOwner'
        (Get-Content -Raw -LiteralPath $script:Leaver) | Should -Match "\[string\]\`$NhiHandoff = 'FlagOnly'"
    }

    It 'NHI hand-off (opt-in) adds the manager as owner BEFORE removing the leaver, and flags credentials to rotate' {
        $app = @{ '@odata.type' = '#microsoft.graph.application'; id = 'app-1'; appId = 'appid-1'; displayName = 'Rostering Sync'; passwordCredentials = @(@{ keyId = 'k1' }); keyCredentials = @() }
        Set-LeaverMocks -Owned @($app) -SpGraphPermissions @('User.Read.All')
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -NhiHandoff ReassignToManager -Confirm:$false -WarningAction SilentlyContinue)
        $calls = @($global:LeaverTest.Calls)
        $calls.IndexOf('addOwner') | Should -BeGreaterThan -1
        $calls.IndexOf('addOwner') | Should -BeLessThan $calls.IndexOf('removeLeaverOwner')   # never ownerless
        Get-Status $r 'NHI:Rostering Sync' 'Hand off ownership' | Should -Be 'reassigned:grace.mwangi@contoso.test'
        Get-Status $r 'NHI:Rostering Sync' 'Rotate credentials' | Should -Be 'FLAGGED-rotate:1'
    }

    It 'a Tier-0 app (Graph RoleManagement.ReadWrite.Directory) is NEVER handed to the manager - flagged for app governance' {
        $app = @{ '@odata.type' = '#microsoft.graph.application'; id = 'app-1'; appId = 'appid-1'; displayName = 'Role Sync'; passwordCredentials = @(); keyCredentials = @() }
        Set-LeaverMocks -Owned @($app) -SpGraphPermissions @('RoleManagement.ReadWrite.Directory')
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -NhiHandoff ReassignToManager -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'NHI:Role Sync' 'Hand off ownership' | Should -Be 'FLAGGED-privileged-owner-review'
        @($global:LeaverTest.Calls) | Should -Not -Contain 'addOwner'
        @($global:LeaverTest.Calls) | Should -Not -Contain 'removeLeaverOwner'
    }

    It 'an app holding a directory role is flagged too, and a failed privilege check flags (fail closed)' {
        $app = @{ '@odata.type' = '#microsoft.graph.application'; id = 'app-1'; appId = 'appid-1'; displayName = 'Helpdesk Bot'; passwordCredentials = @(); keyCredentials = @() }
        Set-LeaverMocks -Owned @($app) -SpDirectoryRoles @('Helpdesk Administrator')
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -NhiHandoff ReassignToManager -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'NHI:Helpdesk Bot' 'Hand off ownership' | Should -Be 'FLAGGED-privileged-owner-review'
        Set-LeaverMocks -Owned @($app) -PrivilegeReadFails
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -NhiHandoff ReassignToManager -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'NHI:Helpdesk Bot' 'Hand off ownership' | Should -Be 'FLAGGED-privileged-owner-review'
        @($global:LeaverTest.Calls) | Should -Not -Contain 'addOwner'
    }

    It 'NHI with no resolvable manager is FLAGGED and its owners are left untouched' {
        $app = @{ '@odata.type' = '#microsoft.graph.application'; id = 'app-1'; appId = 'appid-1'; displayName = 'Rostering Sync'; passwordCredentials = @(); keyCredentials = @() }
        Set-LeaverMocks -Owned @($app) -HasManager $false
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -NhiHandoff ReassignToManager -Confirm:$false -WarningAction SilentlyContinue)
        Get-Status $r 'NHI:Rostering Sync' 'Hand off ownership' | Should -Be 'FLAGGED-no-new-owner'
        @($global:LeaverTest.Calls) | Should -Not -Contain 'removeLeaverOwner'
    }

    It '-WhatIf changes nothing and reports whatif rows' {
        Set-LeaverMocks
        $r = @(& $script:Leaver -UserPrincipalName 'dana.okafor@contoso.test' -WhatIf -WarningAction SilentlyContinue)
        @($global:LeaverTest.Calls).Count | Should -Be 0
        Get-Status $r 'Entra ID' 'Revoke sessions' | Should -Be 'whatif'
        Get-Status $r 'Group:App-ServiceNow-Users' 'Remove membership' | Should -Be 'whatif'
    }
}
