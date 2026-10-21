# Pester 5 tests for post-apply/Set-ExternalCollaboration.ps1 (B2B external
# collaboration settings). Pure functions from the script's syntax tree, then
# the whole script against an in-memory tenant (mocked Invoke-MgGraphRequest):
# partial PATCH of only the owned properties, self-service sign-up off, the
# cross-tenant default read but never written, -WhatIf, fail-closed reads and
# the read-back. No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Sec = Get-LabScriptPath 'post-apply/Set-ExternalCollaboration.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Sec -Name 'Get-GuestRoleTemplateId', 'Get-ExternalCollaborationDesired', 'Compare-AuthorizationPolicy', 'Get-SelfServiceSignUpEnabled', 'ConvertTo-CrossTenantSummary')
    $script:Restricted = '2af84b1e-32c8-42b7-82bc-daa82404023b'
    $script:GuestUser = '10dae51f-b6af-4016-8d66-8c2a99b929b3'

    function New-CrossTenantDefault([bool]$ServiceDefault = $true, [bool]$TrustMfa = $false) {
        $blk = { param($t) @{ usersAndGroups = @{ accessType = $t }; applications = @{ accessType = $t } } }
        @{ isServiceDefault = $ServiceDefault; inboundTrust = @{ isMfaAccepted = $TrustMfa; isCompliantDeviceAccepted = $false; isHybridAzureADJoinedDeviceAccepted = $false }
            b2bCollaborationInbound = (& $blk 'allowed'); b2bCollaborationOutbound = (& $blk 'allowed')
            b2bDirectConnectInbound = (& $blk 'blocked'); b2bDirectConnectOutbound = (& $blk 'blocked') }
    }

    function Set-TenantMock {
        # Entra defaults unless told otherwise. PATCHes are recorded and, unless
        # -IgnoreWrites, applied, so the read-back sees them.
        param([hashtable]$Authz = @{ id = 'authorizationPolicy'; allowInvitesFrom = 'everyone'; guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3'; allowEmailVerifiedUsersToJoinOrganization = $true
                defaultUserRolePermissions = @{ allowedToCreateApps = $false; permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low') } },
            [hashtable]$Flows = @{ id = 'authenticationFlowsPolicy'; selfServiceSignUp = @{ isEnabled = $true } },
            [hashtable]$CrossTenant = (New-CrossTenantDefault), [string[]]$FailUris = @(), [switch]$IgnoreWrites)
        $global:SecTest = @{ Authz = $Authz; Flows = $Flows; CrossTenant = $CrossTenant; FailUris = $FailUris; Ignore = [bool]$IgnoreWrites
            Writes = [System.Collections.Generic.List[object]]::new() }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('Policy.Read.All', 'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.AuthenticationFlows') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:SecTest; $u = "$Uri"
            foreach ($f in $t.FailUris) { if ($u -like $f) { throw "HTTP 403 Forbidden ($u)" } }
            if ($Method -in 'PATCH', 'POST', 'PUT', 'DELETE') {
                $b = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null })
                $t.Writes.Add(@{ Method = $Method; Uri = $u; Body = $b })
                if (-not $t.Ignore -and $Method -eq 'PATCH') {
                    if ($u -like '*/policies/authorizationPolicy') { foreach ($k in $b.Keys) { $t.Authz[$k] = $b[$k] } }
                    if ($u -like '*/policies/authenticationFlowsPolicy') { $t.Flows['selfServiceSignUp'] = $b['selfServiceSignUp'] }
                }
                return $null
            }
            if ($u -like '*/policies/authorizationPolicy') { return $t.Authz.Clone() }
            if ($u -like '*/policies/authenticationFlowsPolicy') { return $t.Flows.Clone() }
            if ($u -like '*/policies/crossTenantAccessPolicy/default') { return $t.CrossTenant }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
}

AfterAll { Remove-Variable -Name SecTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Set-ExternalCollaboration.ps1 - pure functions' {
    It 'uses the documented guest role template ids' {
        Get-GuestRoleTemplateId Restricted | Should -Be '2af84b1e-32c8-42b7-82bc-daa82404023b'
        Get-GuestRoleTemplateId Limited | Should -Be '10dae51f-b6af-4016-8d66-8c2a99b929b3'
    }

    It 'desired state: admins + Guest Inviters, Restricted Guest User, no email-verified join, no self-service sign-up' {
        $d = Get-ExternalCollaborationDesired -AllowInvitesFrom adminsAndGuestInviters -GuestAccess Restricted
        $d.Authorization['allowInvitesFrom'] | Should -Be 'adminsAndGuestInviters'
        $d.Authorization['guestUserRoleId'] | Should -Be $script:Restricted
        $d.Authorization['allowEmailVerifiedUsersToJoinOrganization'] | Should -BeFalse
        $d.SelfServiceSignUp | Should -BeFalse
        @($d.Authorization.Keys) | Should -Not -Contain 'defaultUserRolePermissions' -Because 'user consent belongs to Set-ConsentPolicy.ps1'
    }

    It 'refuses the permissive values (<Value>)' -ForEach @(
        @{ Value = 'everyone'; Kind = 'invites' }
        @{ Value = 'adminsGuestInvitersAndAllMembers'; Kind = 'invites' }
        @{ Value = 'SameAsMembers'; Kind = 'guest' }
    ) {
        if ($Kind -eq 'invites') { { Get-ExternalCollaborationDesired -AllowInvitesFrom $Value -GuestAccess Restricted } | Should -Throw '*not allowed*' }
        else { { Get-ExternalCollaborationDesired -AllowInvitesFrom adminsAndGuestInviters -GuestAccess $Value } | Should -Throw '*not allowed*' }
    }

    It 'compares GUIDs and enums case-insensitively, booleans strictly, and treats a missing property as drift' {
        $want = (Get-ExternalCollaborationDesired -AllowInvitesFrom adminsAndGuestInviters -GuestAccess Restricted).Authorization
        $same = @{ allowInvitesFrom = 'AdminsAndGuestInviters'; guestUserRoleId = $script:Restricted.ToUpperInvariant(); allowEmailVerifiedUsersToJoinOrganization = $false }
        (Compare-AuthorizationPolicy -Current $same -Desired $want).Count | Should -Be 0
        $diff = Compare-AuthorizationPolicy -Current @{ allowInvitesFrom = 'everyone'; guestUserRoleId = $script:Restricted; allowEmailVerifiedUsersToJoinOrganization = 'false' } -Desired $want
        @($diff.Keys) | Should -Be @('allowInvitesFrom', 'allowEmailVerifiedUsersToJoinOrganization')
        @((Compare-AuthorizationPolicy -Current @{} -Desired $want).Keys).Count | Should -Be 3
    }

    It 'reads self-service sign-up as true / false, and an unknown shape as $null (drift, never "off")' {
        Get-SelfServiceSignUpEnabled -Policy @{ selfServiceSignUp = @{ isEnabled = $false } } | Should -BeFalse
        Get-SelfServiceSignUpEnabled -Policy @{ selfServiceSignUp = @{ isEnabled = $true } } | Should -BeTrue
        Get-SelfServiceSignUpEnabled -Policy @{ id = 'x' } | Should -BeNullOrEmpty
    }

    It 'summarises the cross-tenant default and warns on a customised default or tenant-wide MFA trust' {
        $s = ConvertTo-CrossTenantSummary -Default (New-CrossTenantDefault)
        $s.IsServiceDefault | Should -BeTrue
        $s.B2BCollaborationIn | Should -Be 'users allowed, apps allowed'
        $s.B2BDirectConnectIn | Should -Be 'users blocked, apps blocked'
        $s.InboundTrustAccepted | Should -Be 'none'
        @($s.Warnings).Count | Should -Be 0
        $w = ConvertTo-CrossTenantSummary -Default (New-CrossTenantDefault -ServiceDefault $false -TrustMfa $true)
        ($w.Warnings -join "`n") | Should -Match 'customised'
        ($w.Warnings -join "`n") | Should -Match 'isMfaAccepted from EVERY tenant'
    }
}

Describe 'Set-ExternalCollaboration.ps1 - against a mocked tenant' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'fixes an Entra-default tenant with partial PATCHes, never sends defaultUserRolePermissions, never writes cross-tenant access' {
        Set-TenantMock
        $out = @(& $script:Sec -Confirm:$false)
        $LASTEXITCODE | Should -Be 0
        $w = @($global:SecTest.Writes)
        $w.Count | Should -Be 2
        $w[0].Method | Should -Be 'PATCH'; $w[0].Uri | Should -BeLike '*/v1.0/policies/authorizationPolicy'
        @($w[0].Body.Keys | Sort-Object) | Should -Be @('allowEmailVerifiedUsersToJoinOrganization', 'allowInvitesFrom', 'guestUserRoleId')
        $w[0].Body['allowInvitesFrom'] | Should -Be 'adminsAndGuestInviters'
        $w[0].Body['guestUserRoleId'] | Should -Be $script:Restricted
        $w[0].Body['allowEmailVerifiedUsersToJoinOrganization'] | Should -BeFalse
        $w[1].Uri | Should -BeLike '*/v1.0/policies/authenticationFlowsPolicy'
        $w[1].Body['selfServiceSignUp']['isEnabled'] | Should -BeFalse
        @($w | Where-Object { $_.Uri -like '*crossTenantAccessPolicy*' }).Count | Should -Be 0
        $global:SecTest.Authz['defaultUserRolePermissions']['permissionGrantPoliciesAssigned'] | Should -Be @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
        @($out | Where-Object Status -eq 'updated').Count | Should -Be 4
        ($out | Where-Object Setting -eq 'crossTenantAccessPolicy/default').Status | Should -Contain 'report'
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'sends only the drifted property' {
        Set-TenantMock -Authz @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = $script:GuestUser; allowEmailVerifiedUsersToJoinOrganization = $false } -Flows @{ selfServiceSignUp = @{ isEnabled = $false } }
        & $script:Sec -Confirm:$false | Out-Null
        $LASTEXITCODE | Should -Be 0
        @($global:SecTest.Writes).Count | Should -Be 1
        @($global:SecTest.Writes[0].Body.Keys) | Should -Be @('guestUserRoleId')
    }

    It 'is idempotent: a tenant already in the desired state gets no write' {
        Set-TenantMock -Authz @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = $script:Restricted; allowEmailVerifiedUsersToJoinOrganization = $false } -Flows @{ selfServiceSignUp = @{ isEnabled = $false } }
        $out = @(& $script:Sec -Confirm:$false)
        $LASTEXITCODE | Should -Be 0
        $global:SecTest.Writes.Count | Should -Be 0
        @($out | Where-Object Status -eq 'in-sync').Count | Should -Be 4
    }

    It '-GuestAccess Limited sets the Guest User role (also passes MS.AAD.8.1)' {
        Set-TenantMock -Authz @{ allowInvitesFrom = 'adminsAndGuestInviters'; guestUserRoleId = $script:Restricted; allowEmailVerifiedUsersToJoinOrganization = $false } -Flows @{ selfServiceSignUp = @{ isEnabled = $false } }
        & $script:Sec -GuestAccess Limited -Confirm:$false | Out-Null
        $LASTEXITCODE | Should -Be 0
        @($global:SecTest.Writes).Count | Should -Be 1
        $global:SecTest.Writes[0].Body['guestUserRoleId'] | Should -Be $script:GuestUser
    }

    It '-WhatIf writes nothing and still reports the plan' {
        Set-TenantMock
        $out = @(& $script:Sec -WhatIf)
        $LASTEXITCODE | Should -Be 0
        $global:SecTest.Writes.Count | Should -Be 0
        @($out | Where-Object Status -eq 'would-update').Count | Should -Be 4
    }

    It 'a failed read stops before any write (exit 1)' {
        Set-TenantMock -FailUris @('*/policies/authenticationFlowsPolicy')
        $out = @(& $script:Sec -Confirm:$false)
        $LASTEXITCODE | Should -Be 1
        $global:SecTest.Writes.Count | Should -Be 0
        ($out | Where-Object Status -eq 'failed').Detail | Should -BeLike '*Nothing was changed*'
    }

    It 'a write the service did not keep fails the read-back (exit 1)' {
        Set-TenantMock -IgnoreWrites
        $out = @(& $script:Sec -Confirm:$false)
        $LASTEXITCODE | Should -Be 1
        @($out | Where-Object { $_.Setting -like 'read-back*' -and $_.Status -eq 'failed' }).Count | Should -Be 2
    }

    It 'an unreadable cross-tenant default is reported, not fatal; a customised default is a warning' {
        Set-TenantMock -FailUris @('*crossTenantAccessPolicy*')
        & $script:Sec -Confirm:$false | Out-Null
        $LASTEXITCODE | Should -Be 0
        Set-TenantMock -CrossTenant (New-CrossTenantDefault -ServiceDefault $false)
        $out = @(& $script:Sec -Confirm:$false)
        ($out | Where-Object { $_.Setting -eq 'crossTenantAccessPolicy/default' -and $_.Status -eq 'warning' }).Detail | Should -Match 'customised'
    }

    It 'refuses a permissive -AllowInvitesFrom at the parameter' {
        Set-TenantMock
        { & $script:Sec -AllowInvitesFrom everyone -Confirm:$false } | Should -Throw
        $global:SecTest.Writes.Count | Should -Be 0
    }
}

Describe 'Set-ExternalCollaboration.ps1 -OfflinePreview' {
    It 'prints the bodies and makes no Graph call' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'no Graph in -OfflinePreview' }
        $out = @(& $script:Sec -OfflinePreview)
        @($out | Where-Object Status -eq 'preview').Count | Should -Be 5
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }
}
