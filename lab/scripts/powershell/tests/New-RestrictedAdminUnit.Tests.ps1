# Pester 5 tests for post-apply/New-RestrictedAdminUnit.ps1.
#   * Pure helpers (from the syntax tree): the create body, what to do with
#     the AUs Graph returns, the privilege finding that keeps admins out.
#   * Whole-script runs against a mocked tenant (Invoke-MgGraphRequest mock
#     with the real cmdlet's signature): create-or-skip, immutable-flag
#     conflict, fail-closed reads, member guards, -WhatIf.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Rau = Get-LabScriptPath 'post-apply/New-RestrictedAdminUnit.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Rau -Name 'Test-BreakGlassUpn', 'Test-AdminAccountUpn', 'Get-RestrictedAuBody', 'Resolve-ExistingAu', 'Get-PrivilegeFinding')

    function Set-RauMock {
        param(
            [hashtable[]]$Units = @(),
            [string[]]$Members = @(),
            [hashtable]$Users = @{ 'helen.carter@contosohealth.io' = 'u-helen'; 'omar.haddad@contosohealth.io' = 'u-omar' },
            [hashtable]$Privilege = @{},   # userId -> @{ RoleAssignments=..; Groups=..; GroupEligibilities=.. }
            [switch]$FailAuRead, [switch]$FailPrivilegeRead, [switch]$CreatedUnrestricted,
            # AU id -> number of role assignments scoped to it (the RMAU-scoped responder).
            [hashtable]$Responders = @{ 'au-1' = 1 }
        )
        $global:RauTest = @{ Units = $Units; Members = $Members; Users = $Users; Privilege = $Privilege; FailAuRead = [bool]$FailAuRead; FailPriv = [bool]$FailPrivilegeRead; Unrestricted = [bool]$CreatedUnrestricted; Responders = $Responders
            Posts = [System.Collections.Generic.List[object]]::new() }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('AdministrativeUnit.ReadWrite.All', 'User.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:RauTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -eq 'POST') {
                $b = $Body | ConvertFrom-Json -AsHashtable
                $t.Posts.Add(@{ Uri = $u; Body = $b })
                if ($u -like '*/directory/administrativeUnits') { return @{ id = 'au-new'; displayName = $b['displayName'] } }
                return $null
            }
            if ($u -match '/directory/administrativeUnits/au-new\?') { return @{ id = 'au-new'; isMemberManagementRestricted = (-not $t.Unrestricted) } }
            if ($u -match "/directory/administrativeUnits\?\`$filter=displayName eq '") {
                if ($t.FailAuRead) { throw 'HTTP 503 Service Unavailable' }
                return @{ value = @($t.Units) }
            }
            if ($u -match '/directory/administrativeUnits/(?<id>[^/]+)/members') { return @{ value = @($t.Members | ForEach-Object { @{ id = $_ } }) } }
            if ($u -match "role(Assignments|EligibilitySchedules)\?\`$filter=directoryScopeId eq '/administrativeUnits/(?<au>[^']+)'") {
                $au = $Matches.au; $isAssign = $u -like '*roleAssignments*'
                $n = if ($isAssign -and $t.Responders.ContainsKey($au)) { [int]$t.Responders[$au] } else { 0 }
                return @{ value = @(if ($n) { 1..$n | ForEach-Object { @{ id = "ra-$_"; roleDefinitionId = '729827e3-9c14-49f7-bb1b-9608f156bbb8' } } }) }
            }
            if ($u -match "/users\?\`$filter=userPrincipalName eq '(?<n>[^']+)'") {
                $n = $Matches.n
                return @{ value = @(if ($t.Users.ContainsKey($n)) { @{ id = $t.Users[$n]; displayName = $n } }) }
            }
            if ($t.FailPriv) { throw 'HTTP 403 Forbidden' }
            if ($u -match "roleAssignments\?\`$filter=principalId eq '(?<p>[^']+)'") { $p = $Matches.p; return @{ value = @(if ($t.Privilege.ContainsKey($p) -and $t.Privilege[$p].ContainsKey('RoleAssignments')) { $t.Privilege[$p].RoleAssignments }) } }
            if ($u -match "roleEligibilitySchedules\?\`$filter=principalId eq '(?<p>[^']+)'") { return @{ value = @() } }
            if ($u -match '/users/(?<p>[^/]+)/transitiveMemberOf') { $p = $Matches.p; return @{ value = @(if ($t.Privilege.ContainsKey($p) -and $t.Privilege[$p].ContainsKey('Groups')) { $t.Privilege[$p].Groups }) } }
            if ($u -match "group/eligibilitySchedules\?\`$filter=principalId eq '(?<p>[^']+)'") { $p = $Matches.p; return @{ value = @(if ($t.Privilege.ContainsKey($p) -and $t.Privilege[$p].ContainsKey('GroupEligibilities')) { $t.Privilege[$p].GroupEligibilities }) } }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
}

AfterAll { Remove-Variable -Name RauTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'New-RestrictedAdminUnit.ps1 - helpers' {
    It 'creates the AU with the immutable restricted-management flag' {
        $b = Get-RestrictedAuBody -DisplayName 'RMAU-VIP' -Description 'd'
        $b.isMemberManagementRestricted | Should -BeTrue
        $b.displayName | Should -Be 'RMAU-VIP'
    }

    It 'decides create / exists / conflict from what Graph returned' {
        (Resolve-ExistingAu -Units @() -DisplayName 'RMAU-VIP').Action | Should -Be 'create'
        (Resolve-ExistingAu -Units @(@{ id = 'a'; isMemberManagementRestricted = $true }) -DisplayName 'RMAU-VIP').Action | Should -Be 'exists'
        $c = Resolve-ExistingAu -Units @(@{ id = 'a'; isMemberManagementRestricted = $false }) -DisplayName 'RMAU-VIP'
        $c.Action | Should -Be 'conflict'
        $c.Reason | Should -Match 'immutable'
        (Resolve-ExistingAu -Units @(@{ id = 'a'; isMemberManagementRestricted = $null }) -DisplayName 'RMAU-VIP').Action | Should -Be 'conflict' -Because 'null means an ordinary AU'
        (Resolve-ExistingAu -Units @(@{ id = 'a'; isMemberManagementRestricted = $true }, @{ id = 'b'; isMemberManagementRestricted = $true }) -DisplayName 'RMAU-VIP').Action | Should -Be 'conflict'
    }

    It 'finds privilege that must keep a user out of an RMAU' {
        (Get-PrivilegeFinding).Count | Should -Be 0
        (Get-PrivilegeFinding -Groups @(@{ displayName = 'All-Nurses'; isAssignableToRole = $false })).Count | Should -Be 0
        (Get-PrivilegeFinding -Groups @(@{ displayName = 'PIM-Tier1-Helpdesk'; isAssignableToRole = $true })) | Should -Match 'PIM-Tier1-Helpdesk'
        (Get-PrivilegeFinding -RoleAssignments @(@{ id = 'ra' }) -GroupEligibilities @(@{ id = 'ge' })).Count | Should -Be 2
    }
}

Describe 'New-RestrictedAdminUnit.ps1 - against a mocked tenant' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'creates RMAU-VIP restricted and confirms the flag - but adds NOBODY while no role is scoped to it (no responder yet)' {
        Set-RauMock
        Mock Write-Warning {}
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 1
        $global:RauTest.Posts[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/directory/administrativeUnits'
        $global:RauTest.Posts[0].Body.isMemberManagementRestricted | Should -BeTrue
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'No directory role is assigned or eligible' -and $Message -match 'automated containment' }
    }

    It 'adds a VIP by $ref once an RMAU-scoped responder role exists' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true })
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        $global:RauTest.Posts.Count | Should -Be 1
        $global:RauTest.Posts[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/directory/administrativeUnits/au-1/members/$ref'
        $global:RauTest.Posts[0].Body.'@odata.id' | Should -Be 'https://graph.microsoft.com/v1.0/users/u-helen'
    }

    It 'refuses every member of an existing RMAU that has no scoped role' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Responders @{}
        Mock Write-Warning {}
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It 'stops before adding anyone when the created AU does not read back as restricted' {
        Set-RauMock -CreatedUnrestricted -Responders @{ 'au-new' = 1 }
        Mock Write-Warning {}
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        @($global:RauTest.Posts | Where-Object { $_.Uri -like '*/members/$ref' }).Count | Should -Be 0
    }

    It 'leaves an existing restricted AU alone and skips existing members' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Members @('u-helen')
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It 'refuses to "convert" an ordinary AU of the same name (the flag is immutable)' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $false })
        Mock Write-Warning {}
        & $Rau -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'immutable' }
    }

    It 'a failed AU read creates nothing (no duplicate RMAU)' {
        Set-RauMock -FailAuRead
        Mock Write-Warning {}
        & $Rau -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It 'refuses break-glass and adm- accounts without looking them up' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true })
        Mock Write-Warning {}
        & $Rau -MemberUserPrincipalNames 'bg-admin-01@contosohealthlab.onmicrosoft.com', 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { "$Uri" -match 'userPrincipalName' }
    }

    It 'refuses a user who holds privilege (role-assignable group membership) and adds the others' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) `
            -Privilege @{ 'u-omar' = @{ Groups = @(@{ id = 'g'; displayName = 'Privileged-IAM-Admins'; isAssignableToRole = $true }) } }
        Mock Write-Warning {}
        & $Rau -MemberUserPrincipalNames 'omar.haddad@contosohealth.io', 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        @($global:RauTest.Posts | ForEach-Object { $_.Body.'@odata.id' }) | Should -Be @('https://graph.microsoft.com/v1.0/users/u-helen')
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'omar' -and $Message -match 'Privileged-IAM-Admins' }
    }

    It 'fails closed when the privilege check cannot be read' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -FailPrivilegeRead
        Mock Write-Warning {}
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It '-WhatIf with a Graph session creates nothing' {
        Set-RauMock
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -WhatIf
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It '-WhatIf without a Graph session makes no Graph call at all' {
        Set-RauMock
        Mock Get-MgContext { $null }
        & $Rau -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -WhatIf
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
    }

    It 'documents the consequences an operator must accept in its help' {
        $help = Get-Help $Rau -Full | Out-String
        foreach ($s in 'immutable', 'Lifecycle Workflows', 'access reviews', 'APPLICATION permissions', 'password', '100', 'containment playbook', 'RMAU-scoped responder') { $help | Should -Match ([regex]::Escape($s)) }
    }
}
