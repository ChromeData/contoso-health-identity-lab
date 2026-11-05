# Pester 5 tests for post-apply/New-RestrictedAdminUnit.ps1.
#   * Pure helpers (from the syntax tree): the create body, what to do with
#     the AUs Graph returns, the privilege finding that keeps admins out.
#   * Whole-script runs against a mocked tenant (Invoke-MgGraphRequest mock
#     with the real cmdlet's signature): create-or-skip, immutable-flag
#     conflict, fail-closed reads, member guards, -WhatIf, the RMAU-scoped
#     responder grant (-ResponderGroupName, through PIM) and the app-only
#     sign-in (-UseAzureCliToken; az and Connect-MgGraph are mocks).
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Rau = Get-LabScriptPath 'post-apply/New-RestrictedAdminUnit.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Rau -Name 'Test-BreakGlassUpn', 'Test-AdminAccountUpn', 'Get-RestrictedAuBody', 'Resolve-ExistingAu', 'Get-PrivilegeFinding', 'Get-MissingGraphPermission', 'Get-ResponderRequestBody')

    function Set-RauMock {
        param(
            [hashtable[]]$Units = @(),
            [string[]]$Members = @(),
            [hashtable]$Users = @{ 'helen.carter@contosohealth.io' = 'u-helen'; 'omar.haddad@contosohealth.io' = 'u-omar' },
            [hashtable]$Privilege = @{},   # userId -> @{ RoleAssignments=..; Groups=..; GroupEligibilities=.. }
            [switch]$FailAuRead, [switch]$FailPrivilegeRead, [switch]$CreatedUnrestricted,
            # AU id -> number of role assignments scoped to it (the RMAU-scoped responder).
            [hashtable]$Responders = @{ 'au-1' = 1 },
            # Group display name -> group object (the -ResponderGroupName lookup).
            [hashtable]$Groups = @{ 'PIM-Tier0-Privileged-Auth-Admins' = @{ id = 'g-vip'; displayName = 'PIM-Tier0-Privileged-Auth-Admins'; isAssignableToRole = $true } },
            # 'groupId|roleTemplateId|auId' the group already holds.
            [string[]]$GroupRoles = @(),
            # How many PIM requests answer 404 first (a just-created AU PIM cannot see yet).
            [int]$PimNotFound = 0
        )
        $global:RauTest = @{ Units = $Units; Members = $Members; Users = $Users; Privilege = $Privilege; FailAuRead = [bool]$FailAuRead; FailPriv = [bool]$FailPrivilegeRead; Unrestricted = [bool]$CreatedUnrestricted; Responders = $Responders
            Groups = $Groups; GroupRoles = [System.Collections.Generic.List[string]]::new([string[]]$GroupRoles); PimNotFound = $PimNotFound
            Posts = [System.Collections.Generic.List[object]]::new() }
        Mock Write-Host {}
        Mock Start-Sleep {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('AdministrativeUnit.ReadWrite.All', 'User.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:RauTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -eq 'POST') {
                $b = $Body | ConvertFrom-Json -AsHashtable
                $t.Posts.Add(@{ Uri = $u; Body = $b })
                if ($u -like '*/directory/administrativeUnits') { return @{ id = 'au-new'; displayName = $b['displayName'] } }
                if ($u -like '*/roleManagement/directory/roleAssignmentScheduleRequests') {
                    if ($t.PimNotFound -gt 0) { $t.PimNotFound--; $t.Posts.RemoveAt($t.Posts.Count - 1); throw 'Response status code does not indicate success: NotFound (Not Found).' }
                    # PIM provisions the assignment: it now counts as a responder.
                    $au = ([string]$b['directoryScopeId']).Split('/')[-1]
                    $t.GroupRoles.Add("$($b['principalId'])|$($b['roleDefinitionId'])|$au")
                    $t.Responders[$au] = 1 + $(if ($t.Responders.ContainsKey($au)) { [int]$t.Responders[$au] } else { 0 })
                    return @{ id = "req-$($t.Posts.Count)"; status = 'Provisioned' }
                }
                return $null
            }
            if ($u -match "/groups\?\`$filter=displayName eq '(?<n>[^']+)'") {
                $n = $Matches.n
                return @{ value = @(if ($t.Groups.ContainsKey($n)) { $t.Groups[$n] }) }
            }
            if ($u -match "roleAssignments\?\`$filter=principalId eq '(?<p>[^']+)' and roleDefinitionId eq '(?<r>[^']+)' and directoryScopeId eq '/administrativeUnits/(?<au>[^']+)'") {
                $k = "$($Matches.p)|$($Matches.r)|$($Matches.au)"
                return @{ value = @(if ($t.GroupRoles.Contains($k)) { @{ id = "ra-$k" } }) }
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

    It 'treats app-only roles that are a superset as covering the delegated reads' {
        $operator = @('AdministrativeUnit.ReadWrite.All', 'Directory.Read.All', 'RoleManagement.ReadWrite.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
        Get-MissingGraphPermission -Have $operator -Required @('AdministrativeUnit.ReadWrite.All', 'User.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'RoleManagement.ReadWrite.Directory') | Should -BeNullOrEmpty
        Get-MissingGraphPermission -Have @('Directory.Read.All') -Required @('User.Read.All', 'RoleManagement.ReadWrite.Directory') | Should -Be @('RoleManagement.ReadWrite.Directory') -Because 'a Read role never covers a write'
        Get-MissingGraphPermission -Have @() -Required @('User.Read.All') | Should -BeNullOrEmpty -Because 'no scope list = unknown, no warning'
    }

    It 'asks PIM for an ACTIVE, non-expiring assignment of one role at the RMAU scope, held by the group' {
        $b = Get-ResponderRequestBody -GroupId 'g-vip' -RoleTemplateId '729827e3-9c14-49f7-bb1b-9608f156bbb8' -AuId 'au-1' -StartUtc ([datetime]::new(2026, 11, 5, 10, 0, 0, [DateTimeKind]::Utc))
        $b.action | Should -Be 'adminAssign'
        $b.principalId | Should -Be 'g-vip'
        $b.directoryScopeId | Should -Be '/administrativeUnits/au-1'
        $b.scheduleInfo.expiration.type | Should -Be 'noExpiration'
        $b.scheduleInfo.startDateTime | Should -Be '2026-11-05T10:00:00Z'
        $b.justification | Should -Not -BeNullOrEmpty
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

    It '-ResponderGroupName gives the group Helpdesk + Authentication Administrator at the RMAU scope through PIM, then adds the VIP' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Responders @{}
        & $Rau -ResponderGroupName 'PIM-Tier0-Privileged-Auth-Admins' -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        $pim = @($global:RauTest.Posts | Where-Object { $_.Uri -like '*/roleAssignmentScheduleRequests' })
        $pim.Count | Should -Be 2
        @($pim | ForEach-Object { $_.Body.roleDefinitionId }) | Should -Be @('729827e3-9c14-49f7-bb1b-9608f156bbb8', 'c4e39bd9-1100-46d3-8c65-fb160da0071f')
        @($pim | Where-Object { $_.Body.principalId -eq 'g-vip' -and $_.Body.directoryScopeId -eq '/administrativeUnits/au-1' -and $_.Body.action -eq 'adminAssign' }).Count | Should -Be 2
        @($global:RauTest.Posts | Where-Object { $_.Uri -like '*/members/$ref' }).Count | Should -Be 1
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' -and "$Uri" -like '*/roleManagement/directory/roleAssignments' } -Because 'never a direct write that bypasses PIM'
    }

    It '-ResponderGroupName retries a NotFound only while PIM catches up with an RMAU created in this run' {
        Set-RauMock -Responders @{} -PimNotFound 2
        & $Rau -ResponderGroupName 'PIM-Tier0-Privileged-Auth-Admins' -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        @($global:RauTest.Posts | Where-Object { $_.Uri -like '*/roleAssignmentScheduleRequests' }).Count | Should -Be 2
        @($global:RauTest.Posts | Where-Object { $_.Uri -like '*/members/$ref' }).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 2 -Exactly -ParameterFilter { $Seconds -eq 10 }
    }

    It '-ResponderGroupName does NOT retry a NotFound on an RMAU that already existed (fail closed)' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Responders @{} -PimNotFound 1
        Mock Write-Warning {}
        & $Rau -ResponderGroupName 'PIM-Tier0-Privileged-Auth-Admins' -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It '-ResponderGroupName skips roles the group already holds there' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) `
            -GroupRoles @('g-vip|729827e3-9c14-49f7-bb1b-9608f156bbb8|au-1', 'g-vip|c4e39bd9-1100-46d3-8c65-fb160da0071f|au-1')
        & $Rau -ResponderGroupName 'PIM-Tier0-Privileged-Auth-Admins' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It '-ResponderGroupName refuses a group that is not role-assignable, and adds nobody' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Responders @{} `
            -Groups @{ 'VIP-Support' = @{ id = 'g-x'; displayName = 'VIP-Support'; isAssignableToRole = $false } }
        Mock Write-Warning {}
        & $Rau -ResponderGroupName 'VIP-Support' -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'not role-assignable' }
    }

    It '-ResponderGroupName stops when the group is missing (not found is not "no responder needed")' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Groups @{}
        Mock Write-Warning {}
        & $Rau -ResponderGroupName 'PIM-Tier0-Privileged-Auth-Admins' -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:RauTest.Posts.Count | Should -Be 0
    }

    It '-UseAzureCliToken signs in app-only with the Azure CLI token, never with delegated scopes' {
        Set-RauMock -Units @(@{ id = 'au-1'; displayName = 'RMAU-VIP'; isMemberManagementRestricted = $true }) -Members @('u-helen')
        $global:RauFakeToken = 'header.payload.signature'
        Mock az { $global:LASTEXITCODE = 0; $global:RauFakeToken }
        Mock Connect-MgGraph {}
        & $Rau -UseAzureCliToken -MemberUserPrincipalNames 'helen.carter@contosohealth.io' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $AccessToken -is [securestring] -and [System.Net.NetworkCredential]::new('', $AccessToken).Password -eq $global:RauFakeToken }
        Should -Invoke Connect-MgGraph -Times 0 -ParameterFilter { $Scopes }
        Remove-Variable -Name RauFakeToken -Scope Global
    }

    It '-UseAzureCliToken with no Azure CLI token stops before any Graph call' {
        Set-RauMock
        Mock az { $global:LASTEXITCODE = 1 }
        Mock Connect-MgGraph {}
        { & $Rau -UseAzureCliToken -Confirm:$false } | Should -Throw '*No Microsoft Graph token*'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'documents the consequences an operator must accept in its help' {
        $help = Get-Help $Rau -Full | Out-String
        foreach ($s in 'immutable', 'Lifecycle Workflows', 'access reviews', 'APPLICATION permissions', 'password', '100', 'containment playbook', 'RMAU-scoped responder', 'role-assigned-outside-pim') { $help | Should -Match ([regex]::Escape($s)) }
    }
}
