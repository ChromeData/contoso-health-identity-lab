<#
  Pester 5 tests for RoleMap.psm1: pure logic, no vault, no network.
  Ported from the earlier psPAS-PAM-Automation lab; tests marked NEW were
  added while porting and fail against that lab's RoleMap.psm1.
  Run: Invoke-Pester lab/pam/cyberark/tests
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'RoleMap.psm1') -Force
}

Describe 'Get-LabRoleName' {
    It 'returns exactly the three roles the state file uses' {
        Get-LabRoleName | Should -Be @('audit', 'full', 'use')
    }
}

Describe 'Get-LabRolePermission' {
    It 'throws on an unknown role rather than returning an empty set' {
        { Get-LabRolePermission -Role 'administrator' } | Should -Throw '*Unknown role*'
    }
    It 'returns a copy, so a caller cannot change the shared definition' {
        $first = Get-LabRolePermission -Role 'audit'
        $first['ManageSafe'] = $true
        (Get-LabRolePermission -Role 'audit').ContainsKey('ManageSafe') | Should -BeFalse
    }
    It 'NEW: every role uses only real psPAS permission names' {
        # A typo here would be a parameter psPAS does not have.
        $known = Get-LabPermissionName
        foreach ($r in Get-LabRoleName) {
            (Get-LabRolePermission -Role $r).Keys | Where-Object { $_ -notin $known } | Should -BeNullOrEmpty -Because "role $r"
        }
    }
}

Describe 'Get-LabRolePermissionSet (NEW)' {
    It 'names all 22 permissions, true exactly where the role grants them' {
        foreach ($r in Get-LabRoleName) {
            $set = Get-LabRolePermissionSet -Role $r
            $set.Keys.Count | Should -Be 22
            $granted = Get-LabRolePermission -Role $r
            foreach ($k in $set.Keys) { $set[$k] | Should -Be ([bool]$granted[$k]) -Because "$r/$k" }
        }
    }
    It 'sends an explicit false for what the role does not grant (a reset removes extras)' {
        (Get-LabRolePermissionSet -Role 'audit')['RetrieveAccounts'] | Should -BeFalse
    }
}

Describe 'Role boundaries' {
    Context 'audit' {
        BeforeAll { $audit = Get-LabRolePermission -Role 'audit' }
        It 'can list accounts' { $audit['ListAccounts'] | Should -BeTrue }
        It 'CANNOT retrieve a credential' { $audit.ContainsKey('RetrieveAccounts') | Should -BeFalse }
        It 'CANNOT use an account' { $audit.ContainsKey('UseAccounts') | Should -BeFalse }
        It 'CANNOT manage membership' { $audit.ContainsKey('ManageSafeMembers') | Should -BeFalse }
    }
    Context 'use' {
        BeforeAll { $use = Get-LabRolePermission -Role 'use' }
        It 'can retrieve and connect' {
            $use['RetrieveAccounts'] | Should -BeTrue
            $use['UseAccounts'] | Should -BeTrue
        }
        It 'CANNOT manage the safe or its membership' {
            $use.ContainsKey('ManageSafe') | Should -BeFalse
            $use.ContainsKey('ManageSafeMembers') | Should -BeFalse
        }
        It 'CANNOT delete accounts' { $use.ContainsKey('DeleteAccounts') | Should -BeFalse }
    }
    Context 'full' {
        BeforeAll { $full = Get-LabRolePermission -Role 'full' }
        It 'can manage the safe and its membership' {
            $full['ManageSafe'] | Should -BeTrue
            $full['ManageSafeMembers'] | Should -BeTrue
        }
        It 'CANNOT approve access requests (no self-approval)' {
            $full.ContainsKey('requestsAuthorizationLevel1') | Should -BeFalse
            $full.ContainsKey('requestsAuthorizationLevel2') | Should -BeFalse
        }
        It 'NEW: CANNOT skip dual control (AccessWithoutConfirmation)' {
            # The earlier lab granted this to full, which made "cannot
            # self-approve" meaningless.
            $full.ContainsKey('AccessWithoutConfirmation') | Should -BeFalse
        }
    }
    It 'escalates strictly: audit is within use, use is within full' {
        $audit = (Get-LabRolePermission -Role 'audit').Keys
        $use = (Get-LabRolePermission -Role 'use').Keys
        $full = (Get-LabRolePermission -Role 'full').Keys
        ($audit | Where-Object { $_ -notin $use }) | Should -BeNullOrEmpty
        ($use | Where-Object { $_ -notin $full }) | Should -BeNullOrEmpty
    }
}

Describe 'Compare-LabRolePermission' {
    It 'reports nothing when permissions match the role exactly' {
        $actual = [pscustomobject]@{ ListAccounts = $true; ViewAuditLog = $true; ViewSafeMembers = $true }
        Compare-LabRolePermission -Role 'audit' -ActualPermissions $actual | Should -BeNullOrEmpty
    }
    It 'flags privilege creep as Extra' {
        $actual = [pscustomobject]@{ ListAccounts = $true; ViewAuditLog = $true; ViewSafeMembers = $true; RetrieveAccounts = $true }
        $d = @(Compare-LabRolePermission -Role 'audit' -ActualPermissions $actual)
        $d.Count | Should -Be 1
        $d[0].Permission | Should -Be 'RetrieveAccounts'
        $d[0].Kind | Should -Be 'Extra'
    }
    It 'flags a missing permission as Missing' {
        $d = @(Compare-LabRolePermission -Role 'audit' -ActualPermissions ([pscustomobject]@{ ListAccounts = $true; ViewAuditLog = $true }))
        ($d | Where-Object { $_.Permission -eq 'ViewSafeMembers' -and $_.Kind -eq 'Missing' }) | Should -Not -BeNullOrEmpty
    }
    It 'treats a permission set to false as absent' {
        $d = @(Compare-LabRolePermission -Role 'audit' -ActualPermissions ([pscustomobject]@{ ListAccounts = $true; ViewAuditLog = $true; ViewSafeMembers = $false }))
        ($d | Where-Object { $_.Permission -eq 'ViewSafeMembers' -and $_.Kind -eq 'Missing' }) | Should -Not -BeNullOrEmpty
    }
    It 'handles a member with no permission object at all' {
        { Compare-LabRolePermission -Role 'audit' -ActualPermissions $null } | Should -Not -Throw
    }
    It 'ignores non-boolean properties psPAS attaches' {
        $actual = [pscustomobject]@{ ListAccounts = $true; ViewAuditLog = $true; ViewSafeMembers = $true; MemberName = 'x'; MemberId = 42 }
        Compare-LabRolePermission -Role 'audit' -ActualPermissions $actual | Should -BeNullOrEmpty
    }
    It 'NEW: matches camelCase names (psPAS Gen2 returns listAccounts, not ListAccounts)' {
        $actual = [pscustomobject]@{ listAccounts = $true; viewAuditLog = $true; viewSafeMembers = $true; retrieveAccounts = $false }
        Compare-LabRolePermission -Role 'audit' -ActualPermissions $actual | Should -BeNullOrEmpty
    }
    It 'NEW: accepts a hashtable as well as an object' {
        Compare-LabRolePermission -Role 'audit' -ActualPermissions @{ ListAccounts = $true; ViewAuditLog = $true; ViewSafeMembers = $true } |
            Should -BeNullOrEmpty
    }
}
