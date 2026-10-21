# Pester 5 tests for 01-Verify-Baseline.ps1.
#   * Checks 5 and 6 as pure functions (Get-DirectRoleFinding,
#     Get-TierGroupFinding), loaded from the script's syntax tree.
#   * Whole-script runs against a tiny tenant served by mocked Graph SDK
#     cmdlets and a mocked Invoke-MgGraphRequest: the build account is the one
#     WARN before conversion and a PASS after it; an unreadable source FAILs.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    # Real SDK modules so Mock copies the true cmdlet signatures.
    Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    $script:Vb = Get-LabScriptPath '01-Verify-Baseline.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Vb -Name 'Get-RoleTierMap', 'Get-DirectRoleFinding', 'Get-TierGroupFinding', 'Test-PasskeyCoverage', 'Get-PasskeyCoverageFinding')
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    $script:HD = '729827e3-9c14-49f7-bb1b-9608f156bbb8'   # Helpdesk Administrator (Tier 1)
    $script:AA = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'   # Application Administrator (Tier 0)
    $script:Priv = [ordered]@{}; $m = Get-RoleTierMap; foreach ($k in $m.Keys) { $script:Priv[$k] = $m[$k]['Name'] }
    $script:Build = 'admin@contosolab.onmicrosoft.com'
    function New-Row([string]$Id, [string]$Type, [string]$Name, [string]$Role = $script:GA, [string]$Kind = 'Assigned', [string]$MemberType = 'Direct') {
        [pscustomobject]@{ PrincipalId = $Id; PrincipalType = $Type; Name = $Name; RoleDefinitionId = $Role; AssignmentType = $Kind; MemberType = $MemberType }
    }
}

Describe 'Get-DirectRoleFinding (check 5)' {
    It 'reports the build account as a named WARN and nothing else in a fresh lab' {
        $r = @(Get-DirectRoleFinding -ActiveRows @(
                (New-Row 'u-build' 'user' $script:Build),
                (New-Row 'g-bg' 'group' 'Break-Glass-Admins'),
                (New-Row 'g-pim' 'group' 'Privileged-IAM-Admins' -Role 'fe930be7-5e62-47db-91af-98c3a49a38b1')
            ) -PrivilegedRoles $script:Priv -BreakGlassGroupId 'g-bg' -TierGroupIds @('g-pim') -BuildAccountUpn $script:Build)
        @($r | Where-Object Status -eq 'WARN').Count | Should -Be 1
        $w = $r | Where-Object Status -eq 'WARN'
        $w.Check | Should -Be 'Standing Global Administrator'
        $w.Detail | Should -Match ([regex]::Escape($script:Build))
        $w.Detail | Should -Match 'build account'
        $w.Detail | Should -Match 'Convert-BuildAccountToEligible'
        @($r | Where-Object Status -eq 'FAIL').Count | Should -Be 0
    }

    It 'passes the build account once it is eligible, not standing' {
        $r = @(Get-DirectRoleFinding -EligibleRows @((New-Row 'u-build' 'user' $script:Build -Kind 'Eligible')) -PrivilegedRoles $script:Priv -BuildAccountUpn $script:Build)
        @($r | Where-Object Status -ne 'PASS').Count | Should -Be 0
        ($r | Where-Object Check -eq 'Standing privileged roles (humans)').Detail | Should -Be 'none outside break-glass'
        ($r | Where-Object Check -eq 'Eligible Global Administrator').Detail | Should -Match 'build account'
    }

    It 'names every other standing human, foreign role-holding group and privileged workload identity' {
        $r = @(Get-DirectRoleFinding -ActiveRows @(
                (New-Row 'u-sam' 'user' 'sam@contoso.test' -Role $script:HD),
                (New-Row 'g-ops' 'group' 'Ops-Admins' -Role $script:HD),
                (New-Row 'sp-1' 'servicePrincipal' 'legacy-sync-app' -Role $script:AA)
            ) -PrivilegedRoles $script:Priv -BuildAccountUpn $script:Build)
        $warn = @($r | Where-Object Status -eq 'WARN')
        $warn.Count | Should -Be 3
        ($warn | Where-Object Check -eq 'Standing Helpdesk Administrator').Detail | Should -Match 'sam@contoso\.test'
        ($warn | Where-Object Check -eq 'Group holds Helpdesk Administrator').Detail | Should -Match 'Ops-Admins'
        ($warn | Where-Object Check -eq 'Workload identity holds Application Administrator').Detail | Should -Match 'legacy-sync-app'
        @($r | Where-Object Check -eq 'Standing privileged roles (humans)').Count | Should -Be 0
    }

    It 'treats activations as JIT, skips break-glass, derived rows and non-privileged roles' {
        $r = @(Get-DirectRoleFinding -ActiveRows @(
                (New-Row 'u-grace' 'user' 'grace@contoso.test' -Role $script:HD -Kind 'Activated'),
                (New-Row 'bg-1' 'user' 'bg-admin-01@contosolab.onmicrosoft.com'),
                (New-Row 'u-dana' 'user' 'dana@contoso.test' -MemberType 'Group'),
                (New-Row 'u-rr' 'user' 'reader@contoso.test' -Role '4a5d8f65-41da-4de4-8968-e035b65339cf')   # Reports Reader: not in the map
            ) -PrivilegedRoles $script:Priv -BreakGlassUserIds @('bg-1'))
        @($r | Where-Object Status -ne 'PASS').Count | Should -Be 0
        ($r | Where-Object Check -eq 'Open activations (direct)').Detail | Should -Match 'grace@contoso\.test -> Helpdesk Administrator'
    }

    It 'counts a role held by a PIM tier group when the caller adds it to the privileged set' {
        $roles = [ordered]@{} + $script:Priv; $roles['4a5d8f65-41da-4de4-8968-e035b65339cf'] = 'role x (held by PIM-Tier1-Reports)'
        $r = @(Get-DirectRoleFinding -ActiveRows @((New-Row 'u-rr' 'user' 'reader@contoso.test' -Role '4a5d8f65-41da-4de4-8968-e035b65339cf')) -PrivilegedRoles $roles)
        @($r | Where-Object Status -eq 'WARN').Count | Should -Be 1
    }
}

Describe 'Get-TierGroupFinding (check 6)' {
    It 'passes an empty group and reports eligibility and open activations' {
        $r = @(Get-TierGroupFinding -GroupName 'PIM-Tier0-CA-Admins' -Assigned @() -Activated @('u-1') -Eligible @('u-1', 'u-2') -Members @('u-1') -Names @{ 'u-1' = 'amy@contoso.test' })
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'PASS'
        $r[0].Detail | Should -Match 'zero standing members; 2 eligible; 1 activation\(s\) open \(amy@contoso\.test\)'
    }

    It 'names a standing PIM member and a member added outside PIM' {
        $r = @(Get-TierGroupFinding -GroupName 'Privileged-IAM-Admins' -Assigned @('u-perm') -Activated @() -Eligible @() -Members @('u-perm', 'u-sneak') -Names @{ 'u-perm' = 'perm@contoso.test'; 'u-sneak' = 'sneak@contoso.test' })
        @($r | Where-Object Status -eq 'WARN').Count | Should -Be 2
        ($r | Where-Object Check -eq 'Privileged-IAM-Admins standing member').Detail | Should -Match 'perm@contoso\.test'
        ($r | Where-Object Check -eq 'Privileged-IAM-Admins member outside PIM').Detail | Should -Match 'sneak@contoso\.test'
    }

    It 'falls back to "any member is a WARN" when PIM data is unreadable' {
        $r = @(Get-TierGroupFinding -GroupName 'PIM-Tier1-Helpdesk' -Assigned $null -Members @('u-1') -PimReadError 'Forbidden')
        $r[0].Status | Should -Be 'WARN'
        $r[0].Detail | Should -Match 'unreadable: Forbidden'
        (@(Get-TierGroupFinding -GroupName 'PIM-Tier1-Helpdesk' -Assigned $null -Members @() -PimReadError 'Forbidden'))[0].Status | Should -Be 'PASS'
    }
}

Describe 'Get-PasskeyCoverageFinding (check 7)' {
    BeforeAll {
        $script:Cfg = @{ state = 'enabled'; includeTargets = @(@{ id = 'g-admin-accounts'; allowedPasskeyProfiles = @('p') })
            passkeyProfiles = @(@{ id = 'p'; keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') } }) }
    }
    It '<Case> -> <Status>' -ForEach @(
        @{ Case = 'not in any target (only a PIM group)'; Groups = @('g-pim-tier0'); Keys = @('cb69481e-8ff7-4039-93ec-0a2729a154a8'); Status = 'FAIL'; Match = 'no passkey include target' }
        @{ Case = 'covered, no key yet'; Groups = @('g-admin-accounts'); Keys = @(); Status = 'WARN'; Match = 'no passkey registered yet' }
        @{ Case = 'covered, only a blocked model'; Groups = @('g-admin-accounts'); Keys = @('99999999-9999-9999-9999-999999999999'); Status = 'FAIL'; Match = 'blocks' }
        @{ Case = 'covered, one usable and one blocked'; Groups = @('g-admin-accounts'); Keys = @('cb69481e-8ff7-4039-93ec-0a2729a154a8', '99999999-9999-9999-9999-999999999999'); Status = 'WARN'; Match = '1 usable' }
        @{ Case = 'covered, usable key'; Groups = @('g-admin-accounts'); Keys = @('cb69481e-8ff7-4039-93ec-0a2729a154a8'); Status = 'PASS'; Match = 'covered by g-admin-accounts' }
    ) {
        $k = @($Keys | ForEach-Object { @{ aaGuid = $_ } })
        $f = Get-PasskeyCoverageFinding -Label 'adm-x' -Coverage (Test-PasskeyCoverage -Fido2Config $script:Cfg -GroupIds $Groups -Keys $k) -KeyCount $k.Count
        $f.Status | Should -Be $Status
        $f.Detail | Should -Match $Match
    }
}

Describe '01-Verify-Baseline.ps1 end to end (mocked Graph)' {
    BeforeAll {
        function Set-VbMocks {
            param([switch]$Converted, [switch]$RoleReadFails, [switch]$TierGroupLeak, [switch]$TierLookupFails,
                # Passkeys: all_users still targeted (fresh tenant) or only the
                # standing admin groups; who is in Admin-Accounts; keys per user.
                [switch]$AdminTargetsOnly, [string[]]$AdminAccounts = @('u-build'), [hashtable]$Keys = @{ 'u-build' = 1; 'u-ava' = 1 },
                [switch]$Tier0Eligible, [string[]]$AzureMembers = @())
            $global:VbTest = @{ Converted = [bool]$Converted; RoleReadFails = [bool]$RoleReadFails; TierGroupLeak = [bool]$TierGroupLeak; TierLookupFails = [bool]$TierLookupFails
                AdminTargetsOnly = [bool]$AdminTargetsOnly; AdminAccounts = $AdminAccounts; Keys = $Keys; Tier0Eligible = [bool]$Tier0Eligible; AzureMembers = $AzureMembers
                Lines = [System.Collections.Generic.List[string]]::new() }
            Mock Write-Host { $global:VbTest.Lines.Add([string]$Object) }
            Mock Get-MgContext { New-MgContextStub -Scopes @('Group.Read.All', 'User.Read.All', 'RoleManagement.Read.Directory', 'Policy.Read.All', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'PrivilegedEligibilitySchedule.Read.AzureADGroup') }
            Mock Connect-MgGraph { throw 'tests must never connect' }
            Mock Get-MgGroup {
                if ($Filter -match "startswith\(mailNickname,'pim-tier'\)") {
                    if ($global:VbTest.TierLookupFails) { throw 'Request_UnsupportedQuery' }
                    return @([pscustomobject]@{ Id = 'g-pim-tier0-ca-admins'; DisplayName = 'PIM-Tier0-CA-Admins' })
                }
                $nick = $Filter -replace "^mailNickname eq '(.+)'$", '$1'
                $kind = switch -Regex ($nick) { '^(all-nurses|all-icu)$' { 'dynamic' } '^(break-glass-admins|privileged-iam-admins|admin-accounts)$' { 'role' } default { 'assigned' } }
                [pscustomobject]@{ Id = "g-$nick"; DisplayName = $nick; GroupTypes = @(if ($kind -eq 'dynamic') { 'DynamicMembership' }); IsAssignableToRole = ($kind -eq 'role') }
            }
            Mock Get-MgGroupMember {
                switch ($GroupId) {
                    'g-break-glass-admins' { @([pscustomobject]@{ Id = 'bg-1' }, [pscustomobject]@{ Id = 'bg-2' }) }
                    'g-privileged-iam-admins' { @(if ($global:VbTest.TierGroupLeak) { [pscustomobject]@{ Id = 'u-sneak' } }) }
                    'g-pim-azure-rg-contributors' { @($global:VbTest.AzureMembers | ForEach-Object { [pscustomobject]@{ Id = $_ } }) }
                    default { @() }
                }
            }
            Mock Get-MgUser {
                if ($Filter) {
                    return @([pscustomobject]@{ Id = 'bg-1'; UserPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; AccountEnabled = $true },
                        [pscustomobject]@{ Id = 'bg-2'; UserPrincipalName = 'bg-admin-02@contosolab.onmicrosoft.com'; AccountEnabled = $true })
                }
                if ($UserId -eq 'admin@contosolab.onmicrosoft.com') { return [pscustomobject]@{ Id = 'u-build'; UserPrincipalName = $UserId } }
                [pscustomobject]@{ UserPrincipalName = @{ 'u-sneak' = 'sneak@contoso.test'; 'u-grace' = 'grace@contoso.test'; 'u-ava' = 'adm-ava.lin@contosolab.onmicrosoft.com' }[$UserId] }
            }
            Mock Get-MgRoleManagementDirectoryRoleAssignment { @([pscustomobject]@{ PrincipalId = 'g-break-glass-admins'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10' }) }
            Mock Get-MgIdentityConditionalAccessPolicy {
                @([pscustomobject]@{ DisplayName = 'CA001 - Require MFA for all users'; State = 'enabledForReportingButNotEnforced'; Conditions = [pscustomobject]@{ Users = [pscustomobject]@{ ExcludeGroups = @('g-break-glass-admins') } } })
            }
            Mock Invoke-MgGraphRequest {
                $t = $global:VbTest
                $user = @{ '@odata.type' = '#microsoft.graph.user'; userPrincipalName = 'admin@contosolab.onmicrosoft.com' }
                switch -Regex ($Uri) {
                    '/roleAssignmentScheduleInstances' {
                        if ($t.RoleReadFails) { throw 'Forbidden' }
                        return @{ value = @(
                                @{ principalId = 'g-break-glass-admins'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'Break-Glass-Admins' } },
                                @{ principalId = 'g-privileged-iam-admins'; roleDefinitionId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'Privileged-IAM-Admins' } },
                                @{ principalId = 'g-pim-tier0-ca-admins'; roleDefinitionId = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'PIM-Tier0-CA-Admins' } }
                            ) + @(if (-not $t.Converted) { @{ principalId = 'u-build'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = $user } }) }
                    }
                    '/roleEligibilityScheduleInstances' {
                        return @{ value = @(if ($t.Converted) { @{ principalId = 'u-build'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; memberType = 'Direct'; principal = $user } }) }
                    }
                    'privilegedAccess/group/assignmentScheduleInstances' { return @{ value = @() } }
                    'privilegedAccess/group/eligibilityScheduleInstances' {
                        if ($Uri -match 'g-privileged-iam-admins') { return @{ value = @(@{ accessId = 'member'; principalId = 'u-grace' }) } }
                        if ($Uri -match 'g-pim-tier0-ca-admins' -and $t.Tier0Eligible) { return @{ value = @(@{ accessId = 'member'; principalId = 'u-ava' }) } }
                        return @{ value = @() }
                    }
                    '/authenticationMethodConfigurations/fido2' {
                        $targets = @(@{ id = 'g-break-glass-admins'; allowedPasskeyProfiles = @('p-admin') }, @{ id = 'g-admin-accounts'; allowedPasskeyProfiles = @('p-admin') })
                        if (-not $t.AdminTargetsOnly) { $targets += @{ id = 'all_users'; allowedPasskeyProfiles = @('p-default') } }
                        return @{ state = 'enabled'; includeTargets = $targets; excludeTargets = @()
                            passkeyProfiles = @(@{ id = 'p-default'; keyRestrictions = @{ isEnforced = $false } }, @{ id = 'p-admin'; keyRestrictions = @{ isEnforced = $true; enforcementType = 'allow'; aaGuids = @('cb69481e-8ff7-4039-93ec-0a2729a154a8') } }) }
                    }
                    '/users/([^/]+)/authentication/fido2Methods' {
                        $n = [int]$t.Keys[$Matches[1]]
                        return @{ value = @(if ($n) { 1..$n | ForEach-Object { @{ id = "k$_"; aaGuid = 'cb69481e-8ff7-4039-93ec-0a2729a154a8' } } }) }
                    }
                    '/users/([^/]+)/transitiveMemberOf' { return @{ value = @(if ($Matches[1] -in $t.AdminAccounts) { @{ id = 'g-admin-accounts' } }) } }
                    default { throw "unexpected Graph call in test: $Uri" }
                }
            }
        }
        function Invoke-Vb {
            $global:LASTEXITCODE = 0
            & $script:Vb -OnMicrosoftDomain 'contosolab.onmicrosoft.com' -WarningAction SilentlyContinue
            return [pscustomobject]@{ Exit = $LASTEXITCODE; Lines = @($global:VbTest.Lines) }
        }
        function Get-Section([string[]]$Lines, [string]$Header) {
            $on = $false
            foreach ($l in $Lines) {
                if ($l -match '^\s*\[\d/7\]' -or $l -match '^\s*`n\[\d/7\]' -or $l -match '\[\d/7\] ') { $on = $l -match [regex]::Escape($Header) ; continue }
                if ($l -match '^\s*Baseline verification') { $on = $false }
                if ($on -and $l -match '^\s+\[(PASS|WARN|FAIL)\]') { $l }
            }
        }
    }
    AfterAll { Remove-Variable -Name VbTest -Scope Global -ErrorAction SilentlyContinue }

    It 'fresh lab: [5/7] has exactly one WARN, the build account by name; [6/7] passes; exit 0' {
        Set-VbMocks
        $r = Invoke-Vb
        $r.Exit | Should -Be 0
        $s5 = @(Get-Section $r.Lines '[5/7]')
        @($s5 | Where-Object { $_ -match '\[WARN\]' }).Count | Should -Be 1
        ($s5 | Where-Object { $_ -match '\[WARN\]' }) | Should -Match 'Standing Global Administrator - admin@contosolab\.onmicrosoft\.com \(build account\)'
        $s6 = @(Get-Section $r.Lines '[6/7]')
        $s6.Count | Should -Be 2                                     # Privileged-IAM-Admins + PIM-Tier0-CA-Admins
        @($s6 | Where-Object { $_ -notmatch '\[PASS\]' }).Count | Should -Be 0
        ($s6 | Where-Object { $_ -match 'Privileged-IAM-Admins' }) | Should -Match '1 eligible'
    }

    It 'after Convert-BuildAccountToEligible: no WARN at all, the build account shows as eligible' {
        Set-VbMocks -Converted
        $r = Invoke-Vb
        $r.Exit | Should -Be 0
        @($r.Lines | Where-Object { $_ -match '\[WARN\]' }).Count | Should -Be 0
        @(Get-Section $r.Lines '[5/7]') -join "`n" | Should -Match 'Eligible Global Administrator - admin@contosolab\.onmicrosoft\.com \(build account\)'
    }

    It 'a member added to a tier group outside PIM is a WARN by name' {
        Set-VbMocks -TierGroupLeak
        $r = Invoke-Vb
        @(Get-Section $r.Lines '[6/7]') -join "`n" | Should -Match '\[WARN\] Privileged-IAM-Admins member outside PIM - sneak@contoso\.test'
    }

    It 'a failed tier-group lookup FAILs (never "no tier groups") but still checks Privileged-IAM-Admins' {
        Set-VbMocks -TierLookupFails
        $r = Invoke-Vb
        $r.Exit | Should -Be 1
        $s6 = @(Get-Section $r.Lines '[6/7]') -join "`n"
        $s6 | Should -Match '\[FAIL\] PIM tier groups \(pim-tier\*\) - lookup failed: Request_UnsupportedQuery'
        $s6 | Should -Match '\[PASS\] privileged-iam-admins members'
    }

    It '[7/7] passes a fresh tenant (all_users still targeted, build account has a key)' {
        Set-VbMocks
        $r = Invoke-Vb
        @(Get-Section $r.Lines '[7/7]') -join "`n" | Should -Match '\[PASS\] Passkey target admin@contosolab\.onmicrosoft\.com \(build account\) - covered by'
    }

    It '[7/7] FAILs a build account / Tier-0 eligible outside every standing passkey target once all_users is gone' {
        Set-VbMocks -AdminTargetsOnly -AdminAccounts @() -Tier0Eligible
        $r = Invoke-Vb
        $r.Exit | Should -Be 1
        $s7 = @(Get-Section $r.Lines '[7/7]') -join "`n"
        $s7 | Should -Match '\[FAIL\] Passkey target admin@contosolab\.onmicrosoft\.com \(build account\) - no passkey include target'
        $s7 | Should -Match '\[FAIL\] Passkey target adm-ava\.lin@contosolab\.onmicrosoft\.com - no passkey include target'
    }

    It '[7/7] FAILs a STANDING member of PIM-Azure-RG-Contributors outside every passkey target (CA002 covers it at every sign-in)' {
        Set-VbMocks -AdminTargetsOnly -AdminAccounts @('u-build') -AzureMembers @('u-ava')
        $r = Invoke-Vb
        $r.Exit | Should -Be 1
        @(Get-Section $r.Lines '[7/7]') -join "`n" | Should -Match '\[FAIL\] Passkey target adm-ava\.lin@contosolab\.onmicrosoft\.com \(PIM-Azure-RG-Contributors\) - no passkey include target'
    }

    It '[7/7] passes both once they are in Admin-Accounts with an issued key model' {
        Set-VbMocks -AdminTargetsOnly -AdminAccounts @('u-build', 'u-ava') -Tier0Eligible
        $r = Invoke-Vb
        $s7 = @(Get-Section $r.Lines '[7/7]')
        $s7.Count | Should -Be 2
        @($s7 | Where-Object { $_ -notmatch '\[PASS\]' }).Count | Should -Be 0
    }

    It 'an unreadable role source FAILs (never "nobody holds a role") and exits 1' {
        Set-VbMocks -RoleReadFails
        $r = Invoke-Vb
        $r.Exit | Should -Be 1
        @(Get-Section $r.Lines '[5/7]') -join "`n" | Should -Match '\[FAIL\] Privileged directory roles - could not read'
    }
}
