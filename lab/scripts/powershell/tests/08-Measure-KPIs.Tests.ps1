# Pester 5 tests for 08-Measure-KPIs.ps1.
#   * KPI maths: the pure functions, loaded from the script's syntax tree.
#   * Contract with 06-NHI-Inventory.ps1: real -Offline output, fed through
#     ConvertFrom-NhiInventory.
#   * One end-to-end run against a tiny tenant served by a mocked
#     Invoke-MgGraphRequest: the snapshot file is complete, hashed, and holds
#     no identifier (the kpis folder is public).
# No tenant, Vault or Guacamole is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Kpi = Get-LabScriptPath '08-Measure-KPIs.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Kpi)
    $script:Now = [datetime]::new(2026, 10, 20, 12, 0, 0, [DateTimeKind]::Utc)
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    $script:UA = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
    function New-Assignment([string]$Id, [string]$Type, [string]$Kind = 'Assigned', [string]$Role = $script:GA) {
        [pscustomobject]@{ PrincipalId = $Id; PrincipalType = $Type; AssignmentType = $Kind; RoleDefinitionId = $Role }
    }
    function New-CaPolicy {
        param([string]$Name, [string]$State = 'enabled', [string[]]$IncludeUsers = @('All'), [string[]]$ExcludeGroups = @(),
            [string[]]$IncludeRoles = @(), [string[]]$BuiltIn = @('mfa'), [string]$Operator = 'OR', [string]$StrengthId = '',
            [string[]]$Apps = @('All'), [string[]]$Clients = @('all'), [hashtable]$Locations = $null)
        @{
            displayName   = $Name; state = $State
            grantControls = @{ operator = $Operator; builtInControls = $BuiltIn; authenticationStrength = $(if ($StrengthId) { @{ id = $StrengthId } } else { $null }) }
            conditions    = @{
                clientAppTypes = $Clients; locations = $Locations; platforms = $null; devices = $null; signInRiskLevels = @(); userRiskLevels = @()
                applications   = @{ includeApplications = $Apps; excludeApplications = @() }
                users          = @{ includeUsers = $IncludeUsers; excludeUsers = @(); includeGroups = @(); excludeGroups = $ExcludeGroups; includeRoles = $IncludeRoles; excludeRoles = @() }
            }
        }
    }
}

Describe 'Measure-AdminPosture (standing vs eligible)' {
    It 'separates standing, eligible-only, activated, break-glass and workload identities' {
        $active = @(
            (New-Assignment 'u-operator' 'user'),                     # tenant-creator GA left standing
            (New-Assignment 'g-bg' 'group'),                          # Break-Glass-Admins -> GA
            (New-Assignment 'g-pim' 'group' -Role $script:UA),        # Privileged-IAM-Admins -> User Admin (active binding)
            (New-Assignment 'sp-apply' 'servicePrincipal')            # pipeline APPLY identity
        )
        $membership = @{
            'g-bg'  = @{ Permanent = @('bg-1', 'bg-2'); Activated = @(); Eligible = @() }
            'g-pim' = @{ Permanent = @(); Activated = @('u-grace'); Eligible = @('u-grace', 'u-ade') }
        }
        $r = Measure-AdminPosture -ActiveAssignments $active -GroupMembership $membership -BreakGlassUserIds @('bg-1', 'bg-2') -BreakGlassGroupId 'g-bg'
        $r.StandingUsers | Should -Be 1                   # u-operator only
        $r.EligibleOnlyUsers | Should -Be 2               # u-grace (activated now) + u-ade
        $r.ActivatedNow | Should -Be 1
        $r.BreakGlassUsers | Should -Be 2
        $r.PrivilegedServicePrincipals | Should -Be 1
        $r.PctJustInTime | Should -Be 66.7
    }

    It 'keeps one-element member lists as lists (no id concatenation)' {
        $membership = @{ 'g-bg' = @{ Permanent = @('bg-1'); Activated = @('bg-2'); Eligible = @() } }
        $r = Measure-AdminPosture -ActiveAssignments @((New-Assignment 'g-bg' 'group')) -GroupMembership $membership -BreakGlassGroupId 'g-bg'
        $r.BreakGlassUsers | Should -Be 2
    }

    It 'counts someone both standing and eligible as standing' {
        $r = Measure-AdminPosture -ActiveAssignments @((New-Assignment 'u-1' 'user')) -EligibleAssignments @((New-Assignment 'u-1' 'user' 'Eligible'), (New-Assignment 'u-2' 'user' 'Eligible'))
        $r.StandingUsers | Should -Be 1
        $r.EligibleOnlyUsers | Should -Be 1
    }

    It 'treats every member of an ELIGIBLE group as eligible' {
        $membership = @{ 'g-elig' = @{ Permanent = @('u-a'); Activated = @(); Eligible = @('u-b') } }
        $r = Measure-AdminPosture -EligibleAssignments @((New-Assignment 'g-elig' 'group' 'Eligible')) -GroupMembership $membership
        $r.StandingUsers | Should -Be 0
        $r.EligibleOnlyUsers | Should -Be 2
        $r.PctJustInTime | Should -Be 100
    }

    It 'returns a null percentage, not 0, when there are no admins at all' {
        (Measure-AdminPosture).PctJustInTime | Should -BeNullOrEmpty
    }

    It 'splits standing and eligible-only by tier (a person can sit in two tiers)' {
        $tier = @{}; $map = Get-RoleTierMap; foreach ($k in $map.Keys) { $tier[$k] = $map[$k]['Tier'] }
        $SEC = '194ae4cb-b126-40b2-bd5b-6091b380977d'; $HD = '729827e3-9c14-49f7-bb1b-9608f156bbb8'; $OTHER = '4a5d8f65-41da-4de4-8968-e035b65339cf'
        $active = @(
            (New-Assignment 'u-build' 'user'),                               # build account: direct standing GA
            (New-Assignment 'g-t0' 'group' -Role $SEC),                      # PIM-Tier0-Security-Admins
            (New-Assignment 'g-t1' 'group' -Role $HD),                       # PIM-Tier1-Helpdesk
            (New-Assignment 'u-x' 'user' -Role $OTHER)                       # privileged, outside the tier map
        )
        $membership = @{
            'g-t0' = @{ Permanent = @(); Activated = @('u-amy'); Eligible = @('u-amy', 'u-ben') }
            'g-t1' = @{ Permanent = @('u-ben'); Activated = @(); Eligible = @('u-cal') }
        }
        $r = Measure-AdminPosture -ActiveAssignments $active -GroupMembership $membership -RoleTier $tier
        $r.StandingUsers | Should -Be 3                                     # u-build, u-ben (Tier 1 permanent member), u-x
        $r.EligibleOnlyUsers | Should -Be 2                                 # u-amy, u-cal (u-ben is standing overall)
        $r.StandingUsersByTier['global_admin'] | Should -Be 1
        $r.StandingUsersByTier['tier0'] | Should -Be 0
        $r.StandingUsersByTier['tier1'] | Should -Be 1
        $r.StandingUsersByTier['other'] | Should -Be 1
        $r.EligibleOnlyUsersByTier['tier0'] | Should -Be 2                 # u-amy and u-ben: Ben is standing only in Tier 1
        $r.EligibleOnlyUsersByTier['tier1'] | Should -Be 1                 # u-cal
        @($r.StandingUsersByTier.Keys) | Should -Be @('global_admin', 'tier0', 'tier1', 'other')
    }

    It 'returns the service principal ids it counted' {
        $r = Measure-AdminPosture -ActiveAssignments @((New-Assignment 'sp-a' 'servicePrincipal')) -EligibleAssignments @((New-Assignment 'sp-b' 'servicePrincipal' 'Eligible'))
        @($r.PrivilegedServicePrincipalIds) | Sort-Object | Should -Be @('sp-a', 'sp-b')
    }

    It 'keeps break-glass out of every tier' {
        $tier = @{ $script:GA = 'global_admin' }
        $r = Measure-AdminPosture -ActiveAssignments @((New-Assignment 'bg-1' 'user')) -BreakGlassUserIds @('bg-1') -RoleTier $tier
        $r.StandingUsers | Should -Be 0
        $r.StandingUsersByTier['global_admin'] | Should -Be 0
        $r.BreakGlassUsers | Should -Be 1
    }
}

Describe 'Privileged workload identities (directory role OR high-privilege Graph permission)' {
    BeforeAll {
        $script:HP = Get-HighPrivilegeGraphAppRole
        $script:RMRW = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'   # RoleManagement.ReadWrite.Directory
        $script:GRW = '62a82d76-70ea-41e2-9197-370581804d09'    # Group.ReadWrite.All
        $script:URA = 'df021288-bdef-4463-88db-98f22de89214'    # User.Read.All (not high privilege)
    }

    It 'lists every permission the design names, with unique Graph app-role ids' {
        foreach ($n in 'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All', 'Directory.ReadWrite.All',
            'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod', 'UserAuthenticationMethod.ReadWrite.All', 'Group.ReadWrite.All',
            'PrivilegedAccess.ReadWrite.AzureADGroup', 'RoleManagementPolicy.ReadWrite.Directory') {
            @($script:HP.Values) | Should -Contain $n
        }
        foreach ($id in $script:HP.Keys) { $id | Should -Match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$' }
        @($script:HP.Values | Sort-Object -Unique).Count | Should -Be $script:HP.Count
    }

    It 'covers the APPLY identity''s default Graph roles that can escalate (modules/pipeline-identity)' {
        $vars = Get-Content -LiteralPath (Join-Path $script:LabPowerShellRoot '..' '..' 'terraform' 'modules' 'pipeline-identity' 'variables.tf') -Raw
        $block = [regex]::Match($vars, '(?s)variable "apply_graph_roles".*?default\s*=\s*\[(.*?)\]').Groups[1].Value
        $block | Should -Not -BeNullOrEmpty
        $apply = @([regex]::Matches($block, '"([A-Za-z.]+)"') | ForEach-Object { $_.Groups[1].Value })
        # The APPLY identity must be counted: at least its Tier-0 role is watched.
        @($apply | Where-Object { $_ -in @($script:HP.Values) }) | Should -Contain 'RoleManagement.ReadWrite.Directory'
    }

    It 'counts the union once and splits the routes' {
        $grants = @(
            @{ principalId = 'sp-apply'; principalType = 'ServicePrincipal'; appRoleId = $script:RMRW },
            @{ principalId = 'sp-apply'; principalType = 'ServicePrincipal'; appRoleId = $script:GRW },
            @{ principalId = 'sp-both'; principalType = 'ServicePrincipal'; appRoleId = $script:GRW },
            @{ principalId = 'sp-reader'; principalType = 'ServicePrincipal'; appRoleId = $script:URA },   # not high privilege
            @{ principalId = 'u-odd'; principalType = 'User'; appRoleId = $script:RMRW }                  # not a workload identity
        )
        $r = Measure-PrivilegedWorkloadIdentity -DirectoryRoleSpIds @('sp-role', 'sp-both') -GraphAppRoleAssignments $grants -HighPrivilegeAppRoles $script:HP
        $r.Total | Should -Be 3                         # sp-apply, sp-both, sp-role
        $r.ViaDirectoryRole | Should -Be 2
        $r.ViaGraphAppRole | Should -Be 2               # sp-apply, sp-both
        $r.Both | Should -Be 1
        $r.ByPermission['Group.ReadWrite.All'] | Should -Be 2
        $r.ByPermission['RoleManagement.ReadWrite.Directory'] | Should -Be 1
        @($r.ByPermission.Keys) | Should -Not -Contain 'User.Read.All'
    }

    It 'matches app-role ids case-insensitively and returns 0, not null, when nothing is privileged' {
        $r = Measure-PrivilegedWorkloadIdentity -GraphAppRoleAssignments @(@{ principalId = 'sp-a'; principalType = 'ServicePrincipal'; appRoleId = $script:RMRW.ToUpperInvariant() }) -HighPrivilegeAppRoles $script:HP
        $r.Total | Should -Be 1
        (Measure-PrivilegedWorkloadIdentity -HighPrivilegeAppRoles $script:HP).Total | Should -Be 0
    }
}

Describe 'Role tier map (one map, three places)' {
    BeforeAll { $script:Map = Get-RoleTierMap }

    It 'keeps Global Administrator in its own bucket and every id a template GUID' {
        $script:Map[$script:GA]['Tier'] | Should -Be 'global_admin'
        foreach ($k in $script:Map.Keys) {
            $k | Should -Match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
            $script:Map[$k]['Tier'] | Should -BeIn @('global_admin', 'tier0', 'tier1')
        }
    }

    It 'places every role of every modules/pim pim_tier_groups default in the same tier, under the pim-tier prefix' {
        $vars = Get-Content -LiteralPath (Join-Path $script:LabPowerShellRoot '..' '..' 'terraform' 'modules' 'pim' 'variables.tf') -Raw
        $block = [regex]::Match($vars, '(?s)variable "pim_tier_groups"\s*\{.*?\n\}').Value
        $default = [regex]::Match($block, '(?s)\n  default = \{(.*?)\n  \}').Groups[1].Value
        $default | Should -Not -BeNullOrEmpty
        # One entry per tier group: `    key = { ... }` at four spaces.
        $groups = @([regex]::Matches($default, '(?s)\n    ([a-z0-9_]+)\s*=\s*\{(.*?)\n    \}'))
        $groups.Count | Should -BeGreaterThan 0
        foreach ($g in $groups) {
            $key = $g.Groups[1].Value; $body = $g.Groups[2].Value
            $tier = 'tier' + [regex]::Match($body, '\n\s*tier\s*=\s*(\d)').Groups[1].Value
            [regex]::Match($body, 'mail_nickname\s*=\s*"([^"]+)"').Groups[1].Value | Should -BeLike 'pim-tier*' -Because "01/08 discover tier groups by the pim-tier prefix ($key)"
            $ids = @([regex]::Matches($body, '\brole_template_id\s*=\s*"([0-9a-f-]{36})"') | ForEach-Object { $_.Groups[1].Value })
            $extra = [regex]::Match($body, '(?s)additional_role_template_ids\s*=\s*\[(.*?)\]').Groups[1].Value
            $ids += @([regex]::Matches($extra, '"([0-9a-f-]{36})"') | ForEach-Object { $_.Groups[1].Value })
            $ids.Count | Should -BeGreaterThan 0 -Because "$key binds at least one role"
            foreach ($id in $ids) {
                $script:Map.Contains($id) | Should -BeTrue -Because "modules/pim $key binds $id; the KPI and baseline scripts must know it"
                $script:Map[$id]['Tier'] | Should -Be $tier -Because "modules/pim puts $id ($key) in $tier"
            }
        }
    }

    It 'is identical in 01-Verify-Baseline.ps1' {
        $sb = Get-ScriptFunctionBlock -Path (Get-LabScriptPath '01-Verify-Baseline.ps1') -Name 'Get-RoleTierMap'
        . ([scriptblock]::Create(($sb.ToString() -replace 'function Get-RoleTierMap', 'function Get-RoleTierMap01')))
        $other = Get-RoleTierMap01
        @($other.Keys) | Should -Be @($script:Map.Keys)
        foreach ($k in $script:Map.Keys) {
            $other[$k]['Tier'] | Should -Be $script:Map[$k]['Tier']
            $other[$k]['Name'] | Should -Be $script:Map[$k]['Name']
        }
    }
}

Describe 'Test-UniversalMfaPolicy / Measure-CaCoverage' {
    It 'counts MFA and authentication-strength policies for all apps only' {
        Test-UniversalMfaPolicy (New-CaPolicy 'CA001') | Should -BeTrue
        Test-UniversalMfaPolicy (New-CaPolicy 'CA008' -BuiltIn @() -StrengthId 'strength-pr') | Should -BeTrue
        Test-UniversalMfaPolicy (New-CaPolicy 'block' -BuiltIn @('block')) | Should -BeFalse
        Test-UniversalMfaPolicy (New-CaPolicy 'mfa-or-device' -BuiltIn @('mfa', 'compliantDevice')) | Should -BeFalse   # a device alone satisfies it
        Test-UniversalMfaPolicy (New-CaPolicy 'mfa-and-device' -BuiltIn @('mfa', 'compliantDevice') -Operator 'AND') | Should -BeTrue
        Test-UniversalMfaPolicy (New-CaPolicy 'one-app' -Apps @('app-1')) | Should -BeFalse
        Test-UniversalMfaPolicy (New-CaPolicy 'eas-only' -Clients @('exchangeActiveSync')) | Should -BeFalse
        Test-UniversalMfaPolicy (New-CaPolicy 'located' -Locations @{ includeLocations = @('All') }) | Should -BeFalse
    }

    It 'separates enforced coverage from report-only coverage and excludes break-glass from both sides' {
        $users = @('u-1', 'u-2', 'u-3', 'u-4', 'bg-1')
        $groups = @{ 'g-bg' = @('bg-1'); 'g-contractors' = @('u-4') }
        $policies = @(
            (New-CaPolicy 'CA001 - Require MFA for all users' -State 'enabledForReportingButNotEnforced' -ExcludeGroups @('g-bg')),
            (New-CaPolicy 'CA002 - admins' -BuiltIn @() -StrengthId 'pr' -IncludeUsers @() -IncludeRoles @($script:GA) -ExcludeGroups @('g-bg')),
            (New-CaPolicy 'CA004 - block countries' -BuiltIn @('block'))
        )
        $roles = @{ $script:GA = @('u-1', 'bg-1') }
        $r = Measure-CaCoverage -Policies $policies -EnabledMemberIds $users -GroupMembers $groups -RoleMembers $roles -BreakGlassIds @('bg-1')
        $r.Denominator | Should -Be 4
        $r.CoveredEnforced | Should -Be 1          # only u-1, through the enforced admin policy
        $r.PctEnforced | Should -Be 25
        $r.CoveredInclReportOnly | Should -Be 4
        $r.PctInclReportOnly | Should -Be 100
        @($r.PoliciesCounted).Count | Should -Be 2
    }

    It 'honours group exclusions' {
        $r = Measure-CaCoverage -Policies @((New-CaPolicy 'CA001' -ExcludeGroups @('g-contractors'))) -EnabledMemberIds @('u-1', 'u-2') -GroupMembers @{ 'g-contractors' = @('u-2') }
        $r.CoveredEnforced | Should -Be 1
        @($r.UncoveredIds) | Should -Be @('u-2')
    }
}

Describe 'Measure-AccessReview' {
    It 'computes completion, revocation and applied revocation from person-made decisions' {
        $p = @{ id = 'u-rev'; displayName = 'Mei Tanaka' }
        $d = @(
            @{ decision = 'Approve'; applyResult = 'New'; reviewedBy = $p }, @{ decision = 'Deny'; applyResult = 'AppliedSuccessfully'; reviewedBy = $p },
            @{ decision = 'Deny'; applyResult = 'New'; reviewedBy = $p }, @{ decision = 'NotReviewed'; applyResult = 'New' }
        )
        $r = Measure-AccessReview -Decisions $d
        $r.PctCompletion | Should -Be 75
        $r.PctRevocation | Should -Be 66.7
        $r.PctRevocationApplied | Should -Be 50
    }
    It 'never counts a default the SERVICE applied as a review (deny-by-default + autoApply would read ~100%)' {
        $p = @{ id = 'u-rev'; displayName = 'Mei Tanaka' }
        $d = @(
            @{ decision = 'Approve'; reviewedBy = $p },
            @{ decision = 'Deny'; applyResult = 'AppliedSuccessfully'; reviewedBy = @{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'AAD Access Reviews' } },
            @{ decision = 'Deny'; applyResult = 'AppliedSuccessfully'; reviewedBy = @{ id = 'svc-1'; displayName = 'Microsoft Entra Access Reviews' } },
            @{ decision = 'Deny'; applyResult = 'AppliedSuccessfully' }   # no reviewer at all
        )
        $r = Measure-AccessReview -Decisions $d
        $r.Reviewed | Should -Be 1
        $r.PctCompletion | Should -Be 25
        $r.ServiceDecided | Should -Be 3
        $r.ServiceDenied | Should -Be 3
        $r.PctRevocation | Should -Be 0
    }
    It 'agrees with 10-Review-KPIs.ps1 on what a person-made decision is (parity)' {
        $mine = (Get-ScriptFunctionBlock -Path $script:Kpi -Name 'Test-IsHumanDecision').ToString()
        $theirs = (Get-ScriptFunctionBlock -Path (Get-LabScriptPath '10-Review-KPIs.ps1') -Name 'Test-IsHumanDecision').ToString()
        $mine | Should -Be $theirs
        $k08 = (Get-Content -LiteralPath $script:Kpi -Raw) -match "SystemReviewerNames = @\('AAD Access Reviews', 'Microsoft Entra Access Reviews'\)"
        $k10 = (Get-Content -LiteralPath (Get-LabScriptPath '10-Review-KPIs.ps1') -Raw) -match "SystemReviewerNames = @\('AAD Access Reviews', 'Microsoft Entra Access Reviews'\)"
        $k08 | Should -BeTrue
        $k10 | Should -BeTrue
    }
    It 'returns nulls, not zeros, when there is nothing to measure' {
        $r = Measure-AccessReview -Decisions @()
        $r.PctCompletion | Should -BeNullOrEmpty
        $r.PctRevocation | Should -BeNullOrEmpty
    }
}

Describe 'Measure-StaleAccount' {
    It 'uses the newest sign-in signal and separates never-signed-in, pending and guests' {
        $old = $script:Now.AddDays(-100).ToString('o'); $recent = $script:Now.AddDays(-5).ToString('o')
        $users = @(
            @{ id = 'stale'; accountEnabled = $true; userType = 'Member'; createdDateTime = $old; signInActivity = @{ lastSignInDateTime = $old } },
            @{ id = 'fresh-noninteractive'; accountEnabled = $true; userType = 'Member'; createdDateTime = $old; signInActivity = @{ lastSignInDateTime = $old; lastNonInteractiveSignInDateTime = $recent } },
            @{ id = 'never-old'; accountEnabled = $true; userType = 'Member'; createdDateTime = $script:Now.AddDays(-200).ToString('o'); signInActivity = $null },
            @{ id = 'new-hire'; accountEnabled = $true; userType = 'Member'; createdDateTime = $recent; signInActivity = $null },
            @{ id = 'disabled'; accountEnabled = $false; userType = 'Member'; createdDateTime = $old; signInActivity = @{ lastSignInDateTime = $old } },
            @{ id = 'bg-1'; accountEnabled = $true; userType = 'Member'; createdDateTime = $old; signInActivity = $null },
            @{ id = 'guest'; accountEnabled = $true; userType = 'Guest'; createdDateTime = $old; signInActivity = @{ lastSignInDateTime = $old } }
        )
        $r = Measure-StaleAccount -Users $users -StaleDays 90 -Now $script:Now -BreakGlassIds @('bg-1')
        $r.EnabledMembers | Should -Be 4
        $r.Stale | Should -Be 2
        @($r.StaleIds) | Sort-Object | Should -Be @('never-old', 'stale')
        $r.NeverSignedIn | Should -Be 1
        $r.PendingFirstSignIn | Should -Be 1
        $r.StaleGuests | Should -Be 1
        $r.PctStale | Should -Be 50
    }
}

Describe 'Measure-HrToDisable / Test-IsDisableAudit' {
    BeforeAll {
        $script:T0 = $script:Now.AddHours(-2)
        function New-ProvEvent([string]$EmployeeId, [string]$Name, [datetime]$At, [string]$Action = 'disable', [string]$Status = 'success') {
            @{ activityDateTime = $At.ToString('o'); provisioningAction = $Action; provisioningStatusInfo = @{ status = $Status }; sourceIdentity = @{ id = $EmployeeId; displayName = $Name } }
        }
        function New-DisableAudit([string]$UserId, [datetime]$At, [string]$Activity = 'Update user', [string]$NewValue = '[false]') {
            @{ activityDisplayName = $Activity; activityDateTime = $At.ToString('o'); targetResources = @(@{ id = $UserId; modifiedProperties = @(@{ displayName = 'AccountEnabled'; newValue = $NewValue }) }) }
        }
    }

    It 'recognises a disable in the audit log and ignores other user updates' {
        Test-IsDisableAudit (New-DisableAudit 'u' $script:T0) | Should -BeTrue
        Test-IsDisableAudit (New-DisableAudit 'u' $script:T0 'Disable account') | Should -BeTrue
        Test-IsDisableAudit (New-DisableAudit 'u' $script:T0 -NewValue '[true]') | Should -BeFalse
    }

    It 'pairs each HR disable with the first Entra disable after it, by employeeId' {
        $users = @(@{ id = 'u-dana'; employeeId = 'E1001'; displayName = 'Dana Okafor' }, @{ id = 'u-ben'; employeeId = 'E1002'; displayName = 'Ben Ito' })
        $prov = @(
            (New-ProvEvent 'E1001' 'Dana Okafor' $script:T0),
            (New-ProvEvent 'E1002' 'Ben Ito' $script:T0),
            (New-ProvEvent 'E9999' 'Nobody' $script:T0),                          # no such user -> unmatched
            (New-ProvEvent 'E1001' 'Dana Okafor' $script:T0 -Status 'failure')     # failed provisioning -> ignored
        )
        $audits = @(
            (New-DisableAudit 'u-dana' $script:T0.AddMinutes(-30)),                # BEFORE the HR event -> not paired
            (New-DisableAudit 'u-dana' $script:T0.AddMinutes(12)),
            (New-DisableAudit 'u-ben' $script:T0.AddMinutes(40))
        )
        $r = Measure-HrToDisable -ProvisioningEvents $prov -DirectoryAudits $audits -Users $users
        $r.Leavers | Should -Be 2
        $r.Unmatched | Should -Be 1
        $r.MedianMinutes | Should -Be 12
        $r.MaxMinutes | Should -Be 40
    }

    It 'counts the inbound-to-AD leaver logged as update + accountDisabled -> True, once per person, from the earliest row' {
        $users = @(@{ id = 'u-dana'; employeeId = '100492'; displayName = 'Dana Okafor' })
        $upd = { param([datetime]$At, [object[]]$Props) $e = New-ProvEvent '100492' '' $At -Action 'update'; $e['modifiedProperties'] = $Props; $e }
        $prov = @(
            (& $upd $script:T0.AddSeconds(1) @(@{ displayName = 'accountDisabled'; oldValue = ''; newValue = 'True' }, @{ displayName = 'parentDistinguishedName'; newValue = 'OU=Disabled,DC=corp,DC=contoso' })),
            (& $upd $script:T0 @(@{ displayName = 'accountDisabled'; oldValue = ''; newValue = 'True' })),
            (& $upd $script:T0 @(@{ displayName = 'department'; newValue = 'ICU' }))       # an ordinary update: not a leaver
        )
        $r = Measure-HrToDisable -ProvisioningEvents $prov -DirectoryAudits @((New-DisableAudit 'u-dana' $script:T0.AddMinutes(2.5))) -Users $users
        $r.Leavers | Should -Be 1
        $r.Unmatched | Should -Be 0
        $r.MedianMinutes | Should -Be 2.5
    }

    It 'one leaver per HR id even when the rows carry different or missing names' {
        $users = @(@{ id = 'u-dana'; employeeId = '100492'; displayName = 'Dana Okafor' })
        $prov = @((New-ProvEvent '100492' 'Dana Okafor' $script:T0), (New-ProvEvent '100492' '' $script:T0.AddSeconds(2)), (New-ProvEvent '100492' 'D. Okafor' $script:T0.AddSeconds(3)))
        $r = Measure-HrToDisable -ProvisioningEvents $prov -DirectoryAudits @((New-DisableAudit 'u-dana' $script:T0.AddMinutes(3))) -Users $users
        $r.Leavers | Should -Be 1
        $r.MedianMinutes | Should -Be 3
    }

    It 'Test-IsHrLeaverEvent: disable, or update that sets accountDisabled true; never a failed row or another update' {
        Test-IsHrLeaverEvent (New-ProvEvent 'E1' '' $script:T0) | Should -BeTrue
        Test-IsHrLeaverEvent (New-ProvEvent 'E1' '' $script:T0 -Status 'failure') | Should -BeFalse
        $u = New-ProvEvent 'E1' '' $script:T0 -Action 'update'
        $u['modifiedProperties'] = @(@{ displayName = 'accountDisabled'; newValue = 'False' })
        Test-IsHrLeaverEvent $u | Should -BeFalse
        $u['modifiedProperties'] = @(@{ displayName = 'accountDisabled'; newValue = '["True"]' })
        Test-IsHrLeaverEvent $u | Should -BeTrue
        Test-IsHrLeaverEvent (New-ProvEvent 'E1' '' $script:T0 -Action 'create') | Should -BeFalse
    }

    It 'does not guess between two users with the same display name' {
        $users = @(@{ id = 'a'; displayName = 'Sam Lee' }, @{ id = 'b'; displayName = 'Sam Lee' })
        $r = Measure-HrToDisable -ProvisioningEvents @((New-ProvEvent '' 'Sam Lee' $script:T0)) -DirectoryAudits @((New-DisableAudit 'a' $script:T0.AddMinutes(5))) -Users $users
        $r.Leavers | Should -Be 0
        $r.Unmatched | Should -Be 1
    }
}

Describe 'NHI KPIs and the 06-NHI-Inventory.ps1 contract' {
    It 'fallback read: expired credential OR no owner, counted once per app' {
        $apps = @(
            @{ id = 'a1'; owners = @(); passwordCredentials = @(@{ endDateTime = $script:Now.AddDays(-1).ToString('o') }); keyCredentials = @() },
            @{ id = 'a2'; owners = @(@{ id = 'u' }); passwordCredentials = @(@{ endDateTime = $script:Now.AddDays(-1).ToString('o') }); keyCredentials = @() },
            @{ id = 'a3'; owners = @(); passwordCredentials = @(); keyCredentials = @() },
            @{ id = 'a4'; owners = @(@{ id = 'u' }); passwordCredentials = @(); keyCredentials = @(@{ endDateTime = $script:Now.AddDays(60).ToString('o') }) }
        )
        $r = Measure-NhiCredential -Applications $apps -Now $script:Now
        $r.WithExpiredCredential | Should -Be 2
        $r.Orphaned | Should -Be 2
        $r.ExpiredOrOrphaned | Should -Be 3
        $r.Nhis | Should -Be 4
    }

    Context 'with real 06 -Offline output' {
        BeforeAll {
            Mock Write-Host {}
            Mock Out-Host {}
            $dir = Join-Path $TestDrive 'nhi'
            $null = & (Get-LabScriptPath '06-NHI-Inventory.ps1') -Offline -OutputDirectory $dir -WarningAction SilentlyContinue
            $script:NhiJson = Get-Content -LiteralPath (Join-Path $dir 'nhi_inventory.json') -Raw | ConvertFrom-Json
        }
        It 'refuses mock output as evidence' {
            { ConvertFrom-NhiInventory -Inventory $script:NhiJson } | Should -Throw '*only a tenant run*'
        }
        It 'reads 06''s own summary KPIs when the run is a tenant run' {
            $copy = $script:NhiJson | ConvertTo-Json -Depth 10 | ConvertFrom-Json
            $copy.Source = 'tenant'
            $r = ConvertFrom-NhiInventory -Inventory $copy -Now ([datetime]$copy.GeneratedAtUtc).ToUniversalTime().AddMinutes(5)
            $r.ExpiredOrOrphaned | Should -Be $script:NhiJson.Summary.kpi.expiredOrOrphanedNhi
            $r.Orphaned | Should -Be $script:NhiJson.Summary.kpi.orphanedNhi
            $r.WithExpiredCredential | Should -Be $script:NhiJson.Summary.kpi.nhiWithExpiredCredential
        }
        It 'refuses an incomplete or stale inventory' {
            $copy = $script:NhiJson | ConvertTo-Json -Depth 10 | ConvertFrom-Json
            $copy.Source = 'tenant'
            { ConvertFrom-NhiInventory -Inventory $copy -Now ([datetime]$copy.GeneratedAtUtc).ToUniversalTime().AddHours(30) } | Should -Throw '*old*'
            $copy.DataSources[0].Status = 'FAILED'
            { ConvertFrom-NhiInventory -Inventory $copy -Now ([datetime]$copy.GeneratedAtUtc).ToUniversalTime() } | Should -Throw '*incomplete*'
        }
    }
}

Describe 'PAM KPIs from the lab/pam reconcile report and Guacamole history' {
    It 'uses reconcile.sh''s definitions: eligible = VAULTED + HELD + GAP, rotated among VAULTED' {
        $rows = @(
            [pscustomobject]@{ account = 'tier0-admin-01'; status = 'VAULTED'; rotated_within_policy = 'yes' },
            [pscustomobject]@{ account = 'tier0-admin-02'; status = 'VAULTED'; rotated_within_policy = 'no' },
            [pscustomobject]@{ account = 'svc-backup'; status = 'VAULTED'; rotated_within_policy = 'yes' },
            [pscustomobject]@{ account = 'svc-sql'; status = 'HELD'; rotated_within_policy = 'n/a' },
            [pscustomobject]@{ account = 'svc-legacy'; status = 'GAP'; rotated_within_policy = 'no' },
            [pscustomobject]@{ account = 'krbtgt'; status = 'EXCEPTION'; rotated_within_policy = 'n/a' },
            [pscustomobject]@{ account = 'old-admin'; status = 'ORPHAN'; rotated_within_policy = 'n/a' }
        )
        $r = Measure-PamReconcile -Rows $rows
        $r.Eligible | Should -Be 5                  # documented exceptions are out of scope by policy
        $r.PctVaulted | Should -Be 60
        $r.PctRotatedWithinPolicy | Should -Be 66.7
        $r.Gap | Should -Be 1
        $r.Orphan | Should -Be 1
    }

    It 'refuses a file that is not a reconcile report' {
        { Measure-PamReconcile -Rows @([pscustomobject]@{ name = 'x' }) } | Should -Throw '*reconcile.sh*'
    }

    It 'matches the column names lab/pam/reconcile.sh actually writes' {
        $header = Select-String -LiteralPath (Join-Path $script:LabPowerShellRoot '..' '..' 'pam' 'reconcile.sh') -Pattern "^header=" | Select-Object -First 1
        $header | Should -Not -BeNullOrEmpty
        # header=$'account\ttier\t...': the columns are separated by a literal \t.
        $cols = ($header.Line -replace "^header=\$'", '' -replace "'\s*$", '') -split '\\t'
        foreach ($col in 'account', 'status', 'rotated_within_policy') { $cols | Should -Contain $col }
    }

    It 'leaves sessions with an unknown recording status out of the denominator' {
        $s = Measure-PamSession -Sessions @(@{ Recorded = $true }, @{ Recorded = $false }, @{ Recorded = $null })
        $s.Sessions | Should -Be 2
        $s.Unknown | Should -Be 1
        $s.PctRecorded | Should -Be 50
    }
}

Describe 'Snapshot helpers' {
    It 'never records a value for a failed KPI' {
        $k = Get-KpiEntry -Status failed -Value 0 -Note 'boom'
        $k['value'] | Should -BeNullOrEmpty
        $k['status'] | Should -Be 'failed'
    }
    It 'diffs only KPIs measured in both snapshots' {
        $before = @{ kpis = @{ a = @{ status = 'measured'; value = 40.0 }; b = @{ status = 'failed'; value = $null } } }
        $after = [ordered]@{ kpis = [ordered]@{ a = [ordered]@{ status = 'measured'; value = 92.5 }; b = [ordered]@{ status = 'measured'; value = 3 }; c = [ordered]@{ status = 'measured'; value = 1 } } }
        $d = Compare-KpiSnapshot -Before $before -After $after
        $d['a']['delta'] | Should -Be 52.5
        $d['b']['comparable'] | Should -BeFalse
        $d['c']['before'] | Should -Be 'absent'
    }
    It 'nearest-rank percentiles' {
        Get-Percentile -Values @(10, 40, 20, 30) -P 50 | Should -Be 20
        Get-Percentile -Values @(10, 40, 20, 30) -P 90 | Should -Be 40
        Get-Percentile -Values @() -P 50 | Should -BeNullOrEmpty
    }
}

Describe 'Authentication-method classification parity with 07-Passwordless-Rollout.ps1' {
    BeforeAll {
        # Load 07's copy under another name so both can be compared.
        $sb = Get-ScriptFunctionBlock -Path (Get-LabScriptPath '07-Passwordless-Rollout.ps1') -Name 'Get-AuthMethodClass'
        . ([scriptblock]::Create(($sb.ToString() -replace 'function Get-AuthMethodClass', 'function Get-AuthMethodClass07')))
    }
    It 'classifies <Methods> the same way in both scripts' -ForEach @(
        @{ Methods = @('passKeyDeviceBound') }, @{ Methods = @('passKeySynced') }, @{ Methods = @('windowsHelloForBusiness', 'mobilePhone') },
        @{ Methods = @('mobilePhone') }, @{ Methods = @('mobilePhone', 'microsoftAuthenticatorPush') }, @{ Methods = @() },
        @{ Methods = @('temporaryAccessPass') }, @{ Methods = @('passKeySynced', 'passKeyDeviceBoundAuthenticator') }
    ) {
        $a = Get-AuthMethodClass -MethodsRegistered $Methods
        $b = Get-AuthMethodClass07 -MethodsRegistered $Methods
        $a.Class | Should -Be $b.Class
        $a.PhishingResistant | Should -Be $b.PhishingResistant
        $a.DeviceBound | Should -Be $b.DeviceBound
    }
}

Describe '08-Measure-KPIs.ps1 end to end (mocked Graph, -SkipPam)' {
    BeforeAll {
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory',
                'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'Policy.Read.All', 'AccessReview.Read.All', 'Application.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        $old = (Get-Date).ToUniversalTime().AddDays(-200).ToString('o'); $recent = (Get-Date).ToUniversalTime().AddDays(-2).ToString('o')
        $global:KpiTest = @{
            Users = @(
                @{ id = 'u-dana'; displayName = 'Dana Okafor'; userPrincipalName = 'dana.okafor@contoso.test'; accountEnabled = $true; userType = 'Member'; createdDateTime = $old; employeeId = 'E1'; signInActivity = @{ lastSignInDateTime = $recent } },
                @{ id = 'u-grace'; displayName = 'Grace Mwangi'; userPrincipalName = 'grace.mwangi@contoso.test'; accountEnabled = $true; userType = 'Member'; createdDateTime = $old; employeeId = 'E2'; signInActivity = @{ lastSignInDateTime = $old } },
                @{ id = 'bg-1'; displayName = 'BG ADMIN 01'; userPrincipalName = 'bg-admin-01@lab.onmicrosoft.com'; accountEnabled = $true; userType = 'Member'; createdDateTime = $old; employeeId = $null; signInActivity = $null }
            )
        }
        Mock Invoke-MgGraphRequest {
            $t = $global:KpiTest
            switch -Regex ($Uri) {
                '/v1\.0/users\?' { return @{ value = @($t.Users) } }
                "/groups\?.*break-glass-admins" { return @{ value = @(@{ id = 'g-bg' }) } }
                "/groups\?.*pim-tier" { return @{ value = @(@{ id = 'g-tier0' }) } }
                "/groups\?.*privileged-iam-admins" { return @{ value = @(@{ id = 'g-pim' }) } }
                '/groups/g-bg/transitiveMembers' { return @{ value = @(@{ id = 'bg-1' }) } }
                '/groups/g-pim/transitiveMembers' { return @{ value = @(@{ id = 'u-dana' }) } }
                '/groups/g-tier0/transitiveMembers' { return @{ value = @(@{ id = 'u-grace' }) } }
                # isPrivileged (beta) returns GA only here, so Exchange Administrator
                # and the Reports Reader role below are privileged ONLY through the
                # tier map / a PIM tier group holding them.
                '/beta/roleManagement/directory/roleDefinitions' { return @{ value = @(@{ id = '62e90394-69f5-4237-9190-012177145e10'; templateId = '62e90394-69f5-4237-9190-012177145e10' }) } }
                '/roleAssignmentScheduleInstances' {
                    return @{ value = @(
                            @{ principalId = 'g-bg'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.group' } },
                            @{ principalId = 'u-grace'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.user' } },
                            @{ principalId = 'g-pim'; roleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.group' } },
                            # derived row for Dana through g-pim: must not make her standing
                            @{ principalId = 'u-dana'; roleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; assignmentType = 'Assigned'; memberType = 'Group'; principal = @{ '@odata.type' = '#microsoft.graph.user' } },
                            @{ principalId = 'g-tier0'; roleDefinitionId = '4a5d8f65-41da-4de4-8968-e035b65339cf'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.group' } },
                            @{ principalId = 'sp-dirrole'; roleDefinitionId = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'; assignmentType = 'Assigned'; memberType = 'Direct'; principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal' } }) }
                }
                '/roleEligibilityScheduleInstances' { return @{ value = @() } }
                "assignmentScheduleInstances\?.*g-bg" { return @{ value = @(@{ accessId = 'member'; principalId = 'bg-1'; assignmentType = 'Assigned' }) } }
                "eligibilityScheduleInstances\?.*g-bg" { return @{ value = @() } }
                "assignmentScheduleInstances\?.*g-pim" { return @{ value = @(@{ accessId = 'member'; principalId = 'u-dana'; assignmentType = 'Activated' }) } }
                "eligibilityScheduleInstances\?.*g-pim" { return @{ value = @(@{ accessId = 'member'; principalId = 'u-dana' }) } }
                "assignmentScheduleInstances\?.*g-tier0" { return @{ value = @(@{ accessId = 'member'; principalId = 'u-grace'; assignmentType = 'Assigned' }) } }
                "eligibilityScheduleInstances\?.*g-tier0" { return @{ value = @() } }
                '/servicePrincipals\?' {
                    return @{ value = @(@{ id = 'sp-graph'; appRoles = @(
                                    @{ id = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'; value = 'RoleManagement.ReadWrite.Directory' },
                                    @{ id = '62a82d76-70ea-41e2-9197-370581804d09'; value = 'Group.ReadWrite.All' },
                                    @{ id = 'df021288-bdef-4463-88db-98f22de89214'; value = 'User.Read.All' }) }) }
                }
                '/servicePrincipals/sp-graph/appRoleAssignedTo' {
                    return @{ value = @(
                            @{ principalId = 'sp-apply'; principalType = 'ServicePrincipal'; appRoleId = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' },
                            @{ principalId = 'sp-apply'; principalType = 'ServicePrincipal'; appRoleId = '62a82d76-70ea-41e2-9197-370581804d09' },
                            @{ principalId = 'sp-plan'; principalType = 'ServicePrincipal'; appRoleId = 'df021288-bdef-4463-88db-98f22de89214' }) }
                }
                '/userRegistrationDetails' { return @{ value = @(@{ id = 'u-dana'; methodsRegistered = @('passKeyDeviceBound') }, @{ id = 'u-grace'; methodsRegistered = @('mobilePhone') }) } }
                '/conditionalAccess/policies' {
                    return @{ value = @(@{ displayName = 'CA001'; state = 'enabled'; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }
                                conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All'); excludeApplications = @() }; users = @{ includeUsers = @('All'); excludeGroups = @('g-bg') } } }) }
                }
                '/accessReviews/definitions' { return @{ value = @() } }
                '/v1\.0/applications\?' { return @{ value = @(@{ id = 'a1'; displayName = 'orphan'; owners = @(); passwordCredentials = @(@{ endDateTime = $old }); keyCredentials = @() }) } }
                default { throw "unexpected Graph call in test: $Uri" }
            }
        }
        $global:LASTEXITCODE = 0
        $script:OutDir = Join-Path $TestDrive 'kpis'
        $script:DetailDir = Join-Path $TestDrive 'detail'
        $script:Snap = & $script:Kpi -Label 'test' -OutputDirectory $script:OutDir -DetailDirectory $script:DetailDir -SkipPam -WarningAction SilentlyContinue
        $script:File = @(Get-ChildItem -LiteralPath $script:OutDir -Filter '*.json')[0]
    }
    AfterAll { Remove-Variable -Name KpiTest -Scope Global -ErrorAction SilentlyContinue }

    It 'writes one snapshot with every KPI key and exits 0' {
        $LASTEXITCODE | Should -Be 0
        $j = Get-Content -LiteralPath $script:File.FullName -Raw | ConvertFrom-Json -AsHashtable
        $j['schema'] | Should -Be 'contoso-identity-kpis/v1'
        foreach ($k in 'admin_standing_users', 'admin_eligible_only_users', 'admin_jit_pct', 'privileged_service_principals', 'phishing_resistant_pct',
            'phishing_resistant_device_bound_pct', 'ca_mfa_coverage_pct', 'ca_mfa_coverage_incl_report_only_pct', 'access_review_completion_pct',
            'access_review_revocation_pct', 'access_review_revocation_applied_pct', 'stale_accounts', 'hr_to_disable_minutes',
            'nhi_expired_or_orphaned', 'nhi_with_expired_credential', 'nhi_orphaned', 'pam_vaulted_pct', 'pam_rotated_within_policy_pct', 'pam_sessions_recorded_pct') {
            $j['kpis'].Contains($k) | Should -BeTrue -Because "KPI '$k' must always be present (measured, failed or not-measured)"
        }
    }

    It 'computes the tenant numbers correctly' {
        $j = Get-Content -LiteralPath $script:File.FullName -Raw | ConvertFrom-Json -AsHashtable
        $j['kpis']['admin_standing_users']['value'] | Should -Be 1              # Grace's standing GA; break-glass counted apart
        $j['kpis']['admin_standing_users']['detail']['byTier']['global_admin'] | Should -Be 1
        $j['kpis']['admin_standing_users']['detail']['byTier']['other'] | Should -Be 1   # Grace again: permanent member of a PIM tier group
        $j['kpis']['admin_standing_users']['detail']['pimTierGroups'] | Should -Be 2
        # Dana: JIT through Privileged-IAM-Admins -> Exchange Administrator (privileged only via the
        # tier map); the derived memberType=Group row must not make her standing.
        $j['kpis']['admin_eligible_only_users']['value'] | Should -Be 1
        $j['kpis']['admin_eligible_only_users']['detail']['byTier']['tier1'] | Should -Be 1
        $j['kpis']['admin_jit_pct']['value'] | Should -Be 50
        # APPLY (Graph permissions only) + a service principal holding Application Administrator.
        $j['kpis']['privileged_service_principals']['value'] | Should -Be 2
        $j['kpis']['privileged_service_principals']['detail']['viaDirectoryRole'] | Should -Be 1
        $j['kpis']['privileged_service_principals']['detail']['viaGraphApplicationPermission'] | Should -Be 1
        $j['kpis']['privileged_service_principals']['detail']['byPermission']['RoleManagement.ReadWrite.Directory'] | Should -Be 1
        $j['kpis']['phishing_resistant_pct']['value'] | Should -Be 50           # Dana yes, Grace phone only; break-glass excluded
        $j['kpis']['ca_mfa_coverage_pct']['value'] | Should -Be 100
        $j['kpis']['stale_accounts']['value'] | Should -Be 1                    # Grace
        $j['kpis']['nhi_expired_or_orphaned']['value'] | Should -Be 1
        $j['kpis']['access_review_completion_pct']['status'] | Should -Be 'not-measured'
        $j['kpis']['hr_to_disable_minutes']['status'] | Should -Be 'not-measured'
        $j['kpis']['pam_vaulted_pct']['status'] | Should -Be 'not-measured'
    }

    It 'holds no names, UPNs, object ids or tenant domain (the kpis folder is public)' {
        $text = Get-Content -LiteralPath $script:File.FullName -Raw
        $text | Should -Not -Match '@'
        $text | Should -Not -Match 'u-dana|u-grace|bg-1|g-bg|g-pim|g-tier0|sp-apply|sp-dirrole|sp-graph|Dana|Grace|onmicrosoft'
        $text | Should -Not -Match '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
    }

    It 'writes a sha256 sidecar that matches the file' {
        $line = Get-Content -LiteralPath "$($script:File.FullName).sha256" -Raw
        $line | Should -Match '^[0-9a-f]{64}  \S+\.json'
        ($line -split '\s+')[0] | Should -Be (Get-FileHash -LiteralPath $script:File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'keeps per-user detail out of the public folder' {
        @(Get-ChildItem -LiteralPath $script:DetailDir -Filter '*-detail.json').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $script:OutDir -Filter '*-detail.json').Count | Should -Be 0
    }

    It 'reads the lab/pam reconcile report when present (and says why sessions are not measured)' {
        $csv = Join-Path $TestDrive 'reconcile-latest.csv'
        @(
            [pscustomobject]@{ account = 'tier0-admin-01'; status = 'VAULTED'; rotated_within_policy = 'yes' },
            [pscustomobject]@{ account = 'svc-legacy'; status = 'GAP'; rotated_within_policy = 'no' }
        ) | Export-Csv -LiteralPath $csv -NoTypeInformation
        $global:LASTEXITCODE = 0
        $null = & $script:Kpi -Label 'pam' -OutputDirectory (Join-Path $TestDrive 'kpis-pam') -DetailDirectory (Join-Path $TestDrive 'detail-pam') `
            -PamReconcilePath $csv -GuacamoleAdminSecretFile (Join-Path $TestDrive 'no-such-secret') -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $f = @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'kpis-pam') -Filter '*.json')[0]
        $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json -AsHashtable
        $j['kpis']['pam_vaulted_pct']['value'] | Should -Be 50
        $j['kpis']['pam_rotated_within_policy_pct']['value'] | Should -Be 100
        $j['kpis']['pam_sessions_recorded_pct']['status'] | Should -Be 'not-measured'
        (Get-Content -LiteralPath $f.FullName -Raw) | Should -Not -Match 'tier0-admin-01|svc-legacy'   # account names stay in lab/pam/out
    }

    It 'records a failed source as failed (never 0) and exits 1' {
        Mock Invoke-MgGraphRequest { throw 'Forbidden' } -ParameterFilter { $Uri -like '*userRegistrationDetails*' }
        $global:LASTEXITCODE = 0
        $null = & $script:Kpi -Label 'fail' -OutputDirectory (Join-Path $TestDrive 'kpis-fail') -DetailDirectory (Join-Path $TestDrive 'detail-fail') -SkipPam -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $f = @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'kpis-fail') -Filter '*.json')[0]
        $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json -AsHashtable
        $j['kpis']['phishing_resistant_pct']['status'] | Should -Be 'failed'
        $j['kpis']['phishing_resistant_pct']['value'] | Should -BeNullOrEmpty
    }
}
