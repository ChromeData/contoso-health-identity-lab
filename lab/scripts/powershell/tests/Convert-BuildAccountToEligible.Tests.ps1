# Pester 5 tests for post-apply/Convert-BuildAccountToEligible.ps1. Graph, az
# and the operator prompt are all mocked; nothing signs in or changes.
#   * Pure functions: the GA role-policy reader, approver filter, public-record
#     guard (parity with Invoke-BreakGlassDrill.ps1).
#   * Whole-script runs: the happy path (eligible FIRST, standing removed
#     SECOND), -WhatIf, every refusal path (exit 1, no POST, no file), the
#     already-converted no-op, and partial runs that must never remove the
#     standing assignment before the eligibility is confirmed.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Cv = Get-LabScriptPath 'post-apply/Convert-BuildAccountToEligible.ps1'
    # Defines the script's functions here too, so Invoke-AzJson exists and can be mocked.
    . (Get-ScriptFunctionBlock -Path $script:Cv)
    $script:GA = '62e90394-69f5-4237-9190-012177145e10'
    $script:Build = 'admin@contosolab.onmicrosoft.com'

    function New-PolicyRules {
        param([bool]$Approval = $true, [object[]]$Approvers = @(@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = 'u-approver' }),
            [string]$Context = 'c1', [bool]$Mfa = $false, [string]$EligibleMax = 'P365D', [bool]$EligibleExpiryRequired = $true)
        @(
            @{ id = 'Approval_EndUser_Assignment'; '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
                setting = @{ isApprovalRequired = $Approval; approvalStages = @(@{ primaryApprovers = @($Approvers) }) } },
            @{ id = 'Enablement_EndUser_Assignment'; enabledRules = @(if ($Mfa) { 'MultiFactorAuthentication' }) + @('Justification') },
            @{ id = 'AuthenticationContext_EndUser_Assignment'; isEnabled = [bool]$Context; claimValue = $(if ($Context) { $Context } else { $null }) },
            @{ id = 'Expiration_Admin_Eligibility'; isExpirationRequired = $EligibleExpiryRequired; maximumDuration = $EligibleMax }
        )
    }

    function Set-CvMocks {
        param([hashtable]$Over = @{})
        $s = @{
            Standing = $true; Eligible = $false; EligibleAppears = $true; RemoveWorks = $true
            BuildInBg = $false; BgCount = 2; BgDisabled = $false; CaGap = $false; BgGaEnd = $null
            Fido2 = @{ 'bg-1' = 2; 'bg-2' = 2; 'u-build' = 1 }; RuleEnabled = $true; NoAz = $false
            # Key model per user (default: the issued model), the admin profile's
            # enforced allow-list (empty = not enforced) and the build account's groups.
            KeyModels = @{}; AllowList = @(); BuildGroups = @('g-admins')
            Rules = (New-PolicyRules); Approvers = @{ 'u-approver' = @{ id = 'u-approver'; userPrincipalName = 'grace@contoso.test'; accountEnabled = $true } }
            Caller = $script:Build; Typed = $null
        }
        foreach ($k in $Over.Keys) { $s[$k] = $Over[$k] }
        if ($s.ContainsKey('RuleArgs')) { $ra = $s['RuleArgs']; $s.Rules = New-PolicyRules @ra }
        # Mock bodies run in the script's scope, where $script: is THAT script: pass constants in.
        $s.GA = $script:GA; $s.Build = $script:Build
        $s.Posts = [System.Collections.Generic.List[object]]::new()
        $s.Lines = [System.Collections.Generic.List[string]]::new()
        $global:CvTest = $s
        Mock Write-Host { $global:CvTest.Lines.Add([string]$Object) }
        Mock Write-Warning {}
        Mock Start-Sleep {}
        Mock Read-Host { if ($null -eq $global:CvTest.Typed) { throw 'unexpected prompt' }; $global:CvTest.Typed }
        Mock Get-MgContext { [pscustomobject]@{ Account = $global:CvTest.Caller; TenantId = '11111111-1111-1111-1111-111111111111'
                Scopes = @('User.Read.All', 'GroupMember.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory',
                    'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory') } }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Get-Command { if ($global:CvTest.NoAz) { $null } else { [pscustomobject]@{ Name = 'az' } } } -ParameterFilter { $Name -eq 'az' }
        Mock Invoke-AzJson {
            $a = $Arguments -join ' '
            if ($a -like 'account show*') { return 'sub-0000' }
            if ($a -like 'monitor log-analytics workspace show*') { return [pscustomobject]@{ customerId = 'ws-cust'; id = '/subscriptions/sub-0000/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab' } }
            if ($a -like '*SecurityInsights/alertRules/contoso-break-glass-signin*') { return [pscustomobject]@{ properties = [pscustomobject]@{ enabled = $global:CvTest.RuleEnabled; displayName = 'Contoso - Break-glass account sign-in (any)' } } }
            if ($a -like '*scheduledQueryRules*') { return $null }
            throw "unexpected az call in test: $a"
        }
        Mock Invoke-MgGraphRequest {
            $t = $global:CvTest
            if ($Method -eq 'POST') {
                $b = $Body | ConvertFrom-Json -AsHashtable
                $t.Posts.Add(@{ Uri = $Uri; Body = $b })
                if ($Uri -like '*roleEligibilityScheduleRequests') { if ($t.EligibleAppears) { $t.Eligible = $true }; return @{ id = 'req-e'; status = 'Provisioned' } }
                if ($Uri -like '*roleAssignmentScheduleRequests') { if ($t.RemoveWorks) { $t.Standing = $false }; return @{ id = 'req-r'; status = 'Revoked' } }
                throw "unexpected POST in test: $Uri"
            }
            $bgUsers = @(@{ id = 'bg-1'; userPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; accountEnabled = -not $t.BgDisabled },
                @{ id = 'bg-2'; userPrincipalName = 'bg-admin-02@contosolab.onmicrosoft.com'; accountEnabled = $true })
            switch -Regex ($Uri) {
                # bg-admin lookup first: its $select also names userPrincipalName.
                'users\?.*startswith' { return @{ value = @($bgUsers | Select-Object -First $t.BgCount) } }
                'users\?.*userPrincipalName' { return @{ value = @(@{ id = 'u-build'; userPrincipalName = $t.Build; accountEnabled = $true; onPremisesSyncEnabled = $null }) } }
                'groups\?.*break-glass-admins' { return @{ value = @(@{ id = 'g-bg' }) } }
                '/groups/g-bg/members' { return @{ value = @(@{ id = 'bg-1' }, @{ id = 'bg-2' }) + @(if ($t.BuildInBg) { @{ id = 'u-build' } }) } }
                'roleAssignmentScheduleInstances.*u-build' {
                    return @{ value = @(if ($t.Standing) { @{ principalId = 'u-build'; roleDefinitionId = $t.GA; directoryScopeId = '/'; assignmentType = 'Assigned'; memberType = 'Direct'; endDateTime = $null } }) }
                }
                'roleEligibilityScheduleInstances.*u-build' {
                    return @{ value = @(if ($t.Eligible) { @{ principalId = 'u-build'; roleDefinitionId = $t.GA; directoryScopeId = '/'; memberType = 'Direct'; endDateTime = '2027-04-18T00:00:00Z' } }) }
                }
                'roleAssignmentScheduleInstances.*g-bg' {
                    return @{ value = @(@{ principalId = 'g-bg'; roleDefinitionId = $t.GA; directoryScopeId = '/'; assignmentType = 'Assigned'; memberType = 'Direct'; endDateTime = $t.BgGaEnd }) }
                }
                '/conditionalAccess/policies' {
                    $ok = @{ displayName = 'CA001 - Require MFA for all users'; conditions = @{ users = @{ excludeGroups = @('g-bg') } } }
                    $gap = @{ displayName = 'CA009 - Secure security info registration'; conditions = @{ users = @{ excludeGroups = @() } } }
                    return @{ value = @($ok) + @(if ($t.CaGap) { $gap }) }
                }
                '/users/([^/]+)/authentication/fido2Methods' {
                    $u = $Matches[1]; $n = [int]$t.Fido2[$u]
                    $model = if ($t.KeyModels.ContainsKey($u)) { $t.KeyModels[$u] } else { 'cb69481e-8ff7-4039-93ec-0a2729a154a8' }
                    return @{ value = @(if ($n -gt 0) { 1..$n | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod'; id = "k$_"; aaGuid = $model } } }) }
                }
                '/users/([^/]+)/transitiveMemberOf' {
                    $u = $Matches[1]
                    return @{ value = @(if ($u -like 'bg-*') { @{ id = 'g-bg' } } elseif ($u -eq 'u-build') { foreach ($g in $t.BuildGroups) { @{ id = $g } } }) }
                }
                '/authenticationMethodConfigurations/fido2' {
                    return @{ id = 'Fido2'; state = 'enabled'; excludeTargets = @()
                        includeTargets = @(@{ id = 'g-bg'; targetType = 'group'; allowedPasskeyProfiles = @('p-admin') }, @{ id = 'g-admins'; targetType = 'group'; allowedPasskeyProfiles = @('p-admin') })
                        passkeyProfiles = @(@{ id = 'p-admin'; name = 'Contoso - Admins (device-bound, attested)'; keyRestrictions = @{ isEnforced = (@($t.AllowList).Count -gt 0); enforcementType = 'allow'; aaGuids = @($t.AllowList) } })
                    }
                }
                'roleManagementPolicyAssignments' { return @{ value = @(@{ id = 'pa-1'; policy = @{ id = 'pol-ga'; rules = @($t.Rules) } }) } }
                '/users/(u-[a-z]+)\?' { if ($t.Approvers.ContainsKey($Matches[1])) { return $t.Approvers[$Matches[1]] }; throw 'Not found' }
                '/groups/([^/]+)/transitiveMembers' { return @{ value = @($t.Approvers.Values) } }
                default { throw "unexpected Graph call in test: $Uri" }
            }
        }
    }

    function Invoke-Cv {
        param([string]$Name, [switch]$DryRun, [string]$ConfirmUpn = $script:Build)
        $global:LASTEXITCODE = 0
        $pub = Join-Path $TestDrive "$Name-pub"; $priv = Join-Path $TestDrive "$Name-priv"
        $p = @{ BuildAccountUpn = $script:Build; OnMicrosoftDomain = 'contosolab.onmicrosoft.com'; EvidenceDirectory = $pub; PrivateDirectory = $priv
            VerifyAttempts = 2; VerifyDelaySeconds = 0; ChangeTicket = 'CHG0001234'; WarningAction = 'SilentlyContinue' }
        if ($ConfirmUpn) { $p['ConfirmUpn'] = $ConfirmUpn }
        if ($DryRun) { $p['WhatIf'] = $true } else { $p['Confirm'] = $false }
        & $script:Cv @p
        $exit = $LASTEXITCODE
        $file = Get-ChildItem -LiteralPath $pub -Filter '*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
        return [pscustomobject]@{
            Exit = $exit; File = $file; Pub = $pub; Priv = $priv; Posts = @($global:CvTest.Posts); Lines = @($global:CvTest.Lines)
            Record = $(if ($file) { Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable })
        }
    }
}

AfterAll { Remove-Variable -Name CvTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Test-GaRolePolicy (reads what Set-DirectoryRolePimPolicies.ps1 sets)' {
    It 'accepts approval + auth context + a long-enough eligibility cap and returns the approvers' {
        $r = Test-GaRolePolicy -Rules (New-PolicyRules -Approvers @(@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = 'u-a' }, @{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = 'g-appr' })) -RequestedDuration 'P180D'
        @($r.Problems).Count | Should -Be 0
        $r.ActivationAuth | Should -Be 'authentication context c1'
        @($r.Approvers | ForEach-Object { "$($_.Type):$($_.Id)" }) | Should -Be @('user:u-a', 'group:g-appr')
    }
    It 'accepts MFA when no context is set' {
        (Test-GaRolePolicy -Rules (New-PolicyRules -Context '' -Mfa $true) -RequestedDuration 'P180D').ActivationAuth | Should -Be 'MFA'
    }
    It 'flags <Case>' -ForEach @(
        # Rule ARGUMENTS, not rules: -ForEach data is built at discovery, before BeforeAll defines New-PolicyRules.
        @{ Case = 'no approval'; RuleArgs = @{ Approval = $false }; Expect = 'does not require approval' }
        @{ Case = 'approval without approvers'; RuleArgs = @{ Approvers = @() }; Expect = 'no approver' }
        @{ Case = 'no MFA and no context'; RuleArgs = @{ Context = ''; Mfa = $false }; Expect = 'neither MFA nor' }
        @{ Case = 'eligibility capped below the request'; RuleArgs = @{ EligibleMax = 'P90D' }; Expect = 'capped at P90D' }
        @{ Case = 'the default (empty) policy'; RuleArgs = $null; Expect = 'does not require approval' }
    ) {
        $rules = if ($null -eq $RuleArgs) { @() } else { New-PolicyRules @RuleArgs }
        (Test-GaRolePolicy -Rules $rules -RequestedDuration 'P180D').Problems -join ' | ' | Should -Match $Expect
    }
    It 'ignores the cap when expiry is not required' {
        @((Test-GaRolePolicy -Rules (New-PolicyRules -EligibleMax 'P15D' -EligibleExpiryRequired $false) -RequestedDuration 'P180D').Problems).Count | Should -Be 0
    }
}

Describe 'Measure-Approver' {
    It 'keeps only enabled approvers who are neither the build account nor break-glass' {
        $users = @(
            @{ id = 'u-build'; userPrincipalName = 'admin@x.onmicrosoft.com'; accountEnabled = $true },
            @{ id = 'bg-1'; userPrincipalName = 'bg-admin-01@x.onmicrosoft.com'; accountEnabled = $true },
            @{ id = 'u-off'; userPrincipalName = 'off@contoso.test'; accountEnabled = $false },
            @{ id = 'u-grace'; userPrincipalName = 'grace@contoso.test'; accountEnabled = $true },
            @{ id = 'u-grace'; userPrincipalName = 'grace@contoso.test'; accountEnabled = $true }
        )
        @(Measure-Approver -ApproverUsers $users -BuildAccountId 'u-build' -BreakGlassIds @('bg-1')) | Should -Be @('grace@contoso.test')
        @(Measure-Approver -ApproverUsers @($users[0]) -BuildAccountId 'u-build').Count | Should -Be 0
    }
}

Describe 'Public-record guard parity with Invoke-BreakGlassDrill.ps1' {
    It 'uses the same patterns' {
        $drill = (Get-ScriptFunctionBlock -Path (Get-LabScriptPath 'Invoke-BreakGlassDrill.ps1') -Name 'Test-PublicRecordSafe').ToString()
        $mine = (Get-ScriptFunctionBlock -Path $script:Cv -Name 'Test-PublicRecordSafe').ToString()
        $pat = { param($t) [regex]::Match($t, "foreach \(\`$p in (.+?)\) \{").Groups[1].Value }
        (& $pat $mine) | Should -Not -BeNullOrEmpty
        (& $pat $mine) | Should -Be (& $pat $drill)
    }
}

Describe 'Convert-BuildAccountToEligible.ps1 (mocked Graph and az)' {
    It 'happy path: eligible first, standing removed second, break-glass re-checked, record written' {
        Set-CvMocks
        $r = Invoke-Cv -Name 'ok'
        $r.Exit | Should -Be 0
        $r.Posts.Count | Should -Be 2
        $r.Posts[0].Uri | Should -BeLike '*/roleManagement/directory/roleEligibilityScheduleRequests'
        $e = $r.Posts[0].Body
        $e['action'] | Should -Be 'adminAssign'
        $e['principalId'] | Should -Be 'u-build'
        $e['roleDefinitionId'] | Should -Be $script:GA
        $e['directoryScopeId'] | Should -Be '/'
        $e['scheduleInfo']['expiration']['type'] | Should -Be 'afterDuration'
        $e['scheduleInfo']['expiration']['duration'] | Should -Be 'P180D'
        $e['justification'] | Should -Not -BeNullOrEmpty
        $r.Posts[1].Uri | Should -BeLike '*/roleManagement/directory/roleAssignmentScheduleRequests'
        $r.Posts[1].Body['action'] | Should -Be 'adminRemove'
        $r.Posts[1].Body['principalId'] | Should -Be 'u-build'
        $r.Posts[1].Body['roleDefinitionId'] | Should -Be $script:GA
        $r.Record['result'] | Should -Be 'Converted'
        $r.Record['eligibility']['confirmed'] | Should -BeTrue
        $r.Record['standingAssignment']['removalConfirmed'] | Should -BeTrue
        $r.Record['breakGlassGaIntactAfter'] | Should -BeTrue
        $r.Record['changeTicket'] | Should -Be 'CHG0001234'
        @($r.Record['checks'] | Where-Object { $_['status'] -eq 'FAIL' }).Count | Should -Be 0
    }

    It 'the public record holds no UPN, object id or tenant name; the detail stays private; the hash matches' {
        Set-CvMocks
        $r = Invoke-Cv -Name 'privacy'
        $text = Get-Content -LiteralPath $r.File.FullName -Raw
        @(Test-PublicRecordSafe -Json $text).Count | Should -Be 0
        $text | Should -Not -Match 'u-build|g-bg|bg-1|grace|admin@|contosolab'
        $line = Get-Content -LiteralPath "$($r.File.FullName).sha256" -Raw
        ($line -split '\s+')[0] | Should -Be (Get-FileHash -LiteralPath $r.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        @(Get-ChildItem -LiteralPath $r.Priv -Filter '*-detail.json').Count | Should -Be 1
        (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $r.Priv -Filter '*-detail.json')[0].FullName -Raw) | Should -Match 'u-build'
    }

    It '-WhatIf runs every check, changes nothing and writes nothing' {
        Set-CvMocks
        $r = Invoke-Cv -Name 'whatif' -DryRun -ConfirmUpn ''
        $r.Exit | Should -Be 0
        $r.Posts.Count | Should -Be 0
        Test-Path -LiteralPath $r.Pub | Should -BeFalse
        Test-Path -LiteralPath $r.Priv | Should -BeFalse
        ($r.Lines -join "`n") | Should -Match 'WhatIf: every check passed'
        ($r.Lines -join "`n") | Should -Match '\[7/8\]'
    }

    It '-WhatIf with a failing check still refuses (exit 1)' {
        Set-CvMocks -Over @{ CaGap = $true }
        $r = Invoke-Cv -Name 'whatif-refuse' -DryRun -ConfirmUpn ''
        $r.Exit | Should -Be 1
        $r.Posts.Count | Should -Be 0
    }

    It 'refuses when <Case> (exit 1, no change, nothing written)' -ForEach @(
        @{ Case = 'a break-glass account is disabled'; Over = @{ BgDisabled = $true }; Expect = 'Break-glass bg-admin-01: disabled' }
        @{ Case = 'only one break-glass account exists'; Over = @{ BgCount = 1 }; Expect = 'Break-glass count: 1 healthy' }
        @{ Case = 'a CA policy does not exclude break-glass'; Over = @{ CaGap = $true }; Expect = 'CA exclusion: 1 of 2 policies' }
        @{ Case = 'a break-glass account has no FIDO2 key'; Over = @{ Fido2 = @{ 'bg-1' = 2; 'bg-2' = 0; 'u-build' = 1 } }; Expect = 'Passkeys bg-admin-02: 0 usable FIDO2' }
        @{ Case = 'the build account has no passkey'; Over = @{ Fido2 = @{ 'bg-1' = 2; 'bg-2' = 2; 'u-build' = 0 } }; Expect = 'Passkeys build account' }
        @{ Case = 'a break-glass key is a model the enforced allow-list blocks'; Over = @{ AllowList = @('cb69481e-8ff7-4039-93ec-0a2729a154a8'); KeyModels = @{ 'bg-2' = '99999999-9999-9999-9999-999999999999' } }; Expect = 'Passkeys bg-admin-02: 2 registered key(s) of a model the enforced allow-list blocks' }
        @{ Case = 'the build account is in no passkey target (e.g. only a PIM group)'; Over = @{ BuildGroups = @('g-pim-tier0') }; Expect = 'no passkey include target covers this account' }
        @{ Case = 'the build account key is a blocked model'; Over = @{ AllowList = @('cb69481e-8ff7-4039-93ec-0a2729a154a8'); KeyModels = @{ 'u-build' = '99999999-9999-9999-9999-999999999999' } }; Expect = 'has no passkey its profile accepts' }
        @{ Case = 'the break-glass alert rule is disabled'; Over = @{ RuleEnabled = $false }; Expect = 'Alert rule: the break-glass rule exists but is DISABLED' }
        @{ Case = 'the az CLI is missing'; Over = @{ NoAz = $true }; Expect = 'Alert rule: could not check: az CLI not found' }
        @{ Case = 'break-glass GA is time-bound, not permanent'; Over = @{ BgGaEnd = '2026-12-01T00:00:00Z' }; Expect = 'Second GA path: Break-Glass-Admins holds no permanent' }
        @{ Case = 'GA activation needs no approval'; Over = @{ RuleArgs = @{ Approval = $false } }; Expect = 'GA PIM policy: activation does not require approval' }
        @{ Case = 'the only approver is the build account'; Over = @{ Approvers = @{ 'u-approver' = @{ id = 'u-build'; userPrincipalName = 'admin@contosolab.onmicrosoft.com'; accountEnabled = $true } } }; Expect = 'GA approvers: no enabled approver' }
        @{ Case = 'the eligibility cap is shorter than P180D'; Over = @{ RuleArgs = @{ EligibleMax = 'P90D' } }; Expect = 'capped at P90D' }
        @{ Case = 'the build account is in Break-Glass-Admins'; Over = @{ BuildInBg = $true }; Expect = 'Build account not in Break-Glass-Admins' }
        @{ Case = 'the caller is a break-glass account'; Over = @{ Caller = 'bg-admin-01@contosolab.onmicrosoft.com' }; Expect = 'Caller: signed in as bg-admin-01' }
    ) {
        Set-CvMocks -Over $Over
        $r = Invoke-Cv -Name ("refuse-" + ($Case -replace '\W', '-'))
        $r.Exit | Should -Be 1
        $r.Posts.Count | Should -Be 0
        Test-Path -LiteralPath $r.Pub | Should -BeFalse
        Test-Path -LiteralPath $r.Priv | Should -BeFalse
        ($r.Lines -join "`n") | Should -Match 'REFUSED'
        ($r.Lines -join "`n") | Should -Match ([regex]::Escape($Expect))
    }

    It 'resolves an approver GROUP (as modules/pim renders it) and needs one member besides the build account' {
        $grp = @{ RuleArgs = @{ Approvers = @(@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = 'g-tier0-approvers' }) } }
        Set-CvMocks -Over ($grp + @{ Approvers = @{
                    'a' = @{ id = 'u-build'; userPrincipalName = $script:Build; accountEnabled = $true }
                    'b' = @{ id = 'u-grace'; userPrincipalName = 'grace@contoso.test'; accountEnabled = $true } } })
        (Invoke-Cv -Name 'grp-ok').Exit | Should -Be 0
        Set-CvMocks -Over ($grp + @{ Approvers = @{ 'a' = @{ id = 'u-build'; userPrincipalName = $script:Build; accountEnabled = $true } } })
        $r = Invoke-Cv -Name 'grp-only-build'
        $r.Exit | Should -Be 1
        $r.Posts.Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match 'GA approvers: no enabled approver'
    }

    It 'refuses when the typed confirmation does not match' {
        Set-CvMocks -Over @{ Typed = 'someone@contosolab.onmicrosoft.com' }
        $r = Invoke-Cv -Name 'typed-wrong' -ConfirmUpn ''
        $r.Exit | Should -Be 1
        $r.Posts.Count | Should -Be 0
        Test-Path -LiteralPath $r.Pub | Should -BeFalse
        ($r.Lines -join "`n") | Should -Match 'Confirmation - the typed UPN does not match'
    }

    It 'accepts the typed confirmation when it matches' {
        Set-CvMocks -Over @{ Typed = $script:Build.ToUpperInvariant() }
        (Invoke-Cv -Name 'typed-ok' -ConfirmUpn '').Exit | Should -Be 0
    }

    It 'already converted: nothing to do, nothing written, exit 0' {
        Set-CvMocks -Over @{ Standing = $false; Eligible = $true }
        $r = Invoke-Cv -Name 'already'
        $r.Exit | Should -Be 0
        $r.Posts.Count | Should -Be 0
        Test-Path -LiteralPath $r.Pub | Should -BeFalse
    }

    It 'refuses when there is no standing assignment to convert' {
        Set-CvMocks -Over @{ Standing = $false; Eligible = $false }
        $r = Invoke-Cv -Name 'nothing'
        $r.Exit | Should -Be 1
        ($r.Lines -join "`n") | Should -Match 'holds no standing Global Administrator'
    }

    It 'never removes the standing assignment when the eligibility does not appear (Partial, exit 1)' {
        Set-CvMocks -Over @{ EligibleAppears = $false }
        $r = Invoke-Cv -Name 'no-elig'
        $r.Exit | Should -Be 1
        @($r.Posts | Where-Object { $_.Uri -like '*roleAssignmentScheduleRequests' }).Count | Should -Be 0
        $r.Record['result'] | Should -Be 'Partial'
        $r.Record['standingAssignment']['removalConfirmed'] | Should -BeFalse
        $r.Record['breakGlassGaIntactAfter'] | Should -BeTrue
    }

    It 'reports Partial when the standing assignment is still listed after adminRemove' {
        Set-CvMocks -Over @{ RemoveWorks = $false }
        $r = Invoke-Cv -Name 'no-remove'
        $r.Exit | Should -Be 1
        $r.Record['result'] | Should -Be 'Partial'
        $r.Record['eligibility']['confirmed'] | Should -BeTrue
    }

    It 're-run after a partial reuses the existing eligibility (no second eligibility request)' {
        Set-CvMocks -Over @{ Eligible = $true }
        $r = Invoke-Cv -Name 'rerun'
        $r.Exit | Should -Be 0
        @($r.Posts | Where-Object { $_.Uri -like '*roleEligibilityScheduleRequests' }).Count | Should -Be 0
        @($r.Posts | Where-Object { $_.Uri -like '*roleAssignmentScheduleRequests' }).Count | Should -Be 1
        $r.Record['eligibility']['requestStatus'] | Should -Be 'already-eligible'
    }
}
