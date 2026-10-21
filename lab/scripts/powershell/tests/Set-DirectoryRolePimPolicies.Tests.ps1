# Pester 5 tests for post-apply/Set-DirectoryRolePimPolicies.ps1.
#   * Pure helpers (from the syntax tree): file parsing, rule drift, the
#     strengthening-first PATCH order, the eligibility body.
#   * A contract test: the fixture's rule ids are exactly the ones
#     modules/pim/directory-roles.tf renders.
#   * Whole-script runs against a SIMULATED Global Administrator policy: the
#     Invoke-MgGraphRequest mock keeps the rules in memory and applies each
#     PATCH, so a second run proves idempotency, and a Graph that refuses
#     "MFA + auth context" exercises the stop-at-first-failure path.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Drp = Get-LabScriptPath 'post-apply/Set-DirectoryRolePimPolicies.ps1'
    $script:DirectoryRolesTf = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' 'terraform' 'modules' 'pim' 'directory-roles.tf'))
    . (Get-ScriptFunctionBlock -Path $script:Drp -Name 'Read-RolePolicyFile', 'Get-ApproverGroupId', 'Get-RuleDrift', 'Get-RulePatchOrder', 'Test-BreakGlassUpn', 'Test-AdminAccountUpn', 'Get-RoleEligibilityRequestBody')

    $script:Ga = '62e90394-69f5-4237-9190-012177145e10'
    $script:ApproverGid = 'g-pim-approvers-tier0'

    function New-Target([string]$Caller, [string]$Level) {
        [ordered]@{ '@odata.type' = 'microsoft.graph.unifiedRoleManagementPolicyRuleTarget'; caller = $Caller; operations = @('All'); level = $Level; inheritableSettings = @(); enforcedSettings = @() }
    }
    function New-GaPolicy([string]$AuthContext = '', [string]$Mailbox = '') {
        # Same shape as modules/pim directory-roles.tf (local.ga_rules).
        $rules = [System.Collections.Generic.List[object]]::new()
        $rules.Add([ordered]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_EndUser_Assignment'; isExpirationRequired = $true; maximumDuration = 'PT2H'; target = (New-Target 'EndUser' 'Assignment') })
        $en = @(); if (-not $AuthContext) { $en += 'MultiFactorAuthentication' }; $en += 'Justification', 'Ticketing'
        $rules.Add([ordered]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; id = 'Enablement_EndUser_Assignment'; enabledRules = $en; target = (New-Target 'EndUser' 'Assignment') })
        $rules.Add([ordered]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'; id = 'AuthenticationContext_EndUser_Assignment'; isEnabled = [bool]$AuthContext; claimValue = $(if ($AuthContext) { $AuthContext } else { $null }); target = (New-Target 'EndUser' 'Assignment') })
        $rules.Add([ordered]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id = 'Approval_EndUser_Assignment'; target = (New-Target 'EndUser' 'Assignment')
                setting = [ordered]@{ '@odata.type' = 'microsoft.graph.approvalSettings'; isApprovalRequired = $true; isApprovalRequiredForExtension = $false; isRequestorJustificationRequired = $true; approvalMode = 'SingleStage'
                    approvalStages = @([ordered]@{ approvalStageTimeOutInDays = 1; isApproverJustificationRequired = $true; escalationTimeInMinutes = 0; isEscalationEnabled = $false; escalationApprovers = @()
                            primaryApprovers = @([ordered]@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = $script:ApproverGid }) })
                }
            })
        $rules.Add([ordered]@{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_Admin_Eligibility'; isExpirationRequired = $true; maximumDuration = 'P180D'; target = (New-Target 'Admin' 'Eligibility') })
        if ($Mailbox) {
            foreach ($n in @(@('Notification_Admin_EndUser_Assignment', 'EndUser', 'Assignment'), @('Notification_Admin_Admin_Eligibility', 'Admin', 'Eligibility'), @('Notification_Admin_Admin_Assignment', 'Admin', 'Assignment'))) {
                $rules.Add([ordered]@{ notificationType = 'Email'; recipientType = 'Admin'; notificationLevel = 'All'; isDefaultRecipientsEnabled = $true; notificationRecipients = @($Mailbox)
                        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'; id = $n[0]; target = (New-Target $n[1] $n[2]) })
            }
        }
        [ordered]@{ roleDefinitionId = $script:Ga; roleName = 'Global Administrator'; tier = 0; directoryScopeId = '/'; allowNamedEligibility = $true; eligibilityDuration = 'P180D'; rules = @($rules) }
    }
    function Write-PolicyFile([string]$Path, [hashtable]$Policy, [switch]$FullOutput) {
        $map = [ordered]@{ $script:Ga = ($Policy | ConvertTo-Json -Depth 20 -Compress) }
        $doc = if ($FullOutput) { [ordered]@{ directory_role_pim_policies = [ordered]@{ sensitive = $false; value = $map } } } else { $map }
        ($doc | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
    }
    function New-TenantRules {
        # Global Administrator as a fresh tenant ships it (simplified): 8h
        # activation with MFA, no approval, eligibility may be permanent.
        $r = @{}
        $r['Expiration_EndUser_Assignment'] = @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_EndUser_Assignment'; isExpirationRequired = $true; maximumDuration = 'PT8H' }
        $r['Enablement_EndUser_Assignment'] = @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; id = 'Enablement_EndUser_Assignment'; enabledRules = @('MultiFactorAuthentication') }
        $r['AuthenticationContext_EndUser_Assignment'] = @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'; id = 'AuthenticationContext_EndUser_Assignment'; isEnabled = $false; claimValue = $null }
        $r['Approval_EndUser_Assignment'] = @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id = 'Approval_EndUser_Assignment'; setting = @{ isApprovalRequired = $false; isRequestorJustificationRequired = $true; approvalStages = @() } }
        $r['Expiration_Admin_Eligibility'] = @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_Admin_Eligibility'; isExpirationRequired = $false; maximumDuration = 'P365D' }
        $r['Expiration_Admin_Assignment'] = @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = 'Expiration_Admin_Assignment'; isExpirationRequired = $false; maximumDuration = 'P180D' }
        return $r
    }

    function Set-DrpMock {
        param(
            [hashtable]$Rules = (New-TenantRules),
            [hashtable]$Users = @{ 'adm-ava.lin@contosohealthlab.onmicrosoft.com' = 'u-ava'; 'grace.mwangi@contosohealth.io' = 'u-grace' },
            [string[]]$Approvers = @('u-appr-1', 'u-appr-2'),
            [hashtable[]]$Eligible = @(),
            [switch]$RefuseContextWithMfa,
            [switch]$FailPolicyRead
        )
        $global:DrpTest = @{ Rules = $Rules; Users = $Users; Approvers = $Approvers; Eligible = [System.Collections.Generic.List[object]]::new(); Patches = [System.Collections.Generic.List[string]]::new(); Posts = [System.Collections.Generic.List[object]]::new(); RefuseCtx = [bool]$RefuseContextWithMfa; FailRead = [bool]$FailPolicyRead; Ga = $script:Ga; ApproverGid = $script:ApproverGid }
        foreach ($e in $Eligible) { $global:DrpTest.Eligible.Add($e) }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('RoleManagementPolicy.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory', 'User.Read.All', 'GroupMember.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:DrpTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -eq 'PATCH') {
                $b = $Body | ConvertFrom-Json -AsHashtable
                if ($u -notmatch '/policies/roleManagementPolicies/DirectoryRole_t_p/rules/(?<id>\w+)$') { throw "unexpected PATCH $u" }
                $id = $Matches.id
                if ($t.RefuseCtx -and $id -eq 'AuthenticationContext_EndUser_Assignment' -and $b['isEnabled'] -and 'MultiFactorAuthentication' -in @($t.Rules['Enablement_EndUser_Assignment']['enabledRules'])) {
                    throw 'Response status code does not indicate success: BadRequest (RoleManagementPolicyRuleConflict)'
                }
                $t.Patches.Add($id); $t.Rules[$id] = $b
                return $null
            }
            if ($Method -eq 'POST') {
                $b = $Body | ConvertFrom-Json -AsHashtable
                $t.Posts.Add(@{ Uri = $u; Body = $b })
                $t.Eligible.Add(@{ principalId = $b['principalId']; roleDefinitionId = $b['roleDefinitionId']; expirationType = $b['scheduleInfo']['expiration']['type'] })
                return @{ id = 'req-1'; status = 'Provisioned' }
            }
            if ($u -like '*/policies/roleManagementPolicyAssignments*') {
                if ($t.FailRead) { throw 'HTTP 503 Service Unavailable' }
                return @{ value = @(@{ policyId = 'DirectoryRole_t_p'; scopeId = '/'; scopeType = 'DirectoryRole'; roleDefinitionId = $t.Ga }) }
            }
            if ($u -like '*/policies/roleManagementPolicies/DirectoryRole_t_p/rules') { return @{ value = @($t.Rules.Values) } }
            if ($u -match "/users\?\`$filter=userPrincipalName eq '(?<n>[^']+)'") {
                $n = $Matches.n
                return @{ value = @(if ($t.Users.ContainsKey($n)) { @{ id = $t.Users[$n]; displayName = $n } }) }
            }
            if ($u -like "*/groups/$($t.ApproverGid)/transitiveMembers*") { return @{ value = @($t.Approvers | ForEach-Object { @{ id = $_ } }) } }
            if ($u -match "roleEligibilitySchedules\?\`$filter=principalId eq '(?<p>[^']+)' and roleDefinitionId eq '(?<r>[^']+)'") {
                $p = $Matches.p; $r = $Matches.r
                return @{ value = @($t.Eligible | Where-Object { $_.principalId -eq $p -and $_.roleDefinitionId -eq $r } | ForEach-Object { @{ principalId = $_.principalId; scheduleInfo = @{ expiration = @{ type = $_.expirationType } } } }) }
            }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
}

AfterAll { Remove-Variable -Name DrpTest -Scope Global -ErrorAction SilentlyContinue }

# =============================================================================
Describe 'Set-DirectoryRolePimPolicies.ps1 - helpers' {
    It 'fixture rule ids are exactly the ones modules/pim/directory-roles.tf renders' {
        $tf = Get-Content -LiteralPath $DirectoryRolesTf -Raw
        $tfIds = @([regex]::Matches($tf, 'id\s*=\s*"((?:Expiration|Enablement|AuthenticationContext|Approval|Notification)_[A-Za-z_]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $fixtureIds = @((New-GaPolicy -Mailbox 'x@contoso.test').rules | ForEach-Object { $_.id } | Sort-Object -Unique)
        $fixtureIds | Should -Be $tfIds
        $tfIds | Should -Not -Contain 'Expiration_Admin_Assignment' -Because 'break-glass standing GA must stay creatable'
    }

    It 'reads the single-output file and a full terraform output -json the same way' {
        $a = Join-Path $TestDrive 'single.json'; $b = Join-Path $TestDrive 'full.json'
        Write-PolicyFile $a (New-GaPolicy); Write-PolicyFile $b (New-GaPolicy) -FullOutput
        $x = Read-RolePolicyFile -Path $a; $y = Read-RolePolicyFile -Path $b
        @($x.Keys) | Should -Be @($Ga)
        ($x | ConvertTo-Json -Depth 20) | Should -Be ($y | ConvertTo-Json -Depth 20)
        $x[$Ga]['eligibilityDuration'] | Should -Be 'P180D'
    }

    It 'refuses a file whose key and roleDefinitionId disagree' {
        $p = Join-Path $TestDrive 'bad.json'
        $pol = New-GaPolicy; $pol.roleDefinitionId = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        Write-PolicyFile $p $pol
        { Read-RolePolicyFile -Path $p } | Should -Throw '*does not match*'
    }

    It 'finds the groupMembers approver ids in the Approval rule' {
        Get-ApproverGroupId -Rules (New-GaPolicy).rules | Should -Be @($ApproverGid)
    }

    It 'reports drift only on the settings the policy controls' {
        $d = (New-GaPolicy).rules
        $byId = @{}; foreach ($r in $d) { $byId[$r.id] = $r }
        (Get-RuleDrift -Desired $byId['Expiration_Admin_Eligibility'] -Actual @{ isExpirationRequired = $true; maximumDuration = 'P180D'; target = @{ targetObjects = @() } }).Count | Should -Be 0
        (Get-RuleDrift -Desired $byId['Expiration_Admin_Eligibility'] -Actual @{ isExpirationRequired = $false; maximumDuration = 'P365D' }) | Should -Be @('isExpirationRequired', 'maximumDuration')
        (Get-RuleDrift -Desired $byId['Enablement_EndUser_Assignment'] -Actual @{ enabledRules = @('Ticketing', 'MultiFactorAuthentication', 'Justification') }).Count | Should -Be 0 -Because 'order does not matter'
        (Get-RuleDrift -Desired $byId['AuthenticationContext_EndUser_Assignment'] -Actual @{ isEnabled = $false; claimValue = 'c7' }).Count | Should -Be 0 -Because 'a disabled context ignores claimValue'
        (Get-RuleDrift -Desired $byId['Approval_EndUser_Assignment'] -Actual @{ setting = @{ isApprovalRequired = $true; isRequestorJustificationRequired = $true; approvalStages = @(@{ primaryApprovers = @(@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = 'u-1' }) }) } }) | Should -Be @('setting.approvalStages.primaryApprovers')
        (Get-RuleDrift -Desired $byId['Approval_EndUser_Assignment'] -Actual $null) | Should -Be @('rule missing')
    }

    It 'orders PATCHes strengthening-first' {
        $on = @{}; foreach ($r in (New-GaPolicy -AuthContext 'c1').rules) { $on[$r.id] = $r }
        $off = @{}; foreach ($r in (New-GaPolicy).rules) { $off[$r.id] = $r }
        $ids = @('Expiration_EndUser_Assignment', 'Enablement_EndUser_Assignment', 'AuthenticationContext_EndUser_Assignment', 'Approval_EndUser_Assignment')
        $ctxOff = @{ AuthenticationContext_EndUser_Assignment = @{ isEnabled = $false } }
        $ctxOn = @{ AuthenticationContext_EndUser_Assignment = @{ isEnabled = $true; claimValue = 'c1' } }
        # Turning the context ON: context before MFA leaves.
        (Get-RulePatchOrder -RuleIds $ids -Desired $on -Actual $ctxOff) -join ',' | Should -Be 'Expiration_EndUser_Assignment,AuthenticationContext_EndUser_Assignment,Enablement_EndUser_Assignment,Approval_EndUser_Assignment'
        # ... unless the operator accepts the gap (Graph refused both at once).
        (Get-RulePatchOrder -RuleIds $ids -Desired $on -Actual $ctxOff -AllowMfaGap) -join ',' | Should -Be 'Expiration_EndUser_Assignment,Enablement_EndUser_Assignment,AuthenticationContext_EndUser_Assignment,Approval_EndUser_Assignment'
        # Turning it OFF: MFA back before the context goes, wherever they stood.
        (Get-RulePatchOrder -RuleIds $ids -Desired $off -Actual $ctxOn) -join ',' | Should -Be 'Expiration_EndUser_Assignment,Enablement_EndUser_Assignment,AuthenticationContext_EndUser_Assignment,Approval_EndUser_Assignment'
        (Get-RulePatchOrder -RuleIds @('AuthenticationContext_EndUser_Assignment', 'Enablement_EndUser_Assignment') -Desired $off -Actual $ctxOn) -join ',' | Should -Be 'Enablement_EndUser_Assignment,AuthenticationContext_EndUser_Assignment'
        # Unrelated rules keep their order.
        (Get-RulePatchOrder -RuleIds @('Approval_EndUser_Assignment', 'Expiration_Admin_Eligibility') -Desired $on -Actual $ctxOff) -join ',' | Should -Be 'Approval_EndUser_Assignment,Expiration_Admin_Eligibility'
    }

    It 'has comment-based help that Get-Help can parse, naming what it deliberately leaves alone' {
        $h = Get-Help $Drp -Full | Out-String
        $h | Should -Match 'Expiration_Admin_Assignment'
        $h | Should -Match 'STRENGTHENING FIRST'
    }

    It 'builds an expiring eligibility request and refuses anything else' {
        $b = Get-RoleEligibilityRequestBody -RoleDefinitionId $Ga -PrincipalId 'u' -DirectoryScopeId '/' -Duration 'P180D' -Justification 'j' -Start ([datetime]'2026-11-02T10:00:00Z')
        $b.scheduleInfo.expiration.type | Should -Be 'afterDuration'
        $b.scheduleInfo.expiration.duration | Should -Be 'P180D'
        { Get-RoleEligibilityRequestBody -RoleDefinitionId $Ga -PrincipalId 'u' -DirectoryScopeId '/' -Duration 'noExpiration' -Justification 'j' -Start (Get-Date) } | Should -Throw '*never requested*'
    }
}

# =============================================================================
Describe 'Set-DirectoryRolePimPolicies.ps1 - against a simulated GA policy' {
    BeforeEach {
        $global:LASTEXITCODE = 0
        $script:file = Join-Path $TestDrive "ga-$([guid]::NewGuid().ToString('N')).json"
    }

    It 'brings a fresh tenant to the rendered policy, grants 180-day eligibility, and a second run changes nothing' {
        Write-PolicyFile $file (New-GaPolicy)
        Set-DrpMock
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        @($global:DrpTest.Patches) | Should -Be @('Expiration_EndUser_Assignment', 'Enablement_EndUser_Assignment', 'Approval_EndUser_Assignment', 'Expiration_Admin_Eligibility')
        $global:DrpTest.Rules['Expiration_Admin_Assignment'].isExpirationRequired | Should -BeFalse -Because 'the direct-active GA rules are never touched (break-glass)'
        $global:DrpTest.Posts.Count | Should -Be 1
        $post = $global:DrpTest.Posts[0]
        $post.Uri | Should -Be 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests'
        $post.Body.roleDefinitionId | Should -Be $Ga
        $post.Body.directoryScopeId | Should -Be '/'
        $post.Body.scheduleInfo.expiration | Should -BeOfType [System.Collections.IDictionary]
        $post.Body.scheduleInfo.expiration.type | Should -Be 'afterDuration'
        $post.Body.scheduleInfo.expiration.duration | Should -Be 'P180D'

        # Idempotent: same tenant, second run.
        $global:DrpTest.Patches.Clear(); $global:DrpTest.Posts.Clear()
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $LASTEXITCODE | Should -Be 0
        $global:DrpTest.Patches.Count | Should -Be 0
        $global:DrpTest.Posts.Count | Should -Be 0
    }

    It 'never makes break-glass eligible, but still applies the policy' {
        Write-PolicyFile $file (New-GaPolicy)
        Set-DrpMock
        Mock Write-Warning {}
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'bg-admin-01@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:DrpTest.Posts.Count | Should -Be 0
        $global:DrpTest.Patches.Count | Should -BeGreaterThan 0
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'break-glass' }
    }

    It 'switching to the auth context: if Graph refuses it while MFA is on, MFA stays and nothing else happens' {
        Write-PolicyFile $file (New-GaPolicy -AuthContext 'c1')
        Set-DrpMock -RefuseContextWithMfa
        Mock Write-Warning {}
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:DrpTest.Patches | Should -Not -Contain 'Enablement_EndUser_Assignment'
        $global:DrpTest.Rules['Enablement_EndUser_Assignment'].enabledRules | Should -Contain 'MultiFactorAuthentication'
        $global:DrpTest.Posts.Count | Should -Be 0 -Because 'no eligibility under a partial policy'
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'AllowMfaGap' }
    }

    It '-AllowMfaGap: MFA leaves first, then the context is enabled' {
        Write-PolicyFile $file (New-GaPolicy -AuthContext 'c1')
        Set-DrpMock -RefuseContextWithMfa
        & $Drp -PolicyPath $file -Confirm:$false -AllowMfaGap
        $LASTEXITCODE | Should -Be 0
        $p = @($global:DrpTest.Patches)
        [array]::IndexOf($p, 'Enablement_EndUser_Assignment') | Should -BeLessThan ([array]::IndexOf($p, 'AuthenticationContext_EndUser_Assignment'))
        $global:DrpTest.Rules['AuthenticationContext_EndUser_Assignment'].claimValue | Should -Be 'c1'
        $global:DrpTest.Rules['Enablement_EndUser_Assignment'].enabledRules | Should -Not -Contain 'MultiFactorAuthentication'
    }

    It 'a Graph that accepts both: the context goes on BEFORE MFA leaves' {
        Write-PolicyFile $file (New-GaPolicy -AuthContext 'c1')
        Set-DrpMock
        & $Drp -PolicyPath $file -Confirm:$false
        $p = @($global:DrpTest.Patches)
        [array]::IndexOf($p, 'AuthenticationContext_EndUser_Assignment') | Should -BeLessThan ([array]::IndexOf($p, 'Enablement_EndUser_Assignment'))
    }

    It 'a failed policy READ changes nothing (exit 1)' {
        Write-PolicyFile $file (New-GaPolicy)
        Set-DrpMock -FailPolicyRead
        Mock Write-Warning {}
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:DrpTest.Patches.Count | Should -Be 0
        $global:DrpTest.Posts.Count | Should -Be 0
    }

    It 'reports a PERMANENT existing eligibility instead of keeping it silently, and warns on approver overlap' {
        Write-PolicyFile $file (New-GaPolicy)
        Set-DrpMock -Approvers @('u-ava') -Eligible @(@{ principalId = 'u-ava'; roleDefinitionId = $Ga; expirationType = 'noExpiration' })
        Mock Write-Warning {}
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -Confirm:$false
        $global:DrpTest.Posts.Count | Should -Be 0
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'PERMANENT' }
        Should -Invoke Write-Warning -ParameterFilter { $Message -match 'also an approver' }
    }

    It '-WhatIf with a Graph session reads but changes nothing' {
        Write-PolicyFile $file (New-GaPolicy)
        Set-DrpMock
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -WhatIf
        $global:DrpTest.Patches.Count | Should -Be 0
        $global:DrpTest.Posts.Count | Should -Be 0
    }

    It '-WhatIf without a Graph session is an offline preview (no Graph call at all)' {
        Write-PolicyFile $file (New-GaPolicy)
        Set-DrpMock
        Mock Get-MgContext { $null }
        & $Drp -PolicyPath $file -EligibleUserPrincipalNames 'adm-ava.lin@contosohealthlab.onmicrosoft.com' -WhatIf
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
    }
}
