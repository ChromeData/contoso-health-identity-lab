# Pester 5 tests for post-apply/New-LifecycleWorkflows.ps1 (offline preview
# only - no tenant): the mover workflow is opt-in and has the right shape.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Lcw = Get-LabScriptPath 'post-apply/New-LifecycleWorkflows.ps1'

    function Get-PreviewBody {
        # The script prints "POST .../workflows" then the JSON body per workflow.
        param([string[]]$Lines, [string]$Category)
        foreach ($l in $Lines) {
            if ($l -match '^\s*\{' -and $l -match '"category"') {
                $b = $l | ConvertFrom-Json -AsHashtable
                if ($b['category'] -eq $Category) { return $b }
            }
        }
        return $null
    }
}

Describe 'New-LifecycleWorkflows.ps1 -OfflinePreview' {
    BeforeEach {
        $global:LcwOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:LcwOut.Add("$Object") }
        Mock Out-Host {}
        Mock Invoke-MgGraphRequest { throw 'offline preview must not call Graph' }
    }
    AfterAll { Remove-Variable -Name LcwOut -Scope Global -ErrorAction SilentlyContinue }

    It 'without -IncludeMover builds only the joiner and the leaver (mover is opt-in)' {
        $r = @(& $script:Lcw -OfflinePreview)
        @($r | Where-Object Action -EQ 'offline-preview').Count | Should -Be 2
        (Get-PreviewBody -Lines $global:LcwOut -Category 'mover') | Should -BeNullOrEmpty
    }

    It '-IncludeMover adds a mover: attribute-change trigger, ICU scope, package swap, all continueOnError' {
        $r = @(& $script:Lcw -OfflinePreview -IncludeMover)
        @($r | Where-Object Action -EQ 'offline-preview').Count | Should -Be 3
        $m = Get-PreviewBody -Lines $global:LcwOut -Category 'mover'
        $m | Should -Not -BeNullOrEmpty
        $m['executionConditions']['trigger']['@odata.type'] | Should -Be '#microsoft.graph.identityGovernance.attributeChangeTrigger'
        @($m['executionConditions']['trigger']['triggerAttributes'] | ForEach-Object { $_['name'] }) | Should -Be @('department', 'jobTitle')
        $m['executionConditions']['scope']['rule'] | Should -Be "(department eq 'ICU')"
        $m['isSchedulingEnabled'] | Should -BeFalse
        $tasks = @($m['tasks'])
        $tasks.Count | Should -Be 3
        ($tasks | ForEach-Object { $_['continueOnError'] }) | Should -Not -Contain $false
        (@($tasks[0]['arguments']) | Where-Object { $_['name'] -eq 'accessPackageId' })['value'] | Should -Be '<accessPackageId: ICU - Critical Care Apps>'
        (@($tasks[1]['arguments']) | Where-Object { $_['name'] -eq 'accessPackageId' })['value'] | Should -Be '<accessPackageId: Nurse - Clinical Apps>'
    }

    It '-IncludeScheduledLeaver adds a leaver that runs by itself: removed from All-Workforce, scheduling on, the six leaver tasks' {
        $r = @(& $script:Lcw -OfflinePreview -IncludeScheduledLeaver)
        @($r | Where-Object Action -EQ 'offline-preview').Count | Should -Be 3
        $leavers = @(foreach ($l in $global:LcwOut) {
                if ($l -match '^\s*\{' -and $l -match '"category"') { $b = $l | ConvertFrom-Json -AsHashtable; if ($b['category'] -eq 'leaver') { $b } }
            })
        $leavers.Count | Should -Be 2
        $s = @($leavers | Where-Object { $_['displayName'] -eq 'Contoso - Leaver (HR disabled, scheduled)' })[0]
        $s | Should -Not -BeNullOrEmpty
        $s['isSchedulingEnabled'] | Should -BeTrue
        $s['executionConditions']['trigger']['@odata.type'] | Should -Be '#microsoft.graph.identityGovernance.membershipChangeTrigger'
        $s['executionConditions']['trigger']['changeType'] | Should -Be 'remove'
        $s['executionConditions']['scope']['@odata.type'] | Should -Be '#microsoft.graph.identityGovernance.groupBasedSubjectSet'
        @($s['executionConditions']['scope']['groups'])[0]['id'] | Should -Be '<groupId: all-workforce>'
        $onDemand = @($leavers | Where-Object { $_['displayName'] -eq 'Contoso - Leaver (real-time termination)' })[0]
        @($s['tasks']).Count | Should -Be @($onDemand['tasks']).Count
        @($s['tasks'] | ForEach-Object { $_['taskDefinitionId'] }) | Should -Be @($onDemand['tasks'] | ForEach-Object { $_['taskDefinitionId'] })
    }
}

Describe 'New-LifecycleWorkflows.ps1 against a mocked tenant (guards for the E121/E122 follow-ups)' {
    BeforeAll {
        $global:LcwDefs = @(
            'Enable user account', 'Generate TAP and send email', 'Request user access package assignment', 'Disable user account',
            'Revoke all refresh tokens for user', 'Cancel pending access package assignment requests for user',
            'Remove all access package assignments for user', 'Remove user from all groups', 'Remove all licenses for user'
        ) | ForEach-Object { @{ id = "def-$($_ -replace '[^A-Za-z]', '')"; displayName = $_; parameters = @() } }
    }
    BeforeEach {
        Mock Write-Host {}
        Mock Out-Host {}
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('LifecycleWorkflows.ReadWrite.All', 'EntitlementManagement.Read.All', 'User.Read.All', 'Group.Read.All') } }
        $global:LcwGroupRule = '(user.dirSyncEnabled -eq true) -and (user.userType -eq "Member") -and (user.accountEnabled -eq true)'
        $global:LcwManagerMail = $null
        Mock Invoke-MgGraphRequest {
            $u = [string]$Uri
            if ($u -like '*/taskDefinitions*') { return @{ value = $global:LcwDefs } }
            # -like treats '?' as a wildcard, so the more specific URL goes first.
            if ($u -like '*/accessPackages/pkg1*') { return @{ id = 'pkg1'; assignmentPolicies = @(@{ id = 'pol1'; displayName = 'birthright' }) } }
            if ($u -like '*/accessPackages`?*') { return @{ value = @(@{ id = 'pkg1'; displayName = 'Nurse - Clinical Apps' }) } }
            if ($u -like '*/groups?*') { return @{ value = @(@{ id = 'grp-aw'; displayName = 'All-Workforce'; groupTypes = @('DynamicMembership'); membershipRule = $global:LcwGroupRule; membershipRuleProcessingState = 'On' }) } }
            if ($u -like '*/lifecycleWorkflows/workflows') { return @{ value = @(@{ id = 'wf-j'; displayName = 'Contoso - Joiner (Nursing, day 1)' }) } }
            if ($u -like '*/lifecycleWorkflows/workflows/wf-j') { return @{ id = 'wf-j'; category = 'joiner'; executionConditions = @{ '@odata.type' = 'x' }; tasks = @() } }
            if ($u -like '*/manager?*') { return @{ displayName = 'Grace Mwangi'; mail = $global:LcwManagerMail } }
            if ($u -like '*/users/*') { return @{ id = 'u1'; displayName = 'Test Hrform'; department = 'Nursing'; accountEnabled = $true; onPremisesSyncEnabled = $true } }
            throw "unexpected Graph call: $Method $u"
        }
    }
    AfterAll { Remove-Variable -Name LcwGroupRule, LcwManagerMail, LcwDefs -Scope Global -ErrorAction SilentlyContinue }

    It 'warns before a joiner run when the manager has no mail attribute (the TAP email task would fail, E121)' {
        $w = @(& $script:Lcw -RunJoinerFor 'test.hrform@contosohealthlab.com' -WhatIf 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        @($w | Where-Object { $_.Message -match 'has no mail attribute' }).Count | Should -Be 1
    }

    It 'does not warn when the manager has mail' {
        $global:LcwManagerMail = 'grace.mwangi@contosohealthlab.com'
        $w = @(& $script:Lcw -RunJoinerFor 'test.hrform@contosohealthlab.com' -WhatIf 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        @($w | Where-Object { $_.Message -match 'has no mail attribute' }).Count | Should -Be 0
    }

    It 'refuses a scheduled-leaver trigger group whose rule does not require accountEnabled true' {
        $global:LcwGroupRule = '(user.dirSyncEnabled -eq true)'
        { & $script:Lcw -IncludeScheduledLeaver -WhatIf } | Should -Throw '*does not require accountEnabled true*'
    }

    It 'refuses a trigger group whose rule also filters on department (a job move would run the leaver)' {
        $global:LcwGroupRule = '(user.accountEnabled -eq true) -and (user.department -eq "Nursing")'
        { & $script:Lcw -IncludeScheduledLeaver -WhatIf } | Should -Throw '*job move*user.department*'
    }

    It 'refuses a trigger group whose rule uses -or' {
        $global:LcwGroupRule = '(user.accountEnabled -eq true) -or (user.userType -eq "Guest")'
        { & $script:Lcw -IncludeScheduledLeaver -WhatIf } | Should -Throw '*uses -or or -not*'
    }

    It 'resolves the real trigger group id into the scheduled leaver scope' {
        $r = @(& $script:Lcw -IncludeScheduledLeaver -WhatIf)
        @($r | Where-Object { $_.Workflow -eq 'Contoso - Leaver (HR disabled, scheduled)' -and $_.Action -eq 'whatif-create' }).Count | Should -Be 1
        Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Uri -like "*/groups?*mailNickname*all-workforce*" } -Times 1 -Exactly
    }
}
