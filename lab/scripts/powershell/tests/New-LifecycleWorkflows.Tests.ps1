# Pester 5 tests for post-apply/New-LifecycleWorkflows.ps1 (offline preview
# only - no tenant): the mover and the scheduled leave-date leaver are opt-in
# and have the right shape.

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

    It '-IncludeLeaveDateLeaver adds a scheduled leaver: employeeLeaveDateTime day 0, disabled users only, package and group removal, no disable' {
        $r = @(& $script:Lcw -OfflinePreview -IncludeLeaveDateLeaver)
        @($r | Where-Object Action -EQ 'offline-preview').Count | Should -Be 3
        $bodies = @(foreach ($l in $global:LcwOut) { if ($l -match '^\s*\{' -and $l -match '"category"') { $l | ConvertFrom-Json -AsHashtable } })
        $w = @($bodies | Where-Object { $_['displayName'] -eq 'Contoso - Leaver (HR leave date, scheduled)' })
        $w.Count | Should -Be 1
        $w = $w[0]
        $w['category'] | Should -Be 'leaver'
        $w['isSchedulingEnabled'] | Should -BeTrue
        $tr = $w['executionConditions']['trigger']
        $tr['@odata.type'] | Should -Be '#microsoft.graph.identityGovernance.timeBasedAttributeTrigger'
        $tr['timeBasedAttribute'] | Should -Be 'employeeLeaveDateTime'
        $tr['offsetInDays'] | Should -Be 0
        # A rehired (enabled) worker with an old leave date is never processed.
        $w['executionConditions']['scope']['rule'] | Should -Be '(accountEnabled eq false)'
        $defs = @($w['tasks'] | ForEach-Object { $_['taskDefinitionId'] })
        $defs | Should -Contain '<taskDefinitionId: Remove all access package assignments for user>'
        $defs | Should -Contain '<taskDefinitionId: Remove user from all groups>'
        ($defs -join ' ') | Should -Not -Match 'Disable user account'
        (@($w['tasks']) | ForEach-Object { $_['continueOnError'] }) | Should -Not -Contain $false
    }

    It '-ScheduleIntervalHours prints the tenant schedule PATCH; 0 (default) leaves it alone' {
        & $script:Lcw -OfflinePreview -ScheduleIntervalHours 1 | Out-Null
        ($global:LcwOut -join "`n") | Should -Match 'PATCH \S+/lifecycleWorkflows/settings \{ workflowScheduleIntervalInHours = 1 \}'
        $global:LcwOut.Clear()
        & $script:Lcw -OfflinePreview | Out-Null
        ($global:LcwOut -join "`n") | Should -Not -Match 'workflowScheduleIntervalInHours'
    }

    It 'the joiner never admits a disabled user (it re-enabled a same-day HR leaver on 2026-11-07)' {
        & $script:Lcw -OfflinePreview | Out-Null
        $j = Get-PreviewBody -Lines $global:LcwOut -Category 'joiner'
        $j['executionConditions']['scope']['rule'] | Should -Be "(department eq 'Nursing') and (accountEnabled eq true)"
    }

    It '-LeaverExtensionLogicAppName adds the custom task extension (PoP, no callback) right after the built-in package removal' {
        & $script:Lcw -OfflinePreview -IncludeLeaveDateLeaver -LeaverExtensionLogicAppName 'la-lcw-leaver-remove-birthright' | Out-Null
        $ext = @(foreach ($l in $global:LcwOut) { if ($l -match '^\s*\{' -and $l -match 'logicAppTriggerEndpointConfiguration') { $l | ConvertFrom-Json -AsHashtable } })
        $ext.Count | Should -Be 1
        $ext[0]['endpointConfiguration']['logicAppWorkflowName'] | Should -Be 'la-lcw-leaver-remove-birthright'
        $ext[0]['endpointConfiguration']['resourceGroupName'] | Should -Be 'RG-IDENTITY-LAB'
        $ext[0]['authenticationConfiguration']['@odata.type'] | Should -Be '#microsoft.graph.azureAdPopTokenAuthentication'
        $ext[0].Contains('callbackConfiguration') | Should -BeFalse   # fire and forget: no LCW permission on the Logic App
        $w = @(foreach ($l in $global:LcwOut) { if ($l -match '^\s*\{' -and $l -match '"category"') { $b = $l | ConvertFrom-Json -AsHashtable; if ($b['displayName'] -eq 'Contoso - Leaver (HR leave date, scheduled)') { $b } } })[0]
        $defs = @($w['tasks'] | ForEach-Object { $_['taskDefinitionId'] })
        $i = [array]::IndexOf($defs, '<taskDefinitionId: Remove all access package assignments for user>')
        $defs[$i + 1] | Should -Be '<taskDefinitionId: Run a Custom Task Extension>'
        (@($w['tasks'][$i + 1]['arguments']) | Where-Object { $_['name'] -eq 'customTaskExtensionID' })['value'] | Should -Be '<customTaskExtensionId>'
        $w['tasks'][$i + 1]['continueOnError'] | Should -BeTrue
    }

    It '-LeaverExtensionLogicAppName without -IncludeLeaveDateLeaver is refused' {
        { & $script:Lcw -OfflinePreview -LeaverExtensionLogicAppName 'la-x' } | Should -Throw '*needs -IncludeLeaveDateLeaver*'
    }
}
