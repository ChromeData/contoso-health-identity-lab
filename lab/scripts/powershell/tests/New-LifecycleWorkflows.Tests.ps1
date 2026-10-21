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
}
