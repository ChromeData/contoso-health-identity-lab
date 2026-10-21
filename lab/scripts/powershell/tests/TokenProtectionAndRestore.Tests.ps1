# Pester 5 tests for post-apply/Set-TokenProtectionPolicy.ps1 and
# Invoke-CaRestoreDrill.ps1. Graph is a Pester mock holding the CA policies in
# memory; no tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Tp = Get-LabScriptPath 'post-apply/Set-TokenProtectionPolicy.ps1'
    $script:Drill = Get-LabScriptPath 'Invoke-CaRestoreDrill.ps1'

    function Set-CaMocks {
        param([object[]]$Policies = @())
        $global:CaTest = @{ Policies = [System.Collections.Generic.List[object]]::new(); Writes = [System.Collections.Generic.List[string]]::new() }
        foreach ($p in $Policies) { $global:CaTest.Policies.Add($p) }
        Mock Write-Host {}
        Mock Out-Host {}
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:CaTest
            if ("$Uri" -match "groups\?.*mailNickname(%20| )eq(%20| )(%27|')(?<n>[^%']+)(%27|')") {
                $ids = @{ 'ca005-pilot-compliantdevice' = 'g-pilot'; 'break-glass-admins' = 'g-bg' }
                return @{ value = @(if ($ids.ContainsKey($Matches.n)) { @{ id = $ids[$Matches.n] } }) }
            }
            if ($Method -eq 'GET' -and $Uri -match '/conditionalAccess/policies$') { return @{ value = @($t.Policies) } }
            if ($Method -eq 'POST' -and $Uri -match '/conditionalAccess/policies$') {
                $b = $Body | ConvertFrom-Json -AsHashtable; $b['id'] = "p-$($t.Policies.Count + 1)"; $t.Policies.Add($b); $t.Writes.Add("POST $($b['displayName'])"); return $b
            }
            if ($Method -eq 'PATCH' -and $Uri -match '/conditionalAccess/policies/(?<id>[^/]+)$') {
                $b = $Body | ConvertFrom-Json -AsHashtable; $id = $Matches.id
                $p = @($t.Policies | Where-Object { $_['id'] -eq $id })[0]
                foreach ($k in $b.Keys) { $p[$k] = $b[$k] }
                $t.Writes.Add("PATCH $id"); return $null
            }
            throw "unexpected Graph call in test: $Method $Uri"
        }
    }

    function New-CaPolicy([string]$Id, [string]$Name, [string[]]$Exclude = @('g-bg'), [string]$State = 'enabledForReportingButNotEnforced') {
        return @{ id = $Id; displayName = $Name; state = $State
            conditions = @{ clientAppTypes = @('all'); applications = @{ includeApplications = @('All') }; users = @{ includeUsers = @('All'); excludeGroups = $Exclude } }
            grantControls = @{ operator = 'OR'; builtInControls = @('mfa') }; sessionControls = $null }
    }
}

AfterAll { Remove-Variable -Name CaTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Set-TokenProtectionPolicy.ps1' {
    It 'plan mode writes nothing' {
        Set-CaMocks
        & $script:Tp
        $global:CaTest.Writes.Count | Should -Be 0
    }

    It '-Apply creates CA011 report-only: pilot group, break-glass excluded, Windows desktop apps, EXO/SPO/Teams, secureSignInSession' {
        Set-CaMocks
        & $script:Tp -Apply -Confirm:$false
        $p = @($global:CaTest.Policies)[0]
        $p['displayName'] | Should -Be 'CA011 - Token protection (sign-in session) - pilot (report-only)'
        $p['state'] | Should -Be 'enabledForReportingButNotEnforced'
        @($p['conditions']['users']['includeGroups']) | Should -Be @('g-pilot')
        @($p['conditions']['users']['excludeGroups']) | Should -Be @('g-bg')
        @($p['conditions']['platforms']['includePlatforms']) | Should -Be @('windows')
        @($p['conditions']['clientAppTypes']) | Should -Be @('mobileAppsAndDesktopClients')
        @($p['conditions']['applications']['includeApplications']) | Should -Contain '00000002-0000-0ff1-ce00-000000000000'
        $p['sessionControls']['secureSignInSession']['isEnabled'] | Should -BeTrue
        # Converged: a second run writes nothing.
        $before = $global:CaTest.Writes.Count
        & $script:Tp -Apply -Confirm:$false
        $global:CaTest.Writes.Count | Should -Be $before
    }

    It 'never touches the Terraform-managed CA010 (device-code block): creates CA011 beside it' {
        # The collision this script once had: matching "CA010 - " would have
        # PATCHed the device-code block into a token-protection policy.
        $block = New-CaPolicy 'p-tf-ca010' 'CA010 - Block device code flow for all users'
        $block['grantControls'] = @{ operator = 'OR'; builtInControls = @('block') }
        Set-CaMocks -Policies @($block)
        & $script:Tp -Apply -Confirm:$false
        @($global:CaTest.Writes) | Should -Be @('POST CA011 - Token protection (sign-in session) - pilot (report-only)')
        $kept = @($global:CaTest.Policies | Where-Object { $_['id'] -eq 'p-tf-ca010' })[0]
        $kept['displayName'] | Should -Be 'CA010 - Block device code flow for all users'
        @($kept['grantControls']['builtInControls']) | Should -Be @('block')
    }

    It 'refuses (exit 1, no write) a CA011 that is not its token-protection policy' {
        Set-CaMocks -Policies @((New-CaPolicy 'p-other' 'CA011 - Something else'))
        $global:LASTEXITCODE = 0
        & $script:Tp -Apply -Confirm:$false
        $LASTEXITCODE | Should -Be 1
        $global:CaTest.Writes.Count | Should -Be 0
        @($global:CaTest.Policies)[0]['displayName'] | Should -Be 'CA011 - Something else'
    }

    It 'refuses to enforce without the second key' {
        Set-CaMocks
        { & $script:Tp -Apply -State enabled -Confirm:$false } | Should -Throw '*-AllowEnforce*'
        $global:CaTest.Writes.Count | Should -Be 0
    }
}

Describe 'Invoke-CaRestoreDrill.ps1' {
    It 'Snapshot writes the policies with a SHA-256 sidecar; Compare finds weakened exclusions and a deleted policy' {
        Set-CaMocks -Policies @((New-CaPolicy 'p1' 'CA004 - Block sign-in from blocked countries'), (New-CaPolicy 'p2' 'CA001 - Require MFA for all users'))
        $snap = & $script:Drill -Mode Snapshot -OutDir $TestDrive
        $snap.Path | Should -Exist
        "$($snap.Path).sha256" | Should -Exist
        # Drill: someone adds an exclusion to CA004 and deletes CA001.
        @($global:CaTest.Policies | Where-Object { $_['id'] -eq 'p1' })[0]['conditions']['users']['excludeGroups'] = @('g-bg', 'g-attacker')
        [void]$global:CaTest.Policies.Remove(@($global:CaTest.Policies | Where-Object { $_['id'] -eq 'p2' })[0])
        $rows = @(& $script:Drill -Mode Compare -SnapshotPath $snap.Path)
        ($rows | Where-Object Policy -EQ 'CA004 - Block sign-in from blocked countries').Status | Should -Be 'DRIFT'
        ($rows | Where-Object Policy -EQ 'CA004 - Block sign-in from blocked countries').Fields | Should -Be 'conditions'
        ($rows | Where-Object Policy -EQ 'CA001 - Require MFA for all users').Status | Should -Be 'MISSING'
    }

    It 'Restore is plan-only without -Apply; with -Apply it PATCHes back and verifies by re-read' {
        Set-CaMocks -Policies @((New-CaPolicy 'p1' 'CA004 - Block sign-in from blocked countries'))
        $snap = & $script:Drill -Mode Snapshot -OutDir $TestDrive
        @($global:CaTest.Policies)[0]['conditions']['users']['excludeGroups'] = @('g-bg', 'g-attacker')
        & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -OutDir $TestDrive
        $global:CaTest.Writes.Count | Should -Be 0
        $r = & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply -Confirm:$false -OutDir $TestDrive
        $r.Verified | Should -BeTrue
        $r.Action | Should -Be 'PATCH'
        @(@($global:CaTest.Policies)[0]['conditions']['users']['excludeGroups']) | Should -Be @('g-bg')
        # The record is written next to the snapshots, without ids.
        $rec = @(Get-ChildItem -LiteralPath $TestDrive -Filter 'ca-restore-*.json')
        $rec.Count | Should -Be 1
        (Get-Content -LiteralPath $rec[0].FullName -Raw) | Should -Not -Match 'p1|g-bg'
    }

    It 'refuses (nothing written) to restore a snapshot body that does not exclude break-glass' {
        Set-CaMocks -Policies @((New-CaPolicy 'p1' 'CA004 - Block sign-in from blocked countries' -Exclude @()))
        $snap = & $script:Drill -Mode Snapshot -OutDir $TestDrive
        @($global:CaTest.Policies)[0]['state'] = 'disabled'
        { & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply -Confirm:$false -OutDir $TestDrive } | Should -Throw '*does not exclude Break-Glass-Admins*'
        $global:CaTest.Writes.Count | Should -Be 0
    }

    It 'refuses a snapshot without its .sha256 sidecar' {
        Set-CaMocks -Policies @((New-CaPolicy 'p1' 'CA004 - Block sign-in from blocked countries'))
        $snap = & $script:Drill -Mode Snapshot -OutDir $TestDrive
        Remove-Item -LiteralPath "$($snap.Path).sha256"
        { & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply -Confirm:$false -OutDir $TestDrive } | Should -Throw '*no .sha256 sidecar*'
        $global:CaTest.Writes.Count | Should -Be 0
    }

    It 're-creating a deleted ENFORCED policy needs -AllowEnabledRecreate' {
        Set-CaMocks -Policies @((New-CaPolicy 'p1' 'CA004 - Block sign-in from blocked countries' -State 'enabled'))
        $snap = & $script:Drill -Mode Snapshot -OutDir $TestDrive
        [void]$global:CaTest.Policies.Remove(@($global:CaTest.Policies)[0])
        { & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply -Confirm:$false -OutDir $TestDrive } | Should -Throw '*AllowEnabledRecreate*'
        $global:CaTest.Writes.Count | Should -Be 0
        $r = & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply -AllowEnabledRecreate -Confirm:$false -OutDir $TestDrive
        $r.Action | Should -Be 'POST'
        $r.Verified | Should -BeTrue
    }

    It 'refuses a snapshot that no longer matches its .sha256 (no restore from a tampered file)' {
        Set-CaMocks -Policies @((New-CaPolicy 'p1' 'CA004 - Block sign-in from blocked countries'))
        $snap = & $script:Drill -Mode Snapshot -OutDir $TestDrive
        Add-Content -LiteralPath $snap.Path -Value ' '
        { & $script:Drill -Mode Restore -SnapshotPath $snap.Path -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply -Confirm:$false } | Should -Throw '*does not match its .sha256*'
        $global:CaTest.Writes.Count | Should -Be 0
    }
}
