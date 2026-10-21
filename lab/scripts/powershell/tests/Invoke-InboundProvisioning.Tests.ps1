# Pester 5 tests for ../mock-hr/Invoke-InboundProvisioning.ps1 - the HR
# mass-change guards (risk register R10: mass disable AND mass department /
# title change) and the hire-date mapping every birthright rule depends on.
# Every run is -WhatIf: nothing is sent, no Graph connection; the guards must
# trip BEFORE any payload anyway.

BeforeAll {
    $script:Inbound = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'mock-hr' 'Invoke-InboundProvisioning.ps1'))

    function New-Feed {
        # A synthetic feed: $Leavers rows with status=leaver, one joiner.
        param([int]$Leavers)
        $lines = @('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate',
            '900001,Test,Joiner,Nursing,Registered Nurse,200015,joiner,2026-10-19,')
        for ($i = 0; $i -lt $Leavers; $i++) { $lines += "9100$('{0:d2}' -f $i),Leaver,Person$i,Nursing,Registered Nurse,200015,leaver,2020-01-01,2026-10-20" }
        $f = Join-Path $TestDrive "feed-$Leavers.csv"
        Set-Content -LiteralPath $f -Value $lines
        return $f
    }
    # Hermetic baseline path per test (never the real .state/ folder).
    function Get-StatePath { Join-Path $TestDrive ("state-" + [guid]::NewGuid().ToString('N') + '.json') }
}

Describe 'Invoke-InboundProvisioning.ps1 mass-change guard' {
    BeforeEach {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
    }

    It 'refuses a feed that would disable more accounts than -MaxChanges, before sending anything' {
        $f = New-Feed -Leavers 12
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*12 account*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'lets a normal day through (leavers at or under the threshold)' {
        $f = New-Feed -Leavers 3
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It '-Force overrides a reviewed bulk change (and warns), -MaxChanges is tunable' {
        $f = New-Feed -Leavers 12
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -Force -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -MaxChanges 20 -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
    }
}

Describe 'Invoke-InboundProvisioning.ps1 department / job title mass-change guard' {
    BeforeEach {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        # Last pushed roster: 25 nurses on the ward.
        $script:State = Join-Path $TestDrive 'last-pushed.json'
        $b = [ordered]@{}; for ($i = 0; $i -lt 25; $i++) { $b["92$('{0:d4}' -f $i)"] = @{ dept = 'Nursing'; jobTitle = 'Registered Nurse' } }
        ($b | ConvertTo-Json) | Set-Content -LiteralPath $script:State
        function New-WardFeed([int]$Moved, [string]$To = 'Billing') {
            $lines = @('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate')
            for ($i = 0; $i -lt 25; $i++) { $d = if ($i -lt $Moved) { $To } else { 'Nursing' }; $lines += "92$('{0:d4}' -f $i),Nurse,Person$i,$d,Registered Nurse,200015,active,2020-01-01," }
            $f = Join-Path $TestDrive "ward-$Moved.csv"; Set-Content -LiteralPath $f -Value $lines; return $f
        }
    }

    It 'refuses a feed that moves 20 nurses to Billing (birthright access would follow), before sending anything' {
        $f = New-WardFeed -Moved 20
        { & $script:Inbound -CsvPath $f -StatePath $script:State -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*department or job title for 20 worker(s)*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'lets a normal day through (a couple of transfers) and -Force overrides a reviewed reorganisation' {
        { & $script:Inbound -CsvPath (New-WardFeed -Moved 2 -To 'ICU') -StatePath $script:State -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
        { & $script:Inbound -CsvPath (New-WardFeed -Moved 20) -StatePath $script:State -Force -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'never moves the baseline under -WhatIf' {
        $before = Get-FileHash -LiteralPath $script:State
        & $script:Inbound -CsvPath (New-WardFeed -Moved 2 -To 'ICU') -StatePath $script:State -WhatIf -WarningAction SilentlyContinue
        (Get-FileHash -LiteralPath $script:State).Hash | Should -Be $before.Hash
    }
}

Describe 'Invoke-InboundProvisioning.ps1 hire date -> employeeHireDate' {
    BeforeEach {
        $global:InboundOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:InboundOut.Add([string]$Object) }
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
    }

    It 'sends every joiner and active row''s startDate as the custom SCIM extension hireDate (shipped feed)' {
        $feed = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'mock-hr' 'hr_feed.csv'))
        & $script:Inbound -CsvPath $feed -StatePath (Join-Path $TestDrive 'none.json') -WhatIf -WarningAction SilentlyContinue
        $raw = @($global:InboundOut | Where-Object { $_ -match '^\s*\{' })
        $ops = @($raw | ForEach-Object { ($_ | ConvertFrom-Json -AsHashtable)['Operations'] } | ForEach-Object { $_ })
        $ops.Count | Should -BeGreaterThan 0
        $ext = 'urn:ietf:params:scim:schemas:extension:contoso:1.0:User'
        $activeOps = @($ops | Where-Object { $_['data']['active'] })
        foreach ($op in $activeOps) {
            $op['data']['schemas'] | Should -Contain $ext
            $op['data'][$ext]['hireDate'] | Should -Not -BeNullOrEmpty
        }
        # The wire format, checked on the raw JSON (ConvertFrom-Json would
        # re-render the date): ISO-8601 UTC midnight, one per row (every row has a startDate).
        $text = $raw -join "`n"
        ([regex]::Matches($text, '"hireDate":\s*"\d{4}-\d{2}-\d{2}T00:00:00Z"')).Count | Should -Be $ops.Count   # leavers keep theirs too
        $text | Should -Match '"bulkId":\s*"100492"[\s\S]*?"hireDate":\s*"2026-10-19T00:00:00Z"'   # Dana, joiner
    }

    It 'refuses a joiner without a valid startDate (it would match no birthright rule)' {
        $f = Join-Path $TestDrive 'nostart.csv'
        Set-Content -LiteralPath $f -Value @('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate', '900002,No,Start,Nursing,Registered Nurse,200015,joiner,19/10/2026,')
        { & $script:Inbound -CsvPath $f -StatePath (Join-Path $TestDrive 'none.json') -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*no valid startDate*employeeHireDate*'
    }
}

AfterAll { Remove-Variable -Name InboundOut -Scope Global -ErrorAction SilentlyContinue }
