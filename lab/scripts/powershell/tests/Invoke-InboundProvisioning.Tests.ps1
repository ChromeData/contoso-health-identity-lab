# Pester 5 tests for ../mock-hr/Invoke-InboundProvisioning.ps1 - the HR
# mass-change guards (risk register R10: mass disable AND mass department /
# title change), the hire-date mapping every birthright rule depends on, and
# the pipeline path hr-feed.yml uses (-EmployeeId, -ResultPath, -HidePayload,
# -UseAzureCliToken). Guard and mapping runs are -WhatIf: nothing is sent, no
# Graph connection; the guards must trip BEFORE any payload anyway. The
# app-only runs answer az, Connect-MgGraph and Invoke-MgGraphRequest with mocks.

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

    It 'holds back (quarantines) the leavers of a feed that would disable more than the threshold, and says so' {
        $f = New-Feed -Leavers 12
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -QuarantinePath (Join-Path $TestDrive 'q12.json') -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*12 account*'
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

    It 'holds back a feed that moves 20 nurses to Billing (birthright access would follow), and says so' {
        $f = New-WardFeed -Moved 20
        { & $script:Inbound -CsvPath $f -StatePath $script:State -QuarantinePath (Join-Path $TestDrive 'q20.json') -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*department or job title for 20 worker(s)*'
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

Describe 'Invoke-InboundProvisioning.ps1 pipeline path (hr-feed.yml): named rows, result file, no payload echo' {
    BeforeAll {
        # Shipped-shape feed plus one demo hire and one leaver.
        $script:PipeFeed = Join-Path $TestDrive 'pipe-feed.csv'
        Set-Content -LiteralPath $script:PipeFeed -Value @(
            'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate',
            '# comment lines are stripped',
            '400100,Joan,Ferris,Information Technology,IT Director,,active,2017-05-08,',
            '400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,',
            '400105,Lee,Park,Information Technology,Service Desk Analyst,400100,leaver,2024-01-08,2026-11-01')
        $script:Sp = '11111111-1111-1111-1111-111111111111'
        $script:Job = 'API2AD.00000000000000000000000000000000.22222222-2222-2222-2222-222222222222'
    }
    BeforeEach {
        $global:InboundOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:InboundOut.Add([string]$Object) }
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        $script:Result = Join-Path $TestDrive ("result-" + [guid]::NewGuid().ToString('N') + '.json')
    }

    It '-EmployeeId sends only the named rows; -ResultPath records a dry run (ids + status, never names)' {
        & $script:Inbound -CsvPath $script:PipeFeed -StatePath (Get-StatePath) -EmployeeId 400104 -ResultPath $script:Result -WhatIf -WarningAction SilentlyContinue
        $raw = @($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n"
        $ops = @(($raw | ConvertFrom-Json -AsHashtable)['Operations'])
        $ops.Count | Should -Be 1
        $ops[0]['bulkId'] | Should -Be '400104'
        $r = Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json -AsHashtable
        $r['outcome'] | Should -Be 'dry-run'
        @($r['selected']).Count | Should -Be 1
        $r['selected'][0]['employeeId'] | Should -Be '400104'
        $r['batches'][0]['employeeIds'] | Should -Be @('400104')
        (Get-Content -LiteralPath $script:Result -Raw) | Should -Not -Match 'Rivera|Sam|sam\.rivera|2026-11-09'
    }

    It 'an -EmployeeId that is not in the feed stops the run (a typo is never "nothing to send")' {
        { & $script:Inbound -CsvPath $script:PipeFeed -StatePath (Get-StatePath) -EmployeeId 499999 -ResultPath $script:Result -WhatIf } | Should -Throw '*499999*Nothing was sent*'
        (Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json).outcome | Should -Be 'invalid'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It '-HidePayload prints no SCIM JSON (no UPN, ids or hire date in the log)' {
        & $script:Inbound -CsvPath $script:PipeFeed -StatePath (Get-StatePath) -EmployeeId 400104 -HidePayload -WhatIf -WarningAction SilentlyContinue
        $text = $global:InboundOut -join "`n"
        $text | Should -Match 'payload not printed'
        $text | Should -Not -Match 'userName|sam\.rivera|hireDate|2026-11-09|"400104"'
    }

    It 'a guard hold-back is recorded for the summary (kind, count, threshold, the held ids; the joiner still goes)' {
        # Was: the whole run refused. Now (review C2) the 11 leavers are
        # quarantined and the one joiner is still sent (here: dry run).
        $f = New-Feed -Leavers 11
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ResultPath $script:Result -QuarantinePath (Join-Path $TestDrive 'q-pipe.json') -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*'
        $r = Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json
        $r.outcome | Should -Be 'dry-run'
        $r.refusal.kind | Should -Be 'mass-disable'
        $r.refusal.count | Should -Be 11
        $r.refusal.threshold | Should -Be 10
        @($r.quarantined).Count | Should -Be 11
        @($r.batches[0].employeeIds) | Should -Be @('900001')
    }

    It 'a run where every row is held back is recorded as refused (nothing to send)' {
        $lines = @('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate')
        for ($i = 0; $i -lt 11; $i++) { $lines += "9300$('{0:d2}' -f $i),Leaver,Only$i,Nursing,Registered Nurse,200015,leaver,2020-01-01,2026-10-20" }
        $f = Join-Path $TestDrive 'only-leavers.csv'; Set-Content -LiteralPath $f -Value $lines
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ResultPath $script:Result -QuarantinePath (Join-Path $TestDrive 'q-only.json') -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Nothing was sent*Mass-change guard*'
        (Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json).outcome | Should -Be 'refused'
    }

    It 'an invalid row is recorded as invalid with its kind (bad start date)' {
        $f = Join-Path $TestDrive 'bad-date.csv'
        Set-Content -LiteralPath $f -Value @('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate', '400106,Bad,Date,Information Technology,Cloud Engineer,400100,joiner,9/11/2026,')
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ResultPath $script:Result -WhatIf } | Should -Throw '*no valid startDate*'
        $r = Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json
        $r.outcome | Should -Be 'invalid'
        $r.refusal.kind | Should -Be 'bad-start-date'
    }
}

Describe 'Invoke-InboundProvisioning.ps1 -UseAzureCliToken (app-only, GitHub OIDC)' {
    BeforeAll {
        $script:PipeFeed2 = Join-Path $TestDrive 'pipe-feed2.csv'
        Set-Content -LiteralPath $script:PipeFeed2 -Value @(
            'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate',
            '400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,')
        $script:Sp = '11111111-1111-1111-1111-111111111111'
        $script:Job = 'API2AD.00000000000000000000000000000000.22222222-2222-2222-2222-222222222222'
        $global:HrFakeToken = 'eyFAKE.token.never-printed'
    }
    BeforeEach {
        $global:InboundOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:InboundOut.Add([string]$Object) }
        Mock az { $global:LASTEXITCODE = 0; $global:HrFakeToken }
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('SynchronizationData-User.Upload.OwnedBy', 'AuditLog.Read.All'); AuthType = 'UserProvidedAccessToken' } }
        Mock Invoke-MgGraphRequest {}
        $script:Result = Join-Path $TestDrive ("result-" + [guid]::NewGuid().ToString('N') + '.json')
        $script:SavedGha = $env:GITHUB_ACTIONS
        $env:GITHUB_ACTIONS = $null
    }
    AfterEach { $env:GITHUB_ACTIONS = $script:SavedGha }

    It 'takes a Graph token from the Azure CLI, connects with it as a SecureString, and never prints it' {
        & $script:Inbound -CsvPath $script:PipeFeed2 -StatePath (Get-StatePath) -ServicePrincipalId $script:Sp -JobId $script:Job -UseAzureCliToken -HidePayload -ResultPath $script:Result -Confirm:$false -WarningAction SilentlyContinue
        Should -Invoke az -Times 1 -ParameterFilter { $args -contains 'get-access-token' -and $args -contains 'ms-graph' }
        Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter { $AccessToken -is [securestring] -and [System.Net.NetworkCredential]::new('', $AccessToken).Password -eq $global:HrFakeToken }
        Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Uri -like "*/servicePrincipals/$($script:Sp)/synchronization/jobs/$($script:Job)/bulkUpload" -and $ContentType -eq 'application/scim+json' }
        ($global:InboundOut -join "`n") | Should -Not -Match ([regex]::Escape($global:HrFakeToken))
        ($global:InboundOut -join "`n") | Should -Not -Match 'does not list'   # .OwnedBy satisfies the scope check
        $r = Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json
        $r.outcome | Should -Be 'sent'
        $r.batches[0].accepted | Should -BeTrue
        (Get-Content -LiteralPath $script:Result -Raw) | Should -Match '"sentAtUtc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"'   # raw JSON: ConvertFrom-Json re-renders dates
        $r.jobId | Should -Be $script:Job
    }

    It 'masks the token in GitHub Actions (::add-mask::) - the only place it is ever written' {
        $env:GITHUB_ACTIONS = 'true'
        & $script:Inbound -CsvPath $script:PipeFeed2 -StatePath (Get-StatePath) -ServicePrincipalId $script:Sp -JobId $script:Job -UseAzureCliToken -HidePayload -Confirm:$false -WarningAction SilentlyContinue
        $hits = @($global:InboundOut | Where-Object { $_ -match [regex]::Escape($global:HrFakeToken) })
        $hits.Count | Should -Be 1
        $hits[0] | Should -BeExactly "::add-mask::$($global:HrFakeToken)"
    }

    It 'stops before sending when the Azure CLI has no session' {
        Mock az { $global:LASTEXITCODE = 1 }
        { & $script:Inbound -CsvPath $script:PipeFeed2 -StatePath (Get-StatePath) -ServicePrincipalId $script:Sp -JobId $script:Job -UseAzureCliToken -Confirm:$false } | Should -Throw '*No Microsoft Graph token from the Azure CLI*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'a refused upload (403) is recorded with its HTTP status and the run exits 1' {
        Mock Invoke-MgGraphRequest { throw [System.Exception]::new('Response status code does not indicate success: Forbidden (403).') }
        & $script:Inbound -CsvPath $script:PipeFeed2 -StatePath (Get-StatePath) -ServicePrincipalId $script:Sp -JobId $script:Job -UseAzureCliToken -HidePayload -ResultPath $script:Result -Confirm:$false -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $r = Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json
        $r.outcome | Should -Be 'failed'
        $r.batches[0].httpStatus | Should -Be 403
        $r.batches[0].accepted | Should -BeFalse
    }
}

AfterAll { Remove-Variable -Name InboundOut, HrFakeToken -Scope Global -ErrorAction SilentlyContinue }

Describe 'Invoke-InboundProvisioning.ps1 mass-change guard at hospital scale (review C2)' {
    BeforeAll {
        function New-ScaleFeed {
            # $Staff active rows plus $Leavers leaver rows.
            param([int]$Staff, [int]$Leavers, [string]$Name = 'scale')
            $lines = [System.Collections.Generic.List[string]]::new()
            $lines.Add('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate')
            for ($i = 0; $i -lt $Staff; $i++) { $lines.Add("5$('{0:d5}' -f $i),Staff,Person$i,Nursing,Registered Nurse,200015,active,2020-01-01,") }
            for ($i = 0; $i -lt $Leavers; $i++) { $lines.Add("6$('{0:d5}' -f $i),Gone,Person$i,Nursing,Registered Nurse,200015,leaver,2020-01-01,2026-11-01") }
            $f = Join-Path $TestDrive "$Name.csv"; Set-Content -LiteralPath $f -Value $lines; return $f
        }
    }
    BeforeEach {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        $script:Q = Join-Path $TestDrive ("q-" + [guid]::NewGuid().ToString('N') + '.json')
        $script:Approved = Join-Path $TestDrive 'approved.json'
    }

    It 'a normal Monday at 2,000 staff (15 leavers) passes: 1 percent of the population is 20, over the floor of 10' {
        $f = New-ScaleFeed -Staff 2000 -Leavers 15 -Name 'monday'
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -QuarantinePath $script:Q -HidePayload -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
        Test-Path -LiteralPath $script:Q | Should -BeFalse
    }

    It 'the same 15 leavers in a 100-person feed are held back, and the quarantine file names ids only' {
        $f = New-ScaleFeed -Staff 100 -Leavers 15 -Name 'small'
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -QuarantinePath $script:Q -HidePayload -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*DISABLE 15 account*threshold 10*'
        $q = Get-Content -LiteralPath $script:Q -Raw
        @(($q | ConvertFrom-Json).rows).Count | Should -Be 15
        $q | Should -Not -Match 'Gone|Person'
    }

    It 'mean + 3 sigma of the last 30 days raises the threshold for a hospital whose normal day is about 30' {
        $h = Join-Path $TestDrive 'history.json'
        $today = [datetime]::UtcNow.Date
        $rows = for ($d = 1; $d -le 10; $d++) { [ordered]@{ date = $today.AddDays(-$d).ToString('yyyy-MM-dd'); disabling = (28 + ($d % 5)); accessChanges = 2 } }
        (ConvertTo-Json -InputObject @($rows)) | Set-Content -LiteralPath $h
        $f = New-ScaleFeed -Staff 100 -Leavers 33 -Name 'sigma'
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ChangeHistoryPath $h -QuarantinePath $script:Q -HidePayload -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
        # 80 is far outside that history: held back.
        $f2 = New-ScaleFeed -Staff 100 -Leavers 80 -Name 'sigma2'
        { & $script:Inbound -CsvPath $f2 -StatePath (Get-StatePath) -ChangeHistoryPath $h -QuarantinePath $script:Q -HidePayload -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*threeSigma*'
    }

    It 'history older than 30 days, or fewer than 7 days, does not count' {
        $h = Join-Path $TestDrive 'old-history.json'
        $rows = for ($d = 40; $d -le 50; $d++) { [ordered]@{ date = [datetime]::UtcNow.Date.AddDays(-$d).ToString('yyyy-MM-dd'); disabling = 30; accessChanges = 0 } }
        (ConvertTo-Json -InputObject @($rows)) | Set-Content -LiteralPath $h
        $f = New-ScaleFeed -Staff 100 -Leavers 33 -Name 'oldh'
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ChangeHistoryPath $h -QuarantinePath $script:Q -HidePayload -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*'
    }

    It 'many sends on one day count as ONE day: seven same-day entries never unlock the 3-sigma threshold (review of PR #229)' {
        # One approved 40-person event and six zero-change sends, all yesterday.
        $h = Join-Path $TestDrive 'sameday.json'
        $y = [datetime]::UtcNow.Date.AddDays(-1).ToString('yyyy-MM-dd')
        $rows = @([ordered]@{ date = $y; disabling = 40; accessChanges = 0 }) + @(1..6 | ForEach-Object { [ordered]@{ date = $y; disabling = 0; accessChanges = 0 } })
        (ConvertTo-Json -InputObject @($rows)) | Set-Content -LiteralPath $h
        $f = New-ScaleFeed -Staff 100 -Leavers 30 -Name 'sameday'
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ChangeHistoryPath $h -QuarantinePath $script:Q -HidePayload -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*threshold 10*'
    }

    It 'the history keeps one entry per date: a send adds to today, and dates older than 30 days are dropped' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Inbound, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-ChangeHistoryDay' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        $today = [datetime]'2026-11-06'
        $rows = @(
            @{ date = '2026-11-06'; disabling = 3; accessChanges = 1 },
            @{ date = '2026-11-05'; disabling = 2; accessChanges = 0 },
            @{ date = '2026-11-05'; disabling = 1; accessChanges = 4 },
            @{ date = '2026-09-01'; disabling = 9; accessChanges = 9 })
        $out = @(Add-ChangeHistoryDay -Rows $rows -Disabling 5 -AccessChanges 2 -Today $today)
        ($out | ForEach-Object { "$($_.date)=$($_.disabling)/$($_.accessChanges)" }) -join ' ' | Should -Be '2026-11-05=3/4 2026-11-06=8/3'
    }

    It 'a reviewed, unexpired bulk change ticket lets the event through; expired, too small or unlisted holds it back' {
        $f = New-ScaleFeed -Staff 100 -Leavers 40 -Name 'reorg'
        $exp = [datetime]::UtcNow.Date.AddDays(7).ToString('yyyy-MM-dd')
        @{ schema = 'approved-bulk-changes/1'; changes = @(
                @{ ticket = 'CHG0040021'; kind = 'disable'; maxCount = 50; expires = $exp; reason = 'test site closing' },
                @{ ticket = 'CHG0040022'; kind = 'disable'; maxCount = 50; expires = '2020-01-01'; reason = 'expired' },
                @{ ticket = 'CHG0040023'; kind = 'disable'; maxCount = 5; expires = $exp; reason = 'too small' },
                @{ ticket = 'CHG0040024'; kind = 'access-change'; maxCount = 50; expires = $exp; reason = 'wrong kind' }) } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:Approved
        $common = @{ CsvPath = $f; QuarantinePath = $script:Q; ApprovedBulkChangesPath = $script:Approved; HidePayload = $true; WhatIf = $true; WarningAction = 'SilentlyContinue' }
        { & $script:Inbound @common -StatePath (Get-StatePath) -BulkChangeTicket CHG0040021 } | Should -Not -Throw
        { & $script:Inbound @common -StatePath (Get-StatePath) -BulkChangeTicket CHG0040022 } | Should -Throw '*expired*'
        { & $script:Inbound @common -StatePath (Get-StatePath) -BulkChangeTicket CHG0040023 } | Should -Throw '*allows 5*'
        { & $script:Inbound @common -StatePath (Get-StatePath) -BulkChangeTicket CHG0040024 } | Should -Throw '*not in the reviewed list*'
        { & $script:Inbound @common -StatePath (Get-StatePath) -BulkChangeTicket CHG0049999 } | Should -Throw '*not in the reviewed list*'
    }

    It 'the shipped allow-list is empty: no ticket passes until a reviewed PR adds one' {
        $shipped = Join-Path (Split-Path -Parent $script:Inbound) 'approved-bulk-changes.json'
        @((Get-Content -LiteralPath $shipped -Raw | ConvertFrom-Json).changes).Count | Should -Be 0
    }
}

Describe 'Invoke-InboundProvisioning.ps1 UPNs: issued once, ASCII, collision-safe (review C3)' {
    BeforeEach {
        $global:InboundOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:InboundOut.Add([string]$Object) }
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        function Get-UserNames([string[]]$Lines, [string[]]$Only = @()) {
            $global:InboundOut.Clear()
            $f = Join-Path $TestDrive ("upn-" + [guid]::NewGuid().ToString('N') + '.csv')
            Set-Content -LiteralPath $f -Value $Lines -Encoding utf8NoBOM
            $p = @{ CsvPath = $f; StatePath = (Get-StatePath); UpnDomain = 'contosohealthlab.com'; WhatIf = $true; WarningAction = 'SilentlyContinue' }
            if ($Only) { $p.EmployeeId = $Only }
            & $script:Inbound @p
            $raw = @($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n"
            $m = [ordered]@{}
            foreach ($op in @(($raw | ConvertFrom-Json -AsHashtable)['Operations'])) { $m[$op['bulkId']] = $op['data']['userName'] }
            return $m
        }
        $script:H = 'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate'
    }

    It 'the second John Smith gets a suffix digit; the lower employee id keeps the plain name, whatever the row order' {
        $u = Get-UserNames @($script:H, '100500,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,', '100400,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        $u['100400'] | Should -Be 'john.smith@contosohealthlab.com'
        $u['100500'] | Should -Be 'john.smith2@contosohealthlab.com'
    }

    It 'a collision with a worker who is NOT in this run (pipeline -EmployeeId) is still seen' {
        $u = Get-UserNames @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,', '100500,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,') -Only '100500'
        $u.Keys | Should -Be @('100500')
        $u['100500'] | Should -Be 'john.smith2@contosohealthlab.com'
    }

    It "O'Brien, Jose with an accent and a double-barrelled name give plain ASCII" {
        $jose = 'Jos' + [char]0x00E9
        $u = Get-UserNames @($script:H, "100401,Siobhan,O'Brien,Nursing,Registered Nurse,200015,active,2020-01-01,", "100402,$jose,Mu$([char]0x00F1)oz,Nursing,Registered Nurse,200015,active,2020-01-01,", '100403,Mary Ann,Lloyd-Jones,Nursing,Registered Nurse,200015,active,2020-01-01,')
        $u['100401'] | Should -Be 'siobhan.obrien@contosohealthlab.com'
        $u['100402'] | Should -Be 'jose.munoz@contosohealthlab.com'
        $u['100403'] | Should -Be 'maryann.lloyd-jones@contosohealthlab.com'
    }

    It 'a name with no usable ASCII is refused, not sent as an odd UPN' {
        { Get-UserNames @($script:H, "100404,$([char]0x674E),$([char]0x660E),Nursing,Registered Nurse,200015,active,2020-01-01,") } | Should -Throw '*no usable ASCII*'
    }

    It 'a nurse who marries keeps her UPN when the feed carries the HR-issued upn column (never re-derived)' {
        $h = $script:H + ',upn'
        $u = Get-UserNames @($h, '100405,Dana,Okafor-Reid,Nursing,Registered Nurse,200015,active,2020-01-01,,dana.okafor@contosohealthlab.com')
        $u['100405'] | Should -Be 'dana.okafor@contosohealthlab.com'
    }

    It 'a upn column value that is invalid, or used twice, stops the run' {
        $h = $script:H + ',upn'
        { Get-UserNames @($h, "100406,A,B,Nursing,Registered Nurse,200015,active,2020-01-01,,o'brien@x.com") } | Should -Throw '*invalid upn*'
        { Get-UserNames @($h, '100406,A,B,Nursing,Registered Nurse,200015,active,2020-01-01,,a.b@x.com', '100407,C,D,Nursing,Registered Nurse,200015,active,2020-01-01,,a.b@x.com') } | Should -Throw '*same upn*'
    }

    It 'a derived UPN never takes a value another row already holds in the upn column' {
        $h = $script:H + ',upn'
        $u = Get-UserNames @($h, '100408,Jo,Lee,Nursing,Registered Nurse,200015,active,2020-01-01,,jo.lee@contosohealthlab.com', '100300,Jo,Lee,Nursing,Registered Nurse,200015,joiner,2026-11-09,,')
        $u['100408'] | Should -Be 'jo.lee@contosohealthlab.com'
        $u['100300'] | Should -Be 'jo.lee2@contosohealthlab.com'
    }

    It 'an issued UPN stays reserved after a name change: the second John Smith keeps john.smith2, a new hire never gets it (review of PR #229)' {
        # Last push issued 100400 -> john.smith, 100500 -> john.smith2 (in -StatePath).
        $state = Get-StatePath
        @{ '100400' = @{ dept = 'Nursing'; jobTitle = 'Registered Nurse'; upn = 'john.smith@contosohealthlab.com' }
            '100500' = @{ dept = 'Nursing'; jobTitle = 'Registered Nurse'; upn = 'john.smith2@contosohealthlab.com' } } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $state
        # 100400 married (now Jones); a third John Smith is hired.
        $f = Join-Path $TestDrive 'renamed.csv'
        Set-Content -LiteralPath $f -Value @($script:H, '100400,John,Jones,Nursing,Registered Nurse,200015,active,2020-01-01,', '100500,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,', '100600,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        $global:InboundOut.Clear()
        & $script:Inbound -CsvPath $f -StatePath $state -UpnDomain 'contosohealthlab.com' -WhatIf -WarningAction SilentlyContinue
        $m = @{}
        foreach ($op in @((((@($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n") | ConvertFrom-Json -AsHashtable)['Operations']))) { $m[$op['bulkId']] = $op['data']['userName'] }
        $m['100400'] | Should -Be 'john.smith@contosohealthlab.com'
        $m['100500'] | Should -Be 'john.smith2@contosohealthlab.com'
        $m['100600'] | Should -Be 'john.smith3@contosohealthlab.com'
    }

    It 'an issued UPN is reserved even for a worker no longer in the feed, and a row may not take another worker''s issued UPN' {
        $state = Get-StatePath
        @{ '100400' = @{ dept = 'Nursing'; jobTitle = 'Registered Nurse'; upn = 'ana.silva@contosohealthlab.com' } } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $state
        $f = Join-Path $TestDrive 'gone.csv'
        Set-Content -LiteralPath $f -Value @($script:H, '100700,Ana,Silva,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        $global:InboundOut.Clear()
        & $script:Inbound -CsvPath $f -StatePath $state -UpnDomain 'contosohealthlab.com' -WhatIf -WarningAction SilentlyContinue
        ((@($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n") | ConvertFrom-Json -AsHashtable)['Operations'][0]['data']['userName'] | Should -Be 'ana.silva2@contosohealthlab.com'
        $f2 = Join-Path $TestDrive 'steal.csv'
        Set-Content -LiteralPath $f2 -Value @(($script:H + ',upn'), '100700,Ana,Silva,Nursing,Registered Nurse,200015,joiner,2026-11-09,,ana.silva@contosohealthlab.com')
        { & $script:Inbound -CsvPath $f2 -StatePath $state -UpnDomain 'contosohealthlab.com' -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*issued to worker 100400*'
    }

    It 'the SCIM anchor is the employee id (externalId), so the engine matches on it and never on the name' {
        $f = Join-Path $TestDrive 'anchor.csv'
        Set-Content -LiteralPath $f -Value @($script:H, '100409,Ana,Silva,Nursing,Registered Nurse,200015,active,2020-01-01,')
        $global:InboundOut.Clear()
        & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -WhatIf -WarningAction SilentlyContinue
        $op = @((((@($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n") | ConvertFrom-Json -AsHashtable)['Operations']))[0]
        $op['data']['externalId'] | Should -Be '100409'
    }
}

Describe 'Rehire after a leave (review C7): the payload switches the account on in the NEW job' {
    BeforeEach {
        $global:InboundOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:InboundOut.Add([string]$Object) }
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
    }

    It 'a rehired worker (leaver -> active, different department) is sent active=true with the new department and title, same anchor and UPN' {
        $f = Join-Path $TestDrive 'rehire.csv'
        Set-Content -LiteralPath $f -Value @('employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate,upn',
            '100210,Rae,Lin,Pharmacy,Pharmacist,200015,active,2026-11-09,,rae.lin@contosohealthlab.com')
        # Baseline: she left as an ICU nurse 18 months ago.
        $state = Get-StatePath
        (@{ '100210' = @{ dept = 'ICU'; jobTitle = 'Registered Nurse' } } | ConvertTo-Json) | Set-Content -LiteralPath $state
        & $script:Inbound -CsvPath $f -StatePath $state -WhatIf -WarningAction SilentlyContinue
        $op = @((((@($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n") | ConvertFrom-Json -AsHashtable)['Operations']))[0]
        $op['data']['active'] | Should -BeTrue
        $op['data']['externalId'] | Should -Be '100210'
        $op['data']['userName'] | Should -Be 'rae.lin@contosohealthlab.com'
        $op['data']['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department'] | Should -Be 'Pharmacy'
        $op['data']['title'] | Should -Be 'Pharmacist'
        # The new start date is the hire date the birthright rules read.
        ([datetime]$op['data']['urn:ietf:params:scim:schemas:extension:contoso:1.0:User']['hireDate']).ToUniversalTime().ToString('yyyy-MM-dd') | Should -Be '2026-11-09'
    }

    It 'the OU expression the DC prints moves an active account OUT of OU=Disabled (active False -> Disabled, else the department OU), applied Always' {
        $dc = Get-Content -LiteralPath ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'dc' '02-Configure-Domain.ps1'))) -Raw
        $dc | Should -Match 'IIF\(\[active\]=`"False`", `"\$disabledOu`", Switch\(\[urn:ietf:params:scim:schemas:extension:enterprise:2\.0:User:department\]'
        $dc | Should -Match 'apply Always'
    }
}

Describe 'Issued UPNs survive between runs: rebuilt from the git history of the feed (-IssuedFromGitHistory, Greptile on PR #229)' {
    # A runner starts every run with an EMPTY -StatePath. These tests commit
    # feed versions to a throwaway git repo in TestDrive and run the sender
    # with a fresh state file each time, exactly like the runner.
    BeforeEach {
        $global:InboundOut = [System.Collections.Generic.List[string]]::new()
        Mock Write-Host { $global:InboundOut.Add([string]$Object) }
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        $script:H = 'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate'
        $script:Repo = Join-Path $TestDrive ('repo-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Repo | Out-Null
        git -C $script:Repo init -q 2>$null | Out-Null
        git -C $script:Repo config user.email 'test@example.invalid'
        git -C $script:Repo config user.name 'test'
        git -C $script:Repo config commit.gpgsign false
        $script:Feed = Join-Path $script:Repo 'hr_feed.csv'
        function Save-Version([string[]]$Lines) {
            Set-Content -LiteralPath $script:Feed -Value $Lines -Encoding utf8NoBOM
            git -C $script:Repo add hr_feed.csv
            git -C $script:Repo commit -q -m 'hr change' | Out-Null
        }
        function Get-RunnerUserNames([switch]$NoHistory) {
            $global:InboundOut.Clear()
            $p = @{ CsvPath = $script:Feed; StatePath = (Get-StatePath); UpnDomain = 'contosohealthlab.com'; WhatIf = $true; WarningAction = 'SilentlyContinue' }
            if (-not $NoHistory) { $p.IssuedFromGitHistory = $true }
            & $script:Inbound @p
            $raw = @($global:InboundOut | Where-Object { $_ -match '^\s*\{' }) -join "`n"
            $m = [ordered]@{}
            foreach ($op in @(($raw | ConvertFrom-Json -AsHashtable)['Operations'])) { $m[$op['bulkId']] = $op['data']['userName'] }
            return $m
        }
    }

    It 'without the history a restart forgets: the renamed worker''s UPN is handed to a new John Smith (the bug)' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Save-Version @($script:H, '100400,John,Jones,Nursing,Registered Nurse,200015,active,2020-01-01,', '100600,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        (Get-RunnerUserNames -NoHistory)['100600'] | Should -Be 'john.smith@contosohealthlab.com'
    }

    It 'with the history: the renamed worker keeps john.smith, the new John Smith gets john.smith2' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Save-Version @($script:H, '100400,John,Jones,Nursing,Registered Nurse,200015,active,2020-01-01,', '100600,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        $u = Get-RunnerUserNames
        $u['100400'] | Should -Be 'john.smith@contosohealthlab.com'
        $u['100600'] | Should -Be 'john.smith2@contosohealthlab.com'
    }

    It 'a UPN stays reserved after the row is removed from the file (no reuse for a new hire)' {
        Save-Version @($script:H, '100400,Ana,Silva,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Save-Version @($script:H, '100700,Ana,Silva,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        (Get-RunnerUserNames)['100700'] | Should -Be 'ana.silva2@contosohealthlab.com'
    }

    It 'the same worker keeps the same UPN across many runs and renames (stable, not re-derived)' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,', '100500,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Save-Version @($script:H, '100400,John,Jones,Nursing,Registered Nurse,200015,active,2020-01-01,', '100500,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Save-Version @($script:H, '100400,John,Jones,Nursing,Registered Nurse,200015,active,2020-01-01,', '100500,Johnny,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,', '100600,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        $a = Get-RunnerUserNames
        $b = Get-RunnerUserNames
        foreach ($u in $a, $b) {
            $u['100400'] | Should -Be 'john.smith@contosohealthlab.com'
            $u['100500'] | Should -Be 'john.smith2@contosohealthlab.com'
            $u['100600'] | Should -Be 'john.smith3@contosohealthlab.com'
        }
    }

    It 'a version the sender refused (no usable ASCII) issued nothing and is skipped' {
        Save-Version @($script:H, "100400,$([char]0x674E),$([char]0x660E),Nursing,Registered Nurse,200015,active,2020-01-01,")
        Save-Version @($script:H, '100400,Li,Ming,Nursing,Registered Nurse,200015,active,2020-01-01,')
        (Get-RunnerUserNames)['100400'] | Should -Be 'li.ming@contosohealthlab.com'
        ($global:InboundOut -join "`n") | Should -Match '1 refused version'
    }

    It 'the log shows counts only, never a UPN or an employee id' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        $null = Get-RunnerUserNames
        $line = @($global:InboundOut | Where-Object { $_ -match '^Issued UPNs' })
        $line.Count | Should -Be 1
        $line[0] | Should -Not -Match '@|100400'
    }

    It 'a shallow checkout stops the run before anything is sent (the record would be incomplete)' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Save-Version @($script:H, '100400,John,Jones,Nursing,Registered Nurse,200015,active,2020-01-01,')
        $shallow = Join-Path $TestDrive ('shallow-' + [guid]::NewGuid().ToString('N'))
        git clone -q --depth 1 "file://$($script:Repo)" $shallow 2>$null
        $result = Join-Path $TestDrive 'shallow-result.json'
        { & $script:Inbound -CsvPath (Join-Path $shallow 'hr_feed.csv') -StatePath (Get-StatePath) -UpnDomain 'contosohealthlab.com' -IssuedFromGitHistory -ResultPath $result -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*shallow*'
        (Get-Content -LiteralPath $result -Raw | ConvertFrom-Json).refusal.kind | Should -Be 'upn-history'
    }

    It 'a feed that is not committed stops the run' {
        Set-Content -LiteralPath $script:Feed -Value @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        { & $script:Inbound -CsvPath $script:Feed -StatePath (Get-StatePath) -IssuedFromGitHistory -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*not committed*'
    }

    It 'a LATER upn column value stays reserved too, after the row is gone (Greptile on PR #261)' {
        # Committed first with a derived name (never sent), then HR gave an
        # explicit upn, and that is the name the account got. Then the row went.
        Save-Version @($script:H, '100400,Kim,Park,Nursing,Registered Nurse,200015,joiner,2026-11-09,')
        Save-Version @(($script:H + ',upn'), '100400,Kim,Park,Nursing,Registered Nurse,200015,joiner,2026-11-09,,kim.park.rn@contosohealthlab.com')
        Save-Version @(($script:H + ',upn'), '100800,Kim,Park,Nursing,Registered Nurse,200015,joiner,2026-11-10,,')
        (Get-RunnerUserNames)['100800'] | Should -Be 'kim.park2@contosohealthlab.com'
        Save-Version @(($script:H + ',upn'), '100800,Kim,Park,Nursing,Registered Nurse,200015,joiner,2026-11-10,,kim.park.rn@contosohealthlab.com')
        { Get-RunnerUserNames } | Should -Throw '*issued to worker 100400*'
    }

    It 'a feed with UNSTAGED edits stops the run: only committed versions are in the record (Greptile on PR #261)' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Add-Content -LiteralPath $script:Feed -Value '100600,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,'
        { Get-RunnerUserNames } | Should -Throw '*differs from the last commit*'
    }

    It 'a feed with STAGED edits stops the run too' {
        Save-Version @($script:H, '100400,John,Smith,Nursing,Registered Nurse,200015,active,2020-01-01,')
        Add-Content -LiteralPath $script:Feed -Value '100600,John,Smith,Nursing,Registered Nurse,200015,joiner,2026-11-09,'
        git -C $script:Repo add hr_feed.csv
        { Get-RunnerUserNames } | Should -Throw '*differs from the last commit*'
    }

    It 'hr-feed.yml sends with -IssuedFromGitHistory and checks out the full history' {
        $wf = Get-Content -Raw -LiteralPath ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' '..' '.github' 'workflows' 'hr-feed.yml')))
        $wf | Should -Match 'IssuedFromGitHistory = \$true'
        $wf | Should -Match 'fetch-depth: 0'
    }
}
