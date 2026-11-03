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

    It 'a guard refusal is recorded for the summary (outcome refused, kind, count)' {
        $f = New-Feed -Leavers 11
        { & $script:Inbound -CsvPath $f -StatePath (Get-StatePath) -ResultPath $script:Result -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*Mass-change guard*'
        $r = Get-Content -LiteralPath $script:Result -Raw | ConvertFrom-Json
        $r.outcome | Should -Be 'refused'
        $r.refusal.kind | Should -Be 'mass-disable'
        $r.refusal.count | Should -Be 11
        $r.refusal.threshold | Should -Be 10
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
