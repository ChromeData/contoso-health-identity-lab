# Pester 5 tests for the hr-feed.yml pipeline scripts in ../mock-hr:
#   Get-HrFeedChange.ps1     the diff in HR words (hired / left / moved /
#                            rehired / updated / removed), the access-change
#                            baseline it hands the mass-change guard;
#   Write-HrFeedSummary.ps1  the plain-English run summary, the bounded wait
#                            on the provisioning log (mocked Graph): only
#                            entries from THIS send confirm a person; and the
#                            privacy rule: names, job title and department
#                            only - never an employee id, UPN, date, manager.
# End to end: diff -> Invoke-InboundProvisioning.ps1 -WhatIf -> summary.
# hr-feed.yml's "Read the HR change" step, run as written in the workflow
# against a throwaway repo: which commit a push is compared with, so a
# failed push is never skipped and an unreadable run history stops it.
# No tenant: Invoke-MgGraphRequest and Get-MgContext are mocks, Start-Sleep
# is a no-op; `gh` is a stub on PATH.

BeforeDiscovery {
    # The workflow-step block reads the step out of hr-feed.yml (python3 +
    # PyYAML; lab-tests.yml installs python3-yaml), builds a git repo and
    # puts a POSIX-shell `gh` stub on PATH. Without them it is SKIPPED, not
    # passed.
    $script:CanRunStep = $false
    if (-not $IsWindows -and (Get-Command git -ErrorAction SilentlyContinue) -and (Get-Command python3 -ErrorAction SilentlyContinue)) {
        & python3 -c 'import yaml' 2>$null
        $script:CanRunStep = ($LASTEXITCODE -eq 0)
    }
}

BeforeAll {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop   # mocks copy the real cmdlet signatures
    $script:HrDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'mock-hr'))
    $script:Change = Join-Path $script:HrDir 'Get-HrFeedChange.ps1'
    $script:Summary = Join-Path $script:HrDir 'Write-HrFeedSummary.ps1'
    $script:Inbound = Join-Path $script:HrDir 'Invoke-InboundProvisioning.ps1'
    $script:D = [string][char]0x2014   # em dash (the file stays ASCII)
    $script:A = [string][char]0x2192   # arrow
    $script:Header = 'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate'
    $script:Base = @(
        '# a comment line',
        '400100,Joan,Ferris,Information Technology,IT Director,,active,2017-05-08,',
        '100310,Marcus,Bello,Nursing,Registered Nurse,200015,active,2022-01-10,',
        '100205,Priya,Nair,Billing,Billing Specialist,200030,leaver,2021-09-01,2026-10-17',
        '400103,Mei,Tanaka,Information Technology,Access Governance Lead,400100,active,2020-09-14,')
    function New-HrCsv {
        param([string[]]$Rows)
        $f = Join-Path $TestDrive ("feed-" + [guid]::NewGuid().ToString('N') + '.csv')
        Set-Content -LiteralPath $f -Value (@($script:Header) + $Rows)
        return $f
    }
    $script:Sp = '11111111-1111-1111-1111-111111111111'
    $script:AppId = '22222222-2222-2222-2222-222222222222'
    $script:Job = "API2AD.00000000000000000000000000000000.$($script:AppId)"
    function New-SentResult {
        # What Invoke-InboundProvisioning.ps1 -ResultPath writes after a send.
        param([string[]]$Ids, [string]$Outcome = 'sent', [int]$Http = 202, [bool]$Accepted = $true, [string]$SentAt = '2026-11-09T15:00:00Z', $Refusal = $null)
        $f = Join-Path $TestDrive ("sent-" + [guid]::NewGuid().ToString('N') + '.json')
        [ordered]@{
            schema = 'hr-feed-send/1'; outcome = $Outcome; refusal = $Refusal; jobId = $script:Job; servicePrincipalId = $script:Sp
            selected = @($Ids | ForEach-Object { @{ employeeId = $_; status = 'joiner' } }); sentAtUtc = $SentAt
            batches = @(if ($Ids) { [ordered]@{ index = 1; records = $Ids.Count; employeeIds = $Ids; httpStatus = $Http; accepted = $Accepted } })
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $f
        return $f
    }
    function New-ChangesFile {
        param([object[]]$Changes)
        $f = Join-Path $TestDrive ("changes-" + [guid]::NewGuid().ToString('N') + '.json')
        ConvertTo-Json -InputObject @($Changes) -Depth 5 | Set-Content -LiteralPath $f
        return $f
    }
    function New-LogEntry {
        param([string]$Id, [string]$Action = 'create', [string]$Status = 'success', [string]$When = '2026-11-09T15:01:00Z', [string]$ErrorCode = '')
        # Called from inside Invoke-MgGraphRequest mocks: no $script: state here.
        @{ id = [guid]::NewGuid().ToString(); activityDateTime = $When; provisioningAction = $Action
            sourceIdentity = @{ id = $Id; displayName = 'x' }
            provisioningStatusInfo = @{ status = $Status; errorInformation = $(if ($ErrorCode) { @{ errorCode = $ErrorCode; reason = 'CN=Sam Rivera,OU=Information Technology,OU=Workforce,DC=corp sam.rivera@contosohealthlab.com' } } else { $null }) } }
    }
    $script:Sam = [ordered]@{ employeeId = '400104'; kind = 'hired'; send = $true; givenName = 'Sam'; surname = 'Rivera'; dept = 'Information Technology'; jobTitle = 'Cloud Engineer'; status = 'joiner'; previous = $null; changedFields = @() }
}

Describe 'Get-HrFeedChange.ps1: the change in HR words' {
    It 'names a new hire, a leaver, a mover, a return and a removed row; comments and order do not count' {
        $prev = New-HrCsv $script:Base
        $cur = New-HrCsv @(
            '400103,Mei,Tanaka,Information Technology,Access Governance Lead,400100,active,2020-09-14,',   # moved up, unchanged
            '# a different comment',
            '400100,Joan,Ferris,Information Technology,IT Director,,leaver,2017-05-08,2026-11-30',        # left
            '100310,Marcus,Bello,ICU,Registered Nurse,200015,active,2022-01-10,',                         # moved
            '100205,Priya,Nair,Billing,Billing Specialist,200030,active,2021-09-01,',                     # back
            '400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,')         # hired
        $c = @(& $script:Change -CsvPath $cur -PreviousCsvPath $prev)
        ($c | ForEach-Object { "$($_.employeeId)=$($_.kind)" }) -join ' ' | Should -Be '400100=left 100310=moved 100205=rehired 400104=hired'
        ($c | Where-Object employeeId -EQ '100310').previous.dept | Should -Be 'Nursing'
        @($c | Where-Object { -not $_.send }).Count | Should -Be 0
    }

    It 'a deleted row is "removed" and never sent (HR marks leavers, it does not delete them)' {
        $prev = New-HrCsv ($script:Base + '400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,leaver,2026-11-09,2026-11-20')
        $c = @(& $script:Change -CsvPath (New-HrCsv $script:Base) -PreviousCsvPath $prev)
        $c.Count | Should -Be 1
        $c[0].kind | Should -Be 'removed'
        $c[0].send | Should -BeFalse
        $c[0].givenName | Should -Be 'Sam'
    }

    It 'a manager or name change is "updated"; an unchanged file is no change at all' {
        $cur = New-HrCsv ($script:Base -replace '^400103,Mei,Tanaka,(.*),400100,', '400103,Mei,Tanaka,$1,400101,')
        $c = @(& $script:Change -CsvPath $cur -PreviousCsvPath (New-HrCsv $script:Base))
        $c.kind | Should -Be 'updated'
        $c.changedFields | Should -Be @('manager')
        @(& $script:Change -CsvPath (New-HrCsv $script:Base) -PreviousCsvPath (New-HrCsv $script:Base)).Count | Should -Be 0
    }

    It 'refuses a file with the same employeeId twice' {
        $cur = New-HrCsv ($script:Base + '400100,Joan,Ferris,Information Technology,IT Director,,active,2017-05-08,')
        { & $script:Change -CsvPath $cur } | Should -Throw '*400100 appears more than once*'
    }

    It '-EmployeeId lists exactly those rows (diff kind when changed, status kind otherwise); unknown ids stop' {
        $prev = New-HrCsv $script:Base
        $cur = New-HrCsv ($script:Base -replace '^100310,Marcus,Bello,Nursing', '100310,Marcus,Bello,ICU')
        $c = @(& $script:Change -CsvPath $cur -PreviousCsvPath $prev -EmployeeId 100310, 100205)
        ($c | ForEach-Object { "$($_.employeeId)=$($_.kind)" }) -join ' ' | Should -Be '100310=moved 100205=left'
        { & $script:Change -CsvPath $cur -EmployeeId 499999 } | Should -Throw '*499999*'
    }

    It 'a push that only corrects the upn column is a change and is sent (review of PR #229)' {
        $h = $script:Header + ',upn'
        $prev = Join-Path $TestDrive 'upn-prev.csv'; $cur = Join-Path $TestDrive 'upn-cur.csv'
        Set-Content -LiteralPath $prev -Value @($h, '100310,Marcus,Bello,Nursing,Registered Nurse,200015,active,2022-01-10,,marcus.bello@contosohealthlab.com')
        Set-Content -LiteralPath $cur -Value @($h, '100310,Marcus,Bello,Nursing,Registered Nurse,200015,active,2022-01-10,,marcus.bello2@contosohealthlab.com')
        $state = Join-Path $TestDrive 'upn-baseline.json'
        $c = @(& $script:Change -CsvPath $cur -PreviousCsvPath $prev -BaselineStatePath $state)
        $c.Count | Should -Be 1
        $c[0].kind | Should -Be 'updated'
        $c[0].send | Should -BeTrue
        $c[0].changedFields | Should -Be @('upn')
        # The previous file's issued upn goes into the baseline (reserved for that worker).
        (Get-Content -LiteralPath $state -Raw | ConvertFrom-Json -AsHashtable)['100310']['upn'] | Should -Be 'marcus.bello@contosohealthlab.com'
    }

    It 'writes the previous version as the access-change baseline Invoke-InboundProvisioning reads (-StatePath)' {
        # 11 moves in one push: the guard must see them against the PREVIOUS file.
        $rows = 0..10 | ForEach-Object { "92{0:d4},Nurse,P$_,Nursing,Registered Nurse,200015,active,2020-01-01," -f $_ }
        $prev = New-HrCsv $rows
        $cur = New-HrCsv ($rows -replace ',Nursing,', ',Billing,')
        $state = Join-Path $TestDrive 'baseline.json'
        $c = @(& $script:Change -CsvPath $cur -PreviousCsvPath $prev -BaselineStatePath $state)
        @($c | Where-Object kind -EQ 'moved').Count | Should -Be 11
        (Get-Content -LiteralPath $state -Raw | ConvertFrom-Json -AsHashtable)['920000']['dept'] | Should -Be 'Nursing'
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        { & $script:Inbound -CsvPath $cur -EmployeeId @($c.employeeId) -StatePath $state -WhatIf -WarningAction SilentlyContinue } | Should -Throw '*department or job title for 11 worker(s)*'
    }
}

Describe 'Write-HrFeedSummary.ps1: the plain-English story' {
    BeforeEach {
        Mock Write-Host {}
        Mock Start-Sleep {}
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('AuditLog.Read.All'); AuthType = 'UserProvidedAccessToken' } }
        Mock Invoke-MgGraphRequest { @{ value = @() } }
        $script:Md = Join-Path $TestDrive ("summary-" + [guid]::NewGuid().ToString('N') + '.md')
    }

    It 'a confirmed hire reads like the story, with the next step, the Entra link and folded details' {
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -Action 'create')) } } -ParameterFilter { $Uri -like '*auditLogs/provisioning*' }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0 -SignInOutcome success
        $LASTEXITCODE | Should -Be 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match '(?m)^## HR change sent to Microsoft$'
        $md | Should -Match ([regex]::Escape("- **Hired:** Sam Rivera, Cloud Engineer (Information Technology) $($script:D) account created in Active Directory"))
        $md | Should -Match '\*\*Next:\*\* Cloud Sync copies the change from Active Directory to Entra ID'
        $md | Should -Match 'AWS follows by SCIM'
        $md | Should -Match ([regex]::Escape("ManagedAppMenuBlade/~/ProvisioningManagement/appId/$($script:AppId)/objectId/$($script:Sp)"))
        $md | Should -Match '<details><summary>Technical details</summary>'
        Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter { $Method -eq 'GET' -and [uri]::UnescapeDataString($Uri) -like "*jobid eq '$($script:Job)' and sourceIdentity/id eq '400104'*" }
    }

    It 'never prints an employee id, UPN, date, manager or a provisioning error''s free text' {
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -Action 'create' -Status 'failure' -ErrorCode 'AdDuplicateUpn')) } }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0 -TriggerText 'push to hr-feed'
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Not -Match '400104|400100|sam\.rivera|@contosohealthlab|2026-11-09|CN=|OU=Workforce'
        $md | Should -Match 'Microsoft could not apply it \(error AdDuplicateUpn\)'
    }

    It 'a failure in the provisioning log fails the step (exit 1); a leaver success reads "account switched off"' {
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -Status 'failure' -ErrorCode 'X')) } }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0
        $LASTEXITCODE | Should -Be 1
        $left = [ordered]@{} + $script:Sam; $left['kind'] = 'left'; $left['status'] = 'leaver'
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -Action 'update')) } }
        & $script:Summary -ChangesPath (New-ChangesFile @($left)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0
        $LASTEXITCODE | Should -Be 0
        (Get-Content -LiteralPath $script:Md -Raw) | Should -Match ([regex]::Escape("- **Left:** Sam Rivera, Cloud Engineer (Information Technology) $($script:D) account switched off"))
    }

    It 'no log entry within the wait is "not logged yet", never a failure; entries older than the send are ignored' {
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -When '2026-11-09T14:00:00Z')) } }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0
        $LASTEXITCODE | Should -Be 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match 'sent; Microsoft has not logged it yet \(its log can lag a few minutes\)'
        $md | Should -Match '1 not logged yet after'
    }

    It 'an entry from before the send (last push''s hire) never confirms this departure; polling goes on until its own entry' {
        # Sam's hire was logged 30 s before his departure was sent: inside the
        # old two-minute look-back, where it read "account switched off" while
        # the account was still enabled.
        $left = [ordered]@{} + $script:Sam; $left['kind'] = 'left'; $left['status'] = 'leaver'
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -Action 'create' -When '2026-11-09T14:59:30Z')) } }
        & $script:Summary -ChangesPath (New-ChangesFile @($left)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0
        $LASTEXITCODE | Should -Be 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Not -Match 'account switched off'
        $md | Should -Match ([regex]::Escape("- **Left:** Sam Rivera, Cloud Engineer (Information Technology) $($script:D) sent; Microsoft has not logged it yet"))
        # Polling: the old hire answers twice, then the departure's own entry
        # (a failure) arrives. Only that entry decides; the old success, which
        # would have outranked it, does not count.
        Remove-Item -LiteralPath $script:Md
        $global:HrPolls = 0
        Mock Invoke-MgGraphRequest {
            $global:HrPolls++
            $hire = New-LogEntry -Id '400104' -Action 'create' -When '2026-11-09T14:59:30Z'
            if ($global:HrPolls -lt 3) { @{ value = @($hire) } }
            else { @{ value = @((New-LogEntry -Id '400104' -Action 'disable' -Status 'failure' -ErrorCode 'AdAccountLocked' -When '2026-11-09T15:00:40Z'), $hire) } }
        }
        & $script:Summary -ChangesPath (New-ChangesFile @($left)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 120 -PollSeconds 1
        $global:HrPolls | Should -Be 3
        $LASTEXITCODE | Should -Be 1
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match 'Microsoft could not apply it \(error AdAccountLocked\)'
        $md | Should -Not -Match 'account switched off'
        Remove-Variable -Name HrPolls -Scope Global
    }

    It 'allows 5 s of clock skew before the send and no more; an entry with no time never confirms' {
        $cases = @(
            @{ When = '2026-11-09T14:59:55Z'; Expect = 'account created in Active Directory' }   # 5 s early: clock skew
            @{ When = '2026-11-09T14:59:54Z'; Expect = 'sent; Microsoft has not logged it yet' } # 6 s early: an earlier send
            @{ When = ''; Expect = 'sent; Microsoft has not logged it yet' })                     # no time: cannot be shown to be this send's
        foreach ($c in $cases) {
            $global:HrWhen = $c.When
            Mock Invoke-MgGraphRequest { $e = New-LogEntry -Id '400104' -When $global:HrWhen; if (-not $global:HrWhen) { $e.Remove('activityDateTime') }; @{ value = @($e) } }
            $md = Join-Path $TestDrive ("skew-" + [guid]::NewGuid().ToString('N') + '.md')
            & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $md -WaitSeconds 0
            (Get-Content -LiteralPath $md -Raw) | Should -Match ([regex]::Escape("$($script:D) $($c.Expect)")) -Because "an entry at '$($c.When)' for a send at 15:00:00"
        }
        Remove-Variable -Name HrWhen -Scope Global
    }

    It 'a send result without a send time is not matched against the log at all (no guessed window)' {
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104')) } }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104' -SentAt '') -SummaryPath $script:Md -WaitSeconds 0
        $LASTEXITCODE | Should -Be 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match 'sent; the result could not be read from the provisioning log'
        $md | Should -Match 'the send result has no send time'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'polls until the log answers, within the bound' {
        $global:HrPolls = 0
        Mock Invoke-MgGraphRequest { $global:HrPolls++; if ($global:HrPolls -lt 3) { @{ value = @() } } else { @{ value = @((New-LogEntry -Id '400104')) } } }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 120 -PollSeconds 1
        $global:HrPolls | Should -Be 3
        (Get-Content -LiteralPath $script:Md -Raw) | Should -Match 'account created in Active Directory'
        Remove-Variable -Name HrPolls -Scope Global
    }

    It 'a 403 on the log read says the role is missing, and the run still succeeds' {
        Mock Invoke-MgGraphRequest { throw [System.Exception]::new('Response status code does not indicate success: Forbidden (403). Authorization_RequestDenied') }
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath (New-SentResult -Ids '400104') -SummaryPath $script:Md -WaitSeconds 0 -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match 'HR-SYNC has no provisioning-log read role yet'
        $md | Should -Match 'sent; the result could not be read'
    }

    It 'explains a safety-check stop, an invalid file, a refused upload, missing setup and a failed sign-in' {
        $changes = New-ChangesFile @($script:Sam)
        & $script:Summary -ChangesPath $changes -ResultPath (New-SentResult -Ids @() -Outcome 'refused' -Refusal @{ kind = 'mass-disable'; count = 12; threshold = 10 }) -SummaryPath $script:Md -WaitSeconds 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match '## HR change stopped by the safety check'
        $md | Should -Match 'switch off \*\*12\*\* people at once'
        $md | Should -Match 'Nothing was sent'
        Remove-Item -LiteralPath $script:Md
        & $script:Summary -ChangesPath $changes -ResultPath (New-SentResult -Ids @() -Outcome 'invalid' -Refusal @{ kind = 'bad-start-date' }) -SummaryPath $script:Md -WaitSeconds 0
        (Get-Content -LiteralPath $script:Md -Raw) | Should -Match 'no valid start date\. It must look like 2026-11-09'
        Remove-Item -LiteralPath $script:Md
        & $script:Summary -ChangesPath $changes -ResultPath (New-SentResult -Ids '400104' -Outcome 'failed' -Http 403 -Accepted $false) -SummaryPath $script:Md -WaitSeconds 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match '## HR change not delivered'
        $md | Should -Match 'HTTP 403'
        $md | Should -Match 'not delivered: Microsoft refused this batch'
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Remove-Item -LiteralPath $script:Md
        & $script:Summary -ChangesPath $changes -SummaryPath $script:Md -WaitSeconds 0 -MissingSetup 'HR_SYNC_CLIENT_ID, HR_PROV_JOB_ID'
        (Get-Content -LiteralPath $script:Md -Raw) | Should -Match 'Missing repository variable\(s\): \*\*HR_SYNC_CLIENT_ID, HR_PROV_JOB_ID\*\*'
        Remove-Item -LiteralPath $script:Md
        & $script:Summary -ChangesPath $changes -SummaryPath $script:Md -WaitSeconds 0 -SignInOutcome failure
        (Get-Content -LiteralPath $script:Md -Raw) | Should -Match '## HR change not sent: GitHub could not sign in to Microsoft'
    }

    It 'rows held back while the rest were sent: the summary says how many, the real limit used, and the ticket path (review C2)' {
        $f = Join-Path $TestDrive 'held.json'
        [ordered]@{ schema = 'hr-feed-send/1'; outcome = 'dry-run'; refusal = @{ kind = 'mass-disable'; count = 25; threshold = 20 }; jobId = $script:Job; servicePrincipalId = $script:Sp
            selected = @(@{ employeeId = '400104'; status = 'joiner' }); sentAtUtc = $null
            batches = @([ordered]@{ index = 1; records = 1; employeeIds = @('400104'); httpStatus = 0; accepted = $false })
            quarantined = @(1..25 | ForEach-Object { @{ employeeId = "6000$_"; status = 'leaver'; kind = 'mass-disable' } }) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $f
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam)) -ResultPath $f -SummaryPath $script:Md -WaitSeconds 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match 'Held back by the safety check: 25 row'
        $md | Should -Match 'limit for this push is 20'
        $md | Should -Match 'BulkChangeTicket'
        Remove-Item -LiteralPath $script:Md
    }

    It 'a REAL send with some rows held back: the held workers read "held back, NOT sent", never "sent" (review of PR #229)' {
        $gone = [ordered]@{} + $script:Sam; $gone['employeeId'] = '600001'; $gone['kind'] = 'left'; $gone['status'] = 'leaver'; $gone['givenName'] = 'Ana'; $gone['surname'] = 'Gone'
        Mock Invoke-MgGraphRequest { @{ value = @((New-LogEntry -Id '400104' -Action 'create')) } } -ParameterFilter { $Uri -like '*auditLogs/provisioning*' }
        $f = Join-Path $TestDrive 'held-sent.json'
        [ordered]@{ schema = 'hr-feed-send/1'; outcome = 'sent'; refusal = @{ kind = 'mass-disable'; count = 11; threshold = 10 }; jobId = $script:Job; servicePrincipalId = $script:Sp
            selected = @(@{ employeeId = '400104'; status = 'joiner' }); sentAtUtc = '2026-11-09T15:00:00Z'
            batches = @([ordered]@{ index = 1; records = 1; employeeIds = @('400104'); httpStatus = 202; accepted = $true })
            quarantined = @(@{ employeeId = '600001'; status = 'leaver'; kind = 'mass-disable' }) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $f
        & $script:Summary -ChangesPath (New-ChangesFile @($script:Sam, $gone)) -ResultPath $f -SummaryPath $script:Md -WaitSeconds 0 -SignInOutcome success
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match ([regex]::Escape("- **Left:** Ana Gone, Cloud Engineer (Information Technology) $($script:D) held back by the safety check: NOT sent"))
        $md | Should -Not -Match 'Ana Gone[^\n]*Microsoft has not logged it yet'
        $md | Should -Match ([regex]::Escape("- **Hired:** Sam Rivera, Cloud Engineer (Information Technology) $($script:D) account created in Active Directory"))
        $md | Should -Match '\*\*Safety check:\*\* 0 to switch off'
        Should -Invoke Invoke-MgGraphRequest -Times 0 -ParameterFilter { [uri]::UnescapeDataString($Uri) -like "*sourceIdentity/id eq '600001'*" }
        Remove-Item -LiteralPath $script:Md
    }

    It 'a change step that stopped (no changes file) says nothing was sent and points at its log' {
        & $script:Summary -ChangesPath (Join-Path $TestDrive 'missing-changes.json') -SummaryPath $script:Md -WaitSeconds 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match '(?m)^## HR change not sent: the change could not be read$'
        $md | Should -Match 'its log says why .*Nothing was sent to Microsoft\.'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'a push that only removes a row says nothing was sent, and why' {
        $gone = [ordered]@{} + $script:Sam; $gone['kind'] = 'removed'; $gone['send'] = $false
        & $script:Summary -ChangesPath (New-ChangesFile @($gone)) -SummaryPath $script:Md -WaitSeconds 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match '## No HR change to send'
        $md | Should -Match ([regex]::Escape("- **Removed from the HR file:** Sam Rivera, Cloud Engineer (Information Technology) $($script:D) nothing sent: deleting a row does not switch an account off"))
    }

    It 'a move shows from -> to' {
        $move = [ordered]@{} + $script:Sam
        $move['kind'] = 'moved'; $move['dept'] = 'ICU'; $move['jobTitle'] = 'Registered Nurse'; $move['givenName'] = 'Marcus'; $move['surname'] = 'Bello'
        $move['previous'] = @{ dept = 'Nursing'; jobTitle = 'Registered Nurse'; status = 'active' }
        & $script:Summary -ChangesPath (New-ChangesFile @($move)) -ResultPath (New-SentResult -Ids '400104' -Outcome 'dry-run' -Http 0 -Accepted $false) -SummaryPath $script:Md -WaitSeconds 0
        $md = Get-Content -LiteralPath $script:Md -Raw
        $md | Should -Match '## HR change preview \(dry run: nothing was sent\)'
        $md | Should -Match ([regex]::Escape("- **Moved:** Marcus Bello, Registered Nurse: Nursing $($script:A) ICU $($script:D) would update the department or job title in Active Directory"))
        Should -Invoke Invoke-MgGraphRequest -Times 0   # a dry run talks to nobody
    }
}

Describe 'hr-feed chain end to end (dry run): diff -> Invoke-InboundProvisioning -WhatIf -> summary' {
    It 'a hire row added on the branch becomes one "would create" line and one SCIM record' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'tests must never call Graph' }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        $prev = New-HrCsv $script:Base
        $cur = New-HrCsv ($script:Base + '400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,')
        $w = Join-Path $TestDrive 'chain'; New-Item -ItemType Directory -Path $w -Force | Out-Null
        $c = @(& $script:Change -CsvPath $cur -PreviousCsvPath $prev -OutputPath "$w/changes.json" -BaselineStatePath "$w/baseline.json")
        & $script:Inbound -CsvPath $cur -EmployeeId @($c | Where-Object send | ForEach-Object employeeId) -StatePath "$w/baseline.json" -ResultPath "$w/sent.json" -HidePayload -WhatIf -WarningAction SilentlyContinue
        & $script:Summary -ChangesPath "$w/changes.json" -ResultPath "$w/sent.json" -SummaryPath "$w/summary.md" -WaitSeconds 0
        $md = Get-Content -LiteralPath "$w/summary.md" -Raw
        $md | Should -Match ([regex]::Escape("- **Hired:** Sam Rivera, Cloud Engineer (Information Technology) $($script:D) would create the account in Active Directory"))
        $md | Should -Match 'batch 1: 1 record\(s\), not sent \(dry run\)'
        (Get-Content -LiteralPath "$w/sent.json" -Raw | ConvertFrom-Json).selected.employeeId | Should -Be '400104'
    }
}

Describe 'hr-feed.yml: which commit a push is compared with (a failed push is never skipped)' -Skip:(-not $script:CanRunStep) {
    BeforeAll {
        # The "Read the HR change" step's own script, read out of the
        # workflow (so this runs what GitHub runs), against a throwaway repo:
        # main holds the roster; hr-feed has two pushes on top, push 1 hires
        # Sam, push 2 moves Marcus to ICU. `gh` is a stub on PATH answering
        # the run-history lookup: FAKE_GH_RUN = the last successful push
        # run's commit, empty = none yet, 'fail' = the API call fails.
        $wf = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..' '..' '.github' 'workflows' 'hr-feed.yml'))
        $script:Step = Join-Path $TestDrive 'change-step.ps1'
        & python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); print([s for s in d["jobs"]["send"]["steps"] if s.get("id")=="change"][0]["run"])' $wf |
            Set-Content -LiteralPath $script:Step
        $script:Repo = Join-Path $TestDrive 'repo'
        $hr = Join-Path $script:Repo 'lab' 'scripts' 'mock-hr'
        New-Item -ItemType Directory -Path $hr -Force | Out-Null
        Copy-Item -LiteralPath $script:Change -Destination $hr
        function Invoke-Git {
            $o = & git -C $script:Repo -c user.email=test@example.invalid -c user.name=test -c commit.gpgsign=false -c core.hooksPath=/dev/null @args
            if ($LASTEXITCODE -ne 0) { throw "git $args failed" }
            $o
        }
        $csv = Join-Path $hr 'hr_feed.csv'
        Invoke-Git init -q -b main
        Set-Content -LiteralPath $csv -Value (@($script:Header) + $script:Base)
        Invoke-Git add -A
        Invoke-Git commit --no-verify -qm 'roster'
        Invoke-Git update-ref refs/remotes/origin/main HEAD   # what checkout (fetch-depth 0) gives the runner
        Invoke-Git switch -qc hr-feed
        Add-Content -LiteralPath $csv -Value '400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,2026-11-09,'
        Invoke-Git commit --no-verify -qam 'Hire Sam Rivera'
        $script:Hire = "$(Invoke-Git rev-parse HEAD)".Trim()
        (Get-Content -LiteralPath $csv) -replace '^100310,Marcus,Bello,Nursing', '100310,Marcus,Bello,ICU' | Set-Content -LiteralPath $csv
        Invoke-Git commit --no-verify -qam 'Marcus Bello moves to ICU'
        $script:Move = "$(Invoke-Git rev-parse HEAD)".Trim()

        $script:Bin = Join-Path $TestDrive 'bin'
        New-Item -ItemType Directory -Path $script:Bin | Out-Null
        $gh = Join-Path $script:Bin 'gh'
        Set-Content -LiteralPath $gh -Value @(
            '#!/bin/sh',
            'printf "%s\n" "$*" >> "$FAKE_GH_LOG"',
            'if [ "$FAKE_GH_RUN" = fail ]; then echo "gh: Resource not accessible by integration (HTTP 403)" >&2; exit 1; fi',
            'if [ -n "$FAKE_GH_RUN" ]; then echo "$FAKE_GH_RUN"; fi')
        & chmod +x $gh

        function Invoke-ChangeStep {
            # The step as GitHub runs it: pwsh in the checkout, the step's env
            # (the one-time setup variables set, so only the base decides;
            # BEFORE = github.event.before, the commit before this push, which
            # the step must NOT use). Returns the exit code, the log, the step
            # outputs and the gh calls.
            param([string]$LastRun = '', [string]$BaseSha = '', [string]$EventName = 'push', [string]$EmployeeIds = '', [string]$DryRun = 'false')
            $tmp = Join-Path $TestDrive ('runner-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $tmp | Out-Null
            $out = Join-Path $tmp 'github-output'
            New-Item -ItemType File -Path $out | Out-Null
            $vars = @{
                PATH = "$($script:Bin)$([System.IO.Path]::PathSeparator)$env:PATH"; FAKE_GH_RUN = $LastRun; FAKE_GH_LOG = (Join-Path $tmp 'gh.log')
                GITHUB_REF = 'refs/heads/hr-feed'; GITHUB_OUTPUT = $out; RUNNER_TEMP = $tmp; CSV = 'lab/scripts/mock-hr/hr_feed.csv'
                DRY_RUN = $DryRun; EVENT = $EventName; REPO = 'contoso/lab'; GH_TOKEN = 'test-token'; EMPLOYEE_IDS = $EmployeeIds; BEFORE = $script:Hire
                HR_FEED_BASE_SHA = $BaseSha; HR_SYNC_CLIENT_ID = 'x'; AZURE_TENANT_ID = 'x'; HR_PROV_SP_ID = 'x'; HR_PROV_JOB_ID = 'x'; HR_UPN_DOMAIN = 'example.org'
            }
            $saved = @{}
            foreach ($k in $vars.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
            try {
                foreach ($k in $vars.Keys) { [Environment]::SetEnvironmentVariable($k, $(if ($vars[$k]) { $vars[$k] } else { $null })) }
                $log = & pwsh -NoProfile -NonInteractive -WorkingDirectory $script:Repo -File $script:Step 2>&1
                $code = $LASTEXITCODE
            }
            finally { foreach ($k in $vars.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) } }
            $outputs = @{}
            foreach ($l in @(Get-Content -LiteralPath $out)) { if ($l -match '^([^=]+)=(.*)$') { $outputs[$Matches[1]] = $Matches[2] } }
            $calls = Join-Path $tmp 'gh.log'
            [pscustomobject]@{ Code = $code; Log = ($log | Out-String); Outputs = $outputs; GhCalls = @(if (Test-Path -LiteralPath $calls) { Get-Content -LiteralPath $calls }) }
        }
        function Get-SentIds($Run) { @([string]$Run.Outputs['send_ids'] -split ',' | Where-Object { $_ } | Sort-Object) }
    }

    It 'no successful send yet: compares with where hr-feed left main, so a failed first push goes out with the next one' {
        # Push 1 (Sam) failed, push 2 (Marcus) runs. "The commit before this
        # push" would be push 1's commit: Sam would never be sent.
        $r = Invoke-ChangeStep -LastRun ''
        $r.Code | Should -Be 0 -Because $r.Log
        Get-SentIds $r | Should -Be @('100310', '400104')
        $r.Outputs['trigger'] | Should -Match 'where hr-feed left main, no successful send yet'
        $r.GhCalls | Should -Match 'actions/workflows/hr-feed\.yml/runs\?branch=hr-feed&event=push&status=success'
    }

    It 'after a successful send, only what came after it is sent' {
        $r = Invoke-ChangeStep -LastRun $script:Hire
        $r.Code | Should -Be 0 -Because $r.Log
        Get-SentIds $r | Should -Be @('100310')
        $r.Outputs['trigger'] | Should -Match "$($script:Hire.Substring(0, 7)) \(the last successful HR send\)"
    }

    It 'a push that cannot read its run history stops before choosing anything to send' {
        $r = Invoke-ChangeStep -LastRun 'fail'
        $r.Code | Should -Be 1
        $r.Log | Should -Match "::error::GitHub's run history for this workflow could not be read"
        $r.Log | Should -Match 'Nothing was sent'
        $r.Outputs.Contains('send_ids') | Should -BeFalse
    }

    It 'HR_FEED_BASE_SHA is the starting point before the first successful send; one outside the branch stops' {
        $r = Invoke-ChangeStep -BaseSha $script:Hire
        $r.Code | Should -Be 0 -Because $r.Log
        Get-SentIds $r | Should -Be @('100310')
        $r.Outputs['trigger'] | Should -Match 'HR_FEED_BASE_SHA, the starting point set for hr-feed'
        $r = Invoke-ChangeStep -BaseSha ('ab' * 20)
        $r.Code | Should -Be 1
        $r.Log | Should -Match '::error::The repository variable HR_FEED_BASE_SHA \(abab.*\) is not a commit'
        $r.Outputs.Contains('send_ids') | Should -BeFalse
    }

    It 'a last successful send that is not in this branch''s history falls back to the starting point: re-sends, never skips' {
        $r = Invoke-ChangeStep -LastRun ('cd' * 20)
        $r.Code | Should -Be 0 -Because $r.Log
        Get-SentIds $r | Should -Be @('100310', '400104')
        $r.Log | Should -Match "::warning::The last successful HR send \(cdcdcdc\) is not in this branch's history"
    }

    It 're-running a push older than the last successful send stops: its file would undo the later change' {
        Invoke-Git switch -q --detach $script:Hire
        try { $r = Invoke-ChangeStep -LastRun $script:Move }
        finally { Invoke-Git switch -q hr-feed }
        $r.Code | Should -Be 1
        $r.Log | Should -Match '::error::This commit is older than the last successful HR send'
        $r.Outputs.Contains('send_ids') | Should -BeFalse
    }

    It 'a manual run does not stop on the run history: it sends the ids it is given, not a diff' {
        $r = Invoke-ChangeStep -LastRun 'fail' -EventName 'workflow_dispatch' -EmployeeIds '400104' -DryRun 'true'
        $r.Code | Should -Be 0 -Because $r.Log
        Get-SentIds $r | Should -Be @('400104')
        $r.Log | Should -Match 'Hired: Sam Rivera'
    }
}
