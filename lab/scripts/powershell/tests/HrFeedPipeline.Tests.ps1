# Pester 5 tests for the hr-feed.yml pipeline scripts in ../mock-hr:
#   Get-HrFeedChange.ps1     the diff in HR words (hired / left / moved /
#                            rehired / updated / removed), the access-change
#                            baseline it hands the mass-change guard;
#   Write-HrFeedSummary.ps1  the plain-English run summary, the bounded wait
#                            on the provisioning log (mocked Graph), and the
#                            privacy rule: names, job title and department
#                            only - never an employee id, UPN, date, manager.
# End to end: diff -> Invoke-InboundProvisioning.ps1 -WhatIf -> summary.
# No tenant: Invoke-MgGraphRequest and Get-MgContext are mocks, Start-Sleep
# is a no-op.

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
