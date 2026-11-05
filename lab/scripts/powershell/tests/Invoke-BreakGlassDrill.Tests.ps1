# Pester 5 tests for Invoke-BreakGlassDrill.ps1: the assessment and the
# public-record guard (pure functions), then the Preflight and Verify phases
# with Graph, az and Log Analytics all mocked. Nothing signs in, nothing is
# queried: these tests prove the script records only what the (mocked) SIEM
# returned.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Drill = Get-LabScriptPath 'Invoke-BreakGlassDrill.ps1'
    # Defines the script's functions here too, so the I/O helpers
    # (Invoke-AzJson, Invoke-LaQuery) exist and can be mocked.
    . (Get-ScriptFunctionBlock -Path $script:Drill)

    function Set-DrillMocks {
        param([string[]]$AlertedAccounts = @('bg-admin-01', 'bg-admin-02'), [switch]$CaGap, [int]$KeysPerAccount = 2,
            # Enforced admin allow-list (empty = none) and the registered key model.
            [string[]]$AllowList = @(), [string]$ModelAaguid = 'cb69481e-8ff7-4039-93ec-0a2729a154a8')
        $start = (Get-Date).ToUniversalTime().AddHours(-1)
        $global:DrillTest = @{ Start = $start; Alerted = $AlertedAccounts; CaGap = [bool]$CaGap; Keys = $KeysPerAccount; AllowList = $AllowList; ModelAaguid = $ModelAaguid }
        Mock Write-Host {}
        Mock Start-Sleep {}
        Mock Read-Host { throw 'tests must not prompt' }
        Mock Get-Command { [pscustomobject]@{ Name = 'az' } } -ParameterFilter { $Name -eq 'az' }
        Mock Get-MgContext { New-MgContextStub -Scopes @('User.Read.All', 'GroupMember.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:DrillTest
            switch -Regex ($Uri) {
                'groups\?.*break-glass-admins' { return @{ value = @(@{ id = 'g-bg' }) } }
                '/groups/g-bg/members' { return @{ value = @(@{ id = 'bg-1' }, @{ id = 'bg-2' }) } }
                'users\?.*bg-admin-' {
                    return @{ value = @(
                            @{ id = 'bg-1'; userPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; accountEnabled = $true },
                            @{ id = 'bg-2'; userPrincipalName = 'bg-admin-02@contosolab.onmicrosoft.com'; accountEnabled = $true }) }
                }
                '/conditionalAccess/policies' {
                    $ok = @{ displayName = 'CA001 - Require MFA for all users'; conditions = @{ users = @{ excludeGroups = @('g-bg') } } }
                    $gap = @{ displayName = 'CA009 - new policy'; conditions = @{ users = @{ excludeGroups = @() } } }
                    return @{ value = @($ok) + @(if ($t.CaGap) { $gap }) }
                }
                'authenticationMethodConfigurations/fido2' {
                    return @{ state = 'enabled'; includeTargets = @(@{ id = 'g-bg'; targetType = 'group'; allowedPasskeyProfiles = @('p-admin') })
                        passkeyProfiles = @(@{ id = 'p-admin'; keyRestrictions = @{ isEnforced = (@($t.AllowList).Count -gt 0); enforcementType = 'allow'; aaGuids = @($t.AllowList) } }) }
                }
                '/fido2Methods' { return @{ value = @(if ($t.Keys -gt 0) { 1..$t.Keys | ForEach-Object { @{ id = "key-$_"; model = 'YubiKey 5'; aaGuid = $t.ModelAaguid } } }) } }
                default { throw "unexpected Graph call in test: $Uri" }
            }
        }
        Mock Invoke-AzJson {
            $a = $Arguments -join ' '
            if ($a -like 'account show*') { return 'sub-0000' }
            if ($a -like 'monitor log-analytics workspace show*') { return [pscustomobject]@{ customerId = 'ws-cust'; id = '/subscriptions/sub-0000/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab' } }
            if ($a -like '*SecurityInsights/alertRules/contoso-break-glass-signin*') { return [pscustomobject]@{ properties = [pscustomobject]@{ enabled = $true; displayName = 'Contoso - Break-glass account sign-in (any)' } } }
            if ($a -like '*scheduledQueryRules*') { return $null }   # not deployed: Sentinel path only
            throw "unexpected az call in test: $a"
        }
        Mock Invoke-LaQuery {
            $t = $global:DrillTest
            if ($Query -match '^SigninLogs \| where TimeGenerated > ago\(1d\) \| count') { return @([pscustomobject]@{ Count = 12 }) }
            if ($Query -match 'AADNonInteractiveUserSignInLogs') {
                return @(
                    [pscustomobject]@{ TimeGenerated = $t.Start.AddMinutes(5).ToString('o'); UserPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; SignInType = 'interactive'; ResultType = '0'; Methods = 'Passkey (device-bound)'; IPAddress = '203.0.113.10'; CorrelationId = 'c1' },
                    [pscustomobject]@{ TimeGenerated = $t.Start.AddMinutes(9).ToString('o'); UserPrincipalName = 'bg-admin-02@contosolab.onmicrosoft.com'; SignInType = 'interactive'; ResultType = '0'; Methods = 'Passkey (device-bound)'; IPAddress = '203.0.113.10'; CorrelationId = 'c2' })
            }
            if ($Query -match '^SecurityAlert') {
                $i = 0
                return @(foreach ($acct in $t.Alerted) { $i++; [pscustomobject]@{ TimeUtc = $t.Start.AddMinutes(10 + $i).ToString('o'); AlertId = "alert-$i"; Accounts = @($acct) } })
            }
            if ($Query -match '^SecurityIncident') {
                return @(if ($t.Alerted.Count) { [pscustomobject]@{ IncidentNumber = 42; CreatedTime = $t.Start.AddMinutes(12).ToString('o'); Status = 'New'; AlertIds = @('alert-1', 'alert-2') } })
            }
            if ($Query -match '^AuditLogs') { return @([pscustomobject]@{ Operations = 0 }) }
            throw "unexpected KQL in test: $Query"
        }
    }

    function Invoke-Verify {
        param([string]$Name)
        $global:LASTEXITCODE = 0
        $pub = Join-Path $TestDrive "$Name-pub"; $priv = Join-Path $TestDrive "$Name-priv"
        & $script:Drill -Phase Verify -DrillStartUtc $global:DrillTest.Start -DeclaredSignIns 'bg-admin-01:key 1', 'bg-admin-02:key 1' `
            -WaitMinutes 0 -EvidenceDirectory $pub -PrivateDirectory $priv -ChangeTicket 'CHG0001234' -Operator 'MW' -Reviewer 'GM' -WarningAction SilentlyContinue
        $exit = $LASTEXITCODE
        $file = @(Get-ChildItem -LiteralPath $pub -Filter '*.json' -ErrorAction SilentlyContinue)[0]
        return [pscustomobject]@{ Exit = $exit; File = $file; PrivateDir = $priv; Record = $(if ($file) { Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json }) }
    }
}

AfterAll { Remove-Variable -Name DrillTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'Assessment and record guards' {
    It 'derives the short account name and nothing else' {
        Get-ShortName 'BG-ADMIN-01@contoso.onmicrosoft.com' | Should -Be 'bg-admin-01'
        Get-ShortName 'dana.okafor@contoso.test' | Should -BeNullOrEmpty
    }

    It 'parses dynamic columns from the Log Analytics API into lists' {
        $resp = [pscustomobject]@{ tables = @([pscustomobject]@{
                    columns = @([pscustomobject]@{ name = 'AlertId'; type = 'string' }, [pscustomobject]@{ name = 'Accounts'; type = 'dynamic' })
                    rows    = @(, @('a-1', '["bg-admin-01","bg-admin-02"]')) }) }
        $rows = @(ConvertFrom-LaTable $resp)
        $rows[0].AlertId | Should -Be 'a-1'
        @($rows[0].Accounts) | Should -Be @('bg-admin-01', 'bg-admin-02')
    }

    It 'Pass / Partial / Fail follow the runbook table' {
        $t = [datetime]'2026-11-02T14:00:00Z'
        $decl = @([pscustomobject]@{ Account = 'bg-admin-01'; KeyLabel = 'key 1' }, [pscustomobject]@{ Account = 'bg-admin-02'; KeyLabel = 'key 1' })
        $seen = @([pscustomobject]@{ Account = 'bg-admin-01'; TimeGenerated = $t; ResultType = 0; Methods = 'Passkey' }, [pscustomobject]@{ Account = 'bg-admin-02'; TimeGenerated = $t.AddMinutes(3); ResultType = 0; Methods = 'Passkey' })
        $both = @([pscustomobject]@{ TimeUtc = $t.AddMinutes(6); Accounts = @('bg-admin-01') }, [pscustomobject]@{ TimeUtc = $t.AddMinutes(8); Accounts = @('bg-admin-02') })
        (Get-DrillAssessment -Declared $decl -SignIns $seen -Alerts $both).Result | Should -Be 'Pass'
        (Get-DrillAssessment -Declared $decl -SignIns $seen -Alerts $both[0]).Result | Should -Be 'Partial'
        (Get-DrillAssessment -Declared $decl -SignIns $seen[0] -Alerts $both).Result | Should -Be 'Partial'   # bg-admin-02 never reached the logs
        $fail = Get-DrillAssessment -Declared $decl -SignIns $seen -Alerts @()
        $fail.Result | Should -Be 'Fail'
        ($fail.Reasons -join ' ') | Should -Match 'Sev 2'
        (Get-DrillAssessment -Declared @() -SignIns $seen -Alerts $both).Result | Should -Be 'Fail'
    }

    It 'never pairs an alert raised BEFORE the sign-in' {
        $t = [datetime]'2026-11-02T14:00:00Z'
        $r = Get-DrillAssessment -Declared @([pscustomobject]@{ Account = 'bg-admin-01'; KeyLabel = 'key 1' }) `
            -SignIns @([pscustomobject]@{ Account = 'bg-admin-01'; TimeGenerated = $t; ResultType = 0; Methods = '' }) `
            -Alerts @([pscustomobject]@{ TimeUtc = $t.AddMinutes(-30); Accounts = @('bg-admin-01') })
        $r.SignIns[0].alertObserved | Should -BeFalse
    }

    It 'rule-wide (Log Analytics) alerts cover any account' {
        $t = [datetime]'2026-11-02T14:00:00Z'
        $r = Get-DrillAssessment -Declared @([pscustomobject]@{ Account = 'bg-admin-02'; KeyLabel = 'key 2' }) `
            -SignIns @([pscustomobject]@{ Account = 'bg-admin-02'; TimeGenerated = $t; ResultType = 0; Methods = '' }) `
            -Alerts @([pscustomobject]@{ TimeUtc = $t.AddMinutes(7); Accounts = @() }) -AlertsCarryAccounts $false
        $r.Result | Should -Be 'Pass'
        $r.SignIns[0].signInToAlertMinutes | Should -Be 7
    }

    It 'app roles cover the read scopes they include (ReadWrite covers Read, Directory.Read.All covers users and members)' {
        $req = @('User.Read.All', 'GroupMember.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All')
        # The lab operator's application roles (AGENT-RULES access list).
        @(Get-MissingGraphScope -Have @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Directory.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.ReadWrite.All') -Required $req) | Should -BeNullOrEmpty
        @(Get-MissingGraphScope -Have @('Directory.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All') -Required $req) | Should -BeNullOrEmpty
        @(Get-MissingGraphScope -Have $req -Required $req) | Should -BeNullOrEmpty
        @(Get-MissingGraphScope -Have @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All') -Required $req) | Should -Be @('Policy.Read.All')
        # Directory.Read.All does not read authentication methods.
        @(Get-MissingGraphScope -Have @('Directory.Read.All', 'Policy.Read.All') -Required $req) | Should -Be @('UserAuthenticationMethod.Read.All')
        @(Get-MissingGraphScope -Have @() -Required $req) | Should -BeNullOrEmpty
    }

    It 'catches identifiers before a public record is written' {
        @(Test-PublicRecordSafe -Json '{"account":"bg-admin-01","signInUtc":"2026-11-02T14:00:00.0000000Z","incidentNumber":"42"}').Count | Should -Be 0
        @(Test-PublicRecordSafe -Json '{"upn":"bg-admin-01@contoso.onmicrosoft.com"}').Count | Should -Be 2   # the address and the domain
        @(Test-PublicRecordSafe -Json '{"ip":"203.0.113.10"}').Count | Should -Be 1
        @(Test-PublicRecordSafe -Json '{"id":"62e90394-69f5-4237-9190-012177145e10"}').Count | Should -Be 1
        @(Test-PublicRecordSafe -Json '{"ip":"2001:db8:0:0:0:0:0:1"}').Count | Should -Be 1
    }
}

Describe 'Invoke-BreakGlassDrill.ps1 (mocked Graph, az and Log Analytics)' {
    It 'Preflight refuses to start when a CA policy does not exclude break-glass' {
        Set-DrillMocks -CaGap
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Preflight -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'do NOT start the drill' }
    }

    It 'Preflight fails when an account has no FIDO2 key' {
        Set-DrillMocks -KeysPerAccount 0
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Preflight -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
    }

    It 'Preflight fails when the enforced admin allow-list blocks the break-glass key model (lockout)' {
        Set-DrillMocks -AllowList @('cb69481e-8ff7-4039-93ec-0a2729a154a8') -ModelAaguid '99999999-9999-9999-9999-999999999999'
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Preflight -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[FAIL\] Keys bg-admin-01 - 2 registered key\(s\) of a model the enforced allow-list blocks' }
    }

    It 'Preflight passes the keys when they are an allowed model' {
        Set-DrillMocks -AllowList @('cb69481e-8ff7-4039-93ec-0a2729a154a8')
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Preflight -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[PASS\] Keys bg-admin-01 - 2 usable FIDO2 key' }
    }

    It 'App-only: refuses -Phase All (it prompts a person) before any sign-in' {
        Set-DrillMocks
        Mock az { throw 'tests must not call az' }
        { & $script:Drill -Phase All -UseAzureCliToken -WarningAction SilentlyContinue } | Should -Throw '*Preflight or -Phase Verify only*'
        Should -Invoke az -Times 0
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'App-only Preflight (lab: one software passkey each): token from the Azure CLI, app roles accepted, passes' {
        Set-DrillMocks -KeysPerAccount 1
        Mock az { $global:LASTEXITCODE = 0; 'eyJ0ZXN0IjoidG9rZW4ifQ' } -ParameterFilter { "$args" -match 'get-access-token' }
        Mock Connect-MgGraph {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('User.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Directory.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.ReadWrite.All') }
        Mock Write-Warning {}
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Preflight -UseAzureCliToken -ExpectedKeysPerAccount 1
        $LASTEXITCODE | Should -Be 0
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $null -ne $AccessToken -and -not $Scopes }
        Should -Invoke Write-Warning -Times 0 -ParameterFilter { "$Message" -match 'does not cover' }
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '\[PASS\] Keys bg-admin-01 - 1 usable FIDO2 key' }
    }

    It 'App-only: an app missing a read permission is named in a warning' {
        Set-DrillMocks
        Mock az { $global:LASTEXITCODE = 0; 'eyJ0ZXN0IjoidG9rZW4ifQ' } -ParameterFilter { "$args" -match 'get-access-token' }
        Mock Connect-MgGraph {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('Directory.Read.All', 'Policy.Read.All') }
        Mock Write-Warning {}
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Preflight -UseAzureCliToken
        Should -Invoke Write-Warning -Times 1 -ParameterFilter { "$Message" -match 'does not cover: UserAuthenticationMethod\.Read\.All' }
    }

    It 'App-only: no token from the Azure CLI stops the run before Graph' {
        Set-DrillMocks
        Mock az { $global:LASTEXITCODE = 1; '' } -ParameterFilter { "$args" -match 'get-access-token' }
        Mock Connect-MgGraph {}
        { & $script:Drill -Phase Preflight -UseAzureCliToken -WarningAction SilentlyContinue } | Should -Throw '*No Microsoft Graph token from the Azure CLI*'
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'Verify: both sign-ins alerted -> Pass, with incident number and latency, exit 0' {
        Set-DrillMocks
        $v = Invoke-Verify 'pass'
        $v.Exit | Should -Be 0
        $v.Record.result | Should -Be 'Pass'
        $v.Record.alertPath | Should -Be 'sentinel'
        @($v.Record.signIns).Count | Should -Be 2
        $v.Record.signIns[0].keyLabelSource | Should -Be 'operator-declared'
        $v.Record.signIns[0].incidentNumber | Should -Be '42'
        $v.Record.signIns[0].signInToAlertMinutes | Should -Be 6
        $v.Record.signIns[0].signInToIncidentMinutes | Should -Be 7
        $v.Record.changeTicket | Should -Be 'CHG0001234'
        @($v.Record.notCheckedByScript) | Should -Contain 'ServiceNow INC'
    }

    It 'Verify: the public record holds no UPN, IP, object id or tenant domain; the private one keeps them' {
        Set-DrillMocks
        $v = Invoke-Verify 'privacy'
        $text = Get-Content -LiteralPath $v.File.FullName -Raw
        $text | Should -Not -Match '@|onmicrosoft|203\.0\.113\.10|bg-1|g-bg'
        $detail = @(Get-ChildItem -LiteralPath $v.PrivateDir -Filter '*-detail.json')[0]
        (Get-Content -LiteralPath $detail.FullName -Raw) | Should -Match '203\.0\.113\.10'
    }

    It 'Verify: keeps polling after a Pass until the Sentinel incident reaches the workspace, and records it' {
        Set-DrillMocks
        $global:DrillTest.IncidentPolls = 0
        Mock Invoke-LaQuery {
            $t = $global:DrillTest
            if ($Query -match '^SecurityIncident') {
                # The first poll sees the alerts but not yet the incident.
                $t.IncidentPolls++
                if ($t.IncidentPolls -lt 2) { return @() }
                return @([pscustomobject]@{ IncidentNumber = 42; CreatedTime = $t.Start.AddMinutes(12).ToString('o'); Status = 'New'; AlertIds = @('alert-1', 'alert-2') })
            }
            if ($Query -match 'AADNonInteractiveUserSignInLogs') {
                return @(
                    [pscustomobject]@{ TimeGenerated = $t.Start.AddMinutes(5).ToString('o'); UserPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; SignInType = 'interactive'; ResultType = '0'; Methods = 'Passkey (device-bound)'; IPAddress = '203.0.113.10'; CorrelationId = 'c1' },
                    [pscustomobject]@{ TimeGenerated = $t.Start.AddMinutes(9).ToString('o'); UserPrincipalName = 'bg-admin-02@contosolab.onmicrosoft.com'; SignInType = 'interactive'; ResultType = '0'; Methods = 'Passkey (device-bound)'; IPAddress = '203.0.113.10'; CorrelationId = 'c2' })
            }
            if ($Query -match '^SecurityAlert') { return @([pscustomobject]@{ TimeUtc = $t.Start.AddMinutes(11).ToString('o'); AlertId = 'alert-1'; Accounts = @('bg-admin-01', 'bg-admin-02') }) }
            if ($Query -match '^AuditLogs') { return @([pscustomobject]@{ Operations = 0 }) }
            if ($Query -match '^SigninLogs \| where TimeGenerated > ago\(1d\) \| count') { return @([pscustomobject]@{ Count = 12 }) }
            throw "unexpected KQL in test: $Query"
        }
        $pub = Join-Path $TestDrive 'wait-pub'; $priv = Join-Path $TestDrive 'wait-priv'
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Verify -DrillStartUtc $global:DrillTest.Start -DeclaredSignIns 'bg-admin-01:key 1', 'bg-admin-02:key 1' `
            -WaitMinutes 5 -PollSeconds 15 -EvidenceDirectory $pub -PrivateDirectory $priv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $global:DrillTest.IncidentPolls | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -Exactly
        $rec = Get-Content -LiteralPath @(Get-ChildItem -LiteralPath $pub -Filter '*.json')[0].FullName -Raw | ConvertFrom-Json
        $rec.result | Should -Be 'Pass'
        @($rec.signIns | ForEach-Object incidentNumber) | Should -Be @('42', '42')
    }

    It 'Verify: alerts but no Sentinel incident by the deadline -> Partial, exit 1' {
        Set-DrillMocks
        Mock Invoke-LaQuery {
            $t = $global:DrillTest
            if ($Query -match '^SecurityIncident') { return @() }
            if ($Query -match 'AADNonInteractiveUserSignInLogs') {
                return @([pscustomobject]@{ TimeGenerated = $t.Start.AddMinutes(5).ToString('o'); UserPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; SignInType = 'interactive'; ResultType = '0'; Methods = 'Passkey (device-bound)'; IPAddress = '203.0.113.10'; CorrelationId = 'c1' })
            }
            if ($Query -match '^SecurityAlert') { return @([pscustomobject]@{ TimeUtc = $t.Start.AddMinutes(11).ToString('o'); AlertId = 'alert-1'; Accounts = @('bg-admin-01') }) }
            if ($Query -match '^AuditLogs') { return @([pscustomobject]@{ Operations = 0 }) }
            if ($Query -match '^SigninLogs \| where TimeGenerated > ago\(1d\) \| count') { return @([pscustomobject]@{ Count = 12 }) }
            throw "unexpected KQL in test: $Query"
        }
        $pub = Join-Path $TestDrive 'noinc-pub'; $priv = Join-Path $TestDrive 'noinc-priv'
        $global:LASTEXITCODE = 0
        & $script:Drill -Phase Verify -DrillStartUtc $global:DrillTest.Start -DeclaredSignIns 'bg-admin-01:key 1' -WaitMinutes 0 -EvidenceDirectory $pub -PrivateDirectory $priv -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 1
        $rec = Get-Content -LiteralPath @(Get-ChildItem -LiteralPath $pub -Filter '*.json')[0].FullName -Raw | ConvertFrom-Json
        $rec.result | Should -Be 'Partial'
        ($rec.resultReasons -join ' ') | Should -Match 'no Sentinel incident .* bg-admin-01'
    }

    It 'Pending incidents: Sentinel path only, alerted sign-ins without an incident number' {
        $a = [pscustomobject]@{ SignIns = @([pscustomobject]@{ account = 'bg-admin-01'; alertObserved = $true; incidentNumber = $null }, [pscustomobject]@{ account = 'bg-admin-02'; alertObserved = $true; incidentNumber = '42' }, [pscustomobject]@{ account = 'bg-admin-03'; alertObserved = $false; incidentNumber = $null }) }
        @(Get-PendingIncident -Assessment $a -AlertPath 'sentinel') | Should -Be @('bg-admin-01')
        @(Get-PendingIncident -Assessment $a -AlertPath 'log-analytics') | Should -BeNullOrEmpty
    }

    It 'Verify: one sign-in without an alert -> Partial, exit 1' {
        Set-DrillMocks -AlertedAccounts @('bg-admin-01')
        $v = Invoke-Verify 'partial'
        $v.Exit | Should -Be 1
        $v.Record.result | Should -Be 'Partial'
        ($v.Record.signIns | Where-Object account -eq 'bg-admin-02').alertObserved | Should -BeFalse
    }

    It 'Verify: no alert at all -> Fail (Sev 2), exit 1' {
        Set-DrillMocks -AlertedAccounts @()
        $v = Invoke-Verify 'fail'
        $v.Exit | Should -Be 1
        $v.Record.result | Should -Be 'Fail'
    }
}
