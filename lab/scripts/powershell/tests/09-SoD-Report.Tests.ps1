# Pester 5 tests for 09-SoD-Report.ps1 (detective SoD).
#   * Evaluation: the pure functions on small inventories - package/group/
#     role holdings, PIM eligibility, rule statuses, exceptions.
#   * End to end on lab/iga/fixtures/sod-tenant.json (synthetic): exit code =
#     open violations, hashed CSV/JSON/manifest, public files carry no
#     identity, -WhatIf writes nothing, synthetic output refused in the public
#     evidence tree.
#   * Tenant path against a mocked Invoke-MgGraphRequest, and a failing
#     source (exit 255, nothing written, nothing reported as clean).
#   * Parity: helpers duplicated across the lab/iga scripts stay identical.
# Nothing here talks to a tenant, and nothing is written outside TestDrive.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Sod = Get-LabScriptPath '09-SoD-Report.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Sod -Name 'Read-IgaJson', 'Get-CatalogEntry', 'Test-SodRuleSet', 'Test-PublicRecordSafe', 'Get-SubjectPseudonym',
        'ConvertTo-UtcDateTime', 'Get-RuleEntitlement', 'Get-T2PackageName', 'Get-ReviewerOfRecordHolding', 'Test-EligibleOnlyVia', 'ConvertFrom-FixtureInventory', 'Invoke-SodEvaluation', 'ConvertTo-PublicViolation', 'Test-IsPublicEvidencePath')
    $script:Catalog = Read-IgaJson (Join-Path ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))) 'iga' 'access-catalog.json')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:RulesPath = Join-Path $script:LabRoot 'iga' 'sod-rules.json'
    $script:FixturePath = Join-Path $script:LabRoot 'iga' 'fixtures' 'sod-tenant.json'
    $script:Rules = Read-IgaJson $script:RulesPath
    $script:Fixture = Read-IgaJson $script:FixturePath
    $script:AsOf = [datetime]::new(2026, 10, 20, 12, 0, 0, [DateTimeKind]::Utc)

    function New-Inventory {
        # holdings: 'userId|kind|name|via' strings; every named object exists unless listed in -Missing.
        param([string[]]$Holdings, [string[]]$Missing = @(), [hashtable]$Users = @{})
        $exists = @{}
        foreach ($r in $script:Rules['rules']) { foreach ($k in @(Get-RuleEntitlement $r['sideA']) + @(Get-RuleEntitlement $r['sideB'])) { if ($k -notin $Missing) { $exists[$k] = $true } } }
        $h = @($Holdings | ForEach-Object { $u, $k, $n, $v = $_ -split '\|'; @{ userId = $u; kind = $k; name = $n; via = $v } })
        $us = @{}; foreach ($u in @($h | ForEach-Object { $_['userId'] } | Sort-Object -Unique)) { $us[$u] = @{ id = $u; userPrincipalName = "$u@contoso.test"; displayName = $u; accountEnabled = $true } }
        foreach ($k in $Users.Keys) { $us[$k] = $Users[$k] }
        return @{ users = $us; exists = $exists; holdings = $h; dataSources = @() }
    }
    function Get-Rule([string]$Id) { $r = $script:Rules | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50; $r['rules'] = @($r['rules'] | Where-Object { $_['id'] -eq $Id }); return $r }
    function Invoke-Fixture {
        param([hashtable]$Extra = @{}, [string]$RulesPath = $script:RulesPath)
        $out = Join-Path $TestDrive "run-$([guid]::NewGuid().ToString('N'))"
        $global:LASTEXITCODE = 0
        $r = & $script:Sod -InputPath $script:FixturePath -RulesPath $RulesPath -OutputDirectory (Join-Path $out 'public') -DetailDirectory (Join-Path $out 'detail') @Extra -WarningAction SilentlyContinue
        return [pscustomobject]@{ Result = $r; Exit = $LASTEXITCODE; Root = $out }
    }
    Mock Write-Host {}
}

Describe 'Invoke-SodEvaluation' {
    It 'flags a person holding a package on each side; one side alone is fine' {
        $inv = New-Inventory -Holdings @('u1|accessPackages|Nurse - Clinical Apps|assignment', 'u1|accessPackages|Pharmacy - Controlled Substances Apps|assignment',
            'u2|accessPackages|Nurse - Clinical Apps|assignment')
        $r = Invoke-SodEvaluation -Rules (Get-Rule 'SOD-01') -Inventory $inv -AsOf $script:AsOf
        @($r.Violations).Count | Should -Be 1
        $r.Violations[0].UserId | Should -Be 'u1'
        $r.Violations[0].SideA | Should -Be @('accessPackage:Nurse - Clinical Apps[assignment]')
        $r.Violations[0].ActivationRequired | Should -BeFalse
        $r.Rules[0].Status | Should -Be 'evaluated'
    }

    It 'counts group membership (incl. dynamic birthright groups) and app groups' {
        $inv = New-Inventory -Holdings @('u1|groups|All-ICU|member', 'u1|groups|App-Pharmacy-Dispensing-Users|member')
        @((Invoke-SodEvaluation -Rules (Get-Rule 'SOD-01') -Inventory $inv -AsOf $script:AsOf).Violations).Count | Should -Be 1
    }

    It 'PIM eligibility is a violation, flagged activationRequired only when a side is eligible-only' {
        $inv = New-Inventory -Holdings @('u1|directoryRoles|User Administrator|eligible', 'u1|groups|IGA-Access-Reviewers|member',
            'u2|directoryRoles|User Administrator|eligible', 'u2|directoryRoles|User Administrator|active', 'u2|groups|IGA-Access-Reviewers|member',
            'u3|groups|Privileged-IAM-Admins|pimEligible', 'u3|directoryRoles|Identity Governance Administrator|eligible-via-group')
        $v = (Invoke-SodEvaluation -Rules (Get-Rule 'SOD-08') -Inventory $inv -AsOf $script:AsOf).Violations
        @($v).Count | Should -Be 3
        ($v | Where-Object UserId -eq 'u1').ActivationRequired | Should -BeTrue
        ($v | Where-Object UserId -eq 'u2').ActivationRequired | Should -BeFalse      # also active
        ($v | Where-Object UserId -eq 'u2').SideA | Should -Be @('directoryRole:User Administrator[eligible+active]')
        ($v | Where-Object UserId -eq 'u3').ActivationRequired | Should -BeTrue
    }

    It 'SOD-08 side A covers Global Administrator and Groups Administrator (active or eligible)' {
        $inv = New-Inventory -Holdings @('u1|directoryRoles|Global Administrator|eligible', 'u1|groups|IGA-Access-Reviewers|member',
            'u2|directoryRoles|Groups Administrator|active', 'u2|directoryRoles|Identity Governance Administrator|active')
        $v = (Invoke-SodEvaluation -Rules (Get-Rule 'SOD-08') -Inventory $inv -AsOf $script:AsOf).Violations
        @($v | ForEach-Object UserId | Sort-Object) | Should -Be @('u1', 'u2')
        ($v | Where-Object UserId -eq 'u1').ActivationRequired | Should -BeTrue
    }

    It 'SOD-08 reviewer of record: an identity admin who manages someone holding T2 access is in conflict' {
        $holdings = @(@{ userId = 'u-mgr'; kind = 'groups'; name = 'Privileged-IAM-Admins'; via = 'pimEligible' },
            @{ userId = 'u-report'; kind = 'accessPackages'; name = 'Pharmacy - Controlled Substances Apps'; via = 'assignment' },
            @{ userId = 'u-mgr2'; kind = 'groups'; name = 'Privileged-IAM-Admins'; via = 'pimEligible' },
            @{ userId = 'u-nurse'; kind = 'accessPackages'; name = 'Nurse - Clinical Apps'; via = 'assignment' })
        $t2 = @(Get-T2PackageName -Catalog $script:Catalog)
        $t2 | Should -Contain 'Pharmacy - Controlled Substances Apps'
        $t2 | Should -Not -Contain 'Nurse - Clinical Apps'        # T3 birthright: no manager review
        $t2 | Should -Not -Contain 'ICU - Critical Care Apps'     # T3 with a T2 request path: not told apart in v1
        $ror = @(Get-ReviewerOfRecordHolding -Reports @{ 'u-mgr' = @('u-report'); 'u-mgr2' = @('u-nurse') } -Holdings $holdings -T2Packages $t2)
        @($ror | ForEach-Object { $_['userId'] }) | Should -Be @('u-mgr')
        $inv = New-Inventory -Holdings @('u-mgr|groups|Privileged-IAM-Admins|pimEligible', 'u-mgr|reviewerOfRecord|T2-direct-report|manager')
        $v = @((Invoke-SodEvaluation -Rules (Get-Rule 'SOD-08') -Inventory $inv -AsOf $script:AsOf).Violations)
        $v.Count | Should -Be 1
        $v[0].SideB | Should -Be @('reviewerOfRecord:T2-direct-report[manager]')
    }

    It 'a rule with a side that does not exist is not-evaluable (no claim), one with gaps is partial' {
        $inv = New-Inventory -Holdings @('u1|accessPackages|Nurse - Clinical Apps|assignment', 'u1|groups|PIM-EHR-AuditLog-Admins|pimEligible') -Missing @('accessPackages|Prescriber - CPOE Ordering Apps')
        $r = Invoke-SodEvaluation -Rules $script:Rules -Inventory $inv -AsOf $script:AsOf
        ($r.Rules | Where-Object Id -eq 'SOD-02').Status | Should -Be 'not-evaluable'
        ($r.Rules | Where-Object Id -eq 'SOD-07').Status | Should -Be 'partial'
        ($r.Rules | Where-Object Id -eq 'SOD-07').Open | Should -Be 1
        $inv2 = New-Inventory -Holdings @('u1|accessPackages|Nurse - Clinical Apps|assignment', 'u1|accessPackages|Pharmacy - Controlled Substances Apps|assignment') -Missing @('accessPackages|Pharmacy - Controlled Substances Apps', 'groups|App-Pharmacy-Dispensing-Users')
        $r2 = Invoke-SodEvaluation -Rules (Get-Rule 'SOD-01') -Inventory $inv2 -AsOf $script:AsOf
        $r2.Rules[0].Status | Should -Be 'not-evaluable'
        @($r2.Violations).Count | Should -Be 0
    }

    It 'exceptions: valid through the expiry date = excepted; afterwards = exception-expired' {
        $rules = Get-Rule 'SOD-01'
        $rules['exceptions'] = @(@{ ruleId = 'SOD-01'; userPrincipalName = 'u1@contoso.test'; exceptionId = 'E9'; expires = '2026-10-20' })
        $inv = New-Inventory -Holdings @('u1|accessPackages|Nurse - Clinical Apps|assignment', 'u1|accessPackages|Pharmacy - Controlled Substances Apps|assignment')
        $on = Invoke-SodEvaluation -Rules $rules -Inventory $inv -AsOf $script:AsOf
        $on.Violations[0].Status | Should -Be 'excepted'; $on.Violations[0].ExceptionId | Should -Be 'E9'
        $on.Rules[0].Open | Should -Be 0; $on.Rules[0].Excepted | Should -Be 1
        $after = Invoke-SodEvaluation -Rules $rules -Inventory $inv -AsOf $script:AsOf.AddDays(1)
        $after.Violations[0].Status | Should -Be 'exception-expired'
        $after.Rules[0].Open | Should -Be 1
    }

    It 'gives a stable pseudonym that reveals no identity' {
        $p = Get-SubjectPseudonym -UserId '11111111-1111-1111-1111-111111111111'
        $p | Should -Match '^U-[0-9a-f]{12}$'
        Get-SubjectPseudonym -UserId '11111111-1111-1111-1111-111111111111'.ToUpperInvariant() | Should -Be $p
        $pub = ConvertTo-PublicViolation -Violation ([pscustomobject]@{ RuleId = 'SOD-01'; RuleName = 'n'; Risk = 'High'; UserId = '11111111-1111-1111-1111-111111111111'; AccountEnabled = $true
                SideA = @('a'); SideB = @('b'); ActivationRequired = $false; Status = 'open'; ExceptionId = ''; UserPrincipalName = 'x@contoso.test'; DisplayName = 'X' })
        @(Test-PublicRecordSafe -Json ($pub | ConvertTo-Json)) | Should -BeNullOrEmpty
    }

    It 'knows the public evidence tree from the gitignored out/ tree' {
        $ev = Join-Path $script:LabRoot 'evidence'
        Test-IsPublicEvidencePath -Path (Join-Path $ev 'sod') -EvidenceRoot $ev | Should -BeTrue
        Test-IsPublicEvidencePath -Path (Join-Path $ev 'out' 'sod') -EvidenceRoot $ev | Should -BeFalse
        Test-IsPublicEvidencePath -Path $TestDrive -EvidenceRoot $ev | Should -BeFalse
        Test-IsPublicEvidencePath -Path (Join-Path $script:LabRoot 'evidence-other') -EvidenceRoot $ev | Should -BeFalse
    }
}

Describe '09-SoD-Report.ps1 - offline fixture run' {
    It 'exits with the number of open violations (7) and writes a hashed report' {
        $r = Invoke-Fixture
        $r.Exit | Should -Be 7
        $dir = @(Get-ChildItem -LiteralPath (Join-Path $r.Root 'public') -Directory)
        $dir.Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $dir[0].FullName -File | ForEach-Object Name | Sort-Object) | Should -Be @('manifest.sha256', 'sod-report.json', 'sod-violations.csv')
        foreach ($line in Get-Content -LiteralPath (Join-Path $dir[0].FullName 'manifest.sha256')) {
            $hash, $name = $line -split '  ', 2
            (Get-FileHash -LiteralPath (Join-Path $dir[0].FullName $name) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $hash
        }
        $rep = Get-Content -LiteralPath (Join-Path $dir[0].FullName 'sod-report.json') -Raw | ConvertFrom-Json -AsHashtable
        $rep['source'] | Should -Be 'fixture'
        $rep['summary']['violationsOpen'] | Should -Be 7
        $rep['summary']['rulesNotEvaluable'] | Should -Be 4
        $rep['summary']['activationRequired'] | Should -Be 3
        $rep['summary']['disabledAccounts'] | Should -Be 1
        @(Import-Csv -LiteralPath (Join-Path $dir[0].FullName 'sod-violations.csv')).Count | Should -Be 7
        # Grace (fixture) is not a reviewer-group member: her SOD-08 conflict is the reviewer of record for Sofia's T2 package.
        $grace = @($r.Result.Violations | Where-Object { $_.RuleId -eq 'SOD-08' -and $_.UserId -eq 'u-grace' })
        $grace.Count | Should -Be 1
        $grace[0].SideB | Should -Be @('reviewerOfRecord:T2-direct-report[manager]')
    }

    It 'public files carry pseudonyms only; the identity map is in the detail folder' {
        $r = Invoke-Fixture
        $pub = (Get-ChildItem -LiteralPath (Join-Path $r.Root 'public') -Recurse -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        foreach ($u in $script:Fixture['users']) {
            $pub | Should -Not -Match ([regex]::Escape($u['userPrincipalName']))
            $pub | Should -Not -Match ([regex]::Escape($u['displayName']))
            $pub | Should -Not -Match ('"' + [regex]::Escape($u['id']) + '"')
        }
        @(Test-PublicRecordSafe -Json $pub) | Should -BeNullOrEmpty
        $detail = Get-ChildItem -LiteralPath (Join-Path $r.Root 'detail') -Recurse -Filter 'sod-detail.json' | Get-Content -Raw
        $detail | Should -Match 'sofia\.reyes@contoso\.test'
    }

    It '-WhatIf writes nothing but still returns the violation count' {
        $r = Invoke-Fixture -Extra @{ WhatIf = $true }
        $r.Exit | Should -Be 7
        Test-Path -LiteralPath $r.Root | Should -BeFalse
    }

    It 'an unexpired exception takes a violation out of the exit code; an expired one does not' {
        foreach ($case in @(@{ Expires = '2027-01-31'; Exit = 6 }, @{ Expires = '2026-10-19'; Exit = 7 })) {
            $rules = Read-IgaJson $script:RulesPath
            $rules['exceptions'] = @(@{ ruleId = 'SOD-01'; userPrincipalName = 'sofia.reyes@contoso.test'; exceptionId = 'E7'; expires = $case.Expires; compensatingControls = 'test' })
            $p = Join-Path $TestDrive "rules-$($case.Exit).json"; $rules | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $p
            (Invoke-Fixture -RulesPath $p).Exit | Should -Be $case.Exit
        }
    }

    It 'refuses to write synthetic output into the public evidence tree: exit 255, nothing written there' {
        $pub = Join-Path $script:LabRoot 'evidence' 'sod'
        $before = Test-Path -LiteralPath $pub
        $global:LASTEXITCODE = 0
        & $script:Sod -InputPath $script:FixturePath -OutputDirectory $pub -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 255
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like '*public evidence tree*' }
        Test-Path -LiteralPath $pub | Should -Be $before
    }

    It 'refuses an identity-detail folder inside the public evidence tree: exit 255' {
        $global:LASTEXITCODE = 0
        & $script:Sod -InputPath $script:FixturePath -OutputDirectory (Join-Path $TestDrive 'p') -DetailDirectory (Join-Path $script:LabRoot 'evidence' 'sod-detail') -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 255
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like '*public evidence tree*' }
        Test-Path -LiteralPath (Join-Path $TestDrive 'p') | Should -BeFalse
    }

    It 'an invalid ruleset exits 255 (never 1, which would read as "1 open violation")' {
        $rules = Read-IgaJson $script:RulesPath
        $rules['rules'][0]['sideB']['accessPackages'] = @('Nope Apps')
        $p = Join-Path $TestDrive 'bad-rules.json'; $rules | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $p
        $r = Invoke-Fixture -RulesPath $p
        $r.Exit | Should -Be 255
        Test-Path -LiteralPath $r.Root | Should -BeFalse
    }

    It 'caps the exit code at 254 (255 is reserved for "could not read")' {
        $big = @{ asOf = '2026-10-20T12:00:00Z'; objects = @{ accessPackages = @('Nurse - Clinical Apps', 'Pharmacy - Controlled Substances Apps') }; users = @()
            holdings = @(1..260 | ForEach-Object { @{ userId = "u$_"; kind = 'accessPackages'; name = 'Nurse - Clinical Apps'; via = 'assignment' }; @{ userId = "u$_"; kind = 'accessPackages'; name = 'Pharmacy - Controlled Substances Apps'; via = 'assignment' } }) }
        $p = Join-Path $TestDrive 'big.json'; $big | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $p
        $global:LASTEXITCODE = 0
        & $script:Sod -InputPath $p -OutputDirectory (Join-Path $TestDrive 'big') -DetailDirectory (Join-Path $TestDrive 'bigd') -WhatIf | Out-Null
        $LASTEXITCODE | Should -Be 254
    }
}

Describe '09-SoD-Report.ps1 - holdings snapshot for the detective tripwires' {
    It 'writes the columns the KQL watchlist and the SPL lookup read, packages and groups only' {
        $snap = Join-Path $TestDrive 'out' 'sod_holdings.csv'
        $global:LASTEXITCODE = 0
        Mock Write-Host {}
        & $script:Sod -InputPath $script:FixturePath -OutputDirectory (Join-Path $TestDrive 'pub') -DetailDirectory (Join-Path $TestDrive 'det') -HoldingsSnapshotPath $snap | Out-Null
        $snap | Should -Exist
        $lines = @(Get-Content -LiteralPath $snap)
        $lines[0] | Should -Be 'UserObjectId,UserPrincipalName,Kind,Name,SnapshotTime'
        $rows = @($lines | ConvertFrom-Csv)
        $rows.Count | Should -BeGreaterThan 0
        @($rows.Kind | Sort-Object -Unique) | ForEach-Object { $_ | Should -BeIn @('AccessPackage', 'Group') }
        foreach ($r in $rows) { $r.SnapshotTime | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$' }
        # Same column names the twins read.
        $kql = Get-Content -LiteralPath (Join-Path $script:LabRoot 'kql' 'sod-violation-granted.kql') -Raw
        $spl = Get-Content -LiteralPath (Join-Path $script:LabRoot 'splunk' 'detections' 'sod-violation-granted.spl') -Raw
        foreach ($c in 'UserPrincipalName', 'Name', 'SnapshotTime') { $kql | Should -Match $c; $spl | Should -Match $c }
        $spl | Should -Match 'UserObjectId'
    }
    It 'refuses a snapshot path inside the public evidence tree (it holds object ids and UPNs): exit 255' {
        $global:LASTEXITCODE = 0
        Mock Write-Host {}
        $bad = Join-Path $script:LabRoot 'evidence' 'sod' 'sod_holdings.csv'
        & $script:Sod -InputPath $script:FixturePath -OutputDirectory (Join-Path $TestDrive 'pub2') -DetailDirectory (Join-Path $TestDrive 'det2') -HoldingsSnapshotPath $bad | Out-Null
        $LASTEXITCODE | Should -Be 255
        $bad | Should -Not -Exist
    }
}

Describe '09-SoD-Report.ps1 - tenant path (mocked Graph)' {
    BeforeAll {
        function Set-TenantMock {
            param([switch]$FailRoles, [hashtable]$Reports = @{}, [switch]$FailReports)
            $global:SodTest = @{ FailRoles = [bool]$FailRoles; Reports = $Reports; FailReports = [bool]$FailReports }
            Mock Get-MgContext { New-MgContextStub -Scopes @('EntitlementManagement.Read.All', 'GroupMember.Read.All', 'User.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup') }
            Mock Connect-MgGraph { throw 'tests must never connect' }
            Mock Invoke-MgGraphRequest {
                $u = [uri]::UnescapeDataString("$Uri")
                if ($Method -ne 'GET') { throw "read-only script wrote: $Method $u" }
                $pk = @{ 'Nurse - Clinical Apps' = 'ap-nurse'; 'Pharmacy - Controlled Substances Apps' = 'ap-pharm' }
                $gr = @{ 'Privileged-IAM-Admins' = 'g-iam'; 'App-Pharmacy-Dispensing-Users' = 'g-pharm'; 'IGA-Access-Reviewers' = 'g-rev' }
                $user = { param($id, [bool]$en = $true) @{ '@odata.type' = '#microsoft.graph.user'; id = $id; userPrincipalName = "$id@contoso.test"; displayName = $id; accountEnabled = $en } }
                if ($u -match "/accessPackages\?\`$filter=displayName eq '(?<n>.+)'&") { $n = $Matches.n; return @{ value = @($(if ($pk.ContainsKey($n)) { @{ id = $pk[$n]; displayName = $n } }) | Where-Object { $_ }) } }
                if ($u -match "/assignments\?\`$filter=accessPackage/id eq '(?<id>[^']+)' and state eq 'Delivered'") {
                    $t = switch ($Matches.id) { 'ap-nurse' { @('u-nurse', 'u-both') } 'ap-pharm' { @('u-both') } }
                    return @{ value = @($t | ForEach-Object { @{ id = "a-$_"; target = @{ objectId = $_; principalName = "$_@contoso.test"; displayName = $_ } } }) }
                }
                if ($u -match "/groups\?\`$filter=displayName eq '(?<n>.+)'&") { $n = $Matches.n; return @{ value = @($(if ($gr.ContainsKey($n)) { @{ id = $gr[$n]; displayName = $n } }) | Where-Object { $_ }) } }
                if ($u -like '*/groups/g-pharm/transitiveMembers/*') { return @{ value = @((& $user 'u-icu')) } }
                if ($u -like '*/groups/g-rev/transitiveMembers/*') { return @{ value = @((& $user 'u-admin'), (& $user 'u-rolegroup')) } }
                if ($u -like '*/groups/g-iam/transitiveMembers/*') { return @{ value = @() } }
                if ($u -like '*/groups/g-rolegrp/transitiveMembers/*') { return @{ value = @((& $user 'u-rolegroup')) } }
                if ($u -match "eligibilityScheduleInstances\?\`$filter=groupId eq 'g-iam'") { return @{ value = @(@{ accessId = 'member'; principalId = 'u-admin'; principal = (& $user 'u-admin') }) } }
                if ($u -match 'eligibilityScheduleInstances\?\$filter=groupId eq') { return @{ value = @() } }
                if ($u -like '*/roleManagement/directory/roleAssignmentScheduleInstances*') {
                    if ($global:SodTest.FailRoles) { throw 'HTTP 403 Forbidden' }
                    return @{ value = @(@{ roleDefinitionId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; principal = @{ '@odata.type' = '#microsoft.graph.group'; id = 'g-rolegrp' } }) }
                }
                if ($u -like '*/roleManagement/directory/roleEligibilityScheduleInstances*') { return @{ value = @() } }
                if ($u -match '/users/(?<id>[^/]+)/directReports/microsoft\.graph\.user') {
                    if ($global:SodTest.FailReports) { throw 'HTTP 403 Forbidden' }
                    $r = $global:SodTest.Reports
                    return @{ value = @(@($(if ($r.ContainsKey($Matches.id)) { $r[$Matches.id] })) | Where-Object { $_ } | ForEach-Object { @{ id = $_ } }) }
                }
                throw "unexpected Graph call in test: $Method $u"
            }
        }
    }
    AfterAll { Remove-Variable -Name SodTest -Scope Global -ErrorAction SilentlyContinue }

    It 'reads packages, transitive + PIM-eligible group members and role holders behind a group' {
        Set-TenantMock
        $global:LASTEXITCODE = 0
        $r = & $script:Sod -OutputDirectory (Join-Path $TestDrive 'tenant') -DetailDirectory (Join-Path $TestDrive 'tenantd') -WhatIf -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 3
        $v = @($r.Violations)
        @($v | ForEach-Object { "$($_.RuleId):$($_.UserId)" } | Sort-Object) | Should -Be @('SOD-01:u-both', 'SOD-08:u-admin', 'SOD-08:u-rolegroup')
        ($v | Where-Object UserId -eq 'u-admin').ActivationRequired | Should -BeTrue
        ($v | Where-Object UserId -eq 'u-rolegroup').SideA | Should -Be @('directoryRole:User Administrator[active-via-group]')
        $r.Report['source'] | Should -Be 'tenant'
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'reviewer of record: reads directReports of side-A holders only, and flags a manager of a T2 holder' {
        Set-TenantMock -Reports @{ 'u-rolegroup' = @('u-both') }
        $global:LASTEXITCODE = 0
        $r = & $script:Sod -OutputDirectory (Join-Path $TestDrive 'ror') -DetailDirectory (Join-Path $TestDrive 'rord') -WhatIf -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 3
        ($r.Violations | Where-Object UserId -eq 'u-rolegroup').SideB | Should -Contain 'reviewerOfRecord:T2-direct-report[manager]'
        Should -Invoke Invoke-MgGraphRequest -ParameterFilter { "$Uri" -like '*/users/u-nurse/directReports*' } -Times 0
        @($r.Report['dataSources'] | Where-Object { $_['name'] -eq 'directReports' -and $_['status'] -eq 'ok' }).Count | Should -Be 1
    }

    It 'an unreadable directReports source exits 255 (never reported as clean)' {
        Set-TenantMock -FailReports
        $global:LASTEXITCODE = 0
        & $script:Sod -OutputDirectory (Join-Path $TestDrive 'rorf') -DetailDirectory (Join-Path $TestDrive 'rorfd') -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 255
        Test-Path -LiteralPath (Join-Path $TestDrive 'rorf') | Should -BeFalse
    }

    It 'a source that cannot be read exits 255 and writes nothing' {
        Set-TenantMock -FailRoles
        $global:LASTEXITCODE = 0
        $out = Join-Path $TestDrive 'fail'
        & $script:Sod -OutputDirectory $out -DetailDirectory (Join-Path $TestDrive 'faild') -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 255
        Test-Path -LiteralPath $out | Should -BeFalse
    }
}

Describe 'Parity: helpers duplicated across the lab/iga scripts stay identical' {
    BeforeAll {
        function Get-FunctionText([string]$Rel, [string]$Name) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-LabScriptPath $Rel), [ref]$tokens, [ref]$errors)
            $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true) | Select-Object -First 1
            if (-not $f) { throw "$Name not found in $Rel" }
            return ($f.Extent.Text -replace '\s+', ' ')
        }
        $script:IgaScripts = @('09-SoD-Report.ps1', '10-Review-KPIs.ps1', 'post-apply/Set-AutoAssignmentPolicies.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1')
    }
    It '<Name> is the same in <Scripts>' -ForEach @(
        @{ Name = 'Read-IgaJson'; Scripts = @('09-SoD-Report.ps1', '10-Review-KPIs.ps1', 'post-apply/Set-AutoAssignmentPolicies.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1') }
        @{ Name = 'Get-CatalogEntry'; Scripts = @('09-SoD-Report.ps1', '10-Review-KPIs.ps1', 'post-apply/Set-AutoAssignmentPolicies.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1') }
        @{ Name = 'Get-GraphCollection'; Scripts = @('09-SoD-Report.ps1', '10-Review-KPIs.ps1', 'post-apply/Set-AutoAssignmentPolicies.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1') }
        @{ Name = 'Test-SodRuleSet'; Scripts = @('09-SoD-Report.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1') }
        @{ Name = 'Test-IsPublicEvidencePath'; Scripts = @('09-SoD-Report.ps1', '10-Review-KPIs.ps1') }
    ) {
        $texts = @($Scripts | ForEach-Object { Get-FunctionText $_ $Name })
        @($texts | Sort-Object -Unique).Count | Should -Be 1
    }
    It 'Test-PublicRecordSafe matches the existing copy in New-AccessReviewDefinitions.ps1 (same public-record rule)' {
        $body = { param($t) ($t -replace '^.*?param', 'param') }
        $ref = & $body (Get-FunctionText 'post-apply/New-AccessReviewDefinitions.ps1' 'Test-PublicRecordSafe')
        foreach ($s in '09-SoD-Report.ps1', '10-Review-KPIs.ps1') { & $body (Get-FunctionText $s 'Test-PublicRecordSafe') | Should -Be $ref }
    }
}

Describe 'Ruleset mirror: the KQL and SPL SoD tripwires match lab/iga/sod-rules.json' {
    BeforeAll {
        $script:Expected = @(foreach ($r in $script:Rules['rules']) {
                foreach ($side in 'A', 'B') {
                    $d = $r["side$side"]
                    foreach ($n in @($d['accessPackages'])) { if ($n) { "$($r['id'])|$side|AccessPackage|$n" } }
                    foreach ($n in @($d['groups'])) { if ($n) { "$($r['id'])|$side|Group|$n" } }
                }
            }) | Sort-Object
        $script:KqlText = Get-Content -LiteralPath (Join-Path $script:LabRoot 'kql' 'sod-violation-granted.kql') -Raw
        $script:SplText = Get-Content -LiteralPath (Join-Path $script:LabRoot 'splunk' 'detections' 'sod-violation-granted.spl') -Raw
    }

    It 'KQL SodSides lists exactly the package/group sides of every rule' {
        $block = [regex]::Match($script:KqlText, '(?s)let SodSides = datatable\([^)]*\) \[(?<rows>.*?)\];').Groups['rows'].Value
        $block | Should -Not -BeNullOrEmpty
        $rows = @([regex]::Matches($block, '"(?<id>SOD-\d{2})",\s*"(?<side>[AB])",\s*"(?<kind>AccessPackage|Group)",\s*"(?<name>[^"]+)"') | ForEach-Object { "$($_.Groups['id'].Value)|$($_.Groups['side'].Value)|$($_.Groups['kind'].Value)|$($_.Groups['name'].Value)" }) | Sort-Object
        $rows | Should -Be $script:Expected
    }

    It 'KQL SodRules carries every rule id, name and risk' {
        $block = [regex]::Match($script:KqlText, '(?s)let SodRules = datatable\([^)]*\) \[(?<rows>.*?)\];').Groups['rows'].Value
        $rows = @([regex]::Matches($block, '"(?<id>SOD-\d{2})",\s*"(?<name>[^"]+)",\s*"(?<risk>High|Medium|Low)"') | ForEach-Object { "$($_.Groups['id'].Value)|$($_.Groups['name'].Value)|$($_.Groups['risk'].Value)" }) | Sort-Object
        $rows | Should -Be @($script:Rules['rules'] | ForEach-Object { "$($_['id'])|$($_['name'])|$($_['risk'])" } | Sort-Object)
    }

    It 'KQL SodExceptions matches sod-rules.json exceptions (empty today)' {
        $block = [regex]::Match($script:KqlText, '(?s)let SodExceptions = datatable\([^)]*\) \[(?<rows>.*?)\];').Groups['rows'].Value
        @([regex]::Matches($block, '"SOD-\d{2}"')).Count | Should -Be @($script:Rules['exceptions'] | Where-Object { $_ }).Count
    }

    It 'SPL SodTags case() gives every name exactly its rule:side tags' {
        $line = @($script:SplText -split "`n" | Where-Object { $_ -match '^\| eval SodTags=case\(' })[0]
        $line | Should -Not -BeNullOrEmpty
        $got = @{}
        foreach ($m in [regex]::Matches($line, 'Name=="(?<name>[^"]+)", "(?<tags>[^"]+)"')) { $got[$m.Groups['name'].Value] = @($m.Groups['tags'].Value -split ' ' | Sort-Object) -join ' ' }
        $want = @{}
        foreach ($e in $script:Expected) { $id, $side, $kind, $name = $e -split '\|', 4; if (-not $want.ContainsKey($name)) { $want[$name] = @() }; $want[$name] += "${id}:$side" }
        @($got.Keys | Sort-Object) | Should -Be @($want.Keys | Sort-Object)
        foreach ($k in $want.Keys) { $got[$k] | Should -Be ((@($want[$k] | Sort-Object -Unique)) -join ' ') -Because $k }
    }

    It 'SPL RuleName / Risk case() lines carry every rule' {
        foreach ($r in $script:Rules['rules']) {
            $script:SplText | Should -Match ([regex]::Escape("RuleId==""$($r['id'])"", ""$($r['name'])"""))
            $script:SplText | Should -Match ([regex]::Escape("RuleId==""$($r['id'])"", ""$($r['risk'])"""))
        }
    }

    It 'SPL GrantedKind lists exactly the ruleset groups' {
        $line = @($script:SplText -split "`n" | Where-Object { $_ -match '^\| eval GrantedKind=' })[0]
        $names = @([regex]::Matches(([regex]::Match($line, 'in\(Name, (?<l>[^)]*)\)').Groups['l'].Value), '"(?<n>[^"]+)"') | ForEach-Object { $_.Groups['n'].Value }) | Sort-Object
        $names | Should -Be @($script:Expected | Where-Object { ($_ -split '\|')[2] -eq 'Group' } | ForEach-Object { ($_ -split '\|', 4)[3] } | Sort-Object -Unique)
    }
}
