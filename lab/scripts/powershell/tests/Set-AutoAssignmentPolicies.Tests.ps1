# Pester 5 tests for post-apply/Set-AutoAssignmentPolicies.ps1 and the rule
# files it reads (lab/iga/birthright-rules.json, lab/iga/access-catalog.json).
#   * Contract: every HR-feed persona has a job profile; the catalog claims
#     only objects the Terraform source really defines; privileged access is
#     never birthright; no memberOf.
#   * Rule rendering + validation: the pure functions, loaded from the script's
#     syntax tree.
#   * Live path: the whole script against an in-memory tenant served by a
#     mocked Invoke-MgGraphRequest - create, idempotent no-op, drift -> PUT
#     merge, -WhatIf, refusals. No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Saa = Get-LabScriptPath 'post-apply/Set-AutoAssignmentPolicies.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Saa -Name 'Read-IgaJson', 'Get-CatalogEntry', 'ConvertFrom-IsoDuration', 'ConvertTo-RuleLiteral',
        'ConvertTo-MembershipRule', 'Test-BirthrightRuleSet', 'Get-DesiredAutoPolicy', 'ConvertTo-AutoPolicyBody', 'Get-PolicyRule', 'Compare-AutoPolicy', 'Merge-AutoPolicyBody', 'Get-HireDatePreflight')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:RulesPath = Join-Path $script:LabRoot 'iga' 'birthright-rules.json'
    $script:CatalogPath = Join-Path $script:LabRoot 'iga' 'access-catalog.json'
    $script:Rules = Read-IgaJson $script:RulesPath
    $script:Catalog = Read-IgaJson $script:CatalogPath
    function Copy-Rules { return ($script:Rules | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50) }

    function Set-TenantMock {
        # In-memory tenant: packages by name, their policies, resource scopes,
        # groups (isAssignableToRole) and assignments. Writes are recorded.
        param([hashtable]$Packages = @{ 'Nurse - Clinical Apps' = 'ap-nurse'; 'ICU - Critical Care Apps' = 'ap-icu'; 'Pharmacy - Controlled Substances Apps' = 'ap-pharm' },
            [hashtable]$Policies = @{},
            # Group scopes per package; the default matches access-catalog.json 'resources' (the guard compares the counts).
            [hashtable]$Resources = @{ 'ap-nurse' = @('g-sn', 'g-aws'); 'ap-icu' = @('g-sn', 'g-icu'); 'ap-pharm' = @('g-pharm') },
            [hashtable]$Groups = @{}, [object[]]$Assignments = @(), [string[]]$FailUris = @(),
            # pkgId -> the raw resourceRoleScopes response to return instead (shape tests).
            [hashtable]$RawScopes = @{},
            # Enabled Member users the hire-date preflight reads (department, employeeHireDate).
            [object[]]$Users = @(@{ id = 'u-dana'; department = 'Nursing'; employeeHireDate = '2026-10-19T00:00:00Z' }, @{ id = 'u-ava'; department = 'ICU'; employeeHireDate = '2022-01-10T00:00:00Z' }))
        $global:SaaTest = @{ Packages = $Packages; Policies = $Policies; Resources = $Resources; Groups = $Groups; Assignments = $Assignments; FailUris = $FailUris; RawScopes = $RawScopes; Users = $Users
            Writes = [System.Collections.Generic.List[object]]::new() }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('EntitlementManagement.ReadWrite.All', 'Group.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:SaaTest; $u = [uri]::UnescapeDataString("$Uri")
            foreach ($f in $t.FailUris) { if ($u -like $f) { throw "HTTP 403 Forbidden ($u)" } }
            if ($Method -in 'POST', 'PUT', 'DELETE', 'PATCH') {
                $t.Writes.Add(@{ Method = $Method; Uri = $u; Body = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable -Depth 50 } else { $null }) })
                if ($Method -eq 'POST') { return @{ id = 'pol-new' } }
                return $null
            }
            if ($u -match "accessPackages\?\`$filter=displayName eq '(?<n>.+)'&") {
                $n = $Matches.n.Replace("''", "'")
                return @{ value = @($(if ($t.Packages.ContainsKey($n)) { @{ id = $t.Packages[$n]; displayName = $n } })) | Where-Object { $_ } }
            }
            if ($u -match 'accessPackages/(?<id>[^/?]+)\?\$expand=resourceRoleScopes') {
                if ($t.RawScopes.ContainsKey($Matches.id)) { return $t.RawScopes[$Matches.id] }
                $rs = @($t.Resources[$Matches.id] | Where-Object { $_ } | ForEach-Object { @{ scope = @{ originSystem = 'AadGroup'; originId = $_ }; role = @{ originSystem = 'AadGroup' } } })
                return @{ id = $Matches.id; resourceRoleScopes = $rs }
            }
            if ($u -match 'accessPackages/(?<id>[^/?]+)\?\$expand=assignmentPolicies') {
                return @{ id = $Matches.id; assignmentPolicies = @(@($t.Policies[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ id = $_['id'] } }) }
            }
            if ($u -match 'assignmentPolicies/(?<id>[^/?]+)$') {
                foreach ($list in $t.Policies.Values) { foreach ($p in @($list)) { if ($p -and $p['id'] -eq $Matches.id) { return $p } } }
                throw "404 policy $($Matches.id)"
            }
            if ($u -match '/groups/(?<id>[^/?]+)\?\$select=id,displayName,isAssignableToRole') {
                if ($t.Groups.ContainsKey($Matches.id)) { return $t.Groups[$Matches.id] }
                return @{ id = $Matches.id; displayName = 'App-Group'; isAssignableToRole = $false }
            }
            if ($u -match '/users\?\$filter=accountEnabled eq true') { return @{ value = @($t.Users) } }
            if ($u -match "/assignments\?\`$filter=accessPackage/id eq '(?<id>[^']+)'") {
                return @{ value = @($t.Assignments | Where-Object { $_['pkg'] -eq $Matches.id }) }
            }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
    function New-AutoPolicy([string]$Id, [string]$Rule, [string]$Grace = 'P3D', [string]$Name = 'Nurse - Clinical Apps - birthright (HR attributes)') {
        @{
            id = $Id; displayName = $Name; description = $script:Rules['settings']['policyDescription']; allowedTargetScope = 'specificDirectoryUsers'
            createdDateTime = '2026-10-01T00:00:00Z'; modifiedDateTime = '2026-10-01T00:00:00Z'; '@odata.context' = 'x'
            specificAllowedTargets = @(@{ '@odata.type' = '#microsoft.graph.attributeRuleMembers'; description = 'r'; membershipRule = $Rule })
            automaticRequestSettings = @{ requestAccessForAllowedTargets = $true; removeAccessWhenTargetLeavesAllowedTargets = $true; gracePeriodBeforeAccessRemoval = $Grace }
            expiration = @{ type = 'noExpiration' }; requestorSettings = @{ enableTargetsToSelfAddAccess = $false }
        }
    }
    function Get-DesiredFor([string]$Package) { Get-DesiredAutoPolicy -Rules $script:Rules -MatchOn jobTitle | Where-Object Package -eq $Package }
}

AfterAll { Remove-Variable -Name SaaTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'lab/iga rule files - contract' {
    It 'every (department, jobTitle) in the mock HR feed has a job profile' {
        $csv = Join-Path $script:LabRoot 'scripts' 'mock-hr' 'hr_feed.csv'
        $rows = @(Get-Content -LiteralPath $csv | Where-Object { $_ -and $_ -notmatch '^\s*#' }) | ConvertFrom-Csv
        $rows.Count | Should -BeGreaterThan 5
        $have = @($script:Rules['jobProfiles'] | ForEach-Object { "$($_['department'])|$($_['jobTitle'])" })
        foreach ($r in $rows) { "$($r.dept)|$($r.jobTitle)" | Should -BeIn $have -Because "$($r.givenName) $($r.surname) needs a birthright decision (even an empty one)" }
    }

    It 'the shipped rule set is valid in jobTitle and jobCode mode' {
        @(Test-BirthrightRuleSet -Rules $script:Rules -Catalog $script:Catalog -MatchOn jobTitle) | Should -BeNullOrEmpty
        @(Test-BirthrightRuleSet -Rules $script:Rules -Catalog $script:Catalog -MatchOn jobCode) | Should -BeNullOrEmpty
    }

    It 'catalog entries marked terraform are really defined in lab/terraform' {
        $tf = (Get-ChildItem -LiteralPath (Join-Path $script:LabRoot 'terraform' 'modules') -Recurse -Filter '*.tf' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        foreach ($kind in 'accessPackages', 'groups') {
            foreach ($e in @($script:Catalog[$kind] | Where-Object { $_['status'] -eq 'terraform' })) {
                $tf | Should -Match ([regex]::Escape("`"$($e['name'])`"")) -Because "$kind '$($e['name'])' is marked terraform"
            }
        }
        foreach ($e in @($script:Catalog['accessPackages'] + $script:Catalog['groups'])) { $e['status'] | Should -BeIn @('terraform', 'planned') }
    }

    It 'directory role template ids are the documented built-in ids' {
        $ids = @{}; foreach ($r in $script:Catalog['directoryRoles']) { $ids[$r['name']] = $r['templateId'] }
        $ids['User Administrator'] | Should -Be 'fe930be7-5e62-47db-91af-98c3a49a38b1'     # same as modules/pim default
        $ids['Global Administrator'] | Should -Be '62e90394-69f5-4237-9190-012177145e10'
        $ids['Identity Governance Administrator'] | Should -Be '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e'
    }

    It 'privileged access is never birthright, and no rule uses memberOf' {
        foreach ($p in $script:Rules['jobProfiles']) {
            foreach ($b in @($p['birthright'])) {
                $e = Get-CatalogEntry -Catalog $script:Catalog -Kind accessPackages -Name $b
                $e['tier'] | Should -Be 'T3'
                foreach ($r in @($e['resources'])) { $r | Should -Not -Match '^(PIM-|Privileged-|Break-Glass)' }
            }
        }
        (Get-Content -LiteralPath $script:RulesPath -Raw) | Should -Not -Match '(?i)user\.memberof'
    }

    It 'the mover grace period is 72 hours (ADR 0012)' {
        (ConvertFrom-IsoDuration $script:Rules['settings']['gracePeriodBeforeAccessRemoval']).TotalHours | Should -Be 72
    }
}

Describe 'Membership rule rendering' {
    It 'renders the Nurse rule exactly (base conditions, department, sorted titles)' {
        (Get-DesiredFor 'Nurse - Clinical Apps').MembershipRule |
            Should -BeExactly '(user.accountEnabled -eq true) -and (user.userType -eq "Member") -and (user.employeeHireDate -le system.now) -and ((user.department -eq "Nursing" -and user.jobTitle -in ["Nurse Manager","Registered Nurse"]))'
    }

    It 'every rendered automatic-assignment rule starts with the accountEnabled gate (<MatchOn> mode)' -ForEach @(@{ MatchOn = 'jobTitle' }, @{ MatchOn = 'jobCode' }) {
        # Top-level AND clause, not nested in an -or: a disabled user must never
        # match any birthright package. A Graph read of the live ICU policy
        # (2026-11-07, PR #256) shows the same clause.
        $all = @(Get-DesiredAutoPolicy -Rules $script:Rules -MatchOn $MatchOn)
        $all.Count | Should -BeGreaterThan 0
        foreach ($d in $all) {
            $d.MembershipRule.StartsWith('(user.accountEnabled -eq true) -and ', [System.StringComparison]::Ordinal) |
                Should -BeTrue -Because "'$($d.Package)' renders: $($d.MembershipRule)"
        }
    }

    It 'uses the job-code attribute in jobCode mode' {
        $d = Get-DesiredAutoPolicy -Rules $script:Rules -MatchOn jobCode | Where-Object Package -eq 'ICU - Critical Care Apps'
        $d.MembershipRule | Should -Match 'user\.extensionAttribute1 -in \["NUR-MGR","NUR-RN"\]'
        $d.MembershipRule | Should -Not -Match 'jobTitle'
    }

    It 'ORs departments that grant the same package and is independent of profile order' {
        $s = $script:Rules['settings']
        $p1 = @(@{ department = 'B'; jobTitle = 'y' }, @{ department = 'A'; jobTitle = 'x' }, @{ department = 'A'; jobTitle = 'w' })
        $r1 = ConvertTo-MembershipRule -Profiles $p1 -Settings $s -MatchOn jobTitle
        $r2 = ConvertTo-MembershipRule -Profiles @($p1[2], $p1[0], $p1[1]) -Settings $s -MatchOn jobTitle
        $r1 | Should -BeExactly $r2
        $r1 | Should -Match '\(\(user\.department -eq "A" -and user\.jobTitle -in \["w","x"\]\) -or \(user\.department -eq "B"'
    }

    It 'escapes double quotes with a backtick and refuses control characters' {
        ConvertTo-RuleLiteral 'Nurse "Float"' | Should -BeExactly '"Nurse `"Float`""'
        { ConvertTo-RuleLiteral "Nurse`nManager" } | Should -Throw '*Control character*'
        { ConvertTo-RuleLiteral ' ' } | Should -Throw '*Empty*'
    }

    It 'shapes the Graph body like the Learn create example' {
        $b = ConvertTo-AutoPolicyBody -Desired (Get-DesiredFor 'Nurse - Clinical Apps') -AccessPackageId 'ap-nurse'
        $b['allowedTargetScope'] | Should -Be 'specificDirectoryUsers'
        $b['specificAllowedTargets'][0]['@odata.type'] | Should -Be '#microsoft.graph.attributeRuleMembers'
        $b['automaticRequestSettings']['gracePeriodBeforeAccessRemoval'] | Should -Be 'P3D'
        $b['automaticRequestSettings']['removeAccessWhenTargetLeavesAllowedTargets'] | Should -BeTrue
        $b['accessPackage']['id'] | Should -Be 'ap-nurse'
        $b.Contains('expiration') | Should -BeFalse   # an automatic policy never gets the 180-day expiry
    }
}

Describe 'Test-BirthrightRuleSet refuses unsafe rules' {
    It 'refuses <Case>' -ForEach @(
        @{ Case = 'a request-only (T2) package as birthright'; Mutate = { param($r) $r['jobProfiles'][0]['birthright'] = @('Pharmacy - Controlled Substances Apps') }; Expect = '*only T3*' }
        @{ Case = 'a package not in the catalog'; Mutate = { param($r) $r['jobProfiles'][0]['birthright'] = @('Imaginary Apps') }; Expect = '*not in access-catalog*' }
        @{ Case = 'memberOf in a base condition'; Mutate = { param($r) $r['settings']['baseConditions'] = @('user.memberOf -any (group.objectId -in ["x"])') }; Expect = '*memberOf*' }
        @{ Case = 'a grace period that is not a duration'; Mutate = { param($r) $r['settings']['gracePeriodBeforeAccessRemoval'] = '72 hours' }; Expect = '*ISO 8601*' }
        @{ Case = 'a duplicate job profile'; Mutate = { param($r) $r['jobProfiles'] += $r['jobProfiles'][0] }; Expect = '*Duplicate*' }
        @{ Case = 'a non-user attribute'; Mutate = { param($r) $r['settings']['attributes']['jobTitle'] = 'device.displayName' }; Expect = '*not a user property*' }
        @{ Case = 'a rule over the length limit'; Mutate = { param($r) $r['settings']['maxRuleLength'] = 50 }; Expect = '*limit 50*' }
        @{ Case = 'a requestable package that has no request policy'; Mutate = { param($r) $r['jobProfiles'][0]['requestable'] = @('Radiology - Imaging Apps') }; Expect = '*cannot be requested*' }
        @{ Case = 'no hire-date gate (birthright before day one)'; Mutate = { param($r) $r['settings']['baseConditions'] = @('user.accountEnabled -eq true', 'user.userType -eq "Member"') }; Expect = '*employeeHireDate*' }
        @{ Case = 'no accountEnabled condition'; Mutate = { param($r) $r['settings']['baseConditions'] = @('user.userType -eq "Member"', 'user.employeeHireDate -le system.now') }; Expect = '*accountEnabled*' }
    ) {
        $r = Copy-Rules; & $Mutate $r
        (@(Test-BirthrightRuleSet -Rules $r -Catalog $script:Catalog -MatchOn jobTitle) -join "`n") | Should -BeLike $Expect
    }

    It 'refuses a birthright package whose resources include a privileged group' {
        $cat = $script:Catalog | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
        ($cat['accessPackages'] | Where-Object { $_['name'] -eq 'Nurse - Clinical Apps' })['resources'] += 'Privileged-IAM-Admins'
        (@(Test-BirthrightRuleSet -Rules $script:Rules -Catalog $cat -MatchOn jobTitle) -join "`n") | Should -BeLike '*never birthright*'
    }

    It 'the script throws before any Graph call when the rules are unsafe' {
        Set-TenantMock
        $bad = Join-Path $TestDrive 'bad-rules.json'
        $r = Copy-Rules; $r['jobProfiles'][0]['birthright'] = @('Pharmacy - Controlled Substances Apps')
        $r | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $bad
        { & $script:Saa -RulesPath $bad -Confirm:$false -WarningAction SilentlyContinue } | Should -Throw '*not safe to apply*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }
}

Describe 'Compare-AutoPolicy / Merge-AutoPolicyBody' {
    It 'treats P3D and PT72H, and whitespace-only rule changes, as in sync' {
        $d = Get-DesiredFor 'Nurse - Clinical Apps'
        $e = New-AutoPolicy 'p1' ($d.MembershipRule -replace ' -and ', "  -and`n ") 'PT72H'
        @(Compare-AutoPolicy -Existing $e -Desired $d) | Should -BeNullOrEmpty
    }

    It 'names every drifted owned field' {
        $d = Get-DesiredFor 'Nurse - Clinical Apps'
        $e = New-AutoPolicy 'p1' '(user.department -eq "Nursing")' 'P7D'
        $e['automaticRequestSettings']['removeAccessWhenTargetLeavesAllowedTargets'] = $false
        @(Compare-AutoPolicy -Existing $e -Desired $d) | Should -Be @('membershipRule', 'removeAccessWhenTargetLeavesAllowedTargets', 'gracePeriodBeforeAccessRemoval')
    }

    It 'merges: keeps what the service returned, drops read-only fields, overlays the owned ones' {
        $d = Get-DesiredFor 'Nurse - Clinical Apps'
        $m = Merge-AutoPolicyBody -Existing (New-AutoPolicy 'p1' 'old rule' 'P7D') -Desired $d -AccessPackageId 'ap-nurse'
        $m.Contains('id') | Should -BeFalse; $m.Contains('createdDateTime') | Should -BeFalse; $m.Contains('@odata.context') | Should -BeFalse
        $m['expiration']['type'] | Should -Be 'noExpiration'
        $m['requestorSettings'].Contains('enableTargetsToSelfAddAccess') | Should -BeTrue
        $m['specificAllowedTargets'][0]['membershipRule'] | Should -Be $d.MembershipRule
        $m['automaticRequestSettings']['gracePeriodBeforeAccessRemoval'] | Should -Be 'P3D'
        $m['accessPackage']['id'] | Should -Be 'ap-nurse'
    }
}

Describe 'Set-AutoAssignmentPolicies.ps1 - live path (mocked Graph)' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'creates one automatic policy per Terraform birthright package and skips planned ones' {
        Set-TenantMock
        $out = @(& $script:Saa -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        $posts = @($global:SaaTest.Writes | Where-Object Method -eq 'POST')
        $posts.Count | Should -Be 2
        @($posts | ForEach-Object { $_.Body['accessPackage']['id'] } | Sort-Object) | Should -Be @('ap-icu', 'ap-nurse')
        foreach ($p in $posts) { $p.Uri | Should -BeLike '*/identityGovernance/entitlementManagement/assignmentPolicies'; $p.Body['allowedTargetScope'] | Should -Be 'specificDirectoryUsers' }
        @($out | Where-Object Action -eq 'skipped-planned' | ForEach-Object { $_.Package } | Sort-Object) | Should -Be @('Billing - Charge Entry & Coding Apps', 'Radiology - Imaging Apps')
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'is idempotent: an automatic policy that already matches gets no write' {
        $nurse = Get-DesiredFor 'Nurse - Clinical Apps'; $icu = Get-DesiredFor 'ICU - Critical Care Apps'
        Set-TenantMock -Policies @{
            'ap-nurse' = @((New-AutoPolicy 'pol-n' $nurse.MembershipRule), @{ id = 'pol-n-req'; displayName = 'Nurse - 180 day'; automaticRequestSettings = $null })
            'ap-icu'   = @((New-AutoPolicy 'pol-i' $icu.MembershipRule 'P3D' $icu.DisplayName))
        }
        $out = @(& $script:Saa -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        $global:SaaTest.Writes.Count | Should -Be 0
        @($out | Where-Object Action -eq 'in-sync').Count | Should -Be 2
    }

    It 'drift: PUTs the merged policy to the existing automatic policy' {
        Set-TenantMock -Policies @{ 'ap-nurse' = @(New-AutoPolicy 'pol-n' '(user.department -eq "Nursing")' 'P7D') }
        & $script:Saa -AccessPackage 'Nurse - Clinical Apps' -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $w = @($global:SaaTest.Writes)
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'PUT'
        $w[0].Uri | Should -BeLike '*/assignmentPolicies/pol-n'
        $w[0].Body['expiration']['type'] | Should -Be 'noExpiration'
        $w[0].Body['automaticRequestSettings']['gracePeriodBeforeAccessRemoval'] | Should -Be 'P3D'
    }

    It '-WhatIf writes nothing and exits 0' {
        Set-TenantMock
        $out = @(& $script:Saa -WhatIf -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        $global:SaaTest.Writes.Count | Should -Be 0
        @($out | Where-Object Action -eq 'would-create').Count | Should -Be 2
    }

    It 'refuses a package with two automatic policies (overlap unsupported), exit 1' {
        $nurse = Get-DesiredFor 'Nurse - Clinical Apps'
        Set-TenantMock -Policies @{ 'ap-nurse' = @((New-AutoPolicy 'a1' $nurse.MembershipRule), (New-AutoPolicy 'a2' $nurse.MembershipRule)) }
        $out = @(& $script:Saa -AccessPackage 'Nurse - Clinical Apps' -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Action | Should -Be 'failed'
        $global:SaaTest.Writes.Count | Should -Be 0
    }

    It 'fails closed when the package reaches a role-assignable group' {
        Set-TenantMock -Resources @{ 'ap-nurse' = @('g-priv', 'g-aws') } -Groups @{ 'g-priv' = @{ id = 'g-priv'; displayName = 'Some-Admins'; isAssignableToRole = $true } }
        $out = @(& $script:Saa -AccessPackage 'Nurse - Clinical Apps' -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Detail | Should -BeLike '*never birthright*'
        $global:SaaTest.Writes.Count | Should -Be 0
    }

    It 'fails closed when the privileged-resource response <Case>' -ForEach @(
        @{ Case = 'has no resourceRoleScopes key'; Raw = @{ id = 'ap-nurse' } }
        @{ Case = 'has a scope without originId'; Raw = @{ id = 'ap-nurse'; resourceRoleScopes = @(@{ scope = @{ originSystem = 'AadGroup' } }, @{ scope = @{ originSystem = 'AadGroup'; originId = 'g-aws' } }) } }
        @{ Case = 'has a scope without originSystem'; Raw = @{ id = 'ap-nurse'; resourceRoleScopes = @(@{ scope = @{ originId = 'g-sn' } }, @{ scope = @{ originSystem = 'AadGroup'; originId = 'g-aws' } }) } }
        @{ Case = 'is empty while the catalog lists two groups'; Raw = @{ id = 'ap-nurse'; resourceRoleScopes = @() } }
        @{ Case = 'lists fewer group scopes than the catalog'; Raw = @{ id = 'ap-nurse'; resourceRoleScopes = @(@{ scope = @{ originSystem = 'AadGroup'; originId = 'g-sn' } }) } }
    ) {
        Set-TenantMock -RawScopes @{ 'ap-nurse' = $Raw }
        $out = @(& $script:Saa -AccessPackage 'Nurse - Clinical Apps' -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Action | Should -Be 'failed'
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Detail | Should -BeLike '*failing closed*'
        $global:SaaTest.Writes.Count | Should -Be 0
    }

    It 'fails closed when the privileged-resource check cannot be read' {
        Set-TenantMock -FailUris @('*resourceRoleScopes*')
        & $script:Saa -AccessPackage 'Nurse - Clinical Apps' -Confirm:$false -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 1
        $global:SaaTest.Writes.Count | Should -Be 0
    }

    It 'a Terraform package missing from the tenant is a failure, not a skip' {
        Set-TenantMock -Packages @{ 'ICU - Critical Care Apps' = 'ap-icu' }
        $out = @(& $script:Saa -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Action | Should -Be 'failed'
    }

    It 'reports (never deletes) an automatic policy on a request-only package' {
        Set-TenantMock -Policies @{ 'ap-pharm' = @(New-AutoPolicy 'pp' '(user.department -eq "Pharmacy")' 'P3D' 'Pharmacy auto') }
        $out = @(& $script:Saa -Confirm:$false -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Pharmacy - Controlled Substances Apps').Action | Should -Be 'drift-found'
        @($global:SaaTest.Writes | Where-Object Method -in 'DELETE', 'PUT').Count | Should -Be 0
    }

    It 'warns about assignments still held through an expiring request policy' {
        $nurse = Get-DesiredFor 'Nurse - Clinical Apps'
        Set-TenantMock -Policies @{ 'ap-nurse' = @(New-AutoPolicy 'pol-n' $nurse.MembershipRule) } -Assignments @(
            @{ pkg = 'ap-nurse'; id = 'a1'; assignmentPolicy = @{ id = 'pol-n-req' }; schedule = @{ expiration = @{ endDateTime = '2027-04-01T00:00:00Z' } } },
            @{ pkg = 'ap-nurse'; id = 'a2'; assignmentPolicy = @{ id = 'pol-n' }; schedule = @{ expiration = @{ endDateTime = $null } } })
        & $script:Saa -AccessPackage 'Nurse - Clinical Apps' -Confirm:$false -WarningVariable wv -WarningAction SilentlyContinue | Out-Null
        ($wv -join "`n") | Should -Match '1 assignment\(s\) are still held through an EXPIRING request policy \(first ends 2027-04-01\)'
    }
}

Describe 'Set-AutoAssignmentPolicies.ps1 -RenderOnly' {
    It 'renders every birthright package with no Graph call' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'no Graph in -RenderOnly' }
        $d = @(& $script:Saa -RenderOnly)
        @($d.Package) | Should -Be @('Billing - Charge Entry & Coding Apps', 'ICU - Critical Care Apps', 'Nurse - Clinical Apps', 'Radiology - Imaging Apps')
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }
}

Describe 'Set-AutoAssignmentPolicies.ps1 - hire-date preflight' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'Get-HireDatePreflight counts in-scope users and those with a hire date' {
        $r = Get-HireDatePreflight -Users @(@{ department = 'Nursing'; employeeHireDate = '2026-01-01T00:00:00Z' }, @{ department = 'Nursing'; employeeHireDate = $null }, @{ department = 'Billing'; employeeHireDate = '2020-01-01T00:00:00Z' }) -Departments 'Nursing', 'ICU'
        $r.InScope | Should -Be 2
        $r.WithHireDate | Should -Be 1
        $r.Missing | Should -Be 1
    }

    It 'refuses (nothing sent) when no in-scope user has employeeHireDate - the policies would assign nobody' {
        Set-TenantMock -Users @(@{ id = 'u-1'; department = 'Nursing'; employeeHireDate = $null }, @{ id = 'u-2'; department = 'ICU' })
        { & $script:Saa -Confirm:$false -WarningAction SilentlyContinue } | Should -Throw '*Hire-date preflight*NONE has employeeHireDate*'
        $global:SaaTest.Writes.Count | Should -Be 0
    }

    It 'refuses when the birthright departments have nobody at all yet' {
        Set-TenantMock -Users @()
        { & $script:Saa -Confirm:$false -WarningAction SilentlyContinue } | Should -Throw '*Hire-date preflight: 0 enabled*'
        $global:SaaTest.Writes.Count | Should -Be 0
    }

    It 'proceeds, warning by count, when only some in-scope users lack a hire date' {
        Set-TenantMock -Users @(@{ id = 'u-1'; department = 'Nursing'; employeeHireDate = '2026-10-19T00:00:00Z' }, @{ id = 'u-2'; department = 'Nursing'; employeeHireDate = $null })
        & $script:Saa -Confirm:$false -WarningVariable wv -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        ($wv -join "`n") | Should -Match '1 of 2 in-scope user\(s\) have no employeeHireDate'
        @($global:SaaTest.Writes | Where-Object Method -eq 'POST').Count | Should -Be 2
    }
}
