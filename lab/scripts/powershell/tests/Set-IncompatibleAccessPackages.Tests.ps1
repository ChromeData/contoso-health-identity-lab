# Pester 5 tests for post-apply/Set-IncompatibleAccessPackages.ps1 (preventive
# SoD) and lab/iga/sod-rules.json.
#   * The ruleset: 5-10 rules, every name in the catalog, drivers + mitigation.
#   * The plan: the birthright rule (no link ON an automatic package), group
#     links, detective-only rules, de-duplication.
#   * Live path against an in-memory tenant (mocked Invoke-MgGraphRequest):
#     add, idempotent no-op, -Prune of the legacy Nurse -> Pharmacy link,
#     unmanaged links left alone, -WhatIf. No tenant is contacted.
#   * Since the ICU split (ADR 0012), 'ICU - Float Access' is the requestable
#     (T2) ICU path, so SOD-01 links sit on it as well as on Pharmacy.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Sia = Get-LabScriptPath 'post-apply/Set-IncompatibleAccessPackages.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Sia -Name 'Read-IgaJson', 'Get-CatalogEntry', 'Test-SodRuleSet', 'Test-IsBirthrightPackage', 'Get-DesiredIncompatibility')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:Rules = Read-IgaJson (Join-Path $script:LabRoot 'iga' 'sod-rules.json')
    $script:Catalog = Read-IgaJson (Join-Path $script:LabRoot 'iga' 'access-catalog.json')
    function Copy-Rules { return ($script:Rules | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50) }
    function Get-LinkKey($Plan) { @($Plan.Links | ForEach-Object { "$($_.From) X $($_.To)" }) }

    function Set-TenantMock {
        # Packages/groups that exist (name -> id) and the links already on each package.
        param([hashtable]$Packages = @{ 'Nurse - Clinical Apps' = 'ap-nurse'; 'ICU - Critical Care Apps' = 'ap-icu'; 'ICU - Float Access' = 'ap-icu-float'; 'Pharmacy - Controlled Substances Apps' = 'ap-pharm' },
            [hashtable]$Groups = @{ 'All-Nurses' = 'g-nurses'; 'All-ICU' = 'g-icu'; 'App-Pharmacy-Dispensing-Users' = 'g-pharm' },
            [hashtable]$PkgLinks = @{}, [hashtable]$GrpLinks = @{}, [switch]$FailLookups)
        $global:SiaTest = @{ Packages = $Packages; Groups = $Groups; PkgLinks = $PkgLinks; GrpLinks = $GrpLinks; Fail = [bool]$FailLookups
            Writes = [System.Collections.Generic.List[object]]::new() }
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('EntitlementManagement.ReadWrite.All', 'Group.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        Mock Invoke-MgGraphRequest {
            $t = $global:SiaTest; $u = [uri]::UnescapeDataString("$Uri")
            if ($Method -in 'POST', 'DELETE') { $t.Writes.Add(@{ Method = $Method; Uri = $u; Body = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }) }); return $null }
            if ($t.Fail) { throw 'HTTP 503 Service Unavailable' }
            $names = @{}; foreach ($k in $t.Packages.Keys) { $names[$t.Packages[$k]] = $k }; foreach ($k in $t.Groups.Keys) { $names[$t.Groups[$k]] = $k }
            if ($u -match "/accessPackages\?\`$filter=displayName eq '(?<n>.+)'&") { $n = $Matches.n.Replace("''", "'"); return @{ value = @($(if ($t.Packages.ContainsKey($n)) { @{ id = $t.Packages[$n]; displayName = $n } }) | Where-Object { $_ }) } }
            if ($u -match "/groups\?\`$filter=displayName eq '(?<n>.+)'&") { $n = $Matches.n.Replace("''", "'"); return @{ value = @($(if ($t.Groups.ContainsKey($n)) { @{ id = $t.Groups[$n]; displayName = $n } }) | Where-Object { $_ }) } }
            if ($u -match '/accessPackages/(?<id>[^/]+)/incompatibleAccessPackages\?') { return @{ value = @(@($t.PkgLinks[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ id = $_; displayName = $(if ($names.ContainsKey($_)) { $names[$_] } else { "Other package $_" }) } }) } }
            if ($u -match '/accessPackages/(?<id>[^/]+)/incompatibleGroups(\?|$)') { return @{ value = @(@($t.GrpLinks[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ id = $_; displayName = $(if ($names.ContainsKey($_)) { $names[$_] } else { "Other group $_" }) } }) } }
            throw "unexpected Graph call in test: $Method $u"
        }
    }
    # Everything SOD-01 wants, already in place: on Pharmacy and on the
    # requestable ICU - Float Access package.
    $script:Sod01InPlace = @{ PkgLinks = @{ 'ap-pharm' = @('ap-nurse', 'ap-icu', 'ap-icu-float'); 'ap-icu-float' = @('ap-pharm') }; GrpLinks = @{ 'ap-pharm' = @('g-nurses', 'g-icu'); 'ap-icu-float' = @('g-pharm') } }
    # The same plus the legacy Nurse -> Pharmacy link Set-AccessPackageSoD.ps1 used to write.
    $script:Sod01PlusLegacy = @{ PkgLinks = @{ 'ap-pharm' = @('ap-nurse', 'ap-icu', 'ap-icu-float'); 'ap-icu-float' = @('ap-pharm'); 'ap-nurse' = @('ap-pharm') }; GrpLinks = @{ 'ap-pharm' = @('g-nurses', 'g-icu'); 'ap-icu-float' = @('g-pharm') } }
}

AfterAll { Remove-Variable -Name SiaTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'lab/iga/sod-rules.json - contract' {
    It 'is valid against the catalog' { @(Test-SodRuleSet -Rules $script:Rules -Catalog $script:Catalog) | Should -BeNullOrEmpty }

    It 'has 5-10 rules, each with risk, drivers and a mitigating control' {
        $r = @($script:Rules['rules'])
        $r.Count | Should -BeGreaterOrEqual 5; $r.Count | Should -BeLessOrEqual 10
        foreach ($x in $r) { @($x['regulatoryDrivers']).Count | Should -BeGreaterThan 0; $x['mitigatingControlIfException'] | Should -Not -BeNullOrEmpty; $x['risk'] | Should -BeIn 'High', 'Medium', 'Low' }
    }

    It 'covers the clinical and finance pairs the programme names' {
        $names = @($script:Rules['rules'] | ForEach-Object { $_['name'] }) -join "`n"
        foreach ($p in 'Prescribe vs dispense', 'Order vs approve', 'vendor master', 'Payroll entry vs payroll approval', 'break-the-glass vs EHR audit-log', 'inventory', 'Identity administration vs access certification') {
            $names | Should -Match ([regex]::Escape($p))
        }
    }

    It 'keeps the original Nurse / Pharmacy pair (SOD-01 supersedes var.sod_incompatible_pairs)' {
        $r = $script:Rules['rules'] | Where-Object { $_['id'] -eq 'SOD-01' }
        $r['sideA']['accessPackages'] | Should -Contain 'Nurse - Clinical Apps'
        $r['sideB']['accessPackages'] | Should -Contain 'Pharmacy - Controlled Substances Apps'
        (Get-Content -LiteralPath (Join-Path $script:LabRoot 'terraform' 'modules' 'entitlement' 'variables.tf') -Raw) | Should -Match '\[\["nurse", "pharmacy"\]\]'
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'an entitlement not in the catalog'; Mutate = { param($r) $r['rules'][0]['sideB']['accessPackages'] = @('Nope Apps') }; Expect = '*not in access-catalog*' }
        @{ Case = 'the same entitlement on both sides'; Mutate = { param($r) $r['rules'][0]['sideB']['groups'] = @('All-Nurses') }; Expect = '*on both sides*' }
        @{ Case = 'a malformed id'; Mutate = { param($r) $r['rules'][0]['id'] = 'SOD-1' }; Expect = '*must look like SOD-01*' }
        @{ Case = 'a duplicate id'; Mutate = { param($r) $r['rules'][1]['id'] = 'SOD-01' }; Expect = '*Duplicate rule id*' }
        @{ Case = 'no regulatory driver'; Mutate = { param($r) $r['rules'][0]['regulatoryDrivers'] = @() }; Expect = '*regulatoryDrivers*' }
        @{ Case = 'an exception for an unknown rule'; Mutate = { param($r) $r['exceptions'] = @(@{ ruleId = 'SOD-99'; userPrincipalName = 'a@b.test'; exceptionId = 'E1'; expires = '2027-01-31' }) }; Expect = '*unknown rule*' }
        @{ Case = 'an exception without a valid expiry'; Mutate = { param($r) $r['exceptions'] = @(@{ ruleId = 'SOD-01'; userPrincipalName = 'a@b.test'; exceptionId = 'E1'; expires = 'soon' }) }; Expect = '*expires*' }
    ) {
        $r = Copy-Rules; & $Mutate $r
        (@(Test-SodRuleSet -Rules $r -Catalog $script:Catalog) -join "`n") | Should -BeLike $Expect
    }
}

Describe 'Get-DesiredIncompatibility - the plan' {
    BeforeAll { $script:Plan = Get-DesiredIncompatibility -Rules $script:Rules -Catalog $script:Catalog }

    It 'never puts a link ON a birthright (automatic) package' {
        $from = @($script:Plan.Links | ForEach-Object { $_.From } | Sort-Object -Unique)
        foreach ($b in 'Nurse - Clinical Apps', 'ICU - Critical Care Apps', 'Billing - Charge Entry & Coding Apps') { $from | Should -Not -Contain $b }
        @($script:Plan.SkippedBirthright | ForEach-Object { $_.From } | Sort-Object -Unique) | Should -Contain 'Nurse - Clinical Apps'
    }

    It 'writes SOD-01 on the requestable side only: Pharmacy X Nurse, ICU, ICU - Float Access, All-Nurses, All-ICU' {
        $k = Get-LinkKey $script:Plan
        foreach ($x in 'Nurse - Clinical Apps', 'ICU - Critical Care Apps', 'ICU - Float Access', 'All-Nurses', 'All-ICU') { $k | Should -Contain "Pharmacy - Controlled Substances Apps X $x" }
        $k | Should -Not -Contain 'Nurse - Clinical Apps X Pharmacy - Controlled Substances Apps'
        $k | Should -Not -Contain 'ICU - Critical Care Apps X Pharmacy - Controlled Substances Apps'
    }

    It 'the ICU split puts the float (T2) side under SOD-01: ICU - Float Access X Pharmacy and its dispensing group' {
        $k = Get-LinkKey $script:Plan
        $k | Should -Contain 'ICU - Float Access X Pharmacy - Controlled Substances Apps'
        $k | Should -Contain 'ICU - Float Access X App-Pharmacy-Dispensing-Users'
    }

    It 'writes both directions when both packages are requestable (SOD-05)' {
        $k = Get-LinkKey $script:Plan
        $k | Should -Contain 'Finance - Accounts Payable Apps X Finance - Vendor Master Data Apps'
        $k | Should -Contain 'Finance - Vendor Master Data Apps X Finance - Accounts Payable Apps'
    }

    It 'lists role/group-only rules as detective-only' {
        @($script:Plan.DetectiveOnly | ForEach-Object { $_.RuleId }) | Should -Be @('SOD-08')
    }

    It 'de-duplicates links that several rules ask for, keeping every rule id' {
        $keys = Get-LinkKey $script:Plan
        @($keys | Sort-Object -Unique).Count | Should -Be $keys.Count
        $l = $script:Plan.Links | Where-Object { $_.From -eq 'Pharmacy - Controlled Substances Apps' -and $_.To -eq 'Prescriber - CPOE Ordering Apps' }
        @($l.RuleIds) | Should -Be @('SOD-02')
    }

    It 'honours -RuleId' {
        $p = Get-DesiredIncompatibility -Rules $script:Rules -Catalog $script:Catalog -RuleId 'SOD-05'
        @($p.Links).Count | Should -Be 2
    }
}

Describe 'Set-IncompatibleAccessPackages.ps1 - live path (mocked Graph)' {
    BeforeEach { $global:LASTEXITCODE = 0 }

    It 'adds the missing SOD-01 links (packages and groups) and skips planned objects' {
        Set-TenantMock
        $out = @(& $script:Sia -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        $posts = @($global:SiaTest.Writes | Where-Object Method -eq 'POST')
        $posts.Count | Should -Be 7
        $onPharm = @($posts | Where-Object { $_.Uri -like '*/accessPackages/ap-pharm/incompatible*/$ref' })
        $onFloat = @($posts | Where-Object { $_.Uri -like '*/accessPackages/ap-icu-float/incompatible*/$ref' })
        ($onPharm.Count + $onFloat.Count) | Should -Be 7 -Because 'links sit only on the requestable packages, never on Nurse or ICU'
        @($onPharm | ForEach-Object { $_.Body['@odata.id'] } | Sort-Object) | Should -Be @(
            'https://graph.microsoft.com/v1.0/groups/g-icu', 'https://graph.microsoft.com/v1.0/groups/g-nurses',
            'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/ap-icu',
            'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/ap-icu-float',
            'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/ap-nurse')
        @($onFloat | ForEach-Object { $_.Body['@odata.id'] } | Sort-Object) | Should -Be @(
            'https://graph.microsoft.com/v1.0/groups/g-pharm',
            'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/ap-pharm')
        @($out | Where-Object Action -eq 'skipped-planned').Count | Should -BeGreaterThan 0
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'is idempotent: links already in place are not re-added' {
        Set-TenantMock @script:Sod01InPlace
        & $script:Sia -RuleId SOD-01 -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $global:SiaTest.Writes.Count | Should -Be 0
    }

    It 'the legacy Nurse -> Pharmacy link (Set-AccessPackageSoD.ps1) is drift that gates a birthright package: exit 1 without -Prune' {
        Set-TenantMock @script:Sod01PlusLegacy
        $out = @(& $script:Sia -RuleId SOD-01 -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object { $_.Package -eq 'Nurse - Clinical Apps' -and $_.Action -eq 'drift' }).Detail | Should -BeLike '*GATES A BIRTHRIGHT PACKAGE*'
        $global:SiaTest.Writes.Count | Should -Be 0
    }

    It '-Prune -WhatIf shows the removal without making it (exit 0)' {
        Set-TenantMock @script:Sod01PlusLegacy
        $out = @(& $script:Sia -RuleId SOD-01 -Prune -WhatIf -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        @($out | Where-Object Action -eq 'would-remove').Count | Should -Be 1
        $global:SiaTest.Writes.Count | Should -Be 0
    }

    It '-Prune removes the legacy link with DELETE .../$ref' {
        Set-TenantMock @script:Sod01PlusLegacy
        & $script:Sia -RuleId SOD-01 -Prune -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $w = @($global:SiaTest.Writes)
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'DELETE'
        $w[0].Uri | Should -BeLike '*/accessPackages/ap-nurse/incompatibleAccessPackages/ap-pharm/$ref'
    }

    It '-RuleId SOD-02 -Prune never removes the SOD-01 links on the same package (drift is judged against the full ruleset)' {
        Set-TenantMock @script:Sod01InPlace
        $out = @(& $script:Sia -RuleId SOD-02 -Prune -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        @($global:SiaTest.Writes | Where-Object Method -eq 'DELETE').Count | Should -Be 0
        @($out | Where-Object { $_.Action -in 'drift', 'removed', 'would-remove' }).Count | Should -Be 0
    }

    It '-RuleId SOD-02 without -Prune reports no false drift for the SOD-01 links' {
        Set-TenantMock @script:Sod01InPlace
        $out = @(& $script:Sia -RuleId SOD-02 -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        @($out | Where-Object Action -eq 'drift').Count | Should -Be 0
        $global:SiaTest.Writes.Count | Should -Be 0
    }

    It 'never touches a link to an object outside the catalog, even with -Prune' {
        $links = @{ PkgLinks = @{ 'ap-pharm' = @('ap-nurse', 'ap-icu', 'ap-icu-float', 'ap-other'); 'ap-icu-float' = @('ap-pharm') }; GrpLinks = @{ 'ap-pharm' = @('g-nurses', 'g-icu'); 'ap-icu-float' = @('g-pharm') } }
        Set-TenantMock @links
        $out = @(& $script:Sia -RuleId SOD-01 -Prune -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 0
        $global:SiaTest.Writes.Count | Should -Be 0
        @($out | Where-Object Action -eq 'unmanaged').Count | Should -Be 1
    }

    It '-WhatIf writes nothing' {
        Set-TenantMock
        & $script:Sia -WhatIf -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 0
        $global:SiaTest.Writes.Count | Should -Be 0
    }

    It 'a failed lookup is a failure (exit 1), never "nothing to do"' {
        Set-TenantMock -FailLookups
        $out = @(& $script:Sia -RuleId SOD-01 -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        @($out | Where-Object Action -eq 'failed').Count | Should -BeGreaterThan 0
        $global:SiaTest.Writes.Count | Should -Be 0
    }

    It 'a Terraform package missing from the tenant fails; a planned one is skipped' {
        Set-TenantMock -Packages @{ 'Nurse - Clinical Apps' = 'ap-nurse'; 'ICU - Critical Care Apps' = 'ap-icu' }
        $out = @(& $script:Sia -RuleId SOD-01, SOD-02 -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object { $_.Package -eq 'Pharmacy - Controlled Substances Apps' }).Action | Should -Contain 'failed'
        ($out | Where-Object { $_.Package -eq 'Prescriber - CPOE Ordering Apps' }).Action | Should -Contain 'skipped-planned'
    }
}

Describe 'Set-IncompatibleAccessPackages.ps1 -RenderOnly' {
    It 'returns the plan with no Graph call' {
        Mock Write-Host {}
        Mock Invoke-MgGraphRequest { throw 'no Graph in -RenderOnly' }
        $p = & $script:Sia -RenderOnly
        @($p.Links).Count | Should -BeGreaterThan 10
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }
}
