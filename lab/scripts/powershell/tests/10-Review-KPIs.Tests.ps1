# Pester 5 tests for 10-Review-KPIs.ps1 (ADR 0012 review KPIs).
#   * KPI maths on hand-built decision rows: completion counts PEOPLE only,
#     zero denominators are "not-measured" (never 0), rubber-stamp edges
#     (item threshold, approve-all, median gap within an instance, ties),
#     approve-against-recommendation, tiering, birthright scope, lockouts.
#   * End to end on lab/iga/fixtures/review-decisions.json (synthetic): the
#     headline numbers, exit 2 on lockouts, public-safe hashed snapshot,
#     -WhatIf, synthetic output refused in the public evidence tree.
#   * Tenant path on a mocked Invoke-MgGraphRequest, and a failing source.
# No tenant is contacted; nothing is written outside TestDrive.

BeforeDiscovery {
    # -ForEach data is built at discovery time, so its helper lives here.
    function New-PkgDef([string]$Pkg, [string]$Pol, [string]$Name = 'x') {
        @{ displayName = $Name; scope = @{ query = "/identityGovernance/entitlementManagement/accessPackageAssignments?`$filter=(accessPackageId eq '$Pkg' and assignmentPolicyId eq '$Pol')"; queryType = 'MicrosoftGraph' } }
    }
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Kpi = Get-LabScriptPath '10-Review-KPIs.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Kpi -Name 'Read-IgaJson', 'Get-CatalogEntry', 'Test-PublicRecordSafe', 'Get-Field', 'Get-Pct', 'Get-Median', 'Get-ScopeQuery',
        'Get-ReviewTier', 'Test-IsHumanDecision', 'ConvertTo-DecisionRow', 'Get-KpiValue', 'Measure-TierKpi', 'Get-ReviewerGapSecond', 'Measure-ReviewerKpi',
        'Measure-RubberStamp', 'Test-InBirthrightScope', 'Test-HasBirthrightProfile', 'Test-IsLockoutCandidateRow', 'Measure-ClinicalLockout')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:Catalog = Read-IgaJson (Join-Path $script:LabRoot 'iga' 'access-catalog.json')
    $script:Birthright = Read-IgaJson (Join-Path $script:LabRoot 'iga' 'birthright-rules.json')
    $script:FixturePath = Join-Path $script:LabRoot 'iga' 'fixtures' 'review-decisions.json'
    $script:T0 = [datetime]::new(2026, 9, 1, 9, 0, 0, [DateTimeKind]::Utc)

    function New-Row {
        # One decision row as ConvertTo-DecisionRow builds it.
        param([string]$Decision = 'Approve', [string]$Rec = 'Approve', [string]$Reviewer = 'r1', [int]$Sec = 0, [string]$Instance = 'i1',
            [string]$Tier = 'T2', [bool]$Human = $true, [bool]$Just = $true, [string]$Principal = 'p1', [string]$Package = $null, [string]$Apply = 'New')
        [pscustomobject]@{ Tier = $Tier; Package = $Package; DefinitionId = 'd1'; InstanceId = $Instance; Decision = $Decision; Recommendation = $Rec
            IsHuman = $Human; ReviewerId = $(if ($Human) { $Reviewer } else { '' }); ReviewerUpn = ''; ReviewedAt = $script:T0.AddSeconds($Sec)
            HasJustification = $Just; ApplyResult = $Apply; Removed = ($Decision -eq 'Deny') -or ($Decision -eq 'NotReviewed' -and $Apply -eq 'AppliedSuccessfully'); PrincipalId = $Principal }
    }
    function New-Rows([int]$Count, [int]$GapSec, [string]$Reviewer = 'r1', [int]$DenyAt = -1) {
        @(0..($Count - 1) | ForEach-Object { New-Row -Decision $(if ($_ -eq $DenyAt) { 'Deny' } else { 'Approve' }) -Reviewer $Reviewer -Sec ($_ * $GapSec) })
    }
    $script:PkgById = @{ 'ap-nurse' = 'Nurse - Clinical Apps'; 'ap-icu' = 'ICU - Critical Care Apps'; 'ap-icu-float' = 'ICU - Float Access'; 'ap-pharm' = 'Pharmacy - Controlled Substances Apps'; 'ap-x' = 'Not In Catalog' }
    $script:PolById = @{ 'pn-auto' = @{ automatic = $true }; 'pn-req' = @{ automatic = $false }; 'pi-req' = @{ automatic = $false }; 'pf-req' = @{ automatic = $false }; 'pp-req' = @{ automatic = $false } }
    Mock Write-Host {}
}

Describe 'Basic maths' {
    It 'median: odd, even, single, empty' {
        Get-Median -Values @(5, 1, 3) | Should -Be 3
        Get-Median -Values @(4, 1, 3, 2) | Should -Be 2.5
        Get-Median -Values @(7) | Should -Be 7
        Get-Median -Values @() | Should -BeNullOrEmpty
    }
    It 'a percentage with no denominator is null, not 0' {
        Get-Pct 0 0 | Should -BeNullOrEmpty
        Get-Pct 1 3 | Should -Be 33.3
    }
}

Describe 'Who counts as a reviewer' {
    It '<Case>' -ForEach @(
        @{ Case = 'a person who decided'; D = @{ decision = 'Approve'; reviewedBy = @{ id = 'u1'; displayName = 'Pat' } }; Expect = $true }
        @{ Case = 'NotReviewed'; D = @{ decision = 'NotReviewed'; reviewedBy = @{ id = 'u1'; displayName = 'Pat' } }; Expect = $false }
        @{ Case = 'the all-zero id Graph uses for "not reviewed"'; D = @{ decision = 'Deny'; reviewedBy = @{ id = '00000000-0000-0000-0000-000000000000'; displayName = '' } }; Expect = $false }
        @{ Case = 'an empty reviewer'; D = @{ decision = 'Deny'; reviewedBy = @{ id = ''; displayName = '' } }; Expect = $false }
        @{ Case = 'the service applying a default'; D = @{ decision = 'Deny'; reviewedBy = @{ id = 'svc'; displayName = 'AAD Access Reviews' } }; Expect = $false }
    ) {
        Test-IsHumanDecision -Decision $D -SystemReviewerNames @('AAD Access Reviews') | Should -Be $Expect
    }

    It 'a decision row records removals: any Deny, or NotReviewed whose outcome was applied' {
        $tier = @{ Tier = 'T3'; Package = 'Nurse - Clinical Apps' }
        (ConvertTo-DecisionRow -Decision @{ decision = 'Deny'; reviewedBy = @{ id = ''; displayName = 'AAD Access Reviews' } } -TierInfo $tier -SystemReviewerNames 'AAD Access Reviews').Removed | Should -BeTrue
        (ConvertTo-DecisionRow -Decision @{ decision = 'NotReviewed'; applyResult = 'AppliedSuccessfully' } -TierInfo $tier).Removed | Should -BeTrue
        (ConvertTo-DecisionRow -Decision @{ decision = 'NotReviewed'; applyResult = 'New' } -TierInfo $tier).Removed | Should -BeFalse
        (ConvertTo-DecisionRow -Decision @{ decision = 'Approve'; reviewedBy = @{ id = 'u1' }; reviewedDateTime = '2026-09-01T09:00:00Z' } -TierInfo $tier).ReviewedAt.Kind | Should -Be 'Utc'
    }
}

Describe 'Measure-TierKpi' {
    It 'no decisions -> every KPI not-measured (never 0)' {
        $k = Measure-TierKpi -Rows @()
        $k['completion']['status'] | Should -Be 'not-measured'; $k['completion']['value'] | Should -BeNullOrEmpty
        $k['revocation']['status'] | Should -Be 'not-measured'
    }
    It 'all unanswered -> completion 0 measured, revocation not-measured' {
        $k = Measure-TierKpi -Rows @((New-Row -Decision NotReviewed -Human $false), (New-Row -Decision NotReviewed -Human $false))
        $k['completion']['value'] | Should -Be 0; $k['completion']['status'] | Should -Be 'measured'
        $k['revocation']['status'] | Should -Be 'not-measured'
    }
    It 'a default the service applied does not count as completed' {
        $k = Measure-TierKpi -Rows @((New-Row), (New-Row -Decision Deny -Human $false))
        $k['completion']['value'] | Should -Be 50; $k['decidedBySystem'] | Should -Be 1
        $k['revocation']['value'] | Should -Be 0
    }
    It 'approve against recommendation: rate over items recommended Deny, and the unjustified ones' {
        $k = Measure-TierKpi -Rows @((New-Row -Rec Deny -Just $true), (New-Row -Rec Deny -Just $false), (New-Row -Decision Deny -Rec Deny), (New-Row))
        $k['approveAgainstRecommendation']['value'] | Should -Be 66.7
        $k['approveAgainstRecommendation']['numerator'] | Should -Be 2
        $k['approveAgainstRecommendationWithoutJustification'] | Should -Be 1
    }
}

Describe 'Rubber-stamp detection (ADR 0012: >= 10 items AND (approved all OR median gap < 5 s))' {
    It 'measures gaps within an instance only, sorted, ties = 0 s' {
        $rows = @((New-Row -Sec 30), (New-Row -Sec 0), (New-Row -Sec 30), (New-Row -Sec 100000 -Instance 'i2'), (New-Row -Sec 100010 -Instance 'i2'))
        @(Get-ReviewerGapSecond -Rows $rows | Sort-Object) | Should -Be @(0, 10, 30)
    }
    It '<Case>' -ForEach @(
        @{ Case = '10 approvals, slow -> approved all';            Rows = { New-Rows 10 120 };            Eligible = $true;  All = $true;  Fast = $false; Stamp = $true }
        @{ Case = '9 approvals in 1 s -> below the item threshold'; Rows = { New-Rows 9 1 };              Eligible = $false; All = $false; Fast = $false; Stamp = $false }
        @{ Case = '10 items, one deny, 2 s apart -> fast median';   Rows = { New-Rows 10 2 -DenyAt 4 };   Eligible = $true;  All = $false; Fast = $true;  Stamp = $true }
        @{ Case = '10 items, one deny, 60 s apart -> fine';         Rows = { New-Rows 10 60 -DenyAt 4 };  Eligible = $true;  All = $false; Fast = $false; Stamp = $false }
        @{ Case = 'exactly 5 s median -> not under 5 s';            Rows = { New-Rows 10 5 -DenyAt 4 };   Eligible = $true;  All = $false; Fast = $false; Stamp = $false }
        @{ Case = 'bulk approve-all (identical timestamps)';        Rows = { New-Rows 12 0 };             Eligible = $true;  All = $true;  Fast = $true;  Stamp = $true }
    ) {
        $r = @(Measure-ReviewerKpi -Rows (& $Rows) -MinItems 10 -GapSeconds 5)
        $r.Count | Should -Be 1
        $r[0].Eligible | Should -Be $Eligible; $r[0].ApprovedAll | Should -Be $All; $r[0].FastMedian | Should -Be $Fast; $r[0].RubberStamp | Should -Be $Stamp
    }
    It 'DontKnow is an item but not an approval; system decisions are no reviewer at all' {
        $rows = @(New-Rows 9 60) + @(New-Row -Decision DontKnow -Sec 600) + @(New-Row -Decision Deny -Human $false)
        $r = @(Measure-ReviewerKpi -Rows $rows -MinItems 10 -GapSeconds 5)
        $r.Count | Should -Be 1
        $r[0].Items | Should -Be 10; $r[0].ApprovedAll | Should -BeFalse; $r[0].ApprovalPct | Should -Be 90
    }
    It 'rate = flagged / eligible reviewers; no eligible reviewer -> not-measured' {
        $rev = @(Measure-ReviewerKpi -Rows (@(New-Rows 10 0 'a') + @(New-Rows 10 60 'b' 3) + @(New-Rows 3 0 'c')) -MinItems 10 -GapSeconds 5)
        $k = Measure-RubberStamp -Reviewers $rev
        $k['value'] | Should -Be 50; $k['numerator'] | Should -Be 1; $k['denominator'] | Should -Be 2
        (Measure-RubberStamp -Reviewers @(Measure-ReviewerKpi -Rows (New-Rows 3 0) -MinItems 10))['status'] | Should -Be 'not-measured'
    }
}

Describe 'Get-ReviewTier' {
    It '<Case> -> <Tier>' -ForEach @(
        @{ Case = 'privileged display-name prefix'; Def = @{ displayName = 'Privileged access review: PIM-Tier0-CA-Admins'; scope = @{ query = '/groups/g1/transitiveMembers' } }; Tier = 'T1' }
        @{ Case = 'inactive-user prefix'; Def = @{ displayName = 'Inactive users review: App-Okta-Federation-Users'; scope = @{ query = '/groups/g2/transitiveMembers' } }; Tier = 'HYGIENE' }
        @{ Case = 'automatic policy under review'; Def = (New-PkgDef 'ap-nurse' 'pn-auto'); Tier = 'T3' }
        @{ Case = 'the legacy request policy on the birthright-only Nurse package'; Def = (New-PkgDef 'ap-nurse' 'pn-req'); Tier = 'T3' }
        @{ Case = 'ICU - Float Access request policy (float / agency, split from ICU)'; Def = (New-PkgDef 'ap-icu-float' 'pf-req'); Tier = 'T2' }
        @{ Case = 'a request policy left on the birthright-only ICU package'; Def = (New-PkgDef 'ap-icu' 'pi-req'); Tier = 'T3' }
        @{ Case = 'Pharmacy request policy'; Def = (New-PkgDef 'ap-pharm' 'pp-req'); Tier = 'T2' }
        @{ Case = 'a package outside the catalog'; Def = (New-PkgDef 'ap-x' 'pp-req'); Tier = 'UNCLASSIFIED' }
        @{ Case = 'a directory-role scope'; Def = @{ displayName = 'GA review'; scope = @{ query = '/roleManagement/directory/roleDefinitions/62e90394-69f5-4237-9190-012177145e10' } }; Tier = 'T1' }
        @{ Case = 'a privileged catalog group'; Def = @{ displayName = 'adhoc'; scope = @{ query = '/groups/g-iam/transitiveMembers' } }; Tier = 'T1' }
        @{ Case = 'principal/resource scopes'; Def = @{ displayName = 'adhoc'; scope = @{ principalScopes = @(@{ query = '/users' }); resourceScopes = @(@{ query = '/roleManagement/directory/roleDefinitions/x' }) } }; Tier = 'T1' }
        @{ Case = 'anything else'; Def = @{ displayName = 'adhoc'; scope = @{ query = '/groups/g-other/transitiveMembers' } }; Tier = 'UNCLASSIFIED' }
    ) {
        (Get-ReviewTier -Definition $Def -Catalog $script:Catalog -PackageById $script:PkgById -PolicyById $script:PolById -GroupById @{ 'g-iam' = 'Privileged-IAM-Admins'; 'g-other' = 'Finance-Share' })['Tier'] | Should -Be $Tier
    }
}

Describe 'Clinical lockouts' {
    BeforeAll {
        $script:Users = @{
            'u-rn'     = @{ accountEnabled = $true; department = 'Nursing'; jobTitle = 'Registered Nurse' }
            'u-mover'  = @{ accountEnabled = $true; department = 'ICU'; jobTitle = 'Registered Nurse' }
            'u-leaver' = @{ accountEnabled = $false; department = 'Nursing'; jobTitle = 'Registered Nurse' }
        }
        $script:Since = [datetime]::new(2026, 4, 23, 0, 0, 0, [DateTimeKind]::Utc)
    }
    It 'birthright scope follows the job profiles (and is unknown without attributes)' {
        Test-InBirthrightScope -User $script:Users['u-rn'] -Package 'Nurse - Clinical Apps' -BirthrightRules $script:Birthright | Should -BeTrue
        Test-InBirthrightScope -User $script:Users['u-mover'] -Package 'Nurse - Clinical Apps' -BirthrightRules $script:Birthright | Should -BeFalse
        Test-InBirthrightScope -User @{ accountEnabled = $true } -Package 'Nurse - Clinical Apps' -BirthrightRules $script:Birthright | Should -BeNullOrEmpty
    }
    It 'jobCode mode reads the on-premises extension attribute' {
        $b = $script:Birthright | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable -Depth 20; $b['settings']['matchOn'] = 'jobCode'
        Test-InBirthrightScope -User @{ department = 'Nursing'; onPremisesExtensionAttributes = @{ extensionAttribute1 = 'NUR-RN' } } -Package 'Nurse - Clinical Apps' -BirthrightRules $b | Should -BeTrue
    }
    It 'counts a T3 removal of an enabled, in-scope clinician; not a leaver, a mover or a T2 removal' {
        $rows = @((New-Row -Decision Deny -Tier T3 -Principal 'u-rn' -Package 'Nurse - Clinical Apps'),
            (New-Row -Decision Deny -Tier T3 -Principal 'u-leaver' -Package 'Nurse - Clinical Apps'),
            (New-Row -Decision Deny -Tier T3 -Principal 'u-mover' -Package 'Nurse - Clinical Apps'),
            (New-Row -Decision Deny -Tier T2 -Principal 'u-rn' -Package 'ICU - Critical Care Apps'),
            (New-Row -Decision NotReviewed -Human $false -Apply AppliedSuccessfully -Tier T3 -Principal 'u-unknown' -Package 'Nurse - Clinical Apps'))
        $l = Measure-ClinicalLockout -Rows $rows -Users $script:Users -BirthrightRules $script:Birthright -Since $script:Since
        $l.ByReview | Should -Be 2
        @($l.Items | Where-Object Basis -eq 'scope-unknown').Count | Should -Be 1   # unknown person counted (target is 0)
    }
    It 'counts a T2 review removal of a birthright package (ICU request policy) for an in-scope ICU nurse, unless they still hold it' {
        $users = @{ 'u-icu' = @{ accountEnabled = $true; department = 'ICU'; jobTitle = 'Registered Nurse' } }
        $row = New-Row -Decision Deny -Tier T2 -Principal 'u-icu' -Package 'ICU - Critical Care Apps'
        (Measure-ClinicalLockout -Rows @($row) -Users $users -BirthrightRules $script:Birthright -Since $script:Since).ByReview | Should -Be 1
        (Measure-ClinicalLockout -Rows @($row) -Users $users -DeliveredKeys @{ 'u-icu|ICU - Critical Care Apps' = $true } -BirthrightRules $script:Birthright -Since $script:Since).ByReview | Should -Be 0
        # Outside T3, a person whose attributes are unknown (float / agency staff) is not counted.
        (Measure-ClinicalLockout -Rows @((New-Row -Decision Deny -Tier T2 -Principal 'u-agency' -Package 'ICU - Critical Care Apps')) -Users $users -BirthrightRules $script:Birthright -Since $script:Since).ByReview | Should -Be 0
        # A T2 removal of a request-only package is never a lockout.
        (Measure-ClinicalLockout -Rows @((New-Row -Decision Deny -Tier T2 -Principal 'u-icu' -Package 'Pharmacy - Controlled Substances Apps')) -Users $users -BirthrightRules $script:Birthright -Since $script:Since).ByReview | Should -Be 0
        # Since the ICU split, denying an in-scope ICU nurse's float package removes only that package.
        (Measure-ClinicalLockout -Rows @((New-Row -Decision Deny -Tier T2 -Principal 'u-icu' -Package 'ICU - Float Access')) -Users $users -BirthrightRules $script:Birthright -Since $script:Since).ByReview | Should -Be 0
    }
    It 'counts an expiry only inside the window, for an in-scope clinician who no longer holds the package' {
        $exp = @(
            @{ targetId = 'u-rn'; package = 'Nurse - Clinical Apps'; expiredDateTime = '2026-10-01T00:00:00Z' },   # counted
            @{ targetId = 'u-rn'; package = 'Nurse - Clinical Apps'; expiredDateTime = '2026-01-01T00:00:00Z' },   # before the window
            @{ targetId = 'u-mover'; package = 'Nurse - Clinical Apps'; expiredDateTime = '2026-10-01T00:00:00Z' }) # moved out of scope
        (Measure-ClinicalLockout -Rows @() -Users $script:Users -ExpiredAssignments $exp -BirthrightRules $script:Birthright -Since $script:Since).ByExpiry | Should -Be 1
        (Measure-ClinicalLockout -Rows @() -Users $script:Users -ExpiredAssignments $exp -DeliveredKeys @{ 'u-rn|Nurse - Clinical Apps' = $true } -BirthrightRules $script:Birthright -Since $script:Since).ByExpiry | Should -Be 0
    }
}

Describe '10-Review-KPIs.ps1 - offline fixture run' {
    BeforeAll {
        $script:Out = Join-Path $TestDrive 'kpis'; $script:Det = Join-Path $TestDrive 'kpis-detail'
        $global:LASTEXITCODE = 0
        $script:Snap = & $script:Kpi -InputPath $script:FixturePath -OutputDirectory $script:Out -DetailDirectory $script:Det -Label fixture-check -WarningAction SilentlyContinue
        $script:Exit = $LASTEXITCODE
    }
    It 'reproduces the fixture''s expected headline numbers' {
        $s = $script:Snap
        $s.source | Should -Be 'fixture'
        $s.tiers['T1']['completion']['value'] | Should -Be 100; $s.tiers['T1']['completionTargetMet'] | Should -BeTrue
        $s.tiers['T1']['items'] | Should -Be 10                     # the out-of-lookback T1 instance is excluded
        $s.tiers['T2']['completion']['value'] | Should -Be 88.2; $s.tiers['T2']['completionTargetMet'] | Should -BeFalse
        $s.tiers['T3']['definitions'] | Should -Be 1
        $s.tiers['UNCLASSIFIED']['items'] | Should -Be 1
        $s.rubberStamp['kpi']['value'] | Should -Be 50
        $s.overall['approveAgainstRecommendation']['numerator'] | Should -Be 2
        $s.overall['approveAgainstRecommendationWithoutJustification'] | Should -Be 1
        # byReview 1 (Grace): u-float03's Deny now removes only 'ICU - Float Access', not the ICU birthright package (the split).
        $s.clinicalLockouts['byReview'] | Should -Be 1; $s.clinicalLockouts['byExpiry'] | Should -Be 1
        @($s.reviewers | Where-Object { $_['rubberStamp'] }).Count | Should -Be 1
        $s.reviewers[0]['label'] | Should -Be 'R01'
    }
    It 'exits 2 because clinical lockouts are above the 0 target' { $script:Exit | Should -Be 2 }
    It 'writes a hashed snapshot with no reviewer identity; the label map is in the detail file' {
        $f = @(Get-ChildItem -LiteralPath $script:Out -Filter 'reviews-*.json')
        $f.Count | Should -Be 1
        (Get-Content -LiteralPath "$($f[0].FullName).sha256" -Raw).Split(' ')[0] | Should -Be (Get-FileHash -LiteralPath $f[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $txt = Get-Content -LiteralPath $f[0].FullName -Raw
        foreach ($s in 'u-pharmdir', 'u-govlead', 'pharmacy.director', 'contoso.test', 'u-dana', 'u-sofia') { $txt | Should -Not -Match ([regex]::Escape($s)) }
        @(Test-PublicRecordSafe -Json $txt) | Should -BeNullOrEmpty
        (Get-ChildItem -LiteralPath $script:Det -Filter '*-detail.json' | Get-Content -Raw) | Should -Match 'pharmacy\.director@contoso\.test'
    }
    It '-WhatIf writes nothing' {
        $o = Join-Path $TestDrive 'wi'
        & $script:Kpi -InputPath $script:FixturePath -OutputDirectory $o -DetailDirectory (Join-Path $TestDrive 'wid') -WhatIf -WarningAction SilentlyContinue | Out-Null
        Test-Path -LiteralPath $o | Should -BeFalse
    }
    It 'refuses to write synthetic output into the public evidence tree' {
        $pub = Join-Path $script:LabRoot 'evidence' 'kpis'
        $before = @(if (Test-Path -LiteralPath $pub) { Get-ChildItem -LiteralPath $pub -Filter 'reviews-*' })
        { & $script:Kpi -InputPath $script:FixturePath -OutputDirectory $pub -WarningAction SilentlyContinue } | Should -Throw '*public evidence tree*'
        @(if (Test-Path -LiteralPath $pub) { Get-ChildItem -LiteralPath $pub -Filter 'reviews-*' }).Count | Should -Be $before.Count
    }
}

Describe '10-Review-KPIs.ps1 - tenant path (mocked Graph)' {
    BeforeAll {
        function Set-TenantMock {
            param([switch]$FailDecisions)
            $global:KpiTest = @{ Fail = [bool]$FailDecisions }
            Mock Get-MgContext { New-MgContextStub -Scopes @('AccessReview.Read.All', 'EntitlementManagement.Read.All', 'User.Read.All', 'Group.Read.All') }
            Mock Connect-MgGraph { throw 'tests must never connect' }
            Mock Invoke-MgGraphRequest {
                $u = [uri]::UnescapeDataString("$Uri")
                if ($Method -ne 'GET') { throw "read-only script wrote: $Method $u" }
                $now = (Get-Date).ToUniversalTime()
                if ($u -like '*/assignmentPolicies?*') { return @{ value = @(@{ id = 'pp-req'; accessPackage = @{ id = 'ap-pharm'; displayName = 'Pharmacy - Controlled Substances Apps' }; automaticRequestSettings = $null }) } }
                if ($u -like '*/accessReviews/definitions') { return @{ value = @(@{ id = 'd1'; displayName = 'Pharmacy 180'; scope = @{ query = "/identityGovernance/entitlementManagement/accessPackageAssignments?`$filter=(accessPackageId eq 'ap-pharm' and assignmentPolicyId eq 'pp-req')" } }) } }
                if ($u -like '*/definitions/d1/instances') { return @{ value = @(@{ id = 'i1'; status = 'Completed'; endDateTime = $now.AddDays(-10).ToString('o') }) } }
                if ($u -like '*/instances/i1/decisions') {
                    if ($global:KpiTest.Fail) { throw 'HTTP 403 Forbidden' }
                    return @{ value = @(
                            @{ decision = 'Approve'; recommendation = 'Approve'; reviewedBy = @{ id = 'r1'; displayName = 'Rev'; userPrincipalName = 'rev@contoso.test' }; reviewedDateTime = $now.AddDays(-12).ToString('o'); justification = 'ok'; principal = @{ id = 'p1' } },
                            @{ decision = 'NotReviewed'; recommendation = 'Deny'; reviewedBy = @{ id = '00000000-0000-0000-0000-000000000000' }; principal = @{ id = 'p2' } }) }
                }
                if ($u -like '*/entitlementManagement/assignments?*') { return @{ value = @() } }
                throw "unexpected Graph call in test: $Method $u"
            }
        }
    }
    AfterAll { Remove-Variable -Name KpiTest -Scope Global -ErrorAction SilentlyContinue }

    It 'reads policies, definitions, instances and decisions read-only; exit 0' {
        Set-TenantMock
        $global:LASTEXITCODE = 0
        $s = & $script:Kpi -OutputDirectory (Join-Path $TestDrive 't') -DetailDirectory (Join-Path $TestDrive 'td') -WhatIf -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        $s.source | Should -Be 'tenant'
        $s.tiers['T2']['items'] | Should -Be 2
        $s.tiers['T2']['completion']['value'] | Should -Be 50
        Should -Invoke Connect-MgGraph -Times 0
    }
    It 'a source that cannot be read exits 1 and writes nothing' {
        Set-TenantMock -FailDecisions
        $global:LASTEXITCODE = 0
        $o = Join-Path $TestDrive 'tf'
        & $script:Kpi -OutputDirectory $o -DetailDirectory (Join-Path $TestDrive 'tfd') -WarningAction SilentlyContinue | Out-Null
        $LASTEXITCODE | Should -Be 1
        Test-Path -LiteralPath $o | Should -BeFalse
    }
}
