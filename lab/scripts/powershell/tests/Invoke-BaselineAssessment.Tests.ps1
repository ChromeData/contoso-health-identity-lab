# Offline harness for lab/scripts/powershell/Invoke-BaselineAssessment.ps1.
# Uses CISA's published ScubaGear v1.8.0 sample report (cisagov/ScubaGear,
# tag v1.8.0, PowerShell/ScubaGear/Sample-Reports - fetched and SHA-256
# verified by tests/fixtures/Get-ScubaSample.ps1 into the gitignored
# lab/scripts/powershell/out/fixtures/scuba-sample) and a SYNTHETIC Zero
# Trust Assessment results file shaped like Get-ZtAssessmentResults' output.
# No tenant. Without the sample the fixture-based blocks are SKIPPED (shown as
# skipped, never silently passed):
#   pwsh lab/scripts/powershell/tests/fixtures/Get-ScubaSample.ps1
#   Invoke-Pester ./Invoke-BaselineAssessment.Tests.ps1 -Output Detailed

BeforeDiscovery {
    $sampleDir = if ($env:SCUBA_SAMPLE_DIR) { $env:SCUBA_SAMPLE_DIR } else { Join-Path $PSScriptRoot '..' 'out' 'fixtures' 'scuba-sample' }
    $script:HaveScubaSample = @('results.json', 'ScubaResults.csv', 'ActionPlan.csv' | Where-Object { Test-Path -LiteralPath (Join-Path $sampleDir $_) }).Count -eq 3
    # The YAML check shells out to python3 + PyYAML when both are present.
    $script:HavePyYaml = $false
    $py = Get-Command python3 -ErrorAction SilentlyContinue
    if ($py) {
        & $py.Source -I -c 'import yaml' 2>$null
        $script:HavePyYaml = $LASTEXITCODE -eq 0
    }
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Sut = Get-LabScriptPath 'Invoke-BaselineAssessment.ps1'
    $script:SampleDir = if ($env:SCUBA_SAMPLE_DIR) { $env:SCUBA_SAMPLE_DIR } else { Join-Path $PSScriptRoot '..' 'out' 'fixtures' 'scuba-sample' }
    $script:ScubaRun = Join-Path $TestDrive 'M365BaselineConformance_2026_05_04_17_15_48'
    $script:ScubaCsvOnly = Join-Path $TestDrive 'scuba-csv-only'

    # ScubaGear fixture: the real v1.8.0 sample, laid out as a run folder
    # (only when the sample was fetched - the blocks that need it are skipped
    # otherwise).
    if (Test-Path -LiteralPath (Join-Path $SampleDir 'results.json')) {
        New-Item -ItemType Directory -Path (Join-Path $ScubaRun 'IndividualReports') -Force | Out-Null
        Copy-Item (Join-Path $SampleDir 'results.json') (Join-Path $ScubaRun 'ScubaResults_fa5589b7-d528-4f80.json')
        Copy-Item (Join-Path $SampleDir 'ScubaResults.csv') $ScubaRun
        Copy-Item (Join-Path $SampleDir 'ActionPlan.csv') $ScubaRun
        'placeholder' | Set-Content (Join-Path $ScubaRun 'IndividualReports' 'AADReport.html')

        # CSV-only fixture (ScubaGear -KeepIndividualJSON leaves no combined JSON).
        New-Item -ItemType Directory -Path $ScubaCsvOnly -Force | Out-Null
        Copy-Item (Join-Path $SampleDir 'ScubaResults.csv') $ScubaCsvOnly
    }

    # Synthetic Zero Trust fixture with obviously fake tenant identifiers.
    $script:ZtRoot = Join-Path $TestDrive 'ZeroTrustReport'
    New-Item -ItemType Directory -Path (Join-Path $ZtRoot 'zt-export') -Force | Out-Null
    $zt = [ordered]@{
        ExecutedAt = '2026-11-01T10:00:00Z'; TenantId = '99999999-8888-7777-6666-555555555555'
        TenantName = 'FixtureTenantName'; Domain = 'fixturetenant.onmicrosoft.com'; Account = 'fixture.admin@fixturetenant.onmicrosoft.com'
        CurrentVersion = '2.6.0'; LatestVersion = '2.6.0'
        TestResultSummary = @{ IdentityPassed = 2; IdentityTotal = 3 }
        Tests = @(
            @{ TestId = '21770'; TestTitle = 'Inactive applications do not have highly privileged permissions'; TestStatus = 'Passed'; TestPillar = 'Identity'; TestRisk = 'High'; TestResult = 'App SECRET-APP-NAME owned by fixture.admin@fixturetenant.onmicrosoft.com' }
            @{ TestId = '21780'; TestTitle = 'No legacy authentication sign-in activity'; TestStatus = 'Failed'; TestPillar = 'Identity'; TestRisk = 'High'; TestResult = 'Sign-in from 203.0.113.9' }
            @{ TestId = '21790'; TestTitle = 'Guests do not own apps'; TestStatus = 'Passed'; TestPillar = 'Identity'; TestRisk = 'Medium'; TestResult = '' }
            @{ TestId = '21800'; TestTitle = 'Planned test'; TestStatus = 'Planned'; TestPillar = 'Identity'; TestRisk = 'Low'; TestResult = '' }
        )
        TenantInfo = @{ OverviewCaMfaAllUsers = @{ x = 1 } }
        EndOfJson = 'EndOfJson'
    }
    ($zt | ConvertTo-Json -Depth 10) | Set-Content (Join-Path $ZtRoot 'zt-export' 'ZeroTrustAssessmentReport.json')
    '<html>fixture</html>' | Set-Content (Join-Path $ZtRoot 'ZeroTrustAssessmentReport.html')
    'raw sign-in export that must NOT become evidence' | Set-Content (Join-Path $ZtRoot 'zt-export' 'SignIn.json')

    $script:RawRoot = Join-Path $TestDrive 'raw'
    $script:PubRoot = Join-Path $TestDrive 'public'

    function Invoke-Sut {
        param([hashtable]$Extra)
        $p = @{
            Phase = 'before'; ScubaResultsPath = $ScubaRun; ZeroTrustResultsPath = $ZtRoot
            RawOutputRoot = $RawRoot; PublicOutputRoot = $PubRoot; SkipUpload = $true
            InformationAction = 'SilentlyContinue'; WarningAction = 'SilentlyContinue'
        }
        foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
        $out = & $Sut @p 6>$null
        [pscustomobject]@{ Summary = $out; ExitCode = $LASTEXITCODE }
    }
}

Describe 'before run (import mode, both tools)' -Skip:(-not $HaveScubaSample) {
    BeforeAll {
        $global:LASTEXITCODE = 0
        $script:r = Invoke-Sut @{ RunId = '20261101T100000Z' }
        $script:raw = Join-Path $RawRoot '20261101T100000Z-before'
        $script:pub = Join-Path $PubRoot '20261101T100000Z-before'
        $script:pubJson = Get-Content (Join-Path $pub 'summary.json') -Raw | ConvertFrom-Json
    }

    It 'exits 0 and reports both tools ok' {
        $r.ExitCode | Should -Be 0
        $pubJson.scubaGear.status | Should -Be 'ok'
        $pubJson.zeroTrust.status | Should -Be 'ok'
    }

    It 'parses all 30 MS.AAD controls of the v1.8.0 sample and maps every one' {
        @($pubJson.scubaGear.controls).Count | Should -Be 30
        @($pubJson.scubaGear.unmapped).Count | Should -Be 0
        $pubJson.scubaGear.meta.toolVersion | Should -Be '1.8.0'
    }

    It 'computes the SHALL KPI the same way an independent count does' {
        $j = Get-Content (Join-Path $ScubaRun 'ScubaResults_fa5589b7-d528-4f80.json') -Raw | ConvertFrom-Json
        $all = foreach ($g in $j.Results.AAD) { $g.Controls }
        $shall = @($all | Where-Object { $_.Criticality -eq 'Shall' -and $_.Result -notin 'N/A', 'Omitted' })
        $pubJson.scubaGear.kpi.shallAutomated | Should -Be $shall.Count
        $pubJson.scubaGear.kpi.shallPassed | Should -Be @($shall | Where-Object Result -EQ 'Pass').Count
        $pubJson.scubaGear.summary.Passes | Should -Be $j.Summary.AAD.Passes
    }

    It 'strips the HTML indicator badges from requirement text and flags BOD 25-01' {
        $c = $pubJson.scubaGear.controls | Where-Object controlId -EQ 'MS.AAD.1.1v1'
        $c.requirement | Should -Be 'Legacy authentication SHALL be blocked.'
        $c.bod2501 | Should -BeTrue
        $c.labControl | Should -Match 'CA003'
    }

    It 'keeps no tenant identifiers, users, IPs or local paths in the public files' {
        $text = (Get-Content (Join-Path $pub 'summary.json') -Raw) + (Get-Content (Join-Path $pub 'SUMMARY.md') -Raw)
        foreach ($needle in 'ca08493a-c9c8-4db0-a9e8-d3b4bafac269', 'tqhjy', '99999999-8888-7777-6666-555555555555',
            'FixtureTenantName', 'fixturetenant', 'SECRET-APP-NAME', '203.0.113.9', $HOME, $TestDrive) {
            $text | Should -Not -Match ([regex]::Escape($needle))
        }
    }

    It 'keeps the Zero Trust report + results JSON but not the raw export (data minimisation)' {
        Test-Path (Join-Path $raw 'zero-trust' 'ZeroTrustAssessmentReport.json') | Should -BeTrue
        Test-Path (Join-Path $raw 'zero-trust' 'ZeroTrustAssessmentReport.html') | Should -BeTrue
        @(Get-ChildItem $raw -Recurse -Filter 'SignIn.json').Count | Should -Be 0
        $pubJson.zeroTrust.kpi.testsCounted | Should -Be 3
        $pubJson.zeroTrust.kpi.testsPassed | Should -Be 2
        $pubJson.zeroTrust.kpi.highRiskNotPassed | Should -Be 1
    }

    It 'writes a SHA256SUMS that shasum -c verifies, covering every raw file' {
        Push-Location $raw
        try { $out = & shasum -a 256 -c SHA256SUMS 2>&1; $LASTEXITCODE | Should -Be 0 } finally { Pop-Location }
        $listed = @(Get-Content (Join-Path $raw 'SHA256SUMS') | Where-Object { $_ })
        $files = @(Get-ChildItem $raw -Recurse -File | Where-Object { $_.Name -notin 'manifest.json', 'SHA256SUMS' })
        $listed.Count | Should -Be $files.Count
        ($out -join "`n") | Should -Not -Match 'FAILED'
    }

    It 'records the manifest hash in the public summary and SUMMARY.md carries summary.json''s hash' {
        $mHash = (Get-FileHash (Join-Path $raw 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $pubJson.rawManifest.manifestSha256 | Should -Be $mHash
        $sHash = (Get-FileHash (Join-Path $pub 'summary.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        (Get-Content (Join-Path $pub 'SUMMARY.md') -Raw) | Should -Match $sHash
    }

    It 'copied ScubaGear output byte-for-byte' {
        $src = (Get-FileHash (Join-Path $ScubaRun 'ScubaResults_fa5589b7-d528-4f80.json')).Hash
        $dst = (Get-FileHash (Get-ChildItem $raw -Recurse -Filter 'ScubaResults_*.json' | Select-Object -First 1).FullName).Hash
        $dst | Should -Be $src
    }

    It 'refuses to reuse a RunId (evidence is never overwritten)' {
        { & $Sut -Phase before -RunId '20261101T100000Z' -ScubaResultsPath $ScubaRun -ZeroTrustResultsPath $ZtRoot `
                -RawOutputRoot $RawRoot -PublicOutputRoot $PubRoot -SkipUpload -WarningAction SilentlyContinue 6>$null } |
            Should -Throw '*already exists*'
    }
}

Describe 'after run compares against the newest before run' -Skip:(-not $HaveScubaSample) {
    BeforeAll {
        # Same sample with one Fail flipped to Pass and one Pass flipped to Fail.
        $script:AfterRun = Join-Path $TestDrive 'M365BaselineConformance_after'
        New-Item -ItemType Directory -Path $AfterRun -Force | Out-Null
        $j = Get-Content (Join-Path $ScubaRun 'ScubaResults_fa5589b7-d528-4f80.json') -Raw | ConvertFrom-Json
        foreach ($g in $j.Results.AAD) {
            foreach ($c in $g.Controls) {
                if ($c.'Control ID' -eq 'MS.AAD.3.1v1') { $c.Result = 'Pass' }   # was Fail in the sample
                if ($c.'Control ID' -eq 'MS.AAD.1.1v1') { $c.Result = 'Fail' }   # was Pass in the sample
            }
        }
        ($j | ConvertTo-Json -Depth 100) | Set-Content (Join-Path $AfterRun 'ScubaResults_after.json')
        # TestDrive is reset per Describe, so lay down the "before" run here.
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ RunId = '20261101T100000Z' }
        $global:LASTEXITCODE = 0
        $script:r2 = Invoke-Sut @{ Phase = 'after'; RunId = '20261125T100000Z'; ScubaResultsPath = $AfterRun }
        $script:cmp = (Get-Content (Join-Path $PubRoot '20261125T100000Z-after' 'summary.json') -Raw | ConvertFrom-Json).comparison
    }

    It 'finds the before run' { $cmp.baselineRunId | Should -Be '20261101T100000Z' }
    It 'counts one improvement and one regression' {
        $cmp.scubaGear.improved | Should -Be 1
        $cmp.scubaGear.regressed | Should -Be 1
        ($cmp.scubaGear.controls | Where-Object baseId -EQ 'MS.AAD.1.1').change | Should -Be 'REGRESSED'
        ($cmp.scubaGear.controls | Where-Object baseId -EQ 'MS.AAD.3.1').change | Should -Be 'improved'
    }
    It 'shows the delta in SUMMARY.md' {
        (Get-Content (Join-Path $PubRoot '20261125T100000Z-after' 'SUMMARY.md') -Raw) | Should -Match '\| MS\.AAD\.1\.1 \| Pass \| Fail \| REGRESSED \|'
    }
}

Describe 'fallbacks and honesty' -Skip:(-not $HaveScubaSample) {
    It 'parses ScubaResults.csv when no combined JSON exists' {
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ RunId = 'csv-only'; ScubaResultsPath = $ScubaCsvOnly; Tools = @('ScubaGear') }
        $s = Get-Content (Join-Path $PubRoot 'csv-only-before' 'summary.json') -Raw | ConvertFrom-Json
        @($s.scubaGear.controls).Count | Should -Be 30
        $s.scubaGear.meta.sourceFormat | Should -Be 'csv'
    }

    It 'on a non-Windows host without -ScubaResultsPath, records ScubaGear as skipped and exits 1' -Skip:$IsWindows {
        $global:LASTEXITCODE = 0
        $res = Invoke-Sut @{ RunId = 'mac-no-scuba'; ScubaResultsPath = $null }
        $res.ExitCode | Should -Be 1
        $s = Get-Content (Join-Path $PubRoot 'mac-no-scuba-before' 'summary.json') -Raw | ConvertFrom-Json
        $s.scubaGear.status | Should -Be 'skipped'
        $s.scubaGear.reason | Should -Match 'Windows PowerShell 5.1'
        $s.zeroTrust.status | Should -Be 'ok'
    }

    It 'records a failed tool instead of crashing, with no local path in the public reason' {
        $global:LASTEXITCODE = 0
        $empty = Join-Path $TestDrive 'empty-scuba'; New-Item -ItemType Directory $empty -Force | Out-Null
        $res = Invoke-Sut @{ RunId = 'bad-scuba'; ScubaResultsPath = $empty }
        $res.ExitCode | Should -Be 1
        $s = Get-Content (Join-Path $PubRoot 'bad-scuba-before' 'summary.json') -Raw | ConvertFrom-Json
        $s.scubaGear.status | Should -Be 'failed'
        $s.scubaGear.reason | Should -Not -Match ([regex]::Escape($HOME))
        $s.zeroTrust.status | Should -Be 'ok'
    }

    It 'says "not uploaded" when no storage account is given' {
        $global:LASTEXITCODE = 0
        $null = & $Sut -Phase checkpoint -RunId 'no-acct' -ScubaResultsPath $ScubaRun -ZeroTrustResultsPath $ZtRoot `
            -RawOutputRoot $RawRoot -PublicOutputRoot $PubRoot -WarningAction SilentlyContinue 6>$null
        (Get-Content (Join-Path $PubRoot 'no-acct-checkpoint' 'summary.json') -Raw | ConvertFrom-Json).worm.status |
            Should -Match 'not uploaded'
    }

    It '-WhatIf writes nothing' {
        $null = & $Sut -Phase before -RunId 'whatif-run' -ScubaResultsPath $ScubaRun -ZeroTrustResultsPath $ZtRoot `
            -RawOutputRoot $RawRoot -PublicOutputRoot $PubRoot -SkipUpload -WhatIf -WarningAction SilentlyContinue 6>$null
        Test-Path (Join-Path $RawRoot 'whatif-run-before') | Should -BeFalse
        Test-Path (Join-Path $PubRoot 'whatif-run-before') | Should -BeFalse
    }
}

Describe 'non-tenant input never reaches the public evidence tree' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Sut, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-InputSource' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        $varAst = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$NonTenantInputIds' }, $true)
        . ([scriptblock]::Create($varAst.Extent.Text))
        # Generated at run time: a tenant-shaped id that is no fixture, sample
        # or placeholder (a literal would be a GUID in the public repo).
        $script:TenantA = [guid]::NewGuid().ToString()
        $script:TenantB = [guid]::NewGuid().ToString()
        $script:EvidenceRoot = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Sut) '..' '..' 'evidence'))

        function New-ScubaRunFor {   # the CISA sample with MetaData.TenantId replaced
            param([string]$Name, [string]$TenantId)
            $dir = Join-Path $TestDrive $Name
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            $j = Get-Content (Join-Path $ScubaRun 'ScubaResults_fa5589b7-d528-4f80.json') -Raw | ConvertFrom-Json
            $j.MetaData.TenantId = $TenantId
            ($j | ConvertTo-Json -Depth 100) | Set-Content (Join-Path $dir 'ScubaResults_tenant.json')
            $dir
        }
        function New-ZtRunFor {   # the synthetic Zero Trust fixture with TenantId replaced
            param([string]$Name, [string]$TenantId)
            $dir = Join-Path $TestDrive $Name
            New-Item -ItemType Directory -Path (Join-Path $dir 'zt-export') -Force | Out-Null
            $j = Get-Content (Join-Path $ZtRoot 'zt-export' 'ZeroTrustAssessmentReport.json') -Raw | ConvertFrom-Json
            $j.TenantId = $TenantId
            ($j | ConvertTo-Json -Depth 10) | Set-Content (Join-Path $dir 'zt-export' 'ZeroTrustAssessmentReport.json')
            $dir
        }
    }

    It 'classifies the CISA sample, the Zero Trust fixture, placeholders and missing ids as non-tenant' {
        (Get-InputSource 'ca08493a-c9c8-4db0-a9e8-d3b4bafac269').kind | Should -Be 'sample'
        (Get-InputSource 'CA08493A-C9C8-4DB0-A9E8-D3B4BAFAC269').kind | Should -Be 'sample'
        (Get-InputSource '99999999-8888-7777-6666-555555555555').kind | Should -Be 'fixture'
        (Get-InputSource '00000000-0000-0000-0000-000000000000').kind | Should -Be 'fixture'
        (Get-InputSource '').kind | Should -Be 'unknown'
        (Get-InputSource $null).kind | Should -Be 'unknown'
        (Get-InputSource 'not-a-guid').kind | Should -Be 'unknown'
        (Get-InputSource $TenantA).kind | Should -Be 'tenant'
        (Get-InputSource $TenantA).key | Should -Not -Match ([regex]::Escape($TenantA))
        (Get-InputSource $TenantA).key | Should -Be (Get-InputSource $TenantA.ToUpperInvariant()).key
        (Get-InputSource $TenantA).key | Should -Not -Be (Get-InputSource $TenantB).key
    }

    It 'refuses an explicit -PublicOutputRoot inside lab/evidence for the CISA sample, and writes nothing there' -Skip:(-not $HaveScubaSample) {
        $pubInEvidence = Join-Path $EvidenceRoot 'assessments'
        $runId = 'pester-refuse-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        { & $Sut -Phase before -RunId $runId -ScubaResultsPath $ScubaRun -ZeroTrustResultsPath $ZtRoot `
                -RawOutputRoot $RawRoot -PublicOutputRoot $pubInEvidence -SkipUpload -WarningAction SilentlyContinue 6>$null } |
            Should -Throw '*Refusing to write a non-tenant*public evidence tree*'
        $leaked = Join-Path $pubInEvidence "$runId-before"
        $wrote = Test-Path -LiteralPath $leaked
        if ($wrote) { Remove-Item -LiteralPath $leaked -Recurse -Force }   # a regression must not leave it behind
        $wrote | Should -BeFalse
    }

    It 'sends a sample run with the DEFAULT public root to lab/evidence/out/assessments-summary, marked non-tenant' -Skip:(-not $HaveScubaSample) {
        $runId = 'pester-redirect-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $redirected = Join-Path $EvidenceRoot 'out' 'assessments-summary' "$runId-before"
        try {
            $global:LASTEXITCODE = 0
            $null = & $Sut -Phase before -RunId $runId -ScubaResultsPath $ScubaRun -ZeroTrustResultsPath $ZtRoot `
                -RawOutputRoot $RawRoot -SkipUpload -WarningAction SilentlyContinue 6>$null
            Test-Path -LiteralPath (Join-Path $EvidenceRoot 'assessments' "$runId-before") | Should -BeFalse
            $s = Get-Content (Join-Path $redirected 'summary.json') -Raw | ConvertFrom-Json
            $s.source.kind | Should -Be 'non-tenant'
            $s.source.scubaGear | Should -Be 'sample'
            $s.source.zeroTrust | Should -Be 'fixture'
            (Get-Content (Join-Path $redirected 'SUMMARY.md') -Raw) | Should -Match 'NOT A TENANT RUN'
        }
        finally {
            # Leave lab/evidence as it was: the run folder, then its parents if the test made them.
            Remove-Item -LiteralPath $redirected -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($d in (Join-Path $EvidenceRoot 'out' 'assessments-summary'), (Join-Path $EvidenceRoot 'out')) {
                if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) { Remove-Item -LiteralPath $d -Force }
            }
        }
    }

    It 'records a run whose tools name the same real tenant as a tenant run, without the id' -Skip:(-not $HaveScubaSample) {
        $sc = New-ScubaRunFor -Name 'scuba-tenant-a' -TenantId $TenantA
        $ztA = New-ZtRunFor -Name 'zt-tenant-a' -TenantId $TenantA
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ RunId = 'tenant-a'; ScubaResultsPath = $sc; ZeroTrustResultsPath = $ztA }
        $text = Get-Content (Join-Path $PubRoot 'tenant-a-before' 'summary.json') -Raw
        $s = $text | ConvertFrom-Json
        $s.source.kind | Should -Be 'tenant'
        $s.source.scubaGear | Should -Be 'tenant'
        $s.source.zeroTrust | Should -Be 'tenant'
        $text | Should -Not -Match ([regex]::Escape($TenantA))
        $text | Should -Not -Match ([regex]::Escape((Get-InputSource $TenantA).key))
    }

    It 'treats two different tenants, or a CSV-only import, as non-tenant' -Skip:(-not $HaveScubaSample) {
        $sc = New-ScubaRunFor -Name 'scuba-tenant-a2' -TenantId $TenantA
        $ztB = New-ZtRunFor -Name 'zt-tenant-b' -TenantId $TenantB
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ RunId = 'mixed'; ScubaResultsPath = $sc; ZeroTrustResultsPath = $ztB }
        $s = Get-Content (Join-Path $PubRoot 'mixed-before' 'summary.json') -Raw | ConvertFrom-Json
        $s.source.kind | Should -Be 'non-tenant'
        $s.source.detail | Should -Match 'DIFFERENT tenants'
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ RunId = 'csv-tenant'; ScubaResultsPath = $ScubaCsvOnly; Tools = @('ScubaGear') }
        (Get-Content (Join-Path $PubRoot 'csv-tenant-before' 'summary.json') -Raw | ConvertFrom-Json).source.scubaGear | Should -Be 'unknown'
    }

    It 'never computes a before/after delta between a sample run and a tenant run' -Skip:(-not $HaveScubaSample) {
        $sc = New-ScubaRunFor -Name 'scuba-tenant-after' -TenantId $TenantA
        $ztA = New-ZtRunFor -Name 'zt-tenant-after' -TenantId $TenantA
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ RunId = '20261101T090000Z' }   # the sample: non-tenant "before"
        $global:LASTEXITCODE = 0
        $null = Invoke-Sut @{ Phase = 'after'; RunId = '20261126T100000Z'; ScubaResultsPath = $sc; ZeroTrustResultsPath = $ztA
            BaselineSummaryPath = (Join-Path $PubRoot '20261101T090000Z-before' 'summary.json') }
        $cmp = (Get-Content (Join-Path $PubRoot '20261126T100000Z-after' 'summary.json') -Raw | ConvertFrom-Json).comparison
        $cmp.status | Should -Match "not compared: the baseline is a 'non-tenant' run, this one is 'tenant'"
        $cmp.PSObject.Properties['scubaGear'] | Should -BeNullOrEmpty
    }
}

Describe 'ScubaGear config (break-glass is the only exclusion)' {
    BeforeAll {
        # Load the pure helper functions from the script without running it.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Sut, [ref]$null, [ref]$null)
        foreach ($name in 'ConvertTo-ScubaConfigYaml', 'ConvertTo-PublicSafeText') {
            $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        $varAst = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$ScubaCapExclusionPolicyIds' }, $true)
        . ([scriptblock]::Create($varAst.Extent.Text))
        $script:yamlPath = Join-Path $TestDrive 'cfg.yaml'
        ConvertTo-ScubaConfigYaml -GroupId '12345678-1234-1234-1234-123456789abc' -Run 'r1' | Set-Content $yamlPath
    }

    It 'is valid YAML with aad only, the group on every CapExclusions policy and on MS.AAD.7.4 RoleExclusions' -Skip:(-not $HavePyYaml) {
        $py = @'
import sys, yaml, json
d = yaml.safe_load(open(sys.argv[1]))
print(json.dumps(d))
'@
        $json = & (Get-Command python3).Source -I -c $py $yamlPath | ConvertFrom-Json -AsHashtable
        $json.ProductNames | Should -Be @('aad')
        $json.Aad.Keys.Count | Should -Be 10
        foreach ($k in $json.Aad.Keys | Where-Object { $_ -ne 'MS.AAD.7.4v1' }) {
            $json.Aad[$k].CapExclusions.Groups | Should -Be @('12345678-1234-1234-1234-123456789abc')
            $json.Aad[$k].CapExclusions.Keys | Should -Be @('Groups')   # no Users / Applications exclusions
        }
        $json.Aad['MS.AAD.7.4v1'].RoleExclusions.Groups | Should -Be @('12345678-1234-1234-1234-123456789abc')
    }

    It 'writes no exclusions at all when the group is unknown' {
        (ConvertTo-ScubaConfigYaml -GroupId $null -Run 'r2') | Should -Not -Match 'Aad:'
    }

    It 'scrubs GUIDs, UPNs, IPs, tenant domains and the home path from public text' {
        $t = ConvertTo-PublicSafeText "x $HOME/a 11111111-2222-3333-4444-555555555555 bob@contoso.com 198.51.100.4 lab.onmicrosoft.com"
        $t | Should -Be 'x ~/a <guid> <upn> <ip> <tenant-domain>'
    }
}

Describe 'MS.AAD control map stays true to the code' {
    # The map is a literal in the script: read it from the syntax tree (no
    # script body runs) and hold every pointer in it to the repository.
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Sut, [ref]$null, [ref]$null)
        $assign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$ControlMap' }, $false)
        $script:Map = & ([scriptblock]::Create($assign.Right.Extent.Text))
        $repoLab = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
        $script:DevVars = @([regex]::Matches((Get-Content -Raw (Join-Path $repoLab 'terraform/envs/dev/variables.tf')), '(?m)^variable "([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        $script:CaText = (Get-ChildItem (Join-Path $repoLab 'terraform/modules/conditional-access') -Filter '*.tf' | ForEach-Object { Get-Content -Raw $_.FullName }) -join "`n"
        $script:RepoLab = $repoLab
    }

    It 'maps MS.AAD.3.9 to CA010 behind enable_device_code_block (built, not a gap)' {
        $Map['MS.AAD.3.9'].Lab | Should -Match '^CA010 '
        $Map['MS.AAD.3.9'].Flag | Should -Be 'enable_device_code_block'
        $Map['MS.AAD.3.9'].Lab | Should -Not -Match 'Not built'
        $CaText | Should -Match 'authentication_flow_transfer_methods\s*=\s*\["deviceCodeFlow"\]'
    }

    It 'maps MS.AAD.3.8 to CA009 as a compensating control, still expected to fail' {
        $Map['MS.AAD.3.8'].Lab | Should -Match '^CA009 '
        $Map['MS.AAD.3.8'].Flag | Should -Be 'enable_registration_ca'
        $Map['MS.AAD.3.8'].Expect | Should -Match '^Fail expected'
    }

    It 'names only staging flags that exist in envs/dev (or bootstrap)' {
        foreach ($k in $Map.Keys) {
            $f = $Map[$k].Flag
            if ($f -and $f -ne 'bootstrap') { $DevVars | Should -Contain $f -Because "$k names flag '$f'" }
        }
    }

    It 'gives every built control a flag and every "Not built" control none' {
        foreach ($k in $Map.Keys) {
            if ($Map[$k].Lab -match '^Not (built|set)') { $Map[$k].Flag | Should -BeNullOrEmpty -Because $k }
            else { $Map[$k].Flag | Should -Not -BeNullOrEmpty -Because $k }
        }
    }

    It 'names only CA policies, KQL files and post-apply scripts that exist' {
        foreach ($k in $Map.Keys) {
            $lab = $Map[$k].Lab
            foreach ($m in [regex]::Matches($lab, '\bCA0(0[1-9]|10)\b')) {
                $CaText | Should -Match ('\$\{var\.policy_name_prefix\}' + $m.Value.Substring(2) + ' - ') -Because "$k names $($m.Value)"
            }
            foreach ($m in [regex]::Matches($lab, 'lab/kql/[\w-]+\.kql')) {
                Join-Path $RepoLab ($m.Value.Substring(4)) | Should -Exist -Because "$k names $($m.Value)"
            }
            foreach ($m in [regex]::Matches($lab, 'post-apply/[\w-]+\.ps1')) {
                Get-LabScriptPath $m.Value | Should -Exist -Because "$k names $($m.Value)"
            }
        }
    }
}
