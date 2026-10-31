# Pester 5 tests for Diagnose-SignIn.ps1.
#   * The verdict logic (ConvertTo-SignInDiagnosis, loaded from the script's
#     syntax tree) on three synthetic sign-ins from
#     tests/fixtures/sign-ins.fixture.json: allowed after MFA, blocked by
#     CA004 (blocked country), allowed with a CA002 report-only failure; plus
#     the error-code table and an unknown code.
#   * The whole script against a mocked Invoke-MgGraphRequest answering from
#     the fixture: the filter sent, the text block, the Markdown report, a
#     failed read (exit 1, never "no sign-in"), and no sign-in found.
#   * Public-safe: no tenant id, object id or tenant domain in the script or
#     the fixture.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Diag = Get-LabScriptPath 'Diagnose-SignIn.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures' 'sign-ins.fixture.json'
    $script:Fixture = Get-Content -LiteralPath $script:FixturePath -Raw | ConvertFrom-Json -AsHashtable -Depth 20
    $script:SignIns = @($script:Fixture['value'])
    $script:Guid = '[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'

    # The pure functions need the script's two tables ($ErrorCodeText,
    # $GrantText): take the real assignments from the syntax tree, so the
    # tests check the table the script ships, not a copy.
    . (Get-ScriptFunctionBlock -Path $script:Diag)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Diag, [ref]$null, [ref]$null)
    $tables = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -in '$ErrorCodeText', '$GrantText' })
    $tables.Count | Should -Be 2 -Because 'the two plain-words tables sit at the top of the script'
    foreach ($t in $tables) { . ([scriptblock]::Create(($t.Extent.Text -replace '^\$', '$script:'))) }

    function Set-SignInGraphMocks {
        Mock Write-Host {}
        Mock Get-MgContext { New-MgContextStub -Scopes @('AuditLog.Read.All', 'Directory.Read.All') }
        Mock Connect-MgGraph { throw 'tests must never connect' }
        # Mock state through $global:, as the other suites do: the mock body
        # does not see this file's $script: variables.
        $global:SignInTest = @{ Fail = ''; Uris = [System.Collections.Generic.List[string]]::new(); Rows = @($script:SignIns) }
        Mock Invoke-MgGraphRequest {
            $global:SignInTest.Uris.Add($Uri)
            if ($global:SignInTest.Fail) { throw $global:SignInTest.Fail }
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -notlike '*/beta/auditLogs/signIns?*') { throw "unexpected Graph call in test: $Uri" }
            $rows = @($global:SignInTest.Rows)
            if ($decoded -match "correlationId eq '([^']+)'") { $rows = @($rows | Where-Object { $_['correlationId'] -eq $Matches[1] }) }
            if ($decoded -match "userPrincipalName eq '([^']+)'") { $rows = @($rows | Where-Object { $_['userPrincipalName'] -eq $Matches[1] }) }
            return @{ value = $rows }
        }
    }
}

AfterAll { Remove-Variable -Name SignInTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'ConvertTo-SignInDiagnosis (verdicts on the fixture)' {
    It 'success with MFA: "Allowed after MFA" and the method' {
        $d = ConvertTo-SignInDiagnosis $script:SignIns[0]
        $d.Verdict | Should -Be 'Allowed after MFA (Microsoft Authenticator app)'
        $d.Outcome | Should -Be 'Allowed'
        $d.ErrorCode | Should -Be 0
        $d.AppliedPolicies | Should -Be @('CA001')
        $d.ReportOnlyPolicies | Should -BeNullOrEmpty
        $d.Device | Should -Be 'compliant and managed, Windows 11'
        $d.Location | Should -Be 'Seattle, US'
        $d.Risk | Should -Be 'none'
        $d.TellUser | Should -Match 'Your sign-in worked'
        @($d.Text -split "`r?`n")[1] | Should -Be "Verdict: $($d.Verdict)"
        $d.Text | Should -Match 'CA001 +applied, passed; demanded MFA'
        $d.Text | Should -Match 'CA004 +not applied'
        $d.Text | Should -Match 'Tell the user: '
    }

    It 'blocked by CA004: the verdict names the country and the policy' {
        $d = ConvertTo-SignInDiagnosis $script:SignIns[1]
        $d.Verdict | Should -Be 'Blocked: the sign-in came from a country the hospital does not allow (KP) (policy CA004)'
        $d.Outcome | Should -Be 'Blocked'
        $d.ErrorCode | Should -Be 53003
        $d.ErrorText | Should -Be 'blocked by Conditional Access'
        $d.BlockingPolicies | Should -Be @('CA004')
        $d.Device | Should -Be 'unmanaged (not registered with the hospital), Android'
        $d.Risk | Should -Be 'medium (risk state: atRisk)'
        $d.TellUser | Should -Match 'Sign-ins from KP are not allowed'
        $d.Text | Should -Match 'CA004 +applied, NOT met; demanded block'
        $d.Text | Should -Match 'Graph says: Access has been blocked'
    }

    It 'blocked by CA010 (device code flow): names device code flow, not a device to enrol' {
        $d = ConvertTo-SignInDiagnosis @{
            status = @{ errorCode = 53003; failureReason = 'Access has been blocked by Conditional Access policies.' }; conditionalAccessStatus = 'failure'
            appliedConditionalAccessPolicies = @(@{ displayName = 'CA010 - Block device code flow'; result = 'failure'; enforcedGrantControls = @('Block'); enforcedSessionControls = @() })
        }
        $d.Verdict | Should -Be 'Blocked: the sign-in used device code flow, which is blocked (policy CA010)'
        $d.Outcome | Should -Be 'Blocked'
        $d.TellUser | Should -Match 'device code flow'
        $d.TellUser | Should -Not -Match 'enrol' -Because 'a device code flow block is not a device-compliance problem'
    }

    It 'report-only failure on CA002: allowed, with what would have happened' {
        $d = ConvertTo-SignInDiagnosis $script:SignIns[2]
        $d.Verdict | Should -Be 'Allowed, but policy CA002 would have blocked it once enforced (it demands a phishing-resistant method (authentication strength))'
        $d.Outcome | Should -Be 'Allowed, with a warning'
        $d.ErrorCode | Should -Be 0
        $d.AppliedPolicies | Should -Be @('CA001')
        $d.ReportOnlyPolicies | Should -Be @('CA002')
        $d.Mfa | Should -Be 'Mobile app notification (MFA completed in Azure AD)'
        $d.TellUser | Should -Match 'passkey or security key'
        $d.Text | Should -Match 'CA002 +report-only: WOULD HAVE BLOCKED'
        $d.Text | Should -Match 'CA004 +report-only: out of scope'
    }

    It 'maps the common error codes to plain words and prints an unknown code with the failureReason' {
        foreach ($code in 50053, 50126, 50074, 50076, 65001, 530032) {
            $d = ConvertTo-SignInDiagnosis @{ status = @{ errorCode = $code; failureReason = 'x' }; conditionalAccessStatus = 'notApplied'; appliedConditionalAccessPolicies = @() }
            $d.Verdict | Should -Be "Failed: $($script:ErrorCodeText[$code])" -Because "code $code"
            $d.TellUser | Should -Not -BeNullOrEmpty -Because "code $code"
            $d.TellUser | Should -Not -Match 'error \d+' -Because "code $code is a known code and gets a sentence, not a number"
        }
        $u = ConvertTo-SignInDiagnosis @{ status = @{ errorCode = 700016; failureReason = 'Application not found in the directory.' }; appliedConditionalAccessPolicies = @() }
        $u.Verdict | Should -Be 'Failed: error 700016: Application not found in the directory.'
        $u.TellUser | Should -Match '700016'
        $u.Text | Should -Match 'no Conditional Access policy applied'
    }

    It 'a non-Block failure says what the policy demanded; a password-only success says so' {
        $d = ConvertTo-SignInDiagnosis @{
            status = @{ errorCode = 53003; failureReason = 'Blocked by Conditional Access' }; conditionalAccessStatus = 'failure'
            appliedConditionalAccessPolicies = @(@{ displayName = 'CA005 - Require a compliant device for the admin portals'; result = 'failure'; enforcedGrantControls = @('CompliantDevice'); enforcedSessionControls = @() })
            deviceDetail = @{ isCompliant = $false; isManaged = $true; operatingSystem = 'Windows 10' }
        }
        $d.Verdict | Should -Be 'Blocked: policy CA005 demanded a compliant (managed and healthy) device and the sign-in did not provide it'
        $d.Device | Should -Be 'managed but NOT compliant, Windows 10'
        $d.TellUser | Should -Match 'compliant hospital device'
        $p = ConvertTo-SignInDiagnosis @{ status = @{ errorCode = 0 }; conditionalAccessStatus = 'notApplied'; authenticationRequirement = 'singleFactorAuthentication'; appliedConditionalAccessPolicies = @() }
        $p.Verdict | Should -Be 'Allowed with a password only (no MFA was demanded)'
    }
}

Describe 'Diagnose-SignIn.ps1 end to end (mocked Graph, answered from the fixture)' {
    BeforeAll { Set-SignInGraphMocks }
    BeforeEach { $global:SignInTest.Fail = ''; $global:SignInTest.Uris.Clear() }

    It '-CorrelationId: filters on it, returns one object, prints the verdict and writes the Markdown report' {
        $dir = Join-Path $TestDrive 'corr'
        $global:LASTEXITCODE = 0
        $out = @(& $script:Diag -CorrelationId '00000000-0000-4000-8000-0000000000c2' -OutputDirectory $dir)
        $LASTEXITCODE | Should -Be 0
        $out.Count | Should -Be 1
        $out[0].Verdict | Should -Be 'Blocked: the sign-in came from a country the hospital does not allow (KP) (policy CA004)'
        $u = [uri]::UnescapeDataString($global:SignInTest.Uris[0])
        $u | Should -BeLike "*/beta/auditLogs/signIns?*correlationId eq '00000000-0000-4000-8000-0000000000c2'*"
        $u | Should -BeLike '*$orderby=createdDateTime desc*'
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like 'Verdict: Blocked: the sign-in came from a country*' } -Times 1 -Exactly
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like 'Tell the user: Sign-ins from KP are not allowed*' } -Times 1 -Exactly
        $md = @(Get-ChildItem -LiteralPath $dir -Filter 'sign-in-diagnosis-*.md')
        $md.Count | Should -Be 1
        $text = Get-Content -LiteralPath $md[0].FullName -Raw
        $text | Should -Match '# Sign-in diagnosis'
        $text | Should -Match '## 1\. 2026-10-29T13:40:52Z - Blocked: the sign-in came from a country'
        $text | Should -Match 'Tell the user: Sign-ins from KP'
        $text | Should -Not -Match '11111111-1111-1111-1111-111111111111' -Because 'the tenant id from the Graph context must not reach the report'
    }

    It '-UserPrincipalName -LastHours: filters on the UPN and a createdDateTime floor, one object per sign-in, every verdict present' {
        $dir = Join-Path $TestDrive 'upn'
        $global:LASTEXITCODE = 0
        $out = @(& $script:Diag -UserPrincipalName 'nurse.one@contoso.test' -LastHours 48 -OutDir $dir)
        $LASTEXITCODE | Should -Be 0
        $out.Count | Should -Be 2
        @($out | ForEach-Object Verdict) | Should -Be @('Allowed after MFA (Microsoft Authenticator app)', 'Blocked: the sign-in came from a country the hospital does not allow (KP) (policy CA004)')
        $u = [uri]::UnescapeDataString($global:SignInTest.Uris[0])
        $u | Should -BeLike "*userPrincipalName eq 'nurse.one@contoso.test' and createdDateTime ge 20??-??-??T??:??:??Z*"
        $floor = [datetime]::Parse(([regex]::Match($u, 'createdDateTime ge (\S+?)&').Groups[1].Value), $null, 'AdjustToUniversal')
        $floor | Should -BeGreaterThan ((Get-Date).ToUniversalTime().AddHours(-49))
        $floor | Should -BeLessThan ((Get-Date).ToUniversalTime().AddHours(-47))
        $text = Get-Content -LiteralPath (@(Get-ChildItem -LiteralPath $dir -Filter '*.md')[0].FullName) -Raw
        $text | Should -Match '## 1\. .* Allowed after MFA'
        $text | Should -Match '## 2\. .* Blocked: '
    }

    It 'the admin sign-in: report-only CA002 is the verdict, not a footnote' {
        $out = @(& $script:Diag -UserPrincipalName 'adm-admin.two@contoso.test' -OutputDirectory (Join-Path $TestDrive 'adm'))
        $out.Count | Should -Be 1
        $out[0].Verdict | Should -BeLike 'Allowed, but policy CA002 would have blocked it once enforced*'
        $out[0].ReportOnlyPolicies | Should -Be @('CA002')
    }

    It 'a failed Graph read prints FAILED and exits 1, never "no sign-in", and writes no report' {
        $global:SignInTest.Fail = 'Forbidden: AuditLog.Read.All missing'
        $dir = Join-Path $TestDrive 'failed'
        $global:LASTEXITCODE = 0
        $out = @(& $script:Diag -CorrelationId '00000000-0000-4000-8000-0000000000c1' -OutputDirectory $dir -WarningAction SilentlyContinue)
        $LASTEXITCODE | Should -Be 1
        $out.Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like 'FAILED to read the sign-in log*UNKNOWN*' } -Times 1 -Exactly
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like 'No sign-in found*' } -Times 0 -Exactly
        Test-Path -LiteralPath $dir | Should -BeFalse
    }

    It 'no sign-in found is said in words, exit 0, and the report says so too' {
        $dir = Join-Path $TestDrive 'none'
        $global:LASTEXITCODE = 0
        $out = @(& $script:Diag -CorrelationId '00000000-0000-4000-8000-0000000000ff' -OutputDirectory $dir)
        $LASTEXITCODE | Should -Be 0
        $out.Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like 'No sign-in found for correlation id 00000000-0000-4000-8000-0000000000ff*' } -Times 1 -Exactly
        (Get-Content -LiteralPath (@(Get-ChildItem -LiteralPath $dir -Filter '*.md')[0].FullName) -Raw) | Should -Match 'No sign-in found'
    }

    It 'refuses a correlation id that is not a GUID (no OData injection) and needs one of the two inputs' {
        { & $script:Diag -CorrelationId "x' or 1 eq 1" -OutputDirectory $TestDrive } | Should -Throw
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }
}

Describe 'Diagnose-SignIn.ps1 is public-safe' {
    It 'the script holds no GUID, tenant domain, IP address or token-shaped string' {
        $src = Get-Content -LiteralPath $script:Diag -Raw
        $src | Should -Not -Match $script:Guid
        $src | Should -Not -Match 'onmicrosoft\.com|contosohealth\.io|\b\d{1,3}(\.\d{1,3}){3}\b|eyJ[A-Za-z0-9_-]{20,}'
    }

    It 'the fixture is synthetic: every GUID carries the 00000000-0000-4000-8000- prefix, every UPN is @contoso.test, every IP is TEST-NET' {
        $raw = Get-Content -LiteralPath $script:FixturePath -Raw
        $guids = @([regex]::Matches($raw, $script:Guid) | ForEach-Object Value | Sort-Object -Unique)
        $guids.Count | Should -BeGreaterThan 0
        foreach ($g in $guids) { $g | Should -BeLike '00000000-0000-4000-8000-*' }
        $raw | Should -Not -Match 'onmicrosoft|contosohealth\.io'
        foreach ($m in [regex]::Matches($raw, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+')) { $m.Value | Should -BeLike '*@contoso.test' }
        foreach ($m in [regex]::Matches($raw, '\b\d{1,3}(\.\d{1,3}){3}\b')) { $m.Value | Should -Match '^(192\.0\.2|198\.51\.100|203\.0\.113)\.' }
    }
}
