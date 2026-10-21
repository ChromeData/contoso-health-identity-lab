# Pester 5 tests for 00-Preflight.ps1 (tenant-day preflight).
#   * Pure functions (parsers, version maths, every finding builder), loaded
#     from the script's syntax tree: PASS / WARN / FAIL paths per check.
#   * Invoke-Preflight end to end against a fixture repo in TestDrive, with
#     the script's I/O adapters mocked (tools, modules, az, Graph): exit codes
#     0 / 1 / 2, and -Offline never reaches az or Microsoft Graph.
#   * The whole script, run with `&`, once per exit code (a crash is 2).
#   * The read-only contract from the syntax tree (no Mg write / sign-in
#     cmdlet, Graph only through one GET, no file or module writes), and the
#     az login-log adapter against a fake AZURE_CONFIG_DIR in TestDrive.
# No tenant, no real tool run and no network.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Pf = Get-LabScriptPath '00-Preflight.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Pf)

    # Repeated-digit placeholder ids (the public-repo GUID gate allows them).
    $script:TenantGuid = '22222222-2222-2222-2222-222222222222'
    $script:OtherGuid = '33333333-3333-3333-3333-333333333333'
    $script:SubGuid = '44444444-4444-4444-4444-444444444444'
    $script:Domain = 'contosolab.onmicrosoft.com'
    # Fake credentials for the redaction tests, assembled at run time so the
    # source holds no credential-shaped literal for the secret scanners.
    $script:UrlCred = 'x-access-token' + ':' + 'ghp_' + 'FAKEFAKEFAKE'
    function Get-PfRemoteUrl([string]$HostPath) { return 'https://' + $script:UrlCred + '@' + $HostPath }
    $script:FakeJwt = 'ey' + 'JhbGciOiJSUzI1NiJ9' + '.' + 'ey' + 'J0aWQiOiJ4eHh4eHh4In0' + '.' + 'c2lnbmF0dXJl' + 'LXZhbHVl'
    $script:FakeGhToken = 'gh' + 'p_' + ('Fake' * 9)
    $script:FakeUpn = 'admin' + '@' + $script:Domain
    $script:FakeHome = '/Users/' + 'someone'
    $script:GoodTfvars = @'
# fixture lab.tfvars: policy knobs only
enable_premium    = false
enable_governance = false
enable_sentinel   = false # starts its own trial
ca021_enforced_in_tenant = false
pim_tier0_activation_auth_context_id = ""

ca_policy_states = {
  CA001 = "enabledForReportingButNotEnforced" # require MFA
  CA002 = "enabledForReportingButNotEnforced"
  CA010 = "enabledForReportingButNotEnforced" # block device code
}

ca008_scope       = "all_users"
blocked_countries = ["KP", "IR"]
'@

    function New-PfRepo {
        # A minimal repo: versions.tf x2, the two workflow pins, lab.tfvars and
        # three scripts that declare $requiredScopes.
        param([string]$Tfvars = $script:GoodTfvars, [switch]$BuildSource, [switch]$NoTfvars, [hashtable]$Extra = @{})
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $files = @{
            'lab/terraform/envs/dev/versions.tf'                    = "terraform {`n  required_version = `">= 1.9.0`"`n}`n"
            'lab/terraform/envs/bootstrap/versions.tf'              = "terraform {`n  required_version = `">= 1.6.0`"`n}`n"
            '.github/workflows/terraform-apply.yml'                 = "        with:`n          terraform_version: `"1.16.5`"  # lock files`n"
            '.github/workflows/lab-tests.yml'                       = @'
          Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck
          Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser -Force
          foreach ($m in 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users') {
              Install-Module $m -RequiredVersion 2.41.2 -Scope CurrentUser -Force
          }
'@
            'lab/scripts/powershell/post-apply/Set-Fixture.ps1'     = "`$requiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess')`n"
            'lab/scripts/powershell/post-apply/New-AgentFixture.ps1' = "`$requiredScopes = if (`$Remove) { @('AgentIdentity.ReadWrite.All') } else { @('AgentIdentity.Create.All', 'User.Read.All') }`n"
            'lab/scripts/powershell/01-Verify-Baseline.ps1'         = "`$requiredScopes = @('Group.Read.All')`n"
        }
        if (-not $NoTfvars) { $files['lab/terraform/envs/dev/lab.tfvars'] = $Tfvars }
        foreach ($k in $Extra.Keys) { $files[$k] = $Extra[$k] }
        foreach ($k in $files.Keys) {
            $p = Join-Path $root $k
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
            Set-Content -LiteralPath $p -Value $files[$k] -NoNewline
        }
        if ($BuildSource) {
            New-Item -ItemType Directory -Force -Path (Join-Path $root 'build') | Out-Null
            Set-Content -LiteralPath (Join-Path $root 'build/make-public-repo.sh') -Value '#!/usr/bin/env bash'
        }
        return $root
    }

    function New-PfSku([string]$Part, [string]$Status = 'Enabled', [int]$Used = 6, [string[]]$Plans = @()) {
        @{ skuPartNumber = $Part; capabilityStatus = $Status; consumedUnits = $Used; prepaidUnits = @{ enabled = 25 }
            servicePlans = @($Plans | ForEach-Object { @{ servicePlanName = $_; provisioningStatus = 'Success' } }) }
    }
    function New-PfUser([string]$Nick, [bool]$Enabled = $true, [string]$Domain = $script:Domain, [int]$Licences = 1) {
        @{ mailNickname = $Nick; userPrincipalName = "$Nick@$Domain"; accountEnabled = $Enabled
            assignedLicenses = @(1..$Licences | Where-Object { $Licences -gt 0 } | ForEach-Object { @{ skuId = $script:OtherGuid } }) }
    }

    function Set-PfMock {
        # One fully healthy machine + tenant; each switch breaks one thing.
        param(
            [string]$Root,
            [string[]]$MissingTools = @(),
            [string]$Terraform = '1.16.5',
            [string]$GitStatus = '## main...origin/main',
            [string]$GitRemote = '',   # default: an origin URL with embedded (fake) credentials
            [int]$DaemonExit = 0,
            [string]$PsVersion = '7.6.1',
            [hashtable]$Modules = @{ 'Microsoft.Graph.Authentication' = @('2.41.2'); 'Microsoft.Graph.Users' = @('2.41.2'); 'Pester' = @('5.7.1'); 'PSScriptAnalyzer' = @('1.25.0') },
            [switch]$AzSignedOut,
            [string]$AzDomain = $script:Domain,
            $LoginArgs = 'login --tenant {}',
            [string]$BudgetJson = '[{"name":"lab-budget","amount":50.0,"timeGrain":"Monthly"}]',
            [string]$BudgetError = '',   # non-empty: `az consumption budget list` exits 1 with this stderr
            [switch]$NoGraph,
            [string]$GraphAuthFlow = 'InteractiveBrowser',
            [string]$GraphTenant = $script:TenantGuid,
            [string[]]$Scopes = @('Group.Read.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'User.Read.All', 'Organization.Read.All'),
            [object[]]$Skus = @((New-PfSku 'SPE_E5' -Plans 'AAD_PREMIUM', 'AAD_PREMIUM_P2', 'TEAMS1'), (New-PfSku 'Microsoft_Entra_ID_Governance' -Plans 'Entra_Identity_Governance')),
            [object[]]$BreakGlass = @((New-PfUser 'bg-admin-01'), (New-PfUser 'bg-admin-02')),
            [switch]$SkuReadFails
        )
        if (-not $GitRemote) { $url = Get-PfRemoteUrl 'github.com/owner/contoso-health-identity-lab.git'; $GitRemote = "origin`t$url (fetch)`norigin`t$url (push)" }
        $acct = @{ environmentName = 'AzureCloud'; homeTenantId = $script:TenantGuid; id = $script:SubGuid; isDefault = $true; name = 'Azure subscription 1'
            state = 'Enabled'; tenantDefaultDomain = $AzDomain; tenantDisplayName = 'Contoso Health Lab'; tenantId = $script:TenantGuid
            user = @{ name = "admin@$script:Domain"; type = 'user' } } | ConvertTo-Json
        $global:PfTest = @{ Root = $Root; Missing = $MissingTools; Terraform = $Terraform; GitStatus = $GitStatus; GitRemote = $GitRemote; DaemonExit = $DaemonExit
            PsVersion = $PsVersion; Modules = $Modules; AzSignedOut = [bool]$AzSignedOut; AzAccountJson = $acct; LoginArgs = $LoginArgs; BudgetJson = $BudgetJson; BudgetError = $BudgetError
            NoGraph = [bool]$NoGraph; GraphAuthFlow = $GraphAuthFlow; GraphTenant = $GraphTenant; Scopes = $Scopes; Skus = $Skus; BreakGlass = $BreakGlass
            SkuReadFails = [bool]$SkuReadFails; TenantGuid = $script:TenantGuid; Domain = $script:Domain; Lines = [System.Collections.Generic.List[string]]::new() }

        Mock Write-Host { $global:PfTest.Lines.Add([string]$Object) }
        Mock Get-PreflightPsVersion { [version]$global:PfTest.PsVersion }
        Mock Get-PreflightModuleVersion { @($global:PfTest.Modules[$Name] | Where-Object { $_ } | ForEach-Object { [version]$_ }) }
        Mock Get-PreflightCommandPath { if ($Name -in $global:PfTest.Missing) { $null } else { "/fake/bin/$Name" } }
        Mock Get-PreflightAzLoginArgument { $global:PfTest.LoginArgs }
        Mock Invoke-PreflightNative {
            $t = $global:PfTest
            $line = "$Name $($Arguments -join ' ')"
            $r = { param($Out, [int]$Code = 0, [string]$Err = '') [pscustomobject]@{ ExitCode = $Code; Output = $Out; ErrorText = $Err } }
            switch -Regex ($line) {
                '^terraform version -json$' { return & $r ('{"terraform_version":"' + $t.Terraform + '","platform":"darwin_arm64"}') }
                '^gitleaks version$' { return & $r '8.30.1' }
                '^trufflehog --no-update --version$' { return & $r '' 0 'trufflehog 3.97.9' }   # it prints to stderr
                '^shellcheck --version$' { return & $r "ShellCheck - shell script analysis tool`nversion: 0.11.0`nlicense: GNU General Public License, version 3" }
                '^actionlint -version$' { return & $r "1.7.12`ninstalled by downloading from release page" }
                '^gh --version$' { return & $r 'gh version 2.79.0 (2025-09-08)' }
                '^colima version$' { return & $r "colima version 0.10.3`ngit commit: 1234567" }
                '^docker --version$' { return & $r 'Docker version 29.9.0, build 1234567' }
                '^docker info ' { if ($t.DaemonExit) { return & $r '' $t.DaemonExit 'Cannot connect to the Docker daemon' }; return & $r '29.5.2' }
                # Every git call must carry --no-optional-locks (no index refresh).
                '^git --no-optional-locks -C .+ rev-parse --show-toplevel$' { return & $r $t.Root }
                '^git --no-optional-locks -C .+ status --porcelain=v1 --branch$' { return & $r $t.GitStatus }
                '^git --no-optional-locks -C .+ remote -v$' { return & $r $t.GitRemote }
                '^az version -o json$' { return & $r '{"azure-cli": "2.91.0", "azure-cli-core": "2.91.0"}' }
                '^az account show -o json$' { if ($t.AzSignedOut) { return & $r '' 1 "ERROR: Please run 'az login' to setup account." }; return & $r $t.AzAccountJson }
                '^az consumption budget list -o json$' { if ($t.BudgetError) { return & $r '' 1 $t.BudgetError }; return & $r $t.BudgetJson }
                default { throw "unexpected native call in test: $line" }
            }
        }
        Mock Get-PreflightGraphContext {
            if ($global:PfTest.NoGraph) { return $null }
            [pscustomobject]@{ TenantId = $global:PfTest.GraphTenant; Scopes = $global:PfTest.Scopes; AuthType = 'Delegated'
                TokenCredentialType = $global:PfTest.GraphAuthFlow; Account = "admin@$($global:PfTest.Domain)" }
        }
        Mock Invoke-PreflightGraph {
            $t = $global:PfTest
            switch -Regex ($Uri) {
                '/organization\?' { return @{ value = @(@{ displayName = 'Contoso Health Lab'; verifiedDomains = @(@{ name = 'contosohealth.example'; isInitial = $false }, @{ name = $t.Domain; isInitial = $true }) }) } }
                '/subscribedSkus$' { if ($t.SkuReadFails) { throw "Insufficient privileges to complete the operation. request-id: $($t.TenantGuid)" }; return @{ value = @($t.Skus) } }
                '/users\?' { return @{ value = @($t.BreakGlass) } }
                default { throw "unexpected Graph call in test: $Uri" }
            }
        }
    }

    function Invoke-Pf([hashtable]$With = @{}) {
        $p = @{ RepoRoot = $global:PfTest.Root } + $With
        $r = Invoke-Preflight @p
        return [pscustomobject]@{ Exit = $r.ExitCode; Results = @($r.Results); Lines = @($global:PfTest.Lines) }
    }
    function Get-PfFinding($Run, [string]$Check) { @($Run.Results | Where-Object { $_.Check -eq $Check }) }
}

AfterAll { Remove-Variable -Name PfTest -Scope Global -ErrorAction SilentlyContinue }

Describe 'version maths' {
    It 'reads "<Text>" as <Want>' -ForEach @(
        @{ Text = 'v8.30.1'; Want = '8.30.1' }
        @{ Text = 'trufflehog 3.97.9'; Want = '3.97.9' }
        @{ Text = 'Docker version 29.9.0, build 1234567'; Want = '29.9.0' }
        @{ Text = 'git version 2.39.5 (Apple Git-154)'; Want = '2.39.5' }
        @{ Text = '1.7'; Want = '1.7.0' }
    ) {
        [string](ConvertTo-PreflightVersion $Text) | Should -Be $Want
    }

    It 'returns $null for text without a version' {
        ConvertTo-PreflightVersion 'not installed' | Should -BeNullOrEmpty
        ConvertTo-PreflightVersion '' | Should -BeNullOrEmpty
    }

    It '<Version> vs "<Constraint>" -> <Ok>' -ForEach @(
        @{ Version = '1.16.5'; Constraint = '>= 1.9.0'; Ok = $true }
        @{ Version = '1.8.9'; Constraint = '>= 1.9.0'; Ok = $false }
        @{ Version = '1.16.5'; Constraint = '~> 1.6'; Ok = $true }
        @{ Version = '2.0.0'; Constraint = '~> 1.6'; Ok = $false }
        @{ Version = '1.6.9'; Constraint = '~> 1.6.0'; Ok = $true }
        @{ Version = '1.7.0'; Constraint = '~> 1.6.0'; Ok = $false }
        @{ Version = '1.16.5'; Constraint = '>= 1.6, < 2.0'; Ok = $true }
        @{ Version = '2.1.0'; Constraint = '>= 1.6, < 2.0'; Ok = $false }
        @{ Version = '1.16.5'; Constraint = '1.16.5'; Ok = $true }
        @{ Version = '1.16.5'; Constraint = '!= 1.16.5'; Ok = $false }
    ) {
        Test-VersionConstraint -Version ([version]$Version) -Constraint $Constraint | Should -Be $Ok
    }

    It 'refuses a constraint it cannot read instead of guessing' {
        { Test-VersionConstraint -Version ([version]'1.0.0') -Constraint '>= latest' } | Should -Throw '*unsupported*'
    }

    It 'the committed envs/dev required_version accepts the CI-pinned Terraform' {
        $tf = Join-Path $script:LabPowerShellRoot '../../terraform/envs/dev/versions.tf'
        $c = Get-TerraformRequiredVersion (Get-Content -LiteralPath $tf -Raw)
        $c | Should -Not -BeNullOrEmpty
        Test-VersionConstraint -Version ([version]'1.16.5') -Constraint $c | Should -BeTrue
    }

    It 'Get-CiPin falls back to the default when the pattern is absent' {
        Get-CiPin -Text 'terraform_version: "1.17.0"' -Pattern 'terraform_version:\s*"([0-9.]+)"' -Default '1.16.5' | Should -Be '1.17.0'
        Get-CiPin -Text $null -Pattern 'x(\d)' -Default '1.16.5' | Should -Be '1.16.5'
    }
}

Describe 'lab.tfvars (Read-LabTfvarsFile, Get-TfvarsFinding)' {
    It 'reads the boolean flags and the CA map, ignoring comments and non-boolean knobs' {
        $p = Read-LabTfvarsFile -Text $script:GoodTfvars
        @($p.Flags.Keys) | Should -Be @('enable_premium', 'enable_governance', 'enable_sentinel', 'ca021_enforced_in_tenant')
        @($p.CaStates.Keys) | Should -Be @('CA001', 'CA002', 'CA010')
        $p.CaStates['CA010'] | Should -Be 'enabledForReportingButNotEnforced'
        $p.HasCaBlock | Should -BeTrue
        $p.Unterminated | Should -BeFalse
    }

    It 'parses the committed lab.tfvars: flags found, CA map closed, every state a real CA state' {
        $text = Get-Content -LiteralPath (Join-Path $script:LabPowerShellRoot '../../terraform/envs/dev/lab.tfvars') -Raw
        $p = Read-LabTfvarsFile -Text $text
        $p.Flags.Count | Should -BeGreaterThan 10
        $p.Flags.Contains('enable_premium') | Should -BeTrue
        $p.HasCaBlock | Should -BeTrue
        $p.Unterminated | Should -BeFalse
        $p.CaStates.Count | Should -BeGreaterThan 0
        @($p.CaStates.Values | Where-Object { $_ -cnotin @('enabledForReportingButNotEnforced', 'enabled', 'disabled') }).Count | Should -Be 0
    }

    It 'all false + all report-only: two PASS lines' {
        $f = @(Get-TfvarsFinding -Parsed (Read-LabTfvarsFile -Text $script:GoodTfvars))
        @($f | Where-Object Status -ne 'PASS').Count | Should -Be 0
        ($f | Where-Object Check -eq 'lab.tfvars staging flags').Detail | Should -Be '4 flags, all false'
        ($f | Where-Object Check -eq 'lab.tfvars ca_policy_states').Detail | Should -Match '^3 policies, all report-only'
    }

    It 'a flag on before its day FAILs by name; acknowledged, it PASSes' {
        $p = Read-LabTfvarsFile -Text ($script:GoodTfvars -replace 'enable_sentinel   = false', 'enable_sentinel   = true')
        $f = @(Get-TfvarsFinding -Parsed $p)
        $fail = @($f | Where-Object Status -eq 'FAIL')
        $fail.Count | Should -Be 1
        $fail[0].Detail | Should -Match 'on before its day: enable_sentinel'
        $f2 = @(Get-TfvarsFinding -Parsed $p -ExpectedOnFlags 'enable_sentinel')
        @($f2 | Where-Object Status -ne 'PASS').Count | Should -Be 0
        ($f2 | Where-Object Check -eq 'lab.tfvars staging flags').Detail | Should -Match 'on by design \(-ExpectedOnFlags\): enable_sentinel'
    }

    It 'an acknowledged flag that is actually false is a WARN' {
        $f = @(Get-TfvarsFinding -Parsed (Read-LabTfvarsFile -Text $script:GoodTfvars) -ExpectedOnFlags 'enable_premium')
        ($f | Where-Object Status -eq 'WARN').Detail | Should -Match 'names enable_premium, but lab.tfvars has it false'
    }

    It 'CA state <State> -> <Status>' -ForEach @(
        @{ State = 'enabled'; Expected = @(); Status = 'FAIL'; Match = 'CA002 is enforced' }
        @{ State = 'enabled'; Expected = @('CA002'); Status = 'PASS'; Match = 'enforced by design: CA002' }
        @{ State = 'disabled'; Expected = @(); Status = 'WARN'; Match = "CA002 is 'disabled'" }
        @{ State = 'enabledForReporting'; Expected = @(); Status = 'FAIL'; Match = 'not a Conditional Access state' }
    ) {
        $p = Read-LabTfvarsFile -Text ($script:GoodTfvars -replace 'CA002 = "enabledForReportingButNotEnforced"', "CA002 = `"$State`"")
        $ca = @(Get-TfvarsFinding -Parsed $p -ExpectedEnforcedPolicies $Expected | Where-Object Check -eq 'lab.tfvars ca_policy_states')
        $ca.Count | Should -Be 1
        $ca[0].Status | Should -Be $Status
        $ca[0].Detail | Should -Match $Match
    }

    It 'an -ExpectedEnforcedPolicies entry still report-only is a WARN' {
        $ca = @(Get-TfvarsFinding -Parsed (Read-LabTfvarsFile -Text $script:GoodTfvars) -ExpectedEnforcedPolicies 'CA001' | Where-Object Check -eq 'lab.tfvars ca_policy_states')
        $ca[0].Status | Should -Be 'WARN'
        $ca[0].Detail | Should -Match "names CA001, but lab.tfvars has it 'enabledForReportingButNotEnforced'"
    }

    It 'a missing file, a missing map or an unclosed map is a FAIL, never "nothing on"' {
        (@(Get-TfvarsFinding -Parsed $null))[0].Status | Should -Be 'FAIL'
        $noMap = Read-LabTfvarsFile -Text "enable_premium = false`n"
        (@(Get-TfvarsFinding -Parsed $noMap) | Where-Object Check -eq 'lab.tfvars ca_policy_states').Status | Should -Be 'FAIL'
        $open = Read-LabTfvarsFile -Text "enable_premium = false`nca_policy_states = {`n  CA001 = `"enabled`"`n"
        $open.Unterminated | Should -BeTrue
        (@(Get-TfvarsFinding -Parsed $open) | Where-Object Check -eq 'lab.tfvars ca_policy_states').Detail | Should -Match 'not closed'
        (@(Get-TfvarsFinding -Parsed (Read-LabTfvarsFile -Text "ca_policy_states = {`n}`n")) | Where-Object Check -eq 'lab.tfvars staging flags').Status | Should -Be 'FAIL'
    }
}

Describe 'local tool and module findings' {
    It 'terraform: <Case> -> <Status>' -ForEach @(
        @{ Case = 'pinned and in range'; Path = '/x/terraform'; Json = '{"terraform_version":"1.16.5"}'; Status = 'PASS'; Match = '1\.16\.5 \(CI pin 1\.16\.5\); satisfies envs/dev >= 1\.9\.0, envs/bootstrap >= 1\.6\.0' }
        @{ Case = 'below required_version'; Path = '/x/terraform'; Json = '{"terraform_version":"1.8.0"}'; Status = 'FAIL'; Match = '1\.8\.0 does not satisfy envs/dev required_version ">= 1\.9\.0"' }
        @{ Case = 'newer than the CI pin'; Path = '/x/terraform'; Json = '{"terraform_version":"1.17.0"}'; Status = 'WARN'; Match = 'differs from the CI pin 1\.16\.5' }
        @{ Case = 'missing'; Path = ''; Json = ''; Status = 'FAIL'; Match = 'not on PATH' }
        @{ Case = 'unreadable version'; Path = '/x/terraform'; Json = 'segfault'; Status = 'FAIL'; Match = 'could not be read' }
    ) {
        $f = @(Get-TerraformFinding -Path $Path -VersionText $Json -Constraints ([ordered]@{ 'envs/dev' = '>= 1.9.0'; 'envs/bootstrap' = '>= 1.6.0' }) -Pin '1.16.5')
        $worst = if ($f.Status -contains 'FAIL') { 'FAIL' } elseif ($f.Status -contains 'WARN') { 'WARN' } else { 'PASS' }
        $worst | Should -Be $Status
        ($f.Detail -join "`n") | Should -Match $Match
    }

    It 'a missing secret-scan tool is a FAIL, a missing linter a WARN' {
        (Get-ToolFinding -Name 'trufflehog' -Path $null -MissingStatus FAIL -Purpose 'the pre-push secret gate').Status | Should -Be 'FAIL'
        (Get-ToolFinding -Name 'actionlint' -Path '' -MissingStatus WARN).Status | Should -Be 'WARN'
    }

    It 'reads a version with a pattern, WARNs when a present tool prints none, and never prints its path' {
        $f = Get-ToolFinding -Name 'shellcheck' -Path '/Users/someone/.local/bin/shellcheck' -VersionText "ShellCheck`nversion: 0.11.0`nlicense: GPL, version 3" -VersionPattern 'version:\s*(\S+)'
        $f.Status | Should -Be 'PASS'
        $f.Detail | Should -Match '^0\.11\.0'
        $f.Detail | Should -Not -Match 'someone'
        (Get-ToolFinding -Name 'gitleaks' -Path '/x/gitleaks' -VersionText 'panic: runtime error').Status | Should -Be 'WARN'
        (Get-ToolFinding -Name 'az' -Path '/x/az' -PresenceOnly -PresenceNote '; offline').Detail | Should -Be 'on PATH; offline'
    }

    It 'Graph modules: missing -> FAIL, off the CI pin -> WARN, all pinned -> PASS' {
        $f = @(Get-ModuleSetFinding -Check 'Microsoft Graph modules' -Installed ([ordered]@{ 'Microsoft.Graph.Authentication' = @([version]'2.40.0'); 'Microsoft.Graph.Users' = @() }) -Pin '2.41.2')
        ($f | Where-Object Status -eq 'FAIL').Detail | Should -Match 'missing: Microsoft\.Graph\.Users - Install-Module <name> -RequiredVersion 2\.41\.2'
        ($f | Where-Object Status -eq 'WARN').Detail | Should -Match 'Microsoft\.Graph\.Authentication \(has 2\.40\.0\)'
        $ok = @(Get-ModuleSetFinding -Check 'g' -Installed ([ordered]@{ a = @([version]'2.41.2', [version]'2.40.0'); b = @([version]'2.41.2') }) -Pin '2.41.2')
        $ok.Count | Should -Be 1
        $ok[0].Status | Should -Be 'PASS'
        $ok[0].Detail | Should -Be '2/2 installed at 2.41.2'
    }

    It 'Graph modules: the pin everywhere but a stray newer sub-module -> WARN (auto-load would mix versions)' {
        $f = @(Get-ModuleSetFinding -Check 'g' -Installed ([ordered]@{ 'Microsoft.Graph.Authentication' = @([version]'2.42.0', [version]'2.41.2'); 'Microsoft.Graph.Users' = @([version]'2.41.2') }) -Pin '2.41.2')
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'WARN'
        $f[0].Detail | Should -Match 'newest installed versions differ \(Microsoft\.Graph\.Authentication 2\.42\.0, Microsoft\.Graph\.Users 2\.41\.2\)'
        # Every module carrying the same newer version alongside the pin loads consistently: PASS.
        (@(Get-ModuleSetFinding -Check 'g' -Installed ([ordered]@{ a = @([version]'2.42.0', [version]'2.41.2'); b = @([version]'2.42.0', [version]'2.41.2') }) -Pin '2.41.2'))[0].Status | Should -Be 'PASS'
    }

    It 'Pester: none or too old -> WARN; 5.5+ -> PASS and says whether the CI pin is there' {
        (Get-TestModuleFinding -Name 'Pester' -Versions @() -Minimum '5.5.0' -Pin '5.7.1').Status | Should -Be 'WARN'
        (Get-TestModuleFinding -Name 'Pester' -Versions @([version]'3.4.0') -Minimum '5.5.0' -Pin '5.7.1').Detail | Should -Match 'older than 5\.5\.0'
        (Get-TestModuleFinding -Name 'Pester' -Versions @([version]'6.2.0', [version]'5.7.1') -Minimum '5.5.0' -Pin '5.7.1').Detail | Should -Be '6.2.0; CI pin 5.7.1 installed'
        (Get-TestModuleFinding -Name 'Pester' -Versions @([version]'5.6.0') -Minimum '5.5.0' -Pin '5.7.1').Status | Should -Be 'PASS'
    }

    It 'PowerShell <Version> -> <Status>' -ForEach @(
        @{ Version = '5.1.0'; Status = 'FAIL' }
        @{ Version = '7.6.1'; Status = 'PASS' }
        @{ Version = '8.0.0'; Status = 'WARN' }
    ) {
        (Get-PowerShellFinding -Version ([version]$Version)).Status | Should -Be $Status
    }

    It 'containers: daemon down -> WARN with the Colima start line; no docker -> WARN; up -> PASS' {
        $down = Get-ContainerFinding -ColimaPath '/x/colima' -ColimaVersionText 'colima version 0.10.3' -DockerPath '/x/docker' -DockerVersionText 'Docker version 29.9.0' -DaemonExitCode 1 -StartHint 'colima start --cpu 4'
        $down.Status | Should -Be 'WARN'
        $down.Detail | Should -Match 'not reachable.*colima start --cpu 4'
        (Get-ContainerFinding -ColimaPath '' -DockerPath '').Detail | Should -Match 'docker CLI not on PATH'
        $up = Get-ContainerFinding -ColimaPath '/x/colima' -ColimaVersionText 'colima version 0.10.3' -DockerPath '/x/docker' -DockerVersionText 'Docker version 29.9.0' -DaemonExitCode 0 -DaemonVersionText '29.5.2'
        $up.Status | Should -Be 'PASS'
        $up.Detail | Should -Be 'daemon up (server 29.5.2); docker CLI 29.9.0, colima 0.10.3'
    }
}

Describe 'git state' {
    It 'parses the porcelain branch header and counts changed paths' {
        $s = ConvertFrom-GitStatus -Text "## main...origin/main [ahead 1, behind 2]`n M lab/x.ps1`n?? new.txt"
        $s.Branch | Should -Be 'main'
        $s.Upstream | Should -Be 'origin/main'
        $s.Ahead | Should -Be 1
        $s.Behind | Should -Be 2
        $s.Changes | Should -Be 2
        (ConvertFrom-GitStatus -Text '## lab-build-v1').Upstream | Should -Be ''
        (ConvertFrom-GitStatus -Text '## HEAD (no branch)').Detached | Should -BeTrue
        (ConvertFrom-GitStatus -Text '## No commits yet on main').Branch | Should -Be 'main'
        (ConvertFrom-GitStatus -Text '## release-1.2...origin/release-1.2 [gone]').Gone | Should -BeTrue
    }

    It 'strips credentials and the scheme from remote URLs' {
        $url = Get-PfRemoteUrl 'github.com/o/r.git'
        $r = @(ConvertFrom-GitRemote -Text "origin`t$url (fetch)`norigin`t$url (push)")
        $r.Count | Should -Be 1
        $r[0].Url | Should -Be 'github.com/o/r.git'
    }

    It 'shows SSH remotes (scp-like and ssh://) as host/path, without the user' {
        $r = @(ConvertFrom-GitRemote -Text "origin`tgit@github.com:o/r.git (fetch)`nupstream`tssh://git@github.com/o/u.git (fetch)")
        $r[0].Url | Should -Be 'github.com/o/r.git'
        $r[1].Url | Should -Be 'github.com/o/u.git'
    }

    It '<Case> -> <Status>' -ForEach @(
        @{ Case = 'clean, tracking'; Header = '## main...origin/main [ahead 1]'; Remote = $true; Private = $false; Status = 'PASS'; Match = 'branch main, clean, tracking origin/main, 1 ahead; origin -> github\.com/o/r\.git' }
        @{ Case = 'uncommitted changes'; Header = "## main...origin/main`n M a"; Remote = $true; Private = $false; Status = 'WARN'; Match = '1 uncommitted change' }
        @{ Case = 'behind upstream'; Header = '## main...origin/main [behind 3]'; Remote = $true; Private = $false; Status = 'WARN'; Match = '3 commit\(s\) behind origin/main as of the last fetch' }
        @{ Case = 'no remote'; Header = '## main'; Remote = $false; Private = $false; Status = 'WARN'; Match = 'no git remote' }
        @{ Case = 'the build source'; Header = '## main...origin/main'; Remote = $true; Private = $true; Status = 'WARN'; Match = 'build source, not the published clone' }
        @{ Case = 'detached HEAD'; Header = '## HEAD (no branch)'; Remote = $true; Private = $false; Status = 'WARN'; Match = 'detached HEAD' }
    ) {
        $remotes = @(if ($Remote) { [pscustomobject]@{ Name = 'origin'; Url = 'github.com/o/r.git' } })
        $f = @(Get-GitFinding -IsRepo $true -Status (ConvertFrom-GitStatus -Text $Header) -Remotes $remotes -IsBuildSource $Private)
        $worst = if ($f.Status -contains 'WARN') { 'WARN' } else { 'PASS' }
        $worst | Should -Be $Status
        ($f.Detail -join "`n") | Should -Match $Match
    }

    It 'not a git checkout is a FAIL' {
        (@(Get-GitFinding -IsRepo $false -Status $null))[0].Status | Should -Be 'FAIL'
    }
}

Describe 'Azure CLI findings' {
    BeforeAll {
        $script:AcctJson = @{ id = $script:SubGuid; name = 'Azure subscription 1'; state = 'Enabled'; tenantDefaultDomain = $script:Domain; tenantId = $script:TenantGuid
            user = @{ name = "admin@$script:Domain"; type = 'user' } } | ConvertTo-Json
    }

    It 'reads az account show without keeping anything printable but the domain and names' {
        $a = ConvertFrom-AzAccount -Json $script:AcctJson
        $a.Domain | Should -Be $script:Domain
        $a.TenantId | Should -Be $script:TenantGuid
        $a.HasSubscription | Should -BeTrue
        (ConvertFrom-AzAccount -Json (@{ name = 'N/A(tenant level account)'; tenantId = $script:TenantGuid; state = 'Enabled' } | ConvertTo-Json)).HasSubscription | Should -BeFalse
        ConvertFrom-AzAccount -Json 'not json' | Should -BeNullOrEmpty
    }

    It 'signed in: PASS with the domain, never an id or the UPN' {
        $f = @(Get-AzAccountFinding -Account (ConvertFrom-AzAccount -Json $script:AcctJson) -ExpectedDomain $script:Domain)
        @($f | Where-Object Status -ne 'PASS').Count | Should -Be 0
        ($f.Detail -join ' ') | Should -Match ([regex]::Escape($script:Domain))
        ($f.Detail -join ' ') | Should -Not -Match "$script:TenantGuid|$script:SubGuid|admin@"
    }

    It 'not signed in: FAIL with a browser az login, never device code' {
        $f = @(Get-AzAccountFinding -Account $null -ExpectedDomain $script:Domain)
        $f[0].Status | Should -Be 'FAIL'
        $f[0].Detail | Should -Match "az login --tenant $([regex]::Escape($script:Domain))"
        $f[0].Detail | Should -Match 'never --use-device-code'
    }

    It '<Case> -> <Status>' -ForEach @(
        @{ Case = 'service principal'; Patch = @{ user = @{ type = 'servicePrincipal' } }; Expected = ''; Check = 'Azure CLI sign-in'; Status = 'WARN' }
        @{ Case = 'another tenant'; Patch = @{ tenantDefaultDomain = 'fabrikam.onmicrosoft.com' }; Expected = 'contosolab.onmicrosoft.com'; Check = 'Azure CLI sign-in'; Status = 'FAIL' }
        @{ Case = 'tenant-level login'; Patch = @{ name = 'N/A(tenant level account)' }; Expected = ''; Check = 'Azure subscription'; Status = 'WARN' }
        @{ Case = 'subscription disabled'; Patch = @{ state = 'Disabled' }; Expected = ''; Check = 'Azure subscription'; Status = 'FAIL' }
        @{ Case = 'subscription past due'; Patch = @{ state = 'PastDue' }; Expected = ''; Check = 'Azure subscription'; Status = 'WARN' }
    ) {
        $h = $script:AcctJson | ConvertFrom-Json -AsHashtable
        foreach ($k in $Patch.Keys) { $h[$k] = $Patch[$k] }
        $f = @(Get-AzAccountFinding -Account (ConvertFrom-AzAccount -Json ($h | ConvertTo-Json)) -ExpectedDomain $Expected)
        ($f | Where-Object Check -eq $Check).Status | Should -Be $Status
    }

    It 'login method: device code -> WARN (CA010); browser -> PASS; no log left -> PASS that says so; signed out -> nothing' {
        $w = Get-AzLoginMethodFinding -LastLoginArgs 'login --use-device-code --tenant {}'
        $w.Status | Should -Be 'WARN'
        $w.Detail | Should -Match 'CA010'
        (Get-AzLoginMethodFinding -LastLoginArgs 'login --tenant {}').Status | Should -Be 'PASS'
        (Get-AzLoginMethodFinding -LastLoginArgs $null).Detail | Should -Match 'keeps recent commands only'
        Get-AzLoginMethodFinding -LastLoginArgs '--use-device-code' -SignedIn $false | Should -BeNullOrEmpty
    }

    It 'login method: an abbreviated --use-device flag still WARNs; an unreadable command log WARNs, never "no login"' {
        (Get-AzLoginMethodFinding -LastLoginArgs 'login --use-device --tenant {}').Status | Should -Be 'WARN'
        (Get-AzLoginMethodFinding -LastLoginArgs 'login --tenant {} --use-device-code').Status | Should -Be 'WARN'
        (Get-AzLoginMethodFinding -LastLoginArgs 'login --username {}').Status | Should -Be 'PASS'
        $u = Get-AzLoginMethodFinding -LastLoginArgs $null -ReadError 'Access to the path is denied.'
        $u.Status | Should -Be 'WARN'
        $u.Detail | Should -Match 'could not read az''s command log \(Access to the path is denied\.\)'
    }

    It 'az error text: the ERROR line wins over az''s preview / upgrade warnings, else the exit code' {
        $stderr = "Command group 'consumption' is in preview and under development. Reference and support levels: https://aka.ms/CLI_refstatus`nWARNING: A newer version of the Azure CLI is available.`nERROR: (AuthorizationFailed) The client has no access."
        Get-AzErrorLine -Text $stderr | Should -Be 'ERROR: (AuthorizationFailed) The client has no access.'
        Get-AzErrorLine -Text "WARNING: something`nplain failure text" | Should -Be 'plain failure text'
        Get-AzErrorLine -Text "Command group 'consumption' is in preview and under development." -ExitCode 3 | Should -Be 'exit 3'
        Get-AzErrorLine -Text '' -ExitCode 2 | Should -Be 'exit 2'
    }

    It 'budget: <Case> -> <Status>' -ForEach @(
        @{ Case = '$50 monthly'; Budgets = @(@{ name = 'lab'; amount = 50.0; timeGrain = 'Monthly' }); Err = ''; SignedIn = $true; Status = 'PASS'; Match = "'lab' \`$50/Monthly" }
        @{ Case = 'none'; Budgets = @(); Err = ''; SignedIn = $true; Status = 'WARN'; Match = 'no Azure cost budget' }
        @{ Case = 'above the cap'; Budgets = @(@{ name = 'big'; amount = 500.0; timeGrain = 'Monthly' }); Err = ''; SignedIn = $true; Status = 'WARN'; Match = 'above the cap' }
        @{ Case = 'unreadable'; Budgets = $null; Err = 'Forbidden'; SignedIn = $true; Status = 'WARN'; Match = 'could not read budgets.*Forbidden' }
        @{ Case = 'az signed out'; Budgets = $null; Err = ''; SignedIn = $false; Status = 'WARN'; Match = 'not checked' }
    ) {
        $f = Get-BudgetFinding -Budgets $Budgets -ReadError $Err -CapUsd 150 -SignedIn $SignedIn
        $f.Status | Should -Be $Status
        $f.Detail | Should -Match $Match
        $f.Detail | Should -Match 'cap \$150'
        $f.Detail | Should -Match 'recurring billing Off on every trial'
    }
}

Describe 'Microsoft Graph findings' {
    It 'not connected: FAIL with the Connect-MgGraph line (browser, never -UseDeviceCode)' {
        $f = @(Get-GraphContextFinding -Context $null -ConnectScopes @('Group.Read.All', 'Policy.Read.All'))
        $f[0].Status | Should -Be 'FAIL'
        $f[0].Detail | Should -Match "Connect-MgGraph -Scopes 'Group\.Read\.All','Policy\.Read\.All' -NoWelcome"
        $f[0].Detail | Should -Match 'never -UseDeviceCode'
    }

    It '<Case> -> <Status>' -ForEach @(
        @{ Case = 'interactive, same tenant'; Auth = 'Delegated'; Cred = 'InteractiveBrowser'; Tid = '22222222-2222-2222-2222-222222222222'; Status = 'PASS' }
        @{ Case = 'device code'; Auth = 'Delegated'; Cred = 'DeviceCode'; Tid = '22222222-2222-2222-2222-222222222222'; Status = 'WARN' }
        @{ Case = 'app-only'; Auth = 'AppOnly'; Cred = 'ClientCertificate'; Tid = '22222222-2222-2222-2222-222222222222'; Status = 'WARN' }
        @{ Case = 'another tenant than az'; Auth = 'Delegated'; Cred = 'InteractiveBrowser'; Tid = '33333333-3333-3333-3333-333333333333'; Status = 'FAIL' }
    ) {
        $ctx = [pscustomobject]@{ AuthType = $Auth; TokenCredentialType = $Cred; TenantId = $Tid; Scopes = @() }
        $f = @(Get-GraphContextFinding -Context $ctx -AzTenantId $script:TenantGuid)
        $worst = if ($f.Status -contains 'FAIL') { 'FAIL' } elseif ($f.Status -contains 'WARN') { 'WARN' } else { 'PASS' }
        $worst | Should -Be $Status
        ($f.Detail -join ' ') | Should -Not -Match '[0-9a-f]{8}-[0-9a-f]{4}-'
    }

    It 'scopes: missing -> WARN naming them; the Agent ID preview scopes never WARN; case-insensitive' {
        $w = Get-ScopeFinding -Granted @('group.read.all') -Required @('Group.Read.All', 'Policy.Read.All') -Optional @('AgentIdentity.Create.All') -Source 'test'
        $w.Status | Should -Be 'WARN'
        $w.Detail | Should -Match '^1 of 2 missing \(test\): Policy\.Read\.All\.'
        $w.Detail | Should -Match "Connect-MgGraph -Scopes 'Group\.Read\.All','Policy\.Read\.All'"
        $p = Get-ScopeFinding -Granted @('Group.Read.All', 'Policy.Read.All') -Required @('Group.Read.All', 'Policy.Read.All') -Optional @('AgentIdentity.Create.All')
        $p.Status | Should -Be 'PASS'
        $p.Detail | Should -Match 'Agent ID preview scope'
    }

    It 'derives the scope list from the real post-apply scripts (cannot drift from them)' {
        $files = @(Get-ChildItem -LiteralPath (Get-LabScriptPath 'post-apply') -Filter '*.ps1' | ForEach-Object FullName) + @(Get-LabScriptPath '01-Verify-Baseline.ps1')
        $s = Get-PostApplyScopeSet -Path $files
        $s.FilesRead | Should -Be $files.Count
        foreach ($want in 'Policy.ReadWrite.ConditionalAccess', 'RoleManagementPolicy.ReadWrite.Directory', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'EntitlementManagement.ReadWrite.All') {
            $s.Scopes | Should -Contain $want
        }
        @($s.Scopes | Where-Object { $_ -match '^AgentIdentity' }).Count | Should -BeGreaterThan 0
    }

    It 'collects every branch of a conditional $requiredScopes and ignores other strings' {
        $p = Join-Path $TestDrive 'scopes.ps1'
        Set-Content -LiteralPath $p -Value "`$requiredScopes = if (`$x) { @('A.Read.All') } else { @('B.ReadWrite.All', 'not a scope') }`n`$other = @('C.Read.All')"
        (Get-PostApplyScopeSet -Path @($p)).Scopes | Should -Be @('A.Read.All', 'B.ReadWrite.All')
    }

    It 'tenant domain: PASS, wrong tenant FAIL, unreadable FAIL, not compared (no -OnMicrosoftDomain) WARN' {
        $org = @{ displayName = 'Contoso Health Lab'; verifiedDomains = @(@{ name = 'contoso.example'; isInitial = $false }, @{ name = $script:Domain; isInitial = $true }) }
        (Get-TenantDomainFinding -Organization $org -ExpectedDomain $script:Domain).Detail | Should -Be "$script:Domain (Contoso Health Lab)"
        (Get-TenantDomainFinding -Organization $org -ExpectedDomain 'fabrikam.onmicrosoft.com').Status | Should -Be 'FAIL'
        (Get-TenantDomainFinding -ReadError 'Forbidden').Status | Should -Be 'FAIL'
        $w = Get-TenantDomainFinding -Organization $org
        $w.Status | Should -Be 'WARN'
        $w.Detail | Should -Match 'not compared.*-OnMicrosoftDomain'
    }

    It 'SKUs: <Case>' -ForEach @(
        @{ Case = 'E5 + Governance enabled and assigned -> all PASS'; Skus = 'good'; PreTrial = $false; Expect = @{ 'Microsoft 365 E5' = 'PASS'; 'Microsoft Entra ID Governance' = 'PASS'; 'Entra ID P2 service plan' = 'PASS' } }
        @{ Case = 'no trial yet -> FAIL'; Skus = 'none'; PreTrial = $false; Expect = @{ 'Microsoft 365 E5' = 'FAIL'; 'Microsoft Entra ID Governance' = 'FAIL'; 'Entra ID P2 service plan' = 'FAIL' } }
        @{ Case = 'no trial yet, -PreTrial -> WARN'; Skus = 'none'; PreTrial = $true; Expect = @{ 'Microsoft 365 E5' = 'WARN'; 'Microsoft Entra ID Governance' = 'WARN'; 'Entra ID P2 service plan' = 'WARN' } }
        @{ Case = 'E5 in its grace period -> WARN'; Skus = 'warning'; PreTrial = $false; Expect = @{ 'Microsoft 365 E5' = 'WARN' } }
        @{ Case = 'E5 suspended -> FAIL, and P2 gone with it'; Skus = 'suspended'; PreTrial = $false; Expect = @{ 'Microsoft 365 E5' = 'FAIL'; 'Entra ID P2 service plan' = 'FAIL' } }
        @{ Case = 'nobody licensed yet -> WARN'; Skus = 'unassigned'; PreTrial = $false; Expect = @{ 'Microsoft 365 E5' = 'WARN' } }
        @{ Case = 'E5 (no Teams) and no Teams plan -> Teams WARN'; Skus = 'noteams'; PreTrial = $false; Expect = @{ 'Microsoft 365 E5' = 'PASS'; 'Microsoft Teams' = 'WARN' } }
    ) {
        $gov = New-PfSku 'Microsoft_Entra_ID_Governance' -Plans 'Entra_Identity_Governance'
        $set = switch ($Skus) {
            'good' { @((New-PfSku 'SPE_E5' -Plans 'AAD_PREMIUM_P2', 'TEAMS1'), $gov) }
            'none' { @((New-PfSku 'FLOW_FREE')) }
            'warning' { @((New-PfSku 'SPE_E5' -Status 'Warning' -Plans 'AAD_PREMIUM_P2'), $gov) }
            'suspended' { @((New-PfSku 'SPE_E5' -Status 'Suspended' -Plans 'AAD_PREMIUM_P2'), $gov) }
            'unassigned' { @((New-PfSku 'SPE_E5' -Used 0 -Plans 'AAD_PREMIUM_P2'), $gov) }
            'noteams' { @((New-PfSku 'Microsoft_365_E5_(no_Teams)' -Plans 'AAD_PREMIUM_P2'), $gov) }
        }
        $f = @(Get-SkuFinding -Skus $set -E5PartNumbers @('SPE_E5', 'Microsoft_365_E5_(no_Teams)') -GovernancePartNumbers @('Microsoft_Entra_ID_Governance') -PreTrial:$PreTrial)
        foreach ($k in $Expect.Keys) { ($f | Where-Object Check -eq $k).Status | Should -Be $Expect[$k] -Because $k }
        if ($Skus -eq 'none') { ($f | Where-Object Check -eq 'Microsoft 365 E5').Detail | Should -Match 'the tenant has: FLOW_FREE.*(Expected before Day 0|-E5SkuPartNumbers)' }
        if ($Skus -eq 'good') { @($f | Where-Object Check -eq 'Microsoft Teams').Count | Should -Be 0 }
    }

    It 'an unreadable subscribedSkus is a FAIL, not "no licences"' {
        $f = @(Get-SkuFinding -E5PartNumbers 'SPE_E5' -GovernancePartNumbers 'G' -ReadError 'Forbidden')
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'FAIL'
        $f[0].Detail | Should -Match 'Organization\.Read\.All'
    }

    It 'break-glass: <Case> -> <Status>' -ForEach @(
        @{ Case = 'two healthy, licensed'; Users = 'two'; Premium = $false; PreTrial = $false; Status = 'PASS'; Match = '2 found \(bg-admin-01, bg-admin-02\): enabled, on \*\.onmicrosoft\.com, licensed' }
        @{ Case = 'none before enable_premium'; Users = 'none'; Premium = $false; PreTrial = $false; Status = 'WARN'; Match = 'Day 1, PR #1' }
        @{ Case = 'none although enable_premium is on'; Users = 'none'; Premium = $true; PreTrial = $false; Status = 'FAIL'; Match = 'enable_premium is on' }
        @{ Case = 'only one'; Users = 'one'; Premium = $true; PreTrial = $false; Status = 'FAIL'; Match = 'keep at least two' }
        @{ Case = 'one disabled'; Users = 'disabled'; Premium = $true; PreTrial = $false; Status = 'FAIL'; Match = 'bg-admin-02: disabled' }
        @{ Case = 'one on a custom domain'; Users = 'custom'; Premium = $true; PreTrial = $false; Status = 'FAIL'; Match = 'not on the \*\.onmicrosoft\.com domain' }
        @{ Case = 'unlicensed'; Users = 'unlicensed'; Premium = $true; PreTrial = $false; Status = 'WARN'; Match = 'no licence assigned: bg-admin-01, bg-admin-02' }
        @{ Case = 'unlicensed, -PreTrial'; Users = 'unlicensed'; Premium = $true; PreTrial = $true; Status = 'PASS'; Match = 'enabled, on \*\.onmicrosoft\.com\. CA' }
    ) {
        $u = switch ($Users) {
            'two' { @((New-PfUser 'bg-admin-01'), (New-PfUser 'bg-admin-02')) }
            'none' { @() }
            'one' { @((New-PfUser 'bg-admin-01')) }
            'disabled' { @((New-PfUser 'bg-admin-01'), (New-PfUser 'bg-admin-02' -Enabled $false)) }
            'custom' { @((New-PfUser 'bg-admin-01'), (New-PfUser 'bg-admin-02' -Domain 'contosohealth.example')) }
            'unlicensed' { @((New-PfUser 'bg-admin-01' -Licences 0), (New-PfUser 'bg-admin-02' -Licences 0)) }
        }
        $f = @(Get-BreakGlassFinding -Users $u -PremiumOn $Premium -PreTrial:$PreTrial)
        $worst = if ($f.Status -contains 'FAIL') { 'FAIL' } elseif ($f.Status -contains 'WARN') { 'WARN' } else { 'PASS' }
        $worst | Should -Be $Status
        ($f.Detail -join "`n") | Should -Match $Match
        ($f.Detail -join "`n") | Should -Not -Match '@'
    }

    It 'an unreadable user list is a FAIL, not "no break-glass"' {
        (@(Get-BreakGlassFinding -ReadError 'Forbidden'))[0].Status | Should -Be 'FAIL'
    }
}

Describe 'exit code and redaction' {
    It 'exit code: no rows / PASS only -> 0, any WARN -> 1, any FAIL -> 2' {
        Get-PreflightExitCode -Results @() | Should -Be 0
        Get-PreflightExitCode -Results @([pscustomobject]@{ Status = 'PASS' }) | Should -Be 0
        Get-PreflightExitCode -Results @([pscustomobject]@{ Status = 'PASS' }, [pscustomobject]@{ Status = 'WARN' }) | Should -Be 1
        Get-PreflightExitCode -Results @([pscustomobject]@{ Status = 'WARN' }, [pscustomobject]@{ Status = 'FAIL' }) | Should -Be 2
    }

    It 'every finding redacts GUIDs, JWTs and URL credentials' {
        $f = ConvertTo-PreflightFinding 'x' 'FAIL' "tenant $script:TenantGuid token $script:FakeJwt via $(Get-PfRemoteUrl 'example.com/x')"
        $f.Detail | Should -Be 'tenant <id> token <token> via https://example.com/x'
    }

    It 'every finding redacts UPNs, bearer / GitHub tokens and home-folder paths (az / Graph error texts carry them)' {
        $azErr = "ERROR: (AuthorizationFailed) The client '$script:FakeUpn' with object id '$script:TenantGuid' does not have authorization over scope '/subscriptions/$script:SubGuid'"
        (ConvertTo-PreflightFinding 'x' 'WARN' $azErr).Detail | Should -Be "ERROR: (AuthorizationFailed) The client '<upn>' with object id '<id>' does not have authorization over scope '/subscriptions/<id>'"
        (ConvertTo-PreflightFinding 'x' 'WARN' "Authorization: Bearer $('A' * 24) and $script:FakeGhToken").Detail | Should -Be 'Authorization: Bearer <token> and <token>'
        (ConvertTo-PreflightFinding 'x' 'WARN' "Access to the path '$script:FakeHome/.azure/commands' is denied.").Detail | Should -Be "Access to the path '~/.azure/commands' is denied."
        (ConvertTo-PreflightFinding 'x' 'WARN' 'C:\Users\someone\.azure').Detail | Should -Be '~\.azure'
        # The operator hints that name admin@ (no domain) are left alone.
        (ConvertTo-PreflightFinding 'x' 'WARN' 'trial-day work runs as you (admin@ / your adm- account)').Detail | Should -Be 'trial-day work runs as you (admin@ / your adm- account)'
    }
}

Describe 'I/O adapters and the read-only contract' {
    It 'Get-PreflightAzLoginArgument reads the newest login log''s "command args" line; $null with no log; '''' without the line' {
        $prev = $env:AZURE_CONFIG_DIR
        try {
            $env:AZURE_CONFIG_DIR = Join-Path $TestDrive 'azcfg'
            $v = Get-PreflightAzLoginArgument
            $null -eq $v | Should -BeTrue -Because 'no commands folder at all'
            $cmd = Join-Path $env:AZURE_CONFIG_DIR 'commands'
            New-Item -ItemType Directory -Force -Path $cmd | Out-Null
            Set-Content -LiteralPath (Join-Path $cmd '2026-10-19.09-00-00.account_show.11.log') -Value 'command args: account show'
            $v = Get-PreflightAzLoginArgument
            $null -eq $v | Should -BeTrue -Because 'no login log'
            $old = Join-Path $cmd '2026-10-19.09-00-01.login.12.log'
            Set-Content -LiteralPath $old -Value "x`ncommand args: login --use-device-code --tenant {}"
            (Get-Item -LiteralPath $old).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-2)
            $new = Join-Path $cmd '2026-10-20.09-00-00.login.13.log'
            Set-Content -LiteralPath $new -Value "x`ncommand args: login --tenant {}`ny"
            Get-PreflightAzLoginArgument | Should -BeExactly 'login --tenant {}' -Because 'the newest login log wins'
            Set-Content -LiteralPath $new -Value 'no arguments line'
            $v = Get-PreflightAzLoginArgument
            ($v -is [string] -and $v -eq '') | Should -BeTrue -Because 'a login log without its arguments line is "", not $null'
        }
        finally { $env:AZURE_CONFIG_DIR = $prev }
    }

    It 'is read-only by construction: no Mg write or sign-in cmdlet, Graph only through one GET, no file or module writes' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Pf, [ref]$null, [ref]$null)
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
        $names = @($calls | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        @($names | Where-Object { $_ -match '^[A-Za-z]+-Mg' -and $_ -notin @('Get-MgContext', 'Invoke-MgGraphRequest') }) | Should -BeNullOrEmpty
        $graph = @($calls | Where-Object { $_.GetCommandName() -eq 'Invoke-MgGraphRequest' })
        $graph.Count | Should -Be 1
        $graph[0].Extent.Text | Should -Match '-Method GET\b'
        @($names | Where-Object { $_ -match '^(Set|Add|Clear|Out)-Content$|^Out-File$|^(New|Remove|Move|Copy|Rename|Set)-Item$|^Export-|^(Install|Update|Uninstall|Import)-Module$|^Start-Process$|^Invoke-(WebRequest|RestMethod|Expression)$' }) | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-Preflight end to end (mocked adapters)' {
    Context '-Offline' {
        It 'healthy machine: four sections, every check PASS, exit 0 - and no az or Graph call at all' {
            Set-PfMock -Root (New-PfRepo)
            $r = Invoke-Pf @{ Offline = $true }
            $r.Exit | Should -Be 0
            @($r.Results | Where-Object Status -ne 'PASS').Count | Should -Be 0
            @($r.Lines | Where-Object { $_ -match '^\s*\[\d/4\]' }).Count | Should -Be 4
            (Get-PfFinding $r 'az (Azure CLI)').Detail | Should -Match 'version not read offline'
            (Get-PfFinding $r 'Microsoft Graph modules').Detail | Should -Be '2/2 installed at 2.41.2'
            (Get-PfFinding $r 'terraform').Detail | Should -Match 'satisfies envs/bootstrap >= 1\.6\.0, envs/dev >= 1\.9\.0$'
            (Get-PfFinding $r 'gh').Detail | Should -Match '^2\.79\.0 '
            Should -Invoke Get-PreflightGraphContext -Times 0 -Exactly
            Should -Invoke Invoke-PreflightGraph -Times 0 -Exactly
            Should -Invoke Get-PreflightAzLoginArgument -Times 0 -Exactly
            Should -Invoke Invoke-PreflightNative -Times 0 -Exactly -ParameterFilter { $Name -eq 'az' }
        }

        It '<Case> -> exit <Exit>' -ForEach @(
            @{ Case = 'trufflehog missing (pre-push gate)'; Mock = @{ MissingTools = @('trufflehog') }; Repo = @{}; With = @{}; Exit = 2; Check = 'trufflehog' }
            @{ Case = 'terraform missing'; Mock = @{ MissingTools = @('terraform') }; Repo = @{}; With = @{}; Exit = 2; Check = 'terraform' }
            @{ Case = 'az missing'; Mock = @{ MissingTools = @('az') }; Repo = @{}; With = @{}; Exit = 2; Check = 'az (Azure CLI)' }
            @{ Case = 'terraform below required_version'; Mock = @{ Terraform = '1.8.0' }; Repo = @{}; With = @{}; Exit = 2; Check = 'terraform' }
            @{ Case = 'Windows PowerShell'; Mock = @{ PsVersion = '5.1.0' }; Repo = @{}; With = @{}; Exit = 2; Check = 'PowerShell' }
            @{ Case = 'a Graph module missing'; Mock = @{ Modules = @{ 'Microsoft.Graph.Authentication' = @('2.41.2'); 'Pester' = @('5.7.1'); 'PSScriptAnalyzer' = @('1.25.0') } }; Repo = @{}; With = @{}; Exit = 2; Check = 'Microsoft Graph modules' }
            @{ Case = 'a staging flag on'; Mock = @{}; Repo = @{ Tfvars = 'enable_sentinel = true' }; With = @{}; Exit = 2; Check = 'lab.tfvars staging flags' }
            @{ Case = 'lab.tfvars missing'; Mock = @{}; Repo = @{ NoTfvars = $true }; With = @{}; Exit = 2; Check = 'lab.tfvars' }
            @{ Case = 'shellcheck missing'; Mock = @{ MissingTools = @('shellcheck') }; Repo = @{}; With = @{}; Exit = 1; Check = 'shellcheck' }
            @{ Case = 'Pester missing'; Mock = @{ Modules = @{ 'Microsoft.Graph.Authentication' = @('2.41.2'); 'Microsoft.Graph.Users' = @('2.41.2'); 'PSScriptAnalyzer' = @('1.25.0') } }; Repo = @{}; With = @{}; Exit = 1; Check = 'Pester' }
            @{ Case = 'Docker daemon down'; Mock = @{ DaemonExit = 1 }; Repo = @{}; With = @{}; Exit = 1; Check = 'Docker + Colima (PAM stand-ins)' }
            @{ Case = 'uncommitted changes'; Mock = @{ GitStatus = "## main...origin/main`n M lab/terraform/envs/dev/lab.tfvars" }; Repo = @{}; With = @{}; Exit = 1; Check = 'git' }
            @{ Case = 'the build source checkout'; Mock = @{}; Repo = @{ BuildSource = $true }; With = @{}; Exit = 1; Check = 'git' }
            @{ Case = 'terraform newer than the CI pin'; Mock = @{ Terraform = '1.17.0' }; Repo = @{}; With = @{}; Exit = 1; Check = 'terraform' }
            @{ Case = 'gh missing'; Mock = @{ MissingTools = @('gh') }; Repo = @{}; With = @{}; Exit = 1; Check = 'gh' }
            @{ Case = 'a third envs/* root the CLI is too old for'; Mock = @{}; Repo = @{ Extra = @{ 'lab/terraform/envs/prod/versions.tf' = "terraform {`n  required_version = `">= 1.20.0`"`n}`n" } }; With = @{}; Exit = 2; Check = 'terraform' }
        ) {
            $repoArgs = @{} + $Repo
            if ($repoArgs.ContainsKey('Tfvars')) { $repoArgs['Tfvars'] = $script:GoodTfvars -replace 'enable_sentinel   = false', 'enable_sentinel = true' }
            $mockArgs = @{ Root = (New-PfRepo @repoArgs) } + $Mock
            Set-PfMock @mockArgs
            $r = Invoke-Pf (@{ Offline = $true } + $With)
            $r.Exit | Should -Be $Exit
            $want = if ($Exit -eq 2) { 'FAIL' } else { 'WARN' }
            @(Get-PfFinding $r $Check | Where-Object Status -eq $want).Count | Should -BeGreaterThan 0 -Because $Case
            Should -Invoke Invoke-PreflightGraph -Times 0 -Exactly
            Should -Invoke Invoke-PreflightNative -Times 0 -Exactly -ParameterFilter { $Name -eq 'az' }
        }

        It 'a flag flipped on purpose and named in -ExpectedOnFlags passes (exit 0)' {
            Set-PfMock -Root (New-PfRepo -Tfvars ($script:GoodTfvars -replace 'enable_premium    = false', 'enable_premium = true'))
            (Invoke-Pf @{ Offline = $true; ExpectedOnFlags = @('enable_premium') }).Exit | Should -Be 0
        }

        It 'never prints the credentials embedded in a git remote URL' {
            Set-PfMock -Root (New-PfRepo)
            $r = Invoke-Pf @{ Offline = $true }
            ($r.Lines -join "`n") | Should -Not -Match 'ghp_|x-access-token'
            (Get-PfFinding $r 'git').Detail | Should -Match 'origin -> github\.com/owner/contoso-health-identity-lab\.git'
        }
    }

    Context 'online (default)' {
        It 'healthy tenant: six sections, every check PASS, exit 0; the domain is printed, no id, UPN or secret is' {
            Set-PfMock -Root (New-PfRepo)
            $r = Invoke-Pf @{ OnMicrosoftDomain = $script:Domain }
            $r.Exit | Should -Be 0
            @($r.Results | Where-Object Status -ne 'PASS') | ForEach-Object { "$($_.Check): $($_.Detail)" } | Should -BeNullOrEmpty
            @($r.Lines | Where-Object { $_ -match '^\s*\[\d/6\]' }).Count | Should -Be 6
            $all = $r.Lines -join "`n"
            $all | Should -Match ([regex]::Escape("Graph tenant - $script:Domain (Contoso Health Lab)"))
            $all | Should -Match ([regex]::Escape("Azure CLI sign-in - signed in to $script:Domain"))
            $all | Should -Not -Match "$script:TenantGuid|$script:SubGuid|$script:OtherGuid|admin@|ghp_"
            (Get-PfFinding $r 'Budget').Detail | Should -Match "'lab-budget' \`$50/Monthly"
            (Get-PfFinding $r 'Delegated Graph scopes').Detail | Should -Match '^all 5 granted \(declared by 3 post-apply / gate script\(s\) \+ this preflight\); the 2 Agent ID preview scope'
            Should -Invoke Invoke-PreflightGraph -Times 1 -Exactly -ParameterFilter { [uri]::UnescapeDataString($Uri) -match "/users\?\`$filter=startswith\(mailNickname,'bg-admin-'\)" }
            Should -Invoke Invoke-PreflightNative -Times 0 -Exactly -ParameterFilter { $Name -eq 'az' -and ($Arguments -join ' ') -notmatch '^(version|account show|consumption budget list) ' }
        }

        It 'no Graph connection: FAIL with the connect line, and the tenant / SKU / break-glass checks FAIL as "not checked" (exit 2)' {
            Set-PfMock -Root (New-PfRepo) -NoGraph
            $r = Invoke-Pf
            $r.Exit | Should -Be 2
            (Get-PfFinding $r 'Microsoft Graph connection').Detail | Should -Match "Connect-MgGraph -Scopes 'Group\.Read\.All','Organization\.Read\.All','Policy\.Read\.All','Policy\.ReadWrite\.ConditionalAccess','User\.Read\.All' -NoWelcome"
            foreach ($c in 'Graph tenant', 'Licensed SKUs', 'Break-glass accounts (bg-admin-*)') { (Get-PfFinding $r $c).Detail | Should -Be 'not checked: no Microsoft Graph connection' }
            Should -Invoke Invoke-PreflightGraph -Times 0 -Exactly
        }

        It 'az signed out: FAIL; the budget is not read (WARN, with the reminder); Graph is still checked (exit 2)' {
            Set-PfMock -Root (New-PfRepo) -AzSignedOut
            $r = Invoke-Pf
            $r.Exit | Should -Be 2
            (Get-PfFinding $r 'Azure CLI sign-in').Status | Should -Be 'FAIL'
            (Get-PfFinding $r 'Budget').Detail | Should -Match 'not checked \(az is not signed in\)'
            @(Get-PfFinding $r 'Azure CLI login method (CA010)').Count | Should -Be 0
            Should -Invoke Invoke-PreflightNative -Times 0 -Exactly -ParameterFilter { $Name -eq 'az' -and $Arguments[0] -eq 'consumption' }
            @(Get-PfFinding $r 'Licensed SKUs').Count | Should -Be 0
            (Get-PfFinding $r 'Microsoft 365 E5').Status | Should -Be 'PASS'
        }

        It '<Case> -> exit <Exit>' -ForEach @(
            @{ Case = 'az signed in with a device code'; Mock = @{ LoginArgs = 'login --use-device-code' }; With = @{}; Exit = 1; Check = 'Azure CLI login method (CA010)' }
            @{ Case = 'Graph signed in with a device code'; Mock = @{ GraphAuthFlow = 'DeviceCode' }; With = @{}; Exit = 1; Check = 'Microsoft Graph connection' }
            @{ Case = 'a post-apply scope missing'; Mock = @{ Scopes = @('Group.Read.All', 'Policy.Read.All', 'User.Read.All', 'Organization.Read.All') }; With = @{}; Exit = 1; Check = 'Delegated Graph scopes' }
            @{ Case = 'no Azure budget'; Mock = @{ BudgetJson = '[]' }; With = @{}; Exit = 1; Check = 'Budget' }
            @{ Case = 'no E5 / Governance yet'; Mock = @{ Skus = @() }; With = @{}; Exit = 2; Check = 'Microsoft 365 E5' }
            @{ Case = 'no E5 / Governance yet, -PreTrial'; Mock = @{ Skus = @() }; With = @{ PreTrial = $true }; Exit = 1; Check = 'Microsoft 365 E5' }
            @{ Case = 'az and Graph on different tenants'; Mock = @{ GraphTenant = '33333333-3333-3333-3333-333333333333' }; With = @{}; Exit = 2; Check = 'Tenant match (az / Graph)' }
            @{ Case = 'the wrong tenant for -OnMicrosoftDomain'; Mock = @{}; With = @{ OnMicrosoftDomain = 'fabrikam.onmicrosoft.com' }; Exit = 2; Check = 'Graph tenant' }
            @{ Case = 'subscribedSkus unreadable'; Mock = @{ SkuReadFails = $true }; With = @{}; Exit = 2; Check = 'Licensed SKUs' }
            @{ Case = 'only one break-glass account'; Mock = @{ BreakGlass = @(@{ mailNickname = 'bg-admin-01'; userPrincipalName = 'bg-admin-01@contosolab.onmicrosoft.com'; accountEnabled = $true; assignedLicenses = @(@{ skuId = 'x' }) }) }; With = @{}; Exit = 2; Check = 'Break-glass accounts (bg-admin-*)' }
            @{ Case = 'no break-glass yet, enable_premium off'; Mock = @{ BreakGlass = @() }; With = @{}; Exit = 1; Check = 'Break-glass accounts (bg-admin-*)' }
            @{ Case = 'healthy, but no -OnMicrosoftDomain (tenant not compared)'; Mock = @{}; With = @{ OnMicrosoftDomain = '' }; Exit = 1; Check = 'Graph tenant' }
        ) {
            $mockArgs = @{ Root = (New-PfRepo) } + $Mock
            Set-PfMock @mockArgs
            $r = Invoke-Pf $With
            $r.Exit | Should -Be $Exit
            $want = if ($Exit -eq 2) { 'FAIL' } else { 'WARN' }
            @(Get-PfFinding $r $Check | Where-Object Status -eq $want).Count | Should -BeGreaterThan 0 -Because $Case
            ($r.Lines -join "`n") | Should -Not -Match "$script:TenantGuid|$script:OtherGuid"
        }

        It 'enable_premium on (acknowledged) but no bg-admin-* account: FAIL, lockout risk (exit 2)' {
            Set-PfMock -Root (New-PfRepo -Tfvars ($script:GoodTfvars -replace 'enable_premium    = false', 'enable_premium = true')) -BreakGlass @()
            $r = Invoke-Pf @{ ExpectedOnFlags = @('enable_premium') }
            $r.Exit | Should -Be 2
            (Get-PfFinding $r 'Break-glass accounts (bg-admin-*)').Detail | Should -Match 'enable_premium is on'
        }

        It 'budget unreadable: the WARN quotes az''s ERROR line (not its preview notice), with the UPN and ids redacted' {
            $err = "Command group 'consumption' is in preview and under development. Reference and support levels: https://aka.ms/CLI_refstatus`nERROR: (AuthorizationFailed) The client '$script:FakeUpn' with object id '$script:OtherGuid' does not have authorization to perform action 'Microsoft.Consumption/budgets/read' over scope '/subscriptions/$script:SubGuid'"
            Set-PfMock -Root (New-PfRepo) -BudgetError $err
            $r = Invoke-Pf @{ OnMicrosoftDomain = $script:Domain }
            $r.Exit | Should -Be 1
            $b = Get-PfFinding $r 'Budget'
            $b.Status | Should -Be 'WARN'
            $b.Detail | Should -Match "could not read budgets \(az consumption budget list\): ERROR: \(AuthorizationFailed\) The client '<upn>' with object id '<id>'.*'/subscriptions/<id>'"
            ($r.Lines -join "`n") | Should -Not -Match "admin@|$script:OtherGuid|$script:SubGuid|in preview"
        }

        It 'az command log unreadable: WARN for the login method, the rest still runs' {
            Set-PfMock -Root (New-PfRepo)
            Mock Get-PreflightAzLoginArgument { throw "Access to the path '$script:FakeHome/.azure/commands' is denied." }
            $r = Invoke-Pf @{ OnMicrosoftDomain = $script:Domain }
            $r.Exit | Should -Be 1
            $m = Get-PfFinding $r 'Azure CLI login method (CA010)'
            $m.Status | Should -Be 'WARN'
            $m.Detail | Should -Match "could not read az's command log \(Access to the path '~/\.azure/commands' is denied\.\)"
            (Get-PfFinding $r 'Budget').Status | Should -Be 'PASS'
        }

        It 'a post-apply script that does not parse: WARN that the scope list may be incomplete' {
            Set-PfMock -Root (New-PfRepo -Extra @{ 'lab/scripts/powershell/post-apply/Set-Broken.ps1' = "`$requiredScopes = @('Directory.Read.All'`nfunction {" })
            $r = Invoke-Pf @{ OnMicrosoftDomain = $script:Domain }
            $r.Exit | Should -Be 1
            @(Get-PfFinding $r 'Delegated Graph scopes' | Where-Object { $_.Status -eq 'WARN' -and $_.Detail -match '^Set-Broken\.ps1 did not parse' }).Count | Should -Be 1
        }

        It 'reads the az login log before the first az command (each az command logs, and az prunes old logs)' {
            Set-PfMock -Root (New-PfRepo)
            $global:PfTest.Order = [System.Collections.Generic.List[string]]::new()
            Mock Get-PreflightAzLoginArgument { $global:PfTest.Order.Add('log'); 'login --tenant {}' }
            Mock Invoke-PreflightNative -ParameterFilter { $Name -eq 'az' } {
                $global:PfTest.Order.Add("az $($Arguments[0])")
                $out = switch ($Arguments[0]) { 'version' { '{"azure-cli": "2.91.0"}' } 'account' { $global:PfTest.AzAccountJson } default { '[]' } }
                [pscustomobject]@{ ExitCode = 0; Output = $out; ErrorText = '' }
            }
            $null = Invoke-Pf
            @($global:PfTest.Order) | Should -Be @('log', 'az version', 'az account', 'az consumption')
            Should -Invoke Get-PreflightAzLoginArgument -Times 1 -Exactly
        }
    }
}

Describe '00-Preflight.ps1 as a script (exit codes)' {
    It '<Case> -> $LASTEXITCODE <Exit>' -ForEach @(
        @{ Case = 'healthy, -Offline'; Mock = @{}; Repo = @{}; Exit = 0 }
        @{ Case = 'uncommitted changes, -Offline'; Mock = @{ GitStatus = "## main...origin/main`n M a.ps1" }; Repo = @{}; Exit = 1 }
        @{ Case = 'a staging flag on, -Offline'; Mock = @{}; Repo = @{ Flag = $true }; Exit = 2 }
    ) {
        $repoArgs = @{}
        if ($Repo.ContainsKey('Flag')) { $repoArgs['Tfvars'] = $script:GoodTfvars -replace 'enable_sentinel   = false', 'enable_sentinel = true' }
        $root = New-PfRepo @repoArgs
        $mockArgs = @{ Root = $root } + $Mock
        Set-PfMock @mockArgs
        $global:LASTEXITCODE = 0
        & $script:Pf -Offline -RepoRoot $root
        $LASTEXITCODE | Should -Be $Exit
        ($global:PfTest.Lines -join "`n") | Should -Match "exit $Exit\)"
        Should -Invoke Invoke-PreflightGraph -Times 0 -Exactly
    }

    It 'an unexpected error stops it with exit 2 (BLOCKED), never the "warnings only" 1, and the message is redacted' {
        Set-PfMock -Root (New-PfRepo)
        Mock Get-PreflightPsVersion { throw ('boom reading /Users/' + 'someone/x for admin' + '@' + 'contosolab.onmicrosoft.com') }
        $global:LASTEXITCODE = 0
        & $script:Pf -Offline -RepoRoot $global:PfTest.Root
        $LASTEXITCODE | Should -Be 2
        $out = $global:PfTest.Lines -join "`n"
        $out | Should -Match '\[FAIL\] Preflight - stopped on an unexpected error at line \d+: boom reading ~/x for <upn>'
        $out | Should -Match 'did not finish - BLOCKED.*\(exit 2\)'
    }

    It 'rejects a malformed -OnMicrosoftDomain before doing anything' {
        Set-PfMock -Root (New-PfRepo)
        { & $script:Pf -OnMicrosoftDomain 'contoso.com' -RepoRoot $global:PfTest.Root } | Should -Throw
        Should -Invoke Invoke-PreflightNative -Times 0 -Exactly
    }
}
