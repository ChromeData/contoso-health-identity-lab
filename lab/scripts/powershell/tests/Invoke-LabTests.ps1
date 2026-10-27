<#
.SYNOPSIS
    Runs the lab's PowerShell checks offline: PSScriptAnalyzer (errors fail)
    and the Pester 5 suite in this folder. No tenant, no network.

.DESCRIPTION
    What the suite covers (every Graph / az / Log Analytics call is mocked):
      02-Joiner, 03-Mover, 04-Leaver   lifecycle decisions, idempotency, -WhatIf,
                                       "a failed read is never 'nothing there'"
      06-NHI-Inventory                 -Offline contract + online path on a mocked tenant
      07-Passwordless-Rollout          readiness maths, TAP guard rails, CA008 gate
      08-Measure-KPIs                  KPI maths, 06 contract, end-to-end snapshot
                                       (public-safe, hashed, failures never 0)
      Invoke-BreakGlassDrill           Pass/Partial/Fail, public-record guard
      Export-IdentityConfig            normalisation (deterministic, volatile fields
                                       dropped, ids hashed with -Public), the -Offline
                                       fixture end to end, the online path on a mocked
                                       Graph (a failed section is failed, never empty)
      Compare-IdentityConfig           deep diff + severity table, lab.tfvars intent,
                                       break-glass invariants, exceptions with expiry
                                       and term limits, exit codes, public-safe Markdown
      Set-AuthenticationMethodsPolicy  desired state against a simulated policy
      NhiGovernance                    06 / Find-ShadowAdmins offline mocks, app
                                       management + consent policy merges, Agent ID
                                       guards, leaver NHI hand-off
      PostApply                        New-AccessReviewDefinitions, New-B2BConnected-
                                       Organization, Invoke-PostApply order + the
                                       real scripts' parameter contracts
      New-KpiOnePager                  value / direction rendering, unmeasured never 0,
                                       08 comparison parity, end-to-end on files
      Invoke-BaselineAssessment        ScubaGear / Zero Trust import, KPIs, hashing,
                                       public-safe summary (needs the CISA sample:
                                       tests/fixtures/Get-ScubaSample.ps1 - its
                                       blocks are SKIPPED, not passed, without it);
                                       the MS.AAD map against the CA / flag / KQL code
      Reset-DemoState (lab/scripts/demo) -WhatIf writes nothing, only the two HR
                                       rows change, birthright left to HR attributes
      ScriptAnalyzerScope              analyzer suppressions are per function,
                                       justified, never per file
    Passing proves the logic does what the comments say. It does not prove the
    Graph API accepts these calls: that is a tenant-time check (the scripts'
    "verify:" notes list what to confirm).

.PARAMETER CI
    Write lab/scripts/powershell/out/testResults.xml (NUnit, gitignored
    folder) for a pipeline to publish. The exit code is non-zero on any
    failure with or without -CI.

.EXAMPLE
    pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1
.EXAMPLE
    pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1 -CI
#>
#Requires -Version 7.0
[CmdletBinding()]
param([switch]$CI)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Pester 5 syntax throughout; Pester 6 runs it as well (checked 2026-10-20).
# A Pester already imported in this session wins (two Pester versions cannot
# share a session); otherwise the newest installed 5.5+ is loaded.
$loaded = Get-Module Pester
if ($loaded -and $loaded.Version -ge [version]'5.5.0') { $pester = $loaded }
else {
    $pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]'5.5.0' } | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $pester) { throw 'Pester 5.5+ is required: Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck' }
    Import-Module $pester -Force
}
Write-Console "Pester $($pester.Version)" -ForegroundColor DarkGray
foreach ($m in 'PSScriptAnalyzer', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.Governance') {
    if (-not (Get-Module -ListAvailable $m)) { throw "Module '$m' is required (Install-Module $m -Scope CurrentUser). The Graph modules are only loaded so mocks copy the real cmdlet signatures." }
}

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

# 1. Static analysis. Errors fail; every warning is printed. Write-Host in
#    operator scripts is suppressed per FUNCTION (Write-Console, or the
#    function's own param block, with a justification) - never per file - so
#    a new unscoped Write-Host shows up here (tests/ScriptAnalyzerScope.Tests.ps1).
Write-Console "PSScriptAnalyzer: $root" -ForegroundColor Cyan
# Test files share mock state through $global: and define small helpers
# (New-*, plural nouns) on purpose, so those three rules are skipped there only.
$testOnlyExclusions = @('PSAvoidGlobalVars', 'PSUseShouldProcessForStateChangingFunctions', 'PSUseSingularNouns')
$findings = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' | ForEach-Object {
        if ($_.FullName.StartsWith($PSScriptRoot)) { Invoke-ScriptAnalyzer -Path $_.FullName -ExcludeRule $testOnlyExclusions }
        else { Invoke-ScriptAnalyzer -Path $_.FullName }
    })
$errors = @($findings | Where-Object Severity -eq 'Error')
$findings | Where-Object { $_.Severity -ne 'Information' } |
    Format-Table -AutoSize ScriptName, Line, Severity, RuleName | Out-Host
Write-Console ("PSScriptAnalyzer: {0} error(s), {1} warning(s)" -f $errors.Count, @($findings | Where-Object Severity -eq 'Warning').Count) -ForegroundColor $(if ($errors) { 'Red' } else { 'Green' })

# 2. Pester.
$cfg = New-PesterConfiguration
$cfg.Run.Path = $PSScriptRoot
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = 'Normal'
if ($CI) {
    $cfg.Run.Exit = $false
    $cfg.TestResult.Enabled = $true
    $cfg.TestResult.OutputFormat = 'NUnitXml'
    $outDir = Join-Path $root 'out'   # gitignored (lab/scripts/powershell/out/)
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
    $cfg.TestResult.OutputPath = Join-Path $outDir 'testResults.xml'
}
$result = Invoke-Pester -Configuration $cfg

$failed = $result.FailedCount + $errors.Count
if ($failed -or $result.Result -ne 'Passed') {
    Write-Console "FAILED: $($result.FailedCount) test(s), $($errors.Count) analyzer error(s)." -ForegroundColor Red
    exit 1
}
Write-Console "All $($result.PassedCount) tests passed; 0 analyzer errors." -ForegroundColor Green
exit 0
