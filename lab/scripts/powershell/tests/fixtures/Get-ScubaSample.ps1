<#
.SYNOPSIS
    Fetches CISA's published ScubaGear v1.8.0 sample report - the fixture for
    tests/Invoke-BaselineAssessment.Tests.ps1 - and verifies every file
    against a pinned SHA-256 before the tests may use it.

.DESCRIPTION
    Why fetched, not committed: ~2 MB of third-party output does not belong in
    the public repo, and the tests must exercise the REAL ScubaGear result
    shape, not a hand-written imitation.

    Why pinned hashes: the source is a git TAG, and tags can be moved. A file
    whose hash differs is deleted and the script exits 1, so a changed or
    tampered sample can never quietly change what the tests assert.

    Destination: lab/scripts/powershell/out/fixtures/scuba-sample (gitignored).
    Files are DATA - parsed as JSON / CSV by the tests, never executed.

.PARAMETER Destination
    Folder to write to. Default: ../../out/fixtures/scuba-sample.

.EXAMPLE
    pwsh lab/scripts/powershell/tests/fixtures/Get-ScubaSample.ps1
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter()]
    [string]$Destination = (Join-Path $PSScriptRoot '..' '..' 'out' 'fixtures' 'scuba-sample')
)

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

$base = 'https://raw.githubusercontent.com/cisagov/ScubaGear/v1.8.0/PowerShell/ScubaGear/Sample-Reports'
# local name => (upstream name, SHA-256 of the v1.8.0 file)
$files = [ordered]@{
    'results.json'     = @('ScubaResults_fa5589b7-d528-4f80.json', '8746a9ea9142d04ed80f957bf6cdc57e950da6fa9def1b1f16b79886311dee64')
    'ScubaResults.csv' = @('ScubaResults.csv', '5101698a0c066007abce0a3883f6b51e1eac2b2078c33e8d03837ccc1e8b14d8')
    'ActionPlan.csv'   = @('ActionPlan.csv', '9d35a71e5180b977961911ac2a39f218d595427f9ad33f51cbd3842cf49ea7da')
}

if (-not (Test-Path -LiteralPath $Destination)) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
$bad = 0
foreach ($name in $files.Keys) {
    $target = Join-Path $Destination $name
    $upstream, $expected = $files[$name]
    if (Test-Path -LiteralPath $target) {
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -eq $expected) { Write-Console "  [=] $name (verified)"; continue }
        Remove-Item -LiteralPath $target -Force
    }
    Invoke-WebRequest -Uri "$base/$upstream" -OutFile $target -MaximumRetryCount 3 -RetryIntervalSec 2
    $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        Remove-Item -LiteralPath $target -Force
        Write-Warning "  [!] $name hash mismatch (got $actual, pinned $expected) - deleted."
        $bad++
        continue
    }
    Write-Console "  [+] $name (sha256 $expected)"
}
if ($bad) { exit 1 }
Write-Console "ScubaGear v1.8.0 sample ready in $Destination"
