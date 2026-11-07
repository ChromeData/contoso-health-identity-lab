<#
.SYNOPSIS
    Runs the free PingCastle health check on DC01 and prints only the scores.

.DESCRIPTION
    Runs ON DC01 as SYSTEM through lab/scripts/dc/run-on-dc.py (Windows
    PowerShell 5.1). It is read-only: PingCastle reads the directory over
    LDAP and writes its report to a local folder. It changes nothing in AD.

    WHY THESE CHECKS
      The zip is pinned by SHA-256 to one release (4.0.0.31, 2026-10-13),
      so a changed download is refused. The exe must also carry a valid
      Authenticode signature, or the script stops before running it.

    LICENCE
      PingCastle's open-source edition (Non-Profit OSL 3.0) allows internal
      use, also in for-profit companies. Selling PingCastle-based audits to
      others needs the commercial licence. This lab audits its own domain.

    OUTPUT
      Run-command output is capped at about 4 KB, so only the global score,
      the four category scores and the rule IDs with their points are
      printed. The full XML and HTML reports stay on DC01.

.PARAMETER Label
    'before' or 'after': names the report folder so both runs are kept.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('before', 'after')] [string]$Label
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Version = '4.0.0.31'
$Sha256 = 'd54ef62058bb45384a09f1b59c0669680bf492df8414f144688edf681370c0eb'
$Url = "https://github.com/netwrix/pingcastle/releases/download/$Version/PingCastle_$Version.zip"
$Root = 'C:\LabTools\pingcastle'
$Zip = Join-Path $Root "PingCastle_$Version.zip"
$Bin = Join-Path $Root $Version
$Out = Join-Path $Root "report-$Label"

foreach ($p in $Root, $Out) { if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p | Out-Null } }

if (-not (Test-Path -LiteralPath $Zip)) { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Zip }
$got = (Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $Sha256) { Remove-Item -LiteralPath $Zip -Force; throw "PingCastle zip hash mismatch (got $got): refused" }

if (-not (Test-Path -LiteralPath $Bin)) { Expand-Archive -LiteralPath $Zip -DestinationPath $Bin }
$exe = Get-ChildItem -LiteralPath $Bin -Recurse -Filter 'PingCastle.exe' | Select-Object -First 1
if (-not $exe) { throw 'PingCastle.exe not found in the pinned zip' }
$sig = Get-AuthenticodeSignature -LiteralPath $exe.FullName
if ($sig.Status -ne 'Valid') { throw "PingCastle.exe signature is '$($sig.Status)': refused" }
Write-Output ("PingCastle {0}, signer: {1}" -f $Version, $sig.SignerCertificate.Subject)

Push-Location $Out
try {
    & $exe.FullName --healthcheck --server localhost --level Full --no-enum-limit | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "PingCastle exited $LASTEXITCODE" }
}
finally { Pop-Location }

$xmlFile = Get-ChildItem -LiteralPath $Out -Filter 'ad_hc_*.xml' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $xmlFile) { throw 'No PingCastle XML report was written' }
[xml]$x = Get-Content -LiteralPath $xmlFile.FullName -Raw
$h = $x.HealthcheckData

Write-Output ("SCORES {0}: global={1} stale={2} privileged={3} trusts={4} anomalies={5}" -f $Label,
    $h.GlobalScore, $h.StaleObjectsScore, $h.PrivilegiedGroupScore, $h.TrustScore, $h.AnomalyScore)
foreach ($r in @($h.RiskRules.HealthcheckRiskRule)) {
    Write-Output ("RULE {0} {1} {2}" -f $r.Category, $r.RiskId, $r.Points)
}
Write-Output ("REPORT {0}" -f $xmlFile.FullName)
