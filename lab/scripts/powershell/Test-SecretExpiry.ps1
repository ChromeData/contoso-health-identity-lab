<#
.SYNOPSIS
    Monthly expiry check of the long-lived non-Entra secrets register
    (lab/iga/nhi-secrets-register.json). No tenant, no secret value: it reads
    the register file only.

.DESCRIPTION
    WHY (hostile review 2026-11-06, finding H1, "list every long-lived secret,
    who owns it and when it expires"): the register held owners and dates,
    but nothing looked at the dates between NHI inventory runs. A secret can
    expire quietly. The AWS SCIM token is the clearest case: when it expires,
    AWS provisioning stops, and joiners and leavers stop reaching AWS.

    It uses the SAME rules as 06-NHI-Inventory.ps1 (the function
    Test-SecretsRegister is read from that script, so there is one copy of
    the logic) with a wider warning window:

      * The workflow .github/workflows/secret-expiry.yml runs it on the 1st of
        every month. A 60-day window on a monthly run means every secret gets
        at least about 30 days' warning before its expiry date.
      * It FAILS (exit 1) on: an expired entry (SECRET-EXPIRED), one expiring
        inside the window (SECRET-EXPIRING), one with no owner
        (SECRET-NO-OWNER), and a PRESENT secret with no expiry date
        (SECRET-NO-EXPIRY). A failed scheduled run is the alert: GitHub
        notifies the repository's maintainers.
      * A planned secret with no date (not created yet) is listed, not failed.

    Output: a Markdown table (name, owner role, expires, days left, finding)
    to the console and, in GitHub Actions, to the step summary. It prints
    store LOCATIONS and names only; the register never holds a value.

.PARAMETER RegisterPath
    Default lab/iga/nhi-secrets-register.json.

.PARAMETER WarnDays
    Warning window in days. Default 60 (see above). The NHI inventory uses 30.

.PARAMETER Now
    For tests. Default: today (UTC).

.EXAMPLE
    pwsh lab/scripts/powershell/Test-SecretExpiry.ps1
#>
[CmdletBinding()]
param(
    [string]$RegisterPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'nhi-secrets-register.json'),
    [ValidateRange(1, 365)]
    [int]$WarnDays = 60,
    [datetime]$Now = [datetime]::UtcNow.Date
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One copy of the rules: load Test-SecretsRegister from the NHI inventory.
$nhi = Join-Path $PSScriptRoot '06-NHI-Inventory.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($nhi, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Parse errors in ${nhi}: $($errors[0].Message)" }
$def = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-SecretsRegister' }, $false))
if ($def.Count -ne 1) { throw "Test-SecretsRegister not found in $nhi" }
. ([scriptblock]::Create($def[0].Extent.Text))

# Unreadable or invalid = fail: "couldn't read" is never "nothing expires".
if (-not (Test-Path -LiteralPath $RegisterPath -PathType Leaf)) { throw "Register not found: $RegisterPath" }
$register = Get-Content -LiteralPath $RegisterPath -Raw | ConvertFrom-Json -AsHashtable
$out = Test-SecretsRegister -Register $register -Now $Now -WarnDays $WarnDays

$failing = @($out.Findings | Where-Object {
        $_.FindingId -in 'SECRET-EXPIRED', 'SECRET-EXPIRING', 'SECRET-NO-OWNER' -or
        ($_.FindingId -eq 'SECRET-NO-EXPIRY' -and @($out.Rows | Where-Object Name -EQ $_.DisplayName | Where-Object Status -EQ 'present').Count)
    })

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("## Long-lived secrets: expiry check ($($Now.ToString('yyyy-MM-dd')), window $WarnDays days)")
$md.Add('')
$md.Add('| Secret | Owner role | Status | Expires | Days left | Finding |')
$md.Add('|---|---|---|---|---|---|')
foreach ($r in @($out.Rows | Sort-Object { $_.ExpiresOn })) {
    $left = ''
    $d = [datetime]::MinValue
    if ([datetime]::TryParseExact([string]$r.ExpiresOn, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { $left = [string][int]($d - $Now).TotalDays }
    $f = @($out.Findings | Where-Object DisplayName -EQ $r.Name | ForEach-Object FindingId) -join ', '
    $md.Add("| $($r.Name) | $($r.Owner) | $($r.Status) | $($r.ExpiresOn) | $left | $f |")
}
$md.Add('')
if ($failing.Count) {
    $md.Add("**$($failing.Count) item(s) need action:**")
    foreach ($f in $failing) { $md.Add("- $($f.FindingId): $($f.Detail)") }
    $md.Add('')
    $md.Add('Rotate at the store, then update createdOn / expiresOn / dateSource in `lab/iga/nhi-secrets-register.json` in a PR. The AWS SCIM token: `lab/docs/runbooks/rotate-aws-scim-token.md`.')
}
else { $md.Add("Nothing expires in the next $WarnDays days; every secret has an owner role.") }

$text = ($md -join "`n") + "`n"
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $text -Encoding utf8NoBOM }
Write-Output $text
if ($failing.Count) { exit 1 }
exit 0
