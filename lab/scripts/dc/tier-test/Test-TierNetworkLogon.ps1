<#
.SYNOPSIS
    ON DC01: a real SMB connection to the Tier 2 test device, once as the
    Tier 0 admin (must be refused) and once as the Tier 2 admin (must work).

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (run-on-dc.py). Maps \\<device FQDN>\TierTest
    with New-PSDrive -Credential, so no password reaches a command line (a
    `net use` would put it in the process audit log). The FQDN forces
    Kerberos, which Protected Users needs. The refusal for the Tier 0 admin
    comes from the DEVICE: its "Deny access to this computer from the
    network" right (SeDenyNetworkLogonRight) holds Tier0-Admins.

.PARAMETER T0Password / T2Password
    PROTECTED parameters only (keychain:contoso-lab-ad-t0-adm-01 / -t2-adm-01).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameters.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to make a PSCredential from a protected parameter.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$T0Password,
    [Parameter(Mandatory)][string]$T2Password,
    [string]$Device = 'T2DEV01.corp.contosohealthlab.com'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$out = @()
foreach ($c in @(@{ u = 'CORP\t0-adm-01'; p = $T0Password; tier = 'Tier 0'; want = 'refused' }, @{ u = 'CORP\t2-adm-01'; p = $T2Password; tier = 'Tier 2'; want = 'works' })) {
    $cred = New-Object System.Management.Automation.PSCredential ($c.u, (ConvertTo-SecureString $c.p -AsPlainText -Force))
    $name = 'TT' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    try {
        $null = New-PSDrive -Name $name -PSProvider FileSystem -Root "\\$Device\TierTest" -Credential $cred
        $files = @(Get-ChildItem "${name}:\" | ForEach-Object Name)
        Remove-PSDrive $name -Force
        $out += [pscustomobject]@{ account = $c.u; tier = $c.tier; expected = $c.want; result = 'CONNECTED'; detail = "listed: $($files -join ', ')" }
    } catch {
        $out += [pscustomobject]@{ account = $c.u; tier = $c.tier; expected = $c.want; result = 'REFUSED'; detail = $_.Exception.Message.Trim() }
    }
}
$T0Password = $null; $T2Password = $null
$out | ConvertTo-Json
$pass = ($out[0].result -eq 'REFUSED' -and $out[0].detail -match 'logon type') -and ($out[1].result -eq 'CONNECTED')
Write-Output ("VERDICT: {0}" -f $(if ($pass) { 'PASS - Tier 0 admin refused over SMB (logon type not granted); Tier 2 admin connected' } else { 'FAIL - see results above' }))
if (-not $pass) { exit 1 }
