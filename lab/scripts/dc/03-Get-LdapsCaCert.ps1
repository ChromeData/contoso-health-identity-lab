<#
.SYNOPSIS
    Prints the lab Enterprise Root CA certificate as PEM so Vault's LDAP
    secrets engine can verify the DC's LDAPS certificate (no insecure_tls).

.DESCRIPTION
    Runs ON the DC via `az vm run-command invoke`; lab/pam/vault-onboard-ad.sh
    captures the output into lab/pam/.secrets/vault-ca/ad-root-ca.pem
    (vault_install_ca in lab/pam/lib.sh). Public certificate only - nothing
    secret is printed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$tmp = Join-Path $env:TEMP 'ad-root-ca.cer'
certutil -ca.cert $tmp | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -ca.cert failed (exit $LASTEXITCODE) - is the CA configured? Run 02-Configure-Domain.ps1 first" }
$der = [IO.File]::ReadAllBytes($tmp)
Remove-Item $tmp -Force
$b64 = [Convert]::ToBase64String($der, 'InsertLineBreaks')
Write-Output '-----BEGIN CERTIFICATE-----'
Write-Output $b64
Write-Output '-----END CERTIFICATE-----'
