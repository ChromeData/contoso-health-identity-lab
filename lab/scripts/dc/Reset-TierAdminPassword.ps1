<#
.SYNOPSIS
    Runs ON DC01: sets a new password on ONE tier admin account and proves a
    Kerberos sign-in with it.

.DESCRIPTION
    Called by lab/scripts/dc/rotate-tier-admin.py through run-on-dc.py (a
    managed run command: no RDP, the password only in a PROTECTED parameter).
    Windows PowerShell 5.1 as SYSTEM, ActiveDirectory module.

    Why it exists: a password that was typed on a lower-tier machine must be
    treated as known to that machine. The clean close is a new password
    (2026-11-07: t0-adm-01's password went to the temporary Tier 2 VM in the
    PR #239 proof; the VM is deleted).

    Steps:
      1. Refuse any account that is not t0-adm-01, t1-adm-01 or t2-adm-01.
         The build admin (contosoadmin) and the owner are never rotated
         here: other DC01 scripts use contosoadmin, so the owner decides.
      2. Set-ADAccountPassword -Reset (an admin reset: no old password
         needed). Read back pwdLastSet.
      3. Ask for a Kerberos service ticket to DC01's LDAP service AS that
         account with the new password (KerberosSecurityTokenProvider: SSPI
         Kerberos package only, so there is no NTLM fallback). Success means
         the KDC accepted the new password.

    Output markers (rotate-tier-admin.py reads them):
      RESET: DONE       the AD password has changed
      KERBEROS: PASS    a Kerberos ticket was issued with the new password

.PARAMETER SamAccountName
    t0-adm-01 | t1-adm-01 | t2-adm-01.

.PARAMETER NewPassword
    PROTECTED parameter only (never --param).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameter.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to make a SecureString from a protected parameter.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$NewPassword
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$allowed = @('t0-adm-01', 't1-adm-01', 't2-adm-01')
if ($allowed -notcontains $SamAccountName) {
    Write-Output "REFUSED: '$SamAccountName' is not a tier admin this script may rotate ($($allowed -join ', '))."
    exit 1
}
if (-not (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) { Import-Module ActiveDirectory }

$domain = Get-ADDomain
$before = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet
$secure = ConvertTo-SecureString $NewPassword -AsPlainText -Force
Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $secure
$after = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet
if ($after.pwdLastSet -le $before.pwdLastSet) {
    Write-Output 'RESET: FAILED (pwdLastSet did not move)'
    exit 1
}
Write-Output ('RESET: DONE {0} pwdLastSet {1:u} -> {2:u}' -f $SamAccountName, [DateTime]::FromFileTimeUtc($before.pwdLastSet), [DateTime]::FromFileTimeUtc($after.pwdLastSet))

# Kerberos check. The KDC on this DC answers; the ticket is for this DC's
# LDAP service, so no other machine is involved.
Add-Type -AssemblyName System.IdentityModel
$dcHost = (Get-ADDomainController -Identity $env:COMPUTERNAME).HostName
$spn = "ldap/$dcHost"
$cred = New-Object System.Net.NetworkCredential ($SamAccountName, $NewPassword, $domain.NetBIOSName)
$NewPassword = $null
try {
    $provider = New-Object System.IdentityModel.Selectors.KerberosSecurityTokenProvider ($spn, [System.Security.Principal.TokenImpersonationLevel]::Identification, $cred)
    $token = $provider.GetToken([TimeSpan]::FromSeconds(30))
    Write-Output ('KERBEROS: PASS ticket for {0} issued to {1}\{2}, valid to {3:u}' -f $spn, $domain.NetBIOSName, $SamAccountName, $token.ValidTo)
} catch {
    Write-Output ('KERBEROS: FAIL {0}' -f $_.Exception.Message.Trim())
    exit 2
} finally {
    $cred = $null
}
