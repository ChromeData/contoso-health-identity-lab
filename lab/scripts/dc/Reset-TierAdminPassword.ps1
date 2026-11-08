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
      4. Ask again with the OLD password. Only the KDC's bad-password answer
         (SEC_E_LOGON_DENIED) counts as refused; any other error is not
         proof and fails the run.

    Output markers (rotate-tier-admin.py reads them):
      RESET: DONE       the AD password has changed
      KERBEROS: PASS    a Kerberos ticket was issued with the new password
      KERBEROS-OLD: REFUSED  the old password got the bad-password answer

.PARAMETER SamAccountName
    t0-adm-01 | t1-adm-01 | t2-adm-01.

.PARAMETER NewPassword
    PROTECTED parameter only (never --param).

.PARAMETER OldPassword
    PROTECTED parameter only. Used once, for the "old password is refused" check.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameter.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to make a SecureString from a protected parameter.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$NewPassword,
    [Parameter(Mandatory)][string]$OldPassword
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
$nb = $domain.NetBIOSName
$before = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet
$secure = ConvertTo-SecureString $NewPassword -AsPlainText -Force
Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $secure
$after = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet
if ($after.pwdLastSet -le $before.pwdLastSet) {
    Write-Output 'RESET: FAILED (pwdLastSet did not move)'
    exit 1
}
Write-Output ('RESET: DONE {0} pwdLastSet {1:u} -> {2:u}' -f $SamAccountName, [DateTime]::FromFileTimeUtc($before.pwdLastSet), [DateTime]::FromFileTimeUtc($after.pwdLastSet))

# 3 + 4. Kerberos checks against this DC's KDC, for its own LDAP service.
Add-Type -AssemblyName System.IdentityModel
$spn = 'ldap/' + (Get-ADDomainController -Identity $env:COMPUTERNAME).HostName
function Get-Ticket([string]$pw) {
    $cred = New-Object System.Net.NetworkCredential ($SamAccountName, $pw, $nb)
    $p = New-Object System.IdentityModel.Selectors.KerberosSecurityTokenProvider ($spn, [System.Security.Principal.TokenImpersonationLevel]::Identification, $cred)
    $p.GetToken([TimeSpan]::FromSeconds(30))
}
function Test-LogonDenied {
    # True only when SSPI said "bad user name or password" (SEC_E_LOGON_DENIED).
    param([System.Exception]$Exception)
    $logonDenied = -2146893044   # 0x8009030C
    for ($e = $Exception; $null -ne $e; $e = $e.InnerException) {
        if ($e.HResult -eq $logonDenied) { return $true }
        if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq $logonDenied) { return $true }
    }
    return $false
}
function Get-OldPasswordVerdict {
    # REFUSED | ACCEPTED | ERROR: <message>. $Probe is the ticket request.
    param([scriptblock]$Probe)
    try {
        $null = & $Probe
        return 'ACCEPTED'
    } catch {
        $ex = $_.Exception
        if ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
        if (Test-LogonDenied -Exception $ex) { return 'REFUSED' }
        return 'ERROR: ' + $ex.Message.Trim()
    }
}
$rc = 0
try {
    $t = Get-Ticket $NewPassword
    Write-Output ('KERBEROS: PASS ticket for {0} issued to {1}\{2}, valid to {3:u}' -f $spn, $nb, $SamAccountName, $t.ValidTo)
} catch {
    Write-Output ('KERBEROS: FAIL {0}' -f $_.Exception.Message.Trim())
    $rc = 2
}
$verdict = Get-OldPasswordVerdict -Probe { Get-Ticket $OldPassword }
switch -Wildcard ($verdict) {
    'REFUSED' { Write-Output 'KERBEROS-OLD: REFUSED (the KDC answered bad password, SEC_E_LOGON_DENIED, for the old one)' }
    'ACCEPTED' { Write-Output 'KERBEROS-OLD: ACCEPTED (the old password still works)'; $rc = 2 }
    default { Write-Output ('KERBEROS-OLD: {0} (not proof the old password is refused)' -f $verdict); $rc = 2 }
}
$NewPassword = $null; $OldPassword = $null
exit $rc
