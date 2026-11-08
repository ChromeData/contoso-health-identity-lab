<#
.SYNOPSIS
    Runs ON DC01: sets a new password on the build admin (contosoadmin) and
    proves a Kerberos sign-in with it.

.DESCRIPTION
    Called by lab/scripts/dc/rotate-build-admin.py through run-on-dc.py (a
    managed run command: no RDP, the passwords only in PROTECTED parameters).
    Windows PowerShell 5.1 as SYSTEM, ActiveDirectory module.

    Why it exists: the build admin's password was typed on a temporary VM
    (PR #239, the Tier 2 proof; the VM is deleted). A password typed on a
    lower-tier machine is treated as known to that machine. The owner
    approved this rotation on 2026-11-08.

    Steps:
      1. Refuse any account that is not contosoadmin.
      2. Look for Windows services and scheduled tasks on DC01 that run as
         contosoadmin (by name, UPN or SID). They would break with a new password, so the script
         stops before any change if it finds one (DEPENDENTS: FOUND).
      3. Set-ADAccountPassword -Reset (an admin reset: no old password
         needed). Read back pwdLastSet.
      4. Ask the KDC for a Kerberos service ticket to DC01's LDAP service AS
         contosoadmin with the new password (KerberosSecurityTokenProvider:
         SSPI Kerberos package only, no NTLM fallback).
      5. Ask again with the OLD password. The KDC must refuse it with a
         bad-password answer (SEC_E_LOGON_DENIED, 0x8009030C, anywhere in the
         exception chain). Any other error (timeout, KDC unreachable) is NOT
         a refusal: it prints KERBEROS-OLD: ERROR and the check fails.

    Output markers (rotate-build-admin.py reads them):
      DEPENDENTS: NONE | FOUND   services or tasks that run as contosoadmin
      RESET: DONE                the AD password has changed
      KERBEROS: PASS             a ticket was issued with the new password
      KERBEROS-OLD: REFUSED      the KDC answered "bad password" for the old one
      KERBEROS-OLD: ERROR        the check could not tell (fails the run)

.PARAMETER SamAccountName
    Must be contosoadmin.

.PARAMETER NewPassword
    PROTECTED parameter only (never --param).

.PARAMETER OldPassword
    PROTECTED parameter only. Used once, for the "old password is refused" check.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameters.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to make a SecureString from a protected parameter.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string]$NewPassword,
    [Parameter(Mandatory)][string]$OldPassword
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($SamAccountName -ne 'contosoadmin') {
    Write-Output "REFUSED: '$SamAccountName' is not the build admin (contosoadmin)."
    exit 1
}
if (-not (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) { Import-Module ActiveDirectory }
$domain = Get-ADDomain
$nb = $domain.NetBIOSName

# 2. Dependents: anything on DC01 that logs on with this password, named by
#    account name, UPN or SID (a task can store its principal as a SID).
function Test-RunAsAccount {
    param([string]$Principal, [string]$Sam, [string]$Sid)
    if (-not $Principal) { return $false }
    $p = $Principal.Trim()
    if ($Sid -and $p -eq $Sid) { return $true }
    return $p -match ('(^|\\){0}(@|$)' -f [regex]::Escape($Sam))
}
$sid = (Get-ADUser -Identity $SamAccountName).SID.Value
$svc = @(Get-CimInstance Win32_Service | Where-Object { Test-RunAsAccount -Principal $_.StartName -Sam $SamAccountName -Sid $sid } | ForEach-Object Name)
$tasks = @(Get-ScheduledTask | Where-Object { $_.Principal.LogonType -eq 'Password' -and (Test-RunAsAccount -Principal $_.Principal.UserId -Sam $SamAccountName -Sid $sid) } | ForEach-Object { $_.TaskPath + $_.TaskName })
if ($svc.Count -or $tasks.Count) {
    Write-Output ('DEPENDENTS: FOUND services [{0}] tasks [{1}]; nothing changed' -f ($svc -join ', '), ($tasks -join ', '))
    exit 3
}
Write-Output 'DEPENDENTS: NONE (no Windows service or stored-password scheduled task on DC01 runs as contosoadmin)'

# 3. Reset.
$before = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet
Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
$after = Get-ADUser -Identity $SamAccountName -Properties pwdLastSet
if ($after.pwdLastSet -le $before.pwdLastSet) {
    Write-Output 'RESET: FAILED (pwdLastSet did not move)'
    exit 1
}
Write-Output ('RESET: DONE {0} pwdLastSet {1:u} -> {2:u}' -f $SamAccountName, [DateTime]::FromFileTimeUtc($before.pwdLastSet), [DateTime]::FromFileTimeUtc($after.pwdLastSet))

# 4 + 5. Kerberos checks against this DC's KDC, for its own LDAP service.
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
