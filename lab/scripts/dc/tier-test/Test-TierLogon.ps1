<#
.SYNOPSIS
    ON THE TIER 2 TEST DEVICE: proves the GPO "Tier0 - Deny logon to Tier1 and
    Tier2" really denies a Tier 0 admin here, and that a Tier 2 admin still
    signs in.

.DESCRIPTION
    Runs INSIDE vm-t2dev-01 as SYSTEM (run-on-dc.py --rg rg-identity-lab-tiertest
    --vm vm-t2dev-01).

    1. gpupdate, then shows that the GPO is applied to this computer (gpresult)
       and which SIDs the five Deny rights now hold (secedit export = what the
       computer ENFORCES, not what the GPO file says).
    2. Asks Windows itself to sign each admin in, with LogonUser (advapi32) -
       the same check the logon screen (interactive, type 2) and a file-share
       or remote-management connection (network, type 3) go through. Windows
       answers either "a token" (signed in) or an error. Error 1385
       (ERROR_LOGON_TYPE_NOT_GRANTED) means "the password was right, but this
       account may not log on this way here" - that is the deny right working.
    3. Makes a read-only share \\T2DEV01\TierTest (Domain Users: Read) so
       Test-TierNetworkLogon.ps1 can try a real SMB sign-in from DC01.

    Both admins are in Protected Users (Kerberos only); LogonUser on a domain
    member uses Kerberos, so that is not what blocks anyone.

    Secrets: -T0Password / -T2Password are PROTECTED parameters. Each becomes
    an unmanaged string for LogonUser only, and is zeroed after use. Tokens
    are closed at once; nothing is printed but the result codes.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameters.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$T0Password,
    [Parameter(Mandatory)][string]$T2Password,
    [string]$Domain = 'CORP',
    [string]$T0User = 't0-adm-01',
    [string]$T2User = 't2-adm-01'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TierLogon {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static int Try(string user, string domain, string password, int type) {
        IntPtr t;
        if (LogonUserW(user, domain, password, type, 0, out t)) { CloseHandle(t); return 0; }
        return Marshal.GetLastWin32Error();
    }
}
'@

$cs = Get-CimInstance Win32_ComputerSystem
if (-not $cs.PartOfDomain) { throw 'This computer is not domain joined yet.' }
$null = & gpupdate.exe /target:computer /force
$applied = (& gpresult.exe /scope computer /r) -join "`n"
$gpoApplied = $applied -match 'Tier0 - Deny logon to Tier1 and Tier2'

$tmp = Join-Path $env:TEMP ("ur-{0}.inf" -f [guid]::NewGuid())
$null = & secedit.exe /export /areas USER_RIGHTS /cfg $tmp
$deny = @{}
foreach ($l in Get-Content $tmp) { if ($l -match '^(SeDeny\w+)\s*=\s*(.*)$') { $deny[$Matches[1]] = $Matches[2] } }
Remove-Item $tmp -Force

$sidOf = { param($n) (New-Object System.Security.Principal.NTAccount("$Domain\$n")).Translate([System.Security.Principal.SecurityIdentifier]).Value }
$tier0Sid = & $sidOf 'Tier0-Admins'

function Describe([int]$code) {
    switch ($code) { 0 { 'SIGNED IN' } 1385 { 'DENIED: logon type not granted (1385)' } 1326 { 'wrong user name or password (1326)' } default { "error $code" } }
}
$results = @()
foreach ($case in @(@{ u = $T0User; p = $T0Password; tier = 'Tier 0' }, @{ u = $T2User; p = $T2Password; tier = 'Tier 2' })) {
    foreach ($type in @(@{ n = 'interactive (2)'; v = 2 }, @{ n = 'network (3)'; v = 3 })) {
        $code = [TierLogon]::Try($case.u, $Domain, $case.p, $type.v)
        $results += [pscustomobject]@{ account = "$Domain\$($case.u)"; tier = $case.tier; logonType = $type.n; code = $code; result = (Describe $code) }
    }
}
$T0Password = $null; $T2Password = $null

# Share for the SMB test from DC01 (read-only, Domain Users).
$dir = 'C:\TierTest'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -Path (Join-Path $dir 'README.txt') -Value 'Tier GPO test share. Temporary. Deleted with vm-t2dev-01.'
if (-not (Get-SmbShare -Name TierTest -ErrorAction SilentlyContinue)) { New-SmbShare -Name TierTest -Path $dir -ReadAccess "$Domain\Domain Users" | Out-Null }
Enable-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction SilentlyContinue

[pscustomobject]@{
    computer       = "$($env:COMPUTERNAME).$($cs.Domain)"
    ou             = (([adsisearcher]"(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)`$))").FindOne().Properties.distinguishedname | Select-Object -First 1)
    gpoApplied     = $gpoApplied
    tier0AdminsSid = $tier0Sid
    denyRights     = $deny
    logons         = $results
} | ConvertTo-Json -Depth 4

$t0 = @($results | Where-Object tier -EQ 'Tier 0')
$t2 = @($results | Where-Object tier -EQ 'Tier 2')
$pass = $gpoApplied -and (@($t0 | Where-Object code -NE 1385).Count -eq 0) -and (@($t2 | Where-Object code -NE 0).Count -eq 0)
Write-Output ("VERDICT: {0}" -f $(if ($pass) { 'PASS - Tier 0 admin denied (1385) on every tested logon type; Tier 2 admin signed in on every tested logon type' } else { 'FAIL - see logons above' }))
if (-not $pass) { exit 1 }
