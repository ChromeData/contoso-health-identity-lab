<#
.SYNOPSIS
    ON THE TIER 2 TEST DEVICE: proves the GPO "Tier0 - Deny logon to Tier1 and
    Tier2" really denies a Tier 0 admin here, and that a Tier 2 admin still
    signs in.

.DESCRIPTION
    Runs INSIDE vm-t2dev-01 as SYSTEM (run-on-dc.py --rg rg-identity-lab-tiertest
    --vm vm-t2dev-01).

    1. gpupdate, then shows that the GPO is applied to this computer and
       which SIDs the five Deny rights now hold (secedit export = what the
       computer ENFORCES, not what the GPO file says).
       "Applied" is read from `gpresult /x` (XML), from the GPO's own entry:
       Enabled, IsValid, FilterAllowed true, AccessDenied false, and a link
       with AppliedOrder above 0. A plain text search of `gpresult /r` is NOT
       enough: that report also names GPOs that were filtered out (Greptile,
       PR #239). Any missing field counts as "not applied" (fail closed).
       verify: these element names come from gpresult /x output; Microsoft
       Learn does not document that schema. On the next run, compare
       gpoState with the "Applied Group Policy Objects" list of gpresult /r.
    2. Asks Windows itself to sign each admin in, with LogonUser (advapi32) -
       the same check the logon screen (interactive, type 2) and a file-share
       or remote-management connection (network, type 3) go through. Windows
       answers either "a token" (signed in) or an error. Error 1385
       (ERROR_LOGON_TYPE_NOT_GRANTED) means "the password was right, but this
       account may not log on this way here" - that is the deny right working.
    3. Makes a read-only share \\T2DEV01\TierTest (Domain Users: Read) so
       Test-TierNetworkLogon.ps1 can try a real SMB sign-in from DC01.

    Both test admins are in Protected Users (t0) or plain (t2); LogonUser on
    a domain member uses Kerberos, so that is not what blocks anyone.

    WHICH ACCOUNTS (README "Credentials"): the DISPOSABLE accounts that
    New-TierTestAccounts.ps1 makes on DC01 for this proof and
    Remove-TierTestAccounts.ps1 deletes after it. t0-tiertest is a member of
    Tier0-Admins (the SID the deny GPO names) and of nothing privileged, so
    its password, seen on this Tier 2 machine, opens nothing in AD. The
    script refuses a Tier 0 test account that is a direct member of Domain,
    Enterprise or Schema Admins or Administrators. Honest limit: this check
    runs AFTER the password has reached this machine. It stops the proof
    from passing with a real admin; the README keeps real admins out.

    Secrets: -T0Password / -T2Password are PROTECTED parameters. Each is
    passed to LogonUser only. Tokens are closed at once; nothing is printed
    but the result codes.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameters.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$T0Password,
    [Parameter(Mandatory)][string]$T2Password,
    [string]$Domain = 'CORP',
    [string]$T0User = 't0-tiertest',
    [string]$T2User = 't2-tiertest',
    [string]$GpoName = 'Tier0 - Deny logon to Tier1 and Tier2'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-RsopGpoState {
    # The GPO's entry in `gpresult /x` computer results, or $null. gpresult
    # lists applied AND filtered-out GPOs there, so the caller must check the
    # fields, not just the name. local-name(): the report uses XML namespaces.
    param([Parameter(Mandatory)][xml]$Rsop, [Parameter(Mandatory)][string]$Name)
    $field = { param($node, $n) $x = $node.SelectSingleNode("*[local-name()='$n']"); if ($x) { $x.InnerText } else { $null } }
    foreach ($g in @($Rsop.SelectNodes("//*[local-name()='ComputerResults']/*[local-name()='GPO']"))) {
        if ((& $field $g 'Name') -ne $Name) { continue }
        $orders = @($g.SelectNodes("*[local-name()='Link']") | Where-Object { (& $field $_ 'Enabled') -eq 'true' } |
                ForEach-Object { [int](& $field $_ 'AppliedOrder') })
        return [pscustomobject]@{
            Name          = $Name
            Enabled       = & $field $g 'Enabled'
            IsValid       = & $field $g 'IsValid'
            FilterAllowed = & $field $g 'FilterAllowed'
            AccessDenied  = & $field $g 'AccessDenied'
            AppliedOrder  = $orders
        }
    }
    return $null
}

function Test-GpoApplied {
    # Fail closed: every field must say "applied"; a missing field is "no".
    param($State)
    if (-not $State) { return $false }
    return ($State.Enabled -eq 'true' -and $State.IsValid -eq 'true' -and $State.FilterAllowed -eq 'true' -and
        $State.AccessDenied -eq 'false' -and @($State.AppliedOrder | Where-Object { $_ -gt 0 }).Count -gt 0)
}

function Get-PrivilegedMembership {
    # Direct memberOf DNs of the Tier 0 TEST account -> the privileged ones.
    # A non-empty answer means "this is a real admin, not a disposable one".
    param([string[]]$MemberOf)
    @($MemberOf | Where-Object { $_ -match '^CN=(Domain Admins|Enterprise Admins|Schema Admins|Administrators),' })
}

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
$t0Entry = ([adsisearcher]"(&(objectCategory=user)(sAMAccountName=$T0User))").FindOne()
if (-not $t0Entry) { throw "Tier 0 test account $T0User not found. Run New-TierTestAccounts.ps1 on DC01 first." }
$priv = Get-PrivilegedMembership -MemberOf @($t0Entry.Properties.memberof)
if ($priv) { throw "REFUSED: $T0User is a direct member of $($priv -join '; '). Use the disposable t0-tiertest account (README 'Credentials')." }
if (-not @($t0Entry.Properties.memberof | Where-Object { $_ -match '^CN=Tier0-Admins,' })) { throw "$T0User is not a member of Tier0-Admins, so the deny GPO would not name it." }

$null = & gpupdate.exe /target:computer /force
$rsopFile = Join-Path $env:TEMP ("rsop-{0}.xml" -f [guid]::NewGuid())
$null = & gpresult.exe /scope computer /x $rsopFile /f
if (-not (Test-Path -LiteralPath $rsopFile)) { throw 'gpresult /x wrote no report.' }
$gpoState = Get-RsopGpoState -Rsop ([xml](Get-Content -LiteralPath $rsopFile -Raw)) -Name $GpoName
Remove-Item -LiteralPath $rsopFile -Force
$gpoApplied = Test-GpoApplied $gpoState

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
    gpoState       = $gpoState
    tier0AdminsSid = $tier0Sid
    denyRights     = $deny
    logons         = $results
} | ConvertTo-Json -Depth 4

$t0 = @($results | Where-Object tier -EQ 'Tier 0')
$t2 = @($results | Where-Object tier -EQ 'Tier 2')
# Independent of gpresult: the computer must ENFORCE the deny for Tier0-Admins.
$enforced = @('SeDenyInteractiveLogonRight', 'SeDenyNetworkLogonRight' | Where-Object { $deny.ContainsKey($_) -and $deny[$_] -match ('(^|,)' + [regex]::Escape("*$tier0Sid") + '(,|$)') }).Count -eq 2
$pass = $gpoApplied -and $enforced -and (@($t0 | Where-Object code -NE 1385).Count -eq 0) -and (@($t2 | Where-Object code -NE 0).Count -eq 0)
Write-Output ("VERDICT: {0}" -f $(if ($pass) { 'PASS - Tier 0 admin denied (1385) on every tested logon type; Tier 2 admin signed in on every tested logon type' } else { 'FAIL - see logons above' }))
if (-not $pass) { exit 1 }
