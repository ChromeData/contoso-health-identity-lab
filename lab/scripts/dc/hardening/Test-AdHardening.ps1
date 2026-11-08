<#
.SYNOPSIS
    Reads back the AD hardening on DC01 and prints one PASS or FAIL line per
    check. Optionally proves that sign-in still works.

.DESCRIPTION
    Runs ON DC01 as SYSTEM through lab/scripts/dc/run-on-dc.py (Windows
    PowerShell 5.1). Exit code 1 if any check fails.

    CHECKS (read-only)
      Tier OUs and groups exist; the three new admins sit in their tier's
      Accounts OU; they are in Protected Users and "cannot be delegated";
      tier0-admin-01/02 and contosoadmin are NOT in Protected Users; the
      deny-logon GPO holds all five Deny rights for the four Tier 0 SIDs and
      is linked to Tier1\Servers and Tier2\Devices only; the LAPS schema is
      there; both LAPS GPOs hold their values, are linked (enabled) to
      exactly their OU, and the server policy's decryptor is Tier1-Admins;
      DC01 has an
      encrypted DSRM password in AD; the Cloud Sync agent service runs.

    SIGN-IN PROOF (-SignIn yes; writes one temporary object)
      A plain domain user is the "normal user": it is created in CN=Users
      (outside the Cloud Sync scope, so it never reaches Entra) with a random
      password held only in memory, binds to LDAP with Kerberos and with
      NTLM, and is deleted again. Then t2-adm-01 (Protected Users) binds with
      Kerberos (must work) and with NTLM (must be refused): that is what
      Protected Users does, and why the NTLM-based legacy admins stay out.

.PARAMETER SignIn
    'yes' to run the sign-in proof.
.PARAMETER T2Password
    t2-adm-01's password (protected parameter, from the Keychain). Required
    with SignIn=yes: the script stops before creating anything without it.
#>
#Requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The temporary user password is generated in memory and handed to New-ADUser as a SecureString; it is never printed or stored.')]
[CmdletBinding()]
param(
    [string]$SignIn = 'no',
    [string]$T2Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0
function Write-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if (-not $Ok) { $script:Failures++ }
    Write-Output ("{0} {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if ($Detail) { " ($Detail)" } else { '' }))
}

function Test-InfDenyRights {
    # True when every Deny right in the template lists every SID.
    param([string]$Inf, [string[]]$Sids)
    foreach ($r in 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight') {
        $line = ($Inf -split "`r?`n") | Where-Object { $_ -match "^\s*$r\s*=" } | Select-Object -First 1
        if (-not $line) { return $false }
        $have = (($line -split '=', 2)[1] -split ',') | ForEach-Object { $_.Trim().TrimStart('*') }
        foreach ($s in $Sids) { if ($have -notcontains $s) { return $false } }
    }
    return $true
}

function Test-GpoLinks {
    # True only when the GPO report's links are EXACTLY the expected SOM
    # paths (domain/OU/OU) and every one of them is enabled. A missing,
    # extra or disabled link fails. Returns @{ Ok; Detail }.
    param([xml]$Report, [string[]]$Expected)
    # LocalName, not $Report.GPO.LinksTo: under StrictMode a GPO with no
    # links has no LinksTo property (that would throw, not FAIL), and the
    # real report carries a default namespace, which XPath would miss.
    $links = @($Report.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'LinksTo' })
    $have = @($links | ForEach-Object { "$($_.SOMPath)" })
    $off = @($links | Where-Object { "$($_.Enabled)" -ne 'true' } | ForEach-Object { "$($_.SOMPath)" })
    $missing = @($Expected | Where-Object { $have -notcontains $_ })
    $extra = @($have | Where-Object { $Expected -notcontains $_ })
    $ok = ($missing.Count -eq 0 -and $extra.Count -eq 0 -and $off.Count -eq 0)
    $detail = "links: $($have -join '; ')"
    if ($missing) { $detail += " | missing: $($missing -join '; ')" }
    if ($extra) { $detail += " | extra: $($extra -join '; ')" }
    if ($off) { $detail += " | disabled: $($off -join '; ')" }
    return @{ Ok = $ok; Detail = $detail }
}

function Assert-SignInInputs {
    # The sign-in proof has two halves; never run one and report success.
    param([string]$SignIn, [string]$T2Password)
    if ($SignIn -eq 'yes' -and -not $T2Password) {
        throw 'SignIn=yes needs T2Password (keychain:contoso-lab-ad-t2-adm-01): without it the Protected Users half would be skipped'
    }
}

function Test-LdapBind {
    # Returns 'ok' or the error message. Credentials stay in memory.
    param([string]$Server, [Net.NetworkCredential]$Credential, [ValidateSet('Kerberos', 'Ntlm')][string]$Auth)
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $id = New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, 389)
    $c = New-Object DirectoryServices.Protocols.LdapConnection($id, $Credential, [DirectoryServices.Protocols.AuthType]::$Auth)
    try { $c.SessionOptions.Signing = $true; $c.SessionOptions.Sealing = $true; $c.Bind(); return 'ok' }
    catch { return $_.Exception.Message.Trim() }
    finally { $c.Dispose() }
}

function New-RandomPassword {
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $b = New-Object byte[] 24; $rng.GetBytes($b)
    return 'Aa1-' + [Convert]::ToBase64String($b).Replace('/', 'x').Replace('+', 'y').TrimEnd('=')
}

# ---------------------------------------------------------------------------
Assert-SignInInputs -SignIn $SignIn -T2Password $T2Password
Import-Module ActiveDirectory
Import-Module GroupPolicy
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$sid = $domain.DomainSID.Value
Write-Output ("Test-AdHardening at {0:u} on {1}" -f (Get-Date).ToUniversalTime(), $domain.DNSRoot)

# Tiers --------------------------------------------------------------------
foreach ($dn in "OU=Tier0,$base", "OU=Tier1,$base", "OU=Tier2,$base", "OU=Servers,OU=Tier1,$base", "OU=Devices,OU=Tier2,$base") {
    Write-Check "OU $dn" ([bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'"))
}
$pu = @(Get-ADGroupMember 'Protected Users' | ForEach-Object { $_.SamAccountName })
foreach ($t in 0, 1, 2) {
    $u = Get-ADUser -Filter "SamAccountName -eq 't$t-adm-01'" -Properties AccountNotDelegated, MemberOf
    Write-Check "t$t-adm-01 in OU=Accounts,OU=Tier$t" ([bool]$u -and $u.DistinguishedName -like "*,OU=Accounts,OU=Tier$t,$base")
    Write-Check "t$t-adm-01 in Tier$t-Admins" ([bool]$u -and @($u.MemberOf | Where-Object { $_ -like "CN=Tier$t-Admins,*" }).Count -eq 1)
    Write-Check "t$t-adm-01 in Protected Users" ($pu -contains "t$t-adm-01")
    Write-Check "t$t-adm-01 cannot be delegated" ([bool]$u -and $u.AccountNotDelegated)
}
foreach ($n in 'tier0-admin-01', 'tier0-admin-02', 'contosoadmin') {
    Write-Check "$n NOT in Protected Users (NTLM remote-session path)" ($pu -notcontains $n)
}

# Deny-logon GPO -------------------------------------------------------------
$gpo = Get-GPO -Name 'Tier0 - Deny logon to Tier1 and Tier2' -ErrorAction SilentlyContinue
Write-Check 'GPO Tier0 - Deny logon to Tier1 and Tier2 exists' ([bool]$gpo)
if ($gpo) {
    $sysvol = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysVol
    $inf = Join-Path $sysvol ("{0}\Policies\{{{1}}}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -f $domain.DNSRoot, $gpo.Id.ToString().ToUpperInvariant())
    $want = @("$sid-512", "$sid-519", "$sid-518", (Get-ADGroup 'Tier0-Admins').SID.Value)
    $text = if (Test-Path -LiteralPath $inf) { [IO.File]::ReadAllText($inf) } else { '' }
    Write-Check 'deny GPO: 5 Deny rights x 4 Tier 0 SIDs' (Test-InfDenyRights -Inf $text -Sids $want)
    $l = Test-GpoLinks -Report ([xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)) -Expected @("$($domain.DNSRoot)/Tier1/Servers", "$($domain.DNSRoot)/Tier2/Devices")
    Write-Check 'deny GPO linked (enabled) to Tier1/Servers and Tier2/Devices only' $l.Ok $l.Detail
}

# LAPS ---------------------------------------------------------------------
$schemaNc = (Get-ADRootDSE).schemaNamingContext
Write-Check 'LAPS schema (msLAPS-EncryptedDSRMPassword)' ([bool](Get-ADObject -SearchBase $schemaNc -Filter "lDAPDisplayName -eq 'msLAPS-EncryptedDSRMPassword'"))
$root = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
$lapsGpos = @(
    @{ N = 'LAPS - DC01 DSRM password to AD'; Dsrm = 1; Link = "$($domain.DNSRoot)/Domain Controllers"; Reader = $null }
    @{ N = 'LAPS - Tier1 servers local admin to AD'; Dsrm = 0; Link = "$($domain.DNSRoot)/Tier1/Servers"; Reader = "$($domain.NetBIOSName)\Tier1-Admins" }
)
foreach ($g in $lapsGpos) {
    $o = Get-GPO -Name $g.N -ErrorAction SilentlyContinue
    Write-Check "GPO $($g.N) exists" ([bool]$o)
    if (-not $o) { continue }
    $l = Test-GpoLinks -Report ([xml](Get-GPOReport -Guid $o.Id -ReportType Xml)) -Expected @($g.Link)
    Write-Check "$($g.N): linked (enabled) to $($g.Link) only" $l.Ok $l.Detail
    if ($g.Reader) {
        $p = (Get-GPRegistryValue -Guid $o.Id -Key $root -ValueName ADPasswordEncryptionPrincipal -ErrorAction SilentlyContinue).Value
        Write-Check "$($g.N): only $($g.Reader) can decrypt" ("$p".Trim([char]0) -eq $g.Reader) "ADPasswordEncryptionPrincipal=$p"
    }
    $bd = (Get-GPRegistryValue -Guid $o.Id -Key $root -ValueName BackupDirectory -ErrorAction SilentlyContinue).Value
    $enc = (Get-GPRegistryValue -Guid $o.Id -Key $root -ValueName ADPasswordEncryptionEnabled -ErrorAction SilentlyContinue).Value
    Write-Check "$($g.N): BackupDirectory=2 (AD), encryption on" ($bd -eq 2 -and $enc -eq 1) "BackupDirectory=$bd encryption=$enc"
    if ($g.Dsrm) {
        $d = (Get-GPRegistryValue -Guid $o.Id -Key $root -ValueName ADBackupDSRMPassword -ErrorAction SilentlyContinue).Value
        Write-Check "$($g.N): ADBackupDSRMPassword=1" ($d -eq 1)
    }
}
$ds = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$((Get-ADComputer $env:COMPUTERNAME).DistinguishedName)", '(objectClass=computer)', @('msLAPS-EncryptedDSRMPassword', 'msLAPS-PasswordExpirationTime'))
$ds.SearchScope = 'Base'
$r = $ds.FindOne()
$exp = $r.Properties['mslaps-passwordexpirationtime']
Write-Check 'DC01 encrypted DSRM password in AD' ($r.Properties['mslaps-encrypteddsrmpassword'].Count -eq 1) $(if ($exp.Count) { 'expires ' + [DateTime]::FromFileTimeUtc([int64]$exp[0]).ToString('u') } else { 'no expiry' })

# Cloud Sync agent ---------------------------------------------------------
$svc = Get-Service AADConnectProvisioningAgent -ErrorAction SilentlyContinue
Write-Check 'Cloud Sync agent service running' ([bool]$svc -and $svc.Status -eq 'Running')

# Sign-in proof --------------------------------------------------------------
if ($SignIn -eq 'yes') {
    $fqdn = "$env:COMPUTERNAME.$($domain.DNSRoot)"
    $sam = 'zz-signin-' + (Get-Random -Minimum 1000 -Maximum 9999)
    $pw = New-RandomPassword
    New-ADUser -Name $sam -SamAccountName $sam -Path "CN=Users,$base" -Enabled $true -Description 'Temporary sign-in check (Test-AdHardening.ps1); deleted at the end of the run' `
        -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
    try {
        Start-Sleep -Seconds 5
        $cred = New-Object Net.NetworkCredential($sam, $pw, $domain.NetBIOSName)
        $k = Test-LdapBind -Server $fqdn -Credential $cred -Auth Kerberos
        $n = Test-LdapBind -Server $fqdn -Credential $cred -Auth Ntlm
        Write-Check 'normal user signs in with Kerberos' ($k -eq 'ok') $k
        Write-Check 'normal user signs in with NTLM' ($n -eq 'ok') $n
    }
    finally { Remove-ADUser -Identity $sam -Confirm:$false; Write-Output "  temporary user $sam deleted" }
    # Assert-SignInInputs already refused SignIn=yes without T2Password.
    $cred = New-Object Net.NetworkCredential('t2-adm-01', $T2Password, $domain.NetBIOSName)
    $k = Test-LdapBind -Server $fqdn -Credential $cred -Auth Kerberos
    $n = Test-LdapBind -Server $fqdn -Credential $cred -Auth Ntlm
    Write-Check 't2-adm-01 (Protected Users) signs in with Kerberos' ($k -eq 'ok') $k
    Write-Check 't2-adm-01 (Protected Users) is refused over NTLM' ($n -ne 'ok') $n
}

Write-Output ("RESULT {0} failure(s)" -f $script:Failures)
if ($script:Failures) { exit 1 }
