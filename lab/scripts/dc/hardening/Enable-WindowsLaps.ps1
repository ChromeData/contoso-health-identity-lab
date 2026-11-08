<#
.SYNOPSIS
    Turns on Microsoft's built-in Windows LAPS, backed up to AD: DC01's DSRM
    password, and the local Administrator password of every Tier 1 member
    server. Then proves one rotation. Idempotent.

.DESCRIPTION
    Runs ON DC01 as SYSTEM through lab/scripts/dc/run-on-dc.py (Windows
    PowerShell 5.1). Without -Apply yes it only reports.

    WHAT WINDOWS LAPS DOES (plain words)
      Every Windows machine has a local admin password. On a domain
      controller that is the DSRM password, used to repair AD offline. If it
      never changes, or is the same on many machines, one leak opens them
      all. Windows LAPS makes each machine set its own long random password,
      change it on a schedule, and store it ENCRYPTED in its own AD computer
      object. Only Domain Admins (or a group you name) can decrypt it.

    WHAT IT CONFIGURES (all values verified on Microsoft Learn,
    "Configure policy settings for Windows LAPS" and "Get started with
    Windows LAPS and Windows Server Active Directory", read 2026-11-07)
      Schema    Update-LapsADSchema, once per forest (adds msLAPS-*).
      Rights    Set-LapsADComputerSelfPermission on OU=Domain Controllers
                and OU=Servers,OU=Tier1 (a machine may write its own
                password). Set-LapsADReadPasswordPermission for Tier1-Admins
                on OU=Servers,OU=Tier1.
      GPO 1     "LAPS - DC01 DSRM password to AD", linked to Domain
                Controllers: BackupDirectory=2 (AD), ADPasswordEncryptionEnabled=1,
                ADBackupDSRMPassword=1, PasswordComplexity=4, PasswordLength=24,
                PasswordAgeDays=30, ADEncryptedPasswordHistorySize=2.
                DSRM passwords are always decryptable by Domain Admins only
                (ADPasswordEncryptionPrincipal is ignored for DSRM).
      GPO 2     "LAPS - Tier1 servers local admin to AD", linked to
                OU=Servers,OU=Tier1: the same, without the DSRM switch, and
                ADPasswordEncryptionPrincipal = <NETBIOS>\Tier1-Admins, so
                Tier 1 admins can read Tier 1 passwords and nothing above.
      Both GPOs write the GROUP POLICY root
      HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS, not the
      CSP root HKLM\Software\Microsoft\Policies\LAPS (Intune's).

    THE ROTATION PROOF
      Reads DC01's msLAPS-PasswordExpirationTime and a SHA-256 fingerprint
      of the ENCRYPTED blob msLAPS-EncryptedDSRMPassword (ciphertext, not the
      password), runs Reset-LapsPassword, reads both again and prints event
      10018 ("password successfully updated in AD"). The password itself is
      never decrypted or printed.

    NOTE ON KEY VAULT
      01-Install-ADDSForest.ps1 wrote the first DSRM password to Key Vault
      (dc01-dsrm-password). Once LAPS rotates, that value is OLD. The
      current DSRM password is the one in AD: Get-LapsADPassword -Identity
      DC01 -AsPlainText, run by a Domain Admin.

.PARAMETER Apply
    'yes' to make changes. Anything else is a dry run.
.PARAMETER Rotate
    'yes' to force one DSRM rotation and prove it (needs Apply=yes).
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Apply = 'no',
    [string]$Rotate = 'no'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:GpRoot = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'

function Get-LapsPolicyValues {
    # The DWORD settings each GPO writes. DSRM adds ADBackupDSRMPassword.
    param([ValidateSet('Dsrm', 'Server')][string]$Kind)
    $v = [ordered]@{
        BackupDirectory                = 2
        ADPasswordEncryptionEnabled    = 1
        PasswordComplexity             = 4
        PasswordLength                 = 24
        PasswordAgeDays                = 30
        ADEncryptedPasswordHistorySize = 2
    }
    if ($Kind -eq 'Dsrm') { $v['ADBackupDSRMPassword'] = 1 }
    return $v
}

function Get-BlobFingerprint {
    # First 12 hex chars of SHA-256 over the encrypted attribute bytes. It
    # changes when the ciphertext changes; it reveals nothing about the password.
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return 'none' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') })).Substring(0, 12) }
    finally { $sha.Dispose() }
}

function Confirm-LapsGpo {
    param([string]$Name, [string]$Target, [System.Collections.IDictionary]$Values, [string]$Principal)
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) { $gpo = New-GPO -Name $Name -Comment 'Windows LAPS, backup to AD. Code: lab/scripts/dc/hardening/Enable-WindowsLaps.ps1' }
    foreach ($k in $Values.Keys) {
        Set-GPRegistryValue -Guid $gpo.Id -Key $script:GpRoot -ValueName $k -Type DWord -Value ([int]$Values[$k]) | Out-Null
    }
    if ($Principal) { Set-GPRegistryValue -Guid $gpo.Id -Key $script:GpRoot -ValueName 'ADPasswordEncryptionPrincipal' -Type String -Value $Principal | Out-Null }
    if (-not ((Get-GPInheritance -Target $Target).GpoLinks | Where-Object DisplayName -EQ $Name)) {
        New-GPLink -Guid $gpo.Id -Target $Target -LinkEnabled Yes | Out-Null
    }
    return $gpo
}

function Get-DsrmState([string]$Dn) {
    # DirectorySearcher, not Get-ADObject: right after Update-LapsADSchema the
    # AD module's schema cache does not know msLAPS-* yet and returns raw
    # value collections. The searcher gives Int64 (large integer) and byte[].
    $ds = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Dn", '(objectClass=computer)', @('msLAPS-PasswordExpirationTime', 'msLAPS-EncryptedDSRMPassword'))
    $ds.SearchScope = 'Base'
    $r = $ds.FindOne()
    if (-not $r) { throw "Could not read $Dn" }
    $exp = $r.Properties['mslaps-passwordexpirationtime']
    $blob = $r.Properties['mslaps-encrypteddsrmpassword']
    [pscustomobject]@{
        Expires     = if ($exp.Count) { [DateTime]::FromFileTimeUtc([int64]$exp[0]).ToString('u') } else { 'not set' }
        Fingerprint = if ($blob.Count) { Get-BlobFingerprint -Bytes ([byte[]]$blob[0]) } else { 'none' }
    }
}

# ---------------------------------------------------------------------------
$doApply = ($Apply -eq 'yes')
Write-Output ("Enable-WindowsLaps {0} at {1:u}" -f $(if ($doApply) { 'APPLY' } else { 'DRY RUN' }), (Get-Date).ToUniversalTime())
Import-Module ActiveDirectory
Import-Module GroupPolicy
Import-Module LAPS
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$dcOu = $domain.DomainControllersContainer
$srvOu = "OU=Servers,OU=Tier1,$base"
if ($domain.DomainMode -notmatch '2016|2025') { throw "Domain functional level $($domain.DomainMode): LAPS encryption and DSRM backup need 2016 or later" }
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$srvOu'")) { throw "$srvOu is missing: run Set-AdTiering.ps1 first" }

# 1. Schema ------------------------------------------------------------------
$schemaNc = (Get-ADRootDSE).schemaNamingContext
$hasSchema = [bool](Get-ADObject -SearchBase $schemaNc -Filter "lDAPDisplayName -eq 'msLAPS-EncryptedDSRMPassword'")
Write-Output "Schema has msLAPS attributes: $hasSchema"
if (-not $hasSchema -and $doApply) {
    Update-LapsADSchema -Confirm:$false
    Write-Output '  Update-LapsADSchema done'
}

if (-not $doApply) { Write-Output 'Dry run: would set permissions, create and link both GPOs.'; return }

# 2. Permissions -------------------------------------------------------------
Set-LapsADComputerSelfPermission -Identity $dcOu | Out-Null
Set-LapsADComputerSelfPermission -Identity $srvOu | Out-Null
Set-LapsADReadPasswordPermission -Identity $srvOu -AllowedPrincipals @("$($domain.NetBIOSName)\Tier1-Admins") | Out-Null
Write-Output "Self-write on $dcOu and $srvOu; Tier1-Admins may read on $srvOu"

# 3. GPOs --------------------------------------------------------------------
$g1 = Confirm-LapsGpo -Name 'LAPS - DC01 DSRM password to AD' -Target $dcOu -Values (Get-LapsPolicyValues -Kind Dsrm)
$g2 = Confirm-LapsGpo -Name 'LAPS - Tier1 servers local admin to AD' -Target $srvOu -Values (Get-LapsPolicyValues -Kind Server) -Principal "$($domain.NetBIOSName)\Tier1-Admins"
Write-Output "GPO $($g1.DisplayName) $($g1.Id) -> $dcOu"
Write-Output "GPO $($g2.DisplayName) $($g2.Id) -> $srvOu"

# 4. Apply policy now and let LAPS process it --------------------------------
& gpupdate.exe /target:computer /force | Out-Null
Invoke-LapsPolicyProcessing
Start-Sleep -Seconds 20
$dc = Get-ADComputer $env:COMPUTERNAME
$before = Get-DsrmState $dc.DistinguishedName
Write-Output "DSRM in AD (after first processing): expires $($before.Expires), blob $($before.Fingerprint)"
if ($before.Fingerprint -eq 'none') { throw 'No encrypted DSRM password in AD after policy processing: see the Microsoft-Windows-LAPS/Operational log' }

# 5. One rotation -------------------------------------------------------------
if ($Rotate -eq 'yes') {
    $t0 = Get-Date
    Reset-LapsPassword
    Start-Sleep -Seconds 10
    $after = Get-DsrmState $dc.DistinguishedName
    Write-Output "ROTATION before: expires $($before.Expires), blob $($before.Fingerprint)"
    Write-Output "ROTATION after:  expires $($after.Expires), blob $($after.Fingerprint)"
    if ($after.Fingerprint -eq $before.Fingerprint) { throw 'Rotation not visible in AD: the encrypted blob did not change' }
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-LAPS/Operational'; Id = 10018; StartTime = $t0 } -ErrorAction SilentlyContinue |
        Select-Object -First 2 | ForEach-Object { Write-Output ("EVENT {0} {1:u} {2}" -f $_.Id, $_.TimeCreated.ToUniversalTime(), ($_.Message -split "`n")[0].Trim()) }
}
$servers = @(Get-ADComputer -Filter * -SearchBase $srvOu).Count
Write-Output "Member servers in $srvOu today: $servers"
Write-Output 'Enable-WindowsLaps done.'
