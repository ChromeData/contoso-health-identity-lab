<#
.SYNOPSIS
    Joins THIS machine (the temporary Tier 2 test device, vm-t2dev-01) to the
    lab domain, straight into OU=Devices,OU=Tier2, then restarts it.

.DESCRIPTION
    Runs INSIDE the test VM as SYSTEM (lab/scripts/dc/run-on-dc.py --rg
    rg-identity-lab-tiertest --vm vm-t2dev-01). The VNet's DNS server is DC01
    (10.42.2.4) over VNet peering, so the domain name resolves.

    Why straight into Tier2\Devices: the GPO "Tier0 - Deny logon to Tier1 and
    Tier2" (Set-AdTiering.ps1, PR #225) is linked there. A computer in the
    default Computers container would not get it.

    Who joins: CORP\tiertest-join, a DISPOSABLE account that
    New-TierTestAccounts.ps1 makes on DC01. It may only create computer
    objects in OU=Devices,OU=Tier2 and set their password, DNS host name,
    SPNs and account restrictions (the delegated-join rights). Its password
    reaches this Tier 2 machine, so it must be worth nothing beyond that OU,
    and it expires in hours and is deleted after the proof. The script
    REFUSES the build admin (contosoadmin) and the built-in Administrator.
    The join is a network logon to the DC, not a logon to this machine, so
    the deny GPO does not block it. After the restart the GPO applies at boot.

    History: the 2026-11-07 run (E142) joined with CORP\contosoadmin, the
    build admin. That put its password on this machine (Greptile, PR #239).
    See README "Credentials".

    Not built: an offline join (djoin /provision on DC01, /requestodj here).
    It would keep every domain password off this machine, but the join blob
    is itself a secret, and run-on-dc.py prints run-command output, so the
    blob has no safe path from DC01 to here yet.

    The restart is scheduled 20 s out so this run command can report first.

.PARAMETER JoinPassword
    Pass ONLY as a protected parameter (keychain:contoso-lab-tiertest-join).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameter; becomes a SecureString at once.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to turn a protected parameter into a PSCredential.')]
[CmdletBinding()]
param(
    [string]$DomainName = 'corp.contosohealthlab.com',
    [string]$JoinUser = 'CORP\tiertest-join',
    [Parameter(Mandatory)][string]$JoinPassword
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# A domain-wide admin must never sign in from a Tier 2 machine, even to join it.
if (($JoinUser -split '[\\@]') -match '^(contosoadmin|Administrator)$') {
    throw "REFUSED: $JoinUser is a domain-wide admin. Join with the disposable CORP\tiertest-join (New-TierTestAccounts.ps1)."
}

$sec = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
$JoinPassword = $null
$cred = New-Object System.Management.Automation.PSCredential ($JoinUser, $sec)

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -eq $DomainName) { Write-Output "Already joined to $DomainName."; return }

$dc = Resolve-DnsName -Name $DomainName -Type A -ErrorAction Stop | Select-Object -First 1
Write-Output "DNS: $DomainName -> $($dc.IPAddress)"
if (-not (Test-NetConnection -ComputerName $dc.IPAddress -Port 389 -InformationLevel Quiet)) { throw "Cannot reach LDAP on $($dc.IPAddress) (peering / NSG?)." }

$base = ($DomainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','
$ou = "OU=Devices,OU=Tier2,$base"
Add-Computer -DomainName $DomainName -OUPath $ou -Credential $cred -Force
Write-Output "Joined $env:COMPUTERNAME to $DomainName in $ou. Restarting in 20 s."
& shutdown.exe /r /t 20 /c "Domain join (tier GPO test)" | Out-Null
