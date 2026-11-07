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

    Who joins: CORP\contosoadmin (the build admin). The join is a network
    logon to the DC, not a logon to this machine, so the deny GPO does not
    block it. After the restart the GPO applies at boot.

    The restart is scheduled 20 s out so this run command can report first.

.PARAMETER DomainAdminPassword
    Pass ONLY as a protected parameter (keychain:contoso-lab-dc01-admin).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameter; becomes a SecureString at once.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to turn a protected parameter into a PSCredential.')]
[CmdletBinding()]
param(
    [string]$DomainName = 'corp.contosohealthlab.com',
    [string]$DomainAdminUser = 'CORP\contosoadmin',
    [Parameter(Mandatory)][string]$DomainAdminPassword
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sec = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
$DomainAdminPassword = $null
$cred = New-Object System.Management.Automation.PSCredential ($DomainAdminUser, $sec)

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
