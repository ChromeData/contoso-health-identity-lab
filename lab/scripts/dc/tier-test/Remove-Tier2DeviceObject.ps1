<#
.SYNOPSIS
    ON DC01: removes the AD computer object of the deleted Tier 2 test device
    (T2DEV01) so no stale account stays in OU=Devices,OU=Tier2.
.DESCRIPTION
    Run AFTER `tier2-device.py delete`. Refuses any object outside
    OU=Devices,OU=Tier2 and any name but the test device's.
#>
[CmdletBinding()]
param([string]$Name = 'T2DEV01')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Name -ne 'T2DEV01') { throw 'This script removes only the test device T2DEV01.' }
$c = Get-ADComputer -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
if (-not $c) { Write-Output "${Name}: no AD object (already removed)."; return }
if ($c.DistinguishedName -notlike "CN=$Name,OU=Devices,OU=Tier2,*") { throw "Refusing: $($c.DistinguishedName) is not in Tier2\Devices." }
# Remove-ADObject -Recursive: a joined Windows computer gets child objects
# (e.g. the Hyper-V/VM service connection point), and Remove-ADComputer
# refuses a non-leaf object (error 8213, seen 2026-11-07).
Remove-ADObject -Identity $c.DistinguishedName -Recursive -Confirm:$false
Write-Output "Removed $($c.DistinguishedName)."
$n = @(Get-ADComputer -Filter * -SearchBase ('OU=Tier2,' + (Get-ADDomain).DistinguishedName)).Count
Write-Output "Computers in Tier2 now: $n"
