<#
.SYNOPSIS
    ON DC01: deletes the three DISPOSABLE Tier GPO proof accounts and the
    join delegation that New-TierTestAccounts.ps1 made. Safe to re-run.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (run-on-dc.py), after the proof. Status:
    BUILT (mocked tests); not yet RAN.
    Order: the join ACEs on OU=Devices,OU=Tier2 first (dsacls /R needs the
    account to still resolve), then the accounts. Touches only these three
    names, and only in the OUs New-TierTestAccounts.ps1 uses.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$d = Get-ADDomain
$dn = $d.DistinguishedName
$want = @{ 't0-tiertest' = "OU=Accounts,OU=Tier0,$dn"; 't2-tiertest' = "OU=Accounts,OU=Tier2,$dn"; 'tiertest-join' = "OU=Accounts,OU=Tier2,$dn" }

# -ErrorAction Stop: a failed read must stop here, not read as "already gone".
$join = Get-ADUser -Filter "SamAccountName -eq 'tiertest-join'" -ErrorAction Stop
if ($join) {
    $null = & dsacls.exe "OU=Devices,OU=Tier2,$dn" /R "$($d.NetBIOSName)\tiertest-join"
    if ($LASTEXITCODE -ne 0) { throw "dsacls /R for tiertest-join failed (exit $LASTEXITCODE); the account is kept so the ACEs can still be removed." }
    Write-Output "- join delegation on OU=Devices,OU=Tier2 removed"
}
foreach ($sam in 't0-tiertest', 't2-tiertest', 'tiertest-join') {
    $u = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction Stop
    if (-not $u) { Write-Output "= ${sam}: no account (already removed)"; continue }
    if ($u.DistinguishedName -ne "CN=$sam,$($want[$sam])") { throw "REFUSED: $($u.DistinguishedName) is not where New-TierTestAccounts.ps1 puts $sam." }
    Remove-ADUser -Identity $u.DistinguishedName -Confirm:$false
    Write-Output "- $sam removed"
}
