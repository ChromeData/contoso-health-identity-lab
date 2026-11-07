<#
.SYNOPSIS
    Runs ON DC01: removes every on-premises group membership from DISABLED
    leaver accounts in OU=Disabled, so a later rehire comes back with only
    the new job's birthright access and none of the old groups.

.DESCRIPTION
    WHY (review finding C7, "rehire after 18 months"): the HR leaver disables
    the AD account and moves it to OU=Disabled (the parentDistinguishedName
    expression from 02-Configure-Domain.ps1). Nothing removed its AD group
    memberships. 04-Leaver.ps1 removes CLOUD groups, and skips AD-owned ones
    on purpose (Entra cannot change a synced group). A rehire is the same
    AD account switched back on (the provisioning engine matches on
    employeeId), so without this step the old file-share and app groups come
    back with her.

    What it does, per account:
      * only accounts directly in OU=Disabled at the domain root;
      * only accounts that are DISABLED (a rehire already switched back on is
        left alone: its new groups may already be there);
      * never a protected account (adminCount = 1: a member, or former member,
        of a privileged group). Tier 0 is cleaned by hand, on purpose;
      * removes every group in memberOf. The primary group (Domain Users) is
        not in memberOf, so it stays;
      * prints each removal (group name, account) so the run-command output is
        the record of what was taken away.

    Run it as part of the leaver (after HR's disable lands in AD), or daily.
    Called through run-on-dc.py (a managed run command: no RDP, no password on
    any command line). Windows PowerShell 5.1 as SYSTEM, ActiveDirectory
    module. Without -Apply yes it only reports.

    Status: BUILT (offline tests: tests/Clear-LeaverAdGroups.Tests.ps1). Not
    yet run on DC01.

.PARAMETER EmployeeId
    Only this worker (AD employeeID). Empty = every disabled account in
    OU=Disabled.

.PARAMETER Apply
    'yes' removes. Anything else is a dry run. (Run-command parameters are
    strings, so this is not a switch.)

.EXAMPLE
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/Clear-LeaverAdGroups.ps1                          # report only
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/Clear-LeaverAdGroups.ps1 --param EmployeeId=100210 --param Apply=yes
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$EmployeeId = '',

    [Parameter()]
    [string]$Apply = 'no'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($EmployeeId -and $EmployeeId -notmatch '^\d+$') { throw "EmployeeId must be the numeric worker id, not '$EmployeeId'." }
if (-not (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) { Import-Module ActiveDirectory }

$domainDn = (Get-ADDomain).DistinguishedName
$disabledOu = "OU=Disabled,$domainDn"
$filter = if ($EmployeeId) { "employeeID -eq '$EmployeeId'" } else { '*' }
$found = @(Get-ADUser -Filter $filter -SearchBase $disabledOu -SearchScope OneLevel -Properties employeeID, adminCount, Enabled, MemberOf)
if ($found.Count -eq 0) {
    Write-Output "No account in $disabledOu$(if ($EmployeeId) { " has employeeID $EmployeeId" }): nothing to do."
    exit 0
}

$removed = 0; $skipped = 0
foreach ($u in $found) {
    $name = [string]$u.SamAccountName
    if ($u.Enabled) { Write-Output "Skipped ${name}: enabled (a rehire in progress keeps its new groups)."; $skipped++; continue }
    $adminCount = 0
    if ($u.PSObject.Properties['adminCount'] -and $u.adminCount) { $adminCount = [int]$u.adminCount }
    if ($adminCount -eq 1) { Write-Output "Skipped ${name}: protected (adminCount=1). Clean Tier-0 memberships by hand."; $skipped++; continue }
    $groups = @($u.MemberOf | Where-Object { $_ })
    if ($groups.Count -eq 0) { Write-Output "${name}: no group memberships."; continue }
    foreach ($g in $groups) {
        $gName = (([string]$g -split '(?<!\\),', 2)[0]) -replace '^CN=', ''
        if ($Apply -ne 'yes') { Write-Output "Dry run: would remove $name from $gName"; continue }
        Remove-ADGroupMember -Identity $g -Members $u.DistinguishedName -Confirm:$false
        Write-Output "Removed $name from $gName"
        $removed++
    }
}
if ($Apply -ne 'yes') { Write-Output 'Dry run: nothing changed. Re-run with Apply=yes.' }
else { Write-Output "Done: $removed membership(s) removed, $skipped account(s) skipped." }
exit 0
