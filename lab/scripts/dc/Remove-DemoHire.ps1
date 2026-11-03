<#
.SYNOPSIS
    Demo retake helper, runs ON DC01: deletes the Active Directory account
    that HR inbound provisioning created for ONE demo hire (found by
    employeeID), so the hire can be recorded again as a fresh "create".

.DESCRIPTION
    Called by lab/scripts/demo/reset-demo-hire.sh through run-on-dc.py (a
    managed run command: no RDP, no password on any command line). Windows
    PowerShell 5.1 as SYSTEM, ActiveDirectory module.

    It deletes AT MOST ONE account, and refuses when:
      * no account or more than one account has that employeeID;
      * the account is not inside OU=Workforce or OU=Disabled at the domain
        root (the only OUs HR provisioning writes to: 02-Configure-Domain.ps1);
        Tier-0, PAM and service accounts live elsewhere;
      * the account is protected (adminCount = 1: a member, or former
        member, of a privileged group).

    Without -Apply yes it only reports what it found and what it would do.
    Downstream clean-up is automatic: Cloud Sync deletes the Entra user on
    its next cycle, and the AWS SCIM job follows.

.PARAMETER EmployeeId
    The worker id (hr_feed.csv employeeId = AD employeeID).

.PARAMETER Apply
    'yes' deletes. Anything else is a dry run. (Run-command parameters are
    strings, so this is not a switch.)

.EXAMPLE
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/Remove-DemoHire.ps1 --param EmployeeId=400104             # report only
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/Remove-DemoHire.ps1 --param EmployeeId=400104 --param Apply=yes
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EmployeeId,

    [Parameter()]
    [string]$Apply = 'no'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($EmployeeId -notmatch '^\d+$') { throw "EmployeeId must be the numeric worker id, not '$EmployeeId'." }
if (-not (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) { Import-Module ActiveDirectory }

$domainDn = (Get-ADDomain).DistinguishedName
$allowedBases = @("OU=Workforce,$domainDn", "OU=Disabled,$domainDn")

$found = @(Get-ADUser -Filter "employeeID -eq '$EmployeeId'" -Properties employeeID, adminCount, Enabled, ProtectedFromAccidentalDeletion)
if ($found.Count -eq 0) {
    Write-Output "No AD account has employeeID ${EmployeeId}: nothing to delete (already reset)."
    exit 0
}
if ($found.Count -gt 1) {
    Write-Output "REFUSED: $($found.Count) AD accounts share employeeID $EmployeeId. Delete the right one by hand; this script deletes one known account only."
    exit 1
}

$u = $found[0]
$dn = [string]$u.DistinguishedName
$inScope = @($allowedBases | Where-Object { $dn.EndsWith(",$_", [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
$ou = ($dn -split '(?<!\\),', 2)[1]
Write-Output "Found: $($u.Name) ($($u.SamAccountName)) in $ou, enabled=$($u.Enabled)"

if (-not $inScope) {
    Write-Output "REFUSED: the account is outside OU=Workforce / OU=Disabled, so HR provisioning did not create it there. Nothing deleted."
    exit 1
}
$adminCount = 0
if ($u.PSObject.Properties['adminCount'] -and $u.adminCount) { $adminCount = [int]$u.adminCount }
if ($adminCount -eq 1) {
    Write-Output 'REFUSED: the account is protected (adminCount=1: it is, or was, in a privileged group). Nothing deleted.'
    exit 1
}

if ($Apply -ne 'yes') {
    Write-Output "Dry run: would delete this account. Re-run with Apply=yes."
    exit 0
}
if ($u.PSObject.Properties['ProtectedFromAccidentalDeletion'] -and $u.ProtectedFromAccidentalDeletion) {
    Set-ADObject -Identity $dn -ProtectedFromAccidentalDeletion $false
}
Remove-ADUser -Identity $dn -Confirm:$false
Write-Output "Deleted $($u.SamAccountName). Cloud Sync removes the Entra user on its next cycle; AWS follows by SCIM."
exit 0
