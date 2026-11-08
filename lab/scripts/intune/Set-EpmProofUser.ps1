<#
.SYNOPSIS
    EPM proof setup, runs ON CH-WIN11-01: a local STANDARD account and the one
    approved app, so a non-admin can ask Intune EPM to run it elevated.

.DESCRIPTION
    Called through lab/scripts/dc/run-on-dc.py --vm vm-win11-01 (a managed run
    command as SYSTEM; the password arrives as a protected parameter from the
    Mac's Keychain, never on a command line). ASCII only.

    1. Creates or resets the local account epm-standard. It must NOT be in the
       local Administrators group (the script removes it if it is, and fails
       if it still is): EPM proves nothing for an admin.
    2. Adds it to Remote Desktop Users, so it can sign in through Bastion.
    3. Downloads Sysinternals Process Explorer (procexp64.exe) from
       live.sysinternals.com to C:\Program Files\EPM-Proof\ (a folder standard
       users cannot modify, as Learn recommends for elevation rules) and
       prints its SHA-256.
       That hash goes into the EPM rule (New-IntuneEpmAndLaps.ps1 -FileHash).
    4. Reports whether the EPM agent is installed yet (service
       'Microsoft EPM Agent Service'; it arrives with the settings policy).

    -Remove yes deletes the account and the folder (cleanup).

.PARAMETER Password
    The local account's password (protected parameter; Keychain item
    contoso-lab-epm-standard).

.PARAMETER Remove
    'yes' removes the account and C:\Program Files\EPM-Proof instead.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to turn a protected run-command parameter into a local account password (same pattern as dc/tier-test/New-TierTestAccounts.ps1).')]
[CmdletBinding()]
param(
    [Parameter()][string]$Password = '',
    [Parameter()][string]$Remove = 'no'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$name = 'epm-standard'
$dir = 'C:\Program Files\EPM-Proof'
$adminsSid = 'S-1-5-32-544'
$rduSid = 'S-1-5-32-555'

if ($Remove -ceq 'yes') {
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $name; Write-Output "REMOVED: local account $name" }
    else { Write-Output "ABSENT: local account $name" }
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir; Write-Output "REMOVED: $dir" }
    exit 0
}

if ($Password.Length -lt 16) { throw 'A password of at least 16 characters is required (Keychain item contoso-lab-epm-standard).' }
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$Password = $null

$u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
if ($u) {
    Set-LocalUser -Name $name -Password $secure -PasswordNeverExpires $false
    Enable-LocalUser -Name $name
    Write-Output "RESET: local account $name (password from the Keychain)"
} else {
    New-LocalUser -Name $name -Password $secure -FullName 'EPM proof standard user' -Description 'Standard user for the Intune EPM proof (lab/scripts/intune, ADR 0036)' | Out-Null
    Write-Output "CREATED: local account $name"
}

$admins = Get-LocalGroup -SID $adminsSid
if (@(Get-LocalGroupMember -Group $admins | Where-Object { $_.Name -like "*\$name" }).Count -gt 0) {
    Remove-LocalGroupMember -Group $admins -Member $name
}
if (@(Get-LocalGroupMember -Group $admins | Where-Object { $_.Name -like "*\$name" }).Count -gt 0) { throw "$name is still a local administrator" }
Write-Output "CHECKED: $name is NOT in the local Administrators group"

$rdu = Get-LocalGroup -SID $rduSid
if (@(Get-LocalGroupMember -Group $rdu | Where-Object { $_.Name -like "*\$name" }).Count -eq 0) { Add-LocalGroupMember -Group $rdu -Member $name }
Write-Output "CHECKED: $name is in Remote Desktop Users"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = Join-Path $dir 'procexp64.exe'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri 'https://live.sysinternals.com/procexp64.exe' -OutFile $exe
$sig = Get-AuthenticodeSignature -FilePath $exe
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw "procexp64.exe signature is $($sig.Status) / $($sig.SignerCertificate.Subject): not using it" }
$hash = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
Write-Output "APP: $exe signed by Microsoft Corporation (Authenticode Valid)"
Write-Output "SHA256: $hash"

$svc = Get-Service -Name 'EPMAgentService', 'Microsoft EPM Agent Service' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $svc) { $svc = Get-Service | Where-Object { $_.DisplayName -like '*EPM Agent*' } | Select-Object -First 1 }
Write-Output ("EPM AGENT: " + $(if ($svc) { "$($svc.DisplayName) is $($svc.Status)" } else { 'not installed yet' }))
