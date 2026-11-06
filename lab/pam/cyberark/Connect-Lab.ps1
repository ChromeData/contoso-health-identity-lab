<#
.SYNOPSIS
  Open a psPAS session to a self-hosted CyberArk PVWA (CyberArk, LDAP or RADIUS logon).

.DESCRIPTION
  STATUS: BUILT, never run: the lab has no CyberArk tenant. The credential is
  prompted for (Get-Credential) and never written to disk, a log or argv.
  psPAS 8.2.0: New-PASSession -BaseURI -Credential -type
  (psPAS/Public/Authentication/New-PASSession.ps1).

.PARAMETER BaseUri
  The PVWA address, for example https://pvwa.example.org. (Privilege Cloud on Shared
  Services signs in through Identity with other New-PASSession parameters; not covered.)
.PARAMETER AuthType
  CyberArk, LDAP or RADIUS (what the vault is set up for).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaseUri,
    [ValidateSet('CyberArk', 'LDAP', 'RADIUS')][string]$AuthType = 'CyberArk'
)
$ErrorActionPreference = 'Stop'
Import-Module psPAS
$cred = Get-Credential -Message 'CyberArk credentials (never stored)'
New-PASSession -BaseURI $BaseUri -Credential $cred -type $AuthType
Write-Information "Connected to $BaseUri as $($cred.UserName). Next: ./Invoke-SafeReconcile.ps1" -InformationAction Continue
