<#
.SYNOPSIS
  Close the psPAS session. STATUS: BUILT, never run (no CyberArk tenant).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
Import-Module psPAS
if (Get-PASSession) { Close-PASSession; Write-Information 'Session closed.' -InformationAction Continue }
else { Write-Information 'No active session.' -InformationAction Continue }
