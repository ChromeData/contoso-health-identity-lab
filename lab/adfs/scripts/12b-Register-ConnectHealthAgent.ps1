<#
.SYNOPSIS
    Registers the Microsoft Entra Connect Health agent for AD FS on DC01 with
    an access token from a PASSKEY sign-in (no person at the server). ADR 0031.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py), called by
    lab/adfs/connect-health/register.sh. Never run it by hand with a token
    on a command line.

    HOW. Register-MicrosoftEntraConnectHealthAgent in agent 4.5.2487.0 has a
    parameter set "-AadToken <SecureString>" (Get-Command -Syntax on DC01,
    2026-11-07). It is NOT described on Microsoft Learn, which documents only
    the interactive sign-in, -UserPrincipalName and -Credential. The token
    comes from get-agent-token.mjs: the agent's own client id and scope, an
    MFA (passkey) sign-in by the time-boxed Hybrid Identity Administrator
    adm-connecthealth-reg. Microsoft's documented alternative with no person
    (-Credential, a password-only account) cannot pass ARM's mandatory MFA,
    which the registration call goes through.

    Steps:
      1. Refuse if the agent is not installed or already registered (fail
         closed; re-registering is a deliberate act, not a retry).
      2. Turn the protected parameter into a SecureString at once.
      3. Register with -AadToken, log to a file (the log never holds the token).
      4. Read back: Test-MicrosoftEntraConnectHealthConnectivity -Role ADFS
         and the service state.

.PARAMETER AgentToken
    The access token. PROTECTED parameter only (keychain:contoso-lab-connecthealth-token).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to turn a protected run-command parameter into the SecureString -AadToken takes; the plain copy is cleared at once.')]
[CmdletBinding()]
param([Parameter(Mandatory)][string]$AgentToken)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sec = ConvertTo-SecureString $AgentToken -AsPlainText -Force
$AgentToken = $null

$mod = 'C:\Program Files\Microsoft Azure AD Connect Health Agent\Modules\AdHealthConfiguration'
if (-not (Test-Path $mod)) { throw 'The Connect Health agent is not installed (run 12-Install-ConnectHealthAgent.ps1).' }
Import-Module $mod
$cmd = Get-Command Register-MicrosoftEntraConnectHealthAgent
if (-not $cmd.Parameters.ContainsKey('AadToken')) { throw "This agent build has no -AadToken parameter ($($cmd.Module.Version)). Stop: ADR 0031 assumed agent 4.5.2487.0." }

$svc = Get-Service AzureADConnectHealthAgent -ErrorAction SilentlyContinue
$regKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ADHealthAgent' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running' -and $regKey -and ($regKey.PSObject.Properties.Name -contains 'TenantId')) {
    throw 'The agent is already registered and running. Refusing to register again.'
}

$log = Join-Path $env:ProgramData ("ContosoAdfs\connect-health-register-{0:yyyyMMddTHHmmssZ}.log" -f (Get-Date).ToUniversalTime())
Write-Output "[connect-health] registering with -AadToken (log: $log)"
Register-MicrosoftEntraConnectHealthAgent -AadToken $sec -LogFilePath $log
$sec.Dispose()

Start-Sleep -Seconds 20
$conn = (Test-MicrosoftEntraConnectHealthConnectivity -Role ADFS 2>&1 | Out-String).Trim()
$svc = Get-Service AzureADConnectHealthAgent -ErrorAction SilentlyContinue
[pscustomobject]@{
    registered   = $true
    service      = if ($svc) { $svc.Status.ToString() } else { 'missing' }
    connectivity = $conn
    log          = $log
} | ConvertTo-Json
