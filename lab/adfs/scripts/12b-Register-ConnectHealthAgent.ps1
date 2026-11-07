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
      4. Read back, and THROW unless all of these hold (fail closed):
         - the agent's log has no "Result=failed" registration line;
         - the agent's registration marker (HKLM\SOFTWARE\Microsoft\
           ADHealthAgent, value TenantId: the same marker step 1 uses) is set;
         - the service AzureADConnectHealthAgent is Running (polled up to
           -WaitSeconds; it stays Stopped until registration succeeds,
           05b-agent-install.log).
         WHY: the cmdlet does not fail when registration fails. On DC01
         (2026-11-07, evidence 05d) it printed "Configuration Failed" and the
         run still ended with exit code 0. So "the cmdlet returned" proves
         nothing, and register.sh close must not run on a false success.
         Test-MicrosoftEntraConnectHealthConnectivity -Role ADFS is reported
         for information only (its output format is not documented).

.PARAMETER AgentToken
    The access token. PROTECTED parameter only (keychain:contoso-lab-connecthealth-token).

.PARAMETER WaitSeconds
    How long to wait for the agent service to reach Running after the
    registration (default 120).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to turn a protected run-command parameter into the SecureString -AadToken takes; the plain copy is cleared at once.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentToken,
    [ValidateRange(0, 600)][int]$WaitSeconds = 120
)

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
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $log) -Force
Write-Output "[connect-health] registering with -AadToken (log: $log)"
try {
    # Any text the cmdlet writes to the pipeline or error stream is kept for
    # the failure check (the log never holds the token).
    $regOut = (Register-MicrosoftEntraConnectHealthAgent -AadToken $sec -LogFilePath $log 2>&1 | Out-String)
} finally {
    $sec.Dispose()
}

# --- Read back: the cmdlet's return is NOT proof (see step 4 above) ---------
$problems = [Collections.Generic.List[string]]::new()
if ($regOut -match 'Configuration Failed') { $problems.Add('the cmdlet printed "Configuration Failed"') }
$logText = if ([IO.File]::Exists($log)) { [IO.File]::ReadAllText($log) } else { '' }
if (-not $logText) { $problems.Add("no agent log at $log") }
elseif ($logText -match 'Result=failed;type=registration') { $problems.Add('the agent log has a failed registration (Result=failed)') }

$regKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ADHealthAgent' -ErrorAction SilentlyContinue
if (-not ($regKey -and ($regKey.PSObject.Properties.Name -contains 'TenantId') -and "$($regKey.TenantId)")) {
    $problems.Add('no TenantId under HKLM\SOFTWARE\Microsoft\ADHealthAgent (the agent saved no registration)')
}

$deadline = (Get-Date).AddSeconds($WaitSeconds)
do {
    $svc = Get-Service AzureADConnectHealthAgent -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status.ToString() -eq 'Running') { break }
    Start-Sleep -Seconds 10
} while ((Get-Date) -lt $deadline)
$state = if ($svc) { $svc.Status.ToString() } else { 'missing' }
if ($state -ne 'Running') { $problems.Add("service AzureADConnectHealthAgent is $state, not Running") }

if ($problems.Count) {
    throw ("Connect Health registration NOT verified: {0}. Do not run register.sh close as a success; read {1}." -f ($problems -join '; '), $log)
}

$conn = (Test-MicrosoftEntraConnectHealthConnectivity -Role ADFS 2>&1 | Out-String).Trim()
[pscustomobject]@{
    registered   = $true
    tenantId     = "$($regKey.TenantId)"
    service      = $state
    connectivity = $conn
    log          = $log
} | ConvertTo-Json
