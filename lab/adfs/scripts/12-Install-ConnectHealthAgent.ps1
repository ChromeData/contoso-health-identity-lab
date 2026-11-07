<#
.SYNOPSIS
    Installs (does NOT register) the Microsoft Entra Connect Health agent for
    AD FS on DC01. Registration is README step 5b (ADR 0031).

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py).

    Why the agent: Entra's "AD FS application activity" and "AD FS
    application migration" pages (Enterprise apps > Usage & insights) are fed
    ONLY by this agent. It reads the relying-party configuration and the AD
    FS sign-in audits and uploads them. Needs Entra ID P1 or P2 (the E5 trial
    has it). Microsoft Learn, "Install the Microsoft Entra Connect Health
    agents" and "AD FS application migration", checked 2026-11-07.

    Why registration is a separate step: Register-MicrosoftEntraConnectHealthAgent
    signs in as a Global Administrator or Hybrid Identity Administrator.
    Learn's unattended form (-Credential, an account "which does not have
    multifactor authentication enabled") cannot work here: the agent
    registers through Azure Resource Manager, which requires MFA for user
    creates whatever Conditional Access says. So registration is
    12b-Register-ConnectHealthAgent.ps1, fed a passkey-MFA token by
    lab/adfs/connect-health/register.sh (ADR 0031), or a person at the server.

    Steps:
      1. TLS 1.2. Download from Microsoft's published link (default below).
      2. REFUSE unless the Authenticode signature is Valid and the signer is
         Microsoft Corporation (DC01 is Tier 0).
      3. Quiet install (skipped if the agent service already exists).
      4. Report the services and whether the agent is registered.

.PARAMETER InstallerUrl
    Default: https://go.microsoft.com/fwlink/?LinkID=518973 (the Connect
    Health AD FS agent link on the Learn "AD FS application migration" page).
#>
[CmdletBinding()]
param(
    [string]$InstallerUrl = 'https://go.microsoft.com/fwlink/?LinkID=518973'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step([string]$Message) { Write-Output ("[connect-health] {0}" -f $Message) }

if (-not (Get-Service adfssrv -ErrorAction SilentlyContinue)) { throw 'AD FS is not installed. Run 10-Install-Adfs.ps1 first.' }
if ($InstallerUrl -notlike 'https://*') { throw 'InstallerUrl must be https.' }

# Agent 3.x installs AdHealthAdfs* services; 4.x may name them
# AzureADConnectHealth*. Either one means the agent is installed.
$svcPattern = @('AdHealthAdfs*', 'AzureADConnectHealth*')
if (-not (Get-Service $svcPattern -ErrorAction SilentlyContinue)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $dir = Join-Path $env:ProgramData 'ContosoAdfs'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $exe = Join-Path $dir 'AdHealthAdfsAgentSetup.exe'
    Write-Step "downloading $InstallerUrl"
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $exe -UseBasicParsing

    $sig = Get-AuthenticodeSignature -FilePath $exe
    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    if ($sig.Status -ne 'Valid' -or $signer -notmatch 'O=Microsoft Corporation') {
        Remove-Item $exe -Force
        throw "Refusing the installer: signature '$($sig.Status)', signer '$signer'."
    }
    Write-Step "signature Valid ($signer); installing quietly"
    # AdfsMonitoringEnabled=1: without a monitored role the MSI's launch
    # condition stops with "Please select at least one service" (exit 1603,
    # seen on DC01 2026-11-07 with agent 4.5.2487.0). SkipRegistration=1: the
    # bundle would otherwise try to sign in during setup; registration is its
    # own step (README step 5). Same switches as Learn's quiet AD DS install.
    $p = Start-Process -FilePath $exe -ArgumentList '/quiet', 'AdfsMonitoringEnabled=1', 'SkipRegistration=1' -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Installer exit code $($p.ExitCode)." }
} else { Write-Step 'agent already installed' }

$services = Get-Service $svcPattern -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ name = $_.Name; status = $_.Status.ToString() } }
# A registered agent keeps its identity under this key (verify: the value
# name; the script reports, it does not decide on it).
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ADHealthAgent' -ErrorAction SilentlyContinue
[pscustomobject]@{
    installed  = $true
    services   = $services
    registered = [bool]($reg -and ($reg.PSObject.Properties.Name -contains 'TenantId'))
    next       = 'README step 5b: lab/adfs/connect-health/register.sh (ADR 0031), after the flag-on PR is applied.'
} | ConvertTo-Json -Depth 4
