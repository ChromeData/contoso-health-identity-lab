<#
.SYNOPSIS
    Installs (does NOT register) the Microsoft Entra Connect Health agent for
    AD FS on DC01. Registration is a human step: README step 5.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py).

    Why the agent: Entra's "AD FS application activity" and "AD FS
    application migration" pages (Enterprise apps > Usage & insights) are fed
    ONLY by this agent. It reads the relying-party configuration and the AD
    FS sign-in audits and uploads them. Needs Entra ID P1 or P2 (the E5 trial
    has it). Microsoft Learn, "Install the Microsoft Entra Connect Health
    agents" and "AD FS application migration", checked 2026-11-07.

    Why registration is NOT scripted: Register-MicrosoftEntraConnectHealthAgent
    signs in as a Global Administrator or Hybrid Identity Administrator. With
    -Credential it needs an account "which does not have multifactor
    authentication enabled" (same Learn page). In this tenant CA001 requires
    MFA for every user except the two break-glass accounts. So an unattended
    password-only registration is refused, and break-glass accounts are not
    for routine work. The interactive form (no -Credential) opens a Microsoft
    sign-in window on the server, where an admin completes MFA. That needs an
    RDP session and a person.

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

# The Connect Health AD FS agent's Windows services. Older agents install
# AdHealthAdfs* services; the current agent installs ONE service,
# AzureADConnectHealthAgent (seen on DC01, PR #237 install record). Check
# both, so neither version reads as "not installed". The same function is in
# 12-Install-ConnectHealthAgent.ps1 and 19-Remove-Adfs.ps1 (run-on-dc.py
# sends one file); lab/adfs/tests/ConnectHealth.Tests.ps1 keeps them equal.
function Get-ConnectHealthAdfsService {
    @(Get-Service -Name 'AdHealthAdfs*', 'AzureADConnectHealthAgent' -ErrorAction SilentlyContinue)
}

if (-not (Get-Service adfssrv -ErrorAction SilentlyContinue)) { throw 'AD FS is not installed. Run 10-Install-Adfs.ps1 first.' }
if ($InstallerUrl -notlike 'https://*') { throw 'InstallerUrl must be https.' }

if ((Get-ConnectHealthAdfsService).Count -eq 0) {
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
    $p = Start-Process -FilePath $exe -ArgumentList '/quiet' -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Installer exit code $($p.ExitCode)." }
} else { Write-Step 'agent already installed' }

$services = Get-ConnectHealthAdfsService | ForEach-Object { [pscustomobject]@{ name = $_.Name; status = $_.Status.ToString() } }
# A registered agent keeps its identity under this key (verify: the value
# name; the script reports, it does not decide on it).
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ADHealthAgent' -ErrorAction SilentlyContinue
[pscustomobject]@{
    installed  = $true
    services   = $services
    registered = [bool]($reg -and ($reg.PSObject.Properties.Name -contains 'TenantId'))
    next       = 'README step 5: RDP to DC01, run Register-MicrosoftEntraConnectHealthAgent, sign in as a Hybrid Identity Administrator with MFA.'
} | ConvertTo-Json -Depth 4
