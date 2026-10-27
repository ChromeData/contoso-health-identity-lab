<#
.SYNOPSIS
    Installs and registers the Microsoft Entra provisioning agent (Cloud Sync)
    on DC01, unattended. Replaces the README's manual RDP step.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM through `az vm run-command invoke` (Windows
    PowerShell 5.1), after 02-Configure-Domain.ps1, which creates the KDS root
    key the agent's gMSA depends on. Follows Microsoft Learn, "Install the
    Microsoft Entra Connect cloud provisioning agent using a CLI and
    PowerShell".

      1. TLS 1.2 for the download and the agent registration.
      2. Download the installer from -InstallerUrl.
      3. REFUSE to run it unless its Authenticode signature is Valid and the
         signer is Microsoft Corporation. DC01 is Tier 0: nothing unsigned or
         third-party runs on it.
      4. Quiet install (skipped when the agent service already exists).
      5. Connect-AADCloudSyncAzureAD   (registers the agent with the tenant)
      6. Add-AADCloudSyncGMSA          (creates the agent's gMSA)
      7. Add-AADCloudSyncADDomain      (binds the agent to the forest)
      8. Restart the service and fail unless it is Running.

    The same agent serves Cloud Sync AND API-driven provisioning to AD.

    No public installer URL exists: Microsoft serves the package only from the
    Entra admin center (Entra Connect > Cloud sync > Agents > Download). Capture
    the URL there at run time and pass it in; the signature gate in step 3 is
    what makes that safe.

    Secrets: -HybridAdminPassword and -DomainAdminPassword arrive as PROTECTED
    parameters of a managed run command (lab/scripts/dc/run-on-dc.py; never
    returned by Azure, scrubbed from output). They are turned into
    SecureStrings at once and the plain copies are cleared.

    Known limit: Connect-AADCloudSyncAzureAD signs in with a password and has
    no device-code option. If that account must satisfy MFA the sign-in fails
    with an AADSTS error. Use an account scoped to Hybrid Identity
    Administrator for this one step.

.PARAMETER InstallerUrl
    HTTPS URL of the provisioning agent installer, captured from the Entra
    admin center.

.PARAMETER HybridAdminUpn
    Entra account holding at least Hybrid Identity Administrator.

.PARAMETER HybridAdminPassword
    Its password. Pass ONLY through --protected-parameters.

.PARAMETER DomainName
    The AD forest root, e.g. corp.contosohealthlab.com.

.PARAMETER DomainAdminUser
    A domain admin as DOMAIN\user, used to create the gMSA and bind the domain.

.PARAMETER DomainAdminPassword
    Its password. Pass ONLY through --protected-parameters.

.EXAMPLE
    # From the repo root, through the helper: the passwords are resolved from
    # the Keychain inside run-on-dc.py and sent as protected parameters of a
    # managed run command. Never put them on an az command line: the CLI
    # echoes rejected command lines, secrets included.
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/04-Install-CloudSyncAgent.ps1 `
      --param "InstallerUrl=$url" --param "HybridAdminUpn=svc-cloudsync@<tenant>.onmicrosoft.com" `
      --param "DomainName=corp.contosohealthlab.com" --param 'DomainAdminUser=CORP\contosoadmin' `
      --secret HybridAdminPassword=keychain:contoso-lab-cloudsync `
      --secret DomainAdminPassword=keychain:contoso-lab-dc01-admin
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'az vm run-command delivers parameters as strings. The passwords arrive as encrypted protected parameters and are converted to SecureString on the first line that touches them.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The only way to turn a run-command protected parameter into the PSCredential these cmdlets require. The plain copy is cleared immediately after.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
    Justification = 'Microsoft documents only credential-based sign-in for the unattended agent install.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'run-command captures the host stream as the step log.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^https://')] [string]$InstallerUrl,
    [Parameter(Mandatory)] [string]$HybridAdminUpn,
    [Parameter(Mandatory)] [string]$HybridAdminPassword,
    [Parameter(Mandatory)] [string]$DomainName,
    [Parameter(Mandatory)] [ValidatePattern('^[^\\]+\\[^\\]+$')] [string]$DomainAdminUser,
    [Parameter(Mandatory)] [string]$DomainAdminPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) { Write-Host ("[{0:u}] {1}" -f (Get-Date).ToUniversalTime(), $Message) }

# Secrets first: SecureString now, plain copies gone.
$hybridCred = New-Object System.Management.Automation.PSCredential -ArgumentList $HybridAdminUpn, (ConvertTo-SecureString $HybridAdminPassword -AsPlainText -Force)
$domainCred = New-Object System.Management.Automation.PSCredential -ArgumentList $DomainAdminUser, (ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force)
$HybridAdminPassword = $null
$DomainAdminPassword = $null

$serviceName = 'AADConnectProvisioningAgent'
$modulePath  = 'C:\Program Files\Microsoft Azure AD Connect Provisioning Agent\Microsoft.CloudSync.PowerShell.dll'

# 1. TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
    # 2. Download
    $workDir   = Join-Path $env:ProgramData 'ContosoLab\CloudSync'
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    $installer = Join-Path $workDir 'AADConnectProvisioningAgentSetup.exe'
    Write-Step 'Downloading the provisioning agent installer'
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $installer -UseBasicParsing

    # 3. Signature gate
    $sig = Get-AuthenticodeSignature -FilePath $installer
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        Remove-Item -LiteralPath $installer -Force
        throw "Refusing to run the installer: signature status '$($sig.Status)', signer '$($sig.SignerCertificate.Subject)'. Only a valid Microsoft Corporation signature is accepted on DC01."
    }
    Write-Step "Signature OK: $($sig.SignerCertificate.Subject)"

    # 4. Quiet install
    Write-Step 'Installing the agent (quiet)'
    $proc = Start-Process -FilePath $installer -ArgumentList '/quiet' -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) { throw "Installer exited with code $($proc.ExitCode)." }
}
else {
    Write-Step 'Agent service already present: skipping install'
}

if (-not (Test-Path -LiteralPath $modulePath)) { throw "Agent PowerShell module not found at $modulePath." }
Import-Module $modulePath

# 5-7. Register, gMSA, domain
Write-Step 'Registering the agent with Microsoft Entra ID'
Connect-AADCloudSyncAzureAD -Credential $hybridCred

Write-Step 'Creating the agent gMSA'
Add-AADCloudSyncGMSA -Credential $domainCred

Write-Step "Binding the agent to $DomainName"
Add-AADCloudSyncADDomain -DomainName $DomainName -Credential $domainCred

# 8. Restart and verify
Write-Step 'Restarting the agent service'
Restart-Service -Name $serviceName
Start-Sleep -Seconds 10
$status = (Get-Service -Name $serviceName).Status
if ($status -ne 'Running') { throw "Agent service is $status after restart." }
Write-Step "Agent service is Running. Next: Entra admin center > Cloud sync > Agents should show this agent as Healthy."
