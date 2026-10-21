<#
.SYNOPSIS
    Phase 1 of the DC build: prepares the NTDS data disk, generates a DSRM
    password straight into Key Vault, installs AD DS + DNS and creates the
    corp forest. Reboot required afterwards (done by the caller).

.DESCRIPTION
    Runs ON the DC VM as SYSTEM via `az vm run-command invoke` (Windows
    PowerShell 5.1). See README.md in this folder for the exact commands.

    SECRET HANDLING
      The Directory Services Restore Mode password is generated here with a
      CSPRNG and written to Key Vault using the VM's managed identity over the
      vault's private endpoint. It is never printed, never passed as a
      run-command parameter (those are visible in the VM's run-command
      history), and never seen by a human or the pipeline. If the vault write
      fails, the script stops BEFORE promotion - a DC with an unknown DSRM
      password is not acceptable.

    IDEMPOTENT: if the machine is already a domain controller, it exits 0. If
    a promotion is already staged and only the reboot is pending, it also
    exits 0 WITHOUT generating a new DSRM password, so Key Vault keeps the
    one that was actually staged.

.PARAMETER DomainName
    FQDN of the new forest root, e.g. corp.contosohealthlab.com.

.PARAMETER NetbiosName
    NetBIOS name, e.g. CORP.

.PARAMETER KeyVaultName
    Lab Key Vault name (terraform output key_vault_uri / modules/keyvault).

.PARAMETER DsrmSecretName
    Key Vault secret name for the DSRM password. Default dc01-dsrm-password.
    It must match local.dc_kv_secret_names in lab/terraform/modules/dc-vm/main.tf:
    the VM identity's ABAC condition refuses any other name, so a different
    value fails loudly after the 10-minute Key Vault retry window.
#>
#Requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The password is generated in-memory by this script, stored in Key Vault, and must be handed to an AD cmdlet as a SecureString. It never exists outside process memory.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Write-Step logs to the host so log lines never become part of a function return value (as in 02-Configure-Domain.ps1); powershell.exe -File still sends host output to the stdout that run-command captures.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$DomainName,
    [Parameter(Mandatory)] [string]$NetbiosName,
    [Parameter(Mandatory)] [string]$KeyVaultName,
    [string]$DsrmSecretName = 'dc01-dsrm-password'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step([string]$Message) { Write-Host ("[{0:u}] {1}" -f (Get-Date).ToUniversalTime(), $Message) }

function New-StrongPassword([int]$Length = 32) {
    # CSPRNG; guarantees upper/lower/digit/symbol so AD complexity always passes.
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!#%*()-_=+[]{}:?')
    $all = -join $sets
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] ($Length)
    $rng.GetBytes($bytes)
    $chars = New-Object System.Collections.Generic.List[char]
    for ($i = 0; $i -lt $Length; $i++) {
        $set = if ($i -lt $sets.Count) { $sets[$i] } else { $all }
        $chars.Add($set[$bytes[$i] % $set.Length])
    }
    # Fisher-Yates shuffle with fresh random bytes.
    $shuffle = New-Object byte[] ($Length)
    $rng.GetBytes($shuffle)
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = $shuffle[$i] % ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

function Set-KeyVaultSecret([string]$Vault, [string]$Name, [string]$Value) {
    # Managed identity token from IMDS, then a data-plane PUT. The vault FQDN
    # resolves to the private endpoint through the VNet-linked private DNS zone.
    $deadline = (Get-Date).AddMinutes(10)   # role assignments can take minutes to propagate
    while ($true) {
        try {
            $tok = Invoke-RestMethod -Headers @{ Metadata = 'true' } -UseBasicParsing `
                -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net'
            $body = @{ value = $Value; contentType = 'text/plain' } | ConvertTo-Json -Compress
            Invoke-RestMethod -Method Put -UseBasicParsing -ContentType 'application/json' `
                -Headers @{ Authorization = "Bearer $($tok.access_token)" } `
                -Uri "https://$Vault.vault.azure.net/secrets/$Name`?api-version=7.4" -Body $body | Out-Null
            return
        }
        catch {
            if ((Get-Date) -gt $deadline) { throw "Key Vault write for '$Name' failed: $($_.Exception.Message)" }
            Write-Step "Key Vault not writable yet ($($_.Exception.Message)); retrying in 30s..."
            Start-Sleep -Seconds 30
        }
    }
}

# ---------------------------------------------------------------------------
# 0. Already a DC? (DomainRole 4 = backup DC, 5 = primary DC)
# ---------------------------------------------------------------------------
$role = (Get-CimInstance Win32_ComputerSystem).DomainRole
if ($role -ge 4) {
    Write-Step "Already a domain controller (DomainRole=$role). Nothing to do."
    exit 0
}

# DomainRole only changes at the reboot. A re-run before `az vm restart`
# would overwrite the DSRM secret in step 2 and then have its promotion
# refused (dcpromo exit 15, role change pending), leaving Key Vault without
# the password that is actually staged. Ask the DS role service directly.
# verify: state is 2 (NeedReboot) after Install-ADDSForest -NoRebootOnCompletion.
Add-Type -Namespace ContosoLab -Name DsRole -MemberDefinition @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
static extern int DsRoleGetPrimaryDomainInformation(string server, int level, out IntPtr buffer);
[DllImport("netapi32.dll")]
static extern void DsRoleFreeMemory(IntPtr buffer);
// Level 3 = DsRoleOperationState: 0 idle, 1 active, 2 needs reboot (dsrole.h).
public static int OperationState() {
    IntPtr buf;
    int rc = DsRoleGetPrimaryDomainInformation(null, 3, out buf);
    if (rc != 0) { throw new System.ComponentModel.Win32Exception(rc); }
    try { return Marshal.ReadInt32(buf); } finally { DsRoleFreeMemory(buf); }
}
'@
try { $opState = [ContosoLab.DsRole]::OperationState() }
catch { throw "Cannot read the DS role operation state, so not touching the DSRM secret: $($_.Exception.Message)" }
if ($opState -eq 2) {
    Write-Step 'Promotion already staged; only the reboot is pending. DSRM secret left as staged. Restart the VM now (az vm restart).'
    exit 0
}
if ($opState -ne 0) { throw "A role change is in progress (DS role operation state $opState). Wait for it to finish, then re-run." }

# ---------------------------------------------------------------------------
# 1. NTDS data disk -> F: (host caching None is set on the Azure side)
# ---------------------------------------------------------------------------
if (-not (Get-Volume -DriveLetter F -ErrorAction SilentlyContinue)) {
    $raw = Get-Disk | Where-Object PartitionStyle -eq 'RAW' | Sort-Object Number | Select-Object -First 1
    if (-not $raw) { throw 'No RAW data disk found for NTDS (expected the 8 GiB LUN 0 disk).' }
    Write-Step "Initializing disk $($raw.Number) as F: (NTDS)"
    Initialize-Disk -Number $raw.Number -PartitionStyle GPT
    New-Partition -DiskNumber $raw.Number -UseMaximumSize -DriveLetter F |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel 'NTDS' -Confirm:$false | Out-Null
}
else { Write-Step 'F: already present.' }

# ---------------------------------------------------------------------------
# 2. DSRM password -> Key Vault (before promotion, or not at all)
# ---------------------------------------------------------------------------
Write-Step "Generating DSRM password and storing it in Key Vault '$KeyVaultName' as '$DsrmSecretName'"
$dsrm = New-StrongPassword 32
Set-KeyVaultSecret -Vault $KeyVaultName -Name $DsrmSecretName -Value $dsrm
Write-Step 'DSRM password stored (value not displayed).'

# ---------------------------------------------------------------------------
# 3. Roles + forest
# ---------------------------------------------------------------------------
Write-Step 'Installing AD-Domain-Services + DNS'
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools | Out-Null

Write-Step "Creating forest $DomainName ($NetbiosName)"
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -SafeModeAdministratorPassword (ConvertTo-SecureString $dsrm -AsPlainText -Force) `
    -DatabasePath 'F:\NTDS' -LogPath 'F:\NTDS' -SysvolPath 'F:\SYSVOL' `
    -InstallDns -DomainMode WinThreshold -ForestMode WinThreshold `
    -NoRebootOnCompletion -Force | Out-Null
$dsrm = $null

Write-Step 'Promotion staged. Restart the VM now (az vm restart), then run 02-Configure-Domain.ps1.'
