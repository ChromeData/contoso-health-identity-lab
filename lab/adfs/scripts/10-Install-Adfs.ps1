<#
.SYNOPSIS
    Installs a one-server AD FS farm on DC01 for the AD FS -> Entra migration
    exercise (lab/adfs/README.md). Temporary: 19-Remove-Adfs.ps1 takes it out.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM through a managed run command
    (lab/scripts/dc/run-on-dc.py, Windows PowerShell 5.1).

    WHY ON DC01 AND NOT A SEPARATE VM. The lab subscription is an Azure Free
    Trial (quotaId FreeTrial_2014-09-01). Its regional vCPU quota in eastus2
    is 4, and DC01 + the Intune VM (2 x Standard_D2als_v7) already use all 4
    (az vm list-usage, read 2026-11-07). The trial cannot raise the quota, and
    eastus2 offers no B-series to this subscription. So a member server is not
    possible without deleting another VM. AD FS on a domain controller is a
    supported install since Windows Server 2012 R2 (AD FS no longer needs
    IIS). It is still Tier 0 on Tier 0: AD FS holds a token-signing key that
    can mint a sign-in for any user (Golden SAML), so it belongs in the same
    tier as the DC.

    THIS IS A LAB SHORTCUT, NOT THE PRODUCTION DESIGN. Production uses a
    dedicated AD FS server (in practice a farm of two or more), never a
    domain controller, with a Web Application Proxy in front of it for
    internet sign-ins. The lab puts AD FS on DC01 only because the trial
    has no room for another VM. The script prints this line on every run.

    Steps (each is idempotent: a re-run skips what already exists):
      1. Guard: this computer is a domain controller of -DomainName.
      2. Guard: nothing else owns 0.0.0.0:443 (AD FS binds HTTP.sys there).
      3. Install-WindowsFeature ADFS-Federation.
      4. DNS: an A record for the federation service name -> this DC.
      5. TLS certificate for the federation service name (self-signed, 90
         days, key not exportable). Why not the lab CA: the WebServer template
         is not enrollable by DC01$, and the only clients of this endpoint are
         this DC's own test script and the operator's pinned test browser.
      6. Install-AdfsFarm with a gMSA (gmsa-adfs) and the Windows Internal
         Database. AD FS creates the gMSA when it does not exist; the KDS root
         key from 02-Configure-Domain.ps1 makes that possible.
      7. Auditing for Microsoft Entra Connect Health: AD FS audit level
         Verbose, and the "Application Generated" audit subcategory on.
      8. Check that the AD FS service account holds "Generate security
         audits" (SeAuditPrivilege). On a DC that right comes from the Default
         Domain Controllers Policy, which normally lists only LOCAL SERVICE and
         NETWORK SERVICE. Without it AD FS writes no Security-log audits and
         Connect Health sees no sign-ins. The script REPORTS this; it does not
         edit the GPO (a Tier-0 GPO change is the owner's call, README step 3b).

    Secret: -DomainAdminPassword arrives as a PROTECTED parameter
    (run-on-dc.py). It becomes a SecureString at once.

.PARAMETER DomainName
    The AD forest root, e.g. corp.contosohealthlab.com.

.PARAMETER FederationServiceName
    DNS name of the federation service. Default sts.<DomainName>.

.PARAMETER DomainAdminUser
    A domain admin as DOMAIN\user. Install-AdfsFarm needs one to create the
    DKM container (the AD object that protects the AD FS signing keys).

.PARAMETER DomainAdminPassword
    Its password. Pass ONLY as a protected parameter.

.EXAMPLE
    lab/scripts/dc/run-on-dc.py lab/adfs/scripts/10-Install-Adfs.ps1 \
      --param DomainName=corp.contosohealthlab.com \
      --param 'DomainAdminUser=CORP\contosoadmin' \
      --secret DomainAdminPassword=keychain:contoso-lab-dc01-admin
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '',
    Justification = 'Run-command parameters arrive as strings. The password is a protected parameter (run-on-dc.py) and becomes a SecureString on the first line that touches it.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The only way to turn a run-command protected parameter into the SecureString/PSCredential these cmdlets need. The plain copy is cleared right after.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [string]$FederationServiceName = '',
    [Parameter(Mandatory)][string]$DomainAdminUser,
    [Parameter(Mandatory)][string]$DomainAdminPassword,
    [string]$GmsaName = 'gmsa-adfs'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $FederationServiceName) { $FederationServiceName = "sts.$DomainName" }

function Write-Step([string]$Message) { Write-Output ("[adfs-install] {0}" -f $Message) }

Write-Step 'LAB SHORTCUT: AD FS goes on this domain controller only because the Azure trial has no room for another VM. Production uses a dedicated AD FS server (a farm of two or more) behind a Web Application Proxy, never a domain controller.'

# --- 1. This must be a DC of the named domain ---------------------------------
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.DomainRole -lt 4) { throw "Not a domain controller (DomainRole $($cs.DomainRole)). This script is for DC01 only." }
if ($cs.Domain -ne $DomainName) { throw "This DC is in '$($cs.Domain)', not '$DomainName'." }

$sec = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
$DomainAdminPassword = $null
$cred = New-Object System.Management.Automation.PSCredential ($DomainAdminUser, $sec)

# --- 2. Port 443 must be free (or already AD FS's) ----------------------------
$adfsInstalled = [bool](Get-Service adfssrv -ErrorAction SilentlyContinue)
if (-not $adfsInstalled) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue
    if ($listeners) {
        $owners = ($listeners | ForEach-Object { (Get-Process -Id $_.OwningProcess).ProcessName } | Sort-Object -Unique) -join ', '
        # HTTP.sys (System, pid 4) can share 443 by host name; anything else cannot.
        if ($owners -ne 'System') { throw "Port 443 is already used by: $owners. Stop: AD FS needs it." }
    }
}

# --- 3. Role ------------------------------------------------------------------
if (-not (Get-WindowsFeature ADFS-Federation).Installed) {
    Write-Step 'installing the ADFS-Federation role'
    $r = Install-WindowsFeature ADFS-Federation -IncludeManagementTools
    if (-not $r.Success) { throw 'Install-WindowsFeature ADFS-Federation failed.' }
} else { Write-Step 'ADFS-Federation role already installed' }

# --- 4. DNS -------------------------------------------------------------------
$dcIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
$label = $FederationServiceName -replace "\.$([regex]::Escape($DomainName))$", ''
if ($label -eq $FederationServiceName) { throw "FederationServiceName must be inside the AD DNS zone $DomainName (e.g. sts.$DomainName)." }
if (-not (Get-DnsServerResourceRecord -ZoneName $DomainName -Name $label -RRType A -ErrorAction SilentlyContinue)) {
    Write-Step "DNS A $FederationServiceName -> $dcIp"
    Add-DnsServerResourceRecordA -ZoneName $DomainName -Name $label -IPv4Address $dcIp
}

# --- 5. TLS certificate -------------------------------------------------------
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.Subject -eq "CN=$FederationServiceName" -and $_.NotAfter -gt (Get-Date).AddDays(7) -and $_.HasPrivateKey
} | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) {
    Write-Step "self-signed TLS certificate for $FederationServiceName (90 days)"
    $cert = New-SelfSignedCertificate -DnsName $FederationServiceName -CertStoreLocation Cert:\LocalMachine\My `
        -KeyExportPolicy NonExportable -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(90) -FriendlyName 'Contoso lab AD FS (temporary, migration exercise)'
}
# This DC's own test script (13-Get-AdfsClaims.ps1) must trust it.
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$rootStore.Open('ReadWrite')
if (-not ($rootStore.Certificates | Where-Object Thumbprint -eq $cert.Thumbprint)) {
    $pub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $cert.RawData)
    $rootStore.Add($pub)
}
$rootStore.Close()

# --- 6. Farm ------------------------------------------------------------------
$configured = $false
if ($adfsInstalled) { try { $null = Get-AdfsProperties; $configured = $true } catch { $configured = $false } }
if (-not $configured) {
    Write-Step "Install-AdfsFarm $FederationServiceName (gMSA $GmsaName, WID)"
    $netbios = (Get-ADDomain).NetBIOSName
    Install-AdfsFarm -CertificateThumbprint $cert.Thumbprint `
        -FederationServiceName $FederationServiceName `
        -FederationServiceDisplayName 'Contoso Health (lab AD FS, temporary)' `
        -GroupServiceAccountIdentifier "$netbios\$GmsaName`$" `
        -Credential $cred -OverwriteConfiguration:$false | Out-Null
} else { Write-Step 'AD FS farm already configured' }

# --- 7. Auditing --------------------------------------------------------------
Set-AdfsProperties -AuditLevel Verbose
$null = & auditpol.exe /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) { throw "auditpol failed ($LASTEXITCODE)." }   # GUID = "Application Generated" (locale-independent)

# --- 8. SeAuditPrivilege check -----------------------------------------------
$gmsaSid = (Get-ADServiceAccount $GmsaName).SID.Value
$tmp = Join-Path $env:TEMP ("secpol-{0}.inf" -f [guid]::NewGuid())
$null = & secedit.exe /export /areas USER_RIGHTS /cfg $tmp
$line = (Get-Content $tmp | Where-Object { $_ -like 'SeAuditPrivilege*' })
Remove-Item $tmp -Force
# secedit writes most accounts as *SID but some by name (DC01 2026-11-07
# showed "gmsa-adfs$" after step 3b): accept either form.
$items = @(("$line" -split '=', 2)[-1].Split(',') | ForEach-Object { $_.Trim() })
$hasAudit = [bool](($items -contains "*$gmsaSid") -or ($items -contains "$GmsaName`$"))

$svc = Get-Service adfssrv
$props = Get-AdfsProperties
[pscustomobject]@{
    federationService   = $props.HostName
    identifier          = $props.Identifier.AbsoluteUri
    serviceState        = $svc.Status.ToString()
    tlsThumbprint       = $cert.Thumbprint
    auditLevel          = (@($props.AuditLevel) -join ',')   # an array (e.g. Verbose); ToString() printed the type name
    gmsaHasSeAudit      = $hasAudit
    metadataUrl         = "https://$FederationServiceName/FederationMetadata/2007-06/FederationMetadata.xml"
} | ConvertTo-Json
if (-not $hasAudit) {
    Write-Output "[adfs-install] WARNING: $GmsaName`$ does not hold 'Generate security audits'. AD FS will not write sign-in audits, so Connect Health and the migration report see nothing. Do README step 3b."
}
