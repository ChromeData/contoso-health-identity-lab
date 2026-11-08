<#
.SYNOPSIS
    Phase 2 of the DC build (after the post-promotion reboot): DNS forwarder,
    UPN suffix, OU structure, KDS root key, AD CS (LDAPS), and the privileged
    accounts the PAM stand-ins manage. Idempotent.

.DESCRIPTION
    Runs ON the DC as SYSTEM via `az vm run-command invoke` (Windows PowerShell
    5.1). SYSTEM on a domain controller has full directory rights.

    WHAT IT BUILDS
      DNS        forwarder -> 168.63.129.16 (Azure DNS) so the DC still resolves
                 the vault's privatelink zone after it became its own DNS server
      UPN        suffix <UpnSuffix> so HR-provisioned users get
                 given.surname@<custom domain> UPNs that Cloud Sync can match
      OUs        Workforce\<one per HR department>, Disabled, ServiceAccounts,
                 PrivilegedAccounts (all protected from accidental deletion)
      KDS key    required for the gMSA the Entra provisioning agent creates
      AD CS      Enterprise Root CA -> the DC auto-enrolls a certificate ->
                 LDAPS on 636 (Vault's LDAP secrets engine only talks LDAPS)
      Accounts   svc-vault-rotator  Vault's bind/reconcile account (CPM role)
                 svc-pam-discovery  READ-ONLY bind for lab/pam/discover.sh (plain
                                    Domain User: discovery must never run as
                                    the Tier-0 rotator)
                 svc-backup         Vault STATIC role (scheduled rotation)
                 tier0-admin-01/02  Vault LIBRARY set (exclusive check-out),
                                    members of Domain Admins - the privileged
                                    sessions Guacamole records (PSM role)

    THE RECONCILE-ACCOUNT TRADE-OFF (say this on camera)
      tier0-admin-0x are Domain Admins, so AdminSDHolder/SDProp overwrites any
      OU-level delegation on them. For Vault to rotate them, svc-vault-rotator
      gets Reset Password on AdminSDHolder itself - exactly what any PAM
      reconcile account needs. That makes svc-vault-rotator effectively Tier 0:
      its password is generated here, stored ONLY in Key Vault, and should be
      rotated by Vault itself (vault write -f ldap/rotate-root) once onboarded.

    SECRETS
      svc-vault-rotator's password -> Key Vault secret 'svc-vault-rotator'.
      svc-pam-discovery's password -> Key Vault secret 'svc-pam-discovery'
      (read by discover.sh from stdin, never a command-line argument).
      svc-backup and tier0-admin-0x get random passwords that are NOT stored:
      Vault rotates them on onboarding and becomes the only holder. (If Vault
      onboarding fails, reset them in ADUC - nothing is lost but a password.)

.PARAMETER KeyVaultName
    Lab Key Vault name.

.PARAMETER UpnSuffix
    The verified custom domain, e.g. contosohealthlab.com.

.PARAMETER Departments
    One OU per HR department (must match hr_feed.csv 'dept' values).
#>
#Requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The password is generated in-memory by this script, stored in Key Vault, and must be handed to an AD cmdlet as a SecureString. It never exists outside process memory.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Write-Step logs to the host so log lines never become part of Confirm-OU / Confirm-User return values; powershell.exe -File still sends host output to the stdout that run-command captures.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$KeyVaultName,
    [Parameter(Mandatory)] [string]$UpnSuffix,
    [string[]]$Departments = @('Nursing', 'ICU', 'Radiology', 'Billing', 'Administration', 'Information Technology')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Host stream, NOT Write-Output: anything on the success stream inside Confirm-OU /
# Confirm-User would be returned with the DN / hashtable and corrupt the caller's value.
function Write-Step([string]$Message) { Write-Host ("[{0:u}] {1}" -f (Get-Date).ToUniversalTime(), $Message) }

function New-StrongPassword([int]$Length = 32) {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!#%*()-_=+[]{}:?')
    $all = -join $sets
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] ($Length); $rng.GetBytes($bytes)
    $chars = New-Object System.Collections.Generic.List[char]
    for ($i = 0; $i -lt $Length; $i++) {
        $set = if ($i -lt $sets.Count) { $sets[$i] } else { $all }
        $chars.Add($set[$bytes[$i] % $set.Length])
    }
    $shuffle = New-Object byte[] ($Length); $rng.GetBytes($shuffle)
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = $shuffle[$i] % ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

function Set-KeyVaultSecret([string]$Vault, [string]$Name, [string]$Value) {
    $deadline = (Get-Date).AddMinutes(10)
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

function Confirm-OU([string]$Name, [string]$Path) {
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
        Write-Step "  + OU $dn"
    }
    return $dn
}

function Confirm-User([string]$Sam, [string]$Path, [string]$Description) {
    $u = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if ($u) { Write-Step "  = $Sam exists"; return @{ User = $u; Password = $null } }
    $pw = New-StrongPassword 32
    New-ADUser -Name $Sam -SamAccountName $Sam -UserPrincipalName "$Sam@$((Get-ADDomain).DNSRoot)" `
        -Path $Path -Description $Description -Enabled $true -PasswordNeverExpires $true `
        -CannotChangePassword $true -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
    Write-Step "  + $Sam"
    return @{ User = (Get-ADUser $Sam); Password = $pw }
}

# ---------------------------------------------------------------------------
# 0. Wait for AD Web Services after the reboot
# ---------------------------------------------------------------------------
Import-Module ActiveDirectory
$deadline = (Get-Date).AddMinutes(10)
while ($true) {
    try { $domain = Get-ADDomain; break }
    catch {
        if ((Get-Date) -gt $deadline) { throw "AD not ready: $($_.Exception.Message)" }
        Start-Sleep -Seconds 20
    }
}
$base = $domain.DistinguishedName
$netbios = $domain.NetBIOSName
Write-Step "Domain $($domain.DNSRoot) ($base)"

# ---------------------------------------------------------------------------
# 1. DNS: loopback on the adapter + forward to Azure DNS (private zones)
# ---------------------------------------------------------------------------
$fwd = @(Get-DnsServerForwarder).IPAddress | ForEach-Object { $_.IPAddressToString }
if ('168.63.129.16' -notin $fwd) { Set-DnsServerForwarder -IPAddress '168.63.129.16' -PassThru | Out-Null; Write-Step 'DNS forwarder -> 168.63.129.16' }
$nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses '127.0.0.1'
Resolve-DnsName "$KeyVaultName.vault.azure.net" -ErrorAction Stop | Out-Null
Write-Step "Vault FQDN resolves through the DC (private endpoint path intact)"

# ---------------------------------------------------------------------------
# 2. UPN suffix for workforce users
# ---------------------------------------------------------------------------
if ($UpnSuffix -notin (Get-ADForest).UPNSuffixes) {
    Set-ADForest -Identity (Get-ADForest) -UPNSuffixes @{ Add = $UpnSuffix }
    Write-Step "UPN suffix $UpnSuffix added"
}

# ---------------------------------------------------------------------------
# 3. OUs
# ---------------------------------------------------------------------------
$workforce = Confirm-OU 'Workforce' $base
$deptOus = @{}
foreach ($d in $Departments) { $deptOus[$d] = Confirm-OU $d $workforce }
$disabledOu = Confirm-OU 'Disabled' $base
$svcOu = Confirm-OU 'ServiceAccounts' $base
$privOu = Confirm-OU 'PrivilegedAccounts' $base

# ---------------------------------------------------------------------------
# 4. KDS root key (gMSA for the Entra provisioning agent)
# ---------------------------------------------------------------------------
if (-not (Get-KdsRootKey)) {
    # Backdated so it is usable immediately in a single-DC lab (production:
    # let it replicate for 10h instead).
    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
    Write-Step 'KDS root key created'
}

# ---------------------------------------------------------------------------
# 5. AD CS Enterprise Root CA -> DC certificate -> LDAPS
# ---------------------------------------------------------------------------
if (-not (Get-WindowsFeature ADCS-Cert-Authority).Installed) {
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
}
# "Already configured" comes from the CA's own state, never from error text.
$caActive = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active -ErrorAction SilentlyContinue
if ($caActive) { Write-Step "CA already configured ($($caActive.Active))" }
else {
    # verify: Enterprise CA setup as SYSTEM via run-command (it writes to the
    # Configuration partition); if refused, add -Credential for an Enterprise Admin.
    Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
        -CACommonName 'Contoso Health Lab Root CA' -KeyLength 2048 -HashAlgorithmName SHA256 `
        -ValidityPeriod Years -ValidityPeriodUnits 5 -Force | Out-Null
    Write-Step 'Enterprise Root CA installed'
}
try { (Get-Service CertSvc).WaitForStatus('Running', [TimeSpan]::FromMinutes(2)) }
catch { throw "AD CS: CertSvc is not running - no CA, so no DC certificate and no LDAPS ($($_.Exception.Message))" }
certutil -pulse | Out-Null   # trigger autoenrollment of the DC certificate
if ($LASTEXITCODE -ne 0) { Write-Warning "certutil -pulse exited $LASTEXITCODE - re-run it on the DC (README > Verify); LDAPS needs the DC certificate" }
else { Write-Step 'Autoenrollment pulsed - LDAPS is live once the DC certificate lands (usually < 2 min)' }

# ---------------------------------------------------------------------------
# 6. PAM-managed accounts
# ---------------------------------------------------------------------------
Write-Step 'PAM accounts'
$rotator = Confirm-User 'svc-vault-rotator' $svcOu 'Vault LDAP secrets engine bind/reconcile account (CPM role). Tier 0 - see script header.'
if ($rotator.Password) {
    Set-KeyVaultSecret -Vault $KeyVaultName -Name 'svc-vault-rotator' -Value $rotator.Password
    Write-Step '  svc-vault-rotator password stored in Key Vault (value not displayed)'
}
# Discovery binds READ-ONLY: a plain Domain User can read group membership,
# adminCount and SPNs, which is all lab/pam/discover.sh needs. Never the
# rotator - a scan should not hold Tier-0 Reset Password rights. Excluded from
# onboarding by lab/pam/pam-policy.json, so Vault never rotates it away.
$discovery = Confirm-User 'svc-pam-discovery' $svcOu 'Read-only LDAP bind for PAM discovery (lab/pam/discover.sh). Plain Domain User - no delegation.'
if ($discovery.Password) {
    Set-KeyVaultSecret -Vault $KeyVaultName -Name 'svc-pam-discovery' -Value $discovery.Password
    Write-Step '  svc-pam-discovery password stored in Key Vault (value not displayed)'
}
$null = Confirm-User 'svc-backup' $svcOu 'Nightly backup service account - Vault STATIC role (scheduled rotation).'
foreach ($n in 'tier0-admin-01', 'tier0-admin-02') {
    $t = Confirm-User $n $privOu 'Tier-0 admin - Vault LIBRARY (exclusive check-out), sessions recorded by Guacamole.'
    Set-ADAccountControl -Identity $t.User -AccountNotDelegated $true   # "sensitive and cannot be delegated"
    if (-not (Get-ADGroupMember 'Domain Admins' | Where-Object SamAccountName -eq $n)) { Add-ADGroupMember 'Domain Admins' -Members $n }
}
# NOTE: tier0 accounts are deliberately NOT in Protected Users - that group
# blocks NTLM, which breaks Guacamole's RDP NLA handshake.

# ---------------------------------------------------------------------------
# 7. Delegation for svc-vault-rotator (Reset Password + the attributes Vault writes)
# ---------------------------------------------------------------------------
$who = "$netbios\svc-vault-rotator"
# dsacls never throws in 5.1 - check its exit code, then read the grant back.
# Non-protected accounts: inherit to user objects under ServiceAccounts.
$out = dsacls $svcOu /I:S /G "${who}:CA;Reset Password;user" "${who}:WP;pwdLastSet;user" "${who}:WP;lockoutTime;user"
if ($LASTEXITCODE -ne 0) { throw "dsacls on $svcOu failed (exit $LASTEXITCODE): $($out -join ' ')" }
# Protected accounts (Domain Admins members): only AdminSDHolder's ACL survives SDProp.
$adminSd = "CN=AdminSDHolder,CN=System,$base"
$out = dsacls $adminSd /G "${who}:CA;Reset Password" "${who}:WP;pwdLastSet" "${who}:WP;lockoutTime"
if ($LASTEXITCODE -ne 0) { throw "dsacls on $adminSd failed (exit $LASTEXITCODE): $($out -join ' ')" }
$resetPwd = [guid]'00299570-246d-11d0-a768-00aa006e0529'   # User-Force-Change-Password (Reset Password)
$rotatorSid = $rotator.User.SID.Value
foreach ($dn in $svcOu, $adminSd) {
    $sd = (Get-ADObject $dn -Properties nTSecurityDescriptor).nTSecurityDescriptor
    $ace = $sd.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference.Value -eq $rotatorSid -and $_.ObjectType -eq $resetPwd -and $_.AccessControlType -eq 'Allow' }
    if (-not $ace) { throw "Reset Password ACE for $who missing on $dn after dsacls - Vault rotation would fail with insufficient access" }
}
# Run SDProp now instead of waiting up to 60 minutes.
$rootDse = [ADSI]'LDAP://RootDSE'
$rootDse.Put('runProtectAdminGroupsTask', 1)
$rootDse.SetInfo()
Write-Step 'Delegations applied (ServiceAccounts OU + AdminSDHolder); SDProp triggered'

# ---------------------------------------------------------------------------
# 8. Hand-off: the OU mapping expression for API-driven provisioning
# ---------------------------------------------------------------------------
$cases = ($Departments | ForEach-Object { "`"$_`", `"$($deptOus[$_])`"" }) -join ', '
Write-Output ''
Write-Output 'Paste into the provisioning app -> Mappings -> parentDistinguishedName (Expression, apply Always):'
Write-Output "IIF([active]=`"False`", `"$disabledOu`", Switch([urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department], `"$workforce`", $cases))"
Write-Output ''
Write-Step 'Phase 2 complete. Next: install the Entra provisioning agent (README step 4).'
