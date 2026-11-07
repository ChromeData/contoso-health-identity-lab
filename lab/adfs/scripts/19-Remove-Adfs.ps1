<#
.SYNOPSIS
    Decommissions the lab AD FS farm on DC01 (ADR 0009 phase 5). Reports only
    unless -Apply yes.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py).

    Gate first: ADR 0009 says an app leaves AD FS only after "zero AD FS
    sign-ins for the app for an agreed period". The script counts AD FS
    token-issuance audits (Security log, event 1200, source "AD FS Auditing")
    that name the relying party in the last -QuietHours hours. If there are
    any, it stops, unless -Force yes. It also stops when it cannot prove the
    quiet period: no AD FS audit has ever been written (auditing is broken),
    or the Security log does not reach back -QuietHours. Before you decommission, the cutover is
    done and nothing still uses AD FS.

    What -Apply yes removes, in this order:
      1. The relying party trust (disabled first, then removed).
      2. The Connect Health AD FS agent (its own uninstaller, quiet).
      3. The ADFS-Federation role. Windows may ask for a restart; this script
         does NOT restart the DC (other work depends on it). The JSON says so.
      4. The DKM container (CN=ADFS,CN=Microsoft,CN=Program Data,<domain>):
         the AD object that protected the token-signing key. With it gone the
         old signing key cannot be recovered from AD (the Golden SAML key is
         destroyed, not just unused).
      5. The gMSA gmsa-adfs, the DNS A record and the TLS certificate.
      6. The "Application Generated" audit subcategory goes back to off (the
         Windows default on a DC).

    Kept on purpose: GRP-ClaimsViewer-* and adfs-pilot. After the cutover the
    Entra app uses the same groups, so removing them would break the migrated
    app. -RemoveTestObjects yes removes them too, for the final teardown.

.PARAMETER Apply
    'yes' to change anything. Anything else = report only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [string]$FederationServiceName = '',
    [string]$RpIdentifier = 'urn:contoso:claims-viewer',
    [string]$GmsaName = 'gmsa-adfs',
    [ValidateRange(1, 720)][int]$QuietHours = 24,
    [string]$Apply = 'no',
    [string]$Force = 'no',
    [string]$RemoveTestObjects = 'no'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if (-not $FederationServiceName) { $FederationServiceName = "sts.$DomainName" }
$doIt = ($Apply -eq 'yes')

function Write-Step([string]$Message) { Write-Output ("[adfs-remove] {0}" -f $Message) }

$domainDn = (Get-ADDomain).DistinguishedName
$dkm = "CN=ADFS,CN=Microsoft,CN=Program Data,$domainDn"
$adfs = [bool](Get-Service adfssrv -ErrorAction SilentlyContinue)

# --- Gate: is AD FS still issuing tokens for this app? -------------------------
$since = (Get-Date).AddHours(-$QuietHours)
$recent = @()
try {
    $recent = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ProviderName = 'AD FS Auditing'; Id = 1200; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Message -match [regex]::Escape($RpIdentifier) })
} catch [System.Exception] {
    if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
}

# An empty result is proof only if auditing WORKS and the log REACHES BACK far
# enough. Otherwise "no events" may just mean "nothing was written" (the
# gMSA lacks SeAuditPrivilege, 10-Install-Adfs.ps1 step 8) or "the log
# rolled over". So: at least one AD FS token-issuance audit must exist at
# all, and the oldest Security event must be older than the quiet window.
$anyAudit = $null
try {
    $anyAudit = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ProviderName = 'AD FS Auditing'; Id = 1200 } -MaxEvents 1 -ErrorAction Stop
} catch [System.Exception] {
    if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw }
}
$oldest = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1).TimeCreated
$auditsProven = [bool]$anyAudit -and ($oldest -le $since)

$inventory = [ordered]@{
    adfsService       = $adfs
    relyingParty      = $(if ($adfs) { [bool](Get-AdfsRelyingPartyTrust -Identifier $RpIdentifier) } else { $false })
    connectHealth     = [bool](Get-Service 'AdHealthAdfs*' -ErrorAction SilentlyContinue)
    dkmContainer      = [bool](Get-ADObject -Filter "DistinguishedName -eq '$dkm'" -ErrorAction SilentlyContinue)
    gmsa              = [bool](Get-ADServiceAccount -Filter "Name -eq '$GmsaName'")
    tokenIssuances    = $recent.Count
    auditsWork        = [bool]$anyAudit
    securityLogFrom   = $oldest.ToUniversalTime().ToString('o')
    quietWindowHours  = $QuietHours
}
Write-Step ("inventory: " + ($inventory | ConvertTo-Json -Compress))

if (-not $doIt) { Write-Step 'report only (pass -Apply yes to decommission)'; return }
if (-not $auditsProven -and $Force -ne 'yes') {
    throw "Cannot prove the quiet period: AD FS audits found = $([bool]$anyAudit), Security log starts $oldest (window starts $since). Fix auditing (README step 3b) or wait, then re-run (or -Force yes)."
}
if ($recent.Count -gt 0 -and $Force -ne 'yes') {
    throw "AD FS issued $($recent.Count) token(s) for $RpIdentifier in the last $QuietHours h. The app still uses AD FS: finish the cutover first (or -Force yes)."
}

$restart = $false
if ($adfs) {
    if (Get-AdfsRelyingPartyTrust -Identifier $RpIdentifier) {
        Write-Step "removing relying party $RpIdentifier"
        Disable-AdfsRelyingPartyTrust -TargetIdentifier $RpIdentifier
        Remove-AdfsRelyingPartyTrust -TargetIdentifier $RpIdentifier
    }
}

$uninstall = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue |
    Get-ItemProperty | Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -match 'Connect Health.*(AD FS|ADFS)' }
foreach ($u in $uninstall) {
    Write-Step "uninstalling $($u.DisplayName)"
    if ($u.PSChildName -match '^\{[0-9A-F-]+\}$') {
        $p = Start-Process msiexec.exe -ArgumentList "/x $($u.PSChildName) /qn /norestart" -Wait -PassThru
        if ($p.ExitCode -notin 0, 3010) { throw "Uninstall of $($u.DisplayName) failed ($($p.ExitCode))." }
        if ($p.ExitCode -eq 3010) { $restart = $true }
    } else {
        throw "No MSI product code for '$($u.DisplayName)'; uninstall it by hand (UninstallString: $($u.UninstallString))."
    }
}

if ((Get-WindowsFeature ADFS-Federation).Installed) {
    Write-Step 'removing the ADFS-Federation role'
    $r = Uninstall-WindowsFeature ADFS-Federation -IncludeManagementTools
    if (-not $r.Success) { throw 'Uninstall-WindowsFeature ADFS-Federation failed.' }
    if ($r.RestartNeeded -eq 'Yes') { $restart = $true }
}

if (Get-ADObject -Filter "DistinguishedName -eq '$dkm'" -ErrorAction SilentlyContinue) {
    Write-Step "removing the DKM container $dkm"
    Remove-ADObject -Identity $dkm -Recursive -Confirm:$false
}
$g = Get-ADServiceAccount -Filter "Name -eq '$GmsaName'"
if ($g) { Write-Step "removing gMSA $GmsaName"; Remove-ADServiceAccount -Identity $g -Confirm:$false }

$label = $FederationServiceName -replace "\.$([regex]::Escape($DomainName))$", ''
$rec = Get-DnsServerResourceRecord -ZoneName $DomainName -Name $label -RRType A -ErrorAction SilentlyContinue
if ($rec) { Write-Step "removing DNS A $FederationServiceName"; $rec | Remove-DnsServerResourceRecord -ZoneName $DomainName -Force }

foreach ($store in 'Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root') {
    Get-ChildItem $store | Where-Object { $_.Subject -eq "CN=$FederationServiceName" } | ForEach-Object {
        Write-Step "removing certificate $($_.Thumbprint) from $store"; Remove-Item $_.PSPath -Force
    }
}
$null = & auditpol.exe /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable

if ($RemoveTestObjects -eq 'yes') {
    $ou = "OU=Workforce,$domainDn"
    foreach ($n in 'GRP-ClaimsViewer-Clinicians', 'GRP-ClaimsViewer-Admins') {
        $grp = Get-ADGroup -Filter "SamAccountName -eq '$n'" -SearchBase $ou
        if ($grp) { Write-Step "removing group $n"; Remove-ADGroup -Identity $grp -Confirm:$false }
    }
    $pu = Get-ADUser -Filter "SamAccountName -eq 'adfs-pilot'" -SearchBase $ou
    if ($pu) { Write-Step 'removing user adfs-pilot'; Remove-ADUser -Identity $pu -Confirm:$false }
}

[pscustomobject]@{
    decommissioned = $true
    restartNeeded  = $restart
    note           = $(if ($restart) { 'Windows asks for a restart to finish removing the role. Restart DC01 in a quiet window (preflight.sh brings Cloud Sync back).' } else { '' })
} | ConvertTo-Json
