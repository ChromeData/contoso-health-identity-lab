<#
.SYNOPSIS
    The AD half of ITDR containment: disables (or re-enables) an on-prem AD
    account on DC01 for a Sentinel incident, and records what it did.

.DESCRIPTION
    The containment playbook (lab/monitoring/playbook-contain.json) never
    writes to Active Directory. For an account mastered in AD - a user synced
    to Entra by Cloud Sync, or an AD-only Tier-0 account such as
    tier0-admin-01 - AD is the source of authority: an Entra-side disable is
    rejected (synced) or meaningless (AD-only), and the next sync would undo
    it. So the playbook revokes the cloud sessions it can, then FLAGS the
    account in the incident with the exact command line of this script. A
    human runs it - that is the approval for the AD action.

    How it reaches the DC: `az vm run-command invoke` on vm-dc01 (the Azure
    VM agent runs the script as SYSTEM on the DC). No WinRM, no domain
    credential on the laptop, and the operator's Azure RBAC (Virtual Machine
    Contributor or better on the VM) is the access control. The account name
    is validated here AND passed as a run-command parameter, never pasted
    into script text.

    After disabling:
      * Synced users: Cloud Sync carries accountEnabled=false to Entra on its
        next cycle (about 2 minutes, verify: Cloud Sync interval); the
        playbook already revoked the Entra refresh tokens.
      * Tier-0 Vault accounts: force a Vault check-in so Vault ROTATES the
        password (lab/pam: ./psm-session.sh checkin <account>, or as a Vault
        operator: vault write ldap/library/manage/tier0-admins/check-in
        service_account_names=<account>). Disable stops new logons; the
        rotation kills a stolen NT hash / password for good.
      * Kerberos tickets already issued stay valid until they expire (TGT
        lifetime, 10 h by default); the DC refuses renewals and new service
        tickets for a disabled account (verify: on the lab DC).

    Evidence: one JSON record per run in lab/evidence/out/itdr/ (gitignored -
    it names a real account) with the before/after state the DC returned.

.PARAMETER SamAccountName
    The AD logon name the playbook flagged (e.g. tier0-admin-01).

.PARAMETER IncidentNumber
    Sentinel incident number, for the evidence record and the AD description.

.PARAMETER Restore
    Re-enable the account (incident closed as benign / after rotation).

.EXAMPLE
    ./Invoke-AdContainment.ps1 -SamAccountName tier0-admin-01 -IncidentNumber 42 -WhatIf
    ./Invoke-AdContainment.ps1 -SamAccountName tier0-admin-01 -IncidentNumber 42
    ./Invoke-AdContainment.ps1 -SamAccountName tier0-admin-01 -IncidentNumber 42 -Restore
#>

#Requires -Version 7.0

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive operator script: coloured progress goes to the host so it never mixes with returned objects; nothing parses this output.')]
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # sAMAccountName rules: <= 20 chars, no spaces or the AD-reserved characters.
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$')][string]$SamAccountName,
    [Parameter(Mandatory)][ValidateRange(1, 99999999)][int]$IncidentNumber,
    [switch]$Restore,
    [string]$ResourceGroup = 'rg-identity-lab',
    [string]$VmName = 'vm-dc01',
    [string]$EvidenceDir = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'itdr')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

# Accounts this script refuses to disable: the built-in Administrator and the
# Vault bind account would take the DC / the PAM vault down with them, and
# krbtgt is never disabled (its reset is a separate, documented procedure).
$neverDisable = @('administrator', 'krbtgt', 'svc-vault-rotator')
if (-not $Restore -and $SamAccountName.ToLowerInvariant() -in $neverDisable) {
    throw "Refusing to disable '$SamAccountName': it would break the DC or the PAM vault. Follow the manual Tier-0 runbook instead."
}

$mode = if ($Restore) { 'Enable' } else { 'Disable' }

# Runs ON the DC as SYSTEM. Parameters arrive from run-command; the name was
# validated above and is re-validated here (defence in depth on the DC side).
$dcScript = @'
param([string]$SamAccountName, [string]$Mode, [string]$Incident)
$ErrorActionPreference = 'Stop'
if ($SamAccountName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$') { throw 'invalid account name' }
Import-Module ActiveDirectory
$props = 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'Description', 'MemberOf', 'DistinguishedName'
$before = Get-ADUser -Identity $SamAccountName -Properties $props
if ($Mode -eq 'Disable') {
    Disable-ADAccount -Identity $SamAccountName
    Set-ADUser -Identity $SamAccountName -Description ("Disabled by ITDR containment, Sentinel incident {0}, {1:u}" -f $Incident, (Get-Date).ToUniversalTime())
}
else {
    Enable-ADAccount -Identity $SamAccountName
}
$after = Get-ADUser -Identity $SamAccountName -Properties $props
[pscustomobject]@{
    account          = $SamAccountName
    distinguished    = $after.DistinguishedName
    enabled_before   = $before.Enabled
    enabled_after    = $after.Enabled
    last_logon       = if ($after.LastLogonDate) { $after.LastLogonDate.ToUniversalTime().ToString('o') } else { $null }
    password_set     = if ($after.PasswordLastSet) { $after.PasswordLastSet.ToUniversalTime().ToString('o') } else { $null }
    privileged_groups = @($after.MemberOf | Where-Object { $_ -match 'CN=(Domain Admins|Enterprise Admins|Schema Admins|Administrators),' })
} | ConvertTo-Json -Compress
'@

$tmp = New-TemporaryFile
try {
    Set-Content -LiteralPath $tmp.FullName -Value $dcScript -NoNewline
    if (-not $PSCmdlet.ShouldProcess("$VmName ($ResourceGroup)", "$mode AD account '$SamAccountName' for Sentinel incident $IncidentNumber")) { return }

    Write-Host "[1/2] $mode '$SamAccountName' on $VmName (az vm run-command)" -ForegroundColor Cyan
    $raw = az vm run-command invoke -g $ResourceGroup -n $VmName --command-id RunPowerShellScript `
        --scripts "@$($tmp.FullName)" `
        --parameters "SamAccountName=$SamAccountName" "Mode=$mode" "Incident=$IncidentNumber" -o json | ConvertFrom-Json
}
finally {
    Remove-Item -LiteralPath $tmp.FullName -Force -ErrorAction SilentlyContinue
}

# run-command returns stdout and stderr as two status messages.
$stdout = @($raw.value | Where-Object { $_.code -like '*StdOut*' })[0].message
$stderr = @($raw.value | Where-Object { $_.code -like '*StdErr*' })[0].message
if ($stderr) { throw "DC reported an error (nothing is assumed done): $stderr" }
$result = $stdout | ConvertFrom-Json
$expected = -not ($mode -eq 'Disable')
if ($result.enabled_after -ne $expected) { throw "DC says Enabled=$($result.enabled_after) after $mode - check the account by hand." }

Write-Host "[2/2] Evidence record" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$record = [ordered]@{
    recorded_utc  = (Get-Date).ToUniversalTime().ToString('o')
    incident      = $IncidentNumber
    action        = $mode
    operator      = (az account show --query user.name -o tsv)
    dc            = $VmName
    result        = $result
}
$file = Join-Path $EvidenceDir ("ad-containment-{0}-{1}-{2:yyyyMMddTHHmmssZ}.json" -f $IncidentNumber, $SamAccountName, (Get-Date).ToUniversalTime())
$record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file
Write-Host "  $mode done: Enabled $($result.enabled_before) -> $($result.enabled_after). Evidence: $file" -ForegroundColor Green

if ($mode -eq 'Disable') {
    Write-Host @"
Next:
  * Tier-0 Vault account? Force a check-in so Vault rotates the password:
      cd lab/pam && ./psm-session.sh checkin $SamAccountName
  * Synced user? Entra follows on the next Cloud Sync cycle; sessions were already revoked by the playbook.
  * Comment the evidence file name on Sentinel incident $IncidentNumber.
"@ -ForegroundColor Cyan
}
