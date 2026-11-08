<#
.SYNOPSIS
    Retires svc-pam-discovery, runs ON DC01: disables and deletes the AD
    account, and deletes its Key Vault secret.

.DESCRIPTION
    svc-pam-discovery was the read-only LDAP bind for lab/pam/discover.sh, the
    discovery step of the HashiCorp Vault stand-in. ADR 0036 (Microsoft-native
    PAM) retires that stand-in, so the account and its password have no user.
    A service account with no user is attack surface: retire it, do not leave
    it to expire (its 30-day password would expire on 2026-11-26).

    Called through run-on-dc.py (a managed run command: no RDP, no password on
    any command line). Windows PowerShell 5.1 as SYSTEM, ActiveDirectory module.

    It acts on ONE known account and refuses when:
      * the account is not exactly CN=svc-pam-discovery,OU=ServiceAccounts,<domain>
        (02-Configure-Domain.ps1 creates it there);
      * it is protected (adminCount = 1), its primary group is not Domain
        Users (RID 513), or it is a member of any other group: a read-only
        bind has none of these, so any of them means it is not the account
        this script expects.

    Order: report, disable, delete the account, then delete the Key Vault
    secret 'svc-pam-discovery' with DC01's own managed identity (Key Vault
    Secrets Officer, ABAC-limited to the DC's three secret names: modules/
    dc-vm main.tf). The secret goes BEFORE the Terraform change that drops
    the name from that list, or the DC would lose the right to delete it.
    The vault keeps a soft-deleted copy for its retention period; this script
    never reads the value.

    Without -Apply yes it only reports.

.PARAMETER KeyVaultName
    The lab vault (kv-idlab-20f1).

.PARAMETER Apply
    'yes' disables and deletes. Anything else is a dry run.

.EXAMPLE
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/Remove-PamDiscoveryAccount.ps1 --param KeyVaultName=kv-idlab-20f1
    lab/scripts/dc/run-on-dc.py lab/scripts/dc/Remove-PamDiscoveryAccount.ps1 --param KeyVaultName=kv-idlab-20f1 --param Apply=yes
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9-]{3,24}$')]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$Apply = 'no'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) { Import-Module ActiveDirectory }

$name = 'svc-pam-discovery'
$domainDn = (Get-ADDomain).DistinguishedName
$expectedDn = "CN=$name,OU=ServiceAccounts,$domainDn"
# NOT $apply: PowerShell names are case-insensitive, so $apply IS the [string]
# parameter $Apply, and $false stored there becomes the string "False", which
# is truthy. That bug made the first 2026-11-07 "dry run" act. A distinct name.
$doApply = ($Apply -ceq 'yes')

function Get-VaultToken {
    $t = Invoke-RestMethod -Headers @{ Metadata = 'true' } -UseBasicParsing `
        -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net'
    return $t.access_token
}
function Get-SecretState([string]$Token) {
    # Metadata only (readMetadata on the versions list), never the value.
    # 'present' = at least one version listed. A soft-deleted secret still
    # answers 200 here, with an EMPTY list (seen live 2026-11-07), so a 200
    # alone is not "present".
    try {
        $r = Invoke-RestMethod -UseBasicParsing -Headers @{ Authorization = "Bearer $Token" } `
            -Uri "https://$KeyVaultName.vault.azure.net/secrets/$name/versions?api-version=7.4&maxresults=1"
        if (@($r.value).Count -gt 0) { return 'present' } else { return 'absent' }
    } catch {
        $code = $null
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -eq 404) { return 'absent' }
        throw "Key Vault lookup for '$name' failed (HTTP $code): $($_.Exception.Message)"
    }
}

# ---- 1. the account ------------------------------------------------------------
$u = @(Get-ADUser -Filter "SamAccountName -eq '$name'" -Properties adminCount, Enabled, MemberOf, PrimaryGroupID, LastLogonDate, whenCreated, ProtectedFromAccidentalDeletion)
if ($u.Count -gt 1) { Write-Output "REFUSED: $($u.Count) accounts named $name."; exit 1 }
if ($u.Count -eq 1) {
    $a = $u[0]
    if ($a.DistinguishedName -ne $expectedDn) { Write-Output "REFUSED: $name is at $($a.DistinguishedName), not $expectedDn."; exit 1 }
    $adminCount = if ($a.PSObject.Properties['adminCount'] -and $a.adminCount) { [int]$a.adminCount } else { 0 }
    if ($adminCount -eq 1) { Write-Output "REFUSED: $name has adminCount=1 (protected): not the plain read-only bind this script expects."; exit 1 }
    # MemberOf never lists the PRIMARY group, so check it separately: a plain
    # bind's primary group is Domain Users (RID 513). Anything else means the
    # account was repurposed: refuse.
    if ([int]$a.PrimaryGroupID -ne 513) { Write-Output "REFUSED: $name has primary group RID $($a.PrimaryGroupID), not Domain Users (513)."; exit 1 }
    $groups = @($a.MemberOf)
    if ($groups.Count -gt 0) { Write-Output "REFUSED: $name is a member of $($groups.Count) group(s) besides Domain Users: $($groups -join '; ')"; exit 1 }
    Write-Output ("FOUND: {0} enabled={1} created={2:yyyy-MM-dd} lastLogon={3}" -f $a.DistinguishedName, $a.Enabled, $a.whenCreated, $(if ($a.LastLogonDate) { $a.LastLogonDate.ToString('yyyy-MM-ddTHH:mm') } else { 'never' }))
    if ($doApply) {
        Disable-ADAccount -Identity $a.DistinguishedName
        Write-Output "DISABLED: $name"
        if ($a.ProtectedFromAccidentalDeletion) { Set-ADObject -Identity $a.DistinguishedName -ProtectedFromAccidentalDeletion $false }
        Remove-ADUser -Identity $a.DistinguishedName -Confirm:$false
        if (@(Get-ADUser -Filter "SamAccountName -eq '$name'").Count -ne 0) { throw "$name still exists after Remove-ADUser" }
        Write-Output "DELETED: $name (read back: no account of that name)"
    } else {
        Write-Output "DRY RUN: would disable, then delete $name"
    }
} else {
    Write-Output "ABSENT: no AD account $name (already retired)"
}

# ---- 2. its Key Vault secret ----------------------------------------------------------
$tok = Get-VaultToken
$state = Get-SecretState $tok
Write-Output "KEY VAULT: secret '$name' in $KeyVaultName is $state"
if ($state -eq 'present') {
    if ($doApply) {
        Invoke-RestMethod -Method Delete -UseBasicParsing -Headers @{ Authorization = "Bearer $tok" } `
            -Uri "https://$KeyVaultName.vault.azure.net/secrets/$name`?api-version=7.4" | Out-Null
        $after = Get-SecretState $tok
        if ($after -ne 'absent') { throw "the secret '$name' is still $after after DELETE" }
        Write-Output "KEY VAULT: secret '$name' deleted (read back: absent; soft-deleted copy kept for the vault's retention period)"
    } else {
        Write-Output "DRY RUN: would delete the Key Vault secret '$name'"
    }
}
$tok = $null
Write-Output $(if ($doApply) { 'RESULT: svc-pam-discovery retired' } else { 'RESULT: dry run only' })
