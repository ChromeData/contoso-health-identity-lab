<#
.SYNOPSIS
    Finds what USES a service account on a Windows server - services,
    scheduled tasks and IIS application pools that run as it - and prints
    entries in the shape of lab/pam/accounts-dependencies.json.

.DESCRIPTION
    PAM discovery tools find these "usages" so the rotation can update
    them when it changes the password. Vault cannot push a new password into a
    Windows service, so the lab does the other half: find every consumer
    BEFORE a static role is created, and refuse to rotate (onboard.sh,
    rotate.sh) until each one is resolved - switched to read the password
    from Vault at run time, or decommissioned.

    Runs ON each server (tenant time: `az vm run-command invoke`, README
    "Dependency discovery on DC01"), read-only. Prints JSON to stdout:
        { "host": "<computer>", "scanned_at": "...", "accounts": {
            "svc-sql01": [ { "type": "windows-service", "host": "...",
                             "name": "MSSQLSERVER", "owner": "unknown",
                             "resolved": false, "source": "scan" } ] } }
    Every finding starts resolved=false: a scan can see that a service runs as
    the account, never that its password already comes from Vault. A person
    flips it after checking. Merge per-server outputs into the committed map
    with jq (README shows the one-liner). Names only, never a password: the
    LSA secret behind a service logon is not read and cannot be.

.PARAMETER Accounts
    sAMAccountNames to look for, comma-separated (one string, because
    `az vm run-command --parameters` passes strings).

.PARAMETER Domain
    NetBIOS domain name (CORP). Matches DOMAIN\sam, sam@<any UPN suffix> and
    a bare sam in a run-as field.

.EXAMPLE
    ./Get-AccountDependencies.ps1 -Accounts 'svc-backup,svc-sql01' -Domain CORP
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Accounts,
    [Parameter(Mandatory)][string]$Domain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-AccountMatch {
    # True if a run-as value names $Sam in $Domain: CORP\svc-x, svc-x@corp.example,
    # or a bare svc-x. Case-insensitive, like Windows. Local (.\x) and other
    # domains do not match.
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][AllowNull()][string]$Value, [Parameter(Mandatory)][string]$Sam, [Parameter(Mandatory)][string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    if ($v -match '^(?<dom>[^\\]+)\\(?<user>.+)$') { return ($Matches.dom -ieq $Domain -and $Matches.user -ieq $Sam) }
    if ($v -match '^(?<user>[^@]+)@.+$') { return ($Matches.user -ieq $Sam) }
    return ($v -ieq $Sam)
}

function Get-RunAsInventory {
    # Every run-as identity this server knows about, as (type, name, runAs).
    # A source that is absent (no IIS, Task Scheduler module missing on an old
    # OS) is reported on stderr and skipped - an absent source is not "no
    # dependencies", so the caller sees the warning.
    [CmdletBinding()]
    [OutputType([object[]])]
    param()
    $items = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service)) {
            $items.Add([pscustomobject]@{ Type = 'windows-service'; Name = $s.Name; RunAs = $s.StartName })
        }
    } catch { Write-Warning "services not scanned: $($_.Exception.Message)" }
    try {
        foreach ($t in @(Get-ScheduledTask)) {
            $items.Add([pscustomobject]@{ Type = 'scheduled-task'; Name = "$($t.TaskPath)$($t.TaskName)"; RunAs = $t.Principal.UserId })
        }
    } catch { Write-Warning "scheduled tasks not scanned: $($_.Exception.Message)" }
    if (Get-Module -ListAvailable -Name WebAdministration) {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($p in @(Get-ChildItem -Path 'IIS:\AppPools')) {
                $items.Add([pscustomobject]@{ Type = 'iis-app-pool'; Name = $p.Name; RunAs = $p.processModel.userName })
            }
        } catch { Write-Warning "IIS application pools not scanned: $($_.Exception.Message)" }
    }
    return $items.ToArray()
}

function ConvertTo-DependencyMap {
    # Builds the accounts-dependencies.json fragment for this host. Every
    # requested account appears, with [] when nothing uses it here, so "scanned
    # and found nothing" is recorded explicitly.
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)][string[]]$Sam,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$HostName,
        [AllowEmptyCollection()][object[]]$Inventory = @()
    )
    $map = [ordered]@{}
    foreach ($a in $Sam) {
        $found = @($Inventory | Where-Object { Test-AccountMatch -Value $_.RunAs -Sam $a -Domain $Domain } | ForEach-Object {
                [ordered]@{ type = $_.Type; host = $HostName; name = $_.Name; owner = 'unknown'; resolved = $false; source = 'scan' }
            })
        $map[$a] = $found
    }
    return [ordered]@{
        host       = $HostName
        scanned_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        accounts   = $map
    }
}

# --- main (skipped when the tests dot-source only the functions) -------------
$sams = @($Accounts -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($sams.Count -eq 0) { throw '-Accounts is empty' }
$hostName = [System.Net.Dns]::GetHostEntry([string]$env:COMPUTERNAME).HostName
$result = ConvertTo-DependencyMap -Sam $sams -Domain $Domain -HostName $hostName -Inventory @(Get-RunAsInventory)
$result | ConvertTo-Json -Depth 6
