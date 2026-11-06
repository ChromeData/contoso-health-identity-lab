<#
.SYNOPSIS
  First-time setup: create the safes in intended-state.json and add their
  missing members, with permissions from RoleMap.psm1. Adds only; never
  changes or removes an existing member (Invoke-SafeReconcile.ps1 -Apply
  resets permissions).

.DESCRIPTION
  STATUS: RAN against the stub only (tests/New-LabSafe.Tests.ps1). Never run
  against a CyberArk vault.

  Bugs fixed while porting from the earlier lab (each pinned by a test):
    1. Its own hand-written role map disagreed with RoleMap.psm1 (audit had
       no ViewSafeMembers; use and full were short of 3 and 11 permissions),
       so every member it added was drift on the reconciler's first run. It
       now uses Get-LabRolePermissionSet, the same call the reconciler uses.
    2. `Add-PASSafeMember ... @($roleMap[$m.role])` is an array holding the
       hashtable, not a splat. With psPAS's real [boolean] parameters it fails
       to bind ("Cannot convert value System.Object[] to type
       System.Boolean"); the earlier stub swallowed it and recorded a member
       with no permissions.
    3. An unknown role silently became an empty permission set. The state file
       is now validated (Get-LabRolePermission throws) before any write.
    4. `Get-PASSafe -ErrorAction SilentlyContinue` cannot catch psPAS's
       terminating error, so a safe that did not exist yet stopped the script
       before it could create it. Only HTTP 404 means missing now; any other
       error stops the script.

.PARAMETER IntendedStatePath
  The state file (JSON). Default: intended-state.json next to this script.
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$IntendedStatePath = (Join-Path $PSScriptRoot 'intended-state.json'))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Status {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Operator console status lines, not pipeline data.')]
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
}

Import-Module psPAS
Import-Module (Join-Path $PSScriptRoot 'RoleMap.psm1') -Force

$intended = Get-Content -Raw -LiteralPath $IntendedStatePath | ConvertFrom-Json -AsHashtable
$safes = @(if ($intended.ContainsKey('safes')) { $intended.safes })

# Validate every role before the first write (throws on an unknown one).
foreach ($safe in $safes) {
    if (-not $safe['name']) { throw 'a safe entry has no name' }
    foreach ($m in @($safe['members']) | Where-Object { $_ }) { $null = Get-LabRolePermission -Role $m['role'] }
}

if (-not (Get-PASSession)) { throw 'No psPAS session. Run ./Connect-Lab.ps1 first.' }

foreach ($safe in $safes) {
    $exists = $true
    try { $null = Get-PASSafe -SafeName $safe.name }
    catch {
        $status = $null
        try { $status = [int]$_.TargetObject.Exception.Response.StatusCode } catch { $status = $null }
        if (-not ($status -eq 404 -or $_.Exception.Message -match '^\[404\]')) { throw }
        $exists = $false
    }
    if ($exists) {
        Write-Status "safe exists: $($safe.name)"
        $existing = @(Get-PASSafeMember -SafeName $safe.name | ForEach-Object { $_.MemberName })
    } else {
        if (-not $PSCmdlet.ShouldProcess($safe.name, 'Create safe')) { continue }
        Write-Status "creating safe: $($safe.name)" Green
        Add-PASSafe -SafeName $safe.name -Description $safe['description'] -ManagingCPM $safe['managingCPM']
        $existing = @()
    }
    foreach ($m in @($safe['members']) | Where-Object { $_ }) {
        if ($m.name -in $existing) { continue }
        if (-not $PSCmdlet.ShouldProcess("$($safe.name)/$($m.name)", "Add member as '$($m.role)'")) { continue }
        Write-Status "  + member $($m.name) [$($m.role)]"
        $perms = Get-LabRolePermissionSet -Role $m.role
        Add-PASSafeMember -SafeName $safe.name -MemberName $m.name @perms
    }
}
Write-Status 'Safes created. Check with ./Invoke-SafeReconcile.ps1 (it also onboards the accounts with -Apply).'
