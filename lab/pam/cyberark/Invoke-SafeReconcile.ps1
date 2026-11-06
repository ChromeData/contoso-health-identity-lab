<#
.SYNOPSIS
  Report, and optionally correct, drift between intended-state.json and a
  CyberArk vault, through psPAS.

.DESCRIPTION
  WHY: clicking safes together in the web console leaves no record of what was
  meant. Here the intended safes, memberships (as roles, see RoleMap.psm1) and
  accounts are one reviewed file, and this script finds every difference
  between that file and the vault.

  STATUS: RAN against a stub only (tests/stubs/psPAS, Pester). It has NEVER run
  against a CyberArk vault: the lab has no CyberArk licence or tenant. Treat
  every psPAS call here as "written to psPAS 8.2.0's documented parameters,
  not yet seen working".

  Drift, most worrying first:
    UNEXPECTED     a safe member nobody declared: access no document explains
    EXTRA_PERM     a declared member holding more than their role
    DUPLICATE      the same declared account (userName@address) twice in a safe
    WRONG_PLATFORM an account under a different platform than declared
    MISSING        a declared safe, member or account that is not there
    MISSING_PERM   a declared member below their role

  -Apply converges the vault toward the file: it creates missing safes,
  members and accounts, and resets a member's permissions to exactly their
  role (every permission sent, true or false). It NEVER deletes a safe,
  member or account: a reconciler with delete rights will, the first time the
  file is wrong, revoke access during an incident. Removals are reported and
  done by a person.

  FAILS CLOSED: a safe the vault reports as not found (HTTP 404) is drift
  (MISSING). Any other failed read - permissions, network, a 500 - stops the
  run with exit 2, a code drift never uses. The earlier version wrapped every
  lookup in -ErrorAction SilentlyContinue, which cannot catch psPAS's
  terminating errors: run against a stub that throws like psPAS, it stopped
  at the first missing safe (so -Apply could never create one), and every
  failed read ended the script with exit 1, the same code as "drift found".

.PARAMETER IntendedStatePath
  The state file (JSON). Default: intended-state.json next to this script.

.PARAMETER Apply
  Make the corrections. Without it nothing is written. Honours -WhatIf.

.PARAMETER JsonPath
  Also write the drift report as JSON.

.OUTPUTS
  Exit 0 in sync, 1 drift found (also after -Apply, so CI shows it), 2 could
  not run (bad state file, no session, a failed read).

.EXAMPLE
  ./Connect-Lab.ps1 -BaseUri https://pvwa.example.org
  ./Invoke-SafeReconcile.ps1                 # report only
  ./Invoke-SafeReconcile.ps1 -Apply -WhatIf  # what -Apply would change
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$IntendedStatePath = (Join-Path $PSScriptRoot 'intended-state.json'),
    [switch]$Apply,
    [string]$JsonPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Status {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Operator console status lines, not pipeline data.')]
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
}

function Exit-Run([string]$Message) {
    [Console]::Error.WriteLine("COULD NOT RUN: $Message")
    exit 2
}

function Test-NotFound {
    <#
      True only for "the vault says this does not exist" (HTTP 404). psPAS
      8.2.0 raises a terminating error whose TargetObject is the original web
      error (status on .Exception.Response.StatusCode) and whose message starts
      "[<status>]" (psPAS/Private/Invoke-PASRestMethod.ps1). Anything else is
      "could not read", never "not there".
    #>
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $status = $null
    try { $status = [int]$ErrorRecord.TargetObject.Exception.Response.StatusCode } catch { $status = $null }
    if ($status -eq 404) { return $true }
    return [bool]($ErrorRecord.Exception.Message -match '^\[404\]')
}

Import-Module psPAS
Import-Module (Join-Path $PSScriptRoot 'RoleMap.psm1') -Force

# ---------------------------------------------------------------------------
# 1. Validate the state file BEFORE touching the vault. An unknown role
#    reaching the write path would create a member with no permissions,
#    which looks like success.
# ---------------------------------------------------------------------------
try {
    $intended = Get-Content -Raw -LiteralPath $IntendedStatePath | ConvertFrom-Json -AsHashtable
} catch {
    Exit-Run "cannot read state file '$IntendedStatePath': $($_.Exception.Message)"
}
$problems = [System.Collections.Generic.List[string]]::new()
$validRoles = Get-LabRoleName
$safes = @(if ($intended.ContainsKey('safes')) { $intended.safes })
$accounts = @(if ($intended.ContainsKey('accounts')) { $intended.accounts })
$safeNames = @($safes | ForEach-Object { $_['name'] })
foreach ($safe in $safes) {
    if (-not $safe['name']) { $problems.Add('a safe entry has no name'); continue }
    $memberNames = @()
    foreach ($m in @($safe['members'])) {
        if ($null -eq $m) { continue }
        if (-not $m['name']) { $problems.Add("safe '$($safe.name)': a member has no name") }
        elseif ($m['role'] -notin $validRoles) {
            $problems.Add("safe '$($safe.name)' member '$($m.name)' has unknown role '$($m['role'])'. Valid: $($validRoles -join ', ')")
        }
        if ($m['name'] -in $memberNames) { $problems.Add("safe '$($safe.name)': member '$($m.name)' is declared twice") }
        $memberNames += $m['name']
    }
}
foreach ($a in $accounts) {
    foreach ($field in 'safe', 'platformId', 'address', 'userName') {
        if (-not $a[$field]) { $problems.Add("an account entry has no $field") }
    }
    if ($a['safe'] -and $a['safe'] -notin $safeNames) {
        $problems.Add("account $($a['userName'])@$($a['address']) names safe '$($a['safe'])', which the file does not declare")
    }
}
if ($problems.Count) { Exit-Run ("state file invalid:`n  " + ($problems -join "`n  ")) }
Write-Status ("State file valid: {0} safe(s), {1} membership(s), {2} account(s)." -f $safes.Count,
    @($safes | ForEach-Object { @($_['members']) } | Where-Object { $_ }).Count, $accounts.Count) Cyan

try { $session = Get-PASSession } catch { $session = $null }
if (-not $session) { Exit-Run 'no psPAS session. Run ./Connect-Lab.ps1 first.' }

$drift = [System.Collections.Generic.List[object]]::new()
function Add-Drift($Type, $Name, $Issue, $Detail = '') {
    $drift.Add([pscustomobject]@{ Type = $Type; Name = $Name; Issue = $Issue; Detail = $Detail })
}

# ---------------------------------------------------------------------------
# 2. Safes and membership
# ---------------------------------------------------------------------------
foreach ($safe in $safes) {
    Write-Status "==> Safe: $($safe.name)"
    $exists = $true
    try { $null = Get-PASSafe -SafeName $safe.name }
    catch {
        if (-not (Test-NotFound $_)) { Exit-Run "could not read safe '$($safe.name)': $($_.Exception.Message)" }
        $exists = $false
    }

    $declared = @(@($safe['members']) | Where-Object { $_ })
    if (-not $exists) {
        Add-Drift 'Safe' $safe.name 'MISSING'
        if (-not ($Apply -and $PSCmdlet.ShouldProcess($safe.name, 'Create safe'))) {
            continue   # nothing else about it can be checked until it exists
        }
        Write-Status '    creating safe' Yellow
        Add-PASSafe -SafeName $safe.name -Description $safe['description'] -ManagingCPM $safe['managingCPM']
    }

    $live = @()
    if ($exists) {
        try { $live = @(Get-PASSafeMember -SafeName $safe.name) }
        catch { Exit-Run "could not read the members of '$($safe.name)': $($_.Exception.Message)" }
    }

    foreach ($m in $declared) {
        $member = @($live | Where-Object { $_.MemberName -eq $m.name })
        if (-not $member) {
            Add-Drift 'Member' "$($safe.name)/$($m.name)" 'MISSING' "role=$($m.role)"
            if ($Apply -and $PSCmdlet.ShouldProcess("$($safe.name)/$($m.name)", "Add member as '$($m.role)'")) {
                Write-Status "    adding $($m.name) as $($m.role)" Yellow
                $perms = Get-LabRolePermissionSet -Role $m.role
                Add-PASSafeMember -SafeName $safe.name -MemberName $m.name @perms
            }
            continue
        }
        $mismatches = @(Compare-LabRolePermission -Role $m.role -ActualPermissions $member[0].Permissions)
        foreach ($mm in $mismatches) {
            $issue = if ($mm.Kind -eq 'Extra') { 'EXTRA_PERM' } else { 'MISSING_PERM' }
            Add-Drift 'Permission' "$($safe.name)/$($m.name)" $issue $mm.Permission
        }
        if ($mismatches.Count -and $Apply -and $PSCmdlet.ShouldProcess("$($safe.name)/$($m.name)", "Reset permissions to role '$($m.role)'")) {
            Write-Status "    resetting $($m.name) to exactly '$($m.role)'" Yellow
            $perms = Get-LabRolePermissionSet -Role $m.role
            Set-PASSafeMember -SafeName $safe.name -MemberName $m.name @perms
        }
    }

    $declaredNames = @($declared | ForEach-Object { $_.name })
    foreach ($lm in $live) {
        if ($lm.MemberName -notin $declaredNames) {
            Add-Drift 'Member' "$($safe.name)/$($lm.MemberName)" 'UNEXPECTED' 'not in the state file'
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Accounts. An account in the wrong safe or on the wrong platform is the
#    same class of problem as an undeclared member, so it is reconciled too.
# ---------------------------------------------------------------------------
$missingSafes = @($drift | Where-Object { $_.Type -eq 'Safe' -and $_.Issue -eq 'MISSING' } | ForEach-Object { $_.Name })
foreach ($acct in $accounts) {
    $label = "$($acct.safe)/$($acct.userName)@$($acct.address)"
    Write-Status "==> Account: $label"
    $found = @()
    if ($acct.safe -in $missingSafes) {
        # The safe was missing: without -Apply nothing in it can be read; with
        # -Apply it was created a moment ago and holds no accounts yet.
        Add-Drift 'Account' $label 'MISSING' "platform=$($acct.platformId); safe missing"
    } else {
        try {
            $found = @(Get-PASAccount -safeName $acct.safe -search "$($acct.userName) $($acct.address)" |
                    Where-Object { $_.userName -eq $acct.userName -and $_.address -eq $acct.address })
        } catch { Exit-Run "could not read accounts in '$($acct.safe)': $($_.Exception.Message)" }
        if ($found.Count -eq 0) { Add-Drift 'Account' $label 'MISSING' "platform=$($acct.platformId)" }
    }

    if ($found.Count -eq 0) {
        if ($Apply -and $PSCmdlet.ShouldProcess($label, 'Onboard account')) {
            Write-Status '    onboarding' Yellow
            # No secret: the CPM sets one on its first run. A real credential in
            # a state file would defeat the point.
            Add-PASAccount -SafeName $acct.safe -platformID $acct.platformId -address $acct.address `
                -userName $acct.userName -secretType password
        }
        continue
    }
    if ($found.Count -gt 1) {
        Add-Drift 'Account' $label 'DUPLICATE' "$($found.Count) accounts match"
    }
    foreach ($f in $found) {
        if ($f.platformId -ne $acct.platformId) {
            Add-Drift 'Account' $label 'WRONG_PLATFORM' "actual=$($f.platformId) expected=$($acct.platformId)"
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Report
# ---------------------------------------------------------------------------
if ($JsonPath) {
    $report = [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        stateFile    = (Resolve-Path -LiteralPath $IntendedStatePath).Path
        applied      = [bool]$Apply
        driftCount   = $drift.Count
        drift        = $drift
    }
    $dir = Split-Path -Parent $JsonPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonPath -Encoding utf8
}

if ($drift.Count -eq 0) {
    Write-Status 'IN SYNC: the vault matches the state file.' Green
    exit 0
}
Write-Status "DRIFT ($($drift.Count)):" Yellow
Write-Status ($drift | Format-Table -AutoSize | Out-String)
$worry = @($drift | Where-Object { $_.Issue -in 'UNEXPECTED', 'EXTRA_PERM' })
if ($worry.Count) {
    Write-Status "Investigate first: $($worry.Count) undeclared member(s) or excess permission(s)." Red
    Write-Status 'Removals are not automated: confirm each is unauthorised before revoking.' Red
}
if (-not $Apply) { Write-Status 'Re-run with -Apply to create what is missing and reset permissions to the declared role. Nothing is ever deleted.' }
exit 1
