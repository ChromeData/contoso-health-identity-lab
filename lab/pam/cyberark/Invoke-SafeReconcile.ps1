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
  run with exit 2, a code drift never uses. Every read finishes before -Apply
  writes anything, so a failed read never leaves a half-applied run. Any
  other failure (a write the vault rejects, a state file of the wrong shape)
  is exit 2 as well; a rejected write can follow earlier successful ones,
  and the run's output names the step that failed. The earlier version wrapped every
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

# Everything below runs inside one error boundary: any failure the code
# does not expect (a rejected write, a bad file shape, a psPAS error outside
# a read) ends with exit 2, never with PowerShell's default exit 1, which is
# the "drift found" code. Exit-Run itself calls exit, which is not an error,
# so it passes through.
try {
    Import-Module psPAS
    Import-Module (Join-Path $PSScriptRoot 'RoleMap.psm1') -Force

    # -----------------------------------------------------------------------
    # 1. Validate the state file BEFORE touching the vault. An unknown role
    #    reaching the write path would create a member with no permissions,
    #    which looks like success.
    # -----------------------------------------------------------------------
    try {
        $intended = Get-Content -Raw -LiteralPath $IntendedStatePath | ConvertFrom-Json -AsHashtable
    } catch {
        Exit-Run "cannot read state file '$IntendedStatePath': $($_.Exception.Message)"
    }
    if ($intended -isnot [System.Collections.IDictionary]) {
        Exit-Run "state file '$IntendedStatePath' must be a JSON object with 'safes' and 'accounts'"
    }
    $problems = [System.Collections.Generic.List[string]]::new()
    $validRoles = Get-LabRoleName
    $safes = @(if ($intended.Contains('safes')) { $intended['safes'] })
    $accounts = @(if ($intended.Contains('accounts')) { $intended['accounts'] })
    foreach ($x in @($safes + $accounts)) {
        if ($x -isnot [System.Collections.IDictionary]) { $problems.Add("a safe or account entry is not an object: $x") }
    }
    if ($problems.Count) { Exit-Run ("state file invalid:`n  " + ($problems -join "`n  ")) }

    $safeNames = @()
    foreach ($safe in $safes) {
        if (-not $safe['name']) { $problems.Add('a safe entry has no name'); continue }
        # Two entries for one safe could give one member two roles, and every
        # run would then reset it back and forth.
        if ($safe['name'] -in $safeNames) { $problems.Add("safe '$($safe.name)' is declared twice") }
        $safeNames += $safe['name']
        $memberNames = @()
        foreach ($m in @($safe['members'])) {
            if ($null -eq $m) { continue }
            if ($m -isnot [System.Collections.IDictionary]) { $problems.Add("safe '$($safe.name)': a member is not an object"); continue }
            if (-not $m['name']) { $problems.Add("safe '$($safe.name)': a member has no name") }
            elseif ($m['role'] -notin $validRoles) {
                $problems.Add("safe '$($safe.name)' member '$($m.name)' has unknown role '$($m['role'])'. Valid: $($validRoles -join ', ')")
            }
            if ($m['name'] -in $memberNames) { $problems.Add("safe '$($safe.name)': member '$($m.name)' is declared twice") }
            $memberNames += $m['name']
        }
    }
    $accountKeys = @()
    foreach ($a in $accounts) {
        foreach ($field in 'safe', 'platformId', 'address', 'userName') {
            if (-not $a[$field]) { $problems.Add("an account entry has no $field") }
        }
        if ($a['safe'] -and $a['safe'] -notin $safeNames) {
            $problems.Add("account $($a['userName'])@$($a['address']) names safe '$($a['safe'])', which the file does not declare")
        }
        # Declared twice, -Apply would onboard it twice: the very DUPLICATE
        # this script exists to report.
        $key = "$($a['safe'])/$($a['userName'])@$($a['address'])"
        if ($key -in $accountKeys) { $problems.Add("account $key is declared twice") }
        $accountKeys += $key
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
    # What -Apply would do, collected while reading. NOTHING is written until
    # every read has succeeded, so a failed read can never leave a half-applied
    # run behind (exit 2 always means "no writes").
    $plan = [System.Collections.Generic.List[object]]::new()
    function Add-Plan($Target, $What, [scriptblock]$Do) {
        $plan.Add([pscustomobject]@{ Target = $Target; What = $What; Do = $Do })
    }

    # -----------------------------------------------------------------------
    # 2. Read: safes and membership
    # -----------------------------------------------------------------------
    $missingSafes = @()
    foreach ($safe in $safes) {
        Write-Status "==> Safe: $($safe.name)"
        $safeName = [string]$safe['name']
        $exists = $true
        try { $null = Get-PASSafe -SafeName $safeName }
        catch {
            if (-not (Test-NotFound $_)) { Exit-Run "could not read safe '$safeName': $($_.Exception.Message)" }
            $exists = $false
        }
        $declared = @(@($safe['members']) | Where-Object { $_ })

        $live = @()
        if ($exists) {
            try { $live = @(Get-PASSafeMember -SafeName $safeName) }
            catch { Exit-Run "could not read the members of '$safeName': $($_.Exception.Message)" }
        } else {
            Add-Drift 'Safe' $safeName 'MISSING'
            $missingSafes += $safeName
            $desc = [string]$safe['description']; $cpm = [string]$safe['managingCPM']
            Add-Plan $safeName 'Create safe' { Add-PASSafe -SafeName $safeName -Description $desc -ManagingCPM $cpm }.GetNewClosure()
        }

        foreach ($m in $declared) {
            $memberName = [string]$m['name']; $role = [string]$m['role']
            $member = @($live | Where-Object { $_.MemberName -eq $memberName })
            if (-not $member) {
                # A member of a safe that is still missing is not reported
                # separately: nothing about the safe can be read yet.
                if ($exists) { Add-Drift 'Member' "$safeName/$memberName" 'MISSING' "role=$role" }
                $perms = Get-LabRolePermissionSet -Role $role
                Add-Plan "$safeName/$memberName" "Add member as '$role'" { Add-PASSafeMember -SafeName $safeName -MemberName $memberName @perms }.GetNewClosure()
                continue
            }
            $mismatches = @(Compare-LabRolePermission -Role $role -ActualPermissions $member[0].Permissions)
            foreach ($mm in $mismatches) {
                $issue = if ($mm.Kind -eq 'Extra') { 'EXTRA_PERM' } else { 'MISSING_PERM' }
                Add-Drift 'Permission' "$safeName/$memberName" $issue $mm.Permission
            }
            if ($mismatches.Count) {
                $perms = Get-LabRolePermissionSet -Role $role
                Add-Plan "$safeName/$memberName" "Reset permissions to role '$role'" { Set-PASSafeMember -SafeName $safeName -MemberName $memberName @perms }.GetNewClosure()
            }
        }

        $declaredNames = @($declared | ForEach-Object { $_['name'] })
        foreach ($lm in $live) {
            if ($lm.MemberName -notin $declaredNames) {
                Add-Drift 'Member' "$safeName/$($lm.MemberName)" 'UNEXPECTED' 'not in the state file'
            }
        }
    }

    # -----------------------------------------------------------------------
    # 3. Read: accounts. An account in the wrong safe or on the wrong platform
    #    is the same class of problem as an undeclared member.
    # -----------------------------------------------------------------------
    foreach ($acct in $accounts) {
        $aSafe = [string]$acct['safe']; $aUser = [string]$acct['userName']
        $aAddr = [string]$acct['address']; $aPlat = [string]$acct['platformId']
        $label = "$aSafe/$aUser@$aAddr"
        Write-Status "==> Account: $label"
        $found = @()
        if ($aSafe -in $missingSafes) {
            Add-Drift 'Account' $label 'MISSING' "platform=$aPlat; safe missing"
        } else {
            try {
                $found = @(Get-PASAccount -safeName $aSafe -search "$aUser $aAddr" |
                        Where-Object { $_.userName -eq $aUser -and $_.address -eq $aAddr })
            } catch { Exit-Run "could not read accounts in '$aSafe': $($_.Exception.Message)" }
            if ($found.Count -eq 0) { Add-Drift 'Account' $label 'MISSING' "platform=$aPlat" }
        }
        if ($found.Count -eq 0) {
            # No secret: the CPM sets one on its first run. A real credential in
            # a state file would defeat the point.
            Add-Plan $label 'Onboard account' { Add-PASAccount -SafeName $aSafe -platformID $aPlat -address $aAddr -userName $aUser -secretType password }.GetNewClosure()
            continue
        }
        if ($found.Count -gt 1) { Add-Drift 'Account' $label 'DUPLICATE' "$($found.Count) accounts match" }
        foreach ($f in $found) {
            if ($f.platformId -ne $aPlat) { Add-Drift 'Account' $label 'WRONG_PLATFORM' "actual=$($f.platformId) expected=$aPlat" }
        }
    }

    # -----------------------------------------------------------------------
    # 4. Apply, only now that every read has succeeded. In plan order: a safe
    #    is created before its members and accounts.
    # -----------------------------------------------------------------------
    if ($Apply) {
        foreach ($step in $plan) {
            if ($PSCmdlet.ShouldProcess($step.Target, $step.What)) {
                Write-Status "    $($step.What): $($step.Target)" Yellow
                & $step.Do
            }
        }
    }

    # -----------------------------------------------------------------------
    # 5. Report, most worrying first (the order in the header), then by name.
    # -----------------------------------------------------------------------
    $priority = @{ UNEXPECTED = 0; EXTRA_PERM = 1; DUPLICATE = 2; WRONG_PLATFORM = 3; MISSING = 4; MISSING_PERM = 5 }
    $sorted = @($drift | Sort-Object -Property @{ Expression = { $priority[$_.Issue] } }, Name, Detail)
    if ($JsonPath) {
        $report = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            stateFile    = (Resolve-Path -LiteralPath $IntendedStatePath).Path
            applied      = [bool]$Apply
            driftCount   = $sorted.Count
            drift        = $sorted
        }
        $dir = Split-Path -Parent $JsonPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonPath -Encoding utf8
    }
} catch {
    Exit-Run "unexpected error: $($_.Exception.Message)"
}

if ($sorted.Count -eq 0) {
    Write-Status 'IN SYNC: the vault matches the state file.' Green
    exit 0
}
Write-Status "DRIFT ($($sorted.Count)), most worrying first:" Yellow
Write-Status ($sorted | Format-Table -AutoSize | Out-String)
$worry = @($sorted | Where-Object { $_.Issue -in 'UNEXPECTED', 'EXTRA_PERM' })
if ($worry.Count) {
    Write-Status "Investigate first: $($worry.Count) undeclared member(s) or excess permission(s)." Red
    Write-Status 'Removals are not automated: confirm each is unauthorised before revoking.' Red
}
if (-not $Apply) { Write-Status 'Re-run with -Apply to create what is missing and reset permissions to the declared role. Nothing is ever deleted.' }
exit 1
