<#
.SYNOPSIS
    Conditional Access restore drill: snapshot every CA policy, detect drift
    against a snapshot, and restore one policy from it - timed, with a
    restore record written next to the snapshots. Read-only unless -Mode
    Restore with -Apply.

.DESCRIPTION
    WHY: Terraform is the lab's source of truth for CA001-CA010, CA020,
    CA022 and CA060, so "restore" is normally `terraform apply` from main.
    Two cases need more: a policy an attacker or an emergency change deleted
    or weakened before the pipeline could run (the ca-policy-changed.kql
    incident), and policies that live outside the provider (CA021, written by
    Set-AuthContextPolicies.ps1 from a Terraform-rendered body; the CA011
    token-protection pilot; Microsoft-managed policies). The drill proves the
    team can put a known-good policy back, and how long it takes (RTO).

    PRODUCT PATH: Microsoft Entra Backup and Recovery (preview) keeps
    tenant-side backups of CA policies and other objects and restores them
    from the portal or Graph. verify: availability and API in the trial tenant
    before relying on it; this script does not call it. It implements the
    same drill with a snapshot the lab controls, so the drill runs either way:
      Snapshot  GET /identity/conditionalAccess/policies -> <OutDir>/
                ca-policies-<utc>.json + .sha256 (upload to the WORM store,
                lab/terraform/modules/evidence-store, like every capture)
      Compare   current vs a snapshot: per policy, state / exclusions /
                grant / session drift, and policies added or missing
      Restore   one policy (-PolicyName) back to its snapshot: PATCH the
                writable fields (displayName, state, conditions,
                grantControls, sessionControls) if it exists, POST it if it
                was deleted. Only with -Apply (staging switch, default off);
                -WhatIf honoured. Prints the time from start to verified
                re-read and writes the restore record (policy, action,
                verified, RTO seconds, snapshot file + sha256 - no ids) to
                <OutDir>/ca-restore-<utc>.json (gitignored lab/evidence/out).

    RESTORE GUARDS (a snapshot is only as trustworthy as the moment it was
    taken - it may hold an attacker's or an emergency edit, or be hand-edited):
      * the .sha256 sidecar MUST exist and match (Compare tolerates a missing
        one; Restore does not);
      * the restored body MUST exclude Break-Glass-Admins (resolved by
        mailNickname): every other CA-writing script refuses a policy that
        could apply to break-glass, and so does this one;
      * re-creating a DELETED policy in state "enabled" needs a second switch
        (-AllowEnabledRecreate): a restore must not turn on an enforced
        policy that nobody has looked at since the snapshot.

    Every restore is re-read and compared; a mismatch is a FAIL.

    TENANT-TIME: nothing here has run against a tenant. verify (first drill):
      * a v1.0 GET -> PATCH/POST round trip of the Graph-managed CA011
        (sessionControls.secureSignInSession) and CA021
        (applications.includeAuthenticationContextClassReferences, documented
        under beta) keeps those fields - if v1.0 drops them, restore those two
        by re-running Set-TokenProtectionPolicy.ps1 / Set-AuthContextPolicies.ps1;
      * Microsoft Entra Backup and Recovery availability in the trial tenant
        (above).

.PARAMETER Mode
    Snapshot (default), Compare or Restore.

.PARAMETER SnapshotPath
    Compare / Restore: the snapshot JSON written by -Mode Snapshot.

.PARAMETER PolicyName
    Restore: the display name of the one policy to restore.

.PARAMETER Apply
    Restore only: actually write. Without it Restore prints the plan.

.PARAMETER AllowEnabledRecreate
    Restore only: allow re-creating a deleted policy whose snapshot state is
    "enabled" (second switch, see RESTORE GUARDS).

.PARAMETER BreakGlassGroupMailNickname
    Default break-glass-admins (Terraform contract).

.PARAMETER OutDir
    Snapshot and restore-record folder. Default lab/evidence/out/ca-restore
    (gitignored).

.EXAMPLE
    Connect-MgGraph -Scopes 'Policy.Read.All'
    ./Invoke-CaRestoreDrill.ps1 -Mode Snapshot
    # (drill: weaken a report-only policy's exclusions in the portal)
    ./Invoke-CaRestoreDrill.ps1 -Mode Compare -SnapshotPath ../../evidence/out/ca-restore/ca-policies-<utc>.json
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.ConditionalAccess'
    ./Invoke-CaRestoreDrill.ps1 -Mode Restore -SnapshotPath <file> -PolicyName 'CA004 - Block sign-in from blocked countries' -Apply

.GRAPH SCOPES  (delegated)
    Policy.Read.All; Group.Read.All (Restore: resolve Break-Glass-Admins);
    Policy.ReadWrite.ConditionalAccess for Restore -Apply.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('Snapshot', 'Compare', 'Restore')]
    [string]$Mode = 'Snapshot',

    [Parameter()]
    [string]$SnapshotPath = '',

    [Parameter()]
    [string]$PolicyName = '',

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [switch]$AllowEnabledRecreate,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [string]$OutDir = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'ca-restore')
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$caUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
$WritableFields = @('displayName', 'state', 'conditions', 'grantControls', 'sessionControls')

function Get-PolicyShape {
    # Pure: the writable part of a policy as canonical JSON (keys sorted,
    # nulls kept) - what a restore writes and what drift compares.
    param([System.Collections.IDictionary]$Policy)
    $o = [ordered]@{}
    foreach ($f in $WritableFields) { if ($Policy.Contains($f)) { $o[$f] = $Policy[$f] } }
    return (ConvertTo-SortedJson $o)
}

function ConvertTo-SortedJson {
    param($Value)
    function ConvertTo-SortedNode($v) {
        if ($v -is [System.Collections.IDictionary]) {
            $n = [ordered]@{}; foreach ($k in @($v.Keys | Sort-Object)) { $n[$k] = ConvertTo-SortedNode $v[$k] }; return $n
        }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { return , @(foreach ($i in $v) { ConvertTo-SortedNode $i }) }
        return $v
    }
    return (ConvertTo-SortedNode $Value | ConvertTo-Json -Depth 20 -Compress)
}

function Compare-CaSnapshot {
    # Pure: snapshot policies vs current policies (both lists of hashtables).
    param([object[]]$Snapshot, [object[]]$Current)
    $rows = @()
    $cur = @{}; foreach ($p in $Current) { $cur[[string]$p['displayName']] = $p }
    $snap = @{}; foreach ($p in $Snapshot) { $snap[[string]$p['displayName']] = $p }
    foreach ($name in @($snap.Keys | Sort-Object)) {
        if (-not $cur.ContainsKey($name)) { $rows += [pscustomobject]@{ Policy = $name; Status = 'MISSING'; Fields = 'deleted since the snapshot' }; continue }
        $diff = @(foreach ($f in $WritableFields) {
                if ((ConvertTo-SortedJson $snap[$name][$f]) -ne (ConvertTo-SortedJson $cur[$name][$f])) { $f }
            })
        $rows += [pscustomobject]@{ Policy = $name; Status = $(if ($diff) { 'DRIFT' } else { 'same' }); Fields = ($diff -join ',') }
    }
    foreach ($name in @($cur.Keys | Where-Object { -not $snap.ContainsKey($_) } | Sort-Object)) {
        $rows += [pscustomobject]@{ Policy = $name; Status = 'ADDED'; Fields = 'not in the snapshot' }
    }
    return $rows
}

function Get-CurrentPolicy { return @(@((Invoke-MgGraphRequest -Method GET -Uri $caUri)['value']) | Where-Object { $null -ne $_ }) }

function Test-RestoreBody {
    # Pure: every reason a snapshot body must not be written back. Empty = ok.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Body, [Parameter(Mandatory)][string]$BreakGlassGroupId, [bool]$Recreate, [bool]$AllowEnabledRecreate)
    $why = @()
    $ex = $null
    if ($Body.Contains('conditions') -and $Body['conditions'] -is [System.Collections.IDictionary] -and $Body['conditions'].Contains('users') -and $Body['conditions']['users'] -is [System.Collections.IDictionary] -and $Body['conditions']['users'].Contains('excludeGroups')) {
        $ex = @($Body['conditions']['users']['excludeGroups'])
    }
    if (-not $ex -or $BreakGlassGroupId -notin $ex) { $why += 'the snapshot body does not exclude Break-Glass-Admins - restoring it could apply the policy to break-glass (lockout)' }
    if ($Recreate -and [string]$Body['state'] -eq 'enabled' -and -not $AllowEnabledRecreate) { $why += 're-creating a DELETED policy as ENFORCED needs -AllowEnabledRecreate (or restore it, then graduate it through review)' }
    return @($why)
}

function Read-Snapshot([string]$Path, [switch]$RequireSidecar) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { throw "-SnapshotPath '$Path' not found (run -Mode Snapshot first)." }
    $hashFile = "$Path.sha256"
    if ($RequireSidecar -and -not (Test-Path -LiteralPath $hashFile)) { throw "Snapshot $Path has no .sha256 sidecar - refusing to restore from a file whose integrity cannot be checked." }
    if (Test-Path -LiteralPath $hashFile) {
        $want = ((Get-Content -Raw -LiteralPath $hashFile) -split '\s+')[0]
        $have = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        if ($want -ne $have) { throw "Snapshot $Path does not match its .sha256 - refusing to restore from a modified file." }
    }
    return @((Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable)['policies'])
}

switch ($Mode) {
    'Snapshot' {
        $policies = Get-CurrentPolicy
        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        $file = Join-Path $OutDir "ca-policies-$stamp.json"
        @{ takenAtUtc = $stamp; count = $policies.Count; policies = $policies } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $file -Encoding utf8
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        Set-Content -LiteralPath "$file.sha256" -Value "$hash  $(Split-Path $file -Leaf)"
        Write-Console "[PASS] snapshot of $($policies.Count) CA policies: $file (sha256 $hash)" -ForegroundColor Green
        return [pscustomobject]@{ Path = $file; Sha256 = $hash; Count = $policies.Count }
    }
    'Compare' {
        $rows = Compare-CaSnapshot -Snapshot (Read-Snapshot $SnapshotPath) -Current (Get-CurrentPolicy)
        $rows | Format-Table -AutoSize | Out-Host
        if (@($rows | Where-Object Status -NE 'same').Count) { Write-Console '[WARN] drift since the snapshot' -ForegroundColor Yellow }
        return $rows
    }
    'Restore' {
        if (-not $PolicyName) { throw 'Restore needs -PolicyName (one policy per drill).' }
        $start = Get-Date
        $snap = @(Read-Snapshot $SnapshotPath -RequireSidecar | Where-Object { [string]$_['displayName'] -eq $PolicyName })
        if ($snap.Count -ne 1) { throw "Policy '$PolicyName' is not (exactly once) in the snapshot." }
        $body = [ordered]@{}; foreach ($f in $WritableFields) { if ($snap[0].Contains($f)) { $body[$f] = $snap[0][$f] } }
        $live = @(Get-CurrentPolicy | Where-Object { [string]$_['displayName'] -eq $PolicyName })
        $verb = if ($live.Count -eq 1) { 'PATCH' } else { 'POST' }
        # Guards BEFORE any write (and before the plan is shown as restorable).
        $bf = [uri]::EscapeDataString("mailNickname eq '$BreakGlassGroupMailNickname'")
        $bg = @(@((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$bf&`$select=id")['value']) | Where-Object { $null -ne $_ })
        if ($bg.Count -ne 1) { throw "Break-glass group '$BreakGlassGroupMailNickname' resolved $($bg.Count) time(s); refusing to restore without it." }
        $why = @(Test-RestoreBody -Body $body -BreakGlassGroupId ([string]$bg[0]['id']) -Recreate ($verb -eq 'POST') -AllowEnabledRecreate $AllowEnabledRecreate.IsPresent)
        if ($why.Count) { throw "Refusing to restore '$PolicyName': $($why -join '; '). Nothing was written." }
        if ($live.Count -eq 1 -and (Get-PolicyShape $live[0]) -eq (Get-PolicyShape $snap[0])) {
            Write-Console "[PASS] '$PolicyName' already matches the snapshot - nothing to restore" -ForegroundColor Green
            return
        }
        Write-Console "[INFO] '$PolicyName': $verb from the snapshot" -ForegroundColor Yellow
        if (-not $Apply) { Write-Console '[WARN] plan only (re-run with -Apply)' -ForegroundColor Yellow; return }
        if (-not $PSCmdlet.ShouldProcess($PolicyName, "$verb Conditional Access policy from snapshot")) { return }
        $json = $body | ConvertTo-Json -Depth 20
        if ($verb -eq 'PATCH') { Invoke-MgGraphRequest -Method PATCH -Uri "$caUri/$($live[0]['id'])" -Body $json -ContentType 'application/json' | Out-Null }
        else { Invoke-MgGraphRequest -Method POST -Uri $caUri -Body $json -ContentType 'application/json' | Out-Null }
        $after = @(Get-CurrentPolicy | Where-Object { [string]$_['displayName'] -eq $PolicyName })
        $ok = $after.Count -eq 1 -and (Get-PolicyShape $after[0]) -eq (Get-PolicyShape $snap[0])
        $rto = [int]((Get-Date) - $start).TotalSeconds
        if ($ok) { Write-Console "[PASS] '$PolicyName' restored and verified by re-read in $rto s" -ForegroundColor Green }
        else { Write-Console "[FAIL] '$PolicyName' re-read still differs from the snapshot" -ForegroundColor Red }
        $record = [pscustomobject]@{ Policy = $PolicyName; Action = $verb; Verified = $ok; RtoSeconds = $rto; Snapshot = (Split-Path $SnapshotPath -Leaf)
            SnapshotSha256 = (Get-FileHash -LiteralPath $SnapshotPath -Algorithm SHA256).Hash; RestoredAtUtc = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') }
        # The restore record (no ids, no tenant data) next to the snapshots.
        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
        $recFile = Join-Path $OutDir "ca-restore-$($record.RestoredAtUtc).json"
        ($record | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $recFile -Encoding utf8
        Write-Console "[INFO] restore record: $recFile" -ForegroundColor DarkGray
        if (-not $ok) { $record; exit 1 }
        return $record
    }
}
