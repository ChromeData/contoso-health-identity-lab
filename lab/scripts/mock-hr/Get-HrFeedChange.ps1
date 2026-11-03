<#
.SYNOPSIS
    What changed in the HR feed, in HR words: compares hr_feed.csv with an
    earlier version of it and lists who was hired, who left, who moved, who
    came back, whose details changed and which rows were deleted.

.DESCRIPTION
    The first step of .github/workflows/hr-feed.yml. A push to the hr-feed
    branch sends ONLY the rows it changed, so the provisioning log, the
    mass-change guard and the run summary all talk about exactly those people.

    Rows are matched on employeeId; every column is compared (trimmed).
    Comment lines, blank lines and row order do not count as changes.

      kind      when                                              sent?
      --------  ------------------------------------------------  -----
      hired     new row, status joiner or active                  yes
      left      status became leaver (or a new row as leaver)     yes (active=false)
      rehired   status was leaver, now joiner or active           yes
      moved     department or job title changed (not a leaver)    yes
      updated   anything else (name, manager, dates, joiner ->
                active)                                           yes
      removed   row deleted                                       NO: deleting a row
                                                                  is not a leaver;
                                                                  HR marks leavers

    -EmployeeId (workflow_dispatch) lists exactly those rows, changed or not:
    a row that differs from the previous version gets its diff kind, any
    other its status kind (joiner = hired, active = updated, leaver = left).
    With no previous version every row is listed by its status kind.

    -BaselineStatePath writes the PREVIOUS version's department / job title
    per worker in the shape Invoke-InboundProvisioning.ps1 -StatePath reads,
    so its access-change guard compares this push against the file it
    replaces (the gitignored .state/ file does not exist on a runner).

    Output: one object per change; -OutputPath also writes them as JSON. The
    JSON holds names, department and job title (the run summary prints
    those) plus employeeId and status (to select rows); it stays in the
    runner's temp folder.

.PARAMETER CsvPath
    The feed as it is now.

.PARAMETER PreviousCsvPath
    The feed before the change. Empty or missing = list every row of CsvPath
    by its status (no diff).

.PARAMETER EmployeeId
    List only these workers (workflow_dispatch). An id that is not in CsvPath
    stops the run.

.EXAMPLE
    git show HEAD~1:lab/scripts/mock-hr/hr_feed.csv > prev.csv
    ./Get-HrFeedChange.ps1 -CsvPath ./hr_feed.csv -PreviousCsvPath prev.csv | Format-Table kind, givenName, surname, dept
#>

#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "CsvPath '$_' not found." }; $true })]
    [string]$CsvPath,

    [Parameter()]
    [string]$PreviousCsvPath = '',

    [Parameter()]
    [ValidatePattern('^\d+$', ErrorMessage = 'EmployeeId values are numeric worker ids.')]
    [string[]]$EmployeeId = @(),

    [Parameter()]
    [string]$OutputPath = '',

    [Parameter()]
    [string]$BaselineStatePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Columns = 'employeeId', 'givenName', 'surname', 'dept', 'jobTitle', 'manager', 'status', 'startDate', 'endDate'

function Read-HrFeed {
    # The same reading rules as Invoke-InboundProvisioning.ps1: '#' comment
    # lines and blank lines dropped, header row first. Returns an ordered
    # employeeId -> row map; a duplicate id stops the run (which row is HR's?).
    param([Parameter(Mandatory)][string]$Path)
    $lines = @(Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' })
    $map = [ordered]@{}
    if ($lines.Count -lt 2) { return $map }
    foreach ($r in @($lines | ConvertFrom-Csv)) {
        $id = ([string]$r.employeeId).Trim()
        if (-not $id) { continue }
        if ($map.Contains($id)) { throw "employeeId $id appears more than once in '$Path'. Fix the HR file: one row per worker." }
        $row = [ordered]@{}
        foreach ($c in $Columns) { $row[$c] = if ($r.PSObject.Properties[$c]) { ([string]$r.$c).Trim() } else { '' } }
        $map[$id] = $row
    }
    return $map
}

function Get-KindFromStatus {
    param([string]$Status)
    switch ($Status) { 'joiner' { 'hired' } 'leaver' { 'left' } default { 'updated' } }
}

function Get-ChangeKind {
    # One worker's change between two versions of the row (either may be $null).
    param([System.Collections.IDictionary]$Old, [System.Collections.IDictionary]$New)
    if (-not $New) { return 'removed' }
    if (-not $Old) { return $(if ($New['status'] -eq 'leaver') { 'left' } else { 'hired' }) }
    $wasLeaver = $Old['status'] -eq 'leaver'
    $isLeaver = $New['status'] -eq 'leaver'
    if (-not $wasLeaver -and $isLeaver) { return 'left' }
    if ($wasLeaver -and -not $isLeaver) { return 'rehired' }
    if (-not $isLeaver -and ($Old['dept'] -ne $New['dept'] -or $Old['jobTitle'] -ne $New['jobTitle'])) { return 'moved' }
    return 'updated'
}

function New-ChangeRecord {
    param([string]$Id, [string]$Kind, [System.Collections.IDictionary]$Old, [System.Collections.IDictionary]$New)
    $cur = if ($New) { $New } else { $Old }
    $changed = @(if ($Old -and $New) { $Columns | Where-Object { $Old[$_] -ne $New[$_] } })
    [pscustomobject][ordered]@{
        employeeId    = $Id
        kind          = $Kind
        send          = ($Kind -ne 'removed')
        givenName     = $cur['givenName']
        surname       = $cur['surname']
        dept          = $cur['dept']
        jobTitle      = $cur['jobTitle']
        status        = $cur['status']
        previous      = if ($Old) { [ordered]@{ dept = $Old['dept']; jobTitle = $Old['jobTitle']; status = $Old['status'] } } else { $null }
        changedFields = $changed
    }
}

$current = Read-HrFeed -Path $CsvPath
$havePrevious = $PreviousCsvPath -and (Test-Path -LiteralPath $PreviousCsvPath -PathType Leaf)
$previous = if ($havePrevious) { Read-HrFeed -Path $PreviousCsvPath } else { [ordered]@{} }

$changes = [System.Collections.Generic.List[object]]::new()
if ($EmployeeId.Count -gt 0) {
    $unknown = @($EmployeeId | Where-Object { -not $current.Contains($_) })
    if ($unknown) { throw "EmployeeId(s) not in '$CsvPath': $($unknown -join ', ')." }
    foreach ($id in ($EmployeeId | Select-Object -Unique)) {
        $old = if ($previous.Contains($id)) { $previous[$id] } else { $null }
        $new = $current[$id]
        $differs = $havePrevious -and (-not $old -or @($Columns | Where-Object { $old[$_] -ne $new[$_] }))
        $kind = if ($differs) { Get-ChangeKind -Old $old -New $new } else { Get-KindFromStatus $new['status'] }
        $changes.Add((New-ChangeRecord -Id $id -Kind $kind -Old $(if ($differs) { $old } else { $null }) -New $new))
    }
}
elseif (-not $havePrevious) {
    foreach ($id in $current.Keys) {
        $changes.Add((New-ChangeRecord -Id $id -Kind (Get-KindFromStatus $current[$id]['status']) -New $current[$id]))
    }
}
else {
    foreach ($id in $current.Keys) {
        $old = if ($previous.Contains($id)) { $previous[$id] } else { $null }
        $new = $current[$id]
        if ($old -and -not @($Columns | Where-Object { $old[$_] -ne $new[$_] })) { continue }   # unchanged
        $changes.Add((New-ChangeRecord -Id $id -Kind (Get-ChangeKind -Old $old -New $new) -Old $old -New $new))
    }
    foreach ($id in $previous.Keys) {
        if (-not $current.Contains($id)) { $changes.Add((New-ChangeRecord -Id $id -Kind 'removed' -Old $previous[$id])) }
    }
}

if ($OutputPath) {
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ConvertTo-Json -InputObject @($changes) -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
}
if ($BaselineStatePath) {
    # Invoke-InboundProvisioning.ps1 -StatePath shape: employeeId -> { dept, jobTitle }.
    $baseline = [ordered]@{}
    foreach ($id in $previous.Keys) { $baseline[$id] = [ordered]@{ dept = $previous[$id]['dept']; jobTitle = $previous[$id]['jobTitle'] } }
    $dir = Split-Path -Parent $BaselineStatePath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ($baseline | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $BaselineStatePath -Encoding utf8NoBOM
}

$changes
