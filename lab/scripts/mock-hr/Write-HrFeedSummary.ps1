<#
.SYNOPSIS
    Tells the story of one HR-feed run in plain English: who was hired, who
    left, who moved, what Microsoft did with each, and what happens next.
    Waits (bounded) for the Entra provisioning log to confirm each person.

.DESCRIPTION
    The last step of .github/workflows/hr-feed.yml. Its audience is someone
    who is not an identity engineer: the top of the summary is one line per
    person, e.g.

        ## HR change sent to Microsoft
        - **Hired:** Sam Rivera, Cloud Engineer (Information Technology) - account created in Active Directory
        - **Left:** Dana Okafor, Registered Nurse (Nursing) - account switched off

    (the separator is an em dash, the arrow in a move is a real arrow)

        **Next:** Cloud Sync copies the change to Entra ID ...

    and the technical details (batches, HTTP status, provisioning actions)
    sit in a folded <details> block underneath.

    INPUTS
      -ChangesPath  Get-HrFeedChange.ps1 -OutputPath (who changed, in HR words)
      -ResultPath   Invoke-InboundProvisioning.ps1 -ResultPath (what was sent,
                    the guard outcome, each batch's HTTP status). Missing =
                    the send step never got that far.

    CONFIRMATION (only after a real send)
      bulkUpload answers 202 Accepted and processes asynchronously, so the
      script polls GET /auditLogs/provisioning for each person sent
      (jobid + sourceIdentity/id = the employeeId, the filter Microsoft's
      inbound-provisioning quickstart uses) until each has an entry logged
      at or after the send (sentAtUtc) or -WaitSeconds runs out. An entry
      from before the send is an EARLIER change to the same person (last
      push's hire must never confirm this push's departure), so it is
      ignored and polling goes on. Microsoft says these logs can lag
      several minutes: running out is reported as "not logged yet", never
      as a failure. Needs a Microsoft Graph connection (the workflow
      connects HR-SYNC app-only first) with a provisioning-log read role; a
      403 is reported as "log not readable" and the run still succeeds.

    PRIVACY
      Only first name, last name, job title and department are printed.
      Never the employee id, UPN, manager, dates or a provisioning error's
      free-text reason (it can carry a DN or UPN): the error CODE only.

    EXIT CODE
      1 when Microsoft logged a failure for anyone sent; otherwise 0. A
      refused, invalid or undelivered send has already failed its own step.

.PARAMETER WaitSeconds
    How long to wait for the provisioning log (default 180). 0 = look once.

.PARAMETER SignInOutcome
    The azure/login step's outcome (success / failure / skipped), so a run
    that could not sign in says so in plain English.

.EXAMPLE
    ./Write-HrFeedSummary.ps1 -ChangesPath ./changes.json -ResultPath ./sent.json -SummaryPath ./summary.md -WaitSeconds 0
#>

#Requires -Version 7.0
# Microsoft.Graph.Authentication is needed only to read the provisioning log
# after a real send (the workflow installs and connects it); a run that sent
# nothing writes its summary without it.
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ChangesPath,

    [Parameter()]
    [string]$ResultPath = '',

    [Parameter()]
    [string]$SummaryPath = $env:GITHUB_STEP_SUMMARY,

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$WaitSeconds = 180,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 20,

    [Parameter()]
    [string]$SignInOutcome = '',

    # Repo variables the one-time setup has not set yet (comma separated):
    # the run stopped before sending and the summary says what to set.
    [Parameter()]
    [string]$MissingSetup = '',

    # One-line context for the details block, e.g. "push to hr-feed, 1a2b3c4 -> 5d6e7f8".
    [Parameter()]
    [string]$TriggerText = '',

    [Parameter()]
    [ValidateRange(0, 100000)]
    [int]$MaxChanges = 10,

    [Parameter()]
    [ValidateSet('v1.0', 'beta')]
    [string]$GraphApiVersion = 'v1.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The summary's typography, built from code points so this file stays ASCII.
$Dash = [string][char]0x2014    # em dash between a person and what happened
$Arrow = [string][char]0x2192   # from -> to in a move

# =============================================================================
# PURE HELPERS (tests/Write-HrFeedSummary.Tests.ps1)
# =============================================================================
function Get-Field {
    # Property from a hashtable (Invoke-MgGraphRequest, ConvertFrom-Json
    # -AsHashtable) or an object, '' / $null-safe under StrictMode.
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = if ($cur.Contains($p)) { $cur[$p] } else { $null } }
        elseif ($cur.PSObject.Properties[$p]) { $cur = $cur.$p }
        else { return $null }
    }
    return $cur
}

function Get-PersonText {
    # "Sam Rivera, Cloud Engineer (Information Technology)"; a move shows
    # from -> to. Names, title and department only.
    param([Parameter(Mandatory)]$Change)
    $name = ('{0} {1}' -f (Get-Field $Change 'givenName'), (Get-Field $Change 'surname')).Trim()
    $title = [string](Get-Field $Change 'jobTitle'); $dept = [string](Get-Field $Change 'dept')
    $oldTitle = [string](Get-Field $Change 'previous', 'jobTitle'); $oldDept = [string](Get-Field $Change 'previous', 'dept')
    if ((Get-Field $Change 'kind') -eq 'moved' -and (Get-Field $Change 'previous')) {
        if ($oldTitle -eq $title) { return "$name, $title`: $oldDept $Arrow $dept" }
        if ($oldDept -eq $dept) { return "$name, $oldTitle $Arrow $title ($dept)" }
        return "$name, $oldTitle ($oldDept) $Arrow $title ($dept)"
    }
    $role = (@($title, $(if ($dept) { "($dept)" } else { '' })) | Where-Object { $_ }) -join ' '
    if ($role) { return "$name, $role" }
    return $name
}

function ConvertTo-UtcTime {
    # A timestamp as JSON readers hand it over (ConvertFrom-Json and
    # Invoke-MgGraphRequest turn ISO-8601 strings into [datetime]; anything
    # else stays a string) -> a UTC [datetime], or $null when there is none
    # or it does not parse. No zone = UTC: both producers write UTC.
    param($Value)
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ($Value -and [datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function Select-SendEntry {
    # The provisioning-log entries that can belong to THIS send of one
    # person: theirs (sourceIdentity/id), logged at or after the send.
    # Why time and not the upload's own id: bulkUpload answers 202 with an
    # empty body, its Location header is the job-wide log filter (jobid eq
    # ...), and a log entry carries no bulkId or request id, so nothing
    # ties an entry to one upload. sentAtUtc is taken (whole seconds,
    # rounded down) just before the first POST, and Microsoft logs a record
    # only after it has received it, so an entry for this send is never
    # older than sentAtUtc - except by clock skew between the runner and
    # Microsoft (both NTP-synced, well under a second): -ClockSkewSeconds
    # (5) covers that. An entry with no time is never taken: it cannot be
    # shown to be this send's.
    # What time cannot tell apart: an EARLIER send of the same person that
    # Microsoft only logs after this send started. Runs are queued one at a
    # time and each waits for its own confirmation, so that needs the
    # earlier entry to arrive later than the earlier run's whole wait (that
    # run's summary then said "not logged yet").
    param([object[]]$Entries = @(), [Parameter(Mandatory)][string]$EmployeeId, [Parameter(Mandatory)][datetime]$SentAtUtc, [ValidateRange(0, 60)][int]$ClockSkewSeconds = 5)
    $from = $SentAtUtc.AddSeconds(-$ClockSkewSeconds)
    return @($Entries | Where-Object {
            $_ -and [string](Get-Field $_ 'sourceIdentity', 'id') -eq $EmployeeId -and $(
                $when = ConvertTo-UtcTime (Get-Field $_ 'activityDateTime')
                $null -ne $when -and $when -ge $from)
        })
}

function Resolve-ProvisioningOutcome {
    # The provisioning-log entries for ONE person (newer than the send) ->
    # one outcome. A success wins (a create next to a follow-up manager
    # update is "created"); then failure, warning, skipped; none = pending.
    param([object[]]$Entries = @())
    $entries = @($Entries | Where-Object { $_ })
    if (-not $entries) { return @{ state = 'pending'; action = ''; errorCode = '' } }
    $rank = @{ create = 1; disable = 2; enable = 3; delete = 4; stageddelete = 5; update = 6; other = 7 }
    $byStatus = { param($s) @($entries | Where-Object { ([string](Get-Field $_ 'provisioningStatusInfo', 'status')).ToLowerInvariant() -eq $s }) }
    # @(): one match would otherwise unroll to the bare hashtable, and [0] on a
    # hashtable is a key lookup, not the first entry.
    $ok = @(& $byStatus 'success')
    if ($ok) {
        $best = $ok | Sort-Object { $a = ([string](Get-Field $_ 'provisioningAction')).ToLowerInvariant(); if ($rank.ContainsKey($a)) { $rank[$a] } else { 9 } } | Select-Object -First 1
        return @{ state = 'success'; action = ([string](Get-Field $best 'provisioningAction')).ToLowerInvariant(); errorCode = '' }
    }
    foreach ($s in 'failure', 'warning', 'skipped') {
        $hit = @(& $byStatus $s)
        if ($hit) {
            return @{ state = $s; action = ([string](Get-Field $hit[0] 'provisioningAction')).ToLowerInvariant(); errorCode = [string](Get-Field $hit[0] 'provisioningStatusInfo', 'errorInformation', 'errorCode') }
        }
    }
    return @{ state = 'other'; action = ''; errorCode = '' }
}

function Get-OutcomeText {
    # What happened to one person, in plain words. $Mode: dry-run | sent |
    # not-sent; $Outcome from Resolve-ProvisioningOutcome (or pending /
    # unreadable / undelivered).
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Mode, [hashtable]$Outcome = @{ state = 'pending' })
    if ($Kind -eq 'removed') { return 'nothing sent: deleting a row does not switch an account off (mark the person as a leaver instead)' }
    if ($Outcome.state -eq 'held') { return 'held back by the safety check: NOT sent (see above)' }
    if ($Outcome.state -eq 'undelivered') { return 'not delivered: Microsoft refused this batch' }
    if ($Mode -eq 'dry-run') {
        switch ($Kind) {
            'hired' { return 'would create the account in Active Directory' }
            'left' { return 'would switch the account off' }
            'rehired' { return 'would switch the account back on' }
            'moved' { return 'would update the department or job title in Active Directory' }
            default { return 'would update the details in Active Directory' }
        }
    }
    if ($Mode -ne 'sent') { return 'not sent' }
    switch ($Outcome.state) {
        'success' {
            switch ($Kind) {
                'hired' { if ($Outcome.action -eq 'create') { return 'account created in Active Directory' } return 'account was already in Active Directory; its details were updated' }
                'left' { return 'account switched off' }
                'rehired' { return 'account switched back on' }
                'moved' { return 'Active Directory updated with the new role' }
                default { return 'details updated in Active Directory' }
            }
        }
        'skipped' { return 'Microsoft made no change (Active Directory already matched, or the person is outside the HR app''s scope)' }
        'warning' { return 'applied with a warning (see the provisioning log)' }
        'failure' { $code = if ($Outcome.errorCode) { " (error $($Outcome.errorCode))" } else { '' }; return "Microsoft could not apply it$code; see the provisioning log" }
        'unreadable' { return 'sent; the result could not be read from the provisioning log' }
        default { return 'sent; Microsoft has not logged it yet (its log can lag a few minutes)' }
    }
}

function Get-KindLabel {
    param([string]$Kind)
    switch ($Kind) { 'hired' { 'Hired' } 'left' { 'Left' } 'rehired' { 'Back' } 'moved' { 'Moved' } 'removed' { 'Removed from the HR file' } default { 'Updated' } }
}

function Get-ProvisioningLogLink {
    # The HR app's provisioning page in the Entra admin center (the link the
    # demo recording opens; "Provisioning logs" is in its left menu). The
    # app (client) id is the last segment of the job id: <template>.<tenant>.<appId>.
    param([string]$JobId, [string]$ServicePrincipalId)
    $appId = ([string]$JobId -split '\.')[-1]
    if ($ServicePrincipalId -and $appId -match '^[0-9a-fA-F-]{36}$') {
        return "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/appId/$appId/objectId/$ServicePrincipalId"
    }
    return 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview'
}

function Get-RefusalText {
    param($Refusal, [int]$Threshold)
    $kind = [string](Get-Field $Refusal 'kind'); $count = Get-Field $Refusal 'count'
    # The send step records the threshold it really used (floor, percentage
    # of the population or 3 sigma of history); prefer it over the default.
    $t = Get-Field $Refusal 'threshold'
    if ($t) { $Threshold = [int]$t }
    switch ($kind) {
        'mass-disable' { return "This change would switch off **$count** people at once. The limit for this push is $Threshold, because a broken HR export looks exactly like a mass layoff, and switching off a ward mid-shift is the bigger harm. Those rows were held back (quarantined); the other rows were not stopped." }
        'mass-access-change' { return "This change would move **$count** people to a different department or job title at once. The limit for this push is ${Threshold}: access follows department and title, so a bad export would move or remove access for all of them. Those rows were held back (quarantined); the other rows were not stopped." }
        'bad-start-date' { return 'A new or current worker has no valid start date. It must look like 2026-11-09: the start date decides when day-one access begins.' }
        'bad-status' { return 'A row''s status is not one of joiner, active or leaver.' }
        'empty-field' { return 'A row is missing its employee ID, first name, last name or status.' }
        'missing-column' { return 'The header row (the first line) is missing a column.' }
        'no-rows' { return 'The file has no worker rows.' }
        'unknown-employee' { return 'An employee ID that was asked for is not in the HR file.' }
        default { return 'The HR file could not be sent as it is.' }
    }
}

# =============================================================================
# 1. LOAD WHAT CHANGED AND WHAT WAS SENT
# =============================================================================
$changes = @()
if (Test-Path -LiteralPath $ChangesPath -PathType Leaf) {
    $changes = @(Get-Content -LiteralPath $ChangesPath -Raw | ConvertFrom-Json -AsHashtable | ForEach-Object { $_ })
}
else { $changes = $null }
$result = if ($ResultPath -and (Test-Path -LiteralPath $ResultPath -PathType Leaf)) { Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json -AsHashtable } else { $null }

$outcome = if ($result) { [string]$result['outcome'] } else { '' }
$jobId = if ($result) { [string]$result['jobId'] } else { '' }
$spId = if ($result) { [string]$result['servicePrincipalId'] } else { '' }
$batches = if ($result) { @($result['batches'] | Where-Object { $_ }) } else { @() }
$acceptedIds = @($batches | Where-Object { $_['accepted'] } | ForEach-Object { @($_['employeeIds']) } | ForEach-Object { [string]$_ })
$undeliveredIds = @($batches | Where-Object { -not $_['accepted'] -and $_['httpStatus'] } | ForEach-Object { @($_['employeeIds']) } | ForEach-Object { [string]$_ })

# =============================================================================
# 2. WAIT FOR MICROSOFT TO CONFIRM (real sends only, bounded)
# =============================================================================
$personOutcome = @{}
$logNote = ''
$waited = 0
if ($acceptedIds -and $jobId -and $outcome -in 'sent', 'partial') {
    $ctx = $null
    if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) { try { $ctx = Get-MgContext } catch { $ctx = $null } }
    # Entries count from the send onwards (Select-SendEntry). No send time
    # in the result = no way to tell this send's entries from older ones:
    # say so rather than guess a window.
    $sentAt = ConvertTo-UtcTime $result['sentAtUtc']
    if (-not $ctx) { $logNote = 'not read: no Microsoft Graph sign-in in this step' }
    elseif (-not $sentAt) {
        $logNote = 'not readable: the send result has no send time, so older entries could not be told apart from this send'
        foreach ($id in $acceptedIds) { $personOutcome[$id] = @{ state = 'unreadable'; action = ''; errorCode = '' } }
    }
    else {
        $start = [datetime]::UtcNow
        $deadline = $start.AddSeconds($WaitSeconds)
        $open = [System.Collections.Generic.List[string]]::new(); foreach ($i in $acceptedIds) { $open.Add($i) }
        Write-Host "Waiting up to $WaitSeconds s for Microsoft's provisioning log to confirm $($open.Count) person(s)..." -ForegroundColor Cyan
        while ($true) {
            foreach ($id in @($open)) {
                $filter = "jobid eq '$jobId' and sourceIdentity/id eq '$id'"
                $uri = "https://graph.microsoft.com/$GraphApiVersion/auditLogs/provisioning?`$filter=$([uri]::EscapeDataString($filter))&`$top=50"
                try { $resp = Invoke-MgGraphRequest -Method GET -Uri $uri }
                catch {
                    $msg = [string]$_.Exception.Message
                    $logNote = if ($msg -match '403|Forbidden|Authorization_RequestDenied') { 'not readable: HR-SYNC has no provisioning-log read role yet (AuditLog.Read.All)' } else { 'not readable: the provisioning-log request failed (see this step''s log)' }
                    Write-Warning "Provisioning log read failed: $msg"
                    break
                }
                # Only entries from this send: an older one (last push's hire
                # for this push's departure) leaves the person open, and the
                # loop polls again.
                $entries = @(Select-SendEntry -Entries @(Get-Field $resp 'value') -EmployeeId $id -SentAtUtc $sentAt)
                $o = Resolve-ProvisioningOutcome -Entries $entries
                if ($o.state -ne 'pending') { $personOutcome[$id] = $o; [void]$open.Remove($id) }
            }
            if ($logNote -or $open.Count -eq 0 -or [datetime]::UtcNow -ge $deadline) { break }
            Start-Sleep -Seconds ([Math]::Min($PollSeconds, [Math]::Max(1, [int]($deadline - [datetime]::UtcNow).TotalSeconds)))
        }
        $waited = [int]([datetime]::UtcNow - $start).TotalSeconds
        if (-not $logNote) {
            $logNote = if ($open.Count -eq 0) { "read after $waited s" } else { "$($open.Count) not logged yet after $waited s (limit $WaitSeconds s; Microsoft's log can lag several minutes)" }
        }
        if ($logNote -like 'not readable*') { foreach ($id in $open) { $personOutcome[$id] = @{ state = 'unreadable'; action = ''; errorCode = '' } } }
    }
}
foreach ($id in $undeliveredIds) { $personOutcome[$id] = @{ state = 'undelivered'; action = ''; errorCode = '' } }

# =============================================================================
# 3. THE STORY (Markdown)
# =============================================================================
$md = [System.Collections.Generic.List[string]]::new()
$sendable = @($changes | Where-Object { $_ -and $_['send'] })
$removed = @($changes | Where-Object { $_ -and -not $_['send'] })
$mode = switch ($outcome) { 'dry-run' { 'dry-run' } { $_ -in 'sent', 'partial' } { 'sent' } default { 'not-sent' } }
$failedInLog = @($personOutcome.Values | Where-Object { $_.state -eq 'failure' }).Count

if ($null -eq $changes) {
    $md.Add('## HR change not sent: the change could not be read')
    $md.Add(''); $md.Add('The step that reads the change stopped first, and its log says why (a problem in the HR file, or GitHub could not tell which changes were already sent). Nothing was sent to Microsoft.')
}
elseif (-not $sendable -and -not $result) {
    $md.Add('## No HR change to send')
    $md.Add('')
    if (-not $removed) { $md.Add('This commit did not change any worker in the HR file (comments, blank lines or row order only). Nothing was sent.') }
}
elseif ($outcome -eq 'refused') {
    $md.Add('## HR change stopped by the safety check')
    $md.Add(''); $md.Add((Get-RefusalText $result['refusal'] $MaxChanges))
    $md.Add(''); $md.Add('**Nothing was sent.** Check the HR file. If this really is one reviewed change (a reorganisation, a site closing), add its change ticket to `lab/scripts/mock-hr/approved-bulk-changes.json` through a reviewed pull request, then send it with `-BulkChangeTicket`.')
}
elseif ($outcome -eq 'invalid') {
    $md.Add('## HR file not sent: it has a problem')
    $md.Add(''); $md.Add((Get-RefusalText $result['refusal'] $MaxChanges))
    $md.Add(''); $md.Add('**Nothing was sent.** Fix the row and push again; the step "Send the change to Microsoft" names it.')
}
elseif ($outcome -eq 'dry-run') {
    $md.Add('## HR change preview (dry run: nothing was sent)')
}
elseif ($outcome -eq 'sent') {
    $md.Add('## HR change sent to Microsoft')
}
elseif ($outcome -eq 'partial') {
    $md.Add('## HR change partly sent to Microsoft')
}
elseif ($outcome -eq 'failed') {
    $codes = @($batches | ForEach-Object { [int]$_['httpStatus'] } | Where-Object { $_ } | Select-Object -Unique)
    $md.Add('## HR change not delivered')
    $md.Add('')
    if ($codes -contains 403) { $md.Add('Microsoft refused the upload (HTTP 403): HR-SYNC is not allowed to send to the HR app yet. Finish its one-time setup (ownership of the HR app, admin consent): `lab/scripts/mock-hr/README.md`, "HR changes through GitHub Actions".') }
    elseif ($codes -contains 401) { $md.Add('Microsoft did not accept the sign-in token (HTTP 401). Re-run the workflow; if it repeats, check HR-SYNC''s setup.') }
    else { $md.Add("Microsoft did not accept the upload (HTTP $(if ($codes) { $codes -join ', ' } else { 'unknown' })). Nothing reached Active Directory; re-running is safe.") }
}
elseif ($MissingSetup) {
    $md.Add('## HR change not sent: the one-time setup is not finished')
    $md.Add(''); $md.Add("GitHub does not know where to send it yet. Missing repository variable(s): **$MissingSetup** (Settings > Secrets and variables > Actions > Variables). The steps are in ``lab/scripts/mock-hr/README.md``, ""HR changes through GitHub Actions"". Nothing was sent; push again once they are set.")
}
elseif ($SignInOutcome -eq 'failure') {
    $md.Add('## HR change not sent: GitHub could not sign in to Microsoft')
    $md.Add(''); $md.Add('The sign-in as HR-SYNC (GitHub OIDC, no password) was refused, so nothing was sent. Its one-time setup is in `lab/scripts/mock-hr/README.md`, "HR changes through GitHub Actions". Re-running is safe once it is done.')
}
else {
    $md.Add('## HR change not sent')
    $md.Add(''); $md.Add('The send step stopped before it reached Microsoft (see its log). Nothing was sent; re-running is safe.')
}

# Rows the mass-change guard held back while the rest went (review C2).
$held = @(if ($result -and $result['quarantined']) { $result['quarantined'] })
# Those workers were never sent: mark them so their line does not read
# "sent; Microsoft has not logged it yet" in a run whose other batches went.
foreach ($q in $held) { $qid = [string](Get-Field $q 'employeeId'); if ($qid) { $personOutcome[$qid] = @{ state = 'held'; action = ''; errorCode = '' } } }
$heldIds = @($held | ForEach-Object { [string](Get-Field $_ 'employeeId') })
if ($held.Count -and $outcome -ne 'refused') {
    $md.Add('')
    $md.Add("**Held back by the safety check: $($held.Count) row(s).** $((Get-RefusalText $result['refusal'] $MaxChanges))")
    $md.Add('An administrator checks the HR extract. A reviewed bulk event is re-sent with its change ticket (`-BulkChangeTicket`, listed in `lab/scripts/mock-hr/approved-bulk-changes.json` through a reviewed pull request).')
}

if ($changes) {
    $md.Add('')
    foreach ($c in @($sendable + $removed)) {
        $id = [string]$c['employeeId']
        $o = if ($personOutcome.ContainsKey($id)) { $personOutcome[$id] } else { @{ state = 'pending'; action = ''; errorCode = '' } }
        $md.Add(('- **{0}:** {1} {2} {3}' -f (Get-KindLabel $c['kind']), (Get-PersonText $c), $Dash, (Get-OutcomeText -Kind $c['kind'] -Mode $mode -Outcome $o)))
    }
}

if ($mode -eq 'sent') {
    $md.Add('')
    $md.Add('**Next:** Cloud Sync copies the change from Active Directory to Entra ID on its next run (about every 20 minutes); AWS follows by SCIM after that. Entra''s own rules (groups, access packages) then act on the new details.')
}
elseif ($mode -eq 'dry-run') {
    $md.Add('')
    $md.Add('**Next:** to send it for real, commit the change to the `hr-feed` branch and push (or run this workflow on `hr-feed` with dry run off).')
}
if ($jobId -and $mode -eq 'sent') {
    $md.Add('')
    $md.Add("[Open the HR app's provisioning page in Entra]($(Get-ProvisioningLogLink -JobId $jobId -ServicePrincipalId $spId)), then **Provisioning logs**.")
}

# Technical details, folded.
$leaversSent = @($sendable | Where-Object { $_['status'] -eq 'leaver' -and [string]$_['employeeId'] -notin $heldIds }).Count
$moversSent = @($sendable | Where-Object { $_['kind'] -eq 'moved' -and [string]$_['employeeId'] -notin $heldIds }).Count
$md.Add('')
$md.Add('<details><summary>Technical details</summary>')
$md.Add('')
if ($TriggerText) { $md.Add("- **Trigger:** $TriggerText") }
if ($null -ne $changes) { $md.Add("- **Rows in this change:** $($sendable.Count) to send, $($removed.Count) removed (never sent)") }
$md.Add("- **Safety check:** $leaversSent to switch off, $moversSent department/job-title change(s); limit at least $MaxChanges of each per push, or 1 percent of the staff if that is more$(if ($held.Count) { "; $($held.Count) row(s) held back" })")
if ($mode -eq 'dry-run') { $md.Add('- **Sign-in:** none (a dry run builds the payload and talks to nobody)') }
else { $md.Add("- **Signed in as:** HR-SYNC over GitHub OIDC, no stored secret (sign-in: $(if ($SignInOutcome) { $SignInOutcome } else { 'not attempted' }))") }
if ($batches) {
    $template = ([string]$jobId -split '\.')[0]
    $b = @($batches | ForEach-Object { "batch $($_['index']): $($_['records']) record(s), $(if ($_['accepted']) { "HTTP $($_['httpStatus']) accepted" } elseif ($_['httpStatus']) { "HTTP $($_['httpStatus']) refused" } else { 'not sent (dry run)' })" }) -join '; '
    $md.Add("- **SCIM bulkUpload** (``POST /servicePrincipals/{id}/synchronization/jobs/{jobId}/bulkUpload``, ``application/scim+json``, job template ``$template``): $b")
}
if ($personOutcome.Count -or $logNote) {
    $md.Add("- **Provisioning log** (``GET /auditLogs/provisioning``): $(if ($logNote) { $logNote } else { 'not read' })")
    foreach ($c in $sendable) {
        $id = [string]$c['employeeId']
        if ($personOutcome.ContainsKey($id)) {
            $o = $personOutcome[$id]
            $md.Add("  - $(('{0} {1}' -f $c['givenName'], $c['surname']).Trim()): $($o.state)$(if ($o.action) { ", action $($o.action)" })$(if ($o.errorCode) { ", error code $($o.errorCode)" })")
        }
    }
}
$md.Add('- **Path:** HR file (GitHub) -> Entra API-driven inbound provisioning -> provisioning agent -> Active Directory on DC01 -> Cloud Sync -> Entra ID -> SCIM -> AWS')
$md.Add('')
$md.Add('</details>')

$text = ($md -join "`n") + "`n"
if ($SummaryPath) { Add-Content -LiteralPath $SummaryPath -Value $text -Encoding utf8NoBOM }
Write-Host $text
if ($failedInLog -gt 0) { exit 1 }
exit 0
