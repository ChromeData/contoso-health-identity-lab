<#
.SYNOPSIS
    Reads the mock HR roster (hr_feed.csv) and drives Entra ID API-driven
    inbound provisioning by POSTing SCIM-shaped bulkUpload payloads to the
    provisioning job's /bulkUpload endpoint.

.DESCRIPTION
    This is the "HR system -> Entra" integration point for the Contoso Health
    identity lab (video segment 2, "Joiner: HR -> AD -> Entra").

    It stands in for Workday / SAP SuccessFactors. Those products use Entra's
    native gallery connectors, which pull worker data from the HR API. This
    script uses the API-driven path instead: it translates worker records into
    SCIM 2.0 Enterprise User objects and bulk POSTs them to a provisioning job
    you created from the

        "API-driven provisioning to on-premises Active Directory"  (hybrid), or
        "API-driven provisioning to Microsoft Entra ID"            (cloud-only)

    gallery application. The template is the standing-up step (done once in the
    Entra admin center or Terraform); this script is the recurring data push.

    FLOW
      1. Load + validate hr_feed.csv (comment lines stripped).
      2. Map each row -> SCIM Enterprise User object.
      3. Chunk rows into batches of <= 50 (hard service limit, see NOTES).
      4. For each batch, build a SCIM BulkRequest and POST it to
         /servicePrincipals/{spId}/synchronization/jobs/{jobId}/bulkUpload.
      5. Each POST returns 202 Accepted; the provisioning service processes the
         records asynchronously. Poll provisioning logs / the job schedule to
         confirm landing (this script reports the submit result, not the async
         outcome -- query /auditLogs/provisioning afterward, or the Entra
         "Provisioning logs" blade).

    IDEMPOTENCY
      Re-running is safe. The provisioning engine matches on a configured
      anchor (default: externalId == employeeId) and performs an upsert, so a
      given employeeId creates once and updates thereafter. 'leaver' rows are
      sent with active=false, which the engine maps to disable/soft-delete per
      your job's attribute mapping and deprovisioning settings.

.PREREQUISITES
    * Entra ID P1 or P2 on the tenant. API-driven inbound provisioning is a
      Premium feature; it does NOT run on the free tier. (Lifecycle Workflows
      used later in 02-Joiner.ps1 additionally need Entra ID Governance -- but
      the raw inbound provisioning here needs only P1/P2.)
    * A provisioning job already created from the API-driven template, and its
      owning service principal object id + job id (the two IDs this script
      takes as parameters). Get them with:
          Get-MgServicePrincipal -Filter "displayName eq '<your app name>'"
          Get-MgServicePrincipalSynchronizationJob -ServicePrincipalId <spId>
    * Microsoft.Graph.Authentication module (Connect-MgGraph / Invoke-MgGraphRequest).
    * A caller allowed to POST to /bulkUpload (GRAPH SCOPES below). Two ways in:
        - DELEGATED (interactive, lab default): SynchronizationData-User.Upload
          consented, and the signed-in user must hold User Administrator.
        - APP-ONLY (-UseAzureCliToken, the pipeline path): the Azure CLI is
          already signed in as an app - in GitHub Actions, azure/login over
          OIDC as HR-SYNC (.github/workflows/hr-feed.yml) - and the script
          takes a Microsoft Graph token from it. No secret anywhere; the
          token stays in this process (masked in Actions), never in argv,
          a file or the output.

.GRAPH SCOPES  (Microsoft Graph, per the bulkUpload API reference)
    One of these, with admin consent:
      SynchronizationData-User.Upload.OwnedBy  application, least privileged:
                                      the calling app owns / created the
                                      provisioning app.
      SynchronizationData-User.Upload application, broader (any provisioning
                                      app in the tenant).
      SynchronizationData-User.Upload delegated (what this script's interactive
                                      Connect-MgGraph uses): the signed-in user
                                      must ALSO hold User Administrator, or the
                                      POST returns 403.
    (read-back, optional, for the post-submit poll you run separately:)
    AuditLog.Read.All + Directory.Read.All   to read /auditLogs/provisioning
                                      (verify: ProvisioningLog.Read.All, which
                                      the grant-access tutorial uses)
    Synchronization.Read.All          to read job status / schedule

    API version: this endpoint lives under BOTH /v1.0 and /beta. The SCIM bulk
    schema is identical. This script targets /v1.0 by default (see $GraphApiVersion).

.PARAMETER ServicePrincipalId
    Object id (GUID) of the service principal backing the API-driven
    provisioning application. PLACEHOLDER below -- override per tenant.

.PARAMETER JobId
    Synchronization job id of that provisioning app (looks like
    "<templateName>.<guid>"). PLACEHOLDER below -- override per tenant.

.PARAMETER CsvPath
    Path to hr_feed.csv. Defaults to the copy that ships next to this script.

.PARAMETER StatusFilter
    Which lifecycle rows to push. Default pushes everything. Narrow to e.g.
    'joiner' for a clean segment-2 onboarding demo.

.PARAMETER UpnDomain
    Verified custom domain the synthesized UPNs use (given.surname@<UpnDomain>).
    For the hybrid path it must also be an AD UPN suffix. Default is the lab
    placeholder contosohealth.io - pass your real domain.

.PARAMETER MaxChanges
    Mass-change guard (risk register R10), applied to TWO counts separately:
      * DISABLING records (status leaver, sent as active=false);
      * ACCESS-CHANGING records: active/joiner rows whose dept or jobTitle
        differ from the last roster this script pushed successfully
        (-StatePath). Birthright clinical access (Nurse / ICU packages, the
        All-Nurses / All-ICU groups) now FOLLOWS department and job title
        automatically, so a bad export that moves a ward to 'Billing' would
        strip their clinical access on the next evaluation just as surely as
        a mass disable.
    This is the FLOOR of the threshold (default 10). The threshold used is the
    LARGEST of: this floor, -MaxChangePercent of the population, and (when a
    -ChangeHistoryPath file has at least 7 days) the mean + 3 standard
    deviations of the last 30 days. WHY: a fixed count does not scale. A
    20,000-person hospital has about 15 leavers on a normal day, so a fixed 10
    trips every Monday and people learn to override it (review finding C2).
    Over the threshold, the rows of that kind are QUARANTINED: they are held
    back and written to -QuarantinePath, every other row is still sent, and
    the run ends with an error so the pipeline step fails visibly. WHY hold
    back all of them and not "the first N": in a bad export nobody knows which
    N are real, and disabling N wrong people mid-shift is the harm the guard
    exists to stop. This matches what Entra's own provisioning "accidental
    deletions" threshold does: it holds the deletions and lets the other
    changes through.

.PARAMETER MaxChangePercent
    Percentage of the population (joiner + active rows in the WHOLE validated
    feed, before -EmployeeId or -StatusFilter) that one run may disable or
    move. Default 1 (1 percent: 200 people at 20,000, 50 at 5,000). 0 turns
    the percentage part off.

.PARAMETER ChangeHistoryPath
    Optional JSON history of earlier successful runs: an array of
    { "date": "YYYY-MM-DD", "disabling": n, "accessChanges": n }. With at least
    7 days inside the last 30, the threshold may rise to mean + 3 sigma of that
    kind, so a hospital's normal Monday does not trip it. A real send with no
    failed batch appends today's counts. The GitHub pipeline runs on a fresh
    runner and passes no history (only the floor and the percentage apply);
    a scheduled HR extract host keeps one. Unreadable = stop, never "no history".

.PARAMETER BulkChangeTicket
    A reviewed bulk event (a reorganisation, a site closing) by its change
    ticket, for example CHG0040021. The ticket must be listed in
    -ApprovedBulkChangesPath (a file that only changes through a reviewed pull
    request) with its kind, a maximum count and an expiry date. If it is, that
    kind's guard allows up to the listed count. If it is not listed, expired or
    too small, the guard acts as if no ticket was given (quarantine), and says
    why. This replaces "-Force on trust" for planned bulk events.

.PARAMETER ApprovedBulkChangesPath
    The reviewed allow-list for -BulkChangeTicket. Default
    approved-bulk-changes.json next to this script. Schema
    approved-bulk-changes/1: { "changes": [ { "ticket", "kind"
    (disable | access-change), "maxCount", "expires" (YYYY-MM-DD, inclusive),
    "reason" } ] }.

.PARAMETER QuarantinePath
    Where held-back rows are written (employeeId, status and the guard kind
    only: no names). Default .state/quarantine-<UTC time>.json next to this
    script (gitignored).

.PARAMETER StatePath
    The last roster pushed WITHOUT a failed batch (employeeId -> dept,
    jobTitle), the baseline for the access-changing count. Default
    .state/last-pushed-roster.json next to this script (gitignored: it holds
    worker ids and titles). Written only after a real send with no failed
    batch - never under -WhatIf. Missing = first run: nothing to compare, so
    the access-changing count is 0 (stated in the output).

.PARAMETER Force
    Push even when the mass-change guard trips (nothing is quarantined). The
    manual emergency override for an administrator at a console; a planned
    bulk event uses -BulkChangeTicket instead, so the approval is on record.
    The run still prints how many accounts it will disable.

.PARAMETER EmployeeId
    Send only these workers (employeeId). The whole feed is still loaded and
    validated first, and an id that is not in the feed stops the run before
    anything is sent. The pipeline passes the rows that changed in a push
    (Get-HrFeedChange.ps1), so the mass-change guard counts exactly the
    people that push would disable or move.

.PARAMETER UseAzureCliToken
    App-only sign-in for pipelines: take a Microsoft Graph token from the
    Azure CLI session (`az account get-access-token --resource-type ms-graph`)
    and connect with it. Only used when something is actually sent (never
    under -WhatIf).

.PARAMETER ResultPath
    Write a machine-readable result (JSON) for the run summary
    (Write-HrFeedSummary.ps1): the selected rows (employeeId + status only),
    the guard outcome, each batch's HTTP status, and when the send started.
    Written on every outcome: dry run, refused by the guard, sent, failed.

.PARAMETER HidePayload
    Print one line per batch instead of the SCIM JSON. For pipeline logs: the
    payload carries user names (UPNs), employee and manager ids and hire
    dates, which a run log does not need.

.PARAMETER WhatIf
    Standard. With -WhatIf the script builds and prints the SCIM payloads but
    performs NO POST -- use this to review exactly what would be sent (great on
    camera, and the safe default while you have no tenant).

.EXAMPLE
    # Dry run -- build payloads, print them, send nothing:
    ./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -WhatIf

.EXAMPLE
    # Push only new hires (segment-2 demo):
    ./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -StatusFilter joiner

.EXAMPLE
    # Pipeline (hr-feed.yml): app-only, only the changed rows, no payload echo:
    ./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain> `
        -EmployeeId 400104 -UseAzureCliToken -HidePayload -ResultPath ./sent.json -Confirm:$false

.EXAMPLE
    # Full roster sync (what a scheduled HR extract job would push):
    Connect-MgGraph -Scopes 'SynchronizationData-User.Upload'
    ./Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId>

.WHAT IT DEMONSTRATES
    HR as the single source of truth: a flat worker feed becomes Entra identities
    with no manual group adds or tickets. Shows the documented endpoint any HR
    source or HR ISV pushes to, the SCIM Enterprise User contract, the 50-record
    batching rule, and service auth via a single purpose-built Graph permission.

.NOTES
    50-RECORD LIMIT: the /bulkUpload endpoint accepts at most 50 Operations per
    request. Larger rosters MUST be chunked; this script does that automatically
    ($MaxBatchSize). Sending >50 returns HTTP 400.

    CONTENT TYPE: the body is SCIM, so the request Content-Type is
    'application/scim+json'. Invoke-MgGraphRequest is told this explicitly.

    This script was authored for a lab with no live tenant. It is deploy-ready
    but defaults to -WhatIf-friendly behavior and validates everything it can
    offline. Nothing here executes against a tenant until you supply real IDs
    and remove -WhatIf.

    Graph reference: "Quick-start API-driven inbound provisioning"
      POST /servicePrincipals/{id}/synchronization/jobs/{jobId}/bulkUpload
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # -----------------------------------------------------------------------
    # PLACEHOLDERS -- replace with your tenant's values (or pass at call time).
    # These two IDs come from the provisioning app you created from the
    # API-driven template; they are NOT secrets but ARE tenant-specific.
    # -----------------------------------------------------------------------
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$',
        ErrorMessage = 'ServicePrincipalId must be a GUID.')]
    [string]$ServicePrincipalId = '00000000-0000-0000-0000-000000000000',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    # Job id format is "<template>.<32 hex>" e.g. "AADProvisioningJob.<guid-no-dashes>"
    [string]$JobId = 'REPLACE_WITH_SYNC_JOB_ID',

    [Parameter()]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
            throw "CsvPath '$_' not found."
        }
        $true
    })]
    [string]$CsvPath = (Join-Path $PSScriptRoot 'hr_feed.csv'),

    [Parameter()]
    [ValidateSet('all', 'joiner', 'active', 'leaver')]
    [string]$StatusFilter = 'all',

    [Parameter()]
    [ValidateSet('v1.0', 'beta')]
    [string]$GraphApiVersion = 'v1.0',

    # Verified custom domain workforce UPNs are built on (given.surname@<this>).
    # Must also be a UPN suffix in AD for the hybrid (to-AD) provisioning path.
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
    [string]$UpnDomain = 'contosohealth.io',

    [Parameter()]
    [ValidateRange(0, 100000)]
    [int]$MaxChanges = 10,

    [Parameter()]
    [ValidateRange(0, 100)]
    [double]$MaxChangePercent = 1,

    [Parameter()]
    [string]$ChangeHistoryPath = '',

    [Parameter()]
    [ValidatePattern('^(CHG\d{7})?$', ErrorMessage = 'BulkChangeTicket is a change ticket number such as CHG0040021.')]
    [string]$BulkChangeTicket = '',

    [Parameter()]
    [string]$ApprovedBulkChangesPath = (Join-Path $PSScriptRoot 'approved-bulk-changes.json'),

    [Parameter()]
    [string]$QuarantinePath = (Join-Path $PSScriptRoot '.state' ('quarantine-' + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '.json')),

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$StatePath = (Join-Path $PSScriptRoot '.state' 'last-pushed-roster.json'),

    # Only these workers (employeeId); the pipeline passes the changed rows.
    [Parameter()]
    [ValidatePattern('^\d+$', ErrorMessage = 'EmployeeId values are numeric worker ids.')]
    [string[]]$EmployeeId = @(),

    # App-only sign-in from the Azure CLI session (azure/login over OIDC).
    [Parameter()]
    [switch]$UseAzureCliToken,

    # Machine-readable result for the run summary (Write-HrFeedSummary.ps1).
    [Parameter()]
    [string]$ResultPath = '',

    # One line per batch instead of the SCIM JSON (pipeline logs).
    [Parameter()]
    [switch]$HidePayload
)

# --- Fail fast, surface every error, no silent $null property access. --------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Constants ---------------------------------------------------------------
# Hard service limit for the bulkUpload endpoint. Do not raise.
[int]$MaxBatchSize = 50
# SCIM schema URNs (RFC 7643/7644 + Microsoft bulk messages).
$SchemaBulkRequest    = 'urn:ietf:params:scim:api:messages:2.0:BulkRequest'
$SchemaCoreUser       = 'urn:ietf:params:scim:schemas:core:2.0:User'
$SchemaEnterpriseUser = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'
# Custom SCIM extension for attributes the core/enterprise schemas lack (Learn,
# API-driven inbound provisioning: "extend the SCIM schema"). hireDate carries
# hr_feed.csv startDate - every birthright rule (lab/iga/birthright-rules.json)
# requires user.employeeHireDate -le system.now, so without it nobody matches.
$SchemaContosoUser    = 'urn:ietf:params:scim:schemas:extension:contoso:1.0:User'
$BulkUploadUri        = "https://graph.microsoft.com/$GraphApiVersion/servicePrincipals/$ServicePrincipalId/synchronization/jobs/$JobId/bulkUpload"

Write-Verbose "Target endpoint: $BulkUploadUri"

# Run-result state for -ResultPath (Save-RunResult). Set before any check
# that can stop the run, so every outcome is recorded.
$script:SentAtUtc = $null
$script:BatchResults = [System.Collections.Generic.List[object]]::new()
# Rows held back by the mass-change guard (employeeId, status, kind only).
$script:Quarantined = [System.Collections.Generic.List[object]]::new()
$script:GuardRefusals = [System.Collections.Generic.List[object]]::new()

# =============================================================================
# PURE HELPERS (tests/Invoke-InboundProvisioning.Tests.ps1)
# =============================================================================
function ConvertTo-HireDate {
    # 'YYYY-MM-DD' -> 'YYYY-MM-DDT00:00:00Z' (ISO-8601 UTC), '' when invalid.
    # verify: the provisioning attribute mapping accepts this form for
    # employeeHireDate (cloud path) and FormatDateTime for the AD path.
    param([string]$Value)
    $d = [datetime]::MinValue
    if ($Value -match '^\d{4}-\d{2}-\d{2}$' -and [datetime]::TryParseExact($Value, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) {
        return $d.ToString('yyyy-MM-dd') + 'T00:00:00Z'
    }
    return ''
}

function Save-RunResult {
    # The run summary's input (-ResultPath). Holds employee ids and statuses,
    # never names, UPNs or payloads. No-op without -ResultPath.
    param([Parameter(Mandatory)][string]$Outcome, [object]$Refusal = $null, [switch]$NoSelection)
    if (-not $ResultPath) { return }
    $sel = @(if (-not $NoSelection -and (Test-Path variable:script:roster)) { $script:roster | ForEach-Object { [ordered]@{ employeeId = [string]$_.employeeId; status = [string]$_.status } } })
    $doc = [ordered]@{
        schema             = 'hr-feed-send/1'
        outcome            = $Outcome          # invalid | dry-run | nothing | refused | sent | partial | failed
        # A guard hold-back is recorded even when the other rows were sent.
        refusal            = $(if ($Refusal) { $Refusal } elseif ($script:GuardRefusals.Count) { $script:GuardRefusals[0] } else { $null })
        jobId              = $JobId
        servicePrincipalId = $ServicePrincipalId
        selected           = $sel
        sentAtUtc          = $script:SentAtUtc
        batches            = @($script:BatchResults)
        # Held back by the mass-change guard (ids + status only, no names).
        quarantined        = @($script:Quarantined)
        guard              = @($script:GuardRefusals)
    }
    # -WhatIf:$false: the result is the dry run's own report, not a change
    # to anything (under -WhatIf, Set-Content would otherwise skip it).
    $dir = Split-Path -Parent $ResultPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
    ($doc | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $ResultPath -Encoding utf8NoBOM -WhatIf:$false
}

function Stop-InvalidFeed {
    # A feed the script refuses to send: record it for the summary, then stop.
    # $Kind is what the summary explains in plain English; the message (with
    # the row's employeeId) stays in the log.
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Message)
    Save-RunResult -Outcome 'invalid' -Refusal ([ordered]@{ kind = $Kind }) -NoSelection
    throw $Message
}

function Get-HttpStatusFromError {
    # HTTP status of a failed Invoke-MgGraphRequest, or 0 when unknown.
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $resp = $null
    try { $resp = $ErrorRecord.Exception.Response } catch { $resp = $null }
    if ($resp -and $resp.PSObject.Properties['StatusCode']) { return [int]$resp.StatusCode }
    $m = [regex]::Match([string]$ErrorRecord.Exception.Message, '\b(400|401|403|404|409|429|500|502|503)\b')
    if ($m.Success) { return [int]$m.Value }
    return 0
}

function Connect-GraphFromAzureCli {
    # App-only: the Azure CLI is already signed in as an app (azure/login over
    # GitHub OIDC). The token never leaves this process: masked in Actions,
    # handed to Connect-MgGraph as a SecureString, then dropped.
    $global:LASTEXITCODE = 0
    $token = az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$token)) {
        throw 'No Microsoft Graph token from the Azure CLI. Sign it in first (azure/login with OIDC in GitHub Actions, or az login locally).'
    }
    $token = ([string]$token).Trim()
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host "::add-mask::$token" }
    # NetworkCredential.SecurePassword: the same SecureString as
    # ConvertTo-SecureString -AsPlainText, without the analyzer error rule.
    Connect-MgGraph -AccessToken ([System.Net.NetworkCredential]::new('', $token).SecurePassword) -NoWelcome | Out-Null
    Remove-Variable -Name token
}

function Get-AccessChange {
    # Rows (joiner/active) whose dept or jobTitle differ from the baseline
    # (employeeId -> @{ dept; jobTitle }). New workers are not changes.
    param([object[]]$Rows = @(), [System.Collections.IDictionary]$Baseline = @{})
    return @(foreach ($r in @($Rows | Where-Object { $_ -and $_.status -ne 'leaver' })) {
            $id = [string]$r.employeeId
            if (-not $Baseline.Contains($id)) { continue }
            $b = $Baseline[$id]
            if ([string]$b['dept'] -ne [string]$r.dept -or [string]$b['jobTitle'] -ne [string]$r.jobTitle) {
                [pscustomobject]@{ employeeId = $id; From = "$($b['dept']) / $($b['jobTitle'])"; To = "$($r.dept) / $($r.jobTitle)" }
            }
        })
}


function Get-ChangeThreshold {
    # The mass-change threshold for one kind: the largest of the floor
    # (-MaxChanges), a percentage of the population, and mean + 3 sigma of the
    # recent history (>= 7 days inside the last 30). Returns the number and a
    # plain-English "why" for the log and the summary.
    param(
        [int]$Floor,
        [double]$Percent,
        [int]$Population,
        [double[]]$History = @()
    )
    $parts = [ordered]@{ floor = $Floor }
    $t = $Floor
    if ($Percent -gt 0 -and $Population -gt 0) {
        $p = [int][Math]::Ceiling($Population * $Percent / 100.0)
        $parts['percent'] = $p
        if ($p -gt $t) { $t = $p }
    }
    if (@($History).Count -ge 7) {
        $h = @($History)
        $mean = ($h | Measure-Object -Average).Average
        $var = ($h | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Sum).Sum / $h.Count
        $sig = [int][Math]::Ceiling($mean + 3 * [Math]::Sqrt($var))
        $parts['threeSigma'] = $sig
        if ($sig -gt $t) { $t = $sig }
    }
    return [pscustomobject]@{ Threshold = $t; Parts = $parts }
}

function Read-ChangeHistory {
    # Counts of earlier successful runs inside the last 30 days, per kind.
    # An unreadable file stops the run: "couldn't read" is never "no history".
    param([string]$Path, [datetime]$Today = [datetime]::UtcNow.Date)
    $out = @{ disabling = @(); accessChanges = @() }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $out }
    try { $rows = @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable) }
    catch { throw "ChangeHistoryPath '$Path' is unreadable ($($_.Exception.Message)). Fix it, or pass no -ChangeHistoryPath." }
    $d = [datetime]::MinValue
    $recent = @($rows | Where-Object {
            $_ -and [datetime]::TryParseExact([string]$_['date'], 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d) -and
            $d -le $Today -and $d -gt $Today.AddDays(-30)
        })
    $out.disabling = @($recent | ForEach-Object { [double]$_['disabling'] })
    $out.accessChanges = @($recent | ForEach-Object { [double]$_['accessChanges'] })
    return $out
}

function Test-ApprovedBulkChange {
    # Is -BulkChangeTicket a reviewed, unexpired bulk event of this kind that
    # covers $Count rows? Returns @{ Approved; Why }. Fails closed: a missing
    # or unreadable list approves nothing.
    param([string]$Ticket, [string]$Kind, [int]$Count, [string]$Path, [datetime]$Today = [datetime]::UtcNow.Date)
    if (-not $Ticket) { return [pscustomobject]@{ Approved = $false; Why = 'no change ticket given' } }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{ Approved = $false; Why = "ticket $Ticket given, but the reviewed list '$Path' does not exist" } }
    try { $doc = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable }
    catch { return [pscustomobject]@{ Approved = $false; Why = "ticket $Ticket given, but the reviewed list is unreadable ($($_.Exception.Message))" } }
    $entry = @(@($doc['changes']) | Where-Object { $_ -and [string]$_['ticket'] -eq $Ticket -and [string]$_['kind'] -eq $Kind }) | Select-Object -First 1
    if (-not $entry) { return [pscustomobject]@{ Approved = $false; Why = "ticket $Ticket is not in the reviewed list for kind '$Kind'" } }
    $exp = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$entry['expires'], 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$exp)) {
        return [pscustomobject]@{ Approved = $false; Why = "ticket $Ticket has no valid expiry date in the reviewed list" }
    }
    if ($Today -gt $exp) { return [pscustomobject]@{ Approved = $false; Why = "ticket $Ticket expired on $($exp.ToString('yyyy-MM-dd'))" } }
    if ($Count -gt [int]$entry['maxCount']) { return [pscustomobject]@{ Approved = $false; Why = "ticket $Ticket allows $([int]$entry['maxCount']), this run has $Count" } }
    return [pscustomobject]@{ Approved = $true; Why = "reviewed bulk change $Ticket (up to $([int]$entry['maxCount']), until $($exp.ToString('yyyy-MM-dd')))" }
}

function ConvertTo-UpnLocalPart {
    # 'Jose', "O'Brien" -> 'jose', 'obrien': decompose accents (FormD), drop
    # the combining marks, keep a-z, 0-9 and '-' only, lower case. WHY: an
    # apostrophe or accent gives an invalid or odd UPN, and AD's
    # sAMAccountName and SAML NameIDs downstream expect plain ASCII.
    # Returns '' when nothing usable is left (the caller refuses the row).
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $d = $Value.Normalize([System.Text.NormalizationForm]::FormD)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($ch in $d.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) { [void]$sb.Append($ch) }
    }
    $s = $sb.ToString().ToLowerInvariant()
    # Letters that do not decompose (o-stroke, sharp s, ae, l-stroke, dotless i).
    $map = @{ ([char]0x00F8) = 'o'; ([char]0x00DF) = 'ss'; ([char]0x00E6) = 'ae'; ([char]0x0142) = 'l'; ([char]0x0131) = 'i'; ([char]0x0111) = 'd'; ([char]0x00F0) = 'd'; ([char]0x00FE) = 'th'; ([char]0x0153) = 'oe' }
    foreach ($k in $map.Keys) { $s = $s.Replace([string]$k, $map[$k]) }
    $s = [regex]::Replace($s, '[^a-z0-9-]', '')
    return $s.Trim('-')
}

function Resolve-UserName {
    # employeeId -> userName (UPN) for every row in the WHOLE feed.
    # 1. A row's own 'upn' column wins (the HR system issued it at hire and it
    #    never changes). It is validated, never re-derived.
    # 2. Otherwise the UPN is derived ONCE, deterministically: given.surname,
    #    ASCII-normalised, and a suffix digit (2, 3, ...) for a collision. The
    #    worker with the lower employeeId keeps the plain name, so the same
    #    feed always gives the same answer.
    # A name change does NOT rename the account: the provisioning app's
    # userPrincipalName / sAMAccountName mappings are set to "Apply this
    # mapping: Only during object creation" (lab/scripts/mock-hr/README.md,
    # "UPNs: issued once"). The engine matches on externalId (employeeId),
    # never on the name.
    param([Parameter(Mandatory)][object[]]$Rows, [Parameter(Mandatory)][string]$Domain)
    $map = [ordered]@{}
    $taken = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $hasUpnColumn = @($Rows[0].PSObject.Properties.Name) -contains 'upn'
    if ($hasUpnColumn) {
        foreach ($r in $Rows) {
            $u = ([string]$r.upn).Trim()
            if (-not $u) { continue }
            if ($u -notmatch '^[a-z0-9][a-z0-9.-]*@[a-z0-9.-]+\.[a-z]{2,}$') { throw "Row employeeId '$($r.employeeId)' has an invalid upn '$u' (lower-case ASCII local part @ domain)." }
            if (-not $taken.Add($u)) { throw "Two rows carry the same upn '$u'. A UPN belongs to one worker." }
            $map[[string]$r.employeeId] = $u.ToLowerInvariant()
        }
    }
    $pending = @($Rows | Where-Object { -not $map.Contains([string]$_.employeeId) } | Sort-Object { [long]$_.employeeId })
    foreach ($r in $pending) {
        $g = ConvertTo-UpnLocalPart $r.givenName; $f = ConvertTo-UpnLocalPart $r.surname
        if (-not $g -or -not $f) { throw "Row employeeId '$($r.employeeId)': the name leaves no usable ASCII for a UPN. Give the row a upn." }
        $base = "$g.$f"; $cand = "$base@$Domain"; $n = 1
        while ($taken.Contains($cand)) { $n++; $cand = "$base$n@$Domain" }
        [void]$taken.Add($cand)
        $map[[string]$r.employeeId] = $cand
    }
    return $map
}

# =============================================================================
# 1. LOAD + VALIDATE THE HR FEED
# =============================================================================
# Strip our '#' comment lines before Import-Csv (Import-Csv has no comment
# support). We keep the header line and all data lines.
$rawLines = Get-Content -LiteralPath $CsvPath
$dataLines = $rawLines | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne '' }
if (-not $dataLines -or @($dataLines).Count -lt 2) {
    Stop-InvalidFeed 'no-rows' "CsvPath '$CsvPath' has no data rows after stripping comments."
}
$roster = @($dataLines | ConvertFrom-Csv)   # @() keeps a one-row feed an array

# Validate required columns exist exactly once (fail loud on a malformed feed).
$requiredColumns = 'employeeId', 'givenName', 'surname', 'dept', 'jobTitle', 'manager', 'status', 'startDate', 'endDate'
$presentColumns  = $roster[0].PSObject.Properties.Name
$missing = $requiredColumns | Where-Object { $_ -notin $presentColumns }
if ($missing) {
    Stop-InvalidFeed 'missing-column' "hr_feed.csv is missing required column(s): $($missing -join ', ')"
}

# Per-row validation. We refuse to transmit a half-formed record.
$validStatuses = 'joiner', 'active', 'leaver'
foreach ($row in $roster) {
    foreach ($req in 'employeeId', 'givenName', 'surname', 'status') {
        if ([string]::IsNullOrWhiteSpace($row.$req)) {
            Stop-InvalidFeed 'empty-field' "Row for employeeId '$($row.employeeId)' has empty required field '$req'."
        }
    }
    if ($row.status -notin $validStatuses) {
        Stop-InvalidFeed 'bad-status' "Row employeeId '$($row.employeeId)' has invalid status '$($row.status)'. Expected one of: $($validStatuses -join ', ')."
    }
    # startDate becomes employeeHireDate: the birthright rules' base condition.
    # A joiner/active worker without one would silently get no clinical access.
    if ($row.status -ne 'leaver' -and -not (ConvertTo-HireDate $row.startDate)) {
        Stop-InvalidFeed 'bad-start-date' "Row employeeId '$($row.employeeId)' ($($row.status)) has no valid startDate (YYYY-MM-DD): it maps to employeeHireDate, which every birthright rule requires."
    }
}

# UPNs for the WHOLE feed (before any filter), so a collision with a worker
# who is not in this run is still seen, and the answer never depends on which
# rows a push happened to change.
try { $script:UserNames = Resolve-UserName -Rows $roster -Domain $UpnDomain }
catch { Stop-InvalidFeed 'bad-upn' $_.Exception.Message }
# Population for the percentage threshold: everyone not leaving, whole feed.
$population = @($roster | Where-Object { $_.status -ne 'leaver' }).Count

# Only the named workers (the pipeline's changed rows). Checked against the
# validated feed: an unknown id is a typo or a deleted row, never "nothing".
if ($EmployeeId.Count -gt 0) {
    $known = @($roster | ForEach-Object { [string]$_.employeeId })
    $unknown = @($EmployeeId | Where-Object { $_ -notin $known })
    if ($unknown) { Stop-InvalidFeed 'unknown-employee' "EmployeeId(s) not in '$CsvPath': $($unknown -join ', '). Nothing was sent." }
    $roster = @($roster | Where-Object { [string]$_.employeeId -in $EmployeeId })
}

# Apply the status filter (demo convenience).
if ($StatusFilter -ne 'all') {
    $roster = @($roster | Where-Object { $_.status -eq $StatusFilter })
}
if ($roster.Count -eq 0) {
    Write-Warning "No rows to process after StatusFilter '$StatusFilter'. Nothing to do."
    Save-RunResult -Outcome 'nothing'
    return
}
$filterText = if ($EmployeeId.Count -gt 0) { "$StatusFilter, $($EmployeeId.Count) named worker(s)" } else { $StatusFilter }
Write-Host "Loaded $($roster.Count) HR record(s) to process (filter: $filterText)." -ForegroundColor Cyan

# Mass-change guard (R10). Checked BEFORE any payload is sent - and under
# -WhatIf too, so a dry run shows the quarantine the real run would do.
# Over the threshold the rows of that kind are HELD BACK (quarantined) and the
# rest are sent; the run then ends with an error (see -MaxChanges for why).
$history = Read-ChangeHistory -Path $ChangeHistoryPath
$disabling = @($roster | Where-Object { $_.status -eq 'leaver' })

# Second count: department / job title changes against the last pushed roster.
# Birthright access follows those attributes, so they change access in bulk.
$baseline = @{}
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    try {
        $prev = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json -AsHashtable
        foreach ($k in @($prev.Keys)) { $baseline[$k] = $prev[$k] }
    }
    catch { throw "StatePath '$StatePath' is unreadable ($($_.Exception.Message)). Fix or delete it (deleting resets the baseline for the access-change guard)." }
}
else { Write-Host "Access-change guard: no baseline yet ($StatePath) - first push, nothing to compare." -ForegroundColor DarkGray }
$accessChanges = @(Get-AccessChange -Rows $roster -Baseline $baseline)

$guardMessages = [System.Collections.Generic.List[string]]::new()
$checks = @(
    @{ Kind = 'mass-disable'; TicketKind = 'disable'; Ids = @($disabling | ForEach-Object { [string]$_.employeeId }); History = $history.disabling
        Text = { param($n, $t) "this run would DISABLE $n account(s) (status=leaver), over the threshold $t" } },
    @{ Kind = 'mass-access-change'; TicketKind = 'access-change'; Ids = @($accessChanges | ForEach-Object { [string]$_.employeeId }); History = $history.accessChanges
        Text = { param($n, $t) "this run would change department or job title for $n worker(s), over the threshold $t. Birthright clinical access follows those attributes, so this would move or remove access for all of them at the next evaluation. First change(s): $(@($accessChanges | Select-Object -First 3 | ForEach-Object { "$($_.employeeId): $($_.From) -> $($_.To)" }) -join '; ')" } }
)
foreach ($c in $checks) {
    $n = $c.Ids.Count
    $th = Get-ChangeThreshold -Floor $MaxChanges -Percent $MaxChangePercent -Population $population -History $c.History
    $why = ($th.Parts.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join ', '
    if ($n -le $th.Threshold) {
        if ($n) { Write-Host "Mass-change guard ($($c.Kind)): $n, threshold $($th.Threshold) ($why)." -ForegroundColor DarkGray }
        continue
    }
    if ($Force) {
        Write-Warning "Mass-change guard overridden (-Force): $n row(s) of kind $($c.Kind) will be sent (threshold $($th.Threshold))."
        continue
    }
    $ok = Test-ApprovedBulkChange -Ticket $BulkChangeTicket -Kind $c.TicketKind -Count $n -Path $ApprovedBulkChangesPath
    if ($ok.Approved) {
        Write-Warning "Mass-change guard: $n row(s) of kind $($c.Kind) allowed by $($ok.Why) (threshold $($th.Threshold))."
        continue
    }
    # Hold back every row of this kind (no names in the record).
    foreach ($id in $c.Ids) {
        $row = $roster | Where-Object { [string]$_.employeeId -eq $id } | Select-Object -First 1
        $script:Quarantined.Add([ordered]@{ employeeId = $id; status = [string]$row.status; kind = $c.Kind })
    }
    $script:GuardRefusals.Add([ordered]@{ kind = $c.Kind; count = $n; threshold = $th.Threshold; why = $why; ticket = $ok.Why })
    $guardMessages.Add(("Mass-change guard: " + (& $c.Text $n $th.Threshold) + " ($why). Held back (quarantined): $n row(s); $($ok.Why)."))
}
if ($script:Quarantined.Count) {
    $held = @($script:Quarantined | ForEach-Object { $_.employeeId })
    $roster = @($roster | Where-Object { [string]$_.employeeId -notin $held })
    $qDir = Split-Path -Parent $QuarantinePath
    if ($qDir -and -not (Test-Path -LiteralPath $qDir)) { New-Item -ItemType Directory -Path $qDir -Force -WhatIf:$false | Out-Null }
    ([ordered]@{ schema = 'hr-feed-quarantine/1'; createdUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); rows = @($script:Quarantined); guard = @($script:GuardRefusals) } | ConvertTo-Json -Depth 5) |
        Set-Content -LiteralPath $QuarantinePath -Encoding utf8NoBOM -WhatIf:$false
    foreach ($m in $guardMessages) { Write-Warning $m }
    $script:GuardError = (($guardMessages -join ' ') + " The held-back rows are in '$QuarantinePath'. Check the HR extract (a mapping or export error looks exactly like this). For a reviewed bulk event re-run with -BulkChangeTicket (listed in approved-bulk-changes.json), or -Force at a console.")
    if ($roster.Count -eq 0) {
        Save-RunResult -Outcome 'refused' -Refusal $script:GuardRefusals[0]
        throw ("Nothing was sent. " + $script:GuardError)
    }
}
else { $script:GuardError = '' }

# =============================================================================
# 2. MAP ONE HR ROW -> ONE SCIM ENTERPRISE USER OBJECT
# =============================================================================
function ConvertTo-ScimUser {
    <#
        Translates a single hr_feed.csv row into the SCIM 2.0 Enterprise User
        payload the provisioning engine expects. Attribute names here must line
        up with your provisioning job's attribute-mapping expressions.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Row, [Parameter(Mandatory)][string]$Domain)

    # The UPN is resolved once for the whole feed (Resolve-UserName): the
    # row's own HR-issued upn, or a derived, ASCII-normalised, collision-safe
    # one. Never re-derived here from the (possibly changed) name.
    $userName = if ($script:UserNames -and $script:UserNames.Contains([string]$Row.employeeId)) { $script:UserNames[[string]$Row.employeeId] }
    else { throw "No resolved UPN for employeeId '$($Row.employeeId)'." }

    # 'leaver' -> active:false (drives disable/deprovision via job mapping).
    $isActive = ($Row.status -ne 'leaver')

    $scim = [ordered]@{
        schemas     = @($SchemaCoreUser, $SchemaEnterpriseUser)
        externalId  = [string]$Row.employeeId   # anchor / match key
        userName    = $userName
        active      = $isActive
        displayName = ('{0} {1}' -f $Row.givenName, $Row.surname)
        name        = [ordered]@{
            givenName  = $Row.givenName
            familyName = $Row.surname
        }
        title       = $Row.jobTitle
        # SCIM enterprise extension (department + employeeNumber + manager).
        $SchemaEnterpriseUser = [ordered]@{
            employeeNumber = [string]$Row.employeeId
            department     = $Row.dept
        }
    }
    # Custom extension: hire date -> employeeHireDate (birthright base rule).
    # TENANT-TIME mapping (verify: both expressions on the first job setup):
    #   cloud path  [hireDate] -> employeeHireDate
    #   AD path     FormatDateTime([hireDate], , "yyyy-MM-ddTHH:mm:ssZ", "yyyyMMddHHmmss.0Z")
    #               -> msDS-cloudExtensionAttribute1, then Cloud Sync
    #               msDS-cloudExtensionAttribute1 -> employeeHireDate
    #               (post-apply/New-LifecycleWorkflows.ps1 uses the same attribute)
    $hire = ConvertTo-HireDate $Row.startDate
    if ($hire) {
        $scim['schemas'] = @($SchemaCoreUser, $SchemaEnterpriseUser, $SchemaContosoUser)
        $scim[$SchemaContosoUser] = [ordered]@{ hireDate = $hire }
    }

    # Manager is optional (top-of-chain rows have it blank). The engine resolves
    # manager.value against the configured anchor of the referenced worker --
    # here that is the manager's employeeId.
    if (-not [string]::IsNullOrWhiteSpace($Row.manager)) {
        $scim[$SchemaEnterpriseUser]['manager'] = [ordered]@{ value = [string]$Row.manager }
    }

    return $scim
}

# =============================================================================
# 3. CHUNK INTO <= 50-RECORD BATCHES AND BUILD SCIM BulkRequests
# =============================================================================
function New-ScimBulkRequest {
    <# Wraps up to $MaxBatchSize SCIM users into one SCIM BulkRequest body. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject[]]$Rows, [Parameter(Mandatory)][string]$Domain)

    $operations = foreach ($row in $Rows) {
        [ordered]@{
            method = 'POST'
            # bulkId is a client-chosen correlation handle unique within the
            # request; we use the employeeId so provisioning logs are traceable.
            bulkId = [string]$row.employeeId
            path   = '/Users'
            data   = (ConvertTo-ScimUser -Row $row -Domain $Domain)
        }
    }

    return [ordered]@{
        schemas      = @($SchemaBulkRequest)
        Operations   = @($operations)
        failOnErrors = $null   # null = best-effort; set an int to abort a batch
                               # after N record errors.
    }
}

# Build the batches (PowerShell-7 safe chunking).
$batches = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $roster.Count; $i += $MaxBatchSize) {
    $end = [Math]::Min($i + $MaxBatchSize, $roster.Count) - 1
    $batches.Add(@($roster[$i..$end]))
}
Write-Host "Prepared $($batches.Count) batch(es) of up to $MaxBatchSize records each." -ForegroundColor Cyan

# =============================================================================
# 4. ENSURE A GRAPH CONNECTION WITH THE RIGHT SCOPE
# =============================================================================
# We only need a live connection when we are actually going to POST. Under
# -WhatIf we skip auth entirely so the dry run works with zero tenant.
$willSend = $PSCmdlet.ShouldProcess($BulkUploadUri, "POST $($batches.Count) SCIM bulk batch(es)")
if ($willSend) {
    $ctx = $null
    if ($UseAzureCliToken) {
        # App-only (pipeline): always this identity, never a leftover context.
        Write-Host 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
        Connect-GraphFromAzureCli
    }
    try { $ctx = Get-MgContext } catch { $ctx = $null }
    if (-not $ctx) {
        Write-Host 'No Graph context. Connecting (service auth recommended in prod)...' -ForegroundColor Yellow
        # Interactive (delegated) here for the lab: the signed-in user must ALSO
        # hold User Administrator, or the POST returns 403. In production use
        # app-only:
        #   Connect-MgGraph -ClientId <appId> -TenantId <tenant> -CertificateThumbprint <thumb>
        Connect-MgGraph -Scopes 'SynchronizationData-User.Upload'
    }
    # Soft-check the scope is present; warn (don't hard-fail) because app-only
    # tokens surface roles differently than delegated scopes.
    $ctx = Get-MgContext
    # App-only contexts list the token's roles here: either upload role will do.
    if ($ctx.Scopes -and -not @($ctx.Scopes | Where-Object { $_ -in 'SynchronizationData-User.Upload', 'SynchronizationData-User.Upload.OwnedBy' })) {
        Write-Warning "Current context does not list 'SynchronizationData-User.Upload'. The POST will 403 unless the app has SynchronizationData-User.Upload(.OwnedBy), or, delegated, the signed-in user holds User Administrator."
    }
}

# =============================================================================
# 5. SEND (or, under -WhatIf, print) EACH BATCH
# =============================================================================
$batchIndex = 0
# Batches whose POST failed; non-zero => warn + exit 1 at the end.
$failedBatches = 0
foreach ($batch in $batches) {
    $batchIndex++
    $body = New-ScimBulkRequest -Rows $batch -Domain $UpnDomain
    # Depth 8 so the nested enterprise-extension + manager survive serialization.
    $json = $body | ConvertTo-Json -Depth 8

    if (-not $willSend) {
        # -WhatIf / declined: show precisely what WOULD be transmitted.
        Write-Host "`n--- [WhatIf] Batch $batchIndex/$($batches.Count) -> $BulkUploadUri" -ForegroundColor DarkYellow
        if ($HidePayload) {
            Write-Host "    $($batch.Count) SCIM record(s), application/scim+json (payload not printed: -HidePayload)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "    Content-Type: application/scim+json" -ForegroundColor DarkGray
            Write-Host $json
        }
        $script:BatchResults.Add([ordered]@{ index = $batchIndex; records = $batch.Count; employeeIds = @($batch | ForEach-Object { [string]$_.employeeId }); httpStatus = 0; accepted = $false })
        continue
    }

    Write-Host "`nSending batch $batchIndex/$($batches.Count) ($($batch.Count) record(s))..." -ForegroundColor Green
    if (-not $script:SentAtUtc) { $script:SentAtUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $statusCode = 0
    try {
        # 202 Accepted on success. The body is queued; it is NOT processed
        # synchronously. ResponseHeadersVariable lets us surface the location/
        # correlation id for the follow-up provisioning-log query.
        Invoke-MgGraphRequest `
            -Method POST `
            -Uri $BulkUploadUri `
            -Body $json `
            -ContentType 'application/scim+json' `
            -ResponseHeadersVariable respHeaders `
            -StatusCodeVariable statusCode | Out-Null

        Write-Host "  HTTP $statusCode (expected 202 Accepted) -- batch accepted for async processing." -ForegroundColor Green
        $script:BatchResults.Add([ordered]@{ index = $batchIndex; records = $batch.Count; employeeIds = @($batch | ForEach-Object { [string]$_.employeeId }); httpStatus = [int]$statusCode; accepted = $true })
    }
    catch {
        # No silent swallow: report the batch, the record ids, and the error,
        # then keep going so one bad batch does not strand the rest of the feed.
        # Write-Warning, not Write-Error: under EAP=Stop Write-Error would
        # terminate here. The failure still ends the run with exit 1 below.
        $failedBatches++
        $http = Get-HttpStatusFromError $_
        $script:BatchResults.Add([ordered]@{ index = $batchIndex; records = $batch.Count; employeeIds = @($batch | ForEach-Object { [string]$_.employeeId }); httpStatus = $http; accepted = $false })
        $ids = if ($HidePayload) { "$($batch.Count) record(s)" } else { 'employeeIds: ' + (($batch | ForEach-Object { $_.employeeId }) -join ', ') }
        Write-Warning "Batch $batchIndex FAILED ($ids): $($_.Exception.Message)"
    }
}

# =============================================================================
# 6. RESULT + NEXT-STEP GUIDANCE (printed, not executed)
# =============================================================================
if (-not $willSend) {
    # -WhatIf or a declined confirm prompt: never claim anything was submitted.
    Write-Host "`nDry run - nothing was sent to $BulkUploadUri." -ForegroundColor DarkYellow
    Save-RunResult -Outcome 'dry-run'
    if ($script:GuardError) { throw ("Dry run. " + $script:GuardError) }
    return
}

$acceptedBatches = $batches.Count - $failedBatches
if ($acceptedBatches -gt 0) {
    Write-Host @"

Submitted $acceptedBatches of $($batches.Count) batch(es). Processing is asynchronous. To confirm records landed, either:
  * Entra admin center -> Enterprise apps -> <your provisioning app> -> Provisioning logs
  * Graph:  GET /$GraphApiVersion/auditLogs/provisioning?`$filter=... (needs AuditLog.Read.All + Directory.Read.All)
  * Then continue the joiner story with ./powershell/02-Joiner.ps1 for Dana Okafor.
"@ -ForegroundColor Cyan
}
Save-RunResult -Outcome $(if ($failedBatches -eq 0) { 'sent' } elseif ($acceptedBatches -gt 0) { 'partial' } else { 'failed' })
if ($failedBatches -gt 0) {
    # Re-running is safe: the engine upserts on the employeeId anchor (see IDEMPOTENCY).
    # The access-change baseline is NOT moved: the next run still compares
    # against what was last pushed in full.
    Write-Warning "$failedBatches of $($batches.Count) batch(es) FAILED - see the warnings above. Fix the cause and re-run."
    exit 1
}
# Every batch accepted: this roster is the new access-change baseline
# (merged, so a filtered run only moves the rows it pushed).
foreach ($r in $roster) { $baseline[[string]$r.employeeId] = @{ dept = [string]$r.dept; jobTitle = [string]$r.jobTitle } }
$stateDir = Split-Path -Parent $StatePath
if ($stateDir -and -not (Test-Path -LiteralPath $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
($baseline | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $StatePath -Encoding utf8NoBOM
# Today's counts for the 3-sigma history (only when a history file is kept).
if ($ChangeHistoryPath -and -not $script:GuardError) {
    $hist = @()
    if (Test-Path -LiteralPath $ChangeHistoryPath -PathType Leaf) { $hist = @(Get-Content -LiteralPath $ChangeHistoryPath -Raw | ConvertFrom-Json -AsHashtable) }
    $hist += [ordered]@{ date = [datetime]::UtcNow.ToString('yyyy-MM-dd'); disabling = $disabling.Count; accessChanges = $accessChanges.Count }
    (ConvertTo-Json -InputObject @($hist | Select-Object -Last 60) -Depth 3) | Set-Content -LiteralPath $ChangeHistoryPath -Encoding utf8NoBOM
}
if ($script:GuardError) { throw ("The other rows were sent. " + $script:GuardError) }
