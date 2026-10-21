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
    * A caller allowed to POST to /bulkUpload (GRAPH SCOPES below). This
      script connects DELEGATED (interactive, lab): SynchronizationData-User.Upload
      consented, and the signed-in user must hold User Administrator. In
      production an HR extract job or HR ISV integration calls it app-only
      (client credentials) with the application permission.

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
    Default 10 each. Over either threshold the run stops before anything is
    sent, unless -Force (a reviewed bulk event, e.g. a reorganisation or a
    site closure, with its change ticket).

.PARAMETER StatePath
    The last roster pushed WITHOUT a failed batch (employeeId -> dept,
    jobTitle), the baseline for the access-changing count. Default
    .state/last-pushed-roster.json next to this script (gitignored: it holds
    worker ids and titles). Written only after a real send with no failed
    batch - never under -WhatIf. Missing = first run: nothing to compare, so
    the access-changing count is 0 (stated in the output).

.PARAMETER Force
    Push even when the mass-change guard trips. Use only for a reviewed bulk
    change; the run still prints how many accounts it will disable.

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
    [switch]$Force,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$StatePath = (Join-Path $PSScriptRoot '.state' 'last-pushed-roster.json')
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

# =============================================================================
# 1. LOAD + VALIDATE THE HR FEED
# =============================================================================
# Strip our '#' comment lines before Import-Csv (Import-Csv has no comment
# support). We keep the header line and all data lines.
$rawLines = Get-Content -LiteralPath $CsvPath
$dataLines = $rawLines | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne '' }
if (-not $dataLines -or $dataLines.Count -lt 2) {
    throw "CsvPath '$CsvPath' has no data rows after stripping comments."
}
$roster = $dataLines | ConvertFrom-Csv

# Validate required columns exist exactly once (fail loud on a malformed feed).
$requiredColumns = 'employeeId', 'givenName', 'surname', 'dept', 'jobTitle', 'manager', 'status', 'startDate', 'endDate'
$presentColumns  = $roster[0].PSObject.Properties.Name
$missing = $requiredColumns | Where-Object { $_ -notin $presentColumns }
if ($missing) {
    throw "hr_feed.csv is missing required column(s): $($missing -join ', ')"
}

# Per-row validation. We refuse to transmit a half-formed record.
$validStatuses = 'joiner', 'active', 'leaver'
foreach ($row in $roster) {
    foreach ($req in 'employeeId', 'givenName', 'surname', 'status') {
        if ([string]::IsNullOrWhiteSpace($row.$req)) {
            throw "Row for employeeId '$($row.employeeId)' has empty required field '$req'."
        }
    }
    if ($row.status -notin $validStatuses) {
        throw "Row employeeId '$($row.employeeId)' has invalid status '$($row.status)'. Expected one of: $($validStatuses -join ', ')."
    }
    # startDate becomes employeeHireDate: the birthright rules' base condition.
    # A joiner/active worker without one would silently get no clinical access.
    if ($row.status -ne 'leaver' -and -not (ConvertTo-HireDate $row.startDate)) {
        throw "Row employeeId '$($row.employeeId)' ($($row.status)) has no valid startDate (YYYY-MM-DD): it maps to employeeHireDate, which every birthright rule requires."
    }
}

# Apply the status filter (demo convenience).
if ($StatusFilter -ne 'all') {
    $roster = @($roster | Where-Object { $_.status -eq $StatusFilter })
}
if ($roster.Count -eq 0) {
    Write-Warning "No rows to process after StatusFilter '$StatusFilter'. Nothing to do."
    return
}
Write-Host "Loaded $($roster.Count) HR record(s) to process (filter: $StatusFilter)." -ForegroundColor Cyan

# Mass-change guard (R10). Checked BEFORE any payload is sent - and under
# -WhatIf too, so a dry run shows the refusal the real run would hit.
$disabling = @($roster | Where-Object { $_.status -eq 'leaver' })
if ($disabling.Count -gt $MaxChanges) {
    if (-not $Force) {
        throw ("Mass-change guard: this run would DISABLE $($disabling.Count) account(s) (status=leaver), over -MaxChanges $MaxChanges. " +
            'Nothing was sent. Check the HR extract (a mapping or export error looks exactly like this); for a reviewed bulk change re-run with -Force.')
    }
    Write-Warning "Mass-change guard overridden (-Force): $($disabling.Count) account(s) will be disabled (threshold $MaxChanges)."
}
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
if ($accessChanges.Count -gt $MaxChanges) {
    if (-not $Force) {
        throw ("Mass-change guard: this run would change department or job title for $($accessChanges.Count) worker(s), over -MaxChanges $MaxChanges. " +
            'Birthright clinical access follows those attributes, so this would move or remove access for all of them at the next evaluation. Nothing was sent. ' +
            "First change(s): $(@($accessChanges | Select-Object -First 3 | ForEach-Object { "$($_.employeeId): $($_.From) -> $($_.To)" }) -join '; '). " +
            'For a reviewed reorganisation re-run with -Force.')
    }
    Write-Warning "Mass-change guard overridden (-Force): $($accessChanges.Count) worker(s) change department or job title (threshold $MaxChanges)."
}
elseif ($accessChanges.Count) { Write-Host "Access-change guard: $($accessChanges.Count) department/title change(s) (threshold $MaxChanges)." -ForegroundColor DarkGray }

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

    # Derive a deterministic userName/UPN from employeeId-driven name parts.
    # In production the HR feed usually carries the UPN already; we synthesize
    # one to the lab domain so the demo is self-contained.
    $userName = ('{0}.{1}@{2}' -f $Row.givenName, $Row.surname, $Domain).ToLowerInvariant()

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
    if ($ctx.Scopes -and ('SynchronizationData-User.Upload' -notin $ctx.Scopes)) {
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
        Write-Host "    Content-Type: application/scim+json" -ForegroundColor DarkGray
        Write-Host $json
        continue
    }

    Write-Host "`nSending batch $batchIndex/$($batches.Count) ($($batch.Count) record(s))..." -ForegroundColor Green
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
    }
    catch {
        # No silent swallow: report the batch, the record ids, and the error,
        # then keep going so one bad batch does not strand the rest of the feed.
        # Write-Warning, not Write-Error: under EAP=Stop Write-Error would
        # terminate here. The failure still ends the run with exit 1 below.
        $failedBatches++
        $ids = ($batch | ForEach-Object { $_.employeeId }) -join ', '
        Write-Warning "Batch $batchIndex FAILED (employeeIds: $ids): $($_.Exception.Message)"
    }
}

# =============================================================================
# 6. RESULT + NEXT-STEP GUIDANCE (printed, not executed)
# =============================================================================
if (-not $willSend) {
    # -WhatIf or a declined confirm prompt: never claim anything was submitted.
    Write-Host "`nDry run - nothing was sent to $BulkUploadUri." -ForegroundColor DarkYellow
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
