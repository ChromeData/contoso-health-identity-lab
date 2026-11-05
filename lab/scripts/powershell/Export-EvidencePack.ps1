<#
.SYNOPSIS
    Exports an auditor evidence pack from Entra ID to lab/evidence/out/: PIM
    activation history, access-review decisions, Conditional Access inventory,
    MFA registration coverage, and privileged role assignments -- each a JSON
    artifact, with a SHA256+timestamp manifest and a control-mapped SUMMARY.md.

.DESCRIPTION
    Video segment 9, "Evidence & close" -- the differentiator. The pitch:
    "when an auditor asks 'prove least privilege,' this is a one-command export,
    not a week of screenshots."

    Each artifact is a read-only Graph query. After collecting them the script
    computes a SHA256 over every file and writes manifest.json, giving the pack
    tamper-evidence (re-hash later to prove nothing changed) and a defensible
    generated-at timestamp. SUMMARY.md maps each artifact to the SOX and HIPAA
    control it evidences and states what this pack actually found, every
    number computed from the collected records (standing privileged holders,
    CA states, MFA registration, NHI ownership...), never a fixed claim, so
    the pack is self-explaining to a non-engineer and cannot overstate.

    ARTIFACTS
      pim_activation_history.json     every just-in-time elevation: PIM for
                                      Groups selfActivate requests (the lab's
                                      elevation path: Privileged-IAM-Admins and
                                      the tier groups) plus PIM for directory
                                      roles, read from the directory audit log
                                      (completed activations, last 30 days; the
                                      requests list needs a ReadWrite role - see
                                      ARTIFACT 1): who elevated, when, for how
                                      long, with justification.
      pim_active_assignments.json     what is live right now: directory role
                                      assignment instances (the group's standing
                                      binding to User Administrator shows here)
                                      plus current group-membership instances
                                      (Assigned vs Activated).
      pim_activation_activities.json  directoryAudits for PIM = the raw activity
                                      log behind each activation (the "+ activities").
      access_review_decisions.json    accessReviews -> instances -> decisions:
                                      recorded approve/deny attestations.
      conditional_access_policies.json  full CA policy inventory incl. state
                                      (report-only vs enabled) and break-glass
                                      exclusions.
      mfa_registration_coverage.json  per-user strong-auth registration + a
                                      computed coverage percentage.
      privileged_role_assignments.json  all assignments on privileged roles,
                                      flagging which principals are break-glass.
      SUMMARY.md                      control mapping + computed findings
                                      (counts only, no names).
      manifest.json                   SHA256 + size + timestamp for every file.

    COMPANION EVIDENCE (hashed into the manifest, not re-collected): the files
    the other evidence scripts already wrote under lab/evidence, so ONE
    manifest covers the whole capture window - NHI inventory + findings
    (06-NHI-Inventory.ps1, and its committed counts-only nhi/<UTC>/ copy), shadow-admin paths (Find-ShadowAdmins.ps1), the
    Agent ID record (New-AgentIdentity.ps1), app-management policy backups
    (Set-AppGovernancePolicy.ps1), KPI snapshots (08-Measure-KPIs.ps1),
    break-glass drill records (Invoke-BreakGlassDrill.ps1), access-review
    definitions (New-AccessReviewDefinitions.ps1), ScubaGear / Zero Trust
    summaries (Invoke-BaselineAssessment.ps1) and AD containment records
    (monitoring/Invoke-AdContainment.ps1). offline-mock output is never
    included: it is not tenant evidence. Missing ones are listed as 'absent'.

    FAIL-OPEN, NEVER SILENT: if one query fails (missing license, missing scope,
    no data) the script records that artifact's status as 'failed' with the
    error in the manifest and continues, so you still get a hashed, honest pack
    rather than a half-written directory or a crash.

.PREREQUISITES
    * Entra ID P2 for PIM + access reviews data; P1 for the registration report.
    * Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance,
      Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Reports,
      Microsoft.Graph.Identity.DirectoryManagement.

.GRAPH SCOPES  (delegated; admin-consent -- all READ-ONLY)
    RoleManagement.Read.Directory     role definitions + role assignments
    RoleAssignmentSchedule.Read.Directory  PIM-for-roles schedule instances (the
                                      requests list is NOT read: Learn's least
                                      privileged permission for it is
                                      RoleAssignmentSchedule.ReadWrite.Directory)
    RoleEligibilitySchedule.Read.Directory  (read eligible assignments)
    PrivilegedAssignmentSchedule.Read.AzureADGroup  PIM-for-Groups requests/instances
    AccessReview.Read.All             access-review definitions/instances/decisions
    Policy.Read.All                   Conditional Access policy inventory
    AuditLog.Read.All                 directoryAudits (PIM activities and the
                                      directory-role activation history) + MFA report
    Directory.Read.All                principal/role lookups

    APP-ONLY (-UseAzureCliToken, the pipeline path): the same reads as
    APPLICATION permissions. .github/workflows/evidence-pack.yml signs in as
    the EVIDENCE identity (modules/pipeline-identity evidence_graph_roles):
    AuditLog.Read.All, AccessReview.Read.All, Policy.Read.All,
    RoleManagement.Read.Directory, RoleAssignmentSchedule.Read.Directory,
    PrivilegedAssignmentSchedule.Read.AzureADGroup, Directory.Read.All -
    read-only, nothing else. RoleEligibilitySchedule.Read.Directory
    above is listed for completeness; no artifact reads eligibility schedules.

    API versions: CA policies, access reviews and PIM schedules are v1.0.
    The MFA userRegistrationDetails report and some directoryAudit filters are
    served from both v1.0 and beta; cmdlet calls below use whatever the installed
    SDK maps, and REST fallbacks are commented with their version. The one beta
    call is the privileged-role set (unifiedRoleDefinition.isPrivileged is not
    in v1.0); verify: re-check before publishing.

.PARAMETER OutputDirectory
    Destination. Defaults to lab/evidence/out (two levels up from this script).
    Created if absent. Existing *.json/SUMMARY.md/manifest.json are overwritten.

.PARAMETER AccessReviewLookbackDays
    How far back to pull completed access-review instances. Default 365.

.PARAMETER PimGroupMailNicknames
    PIM-governed groups to include in the PIM artifacts. Default: the lab's
    privileged-iam-admins (Terraform contract).

.PARAMETER BreakGlassGroupMailNickname
    The break-glass group every CA policy excludes. Default: the lab's
    break-glass-admins (Terraform contract). Used for excludesBreakGlass.

.PARAMETER SkipPimTierGroups
    Do not add the PIM tier groups (pim-tier0-security-admins,
    pim-tier0-ca-admins, pim-tier1-intune-admins, pim-tier1-helpdesk) to the
    PIM artifacts. By default each one that EXISTS is included (they exist only
    with enable_pim_tiers); an absent one is reported, not warned about.

.PARAMETER EvidenceRoot
    lab/evidence, where the companion evidence lives. Default: two levels up.

.PARAMETER UseAzureCliToken
    App-only sign-in for pipelines: take a Microsoft Graph token from the
    Azure CLI session (`az account get-access-token --resource-type ms-graph`;
    in GitHub Actions, azure/login over OIDC as EVIDENCE) and connect with it,
    always that identity, never a leftover context. The token is masked in
    Actions and stays in this process: never in argv, a file or the output.

.PARAMETER GeneratedBy
    What the manifest records as generatedBy. Default: the signed-in account
    (delegated) or the app id (app-only). The pipeline passes its run, e.g.
    "EVIDENCE app, GitHub Actions run 123 (commit abc1234)", which also dates
    the companion hashes to that commit.

.PARAMETER WhatIf
    Standard. Reports what it WOULD export and writes nothing.

.EXAMPLE
    Connect-MgGraph -Scopes 'RoleManagement.Read.Directory','RoleAssignmentSchedule.Read.Directory','PrivilegedAssignmentSchedule.Read.AzureADGroup','AccessReview.Read.All','Policy.Read.All','AuditLog.Read.All','Directory.Read.All'
    ./Export-EvidencePack.ps1 -WhatIf
    ./Export-EvidencePack.ps1
.EXAMPLE
    # Pipeline (evidence-pack.yml): app-only as EVIDENCE, into the runner's temp folder.
    ./Export-EvidencePack.ps1 -UseAzureCliToken -OutputDirectory $env:RUNNER_TEMP/evidence-pack/pack `
        -GeneratedBy "EVIDENCE app, GitHub Actions run $env:GITHUB_RUN_ID"

.OUTPUTS
    Writes the artifacts + manifest.json + SUMMARY.md into -OutputDirectory and
    returns the manifest object.

.WHAT IT DEMONSTRATES
    Continuous, one-command, tamper-evident audit evidence mapped to named
    SOX/HIPAA controls -- the "prove it to an auditor without screenshots"
    capability most identity projects never build.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    # lab/scripts/powershell -> ../../evidence/out  == lab/evidence/out
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out'),

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$AccessReviewLookbackDays = 365,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$PimGroupMailNicknames = @('privileged-iam-admins'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [switch]$SkipPimTierGroups,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceRoot = (Join-Path $PSScriptRoot '..' '..' 'evidence'),

    # App-only sign-in from the Azure CLI session (azure/login over OIDC).
    [Parameter()]
    [switch]$UseAzureCliToken,

    # Recorded as the manifest's generatedBy (the pipeline names its run).
    [Parameter()]
    [string]$GeneratedBy = ''
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

function Connect-GraphFromAzureCli {
    # App-only: the Azure CLI is already signed in as an app (azure/login over
    # GitHub OIDC, or the lab operator's certificate through
    # lab/scripts/operator/op). The token never leaves this process: masked in
    # Actions, handed to Connect-MgGraph as a SecureString, then dropped. Same
    # as mock-hr/Invoke-InboundProvisioning.ps1, through Write-Console for the
    # analyzer; every lab/scripts/powershell copy is identical (parity test in
    # tests/EvidencePackPipeline.Tests.ps1).
    $global:LASTEXITCODE = 0
    $token = az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$token)) {
        throw 'No Microsoft Graph token from the Azure CLI. Sign it in first (azure/login with OIDC in GitHub Actions, or az login locally).'
    }
    $token = ([string]$token).Trim()
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Console "::add-mask::$token" }
    # NetworkCredential.SecurePassword: the same SecureString as
    # ConvertTo-SecureString -AsPlainText, without the analyzer error rule.
    Connect-MgGraph -AccessToken ([System.Net.NetworkCredential]::new('', $token).SecurePassword) -NoWelcome | Out-Null
    Remove-Variable -Name token
}

$requiredScopes = @(
    'RoleManagement.Read.Directory', 'RoleAssignmentSchedule.Read.Directory',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'AccessReview.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Directory.Read.All'
)
if ($UseAzureCliToken) {
    # App-only (pipeline): always this identity, never a leftover context.
    Write-Console 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
    Connect-GraphFromAzureCli
}
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) {
    if ($UseAzureCliToken) { throw 'No Microsoft Graph context after the app-only sign-in.' }
    Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext
}
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 and lookups may report 'not found' (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

# Resolve + (optionally) create the output directory.
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
Write-Console "Evidence pack destination: $OutputDirectory" -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess($OutputDirectory, 'create/clean output directory')) {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
}

# PIM-governed groups (PIM for Groups list APIs require a groupId filter).
# Select-Object -First 1, not @(...)[0]: under StrictMode an empty result
# would throw IndexOutOfRange and skip the warning.
$graphV1 = 'https://graph.microsoft.com/v1.0'

# Walks a key path through the hashtables Invoke-MgGraphRequest returns. Under
# StrictMode, dot access on a MISSING hashtable key throws; Graph normally
# sends optional keys as null, but if it ever omits one the field is $null.
function Get-Field($Object, [string[]]$Path) {
    $cur = $Object
    foreach ($k in $Path) {
        if ($cur -isnot [System.Collections.IDictionary] -or -not $cur.Contains($k)) { return $null }
        $cur = $cur[$k]
    }
    $cur
}
$pimGroups = @(foreach ($nick in $PimGroupMailNicknames) {
    $g = @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/groups?`$filter=mailNickname eq '$nick'&`$select=id,displayName")['value']) | Select-Object -First 1
    if ($g) { $g } else { Write-Warning "PIM group '$nick' not found; its activations will be missing from the pack." }
})
# PIM tier groups (modules/pim tiers.tf) exist only with enable_pim_tiers, so
# an absent one is information, not a warning.
if (-not $SkipPimTierGroups) {
    foreach ($nick in 'pim-tier0-security-admins', 'pim-tier0-ca-admins', 'pim-tier1-intune-admins', 'pim-tier1-helpdesk') {
        if ($nick -in $PimGroupMailNicknames) { continue }
        $g = @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/groups?`$filter=mailNickname eq '$nick'&`$select=id,displayName")['value']) | Select-Object -First 1
        if ($g) { $pimGroups += $g } else { Write-Console "  [i] PIM tier group '$nick' not deployed (enable_pim_tiers off) - skipped." -ForegroundColor DarkGray }
    }
}

# Break-glass group: every CA policy excludes it BY GROUP (Terraform
# excluded_groups), so the CA artifact flags each policy against this id.
$bgGroup = @((Invoke-MgGraphRequest -Method GET -Uri "$graphV1/groups?`$filter=mailNickname eq '$BreakGlassGroupMailNickname'&`$select=id,displayName")['value']) | Select-Object -First 1
if (-not $bgGroup) { Write-Warning "Break-glass group '$BreakGlassGroupMailNickname' not found; excludesBreakGlass will be null in conditional_access_policies.json." }

# Privileged directory roles. unifiedRoleDefinition.isPrivileged is BETA-only
# (absent from the v1.0 resource and SDK model), so read the set once over REST
# and match assignments on roleDefinitionId (built-in: id = templateId).
# verify: re-check whether isPrivileged has reached v1.0 before relying on beta.
# On failure the two role artifacts are recorded as failed, never as "none".
$privRoleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$privRoleError = $null
try {
    $rdUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,templateId"
    do {
        $rdPage = Invoke-MgGraphRequest -Method GET -Uri $rdUri
        foreach ($rd in @($rdPage['value'])) {
            [void]$privRoleIds.Add($rd['id'])
            if ($rd['templateId']) { [void]$privRoleIds.Add($rd['templateId']) }
        }
        $rdUri = $rdPage['@odata.nextLink']
    } while ($rdUri)
    # Global Administrator is privileged in every tenant (same guard as 05-Reports.ps1).
    if (-not $privRoleIds.Contains('62e90394-69f5-4237-9190-012177145e10')) {
        throw 'isPrivileged filter did not return Global Administrator; privileged-role set is not trustworthy.'
    }
}
catch {
    $privRoleError = "privileged-role lookup (beta isPrivileged) failed: $($_.Exception.Message)"
    Write-Warning "$privRoleError -- pim_active_assignments.json and privileged_role_assignments.json will be recorded as failed."
}

# Manifest accumulator (one entry per artifact file).
$manifestArtifacts = [System.Collections.Generic.List[object]]::new()
# What each artifact collected (or why it failed), kept in memory so SUMMARY.md
# states COMPUTED facts about this pack, never a fixed claim about the tenant.
$collected = @{}

function Export-Artifact {
    <#
        Runs a collection scriptblock, writes <Name> as pretty JSON, hashes it,
        and records a manifest entry. On failure records status=failed (never
        silent) and keeps going.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param(
        [Parameter(Mandatory)][string]$Name,          # file name e.g. pim_activation_history.json
        [Parameter(Mandatory)][scriptblock]$Collector, # returns the data to serialize
        [Parameter(Mandatory)][string]$Control         # short control note for console
    )
    $target = Join-Path $OutputDirectory $Name
    Write-Host "`n- $Name" -ForegroundColor Cyan
    if (-not $PSCmdlet.ShouldProcess($target, 'collect + write artifact')) {
        Write-Host "  [whatif] would collect ($Control) and write $Name" -ForegroundColor DarkYellow
        return
    }
    $status = 'ok'; $err = $null; $count = 0
    try {
        $data = & $Collector
        $data = @($data)                 # normalize to array for a stable count
        $count = $data.Count
        # -InputObject, not the pipeline: 0 records writes [] (piping nothing
        # writes no file and Get-FileHash below would abort the pack), and 1
        # record stays an array.
        (ConvertTo-Json -InputObject $data -Depth 12) | Set-Content -LiteralPath $target -Encoding utf8
        $collected[$Name] = @{ status = 'ok'; data = $data; error = $null }
        Write-Host "  [+] $count record(s) -> $Name" -ForegroundColor Green
    }
    catch {
        $status = 'failed'; $err = $_.Exception.Message
        $collected[$Name] = @{ status = 'failed'; data = @(); error = $err }
        Write-Warning "  [!] $Name FAILED: $err"
        # Write a stub so the file (and its hash) still exist and tell the truth.
        (@{ error = $err; status = 'failed'; generatedUtc = (Get-Date).ToUniversalTime().ToString('o') } |
            ConvertTo-Json) | Set-Content -LiteralPath $target -Encoding utf8
    }
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    $size = (Get-Item -LiteralPath $target).Length
    $manifestArtifacts.Add([pscustomobject]@{
        file         = $Name
        control      = $Control
        status       = $status
        error        = $err
        recordCount  = $count
        sizeBytes    = $size
        sha256       = $hash
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    })
}

# ===========================================================================
# ARTIFACT 1 -- PIM activation history (the elevation audit trail)
# ===========================================================================
Export-Artifact -Name 'pim_activation_history.json' -Control 'SOX access control / HIPAA 164.312(a)(1)' -Collector {
    $rows = [System.Collections.Generic.List[object]]::new()
    # requestId -> its row from the requests API, so the audit log can add
    # what that API does not carry (whether MFA was used) instead of a duplicate.
    $requestRows = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $selectedGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $pimGroups) { if ($g.id) { $null = $selectedGroupIds.Add([string]$g.id) } }
    # (a) PIM for Groups - the lab's elevation path. selfActivate requests on
    # the member role of each PIM-governed group (PrivilegedAssignmentSchedule.
    # Read.AzureADGroup). The requests API also carries what the audit log
    # does not: the ticket number, and requests still pending or denied.
    foreach ($g in $pimGroups) {
        $uri = "$graphV1/identityGovernance/privilegedAccess/group/assignmentScheduleRequests?`$filter=groupId eq '$($g.id)'&`$expand=principal"
        do {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($r in @(@(Get-Field $page 'value') | Where-Object { (Get-Field $_ 'action') -eq 'selfActivate' })) {
                $id = [string](Get-Field $r 'id')
                $row = [pscustomobject]@{
                    elevationType   = 'PIM for Groups'
                    source          = 'PIM requests API'
                    requestId       = $id
                    role            = "$($g.displayName) ($(Get-Field $r 'accessId'))"
                    principalId     = Get-Field $r 'principalId'
                    principal       = Get-Field $r 'principal', 'displayName'
                    action          = Get-Field $r 'action'
                    status          = Get-Field $r 'status'
                    justification   = Get-Field $r 'justification'
                    createdDateTime = Get-Field $r 'createdDateTime'
                    startDateTime   = Get-Field $r 'scheduleInfo', 'startDateTime'
                    expiration      = Get-Field $r 'scheduleInfo', 'expiration', 'endDateTime'
                    ticketNumber    = Get-Field $r 'ticketInfo', 'ticketNumber'
                    mfa             = $null
                }
                $rows.Add($row)
                if ($id) { $requestRows[$id] = $row }
            }
            $uri = $page['@odata.nextLink']
        } while ($uri)
    }
    # (b) Every COMPLETED activation in the directory audit log (AuditLog.Read.All):
    # PIM for directory roles always comes from here, and a PIM-for-Groups
    # activation the requests API no longer returns is added from here too
    # (its RoleAssignmentRequestId is the requests API's id, so nothing is
    # counted twice).
    #
    # WHY not roleManagement/directory/roleAssignmentScheduleRequests: Microsoft
    # Learn's permissions table for "List roleAssignmentScheduleRequests" names
    # RoleAssignmentSchedule.ReadWrite.Directory as the LEAST privileged
    # permission (there is no Read permission for the requests list), and the
    # service enforces it: EVIDENCE, holding RoleAssignmentSchedule.Read.Directory
    # and RoleManagement.Read.Directory, was refused with PermissionScopeNotGranted
    # (evidence-pack runs 41998984309 and 42002625567). The $expand was not the
    # cause: the same two-property expand on roleAssignmentScheduleInstances
    # succeeded under the same token (pim_active_assignments.json, 29 records).
    # The old server-side filter "action eq 'selfActivate'" is also rejected
    # with InvalidFilter, even for an identity that holds the ReadWrite role
    # (checked 2026-11-05). A ReadWrite PIM role would let the evidence
    # collector create role assignments; the audit log carries the same facts
    # read-only: who (initiatedBy), which role (targetResources), StartTime,
    # ExpirationTime, Justification, whether MFA was used, the request id.
    # Limit: Entra keeps directory audits for 30 days (P1/P2), so each pack
    # covers the last 30 days; the WORM store keeps every pack, so the history
    # builds up there. verify: a directory-role activation is logged with
    # category RoleManagement (none happened in the lab's 30-day window on
    # 2026-11-05; any category other than GroupManagement is kept as a role).
    Get-MgAuditLogDirectoryAudit -All -Filter "loggedByService eq 'PIM' and activityDisplayName eq 'Add member to role completed (PIM activation)'" |
        ForEach-Object {
            $details = @{}
            foreach ($kv in @($_.AdditionalDetails)) { if ($kv -and $kv.Key) { $details[[string]$kv.Key] = [string]$kv.Value } }
            $requestId = $details['RoleAssignmentRequestId']
            if ($requestId -and $requestRows.ContainsKey($requestId)) {
                # Already listed from the requests API: keep that row (it has
                # the ticket) and add the audit log's MFA answer to it.
                $requestRows[$requestId].mfa = $details['IsAuthenticatedWithMfa']
                return
            }
            $roleName = (@($_.TargetResources | Where-Object { $_.Type -eq 'Role' } | ForEach-Object { $_.DisplayName }) | Select-Object -First 1)
            $isGroup = $_.Category -eq 'GroupManagement'
            if ($isGroup) {
                # Only the groups this pack covers ($pimGroups: -PimGroupMailNicknames,
                # plus the tier groups unless -SkipPimTierGroups). PIM puts the
                # group's object id in ResourceOriginId (checked live on the six
                # 2026-10-27 activations); the 'Other' targets are the fallback
                # only when it is missing, since they also carry other ids.
                $groupIds = if ($details['ResourceOriginId']) { @($details['ResourceOriginId']) }
                else { @($_.TargetResources | Where-Object { $_.Type -eq 'Other' -and $_.Id } | ForEach-Object { $_.Id }) }
                if (-not @($groupIds | Where-Object { $selectedGroupIds.Contains([string]$_) }).Count) { return }
            }
            $role = if ($isGroup) {
                # The group is the first 'Other' target; the Role target is the access (Member/Owner).
                $groupName = (@($_.TargetResources | Where-Object { $_.Type -eq 'Other' -and $_.DisplayName } | ForEach-Object { $_.DisplayName }) | Select-Object -First 1)
                "$groupName ($("$roleName".ToLowerInvariant()))"
            }
            elseif ($roleName) { $roleName } else { $details['RoleDefinitionOriginId'] }
            $rows.Add([pscustomobject]@{
                elevationType   = if ($isGroup) { 'PIM for Groups' } else { 'PIM for roles' }
                source          = 'directory audit log'
                requestId       = $requestId
                role            = $role
                principalId     = $_.InitiatedBy.User.Id
                principal       = $_.InitiatedBy.User.DisplayName
                action          = 'selfActivate'
                status          = "$($_.Result) ($($_.ActivityDisplayName))"
                justification   = $details['Justification']
                createdDateTime = $_.ActivityDateTime
                startDateTime   = $details['StartTime']
                expiration      = $details['ExpirationTime']
                ticketNumber    = $details['TicketNumber']
                mfa             = $details['IsAuthenticatedWithMfa']
            })
        }
    $rows.ToArray()
}

# ===========================================================================
# ARTIFACT 2 -- PIM active assignments (what is live right now)
# ===========================================================================
Export-Artifact -Name 'pim_active_assignments.json' -Control 'SOX least privilege / HIPAA 164.308(a)(4)' -Collector {
    if ($privRoleError) { throw $privRoleError }
    # (a) Live membership of each PIM-governed group (Activated = JIT, open now).
    foreach ($g in $pimGroups) {
        $uri = "$graphV1/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$($g.id)'&`$expand=principal"
        do {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($i in @(Get-Field $page 'value')) {
                [pscustomobject]@{
                    source          = 'PIM for Groups'
                    role            = "$($g.displayName) ($(Get-Field $i 'accessId'))"
                    isPrivileged    = $true
                    principalId     = Get-Field $i 'principalId'
                    principal       = Get-Field $i 'principal', 'displayName'
                    principalType   = Get-Field $i 'principal', '@odata.type'
                    isBreakGlass    = [bool]($bgGroup -and (Get-Field $i 'principalId') -eq $bgGroup['id'])
                    assignmentType  = Get-Field $i 'assignmentType'   # assigned | activated
                    memberType      = Get-Field $i 'memberType'
                    startDateTime   = Get-Field $i 'startDateTime'
                    endDateTime     = Get-Field $i 'endDateTime'
                }
            }
            $uri = $page['@odata.nextLink']
        } while ($uri)
    }
    # (b) Directory role instances (a group's binding to a role appears here
    # with the GROUP as principal; who is standing is computed in SUMMARY.md
    # from these rows, never assumed). principalType and isBreakGlass let
    # the summary count standing USER holders apart from groups, service
    # principals and the break-glass accounts (same rule as artifact 7).
    Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All `
        -ExpandProperty 'principal,roleDefinition' |
        ForEach-Object {
            $upn = $_.Principal.AdditionalProperties['userPrincipalName']
            [pscustomobject]@{
                source          = 'Directory role'
                role            = $_.RoleDefinition.DisplayName
                isPrivileged    = $privRoleIds.Contains([string]$_.RoleDefinitionId)
                principalId     = $_.PrincipalId
                principal       = $_.Principal.AdditionalProperties['displayName']
                principalType   = $_.Principal.AdditionalProperties['@odata.type']
                isBreakGlass    = [bool](($bgGroup -and $_.PrincipalId -eq $bgGroup['id']) -or ($upn -like 'bg-admin-*'))
                assignmentType  = $_.AssignmentType   # Assigned (standing) | Activated (JIT)
                memberType      = $_.MemberType
                startDateTime   = $_.StartDateTime
                endDateTime     = $_.EndDateTime
            }
        }
}

# ===========================================================================
# ARTIFACT 3 -- PIM activation activities (directory audit log)
# ===========================================================================
Export-Artifact -Name 'pim_activation_activities.json' -Control 'SOX audit logging / HIPAA 164.312(b)' -Collector {
    # PIM writes to the directory audit log; filter the PIM category.
    # REST (v1.0): GET /auditLogs/directoryAudits?$filter=loggedByService eq 'PIM'
    Get-MgAuditLogDirectoryAudit -All -Filter "loggedByService eq 'PIM'" |
        ForEach-Object {
            [pscustomobject]@{
                id                 = $_.Id
                activityDateTime   = $_.ActivityDateTime
                activityDisplayName = $_.ActivityDisplayName
                result             = $_.Result
                initiatedBy        = $_.InitiatedBy.User.UserPrincipalName
                targetResources    = ($_.TargetResources | ForEach-Object { $_.DisplayName }) -join '; '
            }
        }
}

# ===========================================================================
# ARTIFACT 4 -- Access review decisions
# ===========================================================================
# Window start, computed here (script scope) and read by the collector.
$reviewWindowStart = (Get-Date).ToUniversalTime().AddDays(-$AccessReviewLookbackDays)
Export-Artifact -Name 'access_review_decisions.json' -Control 'SOX periodic access recertification / HIPAA 164.308(a)(3)(ii)(B)' -Collector {
    $since = $reviewWindowStart
    $out = [System.Collections.Generic.List[object]]::new()
    $defs = Get-MgIdentityGovernanceAccessReviewDefinition -All
    foreach ($def in $defs) {
        $instances = Get-MgIdentityGovernanceAccessReviewDefinitionInstance -AccessReviewScheduleDefinitionId $def.Id -All |
            Where-Object { -not $_.EndDateTime -or $_.EndDateTime -ge $since }
        foreach ($inst in $instances) {
            $decisions = Get-MgIdentityGovernanceAccessReviewDefinitionInstanceDecision `
                -AccessReviewScheduleDefinitionId $def.Id -AccessReviewInstanceId $inst.Id -All -ErrorAction Stop   # unreadable decisions fail the artifact, never drop silently
            foreach ($d in $decisions) {
                $out.Add([pscustomobject]@{
                    reviewName        = $def.DisplayName
                    instanceId        = $inst.Id
                    instanceStart     = $inst.StartDateTime
                    instanceEnd       = $inst.EndDateTime
                    # principal is a typed identity: DisplayName/Id are real
                    # properties; only the userIdentity UPN is in AdditionalProperties.
                    principal         = $d.Principal.DisplayName
                    principalId       = $d.Principal.Id
                    principalUpn      = $d.Principal.AdditionalProperties['userPrincipalName']
                    decision          = $d.Decision         # Approve | Deny | NotReviewed | DontKnow
                    justification     = $d.Justification
                    reviewedBy        = $d.ReviewedBy.DisplayName
                    reviewedDateTime  = $d.ReviewedDateTime
                    appliedDateTime   = $d.AppliedDateTime
                })
            }
        }
    }
    $out
}

# ===========================================================================
# ARTIFACT 5 -- Conditional Access policy inventory
# ===========================================================================
Export-Artifact -Name 'conditional_access_policies.json' -Control 'SOX logical access / HIPAA 164.312(a)(1), 164.312(d)' -Collector {
    Get-MgIdentityConditionalAccessPolicy -All |
        ForEach-Object {
            [pscustomobject]@{
                id                 = $_.Id
                displayName        = $_.DisplayName
                state              = $_.State    # enabled | disabled | enabledForReportingButNotEnforced
                createdDateTime    = $_.CreatedDateTime
                modifiedDateTime   = $_.ModifiedDateTime
                includeUsers       = $_.Conditions.Users.IncludeUsers
                includeGroups      = $_.Conditions.Users.IncludeGroups
                includeRoles       = $_.Conditions.Users.IncludeRoles
                excludeUsers       = $_.Conditions.Users.ExcludeUsers
                excludeGroups      = $_.Conditions.Users.ExcludeGroups   # break-glass is excluded BY GROUP
                excludeRoles       = $_.Conditions.Users.ExcludeRoles
                excludesBreakGlass = if ($bgGroup) { $bgGroup['id'] -in @($_.Conditions.Users.ExcludeGroups) } else { $null }
                includeApplications = $_.Conditions.Applications.IncludeApplications
                grantControls      = $_.GrantControls.BuiltInControls
                authenticationStrength = $_.GrantControls.AuthenticationStrength.DisplayName   # CA002's control (builtInControls is empty)
                clientAppTypes     = $_.Conditions.ClientAppTypes
            }
        }
}

# ===========================================================================
# ARTIFACT 6 -- MFA registration coverage (+ computed %)
# ===========================================================================
Export-Artifact -Name 'mfa_registration_coverage.json' -Control 'SOX authentication / HIPAA 164.312(d) person-or-entity authentication' -Collector {
    $reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
    $total = @($reg).Count
    $mfaReg = @($reg | Where-Object { $_.IsMfaRegistered }).Count
    $coverage = if ($total) { [math]::Round(100.0 * $mfaReg / $total, 2) } else { 0 }
    # Return a header summary object followed by per-user rows.
    @(
        [pscustomobject]@{
            _summary        = $true
            totalUsers      = $total
            mfaRegistered   = $mfaReg
            coveragePercent = $coverage
            generatedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        }
    ) + @(
        $reg | ForEach-Object {
            [pscustomobject]@{
                userPrincipalName = $_.UserPrincipalName
                isMfaRegistered   = $_.IsMfaRegistered
                isMfaCapable      = $_.IsMfaCapable
                preferredMfaMethod = $_.UserPreferredMethodForSecondaryAuthentication   # v1.0 has no defaultMfaMethod
                systemPreferredMethods = ($_.SystemPreferredAuthenticationMethods -join ';')
                methodsRegistered = ($_.MethodsRegistered -join ';')
            }
        }
    )
}

# ===========================================================================
# ARTIFACT 7 -- Privileged role assignments (all, with break-glass flag)
# ===========================================================================
Export-Artifact -Name 'privileged_role_assignments.json' -Control 'SOX segregation of duties / HIPAA 164.308(a)(3), 164.308(a)(4)' -Collector {
    if ($privRoleError) { throw $privRoleError }
    # Graph expands ONE property per query: expand the principal, name the role from a lookup.
    $roleNames = @{}; Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleNames[[string]$_.Id] = $_.DisplayName }
    Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty 'principal' |
        Where-Object { $privRoleIds.Contains([string]$_.RoleDefinitionId) } |
        ForEach-Object {
            $upn = $_.Principal.AdditionalProperties['userPrincipalName']
            [pscustomobject]@{
                role              = $roleNames[[string]$_.RoleDefinitionId]
                principalId       = $_.PrincipalId
                principal         = $_.Principal.AdditionalProperties['displayName']
                userPrincipalName = $upn
                principalType     = $_.Principal.AdditionalProperties['@odata.type']
                directoryScopeId  = $_.DirectoryScopeId
                # GA is assigned to the Break-Glass-Admins GROUP; bg-admin-NN
                # member rows (if Graph lists them) are flagged too, as in 05-Reports.
                isBreakGlass      = [bool](($bgGroup -and $_.PrincipalId -eq $bgGroup['id']) -or ($upn -like 'bg-admin-*'))
            }
        }
}

# ===========================================================================
# COMPANION EVIDENCE -- files other scripts wrote under lab/evidence. Hashed
# into this manifest (not copied, not re-collected), so one manifest covers
# the capture window. Paths are relative to lab/evidence.
# ===========================================================================
$companionPatterns = @(
    @{ Pattern = 'out/nhi_inventory.json';                  Control = 'NHI ownership + credential inventory (OWASP NHI1-9) / HIPAA 164.308(a)(4)' }
    # The committed, counts-only copy of a tenant NHI run (06-NHI-Inventory.ps1
    # -PublicSummaryDirectory): the one a GitHub runner can see, because out/
    # is gitignored. Same tenant-only rule as the assessments.
    @{ Pattern = 'nhi/*/nhi-summary.json';                  Control = 'NHI inventory counts (OWASP NHI1-9) / HIPAA 164.308(a)(4)'; RunFolders = $true }
    @{ Pattern = 'out/nhi_findings.csv';                    Control = 'NHI findings (OWASP NHI) / SOX access control' }
    @{ Pattern = 'out/nhi_credentials.csv';                 Control = 'NHI credential lifetimes / HIPAA 164.312(d)' }
    @{ Pattern = 'out/shadow_admins.json';                  Control = 'Indirect privilege paths (shadow admins) / SOX segregation of duties' }
    @{ Pattern = 'out/agent_identity.json';                 Control = 'Agent identity: sponsor, MI-federated, no secret / HIPAA 164.312(d)' }
    @{ Pattern = 'out/app_management_policy_backup_*.json'; Control = 'App management policy before-change backup / SOX change management' }
    @{ Pattern = 'kpis/*.json';                             Control = 'KPI snapshots (before/after) / SOX monitoring' }
    @{ Pattern = 'drills/*.json';                           Control = 'Break-glass drill record / HIPAA 164.308(a)(7) contingency plan' }
    @{ Pattern = 'access-reviews/*.json';                   Control = 'Standalone access review definitions / HIPAA 164.308(a)(3)(ii)(B)' }
    @{ Pattern = 'assessments/*/summary.json';              Control = 'ScubaGear + Zero Trust baseline assessment / SOX monitoring'; RunFolders = $true }
    @{ Pattern = 'out/itdr/*.json';                         Control = 'ITDR AD containment record / HIPAA 164.308(a)(6) incident response' }
)
$evRoot = [System.IO.Path]::GetFullPath($EvidenceRoot)
Write-Console "`n- companion evidence under $evRoot" -ForegroundColor Cyan
foreach ($c in $companionPatterns) {
    $dir = Join-Path $evRoot (Split-Path -Path $c.Pattern -Parent)
    $leaf = Split-Path -Path $c.Pattern -Leaf
    $found = @()
    if ($c.ContainsKey('RunFolders')) {
        # <folder>/<run>/<file>: one level of run folders (assessments, nhi).
        $base = Join-Path $evRoot ($c.Pattern -split '/')[0]
        if (Test-Path -LiteralPath $base) { $found = @(Get-ChildItem -LiteralPath $base -Directory | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter $leaf -File }) }
    }
    elseif (Test-Path -LiteralPath $dir) { $found = @(Get-ChildItem -LiteralPath $dir -Filter $leaf -File) }
    if (-not $found.Count) {
        Write-Console "  [ ] $($c.Pattern) - absent" -ForegroundColor DarkGray
        $manifestArtifacts.Add([pscustomobject]@{ file = $c.Pattern; control = $c.Control; status = 'absent'; error = $null; recordCount = 0; sizeBytes = $null; sha256 = $null; generatedUtc = (Get-Date).ToUniversalTime().ToString('o'); source = 'companion' })
        continue
    }
    foreach ($f in $found) {
        $rel = [System.IO.Path]::GetRelativePath($evRoot, $f.FullName).Replace('\', '/')
        if ($c.ContainsKey('RunFolders')) {
            # A run-folder summary is evidence only when its writer recorded a
            # tenant run: source.kind (Invoke-BaselineAssessment.ps1) or source
            # (06-NHI-Inventory.ps1 -PublicSummaryDirectory). A summary built
            # from CISA's sample or a fixture, or one that predates the field,
            # is listed but never hashed in as evidence.
            $kind = $null
            try {
                $sj = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json -AsHashtable
                if ($sj -is [System.Collections.IDictionary]) {
                    if ($sj['source'] -is [System.Collections.IDictionary]) { $kind = [string]$sj['source']['kind'] }
                    elseif ($sj['source'] -is [string]) { $kind = $sj['source'] }
                }
            }
            catch { $kind = $null }
            if ($kind -ne 'tenant') {
                $why = if ($kind) { "source = $kind" } else { 'no source recorded (not written by a tenant run)' }
                Write-Warning "  $rel is NOT a tenant run ($why): listed as not-tenant, not hashed as evidence."
                $manifestArtifacts.Add([pscustomobject]@{ file = $rel; control = $c.Control; status = 'not-tenant'; error = $why; recordCount = $null; sizeBytes = $f.Length; sha256 = $null; generatedUtc = $f.LastWriteTimeUtc.ToString('o'); source = 'companion' })
                continue
            }
        }
        $manifestArtifacts.Add([pscustomobject]@{
            file = $rel; control = $c.Control; status = 'ok'; error = $null; recordCount = $null
            sizeBytes = $f.Length; sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
            generatedUtc = $f.LastWriteTimeUtc.ToString('o'); source = 'companion'
        })
        Write-Console "  [+] $rel" -ForegroundColor Green
    }
}

# ===========================================================================
# SUMMARY.md  (control mapping, human readable)  -- hashed by the manifest.
#
# Every statement about the tenant in it is COMPUTED from the records this run
# collected (or from the companion files it hashed), never written in as a
# fixed claim. WHY: the old template said "standing privileged humans =
# break-glass only" and "every app ... has an owner" whatever the records
# showed; live, the build account held a standing Global Administrator and 8
# of 19 robot identities had no owner (capture-log E70, E72). An evidence
# pack that asserts what it does not show is worse than none.
# Masking: counts, role names and file names only. No person's name, UPN or
# object id appears here (the pack's JSON files name people; this page gets
# shown on screen). Where a count is not zero, the line names the file that
# holds the names.
# ===========================================================================
function Get-SummaryValue($Object, [string]$Name) {
    # One accessor for collector objects (pscustomobject) and JSON read back
    # as hashtables; a missing property is $null, never a StrictMode error.
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value } else { return $null }
}

function Get-EvidenceRecordText {
    # The computed "found in this pack" text for one collected artifact.
    param([Parameter(Mandatory)][string]$Name, [System.Collections.IDictionary]$Records = @{})
    if (-not $Records.Contains($Name)) { return 'Not collected in this run.' }
    $r = $Records[$Name]
    if ($r['status'] -ne 'ok') { return 'Could not be collected in this run (the error is in manifest.json); nothing is claimed for it.' }
    $rows = @($r['data'] | Where-Object { $null -ne $_ })
    # Null-safe counts: piping an empty result ($null) into ForEach-Object
    # runs it once, and @($null).Count is 1, so filter $null out first.
    $count = { param($Items) @($Items | Where-Object { $null -ne $_ }).Count }
    switch ($Name) {
        'pim_activation_history.json' {
            # The rows are activation REQUESTS: the requests API also returns
            # pending and refused ones. Only granted ones are elevations.
            # Status values: Learn, privilegedAccessGroupAssignmentScheduleRequest
            # (Granted, Provisioned, ScheduleCreated, Pending*, Denied, Canceled,
            # Revoked, Failed); audit-log rows read "success (...)".
            $st = { param($r) [string](Get-SummaryValue $r 'status') }
            $granted = @($rows | Where-Object { (& $st $_) -match '^(Granted|Provisioned|ScheduleCreated|success\b)' })
            $pending = & $count ($rows | Where-Object { (& $st $_) -like 'Pending*' })
            $refused = & $count ($rows | Where-Object { (& $st $_) -match '^(Denied|Canceled|Revoked|Failed)' })
            $other = $rows.Count - $granted.Count - $pending - $refused
            $groups = & $count ($granted | Where-Object { (Get-SummaryValue $_ 'elevationType') -eq 'PIM for Groups' })
            $roles = & $count ($granted | Where-Object { (Get-SummaryValue $_ 'elevationType') -eq 'PIM for roles' })
            $why = & $count ($granted | Where-Object { [string](Get-SummaryValue $_ 'justification') })
            $mfa = & $count ($granted | Where-Object { [string](Get-SummaryValue $_ 'mfa') -match '^(?i)true$' })
            $line = "$($rows.Count) activation request(s): $($granted.Count) granted, $pending pending, $refused denied, cancelled, revoked or failed"
            if ($other) { $line += ", $other with another status" }
            return "$line. Of the granted: $groups through PIM for Groups, $roles through PIM for directory roles; $why with a justification; $mfa with MFA confirmed in the audit log. Directory-role and older group activations come from the directory audit log, which keeps 30 days."
        }
        'pim_active_assignments.json' {
            $dir = @($rows | Where-Object { (Get-SummaryValue $_ 'source') -eq 'Directory role' -and (Get-SummaryValue $_ 'isPrivileged') })
            $standing = @($dir | Where-Object { [string](Get-SummaryValue $_ 'assignmentType') -eq 'Assigned' })
            $activated = @($dir | Where-Object { [string](Get-SummaryValue $_ 'assignmentType') -eq 'Activated' })
            $ids = { param($Items) @($Items | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-SummaryValue $_ 'principalId') } | Sort-Object -Unique).Count }
            $bg = & $ids ($standing | Where-Object { Get-SummaryValue $_ 'isBreakGlass' })
            $notBg = @($standing | Where-Object { -not (Get-SummaryValue $_ 'isBreakGlass') })
            $userRows = @($notBg | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.user' -and [string](Get-SummaryValue $_ 'memberType') -ne 'Group' })
            $users = & $ids $userRows
            # 'Assigned' means not just in time, not necessarily forever: count
            # the ones with no end date apart.
            $noEnd = & $ids ($userRows | Where-Object { -not (Get-SummaryValue $_ 'endDateTime') })
            # Users the instances list as holding the role THROUGH a group
            # (memberType Group). Standing members of other role-holding groups
            # are not expanded here; the line says so.
            $viaGroup = & $ids ($notBg | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.user' -and [string](Get-SummaryValue $_ 'memberType') -eq 'Group' })
            $grps = & $ids ($notBg | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.group' })
            $sps = & $ids ($notBg | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.servicePrincipal' })
            $unknown = & $ids ($notBg | Where-Object { (Get-SummaryValue $_ 'principalType') -notin '#microsoft.graph.user', '#microsoft.graph.group', '#microsoft.graph.servicePrincipal' })
            $grpRows = @($rows | Where-Object { (Get-SummaryValue $_ 'source') -eq 'PIM for Groups' })
            $grpAssigned = & $count ($grpRows | Where-Object { [string](Get-SummaryValue $_ 'assignmentType') -eq 'assigned' })
            $grpActivated = & $count ($grpRows | Where-Object { [string](Get-SummaryValue $_ 'assignmentType') -eq 'activated' })
            $line = "Standing (Assigned, not just-in-time) privileged directory-role holders: $users user account(s) outside break-glass assigned directly ($noEnd with no end date), $bg break-glass principal(s), $grps group(s), $sps service principal(s)"
            if ($unknown) { $line += ", $unknown of unknown type" }
            $line += ". Users listed as holding a role through a group: $viaGroup; standing members of the other role-holding groups are not expanded here. Privileged roles activated just in time right now: $($activated.Count). PIM for Groups rows (the governed groups): $grpAssigned standing (assigned), $grpActivated activated."
            if ($users -gt 0) { $line += " **Not zero standing admin:** $users user account(s) outside break-glass hold a standing privileged role directly (names in this file)." }
            else { $line += ' No user account outside break-glass holds a standing privileged role by direct assignment; access through groups is counted separately above.' }
            return $line
        }
        'pim_activation_activities.json' { return "$($rows.Count) PIM entries in the directory audit log (30-day retention)." }
        'access_review_decisions.json' {
            if (-not $rows.Count) { return '0 review decisions in the lookback window: nothing here shows a completed review.' }
            $by = @($rows | Group-Object { [string](Get-SummaryValue $_ 'decision') } | Sort-Object Name | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
            return "$($rows.Count) review decision(s): $by."
        }
        'conditional_access_policies.json' {
            $on = & $count ($rows | Where-Object { (Get-SummaryValue $_ 'state') -eq 'enabled' })
            $ro = & $count ($rows | Where-Object { (Get-SummaryValue $_ 'state') -eq 'enabledForReportingButNotEnforced' })
            $off = & $count ($rows | Where-Object { (Get-SummaryValue $_ 'state') -eq 'disabled' })
            $bgYes = & $count ($rows | Where-Object { (Get-SummaryValue $_ 'excludesBreakGlass') -eq $true })
            $bgNo = & $count ($rows | Where-Object { (Get-SummaryValue $_ 'excludesBreakGlass') -eq $false })
            $bgUnknown = $rows.Count - $bgYes - $bgNo
            $line = "$($rows.Count) Conditional Access policies: $on enforced, $ro report-only, $off off. $bgYes of $($rows.Count) exclude the break-glass group"
            if ($bgNo) { $line += "; **$bgNo do not**" }
            if ($bgUnknown) { $line += "; $bgUnknown unknown (break-glass group not found)" }
            return "$line."
        }
        'mfa_registration_coverage.json' {
            $sum = @($rows | Where-Object { Get-SummaryValue $_ '_summary' }) | Select-Object -First 1
            if (-not $sum) { return 'No coverage summary row in the file.' }
            return "$(Get-SummaryValue $sum 'mfaRegistered') of $(Get-SummaryValue $sum 'totalUsers') users registered for MFA ($(Get-SummaryValue $sum 'coveragePercent')%). Registration is not enforcement: who must use MFA is in conditional_access_policies.json (each policy's users and grant controls)."
        }
        'privileged_role_assignments.json' {
            $bg = & $count ($rows | Where-Object { Get-SummaryValue $_ 'isBreakGlass' })
            $rest = @($rows | Where-Object { -not (Get-SummaryValue $_ 'isBreakGlass') })
            $users = & $count ($rest | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.user' })
            $grps = & $count ($rest | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.group' })
            $sps = & $count ($rest | Where-Object { (Get-SummaryValue $_ 'principalType') -eq '#microsoft.graph.servicePrincipal' })
            $roles = @($rows | ForEach-Object { [string](Get-SummaryValue $_ 'role') } | Sort-Object -Unique).Count
            return "$($rows.Count) assignment(s) on $roles privileged role(s): $bg break-glass, $users to user accounts, $grps to groups, $sps to service principals (names in this file)."
        }
        default { return "$($rows.Count) record(s)." }
    }
}

function ConvertTo-EvidenceSummaryMarkdown {
    # Pure: builds SUMMARY.md from what this run collected. Unit-tested in
    # tests/Export-EvidencePack.Tests.ps1 (no Graph, no files).
    param(
        [System.Collections.IDictionary]$Records = @{},
        [object[]]$Companion = @(),            # the manifest's companion rows (file, status, control)
        [System.Collections.IDictionary]$Nhi = $null,   # newest tenant NHI counts, or $null
        [System.Collections.IDictionary]$Kpi = $null,   # newest KPI snapshot facts, or $null
        [string]$TenantId = '<tenant>',
        [string]$GeneratedUtc = ''
    )
    $rowsMd = @(
        @('pim_activation_history.json', 'Just-in-time elevations: who, which role, when, for how long, why.', 'ITGC Access Control; Change Management', '164.312(a)(1) Access Control; 164.308(a)(4) Information Access Management'),
        @('pim_active_assignments.json', 'Privilege live at export time, standing (Assigned) vs just in time (Activated).', 'Least Privilege', '164.308(a)(4)'),
        @('pim_activation_activities.json', 'The raw directory audit entries behind each PIM action.', 'Audit Logging / Monitoring', '164.312(b) Audit Controls'),
        @('access_review_decisions.json', 'Recertification decisions: whose access, reviewer, decision, time.', 'Periodic Access Recertification', '164.308(a)(3)(ii)(B) Workforce Clearance; 164.308(a)(4)'),
        @('conditional_access_policies.json', 'Every Conditional Access policy, its state and its break-glass exclusion.', 'Logical Access Security', '164.312(a)(1); 164.312(d) Person/Entity Authentication'),
        @('mfa_registration_coverage.json', 'Per-user MFA registration, with a computed coverage %.', 'Authentication Controls', '164.312(d)'),
        @('privileged_role_assignments.json', 'Every assignment on a privileged directory role, break-glass flagged.', 'Segregation of Duties', '164.308(a)(3); 164.308(a)(4)')
    ) | ForEach-Object { "| ``$($_[0])`` | $($_[1]) | $(Get-EvidenceRecordText -Name $_[0] -Records $Records) | $($_[2]) | $($_[3]) |" }

    # Companion evidence: what each kind is, and what this pack found.
    $kinds = @(
        @('out/nhi_inventory.json', 'nhi/*/nhi-summary.json', '06-NHI-Inventory.ps1', 'Non-human identities: owners, credentials, Tier-0 rights, mapped to OWASP NHI Top 10'),
        @('out/shadow_admins.json', $null, 'Find-ShadowAdmins.ps1', 'Indirect paths to admin (owners of role-assignable groups / Tier-0 apps)'),
        @('out/agent_identity.json', $null, 'post-apply/New-AgentIdentity.ps1', 'The agent identity, its sponsor and its credential type'),
        @('out/app_management_policy_backup_*.json', $null, 'post-apply/Set-AppGovernancePolicy.ps1', 'The tenant app policy before it was changed'),
        @('kpis/*.json', $null, '08-Measure-KPIs.ps1', 'KPI snapshots (public-safe aggregates, each with a .sha256)'),
        @('drills/*.json', $null, 'Invoke-BreakGlassDrill.ps1', 'Break-glass drill records'),
        @('access-reviews/*.json', $null, 'post-apply/New-AccessReviewDefinitions.ps1', 'Access review definitions'),
        @('assessments/*/summary.json', $null, 'Invoke-BaselineAssessment.ps1', 'CISA ScubaGear / Zero Trust Assessment summaries'),
        @('out/itdr/*.json', $null, 'monitoring/Invoke-AdContainment.ps1', 'ITDR AD containment records')
    )
    $patternRegex = { param($p) '^' + ([regex]::Escape($p) -replace '\\\*', '[^/]+') + '$' }
    $compMd = foreach ($k in $kinds) {
        $pats = @($k[0], $k[1] | Where-Object { $_ })
        $mine = @($Companion | Where-Object { $f = [string](Get-SummaryValue $_ 'file'); @($pats | Where-Object { $f -match (& $patternRegex $_) -or $f -eq $_ }).Count })
        $ok = @($mine | Where-Object { (Get-SummaryValue $_ 'status') -eq 'ok' })
        $notTenant = @($mine | Where-Object { (Get-SummaryValue $_ 'status') -eq 'not-tenant' })
        $found = if (-not $ok.Count) { 'Absent: not captured in this pack, so nothing is claimed.' } else { "$($ok.Count) file(s) hashed." }
        if ($notTenant.Count) { $found += " $($notTenant.Count) listed as not a tenant run (not evidence)." }
        if ($k[0] -eq 'out/nhi_inventory.json' -and $Nhi) {
            $found = "Latest tenant inventory (``$($Nhi['file'])``, $($Nhi['generatedAtUtc'])): $($Nhi['nhiCount']) non-human identities; **$($Nhi['orphanedNhi']) without an accountable owner**; $($Nhi['tierZeroNhi']) Tier 0; $($Nhi['expired']) with an expired credential. $($ok.Count) file(s) hashed."
            if ($Nhi['complete'] -ne $true) { $found += ' **Incomplete run: a data source failed, so these counts are a minimum, not a clean result.**' }
        }
        if ($k[0] -eq 'kpis/*.json' -and $Kpi) {
            $found += " Latest snapshot (``$($Kpi['file'])``, label ``$($Kpi['label'])``): standing privileged humans = $($Kpi['standing']) (break-glass counted apart)."
        }
        $shown = (@($pats) | ForEach-Object { "``$_``" }) -join ', '
        "| $shown | ``$($k[2])`` | $($k[3]) | $found |"
    }

    return @"
# Contoso Health -- Identity Evidence Pack

**Organization:** Contoso Health
**Tenant:** $TenantId
**Generated (UTC):** $GeneratedUtc
**Generated by:** Export-EvidencePack.ps1

This pack is a point-in-time, tamper-evident export of the identity controls
in the Entra ID tenant. Re-hash each file and compare it with ``manifest.json``
(SHA256). Every "found" cell below is computed from the records in this pack
at export time: counts only, no names (the JSON files hold the names). A
failed or absent record is said to be failed or absent, never read as clean.

| Artifact | What it holds | Found in this pack | SOX control | HIPAA Security Rule |
|---|---|---|---|---|
$($rowsMd -join "`n")

### Companion evidence (hashed in ``manifest.json``, paths relative to ``lab/evidence``)

| Evidence | Produced by | What it holds | Found in this pack |
|---|---|---|---|
$($compMd -join "`n")

## How to verify integrity

``````powershell
# Re-hash an artifact and compare to manifest.json:
(Get-FileHash ./pim_activation_history.json -Algorithm SHA256).Hash
Get-Content ./manifest.json | ConvertFrom-Json |
    Select-Object -ExpandProperty artifacts |
    Where-Object file -eq 'pim_activation_history.json'
``````

> Artifacts with ``status: failed`` in the manifest could not be collected
> (missing license, scope, or data) and contain an error stub -- this is
> recorded honestly rather than omitted.
"@
}

# Facts from the companion files this run hashed (newest tenant record of each kind).
function Get-CompanionFact {
    param([object[]]$Companion = @(), [Parameter(Mandatory)][string]$EvidenceRoot)
    $nhi = $null; $kpi = $null
    # ConvertFrom-Json turns ISO timestamps into [datetime]; print them as ISO
    # again (a culture-formatted date is ambiguous in an audit file).
    $iso = { param($v) if ($v -is [datetime]) { $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$v } }
    foreach ($row in @($Companion | Where-Object { (Get-SummaryValue $_ 'status') -eq 'ok' })) {
        $file = [string](Get-SummaryValue $row 'file')
        $path = Join-Path $EvidenceRoot $file
        if ($file -notmatch '^(out/nhi_inventory\.json|nhi/[^/]+/nhi-summary\.json|kpis/[^/]+\.json)$') { continue }
        try { $j = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable } catch { continue }
        if ($file -like 'kpis/*') {
            if ([string]$j['schema'] -ne 'contoso-identity-kpis/v1') { continue }
            $s = $j['kpis']['admin_standing_users']
            $cand = @{ file = $file; label = [string]$j['label']; generatedAtUtc = (& $iso $j['generatedAtUtc'])
                standing = if ($s -and $s['status'] -eq 'measured') { "$($s['value'])" } else { "not measured ($([string]$s['status']))" } }
            if (-not $kpi -or [datetime]$cand['generatedAtUtc'] -gt [datetime]$kpi['generatedAtUtc']) { $kpi = $cand }
            continue
        }
        # NHI: out/nhi_inventory.json (Source/Summary) or the public nhi-summary.json (source/summary).
        $src = if ($j.Contains('Source')) { [string]$j['Source'] } else { [string]$j['source'] }
        if ($src -ne 'tenant') { continue }
        $sum = if ($j.Contains('Summary')) { $j['Summary'] } else { $j['summary'] }
        $at = & $iso $(if ($j.Contains('GeneratedAtUtc')) { $j['GeneratedAtUtc'] } else { $j['generatedAtUtc'] })
        if (-not $sum -or -not $sum['kpi']) { continue }
        # Complete only when every data source was read: the public summary
        # records it as complete, the full inventory as DataSources statuses.
        # A partial run's counts are a floor, and the page says so.
        $complete = if ($j.Contains('complete')) { $j['complete'] -eq $true }
        elseif ($j.Contains('DataSources')) { -not @(@($j['DataSources']) | Where-Object { $_ -and [string]$_['Status'] -like 'FAILED*' }).Count }
        else { $false }   # completeness not recorded: never assume it
        $cand = @{ file = $file; generatedAtUtc = $at; nhiCount = $sum['nhiCount']; orphanedNhi = $sum['kpi']['orphanedNhi']
            tierZeroNhi = $sum['kpi']['tierZeroNhi']; expired = $sum['kpi']['nhiWithExpiredCredential']; complete = [bool]$complete }
        if (-not $nhi -or [datetime]$cand['generatedAtUtc'] -gt [datetime]$nhi['generatedAtUtc']) { $nhi = $cand }
    }
    return @{ Nhi = $nhi; Kpi = $kpi }
}

$summaryPath = Join-Path $OutputDirectory 'SUMMARY.md'
if ($PSCmdlet.ShouldProcess($summaryPath, 'write SUMMARY.md')) {
    $nowUtc = (Get-Date).ToUniversalTime().ToString('o')
    $tenant = if ($ctx) { $ctx.TenantId } else { '<tenant>' }
    $companionRows = @($manifestArtifacts | Where-Object { $_.PSObject.Properties['source'] -and $_.source -eq 'companion' })
    $facts = Get-CompanionFact -Companion $companionRows -EvidenceRoot $evRoot
    $summary = ConvertTo-EvidenceSummaryMarkdown -Records $collected -Companion $companionRows -Nhi $facts['Nhi'] -Kpi $facts['Kpi'] -TenantId $tenant -GeneratedUtc $nowUtc
    $summary | Set-Content -LiteralPath $summaryPath -Encoding utf8
    $hash = (Get-FileHash -LiteralPath $summaryPath -Algorithm SHA256).Hash
    $size = (Get-Item -LiteralPath $summaryPath).Length
    $manifestArtifacts.Add([pscustomobject]@{
        file = 'SUMMARY.md'; control = 'control mapping (human readable)'; status = 'ok'
        error = $null; recordCount = $null; sizeBytes = $size; sha256 = $hash
        generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    })
}

# ===========================================================================
# manifest.json  (written LAST; hashes every other file, not itself)
# ===========================================================================
$manifestPath = Join-Path $OutputDirectory 'manifest.json'
$manifest = [pscustomobject]@{
    evidencePack = [pscustomobject]@{
        organization    = 'Contoso Health'
        tenantId        = if ($ctx) { $ctx.TenantId } else { $null }
        generatedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        generatedBy     = if ($GeneratedBy) { $GeneratedBy } elseif ($ctx -and $ctx.Account) { $ctx.Account } elseif ($ctx -and $ctx.PSObject.Properties['ClientId'] -and $ctx.ClientId) { "app $($ctx.ClientId) (app-only)" } else { $null }
        hashAlgorithm   = 'SHA256'
        toolVersion     = '1.0.0'
    }
    artifacts = $manifestArtifacts
}
if ($PSCmdlet.ShouldProcess($manifestPath, 'write manifest.json')) {
    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $manifestPath -Encoding utf8
    Write-Console "`n[+] Wrote manifest.json ($($manifestArtifacts.Count) artifacts hashed)." -ForegroundColor Green
}

Write-Console "`nEvidence pack complete: $OutputDirectory" -ForegroundColor Cyan
return $manifest
