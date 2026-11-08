<#
.SYNOPSIS
    Creates, idempotently, the two Entra ID Governance Lifecycle Workflows the
    video shows: "Contoso - Joiner (Nursing, day 1)" and "Contoso - Leaver
    (real-time termination)" - plus, with -IncludeMover (off by default), a
    third: "Contoso - Mover (department change)". Every task definition, the access package and
    its assignment policy are resolved BY NAME at runtime. No GUIDs are
    hardcoded.

.DESCRIPTION
    Video segment 2 (Joiner: "a Lifecycle Workflow runs pre-hire + day-1
    tasks") and the optional Governance path of segment 7 (Leaver). The
    equivalent portal clicks produce the same objects; this script makes them
    repeatable and reviewable.

    Lifecycle Workflows have no azuread Terraform resource, so they live here
    with the other post-apply Graph gaps (Set-AccessPackageSoD.ps1,
    Set-PimGroupEligibility.ps1). The script talks to Microsoft Graph v1.0
    directly (Invoke-MgGraphRequest) at:
        /identityGovernance/lifecycleWorkflows/taskDefinitions   (read)
        /identityGovernance/lifecycleWorkflows/workflows         (create / read)
        /identityGovernance/lifecycleWorkflows/workflows/{id}/createNewVersion
        /identityGovernance/lifecycleWorkflows/workflows/{id}/activate  (run on demand)

    THE TWO WORKFLOWS
      Joiner  category joiner. Trigger: time-based, employeeHireDate, offset 0
              days. Scope rule: (department eq 'Nursing'). Tasks, in order:
                1. Enable user account                    continueOnError
                2. Generate TAP and send email (manager)  continueOnError
                3. Request user access package assignment "Nurse - Clinical Apps"
                4. Add user to groups                     only if -JoinerGroupMailNicknames
      Leaver  category leaver. On-demand only (the "Real-time employee
              termination" pattern: HR says terminate NOW). Tasks, in order,
              contain first, then clean up (same order as 04-Leaver.ps1):
                1. Disable user account
                2. Revoke all refresh tokens for user
                3. Cancel pending access package assignment requests for user
                4. Remove all access package assignments for user
                5. Remove user from all groups
                6. Remove all licenses for user
              Deliberately NOT included: "Delete user account" (AD owns the
              object, and a hospital keeps a terminated identity for audit),
              Teams removal (no Teams in scope; Microsoft 365 groups are
              already covered by task 5).
      Scheduled leaver  category leaver, ONLY with -IncludeScheduledLeaver
              (default off). The same six tasks as the leaver above, but it runs
              BY ITSELF: trigger "Group membership change", action "Removed from
              group", scope = the dynamic group All-Workforce (mailNickname
              -LeaverTriggerGroupMailNickname; rule: synced, member, accountEnabled
              true). When HR's leaver disables the AD account, Cloud Sync turns
              accountEnabled off, the rule drops the user, and the next scheduled
              evaluation runs the leaver (every 3 hours by default; the tenant's
              workflowScheduleIntervalInHours, read 2026-11-07: 3).
              Why: until this, the package stayed on a leaver until IT ran
              04-Leaver.ps1 or the on-demand leaver by hand (E122). The automatic
              assignment policy alone removes the package only after its 3-day
              grace period (ADR 0012), on purpose.
              Trade-off, said plainly: ANY disable of a synced account (for
              example Invoke-AdContainment.ps1 in an incident) also drops the user
              from All-Workforce, so this workflow strips their packages and
              groups too. For a compromised account that is the safe side; a
              restored account requests its packages again.
              Source: Microsoft Learn, "Lifecycle workflow execution conditions"
              (Group membership change trigger, Workflow scheduling) and the Graph
              beta create-workflow example 'leaver ... membershipChangeTrigger
              changeType remove, scope groupBasedSubjectSet groups [{id}]'.
              verify: the v1.0 endpoint accepts this shape (the resource types are
              in v1.0) and a DYNAMIC group as the scope group, on the first create.
      Mover   category mover, ONLY with -IncludeMover (staging switch, default
              off). Trigger: attribute change on department / jobTitle (HR is
              the source: the change arrives through HR -> AD -> Cloud Sync).
              Scope rule: (department eq -MoverToDepartment, default ICU).
              Tasks, in order - the scripted package swap of 03-Mover.ps1 as
              governance automation:
                1. Request user access package assignment  -MoverToPackage
                                                           (ICU - Critical Care Apps)
                2. Remove access package assignment        -MoverFromPackage
                                                           (Nurse - Clinical Apps)
                3. Send the manager a "user moved" email    continueOnError
              Where Set-AutoAssignmentPolicies.ps1 has made the clinical
              packages attribute-driven (ADR 0012 T3), tasks 1-2 become the
              belt-and-braces path: every task is continueOnError, and the
              automatic policy's 72-hour grace still applies. 03-Mover.ps1
              stays the on-demand verification / fallback.
              verify: the attributeChangeTrigger shape (triggerAttributes
              [{name}]) and the mover task display names in the tenant's task
              definitions (resolved by name, like every other task).

    HYBRID: WHO OWNS accountEnabled (read this before running)
      Workers are created by HR -> AD (API-driven inbound provisioning to
      on-premises AD) -> Cloud Sync -> Entra, exactly as 04-Leaver.ps1 assumes.
      The HR feed already decides enabled/disabled: the provisioning job maps
      SCIM active -> AD accountDisabled (NOT), and Cloud Sync carries it up.
      Lifecycle Workflows CAN write accountDisabled to on-premises AD for
      synced users, but only when (a) the Microsoft Entra provisioning agent
      >= 1.1.1586.0 is installed with the "HR-driven provisioning / Microsoft
      Entra Connect Sync" extension configuration, (b) its gMSA has rights on
      the user objects, and (c) the task argument enableOnPremisesAccount /
      disableOnPremisesAccount is "true" (Microsoft Learn: "Managing users
      synchronized from AD DS with Lifecycle Workflows").
      This lab keeps ONE owner per attribute, so by default those arguments
      are "false":
        * synced users  - the enable/disable task does not touch AD; HR already
                          did it. Re-enabling or disabling a synced worker is a
                          change to hr_feed.csv, never a cloud write.
                          # verify: whether such a run shows the task as
                          # Skipped or Failed in Workflow history. Both tasks
                          # are continueOnError, so the rest of the run proceeds
                          # either way.
        * cloud-only users - the task enables/disables in Entra directly.
      -ManageOnPremisesAccounts flips them to "true". Then TWO writers own one
      attribute: if HR still says active, the next HR push re-enables what the
      workflow disabled. Use it only for workers HR does not map accountDisabled
      for. Also documented by Microsoft: these account tasks do not support
      users with Entra role assignments or members/owners of role-assignable
      groups.
      Everything else (TAP, access packages, groups, tokens, licenses) is
      cloud-side and works the same for synced and cloud-only users.

    THE employeeHireDate GAP (why scheduling is OFF by default)
      The time trigger needs employeeHireDate in Entra. There is no matching AD
      attribute, so for this hybrid path the hire date must travel:
        hr_feed.csv startDate -> SCIM payload (Invoke-InboundProvisioning.ps1
        sends it as hireDate in the custom extension
        urn:ietf:params:scim:schemas:extension:contoso:1.0:User) -> provisioning
        expression FormatDateTime(...,"yyyyMMddHHmmss.fZ") into an AD string
        attribute such as msDS-cloudExtensionAttribute1 -> Cloud Sync mapping
        msDS-cloudExtensionAttribute1 -> employeeHireDate. The two mappings are
        TENANT-TIME steps (verify: on the first job setup); the birthright
        policies need the same date (Set-AutoAssignmentPolicies.ps1 refuses to
        run while nobody in scope has it).
      Until the mappings are confirmed, the workflow is created with scheduling disabled and
      the demo uses Run on demand (which ignores the trigger and the scope -
      Microsoft Learn, workflow: activate). -EnableJoinerSchedule turns the
      tenant schedule on (default every 3 hours) once the date flows.
      LAB, 2026-11-05 (capture E91): the date flows (Cloud Sync carries
      EmployeeHireDate, e.g. Helen Carter's 2016-02-01), so the joiner was
      re-run with -EnableJoinerSchedule -UpdateExisting: scheduling is ON.
      Before switching it on, check the catch-up window: Microsoft Learn
      ("Understanding lifecycle workflows", Scheduling) says a time-based
      workflow still processes a user whose trigger date passed up to three
      days earlier. That day no Nursing user had a hire date in the window,
      so the first scheduled runs processed nobody. Keep -EnableJoinerSchedule
      on every later run of this script, or -UpdateExisting turns it off.

    WHY NO GROUP TASK BY DEFAULT
      The app groups (App-ServiceNow-Users, App-AWS-IdentityCenter-Users) are
      granted BY the access package, so its 180-day expiry and SoD rule govern
      them. A direct "Add user to groups" would create membership the package
      cannot expire. All-Nurses is dynamic, and the task cannot touch dynamic,
      role-assignable, mail-enabled or AD-synced groups anyway. Pass
      -JoinerGroupMailNicknames only for cloud-only assigned groups that are
      genuinely birthright and not package-delivered (the script refuses the
      unsupported kinds before creating anything).

    IDEMPOTENT
      Get-then-create by display name. If the workflow exists, its trigger,
      scope and tasks (definition, arguments, enabled, continueOnError) are
      compared with the desired state:
        * equal      -> nothing to do
        * different  -> reported; with -UpdateExisting a NEW VERSION is created
                        (POST .../createNewVersion - tasks and execution
                        conditions are versioned, not patched)
        * description / isEnabled / isSchedulingEnabled differ only -> PATCH
          (with -UpdateExisting)

.PREREQUISITES
    * Entra ID Governance (or Entra Suite) licensing - Lifecycle Workflows are
      a Governance feature. Every user a workflow processes needs the license.
    * Terraform envs/dev applied with enable_governance = true, so the access
      package "Nurse - Clinical Apps" and its assignment policy exist.
    * Signed-in admin holds Lifecycle Workflows Administrator (create/run) and
      at least Catalog reader / Identity Governance Administrator (read the
      access package).
    * TAP task: the Temporary Access Pass authentication-method policy is
      enabled and -TapLifetimeMinutes / -TapIsUsableOnce fit inside it; the
      joiner has a manager (HR feed manager column) whose Entra user has a
      MAIL attribute (lab, 2026-11-07, E121: Grace Mwangi had none, and the
      task failed). For synced users mail comes from AD, so the HR job must
      write AD mail: lab/scripts/dc/configure-sync.py hrapp --mail-domain.
      Delivery is a separate question: contosohealthlab.com has no mail
      service in the lab (Graph /domains: supportedServices empty, read
      2026-11-07), so the email is sent to an address nobody reads. Never say
      on camera that the manager receives it. Production: the manager's real
      Exchange Online mailbox; and the joiner has no other auth methods, no
      sign-ins and no role assignments yet - otherwise that task fails (and,
      being continueOnError, the run continues). Microsoft Learn: the TAP
      starts at the user's employeeHireDate (or now, if that is in the past).
      With employeeHireDate EMPTY the task FAILS: "EmployeeHireDate
      attribute is missing" (lab, 2026-11-05, first on-demand run for the
      cloud-only test-user-c; E91). The run goes on (continueOnError). With
      the date set, the re-run completed all three tasks.
    * Request-access-package task: approval on the policy is bypassed for this
      admin-style request unless the Entitlement Management setting "Enforce
      policy approval setting for admin direct assignments" is on.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated; admin-consent)
    LifecycleWorkflows.ReadWrite.All     read task definitions; create, version,
                                         patch and activate workflows
    EntitlementManagement.Read.All       resolve the access package + policy
    Group.Read.All                       only with -JoinerGroupMailNicknames
    User.Read.All                        only with -RunJoinerFor / -RunLeaverFor
    (-OfflinePreview needs no connection at all.)

.PARAMETER JoinerWorkflowName
    Display name of the joiner workflow. Default "Contoso - Joiner (Nursing, day 1)".

.PARAMETER LeaverWorkflowName
    Display name of the leaver workflow. Default "Contoso - Leaver (real-time termination)".

.PARAMETER JoinerDepartment
    Department value in the joiner scope rule. Default Nursing (HR feed 'dept').

.PARAMETER HireDateOffsetDays
    Days relative to employeeHireDate the joiner triggers (0 = on the day).

.PARAMETER AccessPackageName
    Package the joiner requests. Default "Nurse - Clinical Apps".

.PARAMETER AssignmentPolicyName
    Policy of that package to request through. Empty = the package's only
    policy (Terraform creates exactly one: "<package> - 180 day").

.PARAMETER JoinerGroupMailNicknames
    Optional cloud-only, assigned, non-role-assignable security / Microsoft 365
    groups to add on day 1 (one "Add user to groups" task each). Default none.

.PARAMETER TapLifetimeMinutes
    Temporary Access Pass lifetime, 10..43200. Default 480 (8 h, inside the
    default TAP policy maximum). WHY not shorter: the joiner runs on
    employeeHireDate (midnight UTC) on a 3-hour schedule, so the manager's
    email can arrive hours before the morning shift; a 1-2 hour pass expires
    unread. The emailed TAP is an accepted exception, with its reason, in
    ADR 0016 ("Exception: the joiner's day-one TAP is emailed to the
    manager"). Shorten it only when HR sends a real start time.

.PARAMETER TapIsUsableOnce
    One-time-use TAP. Default $true, which every TAP policy accepts.

.PARAMETER ManageOnPremisesAccounts
    Let the enable/disable tasks write accountDisabled in on-premises AD for
    synced users (see HYBRID above). Default off: HR owns it.

.PARAMETER EnableJoinerSchedule
    Turn on scheduled runs of the joiner (isSchedulingEnabled). Default off
    until employeeHireDate flows (see THE employeeHireDate GAP).

.PARAMETER UpdateExisting
    Apply drift: create a new workflow version (tasks / trigger / scope) or
    PATCH settings. Without it, drift is only reported.

.PARAMETER RunJoinerFor
    UPNs to run the joiner workflow for ON DEMAND after create/verify. Each
    user's department must equal -JoinerDepartment (on-demand runs ignore the
    scope rule, so the script enforces it) unless -Force.

.PARAMETER RunLeaverFor
    UPNs to run the leaver workflow for ON DEMAND. Destructive: asks for
    confirmation unless -Force. A synced user who is still ENABLED is refused
    unless -Force: HR has not terminated them yet (edit hr_feed.csv first).
    That guard is off with -ManageOnPremisesAccounts, where the workflow is
    the one meant to disable the AD account.

.PARAMETER Force
    Skip the leaver confirmation prompt and the scope / HR-state guards above.

.PARAMETER IncludeMover
    Staging switch (default off): also create the mover workflow (see Mover
    above). Off = the script does exactly what it did before.

.PARAMETER MoverWorkflowName
    Default "Contoso - Mover (department change)".

.PARAMETER MoverToDepartment
    Department the mover workflow is scoped to (the move's destination).
    Default ICU.

.PARAMETER MoverToPackage / MoverFromPackage
    Package requested for the new role / removed from the old one. Defaults
    "ICU - Critical Care Apps" / "Nurse - Clinical Apps" (03-Mover.ps1's swap).

.PARAMETER IncludeScheduledLeaver
    Also create the scheduled leaver (group membership change: removed from
    -LeaverTriggerGroupMailNickname). Off by default. Needs the All-Workforce
    group (envs/dev enable_lcw_leaver_trigger = true) and Group.Read.All.

.PARAMETER ScheduledLeaverWorkflowName
    Display name of the scheduled leaver. Default "Contoso - Leaver (HR disabled, scheduled)".

.PARAMETER LeaverTriggerGroupMailNickname
    mailNickname of the dynamic trigger group. Default all-workforce. The
    script refuses a group that is not dynamic, whose processing is not On,
    whose rule does not require accountEnabled true, or whose rule has any
    clause other than the All-Workforce ones (dirSyncEnabled true, userType
    Member, accountEnabled true, joined by -and). A department clause would
    let a job move start the leaver.

.PARAMETER OfflinePreview
    Build and print both workflow bodies with placeholder ids. No Graph
    connection, nothing sent. Use it with no tenant to review the JSON.

.PARAMETER WhatIf
    Standard. Connects and READS (task definitions, package, existing
    workflows), prints the exact bodies, writes nothing.

.EXAMPLE
    # No tenant yet: review the JSON the script would send.
    ./New-LifecycleWorkflows.ps1 -OfflinePreview

.EXAMPLE
    Connect-MgGraph -Scopes 'LifecycleWorkflows.ReadWrite.All','EntitlementManagement.Read.All','User.Read.All'
    ./New-LifecycleWorkflows.ps1 -WhatIf
    ./New-LifecycleWorkflows.ps1
    # Recording: run the joiner for Dana now instead of waiting for her hire date.
    ./New-LifecycleWorkflows.ps1 -RunJoinerFor 'dana.okafor@<your-domain>'

.EXAMPLE
    # Leaver, after hr_feed.csv says status=leaver and the disable has synced:
    ./New-LifecycleWorkflows.ps1 -RunLeaverFor 'dana.okafor@<your-domain>'

.OUTPUTS
    [pscustomobject] rows: Workflow, Id, Action, Detail.

.WHAT IT DEMONSTRATES
    Governance automation as reviewable code: HR-attribute-scoped joiner tasks,
    a real-time leaver, run-time resolution instead of magic GUIDs, and a
    deliberate single-owner design for hybrid account state.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$JoinerWorkflowName = 'Contoso - Joiner (Nursing, day 1)',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$LeaverWorkflowName = 'Contoso - Leaver (real-time termination)',

    [Parameter()]
    # Restrictive on purpose: the value is embedded in an OData-style rule.
    [ValidatePattern('^[A-Za-z0-9 &.-]{1,64}$', ErrorMessage = 'Department may contain letters, digits, space, & . - only.')]
    [string]$JoinerDepartment = 'Nursing',

    [Parameter()]
    [ValidateRange(-180, 180)] # documented range of timeBasedAttributeTrigger.offsetInDays (Graph v1.0)
    [int]$HireDateOffsetDays = 0,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AccessPackageName = 'Nurse - Clinical Apps',

    [Parameter()]
    [string]$AssignmentPolicyName = '',

    [Parameter()]
    [string[]]$JoinerGroupMailNicknames = @(),

    [Parameter()]
    [ValidateRange(10, 43200)]
    [int]$TapLifetimeMinutes = 480,

    [Parameter()]
    [bool]$TapIsUsableOnce = $true,

    [Parameter()]
    [switch]$ManageOnPremisesAccounts,

    [Parameter()]
    [switch]$EnableJoinerSchedule,

    [Parameter()]
    [switch]$UpdateExisting,

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN.')]
    [string[]]$RunJoinerFor = @(),

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN.')]
    [string[]]$RunLeaverFor = @(),

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$IncludeMover,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MoverWorkflowName = 'Contoso - Mover (department change)',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9 &.-]{1,64}$', ErrorMessage = 'Department may contain letters, digits, space, & . - only.')]
    [string]$MoverToDepartment = 'ICU',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MoverToPackage = 'ICU - Critical Care Apps',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$MoverFromPackage = 'Nurse - Clinical Apps',

    [Parameter()]
    [switch]$IncludeScheduledLeaver,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ScheduledLeaverWorkflowName = 'Contoso - Leaver (HR disabled, scheduled)',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$', ErrorMessage = 'A mailNickname: letters, digits, . _ - only.')]
    [string]$LeaverTriggerGroupMailNickname = 'all-workforce',

    [Parameter()]
    [switch]$OfflinePreview
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

$graph = 'https://graph.microsoft.com/v1.0'
$lcw = "$graph/identityGovernance/lifecycleWorkflows"
$em = "$graph/identityGovernance/entitlementManagement"

$results = [System.Collections.Generic.List[object]]::new()
$failures = 0
function Add-Result {
    param([string]$Workflow, [string]$Id, [string]$Action, [string]$Detail = '')
    $results.Add([pscustomobject]@{ Workflow = $Workflow; Id = $Id; Action = $Action; Detail = $Detail })
}

if ($OfflinePreview -and ($RunJoinerFor -or $RunLeaverFor)) {
    throw '-OfflinePreview cannot run workflows on demand (no tenant). Drop -RunJoinerFor / -RunLeaverFor.'
}
if ($ManageOnPremisesAccounts) {
    Write-Warning ('-ManageOnPremisesAccounts: the enable/disable tasks will WRITE accountDisabled in on-premises AD. ' +
        'HR inbound provisioning maps the same attribute, so the next HR push can undo it. Use only for workers HR does not manage.')
}

# =============================================================================
# Graph helpers (hashtable output: missing keys read as $null under StrictMode)
# =============================================================================
function Invoke-Graph {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body
    )
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $params.Body = ($Body | ConvertTo-Json -Depth 12)
        $params.ContentType = 'application/json'
    }
    return Invoke-MgGraphRequest @params
}

function Get-GraphCollection {
    # Follows @odata.nextLink so a tenant with many workflows / definitions is
    # read completely (a missed page would make get-then-create create twice).
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-Graph -Method GET -Uri $next
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    # Items are emitted one by one; callers wrap the call in @() for array semantics.
    return $items.ToArray()
}

function ConvertTo-ODataLiteral {
    param([string]$Value)
    return $Value.Replace("'", "''")
}

# =============================================================================
# 1. CONNECT (skipped for -OfflinePreview)
# =============================================================================
$requiredScopes = @('LifecycleWorkflows.ReadWrite.All', 'EntitlementManagement.Read.All')
if ($JoinerGroupMailNicknames -or $IncludeScheduledLeaver) { $requiredScopes += 'Group.Read.All' }
if ($RunJoinerFor -or $RunLeaverFor) { $requiredScopes += 'User.Read.All' }

if (-not $OfflinePreview) {
    $ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
    if (-not $ctx) {
        Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        $ctx = Get-MgContext
    }
    # Soft check: app-only tokens list roles, not scopes, so warn - do not fail.
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }
}
else {
    Write-Console 'OFFLINE PREVIEW - no Graph connection; ids below are placeholders resolved at runtime on a real run.' -ForegroundColor DarkYellow
}

# =============================================================================
# 2. RESOLVE TASK DEFINITIONS BY NAME (runtime, not hardcoded GUIDs)
# =============================================================================
# Microsoft's own pages spell these names differently (e.g. "Generate TAP and
# send email" in the API vs "Generate Temporary Access Pass and send via email
# to user's manager" in the docs; "Remove user from all groups" vs "Remove
# users from all groups"), so matching is case/punctuation-insensitive over a
# small alias list. The documented ids are in Microsoft Learn
# (lifecycle-workflow-tasks) for cross-checking; this script never uses them.
$taskCatalog = [ordered]@{
    EnableAccount     = @{ Names = @('Enable user account'); Params = @('enableOnPremisesAccount') }
    Tap               = @{ Names = @('Generate TAP and send email', "Generate Temporary Access Pass and send via email to user's manager"); Params = @('tapLifetimeMinutes', 'tapIsUsableOnce') }
    RequestPackage    = @{ Names = @('Request user access package assignment'); Params = @('assignmentPolicyId', 'accessPackageId') }
    AddGroups         = @{ Names = @('Add user to groups'); Params = @('groupID') }
    DisableAccount    = @{ Names = @('Disable user account'); Params = @('disableOnPremisesAccount') }
    RevokeTokens      = @{ Names = @('Revoke all refresh tokens for user'); Params = @() }
    CancelRequests    = @{ Names = @('Cancel pending access package assignment requests for user', 'Cancel all pending access package assignment requests for user'); Params = @() }
    RemoveAllPackages = @{ Names = @('Remove all access package assignments for user'); Params = @() }
    RemoveAllGroups   = @{ Names = @('Remove user from all groups', 'Remove users from all groups'); Params = @() }
    RemoveAllLicenses = @{ Names = @('Remove all licenses for user', 'Remove all license assignments from user'); Params = @() }
    # Mover (-IncludeMover only). verify: display names in the tenant.
    RemovePackage     = @{ Names = @('Remove access package assignment for user'); Params = @('accessPackageId') }
    MoverNotify       = @{ Names = @('Send email to notify manager of user move', "Send email to manager about user's job change"); Params = @() }
}

function Get-NormalizedName { param([string]$Name) return ($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant() }

$definitions = @()
if ($OfflinePreview) {
    # Synthetic stand-ins so the body can be printed without a tenant. The
    # parameter names are the ones Microsoft documents; a real run reads them
    # from the service instead.
    $definitions = @(foreach ($key in $taskCatalog.Keys) {
            @{
                id          = "<taskDefinitionId: $($taskCatalog[$key].Names[0])>"
                displayName = $taskCatalog[$key].Names[0]
                parameters  = @(foreach ($p in $taskCatalog[$key].Params) { @{ name = $p } })
            }
        })
}
else {
    $definitions = @(Get-GraphCollection -Uri "$lcw/taskDefinitions")
    Write-Console "Read $($definitions.Count) built-in task definition(s) from the tenant." -ForegroundColor DarkGray
}

function Resolve-TaskDefinition {
    param([Parameter(Mandatory)][string]$Key)
    $names = $taskCatalog[$Key].Names
    $wanted = @($names | ForEach-Object { Get-NormalizedName $_ })
    $hits = @($definitions | Where-Object { (Get-NormalizedName ([string]$_['displayName'])) -in $wanted })
    if ($hits.Count -eq 1) { return $hits[0] }
    $available = (@($definitions | ForEach-Object { "    - $($_['displayName'])" }) | Sort-Object) -join [Environment]::NewLine
    if ($hits.Count -eq 0) {
        throw "Lifecycle Workflows task definition for '$Key' not found. Looked for: $($names -join ' | '). Task definitions available in this tenant:$([Environment]::NewLine)$available"
    }
    throw "Ambiguous task definition for '$Key': $($hits.Count) matches ($(@($hits | ForEach-Object { $_['displayName'] }) -join ', ')). Available:$([Environment]::NewLine)$available"
}

# Name of a definition parameter, matched by regex. Optional parameters that
# the tenant's definition does not expose return $null and are omitted.
function Get-DefinitionParameterName {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Definition, [Parameter(Mandatory)][string]$Pattern, [string]$DocumentedName)
    $names = @(@($Definition['parameters']) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_['name'] })
    $hit = @($names | Where-Object { $_ -match $Pattern }) | Select-Object -First 1
    if ($hit) { return $hit }
    if ($DocumentedName) {
        Write-Verbose "Definition '$($Definition['displayName'])' lists no parameter matching '$Pattern'; using documented name '$DocumentedName'."
        return $DocumentedName
    }
    return $null
}

$def = @{}
foreach ($key in $taskCatalog.Keys) {
    if ($key -eq 'AddGroups' -and -not $JoinerGroupMailNicknames) { continue }
    if ($key -in 'RemovePackage', 'MoverNotify' -and -not $IncludeMover) { continue }
    $def[$key] = Resolve-TaskDefinition -Key $key
    Write-Verbose "Resolved $key -> $($def[$key]['displayName']) ($($def[$key]['id']))"
}

# =============================================================================
# 3. RESOLVE THE ACCESS PACKAGE + POLICY (and optional groups) BY NAME
# =============================================================================
$packageId = '<accessPackageId: ' + $AccessPackageName + '>'
$policyId = '<assignmentPolicyId: ' + $AccessPackageName + '>'
if (-not $OfflinePreview) {
    $filter = [uri]::EscapeDataString("displayName eq '$(ConvertTo-ODataLiteral $AccessPackageName)'")
    $packages = @(Get-GraphCollection -Uri "$em/accessPackages?`$filter=$filter")
    if ($packages.Count -ne 1) {
        throw "Expected exactly one access package named '$AccessPackageName', found $($packages.Count). Apply Terraform envs/dev with enable_governance = true (modules/entitlement)."
    }
    $packageId = [string]$packages[0]['id']
    $pkg = Invoke-Graph -Method GET -Uri "$em/accessPackages/$packageId`?`$expand=assignmentPolicies"
    $policies = @(@($pkg['assignmentPolicies']) | Where-Object { $null -ne $_ })
    if ($AssignmentPolicyName) { $policies = @($policies | Where-Object { $_['displayName'] -eq $AssignmentPolicyName }) }
    if ($policies.Count -ne 1) {
        $names = @(@($pkg['assignmentPolicies']) | Where-Object { $null -ne $_ } | ForEach-Object { "'$($_['displayName'])'" }) -join ', '
        throw "Cannot pick one assignment policy on '$AccessPackageName' (found $($policies.Count); policies: $names). Pass -AssignmentPolicyName."
    }
    $policyId = [string]$policies[0]['id']
    Write-Console "Access package '$AccessPackageName' ($packageId), policy '$($policies[0]['displayName'])' ($policyId)." -ForegroundColor DarkGray
}

$groupIds = [ordered]@{}
foreach ($nick in $JoinerGroupMailNicknames) {
    if ($OfflinePreview) { $groupIds[$nick] = "<groupId: $nick>"; continue }
    $f = [uri]::EscapeDataString("mailNickname eq '$(ConvertTo-ODataLiteral $nick)'")
    $g = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id,displayName,groupTypes,isAssignableToRole,mailEnabled,securityEnabled,onPremisesSyncEnabled")
    if ($g.Count -ne 1) { throw "Group with mailNickname '$nick' not found (or not unique)." }
    $grp = $g[0]
    # The task supports Microsoft 365 and cloud-only security groups only.
    $problems = @()
    if (@($grp['groupTypes']) -contains 'DynamicMembership') { $problems += 'dynamic' }
    if ($grp['isAssignableToRole'] -eq $true) { $problems += 'role-assignable' }
    if ($grp['onPremisesSyncEnabled'] -eq $true) { $problems += 'synced from AD' }
    if ($grp['mailEnabled'] -eq $true -and -not (@($grp['groupTypes']) -contains 'Unified')) { $problems += 'mail-enabled security/distribution' }
    if ($problems) { throw "Group '$($grp['displayName'])' cannot be used by the 'Add user to groups' task: $($problems -join ', ')." }
    $groupIds[$nick] = [string]$grp['id']
}

# Returns $null when a dynamic rule is only AND-ed clauses from the
# All-Workforce set (modules/groups/main.tf all_workforce rule), otherwise a
# short reason. Comparison ignores case, spaces and parentheses.
function Get-LeaverTriggerRuleProblem {
    param([string]$Rule)
    $allowed = @('user.dirsyncenabled-eqtrue', 'user.usertype-eq"member"', 'user.accountenabled-eqtrue')
    $flat = ($Rule -replace '[()\s]', '').ToLowerInvariant()
    if (-not $flat) { return 'is empty' }
    if ($flat -match '-or|-not') { return 'uses -or or -not' }
    $extra = @($flat -split '-and' | Where-Object { $_ -notin $allowed })
    if ($extra) { return "has clauses a job move can change ($($extra -join ', '))" }
    return $null
}

# The scheduled leaver's trigger group (-IncludeScheduledLeaver). Fail closed:
# it must be exactly one DYNAMIC group whose rule requires accountEnabled true
# and has no clause a job move can change, otherwise "removed from group" would
# not mean "HR disabled the account".
$leaverTriggerGroupId = $null
if ($IncludeScheduledLeaver) {
    if ($OfflinePreview) { $leaverTriggerGroupId = "<groupId: $LeaverTriggerGroupMailNickname>" }
    else {
        $f = [uri]::EscapeDataString("mailNickname eq '$(ConvertTo-ODataLiteral $LeaverTriggerGroupMailNickname)'")
        $g = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id,displayName,groupTypes,membershipRule,membershipRuleProcessingState")
        if ($g.Count -ne 1) { throw "Scheduled leaver: expected exactly one group with mailNickname '$LeaverTriggerGroupMailNickname', found $($g.Count). Apply envs/dev with enable_lcw_leaver_trigger = true (modules/groups All-Workforce)." }
        $tg = $g[0]
        if (-not (@($tg['groupTypes']) -contains 'DynamicMembership')) { throw "Scheduled leaver: '$($tg['displayName'])' is not a dynamic group." }
        if ([string]$tg['membershipRule'] -notmatch 'user\.accountEnabled\s+-eq\s+true') { throw "Scheduled leaver: the rule of '$($tg['displayName'])' does not require accountEnabled true, so leaving it does not mean HR disabled the account: $($tg['membershipRule'])" }
        # WHY an allow-list of clauses: "requires accountEnabled true" is not
        # enough. A rule like (accountEnabled true) -and (department Nursing)
        # also drops a person who moves to ICU, and the leaver workflow would
        # then strip packages, groups and licenses from an active employee.
        # Accept only AND-ed clauses that a job move never changes (the
        # modules/groups All-Workforce rule); refuse -or, -not and any other
        # attribute.
        $ruleProblem = Get-LeaverTriggerRuleProblem -Rule ([string]$tg['membershipRule'])
        if ($ruleProblem) { throw "Scheduled leaver: the rule of '$($tg['displayName'])' $ruleProblem, so leaving the group can mean a job move, not an HR disable: $($tg['membershipRule'])" }
        if ([string]$tg['membershipRuleProcessingState'] -ne 'On') { throw "Scheduled leaver: dynamic processing of '$($tg['displayName'])' is '$($tg['membershipRuleProcessingState'])', not On." }
        $leaverTriggerGroupId = [string]$tg['id']
        Write-Console "Scheduled leaver trigger group '$($tg['displayName'])' ($leaverTriggerGroupId)." -ForegroundColor DarkGray
    }
}

# =============================================================================
# 4. BUILD THE DESIRED WORKFLOW BODIES
# =============================================================================
function ConvertTo-LcwTask {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Definition,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Description,
        [bool]$ContinueOnError = $false,
        [System.Collections.Specialized.OrderedDictionary]$Arguments = ([ordered]@{})
    )
    $argList = @(foreach ($k in $Arguments.Keys) { [ordered]@{ name = [string]$k; value = [string]$Arguments[$k] } })
    return [ordered]@{
        continueOnError  = $ContinueOnError
        description      = $Description
        displayName      = $DisplayName
        isEnabled        = $true
        taskDefinitionId = [string]$Definition['id']
        arguments        = $argList
    }
}

$onPremValue = if ($ManageOnPremisesAccounts) { 'true' } else { 'false' }

# ---- Joiner -----------------------------------------------------------------
$enableArgs = [ordered]@{}
$enableParam = Get-DefinitionParameterName -Definition $def.EnableAccount -Pattern '^enableOnPremisesAccount$'
if ($enableParam) { $enableArgs[$enableParam] = $onPremValue }

# Docs disagree on the lifetime argument name (tapLifetimeInMinutes in the
# task table, tapLifetimeMinutes in the API) - take whatever the tenant's
# definition declares.
$tapArgs = [ordered]@{}
$tapArgs[(Get-DefinitionParameterName -Definition $def.Tap -Pattern '^tapLifetime' -DocumentedName 'tapLifetimeMinutes')] = "$TapLifetimeMinutes"
$tapArgs[(Get-DefinitionParameterName -Definition $def.Tap -Pattern '^tapIsUsableOnce$' -DocumentedName 'tapIsUsableOnce')] = $TapIsUsableOnce.ToString().ToLowerInvariant()

$packageArgs = [ordered]@{}
$packageArgs[(Get-DefinitionParameterName -Definition $def.RequestPackage -Pattern '^assignmentPolicyId$' -DocumentedName 'assignmentPolicyId')] = $policyId
$packageArgs[(Get-DefinitionParameterName -Definition $def.RequestPackage -Pattern '^accessPackageId$' -DocumentedName 'accessPackageId')] = $packageId

$joinerTasks = [System.Collections.Generic.List[object]]::new()
$joinerTasks.Add((ConvertTo-LcwTask -Definition $def.EnableAccount -DisplayName 'Enable user account' -ContinueOnError $true `
            -Description "Cloud-only users: enable in Entra. Synced users: enableOnPremisesAccount=$onPremValue - HR -> AD owns accountEnabled." -Arguments $enableArgs))
$joinerTasks.Add((ConvertTo-LcwTask -Definition $def.Tap -DisplayName "Generate TAP and send email to manager" -ContinueOnError $true `
            -Description "Day-1 passwordless bootstrap: ${TapLifetimeMinutes}-minute TAP mailed to the HR-feed manager." -Arguments $tapArgs))
$joinerTasks.Add((ConvertTo-LcwTask -Definition $def.RequestPackage -DisplayName "Request access package: $AccessPackageName" -ContinueOnError $false `
            -Description "Day-1 role bundle with the policy's 180-day expiry and the Nurse/Pharmacy SoD rule." -Arguments $packageArgs))
foreach ($nick in $groupIds.Keys) {
    $gArgs = [ordered]@{}
    $gArgs[(Get-DefinitionParameterName -Definition $def.AddGroups -Pattern '^groupID$' -DocumentedName 'groupID')] = $groupIds[$nick]
    $joinerTasks.Add((ConvertTo-LcwTask -Definition $def.AddGroups -DisplayName "Add user to group $nick" -ContinueOnError $true `
                -Description "Birthright cloud group $nick (not package-delivered)." -Arguments $gArgs))
}

$joinerBody = [ordered]@{
    category            = 'joiner'
    displayName         = $JoinerWorkflowName
    description         = "Day-1 onboarding for $JoinerDepartment hires (HR -> AD -> Cloud Sync). Managed by lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1."
    isEnabled           = $true
    isSchedulingEnabled = [bool]$EnableJoinerSchedule
    executionConditions = [ordered]@{
        '@odata.type' = '#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions'
        scope         = [ordered]@{
            '@odata.type' = '#microsoft.graph.identityGovernance.ruleBasedSubjectSet'
            rule          = "(department eq '$(ConvertTo-ODataLiteral $JoinerDepartment)')"
        }
        trigger       = [ordered]@{
            '@odata.type'      = '#microsoft.graph.identityGovernance.timeBasedAttributeTrigger'
            timeBasedAttribute = 'employeeHireDate'
            offsetInDays       = $HireDateOffsetDays
        }
    }
    tasks               = $joinerTasks.ToArray()
}

# ---- Leaver -----------------------------------------------------------------
$disableArgs = [ordered]@{}
$disableParam = Get-DefinitionParameterName -Definition $def.DisableAccount -Pattern '^disableOnPremisesAccount$'
if ($disableParam) { $disableArgs[$disableParam] = $onPremValue }

# "Remove all access package assignments" - one Learn page calls a
# daysUntilExpiration argument required (and says setting it SCHEDULES the
# removal instead of doing it now); the v1.0 API reference lists no
# parameters. A real-time leaver wants immediate removal, so the argument is
# deliberately not sent.  # verify: the service accepts the task with no
# arguments; if it rejects it, the create fails loudly with Graph's message.
$leaverTasks = @(
    (ConvertTo-LcwTask -Definition $def.DisableAccount -DisplayName 'Disable user account' -ContinueOnError $true `
        -Description "Cloud-only users: disable in Entra. Synced users: disableOnPremisesAccount=$onPremValue - HR status=leaver -> AD owns it." -Arguments $disableArgs)
    (ConvertTo-LcwTask -Definition $def.RevokeTokens -DisplayName 'Revoke all refresh tokens for user' -ContinueOnError $true `
            -Description 'Kill existing refresh tokens and browser sessions (contain first).')
    (ConvertTo-LcwTask -Definition $def.CancelRequests -DisplayName 'Cancel pending access package requests' -ContinueOnError $true `
            -Description 'Nothing requested before termination can be delivered after it.')
    (ConvertTo-LcwTask -Definition $def.RemoveAllPackages -DisplayName 'Remove all access package assignments' -ContinueOnError $true `
            -Description 'Governed revocation of every package (and the app groups they delivered).')
    (ConvertTo-LcwTask -Definition $def.RemoveAllGroups -DisplayName 'Remove user from all groups' -ContinueOnError $true `
            -Description 'Remaining cloud security / Microsoft 365 groups. Dynamic and AD-synced groups are not touched (rule / AD own them).')
    # verify: that the task removes only DIRECT assignments (Graph cannot
    # remove an inherited license from a user). Group-based licenses go when
    # the user leaves the licensing group: task 5 for cloud assigned groups,
    # the rule or AD for dynamic / synced ones.
    (ConvertTo-LcwTask -Definition $def.RemoveAllLicenses -DisplayName 'Remove all licenses for user' -ContinueOnError $true `
            -Description 'Direct license assignments. Group-based licenses follow group membership.')
)

$leaverBody = [ordered]@{
    category            = 'leaver'
    displayName         = $LeaverWorkflowName
    description         = 'Real-time termination, run on demand after HR marks the worker leaver. Managed by lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1.'
    isEnabled           = $true
    isSchedulingEnabled = $false   # on-demand-only workflows are never scheduled
    executionConditions = [ordered]@{ '@odata.type' = '#microsoft.graph.identityGovernance.onDemandExecutionOnly' }
    tasks               = $leaverTasks
}

# ---- Scheduled leaver (-IncludeScheduledLeaver only) --------------------------
$scheduledLeaverBody = $null
if ($IncludeScheduledLeaver) {
    $scheduledLeaverBody = [ordered]@{
        category            = 'leaver'
        displayName         = $ScheduledLeaverWorkflowName
        description         = "Runs by itself when HR's leaver disables the account (removed from $LeaverTriggerGroupMailNickname). Managed by lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1."
        isEnabled           = $true
        isSchedulingEnabled = $true
        executionConditions = [ordered]@{
            '@odata.type' = '#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions'
            scope         = [ordered]@{
                '@odata.type' = '#microsoft.graph.identityGovernance.groupBasedSubjectSet'
                groups        = @([ordered]@{ id = $leaverTriggerGroupId })
            }
            trigger       = [ordered]@{
                '@odata.type' = '#microsoft.graph.identityGovernance.membershipChangeTrigger'
                changeType    = 'remove'
            }
        }
        tasks               = $leaverTasks
    }
}

# ---- Mover (-IncludeMover only) -----------------------------------------------
$moverBody = $null
if ($IncludeMover) {
    # Both packages resolved by name, like the joiner's (placeholders offline).
    function Resolve-PackageAndPolicy([string]$Name) {
        if ($OfflinePreview) { return @{ Package = "<accessPackageId: $Name>"; Policy = "<assignmentPolicyId: $Name>" } }
        $f = [uri]::EscapeDataString("displayName eq '$(ConvertTo-ODataLiteral $Name)'")
        $pk = @(Get-GraphCollection -Uri "$em/accessPackages?`$filter=$f")
        if ($pk.Count -ne 1) { throw "Expected exactly one access package named '$Name', found $($pk.Count) (enable_governance)." }
        $full = Invoke-Graph -Method GET -Uri "$em/accessPackages/$($pk[0]['id'])`?`$expand=assignmentPolicies"
        $pols = @(@($full['assignmentPolicies']) | Where-Object { $null -ne $_ })
        if ($pols.Count -lt 1) { throw "Access package '$Name' has no assignment policy." }
        return @{ Package = [string]$pk[0]['id']; Policy = [string]$pols[0]['id'] }
    }
    $to = Resolve-PackageAndPolicy $MoverToPackage
    $from = Resolve-PackageAndPolicy $MoverFromPackage
    $reqArgs = [ordered]@{}
    $reqArgs[(Get-DefinitionParameterName -Definition $def.RequestPackage -Pattern '^assignmentPolicyId$' -DocumentedName 'assignmentPolicyId')] = $to.Policy
    $reqArgs[(Get-DefinitionParameterName -Definition $def.RequestPackage -Pattern '^accessPackageId$' -DocumentedName 'accessPackageId')] = $to.Package
    $remArgs = [ordered]@{}
    $remArgs[(Get-DefinitionParameterName -Definition $def.RemovePackage -Pattern '^accessPackageId$' -DocumentedName 'accessPackageId')] = $from.Package
    $moverTasks = @(
        (ConvertTo-LcwTask -Definition $def.RequestPackage -DisplayName "Request access package: $MoverToPackage" -ContinueOnError $true `
            -Description "New role's bundle (ADR 0012: where the package is attribute-driven, the automatic policy already did it)." -Arguments $reqArgs)
        (ConvertTo-LcwTask -Definition $def.RemovePackage -DisplayName "Remove access package: $MoverFromPackage" -ContinueOnError $true `
            -Description 'Old role bundle removed: no accumulation of access across moves (SoD Nurse/Pharmacy stays clean).' -Arguments $remArgs)
        (ConvertTo-LcwTask -Definition $def.MoverNotify -DisplayName 'Email the manager about the move' -ContinueOnError $true `
            -Description 'The manager confirms the move; their answer is the human check on an HR attribute change.')
    )
    $moverBody = [ordered]@{
        category            = 'mover'
        displayName         = $MoverWorkflowName
        description         = "Department change to $MoverToDepartment (HR -> AD -> Cloud Sync): package swap $MoverFromPackage -> $MoverToPackage. Managed by lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1."
        isEnabled           = $true
        isSchedulingEnabled = $false   # on first use, run on demand; turn scheduling on once HR changes flow
        executionConditions = [ordered]@{
            '@odata.type' = '#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions'
            scope         = [ordered]@{
                '@odata.type' = '#microsoft.graph.identityGovernance.ruleBasedSubjectSet'
                rule          = "(department eq '$(ConvertTo-ODataLiteral $MoverToDepartment)')"
            }
            trigger       = [ordered]@{
                '@odata.type'     = '#microsoft.graph.identityGovernance.attributeChangeTrigger'
                triggerAttributes = @([ordered]@{ name = 'department' }, [ordered]@{ name = 'jobTitle' })
            }
        }
        tasks               = $moverTasks
    }
}

# =============================================================================
# 5. CREATE OR RECONCILE (get-then-create by display name)
# =============================================================================
# Functional fingerprint: trigger/scope + ordered tasks (definition, enabled,
# continueOnError, arguments). Task display names/descriptions are cosmetic
# and ignored so a portal rename does not force a new version.
# verify: that GET returns task arguments exactly as sent. If the service
# echoes extra default arguments (e.g. the TAP task's email parameters), a
# freshly created workflow reports drift on the next run; then compare only
# the argument names this script sends.
function Get-WorkflowFingerprint {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Workflow)
    $ec = $Workflow['executionConditions']
    $parts = @([string]$Workflow['category'], [string]$ec['@odata.type'])
    if ($ec.Contains('scope') -and $ec['scope']) {
        $parts += [string]$ec['scope']['rule']
        if ($ec['scope'].Contains('groups')) { $parts += 'groups:' + ((@(@($ec['scope']['groups']) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_['id'] }) | Sort-Object) -join ',') }
    }
    if ($ec.Contains('trigger') -and $ec['trigger']) {
        $tr = $ec['trigger']
        if ($tr.Contains('triggerAttributes')) { $parts += 'change:' + ((@(@($tr['triggerAttributes']) | ForEach-Object { [string]$_['name'] }) | Sort-Object) -join ',') }
        elseif ($tr.Contains('changeType')) { $parts += "membership:$($tr['changeType'])" }
        else { $parts += "$($tr['timeBasedAttribute'])@$($tr['offsetInDays'])" }
    }
    $tasks = @($Workflow['tasks'])
    if ($tasks.Count -gt 0 -and $tasks[0] -is [System.Collections.IDictionary] -and $tasks[0].Contains('executionSequence')) {
        $tasks = @($tasks | Sort-Object { [int]$_['executionSequence'] })
    }
    foreach ($t in $tasks) {
        $argText = (@(@($t['arguments']) | Where-Object { $null -ne $_ } | ForEach-Object { "$($_['name'])=$($_['value'])" }) | Sort-Object) -join ';'
        $parts += ('{0}|en={1}|coe={2}|{3}' -f ([string]$t['taskDefinitionId']).ToLowerInvariant(), $t['isEnabled'], $t['continueOnError'], $argText)
    }
    return $parts
}

$existing = @()
if (-not $OfflinePreview) { $existing = @(Get-GraphCollection -Uri "$lcw/workflows") }

$workflowIds = @{}
foreach ($desired in @($joinerBody, $leaverBody, $scheduledLeaverBody, $moverBody | Where-Object { $null -ne $_ })) {
    $name = $desired.displayName
    Write-Console "`n=== $name ===" -ForegroundColor Cyan
    $json = $desired | ConvertTo-Json -Depth 12

    if ($OfflinePreview) {
        Write-Console "POST $lcw/workflows" -ForegroundColor DarkYellow
        Write-Console $json
        Add-Result $name '' 'offline-preview'
        continue
    }

    $match = @($existing | Where-Object { [string]$_['displayName'] -eq $name })
    if ($match.Count -gt 1) {
        Write-Warning "  $($match.Count) workflows are named '$name' - rename or delete the extras; not touching any."
        Add-Result $name '' 'FAILED' 'duplicate display name'
        $failures++
        continue
    }

    if ($match.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($name, 'create Lifecycle Workflow')) {
            try {
                $created = Invoke-Graph -Method POST -Uri "$lcw/workflows" -Body $desired
                $workflowIds[$name] = [string]$created['id']
                Write-Console "  [+] Created (id $($created['id']), version $($created['version']))." -ForegroundColor Green
                Add-Result $name ([string]$created['id']) 'created'
            }
            catch {
                Write-Warning "  Create failed: $($_.Exception.Message)"
                Add-Result $name '' 'FAILED' $_.Exception.Message
                $failures++
            }
        }
        else {
            Write-Console "  [whatif] Would POST $lcw/workflows with:" -ForegroundColor DarkYellow
            Write-Console $json
            Add-Result $name '' 'whatif-create'
        }
        continue
    }

    # Exists: compare. GET by id expands tasks by default.
    $id = [string]$match[0]['id']
    $current = Invoke-Graph -Method GET -Uri "$lcw/workflows/$id"
    if ([string]$current['category'] -ne $desired.category) {
        # Not recorded in $workflowIds: an on-demand run must never hit a
        # same-named workflow of the wrong kind.
        Write-Warning "  Existing workflow is category '$($current['category'])', expected '$($desired.category)'. Category cannot be versioned - rename or delete it in the portal."
        Add-Result $name $id 'FAILED' 'category mismatch'
        $failures++
        continue
    }
    $workflowIds[$name] = $id

    $want = @(Get-WorkflowFingerprint -Workflow $desired)
    $have = @(Get-WorkflowFingerprint -Workflow $current)
    $structDrift = @(Compare-Object -ReferenceObject $have -DifferenceObject $want -SyncWindow 0)
    $settingDrift = @(foreach ($p in 'description', 'isEnabled', 'isSchedulingEnabled') {
            if ([string]$current[$p] -ne [string]$desired[$p]) { "$p '$($current[$p])' -> '$($desired[$p])'" }
        })

    if (-not $structDrift -and -not $settingDrift) {
        Write-Console "  [=] Up to date (id $id, version $($current['version']))." -ForegroundColor DarkGray
        Add-Result $name $id 'up-to-date'
        continue
    }

    foreach ($d in $structDrift) { Write-Console ("  drift {0} {1}" -f $(if ($d.SideIndicator -eq '=>') { 'want' } else { 'have' }), $d.InputObject) -ForegroundColor Yellow }
    foreach ($d in $settingDrift) { Write-Console "  drift setting $d" -ForegroundColor Yellow }

    if (-not $UpdateExisting) {
        Write-Warning "  '$name' differs from the desired state. Re-run with -UpdateExisting to apply."
        Add-Result $name $id 'drift-reported' "$($structDrift.Count) task/condition line(s), $($settingDrift.Count) setting(s)"
        continue
    }

    try {
        if ($structDrift) {
            if ($PSCmdlet.ShouldProcess($name, 'create new workflow version (tasks / execution conditions)')) {
                $v = Invoke-Graph -Method POST -Uri "$lcw/workflows/$id/createNewVersion" -Body @{ workflow = $desired }
                Write-Console "  [+] New version $($v['version']) created." -ForegroundColor Green
                Add-Result $name $id 'new-version' "version $($v['version'])"
            }
            else { Add-Result $name $id 'whatif-new-version' }
        }
        elseif ($PSCmdlet.ShouldProcess($name, "patch settings: $($settingDrift -join '; ')")) {
            Invoke-Graph -Method PATCH -Uri "$lcw/workflows/$id" -Body ([ordered]@{
                    description         = $desired.description
                    isEnabled           = $desired.isEnabled
                    isSchedulingEnabled = $desired.isSchedulingEnabled
                }) | Out-Null
            Write-Console '  [+] Settings patched.' -ForegroundColor Green
            Add-Result $name $id 'settings-patched' ($settingDrift -join '; ')
        }
        else { Add-Result $name $id 'whatif-patch' }
    }
    catch {
        Write-Warning "  Update failed: $($_.Exception.Message)"
        Add-Result $name $id 'FAILED' $_.Exception.Message
        $failures++
    }
}

# =============================================================================
# 6. OPTIONAL: RUN ON DEMAND (POST .../workflows/{id}/activate)
# =============================================================================
# On-demand runs ignore the workflow's scope and trigger (Microsoft Learn,
# workflow: activate), so the guards that the scope would normally provide are
# enforced here instead. The helper only READS; confirmation and the POST stay
# at script level so -WhatIf / -Confirm / -Force behave as for everything else.
function Get-OnDemandSubject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param(
        [string[]]$UserPrincipalNames,
        [ValidateSet('joiner', 'leaver')][string]$Kind,
        [bool]$SkipGuards
    )
    $subjects = [System.Collections.Generic.List[object]]::new()
    $rejected = 0
    foreach ($upn in $UserPrincipalNames) {
        try {
            $u = Invoke-Graph -Method GET -Uri "$graph/users/$([uri]::EscapeDataString($upn))?`$select=id,displayName,department,accountEnabled,onPremisesSyncEnabled"
        }
        catch {
            Write-Warning "  ${upn}: not found ($($_.Exception.Message))."
            $rejected++
            continue
        }
        if ($Kind -eq 'joiner') {
            # The TAP task mails the pass to the manager. A manager with no
            # mail attribute makes that task fail (E121: Grace Mwangi). Say so
            # before the run; it is a warning, the run still goes ahead
            # (the task is continueOnError and the package request still runs).
            $mgr = $null
            try { $mgr = Invoke-Graph -Method GET -Uri "$graph/users/$([uri]::EscapeDataString($upn))/manager?`$select=displayName,mail" }
            catch { Write-Warning "  ${upn}: could not read the manager ($($_.Exception.Message)). The TAP email task may fail." }
            if ($mgr -and [string]::IsNullOrWhiteSpace([string]$mgr['mail'])) {
                Write-Warning "  ${upn}: manager '$($mgr['displayName'])' has no mail attribute, so 'Generate TAP and send email' will FAIL. Fix: lab/scripts/dc/configure-sync.py hrapp --mail-domain (sets AD mail from the HR userName), then re-send that manager's HR row."
            }
        }
        if ($Kind -eq 'joiner' -and [string]$u['department'] -ne $JoinerDepartment -and -not $SkipGuards) {
            Write-Warning "  ${upn}: department '$($u['department'])' is outside the joiner scope ('$JoinerDepartment'). Skipped (use -Force to override)."
            $rejected++
            continue
        }
        # With -ManageOnPremisesAccounts the workflow itself is the designated
        # writer of AD accountDisabled, so a still-enabled synced user is the
        # expected input, not an HR process that was skipped.
        if ($Kind -eq 'leaver' -and $u['onPremisesSyncEnabled'] -eq $true -and $u['accountEnabled'] -eq $true -and -not $SkipGuards -and -not $ManageOnPremisesAccounts) {
            Write-Warning ("  ${upn}: synced and still ENABLED - HR has not terminated them. Set status=leaver in hr_feed.csv, run " +
                'Invoke-InboundProvisioning.ps1 -StatusFilter leaver, wait for Cloud Sync (or Provision on demand), then re-run. Skipped (use -Force to override).')
            $rejected++
            continue
        }
        $subjects.Add(@{ id = [string]$u['id'] })
        Write-Host "  subject: $($u['displayName']) <$upn> dept=$($u['department']) enabled=$($u['accountEnabled']) synced=$([bool]$u['onPremisesSyncEnabled'])" -ForegroundColor DarkGray
    }
    return [pscustomobject]@{ Subjects = $subjects.ToArray(); Rejected = $rejected }
}

foreach ($run in @(
        @{ Kind = 'joiner'; Name = $JoinerWorkflowName; Upns = $RunJoinerFor }
        @{ Kind = 'leaver'; Name = $LeaverWorkflowName; Upns = $RunLeaverFor }
    )) {
    if (-not $run.Upns) { continue }
    Write-Console "`n=== Run on demand: $($run.Kind) ===" -ForegroundColor Cyan
    $wfId = $workflowIds[$run.Name]
    if (-not $wfId) {
        Write-Warning "  '$($run.Name)' has no id (not created in this run - -WhatIf or a failure). Skipping on-demand run."
        Add-Result $run.Name '' 'run-skipped' 'workflow not available'
        continue
    }
    $picked = Get-OnDemandSubject -UserPrincipalNames $run.Upns -Kind $run.Kind -SkipGuards ([bool]$Force)
    $failures += $picked.Rejected
    if ($picked.Subjects.Count -eq 0) { continue }

    $confirmed = $PSCmdlet.ShouldProcess($run.Name, "run on demand for $($picked.Subjects.Count) user(s)")
    if ($confirmed -and $run.Kind -eq 'leaver' -and -not $Force) {
        # Second, explicit prompt for the destructive one (skipped with -Force).
        $confirmed = $PSCmdlet.ShouldContinue("This disables access, revokes tokens and removes packages, groups and licenses for $($picked.Subjects.Count) user(s).", 'Run leaver workflow?')
    }
    if (-not $confirmed) {
        Add-Result $run.Name $wfId 'whatif-run' ($run.Upns -join ', ')
        continue
    }
    try {
        Invoke-Graph -Method POST -Uri "$lcw/workflows/$wfId/activate" -Body @{ subjects = $picked.Subjects } | Out-Null
        Write-Console "  [+] On-demand run submitted (HTTP 204). Watch: Lifecycle workflows -> $($run.Name) -> Workflow history." -ForegroundColor Green
        Add-Result $run.Name $wfId 'run-submitted' ($run.Upns -join ', ')
    }
    catch {
        Write-Warning "  Activate failed: $($_.Exception.Message)"
        Add-Result $run.Name $wfId 'FAILED' "activate: $($_.Exception.Message)"
        $failures++
    }
}

# =============================================================================
# 7. HOW TO RUN ON DEMAND (printed, not executed)
# =============================================================================
$joinerIdText = if ($workflowIds[$JoinerWorkflowName]) { $workflowIds[$JoinerWorkflowName] } else { '<joiner workflow id>' }
$leaverIdText = if ($workflowIds[$LeaverWorkflowName]) { $workflowIds[$LeaverWorkflowName] } else { '<leaver workflow id>' }
Write-Console @"

HOW TO RUN ON DEMAND (on-demand runs ignore the trigger AND the scope rule)
  Portal : Entra admin center -> ID Governance -> Lifecycle workflows -> Workflows
           -> '$JoinerWorkflowName' -> Run on demand -> + Add users -> Dana Okafor -> Run workflow.
           Results: the same workflow -> Workflow history (per user, per task).
  Script : ./New-LifecycleWorkflows.ps1 -RunJoinerFor 'dana.okafor@<domain>'
           ./New-LifecycleWorkflows.ps1 -RunLeaverFor 'dana.okafor@<domain>'   (after HR marks her leaver)
  Graph  : POST $lcw/workflows/$joinerIdText/activate
           { "subjects": [ { "id": "<user object id>" } ] }       -> 204 No Content
           (Graph PowerShell SDK: Initialize-MgIdentityGovernanceLifecycleWorkflow -WorkflowId <id> -BodyParameter @{ subjects = @(@{ id = '<user id>' }) })
  Leaver : POST $lcw/workflows/$leaverIdText/activate - same body.

BEFORE THE JOINER TAKE
  * TAP task needs: TAP policy enabled; Dana's manager (Grace) has a mail attribute
    (configure-sync.py hrapp --mail-domain; E121 failed without it); Dana has
    no auth methods and has never signed in. On a re-take it fails (continueOnError -
    the package request still runs). For a clean TAP shot use a fresh joiner (Sofia Reyes).
  * Scheduled runs are $(if ($EnableJoinerSchedule) { 'ON' } else { 'OFF (until the tenant-time hireDate -> employeeHireDate mappings are confirmed)' }).
"@ -ForegroundColor Cyan

$results | Format-Table -AutoSize | Out-Host
if ($failures) {
    Write-Warning "$failures failure(s) - see the table above."
    exit 1
}
$results
