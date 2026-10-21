<#
.SYNOPSIS
    Day-1 access for a new hire (default: Dana Okafor). Ensures a license,
    verifies her department birthright group, and confirms her birthright
    access package ("Nurse - Clinical Apps") was DELIVERED by its automatic
    assignment policy. adminAdd is used only for a requestable (T2) package.

.DESCRIPTION
    Video segment 2, "Joiner". By the time this runs, inbound provisioning
    (../mock-hr) has created Dana in AD and Cloud Sync has brought her into
    Entra with department=Nursing. This script delivers her day-1
    entitlements declaratively:

      1. LICENSE  -- ensure she has a usage location + the product license her
         role needs. Idempotent: skipped if already licensed. (Licenses and
         usageLocation are cloud-side, so this works on synced users too.)
      2. BIRTHRIGHT -- All-Nurses is DYNAMIC on (department -eq "Nursing"), so
         she is added AUTOMATICALLY by Entra. This script only *verifies* it
         (you cannot, and must not, manually add to a dynamic group).
      3. APP GROUPS (fallback only) -- add her to App-ServiceNow-Users and
         App-AWS-IdentityCenter-Users directly when the access package is not
         available (the no-Governance path).
      4. ACCESS PACKAGE -- the governed path, by the package's assignment model
         in lab/iga/access-catalog.json (ADR 0012):
           automatic (T3 birthright, e.g. "Nurse - Clinical Apps")
             NOTHING is requested. post-apply/Set-AutoAssignmentPolicies.ps1
             put an automatic assignment policy on the package; entitlement
             management assigns it to everyone whose HR attributes match the
             rule (department + job title, enabled, Member, employeeHireDate
             <= now). This step WAITS (-WaitForAssignmentSeconds) for that
             assignment to reach Delivered and reports it; on timeout it says
             which attribute to check and exits 1. It never sends adminAdd -
             there is no request policy to send it through (verify: Graph
             rejects adminAdd against an automatic policy).
           request (T2, e.g. "ICU - Float Access")
             adminAdd through the package's REQUEST policy (expiry + SoD links),
             skipping any automatic policy.

    THE "RUNS WITHOUT GOVERNANCE" FALLBACK (see big comment block near the end):
    access packages AND Lifecycle Workflows both require **Entra ID Governance**.
    If you are rebuilding on P1/P2 only, the identical joiner logic runs as a
    **Logic App** calling Microsoft Graph (license + group add, no package).
    The full Logic App workflow definition JSON is embedded below as a comment.

.PREREQUISITES
    * Terraform envs/dev applied with enable_premium (+ enable_governance for
      the package path); 01-Verify-Baseline.ps1 passes.
    * Inbound provisioning + Cloud Sync have created the user with department set.
    * For the access-package path: **Entra ID Governance** licensing; the
      package exists (Terraform enable_governance) and, for a birthright
      package, post-apply/Set-AutoAssignmentPolicies.ps1 has run. The user's
      employeeHireDate must have flowed from HR (startDate ->
      ../mock-hr/Invoke-InboundProvisioning.ps1 hireDate -> provisioning ->
      Cloud Sync; TENANT-TIME mapping), or no birthright rule matches.
    * Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
      Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance.

.GRAPH SCOPES  (delegated; admin-consent)
    User.ReadWrite.All                 assign license, read user
    Organization.Read.All              enumerate subscribed SKUs (license id)
    GroupMember.ReadWrite.All          add to the app groups (fallback path)
    Group.Read.All                     resolve group ids
    EntitlementManagement.ReadWrite.All  create the access-package assignment request
    Directory.Read.All                 general reads

.PARAMETER UserPrincipalName
    The joiner. Defaults to the lab protagonist dana.okafor@contosohealth.io.

.PARAMETER AccessPackageName
    Display name of the access package. Defaults to the contract value
    "Nurse - Clinical Apps" (automatic / birthright).

.PARAMETER CatalogPath
    lab/iga/access-catalog.json: decides automatic (wait for delivery) vs
    request (adminAdd). A package missing from it is refused.

.PARAMETER WaitForAssignmentSeconds
    Automatic packages: how long to wait for the assignment to reach
    Delivered. Default 900 (Learn: the policy evaluates within minutes).

.PARAMETER PollSeconds
    Poll interval while waiting. Default 30.

.PARAMETER LicenseSkuPartNumber
    SKU part number to assign. There is deliberately NO default: trial SKUs
    differ by tenant (e.g. SPE_E5 vs a "no Teams" E5 SKU). Run without it once
    and the script lists what your tenant owns, then skips licensing.

.PARAMETER UsageLocation
    Two-letter country code set when the user has none (license assignment
    fails without it). Default US.

.PARAMETER AppGroupMailNicknames
    The app groups the access package grants, used directly ONLY on the
    no-Governance fallback path. Must match lab/terraform/modules/groups.

.PARAMETER UseAccessPackage
    $true (default) uses the governed access-package path. Set $false to use ONLY
    the license + group path (the P1/P2 fallback, mirroring the Logic App).

.PARAMETER WhatIf
    Standard. Prints intended changes, performs none.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.ReadWrite.All','Organization.Read.All','GroupMember.ReadWrite.All','Group.Read.All','EntitlementManagement.ReadWrite.All','Directory.Read.All'
    ./02-Joiner.ps1 -WhatIf                                   # lists the tenant's SKUs
    ./02-Joiner.ps1 -LicenseSkuPartNumber 'SPE_E5'

.EXAMPLE
    # P1/P2-only (no Governance): license + group, no access package:
    ./02-Joiner.ps1 -LicenseSkuPartNumber 'SPE_E5' -UseAccessPackage:$false

.WHAT IT DEMONSTRATES
    Zero-touch day-1 access: birthright packages arrive by HR attribute (no
    request, no approval, no expiry that would lock a nurse out on day 180),
    requestable access goes through a governed request policy, and a
    documented P1/P2 fallback keeps the design working without Entra ID
    Governance.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN/email.')]
    [string]$UserPrincipalName = 'dana.okafor@contosohealth.io',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AccessPackageName = 'Nurse - Clinical Apps',

    [Parameter()]
    # No default on purpose -- see .PARAMETER LicenseSkuPartNumber.
    [string]$LicenseSkuPartNumber = '',

    [Parameter()]
    [ValidatePattern('^[A-Z]{2}$')]
    [string]$UsageLocation = 'US',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$AppGroupMailNicknames = @('app-servicenow-users', 'app-aws-identitycenter-users'),

    [Parameter()]
    [bool]$UseAccessPackage = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'access-catalog.json'),

    [Parameter()]
    [ValidateRange(0, 3600)]
    [int]$WaitForAssignmentSeconds = 900,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 30
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

# ---------------------------------------------------------------------------
# Pure helpers (tests/02-Joiner.Tests.ps1; same copies in 03-Mover.ps1,
# parity-tested).
# ---------------------------------------------------------------------------
function Get-PackageAssignmentModel {
    # 'automatic' | 'request' for a package in lab/iga/access-catalog.json.
    # A package the catalog does not know is an error: guessing "request"
    # would adminAdd a birthright package, guessing "automatic" would wait
    # for an assignment nothing creates.
    param([Parameter(Mandatory)][string]$CatalogPath, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) { throw "Access catalog not found: $CatalogPath" }
    $cat = Get-Content -LiteralPath $CatalogPath -Raw | ConvertFrom-Json -AsHashtable
    $e = @(@($cat['accessPackages']) | Where-Object { $_ -and [string]$_['name'] -eq $Name }) | Select-Object -First 1
    if (-not $e) { throw "Access package '$Name' is not in $CatalogPath; add it there (tier + assignment) first." }
    $m = [string]$e['assignment']
    if ($m -notin 'automatic', 'request') { throw "Access package '$Name' has assignment '$m' in the catalog (expected automatic or request)." }
    return $m
}

function Test-IsAutomaticPolicy {
    # True for an automatic (attribute-rule) assignment policy: it carries
    # automaticRequestSettings. Works on SDK objects and Graph hashtables.
    param($Policy)
    if ($null -eq $Policy) { return $false }
    if ($Policy -is [System.Collections.IDictionary]) { return [bool]($Policy.Contains('automaticRequestSettings') -and $null -ne $Policy['automaticRequestSettings']) }
    $p = $Policy.PSObject.Properties['AutomaticRequestSettings']
    if ($p -and $null -ne $p.Value) { return $true }
    $ap = $Policy.PSObject.Properties['AdditionalProperties']
    return [bool]($ap -and $ap.Value -is [System.Collections.IDictionary] -and $ap.Value.Contains('automaticRequestSettings') -and $null -ne $ap.Value['automaticRequestSettings'])
}

# Day-1 steps that could not be delivered; non-empty => warn + exit 1 at the end.
$incomplete = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Connect with the right scopes.
# ---------------------------------------------------------------------------
$requiredScopes = @(
    'User.ReadWrite.All', 'Organization.Read.All', 'GroupMember.ReadWrite.All',
    'Group.Read.All', 'EntitlementManagement.ReadWrite.All', 'Directory.Read.All'
)
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 and lookups may report 'not found' (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

# ---------------------------------------------------------------------------
# Resolve the target user.
# ---------------------------------------------------------------------------
$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property 'id,displayName,department,assignedLicenses,usageLocation' -ErrorAction SilentlyContinue
if (-not $user) {
    throw "User '$UserPrincipalName' not found. Run inbound provisioning (../mock-hr) and let Cloud Sync run (or provision on demand) so the joiner exists in Entra."
}
Write-Console "Joiner: $($user.DisplayName) <$UserPrincipalName> (dept: $($user.Department))" -ForegroundColor Cyan

# ===========================================================================
# 1. LICENSE  (idempotent)
# ===========================================================================
Write-Console "`n[1/4] License" -ForegroundColor Cyan
$ownedSkus = @(Get-MgSubscribedSku -All)
$sku = if ($LicenseSkuPartNumber) { $ownedSkus | Where-Object SkuPartNumber -eq $LicenseSkuPartNumber | Select-Object -First 1 } else { $null }
# StrictMode-safe projection: '.AssignedLicenses.SkuId' throws on the empty
# array a brand-new joiner has; the foreach statement skips empty and $null.
$assignedSkuIds = @(foreach ($l in $user.AssignedLicenses) { if ($null -ne $l) { $l.SkuId } })
if (-not $LicenseSkuPartNumber -or -not $sku) {
    $owned = ($ownedSkus | ForEach-Object { "$($_.SkuPartNumber) ($($_.ConsumedUnits)/$($_.PrepaidUnits.Enabled) used)" }) -join ', '
    Write-Warning "  No usable -LicenseSkuPartNumber ('$LicenseSkuPartNumber'). Skipping license. Tenant owns: $owned"
}
elseif ($assignedSkuIds -contains $sku.SkuId) {
    Write-Console "  [=] Already licensed with $LicenseSkuPartNumber." -ForegroundColor DarkGray
}
else {
    # License assignment 400s without a usage location; it is a cloud-side
    # attribute, so it can be set even on an AD-synced user.
    if (-not $user.UsageLocation -and $PSCmdlet.ShouldProcess($UserPrincipalName, "set usageLocation $UsageLocation")) {
        Update-MgUser -UserId $user.Id -UsageLocation $UsageLocation
        Write-Console "  [+] Set usageLocation = $UsageLocation." -ForegroundColor Green
    }
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "assign license $LicenseSkuPartNumber")) {
        Set-MgUserLicense -UserId $user.Id -AddLicenses @(@{ SkuId = $sku.SkuId }) -RemoveLicenses @() | Out-Null
        Write-Console "  [+] Assigned $LicenseSkuPartNumber." -ForegroundColor Green
    }
}

# ===========================================================================
# 2. DYNAMIC GROUP  (verify only -- membership is automatic)
# ===========================================================================
Write-Console "`n[2/4] Birthright group (All-Nurses, dynamic)" -ForegroundColor Cyan
$dyn = Get-MgGroup -Filter "mailNickname eq 'all-nurses'" -ErrorAction SilentlyContinue
if ($dyn) {
    $isMember = Get-MgGroupMember -GroupId $dyn.Id -All -ErrorAction SilentlyContinue | Where-Object Id -eq $user.Id
    if ($isMember) { Write-Console "  [=] Confirmed in All-Nurses (dynamic rule matched on department)." -ForegroundColor Green }
    else { Write-Console "  [i] Not yet in All-Nurses. Dynamic processing is async (minutes) and keys off department='Nursing'. Verify the attribute, then re-check." -ForegroundColor Yellow }
}
else { Write-Warning "  All-Nurses group missing. Apply Terraform envs/dev with enable_premium = true, then run 01-Verify-Baseline.ps1." }

# ===========================================================================
# 3. ASSIGNED GROUP  (fallback / baseline app access)
# ===========================================================================
Write-Console "`n[3/4] App groups ($($AppGroupMailNicknames -join ', '))" -ForegroundColor Cyan
foreach ($nick in $AppGroupMailNicknames) {
    $assigned = Get-MgGroup -Filter "mailNickname eq '$nick'" -ErrorAction SilentlyContinue
    if (-not $assigned) {
        Write-Warning "  Group '$nick' missing. Apply Terraform envs/dev with enable_premium = true."
        continue
    }
    $isMember = Get-MgGroupMember -GroupId $assigned.Id -All -ErrorAction SilentlyContinue | Where-Object Id -eq $user.Id
    if ($isMember) { Write-Console "  [=] Already a member of $nick." -ForegroundColor DarkGray }
    elseif (-not $UseAccessPackage -and $PSCmdlet.ShouldProcess($UserPrincipalName, "add to $nick")) {
        # When the access package is in play it owns the group grant; we only
        # add directly in the no-Governance fallback path.
        New-MgGroupMember -GroupId $assigned.Id -DirectoryObjectId $user.Id
        Write-Console "  [+] Added to $nick (fallback path)." -ForegroundColor Green
    }
    else { Write-Console "  [i] Leaving $nick to the access package (step 4)." -ForegroundColor DarkGray }
}

# ===========================================================================
# 4. ACCESS PACKAGE  (governed path -- requires Entra ID Governance)
# ===========================================================================
Write-Console "`n[4/4] Access package ('$AccessPackageName')" -ForegroundColor Cyan
if (-not $UseAccessPackage) {
    Write-Console "  [skip] -UseAccessPackage:`$false -> using the P1/P2 fallback (license + group only)." -ForegroundColor Yellow
}
else {
    # -ErrorAction Stop + catch: a rejected query (wrong filter, missing scope,
    # no Governance license) is reported and fails the run; it must never read
    # as "not found" followed by "Joiner complete".
    try {
        # Resolve the access package + an assignment policy that permits adminAdd.
        $ap = Get-MgEntitlementManagementAccessPackage -Filter "displayName eq '$AccessPackageName'" -ErrorAction Stop
        if (-not $ap) {
            Write-Warning "  Access package '$AccessPackageName' not found. Create it in Entra Governance (needs the Governance license), then re-run. Falling back to NOT granting via package."
            $incomplete.Add("access package '$AccessPackageName' not found")
        }
        else {
            # v1.0 policies/assignments have no accessPackageId property: expand the
            # package's assignmentPolicies (as Reset-DemoState / New-LifecycleWorkflows do).
            $model = Get-PackageAssignmentModel -CatalogPath $CatalogPath -Name $AccessPackageName
            $apFull = Get-MgEntitlementManagementAccessPackage -AccessPackageId $ap.Id -ExpandProperty assignmentPolicies -ErrorAction Stop
            $allPolicies = @(@($apFull.AssignmentPolicies) | Where-Object { $null -ne $_ })
            $autoPolicies = @($allPolicies | Where-Object { Test-IsAutomaticPolicy $_ })
            $getDelivered = {
                @(Get-MgEntitlementManagementAssignment -All -ErrorAction Stop `
                        -Filter "accessPackage/id eq '$($ap.Id)' and target/objectId eq '$($user.Id)'" -ExpandProperty 'target,accessPackage' |
                        Where-Object { $_ -and $_.State -in 'delivered', 'delivering', 'partiallyDelivered' })
            }
            if ($model -eq 'automatic') {
                # BIRTHRIGHT: assigned by the automatic policy from HR attributes.
                # Never adminAdd - verify, and wait for delivery.
                if ($autoPolicies.Count -eq 0) {
                    Write-Warning "  '$AccessPackageName' is a birthright (automatic) package but has no automatic assignment policy. Run post-apply/Set-AutoAssignmentPolicies.ps1, then re-run. No request was sent."
                    $incomplete.Add("no automatic policy on '$AccessPackageName'")
                }
                elseif ($WhatIfPreference) {
                    Write-Console "  [whatif] Birthright package: would wait up to $WaitForAssignmentSeconds s for the automatic policy to deliver it. No request is ever sent." -ForegroundColor DarkYellow
                }
                else {
                    # Bounded by attempts, not the clock: -WaitForAssignmentSeconds / -PollSeconds checks.
                    $attempts = [int][math]::Ceiling($WaitForAssignmentSeconds / $PollSeconds)
                    $held = & $getDelivered
                    for ($i = 0; -not $held -and $i -lt $attempts; $i++) {
                        Write-Console "  [i] Waiting for the automatic (birthright) assignment - next check in $PollSeconds s." -ForegroundColor DarkGray
                        Start-Sleep -Seconds $PollSeconds
                        $held = & $getDelivered
                    }
                    if ($held) {
                        Write-Console "  [=] '$AccessPackageName' $($held[0].State) by the automatic (birthright) policy - no request, no approval, no expiry." -ForegroundColor Green
                    }
                    else {
                        Write-Warning "  '$AccessPackageName' was not delivered within $WaitForAssignmentSeconds s. The automatic policy assigns it only while the rule matches: department and job title (lab/iga/birthright-rules.json), account enabled, and employeeHireDate set and not in the future. Check those on the user (employeeHireDate flows from HR startDate), then re-run. No adminAdd is sent for a birthright package."
                        $incomplete.Add("birthright '$AccessPackageName' not delivered")
                    }
                }
            }
            else {
                # REQUESTABLE (T2): adminAdd through the REQUEST policy. An
                # automatic policy on the same package is never used for this.
                $requestPolicies = @($allPolicies | Where-Object { -not (Test-IsAutomaticPolicy $_) })
                # Terraform names its request policy "<package> - <N> day"; prefer it if
                # someone added more policies in the portal.
                $policies = if ($requestPolicies.Count -gt 1) { @($requestPolicies | Where-Object DisplayName -like "$AccessPackageName - * day") } else { $requestPolicies }
                $policy = $policies | Select-Object -First 1
                if (-not $policy) {
                    Write-Warning "  No request policy on '$AccessPackageName' ($($allPolicies.Count) polic(ies), $($autoPolicies.Count) automatic). A request policy (expiry + SoD) must exist to request against."
                    $incomplete.Add("no request policy on '$AccessPackageName'")
                }
                else {
                    # Guard against a duplicate request: skip if the user already has a
                    # delivered/delivering assignment. v1.0 filters on accessPackage/id.
                    $existingAssign = & $getDelivered
                    if ($existingAssign) {
                        Write-Console "  [=] User already has a '$AccessPackageName' assignment ($($existingAssign[0].State))." -ForegroundColor DarkGray
                    }
                    elseif ($PSCmdlet.ShouldProcess($UserPrincipalName, "request access package '$AccessPackageName' (adminAdd)")) {
                        # v1.0 schema: requestType=adminAdd + assignment{ targetId, accessPackageId, assignmentPolicyId }.
                        $reqBody = @{
                            requestType = 'adminAdd'
                            assignment  = @{
                                targetId           = $user.Id
                                accessPackageId    = $ap.Id
                                assignmentPolicyId = $policy.Id
                            }
                        }
                        $req = New-MgEntitlementManagementAssignmentRequest -BodyParameter $reqBody
                        Write-Console "  [+] Submitted assignment request $($req.Id) (state: $($req.State)) through request policy '$($policy.DisplayName)' (expiry + SoD links)." -ForegroundColor Green
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "  Access-package step failed: $($_.Exception.Message)"
        $incomplete.Add('access-package step failed (see warning above)')
    }
}

if ($incomplete.Count) {
    Write-Warning "Joiner INCOMPLETE for ${UserPrincipalName}: $($incomplete -join '; '). Fix the above and re-run (idempotent), or use -UseAccessPackage:`$false for the P1/P2 path."
    exit 1
}
Write-Console "`nJoiner complete for $UserPrincipalName." -ForegroundColor Cyan

# ===========================================================================
# ======  LOGIC APP ALTERNATIVE  --  "runs without Entra ID Governance"  ======
# ===========================================================================
# Access packages and Lifecycle Workflows BOTH require Entra ID Governance. The
# video callout promises a version that runs on P1/P2 alone. That version is a
# Logic App (Consumption) that authenticates to Microsoft Graph with its own
# SYSTEM-ASSIGNED MANAGED IDENTITY (no secret) and performs the same day-1 steps
# the script above does -- MINUS the access package (it adds the group directly
# and relies on the group's own lifecycle instead of a package policy).
#
# Grant the Logic App's managed identity these Graph APP roles (admin-consent):
#   User.ReadWrite.All, GroupMember.ReadWrite.All, Organization.Read.All
#
# Trigger options:
#   * HTTP request trigger, called by the HR feed / provisioning webhook, OR
#   * Recurrence (e.g. every 15 min) that reads the HR feed and diffs.
#
# Deploy as an ARM/Bicep resource or paste into the Logic Apps designer (code
# view). Replace <...> placeholders. This is reference JSON, kept as a comment
# so this .ps1 stays a single self-documenting artifact:
#
# {
#   "definition": {
#     "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
#     "contentVersion": "1.0.0.0",
#     "parameters": {
#       "graphResource": { "type": "String", "defaultValue": "https://graph.microsoft.com" }
#     },
#     "triggers": {
#       "When_a_new_hire_is_posted": {
#         "type": "Request",
#         "kind": "Http",
#         "inputs": {
#           "schema": {
#             "type": "object",
#             "properties": {
#               "userPrincipalName": { "type": "string" },
#               "skuId":            { "type": "string" },
#               "assignedGroupId":  { "type": "string" }
#             },
#             "required": [ "userPrincipalName", "assignedGroupId" ]
#           }
#         }
#       }
#     },
#     "actions": {
#       "Get_user": {
#         "type": "Http",
#         "inputs": {
#           "method": "GET",
#           "uri": "@{parameters('graphResource')}/v1.0/users/@{encodeURIComponent(triggerBody()?['userPrincipalName'])}?$select=id,assignedLicenses",
#           "authentication": { "type": "ManagedServiceIdentity", "audience": "@parameters('graphResource')" }
#         }
#       },
#       "Assign_license": {
#         "type": "Http",
#         "runAfter": { "Get_user": [ "Succeeded" ] },
#         "inputs": {
#           "method": "POST",
#           "uri": "@{parameters('graphResource')}/v1.0/users/@{body('Get_user')?['id']}/assignLicense",
#           "authentication": { "type": "ManagedServiceIdentity", "audience": "@parameters('graphResource')" },
#           "body": {
#             "addLicenses": [ { "skuId": "@{triggerBody()?['skuId']}", "disabledPlans": [] } ],
#             "removeLicenses": []
#           }
#         }
#       },
#       "Add_to_assigned_group": {
#         "type": "Http",
#         "runAfter": { "Assign_license": [ "Succeeded", "Skipped" ] },
#         "inputs": {
#           "method": "POST",
#           "uri": "@{parameters('graphResource')}/v1.0/groups/@{triggerBody()?['assignedGroupId']}/members/$ref",
#           "authentication": { "type": "ManagedServiceIdentity", "audience": "@parameters('graphResource')" },
#           "body": {
#             "@@odata.id": "@{parameters('graphResource')}/v1.0/directoryObjects/@{body('Get_user')?['id']}"
#           }
#         }
#       },
#       "Response": {
#         "type": "Response",
#         "runAfter": { "Add_to_assigned_group": [ "Succeeded" ] },
#         "inputs": { "statusCode": 200, "body": { "status": "joiner day-1 access applied (no-Governance path)" } }
#       }
#     }
#   }
# }
#
# Mapping back to this script:
#   Get_user + Assign_license  == step 1 (LICENSE)
#   All-Nurses                 == automatic (dynamic group; the Logic App need not touch it)
#   Add_to_assigned_group      == step 3 (APP GROUPS; call once per app group id)
#   (no access-package action)  == the one capability you give up without Governance
# ===========================================================================
