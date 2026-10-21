<#
.SYNOPSIS
    Applies the Terraform-rendered PIM policy of a directory role (Global
    Administrator) and grants NAMED, EXPIRING eligibility for it. Idempotent.

.DESCRIPTION
    azuread 3.10 has no resource for a directory role's own PIM policy, and
    azuread_directory_role_eligibility_schedule_request always requests
    noExpiration. So modules/pim (directory-roles.tf) renders the Graph rule
    bodies from real ids into output directory_role_pim_policies, and this
    script makes the tenant match them - the DEFINITION stays code-reviewed
    in Terraform; only the HTTP calls happen here.

    Per role in the file (today: Global Administrator):
      1. GET /policies/roleManagementPolicyAssignments?$filter=scopeId eq '/'
         and scopeType eq 'DirectoryRole' and roleDefinitionId eq '<id>'
         -> the role's policy id.
      2. GET .../roleManagementPolicies/<policyId>/rules, compare each
         rendered rule; [=] in state, [~] differs.
      3. PATCH only the rules that differ, STRENGTHENING FIRST:
           * switching TO the auth context: AuthenticationContext rule
             enabled BEFORE MultiFactorAuthentication leaves the Enablement
             rule;
           * switching BACK: MFA added BEFORE the context is switched off.
         The first failed PATCH stops that role (later rules, and its
         eligibility grants, are not attempted), so a partial run never
         leaves a weaker policy than it found. If Graph refuses the context
         while MFA is still on (verify: Graph may reject both together),
         re-run with -AllowMfaGap: MFA is dropped first, leaving activation
         with approval + justification + ticket only until the next PATCH,
         seconds later.
      4. Grants each -EligibleUserPrincipalNames person eligibility through
         POST /roleManagement/directory/roleEligibilityScheduleRequests,
         expiration afterDuration = the rendered eligibilityDuration (P180D).
         Existing eligibility is kept ([=]); a PERMANENT one is reported.

    Guards: break-glass (bg-admin-NN) is never made eligible (standing GA by
    design, ADR 0003); a non-adm- account gets a warning; a person in the
    role's approver group gets a warning; a failed READ is a failure.

    Deliberately NOT touched: the role's direct-ACTIVE assignment rules
    (Expiration_Admin_Assignment, Enablement_Admin_Assignment) - break-glass
    holds standing GA through a Terraform role assignment (modules/pim
    directory-roles.tf explains; verify: whether the roleAssignments API
    honours them).

    TENANT-TIME. Nothing here has run against a tenant. verify (first run):
      * the AuthenticationContext and Notification rule PATCH bodies (Graph
        documents the types but gives no example for these two);
      * that Graph accepts the GA policy with approval by a groupMembers
        approver group that is role-assignable;
    Settled (Learn, PIM for Groups role settings): PIM's MFA backup "isn't
    triggered" while the context's CA policy is report-only or off, so the
    context must never be set before CA021 is ENFORCED in the tenant -
    Terraform refuses it until CA021 is declared enabled AND attested
    (ca021_enforced_in_tenant).

.NOTES
    PREREQUISITES
    * envs/dev applied with enable_premium and modules/pim
      enable_global_admin_pim_policy = true (wiring: envs/dev README).
    * terraform -chdir=lab/terraform/envs/dev output -json directory_role_pim_policies > ga-policy.json
    * Role: Privileged Role Administrator (or Global Administrator).


    GRAPH SCOPES (delegated; admin-consent)
    RoleManagementPolicy.ReadWrite.Directory     read / PATCH role policy rules
    RoleEligibilitySchedule.ReadWrite.Directory  read / create role eligibility
    User.Read.All, GroupMember.Read.All          resolve people, approver members

.PARAMETER PolicyPath
    JSON written by `terraform output -json directory_role_pim_policies`: a
    map of role template id -> JSON STRING. A full `terraform output -json`
    file is accepted too.

.PARAMETER EligibleUserPrincipalNames
    Admin accounts to make eligible for every role whose rendered policy has
    allowNamedEligibility = true. Empty = policies only.

.PARAMETER AllowMfaGap
    Order the MFA -> auth-context switch MFA-removal first. Only after a run
    without it failed on the AuthenticationContext rule.

.EXAMPLE
    terraform -chdir=lab/terraform/envs/dev output -json directory_role_pim_policies > ga-policy.json
    Connect-MgGraph -Scopes 'RoleManagementPolicy.ReadWrite.Directory','RoleEligibilitySchedule.ReadWrite.Directory','User.Read.All','GroupMember.Read.All'
    ./Set-DirectoryRolePimPolicies.ps1 -PolicyPath ./ga-policy.json -EligibleUserPrincipalNames 'adm-first.last@<tenant>.onmicrosoft.com' -WhatIf
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PolicyPath,

    [Parameter()]
    [string[]]$EligibleUserPrincipalNames = @(),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Justification = 'Lab: named Global Administrator eligibility - expires; activation needs approval, justification, ticket and MFA or the Tier-0 auth context.',

    [Parameter()]
    [switch]$AllowMfaGap
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

# =============================================================================
# Pure helpers (unit-tested without a tenant)
# =============================================================================
function Read-RolePolicyFile {
    # Returns an ordered map roleDefinitionId -> policy (hashtable). Accepts the
    # single-output JSON (id -> JSON string) or a full `terraform output -json`.
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if ($null -eq $raw) { return [ordered]@{} }
    if ($raw.Contains('directory_role_pim_policies') -and $raw['directory_role_pim_policies'] -is [System.Collections.IDictionary]) {
        $raw = $raw['directory_role_pim_policies']['value']
        if ($null -eq $raw) { return [ordered]@{} }
    }
    $out = [ordered]@{}
    foreach ($k in @($raw.Keys | Sort-Object)) {
        $v = $raw[$k]
        $p = if ($v -is [string]) { $v | ConvertFrom-Json -AsHashtable } else { $v }
        foreach ($need in 'roleDefinitionId', 'rules', 'eligibilityDuration') {
            if (-not $p.Contains($need)) { throw "Policy '$k' has no '$need': is $Path the directory_role_pim_policies output?" }
        }
        if ($p['roleDefinitionId'] -ne $k) { throw "Policy key '$k' does not match its roleDefinitionId '$($p['roleDefinitionId'])'." }
        $out[$k] = $p
    }
    return $out
}

function Get-ApproverGroupId {
    # groupIds of the groupMembers approvers in the rendered Approval rule.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules)
    $approval = @($Rules | Where-Object { $_['id'] -eq 'Approval_EndUser_Assignment' }) | Select-Object -First 1
    if (-not $approval) { return @() }
    return @(foreach ($s in @($approval['setting']['approvalStages'])) {
            foreach ($a in @($s['primaryApprovers'])) { if ($a['@odata.type'] -eq '#microsoft.graph.groupMembers') { $a['groupId'] } }
        })
}

function Get-RuleDrift {
    # Names the settings where the tenant's rule differs from the rendered
    # one. Empty = in desired state. Only the fields the policy controls are
    # compared (Graph returns more, e.g. target.targetObjects).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Desired, [System.Collections.IDictionary]$Actual)
    if ($null -eq $Actual) { return , @('rule missing') }
    $diffs = [System.Collections.Generic.List[string]]::new()
    $type = [string]$Desired['@odata.type']
    function Get-Value($Map, [string]$Key) { if ($null -ne $Map -and $Map.Contains($Key)) { return $Map[$Key] } return $null }
    function Get-SortedSet($Value) { return ((@($Value | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) | Sort-Object -Unique) -join ',') }
    switch -Wildcard ($type) {
        '*ExpirationRule' {
            foreach ($k in 'isExpirationRequired', 'maximumDuration') {
                if ([string](Get-Value $Desired $k) -ne [string](Get-Value $Actual $k)) { $diffs.Add($k) }
            }
        }
        '*EnablementRule' {
            if ((Get-SortedSet (Get-Value $Desired 'enabledRules')) -ne (Get-SortedSet (Get-Value $Actual 'enabledRules'))) { $diffs.Add('enabledRules') }
        }
        '*AuthenticationContextRule' {
            $want = [bool](Get-Value $Desired 'isEnabled')
            if ($want -ne [bool](Get-Value $Actual 'isEnabled')) { $diffs.Add('isEnabled') }
            if ($want -and [string](Get-Value $Desired 'claimValue') -ne [string](Get-Value $Actual 'claimValue')) { $diffs.Add('claimValue') }
        }
        '*ApprovalRule' {
            $ds = Get-Value $Desired 'setting'; $as = Get-Value $Actual 'setting'
            foreach ($k in 'isApprovalRequired', 'isRequestorJustificationRequired') {
                if ([string](Get-Value $ds $k) -ne [string](Get-Value $as $k)) { $diffs.Add("setting.$k") }
            }
            $da = Get-SortedSet (@(foreach ($s in @(Get-Value $ds 'approvalStages')) { foreach ($a in @(Get-Value $s 'primaryApprovers')) { "$(Get-Value $a '@odata.type')|$(Get-Value $a 'groupId')$(Get-Value $a 'userId')" } }))
            $aa = Get-SortedSet (@(foreach ($s in @(Get-Value $as 'approvalStages')) { foreach ($a in @(Get-Value $s 'primaryApprovers')) { "$(Get-Value $a '@odata.type')|$(Get-Value $a 'groupId')$(Get-Value $a 'userId')" } }))
            if ($da -ne $aa) { $diffs.Add('setting.approvalStages.primaryApprovers') }
        }
        '*NotificationRule' {
            foreach ($k in 'notificationLevel', 'isDefaultRecipientsEnabled') {
                if ([string](Get-Value $Desired $k) -ne [string](Get-Value $Actual $k)) { $diffs.Add($k) }
            }
            if ((Get-SortedSet (Get-Value $Desired 'notificationRecipients')) -ne (Get-SortedSet (Get-Value $Actual 'notificationRecipients'))) { $diffs.Add('notificationRecipients') }
        }
        default { throw "Unsupported rule type '$type' ($($Desired['id']))." }
    }
    return , @($diffs)
}

function Get-RulePatchOrder {
    # Orders the rule ids to PATCH so the policy is never weaker in between:
    # turning the auth context ON goes before MFA leaves the Enablement rule;
    # turning it OFF goes after MFA is back. -AllowMfaGap reverses the first
    # case (only for a Graph that refuses MFA and the context together).
    param(
        [Parameter(Mandatory)][string[]]$RuleIds,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Desired,
        [System.Collections.IDictionary]$Actual = @{},
        [switch]$AllowMfaGap
    )
    $ctxId = 'AuthenticationContext_EndUser_Assignment'; $enId = 'Enablement_EndUser_Assignment'
    $order = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $RuleIds) { $order.Add($id) }
    if ($ctxId -in $RuleIds -and $enId -in $RuleIds) {
        $wantCtx = [bool]$Desired[$ctxId]['isEnabled']
        $haveCtx = $Actual.Contains($ctxId) -and $null -ne $Actual[$ctxId] -and [bool]$Actual[$ctxId]['isEnabled']
        $ctxFirst = if ($wantCtx -and -not $haveCtx) { -not $AllowMfaGap } elseif (-not $wantCtx -and $haveCtx) { $false } else { $true }
        [void]$order.Remove($ctxId); [void]$order.Remove($enId)
        $pair = if ($ctxFirst) { @($ctxId, $enId) } else { @($enId, $ctxId) }
        # Keep the pair where the first of them stood.
        $at = [Math]::Min([array]::IndexOf($RuleIds, $ctxId), [array]::IndexOf($RuleIds, $enId))
        $order.InsertRange([Math]::Min($at, $order.Count), [string[]]$pair)
    }
    return , $order.ToArray()
}

function Test-BreakGlassUpn {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    return [bool]($UserPrincipalName -match '^bg-admin-\d+@')
}

function Test-AdminAccountUpn {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    return [bool]($UserPrincipalName -match '^adm-')
}

function Get-RoleEligibilityRequestBody {
    param(
        [Parameter(Mandatory)][string]$RoleDefinitionId,
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$DirectoryScopeId,
        [Parameter(Mandatory)][string]$Duration,
        [Parameter(Mandatory)][string]$Justification,
        [Parameter(Mandatory)][datetime]$Start
    )
    if ($Duration -notmatch '^P\d+D$') { throw "Refusing eligibility without a whole-day expiry ('$Duration'): noExpiration is never requested." }
    return [ordered]@{
        action           = 'adminAssign'
        justification    = $Justification
        roleDefinitionId = $RoleDefinitionId
        directoryScopeId = $DirectoryScopeId
        principalId      = $PrincipalId
        scheduleInfo     = [ordered]@{
            startDateTime = $Start.ToUniversalTime().ToString('o')
            expiration    = [ordered]@{ type = 'afterDuration'; duration = $Duration }
        }
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $items.ToArray()
}

# =============================================================================
# Main
# =============================================================================
$policies = Read-RolePolicyFile -Path $PolicyPath
if ($policies.Count -eq 0) {
    Write-Warning "No directory role policies in $PolicyPath. Is enable_global_admin_pim_policy = true in modules/pim (and applied)?"
    exit 1
}

$requiredScopes = @('RoleManagementPolicy.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory', 'User.Read.All', 'GroupMember.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx -and -not $WhatIfPreference) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
if ($ctx) {
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }
}

# Guards that need no tenant: refuse break-glass before anything is sent.
$failures = 0
$people = [System.Collections.Generic.List[string]]::new()
foreach ($upn in $EligibleUserPrincipalNames) {
    if (Test-BreakGlassUpn -UserPrincipalName $upn) {
        Write-Warning "  [x] $upn is a break-glass account: it holds standing Global Administrator by design (ADR 0003) and is never made eligible. Skipped."
        $failures++
        continue
    }
    if (-not (Test-AdminAccountUpn -UserPrincipalName $upn)) {
        Write-Warning "  [!] $upn is not an adm- account. Privileged eligibility belongs on a separate cloud-only admin account (privileged-access standard section 1)."
    }
    $people.Add($upn)
}

Write-Console "Directory role PIM policies: $($policies.Count) rendered by Terraform" -ForegroundColor Cyan

foreach ($roleId in $policies.Keys) {
    $p = $policies[$roleId]
    $name = if ($p.Contains('roleName')) { [string]$p['roleName'] } else { $roleId }
    $rules = @($p['rules'])
    $desired = [ordered]@{}; foreach ($r in $rules) { $desired[[string]$r['id']] = $r }
    Write-Console "`n$name ($roleId) - eligibility $($p['eligibilityDuration'])" -ForegroundColor Cyan

    if (-not $ctx) {
        # -WhatIf with no Graph session: offline preview of what would be sent.
        foreach ($id in $desired.Keys) { Write-Console "  [?] would ensure rule $id" -ForegroundColor Yellow }
        foreach ($upn in $people) { Write-Console "  [?] would make $upn eligible for $($p['eligibilityDuration'])" -ForegroundColor Yellow }
        continue
    }

    # 1-2. The role's policy and its current rules. A failed read stops the role.
    try {
        $assignment = @(Get-GraphCollection -Uri "$graph/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleId'") | Select-Object -First 1
        if (-not $assignment) { throw "no roleManagementPolicyAssignment for role $roleId at scope '/'" }
        $policyId = [string]$assignment['policyId']
        $current = @{}
        foreach ($r in @(Get-GraphCollection -Uri "$graph/policies/roleManagementPolicies/$policyId/rules")) { $current[[string]$r['id']] = $r }
    }
    catch {
        Write-Warning "  [!] $name - could not read its PIM policy: $($_.Exception.Message). Nothing changed for this role."
        $failures++
        continue
    }

    $toPatch = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $desired.Keys) {
        $actual = if ($current.Contains($id)) { $current[$id] } else { $null }
        $diffs = Get-RuleDrift -Desired $desired[$id] -Actual $actual
        if ($diffs.Count) { Write-Console "  [~] $id differs: $($diffs -join ', ')" -ForegroundColor Yellow; $toPatch.Add($id) }
        else { Write-Console "  [=] $id" -ForegroundColor DarkGray }
    }

    # 3. PATCH, strengthening first; stop the role at the first failure.
    $policyComplete = $true
    if ($toPatch.Count) {
        $ordered = Get-RulePatchOrder -RuleIds $toPatch.ToArray() -Desired $desired -Actual $current -AllowMfaGap:$AllowMfaGap
        foreach ($id in $ordered) {
            $json = $desired[$id] | ConvertTo-Json -Depth 20 -Compress
            if ($PSCmdlet.ShouldProcess("$name rule $id", 'PATCH roleManagementPolicies rule')) {
                try {
                    Invoke-MgGraphRequest -Method PATCH -Uri "$graph/policies/roleManagementPolicies/$policyId/rules/$id" -Body $json -ContentType 'application/json' | Out-Null
                    Write-Console "  [+] $id updated." -ForegroundColor Green
                }
                catch {
                    $hint = if ($id -eq 'AuthenticationContext_EndUser_Assignment' -and [bool]$desired[$id]['isEnabled'] -and -not $AllowMfaGap) { ' If Graph refuses the context while MFA is still required, re-run with -AllowMfaGap.' } else { '' }
                    Write-Warning "  [!] $id not updated: $($_.Exception.Message). Remaining rules for $name were NOT attempted, and no eligibility is granted under a partial policy.$hint"
                    $failures++
                    $policyComplete = $false
                    break
                }
            }
            else { $policyComplete = $false }
        }
    }

    # 4. Named, expiring eligibility.
    if (-not $p['allowNamedEligibility'] -or $people.Count -eq 0) { continue }
    if (-not $policyComplete -and -not $WhatIfPreference) { continue }

    $approverIds = @()
    foreach ($gid in @(Get-ApproverGroupId -Rules $rules)) {
        try { $approverIds += @(Get-GraphCollection -Uri "$graph/groups/$gid/transitiveMembers?`$select=id" | ForEach-Object { $_['id'] }) }
        catch { Write-Warning "  [!] Could not read approver group ${gid}: $($_.Exception.Message); check approver/eligible overlap by hand." }
    }

    foreach ($upn in $people) {
        try {
            $user = @(Get-GraphCollection -Uri "$graph/users?`$filter=userPrincipalName eq '$upn'&`$select=id,displayName") | Select-Object -First 1
            if (-not $user) { Write-Warning "  '$upn' not found - create the admin account first."; $failures++; continue }
            $existing = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($user['id'])' and roleDefinitionId eq '$roleId'")
        }
        catch {
            Write-Warning "  [!] Could not read $upn or its eligibility: $($_.Exception.Message)"
            $failures++
            continue
        }
        if ($user['id'] -in $approverIds) {
            Write-Warning "  [!] $upn is also an approver for $name. Keep approvers and eligible people disjoint."
        }
        if ($existing) {
            $permanent = @($existing | Where-Object { $_.Contains('scheduleInfo') -and $_['scheduleInfo'] -and $_['scheduleInfo']['expiration'] -and $_['scheduleInfo']['expiration']['type'] -eq 'noExpiration' })
            if ($permanent) { Write-Warning "  [~] $upn holds a PERMANENT $name eligibility. Remove it (adminRemove) and re-run so it expires after $($p['eligibilityDuration'])." }
            else { Write-Console "  [=] $upn is already eligible." -ForegroundColor DarkGray }
            continue
        }
        if ($PSCmdlet.ShouldProcess($upn, "make eligible for $name for $($p['eligibilityDuration'])")) {
            $body = Get-RoleEligibilityRequestBody -RoleDefinitionId $roleId -PrincipalId $user['id'] -DirectoryScopeId ([string]$p['directoryScopeId']) -Duration ([string]$p['eligibilityDuration']) -Justification $Justification -Start (Get-Date) | ConvertTo-Json -Depth 5
            try {
                $req = Invoke-MgGraphRequest -Method POST -Uri "$graph/roleManagement/directory/roleEligibilityScheduleRequests" -Body $body -ContentType 'application/json' -OutputType HashTable
                Write-Console "  [+] $upn eligible for $name for $($p['eligibilityDuration']) (request $($req['id']), status $($req['status']))." -ForegroundColor Green
            }
            catch {
                Write-Warning "  [!] $upn not made eligible: $($_.Exception.Message)"
                $failures++
            }
        }
    }
}

if ($failures) { Write-Warning "$failures step(s) failed."; exit 1 }
Write-Console "`nVerify: Entra -> PIM -> Microsoft Entra roles -> Settings -> Global Administrator, and Assignments -> Eligible (End time set)." -ForegroundColor Cyan
