<#
.SYNOPSIS
    Birthright access from HR attributes: creates or updates ONE Entra ID
    Governance automatic assignment policy per birthright access package,
    from lab/iga/birthright-rules.json. Idempotent; -WhatIf; -RenderOnly
    needs no tenant.

.DESCRIPTION
    ADR 0012 tier T3. Core clinical access is not requested and approved one
    nurse at a time: entitlement management assigns the package to everyone
    whose HR attributes match a rule, and removes it 72 hours after they stop
    matching (the mover grace period). A mover is therefore driven by the HR
    attribute change itself; 03-Mover.ps1 becomes the verification/fallback.

    WHAT IT DOES, per package that has a birthright job profile
      1. Builds the membership rule from the job profiles (department +
         jobTitle today, department + jobCode in the target state), always
         AND-ed with accountEnabled, userType = Member and employeeHireDate
         <= now (no birthright before day one).
      2. Refuses (no Graph write) when the rule set is unsafe: a birthright
         package that is privileged, reaches a role-assignable or PIM/
         Privileged/Break-Glass group, is not tier T3, uses memberOf, or
         exceeds the 3,072-character rule limit.
      3. Finds the package (planned packages are skipped and said so), reads
         its policies, and:
           no automatic policy   -> POST one (allowedTargetScope =
                                    specificDirectoryUsers, attributeRuleMembers,
                                    automaticRequestSettings with the grace period)
           one automatic policy  -> compare; PUT the merged policy only if the
                                    rule, scope or automatic settings drifted
           two or more           -> FAIL for that package: Microsoft supports
                                    several automatic policies only with no
                                    overlap and no transitions between them
      0. PREFLIGHT (before any write): counts the enabled Member users in the
         birthright departments and how many have employeeHireDate. Every
         rule requires "user.employeeHireDate -le system.now", so with NO
         hire date in scope the policies would assign the packages to NOBODY
         - a clinical lockout by design. The run refuses at zero (nothing
         sent) and warns, by count, about in-scope users still missing one.
         The hire date flows HR startDate -> mock-hr/
         Invoke-InboundProvisioning.ps1 (SCIM extension hireDate) ->
         provisioning mapping -> Cloud Sync -> employeeHireDate (TENANT-TIME
         mappings; verify: on the first job setup).
      4. Reports, never deletes: an automatic policy on a package the catalog
         says is request-only (privileged or discretionary access handed out
         by attribute), and assignments still held through an expiring
         request policy on a birthright package (the day-180 lockout ADR 0012
         describes).

    WHY THE PUT IS A MERGE: the v1.0 update is a full replace (PUT) whose
    body must carry every required property. The script reads the current
    policy, removes read-only fields, overlays only the fields this file
    owns, and sends the rest back as the service returned it.

    WHAT IT DOES NOT DO: delete a policy (removing an automatic policy removes
    access from everyone it assigned - a portal decision for a human), or
    touch request policies (Terraform owns them; lab/iga/README.md "Not wired yet").

.PREREQUISITES
    * Terraform envs/dev applied with enable_premium + enable_governance.
    * Signed-in role: Identity Governance Administrator. Microsoft Learn:
      catalog owners and access package managers CANNOT create automatic
      assignment policies.
    * License: Microsoft Entra ID Governance (or Entra Suite).
    * The attributes in the rule must be written by HR provisioning only
      (Learn: dynamic-rule security = whoever can write the attribute).

.GRAPH SCOPES  (delegated; admin consent)
    EntitlementManagement.ReadWrite.All   read packages/policies, create/update policies
    Group.Read.All                        privileged-resource guard (isAssignableToRole)
    User.Read.All                         hire-date preflight (department, employeeHireDate)

    APP-ONLY (-UseAzureCliToken, the pipeline path): the same three as
    application permissions, or a ReadWrite superset. terraform-apply.yml
    runs this script after a successful apply as the APPLY identity, whose
    baseline Graph roles (modules/pipeline-identity apply_graph_roles) hold
    EntitlementManagement.ReadWrite.All, Group.ReadWrite.All and
    User.ReadWrite.All: nothing extra is granted for it (pinned by
    tests/AutoAssignmentPipeline.Tests.ps1). The "Identity Governance
    Administrator" prerequisite above is for a DELEGATED caller; an app with
    EntitlementManagement.ReadWrite.All needs no directory role.
    verify: on the first pipeline run, that the application permission
    creates an AUTOMATIC assignment policy (Learn documents the permission
    for the create call, not the automatic case specifically).

.PARAMETER RulesPath
    Birthright rules. Default lab/iga/birthright-rules.json.

.PARAMETER CatalogPath
    Access catalog (tiers, statuses, resources). Default lab/iga/access-catalog.json.

.PARAMETER MatchOn
    jobTitle or jobCode. Empty = the rule file's settings.matchOn.

.PARAMETER AccessPackage
    Limit the run to these package display names. Default: every package
    with a birthright job profile.

.PARAMETER RenderOnly
    Validate the rules and print the policies that would be sent. No Graph
    module, connection or tenant needed. Returns the desired policies.

.PARAMETER UseAzureCliToken
    App-only sign-in for pipelines: take a Microsoft Graph token from the
    Azure CLI session (`az account get-access-token --resource-type ms-graph`;
    in GitHub Actions, azure/login over OIDC) and connect with it - always
    that identity, never a leftover context. The token is masked in Actions
    and stays in this process: never in argv, a file or the output. Used for
    -WhatIf too (the comparison needs the tenant's current policies).

.PARAMETER SummaryPath
    Write plain-English Markdown bullets for a run summary (terraform-apply.yml
    puts them in the Apply summary), e.g.
      - Automatic access rule set: **IT - Cloud Engineering Apps** goes to
        everyone in Information Technology with the job title Cloud Engineer.
      - No automatic access rules needed changing.
    Written on every outcome once the rule file is read, refusals included.
    Package names and rule wording only: never a person.

.PARAMETER SummaryDetailsPath
    The same run's technical lines (action and policy id per package) for the
    summary's details section.

.EXAMPLE
    ./Set-AutoAssignmentPolicies.ps1 -RenderOnly
.EXAMPLE
    Connect-MgGraph -Scopes 'EntitlementManagement.ReadWrite.All','Group.Read.All'
    ./Set-AutoAssignmentPolicies.ps1 -WhatIf
    ./Set-AutoAssignmentPolicies.ps1            # prompts per change (ConfirmImpact High)
.EXAMPLE
    # Pipeline (terraform-apply.yml, after a successful apply, as APPLY):
    ./Set-AutoAssignmentPolicies.ps1 -UseAzureCliToken -Confirm:$false `
        -SummaryPath $env:RUNNER_TEMP/plain-autoassign.md -SummaryDetailsPath $env:RUNNER_TEMP/tech-autoassign.md

.OUTPUTS
    -RenderOnly: the desired policies. Otherwise one result row per package
    (Package, Action, Detail). Exit 1 when any package FAILED or a request-only
    package carries an automatic policy (drift-found). A refusal before any
    write (unsafe rule file, no hire dates in scope, no Graph sign-in) throws.

.NOTES
    TENANT-TIME: nothing here has run against Entra. Confirmed on Microsoft
    Learn 2026-10-20: POST/PUT /identityGovernance/entitlementManagement/
    assignmentPolicies, allowedTargetScope specificDirectoryUsers,
    #microsoft.graph.attributeRuleMembers + membershipRule,
    automaticRequestSettings {requestAccessForAllowedTargets,
    removeAccessWhenTargetLeavesAllowedTargets, gracePeriodBeforeAccessRemoval
    (ISO 8601 duration)}, one automatic policy per package, 15,000 identities
    per policy, memberOf quarantined from 2026-11-03, backtick escaping of
    double quotes in rule values, 3,072-character rule limit.
    verify: GET accessPackages/{id}?$expand=resourceRoleScopes($expand=role,scope)
      returns scope.originId = group object id (privileged guard). If the
      shape differs the guard FAILS CLOSED - fix the query, do not remove it:
      no resourceRoleScopes key, a scope without originSystem / originId, or
      a number of AadGroup scopes different from the catalog entry's
      'resources' count each fail the package (nothing written).
    verify: the service returns membershipRule exactly as sent (whitespace is
      normalised before comparing; any other rewrite shows as drift every run).
    verify: an automatic policy accepts the PUT with the expiration /
      requestorSettings the service itself returned.
    verify: assignments created earlier by the 180-day request policy are
      left alone by the automatic policy ("creates assignments for those who
      don't already have assignments") - so they still EXPIRE. Whether the
      automatic policy re-assigns at that moment is undocumented; the script
      lists them so they can be watched (10-Review-KPIs.ps1 clinical lockouts).
    verify: removing a package assignment keeps a group membership another
      assignment still grants (Nurse and ICU both grant App-ServiceNow-Users).
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RulesPath = (Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'birthright-rules.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'access-catalog.json'),

    [Parameter()]
    [ValidateSet('', 'jobTitle', 'jobCode')]
    [string]$MatchOn = '',

    [Parameter()]
    [string[]]$AccessPackage = @(),

    [Parameter()]
    [switch]$RenderOnly,

    # App-only sign-in from the Azure CLI session (azure/login over OIDC).
    [Parameter()]
    [switch]$UseAzureCliToken,

    # Plain-English bullets for a run summary (terraform-apply.yml).
    [Parameter()]
    [string]$SummaryPath = '',

    # Technical lines for the same summary's details section.
    [Parameter()]
    [string]$SummaryDetailsPath = ''
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

# =============================================================================
# PURE FUNCTIONS - no I/O. Unit-tested in tests/Set-AutoAssignmentPolicies.Tests.ps1
# (loaded from this file's syntax tree, so the script body never runs there).
# =============================================================================

function Read-IgaJson {
    # Shared by the lab/iga scripts (parity-tested): JSON file -> hashtable.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 50)
}

function Get-CatalogEntry {
    # Shared by the lab/iga scripts (parity-tested): catalog entry by kind + name, or $null.
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][ValidateSet('accessPackages', 'groups', 'directoryRoles')][string]$Kind, [Parameter(Mandatory)][string]$Name)
    foreach ($e in @($Catalog[$Kind])) { if ($e -and [string]$e['name'] -eq $Name) { return $e } }
    return $null
}

function ConvertFrom-IsoDuration {
    # ISO 8601 duration (P3D, PT72H) -> TimeSpan; $null when it does not parse.
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return [System.Xml.XmlConvert]::ToTimeSpan($Value.Trim()) } catch { return $null }
}

function ConvertTo-RuleLiteral {
    # A string value for a dynamic membership rule: double quotes escaped with
    # a backtick (Microsoft Learn, rule syntax); control characters refused.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'Empty value in a membership rule.' }
    if ($Value -match '[\x00-\x1F]') { throw "Control character in membership rule value '$Value'." }
    return '"' + $Value.Replace('"', '`"') + '"'
}

function ConvertTo-MembershipRule {
    # Job profiles that grant ONE package -> one membership rule:
    #   (base1) -and (base2) -and ((dept -eq "X" -and match -in [...]) -or (...))
    # Profiles are grouped by department; departments and values are sorted
    # so the rule text is stable run to run (idempotent comparisons).
    param([Parameter(Mandatory)][object[]]$Profiles, [Parameter(Mandatory)]$Settings, [Parameter(Mandatory)][ValidateSet('jobTitle', 'jobCode')][string]$MatchOn)
    $attrs = $Settings['attributes']
    $deptAttr = [string]$attrs['department']; $matchAttr = [string]$attrs[$MatchOn]
    if (-not $deptAttr -or -not $matchAttr) { throw "settings.attributes must define 'department' and '$MatchOn'." }
    $clauses = foreach ($g in (@($Profiles) | Group-Object { [string]$_['department'] } | Sort-Object Name)) {
        $values = @($g.Group | ForEach-Object { [string]$_[$MatchOn] } | Sort-Object -Unique)
        if ($values.Count -eq 0 -or ($values | Where-Object { [string]::IsNullOrWhiteSpace($_) })) { throw "A job profile in department '$($g.Name)' has no $MatchOn." }
        $list = ($values | ForEach-Object { ConvertTo-RuleLiteral $_ }) -join ','
        "($deptAttr -eq $(ConvertTo-RuleLiteral $g.Name) -and $matchAttr -in [$list])"
    }
    $base = @($Settings['baseConditions'] | ForEach-Object { "($_)" })
    return (@($base) + "($(@($clauses) -join ' -or '))") -join ' -and '
}

function Test-BirthrightRuleSet {
    # Every reason the rule file must not be applied. Empty = safe to apply.
    param([Parameter(Mandatory)]$Rules, [Parameter(Mandatory)]$Catalog, [ValidateSet('', 'jobTitle', 'jobCode')][string]$MatchOn = '')
    $errs = [System.Collections.Generic.List[string]]::new()
    $s = $Rules['settings']
    if (-not $s) { $errs.Add('settings missing.'); return $errs.ToArray() }
    $mode = if ($MatchOn) { $MatchOn } else { [string]$s['matchOn'] }
    if ($mode -notin 'jobTitle', 'jobCode') { $errs.Add("settings.matchOn must be jobTitle or jobCode (got '$mode').") }
    $attrs = $s['attributes']
    foreach ($k in 'department', $mode) {
        if (-not $attrs -or -not $attrs[$k]) { $errs.Add("settings.attributes.$k missing.") }
        elseif ([string]$attrs[$k] -notmatch '^user\.[A-Za-z][A-Za-z0-9_]*$') { $errs.Add("settings.attributes.$k '$($attrs[$k])' is not a user property (user.<name>).") }
    }
    # memberOf is quarantined from 2026-11-03 (Learn) and never allowed here (ADR 0012).
    $attrValues = if ($attrs) { @($attrs.Values) } else { @() }
    $ruleText = (@($attrValues) + @($s['baseConditions'])) -join ' '
    if ($ruleText -match '(?i)memberof') { $errs.Add('memberOf must not appear in a birthright rule (ADR 0012; quarantined from 2026-11-03).') }
    # Birthright never fires before day one (HIPAA minimum necessary): an enabled pre-hire is not in scope.
    if (-not @($s['baseConditions'] | Where-Object { [string]$_ -match '^\s*user\.employeeHireDate\s+-le\s+system\.now\s*$' })) { $errs.Add('settings.baseConditions must include "user.employeeHireDate -le system.now" (no birthright before the hire date).') }
    foreach ($req in 'user.accountEnabled -eq true', 'user.userType -eq "Member"') { if ([string]$req -notin @($s['baseConditions'])) { $errs.Add("settings.baseConditions must include '$req'.") } }
    if (-not (ConvertFrom-IsoDuration ([string]$s['gracePeriodBeforeAccessRemoval']))) { $errs.Add("settings.gracePeriodBeforeAccessRemoval '$($s['gracePeriodBeforeAccessRemoval'])' is not an ISO 8601 duration.") }
    foreach ($b in 'requestAccessForAllowedTargets', 'removeAccessWhenTargetLeavesAllowedTargets') { if ($s[$b] -isnot [bool]) { $errs.Add("settings.$b must be true or false.") } }

    $nb = $Rules['neverBirthright']
    $patterns = if ($nb) { @($nb['groupNamePatterns']) } else { @() }
    $seenTitle = @{}; $seenCode = @{}
    foreach ($p in @($Rules['jobProfiles'])) {
        $dept = [string]$p['department']; $title = [string]$p['jobTitle']; $code = [string]$p['jobCode']
        $who = "job profile '$dept / $title'"
        if (-not $dept -or -not $title) { $errs.Add("A job profile has no department or jobTitle."); continue }
        $k = "$dept|$title".ToLowerInvariant(); if ($seenTitle.ContainsKey($k)) { $errs.Add("Duplicate $who.") } else { $seenTitle[$k] = 1 }
        if ($mode -eq 'jobCode') {
            if (-not $code) { $errs.Add("$who has no jobCode (matchOn = jobCode).") }
            else { $kc = "$dept|$code".ToLowerInvariant(); if ($seenCode.ContainsKey($kc)) { $errs.Add("Duplicate jobCode '$code' in department '$dept'.") } else { $seenCode[$kc] = 1 } }
        }
        foreach ($pkgName in @($p['birthright'])) {
            if (-not $pkgName) { continue }
            $e = Get-CatalogEntry -Catalog $Catalog -Kind accessPackages -Name $pkgName
            if (-not $e) { $errs.Add("$who`: birthright package '$pkgName' is not in access-catalog.json."); continue }
            if ([string]$e['tier'] -ne 'T3') { $errs.Add("$who`: '$pkgName' is tier $($e['tier']); only T3 packages may be birthright (ADR 0012).") }
            if ([string]$e['assignment'] -notmatch 'automatic') { $errs.Add("$who`: '$pkgName' is request-only in the catalog; it cannot be birthright.") }
            if ($e['privileged'] -eq $true) { $errs.Add("$who`: '$pkgName' is privileged; privileged access is never birthright.") }
            foreach ($r in @($e['resources'])) {
                if (-not $r) { continue }
                if (@($patterns | Where-Object { $r -match $_ })) { $errs.Add("$who`: '$pkgName' grants '$r', a privileged group name; privileged access is never birthright.") }
                $g = Get-CatalogEntry -Catalog $Catalog -Kind groups -Name $r
                if ($g -and ($g['privileged'] -eq $true -or [string]$g['kind'] -eq 'role-assignable')) { $errs.Add("$who`: '$pkgName' grants '$r' (privileged / role-assignable); privileged access is never birthright.") }
            }
        }
        foreach ($pkgName in @($p['requestable'])) {
            if (-not $pkgName) { continue }
            $e = Get-CatalogEntry -Catalog $Catalog -Kind accessPackages -Name $pkgName
            if (-not $e) { $errs.Add("$who`: requestable package '$pkgName' is not in access-catalog.json."); continue }
            if ([string]$e['assignment'] -notmatch 'request') { $errs.Add("$who`: '$pkgName' has no request policy in the catalog, so it cannot be requested.") }
            if ($pkgName -in @($p['birthright'])) { $errs.Add("$who`: '$pkgName' is both birthright and requestable.") }
        }
    }
    if ($errs.Count -eq 0 -and $mode -in 'jobTitle', 'jobCode') {
        $max = if ($s['maxRuleLength']) { [int]$s['maxRuleLength'] } else { 3072 }
        foreach ($d in (Get-DesiredAutoPolicy -Rules $Rules -MatchOn $mode)) {
            if ($d.MembershipRule.Length -gt $max) { $errs.Add("Rule for '$($d.Package)' is $($d.MembershipRule.Length) characters (limit $max).") }
        }
    }
    return $errs.ToArray()
}

function Get-DesiredAutoPolicy {
    # One desired automatic policy per birthright package (sorted by name).
    param([Parameter(Mandatory)]$Rules, [Parameter(Mandatory)][ValidateSet('jobTitle', 'jobCode')][string]$MatchOn)
    $s = $Rules['settings']
    $byPackage = [ordered]@{}
    foreach ($p in @($Rules['jobProfiles'])) {
        foreach ($pkgName in @($p['birthright'])) {
            if (-not $pkgName) { continue }
            if (-not $byPackage.Contains($pkgName)) { $byPackage[$pkgName] = [System.Collections.Generic.List[object]]::new() }
            $byPackage[$pkgName].Add($p)
        }
    }
    foreach ($pkgName in ($byPackage.Keys | Sort-Object)) {
        $rule = ConvertTo-MembershipRule -Profiles $byPackage[$pkgName].ToArray() -Settings $s -MatchOn $MatchOn
        $name = ([string]$s['policyDisplayName']).Replace('{package}', $pkgName)
        [pscustomobject]@{
            Package        = $pkgName
            DisplayName    = $name
            Description    = [string]$s['policyDescription']
            MembershipRule = $rule
            Settings       = [ordered]@{
                requestAccessForAllowedTargets             = [bool]$s['requestAccessForAllowedTargets']
                removeAccessWhenTargetLeavesAllowedTargets = [bool]$s['removeAccessWhenTargetLeavesAllowedTargets']
                gracePeriodBeforeAccessRemoval             = [string]$s['gracePeriodBeforeAccessRemoval']
            }
            Profiles       = @($byPackage[$pkgName] | ForEach-Object { "$($_['department']) / $($_['jobTitle'])" })
        }
    }
}

function Get-HireDatePreflight {
    # Users (id, department, employeeHireDate, as Graph returns them) ->
    # how many are in the birthright departments and how many of those carry
    # a hire date. Pure.
    param([AllowEmptyCollection()][object[]]$Users = @(), [Parameter(Mandatory)][string[]]$Departments)
    $inScope = @($Users | Where-Object { $_ -and [string]$_['department'] -in $Departments })
    $withHire = @($inScope | Where-Object { $_.Contains('employeeHireDate') -and $_['employeeHireDate'] })
    return [pscustomobject]@{ InScope = $inScope.Count; WithHireDate = $withHire.Count; Missing = $inScope.Count - $withHire.Count }
}

function ConvertTo-AutoPolicyBody {
    # The fields this script owns, shaped like the Learn create example.
    param([Parameter(Mandatory)]$Desired, [Parameter(Mandatory)][string]$AccessPackageId)
    return [ordered]@{
        displayName              = $Desired.DisplayName
        description              = $Desired.Description
        allowedTargetScope       = 'specificDirectoryUsers'
        specificAllowedTargets   = @([ordered]@{
                '@odata.type'  = '#microsoft.graph.attributeRuleMembers'
                description    = "Birthright rule for $($Desired.Package) (lab/iga/birthright-rules.json)"
                membershipRule = $Desired.MembershipRule
            })
        automaticRequestSettings = [ordered]@{
            requestAccessForAllowedTargets             = $Desired.Settings['requestAccessForAllowedTargets']
            removeAccessWhenTargetLeavesAllowedTargets = $Desired.Settings['removeAccessWhenTargetLeavesAllowedTargets']
            gracePeriodBeforeAccessRemoval             = $Desired.Settings['gracePeriodBeforeAccessRemoval']
        }
        accessPackage            = [ordered]@{ id = $AccessPackageId }
    }
}

function Get-PolicyRule {
    # membershipRule of an automatic policy's attributeRuleMembers target, or ''.
    param([Parameter(Mandatory)]$Policy)
    foreach ($t in @($Policy['specificAllowedTargets'])) {
        if ($t -and [string]$t['@odata.type'] -like '*attributeRuleMembers*') { return [string]$t['membershipRule'] }
    }
    return ''
}

function Compare-AutoPolicy {
    # Names of the owned fields that differ (empty = in sync). Rule text is
    # compared with whitespace collapsed; durations as TimeSpans (P3D = PT72H).
    param([Parameter(Mandatory)]$Existing, [Parameter(Mandatory)]$Desired)
    $diff = [System.Collections.Generic.List[string]]::new()
    $norm = { param($t) ([regex]::Replace([string]$t, '\s+', ' ')).Trim() }
    if ((& $norm (Get-PolicyRule $Existing)) -cne (& $norm $Desired.MembershipRule)) { $diff.Add('membershipRule') }
    if ([string]$Existing['allowedTargetScope'] -ne 'specificDirectoryUsers') { $diff.Add('allowedTargetScope') }
    if ([string]$Existing['displayName'] -cne $Desired.DisplayName) { $diff.Add('displayName') }
    if ([string]$Existing['description'] -cne $Desired.Description) { $diff.Add('description') }
    $ars = $Existing['automaticRequestSettings']
    if (-not $ars) { $diff.Add('automaticRequestSettings') }
    else {
        foreach ($b in 'requestAccessForAllowedTargets', 'removeAccessWhenTargetLeavesAllowedTargets') { if ([bool]$ars[$b] -ne [bool]$Desired.Settings[$b]) { $diff.Add($b) } }
        $have = ConvertFrom-IsoDuration ([string]$ars['gracePeriodBeforeAccessRemoval']); $want = ConvertFrom-IsoDuration ([string]$Desired.Settings['gracePeriodBeforeAccessRemoval'])
        if ($have -ne $want) { $diff.Add('gracePeriodBeforeAccessRemoval') }
    }
    return $diff.ToArray()
}

function Merge-AutoPolicyBody {
    # PUT body: the policy as the service returned it, minus read-only and
    # OData annotation fields, with the owned fields overlaid.
    param([Parameter(Mandatory)]$Existing, [Parameter(Mandatory)]$Desired, [Parameter(Mandatory)][string]$AccessPackageId)
    $readOnly = @('id', 'createdDateTime', 'modifiedDateTime', 'catalog', 'customExtensionStageSettings')
    $body = [ordered]@{}
    foreach ($k in $Existing.Keys) {
        if ($k -in $readOnly -or $k -like '@odata.*' -or $k -like '*@odata.*') { continue }
        $body[$k] = $Existing[$k]
    }
    $owned = ConvertTo-AutoPolicyBody -Desired $Desired -AccessPackageId $AccessPackageId
    foreach ($k in $owned.Keys) { $body[$k] = $owned[$k] }
    return $body
}

function Get-MissingGraphPermission {
    # Required permissions the context does not cover. A ReadWrite (or
    # Directory) permission covers its Read counterpart: the app-only APPLY
    # identity holds Group.ReadWrite.All / User.ReadWrite.All, not the Read
    # roles a delegated operator consents to. Empty -Have = unknown (no warning).
    param([AllowEmptyCollection()][string[]]$Have = @(), [Parameter(Mandatory)][string[]]$Required)
    if (-not @($Have | Where-Object { $_ })) { return @() }
    $coveredBy = @{
        'Group.Read.All' = @('Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
        'User.Read.All'  = @('User.Read.All', 'User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
    }
    return @($Required | Where-Object {
            $ok = if ($coveredBy.ContainsKey($_)) { $coveredBy[$_] } else { @($_) }
            -not @($Have | Where-Object { $_ -in $ok })
        })
}

function ConvertTo-AudienceText {
    # Who a birthright package goes to, in plain words, from its job
    # profiles: "everyone in Nursing with the job title Nurse Manager or
    # Registered Nurse". Departments and values sorted, as in the rule.
    param([Parameter(Mandatory)]$Rules, [Parameter(Mandatory)][string]$Package, [Parameter(Mandatory)][ValidateSet('jobTitle', 'jobCode')][string]$MatchOn)
    $what = if ($MatchOn -eq 'jobCode') { 'job code' } else { 'job title' }
    $profiles = @(@($Rules['jobProfiles']) | Where-Object { $_ -and $Package -in @($_['birthright']) })
    if (-not $profiles) { return 'nobody yet (no job profile in lab/iga/birthright-rules.json names it)' }
    $parts = foreach ($g in (@($profiles) | Group-Object { [string]$_['department'] } | Sort-Object Name)) {
        $v = @($g.Group | ForEach-Object { [string]$_[$MatchOn] } | Sort-Object -Unique)
        $list = if ($v.Count -le 1) { $v -join '' } else { (@($v[0..($v.Count - 2)]) -join ', ') + ' or ' + $v[-1] }
        "everyone in $($g.Name) with the $what $list"
    }
    return (@($parts) -join '; and ')
}

function Get-AutoAssignmentFailureText {
    # A failed package's technical detail -> one plain sentence.
    param([AllowEmptyString()][string]$Detail = '')
    if ($Detail -like '*never birthright*') { return 'It would hand out admin-level access, and admin access is never given automatically.' }
    if ($Detail -like '*failing closed*') { return 'Its groups in Entra do not match the access catalog, so the safety check stopped it.' }
    if ($Detail -like '*not found in the tenant*') { return 'The access package does not exist in Entra yet.' }
    if ($Detail -like '*automatic policies*') { return 'It already has more than one automatic rule in Entra; an administrator merges them into one in the portal.' }
    if ($Detail -like '*share this display name*') { return 'Two access packages in Entra have this name.' }
    if ($Detail -match '\b403\b|Forbidden|Authorization_RequestDenied') { return 'Microsoft refused it: the pipeline identity is missing a permission.' }
    return 'Microsoft did not accept the change.'
}

function ConvertTo-AutoAssignmentSummary {
    # Result rows (Package, Action, Detail) or a refusal -> the run summary:
    # Plain = bullets for someone who is not an identity engineer, Details =
    # the technical lines. Package names, rule wording and policy ids only.
    param([AllowEmptyCollection()][object[]]$Results = @(), [Parameter(Mandatory)]$Rules, [Parameter(Mandatory)][ValidateSet('jobTitle', 'jobCode')][string]$MatchOn, [hashtable]$Refusal = $null)
    $plain = [System.Collections.Generic.List[string]]::new()
    $details = [System.Collections.Generic.List[string]]::new()
    $source = "``Set-AutoAssignmentPolicies.ps1`` from ``lab/iga/birthright-rules.json`` (match on $MatchOn, access removed $([string]$Rules['settings']['gracePeriodBeforeAccessRemoval']) after someone stops matching)"
    if ($Refusal) {
        $kind = [string]$Refusal['kind']
        $plain.Add($(switch ($kind) {
                    'unsafe-rules' { "- **Automatic access rules not changed:** the rule file failed its safety checks ($($Refusal['count']) problem(s), listed in the step log), so nothing was sent to Microsoft." }
                    'no-hire-date' { "- **Automatic access rules not changed:** none of the $($Refusal['inScope']) people in the departments these rules cover has a start date in Entra yet, so every rule would give access to nobody. Nothing was sent; the start date has to arrive from HR first." }
                    'sign-in' { '- **Automatic access rules not checked:** the pipeline could not get a Microsoft Graph sign-in. Nothing was changed; re-running the workflow is safe.' }
                    'unknown-package' { '- **Automatic access rules not changed:** a package that was asked for has no birthright rule.' }
                    default { '- **Automatic access rules not checked:** Microsoft Graph did not answer a read (see the step log). Nothing was changed.' }
                }))
        $details.Add("- **Automatic access rules:** $source; stopped before any change ($kind)")
        return [pscustomobject]@{ Plain = $plain.ToArray(); Details = $details.ToArray() }
    }
    foreach ($r in @($Results | Where-Object { $_ })) {
        $pkg = [string]$r.Package
        switch ([string]$r.Action) {
            'created' { $plain.Add("- Automatic access rule set: **$pkg** goes to $(ConvertTo-AudienceText -Rules $Rules -Package $pkg -MatchOn $MatchOn).") }
            'updated' { $plain.Add("- Automatic access rule updated: **$pkg** now goes to $(ConvertTo-AudienceText -Rules $Rules -Package $pkg -MatchOn $MatchOn).") }
            'would-create' { $plain.Add("- Dry run: would set the automatic access rule for **$pkg** (to $(ConvertTo-AudienceText -Rules $Rules -Package $pkg -MatchOn $MatchOn)).") }
            'would-update' { $plain.Add("- Dry run: would update the automatic access rule for **$pkg** (to $(ConvertTo-AudienceText -Rules $Rules -Package $pkg -MatchOn $MatchOn)).") }
            'failed' { $plain.Add("- **Automatic access rule not set: $pkg.** $(Get-AutoAssignmentFailureText ([string]$r.Detail)) Nothing was changed for this package.") }
            'drift-found' { $plain.Add("- **Needs a person: $pkg** is handed out automatically in Entra, but it should only be given on request. Nothing was removed; an administrator checks who holds it, then deletes that rule in the portal.") }
        }
    }
    if (-not @($Results | Where-Object { $_ -and [string]$_.Action -notin 'in-sync', 'skipped-planned' })) { $plain.Add('- No automatic access rules needed changing.') }
    $rows = @($Results | Where-Object { $_ -and [string]$_.Action -ne 'skipped-planned' } | ForEach-Object { "$($_.Package): $($_.Action) ($($_.Detail))" })
    $planned = @($Results | Where-Object { $_ -and [string]$_.Action -eq 'skipped-planned' } | ForEach-Object { [string]$_.Package })
    $details.Add("- **Automatic access rules:** $source")
    foreach ($row in $rows) { $details.Add("  - $row") }
    if ($planned) { $details.Add("  - planned, not built yet (skipped): $($planned -join ', ')") }
    return [pscustomobject]@{ Plain = $plain.ToArray(); Details = $details.ToArray() }
}

# =============================================================================
# SCRIPT BODY
# =============================================================================
$rules = Read-IgaJson -Path $RulesPath
$catalog = Read-IgaJson -Path $CatalogPath
$mode = if ($MatchOn) { $MatchOn } else { [string]$rules['settings']['matchOn'] }

# -SummaryPath / -SummaryDetailsPath, written on every outcome from here on.
$summaryTargets = @{ Plain = $SummaryPath; Details = $SummaryDetailsPath }
function Save-AutoAssignmentSummary {
    # Refusals included, so a run summary never has to guess what happened.
    # -WhatIf:$false: the summary is this run's own report, not a change.
    param([AllowEmptyCollection()][object[]]$Results = @(), [hashtable]$Refusal = $null)
    if (-not $summaryTargets.Plain -and -not $summaryTargets.Details) { return }
    $sm = if ($mode -in 'jobTitle', 'jobCode') { $mode } else { 'jobTitle' }
    $s = ConvertTo-AutoAssignmentSummary -Results $Results -Rules $rules -MatchOn $sm -Refusal $Refusal
    foreach ($target in @(@{ Path = $summaryTargets.Plain; Lines = $s.Plain }, @{ Path = $summaryTargets.Details; Lines = $s.Details })) {
        if (-not $target.Path) { continue }
        $dir = Split-Path -Parent $target.Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null }
        Set-Content -LiteralPath $target.Path -Value $target.Lines -Encoding utf8NoBOM -WhatIf:$false
    }
}

$problems = @(Test-BirthrightRuleSet -Rules $rules -Catalog $catalog -MatchOn $mode)
if ($problems.Count) {
    foreach ($p in $problems) { Write-Warning "  RULE ERROR: $p" }
    Save-AutoAssignmentSummary -Refusal @{ kind = 'unsafe-rules'; count = $problems.Count }
    throw "birthright-rules.json is not safe to apply ($($problems.Count) error(s)). Nothing was sent to Graph."
}
$desired = @(Get-DesiredAutoPolicy -Rules $rules -MatchOn $mode)
if ($AccessPackage.Count) {
    $unknown = @($AccessPackage | Where-Object { $_ -notin $desired.Package })
    if ($unknown) { Save-AutoAssignmentSummary -Refusal @{ kind = 'unknown-package' }; throw "-AccessPackage names no birthright package: $($unknown -join ', ')" }
    $desired = @($desired | Where-Object { $_.Package -in $AccessPackage })
}

Write-Console "Birthright automatic assignment policies (matchOn = $mode, grace $($rules['settings']['gracePeriodBeforeAccessRemoval']))" -ForegroundColor Cyan
foreach ($d in $desired) {
    $status = [string](Get-CatalogEntry -Catalog $catalog -Kind accessPackages -Name $d.Package)['status']
    Write-Console "  $($d.Package)  [$status]  <- $($d.Profiles -join '; ')" -ForegroundColor Cyan
    Write-Console "    $($d.MembershipRule)" -ForegroundColor DarkGray
}
if ($RenderOnly) { return $desired }

# ---- Graph ------------------------------------------------------------------
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    Save-AutoAssignmentSummary -Refusal @{ kind = 'no-graph-module' }
    throw 'Microsoft.Graph.Authentication is required (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser), or use -RenderOnly.'
}

function Connect-GraphFromAzureCli {
    # App-only: the Azure CLI is already signed in as an app (azure/login over
    # GitHub OIDC). The token never leaves this process: masked in Actions,
    # handed to Connect-MgGraph as a SecureString, then dropped. Same as
    # mock-hr/Invoke-InboundProvisioning.ps1, through Write-Console for the
    # analyzer; one copy each in Set-AutoAssignmentPolicies.ps1 and
    # Export-EvidencePack.ps1 (parity-tested).
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

$requiredScopes = @('EntitlementManagement.ReadWrite.All', 'Group.Read.All', 'User.Read.All')
if ($UseAzureCliToken) {
    # App-only (pipeline): always this identity, never a leftover context.
    Write-Console 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
    try { Connect-GraphFromAzureCli }
    catch { Save-AutoAssignmentSummary -Refusal @{ kind = 'sign-in' }; throw }
}
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) {
    if ($UseAzureCliToken) { Save-AutoAssignmentSummary -Refusal @{ kind = 'sign-in' }; throw 'No Microsoft Graph context after the app-only sign-in.' }
    Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext
}
# App-only contexts list the token's roles here; a ReadWrite role covers its Read.
$missingScopes = @(Get-MissingGraphPermission -Have @($ctx.Scopes) -Required $requiredScopes)
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }

$em = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement'
$graph = 'https://graph.microsoft.com/v1.0'
function Invoke-Graph {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body = $null)
    if ($null -ne $Body) { return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 20) -ContentType 'application/json' -OutputType HashTable }
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType HashTable
}
function Get-GraphCollection {
    # Shared by the lab/iga scripts (parity-tested): every page of a Graph collection.
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $items.ToArray()
}
function Find-AccessPackage {
    param([Parameter(Mandatory)][string]$Name)
    $f = [uri]::EscapeDataString("displayName eq '$($Name.Replace("'", "''"))'")
    return @(Get-GraphCollection -Uri "$em/accessPackages?`$filter=$f&`$select=id,displayName")
}
function Get-PackagePolicy {
    # Full policy objects of one package (the expand gives ids; each GET gives every property).
    param([Parameter(Mandatory)][string]$PackageId)
    $pkg = Invoke-Graph -Uri "$em/accessPackages/$PackageId`?`$expand=assignmentPolicies"
    return @(@($pkg['assignmentPolicies']) | Where-Object { $_ } | ForEach-Object { Invoke-Graph -Uri "$em/assignmentPolicies/$($_['id'])" })
}
function Test-PrivilegedResource {
    # Fail-closed guard: names of privileged groups the package grants. Any
    # response shape it cannot fully judge THROWS (the package then fails and
    # nothing is written) - an empty answer must never read as "not privileged".
    param([Parameter(Mandatory)][string]$PackageId, [Parameter(Mandatory)][int]$ExpectedGroupCount)
    $pkg = Invoke-Graph -Uri "$em/accessPackages/$PackageId`?`$expand=resourceRoleScopes(`$expand=role,scope)"
    if (-not ($pkg -is [System.Collections.IDictionary]) -or -not $pkg.Contains('resourceRoleScopes')) { throw "privileged-resource check: the package response has no resourceRoleScopes (query shape changed?) - failing closed." }
    $hits = @(); $groups = 0
    foreach ($rrs in @($pkg['resourceRoleScopes'])) {
        if (-not $rrs) { continue }
        $scope = $rrs['scope']
        if (-not $scope -or -not [string]$scope['originSystem'] -or -not [string]$scope['originId']) { throw "privileged-resource check: a resource scope has no originSystem/originId - failing closed." }
        if ([string]$scope['originSystem'] -ne 'AadGroup') { continue }
        $groups++
        $g = Invoke-Graph -Uri "$graph/groups/$($scope['originId'])?`$select=id,displayName,isAssignableToRole"
        $pat = @($rules['neverBirthright']['groupNamePatterns'] | Where-Object { [string]$g['displayName'] -match $_ })
        if ($g['isAssignableToRole'] -eq $true -or $pat) { $hits += [string]$g['displayName'] }
    }
    if ($groups -ne $ExpectedGroupCount) { throw "privileged-resource check: $groups group scope(s) in the tenant, $ExpectedGroupCount in access-catalog.json 'resources' - fix the catalog or the package before granting it automatically (failing closed)." }
    return $hits
}

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Package, [string]$Action, [string]$Detail)
    $results.Add([pscustomobject]@{ Package = $Package; Action = $Action; Detail = $Detail })
    $color = switch ($Action) { 'failed' { 'Red' } 'drift-found' { 'Red' } 'created' { 'Green' } 'updated' { 'Green' } 'in-sync' { 'DarkGray' } default { 'Yellow' } }
    Write-Host ("  [{0}] {1}: {2}" -f $Action, $Package, $Detail) -ForegroundColor $color
}

# ---- Preflight: employeeHireDate must have flowed, or nobody matches ----------
Write-Console "`nPreflight: employeeHireDate in the birthright departments" -ForegroundColor Cyan
$birthrightDepts = @(@($rules['jobProfiles']) | Where-Object { $_ -and @(@($_['birthright']) | Where-Object { $_ -in $desired.Package }).Count } | ForEach-Object { [string]$_['department'] } | Sort-Object -Unique)
$uf = [uri]::EscapeDataString("accountEnabled eq true and userType eq 'Member'")
try { $preUsers = @(Get-GraphCollection -Uri "$graph/users?`$filter=$uf&`$select=id,department,employeeHireDate&`$top=999") }
catch { Save-AutoAssignmentSummary -Refusal @{ kind = 'graph-read' }; throw }
$pre = Get-HireDatePreflight -Users $preUsers -Departments $birthrightDepts
if ($pre.WithHireDate -eq 0) {
    Save-AutoAssignmentSummary -Refusal @{ kind = 'no-hire-date'; inScope = $pre.InScope }
    throw ("Hire-date preflight: $($pre.InScope) enabled Member user(s) in the birthright departments ($($birthrightDepts -join ', ')) and NONE has employeeHireDate. " +
        'Every birthright rule requires "user.employeeHireDate -le system.now", so the automatic policies would assign the packages to nobody (a clinical lockout). ' +
        'Map HR startDate -> employeeHireDate first (mock-hr/Invoke-InboundProvisioning.ps1 sends it as the SCIM hireDate; the provisioning and Cloud Sync mappings are tenant-time steps), re-provision, then re-run. Nothing was sent.')
}
if ($pre.Missing -gt 0) { Write-Warning "  $($pre.Missing) of $($pre.InScope) in-scope user(s) have no employeeHireDate: they will get NO birthright access until HR provisioning sets it." }
else { Write-Console "  [=] $($pre.WithHireDate) of $($pre.InScope) in-scope user(s) carry employeeHireDate." -ForegroundColor DarkGray }

Write-Console "`nApplying" -ForegroundColor Cyan
foreach ($d in $desired) {
    $entry = Get-CatalogEntry -Catalog $catalog -Kind accessPackages -Name $d.Package
    try {
        $found = @(Find-AccessPackage -Name $d.Package)
        if ($found.Count -eq 0) {
            if ([string]$entry['status'] -eq 'planned') { Add-Result $d.Package 'skipped-planned' 'planned package (access-catalog.json); not created by Terraform yet' }
            else { Add-Result $d.Package 'failed' "not found in the tenant. Apply Terraform envs/dev with enable_governance = true first." }
            continue
        }
        if ($found.Count -gt 1) { Add-Result $d.Package 'failed' "$($found.Count) access packages share this display name; resolve the duplicate first."; continue }
        $pkgId = [string]$found[0]['id']

        $priv = @(Test-PrivilegedResource -PackageId $pkgId -ExpectedGroupCount @(@($entry['resources']) | Where-Object { $_ }).Count)
        if ($priv.Count) { Add-Result $d.Package 'failed' "grants privileged group(s) $($priv -join ', '); privileged access is never birthright. Nothing changed."; continue }

        $auto = @(Get-PackagePolicy -PackageId $pkgId | Where-Object { $_['automaticRequestSettings'] })
        if ($auto.Count -gt 1) { Add-Result $d.Package 'failed' "$($auto.Count) automatic policies. Microsoft supports this only with no overlap and no transitions between them; consolidate to one in the portal."; continue }

        if ($auto.Count -eq 0) {
            if ($PSCmdlet.ShouldProcess($d.Package, "create automatic assignment policy: $($d.MembershipRule)")) {
                $created = Invoke-Graph -Method POST -Uri "$em/assignmentPolicies" -Body (ConvertTo-AutoPolicyBody -Desired $d -AccessPackageId $pkgId)
                Add-Result $d.Package 'created' "policy $($created['id']). Entitlement management evaluates the rule within minutes (Learn); it also creates its own dynamic group - do not edit that group."
            }
            else { Add-Result $d.Package 'would-create' $d.DisplayName }
        }
        else {
            $existing = $auto[0]
            $drift = @(Compare-AutoPolicy -Existing $existing -Desired $d)
            if ($drift.Count -eq 0) { Add-Result $d.Package 'in-sync' "policy $($existing['id'])" }
            elseif ($PSCmdlet.ShouldProcess($d.Package, "update automatic policy $($existing['id']) ($($drift -join ', '))")) {
                Invoke-Graph -Method PUT -Uri "$em/assignmentPolicies/$($existing['id'])" -Body (Merge-AutoPolicyBody -Existing $existing -Desired $d -AccessPackageId $pkgId) | Out-Null
                Add-Result $d.Package 'updated' "policy $($existing['id']): $($drift -join ', ')"
            }
            else { Add-Result $d.Package 'would-update' "policy $($existing['id']): $($drift -join ', ')" }
        }

        # Report only: assignments still held through an expiring (request) policy.
        $autoIds = @($auto | ForEach-Object { [string]$_['id'] })
        $f = [uri]::EscapeDataString("accessPackage/id eq '$pkgId' and state eq 'Delivered'")
        $expiring = @(Get-GraphCollection -Uri "$em/assignments?`$filter=$f&`$expand=assignmentPolicy" | Where-Object {
                $pol = $_['assignmentPolicy']; $pid_ = if ($pol) { [string]$pol['id'] } else { '' }
                $end = if ($_['schedule'] -and $_['schedule']['expiration']) { $_['schedule']['expiration']['endDateTime'] } else { $null }
                $pid_ -notin $autoIds -and $end })
        if ($expiring.Count) {
            $first = ($expiring | ForEach-Object { ([datetime]$_['schedule']['expiration']['endDateTime']).ToUniversalTime() } | Sort-Object | Select-Object -First 1)
            Write-Warning "  $($d.Package): $($expiring.Count) assignment(s) are still held through an EXPIRING request policy (first ends $($first.ToString('yyyy-MM-dd'))). verify: whether the automatic policy re-assigns them at expiry; until confirmed, watch 10-Review-KPIs.ps1 clinicalLockouts.byExpiry."
        }
    }
    catch { Add-Result $d.Package 'failed' $_.Exception.Message }
}

# Report only: an automatic policy on a package the catalog says is request-only.
foreach ($e in @($catalog['accessPackages'] | Where-Object { $_ -and [string]$_['status'] -eq 'terraform' -and [string]$_['assignment'] -notmatch 'automatic' })) {
    if ($AccessPackage.Count -and [string]$e['name'] -notin $AccessPackage) { continue }
    try {
        $found = @(Find-AccessPackage -Name ([string]$e['name']))
        if ($found.Count -ne 1) { continue }
        $auto = @(Get-PackagePolicy -PackageId ([string]$found[0]['id']) | Where-Object { $_['automaticRequestSettings'] })
        if ($auto.Count) { Add-Result ([string]$e['name']) 'drift-found' "has $($auto.Count) automatic policy(ies) but is request-only (tier $($e['tier'])). Access handed out by attribute - remove it in the portal after checking who holds it. Not deleted by this script." }
    }
    catch { Add-Result ([string]$e['name']) 'failed' "request-only check: $($_.Exception.Message)" }
}

$bad = @($results | Where-Object Action -in 'failed', 'drift-found')
Save-AutoAssignmentSummary -Results $results.ToArray()
Write-Console ("`n{0} package(s): {1}" -f $results.Count, (($results | Group-Object Action | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')) -ForegroundColor $(if ($bad) { 'Red' } else { 'Green' })
Write-Console 'Verify: Entra -> ID Governance -> Access packages -> <package> -> Policies (auto-assignment) and Assignments.' -ForegroundColor Cyan
$results.ToArray()
if ($bad) { exit 1 }
