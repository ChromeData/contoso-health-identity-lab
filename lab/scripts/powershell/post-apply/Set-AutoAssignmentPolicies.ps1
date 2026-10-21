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

.EXAMPLE
    ./Set-AutoAssignmentPolicies.ps1 -RenderOnly
.EXAMPLE
    Connect-MgGraph -Scopes 'EntitlementManagement.ReadWrite.All','Group.Read.All'
    ./Set-AutoAssignmentPolicies.ps1 -WhatIf
    ./Set-AutoAssignmentPolicies.ps1            # prompts per change (ConfirmImpact High)

.OUTPUTS
    -RenderOnly: the desired policies. Otherwise one result row per package
    (Package, Action, Detail). Exit 1 when any package FAILED.

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
    [switch]$RenderOnly
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

# =============================================================================
# SCRIPT BODY
# =============================================================================
$rules = Read-IgaJson -Path $RulesPath
$catalog = Read-IgaJson -Path $CatalogPath
$mode = if ($MatchOn) { $MatchOn } else { [string]$rules['settings']['matchOn'] }

$problems = @(Test-BirthrightRuleSet -Rules $rules -Catalog $catalog -MatchOn $mode)
if ($problems.Count) {
    foreach ($p in $problems) { Write-Warning "  RULE ERROR: $p" }
    throw "birthright-rules.json is not safe to apply ($($problems.Count) error(s)). Nothing was sent to Graph."
}
$desired = @(Get-DesiredAutoPolicy -Rules $rules -MatchOn $mode)
if ($AccessPackage.Count) {
    $unknown = @($AccessPackage | Where-Object { $_ -notin $desired.Package })
    if ($unknown) { throw "-AccessPackage names no birthright package: $($unknown -join ', ')" }
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
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser), or use -RenderOnly.' }
$requiredScopes = @('EntitlementManagement.ReadWrite.All', 'Group.Read.All', 'User.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
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
$pre = Get-HireDatePreflight -Users @(Get-GraphCollection -Uri "$graph/users?`$filter=$uf&`$select=id,department,employeeHireDate&`$top=999") -Departments $birthrightDepts
if ($pre.WithHireDate -eq 0) {
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
Write-Console ("`n{0} package(s): {1}" -f $results.Count, (($results | Group-Object Action | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')) -ForegroundColor $(if ($bad) { 'Red' } else { 'Green' })
Write-Console 'Verify: Entra -> ID Governance -> Access packages -> <package> -> Policies (auto-assignment) and Assignments.' -ForegroundColor Cyan
$results.ToArray()
if ($bad) { exit 1 }
