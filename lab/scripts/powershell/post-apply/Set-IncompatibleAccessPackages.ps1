<#
.SYNOPSIS
    PREVENTIVE separation of duties: turns lab/iga/sod-rules.json into Entra
    entitlement-management incompatibleAccessPackages / incompatibleGroups
    links. Idempotent; -WhatIf; -Prune; -RenderOnly needs no tenant.
    SUPERSEDES post-apply/Set-AccessPackageSoD.ps1 (see RELATION below).

.DESCRIPTION
    An incompatibility link lives ON the package being requested: "a user who
    already holds X (package) or is in G (group) cannot request this package,
    and an admin cannot newly assign it" (Microsoft Learn). Links are
    one-directional, so each pair is written in every direction that is
    SAFE - and one direction is not:

    THE BIRTHRIGHT RULE (ADR 0012). A package with an automatic (HR-attribute)
    policy never gets incompatibility links of its own. A link on "Nurse -
    Clinical Apps" would let an exception-holder's pharmacy access block the
    nurse's automatic birthright assignment - a clinical lockout created by a
    control. So SOD-01 is written as:
        Pharmacy - Controlled Substances Apps  X  Nurse - Clinical Apps, ICU - Critical Care Apps   (packages)
        Pharmacy - Controlled Substances Apps  X  All-Nurses, All-ICU                              (dynamic groups)
    and NOT the reverse. The reverse case (a pharmacist whose HR record moves
    to Nursing) is caught by 09-SoD-Report.ps1, the detective half.
    verify: Learn does not say whether automatic assignment honours
    incompatible packages; this design is safe either way.

    Rules with no requestable package on either side (directory roles, PIM
    groups, two birthright packages) cannot be enforced by entitlement
    management at all; they are listed as DETECTIVE-ONLY.

    LIVE RUN, per managed package (one that appears in the rules)
      * missing desired link            -> POST .../incompatibleAccessPackages/$ref
                                           or .../incompatibleGroups/$ref
      * link to a catalog object that is
        not desired (e.g. the legacy
        Nurse -> Pharmacy link)          -> reported as drift; removed only
                                           with -Prune (DELETE .../$ref)
      * link to anything not in the
        catalog                          -> reported, never touched
      * planned package/group            -> skipped and said so

    RELATION TO Set-AccessPackageSoD.ps1: that script writes ONE pair (Nurse
    <-> Pharmacy) in BOTH directions. This script writes all nine rules and
    deliberately omits the Nurse -> Pharmacy direction, which now gates a
    birthright package. Running both makes them fight (it re-adds, this one
    reports or prunes). Set-AccessPackageSoD.ps1 is therefore superseded:
    lab/iga/README.md ("Not wired yet") lists the Invoke-PostApply change.

.PREREQUISITES
    * Terraform envs/dev applied with enable_premium + enable_governance.
    * Run AFTER Set-AutoAssignmentPolicies.ps1 (which packages are automatic
      is read from access-catalog.json, not from the tenant).
    * Role: Access package manager / Catalog owner on the Clinical catalog,
      or Identity Governance Administrator.

.GRAPH SCOPES  (delegated; admin consent)
    EntitlementManagement.ReadWrite.All   list/add/remove incompatibility links
    Group.Read.All                        resolve group names to ids

.PARAMETER RulesPath
    Default lab/iga/sod-rules.json.

.PARAMETER CatalogPath
    Default lab/iga/access-catalog.json.

.PARAMETER RuleId
    Only ADD the links these rules ask for (e.g. SOD-01). Default: all.
    Whether an existing link is drift is still judged against the FULL
    ruleset, so -RuleId with -Prune never removes another rule's link.

.PARAMETER Prune
    Remove links between catalog objects that the rules do not ask for. A
    -WhatIf -Prune run shows what would go.

.PARAMETER RenderOnly
    Validate the rules and print the desired links and the detective-only
    rules. No Graph module, connection or tenant needed.

.EXAMPLE
    ./Set-IncompatibleAccessPackages.ps1 -RenderOnly
.EXAMPLE
    Connect-MgGraph -Scopes 'EntitlementManagement.ReadWrite.All','Group.Read.All'
    ./Set-IncompatibleAccessPackages.ps1 -WhatIf -Prune
    ./Set-IncompatibleAccessPackages.ps1 -Prune

.OUTPUTS
    -RenderOnly: the plan (Links, DetectiveOnly, SkippedBirthright).
    Otherwise one row per link action. Exit 1 when a lookup or write failed,
    or (outside -WhatIf) a link that gates a birthright package is left in place.

.NOTES
    TENANT-TIME: nothing here has run against Entra. Confirmed on Microsoft
    Learn 2026-10-20: POST/DELETE .../accessPackages/{id}/incompatibleAccessPackages/$ref
    and .../incompatibleGroups/$ref (EntitlementManagement.ReadWrite.All, 204);
    links are unidirectional; an incompatible package blocks requests AND new
    admin assignments; existing holders are NOT removed (hence 09-SoD-Report.ps1).
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RulesPath = (Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'sod-rules.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' '..' 'iga' 'access-catalog.json'),

    [Parameter()]
    [ValidatePattern('^SOD-\d{2}$')]
    [string[]]$RuleId = @(),

    [Parameter()]
    [switch]$Prune,

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
# PURE FUNCTIONS - unit-tested in tests/Set-IncompatibleAccessPackages.Tests.ps1
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

function Test-SodRuleSet {
    # Shared by Set-IncompatibleAccessPackages.ps1 and 09-SoD-Report.ps1
    # (parity-tested). Every reason the ruleset must not be used; empty = valid.
    param([Parameter(Mandatory)]$Rules, [Parameter(Mandatory)]$Catalog)
    $errs = [System.Collections.Generic.List[string]]::new()
    $ids = @{}
    $kinds = [ordered]@{ accessPackages = 'accessPackages'; groups = 'groups'; directoryRoles = 'directoryRoles' }
    foreach ($r in @($Rules['rules'])) {
        $id = [string]$r['id']
        if ($id -notmatch '^SOD-\d{2}$') { $errs.Add("Rule id '$id' must look like SOD-01."); continue }
        if ($ids.ContainsKey($id)) { $errs.Add("Duplicate rule id $id.") } else { $ids[$id] = 1 }
        if ([string]$r['risk'] -notin 'High', 'Medium', 'Low') { $errs.Add("$id`: risk must be High, Medium or Low.") }
        foreach ($f in 'name', 'riskStatement', 'mitigatingControlIfException') { if ([string]::IsNullOrWhiteSpace([string]$r[$f])) { $errs.Add("$id`: $f is empty.") } }
        if (@($r['regulatoryDrivers'] | Where-Object { $_ }).Count -eq 0) { $errs.Add("$id`: regulatoryDrivers is empty.") }
        $sides = @{}
        foreach ($sideName in 'sideA', 'sideB') {
            $side = $r[$sideName]
            $names = [System.Collections.Generic.List[string]]::new()
            if (-not $side) { $errs.Add("$id`: $sideName missing."); continue }
            foreach ($k in $kinds.Keys) {
                foreach ($n in @($side[$k])) {
                    if (-not $n) { continue }
                    if (-not (Get-CatalogEntry -Catalog $Catalog -Kind $k -Name $n)) { $errs.Add("$id`: $sideName.$k '$n' is not in access-catalog.json.") }
                    $names.Add("$k|$n")
                }
            }
            if ($names.Count -eq 0) { $errs.Add("$id`: $sideName names no entitlement.") }
            $sides[$sideName] = $names
        }
        if ($sides.ContainsKey('sideA') -and $sides.ContainsKey('sideB')) {
            $both = @($sides['sideA'] | Where-Object { $_ -in $sides['sideB'] })
            if ($both) { $errs.Add("$id`: '$($both -join ', ')' is on both sides.") }
        }
    }
    foreach ($x in @($Rules['exceptions'])) {
        if (-not $x) { continue }
        if ([string]$x['ruleId'] -notin $ids.Keys) { $errs.Add("Exception '$($x['exceptionId'])' names unknown rule '$($x['ruleId'])'.") }
        if (-not $x['userPrincipalName']) { $errs.Add("Exception '$($x['exceptionId'])' has no userPrincipalName.") }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$x['expires'], [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { $errs.Add("Exception '$($x['exceptionId'])' has no valid expires date.") }
    }
    return $errs.ToArray()
}

function Test-IsBirthrightPackage {
    # A package with an automatic (HR-attribute) policy: never gated (ADR 0012).
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][string]$Name)
    $e = Get-CatalogEntry -Catalog $Catalog -Kind accessPackages -Name $Name
    return [bool]($e -and [string]$e['assignment'] -match 'automatic')
}

function Get-DesiredIncompatibility {
    # Rules -> the links to write, the directions skipped because they would
    # gate a birthright package, and the rules no link can enforce.
    param([Parameter(Mandatory)]$Rules, [Parameter(Mandatory)]$Catalog, [string[]]$RuleId = @())
    $links = [ordered]@{}
    $skipped = [System.Collections.Generic.List[object]]::new()
    $detective = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Rules['rules'])) {
        $id = [string]$r['id']
        if ($RuleId.Count -and $id -notin $RuleId) { continue }
        $made = 0
        foreach ($pair in @(@($r['sideA'], $r['sideB']), @($r['sideB'], $r['sideA']))) {
            $from, $to = $pair
            foreach ($p in @($from['accessPackages'])) {
                if (-not $p) { continue }
                $targets = @(@($to['accessPackages']) | Where-Object { $_ } | ForEach-Object { @{ Kind = 'accessPackage'; Name = [string]$_ } }) +
                           @(@($to['groups']) | Where-Object { $_ } | ForEach-Object { @{ Kind = 'group'; Name = [string]$_ } })
                foreach ($t in $targets) {
                    if (Test-IsBirthrightPackage -Catalog $Catalog -Name $p) {
                        $skipped.Add([pscustomobject]@{ RuleId = $id; From = [string]$p; ToKind = $t.Kind; To = $t.Name; Reason = 'birthright package: never gated (ADR 0012); 09-SoD-Report.ps1 detects this direction' })
                        continue
                    }
                    $key = "$p|$($t.Kind)|$($t.Name)"
                    if (-not $links.Contains($key)) { $links[$key] = [pscustomobject]@{ From = [string]$p; ToKind = $t.Kind; To = $t.Name; RuleIds = [System.Collections.Generic.List[string]]::new() } }
                    if ($id -notin $links[$key].RuleIds) { $links[$key].RuleIds.Add($id) }
                    $made++
                }
            }
        }
        if ($made -eq 0) {
            $why = if (@($r['sideA']['accessPackages']) + @($r['sideB']['accessPackages']) | Where-Object { $_ }) { 'every package on the rule is birthright (automatic) - a link would gate it' } else { 'no access package on either side (roles / groups only)' }
            $detective.Add([pscustomobject]@{ RuleId = $id; Reason = $why })
        }
    }
    return [pscustomobject]@{ Links = @($links.Values); SkippedBirthright = $skipped.ToArray(); DetectiveOnly = $detective.ToArray() }
}

# =============================================================================
# SCRIPT BODY
# =============================================================================
$rules = Read-IgaJson -Path $RulesPath
$catalog = Read-IgaJson -Path $CatalogPath
$problems = @(Test-SodRuleSet -Rules $rules -Catalog $catalog)
if ($problems.Count) {
    foreach ($p in $problems) { Write-Warning "  RULE ERROR: $p" }
    throw "sod-rules.json is not valid ($($problems.Count) error(s)). Nothing was sent to Graph."
}
$unknownIds = @($RuleId | Where-Object { $_ -notin @($rules['rules'] | ForEach-Object { [string]$_['id'] }) })
if ($unknownIds) { throw "-RuleId names unknown rule(s): $($unknownIds -join ', ')" }
$plan = Get-DesiredIncompatibility -Rules $rules -Catalog $catalog -RuleId $RuleId
# What may STAY is always judged against the FULL ruleset: -RuleId narrows what
# is ADDED, never what counts as wanted. Otherwise '-RuleId SOD-02 -Prune' would
# treat Pharmacy's four SOD-01 links as unwanted and DELETE them.
$fullPlan = if ($RuleId.Count) { Get-DesiredIncompatibility -Rules $rules -Catalog $catalog } else { $plan }

Write-Console "Preventive SoD plan: $(@($plan.Links).Count) link(s)" -ForegroundColor Cyan
foreach ($l in $plan.Links) { Write-Console ("  {0}  X  {1} '{2}'   [{3}]" -f $l.From, $l.ToKind, $l.To, ($l.RuleIds -join ',')) -ForegroundColor Cyan }
foreach ($g in ($plan.SkippedBirthright | Group-Object From)) { Write-Console ("  (nothing on '{0}', {1} direction(s): {2})" -f $g.Name, $g.Count, $g.Group[0].Reason) -ForegroundColor DarkGray }
foreach ($d in $plan.DetectiveOnly) { Write-Console "  DETECTIVE-ONLY $($d.RuleId): $($d.Reason)" -ForegroundColor Yellow }
if ($RenderOnly) { return $plan }

# ---- Graph ------------------------------------------------------------------
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser), or use -RenderOnly.' }
$requiredScopes = @('EntitlementManagement.ReadWrite.All', 'Group.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }

$graph = 'https://graph.microsoft.com/v1.0'
$em = "$graph/identityGovernance/entitlementManagement"
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

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$From, [string]$Action, [string]$Detail)
    $results.Add([pscustomobject]@{ Package = $From; Action = $Action; Detail = $Detail })
    $color = switch -Wildcard ($Action) { 'failed' { 'Red' } 'drift*' { 'Red' } 'added' { 'Green' } 'removed' { 'Green' } 'in-place' { 'DarkGray' } default { 'Yellow' } }
    Write-Host ("  [{0}] {1}: {2}" -f $Action, $From, $Detail) -ForegroundColor $color
}

# Resolve every catalog package/group the rules can touch: name -> id, or a status.
$resolved = @{}   # "accessPackage|name" / "group|name" -> @{ Id; Status }
function Resolve-CatalogObject {
    param([ValidateSet('accessPackage', 'group')][string]$Kind, [string]$Name)
    $key = "$Kind|$Name"
    if ($resolved.ContainsKey($key)) { return $resolved[$key] }
    $kindKey = if ($Kind -eq 'accessPackage') { 'accessPackages' } else { 'groups' }
    $entry = Get-CatalogEntry -Catalog $catalog -Kind $kindKey -Name $Name
    $f = [uri]::EscapeDataString("displayName eq '$($Name.Replace("'", "''"))'")
    $uri = if ($Kind -eq 'accessPackage') { "$em/accessPackages?`$filter=$f&`$select=id,displayName" } else { "$graph/groups?`$filter=$f&`$select=id,displayName" }
    $hits = @(Get-GraphCollection -Uri $uri)
    $r = if ($hits.Count -eq 1) { @{ Id = [string]$hits[0]['id']; Status = 'found' } }
    elseif ($hits.Count -gt 1) { @{ Id = $null; Status = 'ambiguous' } }
    elseif ($entry -and [string]$entry['status'] -eq 'planned') { @{ Id = $null; Status = 'planned' } }
    else { @{ Id = $null; Status = 'missing' } }
    $resolved[$key] = $r
    return $r
}

$birthrightGateLeft = 0
$managedPackages = @($plan.Links | ForEach-Object { $_.From }) + @($plan.SkippedBirthright | ForEach-Object { $_.From }) | Sort-Object -Unique
foreach ($pkgName in $managedPackages) {
    try {
        $src = Resolve-CatalogObject -Kind accessPackage -Name $pkgName
        if ($src.Status -ne 'found') {
            $act = if ($src.Status -eq 'planned') { 'skipped-planned' } else { 'failed' }
            Add-Result $pkgName $act "package $($src.Status)$(if ($src.Status -eq 'missing') { ' - apply Terraform envs/dev with enable_governance = true' })"
            continue
        }
        $curPkgs = @(Get-GraphCollection -Uri "$em/accessPackages/$($src.Id)/incompatibleAccessPackages?`$select=id,displayName")
        # No $select here: Graph v1.0 answers 404 NotFound to incompatibleGroups?$select=...
        # (proven 2026-10-27 against a live tenant); the bare collection returns id + displayName anyway.
        $curGrps = @(Get-GraphCollection -Uri "$em/accessPackages/$($src.Id)/incompatibleGroups")
        $current = @($curPkgs | ForEach-Object { @{ Kind = 'accessPackage'; Id = [string]$_['id']; Name = [string]$_['displayName'] } }) +
                   @($curGrps | ForEach-Object { @{ Kind = 'group'; Id = [string]$_['id']; Name = [string]$_['displayName'] } })
        $wanted = @($plan.Links | Where-Object From -eq $pkgName)
        $wantedIds = @{}
        $wantedNames = @{}
        # Links the FULL ruleset wants on this package (other rules included) are
        # never drift. Resolve them by id; also keep their kind|name, so an
        # ambiguous or unresolvable target is left alone rather than pruned.
        foreach ($k in @($fullPlan.Links | Where-Object From -eq $pkgName)) {
            $wantedNames["$($k.ToKind)|$($k.To)"] = 1
            if (@($wanted | Where-Object { $_.ToKind -eq $k.ToKind -and $_.To -eq $k.To })) { continue }   # resolved below
            $kd = Resolve-CatalogObject -Kind $k.ToKind -Name $k.To
            if ($kd.Status -eq 'found') { $wantedIds["$($k.ToKind)|$($kd.Id)"] = 1 }
        }

        foreach ($l in $wanted) {
            $dst = Resolve-CatalogObject -Kind $l.ToKind -Name $l.To
            if ($dst.Status -ne 'found') {
                $act = if ($dst.Status -eq 'planned') { 'skipped-planned' } else { 'failed' }
                Add-Result $pkgName $act "$($l.ToKind) '$($l.To)' $($dst.Status) [$($l.RuleIds -join ',')]"
                continue
            }
            $wantedIds["$($l.ToKind)|$($dst.Id)"] = 1
            if (@($current | Where-Object { $_.Kind -eq $l.ToKind -and $_.Id -eq $dst.Id })) { Add-Result $pkgName 'in-place' "X $($l.ToKind) '$($l.To)'"; continue }
            $seg = if ($l.ToKind -eq 'accessPackage') { 'incompatibleAccessPackages' } else { 'incompatibleGroups' }
            $odataId = if ($l.ToKind -eq 'accessPackage') { "$em/accessPackages/$($dst.Id)" } else { "$graph/groups/$($dst.Id)" }
            if ($PSCmdlet.ShouldProcess("'$pkgName'", "mark incompatible with $($l.ToKind) '$($l.To)' [$($l.RuleIds -join ',')]")) {
                Invoke-MgGraphRequest -Method POST -Uri "$em/accessPackages/$($src.Id)/$seg/`$ref" -Body (@{ '@odata.id' = $odataId } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
                Add-Result $pkgName 'added' "X $($l.ToKind) '$($l.To)' [$($l.RuleIds -join ',')]"
            }
            else { Add-Result $pkgName 'would-add' "X $($l.ToKind) '$($l.To)' [$($l.RuleIds -join ',')]" }
        }

        # Links present but not wanted. Only catalog objects are ours to judge.
        foreach ($c in $current) {
            if ($wantedIds.ContainsKey("$($c.Kind)|$($c.Id)") -or $wantedNames.ContainsKey("$($c.Kind)|$($c.Name)")) { continue }
            $kindKey = if ($c.Kind -eq 'accessPackage') { 'accessPackages' } else { 'groups' }
            if (-not (Get-CatalogEntry -Catalog $catalog -Kind $kindKey -Name $c.Name)) { Add-Result $pkgName 'unmanaged' "X $($c.Kind) '$($c.Name)' (not in access-catalog.json; left alone)"; continue }
            $gatesBirthright = Test-IsBirthrightPackage -Catalog $catalog -Name $pkgName
            $what = "X $($c.Kind) '$($c.Name)'$(if ($gatesBirthright) { ' - GATES A BIRTHRIGHT PACKAGE (clinical lockout risk)' })"
            if ($Prune -and $PSCmdlet.ShouldProcess("'$pkgName'", "remove incompatibility with $($c.Kind) '$($c.Name)'")) {
                $seg = if ($c.Kind -eq 'accessPackage') { 'incompatibleAccessPackages' } else { 'incompatibleGroups' }
                Invoke-MgGraphRequest -Method DELETE -Uri "$em/accessPackages/$($src.Id)/$seg/$($c.Id)/`$ref" | Out-Null
                Add-Result $pkgName 'removed' $what
            }
            else {
                Add-Result $pkgName $(if ($Prune) { 'would-remove' } else { 'drift' }) "$what$(if (-not $Prune) { ' (re-run with -Prune)' })"
                if ($gatesBirthright -and -not $WhatIfPreference) { $birthrightGateLeft++ }
            }
        }
    }
    catch { Add-Result $pkgName 'failed' $_.Exception.Message }
}

$failed = @($results | Where-Object Action -eq 'failed')
Write-Console ("`n{0}" -f (($results | Group-Object Action | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')) -ForegroundColor $(if ($failed -or $birthrightGateLeft) { 'Red' } else { 'Green' })
foreach ($d in $plan.DetectiveOnly) { Write-Console "  $($d.RuleId) is detective-only: run 09-SoD-Report.ps1." -ForegroundColor Yellow }
Write-Console "Verify: Entra -> ID Governance -> Access packages -> <package> -> Separation of duties." -ForegroundColor Cyan
$results.ToArray()
if ($failed -or $birthrightGateLeft) { exit 1 }
