<#
.SYNOPSIS
    Access-review KPIs per ADR 0012, per risk tier and per reviewer:
    completion, revocation, rubber-stamp rate, approve-against-recommendation
    and clinical lockouts. Reads Graph access review definitions, instances
    and decisions (or an offline fixture) and writes one hashed, public-safe
    snapshot to lab/evidence/kpis/reviews-<UTC timestamp>.json.

.DESCRIPTION
    ADR 0012 "How it is measured", implemented:

      KPI                         definition (this script)                         target
      completion                  decisions made by a PERSON / items in scope       T1 100 %, T2 >= 95 %
      revocation                  Deny by a person / decisions made by a person     watched
      rubber-stamp rate           among reviewers with >= 10 items (the minimum      < 10 % of reviewers
                                  applies to BOTH clauses): those who approved
                                  all of them, OR whose median gap between
                                  consecutive decisions (same review instance)
                                  is < 5 s. Fewer than 10 items = not eligible:
                                  too few gaps for a median to mean anything.
                                  Thresholds: access-catalog.json reviewTiers.
                                  rubberStamp (also read by midpoint/
                                  run-campaign.sh, so both agree).
      approve against             Approve where recommendation = Deny /             reported; each needs
      recommendation              items recommended Deny                            a justification
      clinical lockouts           still-employed clinicians who lost birthright     0
                                  access through a review (Deny, or an applied
                                  default) or through an EXPIRY. A review counts
                                  whatever tier it was given: a T2 review of
                                  ICU's request policy that removes an in-scope
                                  ICU nurse is a lockout too (outside T3 only
                                  when the person is KNOWN to be in scope). Not
                                  counted when the person still holds the
                                  package another way (a Delivered assignment).

    WHO IS A PERSON: a decision whose reviewedBy is empty, the all-zero id
    ("not reviewed" per Graph) or a system reviewer name (-SystemReviewerNames)
    is not counted as reviewed, even when a default decision filled it in -
    otherwise "unanswered = removed" would show up as 100 % completion.

    TIERS (lab/iga/access-catalog.json reviewTiers): display-name prefix
    first ("Privileged access review:" = T1, "Inactive users review:" =
    HYGIENE), then the access package + policy in the scope query: automatic
    policy = T3, request policy = the package's request tier, a request
    policy left on a birthright-only package (today's 180-day "Nurse -
    Clinical Apps") = T3. Directory-role scopes and privileged catalog groups
    = T1. Anything else = UNCLASSIFIED (reported, never dropped). ADR 0012
    says T3 has no human campaign, so ANY T3 review is listed as a finding.

    "STILL EMPLOYED": account enabled and, for birthright packages, the
    person still matches a job profile for that package in
    lab/iga/birthright-rules.json (a mover losing the OLD department's bundle
    is the design working, not a lockout). Unknown attributes are counted as
    a lockout (conservative: the target is 0).

    PUBLIC-SAFE: reviewers appear as R01, R02 ... (most items first); no names,
    UPNs or object ids - the write is refused if one is found. The label map
    and the lockout / approve-against-recommendation rows go to the gitignored
    lab/evidence/out/kpis/. A <file>.sha256 sidecar is written (sha256sum format).

    -InputPath runs OFFLINE against lab/iga/fixtures/review-decisions.json
    (SYNTHETIC). Fixture output is stamped source = fixture and refused in the
    public lab/evidence tree; default lab/evidence/out/kpis.

    EXIT CODES: 0 measured; 1 a data source could not be read (nothing
    written, nothing reported as 0); 2 measured AND clinical lockouts > 0
    (an ADR 0012 revisit trigger).

.GRAPH SCOPES  (delegated, READ-ONLY)
    AccessReview.Read.All            definitions, instances, decisions
    EntitlementManagement.Read.All   policies (automatic or request), assignments
    User.Read.All                    accountEnabled + HR attributes of lockout candidates
    Group.Read.All                   names of groups in review scopes

.PARAMETER CatalogPath
    Default lab/iga/access-catalog.json.

.PARAMETER BirthrightRulesPath
    Default lab/iga/birthright-rules.json (birthright scope for lockouts).

.PARAMETER InputPath
    Offline fixture. Shape: lab/iga/fixtures/review-decisions.json.

.PARAMETER LookbackDays
    Instances that ended within this many days (or are still open). Default
    180 - one T2 cycle, two T1 cycles.

.PARAMETER Label
    Free text stored in the snapshot (baseline, after-tiering, ...).

.PARAMETER RubberStampMinItems
    Default from the catalog (10, ADR 0012).

.PARAMETER RubberStampMedianGapSeconds
    Default from the catalog (5, ADR 0012).

.PARAMETER SystemReviewerNames
    reviewedBy display names that mean "the service decided".

.EXAMPLE
    ./10-Review-KPIs.ps1 -InputPath ../../iga/fixtures/review-decisions.json -WhatIf
.EXAMPLE
    Connect-MgGraph -Scopes 'AccessReview.Read.All','EntitlementManagement.Read.All','User.Read.All','Group.Read.All'
    ./10-Review-KPIs.ps1 -Label first-cycle

.NOTES
    TENANT-TIME: never run against Entra; ADR 0012 says "fill this in after
    the first cycle". Confirmed on Microsoft Learn 2026-10-20: decision fields
    decision (Approve|Deny|NotReviewed|DontKnow), recommendation
    (Approve|Deny|NoInfoAvailable), reviewedBy (all-zero id = not reviewed),
    reviewedDateTime, applyResult, justification; access-package review scope
    query "/identityGovernance/entitlementManagement/accessPackageAssignments?
    $filter=(accessPackageId eq '...' and assignmentPolicyId eq '...')";
    assignmentPolicies?$expand=accessPackage with automaticRequestSettings
    present only on automatic policies (Learn's memberOf scan).
    verify: policy-attached access-package reviews are listed under
      /identityGovernance/accessReviews/definitions (ADR 0012 open item).
    verify: the reviewedBy display name the service writes when a DEFAULT
      decision is applied ("AAD Access Reviews" assumed; add others to
      -SystemReviewerNames), and whether an unanswered item that was removed
      reads decision NotReviewed + applyResult AppliedSuccessfully.
    verify: multi-stage reviews - instance-level decisions are the final ones.
    verify: expired assignments stay listable with state eq 'Expired' and an
      expiredDateTime for at least the lookback window.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'access-catalog.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BirthrightRulesPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'birthright-rules.json'),

    [Parameter()]
    [string]$InputPath = '',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$LookbackDays = 180,

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]{1,40}$', ErrorMessage = 'Label: letters, digits, . _ - only.')]
    [string]$Label = 'snapshot',

    [Parameter()]
    [string]$OutputDirectory = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DetailDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'kpis'),

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$RubberStampMinItems = 0,

    [Parameter()]
    [ValidateRange(0, 3600)]
    [double]$RubberStampMedianGapSeconds = -1,

    [Parameter()]
    [string[]]$SystemReviewerNames = @('AAD Access Reviews', 'Microsoft Entra Access Reviews')
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
# PURE FUNCTIONS - unit-tested in tests/10-Review-KPIs.Tests.ps1
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

function Test-PublicRecordSafe {
    # Same rule as Invoke-BreakGlassDrill.ps1 / New-AccessReviewDefinitions.ps1:
    # a public record must not carry an email/UPN, IP address, GUID or
    # onmicrosoft domain. Emits the offending strings; nothing = safe.
    param([string]$Json)
    $bad = @()
    foreach ($p in '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', '\b\d{1,3}(\.\d{1,3}){3}\b', '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '(?i)onmicrosoft\.com') {
        foreach ($m in [regex]::Matches($Json, $p)) { $bad += $m.Value }
    }
    return @($bad | Sort-Object -Unique)
}

function Test-IsPublicEvidencePath {
    # True when Path is inside lab/evidence but not inside the gitignored lab/evidence/out.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$EvidenceRoot)
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd($sep) + $sep
    $ev = [System.IO.Path]::GetFullPath($EvidenceRoot).TrimEnd($sep) + $sep
    $out = [System.IO.Path]::GetFullPath((Join-Path $EvidenceRoot 'out')).TrimEnd($sep) + $sep
    return $full.StartsWith($ev, [StringComparison]::OrdinalIgnoreCase) -and -not $full.StartsWith($out, [StringComparison]::OrdinalIgnoreCase)
}

function Get-Field {
    # Index-walk nested dictionaries; a missing key is $null.
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($k in $Path) {
        if ($cur -isnot [System.Collections.IDictionary] -or -not $cur.Contains($k)) { return $null }
        $cur = $cur[$k]
    }
    return $cur
}

function Get-Pct {
    param([double]$Numerator, [double]$Denominator)
    if ($Denominator -le 0) { return $null }
    return [math]::Round(100.0 * $Numerator / $Denominator, 1)
}

function Get-Median {
    param([AllowEmptyCollection()][double[]]$Values = @())
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $mid = [int][math]::Floor($v.Count / 2)
    if ($v.Count % 2) { return [double]$v[$mid] }
    return ([double]$v[$mid - 1] + [double]$v[$mid]) / 2.0
}

function Get-ScopeQuery {
    # Every Graph query string in a definition's scope (query scopes,
    # principal/resource scopes, instance enumeration scope).
    param([Parameter(Mandatory)]$Definition)
    $q = @()
    foreach ($s in @((Get-Field $Definition @('scope')), (Get-Field $Definition @('instanceEnumerationScope')))) {
        if (-not $s) { continue }
        if ($s['query']) { $q += [string]$s['query'] }
        foreach ($k in 'principalScopes', 'resourceScopes') { foreach ($x in @($s[$k])) { if ($x -and $x['query']) { $q += [string]$x['query'] } } }
    }
    return $q
}

function Get-ReviewTier {
    # Definition -> @{ Tier; Reason; Package (display name when the scope is an access package) }.
    param([Parameter(Mandatory)]$Definition, [Parameter(Mandatory)]$Catalog,
        [hashtable]$PackageById = @{}, [hashtable]$PolicyById = @{}, [hashtable]$GroupById = @{})
    $name = [string]$Definition['displayName']
    foreach ($p in @(Get-Field $Catalog @('reviewTiers', 'displayNamePrefixes'))) {
        if ($p -and $name.StartsWith([string]$p['prefix'], [StringComparison]::OrdinalIgnoreCase)) { return @{ Tier = [string]$p['tier']; Reason = "displayName prefix '$($p['prefix'])'"; Package = $null } }
    }
    $queries = @(Get-ScopeQuery -Definition $Definition)
    foreach ($q in $queries) {
        $m = [regex]::Match($q, "accessPackageId eq '(?<id>[^']+)'")
        if (-not $m.Success) { continue }
        $pkgName = if ($PackageById.ContainsKey($m.Groups['id'].Value)) { [string]$PackageById[$m.Groups['id'].Value] } else { $null }
        $entry = if ($pkgName) { Get-CatalogEntry -Catalog $Catalog -Kind accessPackages -Name $pkgName } else { $null }
        if (-not $entry) { return @{ Tier = 'UNCLASSIFIED'; Reason = 'access package not in access-catalog.json'; Package = $pkgName } }
        $pm = [regex]::Match($q, "assignmentPolicyId eq '(?<id>[^']+)'")
        $policy = if ($pm.Success -and $PolicyById.ContainsKey($pm.Groups['id'].Value)) { $PolicyById[$pm.Groups['id'].Value] } else { $null }
        if ($policy -and $policy['automatic'] -eq $true) { return @{ Tier = 'T3'; Reason = 'automatic (birthright) policy under review'; Package = $pkgName } }
        if ($entry['requestTier']) { return @{ Tier = [string]$entry['requestTier']; Reason = 'request policy on a birthright+request package'; Package = $pkgName } }
        if ([string]$entry['assignment'] -match 'request') { return @{ Tier = [string]$entry['tier']; Reason = 'request policy'; Package = $pkgName } }
        return @{ Tier = 'T3'; Reason = 'request policy left on a birthright-only package (the 180-day expiry ADR 0012 rules out)'; Package = $pkgName }
    }
    foreach ($q in $queries) {
        if ($q -match '(?i)roleDefinition') { return @{ Tier = 'T1'; Reason = 'directory role scope'; Package = $null } }
        $gm = [regex]::Match($q, '/groups/(?<id>[^/?]+)')
        if ($gm.Success) {
            $gName = if ($GroupById.ContainsKey($gm.Groups['id'].Value)) { [string]$GroupById[$gm.Groups['id'].Value] } else { '' }
            $g = if ($gName) { Get-CatalogEntry -Catalog $Catalog -Kind groups -Name $gName } else { $null }
            if ($g -and $g['privileged'] -eq $true) { return @{ Tier = 'T1'; Reason = 'privileged group scope'; Package = $null } }
        }
    }
    return @{ Tier = 'UNCLASSIFIED'; Reason = 'no tier rule matched'; Package = $null }
}

function Test-IsHumanDecision {
    # A decision a PERSON made: not NotReviewed, a real reviewer id, not a system name.
    param([Parameter(Mandatory)]$Decision, [string[]]$SystemReviewerNames = @())
    if ([string]$Decision['decision'] -in '', 'NotReviewed') { return $false }
    $id = [string](Get-Field $Decision @('reviewedBy', 'id'))
    if (-not $id -or $id -match '^[0-]+$') { return $false }
    return ([string](Get-Field $Decision @('reviewedBy', 'displayName'))) -notin $SystemReviewerNames
}

function ConvertTo-DecisionRow {
    # One Graph decision item -> the flat row every KPI is computed from.
    param([Parameter(Mandatory)]$Decision, [Parameter(Mandatory)]$TierInfo, [string]$DefinitionId, [string]$InstanceId, [string[]]$SystemReviewerNames = @())
    $when = $null
    $raw = Get-Field $Decision @('reviewedDateTime')
    if ($raw) { try { $when = ([datetime]$raw).ToUniversalTime() } catch { $when = $null } }
    # (PowerShell names are case-insensitive: never reuse $decision for the verdict.)
    $verdict = [string]$Decision['decision']; $apply = [string]$Decision['applyResult']
    $human = Test-IsHumanDecision -Decision $Decision -SystemReviewerNames $SystemReviewerNames
    return [pscustomobject]@{
        Tier           = [string]$TierInfo['Tier']
        Package        = $TierInfo['Package']
        DefinitionId   = $DefinitionId
        InstanceId     = $InstanceId
        Decision       = $verdict
        Recommendation = [string]$Decision['recommendation']
        IsHuman        = $human
        ReviewerId     = if ($human) { [string](Get-Field $Decision @('reviewedBy', 'id')) } else { '' }
        ReviewerUpn    = if ($human) { [string](Get-Field $Decision @('reviewedBy', 'userPrincipalName')) } else { '' }
        ReviewedAt     = $when
        HasJustification = -not [string]::IsNullOrWhiteSpace([string]$Decision['justification'])
        ApplyResult    = $apply
        # A removal: any Deny (a person's or an applied default), or an
        # unanswered item whose (default) outcome was applied.
        Removed        = ($verdict -eq 'Deny') -or ($verdict -eq 'NotReviewed' -and $apply -eq 'AppliedSuccessfully')
        PrincipalId    = [string](Get-Field $Decision @('principal', 'id'))
    }
}

function Get-KpiValue {
    param($Value, [string]$Unit = '%', $Numerator = $null, $Denominator = $null)
    $o = [ordered]@{ status = if ($null -eq $Value) { 'not-measured' } else { 'measured' }; value = $Value; unit = $Unit }
    if ($null -ne $Numerator) { $o['numerator'] = $Numerator }
    if ($null -ne $Denominator) { $o['denominator'] = $Denominator }
    return $o
}

function Measure-TierKpi {
    # Completion / revocation / approve-against-recommendation for one tier's rows.
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $all = @($Rows | Where-Object { $_ })
    $human = @($all | Where-Object IsHuman)
    $denied = @($human | Where-Object Decision -eq 'Deny')
    $recDeny = @($all | Where-Object Recommendation -eq 'Deny')
    $against = @($human | Where-Object { $_.Decision -eq 'Approve' -and $_.Recommendation -eq 'Deny' })
    return [ordered]@{
        items                         = $all.Count
        reviewedByPerson              = $human.Count
        notReviewed                   = @($all | Where-Object Decision -eq 'NotReviewed').Count
        decidedBySystem               = @($all | Where-Object { -not $_.IsHuman -and $_.Decision -ne 'NotReviewed' }).Count
        dontKnow                      = @($human | Where-Object Decision -eq 'DontKnow').Count
        completion                    = Get-KpiValue (Get-Pct $human.Count $all.Count) '%' $human.Count $all.Count
        revocation                    = Get-KpiValue (Get-Pct $denied.Count $human.Count) '%' $denied.Count $human.Count
        approveAgainstRecommendation  = Get-KpiValue (Get-Pct $against.Count $recDeny.Count) '%' $against.Count $recDeny.Count
        approveAgainstRecommendationWithoutJustification = @($against | Where-Object { -not $_.HasJustification }).Count
    }
}

function Get-ReviewerGapSecond {
    # Seconds between a reviewer's consecutive decisions, WITHIN each review
    # instance (a gap across instances is weeks, not a signal).
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $gaps = [System.Collections.Generic.List[double]]::new()
    foreach ($g in (@($Rows | Where-Object { $_ -and $_.ReviewedAt }) | Group-Object InstanceId)) {
        $t = @($g.Group | Sort-Object ReviewedAt | ForEach-Object { $_.ReviewedAt })
        for ($i = 1; $i -lt $t.Count; $i++) { $gaps.Add([math]::Max(0, ($t[$i] - $t[$i - 1]).TotalSeconds)) }
    }
    return $gaps.ToArray()
}

function Measure-ReviewerKpi {
    # Per reviewer (people only): volume, approvals, revocation, median gap, rubber-stamp flags.
    param([AllowEmptyCollection()][object[]]$Rows = @(), [int]$MinItems = 10, [double]$GapSeconds = 5)
    $out = foreach ($g in (@($Rows | Where-Object { $_ -and $_.IsHuman }) | Group-Object ReviewerId)) {
        $items = @($g.Group)
        $approved = @($items | Where-Object Decision -eq 'Approve').Count
        $denied = @($items | Where-Object Decision -eq 'Deny').Count
        $median = Get-Median -Values (Get-ReviewerGapSecond -Rows $items)
        $eligible = $items.Count -ge $MinItems
        $approvedAll = $eligible -and $approved -eq $items.Count
        $fast = $eligible -and $null -ne $median -and $median -lt $GapSeconds
        [pscustomobject]@{
            ReviewerId       = $g.Name
            ReviewerUpn      = [string]$items[0].ReviewerUpn
            Tiers            = @($items | ForEach-Object { $_.Tier } | Sort-Object -Unique)
            Items            = $items.Count
            Approved         = $approved
            Denied           = $denied
            ApprovalPct      = Get-Pct $approved $items.Count
            RevocationPct    = Get-Pct $denied $items.Count
            MedianGapSeconds = if ($null -eq $median) { $null } else { [math]::Round($median, 1) }
            Eligible         = $eligible
            ApprovedAll      = $approvedAll
            FastMedian       = $fast
            RubberStamp      = $approvedAll -or $fast
        }
    }
    return @($out | Sort-Object @{ Expression = 'Items'; Descending = $true }, ReviewerId)
}

function Measure-RubberStamp {
    param([AllowEmptyCollection()][object[]]$Reviewers = @())
    $eligible = @($Reviewers | Where-Object { $_ -and $_.Eligible })
    $flagged = @($eligible | Where-Object RubberStamp)
    return Get-KpiValue (Get-Pct $flagged.Count $eligible.Count) '% of reviewers' $flagged.Count $eligible.Count
}

function Test-InBirthrightScope {
    # Does the user still match a job profile that grants Package? $null = unknown.
    param([Parameter(Mandatory)]$User, [Parameter(Mandatory)][string]$Package, [Parameter(Mandatory)]$BirthrightRules)
    $s = $BirthrightRules['settings']; $mode = [string]$s['matchOn']
    $dept = [string]$User['department']
    $val = if ($mode -eq 'jobTitle') { [string]$User['jobTitle'] } else {
        $attr = ([string]$s['attributes']['jobCode']) -replace '^user\.', ''
        if ($attr -match '^extensionAttribute\d+$') { [string](Get-Field $User @('onPremisesExtensionAttributes', $attr)) } else { [string]$User[$attr] }
    }
    if (-not $dept -or -not $val) { return $null }
    foreach ($p in @($BirthrightRules['jobProfiles'])) {
        if ($Package -in @($p['birthright']) -and [string]$p['department'] -eq $dept -and [string]$p[$mode] -eq $val) { return $true }
    }
    return $false
}

function Test-HasBirthrightProfile {
    # Is Package granted by any job profile in birthright-rules.json?
    param([string]$Package, [Parameter(Mandatory)]$BirthrightRules)
    if (-not $Package) { return $false }
    foreach ($p in @($BirthrightRules['jobProfiles'])) { if ($p -and $Package -in @($p['birthright'])) { return $true } }
    return $false
}

function Test-IsLockoutCandidateRow {
    # A removal that may be a lockout: any T3 removal, or a removal (any tier)
    # of a package some job profile grants as birthright.
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)]$BirthrightRules)
    if (-not $Row -or -not $Row.Removed) { return $false }
    return ($Row.Tier -eq 'T3') -or (Test-HasBirthrightProfile -Package $Row.Package -BirthrightRules $BirthrightRules)
}

function Measure-ClinicalLockout {
    # Still-employed clinicians who lost birthright access by review or by expiry.
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Users = @{}, [AllowEmptyCollection()][object[]]$ExpiredAssignments = @(),
        [hashtable]$DeliveredKeys = @{}, [Parameter(Mandatory)]$BirthrightRules, [Parameter(Mandatory)][datetime]$Since)
    $items = [System.Collections.Generic.List[object]]::new()
    $judge = {
        param([string]$UserId, [string]$Package, [hashtable]$UserIndex, $Profiles)
        $u = if ($UserId -and $UserIndex.ContainsKey($UserId)) { $UserIndex[$UserId] } else { $null }
        if ($u -and $u['accountEnabled'] -eq $false) { return $null }                         # left: not a lockout
        $scope = if ($u -and $Package) { Test-InBirthrightScope -User $u -Package $Package -BirthrightRules $Profiles } else { $null }
        if ($scope -eq $false) { return $null }                                               # moved out of scope: the design working
        return $(if ($null -eq $scope) { 'scope-unknown' } else { 'in-scope' })
    }
    foreach ($r in @($Rows | Where-Object { Test-IsLockoutCandidateRow -Row $_ -BirthrightRules $BirthrightRules })) {
        if ($r.Package -and $DeliveredKeys.ContainsKey("$($r.PrincipalId)|$($r.Package)")) { continue }   # still holds it another way
        $why = & $judge $r.PrincipalId $r.Package $Users $BirthrightRules
        # Outside T3 (e.g. a T2 review of ICU's request policy) most holders are
        # float / agency staff the birthright rule never covered: count only a
        # person KNOWN to be in birthright scope. T3 keeps the conservative
        # unknown = lockout.
        if ($why -eq 'scope-unknown' -and $r.Tier -ne 'T3') { continue }
        if ($why) { $items.Add([pscustomobject]@{ Cause = 'review'; UserId = $r.PrincipalId; Package = $r.Package; Basis = $why; Decision = $r.Decision; ByPerson = $r.IsHuman }) }
    }
    foreach ($a in @($ExpiredAssignments | Where-Object { $_ })) {
        $when = if ($a['expiredDateTime']) { ([datetime]$a['expiredDateTime']).ToUniversalTime() } else { $null }
        if (-not $when -or $when -lt $Since) { continue }
        if ($DeliveredKeys.ContainsKey("$($a['targetId'])|$($a['package'])")) { continue }      # still holds it another way
        $why = & $judge ([string]$a['targetId']) ([string]$a['package']) $Users $BirthrightRules
        if ($why) { $items.Add([pscustomobject]@{ Cause = 'expiry'; UserId = [string]$a['targetId']; Package = [string]$a['package']; Basis = $why; Decision = 'Expired'; ByPerson = $false }) }
    }
    return [pscustomobject]@{
        ByReview = @($items | Where-Object Cause -eq 'review').Count
        ByExpiry = @($items | Where-Object Cause -eq 'expiry').Count
        Items    = $items.ToArray()
    }
}

# =============================================================================
# SCRIPT BODY
# =============================================================================
$catalog = Read-IgaJson -Path $CatalogPath
$birthright = Read-IgaJson -Path $BirthrightRulesPath
$rs = Get-Field $catalog @('reviewTiers', 'rubberStamp')
$minItems = if ($RubberStampMinItems -gt 0) { $RubberStampMinItems } elseif ($rs -and $rs['minItems']) { [int]$rs['minItems'] } else { 10 }
$gapSec = if ($RubberStampMedianGapSeconds -ge 0) { $RubberStampMedianGapSeconds } elseif ($rs -and $null -ne $rs['medianGapSeconds']) { [double]$rs['medianGapSeconds'] } else { 5 }
$evidenceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'evidence'))
$isFixture = [bool]$InputPath
if (-not $OutputDirectory) { $OutputDirectory = if ($isFixture) { Join-Path $evidenceRoot 'out' 'kpis' } else { Join-Path $evidenceRoot 'kpis' } }
if ($isFixture -and (Test-IsPublicEvidencePath -Path $OutputDirectory -EvidenceRoot $evidenceRoot)) {
    throw "Refusing to write a fixture (synthetic) KPI snapshot into the public evidence tree ($OutputDirectory). Use the default lab/evidence/out/kpis."
}
if (Test-IsPublicEvidencePath -Path $DetailDirectory -EvidenceRoot $evidenceRoot) { throw "-DetailDirectory '$DetailDirectory' is inside the public evidence tree; detail must go to lab/evidence/out/." }

$packageById = @{}; $policyById = @{}; $groupById = @{}; $users = @{}
$definitions = @(); $assignments = @(); $sources = [System.Collections.Generic.List[object]]::new()
if ($isFixture) {
    $fx = Read-IgaJson -Path $InputPath
    $now = if ($fx['asOf']) { ([datetime]$fx['asOf']).ToUniversalTime() } else { (Get-Date).ToUniversalTime() }
    foreach ($p in @($fx['accessPackages'])) { if ($p) { $packageById[[string]$p['id']] = [string]$p['displayName'] } }
    foreach ($p in @($fx['assignmentPolicies'])) { if ($p) { $policyById[[string]$p['id']] = @{ accessPackageId = [string]$p['accessPackageId']; automatic = [bool]$p['automatic'] } } }
    foreach ($g in @($fx['groups'])) { if ($g) { $groupById[[string]$g['id']] = [string]$g['displayName'] } }
    foreach ($u in @($fx['users'])) { if ($u) { $users[[string]$u['id']] = $u } }
    $definitions = @($fx['definitions'] | Where-Object { $_ })
    $assignments = @(@($fx['assignments']) | Where-Object { $_ } | ForEach-Object {
            @{ targetId = [string]$_['targetId']; package = [string]$packageById[[string]$_['accessPackageId']]; state = [string]$_['state']; expiredDateTime = $_['expiredDateTime'] } })
    $sources.Add(@{ name = 'fixture'; status = 'ok' })
    Write-Console "Review KPIs - OFFLINE against $(Split-Path -Leaf $InputPath) (synthetic fixture, not tenant data)" -ForegroundColor Yellow
}
else {
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required for a tenant run (or use -InputPath).' }
    $requiredScopes = @('AccessReview.Read.All', 'EntitlementManagement.Read.All', 'User.Read.All', 'Group.Read.All')
    $ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
    if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Sources needing them FAIL (exit 1), never read as 0." }
    $now = (Get-Date).ToUniversalTime()
    Write-Console 'Review KPIs - tenant' -ForegroundColor Cyan
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
    $since0 = $now.AddDays(-$LookbackDays)
    try {
        foreach ($p in (Get-GraphCollection -Uri "$em/assignmentPolicies?`$expand=accessPackage&`$top=50")) {
            $ap = $p['accessPackage']
            if ($ap) { $packageById[[string]$ap['id']] = [string]$ap['displayName'] }
            $policyById[[string]$p['id']] = @{ accessPackageId = if ($ap) { [string]$ap['id'] } else { '' }; automatic = [bool]$p['automaticRequestSettings'] }
        }
        $sources.Add(@{ name = 'assignmentPolicies'; status = 'ok' })
    }
    catch { $sources.Add(@{ name = 'assignmentPolicies'; status = 'FAILED'; detail = $_.Exception.Message }) }
    try {
        $defs = [System.Collections.Generic.List[object]]::new()
        foreach ($d in (Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions")) {
            $insts = foreach ($i in (Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions/$($d['id'])/instances")) {
                $end = Get-Field $i @('endDateTime')
                if ($end -and ([datetime]$end).ToUniversalTime() -lt $since0 -and [string]$i['status'] -ne 'InProgress') { continue }
                $i['decisions'] = @(Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions/$($d['id'])/instances/$($i['id'])/decisions")
                $i
            }
            $d['instances'] = @($insts)
            foreach ($q in (Get-ScopeQuery -Definition $d)) {
                $gm = [regex]::Match($q, '/groups/(?<id>[^/?]+)')
                if ($gm.Success -and -not $groupById.ContainsKey($gm.Groups['id'].Value)) {
                    # A group deleted since the review ran only costs its tier (UNCLASSIFIED), not the whole run.
                    try { $groupById[$gm.Groups['id'].Value] = [string](Invoke-MgGraphRequest -Method GET -Uri "$graph/groups/$($gm.Groups['id'].Value)?`$select=id,displayName" -OutputType HashTable)['displayName'] }
                    catch { Write-Verbose "group name lookup failed: $($_.Exception.Message)"; $groupById[$gm.Groups['id'].Value] = '' }
                }
            }
            $defs.Add($d)
        }
        $definitions = $defs.ToArray()
        $sources.Add(@{ name = 'accessReviews'; status = 'ok' })
    }
    catch { $sources.Add(@{ name = 'accessReviews'; status = 'FAILED'; detail = $_.Exception.Message }) }
    try {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($e in @($catalog['accessPackages'] | Where-Object { $_ -and [string]$_['tier'] -eq 'T3' })) {
            $ids = @($packageById.Keys | Where-Object { $packageById[$_] -eq [string]$e['name'] })
            foreach ($pkgId in $ids) {
                foreach ($state in 'Expired', 'Delivered') {
                    $f = [uri]::EscapeDataString("accessPackage/id eq '$pkgId' and state eq '$state'")
                    foreach ($a in (Get-GraphCollection -Uri "$em/assignments?`$filter=$f&`$expand=target")) {
                        $list.Add(@{ targetId = [string](Get-Field $a @('target', 'objectId')); package = [string]$e['name']; state = $state; expiredDateTime = $a['expiredDateTime'] })
                    }
                }
            }
        }
        $assignments = $list.ToArray()
        $sources.Add(@{ name = 'birthrightAssignments'; status = 'ok' })
    }
    catch { $sources.Add(@{ name = 'birthrightAssignments'; status = 'FAILED'; detail = $_.Exception.Message }) }
}

$failedSources = @($sources | Where-Object { $_['status'] -ne 'ok' })
if ($failedSources.Count) {
    foreach ($s in $failedSources) { Write-Console "  [FAILED] $($s['name']): $($s['detail'])" -ForegroundColor Red }
    Write-Console 'A data source could not be read: nothing written, no KPI reported as 0 (exit 1).' -ForegroundColor Red
    exit 1
}

# ---- flatten + classify -----------------------------------------------------
$since = $now.AddDays(-$LookbackDays)
$rows = [System.Collections.Generic.List[object]]::new()
$defSummary = [System.Collections.Generic.List[object]]::new()
foreach ($d in $definitions) {
    $tier = Get-ReviewTier -Definition $d -Catalog $catalog -PackageById $packageById -PolicyById $policyById -GroupById $groupById
    $n = 0
    foreach ($i in @($d['instances'])) {
        if (-not $i) { continue }
        $end = Get-Field $i @('endDateTime')
        if ($end -and ([datetime]$end).ToUniversalTime() -lt $since -and [string]$i['status'] -ne 'InProgress') { continue }
        foreach ($dec in @($i['decisions'])) {
            if (-not $dec) { continue }
            $rows.Add((ConvertTo-DecisionRow -Decision $dec -TierInfo $tier -DefinitionId ([string]$d['id']) -InstanceId ([string]$i['id']) -SystemReviewerNames $SystemReviewerNames)); $n++
        }
    }
    $defSummary.Add([pscustomobject]@{ Tier = $tier['Tier']; Reason = $tier['Reason']; Decisions = $n; DisplayName = [string]$d['displayName'] })
}
$allRows = $rows.ToArray()

# Tenant mode: HR attributes + state of lockout candidates only.
$expired = @($assignments | Where-Object { [string]$_['state'] -eq 'Expired' })
$delivered = @{}; foreach ($a in @($assignments | Where-Object { [string]$_['state'] -eq 'Delivered' })) { $delivered["$($a['targetId'])|$($a['package'])"] = $true }
if (-not $isFixture) {
    $candidates = @(@($allRows | Where-Object { Test-IsLockoutCandidateRow -Row $_ -BirthrightRules $birthright } | ForEach-Object { $_.PrincipalId }) + @($expired | ForEach-Object { [string]$_['targetId'] }) | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($uid in $candidates) {
        try { $users[$uid] = Invoke-MgGraphRequest -Method GET -Uri "$graph/users/$uid`?`$select=id,accountEnabled,department,jobTitle,onPremisesExtensionAttributes" -OutputType HashTable }
        catch { Write-Verbose "user lookup failed (counted as scope-unknown): $($_.Exception.Message)" }
    }
}

# ---- measure ------------------------------------------------------------------
$tiersOut = [ordered]@{}
$targets = Get-Field $catalog @('reviewTiers', 'targets')
foreach ($t in 'T1', 'T2', 'T3', 'HYGIENE', 'UNCLASSIFIED') {
    $tr = @($allRows | Where-Object Tier -eq $t)
    $k = Measure-TierKpi -Rows $tr
    $rev = @(Measure-ReviewerKpi -Rows $tr -MinItems $minItems -GapSeconds $gapSec)
    $k['rubberStamp'] = Measure-RubberStamp -Reviewers $rev
    $k['definitions'] = @($defSummary | Where-Object Tier -eq $t).Count
    $target = if ($targets -and $targets.Contains($t)) { $targets[$t]['completionPct'] } else { $null }
    $k['completionTargetPct'] = $target
    $k['completionTargetMet'] = if ($null -eq $target -or $k['completion']['status'] -ne 'measured') { $null } else { [double]$k['completion']['value'] -ge [double]$target }
    $tiersOut[$t] = $k
}
$reviewers = @(Measure-ReviewerKpi -Rows $allRows -MinItems $minItems -GapSeconds $gapSec)
$labels = [ordered]@{}; $i = 0
foreach ($r in $reviewers) { $i++; $labels[$r.ReviewerId] = 'R{0:D2}' -f $i }
$overall = Measure-TierKpi -Rows $allRows
$rubber = Measure-RubberStamp -Reviewers $reviewers
$lock = Measure-ClinicalLockout -Rows $allRows -Users $users -ExpiredAssignments $expired -DeliveredKeys $delivered -BirthrightRules $birthright -Since $since
$lockTotal = $lock.ByReview + $lock.ByExpiry

$findings = [System.Collections.Generic.List[string]]::new()
foreach ($t in 'T1', 'T2') { if ($tiersOut[$t]['completionTargetMet'] -eq $false) { $findings.Add("$t completion $($tiersOut[$t]['completion']['value']) % is below the $($tiersOut[$t]['completionTargetPct']) % target.") } }
if ($tiersOut['T3']['definitions']) { $findings.Add("$($tiersOut['T3']['definitions']) review definition(s) cover T3 birthright access; ADR 0012 says T3 has no human campaign.") }
if ($rubber['status'] -eq 'measured' -and [double]$rubber['value'] -ge 10) { $findings.Add("Rubber-stamp rate $($rubber['value']) % of eligible reviewers ($($rubber['numerator'])/$($rubber['denominator'])) is at or above the 10 % ceiling.") }
if ($overall['approveAgainstRecommendationWithoutJustification']) { $findings.Add("$($overall['approveAgainstRecommendationWithoutJustification']) approval(s) against a Deny recommendation carry no justification.") }
if ($lockTotal) { $findings.Add("$lockTotal clinical lockout(s) caused by governance (review $($lock.ByReview), expiry $($lock.ByExpiry)); target 0 - ADR 0012 revisit trigger.") }
if ($tiersOut['UNCLASSIFIED']['definitions']) { $findings.Add("$($tiersOut['UNCLASSIFIED']['definitions']) review definition(s) match no tier rule (access-catalog.json reviewTiers).") }

$snapshot = [ordered]@{
    schema           = 'contoso-iga/review-kpis/v1'
    label            = $Label
    generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
    measuredAsOf     = $now.ToString('o')
    source           = if ($isFixture) { 'fixture' } else { 'tenant' }
    inputFile        = if ($isFixture) { Split-Path -Leaf $InputPath } else { $null }
    status           = if ($allRows.Count) { 'measured' } else { 'not-measured' }
    parameters       = [ordered]@{ lookbackDays = $LookbackDays; rubberStampMinItems = $minItems; rubberStampMedianGapSeconds = $gapSec; systemReviewerNames = $SystemReviewerNames }
    coverage         = [ordered]@{ definitions = @($definitions).Count; decisions = $allRows.Count; byTier = [ordered]@{} }
    overall          = $overall
    tiers            = $tiersOut
    rubberStamp      = [ordered]@{ kpi = $rubber; targetReviewerPctBelow = 10; minItems = $minItems; medianGapSeconds = $gapSec }
    reviewers        = @($reviewers | ForEach-Object { [ordered]@{
                label = $labels[$_.ReviewerId]; tiers = $_.Tiers; items = $_.Items; approvalPct = $_.ApprovalPct; revocationPct = $_.RevocationPct
                medianGapSeconds = $_.MedianGapSeconds; eligible = $_.Eligible; approvedAll = $_.ApprovedAll; fastMedian = $_.FastMedian; rubberStamp = $_.RubberStamp } })
    clinicalLockouts = [ordered]@{ byReview = $lock.ByReview; byExpiry = $lock.ByExpiry; total = $lockTotal; target = 0; targetMet = ($lockTotal -eq 0); scopeUnknown = @($lock.Items | Where-Object Basis -eq 'scope-unknown').Count }
    findings         = $findings.ToArray()
}
foreach ($t in $tiersOut.Keys) { $snapshot['coverage']['byTier'][$t] = $tiersOut[$t]['definitions'] }

Write-Console ("  {0,-13} {1,6} {2,11} {3,11} {4,12}" -f 'tier', 'items', 'completion', 'revocation', 'rubberStamp') -ForegroundColor Cyan
foreach ($t in $tiersOut.Keys) {
    $k = $tiersOut[$t]; if (-not $k['items']) { continue }
    $fmtPct = { param($v) if ($null -eq $v) { 'n/a' } else { "$v%" } }
    Write-Console ("  {0,-13} {1,6} {2,11} {3,11} {4,12}" -f $t, $k['items'], (& $fmtPct $k['completion']['value']), (& $fmtPct $k['revocation']['value']), (& $fmtPct $k['rubberStamp']['value']))
}
Write-Console ("  clinical lockouts: {0} (review {1}, expiry {2}); target 0" -f $lockTotal, $lock.ByReview, $lock.ByExpiry) -ForegroundColor $(if ($lockTotal) { 'Red' } else { 'Green' })
foreach ($f in $findings) { Write-Console "  FINDING: $f" -ForegroundColor Yellow }

$json = $snapshot | ConvertTo-Json -Depth 12
$unsafe = @(Test-PublicRecordSafe -Json $json)
if ($unsafe.Count) { throw "Public KPI snapshot would contain identifiers ($($unsafe -join ', ')); nothing written." }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$file = Join-Path ([System.IO.Path]::GetFullPath($OutputDirectory)) "reviews-$stamp.json"
if ($PSCmdlet.ShouldProcess($file, 'write review KPI snapshot (+ .sha256) and reviewer detail')) {
    foreach ($dir in $OutputDirectory, $DetailDirectory) { if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } }
    $json | Set-Content -LiteralPath $file -Encoding utf8NoBOM
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  reviews-$stamp.json" | Set-Content -LiteralPath "$file.sha256" -Encoding utf8NoBOM
    [ordered]@{
        generatedAtUtc = $snapshot['generatedAtUtc']; snapshot = "reviews-$stamp.json"; source = $snapshot['source']
        reviewers      = @($reviewers | ForEach-Object { [ordered]@{ label = $labels[$_.ReviewerId]; reviewerId = $_.ReviewerId; userPrincipalName = $_.ReviewerUpn } })
        lockouts       = @($lock.Items)
        approvedAgainstRecommendation = @($allRows | Where-Object { $_.IsHuman -and $_.Decision -eq 'Approve' -and $_.Recommendation -eq 'Deny' } | Select-Object Tier, Package, DefinitionId, InstanceId, ReviewerId, PrincipalId, HasJustification)
        definitions    = @($defSummary)
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $DetailDirectory "reviews-$stamp-detail.json") -Encoding utf8NoBOM
    Write-Console "`nSnapshot: $file (sha256 $hash)" -ForegroundColor Cyan
}

[pscustomobject]$snapshot
if ($lockTotal) { exit 2 }
exit 0
