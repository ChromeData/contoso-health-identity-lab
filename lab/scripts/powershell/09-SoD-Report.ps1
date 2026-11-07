<#
.SYNOPSIS
    DETECTIVE separation of duties: evaluates who ALREADY holds both sides of
    a rule in lab/iga/sod-rules.json - access package assignments, group
    membership (transitive, plus PIM-for-Groups eligibility) and directory
    roles (active and PIM-eligible) - and writes a hashed CSV + JSON report.
    Exit code = number of open violations.

.DESCRIPTION
    Preventive SoD (post-apply/Set-IncompatibleAccessPackages.ps1) only stops
    NEW requests and admin assignments; Microsoft Learn is explicit that it
    never removes access someone already holds. This is the other half: a
    point-in-time report of existing conflicts, including the directions the
    preventive script deliberately leaves open (a birthright package is never
    gated - ADR 0012) and rules made only of roles and PIM groups (SOD-08).

    HOLDING A SIDE (sod-rules.json holdingSemantics)
      access package  a delivered assignment
      group           direct or transitive member; for a PIM-for-Groups group
                      also an ELIGIBLE member (they can activate it)
      directory role  active (permanent or activated) or PIM-eligible, held
                      directly or through a role-assignable group
    A violation reached only through eligibility is still a violation (the
    person can activate it alone); it is flagged activationRequired.

    REVIEWER OF RECORD (a rule side with "reviewerOfRecord": true; SOD-08)
      ADR 0012 makes the requestor's MANAGER the T2 reviewer. So a side-A
      holder (identity administration) who manages someone holding T2
      (request-policy) access certifies access they can also grant - held as
      reviewerOfRecord:T2-direct-report[manager]. T2 = catalog tier 'T2'
      packages; the T2 request path of an automatic+request package (ICU) is
      not told apart from its birthright policy in v1, so it is not counted.
      Tenant: GET /users/{id}/directReports for side-A holders only.
      Fixture: users[].managerId.

    RULE STATUS - never "clean" by omission
      evaluated       every entitlement on the rule exists
      partial         both sides have at least one entitlement that exists
      not-evaluable   a side has none (planned objects): reported, and no
                      claim is made about that rule

    EXCEPTIONS: an unexpired entry in sod-rules.json "exceptions"
    (standards/exception-process.md) marks the violation 'excepted' - listed,
    not counted in the exit code. Expired = 'exception-expired' = counted.

    OUTPUT (only when the script actually runs - nothing is pre-created)
      <OutputDirectory>/<UTC timestamp>/
        sod-report.json      summary, rule statuses, violations
        sod-violations.csv   one row per (rule, person)
        manifest.sha256      sha256sum format: `shasum -a 256 -c manifest.sha256`
      Public files carry a pseudonym per person (U- + 12 hex of SHA-256 of the
      object id), never a name, UPN or object id; the write is refused if any
      such string is found. The name <-> pseudonym map goes to the gitignored
      <DetailDirectory>/<timestamp>/sod-detail.json.

    -InputPath runs OFFLINE against a JSON inventory (lab/iga/fixtures/
    sod-tenant.json is synthetic). Its output is stamped source = fixture and
    is REFUSED in the public lab/evidence tree - synthetic data never sits
    next to tenant evidence. Default for fixture runs: lab/evidence/out/sod.

    EXIT CODES
      0..254  number of open violations (capped at 254)
      255     no valid report: a data source could not be read, the input was
              invalid or refused (bad ruleset, public-tree refusal, identifier
              refusal), or the run failed (Graph module missing, sign-in
              failed). Nothing is reported as clean. A caller must never read
              255 as "255 violations" or a crash as "1 violation".

.PREREQUISITES
    Tenant mode: Entra ID Governance (packages), P2 (PIM). Read-only roles are
    enough: Global Reader (+ Identity Governance reader rights).

.GRAPH SCOPES  (delegated, READ-ONLY)
    EntitlementManagement.Read.All                   packages + assignments
    GroupMember.Read.All, User.Read.All              memberships, user state, directReports
    RoleManagement.Read.Directory                    role assignment/eligibility instances
    PrivilegedEligibilitySchedule.Read.AzureADGroup  PIM-for-Groups eligibility

.PARAMETER RulesPath
    Default lab/iga/sod-rules.json.

.PARAMETER CatalogPath
    Default lab/iga/access-catalog.json.

.PARAMETER InputPath
    Offline inventory (fixture). See lab/iga/fixtures/sod-tenant.json for the shape.

.PARAMETER OutputDirectory
    Public report folder. Default lab/evidence/sod (tenant) or
    lab/evidence/out/sod (-InputPath).

.PARAMETER DetailDirectory
    Gitignored identity detail. Default lab/evidence/out/sod. Refused if it is
    inside the public evidence tree.

.PARAMETER AsOf
    Date exceptions are judged against. Default: now (tenant) or the
    fixture's asOf.

.PARAMETER HoldingsSnapshotPath
    Also write the HOLDINGS SNAPSHOT the detective tripwires read for access
    granted before their 14-day AuditLogs window: one CSV row per user and
    access package / group held, columns
      UserObjectId,UserPrincipalName,Kind,Name,SnapshotTime
    (Kind AccessPackage | Group, SnapshotTime yyyy-MM-ddTHH:mm:ss UTC - the
    names lab/kql/sod-violation-granted.kql and its SPL twin read). It holds
    object ids and UPNs, so it is refused inside the public evidence tree;
    default '' = not written. TENANT-TIME, by hand: upload it as Sentinel
    watchlist "sod_holdings" (SearchKey UserObjectId), and copy it to
    lab/splunk/app/contoso_identity/lookups/contoso_sod_holdings.csv
    (gitignored) for the Splunk twin.

.PARAMETER UseAzureCliToken
    App-only sign-in: take a Microsoft Graph token from the Azure CLI session
    (`az account get-access-token --resource-type ms-graph`) and connect
    with it, always that identity, never a leftover context. For the lab
    operator: `lab/scripts/operator/op pwsh ./<this script> -UseAzureCliToken`
    (its own az profile, certificate sign-in). The token stays in this
    process: never in argv, a file or the output (masked in GitHub Actions).

.EXAMPLE
    ./09-SoD-Report.ps1 -InputPath ../../iga/fixtures/sod-tenant.json -WhatIf
.EXAMPLE
    Connect-MgGraph -Scopes 'EntitlementManagement.Read.All','GroupMember.Read.All','User.Read.All','RoleManagement.Read.Directory','PrivilegedEligibilitySchedule.Read.AzureADGroup'
    ./09-SoD-Report.ps1; "open violations: $LASTEXITCODE"

.NOTES
    TENANT-TIME: never run against Entra. Confirmed on Microsoft Learn
    2026-10-20: assignments filter "accessPackage/id eq '<id>' and state eq
    'Delivered'" with $expand=target (Learn's own SoD script); incompatibility
    does not remove existing access; role/eligibility schedule instances with
    $expand=principal (also used by 08-Measure-KPIs.ps1).
    verify: accessPackageSubject.principalName is the UPN for member users.
    verify: a role assigned to a role-assignable group appears once, with the
      group as principal (members are expanded here, active and PIM-eligible).
    verify: transitiveMembers of a PIM-for-Groups group lists ACTIVATED
      members only (eligible ones are read separately and labelled).
    verify: GET /users/{id}/directReports is readable with User.Read.All
      (reviewer-of-record check).
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RulesPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'sod-rules.json'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..' '..' 'iga' 'access-catalog.json'),

    [Parameter()]
    [string]$InputPath = '',

    [Parameter()]
    [string]$OutputDirectory = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DetailDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'sod'),

    [Parameter()]
    [Nullable[datetime]]$AsOf = $null,

    [Parameter()]
    [string]$HoldingsSnapshotPath = '',

    # App-only sign-in from the Azure CLI session (the lab operator via
    # lab/scripts/operator/op, or azure/login over OIDC).
    [Parameter()]
    [switch]$UseAzureCliToken
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

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

function Get-MissingGraphScope {
    # Required Graph permissions the current context does not cover, for the
    # "does not list" warning. An app-only identity (-UseAzureCliToken, e.g.
    # the lab operator) often holds the ReadWrite role, not the Read one a
    # delegated admin consents to. Microsoft Learn's permission tables list
    # X.ReadWrite.Y as a higher-privileged permission wherever X.Read.Y is the
    # least privileged one, and Directory.Read.All for the user, group,
    # membership and application reads (checked 2026-11-05 on "List
    # applications" and "List group transitive members"). Empty -Have
    # (unknown context) = no warning. Identical in 06-NHI-Inventory.ps1,
    # 08-Measure-KPIs.ps1, 09-SoD-Report.ps1 and Invoke-BreakGlassDrill.ps1
    # (parity test in tests/EvidencePackPipeline.Tests.ps1).
    param([AllowEmptyCollection()][string[]]$Have = @(), [Parameter(Mandatory)][string[]]$Required)
    if (-not @($Have | Where-Object { $_ })) { return @() }
    $directoryCovers = @('User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Application.Read.All')
    $hasDirectory = ('Directory.Read.All' -in $Have) -or ('Directory.ReadWrite.All' -in $Have)
    return @($Required | Where-Object {
            ($_ -notin $Have) -and (($_ -replace '\.Read\.', '.ReadWrite.') -notin $Have) -and
            -not ($hasDirectory -and $_ -in $directoryCovers)
        })
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Any terminating error in the script body (invalid ruleset, a refused path, a
# refused identifier, Graph module missing, sign-in failed) exits 255 - never
# pwsh's default 1, which a caller would read as "1 open violation".
trap {
    Write-Console "SoD report FAILED (exit 255): $($_.Exception.Message)" -ForegroundColor Red
    Write-Console 'No report written; nothing is reported as clean.' -ForegroundColor Red
    exit 255
}

# =============================================================================
# PURE FUNCTIONS - unit-tested in tests/09-SoD-Report.Tests.ps1
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

function Get-SubjectPseudonym {
    # Stable, non-reversible label for a person in a public record.
    param([Parameter(Mandatory)][string]$UserId)
    $bytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($UserId.ToLowerInvariant()))
    return 'U-' + ([Convert]::ToHexString($bytes).Substring(0, 12).ToLowerInvariant())
}

function ConvertTo-UtcDateTime {
    # A JSON date (already a DateTime after ConvertFrom-Json, or a string) -> UTC.
    param([Parameter(Mandatory)]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
}

function Get-RuleEntitlement {
    # "kind|name" keys of one rule side. reviewerOfRecord = true adds the
    # derived holding 'reviewerOfRecord|T2-direct-report' (see .DESCRIPTION).
    param($Side)
    $keys = @()
    foreach ($k in 'accessPackages', 'groups', 'directoryRoles') { foreach ($n in @($Side[$k])) { if ($n) { $keys += "$k|$n" } } }
    if ($Side -and $Side['reviewerOfRecord'] -eq $true) { $keys += 'reviewerOfRecord|T2-direct-report' }
    return $keys
}

function Get-T2PackageName {
    # Request-only (tier T2) catalog packages: the access a manager certifies (ADR 0012 T2).
    param([Parameter(Mandatory)]$Catalog)
    return @(@($Catalog['accessPackages']) | Where-Object { $_ -and [string]$_['tier'] -eq 'T2' } | ForEach-Object { [string]$_['name'] })
}

function Get-ReviewerOfRecordHolding {
    # Managers (reviewer of record for T2) of anyone holding a T2 package.
    # Reports: managerId -> list of direct-report ids. Holdings: the inventory
    # holdings already read. Returns holdings of kind reviewerOfRecord.
    param([Parameter(Mandatory)][hashtable]$Reports, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Holdings, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$T2Packages)
    $t2Holders = @{}
    foreach ($h in $Holdings) { if ($h -and [string]$h['kind'] -eq 'accessPackages' -and [string]$h['name'] -in $T2Packages) { $t2Holders[[string]$h['userId']] = $true } }
    $out = @()
    foreach ($m in ($Reports.Keys | Sort-Object)) {
        if (@($Reports[$m] | Where-Object { $_ -and $t2Holders.ContainsKey([string]$_) }).Count) {
            $out += @{ userId = [string]$m; kind = 'reviewerOfRecord'; name = 'T2-direct-report'; via = 'manager' }
        }
    }
    return $out
}

function Test-EligibleOnlyVia {
    param([string]$Via)
    return $Via -in 'pimEligible', 'eligible', 'eligible-via-group'
}

function ConvertFrom-FixtureInventory {
    # Offline inventory (lab/iga/fixtures/sod-tenant.json) -> the shape the
    # live collector builds: users (id -> user), exists (kind|name -> $true),
    # holdings (list of @{ userId; kind; name; via }). With -Catalog, and when
    # the fixture's users carry managerId, the reviewer-of-record holdings are
    # derived the same way the tenant path derives them.
    param([Parameter(Mandatory)]$Fixture, $Catalog = $null)
    $users = @{}
    foreach ($u in @($Fixture['users'])) { if ($u) { $users[[string]$u['id']] = $u } }
    $exists = @{}
    $objects = if ($Fixture['objects']) { $Fixture['objects'] } else { @{} }
    foreach ($k in 'accessPackages', 'groups', 'directoryRoles') {
        foreach ($n in @($objects[$k])) { if ($n) { $exists["$k|$n"] = $true } }
    }
    $holdings = @(@($Fixture['holdings']) | Where-Object { $_ } | ForEach-Object {
            @{ userId = [string]$_['userId']; kind = [string]$_['kind']; name = [string]$_['name']; via = [string]$_['via'] }
        })
    $withManager = @($users.Values | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains('managerId') })
    if ($Catalog -and $withManager.Count) {
        $reports = @{}
        foreach ($u in $withManager) { $m = [string]$u['managerId']; if (-not $m) { continue }; if (-not $reports.ContainsKey($m)) { $reports[$m] = @() }; $reports[$m] += [string]$u['id'] }
        $holdings = @($holdings) + @(Get-ReviewerOfRecordHolding -Reports $reports -Holdings $holdings -T2Packages @(Get-T2PackageName -Catalog $Catalog))
        $exists['reviewerOfRecord|T2-direct-report'] = $true
    }
    return @{ users = $users; exists = $exists; holdings = $holdings; dataSources = @(@{ name = 'fixture'; status = 'ok' }) }
}

function Invoke-SodEvaluation {
    # Rules x inventory -> rule results + violations. Pure.
    param([Parameter(Mandatory)]$Rules, [Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)][datetime]$AsOf)
    # userId -> "kind|name" -> list of via
    $index = @{}
    foreach ($h in @($Inventory['holdings'])) {
        if (-not $h -or -not $h['userId']) { continue }
        $u = [string]$h['userId']; $key = "$($h['kind'])|$($h['name'])"
        if (-not $index.ContainsKey($u)) { $index[$u] = @{} }
        if (-not $index[$u].ContainsKey($key)) { $index[$u][$key] = [System.Collections.Generic.List[string]]::new() }
        if ([string]$h['via'] -notin $index[$u][$key]) { $index[$u][$key].Add([string]$h['via']) }
    }
    $ruleResults = [System.Collections.Generic.List[object]]::new()
    $violations = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Rules['rules'])) {
        $a = @(Get-RuleEntitlement $r['sideA']); $b = @(Get-RuleEntitlement $r['sideB'])
        $missing = @(@($a) + @($b) | Where-Object { -not $Inventory['exists'].ContainsKey($_) })
        $aOk = @($a | Where-Object { $Inventory['exists'].ContainsKey($_) }); $bOk = @($b | Where-Object { $Inventory['exists'].ContainsKey($_) })
        $status = if ($aOk.Count -eq 0 -or $bOk.Count -eq 0) { 'not-evaluable' } elseif ($missing.Count) { 'partial' } else { 'evaluated' }
        $open = 0; $excepted = 0
        if ($status -ne 'not-evaluable') {
            foreach ($uid in ($index.Keys | Sort-Object)) {
                $held = $index[$uid]
                $hitA = @($aOk | Where-Object { $held.ContainsKey($_) }); $hitB = @($bOk | Where-Object { $held.ContainsKey($_) })
                if (-not $hitA.Count -or -not $hitB.Count) { continue }
                $fmt = { param($keys) @($keys | ForEach-Object { $k, $n = $_ -split '\|', 2; "$($k.TrimEnd('s')):$n[$(@($held[$_]) -join '+')]" }) }
                $eligOnly = { param($keys) -not @($keys | Where-Object { @($held[$_] | Where-Object { -not (Test-EligibleOnlyVia $_) }).Count }).Count }
                $user = if ($Inventory['users'].ContainsKey($uid)) { $Inventory['users'][$uid] } else { @{} }
                $upn = [string]$user['userPrincipalName']
                $exc = @(@($Rules['exceptions']) | Where-Object { $_ -and [string]$_['ruleId'] -eq [string]$r['id'] -and $upn -and [string]$_['userPrincipalName'] -eq $upn }) | Select-Object -First 1
                $vStatus = 'open'; $excId = ''
                if ($exc) {
                    $excId = [string]$exc['exceptionId']
                    $exp = ConvertTo-UtcDateTime $exc['expires']
                    # An exception is valid through the whole of its expiry date.
                    $vStatus = if ($AsOf.ToUniversalTime().Date -le $exp.Date) { 'excepted' } else { 'exception-expired' }
                }
                if ($vStatus -eq 'excepted') { $excepted++ } else { $open++ }
                $violations.Add([pscustomobject]@{
                        RuleId             = [string]$r['id']
                        RuleName           = [string]$r['name']
                        Risk               = [string]$r['risk']
                        UserId             = $uid
                        UserPrincipalName  = $upn
                        DisplayName        = [string]$user['displayName']
                        AccountEnabled     = $user['accountEnabled']
                        SideA              = (& $fmt $hitA)
                        SideB              = (& $fmt $hitB)
                        ActivationRequired = [bool]((& $eligOnly $hitA) -or (& $eligOnly $hitB))
                        Status             = $vStatus
                        ExceptionId        = $excId
                    })
            }
        }
        $ruleResults.Add([pscustomobject]@{ Id = [string]$r['id']; Name = [string]$r['name']; Risk = [string]$r['risk']; Status = $status; Missing = @($missing); Open = $open; Excepted = $excepted })
    }
    return [pscustomobject]@{ Rules = $ruleResults.ToArray(); Violations = $violations.ToArray() }
}

function ConvertTo-PublicViolation {
    # A violation as it may appear in the public record: pseudonym, no identity.
    param([Parameter(Mandatory)]$Violation)
    return [ordered]@{
        ruleId             = $Violation.RuleId
        ruleName           = $Violation.RuleName
        risk               = $Violation.Risk
        subject            = Get-SubjectPseudonym -UserId $Violation.UserId
        accountEnabled     = $Violation.AccountEnabled
        sideA              = ($Violation.SideA -join '; ')
        sideB              = ($Violation.SideB -join '; ')
        activationRequired = $Violation.ActivationRequired
        status             = $Violation.Status
        exceptionId        = $Violation.ExceptionId
    }
}

function ConvertTo-HoldingsSnapshot {
    # Inventory holdings -> the rows of the sod_holdings watchlist / Splunk
    # lookup. Only access packages and groups (what the tripwires match on);
    # directory roles and derived reviewer-of-record holdings are not grants
    # the AuditLogs rule sees, so they are left out. One row per user + name.
    param([AllowEmptyCollection()][object[]]$Holdings = @(), [hashtable]$Users = @{}, [Parameter(Mandatory)][datetime]$SnapshotTime)
    $kindName = @{ accessPackages = 'AccessPackage'; groups = 'Group' }
    $t = $SnapshotTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    $seen = @{}
    foreach ($h in @($Holdings | Where-Object { $_ -and $kindName.ContainsKey([string]$_['kind']) })) {
        $key = "$($h['userId'])|$($h['kind'])|$($h['name'])"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $u = if ($Users.ContainsKey([string]$h['userId'])) { $Users[[string]$h['userId']] } else { $null }
        $upn = if ($u -is [System.Collections.IDictionary] -and $u.Contains('userPrincipalName')) { ([string]$u['userPrincipalName']).ToLowerInvariant() } else { '' }
        [pscustomobject][ordered]@{ UserObjectId = [string]$h['userId']; UserPrincipalName = $upn; Kind = $kindName[[string]$h['kind']]; Name = [string]$h['name']; SnapshotTime = $t }
    }
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

# =============================================================================
# SCRIPT BODY
# =============================================================================
$rules = Read-IgaJson -Path $RulesPath
$catalog = Read-IgaJson -Path $CatalogPath
$problems = @(Test-SodRuleSet -Rules $rules -Catalog $catalog)
if ($problems.Count) {
    foreach ($p in $problems) { Write-Warning "  RULE ERROR: $p" }
    throw "sod-rules.json is not valid ($($problems.Count) error(s))."
}
$evidenceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'evidence'))
$isFixture = [bool]$InputPath
# Fail closed: a fixture run must never look like it signed in to a tenant.
if ($isFixture -and $UseAzureCliToken) { throw '-InputPath and -UseAzureCliToken exclude each other: a fixture run never contacts a tenant.' }
if (-not $OutputDirectory) { $OutputDirectory = if ($isFixture) { Join-Path $evidenceRoot 'out' 'sod' } else { Join-Path $evidenceRoot 'sod' } }
if ($isFixture -and (Test-IsPublicEvidencePath -Path $OutputDirectory -EvidenceRoot $evidenceRoot)) {
    throw "Refusing to write a fixture (synthetic) report into the public evidence tree ($OutputDirectory). lab/evidence holds only output of real runs; use the default lab/evidence/out/sod."
}
if (Test-IsPublicEvidencePath -Path $DetailDirectory -EvidenceRoot $evidenceRoot) { throw "-DetailDirectory '$DetailDirectory' is inside the public evidence tree; identity detail must go to lab/evidence/out/." }
if ($HoldingsSnapshotPath -and (Test-IsPublicEvidencePath -Path (Split-Path -Parent ([System.IO.Path]::GetFullPath($HoldingsSnapshotPath))) -EvidenceRoot $evidenceRoot)) {
    throw "-HoldingsSnapshotPath '$HoldingsSnapshotPath' is inside the public evidence tree; the snapshot holds object ids and UPNs (write it under lab/evidence/out/ or another gitignored path)."
}

# ---- inventory ------------------------------------------------------------
$failedSources = @()
if ($isFixture) {
    $fixture = Read-IgaJson -Path $InputPath
    $inventory = ConvertFrom-FixtureInventory -Fixture $fixture -Catalog $catalog
    if (-not $AsOf) { $AsOf = if ($fixture['asOf']) { ConvertTo-UtcDateTime $fixture['asOf'] } else { (Get-Date).ToUniversalTime() } }
    Write-Console "SoD report - OFFLINE against $(Split-Path -Leaf $InputPath) (synthetic fixture, not tenant data)" -ForegroundColor Yellow
}
else {
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required for a tenant run (or use -InputPath).' }
    $requiredScopes = @('EntitlementManagement.Read.All', 'GroupMember.Read.All', 'User.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
    if ($UseAzureCliToken) {
        # App-only: always this identity, never a leftover context.
        Write-Console 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
        Connect-GraphFromAzureCli
    }
    $ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
    if (-not $ctx) {
        if ($UseAzureCliToken) { throw 'No Microsoft Graph context after the app-only sign-in.' }
        Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext
    }
    $missingScopes = @(Get-MissingGraphScope -Have @($ctx.Scopes) -Required $requiredScopes)
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Sources needing them will FAIL (exit 255), never read as empty." }
    if (-not $AsOf) { $AsOf = (Get-Date).ToUniversalTime() }
    Write-Console 'SoD report - tenant' -ForegroundColor Cyan

    $graph = 'https://graph.microsoft.com/v1.0'
    $em = "$graph/identityGovernance/entitlementManagement"
    function Get-GraphThrottleDelay {
        # Parity-tested copy (tests/Scale20k.Tests.ps1). Returns the seconds to wait
        # when a Graph call failed because Graph throttled it (HTTP 429, or 503
        # Service Unavailable), else $null. Why this exists: Microsoft.Graph's own
        # retry handler retries a throttled call a few times (verify: Microsoft
        # Learn "Microsoft Graph throttling guidance" and Set-MgRequestContext
        # -MaxRetry, default 3). In a 20,000-user tenant a long paged read can
        # outlive those retries, and then one throttled page used to fail the whole
        # read (karen-review I2). The wait is the Retry-After header when Graph
        # sends one, else 10 seconds, kept between 1 and 120 seconds.
        param($ErrorRecord)
        $ex = $ErrorRecord.Exception
        $resp = $null
        if ($ex -and $ex.PSObject.Properties['Response']) { $resp = $ex.Response }
        $code = 0
        if ($resp -and $resp.PSObject.Properties['StatusCode']) { try { $code = [int]$resp.StatusCode } catch { $code = 0 } }
        if (-not $code -and $ex) {
            if ($ex.Message -match '\b429\b|TooManyRequests') { $code = 429 }
            elseif ($ex.Message -match '\b503\b|ServiceUnavailable') { $code = 503 }
        }
        if ($code -ne 429 -and $code -ne 503) { return $null }
        $seconds = 0
        if ($resp -and $resp.PSObject.Properties['Headers'] -and $resp.Headers) {
            $ra = $null
            try { $ra = $resp.Headers.RetryAfter } catch { $ra = $null }
            if ($ra -and $ra.Delta) { $seconds = [int][math]::Ceiling($ra.Delta.TotalSeconds) }
            elseif ($ra -and $ra.Date) { $seconds = [int][math]::Ceiling(($ra.Date - [DateTimeOffset]::UtcNow).TotalSeconds) }
        }
        if ($seconds -le 0) { $seconds = 10 }
        return [math]::Min([math]::Max($seconds, 1), 120)
    }
    function Invoke-GraphGetWithRetry {
        # Parity-tested copy (tests/Scale20k.Tests.ps1). One Graph GET; a throttled
        # call is retried after the wait Graph asks for, at most -MaxRetry times.
        # Any other error, or a throttle that outlasts the retries, is thrown:
        # a caller never gets a partial collection that looks complete.
        param([Parameter(Mandatory)][string]$Uri, [int]$MaxRetry = 5)
        for ($attempt = 0; ; $attempt++) {
            try { return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable -ErrorAction Stop }
            catch {
                $wait = Get-GraphThrottleDelay -ErrorRecord $_
                if ($null -eq $wait -or $attempt -ge $MaxRetry) { throw }
                Write-Warning "Graph throttled a read (try $($attempt + 1) of $MaxRetry); waiting $wait s as Graph asks."
                Start-Sleep -Seconds $wait
            }
        }
    }
    function Get-GraphCollection {
        # Shared by the lab/iga scripts (parity-tested): every page of a Graph collection.
        param([Parameter(Mandatory)][string]$Uri)
        $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
        while ($next) {
            $page = Invoke-GraphGetWithRetry -Uri $next
            foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
            $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
        }
        return $items.ToArray()
    }
    $inventory = @{ users = @{}; exists = @{}; holdings = [System.Collections.Generic.List[object]]::new(); dataSources = [System.Collections.Generic.List[object]]::new() }
    function Add-SourceStatus { param([string]$Name, [string]$Status, [string]$Detail = '') $inventory['dataSources'].Add(@{ name = $Name; status = $Status; detail = $Detail }) }
    function Add-Holding { param([string]$UserId, [string]$Kind, [string]$Name, [string]$Via) $inventory['holdings'].Add(@{ userId = $UserId; kind = $Kind; name = $Name; via = $Via }) }
    function Add-UserInfo {
        param($U)
        if (-not $U -or -not $U['id']) { return }
        $id = [string]$U['id']
        if (-not $inventory['users'].ContainsKey($id)) { $inventory['users'][$id] = @{ id = $id; userPrincipalName = $null; displayName = $null; accountEnabled = $null } }
        foreach ($k in 'userPrincipalName', 'displayName', 'accountEnabled') { if ($U.ContainsKey($k) -and $null -ne $U[$k]) { $inventory['users'][$id][$k] = $U[$k] } }
    }
    $groupUserCache = @{}
    function Get-GroupUser {
        param([string]$GroupId)
        if (-not $groupUserCache.ContainsKey($GroupId)) {
            $groupUserCache[$GroupId] = @(Get-GraphCollection -Uri "$graph/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,displayName,accountEnabled")
        }
        return $groupUserCache[$GroupId]
    }
    function Get-GroupEligibleUser {
        # PIM-for-Groups ELIGIBLE members (accessId member), groups expanded to their users.
        param([string]$GroupId)
        $out = @()
        foreach ($i in (Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$GroupId'&`$expand=principal")) {
            if ([string]$i['accessId'] -ne 'member') { continue }
            $p = $i['principal']
            $type = if ($p) { [string]$p['@odata.type'] } else { '' }
            if ($type -like '*group') { $out += @(Get-GroupUser -GroupId ([string]$p['id'])) }
            elseif ($p) { $out += $p } else { $out += @{ id = [string]$i['principalId'] } }
        }
        return $out
    }
    $wanted = @{}
    foreach ($r in @($rules['rules'])) { foreach ($k in @(Get-RuleEntitlement $r['sideA']) + @(Get-RuleEntitlement $r['sideB'])) { $wanted[$k] = $true } }
    # The reviewer-of-record check needs every T2 package's assignments, not only the ones a rule names.
    $rorRules = @(@($rules['rules']) | Where-Object { $_['sideA']['reviewerOfRecord'] -eq $true -or $_['sideB']['reviewerOfRecord'] -eq $true })
    if ($rorRules.Count) { foreach ($n in @(Get-T2PackageName -Catalog $catalog)) { $wanted["accessPackages|$n"] = $true } }

    # Access packages: delivered assignments.
    try {
        foreach ($name in @($wanted.Keys | Where-Object { $_ -like 'accessPackages|*' } | ForEach-Object { ($_ -split '\|', 2)[1] } | Sort-Object)) {
            $f = [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'")
            $pk = @(Get-GraphCollection -Uri "$em/accessPackages?`$filter=$f&`$select=id,displayName")
            if ($pk.Count -gt 1) { throw "$($pk.Count) access packages are named '$name'." }
            if ($pk.Count -eq 0) { continue }
            $inventory['exists']["accessPackages|$name"] = $true
            $af = [uri]::EscapeDataString("accessPackage/id eq '$($pk[0]['id'])' and state eq 'Delivered'")
            foreach ($a in (Get-GraphCollection -Uri "$em/assignments?`$filter=$af&`$expand=target")) {
                $t = $a['target']; if (-not $t -or -not $t['objectId']) { continue }
                Add-UserInfo @{ id = [string]$t['objectId']; userPrincipalName = $t['principalName']; displayName = $t['displayName'] }
                Add-Holding ([string]$t['objectId']) 'accessPackages' $name 'assignment'
            }
        }
        Add-SourceStatus 'accessPackageAssignments' 'ok'
    }
    catch { Add-SourceStatus 'accessPackageAssignments' 'FAILED' $_.Exception.Message }

    # Groups: transitive members, plus PIM-for-Groups eligible members.
    try {
        foreach ($name in @($wanted.Keys | Where-Object { $_ -like 'groups|*' } | ForEach-Object { ($_ -split '\|', 2)[1] } | Sort-Object)) {
            $f = [uri]::EscapeDataString("displayName eq '$($name.Replace("'", "''"))'")
            $g = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id,displayName")
            if ($g.Count -gt 1) { throw "$($g.Count) groups are named '$name'." }
            if ($g.Count -eq 0) { continue }
            $inventory['exists']["groups|$name"] = $true
            foreach ($u in (Get-GroupUser -GroupId ([string]$g[0]['id']))) { Add-UserInfo $u; Add-Holding ([string]$u['id']) 'groups' $name 'member' }
            $entry = Get-CatalogEntry -Catalog $catalog -Kind groups -Name $name
            if ($entry -and $entry['pimForGroups'] -eq $true) {
                foreach ($u in (Get-GroupEligibleUser -GroupId ([string]$g[0]['id']))) { Add-UserInfo $u; Add-Holding ([string]$u['id']) 'groups' $name 'pimEligible' }
            }
        }
        Add-SourceStatus 'groupMemberships' 'ok'
    }
    catch { Add-SourceStatus 'groupMemberships' 'FAILED' $_.Exception.Message }

    # Directory roles: active + eligible instances; group principals expanded.
    try {
        $roleNames = @($wanted.Keys | Where-Object { $_ -like 'directoryRoles|*' } | ForEach-Object { ($_ -split '\|', 2)[1] })
        if ($roleNames.Count) {
            $byTemplate = @{}
            foreach ($n in $roleNames) { $e = Get-CatalogEntry -Catalog $catalog -Kind directoryRoles -Name $n; $byTemplate[[string]$e['templateId']] = $n; $inventory['exists']["directoryRoles|$n"] = $true }
            foreach ($src in @(@{ uri = "$graph/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=principal"; via = 'active' },
                    @{ uri = "$graph/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal"; via = 'eligible' })) {
                foreach ($i in (Get-GraphCollection -Uri $src.uri)) {
                    $rid = [string]$i['roleDefinitionId']; if (-not $byTemplate.ContainsKey($rid)) { continue }
                    $p = $i['principal']; if (-not $p) { continue }
                    $type = [string]$p['@odata.type']
                    if ($type -like '*user') { Add-UserInfo $p; Add-Holding ([string]$p['id']) 'directoryRoles' $byTemplate[$rid] $src.via }
                    elseif ($type -like '*group') {
                        $memberVia = if ($src.via -eq 'active') { 'active-via-group' } else { 'eligible-via-group' }
                        foreach ($u in (Get-GroupUser -GroupId ([string]$p['id']))) { Add-UserInfo $u; Add-Holding ([string]$u['id']) 'directoryRoles' $byTemplate[$rid] $memberVia }
                        foreach ($u in (Get-GroupEligibleUser -GroupId ([string]$p['id']))) { Add-UserInfo $u; Add-Holding ([string]$u['id']) 'directoryRoles' $byTemplate[$rid] 'eligible-via-group' }
                    }
                }
            }
        }
        Add-SourceStatus 'directoryRoles' 'ok'
    }
    catch { Add-SourceStatus 'directoryRoles' 'FAILED' $_.Exception.Message }

    # Reviewer of record: direct reports of the people holding the OTHER side of a reviewerOfRecord rule.
    if ($rorRules.Count) {
        try {
            $candidateKeys = @{}
            foreach ($r in $rorRules) {
                $other = if ($r['sideB']['reviewerOfRecord'] -eq $true) { $r['sideA'] } else { $r['sideB'] }
                foreach ($k in @(Get-RuleEntitlement $other)) { $candidateKeys[$k] = $true }
            }
            $candidates = @($inventory['holdings'] | Where-Object { $candidateKeys.ContainsKey("$($_['kind'])|$($_['name'])") } | ForEach-Object { [string]$_['userId'] } | Sort-Object -Unique)
            $reports = @{}
            foreach ($id in $candidates) { $reports[$id] = @(Get-GraphCollection -Uri "$graph/users/$id/directReports/microsoft.graph.user?`$select=id" | ForEach-Object { [string]$_['id'] }) }
            foreach ($h in @(Get-ReviewerOfRecordHolding -Reports $reports -Holdings @($inventory['holdings']) -T2Packages @(Get-T2PackageName -Catalog $catalog))) { Add-Holding $h['userId'] $h['kind'] $h['name'] $h['via'] }
            $inventory['exists']['reviewerOfRecord|T2-direct-report'] = $true
            Add-SourceStatus 'directReports' 'ok'
        }
        catch { Add-SourceStatus 'directReports' 'FAILED' $_.Exception.Message }
    }
    $failedSources = @($inventory['dataSources'] | Where-Object { $_['status'] -ne 'ok' })
}

if ($failedSources.Count) {
    foreach ($s in $failedSources) { Write-Console "  [FAILED] $($s['name']): $($s['detail'])" -ForegroundColor Red }
    Write-Console 'A data source could not be read: no report written, nothing reported as clean (exit 255).' -ForegroundColor Red
    exit 255
}

# ---- evaluate ---------------------------------------------------------------
$result = Invoke-SodEvaluation -Rules $rules -Inventory $inventory -AsOf ([datetime]$AsOf)

# Tenant mode: fill accountEnabled for people in violation (default user projections omit it).
if (-not $isFixture) {
    foreach ($v in @($result.Violations | Where-Object { $null -eq $_.AccountEnabled })) {
        try {
            $u = Invoke-MgGraphRequest -Method GET -Uri "$graph/users/$($v.UserId)?`$select=id,userPrincipalName,displayName,accountEnabled" -OutputType HashTable
            $v.AccountEnabled = $u['accountEnabled']; if (-not $v.UserPrincipalName) { $v.UserPrincipalName = [string]$u['userPrincipalName'] }; if (-not $v.DisplayName) { $v.DisplayName = [string]$u['displayName'] }
        }
        catch { Write-Verbose "accountEnabled lookup failed for a violating user: $($_.Exception.Message)" }
    }
}

$open = @($result.Violations | Where-Object Status -ne 'excepted')
$excepted = @($result.Violations | Where-Object Status -eq 'excepted')
foreach ($rr in $result.Rules) {
    $color = switch ($rr.Status) { 'not-evaluable' { 'DarkYellow' } default { if ($rr.Open) { 'Red' } else { 'Green' } } }
    $note = if ($rr.Status -eq 'evaluated') { '' } else { " (missing: $($rr.Missing -join ', '))" }
    Write-Console ("  {0} {1,-14} open {2,3}  excepted {3,2}  {4}{5}" -f $rr.Id, $rr.Status, $rr.Open, $rr.Excepted, $rr.Name, $note) -ForegroundColor $color
}

# ---- write -----------------------------------------------------------------
$now = (Get-Date).ToUniversalTime()
$sha = { param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
$publicRows = @($result.Violations | ForEach-Object { ConvertTo-PublicViolation -Violation $_ })
$report = [ordered]@{
    schema         = 'contoso-iga/sod-report/v1'
    generatedAtUtc = $now.ToString('o')
    source         = if ($isFixture) { 'fixture' } else { 'tenant' }
    inputFile      = if ($isFixture) { Split-Path -Leaf $InputPath } else { $null }
    asOf           = ([datetime]$AsOf).ToUniversalTime().ToString('yyyy-MM-dd')
    rulesFile      = [ordered]@{ name = Split-Path -Leaf $RulesPath; sha256 = (& $sha $RulesPath) }
    catalogFile    = [ordered]@{ name = Split-Path -Leaf $CatalogPath; sha256 = (& $sha $CatalogPath) }
    summary        = [ordered]@{
        rules             = @($result.Rules).Count
        rulesEvaluated    = @($result.Rules | Where-Object Status -eq 'evaluated').Count
        rulesPartial      = @($result.Rules | Where-Object Status -eq 'partial').Count
        rulesNotEvaluable = @($result.Rules | Where-Object Status -eq 'not-evaluable').Count
        violationsOpen    = $open.Count
        violationsExcepted = $excepted.Count
        activationRequired = @($open | Where-Object ActivationRequired).Count
        disabledAccounts  = @($open | Where-Object { $_.AccountEnabled -eq $false }).Count
        exitCode          = [math]::Min($open.Count, 254)
    }
    rules          = @($result.Rules | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name; risk = $_.Risk; status = $_.Status; missing = @($_.Missing); open = $_.Open; excepted = $_.Excepted } })
    violations     = $publicRows
    dataSources    = @($inventory['dataSources'])
    note           = 'Subjects are pseudonyms (U- + SHA-256 prefix of the object id). Identity detail is in the gitignored lab/evidence/out/sod. not-evaluable rules make no claim either way.'
}
$json = $report | ConvertTo-Json -Depth 10
$csv = ($publicRows | ForEach-Object { [pscustomobject]$_ } | ConvertTo-Csv -NoTypeInformation) -join "`n"
if (-not $publicRows.Count) { $csv = '"ruleId","ruleName","risk","subject","accountEnabled","sideA","sideB","activationRequired","status","exceptionId"' }
$unsafe = @(Test-PublicRecordSafe -Json ($json + "`n" + $csv))
if ($unsafe.Count) { throw "Public SoD record would contain identifiers ($($unsafe -join ', ')); nothing written." }

$stamp = $now.ToString('yyyyMMddTHHmmssZ')
$dir = Join-Path ([System.IO.Path]::GetFullPath($OutputDirectory)) $stamp
$n = 1; while (Test-Path -LiteralPath $dir) { $n++; $dir = Join-Path ([System.IO.Path]::GetFullPath($OutputDirectory)) "$stamp-$n" }
$detailDir = Join-Path ([System.IO.Path]::GetFullPath($DetailDirectory)) (Split-Path -Leaf $dir)
if ($PSCmdlet.ShouldProcess($dir, 'write SoD report (json + csv + manifest) and identity detail')) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $jsonPath = Join-Path $dir 'sod-report.json'; $csvPath = Join-Path $dir 'sod-violations.csv'
    $json | Set-Content -LiteralPath $jsonPath -Encoding utf8NoBOM
    $csv | Set-Content -LiteralPath $csvPath -Encoding utf8NoBOM
    # sha256sum format, so `shasum -a 256 -c manifest.sha256` verifies it from inside the folder.
    @("$(& $sha $jsonPath)  sod-report.json", "$(& $sha $csvPath)  sod-violations.csv") | Set-Content -LiteralPath (Join-Path $dir 'manifest.sha256') -Encoding utf8NoBOM
    New-Item -ItemType Directory -Path $detailDir -Force | Out-Null
    [ordered]@{
        generatedAtUtc = $report['generatedAtUtc']; report = (Split-Path -Leaf $dir); source = $report['source']
        subjects       = @($result.Violations | Sort-Object UserId -Unique | ForEach-Object { [ordered]@{ subject = (Get-SubjectPseudonym -UserId $_.UserId); userId = $_.UserId; userPrincipalName = $_.UserPrincipalName; displayName = $_.DisplayName } })
        violations     = @($result.Violations)
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $detailDir 'sod-detail.json') -Encoding utf8NoBOM
    Write-Console "`nReport: $dir" -ForegroundColor Cyan
}
if ($HoldingsSnapshotPath -and $PSCmdlet.ShouldProcess($HoldingsSnapshotPath, 'write the sod_holdings snapshot (object ids + UPNs, gitignored location)')) {
    $snapRows = @(ConvertTo-HoldingsSnapshot -Holdings @($inventory['holdings']) -Users $inventory['users'] -SnapshotTime $now)
    $snapDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($HoldingsSnapshotPath))
    if (-not (Test-Path -LiteralPath $snapDir)) { New-Item -ItemType Directory -Path $snapDir -Force | Out-Null }
    $lines = @('UserObjectId,UserPrincipalName,Kind,Name,SnapshotTime') + @($snapRows | ConvertTo-Csv -NoTypeInformation -UseQuotes AsNeeded | Select-Object -Skip 1)
    $lines | Set-Content -LiteralPath $HoldingsSnapshotPath -Encoding utf8NoBOM
    Write-Console "Holdings snapshot: $HoldingsSnapshotPath ($($snapRows.Count) row(s)) - TENANT-TIME: upload as Sentinel watchlist sod_holdings (SearchKey UserObjectId) and copy to the Splunk lookup contoso_sod_holdings.csv." -ForegroundColor Cyan
}

Write-Console ("{0} open violation(s), {1} excepted; {2} rule(s) not evaluable." -f $open.Count, $excepted.Count, $report['summary']['rulesNotEvaluable']) -ForegroundColor $(if ($open.Count) { 'Red' } else { 'Green' })
[pscustomobject]@{ Report = $report; Violations = $result.Violations; Directory = $dir }
exit ([math]::Min($open.Count, 254))
