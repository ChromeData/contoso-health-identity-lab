<#
.SYNOPSIS
    Read-only export of the tenant configuration this repository owns, as one
    normalised JSON snapshot: Conditional Access, named locations,
    authentication strengths, the authentication methods policy, PIM
    role-management policies (directory roles and PIM for Groups), consent and
    app-management policies, cross-tenant access defaults, and the break-glass
    exclusion facts. Written to lab/evidence/config-snapshots/<UTC>.json with
    a SHA256SUMS line. Compare-IdentityConfig.ps1 diffs it against the
    committed baseline and the declared intent in code.

.DESCRIPTION
    WHY: the lab's Conditional Access, PIM and authentication-method settings
    are code (modules/conditional-access, modules/pim, post-apply/). The
    real-time detections (lab/kql/ca-policy-changed.kql,
    auth-method-changed-by-admin.kql, role-assigned-outside-pim.kql,
    pim-group-member-added-outside-pim.kql) catch a change AS IT HAPPENS, but
    a change that slipped past them (a rule not yet deployed, an outage, a
    Microsoft-managed edit, a portal change nobody alerted on) stays invisible
    until someone looks. This export plus the compare is the periodic
    RECONCILE: every night, the tenant as it is against the tenant as the
    code says it should be (.github/workflows/config-drift.yml).

    NORMALISATION (deterministic: the same tenant state gives the same bytes)
      * Every dictionary's keys are sorted; scalar arrays are sorted (they are
        sets: exclusions, countries, combinations) except where order is the
        setting (Get-OrderSensitiveKey); arrays of objects are sorted by displayName,
        then id, then their own canonical JSON.
      * Volatile fields are dropped (Get-VolatileFieldName): created /
        modified timestamps, lastModifiedBy, version counters, @odata.context.
      * Personal identifiers never reach the file, in either mode: strings
        that look like an email or UPN are replaced by '[redacted]', PIM
        notificationRecipients become a count, break-glass members are
        counted, not named.
      * -Public additionally replaces every object id (GUID, wherever it
        appears, inside policy ids and reviewer queries too) with
        'h:' + the first 16 hex of SHA-256 of the lowercase id, and every IP
        range with the same hash of the CIDR. Stable, so a public baseline
        and a public snapshot still compare; no id or address in a public
        folder. The CI run uses -Public. Without -Public the file holds
        object ids and belongs in the gitignored lab/evidence/out/.

    SECTIONS (snapshot key -> Graph read, all v1.0, all GET)
      conditionalAccessPolicies     /identity/conditionalAccess/policies
      namedLocations                /identity/conditionalAccess/namedLocations
      authenticationStrengths       /policies/authenticationStrengthPolicies
                                    + /{id}/combinationConfigurations (the
                                    FIDO2 AAGUID allow-list of the admin strength)
      authenticationMethodsPolicy   /policies/authenticationMethodsPolicy
      pimDirectoryRolePolicies      /policies/roleManagementPolicyAssignments
                                    ?$filter=scopeId eq '/' and scopeType eq
                                    'DirectoryRole' and roleDefinitionId eq
                                    '<id>'&$expand=policy($expand=rules), one
                                    read per -DirectoryRoleTemplateIds (default:
                                    Global Administrator, the role the lab's
                                    Set-DirectoryRolePimPolicies.ps1 manages)
      pimGroupPolicies              the same, scopeType 'Group', for every
                                    group whose mailNickname starts with
                                    -PimTierGroupPrefix plus -PimGroupMailNicknames
      consentPolicy                 /policies/authorizationPolicy +
                                    /policies/adminConsentRequestPolicy
      appManagementPolicy           /policies/defaultAppManagementPolicy
      crossTenantAccessDefaults     /policies/crossTenantAccessPolicy/default
      breakGlass                    the -BreakGlassGroupMailNickname group:
                                    found, member count, enabled members,
                                    holds Global Administrator (a standing
                                    roleAssignment), and per CA policy whether
                                    its excludeGroups names the group

    A FAILED READ IS NEVER "NOTHING THERE": a section whose read throws is
    written as { status: "failed", error: "..." }, never as an empty list,
    and the script exits 1 after writing the file. Compare-IdentityConfig.ps1
    raises a finding for every failed section. The same rule as
    08-Measure-KPIs.ps1 and 09-SoD-Report.ps1.

    -Offline -FixturePath replays a committed mock tenant
    (tests/fixtures/identity-config.fixture.json) through the SAME collector
    code: every Graph URI is answered from the fixture instead of
    Invoke-MgGraphRequest. The file then carries source "offline-fixture",
    defaults to the gitignored lab/evidence/out/config-snapshots/, and is
    refused inside the public evidence tree: it can never pass for tenant
    evidence.

.PREREQUISITES
    * Entra ID P1 (Conditional Access), P2 (PIM policies). Roles: Global
      Reader is enough; in CI the PLAN app's application roles.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated or application, READ-ONLY)
    Policy.Read.All                           CA policies, named locations,
                                              authentication strengths and
                                              methods, authorization / consent /
                                              app-management / cross-tenant policies
    RoleManagementPolicy.Read.Directory       directory-role PIM policies
    RoleManagementPolicy.Read.AzureADGroup    PIM-for-Groups policies
    Group.Read.All, GroupMember.Read.All      PIM tier groups, break-glass group + members
    RoleManagement.Read.Directory             break-glass Global Administrator assignment
    verify: the PLAN app (modules/pipeline-identity plan_graph_roles) holds
    all of these except RoleManagementPolicy.Read.Directory; until that role
    is added through extra_plan_graph_roles (a human bootstrap apply), the
    nightly run records pimDirectoryRolePolicies as failed.

.PARAMETER OutputDirectory
    Snapshot folder. Default lab/evidence/config-snapshots (tenant, public
    with -Public) or lab/evidence/out/config-snapshots (-Offline, gitignored).

.PARAMETER Label
    Free text stored in the file, e.g. nightly, pre-graduation.

.PARAMETER Public
    Hash every object id and IP range (see NORMALISATION). Required for a
    file that is committed or attached to a GitHub issue.

.PARAMETER Offline
    Replay -FixturePath instead of reading a tenant. No Graph connection.

.PARAMETER FixturePath
    The mock tenant for -Offline. Default tests/fixtures/identity-config.fixture.json.

.PARAMETER BreakGlassGroupMailNickname
    Default break-glass-admins (modules/entra-baseline).

.PARAMETER PimTierGroupPrefix
    mailNickname prefix of the PIM tier groups (modules/pim tiers.tf). Default pim-tier.

.PARAMETER PimGroupMailNicknames
    Other PIM-governed groups. Default privileged-iam-admins.

.PARAMETER DirectoryRoleTemplateIds
    Directory roles whose PIM policy is exported. Default: Global Administrator.

.EXAMPLE
    ./Export-IdentityConfig.ps1 -Offline -OutputDirectory ../../evidence/out/config-snapshots
    # the mock tenant, no connection

.EXAMPLE
    Connect-MgGraph -Scopes 'Policy.Read.All','RoleManagementPolicy.Read.Directory','RoleManagementPolicy.Read.AzureADGroup','Group.Read.All','GroupMember.Read.All','RoleManagement.Read.Directory'
    ./Export-IdentityConfig.ps1 -Public -Label nightly
    ./Compare-IdentityConfig.ps1 -SnapshotPath ../../evidence/config-snapshots/<UTC>.json -MarkdownPath drift.md

.OUTPUTS
    The snapshot object (also written as JSON). Exit 1 if any section failed.

.NOTES
    TENANT-TIME: nothing here has run against a tenant.
    verify: $expand=policy($expand=rules) on roleManagementPolicyAssignments
      returns the rules inline (Learn documents it; Set-DirectoryRolePimPolicies.ps1
      reads the rules in a second call instead). If it does not, the section
      records failed and the expand is split into two reads.
    verify: /policies/authenticationStrengthPolicies/{id}/combinationConfigurations
      on a built-in strength returns an empty list, not 404.
    verify: roleAssignments with $filter on roleDefinitionId and principalId
      (ConsistencyLevel not required on v1.0 for this filter).
    verify: the authentication methods policy's lastModifiedDateTime and
      policyVersion are the only fields that move between identical reads;
      the first two nightly runs on an unchanged tenant must hash the same.
    verify: adminConsentRequestPolicy 'version' increments on every write and
      is dropped as volatile here; the reviewers list is what matters.

.WHAT IT DEMONSTRATES
    Identity guardrails as a closed loop: declared state in code, real-time
    tamper detection in Sentinel, and a nightly reconcile that cannot be
    silenced by a missed alert. A tamper-evident, public-safe snapshot of the
    control plane that an auditor can hash.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [string]$OutputDirectory = '',

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]{1,40}$', ErrorMessage = 'Label: letters, digits, . _ - only.')]
    [string]$Label = 'snapshot',

    [Parameter()]
    [switch]$Public,

    [Parameter()]
    [switch]$Offline,

    [Parameter()]
    [string]$FixturePath = (Join-Path $PSScriptRoot 'tests' 'fixtures' 'identity-config.fixture.json'),

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]{1,64}$', ErrorMessage = 'BreakGlassGroupMailNickname: lowercase letters, digits, - only.')]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]{1,40}$', ErrorMessage = 'PimTierGroupPrefix: lowercase letters, digits, - only.')]
    [string]$PimTierGroupPrefix = 'pim-tier',

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]{1,64}$', ErrorMessage = 'PimGroupMailNicknames: lowercase letters, digits, - only.')]
    [string[]]$PimGroupMailNicknames = @('privileged-iam-admins'),

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string[]]$DirectoryRoleTemplateIds = @('62e90394-69f5-4237-9190-012177145e10')   # Global Administrator
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
# PURE FUNCTIONS - no I/O. Unit-tested in tests/Export-IdentityConfig.Tests.ps1,
# which loads them from this file's syntax tree without running the script.
# =============================================================================

function Get-Field {
    # Index-walk nested dictionaries; a missing key is $null (dot access on a
    # missing hashtable key throws under StrictMode).
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { if (-not $cur.Contains($p)) { return $null }; $cur = $cur[$p] }
        else { $prop = $cur.PSObject.Properties[$p]; if (-not $prop) { return $null }; $cur = $prop.Value }
    }
    return $cur
}

function Get-VolatileFieldName {
    # Fields that change without the configuration changing. Dropped
    # everywhere in the tree. 'version' is adminConsentRequestPolicy's write
    # counter; 'policyVersion' is the authentication methods policy's.
    return @('createdDateTime', 'modifiedDateTime', 'lastModifiedDateTime', 'lastModifiedBy', 'deletedDateTime',
        '@odata.context', '@odata.id', '@odata.etag', 'version', 'policyVersion', 'policyMigrationState')
}

function Get-OrderSensitiveKey {
    # Arrays whose ORDER is the setting; every other scalar array is a set
    # and is sorted. Approval stages run in sequence; the identity-provider
    # precedence order is a precedence.
    return @('approvalStages', 'primaryIdentityProviderPrecedenceOrder')
}

function Get-ObjectIdHash {
    # 'h:' + 16 hex of SHA-256 of the lowercase value. Stable across runs, so
    # a public baseline and a public snapshot compare equal when the tenant
    # has not moved; nothing in a public folder resolves to an object.
    param([Parameter(Mandatory)][string]$Value)
    $bytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant()))
    return 'h:' + ([Convert]::ToHexString($bytes).Substring(0, 16).ToLowerInvariant())
}

function ConvertTo-ScrubbedString {
    # Personal identifiers never reach the file: anything shaped like an
    # email / UPN becomes '[redacted]' in every mode. With -Public every GUID
    # inside the string (an id, or a composite policy id, or a reviewer
    # query) becomes its hash.
    param([AllowEmptyString()][string]$Value, [bool]$HashIds)
    $guidPattern = '[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
    $emailPattern = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    $s = [regex]::Replace($Value, $emailPattern, '[redacted]')
    if ($HashIds) { $s = [regex]::Replace($s, $guidPattern, { param($m) Get-ObjectIdHash -Value $m.Value }) }
    return $s
}

function ConvertTo-StableConfig {
    # The normalised shape of one Graph object or collection (see
    # NORMALISATION in the header): volatile fields out, identifiers scrubbed
    # (hashed with -Public), keys sorted, set-like arrays sorted, object
    # arrays ordered by id / displayName / canonical JSON. Deterministic.
    param($Value, [bool]$HashIds = $false, [string]$Key = '')
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (ConvertTo-ScrubbedString -Value $Value -HashIds $HashIds) }
    if ($Value -is [System.Collections.IDictionary]) {
        $volatile = Get-VolatileFieldName
        $out = [ordered]@{}
        foreach ($k in @($Value.Keys | Sort-Object -Culture 'en-US' -CaseSensitive)) {
            if ($k -in $volatile) { continue }
            if ("$k" -like '@odata*') { continue }   # Graph annotations carry the tenant id in a URL; never part of the configuration
            if ($k -eq 'notificationRecipients') {
                # Mailboxes are personal identifiers; the count still shows a
                # recipient added or removed.
                $out['notificationRecipientCount'] = @($Value[$k] | Where-Object { $null -ne $_ }).Count
                continue
            }
            if ($k -eq 'cidrAddress' -and $HashIds) { $out[$k] = Get-ObjectIdHash -Value ([string]$Value[$k]); continue }
            $out[$k] = ConvertTo-StableConfig -Value $Value[$k] -HashIds $HashIds -Key $k
        }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($i in $Value) { ConvertTo-StableConfig -Value $i -HashIds $HashIds -Key $Key })
        if ($Key -in (Get-OrderSensitiveKey)) { return , $items }
        $dicts = @($items | Where-Object { $_ -is [System.Collections.IDictionary] })
        if ($dicts.Count -eq 0) { return , @($items | Sort-Object -Culture 'en-US' -CaseSensitive) }
        if ($dicts.Count -ne $items.Count) { return , $items }
        $sorted = @($items | Sort-Object -Culture 'en-US' -CaseSensitive -Property @(
                @{ Expression = { if ($_.Contains('displayName')) { [string]$_['displayName'] } else { '' } } },
                @{ Expression = { if ($_.Contains('id')) { [string]$_['id'] } else { '' } } },
                @{ Expression = { $_ | ConvertTo-Json -Depth 30 -Compress } }))
        return , $sorted
    }
    return $Value
}

function ConvertTo-CanonicalJson {
    # The bytes that are hashed: the stable shape, pretty-printed, LF only.
    param($Value)
    return ((ConvertTo-Json -InputObject $Value -Depth 30) -replace "`r`n", "`n")
}

function Test-PublicRecordSafe {
    # Same rule as 09-SoD-Report.ps1 / Invoke-BreakGlassDrill.ps1: a public
    # record must not carry an email/UPN, IP address, GUID or onmicrosoft
    # domain. Emits the offending strings; nothing = safe.
    param([string]$Json)
    $bad = @()
    foreach ($p in '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', '\b\d{1,3}(\.\d{1,3}){3}\b', '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '(?i)onmicrosoft\.com') {
        foreach ($m in [regex]::Matches($Json, $p)) { $bad += $m.Value }
    }
    return @($bad | Sort-Object -Unique)
}

function Test-PublicEvidencePath {
    # True when the path is inside lab/evidence but not lab/evidence/out
    # (the gitignored tree). Offline output is refused there.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$EvidenceRoot)
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $root = [System.IO.Path]::GetFullPath($EvidenceRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $out = Join-Path $root 'out'
    if (-not ($full -eq $root -or $full.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::Ordinal))) { return $false }
    return -not ($full -eq $out -or $full.StartsWith($out + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::Ordinal))
}

function Get-BreakGlassFact {
    # Pure: the facts the baseline check (01-Verify-Baseline.ps1 [4/7]) treats
    # as invariants, from already-read objects. Members are counted, never
    # named; the group id is scrubbed by the caller like every other id.
    param([AllowNull()]$Group, [AllowEmptyCollection()][object[]]$Members = @(), [AllowEmptyCollection()][object[]]$GlobalAdminAssignments = @(),
        [AllowEmptyCollection()][object[]]$Policies = @())
    $facts = [ordered]@{
        groupFound               = ($null -ne $Group)
        groupId                  = $(if ($Group) { [string]$Group['id'] } else { $null })
        isAssignableToRole       = $(if ($Group) { [bool](Get-Field $Group @('isAssignableToRole')) } else { $null })
        memberCount              = @($Members).Count
        enabledMemberCount       = @($Members | Where-Object { $_ -and (Get-Field $_ @('accountEnabled')) -ne $false }).Count
        holdsGlobalAdministrator = (@($GlobalAdminAssignments).Count -gt 0)
        excludedFromPolicies     = @()
        notExcludedFromPolicies  = @()
    }
    $gid = $facts['groupId']
    $yes = [System.Collections.Generic.List[string]]::new(); $no = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $Policies) {
        if (-not $p) { continue }
        $name = [string](Get-Field $p @('displayName'))
        $ex = @(Get-Field $p @('conditions', 'users', 'excludeGroups'))
        if ($gid -and $gid -in $ex) { $yes.Add($name) } else { $no.Add($name) }
    }
    $facts['excludedFromPolicies'] = @($yes | Sort-Object -Culture 'en-US' -CaseSensitive)
    $facts['notExcludedFromPolicies'] = @($no | Sort-Object -Culture 'en-US' -CaseSensitive)
    return $facts
}

function Get-WellKnownRoleName {
    # Directory role template id -> name, for the roles the lab's tier map
    # names (08-Measure-KPIs.ps1 Get-RoleTierMap; tests check the two agree).
    # Template ids are Microsoft constants, identical in every tenant, but a
    # public snapshot hashes every GUID, so the NAME is what keys the item.
    param([Parameter(Mandatory)][string]$TemplateId)
    $map = @{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        '0526716b-113d-4c15-b2c8-68e3c22b9f80' = 'Authentication Policy Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' = 'Groups Administrator'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
        '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
        '4d6ac14f-3453-41d0-bef9-a3e0c569773a' = 'License Administrator'
        '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e' = 'Identity Governance Administrator'
        '59d46f88-662b-457b-bceb-5c3809e5908f' = 'Lifecycle Workflows Administrator'
    }
    $k = $TemplateId.ToLowerInvariant()
    if ($map.ContainsKey($k)) { return $map[$k] }
    return "role $(Get-ObjectIdHash -Value $k)"
}

function Get-FixtureResponse {
    # -Offline: the fixture entry whose URI fragment is the LONGEST one
    # contained in the requested URI (so '/{id}/combinationConfigurations'
    # wins over the list). A URI nothing answers throws, like a 404 would.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Responses, [Parameter(Mandatory)][string]$Uri)
    $decoded = [uri]::UnescapeDataString($Uri)
    $best = $null
    foreach ($k in $Responses.Keys) {
        if ($decoded.Contains([string]$k, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($null -eq $best -or ([string]$k).Length -gt $best.Length) { $best = [string]$k }
        }
    }
    if ($null -eq $best) { throw "fixture has no response for $Uri" }
    return $Responses[$best]
}

# =============================================================================
# COLLECTORS (I/O). Each section catches its own failure.
# =============================================================================
$graph = 'https://graph.microsoft.com/v1.0'
$evidenceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'evidence'))
if (-not $OutputDirectory) {
    $OutputDirectory = if ($Offline) { Join-Path $evidenceRoot 'out' 'config-snapshots' } else { Join-Path $evidenceRoot 'config-snapshots' }
}
if ($Offline -and (Test-PublicEvidencePath -Path $OutputDirectory -EvidenceRoot $evidenceRoot)) {
    throw "-Offline output must not go into the public evidence tree ($OutputDirectory): a fixture replay is not tenant evidence. Use lab/evidence/out/config-snapshots."
}
if (-not $Offline -and -not $Public -and (Test-PublicEvidencePath -Path $OutputDirectory -EvidenceRoot $evidenceRoot)) {
    throw "A snapshot with object ids must not go into the public evidence tree ($OutputDirectory): add -Public, or write to lab/evidence/out/."
}

$fixture = $null
if ($Offline) {
    if (-not (Test-Path -LiteralPath $FixturePath -PathType Leaf)) { throw "-FixturePath '$FixturePath' not found." }
    $fixture = Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json -AsHashtable -Depth 50
    if (-not ($fixture -is [System.Collections.IDictionary]) -or -not $fixture.Contains('responses')) { throw "Fixture $FixturePath has no 'responses' map." }
    Write-Console 'OFFLINE: replaying the committed fixture. Nothing here is tenant evidence.' -ForegroundColor DarkYellow
}

function Invoke-Graph {
    param([Parameter(Mandatory)][string]$Uri)
    if ($Offline) { return (Get-FixtureResponse -Responses $fixture['responses'] -Uri $Uri) }
    return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable
}
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-Graph -Uri $next
        if (-not ($page -is [System.Collections.IDictionary]) -or -not $page.Contains('value')) { throw "unexpected response shape (no 'value') from $next" }
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $items.ToArray()
}
function Get-GroupByMailNickname {
    param([Parameter(Mandatory)][string]$MailNickname)
    $f = [uri]::EscapeDataString("mailNickname eq '$MailNickname'")
    return @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id,displayName,mailNickname,isAssignableToRole") | Select-Object -First 1
}

$requiredScopes = @('Policy.Read.All', 'RoleManagementPolicy.Read.Directory', 'RoleManagementPolicy.Read.AzureADGroup', 'Group.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory')
if (-not $Offline) {
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser), or use -Offline.' }
    $ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
    if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Sections needing them are recorded as failed, never as empty." }
}

$now = (Get-Date).ToUniversalTime()
$sections = [ordered]@{}
$hashIds = [bool]$Public

function Read-Section {
    # Runs one collector; its result (already normalised by the collector)
    # becomes { status: ok, ... } or { status: failed, error } - the error
    # message scrubbed like any other string, because Graph errors can quote
    # the caller's UPN.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Read)
    Write-Host ("  {0,-30} " -f $Name) -NoNewline
    try {
        $body = & $Read
        $entry = [ordered]@{ status = 'ok' }
        foreach ($k in $body.Keys) { $entry[$k] = $body[$k] }
        $sections[$Name] = $entry
        Write-Host 'ok' -ForegroundColor Green
    }
    catch {
        $msg = ConvertTo-ScrubbedString -Value $_.Exception.Message -HashIds $hashIds
        $sections[$Name] = [ordered]@{ status = 'failed'; error = $msg }
        Write-Host "FAILED: $msg" -ForegroundColor Red
    }
}

Write-Console "Exporting identity configuration ($(if ($Offline) { 'offline fixture' } else { 'tenant' }); identifiers $(if ($Public) { 'hashed' } else { 'object ids' }))..." -ForegroundColor Cyan

$rawCache = @{}   # raw reads a later section needs (breakGlass reads the CA policies)
Read-Section 'conditionalAccessPolicies' {
    $rawCache['caPolicies'] = @(Get-GraphCollection -Uri "$graph/identity/conditionalAccess/policies")
    [ordered]@{ count = @($rawCache['caPolicies']).Count; items = (ConvertTo-StableConfig -Value @($rawCache['caPolicies']) -HashIds $hashIds -Key 'items') }
}

Read-Section 'namedLocations' {
    $raw = @(Get-GraphCollection -Uri "$graph/identity/conditionalAccess/namedLocations")
    [ordered]@{ count = $raw.Count; items = (ConvertTo-StableConfig -Value $raw -HashIds $hashIds -Key 'items') }
}

Read-Section 'authenticationStrengths' {
    $raw = @(Get-GraphCollection -Uri "$graph/policies/authenticationStrengthPolicies")
    foreach ($s in $raw) {
        # The FIDO2 AAGUID allow-list lives in a child collection; a strength
        # whose combinations cannot be read fails the whole section.
        $s['combinationConfigurations'] = @(Get-GraphCollection -Uri "$graph/policies/authenticationStrengthPolicies/$([string]$s['id'])/combinationConfigurations")
    }
    [ordered]@{ count = $raw.Count; items = (ConvertTo-StableConfig -Value $raw -HashIds $hashIds -Key 'items') }
}

Read-Section 'authenticationMethodsPolicy' {
    $raw = Invoke-Graph -Uri "$graph/policies/authenticationMethodsPolicy"
    if (-not ($raw -is [System.Collections.IDictionary]) -or -not $raw.Contains('authenticationMethodConfigurations')) { throw 'unexpected response shape (no authenticationMethodConfigurations)' }
    [ordered]@{ policy = (ConvertTo-StableConfig -Value $raw -HashIds $hashIds) }
}

Read-Section 'pimDirectoryRolePolicies' {
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($roleId in $DirectoryRoleTemplateIds) {
        $f = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$roleId'")
        $rows = @(Get-GraphCollection -Uri "$graph/policies/roleManagementPolicyAssignments?`$filter=$f&`$expand=policy(`$expand=rules)")
        if ($rows.Count -eq 0) { throw "no roleManagementPolicyAssignment for role $roleId at scope '/' (PIM not licensed, or the read is not allowed)" }
        foreach ($r in $rows) {
            if (-not (Get-Field $r @('policy', 'rules'))) { throw "policy rules not returned inline for role $roleId (verify: `$expand=policy(`$expand=rules))" }
            $r['roleDisplayName'] = Get-WellKnownRoleName -TemplateId $roleId
            $items.Add($r)
        }
    }
    [ordered]@{ count = $items.Count; items = (ConvertTo-StableConfig -Value $items.ToArray() -HashIds $hashIds -Key 'items') }
}

Read-Section 'pimGroupPolicies' {
    $groups = [System.Collections.Generic.List[object]]::new()
    $pf = [uri]::EscapeDataString("startswith(mailNickname,'$PimTierGroupPrefix')")
    foreach ($g in @(Get-GraphCollection -Uri "$graph/groups?`$filter=$pf&`$select=id,displayName,mailNickname")) { $groups.Add($g) }
    foreach ($nick in $PimGroupMailNicknames) {
        $g = Get-GroupByMailNickname -MailNickname $nick
        if ($g) { $groups.Add($g) } else { throw "PIM group '$nick' not found (a missing governed group is drift, not an empty list)" }
    }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($g in ($groups | Sort-Object { [string]$_['mailNickname'] })) {
        $gid = [string]$g['id']
        $f = [uri]::EscapeDataString("scopeId eq '$gid' and scopeType eq 'Group'")
        $rows = @(Get-GraphCollection -Uri "$graph/policies/roleManagementPolicyAssignments?`$filter=$f&`$expand=policy(`$expand=rules)")
        if ($rows.Count -eq 0) { throw "no PIM policy assignment for group $([string]$g['mailNickname']) (not PIM-governed, or the read is not allowed)" }
        foreach ($r in $rows) {
            if (-not (Get-Field $r @('policy', 'rules'))) { throw "policy rules not returned inline for group $([string]$g['mailNickname'])" }
            # The group's mailNickname is the stable, public-safe key; the
            # composite assignment id (tenant id + policy id) is hashed with -Public.
            $r['groupMailNickname'] = [string]$g['mailNickname']
            $r['groupDisplayName'] = [string]$g['displayName']
            $items.Add($r)
        }
    }
    [ordered]@{ count = $items.Count; groups = @($groups | ForEach-Object { [string]$_['mailNickname'] } | Sort-Object -Culture 'en-US' -CaseSensitive); items = (ConvertTo-StableConfig -Value $items.ToArray() -HashIds $hashIds -Key 'items') }
}

Read-Section 'consentPolicy' {
    $authz = Invoke-Graph -Uri "$graph/policies/authorizationPolicy"
    if (-not ($authz -is [System.Collections.IDictionary]) -or -not $authz.Contains('defaultUserRolePermissions')) { throw 'authorizationPolicy: unexpected response shape' }
    $acr = Invoke-Graph -Uri "$graph/policies/adminConsentRequestPolicy"
    if (-not ($acr -is [System.Collections.IDictionary]) -or -not $acr.Contains('isEnabled')) { throw 'adminConsentRequestPolicy: unexpected response shape' }
    [ordered]@{ authorizationPolicy = (ConvertTo-StableConfig -Value $authz -HashIds $hashIds); adminConsentRequestPolicy = (ConvertTo-StableConfig -Value $acr -HashIds $hashIds) }
}

Read-Section 'appManagementPolicy' {
    $raw = Invoke-Graph -Uri "$graph/policies/defaultAppManagementPolicy"
    if (-not ($raw -is [System.Collections.IDictionary]) -or -not $raw.Contains('applicationRestrictions')) { throw 'defaultAppManagementPolicy: unexpected response shape' }
    [ordered]@{ policy = (ConvertTo-StableConfig -Value $raw -HashIds $hashIds) }
}

Read-Section 'crossTenantAccessDefaults' {
    $raw = Invoke-Graph -Uri "$graph/policies/crossTenantAccessPolicy/default"
    if (-not ($raw -is [System.Collections.IDictionary]) -or -not $raw.Contains('b2bCollaborationInbound')) { throw 'crossTenantAccessPolicy/default: unexpected response shape' }
    [ordered]@{ policy = (ConvertTo-StableConfig -Value $raw -HashIds $hashIds) }
}

Read-Section 'breakGlass' {
    if ($sections['conditionalAccessPolicies']['status'] -ne 'ok') { throw 'Conditional Access policies could not be read, so the exclusion facts cannot be established' }
    $g = Get-GroupByMailNickname -MailNickname $BreakGlassGroupMailNickname
    $members = @(); $ga = @()
    if ($g) {
        $members = @(Get-GraphCollection -Uri "$graph/groups/$([string]$g['id'])/members?`$select=id,accountEnabled")
        $f = [uri]::EscapeDataString("roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10' and principalId eq '$([string]$g['id'])'")
        $ga = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleAssignments?`$filter=$f")
    }
    $facts = Get-BreakGlassFact -Group $g -Members $members -GlobalAdminAssignments $ga -Policies @($rawCache['caPolicies'])
    [ordered]@{ groupMailNickname = $BreakGlassGroupMailNickname; facts = (ConvertTo-StableConfig -Value $facts -HashIds $hashIds) }
}

# =============================================================================
# SNAPSHOT
# =============================================================================
$failed = @($sections.Keys | Where-Object { $sections[$_]['status'] -eq 'failed' })
$snapshot = [ordered]@{
    schema         = 'contoso-identity-config/v1'
    label          = $Label
    generatedAtUtc = $now.ToString('o')
    generator      = 'lab/scripts/powershell/Export-IdentityConfig.ps1'
    source         = $(if ($Offline) { 'offline-fixture' } else { 'tenant' })
    public         = [bool]$Public
    identifiers    = $(if ($Public) { 'hashed: h: + 16 hex of SHA-256 of the lowercase object id / CIDR' } else { 'object ids (not for the public evidence tree)' })
    parameters     = [ordered]@{
        breakGlassGroupMailNickname = $BreakGlassGroupMailNickname; pimTierGroupPrefix = $PimTierGroupPrefix; pimGroupMailNicknames = @($PimGroupMailNicknames)
        directoryRoles              = @($DirectoryRoleTemplateIds | ForEach-Object { Get-WellKnownRoleName -TemplateId $_ })
        directoryRoleTemplateIds    = (ConvertTo-StableConfig -Value @($DirectoryRoleTemplateIds) -HashIds $hashIds)   # Microsoft constants, hashed all the same with -Public
    }
    failedSections = @($failed)
    sections       = $sections
}
if ($Offline) { $snapshot['fixture'] = [ordered]@{ name = (Split-Path -Leaf $FixturePath); sha256 = (Get-FileHash -LiteralPath $FixturePath -Algorithm SHA256).Hash.ToLowerInvariant() } }

$json = ConvertTo-CanonicalJson -Value $snapshot
if ($Public) {
    $unsafe = @(Test-PublicRecordSafe -Json $json)
    if ($unsafe.Count) { throw "Public snapshot still carries an identifier ($($unsafe.Count) string(s)); nothing written. First: $($unsafe[0])" }
}

$stamp = $now.ToString('yyyyMMddTHHmmssZ')
$dir = [System.IO.Path]::GetFullPath($OutputDirectory)
$file = Join-Path $dir "$stamp.json"
if ($PSCmdlet.ShouldProcess($file, 'write configuration snapshot (+ SHA256SUMS line)')) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($file, $json + "`n", [System.Text.UTF8Encoding]::new($false))
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    # sha256sum format, one line per snapshot, so `shasum -a 256 -c SHA256SUMS`
    # verifies the whole folder; a re-written stamp replaces its own line.
    $sums = Join-Path $dir 'SHA256SUMS'
    $lines = @(); if (Test-Path -LiteralPath $sums) { $lines = @(Get-Content -LiteralPath $sums | Where-Object { $_ -and $_ -notmatch "\s$([regex]::Escape("$stamp.json"))$" }) }
    $lines += "$hash  $stamp.json"
    [System.IO.File]::WriteAllText($sums, (($lines | Sort-Object -Culture 'en-US' -CaseSensitive) -join "`n") + "`n", [System.Text.UTF8Encoding]::new($false))
    $snapshot['file'] = [ordered]@{ path = $file; sha256 = $hash }
    Write-Console "`nSnapshot: $file (sha256 $hash)" -ForegroundColor Cyan
}

if ($failed.Count) {
    Write-Console "$($failed.Count) section(s) FAILED: $($failed -join ', ') - recorded as failed, not as empty (exit 1)." -ForegroundColor Red
    [pscustomobject]$snapshot
    exit 1
}
return [pscustomobject]$snapshot
