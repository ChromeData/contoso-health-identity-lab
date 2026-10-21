<#
.SYNOPSIS
    Writes the two tenant objects Terraform renders but cannot create for PIM
    activation step-up: the Conditional Access authentication context (c1)
    and CA021, the policy that targets it. Idempotent; supports -WhatIf.

.DESCRIPTION
    azuread 3.10 has no authenticationContextClassReference resource and
    cannot target an authentication context from a CA policy, so
    modules/conditional-access (admins.tf) renders both Graph request bodies
    from real ids into the output pim_auth_context_requests, and this script
    sends them. The DEFINITION stays code-reviewed in Terraform; only the
    HTTP calls happen here (same pattern as New-AccessReviewDefinitions.ps1).

    REFUSES TO RUN when the output is null (enable_pim_auth_context = false).

    SECOND USE - CA023 (protected actions): the same shape is rendered as
    output protected_actions_auth_context_requests (auth context c2, policy
    key CA023, enable_protected_actions_ca). Run this script with that file
    as -RequestsPath: every check below applies unchanged (only the key and
    context differ). Binding c2 to the protected actions themselves is a
    separate TENANT-TIME step (Invoke-PostApply.ps1 prints it), done only
    once CA023 is ENFORCED.

    Order of work:
      0. Validate the rendered request before touching the tenant - it is an
         input file, so a hand-edited or stale body is refused, never sent:
         auth context id c1..c25 and published (isAvailable = true); CA021
         targets ONLY that context (no apps, no groups - never the PIM group
         itself), includes All users, excludes break-glass, grants with an
         authentication strength by bare id and no built-in control, and
         forces sign-in frequency "every time".
      1. Tenant pre-flight (read only): the break-glass group (looked up by
         mailNickname) must be in CA021's excludeGroups, and the strength
         CA021 grants with must allow phishing-resistant methods ONLY.
      2. Authentication context: PATCH
         /identity/conditionalAccess/authenticationContextClassReferences/<id>
         (create-or-update). Equal = no write. An id already in use under a
         different displayName is REFUSED (it belongs to something else).
      3. CA021: find the policy whose displayName starts with the rendered
         prefix ("CA021 - "). None = POST; one = PATCH when any owned field
         drifts (portal edits are reverted to the code-reviewed body); more
         than one, or a match that is not an auth-context policy = REFUSED.
         Never deletes.
    Each step emits one result object (Target, Action, Drift, Id).

    ORDERING WITH PIM (Learn): create and ENABLE CA021 before PIM requires
    the context - PIM's MFA backup is not triggered while the context's
    policy is report-only or off (Learn, PIM for Groups role settings), so a
    context without an ENFORCED CA021 means no step-up at all. Terraform
    refuses a plan that hands modules/pim the context unless CA021 is
    declared "enabled" AND the operator attests ca021_enforced_in_tenant =
    true. Set that attestation only after THIS script, run against an apply
    that declared CA021 enabled, reports it enabled in the tenant (the
    closing line says so); then, in a later change, the PIM value.

    CHANGE DETECTION: lab/kql/ca-policy-changed.kql alerts on every CA write
    that is not the CI apply identity - including this script's (delegated)
    writes. That is expected: run it inside the change window and reference
    the PR.

    TENANT-TIME. Nothing here has run against a tenant. verify (first run):
      * Graph v1.0 accepts includeAuthenticationContextClassReferences on
        POST (it is in the live v1.0 $metadata; the v1.0 docs page lists it
        under beta) - otherwise re-run with -GraphVersion beta;
      * whether includeApplications must be present, empty or omitted;
      * sign-in frequency "everyTime" on an auth-context policy (the Graph
        signInFrequencySessionControl page lists a narrower set than Learn);
      * a second run reports Unchanged for both objects (drift compare
        converges against what Graph returns);
      * least-privilege scopes below (GroupMember.Read.All for the group
        lookup; whether POST still wants Policy.Read.All beside
        Policy.ReadWrite.ConditionalAccess).

.PREREQUISITES
    * envs/dev applied with enable_premium and the module's
      enable_pim_auth_context = true.
    * terraform -chdir=lab/terraform/envs/dev output -json pim_auth_context_requests > ca021.json
      (a full `terraform output -json` file is accepted too).
    * Role: Conditional Access Administrator (or Security Administrator).

.GRAPH SCOPES  (delegated)
    Policy.Read.All                     read policies, contexts, strengths (also -WhatIf)
    Policy.ReadWrite.ConditionalAccess  write the context and CA021 (not needed for -WhatIf)
    GroupMember.Read.All                resolve break-glass by mailNickname

.PARAMETER RequestsPath
    JSON from `terraform output -json pim_auth_context_requests`, or a full
    `terraform output -json` file (the pim_auth_context_requests entry is
    unwrapped).

.PARAMETER GraphVersion
    v1.0 (default) or beta, for the Conditional Access endpoints only.

.PARAMETER BreakGlassGroupMailNickname
    Default break-glass-admins (Terraform contract, modules/groups).

.EXAMPLE
    terraform -chdir=lab/terraform/envs/dev output -json pim_auth_context_requests > ca021.json
    ./Set-AuthContextPolicies.ps1 -RequestsPath ./ca021.json -WhatIf     # offline preview (no Graph session) or tenant plan
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.ConditionalAccess','GroupMember.Read.All'
    ./Set-AuthContextPolicies.ps1 -RequestsPath ./ca021.json -WhatIf     # reads the tenant, writes nothing
    ./Set-AuthContextPolicies.ps1 -RequestsPath ./ca021.json             # prompts (ConfirmImpact High)
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$RequestsPath,

    [Parameter()]
    [ValidateSet('v1.0', 'beta')]
    [string]$GraphVersion = 'v1.0',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins'
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

$graphV1 = 'https://graph.microsoft.com/v1.0'
$caBase = "https://graph.microsoft.com/$GraphVersion/identity/conditionalAccess"

# =============================================================================
# Pure helpers (unit-tested without a tenant)
# =============================================================================
function Read-AuthContextRequest {
    # Returns a hashtable with the parsed request, or $null when the output is
    # null (enable_pim_auth_context = false). Accepts the single-output JSON
    # or a full `terraform output -json`.
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if ($null -eq $raw) { return $null }
    if ($raw -isnot [System.Collections.IDictionary]) { throw "$Path is not a JSON object." }
    if ($raw.Contains('pim_auth_context_requests')) {
        $entry = $raw['pim_auth_context_requests']
        $raw = if ($entry -is [System.Collections.IDictionary] -and $entry.Contains('value')) { $entry['value'] } else { $entry }
        if ($null -eq $raw) { return $null }
    }
    foreach ($k in 'auth_context_id', 'auth_context_body', 'policy_match_prefix', 'policy_display_name', 'policy_state', 'policy_body') {
        if (-not $raw.Contains($k)) { throw "$Path has no '$k' - is it the pim_auth_context_requests output of modules/conditional-access?" }
    }
    # Terraform renders the bodies as JSON strings; tolerate parsed objects.
    $parse = { param($v) if ($v -is [string]) { $v | ConvertFrom-Json -AsHashtable } else { $v } }
    return @{
        PolicyKey         = if ($raw.Contains('policy_key')) { [string]$raw['policy_key'] } else { 'CA021' }
        AuthContextId     = [string]$raw['auth_context_id']
        AuthContextBody   = & $parse $raw['auth_context_body']
        PolicyMatchPrefix = [string]$raw['policy_match_prefix']
        PolicyDisplayName = [string]$raw['policy_display_name']
        PolicyState       = [string]$raw['policy_state']
        PolicyBody        = & $parse $raw['policy_body']
    }
}

function Get-MapValue {
    # Nested lookup that tolerates missing keys: Get-MapValue $h 'a','b'.
    param($Map, [string[]]$Path)
    $cur = $Map
    foreach ($p in $Path) {
        if ($cur -isnot [System.Collections.IDictionary] -or -not $cur.Contains($p)) { return $null }
        $cur = $cur[$p]
    }
    return $cur
}

function Test-AuthContextRequest {
    # Lists every reason the rendered request must NOT be sent. Empty = ok.
    param([Parameter(Mandatory)][hashtable]$Request)
    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $ContextIdPattern = '^c([1-9]|1[0-9]|2[0-5])$'   # Graph documents c1..c25
    $problems = [System.Collections.Generic.List[string]]::new()
    $id = $Request.AuthContextId
    $ctx = $Request.AuthContextBody
    $p = $Request.PolicyBody
    $prefix = $Request.PolicyMatchPrefix

    if ($id -notmatch $ContextIdPattern) { $problems.Add("auth context id '$id' is not c1..c25") }
    if ($ctx -isnot [System.Collections.IDictionary]) { $problems.Add('auth context body is not an object'); $ctx = @{} }
    if ((Get-MapValue $ctx 'isAvailable') -ne $true) { $problems.Add('auth context must be published (isAvailable = true) or PIM cannot use it') }
    if ([string]::IsNullOrWhiteSpace([string](Get-MapValue $ctx 'displayName'))) { $problems.Add('auth context displayName is empty') }

    if ($p -isnot [System.Collections.IDictionary]) { $problems.Add('policy body is not an object'); return $problems.ToArray() }
    if ([string]::IsNullOrWhiteSpace($prefix) -or -not $prefix.EndsWith(' - ')) { $problems.Add("policy match prefix '$prefix' must look like 'CA021 - '") }
    $name = [string](Get-MapValue $p 'displayName')
    if (-not $prefix -or -not $name.StartsWith($prefix, [System.StringComparison]::Ordinal)) { $problems.Add("policy displayName '$name' does not start with '$prefix'") }
    if ($name -ne $Request.PolicyDisplayName) { $problems.Add('policy displayName differs from policy_display_name') }
    $state = [string](Get-MapValue $p 'state')
    if ($state -notin 'enabled', 'disabled', 'enabledForReportingButNotEnforced') { $problems.Add("policy state '$state' is not a Conditional Access state") }
    if ($state -ne $Request.PolicyState) { $problems.Add('policy body state differs from policy_state') }

    $refs = @(Get-MapValue $p 'conditions', 'applications', 'includeAuthenticationContextClassReferences' | Where-Object { $_ })
    if ($refs.Count -ne 1 -or $refs[0] -ne $id) { $problems.Add("policy must target exactly the auth context '$id' (found: $($refs -join ','))") }
    if (@(Get-MapValue $p 'conditions', 'applications', 'includeApplications' | Where-Object { $_ }).Count) { $problems.Add('policy must not target applications as well as the auth context') }

    $inc = @(Get-MapValue $p 'conditions', 'users', 'includeUsers' | Where-Object { $_ })
    if ($inc.Count -ne 1 -or $inc[0] -ne 'All') { $problems.Add('policy must include All users (Learn: never the PIM group, the requester is not a member yet)') }
    foreach ($k in 'includeGroups', 'includeRoles') {
        if (@(Get-MapValue $p 'conditions', 'users', $k | Where-Object { $_ }).Count) { $problems.Add("policy must not set users.$k") }
    }
    $ex = @(Get-MapValue $p 'conditions', 'users', 'excludeGroups' | Where-Object { $_ })
    if ($ex.Count -eq 0) { $problems.Add('policy must exclude the break-glass group') }
    foreach ($g in $ex) { if ([string]$g -notmatch $GuidPattern) { $problems.Add("excludeGroups entry '$g' is not a group object id") } }

    $sid = [string](Get-MapValue $p 'grantControls', 'authenticationStrength', 'id')
    if ($sid -notmatch $GuidPattern) { $problems.Add("grant must use an authentication strength by bare object id (got '$sid')") }
    if (@(Get-MapValue $p 'grantControls', 'builtInControls' | Where-Object { $_ }).Count) { $problems.Add('grant must not combine built-in controls (e.g. mfa) with the authentication strength') }

    if ((Get-MapValue $p 'sessionControls', 'signInFrequency', 'isEnabled') -ne $true -or
        [string](Get-MapValue $p 'sessionControls', 'signInFrequency', 'frequencyInterval') -ne 'everyTime') {
        $problems.Add('policy must force sign-in frequency "everyTime" (a fresh sign-in per activation)')
    }
    # Unrolled on purpose (callers wrap in @()): a comma-return would nest an
    # empty list inside @() as one element.
    return $problems.ToArray()
}

function Add-FlatValue {
    # Flattens a Graph object into path -> canonical string, dropping nulls,
    # empty strings, empty arrays and OData annotations, so "unset" and
    # "null" compare equal and arrays compare order-independently.
    param($Value, [string]$Prefix, [hashtable]$Map)
    if ($null -eq $Value) { return }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in $Value.Keys) {
            # Annotations: '@odata.context', and 'authenticationStrength@odata.context'.
            if ([string]$k -like '*@odata*') { continue }
            Add-FlatValue -Value $Value[$k] -Prefix ($(if ($Prefix) { "$Prefix.$k" } else { [string]$k })) -Map $Map
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
        if ($items.Count -eq 0) { return }
        $Map[$Prefix] = (@($items | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { $_ | ConvertTo-Json -Depth 10 -Compress } else { [string]$_ } }) | Sort-Object) -join '|'
        return
    }
    if ($Value -is [bool]) { $Map[$Prefix] = $Value.ToString().ToLowerInvariant(); return }
    if ([string]$Value -eq '') { return }
    $Map[$Prefix] = [string]$Value
}

function Get-CaPolicyDrift {
    # Owned fields of CA021 that differ between the rendered body and the
    # tenant. Anything the tenant carries that the body does not (an added
    # location, exclusion, platform, session control) is drift too.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Desired, [Parameter(Mandatory)][System.Collections.IDictionary]$Current)
    $d = @{}; $c = @{}
    foreach ($section in 'displayName', 'state', 'conditions', 'grantControls', 'sessionControls') {
        $dv = if ($Desired.Contains($section)) { $Desired[$section] } else { $null }
        $cv = if ($Current.Contains($section)) { $Current[$section] } else { $null }
        if ($section -eq 'grantControls' -and $cv -is [System.Collections.IDictionary]) {
            # Graph expands the strength object on GET; only its id is owned.
            $copy = @{}; foreach ($k in $cv.Keys) { $copy[$k] = $cv[$k] }
            $s = $copy['authenticationStrength']
            if ($s -is [System.Collections.IDictionary]) { $copy['authenticationStrength'] = @{ id = $s['id'] } }
            $cv = $copy
        }
        Add-FlatValue -Value $dv -Prefix $section -Map $d
        Add-FlatValue -Value $cv -Prefix $section -Map $c
    }
    # Emits the drifted paths unrolled; callers wrap in @().
    foreach ($k in @(@($d.Keys) + @($c.Keys) | Sort-Object -Unique)) {
        if (-not $d.ContainsKey($k) -or -not $c.ContainsKey($k) -or $d[$k] -cne $c[$k]) { $k }
    }
}

function Get-AuthContextDrift {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Desired, [Parameter(Mandatory)][System.Collections.IDictionary]$Current)
    # Emits the drifted fields unrolled; callers wrap in @().
    foreach ($k in 'displayName', 'description', 'isAvailable') {
        $dv = if ($Desired.Contains($k)) { [string]$Desired[$k] } else { '' }
        $cv = if ($Current.Contains($k)) { [string]$Current[$k] } else { '' }
        if ($dv -cne $cv) { $k }
    }
}

function Test-PhishingResistantStrength {
    # True when every allowed combination is phishing-resistant.
    param([object[]]$AllowedCombinations)
    $PhishingResistantCombinations = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor')
    $all = @($AllowedCombinations | Where-Object { $_ })
    return ($all.Count -gt 0 -and @($all | Where-Object { $_ -notin $PhishingResistantCombinations }).Count -eq 0)
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    # Unrolled on purpose: callers wrap the call in @().
    return $items.ToArray()
}

function ConvertTo-StepResult {
    param([string]$Target, [string]$Action, [string[]]$Drift = @(), [string]$Id = '')
    return [pscustomobject]@{ Target = $Target; Action = $Action; Drift = @($Drift); Id = $Id }
}

# =============================================================================
# Main
# =============================================================================
$request = Read-AuthContextRequest -Path $RequestsPath
if ($null -eq $request) {
    throw "No CA021 request in ${RequestsPath}: pim_auth_context_requests is null, i.e. enable_pim_auth_context = false in modules/conditional-access. This script only runs for a Terraform-rendered CA021."
}
$problems = @(Test-AuthContextRequest -Request $request)
if ($problems.Count) {
    throw "Refusing to send the rendered CA021 request ($RequestsPath):`n  - $($problems -join "`n  - ")`nRe-render it with terraform output; never hand-edit it."
}

$ctxId = $request.AuthContextId
$ctxBody = $request.AuthContextBody
$policyBody = $request.PolicyBody
$policyName = $request.PolicyDisplayName
$prefix = $request.PolicyMatchPrefix
$key = $request.PolicyKey
Write-Console "$key ($($request.PolicyState)) on authentication context $ctxId - Graph $GraphVersion" -ForegroundColor Cyan

$requiredScopes = @('Policy.Read.All', 'GroupMember.Read.All')
if (-not $WhatIfPreference) { $requiredScopes += 'Policy.ReadWrite.ConditionalAccess' }
$mg = $null; try { $mg = Get-MgContext } catch { $mg = $null }
if (-not $mg) {
    if ($WhatIfPreference) {
        # Offline preview: no Graph session, nothing read or written.
        Write-Console '  [?] no Graph session: offline preview of the two requests (nothing read or written).' -ForegroundColor Yellow
        Write-Console "  PATCH $caBase/authenticationContextClassReferences/$ctxId" -ForegroundColor DarkGray
        Write-Console ($ctxBody | ConvertTo-Json -Depth 10) -ForegroundColor DarkGray
        Write-Console "  POST|PATCH $caBase/policies  ($policyName)" -ForegroundColor DarkGray
        Write-Console ($policyBody | ConvertTo-Json -Depth 20) -ForegroundColor DarkGray
        ConvertTo-StepResult -Target "authenticationContext $ctxId" -Action 'Preview'
        ConvertTo-StepResult -Target $policyName -Action 'Preview'
        return
    }
    Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow
    Connect-MgGraph -Scopes $requiredScopes
    $mg = Get-MgContext
}
$missingScopes = @($requiredScopes | Where-Object { $mg.Scopes -and $_ -notin $mg.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run)." }

# --- 1. Tenant pre-flight (read only; a failed read stops everything) --------
$bg = @(Get-GraphCollection -Uri "$graphV1/groups?`$filter=mailNickname eq '$($BreakGlassGroupMailNickname.Replace("'", "''"))'&`$select=id,displayName")
if ($bg.Count -ne 1) { throw "Break-glass group '$BreakGlassGroupMailNickname' resolved to $($bg.Count) groups - refusing to write a CA policy that cannot be shown to exclude it." }
$bgId = [string]$bg[0]['id']
if (@(Get-MapValue $policyBody 'conditions', 'users', 'excludeGroups') -notcontains $bgId) {
    throw "The rendered $key does not exclude the tenant's break-glass group ($BreakGlassGroupMailNickname). Refusing - re-render from the same state the groups module applied."
}
$strengthId = [string](Get-MapValue $policyBody 'grantControls', 'authenticationStrength', 'id')
$strength = Invoke-MgGraphRequest -Method GET -Uri "$graphV1/policies/authenticationStrengthPolicies/$strengthId" -OutputType HashTable
if (-not (Test-PhishingResistantStrength -AllowedCombinations @($strength['allowedCombinations']))) {
    throw "Authentication strength $strengthId ('$($strength['displayName'])') allows non-phishing-resistant combinations ($(@($strength['allowedCombinations']) -join ', ')). Refusing to gate privileged activation with it."
}
Write-Console "  [=] pre-flight: break-glass excluded, strength '$($strength['displayName'])' is phishing-resistant only" -ForegroundColor DarkGray

# --- 2. Authentication context ----------------------------------------------
$contexts = @(Get-GraphCollection -Uri "$caBase/authenticationContextClassReferences")
$existingCtx = @($contexts | Where-Object { [string]$_['id'] -eq $ctxId }) | Select-Object -First 1
$ctxUri = "$caBase/authenticationContextClassReferences/$ctxId"
$ctxJson = $ctxBody | ConvertTo-Json -Depth 10 -Compress
if (-not $existingCtx) {
    if ($PSCmdlet.ShouldProcess("authentication context $ctxId", 'create (PATCH)')) {
        Invoke-MgGraphRequest -Method PATCH -Uri $ctxUri -Body $ctxJson -ContentType 'application/json' | Out-Null
        Write-Console "  [+] authentication context $ctxId created ('$($ctxBody['displayName'])', published)" -ForegroundColor Green
        ConvertTo-StepResult -Target "authenticationContext $ctxId" -Action 'Created' -Id $ctxId
    }
    else { ConvertTo-StepResult -Target "authenticationContext $ctxId" -Action 'WouldCreate' -Id $ctxId }
}
else {
    if ([string]$existingCtx['displayName'] -cne [string]$ctxBody['displayName']) {
        throw "Authentication context $ctxId already exists as '$($existingCtx['displayName'])' - it belongs to something else. Choose another pim_auth_context_id (and keep modules/pim on the same id), or rename it by hand after checking which policies target it."
    }
    $ctxDrift = @(Get-AuthContextDrift -Desired $ctxBody -Current $existingCtx)
    if ($ctxDrift.Count -eq 0) {
        Write-Console "  [=] authentication context $ctxId in sync" -ForegroundColor DarkGray
        ConvertTo-StepResult -Target "authenticationContext $ctxId" -Action 'Unchanged' -Id $ctxId
    }
    elseif ($PSCmdlet.ShouldProcess("authentication context $ctxId", "update (PATCH: $($ctxDrift -join ', '))")) {
        Invoke-MgGraphRequest -Method PATCH -Uri $ctxUri -Body $ctxJson -ContentType 'application/json' | Out-Null
        Write-Console "  [~] authentication context $ctxId updated ($($ctxDrift -join ', '))" -ForegroundColor Green
        ConvertTo-StepResult -Target "authenticationContext $ctxId" -Action 'Updated' -Drift $ctxDrift -Id $ctxId
    }
    else { ConvertTo-StepResult -Target "authenticationContext $ctxId" -Action 'WouldUpdate' -Drift $ctxDrift -Id $ctxId }
}

# --- 3. CA021 ---------------------------------------------------------------
$found = @(Get-GraphCollection -Uri "$caBase/policies" | Where-Object { ([string]$_['displayName']).StartsWith($prefix, [System.StringComparison]::Ordinal) })
if ($found.Count -gt 1) {
    throw "$($found.Count) policies start with '$prefix' ($(@($found | ForEach-Object { $_['id'] }) -join ', ')) - resolve by hand; numbers are never reused."
}
$policyJson = $policyBody | ConvertTo-Json -Depth 20 -Compress
if ($found.Count -eq 0) {
    if ($PSCmdlet.ShouldProcess($policyName, 'create Conditional Access policy (POST)')) {
        $created = Invoke-MgGraphRequest -Method POST -Uri "$caBase/policies" -Body $policyJson -ContentType 'application/json' -OutputType HashTable
        Write-Console "  [+] '$policyName' created ($($created['id']), state $($policyBody['state']))" -ForegroundColor Green
        ConvertTo-StepResult -Target $policyName -Action 'Created' -Id ([string]$created['id'])
    }
    else { ConvertTo-StepResult -Target $policyName -Action 'WouldCreate' }
}
else {
    $current = $found[0]
    $currentId = [string]$current['id']
    if (@(Get-MapValue $current 'conditions', 'applications', 'includeAuthenticationContextClassReferences' | Where-Object { $_ }).Count -eq 0) {
        throw "'$($current['displayName'])' ($currentId) matches '$prefix' but does not target an authentication context - refusing to overwrite a different policy. Resolve the numbering by hand."
    }
    if (@(Get-MapValue $current 'conditions', 'users', 'excludeGroups') -notcontains $bgId) {
        Write-Warning "  [!] the existing '$($current['displayName'])' does NOT exclude break-glass - the update below restores it."
    }
    $drift = @(Get-CaPolicyDrift -Desired $policyBody -Current $current)
    if ($drift.Count -eq 0) {
        Write-Console "  [=] '$policyName' in sync ($currentId)" -ForegroundColor DarkGray
        ConvertTo-StepResult -Target $policyName -Action 'Unchanged' -Id $currentId
    }
    elseif ($PSCmdlet.ShouldProcess([string]$current['displayName'], "update Conditional Access policy (PATCH: $($drift -join ', '))")) {
        Invoke-MgGraphRequest -Method PATCH -Uri "$caBase/policies/$currentId" -Body $policyJson -ContentType 'application/json' | Out-Null
        Write-Console "  [~] '$policyName' updated ($($drift -join ', '))" -ForegroundColor Green
        ConvertTo-StepResult -Target $policyName -Action 'Updated' -Drift $drift -Id $currentId
    }
    else { ConvertTo-StepResult -Target $policyName -Action 'WouldUpdate' -Drift $drift -Id $currentId }
}

if ($key -ne 'CA021') {
    # CA023 (protected actions): no PIM attestation; the next step is binding the context.
    if ($request.PolicyState -eq 'enabled' -and -not $WhatIfPreference) {
        Write-Console "`n$key is ENFORCED in the tenant. TENANT-TIME next step: bind authentication context '$ctxId' to the protected actions (Conditional Access policy / named-location update + delete) - Invoke-PostApply.ps1 prints the command." -ForegroundColor Cyan
    }
    else {
        Write-Console "`n$key is $($request.PolicyState)$(if ($WhatIfPreference) { ' (dry run: nothing written)' }). Do NOT bind '$ctxId' to the protected actions until $key is enabled in the tenant - a report-only policy behind the context applies no step-up." -ForegroundColor Cyan
    }
}
elseif ($request.PolicyState -eq 'enabled' -and -not $WhatIfPreference) {
    Write-Console "`n$key is ENFORCED in the tenant (written or verified by this run). Next change: ca021_enforced_in_tenant = true; the change after that may set pim_tier0_activation_auth_context_id = '$ctxId' (two applies for existing Tier-0 policies: MFA off first, then the context)." -ForegroundColor Cyan
}
elseif ($request.PolicyState -eq 'enabled') {
    Write-Console "`n$key is declared ENFORCED, but this was a dry run: nothing was written, so do NOT set ca021_enforced_in_tenant yet." -ForegroundColor Cyan
}
else {
    Write-Console "`n$key is $($request.PolicyState). Keep ca021_enforced_in_tenant = false and pim_tier0_activation_auth_context_id empty (Terraform refuses the context until CA021 is enabled AND attested in the tenant)." -ForegroundColor Cyan
}
