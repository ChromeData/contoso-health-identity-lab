<#
.SYNOPSIS
    Creates a real Microsoft Entra Agent ID for the lab: an agent identity
    blueprint, its blueprint principal, a managed-identity federated
    credential (no secret, ever), and one agent identity with an accountable
    human sponsor. Idempotent. Fails closed if the Agent ID API isn't
    available, and never falls back to a plain app registration.

.DESCRIPTION
    Why this exists: the lab's AI pull-request reviewer runs under the PLAN
    pipeline identity. That is a workflow calling a model, not an agent
    identity, and nhi-standard N10 says it must not be presented as one.
    This script gives the lab a real agent identity, built the way Microsoft
    documents it:

      blueprint            (applications/microsoft.graph.agentIdentityBlueprint)
        |- sponsor          the human accountable for the agent (required)
        |- owners           who may change it; the creator is added automatically
        |- credential       federated identity credential: issuer = this tenant,
        |                   subject = a user-assigned managed identity's
        |                   principal id. The agent's runtime gets tokens with
        |                   no stored secret (nhi-standard N2, N3, N7).
        `- blueprint principal (servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal)
      agent identity       (servicePrincipals/microsoft.graph.agentIdentity),
                           created FROM the blueprint, own sponsor. It holds no
                           permissions until they are granted on purpose.

    STATUS - IDENTITY ONLY: no permission is granted and no runtime calls the
    agent yet. Governance (sponsor, owners, secretless credential, lifecycle)
    is what this lab shows; an agent that ACTS needs one read-only grant and a
    runtime on the managed identity, which is future work. The AI PR reviewer
    keeps running under the PLAN identity and is never presented as this agent.

    The scenario agent is "Contoso Access Review Assistant": it would read
    access-review data and draft recommendations for the reviewing manager.
    Recommendations only; the human decides. Its sponsor defaults to Grace
    Mwangi (Nurse Manager), who reviews the nursing access it summarises.

    API STATUS (checked 2026-10-20 on Microsoft Learn): the blueprint, blueprint
    principal and agent identity create calls are documented in Graph v1.0
    (agentidentityblueprint-post, agentidentityblueprintprincipal-post,
    agentidentity-post). The admin-center wizards are still labelled
    "(Preview)". verify before the trial window:
      * licensing: Agent 365 is now required for Conditional Access /
        ID Protection for agents. Whether creating a blueprint needs it too
        isn't stated on the create pages.
      * the federated credential path: the how-to says "<agent-blueprint-id>"
        is the blueprint's appId; this script uses the object id, which is what
        /applications/{id} takes.
      * the Agent 365 registry: Microsoft says agents created through raw Graph
        should also be posted to the Agent Registry API to show up in the
        Microsoft 365 admin center. That call isn't scripted here.
    -AcceptPreview is required for a live run, so nobody starts this by
    accident before those checks.

    FAIL CLOSED, NO SUBSTITUTES:
      * Agent ID endpoints return an error -> stop. The script never creates an
        ordinary app registration "as an agent", which would be exactly the
        relabelling problem N10 exists to prevent.
      * No managed identity principal id -> stop, unless you pass
        -SkipFederatedCredential (the identity then has no way to get a
        token, which is safe but inert). The script never calls addPassword.
      * Sponsor missing or disabled -> stop. An agent without an accountable
        human is OWASP NHI1 on day one.
      * The id given isn't a managed identity -> stop.

    TEARDOWN: -Remove deletes the agent identity, then the blueprint (Microsoft
    says deleting a blueprint also cleans up its agent identities). It only
    deletes objects tagged 'contoso-lab:agent-id'. Deleted objects stay
    restorable for 30 days.

    PRODUCTION NOTE: in production the agent's hosting service creates agent
    identities itself, signing in as the blueprint (client credentials with
    the managed-identity assertion, AgentIdentity.CreateAsManager). The lab
    creates one with the delegated operator, who owns the blueprint and so
    needs no Agent ID role.

.PREREQUISITES
    * The runtime user-assigned managed identity exists (Terraform output
      agent_runtime_uami_principal_id, behind its staging flag).
    * Role: Agent ID Developer or Agent ID Administrator, unless the tenant
      setting "Users can create agent blueprints" is Yes. As the blueprint's
      owner you can then create agent identities from it with no extra role.

.GRAPH SCOPES  (delegated; admin-consent)
    AgentIdentityBlueprint.Create             create the blueprint
    AgentIdentityBlueprint.AddRemoveCreds.All add the federated credential
    AgentIdentityBlueprintPrincipal.Create    create the blueprint principal
    AgentIdentity.Create.All                  create the agent identity
    Application.Read.All                      find existing objects, check the managed identity
    User.Read.All                             resolve the sponsor and owners
    (-Remove also needs AgentIdentityBlueprint.ReadWrite.All and
     AgentIdentity.ReadWrite.All. verify: delete permission names.)

.PARAMETER BlueprintDisplayName
    Default 'Contoso Access Review Assistant (blueprint)'.

.PARAMETER AgentDisplayName
    Default 'contoso-access-review-assistant'.

.PARAMETER SponsorUserPrincipalName
    The accountable human. Default grace.mwangi@contosohealth.io.

.PARAMETER OwnerUserPrincipalNames
    Extra blueprint owners. You (the creator) are added automatically; add one
    more so the blueprint survives a leaver (nhi-standard N1).

.PARAMETER ManagedIdentityPrincipalId
    Principal (object) id of the runtime user-assigned managed identity. It
    becomes the federated credential's subject. Use a dedicated identity, not
    the Key Vault reader UAMI: one identity per workload (OWASP NHI9).

.PARAMETER SkipFederatedCredential
    Create the identity objects without a credential.

.PARAMETER AcceptPreview
    Required for a live run (see API STATUS).

.PARAMETER Remove
    Tear down the lab agent identity and blueprint.

.PARAMETER OfflinePreview
    No connection: print the planned requests with placeholder ids.

.EXAMPLE
    ./New-AgentIdentity.ps1 -OfflinePreview

.EXAMPLE
    Connect-MgGraph -Scopes 'AgentIdentityBlueprint.Create','AgentIdentityBlueprint.AddRemoveCreds.All','AgentIdentityBlueprintPrincipal.Create','AgentIdentity.Create.All','Application.Read.All','User.Read.All'
    ./New-AgentIdentity.ps1 -ManagedIdentityPrincipalId <uami principal id> -SponsorUserPrincipalName 'grace.mwangi@<domain>' -AcceptPreview -WhatIf
    ./New-AgentIdentity.ps1 -ManagedIdentityPrincipalId <uami principal id> -SponsorUserPrincipalName 'grace.mwangi@<domain>' -AcceptPreview

.OUTPUTS
    [pscustomobject] with the blueprint appId and object id, blueprint principal
    id, agent identity id, sponsor and credential subject. Also written to
    agent_identity.json in lab/evidence/out (no secrets exist to leak).
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BlueprintDisplayName = 'Contoso Access Review Assistant (blueprint)',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AgentDisplayName = 'contoso-access-review-assistant',

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN.')]
    [string]$SponsorUserPrincipalName = 'grace.mwangi@contosohealth.io',

    [Parameter()]
    [string[]]$OwnerUserPrincipalNames = @(),

    [Parameter()]
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', ErrorMessage = 'Must be a GUID (the managed identity principal / object id).')]
    [string]$ManagedIdentityPrincipalId = '',

    [Parameter()]
    [switch]$SkipFederatedCredential,

    [Parameter()]
    [switch]$AcceptPreview,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [switch]$OfflinePreview,

    [Parameter()]
    [string]$OutputDirectory = ''
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
$odata = @{ 'OData-Version' = '4.0' }        # required when the body or URL uses a derived type
$labTag = 'contoso-lab:agent-id'            # -Remove only touches objects carrying this tag
$exchangeAudience = 'api://AzureADTokenExchange'
$ficName = 'agent-runtime-uami'
if (-not $OutputDirectory) { $OutputDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../evidence/out')) }

# ===========================================================================
# 0. GUARDS (before any connection)
# ===========================================================================
if (-not $Remove -and -not $SkipFederatedCredential -and -not $ManagedIdentityPrincipalId -and -not $OfflinePreview) {
    throw 'No -ManagedIdentityPrincipalId. The agent needs a secretless way to get tokens (a managed-identity federated credential); this script never adds a client secret. Pass the runtime UAMI principal id (Terraform output agent_runtime_uami_principal_id), or -SkipFederatedCredential to create an inert identity. Nothing was changed.'
}
if (-not $OfflinePreview -and -not $Remove -and -not $AcceptPreview) {
    throw 'Entra Agent ID is labelled Preview in the admin center and its licensing (Agent 365) must be checked first (see API STATUS in this script''s help). Re-run with -AcceptPreview once checked. Nothing was changed.'
}

function Get-Value($Object, [string[]]$Path) {
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$p] }
        elseif ($cur.PSObject.Properties[$p]) { $cur = $cur.$p }
        else { return $null }
    }
    return $cur
}

# First match or $null. Not @(...)[0]: StrictMode throws on an empty index.
function Get-First([string]$Uri) {
    $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $odata -ErrorAction Stop
    return @($r['value']) | Select-Object -First 1
}

# ===========================================================================
# OFFLINE PREVIEW
# ===========================================================================
if ($OfflinePreview) {
    Write-Console 'OFFLINE PREVIEW - no Graph connection; <...> values are resolved at runtime.' -ForegroundColor DarkYellow
    $mi = if ($ManagedIdentityPrincipalId) { $ManagedIdentityPrincipalId } else { '<runtime UAMI principal id>' }
    $steps = @(
        @{ Step = '1 blueprint'; Method = 'POST'; Uri = "$graph/applications/microsoft.graph.agentIdentityBlueprint"
            Body = [ordered]@{ displayName = $BlueprintDisplayName; tags = @($labTag)
                'sponsors@odata.bind' = @("$graph/users/<sponsorId: $SponsorUserPrincipalName>")
                'owners@odata.bind' = @($OwnerUserPrincipalNames | ForEach-Object { "$graph/users/<ownerId: $_>" }) } }
        @{ Step = '2 blueprint principal'; Method = 'POST'; Uri = "$graph/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal"
            Body = [ordered]@{ appId = '<blueprint appId>' } }
        @{ Step = '3 federated credential'; Method = 'POST'; Uri = "$graph/applications/<blueprint objectId>/federatedIdentityCredentials"
            Body = [ordered]@{ name = $ficName; issuer = 'https://login.microsoftonline.com/<tenantId>/v2.0'; subject = $mi; audiences = @($exchangeAudience) } }
        @{ Step = '4 agent identity'; Method = 'POST'; Uri = "$graph/servicePrincipals/microsoft.graph.agentIdentity"
            Body = [ordered]@{ displayName = $AgentDisplayName; agentIdentityBlueprintId = '<blueprint appId>'
                'sponsors@odata.bind' = @("$graph/users/<sponsorId: $SponsorUserPrincipalName>") } }
    )
    if ($SkipFederatedCredential) { $steps = @($steps | Where-Object { $_.Step -ne '3 federated credential' }) }
    foreach ($s in $steps) {
        Write-Console "`n[$($s.Step)] $($s.Method) $($s.Uri)   (OData-Version: 4.0)" -ForegroundColor Cyan
        $s.Body | ConvertTo-Json -Depth 5 | Out-Host
    }
    Write-Console "`nNo permissions are granted. No client secret is ever added (the app management policy would block one on a new app anyway)." -ForegroundColor DarkGray
    return
}

# ===========================================================================
# 1. CONNECT + RESOLVE
# ===========================================================================
$requiredScopes = if ($Remove) {
    @('AgentIdentityBlueprint.ReadWrite.All', 'AgentIdentity.ReadWrite.All', 'Application.Read.All')
}
else {
    @('AgentIdentityBlueprint.Create', 'AgentIdentityBlueprint.AddRemoveCreds.All', 'AgentIdentityBlueprintPrincipal.Create',
        'AgentIdentity.Create.All', 'Application.Read.All', 'User.Read.All')
}
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }
$tenantId = [string]$ctx.TenantId

# Is Agent ID reachable at all? One read of the blueprint collection decides.
$escapedBp = $BlueprintDisplayName.Replace("'", "''")
try {
    $blueprint = Get-First "$graph/applications/microsoft.graph.agentIdentityBlueprint?`$filter=displayName eq '$escapedBp'&`$select=id,appId,displayName,tags"
}
catch {
    throw "Agent ID API not available in this tenant ($($_.Exception.Message)). Check licensing and the preview status (help: API STATUS). NOT creating an ordinary app registration as a substitute: that would be a relabelled app, which nhi-standard N10 forbids. Nothing was changed."
}

# ===========================================================================
# REMOVE (teardown)
# ===========================================================================
if ($Remove) {
    if (-not $blueprint) { Write-Console "  [=] Blueprint '$BlueprintDisplayName' not found; nothing to remove." -ForegroundColor DarkGray; return }
    if ($labTag -notin @(Get-Value $blueprint @('tags'))) { throw "Blueprint '$BlueprintDisplayName' doesn't carry the tag '$labTag', so this script didn't create it. Not deleting." }
    $escapedAg = $AgentDisplayName.Replace("'", "''")
    $agent = Get-First "$graph/servicePrincipals/microsoft.graph.agentIdentity?`$filter=displayName eq '$escapedAg'&`$select=id,displayName,agentIdentityBlueprintId"
    if ($agent -and [string]$agent['agentIdentityBlueprintId'] -eq [string]$blueprint['appId'] -and
        $PSCmdlet.ShouldProcess("agent identity '$AgentDisplayName'", 'delete (soft delete, restorable 30 days)')) {
        Invoke-MgGraphRequest -Method DELETE -Uri "$graph/servicePrincipals/$($agent['id'])" -Headers $odata | Out-Null
        Write-Console "  [-] Agent identity '$AgentDisplayName' deleted." -ForegroundColor Yellow
    }
    if ($PSCmdlet.ShouldProcess("blueprint '$BlueprintDisplayName'", 'delete (also cleans up its agent identities; restorable 30 days)')) {
        Invoke-MgGraphRequest -Method DELETE -Uri "$graph/applications/$($blueprint['id'])" -Headers $odata | Out-Null
        Write-Console "  [-] Blueprint '$BlueprintDisplayName' deleted." -ForegroundColor Yellow
    }
    return
}

# Sponsor: an enabled human. Owners: optional extra humans.
$escapedSponsor = $SponsorUserPrincipalName.Replace("'", "''")
$sponsor = Get-First "$graph/users?`$filter=userPrincipalName eq '$escapedSponsor'&`$select=id,displayName,accountEnabled"
if (-not $sponsor) { throw "Sponsor '$SponsorUserPrincipalName' not found (run inbound provisioning first). Nothing was changed." }
if (-not $sponsor['accountEnabled']) { throw "Sponsor '$SponsorUserPrincipalName' is disabled. A leaver can't be accountable for an agent. Nothing was changed." }
$ownerIds = foreach ($upn in $OwnerUserPrincipalNames) {
    $o = Get-First "$graph/users?`$filter=userPrincipalName eq '$($upn.Replace("'", "''"))'&`$select=id,accountEnabled"
    if (-not $o -or -not $o['accountEnabled']) { throw "Owner '$upn' not found or disabled. Nothing was changed." }
    [string]$o['id']
}
$ownerIds = @($ownerIds)

# The credential subject must really be a managed identity: binding the
# blueprint to some other principal would hand its tokens to the wrong workload.
if ($ManagedIdentityPrincipalId) {
    try { $mi = Invoke-MgGraphRequest -Method GET -Uri "$graph/servicePrincipals/$($ManagedIdentityPrincipalId)?`$select=id,displayName,servicePrincipalType" }
    catch { throw "Managed identity principal '$ManagedIdentityPrincipalId' not found ($($_.Exception.Message)). Nothing was changed." }
    if ("$($mi['servicePrincipalType'])" -ne 'ManagedIdentity') { throw "'$($mi['displayName'])' is a $($mi['servicePrincipalType']), not a managed identity. Nothing was changed." }
    Write-Console "Runtime managed identity: $($mi['displayName']) ($ManagedIdentityPrincipalId)" -ForegroundColor Cyan
}
Write-Console "Sponsor: $($sponsor['displayName']) <$SponsorUserPrincipalName>" -ForegroundColor Cyan

$report = [System.Collections.Generic.List[object]]::new()
function Add-Step([string]$Object, [string]$Status, [string]$Id = '') { $report.Add([pscustomobject]@{ Object = $Object; Status = $Status; Id = $Id }) }

# ===========================================================================
# 2. BLUEPRINT
# ===========================================================================
Write-Console "`n[1/4] Agent identity blueprint" -ForegroundColor Cyan
if ($blueprint) {
    Write-Console "  [=] Exists: appId $($blueprint['appId'])." -ForegroundColor DarkGray
    Add-Step 'blueprint' 'exists' ([string]$blueprint['appId'])
}
elseif ($PSCmdlet.ShouldProcess($BlueprintDisplayName, 'create agent identity blueprint')) {
    # verify: 'tags' accepted on blueprint create (it is an application
    # property; agent identities inherit the union of blueprint tags).
    $body = [ordered]@{
        displayName           = $BlueprintDisplayName
        tags                  = @($labTag)
        'sponsors@odata.bind' = @("$graph/users/$($sponsor['id'])")
    }
    # The creator becomes an owner automatically; extra owners avoid a
    # single-owner orphan when that person leaves.
    if ($ownerIds.Count) { $body['owners@odata.bind'] = @($ownerIds | ForEach-Object { "$graph/users/$_" }) }
    $blueprint = Invoke-MgGraphRequest -Method POST -Uri "$graph/applications/microsoft.graph.agentIdentityBlueprint" -Headers $odata `
        -Body ($body | ConvertTo-Json -Depth 4) -ContentType 'application/json'
    Write-Console "  [+] Created: appId $($blueprint['appId'])." -ForegroundColor Green
    Add-Step 'blueprint' 'created' ([string]$blueprint['appId'])
}
else { Add-Step 'blueprint' 'whatif'; $report | Format-Table -AutoSize | Out-Host; return }

# ===========================================================================
# 3. BLUEPRINT PRINCIPAL
# ===========================================================================
Write-Console "`n[2/4] Blueprint principal" -ForegroundColor Cyan
$bpPrincipal = Get-First "$graph/servicePrincipals?`$filter=appId eq '$($blueprint['appId'])'&`$select=id,appId"
if ($bpPrincipal) {
    Write-Console '  [=] Exists.' -ForegroundColor DarkGray
    Add-Step 'blueprint principal' 'exists' ([string]$bpPrincipal['id'])
}
elseif ($PSCmdlet.ShouldProcess($BlueprintDisplayName, 'create blueprint principal')) {
    $bpPrincipal = Invoke-MgGraphRequest -Method POST -Uri "$graph/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal" -Headers $odata `
        -Body (@{ appId = [string]$blueprint['appId'] } | ConvertTo-Json) -ContentType 'application/json'
    Write-Console "  [+] Created: $($bpPrincipal['id'])." -ForegroundColor Green
    Add-Step 'blueprint principal' 'created' ([string]$bpPrincipal['id'])
}
else { Add-Step 'blueprint principal' 'whatif' }

# ===========================================================================
# 4. FEDERATED CREDENTIAL (managed identity -> blueprint)
# ===========================================================================
Write-Console "`n[3/4] Federated credential" -ForegroundColor Cyan
if ($SkipFederatedCredential) {
    Write-Warning '  -SkipFederatedCredential: no credential. The agent can''t get tokens until one is added (re-run with -ManagedIdentityPrincipalId).'
    Add-Step 'federated credential' 'SKIPPED'
}
else {
    $issuer = "https://login.microsoftonline.com/$tenantId/v2.0"
    $existingFics = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/applications/$($blueprint['id'])/federatedIdentityCredentials" -Headers $odata)['value'])
    $match = $existingFics | Where-Object { $_ -and $_['issuer'] -eq $issuer -and $_['subject'] -eq $ManagedIdentityPrincipalId } | Select-Object -First 1
    # Any OTHER credential on the blueprint is a finding: the design is exactly one.
    $others = @($existingFics | Where-Object { $_ -and -not ($_['issuer'] -eq $issuer -and $_['subject'] -eq $ManagedIdentityPrincipalId) })
    if ($others.Count) { Write-Warning "  Blueprint has $($others.Count) other federated credential(s): $(@($others | ForEach-Object { $_['name'] }) -join ', '). Review them (OWASP NHI9 reuse)." }
    if ($match) {
        Write-Console "  [=] Exists ($($match['name']))." -ForegroundColor DarkGray
        Add-Step 'federated credential' 'exists' $ManagedIdentityPrincipalId
    }
    elseif ($PSCmdlet.ShouldProcess($BlueprintDisplayName, "add federated credential (subject = managed identity $ManagedIdentityPrincipalId)")) {
        $fic = @{ name = $ficName; issuer = $issuer; subject = $ManagedIdentityPrincipalId; audiences = @($exchangeAudience)
            description = 'Contoso lab: agent runtime UAMI -> blueprint. No secrets.' }
        Invoke-MgGraphRequest -Method POST -Uri "$graph/applications/$($blueprint['id'])/federatedIdentityCredentials" -Headers $odata `
            -Body ($fic | ConvertTo-Json -Depth 3) -ContentType 'application/json' | Out-Null
        Write-Console '  [+] Added.' -ForegroundColor Green
        Add-Step 'federated credential' 'created' $ManagedIdentityPrincipalId
    }
    else { Add-Step 'federated credential' 'whatif' }
}

# ===========================================================================
# 5. AGENT IDENTITY (from the blueprint, with a sponsor)
# ===========================================================================
Write-Console "`n[4/4] Agent identity" -ForegroundColor Cyan
$escapedAg = $AgentDisplayName.Replace("'", "''")
$agent = Get-First "$graph/servicePrincipals/microsoft.graph.agentIdentity?`$filter=displayName eq '$escapedAg'&`$select=id,displayName,agentIdentityBlueprintId"
if ($agent -and [string]$agent['agentIdentityBlueprintId'] -ne [string]$blueprint['appId']) {
    throw "An agent identity named '$AgentDisplayName' exists but belongs to another blueprint ($($agent['agentIdentityBlueprintId'])). Pick another -AgentDisplayName. Blueprint and principal are in place; no agent identity was created."
}
if ($agent) {
    Write-Console "  [=] Exists: $($agent['id'])." -ForegroundColor DarkGray
    Add-Step 'agent identity' 'exists' ([string]$agent['id'])
}
elseif ($PSCmdlet.ShouldProcess($AgentDisplayName, "create agent identity (blueprint $($blueprint['appId']), sponsor $SponsorUserPrincipalName)")) {
    $body = [ordered]@{
        displayName              = $AgentDisplayName
        agentIdentityBlueprintId = [string]$blueprint['appId']
        'sponsors@odata.bind'    = @("$graph/users/$($sponsor['id'])")
    }
    $agent = Invoke-MgGraphRequest -Method POST -Uri "$graph/servicePrincipals/microsoft.graph.agentIdentity" -Headers $odata `
        -Body ($body | ConvertTo-Json -Depth 3) -ContentType 'application/json'
    Write-Console "  [+] Created: $($agent['id'])." -ForegroundColor Green
    Add-Step 'agent identity' 'created' ([string]$agent['id'])
}
else { Add-Step 'agent identity' 'whatif' }

# ===========================================================================
# 6. REPORT
# ===========================================================================
Write-Console ''
$report | Format-Table -AutoSize | Out-Host
$result = [pscustomobject]@{
    GeneratedAtUtc             = (Get-Date).ToUniversalTime().ToString('o')
    BlueprintDisplayName       = $BlueprintDisplayName
    BlueprintAppId             = [string]$blueprint['appId']
    BlueprintObjectId          = [string]$blueprint['id']
    BlueprintPrincipalId       = if ($bpPrincipal) { [string]$bpPrincipal['id'] } else { '' }
    AgentDisplayName           = $AgentDisplayName
    AgentIdentityId            = if ($agent) { [string]$agent['id'] } else { '' }
    Sponsor                    = $SponsorUserPrincipalName
    FederatedCredentialSubject = if ($SkipFederatedCredential) { '' } else { $ManagedIdentityPrincipalId }
    PermissionsGranted         = 'none'
    Steps                      = $report.ToArray()
}
if (-not $WhatIfPreference) {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'agent_identity.json') -Encoding utf8
}
Write-Console @"
Next (deliberate, separate steps):
  * Grant the AGENT identity (not the blueprint) only what the scenario needs, by
    admin consent, and record it in the NHI inventory review.
  * Check it in Entra > Agents > Agent identities: sponsor = $SponsorUserPrincipalName.
  * Run ./06-NHI-Inventory.ps1: the blueprint shows as AgentBlueprint with one
    federated credential and no secret, and the agent as AgentIdentity with a sponsor.
"@ -ForegroundColor Cyan
return $result
