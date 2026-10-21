<#
.SYNOPSIS
    External collaboration (B2B guest) tenant settings as code: who may invite
    guests, how much of the directory a guest can see, and no self-service
    sign-up. Idempotent; -WhatIf; -OfflinePreview needs no tenant. Reads, and
    never changes, the cross-tenant access DEFAULT.

.DESCRIPTION
    Guests at Contoso Health arrive one way: an affiliated clinic's physician
    requests the sponsor-approved "Affiliated Physicians" access package
    (modules/entitlement b2b.tf), or an admin / Guest Inviter invites someone
    on purpose. Everything else that creates or empowers a guest is closed:

      1. authorizationPolicy - PATCH with ONLY the properties this script owns
         (Graph: "supply only the values for properties to update"):
           allowInvitesFrom          = adminsAndGuestInviters   Global Admin, User
                                       Admin and Guest Inviter only (CISA SCuBA
                                       MS.AAD.8.2). Entra default: everyone.
           guestUserRoleId           = 2af84b1e-32c8-42b7-82bc-daa82404023b
                                       Restricted Guest User: a guest sees only
                                       their own directory object (MS.AAD.8.1).
           allowEmailVerifiedUsersToJoinOrganization = false
                                       no "join the tenant by email validation".
         defaultUserRolePermissions is NEVER sent: Set-ConsentPolicy.ps1 owns it
         (user consent), and a partial PATCH leaves it as it is.
      2. authenticationFlowsPolicy - selfServiceSignUp.isEnabled = false: no
         guest self-service sign-up through user flows.
      3. Cross-tenant access default - READ-ONLY report (GET
         /policies/crossTenantAccessPolicy/default). See CROSS-TENANT below.

    FAIL CLOSED: both policies are read before any write; a failed read stops
    the script with nothing changed (exit 1). After a write the script reads
    both back and exits 1 if they do not show the desired values.

    CROSS-TENANT ACCESS (B2B) - deliberately NOT changed by this script
      The lab keeps the Microsoft service default (isServiceDefault = true):
      B2B collaboration inbound and outbound allowed for all users and apps,
      B2B direct connect blocked, inbound trust off (no partner MFA, compliant
      device or hybrid-join claim accepted). Reasons:
        * Restricting the DEFAULT inbound B2B collaboration to an allow-list
          blocks every tenant not listed - including a connected organization
          added later - so it belongs with an organization-specific setting for
          the affiliated clinic's tenant (crossTenantAccessPolicy/partners),
          created when that tenant id is known (b2b_connected_organization.
          tenant_id). Tenant-time decision; not built.
        * Partner MFA trust (inboundTrust.isMfaAccepted) goes on that partner
          entry only, never the default: trusting every tenant's MFA would let
          any tenant's weakest MFA satisfy Contoso's CA policies.
        * B2B direct connect stays blocked (it is Teams shared channels only).
      The report warns if the default is no longer the service default, so a
      portal change shows up in the run log.

    NOT BUILT: CISA MS.AAD.8.3 (invitations only to allow-listed domains, the
    portal's "Collaboration restrictions"). verify: whether Microsoft Graph
    v1.0 exposes the B2B domain allow/deny list - it is not a property of
    authorizationPolicy; until then it is a portal step.

.PREREQUISITES
    * Roles (Microsoft Learn, least privileged): Privileged Role Administrator
      (authorizationPolicy update); External ID User Flow Administrator
      (authenticationFlowsPolicy update); Security Reader / Global Reader
      (cross-tenant default read).
    * Run after Terraform envs/dev (enable_b2b_governance) and
      New-B2BConnectedOrganization.ps1, so the guest path that stays open is
      the one the access package defines.

.GRAPH SCOPES  (delegated; admin consent)
    Policy.Read.All                       read all three policies
    Policy.ReadWrite.Authorization        PATCH authorizationPolicy
    Policy.ReadWrite.AuthenticationFlows  PATCH authenticationFlowsPolicy

.PARAMETER AllowInvitesFrom
    adminsAndGuestInviters (default) or none. The two permissive values
    (adminsGuestInvitersAndAllMembers, everyone) are not offered.
    verify: 'none' may also stop entitlement management from creating the
    guest when an Affiliated Physicians request is approved - test the B2B
    package flow before choosing it.

.PARAMETER GuestAccess
    Restricted (default, Restricted Guest User 2af84b1e-...) or Limited (Guest
    User 10dae51f-..., the Entra default; also passes MS.AAD.8.1). "Same as
    member users" is not offered.

.PARAMETER OfflinePreview
    No Graph module, connection or tenant: print the request bodies against
    an assumed Entra-default tenant and stop.

.EXAMPLE
    ./Set-ExternalCollaboration.ps1 -OfflinePreview
.EXAMPLE
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.Authorization','Policy.ReadWrite.AuthenticationFlows'
    ./Set-ExternalCollaboration.ps1 -WhatIf
    ./Set-ExternalCollaboration.ps1

.OUTPUTS
    One row per setting (Setting, Status, Detail). Exit 1 when a read, a write
    or the read-back failed.

.NOTES
    TENANT-TIME: nothing here has run against Entra. Confirmed on Microsoft
    Learn 2026-10-20: PATCH /policies/authorizationPolicy (partial body,
    204, Policy.ReadWrite.Authorization, Privileged Role Administrator);
    allowInvitesFrom values none / adminsAndGuestInviters /
    adminsGuestInvitersAndAllMembers / everyone (everyone = default outside
    US Government); guestUserRoleId supports User, Guest User
    10dae51f-b6af-4016-8d66-8c2a99b929b3 and Restricted Guest User
    2af84b1e-32c8-42b7-82bc-daa82404023b; PATCH
    /policies/authenticationFlowsPolicy {selfServiceSignUp:{isEnabled}} (204,
    Policy.ReadWrite.AuthenticationFlows, External ID User Flow
    Administrator); GET /policies/crossTenantAccessPolicy/default
    (Policy.Read.All) with isServiceDefault and the service-default values
    described above.
    verify: how long a guestUserRoleId change takes to reach existing guests,
    and that Restricted Guest User still lets an Affiliated Physicians guest
    use My Access and the clinical portal (it hides other users and groups).
    verify: whether allowEmailVerifiedUsersToJoinOrganization already reads
    false on a new tenant.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('adminsAndGuestInviters', 'none')]
    [string]$AllowInvitesFrom = 'adminsAndGuestInviters',

    [Parameter()]
    [ValidateSet('Restricted', 'Limited')]
    [string]$GuestAccess = 'Restricted',

    [Parameter()]
    [switch]$OfflinePreview
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
# PURE FUNCTIONS - unit-tested in tests/Set-ExternalCollaboration.Tests.ps1
# =============================================================================

function Get-GuestRoleTemplateId {
    # Graph authorizationPolicy.guestUserRoleId values (Microsoft Learn).
    # "Same as member users" (the User role) is deliberately not offered.
    param([Parameter(Mandatory)][ValidateSet('Restricted', 'Limited')][string]$Level)
    switch ($Level) {
        'Restricted' { return '2af84b1e-32c8-42b7-82bc-daa82404023b' }   # Restricted Guest User
        'Limited' { return '10dae51f-b6af-4016-8d66-8c2a99b929b3' }      # Guest User (Entra default)
    }
}

function Get-ExternalCollaborationDesired {
    # The authorizationPolicy properties this script owns, and the self-service
    # sign-up switch. Nothing else is ever sent.
    param([Parameter(Mandatory)][string]$AllowInvitesFrom, [Parameter(Mandatory)][string]$GuestAccess)
    if ($AllowInvitesFrom -notin 'adminsAndGuestInviters', 'none') { throw "allowInvitesFrom '$AllowInvitesFrom' is not allowed (only adminsAndGuestInviters or none)." }
    if ($GuestAccess -notin 'Restricted', 'Limited') { throw "Guest access '$GuestAccess' is not allowed (only Restricted or Limited)." }
    return [pscustomobject]@{
        Authorization     = [ordered]@{
            allowInvitesFrom                          = $AllowInvitesFrom
            guestUserRoleId                           = Get-GuestRoleTemplateId -Level $GuestAccess
            allowEmailVerifiedUsersToJoinOrganization = $false
        }
        SelfServiceSignUp = $false
    }
}

function Compare-AuthorizationPolicy {
    # Owned properties whose current value differs from the desired one, as
    # an ordered map (property -> desired value). Empty = in sync. GUIDs and
    # enum strings compare case-insensitively; a missing property is drift.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Current, [Parameter(Mandatory)][System.Collections.IDictionary]$Desired)
    $diff = [ordered]@{}
    foreach ($k in $Desired.Keys) {
        $want = $Desired[$k]
        if (-not $Current.Contains($k) -or $null -eq $Current[$k]) { $diff[$k] = $want; continue }
        $have = $Current[$k]
        $same = if ($want -is [bool]) { ($have -is [bool]) -and ($have -eq $want) } else { [string]$have -ieq [string]$want }
        if (-not $same) { $diff[$k] = $want }
    }
    return $diff
}

function Get-SelfServiceSignUpEnabled {
    # authenticationFlowsPolicy -> $true / $false, or $null when the shape is
    # not the documented one (treated as drift, never as "off").
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Policy)
    if (-not $Policy.Contains('selfServiceSignUp') -or -not ($Policy['selfServiceSignUp'] -is [System.Collections.IDictionary])) { return $null }
    $v = $Policy['selfServiceSignUp']['isEnabled']
    if ($v -is [bool]) { return $v }
    return $null
}

function ConvertTo-CrossTenantSummary {
    # Cross-tenant access default -> one line per setting, and the warnings a
    # reviewer should see. Read-only: this script never writes this policy.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Default)
    $access = {
        param($Section)
        if (-not ($Section -is [System.Collections.IDictionary])) { return 'unknown' }
        $ug = $Section['usersAndGroups']; $apps = $Section['applications']
        $u = if ($ug -is [System.Collections.IDictionary]) { [string]$ug['accessType'] } else { '?' }
        $a = if ($apps -is [System.Collections.IDictionary]) { [string]$apps['accessType'] } else { '?' }
        return "users $u, apps $a"
    }
    $trust = $Default['inboundTrust']
    $trustOn = @()
    if ($trust -is [System.Collections.IDictionary]) { foreach ($k in 'isMfaAccepted', 'isCompliantDeviceAccepted', 'isHybridAzureADJoinedDeviceAccepted') { if ($trust[$k] -eq $true) { $trustOn += $k } } }
    $warnings = [System.Collections.Generic.List[string]]::new()
    if ($Default['isServiceDefault'] -ne $true) { $warnings.Add('The cross-tenant access default has been customised (isServiceDefault is not true). Review the change; this script does not manage it.') }
    if ($trustOn.Count) { $warnings.Add("The DEFAULT inbound trust accepts $($trustOn -join ', ') from EVERY tenant. Trust partner claims per partner only.") }
    $dcIn = & $access $Default['b2bDirectConnectInbound']
    if ($dcIn -match 'allowed') { $warnings.Add("B2B direct connect inbound is allowed by default ($dcIn).") }
    return [pscustomobject]@{
        IsServiceDefault       = ($Default['isServiceDefault'] -eq $true)
        B2BCollaborationIn     = & $access $Default['b2bCollaborationInbound']
        B2BCollaborationOut    = & $access $Default['b2bCollaborationOutbound']
        B2BDirectConnectIn     = $dcIn
        B2BDirectConnectOut    = & $access $Default['b2bDirectConnectOutbound']
        InboundTrustAccepted   = $(if ($trustOn.Count) { $trustOn -join ', ' } else { 'none' })
        Warnings               = $warnings.ToArray()
    }
}

# =============================================================================
# SCRIPT BODY
# =============================================================================
$graph = 'https://graph.microsoft.com/v1.0'
$desired = Get-ExternalCollaborationDesired -AllowInvitesFrom $AllowInvitesFrom -GuestAccess $GuestAccess
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Setting, [string]$Status, [string]$Detail = '')
    $results.Add([pscustomobject]@{ Setting = $Setting; Status = $Status; Detail = $Detail })
    $color = switch -Wildcard ($Status) { 'failed' { 'Red' } 'warn*' { 'Yellow' } 'updated' { 'Green' } 'in-sync' { 'DarkGray' } default { 'Cyan' } }
    Write-Host ("  [{0}] {1}: {2}" -f $Status, $Setting, $Detail) -ForegroundColor $color
}
if ($AllowInvitesFrom -eq 'none') { Write-Warning "allowInvitesFrom = none: verify that entitlement management can still create the guest for an approved Affiliated Physicians request before relying on it." }

if ($OfflinePreview) {
    Write-Console 'OFFLINE PREVIEW - no Graph connection. Assumes an Entra-default tenant (everyone may invite, Guest User role, self-service sign-up on).' -ForegroundColor DarkYellow
    Write-Console "PATCH $graph/policies/authorizationPolicy" -ForegroundColor DarkGray
    ($desired.Authorization | ConvertTo-Json) | Out-Host
    Write-Console "PATCH $graph/policies/authenticationFlowsPolicy" -ForegroundColor DarkGray
    (@{ selfServiceSignUp = @{ isEnabled = $desired.SelfServiceSignUp } } | ConvertTo-Json) | Out-Host
    Write-Console "GET   $graph/policies/crossTenantAccessPolicy/default   (read-only report; never changed)" -ForegroundColor DarkGray
    foreach ($k in $desired.Authorization.Keys) { Add-Result "authorizationPolicy.$k" 'preview' ([string]$desired.Authorization[$k]) }
    Add-Result 'authenticationFlowsPolicy.selfServiceSignUp.isEnabled' 'preview' 'False'
    Add-Result 'crossTenantAccessPolicy/default' 'preview' 'read-only report'
    return $results.ToArray()
}

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required (Install-Module Microsoft.Graph.Authentication -Scope CurrentUser), or use -OfflinePreview.' }
$requiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.Authorization', 'Policy.ReadWrite.AuthenticationFlows')
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }

function Get-Authz {
    # v1.0 returns the singleton; older responses wrapped it in 'value'.
    $a = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authorizationPolicy" -OutputType HashTable
    if ($a -is [System.Collections.IDictionary] -and $a.Contains('value')) { $a = @($a['value']) | Select-Object -First 1 }
    if (-not ($a -is [System.Collections.IDictionary])) { throw 'authorizationPolicy: unexpected response shape.' }
    return $a
}
function Get-AuthenticationFlowPolicy { return Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authenticationFlowsPolicy" -OutputType HashTable }

# ---- 0. Read everything first (fail closed) ----------------------------------
try {
    $authz = Get-Authz
    $flows = Get-AuthenticationFlowPolicy
}
catch {
    Add-Result 'read' 'failed' "could not read the current policies: $($_.Exception.Message). Nothing was changed."
    $results.ToArray()
    exit 1
}

# ---- 1. authorizationPolicy ---------------------------------------------------
Write-Console "`n[1/3] authorizationPolicy (guest invitations + guest access)" -ForegroundColor Cyan
$drift = Compare-AuthorizationPolicy -Current $authz -Desired $desired.Authorization
$wrote = $false
if ($drift.Count -eq 0) {
    foreach ($k in $desired.Authorization.Keys) { Add-Result "authorizationPolicy.$k" 'in-sync' ([string]$desired.Authorization[$k]) }
}
else {
    $was = ($drift.Keys | ForEach-Object { "$_ was '$($authz[$_])'" }) -join '; '
    if ($PSCmdlet.ShouldProcess('authorizationPolicy (tenant-wide)', "PATCH $(($drift.Keys | ForEach-Object { "$_=$($drift[$_])" }) -join ', ')")) {
        try {
            Invoke-MgGraphRequest -Method PATCH -Uri "$graph/policies/authorizationPolicy" -Body ($drift | ConvertTo-Json -Compress) -ContentType 'application/json' | Out-Null
            foreach ($k in $drift.Keys) { Add-Result "authorizationPolicy.$k" 'updated' "$([string]$drift[$k]) ($was)" }
            $wrote = $true
        }
        catch { Add-Result 'authorizationPolicy' 'failed' $_.Exception.Message }
    }
    else { foreach ($k in $drift.Keys) { Add-Result "authorizationPolicy.$k" 'would-update' "$([string]$drift[$k]) (now '$($authz[$k])')" } }
}

# ---- 2. Guest self-service sign-up -------------------------------------------
Write-Console "`n[2/3] authenticationFlowsPolicy (guest self-service sign-up)" -ForegroundColor Cyan
$ssu = Get-SelfServiceSignUpEnabled -Policy $flows
if ($ssu -eq $false) { Add-Result 'authenticationFlowsPolicy.selfServiceSignUp.isEnabled' 'in-sync' 'False' }
elseif ($PSCmdlet.ShouldProcess('authenticationFlowsPolicy (tenant-wide)', 'selfServiceSignUp.isEnabled = false')) {
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "$graph/policies/authenticationFlowsPolicy" -Body (@{ selfServiceSignUp = @{ isEnabled = $false } } | ConvertTo-Json -Compress) -ContentType 'application/json' | Out-Null
        Add-Result 'authenticationFlowsPolicy.selfServiceSignUp.isEnabled' 'updated' "False (was '$ssu')"
        $wrote = $true
    }
    catch { Add-Result 'authenticationFlowsPolicy' 'failed' $_.Exception.Message }
}
else { Add-Result 'authenticationFlowsPolicy.selfServiceSignUp.isEnabled' 'would-update' "False (now '$ssu')" }

# ---- 3. Cross-tenant access default: report only ------------------------------
Write-Console "`n[3/3] Cross-tenant access default (read-only)" -ForegroundColor Cyan
try {
    $ct = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/crossTenantAccessPolicy/default" -OutputType HashTable
    $sum = ConvertTo-CrossTenantSummary -Default $ct
    Add-Result 'crossTenantAccessPolicy/default' 'report' ("service default: {0}; B2B collaboration in: {1}; out: {2}; direct connect in: {3}; inbound trust: {4}" -f $sum.IsServiceDefault, $sum.B2BCollaborationIn, $sum.B2BCollaborationOut, $sum.B2BDirectConnectIn, $sum.InboundTrustAccepted)
    foreach ($w in $sum.Warnings) { Add-Result 'crossTenantAccessPolicy/default' 'warning' $w }
    Write-Console '  Partner trust (MFA) and any inbound allow-list belong on an organization-specific entry for the affiliated clinic (crossTenantAccessPolicy/partners), not the default. Not changed here.' -ForegroundColor DarkGray
}
catch { Add-Result 'crossTenantAccessPolicy/default' 'warning' "could not read the default (report only, not a failure): $($_.Exception.Message)" }

# ---- 4. Read back -------------------------------------------------------------
if ($wrote) {
    try {
        $after = Compare-AuthorizationPolicy -Current (Get-Authz) -Desired $desired.Authorization
        if ($after.Count) { Add-Result 'read-back authorizationPolicy' 'failed' "still differs: $($after.Keys -join ', ')" }
        $ssuAfter = Get-SelfServiceSignUpEnabled -Policy (Get-AuthenticationFlowPolicy)
        if ($ssuAfter -ne $false) { Add-Result 'read-back authenticationFlowsPolicy' 'failed' "selfServiceSignUp.isEnabled is '$ssuAfter'" }
    }
    catch { Add-Result 'read-back' 'failed' $_.Exception.Message }
}

$failed = @($results | Where-Object Status -eq 'failed')
Write-Console ("`n{0}" -f (($results | Group-Object Status | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')) -ForegroundColor $(if ($failed) { 'Red' } else { 'Green' })
Write-Console 'Verify: Entra admin center -> External Identities -> External collaboration settings (guest user access, guest invite settings, self-service sign up) and -> Cross-tenant access settings -> Default settings.' -ForegroundColor Cyan
$results.ToArray()
if ($failed) { exit 1 }
