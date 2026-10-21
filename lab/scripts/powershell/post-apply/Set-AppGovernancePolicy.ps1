<#
.SYNOPSIS
    Sets the tenant-wide app management policy (defaultAppManagementPolicy):
    no client secrets or symmetric keys on NEW apps, a 180-day maximum
    certificate lifetime on new apps, a 90-day cap on new secrets added to
    EXISTING apps, and no custom (client-generated) passwords anywhere.
    Idempotent; backs up the current policy first. Fills a gap the azuread
    Terraform provider can't express.

.DESCRIPTION
    Preventive half of NHI governance (the detective half is
    06-NHI-Inventory.ps1). nhi-standard N2 says "no password credentials";
    this makes that a platform rule instead of a review comment, so a client
    secret on a new app is rejected at creation time by Entra itself.

    DESIGN: TWO DATES, NOT ONE
      * NEW apps (created after -RestrictAppsCreatedAfter, default the first
        time this script enforces): passwordAddition + symmetricKeyAddition
        blocked; asymmetricKeyLifetime <= -MaxCertificateLifetimeDays. New
        workloads must federate, use a managed identity or a short-lived cert.
      * ALL apps (cut-off 2015-01-01): customPasswordAddition blocked, and a
        new secret on an existing app is capped at
        -LegacyAppMaxSecretLifetimeDays (passwordLifetime + symmetricKeyLifetime).
        Existing apps keep working while each new secret is short-lived. That
        is the migration path for exception E3 (midpoint-reader) instead of a
        cliff.
    Neither date breaks running apps. Microsoft: the policy blocks the create or
    update that violates it, never token issuance for an existing credential.

    PORTAL-COMPATIBLE BY DEFAULT: the Entra admin center (Enterprise apps >
    Application policies) expects each restriction to be identical in
    applicationRestrictions AND servicePrincipalRestrictions, or it locks the
    blade ("modified outside of this interface"). This script writes both
    unless you pass -SkipServicePrincipalRestrictions.

    MERGE, NEVER CLOBBER: a PATCH replaces each credential collection whole, so
    the script reads the current policy and replaces only the restriction types
    it manages. Anything else already configured (identifier-URI rules, other
    restriction types) is carried over. The previous policy is saved as JSON
    before any change. To roll back, PATCH that file's body to the same
    endpoint.

    ORDERING WITH OTHER WORKFLOWS (tenant time):
      * Run after the SSO/SCIM apps exist (enable_sso_apps). verify: whether
        asymmetricKeyLifetime also limits SAML token-signing certificates added
        to a gallery app's service principal (default lifetime 3 years). If it
        does, an SSO app created after the cut-off needs a <= 180-day signing
        cert.
      * midpoint-reader (lab/pam/README.md) was created before the cut-off, so
        it can still get a secret, but only for up to 90 days.

    STATUS: not run against a tenant. -OfflinePreview prints the exact request
    body with no connection.

.PREREQUISITES
    * Role: Application Administrator or Cloud Application Administrator (Graph
      API page). The Entra how-to also lists Security Administrator for the
      admin-center blade.
    * Licence: verify. Microsoft's app-management-policy pages state no licence
      requirement; some older pages tie app policies to Workload ID Premium.
      Check before the trial window.

.GRAPH SCOPES  (delegated; admin-consent)
    Policy.Read.All                           read the current policy (backup + diff)
    Policy.ReadWrite.ApplicationConfiguration PATCH /policies/defaultAppManagementPolicy

.PARAMETER MaxCertificateLifetimeDays
    Max lifetime of a certificate added to a NEW app. Default 180 (Microsoft's
    recommended maximum; matches 06-NHI-Inventory -MaxCredentialLifetimeDays).

.PARAMETER LegacyAppMaxSecretLifetimeDays
    Max lifetime of a new secret on an EXISTING app. Default 90. 0 = don't set
    a lifetime cap.

.PARAMETER RestrictAppsCreatedAfter
    Cut-off for the new-app rules. Default: keep the date already in the policy
    (so re-runs don't move it), or now if the rule isn't there yet. A bare date
    is local time; pass '2026-11-01T00:00:00Z' for UTC.

.PARAMETER SkipServicePrincipalRestrictions
    Only write applicationRestrictions (breaks admin-center editing, see above).

.PARAMETER BackupDirectory
    Where the pre-change policy JSON goes. Default lab/evidence/out (gitignored).

.PARAMETER OfflinePreview
    No connection: print the request body built from an empty policy.

.EXAMPLE
    ./Set-AppGovernancePolicy.ps1 -OfflinePreview

.EXAMPLE
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.ApplicationConfiguration'
    ./Set-AppGovernancePolicy.ps1 -WhatIf
    ./Set-AppGovernancePolicy.ps1
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 730)]
    [int]$MaxCertificateLifetimeDays = 180,

    [Parameter()]
    [ValidateRange(0, 730)]
    [int]$LegacyAppMaxSecretLifetimeDays = 90,

    [Parameter()]
    [Nullable[datetime]]$RestrictAppsCreatedAfter = $null,

    [Parameter()]
    [switch]$SkipServicePrincipalRestrictions,

    [Parameter()]
    [string]$BackupDirectory = '',

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

$endpoint = 'https://graph.microsoft.com/v1.0/policies/defaultAppManagementPolicy'
$allAppsCutoff = '2015-01-01T00:00:00Z'     # "every app": Entra treats SPs with no createdDateTime as 2019-01-01
if (-not $BackupDirectory) { $BackupDirectory = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../evidence/out')) }

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

function ConvertTo-IsoUtc($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $d = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
        return $d.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return [string]$Value
}

# One comparable string per restriction, so "already compliant" is a set
# comparison and not a fragile JSON diff (Graph may reorder or reformat).
function Get-RestrictionKey($R) {
    $state = [string](Get-Value $R @('state')); if (-not $state) { $state = 'enabled' }
    '{0}|{1}|{2}|{3}' -f (Get-Value $R @('restrictionType')), $state, (Get-Value $R @('maxLifetime')), (ConvertTo-IsoUtc (Get-Value $R @('restrictForAppsCreatedAfterDateTime')))
}

# ===========================================================================
# 1. READ CURRENT POLICY
# ===========================================================================
if ($OfflinePreview) {
    Write-Console 'OFFLINE PREVIEW - no Graph connection; showing the body this script would PATCH onto an empty (default) policy.' -ForegroundColor DarkYellow
    $current = @{
        id = '00000000-0000-0000-0000-000000000000'; isEnabled = $false
        applicationRestrictions = @{ passwordCredentials = @(); keyCredentials = @() }
        servicePrincipalRestrictions = @{ passwordCredentials = @(); keyCredentials = @() }
    }
}
else {
    $requiredScopes = @('Policy.Read.All', 'Policy.ReadWrite.ApplicationConfiguration')
    $ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
    if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). The PATCH will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }
    $current = Invoke-MgGraphRequest -Method GET -Uri $endpoint
}
Write-Console "Tenant app management policy: isEnabled=$($current['isEnabled'])" -ForegroundColor Cyan

# ===========================================================================
# 2. BUILD THE DESIRED RESTRICTIONS
# ===========================================================================
# Keep the cut-off already in force for the new-app rules unless one is given,
# so re-running never moves the line (and never silently widens it).
$existingNewAppDate = @(Get-Value $current @('applicationRestrictions', 'passwordCredentials')) |
    Where-Object { $_ -and (Get-Value $_ @('restrictionType')) -eq 'passwordAddition' -and "$(Get-Value $_ @('state'))" -ne 'disabled' } |
    ForEach-Object { ConvertTo-IsoUtc (Get-Value $_ @('restrictForAppsCreatedAfterDateTime')) } | Select-Object -First 1
$newAppCutoff = if ($RestrictAppsCreatedAfter) { ConvertTo-IsoUtc $RestrictAppsCreatedAfter }
elseif ($existingNewAppDate) { $existingNewAppDate }
else { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
Write-Console "  New-app rules apply to apps created after $newAppCutoff; all-app rules after $allAppsCutoff." -ForegroundColor DarkGray

function Get-DesiredRestriction([string]$Type, $MaxLifetime, [string]$Cutoff) {
    [ordered]@{ restrictionType = $Type; state = 'enabled'; maxLifetime = $MaxLifetime; restrictForAppsCreatedAfterDateTime = $Cutoff }
}
# Pairs the admin center treats as one setting share identical values.
$desiredPassword = @(
    (Get-DesiredRestriction 'passwordAddition' $null $newAppCutoff),          # "Block password addition" (new apps)
    (Get-DesiredRestriction 'symmetricKeyAddition' $null $newAppCutoff),
    (Get-DesiredRestriction 'customPasswordAddition' $null $allAppsCutoff)     # "Block custom passwords" (all apps)
)
if ($LegacyAppMaxSecretLifetimeDays -gt 0) {
    $desiredPassword += @(
        (Get-DesiredRestriction 'passwordLifetime' "P$($LegacyAppMaxSecretLifetimeDays)D" $allAppsCutoff),   # "Restrict max password lifetime"
        (Get-DesiredRestriction 'symmetricKeyLifetime' "P$($LegacyAppMaxSecretLifetimeDays)D" $allAppsCutoff))
}
$desiredKey = @((Get-DesiredRestriction 'asymmetricKeyLifetime' "P$($MaxCertificateLifetimeDays)D" $newAppCutoff))   # "Restrict max certificate lifetime"

function Merge-Restriction([object[]]$Current, [object[]]$Desired) {
    $managed = @($Desired | ForEach-Object { $_.restrictionType })
    $kept = @($Current | Where-Object { $_ -and (Get-Value $_ @('restrictionType')) -notin $managed })
    return @($kept) + @($Desired)
}

$collections = @('applicationRestrictions')
if (-not $SkipServicePrincipalRestrictions) { $collections += 'servicePrincipalRestrictions' }
$body = [ordered]@{ isEnabled = $true }
$changes = [System.Collections.Generic.List[string]]::new()
foreach ($col in $collections) {
    # Copy the whole current collection object so sub-properties this script
    # doesn't manage (e.g. identifierUris) are sent back unchanged.
    # verify: that beta-only restrictions (audiences, trustedCertificateAuthority)
    # survive a v1.0 PATCH of this object; the backup lets you restore them.
    $curCol = Get-Value $current @($col)
    $newCol = [ordered]@{}
    if ($curCol -is [System.Collections.IDictionary]) { foreach ($k in $curCol.Keys) { if ($k -notlike '@odata.*') { $newCol[$k] = $curCol[$k] } } }
    $curPw = @(Get-Value $curCol @('passwordCredentials'))
    $curKey = @(Get-Value $curCol @('keyCredentials'))
    $newCol['passwordCredentials'] = @(Merge-Restriction $curPw $desiredPassword)
    $newCol['keyCredentials'] = @(Merge-Restriction $curKey $desiredKey)
    $body[$col] = $newCol

    $before = @($curPw + $curKey | Where-Object { $_ } | ForEach-Object { Get-RestrictionKey $_ } | Sort-Object)
    $after = @($newCol['passwordCredentials'] + $newCol['keyCredentials'] | ForEach-Object { Get-RestrictionKey $_ } | Sort-Object)
    if (($before -join "`n") -ne ($after -join "`n")) { $changes.Add($col) }
}
if (-not $current['isEnabled']) { $changes.Add('isEnabled') }

$jsonBody = $body | ConvertTo-Json -Depth 10
if ($OfflinePreview) {
    Write-Console "`nPATCH $endpoint" -ForegroundColor Cyan
    $jsonBody | Out-Host
    return
}

# ===========================================================================
# 3. APPLY (backup first) AND VERIFY
# ===========================================================================
if (-not $changes.Count) {
    Write-Console '  [=] Already compliant: every managed restriction is present with the same values. No change.' -ForegroundColor Green
}
elseif ($PSCmdlet.ShouldProcess('tenant defaultAppManagementPolicy', "PATCH ($($changes -join ', '))")) {
    if (-not (Test-Path -LiteralPath $BackupDirectory)) { New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null }
    $backup = Join-Path $BackupDirectory ("app_management_policy_backup_{0}.json" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
    $current | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $backup -Encoding utf8
    Write-Console "  Backup of the current policy: $backup" -ForegroundColor DarkGray
    Invoke-MgGraphRequest -Method PATCH -Uri $endpoint -Body $jsonBody -ContentType 'application/json' | Out-Null
    Write-Console "  [+] Policy updated ($($changes -join ', '))." -ForegroundColor Green
}
else {
    Write-Console "  [whatif] Would PATCH $endpoint ($($changes -join ', ')) with:" -ForegroundColor DarkYellow
    $jsonBody | Out-Host
    return
}

# Read back and prove it (eventual consistency: retry briefly).
$ok = $false
for ($i = 0; $i -lt 5 -and -not $ok; $i++) {
    if ($i) { Start-Sleep -Seconds 5 }
    $readBack = Invoke-MgGraphRequest -Method GET -Uri $endpoint
    $missing = foreach ($col in $collections) {
        $have = @(@(Get-Value $readBack @($col, 'passwordCredentials')) + @(Get-Value $readBack @($col, 'keyCredentials')) | Where-Object { $_ } | ForEach-Object { Get-RestrictionKey $_ })
        foreach ($d in @($desiredPassword + $desiredKey)) { $k = Get-RestrictionKey $d; if ($k -notin $have) { "$col/$k" } }
    }
    $ok = $readBack['isEnabled'] -and -not @($missing).Count
}
$readBackRows = foreach ($col in $collections) {
    foreach ($r in @(@(Get-Value $readBack @($col, 'passwordCredentials')) + @(Get-Value $readBack @($col, 'keyCredentials')) | Where-Object { $_ })) {
        [pscustomobject]@{ Collection = $col; Restriction = Get-Value $r @('restrictionType'); State = Get-Value $r @('state'); MaxLifetime = Get-Value $r @('maxLifetime'); AppsCreatedAfter = ConvertTo-IsoUtc (Get-Value $r @('restrictForAppsCreatedAfterDateTime')) }
    }
}
$readBackRows | Format-Table -AutoSize | Out-Host
if (-not $ok) {
    Write-Warning "Read-back does not show every restriction: $(@($missing) -join '; '). Check Entra > Enterprise apps > Application policies."
    exit 1
}
Write-Console 'Verified. Test: create a throwaway app and add a client secret; it must be rejected. Existing apps keep working (only new credentials are checked).' -ForegroundColor Cyan
