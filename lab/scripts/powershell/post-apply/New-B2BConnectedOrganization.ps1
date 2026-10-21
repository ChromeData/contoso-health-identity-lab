<#
.SYNOPSIS
    Creates the B2B pieces Terraform renders but cannot create: the affiliated
    clinic's CONNECTED ORGANIZATION (state configured), its internal sponsor,
    and the tenant-wide external-user lifecycle setting. Idempotent.

.DESCRIPTION
    modules/entitlement (b2b.tf) builds the externally visible "Affiliated
    Partners" catalog and the "Affiliated Physicians" package, whose policy
    lets only users from CONFIGURED connected organizations request it. The
    azuread provider has no connectedOrganization or entitlementManagement
    settings resource, so Terraform renders the Graph bodies into the output
    b2b_post_apply and this script sends them:

      1. Connected organization, matched by displayName:
           missing            -> POST  .../connectedOrganizations (state configured)
           exists, "proposed" -> PATCH state = configured
             (the service auto-creates PROPOSED orgs when a stranger requests a
             package; only CONFIGURED ones satisfy the policy scope
             AllConfiguredConnectedOrganizationSubjects)
           exists, configured -> [=]
      2. Internal sponsor = B2B-Sponsors-MedicalStaffOffice:
           POST .../connectedOrganizations/{id}/internalSponsors/$ref
         Already a sponsor -> skipped. verify: Graph accepts a GROUP as a
         sponsor; if it refuses, each user member is added instead (and that
         is reported, because sponsor membership then stops following the
         group).
      3. TENANT-WIDE setting (ConfirmImpact High, prints the current values
         first): when a connected-org guest's LAST assignment ends, block
         sign-in, then delete the guest after N days
         (externalUserLifecycleAction = blockSignInAndDelete). This is the
         control that stops a former guest lingering in the directory.

    Output: the connected organization id. Put it in terraform.tfvars (or the
    TF_B2B_CONNECTED_ORGANIZATION_ID repo variable) as
    b2b_connected_organization_id; the next plan narrows the guest policy to
    SpecificConnectedOrganizationSubjects (this clinic only).

    TENANT-TIME. Nothing here has run against a tenant.

.PREREQUISITES
    * envs/dev applied with enable_premium + enable_governance +
      enable_b2b_governance, and people added to B2B-Sponsors-MedicalStaffOffice.
    * terraform -chdir=lab/terraform/envs/dev output -json b2b_post_apply > b2b.json
    * Role: Identity Governance Administrator.

.GRAPH SCOPES  (delegated; admin-consent)
    EntitlementManagement.ReadWrite.All
    GroupMember.Read.All   (only for the sponsor fallback: list group members)

.PARAMETER PostApplyPath
    JSON from `terraform output -json b2b_post_apply` (an object whose *_body
    fields are JSON strings). A full `terraform output -json` file is
    accepted too (the b2b_post_apply entry is unwrapped).

.PARAMETER TenantDomain
    Optional verified domain for the printed My Access link
    (https://myaccess.microsoft.com/@<domain>#/access-packages/<id>).

.PARAMETER SkipTenantSettings
    Leave the tenant-wide external-user lifecycle setting untouched.

.EXAMPLE
    terraform -chdir=lab/terraform/envs/dev output -json b2b_post_apply > b2b.json
    Connect-MgGraph -Scopes 'EntitlementManagement.ReadWrite.All','GroupMember.Read.All'
    ./New-B2BConnectedOrganization.ps1 -PostApplyPath ./b2b.json -WhatIf
    ./New-B2BConnectedOrganization.ps1 -PostApplyPath ./b2b.json -TenantDomain contosohealth.io
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PostApplyPath,

    [Parameter()]
    [string]$TenantDomain = '',

    [Parameter()]
    [switch]$SkipTenantSettings
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
$em = "$graph/identityGovernance/entitlementManagement"

# =============================================================================
# Helpers
# =============================================================================
function Read-B2BPostApplyFile {
    # Returns the b2b_post_apply object with the *_body strings parsed into
    # ordered hashtables. $null when the output is null (flag off).
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if ($null -eq $raw) { return $null }
    if ($raw.Contains('b2b_post_apply') -and $raw['b2b_post_apply'] -is [System.Collections.IDictionary]) { $raw = $raw['b2b_post_apply']['value'] }
    if ($null -eq $raw) { return $null }
    foreach ($k in @($raw.Keys)) {
        if ($k -like '*_body' -and $raw[$k] -is [string]) { $raw[$k] = $raw[$k] | ConvertFrom-Json -AsHashtable }
    }
    return $raw
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    # Unrolled on purpose: callers wrap the call in @() (a comma-return here
    # would nest the whole page list inside @() as ONE element).
    return $items.ToArray()
}

# =============================================================================
# Main
# =============================================================================
$in = Read-B2BPostApplyFile -Path $PostApplyPath
if ($null -eq $in) { Write-Warning "b2b_post_apply is null in $PostApplyPath. Is enable_b2b_governance = true in lab.tfvars (and applied)?"; exit 1 }
foreach ($k in 'connected_organization_body', 'internal_sponsor_group_object_id', 'entitlement_settings_body', 'access_package_id') {
    if (-not $in.Contains($k) -or $null -eq $in[$k]) { throw "b2b_post_apply has no '$k' - re-export it from the current Terraform output." }
}

$requiredScopes = @('EntitlementManagement.ReadWrite.All', 'GroupMember.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx -and -not $WhatIfPreference) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
if ($ctx) {
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }
}

$orgBody = $in['connected_organization_body']
$orgName = [string]$orgBody['displayName']
$sponsorGroupId = [string]$in['internal_sponsor_group_object_id']
$failures = 0
$orgId = $null

# ---- 1. Connected organization ----------------------------------------------
Write-Console "Connected organization: $orgName" -ForegroundColor Cyan
$existing = $null
if ($ctx) {
    $found = @(Get-GraphCollection -Uri "$em/connectedOrganizations?`$filter=displayName eq '$($orgName.Replace("'", "''"))'")
    if ($found.Count -gt 1) { throw "More than one connected organization is named '$orgName' - resolve the duplicate in the portal first." }
    if ($found.Count -eq 1) { $existing = $found[0] }
}

if ($existing) {
    $orgId = [string]$existing['id']
    if ([string]$existing['state'] -eq 'proposed') {
        if ($PSCmdlet.ShouldProcess("connected organization '$orgName' ($orgId)", 'PATCH state proposed -> configured')) {
            Invoke-MgGraphRequest -Method PATCH -Uri "$em/connectedOrganizations/$orgId" -Body (@{ state = 'configured' } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
            Write-Console "  [+] '$orgName' promoted to configured." -ForegroundColor Green
        }
    }
    else { Write-Console "  [=] '$orgName' exists ($([string]$existing['state']))." -ForegroundColor DarkGray }
}
elseif ($PSCmdlet.ShouldProcess("connected organization '$orgName'", 'POST (state configured)')) {
    $created = Invoke-MgGraphRequest -Method POST -Uri "$em/connectedOrganizations" -Body ($orgBody | ConvertTo-Json -Depth 10 -Compress) -ContentType 'application/json' -OutputType HashTable
    $orgId = [string]$created['id']
    Write-Console "  [+] '$orgName' created ($orgId, $([string]$created['state']))." -ForegroundColor Green
}
else {
    Write-Console "  [?] would POST:" -ForegroundColor Yellow
    Write-Console ($orgBody | ConvertTo-Json -Depth 10) -ForegroundColor DarkGray
}

# ---- 2. Internal sponsor -----------------------------------------------------
if ($orgId) {
    $sponsorIds = @(Get-GraphCollection -Uri "$em/connectedOrganizations/$orgId/internalSponsors" | ForEach-Object { $_['id'] })
    if ($sponsorGroupId -in $sponsorIds) {
        Write-Console "  [=] sponsor group already an internal sponsor." -ForegroundColor DarkGray
    }
    elseif ($PSCmdlet.ShouldProcess("connected organization '$orgName'", "add internal sponsor group $sponsorGroupId")) {
        try {
            $ref = @{ '@odata.id' = "$graph/groups/$sponsorGroupId" } | ConvertTo-Json
            Invoke-MgGraphRequest -Method POST -Uri "$em/connectedOrganizations/$orgId/internalSponsors/`$ref" -Body $ref -ContentType 'application/json' | Out-Null
            Write-Console "  [+] sponsor group added." -ForegroundColor Green
        }
        catch {
            # verify: whether Graph accepts a group here. Fall back to the
            # group's user members - and say so, because sponsorship then no
            # longer follows group membership.
            Write-Warning "  Group refused as internal sponsor ($($_.Exception.Message)). Adding its user members individually - re-run after membership changes."
            $members = @(Get-GraphCollection -Uri "$graph/groups/$sponsorGroupId/members/microsoft.graph.user?`$select=id,userPrincipalName")
            if (-not $members.Count) { Write-Warning '  The sponsor group has no user members - add the Medical Staff Office people first.'; $failures++ }
            foreach ($m in $members) {
                if ($m['id'] -in $sponsorIds) { Write-Console "  [=] $($m['userPrincipalName']) already a sponsor." -ForegroundColor DarkGray; continue }
                try {
                    Invoke-MgGraphRequest -Method POST -Uri "$em/connectedOrganizations/$orgId/internalSponsors/`$ref" -Body (@{ '@odata.id' = "$graph/users/$($m['id'])" } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
                    Write-Console "  [+] sponsor $($m['userPrincipalName']) added." -ForegroundColor Green
                }
                catch { Write-Warning "  Failed to add sponsor $($m['userPrincipalName']): $($_.Exception.Message)"; $failures++ }
            }
        }
    }
}

# ---- 3. Tenant-wide external-user lifecycle ----------------------------------
if (-not $SkipTenantSettings) {
    $desired = $in['entitlement_settings_body']
    $current = $null
    if ($ctx) {
        $current = Invoke-MgGraphRequest -Method GET -Uri "$em/settings" -OutputType HashTable
        Write-Console ("Tenant setting now: externalUserLifecycleAction='{0}', durationUntilExternalUserDeletedAfterBlocked='{1}'" -f $current['externalUserLifecycleAction'], $current['durationUntilExternalUserDeletedAfterBlocked']) -ForegroundColor Cyan
    }
    $same = $current -and ([string]$current['externalUserLifecycleAction'] -eq [string]$desired['externalUserLifecycleAction']) -and ([string]$current['durationUntilExternalUserDeletedAfterBlocked'] -eq [string]$desired['durationUntilExternalUserDeletedAfterBlocked'])
    if ($same) { Write-Console '  [=] external-user lifecycle already as rendered.' -ForegroundColor DarkGray }
    elseif ($PSCmdlet.ShouldProcess('entitlement management settings (TENANT-WIDE)', "PATCH externalUserLifecycleAction=$($desired['externalUserLifecycleAction']), delete after $($desired['durationUntilExternalUserDeletedAfterBlocked'])")) {
        Invoke-MgGraphRequest -Method PATCH -Uri "$em/settings" -Body ($desired | ConvertTo-Json -Compress) -ContentType 'application/json' | Out-Null
        Write-Console '  [+] external-user lifecycle set.' -ForegroundColor Green
    }
}

# ---- Output --------------------------------------------------------------------
$domain = if ($TenantDomain) { $TenantDomain } else { '<tenant-domain>' }
if ($orgId) { Write-Console "`nConnected organization id: $orgId  -> set b2b_connected_organization_id (terraform.tfvars / TF_B2B_CONNECTED_ORGANIZATION_ID), then re-plan to narrow the policy to this clinic." -ForegroundColor Cyan }
Write-Console "My Access link for the clinic: https://myaccess.microsoft.com/@$domain#/access-packages/$($in['access_package_id'])" -ForegroundColor Cyan
if ($failures) { Write-Warning "$failures step(s) failed."; exit 1 }
