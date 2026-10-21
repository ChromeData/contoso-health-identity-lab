<#
.SYNOPSIS
    Creates the VIP RESTRICTED MANAGEMENT administrative unit (RMAU-VIP) through
    Graph and, optionally, adds named VIP accounts to it. Idempotent.

.DESCRIPTION
    A restricted management administrative unit (isMemberManagementRestricted
    = true) protects its members from tenant-scoped administrators: only roles
    assigned AT THE RMAU's SCOPE can change them. The service desk's AU-scoped
    roles (modules/pim helpdesk.tf, AU-Workforce-Standard) can no longer reset
    a VIP's password or methods, whatever the caller says - the Scattered
    Spider help-desk path (help-desk-identity-verification.md).

    Why a script, not Terraform: azuread 3.10.0 has no attribute for
    isMemberManagementRestricted, and Graph makes it IMMUTABLE after creation.
    Managing the AU with azuread_administrative_unit would let a replace
    silently recreate it WITHOUT the restriction. Read it in Terraform with
    data "azuread_administrative_unit" if a module needs its id.

    Steps:
      1. Find the AU by displayName (a failed read stops the run - never a
         duplicate). Exists and restricted -> [=]. Exists but NOT restricted
         -> stop: the flag cannot be added later; use another name or delete
         the ordinary AU first. Several with the name -> stop.
      2. POST /directory/administrativeUnits with isMemberManagementRestricted
         = true (behind ShouldProcess; ConfirmImpact High).
      3. Before ANY member is added: at least one directory role must be
         assigned (active or eligible) AT THE RMAU's SCOPE - the RMAU-scoped
         responder. Without one, nobody but a Global / Privileged Role
         Administrator assigning themselves could revoke, reset or disable a
         VIP, and the containment playbook cannot either (its Graph
         application permissions do not apply to RMAU members; it escalates
         them to that human instead). No responder = every member refused.
      4. For each -MemberUserPrincipalNames VIP: refuse break-glass and adm-
         admin accounts, and refuse anyone who holds or is eligible for a
         directory role or a role-assignable group (see CONSEQUENCES); then
         POST members/$ref. Existing members are skipped.

    CONSEQUENCES OF PUTTING SOMEONE IN AN RMAU (Learn: "Restricted management
    administrative units", learn.microsoft.com/entra/identity/role-based-access-control/admin-units-restricted-management,
    read 2026-10-20):
      * Tenant-scoped Global Administrators and Privileged Role
        Administrators can NOT modify the members (properties, password,
        methods, delete, disable). They CAN manage the RMAU itself: add or
        remove members, and assign roles scoped to it (including to
        themselves) - that is the recovery path.
      * Graph APPLICATION permissions do not apply to members: the Terraform
        APPLY identity and app-based automation cannot change them - that
        includes the ITDR containment playbook (lab/monitoring/
        playbook-contain.json: revoke sessions, confirm compromised, disable),
        which therefore detects RMAU membership and escalates to the
        RMAU-scoped responder instead (verify: tenant-time, with one test
        VIP, which of those three calls the RMAU blocks, and whether the
        Cloud Sync AD-disable path still reaches a synced VIP). HR inbound
        provisioning (an app) probably cannot update a VIP's attributes
        either - verify: tenant-time, with one test VIP.
      * Members can't be managed by Microsoft Entra ID Governance: PIM,
        entitlement management, Lifecycle Workflows or access reviews. So a
        VIP drops out of every access review, and the LEAVER automation
        (04-Leaver.ps1, Lifecycle Workflows) can't disable them - VIP
        offboarding is a manual step by an RMAU-scoped administrator.
      * An admin placed in an RMAU may become unrecoverable: no role that
        can be scoped to an AU can reset a Global Administrator's password.
        Hence the refusal of role holders and adm- / bg-admin- accounts.
      * isMemberManagementRestricted can't be changed after creation; at
        most 100 RMAUs per tenant; after deleting one, protection can take
        up to 30 minutes to lift.
      * Licensing: Entra ID P1 for each RMAU administrator; members need
        only Free.
      * Until a role is assigned at RMAU scope (TENANT-TIME: Authentication
        Administrator + Helpdesk Administrator scoped to RMAU-VIP, held by a
        small role-assignable "VIP support" PIM group), nobody but a GA/PRA
        assigning themselves can reset a VIP's password. Plan that before
        adding the first member.

    Audit: "Add administrative unit" (IsMemberManagementRestricted = true)
    and "Add member to restricted management administrative unit" are
    written to the Entra audit log.

    TENANT-TIME. Nothing here has run against a tenant.

.NOTES
    GRAPH SCOPES (delegated; admin-consent)
    AdministrativeUnit.ReadWrite.All                 create the RMAU, add members
    User.Read.All, GroupMember.Read.All              resolve VIPs, role-assignable memberships
    RoleManagement.Read.Directory                    direct role assignments / eligibility
    PrivilegedEligibilitySchedule.Read.AzureADGroup  PIM-for-Groups eligibility
    Role: Privileged Role Administrator (or Global Administrator).

.PARAMETER DisplayName
    Default RMAU-VIP.

.PARAMETER MemberUserPrincipalNames
    VIP workforce accounts to add (e.g. the Chief Nursing Officer). Empty =
    create the RMAU only.

.EXAMPLE
    Connect-MgGraph -Scopes 'AdministrativeUnit.ReadWrite.All','User.Read.All','GroupMember.Read.All','RoleManagement.Read.Directory','PrivilegedEligibilitySchedule.Read.AzureADGroup'
    ./New-RestrictedAdminUnit.ps1 -WhatIf
    ./New-RestrictedAdminUnit.ps1 -MemberUserPrincipalNames 'first.last@<domain>' -Confirm:$false
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,255}$')]
    [string]$DisplayName = 'RMAU-VIP',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Description = 'VIP accounts - managed only by roles scoped to this restricted management administrative unit.',

    [Parameter()]
    [string[]]$MemberUserPrincipalNames = @()
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

# =============================================================================
# Pure helpers (unit-tested without a tenant)
# =============================================================================
function Test-BreakGlassUpn {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    return [bool]($UserPrincipalName -match '^bg-admin-\d+@')
}

function Test-AdminAccountUpn {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    return [bool]($UserPrincipalName -match '^adm-')
}

function Get-RestrictedAuBody {
    param([Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$Description)
    return [ordered]@{ displayName = $DisplayName; description = $Description; isMemberManagementRestricted = $true }
}

function Resolve-ExistingAu {
    # What to do given the AUs Graph returned for the display name.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Units, [Parameter(Mandatory)][string]$DisplayName)
    $u = @($Units | Where-Object { $null -ne $_ })
    if ($u.Count -eq 0) { return [pscustomobject]@{ Action = 'create'; Unit = $null; Reason = '' } }
    if ($u.Count -gt 1) { return [pscustomobject]@{ Action = 'conflict'; Unit = $null; Reason = "$($u.Count) administrative units are named '$DisplayName'; resolve the duplicates first." } }
    $one = $u[0]
    if ($one.Contains('isMemberManagementRestricted') -and $one['isMemberManagementRestricted'] -eq $true) {
        return [pscustomobject]@{ Action = 'exists'; Unit = $one; Reason = '' }
    }
    return [pscustomobject]@{ Action = 'conflict'; Unit = $one; Reason = "'$DisplayName' ($($one['id'])) exists as an ORDINARY administrative unit. isMemberManagementRestricted is immutable after creation: choose another -DisplayName, or delete that AU first (check what is scoped to it)." }
}

function Get-PrivilegeFinding {
    # Why a user must not go into an RMAU (empty = none found). Inputs are the
    # raw Graph collections, so the decision is testable offline.
    param(
        [AllowEmptyCollection()][object[]]$RoleAssignments = @(),
        [AllowEmptyCollection()][object[]]$RoleEligibilities = @(),
        [AllowEmptyCollection()][object[]]$Groups = @(),
        [AllowEmptyCollection()][object[]]$GroupEligibilities = @()
    )
    $f = [System.Collections.Generic.List[string]]::new()
    if (@($RoleAssignments).Count) { $f.Add("$(@($RoleAssignments).Count) active directory role assignment(s)") }
    if (@($RoleEligibilities).Count) { $f.Add("$(@($RoleEligibilities).Count) directory role eligibility(ies)") }
    $ra = @($Groups | Where-Object { $_ -and $_.Contains('isAssignableToRole') -and $_['isAssignableToRole'] -eq $true })
    if ($ra.Count) { $f.Add("member of role-assignable group(s): $(@($ra | ForEach-Object { $_['displayName'] }) -join ', ')") }
    if (@($GroupEligibilities).Count) { $f.Add("$(@($GroupEligibilities).Count) PIM-for-Groups eligibility(ies)") }
    return , @($f)
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.Contains('@odata.nextLink')) { $page['@odata.nextLink'] } else { $null }
    }
    return $items.ToArray()
}

# =============================================================================
# Main
# =============================================================================
$requiredScopes = @('AdministrativeUnit.ReadWrite.All', 'User.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory', 'PrivilegedEligibilitySchedule.Read.AzureADGroup')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx -and -not $WhatIfPreference) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
if (-not $ctx) {
    # -WhatIf with no Graph session: offline preview.
    Write-Console "[?] would ensure restricted management AU '$DisplayName':" -ForegroundColor Yellow
    Write-Console ((Get-RestrictedAuBody -DisplayName $DisplayName -Description $Description) | ConvertTo-Json) -ForegroundColor DarkGray
    foreach ($upn in $MemberUserPrincipalNames) { Write-Console "[?] would check and add $upn" -ForegroundColor Yellow }
    exit 0
}
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

# 1. Find it. A failed read stops the run: a duplicate RMAU is worse.
$escaped = $DisplayName.Replace("'", "''")
try {
    $found = @(Get-GraphCollection -Uri "$graph/directory/administrativeUnits?`$filter=displayName eq '$escaped'&`$select=id,displayName,isMemberManagementRestricted")
}
catch {
    Write-Warning "Could not read administrative units: $($_.Exception.Message). Nothing created."
    exit 1
}
$decision = Resolve-ExistingAu -Units $found -DisplayName $DisplayName
if ($decision.Action -eq 'conflict') { Write-Warning $decision.Reason; exit 1 }

$au = $decision.Unit
if ($decision.Action -eq 'exists') { Write-Console "[=] '$DisplayName' exists ($($au['id'])) and is restricted management." -ForegroundColor DarkGray }
else {
    # 2. Create.
    $json = Get-RestrictedAuBody -DisplayName $DisplayName -Description $Description | ConvertTo-Json -Compress
    if ($PSCmdlet.ShouldProcess($DisplayName, 'POST /directory/administrativeUnits (isMemberManagementRestricted = true, immutable)')) {
        try {
            $au = Invoke-MgGraphRequest -Method POST -Uri "$graph/directory/administrativeUnits" -Body $json -ContentType 'application/json' -OutputType HashTable
            # Confirm the immutable flag from a fresh read before anyone is added.
            $check = Invoke-MgGraphRequest -Method GET -Uri "$graph/directory/administrativeUnits/$($au['id'])?`$select=id,isMemberManagementRestricted" -OutputType HashTable
            if ($check['isMemberManagementRestricted'] -ne $true) { Write-Warning "Created '$DisplayName' ($($au['id'])) but Graph reports isMemberManagementRestricted is not true. Nobody was added; check it in the portal."; exit 1 }
            Write-Console "[+] '$DisplayName' created ($($au['id'])), restricted management." -ForegroundColor Green
        }
        catch { Write-Warning "'$DisplayName' not created: $($_.Exception.Message)"; exit 1 }
    }
}

# 3. The RMAU-scoped responder must exist before anyone is added.
$failures = 0
$memberIds = @()
if ($MemberUserPrincipalNames.Count) {
    if (-not $au) {
        Write-Warning "  '$DisplayName' does not exist yet (dry run): members are added only once a role is assigned at its scope (the RMAU-scoped responder). None added."
        exit $(if ($WhatIfPreference) { 0 } else { 1 })
    }
    try {
        $scope = [uri]::EscapeDataString("directoryScopeId eq '/administrativeUnits/$($au['id'])'")
        $responders = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleAssignments?`$filter=$scope") + @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleEligibilitySchedules?`$filter=$scope")
    }
    catch { Write-Warning "Could not read the role assignments scoped to '$DisplayName' ($($_.Exception.Message)). No member added (fail closed)."; exit 1 }
    if ($responders.Count -eq 0) {
        Write-Warning ("No directory role is assigned or eligible at '$DisplayName' scope. Refusing every member: nobody but a Global / Privileged Role Administrator assigning themselves could revoke, reset or disable a VIP, and automated containment cannot act on RMAU members (Graph application permissions do not apply to them). " +
            "First assign Authentication + Helpdesk Administrator scoped to '$DisplayName' to a small role-assignable VIP-support PIM group (TENANT-TIME), then re-run.")
        exit 1
    }
    Write-Console "[=] $($responders.Count) role assignment(s)/eligibility(ies) scoped to '$DisplayName' (RMAU-scoped responder present)." -ForegroundColor DarkGray
    try { $memberIds = @(Get-GraphCollection -Uri "$graph/directory/administrativeUnits/$($au['id'])/members?`$select=id" | ForEach-Object { $_['id'] }) }
    catch { Write-Warning "Could not read the members of '$DisplayName': $($_.Exception.Message). No member added."; exit 1 }
}

# 4. Members.

foreach ($upn in $MemberUserPrincipalNames) {
    if (Test-BreakGlassUpn -UserPrincipalName $upn) {
        Write-Warning "  [x] $upn is break-glass: in an RMAU nobody could reset it (no AU-scopable role can). Refused."
        $failures++; continue
    }
    if (Test-AdminAccountUpn -UserPrincipalName $upn) {
        Write-Warning "  [x] $upn is an admin account: RMAU-VIP is for VIP workforce accounts; an admin inside it may become unrecoverable. Refused."
        $failures++; continue
    }
    try {
        $user = @(Get-GraphCollection -Uri "$graph/users?`$filter=userPrincipalName eq '$upn'&`$select=id,displayName") | Select-Object -First 1
        if (-not $user) { Write-Warning "  '$upn' not found."; $failures++; continue }
        $uid = $user['id']
        $finding = Get-PrivilegeFinding `
            -RoleAssignments @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleAssignments?`$filter=principalId eq '$uid'") `
            -RoleEligibilities @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$uid'") `
            -Groups @(Get-GraphCollection -Uri "$graph/users/$uid/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName,isAssignableToRole") `
            -GroupEligibilities @(Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '$uid'")
    }
    catch {
        # Fail closed: an unreadable privilege check is not "no privilege".
        Write-Warning "  [!] Could not check $upn ($($_.Exception.Message)). Not added."
        $failures++; continue
    }
    if ($finding.Count) {
        Write-Warning "  [x] $upn holds privilege ($($finding -join '; ')). PIM and access reviews stop managing RMAU members, and an admin inside one may become unrecoverable. Refused."
        $failures++; continue
    }
    if ($uid -in $memberIds) { Write-Console "  [=] $upn is already a member." -ForegroundColor DarkGray; continue }
    if (-not $au) { Write-Console "  [?] would add $upn once '$DisplayName' exists." -ForegroundColor Yellow; continue }
    if ($PSCmdlet.ShouldProcess($upn, "add to restricted management AU '$DisplayName' (tenant admins, PIM, reviews and Lifecycle Workflows stop managing this user)")) {
        try {
            $ref = @{ '@odata.id' = "$graph/users/$uid" } | ConvertTo-Json -Compress
            Invoke-MgGraphRequest -Method POST -Uri "$graph/directory/administrativeUnits/$($au['id'])/members/`$ref" -Body $ref -ContentType 'application/json' | Out-Null
            Write-Console "  [+] $upn added." -ForegroundColor Green
        }
        catch { Write-Warning "  [!] $upn not added: $($_.Exception.Message)"; $failures++ }
    }
}

if ($failures) { Write-Warning "$failures member(s) not added."; exit 1 }
Write-Console "`nNext (TENANT-TIME): assign Authentication + Helpdesk Administrator scoped to '$DisplayName' to a small role-assignable VIP-support PIM group, and move VIP offboarding to a manual RMAU-scoped step. Verify: Entra -> Roles & admins -> Admin units -> $DisplayName (Restricted management: Yes)." -ForegroundColor Cyan
