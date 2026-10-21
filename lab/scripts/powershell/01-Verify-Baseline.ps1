<#
.SYNOPSIS
    Read-only verification that the Terraform-owned tenant baseline is in place
    and safe: the contract groups exist with the right membership type, the
    break-glass accounts are healthy, hold Global Admin, and are excluded from
    EVERY Conditional Access policy. Exits non-zero on any FAIL.

.DESCRIPTION
    Ownership model (one owner per object, no dual management):

      Terraform (lab/terraform/envs/dev)   break-glass accounts + group, all
                                           groups, CA, PIM policy, packages
      HR feed (../mock-hr)                 every workforce user (Dana, managers)
      This script                          VERIFIES - it creates nothing

    Earlier versions of this script created groups and break-glass accounts
    too, which produced a second, CA-unprotected break-glass group. Creating is
    now Terraform's job alone; this script is the post-apply safety check and
    the "is it safe to enforce CA?" gate.

    CHECKS
      1. Contract groups exist (by mailNickname) with the expected type:
         dynamic (All-Nurses, All-ICU), role-assignable (Break-Glass-Admins,
         Privileged-IAM-Admins), assigned (App-*).
      2. Break-glass accounts: on *.onmicrosoft.com, enabled, members of
         Break-Glass-Admins.
      3. Break-Glass-Admins holds Global Administrator.
      4. EVERY Conditional Access policy excludes Break-Glass-Admins - the one
         invariant that prevents a tenant lockout.
      5. Direct privileged directory-role assignments, standing vs eligible,
         for every role in the lab tier map (Global Administrator, Tier 0,
         Tier 1 - Get-RoleTierMap) and every role a PIM tier group holds:
           * a human with a STANDING role outside break-glass - WARN, by name.
             The build account (-BuildAccountUpn, default admin@<tenant>) is
             expected here until post-apply/Convert-BuildAccountToEligible.ps1
             has run, and is labelled as such;
           * a role-holding group outside the tier model, or a workload
             identity holding a privileged role - WARN;
           * PIM-eligible assignments and open activations - PASS (JIT).
         Break-Glass-Admins is checked in 3; tier groups in 6.
      6. Every PIM tier group (Privileged-IAM-Admins and pim-tier*) has no
         standing members: an ACTIVE assignment that is not an activation, or
         a member PIM does not know about (added outside PIM), is a WARN by
         name; open activations and eligible members are PASS. If PIM-for-
         Groups data cannot be read, any member is a WARN (an activation is
         expected for up to its 4h / 8h cap).
      7. Admin passkey coverage: the build account, every user directly
         ELIGIBLE for Global Administrator or a Tier-0 role, every eligible
         member of a Tier-0 tier group (pim-tier0*), and every STANDING member
         of PIM-Azure-RG-Contributors (in CA002 / CA020 at every sign-in) must
         be in a passkey
         include target whose allowed profile accepts their registered key.
         Eligible people are NOT members of a PIM group outside an activation,
         so the target must be a standing group (Admin-Accounts). Not covered,
         or every registered key blocked by the allow-list, is a FAIL (CA002 /
         CA021 enforcement would lock them out); no key registered yet is a
         WARN.

.PREREQUISITES
    * Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
      Microsoft.Graph.Users, Microsoft.Graph.Identity.Governance,
      Microsoft.Graph.Identity.SignIns.

.GRAPH SCOPES  (delegated, READ-ONLY)
    Group.Read.All                    groups, types, members
    User.Read.All                     break-glass accounts, role holders' names
    RoleManagement.Read.Directory     role assignment / eligibility instances
    Policy.Read.All                   Conditional Access policies, passkey (FIDO2) policy
    UserAuthenticationMethod.Read.All registered passkey models (check 7)
    PrivilegedAssignmentSchedule.Read.AzureADGroup, PrivilegedEligibilitySchedule.Read.AzureADGroup
                                      PIM-for-Groups membership of the tier groups

.PARAMETER OnMicrosoftDomain
    The tenant's initial *.onmicrosoft.com domain the break-glass accounts must
    live on (same value as Terraform's onmicrosoft_domain).

.PARAMETER BuildAccountUpn
    The tenant-creation account that built the lab (setup step: a cloud-only
    Global Administrator). Default admin@<OnMicrosoftDomain>. Labels its WARN
    in check 5; check 7 requires it to keep a usable admin passkey.

.PARAMETER PimTierGroupPrefix
    mailNickname prefix of the PIM tier groups (lab/terraform/modules/pim
    tiers.tf). Default pim-tier.

.EXAMPLE
    Connect-MgGraph -Scopes 'Group.Read.All','User.Read.All','RoleManagement.Read.Directory','Policy.Read.All','PrivilegedAssignmentSchedule.Read.AzureADGroup','PrivilegedEligibilitySchedule.Read.AzureADGroup','UserAuthenticationMethod.Read.All'
    ./01-Verify-Baseline.ps1 -OnMicrosoftDomain 'contosohealthlab.onmicrosoft.com'

.NOTES
    TENANT-TIME: not run against a tenant yet.
    verify: the tenant-creation Global Administrator shows in
      roleAssignmentScheduleInstances as assignmentType "Assigned",
      memberType "Direct".
    verify: whether role-holding groups also yield per-user instance rows with
      memberType "Group" (skipped here; the group row is what counts).
    verify: whether a member added to a PIM-governed group OUTSIDE PIM shows
      as an "Assigned" PIM-for-Groups instance (reported as a standing member)
      or not at all (reported as "member outside PIM"). Both are WARNs.

.WHAT IT DEMONSTRATES
    Treating "break-glass is excluded from every CA policy" as a continuously
    verified control, not a one-time setup step - and a clean single-owner
    model between IaC, HR, and operational scripts.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9-]+\.onmicrosoft\.com$',
        ErrorMessage = 'OnMicrosoftDomain must look like <tenant>.onmicrosoft.com')]
    [string]$OnMicrosoftDomain,

    [Parameter()]
    [ValidatePattern('^$|^[^@\s]+@[A-Za-z0-9.-]+$', ErrorMessage = 'BuildAccountUpn must look like name@domain')]
    [string]$BuildAccountUpn = '',

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]{1,40}$', ErrorMessage = 'PimTierGroupPrefix: lowercase letters, digits, - only.')]
    [string]$PimTierGroupPrefix = 'pim-tier'
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

# Global Administrator role TEMPLATE id (constant across every tenant).
$GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
if (-not $BuildAccountUpn) { $BuildAccountUpn = "admin@$OnMicrosoftDomain" }

# =============================================================================
# PURE FUNCTIONS (no I/O) - tests/01-Verify-Baseline.Tests.ps1 loads them from
# this file's syntax tree.
# =============================================================================
function Get-RoleTierMap {
    # Directory role template id -> lab tier (Enterprise Access Model: Tier 0 =
    # control plane, Tier 1 = management plane), as lab/terraform/modules/pim
    # binds them to PIM tier groups. Global Administrator is its own key: it is
    # never bound to a tier group (per-person direct eligibility; break-glass
    # keeps it standing). Template ids checked against Learn "Microsoft Entra
    # built-in roles" (entra-docs permissions-reference) on 2026-10-20. Same
    # map in 08-Measure-KPIs.ps1; tests/08-Measure-KPIs.Tests.ps1 checks the
    # two agree and cover every modules/pim pim_tier_groups default.
    return [ordered]@{
        '62e90394-69f5-4237-9190-012177145e10' = @{ Name = 'Global Administrator'; Tier = 'global_admin' }
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = @{ Name = 'Privileged Role Administrator'; Tier = 'tier0' }
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = @{ Name = 'Privileged Authentication Administrator'; Tier = 'tier0' }
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ Name = 'Security Administrator'; Tier = 'tier0' }
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = @{ Name = 'Conditional Access Administrator'; Tier = 'tier0' }
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = @{ Name = 'Hybrid Identity Administrator'; Tier = 'tier0' }
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = @{ Name = 'Application Administrator'; Tier = 'tier0' }
        '158c047a-c907-4556-b7ef-446551a6b5f7' = @{ Name = 'Cloud Application Administrator'; Tier = 'tier0' }
        '0526716b-113d-4c15-b2c8-68e3c22b9f80' = @{ Name = 'Authentication Policy Administrator'; Tier = 'tier0' }
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = @{ Name = 'User Administrator'; Tier = 'tier1' }
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' = @{ Name = 'Groups Administrator'; Tier = 'tier1' }
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = @{ Name = 'Authentication Administrator'; Tier = 'tier1' }
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = @{ Name = 'Helpdesk Administrator'; Tier = 'tier1' }
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = @{ Name = 'Intune Administrator'; Tier = 'tier1' }
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = @{ Name = 'Exchange Administrator'; Tier = 'tier1' }
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = @{ Name = 'SharePoint Administrator'; Tier = 'tier1' }
        '69091246-20e8-4a56-aa4d-066075b2a7a8' = @{ Name = 'Teams Administrator'; Tier = 'tier1' }
        '4d6ac14f-3453-41d0-bef9-a3e0c569773a' = @{ Name = 'License Administrator'; Tier = 'tier1' }
        '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e' = @{ Name = 'Identity Governance Administrator'; Tier = 'tier1' }
        '59d46f88-662b-457b-bceb-5c3809e5908f' = @{ Name = 'Lifecycle Workflows Administrator'; Tier = 'tier1' }
    }
}

function Get-DirectRoleFinding {
    # Check 5. Rows are role assignment / eligibility schedule INSTANCES
    # normalised to PrincipalId, PrincipalType (user|group|servicePrincipal),
    # Name (UPN or display name), RoleDefinitionId, AssignmentType
    # (Assigned|Activated; eligibility rows: Eligible), MemberType.
    # Returns Check/Status/Detail rows; the caller prints them.
    param(
        [AllowEmptyCollection()][object[]]$ActiveRows = @(),
        [AllowEmptyCollection()][object[]]$EligibleRows = @(),
        [Parameter(Mandatory)][System.Collections.IDictionary]$PrivilegedRoles,   # role id -> display name
        [AllowEmptyCollection()][string[]]$BreakGlassUserIds = @(),
        [string]$BreakGlassGroupId = '',
        [AllowEmptyCollection()][string[]]$TierGroupIds = @(),
        [string]$BuildAccountUpn = ''
    )
    $out = [System.Collections.Generic.List[object]]::new()
    $buildUpn = $BuildAccountUpn
    $isBuild = { param($r) $buildUpn -and [string]$r.Name -ieq $buildUpn }
    $roleName = { param([string]$Id) if ($PrivilegedRoles.Contains($Id)) { [string]$PrivilegedRoles[$Id] } else { "role $Id" } }
    $standingHumans = 0; $activations = @(); $eligibleOther = @()
    foreach ($r in @($ActiveRows | Where-Object { $_ -and $PrivilegedRoles.Contains([string]$_.RoleDefinitionId) })) {
        $role = & $roleName ([string]$r.RoleDefinitionId)
        switch ([string]$r.PrincipalType) {
            'user' {
                # A memberType "Group" row is derived from a role-holding group: check 6 / the group row cover it.
                if ([string]$r.MemberType -eq 'Group' -or $r.PrincipalId -in $BreakGlassUserIds) { break }
                if ([string]$r.AssignmentType -eq 'Activated') { $activations += "$($r.Name) -> $role"; break }
                $standingHumans++
                if (& $isBuild $r) {
                    $out.Add([pscustomobject]@{ Check = "Standing $role"; Status = 'WARN'; Detail = "$($r.Name) (build account) - expected until post-apply/Convert-BuildAccountToEligible.ps1 runs; production target is zero" })
                }
                else {
                    $out.Add([pscustomobject]@{ Check = "Standing $role"; Status = 'WARN'; Detail = "$($r.Name) - a human with a standing privileged role outside break-glass; make it PIM-eligible (production target is zero)" })
                }
            }
            'group' {
                if (($BreakGlassGroupId -and $r.PrincipalId -eq $BreakGlassGroupId) -or $r.PrincipalId -in $TierGroupIds) { break }   # checks 3 and 6
                $out.Add([pscustomobject]@{ Check = "Group holds $role"; Status = 'WARN'; Detail = "$($r.Name) - role-holding group outside the PIM tier model; its members hold the role without PIM" })
            }
            'servicePrincipal' {
                $out.Add([pscustomobject]@{ Check = "Workload identity holds $role"; Status = 'WARN'; Detail = "$($r.Name) - standing directory role on a service principal; record it in the NHI inventory and risk register" })
            }
            default {
                $out.Add([pscustomobject]@{ Check = "Unknown principal holds $role"; Status = 'WARN'; Detail = "$($r.Name) ($($r.PrincipalType))" })
            }
        }
    }
    foreach ($e in @($EligibleRows | Where-Object { $_ -and $PrivilegedRoles.Contains([string]$_.RoleDefinitionId) })) {
        if ([string]$e.PrincipalType -ne 'user' -or [string]$e.MemberType -eq 'Group') { continue }
        $role = & $roleName ([string]$e.RoleDefinitionId)
        if (& $isBuild $e) { $out.Add([pscustomobject]@{ Check = "Eligible $role"; Status = 'PASS'; Detail = "$($e.Name) (build account) - PIM-eligible, activates just in time" }) }
        else { $eligibleOther += "$($e.Name) -> $role" }
    }
    if ($standingHumans -eq 0) { $out.Insert(0, [pscustomobject]@{ Check = 'Standing privileged roles (humans)'; Status = 'PASS'; Detail = 'none outside break-glass' }) }
    if ($eligibleOther.Count) { $out.Add([pscustomobject]@{ Check = 'Eligible-only (direct)'; Status = 'PASS'; Detail = "$($eligibleOther.Count): $(($eligibleOther | Sort-Object) -join '; ')" }) }
    if ($activations.Count) { $out.Add([pscustomobject]@{ Check = 'Open activations (direct)'; Status = 'PASS'; Detail = "$($activations.Count), just in time: $(($activations | Sort-Object) -join '; ')" }) }
    return $out.ToArray()
}

function Get-TierGroupFinding {
    # Check 6, one group. Assigned / Activated: PIM-for-Groups member
    # assignment-schedule instances (principal ids); Eligible: eligibility
    # instances; Members: current member ids. $null Assigned = PIM data
    # unreadable. Names: id -> UPN for the messages.
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [AllowNull()][AllowEmptyCollection()][string[]]$Assigned = $null,
        [AllowEmptyCollection()][string[]]$Activated = @(),
        [AllowEmptyCollection()][string[]]$Eligible = @(),
        [AllowEmptyCollection()][string[]]$Members = @(),
        [hashtable]$Names = @{},
        [string]$PimReadError = ''
    )
    $nameMap = $Names
    $nameOf = { param([string]$Id) if ($nameMap.ContainsKey($Id) -and $nameMap[$Id]) { [string]$nameMap[$Id] } else { $Id } }
    if ($null -eq $Assigned -or $PimReadError) {
        if (@($Members).Count -eq 0) { return @([pscustomobject]@{ Check = "$GroupName members"; Status = 'PASS'; Detail = 'zero members (PIM-for-Groups data unreadable, so eligibility not shown)' }) }
        return @([pscustomobject]@{ Check = "$GroupName members"; Status = 'WARN'; Detail = "$(@($Members).Count) member(s): $((@($Members) | ForEach-Object { & $nameOf $_ }) -join ', ') - fine during an open PIM activation, otherwise investigate (PIM-for-Groups data unreadable: $PimReadError)" })
    }
    $out = [System.Collections.Generic.List[object]]::new()
    $act = @($Activated | Where-Object { $_ })
    $standing = @($Assigned | Where-Object { $_ -and $_ -notin $act })
    $outside = @($Members | Where-Object { $_ -and $_ -notin $act -and $_ -notin $standing })
    foreach ($u in $standing) { $out.Add([pscustomobject]@{ Check = "$GroupName standing member"; Status = 'WARN'; Detail = "$(& $nameOf $u) - active assignment that is not an activation; make it eligible" }) }
    foreach ($u in $outside) { $out.Add([pscustomobject]@{ Check = "$GroupName member outside PIM"; Status = 'WARN'; Detail = "$(& $nameOf $u) - member PIM has no schedule for (added directly; never expires); remove and grant eligibility" }) }
    if ($out.Count -eq 0) {
        $msg = "zero standing members; $(@($Eligible | Where-Object { $_ } | Sort-Object -Unique).Count) eligible"
        if ($act.Count) { $msg += "; $($act.Count) activation(s) open ($((@($act) | ForEach-Object { & $nameOf $_ }) -join ', '))" }
        $out.Add([pscustomobject]@{ Check = "$GroupName members"; Status = 'PASS'; Detail = $msg })
    }
    return $out.ToArray()
}

function Test-PasskeyCoverage {
    # Which passkey (FIDO2) include targets cover ONE account, which profiles
    # they allow, and which of its registered keys a profile in scope still
    # accepts. Pure. Entra evaluates profiles as "any in scope satisfies".
    # PARITY: identical copies in Convert-BuildAccountToEligible.ps1,
    # 01-Verify-Baseline.ps1 and Invoke-BreakGlassDrill.ps1 (tested).
    #   Fido2Config  the fido2 authenticationMethodConfiguration (hashtable)
    #   GroupIds     the account's transitive group ids
    #   Keys         its fido2AuthenticationMethod objects (aaGuid used)
    param(
        [AllowNull()]$Fido2Config,
        [AllowNull()][AllowEmptyCollection()][string[]]$GroupIds = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$Keys = @()
    )
    $groups = @(@($GroupIds) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $r = [ordered]@{ Covered = $false; TargetIds = @(); ProfileIds = @(); AcceptedKeys = 0; RejectedAaguids = @(); Reason = '' }
    $cfg = $Fido2Config
    if ($null -eq $cfg -or $cfg -isnot [System.Collections.IDictionary] -or -not $cfg.Contains('state') -or [string]$cfg['state'] -ne 'enabled') {
        $r.Reason = 'the passkey (FIDO2) method is not enabled'; return [pscustomobject]$r
    }
    $ex = @(@($(if ($cfg.Contains('excludeTargets')) { $cfg['excludeTargets'] })) | Where-Object { $_ -is [System.Collections.IDictionary] -and ([string]$_['id']).ToLowerInvariant() -in $groups })
    if ($ex) { $r.Reason = "excluded from passkeys by target $([string]$ex[0]['id'])"; return [pscustomobject]$r }
    $targets = @(@($(if ($cfg.Contains('includeTargets')) { $cfg['includeTargets'] })) | Where-Object {
            $_ -is [System.Collections.IDictionary] -and ([string]$_['id'] -eq 'all_users' -or ([string]$_['id']).ToLowerInvariant() -in $groups) })
    if (-not $targets) { $r.Reason = 'no passkey include target covers this account'; return [pscustomobject]$r }
    $r.TargetIds = @($targets | ForEach-Object { [string]$_['id'] })
    # Restriction sets in scope: one per allowed profile, or the method-level
    # keyRestrictions when passkey profiles are not turned on.
    $sets = @()
    if ($cfg.Contains('passkeyProfiles') -and $null -ne $cfg['passkeyProfiles']) {
        $allowed = @($targets | ForEach-Object { if ($_.Contains('allowedPasskeyProfiles')) { @($_['allowedPasskeyProfiles']) } } | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
        $profiles = @(@($cfg['passkeyProfiles']) | Where-Object { $_ -is [System.Collections.IDictionary] -and ([string]$_['id']).ToLowerInvariant() -in $allowed })
        $r.ProfileIds = @($profiles | ForEach-Object { [string]$_['id'] })
        if (-not $profiles) { $r.Reason = 'the covering targets allow no existing passkey profile'; return [pscustomobject]$r }
        $sets = @($profiles | ForEach-Object { if ($_.Contains('keyRestrictions') -and $_['keyRestrictions'] -is [System.Collections.IDictionary]) { $_['keyRestrictions'] } else { @{} } })
    }
    else { $sets = @(if ($cfg.Contains('keyRestrictions') -and $cfg['keyRestrictions'] -is [System.Collections.IDictionary]) { $cfg['keyRestrictions'] } else { @{} }) }
    $r.Covered = $true
    foreach ($k in @(@($Keys) | Where-Object { $null -ne $_ })) {
        $g = ''
        if ($k -is [System.Collections.IDictionary] -and $k.Contains('aaGuid') -and $k['aaGuid']) { $g = ([string]$k['aaGuid']).ToLowerInvariant() }
        $ok = $false
        foreach ($kr in $sets) {
            if (-not $kr.Contains('isEnforced') -or $kr['isEnforced'] -ne $true) { $ok = $true; break }
            $list = @(@($kr['aaGuids']) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
            if ([string]$kr['enforcementType'] -eq 'block') { if ($g -notin $list) { $ok = $true; break } }
            elseif ($g -and $g -in $list) { $ok = $true; break }
        }
        if ($ok) { $r.AcceptedKeys++ } else { $r.RejectedAaguids += $(if ($g) { $g } else { '<no aaGuid>' }) }
    }
    return [pscustomobject]$r
}

function Get-PasskeyCoverageFinding {
    # Check 7, one principal: Test-PasskeyCoverage result -> finding.
    param([Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)]$Coverage, [int]$KeyCount = 0)
    $c = "Passkey target $Label"
    if (-not $Coverage.Covered) {
        return [pscustomobject]@{ Check = $c; Status = 'FAIL'; Detail = "$($Coverage.Reason): it cannot register or use an admin passkey, so CA002 / CA021 enforcement would lock it out. Add it to Admin-Accounts (post-apply/New-AdminAccounts.ps1) and re-run Set-AuthenticationMethodsPolicy.ps1" }
    }
    if ($KeyCount -eq 0) { return [pscustomobject]@{ Check = $c; Status = 'WARN'; Detail = "covered by $($Coverage.TargetIds -join ', '), but no passkey registered yet - register an issued key model before CA002 / CA021 are enforced" } }
    if ($Coverage.AcceptedKeys -eq 0) {
        return [pscustomobject]@{ Check = $c; Status = 'FAIL'; Detail = "every registered key ($KeyCount) is a model its profile blocks ($(@($Coverage.RejectedAaguids | Sort-Object -Unique) -join ', ')): enforcement would lock it out" }
    }
    if ($Coverage.RejectedAaguids.Count) {
        return [pscustomobject]@{ Check = $c; Status = 'WARN'; Detail = "$($Coverage.AcceptedKeys) usable key(s); $($Coverage.RejectedAaguids.Count) blocked by the allow-list ($(@($Coverage.RejectedAaguids | Sort-Object -Unique) -join ', '))" }
    }
    return [pscustomobject]@{ Check = $c; Status = 'PASS'; Detail = "covered by $($Coverage.TargetIds -join ', '); $($Coverage.AcceptedKeys) usable key(s)" }
}

# Contract groups (must match lab/terraform/modules/groups).
$ContractGroups = @(
    @{ Nick = 'break-glass-admins';            Kind = 'role-assignable' }
    @{ Nick = 'privileged-iam-admins';         Kind = 'role-assignable' }
    @{ Nick = 'admin-accounts';                Kind = 'role-assignable' }
    @{ Nick = 'all-nurses';                    Kind = 'dynamic' }
    @{ Nick = 'all-icu';                       Kind = 'dynamic' }
    @{ Nick = 'app-servicenow-users';          Kind = 'assigned' }
    @{ Nick = 'app-aws-identitycenter-users';  Kind = 'assigned' }
    @{ Nick = 'app-okta-federation-users';     Kind = 'assigned' }
    @{ Nick = 'app-icu-criticalcare-users';    Kind = 'assigned' }
    @{ Nick = 'app-pharmacy-dispensing-users'; Kind = 'assigned' }
)

$requiredScopes = @('Group.Read.All', 'User.Read.All', 'RoleManagement.Read.Directory', 'Policy.Read.All',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'UserAuthenticationMethod.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = $requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes }
if ($missingScopes) { Write-Warning "Connected context is missing scope(s): $($missingScopes -join ', '). Checks may fail with 403." }

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Check, [ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$Status]
    Write-Host ("  [{0}] {1} - {2}" -f $Status, $Check, $Detail) -ForegroundColor $color
}

# ===========================================================================
# 1. CONTRACT GROUPS
# ===========================================================================
Write-Console "`n[1/7] Contract groups" -ForegroundColor Cyan
$groups = @{}
foreach ($g in $ContractGroups) {
    $found = Get-MgGroup -Filter "mailNickname eq '$($g.Nick)'" -Property 'id,displayName,groupTypes,isAssignableToRole,membershipRule' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $found) { Add-Result "Group $($g.Nick)" 'FAIL' 'missing - run the Terraform apply (enable_premium = true)'; continue }
    $groups[$g.Nick] = $found
    $isDynamic = @($found.GroupTypes) -contains 'DynamicMembership'
    $isRoleAssignable = [bool]$found.IsAssignableToRole
    $ok = switch ($g.Kind) {
        'dynamic'         { $isDynamic }
        'role-assignable' { $isRoleAssignable -and -not $isDynamic }
        'assigned'        { -not $isDynamic -and -not $isRoleAssignable }
    }
    if ($ok) { Add-Result "Group $($found.DisplayName)" 'PASS' $g.Kind }
    else { Add-Result "Group $($found.DisplayName)" 'FAIL' "expected $($g.Kind) (dynamic=$isDynamic, roleAssignable=$isRoleAssignable)" }
}

# ===========================================================================
# 2. BREAK-GLASS ACCOUNTS
# ===========================================================================
Write-Console "`n[2/7] Break-glass accounts" -ForegroundColor Cyan
$bgGroup = $groups['break-glass-admins']
$bgMemberIds = @()
if ($bgGroup) { $bgMemberIds = @(Get-MgGroupMember -GroupId $bgGroup.Id -All | ForEach-Object Id) }
$bgUsers = @(Get-MgUser -Filter "startswith(mailNickname,'bg-admin-')" -Property 'id,userPrincipalName,accountEnabled' -All)
if ($bgUsers.Count -lt 2) { Add-Result 'Break-glass count' 'FAIL' "found $($bgUsers.Count); keep at least two" }
else { Add-Result 'Break-glass count' 'PASS' "$($bgUsers.Count) accounts" }
foreach ($u in $bgUsers) {
    $problems = @()
    if (-not $u.UserPrincipalName.ToLowerInvariant().EndsWith("@$($OnMicrosoftDomain.ToLowerInvariant())")) { $problems += 'not on onmicrosoft.com domain' }
    if (-not $u.AccountEnabled) { $problems += 'disabled' }
    if ($u.Id -notin $bgMemberIds) { $problems += 'not in Break-Glass-Admins' }
    if ($problems) { Add-Result $u.UserPrincipalName 'FAIL' ($problems -join '; ') }
    else { Add-Result $u.UserPrincipalName 'PASS' 'enabled, onmicrosoft.com, in Break-Glass-Admins' }
}

# ===========================================================================
# 3. BREAK-GLASS HOLDS GLOBAL ADMIN
# ===========================================================================
Write-Console "`n[3/7] Break-glass role" -ForegroundColor Cyan
$gaAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$GlobalAdminRoleTemplateId'" -All)
if ($bgGroup -and ($gaAssignments | Where-Object PrincipalId -eq $bgGroup.Id)) {
    Add-Result 'Break-Glass-Admins = Global Admin' 'PASS' 'standing assignment present'
}
else { Add-Result 'Break-Glass-Admins = Global Admin' 'FAIL' 'no Global Administrator assignment on the group' }

# ===========================================================================
# 4. EVERY CA POLICY EXCLUDES BREAK-GLASS
# ===========================================================================
Write-Console "`n[4/7] Conditional Access exclusions" -ForegroundColor Cyan
$policies = @(Get-MgIdentityConditionalAccessPolicy -All)
if ($policies.Count -eq 0) { Add-Result 'CA policies' 'WARN' 'none found (expected 5, CA001-CA005, once enable_premium = true)' }
foreach ($p in $policies) {
    $excluded = @($p.Conditions.Users.ExcludeGroups)
    if ($bgGroup -and $bgGroup.Id -in $excluded) { Add-Result "CA '$($p.DisplayName)'" 'PASS' "excludes break-glass (state: $($p.State))" }
    else { Add-Result "CA '$($p.DisplayName)'" 'FAIL' "does NOT exclude Break-Glass-Admins (state: $($p.State)) - lockout risk" }
}

# Shared by checks 5 and 6: Graph helpers (hashtable output) and the PIM tier groups.
$graph = 'https://graph.microsoft.com/v1.0'
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new(); $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType HashTable
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    return $items.ToArray()
}
$upnCache = @{}
function Get-PrincipalName {
    # UPN for a user id (cached); the id itself when it cannot be resolved.
    param([string]$Id)
    if (-not $upnCache.ContainsKey($Id)) {
        $upnCache[$Id] = $Id
        try { $upnCache[$Id] = [string](Get-MgUser -UserId $Id -Property userPrincipalName).UserPrincipalName }
        catch { Write-Verbose "Principal $Id is not a readable user: $($_.Exception.Message)" }
    }
    return $upnCache[$Id]
}
$tierGroups = [ordered]@{}   # id -> display name
if ($groups['privileged-iam-admins']) { $tierGroups[$groups['privileged-iam-admins'].Id] = $groups['privileged-iam-admins'].DisplayName }
$tierLookupError = ''
try { foreach ($g in @(Get-MgGroup -Filter "startswith(mailNickname,'$PimTierGroupPrefix')" -Property 'id,displayName,mailNickname' -All)) { $tierGroups[$g.Id] = $g.DisplayName } }
catch { $tierLookupError = $_.Exception.Message }   # reported in check 6
# Break-glass = the bg-admin-NN accounts (check 2); anyone else in the group is not exempt here.
$bgUserIds = @($bgUsers | ForEach-Object Id)

# ===========================================================================
# 5. DIRECT PRIVILEGED ROLES: STANDING VS ELIGIBLE
# ===========================================================================
Write-Console "`n[5/7] Privileged directory roles: standing vs eligible" -ForegroundColor Cyan
$coverageIds = [ordered]@{}   # user id -> label, for check 7
try {
    $privRoles = [ordered]@{}
    $tierMap = Get-RoleTierMap
    foreach ($k in $tierMap.Keys) { $privRoles[$k] = $tierMap[$k]['Name'] }
    $normRow = {
        param($i, [string]$Kind)
        $p = $i['principal']
        $type = if ($p -is [System.Collections.IDictionary] -and $p.Contains('@odata.type')) { ([string]$p['@odata.type']) -replace '^#microsoft\.graph\.' } else { '' }
        $name = if ($p -is [System.Collections.IDictionary] -and $p.Contains('userPrincipalName') -and $p['userPrincipalName']) { [string]$p['userPrincipalName'] }
        elseif ($p -is [System.Collections.IDictionary] -and $p.Contains('displayName') -and $p['displayName']) { [string]$p['displayName'] }
        else { [string]$i['principalId'] }
        [pscustomobject]@{
            PrincipalId = [string]$i['principalId']; PrincipalType = $type; Name = $name; RoleDefinitionId = [string]$i['roleDefinitionId']
            AssignmentType = $(if ($Kind -eq 'Eligible') { 'Eligible' } else { [string]$i['assignmentType'] }); MemberType = [string]$i['memberType']
        }
    }
    $activeRows = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=principal" | ForEach-Object { & $normRow $_ 'Active' })
    $eligibleRows = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal" | ForEach-Object { & $normRow $_ 'Eligible' })
    # Any role a PIM tier group holds or is eligible for is privileged too.
    foreach ($r in @($activeRows + $eligibleRows)) {
        if ($r.PrincipalType -eq 'group' -and $tierGroups.Contains($r.PrincipalId) -and -not $privRoles.Contains($r.RoleDefinitionId)) { $privRoles[$r.RoleDefinitionId] = "role $($r.RoleDefinitionId) (held by $($tierGroups[$r.PrincipalId]))" }
    }
    # Check 7 input: users DIRECTLY eligible for Global Administrator or a Tier-0 role.
    foreach ($r in $eligibleRows) {
        if ($r.PrincipalType -eq 'user' -and $r.MemberType -ne 'Group' -and $tierMap.Contains($r.RoleDefinitionId) -and [string]$tierMap[$r.RoleDefinitionId]['Tier'] -in @('global_admin', 'tier0') -and $r.PrincipalId -notin $bgUserIds) {
            $coverageIds[$r.PrincipalId] = $r.Name
        }
    }
    $findings = Get-DirectRoleFinding -ActiveRows $activeRows -EligibleRows $eligibleRows -PrivilegedRoles $privRoles -BreakGlassUserIds $bgUserIds `
        -BreakGlassGroupId $(if ($bgGroup) { $bgGroup.Id } else { '' }) -TierGroupIds @($tierGroups.Keys) -BuildAccountUpn $BuildAccountUpn
    foreach ($f in $findings) { Add-Result $f.Check $f.Status $f.Detail }
}
catch {
    # An unread source is not "nobody holds a role".
    Add-Result 'Privileged directory roles' 'FAIL' "could not read role assignment / eligibility instances: $($_.Exception.Message)"
}

# ===========================================================================
# 6. PIM TIER GROUPS HAVE NO STANDING MEMBERS
# ===========================================================================
Write-Console "`n[6/7] PIM tier groups: no standing members" -ForegroundColor Cyan
# An unread source is not "no tier groups".
if ($tierLookupError) { Add-Result "PIM tier groups ($PimTierGroupPrefix*)" 'FAIL' "lookup failed: $tierLookupError" }
elseif ($tierGroups.Count -eq 0) { Add-Result 'PIM tier groups' 'WARN' "none found (Privileged-IAM-Admins missing - see [1/7]; pim-tier* groups need enable_pim_tiers = true)" }
foreach ($gid in @($tierGroups.Keys)) {
    $gname = [string]$tierGroups[$gid]
    $members = @(Get-MgGroupMember -GroupId $gid -All | ForEach-Object Id)
    $assigned = $null; $activated = @(); $eligible = @(); $pimError = ''
    try {
        $f = [uri]::EscapeDataString("groupId eq '$gid'")
        $asg = @(Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=$f" | Where-Object { [string]$_['accessId'] -eq 'member' })
        $elg = @(Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=$f" | Where-Object { [string]$_['accessId'] -eq 'member' })
        $assigned = @($asg | Where-Object { [string]$_['assignmentType'] -ne 'Activated' } | ForEach-Object { [string]$_['principalId'] })
        $activated = @($asg | Where-Object { [string]$_['assignmentType'] -eq 'Activated' } | ForEach-Object { [string]$_['principalId'] })
        $eligible = @($elg | ForEach-Object { [string]$_['principalId'] })
    }
    catch { $pimError = $_.Exception.Message }
    $names = @{}
    foreach ($id in @(@($members) + @($assigned) + @($activated) | Where-Object { $_ } | Sort-Object -Unique)) { $names[$id] = Get-PrincipalName $id }
    foreach ($f in (Get-TierGroupFinding -GroupName $gname -Assigned $assigned -Activated $activated -Eligible $eligible -Members $members -Names $names -PimReadError $pimError)) {
        Add-Result $f.Check $f.Status $f.Detail
    }
    # Check 7 input: eligible members of a Tier-0 tier group.
    if ($gname -match '(?i)tier0') {
        foreach ($id in @($eligible | Where-Object { $_ -and $_ -notin $bgUserIds })) { if (-not $coverageIds.Contains($id)) { $coverageIds[$id] = Get-PrincipalName $id } }
    }
}

# ===========================================================================
# 7. ADMIN PASSKEY COVERAGE
# ===========================================================================
Write-Console "`n[7/7] Admin passkey coverage (build account, Tier-0 / Global Administrator eligibles)" -ForegroundColor Cyan
# An eligible person is in a PIM group only DURING an activation, which needs
# the phishing-resistant step-up first: the key has to work through a STANDING
# target (Admin-Accounts), and the key's model has to pass the allow-list.
try {
    $bu = Get-MgUser -UserId $BuildAccountUpn -Property 'id,userPrincipalName' -ErrorAction Stop
    if ($bu -and $bu.Id) {
        if ($coverageIds.Contains([string]$bu.Id)) { $coverageIds.Remove([string]$bu.Id) }
        $coverageIds.Insert(0, [string]$bu.Id, "$BuildAccountUpn (build account)")
    }
}
catch { Write-Verbose "Build account $BuildAccountUpn not found: $($_.Exception.Message)" }
# Standing members of the Azure PIM group (modules/pim azure.tf): CA002 / CA020
# include the group, so they need an accepted key at EVERY sign-in.
try {
    $azg = Get-MgGroup -Filter "mailNickname eq 'pim-azure-rg-contributors'" -Property 'id' -ErrorAction Stop | Select-Object -First 1
    if ($azg) { foreach ($m in @(Get-MgGroupMember -GroupId $azg.Id -All -ErrorAction Stop)) { if ($m.Id -notin $bgUserIds -and -not $coverageIds.Contains([string]$m.Id)) { $coverageIds[[string]$m.Id] = "$(Get-PrincipalName ([string]$m.Id)) (PIM-Azure-RG-Contributors)" } } }
}
catch { Add-Result 'Passkey target PIM-Azure-RG-Contributors' 'FAIL' "could not read its members: $($_.Exception.Message)" }
if ($coverageIds.Count -eq 0) { Add-Result 'Admin passkey coverage' 'PASS' 'no build account or Tier-0 / Global Administrator eligible to check' }
else {
    $fido2Cfg = $null
    try { $fido2Cfg = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2" -OutputType HashTable }
    catch { Add-Result 'Admin passkey coverage' 'FAIL' "could not read the passkey (FIDO2) configuration: $($_.Exception.Message)" }
    if ($fido2Cfg) {
        foreach ($id in @($coverageIds.Keys)) {
            $label = [string]$coverageIds[$id]
            try {
                $keys = @(Get-GraphCollection -Uri "$graph/users/$id/authentication/fido2Methods")
                $grp = @(Get-GraphCollection -Uri "$graph/users/$id/transitiveMemberOf?`$select=id" | ForEach-Object { [string]$_['id'] })
                $f = Get-PasskeyCoverageFinding -Label $label -Coverage (Test-PasskeyCoverage -Fido2Config $fido2Cfg -GroupIds $grp -Keys $keys) -KeyCount $keys.Count
                Add-Result $f.Check $f.Status $f.Detail
            }
            catch { Add-Result "Passkey target $label" 'FAIL' "could not read its passkeys or groups: $($_.Exception.Message)" }
        }
    }
}

# ===========================================================================
# SUMMARY
# ===========================================================================
$fails = @($results | Where-Object Status -eq 'FAIL').Count
$warns = @($results | Where-Object Status -eq 'WARN').Count
Write-Console "`nBaseline verification: $fails FAIL, $warns WARN, $(@($results).Count - $fails - $warns) PASS" -ForegroundColor $(if ($fails) { 'Red' } elseif ($warns) { 'Yellow' } else { 'Green' })
if ($fails) {
    Write-Console 'Do NOT enforce Conditional Access until every FAIL is resolved.' -ForegroundColor Red
    exit 1
}
# Explicit success code: when dot-run in an interactive session, $LASTEXITCODE
# would otherwise keep whatever the previous native command left behind.
exit 0
