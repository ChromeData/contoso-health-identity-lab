<#
.SYNOPSIS
    Turns the build account's standing Global Administrator into a PIM-eligible
    direct assignment (expires after 180 days), then removes the standing
    assignment. Runs only after break-glass, the second Global Administrator
    path, alerting and the Global Administrator activation policy have all been
    verified; refuses on any failed check. -WhatIf runs every check and changes
    nothing.

.DESCRIPTION
    The lab is built from the tenant-creation account (admin@<tenant>), a
    cloud-only standing Global Administrator. 01-Verify-Baseline.ps1 [5/7]
    flags it by name. Zero standing access means it goes eligible too. This is
    the step most likely to lock the operator out, so the script checks first
    and refuses unless every check passes:

      [1/8] Build account     exists, enabled, cloud-only, not a break-glass
                              account or Break-Glass-Admins member, and holds
                              Global Administrator DIRECTLY and STANDING
                              (assignmentType Assigned) at "/". Already eligible
                              with nothing standing = nothing to do (exit 0).
      [2/8] Break-glass       >= 2 bg-admin-NN accounts, enabled, members of
                              Break-Glass-Admins (and on the onmicrosoft.com
                              domain when -OnMicrosoftDomain is given).
      [3/8] Second GA path    Break-Glass-Admins holds a PERMANENT active Global
                              Administrator assignment at "/" (no end date).
      [4/8] CA exclusion      EVERY Conditional Access policy excludes
                              Break-Glass-Admins.
      [5/8] Passkeys          each break-glass account has at least
                              -MinFido2KeysPerAccount USABLE FIDO2 passkeys, and
                              the build account has at least one (activating
                              Global Administrator needs phishing-resistant
                              sign-in once the c1 authentication context is
                              set). Usable = the account is in a passkey include
                              target AND a profile in scope accepts the key's
                              AAGUID; a break-glass key the enforced allow-list
                              blocks is a FAIL (verify: Learn says key
                              restrictions also stop keys already registered).
      [6/8] Alert rule        the break-glass sign-in rule is deployed AND
                              enabled (Sentinel NRT "contoso-break-glass-signin-nrt",
                              the scheduled "contoso-break-glass-signin" before
                              2026-11-05, or Log Analytics
                              "alert-contoso-break-glass-signin").
      [7/8] GA PIM policy     post-apply/Set-DirectoryRolePimPolicies.ps1 has
                              set the Global Administrator role policy:
                              activation needs approval, with at least one
                              enabled approver who is neither the build account
                              nor break-glass (otherwise the build account could
                              never activate); activation needs MFA or an
                              authentication context; eligible-assignment
                              expiry allows -EligibilityDuration.
      [8/8] Confirmation      the caller is not a break-glass account, and types
                              the build account UPN (or passes -ConfirmUpn).

    THEN (only when every check passed and ShouldProcess allows it)
      1. POST roleEligibilityScheduleRequests: adminAssign, Global
         Administrator, "/", expiration afterDuration -EligibilityDuration.
         Skipped when the eligibility already exists (re-run after a partial).
      2. Poll until that eligibility shows in roleEligibilityScheduleInstances.
         The standing assignment is never removed before this is confirmed.
      3. POST roleAssignmentScheduleRequests: adminRemove for the standing
         assignment.
      4. Poll until the standing assignment is gone, and re-check that
         Break-Glass-Admins still holds Global Administrator.
      5. Write the run record: lab/evidence/pim/<stamp>-build-account-
         conversion.json (+ .sha256) with check names, statuses and outcomes
         only - no UPN, object id or tenant name - and the full detail to the
         gitignored lab/evidence/out/pim/. Nothing is written on a refusal or
         under -WhatIf.

.PREREQUISITES
    * Run as the build account itself or as a second admin with Privileged
      Role Administrator (activated) - never as a break-glass account.
    * post-apply/Set-DirectoryRolePimPolicies.ps1 run with a second approver.
    * Both break-glass accounts drilled (Invoke-BreakGlassDrill.ps1) - this
      script checks the preconditions, not that the keys work.
    * az CLI signed in with Reader on the resource group (alert-rule check).
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated; admin consent)
    User.Read.All, GroupMember.Read.All, Policy.Read.All    accounts, groups, CA
    UserAuthenticationMethod.Read.All                       passkeys
    RoleManagement.Read.Directory                           role instances + role policy
    RoleEligibilitySchedule.ReadWrite.Directory             create the eligibility
    RoleAssignmentSchedule.ReadWrite.Directory              remove the standing assignment

.PARAMETER BuildAccountUpn
    The account to convert (setup: admin@<tenant>.onmicrosoft.com).

.PARAMETER EligibilityDuration
    How long the eligibility lasts before it must be renewed. Default P180D,
    the modules/pim global_admin_eligible_duration default (P15D..P180D).

.PARAMETER ConfirmUpn
    Non-interactive confirmation: must equal -BuildAccountUpn.

.PARAMETER ChangeTicket
    Change ticket number, stored in the record.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All','GroupMember.Read.All','Policy.Read.All','UserAuthenticationMethod.Read.All','RoleManagement.Read.Directory','RoleEligibilitySchedule.ReadWrite.Directory','RoleAssignmentSchedule.ReadWrite.Directory'
    ./Convert-BuildAccountToEligible.ps1 -BuildAccountUpn 'admin@<tenant>.onmicrosoft.com' -OnMicrosoftDomain '<tenant>.onmicrosoft.com' -WhatIf
    ./Convert-BuildAccountToEligible.ps1 -BuildAccountUpn 'admin@<tenant>.onmicrosoft.com' -OnMicrosoftDomain '<tenant>.onmicrosoft.com' -ChangeTicket 'CHG0001234'

.NOTES
    TENANT-TIME: never run - no tenant exists yet. Nothing under
    lab/evidence/pim/ may be cited until this script has produced it.
    verify: roleAssignmentScheduleRequests adminRemove removes an assignment
      made outside PIM (the tenant-creation Global Administrator). If it does
      not, remove it in the portal (Roles and administrators > Global
      Administrator > Assignments) or with DELETE /roleManagement/directory/
      roleAssignments/{roleAssignmentOriginId}; then re-run this script to
      verify and record.
    verify: PIM accepts adminRemove when the caller removes their OWN
      assignment; if not, run step 3 as a second admin.
    verify: $filter on principalId and roleDefinitionId for the schedule
      instance lists (documented eq support).
    verify: /users/{id}/authentication/fido2Methods returns aaGuid for every
      registered passkey (the [5/8] key-model check depends on it).
    The Global Administrator role policy itself (approval, auth context,
    expiry) is owned by post-apply/Set-DirectoryRolePimPolicies.ps1; this
    script only READS it.

.WHAT IT DEMONSTRATES
    Removing the last standing human admin as a gated change: preconditions
    proven by code, the order that cannot lock you out (eligible first,
    standing removed second, break-glass re-checked), and a record that only
    exists if the change really happened.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', ErrorMessage = 'BuildAccountUpn must look like name@domain')]
    [string]$BuildAccountUpn,

    [Parameter()]
    [ValidatePattern('^$|^[A-Za-z0-9-]+\.onmicrosoft\.com$', ErrorMessage = 'OnMicrosoftDomain must look like <tenant>.onmicrosoft.com')]
    [string]$OnMicrosoftDomain = '',

    [Parameter()]
    # Same set modules/pim allows for global_admin_eligible_duration (GA
    # eligibility expires within 180 days); [7/8] also checks the live cap.
    [ValidateSet('P15D', 'P30D', 'P90D', 'P180D')]
    [string]$EligibilityDuration = 'P180D',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidateRange(1, 5)]
    [int]$MinFido2KeysPerAccount = 1,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup = 'rg-identity-lab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName = 'loga-idlab',

    [Parameter()]
    [string]$ConfirmUpn = '',

    [Parameter()]
    [ValidatePattern('^$|^[A-Za-z0-9._-]{1,32}$', ErrorMessage = 'A ticket number such as CHG0001234.')]
    [string]$ChangeTicket = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Justification = 'Zero standing access: build account standing Global Administrator converted to PIM-eligible after break-glass verification.',

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$VerifyAttempts = 12,

    [Parameter()]
    [ValidateRange(0, 120)]
    [int]$VerifyDelaySeconds = 10,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..' '..' '..' 'evidence' 'pim'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PrivateDirectory = (Join-Path $PSScriptRoot '..' '..' '..' 'evidence' 'out' 'pim')
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
$GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'

# =============================================================================
# PURE FUNCTIONS (tests/Convert-BuildAccountToEligible.Tests.ps1)
# =============================================================================
function Get-ShortName {
    # 'bg-admin-01@tenant.onmicrosoft.com' -> 'bg-admin-01'. Anything else -> $null.
    param([string]$UserPrincipalName)
    if ($UserPrincipalName -match '(?i)^(bg-admin-\d{2})@') { return $Matches[1].ToLowerInvariant() }
    return $null
}

function Test-GaRolePolicy {
    # Reads the Global Administrator role-management policy rules (Graph
    # unifiedRoleManagementPolicy rules, as hashtables) and says whether
    # Set-DirectoryRolePimPolicies.ps1's settings are in place. Returns
    # Problems (empty = OK), the approver references to resolve, and how
    # activation is authenticated.
    param([AllowEmptyCollection()][object[]]$Rules = @(), [Parameter(Mandatory)][string]$RequestedDuration)
    $byId = @{}; foreach ($r in @($Rules | Where-Object { $_ })) { $byId[[string]$r['id']] = $r }
    $problems = [System.Collections.Generic.List[string]]::new()
    $approvers = [System.Collections.Generic.List[object]]::new()
    $appr = $byId['Approval_EndUser_Assignment']
    $setting = if ($appr -and $appr.Contains('setting')) { $appr['setting'] } else { $null }
    if (-not $setting -or $setting['isApprovalRequired'] -ne $true) { $problems.Add('activation does not require approval (run post-apply/Set-DirectoryRolePimPolicies.ps1)') }
    else {
        foreach ($stage in @($setting['approvalStages'] | Where-Object { $_ })) {
            foreach ($a in @($stage['primaryApprovers'] | Where-Object { $_ })) {
                $type = ([string]$a['@odata.type']) -replace '^#microsoft\.graph\.'
                switch ($type) {
                    'singleUser' { $approvers.Add([pscustomobject]@{ Type = 'user'; Id = [string]$a['userId'] }) }
                    'groupMembers' { $approvers.Add([pscustomobject]@{ Type = 'group'; Id = [string]$a['groupId'] }) }
                    default { $approvers.Add([pscustomobject]@{ Type = $type; Id = '' }) }
                }
            }
        }
        if ($approvers.Count -eq 0) { $problems.Add('approval is required but no approver is set') }
    }
    $mfa = $byId['Enablement_EndUser_Assignment']
    $hasMfa = $mfa -and @($mfa['enabledRules']) -contains 'MultiFactorAuthentication'
    $ctxRule = $byId['AuthenticationContext_EndUser_Assignment']
    $hasCtx = $ctxRule -and $ctxRule['isEnabled'] -eq $true -and [string]$ctxRule['claimValue']
    $auth = if ($hasCtx) { "authentication context $([string]$ctxRule['claimValue'])" } elseif ($hasMfa) { 'MFA' } else { 'none' }
    if ($auth -eq 'none') { $problems.Add('activation requires neither MFA nor an authentication context') }
    $exp = $byId['Expiration_Admin_Eligibility']
    if ($exp -and $exp['isExpirationRequired'] -eq $true) {
        try {
            if ([System.Xml.XmlConvert]::ToTimeSpan([string]$exp['maximumDuration']) -lt [System.Xml.XmlConvert]::ToTimeSpan($RequestedDuration)) {
                $problems.Add("eligible assignments are capped at $($exp['maximumDuration']), shorter than $RequestedDuration")
            }
        }
        catch { $problems.Add("eligible-assignment cap '$($exp['maximumDuration'])' is not an ISO 8601 duration") }
    }
    return [pscustomobject]@{ Problems = $problems.ToArray(); Approvers = $approvers.ToArray(); ActivationAuth = $auth }
}

function Measure-Approver {
    # Approver USERS (resolved: id, userPrincipalName, accountEnabled) -> the
    # ones who can actually approve the build account: enabled, not the build
    # account, not break-glass.
    param(
        [AllowEmptyCollection()][object[]]$ApproverUsers = @(),
        [Parameter(Mandatory)][string]$BuildAccountId,
        [AllowEmptyCollection()][string[]]$BreakGlassIds = @()
    )
    return @($ApproverUsers | Where-Object {
            $_ -and $_['accountEnabled'] -ne $false -and [string]$_['id'] -ne $BuildAccountId -and [string]$_['id'] -notin $BreakGlassIds -and
            -not (Get-ShortName ([string]$_['userPrincipalName']))
        } | ForEach-Object { [string]$_['userPrincipalName'] } | Sort-Object -Unique)
}

function Test-PublicRecordSafe {
    # The public record must not carry an email/UPN, IP address, GUID or
    # onmicrosoft domain. Same patterns as Invoke-BreakGlassDrill.ps1
    # (parity-tested). Emits the offending strings (call it inside @()).
    param([string]$Json)
    $bad = @()
    foreach ($p in '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', '\b\d{1,3}(\.\d{1,3}){3}\b', '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '(?i)onmicrosoft\.com', '(?i)\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){4,7}\b') {
        foreach ($m in [regex]::Matches($Json, $p)) { $bad += $m.Value }
    }
    return @($bad | Sort-Object -Unique)
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

# =============================================================================
# I/O HELPERS
# =============================================================================
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

function Invoke-GraphPost {
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][System.Collections.IDictionary]$Body)
    return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 10 -Compress) -ContentType 'application/json' -OutputType HashTable
}

function Invoke-AzJson {
    # Runs az, returns parsed JSON. -AllowNotFound turns a 404 into $null (a
    # rule that is not deployed is an answer, not an error). Same as
    # Invoke-BreakGlassDrill.ps1.
    param([Parameter(Mandatory)][string[]]$Arguments, [switch]$AllowNotFound)
    $PSNativeCommandUseErrorActionPreference = $false
    $out = & az @Arguments --only-show-errors -o json 2>&1
    $stderr = (@($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) | ForEach-Object { $_.ToString() }) -join ' '
    $stdout = (@($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        if ($AllowNotFound -and $stderr -match '(?i)NotFound|\(404\)|was not found') { return $null }
        throw "az $($Arguments[0..1] -join ' ') failed: $stderr"
    }
    if (-not $stdout.Trim()) { return $null }
    return $stdout | ConvertFrom-Json
}

function Get-GaInstance {
    # Active (Assignment) or eligible (Eligibility) Global Administrator
    # instances for one principal, tenant scope only.
    param([Parameter(Mandatory)][string]$PrincipalId, [ValidateSet('Assignment', 'Eligibility')][string]$Kind)
    $f = [uri]::EscapeDataString("principalId eq '$PrincipalId' and roleDefinitionId eq '$GlobalAdminRoleTemplateId'")
    return @(Get-GraphCollection -Uri "$graph/roleManagement/directory/role$($Kind)ScheduleInstances?`$filter=$f" | Where-Object { [string]$_['directoryScopeId'] -eq '/' })
}

function Wait-Condition {
    # Polls a read-only scriptblock until it returns $true.
    param([Parameter(Mandatory)][scriptblock]$Condition, [int]$Attempts, [int]$DelaySeconds)
    for ($i = 1; $i -le $Attempts; $i++) {
        if (& $Condition) { return $true }
        if ($i -lt $Attempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return $false
}

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    # Label is public (no UPN / id); Detail stays in the private record.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Label, [ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status, [string]$Detail)
    $checks.Add([pscustomobject]@{ Check = $Label; Status = $Status; Detail = $Detail })
    Write-Host ("  [{0}] {1} - {2}" -f $Status, $Label, $Detail) -ForegroundColor @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$Status]
}

# =============================================================================
# CONNECT
# =============================================================================
$requiredScopes = @('User.Read.All', 'GroupMember.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory',
    'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory')
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Checks needing them will FAIL." }

# =============================================================================
# CHECKS (read-only)
# =============================================================================
$state = [ordered]@{ BuildId = ''; Standing = @(); Eligible = @(); BgGroupId = ''; BgIds = @() }

Write-Console "`n[1/8] Build account" -ForegroundColor Cyan
$build = $null
try {
    $f = [uri]::EscapeDataString("userPrincipalName eq '$BuildAccountUpn'")
    $build = @(Get-GraphCollection -Uri "$graph/users?`$filter=$f&`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled") | Select-Object -First 1
    if (-not $build) { Add-Check 'Build account' 'FAIL' "$BuildAccountUpn not found" }
    else {
        $state.BuildId = [string]$build['id']
        $problems = @()
        if ($build['accountEnabled'] -eq $false) { $problems += 'disabled' }
        if ($build['onPremisesSyncEnabled'] -eq $true) { $problems += 'synced from AD (an admin account must be cloud-only)' }
        if (Get-ShortName $BuildAccountUpn) { $problems += 'is a break-glass account' }
        $active = @(Get-GaInstance -PrincipalId $state.BuildId -Kind Assignment)
        $state.Standing = @($active | Where-Object { [string]$_['assignmentType'] -eq 'Assigned' -and [string]$_['memberType'] -ne 'Group' })
        $state.Eligible = @(Get-GaInstance -PrincipalId $state.BuildId -Kind Eligibility | Where-Object { [string]$_['memberType'] -ne 'Group' })
        $viaGroup = @($active | Where-Object { [string]$_['memberType'] -eq 'Group' })
        if ($problems) { Add-Check 'Build account' 'FAIL' "$BuildAccountUpn - $($problems -join '; ')" }
        elseif ($state.Standing.Count -eq 0 -and $state.Eligible.Count -gt 0) {
            Add-Check 'Build account' 'PASS' "$BuildAccountUpn is already PIM-eligible for Global Administrator and holds no standing assignment - nothing to do"
            Write-Console "`nAlready converted. Nothing changed, nothing written." -ForegroundColor Green
            exit 0
        }
        elseif ($state.Standing.Count -eq 0 -and $viaGroup.Count) { Add-Check 'Build account' 'FAIL' "$BuildAccountUpn holds Global Administrator through a group; this script converts a direct assignment only" }
        elseif ($state.Standing.Count -eq 0) { Add-Check 'Build account' 'FAIL' "$BuildAccountUpn holds no standing Global Administrator - nothing to convert" }
        else { Add-Check 'Build account' 'PASS' "$BuildAccountUpn - enabled, cloud-only, standing Global Administrator (direct)$(if ($state.Eligible.Count) { '; already eligible too (re-run after a partial)' })" }
    }
}
catch { Add-Check 'Build account' 'FAIL' "could not read the build account or its role instances: $($_.Exception.Message)" }

Write-Console "`n[2/8] Break-glass accounts" -ForegroundColor Cyan
$bgUsers = @()
try {
    $gf = [uri]::EscapeDataString("mailNickname eq '$BreakGlassGroupMailNickname'")
    $bgGroup = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$gf&`$select=id") | Select-Object -First 1
    if (-not $bgGroup) { Add-Check 'Break-Glass-Admins' 'FAIL' 'group not found (Terraform enable_premium)' }
    else {
        $state.BgGroupId = [string]$bgGroup['id']
        $memberIds = @(Get-GraphCollection -Uri "$graph/groups/$($state.BgGroupId)/members?`$select=id" | ForEach-Object { [string]$_['id'] })
        if ($state.BuildId -and $state.BuildId -in $memberIds) { Add-Check 'Build account not in Break-Glass-Admins' 'FAIL' "$BuildAccountUpn is a member of Break-Glass-Admins: it would keep Global Administrator AND bypass every CA policy" }
        $uf = [uri]::EscapeDataString("startswith(mailNickname,'bg-admin-')")
        $bgUsers = @(Get-GraphCollection -Uri "$graph/users?`$filter=$uf&`$select=id,userPrincipalName,accountEnabled")
        $healthy = 0
        foreach ($u in $bgUsers) {
            $short = Get-ShortName ([string]$u['userPrincipalName'])
            $problems = @()
            if (-not $short) { $problems += 'UPN does not follow bg-admin-NN@' }
            if ($u['accountEnabled'] -eq $false) { $problems += 'disabled' }
            if ([string]$u['id'] -notin $memberIds) { $problems += 'not in Break-Glass-Admins' }
            if ($OnMicrosoftDomain -and -not ([string]$u['userPrincipalName']).ToLowerInvariant().EndsWith("@$($OnMicrosoftDomain.ToLowerInvariant())")) { $problems += 'not on the onmicrosoft.com domain' }
            if ($problems) { Add-Check "Break-glass $short" 'FAIL' ($problems -join '; ') } else { $healthy++; Add-Check "Break-glass $short" 'PASS' 'enabled, in Break-Glass-Admins' }
        }
        $state.BgIds = @($bgUsers | ForEach-Object { [string]$_['id'] })
        if ($healthy -lt 2) { Add-Check 'Break-glass count' 'FAIL' "$healthy healthy break-glass account(s); two are required before the last standing human admin goes" }
        else { Add-Check 'Break-glass count' 'PASS' "$healthy healthy accounts" }
    }
}
catch { Add-Check 'Break-glass accounts' 'FAIL' "could not read: $($_.Exception.Message)" }

Write-Console "`n[3/8] Second Global Administrator path (break-glass)" -ForegroundColor Cyan
try {
    if (-not $state.BgGroupId) { Add-Check 'Second GA path' 'FAIL' 'Break-Glass-Admins not found' }
    else {
        $bgGa = @(Get-GaInstance -PrincipalId $state.BgGroupId -Kind Assignment | Where-Object { [string]$_['assignmentType'] -eq 'Assigned' -and -not $_['endDateTime'] })
        if ($bgGa.Count) { Add-Check 'Second GA path' 'PASS' 'Break-Glass-Admins holds a permanent active Global Administrator assignment at /' }
        else { Add-Check 'Second GA path' 'FAIL' 'Break-Glass-Admins holds no permanent active Global Administrator at / - converting would leave no standing way back in' }
    }
}
catch { Add-Check 'Second GA path' 'FAIL' "could not read: $($_.Exception.Message)" }

Write-Console "`n[4/8] Break-glass excluded from every Conditional Access policy" -ForegroundColor Cyan
try {
    $policies = @(Get-GraphCollection -Uri "$graph/identity/conditionalAccess/policies")
    $notExcluded = @($policies | Where-Object { $state.BgGroupId -notin @($_['conditions']['users']['excludeGroups']) })
    if (-not $state.BgGroupId) { Add-Check 'CA exclusion' 'FAIL' 'Break-Glass-Admins not found' }
    elseif ($policies.Count -eq 0) { Add-Check 'CA exclusion' 'WARN' 'no Conditional Access policies found' }
    elseif ($notExcluded.Count) { Add-Check 'CA exclusion' 'FAIL' "$($notExcluded.Count) of $($policies.Count) policies do NOT exclude Break-Glass-Admins: $(@($notExcluded | ForEach-Object { $_['displayName'] }) -join '; ')" }
    else { Add-Check 'CA exclusion' 'PASS' "all $($policies.Count) policies exclude Break-Glass-Admins" }
}
catch { Add-Check 'CA exclusion' 'FAIL' "could not read Conditional Access policies: $($_.Exception.Message)" }

Write-Console "`n[5/8] Passkeys (FIDO2): registered, covered by a passkey target, accepted by its profile" -ForegroundColor Cyan
# Counting keys is not enough: a key only works while (a) a passkey include
# target covers the account and (b) a profile in scope accepts the key's model.
# An enforced AAGUID allow-list blocks keys already registered (verify: Learn,
# passkey profile key restrictions), and break-glass is FIDO2-only - a key
# outside the list is a break-glass lockout, and losing the target is a
# build-account lockout once it depends on CA021 / CA002.
$fido2Cfg = $null
try { $fido2Cfg = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2" -OutputType HashTable }
catch { Add-Check 'Passkey policy' 'FAIL' "could not read the passkey (FIDO2) method configuration: $($_.Exception.Message)" }
function Get-PasskeyState {
    param([string]$UserId)
    $keys = @(Get-GraphCollection -Uri "$graph/users/$UserId/authentication/fido2Methods")
    $groups = @(Get-GraphCollection -Uri "$graph/users/$UserId/transitiveMemberOf?`$select=id" | ForEach-Object { [string]$_['id'] })
    return [pscustomobject]@{ Keys = $keys.Count; Coverage = (Test-PasskeyCoverage -Fido2Config $fido2Cfg -GroupIds $groups -Keys $keys) }
}
if ($fido2Cfg) {
    foreach ($u in $bgUsers) {
        $short = Get-ShortName ([string]$u['userPrincipalName'])
        if (-not $short) { continue }   # already a FAIL in [2/8]
        try {
            $ps = Get-PasskeyState ([string]$u['id']); $cov = $ps.Coverage; $n = $cov.AcceptedKeys
            if (-not $cov.Covered) { Add-Check "Passkeys $short" 'FAIL' "$($ps.Keys) FIDO2 key(s) but $($cov.Reason): break-glass could not sign in with them" }
            elseif ($cov.RejectedAaguids.Count) { Add-Check "Passkeys $short" 'FAIL' "$($cov.RejectedAaguids.Count) registered key(s) of a model the enforced allow-list blocks ($(@($cov.RejectedAaguids | Sort-Object -Unique) -join ', ')): add the model to admin_fido2_allowed_aaguids or re-key break-glass first" }
            elseif ($n -ge $MinFido2KeysPerAccount) { Add-Check "Passkeys $short" $(if ($n -ge 2) { 'PASS' } else { 'WARN' }) "$n usable FIDO2 key(s)$(if ($n -lt 2) { '; the standard is two, one per safe' })" }
            else { Add-Check "Passkeys $short" 'FAIL' "$n usable FIDO2 key(s); at least $MinFido2KeysPerAccount required" }
        }
        catch { Add-Check "Passkeys $short" 'FAIL' "could not read authentication methods or groups: $($_.Exception.Message)" }
    }
    if ($bgUsers.Count -eq 0) { Add-Check 'Passkeys break-glass' 'FAIL' 'no break-glass account to check' }
    if ($state.BuildId) {
        try {
            $ps = Get-PasskeyState $state.BuildId; $cov = $ps.Coverage
            if (-not $cov.Covered) { Add-Check 'Passkeys build account' 'FAIL' "$BuildAccountUpn - $($cov.Reason): it could not use an admin passkey, so once eligible it could never activate Global Administrator under the c1 context. Add it to Admin-Accounts (post-apply/New-AdminAccounts.ps1) and re-run Set-AuthenticationMethodsPolicy.ps1" }
            elseif ($cov.AcceptedKeys -ge 1) { Add-Check 'Passkeys build account' 'PASS' "$($cov.AcceptedKeys) usable passkey(s) via $($cov.TargetIds -join ', ') - can satisfy a phishing-resistant activation" }
            else { Add-Check 'Passkeys build account' 'FAIL' "$BuildAccountUpn has no passkey its profile accepts ($($ps.Keys) registered$(if ($cov.RejectedAaguids.Count) { "; blocked models: $(@($cov.RejectedAaguids | Sort-Object -Unique) -join ', ')" })): once eligible it could not activate Global Administrator under the c1 context (register an issued model first)" }
        }
        catch { Add-Check 'Passkeys build account' 'FAIL' "could not read authentication methods or groups: $($_.Exception.Message)" }
    }
}

Write-Console "`n[6/8] Break-glass sign-in alert rule" -ForegroundColor Cyan
try {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'az CLI not found (az login first)' }
    $subId = [string](Invoke-AzJson -Arguments @('account', 'show', '--query', 'id'))
    $ws = Invoke-AzJson -Arguments @('monitor', 'log-analytics', 'workspace', 'show', '-g', $ResourceGroup, '-n', $WorkspaceName)
    # Near-real-time rule since 2026-11-05 (modules/monitoring, name -nrt);
    # the scheduled name is still tried for a workspace applied before that.
    # 2025-01-01-preview: the GA alertRules versions do not return NRT rules
    # ("not found in version 2023-02-01", read live 2026-11-05).
    $sentinel = $null
    foreach ($ruleName in @('contoso-break-glass-signin-nrt', 'contoso-break-glass-signin')) {
        $sentinel = Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url', "https://management.azure.com$($ws.id)/providers/Microsoft.SecurityInsights/alertRules/$($ruleName)?api-version=2025-01-01-preview") -AllowNotFound
        if ($sentinel) { break }
    }
    $la = Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url', "https://management.azure.com/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/scheduledQueryRules/alert-contoso-break-glass-signin?api-version=2021-08-01") -AllowNotFound
    if ($sentinel -and $sentinel.properties.enabled) { Add-Check 'Alert rule' 'PASS' "Sentinel rule '$($sentinel.properties.displayName)' enabled" }
    elseif ($la -and $la.properties.enabled) { Add-Check 'Alert rule' 'PASS' "Log Analytics alert '$($la.properties.displayName)' enabled" }
    elseif ($sentinel -or $la) { Add-Check 'Alert rule' 'FAIL' 'the break-glass rule exists but is DISABLED' }
    else { Add-Check 'Alert rule' 'FAIL' 'no break-glass sign-in rule deployed (Terraform enable_sentinel or enable_la_alerts)' }
}
catch { Add-Check 'Alert rule' 'FAIL' "could not check: $($_.Exception.Message)" }

Write-Console "`n[7/8] Global Administrator PIM policy (Set-DirectoryRolePimPolicies.ps1)" -ForegroundColor Cyan
try {
    $pf = [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$GlobalAdminRoleTemplateId'")
    $pa = @(Get-GraphCollection -Uri "$graph/policies/roleManagementPolicyAssignments?`$filter=$pf&`$expand=policy(`$expand=rules)") | Select-Object -First 1
    if (-not $pa -or -not $pa['policy']) { throw 'no role-management policy assignment found for Global Administrator' }
    $pol = Test-GaRolePolicy -Rules @($pa['policy']['rules']) -RequestedDuration $EligibilityDuration
    foreach ($p in $pol.Problems) { Add-Check 'GA PIM policy' 'FAIL' $p }
    if (-not $pol.Problems.Count) {
        Add-Check 'GA PIM policy' 'PASS' "approval required; activation needs $($pol.ActivationAuth); eligibility of $EligibilityDuration allowed"
        $users = @()
        foreach ($a in $pol.Approvers) {
            if ($a.Type -eq 'user' -and $a.Id) { try { $users += @(Invoke-MgGraphRequest -Method GET -Uri "$graph/users/$($a.Id)?`$select=id,userPrincipalName,accountEnabled" -OutputType HashTable) } catch { Write-Verbose "approver $($a.Id) unreadable: $($_.Exception.Message)" } }
            elseif ($a.Type -eq 'group' -and $a.Id) { $users += @(Get-GraphCollection -Uri "$graph/groups/$($a.Id)/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,accountEnabled") }
        }
        $usable = @(Measure-Approver -ApproverUsers $users -BuildAccountId $(if ($state.BuildId) { $state.BuildId } else { '-' }) -BreakGlassIds $state.BgIds)
        if ($usable.Count) { Add-Check 'GA approvers' 'PASS' "$($usable.Count) approver(s) other than the build account and break-glass: $($usable -join ', ')" }
        else { Add-Check 'GA approvers' 'FAIL' 'no enabled approver other than the build account and break-glass - the build account could never activate (add a second approver, then re-run Set-DirectoryRolePimPolicies.ps1)' }
    }
}
catch { Add-Check 'GA PIM policy' 'FAIL' "could not read the Global Administrator role policy: $($_.Exception.Message)" }

# =============================================================================
# REFUSE / WHATIF / CONFIRM
# =============================================================================
function Show-Refusal {
    $f = @($checks | Where-Object Status -eq 'FAIL')
    Write-Host "`nREFUSED: $($f.Count) check(s) failed - nothing changed, nothing written." -ForegroundColor Red
    foreach ($c in $f) { Write-Host "  - $($c.Check): $($c.Detail)" -ForegroundColor Red }
}

Write-Console "`n[8/8] Confirmation" -ForegroundColor Cyan
$caller = [string]$ctx.Account
if (Get-ShortName $caller) { Add-Check 'Caller' 'FAIL' "signed in as $caller - break-glass is for emergencies, not routine changes (and the sign-in raises the alert)" }
else { Add-Check 'Caller' 'PASS' "$(if ($caller) { $caller } else { 'app-only context' })" }

if (@($checks | Where-Object Status -eq 'FAIL').Count) { Show-Refusal; exit 1 }

$plan = "create a PIM-eligible Global Administrator assignment for $BuildAccountUpn (afterDuration $EligibilityDuration), confirm it, then remove the standing assignment"
if ($WhatIfPreference) {
    Add-Check 'Confirmation' 'PASS' 'skipped (-WhatIf)'
    Write-Console "`nWhatIf: every check passed. Would $plan. Nothing changed, nothing written." -ForegroundColor Green
    exit 0
}
$typed = if ($ConfirmUpn) { $ConfirmUpn } else { Read-Host "Type the build account UPN ($BuildAccountUpn) to convert it" }
if ([string]$typed -ine $BuildAccountUpn) { Add-Check 'Confirmation' 'FAIL' 'the typed UPN does not match -BuildAccountUpn'; Show-Refusal; exit 1 }
Add-Check 'Confirmation' 'PASS' 'caller confirmed the build account UPN'
if (-not $PSCmdlet.ShouldProcess("Global Administrator for $BuildAccountUpn", $plan)) {
    Write-Console 'Not confirmed - nothing changed, nothing written.' -ForegroundColor Yellow
    exit 1
}

# =============================================================================
# ACT: eligible first, standing removed second, break-glass re-checked
# =============================================================================
$run = [ordered]@{
    EligibilityRequestStatus = $null; EligibilityRequestId = $null; EligibilityConfirmed = $false
    RemoveRequestStatus = $null; RemoveRequestId = $null; StandingRemovedConfirmed = $false
    BreakGlassGaIntactAfter = $false; Errors = @()
}
$startUtc = (Get-Date).ToUniversalTime()
try {
    if ($state.Eligible.Count -eq 0) {
        Write-Console "`nCreating the eligibility ($EligibilityDuration)..." -ForegroundColor Cyan
        $req = Invoke-GraphPost -Uri "$graph/roleManagement/directory/roleEligibilityScheduleRequests" -Body ([ordered]@{
                action = 'adminAssign'; justification = $Justification; roleDefinitionId = $GlobalAdminRoleTemplateId; directoryScopeId = '/'
                principalId = $state.BuildId
                scheduleInfo = [ordered]@{ startDateTime = $startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); expiration = [ordered]@{ type = 'afterDuration'; duration = $EligibilityDuration } }
            })
        $run.EligibilityRequestStatus = [string]$req['status']; $run.EligibilityRequestId = [string]$req['id']
        if ($run.EligibilityRequestStatus -match '(?i)fail|denied|revoked|canceled') { throw "eligibility request status '$($run.EligibilityRequestStatus)'" }
    }
    else { $run.EligibilityRequestStatus = 'already-eligible' }
    $run.EligibilityConfirmed = Wait-Condition -Attempts $VerifyAttempts -DelaySeconds $VerifyDelaySeconds -Condition {
        @(Get-GaInstance -PrincipalId $state.BuildId -Kind Eligibility | Where-Object { [string]$_['memberType'] -ne 'Group' }).Count -gt 0
    }
    if (-not $run.EligibilityConfirmed) { throw 'the eligibility did not appear in roleEligibilityScheduleInstances; the standing assignment was NOT removed' }
    # Break-glass could have changed since [3/8]: re-check right before removing.
    if (-not @(Get-GaInstance -PrincipalId $state.BgGroupId -Kind Assignment | Where-Object { [string]$_['assignmentType'] -eq 'Assigned' -and -not $_['endDateTime'] }).Count) {
        throw 'Break-Glass-Admins no longer holds a permanent Global Administrator assignment; the standing assignment was NOT removed'
    }

    Write-Console 'Eligibility confirmed. Removing the standing assignment...' -ForegroundColor Cyan
    $rm = Invoke-GraphPost -Uri "$graph/roleManagement/directory/roleAssignmentScheduleRequests" -Body ([ordered]@{
            action = 'adminRemove'; justification = $Justification; roleDefinitionId = $GlobalAdminRoleTemplateId; directoryScopeId = '/'; principalId = $state.BuildId
        })
    $run.RemoveRequestStatus = [string]$rm['status']; $run.RemoveRequestId = [string]$rm['id']
    $run.StandingRemovedConfirmed = Wait-Condition -Attempts $VerifyAttempts -DelaySeconds $VerifyDelaySeconds -Condition {
        @(Get-GaInstance -PrincipalId $state.BuildId -Kind Assignment | Where-Object { [string]$_['assignmentType'] -eq 'Assigned' -and [string]$_['memberType'] -ne 'Group' }).Count -eq 0
    }
    if (-not $run.StandingRemovedConfirmed) { throw 'the standing assignment is still listed after the adminRemove request (see .NOTES verify:)' }
}
catch { $run.Errors += $_.Exception.Message; Write-Warning $_.Exception.Message }
try {
    $run.BreakGlassGaIntactAfter = @(Get-GaInstance -PrincipalId $state.BgGroupId -Kind Assignment | Where-Object { [string]$_['assignmentType'] -eq 'Assigned' -and -not $_['endDateTime'] }).Count -gt 0
}
catch { $run.Errors += "break-glass re-check failed: $($_.Exception.Message)" }

$result = if ($run.EligibilityConfirmed -and $run.StandingRemovedConfirmed -and $run.BreakGlassGaIntactAfter -and -not @($run.Errors).Count) { 'Converted' }
elseif ($run.EligibilityConfirmed -or $run.EligibilityRequestStatus) { 'Partial' }
else { 'Failed' }

# =============================================================================
# RECORD (only reached when the change was attempted for real)
# =============================================================================
$now = (Get-Date).ToUniversalTime()
$stamp = $now.ToString('yyyyMMddTHHmmssZ')
$public = [ordered]@{
    schema                  = 'contoso-pim-build-account-conversion/v1'
    generatedAtUtc          = $now.ToString('o')
    generator               = 'lab/scripts/powershell/post-apply/Convert-BuildAccountToEligible.ps1'
    role                    = 'Global Administrator'
    result                  = $result
    eligibility             = [ordered]@{ expiration = 'afterDuration'; duration = $EligibilityDuration; requestStatus = $run.EligibilityRequestStatus; confirmed = $run.EligibilityConfirmed }
    standingAssignment      = [ordered]@{ removeRequestStatus = $run.RemoveRequestStatus; removalConfirmed = $run.StandingRemovedConfirmed }
    breakGlassGaIntactAfter = $run.BreakGlassGaIntactAfter
    errorCount              = @($run.Errors).Count
    changeTicket            = $(if ($ChangeTicket) { $ChangeTicket } else { $null })
    checks                  = @($checks | ForEach-Object { [ordered]@{ check = $_.Check; status = $_.Status } })
}
$json = $public | ConvertTo-Json -Depth 6
$leaks = @(Test-PublicRecordSafe -Json $json)
foreach ($d in $PrivateDirectory, $EvidenceDirectory) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
$privateFile = Join-Path $PrivateDirectory "$stamp-build-account-conversion-detail.json"
[ordered]@{ public = $public; buildAccountUpn = $BuildAccountUpn; buildAccountId = $state.BuildId; caller = $caller; run = $run; checks = @($checks) } |
    ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $privateFile -Encoding utf8NoBOM
if ($leaks.Count) {
    Write-Warning "Public record NOT written - it would contain identifiers ($($leaks.Count)); the full record is in $privateFile"
}
else {
    $file = Join-Path $EvidenceDirectory "$stamp-build-account-conversion.json"
    $json | Set-Content -LiteralPath $file -Encoding utf8NoBOM
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $stamp-build-account-conversion.json" | Set-Content -LiteralPath "$file.sha256" -Encoding utf8NoBOM
    Write-Console "`nRecord: $file (sha256 $hash)" -ForegroundColor Cyan
}
Write-Console "Detail (gitignored): $privateFile" -ForegroundColor DarkGray

if ($result -eq 'Converted') {
    Write-Console "`nCONVERTED: $BuildAccountUpn is PIM-eligible for Global Administrator ($EligibilityDuration) with no standing assignment; Break-Glass-Admins still holds it." -ForegroundColor Green
    Write-Console 'Next: run 01-Verify-Baseline.ps1 ([5/7] should show the build account as eligible, no WARN), then one test activation with approval.' -ForegroundColor Green
    exit 0
}
Write-Console "`n$($result.ToUpperInvariant()): $(@($run.Errors) -join '; ')" -ForegroundColor Red
Write-Console 'Break-glass was never touched. Re-run after fixing the cause: an existing eligibility is reused, and the standing assignment is only removed once the eligibility is confirmed.' -ForegroundColor Yellow
exit 1
