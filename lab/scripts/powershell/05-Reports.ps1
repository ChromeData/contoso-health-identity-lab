<#
.SYNOPSIS
    Hygiene/attestation reports for the Contoso Health tenant: stale accounts,
    users without MFA, STANDING privileged role holders, and guest sprawl.
    Writes a CSV per report and prints summaries to the console.

.DESCRIPTION
    The segment-9 metrics slide (standing admins 14->0, MFA 72%->100%, orphaned
    accounts 40->0) is ILLUSTRATIVE -- a lab has no "before" (see
    lab/docs/STAND-INS.md). These reports are the queries that would produce
    those numbers in a real tenant. Each run is ONE point-in-time snapshot, not
    a trend: keep the CSVs from scheduled runs if you want a measured one.

    REPORTS
      1. STALE ACCOUNTS       -- enabled users whose last interactive sign-in is
                                 older than -StaleDays (default 90), plus users
                                 that have never signed in. These are the orphan
                                 candidates offboarding should have caught.
                                 Break-glass accounts are excluded and counted
                                 separately: never signing in is their goal.
      2. USERS WITHOUT MFA    -- members not registered for a strong auth method,
                                 from the authentication-methods registration
                                 report. The gap behind "MFA coverage".
      3. STANDING PRIVILEGED  -- principals with PERMANENT (assignmentType=
                                 'Assigned') directory-role assignments on
                                 PRIVILEGED roles. In a zero-standing-admin
                                 design this should be ONLY the Break-Glass-Admins
                                 group (Terraform assigns Global Admin to the
                                 group, not to the bg-admin-NN users) and the
                                 Privileged-IAM-Admins group's User Administrator
                                 binding (modules/pim: the group holds the role,
                                 its membership is the just-in-time part, checked
                                 by 01-Verify-Baseline [6/7]); anyone else --
                                 including an operator/tenant-creator Global
                                 Admin left standing -- is a finding.
      4. GUEST SPRAWL         -- userType=Guest external identities, with
                                 creation date and last sign-in, to spot
                                 abandoned B2B guests.

.PREREQUISITES
    * Entra ID P1/P2 (signInActivity + registration report are Premium).
    * Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Users,
      Microsoft.Graph.Identity.DirectoryManagement,
      Microsoft.Graph.Identity.Governance, Microsoft.Graph.Reports.

.GRAPH SCOPES  (delegated; admin-consent -- all READ-ONLY)
    User.Read.All                 enumerate users, userType, signInActivity
    AuditLog.Read.All             signInActivity + authn-method registration report
    RoleManagement.Read.Directory read standing role assignments + role defs
                                  (privileged-role set from the beta isPrivileged flag)
    Directory.Read.All            Break-Glass-Admins group + members, general reads

.PARAMETER StaleDays
    Age threshold (days) for the stale-account report. Default 90.

.PARAMETER OutputDirectory
    Where CSVs are written. Default ./out beside this script (created if absent).

.PARAMETER SkipCsv
    Console-only; do not write CSV files.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory','Directory.Read.All'
    ./05-Reports.ps1 -StaleDays 60

.OUTPUTS
    Writes stale_accounts.csv, users_without_mfa.csv, standing_privileged.csv,
    guest_sprawl.csv (unless -SkipCsv) and returns a hashtable of the four
    result sets for further processing. A report whose query FAILS is never
    shown as a clean 0-row result: it prints FAILED in red, its CSV is a
    one-row FAILED stub, it is listed in FailedReports, and the script exits 1.

.WHAT IT DEMONSTRATES
    The access-review/attestation queries an auditor actually wants, expressed
    as least-privilege read-only Graph calls -- the data layer under the
    headline metrics.

.NOTES
    signInActivity can be null for accounts that have never signed in or very
    new ones; the stale report treats null lastSignIn on an enabled account as
    "never signed in" (a stale candidate), which is the conservative choice.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'out'),

    [Parameter()]
    [switch]$SkipCsv
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

$requiredScopes = @('User.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 and lookups may report 'not found' (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

if (-not $SkipCsv -and -not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$failedReports = @()
function Save-Report {
    # -FailedReason = the query failed. Say so in red and write a one-row FAILED
    # stub CSV (overwriting any earlier run), so a failure never reads as
    # "0 rows = clean".
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Name, [object[]]$Data, [string]$FailedReason)
    if ($FailedReason) {
        Write-Host "`n==== $Name -- FAILED, result UNKNOWN (not a pass) ====" -ForegroundColor Red
        $script:failedReports += $Name
        $Data = @([pscustomobject]@{ Report = $Name; Status = 'FAILED'; Error = $FailedReason })
    }
    else {
        Write-Host "`n==== $Name ($($Data.Count) rows) ====" -ForegroundColor Cyan
        if ($Data.Count) { $Data | Format-Table -AutoSize | Out-Host }
    }
    if (-not $SkipCsv) {
        $path = Join-Path $OutputDirectory ("{0}.csv" -f ($Name -replace '\s+', '_').ToLowerInvariant())
        $Data | Export-Csv -LiteralPath $path -NoTypeInformation
        Write-Host "  -> $path" -ForegroundColor DarkGray
    }
}

$cutoff = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)
$graph = 'https://graph.microsoft.com'
$GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'   # same in every tenant

# ---------------------------------------------------------------------------
# Break-glass contract (lab/terraform/modules/groups): Global Administrator is
# assigned to the Break-Glass-Admins GROUP, whose members are the bg-admin-NN
# accounts. Anchored on the group id, as in 01-Verify-Baseline; used by reports
# 1 and 3. Raw REST keeps this on the Authentication module.
# ---------------------------------------------------------------------------
$bgPrincipalIds = @(); $bgUserIds = @(); $bgOtherMembers = @()
$bgGroup = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/v1.0/groups?`$filter=mailNickname eq 'break-glass-admins'&`$select=id")['value']) |
    Select-Object -First 1
if (-not $bgGroup) {
    Write-Warning "Break-Glass-Admins (mailNickname 'break-glass-admins') not found: nothing is treated as break-glass, so every standing privileged assignment is reported as a finding."
}
else {
    $bgPrincipalIds = @($bgGroup['id'])
    $uri = "$graph/v1.0/groups/$($bgGroup['id'])/members?`$select=id,displayName,userPrincipalName"
    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($m in @($page['value'])) {
            if ("$($m['userPrincipalName'])" -like 'bg-admin-*') { $bgUserIds += $m['id'] }
            else { $bgOtherMembers += "$($m['displayName']) ($($m['id']))" }
        }
        $uri = $page['@odata.nextLink']
    } while ($uri)
    # Members count as expected too, in case Graph lists per-member instances
    # (memberType 'Group'). Non-bg-admin members are a finding (report 3).
    $bgPrincipalIds += $bgUserIds
}

# PIM contract (lab/terraform/modules/pim): Privileged-IAM-Admins holds User
# Administrator ACTIVELY by design; the just-in-time control is its eligible-
# only membership (01-Verify-Baseline [6/7]). So that one binding, the group
# itself on that one role, is expected in report 3. Any other role on the
# group, or a member listed per-member, is still a finding.
$UserAdminRoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'   # modules/pim role_template_id default
$pimGroupId = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/v1.0/groups?`$filter=mailNickname eq 'privileged-iam-admins'&`$select=id")['value']) |
    Select-Object -First 1 | ForEach-Object { $_['id'] }
if (-not $pimGroupId) {
    Write-Warning "Privileged-IAM-Admins (mailNickname 'privileged-iam-admins') not found: its User Administrator binding, if any, is reported as a finding."
}

# ===========================================================================
# 1. STALE ACCOUNTS
# ===========================================================================
# signInActivity requires AuditLog.Read.All and is a beta-origin property now in
# v1.0; request it explicitly via -Property.
$allUsers = Get-MgUser -All -Property 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity'
$bgSkipped = 0
$stale = foreach ($u in $allUsers) {
    if (-not $u.AccountEnabled) { continue }                 # disabled already handled by leaver
    if ($u.Id -in $bgUserIds) { $bgSkipped++; continue }     # break-glass: never signing in is the goal
    $last = $null
    if ($u.SignInActivity) { $last = $u.SignInActivity.LastSignInDateTime }
    $isStale = (-not $last) -or ($last -lt $cutoff)
    if ($isStale) {
        [pscustomobject]@{
            DisplayName       = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            UserType          = $u.UserType
            CreatedDateTime   = $u.CreatedDateTime
            LastSignInUtc     = if ($last) { $last } else { 'never' }
            StaleThresholdDays = $StaleDays
        }
    }
}
Save-Report 'stale accounts' @($stale)
if ($bgSkipped) {
    Write-Console "  Excluded $bgSkipped break-glass account(s) (Break-Glass-Admins members): expected to never sign in; every sign-in alerts via lab/kql/break-glass-signin.kql." -ForegroundColor DarkGray
}

# ===========================================================================
# 2. USERS WITHOUT MFA
# ===========================================================================
# Authentication-methods registration report (reports/authenticationMethods/
# userRegistrationDetails). isMfaRegistered=false => no strong auth method.
$mfaGap = @(); $mfaFailed = $null
try {
    $reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
    $mfaGap = foreach ($r in $reg) {
        if (-not $r.IsMfaRegistered) {
            [pscustomobject]@{
                UserPrincipalName   = $r.UserPrincipalName
                DisplayName         = $r.UserDisplayName
                IsMfaRegistered     = $r.IsMfaRegistered
                IsMfaCapable        = $r.IsMfaCapable
                # v1.0 name; the old beta defaultMfaMethod is not on the v1.0 model.
                PreferredSecondaryMethod = $r.UserPreferredMethodForSecondaryAuthentication
                MethodsRegistered   = ($r.MethodsRegistered -join ';')
            }
        }
    }
}
catch {
    # Non-silent: the report is marked FAILED below, never saved as "0 gaps".
    $mfaFailed = $_.Exception.Message
    Write-Warning "Registration report query FAILED ($mfaFailed). Raw REST equivalent:"
    Write-Warning "  Invoke-MgGraphRequest GET /v1.0/reports/authenticationMethods/userRegistrationDetails?`$filter=isMfaRegistered eq false"
}
Save-Report 'users without mfa' @($mfaGap) -FailedReason $mfaFailed

# ===========================================================================
# 3. STANDING PRIVILEGED ROLE HOLDERS
# ===========================================================================
# assignmentType 'Assigned' = permanent/standing; 'Activated' = a live PIM
# activation. We want standing holders of PRIVILEGED roles.
# "Privileged" = Entra's own isPrivileged flag. It exists only on the BETA
# roleDefinition (the v1.0 SDK model has no IsPrivileged property), so the
# privileged role ids are read once from beta. verify: beta still supports
# $filter=isPrivileged eq true (learn.microsoft.com/graph/api/resources/
# unifiedroledefinition?view=graph-rest-beta).
$standing = @(); $standingFailed = $null
try {
    $privRoleIds = @()
    $uri = "$graph/beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,templateId"
    do {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($d in @($page['value'])) { $privRoleIds += @($d['id'], $d['templateId']) }
        $uri = $page['@odata.nextLink']
    } while ($uri)
    # Global Administrator is privileged in every tenant: if it is missing, the
    # filter was not honored and a partial set would be a false pass.
    if ($GlobalAdminRoleTemplateId -notin $privRoleIds) {
        throw 'isPrivileged filter did not return Global Administrator; privileged-role set is not trustworthy.'
    }
    $instances = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All `
        -ExpandProperty 'principal,roleDefinition' -Filter "assignmentType eq 'Assigned'" -ErrorAction Stop
    $standing = foreach ($i in $instances) {
        if ($i.RoleDefinitionId -in $privRoleIds) {
            $rd = $i.RoleDefinition
            $p = $i.Principal
            $pName = if ($p) { $p.AdditionalProperties['displayName'] } else { $i.PrincipalId }
            $pUpn  = if ($p) { $p.AdditionalProperties['userPrincipalName'] } else { '' }
            [pscustomobject]@{
                Role             = if ($rd) { $rd.DisplayName } else { $i.RoleDefinitionId }
                PrincipalName    = $pName
                UserPrincipalName = $pUpn
                PrincipalType    = if ($p) { "$($p.AdditionalProperties['@odata.type'])" -replace '^#microsoft\.graph\.' } else { '' }
                PrincipalId      = $i.PrincipalId
                AssignmentType   = $i.AssignmentType
                MemberType       = $i.MemberType
                ExpectedBreakGlass = ($i.PrincipalId -in $bgPrincipalIds)
                ExpectedPimGroup   = [bool]($pimGroupId -and $i.PrincipalId -eq $pimGroupId -and
                                            ($i.RoleDefinitionId -eq $UserAdminRoleTemplateId -or
                                             ($rd -and $rd.TemplateId -eq $UserAdminRoleTemplateId)))
            }
        }
    }
}
catch {
    # Non-silent: the report is marked FAILED below and the green OK is skipped.
    $standingFailed = $_.Exception.Message
    Write-Warning "Standing-privileged query FAILED ($standingFailed). Raw REST equivalents:"
    Write-Warning "  Invoke-MgGraphRequest GET /beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,templateId"
    Write-Warning "  Invoke-MgGraphRequest GET /v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=assignmentType eq 'Assigned'&`$expand=principal,roleDefinition"
}
Save-Report 'standing privileged' @($standing) -FailedReason $standingFailed
if (-not $standingFailed) {
    $unexpected = @($standing | Where-Object { -not $_.ExpectedBreakGlass -and -not $_.ExpectedPimGroup })
    if ($bgOtherMembers.Count) {
        Write-Warning "FINDING: Break-Glass-Admins has $($bgOtherMembers.Count) member(s) that are not bg-admin-* accounts ($($bgOtherMembers -join '; ')) -- each holds standing Global Admin through the group."
    }
    if ($unexpected.Count) {
        Write-Warning "FINDING: $($unexpected.Count) standing privileged assignment(s) beyond break-glass and the PIM group's User Administrator binding -- zero-standing-admin violated."
    }
    if (-not $unexpected.Count -and -not $bgOtherMembers.Count) {
        Write-Console "  OK: standing privileged access limited to break-glass (+ the PIM group's role binding; its membership is just-in-time)." -ForegroundColor Green
    }
}

# ===========================================================================
# 4. GUEST SPRAWL
# ===========================================================================
$guests = foreach ($u in ($allUsers | Where-Object UserType -eq 'Guest')) {
    $last = if ($u.SignInActivity) { $u.SignInActivity.LastSignInDateTime } else { $null }
    [pscustomobject]@{
        DisplayName       = $u.DisplayName
        UserPrincipalName = $u.UserPrincipalName
        CreatedDateTime   = $u.CreatedDateTime
        LastSignInUtc     = if ($last) { $last } else { 'never' }
        StaleGuest        = (-not $last) -or ($last -lt $cutoff)
    }
}
Save-Report 'guest sprawl' @($guests)

# Return structured results for downstream use (e.g. the evidence pack).
$reportResults = @{
    StaleAccounts      = @($stale)
    UsersWithoutMfa    = @($mfaGap)
    StandingPrivileged = @($standing)
    GuestSprawl        = @($guests)
    FailedReports      = @($failedReports)   # listed sets are UNKNOWN, not clean
}
if ($failedReports.Count) {
    Write-Console "`n$($failedReports.Count) report(s) FAILED: $($failedReports -join ', ') -- results unknown, not clean." -ForegroundColor Red
    $reportResults   # still hand back what did complete
    exit 1
}
return $reportResults
