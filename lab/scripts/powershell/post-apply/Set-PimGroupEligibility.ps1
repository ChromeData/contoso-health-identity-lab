<#
.SYNOPSIS
    Makes named admin accounts ELIGIBLE (not active) members of a PIM-governed
    group - Privileged-IAM-Admins or a PIM tier group - for a LIMITED time
    (180 days Tier 0, 365 days Tier 1). Idempotent.

.DESCRIPTION
    Terraform (modules/pim) binds each group actively to its directory role(s)
    and sets the PIM-for-Groups policy: activation rules, approval by the
    tier's approver GROUP, and - since the policy now REQUIRES eligible
    assignments to expire - a maximum eligibility of P180D (Tier 0) or P365D
    (Tier 1 and Privileged-IAM-Admins). WHO is eligible is operational data,
    so it is set here, after the people exist, instead of in Terraform.

    Graph: POST /identityGovernance/privilegedAccess/group/eligibilityScheduleRequests
           action = adminAssign, accessId = member,
           scheduleInfo.expiration = { type = afterDuration, duration = P180D | P365D }
    A noExpiration request is no longer possible: the policy refuses it.

    Tier is read from the group's mailNickname (pim-tier0-* = Tier 0;
    everything else, including privileged-iam-admins, = Tier 1). A longer
    duration than the tier allows is refused here, before Graph refuses it.

    Guards (privileged-access standard section 1, help-desk runbook):
      * break-glass (bg-admin-NN) is never made eligible - it holds standing
        Global Administrator and is outside PIM by design (ADR 0003);
      * an account without the adm- prefix gets a warning: eligibility
        belongs on a separate cloud-only admin account, never the synced
        workforce account (iam-standard gap G1 until adm- accounts exist);
      * a person who is also a member of the same tier's approver group
        (pim-approvers-tier0 / -tier1) gets a warning: approvers and eligible
        people should be disjoint;
      * an existing PERMANENT eligibility (created before expiry was
        required) is reported, not silently kept. verify: whether enabling
        expiration_required trims such eligibilities on its own.
      * a failed READ is a failure, never "not eligible yet".

    No default person. The lab's HR feed holds clinical and business staff
    only; a clinical manager eligible for User Administrator is exactly the
    SOD-08 conflict. Name the IT/IAM engineer's admin account explicitly.

.NOTES
    PREREQUISITES
    * Terraform envs/dev applied with enable_premium = true (and
      enable_pim_tiers for the tier groups).
    * The admin accounts exist and hold an Entra ID P2 (or E5) licence.


    GRAPH SCOPES (delegated; admin-consent)
    PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup   create / read eligibility
    Group.Read.All, User.Read.All                          resolve ids, approver group members

.PARAMETER UserPrincipalNames
    Admin accounts to make eligible (required), e.g.
    adm-first.last@<tenant>.onmicrosoft.com.

.PARAMETER GroupMailNickname
    The PIM-governed group. Default privileged-iam-admins (Terraform contract);
    tier groups: terraform output tier_group_mail_nicknames.

.PARAMETER EligibilityDuration
    P15D | P30D | P90D | P180D | P365D. Default: the tier's maximum (Tier 0
    P180D, Tier 1 P365D). Never longer than the tier allows.

.EXAMPLE
    Connect-MgGraph -Scopes 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup','Group.Read.All','User.Read.All'
    ./Set-PimGroupEligibility.ps1 -UserPrincipalNames 'adm-first.last@<tenant>.onmicrosoft.com' -WhatIf
    ./Set-PimGroupEligibility.ps1 -GroupMailNickname pim-tier0-ca-admins -UserPrincipalNames 'adm-first.last@<tenant>.onmicrosoft.com'
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$UserPrincipalNames,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupMailNickname = 'privileged-iam-admins',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Justification = 'Lab: eligible admin - expires; activation requires MFA (or the Tier-0 auth context), justification and, where the tier says so, approval.',

    [Parameter()]
    [ValidatePattern('^P(15|30|90|180|365)D$')]
    [string]$EligibilityDuration
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
function Get-PimGroupTier {
    # modules/pim naming contract: pim-tier0-* is Tier 0; everything else
    # (privileged-iam-admins, pim-tier1-*) is Tier 1.
    param([Parameter(Mandatory)][string]$MailNickname)
    if ($MailNickname -match '^pim-tier0-') { return 0 }
    return 1
}

function ConvertTo-DurationDay {
    param([Parameter(Mandatory)][string]$Duration)
    if ($Duration -notmatch '^P(\d+)D$') { throw "Not a whole-day ISO-8601 duration: '$Duration'." }
    return [int]$Matches[1]
}

function Get-EligibilityDuration {
    # The tier's maximum unless a shorter one is requested; longer = refused.
    param([Parameter(Mandatory)][int]$Tier, [string]$Requested)
    $max = if ($Tier -eq 0) { 'P180D' } else { 'P365D' }
    if ([string]::IsNullOrWhiteSpace($Requested)) { return $max }
    if ((ConvertTo-DurationDay $Requested) -gt (ConvertTo-DurationDay $max)) {
        throw "EligibilityDuration $Requested exceeds the Tier-$Tier maximum ($max): modules/pim refuses it (eligible_assignment_rules)."
    }
    return $Requested
}

function Test-BreakGlassUpn {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    return [bool]($UserPrincipalName -match '^bg-admin-\d+@')
}

function Test-AdminAccountUpn {
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    return [bool]($UserPrincipalName -match '^adm-')
}

function Get-EligibilityRequestBody {
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$Justification,
        [Parameter(Mandatory)][string]$Duration,
        [Parameter(Mandatory)][datetime]$Start
    )
    return [ordered]@{
        accessId      = 'member'
        principalId   = $PrincipalId
        groupId       = $GroupId
        action        = 'adminAssign'
        justification = $Justification
        scheduleInfo  = [ordered]@{
            startDateTime = $Start.ToUniversalTime().ToString('o')
            expiration    = [ordered]@{ type = 'afterDuration'; duration = $Duration }
        }
    }
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
$tier = Get-PimGroupTier -MailNickname $GroupMailNickname
$duration = Get-EligibilityDuration -Tier $tier -Requested $EligibilityDuration

$requiredScopes = @('PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup', 'Group.Read.All', 'User.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403 and lookups may report 'not found' (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

# Select-Object -First 1, not @(...)[0]: under StrictMode an empty result
# throws IndexOutOfRange instead of reaching the 'not found' message below.
$group = @(Get-GraphCollection -Uri "$graph/groups?`$filter=mailNickname eq '$GroupMailNickname'&`$select=id,displayName") | Select-Object -First 1
if (-not $group) { throw "Group '$GroupMailNickname' not found. Apply Terraform envs/dev with enable_premium = true (and enable_pim_tiers for tier groups) first." }
Write-Console "PIM for Groups: $($group['displayName']) ($($group['id'])) - Tier $tier, eligibility $duration" -ForegroundColor Cyan

# Approvers of this tier (approvers.tf). Missing group = nothing routes
# approvals to it; an unreadable one is reported, the run goes on.
$approverIds = @()
$approverNick = if ($tier -eq 0) { 'pim-approvers-tier0' } else { 'pim-approvers-tier1' }
try {
    $approverGroup = @(Get-GraphCollection -Uri "$graph/groups?`$filter=mailNickname eq '$approverNick'&`$select=id,displayName") | Select-Object -First 1
    if ($approverGroup) { $approverIds = @(Get-GraphCollection -Uri "$graph/groups/$($approverGroup['id'])/transitiveMembers?`$select=id" | ForEach-Object { $_['id'] }) }
}
catch { Write-Warning "  [!] Could not read $approverNick ($($_.Exception.Message)); check by hand that no approver is made eligible." }

$failures = 0
foreach ($upn in $UserPrincipalNames) {
    if (Test-BreakGlassUpn -UserPrincipalName $upn) {
        Write-Warning "  [x] $upn is a break-glass account: never PIM-eligible (standing Global Administrator, ADR 0003). Skipped."
        $failures++
        continue
    }
    if (-not (Test-AdminAccountUpn -UserPrincipalName $upn)) {
        Write-Warning "  [!] $upn is not an adm- account. Eligibility belongs on a separate cloud-only admin account, never the workforce account (privileged-access standard section 1)."
    }

    try {
        $user = @(Get-GraphCollection -Uri "$graph/users?`$filter=userPrincipalName eq '$upn'&`$select=id,displayName") | Select-Object -First 1
    }
    catch {
        Write-Warning "  [!] Could not look up ${upn}: $($_.Exception.Message)"
        $failures++
        continue
    }
    if (-not $user) {
        Write-Warning "  '$upn' not found - create the admin account first."
        $failures++
        continue
    }
    if ($user['id'] -in $approverIds) {
        Write-Warning "  [!] $upn is also a member of $approverNick. Approvers cannot approve their own request, but keep approvers and eligible people disjoint (no mutual approval)."
    }

    # A failed read is a failure, never "not eligible yet".
    try {
        $existing = @(Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($group['id'])' and principalId eq '$($user['id'])'" |
            Where-Object { $_['accessId'] -eq 'member' })
    }
    catch {
        Write-Warning "  [!] Could not read existing eligibility for ${upn}: $($_.Exception.Message)"
        $failures++
        continue
    }
    if ($existing) {
        $permanent = @($existing | Where-Object { $_.Contains('scheduleInfo') -and $_['scheduleInfo'] -and $_['scheduleInfo']['expiration'] -and $_['scheduleInfo']['expiration']['type'] -eq 'noExpiration' })
        if ($permanent) {
            Write-Warning "  [~] $upn holds a PERMANENT eligibility created before expiry was required. Remove it (adminRemove) and re-run, or renew it in the portal, so it expires after $duration."
        }
        else { Write-Console "  [=] $upn is already an eligible member." -ForegroundColor DarkGray }
        continue
    }

    if ($PSCmdlet.ShouldProcess($upn, "make eligible member of $($group['displayName']) for $duration")) {
        $body = Get-EligibilityRequestBody -GroupId $group['id'] -PrincipalId $user['id'] -Justification $Justification -Duration $duration -Start (Get-Date) | ConvertTo-Json -Depth 5
        try {
            $req = Invoke-MgGraphRequest -Method POST -Uri "$graph/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" -Body $body -ContentType 'application/json' -OutputType HashTable
            Write-Console "  [+] $upn eligible for $duration (request $($req['id']), status $($req['status']))." -ForegroundColor Green
        }
        catch {
            Write-Warning "  Failed for ${upn}: $($_.Exception.Message)"
            $failures++
        }
    }
}

if ($failures) { Write-Warning "$failures user(s) not made eligible."; exit 1 }
Write-Console "`nDone. Verify: Entra -> PIM -> Groups -> $($group['displayName']) -> Assignments -> Eligible (End time = start + $duration)." -ForegroundColor Cyan
