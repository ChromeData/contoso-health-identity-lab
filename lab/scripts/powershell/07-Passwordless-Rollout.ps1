<#
.SYNOPSIS
    Passwordless rollout helper, pilot -> broad: registration status per group,
    Temporary Access Pass (TAP) onboarding for named users, and a go/no-go
    readiness report for enforcing CA008 (phishing-resistant authentication
    strength for all users). Read-only unless -IssueTapFor is given.

.DESCRIPTION
    The rollout is a sequence, not a switch:

      1. Set-AuthenticationMethodsPolicy.ps1 enables passkey profiles, TAP and
         the registration campaign (admins first, then -IncludeStaffRollout).
      2. THIS SCRIPT, -Stage Pilot: who in the pilot group(s) already has a
         phishing-resistant method, who has only phishable MFA, who has phone
         methods only, who has nothing. Hand a TAP to the people who need help
         registering (-IssueTapFor).
      3. Same script, -Stage Broad: the same numbers for every enabled member.
      4. The CA008 section says whether enforcing CA008 today would block
         anyone: in-scope users without a method the policy's authentication
         strength accepts, plus users the report-only policy already would
         have failed in the sign-in log. Graduate CA008 (one policy per PR,
         lab/docs/runbooks/graduate-a-ca-policy.md) only on READY.

    TAP REUSE: new hires get their TAP from the joiner Lifecycle Workflow
    (post-apply/New-LifecycleWorkflows.ps1, task "Generate TAP and send email",
    480 min, one-time). That task only works for a user with NO methods and no
    sign-ins yet, so it cannot onboard the existing workforce. -IssueTapFor
    covers them with the same defaults (-TapLifetimeMinutes 480,
    -TapIsUsableOnce $true), checked against the TAP policy before the call.
    The pass is a credential: it is returned as a SecureString and printed only
    with -RevealTap. Deliver it out of band (in person, or to the manager).

    CLASSIFICATION (registration report methodsRegistered; verify: method names)
      phishing-resistant, device-bound  passKeyDeviceBound*, fido2SecurityKey,
                                        windowsHelloForBusiness, macOsSecureEnclaveKey
      phishing-resistant, synced        passKeySynced (unattested: counted as
                                        phishing-resistant, reported separately)
      phishable MFA only                Authenticator push/phone sign-in, OTP, phone, email
      phone only                        mobilePhone / alternateMobilePhone / officePhone
                                        (the population SMS/voice retirement strands)
      none                              no MFA method
    The registration report refreshes periodically (lastUpdatedDateTime), so a
    key registered minutes ago may not show yet.

.PREREQUISITES
    * Set-AuthenticationMethodsPolicy.ps1 -Apply has run (TAP + passkeys on).
    * CA008 deployed in report-only for the readiness section
      (Terraform enable_phishing_resistant_all_users).
    * Roles: Reports Reader (or Security Reader) for the reports; Authentication
      Administrator to issue a TAP to a non-admin (Privileged Authentication
      Administrator for admins - this script refuses break-glass outright).
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated)
    User.Read.All                       users, membership
    GroupMember.Read.All                pilot group members
    AuditLog.Read.All                   registration report + sign-in logs
    Policy.Read.All                     CA008, its authentication strength, TAP policy
    UserAuthenticationMethod.ReadWrite.All   only with -IssueTapFor
    GroupMember.ReadWrite.All           only with -PromoteReadyToPilot

.PARAMETER Stage
    Pilot (default): members of -PilotGroupMailNicknames. Broad: every enabled
    member user.

.PARAMETER PilotGroupMailNicknames
    Pilot groups. Default all-nurses (the lab's joiner department).

.PARAMETER IssueTapFor
    UPNs to issue a one-time TAP to. Nothing is issued without this.

.PARAMETER TapLifetimeMinutes
    TAP lifetime. Default 480, same as the joiner workflow.

.PARAMETER TapIsUsableOnce
    One-time TAP. Default $true, same as the joiner workflow.

.PARAMETER RevealTap
    Print each issued TAP to the console. Without it the pass is only in the
    returned objects as a SecureString.

.PARAMETER Force
    Issue a TAP even to a user who already has a phishing-resistant method.

.PARAMETER PolicyNamePrefix
    CA display-name prefix (Terraform policy_name_prefix). Default CA, so the
    policy found is "CA008 - ...".

.PARAMETER SignInLookbackDays
    Days of sign-in log to scan for CA008 report-only failures. Default 7.

.PARAMETER MaxSignInPages
    Upper bound on sign-in pages read (tenant safety). Default 20; the summary
    says when the scan was capped.

.PARAMETER OutputDirectory
    Per-user CSV + summary JSON. Default lab/evidence/out/passwordless
    (gitignored: it holds names).

.PARAMETER FailIfNotReady
    Exit 1 when CA008 is NOT READY (use as a pipeline gate).

.PARAMETER Ca008PilotGroupMailNickname
    The CA008 enforcement pilot group (modules/conditional-access creates
    CA008-Pilot-PhishingResistant). Default ca008-pilot-phishingresistant.

.PARAMETER PromoteReadyToPilot
    Add every user in this run's population who already holds a method the
    CA008 strength accepts to the pilot group (GroupMember.ReadWrite.All).
    Honours -WhatIf. Default off: the report lists them either way.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All','GroupMember.Read.All','AuditLog.Read.All','Policy.Read.All'
    ./07-Passwordless-Rollout.ps1 -Stage Pilot

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All','GroupMember.Read.All','AuditLog.Read.All','Policy.Read.All','UserAuthenticationMethod.ReadWrite.All'
    ./07-Passwordless-Rollout.ps1 -IssueTapFor 'marcus.bello@<domain>' -WhatIf
    $r = ./07-Passwordless-Rollout.ps1 -IssueTapFor 'marcus.bello@<domain>'
    $r.TapsIssued[0].TemporaryAccessPass | ConvertFrom-SecureString -AsPlainText   # hand over out of band

.EXAMPLE
    ./07-Passwordless-Rollout.ps1 -Stage Broad -FailIfNotReady

.OUTPUTS
    [pscustomobject] Stage, GroupSummary, Ca008, TapsIssued, PerUserCsv.

.NOTES
    TENANT-TIME: nothing here has run against Entra yet.
    verify: methodsRegistered value names (passKeyDeviceBound,
      passKeyDeviceBoundAuthenticator, passKeyDeviceBoundWindowsHello,
      passKeySynced, windowsHelloForBusiness, macOsSecureEnclaveKey) against a
      live report.
    verify: a synced passkey satisfies the "fido2" combination of an
      authentication strength (Microsoft Learn: synced passkeys are FIDO2
      credentials without attestation).
    verify: appliedConditionalAccessPolicies[].result reports
      reportOnlyFailure / reportOnlyInterrupted for a report-only policy.
    Guests: passkey registration for B2B and internal guests is planned for the
    end of 2026 (Microsoft Learn SMS/voice FAQ), so guests in CA008 scope are
    counted separately and flagged, not silently dropped.

.WHAT IT DEMONSTRATES
    Running a phishing-resistant rollout on measured readiness: per-group
    status, a credential-safe TAP bootstrap that reuses the joiner design,
    and an enforcement gate driven by report-only evidence.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateSet('Pilot', 'Broad')]
    [string]$Stage = 'Pilot',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$PilotGroupMailNicknames = @('all-nurses'),

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'Must be a valid UPN.')]
    [string[]]$IssueTapFor = @(),

    [Parameter()]
    [ValidateRange(10, 43200)]
    [int]$TapLifetimeMinutes = 480,

    [Parameter()]
    [bool]$TapIsUsableOnce = $true,

    [Parameter()]
    [switch]$RevealTap,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyNamePrefix = 'CA',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$SignInLookbackDays = 7,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$MaxSignInPages = 20,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'passwordless'),

    [Parameter()]
    [switch]$FailIfNotReady,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Ca008PilotGroupMailNickname = 'ca008-pilot-phishingresistant',

    [Parameter()]
    [switch]$PromoteReadyToPilot
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
# Pure helpers (no Graph calls) - unit-tested in tests/07-Passwordless-Rollout.Tests.ps1
# =============================================================================
function Get-AuthMethodClass {
    # One user's registered methods -> rollout class. The method lists are
    # duplicated in 08-Measure-KPIs.ps1 on purpose (each script stays
    # standalone); a Pester test asserts the two classify identically.
    param([AllowNull()][AllowEmptyCollection()][string[]]$MethodsRegistered)
    $deviceBound = @('passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello',
        'fido2SecurityKey', 'windowsHelloForBusiness', 'macOsSecureEnclaveKey')
    $synced = @('passKeySynced')
    $phone = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
    $phishable = @('microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless', 'softwareOneTimePasscode',
        'hardwareOneTimePasscode', 'email') + $phone
    $m = @($MethodsRegistered | Where-Object { $_ })
    $hasDb = @($m | Where-Object { $_ -in $deviceBound }).Count -gt 0
    $hasSy = @($m | Where-Object { $_ -in $synced }).Count -gt 0
    $mfa = @($m | Where-Object { $_ -in $phishable })
    $class = if ($hasDb) { 'PhishingResistantDeviceBound' }
    elseif ($hasSy) { 'PhishingResistantSyncedOnly' }
    elseif ($mfa.Count -gt 0 -and @($mfa | Where-Object { $_ -notin $phone }).Count -eq 0) { 'PhoneOnly' }
    elseif ($mfa.Count -gt 0) { 'PhishableMfaOnly' }
    else { 'None' }
    return [pscustomobject]@{
        Class              = $class
        PhishingResistant  = ($hasDb -or $hasSy)
        DeviceBound        = $hasDb
        Methods            = ($m -join ';')
    }
}

function Test-StrengthSatisfied {
    # Can a user with these registered methods satisfy an authentication
    # strength with these allowedCombinations? (verify: mapping)
    param([AllowNull()][AllowEmptyCollection()][string[]]$MethodsRegistered, [string[]]$AllowedCombinations)
    $map = @{
        'passKeyDeviceBound'              = 'fido2'
        'passKeyDeviceBoundAuthenticator' = 'fido2'
        'passKeyDeviceBoundWindowsHello'  = 'fido2'
        'passKeySynced'                   = 'fido2'
        'fido2SecurityKey'                = 'fido2'
        'windowsHelloForBusiness'         = 'windowsHelloForBusiness'
        'macOsSecureEnclaveKey'           = 'windowsHelloForBusiness'
    }
    $combos = @($AllowedCombinations | ForEach-Object { ([string]$_).ToLowerInvariant() })
    foreach ($m in @($MethodsRegistered | Where-Object { $_ })) {
        if ($map.ContainsKey($m) -and $combos -contains $map[$m].ToLowerInvariant()) { return $true }
    }
    return $false
}

function Get-Ca008Readiness {
    # Go/no-go from three inputs: in-scope users, their registration rows
    # (by user id), and the user ids report-only CA008 already failed.
    param(
        [object[]]$InScopeUsers,                     # objects with Id, UserPrincipalName, UserType
        [hashtable]$RegistrationById,                 # id -> methodsRegistered string[]
        [string[]]$AllowedCombinations,
        [AllowEmptyCollection()][string[]]$ReportOnlyFailureUserIds = @()
    )
    $lacking = [System.Collections.Generic.List[object]]::new()
    $guests = 0
    foreach ($u in @($InScopeUsers)) {
        $methods = if ($RegistrationById.ContainsKey($u.Id)) { @($RegistrationById[$u.Id]) } else { @() }
        if (-not (Test-StrengthSatisfied -MethodsRegistered $methods -AllowedCombinations $AllowedCombinations)) {
            $lacking.Add($u)
            if ($u.UserType -eq 'Guest') { $guests++ }
        }
    }
    $lackingIds = @($lacking | ForEach-Object { $_.Id })   # scriptblock: ForEach-Object <member> echoes under -WhatIf
    # A user who failed in report-only but has since registered is no longer a blocker.
    $stillFailing = @($ReportOnlyFailureUserIds | Where-Object { $_ -in $lackingIds } | Sort-Object -Unique)
    $n = @($InScopeUsers).Count
    $reasons = @()
    if ($lacking.Count) { $reasons += "$($lacking.Count) in-scope user(s) have no method the authentication strength accepts$(if ($guests) { " ($guests guest(s): passkeys for guests are not available yet)" })" }
    if ($stillFailing.Count) { $reasons += "$($stillFailing.Count) of them already failed CA008 in report-only" }
    return [pscustomobject]@{
        Verdict           = $(if ($n -gt 0 -and $lacking.Count -eq 0) { 'READY' } else { 'NOT READY' })
        InScope           = $n
        Satisfying        = $n - $lacking.Count
        PctSatisfying     = $(if ($n) { [math]::Round(100.0 * ($n - $lacking.Count) / $n, 1) } else { $null })
        Lacking           = $lacking.ToArray()
        GuestsLacking     = $guests
        ReportOnlyBlocked = $stillFailing.Count
        Reasons           = $(if ($n -eq 0) { @('no users in scope - check the policy targets') } else { $reasons })
    }
}

# =============================================================================
# Graph helpers
# =============================================================================
function Invoke-Graph {
    param([Parameter(Mandatory)][ValidateSet('GET', 'POST')][string]$Method, [Parameter(Mandatory)][string]$Uri, [object]$Body)
    $p = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($PSBoundParameters.ContainsKey('Body')) { $p.Body = ($Body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
    return Invoke-MgGraphRequest @p
}
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxPages = 0)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $pages = 0; $capped = $false
    while ($next) {
        if ($MaxPages -gt 0 -and $pages -ge $MaxPages) { $capped = $true; break }
        $page = Invoke-Graph -Method GET -Uri $next
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = $page['@odata.nextLink']; $pages++
    }
    if ($capped) { $script:SignInScanCapped = $true }
    return $items.ToArray()
}
function Get-GroupByNickname {
    param([string]$MailNickname)
    $f = [uri]::EscapeDataString("mailNickname eq '$($MailNickname.Replace("'", "''"))'")
    return @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id,displayName") | Select-Object -First 1
}
function Get-GroupUserMember {
    param([string]$GroupId)
    return @(Get-GraphCollection -Uri "$graph/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,accountEnabled,userType")
}

# =============================================================================
# CONNECT
# =============================================================================
$requiredScopes = @('User.Read.All', 'GroupMember.Read.All', 'AuditLog.Read.All', 'Policy.Read.All')
if ($IssueTapFor) { $requiredScopes += 'UserAuthenticationMethod.ReadWrite.All' }
if ($PromoteReadyToPilot) { $requiredScopes += 'GroupMember.ReadWrite.All' }
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }
$script:SignInScanCapped = $false

# Break-glass members are never part of a rollout population and never get a TAP.
$bg = Get-GroupByNickname $BreakGlassGroupMailNickname
$bgIds = @(if ($bg) { Get-GroupUserMember ([string]$bg['id']) | ForEach-Object { [string]$_['id'] } })
if (-not $bg) { Write-Warning "Break-glass group '$BreakGlassGroupMailNickname' not found; nothing is excluded as break-glass." }

# =============================================================================
# 1. POPULATION + REGISTRATION STATUS PER GROUP
# =============================================================================
Write-Console "`n[1/3] Registration status ($Stage)" -ForegroundColor Cyan
$populations = [ordered]@{}   # label -> user rows
if ($Stage -eq 'Pilot') {
    foreach ($nick in $PilotGroupMailNicknames) {
        $g = Get-GroupByNickname $nick
        if (-not $g) { Write-Warning "  Pilot group '$nick' not found - skipped."; continue }
        $populations[[string]$g['displayName']] = @(Get-GroupUserMember ([string]$g['id']))
    }
}
else {
    $populations['All enabled members'] = @(Get-GraphCollection -Uri "$graph/users?`$select=id,userPrincipalName,accountEnabled,userType" |
        Where-Object { [string]$_['userType'] -eq 'Member' })
}

$regRows = @(Get-GraphCollection -Uri "$graph/reports/authenticationMethods/userRegistrationDetails")
$regById = @{}
foreach ($r in $regRows) { $regById[[string]$r['id']] = @(@($r['methodsRegistered']) | Where-Object { $_ }) }

$perUser = [System.Collections.Generic.List[object]]::new()
$groupSummary = foreach ($label in $populations.Keys) {
    $users = @($populations[$label] | Where-Object { $_['accountEnabled'] -ne $false -and [string]$_['id'] -notin $bgIds })
    $classes = foreach ($u in $users) {
        $c = Get-AuthMethodClass -MethodsRegistered $(if ($regById.ContainsKey([string]$u['id'])) { $regById[[string]$u['id']] } else { @() })
        $perUser.Add([pscustomobject]@{ Population = $label; UserPrincipalName = [string]$u['userPrincipalName']; UserType = [string]$u['userType']; Class = $c.Class; Methods = $c.Methods })
        $c
    }
    $classes = @($classes)
    $n = $users.Count
    [pscustomobject]@{
        Population             = $label
        Users                  = $n
        PhishingResistant      = @($classes | Where-Object PhishingResistant).Count
        DeviceBound            = @($classes | Where-Object DeviceBound).Count
        SyncedOnly             = @($classes | Where-Object Class -eq 'PhishingResistantSyncedOnly').Count
        PhishableMfaOnly       = @($classes | Where-Object Class -eq 'PhishableMfaOnly').Count
        PhoneOnly              = @($classes | Where-Object Class -eq 'PhoneOnly').Count
        NoMfa                  = @($classes | Where-Object Class -eq 'None').Count
        PctPhishingResistant   = $(if ($n) { [math]::Round(100.0 * @($classes | Where-Object PhishingResistant).Count / $n, 1) } else { $null })
    }
}
$groupSummary = @($groupSummary)
$groupSummary | Format-Table -AutoSize | Out-Host
$needHelp = @($perUser | Where-Object { $_.Class -in 'None', 'PhoneOnly', 'PhishableMfaOnly' } | Select-Object -ExpandProperty UserPrincipalName -Unique)
if ($needHelp.Count) { Write-Console "  $($needHelp.Count) user(s) without a phishing-resistant method - candidates for -IssueTapFor (see the per-user CSV)." -ForegroundColor Yellow }

# =============================================================================
# 2. TAP ONBOARDING (only with -IssueTapFor)
# =============================================================================
Write-Console "`n[2/3] Temporary Access Pass onboarding" -ForegroundColor Cyan
$taps = [System.Collections.Generic.List[object]]::new()
function Add-Tap { param([string]$Upn, [string]$Status, [securestring]$Pass = $null, [string]$Detail = '')
    $taps.Add([pscustomobject]@{ UserPrincipalName = $Upn; Status = $Status; LifetimeMinutes = $TapLifetimeMinutes; IsUsableOnce = $TapIsUsableOnce; TemporaryAccessPass = $Pass; Detail = $Detail })
}
if (-not $IssueTapFor) { Write-Console '  [skip] No -IssueTapFor; nothing issued.' -ForegroundColor DarkGray }
else {
    $tapPolicy = Invoke-Graph -Method GET -Uri "$graph/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass"
    $policyProblems = @()
    if ([string]$tapPolicy['state'] -ne 'enabled') { $policyProblems += 'TAP method is disabled (run Set-AuthenticationMethodsPolicy.ps1 -Apply)' }
    if ($TapLifetimeMinutes -lt [int]$tapPolicy['minimumLifetimeInMinutes'] -or $TapLifetimeMinutes -gt [int]$tapPolicy['maximumLifetimeInMinutes']) {
        $policyProblems += "lifetime $TapLifetimeMinutes min is outside the policy's $($tapPolicy['minimumLifetimeInMinutes'])-$($tapPolicy['maximumLifetimeInMinutes'])"
    }
    if ([bool]$tapPolicy['isUsableOnce'] -and -not $TapIsUsableOnce) { $policyProblems += 'policy allows one-time passes only; pass -TapIsUsableOnce $true' }
    $tapInclude = @(@($tapPolicy['includeTargets']) | Where-Object { $_ } | ForEach-Object { [string]$_['id'] })
    $tapExclude = @(@($tapPolicy['excludeTargets']) | Where-Object { $_ } | ForEach-Object { [string]$_['id'] })
    if ($policyProblems) { foreach ($p in $policyProblems) { Write-Warning "  TAP policy: $p" } }

    foreach ($upn in $IssueTapFor) {
        if ($policyProblems) { Add-Tap $upn 'FAILED-policy' -Detail ($policyProblems -join '; '); continue }
        try {
            $f = [uri]::EscapeDataString("userPrincipalName eq '$($upn.Replace("'", "''"))'")
            $u = @(Get-GraphCollection -Uri "$graph/users?`$filter=$f&`$select=id,userPrincipalName,accountEnabled") | Select-Object -First 1
            if (-not $u) { Add-Tap $upn 'FAILED-not-found'; continue }
            $uid = [string]$u['id']
            if ($uid -in $bgIds) { Add-Tap $upn 'REFUSED-break-glass' -Detail 'break-glass accounts use FIDO2 keys only, never a TAP'; continue }
            if ($u['accountEnabled'] -eq $false) { Add-Tap $upn 'FAILED-disabled'; continue }
            $groups = @(Get-GraphCollection -Uri "$graph/users/$uid/transitiveMemberOf/microsoft.graph.group?`$select=id" | ForEach-Object { [string]$_['id'] })
            if (@($groups | Where-Object { $_ -in $tapExclude }).Count) { Add-Tap $upn 'FAILED-excluded' -Detail 'user is in a TAP policy exclude group'; continue }
            if ('all_users' -notin $tapInclude -and -not @($groups | Where-Object { $_ -in $tapInclude }).Count) { Add-Tap $upn 'FAILED-not-in-scope' -Detail 'user is not in a TAP policy include target'; continue }
            $class = Get-AuthMethodClass -MethodsRegistered $(if ($regById.ContainsKey($uid)) { $regById[$uid] } else { @() })
            if ($class.PhishingResistant -and -not $Force) { Add-Tap $upn 'SKIPPED-already-registered' -Detail "has $($class.Class); use -Force for a recovery TAP"; continue }
            # One TAP per user: an existing usable pass is reported, never replaced.
            $existing = @(Get-GraphCollection -Uri "$graph/users/$uid/authentication/temporaryAccessPassMethods" | Where-Object { $_['isUsable'] })
            if ($existing) { Add-Tap $upn 'SKIPPED-has-usable-tap' -Detail "created $($existing[0]['createdDateTime']), lifetime $($existing[0]['lifetimeInMinutes']) min"; continue }
            if (-not $PSCmdlet.ShouldProcess($upn, "issue a $TapLifetimeMinutes-minute $(if ($TapIsUsableOnce) { 'one-time ' })Temporary Access Pass")) { Add-Tap $upn 'whatif'; continue }
            $resp = Invoke-Graph -Method POST -Uri "$graph/users/$uid/authentication/temporaryAccessPassMethods" -Body @{ lifetimeInMinutes = $TapLifetimeMinutes; isUsableOnce = $TapIsUsableOnce }
            $plain = [string]$resp['temporaryAccessPass']
            # Wrap the pass in a SecureString straight away so it does not sit
            # in the returned objects (or a transcript) as plain text.
            $secure = $null
            if ($plain) { $secure = [securestring]::new(); foreach ($ch in $plain.ToCharArray()) { $secure.AppendChar($ch) }; $secure.MakeReadOnly() }
            if ($RevealTap -and $plain) { Write-Console "  TAP for ${upn}: $plain  (deliver out of band; expires after $TapLifetimeMinutes min)" -ForegroundColor Magenta }
            $plain = $null; $resp = $null
            Add-Tap $upn 'issued' -Pass $secure -Detail 'register a passkey at https://aka.ms/mysecurityinfo with it'
        }
        catch { Add-Tap $upn 'FAILED' -Detail $_.Exception.Message }
    }
    $taps | Select-Object UserPrincipalName, Status, LifetimeMinutes, IsUsableOnce, Detail | Format-Table -AutoSize | Out-Host
}

# =============================================================================
# 3. CA008 ENFORCEMENT READINESS
# =============================================================================
Write-Console "`n[3/3] CA008 readiness (phishing-resistant for all users)" -ForegroundColor Cyan
$ca008Name = "${PolicyNamePrefix}008"
$ca008 = @(Get-GraphCollection -Uri "$graph/identity/conditionalAccess/policies" | Where-Object { ([string]$_['displayName']).StartsWith($ca008Name, [StringComparison]::OrdinalIgnoreCase) })
$readiness = $null
if ($ca008.Count -ne 1) {
    $readiness = [pscustomobject]@{ Verdict = 'NOT READY'; Reasons = @("expected one policy named '$ca008Name - ...', found $($ca008.Count) (Terraform enable_phishing_resistant_all_users)") }
}
else {
    $p = $ca008[0]
    $strengthId = [string]$(if ($p['grantControls'] -and $p['grantControls']['authenticationStrength']) { $p['grantControls']['authenticationStrength']['id'] })
    $combos = @()
    if ($strengthId) {
        $s = Invoke-Graph -Method GET -Uri "$graph/identity/conditionalAccess/authenticationStrength/policies/$strengthId"
        $combos = @(@($s['allowedCombinations']) | Where-Object { $_ })
    }
    $u = $p['conditions']['users']
    $includeUsers = @(@($u['includeUsers']) | Where-Object { $_ })
    $excludeIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @(@($u['excludeUsers']) | Where-Object { $_ })) { [void]$excludeIds.Add([string]$x) }
    foreach ($gid in @(@($u['excludeGroups']) | Where-Object { $_ })) {
        foreach ($m in (Get-GroupUserMember ([string]$gid))) { [void]$excludeIds.Add([string]$m['id']) }
    }
    $scopeRows = @()
    if ($includeUsers -contains 'All') {
        $scopeRows = @(Get-GraphCollection -Uri "$graph/users?`$select=id,userPrincipalName,accountEnabled,userType")
    }
    else {
        $scopeRows = @(foreach ($gid in @(@($u['includeGroups']) | Where-Object { $_ })) { Get-GroupUserMember ([string]$gid) })
        foreach ($uid in @($includeUsers | Where-Object { $_ -match '^[0-9a-f-]{36}$' })) {
            $scopeRows += Invoke-Graph -Method GET -Uri "$graph/users/$uid`?`$select=id,userPrincipalName,accountEnabled,userType"
        }
        if (@($u['includeRoles']).Count) { Write-Warning '  CA008 targets roles; role holders are not expanded here (expected: All users).' }
    }
    # CA008 (modules/conditional-access) excludes every guest/external user
    # type: a resource tenant cannot register a passkey for a guest. Members
    # with userType Guest are dropped here to match; external MEMBERS
    # (b2bCollaborationMember) cannot be told apart from userType alone and
    # stay in (verify: excludeGuestsOrExternalUsers shape on the live policy).
    $excludesGuests = $null -ne $u['excludeGuestsOrExternalUsers'] -and @($u['excludeGuestsOrExternalUsers']['guestOrExternalUserTypes']).Count -gt 0
    $inScope = @($scopeRows | Where-Object { $_['accountEnabled'] -ne $false -and -not $excludeIds.Contains([string]$_['id']) -and -not ($excludesGuests -and [string]$_['userType'] -eq 'Guest') } |
        Sort-Object { [string]$_['id'] } -Unique |
        ForEach-Object { [pscustomobject]@{ Id = [string]$_['id']; UserPrincipalName = [string]$_['userPrincipalName']; UserType = [string]$_['userType'] } })

    # Report-only evidence: sign-ins where CA008 would have failed.
    $since = (Get-Date).ToUniversalTime().AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = @(Get-GraphCollection -Uri "$graph/auditLogs/signIns?`$filter=createdDateTime ge $since&`$top=500" -MaxPages $MaxSignInPages)
    $roFail = @(foreach ($si in $signIns) {
            foreach ($ap in @($si['appliedConditionalAccessPolicies'])) {
                if ($ap -and [string]$ap['id'] -eq [string]$p['id'] -and [string]$ap['result'] -in 'reportOnlyFailure', 'reportOnlyInterrupted') { [string]$si['userId'] }
            }
        }) | Sort-Object -Unique
    $readiness = Get-Ca008Readiness -InScopeUsers $inScope -RegistrationById $regById -AllowedCombinations $combos -ReportOnlyFailureUserIds @($roFail)
    if (-not $strengthId) { $readiness.Verdict = 'NOT READY'; $readiness.Reasons += 'CA008 has no authentication strength grant control' }
    $readiness | Add-Member -NotePropertyName PolicyState -NotePropertyValue ([string]$p['state'])
    $readiness | Add-Member -NotePropertyName AllowedCombinations -NotePropertyValue $combos
    $readiness | Add-Member -NotePropertyName SignInsScanned -NotePropertyValue $signIns.Count
    $readiness | Add-Member -NotePropertyName SignInScanCapped -NotePropertyValue $script:SignInScanCapped
    if ([string]$p['state'] -eq 'enabled') { Write-Console '  CA008 is already ENFORCED.' -ForegroundColor Yellow }
}
# Pilot wave: who in this run's population could be enforced today (holds a
# method the CA008 strength accepts) and is not in the CA008 pilot group yet.
# -PromoteReadyToPilot adds them; widening the pilot is a membership change,
# never a policy edit (modules/conditional-access, CA008 rollout steps).
$promoted = 0; $readyNotInPilot = @()
$pilotGroup = Get-GroupByNickname $Ca008PilotGroupMailNickname
if (-not $pilotGroup) { Write-Console "  [i] CA008 pilot group '$Ca008PilotGroupMailNickname' not found (exists with enable_phishing_resistant_all_users)." -ForegroundColor DarkGray }
elseif ($readiness.PSObject.Properties['AllowedCombinations']) {
    $pilotIds = @(Get-GroupUserMember ([string]$pilotGroup['id']) | ForEach-Object { [string]$_['id'] })
    $population = @($populations.Values | ForEach-Object { $_ } | Where-Object { $_ -and $_['accountEnabled'] -ne $false -and [string]$_['id'] -notin $bgIds } | Sort-Object { [string]$_['id'] } -Unique)
    $readyNotInPilot = @($population | Where-Object {
            [string]$_['id'] -notin $pilotIds -and
            (Test-StrengthSatisfied -MethodsRegistered $(if ($regById.ContainsKey([string]$_['id'])) { $regById[[string]$_['id']] } else { @() }) -AllowedCombinations $readiness.AllowedCombinations)
        })
    Write-Console "  CA008 pilot group: $($pilotIds.Count) member(s); $($readyNotInPilot.Count) ready user(s) in this $Stage population not in it yet." -ForegroundColor Cyan
    if ($PromoteReadyToPilot) {
        foreach ($r in $readyNotInPilot) {
            if (-not $PSCmdlet.ShouldProcess([string]$r['userPrincipalName'], "add to $Ca008PilotGroupMailNickname")) { continue }
            try {
                Invoke-Graph -Method POST -Uri "$graph/groups/$($pilotGroup['id'])/members/`$ref" -Body @{ '@odata.id' = "$graph/directoryObjects/$($r['id'])" } | Out-Null
                $promoted++
            }
            catch { Write-Warning "  Could not add $($r['userPrincipalName']) to the pilot group: $($_.Exception.Message)" }
        }
        Write-Console "  [+] Added $promoted user(s) to $Ca008PilotGroupMailNickname." -ForegroundColor Green
    }
}

$color = if ($readiness.Verdict -eq 'READY') { 'Green' } else { 'Red' }
Write-Console "  CA008: $($readiness.Verdict)" -ForegroundColor $color
foreach ($r in @($readiness.Reasons)) { Write-Console "    - $r" -ForegroundColor $color }
if ($readiness.PSObject.Properties['SignInScanCapped'] -and $readiness.SignInScanCapped) { Write-Warning "  Sign-in scan stopped at $MaxSignInPages page(s); report-only counts are a lower bound." }

# =============================================================================
# OUTPUT (names stay in the gitignored out/ folder)
# =============================================================================
$csv = $null
if ($PSCmdlet.ShouldProcess($OutputDirectory, 'write per-user CSV + summary JSON')) {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $csv = Join-Path $OutputDirectory "registration-$($Stage.ToLowerInvariant())-$stamp.csv"
    $perUser | Export-Csv -LiteralPath $csv -NoTypeInformation
    [ordered]@{
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        stage          = $Stage
        groups         = $groupSummary
        ca008          = [ordered]@{
            verdict = $readiness.Verdict; reasons = @($readiness.Reasons)
            inScope = $(if ($readiness.PSObject.Properties['InScope']) { $readiness.InScope }); pctSatisfying = $(if ($readiness.PSObject.Properties['PctSatisfying']) { $readiness.PctSatisfying })
        }
        tapsIssued     = @($taps | Where-Object Status -eq 'issued').Count
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory "summary-$($Stage.ToLowerInvariant())-$stamp.json") -Encoding utf8
    Write-Console "`nPer-user CSV: $csv" -ForegroundColor DarkGray
}

$out = [pscustomobject]@{ Stage = $Stage; GroupSummary = $groupSummary; Ca008 = $readiness; ReadyNotInPilot = @($readyNotInPilot).Count; PromotedToPilot = $promoted; TapsIssued = $taps.ToArray(); PerUserCsv = $csv }
$tapFailed = @($taps | Where-Object { $_.Status -like 'FAILED*' }).Count
if ($tapFailed) { Write-Warning "$tapFailed TAP request(s) failed - see the table above." }
if (($FailIfNotReady -and $readiness.Verdict -ne 'READY') -or $tapFailed) { $out; exit 1 }
return $out
