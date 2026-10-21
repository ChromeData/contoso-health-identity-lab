<#
.SYNOPSIS
    Token Protection pilot as code: one REPORT-ONLY Conditional Access policy
    (CA011) that requires device-bound sign-in session tokens for Exchange
    Online, SharePoint Online and Teams on Windows, scoped to the CA005 pilot
    group. Read-only PLAN by default; changes the tenant only with -Apply.

.DESCRIPTION
    WHY: stolen session tokens (AiTM phishing, infostealers) replay MFA that
    already happened - risk register R03. The other CA policies decide HOW a
    user signs in; Token Protection decides whether the token presented later is still
    bound to the device it was issued to (Primary Refresh Token binding), so a
    copied token is worthless elsewhere.

    WHY A SCRIPT: the azuread provider (3.10) has no session control for it
    (session_controls offers sign-in frequency, persistent browser, CAE-adjacent
    settings only), so this is a post-apply Graph step like the other gaps.

    NUMBER: CA011, a baseline-range number of its own (CA design principles:
    a control the provider can't express gets its own Graph-managed policy,
    never patched onto a Terraform one). It was CA010 until CA010 became the
    Terraform-managed device-code block; it had never reached a tenant.

    WHAT IT WRITES (desired state, compared on every run)
      displayName  "CA011 - Token protection (sign-in session) - pilot (<state>)"
      state        enabledForReportingButNotEnforced (default). "enabled" needs
                   -State enabled AND -AllowEnforce (second key): enforcing
                   breaks unsupported clients (Microsoft's own guidance is
                   report-only first, pilot, then enforce).
      users        include the CA005 pilot group (CA005-Pilot-CompliantDevice,
                   the managed Windows 11 device's users); exclude break-glass.
      apps         Exchange Online 00000002-0000-0ff1-ce00-000000000000,
                   SharePoint Online 00000003-0000-0ff1-ce00-000000000000,
                   Microsoft Teams Services cc15fd57-2c6c-4117-a88c-83b1d56b4bbe
                   (the supported resources for native apps - Microsoft Learn,
                   "Token protection").
      platforms    windows;  client apps: mobileAppsAndDesktopClients
      session      secureSignInSession { isEnabled = true }
    verify: the Graph property (beta sessionControls.secureSignInSession) and
    the licence (Microsoft Learn lists Entra ID P1 at the time of writing) on
    the first run; the CA005 device must be Entra-joined Windows 10+.

    IDEMPOTENT: finds its policy by the "CA011 - " prefix; equal = no write;
    different = PATCH (with -Apply); missing = POST (with -Apply). Never
    deletes. OWNERSHIP GUARD: a CA011 policy that is not this script's
    token-protection policy (displayName "CA011 - Token protection ...") is
    REFUSED (exit 1), never rewritten. Break-glass exclusion is asserted on
    every run (exit 1 if a policy carrying this name lacks it).

.PARAMETER Apply
    Staging switch (default off). Without it the script only reads and prints
    the plan.

.PARAMETER State
    enabledForReportingButNotEnforced (default) or enabled.

.PARAMETER AllowEnforce
    Second key for -State enabled.

.PARAMETER PilotGroupMailNickname / BreakGlassGroupMailNickname
    Defaults ca005-pilot-compliantdevice / break-glass-admins (Terraform
    contract, modules/groups).

.PARAMETER OfflinePreview
    No tenant: print the desired JSON with placeholder group ids.

.EXAMPLE
    ./Set-TokenProtectionPolicy.ps1 -OfflinePreview
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.ConditionalAccess','Group.Read.All'
    ./Set-TokenProtectionPolicy.ps1                 # plan
    ./Set-TokenProtectionPolicy.ps1 -Apply -WhatIf  # shows the write
    ./Set-TokenProtectionPolicy.ps1 -Apply          # report-only pilot

.GRAPH SCOPES  (delegated)
    Policy.Read.All, Policy.ReadWrite.ConditionalAccess (with -Apply), Group.Read.All
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [ValidateSet('enabledForReportingButNotEnforced', 'enabled')]
    [string]$State = 'enabledForReportingButNotEnforced',

    [Parameter()]
    [switch]$AllowEnforce,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PilotGroupMailNickname = 'ca005-pilot-compliantdevice',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

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

# beta: sessionControls.secureSignInSession (verify: v1.0 availability).
$caUri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
$PolicyPrefix = 'CA011 - '
# Only a policy carrying this full prefix is ours to PATCH (ownership guard).
$OwnedPrefix = "${PolicyPrefix}Token protection"
$ResourceAppIds = @(
    '00000002-0000-0ff1-ce00-000000000000',   # Office 365 Exchange Online
    '00000003-0000-0ff1-ce00-000000000000',   # Office 365 SharePoint Online
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'    # Microsoft Teams Services
)

if ($State -eq 'enabled' -and -not $AllowEnforce) {
    throw 'Enforcing Token Protection breaks unsupported clients: -State enabled needs -AllowEnforce as well (report-only first, then the pilot, then enforce).'
}

function Get-DesiredPolicy {
    # Pure: the policy this script owns. Unit-tested.
    param([string]$PilotGroupId, [string]$BreakGlassGroupId, [string]$PolicyState)
    $label = if ($PolicyState -eq 'enabled') { 'enforced' } else { 'report-only' }
    return [ordered]@{
        displayName     = "${PolicyPrefix}Token protection (sign-in session) - pilot ($label)"
        state           = $PolicyState
        conditions      = [ordered]@{
            clientAppTypes = @('mobileAppsAndDesktopClients')
            applications   = [ordered]@{ includeApplications = $ResourceAppIds }
            platforms      = [ordered]@{ includePlatforms = @('windows') }
            users          = [ordered]@{ includeGroups = @($PilotGroupId); excludeGroups = @($BreakGlassGroupId) }
        }
        sessionControls = [ordered]@{ secureSignInSession = [ordered]@{ isEnabled = $true } }
    }
}

function Get-PolicyDrift {
    # Pure: which owned fields differ (compared as canonical JSON).
    param([System.Collections.IDictionary]$Desired, [System.Collections.IDictionary]$Current)
    $drift = @()
    if ([string]$Current['displayName'] -ne [string]$Desired['displayName']) { $drift += 'displayName' }
    if ([string]$Current['state'] -ne [string]$Desired['state']) { $drift += 'state' }
    $c = $Current['conditions']; $d = $Desired['conditions']
    foreach ($pair in @(
            @('applications.includeApplications', @($c['applications']['includeApplications']), @($d['applications']['includeApplications'])),
            @('platforms.includePlatforms', @($c['platforms']['includePlatforms']), @($d['platforms']['includePlatforms'])),
            @('users.includeGroups', @($c['users']['includeGroups']), @($d['users']['includeGroups'])),
            @('users.excludeGroups', @($c['users']['excludeGroups']), @($d['users']['excludeGroups'])),
            @('clientAppTypes', @($c['clientAppTypes']), @($d['clientAppTypes'])))) {
        if ((@($pair[1] | Sort-Object) -join ',') -ne (@($pair[2] | Sort-Object) -join ',')) { $drift += $pair[0] }
    }
    $s = $Current['sessionControls']
    $on = $s -and $s['secureSignInSession'] -and [bool]$s['secureSignInSession']['isEnabled']
    if (-not $on) { $drift += 'sessionControls.secureSignInSession' }
    return $drift
}

function Resolve-GroupId([string]$Nick) {
    $r = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=mailNickname eq '$Nick'&`$select=id"
    $v = @($r['value'])
    if ($v.Count -ne 1) { return $null }
    return [string]$v[0]['id']
}

if ($OfflinePreview) {
    $desired = Get-DesiredPolicy -PilotGroupId '<CA005 pilot group id>' -BreakGlassGroupId '<Break-Glass-Admins id>' -PolicyState $State
    Write-Console ($desired | ConvertTo-Json -Depth 8)
    Write-Console 'Offline preview: nothing read or written.' -ForegroundColor DarkGray
    return
}

$pilotId = Resolve-GroupId $PilotGroupMailNickname
$bgId = Resolve-GroupId $BreakGlassGroupMailNickname
if (-not $bgId) { Write-Console "[FAIL] break-glass group '$BreakGlassGroupMailNickname' not found - refusing to write a CA policy that cannot exclude it" -ForegroundColor Red; exit 1 }
if (-not $pilotId) { Write-Console "[FAIL] pilot group '$PilotGroupMailNickname' not found - apply Terraform envs/dev (enable_premium) first" -ForegroundColor Red; exit 1 }

$desired = Get-DesiredPolicy -PilotGroupId $pilotId -BreakGlassGroupId $bgId -PolicyState $State
$existing = @(@((Invoke-MgGraphRequest -Method GET -Uri $caUri)['value']) | Where-Object { [string]$_['displayName'] -like "$PolicyPrefix*" })
if ($existing.Count -gt 1) { Write-Console "[FAIL] $($existing.Count) policies start with '$PolicyPrefix' - resolve by hand" -ForegroundColor Red; exit 1 }

if ($existing.Count -eq 0) {
    Write-Console "[INFO] CA011 missing: would create (state $State)" -ForegroundColor Yellow
    if (-not $Apply) { Write-Console '[WARN] plan only (re-run with -Apply)' -ForegroundColor Yellow; return }
    if ($PSCmdlet.ShouldProcess($desired.displayName, 'create Conditional Access policy')) {
        $created = Invoke-MgGraphRequest -Method POST -Uri $caUri -Body ($desired | ConvertTo-Json -Depth 8) -ContentType 'application/json'
        Write-Console "[PASS] created $($created['id'])" -ForegroundColor Green
    }
    return
}

$current = $existing[0]
# Ownership guard: never PATCH a policy that merely shares the number (a
# hand-made CA011, or a renumbered Terraform policy) into a token-protection
# policy - the next apply would fight it, and its own control would vanish.
if (-not ([string]$current['displayName']).StartsWith($OwnedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Console "[FAIL] '$($current['displayName'])' starts with '$PolicyPrefix' but is not this script's token-protection policy - refusing to change it. Resolve the number clash by hand." -ForegroundColor Red
    exit 1
}
$drift = @(Get-PolicyDrift -Desired $desired -Current $current)
# The invariant every CA policy in this lab carries, checked even without drift.
if (@($current['conditions']['users']['excludeGroups']) -notcontains $bgId) {
    Write-Console '[FAIL] the existing CA011 does not exclude break-glass' -ForegroundColor Red
    if (-not $Apply) { exit 1 }
}
if ($drift.Count -eq 0) { Write-Console '[PASS] CA011 in sync with desired state' -ForegroundColor Green; return }
Write-Console "[INFO] drift in: $($drift -join ', ')" -ForegroundColor Yellow
if (-not $Apply) { Write-Console '[WARN] plan only (re-run with -Apply)' -ForegroundColor Yellow; return }
if ($PSCmdlet.ShouldProcess([string]$current['displayName'], "PATCH ($($drift -join ', '))")) {
    Invoke-MgGraphRequest -Method PATCH -Uri "$caUri/$($current['id'])" -Body ($desired | ConvertTo-Json -Depth 8) -ContentType 'application/json' | Out-Null
    Write-Console '[PASS] CA011 updated' -ForegroundColor Green
}
