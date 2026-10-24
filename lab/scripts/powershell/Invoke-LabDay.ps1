<#
.SYNOPSIS
    The trial-window day runner. Invoke-LabDay.ps1 -Day <n> walks one day of
    the 30-day Microsoft 365 E5 + Entra ID Governance window in order:
    preflight first, every tenant change delegated to the lab script that
    owns it (dry run, then your yes, then its own confirmations), a pause
    with the exact console path at every portal step, and a read-only
    evidence capture wherever an API can read the result.

.DESCRIPTION
    WHY
      The trials are the scarce resource: 30 days of E5 (Entra ID P2,
      Intune, Defender), 30 of Entra ID Governance, 31 of Sentinel. Every
      line of code is written and tested offline before Day 0, so the window
      is spent running and capturing, not coding. This script makes each
      day one command: nothing is forgotten, nothing runs out of order, and
      the evidence is hashed the moment it exists (capture rule 1: once,
      when it happens).

    WHAT A RUN DOES
      1. 00-Preflight.ps1, in this session (so it sees your Graph and az
         sign-ins), told which lab.tfvars flags and CA graduations the plan
         says are on by now. Exit 2 stops the day; exit 1 asks first.
      2. The day's steps in order (evidence/LabDayPlan.psd1, one entry each):
           console   the exact console path, what success looks like, the
                     rollback; then [d]one / [s]kip / [m]issed / [q]uit
           pr        the lab.tfvars change and the PR route (a flag flip is
                     a PR, planned and applied by the pipeline); after
                     [d]one it reads this clone's lab.tfvars to confirm
           terminal  the command to run yourself (a local apply, the Windows
                     assessment host, the bash scripts in lab/pam), then waits
           script    the existing lab script, never a re-implementation:
                     read-only runs go straight ahead; a change runs its dry
                     run first (-WhatIf, or Invoke-PostApply.ps1 without
                     -Execute), then asks you, then the real run with the
                     script's own confirmations. A non-zero exit stops the day.
      3. After a step, the read-only captures it names, into
         lab/evidence/tenant/<UTC day>/<evidence id>/ (ids from
         lab/docs/evidence-capture-plan.md): raw/ (private: the Graph / Log
         Analytics / pipeline exports and the script transcripts, kept out
         of git by a .gitignore beside it), manifest.json and SHA256SUMS
         (public-safe), plus one row in lab/evidence/capture-log.csv. A read
         that fails (no Graph session, a missing scope) is an item marked
         failed in a sealed capture and the day goes on; the closing lines
         name the -CaptureOnly command that takes it again.
      4. Progress in lab/scripts/powershell/out/labday/state.json
         (gitignored), one entry per step id: done, missed, skipped (an
         optional step), deferred ([s]kip or [q]uit), failed or running.
         After a failure or a [q]uit, run the same command again: it carries
         on at the first step that is not done, missed or a skipped optional
         step. A failed or interrupted step resumes as the same attempt (its
         start time, the window its captures read, and its before-capture
         are kept); a script step starts again from its dry run. A step is
         marked done before its captures run, so a capture that breaks
         (exit 3) never makes a resume repeat the change: take it again with
         -Step <id> -CaptureOnly.

    THE DAYS (-WhatIf prints any day in full)
       0  Trials, licences, security defaults; sign-in logs flowing (E08, E09)
       1  Baselines (E10, E11), every CA policy report-only (E12), break-glass
          keys and the baseline gate (E13), HR active rows, admin accounts,
          ITDR telemetry (E15a)
       2  Sentinel (E15), PIM tiers and eligibility (E16, E16a), Global
          Administrator policy and the build account made eligible (E16b),
          help-desk AU (E16c), first activation (E17, E17b, E18), c1 report-only (E17c)
       3  Governance (E19), joiner (E20, E20b), auth methods + consent (E21);
          Days 3-5: DC01 events and the second-wave rules (E15b, E15c)
       4  AWS SSO + SCIM, the Clinical Portal token, app governance (E22-E25)
       5  Risk simulation (E26, E27), Intune
       6  CA insights (E28), device code (E28b), passwordless pilot (E29)
       7  CA003 (E30, E31)      8  reviews (E32), B2B (E33), Azure PIM (E34), Splunk
       9  CA001 (E35)          10  CA002, CA007 (E36); Days 10-11: CA021, PIM on c1 (E36b)
      11  Tor again (E37)       12  CA006 (E38), CA009/CA010/CA020 (E38b), Pharmacy review (E39)
      13  review KPIs (E39b), SoD tripwire (E39c), containment playbook (E40)
      14  containment drill (E41), joiner and mover takes (E52 mover)
      15  one event per ITDR rule (E42-E48)
      16  break-glass drill (E49), CA004 through the pipeline
      17  CA005 (E50), CA060 (E50b), PAM on DC01 (E51a, E51, E51f), AD plane (E51b, E51c)
      18  CA restore drill (E51d), token protection (E51e), protected actions
          (E51g), leaver (E52)
      19  NHI (E53), Agent ID (E53b), midPoint reads Entra (E53c, optional)
      20-24  buffer: re-takes only
      25  KPIs after (E54)     26  assessment after (E55)     27  evidence pack (E56)
      28  close-out and the WORM decision (E57)  29  post-trial PRs (E58)
    Not here: the pre-window steps (P1-P5, E01-E07) and the teardown.

    SAFETY
      * -WhatIf prints the day and calls nothing: no script, no Graph, no
        az, no gh, no file written.
      * This script never changes the tenant. Every change is made by the
        script that owns it, after its own dry run and your yes.
      * Captures read only: Graph through GET alone; az and gh through an
        allowlist of read verbs; never `terraform output` (it prints
        sensitive values in clear text).
      * It never signs in for you and never uses device code (CA010): each
        script opens the browser itself.
      * The public files (manifest.json, SHA256SUMS, the capture-log row)
        carry no tenant id, object id, UPN or IP; the manifest writer
        refuses one that would.

.PARAMETER Day
    The trial day, 0 (both trials activated) to 29.

.PARAMETER Step
    Run only this step: its id (as -WhatIf lists them) or an evidence id
    (E16b runs every step of the day that captures E16b). Runs even when
    the step is already done, as a new attempt; its captures are then new
    re-run ids.

.PARAMETER CaptureOnly
    Run only the after-captures of the day's steps (or of -Step): for a
    step you did by hand, or a capture with failed reads (no Graph
    session). No step runs, nothing is marked done, no before-capture is
    taken (that state is gone once the step ran). With an evidence id as
    -Step, only that id's folders. Preflight still runs first.

.PARAMETER SinceUtc
    With -CaptureOnly: the start of the window the log captures read.
    Default: when the step started under this script, else 24 hours ago.

.PARAMETER NewSettingsFile
    Write an empty settings template to -SettingsPath (never overwrites)
    and stop. The settings hold names and ids, never a secret.

.PARAMETER SettingsPath
    JSON with the lab's names and ids (tenant domain, provisioning ids, Key
    Vault name ...). Default lab/scripts/powershell/out/labday/settings.json
    (gitignored).

.PARAMETER StatePath
    Progress file. Default lab/scripts/powershell/out/labday/state.json (gitignored).

.PARAMETER EvidenceRoot
    Where captures go. Default lab/evidence/tenant.

.PARAMETER CaptureLogPath
    The capture log. Default lab/evidence/capture-log.csv.

.PARAMETER NoCaptureLog
    Capture without appending capture-log rows (a rehearsal).

.PARAMETER ExpectedOnFlags
    Flags on by design that the plan does not know about (for example
    accept_admin_synced_passkey_risk, or containment_on_alert_added): added
    to what preflight is told to expect.

.PARAMETER ExpectedEnforcedPolicies
    CA ids graduated outside the plan: added to what preflight expects.

.PARAMETER LabRoot
    The lab/ folder. Default two levels above this script. (The Pester
    suite points it at stub scripts.)

.PARAMETER PlanPath
    The plan. Default evidence/LabDayPlan.psd1 beside this script.

.EXAMPLE
    ./Invoke-LabDay.ps1 -Day 2 -WhatIf
    The whole of Day 2: every step, the exact commands with your settings
    filled in, the captures and where they go. Nothing runs.

.EXAMPLE
    ./Invoke-LabDay.ps1 -NewSettingsFile -Day 0
    Then fill in out/labday/settings.json (names and ids only).

.EXAMPLE
    Connect-MgGraph -Scopes <the read scopes -WhatIf prints> -NoWelcome    # browser, passkey
    az login --tenant <tenant>.onmicrosoft.com                              # browser
    ./Invoke-LabDay.ps1 -Day 2
    Run it in the pwsh session that holds the Graph connection (not
    `pwsh -File`, which starts a new session without it).

.EXAMPLE
    ./Invoke-LabDay.ps1 -Day 2 -Step E16b -CaptureOnly
    Capture E16b again (a new re-run id) after connecting Graph with the
    scopes a failed capture reported.

.NOTES
    Exit codes: 0 every selected step done (or -WhatIf); 1 stopped by you,
    or steps left for later; 2 preflight blocked; 3 a step failed (fix it,
    run the same command again: it resumes there) or its capture broke
    (-Step <id> -CaptureOnly); 4 bad -Step.
    A script step passes when $LASTEXITCODE after it is 0 (or one the plan
    allows: OkExitCodes, OkExitCodeMax), read the way Invoke-PostApply.ps1
    reads its steps; a script that throws fails the step.
    Status: BUILT. tests/Invoke-LabDay.Tests.ps1 runs every day of the plan
    against stub scripts generated from the real scripts' param blocks
    (every call binds) with Graph, az and gh mocked. No step has run
    against a tenant: none exists yet.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateRange(0, 29)]
    [int]$Day,

    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9-]{0,63}$')]
    [string]$Step = '',

    [switch]$CaptureOnly,

    [Nullable[datetime]]$SinceUtc = $null,

    [switch]$NewSettingsFile,

    [string]$SettingsPath = (Join-Path $PSScriptRoot 'out' 'labday' 'settings.json'),

    [string]$StatePath = (Join-Path $PSScriptRoot 'out' 'labday' 'state.json'),

    [string]$EvidenceRoot = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'tenant'),

    [string]$CaptureLogPath = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'capture-log.csv'),

    [switch]$NoCaptureLog,

    [ValidatePattern('^[a-z0-9_]+$')]
    [string[]]$ExpectedOnFlags = @(),

    [ValidatePattern('^CA\d{3}$')]
    [string[]]$ExpectedEnforcedPolicies = @(),

    [string]$LabRoot = (Join-Path $PSScriptRoot '..' '..'),

    [string]$PlanPath = (Join-Path $PSScriptRoot 'evidence' 'LabDayPlan.psd1')
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

# The capture helpers. Imported once: a second import would drop the mocks
# the Pester suite puts on them.
$modulePath = Join-Path $PSScriptRoot 'evidence' 'LabEvidence.psm1'
$loadedModule = Get-Module -Name 'LabEvidence'
if (-not $loadedModule -or [System.IO.Path]::GetFullPath($loadedModule.Path) -ne [System.IO.Path]::GetFullPath($modulePath)) {
    Import-Module $modulePath -Force -DisableNameChecking
}

$script:LabRootFull = [System.IO.Path]::GetFullPath($LabRoot)
$script:RepoRoot = Split-Path -Parent $script:LabRootFull
$EvidenceRoot = [System.IO.Path]::GetFullPath($EvidenceRoot)
$CaptureLogPath = [System.IO.Path]::GetFullPath($CaptureLogPath)
$StatePath = [System.IO.Path]::GetFullPath($StatePath)
$SettingsPath = [System.IO.Path]::GetFullPath($SettingsPath)
$script:TranscriptDir = Join-Path (Split-Path -Parent $StatePath) 'transcripts'

# Values the plan cannot know in advance: asked once per step when the
# settings file leaves them empty (never written to a log or the state).
$script:Promptable = @{
    ChangeTicket        = '^[A-Za-z0-9._-]{1,32}$'
    CaRestorePolicyName = '^[^\r\n]{3,256}$'
    E5SkuPartNumber     = '^[A-Za-z0-9_()+.-]{2,64}$'
}
$script:StepPrompted = @{}
$script:CapturesWritten = [System.Collections.Generic.List[object]]::new()
$script:NoLog = [bool]$NoCaptureLog
$script:ExtraOnFlags = @($ExpectedOnFlags)
$script:ExtraEnforced = @($ExpectedEnforcedPolicies)

# =============================================================================
# Plan
# =============================================================================
function Import-LabDayPlan {
    # Loads and normalises evidence/LabDayPlan.psd1; a malformed step throws
    # here, before anything runs.
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Plan not found: $Path" }
    $skip = @{}
    if ((Get-Command Import-PowerShellDataFile).Parameters.ContainsKey('SkipLimitCheck')) { $skip['SkipLimitCheck'] = $true }
    $raw = Import-PowerShellDataFile -LiteralPath $Path @skip
    $titles = @{}
    foreach ($d in @($raw['Days'])) { $titles[[int]$d['Day']] = [string]$d['Title'] }
    $steps = [System.Collections.Generic.List[hashtable]]::new()
    $seen = @{}
    foreach ($s in @($raw['Steps'])) {
        $n = ConvertTo-LabDayStep -Raw $s
        if ($seen.ContainsKey($n.Id)) { throw "Plan: step id '$($n.Id)' is used twice." }
        $seen[$n.Id] = $true
        $steps.Add($n)
    }
    return @{ Titles = $titles; Steps = $steps.ToArray(); PreWindowFlags = @($raw['PreWindowFlags'] | Where-Object { $_ }) }
}

function ConvertTo-LabDayStep {
    param([Parameter(Mandatory)][hashtable]$Raw)
    $id = [string]$Raw['Id']
    if ($id -notmatch '^[a-z0-9][a-z0-9-]{0,63}$') { throw "Plan: bad step id '$id'." }
    $known = @('Id', 'Day', 'Days', 'Kind', 'Title', 'Evidence', 'Part', 'NewCaptureId', 'Rerun', 'Optional', 'Local', 'Do', 'Before',
        'Flags', 'FlagsOff', 'Enforce', 'Success', 'Note', 'Rollback', 'MissedReason', 'Check', 'Script', 'Args', 'Runs',
        'OkExitCodes', 'OkExitCodeMax', 'Capture', 'CaptureBefore')
    $unknown = @($Raw.Keys | Where-Object { $_ -notin $known })
    if ($unknown.Count) { throw "Plan: step '$id' has unknown field(s) $($unknown -join ', ') (a typo would silently drop it)." }
    if (-not ($Raw.ContainsKey('Day') -or $Raw.ContainsKey('Days'))) { throw "Plan: step '$id' names no Day or Days." }
    $days = @(if ($Raw.ContainsKey('Days')) { $Raw['Days'] | ForEach-Object { [int]$_ } } else { [int]$Raw['Day'] })
    if (-not $days.Count -or @($days | Where-Object { $_ -lt 0 -or $_ -gt 29 }).Count) { throw "Plan: step '$id' has no day in 0-29." }
    $kind = [string]$Raw['Kind']
    if ($kind -notin @('console', 'pr', 'terminal', 'script')) { throw "Plan: step '$id' has kind '$kind' (console, pr, terminal or script)." }
    if (-not [string]$Raw['Title']) { throw "Plan: step '$id' has no Title." }
    $runs = @()
    if ($kind -eq 'script') {
        if (-not $Raw['Script']) { throw "Plan: script step '$id' names no Script." }
        $runs = @(if ($Raw.ContainsKey('Runs')) { $Raw['Runs'] } else { @{ Mode = 'read' } })
        foreach ($r in $runs) { if ([string]$r['Mode'] -notin @('read', 'dry', 'real')) { throw "Plan: step '$id' has a run mode '$($r['Mode'])' (read, dry or real)." } }
    }
    elseif ($Raw['Script'] -or $Raw['Runs'] -or $Raw['Args']) { throw "Plan: step '$id' is a $kind step: Script, Args and Runs belong to script steps." }
    $list = { param($k) @($Raw[$k] | Where-Object { $null -ne $_ -and [string]$_ -ne '' }) }
    $evidence = @(& $list 'Evidence' | ForEach-Object { [string]$_ })
    foreach ($e in $evidence) { if ($e -cnotmatch '^E\d{2}[a-z]?$') { throw "Plan: step '$id' has evidence id '$e' (E<nn>[a-z])." } }
    if ($Raw['NewCaptureId'] -and [string]$Raw['NewCaptureId'] -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,47}$') { throw "Plan: step '$id' has a bad NewCaptureId." }
    if ($Raw['Part'] -and [string]$Raw['Part'] -cnotmatch '^[a-z0-9][a-z0-9-]{0,39}$') { throw "Plan: step '$id' has a bad Part." }
    $ids = @(if ($Raw['NewCaptureId']) { [string]$Raw['NewCaptureId'] } else { $evidence })
    $recipes = @(Get-LabCaptureRecipeName)
    $specKeys = @('Recipe', 'Name', 'Evidence', 'Part', 'User', 'Service', 'Query', 'Workflow', 'Path', 'LookbackHours')
    foreach ($spec in @(& $list 'Capture') + @(& $list 'CaptureBefore')) {
        if ($spec -isnot [hashtable]) { throw "Plan: step '$id' has a capture that is not a hashtable." }
        $r = [string]$spec['Recipe']
        if ($r -notin $recipes) { throw "Plan: step '$id' names capture recipe '$r' (known: $($recipes -join ', '))." }
        $bad = @($spec.Keys | Where-Object { $_ -notin $specKeys })
        if ($bad.Count) { throw "Plan: step '$id', recipe '$r': unknown field(s) $($bad -join ', ')." }
        $need = @{ la = 'Query'; files = 'Path'; 'logic-app-runs' = 'Workflow' }
        if ($need.ContainsKey($r) -and -not $spec[$need[$r]]) { throw "Plan: step '$id', recipe '$r' needs $($need[$r])." }
        if (-not $ids.Count) { throw "Plan: step '$id' captures but names no Evidence (or NewCaptureId) to file it under." }
        if ($spec['Evidence'] -and [string]$spec['Evidence'] -notin $ids) { throw "Plan: step '$id' files a capture under '$($spec['Evidence'])', which is not one of its evidence ids." }
        if ($spec.ContainsKey('Part') -and [string]$spec['Part'] -cnotmatch '^[a-z0-9][a-z0-9-]{0,39}$') { throw "Plan: step '$id', recipe '$r': bad Part." }
    }
    return @{
        Id = $id; Days = $days; Kind = $kind; Title = [string]$Raw['Title']
        Evidence = $evidence; Part = [string]$Raw['Part']; NewCaptureId = [string]$Raw['NewCaptureId']
        Rerun = [bool]$Raw['Rerun']; Optional = [bool]$Raw['Optional']; Local = [bool]$Raw['Local']
        Do = @(& $list 'Do'); Before = @(& $list 'Before')
        Flags = @(& $list 'Flags'); FlagsOff = @(& $list 'FlagsOff'); Enforce = @(& $list 'Enforce')
        Success = [string]$Raw['Success']; Note = [string]$Raw['Note']; Rollback = [string]$Raw['Rollback']; MissedReason = [string]$Raw['MissedReason']
        Check = [string]$Raw['Check']
        Script = [string]$Raw['Script']; Args = $(if ($Raw['Args']) { $Raw['Args'] } else { @{} }); Runs = $runs
        OkExitCodes = $(if ($Raw.ContainsKey('OkExitCodes')) { @($Raw['OkExitCodes'] | ForEach-Object { [int]$_ }) } else { @(0) })
        OkExitCodeMax = $(if ($Raw.ContainsKey('OkExitCodeMax')) { [int]$Raw['OkExitCodeMax'] } else { -1 })
        Capture = @(& $list 'Capture'); CaptureBefore = @(& $list 'CaptureBefore')
    }
}

function Get-LabDayStepFor {
    param([Parameter(Mandatory)][hashtable]$Plan, [Parameter(Mandatory)][int]$ForDay)
    return @($Plan.Steps | Where-Object { $ForDay -in $_.Days })
}

function Get-LabDayStepEvidence {
    # The capture ids a step writes: its evidence ids, or its new capture id.
    param([Parameter(Mandatory)][hashtable]$PlanStep)
    if ($PlanStep.NewCaptureId) { return @($PlanStep.NewCaptureId) }
    return @($PlanStep.Evidence)
}

# =============================================================================
# State and settings
# =============================================================================
function Read-LabDayState {
    param([Parameter(Mandatory)][string]$Path)
    $state = @{ schema = 'contoso-lab-day-state/1'; steps = @{} }
    if (Test-Path -LiteralPath $Path) {
        $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
        if ($j -and $j['steps']) { $state['steps'] = $j['steps'] }
    }
    return $state
}

function Save-LabDayState {
    # Atomic: write a temp file, then move it over the old one.
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = "$Path.tmp"
    ConvertTo-Json -InputObject $State -Depth 10 | Set-Content -LiteralPath $tmp -Encoding utf8NoBOM
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Get-LabDayEntry {
    param([Parameter(Mandatory)][string]$Id)
    if (-not $script:State['steps'].ContainsKey($Id)) { $script:State['steps'][$Id] = @{ status = ''; transcripts = @(); captures = @() } }
    return $script:State['steps'][$Id]
}

function Get-LabDayStatus {
    param([Parameter(Mandatory)][string]$Id)
    if ($script:State['steps'].ContainsKey($Id)) { return [string]$script:State['steps'][$Id]['status'] }
    return ''
}

function Get-LabDaySettingDefault {
    # Every key the plan's placeholders use. Names and ids only: no secret
    # ever goes in the settings file.
    return [ordered]@{
        OnMicrosoftDomain              = ''      # <tenant>.onmicrosoft.com
        Domain                         = ''      # the custom domain (HR UPNs)
        ResourceGroup                  = 'rg-identity-lab'
        WorkspaceName                  = 'loga-idlab'
        KeyVaultName                   = ''
        EvidenceStorageAccount         = ''
        ProvisioningServicePrincipalId = ''      # the HR inbound provisioning app
        ProvisioningJobId              = ''
        E5SkuPartNumber                = ''      # asked when empty (Get-MgSubscribedSku names it)
        ServiceNowInstance             = ''      # devNNNNNN
        ServiceNowUser                 = ''      # the integration user
        TeamsGroupId                   = ''
        TeamsChannelId                 = ''
        AdminUpn                       = 'admin@{OnMicrosoftDomain}'
        EligibleAdminUpn               = 'adm-ava.lin@{OnMicrosoftDomain}'
        Tier1AdminUpn                  = 'adm-raj.patel@{OnMicrosoftDomain}'
        JoinerUpn                      = 'dana.okafor@{Domain}'
        PilotUpn                       = ''      # the CA005 / Intune pilot user
        TestAccountA                   = 'tst-a@{OnMicrosoftDomain}'
        TestAccountB                   = 'tst-b@{OnMicrosoftDomain}'
        TestAccountC                   = 'tst-c@{OnMicrosoftDomain}'
        TestAccountD                   = 'tst-d@{OnMicrosoftDomain}'
        TestAccountE                   = 'tst-e@{OnMicrosoftDomain}'
        TestAccountF                   = 'tst-f@{OnMicrosoftDomain}'
        TestSmsUpn                     = 'tst-sms@{OnMicrosoftDomain}'
        VipUserPrincipalNames          = @()
        BreakGlassKeysPerAccount       = 2
        BreakGlassDeclaredSignIns      = @()     # empty = every account x every key
        SkipPam                        = $true   # false once the vault stack is up
        Operator                       = ''      # initials for the capture log
        CaRestorePolicyName            = ''      # asked when empty
        ChangeTicket                   = ''      # asked when empty, per step
        ExtraExpectedOnFlags           = @()
        ExtraEnforcedPolicies          = @()
    }
}

function Read-LabDaySetting {
    param([Parameter(Mandatory)][string]$Path)
    $s = @{}
    $defaults = Get-LabDaySettingDefault
    foreach ($k in $defaults.Keys) { $s[$k] = $defaults[$k] }
    if (Test-Path -LiteralPath $Path) {
        $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
        if ($j) { foreach ($k in $j.Keys) { if ($k -notlike '_*') { $s[$k] = $j[$k] } } }
    }
    if ($s['OnMicrosoftDomain'] -and [string]$s['OnMicrosoftDomain'] -notmatch '^[A-Za-z0-9-]+\.onmicrosoft\.com$') { throw "Settings: OnMicrosoftDomain must look like <tenant>.onmicrosoft.com." }
    if ($s['Operator'] -and [string]$s['Operator'] -notmatch '^[A-Za-z0-9 ._-]{1,32}$') { throw 'Settings: Operator is initials only (no @, no full name): it goes into the public capture log.' }
    if (-not @($s['BreakGlassDeclaredSignIns'] | Where-Object { $_ }).Count) {
        $n = [Math]::Max(1, [int]$s['BreakGlassKeysPerAccount'])
        $s['BreakGlassDeclaredSignIns'] = @(foreach ($a in '01', '02') { foreach ($k in 1..$n) { "bg-admin-$($a):key $k" } })
    }
    return $s
}

# =============================================================================
# Placeholders
# =============================================================================
function Test-LabDayHasValue {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return [bool]$Value }
    if ($Value -is [System.Collections.IList]) { return [bool]@($Value | Where-Object { $null -ne $_ -and [string]$_ -ne '' }).Count }
    return $true
}

function Resolve-LabDayToken {
    # One {Name} or {Name:Arg}. -Preview never asks and never throws: it
    # shows <Name> for anything it cannot fill.
    param([Parameter(Mandatory)][string]$Name, [string]$Arg = '', [switch]$Preview, [int]$Depth = 0)
    switch ($Name) {
        'StartUtc' {
            $e = if ($script:State['steps'].ContainsKey($Arg)) { $script:State['steps'][$Arg] } else { $null }
            if ($e -and $e['startedUtc']) { return ([datetime]$e['startedUtc']).ToUniversalTime() }
            if ($Preview) { return "<when step $Arg started>" }
            throw "step '$Arg' has no recorded start: run it through this script first."
        }
        'NewestFile' {
            $f = Get-ChildItem -Path (Join-Path $script:LabRootFull $Arg) -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
            if ($f) { return $f.FullName }
            if ($Preview) { return "<newest lab/$Arg>" }
            throw "no file matches lab/$Arg yet."
        }
        'KpiBaseline' {
            $p = Find-LabKpiBaseline -KpiDirectory (Join-Path $script:LabRootFull 'evidence' 'kpis')
            if ($p) { return $p }
            if ($Preview) { return '<the KPI snapshot labelled baseline>' }
            throw 'no KPI snapshot labelled baseline under lab/evidence/kpis/ (E11, Day 1).'
        }
        'PowerShellOut' { return (Join-Path $script:LabRootFull 'scripts' 'powershell' 'out') }
        default {
            $v = $script:Settings[$Name]
            if (Test-LabDayHasValue $v) {
                if ($v -is [string] -and $v.Contains('{')) { return (Expand-LabDayValue -Value $v -Preview:$Preview -Depth ($Depth + 1)) }
                return $v
            }
            if ($Preview) { return "<$Name>" }
            if ($script:Promptable.ContainsKey($Name)) {
                if (-not $script:StepPrompted.ContainsKey($Name)) { $script:StepPrompted[$Name] = Read-LabOperatorInput -Prompt "  $Name for this step" -Pattern $script:Promptable[$Name] }
                return $script:StepPrompted[$Name]
            }
            throw "setting '$Name' is empty: add it to the settings file (-SettingsPath; -NewSettingsFile writes a template)."
        }
    }
}

function Expand-LabDayValue {
    # Fills {placeholders} in strings, hashtables and arrays. A string that
    # is exactly one placeholder keeps the setting's type (bool, int, array,
    # datetime), so a switch gets $true / $false, never the string "False".
    param([AllowNull()]$Value, [switch]$Preview, [int]$Depth = 0)
    if ($Depth -gt 5) { throw 'placeholders nested more than 5 deep.' }
    if ($null -eq $Value) { return $null }
    $pattern = '\{([A-Za-z][A-Za-z0-9]*)(?::([^{}]+))?\}'
    if ($Value -is [string]) {
        $whole = [regex]::Match($Value, "^$pattern$")
        if ($whole.Success) { return (Resolve-LabDayToken -Name $whole.Groups[1].Value -Arg $whole.Groups[2].Value -Preview:$Preview -Depth $Depth) }
        $sb = [System.Text.StringBuilder]::new()
        $last = 0
        foreach ($m in [regex]::Matches($Value, $pattern)) {
            [void]$sb.Append($Value.Substring($last, $m.Index - $last))
            $r = Resolve-LabDayToken -Name $m.Groups[1].Value -Arg $m.Groups[2].Value -Preview:$Preview -Depth $Depth
            [void]$sb.Append((@($r) | ForEach-Object { [string]$_ }) -join ',')
            $last = $m.Index + $m.Length
        }
        [void]$sb.Append($Value.Substring($last))
        return $sb.ToString()
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $Value.Keys) { $h[$k] = Expand-LabDayValue -Value $Value[$k] -Preview:$Preview -Depth $Depth }
        return $h
    }
    if ($Value -is [System.Collections.IList]) { return , @(foreach ($v in $Value) { Expand-LabDayValue -Value $v -Preview:$Preview -Depth $Depth }) }
    return $Value
}

function Format-LabDayArgument {
    # A parameter hashtable as the command line you would type.
    param([hashtable]$Parameters = @{})
    $parts = foreach ($k in @($Parameters.Keys | Sort-Object)) {
        $v = $Parameters[$k]
        if ($v -is [bool] -or $v -is [switch]) { if ($v) { "-$k" } else { "-$($k):`$false" } }
        elseif ($v -is [System.Collections.IDictionary]) { "-$k @{ " + ((@($v.Keys | Sort-Object) | ForEach-Object { "'$_' = " + ((@($v[$_]) | ForEach-Object { "'$_'" }) -join ',') }) -join '; ') + ' }' }
        elseif ($v -is [System.Collections.IList]) { "-$k " + ((@($v) | ForEach-Object { "'$_'" }) -join ',') }
        elseif ($v -is [datetime]) { "-$k '$($v.ToUniversalTime().ToString('o'))'" }
        elseif ($v -is [int]) { "-$k $v" }
        else { "-$k '$v'" }
    }
    return (@($parts) -join ' ')
}

function Get-LabDayRunParameter {
    # Args + the run's Add, expanded (asks for a prompted value; -Preview never).
    param([Parameter(Mandatory)][hashtable]$PlanStep, [Parameter(Mandatory)][hashtable]$Run, [switch]$Preview)
    $p = @{}
    foreach ($k in $PlanStep.Args.Keys) { $p[$k] = $PlanStep.Args[$k] }
    if ($Run['Add']) { foreach ($k in $Run['Add'].Keys) { $p[$k] = $Run['Add'][$k] } }
    return (Expand-LabDayValue -Value $p -Preview:$Preview)
}

# =============================================================================
# Preflight expectations: what the plan says is on by now
# =============================================================================
function Get-LabDayExpectation {
    <#
    The lab.tfvars flags and CA graduations preflight should expect today:
    the pre-window flags; every step done under this script; every step of
    an earlier day this script never saw (done by hand). A step marked
    skipped, missed, deferred or failed does not count.
    #>
    param([Parameter(Mandatory)][hashtable]$Plan, [Parameter(Mandatory)][int]$ForDay)
    $flags = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $Plan.PreWindowFlags) { if ($f -notin $flags) { $flags.Add($f) } }
    $enforced = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $Plan.Steps) {
        $st = Get-LabDayStatus -Id $s.Id
        $counts = if ($st -eq 'done') { $true } elseif ($st) { $false } else { ($s.Days | Measure-Object -Maximum).Maximum -lt $ForDay }
        if (-not $counts) { continue }
        foreach ($f in $s.Flags) { if ($f -notin $flags) { $flags.Add($f) } }
        foreach ($f in $s.FlagsOff) { [void]$flags.Remove($f) }
        foreach ($c in $s.Enforce) { if ($c -notin $enforced) { $enforced.Add($c) } }
    }
    foreach ($f in @($script:Settings['ExtraExpectedOnFlags']) + @($script:ExtraOnFlags)) { if ($f -and $f -notin $flags) { $flags.Add([string]$f) } }
    foreach ($c in @($script:Settings['ExtraEnforcedPolicies']) + @($script:ExtraEnforced)) { if ($c -and $c -notin $enforced) { $enforced.Add([string]$c) } }
    return @{ Flags = @($flags | Sort-Object); Enforced = @($enforced | Sort-Object) }
}

function Get-LabDayPreflightParameter {
    param([Parameter(Mandatory)][hashtable]$Plan)
    $exp = Get-LabDayExpectation -Plan $Plan -ForDay $Day
    $p = @{}
    if ($script:Settings['OnMicrosoftDomain']) { $p['OnMicrosoftDomain'] = [string]$script:Settings['OnMicrosoftDomain'] }
    if ($exp.Flags.Count) { $p['ExpectedOnFlags'] = $exp.Flags }
    if ($exp.Enforced.Count) { $p['ExpectedEnforcedPolicies'] = $exp.Enforced }
    if ($Day -eq 0) { $p['PreTrial'] = $true }
    return $p
}

# =============================================================================
# Showing a step
# =============================================================================
function Show-LabDayStep {
    param([Parameter(Mandatory)][hashtable]$PlanStep, [int]$Index, [switch]$Preview)
    $st = Get-LabDayStatus -Id $PlanStep.Id
    $tags = @($PlanStep.Kind)
    if ($PlanStep.Optional) { $tags += 'optional' }
    if ($PlanStep.Local) { $tags += 'local apply' }
    if ($PlanStep.Days.Count -gt 1) { $tags += "Days $($PlanStep.Days[0])-$($PlanStep.Days[-1])" }
    $ev = @(Get-LabDayStepEvidence -PlanStep $PlanStep)
    Write-Console ("`n[{0,2}] {1}  ({2}){3}{4}" -f $Index, $PlanStep.Title, ($tags -join ', '), $(if ($ev.Count) { "  evidence: $($ev -join ', ')" } else { '' }), $(if ($st) { "  [$st]" } else { '' })) -ForegroundColor Cyan
    Write-Console "     step id: $($PlanStep.Id)" -ForegroundColor DarkGray
    foreach ($b in $PlanStep.Before) { Write-Console "     first:   $(Expand-LabDayValue -Value $b -Preview)" -ForegroundColor Yellow }
    foreach ($d in $PlanStep.Do) { Write-Console "     do:      $(Expand-LabDayValue -Value $d -Preview)" }
    if ($PlanStep.Flags.Count) { Write-Console "     flag:    $(@($PlanStep.Flags | ForEach-Object { "$_ = true" }) -join ', ')  (lab/terraform/envs/dev/lab.tfvars)" -ForegroundColor Magenta }
    if ($PlanStep.FlagsOff.Count) { Write-Console "     flag:    $(@($PlanStep.FlagsOff | ForEach-Object { "$_ = false" }) -join ', ')  (lab/terraform/envs/dev/lab.tfvars)" -ForegroundColor Magenta }
    if ($PlanStep.Enforce.Count) { Write-Console "     graduate: $(@($PlanStep.Enforce | ForEach-Object { 'ca_policy_states {0} = "enabled"' -f $_ }) -join ', ')" -ForegroundColor Magenta }
    if ($PlanStep.Kind -eq 'pr') {
        $route = if ($PlanStep.Local) { 'the local apply first (as written above), then the PR' } else { 'edit lab.tfvars > push a branch > open the PR > read the plan comment (only this change) > merge > Actions > terraform-apply > Review deployments > approve prod > apply green' }
        Write-Console "     route:   $route" -ForegroundColor DarkGray
    }
    if ($PlanStep.Kind -eq 'script') {
        foreach ($run in $PlanStep.Runs) {
            $params = Get-LabDayRunParameter -PlanStep $PlanStep -Run $run -Preview
            $label = @{ read = 'run'; dry = 'dry run'; real = 'real run (asks you first)' }[[string]$run['Mode']]
            Write-Console "     $($label.PadRight(8)): lab/$($PlanStep.Script) $(Format-LabDayArgument -Parameters $params)"
        }
    }
    if ($PlanStep.Success) { Write-Console "     success: $(Expand-LabDayValue -Value $PlanStep.Success -Preview)" -ForegroundColor Green }
    if ($PlanStep.Note) { Write-Console "     note:    $($PlanStep.Note)" -ForegroundColor Yellow }
    if ($PlanStep.Rollback) { Write-Console "     rollback: $($PlanStep.Rollback)" -ForegroundColor DarkGray }
    if ($Preview -and $ev.Count) {
        foreach ($phase in 'before', 'after') {
            $groups = Get-LabDayCaptureGroup -PlanStep $PlanStep -Phase $phase
            foreach ($g in $groups.Values) {
                $recipes = @($g.Specs | ForEach-Object { $_['Recipe'] })
                if ($phase -eq 'after' -and $PlanStep.Kind -eq 'script' -and $g.Default) { $recipes += 'transcripts' }
                if (-not $recipes.Count) { continue }
                Write-Console "     capture ($phase): $($recipes -join ', ')  ->  lab/evidence/tenant/<UTC day>/$($g.Id)$(if ($g.Part) { "-$($g.Part)" })/" -ForegroundColor DarkCyan
            }
        }
    }
}

function Get-LabDayCaptureGroup {
    # A step's capture specs for one phase, grouped into folders (evidence
    # id + part). The step's own folder (first id, its part) is Default:
    # the script transcripts go there.
    param([Parameter(Mandatory)][hashtable]$PlanStep, [Parameter(Mandatory)][ValidateSet('before', 'after')][string]$Phase)
    $groups = [ordered]@{}
    $ids = @(Get-LabDayStepEvidence -PlanStep $PlanStep)
    if (-not $ids.Count) { return $groups }
    $defaultId = $ids[0]
    $defaultPart = if ($Phase -eq 'before') { 'before' } else { $PlanStep.Part }
    if ($Phase -eq 'after') { $groups["$defaultId|$defaultPart"] = @{ Id = $defaultId; Part = $defaultPart; Default = $true; Specs = [System.Collections.Generic.List[hashtable]]::new() } }
    $specs = if ($Phase -eq 'before') { $PlanStep.CaptureBefore } else { $PlanStep.Capture }
    foreach ($spec in @($specs)) {
        $id = if ($spec['Evidence']) { [string]$spec['Evidence'] } else { $defaultId }
        $part = if ($spec.ContainsKey('Part')) { [string]$spec['Part'] } elseif ($id -eq $defaultId) { $defaultPart } else { '' }
        $key = "$id|$part"
        if (-not $groups.Contains($key)) { $groups[$key] = @{ Id = $id; Part = $part; Default = ($key -eq "$defaultId|$defaultPart"); Specs = [System.Collections.Generic.List[hashtable]]::new() } }
        $groups[$key].Specs.Add($spec)
    }
    return $groups
}

function Show-LabDayCoverage {
    # Close-out: which evidence ids in the plan have no capture-log row yet.
    param([Parameter(Mandatory)][hashtable]$Plan)
    $ids = @(Get-LabCaptureLogId -Path $CaptureLogPath)
    $want = @($Plan.Steps | ForEach-Object { $_.Evidence } | Where-Object { $_ } | Sort-Object -Unique)
    $missing = @($want | Where-Object { $e = $_; -not @($ids | Where-Object { $_ -eq $e -or $_ -like "$e-*" -or $_ -like "$e.*" }).Count })
    if ($missing.Count) { Write-Console "     capture log: $($missing.Count) of $($want.Count) evidence ids have no row yet: $($missing -join ', ') (each needs a capture or a missed row)" -ForegroundColor Yellow }
    else { Write-Console "     capture log: every one of the $($want.Count) evidence ids has a row." -ForegroundColor Green }
}

function Test-LabDayTfvar {
    # After a PR step: does this clone's lab.tfvars show the change?
    param([Parameter(Mandatory)][hashtable]$PlanStep)
    $tf = Read-LabTfvarsState -Path (Join-Path $script:LabRootFull 'terraform' 'envs' 'dev' 'lab.tfvars')
    if (-not $tf) { Write-Warning 'lab/terraform/envs/dev/lab.tfvars not found in this clone: the flag could not be checked.'; return }
    $bad = @()
    foreach ($f in $PlanStep.Flags) { if (-not ($tf.Flags.Contains($f) -and $tf.Flags[$f])) { $bad += "$f = true" } }
    foreach ($f in $PlanStep.FlagsOff) { if ($tf.Flags.Contains($f) -and $tf.Flags[$f]) { $bad += "$f = false" } }
    foreach ($c in $PlanStep.Enforce) { if (-not ($tf.CaStates.Contains($c) -and $tf.CaStates[$c] -eq 'enabled')) { $bad += "$c enabled" } }
    if ($bad.Count) { Write-Warning "This clone's lab.tfvars does not show $($bad -join ', ') yet: pull main after the merge (the pipeline applies what main holds), then check again." }
    elseif ($PlanStep.Flags.Count -or $PlanStep.FlagsOff.Count -or $PlanStep.Enforce.Count) { Write-Console '     lab.tfvars in this clone agrees.' -ForegroundColor Green }
}

# =============================================================================
# Running a step
# =============================================================================
function Invoke-LabDayScript {
    <#
    Runs one lab script in THIS session (so it sees the Graph and az
    sign-ins) from lab/scripts/powershell, where the trial-window commands
    run. With -TranscriptPath its console output is also kept (raw/, private).
    Returns the exit code.
    #>
    param([Parameter(Mandatory)][string]$RelativePath, [hashtable]$Parameters = @{}, [string]$TranscriptPath = '')
    $path = Join-Path $script:LabRootFull $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "script not found: lab/$RelativePath" }
    $global:LASTEXITCODE = 0
    Push-Location -LiteralPath (Join-Path $script:LabRootFull 'scripts' 'powershell')
    try {
        if ($TranscriptPath) { & $path @Parameters *>&1 | Tee-Object -FilePath $TranscriptPath | Out-Host }
        else { & $path @Parameters | Out-Host }
        return [int]$global:LASTEXITCODE
    }
    finally { Pop-Location }
}

function Test-LabDayExitCode {
    param([Parameter(Mandatory)][hashtable]$PlanStep, [Parameter(Mandatory)][int]$Code)
    if ($Code -in $PlanStep.OkExitCodes) { return $true }
    return ($PlanStep.OkExitCodeMax -ge 0 -and $Code -ge 0 -and $Code -le $PlanStep.OkExitCodeMax)
}

function Invoke-LabDayStepWork {
    # The step itself. Returns done | deferred | skipped | missed | quit, or
    # throws (the caller records the failure and stops the day).
    param([Parameter(Mandatory)][hashtable]$PlanStep)
    if ($PlanStep.Optional) {
        $c = Read-LabOperatorChoice -Prompt '     Optional step:' -Choices @('r=run', 's=skip', 'q=quit')
        if ($c -eq 'skip') { return 'skipped' }
        if ($c -eq 'quit') { return 'quit' }
    }
    if ($PlanStep.Kind -ne 'script') {
        if ($PlanStep.Check -eq 'capture-log-coverage') { Show-LabDayCoverage -Plan $script:Plan }
        $c = Read-LabOperatorChoice -Prompt '     When it is done:' -Choices @('d=done', 's=skip', 'm=missed', 'q=quit')
        switch ($c) {
            'done' { if ($PlanStep.Kind -eq 'pr') { Test-LabDayTfvar -PlanStep $PlanStep }; return 'done' }
            'skip' { return 'deferred' }
            'missed' { return 'missed' }
            default { return 'quit' }
        }
    }
    $i = 0
    $stamp = [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    # @(): one evidence id is a bare string and none is $null; .Count on
    # either throws under strict mode.
    $keep = [bool]@(Get-LabDayStepEvidence -PlanStep $PlanStep).Count
    foreach ($run in $PlanStep.Runs) {
        $i++
        $mode = [string]$run['Mode']
        $params = Get-LabDayRunParameter -PlanStep $PlanStep -Run $run
        $line = "lab/$($PlanStep.Script) $(Format-LabDayArgument -Parameters $params)"
        if ($mode -eq 'real') {
            Write-Console "`n     REAL RUN: $line" -ForegroundColor Yellow
            $own = if ($params.ContainsKey('Confirm') -and -not $params['Confirm']) { 'it runs with -Confirm:$false: this answer is its only confirmation' } else { 'its own confirmations still apply' }
            $c = Read-LabOperatorChoice -Prompt "     Run it for real? ($own)" -Choices @('y=yes', 's=skip', 'q=quit')
            if ($c -eq 'skip') { return 'deferred' }
            if ($c -eq 'quit') { return 'quit' }
        }
        else { Write-Console "`n     $(if ($mode -eq 'dry') { 'DRY RUN' } else { 'RUN' }): $line" -ForegroundColor Cyan }
        $transcript = ''
        if ($keep) {
            if (-not (Test-Path -LiteralPath $script:TranscriptDir)) { New-Item -ItemType Directory -Path $script:TranscriptDir -Force | Out-Null }
            $transcript = Join-Path $script:TranscriptDir "$($PlanStep.Id)-$stamp-$i-$mode.log"
        }
        $code = Invoke-LabDayScript -RelativePath $PlanStep.Script -Parameters $params -TranscriptPath $transcript
        if ($transcript) {
            $entry = Get-LabDayEntry -Id $PlanStep.Id
            $entry['transcripts'] = @(@($entry['transcripts']) + $transcript | Where-Object { $_ })
            $script:RunTranscripts += $transcript
        }
        if (-not (Test-LabDayExitCode -PlanStep $PlanStep -Code $code)) { throw "lab/$($PlanStep.Script) ($mode run) exited $code" }
    }
    return 'done'
}

# =============================================================================
# Capturing a step
# =============================================================================
function Invoke-LabDayCapture {
    <#
    Runs a step's capture specs (Phase before = CaptureBefore, after =
    Capture) grouped into one folder per evidence id + part, adds the run
    transcripts to the step's own folder, seals each folder and logs it.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$PlanStep,
        [Parameter(Mandatory)][ValidateSet('before', 'after')][string]$Phase,
        [Parameter(Mandatory)][datetime]$Since,
        [AllowEmptyCollection()][string[]]$Transcripts = @(),
        # -CaptureOnly with an evidence id as -Step: only that id's folders.
        [string]$OnlyEvidence = ''
    )
    $groups = Get-LabDayCaptureGroup -PlanStep $PlanStep -Phase $Phase
    $tx = @($Transcripts | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    # The step's own folder exists only when it has something to hold.
    foreach ($k in @($groups.Keys)) {
        if ((-not $groups[$k].Specs.Count -and -not ($groups[$k].Default -and $tx.Count)) -or ($OnlyEvidence -and $groups[$k].Id -ne $OnlyEvidence)) { $groups.Remove($k) }
    }
    if (-not $groups.Count) { return }

    $required = @(Get-LabCaptureScope -Specs @($groups.Values | ForEach-Object { $_.Specs }))
    $gap = @(Get-LabGraphScopeGap -Required $required)
    if ($gap.Count) { Write-Warning "Graph session: $($gap -join ', ') - those reads will be recorded as failed. Connect-MgGraph (browser) with the scopes -WhatIf lists, then -Day $Day -Step $($PlanStep.Id) -CaptureOnly." }

    foreach ($g in $groups.Values) {
        $ctx = Initialize-LabCapture -EvidenceRoot $EvidenceRoot -Id $g.Id -Part $g.Part -SinceUtc $Since -Settings $script:Settings -LabRoot $script:LabRootFull -Rerun:([bool]$PlanStep.Rerun)
        Write-Console "     capture: $($ctx.DayStamp)/$($ctx.Name)$(if ($ctx.RerunOf) { "  (re-run of $($ctx.RerunOf))" })" -ForegroundColor DarkCyan
        foreach ($spec in $g.Specs) {
            try { $expanded = Expand-LabDayValue -Value $spec }
            catch { $expanded = @{ Recipe = [string]$spec['Recipe']; Name = [string]$spec['Name']; Unresolved = $_.Exception.Message } }
            Invoke-LabCaptureRecipe -Context $ctx -Spec $expanded
        }
        if ($g.Default) { foreach ($t in $tx) { Add-LabCaptureFile -Context $ctx -Path $t } }
        $res = Complete-LabCapture -Context $ctx -Meta @{ labDay = $Day; step = $PlanStep.Id; title = $PlanStep.Title; note = $PlanStep.Note }
        $rel = [System.IO.Path]::GetRelativePath($script:RepoRoot, $res.Dir) -replace '\\', '/'
        if (-not $script:NoLog) {
            $what = $PlanStep.Title
            if ($g.Part) { $what = "$what ($($g.Part))" }
            if ($res.RerunOf) { $what = "re-run of $($res.RerunOf): $what" }
            if ($res.Failed) { $what = "$what [$($res.Failed) of $($res.Items) reads failed: see the manifest]" }
            Add-LabCaptureLogRow -Path $CaptureLogPath -Id $res.Name -Utc ([datetime]::UtcNow) -What $what -Sha256 $res.Sha256 -StoredAt "$rel/" -Public 'manifest' -Operator ([string]$script:Settings['Operator'])
        }
        $entry = Get-LabDayEntry -Id $PlanStep.Id
        $entry['captures'] = @(@($entry['captures']) + "$rel/" | Where-Object { $_ })
        $script:CapturesWritten.Add([pscustomobject]@{ Name = $res.Name; Id = $g.Id; Step = $PlanStep.Id; Rel = $rel; Dir = $res.Dir; Failed = $res.Failed })
        $color = if ($res.Failed) { 'Yellow' } else { 'Green' }
        Write-Console "     sealed:  $rel/  (SHA256SUMS sha256 $($res.Sha256))$(if ($res.Failed) { "  $($res.Failed) read(s) FAILED" })" -ForegroundColor $color
    }
}

function Invoke-LabDayCaptureSafely {
    <#
    Invoke-LabDayCapture, but a capture that breaks (the folder cannot be
    written, a manifest that would carry an identifier, a capture log with
    other columns) is reported and recorded on the step instead of ending
    the run half-way. A read that fails is not a break: it is an item marked
    failed inside a sealed capture. Returns $true when the capture sealed.
    #>
    param([Parameter(Mandatory)][hashtable]$PlanStep, [Parameter(Mandatory)][hashtable]$Entry, [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][datetime]$Since, [AllowEmptyCollection()][string[]]$Transcripts = @(), [string]$OnlyEvidence = '')
    try {
        $null = Invoke-LabDayCapture -PlanStep $PlanStep -Phase $Phase -Since $Since -Transcripts $Transcripts -OnlyEvidence $OnlyEvidence
        $Entry['captureError'] = ''
        return $true
    }
    catch {
        $msg = ConvertTo-LabSafeText -Text $_.Exception.Message
        $Entry['captureError'] = "$($Phase): $msg"
        Write-Console "`nCAPTURE FAILED ($Phase, $($PlanStep.Id)): $msg" -ForegroundColor Red
        return $false
    }
}

function Add-LabDayMissedRow {
    # [m]issed: one capture-log row per evidence id (capture rule 1).
    param([Parameter(Mandatory)][hashtable]$PlanStep)
    if ($script:NoLog) { return }
    $ids = @(Get-LabDayStepEvidence -PlanStep $PlanStep)
    $reason = if ($PlanStep.MissedReason) { $PlanStep.MissedReason } else { $PlanStep.Title }
    for ($k = 0; $k -lt $ids.Count; $k++) {
        $id = if ($k -eq 0 -and $PlanStep.Part) { "$($ids[$k])-$($PlanStep.Part)" } else { $ids[$k] }
        Add-LabCaptureLogRow -Path $CaptureLogPath -Id $id -Utc ([datetime]::UtcNow) -What "missed: $reason" -Operator ([string]$script:Settings['Operator'])
    }
}

# =============================================================================
# MAIN
# =============================================================================
$script:Settings = Read-LabDaySetting -Path $SettingsPath
$script:State = Read-LabDayState -Path $StatePath
$script:Plan = Import-LabDayPlan -Path $PlanPath
$script:RunTranscripts = @()

if ($NewSettingsFile) {
    if (Test-Path -LiteralPath $SettingsPath) { Write-Console "Settings file exists, left as it is: $SettingsPath" -ForegroundColor Yellow; exit 0 }
    if ($PSCmdlet.ShouldProcess($SettingsPath, 'write an empty settings template (names and ids only, never a secret)')) {
        $dir = Split-Path -Parent $SettingsPath
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $template = [ordered]@{ _comment = 'Invoke-LabDay.ps1 settings: names and ids only, NEVER a secret. Gitignored. {OnMicrosoftDomain} / {Domain} are filled in for you.' }
        $defaults = Get-LabDaySettingDefault
        foreach ($k in $defaults.Keys) { $template[$k] = $defaults[$k] }
        ConvertTo-Json -InputObject $template -Depth 5 | Set-Content -LiteralPath $SettingsPath -Encoding utf8NoBOM
        Write-Console "Wrote $SettingsPath - fill it in, then run -Day $Day -WhatIf." -ForegroundColor Green
    }
    exit 0
}

$daySteps = @(Get-LabDayStepFor -Plan $script:Plan -ForDay $Day)
$selected = $daySteps
if ($Step) {
    $selected = @($daySteps | Where-Object { $_.Id -eq $Step -or $Step -in $_.Evidence -or $_.NewCaptureId -eq $Step })
    if (-not $selected.Count) {
        $elsewhere = @($script:Plan.Steps | Where-Object { $_.Id -eq $Step -or $Step -in $_.Evidence -or $_.NewCaptureId -eq $Step } | ForEach-Object { "$($_.Id) (Day $($_.Days -join '/'))" })
        $hint = if ($elsewhere.Count) { "It is on: $($elsewhere -join ', ')." } else { "Day $Day steps: $(@($daySteps | ForEach-Object { $_.Id }) -join ', ')." }
        Write-Console "No step '$Step' on Day $Day. $hint" -ForegroundColor Red
        exit 4
    }
}

$title = if ($script:Plan.Titles.ContainsKey($Day)) { $script:Plan.Titles[$Day] } else { '' }
$allSpecs = @($selected | ForEach-Object { $_.Capture; $_.CaptureBefore } | Where-Object { $_ })
$scopes = @(Get-LabCaptureScope -Specs $allSpecs)

if (-not $PSCmdlet.ShouldProcess("Day $Day ($($selected.Count) step(s))", 'run the trial-window steps: preflight, each change through its own script after its dry run and your yes, read-only captures')) {
    # -WhatIf: the day as it would run. Nothing is called and nothing is written.
    Write-Console "`nDay $Day - $title$(if ($CaptureOnly) { '  (captures only)' })" -ForegroundColor White
    $pf = Get-LabDayPreflightParameter -Plan $script:Plan
    Write-Console "  preflight: lab/scripts/powershell/00-Preflight.ps1 $(Format-LabDayArgument -Parameters $pf)" -ForegroundColor DarkGray
    if ($scopes.Count) { Write-Console "  Graph read scopes for today's captures: Connect-MgGraph -Scopes $($scopes -join ',') -NoWelcome   (browser; never device code)" -ForegroundColor DarkGray }
    $n = 0
    foreach ($s in $selected) { $n++; Show-LabDayStep -PlanStep $s -Index $n -Preview }
    Write-Console "`nCaptures go to $EvidenceRoot/<UTC day>/<evidence id>/ (raw/ private; manifest.json + SHA256SUMS public-safe) and a row in $CaptureLogPath." -ForegroundColor DarkGray
    exit 0
}

$exitCode = 0
try {
    Write-Console "`n=== Day $Day - $title$(if ($CaptureOnly) { '  (captures only)' }) ===" -ForegroundColor White
    if (-not $CaptureOnly) {
        Write-Console 'Every morning: M365 admin center > Billing > Your products: recurring billing Off on every trial. Start DC01 (and the Intune VM once it exists): both deallocate at 19:00 Eastern. Log in to the ServiceNow PDI so it is not reclaimed.' -ForegroundColor DarkYellow
    }
    if ($scopes.Count) { Write-Console "Graph read scopes for today's captures: Connect-MgGraph -Scopes $($scopes -join ',') -NoWelcome   (browser; never device code)" -ForegroundColor DarkGray }

    # 1. Preflight, in this session.
    $pf = Get-LabDayPreflightParameter -Plan $script:Plan
    Write-Console "`n--- Preflight: 00-Preflight.ps1 $(Format-LabDayArgument -Parameters $pf)" -ForegroundColor Cyan
    $pfCode = Invoke-LabDayScript -RelativePath 'scripts/powershell/00-Preflight.ps1' -Parameters $pf
    if ($pfCode -eq 1) {
        $c = Read-LabOperatorChoice -Prompt 'Preflight: ready with warnings. Read them. Go on?' -Choices @('y=yes', 'n=no')
        if ($c -ne 'yes') { Write-Console 'Stopped before the first step.' -ForegroundColor Yellow; exit 1 }
    }
    elseif ($pfCode -ne 0) {
        Write-Console "Preflight: BLOCKED (exit $pfCode). Fix every FAIL, then run the same command again." -ForegroundColor Red
        exit 2
    }

    # 2. The steps.
    $n = 0
    $left = 0
    $worked = 0
    # -Step E17b -CaptureOnly takes only E17b's folders, not the whole step's.
    $onlyEvidence = if ($CaptureOnly -and $Step -and -not @($selected | Where-Object { $_.Id -eq $Step }).Count) { $Step } else { '' }
    foreach ($s in $selected) {
        $n++
        $entry = Get-LabDayEntry -Id $s.Id
        $script:StepPrompted = @{}
        $script:RunTranscripts = @()

        if ($CaptureOnly) {
            # The after-captures only: the before-state is gone once a step ran.
            if (-not @(Get-LabDayStepEvidence -PlanStep $s).Count) { continue }
            if (-not $s.Capture.Count -and -not @($entry['transcripts']).Count) { continue }
            $since = if ($null -ne $SinceUtc) { ([datetime]$SinceUtc).ToUniversalTime() } elseif ($entry['startedUtc']) { ([datetime]$entry['startedUtc']).ToUniversalTime() } else { [datetime]::UtcNow.AddHours(-24) }
            Write-Console "`n[$n] $($s.Title)  (captures since $($since.ToString("yyyy-MM-dd'T'HH:mm'Z'")))" -ForegroundColor Cyan
            $worked++
            $ok = Invoke-LabDayCaptureSafely -PlanStep $s -Entry $entry -Phase 'after' -Since $since -Transcripts @($entry['transcripts']) -OnlyEvidence $onlyEvidence
            if ($ok) { $entry['capturedUtc'] = [datetime]::UtcNow.ToString('o') }
            Save-LabDayState -State $script:State -Path $StatePath
            if (-not $ok) { $exitCode = 3; break }
            continue
        }

        $status = [string]$entry['status']
        if (-not $Step -and ($status -in @('done', 'missed') -or ($status -eq 'skipped' -and $s.Optional))) { continue }

        # A failed or interrupted step resumes as the same attempt: its start
        # (the window its captures read) and its before-capture are kept.
        # Anything else (new, deferred, an explicit -Step) is a new attempt.
        $resume = (-not $Step) -and $status -in @('running', 'failed') -and [bool]$entry['startedUtc']
        if (-not $resume) { $entry['startedUtc'] = [datetime]::UtcNow.ToString('o'); $entry['beforeCapturedUtc'] = '' }
        $worked++
        Show-LabDayStep -PlanStep $s -Index $n
        $started = ([datetime]$entry['startedUtc']).ToUniversalTime()
        if ($resume) { Write-Console "     resuming: this step $status last time (started $($started.ToString("yyyy-MM-dd'T'HH:mm'Z'"))); a script step starts again from its dry run." -ForegroundColor Yellow }
        $entry['status'] = 'running'
        Save-LabDayState -State $script:State -Path $StatePath

        if ($s.CaptureBefore.Count -and -not $entry['beforeCapturedUtc']) {
            if (-not (Invoke-LabDayCaptureSafely -PlanStep $s -Entry $entry -Phase 'before' -Since $started)) {
                $entry['status'] = 'failed'; $entry['error'] = 'the before-capture failed: the step did not run'
                Save-LabDayState -State $script:State -Path $StatePath
                Write-Console 'Nothing ran. Fix it, then run the same command again: it resumes at this step.' -ForegroundColor Red
                $exitCode = 3
                break
            }
            $entry['beforeCapturedUtc'] = [datetime]::UtcNow.ToString('o')
            Save-LabDayState -State $script:State -Path $StatePath
        }

        try { $result = Invoke-LabDayStepWork -PlanStep $s }
        catch {
            $msg = ConvertTo-LabSafeText -Text $_.Exception.Message
            $entry['status'] = 'failed'; $entry['error'] = $msg
            Save-LabDayState -State $script:State -Path $StatePath
            Write-Console "`nFAILED: $($s.Id): $msg" -ForegroundColor Red
            Write-Console "Fix it, then run the same command again: it resumes at this step. (Rollback: $(if ($s.Rollback) { $s.Rollback } else { 'none needed' }))" -ForegroundColor Red
            $exitCode = 3
            break
        }

        switch ($result) {
            'done' {
                # Done first, captures second: a capture that breaks must never
                # make a resume run the change again.
                $entry['status'] = 'done'; $entry['completedUtc'] = [datetime]::UtcNow.ToString('o'); $entry['error'] = ''
                Save-LabDayState -State $script:State -Path $StatePath
                if ($s.Capture.Count -or $script:RunTranscripts.Count) {
                    if (-not (Invoke-LabDayCaptureSafely -PlanStep $s -Entry $entry -Phase 'after' -Since $started -Transcripts $script:RunTranscripts)) {
                        Write-Console "The step itself is done. Fix the cause, then capture it again: -Day $Day -Step $($s.Id) -CaptureOnly" -ForegroundColor Red
                        $exitCode = 3
                    }
                }
            }
            'missed' {
                try { Add-LabDayMissedRow -PlanStep $s; $entry['status'] = 'missed'; $entry['completedUtc'] = [datetime]::UtcNow.ToString('o') }
                catch {
                    $entry['status'] = 'failed'; $entry['error'] = ConvertTo-LabSafeText -Text "the missed row was not written: $($_.Exception.Message)"
                    Write-Console "`nFAILED: $($s.Id): $($entry['error'])" -ForegroundColor Red
                    $exitCode = 3
                }
            }
            'skipped' { $entry['status'] = 'skipped' }
            'deferred' { $entry['status'] = 'deferred'; $left++ }
            default { $entry['status'] = 'deferred' }
        }
        Save-LabDayState -State $script:State -Path $StatePath
        if ($exitCode -eq 3) { break }
        if ($result -eq 'quit') {
            Write-Console "`nStopped at $($s.Id). Run the same command again to carry on from here." -ForegroundColor Yellow
            $exitCode = 1
            break
        }
    }
    if ($exitCode -eq 0 -and $left) { $exitCode = 1; Write-Console "`n$left step(s) left for later: they come back on the next run." -ForegroundColor Yellow }
    if ($exitCode -eq 0 -and -not $worked) {
        if ($CaptureOnly) { Write-Console "`nNothing to capture: no selected step names a capture (or holds a transcript)." -ForegroundColor Yellow }
        else { Write-Console "`nNothing left on Day $($Day): every step is done, missed or a skipped optional step. -Step <id> runs one again." -ForegroundColor Green }
    }
}
finally {
    if ($script:CapturesWritten.Count) {
        Write-Console "`nCaptures written this run ($($script:CapturesWritten.Count)). Same day (capture rule 3), from the repository root, upload each folder to the WORM store:" -ForegroundColor Cyan
        $acct = if ($script:Settings['EvidenceStorageAccount']) { [string]$script:Settings['EvidenceStorageAccount'] } else { '<store>' }
        foreach ($c in $script:CapturesWritten) {
            Write-Console "  az storage blob upload-batch --auth-mode login --overwrite false -d evidence --destination-path captures/$($c.Name) -s $($c.Rel) --account-name $acct" -ForegroundColor DarkGray
        }
        Write-Console 'Then commit each manifest.json + SHA256SUMS and the capture-log rows (raw/ stays out of git: the .gitignore beside it).' -ForegroundColor DarkGray
        foreach ($c in @($script:CapturesWritten | Where-Object { $_.Failed })) {
            # The evidence id takes only its own folders, unless other steps of the day file under it too.
            $id = $c.Id
            $sel = if (@($daySteps | Where-Object { $id -in @(Get-LabDayStepEvidence -PlanStep $_) }).Count -eq 1) { $id } else { $c.Step }
            Write-Console "  $($c.Name): $($c.Failed) read(s) failed. Fix the session (scopes, az login), then: ./Invoke-LabDay.ps1 -Day $Day -Step $sel -CaptureOnly" -ForegroundColor Yellow
        }
    }
}
exit $exitCode
