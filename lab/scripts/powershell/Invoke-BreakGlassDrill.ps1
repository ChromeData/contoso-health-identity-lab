<#
.SYNOPSIS
    Guided break-glass drill: preflight checks, operator-performed sign-ins,
    then evidence that the alert fired, read back from Log Analytics. Writes
    a dated drill record to lab/evidence/drills/ containing only what was
    observed.

.DESCRIPTION
    Automates the checking parts of lab/docs/runbooks/break-glass-drill.md.
    The sign-ins themselves stay human: a script that could sign in as a
    standing Global Admin would be the most dangerous file in the repo.

    PHASES
      Preflight  read-only; refuses to start the drill on any FAIL:
                   1. both break-glass accounts exist (bg-admin-NN), are
                      enabled, are members of Break-Glass-Admins (and on the
                      onmicrosoft.com domain when -OnMicrosoftDomain is given);
                   2. EVERY Conditional Access policy excludes Break-Glass-Admins;
                   3. each account has >= -ExpectedKeysPerAccount USABLE FIDO2
                      keys: the passkey policy targets Break-Glass-Admins and a
                      profile in scope accepts each key's model (AAGUID). A
                      registered key the enforced allow-list blocks is a FAIL -
                      break-glass is FIDO2-only, so it would be locked out
                      (verify: Learn, key restrictions apply to keys already
                      registered);
                   4. the break-glass sign-in rule is deployed AND enabled
                      (Sentinel "contoso-break-glass-signin", or the Log
                      Analytics alert "alert-contoso-break-glass-signin");
                   5. sign-in data reached the workspace in the last 24 h
                      (WARN: no data, no alert).
      Verify     after the operator's sign-ins: polls Log Analytics for the
                 break-glass sign-ins since -DrillStartUtc, the alerts / incidents
                 the rule raised, and any audit operation the break-glass
                 accounts initiated; re-runs the preflight (runbook step 7);
                 writes the record.
      All        (default) Preflight, then prompts the operator through each
                 sign-in, then Verify.

    WHAT THE RECORD SAYS - AND DOES NOT
      * Observed: sign-in rows (time, result, method), alert/incident times,
        sign-in -> alert minutes, incident numbers, audit operation count.
      * Operator-declared, labelled as such: which key label was used (the
        logs do not say which physical key), operator/reviewer initials,
        change ticket.
      * Not checked by this script, left null for the operator: Teams card,
        ServiceNow INC, Splunk alert (fill them in the drill log by hand).
      * Result: Pass = every declared sign-in seen in the logs and alerted;
        Partial = some sign-in not seen or not alerted; Fail = no alert for
        any break-glass sign-in (runbook: Sev 2).
    The public record (lab/evidence/drills/) holds account SHORT names, key
    labels, times and ticket numbers only - no UPN domain, IP, object id or
    tenant name (lab/evidence/drills/README.md). The full observation (UPNs,
    IPs, correlation ids) goes to the gitignored lab/evidence/out/drills/.

.PREREQUISITES
    * Graph roles: Global Reader + Authentication Administrator (read FIDO2
      methods); Graph scopes below.
    * az CLI signed in with Reader on the resource group and Log Analytics
      Reader on the workspace (+ Microsoft Sentinel Reader on the Sentinel path).
    * A change ticket opened BEFORE the drill (runbook) - pass it as -ChangeTicket.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated, READ-ONLY)
    User.Read.All, GroupMember.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All

    APP-ONLY (-UseAzureCliToken): the Graph token is taken from the Azure CLI
    session, which is already signed in as an app - in the lab, the lab
    operator through `lab/scripts/operator/op pwsh ...` (ADR 0024). The app's
    APPLICATION permissions must cover the four above: a ReadWrite role covers
    its Read, and Directory.Read.All covers User.Read.All and
    GroupMember.Read.All (Get-MissingGraphScope; the operator holds
    User.ReadWrite.All, GroupMember.ReadWrite.All, Directory.Read.All,
    Policy.Read.All and UserAuthenticationMethod.ReadWrite.All). The script
    still only READS. App-only refuses -Phase All, which prompts a person
    through each sign-in: run Preflight, do the sign-ins, then Verify.
    (Learn, permissions reference: the Read.All application permissions are
    included in their ReadWrite.All counterparts; Directory.Read.All reads
    users, groups and memberships.)

.PARAMETER Phase
    Preflight | Verify | All (default).

.PARAMETER DrillStartUtc
    Verify only: when the drill started (the Preflight phase prints it).

.PARAMETER DeclaredSignIns
    Verify only: what the operator did, as 'bg-admin-01:key 1','bg-admin-01:key 2',...
    (All collects these interactively).

.PARAMETER WaitMinutes
    How long Verify polls for alerts. Default 30 (ingestion lag is 5-15 min,
    the rule runs every 5 min).

.EXAMPLE
    ./Invoke-BreakGlassDrill.ps1 -OnMicrosoftDomain 'contosohealthlab.onmicrosoft.com' -ChangeTicket 'CHG0001234' -Operator 'MW' -Reviewer 'GM'

.EXAMPLE
    lab/scripts/operator/op pwsh -NoProfile -File lab/scripts/powershell/Invoke-BreakGlassDrill.ps1 -Phase Preflight -UseAzureCliToken -ExpectedKeysPerAccount 1
    # Lab, app-only as the lab operator. The lab holds ONE software passkey per
    # break-glass account (lab/docs/runbooks/break-glass-drill.md, lab deviation),
    # hence -ExpectedKeysPerAccount 1.

.EXAMPLE
    ./Invoke-BreakGlassDrill.ps1 -Phase Preflight
    # ... sign-ins ...
    ./Invoke-BreakGlassDrill.ps1 -Phase Verify -DrillStartUtc '2026-11-02T14:00:00Z' `
        -DeclaredSignIns 'bg-admin-01:key 1','bg-admin-01:key 2','bg-admin-02:key 1','bg-admin-02:key 2' -ChangeTicket 'CHG0001234'

.NOTES
    TENANT-TIME: never run - no tenant, no workspace yet. Nothing in
    lab/evidence/drills/ may be cited until this script (or the runbook by
    hand) has produced a record from a real drill.
    verify: SecurityAlert.AlertName equals the analytics rule display name.
    verify: Sentinel alertRules api-version 2023-02-01 and scheduledQueryRules
      api-version 2021-08-01 return properties.enabled.
    verify: Alerts Management list (api-version 2019-05-05-preview) filtered by
      alertRule returns the log-alert firings.
    verify: `az rest --resource https://api.loganalytics.io` gets a token for
      the Log Analytics query API.
    verify: AuthenticationDetails[].authenticationMethod names a passkey /
      FIDO2 sign-in ("Passkey (device-bound)" / "FIDO2 security key").

.WHAT IT DEMONSTRATES
    Treating emergency access as an operated control: preconditions verified
    by code, the human step kept human, and the evidence of detection pulled
    from the SIEM rather than asserted.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidateSet('Preflight', 'Verify', 'All')]
    [string]$Phase = 'All',

    [Parameter()]
    [ValidatePattern('^$|^[A-Za-z0-9-]+\.onmicrosoft\.com$', ErrorMessage = 'OnMicrosoftDomain must look like <tenant>.onmicrosoft.com')]
    [string]$OnMicrosoftDomain = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidateRange(1, 5)]
    [int]$ExpectedKeysPerAccount = 2,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup = 'rg-identity-lab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName = 'loga-idlab',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    # modules/monitoring: Sentinel rule name "contoso-break-glass-signin", LA
    # alert "alert-contoso-break-glass-signin", both with this display name.
    [string]$RuleDisplayName = 'Contoso - Break-glass account sign-in (any)',

    [Parameter()]
    [Nullable[datetime]]$DrillStartUtc = $null,

    [Parameter()]
    [ValidatePattern('^bg-admin-\d{2}:[A-Za-z0-9 _-]{1,20}$', ErrorMessage = "Use 'bg-admin-NN:<key label>', e.g. 'bg-admin-01:key 1'.")]
    [string[]]$DeclaredSignIns = @(),

    [Parameter()]
    # Public record: initials and ticket numbers only - no emails or names.
    [ValidatePattern('^$|^[A-Za-z0-9 ._-]{1,32}$', ErrorMessage = 'Initials / ticket numbers only (no @, no full names).')]
    [string]$Operator = '',

    [Parameter()]
    [ValidatePattern('^$|^[A-Za-z0-9 ._-]{1,32}$', ErrorMessage = 'Initials / ticket numbers only (no @, no full names).')]
    [string]$Reviewer = '',

    [Parameter()]
    [ValidatePattern('^$|^[A-Za-z0-9._-]{1,32}$', ErrorMessage = 'A ticket number such as CHG0001234.')]
    [string]$ChangeTicket = '',

    [Parameter()]
    [ValidateRange(0, 240)]
    [int]$WaitMinutes = 30,

    [Parameter()]
    [ValidateRange(15, 600)]
    [int]$PollSeconds = 60,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'drills'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PrivateDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'drills'),

    [Parameter()]
    # App-only: Microsoft Graph token from the Azure CLI session (see .GRAPH SCOPES).
    [switch]$UseAzureCliToken
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
# PURE FUNCTIONS (unit-tested in tests/Invoke-BreakGlassDrill.Tests.ps1)
# =============================================================================
function Get-ShortName {
    # 'bg-admin-01@tenant.onmicrosoft.com' -> 'bg-admin-01'. Anything else -> $null.
    param([string]$UserPrincipalName)
    if ($UserPrincipalName -match '(?i)^(bg-admin-\d{2})@') { return $Matches[1].ToLowerInvariant() }
    return $null
}

function ConvertFrom-LaTable {
    # Log Analytics query API response -> objects (first table).
    param($Response)
    $t = @($Response.tables)[0]
    if (-not $t) { return @() }
    $cols = @($t.columns)
    foreach ($row in @($t.rows)) {
        $o = [ordered]@{}
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $v = @($row)[$i]
            # The query API returns `dynamic` columns as JSON text (verify);
            # parse arrays/objects so e.g. Accounts / AlertIds are real lists.
            if ([string]$cols[$i].type -eq 'dynamic' -and $v -is [string] -and $v -match '^\s*[\[{]') {
                try { $v = $v | ConvertFrom-Json -NoEnumerate } catch { Write-Verbose "column $($cols[$i].name): kept as text ($($_.Exception.Message))" }
            }
            $o[[string]$cols[$i].name] = $v
        }
        [pscustomobject]$o
    }
}

function Get-DrillAssessment {
    # Declared: objects Account, KeyLabel. SignIns: observed rows (Account,
    # TimeGenerated, ResultType, Methods). Alerts: observed firings (TimeUtc,
    # Accounts = short names, or empty when the alert path is rule-wide).
    # Each declared sign-in is matched to the earliest unused observed sign-in
    # for that account, in declaration order.
    param(
        [object[]]$Declared,
        [AllowEmptyCollection()][object[]]$SignIns = @(),
        [AllowEmptyCollection()][object[]]$Alerts = @(),
        [AllowEmptyCollection()][object[]]$Incidents = @(),
        [bool]$AlertsCarryAccounts = $true
    )
    $used = [System.Collections.Generic.HashSet[int]]::new()
    $obs = @($SignIns | Sort-Object { [datetime]$_.TimeGenerated })
    $rows = foreach ($d in @($Declared)) {
        $match = $null
        for ($i = 0; $i -lt $obs.Count; $i++) {
            if (-not $used.Contains($i) -and $obs[$i].Account -eq $d.Account) { $match = $obs[$i]; [void]$used.Add($i); break }
        }
        $alert = $null
        if ($match) {
            $t = ([datetime]$match.TimeGenerated).ToUniversalTime()
            $alert = @($Alerts | Where-Object {
                    ([datetime]$_.TimeUtc).ToUniversalTime() -ge $t.AddMinutes(-1) -and
                    (-not $AlertsCarryAccounts -or @($_.Accounts) -contains $d.Account)
                } | Sort-Object { [datetime]$_.TimeUtc }) | Select-Object -First 1
        }
        $incident = if ($alert -and $alert.PSObject.Properties['AlertId']) { @($Incidents | Where-Object { @($_.AlertIds) -contains $alert.AlertId }) | Select-Object -First 1 } else { $null }
        [pscustomobject]@{
            account               = $d.Account
            keyLabel              = $d.KeyLabel
            keyLabelSource        = 'operator-declared'
            observedInLogs        = [bool]$match
            signInUtc             = $(if ($match) { ([datetime]$match.TimeGenerated).ToUniversalTime().ToString('o') } else { $null })
            signInResultType      = $(if ($match) { [string]$match.ResultType } else { $null })
            signInMethods         = $(if ($match) { [string]$match.Methods } else { $null })
            alertObserved         = [bool]$alert
            alertUtc              = $(if ($alert) { ([datetime]$alert.TimeUtc).ToUniversalTime().ToString('o') } else { $null })
            signInToAlertMinutes  = $(if ($alert) { [math]::Round((([datetime]$alert.TimeUtc).ToUniversalTime() - ([datetime]$match.TimeGenerated).ToUniversalTime()).TotalMinutes, 1) } else { $null })
            incidentNumber        = $(if ($incident) { [string]$incident.IncidentNumber } else { $null })
            signInToIncidentMinutes = $(if ($incident -and $incident.PSObject.Properties['CreatedTime'] -and $incident.CreatedTime) { [math]::Round((([datetime]$incident.CreatedTime).ToUniversalTime() - ([datetime]$match.TimeGenerated).ToUniversalTime()).TotalMinutes, 1) } else { $null })
        }
    }
    $rows = @($rows)
    $reasons = @()
    $notSeen = @($rows | Where-Object { -not $_.observedInLogs })
    $notAlerted = @($rows | Where-Object { $_.observedInLogs -and -not $_.alertObserved })
    if ($notSeen.Count) { $reasons += "$($notSeen.Count) declared sign-in(s) not found in the sign-in logs" }
    if ($notAlerted.Count) { $reasons += "$($notAlerted.Count) observed sign-in(s) with no alert" }
    $anyAlert = @($rows | Where-Object alertObserved).Count -gt 0
    $result = if ($rows.Count -eq 0) { 'Fail' }
    elseif (-not $anyAlert -and @($rows | Where-Object observedInLogs).Count -gt 0) { 'Fail' }
    elseif ($notSeen.Count -or $notAlerted.Count) { 'Partial' }
    else { 'Pass' }
    if ($rows.Count -eq 0) { $reasons += 'no sign-ins were declared' }
    elseif ($result -eq 'Fail' -and @($rows | Where-Object observedInLogs).Count) { $reasons += 'no alert fired for any break-glass sign-in (runbook: Sev 2 defect)' }
    elseif ($result -eq 'Fail') { $reasons += 'none of the declared sign-ins reached the workspace' }
    return [pscustomobject]@{ Result = $result; Reasons = $reasons; SignIns = $rows }
}

function Get-PendingIncident {
    # Sentinel path only: the accounts whose sign-in was alerted but has no
    # incident number yet (Log Analytics alerts raise no incident). Pure.
    param($Assessment, [string]$AlertPath)
    if ($AlertPath -ne 'sentinel' -or -not $Assessment) { return @() }
    return @(@($Assessment.SignIns) | Where-Object { $_.alertObserved -and -not $_.incidentNumber } | ForEach-Object { [string]$_.account })
}

function Test-PublicRecordSafe {
    # The public drill log must not carry an email/UPN, IP address, GUID or
    # onmicrosoft domain (lab/evidence/drills/README.md). Emits the offending
    # strings (call it inside @()); nothing = safe.
    param([string]$Json)
    $bad = @()
    foreach ($p in '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+', '\b\d{1,3}(\.\d{1,3}){3}\b', '\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b', '(?i)onmicrosoft\.com', '(?i)\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){4,7}\b') {
        foreach ($m in [regex]::Matches($Json, $p)) { $bad += $m.Value }
    }
    return @($bad | Sort-Object -Unique)
}

function Get-MissingGraphScope {
    # Required Graph permissions the current context does not cover, for the
    # "does not list" warning. An app-only identity (-UseAzureCliToken, e.g.
    # the lab operator) often holds the ReadWrite role, not the Read one a
    # delegated admin consents to. Microsoft Learn's permission tables list
    # X.ReadWrite.Y as a higher-privileged permission wherever X.Read.Y is the
    # least privileged one, and Directory.Read.All for the user, group,
    # membership and application reads (checked 2026-11-05 on "List
    # applications" and "List group transitive members"). Empty -Have
    # (unknown context) = no warning. Identical in 06-NHI-Inventory.ps1,
    # 08-Measure-KPIs.ps1, 09-SoD-Report.ps1 and Invoke-BreakGlassDrill.ps1
    # (parity test in tests/EvidencePackPipeline.Tests.ps1).
    param([AllowEmptyCollection()][string[]]$Have = @(), [Parameter(Mandatory)][string[]]$Required)
    if (-not @($Have | Where-Object { $_ })) { return @() }
    $directoryCovers = @('User.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Application.Read.All')
    $hasDirectory = ('Directory.Read.All' -in $Have) -or ('Directory.ReadWrite.All' -in $Have)
    return @($Required | Where-Object {
            ($_ -notin $Have) -and (($_ -replace '\.Read\.', '.ReadWrite.') -notin $Have) -and
            -not ($hasDirectory -and $_ -in $directoryCovers)
        })
}

# =============================================================================
# I/O HELPERS
# =============================================================================
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

function Connect-GraphFromAzureCli {
    # App-only: the Azure CLI is already signed in as an app (azure/login over
    # GitHub OIDC, or the lab operator's certificate through
    # lab/scripts/operator/op). The token never leaves this process: masked in
    # Actions, handed to Connect-MgGraph as a SecureString, then dropped. Same
    # as mock-hr/Invoke-InboundProvisioning.ps1, through Write-Console for the
    # analyzer; every lab/scripts/powershell copy is identical (parity test in
    # tests/EvidencePackPipeline.Tests.ps1).
    $global:LASTEXITCODE = 0
    $token = az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$token)) {
        throw 'No Microsoft Graph token from the Azure CLI. Sign it in first (azure/login with OIDC in GitHub Actions, or az login locally).'
    }
    $token = ([string]$token).Trim()
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Console "::add-mask::$token" }
    # NetworkCredential.SecurePassword: the same SecureString as
    # ConvertTo-SecureString -AsPlainText, without the analyzer error rule.
    Connect-MgGraph -AccessToken ([System.Net.NetworkCredential]::new('', $token).SecurePassword) -NoWelcome | Out-Null
    Remove-Variable -Name token
}

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

function Invoke-AzJson {
    # Runs az, returns parsed JSON. -AllowNotFound turns a 404 into $null
    # (a rule that is not deployed is an answer, not an error).
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

function Invoke-LaQuery {
    # Log Analytics query API through az rest; the body goes via a 0600 temp
    # file so the KQL is not mangled by native-argument quoting.
    param([Parameter(Mandatory)][string]$WorkspaceCustomerId, [Parameter(Mandatory)][string]$Query)
    $tmp = New-TemporaryFile
    try {
        @{ query = $Query } | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp.FullName -Encoding utf8NoBOM
        $resp = Invoke-AzJson -Arguments @('rest', '--method', 'post', '--url', "https://api.loganalytics.io/v1/workspaces/$WorkspaceCustomerId/query",
            '--resource', 'https://api.loganalytics.io', '--body', "@$($tmp.FullName)")
        return @(ConvertFrom-LaTable $resp)
    }
    finally { Remove-Item -LiteralPath $tmp.FullName -Force -ErrorAction SilentlyContinue }
}

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Check, [ValidateSet('PASS', 'WARN', 'FAIL')][string]$Status, [string]$Detail)
    $checks.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
    Write-Host ("  [{0}] {1} - {2}" -f $Status, $Check, $Detail) -ForegroundColor @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$Status]
}

# =============================================================================
# CONNECT (Graph + az)
# =============================================================================
$requiredScopes = @('User.Read.All', 'GroupMember.Read.All', 'Policy.Read.All', 'UserAuthenticationMethod.Read.All')
if ($UseAzureCliToken) {
    # -Phase All stops at Read-Host for each sign-in: a person's flow, not an
    # app's. App-only runs Preflight, then the sign-ins, then Verify.
    if ($Phase -eq 'All') { throw '-UseAzureCliToken runs -Phase Preflight or -Phase Verify only (-Phase All prompts a person through each sign-in).' }
    # Always this identity, never a leftover delegated context.
    Write-Console 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
    Connect-GraphFromAzureCli
}
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) {
    if ($UseAzureCliToken) { throw 'No Microsoft Graph context after the app-only sign-in.' }
    Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext
}
$missingScopes = @(Get-MissingGraphScope -Have @($ctx.Scopes) -Required $requiredScopes)
if ($missingScopes) { Write-Warning "Current Graph context does not cover: $($missingScopes -join ', '). Checks needing them will FAIL." }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'az CLI not found; the alert checks need it (az login first).' }
$subId = [string](Invoke-AzJson -Arguments @('account', 'show', '--query', 'id'))
$ws = Invoke-AzJson -Arguments @('monitor', 'log-analytics', 'workspace', 'show', '-g', $ResourceGroup, '-n', $WorkspaceName)
$wsCustomerId = [string]$ws.customerId
$sentinelRuleUri = "https://management.azure.com$($ws.id)/providers/Microsoft.SecurityInsights/alertRules/contoso-break-glass-signin?api-version=2023-02-01"
$laRuleId = "/subscriptions/$subId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/scheduledQueryRules/alert-contoso-break-glass-signin"

# =============================================================================
# PREFLIGHT (read-only)
# =============================================================================
function Invoke-Preflight {
    # Script parameters are passed in explicitly so the function's inputs are visible.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$GroupMailNickname, [string]$Domain, [int]$KeysPerAccount)
    $script:checks.Clear()
    $ctxOut = [pscustomobject]@{ AlertPath = $null; KeyCounts = [ordered]@{} }

    Write-Host "`n[1/5] Break-glass accounts" -ForegroundColor Cyan
    $f = [uri]::EscapeDataString("mailNickname eq '$GroupMailNickname'")
    $bgGroup = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id") | Select-Object -First 1
    if (-not $bgGroup) { Add-Check 'Break-Glass-Admins' 'FAIL' 'group not found (Terraform enable_premium)'; return $ctxOut }
    $bgGroupId = [string]$bgGroup['id']
    $memberIds = @(Get-GraphCollection -Uri "$graph/groups/$bgGroupId/members?`$select=id" | ForEach-Object { [string]$_['id'] })
    $uf = [uri]::EscapeDataString("startswith(mailNickname,'bg-admin-')")
    $bgUsers = @(Get-GraphCollection -Uri "$graph/users?`$filter=$uf&`$select=id,userPrincipalName,accountEnabled")
    if ($bgUsers.Count -lt 2) { Add-Check 'Account count' 'FAIL' "found $($bgUsers.Count); two are required" } else { Add-Check 'Account count' 'PASS' "$($bgUsers.Count) accounts" }
    foreach ($u in $bgUsers) {
        $short = Get-ShortName ([string]$u['userPrincipalName'])
        $problems = @()
        if (-not $short) { $problems += 'UPN does not follow bg-admin-NN@' }
        if ($u['accountEnabled'] -eq $false) { $problems += 'disabled' }
        if ([string]$u['id'] -notin $memberIds) { $problems += 'not in Break-Glass-Admins' }
        if ($Domain -and -not ([string]$u['userPrincipalName']).ToLowerInvariant().EndsWith("@$($Domain.ToLowerInvariant())")) { $problems += 'not on the onmicrosoft.com domain' }
        if ($problems) { Add-Check "Account $short" 'FAIL' ($problems -join '; ') } else { Add-Check "Account $short" 'PASS' 'enabled, in Break-Glass-Admins' }
    }

    Write-Host "`n[2/5] Excluded from every Conditional Access policy" -ForegroundColor Cyan
    $policies = @(Get-GraphCollection -Uri "$graph/identity/conditionalAccess/policies")
    $notExcluded = @($policies | Where-Object { $bgGroupId -notin @($_['conditions']['users']['excludeGroups']) })
    if ($policies.Count -eq 0) { Add-Check 'CA exclusion' 'WARN' 'no CA policies found' }
    elseif ($notExcluded.Count) { Add-Check 'CA exclusion' 'FAIL' "$($notExcluded.Count) of $($policies.Count) policies do NOT exclude Break-Glass-Admins: $(@($notExcluded | ForEach-Object { $_['displayName'] }) -join '; ')" }
    else { Add-Check 'CA exclusion' 'PASS' "all $($policies.Count) policies exclude Break-Glass-Admins" }

    Write-Host "`n[3/5] FIDO2 keys and passkey policy" -ForegroundColor Cyan
    $fido2 = Invoke-MgGraphRequest -Method GET -Uri "$graph/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2" -OutputType HashTable
    $targeted = [string]$fido2['state'] -eq 'enabled' -and @(@($fido2['includeTargets']) | Where-Object { $_ -and ([string]$_['id'] -eq $bgGroupId -or [string]$_['id'] -eq 'all_users') }).Count -gt 0
    if ($targeted) { Add-Check 'Passkey policy' 'PASS' 'enabled for Break-Glass-Admins' } else { Add-Check 'Passkey policy' 'FAIL' 'passkeys not enabled for Break-Glass-Admins (post-apply/Set-AuthenticationMethodsPolicy.ps1 -Apply)' }
    foreach ($u in $bgUsers) {
        $short = Get-ShortName ([string]$u['userPrincipalName'])
        if (-not $short) { continue }   # already a FAIL in [1/5]
        try {
            $keys = @(Get-GraphCollection -Uri "$graph/users/$($u['id'])/authentication/fido2Methods")
            $cov = Test-PasskeyCoverage -Fido2Config $fido2 -GroupIds @($bgGroupId) -Keys $keys
            $ctxOut.KeyCounts[$short] = $cov.AcceptedKeys
            if ($cov.RejectedAaguids.Count) { Add-Check "Keys $short" 'FAIL' "$($cov.RejectedAaguids.Count) registered key(s) of a model the enforced allow-list blocks ($(@($cov.RejectedAaguids | Sort-Object -Unique) -join ', ')): break-glass is FIDO2-only - add the model to the admin allow-list or re-key first" }
            elseif ($cov.AcceptedKeys -ge $KeysPerAccount) { Add-Check "Keys $short" 'PASS' "$($cov.AcceptedKeys) usable FIDO2 key(s)" }
            elseif ($cov.AcceptedKeys -gt 0) { Add-Check "Keys $short" 'WARN' "$($cov.AcceptedKeys) usable key(s); the standard is $KeysPerAccount (one per safe)" }
            elseif ($keys.Count -gt 0) { Add-Check "Keys $short" 'FAIL' "$($keys.Count) key(s) registered but none usable: $($cov.Reason)" }
            else { Add-Check "Keys $short" 'FAIL' 'no FIDO2 key registered (human step 6)' }
        }
        catch { Add-Check "Keys $short" 'FAIL' "could not read FIDO2 methods: $($_.Exception.Message)" }
    }

    Write-Host "`n[4/5] Break-glass sign-in rule" -ForegroundColor Cyan
    $sentinel = Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url', $sentinelRuleUri) -AllowNotFound
    $la = Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url', "https://management.azure.com$laRuleId`?api-version=2021-08-01") -AllowNotFound
    if ($sentinel -and $sentinel.properties.enabled) { $ctxOut.AlertPath = 'sentinel'; Add-Check 'Alert rule' 'PASS' "Sentinel rule '$($sentinel.properties.displayName)' enabled" }
    elseif ($la -and $la.properties.enabled) { $ctxOut.AlertPath = 'log-analytics'; Add-Check 'Alert rule' 'PASS' "Log Analytics alert '$($la.properties.displayName)' enabled" }
    elseif ($sentinel -or $la) { Add-Check 'Alert rule' 'FAIL' 'the rule exists but is DISABLED - the drill would prove nothing' }
    else { Add-Check 'Alert rule' 'FAIL' 'no break-glass rule deployed (Terraform enable_sentinel or enable_la_alerts)' }

    Write-Host "`n[5/5] Sign-in data in the workspace" -ForegroundColor Cyan
    try {
        $n = @(Invoke-LaQuery -WorkspaceCustomerId $wsCustomerId -Query 'SigninLogs | where TimeGenerated > ago(1d) | count')
        $cnt = if ($n.Count) { [int]$n[0].Count } else { 0 }
        if ($cnt -gt 0) { Add-Check 'SigninLogs ingestion' 'PASS' "$cnt sign-in row(s) in the last 24 h" }
        else { Add-Check 'SigninLogs ingestion' 'WARN' 'no SigninLogs rows in 24 h - check Entra diagnostic settings; the alert cannot fire without data' }
    }
    catch { Add-Check 'SigninLogs ingestion' 'FAIL' "query failed: $($_.Exception.Message)" }
    return $ctxOut
}

# =============================================================================
# VERIFY (read-only queries + the record)
# =============================================================================
function Get-DrillObservation {
    param([datetime]$StartUtc, [string]$AlertPath, [string]$RuleName)
    $start = $StartUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $kqlSignIns = @"
union (SigninLogs | extend SignInType = "interactive"),
      (AADNonInteractiveUserSignInLogs | extend SignInType = "non-interactive")
| where TimeGenerated >= datetime($start)
| where UserPrincipalName matches regex @"(?i)^bg-admin-\d{2}@"
| extend AD = parse_json(tostring(AuthenticationDetails))
| mv-apply d = AD on (summarize Methods = make_set(tostring(d.authenticationMethod)))
| project TimeGenerated, UserPrincipalName, SignInType, ResultType, Methods = strcat_array(Methods, "; "), IPAddress, CorrelationId
| sort by TimeGenerated asc
"@
    $signIns = @(Invoke-LaQuery -WorkspaceCustomerId $wsCustomerId -Query $kqlSignIns | ForEach-Object {
            $_ | Add-Member -NotePropertyName Account -NotePropertyValue (Get-ShortName ([string]$_.UserPrincipalName)) -PassThru
        })
    $alerts = @(); $incidents = @(); $carry = $true
    if ($AlertPath -eq 'sentinel') {
        $name = $RuleName.Replace('"', '\"')
        $alerts = @(Invoke-LaQuery -WorkspaceCustomerId $wsCustomerId -Query @"
SecurityAlert
| where TimeGenerated >= datetime($start) and AlertName == "$name"
| extend Accounts = extract_all(@"(?i)\b(bg-admin-\d{2})@", tostring(Entities))
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project TimeUtc = TimeGenerated, AlertId = SystemAlertId, Accounts
"@ | ForEach-Object { $_.Accounts = @(@($_.Accounts) | ForEach-Object { ([string]$_).ToLowerInvariant() }); $_ })
        $incidents = @(Invoke-LaQuery -WorkspaceCustomerId $wsCustomerId -Query @"
SecurityIncident
| where CreatedTime >= datetime($start) and Title == "$name"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project IncidentNumber, CreatedTime, Status, AlertIds
"@)
    }
    elseif ($AlertPath -eq 'log-analytics') {
        # Log alerts are rule-wide (no per-account entities) and muted for an
        # hour after firing, so one firing can cover several sign-ins.
        $carry = $false
        $resp = Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url',
            "https://management.azure.com/subscriptions/$subId/providers/Microsoft.AlertsManagement/alerts?api-version=2019-05-05-preview&alertRule=$([uri]::EscapeDataString($laRuleId))&timeRange=1d")
        $alerts = @(@($resp.value) | Where-Object { $_ -and ([datetime]$_.properties.essentials.startDateTime).ToUniversalTime() -ge $StartUtc.ToUniversalTime() } |
            ForEach-Object { [pscustomobject]@{ TimeUtc = $_.properties.essentials.startDateTime; Accounts = @() } })
    }
    $audit = @(Invoke-LaQuery -WorkspaceCustomerId $wsCustomerId -Query @"
AuditLogs
| where TimeGenerated >= datetime($start)
| where tostring(InitiatedBy.user.userPrincipalName) matches regex @"(?i)^bg-admin-\d{2}@"
| summarize Operations = count()
"@)
    return [pscustomobject]@{
        SignIns = $signIns; Alerts = $alerts; Incidents = $incidents; AlertsCarryAccounts = $carry
        AuditOperations = $(if ($audit.Count) { [int]$audit[0].Operations } else { 0 })
    }
}

# =============================================================================
# RUN
# =============================================================================
$pre = $null
if ($Phase -in 'Preflight', 'All') {
    $pre = Invoke-Preflight -GroupMailNickname $BreakGlassGroupMailNickname -Domain $OnMicrosoftDomain -KeysPerAccount $ExpectedKeysPerAccount
    $preflightChecks = @($checks.ToArray())
    $fails = @($preflightChecks | Where-Object Status -eq 'FAIL').Count
    if ($fails) {
        Write-Console "`nPreflight: $fails FAIL - do NOT start the drill. Fix, then re-run." -ForegroundColor Red
        exit 1
    }
    Write-Console "`nPreflight passed. Alert path: $($pre.AlertPath)." -ForegroundColor Green
    if ($Phase -eq 'Preflight') {
        $start = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Write-Console "Start the drill now. Then: ./Invoke-BreakGlassDrill.ps1 -Phase Verify -DrillStartUtc '$start' -DeclaredSignIns 'bg-admin-01:key 1',... -ChangeTicket <CHG>" -ForegroundColor Cyan
        exit 0
    }
}
else { $preflightChecks = @() }

if ($Phase -eq 'All') {
    $DrillStartUtc = (Get-Date).ToUniversalTime()
    Write-Console "`nDRILL START $($DrillStartUtc.ToString('u')). Runbook: lab/docs/runbooks/break-glass-drill.md" -ForegroundColor Cyan
    Write-Console 'Private browser window -> Entra admin center. Look, do not change. Sign out after each sign-in.' -ForegroundColor Cyan
    $plan = foreach ($acct in @($pre.KeyCounts.Keys | Sort-Object)) { for ($k = 1; $k -le [math]::Max(1, [int]$pre.KeyCounts[$acct]); $k++) { "${acct}:key $k" } }
    $decl = @()
    foreach ($p in $plan) {
        $answer = Read-Host "Sign in as $($p.Split(':')[0]) with $($p.Split(':')[1]). Press Enter when done, or type 'skip'"
        if ($answer -ne 'skip') { $decl += $p }
    }
    $DeclaredSignIns = $decl
}
if (-not $DrillStartUtc) { throw '-DrillStartUtc is required for -Phase Verify (the Preflight phase prints it).' }
if (-not $DeclaredSignIns) { Write-Warning 'No declared sign-ins: the record will say Fail (nothing to verify).' }
$declared = @($DeclaredSignIns | ForEach-Object { $a, $k = $_ -split ':', 2; [pscustomobject]@{ Account = $a.ToLowerInvariant(); KeyLabel = $k } })
$alertPath = if ($pre) { $pre.AlertPath } else { $null }
if (-not $alertPath) {
    # Verify-only run: detect the path the same way the preflight does.
    $s = Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url', $sentinelRuleUri) -AllowNotFound
    $alertPath = if ($s -and $s.properties.enabled) { 'sentinel' } elseif (Invoke-AzJson -Arguments @('rest', '--method', 'get', '--url', "https://management.azure.com$laRuleId`?api-version=2021-08-01") -AllowNotFound) { 'log-analytics' } else { 'none' }
}

Write-Console "`nVerifying (polling up to $WaitMinutes min for alerts)..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes($WaitMinutes)
do {
    $obs = Get-DrillObservation -StartUtc $DrillStartUtc -AlertPath $alertPath -RuleName $RuleDisplayName
    $assess = Get-DrillAssessment -Declared $declared -SignIns $obs.SignIns -Alerts $obs.Alerts -Incidents $obs.Incidents -AlertsCarryAccounts $obs.AlertsCarryAccounts
    # A Pass is final only once each alerted sign-in also has its incident on
    # the Sentinel path: the incident is created seconds after the alert and
    # reaches SecurityIncident later still (first lab drill, 2026-11-05: alert
    # 10:52:45Z, incident 10:52:55Z; stopping at the alert left the incident
    # number out of the record).
    $pending = @(Get-PendingIncident -Assessment $assess -AlertPath $alertPath)
    if (($assess.Result -eq 'Pass' -and -not $pending.Count) -or (Get-Date) -ge $deadline) { break }
    if ($assess.Result -eq 'Pass') { Write-Console ("  {0:HH:mm:ss} Pass; waiting for the incident of: {1}" -f (Get-Date), ($pending -join ', ')) -ForegroundColor DarkGray; Start-Sleep -Seconds $PollSeconds; continue }
    Write-Console ("  {0:HH:mm:ss} {1}: {2}" -f (Get-Date), $assess.Result, ($assess.Reasons -join '; ')) -ForegroundColor DarkGray
    Start-Sleep -Seconds $PollSeconds
} while ($true)

Write-Console "`nPost-drill re-check (runbook step 7)" -ForegroundColor Cyan
$null = Invoke-Preflight -GroupMailNickname $BreakGlassGroupMailNickname -Domain $OnMicrosoftDomain -KeysPerAccount $ExpectedKeysPerAccount
$postChecks = @($checks.ToArray())

# =============================================================================
# RECORD
# =============================================================================
$verifiedAt = (Get-Date).ToUniversalTime()
$record = [ordered]@{
    schema                   = 'contoso-breakglass-drill/v1'
    drillDateUtc             = $DrillStartUtc.ToUniversalTime().ToString('yyyy-MM-dd')
    startedAtUtc             = $DrillStartUtc.ToUniversalTime().ToString('o')
    verifiedAtUtc            = $verifiedAt.ToString('o')
    generator                = 'lab/scripts/powershell/Invoke-BreakGlassDrill.ps1'
    operator                 = $(if ($Operator) { $Operator } else { $null })
    reviewer                 = $(if ($Reviewer) { $Reviewer } else { $null })
    changeTicket             = $(if ($ChangeTicket) { $ChangeTicket } else { $null })
    alertPath                = $alertPath
    preflight                = @($preflightChecks | ForEach-Object { [ordered]@{ check = $_.Check; status = $_.Status } })
    postDrillChecks          = @($postChecks | ForEach-Object { [ordered]@{ check = $_.Check; status = $_.Status } })
    signIns                  = @($assess.SignIns | ForEach-Object { [ordered]@{
                account = $_.account; keyLabel = $_.keyLabel; keyLabelSource = $_.keyLabelSource
                observedInLogs = $_.observedInLogs; signInUtc = $_.signInUtc; signInResultType = $_.signInResultType; signInMethods = $_.signInMethods
                alertObserved = $_.alertObserved; alertUtc = $_.alertUtc; signInToAlertMinutes = $_.signInToAlertMinutes; incidentNumber = $_.incidentNumber
                signInToIncidentMinutes = $_.signInToIncidentMinutes
            } })
    auditOperationsByBreakGlass = $obs.AuditOperations
    notCheckedByScript       = @('Teams card', 'ServiceNow INC', 'Splunk alert')
    result                   = $assess.Result
    resultReasons            = @($assess.Reasons)
}
if ($obs.AuditOperations -gt 0) { $record.resultReasons += "$($obs.AuditOperations) audit operation(s) initiated by break-glass in the window - the second admin must review them" }
$json = $record | ConvertTo-Json -Depth 6
$leaks = @(Test-PublicRecordSafe -Json $json)
if ($leaks.Count) { throw "Refusing to write the public record: it contains $($leaks.Count) identifying value(s). Nothing written." }

$stamp = $DrillStartUtc.ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ')
if ($PSCmdlet.ShouldProcess($EvidenceDirectory, "write drill record $stamp")) {
    foreach ($d in $EvidenceDirectory, $PrivateDirectory) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    $pub = Join-Path $EvidenceDirectory "$stamp-break-glass-drill.json"
    $json | Set-Content -LiteralPath $pub -Encoding utf8NoBOM
    # Full observation (UPNs, IPs, correlation ids) stays in the gitignored folder.
    [ordered]@{ record = "$stamp-break-glass-drill.json"; signInRows = $obs.SignIns; alerts = $obs.Alerts; incidents = $obs.Incidents } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PrivateDirectory "$stamp-break-glass-drill-detail.json") -Encoding utf8NoBOM
    Write-Console "`nDrill record: $pub" -ForegroundColor Cyan
}

# Rows for the drill log table in lab/evidence/drills/README.md (paste by hand;
# cells the script did not observe are left blank).
Write-Console "`nDrill-log rows:" -ForegroundColor Cyan
foreach ($s in $assess.SignIns) {
    $alertCell = if ($s.alertObserved) { "yes$(if ($s.incidentNumber) { " (#$($s.incidentNumber))" })" } else { 'no' }
    # The log column is sign-in -> INCIDENT; on the Log Analytics path there is
    # no incident, so the cell stays blank (the alert minutes are in the record).
    $sumCell = if ($null -ne $s.signInToIncidentMinutes) { $s.signInToIncidentMinutes } else { '' }
    Write-Console "| $($record.drillDateUtc) | $($s.account) | $($s.keyLabel) | $(if ($s.observedInLogs) { 'yes' } else { 'not seen' }) | $alertCell | | | | $sumCell | $(if ($obs.AuditOperations) { "yes ($($obs.AuditOperations))" } else { 'none' }) | $Operator | $Reviewer | $ChangeTicket | $($assess.Result) | |"
}
$color = @{ Pass = 'Green'; Partial = 'Yellow'; Fail = 'Red' }[$assess.Result]
Write-Console "`nDrill result: $($assess.Result)$(if ($assess.Reasons) { ' - ' + ($assess.Reasons -join '; ') })" -ForegroundColor $color
if ($assess.Result -ne 'Pass') { exit 1 }
exit 0
