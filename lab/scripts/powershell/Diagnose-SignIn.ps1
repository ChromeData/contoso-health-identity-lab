<#
.SYNOPSIS
    A help-desk engineer pastes a sign-in correlation id, or a user principal
    name and a time window, and gets a plain-English explanation of what
    happened: which Conditional Access policies applied, which were
    report-only, what each one demanded (MFA, compliant device, strength),
    whether the device, location and risk checks passed, and the one line to
    tell the user.

.DESCRIPTION
    "I can't sign in" reaches the service desk as a screenshot with a
    correlation id. The sign-in log already holds the answer, but spread over
    a dozen fields and status codes. This script reads ONE sign-in (or every
    sign-in for a user in the last -LastHours) from the beta sign-in log and
    turns it into:

      1. A VERDICT in plain words, first line, e.g.
           Blocked: the sign-in came from a country the hospital does not allow (policy CA004)
           Allowed after MFA (Microsoft Authenticator app)
           Allowed, but policy CA002 would have blocked it once enforced
      2. The FACTS as short labelled lines: result code, every Conditional
         Access policy with its result (applied / not applied / report-only)
         and what it demanded, the authentication requirement and MFA method,
         device compliance, location, risk, client app.
      3. "Tell the user:" one sentence the engineer can read out.

    The same is returned as a [pscustomobject] per sign-in (pipe it, filter
    it) and written as a Markdown report to -OutputDirectory.

    STATUS: written and tested OFFLINE only (mocked Graph, synthetic
    sign-ins in tests/fixtures/sign-ins.fixture.json); it has not run against
    a tenant.

    NEVER SILENT: a failed Graph read prints FAILED and exits 1; "no sign-in
    found" is said in so many words (the log can lag a few minutes, and the
    window may be too short), never shown as an empty success.

.PREREQUISITES
    * Modules: Microsoft.Graph.Authentication (raw REST via Invoke-MgGraphRequest).
    * Entra ID P1 or P2: the sign-in log with Conditional Access detail.

.GRAPH SCOPES  (delegated; admin-consent -- all READ-ONLY)
    AuditLog.Read.All     /beta/auditLogs/signIns
    Directory.Read.All    required alongside AuditLog.Read.All by the signIns API

.PARAMETER CorrelationId
    The correlation id from the user's error page or the portal sign-in
    blade. A GUID; one sign-in (sometimes two or three legs of the same
    sign-in share it, all are shown).

.PARAMETER UserPrincipalName
    Instead of a correlation id: every sign-in by this user in the last
    -LastHours, newest first (at most 50).

.PARAMETER LastHours
    Window for -UserPrincipalName. Default 24, at most 720 (the log keeps 30
    days on P1/P2).

.PARAMETER OutputDirectory
    Where the Markdown report goes. Default lab/evidence/out/sign-in
    (gitignored: the report names a person). Alias: -OutDir.

.EXAMPLE
    Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All'
    ./Diagnose-SignIn.ps1 -CorrelationId 'the-guid-from-the-error-page'

.EXAMPLE
    ./Diagnose-SignIn.ps1 -UserPrincipalName 'first.last@contoso.test' -LastHours 4 |
        Where-Object Verdict -like 'Blocked*' | Select-Object CreatedDateTime, Verdict, TellUser

.OUTPUTS
    One [pscustomobject] per sign-in (CreatedDateTime, CorrelationId,
    UserPrincipalName, App, Verdict, TellUser, ErrorCode, ErrorText,
    Policies, ReportOnlyPolicies, Device, Location, Risk, Text ...) and
    sign-in-diagnosis-<UTC>.md in -OutputDirectory. Exit 1 when the Graph
    read fails.

.WHAT IT DEMONSTRATES
    The Conditional Access design is only as good as the help desk's ability
    to explain it. Report-only results read out loud ("would have blocked")
    are how CA002 and CA008 get enforced without a flood of tickets.

.NOTES
    verify: /beta/auditLogs/signIns accepts $filter on correlationId, and on
    userPrincipalName combined with createdDateTime ge, with $orderby
    createdDateTime desc (learn.microsoft.com/graph/api/signin-list?view=
    graph-rest-beta). The result strings of appliedConditionalAccessPolicies
    (success, failure, notApplied, reportOnlySuccess, reportOnlyFailure,
    reportOnlyNotApplied, reportOnlyInterrupted) are from the beta
    conditionalAccessPolicyResult enum.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'ByUser')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByCorrelationId')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$CorrelationId,

    [Parameter(Mandatory, ParameterSetName = 'ByUser')]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(ParameterSetName = 'ByUser')]
    [ValidateRange(1, 720)]
    [int]$LastHours = 24,

    [Parameter()]
    [Alias('OutDir')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'sign-in')
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

# ===========================================================================
# 0. TABLES: error codes and grant controls in plain words
# ===========================================================================
# status.errorCode -> what to say. Anything else prints the code and Graph's
# own failureReason. verify: the AADSTS codes page (learn.microsoft.com/entra/
# identity-platform/reference-error-codes) for new codes worth adding.
$ErrorCodeText = @{
    0      = 'success'
    50053  = 'the account is locked (too many wrong passwords, or sign-ins from a blocked address)'
    50074  = 'MFA was required and was not completed'
    50076  = 'MFA was needed for this app or location and was not completed'
    50126  = 'wrong password (or wrong user name)'
    53003  = 'blocked by Conditional Access'
    65001  = 'the app needs consent that has not been granted'
    530032 = 'blocked by a security policy (a Microsoft-managed or tenant security policy, not one of the lab CA policies)'
}
# enforcedGrantControls values -> what the policy demanded.
$GrantText = @{
    'Block'                         = 'block'
    'Mfa'                           = 'MFA'
    'CompliantDevice'               = 'a compliant (managed and healthy) device'
    'DomainJoinedDevice'            = 'a hybrid-joined device'
    'ApprovedApplication'           = 'an approved client app'
    'CompliantApplication'          = 'an app protection policy'
    'PasswordChange'                = 'a password change'
    'RequireAuthenticationStrength' = 'a phishing-resistant method (authentication strength)'
    'AuthenticationStrength'        = 'a phishing-resistant method (authentication strength)'
}
$MaxSignIns = 50

# ===========================================================================
# 1. HELPERS
# ===========================================================================
function Get-Value($Object, [string[]]$Path) {
    $cur = $Object
    foreach ($p in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$p] }
        elseif ($cur.PSObject.Properties[$p]) { $cur = $cur.$p }
        else { return $null }
    }
    return $cur
}

function Invoke-GraphGetAll([string]$Uri, [int]$Max = 0) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        if ($page -is [System.Collections.IDictionary] -and $page.Contains('value')) {
            foreach ($v in @($page['value'])) { $items.Add($v) }
            $next = if ($page.Contains('@odata.nextLink')) { [string]$page['@odata.nextLink'] } else { $null }
        }
        else { $items.Add($page); $next = $null }
        if ($Max -and $items.Count -ge $Max) { break }
    }
    return $items.ToArray()
}

function Format-TimeStamp($Value) {
    # Graph hands dates back as [datetime] (hashtable output) or ISO strings;
    # either way print UTC ISO, never the machine's culture format.
    if ($null -eq $Value -or "$Value" -eq '') { return 'unknown time' }
    if ($Value -is [datetime]) {
        $dt = if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return $dt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) {
        return $parsed.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return [string]$Value
}

function Get-PolicyCode([string]$DisplayName) {
    # 'CA004 - Block sign-in from blocked countries' -> 'CA004'; otherwise the name.
    if ($DisplayName -match '^\s*(CA\d{3})\b') { return $Matches[1] }
    return $DisplayName
}

function Get-GrantText([object[]]$Grants) {
    $words = @(foreach ($g in @($Grants)) { if ($GrantText.ContainsKey([string]$g)) { $GrantText[[string]$g] } else { [string]$g } })
    if (-not $words.Count) { return 'nothing (no grant control recorded)' }
    return ($words -join ' and ')
}

function Get-BlockReason([string]$PolicyName, [string]$Country) {
    # Why a Block policy fired, from what the policy is about. Plain words
    # first, the policy code in brackets.
    $code = Get-PolicyCode $PolicyName
    $where = if ($Country) { "a country the hospital does not allow ($Country)" } else { 'a country the hospital does not allow' }
    switch -Regex ($PolicyName) {
        'countr|location|geo' { return "the sign-in came from $where (policy $code)" }
        'legacy|basic auth' { return "the app signed in the old way (legacy authentication), which is blocked (policy $code)" }
        'risk' { return "the sign-in was judged risky (policy $code)" }
        'device.?code' { return "the sign-in used device code flow, which is blocked (policy $code)" }
        'device|compliant' { return "the device is not a compliant hospital device (policy $code)" }
        default { return "policy $code blocks this sign-in" }
    }
}

function ConvertTo-SignInDiagnosis($SignIn) {
    # One sign-in (a Graph beta signIn, hashtable or object) -> the verdict,
    # the facts and the sentence for the user. Pure: no Graph, no console.
    $errorCode = [int](Get-Value $SignIn @('status', 'errorCode'))
    $failureReason = [string](Get-Value $SignIn @('status', 'failureReason'))
    $errorText = if ($ErrorCodeText.ContainsKey($errorCode)) { $ErrorCodeText[$errorCode] } else { "error $errorCode" + $(if ($failureReason) { ": $failureReason" } else { '' }) }
    $caStatus = [string](Get-Value $SignIn @('conditionalAccessStatus'))
    $requirement = [string](Get-Value $SignIn @('authenticationRequirement'))
    $mfaMethod = [string](Get-Value $SignIn @('mfaDetail', 'authMethod'))
    $mfaDetail = [string](Get-Value $SignIn @('mfaDetail', 'authDetail'))
    $isCompliant = Get-Value $SignIn @('deviceDetail', 'isCompliant')
    $isManaged = Get-Value $SignIn @('deviceDetail', 'isManaged')
    $os = [string](Get-Value $SignIn @('deviceDetail', 'operatingSystem'))
    $city = [string](Get-Value $SignIn @('location', 'city'))
    $country = [string](Get-Value $SignIn @('location', 'countryOrRegion'))
    $riskLevel = [string](Get-Value $SignIn @('riskLevelDuringSignIn'))
    $riskState = [string](Get-Value $SignIn @('riskState'))
    $clientApp = [string](Get-Value $SignIn @('clientAppUsed'))
    $app = [string](Get-Value $SignIn @('appDisplayName'))
    $upn = [string](Get-Value $SignIn @('userPrincipalName'))

    $policies = @(foreach ($p in @(Get-Value $SignIn @('appliedConditionalAccessPolicies'))) {
            [pscustomobject]@{
                Name    = [string](Get-Value $p @('displayName'))
                Code    = Get-PolicyCode ([string](Get-Value $p @('displayName')))
                Result  = [string](Get-Value $p @('result'))
                Grant   = @(Get-Value $p @('enforcedGrantControls') | Where-Object { $_ })
                Session = @(Get-Value $p @('enforcedSessionControls') | Where-Object { $_ })
            }
        })
    $applied = @($policies | Where-Object Result -eq 'success')
    $blockers = @($policies | Where-Object Result -eq 'failure')
    $reportOnlyFailed = @($policies | Where-Object Result -eq 'reportOnlyFailure')
    $reportOnlyPassed = @($policies | Where-Object Result -eq 'reportOnlySuccess')

    $device = if ($null -eq $isCompliant -and $null -eq $isManaged) { 'unknown (no device detail recorded)' }
    elseif ($isCompliant) { 'compliant and managed' }
    elseif ($isManaged) { 'managed but NOT compliant' }
    else { 'unmanaged (not registered with the hospital)' }
    if ($os) { $device += ", $os" }
    $location = (@($city, $country) | Where-Object { $_ }) -join ', '
    if (-not $location) { $location = 'unknown' }
    $risk = if ($riskLevel) { $riskLevel } else { 'none' }
    if ($riskState -and $riskState -ne 'none') { $risk += " (risk state: $riskState)" }
    $mfaText = if ($mfaMethod) { $mfaMethod + $(if ($mfaDetail) { " ($mfaDetail)" } else { '' }) } else { 'no MFA recorded' }

    # The verdict, worst news first.
    $verdict = ''; $tell = ''; $outcome = 'Failed'
    if ($errorCode -eq 53003 -or ($caStatus -eq 'failure' -and $blockers.Count)) {
        $outcome = 'Blocked'
        $b = if ($blockers.Count) { $blockers[0] } else { $null }
        if ($b -and $b.Grant -contains 'Block') {
            $verdict = "Blocked: $(Get-BlockReason $b.Name $country)"
            switch -Regex ($b.Name) {
                'countr|location|geo' { $tell = "Sign-ins from $(if ($country) { $country } else { 'this country' }) are not allowed; if you are travelling, use the hospital VPN or tell the service desk before you travel." }
                'legacy|basic auth' { $tell = 'The app you used signs in an old way that is no longer allowed; update to the current app or use the web version.' }
                'risk' { $tell = 'This sign-in looked risky, so it was blocked; the service desk will check it with you and reset your password if needed.' }
                # Device code flow blocks must be handled before the generic device match
                # below, so the user is not wrongly told to enrol a device. break stops the
                # later 'device|compliant' case (switch -Regex runs every match otherwise).
                'device.?code' { $tell = 'This app signed in with device code flow, where you type a code shown on another screen; the hospital blocks that, so sign in directly in the browser or the app itself instead of entering a code.'; break }
                'device|compliant' { $tell = 'Sign in from your hospital-managed device, or enrol this one with the service desk first.' }
                default { $tell = "This sign-in is blocked by policy $($b.Code); the service desk is checking whether you should be in its scope." }
            }
        }
        elseif ($b) {
            $need = Get-GrantText $b.Grant
            $verdict = "Blocked: policy $($b.Code) demanded $need and the sign-in did not provide it"
            $tell = switch -Regex (($b.Grant -join ' ')) {
                'CompliantDevice|DomainJoinedDevice' { 'This device is not a compliant hospital device; sign in from your managed device or enrol this one.' }
                'AuthenticationStrength' { 'This app needs a phishing-resistant method (a passkey or security key); register one at My Security Info and sign in again.' }
                'Mfa' { 'Approve the MFA prompt on your phone or key; if none arrives, check your methods at My Security Info.' }
                default { "This sign-in needs $need; the service desk will help you meet it." }
            }
        }
        else {
            $verdict = "Blocked: $errorText"
            $tell = 'Conditional Access blocked this sign-in; the service desk is checking which policy and why.'
        }
    }
    elseif ($errorCode -eq 0) {
        if ($reportOnlyFailed.Count) {
            $outcome = 'Allowed, with a warning'
            $r = $reportOnlyFailed[0]
            $would = if ($r.Grant -contains 'Block') { 'blocked it' } else { "blocked it once enforced (it demands $(Get-GrantText $r.Grant))" }
            $verdict = "Allowed, but policy $($r.Code) would have $would"
            $tell = switch -Regex (($r.Grant -join ' ')) {
                'AuthenticationStrength' { "Your sign-in worked today, but soon this will need a passkey or security key; register one at My Security Info now so nothing changes for you later." }
                'CompliantDevice|DomainJoinedDevice' { 'Your sign-in worked today, but soon this will need a hospital-managed device; enrol this one or switch to your managed device.' }
                'Mfa' { 'Your sign-in worked today, but soon it will ask for MFA; make sure your methods are set up at My Security Info.' }
                default { "Your sign-in worked today; a policy change is coming ($($r.Code)) and the service desk will tell you what it needs." }
            }
        }
        elseif ($requirement -eq 'multiFactorAuthentication') {
            $outcome = 'Allowed'
            $verdict = "Allowed after MFA" + $(if ($mfaMethod) { " ($mfaMethod)" } else { '' })
            $tell = 'Your sign-in worked; if the app still shows an error, the problem is in the app, not the sign-in.'
        }
        else {
            $outcome = 'Allowed'
            $verdict = 'Allowed with a password only (no MFA was demanded)'
            $tell = 'Your sign-in worked without MFA; if the app still shows an error, the problem is in the app, not the sign-in.'
        }
    }
    else {
        $verdict = "Failed: $errorText"
        $tell = switch ($errorCode) {
            50053 { 'Your account is locked after too many wrong passwords; wait a few minutes or reset your password with self-service reset.' }
            50074 { 'Approve the MFA prompt on your phone or key and try again; if no prompt arrives, check your methods at My Security Info.' }
            50076 { 'This app or location asks for MFA; approve the prompt and try again, or check your methods at My Security Info.' }
            50126 { 'The password was not accepted; type it again carefully, or reset it with self-service password reset.' }
            65001 { 'This app needs an administrator to approve it before you can use it; the service desk will raise that request.' }
            530032 { 'A security policy blocked this sign-in; the service desk is checking it and will call you back.' }
            default { "The sign-in failed with error $errorCode; the service desk is looking into it." }
        }
    }

    $created = Format-TimeStamp (Get-Value $SignIn @('createdDateTime'))
    $lines =[System.Collections.Generic.List[string]]::new()
    $lines.Add("==== Sign-in $created  $upn -> $app ====")
    $lines.Add("Verdict: $verdict")
    $lines.Add("  Result             : $outcome; error $errorCode ($errorText)" + $(if ($failureReason -and $errorCode -ne 0) { "; Graph says: $failureReason" } else { '' }))
    $caLine = if ($caStatus) { $caStatus } else { 'not recorded' }
    if ($caStatus -eq 'notApplied' -or -not $policies.Count) { $caLine += ' (no Conditional Access policy applied to this sign-in)' }
    $lines.Add("  Conditional Access : $caLine")
    foreach ($p in $policies) {
        $what = switch ($p.Result) {
            'success' { "applied, passed; demanded $(Get-GrantText $p.Grant)" }
            'failure' { "applied, NOT met; demanded $(Get-GrantText $p.Grant)" }
            'notApplied' { 'not applied (out of scope)' }
            'reportOnlySuccess' { "report-only: would have passed ($(Get-GrantText $p.Grant))" }
            'reportOnlyFailure' { "report-only: WOULD HAVE BLOCKED; demands $(Get-GrantText $p.Grant)" }
            'reportOnlyNotApplied' { 'report-only: out of scope' }
            'reportOnlyInterrupted' { 'report-only: could not be evaluated (interrupted)' }
            default { $p.Result }
        }
        if ($p.Session.Count) { $what += "; session: $($p.Session -join ', ')" }
        $lines.Add(("    {0,-10} {1}" -f $p.Code, $what))
    }
    $lines.Add("  Authentication     : $(if ($requirement) { $requirement } else { 'not recorded' }); MFA: $mfaText")
    $lines.Add("  Device             : $device")
    $lines.Add("  Location           : $location")
    $lines.Add("  Risk               : $risk")
    $lines.Add("  Client app         : $(if ($clientApp) { $clientApp } else { 'not recorded' })")
    $lines.Add("  Correlation id     : $(Get-Value $SignIn @('correlationId'))")
    $lines.Add("Tell the user: $tell")

    return [pscustomobject]@{
        CreatedDateTime           = $created
        CorrelationId             = [string](Get-Value $SignIn @('correlationId'))
        UserPrincipalName         = $upn
        App                       = $app
        ClientApp                 = $clientApp
        Outcome                   = $outcome
        Verdict                   = $verdict
        TellUser                  = $tell
        ErrorCode                 = $errorCode
        ErrorText                 = $errorText
        FailureReason             = $failureReason
        ConditionalAccessStatus   = $caStatus
        AppliedPolicies           = @($applied | ForEach-Object Code)
        BlockingPolicies          = @($blockers | ForEach-Object Code)
        ReportOnlyPolicies        = @($reportOnlyFailed | ForEach-Object Code)
        ReportOnlyPassedPolicies  = @($reportOnlyPassed | ForEach-Object Code)
        Policies                  = $policies
        AuthenticationRequirement = $requirement
        Mfa                       = $mfaText
        Device                    = $device
        Location                  = $location
        Risk                      = $risk
        Text                      = ($lines -join [Environment]::NewLine)
    }
}

function ConvertTo-SignInMarkdown([object[]]$Diagnoses, [string]$Query, [datetime]$Now) {
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('# Sign-in diagnosis')
    $md.Add('')
    $md.Add("Generated $($Now.ToString('u')) by Diagnose-SignIn.ps1. Query: $Query.")
    $md.Add('')
    $md.Add('Names a person: this file belongs in `lab/evidence/out/` (gitignored), not in a commit.')
    $md.Add('')
    if (-not $Diagnoses.Count) {
        $md.Add('**No sign-in found.** The log can lag a few minutes; widen `-LastHours` or check the correlation id.')
        return ($md -join [Environment]::NewLine)
    }
    $n = 0
    foreach ($d in $Diagnoses) {
        $n++
        $md.Add("## $n. $($d.CreatedDateTime) - $($d.Verdict)")
        $md.Add('')
        $md.Add('```text')
        $md.Add($d.Text)
        $md.Add('```')
        $md.Add('')
    }
    return ($md -join [Environment]::NewLine)
}

# ===========================================================================
# 2. READ THE SIGN-IN LOG
# ===========================================================================
$graph = 'https://graph.microsoft.com'
$requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
$ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext }
$missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). The sign-in read will return 403 (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

$Now = (Get-Date).ToUniversalTime()
if ($PSCmdlet.ParameterSetName -eq 'ByCorrelationId') {
    $filter = "correlationId eq '$CorrelationId'"
    $query = "correlation id $CorrelationId"
}
else {
    # OData string literal: a quote in the UPN is doubled, nothing else is interpreted.
    $since = $Now.AddHours(-$LastHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "userPrincipalName eq '$($UserPrincipalName -replace "'", "''")' and createdDateTime ge $since"
    $query = "$UserPrincipalName, last $LastHours h (since $since)"
}
$uri = "$graph/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($filter))&`$orderby=createdDateTime desc&`$top=$MaxSignIns"

Write-Console "Reading sign-ins for $query ..." -ForegroundColor DarkGray
$signIns = @()
try { $signIns = @(Invoke-GraphGetAll $uri -Max $MaxSignIns) }
catch {
    Write-Console "FAILED to read the sign-in log: $($_.Exception.Message) -- result UNKNOWN, not 'no sign-in'." -ForegroundColor Red
    Write-Warning "Raw REST equivalent: Invoke-MgGraphRequest GET $uri"
    exit 1
}

# ===========================================================================
# 3. EXPLAIN AND WRITE
# ===========================================================================
$diagnoses = @(foreach ($s in $signIns) { ConvertTo-SignInDiagnosis $s })
if (-not $diagnoses.Count) {
    Write-Console "No sign-in found for $query. The log can lag a few minutes; widen -LastHours or check the correlation id." -ForegroundColor Yellow
}
foreach ($d in $diagnoses) {
    $colour = switch -Wildcard ($d.Outcome) { 'Allowed' { 'Green' } 'Allowed,*' { 'Yellow' } default { 'Red' } }
    $textLines = $d.Text -split "`r?`n"
    Write-Console ''
    Write-Console $textLines[0] -ForegroundColor Cyan
    Write-Console $textLines[1] -ForegroundColor $colour
    foreach ($l in $textLines[2..($textLines.Count - 1)]) {
        if ($l -like 'Tell the user:*') { Write-Console $l -ForegroundColor White } else { Write-Console $l -ForegroundColor DarkGray }
    }
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$reportPath = Join-Path $OutputDirectory "sign-in-diagnosis-$($Now.ToString('yyyyMMddTHHmmssZ')).md"
ConvertTo-SignInMarkdown -Diagnoses $diagnoses -Query $query -Now $Now | Set-Content -LiteralPath $reportPath -Encoding utf8
Write-Console "`nReport: $reportPath ($($diagnoses.Count) sign-in(s))" -ForegroundColor DarkGray

return $diagnoses
