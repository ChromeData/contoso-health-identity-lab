<#
.SYNOPSIS
    Authentication methods policy as code: passkey (FIDO2) profiles, Temporary
    Access Pass, Microsoft Authenticator hardening, a passkey registration
    campaign, and (gated) SMS/voice retirement. Read-only PLAN by default;
    changes the tenant only with -Apply.

.DESCRIPTION
    WHY A SCRIPT: the azuread Terraform provider has no resource for the
    authentication methods policy (method configurations, passkey profiles,
    registration campaign), so this is a post-apply step like the others in
    this folder. It is written as desired state: every run reads the live
    policy, prints the drift, and only with -Apply PATCHes and re-reads to
    confirm. Re-running a converged tenant changes nothing.

    WHAT IT CONFIGURES (and why)

      1. PASSKEYS (FIDO2) with passkey profiles
         * "Contoso - Admins (device-bound, attested)": deviceBound only,
           attestationEnforcement = registrationOnly, optional AAGUID allow-list
           (-AdminAllowedAaguids). Targets Break-Glass-Admins + STANDING admin
           groups: Admin-Accounts (every cloud-only adm- account + the build
           account) and PIM-Azure-RG-Contributors (standing members, eligible
           for an Azure role). NEVER a PIM-for-Groups group (pim-tier*,
           privileged-iam-admins): those are eligible-only, so an adm- account
           is a member only during an activation it must pass the step-up
           (CA021 / CA002) to start - a passkey target there covers nobody at
           registration or sign-in. The script refuses such a group.
           Attestation lets Entra verify the key's make/model at registration,
           which is the assurance a privileged credential needs.
         * "Contoso - Workforce (synced or device-bound)": deviceBound + synced,
           attestation disabled (synced passkeys CANNOT be attested - Microsoft
           Learn). Only with -IncludeStaffRollout (Terraform flag
           enable_phishing_resistant_all_users). Synced passkeys are still
           phishing-resistant; Microsoft says to treat them with "the same
           security posture as other unattested authenticators", so they are a
           good staff default and never the admin control.
         * Profile evaluation is "ANY profile in scope satisfies" (Microsoft
           Learn). So the staff target is a WORKFORCE group, never all_users:
           all_users would put break-glass in scope of the synced profile and
           silently undo the attested-only rule. Admin work is done from a
           separate cloud-only adm- account, which is never HR-synced and so
           never in All-Workforce. If an HR-synced account ever held an admin
           role it could still register a synced passkey; the control that
           keeps that off admin roles is the admin authentication strength
           (CA002 / CA021 / CA022, AAGUID-restricted, see NOTES). Because
           that control is EMPTY by default, -IncludeStaffRollout without
           -AdminAllowedAaguids is a FAIL and the workforce target is not
           applied - unless -AcceptAdminSyncedPasskeyRisk records that the
           admin assurance drop is a reviewed decision (the Terraform side has
           the same second key: accept_admin_synced_passkey_risk).
      2. TEMPORARY ACCESS PASS - the passwordless bootstrap. Lifetime limits
         fit the joiner Lifecycle Workflow's TAP task (480 min, one-time) and
         07-Passwordless-Rollout.ps1. Break-glass excluded: a TAP on a standing
         Global Admin is a takeover path.
      3. MICROSOFT AUTHENTICATOR - the bridge method while passkeys roll out.
         App name + location shown in the push (helps users spot MFA fatigue
         attacks); OTP codes in Authenticator off (phishable). Number matching
         is always on for push and is no longer a setting (see NOTES).
      4. REGISTRATION CAMPAIGN - nudges in-scope users to register a passkey
         (targetedAuthenticationMethod = Fido2) after their next MFA. Admin
         groups always; workforce groups with -IncludeStaffRollout.
         Break-glass excluded (keys are registered in a controlled ceremony).
      5. SMS / VOICE - break-glass is always excluded from both. The methods
         themselves are disabled only with -DisableSmsVoice, and only if NO
         in-scope user depends on phone methods alone (fail closed). Microsoft
         retires Microsoft-provided SMS/voice MFA on 1 Feb 2027 (1 Jul 2027 for
         Global Administrators and external users), with no opt-out for
         enforcement; users whose only MFA method is SMS/voice then get a
         blocking passkey-registration prompt (Microsoft Learn FAQ,
         concept-sms-voice-retirement-faq, updated 2026-09-23). Disabling
         earlier, on our schedule, after the campaign has done its job, is the
         controlled version of the same change.
      6. REPORT SUSPICIOUS ACTIVITY (beta) - only with
         -EnableReportSuspiciousActivity (Terraform flag
         enable_identity_protection_ca). A user who reports an MFA prompt they
         did not start is set to high user risk, which CA006 then remediates.

    BREAK-GLASS INVARIANTS (checked at the end, exit 1 on any FAIL)
      * Break-Glass-Admins is in the passkey policy, scoped ONLY to the
        attested admin profile;
      * it is excluded from TAP, Authenticator, SMS, voice and the campaign;
      * with -AdminAllowedAaguids: every key already registered to a
        break-glass account is a model on that list. Break-glass is FIDO2-only,
        and an enforced key restriction also blocks keys that are already
        registered (verify: Learn, passkey profiles / key restrictions), so a
        key outside the list would lock break-glass out. Checked BEFORE the
        passkey PATCH: on any mismatch (or an unreadable key list) the passkey
        section sends nothing.

    ADMIN COVERAGE (exit 1 on any FAIL)
      * every resolved admin group is an include target scoped to the admin
        profile, and Admin-Accounts exists;
      * -BuildAccountUpn: the build account is in an include target (its key
        must keep working through CA021 / CA002 and the GA conversion);
      * admin-target members holding keys outside -AdminAllowedAaguids are
        listed as WARN (they can still use TAP / Authenticator to re-register).

    SAFETY
      * PLAN by default. -Apply is the staging flag (default off) and still
        honours -WhatIf / -Confirm.
      * Existing passkey include-targets that are not ours are KEPT unless
        -ReplaceExistingTargets: removing a group from the passkey policy stops
        its members signing in with passkeys they already registered.
      * Passkey profiles must already be turned on in the tenant. The opt-in is
        irreversible (Microsoft Learn), so the script never does it implicitly;
        it stops that section and tells you where the switch is.

.PREREQUISITES
    * Signed-in admin: Authentication Policy Administrator (least privileged
      role for these PATCHes per the Graph reference).
    * Terraform envs/dev applied with enable_premium (groups exist).
    * -IncludeStaffRollout: the workforce group (-StaffGroupMailNicknames,
      default all-workforce) exists - see NOTES / wiring.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated)
    Policy.Read.All                         read the policy (PLAN)
    Policy.ReadWrite.AuthenticationMethod   PATCH method configurations (-Apply)
    Group.Read.All                          resolve target groups by mailNickname, members
    AuditLog.Read.All                       registration report (-DisableSmsVoice pre-check)
    UserAuthenticationMethod.Read.All       registered key models (-AdminAllowedAaguids)
    User.Read.All                           build account + its groups (-BuildAccountUpn)

.PARAMETER Apply
    Staging flag. Without it the script only reads and prints the plan.

.PARAMETER IncludeStaffRollout
    Add the workforce passkey profile target and campaign target. Mirrors the
    Terraform flag enable_phishing_resistant_all_users (default false).

.PARAMETER DisableSmsVoice
    Disable the SMS and voice methods (fail-closed pre-check, see above).

.PARAMETER EnableReportSuspiciousActivity
    Turn on "Report suspicious activity" (beta API). Mirrors
    enable_identity_protection_ca.

.PARAMETER ReplaceExistingTargets
    Drop passkey include-targets this script does not manage (e.g. a
    Microsoft-created all_users target). Off by default - see SAFETY.

.PARAMETER BreakGlassGroupMailNickname
    Default break-glass-admins (Terraform contract).

.PARAMETER AdminGroupMailNicknames
    STANDING groups scoped to the attested admin profile and the campaign.
    Default admin-accounts (modules/groups; FAIL when missing) and
    pim-azure-rg-contributors (modules/pim azure.tf; skipped with a note while
    enable_pim_azure_resources is off). A PIM-for-Groups group (pim-tier*,
    privileged-iam-admins) is refused: it has no standing members.
    Break-glass is always added on top.

.PARAMETER BuildAccountUpn
    The build account (admin@<tenant>.onmicrosoft.com). When given, the run
    FAILs unless it is covered by a passkey include target - it must keep a
    working admin key through CA021 / CA002 and
    Convert-BuildAccountToEligible.ps1. Invoke-PostApply.ps1 passes it.

.PARAMETER StaffGroupMailNicknames
    Workforce groups for the synced-allowed profile (-IncludeStaffRollout).
    Default all-workforce. Missing groups are skipped with a WARN.

.PARAMETER AdminAllowedAaguids
    AAGUID allow-list for the admin profile (your security-key models) - the
    SAME list as Terraform admin_fido2_allowed_aaguids (Invoke-PostApply.ps1
    passes the output). Empty = any attested device-bound passkey for the
    admin profile, and the workforce rollout is refused (see above).

.PARAMETER AcceptAdminSyncedPasskeyRisk
    Second key: run -IncludeStaffRollout with NO -AdminAllowedAaguids anyway
    (admins could then satisfy CA002 with a synced passkey). Reported as WARN.
    Mirrors Terraform accept_admin_synced_passkey_risk.

.PARAMETER TapMaximumLifetimeMinutes
    TAP policy maximum. Default 480 so the joiner workflow's 480-minute TAP fits.

.PARAMETER TapIsUsableOnce
    TAP policy one-time-use. Default $true (strictest; the joiner workflow and
    07-Passwordless-Rollout.ps1 both request one-time passes).

.PARAMETER CampaignSnoozeDays
    Days between campaign nudges after "Not now" (0-14). Default 1.

.PARAMETER OfflinePreview
    No tenant: print the desired JSON per section with placeholder group ids.

.EXAMPLE
    ./Set-AuthenticationMethodsPolicy.ps1 -OfflinePreview -IncludeStaffRollout

.EXAMPLE
    Connect-MgGraph -Scopes 'Policy.Read.All','Policy.ReadWrite.AuthenticationMethod','Group.Read.All','AuditLog.Read.All'
    ./Set-AuthenticationMethodsPolicy.ps1                     # plan only
    ./Set-AuthenticationMethodsPolicy.ps1 -Apply -WhatIf      # shows each PATCH
    ./Set-AuthenticationMethodsPolicy.ps1 -Apply              # admins + break-glass + TAP + Authenticator
    ./Set-AuthenticationMethodsPolicy.ps1 -Apply -IncludeStaffRollout   # later, after the pilot

.NOTES
    TENANT-TIME (nothing here has run against Entra yet):
      verify: passkey profiles - new profile ids are caller-chosen GUIDs in the
        PATCH (the v1.0 update example passes the ids it references); this
        script derives them deterministically from the profile name.
      verify: PATCH replaces the whole passkeyProfiles / includeTargets
        collections, so the script always sends existing + desired together.
      verify: profile limit. Microsoft Learn says "up to three passkey profiles,
        including the Default passkey profile"; the script needs two of its own.
      verify: number matching. It is not a property on the v1.0
        microsoftAuthenticatorFeatureSettings (only app/location context), and
        Microsoft enforced number matching for all Authenticator push in 2023.
      verify: featureSettings excludeTarget uses the all-zero GUID for "none"
        (Graph update example); check the PATCH is accepted.
      verify: reportSuspiciousActivitySettings is beta-only; shape from the
        beta authenticationMethodsPolicy resource.
      verify: registration campaign - since 1 Sep 2026 Microsoft may have set
        it to a Microsoft-managed state; an explicit state = enabled takes it
        back under this script's control.
      verify: the registration-report method names used by the SMS/voice
        pre-check (mobilePhone, alternateMobilePhone, officePhone).
    PAIRS WITH:
      * modules/conditional-access admin_fido2_allowed_aaguids (CA002): pass
        the same AAGUIDs as -AdminAllowedAaguids, so the key models admins may
        REGISTER and the models CA002 ACCEPTS are one list - a synced passkey
        then cannot satisfy an admin role even for a person in both targets.
      * Group all-workforce (wiring: groups module, behind
        enable_phishing_resistant_all_users): dynamic, HR-synced members only,
        so cloud-only admin and break-glass accounts are never in it. Until it
        exists pass e.g. -StaffGroupMailNicknames 'all-nurses','all-icu'.
    Sources: learn.microsoft.com/graph/api/fido2authenticationmethodconfiguration-update,
    /graph/api/resources/passkeyprofile, /entra/identity/authentication/how-to-authentication-passkeys-fido2,
    /graph/api/resources/authenticationmethodsregistrationcampaign,
    /entra/identity/authentication/concept-sms-voice-retirement-faq.

.WHAT IT DEMONSTRATES
    Passwordless as a governed rollout: method policy in code with a plan,
    profiles that separate admin assurance from staff convenience, a measured
    nudge before anything is switched off, and break-glass invariants checked
    on every run.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [switch]$IncludeStaffRollout,

    [Parameter()]
    [switch]$DisableSmsVoice,

    [Parameter()]
    [switch]$EnableReportSuspiciousActivity,

    [Parameter()]
    [switch]$ReplaceExistingTargets,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$AdminGroupMailNicknames = @('admin-accounts', 'pim-azure-rg-contributors'),

    [Parameter()]
    [ValidatePattern('^$|^[^@\s]+@[^@\s]+\.[^@\s]+$', ErrorMessage = 'BuildAccountUpn must be a UPN.')]
    [string]$BuildAccountUpn = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$StaffGroupMailNicknames = @('all-workforce'),

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$', ErrorMessage = 'Each AAGUID must be a GUID.')]
    [string[]]$AdminAllowedAaguids = @(),

    [Parameter()]
    [switch]$AcceptAdminSyncedPasskeyRisk,

    [Parameter()]
    [ValidateRange(60, 43200)]
    [int]$TapMaximumLifetimeMinutes = 480,

    [Parameter()]
    [bool]$TapIsUsableOnce = $true,

    [Parameter()]
    [ValidateRange(0, 14)]
    [int]$CampaignSnoozeDays = 1,

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

$graph = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'
$amp = "$graph/policies/authenticationMethodsPolicy"

# Profile names are the natural key: the script finds its profiles by name and
# derives their ids from the name, so re-runs never create duplicates.
$AdminProfileName = 'Contoso - Admins (device-bound, attested)'
$StaffProfileName = 'Contoso - Workforce (synced or device-bound)'
# The TAP joiner workflow (post-apply/New-LifecycleWorkflows.ps1) requests 480
# minutes; keep the minimum at or below that and the default short.
$TapMinimumLifetimeMinutes = 60
$TapDefaultLifetimeMinutes = 60
$TapDefaultLength = 12

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Section, [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Section = $Section; Status = $Status; Detail = $Detail })
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'DarkGray' }[$Status]
    Write-Host ("  [{0}] {1} - {2}" -f $Status, $Section, $Detail) -ForegroundColor $color
}

# =============================================================================
# Helpers (hashtable output: index access, never dot access, under StrictMode)
# =============================================================================
function Invoke-Graph {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body
    )
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'HashTable' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $params.Body = ($Body | ConvertTo-Json -Depth 20)
        $params.ContentType = 'application/json'
    }
    return Invoke-MgGraphRequest @params
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-Graph -Method GET -Uri $next
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    return $items.ToArray()
}

function Get-Field {
    # Walks a key path through nested dictionaries; a missing key is $null.
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($k in $Path) {
        if ($cur -isnot [System.Collections.IDictionary] -or -not $cur.Contains($k)) { return $null }
        $cur = $cur[$k]
    }
    return $cur
}

function Get-NameBasedGuid {
    # Name-based GUID (RFC 4122 v5 layout over SHA-1): the same profile name
    # always yields the same id, in every tenant and every run, so the plan is
    # stable and -OfflinePreview prints the real value.
    param([Parameter(Mandatory)][string]$Name)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("contoso-identity-lab/passkey-profile/$Name")
    $hash = [System.Security.Cryptography.SHA1]::HashData($bytes)
    $g = $hash[0..15]
    $g[6] = ($g[6] -band 0x0F) -bor 0x50
    $g[8] = ($g[8] -band 0x3F) -bor 0x80
    $hex = -join ($g | ForEach-Object { $_.ToString('x2') })
    return '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20, 12)
}

function ConvertTo-Canonical {
    # Canonical JSON for comparison: dictionary keys sorted, '@odata.*' noise
    # dropped, arrays of objects sorted by id, flag enums (passkeyTypes) and
    # GUID-like strings normalised. Two equal configurations serialise equally.
    param($Value, [string]$Key = '')
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in (@($Value.Keys) | Where-Object { $_ -notlike '@odata.*' } | Sort-Object)) { $o[$k] = ConvertTo-Canonical -Value $Value[$k] -Key $k }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $arr = @(foreach ($v in $Value) { ConvertTo-Canonical -Value $v -Key $Key })
        $sorted = @($arr | Sort-Object { if ($_ -is [System.Collections.IDictionary] -and $_.Contains('id')) { [string]$_['id'] } else { ($_ | ConvertTo-Json -Compress -Depth 20) } })
        return , $sorted
    }
    if ($Value -is [string]) {
        if ($Key -eq 'passkeyTypes') { return ((@($Value -split '\s*,\s*' | Where-Object { $_ }) | Sort-Object) -join ',') }
        if ($Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $Value.ToLowerInvariant() }
    }
    return $Value
}

function Select-DesiredShape {
    # Projects CURRENT onto the keys DESIRED sets, so server-side extras
    # (read-only fields, defaults we do not manage) never show as drift.
    param($Current, $Desired)
    if ($Desired -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Desired.Keys) {
            if ($k -like '@odata.*') { continue }
            $o[$k] = Select-DesiredShape -Current (Get-Field $Current @($k)) -Desired $Desired[$k]
        }
        return $o
    }
    if ($Desired -is [System.Collections.IEnumerable] -and $Desired -isnot [string]) {
        $dicts = @($Desired | Where-Object { $_ -is [System.Collections.IDictionary] })
        if (-not $dicts) { return , @($Current) }
        # Element shape = union of the desired elements' keys, each carrying a
        # sample desired value, so nested arrays/objects project with the right
        # type (a one-element array must stay an array, or it would read as drift).
        $shape = [ordered]@{}
        foreach ($d in $dicts) { foreach ($k in $d.Keys) { if (-not $shape.Contains($k)) { $shape[$k] = $d[$k] } } }
        return , @(foreach ($c in @($Current)) { if ($null -ne $c) { Select-DesiredShape -Current $c -Desired $shape } })
    }
    if ($Current -is [System.Collections.IEnumerable] -and $Current -isnot [string] -and $Current -isnot [System.Collections.IDictionary]) { return , @($Current) }
    return $Current
}

function Get-Drift {
    # Returns the top-level keys whose canonical form differs.
    param($Current, [System.Collections.IDictionary]$Desired)
    $drift = @()
    foreach ($k in $Desired.Keys) {
        if ($k -like '@odata.*') { continue }
        $cur = ConvertTo-Canonical -Value (Select-DesiredShape -Current (Get-Field $Current @($k)) -Desired $Desired[$k]) -Key $k
        $des = ConvertTo-Canonical -Value $Desired[$k] -Key $k
        $cj = $cur | ConvertTo-Json -Compress -Depth 20
        $dj = $des | ConvertTo-Json -Compress -Depth 20
        if ($cj -ne $dj) { $drift += $k }
    }
    return , $drift
}

function Test-PimGovernedNickname {
    # PIM-for-Groups groups (eligible-only membership) by the shared naming
    # contract: modules/pim tier groups (pim-tier*) and Privileged-IAM-Admins.
    # PIM-Azure-RG-Contributors and the approver groups have STANDING members.
    param([string]$MailNickname)
    return ($MailNickname -match '(?i)^pim-tier\d' -or $MailNickname -ieq 'privileged-iam-admins')
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

function Merge-ExcludeTarget {
    # Adds the break-glass group to an existing excludeTargets list without
    # dropping exclusions someone else made on purpose.
    param($Existing, [string]$GroupId)
    $list = @(foreach ($e in @($Existing)) { if ($null -ne $e) { @{ id = [string]$e['id']; targetType = [string]$e['targetType'] } } })
    if (-not ($list | Where-Object { $_['id'] -eq $GroupId })) { $list += @{ id = $GroupId; targetType = 'group' } }
    return , $list
}

function Invoke-Section {
    # Plan -> (optional) PATCH -> re-read -> verify, for one configuration.
    # ConfirmImpact High: with -Apply each PATCH asks for confirmation unless
    # -Confirm:$false - these settings change sign-in for every user.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Desired,
        $Current
    )
    if ($OfflinePreview) {
        Write-Host "  PATCH $Uri" -ForegroundColor DarkYellow
        Write-Host ($Desired | ConvertTo-Json -Depth 20) -ForegroundColor DarkGray
        Add-Result $Name 'INFO' 'offline preview (desired JSON above)'
        return
    }
    $drift = Get-Drift -Current $Current -Desired $Desired
    if ($drift.Count -eq 0) { Add-Result $Name 'PASS' 'in sync with desired state'; return }
    Add-Result $Name 'INFO' "drift in: $($drift -join ', ')"
    Write-Verbose ("Desired body for ${Name}:`n" + ($Desired | ConvertTo-Json -Depth 20))
    if (-not $Apply) { Add-Result $Name 'WARN' 'not applied (plan only; re-run with -Apply)'; return }
    if (-not $PSCmdlet.ShouldProcess($Name, "PATCH $Uri ($($drift -join ', '))")) { Add-Result $Name 'INFO' 'skipped (WhatIf/declined)'; return }
    try {
        Invoke-Graph -Method PATCH -Uri $Uri -Body $Desired | Out-Null
        # Read-after-write: report what the service holds, not what we sent.
        $after = Invoke-Graph -Method GET -Uri $Uri
        $left = Get-Drift -Current $after -Desired $Desired
        if ($left.Count -eq 0) { Add-Result $Name 'PASS' 'applied and verified by re-read' }
        else { Add-Result $Name 'FAIL' "applied, but re-read still differs in: $($left -join ', ')" }
    }
    catch { Add-Result $Name 'FAIL' "PATCH failed: $($_.Exception.Message)" }
}

# =============================================================================
# 1. CONNECT (skipped for -OfflinePreview)
# =============================================================================
# Refuse a PIM-for-Groups group as an admin target before anything is read:
# eligible-only membership means nobody is in it when the key is needed.
$pimTargets = @($AdminGroupMailNicknames | Where-Object { Test-PimGovernedNickname $_ })
if ($pimTargets) {
    throw "Refusing admin passkey target(s) $($pimTargets -join ', '): PIM-for-Groups groups have no standing members. An eligible adm- account is a member only DURING an activation, which it must pass the phishing-resistant step-up (CA021 / CA002) to start, so a passkey target there covers nobody when the key is registered or used. Target the standing Admin-Accounts group (modules/groups) instead."
}
$requiredScopes = @('Policy.Read.All', 'Group.Read.All')
if ($Apply) { $requiredScopes += 'Policy.ReadWrite.AuthenticationMethod' }
if ($DisableSmsVoice) { $requiredScopes += 'AuditLog.Read.All' }
if (@($AdminAllowedAaguids).Count -gt 0) { $requiredScopes += 'UserAuthenticationMethod.Read.All' }
if ($BuildAccountUpn) { $requiredScopes += 'User.Read.All' }
if (-not $OfflinePreview) {
    $ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
    if (-not $ctx) { Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext }
    $missingScopes = @($requiredScopes | Where-Object { $ctx.Scopes -and $_ -notin $ctx.Scopes })
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Calls needing them will return 403." }
}
else { Write-Console 'OFFLINE PREVIEW - no Graph connection; group ids are placeholders resolved by mailNickname on a real run.' -ForegroundColor DarkYellow }
Write-Console "Mode: $(if ($OfflinePreview) { 'offline preview' } elseif ($Apply) { 'APPLY' } else { 'plan (read-only)' }); staff rollout: $([bool]$IncludeStaffRollout); disable SMS/voice: $([bool]$DisableSmsVoice)" -ForegroundColor Cyan

# =============================================================================
# 2. RESOLVE GROUPS
# =============================================================================
Write-Console "`n[1/7] Target groups" -ForegroundColor Cyan
function Resolve-GroupId {
    param([string]$MailNickname)
    if ($OfflinePreview) { return "<groupId: $MailNickname>" }
    $f = [uri]::EscapeDataString("mailNickname eq '$($MailNickname.Replace("'", "''"))'")
    $g = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id,displayName")
    if ($g.Count -eq 1) { return [string]$g[0]['id'] }
    if ($g.Count -gt 1) { throw "mailNickname '$MailNickname' matches $($g.Count) groups; fix the duplicate first." }
    return $null
}
$bgGroupId = Resolve-GroupId $BreakGlassGroupMailNickname
if (-not $bgGroupId) { throw "Break-glass group '$BreakGlassGroupMailNickname' not found. Apply Terraform envs/dev (enable_premium) and run 01-Verify-Baseline.ps1 first." }
Add-Result 'Group break-glass' 'PASS' $BreakGlassGroupMailNickname

$adminGroupIds = [ordered]@{}
foreach ($nick in $AdminGroupMailNicknames) {
    $id = Resolve-GroupId $nick
    if ($id) { $adminGroupIds[$nick] = $id; Add-Result "Group $nick" 'PASS' 'admin profile target (standing members)' }
    elseif ($nick -eq 'admin-accounts') { Add-Result "Group $nick" 'FAIL' 'missing - apply Terraform envs/dev (enable_premium; modules/groups Admin-Accounts). Without it no admin account has a passkey target' }
    elseif ($nick -eq 'pim-azure-rg-contributors') { Add-Result "Group $nick" 'INFO' 'not found - skipped (exists only with enable_pim_azure_resources = true)' }
    else { Add-Result "Group $nick" 'WARN' 'not found - skipped' }
}
# Workforce groups are resolved even without the rollout flag, so a target an
# earlier rollout created is recognised as ours and left alone (never removed:
# that would cut its members off from passkeys they already use).
$staffGroupIds = [ordered]@{}
foreach ($nick in $StaffGroupMailNicknames) {
    $id = Resolve-GroupId $nick
    if ($id) {
        $staffGroupIds[$nick] = $id
        if ($IncludeStaffRollout) { Add-Result "Group $nick" 'PASS' 'workforce profile target' }
    }
    elseif ($IncludeStaffRollout) { Add-Result "Group $nick" 'WARN' 'missing - workforce passkey target and campaign skipped for it (groups module wiring, enable_phishing_resistant_all_users)' }
}
# Admin assurance guard. The workforce profile allows SYNCED passkeys, and an
# HR-synced admin is in All-Workforce too; profiles are "any in scope
# satisfies", so only the AAGUID allow-list on the admin strength (CA002 /
# CA021 / CA022, same list as -AdminAllowedAaguids) keeps a synced passkey off admin
# sign-ins. No list -> the rollout would silently lower admin assurance.
$staffBlocked = $false
if ($IncludeStaffRollout -and @($AdminAllowedAaguids).Count -eq 0) {
    if ($AcceptAdminSyncedPasskeyRisk) {
        Add-Result 'Admin assurance' 'WARN' 'workforce rollout with NO admin AAGUID allow-list: admins can satisfy CA002/CA021/CA022 with a synced passkey (risk accepted via -AcceptAdminSyncedPasskeyRisk; record it in the risk register)'
    }
    elseif ($OfflinePreview) {
        # Preview shows the JSON either way; a real run would refuse the staff target.
        Add-Result 'Admin assurance' 'WARN' 'a real run would FAIL here: workforce rollout without -AdminAllowedAaguids (or -AcceptAdminSyncedPasskeyRisk) leaves admins able to satisfy CA002 with a synced passkey'
    }
    else {
        Add-Result 'Admin assurance' 'FAIL' 'workforce rollout without -AdminAllowedAaguids: admins in All-Workforce could register a SYNCED passkey that CA002 accepts. Pass the issued key models (same list as Terraform admin_fido2_allowed_aaguids) or -AcceptAdminSyncedPasskeyRisk. Workforce target NOT applied this run.'
        $staffBlocked = $true
    }
}
# Groups this run TARGETS with the workforce profile and the campaign.
$staffTargetIds = @(if ($IncludeStaffRollout -and -not $staffBlocked) { $staffGroupIds.Values })   # @(): never $null, never a stray element
Add-Result 'Admin targets' 'INFO' 'standing groups only (Admin-Accounts, PIM-Azure-RG-Contributors); PIM-for-Groups groups are refused - their eligible members are not in them when the key is needed'

# Build account: its groups, read once for the coverage check at the end.
$buildUser = $null; $buildGroupIds = @()
if ($BuildAccountUpn -and -not $OfflinePreview) {
    try {
        $buildUser = Invoke-Graph -Method GET -Uri "$graph/users/$([uri]::EscapeDataString($BuildAccountUpn))?`$select=id,userPrincipalName"
        $buildGroupIds = @(Get-GraphCollection -Uri "$graph/users/$([string]$buildUser['id'])/transitiveMemberOf?`$select=id" | ForEach-Object { [string]$_['id'] })
        if ([string]$buildUser['id'] -and @($adminGroupIds.Values | Where-Object { $_ -in $buildGroupIds }).Count -eq 0) {
            Add-Result 'Build account' 'FAIL' "$BuildAccountUpn is in no admin passkey target group: it could not register or use an admin passkey, so it could never satisfy CA021 / CA002. Add it to Admin-Accounts (post-apply/New-AdminAccounts.ps1 -BuildAccountUpn)"
        }
        else { Add-Result 'Build account' 'PASS' "$BuildAccountUpn is a member of an admin passkey target group" }
    }
    catch { Add-Result 'Build account' 'FAIL' "could not read $BuildAccountUpn or its groups: $($_.Exception.Message)"; $buildUser = $null }
}

# =============================================================================
# 3. READ THE POLICY
# =============================================================================
Write-Console "`n[2/7] Authentication methods policy" -ForegroundColor Cyan
$policy = $null
$configs = @{}
if (-not $OfflinePreview) {
    $policy = Invoke-Graph -Method GET -Uri $amp
    foreach ($c in @($policy['authenticationMethodConfigurations'])) { if ($c) { $configs[[string]$c['id']] = $c } }
    # Method ids are case-insensitive in the API ("Fido2" / "fido2").
    $configs = [System.Collections.Hashtable]::new($configs, [System.StringComparer]::OrdinalIgnoreCase)
    $migration = [string]$policy['policyMigrationState']
    if ($migration -eq 'migrationComplete') { Add-Result 'Policy migration' 'PASS' 'migrationComplete - legacy MFA/SSPR method settings are ignored' }
    else { Add-Result 'Policy migration' 'WARN' "state '$migration' - finish the legacy MFA/SSPR migration in the portal so this policy is the only source of truth" }
}

# =============================================================================
# 4. PASSKEYS (FIDO2) + PASSKEY PROFILES
# =============================================================================
Write-Console "`n[3/7] Passkeys (FIDO2) and passkey profiles" -ForegroundColor Cyan
$fido2Uri = "$amp/authenticationMethodConfigurations/fido2"
$fido2 = if ($OfflinePreview) { $null } else { $configs['fido2'] }
$fido2Ready = $true
if (-not $OfflinePreview -and -not $fido2) { Add-Result 'Passkeys' 'FAIL' 'fido2 configuration missing from the policy read'; $fido2Ready = $false }
elseif (-not $OfflinePreview -and $null -eq (Get-Field $fido2 @('passkeyProfiles'))) {
    # verify: whether a PATCH with passkeyProfiles opts the tenant in. The
    # documented opt-in is the portal banner and it is irreversible.
    Add-Result 'Passkeys' 'FAIL' 'passkey profiles are not turned on. Entra admin center > Authentication methods > Policies > Passkey (FIDO2) > banner link (irreversible), then re-run'
    $fido2Ready = $false
}
if ($fido2Ready) {
    $adminProfileId = Get-NameBasedGuid $AdminProfileName
    $staffProfileId = Get-NameBasedGuid $StaffProfileName
    $existingProfiles = @(if ($fido2) { @(Get-Field $fido2 @('passkeyProfiles')) | Where-Object { $null -ne $_ } })
    # Reuse an existing profile's id when one with our name already exists
    # (e.g. created in the portal), so we update it instead of adding a twin.
    foreach ($p in $existingProfiles) {
        if ([string]$p['name'] -eq $AdminProfileName) { $adminProfileId = [string]$p['id'] }
        if ([string]$p['name'] -eq $StaffProfileName) { $staffProfileId = [string]$p['id'] }
    }
    $aaguids = @($AdminAllowedAaguids | ForEach-Object { $_.ToLowerInvariant() })
    $adminProfile = [ordered]@{
        id                     = $adminProfileId
        name                   = $AdminProfileName
        passkeyTypes           = 'deviceBound'
        attestationEnforcement = 'registrationOnly'
        keyRestrictions        = [ordered]@{ isEnforced = ($aaguids.Count -gt 0); enforcementType = 'allow'; aaGuids = $aaguids }
    }
    $staffProfile = [ordered]@{
        id                     = $staffProfileId
        name                   = $StaffProfileName
        passkeyTypes           = 'deviceBound,synced'
        attestationEnforcement = 'disabled'   # synced passkeys cannot be attested
        keyRestrictions        = [ordered]@{ isEnforced = $false; enforcementType = 'allow'; aaGuids = @() }
    }
    # Send the whole collection: untouched profiles (incl. the non-deletable
    # Default) + ours. The staff profile is created only with the rollout flag.
    $profiles = @(foreach ($p in $existingProfiles) { if ([string]$p['id'] -notin @($adminProfileId, $staffProfileId)) { $p } })
    $profiles += $adminProfile
    $wantStaffProfile = ($IncludeStaffRollout -and -not $staffBlocked) -or @($existingProfiles | Where-Object { [string]$_['id'] -eq $staffProfileId }).Count -gt 0
    if ($wantStaffProfile) { $profiles += $staffProfile }

    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($gid in (@($bgGroupId) + @($adminGroupIds.Values))) {
        $targets.Add([ordered]@{ targetType = 'group'; id = $gid; isRegistrationRequired = $false; allowedPasskeyProfiles = @($adminProfileId) })
    }
    foreach ($gid in $staffTargetIds) {
        $targets.Add([ordered]@{ targetType = 'group'; id = $gid; isRegistrationRequired = $false; allowedPasskeyProfiles = @($staffProfileId) })
    }
    foreach ($t in @(if ($fido2) { @(Get-Field $fido2 @('includeTargets')) | Where-Object { $null -ne $_ } })) {
        $tid = [string]$t['id']
        if ($tid -in (@($bgGroupId) + @($adminGroupIds.Values) + $staffTargetIds)) { continue }
        if ($tid -in @($staffGroupIds.Values)) {
            # Workforce target from an earlier rollout, flag now off: keep as is.
            $targets.Add($t); Add-Result 'Passkeys' 'INFO' "keeping existing workforce target '$tid' (rollout flag off; never removed by this script)"
            continue
        }
        if ($ReplaceExistingTargets) { Add-Result 'Passkeys' 'WARN' "removing unmanaged include target '$($t['id'])' (-ReplaceExistingTargets): its members lose passkey sign-in unless another target covers them" }
        else {
            $targets.Add($t)
            $note = if ([string]$t['id'] -eq 'all_users') { ' - all_users puts break-glass in scope of that target''s profiles too (invariant check below)' } else { '' }
            Add-Result 'Passkeys' 'WARN' "keeping unmanaged include target '$($t['id'])'$note"
        }
    }
    $fido2Desired = [ordered]@{
        '@odata.type'                    = '#microsoft.graph.fido2AuthenticationMethodConfiguration'
        state                            = 'enabled'
        isSelfServiceRegistrationAllowed = $true
        passkeyProfiles                  = $profiles
        includeTargets                   = $targets.ToArray()
    }
    if (@($profiles).Count -gt 3) { Add-Result 'Passkeys' 'WARN' "$(@($profiles).Count) passkey profiles; Microsoft Learn documents a limit of three including Default (verify)" }

    # KEY-MODEL GUARD (before anything is sent). Break-glass is FIDO2-only and
    # scoped ONLY to the admin profile; an enforced AAGUID allow-list there
    # also stops sign-in with keys that are already registered (verify:
    # Learn, passkey profile key restrictions). A break-glass key outside the
    # list would therefore lock break-glass out: refuse the passkey PATCH.
    $keyGuardOk = $true
    if ($aaguids.Count -gt 0 -and -not $OfflinePreview) {
        $desiredForCheck = @{ state = 'enabled'; passkeyProfiles = $profiles; includeTargets = $targets.ToArray() }
        try {
            $bgUsers = @(Get-GraphCollection -Uri "$graph/groups/$bgGroupId/members?`$select=id,userPrincipalName")
            foreach ($u in $bgUsers) {
                $keys = @(Get-GraphCollection -Uri "$graph/users/$([string]$u['id'])/authentication/fido2Methods")
                $cov = Test-PasskeyCoverage -Fido2Config $desiredForCheck -GroupIds @($bgGroupId) -Keys $keys
                if ($cov.RejectedAaguids.Count -gt 0) {
                    $keyGuardOk = $false
                    Add-Result 'BG: key models' 'FAIL' "$([string]$u['userPrincipalName']): $($cov.RejectedAaguids.Count) registered key(s) of a model outside -AdminAllowedAaguids ($(@($cov.RejectedAaguids | Sort-Object -Unique) -join ', ')). Enforcing the list would block them and lock break-glass out. Add the model to the list (and Terraform admin_fido2_allowed_aaguids) or re-key break-glass first"
                }
            }
            if ($keyGuardOk) { Add-Result 'BG: key models' 'PASS' "every registered break-glass key ($(@($bgUsers).Count) account(s)) is a model on the admin allow-list" }
        }
        catch { $keyGuardOk = $false; Add-Result 'BG: key models' 'FAIL' "could not read break-glass keys ($($_.Exception.Message)); an allow-list cannot be enforced blind" }
        # Admin-target members: a key outside the list stops working for that
        # person; they can re-register with TAP, so WARN, not FAIL.
        foreach ($nick in @($adminGroupIds.Keys)) {
            try {
                $members = @(Get-GraphCollection -Uri "$graph/groups/$($adminGroupIds[$nick])/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName")
                $hit = 0
                foreach ($u in $members) {
                    $keys = @(Get-GraphCollection -Uri "$graph/users/$([string]$u['id'])/authentication/fido2Methods")
                    $cov = Test-PasskeyCoverage -Fido2Config $desiredForCheck -GroupIds @($adminGroupIds[$nick]) -Keys $keys
                    if ($cov.RejectedAaguids.Count -gt 0) { $hit++ }
                }
                if ($hit) { Add-Result "Key models $nick" 'WARN' "$hit member(s) hold a key outside the allow-list; it stops working once enforced (re-register an issued model, TAP if needed)" }
            }
            catch { Add-Result "Key models $nick" 'WARN' "could not read members' keys: $($_.Exception.Message)" }
        }
    }
    if ($keyGuardOk) { Invoke-Section -Name 'Passkeys (FIDO2)' -Uri $fido2Uri -Desired $fido2Desired -Current $fido2 }
    else { Add-Result 'Passkeys (FIDO2)' 'FAIL' 'NOT sent: the break-glass key-model guard failed (see BG: key models)' }
}

# =============================================================================
# 5. TEMPORARY ACCESS PASS
# =============================================================================
Write-Console "`n[4/7] Temporary Access Pass" -ForegroundColor Cyan
$tap = if ($OfflinePreview) { $null } else { $configs['TemporaryAccessPass'] }
$tapDesired = [ordered]@{
    '@odata.type'            = '#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration'
    state                    = 'enabled'
    defaultLifetimeInMinutes = $TapDefaultLifetimeMinutes
    minimumLifetimeInMinutes = $TapMinimumLifetimeMinutes
    maximumLifetimeInMinutes = $TapMaximumLifetimeMinutes
    defaultLength            = $TapDefaultLength
    isUsableOnce             = $TapIsUsableOnce
    includeTargets           = @([ordered]@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false })
    excludeTargets           = (Merge-ExcludeTarget -Existing (Get-Field $tap @('excludeTargets')) -GroupId $bgGroupId)
}
if ($TapMaximumLifetimeMinutes -lt 480) { Add-Result 'TAP' 'WARN' "maximum $TapMaximumLifetimeMinutes min is below the joiner workflow's 480-minute TAP; that task will fail" }
Invoke-Section -Name 'Temporary Access Pass' -Uri "$amp/authenticationMethodConfigurations/TemporaryAccessPass" -Desired $tapDesired -Current $tap

# =============================================================================
# 6. MICROSOFT AUTHENTICATOR
# =============================================================================
Write-Console "`n[5/7] Microsoft Authenticator" -ForegroundColor Cyan
$ma = if ($OfflinePreview) { $null } else { $configs['MicrosoftAuthenticator'] }
$contextOn = [ordered]@{
    state         = 'enabled'
    includeTarget = [ordered]@{ targetType = 'group'; id = 'all_users' }
    excludeTarget = [ordered]@{ targetType = 'group'; id = '00000000-0000-0000-0000-000000000000' }
}
$maDesired = [ordered]@{
    '@odata.type'         = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration'
    state                 = 'enabled'
    isSoftwareOathEnabled = $false   # OTP codes are phishable; push + passkeys only
    featureSettings       = [ordered]@{
        displayAppInformationRequiredState      = $contextOn
        displayLocationInformationRequiredState = $contextOn
    }
    includeTargets        = @([ordered]@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false; authenticationMode = 'any' })
    excludeTargets        = (Merge-ExcludeTarget -Existing (Get-Field $ma @('excludeTargets')) -GroupId $bgGroupId)
}
Add-Result 'Authenticator' 'INFO' 'number matching: always on for push (service-enforced, not a v1.0 setting - verify)'
Invoke-Section -Name 'Microsoft Authenticator' -Uri "$amp/authenticationMethodConfigurations/MicrosoftAuthenticator" -Desired $maDesired -Current $ma

# =============================================================================
# 7. REGISTRATION CAMPAIGN (passkey nudge)
# =============================================================================
Write-Console "`n[6/7] Registration campaign (passkey)" -ForegroundColor Cyan
$campaignTargets = @(foreach ($gid in (@($adminGroupIds.Values) + $staffTargetIds)) {
        [ordered]@{ id = $gid; targetType = 'group'; targetedAuthenticationMethod = 'Fido2' }
    })
$currentCampaign = Get-Field $policy @('registrationEnforcement', 'authenticationMethodsRegistrationCampaign')
if ($campaignTargets.Count -eq 0) { Add-Result 'Campaign' 'WARN' 'no admin or workforce groups resolved; campaign not configured' }
else {
    $campaignDesired = [ordered]@{
        registrationEnforcement = [ordered]@{
            authenticationMethodsRegistrationCampaign = [ordered]@{
                state                = 'enabled'
                snoozeDurationInDays = $CampaignSnoozeDays
                includeTargets       = $campaignTargets
                excludeTargets       = (Merge-ExcludeTarget -Existing (Get-Field $currentCampaign @('excludeTargets')) -GroupId $bgGroupId)
            }
        }
    }
    Invoke-Section -Name 'Registration campaign' -Uri $amp -Desired $campaignDesired -Current $policy
}

# =============================================================================
# 8. SMS / VOICE (gated, fail-closed) + REPORT SUSPICIOUS ACTIVITY (gated, beta)
# =============================================================================
Write-Console "`n[7/7] SMS / voice and report suspicious activity" -ForegroundColor Cyan
$disableApproved = $false
if (-not $DisableSmsVoice) {
    $smsState = if ($OfflinePreview) { 'unknown (offline)' } else { [string](Get-Field $configs['Sms'] @('state')) }
    $voiceState = if ($OfflinePreview) { 'unknown (offline)' } else { [string](Get-Field $configs['Voice'] @('state')) }
    Add-Result 'SMS/voice' 'INFO' "state left as is (sms: $smsState, voice: $voiceState). Microsoft-provided SMS/voice MFA ends 1 Feb 2027 (1 Jul 2027 for Global Admins/external users); plan the switch with -DisableSmsVoice after the campaign"
}
else {
    $dependent = 0; $checkOk = $true
    if (-not $OfflinePreview) {
        try {
            # Users whose ONLY registered methods are phone-based would be left
            # without MFA. Break-glass is excluded (FIDO2-only by design).
            $bgMembers = @(Get-GraphCollection -Uri "$graph/groups/$bgGroupId/members?`$select=id" | ForEach-Object { [string]$_['id'] })
            $phoneOnly = @('mobilePhone', 'alternateMobilePhone', 'officePhone')
            $reg = @(Get-GraphCollection -Uri "$graph/reports/authenticationMethods/userRegistrationDetails")
            foreach ($r in $reg) {
                if ([string]$r['id'] -in $bgMembers) { continue }
                $m = @(@($r['methodsRegistered']) | Where-Object { $_ })
                if ($m.Count -gt 0 -and @($m | Where-Object { $_ -notin $phoneOnly }).Count -eq 0) { $dependent++ }
            }
        }
        catch { $checkOk = $false; Add-Result 'SMS/voice' 'FAIL' "pre-check could not read the registration report: $($_.Exception.Message) - not disabling" }
    }
    if ($checkOk -and $dependent -gt 0) {
        Add-Result 'SMS/voice' 'FAIL' "$dependent user(s) have only phone methods; disabling would strand them. Run the campaign, re-check with 07-Passwordless-Rollout.ps1, then retry"
    }
    elseif ($checkOk) { $disableApproved = $true }
}
# Whatever happens to the methods themselves, break-glass is excluded from
# both (it is FIDO2-only); while they stay enabled, that exclusion is the
# only thing between a phone number and a standing Global Admin.
foreach ($m in @(@{ Id = 'Sms'; Type = '#microsoft.graph.smsAuthenticationMethodConfiguration' }, @{ Id = 'Voice'; Type = '#microsoft.graph.voiceAuthenticationMethodConfiguration' })) {
    $cur = if ($OfflinePreview) { $null } else { $configs[$m.Id] }
    $desired = [ordered]@{ '@odata.type' = $m.Type; excludeTargets = (Merge-ExcludeTarget -Existing (Get-Field $cur @('excludeTargets')) -GroupId $bgGroupId) }
    if ($disableApproved) { $desired['state'] = 'disabled' }
    Invoke-Section -Name "$($m.Id) method" -Uri "$amp/authenticationMethodConfigurations/$($m.Id)" -Desired $desired -Current $cur
}
if ($EnableReportSuspiciousActivity) {
    # verify: beta-only property; shape from the beta authenticationMethodsPolicy resource.
    $rsaDesired = [ordered]@{
        reportSuspiciousActivitySettings = [ordered]@{
            state              = 'enabled'
            includeTarget      = [ordered]@{ targetType = 'group'; id = 'all_users' }
            voiceReportingCode = 0
        }
    }
    $betaPolicy = $null
    if (-not $OfflinePreview) {
        try { $betaPolicy = Invoke-Graph -Method GET -Uri "$graphBeta/policies/authenticationMethodsPolicy" }
        catch { Add-Result 'Report suspicious activity' 'WARN' "beta read failed: $($_.Exception.Message)" }
    }
    if ($OfflinePreview -or $betaPolicy) {
        Invoke-Section -Name 'Report suspicious activity (beta)' -Uri "$graphBeta/policies/authenticationMethodsPolicy" -Desired $rsaDesired -Current $betaPolicy
    }
}
else { Add-Result 'Report suspicious activity' 'INFO' 'not managed (pass -EnableReportSuspiciousActivity with enable_identity_protection_ca)' }

# =============================================================================
# 9. BREAK-GLASS INVARIANTS (on the state the service holds now)
# =============================================================================
Write-Console "`nBreak-glass invariants" -ForegroundColor Cyan
if ($OfflinePreview) { Add-Result 'Break-glass invariants' 'INFO' 'checked against the live policy on a real run' }
else {
    $now = Invoke-Graph -Method GET -Uri $amp
    $live = @{}
    foreach ($c in @($now['authenticationMethodConfigurations'])) { if ($c) { $live[[string]$c['id']] = $c } }
    $live = [System.Collections.Hashtable]::new($live, [System.StringComparer]::OrdinalIgnoreCase)

    $f2 = $live['fido2']
    $bgTarget = @(@(Get-Field $f2 @('includeTargets')) | Where-Object { $_ -and [string]$_['id'] -eq $bgGroupId }) | Select-Object -First 1
    $liveAdminProfile = @(@(Get-Field $f2 @('passkeyProfiles')) | Where-Object { $_ -and [string]$_['name'] -eq $AdminProfileName }) | Select-Object -First 1
    $allUsersTarget = @(@(Get-Field $f2 @('includeTargets')) | Where-Object { $_ -and [string]$_['id'] -eq 'all_users' }).Count -gt 0
    if ([string](Get-Field $f2 @('state')) -ne 'enabled' -or -not $bgTarget) {
        Add-Result 'BG: passkeys enabled' 'FAIL' 'Break-Glass-Admins is not an include target of an enabled passkey policy (human step 6 is not done)'
    }
    elseif (-not $liveAdminProfile -or @($bgTarget['allowedPasskeyProfiles']).Count -ne 1 -or [string]@($bgTarget['allowedPasskeyProfiles'])[0] -ne [string]$liveAdminProfile['id']) {
        Add-Result 'BG: passkeys enabled' 'FAIL' 'Break-Glass-Admins is not scoped to ONLY the attested admin profile'
    }
    elseif ($allUsersTarget) {
        Add-Result 'BG: passkeys enabled' 'FAIL' 'an all_users passkey target also covers break-glass with its profiles; remove it (-ReplaceExistingTargets) once Admin-Accounts and the workforce targets exist'
    }
    else { Add-Result 'BG: passkeys enabled' 'PASS' 'attested device-bound profile only' }

    # Admin coverage: every standing admin group is a target on the admin
    # profile, and the build account is covered by some target.
    foreach ($nick in @($adminGroupIds.Keys)) {
        $t = @(@(Get-Field $f2 @('includeTargets')) | Where-Object { $_ -and [string]$_['id'] -eq $adminGroupIds[$nick] }) | Select-Object -First 1
        if (-not $t -or -not $liveAdminProfile -or [string]$liveAdminProfile['id'] -notin @($t['allowedPasskeyProfiles'] | ForEach-Object { [string]$_ })) {
            Add-Result "Admin target $nick" 'FAIL' 'not an include target scoped to the admin profile: its members cannot register or use an admin passkey'
        }
        else { Add-Result "Admin target $nick" 'PASS' 'include target on the admin profile' }
    }
    if ($buildUser) {
        $cov = Test-PasskeyCoverage -Fido2Config $f2 -GroupIds $buildGroupIds
        if ($cov.Covered) { Add-Result 'Build account passkey target' 'PASS' "covered by $($cov.TargetIds -join ', ')" }
        else { Add-Result 'Build account passkey target' 'FAIL' "$BuildAccountUpn - $($cov.Reason)" }
    }

    foreach ($m in 'TemporaryAccessPass', 'MicrosoftAuthenticator', 'Sms', 'Voice') {
        $cfg = $live[$m]
        if (-not $cfg -or [string]$cfg['state'] -ne 'enabled') { Add-Result "BG: excluded from $m" 'PASS' 'method disabled'; continue }
        $ex = @(@(Get-Field $cfg @('excludeTargets')) | Where-Object { $_ -and [string]$_['id'] -eq $bgGroupId }).Count -gt 0
        if ($ex) { Add-Result "BG: excluded from $m" 'PASS' 'excluded' }
        else { Add-Result "BG: excluded from $m" 'FAIL' 'break-glass can use or be issued this method' }
    }
    $camp = Get-Field $now @('registrationEnforcement', 'authenticationMethodsRegistrationCampaign')
    if ([string](Get-Field $camp @('state')) -ne 'enabled') { Add-Result 'BG: excluded from campaign' 'PASS' 'campaign not enabled' }
    elseif (@(@(Get-Field $camp @('excludeTargets')) | Where-Object { $_ -and [string]$_['id'] -eq $bgGroupId }).Count -gt 0) { Add-Result 'BG: excluded from campaign' 'PASS' 'excluded' }
    else { Add-Result 'BG: excluded from campaign' 'FAIL' 'campaign would nudge break-glass to register methods' }
}

# =============================================================================
# SUMMARY
# =============================================================================
$fails = @($results | Where-Object Status -eq 'FAIL').Count
$warns = @($results | Where-Object Status -eq 'WARN').Count
Write-Console "`nAuthentication methods policy: $fails FAIL, $warns WARN" -ForegroundColor $(if ($fails) { 'Red' } elseif ($warns) { 'Yellow' } else { 'Green' })
if ($fails) { exit 1 }
exit 0
