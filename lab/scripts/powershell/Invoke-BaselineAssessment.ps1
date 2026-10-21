<#
.SYNOPSIS
    Runs (or imports) CISA ScubaGear for Entra ID and Microsoft's Zero Trust
    Assessment before and after the lab is applied, hashes every output
    (SHA-256), keeps the raw reports private, writes a public-safe summary that
    maps each ScubaGear MS.AAD policy to the lab control that answers it, and
    copies everything to the WORM evidence store.

.DESCRIPTION
    Why: "Zero Trust" and "secure baseline" are claims until something
    independent measures them. ScubaGear is CISA's own assessment of the
    SCuBA Entra ID baseline (the BOD 25-01 checks); the Zero Trust Assessment
    is Microsoft's. Running both BEFORE the premium apply and AFTER the
    policies have graduated turns the lab's design into a measured delta:
    which MS.AAD controls moved from Fail to Pass, which stayed failing, and
    why (the mapping says, per control, which lab control and staging flag
    answers it and what result to expect).

    WHAT IT DOES, IN ORDER
      1. ScubaGear (-ProductNames aad). ScubaGear runs only in Windows
         PowerShell 5.1 on Windows, so on Windows this script starts it in a
         powershell.exe child process; anywhere else, run ScubaGear on a
         Windows machine and pass its output folder with -ScubaResultsPath.
         A generated config documents the break-glass group as the ONLY
         Conditional Access exclusion (CapExclusions) and the only permanent
         Global Administrator (RoleExclusions for MS.AAD.7.4), which is how
         CISA expects emergency-access accounts to be declared. Nothing else
         is excluded or omitted, so the results are not tuned to pass.
      2. Zero Trust Assessment (Invoke-ZtAssessment -Pillar Identity, PS 7).
         Or pass a finished run with -ZeroTrustResultsPath.
      3. Raw outputs -> lab/evidence/out/assessments/<RunId>-<Phase>/
         (gitignored: they name the tenant, users and policies).
         manifest.json + SHA256SUMS (shasum -a 256 -c compatible) hash every
         raw file.
      4. Public summary -> lab/evidence/assessments/<RunId>-<Phase>/
         summary.json + SUMMARY.md: control IDs, results, criticality, lab
         mapping, KPIs, before/after delta and the raw files' SHA-256. No
         tenant id, domain, user, policy detail text or IP. Committing it puts
         the hashes in git history: anyone can later check the private WORM
         copy against them. ONLY for a tenant run: the tenant id each tool
         recorded is read (then dropped) first, and input from CISA's
         published sample, a test fixture, a CSV-only import (names no
         tenant) or two different tenants is a non-tenant run - its summary
         goes to lab/evidence/out/assessments-summary/ (gitignored) with
         source.kind = non-tenant, and an explicit -PublicOutputRoot inside
         lab/evidence is refused. A before/after delta is only computed
         between two runs of the same kind.
      5. Upload raw + public files to the WORM container (az CLI, Entra auth,
         --overwrite false) under assessments/<RunId>-<Phase>/. Versioning +
         the account immutability policy keep every upload unmodifiable.

    DATA MINIMISATION: from the Zero Trust Assessment only the HTML report and
    ZeroTrustAssessmentReport.json are kept as evidence. Its zt-export working
    folder (raw tenant export, sign-in logs) stays in _work/, is not hashed or
    uploaded, and should be deleted after the run (Microsoft's own guidance):
    immutable storage would otherwise keep personal data for the full
    retention period with no way to erase it.

    FAIL-OPEN, NEVER SILENT: if one tool fails or cannot run on this OS, its
    status is recorded as failed/skipped with the reason in both summaries
    and the other tool still runs. The script exits 1 if any selected tool
    did not produce results or any upload failed.

    NOT RUN AGAINST A TENANT YET. The parsing was checked offline against
    CISA's published ScubaGear v1.8.0 sample report and a synthetic Zero Trust
    fixture (both recognised as non-tenant input, so a rehearsal can never
    write into lab/evidence); the run paths (child-process ScubaGear,
    Invoke-ZtAssessment, az upload) are written from the vendors'
    documentation and are tenant-time steps (lab/docs/evidence-capture-plan.md).

.PREREQUISITES
    * PowerShell 7 (this script).
    * ScubaGear (Windows only): Install-Module ScubaGear; Install-ScubaDependencies
      (formerly Initialize-SCuBA; installs OPA). Checked against v1.8.0.
    * Zero Trust Assessment: Install-Module ZeroTrustAssessment -Scope CurrentUser
      (PS 7; not supported on Windows on ARM64). First run needs a Global
      Administrator to consent; later runs need Global Reader + Security Reader
      (Exchange/SharePoint roles only for those pillars).
    * Optional: Microsoft.Graph.Authentication (resolves the break-glass group
      id when -BreakGlassGroupObjectId is not given; scope Group.Read.All).
    * Upload: Azure CLI, `az login` as an identity holding Storage Blob Data
      Contributor (no-delete ABAC condition) on the evidence container, from
      an IP the storage firewall admits (modules/evidence-store header).

.GRAPH SCOPES
    This script itself asks only for Group.Read.All (read-only), and only to
    look up the break-glass group. ScubaGear and Connect-ZtAssessment request
    their own read scopes on sign-in.

.PARAMETER Phase
    before     - baseline: licences assigned, premium layer NOT yet applied.
    after      - after apply AND after the CA policies have graduated.
    checkpoint - any other point (e.g. right after the report-only apply).

.PARAMETER Tools
    ScubaGear, ZeroTrust, or both (default).

.PARAMETER ScubaResultsPath
    Import a finished ScubaGear run: its output folder (the one holding
    ScubaResults_*.json) or a parent of it. The folder is copied into the run
    and the copy is hash-checked against the source.

.PARAMETER ZeroTrustResultsPath
    Import a finished Zero Trust Assessment: its -Path folder (holding
    ZeroTrustAssessmentReport.html and zt-export/) or the results JSON itself.

.PARAMETER BreakGlassGroupObjectId
    Object id of Break-Glass-Admins, written into the ScubaGear config as the
    documented exclusion. Default: looked up by mailNickname via Graph.

.PARAMETER StorageAccountName / ContainerName
    WORM store (modules/evidence-store outputs). No account = no upload, with
    a warning; the public summary then says "not uploaded".

.PARAMETER BaselineSummaryPath
    Public summary.json to compare against. Default for -Phase after: the
    newest "before" run under -PublicOutputRoot.

.EXAMPLE
    # On the Windows admin workstation: both tools, then upload.
    ./Invoke-BaselineAssessment.ps1 -Phase before -StorageAccountName stidlabevidence7f3a -WhatIf
    ./Invoke-BaselineAssessment.ps1 -Phase before -StorageAccountName stidlabevidence7f3a

.EXAMPLE
    # On macOS: ScubaGear ran on Windows, folder copied over.
    ./Invoke-BaselineAssessment.ps1 -Phase after `
        -ScubaResultsPath ~/Downloads/M365BaselineConformance_2026_11_20_14_02_11 `
        -ZeroTrustResultsPath ~/ZeroTrustReport -StorageAccountName stidlabevidence7f3a

.OUTPUTS
    The public summary object (also written to summary.json).

.WHAT IT DEMONSTRATES
    Measured Zero Trust instead of described Zero Trust: an independent
    government baseline and a vendor assessment, run before and after, hashed
    at collection, stored write-once, and mapped control by control to the
    design that changed the result.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('before', 'after', 'checkpoint')]
    [string]$Phase,

    [Parameter()]
    [ValidateSet('ScubaGear', 'ZeroTrust')]
    [string[]]$Tools = @('ScubaGear', 'ZeroTrust'),

    [Parameter()]
    [string]$ScubaResultsPath,

    [Parameter()]
    [string]$ZeroTrustResultsPath,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$BreakGlassGroupObjectId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidateSet('All', 'Identity', 'Devices')]
    # Identity by default: it is what this lab builds, and it avoids the
    # Exchange/SharePoint sign-ins and roles the other pillars need.
    [string]$ZtPillar = 'Identity',

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$ZtDays = 30,

    [Parameter()]
    # Device code sign-in for Connect-ZtAssessment. CA010 (block device code
    # flow) blocks it once ENFORCED: use browser sign-in, or the CA010
    # exception group through the exception process.
    [switch]$UseDeviceCode,

    [Parameter()]
    # Use when Connect-ZtAssessment already ran in this session.
    [switch]$SkipZtConnect,

    [Parameter()]
    [ValidatePattern('^[0-9A-Za-z-]{1,40}$')]
    # Sortable UTC stamp: the newest "before" run is found by name.
    [string]$RunId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    # lab/scripts/powershell -> lab/evidence/out/assessments (gitignored by lab/evidence/out/)
    [string]$RawOutputRoot = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'evidence', 'out', 'assessments'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    # lab/scripts/powershell -> lab/evidence/assessments (public, committed).
    # Tenant runs only: a non-tenant run goes to lab/evidence/out/assessments-summary.
    [string]$PublicOutputRoot = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'evidence', 'assessments'),

    [Parameter()]
    [string]$BaselineSummaryPath,

    [Parameter()]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [Parameter()]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')]
    [string]$ContainerName = 'evidence',

    [Parameter()]
    [switch]$SkipUpload
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

$ToolVersion = '1.0.0'

# ScubaGear policy IDs that accept CapExclusions in the config file, as
# documented for v1.8.0 (configuration.md) with the version suffixes the
# v1.8.0 sample report uses (MS.AAD.3.2 is v2 there). verify: re-read
# docs/configuration/configuration.md when ScubaGear is upgraded - a key whose
# suffix no longer matches a policy is not applied.
$ScubaCapExclusionPolicyIds = @(
    'MS.AAD.1.1v1', 'MS.AAD.2.1v1', 'MS.AAD.2.3v1', 'MS.AAD.3.1v1', 'MS.AAD.3.2v2',
    'MS.AAD.3.6v1', 'MS.AAD.3.7v1', 'MS.AAD.3.8v1', 'MS.AAD.3.9v1'
)

# Inputs that are NOT a run against our tenant. The scrubber removes tenant ids
# from the public summary, so once written a summary built from CISA's
# published sample or a test fixture could no longer be told apart from a
# tenant run. Such a run (and any input naming no tenant, or two different
# tenants) never writes into the public evidence tree: its summary goes to
# lab/evidence/out/assessments-summary/ and records source.kind = non-tenant.
$NonTenantInputIds = @{
    'ca08493a-c9c8-4db0-a9e8-d3b4bafac269' = 'sample: CISA ScubaGear v1.8.0 published sample report'
    '99999999-8888-7777-6666-555555555555' = 'fixture: synthetic Zero Trust results (tests/Invoke-BaselineAssessment.Tests.ps1)'
}

# ===========================================================================
# MS.AAD -> lab control map. Keyed by the policy id WITHOUT its version
# suffix, so a baseline revision (v1 -> v2) still maps. Lab = what in this lab
# answers the control; Flag = the envs/dev staging flag that turns it on
# ("" = not built); Expect = the result to expect and why, written BEFORE any
# run so the after-run can be held to it. Unmapped ids are reported, never
# dropped.
# ===========================================================================
$ControlMap = [ordered]@{
    'MS.AAD.1.1' = @{ Lab = 'CA003 block legacy authentication; lab/kql/legacy-auth.kql'; Flag = 'enable_premium'; Expect = 'Pass once CA003 is enabled. Report-only does not satisfy it.' }
    # MS.AAD.2.1v1 reads "Users detected as high risk SHALL be blocked" (grant: Block Access). CA006 deliberately
    # self-remediates instead (MFA + secure password change), so this control is EXPECTED to fail: a documented
    # deviation, not a gap to close - unless a block-on-high-user-risk policy is added for CISA conformance.
    'MS.AAD.2.1' = @{ Lab = 'CA006 user risk high: MFA + secure password change (self-remediation, P2) - remediates, does NOT block'; Flag = 'enable_identity_protection_ca'; Expect = 'Fail expected: deliberate deviation. CA006 uses self-remediation (MFA + secure password change), not Block Access; record it as an accepted deviation (risk register / CA design ADR), do not count it as a regression.' }
    'MS.AAD.2.2' = @{ Lab = 'Risky-user detection: lab/kql/identity-risk.kql (AADRiskyUsers / AADUserRiskEvents), plus the Identity Protection risky-user email'; Flag = 'enable_itdr_detections'; Expect = 'Depends on the Identity Protection notification recipients being set (tenant setting). verify: what ScubaGear reads.' }
    'MS.AAD.2.3' = @{ Lab = 'CA007 sign-in risk high: block (P2)'; Flag = 'enable_identity_protection_ca'; Expect = 'Pass once CA007 is enabled.' }
    'MS.AAD.3.1' = @{ Lab = 'CA008 phishing-resistant authentication strength (all users report-only, then pilot enforced, then all users)'; Flag = 'enable_phishing_resistant_all_users'; Expect = 'Fail while CA008 stays report-only: a deliberate pilot, recorded as an open gap until enforced.' }
    'MS.AAD.3.2' = @{ Lab = 'CA001 require MFA for all users'; Flag = 'enable_premium'; Expect = 'Pass once CA001 is enabled.' }
    # 3.3-3.5: Invoke-PostApply runs Set-AuthenticationMethodsPolicy.ps1 (step auth-methods) whenever enable_premium is
    # on; enable_phishing_resistant_all_users only adds the workforce passkey rollout (-IncludeStaffRollout).
    'MS.AAD.3.3' = @{ Lab = 'post-apply/Set-AuthenticationMethodsPolicy.ps1 (post-apply step auth-methods): Authenticator shows app name and location'; Flag = 'enable_premium'; Expect = 'Pass after Set-AuthenticationMethodsPolicy.ps1 -Apply. verify: setting still exposed.' }
    'MS.AAD.3.4' = @{ Lab = 'Authentication methods migration = Migration Complete: a portal step. Set-AuthenticationMethodsPolicy.ps1 only REPORTS policyMigrationState (WARN until complete), it never changes it'; Flag = 'enable_premium'; Expect = 'Fail until the migration is marked complete in the portal (no lab script sets it).' }
    'MS.AAD.3.5' = @{ Lab = 'post-apply/Set-AuthenticationMethodsPolicy.ps1 -DisableSmsVoice disables SMS + voice (fail closed while any in-scope user has only phone methods; Invoke-PostApply does not pass it). Email OTP is NOT changed by any lab script. Joiners onboard with a Temporary Access Pass'; Flag = 'enable_premium'; Expect = 'Fail expected until -DisableSmsVoice has run AND email OTP is disabled by hand (check guest / B2B email-OTP sign-in impact first). Documented gap.' }
    'MS.AAD.3.6' = @{ Lab = 'CA002 phishing-resistant MFA for admin roles (authentication strength; Microsoft''s 14-role template list is a validated floor, plus the tier roles)'; Flag = 'enable_premium'; Expect = 'Pass once CA002 is enabled, if its role list covers ScubaGear''s highly privileged roles. verify on first run.' }
    'MS.AAD.3.7' = @{ Lab = 'CA005 compliant device for the admin portals (CA005-Pilot-CompliantDevice group only; the compliant device itself is enable_intune_vm)'; Flag = 'enable_premium'; Expect = 'Fail or Warning expected: CA005 is a scoped pilot, not all sign-ins (SHOULD).' }
    # 3.8: CA009 protects the SAME user action (urn:user:registersecurityinfo) with an authentication strength (one-time
    # TAP or phishing-resistant), not with the managed-device grant ScubaGear checks: a compensating control.
    'MS.AAD.3.8' = @{ Lab = 'CA009 register security info: one-time TAP or phishing-resistant strength (user action urn:user:registersecurityinfo) - compensating, NOT a managed-device grant'; Flag = 'enable_registration_ca'; Expect = 'Fail expected (SHOULD): ScubaGear looks for a managed-device grant on the registration user action; CA009 uses an authentication strength instead. Documented deviation, not a regression.' }
    'MS.AAD.3.9' = @{ Lab = 'CA010 block device code flow (authentication flows: deviceCodeFlow; All users, All resources, Block; break-glass excluded)'; Flag = 'enable_device_code_block'; Expect = 'Pass once CA010 is enabled (report-only does not satisfy it). Fail if a CA010-Exclusion group or excluded application is set: only break-glass is a declared CapExclusion. Enforcing breaks az login --use-device-code and -UseDeviceCode - switch to browser sign-in first.' }
    'MS.AAD.4.1' = @{ Lab = 'modules/entra-diagnostics (envs/bootstrap): Entra logs to loga-idlab, detections in Sentinel or LA alerts'; Flag = 'bootstrap'; Expect = 'ScubaGear cannot see the SOC: evidence is the diagnostic setting plus a fired alert.' }
    'MS.AAD.5.1' = @{ Lab = 'Not set by any lab script: Set-ConsentPolicy.ps1 deliberately leaves allowedToCreateApps as it is'; Flag = ''; Expect = 'Fail expected until users can no longer register apps (one tenant setting). Documented gap.' }
    # 5.2-5.7: Invoke-PostApply runs Set-ConsentPolicy.ps1 and Set-AppGovernancePolicy.ps1 only with enable_nhi_governance.
    'MS.AAD.5.2' = @{ Lab = 'post-apply/Set-ConsentPolicy.ps1: user consent only to verified publishers, low-impact permissions (or disabled)'; Flag = 'enable_nhi_governance'; Expect = 'Pass after Set-ConsentPolicy.ps1; ScubaGear may want consent fully disabled (-UserConsent Disabled). verify.' }
    'MS.AAD.5.3' = @{ Lab = 'post-apply/Set-ConsentPolicy.ps1: admin consent workflow with a named reviewer group'; Flag = 'enable_nhi_governance'; Expect = 'Pass after Set-ConsentPolicy.ps1.' }
    'MS.AAD.5.5' = @{ Lab = 'post-apply/Set-AppGovernancePolicy.ps1: password addition blocked on new apps'; Flag = 'enable_nhi_governance'; Expect = 'Newer baseline control (not in ScubaGear v1.8.0). Apps created before the cutoff are capped (5.6), not blocked. verify on the installed version.' }
    'MS.AAD.5.6' = @{ Lab = 'post-apply/Set-AppGovernancePolicy.ps1: 90-day cap on secrets added to existing apps'; Flag = 'enable_nhi_governance'; Expect = 'Newer baseline control (not in ScubaGear v1.8.0; CISA limit 180 days, lab 90). verify on the installed version.' }
    'MS.AAD.5.7' = @{ Lab = 'post-apply/Set-AppGovernancePolicy.ps1: 180-day maximum certificate lifetime on new apps'; Flag = 'enable_nhi_governance'; Expect = 'Newer baseline control (not in ScubaGear v1.8.0; CISA limit 365 days, lab 180). verify on the installed version.' }
    'MS.AAD.6.1' = @{ Lab = 'Not set by any lab script: the tenant password-expiration setting is left as it is (cloud accounts; synced accounts follow AD policy)'; Flag = ''; Expect = 'Pass expected on a new tenant. verify.' }
    'MS.AAD.7.1' = @{ Lab = 'Global Administrators: bg-admin-01/02 via Break-Glass-Admins plus the operator admin'; Flag = 'enable_premium'; Expect = 'Pass when 2-8 Global Administrators exist.' }
    'MS.AAD.7.2' = @{ Lab = 'Fine-grained roles: Privileged-IAM-Admins (User Administrator) and the 16 PIM tier groups (8 Tier-0 incl. Security, Conditional Access, Privileged Role Administrator; 8 Tier-1 incl. Intune, Helpdesk, Exchange Administrator); Global Administrator is never a tier group'; Flag = 'enable_pim_tiers'; Expect = 'Pass once privileged work runs through the tier groups, not Global Administrator.' }
    'MS.AAD.7.3' = @{ Lab = 'Cloud-only privileged accounts: break-glass on *.onmicrosoft.com; admin accounts out of Cloud Sync scope'; Flag = 'enable_premium'; Expect = 'Pass expected.' }
    'MS.AAD.7.4' = @{ Lab = 'No permanent active privileged assignments: PIM for Groups makes membership just-in-time'; Flag = 'enable_pim_tiers'; Expect = 'Break-glass permanent GA is the one declared exclusion. A role held actively by a PIM-governed group may still be reported; that is a design decision, not excluded. verify.' }
    'MS.AAD.7.5' = @{ Lab = 'Privileged roles provisioned only through PIM'; Flag = 'enable_pim_tiers'; Expect = 'Pass expected once no role is assigned outside PIM (lab/kql/role-assigned-outside-pim.kql alerts if one is).' }
    # 7.6-7.9: ScubaGear reads the PIM policy of each highly privileged DIRECTORY ROLE (the v1.8.0 sample lists them
    # as "<role>(Directory Role)"). The lab writes only the Global Administrator role policy (modules/pim
    # directory-roles.tf -> post-apply/Set-DirectoryRolePimPolicies.ps1); every other privileged role is held by a
    # PIM-for-Groups tier group, whose notifications modules/pim sets on the GROUP policy, not the role's.
    'MS.AAD.7.6' = @{ Lab = 'Global Administrator role PIM policy (post-apply/Set-DirectoryRolePimPolicies.ps1): activation needs approval by PIM-Approvers-Tier0, MFA or the Tier-0 auth context, justification + ticket, 2 h; break-glass keeps its standing assignment'; Flag = 'enable_global_admin_pim_policy'; Expect = 'Pass once the GA role policy is written (Approval_EndUser_Assignment, isApprovalRequired). Fail before that: the tenant default lets GA activate without approval. verify on first run.' }
    'MS.AAD.7.7' = @{ Lab = 'Assignment alerts to pim_alert_mailbox: GA role policy (eligible + direct-active assignment rules) and the PIM tier groups (modules/pim); lab/kql/role-assigned-outside-pim.kql is the SOC path'; Flag = 'enable_global_admin_pim_policy'; Expect = 'Pass for Global Administrator once its policy is written with pim_alert_mailbox set (empty mailbox = no notification rule rendered). The other highly privileged directory roles keep their default policies, so ScubaGear may still list them. verify.' }
    'MS.AAD.7.8' = @{ Lab = 'GA activation alert: Notification_Admin_EndUser_Assignment in the GA role policy -> pim_alert_mailbox; lab/kql/pim-activation.kql (SOC path)'; Flag = 'enable_global_admin_pim_policy'; Expect = 'Pass once the GA role policy is written with pim_alert_mailbox set. verify.' }
    'MS.AAD.7.9' = @{ Lab = 'Other privileged activations: PIM-for-Groups activation alerts on the Tier-0 and approval-gated tier groups (modules/pim, pim_alert_mailbox) plus lab/kql/pim-activation.kql; no other directory role policy is managed'; Flag = 'enable_pim_tiers'; Expect = 'Warning / Fail expected (SHOULD): ScubaGear reads the directory-role policies, which the lab leaves at default for every role but GA. Documented gap.' }
    'MS.AAD.8.1' = @{ Lab = 'post-apply/Set-ExternalCollaboration.ps1: guestUserRoleId = Restricted Guest User (guests see only their own directory object)'; Flag = 'enable_b2b_governance'; Expect = 'Pass after Set-ExternalCollaboration.ps1.' }
    'MS.AAD.8.2' = @{ Lab = 'post-apply/Set-ExternalCollaboration.ps1: allowInvitesFrom = adminsAndGuestInviters; guests arrive through sponsored access packages'; Flag = 'enable_b2b_governance'; Expect = 'Pass after Set-ExternalCollaboration.ps1.' }
    'MS.AAD.8.3' = @{ Lab = 'Not built: the invitation domain allow-list (portal "Collaboration restrictions") is a portal step - Set-ExternalCollaboration.ps1 does not set it. Connected organizations scope who can REQUEST the guest package, not who can be invited'; Flag = ''; Expect = 'N/A in ScubaGear v1.8.0 (manual check). Documented gap (SHOULD) until the allow-list is set by hand.' }
    'MS.AAD.9.1' = @{ Lab = 'Not built: no Conditional Access policy blocks risky agents. post-apply/New-AgentIdentity.ps1 creates one governed agent identity (sponsor, managed-identity credential, no permissions), not an agent-risk policy'; Flag = ''; Expect = 'Newer baseline control (not in ScubaGear v1.8.0; SHALL; needs Entra ID P2 plus Agent 365 or Microsoft 365 E7). Gap.' }
}

# ===========================================================================
# Helpers (pure: they read and compute; all writes happen in the main body
# behind ShouldProcess).
# ===========================================================================

# Under StrictMode, reading a property that is absent throws. Tool outputs
# change shape between versions, so every optional field goes through this.
function Get-Prop {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null }
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

# Where a tool's results came from, judged on the tenant id the tool itself
# recorded (ScubaGear MetaData.TenantId, Zero Trust TenantId). Returns the kind
# and a public-safe note - never the id. key = SHA-256 of the id, only to tell
# whether two tools saw the same tenant; it is never written anywhere.
function Get-InputSource {
    param([AllowNull()][AllowEmptyString()][string]$TenantId)
    $id = if ($TenantId) { $TenantId.Trim().ToLowerInvariant() } else { '' }
    if (-not $id) { return [pscustomobject]@{ kind = 'unknown'; note = 'the results name no tenant (no tenant id recorded)'; key = $null } }
    if ($id -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        return [pscustomobject]@{ kind = 'unknown'; note = 'the recorded tenant id is not a GUID'; key = $null }
    }
    if ($NonTenantInputIds.ContainsKey($id)) {
        $v = $NonTenantInputIds[$id]
        return [pscustomobject]@{ kind = ($v -split ':')[0]; note = $v; key = $null }
    }
    if (@($id.Replace('-', '').ToCharArray() | Select-Object -Unique).Count -eq 1) {
        return [pscustomobject]@{ kind = 'fixture'; note = 'fixture: a repeated-digit placeholder tenant id'; key = $null }
    }
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { $key = [BitConverter]::ToString($h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($id))) } finally { $h.Dispose() }
    [pscustomobject]@{ kind = 'tenant'; note = 'tenant run'; key = $key }
}

# True when Path is inside lab/evidence but not inside the gitignored lab/evidence/out
# (same test as 09-SoD-Report.ps1 / 10-Review-KPIs.ps1).
function Test-IsPublicEvidencePath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$EvidenceRoot)
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd($sep) + $sep
    $ev = [System.IO.Path]::GetFullPath($EvidenceRoot).TrimEnd($sep) + $sep
    $out = [System.IO.Path]::GetFullPath((Join-Path $EvidenceRoot 'out')).TrimEnd($sep) + $sep
    return $full.StartsWith($ev, [StringComparison]::OrdinalIgnoreCase) -and -not $full.StartsWith($out, [StringComparison]::OrdinalIgnoreCase)
}

# Error text can carry local paths, tenant GUIDs, UPNs or IPs (an az or Graph
# error, a "not found under <home>/..." message). Anything that reaches the
# PUBLIC summary goes through this first; the private manifest keeps the
# original.
function ConvertTo-PublicSafeText {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = $Text
    if ($HOME) { $t = $t.Replace($HOME, '~') }
    $t = $t -replace '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<guid>'
    $t = $t -replace '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<upn>'
    $t = $t -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '<ip>'
    $t -replace '(?i)\b[a-z0-9-]+\.onmicrosoft\.com\b', '<tenant-domain>'
}

function Get-RelativePath {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path)
    [System.IO.Path]::GetRelativePath($Root, $Path) -replace '\\', '/'
}

# One entry per file under $Root (excluding the working folder), lowercase hex
# so SHA256SUMS verifies with `shasum -a 256 -c` and `sha256sum -c`.
function Get-HashManifest {
    param([Parameter(Mandatory)][string]$Root, [string[]]$ExcludeTopLevel = @('_work'))
    Get-ChildItem -LiteralPath $Root -Recurse -File |
        Where-Object { (Get-RelativePath $Root $_.FullName).Split('/')[0] -notin $ExcludeTopLevel } |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject][ordered]@{
                path      = Get-RelativePath $Root $_.FullName
                sha256    = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                sizeBytes = $_.Length
            }
        }
}

# ScubaGear's Requirement field carries HTML indicator badges after the text.
function ConvertTo-PlainRequirement {
    param([string]$Html)
    if (-not $Html) { return '' }
    $text = ($Html -split '<div', 2)[0] -replace '<[^>]+>', ''
    [System.Net.WebUtility]::HtmlDecode($text).Trim()
}

function Find-ScubaResultFile {
    # Newest ScubaResults*.json (default output) or ScubaResults*.csv (the
    # only combined file when ScubaGear ran with -KeepIndividualJSON).
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) { return (Get-Item -LiteralPath $Path) }
    $json = Get-ChildItem -LiteralPath $Path -Recurse -File -Filter 'ScubaResults*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($json) { return $json }
    Get-ChildItem -LiteralPath $Path -Recurse -File -Filter 'ScubaResults*.csv' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
}

function ConvertFrom-ScubaResult {
    <#
        Reads ScubaResults_<uuid>.json (Results.AAD[].Controls[]) or, as a
        fallback, ScubaResults.csv. Field names checked against CISA's v1.8.0
        sample report. Returns tool metadata WITHOUT tenant identifiers, the
        product summary and one row per MS.AAD control. Details text is left
        out on purpose: it names users and policies.
    #>
    param([Parameter(Mandatory)][System.IO.FileInfo]$File)
    $rows = [System.Collections.Generic.List[object]]::new()
    $meta = [ordered]@{ toolVersion = $null; reportTimestampZulu = $null; sourceFormat = $File.Extension.TrimStart('.') }
    $summary = $null
    # ScubaResults.csv names no tenant: a CSV-only import is 'unknown'.
    $source = Get-InputSource $null

    if ($File.Extension -eq '.json') {
        $j = Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json
        $md = Get-Prop $j 'MetaData'
        # Read BEFORE it is dropped: the only way to tell the CISA sample or a
        # fixture from a tenant run. The id itself goes nowhere.
        $source = Get-InputSource ([string](Get-Prop $md 'TenantId'))
        $meta.toolVersion = Get-Prop $md 'ToolVersion'
        $meta.reportTimestampZulu = Get-Prop $md 'TimestampZulu'
        $summary = Get-Prop (Get-Prop $j 'Summary') 'AAD'
        foreach ($group in @(Get-Prop (Get-Prop $j 'Results') 'AAD')) {
            foreach ($c in @(Get-Prop $group 'Controls')) {
                if ($null -eq $c) { continue }
                $rows.Add([pscustomobject]@{
                        Id          = [string](Get-Prop $c 'Control ID')
                        Result      = [string](Get-Prop $c 'Result')
                        Criticality = [string](Get-Prop $c 'Criticality')
                        RawReq      = [string](Get-Prop $c 'Requirement')
                    })
            }
        }
    }
    else {
        foreach ($r in (Import-Csv -LiteralPath $File.FullName)) {
            $rows.Add([pscustomobject]@{
                    Id          = [string](Get-Prop $r 'Control ID')
                    Result      = [string](Get-Prop $r 'Result')
                    Criticality = [string](Get-Prop $r 'Criticality')
                    RawReq      = [string](Get-Prop $r 'Requirement')
                })
        }
    }

    $controls = foreach ($r in ($rows | Where-Object { $_.Id -like 'MS.AAD.*' })) {
        $baseId = $r.Id -replace 'v\d+$', ''
        $map = if ($ControlMap.Contains($baseId)) { $ControlMap[$baseId] } else { $null }
        [pscustomobject][ordered]@{
            controlId   = $r.Id
            baseId      = $baseId
            result      = $r.Result
            criticality = $r.Criticality
            bod2501     = [bool]($r.RawReq -match 'indicator-bod')
            requirement = ConvertTo-PlainRequirement $r.RawReq
            labControl  = if ($map) { $map.Lab } else { $null }
            stagingFlag = if ($map) { $map.Flag } else { $null }
            expected    = if ($map) { $map.Expect } else { 'UNMAPPED: add this control to the map in Invoke-BaselineAssessment.ps1' }
        }
    }
    $controls = @($controls)
    if (-not $controls.Count) { throw "No MS.AAD controls found in $($File.Name): was ScubaGear run with -ProductNames aad?" }

    # Summary as ScubaGear reported it; computed from the rows if absent (CSV).
    $sum = [ordered]@{}
    foreach ($k in 'Passes', 'Failures', 'Warnings', 'Manual', 'Errors', 'Omits', 'IncorrectResults') {
        $sum[$k] = Get-Prop $summary $k
    }
    if ($null -eq $summary) {
        $sum.Passes = @($controls | Where-Object result -EQ 'Pass').Count
        $sum.Failures = @($controls | Where-Object result -EQ 'Fail').Count
        $sum.Warnings = @($controls | Where-Object result -EQ 'Warning').Count
        $sum.Errors = @($controls | Where-Object result -EQ 'Error').Count
    }

    # KPI: SHALL controls with an automated check (criticality exactly
    # "Shall"; "Shall/Not-Implemented" means ScubaGear cannot test it). N/A
    # and Omitted are out of the denominator; Error counts as not passing.
    $shall = @($controls | Where-Object { $_.criticality -eq 'Shall' -and $_.result -notin 'N/A', 'Omitted' })
    $shallPass = @($shall | Where-Object result -EQ 'Pass').Count
    [pscustomobject][ordered]@{
        meta     = $meta
        summary  = $sum
        kpi      = [ordered]@{
            shallAutomated  = $shall.Count
            shallPassed     = $shallPass
            shallPassRatePc = if ($shall.Count) { [math]::Round(100.0 * $shallPass / $shall.Count, 1) } else { $null }
            bod2501Failing  = @($controls | Where-Object { $_.bod2501 -and $_.result -eq 'Fail' }).Count
        }
        controls = $controls
        unmapped = @($controls | Where-Object { -not $ControlMap.Contains($_.baseId) } | ForEach-Object controlId)
        source   = $source
    }
}

function ConvertFrom-ZtResult {
    <#
        Reads zt-export/ZeroTrustAssessmentReport.json (Get-ZtAssessmentResults:
        Tests[] with TestId/TestTitle/TestStatus/TestPillar/TestRisk). TenantId,
        TenantName, Domain, Account and each test's TestResult/TestDescription
        (which name tenant objects) are deliberately not carried into the
        public summary.
    #>
    param([Parameter(Mandatory)][string]$JsonPath)
    $j = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    $tests = @(foreach ($t in @(Get-Prop $j 'Tests')) {
            if ($null -eq $t) { continue }
            [pscustomobject][ordered]@{
                testId = [string](Get-Prop $t 'TestId')
                title  = [string](Get-Prop $t 'TestTitle')
                status = [string](Get-Prop $t 'TestStatus')
                pillar = [string](Get-Prop $t 'TestPillar')
                risk   = [string](Get-Prop $t 'TestRisk')
            }
        })
    if (-not $tests.Count) { throw "No Tests[] in $JsonPath - not a Zero Trust Assessment results file?" }
    $counted = @($tests | Where-Object { $_.status -notin 'Skipped', 'Planned' })
    $passed = @($counted | Where-Object status -EQ 'Passed').Count
    $executedAt = Get-Prop $j 'ExecutedAt'
    $byStatus = [ordered]@{}
    foreach ($g in @($tests | Group-Object status | Sort-Object Name)) { $byStatus[$g.Name] = $g.Count }
    [pscustomobject][ordered]@{
        meta    = [ordered]@{
            toolVersion = Get-Prop $j 'CurrentVersion'
            executedAt  = if ($executedAt -is [datetime]) { $executedAt.ToUniversalTime().ToString('o') } else { [string]$executedAt }
        }
        kpi     = [ordered]@{
            testsCounted       = $counted.Count
            testsPassed        = $passed
            passRatePc         = if ($counted.Count) { [math]::Round(100.0 * $passed / $counted.Count, 1) } else { $null }
            highRiskNotPassed  = @($counted | Where-Object { $_.risk -eq 'High' -and $_.status -ne 'Passed' }).Count
        }
        byStatus = $byStatus
        tests   = $tests
        source  = Get-InputSource ([string](Get-Prop $j 'TenantId'))
    }
}

function Compare-AssessmentRun {
    # Control-by-control delta against a baseline public summary.json.
    param([Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Current)
    $out = [ordered]@{ baselineRunId = Get-Prop $Baseline 'runId'; baselinePhase = Get-Prop $Baseline 'phase' }

    $bScuba = Get-Prop (Get-Prop $Baseline 'scubaGear') 'controls'
    $cScuba = Get-Prop $Current.scubaGear 'controls'
    if ($bScuba -and $cScuba) {
        $before = @{}; foreach ($c in @($bScuba)) { $before[(Get-Prop $c 'baseId')] = Get-Prop $c 'result' }
        $rows = foreach ($c in @($cScuba)) {
            $was = if ($before.ContainsKey($c.baseId)) { $before[$c.baseId] } else { $null }
            $change = if ($null -eq $was) { 'new' }
            elseif ($was -eq $c.result) { 'unchanged' }
            elseif ($c.result -eq 'Pass') { 'improved' }
            elseif ($was -eq 'Pass') { 'REGRESSED' }
            else { 'changed' }
            [pscustomobject][ordered]@{ baseId = $c.baseId; before = $was; after = $c.result; change = $change }
        }
        $rows = @($rows)
        $out.scubaGear = [ordered]@{
            shallPassRateBeforePc = Get-Prop (Get-Prop (Get-Prop $Baseline 'scubaGear') 'kpi') 'shallPassRatePc'
            shallPassRateAfterPc  = $Current.scubaGear.kpi.shallPassRatePc
            improved              = @($rows | Where-Object change -EQ 'improved').Count
            regressed             = @($rows | Where-Object change -EQ 'REGRESSED').Count
            controls              = $rows
        }
    }

    $bZt = Get-Prop (Get-Prop $Baseline 'zeroTrust') 'tests'
    $cZt = Get-Prop $Current.zeroTrust 'tests'
    if ($bZt -and $cZt) {
        $before = @{}; foreach ($t in @($bZt)) { $before[(Get-Prop $t 'testId')] = Get-Prop $t 'status' }
        $changed = @(foreach ($t in @($cZt)) {
                $was = if ($before.ContainsKey($t.testId)) { $before[$t.testId] } else { $null }
                if ($was -ne $t.status) { [pscustomobject][ordered]@{ testId = $t.testId; title = $t.title; before = $was; after = $t.status } }
            })
        $out.zeroTrust = [ordered]@{
            passRateBeforePc = Get-Prop (Get-Prop (Get-Prop $Baseline 'zeroTrust') 'kpi') 'passRatePc'
            passRateAfterPc  = $Current.zeroTrust.kpi.passRatePc
            changedTests     = $changed
        }
    }
    $out
}

function Resolve-BreakGlassGroup {
    param([Parameter(Mandatory)][string]$MailNickname)
    # Same lookup as Export-EvidencePack.ps1 (mailNickname is the Terraform
    # contract). Read-only; returns $null with a warning, never throws.
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        Write-Warning 'Microsoft.Graph.Authentication not available: cannot look up the break-glass group. Pass -BreakGlassGroupObjectId.'
        return $null
    }
    try {
        if (-not (Get-MgContext)) { Connect-MgGraph -Scopes 'Group.Read.All' -NoWelcome }
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=mailNickname eq '$MailNickname'&`$select=id,displayName"
        $g = @((Invoke-MgGraphRequest -Method GET -Uri $uri)['value']) | Select-Object -First 1
        if ($g) { return [string]$g['id'] }
        Write-Warning "Group '$MailNickname' not found."
    }
    catch { Write-Warning "Break-glass group lookup failed: $($_.Exception.Message)" }
    $null
}

function ConvertTo-ScubaConfigYaml {
    # The ONLY exclusions are the break-glass group: CA exclusions on every
    # policy ScubaGear lets you declare them for, and the permanent Global
    # Administrator assignment for MS.AAD.7.4. Written into the private raw
    # folder (it holds a tenant object id).
    param([string]$GroupId, [string]$Run)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# Generated by Invoke-BaselineAssessment.ps1 for run $Run.")
    $lines.Add('# Only documented exclusion: the break-glass group (emergency access).')
    $lines.Add("ProductNames: ['aad']")
    $lines.Add('M365Environment: commercial')
    $lines.Add('OrgName: Contoso Health (lab)')
    if ($GroupId) {
        $lines.Add('Aad:')
        foreach ($id in $ScubaCapExclusionPolicyIds) {
            $lines.Add("  ${id}:")
            $lines.Add('    CapExclusions:')
            $lines.Add('      Groups:')
            $lines.Add("        - `"$GroupId`"")
        }
        $lines.Add('  MS.AAD.7.4v1:')
        $lines.Add('    RoleExclusions:')
        $lines.Add('      Groups:')
        $lines.Add("        - `"$GroupId`"")
    }
    $lines -join "`n"
}

function Copy-VerifiedTree {
    # Import mode: copy a tool's output into the run, then prove the copy is
    # byte-identical to the source before anything is hashed as evidence.
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
    $leaf = Split-Path -Leaf $Source
    $srcFiles = Get-ChildItem -LiteralPath $Source -Recurse -File
    foreach ($f in $srcFiles) {
        $rel = [System.IO.Path]::GetRelativePath($Source, $f.FullName)
        $dst = Join-Path -Path $Destination -ChildPath $leaf -AdditionalChildPath $rel
        if ((Get-FileHash -LiteralPath $f.FullName).Hash -ne (Get-FileHash -LiteralPath $dst).Hash) {
            throw "Copy verification failed for $rel"
        }
    }
    Join-Path $Destination $leaf
}

function Send-EvidenceFile {
    # Entra auth only (shared key is disabled on the account). --overwrite
    # false: evidence is never replaced; a re-run gets a new RunId.
    param(
        [Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string]$BlobName,
        [Parameter(Mandatory)][string]$Sha256
    )
    $azArgs = @(
        'storage', 'blob', 'upload', '--account-name', $StorageAccountName, '--container-name', $ContainerName,
        '--name', $BlobName, '--file', $File, '--auth-mode', 'login', '--overwrite', 'false',
        '--validate-content', '--metadata', "sha256=$Sha256", "runid=$RunId", "phase=$Phase",
        '--only-show-errors', '--output', 'none'
    )
    $out = & az @azArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }

    # Spot-check that the service reports a retention policy on the blob.
    # verify: field name in az output (immutabilityPolicy.expiryTime) and
    # whether an inherited account-level policy is shown per blob.
    $show = & az storage blob show --account-name $StorageAccountName --container-name $ContainerName `
        --name $BlobName --auth-mode login --query '{versionId:versionId, expiry:immutabilityPolicy.expiryTime}' `
        --output json --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ versionId = $null; immutabilityExpiry = $null } }
    $s = ($show | Out-String) | ConvertFrom-Json
    [pscustomobject]@{ versionId = (Get-Prop $s 'versionId'); immutabilityExpiry = (Get-Prop $s 'expiry') }
}

function Format-SummaryMarkdown {
    param([Parameter(Mandatory)]$S, [string]$SummaryJsonSha256)
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# Baseline assessment - $($S.runId) ($($S.phase))")
    $null = $md.AppendLine()
    $null = $md.AppendLine("Generated (UTC): $($S.generatedUtc) by Invoke-BaselineAssessment.ps1 $($S.toolVersion).")
    if ($S.source.kind -ne 'tenant') {
        $null = $md.AppendLine()
        $null = $md.AppendLine("**NOT A TENANT RUN** ($($S.source.detail)). Not evidence about any tenant; never place it under lab/evidence.")
    }
    else { $null = $md.AppendLine('Source: a run against the tenant (every tool recorded the same tenant id; the id is not published).') }
    $null = $md.AppendLine('Public-safe: no tenant id, domain, user, IP or policy detail text. The raw reports are private,')
    $null = $md.AppendLine('in the WORM evidence store; the SHA-256 of every raw file is in summary.json (rawManifest).')
    $null = $md.AppendLine()
    $null = $md.AppendLine("summary.json SHA-256: ``$SummaryJsonSha256``  ")
    $null = $md.AppendLine("Raw manifest.json SHA-256: ``$($S.rawManifest.manifestSha256)``  ")
    $null = $md.AppendLine("WORM: $($S.worm.status) ($($S.worm.uploaded) uploaded, $($S.worm.failed) failed) under ``$($S.worm.container)/$($S.worm.prefix)``")
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Tools')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Tool | Status | Version | Note |')
    $null = $md.AppendLine('|---|---|---|---|')
    foreach ($k in 'scubaGear', 'zeroTrust') {
        $t = $S[$k]
        $null = $md.AppendLine("| $k | $($t.status) | $(Get-Prop $t.meta 'toolVersion') | $($t.reason) |")
    }
    if ($S.scubaGear.status -eq 'ok') {
        $k = $S.scubaGear.kpi
        $null = $md.AppendLine()
        $null = $md.AppendLine('## ScubaGear (CISA SCuBA, Entra ID baseline)')
        $null = $md.AppendLine()
        $null = $md.AppendLine("SHALL controls with automated checks passing: **$($k.shallPassed) / $($k.shallAutomated)** ($($k.shallPassRatePc)%). BOD 25-01 controls failing: $($k.bod2501Failing).")
        $null = $md.AppendLine()
        $null = $md.AppendLine('| Control | Result | Criticality | BOD 25-01 | Lab control | Staging flag | Expected |')
        $null = $md.AppendLine('|---|---|---|---|---|---|---|')
        foreach ($c in $S.scubaGear.controls) {
            $null = $md.AppendLine("| $($c.controlId) | $($c.result) | $($c.criticality) | $(if ($c.bod2501) { 'yes' } else { '' }) | $($c.labControl) | $($c.stagingFlag) | $($c.expected) |")
        }
    }
    if ($S.zeroTrust.status -eq 'ok') {
        $k = $S.zeroTrust.kpi
        $null = $md.AppendLine()
        $null = $md.AppendLine("## Zero Trust Assessment (pillar: $($S.zeroTrust.pillar))")
        $null = $md.AppendLine()
        $null = $md.AppendLine("Tests passed: **$($k.testsPassed) / $($k.testsCounted)** ($($k.passRatePc)%). High-risk tests not passed: $($k.highRiskNotPassed).")
    }
    if ($S.comparison) {
        $c = $S.comparison
        $null = $md.AppendLine()
        $null = $md.AppendLine("## Change since $(Get-Prop $c 'baselineRunId') ($(Get-Prop $c 'baselinePhase'))")
        $null = $md.AppendLine()
        $sg = Get-Prop $c 'scubaGear'
        if ($sg) {
            $null = $md.AppendLine("ScubaGear SHALL pass rate: $($sg.shallPassRateBeforePc)% -> $($sg.shallPassRateAfterPc)%. Improved: $($sg.improved). Regressed: $($sg.regressed).")
            $null = $md.AppendLine()
            $null = $md.AppendLine('| Control | Before | After | Change |')
            $null = $md.AppendLine('|---|---|---|---|')
            foreach ($r in @($sg.controls | Where-Object change -NE 'unchanged')) {
                $null = $md.AppendLine("| $($r.baseId) | $($r.before) | $($r.after) | $($r.change) |")
            }
        }
        $zt = Get-Prop $c 'zeroTrust'
        if ($zt) {
            $null = $md.AppendLine()
            $null = $md.AppendLine("Zero Trust Assessment pass rate: $($zt.passRateBeforePc)% -> $($zt.passRateAfterPc)%. Tests that changed status: $(@($zt.changedTests).Count).")
        }
        if (Get-Prop $c 'status') { $null = $md.AppendLine("Comparison: $($c.status)") }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('Verify the private copy: download the run folder from the WORM container, then')
    $null = $md.AppendLine('`shasum -a 256 -c SHA256SUMS` inside it, and compare manifest.json''s hash with the one above.')
    $md.ToString()
}

# ===========================================================================
# Main
# ===========================================================================
$runName = "$RunId-$Phase"
$rawRun = Join-Path ([System.IO.Path]::GetFullPath($RawOutputRoot)) $runName
$pubRun = Join-Path ([System.IO.Path]::GetFullPath($PublicOutputRoot)) $runName
$blobPrefix = "assessments/$runName"
$evidenceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' 'evidence'))
$explicitPublicRoot = $PSBoundParameters.ContainsKey('PublicOutputRoot')

Write-Console "Baseline assessment run $runName" -ForegroundColor Cyan
Write-Console "  raw (private, gitignored): $rawRun"
Write-Console "  public summary (commit):   $pubRun (only for a tenant run; decided once the results are read)"

# Evidence is never overwritten: a second run with the same id is refused.
foreach ($d in $rawRun, $pubRun) {
    if (Test-Path -LiteralPath $d) { throw "$d already exists. Each run needs a new -RunId; evidence folders are never reused." }
}
if ($PSCmdlet.ShouldProcess($rawRun, 'create the raw run folder')) {
    New-Item -ItemType Directory -Path $rawRun -Force | Out-Null
}

$toolState = [ordered]@{
    scubaGear = [ordered]@{ status = 'not-selected'; reason = ''; meta = $null; mode = $null }
    zeroTrust = [ordered]@{ status = 'not-selected'; reason = ''; meta = $null; mode = $null }
}
$scuba = $null; $zt = $null

# ---------------------------------------------------------------------------
# 1. ScubaGear
# ---------------------------------------------------------------------------
if ('ScubaGear' -in $Tools) {
    $scubaDir = Join-Path $rawRun 'scubagear'
    $resultFile = $null
    try {
        if ($ScubaResultsPath) {
            $toolState.scubaGear.mode = 'imported'
            $src = (Resolve-Path -LiteralPath $ScubaResultsPath).Path
            if (Test-Path -LiteralPath $src -PathType Leaf) { $src = Split-Path -Parent $src }
            $resultFile = Find-ScubaResultFile -Path $src
            if (-not $resultFile) { throw "No ScubaResults*.json or ScubaResults*.csv under $src" }
            # Copy the folder that holds the results file (the timestamped run folder).
            $runFolder = $resultFile.Directory.FullName
            if ($PSCmdlet.ShouldProcess($runFolder, "copy ScubaGear output into $scubaDir (hash-verified)")) {
                $copied = Copy-VerifiedTree -Source $runFolder -Destination $scubaDir
                $resultFile = Find-ScubaResultFile -Path $copied
            }
        }
        elseif ($IsWindows) {
            $toolState.scubaGear.mode = 'run'
            $bg = if ($BreakGlassGroupObjectId) { $BreakGlassGroupObjectId } else { Resolve-BreakGlassGroup -MailNickname $BreakGlassGroupMailNickname }
            if (-not $bg) {
                Write-Warning 'No break-glass group id: ScubaGear will report the (correct) break-glass CA exclusions as failures. Pass -BreakGlassGroupObjectId to declare them.'
            }
            $cfgPath = Join-Path $rawRun 'scubagear-config.yaml'
            if ($PSCmdlet.ShouldProcess('ScubaGear (Windows PowerShell 5.1 child process)', "Invoke-SCuBA -ProductNames aad -OutPath $scubaDir")) {
                New-Item -ItemType Directory -Path $scubaDir -Force | Out-Null
                ConvertTo-ScubaConfigYaml -GroupId $bg -Run $runName | Set-Content -LiteralPath $cfgPath -Encoding utf8
                # Values are embedded single-quoted (quotes doubled) and the
                # script is passed -EncodedCommand, so no path can break out.
                # Parameter presence is probed because ScubaGear renames and
                # adds switches between releases.
                $q = { param($s) "'" + ($s -replace "'", "''") + "'" }
                $child = @"
`$ErrorActionPreference = 'Stop'
Import-Module ScubaGear
`$cmd = Get-Command Invoke-SCuBA
`$p = @{ ProductNames = @('aad'); OutPath = $(& $q $scubaDir); ConfigFilePath = $(& $q $cfgPath) }
if (`$cmd.Parameters.ContainsKey('Quiet')) { `$p['Quiet'] = `$true }
if (`$cmd.Parameters.ContainsKey('SilenceBODWarnings')) { `$p['SilenceBODWarnings'] = `$true }
Invoke-SCuBA @p
"@
                $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($child))
                # RemoteSigned for this child only: enough for PSGallery
                # modules, and it changes no machine or user policy.
                & powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -EncodedCommand $enc
                if ($LASTEXITCODE -ne 0) { throw "ScubaGear exited with code $LASTEXITCODE" }
                $resultFile = Find-ScubaResultFile -Path $scubaDir
                if (-not $resultFile) { throw "ScubaGear finished but no ScubaResults file is under $scubaDir" }
            }
        }
        else {
            $toolState.scubaGear.status = 'skipped'
            $toolState.scubaGear.reason = 'ScubaGear runs only in Windows PowerShell 5.1 on Windows. Run it there and pass -ScubaResultsPath.'
            Write-Warning $toolState.scubaGear.reason
        }
        if ($toolState.scubaGear.status -ne 'skipped' -and $resultFile) {
            $scuba = ConvertFrom-ScubaResult -File $resultFile
            $toolState.scubaGear.status = 'ok'
            $toolState.scubaGear.meta = $scuba.meta
            Write-Console "  [+] ScubaGear $($scuba.meta.toolVersion): $($scuba.controls.Count) MS.AAD controls, SHALL pass $($scuba.kpi.shallPassed)/$($scuba.kpi.shallAutomated)" -ForegroundColor Green
            if ($scuba.unmapped) { Write-Warning "Unmapped ScubaGear controls (add them to the map): $($scuba.unmapped -join ', ')" }
        }
        elseif ($toolState.scubaGear.status -ne 'skipped') {
            $toolState.scubaGear.status = 'whatif'
        }
    }
    catch {
        $toolState.scubaGear.status = 'failed'
        $toolState.scubaGear.reason = $_.Exception.Message
        Write-Warning "ScubaGear FAILED: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 2. Zero Trust Assessment
# ---------------------------------------------------------------------------
if ('ZeroTrust' -in $Tools) {
    $ztDir = Join-Path $rawRun 'zero-trust'
    $ztJsonName = 'ZeroTrustAssessmentReport.json'
    $ztHtmlName = 'ZeroTrustAssessmentReport.html'
    $ztJson = $null
    try {
        $srcRoot = $null
        if ($ZeroTrustResultsPath) {
            $toolState.zeroTrust.mode = 'imported'
            $srcRoot = (Resolve-Path -LiteralPath $ZeroTrustResultsPath).Path
        }
        else {
            $toolState.zeroTrust.mode = 'run'
            $srcRoot = Join-Path -Path $rawRun -ChildPath '_work' -AdditionalChildPath 'zero-trust'
            if ($PSCmdlet.ShouldProcess('Zero Trust Assessment', "Invoke-ZtAssessment -Pillar $ZtPillar -Days $ZtDays -Path $srcRoot")) {
                Import-Module ZeroTrustAssessment -ErrorAction Stop
                if (-not $SkipZtConnect) {
                    $c = @{}; if ($UseDeviceCode) { $c['UseDeviceCode'] = $true }
                    Connect-ZtAssessment @c
                }
                $inv = Get-Command Invoke-ZtAssessment
                $p = @{ Path = $srcRoot }
                if ($inv.Parameters.ContainsKey('Pillar')) { $p['Pillar'] = $ZtPillar }
                if ($inv.Parameters.ContainsKey('Days')) { $p['Days'] = $ZtDays }
                # Telemetry is the tenant id only, but there is no reason to send it.
                if ($inv.Parameters.ContainsKey('DisableTelemetry')) { $p['DisableTelemetry'] = $true }
                Invoke-ZtAssessment @p
            }
            else { $srcRoot = $null }
        }

        if ($srcRoot) {
            $jsonSrc = if (Test-Path -LiteralPath $srcRoot -PathType Leaf) { Get-Item -LiteralPath $srcRoot }
            else { Get-ChildItem -LiteralPath $srcRoot -Recurse -File -Filter $ztJsonName | Select-Object -First 1 }
            if (-not $jsonSrc) { throw "No $ztJsonName under $srcRoot" }
            # The HTML sits in the -Path folder, i.e. the parent of zt-export.
            $searchRoot = if (Test-Path -LiteralPath $srcRoot -PathType Leaf) { Split-Path -Parent (Split-Path -Parent $srcRoot) } else { $srcRoot }
            $htmlSrc = Get-ChildItem -LiteralPath $searchRoot -Recurse -File -Filter $ztHtmlName -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($PSCmdlet.ShouldProcess($ztDir, 'copy Zero Trust report + results JSON (raw export left out: data minimisation)')) {
                New-Item -ItemType Directory -Path $ztDir -Force | Out-Null
                foreach ($f in @($jsonSrc, $htmlSrc) | Where-Object { $_ }) {
                    $dst = Join-Path $ztDir $f.Name
                    Copy-Item -LiteralPath $f.FullName -Destination $dst
                    if ((Get-FileHash -LiteralPath $f.FullName).Hash -ne (Get-FileHash -LiteralPath $dst).Hash) { throw "Copy verification failed for $($f.Name)" }
                }
                if (-not $htmlSrc) { Write-Warning "$ztHtmlName not found next to the results; only the JSON is kept." }
                $ztJson = Join-Path $ztDir $ztJsonName
            }
            else { $ztJson = $jsonSrc.FullName }
            $zt = ConvertFrom-ZtResult -JsonPath $ztJson
            $toolState.zeroTrust.status = 'ok'
            $toolState.zeroTrust.meta = $zt.meta
            Write-Console "  [+] Zero Trust Assessment $($zt.meta.toolVersion): $($zt.kpi.testsPassed)/$($zt.kpi.testsCounted) tests passed" -ForegroundColor Green
            if ($toolState.zeroTrust.mode -eq 'run') {
                Write-Warning "Raw Zero Trust export left in $srcRoot (not hashed, not uploaded). Microsoft recommends deleting it once the report is stored."
            }
        }
        else { $toolState.zeroTrust.status = 'whatif' }
    }
    catch {
        $toolState.zeroTrust.status = 'failed'
        $toolState.zeroTrust.reason = $_.Exception.Message
        Write-Warning "Zero Trust Assessment FAILED: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 2b. Is this a run against a tenant? Only then may the summary go public.
#     Judged per tool on the tenant id the tool recorded (read, then dropped).
# ---------------------------------------------------------------------------
$toolSources = [ordered]@{}
if ($scuba) { $toolSources.scubaGear = $scuba.source }
if ($zt) { $toolSources.zeroTrust = $zt.source }
$tenantKeys = @($toolSources.Values | Where-Object kind -EQ 'tenant' | ForEach-Object key | Select-Object -Unique)
$nonTenant = @($toolSources.GetEnumerator() | Where-Object { $_.Value.kind -ne 'tenant' } | ForEach-Object { "$($_.Key): $($_.Value.note)" })
$runSource = if (-not $toolSources.Count) { 'non-tenant: no tool produced results' }
elseif ($nonTenant) { "non-tenant: $($nonTenant -join '; ')" }
elseif ($tenantKeys.Count -gt 1) { 'non-tenant: ScubaGear and the Zero Trust Assessment name DIFFERENT tenants' }
else { 'tenant run' }
$isTenantRun = $runSource -eq 'tenant run'
if (-not $isTenantRun -and (Test-IsPublicEvidencePath -Path $PublicOutputRoot -EvidenceRoot $evidenceRoot)) {
    if ($explicitPublicRoot) {
        throw "Refusing to write a $runSource summary into the public evidence tree ($PublicOutputRoot): lab/evidence holds only real tenant runs. The raw copy stays private in $rawRun. Leave -PublicOutputRoot at its default (non-tenant runs then go to lab/evidence/out/assessments-summary) or point it outside lab/evidence."
    }
    $PublicOutputRoot = Join-Path $evidenceRoot 'out' 'assessments-summary'
    $pubRun = Join-Path ([System.IO.Path]::GetFullPath($PublicOutputRoot)) $runName
    if (Test-Path -LiteralPath $pubRun) { throw "$pubRun already exists. Each run needs a new -RunId; evidence folders are never reused." }
    Write-Warning "NOT A TENANT RUN ($runSource): the summary goes to $pubRun (gitignored), not the public evidence tree."
}
if ($PSCmdlet.ShouldProcess($pubRun, 'create the summary folder')) {
    New-Item -ItemType Directory -Path $pubRun -Force | Out-Null
}

# ---------------------------------------------------------------------------
# 3. Hash the raw run (private): manifest.json + SHA256SUMS
# ---------------------------------------------------------------------------
$rawFiles = @()
$manifestSha = $null
$manifestPath = Join-Path $rawRun 'manifest.json'
$sumsPath = Join-Path $rawRun 'SHA256SUMS'
if ($PSCmdlet.ShouldProcess($rawRun, 'hash raw outputs (manifest.json, SHA256SUMS)')) {
    $rawFiles = @(Get-HashManifest -Root $rawRun)
    $rawManifest = [ordered]@{
        run           = $runName
        generatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        generatedBy   = "Invoke-BaselineAssessment.ps1 $ToolVersion"
        hashAlgorithm = 'SHA256'
        tools         = $toolState
        excluded      = @('_work/ (raw Zero Trust export: not evidence, not uploaded)')
        files         = $rawFiles
    }
    ($rawManifest | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $manifestPath -Encoding utf8
    ($rawFiles | ForEach-Object { "$($_.sha256)  $($_.path)" }) -join "`n" | Set-Content -LiteralPath $sumsPath -Encoding utf8 -NoNewline
    Add-Content -LiteralPath $sumsPath -Value '' -Encoding utf8   # trailing newline for shasum -c
    $manifestSha = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Console "  [+] Hashed $($rawFiles.Count) raw file(s); manifest.json sha256 $manifestSha" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 4. Public-safe summary object
# ---------------------------------------------------------------------------
$summary = [ordered]@{
    schema       = 'contoso-baseline-assessment/1'
    runId        = $RunId
    phase        = $Phase
    generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    toolVersion  = $ToolVersion
    # tenant = every tool that produced results ran against the same real
    # tenant; anything else (the CISA sample, a fixture, no tenant id) is
    # non-tenant and never written into the public evidence tree.
    source       = [ordered]@{
        kind      = if ($isTenantRun) { 'tenant' } else { 'non-tenant' }
        detail    = $runSource
        scubaGear = if ($toolSources.Contains('scubaGear')) { $toolSources.scubaGear.kind } else { $null }
        zeroTrust = if ($toolSources.Contains('zeroTrust')) { $toolSources.zeroTrust.kind } else { $null }
    }
    scubaGear    = [ordered]@{
        status = $toolState.scubaGear.status; reason = ConvertTo-PublicSafeText $toolState.scubaGear.reason; mode = $toolState.scubaGear.mode
        meta = if ($scuba) { $scuba.meta } else { $null }
        summary = if ($scuba) { $scuba.summary } else { $null }
        kpi = if ($scuba) { $scuba.kpi } else { $null }
        # @(if ...) not if/else: an `if` returning an empty or one-item array
        # unrolls it, and the JSON would say null / an object instead of [].
        unmapped = @(if ($scuba) { $scuba.unmapped })
        controls = @(if ($scuba) { $scuba.controls })
    }
    zeroTrust    = [ordered]@{
        status = $toolState.zeroTrust.status; reason = ConvertTo-PublicSafeText $toolState.zeroTrust.reason; mode = $toolState.zeroTrust.mode
        pillar = $ZtPillar
        meta = if ($zt) { $zt.meta } else { $null }
        kpi = if ($zt) { $zt.kpi } else { $null }
        byStatus = if ($zt) { $zt.byStatus } else { $null }
        tests = @(if ($zt) { $zt.tests })
    }
    rawManifest  = [ordered]@{
        location       = 'private: lab/evidence/out/assessments (gitignored) + WORM container'
        manifestSha256 = $manifestSha
        files          = $rawFiles
    }
    worm         = [ordered]@{ status = 'not-uploaded'; container = $ContainerName; prefix = "$blobPrefix/"; uploaded = 0; failed = 0; immutabilityReported = 0 }
    comparison   = $null
}

# Before/after delta.
$baselineFile = $BaselineSummaryPath
if (-not $baselineFile -and $Phase -eq 'after' -and (Test-Path -LiteralPath $PublicOutputRoot)) {
    $baselineFile = Get-ChildItem -LiteralPath $PublicOutputRoot -Directory |
        Where-Object { $_.Name -like '*-before' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'summary.json')) } |
        Sort-Object Name -Descending | Select-Object -First 1 |
        ForEach-Object { Join-Path $_.FullName 'summary.json' }
}
if ($baselineFile) {
    try {
        $baseline = Get-Content -LiteralPath $baselineFile -Raw | ConvertFrom-Json -Depth 100
        $baselineKind = [string](Get-Prop (Get-Prop $baseline 'source') 'kind')
        if ($baselineKind -ne $summary.source.kind) {
            # A tenant delta against a sample (or the reverse) would be fiction.
            $summary.comparison = [ordered]@{ status = "not compared: the baseline is a '$(if ($baselineKind) { $baselineKind } else { 'unrecorded' })' run, this one is '$($summary.source.kind)'" }
            Write-Warning $summary.comparison.status
        }
        else { $summary.comparison = Compare-AssessmentRun -Baseline $baseline -Current $summary }
    }
    catch {
        Write-Warning "Baseline unreadable: $($_.Exception.Message)"
        $summary.comparison = [ordered]@{ status = ConvertTo-PublicSafeText "baseline unreadable: $($_.Exception.Message)" }
    }
}
elseif ($Phase -eq 'after') {
    $summary.comparison = [ordered]@{ status = 'no "before" run found under the public root; pass -BaselineSummaryPath' }
    Write-Warning $summary.comparison.status
}

# ---------------------------------------------------------------------------
# 5. Upload raw files to the WORM store
# ---------------------------------------------------------------------------
$uploadFailures = 0
$canUpload = $false
if ($SkipUpload) {
    $summary.worm.status = 'skipped (-SkipUpload)'
}
elseif (-not $StorageAccountName) {
    $summary.worm.status = 'not uploaded: no -StorageAccountName'
    Write-Warning 'No -StorageAccountName: nothing goes to the WORM store. Upload this run before relying on it as evidence.'
}
elseif (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    $summary.worm.status = 'failed: Azure CLI (az) not found' # fixed text: no az output reaches the public summary
    $uploadFailures++
    Write-Warning $summary.worm.status
}
else {
    $null = & az account show --only-show-errors --output none 2>&1
    if ($LASTEXITCODE -ne 0) {
        $summary.worm.status = 'failed: az is not signed in (az login)'
        $uploadFailures++
        Write-Warning $summary.worm.status
    }
    else { $canUpload = $true }
}

if ($canUpload -and $PSCmdlet.ShouldProcess("$StorageAccountName/$ContainerName/$blobPrefix/raw/", "upload $($rawFiles.Count + 2) raw file(s)")) {
    $toSend = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($rf in $rawFiles) { $toSend.Add(@{ path = $rf.path; sha256 = $rf.sha256 }) }
    $toSend.Add(@{ path = 'manifest.json'; sha256 = $manifestSha })
    $toSend.Add(@{ path = 'SHA256SUMS'; sha256 = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLowerInvariant() })
    foreach ($f in $toSend) {
        try {
            $r = Send-EvidenceFile -File (Join-Path $rawRun $f.path) -BlobName "$blobPrefix/raw/$($f.path)" -Sha256 $f.sha256
            $summary.worm.uploaded++
            if ($r.immutabilityExpiry) { $summary.worm.immutabilityReported++ }
        }
        catch {
            $summary.worm.failed++; $uploadFailures++
            Write-Warning "Upload failed for $($f.path): $($_.Exception.Message)"
        }
    }
    $summary.worm.status = if ($summary.worm.failed) { 'partial' } else { 'uploaded' }
    if ($summary.worm.uploaded -and -not $summary.worm.immutabilityReported) {
        Write-Warning 'No uploaded blob reported an immutability expiry. Check the account policy (az storage account show --query immutableStorageWithVersioning) before relying on WORM.'
    }
}

# ---------------------------------------------------------------------------
# 6. Write the public summary (summary.json, then SUMMARY.md which carries
#    summary.json's hash), then upload both.
# ---------------------------------------------------------------------------
$pubJson = Join-Path $pubRun 'summary.json'
$pubMd = Join-Path $pubRun 'SUMMARY.md'
if ($PSCmdlet.ShouldProcess($pubRun, 'write public summary.json + SUMMARY.md')) {
    ($summary | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $pubJson -Encoding utf8
    $pubJsonSha = (Get-FileHash -LiteralPath $pubJson -Algorithm SHA256).Hash.ToLowerInvariant()
    Format-SummaryMarkdown -S $summary -SummaryJsonSha256 $pubJsonSha | Set-Content -LiteralPath $pubMd -Encoding utf8
    Write-Console "  [+] Public summary: $pubJson (sha256 $pubJsonSha)" -ForegroundColor Green

    if ($canUpload) {
        foreach ($f in $pubJson, $pubMd) {
            try {
                $sha = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant()
                $null = Send-EvidenceFile -File $f -BlobName "$blobPrefix/public/$(Split-Path -Leaf $f)" -Sha256 $sha
            }
            catch { $uploadFailures++; Write-Warning "Upload failed for $(Split-Path -Leaf $f): $($_.Exception.Message)" }
        }
    }
}

# ---------------------------------------------------------------------------
# Exit status: honest, never silent.
# ---------------------------------------------------------------------------
$toolProblems = @($toolState.GetEnumerator() | Where-Object { $_.Value.status -in 'failed', 'skipped' } | ForEach-Object Key)
Write-Console "`nRun $runName complete." -ForegroundColor Cyan
if ($toolProblems -or $uploadFailures) {
    Write-Warning "Incomplete: tools not producing results: $($toolProblems -join ', '); upload failures: $uploadFailures."
}
[pscustomobject]$summary
if (-not $WhatIfPreference -and ($toolProblems -or $uploadFailures)) { exit 1 }
