<#
.SYNOPSIS
    Measures the identity program's KPIs from the live tenant (and the local
    PAM stand-ins) and writes one dated, hashed snapshot to
    lab/evidence/kpis/<timestamp>.json. Run once as the BASELINE before a
    change and again AFTER it; -CompareTo prints the deltas.

.DESCRIPTION
    Replaces the illustrative segment-9 metrics slide with measured numbers.
    Every KPI is computed from a read-only query; nothing is estimated. A KPI
    whose source cannot be read is recorded as status "failed" with the
    error, and one that does not apply (no leaver in the window, PAM stack not
    running) as "not-measured" with the reason. Neither is ever written as 0.

    KPIS (snapshot file key -> definition)
      admin_standing_users            humans holding a PRIVILEGED directory role
                                      permanently (directly, or as a permanent
                                      member of a role-holding group).
                                      Break-glass is counted apart, by design.
                                      PRIVILEGED = Microsoft's isPrivileged
                                      label UNION the lab tier map (Get-RoleTierMap:
                                      Global Administrator, Tier 0, Tier 1 -
                                      some Tier-1 roles carry no Microsoft label)
                                      UNION any role held by a PIM tier group
                                      (mailNickname -PimTierGroupPrefix* or
                                      -PimGroupMailNicknames). So a direct
                                      standing Global Administrator (the build
                                      account) and a permanent member of any
                                      tier group both count. detail.byTier
                                      splits it (global_admin / tier0 / tier1 /
                                      other); a person can sit in several tiers.
      admin_eligible_only_users       humans who can only ACTIVATE a privileged
                                      role (PIM role eligibility, or PIM-for-
                                      Groups eligibility on a role-holding group)
      admin_jit_pct                   eligible-only / (standing + eligible-only)
      privileged_service_principals   workload identities (service principals,
                                      managed identities) that hold a privileged
                                      directory role (active or eligible) OR a
                                      high-privilege Microsoft Graph APPLICATION
                                      permission (Get-HighPrivilegeGraphAppRole,
                                      e.g. RoleManagement.ReadWrite.Directory).
                                      The pipeline APPLY identity holds no
                                      directory role - it is counted through
                                      its Graph permissions (ADR 0005).
                                      detail splits viaDirectoryRole /
                                      viaGraphApplicationPermission / byPermission.
      phishing_resistant_pct          enabled members with a passkey / WHfB /
                                      platform credential (break-glass excluded)
      phishing_resistant_device_bound_pct   the attested-capable subset
      ca_mfa_coverage_pct             enabled members in scope of >= 1 ENABLED
                                      policy that requires MFA or an
                                      authentication strength for ALL apps with
                                      no narrowing condition (break-glass
                                      excluded from numerator and denominator)
      ca_mfa_coverage_incl_report_only_pct   same, counting report-only policies
                                      (what graduating them would give)
      access_review_completion_pct    decisions a PERSON made / all decisions
                                      (instances ending in the lookback window).
                                      A default the service applied (reviewer
                                      'AAD Access Reviews' / all-zero id,
                                      -SystemReviewerNames) is NOT a review:
                                      with defaultDecision Deny + autoApply it
                                      would otherwise read ~100% with nobody
                                      answering. Same rule as 10-Review-KPIs.ps1
                                      (Test-IsHumanDecision, parity-tested);
                                      service-applied defaults are reported in
                                      the detail.
      access_review_revocation_pct    person-made Deny / person-made decisions
      access_review_revocation_applied_pct   person-made Deny applied successfully
      stale_accounts                  enabled members with no sign-in for
                                      -StaleDays (or never, when created before
                                      that), break-glass excluded
      hr_to_disable_minutes           per leaver: inbound-provisioning "disable"
                                      event -> Entra disable audit event
                                      (median / p90 / max)
      nhi_expired_or_orphaned         NHIs with an expired credential still
                                      attached OR no accountable owner (split
                                      into nhi_with_expired_credential and
                                      nhi_orphaned). Taken from the summary of
                                      06-NHI-Inventory.ps1 (-NhiInventoryPath,
                                      all NHI kinds); without it, a narrower
                                      direct read of app registrations.
      pam_vaulted_pct                 vaulted / eligible privileged AD accounts
      pam_rotated_within_policy_pct   vaulted accounts rotated within their tier's
                                      policy. Both straight from lab/pam/reconcile.sh
                                      (discovery x Vault), not recomputed here.
      pam_sessions_recorded_pct       brokered sessions (Guacamole history) with
                                      a recording
      secure_score_pct                Microsoft Secure Score (Graph
                                      /security/secureScores, one record a day,
                                      about 90 days kept): today's currentScore
                                      / maxScore, and in detail the same on the
                                      baseline day (-SecureScoreBaselineDate,
                                      default the oldest record kept) plus every
                                      control whose score moved between the two.
                                      Opt-in (-IncludeSecureScore): it needs
                                      SecurityEvents.Read.All, which the other
                                      KPIs do not. Without the switch it is
                                      not-measured, never 0.

    WHAT THE FILE CONTAINS: aggregates only (counts, percentages, minutes).
    No names, UPNs, object ids or tenant id - the kpis folder is public.
    Per-user detail for remediation goes to the gitignored
    lab/evidence/out/kpis/ (-DetailDirectory). A <file>.sha256 sidecar is
    written for the evidence store.

.PREREQUISITES
    * Entra ID P1 (signInActivity, sign-in/provisioning logs), P2 (PIM data,
      access reviews). Roles: Global Reader + Reports Reader is enough.
    * PAM KPIs: lab/pam stack up and onboarded, and lab/pam/discover.sh +
      lab/pam/reconcile.sh run within -PamReportMaxAgeHours (default 24). The
      Guacamole admin secret is read from lab/pam/.secrets/guacadmin-password
      (local stack only) and never printed.
    * Module: Microsoft.Graph.Authentication (Invoke-MgGraphRequest only).

.GRAPH SCOPES  (delegated, READ-ONLY)
    User.Read.All, Group.Read.All, Directory.Read.All
    AuditLog.Read.All                    signInActivity, registration report,
                                         provisioning logs, directory audits
    RoleManagement.Read.Directory        role assignment/eligibility instances
    PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.Read.AzureADGroup
                                         PIM for Groups membership
    Policy.Read.All                      Conditional Access policies
    AccessReview.Read.All                access-review decisions
    SecurityEvents.Read.All              Secure Score history (-IncludeSecureScore
                                         only; least privileged per Microsoft
                                         Learn, List secureScores)
    Application.Read.All                 Graph application-permission grants
                                         (servicePrincipals/{id}/appRoleAssignedTo)
                                         and NHI credentials (no -NhiInventoryPath)

.PARAMETER Label
    Free text stored in the file, e.g. baseline, after-ca-graduation.

.PARAMETER OutputDirectory
    Public snapshot folder. Default lab/evidence/kpis.

.PARAMETER DetailDirectory
    Gitignored per-object detail. Default lab/evidence/out/kpis.

.PARAMETER CompareTo
    An earlier snapshot file; deltas are printed and stored in the new file.

.PARAMETER InboundProvisioningServicePrincipalId
    Service principal object id of the API-driven inbound provisioning app
    (the -ServicePrincipalId given to mock-hr/Invoke-InboundProvisioning.ps1).
    Without it, hr_to_disable_minutes is not measured.

.PARAMETER NhiInventoryPath
    nhi_inventory.json from a TENANT run of 06-NHI-Inventory.ps1 (refused if
    it is -Offline mock output, has a FAILED data source, or is > 24 h old).

.PARAMETER PimTierGroupPrefix
    mailNickname prefix of the PIM tier groups (lab/terraform/modules/pim
    tiers.tf). Every role such a group holds or is eligible for counts as
    privileged. Default pim-tier.

.PARAMETER PimGroupMailNicknames
    Other PIM-governed role-holding groups. Default privileged-iam-admins.

.PARAMETER SkipPam
    Do not read the local PAM stand-ins.

.PARAMETER PamReconcilePath
    The reconcile report. Default lab/pam/out/reconcile-latest.csv.

.PARAMETER UseAzureCliToken
    App-only sign-in: take a Microsoft Graph token from the Azure CLI session
    (`az account get-access-token --resource-type ms-graph`) and connect
    with it, always that identity, never a leftover context. For the lab
    operator: `lab/scripts/operator/op pwsh ./<this script> -UseAzureCliToken`
    (its own az profile, certificate sign-in). The token stays in this
    process: never in argv, a file or the output (masked in GitHub Actions).

.EXAMPLE
    Connect-MgGraph -Scopes 'User.Read.All','Group.Read.All','Directory.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory','PrivilegedEligibilitySchedule.Read.AzureADGroup','PrivilegedAssignmentSchedule.Read.AzureADGroup','Policy.Read.All','AccessReview.Read.All','Application.Read.All'
    ./08-Measure-KPIs.ps1 -Label baseline -SkipPam
    # ... terraform apply / graduate a policy / run the rollout ...
    ./08-Measure-KPIs.ps1 -Label after -CompareTo ../../evidence/kpis/<baseline>.json

.OUTPUTS
    The snapshot object (also written as JSON).

.NOTES
    RAN - tenant: baseline 2026-10-27 (E11), after 2026-10-29 (E11b) and
    2026-11-05 (app-only as the lab operator, E72). The PAM KPIs have not
    read a live Vault (-SkipPam on every tenant run so far).
    roleAssignmentScheduleInstances includes assignments made directly through
      the role assignments API (Graph docs, "List roleAssignmentScheduleInstances").
    verify: such direct assignments (Terraform, the tenant-creation Global
      Administrator) show assignmentType "Assigned" (05-Reports.ps1 relies on
      the same).
    verify: whether role-holding groups also yield per-user instance rows with
      memberType "Group". If they do, those rows are skipped here: the group's
      own row plus its PIM-for-Groups membership already classifies the user
      (otherwise a JIT member would be counted as standing).
    verify: appRoleAssignedTo on the Microsoft Graph service principal lists
      every application-permission grant, managed identities included.
    verify: access-package assignment reviews appear under
      /identityGovernance/accessReviews/definitions.
    verify: Cloud Sync's disable of a synced user is logged in directoryAudits
      as "Update user" (AccountEnabled -> false) or "Disable account".
    Checked live 2026-11-05: the inbound provisioning log's sourceIdentity.id
      is the HR externalId (= the Entra employeeId), and a leaver is logged as
      provisioningAction 'update' with accountDisabled -> True
      (Test-IsHrLeaverEvent).
    verify: Guacamole 1.6 history entries list a recording in "logs" when
      RECORDING_SEARCH_PATH is set (lab/pam/docker-compose.yml sets it).
    lab/pam/reconcile.sh contract used here: CSV columns account, status
      (VAULTED|EXCEPTION|HELD|GAP|ORPHAN) and rotated_within_policy (yes|no|n/a);
      tests/08-Measure-KPIs.Tests.ps1 checks the header in reconcile.sh.
    06-NHI-Inventory.ps1 contract used here: Source, DataSources[].Status,
      GeneratedAtUtc, Summary.nhiCount and Summary.kpi.{expiredOrOrphanedNhi,
      nhiWithExpiredCredential, orphanedNhi}.
    The method lists in Get-AuthMethodClass duplicate 07-Passwordless-Rollout.ps1
    on purpose; tests/08-Measure-KPIs.Tests.ps1 asserts they agree.

.WHAT IT DEMONSTRATES
    Measured outcomes instead of an illustrative slide: a repeatable,
    tamper-evident before/after record of zero standing privilege, phishing-
    resistant coverage, CA coverage, review hygiene, leaver latency, NHI
    hygiene and PAM coverage.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9._-]{1,40}$', ErrorMessage = 'Label: letters, digits, . _ - only.')]
    [string]$Label = 'snapshot',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'kpis'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DetailDirectory = (Join-Path $PSScriptRoot '..' '..' 'evidence' 'out' 'kpis'),

    [Parameter()]
    [string]$CompareTo = '',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$AccessReviewLookbackDays = 90,

    [Parameter()]
    # Reviewer display names the SERVICE uses when it applies a default
    # decision (same default as 10-Review-KPIs.ps1).
    [string[]]$SystemReviewerNames = @('AAD Access Reviews', 'Microsoft Entra Access Reviews'),

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$HrToDisableLookbackDays = 30,

    [Parameter()]
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$InboundProvisioningServicePrincipalId = '',

    [Parameter()]
    [string]$NhiInventoryPath = '',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$BreakGlassGroupMailNickname = 'break-glass-admins',

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]{1,40}$', ErrorMessage = 'PimTierGroupPrefix: lowercase letters, digits, - only.')]
    [string]$PimTierGroupPrefix = 'pim-tier',

    [Parameter()]
    [ValidatePattern('^[a-z0-9-]{1,64}$', ErrorMessage = 'PimGroupMailNicknames: lowercase letters, digits, - only.')]
    [string[]]$PimGroupMailNicknames = @('privileged-iam-admins'),

    [Parameter()]
    [switch]$SkipPam,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PamReconcilePath = (Join-Path $PSScriptRoot '..' '..' 'pam' 'out' 'reconcile-latest.csv'),

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$PamReportMaxAgeHours = 24,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GuacamoleUrl = 'http://127.0.0.1:8081/guacamole',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GuacamoleAdminSecretFile = (Join-Path $PSScriptRoot '..' '..' 'pam' '.secrets' 'guacadmin-password'),

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$PamSessionLookbackDays = 30,

    # App-only sign-in from the Azure CLI session (the lab operator via
    # lab/scripts/operator/op, or azure/login over OIDC).
    [Parameter()]
    [switch]$UseAzureCliToken,

    # Microsoft Secure Score history (needs SecurityEvents.Read.All).
    [Parameter()]
    [switch]$IncludeSecureScore,

    # The "before" day for Secure Score: the first daily record on or after
    # this date (yyyy-MM-dd). Empty = the oldest record Microsoft still keeps.
    [Parameter()]
    [ValidatePattern('^$|^\d{4}-\d{2}-\d{2}$')]
    [string]$SecureScoreBaselineDate = ''
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# PURE KPI FUNCTIONS - no I/O. Unit-tested in tests/08-Measure-KPIs.Tests.ps1,
# which loads them from this file's syntax tree without running the script.
# =============================================================================

function Get-Field {
    # Index-walk nested dictionaries; a missing key is $null (dot access on a
    # missing hashtable key throws under StrictMode).
    param($Object, [string[]]$Path)
    $cur = $Object
    foreach ($k in $Path) {
        if ($cur -isnot [System.Collections.IDictionary] -or -not $cur.Contains($k)) { return $null }
        $cur = $cur[$k]
    }
    return $cur
}

function Get-Pct {
    param([double]$Numerator, [double]$Denominator)
    if ($Denominator -le 0) { return $null }
    return [math]::Round(100.0 * $Numerator / $Denominator, 1)
}

function Get-Percentile {
    # Nearest-rank percentile of a numeric list.
    param([double[]]$Values, [ValidateRange(1, 100)][int]$P)
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $rank = [math]::Ceiling($P / 100.0 * $v.Count)
    return $v[[math]::Max(0, $rank - 1)]
}

function Get-AuthMethodClass {
    # Same lists as 07-Passwordless-Rollout.ps1 (parity-tested).
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
    return [pscustomobject]@{ Class = $class; PhishingResistant = ($hasDb -or $hasSy); DeviceBound = $hasDb; Methods = ($m -join ';') }
}

function Measure-PhishingResistant {
    param(
        [string[]]$EnabledMemberIds,
        [hashtable]$RegistrationById,          # id -> methodsRegistered
        [AllowEmptyCollection()][string[]]$BreakGlassIds = @()
    )
    $ids = @($EnabledMemberIds | Where-Object { $_ -notin $BreakGlassIds })
    $pr = 0; $db = 0
    foreach ($id in $ids) {
        $c = Get-AuthMethodClass -MethodsRegistered $(if ($RegistrationById.ContainsKey($id)) { @($RegistrationById[$id]) } else { @() })
        if ($c.PhishingResistant) { $pr++ }
        if ($c.DeviceBound) { $db++ }
    }
    $bgWithKey = @($BreakGlassIds | Where-Object { $RegistrationById.ContainsKey($_) -and (Get-AuthMethodClass -MethodsRegistered @($RegistrationById[$_])).DeviceBound }).Count
    return [pscustomobject]@{
        Denominator = $ids.Count; PhishingResistant = $pr; DeviceBound = $db
        Pct = Get-Pct $pr $ids.Count; PctDeviceBound = Get-Pct $db $ids.Count
        BreakGlassAccounts = @($BreakGlassIds).Count; BreakGlassWithDeviceBoundKey = $bgWithKey
    }
}

function Get-RoleTierMap {
    # Directory role template id -> lab tier (Enterprise Access Model: Tier 0 =
    # control plane, Tier 1 = management plane), as lab/terraform/modules/pim
    # binds them to PIM tier groups. Global Administrator is its own key: it is
    # never bound to a tier group (per-person direct eligibility; break-glass
    # keeps it standing). Template ids checked against Learn "Microsoft Entra
    # built-in roles" (entra-docs permissions-reference) on 2026-10-20. Same
    # map in 01-Verify-Baseline.ps1; tests/08-Measure-KPIs.Tests.ps1 checks the
    # two agree and cover every modules/pim pim_tier_groups default.
    return [ordered]@{
        '62e90394-69f5-4237-9190-012177145e10' = @{ Name = 'Global Administrator'; Tier = 'global_admin' }
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = @{ Name = 'Privileged Role Administrator'; Tier = 'tier0' }
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = @{ Name = 'Privileged Authentication Administrator'; Tier = 'tier0' }
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ Name = 'Security Administrator'; Tier = 'tier0' }
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = @{ Name = 'Conditional Access Administrator'; Tier = 'tier0' }
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = @{ Name = 'Hybrid Identity Administrator'; Tier = 'tier0' }
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = @{ Name = 'Application Administrator'; Tier = 'tier0' }
        '158c047a-c907-4556-b7ef-446551a6b5f7' = @{ Name = 'Cloud Application Administrator'; Tier = 'tier0' }
        '0526716b-113d-4c15-b2c8-68e3c22b9f80' = @{ Name = 'Authentication Policy Administrator'; Tier = 'tier0' }
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = @{ Name = 'User Administrator'; Tier = 'tier1' }
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' = @{ Name = 'Groups Administrator'; Tier = 'tier1' }
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = @{ Name = 'Authentication Administrator'; Tier = 'tier1' }
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = @{ Name = 'Helpdesk Administrator'; Tier = 'tier1' }
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = @{ Name = 'Intune Administrator'; Tier = 'tier1' }
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = @{ Name = 'Exchange Administrator'; Tier = 'tier1' }
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = @{ Name = 'SharePoint Administrator'; Tier = 'tier1' }
        '69091246-20e8-4a56-aa4d-066075b2a7a8' = @{ Name = 'Teams Administrator'; Tier = 'tier1' }
        '4d6ac14f-3453-41d0-bef9-a3e0c569773a' = @{ Name = 'License Administrator'; Tier = 'tier1' }
        '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e' = @{ Name = 'Identity Governance Administrator'; Tier = 'tier1' }
        '59d46f88-662b-457b-bceb-5c3809e5908f' = @{ Name = 'Lifecycle Workflows Administrator'; Tier = 'tier1' }
    }
}

function Get-HighPrivilegeGraphAppRole {
    # Microsoft Graph APPLICATION permissions (app roles on the Microsoft Graph
    # service principal) that let a workload identity grant itself or someone
    # else privileged access, or switch off the controls that would stop it.
    # appRoleId -> permission name. Ids are the "Application" column of Learn
    # "Microsoft Graph permissions reference" (microsoft-graph-docs-contrib,
    # ms.date 2026-09-14), read 2026-10-20. The collector also matches by name
    # against the tenant's own Graph app roles, so a changed id is still caught.
    return [ordered]@{
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory'                     # assign any directory role, itself included
        '06b708a9-e830-4db3-a914-8e69da51d44f' = 'AppRoleAssignment.ReadWrite.All'                        # grant itself any application permission
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'                              # add a credential to any app, then act as it
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
        '01c0a623-fc9b-48e9-b794-0756f8e8f067' = 'Policy.ReadWrite.ConditionalAccess'                     # switch off or carve out Conditional Access
        '29c18626-4985-4dcd-85c0-193eef327366' = 'Policy.ReadWrite.AuthenticationMethod'                  # weaken the methods policy (TAP, passkey profiles)
        '50483e42-d915-4231-9639-7fdb7fd190e5' = 'UserAuthenticationMethod.ReadWrite.All'                 # add a sign-in method (e.g. TAP) to any user
        '62a82d76-70ea-41e2-9197-370581804d09' = 'Group.ReadWrite.All'                                    # membership of access / CA-scoping groups
        '2f6817f8-7b12-4f0f-bc18-eeaf60705a9e' = 'PrivilegedAccess.ReadWrite.AzureADGroup'                # PIM for Groups assignments
        '31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad' = 'RoleManagementPolicy.ReadWrite.Directory'               # strip approval / MFA from role activation
        'b38dcc4d-a239-4ed6-aa84-6c65b284f97c' = 'RoleManagementPolicy.ReadWrite.AzureADGroup'            # same, for the PIM tier groups' policies
        'dd199f4a-f148-40a4-a2ec-f0069cc799ec' = 'RoleAssignmentSchedule.ReadWrite.Directory'             # active directory-role assignments through PIM
        'fee28b28-e1f3-4841-818e-2704dc62245f' = 'RoleEligibilitySchedule.ReadWrite.Directory'            # directory-role eligibility through PIM
        '41202f2c-f7ab-45be-b001-85c9728b9d69' = 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup'    # active member of a role-holding group
        '618b6020-bca8-4de6-99f6-ef445fa4d857' = 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup'   # eligible member of a role-holding group
        '7e05723c-0bb0-42da-be95-ae9f08a6e53c' = 'Domain.ReadWrite.All'                                   # federate a domain = sign in as its users
        '8e8e4742-1d95-4f68-9d56-6ee75648c72a' = 'DelegatedPermissionGrant.ReadWrite.All'                 # consent any delegated permission for any app
    }
}

function Measure-AdminPosture {
    # Assignments are pre-filtered to PRIVILEGED roles and normalised to
    # objects with PrincipalId, PrincipalType (user|group|servicePrincipal),
    # AssignmentType (Assigned|Activated; eligibility rows: Eligible) and
    # RoleDefinitionId.
    # GroupMembership: groupId -> @{ Permanent; Activated; Eligible } user ids
    # (PIM for Groups member access for role-holding groups).
    # RoleTier: role template id -> 'global_admin' | 'tier0' | 'tier1'; any
    # other privileged role is 'other'. Only the per-tier split uses it.
    param(
        [AllowEmptyCollection()][object[]]$ActiveAssignments = @(),
        [AllowEmptyCollection()][object[]]$EligibleAssignments = @(),
        [hashtable]$GroupMembership = @{},
        [AllowEmptyCollection()][string[]]$BreakGlassUserIds = @(),
        [string]$BreakGlassGroupId = '',
        [hashtable]$RoleTier = @{}
    )
    $tiers = @('global_admin', 'tier0', 'tier1', 'other')
    $tierById = $RoleTier
    function Get-EmptyIdSet { return , [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
    $standing = Get-EmptyIdSet; $eligible = Get-EmptyIdSet; $activated = Get-EmptyIdSet; $bg = Get-EmptyIdSet; $sps = Get-EmptyIdSet
    $standingT = @{}; $eligibleT = @{}
    foreach ($t in $tiers) { $standingT[$t] = Get-EmptyIdSet; $eligibleT[$t] = Get-EmptyIdSet }
    function Get-TierOf([string]$RoleId) {
        if ($RoleId -and $tierById.ContainsKey($RoleId) -and [string]$tierById[$RoleId] -in $tiers) { return [string]$tierById[$RoleId] }
        return 'other'
    }
    # Every add goes through these two so the per-tier split cannot drift from
    # the totals. Activated users are JIT: they land in the eligible sets.
    function Add-Standing([string]$UserId, [string]$Tier) { [void]$standing.Add($UserId); [void]$standingT[$Tier].Add($UserId) }
    function Add-Eligible([string]$UserId, [string]$Tier, [switch]$Jit) {
        [void]$eligible.Add($UserId); [void]$eligibleT[$Tier].Add($UserId)
        if ($Jit) { [void]$activated.Add($UserId) }
    }
    function Get-MemberSet([hashtable]$Map, [string]$GroupId, [string]$Kind) {
        # Always called inside @(): a one-element result must stay an array
        # (string + string would concatenate two ids into one).
        if (-not $Map.ContainsKey($GroupId)) { return }
        $g = $Map[$GroupId]
        if ($g -is [System.Collections.IDictionary] -and $g.Contains($Kind)) { $g[$Kind] | Where-Object { $_ } }
    }
    foreach ($a in @($ActiveAssignments)) {
        $tier = Get-TierOf ([string]$a.RoleDefinitionId)
        if ($a.PrincipalType -eq 'servicePrincipal') { [void]$sps.Add($a.PrincipalId) }
        elseif ($a.PrincipalType -eq 'user') {
            if ($a.PrincipalId -in $BreakGlassUserIds) { [void]$bg.Add($a.PrincipalId) }
            elseif ($a.AssignmentType -eq 'Activated') { Add-Eligible $a.PrincipalId $tier -Jit }
            else { Add-Standing $a.PrincipalId $tier }
        }
        elseif ($a.PrincipalType -eq 'group') {
            $perm = @(Get-MemberSet $GroupMembership $a.PrincipalId 'Permanent')
            $act = @(Get-MemberSet $GroupMembership $a.PrincipalId 'Activated')
            $elig = @(Get-MemberSet $GroupMembership $a.PrincipalId 'Eligible')
            if ($BreakGlassGroupId -and $a.PrincipalId -eq $BreakGlassGroupId) { foreach ($u in ($perm + $act)) { [void]$bg.Add($u) } }
            elseif ($a.AssignmentType -eq 'Activated') {
                # A role held through an ACTIVATED assignment on a group is JIT for everyone in it.
                foreach ($u in ($perm + $act)) { Add-Eligible $u $tier -Jit }
                foreach ($u in $elig) { Add-Eligible $u $tier }
            }
            else {
                # Group holds the role permanently: permanent members are standing,
                # members inside a PIM-for-Groups activation are JIT, eligible members can activate.
                foreach ($u in $perm) { Add-Standing $u $tier }
                foreach ($u in $act) { Add-Eligible $u $tier -Jit }
                foreach ($u in $elig) { Add-Eligible $u $tier }
            }
        }
    }
    foreach ($e in @($EligibleAssignments)) {
        $tier = Get-TierOf ([string]$e.RoleDefinitionId)
        if ($e.PrincipalType -eq 'servicePrincipal') { [void]$sps.Add($e.PrincipalId) }
        elseif ($e.PrincipalType -eq 'user') { if ($e.PrincipalId -notin $BreakGlassUserIds) { Add-Eligible $e.PrincipalId $tier } }
        elseif ($e.PrincipalType -eq 'group') {
            # Everyone who is or can become a member of an ELIGIBLE group is eligible.
            foreach ($k in 'Permanent', 'Eligible', 'Activated') { foreach ($u in @(Get-MemberSet $GroupMembership $e.PrincipalId $k)) { Add-Eligible $u $tier } }
        }
    }
    # Break-glass is counted apart, everywhere.
    foreach ($u in @($bg)) {
        [void]$standing.Remove($u); [void]$eligible.Remove($u); [void]$activated.Remove($u)
        foreach ($t in $tiers) { [void]$standingT[$t].Remove($u); [void]$eligibleT[$t].Remove($u) }
    }
    # Standing wins: someone standing AND eligible is a standing admin (per
    # tier for the split: standing in Tier 1 and eligible for Tier 0 counts
    # once in each). A user active right now through an activation is
    # eligible-only, not standing.
    $eligibleOnly = @($eligible | Where-Object { -not $standing.Contains($_) })
    $standingBy = [ordered]@{}; $eligibleBy = [ordered]@{}
    foreach ($t in $tiers) {
        $standingBy[$t] = $standingT[$t].Count
        $eligibleBy[$t] = @($eligibleT[$t] | Where-Object { -not $standingT[$t].Contains($_) }).Count
    }
    return [pscustomobject]@{
        StandingUsers                 = $standing.Count
        EligibleOnlyUsers             = $eligibleOnly.Count
        ActivatedNow                  = @($activated | Where-Object { -not $standing.Contains($_) }).Count
        BreakGlassUsers               = $bg.Count
        PrivilegedServicePrincipals   = $sps.Count
        PrivilegedServicePrincipalIds = @($sps)
        PctJustInTime                 = Get-Pct $eligibleOnly.Count ($standing.Count + $eligibleOnly.Count)
        StandingUserIds               = @($standing)
        StandingUsersByTier           = $standingBy
        EligibleOnlyUsersByTier       = $eligibleBy
    }
}

function Measure-PrivilegedWorkloadIdentity {
    # Union of two routes to privilege for a workload identity:
    #   * a privileged directory role (service principal ids from
    #     Measure-AdminPosture, active or eligible), and
    #   * a high-privilege Microsoft Graph APPLICATION permission
    #     (appRoleAssignedTo rows on the Microsoft Graph service principal:
    #     principalId, principalType, appRoleId).
    # HighPrivilegeAppRoles: appRoleId -> permission name. Only
    # principalType ServicePrincipal counts (managed identities are service
    # principals too).
    param(
        [AllowEmptyCollection()][string[]]$DirectoryRoleSpIds = @(),
        [AllowEmptyCollection()][object[]]$GraphAppRoleAssignments = @(),
        [System.Collections.IDictionary]$HighPrivilegeAppRoles = @{}
    )
    $viaRole = [System.Collections.Generic.HashSet[string]]::new([string[]]@($DirectoryRoleSpIds | Where-Object { $_ }), [StringComparer]::OrdinalIgnoreCase)
    $viaGraph = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $byPerm = @{}
    $known = @{}; foreach ($k in @($HighPrivilegeAppRoles.Keys)) { $known[([string]$k).ToLowerInvariant()] = [string]$HighPrivilegeAppRoles[$k] }
    foreach ($a in @($GraphAppRoleAssignments | Where-Object { $_ })) {
        if ([string](Get-Field $a @('principalType')) -ne 'ServicePrincipal') { continue }
        $roleId = ([string](Get-Field $a @('appRoleId'))).ToLowerInvariant()
        if (-not $known.ContainsKey($roleId)) { continue }
        $spId = [string](Get-Field $a @('principalId'))
        if (-not $spId) { continue }
        [void]$viaGraph.Add($spId)
        $name = $known[$roleId]
        if (-not $byPerm.ContainsKey($name)) { $byPerm[$name] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
        [void]$byPerm[$name].Add($spId)
    }
    $all = [System.Collections.Generic.HashSet[string]]::new($viaRole, [StringComparer]::OrdinalIgnoreCase); $all.UnionWith($viaGraph)
    $both = [System.Collections.Generic.HashSet[string]]::new($viaRole, [StringComparer]::OrdinalIgnoreCase); $both.IntersectWith($viaGraph)
    $perm = [ordered]@{}; foreach ($n in @($byPerm.Keys | Sort-Object)) { $perm[$n] = $byPerm[$n].Count }
    return [pscustomobject]@{
        Total = $all.Count; ViaDirectoryRole = $viaRole.Count; ViaGraphAppRole = $viaGraph.Count; Both = $both.Count
        ByPermission = $perm; Ids = @($all)
    }
}

function Test-UniversalMfaPolicy {
    # Counts only policies that require MFA (or an authentication strength) for
    # every cloud app with no narrowing condition: a policy limited by
    # location, platform, risk, device filter or client app type is not
    # universal coverage. Returns $false for block / device-only policies.
    param([System.Collections.IDictionary]$Policy)
    $gc = Get-Field $Policy @('grantControls')
    if (-not $gc) { return $false }
    $builtIn = @(@(Get-Field $gc @('builtInControls')) | Where-Object { $_ })
    $strength = Get-Field $gc @('authenticationStrength')
    $operator = [string](Get-Field $gc @('operator'))
    $hasStrength = $null -ne $strength -and $null -ne (Get-Field $strength @('id'))
    $requiresMfa = if ($hasStrength) { $operator -eq 'AND' -or $builtIn.Count -eq 0 }
    elseif ($builtIn -contains 'mfa') { $operator -eq 'AND' -or $builtIn.Count -eq 1 }
    else { $false }
    if (-not $requiresMfa) { return $false }
    $c = Get-Field $Policy @('conditions')
    $apps = @(@(Get-Field $c @('applications', 'includeApplications')) | Where-Object { $_ })
    $exApps = @(@(Get-Field $c @('applications', 'excludeApplications')) | Where-Object { $_ })
    if ($apps -notcontains 'All' -or $exApps.Count) { return $false }
    $clients = @(@(Get-Field $c @('clientAppTypes')) | Where-Object { $_ })
    if ($clients.Count -and $clients -notcontains 'all' -and -not ($clients -contains 'browser' -and $clients -contains 'mobileAppsAndDesktopClients')) { return $false }
    foreach ($narrow in 'locations', 'platforms', 'devices') { if (Get-Field $c @($narrow)) { return $false } }
    foreach ($risk in 'signInRiskLevels', 'userRiskLevels') { if (@(@(Get-Field $c @($risk)) | Where-Object { $_ }).Count) { return $false } }
    return $true
}

function Get-PolicyUserScope {
    # Users (from the enabled-member universe) a policy applies to.
    param(
        [System.Collections.IDictionary]$Policy,
        [string[]]$Universe,
        [hashtable]$GroupMembers = @{},   # groupId -> user ids (transitive)
        [hashtable]$RoleMembers = @{}     # roleTemplateId -> user ids (active)
    )
    $u = Get-Field $Policy @('conditions', 'users')
    $in = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $incUsers = @(@(Get-Field $u @('includeUsers')) | Where-Object { $_ })
    if ($incUsers -contains 'All') { foreach ($x in $Universe) { [void]$in.Add($x) } }
    foreach ($x in @($incUsers | Where-Object { $_ -notin 'All', 'None', 'GuestsOrExternalUsers' })) { [void]$in.Add($x) }
    foreach ($g in @(@(Get-Field $u @('includeGroups')) | Where-Object { $_ })) { if ($GroupMembers.ContainsKey($g)) { foreach ($x in @($GroupMembers[$g])) { [void]$in.Add($x) } } }
    foreach ($r in @(@(Get-Field $u @('includeRoles')) | Where-Object { $_ })) { if ($RoleMembers.ContainsKey($r)) { foreach ($x in @($RoleMembers[$r])) { [void]$in.Add($x) } } }
    foreach ($x in @(@(Get-Field $u @('excludeUsers')) | Where-Object { $_ })) { [void]$in.Remove($x) }
    foreach ($g in @(@(Get-Field $u @('excludeGroups')) | Where-Object { $_ })) { if ($GroupMembers.ContainsKey($g)) { foreach ($x in @($GroupMembers[$g])) { [void]$in.Remove($x) } } }
    foreach ($r in @(@(Get-Field $u @('excludeRoles')) | Where-Object { $_ })) { if ($RoleMembers.ContainsKey($r)) { foreach ($x in @($RoleMembers[$r])) { [void]$in.Remove($x) } } }
    $set = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Universe), [StringComparer]::OrdinalIgnoreCase)
    return @($in | Where-Object { $set.Contains($_) })
}

function Measure-CaCoverage {
    param(
        [object[]]$Policies,
        [string[]]$EnabledMemberIds,
        [hashtable]$GroupMembers = @{},
        [hashtable]$RoleMembers = @{},
        [AllowEmptyCollection()][string[]]$BreakGlassIds = @()
    )
    $universe = @($EnabledMemberIds | Where-Object { $_ -notin $BreakGlassIds })
    $enforced = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $withRo = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $counted = @()
    foreach ($p in @($Policies)) {
        if (-not (Test-UniversalMfaPolicy -Policy $p)) { continue }
        $state = [string](Get-Field $p @('state'))
        if ($state -notin 'enabled', 'enabledForReportingButNotEnforced') { continue }
        $counted += "$([string](Get-Field $p @('displayName'))) [$state]"
        foreach ($x in (Get-PolicyUserScope -Policy $p -Universe $universe -GroupMembers $GroupMembers -RoleMembers $RoleMembers)) {
            [void]$withRo.Add($x)
            if ($state -eq 'enabled') { [void]$enforced.Add($x) }
        }
    }
    return [pscustomobject]@{
        Denominator = $universe.Count
        CoveredEnforced = $enforced.Count; PctEnforced = Get-Pct $enforced.Count $universe.Count
        CoveredInclReportOnly = $withRo.Count; PctInclReportOnly = Get-Pct $withRo.Count $universe.Count
        PoliciesCounted = $counted
        UncoveredIds = @($universe | Where-Object { -not $enforced.Contains($_) })
    }
}

function Test-IsHumanDecision {
    # A decision a PERSON made: not NotReviewed, a real reviewer id, not a system name.
    param([Parameter(Mandatory)]$Decision, [string[]]$SystemReviewerNames = @())
    if ([string]$Decision['decision'] -in '', 'NotReviewed') { return $false }
    $id = [string](Get-Field $Decision @('reviewedBy', 'id'))
    if (-not $id -or $id -match '^[0-]+$') { return $false }
    return ([string](Get-Field $Decision @('reviewedBy', 'displayName'))) -notin $SystemReviewerNames
}

function Measure-AccessReview {
    # Decisions as Graph returns them (decision: Approve | Deny | NotReviewed
    # | DontKnow; applyResult: New | AppliedSuccessfully | ...; reviewedBy).
    # Only PERSON-made decisions count as reviewed (Test-IsHumanDecision, the
    # same rule 10-Review-KPIs.ps1 uses); defaults the service applied are
    # counted apart (ServiceDecided), never as completion.
    param([AllowEmptyCollection()][object[]]$Decisions = @(), [string[]]$SystemReviewerNames = @('AAD Access Reviews', 'Microsoft Entra Access Reviews'))
    $all = @($Decisions | Where-Object { $_ })
    $reviewed = @($all | Where-Object { Test-IsHumanDecision -Decision $_ -SystemReviewerNames $SystemReviewerNames })
    $service = @($all | Where-Object { [string](Get-Field $_ @('decision')) -notin '', 'NotReviewed' -and -not (Test-IsHumanDecision -Decision $_ -SystemReviewerNames $SystemReviewerNames) })
    $denied = @($reviewed | Where-Object { [string](Get-Field $_ @('decision')) -eq 'Deny' })
    $applied = @($denied | Where-Object { [string](Get-Field $_ @('applyResult')) -eq 'AppliedSuccessfully' })
    return [pscustomobject]@{
        Decisions = $all.Count; Reviewed = $reviewed.Count; Denied = $denied.Count; DeniedApplied = $applied.Count
        ServiceDecided = $service.Count; ServiceDenied = @($service | Where-Object { [string](Get-Field $_ @('decision')) -eq 'Deny' }).Count
        PctCompletion = Get-Pct $reviewed.Count $all.Count
        PctRevocation = Get-Pct $denied.Count $reviewed.Count
        PctRevocationApplied = Get-Pct $applied.Count $denied.Count
    }
}

function Measure-StaleAccount {
    # Stale = enabled, last sign-in (interactive, non-interactive or
    # successful - the newest) older than the cutoff, or never signed in while
    # created before the cutoff. A new hire who has not signed in yet is
    # "pending first sign-in", not stale.
    param(
        [object[]]$Users,                   # Graph user hashtables incl. signInActivity
        [int]$StaleDays = 90,
        [datetime]$Now = (Get-Date).ToUniversalTime(),
        [AllowEmptyCollection()][string[]]$BreakGlassIds = @()
    )
    $cutoff = $Now.AddDays(-$StaleDays)
    $members = 0; $stale = [System.Collections.Generic.List[string]]::new(); $never = 0; $pending = 0; $guestStale = 0
    foreach ($u in @($Users)) {
        if ((Get-Field $u @('accountEnabled')) -eq $false) { continue }
        $id = [string](Get-Field $u @('id'))
        if ($id -in $BreakGlassIds) { continue }   # break-glass: never signing in is the goal
        $isGuest = [string](Get-Field $u @('userType')) -eq 'Guest'
        if (-not $isGuest) { $members++ }
        $times = @(foreach ($k in 'lastSignInDateTime', 'lastNonInteractiveSignInDateTime', 'lastSuccessfulSignInDateTime') {
                $t = Get-Field $u @('signInActivity', $k)
                if ($t) { ([datetime]$t).ToUniversalTime() }
            })
        $last = if ($times.Count) { ($times | Sort-Object -Descending)[0] } else { $null }
        $created = Get-Field $u @('createdDateTime')
        $isStale = $false
        if ($last) { $isStale = $last -lt $cutoff }
        elseif ($created -and ([datetime]$created).ToUniversalTime() -ge $cutoff) { if (-not $isGuest) { $pending++ } }
        else { $isStale = $true; if (-not $isGuest) { $never++ } }
        if ($isStale) { if ($isGuest) { $guestStale++ } else { $stale.Add($id) } }
    }
    return [pscustomobject]@{
        EnabledMembers = $members; Stale = $stale.Count; NeverSignedIn = $never; PendingFirstSignIn = $pending
        PctStale = Get-Pct $stale.Count $members; StaleGuests = $guestStale; StaleIds = $stale.ToArray()
    }
}

function Test-IsDisableAudit {
    param([System.Collections.IDictionary]$Audit)
    $name = [string](Get-Field $Audit @('activityDisplayName'))
    if ($name -eq 'Disable account') { return $true }
    if ($name -ne 'Update user') { return $false }
    foreach ($t in @(Get-Field $Audit @('targetResources'))) {
        foreach ($mp in @(Get-Field $t @('modifiedProperties'))) {
            if ([string](Get-Field $mp @('displayName')) -eq 'AccountEnabled' -and [string](Get-Field $mp @('newValue')) -match 'false') { return $true }
        }
    }
    return $false
}

function Test-IsHrLeaverEvent {
    # An inbound-provisioning log row that is an HR leaver reaching AD.
    # provisioningAction 'disable' is the documented case; API-driven inbound
    # provisioning to on-premises AD logs the lab's leaver as 'update' with
    # the modified property accountDisabled -> True instead (and the move to
    # OU=Disabled as parentDistinguishedName): read live from
    # /auditLogs/provisioning on 2026-11-05 for the 2026-10-28 leaver (E52),
    # which the 'disable'-only rule had reported as "no matched leaver".
    param([System.Collections.IDictionary]$Row)
    if ([string](Get-Field $Row @('provisioningStatusInfo', 'status')) -ne 'success') { return $false }
    $action = [string](Get-Field $Row @('provisioningAction'))
    if ($action -eq 'disable') { return $true }
    if ($action -ne 'update') { return $false }
    foreach ($mp in @(Get-Field $Row @('modifiedProperties'))) {
        if ($mp -and [string](Get-Field $mp @('displayName')) -eq 'accountDisabled' -and [string](Get-Field $mp @('newValue')) -match '^\s*\[?\s*"?true"?\s*\]?\s*$') { return $true }
    }
    return $false
}

function Measure-HrToDisable {
    # Pairs each successful inbound-provisioning "disable" (HR leaver reached
    # the provisioning service and AD) with the first Entra disable audit for
    # the same user at or after it. Matching: HR externalId == employeeId,
    # falling back to a UNIQUE displayName. Unmatched events are counted, not
    # guessed. The clock starts at the provisioning event: the HR system's own
    # delay before it sends the record is outside what Entra can see.
    param(
        [AllowEmptyCollection()][object[]]$ProvisioningEvents = @(),
        [AllowEmptyCollection()][object[]]$DirectoryAudits = @(),
        [AllowEmptyCollection()][object[]]$Users = @()
    )
    $byEmployeeId = @{}; $byName = @{}
    foreach ($u in @($Users)) {
        $eid = [string](Get-Field $u @('employeeId')); $dn = [string](Get-Field $u @('displayName')); $id = [string](Get-Field $u @('id'))
        if ($eid) { $byEmployeeId[$eid] = $id }
        if ($dn) { if ($byName.ContainsKey($dn)) { $byName[$dn] = $null } else { $byName[$dn] = $id } }
    }
    $disables = @(foreach ($a in @($DirectoryAudits)) {
            if ($a -and (Test-IsDisableAudit $a)) {
                $target = @(Get-Field $a @('targetResources')) | Select-Object -First 1
                [pscustomobject]@{ UserId = [string](Get-Field $target @('id')); At = ([datetime](Get-Field $a @('activityDateTime'))).ToUniversalTime() }
            }
        })
    $minutes = [System.Collections.Generic.List[double]]::new(); $unmatched = 0
    # One leaver per HR identity: the provisioning service can log the same
    # leaver more than once (the disable and the OU move); the clock starts
    # at the EARLIEST of them.
    $leaverEvents = @($ProvisioningEvents | Where-Object { $_ -and (Test-IsHrLeaverEvent $_) } |
        Sort-Object { ([datetime](Get-Field $_ @('activityDateTime'))).ToUniversalTime() })
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($e in $leaverEvents) {
        # The stable HR id is the key; the name only when there is no id
        # (the same person can be logged with and without a display name).
        $srcKeyId = [string](Get-Field $e @('sourceIdentity', 'id')); $srcKeyName = [string](Get-Field $e @('sourceIdentity', 'displayName'))
        $key = if ($srcKeyId) { "id:$srcKeyId" } elseif ($srcKeyName) { "name:$srcKeyName" } else { '' }
        if ($key -and -not $seen.Add($key)) { continue }
        $srcId = [string](Get-Field $e @('sourceIdentity', 'id')); $srcName = [string](Get-Field $e @('sourceIdentity', 'displayName'))
        $uid = if ($srcId -and $byEmployeeId.ContainsKey($srcId)) { $byEmployeeId[$srcId] } elseif ($srcName -and $byName.ContainsKey($srcName)) { $byName[$srcName] } else { $null }
        $t0 = ([datetime](Get-Field $e @('activityDateTime'))).ToUniversalTime()
        $hit = @(if ($uid) { $disables | Where-Object { $_.UserId -eq $uid -and $_.At -ge $t0 } | Sort-Object At | Select-Object -First 1 })
        if ($hit.Count) { $minutes.Add([math]::Round(($hit[0].At - $t0).TotalMinutes, 1)) } else { $unmatched++ }
    }
    $m = $minutes.ToArray()
    return [pscustomobject]@{
        Leavers = $m.Count; Unmatched = $unmatched
        MedianMinutes = Get-Percentile -Values $m -P 50
        P90Minutes = Get-Percentile -Values $m -P 90
        MaxMinutes = $(if ($m.Count) { ($m | Measure-Object -Maximum).Maximum } else { $null })
    }
}

function Measure-SecureScore {
    # Microsoft Secure Score history -> the baseline day vs the latest day.
    # One record per day (createdDateTime); if a day appears twice the later
    # record wins. The baseline is the first day on or after -BaselineDate (or
    # the oldest day kept). A control counts as "moved" when its score differs
    # between the two days; a control present on only one day is reported
    # with $null on the other side, never as 0.
    param(
        [AllowEmptyCollection()][object[]]$History,
        [string]$BaselineDate = ''
    )
    $days = @{}
    foreach ($r in @($History)) {
        if ($null -eq $r) { continue }
        $created = Get-Field $r @('createdDateTime')
        if (-not $created) { continue }
        $ts = ([datetime]$created).ToUniversalTime()
        $key = $ts.ToString('yyyy-MM-dd')
        if (-not $days.ContainsKey($key) -or $ts -gt $days[$key].Ts) { $days[$key] = @{ Ts = $ts; Record = $r } }
    }
    if ($days.Count -eq 0) { throw 'Secure Score history is empty: no daily record to measure.' }
    $ordered = @($days.Keys | Sort-Object)
    # @() around the whole if: a one-element result would otherwise unroll to a
    # bare string, and [0] would then be its first character.
    $baseKeys = @(if ($BaselineDate) { $ordered | Where-Object { $_ -ge $BaselineDate } | Select-Object -First 1 } else { $ordered[0] })
    if ($baseKeys.Count -eq 0 -or -not $baseKeys[0]) { throw "No Secure Score record on or after $BaselineDate (oldest kept: $($ordered[0]); newest: $($ordered[-1]))." }
    $baseKey = [string]$baseKeys[0]
    $lastKey = [string]$ordered[-1]
    $point = {
        param([string]$Key)
        $rec = $days[$Key].Record
        $cur = [double](Get-Field $rec @('currentScore')); $max = [double](Get-Field $rec @('maxScore'))
        if ($max -le 0) { throw "Secure Score record for $Key has no maxScore." }
        [ordered]@{ date = $Key; score = [math]::Round($cur, 2); maxScore = [math]::Round($max, 2); pct = [math]::Round(100 * $cur / $max, 1) }
    }
    $base = & $point $baseKey
    $last = & $point $lastKey
    $controls = {
        param([string]$Key)
        $m = @{}
        foreach ($c in @(Get-Field $days[$Key].Record @('controlScores'))) {
            if ($null -eq $c) { continue }
            $n = [string](Get-Field $c @('controlName')); if (-not $n) { continue }
            $m[$n] = @{ Category = [string](Get-Field $c @('controlCategory')); Score = [double](Get-Field $c @('score')) }
        }
        $m
    }
    $cb = & $controls $baseKey; $cl = & $controls $lastKey
    $moved = foreach ($n in @(@($cb.Keys) + @($cl.Keys) | Sort-Object -Unique)) {
        $b = if ($cb.ContainsKey($n)) { $cb[$n].Score } else { $null }
        $a = if ($cl.ContainsKey($n)) { $cl[$n].Score } else { $null }
        if ($null -ne $b -and $null -ne $a -and [math]::Abs($a - $b) -lt 0.005) { continue }
        $cat = if ($cl.ContainsKey($n)) { $cl[$n].Category } else { $cb[$n].Category }
        [ordered]@{ control = $n; category = $cat; before = $b; after = $a; delta = $(if ($null -ne $b -and $null -ne $a) { [math]::Round($a - $b, 2) } else { $null }) }
    }
    $moved = @($moved | Sort-Object -Property @{ Expression = { if ($null -ne $_['delta']) { [math]::Abs($_['delta']) } else { 0 } }; Descending = $true }, @{ Expression = { $_['control'] } })
    return [pscustomobject]@{
        Baseline = $base; Latest = $last; Days = $ordered.Count
        DeltaScore = [math]::Round($last.score - $base.score, 2); DeltaPct = [math]::Round($last.pct - $base.pct, 1)
        MaxScoreChanged = ($last.maxScore -ne $base.maxScore)
        ControlsMoved = $moved
    }
}

function Measure-NhiCredential {
    # FALLBACK when no 06 output is given: application objects only (owners
    # expanded). Same KPI definitions as 06 (an NHI with >= 1 expired
    # credential still attached; an NHI with no owner) but narrower coverage:
    # SP-only, managed-identity and agent rows need 06-NHI-Inventory.ps1.
    param([AllowEmptyCollection()][object[]]$Applications = @(), [datetime]$Now = (Get-Date).ToUniversalTime())
    $apps = @($Applications | Where-Object { $_ })
    $expiredIds = [System.Collections.Generic.HashSet[string]]::new(); $orphanIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($a in $apps) {
        $id = [string](Get-Field $a @('id'))
        $creds = @(@(Get-Field $a @('passwordCredentials')) + @(Get-Field $a @('keyCredentials')) | Where-Object { $_ })
        if (@($creds | Where-Object { $end = Get-Field $_ @('endDateTime'); $end -and ([datetime]$end).ToUniversalTime() -lt $Now }).Count) { [void]$expiredIds.Add($id) }
        if (@(@(Get-Field $a @('owners')) | Where-Object { $_ }).Count -eq 0) { [void]$orphanIds.Add($id) }
    }
    $either = [System.Collections.Generic.HashSet[string]]::new($expiredIds); $either.UnionWith($orphanIds)
    return [pscustomobject]@{
        Nhis = $apps.Count; WithExpiredCredential = $expiredIds.Count; Orphaned = $orphanIds.Count; ExpiredOrOrphaned = $either.Count
        Source = 'graph (app registrations only)'
    }
}

function ConvertFrom-NhiInventory {
    # The nhi_inventory.json 06-NHI-Inventory.ps1 writes. Its own summary KPIs
    # are reused as-is (one definition, one place). Refused when it is mock
    # output, when a data source failed (incomplete is not clean), or when it
    # is older than -MaxAgeHours (a stale file would misstate the "after").
    param([Parameter(Mandatory)]$Inventory, [datetime]$Now = (Get-Date).ToUniversalTime(), [int]$MaxAgeHours = 24)
    $src = [string]$Inventory.Source
    if ($src -ne 'tenant') { throw "NHI inventory source is '$src'; only a tenant run (not -Offline mock output) is evidence." }
    $failed = @(@($Inventory.DataSources) | Where-Object { $_ -and [string]$_.Status -like 'FAILED*' } | ForEach-Object { [string]$_.Name })
    if ($failed.Count) { throw "NHI inventory is incomplete: failed source(s) $($failed -join ', ')." }
    $age = ($Now - ([datetime]$Inventory.GeneratedAtUtc).ToUniversalTime()).TotalHours
    if ($age -gt $MaxAgeHours) { throw "NHI inventory is $([math]::Round($age, 1)) h old (max $MaxAgeHours h); re-run 06-NHI-Inventory.ps1." }
    $k = $Inventory.Summary.kpi
    return [pscustomobject]@{
        Nhis = [int]$Inventory.Summary.nhiCount; WithExpiredCredential = [int]$k.nhiWithExpiredCredential
        Orphaned = [int]$k.orphanedNhi; ExpiredOrOrphaned = [int]$k.expiredOrOrphanedNhi
        Source = '06-NHI-Inventory.ps1'
    }
}

function Measure-PamReconcile {
    # Rows of lab/pam/out/reconcile-latest.csv (lab/pam/reconcile.sh). The PAM
    # stand-in owns the definitions, so this reuses them instead of keeping a
    # second copy: eligible = VAULTED + HELD + GAP (documented EXCEPTIONs are
    # out of scope by policy); rotated within policy = rotated_within_policy
    # 'yes' among VAULTED (static role: age <= rotation_period + 5 min;
    # library: checked out, or AD pwdLastSet within the tier's max age).
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $rows = @($Rows | Where-Object { $_ })
    foreach ($col in 'account', 'status', 'rotated_within_policy') {
        if ($rows.Count -and -not $rows[0].PSObject.Properties[$col]) { throw "reconcile report has no '$col' column; expected lab/pam/reconcile.sh output." }
    }
    $by = { param([string]$S) @($rows | Where-Object { [string]$_.status -eq $S }).Count }
    $vaulted = & $by 'VAULTED'; $held = & $by 'HELD'; $gap = & $by 'GAP'
    $within = @($rows | Where-Object { [string]$_.status -eq 'VAULTED' -and [string]$_.rotated_within_policy -eq 'yes' }).Count
    $eligible = $vaulted + $held + $gap
    return [pscustomobject]@{
        Eligible = $eligible; Vaulted = $vaulted; PctVaulted = Get-Pct $vaulted $eligible
        RotatedWithinPolicy = $within; PctRotatedWithinPolicy = Get-Pct $within $vaulted
        Held = $held; Gap = $gap; Orphan = (& $by 'ORPHAN'); Exceptions = (& $by 'EXCEPTION')
    }
}

function Measure-PamSession {
    # Brokered sessions (Guacamole history): Recorded = $true / $false, or
    # $null when the history entry does not say - unknown is left out of the
    # denominator rather than counted either way.
    param([AllowEmptyCollection()][object[]]$Sessions = @())
    $known = @($Sessions | Where-Object { $_ -and $null -ne $_['Recorded'] })
    $rec = @($known | Where-Object { $_['Recorded'] }).Count
    return [pscustomobject]@{ Sessions = $known.Count; Unknown = @($Sessions | Where-Object { $_ -and $null -eq $_['Recorded'] }).Count; Recorded = $rec; PctRecorded = Get-Pct $rec $known.Count }
}

function Get-KpiEntry {
    param(
        [ValidateSet('measured', 'failed', 'not-measured')][string]$Status,
        $Value = $null, [string]$Unit = '', $Numerator = $null, $Denominator = $null,
        [string]$Note = '', [System.Collections.IDictionary]$Detail = $null
    )
    $k = [ordered]@{ status = $Status; value = $(if ($Status -eq 'measured') { $Value } else { $null }); unit = $Unit }
    if ($null -ne $Numerator) { $k.numerator = $Numerator }
    if ($null -ne $Denominator) { $k.denominator = $Denominator }
    if ($Note) { $k.note = $Note }
    if ($Detail) { $k.detail = $Detail }
    return $k
}

function Compare-KpiSnapshot {
    # Numeric deltas for KPIs measured in BOTH snapshots; anything else is
    # listed as not comparable rather than diffed against a null.
    param([System.Collections.IDictionary]$Before, [System.Collections.IDictionary]$After)
    $deltas = [ordered]@{}
    foreach ($key in @($After['kpis'].Keys)) {
        $a = $After['kpis'][$key]; $b = Get-Field $Before @('kpis', $key)
        $ok = $b -and [string]$b['status'] -eq 'measured' -and [string]$a['status'] -eq 'measured' -and
        ($a['value'] -is [ValueType]) -and ($b['value'] -is [ValueType])
        if ($ok) { $deltas[$key] = [ordered]@{ before = $b['value']; after = $a['value']; delta = [math]::Round([double]$a['value'] - [double]$b['value'], 1) } }
        else { $deltas[$key] = [ordered]@{ comparable = $false; before = $(if ($b) { [string]$b['status'] } else { 'absent' }); after = [string]$a['status'] } }
    }
    return $deltas
}

# =============================================================================
# COLLECTORS (I/O). Each KPI block catches its own failure.
# =============================================================================
$graph = 'https://graph.microsoft.com/v1.0'
$GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
# Microsoft Graph's own application (first-party appId, identical in every tenant).
$MicrosoftGraphAppId = '00000003-0000-0000-c000-000000000000'

function Invoke-Graph { param([string]$Uri) return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable }
function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-Graph -Uri $next
        foreach ($v in @($page['value'])) { if ($null -ne $v) { $items.Add($v) } }
        $next = $page['@odata.nextLink']
    }
    return $items.ToArray()
}
$memberCache = @{}
function Get-GroupUserIdList {
    param([string]$GroupId)
    if (-not $memberCache.ContainsKey($GroupId)) {
        $memberCache[$GroupId] = @(Get-GraphCollection -Uri "$graph/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id" | ForEach-Object { [string]$_['id'] })
    }
    return $memberCache[$GroupId]
}
function Get-PrincipalType { param($Principal) return ([string](Get-Field $Principal @('@odata.type'))) -replace '^#microsoft\.graph\.' }

$requiredScopes = @('User.Read.All', 'Group.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'Policy.Read.All', 'AccessReview.Read.All',
    'Application.Read.All')   # Graph application-permission grants (always) + NHI fallback read
if ($IncludeSecureScore) { $requiredScopes += 'SecurityEvents.Read.All' }
if ($UseAzureCliToken) {
    # App-only: always this identity, never a leftover context.
    Write-Console 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
    Connect-GraphFromAzureCli
}
$ctx = $null; try { $ctx = Get-MgContext } catch { Write-Verbose "Get-MgContext failed: $($_.Exception.Message)"; $ctx = $null }
if (-not $ctx) {
    if ($UseAzureCliToken) { throw 'No Microsoft Graph context after the app-only sign-in.' }
    Write-Console 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes -NoWelcome; $ctx = Get-MgContext
}
$missingScopes = @(Get-MissingGraphScope -Have @($ctx.Scopes) -Required $requiredScopes)
if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). KPIs needing them are recorded as failed." }

$now = (Get-Date).ToUniversalTime()
$kpis = [ordered]@{}
$detail = [ordered]@{}
function Write-KpiLine {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param([string]$Key)
    $k = $kpis[$Key]
    $txt = if ($k['status'] -eq 'measured') { "$($k['value']) $($k['unit'])" } else { "$($k['status'].ToUpperInvariant()) $(if ($k.Contains('note')) { $k['note'] })" }
    Write-Host ("  {0,-44} {1}" -f $Key, $txt) -ForegroundColor $(switch ($k['status']) { 'measured' { 'Green' } 'failed' { 'Red' } default { 'Yellow' } })
}

# --- shared reads -------------------------------------------------------------
Write-Console 'Reading directory...' -ForegroundColor Cyan
$users = @(); $usersError = $null; $signInError = $null
$userSelect = 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,employeeId'
try { $users = @(Get-GraphCollection -Uri "$graph/users?`$select=$userSelect,signInActivity") }
catch {
    # signInActivity needs P1 + AuditLog.Read.All; without it only the stale
    # KPI is lost, so read the users again without it.
    $signInError = $_.Exception.Message
    Write-Warning "User read with signInActivity failed ($signInError); retrying without it."
    try { $users = @(Get-GraphCollection -Uri "$graph/users?`$select=$userSelect") }
    catch { $usersError = $_.Exception.Message; Write-Warning "User read failed: $usersError" }
}
$enabledMemberIds = @($users | Where-Object { $_['accountEnabled'] -ne $false -and [string]$_['userType'] -eq 'Member' } | ForEach-Object { [string]$_['id'] })
$bgGroupId = ''; $bgIds = @()
try {
    $f = [uri]::EscapeDataString("mailNickname eq '$BreakGlassGroupMailNickname'")
    $bg = @(Get-GraphCollection -Uri "$graph/groups?`$filter=$f&`$select=id") | Select-Object -First 1
    if ($bg) { $bgGroupId = [string]$bg['id']; $bgIds = @(Get-GroupUserIdList $bgGroupId) }
    else { Write-Warning "Break-glass group '$BreakGlassGroupMailNickname' not found; no account is treated as break-glass." }
}
catch { Write-Warning "Break-glass lookup failed: $($_.Exception.Message)" }

# --- 1. admin posture -----------------------------------------------------------
Write-Console "`n[1/8] Standing vs eligible admins" -ForegroundColor Cyan
$roleMembers = @{}   # roleDefinitionId -> active user ids (reused by CA coverage)
$roleTierMap = Get-RoleTierMap
$roleTier = @{}; foreach ($k in @($roleTierMap.Keys)) { $roleTier[$k] = $roleTierMap[$k]['Tier'] }
try {
    $priv = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    # isPrivileged is beta-only (same approach and guard as 05-Reports.ps1).
    foreach ($d in (Get-GraphCollection -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,templateId")) {
        [void]$priv.Add([string]$d['id']); if ($d['templateId']) { [void]$priv.Add([string]$d['templateId']) }
    }
    if (-not $priv.Contains($GlobalAdminRoleTemplateId)) { throw 'isPrivileged filter did not return Global Administrator; privileged-role set is not trustworthy.' }
    # The lab tier map adds the Tier-0/1 roles Microsoft does not label
    # privileged (e.g. Authentication Policy, Groups, Exchange Administrator).
    foreach ($k in @($roleTier.Keys)) { [void]$priv.Add($k) }
    # PIM tier groups: every role they hold or are eligible for counts too, so
    # a tier added in modules/pim is measured even before this map learns it.
    # A failed lookup fails the admin KPIs (an unread source is not "none").
    $tierGroupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $filters = @("startswith(mailNickname,'$PimTierGroupPrefix')") + @($PimGroupMailNicknames | ForEach-Object { "mailNickname eq '$_'" })
    foreach ($flt in $filters) {
        foreach ($g in (Get-GraphCollection -Uri "$graph/groups?`$filter=$([uri]::EscapeDataString($flt))&`$select=id")) { [void]$tierGroupIds.Add([string]$g['id']) }
    }
    $activeRaw = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=principal")
    $eligibleRaw = @(Get-GraphCollection -Uri "$graph/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal")
    $norm = {
        param($i, [string]$Kind)
        [pscustomobject]@{
            PrincipalId = [string]$i['principalId']; PrincipalType = (Get-PrincipalType $i['principal'])
            RoleDefinitionId = [string]$i['roleDefinitionId']; AssignmentType = $(if ($Kind -eq 'Eligible') { 'Eligible' } else { [string]$i['assignmentType'] })
            MemberType = [string]$i['memberType']
        }
    }
    # A user row with memberType "Group" is derived from a role-holding group;
    # the group's own row (plus its PIM-for-Groups membership) classifies that
    # user, so the derived row is skipped (see .NOTES verify).
    $isDerived = { param($r) $r.PrincipalType -eq 'user' -and $r.MemberType -eq 'Group' }
    $active = @($activeRaw | ForEach-Object { & $norm $_ 'Active' } | Where-Object { -not (& $isDerived $_) })
    $eligibleAll = @($eligibleRaw | ForEach-Object { & $norm $_ 'Eligible' } | Where-Object { -not (& $isDerived $_) })
    foreach ($r in @($active + $eligibleAll)) { if ($r.PrincipalType -eq 'group' -and $tierGroupIds.Contains($r.PrincipalId)) { [void]$priv.Add($r.RoleDefinitionId) } }
    $activePriv = @($active | Where-Object { $priv.Contains($_.RoleDefinitionId) })
    $eligiblePriv = @($eligibleAll | Where-Object { $priv.Contains($_.RoleDefinitionId) })

    # PIM for Groups membership of every group that holds or is eligible for a privileged role.
    $membership = @{}; $pimNotes = @()
    foreach ($gid in (@($activePriv + $eligiblePriv | Where-Object PrincipalType -eq 'group' | ForEach-Object { $_.PrincipalId }) | Sort-Object -Unique)) {
        try {
            $asg = @(Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq '$gid'" | Where-Object { $_['accessId'] -eq 'member' })
            $elg = @(Get-GraphCollection -Uri "$graph/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$gid'" | Where-Object { $_['accessId'] -eq 'member' })
            $membership[$gid] = @{
                Permanent = @($asg | Where-Object { $_['assignmentType'] -ne 'Activated' } | ForEach-Object { [string]$_['principalId'] })
                Activated = @($asg | Where-Object { $_['assignmentType'] -eq 'Activated' } | ForEach-Object { [string]$_['principalId'] })
                Eligible  = @($elg | ForEach-Object { [string]$_['principalId'] })
            }
        }
        catch {
            # Not PIM-managed (or no read): every current member counts as
            # standing - the conservative reading, stated in the note.
            $membership[$gid] = @{ Permanent = @(Get-GroupUserIdList $gid); Activated = @(); Eligible = @() }
            $pimNotes += 'a role-holding group without readable PIM-for-Groups data was counted as standing'
        }
    }
    $posture = Measure-AdminPosture -ActiveAssignments $activePriv -EligibleAssignments $eligiblePriv -GroupMembership $membership -BreakGlassUserIds $bgIds -BreakGlassGroupId $bgGroupId -RoleTier $roleTier
    $note = (@('break-glass counted apart; privileged = isPrivileged + lab tier map + PIM tier-group roles') + ($pimNotes | Sort-Object -Unique)) -join '; '
    $kpis['admin_standing_users'] = Get-KpiEntry -Status measured -Value $posture.StandingUsers -Unit 'users' -Note $note -Detail ([ordered]@{
            breakGlassUsers = $posture.BreakGlassUsers; activatedNow = $posture.ActivatedNow; pimTierGroups = $tierGroupIds.Count; byTier = $posture.StandingUsersByTier })
    $kpis['admin_eligible_only_users'] = Get-KpiEntry -Status measured -Value $posture.EligibleOnlyUsers -Unit 'users' -Detail ([ordered]@{ byTier = $posture.EligibleOnlyUsersByTier })
    $kpis['admin_jit_pct'] = Get-KpiEntry -Status measured -Value $posture.PctJustInTime -Unit '%' -Numerator $posture.EligibleOnlyUsers -Denominator ($posture.StandingUsers + $posture.EligibleOnlyUsers)
    $detail['standing_user_ids'] = $posture.StandingUserIds

    # Workload identities: a privileged directory role OR a high-privilege
    # Graph application permission. Its own failure fails only this KPI.
    try {
        $gsp = @(Get-GraphCollection -Uri "$graph/servicePrincipals?`$filter=$([uri]::EscapeDataString("appId eq '$MicrosoftGraphAppId'"))&`$select=id,appRoles") | Select-Object -First 1
        if (-not $gsp) { throw 'the Microsoft Graph service principal was not found in the tenant' }
        $hp = [ordered]@{}; $hpNotes = @()
        $tenantRoleIds = @{}; foreach ($r in @($gsp['appRoles'] | Where-Object { $_ })) { $tenantRoleIds[[string]$r['value']] = [string]$r['id'] }
        $learn = Get-HighPrivilegeGraphAppRole
        $absent = @()
        foreach ($id in @($learn.Keys)) {
            $name = $learn[$id]; $hp[$id] = $name
            # Match by name too, in case the tenant's id ever differs from Learn's.
            if ($tenantRoleIds.ContainsKey($name)) { if ($tenantRoleIds[$name] -ne $id) { $hp[$tenantRoleIds[$name]] = $name; $hpNotes += "verify: $name has a different id in this tenant (both matched)" } }
            else { $absent += $name }
        }
        if (-not $tenantRoleIds.Count) { $hpNotes += "Graph app roles unreadable; matched on Learn's ids only" }
        elseif ($absent.Count) { $hpNotes += "verify: $($absent.Count) watched permission(s) not among the tenant's Graph app roles, matched on Learn's ids: $($absent -join ', ')" }
        $grants = @(Get-GraphCollection -Uri "$graph/servicePrincipals/$($gsp['id'])/appRoleAssignedTo")
        $wl = Measure-PrivilegedWorkloadIdentity -DirectoryRoleSpIds $posture.PrivilegedServicePrincipalIds -GraphAppRoleAssignments $grants -HighPrivilegeAppRoles $hp
        $kpis['privileged_service_principals'] = Get-KpiEntry -Status measured -Value $wl.Total -Unit 'service principals' -Note ((@('privileged directory role OR high-privilege Graph application permission (expected: the pipeline APPLY identity)') + $hpNotes) -join '; ') -Detail ([ordered]@{
                viaDirectoryRole = $wl.ViaDirectoryRole; viaGraphApplicationPermission = $wl.ViaGraphAppRole; viaBoth = $wl.Both
                graphPermissionsWatched = $learn.Count; byPermission = $wl.ByPermission })
        $detail['privileged_service_principal_ids'] = $wl.Ids
    }
    catch { $kpis['privileged_service_principals'] = Get-KpiEntry -Status failed -Note "Graph application-permission read failed: $($_.Exception.Message)" }

    # Active role holders (all roles) for CA includeRoles/excludeRoles.
    foreach ($a in $active) {
        $ids = @(switch ($a.PrincipalType) { 'user' { $a.PrincipalId } 'group' { Get-GroupUserIdList $a.PrincipalId } })
        if (-not $roleMembers.ContainsKey($a.RoleDefinitionId)) { $roleMembers[$a.RoleDefinitionId] = @() }
        $roleMembers[$a.RoleDefinitionId] = @($roleMembers[$a.RoleDefinitionId] + $ids | Sort-Object -Unique)
    }
}
catch {
    foreach ($k in 'admin_standing_users', 'admin_eligible_only_users', 'admin_jit_pct', 'privileged_service_principals') { $kpis[$k] = Get-KpiEntry -Status failed -Note $_.Exception.Message }
}
'admin_standing_users', 'admin_eligible_only_users', 'admin_jit_pct', 'privileged_service_principals' | ForEach-Object { Write-KpiLine $_ }

# --- 2. phishing-resistant -------------------------------------------------------
Write-Console "`n[2/8] Phishing-resistant authentication" -ForegroundColor Cyan
$regById = @{}
try {
    if ($usersError) { throw "user read failed: $usersError" }
    foreach ($r in (Get-GraphCollection -Uri "$graph/reports/authenticationMethods/userRegistrationDetails")) { $regById[[string]$r['id']] = @(@($r['methodsRegistered']) | Where-Object { $_ }) }
    $pr = Measure-PhishingResistant -EnabledMemberIds $enabledMemberIds -RegistrationById $regById -BreakGlassIds $bgIds
    $kpis['phishing_resistant_pct'] = Get-KpiEntry -Status measured -Value $pr.Pct -Unit '%' -Numerator $pr.PhishingResistant -Denominator $pr.Denominator -Note 'synced passkeys count (unattested); break-glass excluded' -Detail ([ordered]@{ breakGlassAccounts = $pr.BreakGlassAccounts; breakGlassWithDeviceBoundKey = $pr.BreakGlassWithDeviceBoundKey })
    $kpis['phishing_resistant_device_bound_pct'] = Get-KpiEntry -Status measured -Value $pr.PctDeviceBound -Unit '%' -Numerator $pr.DeviceBound -Denominator $pr.Denominator
}
catch { foreach ($k in 'phishing_resistant_pct', 'phishing_resistant_device_bound_pct') { $kpis[$k] = Get-KpiEntry -Status failed -Note $_.Exception.Message } }
'phishing_resistant_pct', 'phishing_resistant_device_bound_pct' | ForEach-Object { Write-KpiLine $_ }

# --- 3. CA coverage ----------------------------------------------------------------
Write-Console "`n[3/8] Conditional Access MFA coverage" -ForegroundColor Cyan
try {
    if ($usersError) { throw "user read failed: $usersError" }
    $policies = @(Get-GraphCollection -Uri "$graph/identity/conditionalAccess/policies")
    $groupMembers = @{}
    foreach ($p in $policies) {
        foreach ($g in @(@(Get-Field $p @('conditions', 'users', 'includeGroups')) + @(Get-Field $p @('conditions', 'users', 'excludeGroups')) | Where-Object { $_ })) {
            if (-not $groupMembers.ContainsKey($g)) { $groupMembers[$g] = @(Get-GroupUserIdList $g) }
        }
    }
    $cov = Measure-CaCoverage -Policies $policies -EnabledMemberIds $enabledMemberIds -GroupMembers $groupMembers -RoleMembers $roleMembers -BreakGlassIds $bgIds
    $kpis['ca_mfa_coverage_pct'] = Get-KpiEntry -Status measured -Value $cov.PctEnforced -Unit '%' -Numerator $cov.CoveredEnforced -Denominator $cov.Denominator -Note 'enabled policies requiring MFA/auth strength for all apps, no narrowing condition; break-glass excluded by design' -Detail ([ordered]@{ policiesCounted = @($cov.PoliciesCounted).Count })
    $kpis['ca_mfa_coverage_incl_report_only_pct'] = Get-KpiEntry -Status measured -Value $cov.PctInclReportOnly -Unit '%' -Numerator $cov.CoveredInclReportOnly -Denominator $cov.Denominator
    $detail['ca_uncovered_user_ids'] = $cov.UncoveredIds
}
catch { foreach ($k in 'ca_mfa_coverage_pct', 'ca_mfa_coverage_incl_report_only_pct') { $kpis[$k] = Get-KpiEntry -Status failed -Note $_.Exception.Message } }
'ca_mfa_coverage_pct', 'ca_mfa_coverage_incl_report_only_pct' | ForEach-Object { Write-KpiLine $_ }

# --- 4. access reviews ----------------------------------------------------------------
Write-Console "`n[4/8] Access reviews (last $AccessReviewLookbackDays days)" -ForegroundColor Cyan
try {
    $since = $now.AddDays(-$AccessReviewLookbackDays)
    $decisions = [System.Collections.Generic.List[object]]::new(); $instances = 0
    foreach ($def in (Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions")) {
        foreach ($inst in (Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions/$($def['id'])/instances")) {
            $end = Get-Field $inst @('endDateTime')
            if ($end -and ([datetime]$end).ToUniversalTime() -lt $since) { continue }
            $instances++
            foreach ($d in (Get-GraphCollection -Uri "$graph/identityGovernance/accessReviews/definitions/$($def['id'])/instances/$($inst['id'])/decisions")) { $decisions.Add($d) }
        }
    }
    if ($decisions.Count -eq 0) {
        foreach ($k in 'access_review_completion_pct', 'access_review_revocation_pct', 'access_review_revocation_applied_pct') { $kpis[$k] = Get-KpiEntry -Status not-measured -Note "no review decisions in the window ($instances instance(s)) - enable_access_reviews / run a review first" }
    }
    else {
        $ar = Measure-AccessReview -Decisions $decisions.ToArray() -SystemReviewerNames $SystemReviewerNames
        $kpis['access_review_completion_pct'] = Get-KpiEntry -Status measured -Value $ar.PctCompletion -Unit '%' -Numerator $ar.Reviewed -Denominator $ar.Decisions -Note 'person-made decisions only (service-applied defaults excluded, same rule as 10-Review-KPIs.ps1)' -Detail ([ordered]@{ instances = $instances; serviceDecided = $ar.ServiceDecided; serviceDenied = $ar.ServiceDenied })
        $kpis['access_review_revocation_pct'] = Get-KpiEntry -Status measured -Value $ar.PctRevocation -Unit '%' -Numerator $ar.Denied -Denominator $ar.Reviewed
        $kpis['access_review_revocation_applied_pct'] = $(if ($ar.Denied) { Get-KpiEntry -Status measured -Value $ar.PctRevocationApplied -Unit '%' -Numerator $ar.DeniedApplied -Denominator $ar.Denied } else { Get-KpiEntry -Status not-measured -Note 'no Deny decisions in the window' })
    }
}
catch { foreach ($k in 'access_review_completion_pct', 'access_review_revocation_pct', 'access_review_revocation_applied_pct') { $kpis[$k] = Get-KpiEntry -Status failed -Note $_.Exception.Message } }
'access_review_completion_pct', 'access_review_revocation_pct', 'access_review_revocation_applied_pct' | ForEach-Object { Write-KpiLine $_ }

# --- 5. stale accounts ------------------------------------------------------------------
Write-Console "`n[5/8] Stale accounts (> $StaleDays days)" -ForegroundColor Cyan
try {
    if ($usersError) { throw "user read failed: $usersError" }
    if ($signInError) { throw "signInActivity unreadable: $signInError" }
    $st = Measure-StaleAccount -Users $users -StaleDays $StaleDays -Now $now -BreakGlassIds $bgIds
    $kpis['stale_accounts'] = Get-KpiEntry -Status measured -Value $st.Stale -Unit 'accounts' -Numerator $st.Stale -Denominator $st.EnabledMembers -Note "pct $($st.PctStale); never signed in: $($st.NeverSignedIn); pending first sign-in: $($st.PendingFirstSignIn); stale guests: $($st.StaleGuests)"
    $detail['stale_user_ids'] = $st.StaleIds
}
catch { $kpis['stale_accounts'] = Get-KpiEntry -Status failed -Note $_.Exception.Message }
Write-KpiLine 'stale_accounts'

# --- 6. HR-to-disable ---------------------------------------------------------------------
Write-Console "`n[6/8] HR-to-disable latency (last $HrToDisableLookbackDays days)" -ForegroundColor Cyan
if (-not $InboundProvisioningServicePrincipalId) {
    $kpis['hr_to_disable_minutes'] = Get-KpiEntry -Status not-measured -Note 'pass -InboundProvisioningServicePrincipalId (the inbound provisioning app)'
}
else {
    try {
        $sinceIso = $now.AddDays(-$HrToDisableLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $prov = @(Get-GraphCollection -Uri "$graph/auditLogs/provisioning?`$filter=activityDateTime ge $sinceIso" |
            Where-Object { [string](Get-Field $_ @('servicePrincipal', 'id')) -eq $InboundProvisioningServicePrincipalId })
        $audits = @()
        foreach ($act in 'Update user', 'Disable account') {
            $f = [uri]::EscapeDataString("activityDateTime ge $sinceIso and activityDisplayName eq '$act'")
            $audits += @(Get-GraphCollection -Uri "$graph/auditLogs/directoryAudits?`$filter=$f")
        }
        $hr = Measure-HrToDisable -ProvisioningEvents $prov -DirectoryAudits $audits -Users $users
        $kpis['hr_to_disable_minutes'] = $(if ($hr.Leavers -eq 0) {
                Get-KpiEntry -Status not-measured -Note "no matched leaver in the window ($($hr.Unmatched) unmatched disable event(s))"
            }
            else {
                Get-KpiEntry -Status measured -Value $hr.MedianMinutes -Unit 'minutes (median)' -Detail ([ordered]@{ leavers = $hr.Leavers; p90 = $hr.P90Minutes; max = $hr.MaxMinutes; unmatched = $hr.Unmatched }) -Note 'clock starts at the inbound provisioning disable event'
            })
    }
    catch { $kpis['hr_to_disable_minutes'] = Get-KpiEntry -Status failed -Note $_.Exception.Message }
}
Write-KpiLine 'hr_to_disable_minutes'

# --- 7. NHI credentials -----------------------------------------------------------------------
Write-Console "`n[7/8] Non-human identity credentials" -ForegroundColor Cyan
$nhiKeys = 'nhi_expired_or_orphaned', 'nhi_with_expired_credential', 'nhi_orphaned'
try {
    $nhi = if ($NhiInventoryPath) {
        if (-not (Test-Path -LiteralPath $NhiInventoryPath)) { throw "NHI inventory '$NhiInventoryPath' not found (run 06-NHI-Inventory.ps1)." }
        ConvertFrom-NhiInventory -Inventory (Get-Content -LiteralPath $NhiInventoryPath -Raw | ConvertFrom-Json) -Now $now
    }
    else {
        # verify: $select inside $expand=owners on /applications.
        Measure-NhiCredential -Applications @(Get-GraphCollection -Uri "$graph/applications?`$select=id,displayName,passwordCredentials,keyCredentials&`$expand=owners(`$select=id)") -Now $now
    }
    $kpis['nhi_expired_or_orphaned'] = Get-KpiEntry -Status measured -Value $nhi.ExpiredOrOrphaned -Unit 'NHIs' -Denominator $nhi.Nhis -Note "source: $($nhi.Source)"
    $kpis['nhi_with_expired_credential'] = Get-KpiEntry -Status measured -Value $nhi.WithExpiredCredential -Unit 'NHIs' -Denominator $nhi.Nhis -Note 'expired credential still attached'
    $kpis['nhi_orphaned'] = Get-KpiEntry -Status measured -Value $nhi.Orphaned -Unit 'NHIs' -Denominator $nhi.Nhis -Note 'no accountable owner'
}
catch { foreach ($k in $nhiKeys) { $kpis[$k] = Get-KpiEntry -Status failed -Note $_.Exception.Message } }
$nhiKeys | ForEach-Object { Write-KpiLine $_ }

# --- 7b. Microsoft Secure Score (opt-in) -------------------------------------------------------
# Microsoft's own rating of the tenant's security settings, kept by Microsoft
# as one record a day for about 90 days, so the "before" is read from the
# history itself rather than from an older snapshot that never had it.
Write-Console "`n[7b/8] Microsoft Secure Score (history)" -ForegroundColor Cyan
if (-not $IncludeSecureScore) {
    $kpis['secure_score_pct'] = Get-KpiEntry -Status not-measured -Note 'pass -IncludeSecureScore (Graph /security/secureScores, SecurityEvents.Read.All)'
}
else {
    try {
        # $top=90: Microsoft keeps about 90 daily records (Learn: List secureScores).
        $ss = Measure-SecureScore -History @(Get-GraphCollection -Uri "$graph/security/secureScores?`$top=90") -BaselineDate $SecureScoreBaselineDate
        $kpis['secure_score_pct'] = Get-KpiEntry -Status measured -Value $ss.Latest.pct -Unit '%' -Numerator $ss.Latest.score -Denominator $ss.Latest.maxScore `
            -Note ("{0}: {1} % ({2} of {3}) -> {4}: {5} % ({6} of {7}); {8} control(s) moved{9}" -f $ss.Baseline.date, $ss.Baseline.pct, $ss.Baseline.score, $ss.Baseline.maxScore,
                $ss.Latest.date, $ss.Latest.pct, $ss.Latest.score, $ss.Latest.maxScore, @($ss.ControlsMoved).Count, $(if ($ss.MaxScoreChanged) { '; the maximum changed too (Microsoft added or removed controls)' } else { '' })) `
            -Detail ([ordered]@{ baseline = $ss.Baseline; latest = $ss.Latest; days = $ss.Days; deltaScore = $ss.DeltaScore; deltaPct = $ss.DeltaPct; controlsMoved = @($ss.ControlsMoved) })
    }
    catch { $kpis['secure_score_pct'] = Get-KpiEntry -Status failed -Note $_.Exception.Message }
}
Write-KpiLine 'secure_score_pct'

# --- 8. PAM stand-ins (lab/pam reconcile report + Guacamole session history) ---------------------
Write-Console "`n[8/8] PAM (Vault + Guacamole stand-ins)" -ForegroundColor Cyan
$pamKeys = 'pam_vaulted_pct', 'pam_rotated_within_policy_pct', 'pam_sessions_recorded_pct'
if ($SkipPam) { foreach ($k in $pamKeys) { $kpis[$k] = Get-KpiEntry -Status not-measured -Note '-SkipPam' } }
else {
    # Vaulted / rotated: lab/pam/reconcile.sh's report (discovery x Vault),
    # so the definition lives in one place. A missing report means the PAM
    # stand-in is not in use; a stale one would misstate the "after".
    try {
        if (-not (Test-Path -LiteralPath $PamReconcilePath)) {
            foreach ($k in 'pam_vaulted_pct', 'pam_rotated_within_policy_pct') { $kpis[$k] = Get-KpiEntry -Status not-measured -Note 'no reconcile report: run lab/pam/discover.sh then lab/pam/reconcile.sh' }
        }
        else {
            $age = ($now - (Get-Item -LiteralPath $PamReconcilePath).LastWriteTimeUtc).TotalHours
            if ($age -gt $PamReportMaxAgeHours) { throw "reconcile report is $([math]::Round($age, 1)) h old (max $PamReportMaxAgeHours h); re-run lab/pam/reconcile.sh" }
            $rc = Measure-PamReconcile -Rows @(Import-Csv -LiteralPath $PamReconcilePath)
            $kpis['pam_vaulted_pct'] = Get-KpiEntry -Status measured -Value $rc.PctVaulted -Unit '%' -Numerator $rc.Vaulted -Denominator $rc.Eligible -Note "source: lab/pam/reconcile.sh; GAP $($rc.Gap), held $($rc.Held), orphan $($rc.Orphan), documented exceptions $($rc.Exceptions)"
            $kpis['pam_rotated_within_policy_pct'] = $(if ($rc.Vaulted) { Get-KpiEntry -Status measured -Value $rc.PctRotatedWithinPolicy -Unit '%' -Numerator $rc.RotatedWithinPolicy -Denominator $rc.Vaulted -Note 'definition: lab/pam/reconcile.sh' } else { Get-KpiEntry -Status not-measured -Note 'nothing vaulted yet' })
        }
    }
    catch { foreach ($k in 'pam_vaulted_pct', 'pam_rotated_within_policy_pct') { $kpis[$k] = Get-KpiEntry -Status failed -Note $_.Exception.Message } }

    # Sessions recorded: every Guacamole connection is a brokered privileged
    # session (the PSM stand-in has no other kind), read from its history.
    try {
        if (-not (Test-Path -LiteralPath $GuacamoleAdminSecretFile)) {
            $kpis['pam_sessions_recorded_pct'] = Get-KpiEntry -Status not-measured -Note 'Guacamole admin secret not found (lab/pam stack not in use)'
        }
        else {
            # Form-encoded body to the local stack only; the secret is never printed.
            $pw = (Get-Content -LiteralPath $GuacamoleAdminSecretFile -Raw).Trim()
            $tok = (Invoke-RestMethod -Method Post -Uri "$GuacamoleUrl/api/tokens" -Body @{ username = 'guacadmin'; password = $pw } -TimeoutSec 10).authToken
            $pw = $null
            try {
                $gh = @{ 'Guacamole-Token' = $tok }
                $cut = $now.AddDays(-$PamSessionLookbackDays)
                $hist = @(Invoke-RestMethod -Uri "$GuacamoleUrl/api/session/data/postgresql/history/connections" -Headers $gh -TimeoutSec 10)
                $sessions = @(foreach ($h in $hist) {
                        $start = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$h.startDate).UtcDateTime
                        if ($start -lt $cut) { continue }
                        # verify: Guacamole 1.6 lists a session's recording under "logs"
                        # when RECORDING_SEARCH_PATH is set (lab/pam/docker-compose.yml).
                        $rec = $null
                        if ($h.PSObject.Properties['logs'] -and $h.logs) {
                            $rec = @($h.logs.PSObject.Properties | Where-Object { $_.Value.PSObject.Properties['type'] -and [string]$_.Value.type -match 'RECORDING' }).Count -gt 0
                        }
                        @{ Connection = [string]$h.connectionName; Recorded = $rec }
                    })
            }
            finally { try { Invoke-RestMethod -Method Delete -Uri "$GuacamoleUrl/api/tokens/$tok" -TimeoutSec 10 | Out-Null } catch { Write-Verbose "Guacamole token revoke failed: $($_.Exception.Message)" } }
            $ss = Measure-PamSession -Sessions $sessions
            $kpis['pam_sessions_recorded_pct'] = $(if ($ss.Sessions) {
                    Get-KpiEntry -Status measured -Value $ss.PctRecorded -Unit '%' -Numerator $ss.Recorded -Denominator $ss.Sessions -Note "sessions with unknown recording status left out: $($ss.Unknown)"
                }
                else { Get-KpiEntry -Status not-measured -Note "no brokered session with a known recording status in the last $PamSessionLookbackDays days ($($ss.Unknown) unknown)" })
        }
    }
    catch { $kpis['pam_sessions_recorded_pct'] = Get-KpiEntry -Status failed -Note "Guacamole read failed: $($_.Exception.Message)" }
}
$pamKeys | ForEach-Object { Write-KpiLine $_ }

# =============================================================================
# SNAPSHOT
# =============================================================================
$snapshot = [ordered]@{
    schema         = 'contoso-identity-kpis/v1'
    label          = $Label
    generatedAtUtc = $now.ToString('o')
    generator      = 'lab/scripts/powershell/08-Measure-KPIs.ps1'
    parameters     = [ordered]@{ staleDays = $StaleDays; accessReviewLookbackDays = $AccessReviewLookbackDays; hrToDisableLookbackDays = $HrToDisableLookbackDays; pamSessionLookbackDays = $PamSessionLookbackDays }
    kpis           = $kpis
}
if ($CompareTo) {
    if (-not (Test-Path -LiteralPath $CompareTo)) { throw "-CompareTo '$CompareTo' not found." }
    $before = Get-Content -LiteralPath $CompareTo -Raw | ConvertFrom-Json -AsHashtable
    $snapshot['comparison'] = [ordered]@{ against = [string]$before['generatedAtUtc']; againstLabel = [string]$before['label']; deltas = (Compare-KpiSnapshot -Before $before -After $snapshot) }
    Write-Console "`nDeltas vs '$($before['label'])' ($($before['generatedAtUtc'])):" -ForegroundColor Cyan
    foreach ($k in $snapshot['comparison']['deltas'].Keys) {
        $d = $snapshot['comparison']['deltas'][$k]
        if ($d.Contains('delta')) { Write-Console ("  {0,-44} {1} -> {2} ({3:+0.#;-0.#;0})" -f $k, $d['before'], $d['after'], $d['delta']) }
        else { Write-Console ("  {0,-44} not comparable ({1} -> {2})" -f $k, $d['before'], $d['after']) -ForegroundColor DarkGray }
    }
}

$stamp = $now.ToString('yyyyMMddTHHmmssZ')
$file = Join-Path ([System.IO.Path]::GetFullPath($OutputDirectory)) "$stamp.json"
if ($PSCmdlet.ShouldProcess($file, 'write KPI snapshot (+ .sha256) and per-object detail')) {
    foreach ($dir in $OutputDirectory, $DetailDirectory) { if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null } }
    $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $file -Encoding utf8NoBOM
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    # sha256sum format, so `shasum -a 256 -c` verifies it.
    "$hash  $stamp.json" | Set-Content -LiteralPath "$file.sha256" -Encoding utf8NoBOM
    # Detail holds object ids: gitignored folder only.
    [ordered]@{ generatedAtUtc = $snapshot['generatedAtUtc']; snapshot = "$stamp.json"; detail = $detail } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $DetailDirectory "$stamp-detail.json") -Encoding utf8NoBOM
    Write-Console "`nSnapshot: $file (sha256 $hash)" -ForegroundColor Cyan
}

$failed = @($kpis.Keys | Where-Object { $kpis[$_]['status'] -eq 'failed' })
if ($failed.Count) {
    Write-Console "$($failed.Count) KPI(s) FAILED: $($failed -join ', ') - recorded as failed, not as zero." -ForegroundColor Red
    [pscustomobject]$snapshot
    exit 1
}
return [pscustomobject]$snapshot
