<#
.SYNOPSIS
    Inventories every non-human identity (NHI) in the tenant: app
    registrations, service principals, managed identities, Entra Agent ID
    blueprints and agent identities, and their federated credentials. Flags
    orphans, client secrets, long-lived or expired credentials, stale
    identities, insecure federation and Tier-0 permissions. Every finding
    carries an OWASP Non-Human Identities Top 10 (2025) ID and the lab NHI
    standard rule it breaks. Writes CSV + JSON for the evidence pack.

.DESCRIPTION
    The panel question this answers: "How many service principals have expired
    or orphaned credentials, and which of them could make themselves Global
    Admin?" A workforce identity has HR as its source of truth; an NHI has only
    its owner. When the owner leaves, nothing disables the NHI (OWASP NHI1), so
    this script is the DETECTIVE control behind
    lab/docs/standards/nhi-standard.md. The PREVENTIVE controls are the leaver
    hand-off (04-Leaver.ps1 step 7), the app management policy
    (post-apply/Set-AppGovernancePolicy.ps1) and the consent policy
    (post-apply/Set-ConsentPolicy.ps1).

    STATUS: RAN - tenant (2026-11-05, as the lab operator, app-only:
    lab/evidence/nhi/, capture-log E70). Tested offline as well:
    -Offline runs the same classification code against a built-in mock tenant
    that models the lab's real NHIs (the two pipeline identities,
    midpoint-reader, the Key Vault UAMI, DC01's managed identity) plus seeded
    bad examples. A mock run writes to lab/evidence/out/offline-mock/ and puts
    source = 'offline-mock' on every row, so it can never pass for tenant
    evidence.

    WHAT IS INVENTORIED (one row per NHI)
      AppRegistration           application object joined to its home-tenant
                                service principal by appId. Credentials live on
                                the app; permissions, roles and sign-ins live on
                                the SP, so one row is the whole workload.
      AgentBlueprint            Entra Agent ID blueprint (+ blueprint principal)
      AgentIdentity             Entra Agent ID agent identity (sponsor-governed)
      ManagedIdentity           user- or system-assigned. The owner model is
                                Azure RBAC on the resource, so no Entra owner is
                                expected (and none is flagged).
      ThirdPartyApp             SP of an app homed in another tenant
      OrphanedServicePrincipal  home-tenant SP whose app registration is gone
    Microsoft first-party SPs are counted but left out
    (-IncludeMicrosoftFirstParty to keep them).

    FINDINGS  (OWASP NHI Top 10 2025 -> lab NHI standard rule)
      OWNER-NONE, OWNER-NO-HUMAN, OWNER-ALL-DISABLED  NHI1 Improper Offboarding  N1, N9
      OWNER-SINGLE (no second owner)                  NHI1                       N1
      OWNER-TIER0 (a Tier-0 identity HAS an Entra
      owner: a standing way to act as it)             NHI5 Overprivileged        N1, N6
      SP-WITHOUT-APP                                  NHI1                       N1
      AGENT-NO-SPONSOR                                NHI1                       N10
      STALE, STALE-NEVER                              NHI1                       N8
      CRED-EXPIRED (still attached)                   NHI1                       N8
      SECRET-PRESENT                                  NHI2 Secret Leakage        N2
      THIRDPARTY-CONSENT                              NHI3 Vulnerable 3rd-Party  N6
      SYMMETRIC-KEY, IMPLICIT-GRANT                   NHI4 Insecure Auth         N2, N7
      PERM-TIER0, ROLE-PRIVILEGED                     NHI5 Overprivileged        N6
      PERM-SENSITIVE, DELEGATED-TENANTWIDE            NHI5                       N6
      FIC-PR-WRITE, FIC-BRANCH, FIC-WILDCARD,
      FIC-AUDIENCE                                    NHI6 Insecure Cloud Deploy N3
      CRED-LONG-LIVED, CRED-EXPIRING                  NHI7 Long-Lived Secrets    N5
      FIC-MULTI-ENV                                   NHI8 Environment Isolation N3
      FIC-REUSE                                       NHI9 NHI Reuse             N3
    NHI10 (Human Use of NHI) can't be seen in object inventory; it needs
    sign-in log analysis (interactive or unusual-IP service principal
    sign-ins). The JSON 'owaspCoverage' block says so instead of implying full
    coverage.

    Severity goes up one level for a Tier-0 identity (a Tier-0 Graph
    permission or a privileged directory role). An orphaned read-only app is
    hygiene; an orphaned app that can grant itself Global Admin is an incident.

    NEVER SILENT: each data source is recorded in 'dataSources' as ok or
    FAILED. A failed source never reads as clean. For example, no sign-in data
    means LastSignIn = 'unknown' and no stale verdict, not 'never'. Any failed
    source makes the script exit 1.

.PREREQUISITES
    * Modules: Microsoft.Graph.Authentication (all calls are raw REST through
      Invoke-MgGraphRequest, so no other Graph sub-module is needed).
    * Entra ID P1 or P2 for the service principal sign-in activity report
      (verify: licence for /beta/reports/servicePrincipalSignInActivities).
    * Read-only: no role beyond Global Reader / Security Reader is needed.

.GRAPH SCOPES  (delegated; admin-consent -- all READ-ONLY)
    Application.Read.All           applications, service principals, owners,
                                   federated credentials, appRoleAssignedTo,
                                   oauth2PermissionGrants
    Directory.Read.All             owner account state (accountEnabled)
    RoleManagement.Read.Directory  role definitions + privileged role assignments
    AuditLog.Read.All              servicePrincipalSignInActivities (beta)
    AgentIdentity.Read.All         agent identities + sponsors (Agent ID); only
                                   needed when agent identities exist

    API versions: everything is v1.0 except two beta calls: the sign-in
    activity report (beta only, verify before publishing) and the role
    definitions' isPrivileged flag (falls back to a static Tier-0 role list if
    beta is unavailable).

.PARAMETER OutputDirectory
    Where the CSV/JSON go. Default lab/evidence/out (gitignored, holds tenant
    data); -Offline defaults to lab/evidence/out/offline-mock.

.PARAMETER StaleDays
    No sign-in for this many days = stale (nhi-standard N8). Default 90.

.PARAMETER ExpiryWarningDays
    Credentials expiring within this many days are flagged for rotation. Default 30.

.PARAMETER MaxCredentialLifetimeDays
    Longest acceptable credential lifetime. Default 180, Microsoft's
    recommended certificate maximum and the same value
    Set-AppGovernancePolicy.ps1 enforces for new certificates.

.PARAMETER TierZeroPermissions
    Microsoft Graph APPLICATION permissions that let an identity escalate to
    Global Admin or rewrite tenant security policy (nhi-standard N6: these make
    an NHI Tier 0 and need a risk acceptance).

.PARAMETER SensitivePermissions
    Graph application permissions with broad write or bulk-data reach that
    are not Tier 0 on their own.

.PARAMETER HighRiskDelegatedScopes
    Delegated scopes that are a consent-phishing prize when granted tenant-wide
    (consentType AllPrincipals).

.PARAMETER IncludeMicrosoftFirstParty
    Keep Microsoft-owned SPs in the inventory (default: counted, not listed).

.PARAMETER SkipSignInActivity
    Don't call the beta sign-in activity report. LastSignIn is 'unknown' and
    no stale verdicts are made.

.PARAMETER Offline
    No Graph connection. Classify the built-in mock tenant instead.

.PARAMETER SecretsRegisterPath
    Merge the register of NON-ENTRA long-lived secrets
    (lab/iga/nhi-secrets-register.json: AWS SCIM token, Okta / midPoint
    client secrets, ServiceNow, Teams webhook, Splunk HEC, the PAM stack's
    .env and .secrets). Graph cannot see them, so without the register they
    have no owner, expiry or rotation on record. Each entry becomes a row in
    nhi_secrets.csv (names and store LOCATIONS only - the register never holds
    a value) and is checked: SECRET-NO-OWNER (High), SECRET-EXPIRED (High),
    SECRET-NO-EXPIRY and SECRET-NO-ROTATION (Medium). Findings carry OWASP
    NHI2 / NHI7 like the Entra ones. createdOn / expiresOn are yyyy-MM-dd or
    "unknown (<reason>)" - an explicit no-date marker that is still flagged
    SECRET-NO-EXPIRY, with the reason. An unreadable or invalid register
    (a malformed date, expiresOn before createdOn) is a FAILED data source
    (exit 1), never "no secrets". Default '' = not merged.

.PARAMETER OwnersRegisterPath
    The NHI owners register (lab/iga/nhi-owners.json, ADR 0018). Entries with
    ownerModel 'role' are identities whose accountable owner is a ROLE, not an
    Entra owner: the Tier-0 identities (an Entra owner can add a credential
    and act as the app, so they must have none). Such an identity, matched by
    display name, counts as owned (OwnerModel 'Register role (<role>)', no
    OWNER-NONE) - but only while it has NO Entra owner and its name is unique
    among the tenant's app registrations; a duplicate name stays unowned (a
    look-alike app must not inherit the register's cover). Any Tier-0
    identity (by permission, directory role or register tier) that HAS an
    Entra owner is flagged OWNER-TIER0. An unreadable or invalid register is
    a FAILED data source (exit 1) and nothing is counted as owned by it.
    Default '' = not read.

.PARAMETER FailOnSeverity
    Exit 2 when any finding is at or above this severity (for a scheduled job
    or CI gate). Default None: findings are reported, not fatal.

.PARAMETER PublicSummaryDirectory
    Also write a PUBLIC, counts-only record of a tenant run to
    <dir>/<UTC>/nhi-summary.json with a SHA256SUMS file (sha256sum format,
    the lab/evidence convention): totals by kind, severity, OWASP NHI id and
    finding id, the KPI counts, each data source's status, and the SHA-256 of
    every private output file, so the private copy can be matched to it
    later. No display name, app id, object id, owner, UPN or tenant id: the
    write is refused if the record contains a GUID, an '@' or the tenant id.
    Refused with -Offline (mock data never sits next to tenant evidence).
    Normally lab/evidence/nhi. Default '' = not written.

.PARAMETER UseAzureCliToken
    App-only sign-in: take a Microsoft Graph token from the Azure CLI session
    (`az account get-access-token --resource-type ms-graph`) and connect
    with it, always that identity, never a leftover context. For the lab
    operator: `lab/scripts/operator/op pwsh ./<this script> -UseAzureCliToken`
    (its own az profile, certificate sign-in). The token stays in this
    process: never in argv, a file or the output (masked in GitHub Actions).

.EXAMPLE
    ./06-NHI-Inventory.ps1 -Offline
    # Mock tenant, no connection: shows every finding type and the OWASP mapping.

.EXAMPLE
    Connect-MgGraph -Scopes 'Application.Read.All','Directory.Read.All','RoleManagement.Read.Directory','AuditLog.Read.All'
    ./06-NHI-Inventory.ps1 -StaleDays 90 -FailOnSeverity Critical

.OUTPUTS
    nhi_inventory.csv   one row per NHI (ObjectId, owners, OwnerCount, credential
                        counts, next expiry, last sign-in, Tier-0 permissions,
                        roles, max severity)
    nhi_credentials.csv one row per credential, federated ones included, with
                        CredentialStatus (active/expiring/expired/n/a/none) and
                        OwnerCount; an NHI with no credential gets one 'none'
                        row. OwnerCount 0 = orphaned; blank = not an
                        Entra-owner concept, or unknown.
    nhi_findings.csv    one row per finding (OWASP ID, standard rule, fix)
    nhi_inventory.json  all three, plus dataSources, summary KPIs, owaspCoverage.
                        08-Measure-KPIs.ps1 -NhiInventoryPath reads this file:
                        Source (must be 'tenant'), DataSources[].Status,
                        GeneratedAtUtc, Summary.nhiCount and Summary.kpi.
                        {expiredOrOrphanedNhi, nhiWithExpiredCredential,
                        orphanedNhi}. Keep those names stable.
    Returns the same structure as a [pscustomobject].

.WHAT IT DEMONSTRATES
    NHI governance as a measurable control: owners, credential hygiene and
    privilege for every workload identity, mapped to a public risk taxonomy
    (OWASP NHI Top 10) and to the lab's own standard. It also gives the KPI
    "expired or orphaned NHI credentials" a real query behind it.
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$OutputDirectory = '',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$ExpiryWarningDays = 30,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MaxCredentialLifetimeDays = 180,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$TierZeroPermissions = @(
        'RoleManagement.ReadWrite.Directory',                 # assign any directory role, incl. Global Admin
        'Directory.ReadWrite.All',                            # rewrite most directory objects
        'Application.ReadWrite.All',                          # add a credential to ANY app, then act as it
        'AppRoleAssignment.ReadWrite.All',                    # grant itself any app permission
        'RoleAssignmentSchedule.ReadWrite.Directory',         # PIM: create active role assignments
        'RoleEligibilitySchedule.ReadWrite.Directory',        # PIM: create eligible role assignments
        'PrivilegedAccess.ReadWrite.AzureADGroup',            # PIM for Groups (role-assignable groups)
        'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
        'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
        'RoleManagementPolicy.ReadWrite.Directory',           # weaken PIM activation rules for roles
        'UserAuthenticationMethod.ReadWrite.All',             # add a TAP / method to any user = takeover
        'Policy.ReadWrite.ConditionalAccess',                 # switch off Conditional Access
        'Policy.ReadWrite.AuthenticationMethod',              # weaken tenant MFA policy
        'Policy.ReadWrite.PermissionGrant',                   # change who may consent to what
        'Domain.ReadWrite.All',                               # add a federated domain = forged sign-ins
        'User-PasswordProfile.ReadWrite.All',                 # reset any password
        'Organization.ReadWrite.All',                         # tenant-wide settings (e.g. CBA trust)
        'EntitlementManagement.ReadWrite.All'                 # hand out any access package, privileged ones included
    ),

    [Parameter()]
    [string[]]$SensitivePermissions = @(
        'User.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All',
        'EntitlementManagement.ReadWrite.All', 'RoleManagementPolicy.ReadWrite.AzureADGroup',
        'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All', 'Sites.ReadWrite.All',
        'Sites.FullControl.All', 'Application.ReadWrite.OwnedBy',
        'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All'
    ),

    [Parameter()]
    [string[]]$HighRiskDelegatedScopes = @(
        'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Files.Read.All', 'Files.ReadWrite.All',
        'Sites.ReadWrite.All', 'Directory.AccessAsUser.All', 'Directory.ReadWrite.All',
        'User.ReadWrite.All', 'MailboxSettings.ReadWrite', 'Contacts.ReadWrite'
    ),

    [Parameter()]
    [switch]$IncludeMicrosoftFirstParty,

    [Parameter()]
    [switch]$SkipSignInActivity,

    [Parameter()]
    [switch]$Offline,

    [Parameter()]
    [ValidateSet('None', 'Critical', 'High', 'Medium', 'Low')]
    [string]$FailOnSeverity = 'None',

    [Parameter()]
    [string]$SecretsRegisterPath = '',

    # NHI owners register (role-owned Tier-0 identities). '' = not read.
    [Parameter()]
    [string]$OwnersRegisterPath = '',

    # App-only sign-in from the Azure CLI session (the lab operator via
    # lab/scripts/operator/op, or azure/login over OIDC).
    [Parameter()]
    [switch]$UseAzureCliToken,

    # Public, counts-only copy of the run (lab/evidence/nhi/<UTC>/). '' = not written.
    [Parameter()]
    [string]$PublicSummaryDirectory = ''
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

# ===========================================================================
# 0. CONSTANTS, TAXONOMY AND HELPERS
# ===========================================================================
# Fail closed: a mock run must never look like it signed in to a tenant.
if ($Offline -and $UseAzureCliToken) { throw '-Offline and -UseAzureCliToken exclude each other: -Offline never contacts a tenant.' }
if ($Offline -and $PublicSummaryDirectory) { throw '-PublicSummaryDirectory is for tenant runs only: mock data never sits next to tenant evidence.' }
$Now = (Get-Date).ToUniversalTime()
$Source = if ($Offline) { 'offline-mock' } else { 'tenant' }
if (-not $OutputDirectory) {
    $evidenceOut = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../evidence/out'))
    $OutputDirectory = if ($Offline) { Join-Path $evidenceOut 'offline-mock' } else { $evidenceOut }
}

$GraphAppId = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph, same in every tenant
# Tenants that own Microsoft first-party apps. verify: Microsoft Services
# (f8cdef31-...) and Microsoft corp (72f988bf-...) cover the first-party SPs
# seen in a new tenant; anything else is treated as third party.
$MicrosoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
$GitHubIssuer = 'https://token.actions.githubusercontent.com'
$ExchangeAudience = 'api://AzureADTokenExchange'

# Fallback when the beta isPrivileged flag can't be read: built-in roles that
# reach Tier 0 (template ids are the same in every tenant). The online path
# prefers Microsoft's own isPrivileged list. verify: re-check against
# learn.microsoft.com/entra/identity/role-based-access-control/privileged-roles-permissions
$StaticPrivilegedRoles = [ordered]@{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
    '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
    'fdd7a751-b60b-444a-984c-02652fe8fa1c' = 'Groups Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'
}

# OWASP Non-Human Identities Top 10 - 2025 (owasp.org/www-project-non-human-identities-top-10).
$OwaspTitles = [ordered]@{
    'NHI1' = 'Improper Offboarding'
    'NHI2' = 'Secret Leakage'
    'NHI3' = 'Vulnerable Third-Party NHI'
    'NHI4' = 'Insecure Authentication'
    'NHI5' = 'Overprivileged NHI'
    'NHI6' = 'Insecure Cloud Deployment Configurations'
    'NHI7' = 'Long-Lived Secrets'
    'NHI8' = 'Environment Isolation'
    'NHI9' = 'NHI Reuse'
    'NHI10' = 'Human Use of NHI'
}

# One place for the mapping and the fix, so every row with the same FindingId
# says the same thing (and the OWASP coverage block is computed, not typed).
$Catalog = @{
    'OWNER-NONE'           = @{ Owasp = 'NHI1'; Rule = 'N1'; Fix = 'Name two human owners (or one owner plus a team group); for a Tier-0 identity, record its accountable role in lab/iga/nhi-owners.json instead (no Entra owner). With no owner after 30 days, disable the identity.' }
    'OWNER-NO-HUMAN'       = @{ Owasp = 'NHI1'; Rule = 'N1'; Fix = 'Owned only by other service principals: add accountable human owners.' }
    'OWNER-ALL-DISABLED'   = @{ Owasp = 'NHI1'; Rule = 'N1, N9'; Fix = 'Every human owner is disabled (a leaver): reassign to the owner''s manager, rotate credentials the leaver could see.' }
    'OWNER-SINGLE'         = @{ Owasp = 'NHI1'; Rule = 'N1'; Fix = 'Add a second owner or a team group so one leaver doesn''t orphan the identity.' }
    'OWNER-TIER0'          = @{ Owasp = 'NHI5'; Rule = 'N1, N6'; Fix = 'Remove the Entra owner(s): an owner can add a credential and act as this Tier-0 identity, outside PIM. Record its accountable owner as a role in lab/iga/nhi-owners.json and change it only through reviewed code.' }
    'SP-WITHOUT-APP'       = @{ Owasp = 'NHI1'; Rule = 'N1'; Fix = 'The app registration was deleted but its service principal (and grants) remain: confirm nothing uses it, then delete it.' }
    'AGENT-NO-SPONSOR'     = @{ Owasp = 'NHI1'; Rule = 'N10'; Fix = 'Every agent identity needs an accountable human sponsor: add one or disable the agent.' }
    'STALE'                = @{ Owasp = 'NHI1'; Rule = 'N8'; Fix = 'No sign-in within the stale window: confirm with the owner, then disable; delete after a further 30 days.' }
    'STALE-NEVER'          = @{ Owasp = 'NHI1'; Rule = 'N8'; Fix = 'Never signed in and older than the stale window: confirm it is needed or remove it.' }
    'CRED-EXPIRED'         = @{ Owasp = 'NHI1'; Rule = 'N8'; Fix = 'Remove expired credentials; they add noise and hide which credential is live.' }
    'SECRET-PRESENT'       = @{ Owasp = 'NHI2'; Rule = 'N2'; Fix = 'Replace the client secret with workload identity federation, a managed identity or a Key Vault certificate, then remove it.' }
    'THIRDPARTY-CONSENT'   = @{ Owasp = 'NHI3'; Rule = 'N6'; Fix = 'Review the vendor app''s tenant-wide grants; revoke high-risk scopes or the app, and route future requests through admin consent.' }
    'SYMMETRIC-KEY'        = @{ Owasp = 'NHI4'; Rule = 'N2'; Fix = 'Symmetric keys are shared secrets: replace with federation or an asymmetric certificate.' }
    'IMPLICIT-GRANT'       = @{ Owasp = 'NHI4'; Rule = 'N7'; Fix = 'Turn off implicit-grant access-token issuance; use auth code + PKCE.' }
    'PERM-TIER0'           = @{ Owasp = 'NHI5'; Rule = 'N6'; Fix = 'Tier-0 Graph permission: remove it, or record a risk acceptance with compensating controls (exception-process.md).' }
    'ROLE-PRIVILEGED'      = @{ Owasp = 'NHI5'; Rule = 'N6'; Fix = 'Privileged directory role on a workload: remove it or scope it (administrative unit, narrower role) and record a risk acceptance.' }
    'PERM-SENSITIVE'       = @{ Owasp = 'NHI5'; Rule = 'N6'; Fix = 'Broad write or bulk-data permission: justify it in the owner attestation or replace with a narrower one.' }
    'DELEGATED-TENANTWIDE' = @{ Owasp = 'NHI5'; Rule = 'N6'; Fix = 'High-risk delegated scope consented for all users: narrow it or move to per-user consent.' }
    'FIC-PR-WRITE'         = @{ Owasp = 'NHI6'; Rule = 'N3'; Fix = 'A pull_request subject lets any PR mint a token for an identity with write rights: split read (PR) and write (protected environment) identities.' }
    'FIC-BRANCH'           = @{ Owasp = 'NHI6'; Rule = 'N3'; Fix = 'Branch-scoped subject: any workflow on that branch gets a token. Use a reviewer-protected environment subject.' }
    'FIC-WILDCARD'         = @{ Owasp = 'NHI6'; Rule = 'N3'; Fix = 'Flexible (claims-matching) federated credential: replace with exact subjects.' }
    'FIC-AUDIENCE'         = @{ Owasp = 'NHI6'; Rule = 'N3'; Fix = 'Non-default audience on a federated credential: use api://AzureADTokenExchange unless a documented exception applies.' }
    'CRED-LONG-LIVED'      = @{ Owasp = 'NHI7'; Rule = 'N5'; Fix = 'Credential lifetime exceeds the maximum: reissue with a shorter lifetime (Key Vault auto-rotation) or move to federation.' }
    'CRED-EXPIRING'        = @{ Owasp = 'NHI7'; Rule = 'N5'; Fix = 'Rotation due: issue the replacement, cut over, then remove the old credential.' }
    'FIC-MULTI-ENV'        = @{ Owasp = 'NHI8'; Rule = 'N3'; Fix = 'One identity federates from several environments (e.g. dev and prod): give each environment its own identity.' }
    'FIC-REUSE'            = @{ Owasp = 'NHI9'; Rule = 'N3'; Fix = 'One identity federates from several workloads (repositories, service accounts): one identity per workload.' }
}

$SeverityRank = @{ 'Info' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Critical' = 4 }
# Case-insensitive sets: a permission typed 'directory.readwrite.all' in a
# parameter must still match what Graph returns.
$TierZeroSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$TierZeroPermissions, [System.StringComparer]::OrdinalIgnoreCase)
$SensitiveSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$SensitivePermissions, [System.StringComparer]::OrdinalIgnoreCase)
$ReadSignIns = -not $SkipSignInActivity

function Test-SecretsRegister {
    # Pure: register entries -> one row per secret + its findings. Never
    # reads or prints a value: the register holds names and store locations.
    param([Parameter(Mandatory)]$Register, [Parameter(Mandatory)][datetime]$Now, [string]$Source = 'register')
    $rows = [System.Collections.Generic.List[object]]::new(); $fx = [System.Collections.Generic.List[object]]::new()
    $entries = @($(if ($Register -is [System.Collections.IDictionary] -and $Register.Contains('secrets')) { $Register['secrets'] }) | Where-Object { $_ })
    if (-not $entries.Count) { throw 'the secrets register has no secrets[] entries' }
    foreach ($e in $entries) {
        $name = [string]$e['name']
        if (-not $name) { throw 'a secrets register entry has no name' }
        foreach ($k in 'store', 'status') { if (-not $e.Contains($k) -or -not [string]$e[$k]) { throw "secrets register entry '$name' has no $k" } }
        if ([string]$e['status'] -notin 'present', 'planned') { throw "secrets register entry '$name': status must be present or planned" }
        $exp = $null; $created = $null; $undated = ''
        foreach ($k in 'createdOn', 'expiresOn') {
            if (-not ($e.Contains($k) -and $e[$k])) { continue }
            $v = [string]$e[$k]
            # "unknown (<reason>)" records WHY no date can be read yet (a tenant-time secret, a stack not generated
            # here). It is still no date: the entry stays SECRET-NO-EXPIRY, with the reason on the finding.
            if ($v -match '^unknown \(.+\)$') { if ($k -eq 'expiresOn') { $undated = $v }; continue }
            try { $d = [datetime]::ParseExact($v, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }
            catch { throw "secrets register entry '$name': $k '$v' is not yyyy-MM-dd or 'unknown (<reason>)'" }
            if ($k -eq 'createdOn') { $created = $d } else { $exp = $d }
        }
        if ($created -and $exp -and $exp -lt $created) { throw "secrets register entry '$name': expiresOn $($exp.ToString('yyyy-MM-dd')) is before createdOn $($created.ToString('yyyy-MM-dd'))" }
        $owner = if ($e.Contains('owner')) { [string]$e['owner'] } else { '' }
        $rot = if ($e.Contains('rotation')) { [string]$e['rotation'] } else { '' }
        $add = {
            param($id, $sev, $detail)
            $o = if ($id -eq 'SECRET-NO-OWNER') { 'NHI1' } else { 'NHI7' }
            # Same columns as the Entra findings (Add-Finding), so one CSV holds both.
            $fx.Add([pscustomobject][ordered]@{ Source = $Source; Kind = 'NonEntraSecret'; DisplayName = $name; AppId = ''; ObjectId = "secret:$name"; FindingId = $id; Severity = $sev
                    OwaspNhi = "${o}:2025"; OwaspTitle = $(if ($o -eq 'NHI1') { 'Improper Offboarding' } else { 'Long-Lived Secrets' })
                    StandardRule = 'privileged-access-standard: every remaining secret has an owner, an expiry and a rotation'; Detail = $detail
                    Remediation = 'Fill the register entry (owner role, expiresOn yyyy-MM-dd, rotation) and rotate the secret at its store.' })
        }
        if (-not $owner) { & $add 'SECRET-NO-OWNER' 'High' "$name ($([string]$e['system'])) has no owner role" }
        if ($exp -and $exp -lt $Now.Date) { & $add 'SECRET-EXPIRED' 'High' "$name expired on $($exp.ToString('yyyy-MM-dd')) and is still listed" }
        elseif (-not $exp) { & $add 'SECRET-NO-EXPIRY' 'Medium' ("$name has no expiry date on record ($([string]$e['status']))" + $(if ($undated) { ": $undated" })) }
        if (-not $rot) { & $add 'SECRET-NO-ROTATION' 'Medium' "$name has no rotation rule" }
        $rows.Add([pscustomobject][ordered]@{ Source = $Source; Name = $name; System = [string]$e['system']; Store = [string]$e['store']; Owner = $owner
                ExpiresOn = $(if ($exp) { $exp.ToString('yyyy-MM-dd') } else { $undated }); Rotation = $rot; Status = [string]$e['status']; OwaspNhi = (@($e['owaspNhi']) -join ', ') })
    }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Findings = $fx.ToArray() }
}

function Read-OwnersRegister {
    # Pure: the owners register -> displayName -> @{ Role; Tier } for the
    # identities owned by a ROLE (ownerModel 'role'). Throws on anything it
    # cannot trust, so the caller records a FAILED source and counts nothing
    # as owned (fail closed).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Register)
    $roles = Get-Value $Register @('roles')
    if ($roles -isnot [System.Collections.IDictionary] -or $roles.Count -eq 0) { throw "owners register: 'roles' must name at least one role" }
    $ids = @(Get-Value $Register @('identities'))
    if ($ids.Count -eq 0 -or $null -eq $ids[0]) { throw "owners register: 'identities' is empty" }
    $map = @{}; $seen = @{}
    foreach ($e in $ids) {
        $name = [string](Get-Value $e @('displayName'))
        if (-not $name) { throw 'owners register: an identity has no displayName' }
        if ($seen.ContainsKey($name)) { throw "owners register: '$name' is listed twice" }
        $seen[$name] = $true
        $model = [string](Get-Value $e @('ownerModel'))
        if ($model -notin 'entra', 'role') { throw "owners register: '$name' ownerModel must be 'entra' or 'role' (got '$model')" }
        if ($model -eq 'role') {
            $role = [string](Get-Value $e @('accountableOwnerRole'))
            if (-not $role -or -not $roles.Contains($role)) { throw "owners register: '$name' names role '$role', which is not in 'roles'" }
            $map[$name] = @{ Role = $role; Tier = [string](Get-Value $e @('tier')) }
        }
    }
    return $map
}

function Get-RaisedSeverity([string]$Severity) {
    switch ($Severity) { 'Info' { 'Low' } 'Low' { 'Medium' } 'Medium' { 'High' } default { 'Critical' } }
}

# Safe nested read for Graph hashtables and objects: StrictMode throws on a
# missing property, and Graph omits null properties from some responses.
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

# Graph dates arrive as ISO strings or already-parsed DateTime, depending on
# the deserializer. Unparseable -> $null (the caller treats it as unknown).
function ConvertTo-UtcDate($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed.UtcDateTime }
    return $null
}

$dataSources = [System.Collections.Generic.List[object]]::new()
function Add-DataSource([string]$Name, [string]$Status, [string]$Detail = '') {
    $dataSources.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
    if ($Status -like 'FAILED*') { Write-Warning "Data source '$Name' FAILED: $Detail -- related columns are UNKNOWN, not clean." }
}

# GET with paging. Throws on error; callers decide whether a source is fatal.
function Invoke-GraphGetAll([string]$Uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        if ($page -is [System.Collections.IDictionary] -and $page.Contains('value')) {
            foreach ($v in @($page['value'])) { $items.Add($v) }
            $next = if ($page.Contains('@odata.nextLink')) { [string]$page['@odata.nextLink'] } else { $null }
        }
        else { $items.Add($page); $next = $null }
    }
    return $items.ToArray()
}

# ===========================================================================
# 1. COLLECT  (tenant via Graph, or the built-in mock tenant)
# ===========================================================================
# Both paths return the SAME shape, so section 2 (the classification) runs
# identical code offline and online. That is what makes -Offline a real test.
#   Applications / ServicePrincipals : Graph objects (hashtables), owners expanded
#   Fics          : appObjectId -> FIC list, or $null when the read failed
#   GraphAppRoles : appRoleId -> permission value (Microsoft Graph SP)
#   GraphAssignments : appRoleAssignedTo rows on the Graph SP (or $null)
#   PrivilegedRoles  : principalId -> list of privileged role names (or $null)
#   Grants        : oauth2PermissionGrants (or $null)
#   SignIns       : appId -> last sign-in (DateTime) (or $null = unavailable)
#   OwnerState    : userId -> $true/$false accountEnabled ($null = unknown)
#   AgentSponsors : agent SP id -> sponsor count ($null = unknown)

function Get-MockDate([double]$Days) { return $Now.AddDays($Days).ToString('o') }

function Get-MockTenant {
    # A mock tenant: the lab's own NHIs (names match modules/pipeline-identity,
    # modules/keyvault, modules/dc-vm and lab/pam/README.md) plus seeded bad
    # examples so every rule has something to fire on. Ids say 'mock-' on
    # purpose. Dates are relative to now so results never drift.
    $tid = 'mock-tenant-contosohealth'
    $user = @{}
    foreach ($u in @(
            @('operator', 'Lab Operator', 'lab-operator'),
            @('grace', 'Grace Mwangi', 'grace.mwangi'),
            @('omar', 'Omar Haddad', 'omar.haddad'),
            @('daniel', 'Daniel Osei', 'daniel.osei'),
            @('priya', 'Priya Nair', 'priya.nair'))) {
        $user[$u[0]] = @{ '@odata.type' = '#microsoft.graph.user'; id = "mock-user-$($u[0])"; displayName = $u[1]; userPrincipalName = "$($u[2])@contosohealth.io" }
    }
    $noImplicit = @{ implicitGrantSettings = @{ enableAccessTokenIssuance = $false } }
    $repoLab = 'contoso-health@1001/identity-lab@2002'
    $repoPortal = 'contoso-health@1001/clinical-portal@3003'

    $apps = @(
        @{ id = 'mock-app-plan'; appId = 'mock-appid-plan'; displayName = 'gh-oidc-entra-plan (read-only)'; createdDateTime = (Get-MockDate -30)
            passwordCredentials = @(); keyCredentials = @(); signInAudience = 'AzureADMyOrg'; web = $noImplicit; owners = @() }
        @{ id = 'mock-app-apply'; appId = 'mock-appid-apply'; displayName = 'gh-oidc-entra-apply (write)'; createdDateTime = (Get-MockDate -30)
            passwordCredentials = @(); keyCredentials = @(); signInAudience = 'AzureADMyOrg'; web = $noImplicit; owners = @() }
        @{ id = 'mock-app-midpoint'; appId = 'mock-appid-midpoint'; displayName = 'midpoint-reader'; createdDateTime = (Get-MockDate -20)
            passwordCredentials = @(@{ keyId = 'mock-key-mp1'; displayName = 'midpoint-connector'; startDateTime = (Get-MockDate -20); endDateTime = (Get-MockDate 345) })
            keyCredentials = @(); signInAudience = 'AzureADMyOrg'; web = $noImplicit; owners = @($user.operator) }
        @{ id = 'mock-app-legacy'; appId = 'mock-appid-legacy'; displayName = 'legacy-report-exporter'; createdDateTime = (Get-MockDate -900)
            passwordCredentials = @(@{ keyId = 'mock-key-lr1'; displayName = 'export-job'; startDateTime = (Get-MockDate -740); endDateTime = (Get-MockDate -10) })
            keyCredentials = @(@{ keyId = 'mock-key-lr2'; displayName = 'CN=legacy-report-exporter'; type = 'AsymmetricX509Cert'; usage = 'Verify'; startDateTime = (Get-MockDate -400); endDateTime = (Get-MockDate 695) })
            signInAudience = 'AzureADMyOrg'; web = @{ implicitGrantSettings = @{ enableAccessTokenIssuance = $true } }; owners = @($user.priya) }
        @{ id = 'mock-app-ci'; appId = 'mock-appid-ci'; displayName = 'ci-multi-env-deployer'; createdDateTime = (Get-MockDate -200)
            passwordCredentials = @(); keyCredentials = @(); signInAudience = 'AzureADMyOrg'; web = $noImplicit; owners = @($user.omar, $user.daniel) }
        @{ '@odata.type' = '#microsoft.graph.agentIdentityBlueprint'; id = 'mock-app-blueprint'; appId = 'mock-appid-blueprint'
            displayName = 'Contoso Access Review Assistant (blueprint)'; createdDateTime = (Get-MockDate -5)
            passwordCredentials = @(); keyCredentials = @(); signInAudience = 'AzureADMyOrg'; web = $noImplicit; owners = @($user.operator, $user.grace) }
    )
    $fic = { param($name, $issuer, $subject) @{ name = $name; issuer = $issuer; subject = $subject; audiences = @($ExchangeAudience) } }
    $fics = @{
        'mock-app-plan'      = @(& $fic 'github-pull-request' $GitHubIssuer "repo:${repoLab}:pull_request")
        'mock-app-apply'     = @(& $fic 'github-env-prod' $GitHubIssuer "repo:${repoLab}:environment:prod")
        'mock-app-midpoint'  = @()
        'mock-app-legacy'    = @()
        'mock-app-ci'        = @(
            (& $fic 'env-dev' $GitHubIssuer "repo:${repoLab}:environment:dev"),
            (& $fic 'env-prod' $GitHubIssuer "repo:${repoLab}:environment:prod"),
            (& $fic 'portal-pr' $GitHubIssuer "repo:${repoPortal}:pull_request"))
        'mock-app-blueprint' = @(& $fic 'agent-runtime-uami' "https://login.microsoftonline.com/$tid/v2.0" 'mock-sp-agent-uami')
    }

    $sp = { param($id, $appId, $name, $owner, $type)
        @{ id = $id; appId = $appId; displayName = $name; servicePrincipalType = $type; accountEnabled = $true
            appOwnerOrganizationId = $owner; passwordCredentials = @(); keyCredentials = @(); alternativeNames = @()
            verifiedPublisher = @{ verifiedPublisherId = $null }; owners = @() } }
    $sps = @(
        (& $sp 'mock-sp-plan' 'mock-appid-plan' 'gh-oidc-entra-plan (read-only)' $tid 'Application'),
        (& $sp 'mock-sp-apply' 'mock-appid-apply' 'gh-oidc-entra-apply (write)' $tid 'Application'),
        (& $sp 'mock-sp-midpoint' 'mock-appid-midpoint' 'midpoint-reader' $tid 'Application'),
        (& $sp 'mock-sp-legacy' 'mock-appid-legacy' 'legacy-report-exporter' $tid 'Application'),
        (& $sp 'mock-sp-ci' 'mock-appid-ci' 'ci-multi-env-deployer' $tid 'Application'),
        (& $sp 'mock-sp-oldhr' 'mock-appid-oldhr' 'old-hr-connector' $tid 'Application'),
        (& $sp 'mock-sp-pdf' 'mock-appid-pdf' 'PDF Wizard Online' 'mock-tenant-vendor' 'Application'),
        (& $sp 'mock-sp-msgraph' $GraphAppId 'Microsoft Graph' $MicrosoftTenantIds[0] 'Application')
    )
    $bp = & $sp 'mock-sp-blueprint' 'mock-appid-blueprint' 'Contoso Access Review Assistant (blueprint)' $tid 'Application'
    $bp['@odata.type'] = '#microsoft.graph.agentIdentityBlueprintPrincipal'
    $agentOk = & $sp 'mock-sp-agent-ara' 'mock-appid-agent-ara' 'contoso-access-review-assistant' $tid 'ServiceIdentity'
    $agentOk['@odata.type'] = '#microsoft.graph.agentIdentity'
    $agentOrphan = & $sp 'mock-sp-agent-pilot' 'mock-appid-agent-pilot' 'pilot-scheduling-agent' $tid 'ServiceIdentity'
    $agentOrphan['@odata.type'] = '#microsoft.graph.agentIdentity'
    $uamiKv = & $sp 'mock-sp-uami-kv' 'mock-appid-uami-kv' 'uami-idlab-kv-reader' $tid 'ManagedIdentity'
    $uamiKv['alternativeNames'] = @('isExplicit=True', '/subscriptions/<sub>/resourceGroups/rg-idlab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-idlab-kv-reader')
    $uamiAgent = & $sp 'mock-sp-agent-uami' 'mock-appid-agent-uami' 'uami-agent-runtime' $tid 'ManagedIdentity'
    $uamiAgent['alternativeNames'] = @('isExplicit=True', '/subscriptions/<sub>/resourceGroups/rg-idlab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-agent-runtime')
    $dc01 = & $sp 'mock-sp-dc01' 'mock-appid-dc01' 'DC01' $tid 'ManagedIdentity'
    $dc01['alternativeNames'] = @('isExplicit=False', '/subscriptions/<sub>/resourceGroups/rg-idlab/providers/Microsoft.Compute/virtualMachines/DC01')
    $sps += @($bp, $agentOk, $agentOrphan, $uamiKv, $uamiAgent, $dc01)

    # Graph app roles: mock ids, internally consistent (online uses real ids).
    $assign = [System.Collections.Generic.List[object]]::new()
    $roleMap = @{}
    $mockPerms = @{
        'mock-sp-plan'     = @('User.Read.All', 'Group.Read.All', 'Policy.Read.All', 'EntitlementManagement.Read.All', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.AzureADGroup')
        'mock-sp-apply'    = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'EntitlementManagement.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.AzureADGroup')
        'mock-sp-midpoint' = @('User.Read.All', 'Group.Read.All')
        'mock-sp-legacy'   = @('Directory.ReadWrite.All')
        'mock-sp-ci'       = @('Group.ReadWrite.All')
    }
    foreach ($spId in $mockPerms.Keys) {
        foreach ($perm in $mockPerms[$spId]) {
            $roleMap["mock-approle-$perm"] = $perm
            $assign.Add(@{ principalId = $spId; principalType = 'ServicePrincipal'; appRoleId = "mock-approle-$perm" })
        }
    }

    return @{
        TenantId          = $tid
        Applications      = $apps
        ServicePrincipals = $sps
        Fics              = $fics
        GraphAppRoles     = $roleMap
        GraphAssignments  = $assign.ToArray()
        PrivilegedRoles   = @{ 'mock-sp-oldhr' = @('User Administrator') }
        Grants            = @(@{ clientId = 'mock-sp-pdf'; consentType = 'AllPrincipals'; scope = 'openid profile offline_access Files.ReadWrite.All Mail.Read' })
        SignIns           = @{
            'mock-appid-plan' = $Now.AddDays(-1); 'mock-appid-apply' = $Now.AddDays(-2); 'mock-appid-midpoint' = $Now.AddDays(-3)
            'mock-appid-legacy' = $Now.AddDays(-200); 'mock-appid-ci' = $Now.AddDays(-5); 'mock-appid-uami-kv' = $Now.AddDays(-1)
            'mock-appid-agent-uami' = $Now.AddDays(-1); 'mock-appid-pdf' = $Now.AddDays(-10); 'mock-appid-agent-ara' = $Now.AddDays(-1)
            'mock-appid-oldhr' = $Now.AddDays(-400); 'mock-appid-blueprint' = $Now.AddDays(-1)
        }
        OwnerState        = @{ 'mock-user-operator' = $true; 'mock-user-grace' = $true; 'mock-user-omar' = $true; 'mock-user-daniel' = $true; 'mock-user-priya' = $false }
        AgentSponsors     = @{ 'mock-sp-agent-ara' = 1; 'mock-sp-agent-pilot' = 0 }
    }
}

function Get-OnlineTenant {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    $graph = 'https://graph.microsoft.com'
    $requiredScopes = @('Application.Read.All', 'Directory.Read.All', 'RoleManagement.Read.Directory', 'AuditLog.Read.All')
    if ($UseAzureCliToken) {
        # App-only: always this identity, never a leftover context.
        Write-Host 'Signing in to Microsoft Graph app-only (token from the Azure CLI session)...' -ForegroundColor Yellow
        Connect-GraphFromAzureCli
    }
    $ctx = $null; try { $ctx = Get-MgContext } catch { $ctx = $null }
    if (-not $ctx) {
        if ($UseAzureCliToken) { throw 'No Microsoft Graph context after the app-only sign-in.' }
        Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Yellow; Connect-MgGraph -Scopes $requiredScopes; $ctx = Get-MgContext
    }
    $missingScopes = @(Get-MissingGraphScope -Have @($ctx.Scopes) -Required $requiredScopes)
    if ($missingScopes) { Write-Warning "Current Graph context does not list: $($missingScopes -join ', '). Reads needing them fail and are recorded as FAILED sources (Disconnect-MgGraph, then re-run to reconnect with all scopes)." }

    $t = @{ TenantId = [string]$ctx.TenantId; Fics = @{}; GraphAppRoles = @{}; GraphAssignments = $null; PrivilegedRoles = $null
        Grants = $null; SignIns = $null; OwnerState = @{}; AgentSponsors = @{} }

    # Core objects. Without them there is no inventory, so these failures are fatal.
    # $expand=owners returns up to 20 owners per object (verify: expand limit),
    # which is more than any NHI should have.
    Write-Host 'Reading app registrations and service principals...' -ForegroundColor Cyan
    $t.Applications = @(Invoke-GraphGetAll "$graph/v1.0/applications?`$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials,signInAudience,web,verifiedPublisher&`$expand=owners")
    $t.ServicePrincipals = @(Invoke-GraphGetAll "$graph/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,passwordCredentials,keyCredentials,alternativeNames,verifiedPublisher&`$expand=owners")
    Add-DataSource 'applications+servicePrincipals' 'ok' "$($t.Applications.Count) apps, $($t.ServicePrincipals.Count) SPs"

    # If an object came back without an 'owners' key (expand not honoured),
    # read its owners directly: a missing key must never read as "no owners".
    $ownerReadFails = 0
    foreach ($pair in @(@{ Path = 'applications'; Items = $t.Applications }, @{ Path = 'servicePrincipals'; Items = $t.ServicePrincipals })) {
        foreach ($o in $pair.Items) {
            if ($o -is [System.Collections.IDictionary] -and -not $o.Contains('owners')) {
                try { $o['owners'] = @(Invoke-GraphGetAll "$graph/v1.0/$($pair.Path)/$($o['id'])/owners") }
                catch { $o['_ownersUnknown'] = $true; $ownerReadFails++ }
            }
        }
    }
    if ($ownerReadFails) { Add-DataSource 'owners (direct read)' "FAILED ($ownerReadFails objects)" 'owners unknown for those objects' }

    # Owner account state. Expanded owners carry the default user properties,
    # which don't include accountEnabled, so look each owner up once.
    $ownerIds = @(@($t.Applications) + @($t.ServicePrincipals) | ForEach-Object { @(Get-Value $_ @('owners')) } |
        Where-Object { $_ -and "$(Get-Value $_ @('@odata.type'))" -eq '#microsoft.graph.user' } | ForEach-Object { [string]$_['id'] } | Sort-Object -Unique)
    $ownerFails = 0
    foreach ($oid in $ownerIds) {
        try {
            $u = Invoke-MgGraphRequest -Method GET -Uri "$graph/v1.0/users/$($oid)?`$select=id,accountEnabled" -ErrorAction Stop
            $t.OwnerState[$oid] = [bool]$u['accountEnabled']
        }
        catch { $t.OwnerState[$oid] = $null; $ownerFails++ }
    }
    if ($ownerFails) { Add-DataSource 'owner accountEnabled' "FAILED ($ownerFails of $($ownerIds.Count))" 'owner state unknown for those owners; no orphan verdict is made on unknown state' }
    else { Add-DataSource 'owner accountEnabled' 'ok' "$($ownerIds.Count) owners" }

    # Federated credentials, per app. One call each (use $batch at scale).
    $ficFails = 0
    foreach ($a in $t.Applications) {
        try { $t.Fics[[string]$a['id']] = @(Invoke-GraphGetAll "$graph/v1.0/applications/$($a['id'])/federatedIdentityCredentials") }
        catch { $t.Fics[[string]$a['id']] = $null; $ficFails++ }
    }
    if ($ficFails) { Add-DataSource 'federatedIdentityCredentials' "FAILED ($ficFails of $($t.Applications.Count))" 'federation checks skipped for those apps' }
    else { Add-DataSource 'federatedIdentityCredentials' 'ok' }

    # Microsoft Graph APPLICATION permissions: every assignment of a Graph app
    # role, read once from the resource side (appRoleAssignedTo) instead of
    # once per service principal.
    try {
        $graphSp = Invoke-MgGraphRequest -Method GET -Uri "$graph/v1.0/servicePrincipals(appId='$GraphAppId')?`$select=id,appRoles" -ErrorAction Stop
        foreach ($r in @($graphSp['appRoles'])) { $t.GraphAppRoles[[string]$r['id']] = [string]$r['value'] }
        $t.GraphAssignments = @(Invoke-GraphGetAll "$graph/v1.0/servicePrincipals/$($graphSp['id'])/appRoleAssignedTo")
        Add-DataSource 'graph appRoleAssignedTo' 'ok' "$($t.GraphAssignments.Count) assignments"
    }
    catch { Add-DataSource 'graph appRoleAssignedTo' 'FAILED' $_.Exception.Message }

    # Privileged directory roles held by service principals.
    try {
        $roleDefs = @(Invoke-GraphGetAll "$graph/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId")
        $privilegedIds = @()
        try {
            $privilegedIds = @((Invoke-GraphGetAll "$graph/beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true&`$select=id,templateId") | ForEach-Object { [string]$_['id'] })
        }
        catch {
            Write-Warning "beta isPrivileged unavailable ($($_.Exception.Message)); using the static Tier-0 role list."
            $privilegedIds = @($StaticPrivilegedRoles.Keys)
        }
        $spIds = @{}; foreach ($s in $t.ServicePrincipals) { $spIds[[string]$s['id']] = $true }
        $t.PrivilegedRoles = @{}
        foreach ($def in ($roleDefs | Where-Object { [string]$_['id'] -in $privilegedIds -or [string]$_['templateId'] -in $privilegedIds })) {
            $rows = @(Invoke-GraphGetAll "$graph/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($def['id'])'&`$select=principalId,roleDefinitionId,directoryScopeId")
            foreach ($row in $rows | Where-Object { $spIds.ContainsKey([string]$_['principalId']) }) {
                $p = [string]$row['principalId']
                if (-not $t.PrivilegedRoles.ContainsKey($p)) { $t.PrivilegedRoles[$p] = @() }
                $t.PrivilegedRoles[$p] += [string]$def['displayName']
            }
        }
        Add-DataSource 'privileged directory roles' 'ok'
    }
    catch { $t.PrivilegedRoles = $null; Add-DataSource 'privileged directory roles' 'FAILED' $_.Exception.Message }

    # Delegated grants (consent). Tenant-wide = consentType AllPrincipals.
    try { $t.Grants = @(Invoke-GraphGetAll "$graph/v1.0/oauth2PermissionGrants"); Add-DataSource 'oauth2PermissionGrants' 'ok' }
    catch { Add-DataSource 'oauth2PermissionGrants' 'FAILED' $_.Exception.Message }

    # Last sign-in per appId. verify: beta only (no v1.0 version listed).
    if (-not $ReadSignIns) { Add-DataSource 'servicePrincipalSignInActivities' 'skipped' 'LastSignIn = unknown; no stale verdicts' }
    else {
        try {
            $t.SignIns = @{}
            foreach ($row in (Invoke-GraphGetAll "$graph/beta/reports/servicePrincipalSignInActivities")) {
                $t.SignIns[[string]$row['appId']] = ConvertTo-UtcDate (Get-Value $row @('lastSignInActivity', 'lastSignInDateTime'))
            }
            Add-DataSource 'servicePrincipalSignInActivities (beta)' 'ok' "$($t.SignIns.Count) rows"
        }
        catch { $t.SignIns = $null; Add-DataSource 'servicePrincipalSignInActivities (beta)' 'FAILED' $_.Exception.Message }
    }

    # Agent identity sponsors. verify: the v1.0 List sponsors page lists
    # APPLICATION permission only (AgentIdentity.ReadWrite.All), so a delegated
    # session may get 403 here; that is recorded, never read as "no sponsor".
    $agents = @($t.ServicePrincipals | Where-Object { "$(Get-Value $_ @('@odata.type'))" -eq '#microsoft.graph.agentIdentity' })
    if ($agents.Count) {
        $sponsorFails = 0
        foreach ($ag in $agents) {
            try { $t.AgentSponsors[[string]$ag['id']] = @(Invoke-GraphGetAll "$graph/v1.0/servicePrincipals/$($ag['id'])/microsoft.graph.agentIdentity/sponsors").Count }
            catch { $t.AgentSponsors[[string]$ag['id']] = $null; $sponsorFails++ }
        }
        if ($sponsorFails) { Add-DataSource 'agent identity sponsors' "FAILED ($sponsorFails of $($agents.Count))" 'List sponsors may need an app-only connection (AgentIdentity.ReadWrite.All); check sponsors in the Entra admin center' }
        else { Add-DataSource 'agent identity sponsors' 'ok' }
    }
    return $t
}

if ($Offline) {
    Write-Console 'OFFLINE: classifying the built-in MOCK tenant. Nothing here is tenant evidence.' -ForegroundColor DarkYellow
    $tenant = Get-MockTenant
    foreach ($n in 'applications+servicePrincipals', 'owner accountEnabled', 'federatedIdentityCredentials', 'graph appRoleAssignedTo',
        'privileged directory roles', 'oauth2PermissionGrants', 'servicePrincipalSignInActivities (beta)', 'agent identity sponsors') {
        Add-DataSource $n 'ok (mock)'
    }
}
else {
    $tenant = Get-OnlineTenant
}

# ===========================================================================
# 2. CLASSIFY  (identical for mock and tenant data)
# ===========================================================================
$tenantId = [string]$tenant.TenantId
$findings = [System.Collections.Generic.List[object]]::new()
$records = [System.Collections.Generic.List[object]]::new()
$excludedFirstParty = 0

function Add-Finding($Record, [string]$Id, [string]$Severity, [string]$Detail) {
    $c = $Catalog[$Id]
    if ($Record.IsTierZero -and $Id -notin 'PERM-TIER0', 'ROLE-PRIVILEGED', 'PERM-SENSITIVE', 'CRED-EXPIRING') { $Severity = Get-RaisedSeverity $Severity }
    $findings.Add([pscustomobject]@{
            Source       = $Source
            Kind         = $Record.Kind
            DisplayName  = $Record.DisplayName
            AppId        = $Record.AppId
            ObjectId     = if ($Record.SpObjectId) { $Record.SpObjectId } else { $Record.AppObjectId }
            FindingId    = $Id
            Severity     = $Severity
            OwaspNhi     = "$($c.Owasp):2025"
            OwaspTitle   = $OwaspTitles[$c.Owasp]
            StandardRule = $c.Rule
            Detail       = $Detail
            Remediation  = $c.Fix
        })
}

# Graph permissions and roles per SP id.
$permsBySp = @{}
if ($null -ne $tenant.GraphAssignments) {
    foreach ($a in $tenant.GraphAssignments) {
        if ("$(Get-Value $a @('principalType'))" -ne 'ServicePrincipal') { continue }
        $value = $tenant.GraphAppRoles[[string]$a['appRoleId']]
        if (-not $value) { continue }
        $p = [string]$a['principalId']
        if (-not $permsBySp.ContainsKey($p)) { $permsBySp[$p] = [System.Collections.Generic.List[string]]::new() }
        $permsBySp[$p].Add($value)
    }
}
$grantsBySp = @{}
if ($null -ne $tenant.Grants) {
    foreach ($g in $tenant.Grants) {
        if ("$(Get-Value $g @('consentType'))" -ne 'AllPrincipals') { continue }
        $c = [string]$g['clientId']
        if (-not $grantsBySp.ContainsKey($c)) { $grantsBySp[$c] = [System.Collections.Generic.List[string]]::new() }
        foreach ($s in ("$(Get-Value $g @('scope'))" -split '\s+' | Where-Object { $_ })) { $grantsBySp[$c].Add($s) }
    }
}

function Get-OwnerSummary([object[]]$Owners) {
    $list = foreach ($o in $Owners) {
        if (-not $o) { continue }
        $type = ("$(Get-Value $o @('@odata.type'))" -replace '^#microsoft\.graph\.', '')
        $id = [string](Get-Value $o @('id'))
        $enabled = if ($type -eq 'user') { if ($tenant.OwnerState.ContainsKey($id)) { $tenant.OwnerState[$id] } else { $null } } else { $null }
        $label = if (Get-Value $o @('userPrincipalName')) { [string](Get-Value $o @('userPrincipalName')) } else { [string](Get-Value $o @('displayName')) }
        [pscustomobject]@{ Id = $id; Type = $type; Label = $label; Enabled = $enabled }
    }
    return @($list | Sort-Object Id -Unique)
}

# Build one record per NHI (see "WHAT IS INVENTORIED").
$homeSpByAppId = @{}
foreach ($s in $tenant.ServicePrincipals) {
    $odata = "$(Get-Value $s @('@odata.type'))"
    if ([string](Get-Value $s @('appOwnerOrganizationId')) -eq $tenantId -and $odata -ne '#microsoft.graph.agentIdentity' -and
        "$(Get-Value $s @('servicePrincipalType'))" -ne 'ManagedIdentity') {
        $homeSpByAppId[[string]$s['appId']] = $s
    }
}
$consumedSp = @{}

function Get-NhiRecord([string]$Kind, $App, $Sp) {
    $r = [ordered]@{
        Kind = $Kind; DisplayName = ''; AppId = ''; AppObjectId = ''; SpObjectId = ''
        Created = $null; Owners = @(); OwnersKnown = $true; Passwords = @(); KeyCreds = @(); Fics = @(); FicsKnown = $true
        TierZero = @(); Sensitive = @(); Roles = @(); TenantWideScopes = @(); IsTierZero = $false
        ImplicitGrant = $false; PublisherVerified = $false; Sponsors = $null; OwnerModel = 'Entra owners'; ManagedIdentityType = ''; AccountableOwner = ''
        LastSignIn = $null; SignInKnown = $false
    }
    if ($App) {
        $r.DisplayName = [string]$App['displayName']; $r.AppId = [string]$App['appId']; $r.AppObjectId = [string]$App['id']
        $r.Created = ConvertTo-UtcDate (Get-Value $App @('createdDateTime'))
        $r.Owners += @(Get-Value $App @('owners'))
        if (Get-Value $App @('_ownersUnknown')) { $r.OwnersKnown = $false }
        $r.Passwords += @(Get-Value $App @('passwordCredentials') | Where-Object { $_ } | ForEach-Object { @{ Cred = $_; On = 'app' } })
        $r.KeyCreds += @(Get-Value $App @('keyCredentials') | Where-Object { $_ } | ForEach-Object { @{ Cred = $_; On = 'app' } })
        $r.ImplicitGrant = [bool](Get-Value $App @('web', 'implicitGrantSettings', 'enableAccessTokenIssuance'))
        $ficList = $tenant.Fics[[string]$App['id']]
        if ($null -eq $ficList) { $r.FicsKnown = $false } else { $r.Fics = @($ficList) }
    }
    if ($Sp) {
        if (-not $r.DisplayName) { $r.DisplayName = [string]$Sp['displayName'] }
        if (-not $r.AppId) { $r.AppId = [string](Get-Value $Sp @('appId')) }
        $r.SpObjectId = [string]$Sp['id']
        $r.Owners += @(Get-Value $Sp @('owners'))
        if (Get-Value $Sp @('_ownersUnknown')) { $r.OwnersKnown = $false }
        $r.Passwords += @(Get-Value $Sp @('passwordCredentials') | Where-Object { $_ } | ForEach-Object { @{ Cred = $_; On = 'sp' } })
        $r.KeyCreds += @(Get-Value $Sp @('keyCredentials') | Where-Object { $_ } | ForEach-Object { @{ Cred = $_; On = 'sp' } })
        $r.PublisherVerified = [bool](Get-Value $Sp @('verifiedPublisher', 'verifiedPublisherId'))
        if ($permsBySp.ContainsKey($r.SpObjectId)) {
            $r.TierZero = @($permsBySp[$r.SpObjectId] | Where-Object { $TierZeroSet.Contains($_) } | Sort-Object -Unique)
            $r.Sensitive = @($permsBySp[$r.SpObjectId] | Where-Object { $SensitiveSet.Contains($_) } | Sort-Object -Unique)
        }
        if ($null -ne $tenant.PrivilegedRoles -and $tenant.PrivilegedRoles.ContainsKey($r.SpObjectId)) { $r.Roles = @($tenant.PrivilegedRoles[$r.SpObjectId] | Sort-Object -Unique) }
        if ($grantsBySp.ContainsKey($r.SpObjectId)) { $r.TenantWideScopes = @($grantsBySp[$r.SpObjectId] | Sort-Object -Unique) }
    }
    $r.IsTierZero = ($r.TierZero.Count -gt 0) -or ($r.Roles.Count -gt 0)
    if ($null -ne $tenant.SignIns -and $r.AppId) {
        $r.SignInKnown = $true
        $r.LastSignIn = if ($tenant.SignIns.ContainsKey($r.AppId)) { $tenant.SignIns[$r.AppId] } else { $null }
    }
    return $r
}

foreach ($app in $tenant.Applications) {
    $kind = if ("$(Get-Value $app @('@odata.type'))" -match 'agentIdentityBlueprint$') { 'AgentBlueprint' } else { 'AppRegistration' }
    $sp = $homeSpByAppId[[string]$app['appId']]
    if ($sp) { $consumedSp[[string]$sp['id']] = $true }
    $records.Add((Get-NhiRecord $kind $app $sp))
}
foreach ($sp in $tenant.ServicePrincipals) {
    if ($consumedSp.ContainsKey([string]$sp['id'])) { continue }
    $odata = "$(Get-Value $sp @('@odata.type'))"
    $ownerOrg = [string](Get-Value $sp @('appOwnerOrganizationId'))
    if ($ownerOrg -in $MicrosoftTenantIds -and -not $IncludeMicrosoftFirstParty) { $excludedFirstParty++; continue }
    $kind = if ($odata -eq '#microsoft.graph.agentIdentity') { 'AgentIdentity' }
    elseif ("$(Get-Value $sp @('servicePrincipalType'))" -eq 'ManagedIdentity') { 'ManagedIdentity' }
    elseif ($ownerOrg -in $MicrosoftTenantIds) { 'MicrosoftFirstParty' }
    elseif ($ownerOrg -eq $tenantId) { 'OrphanedServicePrincipal' }
    else { 'ThirdPartyApp' }
    $rec = Get-NhiRecord $kind $null $sp
    if ($kind -eq 'ManagedIdentity') {
        $rec.OwnerModel = 'Azure RBAC on the resource'
        $rec.ManagedIdentityType = if (@(Get-Value $sp @('alternativeNames')) -contains 'isExplicit=True') { 'UserAssigned' } else { 'SystemAssigned' }
    }
    elseif ($kind -eq 'ThirdPartyApp') { $rec.OwnerModel = 'Vendor (other tenant)' }
    elseif ($kind -eq 'MicrosoftFirstParty') { $rec.OwnerModel = 'Microsoft' }
    elseif ($kind -eq 'AgentIdentity') {
        $rec.OwnerModel = 'Sponsor (Agent ID)'
        $rec.Sponsors = if ($tenant.AgentSponsors.ContainsKey($rec.SpObjectId)) { $tenant.AgentSponsors[$rec.SpObjectId] } else { $null }
    }
    $records.Add($rec)
}

# Owners register: identities whose accountable owner is a ROLE (Tier 0, no
# Entra owner). Read before the rules, so a role-owned identity is judged as
# owned; a duplicate display name in the tenant is never covered.
$roleOwned = @{}
if ($OwnersRegisterPath) {
    try {
        if (-not (Test-Path -LiteralPath $OwnersRegisterPath -PathType Leaf)) { throw "not found: $OwnersRegisterPath" }
        $regMap = Read-OwnersRegister -Register (Get-Content -LiteralPath $OwnersRegisterPath -Raw | ConvertFrom-Json -AsHashtable)
        $nameCount = @{}
        foreach ($r in @($records | Where-Object { $_.Kind -in 'AppRegistration', 'AgentBlueprint' })) { $nameCount[$r.DisplayName] = 1 + $(if ($nameCount.ContainsKey($r.DisplayName)) { $nameCount[$r.DisplayName] } else { 0 }) }
        $notes = @()
        foreach ($n in @($regMap.Keys | Sort-Object)) {
            $c = if ($nameCount.ContainsKey($n)) { $nameCount[$n] } else { 0 }
            if ($c -eq 1) { $roleOwned[$n] = $regMap[$n] }
            elseif ($c -gt 1) { $notes += "'$n' matches $c app registrations - none counted as owned"; Write-Warning "Owners register: '$n' matches $c app registrations; none is counted as role-owned." }
            else { $notes += "'$n' not in the tenant" }
        }
        Add-DataSource 'ownersRegister' 'ok' ("$($roleOwned.Count) identit$(if ($roleOwned.Count -eq 1) { 'y' } else { 'ies' }) owned by a role" + $(if ($notes) { '; ' + ($notes -join '; ') } else { '' }))
    }
    catch { $roleOwned = @{}; Add-DataSource 'ownersRegister' 'FAILED' $_.Exception.Message }
}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
foreach ($rec in $records) {
    $owners = @(Get-OwnerSummary @($rec.Owners))
    $rec.OwnerSummary = $owners

    # NHI5 - privilege first, so later rules know whether the record is Tier 0.
    if ($rec.TierZero.Count) { Add-Finding $rec 'PERM-TIER0' 'Critical' "Graph application permission(s): $($rec.TierZero -join ', ')" }
    if ($rec.Roles.Count) { Add-Finding $rec 'ROLE-PRIVILEGED' 'Critical' "Privileged directory role(s): $($rec.Roles -join ', ')" }
    if ($rec.Sensitive.Count) { Add-Finding $rec 'PERM-SENSITIVE' 'Medium' "Graph application permission(s): $($rec.Sensitive -join ', ')" }
    $riskyScopes = @($rec.TenantWideScopes | Where-Object { $_ -in $HighRiskDelegatedScopes })

    # NHI3 - third-party (vendor) apps with tenant-wide reach.
    if ($rec.Kind -eq 'ThirdPartyApp') {
        $appPerms = @($rec.TierZero + $rec.Sensitive)
        $pub = if ($rec.PublisherVerified) { 'verified publisher' } else { 'UNVERIFIED publisher' }
        if ($riskyScopes.Count -or $appPerms.Count) {
            Add-Finding $rec 'THIRDPARTY-CONSENT' 'High' "Vendor app ($pub) holds tenant-wide: $(@($riskyScopes + $appPerms) -join ', ')"
        }
        elseif (-not $rec.PublisherVerified -and $rec.TenantWideScopes.Count) {
            Add-Finding $rec 'THIRDPARTY-CONSENT' 'Medium' "Vendor app ($pub) holds tenant-wide delegated scopes: $($rec.TenantWideScopes -join ', ')"
        }
    }
    elseif ($riskyScopes.Count) {
        Add-Finding $rec 'DELEGATED-TENANTWIDE' 'Medium' "High-risk delegated scope(s) consented for all users: $($riskyScopes -join ', ')"
    }

    # NHI1 - ownership. Managed identities (Azure RBAC), vendor apps and
    # Microsoft apps have no Entra owner by design; agent identities are
    # governed by sponsors instead.
    if ($rec.Kind -in 'AppRegistration', 'AgentBlueprint' -and $rec.OwnersKnown) {
        $humans = @($owners | Where-Object Type -eq 'user')
        $enabledHumans = @($humans | Where-Object { $_.Enabled -eq $true })
        $disabledHumans = @($humans | Where-Object { $_.Enabled -eq $false })
        $nonHuman = @($owners | Where-Object Type -ne 'user')
        $reg = if ($roleOwned.ContainsKey($rec.DisplayName)) { $roleOwned[$rec.DisplayName] } else { $null }
        # Tier 0 by what it can do (permission, role) or by the register's word.
        $tierZeroOwnerRule = $rec.IsTierZero -or ($reg -and $reg.Tier -like 'Tier 0*')
        if ($tierZeroOwnerRule -and $owners.Count -gt 0) {
            Add-Finding $rec 'OWNER-TIER0' 'High' "Tier-0 identity with Entra owner(s): $(@($owners.Label) -join ', '). Each can add a credential and act as it."
        }
        if ($reg -and $owners.Count -eq 0) {
            # Owned by a role, as designed: no Entra owner to take it over.
            $rec.OwnerModel = "Register role ($($reg.Role))"
            $rec.AccountableOwner = $reg.Role
        }
        elseif ($reg) {
            # Role-owned on paper, but someone holds Entra ownership: OWNER-TIER0
            # above says so; the register still names who answers for it.
            $rec.AccountableOwner = $reg.Role
        }
        elseif ($owners.Count -eq 0) {
            Add-Finding $rec 'OWNER-NONE' 'Medium' 'No owners on the app registration or its service principal.'
        }
        elseif ($humans.Count -eq 0) {
            Add-Finding $rec 'OWNER-NO-HUMAN' 'Medium' "Owned only by: $(@($nonHuman.Label) -join ', ')"
        }
        elseif ($disabledHumans.Count -eq $humans.Count) {
            Add-Finding $rec 'OWNER-ALL-DISABLED' 'High' "Every human owner is disabled: $(@($disabledHumans.Label) -join ', ')"
        }
        elseif ($enabledHumans.Count -eq 1 -and $humans.Count -eq 1 -and $nonHuman.Count -eq 0 -and -not $tierZeroOwnerRule) {
            # Not for Tier 0: its fix is no Entra owner at all (OWNER-TIER0), never a second one.
            Add-Finding $rec 'OWNER-SINGLE' 'Low' "Single owner: $($enabledHumans[0].Label)"
        }
    }
    if ($rec.Kind -eq 'OrphanedServicePrincipal') {
        Add-Finding $rec 'SP-WITHOUT-APP' 'High' 'Home-tenant service principal with no app registration (deleted app; the SP, its grants and roles remain).'
    }
    if ($rec.Kind -eq 'AgentIdentity' -and $null -ne $rec.Sponsors -and $rec.Sponsors -eq 0) {
        Add-Finding $rec 'AGENT-NO-SPONSOR' 'High' 'Agent identity with no sponsor: no human is accountable for what it does.'
    }

    # NHI1 - activity. Unknown sign-in data never produces a verdict.
    if ($rec.SignInKnown -and $rec.Kind -ne 'MicrosoftFirstParty') {
        if ($rec.LastSignIn) {
            $idle = [int]($Now - $rec.LastSignIn).TotalDays
            if ($idle -gt $StaleDays) { Add-Finding $rec 'STALE' 'Medium' "Last sign-in $idle days ago ($($rec.LastSignIn.ToString('yyyy-MM-dd')))." }
        }
        elseif ($rec.Created -and ($Now - $rec.Created).TotalDays -gt $StaleDays) {
            Add-Finding $rec 'STALE-NEVER' 'Low' "No sign-in on record; created $($rec.Created.ToString('yyyy-MM-dd'))."
        }
    }

    # NHI2 / NHI4 / NHI7 / NHI1 - credentials.
    foreach ($p in $rec.Passwords) {
        $cred = $p.Cred
        $start = ConvertTo-UtcDate (Get-Value $cred @('startDateTime'))
        $end = ConvertTo-UtcDate (Get-Value $cred @('endDateTime'))
        $label = "secret '$(Get-Value $cred @('displayName'))' on $($p.On)"
        $sev = if ($rec.Fics.Count) { 'High' } else { 'Medium' }   # a secret beside federation defeats the secretless design
        Add-Finding $rec 'SECRET-PRESENT' $sev "$label$(if ($rec.Fics.Count) { ' (alongside federated credentials)' })"
        if ($end -and $end -lt $Now) { Add-Finding $rec 'CRED-EXPIRED' 'Low' "$label expired $($end.ToString('yyyy-MM-dd'))." }
        elseif ($end -and ($end - $Now).TotalDays -le $ExpiryWarningDays) { Add-Finding $rec 'CRED-EXPIRING' 'Info' "$label expires $($end.ToString('yyyy-MM-dd'))." }
        if ($start -and $end -and ($end - $start).TotalDays -gt $MaxCredentialLifetimeDays) {
            Add-Finding $rec 'CRED-LONG-LIVED' 'Medium' "$label lifetime $([int]($end - $start).TotalDays) days (max $MaxCredentialLifetimeDays)."
        }
    }
    foreach ($k in $rec.KeyCreds) {
        $cred = $k.Cred
        $start = ConvertTo-UtcDate (Get-Value $cred @('startDateTime'))
        $end = ConvertTo-UtcDate (Get-Value $cred @('endDateTime'))
        $type = [string](Get-Value $cred @('type'))
        # SP keys with usage 'Sign' are SAML token-signing certificates: they
        # sign tokens FOR the app, they don't authenticate AS it. Only their
        # expiry matters (an expired one breaks SSO).
        $isSamlSigning = $k.On -eq 'sp' -and [string](Get-Value $cred @('usage')) -eq 'Sign'
        $label = "$(if ($isSamlSigning) { 'SAML signing cert' } elseif ($type -eq 'Symmetric') { 'symmetric key' } else { 'certificate' }) '$(Get-Value $cred @('displayName'))' on $($k.On)"
        if ($type -eq 'Symmetric') { Add-Finding $rec 'SYMMETRIC-KEY' 'Medium' $label }
        if ($end -and $end -lt $Now) { Add-Finding $rec 'CRED-EXPIRED' 'Low' "$label expired $($end.ToString('yyyy-MM-dd'))." }
        elseif ($end -and ($end - $Now).TotalDays -le $ExpiryWarningDays) { Add-Finding $rec 'CRED-EXPIRING' 'Info' "$label expires $($end.ToString('yyyy-MM-dd'))." }
        if (-not $isSamlSigning -and $start -and $end -and ($end - $start).TotalDays -gt $MaxCredentialLifetimeDays) {
            Add-Finding $rec 'CRED-LONG-LIVED' 'Medium' "$label lifetime $([int]($end - $start).TotalDays) days (max $MaxCredentialLifetimeDays)."
        }
    }
    if ($rec.ImplicitGrant) { Add-Finding $rec 'IMPLICIT-GRANT' 'Medium' 'web.implicitGrantSettings.enableAccessTokenIssuance = true' }

    # NHI6 / NHI8 / NHI9 - federation.
    if ($rec.Fics.Count) {
        $canWrite = @($rec.TierZero + $rec.Sensitive | Where-Object { $_ -match 'ReadWrite|Write\.|\.Send|FullControl|PrivilegedOperations' }).Count -gt 0 -or $rec.Roles.Count -gt 0
        $contexts = [System.Collections.Generic.HashSet[string]]::new()
        $workloads = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($f in $rec.Fics) {
            $issuer = [string](Get-Value $f @('issuer'))
            $subject = [string](Get-Value $f @('subject'))
            $name = [string](Get-Value $f @('name'))
            if (Get-Value $f @('claimsMatchingExpression')) {
                Add-Finding $rec 'FIC-WILDCARD' 'Medium' "Federated credential '$name' uses claimsMatchingExpression (pattern, not exact subject)."
            }
            $aud = @(Get-Value $f @('audiences'))
            if ($aud.Count -ne 1 -or $aud[0] -ne $ExchangeAudience) { Add-Finding $rec 'FIC-AUDIENCE' 'Low' "Federated credential '$name' audiences: $($aud -join ', ')" }
            if ($issuer -eq $GitHubIssuer -and $subject -match '^repo:(?<repo>[^:]+):(?<ctx>.+)$') {
                [void]$workloads.Add("github:$($Matches.repo)")
                $ctxValue = $Matches.ctx
                [void]$contexts.Add($ctxValue)
                if ($ctxValue -eq 'pull_request' -and $canWrite) {
                    Add-Finding $rec 'FIC-PR-WRITE' 'High' "Federated credential '$name' trusts pull_request for an identity with write rights."
                }
                elseif ($ctxValue -like 'ref:refs/heads/*') {
                    Add-Finding $rec 'FIC-BRANCH' $(if ($canWrite) { 'Medium' } else { 'Low' }) "Federated credential '$name' trusts a branch ($ctxValue), not a protected environment."
                }
            }
            else {
                # Kubernetes SA, managed identity (Agent ID), other IdPs: the
                # subject itself identifies the workload.
                [void]$workloads.Add("${issuer}|${subject}")
                [void]$contexts.Add("${issuer}|${subject}")
            }
        }
        $envs = @($contexts | Where-Object { $_ -like 'environment:*' -or $_ -eq 'pull_request' -or $_ -like 'ref:*' })
        if ($envs.Count -gt 1) { Add-Finding $rec 'FIC-MULTI-ENV' 'Medium' "Trusted from $($envs.Count) contexts: $($envs -join ', ')" }
        if ($workloads.Count -gt 1) { Add-Finding $rec 'FIC-REUSE' 'Medium' "Trusted from $($workloads.Count) workloads: $(@($workloads) -join ', ')" }
    }
}

# ===========================================================================
# 3. OUTPUT
# ===========================================================================
function Get-MaxSeverity([object[]]$Rows) {
    $max = $null
    foreach ($r in $Rows) { if ($null -eq $max -or $SeverityRank[$r.Severity] -gt $SeverityRank[$max]) { $max = $r.Severity } }
    return $max
}

# OwnerCount = ACCOUNTABLE humans: enabled human owners (apps, blueprints,
# orphaned SPs) or sponsors (agent identities). Blank when ownership isn't an
# Entra concept (managed identity = Azure RBAC; vendor and Microsoft apps; a
# Tier-0 identity owned by a register role, see AccountableOwner) or when
# owner state couldn't be read, so 0 always means "orphaned", never
# "unknown".
function Get-OwnerCount($Rec) {
    if ($Rec.Kind -eq 'AgentIdentity') { if ($null -eq $Rec.Sponsors) { return '' } else { return [int]$Rec.Sponsors } }
    if ($Rec.Kind -notin 'AppRegistration', 'AgentBlueprint', 'OrphanedServicePrincipal' -or -not $Rec.OwnersKnown) { return '' }
    if ($Rec.AccountableOwner -and @($Rec.OwnerSummary).Count -eq 0) { return '' }   # owned by a register role, by design no Entra owner
    $enabled = @($Rec.OwnerSummary | Where-Object { $_.Type -eq 'user' -and $_.Enabled -eq $true }).Count
    $unknown = @($Rec.OwnerSummary | Where-Object { $_.Type -eq 'user' -and $null -eq $_.Enabled }).Count
    if ($enabled -eq 0 -and $unknown -gt 0) { return '' }
    return $enabled
}
function Get-RecordObjectId($Rec) { if ($Rec.SpObjectId) { $Rec.SpObjectId } else { $Rec.AppObjectId } }

# One row per credential (federated ones included), and one 'none' row for an
# NHI with no credential so every NHI is present: the rotation worklist.
# Graph never returns secret values, so none can appear here.
$credentialRows = foreach ($rec in $records) {
    $base = [ordered]@{ Source = $Source; ObjectId = (Get-RecordObjectId $rec); Kind = $rec.Kind; DisplayName = $rec.DisplayName; OwnerCount = (Get-OwnerCount $rec) }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @(@($rec.Passwords | ForEach-Object { @{ Item = $_; Type = 'secret' } }) + @($rec.KeyCreds | ForEach-Object { @{ Item = $_; Type = 'key' } }))) {
        $cred = $c.Item.Cred
        $start = ConvertTo-UtcDate (Get-Value $cred @('startDateTime'))
        $end = ConvertTo-UtcDate (Get-Value $cred @('endDateTime'))
        $type = if ($c.Type -eq 'secret') { 'secret' }
        elseif ([string](Get-Value $cred @('type')) -eq 'Symmetric') { 'symmetric' }
        elseif ($c.Item.On -eq 'sp' -and [string](Get-Value $cred @('usage')) -eq 'Sign') { 'saml-signing' }
        else { 'certificate' }
        $status = if (-not $end) { 'unknown' } elseif ($end -lt $Now) { 'expired' } elseif (($end - $Now).TotalDays -le $ExpiryWarningDays) { 'expiring' } else { 'active' }
        $row = [ordered]@{} + $base
        $row += [ordered]@{ CredentialType = $type; CredentialName = [string](Get-Value $cred @('displayName')); KeyId = [string](Get-Value $cred @('keyId')); On = $c.Item.On
            StartUtc = if ($start) { $start.ToString('o') } else { '' }; EndUtc = if ($end) { $end.ToString('o') } else { '' }
            LifetimeDays = if ($start -and $end) { [int]($end - $start).TotalDays } else { '' }; CredentialStatus = $status }
        $rows.Add([pscustomobject]$row)
    }
    foreach ($f in $rec.Fics) {
        $row = [ordered]@{} + $base
        $row += [ordered]@{ CredentialType = 'federated'; CredentialName = [string](Get-Value $f @('name')); KeyId = ''; On = 'app'
            StartUtc = ''; EndUtc = ''; LifetimeDays = ''; CredentialStatus = 'n/a'; Subject = [string](Get-Value $f @('subject')) }
        $rows.Add([pscustomobject]$row)
    }
    if (-not $rows.Count) {
        $row = [ordered]@{} + $base
        $row += [ordered]@{ CredentialType = 'none'; CredentialName = ''; KeyId = ''; On = ''; StartUtc = ''; EndUtc = ''; LifetimeDays = ''; CredentialStatus = 'none' }
        $rows.Add([pscustomobject]$row)
    }
    $rows.ToArray()
}
# Uniform columns for Export-Csv (it takes the header from the first row).
$credentialRows = @($credentialRows | Select-Object Source, ObjectId, Kind, DisplayName, OwnerCount, CredentialType, CredentialName, KeyId, On, StartUtc, EndUtc, LifetimeDays, CredentialStatus,
    @{ Name = 'Subject'; Expression = { if ($_.PSObject.Properties['Subject']) { $_.Subject } else { '' } } })

$inventory = foreach ($rec in $records) {
    $mine = @($findings | Where-Object { ($_.ObjectId -eq $rec.SpObjectId -and $rec.SpObjectId) -or ($_.ObjectId -eq $rec.AppObjectId -and $rec.AppObjectId) })
    $expiries = @(@($rec.Passwords) + @($rec.KeyCreds) | ForEach-Object { ConvertTo-UtcDate (Get-Value $_.Cred @('endDateTime')) } | Where-Object { $_ -and $_ -ge $Now } | Sort-Object)
    $certs = @($rec.KeyCreds | Where-Object { [string](Get-Value $_.Cred @('type')) -ne 'Symmetric' })
    [pscustomobject]@{
        Source                   = $Source
        ObjectId                 = Get-RecordObjectId $rec
        Kind                     = $rec.Kind
        DisplayName              = $rec.DisplayName
        AppId                    = $rec.AppId
        AppObjectId              = $rec.AppObjectId
        SpObjectId               = $rec.SpObjectId
        ManagedIdentityType      = $rec.ManagedIdentityType
        OwnerModel               = $rec.OwnerModel
        AccountableOwner         = $rec.AccountableOwner
        Owners                   = (@($rec.OwnerSummary | ForEach-Object { "$($_.Label)$(if ($_.Enabled -eq $false) { ' (DISABLED)' } elseif ($null -eq $_.Enabled -and $_.Type -eq 'user') { ' (state unknown)' })" }) -join '; ')
        EnabledHumanOwners       = @($rec.OwnerSummary | Where-Object { $_.Type -eq 'user' -and $_.Enabled -eq $true }).Count
        OwnerCount               = Get-OwnerCount $rec
        Sponsors                 = if ($rec.Kind -eq 'AgentIdentity') { if ($null -eq $rec.Sponsors) { 'unknown' } else { $rec.Sponsors } } else { '' }
        SecretCount              = $rec.Passwords.Count
        CertificateCount         = $certs.Count
        FederatedCredentialCount = if ($rec.FicsKnown) { $rec.Fics.Count } else { 'unknown' }
        NextCredentialExpiryUtc  = if ($expiries.Count) { $expiries[0].ToString('o') } else { '' }
        LastSignInUtc            = if (-not $rec.SignInKnown) { 'unknown' } elseif ($rec.LastSignIn) { $rec.LastSignIn.ToString('o') } else { 'never' }
        TierZeroPermissions      = $rec.TierZero -join ', '
        SensitivePermissions     = $rec.Sensitive -join ', '
        PrivilegedRoles          = $rec.Roles -join ', '
        TenantWideDelegated      = $rec.TenantWideScopes -join ' '
        FindingCount             = $mine.Count
        MaxSeverity              = if ($mine.Count) { Get-MaxSeverity $mine } else { '' }
        OwaspIds                 = (@($mine | ForEach-Object OwaspNhi | Sort-Object -Unique) -join ', ')
    }
}
$inventory = @($inventory)
# Non-Entra long-lived secrets (register): rows + findings, merged below.
$secretRows = @()
if ($SecretsRegisterPath) {
    try {
        if (-not (Test-Path -LiteralPath $SecretsRegisterPath -PathType Leaf)) { throw "not found: $SecretsRegisterPath" }
        $sr = Test-SecretsRegister -Register (Get-Content -LiteralPath $SecretsRegisterPath -Raw | ConvertFrom-Json -AsHashtable) -Now $Now
        $secretRows = @($sr.Rows)
        foreach ($f in $sr.Findings) { $findings.Add($f) }
        Add-DataSource 'secretsRegister' 'ok' "$($secretRows.Count) secret(s)"
    }
    catch { Add-DataSource 'secretsRegister' 'FAILED' $_.Exception.Message }
}
$findingRows = @($findings | Sort-Object @{ Expression = { $SeverityRank[$_.Severity] }; Descending = $true }, DisplayName, FindingId)

# OWASP coverage: computed from the catalog, plus the honest gap.
$owaspCoverage = foreach ($k in $OwaspTitles.Keys) {
    $ids = @($Catalog.Keys | Where-Object { $Catalog[$_].Owasp -eq $k } | Sort-Object)
    [pscustomobject]@{
        Owasp       = "${k}:2025"
        Title       = $OwaspTitles[$k]
        FindingIds  = $ids -join ', '
        Findings    = @($findingRows | Where-Object OwaspNhi -eq "${k}:2025").Count
        CoveredHere = [bool]$ids.Count
        Note        = if ($ids.Count) { '' } else { 'Not observable in object inventory: needs sign-in log detection (interactive or unusual-IP service principal sign-ins).' }
    }
}

$orphanIds = 'OWNER-NONE', 'OWNER-NO-HUMAN', 'OWNER-ALL-DISABLED', 'SP-WITHOUT-APP', 'AGENT-NO-SPONSOR'
$summary = [ordered]@{
    nhiCount                    = $inventory.Count
    excludedMicrosoftFirstParty = $excludedFirstParty
    byKind                      = [ordered]@{}
    findingsBySeverity          = [ordered]@{}
    findingsByOwasp             = [ordered]@{}
    kpi                         = [ordered]@{
        orphanedNhi              = @($findingRows | Where-Object FindingId -in $orphanIds | Select-Object -ExpandProperty ObjectId -Unique).Count
        nhiWithExpiredCredential = @($findingRows | Where-Object FindingId -eq 'CRED-EXPIRED' | Select-Object -ExpandProperty ObjectId -Unique).Count
        expiredOrOrphanedNhi     = @($findingRows | Where-Object { $_.FindingId -in $orphanIds -or $_.FindingId -eq 'CRED-EXPIRED' } | Select-Object -ExpandProperty ObjectId -Unique).Count
        nhiWithSecrets           = @($inventory | Where-Object { $_.SecretCount -gt 0 }).Count
        tierZeroNhi              = @($records | Where-Object IsTierZero).Count
        roleOwnedNhi             = @($records | Where-Object { $_.AccountableOwner -and $_.OwnerModel -like 'Register role*' }).Count
        tierZeroWithEntraOwner   = @($findingRows | Where-Object FindingId -eq 'OWNER-TIER0' | Select-Object -ExpandProperty ObjectId -Unique).Count
        staleNhi                 = @($findingRows | Where-Object FindingId -in 'STALE', 'STALE-NEVER' | Select-Object -ExpandProperty ObjectId -Unique).Count
        registeredSecrets        = $secretRows.Count
        secretsWithoutOwnerOrExpiry = @($findingRows | Where-Object FindingId -in 'SECRET-NO-OWNER', 'SECRET-NO-EXPIRY', 'SECRET-EXPIRED' | Select-Object -ExpandProperty ObjectId -Unique).Count
    }
}
foreach ($g in ($inventory | Group-Object Kind | Sort-Object Name)) { $summary.byKind[$g.Name] = $g.Count }
foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $summary.findingsBySeverity[$s] = @($findingRows | Where-Object Severity -eq $s).Count }
foreach ($c in $owaspCoverage) { $summary.findingsByOwasp[$c.Owasp] = $c.Findings }

$result = [pscustomobject]@{
    SchemaVersion  = 1
    GeneratedAtUtc = $Now.ToString('o')
    Source         = $Source
    TenantId       = $tenantId
    Parameters     = [ordered]@{ StaleDays = $StaleDays; ExpiryWarningDays = $ExpiryWarningDays; MaxCredentialLifetimeDays = $MaxCredentialLifetimeDays }
    DataSources    = $dataSources.ToArray()
    Summary        = $summary
    OwaspCoverage  = @($owaspCoverage)
    Inventory      = $inventory
    Findings       = $findingRows
    Credentials    = $credentialRows
    Secrets        = $secretRows
}

Write-Console "`n==== NHI inventory ($Source): $($inventory.Count) identities, $($findingRows.Count) findings ====" -ForegroundColor Cyan
$inventory | Select-Object Kind, DisplayName, EnabledHumanOwners, SecretCount, FederatedCredentialCount, LastSignInUtc, MaxSeverity, OwaspIds |
    Format-Table -AutoSize | Out-Host
Write-Console 'Findings by severity:' -ForegroundColor Cyan
$summary.findingsBySeverity.GetEnumerator() | ForEach-Object { '  {0,-9} {1}' -f $_.Key, $_.Value } | Out-Host
Write-Console 'OWASP NHI Top 10 coverage:' -ForegroundColor Cyan
$owaspCoverage | Select-Object Owasp, Title, Findings, CoveredHere | Format-Table -AutoSize | Out-Host
$top = @($findingRows | Where-Object { $_.Severity -in 'Critical', 'High' })
if ($top.Count) {
    Write-Console "Critical/High findings ($($top.Count)):" -ForegroundColor Yellow
    # Detail and Remediation are in nhi_findings.csv; the console stays scannable.
    $top | Select-Object Severity, DisplayName, FindingId, OwaspNhi, StandardRule | Format-Table -AutoSize | Out-Host
}
Write-Console ("KPI: {0} NHI(s) orphaned or holding an expired credential; {1} Tier-0 NHI(s)." -f $summary.kpi.expiredOrOrphanedNhi, $summary.kpi.tierZeroNhi) -ForegroundColor Cyan

if ($PSCmdlet.ShouldProcess($OutputDirectory, 'write nhi_inventory.csv, nhi_credentials.csv, nhi_findings.csv, nhi_inventory.json')) {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $inventory | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'nhi_inventory.csv') -NoTypeInformation
    $credentialRows | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'nhi_credentials.csv') -NoTypeInformation
    # Always write the findings file, even when empty, so a clean run leaves
    # evidence that it ran (an absent file proves nothing).
    if ($findingRows.Count) { $findingRows | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'nhi_findings.csv') -NoTypeInformation }
    else { Set-Content -LiteralPath (Join-Path $OutputDirectory 'nhi_findings.csv') -Value '"Source","FindingId","Severity"' }
    if ($SecretsRegisterPath) {
        if ($secretRows.Count) { $secretRows | Export-Csv -LiteralPath (Join-Path $OutputDirectory 'nhi_secrets.csv') -NoTypeInformation }
        else { Set-Content -LiteralPath (Join-Path $OutputDirectory 'nhi_secrets.csv') -Value '"Source","Name","System","Store","Owner","ExpiresOn","Rotation","Status","OwaspNhi"' }
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'nhi_inventory.json') -Encoding utf8
    Write-Console "Written to $OutputDirectory" -ForegroundColor DarkGray
}

$failedSources = @($dataSources | Where-Object { $_.Status -like 'FAILED*' })
# Public, counts-only record (-PublicSummaryDirectory). WHY a separate file:
# the CSV/JSON above name every app, owner and object id, so they stay in the
# gitignored lab/evidence/out; this one carries only numbers and the private
# files' hashes, the same split as 08-Measure-KPIs.ps1 (snapshot vs detail)
# and 09-SoD-Report.ps1 (pseudonyms vs sod-detail.json).
if ($PublicSummaryDirectory -and $PSCmdlet.ShouldProcess($PublicSummaryDirectory, 'write the public counts-only NHI summary (+ SHA256SUMS)')) {
    $privateHashes = [ordered]@{}
    # Only the files THIS run wrote: nhi_secrets.csv exists only when the
    # register was read; a copy left by an earlier run must never be tied to
    # these counts.
    $written = @('nhi_inventory.json', 'nhi_inventory.csv', 'nhi_credentials.csv', 'nhi_findings.csv') + @(if ($SecretsRegisterPath) { 'nhi_secrets.csv' })
    foreach ($n in $written) {
        $p = Join-Path $OutputDirectory $n
        if (Test-Path -LiteralPath $p) { $privateHashes[$n] = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    $byFinding = [ordered]@{}
    foreach ($g in ($findingRows | Group-Object FindingId, Severity | Sort-Object Name)) { $byFinding[$g.Name -replace ', ', ' / '] = $g.Count }
    $public = [ordered]@{
        schema          = 'contoso-nhi-summary/1'
        generatedAtUtc  = $Now.ToString('o')
        generator       = 'lab/scripts/powershell/06-NHI-Inventory.ps1'
        source          = $Source
        # false = a data source FAILED: the counts are a floor, not clean.
        complete        = ($failedSources.Count -eq 0)
        parameters      = $result.Parameters
        dataSources     = @($dataSources | ForEach-Object { [ordered]@{ name = $_.Name; status = $_.Status } })
        summary         = $summary
        findingsById    = $byFinding
        owaspCoverage   = @($owaspCoverage | ForEach-Object { [ordered]@{ owasp = $_.Owasp; title = $_.Title; findings = $_.Findings; coveredHere = $_.CoveredHere } })
        privateFiles    = $privateHashes
        note            = 'Counts only. The named rows are in the gitignored lab/evidence/out (nhi_*.csv / nhi_inventory.json); privateFiles holds their SHA-256.'
    }
    $text = $public | ConvertTo-Json -Depth 8
    # Fail closed: any identifier-shaped string stops the write. The private
    # file hashes are 64 hex characters, not GUID-shaped, so they pass.
    $unsafe = @()
    if ($text -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { $unsafe += 'a GUID' }
    if ($text -match '@') { $unsafe += "an '@'" }
    if ($tenantId -and $text.Contains([string]$tenantId)) { $unsafe += 'the tenant id' }
    if ($unsafe.Count) { throw "Public NHI summary would contain $($unsafe -join ', '); nothing public written." }
    $pubDir = Join-Path ([System.IO.Path]::GetFullPath($PublicSummaryDirectory)) $Now.ToString('yyyyMMddTHHmmssZ')
    New-Item -ItemType Directory -Path $pubDir -Force | Out-Null
    $pubFile = Join-Path $pubDir 'nhi-summary.json'
    $text | Set-Content -LiteralPath $pubFile -Encoding utf8NoBOM
    "$((Get-FileHash -LiteralPath $pubFile -Algorithm SHA256).Hash.ToLowerInvariant())  nhi-summary.json" | Set-Content -LiteralPath (Join-Path $pubDir 'SHA256SUMS') -Encoding utf8NoBOM
    Write-Console "Public counts-only summary: $pubFile" -ForegroundColor Cyan
}

if ($failedSources.Count) {
    Write-Console "`n$($failedSources.Count) data source(s) FAILED: $(@($failedSources.Name) -join ', ') -- the inventory is INCOMPLETE, not clean." -ForegroundColor Red
    $result
    exit 1
}
if ($FailOnSeverity -ne 'None') {
    $gate = @($findingRows | Where-Object { $SeverityRank[$_.Severity] -ge $SeverityRank[$FailOnSeverity] })
    if ($gate.Count) {
        Write-Console "$($gate.Count) finding(s) at or above $FailOnSeverity (-FailOnSeverity)." -ForegroundColor Red
        $result
        exit 2
    }
}
return $result
