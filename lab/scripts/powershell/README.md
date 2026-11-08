# PowerShell: lifecycle, post-apply Graph steps, reports, drills

Microsoft Graph PowerShell scripts for the Contoso Health lab: the joiner /
mover / leaver follow-through, every tenant setting the Terraform providers
cannot express (`post-apply/`), and the reports, KPIs, drills and evidence
export an auditor asks for.

**Status: BUILT.** On 2026-10-20 the lab Pester suite passed **917 tests, 0
failed, 0 skipped** with every Graph, `az` and Log Analytics call mocked
(`tests/Invoke-LabTests.ps1`, Pester 5.7.1 and 6.2.0), and PSScriptAnalyzer
reported **0 errors** and no warning outside test files (warnings are not
gating). **Scripts 00 to 06, 08 and the evidence and config exports have run against the lab tenant** (RAN · tenant: joiner, mover and leaver runs captured as E30 to E52; KPI snapshot E11b). Passing proves the logic does what the comments say;
whether Graph accepts each call is a tenant-time check, listed in each
script's `.NOTES` as `verify:`.

Scenario contract (names, groups, packages) and the full lifecycle run order:
[`../README.md`](../README.md).

## Safety model

- **Read-only unless asked.** Every script that writes supports `-WhatIf`
  (`SupportsShouldProcess`). Several have a stronger default:
  `Set-AuthenticationMethodsPolicy.ps1` and `Set-TokenProtectionPolicy.ps1`
  only *plan* until `-Apply`; `Invoke-CaRestoreDrill.ps1` writes only with
  `-Mode Restore -Apply`; `Invoke-PostApply.ps1` is a dry run until
  `-Execute`; `07-Passwordless-Rollout.ps1` is read-only unless
  `-IssueTapFor` or `-PromoteReadyToPilot`.
- **No tenant needed to look.** `-OfflinePreview`, `-RenderOnly` and
  `-Offline` print what would be sent, from fixtures, with no connection.
- **Least scope.** Each script asks `Connect-MgGraph` only for the scopes in
  the table below, adds a write scope only in the mode that writes, and
  warns about any scope missing from an existing session instead of
  silently failing. Run `Disconnect-MgGraph` between scripts to reconnect
  with the next one's scopes.
- **A failed read is never "nothing there".** Scripts record failed sources
  and exit non-zero rather than reporting an empty tenant as clean.
- **Evidence is public-safe and hashed.** Committed outputs go to
  `lab/evidence/<area>/` with a SHA-256 file; anything that names people or
  object ids goes to the gitignored `lab/evidence/out/`.

## Scripts

### Lifecycle, reports, KPIs, drills (`./`)

| Script | Purpose | Writes | Safe mode | Graph scopes (delegated) |
|---|---|---|---|---|
| `00-Preflight.ps1` | Tenant-day preflight: local tools and module versions, repo state, then (unless `-Offline`) the current `az` session and Graph connection. Exit 0 ready, 1 ready with warnings, 2 blocked. Never prints a tenant, object id, token, UPN or local path | nothing | read-only; `-Offline` makes no `az` or Graph call | Organization.Read.All |
| `01-Verify-Baseline.ps1` | Proves the Terraform baseline is safe: contract groups, break-glass healthy and holding Global Administrator, break-glass excluded from **every** CA policy; 7 checks, the last ([7/7]) admin passkey coverage. Exit 1 on any FAIL. The gate before every post-apply step | nothing | read-only | Group.Read.All, User.Read.All, RoleManagement.Read.Directory, Policy.Read.All, PrivilegedAssignmentSchedule.Read.AzureADGroup, PrivilegedEligibilitySchedule.Read.AzureADGroup |
| `02-Joiner.ps1` | Day-1 access: licence, birthright group check; verifies the birthright package was Delivered by its automatic policy, and uses `adminAdd` only for a T2 package. Exits 1 with "Joiner INCOMPLETE" if the governed path cannot be delivered | licence, package assignment | `-WhatIf` | User.ReadWrite.All, Organization.Read.All, GroupMember.ReadWrite.All, Group.Read.All, EntitlementManagement.ReadWrite.All, Directory.Read.All |
| `03-Mover.ps1` | Waits for the synced department (HR → AD → Cloud Sync), then verifies that the automatic policies swapped the birthright packages (the old one goes after the 72 h grace period); removes and requests only requestable (T2) packages, as the fallback; writes department only for cloud-only users | package changes | `-WhatIf` | User.ReadWrite.All, EntitlementManagement.ReadWrite.All, Directory.Read.All |
| `04-Leaver.ps1` | Confirms the disable, revokes sessions, removes packages, groups and app assignments, optional SCIM deprovision on demand, hands over the apps and service principals the leaver owned (never a Tier-0 app to a manager), timestamped report | sessions, assignments | `-WhatIf` | User.ReadWrite.All, User.RevokeSessions.All, GroupMember.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Application.Read.All, EntitlementManagement.ReadWrite.All, Directory.Read.All (+ Synchronization.ReadWrite.All with `-ProvisionOnDemandApps`, Application.ReadWrite.All with `-NhiHandoff ReassignToManager`) |
| `05-Reports.ps1` | Stale accounts, users without MFA, standing privileged role holders, guest sprawl (CSV per report) | local CSV | read-only | User.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, Directory.Read.All |
| `06-NHI-Inventory.ps1` | Every non-human identity (apps, service principals, managed identities, Agent ID) against OWASP's NHI Top 10: orphans, secrets, long-lived or expired credentials, insecure federation, Tier-0 permissions. `-PublicSummaryDirectory lab/evidence/nhi` adds a counts-only public record; `-OwnersRegisterPath lab/iga/nhi-owners.json` counts Tier-0 identities owned by a register role as owned and flags any Tier-0 identity with an Entra owner (`OWNER-TIER0`); `-UseAzureCliToken`: app-only, e.g. as the lab operator (`lab/scripts/operator/op pwsh ...`) | `lab/evidence/out/` (named rows), `lab/evidence/nhi/` (counts, hashed) | `-Offline` | Application.Read.All, Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All |
| `Test-SecretExpiry.ps1` | Monthly check (`.github/workflows/secret-expiry.yml`, 1st of the month) of the non-Entra long-lived secrets register `lab/iga/nhi-secrets-register.json`, with the same rules as `06-NHI-Inventory.ps1`: fails on an expired secret, one expiring within 60 days, a missing owner, or a present secret with no date. AWS SCIM token: `lab/docs/runbooks/rotate-aws-scim-token.md` | GitHub step summary | always offline (reads the register file only) | none |
| `07-Passwordless-Rollout.ps1` | Registration status per group, TAP onboarding for named users, go / no-go readiness for enforcing CA008 (`-Stage Pilot` / `Broad`) | TAPs, CA008 pilot membership (only when asked) | read-only by default; `-WhatIf` | User.Read.All, GroupMember.Read.All, AuditLog.Read.All, Policy.Read.All (+ UserAuthenticationMethod.ReadWrite.All with `-IssueTapFor`, GroupMember.ReadWrite.All with `-PromoteReadyToPilot`) |
| `08-Measure-KPIs.ps1` | KPI snapshot (standing admins, phishing-resistant coverage, HR-to-disable minutes, NHI findings, PAM), baseline then after; `-CompareTo` prints deltas. A failed measure is recorded as failed, never 0. `-UseAzureCliToken`: app-only (the lab operator). `-IncludeSecureScore`: Microsoft Secure Score today vs the baseline day of Microsoft's own daily history (`-SecureScoreBaselineDate`, default the oldest record kept), with the controls that moved | `lab/evidence/kpis/` (hashed) | `-WhatIf` | User.Read.All, Group.Read.All, Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.Read.AzureADGroup, Policy.Read.All, AccessReview.Read.All, Application.Read.All; SecurityEvents.Read.All with `-IncludeSecureScore` |
| `09-SoD-Report.ps1` | Detective SoD over `lab/iga/sod-rules.json`: packages, groups (transitive + PIM-eligible), roles (active + eligible), the reviewer of record. Exit code = open violations; 255 = no valid report. `-UseAzureCliToken`: app-only (the lab operator) | `lab/evidence/sod/` (pseudonymised, hashed) | `-WhatIf`, `-InputPath` fixture | EntitlementManagement.Read.All, GroupMember.Read.All, User.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup |
| `10-Review-KPIs.ps1` | Access-review KPIs per ADR 0012 tier and reviewer: completion, revocation, rubber-stamp rate (reviewers with 10+ items), approve-against-recommendation, clinical lockouts | `lab/evidence/kpis/reviews-<UTC>.json` (hashed) | `-WhatIf`, `-InputPath` fixture | AccessReview.Read.All, EntitlementManagement.Read.All, User.Read.All, Group.Read.All |
| `Diagnose-SignIn.ps1` | Help-desk sign-in explainer: paste a correlation id, or a UPN and `-LastHours`, and get a plain-words verdict per sign-in ("Blocked: the sign-in came from a country the hospital does not allow (policy CA004)", "Allowed after MFA", "Allowed, but policy CA002 would have blocked it once enforced"), the facts (every CA policy's result and what it demanded, MFA method, device compliance, location, risk, client app), and "Tell the user:" one sentence; common AADSTS codes in plain words. One object per sign-in to pipe, plus a Markdown report. A failed read is FAILED (exit 1), never "no sign-in" | `lab/evidence/out/sign-in/` (names a person; gitignored) | read-only | AuditLog.Read.All, Directory.Read.All |
| `Find-ShadowAdmins.ps1` | Principals one step from a privileged role: owners of role-assignable groups or Tier-0 apps, app admins who can add a credential to a Tier-0 app, workloads whose Graph permissions amount to directory write, PIM-eligible paths | `lab/evidence/out/` | `-Offline`; `-FailOnFinding` (non-zero exit on a finding) | RoleManagement.Read.Directory, Group.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.Read.AzureADGroup, Application.Read.All, Directory.Read.All |
| `Invoke-BaselineAssessment.ps1` | Runs or imports CISA ScubaGear and Microsoft's Zero Trust Assessment (`-Phase before` / `after` / `checkpoint`), hashes every output, maps each ScubaGear MS.AAD policy to the lab control, uploads to the WORM store | `lab/evidence/assessments/` (public-safe summary); raw reports to `lab/evidence/out/` and the evidence store | `-WhatIf`, `-SkipUpload` | Group.Read.All (ScubaGear and the Zero Trust Assessment request their own read scopes) |
| `Invoke-BreakGlassDrill.ps1` | Guided break-glass drill (`-Phase Preflight` / `Verify` / `All`): preflight checks, operator-performed sign-ins, then proof the alert fired, read back from Log Analytics | `lab/evidence/drills/` (only what was observed) | `-WhatIf` | User.Read.All, GroupMember.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All |
| `Invoke-CaRestoreDrill.ps1` | CA restore drill (`-Mode Snapshot` / `Compare` / `Restore`): snapshot every policy, detect drift, restore one, timed | `lab/evidence/out/ca-restore/`; the tenant only with `-Mode Restore -Apply` | read-only by default; `-WhatIf` | Policy.Read.All (+ Policy.ReadWrite.ConditionalAccess to restore) |
| `New-KpiOnePager.ps1` | The one-page KPI view for the CISO (monthly) and the board (quarterly): three headline numbers, every KPI with its direction of travel against an earlier snapshot, and each unmeasured KPI stated as such, never as 0. Reads the newest `08` snapshot (or `-SnapshotPath`), `-CompareTo` for direction; writes `<stamp>-onepager.md` + `.sha256` next to it | `lab/evidence/kpis/` (hashed) | `-WhatIf` | none (reads snapshot files only) |
| `Export-EvidencePack.ps1` | Auditor evidence pack: PIM activation history, access-review decisions, CA inventory, MFA coverage, privileged role assignments, plus the companion evidence above, under one SHA-256 manifest and a control-mapped `SUMMARY.md`. `-UseAzureCliToken`: app-only, as EVIDENCE in `evidence-pack.yml` | `lab/evidence/out/` | `-WhatIf` | RoleManagement.Read.Directory, PrivilegedAssignmentSchedule.Read.AzureADGroup, AccessReview.Read.All, Policy.Read.All, AuditLog.Read.All, Directory.Read.All (app-only: the same six as application roles) |
| `Publish-EvidencePack.ps1` | Files a pack in the WORM evidence store: each file checked against the manifest, uploaded as a new blob under one dated prefix (`--overwrite false`, Entra auth), read back and re-hashed, the store's retention lock recorded; a firewall / permission / sign-in refusal stops at the first file. `-ResultPath` for the summary | the evidence container (new blobs only) | `-WhatIf` | none (Azure Storage data plane: create + read in the evidence container) |
| `Write-EvidencePackSummary.ps1` | The plain-English job summary of `evidence-pack.yml` ("Evidence pack filed — 7 records, each fingerprinted", "nobody can change or delete these files for N days", portal link), technical details folded. Counts only: never a name, UPN or raw Graph error | `$GITHUB_STEP_SUMMARY` | reads two files | none |
| `Export-IdentityConfig.ps1` | Read-only export of the tenant configuration the code owns (CA policies, named locations, authentication strengths and methods policy, PIM policies for directory roles and PIM for Groups, consent / app-management / cross-tenant policies, break-glass exclusion facts) as one normalised, deterministic JSON snapshot; `-Public` hashes every object id and IP range. A section that cannot be read is recorded as `failed`, never as empty (exit 1) | `lab/evidence/config-snapshots/` (hashed, `SHA256SUMS`); without `-Public`, `lab/evidence/out/` only | `-WhatIf`; `-Offline -FixturePath` replays `tests/fixtures/identity-config.fixture.json` | Policy.Read.All, RoleManagementPolicy.Read.Directory, RoleManagementPolicy.Read.AzureADGroup, Group.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory |
| `Compare-IdentityConfig.ps1` | Drift: a snapshot against the committed baseline (`lab/config-baseline/identity-config.json`) and the declared intent in `lab.tfvars` (`ca_policy_states`, `blocked_countries`) plus the break-glass invariants; High / Medium / Low per the exception standard; time-boxed exceptions from `drift-exceptions.json` (expired = reactivated); JSON findings and a GitHub-issue Markdown. Exit 2 High, 1 Medium, 0 otherwise, 3 = unusable input | `-JsonPath`, `-MarkdownPath` (public-safe) | no tenant: two files in | none (reads files only) |

### Post-apply (`post-apply/`): what Terraform cannot express

| Script | Purpose | Safe mode | Graph scopes (delegated) |
|---|---|---|---|
| `Invoke-PostApply.ps1` | Runs every step below that applies, in dependency order, from one `terraform output -json` file (table in the next section) | dry run by default; `-ListOnly` needs no tenant; `-Execute` to change | each step's own |
| `New-AdminAccounts.ps1` | The cloud-only `adm-` admin accounts from `lab/iga/admin-accounts.json`: owner checked against HR (or, for a row with no HR owner such as `adm-presenter`, a sponsor checked as an enabled member user and set through the `sponsors` relationship instead of a manager), no known password (first sign-in is a TAP, then a passkey), no licence or mailbox, manager = the owner; each one (and, with `-BuildAccountUpn`, the build account) put in the standing **Admin-Accounts** group, the admin passkey target. Grants no role or eligibility | `-WhatIf`; `-RenderOnly` needs no tenant | User.ReadWrite.All, GroupMember.ReadWrite.All, RoleManagement.ReadWrite.Directory (membership of a role-assignable group) |
| `Set-AuthenticationMethodsPolicy.ps1` | Passkey profiles (attested device-bound for admins, synced allowed for staff), TAP, Authenticator hardening, registration campaign, gated SMS / voice retirement; break-glass method invariants | PLAN by default; `-Apply`; `-OfflinePreview` | Policy.Read.All, Group.Read.All (+ Policy.ReadWrite.AuthenticationMethod with `-Apply`) |
| `Set-AuthContextPolicies.ps1` | Authentication context `c1` and CA021, which targets it (PIM step-up); run a second time with the protected-actions file, context `c2` and CA023 (step-up before changing CA policies or named locations) | `-WhatIf` | Policy.Read.All, GroupMember.Read.All (+ Policy.ReadWrite.ConditionalAccess when writing) |
| `Set-TokenProtectionPolicy.ps1` | CA011: report-only Token Protection for Exchange, SharePoint and Teams on Windows, CA005 pilot group | PLAN by default; `-Apply`; `-OfflinePreview` | Policy.Read.All, Policy.ReadWrite.ConditionalAccess, Group.Read.All |
| `Set-AutoAssignmentPolicies.ps1` | Birthright access from HR attributes: one automatic assignment policy per birthright package (`lab/iga/birthright-rules.json`). `terraform-apply.yml` runs it after every successful apply, app-only as APPLY (`-UseAzureCliToken`), with plain-English lines for the Apply summary (`-SummaryPath`) | `-WhatIf`; `-RenderOnly` | EntitlementManagement.ReadWrite.All, Group.Read.All, User.Read.All (app-only: APPLY's ReadWrite roles cover them) |
| `Set-IncompatibleAccessPackages.ps1` | Preventive SoD links from `lab/iga/sod-rules.json`, only on requestable packages | `-WhatIf`; `-RenderOnly`; `-Prune` | EntitlementManagement.ReadWrite.All, Group.Read.All |
| `Set-AccessPackageSoD.ps1` | Deprecated: forwards to `Set-IncompatibleAccessPackages.ps1` | as above | — |
| `New-LifecycleWorkflows.ps1` | Joiner (day 1) and leaver (real-time) Lifecycle Workflows, opt-in mover (`-IncludeMover`); `-RunJoinerFor` / `-RunLeaverFor` run one on demand | `-WhatIf`; `-OfflinePreview` | LifecycleWorkflows.ReadWrite.All, EntitlementManagement.Read.All (+ Group.Read.All, User.Read.All when used) |
| `Set-DirectoryRolePimPolicies.ps1` | Global Administrator's PIM policy (rendered by `modules/pim`) and named, expiring eligibility | `-WhatIf` | RoleManagementPolicy.ReadWrite.Directory, RoleEligibilitySchedule.ReadWrite.Directory, User.Read.All, GroupMember.Read.All |
| `Set-PimGroupEligibility.ps1` | Named admin accounts made **eligible** for a PIM group, 180 days Tier 0 / 365 days Tier 1; warns on an approver who is also eligible | `-WhatIf` | PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, Group.Read.All, User.Read.All |
| `New-RestrictedAdminUnit.ps1` | VIP restricted management administrative unit (RMAU-VIP), optionally with named members | `-WhatIf` | AdministrativeUnit.ReadWrite.All, User.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup |
| `New-AccessReviewDefinitions.ps1` | Standalone reviews Terraform renders: privileged (PIM groups, Global Administrator eligibility) and inactive-user; refuses a body that keeps access on silence | `-WhatIf` | AccessReview.ReadWrite.All, Group.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup (+ RoleEligibilitySchedule.Read.Directory for the Global Administrator review) |
| `New-B2BConnectedOrganization.ps1` | The affiliated clinic's connected organization (configured), its internal sponsor, the tenant-wide external-user lifecycle setting | `-WhatIf`; `-SkipTenantSettings` | EntitlementManagement.ReadWrite.All, GroupMember.Read.All |
| `Set-ExternalCollaboration.ps1` | Who may invite guests, what guests can see, no self-service sign-up; reads (never changes) the cross-tenant access default | `-WhatIf`; `-OfflinePreview` | Policy.Read.All, Policy.ReadWrite.Authorization, Policy.ReadWrite.AuthenticationFlows |
| `Set-AppGovernancePolicy.ps1` | Tenant app management policy: no secrets on new apps, 180-day certificate cap, 90-day cap on new secrets for existing apps; backs up the current policy first | `-WhatIf`; `-OfflinePreview` | Policy.Read.All, Policy.ReadWrite.ApplicationConfiguration |
| `Set-ConsentPolicy.ps1` | User consent only to verified publishers and low-impact permissions (or `-UserConsent Disabled`); admin consent workflow reviewed by App-Consent-Reviewers | `-WhatIf`; `-OfflinePreview` | Policy.Read.All, Policy.ReadWrite.Authorization, Policy.ReadWrite.PermissionGrant, Policy.ReadWrite.ConsentRequest, Application.Read.All, Group.Read.All, User.Read.All |
| `New-AgentIdentity.ps1` | A Microsoft Entra Agent ID: blueprint, blueprint principal, managed-identity federated credential (no secret), one agent identity with a human sponsor. Identity only: no permission, nothing calls it yet. Fails closed if the preview API is unavailable | `-WhatIf`; `-OfflinePreview` | AgentIdentityBlueprint.Create, AgentIdentityBlueprint.AddRemoveCreds.All, AgentIdentityBlueprintPrincipal.Create, AgentIdentity.Create.All, Application.Read.All, User.Read.All |
| `Convert-BuildAccountToEligible.ps1` | Last and opt-in: turns the build account's standing Global Administrator into 180-day eligibility after eight checks (break-glass, a second GA path, alerting, the GA policy); asks for the typed UPN | `-WhatIf` | User.Read.All, GroupMember.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, RoleEligibilitySchedule.ReadWrite.Directory, RoleAssignmentSchedule.ReadWrite.Directory |

## Post-apply orchestration (order)

After `terraform apply` of `lab/terraform/envs/dev`:

```powershell
terraform -chdir=lab/terraform/envs/dev output -json > tf-out.json
./post-apply/Invoke-PostApply.ps1 -OutputsPath ./tf-out.json -ListOnly    # the plan, no tenant
./post-apply/Invoke-PostApply.ps1 -OutputsPath ./tf-out.json              # dry run: -WhatIf / PLAN everywhere
./post-apply/Invoke-PostApply.ps1 -OutputsPath ./tf-out.json -Execute `
    -PimEligibility @{ 'privileged-iam-admins' = @('adm-first.last@<tenant>.onmicrosoft.com') }
```

A step whose flag is off has a null Terraform output and is skipped.

| # | Step | Script | Runs when | Why here |
|---|---|---|---|---|
| 1 | baseline (**gate**) | `01-Verify-Baseline.ps1` | `enable_premium` | Every later step changes sign-in; break-glass must provably be excluded from every CA policy. Exit 1 stops everything |
| 1b | admin-accounts | `New-AdminAccounts.ps1` (`lab/iga/admin-accounts.json` → Admin-Accounts) | `enable_premium` | Before 2: the admin passkey profile targets Admin-Accounts, so the `adm-` accounts (and the build account, with `-BuildAccountUpn`) must be in it first; before 9: nobody can be made eligible before their account exists |
| 2 | auth-methods | `Set-AuthenticationMethodsPolicy.ps1` | `enable_premium` | Before anything that needs people to hold passkeys (CA008 pilot, CA021) |
| 3 | auth-context | `Set-AuthContextPolicies.ps1` | `enable_pim_auth_context` | The context and CA021 must exist before PIM requires `c1` (step 8) |
| 3b | protected-actions | `Set-AuthContextPolicies.ps1` (CA023, context `c2`) + a manual bind | `enable_protected_actions_ca` | Writes `c2` and CA023 like step 3. Binding `c2` to CA policy and named-location changes is printed as a manual step, and only once CA023 is enforced (a report-only policy applies no step-up) |
| 4 | token-protection | `Set-TokenProtectionPolicy.ps1` (CA011) | `enable_intune_vm` + premium | Needs the CA005 pilot device |
| 5 | auto-assignment | `Set-AutoAssignmentPolicies.ps1` | `enable_governance` | Before 6: SoD links are never written on a package with an automatic policy |
| 6 | sod | `Set-IncompatibleAccessPackages.ps1` | `enable_governance` | |
| 7 | lifecycle-workflows | `New-LifecycleWorkflows.ps1` | `enable_governance` | |
| 8 | directory-role-pim | `Set-DirectoryRolePimPolicies.ps1` | `enable_global_admin_pim_policy` | Before 12: the first privileged review should see the eligible members |
| 9 | pim-eligibility | `Set-PimGroupEligibility.ps1` (per group) | `-PimEligibility` given | Same reason; needs HR-provisioned people |
| 10 | helpdesk-au | manual Graph PATCH (dynamic AU rule, Terraform output) | `enable_helpdesk_au_scoping` | |
| 11 | restricted-au | `New-RestrictedAdminUnit.ps1` (RMAU-VIP) | `enable_helpdesk_au_scoping` + `-VipUserPrincipalNames` | |
| 12 | access-reviews | `New-AccessReviewDefinitions.ps1` | `enable_access_reviews_privileged` / `_inactive` | Its self-review guard reads PIM eligibility |
| 13 | b2b | `New-B2BConnectedOrganization.ps1` | `enable_b2b_governance` | Before 14: the one open guest path must exist before the lock-down |
| 14 | external-collab | `Set-ExternalCollaboration.ps1` | `enable_b2b_governance` | |
| 15 | aws-saml-cert | manual command from Terraform output | `enable_sso_apps` | Before 16: the certificate cap must not block the gallery app's signing certificate (verify:) |
| 16 | app-governance | `Set-AppGovernancePolicy.ps1` | `enable_nhi_governance` | |
| 17 | consent | `Set-ConsentPolicy.ps1` | `enable_nhi_governance` | Needs App-Consent-Reviewers (Terraform) |
| 18 | agent-identity | `New-AgentIdentity.ps1` | `enable_agent_identity` | |
| 19 | build-account (**last**) | `Convert-BuildAccountToEligible.ps1` | `enable_global_admin_pim_policy` + `-BuildAccountUpn`, and only if no earlier step failed | Removes the last standing human Global Administrator, so everything needing GA runs first |
| 20 | manual hand-offs | containment playbook, vault feed, evidence-store writer grant, guacamole-psm client id | their flags | Grants CI must never make (`lab/terraform/README.md`, human step 15) |

## Lifecycle order (with HR)

1. HR provisioning of at least the Information Technology rows
   (`../mock-hr/`, managers first): they own the `adm-` accounts, and
   `New-AdminAccounts.ps1` fails any row whose owner does not exist yet.
   Then steps 1-7 above, the rest of HR provisioning, and
   `Set-PimGroupEligibility.ps1` for the named admin accounts.
2. Joiner: `02-Joiner.ps1`, or with Governance the joiner workflow
   (`New-LifecycleWorkflows.ps1 -RunJoinerFor`).
3. Mover: edit the row in `hr_feed.csv`, re-run inbound provisioning, then
   `03-Mover.ps1`.
4. Leaver: set the row to `leaver`, run inbound provisioning, then
   `04-Leaver.ps1` (or the leaver workflow).
5. Reports and evidence: `05-Reports.ps1`, `09-SoD-Report.ps1`,
   `Export-EvidencePack.ps1`.

For the trial window (baselines before premium configuration, KPIs before and
after, drills), follow [`../../docs/evidence-capture-plan.md`](../../docs/evidence-capture-plan.md):
`Invoke-BaselineAssessment.ps1 -Phase before` and `08-Measure-KPIs.ps1 -Label
baseline` come first; `Invoke-BreakGlassDrill.ps1`, the `after` phase and
`Export-EvidencePack.ps1` come last.

## Configuration drift: export, compare, nightly reconcile

The lab's control plane (Conditional Access, PIM policies, authentication
methods, consent and app-management policies, cross-tenant defaults, the
break-glass exclusions) is code. Two scripts close the loop between that
code and the tenant, next to the real-time detections:

| Layer | What | When | Where |
|---|---|---|---|
| Real-time detection | A change as it is made: policy disabled or moved to report-only, an exclusion added, a named location or strength weakened, an admin changing someone's MFA, a role assigned outside PIM | minutes, Sentinel / Log Analytics | [`../../kql/ca-policy-changed.kql`](../../kql/ca-policy-changed.kql), `auth-method-changed-by-admin.kql`, `role-assigned-outside-pim.kql`, `pim-group-member-added-outside-pim.kql` |
| Nightly reconcile | The tenant as it is against the tenant as the code says: `Export-IdentityConfig.ps1 -Public`, then `Compare-IdentityConfig.ps1` against the committed baseline and `lab.tfvars`; a classified finding opens or updates one `identity-drift` issue | nightly and on demand, CI with the read-only PLAN identity | [`.github/workflows/config-drift.yml`](../../../.github/workflows/config-drift.yml), [`../../config-baseline/`](../../config-baseline/) |
| Exceptions with expiry | An accepted difference has an id, an owner, an approver and an expiry (90 days High, 180 Medium / Low); the day after it expires the finding is open again; a malformed entry is ignored, never honoured | per finding | [`../../config-baseline/drift-exceptions.json`](../../config-baseline/drift-exceptions.json), [`../../docs/standards/exception-process.md`](../../docs/standards/exception-process.md) |

Why both: a detection can be missed (a rule not yet deployed, an outage, a
Microsoft-managed edit, an alert nobody acted on). The reconcile cannot be
silenced by a missed alert, and a read that fails is a finding
("unknown, not absent"), never silence. Remediation is a pull request: the
code is the source of truth, so a finding is either a change that skipped
review, or a baseline nobody updated after one.

Run it without a tenant:

```powershell
./Export-IdentityConfig.ps1 -Offline -OutputDirectory ../../evidence/out/config-snapshots   # the committed fixture, hashed ids
./Compare-IdentityConfig.ps1 -SnapshotPath ../../evidence/out/config-snapshots/<UTC>.json -MarkdownPath ../../evidence/out/drift.md
```

Against the placeholder baseline the compare reports "no baseline yet"
and still runs the intent and break-glass checks. Committing the first
baseline is a tenant-time step ([`../../config-baseline/README.md`](../../config-baseline/README.md),
exception E59). **BUILT, not run**: neither script has read a tenant, and
the workflow has never run.

## Tests

```powershell
pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1        # PSScriptAnalyzer (errors fail) + every Pester suite
pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1 -CI    # also writes out/testResults.xml (gitignored)
```

36 test files in `tests/`, one per script or area (`Reset-DemoState.Tests.ps1`
covers [`../demo/`](../demo/)). Two are shared:
`PostApply.Tests.ps1` checks `Invoke-PostApply.ps1`'s order and the real
scripts' parameter contracts, and is the only coverage of
`New-B2BConnectedOrganization.ps1`; `NhiGovernance.Tests.ps1` covers 06,
`Find-ShadowAdmins`, the app and consent policies, Agent ID and the leaver
hand-off. The Graph modules are
loaded only so Pester mocks copy the real cmdlet signatures: a call with a
wrong parameter name fails a test. `Invoke-BaselineAssessment.Tests.ps1`
needs CISA's ScubaGear sample (`tests/fixtures/Get-ScubaSample.ps1`,
SHA-256 pinned); without it those blocks are skipped, not passed.
`Scale20k.Tests.ps1` is the scale evidence (karen-review I2): a mocked
20,000-user tenant served in 21 pages of 999, with one page throttled (HTTP
429, Retry-After). The Graph readers of 06, 08 and 09 must return exactly
20,000 objects, wait the seconds Graph asks for, and throw rather than return
a partial list when the throttle outlasts 5 retries. It found one gap: the
scripts relied only on the Graph SDK's own retry, so a throttle that outlived
it failed the whole read. `Invoke-GraphGetWithRetry` and
`Get-GraphThrottleDelay` now add a bounded retry; they are parity-tested
copies in 06, 08, 09, 10 and the two lab/iga post-apply scripts. It proves
the paging and retry logic, not Graph's real limits.
`.github/workflows/lab-tests.yml` runs the same suite on every pull request
with no credential (configured; not run yet).

Write-Host is how these scripts talk to the person running them (colour,
`-NoNewline`), so `PSAvoidUsingWriteHost` is suppressed - per function, with
a justification, never per file: script-level status lines go through each
script's `Write-Console` wrapper (`Write-Host @args`, so the output is
unchanged), and a function that writes to the console carries the attribute
on its own param block. `ScriptAnalyzerScope.Tests.ps1` refuses a file-level
suppression, an unjustified one, and a script-level `Write-Host`.

Last run, 2026-10-20 21:43 UTC (author's machine, working tree, Pester 6.2.0
and again with CI's pin 5.7.1): 917 passed, 0 failed, 0 skipped;
PSScriptAnalyzer 0 errors, 19 warnings - all `PSReviewUnusedParameter` on
mock stubs in `NhiGovernance.Tests.ps1` that mirror real cmdlet parameters
(was 480, 453 of them outside test files).

## Neighbours

- [`../mock-hr/`](../mock-hr/): the HR feed and API-driven inbound
  provisioning (the Workday stand-in).
- [`../dc/`](../dc/): DC01 promotion and domain configuration.
- [`../intune/`](../intune/): the CA005 compliant-device baseline.
- [`../monitoring/`](../monitoring/): playbook deployment, AD containment,
  the Vault audit feed, and the ITDR Pester suite.
- [`../demo/`](../demo/): demo-state reset.
