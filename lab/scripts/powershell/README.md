# PowerShell: lifecycle, post-apply Graph steps, reports, drills

Microsoft Graph PowerShell scripts for the Contoso Health lab: the joiner /
mover / leaver follow-through, every tenant setting the Terraform providers
cannot express (`post-apply/`), and the reports, KPIs, drills and evidence
export an auditor asks for.

**Status: BUILT.** On 2026-10-21 the lab Pester suite passed **1074 tests, 0
failed, 0 skipped** with every Graph, `az` and Log Analytics call mocked
(`tests/Invoke-LabTests.ps1`, Pester 5.7.1 and 6.2.0; hashed record
[`offline-tests/20261021T074732Z`](../../evidence/offline-tests/20261021T074732Z/README.md)),
and PSScriptAnalyzer reported **0 errors** and no warning outside test files
(warnings are not gating). **No script has run against a tenant**
(RAN · tenant: nothing). Passing proves the logic does what the comments say;
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
| `06-NHI-Inventory.ps1` | Every non-human identity (apps, service principals, managed identities, Agent ID) against OWASP's NHI Top 10: orphans, secrets, long-lived or expired credentials, insecure federation, Tier-0 permissions | `lab/evidence/out/` | `-Offline` | Application.Read.All, Directory.Read.All, RoleManagement.Read.Directory, AuditLog.Read.All |
| `07-Passwordless-Rollout.ps1` | Registration status per group, TAP onboarding for named users, go / no-go readiness for enforcing CA008 (`-Stage Pilot` / `Broad`) | TAPs, CA008 pilot membership (only when asked) | read-only by default; `-WhatIf` | User.Read.All, GroupMember.Read.All, AuditLog.Read.All, Policy.Read.All (+ UserAuthenticationMethod.ReadWrite.All with `-IssueTapFor`, GroupMember.ReadWrite.All with `-PromoteReadyToPilot`) |
| `08-Measure-KPIs.ps1` | KPI snapshot (standing admins, phishing-resistant coverage, HR-to-disable minutes, NHI findings, PAM), baseline then after; `-CompareTo` prints deltas. A failed measure is recorded as failed, never 0 | `lab/evidence/kpis/` (hashed) | `-WhatIf` | User.Read.All, Group.Read.All, Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.Read.AzureADGroup, Policy.Read.All, AccessReview.Read.All, Application.Read.All |
| `09-SoD-Report.ps1` | Detective SoD over `lab/iga/sod-rules.json`: packages, groups (transitive + PIM-eligible), roles (active + eligible), the reviewer of record. Exit code = open violations; 255 = no valid report | `lab/evidence/sod/` (pseudonymised, hashed) | `-WhatIf`, `-InputPath` fixture | EntitlementManagement.Read.All, GroupMember.Read.All, User.Read.All, RoleManagement.Read.Directory, PrivilegedEligibilitySchedule.Read.AzureADGroup |
| `10-Review-KPIs.ps1` | Access-review KPIs per ADR 0012 tier and reviewer: completion, revocation, rubber-stamp rate (reviewers with 10+ items), approve-against-recommendation, clinical lockouts | `lab/evidence/kpis/reviews-<UTC>.json` (hashed) | `-WhatIf`, `-InputPath` fixture | AccessReview.Read.All, EntitlementManagement.Read.All, User.Read.All, Group.Read.All |
| `Find-ShadowAdmins.ps1` | Principals one step from a privileged role: owners of role-assignable groups or Tier-0 apps, app admins who can add a credential to a Tier-0 app, workloads whose Graph permissions amount to directory write, PIM-eligible paths | `lab/evidence/out/` | `-Offline`; `-FailOnFinding` (non-zero exit on a finding) | RoleManagement.Read.Directory, Group.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup, PrivilegedAssignmentSchedule.Read.AzureADGroup, Application.Read.All, Directory.Read.All |
| `Invoke-BaselineAssessment.ps1` | Runs or imports CISA ScubaGear and Microsoft's Zero Trust Assessment (`-Phase before` / `after` / `checkpoint`), hashes every output, maps each ScubaGear MS.AAD policy to the lab control, uploads to the WORM store | `lab/evidence/assessments/` (public-safe summary); raw reports to `lab/evidence/out/` and the evidence store | `-WhatIf`, `-SkipUpload` | Group.Read.All (ScubaGear and the Zero Trust Assessment request their own read scopes) |
| `Invoke-BreakGlassDrill.ps1` | Guided break-glass drill (`-Phase Preflight` / `Verify` / `All`): preflight checks, operator-performed sign-ins, then proof the alert fired, read back from Log Analytics | `lab/evidence/drills/` (only what was observed) | `-WhatIf` | User.Read.All, GroupMember.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All |
| `Invoke-CaRestoreDrill.ps1` | CA restore drill (`-Mode Snapshot` / `Compare` / `Restore`): snapshot every policy, detect drift, restore one, timed | `lab/evidence/out/ca-restore/`; the tenant only with `-Mode Restore -Apply` | read-only by default; `-WhatIf` | Policy.Read.All (+ Policy.ReadWrite.ConditionalAccess to restore) |
| `Export-EvidencePack.ps1` | Auditor evidence pack: PIM activation history, access-review decisions, CA inventory, MFA coverage, privileged role assignments, plus the companion evidence above, under one SHA-256 manifest and a control-mapped `SUMMARY.md` | `lab/evidence/out/` | `-WhatIf` | RoleManagement.Read.Directory, PrivilegedAssignmentSchedule.Read.AzureADGroup, AccessReview.Read.All, Policy.Read.All, AuditLog.Read.All, Directory.Read.All |

### Post-apply (`post-apply/`): what Terraform cannot express

| Script | Purpose | Safe mode | Graph scopes (delegated) |
|---|---|---|---|
| `Invoke-PostApply.ps1` | Runs every step below that applies, in dependency order, from one `terraform output -json` file (table in the next section) | dry run by default; `-ListOnly` needs no tenant; `-Execute` to change | each step's own |
| `New-AdminAccounts.ps1` | The cloud-only `adm-` admin accounts from `lab/iga/admin-accounts.json`: owner checked against HR, no known password (first sign-in is a TAP, then a passkey), no licence or mailbox, manager = the owner; each one (and, with `-BuildAccountUpn`, the build account) put in the standing **Admin-Accounts** group, the admin passkey target. Grants no role or eligibility | `-WhatIf`; `-RenderOnly` needs no tenant | User.ReadWrite.All, GroupMember.ReadWrite.All, RoleManagement.ReadWrite.Directory (membership of a role-assignable group) |
| `Set-AuthenticationMethodsPolicy.ps1` | Passkey profiles (attested device-bound for admins, synced allowed for staff), TAP, Authenticator hardening, registration campaign, gated SMS / voice retirement; break-glass method invariants | PLAN by default; `-Apply`; `-OfflinePreview` | Policy.Read.All, Group.Read.All (+ Policy.ReadWrite.AuthenticationMethod with `-Apply`) |
| `Set-AuthContextPolicies.ps1` | Authentication context `c1` and CA021, which targets it (PIM step-up); run a second time with the protected-actions file, context `c2` and CA023 (step-up before changing CA policies or named locations) | `-WhatIf` | Policy.Read.All, GroupMember.Read.All (+ Policy.ReadWrite.ConditionalAccess when writing) |
| `Set-TokenProtectionPolicy.ps1` | CA011: report-only Token Protection for Exchange, SharePoint and Teams on Windows, CA005 pilot group | PLAN by default; `-Apply`; `-OfflinePreview` | Policy.Read.All, Policy.ReadWrite.ConditionalAccess, Group.Read.All |
| `Set-AutoAssignmentPolicies.ps1` | Birthright access from HR attributes: one automatic assignment policy per birthright package (`lab/iga/birthright-rules.json`) | `-WhatIf`; `-RenderOnly` | EntitlementManagement.ReadWrite.All, Group.Read.All |
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

## Invoke-LabDay: one command per trial day

`Invoke-LabDay.ps1` walks one day of the 30-day trial window from a plan kept
as data (`evidence/LabDayPlan.psd1`, Days 0-29): `00-Preflight.ps1` first,
then each step in order. A tenant change always goes through the script that
owns it (its dry run, then your yes, then the script's own confirmations); a
portal step pauses with the exact console path; wherever an API can read the
result, read-only captures (Graph GET, Log Analytics queries, ARM reads, the
pipeline's own run logs) go to `lab/evidence/tenant/<UTC day>/<evidence id>/`
as private `raw/` exports plus a public-safe `manifest.json`, a `SHA256SUMS`
and a capture-log row. Progress is kept in the gitignored
`out/labday/state.json`: after a failure or a `[q]uit`, the same command
carries on where it stopped. Before the first day, `-NewSettingsFile -Day 0`
writes the settings template (names and ids, never a secret).

```powershell
./Invoke-LabDay.ps1 -Day 2 -WhatIf                   # the whole day, printed: nothing runs, nothing is written
./Invoke-LabDay.ps1 -Day 2                           # run it, in the pwsh session that holds your Graph sign-in
./Invoke-LabDay.ps1 -Day 2 -Step build-account       # one step: a step id, or an evidence id such as E16b
./Invoke-LabDay.ps1 -Day 2 -Step E16b -CaptureOnly   # take that capture again; no step runs
```

**Status: BUILT.** `tests/Invoke-LabDay.Tests.ps1` (151 tests) runs every
day of the plan against stubs generated from the real scripts' param blocks,
with every Graph, `az` and `gh` call mocked. Nothing in it has run against a
tenant (RAN · tenant: nothing yet): each capture recipe's scopes and query
shape are tenant-time checks (`verify:` in `evidence/LabEvidence.Recipes.ps1`).

## Tests

```powershell
pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1        # PSScriptAnalyzer (errors fail) + every Pester suite
pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1 -CI    # also writes out/testResults.xml (gitignored)
```

33 test files in `tests/`, one per script or area (`Reset-DemoState.Tests.ps1`
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
`.github/workflows/lab-tests.yml` runs the same suite on every pull request
with no credential. On GitHub's runners it passed on the published commit,
with 917 tests at that commit
([run](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523030602)).

Write-Host is how these scripts talk to the person running them (colour,
`-NoNewline`), so `PSAvoidUsingWriteHost` is suppressed - per function, with
a justification, never per file: script-level status lines go through each
script's `Write-Console` wrapper (`Write-Host @args`, so the output is
unchanged), and a function that writes to the console carries the attribute
on its own param block. `ScriptAnalyzerScope.Tests.ps1` refuses a file-level
suppression, an unjustified one, and a script-level `Write-Host`.

Last run, 2026-10-21 (hashed record
[`offline-tests/20261021T074732Z`](../../evidence/offline-tests/20261021T074732Z/README.md):
author's machine, a copy of the working tree, CI's pin Pester 5.7.1 and again
with 6.2.0): 1074 passed, 0 failed, 0 skipped;
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
