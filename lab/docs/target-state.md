# Target state — Contoso Health identity platform (lab scenario)

**Status:** Proposed · **Date:** 2026-10-20 · **Scope:** Contoso Health, a
fictional 5,000-user hospital used as this lab's scenario. Not a real
organization.

This maps the platform to the four layers of Microsoft's Enterprise Access
Model (EAM): control plane, management plane, data and workload plane, and
user and app access. For each layer it states the target, what the lab
implements today with file evidence, and the gap to close. The decisions
behind it are in the ADRs (`adr/README.md`).

> **Evidence level (updated 2026-10-31).** The lab now runs in a real Entra tenant: 64 applied changes, nine enforced sign-in policies, a timed leaver (E52), an evidence pack and a zero-drift baseline. The note below is the original 2026-10-21 position, kept for the record: no `terraform apply` had run and no tenant existed yet
> (`lab/terraform/README.md`, Validate status). In the "Lab today" column,
> **BUILT** means code that passes `validate`/`fmt`, mocked `terraform test`,
> Pester or structural checks; **RAN · harness** means it ran end to end in
> a local harness on 2026-10-20 (PAM stand-ins 284/284, the 500-account
> scale run 79/79, midPoint 91/91, dynamic database credentials 60/60,
> Kubernetes on kind 64/64), each with a hashed run record in
> `lab/evidence/` (index: `lab/evidence/README.md`). **RAN · tenant:**
> nothing yet. None of it is tenant evidence until the roadmap's first
> phase runs.

## Scenario baseline (assumed, not measured)

The lab has no "before" state (`lab/docs/STAND-INS.md`, metrics row). The
scenario assumes a typical regional hospital:

- On-premises AD is the source for workforce accounts; HR is Workday or
  SuccessFactors (here a mock: `lab/scripts/mock-hr/`).
- An acquired clinic runs its own Okta tenant (`lab/docs/okta-migration-runbook.md`).
- Admin rights are granted directly and stay granted; leavers depend on tickets.
- Clinicians move between units often, so access piles up.
- SaaS (ServiceNow) and cloud (AWS) access is managed per app.

## Target principles

1. No standing human admin outside two monitored break-glass accounts.
2. HR is the only source of joiner, mover and leaver events.
3. Every identity control change is code, planned on a PR, gated by a human.
4. Tier-0 credentials are vaulted, checked out, recorded and rotated on check-in.
5. Workloads authenticate with short-lived federated tokens, not stored secrets.
6. Every control produces evidence an auditor can verify without screenshots.

## By EAM layer

### 1. Control plane (Tier 0: identity systems and anything that can change them)

| Target | Lab today (evidence) | Gap |
|---|---|---|
| Two cloud-only break-glass accounts, excluded from CA, alerted on every sign-in | `bg-admin-01/02` on `*.onmicrosoft.com`, at least two enforced by validation (`lab/terraform/modules/groups/variables.tf`); excluded on every CA policy (`modules/conditional-access`); threshold-1 alert across interactive and non-interactive sign-ins (`lab/kql/break-glass-signin.kql`); exclusions checked by `lab/scripts/powershell/01-Verify-Baseline.ps1`. BUILT: a guided drill that refuses to start on a failed preflight and writes a dated record (`Invoke-BreakGlassDrill.ps1`) | Lab: one software passkey per account in the operator Mac's Keychain, not hardware keys in safes (runbook, lab deviation); first lab drill 2026-11-05, Pass, incident #42 (`lab/evidence/drills/README.md`). Hardware keys and password rotation stay human steps (`lab/terraform/README.md`, human step 6) |
| Zero standing admin: just-in-time elevation with phishing-resistant step-up, justification, approval, expiry | BUILT (`modules/pim`): every privileged directory role mapped to a Tier-0 or Tier-1 PIM-for-Groups group; approval by an approver group; eligibility that expires (Tier 0 180 days, Tier 1 365 days); no permanent active assignment; notifications to a security mailbox; Global Administrator by direct, expiring eligibility per named admin; the build account converted to eligible; Tier-0 activation tied to auth context `c1` and CA021 (sign-in every time, admin strength); eligibility granted post-HR (`post-apply/Set-PimGroupEligibility.ps1`). Decision: ADR 0020 | `c1` takes effect only once CA021 is enforced. Approval and expiry are policy settings nobody has seen work in a tenant yet (evidence captures E16–E17c, E36b) |
| Conditional Access as code, report-only first, one policy graduated per PR | BUILT: CA001–CA011 (baseline; CA011 is the token-protection pilot, written by a Graph script), CA020–CA023 (admins and PAM; CA021 / CA023 rendered for Graph), CA060 (shared clinical workstations), each report-only behind its own staging flag; `policy_states` validation; mocked tests (`modules/conditional-access/tests/`). Risk-based CA006/CA007 included. **Protected actions:** CA023 puts a step-up on authentication context `c2` (`enable_protected_actions_ca`), report-only | CA021 and CA023 live in Graph, not Terraform: the provider can't target an authentication context, so a post-apply script writes them from bodies Terraform renders. Binding `c2` to the protected actions (CA policy and named-location update and delete) is a tenant-time step, only once CA023 is enforced |
| Change identity for the tenant is gated and cannot widen itself | PLAN/APPLY split; APPLY subject scoped to `environment:prod` (`modules/pipeline-identity/main.tf`); `prod` reviewer gate (`.github/workflows/terraform-apply.yml`); CI identities applied by a human from `envs/bootstrap`; state account ReadOnly lock (`lab/terraform/README.md`, Remote-state bootstrap) | APPLY holds `RoleManagement.ReadWrite.Directory`, so it is effectively Tier 0 (`lab/pipelines/README.md` §5). Accepted for the lab only, time-boxed (ADR 0005, risk register R01); production needs a separate Tier-0 identity |
| Tier-0 AD credentials vaulted and rotated, used only by a named person against an approved change | RAN · harness against a Samba AD DC (`lab/pam/test/e2e.sh`, 284/284; hashed record `lab/evidence/pam/20261020T220031Z/`): discovery, bulk onboarding, dependency-gated rotation and reconciliation; exclusive check-out, rotate-on-check-in; one Guacamole user per operator and a per-check-out Vault token carrying the change number and its approvers; check-out refused without an approved, in-window ServiceNow change assigned to the requester (Table API mock), and for Tier 0 without two distinct approvers, neither the requester (dual control); a recorded RDP session to a Linux xrdp stand-in for DC01; a 3-node Vault cluster with auto-unseal, leader failover and a timed DR drill (ADR 0019; `lab/evidence/pam-dr/`). The same scripts at 500 accounts: GAP 0 (`lab/evidence/pam-scale/20261020T193913Z/`). BUILT: Entra sign-in to the broker behind CA022 (`enable_pam_oidc_app`) | Not run against DC01, Entra or a ServiceNow instance; the RDP stand-in is Linux, not Windows. One DC (`STAND-INS.md`). Production PAM is a SaaS purchase (`vendor-evaluation.md`) |
| Tier-0 admins work from a trusted device, with short admin sessions | CA005 compliant device for admin portals, pilot group only; CA020 sign-in every 4 hours on the admin portals for Tier-0/1 admins (both BUILT, report-only; `modules/conditional-access`, `modules/intune-vm`, `lab/scripts/intune/New-IntuneComplianceBaseline.ps1`) | Pilot scope only; no dedicated privileged access workstation build, so CA021 doesn't require a compliant device yet |

### 2. Management plane (tools that manage workloads: Azure, Intune, pipeline, SIEM)

| Target | Lab today (evidence) | Gap |
|---|---|---|
| Pipeline reads with a read-only identity and holds no stored secret | OIDC federation, no client secret (`lab/pipelines/README.md` §2); PLAN is Reader + Graph read only; SHA-pinned actions, Checkov, TruffleHog (§4) | PLAN can read state, which holds generated passwords (§5). Production keeps state where CI has no role |
| Secrets in a private, least-privilege vault | Key Vault with RBAC, private endpoint, deny-by-default firewall; UAMI ABAC-limited to named secrets (`modules/keyvault`, `tests/uami_abac.tftest.hcl`) | Key Vault ABAC is preview (verify: GA status) |
| Audit trail a PR cannot remove | Entra diagnostics owned by `envs/bootstrap` only (`modules/entra-diagnostics`) | APPLY's subscription Contributor can still delete or cap `loga-idlab` (`envs/bootstrap/main.tf` header) |
| Detections and response on identity signals | BUILT: 24 KQL detections with SPL twins (`lab/kql/`, `lab/splunk/detections/`; list and mapping in `threat-model.md`), deployed as Sentinel rules or LA alerts by `modules/monitoring`; notify playbook to Teams and ServiceNow (`lab/monitoring/playbook-notify.json`); a containment playbook that asks a listed approver (never the subject) in Teams, then revokes sessions, confirms the user compromised and disables a cloud-only account, or flags a synced one for disable in AD by `Invoke-AdContainment.ps1`; no answer in 4 hours means no action (`lab/monitoring/playbook-contain.json`, ADR 0017) | 17 rules are scheduled in Sentinel (E15, E15b); 5 held back in `itdr_exclude_rules`. No rule yet for APPLY used outside a workflow, or for bulk HR attribute changes. For an AD-synced account, containment only flags it: until someone disables it in AD and cleans its methods, CA006 can be passed with an attacker-registered method (R03). The playbook's editors and its optional directory role are a takeover path of their own (R16) |
| Azure resource roles just in time | BUILT: PIM for an Azure resource role behind `enable_pim_azure_resources` (`modules/pim/azure.tf`) | One scope and role in the lab; production covers every subscription |

### 3. Data and workload plane (applications, data, workloads)

| Target | Lab today (evidence) | Gap |
|---|---|---|
| App access granted by group from governed packages | `App-*` groups (`modules/groups`) fed by access packages (`modules/entitlement`). BUILT: SAML SSO and SCIM to AWS IAM Identity Center, ServiceNow SAML SSO and provisioning (RAN, capture-log E80-E83) and the Clinical Portal OIDC app with app roles (`modules/apps`) | The Clinical Portal has no real app behind it; staff sign-ins so far are the test users' (AWS E72, ServiceNow E83) |
| Cloud access federated, short-lived, least privilege | AWS IAM Identity Center permission set `ViewOnlyAccess`, PT4H, to the SCIM group (`lab/terraform/aws/`) | Targets the management account by default (documented lab trade-off); production targets a member account |
| Workloads use federated, audience-bound tokens | RAN · harness on a kind cluster (64/64; hashed record `lab/evidence/k8s/20261020T202112Z/`): Vault Kubernetes auth with a 10-minute audience-bound token, no Kubernetes Secret, admission policy pins image digest (`lab/k8s/README.md`, `lab/terraform/k8s/identity`) | AKS mapping is written but never applied (`lab/terraform/k8s/aks-mapping`); stand-in limits in `lab/k8s/README.md` §6 |
| No standing passwords to clinical databases | RAN · harness (60/60, `lab/pam/dynamic-db/`; hashed record in `lab/evidence/dynamic-db/20261020T163436Z/`): Vault issues a new PostgreSQL login per request, named after the requester, SELECT on the `clinical` schema only, 1-hour lease capped at 4 hours; revoking the lease ends live sessions and drops the role; the bootstrap superuser password is nulled | A local stand-in with synthetic data; production uses the secrets product the PAM POC picks |
| Every non-human identity has an owner, an expiry and no password credential | Pipeline and UAMI identities are secretless by design. BUILT: an NHI inventory with OWASP NHI findings (`06-NHI-Inventory.ps1`); an app management policy that rejects secrets on new apps and caps credential lifetimes (`post-apply/Set-AppGovernancePolicy.ps1`); a consent policy with an admin consent workflow (`post-apply/Set-ConsentPolicy.ps1`); an owner hand-off step in `04-Leaver.ps1`; shadow-admin paths (`Find-ShadowAdmins.ps1`). Decision: ADR 0018 | All offline only. Existing secrets stay until rotated (the `midpoint-reader` exception). CA for workload identities needs Workload ID Premium |

### 4. User and app access (workforce, partners, how they reach apps)

| Target | Lab today (evidence) | Gap |
|---|---|---|
| HR-driven joiner, mover, leaver with no manual account creation | API-driven inbound provisioning (`lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1`) → AD → Cloud Sync, with a mass-change guard that stops a run disabling more than 10 accounts; dynamic birthright groups (`modules/groups`); scripts 02–04 (`lab/scripts/powershell/`); Lifecycle Workflows (`post-apply/New-LifecycleWorkflows.ps1`). BUILT: birthright packages assigned by automatic assignment policies from HR attributes, removed 72 hours after someone stops matching, never before the hire date (`post-apply/Set-AutoAssignmentPolicies.ps1`, `lab/iga/birthright-rules.json`) | No daily HR ↔ Entra reconciliation (R10). HR start date isn't yet mapped to `employeeHireDate`, so birthright would match no one until it is (`lab/iga/README.md`) |
| Access expires unless re-approved, at a cadence set by risk (ADR 0012) | BUILT: access packages with approval and 180-day expiry; a review tier per package, with birthright clinical never removed on silence (`modules/entitlement`); T1 privileged review definitions, unanswered = removed (`post-apply/New-AccessReviewDefinitions.ps1`); review KPIs per tier and reviewer (`10-Review-KPIs.ps1`). RAN · harness: a midPoint certification campaign with accept, revoke and no-response outcomes and the revoked access removed (`lab/evidence/midpoint/`) | No Entra review has run; the KPIs have only the stand-in campaign's numbers |
| Separation of duties enforced before access is granted and checked after | BUILT: nine SoD rules (`lab/iga/sod-rules.json`); incompatible packages and groups that never gate a birthright package (`post-apply/Set-IncompatibleAccessPackages.ps1`); a detective report including PIM-eligible holdings (`09-SoD-Report.ps1`); `sod-violation-granted.kql` | SoD inside an application (EHR roles) needs an IGA product (`vendor-evaluation.md` §6) |
| Leaver contained in minutes | `04-Leaver.ps1`: revokes sessions, removes packages, groups and app roles, hands NHI ownership on, provisions on demand | No measured HR-to-disable time yet (roadmap KPI) |
| MFA everywhere, phishing-resistant for admins, then for everyone | RAN · tenant (CA001, CA003, CA004, CA009, CA010 enforced; CA002 report-only; CA008 and CA060 still BUILT behind flags): CA001 MFA all users; CA002 phishing-resistant for admins (the full admin-role list plus the tier groups); CA003 block legacy auth; CA004 block countries; CA008 phishing-resistant for all users, pilot first; CA009 registration only with a one-time TAP or a phishing-resistant method; CA010 block device code flow; CA060 shared clinical workstations; authentication methods policy and rollout tooling (`post-apply/Set-AuthenticationMethodsPolicy.ps1`, `07-Passwordless-Rollout.ps1`). Decisions: ADR 0015 (risk thresholds), ADR 0016 (passkeys, registration), ADR 0014 (shared stations) | Enforcement for all staff is the rollout itself (`passwordless-rollout-plan.md`); no shared clinical station exists in the lab |
| The service desk can't be used to take over an admin | Verification ladder (`runbooks/help-desk-identity-verification.md`). BUILT: help-desk roles scoped to an administrative unit of standard workforce users; `auth-method-changed-by-admin.kql` and `security-info-registered-risky.kql` | A restricted-management AU for VIPs takes its members out of reviews and leaver workflows; that trade-off is open |
| Partners and guests governed | BUILT: connected organization, sponsor approval, 90-day expiry, monthly sponsor review, guest removed with its last assignment (`modules/entitlement/b2b.tf`); guest sprawl report (`05-Reports.ps1`, report 4) | No guest MFA policy; no inactive-guest review (R11) |
| Acquired IdP consolidated without day-one lockout | Phased Okta → Entra runbook with rollback (`lab/docs/okta-migration-runbook.md`) | Not run |

## What "done" looks like

The target is met when each KPI in `roadmap.md` has a measured value from the
tenant, each high residual risk in `risk-register.md` is closed or formally
accepted, and `lab/scripts/powershell/Export-EvidencePack.ps1` produces a
hashed pack that covers every layer above.
