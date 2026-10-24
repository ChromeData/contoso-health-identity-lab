# Target state — Contoso Health identity platform (lab scenario)

**Status:** Proposed · **Date:** 2026-10-20 · **Scope:** Contoso Health, a
fictional 5,000-user hospital. Not a real organization.

The platform mapped to the four layers of Microsoft's Enterprise Access
Model: control plane, management plane, data and workload plane, user and
app access. For each layer: the target, where the lab is today (status word
and one path), and the gap to close. Status words are the repository's:
RAN · tenant (nothing yet), RAN · harness, BUILT, DESIGNED. The decisions
are in the [ADRs](adr/README.md).

Three labels in the tables: `c1` is the Conditional Access authentication
context that asks for a fresh phishing-resistant sign-in before a Tier-0 PIM
role activates (policy CA021). `c2` is the context that asks for the same
step-up before anyone changes a Conditional Access policy or named location
(CA023). R01–R16 are the risk IDs in the [risk register](risk-register.md).

## Scenario baseline (assumed, not measured)

On-premises AD is the source for workforce accounts and HR is Workday or
SuccessFactors (a mock here). An acquired clinic runs its own Okta. Admin
rights are granted directly and stay granted; leavers depend on tickets;
clinicians move between units often, so access piles up; SaaS and cloud
access is managed per app.

## Target principles

1. No standing human admin outside two monitored break-glass accounts.
2. HR is the only source of joiner, mover and leaver events.
3. Every identity control change is code, planned on a PR, gated by a human.
4. Tier-0 credentials are vaulted, checked out, recorded and rotated on
   check-in.
5. No secrets in the delivery pipeline; workloads use short-lived federated
   tokens, and every remaining secret is inventoried with an owner, expiry
   and rotation.
6. Every control produces evidence an auditor can verify without
   screenshots.

## 1. Control plane (Tier 0: identity systems and anything that can change them)

| Target | Lab today | Gap |
|---|---|---|
| Two cloud-only break-glass accounts, excluded from CA, alerted on every sign-in | BUILT: `modules/groups`, `break-glass-signin.kql`, `01-Verify-Baseline.ps1`, a guided drill script (ADR 0003) | Keys and password rotation are human steps; no drill has run |
| Zero standing admin: just-in-time elevation with step-up, justification, approval, expiry | BUILT: `modules/pim`, every privileged role in a Tier-0 or Tier-1 group, Global Administrator by direct expiring eligibility, Tier-0 step-up on `c1` ([ADR 0002](adr/0002-pim-for-groups-vs-direct-role-eligibility.md)) | `c1` takes effect only once CA021 is enforced; approval and expiry not yet seen working in a tenant |
| Conditional Access as code, report-only first, one graduation per PR | BUILT: 16 policies, each behind its own staging flag ([CA design principles](standards/conditional-access-design-principles.md) §1) | CA011, CA021 and CA023 are written by Graph scripts the provider can't express; binding `c2` to protected actions is a tenant-time step |
| The tenant's change identity is gated and can't widen itself | BUILT: PLAN/APPLY split by subject, `prod` reviewer, CI identities applied by a human (ADR 0004) | APPLY is effectively Tier 0: a time-boxed lab acceptance (ADR 0005, R01); production needs a separate Tier-0 identity |
| Tier-0 AD credentials vaulted and rotated, used only by a named person against an approved change | RAN · harness against a Samba DC (`lab/evidence/pam/`): discovery to reconciliation, ticket-gated per-person check-out under dual control, recorded sessions, HA and a timed DR drill; the same scripts at 500 accounts (`lab/evidence/pam-scale/`) | Not run against DC01, Entra or ServiceNow; one DC; production PAM is a SaaS purchase ([vendor-evaluation.md](vendor-evaluation.md)) |
| Tier-0 admins work from a trusted device with short sessions | BUILT, report-only: CA005 (pilot), CA020 | Pilot scope only; no privileged access workstation build |

## 2. Management plane (Azure, Intune, pipeline, SIEM)

| Target | Lab today | Gap |
|---|---|---|
| Pipeline reads with a read-only identity and holds no stored secret | BUILT: OIDC federation, PLAN is Reader + Graph read, pinned actions, Checkov, TruffleHog | PLAN can read state, which holds generated passwords; production keeps state where CI has no role |
| Secrets in a private, least-privilege vault | BUILT: Key Vault with RBAC, private endpoint, ABAC-limited identities (`modules/keyvault`) | Key Vault ABAC is preview |
| An audit trail a PR can't remove | BUILT: Entra diagnostics owned by the human-applied bootstrap root | APPLY's Contributor can still delete or cap the workspace |
| Detection and response on identity signals | BUILT: 22 KQL rules with SPL twins ([threat-model.md](threat-model.md)); all 22 passed their cases on the local Kusto emulator (`lab/evidence/kusto/`); approval-gated containment (ADR 0017) | No rule has run in a workspace. No rule yet for APPLY used outside a workflow or bulk HR changes. For AD-synced accounts containment only flags (R03); the playbook's editors are a takeover path (R16) |
| Azure resource roles just in time | BUILT: PIM for one Azure resource role (`modules/pim/azure.tf`) | Production covers every subscription |

## 3. Data and workload plane

| Target | Lab today | Gap |
|---|---|---|
| App access granted by group from governed packages | BUILT: `App-*` groups fed by access packages; AWS SAML + SCIM, ServiceNow SAML (flag off), the Clinical Portal OIDC app (`modules/apps`) | ServiceNow provisioning is DESIGNED; nobody has signed in through any app |
| Cloud access federated, short-lived, least privilege | BUILT: AWS `ViewOnlyAccess` permission set, PT4H (`lab/terraform/aws/`) | Targets the management account by default; production targets a member account |
| Workloads use federated, audience-bound tokens | RAN · harness on kind, 64/64 (`lab/evidence/k8s/`): Vault Kubernetes auth, no Kubernetes Secret; Conjur policy allow/deny | The AKS mapping is written, never applied |
| No standing passwords to clinical databases | RAN · harness, 60/60 (`lab/evidence/dynamic-db/`): a new PostgreSQL login per request, 1-hour lease, dropped on revoke | Synthetic data; production uses the product the PAM POC picks |
| Every non-human identity has an owner, an expiry and no password credential | BUILT: NHI inventory with the secrets register, app management and consent policies, leaver hand-off (ADR 0018) | Offline only; existing secrets stay until rotated (`midpoint-reader`); CA for workload identities needs Workload ID Premium |

## 4. User and app access

| Target | Lab today | Gap |
|---|---|---|
| HR-driven joiner, mover, leaver with no manual account creation | BUILT: API-driven provisioning → AD with a mass-change guard (Cloud Sync on to Entra is DESIGNED, ADR 0001); birthright by automatic assignment, 72-hour mover grace, never before the hire date (ADR 0006, ADR 0012) | No daily HR ↔ Entra reconciliation (R10); HR start date not yet mapped to `employeeHireDate` |
| Access expires unless re-approved, at a cadence set by risk | BUILT: per-package review tiers and KPIs (ADR 0012). RAN · harness: a midPoint campaign (`lab/evidence/midpoint/`) | No Entra review has run |
| Separation of duties enforced before grant and checked after | BUILT: nine SoD rules, preventive and detective | SoD inside an application needs an IGA product ([vendor-evaluation.md](vendor-evaluation.md) §6) |
| Leaver contained in minutes | BUILT: `04-Leaver.ps1` revokes sessions and removes access | No measured HR-to-disable time yet |
| MFA everywhere, phishing-resistant for admins, then everyone | BUILT, report-only: CA001–CA003, CA008–CA010, CA060 and the methods policy (ADR 0014, 0015, 0016) | Enforcement for all staff is the rollout itself ([passwordless-rollout-plan.md](passwordless-rollout-plan.md)) |
| The service desk can't be used to take over an admin | BUILT: help-desk roles scoped to an AU of standard users; verification ladder | The VIP restricted AU takes its members out of reviews and leaver workflows |
| Partners and guests governed | BUILT: connected organization, sponsor approval, 90-day expiry (`modules/entitlement/b2b.tf`) | No guest MFA policy; no inactive-guest review (R11) |
| Acquired IdP consolidated without day-one lockout | DESIGNED: [okta-migration-runbook.md](okta-migration-runbook.md) | Not run |

## What "done" looks like

Each KPI in [`roadmap.md`](roadmap.md) has a measured value from the tenant,
each high residual risk in [`risk-register.md`](risk-register.md) is closed
or formally accepted, and `Export-EvidencePack.ps1` produces a hashed pack
that covers every layer above.
