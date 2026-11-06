# Roadmap — rolling the platform out to 5,000 users (lab scenario)

**Status:** Proposed · **Date:** 2026-10-20 · **Scope:** Contoso Health, the
lab's fictional 5,000-user hospital. Day 0 is the day licensing is in place
and the first tenant apply is approved.

Each phase has one KPI. Only definitions are given here. Values come from the
tenant after each phase runs. Nothing below has been measured yet.
Target state: `target-state.md`. Risks (R01–R16): `risk-register.md`.
Status words: **RAN · harness** = ran in a local harness only (Docker,
kind), **BUILT** = offline-tested code, **DESIGNED** = written down only (as
in `risk-register.md`); **RAN · tenant**: nothing yet. RAN · harness counts
come from the hashed run records of 2026-10-20 in `lab/evidence/` (index:
`lab/evidence/README.md`).

## Before Day 0 · what is already built

Most of the build work this roadmap first planned for Phases 1–3 now exists
as code. The phases below are therefore about **running it**: applying in
report-only, capturing evidence, then enforcing in waves.

| Capability | Status | Evidence |
|---|---|---|
| Pipeline: OIDC PLAN/APPLY split, reviewer gate, CI identities applied by hand | BUILT | `lab/terraform/envs/bootstrap`, `.github/workflows/`, ADR 0004, ADR 0005 |
| Conditional Access: CA001–CA011 (CA011 via Graph script), CA020–CA023 (CA021 / CA023 rendered for Graph) and CA060, each report-only behind its own staging flag (CA021 and CA023 are written through Graph by a post-apply script, because the provider can't target an authentication context; CA011, the token-protection pilot, is a Graph script too) | BUILT | `modules/conditional-access`, `post-apply/Set-AuthContextPolicies.ps1`, `post-apply/Set-TokenProtectionPolicy.ps1`; ADR 0014, ADR 0015, ADR 0016 |
| PIM: every privileged role mapped to Tier 0 or Tier 1, approver groups, eligibility expiry (Tier 0 180 days, Tier 1 365 days), no permanent active, notifications, Global Administrator by direct eligibility, step-up on auth context `c1`; help-desk roles scoped to an administrative unit | BUILT | `modules/pim` (`tiers.tf`, `approvers.tf`, `directory-roles.tf`, `helpdesk.tf`), `post-apply/Set-PimGroupEligibility.ps1`, `post-apply/Set-DirectoryRolePimPolicies.ps1`, `post-apply/Convert-BuildAccountToEligible.ps1`, `post-apply/Set-AuthContextPolicies.ps1`, `post-apply/New-RestrictedAdminUnit.ps1`; ADR 0020 |
| IGA: birthright by automatic assignment, review tier per package (ADR 0012), SoD (preventive and detective), review KPIs | BUILT | `lab/iga/`, `post-apply/Set-AutoAssignmentPolicies.ps1`, `post-apply/Set-IncompatibleAccessPackages.ps1`, `09-SoD-Report.ps1`, `10-Review-KPIs.ps1` |
| Certification campaign in the IGA stand-in | RAN · harness | `lab/pam/midpoint/`, `lab/evidence/midpoint/` (`e2e-midpoint.sh`, 91/91) |
| ITDR: 24 detections; an approval-gated containment playbook | BUILT | `lab/kql/`, `lab/monitoring/playbook-contain.json`, `modules/monitoring`; ADR 0017 |
| PAM stand-ins: discovery to reconciliation, ticket-gated per-person sessions under Tier-0 dual control, recorded SSH and RDP (the RDP target is a Linux xrdp stand-in for DC01), SSH certificates, HA and a timed DR drill; discovery to reconciliation at 500 accounts | RAN · harness | `lab/pam/test/e2e.sh` (284/284; hashed records `lab/evidence/pam/20261020T220031Z/` and `lab/evidence/pam-dr/20261020T220031Z/`); `test/e2e-scale.sh` (79/79; `lab/evidence/pam-scale/20261020T193913Z/`); ADR 0019 |
| Just-in-time database credentials | RAN · harness | `lab/pam/dynamic-db/` (`e2e-dynamic-db.sh`, 60/60; hashed record in `lab/evidence/dynamic-db/20261020T163436Z/`) |
| Kubernetes workload identity | RAN · harness (kind) | `lab/k8s/` (64/64; hashed record `lab/evidence/k8s/20261020T202112Z/`) |
| NHI governance: inventory, app management policy, consent policy, shadow admins | BUILT | `06-NHI-Inventory.ps1`, `post-apply/Set-AppGovernancePolicy.ps1`, `post-apply/Set-ConsentPolicy.ps1`, `Find-ShadowAdmins.ps1`; ADR 0018 |
| Passwordless tooling; B2B guest governance; SSO + SCIM to AWS; CA restore and break-glass drill scripts | BUILT | `post-apply/Set-AuthenticationMethodsPolicy.ps1`, `07-Passwordless-Rollout.ps1`, `modules/entitlement/b2b.tf`, `modules/apps`, `Invoke-CaRestoreDrill.ps1`, `Invoke-BreakGlassDrill.ps1` |
| Evidence: WORM store, hashed evidence pack, KPI snapshots, ScubaGear/Zero Trust before-and-after | BUILT | `modules/evidence-store`, `Export-EvidencePack.ps1`, `08-Measure-KPIs.ps1`, `Invoke-BaselineAssessment.ps1` |

| Configuration drift: nightly read-only reconcile against the committed baseline, `identity-drift` issue, exceptions with expiry | BUILT (placeholder baseline until E59) | `Export-IdentityConfig.ps1`, `Compare-IdentityConfig.ps1`, `.github/workflows/config-drift.yml`, `lab/config-baseline/`; ADR 0021 |
| Okta coexistence for the acquired clinic: Entra as Okta's OIDC IdP, routing rule with fallback, one legacy app | BUILT (Entra side behind `enable_okta_federation`; Okta root human-applied) | `modules/apps/okta.tf`, `lab/terraform/okta/`; ADR 0022; `okta-migration-runbook.md` |
| Executive reporting: the one-page KPI view, the operating model (decision rights, forums, SLAs, what is reported to whom), the tabletop and post-incident report | BUILT (the page); DESIGNED (the model, never operated) | `New-KpiOnePager.ps1`, `standards/iam-operating-model.md`, `runbooks/identity-incident-tabletop.md`, `runbooks/post-incident-report-template.md` |

**Still not built:** the split APPLY identity (ADR 0005, option 3) and a rule
for APPLY used outside a workflow (R01); daily HR ↔ Entra reconciliation
(R10); the shared-workstation screen-lock profile (ADR 0014); the guest MFA
policy (passwordless plan, phase 5); provisioning to ServiceNow (its SAML
SSO is BUILT behind `enable_servicenow_sso`); moving the clinic's second and
later apps off Okta (runbook Phase 2, one PR per app).

## Phase 1 · Days 0–90 · Apply in report-only, in the capture order

**Goal:** every control above running in the tenant, Tier 0 just in time,
and one piece of evidence per control, without changing what clinicians see.

The order is the lab's trial capture order (`evidence-capture-plan.md`). The
30-day trial is this phase compressed, so the same dependencies hold: sign-in
data before Sentinel, report-only data before any graduation, and CA021
enforced before PIM is switched to `c1`. One thing is not compressed here:
Phase 1 keeps the lab's rule of at least 14 days in report-only, covering
nights and a weekend (`runbooks/graduate-a-ca-policy.md`). The trial's
five-to-eleven-day window is a recorded exception for that window only.

| Order | Weeks | Work | Captures |
|---|---|---|---|
| 1 | Before Day 0 | Bootstrap CI identities by hand; lock the state account; prove the federated trust refuses a wrong subject; WORM evidence store | E01–E07 |
| 2 | 1 | Licences; ScubaGear and Zero Trust baseline; KPI baseline | E08–E11 |
| 3 | 1 | CA001–CA010 and CA020 in report-only; break-glass passkeys; exclusions verified | E12–E13 |
| 4 | 1–2 | Entra logs to the SIEM; detections enabled as their tables fill, the second-wave rules last | E15a, E15, E15b, E15c |
| 5 | 2 | PIM tiers, approver groups, expiry, notifications; Global Administrator by direct eligibility and the build account made eligible; help-desk AU; auth context `c1` created and CA021 in report-only; the first activation and its alert | E16–E18 |
| 6 | 2–3 | Governance: packages and review tiers, birthright by automatic assignment, SoD links, Lifecycle Workflows; HR joiner for one pilot department (Nursing) | E19–E20b |
| 7 | 3 | Authentication methods, consent and app management policies | E21 |
| 8 | 3–4 | SSO and SCIM to AWS IAM Identity Center; the Clinical Portal OIDC app | E22–E25 |
| 9 | 4–5 | Risk simulation; report-only insights; device-code check; passwordless pilot | E26–E29, E28b |
| 10 | 5–8 | Graduate one policy per PR: CA003, CA001, CA002, CA007, CA006; then CA021 and the PIM switch to `c1`; then CA009, CA010, CA020 | E30–E38b |
| 11 | 5–9 | Access reviews and review KPIs; the SoD test; B2B; PIM for Azure resources | E32–E34, E39–E39c |
| 12 | 6–9 | Approval-gated containment; each detection fired once on test accounts; help-desk scope test | E40–E48, E46b, E46c |
| 13 | 9–11 | Break-glass drill; PAM on DC01; the AD plane; vault and DC-allowlist rules; CA restore drill; token protection pilot (CA011, report-only); protected actions (CA023 + `c2`, BUILT offline; binding `c2` waits until CA023 is enforced) | E49–E51g |
| 14 | 11–12 | Mover (birthright grace) and leaver; NHI inventory and shadow admins; agent identity | E52–E53c |
| 15 | 12–13 | Measure "after"; hash the evidence pack into the WORM store | E54–E57 |

CA060 (shared clinical workstations) waits for Phase 3: it needs stations
enrolled with the `CH-SharedClinical` Autopilot profile and Clinical
Operations sign-off per unit (ADR 0014).

**Dependencies:** Entra ID P1/P2 and Governance licensing; HRIS owner agrees
the feed contract, including HR start date mapped to `employeeHireDate`
(birthright waits for day one); a non-production tenant for CA rehearsal
(R08); SOC accepts the detection queue; a Tier-0 approver group with at least
two members; a monitored security mailbox for PIM notifications.

**Risks:** R01 (APPLY identity is Tier 0), R02 (break-glass), R07 (licensing
or trial lapse before evidence is captured), R12 (CA lockout), R14
(help-desk social engineering).

**KPI — Standing privileged principals.** Humans who hold a privileged
directory role permanently, directly or as a permanent member of a
role-holding group. Break-glass is counted apart. Source: `08-Measure-KPIs.ps1`
(`admin_standing_users`, split by tier), cross-checked with `05-Reports.ps1`
report 3. Direction: down to zero.

## Phase 2 · Days 90–180 · Enforce and govern

**Goal:** take enforcement from the pilot groups to the whole workforce, in
waves, and move every department onto HR-driven access.

| Work | Status (evidence) |
|---|---|
| Passwordless phases 1–3 (admins, IT, office staff): CA008 widened by department wave groups; SMS and voice turned off once no one depends on them | BUILT: CA008 scope flags (`modules/conditional-access`), `07-Passwordless-Rollout.ps1`, `post-apply/Set-AuthenticationMethodsPolicy.ps1`; sequence in `passwordless-rollout-plan.md` |
| CA004 and CA005 beyond the pilot; CA022 once the PAM app is in use | BUILT, report-only |
| Birthright for every clinical department; HR job codes replace job titles in the rules | BUILT for title rules (`lab/iga/birthright-rules.json`); job codes DESIGNED |
| Joiner and leaver Lifecycle Workflows for all departments | BUILT: `post-apply/New-LifecycleWorkflows.ps1`, `04-Leaver.ps1` |
| Okta coexistence Phases 0–2: Okta trusts Entra, apps move one at a time | Phase 1 BUILT: `modules/apps/okta.tf` (`enable_okta_federation`), `lab/terraform/okta/` (human-applied), ADR 0022; Phase 2 (each app moves) DESIGNED: `lab/docs/okta-migration-runbook.md` |
| SSO and SCIM for ServiceNow | AWS IAM Identity Center is BUILT (`modules/apps`, `lab/terraform/aws/`); ServiceNow SAML SSO and provisioning RAN in the tenant (`modules/apps/servicenow.tf`, `servicenow_provisioning.tf`; capture-log E57, E80-E83) |
| Production PAM for Tier-0 AD accounts | Proposed: SaaS PAM after a two-vendor POC (`vendor-evaluation.md`). The POC acceptance tests come from the local harness (RAN · harness, `lab/pam/test/e2e.sh`): per-person, ticket-gated sessions under dual control, HA failover and a timed DR drill (R06, R09) |
| Split APPLY: a Tier-0-only pipeline identity with two reviewers for role-bearing resources; alert on APPLY used outside a workflow | Not built; ADR 0005 (option 3), R01 |

**Dependencies:** Phase 1 KPI measured and near zero; app owners for
ServiceNow; a JML SLA agreed with HR and audit; the help-desk verification
runbook in force before each passwordless wave.

**Risks:** R03 (token theft), R09 (single DC), R10 (HR feed integrity, now
that birthright follows it), R12 (lockout during enforcement waves), R15
(toxic access as packages spread).

**KPI — Leaver containment time.** Minutes from an HR record changing to
`status = leaver` to the moment the Entra account is disabled and sessions
are revoked. Measured per leaver from provisioning logs and the audit event
for `revokeSignInSessions`. Report the median and the slowest 5%. The target
is set by the JML SLA.

## Phase 3 · Days 180–365 · Scale and assure

**Goal:** prove the controls keep working, and extend them to partners,
non-human identities and risk signals.

| Work | Status (evidence) |
|---|---|
| Clinicians: passwordless phase 4 and CA060 enforced one unit at a time, with Clinical Operations sign-off, stations enrolled with the `CH-SharedClinical` Autopilot profile and a 5-minute screen lock | CA060 BUILT, report-only (`modules/conditional-access`, ADR 0014); the screen-lock profile is not built |
| Risk-tiered certification (ADR 0012) at scale: T1 privileged quarterly, T2 requestable by 180-day expiry, T3 birthright never removed on silence | BUILT: per-tier review settings (`modules/entitlement`), T1 definitions (`post-apply/New-AccessReviewDefinitions.ps1`), KPIs (`10-Review-KPIs.ps1`). The stand-in campaign RAN · harness (`lab/evidence/midpoint/`) |
| Guests: passwordless phase 5 (a guest MFA policy), inactive-guest review | B2B governance BUILT (`modules/entitlement/b2b.tf`); the guest policy is not built |
| NHI governance as routine: quarterly owner attestation; Conditional Access for the Tier-0 service principals | Inventory, app management and consent policies BUILT; the CA for workload identities needs Workload ID Premium |
| Containment widened: decide which High rules may contain without a human approval | Approval-gated playbook BUILT (`lab/monitoring/playbook-contain.json`) |
| Just-in-time credentials for clinical reporting databases | RAN · harness (`lab/pam/dynamic-db/`); in production through the product the PAM POC picks |
| Okta Phase 4 decommission | DESIGNED: `lab/docs/okta-migration-runbook.md` |
| Workload identity on AKS via Entra Workload ID | BUILT, never applied: `lab/terraform/k8s/aks-mapping`; the kind version RAN · harness (64/64) |

**Dependencies:** governance licensing for every user in scope of reviews;
app owners named for every enterprise app; SOC approval for any containment
without approval; Clinical Operations sign-off per unit.

**Risks:** R04 (consent phishing), R05 (orphaned NHI credentials), R11
(stale guests), reviewer fatigue leading to rubber-stamp approvals.

**KPI — On-time recertification rate.** Of the items in scope for the
quarter's T1 and T2 reviews, the percentage with a decision made by a person
before the review closes and, where denied, removed. A default decision
applied to an unanswered item is not counted as reviewed. Source:
`10-Review-KPIs.ps1` (completion per tier), from the review decisions in the
evidence pack (`Export-EvidencePack.ps1`). Targets from ADR 0012: T1 100%,
T2 ≥ 95%.

## Sequencing rules

- No CA policy is enforced until its report-only impact has been reviewed and
  break-glass exclusion is verified (`01-Verify-Baseline.ps1`).
- PIM requires authentication context `c1` only after CA021 is enforced.
  While CA021 is report-only, PIM keeps its MFA requirement: Microsoft Learn
  says PIM's MFA fallback doesn't trigger when the context's policy is in
  report-only.
- CA010 is enforced only after admin tooling stops using device-code sign-in,
  or the exception is recorded (`standards/exception-process.md`).
- No phase starts enforcement work until the previous phase's KPI has a
  measured value.
- Any change to the CI identities goes through `envs/bootstrap`, by a human,
  never through a PR.
