# Roadmap — rolling the platform out to 5,000 users (lab scenario)

**Status:** Proposed · **Date:** 2026-10-20 · **Scope:** Contoso Health, the
lab's fictional 5,000-user hospital. Day 0 is the day licensing is in place
and the first tenant apply is approved.

Most of the build is already code (BUILT, tested offline) or has run on
local harnesses (RAN · harness, records in `lab/evidence/`); what exists
today is in [`target-state.md`](target-state.md). The phases below are
therefore about **running it**: apply in report-only, capture evidence, then
enforce in waves. Each phase has one KPI, defined here and measured only
after the phase runs. Risks: [`risk-register.md`](risk-register.md).

**Not built yet:** the split APPLY identity and a rule for APPLY used
outside a workflow (R01); daily HR ↔ Entra reconciliation (R10); the
shared-workstation screen-lock profile (ADR 0014); the guest MFA policy;
ServiceNow provisioning.

## Phase 1 · Days 0–90 · Apply in report-only, in the capture order

**Goal:** every control running in the tenant, Tier 0 just in time, and one
piece of evidence per control, without changing what clinicians see.

The order is the trial's capture order (the coverage index in
[`evidence-capture-plan.md`](evidence-capture-plan.md)), with the same
dependencies:

1. **Weeks 0–1:** pipeline trust and the WORM store; licences, the
   ScubaGear and Zero Trust baseline and the KPI baseline; CA001–CA010 and
   CA020 in report-only with break-glass exclusions verified (E01–E13).
2. **Weeks 1–4:** logs to the SIEM and detections enabled as their tables
   fill; PIM tiers, approver groups, expiry and the first activation;
   governance and the HR joiner for one pilot department, Nursing; methods,
   consent and app policies; SSO and SCIM (E15–E25).
3. **Weeks 4–9:** risk simulation and report-only insights; graduation one
   policy per PR (CA003, CA001, CA002, CA007, CA006; then CA021 and the PIM
   switch to `c1`; then CA009, CA010, CA020); access reviews, the SoD test,
   B2B and approval-gated containment; each detection fired once on a test
   account (E26–E48).
4. **Weeks 9–13:** the break-glass drill, PAM on DC01 and the AD plane, the
   CA restore drill and token-protection pilot, mover and leaver, the NHI
   inventory; then measure "after" and hash the evidence pack (E49–E57).

Unlike the 30-day trial, Phase 1 keeps the 14-day report-only rule, covering
nights and a weekend. CA060 waits for Phase 3: it needs stations enrolled
with the `CH-SharedClinical` Autopilot profile and Clinical Operations
sign-off per unit.

**Dependencies:** P1/P2 and Governance licensing; the HRIS owner agrees the
feed contract, including HR start date mapped to `employeeHireDate`; a
non-production tenant for CA rehearsal (R08); the SOC accepts the detection
queue; a Tier-0 approver group with at least two members; a monitored
security mailbox for PIM notifications.

**Risks:** R01, R02, R07 (licence or trial lapse before capture), R12, R14.

**KPI — Standing privileged principals.** Humans who hold a privileged
directory role permanently, directly or as a permanent member of a
role-holding group, break-glass counted apart. Source: `08-Measure-KPIs.ps1`
(`admin_standing_users`, by tier), cross-checked with `05-Reports.ps1`.
Direction: down to zero.

## Phase 2 · Days 90–180 · Enforce and govern

**Goal:** enforcement from the pilot groups to the whole workforce, in
waves, and every department on HR-driven access.

| Work | Status |
|---|---|
| Passwordless phases 1–3 (admins, IT, office staff): CA008 widened by department waves; SMS and voice off once nobody depends on them | BUILT ([passwordless-rollout-plan.md](passwordless-rollout-plan.md)) |
| CA004 and CA005 beyond the pilot; CA022 once the PAM app is in use | BUILT, report-only |
| Birthright for every clinical department; HR job codes replace job titles in the rules | BUILT for titles; job codes DESIGNED |
| Joiner and leaver Lifecycle Workflows for all departments | BUILT |
| Okta coexistence, phases 0–2 | DESIGNED ([okta-migration-runbook.md](okta-migration-runbook.md)) |
| SSO for ServiceNow; ServiceNow provisioning | SAML BUILT (flag off); provisioning DESIGNED |
| Production PAM for Tier-0 AD accounts, chosen by a two-vendor POC whose tests come from the harness | Proposed ([vendor-evaluation.md](vendor-evaluation.md)) |
| Split APPLY: a Tier-0-only pipeline identity with two reviewers; an alert on APPLY outside a workflow | Not built (ADR 0005, option 3) |

**Dependencies:** the Phase 1 KPI measured and near zero; app owners for
ServiceNow; a JML SLA agreed with HR and audit; the help-desk verification
runbook in force before each passwordless wave.

**Risks:** R03, R09, R10 (now that birthright follows HR), R12, R15.

**KPI — Leaver containment time.** Minutes from an HR record changing to
`status = leaver` to the Entra account disabled and sessions revoked, from
provisioning logs and the `revokeSignInSessions` audit event. Median and
slowest 5%; the target is set by the JML SLA.

## Phase 3 · Days 180–365 · Scale and assure

**Goal:** prove the controls keep working, and extend them to partners,
non-human identities and risk signals.

| Work | Status |
|---|---|
| Clinicians: passwordless phase 4 and CA060, one unit at a time with Clinical Operations sign-off and a 5-minute screen lock | CA060 BUILT; the screen-lock profile not built |
| Risk-tiered certification at scale: T1 quarterly, T2 by 180-day expiry, T3 never removed on silence | BUILT (ADR 0012); the stand-in campaign RAN · harness |
| Guests: a guest MFA policy and the inactive-guest review | B2B governance BUILT; the guest policy not built |
| NHI governance as routine: quarterly owner attestation; CA for the Tier-0 service principals | Inventory and policies BUILT; workload CA needs Workload ID Premium |
| Containment widened: which High rules may contain without a human | The approval-gated playbook BUILT |
| Just-in-time credentials for clinical reporting databases | RAN · harness; production through the product the PAM POC picks |
| Okta phase 4 decommission; workload identity on AKS | DESIGNED; the AKS mapping BUILT, never applied |

**Dependencies:** governance licensing for everyone in review scope; app
owners named for every enterprise app; SOC approval for any containment
without approval; Clinical Operations sign-off per unit.

**Risks:** R04, R05, R11, and reviewer fatigue turning into rubber stamps.

**KPI — On-time recertification rate.** Of the items in scope for the
quarter's T1 and T2 reviews, the share with a decision made by a person
before the review closes and, where denied, removed. A default applied to
an unanswered item doesn't count. Source: `10-Review-KPIs.ps1`. Targets
(ADR 0012): T1 100%, T2 ≥ 95%.

## Sequencing rules

- No CA policy is enforced until its report-only impact is reviewed and the
  break-glass exclusion is verified.
- PIM requires `c1` only after CA021 is enforced: while CA021 is
  report-only, PIM keeps its MFA requirement, because its MFA fallback
  doesn't trigger when the context's policy is report-only.
- CA010 is enforced only after admin tooling stops using device-code
  sign-in, or the exception is recorded.
- No phase starts enforcement until the previous phase's KPI has a measured
  value.
- Any change to the CI identities goes through `envs/bootstrap`, by a human,
  never through a PR.
