# Conditional Access Design Principles

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario): Entra ID tenant |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. The CISO approves changes to policy that's being enforced |
| Implementation | `lab/terraform/modules/conditional-access`, states in `lab/terraform/envs/dev/lab.tfvars` |

## 1. Persona-based targeting

Policies target **personas** (who) crossed with **apps** (what), not individual
people. Each persona is a group or a role set, and each one has an owner.

| Persona | Defined by | Lab coverage |
|---|---|---|
| All workforce | All users, minus break-glass | CA001, CA003, CA004. Behind staging flags: CA006 and CA007 (risk, ADR 0015), CA008 (phishing-resistant rollout) and CA009 (security-info registration, both ADR 0016), CA010 (device code flow) |
| Admins | The directory roles in `admin_role_template_ids` (Microsoft's template list plus the lab's tier extras) and the admin groups in `admin_scope_group_object_ids` | CA002; CA005 (pilot group only). Behind staging flags: CA020 (admin-portal sign-in frequency), CA021 (PIM activation step-up, Graph-managed, ADR 0020), CA022 (PAM session broker and admin portals) |
| Clinicians on shared workstations | Device filter (`enrollmentProfileName`) plus the clinical groups | CA060 (ADR 0014), behind a staging flag. Code only: no such device exists in the lab |
| Guests and external clinicians | `userType` / connected organization | **No guest-specific policy.** The All-users policies cover guests, except CA006, CA008, CA009 and CA022, which exclude them on purpose (each says why) |
| Workload identities | Service principals | **Not built**. Needs Workload ID Premium (verify) |
| Emergency access | `Break-Glass-Admins` | Excluded everywhere (§3) |

**Clinical availability rule.** A policy that can block sign-in for clinical
staff needs the Clinical Operations sign-off ([raci.md](raci.md)) before
enforcement, and it needs a documented fallback (for example, a TAP from the
service desk). Locking a nurse out of the EHR during a shift is a patient-safety
event, not just an IT incident.

## 2. Report-only first, and one graduation per PR

- Every new policy starts as `enabledForReportingButNotEnforced`. The module
  enforces this through `policy_states` validation: a missing key, unknown key
  or invalid state fails the plan (`modules/conditional-access/variables.tf`).
- The minimum report-only window is **14 days**, covering at least one weekend
  and night-shift cycle. Graduate only when the Report-only results show no
  unplanned failures for a clinical persona. Graduating sooner inside the
  lab's 30-day trial is exception E9 ([exception-process.md](exception-process.md)).
- **One policy changes state per PR.** The PR includes the plan comment, the
  report-only evidence (a query or a workbook screenshot) and a rollback line
  (flip back to report-only).
- In the lab, 9 of 11 policies are **graduated** (E30, under exception E9), with
  the report-only counts in each PR body; CA002 and CA021 stay report-only
  until passkeys exist.

## 3. Exclusions are governed

- The **only** standing exclusion is `Break-Glass-Admins`, applied as a group
  on every policy (`excluded_groups` in each `azuread_conditional_access_policy`).
  `01-Verify-Baseline.ps1` proves it.
- Any other exclusion goes through the [exception process](exception-process.md).
  It must use a dedicated group named `CA0NN-Exclusion-<reason>`, carry an
  expiry and an owner, and be reviewed monthly. Never exclude individual users
  inline.
- Pipeline identities aren't users, so user-targeted policies don't apply to
  them. That isn't an exclusion, but it is a coverage gap (see the NHI standard).

## 4. Naming

`CA0NN - <Require|Block> <control> for <persona>[ (<scope>)]`

- Numbers are permanent and never reused. A retired policy keeps its number in
  the change log.
- Number ranges: 001–019 baseline (all users); 020–039 admins and privileged
  access; 040–059 risk-based; 060–079 clinical and device; 080–099 guests and
  workload identities. The lab's CA001–CA008 predate these ranges and keep
  their numbers, including the two risk policies, CA006 and CA007.
- The lab's policies after the ranges: CA009, CA010 and CA011 (baseline;
  CA011 is the token-protection pilot, Graph-managed by
  `Set-TokenProtectionPolicy.ps1`, in the baseline range because it targets
  all-user session resources), CA020, CA021, CA022 and CA023 (admins; CA023
  is the protected-actions step-up, rendered for
  `Set-AuthContextPolicies.ps1`), CA060 (clinical). CA022 was numbered CA009 in
  code before the ranges existed. It had never reached a tenant, so it
  moved once, before first use; from now on a number that has been applied
  never moves.
- Lab examples: `CA001 - Require MFA for all users`,
  `CA005 - Require compliant device for admin portals (pilot)`. The prefix is
  `policy_name_prefix` in `modules/conditional-access/variables.tf`.

## 5. Change control and detection

- CA changes **only** through code: PR, plan, then `prod` reviewer, then apply
  (`lab/pipelines/README.md`). The APPLY identity is the only writer.
- A portal edit counts as drift. The next apply reverts it, and the plan log
  shows it.
- A CA create, update or delete made by anything **other** than the APPLY
  identity must alert the SOC. `ca-policy-changed.kql` does this: High for a
  weakening change (a policy deleted, disabled, moved to report-only or given
  new exclusions; a named location or authentication strength weakened),
  Medium for other drift, Low for the APPLY identity, matched by immutable
  ID. `modules/monitoring` deploys it; it has not fired in a tenant.
- Three policies are written by post-apply Graph scripts instead of the
  provider. CA021 and CA023 (the provider can't target an authentication
  context): Terraform renders their bodies, so the PR still carries the
  change. CA011, the token-protection pilot (`Set-TokenProtectionPolicy.ps1`,
  no provider support): the script holds the desired state and shows drift
  on every run.

## 6. Design rules

1. Block legacy authentication in a separate policy (CA003), never folded into
   MFA.
2. Admin policies use **authentication strength** (phishing-resistant), not the
   generic MFA control (CA002).
3. Device compliance for admin portals is piloted on a group first (CA005 is
   scoped to `CA005-Pilot-CompliantDevice`).
4. Risk-based policies (user risk and sign-in risk) belong in CA, not in legacy
   Identity Protection policies. CA006 and CA007 do this, behind a staging
   flag. They need P2.
5. Microsoft's mandatory MFA for admin portals applies even to excluded
   accounts. Break-glass therefore uses FIDO2 (`lab/terraform/README.md`,
   human step 6).
6. A control the provider can't express (token protection, CAE strict
   location) goes in its own Graph-managed policy under its own number, never
   patched onto a Terraform-managed one. The provider rebuilds a policy's
   session controls on every update, so the next apply would very likely
   remove it (verify; `modules/conditional-access/admins.tf`).

## 7. Where the lab is short of these principles

- No guest or workload-identity personas. The clinician persona (CA060) is
  code with no device behind it.
- Everything after CA005 sits behind a staging flag, so a default plan
  creates only CA001–CA005.
- No policy has graduated, so no report-only evidence exists.
- No CA-change detection has fired; it exists only as a rule.
- The token-protection pilot (CA011) is Graph-managed and report-only; it
  has not run.

verify:
- the date that legacy Identity Protection user-risk and sign-in-risk
  policies were retired (reported as 2026-10-01).
- whether the CA directory-role condition covers roles held through PIM for
  Groups (also flagged in the privileged-access standard). CA002 can also
  target the admin groups for that reason, and because Conditional Access
  doesn't evaluate administrative-unit-scoped role assignments (Microsoft
  Learn, checked 2026-10-20).
