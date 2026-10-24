# Conditional Access Design Principles

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario): Entra ID tenant |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. The CISO approves changes to enforced policy |
| Implementation | `lab/terraform/modules/conditional-access`, states in `lab/terraform/envs/dev/lab.tfvars` |

## 1. Personas and the policy list

Policies target **personas** (who) crossed with **apps** (what), never
individual people. Each persona is a group or a role set with an owner.

| Persona | Defined by | Policies |
|---|---|---|
| All workforce | All users, minus break-glass | CA001, CA003, CA004, CA006, CA007, CA008, CA009, CA010, CA011 |
| Admins | `admin_role_template_ids` (Microsoft's template list plus the tier extras) and the admin groups in `admin_scope_group_object_ids` | CA002, CA005, CA020, CA021, CA022, CA023 |
| Clinicians on shared workstations | Device filter (`enrollmentProfileName`) plus the clinical groups | CA060 |
| Guests | `userType` / connected organization | No guest-specific policy yet. All-users policies cover guests except CA006, CA008, CA009 and CA022, which exclude them on purpose |
| Workload identities | Service principals | **Not built:** needs Workload ID Premium |
| Emergency access | `Break-Glass-Admins` | Excluded everywhere (§3) |

**This is the single home of the CA list.** Every policy is BUILT and
report-only; none has run against a tenant. Every flag below also needs
`enable_premium` (Conditional Access is P1).

| Policy | What it does | Created by · flag |
|---|---|---|
| CA001 | MFA for all users | Terraform · `enable_premium` |
| CA002 | Phishing-resistant strength for admins (roles and admin groups) | Terraform · `enable_premium` |
| CA003 | Block legacy authentication | Terraform · `enable_premium` |
| CA004 | Block sign-in from blocked countries | Terraform · `enable_premium` |
| CA005 | Compliant device for the admin portals, pilot group only | Terraform · `enable_premium` |
| CA006 | User risk High → MFA and a secure password change (ADR 0015) | Terraform · `enable_identity_protection_ca` |
| CA007 | Sign-in risk High → block (ADR 0015) | Terraform · same |
| CA008 | Phishing-resistant workforce strength, pilot group first (ADR 0016) | Terraform · `enable_phishing_resistant_all_users` |
| CA009 | Register security info only with a one-time TAP or a phishing-resistant method (ADR 0016) | Terraform · `enable_registration_ca` |
| CA010 | Block device code flow, with an exception group | Terraform · `enable_device_code_block` |
| CA011 | Token protection pilot on one device | Graph script `Set-TokenProtectionPolicy.ps1` |
| CA020 | Admin portals: sign-in every 4 hours for Tier-0/1 admins | Terraform · `enable_admin_session_controls` |
| CA021 | Tier-0 PIM activation step-up, auth context `c1` (ADR 0002) | Rendered by Terraform, written by `Set-AuthContextPolicies.ps1` · `enable_pim_auth_context` |
| CA022 | Admin strength for the PAM broker and admin portals | Terraform · `enable_pam_oidc_app` |
| CA023 | Protected actions step-up, auth context `c2`, before CA policy or named-location edits | Rendered by Terraform, written by `Set-AuthContextPolicies.ps1` · `enable_protected_actions_ca` |
| CA060 | Shared clinical workstations: workforce strength, 8-hour frequency, no persistent browser (ADR 0014) | Terraform · `enable_shared_clinical_ca` |

**Clinical availability rule.** A policy that can block clinical staff
needs Clinical Operations sign-off ([raci.md](raci.md)) and a documented
fallback (for example a TAP from the service desk) before enforcement.
Locking a nurse out of the EHR during a shift is a patient-safety event,
not just an IT incident.

## 2. Report-only first, and one graduation per PR

- Every new policy starts `enabledForReportingButNotEnforced`. The
  `policy_states` validation fails the plan on a missing key, an unknown key
  or an invalid state.
- The minimum report-only window is **14 days**, covering a weekend and a
  night-shift cycle. Graduate only when the report-only results show no
  unplanned failures for a clinical persona. Graduating sooner inside the
  30-day trial is exception E9.
- **One policy changes state per PR,** with the plan comment, the report-only
  evidence and a one-line rollback
  ([graduate-a-ca-policy.md](../runbooks/graduate-a-ca-policy.md)).

## 3. Exclusions are governed

- The **only** standing exclusion is `Break-Glass-Admins`, applied as a group
  on every policy; `01-Verify-Baseline.ps1` proves it.
- Any other exclusion goes through the [exception process](exception-process.md):
  a dedicated `CA0NN-Exclusion-<reason>` group with an expiry and an owner,
  reviewed monthly. Never individual users inline.
- Pipeline identities aren't users, so user-targeted policies don't apply to
  them: not an exclusion, but a coverage gap (NHI standard).

## 4. Naming

`CA0NN - <Require|Block> <control> for <persona>[ (<scope>)]`

- Numbers are permanent and never reused.
- Ranges: 001–019 baseline (all users); 020–039 admins and privileged
  access; 040–059 risk-based; 060–079 clinical and device; 080–099 guests
  and workload identities. CA001–CA008 predate the ranges and keep their
  numbers, including the risk policies CA006 and CA007.
- The prefix is `policy_name_prefix` in `modules/conditional-access`.

## 5. Change control and detection

- CA changes **only** through code: PR, plan, `prod` reviewer, apply. The
  APPLY identity is the only writer; a portal edit is drift that the next
  apply reverts.
- A CA change by anything **other** than APPLY alerts
  (`ca-policy-changed.kql`): High for a weakening change (a policy deleted,
  disabled, moved to report-only or given new exclusions; a named location
  or authentication strength weakened), Medium for other drift, Low for
  APPLY, matched by immutable ID.
- Three policies are written by post-apply Graph scripts: CA021 and CA023
  (the provider can't target an authentication context; Terraform renders
  their bodies, so the PR still carries the change) and CA011 (no provider
  support; the script holds the desired state and shows drift on every run).

## 6. Design rules

1. Legacy authentication is blocked in its own policy (CA003), never folded
   into MFA.
2. Admin policies use an **authentication strength**, not the generic MFA
   control.
3. Device compliance for admin portals is piloted on a group first (CA005).
4. Risk-based policies live in CA, not legacy ID Protection policies, which
   retired on 2026-10-01 (CA006, CA007; P2).
5. Microsoft's mandatory admin-portal MFA applies even to excluded accounts,
   so break-glass uses FIDO2.
6. A control the provider can't express (token protection) goes in its own
   Graph-managed policy under its own number, never patched onto a
   Terraform-managed one, which the next apply would rebuild.

## 7. Where the lab is short of these principles

- No guest or workload-identity personas; CA060 has no device behind it.
- No policy has graduated, so no report-only evidence exists, and no
  CA-change detection has fired.
- Conditional Access doesn't evaluate administrative-unit-scoped role
  assignments (Microsoft Learn, checked 2026-10-20), and coverage of roles
  held through PIM for Groups isn't confirmed, so CA002 also targets the
  admin groups directly.
