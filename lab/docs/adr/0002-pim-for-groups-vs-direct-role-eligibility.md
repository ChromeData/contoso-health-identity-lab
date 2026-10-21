# ADR 0002: PIM for Groups vs. direct directory-role eligibility

- **Status:** Accepted (lab). **Partly superseded by [ADR 0020](0020-pim-activation-design.md)** (approvers, eligibility expiry, more roles). The pattern below stands: a group actively holds the role, and membership is eligible-only. Code validated offline; no activation has run yet.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Superseded parts

The text below is the decision as made. ADR 0020 replaced three parts of
it, and those parts are current there, not here:

- **Approvers.** One role-assignable approver group per tier, not named
  users.
- **Eligibility.** It now expires (Tier 0 `P180D`, Tier 1 and this group
  `P365D`) instead of relying on a review alone.
- **More roles.** The second revisit trigger below fired: `modules/pim`
  repeats this pattern with one group per role. Global Administrator is the
  exception, with direct named eligibility (option 1, for that one role).

## Context

The target is zero standing admin access. Outside the two break-glass
accounts (ADR 0003), no human should hold a directory role at rest.
Elevation must be just-in-time, with MFA, a justification, an approval and a
time cap. And it must be **code**: the activation policy is a control, so it
belongs in a reviewed PR, not in portal clicks.

The constraint is the provider. The azuread provider fully supports the PIM
for Groups policy (`azuread_group_role_management_policy`). It does **not**
support the directory-role activation policy (Graph
`unifiedRoleManagementPolicy`).

## Options considered

1. **Direct role eligibility.** Make people eligible for User Administrator
   and set the role's own activation policy. This is the most familiar model
   and gives the clearest "who can be what" report. But the policy can't be
   expressed in Terraform, so it would need a post-apply Graph script and
   would drift silently.
2. **Group eligible for the role, plus eligible group membership.** Every
   elevation then needs two activations (membership first, then the role),
   which is more friction and more chances for an approval to stall.
3. **A role-assignable group that actively holds the role, with eligible-only
   membership through PIM for Groups (chosen).** One activation, and the
   provider manages the whole policy.
4. **Standing assignment.** Rejected outright: it contradicts the
   zero-standing-access target.

## Decision

`Privileged-IAM-Admins`, a role-assignable group, **actively** holds User
Administrator. User Administrator is a scoped Tier-1 role, deliberately not
Global Administrator.

The group has **no permanent members**. Membership is eligible-only and is
activated through PIM for Groups with:

- MFA
- a justification
- approval by named approvers
- a maximum of `PT4H`

Plan fails if approval is required and no approver is named. Direct active
membership must expire. Who is eligible is operational data, so a post-apply
script sets it, not Terraform.

## Consequences

- **One provider-managed policy, reviewable in a PR.** A change to MFA,
  approval or the duration appears in the plan comment.
- **The group is the choke point.** Anyone who can change its membership
  outside PIM gets User Administrator. **Compensating controls:**
  - Role-assignable groups limit who can manage membership (verify: Global
    Administrator, Privileged Role Administrator and group owners).
  - Direct active membership must expire (`expire_after`). The shortest
    value the provider accepts is P15D, so a directly added member can
    persist for up to 15 days. This is a residual risk.
  - `01-Verify-Baseline.ps1` check 6 warns on any standing member.
  - `pim-activation.kql` alerts on completed activations.
  - `pim-group-member-added-outside-pim.kql` alerts on a member added
    directly, or as a permanent active member through PIM. It is High unless
    the CI apply identity made the change, matched by immutable id.
    `modules/monitoring` deploys it (`itdr.tf`); it has not fired in a
    tenant.
- **Terraform is blind to membership drift.** `ignore_changes = [members]`
  stops every activation showing up as drift, but Terraform also won't flag
  a rogue member. The baseline script and
  `pim-group-member-added-outside-pim.kql` cover this.
- **Reporting needs one extra hop.** "Who holds User Administrator" shows the
  group, so auditors have to expand its eligibility schedules. The evidence
  pack has to present both.
- **Self-approval:** a requester can't approve their own activation
  (verify). In a solo lab the approver must be a second account.
- **Eligibility doesn't expire.** A periodic review of who is eligible is
  the control.
- **Licensing:** PIM for Groups needs Entra ID P2 or Entra ID Governance for
  every eligible user (`lab/terraform/README.md`, license table).

## Revisit trigger

- The azuread provider adds the directory-role activation policy. Option 1
  becomes expressible, and its clearer reporting may win.
- More than one Tier-1 role needs separate approvers or durations. That
  means one group per role, or a move to option 1.
- An audit finding that the group indirection hides who holds privilege.

## Evidence

- `lab/terraform/modules/pim/main.tf` (pattern header, precondition,
  `active_assignment_rules`)
- `lab/terraform/modules/pim/variables.tf` (`PT4H`, `require_approval = true`,
  P15D minimum)
- `lab/terraform/modules/groups/main.tf` (`Privileged-IAM-Admins`,
  `assignable_to_role = true`, `ignore_changes = [members]`)
- `lab/terraform/modules/pim/tests/pim.tftest.hcl`
- `lab/scripts/powershell/post-apply/Set-PimGroupEligibility.ps1`
- `lab/scripts/powershell/01-Verify-Baseline.ps1` (check 6)
- `lab/kql/pim-activation.kql`, `lab/kql/pim-group-member-added-outside-pim.kql`
- `lab/terraform/README.md` (human step 2)
- For the superseded parts: ADR 0020's evidence (`modules/pim/approvers.tf`,
  `tiers.tf`, `directory-roles.tf`), and the privileged access review body
  in `lab/terraform/modules/entitlement/reviews.tf`
