# ADR 0020: PIM activation design (approvers, expiry, step-up, Global Administrator, help-desk scope)

- **Status:** Accepted (lab). BUILT: Terraform where the provider allows it, post-apply Graph scripts where it doesn't, all tested offline only. RAN · tenant: real activations raised a Sentinel incident and a ServiceNow ticket (E40b), AWS admin was activated and given back (E99), and a help-desk admin activated PIM-Tier1-Helpdesk with a passkey (E104). **Partly supersedes ADR 0002** (approvers, eligibility expiry, more roles); 0002's pattern stands (a group actively holds the role, and membership is eligible-only).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

ADR 0002 made elevation just-in-time through PIM for Groups, with two
gaps: eligibility never expired, so a review was the only control on who
is eligible, and approval went to named single users. The tier groups
added since then raise more questions: how long each tier stays active,
which Tier-1 roles need approval, what a Tier-0 activation must prove,
how Global Administrator is reached when it must never sit behind a group,
and how the service desk resets methods without reaching every account.

Two constraints shape the answers. Microsoft says PIM falls back to plain
MFA only when **no** CA policy targets the activation's authentication
context: a policy that is off, in report-only, or excludes the eligible
users triggers no fallback (Learn; see Sources). And azuread 3.10.0 can't
create authentication contexts, CA policies that target them,
directory-role settings, or restricted-management administrative units
(AUs).

## Options considered

| Question | Chosen | Rejected, and why |
|---|---|---|
| Who approves | One approver **group** per tier (`PIM-Approvers-Tier0`, `-Tier1`, routed as `groupMembers`). Members are set in code, and both groups are role-assignable so the roles they approve can't edit them. Keeping approvers apart from the eligible people is a convention, not a control: eligibility is set post-apply, and `Set-PimGroupEligibility.ps1` only warns on overlap. PIM itself refuses self-approval (verify) | **Single named approvers:** one absence blocks Tier-0 activation, requests expire after 24 hours, and Microsoft advises at least two approvers. **No approval:** one phished admin gets Tier 0 at once |
| How long an activation lasts | Tier 0 **4 h**; Global Administrator and Privileged Authentication Administrator **2 h**; Tier 1 **8 h**, one shift; `Privileged-IAM-Admins` (User Administrator) 4 h | **Tier 0 2 h and Tier 1 4 h for every role** (the privileged-access standard's draft): a service-desk role would lapse mid-shift and need a second activation every shift, and a Tier-0 change (plan, apply, verify) that overruns 2 h needs a second approval mid-change. Both teach people to re-request and approvers to approve without reading. The two roles that can take over any account on their own keep 2 h, and CA020 still forces a fresh sign-in every 4 h on the admin portals |
| Which Tier-1 activations need approval | Only roles that reach Tier-0 assets or every non-admin account: Intune Administrator, User Administrator, and the IGA group (Identity Governance + Lifecycle Workflows Administrator). The rest need a justification and MFA, and every activation is alerted (`pim-activation.kql`) | **Approval on every Tier-1 activation** (the standard's draft): the service desk activates at every shift start, and a queue on every shift trains approvers to rubber-stamp. The service-desk roles reach only the standard-workforce AU once `enable_helpdesk_au_scoping` is on, and can't touch admins |
| How long eligibility lasts | It expires: Tier 0 **P180D**, Tier 1 **P365D**. Active assignments always expire too (P15D, the provider's minimum) | **Permanent eligibility plus a review** (ADR 0002): the review depends on reviewers acting, and reviews of PIM-group eligibility need ID Governance licensing (verify). Expiry fails closed, and the ADR 0012 T1 review still runs |
| What Tier-0 activation proves | Authentication context **`c1`**. A CA policy (CA021, Graph-managed) targets it: the admin phishing-resistant strength, with sign-in frequency every time | **The MFA flag:** an earlier MFA in the session satisfies it, of any strength. **CA002 alone:** the role condition matches users only once they're active, so it applies after activation, not at it |
| Global Administrator | **Direct** eligibility per named person, set through Graph, with expiry, approval and `c1` | **GA in a tier group:** one membership change away, and blocked by validation. **Standing GA for admins:** contradicts zero standing access. Break-glass keeps standing GA (ADR 0003) |
| Service-desk scope | Authentication and Helpdesk Administrator **scoped to an AU** of standard workforce users, held by a PIM group. VIPs go in a restricted-management AU | **Tenant-wide help-desk roles:** they can reset methods for every non-admin, VIPs included |

## Decision

- **Role-to-tier map.** **Tier 0** is anything that can change who gets in
  or how sign-in is protected: Privileged Role, Privileged Authentication,
  Security, Conditional Access, Hybrid Identity, Application, Cloud
  Application and Authentication Policy Administrator. Microsoft doesn't
  label the last one privileged, but it sets the methods policy ADR 0016
  depends on. **Tier 1** is the management plane: User, Groups,
  Authentication, Helpdesk, Intune, Exchange, SharePoint, Teams, License,
  Identity Governance and Lifecycle Workflows Administrator. Intune
  Administrator still needs approval, because it reads LAPS passwords and
  BitLocker keys. So does the IGA group (`PIM-Tier1-IGA-Admins`): Microsoft
  labels both of its roles privileged, and whoever holds them can change
  who gets clinical access by HR attribute and issue TAPs through a joiner
  workflow.
- **Intune Administrator is Tier 1 only until privileged workstations
  exist.** Intune can push scripts and apps to every device it manages.
  Once PAWs (CA005's production design) or DC-management devices are
  Intune-managed, an Intune Administrator controls Tier 0. See the revisit
  trigger.
- **Privileged roles not on the map are never assigned.** Domain Name,
  External Identity Provider and Authentication Extensibility
  Administrator fit the Tier-0 rule (federated domains, outside sign-in,
  code in the token path) and are not mapped. An active assignment of any
  of them outside PIM alerts as High (`role-assigned-outside-pim.kql`); an
  eligible one made directly in PIM shows only at its first activation
  (`pim-activation.kql`). If one is ever needed, it goes into a Tier-0
  group first. One read-only exception (2026-11-05): `PIM-Demo-Readers`
  (`modules/pim/demo-readers.tf`) holds Global Reader and Security Reader,
  both labelled privileged, for the demo presenter: eligible-only, 8 h,
  MFA + reason, no approval, every activation mailed, outside the tier map
  and the CA002 / CA020 scope.
- **Standing directory roles have two exceptions:** break-glass (ADR
  0003), and the containment identity's Authentication Administrator, only
  if it is ever turned on (ADR 0017, a recorded risk acceptance). Every
  other active role assignment expires. Graph permissions held by
  non-human identities are governed separately (ADRs 0005 and 0018).
- **Notifications.** Tier-0 activations, new eligibility and any direct
  active assignment also email a security mailbox. That is a second signal
  alongside the detections.
- **Order of the `c1` switch-over: three separate changes.** Learn (PIM
  for Groups role settings): when the context's CA policy is report-only
  or off, there is no step-up and no MFA backup, so PIM must not point at
  `c1` before the enforced CA021 is in the tenant.
  1. **Change 1:** `ca_policy_states.CA021 = "enabled"`, apply, then run
     `Set-AuthContextPolicies.ps1`, which writes `c1` and the enforced
     CA021.
  2. **Change 2, later:** `ca021_enforced_in_tenant = true`, only once the
     script reports CA021 enabled in the tenant. This is an operator
     attestation: `terraform apply` writes the Tier-0 PIM policies before
     any post-apply step, so the declared state of the same change can't
     protect them.
  3. **Change 3, the PIM context, in two applies** for existing Tier-0
     policies: first `pim_tier0_auth_context_switchover_step1 = true`,
     which turns the MFA flag off; then
     `pim_tier0_activation_auth_context_id = "c1"`. The provider marks the
     two settings as conflicting and keeps the prior state for an unset
     value, so a single apply could leave MFA set.

  The `envs/dev` root validation refuses `c1` (and step 1) until all three
  hold: `enable_pim_auth_context`, CA021 `enabled`, and
  `ca021_enforced_in_tenant`. `modules/conditional-access` and
  `modules/pim` refuse it too. Between the two applies of change 3, Tier 0
  still needs approval and a justification but no step-up. Run them back to
  back, and approvers deny any request that arrives in between. CA021
  targets all users, never the PIM group, because the requester isn't a
  member yet at activation.
- **The VIP restricted-management AU is created by a Graph script**
  (`New-RestrictedAdminUnit.ps1`), never by the Terraform resource. Its flag
  can be set only at creation, and a Terraform replace would quietly
  recreate it without the restriction.

## Consequences

- **Eligibility now lapses.** An admin whose eligibility expires can't
  activate during an incident. So renewal reminders matter, and break-glass
  stays the fallback. `Set-PimGroupEligibility.ps1` requests an expiring
  eligibility, because a permanent one would now be refused. verify:
  whether existing permanent eligibilities are cut back.
- **Step-up covers the moment of activation only.** Once activated, the
  role works from any session. CA002 (with the tier groups added to its
  `included_groups`) and the admin-portal sign-in frequency cover what
  comes after.
- **Graph-managed pieces don't show in `terraform plan`.** The detections
  cover the gap: `pim-activation-without-auth-context` fires on a Tier-0
  activation that wasn't stepped up, or whose policy only ran in
  report-only.
- **AU-scoped roles are invisible to CA's role condition.** The service-desk
  PIM group goes into CA002 `included_groups`.
- **Restricted-management AU members are outside automation.** PIM,
  entitlement management, lifecycle workflows and access reviews can't
  manage them, so VIP leavers and reviews are manual. Tenant-wide Global
  Administrators can't modify them, and Graph application permissions
  don't apply to them: containment (ADR 0017) would need a role scoped to
  that AU to disable a VIP. verify: whether HR inbound provisioning can update
  them. No PIM group ever goes in one; PIM doesn't support that.
- **Licensing:** P2 or ID Governance per eligible user; P1 per AU admin.

## How it is measured

Fill this in after the first activations.

| Measure | Source | Target |
|---|---|---|
| `admin_standing_users`, excluding break-glass | `08-Measure-KPIs.ps1` | 0 |
| `admin_jit_pct` | Same | 100% |
| Tier-0 activations with no step-up | `pim-activation-without-auth-context.kql` | 0 once CA021 is enforced |
| Request → approval, median and p90 | PIM audit logs | Reported. Agreed with the SOC |
| Eligibilities lapsed vs. renewed, per quarter | PIM eligibility schedules | Every lapse intended |
| Tier-1 re-activations within one shift | PIM audit logs | Watched. A rising count means the cap is too short |

## Revisit trigger

- The azuread provider gains directory-role settings, authentication
  contexts or the restricted-management flag: move those parts into
  Terraform.
- Approval latency delays incident response.
- A Tier-0 activation completes without the step-up.
- Microsoft changes PIM's authentication-context fallback.
- A VIP leaver is missed because their account is in the restricted AU.
- CA005 widens to all admins, or PAWs become Intune-managed: move Intune
  Administrator to Tier 0, or put PAWs under an Intune scope that only
  Tier-0 people administer (verify: Intune scope tags).
- An unmapped privileged role is needed.

## Evidence

- `lab/terraform/modules/pim/`: `main.tf`, `approvers.tf`, `tiers.tf`,
  `helpdesk.tf`, `directory-roles.tf`, `variables.tf` (`pim_tier_groups`
  and the validation banning Global Administrator, the eligibility
  durations, the activation caps (`tier0_`, `tier1_` and
  `global_admin_activation_max_duration`),
  `tier0_activation_auth_context_id` and its gate) and
  `tests/pim.tftest.hcl`
- `lab/terraform/modules/conditional-access/`: `main.tf` (CA002
  `included_groups`: the tier groups and the help-desk group), `admins.tf`
  (CA021, rendered for Graph) and `tests/ca002_ca020_ca021_admins.tftest.hcl`
- `lab/scripts/powershell/post-apply/`: `Set-PimGroupEligibility.ps1`,
  `Set-AuthContextPolicies.ps1`, `Set-DirectoryRolePimPolicies.ps1`,
  `New-RestrictedAdminUnit.ps1`
- `lab/kql/pim-activation.kql`,
  `lab/kql/pim-activation-without-auth-context.kql`,
  `lab/kql/pim-group-member-added-outside-pim.kql`,
  `lab/kql/role-assigned-outside-pim.kql`
- `lab/docs/runbooks/pim-activation-support.md`,
  `lab/docs/runbooks/help-desk-identity-verification.md`
- `lab/docs/standards/privileged-access-standard.md`

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-role-settings
  (the authentication-context fallback is a backup that isn't triggered
  if the policy is off, report-only, or excludes eligible users; create and
  enable the policy first; don't target the group; at least two
  approvers; RMAU groups unsupported)
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management
  (set only at creation; governance features excluded; app permissions
  don't apply; P1 per AU admin)
