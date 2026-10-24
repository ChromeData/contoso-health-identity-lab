# ADR 0002: PIM design: PIM for Groups, tiers, approvers, expiry and step-up

- **Status:** Accepted (lab). BUILT: Terraform where the provider allows it, post-apply Graph scripts where it doesn't, tested offline only. No activation has run in a tenant. **Absorbs ADR 0020** (PIM activation design), merged on 2026-10-21 before any tenant run; [0020](0020-pim-activation-design.md) is kept as a pointer.
- **Date:** 2026-10-20 (merged 2026-10-21)
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The target is zero standing admin access. Outside the two break-glass
accounts (ADR 0003), no human holds a directory role at rest. Elevation is
just in time, with a justification, an approval where the role warrants it,
a time cap and an expiry, and the activation policy is **code** in a
reviewed PR, not portal clicks.

Two constraints shape the design:

- **The provider.** azuread 3.10.0 fully manages the PIM for Groups policy
  (`azuread_group_role_management_policy`). It can't manage the
  directory-role activation policy, authentication contexts, CA policies that
  target them, or restricted-management administrative units (AUs).
- **PIM's step-up fallback.** PIM falls back to plain MFA only when **no** CA
  policy targets the activation's authentication context. A policy that is
  off, report-only or excludes the eligible users triggers no fallback
  (Learn, PIM for Groups role settings). A report-only step-up policy would
  leave activation with no MFA at all.

## Options considered

| Question | Chosen | Rejected, and why |
|---|---|---|
| How a role is held | A role-assignable group **actively** holds the role; membership is eligible-only through PIM for Groups. One activation, and the provider manages the whole policy | **Direct role eligibility:** clearest "who can be what" report, but the role's policy can't be expressed in Terraform and would drift silently. **Group eligible for the role plus eligible membership:** two activations per elevation. **Standing assignment:** contradicts zero standing access |
| Who approves | One approver **group** per tier (`PIM-Approvers-Tier0`, `-Tier1`), role-assignable so the roles they approve can't edit them. PIM refuses self-approval | **Named single approvers:** one absence blocks Tier-0 activation, requests expire after 24 hours, and Microsoft advises at least two. **No approval:** one phished admin gets Tier 0 at once |
| How long an activation lasts | Tier 0 **4 h**; Global Administrator and Privileged Authentication Administrator **2 h**; Tier 1 **8 h**, one shift; `Privileged-IAM-Admins` (User Administrator) 4 h | **Tier 0 2 h and Tier 1 4 h for every role:** the service desk would re-activate mid-shift, and a Tier-0 change that overruns 2 h needs a second approval mid-change. Both teach approvers to approve without reading |
| Which Tier-1 activations need approval | Roles that reach Tier-0 assets or every non-admin account: Intune Administrator (LAPS passwords, BitLocker keys), User Administrator, and the IGA group (Identity Governance + Lifecycle Workflows Administrator). The rest need a justification and MFA, and every activation alerts | **Approval on every Tier-1 activation:** the service desk activates every shift, and a queue on every shift trains approvers to rubber-stamp |
| How long eligibility lasts | It expires: Tier 0 **P180D**, Tier 1 and `Privileged-IAM-Admins` **P365D**. Direct active assignments expire too (P15D, the provider's minimum) | **Permanent eligibility plus a review:** the review depends on reviewers acting. Expiry fails closed, and the ADR 0012 T1 review still runs |
| What Tier-0 activation proves | Authentication context **`c1`**, targeted by CA021 (Graph-managed): the admin phishing-resistant strength, sign-in every time | **The MFA flag:** an earlier MFA in the session satisfies it, of any strength. **CA002 alone:** it applies after activation, not at it |
| Global Administrator | **Direct**, expiring eligibility per named person, set by a reviewed Graph script, with approval and `c1` | **GA in a tier group:** one membership change away, and blocked by validation. **Standing GA for admins:** contradicts zero standing access. Break-glass keeps standing GA (ADR 0003) |
| Service-desk scope | Helpdesk and Authentication Administrator **scoped to an AU** of standard workforce users (`AU-Workforce-Standard`), held by `PIM-Tier1-Helpdesk`. VIPs go in a restricted-management AU | **Tenant-wide help-desk roles:** they can reset methods for every non-admin, VIPs included |

## Decision

- **Role-to-tier map** (`pim_tier_groups`, one group per role).
  - **Tier 0**, anything that can change who gets in or how sign-in is
    protected (8 groups): Privileged Role, Privileged Authentication,
    Security, Conditional Access, Hybrid Identity, Application, Cloud
    Application and Authentication Policy Administrator. Microsoft doesn't
    label the last one privileged, but it sets the methods policy ADR 0016
    depends on.
  - **Tier 1**, the management plane (8 groups): Intune, Helpdesk +
    Authentication, Groups, Exchange, SharePoint, Teams, License, and
    Identity Governance + Lifecycle Workflows Administrator. User
    Administrator stays on `Privileged-IAM-Admins`.
  - **Intune Administrator is Tier 1 only until privileged workstations
    exist.** Once PAWs or DC-management devices are Intune-managed, it
    controls Tier 0 (revisit trigger).
- **Privileged roles not on the map are never assigned.** Domain Name,
  External Identity Provider and Authentication Extensibility Administrator
  fit the Tier-0 rule and aren't mapped. An active assignment of any of them
  outside PIM alerts High (`role-assigned-outside-pim.kql`).
- **Standing directory roles have two exceptions:** break-glass (ADR 0003),
  and the containment identity's Authentication Administrator, only if it is
  ever turned on (ADR 0017, a recorded risk acceptance).
- **Who is eligible is operational data**, set after HR provisioning by
  `Set-PimGroupEligibility.ps1`, never by Terraform. It requests expiring
  eligibility, and warns (doesn't refuse) when an approver is also eligible.
- **Notifications.** Tier-0 activations, new eligibility and any direct
  active assignment also email a security mailbox, a second signal next to
  the detections.
- **The `c1` switch-over is three separate changes,** because a report-only
  CA021 removes PIM's MFA fallback: (1) enforce CA021 and run
  `Set-AuthContextPolicies.ps1`; (2) set `ca021_enforced_in_tenant = true`
  once the script reports it enabled in the tenant; (3) switch the Tier-0
  PIM policy to `c1` in two back-to-back applies (MFA off, then `c1`),
  because the provider can't make that switch in one. The `envs/dev`
  validation, `modules/conditional-access` and `modules/pim` all refuse `c1`
  until the first two hold. CA021 targets all users, never the PIM group:
  the requester isn't a member yet at activation.
- **The VIP restricted-management AU is created by a Graph script**
  (`New-RestrictedAdminUnit.ps1`), never by Terraform: the flag can be set
  only at creation, and a Terraform replace would recreate it without the
  restriction.

## Consequences

- **The group is the choke point.** Anyone who changes its membership
  outside PIM gets the role. Compensating controls: only Privileged Role
  Administrators, Global Administrators and the group's owners can change a
  role-assignable group's membership; a directly added member expires within
  15 days; `01-Verify-Baseline.ps1` check 6 warns on a standing member; and
  `pim-group-member-added-outside-pim.kql` alerts High on a direct add
  (always High for `Break-Glass-Admins`), matched by immutable id so the CI
  apply identity's own changes stay Low.
- **Terraform is blind to membership drift** (`ignore_changes = [members]`,
  or every activation would show as drift). The baseline check and the rule
  cover it.
- **Exchange and SharePoint Administrator activate without approval.** Either
  can reach mailbox or site content, which in a hospital means PHI. Every
  activation alerts (`pim-activation.kql`) and is matched to a ticket; if
  the SOC can't keep up, approval is one line per group (`require_approval`
  in `pim_tier_groups`).
- **Eligibility lapses.** An admin whose eligibility expired can't activate
  during an incident, so renewal reminders matter and break-glass stays the
  fallback.
- **Step-up covers the moment of activation only.** CA002 (with the tier
  groups in `included_groups`) and CA020's 4-hour admin-portal sign-in
  frequency cover the session afterwards.
- **Graph-managed pieces don't show in `terraform plan`.**
  `pim-activation-without-auth-context.kql` fires on a Tier-0 activation
  that wasn't stepped up.
- **AU-scoped roles are invisible to CA's role condition,** so the
  help-desk PIM group goes into CA002's `included_groups`.
- **Restricted-management AU members are outside automation.** PIM,
  entitlement management, Lifecycle Workflows and access reviews can't
  manage them, so VIP leavers and reviews are manual, and containment
  (ADR 0017) escalates them to a person.
- **Reporting needs one extra hop:** "who holds User Administrator" shows
  the group, so the evidence pack exports both the role assignments and the
  group's activation history.
- **Licensing:** P2 or ID Governance per eligible user; P1 per AU admin.

## How it is measured

Fill this in after the first activations.

| Measure | Source | Target |
|---|---|---|
| `admin_standing_users`, excluding break-glass | `08-Measure-KPIs.ps1` | 0 |
| `admin_jit_pct` | Same | 100% |
| Tier-0 activations with no step-up | `pim-activation-without-auth-context.kql` | 0 once CA021 is enforced |
| Request → approval, median and p90 | PIM audit logs | Reported, agreed with the SOC |
| Eligibilities lapsed vs. renewed, per quarter | PIM eligibility schedules | Every lapse intended |
| Tier-1 re-activations within one shift | PIM audit logs | Watched: a rising count means the cap is too short |

## Revisit trigger

- The azuread provider gains directory-role settings, authentication
  contexts or the restricted-management flag: move those parts into
  Terraform, and reconsider direct role eligibility for its clearer
  reporting.
- Approval latency delays incident response, or a Tier-0 activation
  completes without the step-up.
- Microsoft changes PIM's authentication-context fallback.
- PAWs become Intune-managed: move Intune Administrator to Tier 0.
- A VIP leaver is missed because their account is in the restricted AU.
- An audit finding that the group indirection hides who holds privilege.

## Evidence

- `lab/terraform/modules/pim/`: `main.tf` (pattern, precondition,
  `active_assignment_rules`), `tiers.tf`, `approvers.tf`, `helpdesk.tf`,
  `directory-roles.tf`, `azure.tf`, `variables.tf` (`pim_tier_groups`, the
  validation banning Global Administrator, durations, caps,
  `tier0_activation_auth_context_id` and its gate),
  `tests/pim.tftest.hcl`
- `lab/terraform/modules/groups/main.tf` (`Privileged-IAM-Admins`,
  `assignable_to_role = true`, `ignore_changes = [members]`)
- `lab/terraform/modules/conditional-access/`: `main.tf` (CA002
  `included_groups`), `admins.tf` (CA021, rendered for Graph),
  `tests/ca002_ca020_ca021_admins.tftest.hcl`
- `lab/scripts/powershell/post-apply/`: `Set-PimGroupEligibility.ps1`,
  `Set-AuthContextPolicies.ps1`, `Set-DirectoryRolePimPolicies.ps1`,
  `Convert-BuildAccountToEligible.ps1`, `New-RestrictedAdminUnit.ps1`
- `lab/scripts/powershell/01-Verify-Baseline.ps1` (check 6)
- `lab/kql/pim-activation.kql`, `pim-activation-without-auth-context.kql`,
  `pim-group-member-added-outside-pim.kql`, `role-assigned-outside-pim.kql`
- `lab/terraform/modules/entitlement/reviews.tf` (the privileged access
  review of PIM eligibility)
- [`runbooks/pim-activation-support.md`](../runbooks/pim-activation-support.md),
  [`runbooks/help-desk-identity-verification.md`](../runbooks/help-desk-identity-verification.md),
  [`standards/privileged-access-standard.md`](../standards/privileged-access-standard.md)

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/groups-role-settings
  (the authentication-context fallback isn't triggered if the policy is off,
  report-only, or excludes eligible users; at least two approvers; RMAU
  groups unsupported)
- https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management
  (set only at creation; governance features excluded; P1 per AU admin)
