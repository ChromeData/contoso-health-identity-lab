# modules/pim

Just-in-time admin access for Contoso Health: no human holds an admin role at
rest. It is **activated**, time-boxed, approved where the tier says so, and
recorded. Decisions: [ADR 0002](../../../docs/adr/0002-pim-for-groups-vs-direct-role-eligibility.md)
(PIM for Groups as the elevation path) and
[ADR 0020](../../../docs/adr/0020-pim-activation-design.md) (approver groups,
eligibility expiry, activation caps, step-up, direct Global Administrator
eligibility, AU-scoped help desk).

**Status: BUILT.** `validate` and 32 mocked `terraform test` runs pass
(HashiCorp Terraform 1.16.5, 2026-10-20). **Nothing has been applied: no
tenant exists yet.** **TENANT-TIME** steps need the M365 E5 trial (Entra ID
P2); *verify:* items are checked in that window.

| File | Flag in `envs/dev` (default) | What it builds |
|------|------------------------------|----------------|
| `main.tf` | `enable_premium` (false) | `Privileged-IAM-Admins` actively holds **User Administrator**. Its membership is eligible-only: PIM for Groups, MFA + justification + approval by `PIM-Approvers-Tier1` (`pim_require_approval`, default **true**), 4h, eligibility expires after 365 days |
| `approvers.tf` | `enable_premium` (false) | `PIM-Approvers-Tier0` and `PIM-Approvers-Tier1`, role-assignable groups routed as `groupMembers` approvers; members come from `tier0_approver_object_ids` / `approver_object_ids`. A `check` warns on fewer than two approvers |
| `tiers.tf` | `enable_pim_tiers` (false) | 16 role-assignable tier groups using the same pattern (table below) |
| `helpdesk.tf` | `enable_helpdesk_au_scoping` (false) | `AU-Workforce-Standard` and the help-desk roles of `PIM-Tier1-Helpdesk` scoped to it instead of the tenant. The AU's dynamic rule is a Graph PATCH (output `workforce_au_membership_body`) |
| `directory-roles.tf` | `enable_global_admin_pim_policy` (false) | Global Administrator's own PIM policy, **rendered** (output `directory_role_pim_policies`) for `post-apply/Set-DirectoryRolePimPolicies.ps1`: approval by `PIM-Approvers-Tier0`, MFA or the `c1` context, justification + ticket, 2h, named eligibility for 180 days. Break-glass keeps its standing assignment |
| `reviews.tf` | `enable_access_reviews_privileged` (false) | Rendered bodies (output `pim_eligible_review_bodies`) for quarterly, default-deny reviews of every PIM-governed group (eligible + active members), created by `post-apply/New-AccessReviewDefinitions.ps1` |
| `azure.tf` | `enable_pim_azure_resources` (false) | `PIM-Azure-RG-Contributors` is **eligible** for Contributor on the lab RG, with an Azure PIM activation policy (MFA + justification + approval by `PIM-Approvers-Tier0`, approver type Group, 4h) |
| `aws.tf` | `enable_pim_aws_admin` (false) | `PIM-AWS-Lab-Admins`, role-assignable, **eligible-only** membership = administrator of the lab AWS account ([ADR 0025](../../../docs/adr/0025-aws-admin-just-in-time-through-entra.md)). envs/dev assigns it to the AWS IAM Identity Center app (modules/apps); `lab/terraform/aws` gives its SCIM copy the `LabAdministrator` permission set. Activation: MFA + justification, 2h, no approval while the lab has one human admin (`aws_admin_require_approval`), every activation mailed to `pim_alert_mailbox`; eligibility expires after 180 days; reviewed quarterly, but **not** in `privileged_review_targets` (the CA002 / CA020 scope) |

## Tier model

Tier 0 is the control plane: a role that can change how sign-in is protected,
grant roles, or take over a workload identity. Tier 1 changes devices,
ordinary users or one workload.

| Group | Role | Tier | Activation | Eligibility expires |
|-------|------|------|------------|---------------------|
| PIM-Tier0-Security-Admins | Security Administrator (`194ae4cb-…`) | 0 | MFA (or `c1`) + justification + ticket + **approval**, 4h | 180 days |
| PIM-Tier0-CA-Admins | Conditional Access Administrator (`b1be1c3e-…`) | 0 | same, 4h | 180 days |
| PIM-Tier0-Privileged-Role-Admins | Privileged Role Administrator (`e8611ab8-…`) | 0 | same, 4h | 180 days |
| PIM-Tier0-Privileged-Auth-Admins | Privileged Authentication Administrator (`7be44c8a-…`) | 0 | same, **2h** | 180 days |
| PIM-Tier0-Hybrid-Identity-Admins | Hybrid Identity Administrator (`8ac3fc64-…`) | 0 | same, 4h | 180 days |
| PIM-Tier0-Application-Admins | Application Administrator (`9b895d92-…`) | 0 | same, 4h | 180 days |
| PIM-Tier0-Cloud-Application-Admins | Cloud Application Administrator | 0 | same, 4h | 180 days |
| PIM-Tier0-Auth-Policy-Admins | Authentication Policy Administrator | 0 | same, 4h | 180 days |
| PIM-Tier1-Intune-Admins | Intune Administrator | 1 | MFA + justification + **approval**, 8h | 365 days |
| PIM-Tier1-Helpdesk | Helpdesk Administrator + Authentication Administrator (AU-scoped with `enable_helpdesk_au_scoping`) | 1 | MFA + justification, 8h | 365 days |
| PIM-Tier1-Groups-Admins | Groups Administrator | 1 | MFA + justification, 8h | 365 days |
| PIM-Tier1-Exchange-Admins | Exchange Administrator | 1 | same, 8h | 365 days |
| PIM-Tier1-SharePoint-Admins | SharePoint Administrator | 1 | same, 8h | 365 days |
| PIM-Tier1-Teams-Admins | Teams Administrator | 1 | same, 8h | 365 days |
| PIM-Tier1-License-Admins | License Administrator | 1 | same, 8h | 365 days |
| PIM-Tier1-IGA-Admins | Identity Governance Administrator + Lifecycle Workflows Administrator | 1 | MFA + justification + **approval**, 8h | 365 days |
| Privileged-IAM-Admins (`main.tf`) | User Administrator (`fe930be7-…`) | 1 | MFA + justification + **approval**, 4h | 365 days |
| Global Administrator (`directory-roles.tf`, named people, no group) | Global Administrator | 0 | MFA (or `c1`) + justification + ticket + **approval**, 2h | 180 days |
| PIM-Azure-RG-Contributors (`azure.tf`) | Azure **Contributor** on rg-identity-lab | 0 | MFA + justification + **approval**, 4h | permanent eligibility, reviewed quarterly |

Template ids are in `variables.tf` (`pim_tier_groups`) and were checked
against Microsoft's built-in roles reference on 2026-10-20.

**Why these tiers.** A Conditional Access Administrator can exclude
themselves from every policy; a Security Administrator can turn off what
would notice; a Privileged Role Administrator can grant any role; an
Application Administrator can add a credential to any service principal,
the pipeline's APPLY identity included
([ADR 0005](../../../docs/adr/0005-risk-acceptance-apply-identity-tier0.md)).
So they are Tier 0. Authentication Policy Administrator is not labelled
privileged by Microsoft, but it sets the methods policy CA008 and CA009 rely
on, so it is Tier 0 here. Tier 1 gets a shift-length window and no approval
queue, because an approver who sees every help-desk shift learns to
rubber-stamp. Two Tier-1 groups are the exception: Intune (it reads LAPS
passwords and BitLocker keys) and IGA (both of its roles are labelled
privileged by Microsoft: whoever holds them can change who gets clinical
access by HR attribute and issue TAPs through a joiner workflow). ADR 0020
records both exceptions, with User Administrator. Contributor on the RG is Tier 0 because the RG holds DC01:
`az vm run-command` runs code as SYSTEM on the domain controller.

**Guardrails in code** (`variables.tf`, preconditions, checks):

- Global Administrator can never be a tier group's role, primary or
  additional (break-glass only; named eligibility through
  `directory-roles.tf`).
- The original `Privileged-IAM-Admins` binding (`role_template_id`) can
  hold neither Global Administrator nor a Tier-0 role: it gets Tier-1
  activation rules, so those roles go through a `tier = 0` group.
- A Tier-0 role cannot sit in a Tier-1 group, and a Tier-0 group cannot
  waive approval.
- Tier 0 without approvers fails at plan.
- Tier-0 eligibility cannot be longer than 180 days, and no per-group
  override can lengthen a tier's activation cap.
- Direct *active* assignment always expires.
- The authentication context (`tier0_activation_auth_context_id = "c1"`)
  replaces MFA on Tier 0 only, and the plan refuses it until CA021 is
  declared enforced (`activation_auth_context_ca_enforced`). Existing Tier-0
  policies switch in two applies (`tier0_auth_context_switchover_step1`,
  then `c1`), because the provider declares the two arguments as
  conflicting (ConflictsWith) and keeps the prior state for an unset value
  (verify: whether Graph itself accepts both).
- Azure eligibility can never be for a role that grants access (Owner, User
  Access Administrator, RBAC Administrator).
- `pim_alert_mailbox` must be empty or one address; Tier-1 activations notify
  it only when `tier1_activation_notifications` is on.

## Provider notes

- `azurerm_role_management_policy` auto-imports the existing policy, and its
  **destroy is a no-op** (checked in the azurerm 4.81 source). Turning the flag
  off leaves the last settings in Azure.
- `azurerm_pim_eligible_role_assignment` without `schedule` requests **no
  expiration**. That works only after the policy allows permanent eligibility,
  hence the `depends_on`. It is the one permanent eligibility in the module,
  reviewed quarterly (output `privileged_review_targets`).
- azuread 3.10 has no directory-role policy resource, and
  `azuread_directory_role_eligibility_schedule_request` always sends
  `noExpiration`, which the Global Administrator policy refuses. Hence the
  rendered bodies and the post-apply script.
- azuread 3.10's administrative unit has no dynamic membership and no
  restricted-management attribute: the dynamic rule is a Graph PATCH, and
  the VIP restricted AU is created by `post-apply/New-RestrictedAdminUnit.ps1`.
  `workforce_au_excluded_employee_ids` keeps that AU's VIPs out of the
  help desk's AU by HR employee id (the base rule is parenthesised, then
  `-and (user.employeeId -notIn [...])` is appended). The VIP AU's own responder roles
  (Helpdesk + Authentication Administrator held by
  `PIM-Tier0-Privileged-Auth-Admins` at `RMAU-VIP` scope) are granted by
  that script through PIM, not by this module: Terraform never sees the
  RMAU. Both ran in the lab tenant on 2026-11-05 (capture E16c).
- AU-scoped role assignments are not evaluated by Conditional Access's
  directory-role condition, so CA002 / CA020 include `PIM-Tier1-Helpdesk` by
  group.

## Who may apply what (TENANT-TIME)

| Change | Graph / ARM permission | CI APPLY identity has it? |
|--------|------------------------|---------------------------|
| Tier and approver groups, role binding, PIM-for-Groups policies | `Group.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `RoleManagementPolicy.ReadWrite.AzureADGroup` | Yes (envs/bootstrap `apply_graph_roles`) |
| `AU-Workforce-Standard` and its scoped assignments | `AdministrativeUnit.ReadWrite.All` in addition to the above (APPLY); `AdministrativeUnit.Read.All` for PLAN (confirmed 2026-10-27: the plan lists AUs) | verify against `apply_graph_roles` before flipping `enable_helpdesk_au_scoping` |
| Global Administrator policy + eligibility | `RoleManagementPolicy.ReadWrite.Directory`, `RoleEligibilitySchedule.ReadWrite.Directory` | Not used: `Set-DirectoryRolePimPolicies.ps1` runs as a human |
| `PIM-AWS-Lab-Admins` and its PIM-for-Groups policy | same as the tier groups | Yes |
| Azure eligible assignment + Azure PIM policy | `Microsoft.Authorization/roleEligibilityScheduleRequests/write`, `roleManagementPolicies/write` on the RG (Owner / User Access Administrator) | **No.** It holds Contributor plus an ABAC-limited RBAC Administrator (*verify:* RBAC Administrator lacks these actions). The first apply of `enable_pim_azure_resources` is a **human apply**. Do not hand CI Owner. |

## Post-apply

Eligibility (*who* may activate) is operational data that references
HR-provisioned people, so it is never set in Terraform.
`lab/scripts/powershell/post-apply/Set-PimGroupEligibility.ps1` grants it
per group, with expiry (180 days Tier 0, 365 days Tier 1), and warns when a
person it makes eligible is in the same tier's approver group. Group
nicknames come from output `tier_group_mail_nicknames`:

```powershell
./Set-PimGroupEligibility.ps1 -GroupMailNickname pim-tier0-ca-admins `
    -UserPrincipalNames 'adm-first.last@<tenant>.onmicrosoft.com' -WhatIf
./Set-PimGroupEligibility.ps1 -GroupMailNickname pim-tier1-helpdesk `
    -UserPrincipalNames 'adm-first.last@<tenant>.onmicrosoft.com'
```

`post-apply/Invoke-PostApply.ps1` runs it (`-PimEligibility`) after the
Global Administrator policy and before the access reviews, together with
`Set-AuthContextPolicies.ps1` (CA021 + `c1`), `Set-DirectoryRolePimPolicies.ps1`,
`New-RestrictedAdminUnit.ps1` and, last and opt-in,
`Convert-BuildAccountToEligible.ps1`
([`lab/scripts/powershell/README.md`](../../../scripts/powershell/README.md)).

For **AWS** (`aws.tf`), eligibility is granted like a tier group's, with the
Tier-0 duration the policy allows (the nickname is not `pim-tier0-*`, so pass
it explicitly):

```powershell
./Set-PimGroupEligibility.ps1 -GroupMailNickname pim-aws-lab-admins `
    -UserPrincipalNames 'adm-labops@<tenant>.onmicrosoft.com' -EligibilityDuration P180D
```

For **Azure**, membership of `PIM-Azure-RG-Contributors` is ordinary (active)
membership. The *role* is what gets activated. The group is role-assignable,
so adding a member needs Privileged Role Administrator:
`POST https://graph.microsoft.com/v1.0/groups/<azure_pim_group_object_id>/members/$ref`
with `{"@odata.id":"https://graph.microsoft.com/v1.0/users/<id>"}`.

## TENANT-TIME steps (capture the evidence listed)

1. `enable_pim_tiers = true`, apply, then make one Tier-0 and one Tier-1
   person eligible. *Evidence:* activate both side by side. Tier 1 is granted
   immediately for 8h; Tier 0 waits for an approver-group member and is
   capped at 4h. Capture the audit log entries for each activation (the
   request, the approval, the member added by PIM) and output
   `tier_activation_policies`. Request to approval:
   `<measured: minutes>`.
2. **ITDR negative test:** as break-glass, add a member to a tier group
   *directly* (not through PIM), then remove them. The detection
   `pim-group-member-added-outside-pim` should fire on that audit event.
   For `PIM-Azure-RG-Contributors` a direct add is the intended path, so it
   takes the Medium `AzurePimEligibleMember` path instead of High.
3. `enable_global_admin_pim_policy = true`, then
   `Set-DirectoryRolePimPolicies.ps1 -WhatIf` and for real. *Evidence:* the
   role's policy rules read back from Graph, and one named eligibility with
   its end date.
4. `enable_pim_azure_resources = true` as a human Owner, then add one member.
   Activate through *PIM → My roles → Azure resources*. *Evidence:* the Azure
   Activity Log `roleAssignmentScheduleRequests` write, the approval, and the
   expiry 4h later.
5. **Remove the last standing human access.** Once steps 3 and 4 work,
   convert the build account's standing Global Administrator to eligible
   (`Convert-BuildAccountToEligible.ps1`) and the human's standing Owner on
   the subscription or RG to an eligible assignment. Standing privileged
   principals before / after: `<measured: count before>` /
   `<measured: count after>`.
6. **Turning features off:** the tier groups and role bindings are destroyed
   cleanly, but the Azure PIM policy settings stay (destroy is a no-op).

## verify: (open until the trial)

- PIM does not let a requester approve their own activation (PIM approval
  docs).
- A role-assignable group works as a `groupMembers` approver.
- The RBAC Administrator role has no `roleEligibilityScheduleRequests/write`
  or `roleManagementPolicies/write`.
- The subscription-scoped role definition id resolves the RG-scope policy on
  the first apply.
- An API-created review of a PIM-governed group expands **eligible** members
  the way a portal-created one does (`reviews.tf` header).
- A later provider update of the AU leaves its dynamic membership untouched.

## Offline tests

```bash
cd lab/terraform/modules/pim
terraform init -backend=false && terraform test   # HashiCorp Terraform 1.16.5
```

`tests/pim.tftest.hcl` (mock azuread + azurerm, **32 runs, all passing on
2026-10-20**) covers:

- every feature off: only the original binding exists;
- the tier map, per-tier activation strength, ticket, expiry and
  notifications; one approver warns; the mailbox must be an address;
- the `c1` context: refused before CA021 is enforced, replaces MFA on Tier 0
  only, the two-apply switchover, the Graph id range;
- guardrails: Tier 0 without approvers, Global Administrator as primary or
  additional role, a Tier-0 role in a Tier-1 group, Tier 0 waiving approval,
  AU scope on a role that cannot take it, overrides longer than the tier cap,
  Tier-0 eligibility over 180 days, Privileged-IAM-Admins holding Global
  Administrator or a Tier-0 role;
- help-desk AU scoping, and AU scoping without tiers warns and plans nothing;
- the Global Administrator rule bodies (with and without `c1`, approvers
  required);
- the PIM-eligible review bodies; none without a fallback reviewer; the
  reviewer group can never be a reviewed group;
- Azure PIM: Contributor role id form, RG scope, the *group* as principal,
  Tier-0 policy and approvers; a missing scope fails and Owner eligibility is
  rejected.
