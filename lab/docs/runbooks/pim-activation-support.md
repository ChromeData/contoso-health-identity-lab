# Runbook: PIM activation support (L1 / L2)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). **Status:**
written against the lab code; not yet exercised (no tenant deployed).

## The design you are supporting

| Fact | Source |
|---|---|
| Group **Privileged-IAM-Admins** holds **User Administrator** actively; *membership* is the just-in-time part | `lab/terraform/modules/pim/main.tf` |
| Activation needs MFA, a justification, approval, and lasts at most **PT4H** | same, `activation_rules` |
| Approvers are the members of a role-assignable approver group per tier (`PIM-Approvers-Tier1` for this group, `PIM-Approvers-Tier0` for Tier 0), filled from `TF_PIM_APPROVER_OBJECT_IDS` | `lab/pipelines/README.md` §5 D, `modules/pim/approvers.tf` |
| The same pattern covers more roles in tier groups (`enable_pim_tiers`, off by default): eight Tier-0 groups (`PIM-Tier0-*`) need approval and a ticket number and last at most 4 h (Privileged Authentication Administrator 2 h); seven Tier-1 groups (`PIM-Tier1-*`) last at most 8 h, one shift, with no approval except Intune (the standard also wants it on Exchange and SharePoint: exception E10 in `standards/exception-process.md`). Global Administrator is never a tier group: named people are eligible directly on the role (2 h, Tier-0 approval) | `modules/pim/tiers.tf`, `directory-roles.tf`, `variables.tf` |
| Tier-0 activation can require authentication context **c1** instead of plain MFA (`tier0_activation_auth_context_id`, empty by default). c1 is met only through CA021: the admin phishing-resistant strength, with a fresh sign-in every time. It is switched on only after CA021 is enforced ([graduate-a-ca-policy.md](graduate-a-ca-policy.md), [ADR 0020](../adr/0020-pim-activation-design.md)) | `modules/pim/tiers.tf`, `modules/conditional-access/admins.tf` |
| Eligibility expires: **P365D** on this group and Tier 1, **P180D** on Tier 0. Renewal goes through L2 like a new grant. A direct *active* assignment (bypassing activation) must expire, shortest choice **P15D** | `modules/pim/main.tf`, `tiers.tf`, `variables.tf` |
| Who is eligible is set after HR provisioning by `Set-PimGroupEligibility.ps1`. It has no default person: name the IT/IAM engineer's account explicitly (a clinical manager eligible for User Administrator is the SOD-08 conflict) | `lab/scripts/powershell/post-apply/` |
| User Administrator is in CA002 (phishing-resistant MFA for admins), so an activated user needs FIDO2 / Windows Hello / CBA once CA002 is enforced | `modules/conditional-access/variables.tf` |
| Every completed activation raises Sentinel "Contoso - PIM activation (just-in-time elevation)", Medium. A member added outside PIM raises a separate ITDR incident | `lab/kql/pim-activation.kql`, `lab/kql/pim-group-member-added-outside-pim.kql`, `modules/monitoring` |

No one holds standing admin outside the two break-glass accounts. **Support
never "fixes" a PIM problem by adding a standing member.**

## Triage

| Symptom | Likely cause | Check | Fix | Tier |
|---|---|---|---|---|
| Group not listed under *My roles → Groups* | Not eligible, or the eligibility expired | Eligibility query below | Access request with manager approval → L2 runs `Set-PimGroupEligibility.ps1 -UserPrincipalNames <upn> -WhatIf`, then without `-WhatIf` | L1 → L2 |
| Request stuck "pending approval" | Approval required; approver absent | Request status query below | Ping an approver from the list; a second approver may act. Changing the approver list is a GitHub variable change plus a reviewed apply, not a portal edit. Tier-1 tier groups other than Intune need no approval | L1 |
| MFA fails at activation | `require_mfa_on_activation = true`; no usable method | User's registered methods | Register a method (TAP if needed); never disable the requirement | L1 |
| Blocked after activation with "phishing-resistant" error | CA002 enforced, user has only push/SMS | Sign-in log `ConditionalAccessPolicies` | Register FIDO2 / Windows Hello; this is working as designed | L1 |
| Tier-0 activation asks for a fresh sign-in, then fails | Auth context c1 in force; the user has no method the admin strength accepts (an issued key, when the AAGUID list is set) | Sign-in log for CA021 | Register an issued security key; never switch the tier back to MFA as a fix (that is a reviewed PR) | L1 → L2 |
| Activated but no permissions | Token predates the group change | Sign-in time vs activation time | Sign out and back in; wait a few minutes (verify: propagation time) | L1 |
| Expired mid-task | 4 h cap (2 h for Global Administrator and Privileged Authentication Administrator, 8 h on Tier-1 tier groups) | Activation end time | Re-activate with a new justification. Changing the cap is a PR to `modules/pim` | L1 |
| "I need it permanently" | Request conflicts with zero standing admin | n/a | Decline; route to the exception process in [jml-exception.md](jml-exception.md) with a risk owner | L2 |

## Checks (Graph, `PrivilegedAccess.Read.AzureADGroup` or the PIM-for-Groups read scopes)

```http
GET /identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=groupId eq '{groupId}' and principalId eq '{userId}'
GET /identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=groupId eq '{groupId}'
GET /identityGovernance/privilegedAccess/group/assignmentScheduleRequests?$filter=groupId eq '{groupId}' and principalId eq '{userId}'
```

verify: the least-privileged read scope, the required `$filter` keys and the request `status` values (e.g.
`PendingApproval`, `Provisioned`, `Denied`) against the Graph reference before
first use.

Portal: Entra admin center → ID Governance → Privileged Identity Management →
Groups → Privileged-IAM-Admins → Assignments (Eligible / Active) and *Audit*.
(verify: blade labels in the current portal.)

`lab/scripts/powershell/01-Verify-Baseline.ps1` check 6 WARNs while an
activation is open; that is expected for up to 4 h. A WARN outside a known
activation window is a finding: someone holds standing membership.

## Audit and evidence

- Live alert: the PIM activation incident (Teams card + ServiceNow INC via
  `lab/monitoring/playbook-notify.json`). L1 confirms each one matches a ticket
  or a justification; an activation with no matching work item goes to L2.
- History: `lab/scripts/powershell/Export-EvidencePack.ps1` writes
  `pim_activation_history.json` (who, when, justification) to the gitignored
  `lab/evidence/out/`.

## Escalation

PIM unavailable and admin action cannot wait: escalate to the IAM lead. Use of
break-glass is reserved for when normal admin access is impossible; it pages
High and requires a second-admin review (`lab/kql/break-glass-signin.kql`).
