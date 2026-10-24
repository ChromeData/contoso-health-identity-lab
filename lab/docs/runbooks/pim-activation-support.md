# Runbook: PIM activation support (L1 / L2)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). **Status:**
written against the lab code; not yet exercised (no tenant deployed).

## The design you are supporting

Role-assignable groups hold the roles; *membership* is the just-in-time
part, activated through PIM for Groups with MFA and a justification.
`Privileged-IAM-Admins` (User Administrator): approval, at most 4 h. Eight
Tier-0 groups: approval and a ticket number, at most 4 h (2 h for
Privileged Authentication Administrator). Eight Tier-1 groups: one 8-hour
shift, approval only for Intune and the IGA group. Global Administrator is
never a group: named people are eligible directly (2 h, Tier-0 approval).
Eligibility expires (Tier 0 180 days, Tier 1 365 days), and every completed
activation alerts the SOC (`pim-activation.kql`). Full design and caps:
[ADR 0002](../adr/0002-pim-for-groups-vs-direct-role-eligibility.md).

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
