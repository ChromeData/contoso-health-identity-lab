# Runbook: help-desk identity verification before a password reset, MFA reset or TAP (L1 / L2)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital).
**Status:** written against the lab design; not yet exercised. There is no
tenant. The help-desk roles are code only: `PIM-Tier1-Helpdesk` holds
Helpdesk Administrator and Authentication Administrator, scoped to the
`AU-Workforce-Standard` administrative unit when `enable_helpdesk_au_scoping`
is on (`modules/pim/helpdesk.tf`; design in ADR 0020; see *Not built*).

## Why this exists

- **Scattered Spider.** The FBI/CISA advisory AA23-320A (published
  2023-11-16, updated 2025-07-29) describes actors who call IT help desks to
  get passwords or MFA tokens reset, then sign in as the victim:
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
- **MGM Resorts, 2023.** MGM's 8-K confirms the incident and about
  $100 million of impact, but it doesn't name the entry vector:
  https://www.sec.gov/Archives/edgar/data/789570/000119312523251667/d461062d8k.htm.
  The help-desk call is public reporting, not MGM's statement, so cite CISA
  for the technique.
- **The failing control is a person.** This runbook removes discretion:
  nothing the caller says decides the outcome.

## Rules

1. **Knowledge never verifies.** Employee ID, date of birth, SSN digits, the
   manager's name and the start date are all in breach data. Use them to
   find the record, never to prove identity.
2. **Never use contact details the caller gives you.** Hang up and call back
   on a number from the HR record. Don't use caller ID, and don't use a phone
   method registered in Entra: the attacker may already own it.
3. **The result never goes to the caller.** A Temporary Access Pass (TAP) or
   a temporary password goes to a verified third party, or is collected in
   person with photo ID.
4. **Urgency or seniority raises the level by one.**
5. **Self-service password reset first.** If the user can still reset with
   their own methods, the help desk resets nothing.
6. **Every action has a ticket** recording the level used and who verified.
   No ticket, no action.

## Verification ladder

| Level | Target | Verification | Delivery |
|---|---|---|---|
| **V1** | Workforce user, password only, can't use self-service reset | Callback on the HR-record number, **and** the manager confirms on the manager's own HR-record number | Temporary password to the manager; must be changed at next sign-in |
| **V2** | Workforce user who has lost every MFA method | V1, plus a live video call with the camera on, or the user at the service desk with photo ID | One-time 60-minute TAP, to the manager or in person. The user registers a phishing-resistant method within 10 minutes of signing in with it |
| **V2-C** | Clinician on shift, key lost, patient care waiting | The charge nurse or house supervisor, called back on the unit's directory number, confirms the clinician in person and checks the badge photo | One-time 60-minute TAP to the charge nurse. A replacement key from unit stock is registered on the spot. Target: back at work in ≤ 15 minutes |
| **V3** | Any admin role, PIM-eligible user, member or owner of a role-assignable group, or VIP | An IAM L2 engineer checks government photo ID against HR in person, plus a manager callback. Remote is allowed only by live video showing the ID, plus the callback, with a second IAM engineer's approval | TAP in person only |
| none | Break-glass (`bg-admin-NN`) | Never through the help desk | [break-glass-drill.md](break-glass-drill.md) custody procedure |

Entra Verified ID Face Check would replace the video check for remote V3. It
is out of scope under ADR 0011, and remote privileged recovery is that
ADR's revisit trigger.

## What each role can and cannot do

- **Service desk (V1–V2-C): Authentication Administrator,** eligible through
  PIM and scoped to an administrative unit of ordinary workforce users. It's
  a Tier-1 role: activation needs a justification and lasts at most the
  Tier-1 cap in `modules/pim` (8 hours, one shift; the privileged-access
  standard's target is 4).
  - **What it covers:** authentication methods (including TAP) and
    passwords, for non-admin users only.
  - **What Microsoft's role tables put out of its reach:** Global
    Administrators, most admin roles, members and owners of role-assignable
    groups (so every eligible member of `Privileged-IAM-Admins`), and users
    in a restricted management administrative unit.
  - **Not used in this runbook:** its disable, delete and restore rights.
- **IAM L2 (V3 only): Privileged Authentication Administrator.** It can act
  on any user, Global Administrators included, so it's Tier 0. It is
  eligible through PIM (`PIM-Tier0-Privileged-Auth-Admins`), with approval,
  a ticket number and a 2-hour maximum.
- **Never a help-desk role: Authentication Policy Administrator,** which
  changes the methods policy itself.
- **VIPs with no admin role** aren't covered by that role scoping. Put them
  in a restricted management administrative unit. That takes Entra ID P1
  for each AU administrator, and its members drop out of PIM, entitlement
  management, Lifecycle Workflows and access reviews, so VIP leavers and
  reviews become manual (Microsoft Learn, restricted management
  administrative units, checked 2026-10-20).
  - **In the lab (RAN · tenant, 2026-11-05, capture E16c):** `RMAU-VIP`
    holds Helen Carter (Chief Nursing Officer) and Joan Ferris (IT
    Director). Only `PIM-Tier0-Privileged-Auth-Admins` holds Helpdesk and
    Authentication Administrator at its scope, so resetting a VIP is a
    Tier-0 activation with someone else's approval, a ticket and a time
    limit - never the service desk. The service desk's own AU,
    `AU-Workforce-Standard`, excludes both by HR employee id
    (`helpdesk_au_excluded_employee_ids`), so they are not on its member
    list either. Nobody is eligible for that Tier-0 group yet: until
    someone is, a VIP reset means a Global or Privileged Role
    Administrator granting that eligibility first (an audited change).
    Cloud Sync still updates RMAU members (on-demand provisioning of
    Helen, 2026-11-05: "updated in Microsoft Entra ID").
- **The help desk never:**
  - adds a phone method on the caller's word
  - issues a multi-use TAP
  - excludes anyone from Conditional Access
  - touches break-glass
- **The scripts follow the same split.** `07-Passwordless-Rollout.ps1
  -IssueTapFor` documents it and refuses break-glass.

## Procedure

1. Open the ticket. Record the claimed identity, the request, and where the
   callback number came from.
2. Check the target. Does the user hold an admin role, PIM eligibility or
   membership of a role-assignable group? If so, the case is V3: transfer it
   to IAM L2.
3. End the inbound call. Call back on the HR-record number. Verify at the
   right level, and record the level and the verifier.
4. Act in this order:
   1. Delete the lost method.
   2. Issue the TAP or the temporary password.
   3. If a device was lost or stolen, revoke sessions
      (`Revoke-MgUserSignInSession`).

   A session started with a TAP can outlive the TAP. Sign-in frequency
   bounds it.
5. Deliver as the table says. Close the ticket only when a new
   phishing-resistant method is registered and the TAP has been used or
   deleted.

## Logging and the detection that watches it

- **Audit trail.** Every admin change to another user's methods is written
  to `AuditLogs` as "Admin registered security info", "Admin updated
  security info" or "Admin deleted security info".
- **The detection.** `auth-method-changed-by-admin.kql` raises an incident
  for each change. Severity is High when the target is privileged, matched
  by object ID: break-glass, members and eligible members of the PIM
  groups, and directory-role holders (the list comes from
  `Find-ShadowAdmins.ps1`). It is Medium otherwise. A TAP issuance is
  flagged so it can be matched to the joiner or recovery ticket.
- **Ticket matching.** SOC L1 matches every incident to a ticket within one
  business hour. If there's no ticket, or the verifier doesn't match, treat
  the agent and the target under
  [compromised-identity.md](compromised-identity.md).
- **QA.** Each month, QA samples 10 tickets per agent against the level the
  target required.

## Metrics

Fill these in after running.

- Resets with a matching ticket and verifier. Target: 100%.
- Callbacks that didn't reach the claimed person. Each one is reviewed as a
  possible attack.
- Median V2-C restore time. Target: 15 minutes or less.

## Not built

- **Tenant-time steps, both RAN · tenant (2026-11-05, E16c):** the
  provider can't create dynamic AU membership, so the
  `AU-Workforce-Standard` rule is a Graph PATCH of the body
  `modules/pim` renders (`pim_workforce_au_membership_body`, now with the
  VIP exclusion). The restricted management administrative unit for VIPs
  is a Graph call too, because the provider can't set that property:
  `post-apply/New-RestrictedAdminUnit.ps1 -UseAzureCliToken
  -ResponderGroupName PIM-Tier0-Privileged-Auth-Admins`, run as the lab
  operator. Not yet exercised: a real reset attempt by `adm-raj.patel`
  against a VIP (expected: refused).
- **Applied, report-only:** CA002 now lists Microsoft's template admin
  roles plus the lab's tier extras (Authentication Administrator and
  Privileged Authentication Administrator included), and can also target
  the admin groups (`admin_scope_group_object_ids`). Conditional Access
  doesn't enforce its directory-role condition for
  administrative-unit-scoped role assignments (a Microsoft Learn warning,
  checked 2026-10-20), so AU-scoped help-desk admins are covered only
  through their group. CA002 is report-only, so none of this
  requires phishing-resistant MFA yet.
- **Nothing here has run:** no ticket has been matched to an incident, and
  no QA sample exists.
