# ADR 0029: The HR leaver removes birthright access packages through a Logic App, because the built-in Lifecycle Workflows task skips them

- **Status:** The leave-date leaver workflow is RAN · tenant (2026-11-07/08, capture log E179-E181; worker 100496 in E180): it ran by itself, but it did not remove the birthright package. The Logic App step is BUILT (Terraform `modules/leaver-extension`, tests pass) and waits for the owner's apply approval. It has not run yet.
- **Date:** 2026-11-08
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** after the first tenant run of the Logic App, or 2027-02-08
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.
- **Related:** [ADR 0012](0012-access-review-no-response-and-clinical-lockout.md) (T3 birthright, 72 h mover grace), [ADR 0028](0028-orangehrm-as-the-hris.md) (OrangeHRM leavers)

## Context

Birthright (T3) packages come from automatic assignment policies
(`lab/iga/birthright-rules.json`). When a user stops matching the rule, Entra
does not remove the package at once. It sets the assignment to expire after
`gracePeriodBeforeAccessRemoval`, which is 72 h on purpose (ADR 0012: a
mover keeps the old bundle through the first shifts). For a leaver, 72 h of
standing access is too long. The owner's decision (2026-11-07): the leaver
gap must close by itself, with no hand step.

## What we measured (2026-11-07/08, lab tenant, times in UTC; capture log E180)

| Step | Time |
|---|---|
| HR terminates worker 100496 in OrangeHRM | 23:45:56 |
| HR job: AD disabled, leave date written | 23:47:00 |
| Cloud Sync: Entra disabled, `employeeLeaveDateTime` set | 23:52:37 |
| Automatic policy: assignment set to expire at +72 h | 00:11:38 |
| Scheduled leaver workflow runs (1 h schedule), 5 of 5 tasks "completed" | 01:10:34 |
| **"Remove all access package assignments for user": no entitlement event; the assignment stays `AutoAssignmentInGracePeriod`** | 01:10:47 |
| `adminRemove` request by the lab operator (a hand step) | 04:51:42 |
| Assignment removed (state `Expired`) | 04:55:02 |

## Why the built-in task skips the package

**Observed:** the task reported success but did nothing to an assignment that
an automatic policy made. The audit log has no event at 01:10:47. In the same
tenant, `adminRemove` does remove such an assignment.

**Our reading (not documented by Microsoft, as far as we found on 2026-11-08):**
an automatic policy owns its assignments. Entra adds them and removes them
from the policy rule and its grace period. The built-in task appears to
remove only assignments that a request or an administrator created, and to
leave policy-owned ones to the policy. That would also stop the task from
fighting the policy for a user who still matches the rule. A direct
`adminRemove` is an explicit administrator action, so Entra accepts it.
If Microsoft changes this behaviour, the Logic App step finds nothing left to
remove and does no harm.

## Decision

1. **Keep the scheduled leave-date leaver** (`New-LifecycleWorkflows.ps1
   -IncludeLeaveDateLeaver`). It triggers on `employeeLeaveDateTime` (HR job
   -> AD `msDS-cloudExtensionAttribute2` -> Cloud Sync), for disabled users
   only. It revokes tokens, cancels requests, removes request-based packages,
   groups and licenses.
2. **Add one task to it: "Run a Custom Task Extension"**, right after the
   built-in package task. It calls a consumption Logic App
   (`lab/terraform/modules/leaver-extension`) that:
   - reads the user's assignments with `$expand=assignmentPolicy`;
   - for each **delivered** assignment whose policy has
     `automaticRequestSettings`, sends `adminRemove`;
   - does nothing else.
3. **Identity and permission, the narrowest that does the job:**
   - The Logic App's **system-assigned managed identity**. No secret,
     certificate or connection string exists.
   - The entitlement role **Access package assignment manager**
     (`e2182095-…`), on the **Clinical catalog only**. It does not get
     `EntitlementManagement.ReadWrite.All` (every catalog, policy and role in
     the tenant), and it gets no directory role.
   - Verify on the first run: that Graph honours a catalog role for an
     app-only token. If it answers 403, the fallback is the tenant-wide
     application permission. That is a wider grant, so it needs a new owner
     decision.
4. **Only Lifecycle Workflows can start it.** The trigger has an AADPOP
   policy. It accepts only the Lifecycle Workflows app
   (`ce79fdc4-cd1d-4ea5-8139-e74d7dbe0bb7`, read from the tenant), and only
   for this workflow's ARM path (Learn, "Configure a Logic App for Lifecycle
   Workflow use").
5. **Fire and forget:** no callback. The identity needs no Lifecycle
   Workflows permission. The cost is that the workflow history shows the task
   as done when the Logic App starts. The Logic App's run history and the
   entitlement audit log show the result.

## Options not chosen

- **HR-SYNC removes the package right after the terminate.** The Entra
  account stays enabled for about 7 minutes after the send, so the policy
  could add the package again. HR-SYNC would also need a write permission on
  entitlement management, which mixes HR authority with access authority.
- **Shorter grace period on the birthright policies.** The grace protects
  movers (ADR 0012). A policy has one grace period for all reasons.
- **A person runs `04-Leaver.ps1`.** It works, but it is the hand step the
  owner ruled out.

## Expected timing (to be measured on the first run)

HR click -> Entra disabled: about 7 min (measured). Then up to 1 h (the
tenant schedule, measured run at +1:24:38). Then `adminRemove`: 3 min 20 s
(measured as a hand step). Worst case is about 1.5 h, against 72 h today.

## Cost

Consumption plan, billed per action. A leaver uses a handful of actions.
Between leavers nothing runs and nothing is billed. Well under $5/day.
