# ADR 0037: The leaver Logic App gets EntitlementManagement.ReadWrite.All, because app-only callers cannot use catalog-scoped roles

- **Status:** BUILT (PR #281: `modules/leaver-extension`, tests pass). Waits for the owner's round-4 apply. The finding that led to it is RAN · tenant (2026-11-08, capture log E183).
- **Date:** 2026-11-08
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer). Granted at the owner's discretion (decision 2026-11-08).
- **Next review:** after the first successful leaver run with this permission, or 2027-02-08
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.
- **Partly supersedes:** [ADR 0029](0029-leaver-removes-birthright-packages-through-a-logic-app.md) decision 3 (the catalog role as the only grant).

## Context

ADR 0029 gave the leaver Logic App's managed identity the narrowest grant we
knew: the entitlement role "Access package assignment manager" on the
Clinical catalog only. It said to verify on the first run whether Graph
honours a catalog role for an app-only token.

**It does not (E183).** Round 3 applied the Logic App. Lifecycle Workflows
called it twice (on demand at 22:34:09Z, on schedule at 23:11:07Z). In both
runs, `GET /identityGovernance/entitlementManagement/assignments` returned
**403** "User is not authorized to perform the operation". The catalog role
assignment exists (Graph read). Entitlement management's catalog roles work
for a signed-in user. For an app-only caller, Graph checks the application
permission in the token, and this token had none. The birthright package was
not removed.

## Decision

1. The identity gets the Microsoft Graph **application permission
   `EntitlementManagement.ReadWrite.All`**
   (`azuread_app_role_assignment.entitlement_management_readwrite`), read
   through the same 90 s replication wait.
2. The catalog role stays. It has no effect for this caller. Removing it
   would orphan the assignment that run 42527718010 created (PR #281 imports
   it into state).

## The risk, and why it is bounded

The permission is tenant-wide: every catalog, policy and assignment. The
bounds are in what can start the Logic App and what it does:

- **Who can call it:** only Lifecycle Workflows. The trigger's AADPOP policy
  accepts only a Proof-of-Possession token from the Lifecycle Workflows app
  (`ce79fdc4-…`) for this workflow's ARM path. The stored trigger URL has no
  SAS signature (PR #281). There is no secret anywhere.
- **What it does:** it reads the assignments of the one subject the workflow
  passes in, and for each **delivered** assignment whose policy is automatic,
  it sends `adminRemove`. It sends nothing else (pinned by the module test).
- **Who can change it:** changing the Logic App definition needs Azure write on
  RG-IDENTITY-LAB, which goes through the apply gate. The lab operator is
  read-only outside an owner-opened session (ADR 0030).
- **Residual risk:** anyone who can edit the Logic App, or who controls
  Lifecycle Workflows (Lifecycle Workflows Administrator), can make it remove
  any access package assignment. Removal is the worst it can do: it cannot
  create assignments, change policies or grant roles through its code path.

## Monitoring

**DESIGNED (not built here):** a Sentinel rule on `AuditLogs` where the
initiator is this identity and the operation is not an entitlement-management
removal, or the removal's target is not a user who was disabled in the
previous hour:

```kusto
AuditLogs
| where TimeGenerated > ago(1h)
| where tostring(InitiatedBy.app.servicePrincipalId) == "<leaver Logic App principal id>"
| where Category != "EntitlementManagement"
    or OperationName !has "remove"
```

It is not added now because each new rule in this lab needs its own flag and
a kusto-harness run before Sentinel accepts it (`modules/monitoring/itdr_v4.tf`
header). It is a follow-up, not a precondition.

## Options not chosen

- **`EntitlementManagement.Read.All` + a narrower write permission.** Graph
  has no application permission narrower than ReadWrite.All for
  `assignmentRequests` (adminRemove), as far as we found on 2026-11-08.
- **Keep only the catalog role.** It does not work for app-only callers (E183).
- **A person runs `04-Leaver.ps1`.** It works, but it is the hand step the
  owner ruled out.
