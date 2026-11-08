# ADR 0001: Entra Cloud Sync vs. Entra Connect Sync

- **Status:** Accepted (lab). RAN · tenant: Cloud Sync carries AD changes to Entra ID since 2026-10-28 (capture log E52: a mover and a timed leaver through DC01 and the provisioning agent).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

In the scenario, Contoso Health keeps Active Directory for its on-premises
workloads. The lab models this with DC01: Vault rotates real AD accounts over
LDAPS, and the Tier-0 and service accounts live only in AD. HR provisioning
writes workers into department OUs in AD, so something has to carry those
users up to Entra ID. Everything downstream depends on that path: dynamic
groups, access packages, Conditional Access and the leaver disable.

There are two Microsoft sync engines. They differ in where the engine runs,
who patches it, and what it can sync.

## Options considered

1. **Entra Connect Sync.** A Windows server running the sync engine with a
   SQL database (LocalDB or full SQL), and a sync-rules editor for complex
   attribute flows. It has the widest feature set. The server is Tier 0 in
   its own right: it holds the AD connector account and directory-wide
   credentials. Configuration lives on that server.
2. **Entra Cloud Sync (chosen).** A lightweight provisioning agent
   on-premises, with the configuration and engine in Entra. You can run
   several agents for availability, and it supports disconnected forests
   (verify: current multi-forest and agent-count guidance). It has fewer
   features than Connect Sync (see Consequences).
3. **Cloud-only identities, with no AD in the user path.** HR provisions
   straight into Entra through API-driven provisioning to Entra ID. That's
   simplest, but it leaves the AD-dependent workloads and the PAM rotation
   targets without workforce accounts.
4. **Both engines side by side** for different OUs or forests. This is a
   migration pattern, not an end state (verify: supported coexistence
   scoping).

## Decision

Use **Cloud Sync**, scoped by OU to `OU=Workforce` (with its department
sub-OUs) and `OU=Disabled`. `OU=ServiceAccounts` and `OU=PrivilegedAccounts`
are deliberately out of scope, so Tier-0 and service accounts never reach
Entra.

The deciding factor is that **one agent does two jobs.** The provisioning
agent on DC01 serves both Cloud Sync and API-driven inbound provisioning to
AD (ADR 0006). That's one agent and one gMSA, with no separate sync server
and no SQL instance to patch and protect.

## Consequences

- **Source of authority stays in AD.** Entra rejects cloud writes to synced
  attributes, so department, title and enabled state change only through
  HR → AD (`lab/scripts/demo/Reset-DemoState.ps1`). This is intended: it
  keeps HR as the single writer.
- **The leaver path depends on scoping.** If `OU=Disabled` isn't in scope, a
  leaver moved there falls out of scope and is **soft-deleted** in Entra
  instead of showing as disabled (`lab/scripts/dc/README.md`, step 6).
  Treat this as a configuration invariant to check, not as tribal knowledge.
- **Latency sets a floor on the HR-to-disable SLA.** Users sync on a roughly
  10–20 minute cycle (`lab/scripts/demo/README.md`). `04-Leaver.ps1` revokes
  sessions directly instead of waiting for sync, and the demo uses
  *Provision on demand*.
- **Feature gaps to track** (verify each against current Microsoft docs
  before production):
  - device-object sync for hybrid join
  - Exchange hybrid writeback
  - large-group and object-count limits
  - custom sync-rule depth compared with Connect Sync

  Pass-through authentication isn't part of this decision. The sign-in
  method is covered in ADR 0009.
- **Risk: the agent host is Tier 0.** In the lab the agent runs on DC01
  because the budget allows one VM. **Compensating control:** NSG access
  from the operator's IP only, and auto-shutdown (`lab/terraform/modules/dc-vm`).
  Production would run at least two agents on dedicated, hardened Tier-0
  member servers.
- **Single-forest lab.** An acquired clinic's forest would be added as a
  second Cloud Sync configuration. The lab doesn't build this. The clinic's
  Okta users are handled in `lab/docs/okta-migration-runbook.md`.

## Revisit trigger

- A requirement Cloud Sync can't meet, such as device sync for hybrid join,
  Exchange hybrid writeback or a complex attribute transform.
- Object or group counts get near Cloud Sync's documented limits.
- An acquisition brings a forest with conflicting UPNs or source anchors.
- Microsoft changes the agent or engine support roadmap.

## Evidence

- `lab/terraform/modules/dc-vm/main.tf` (header: HR → AD → Cloud Sync → Entra)
- `lab/scripts/dc/README.md` (step 4: one agent for Cloud Sync and API-driven
  provisioning; step 6: OU scoping and the `OU=Disabled` soft-delete trap)
- `lab/scripts/mock-hr/README.md` (one-time setup, step 1: provisioning to on-premises AD)
- `lab/scripts/demo/README.md` (sync timing table)
- `lab/docs/architecture.md` (story step 1)
