# ADR 0001: Entra Cloud Sync vs. Entra Connect Sync

- **Status:** Accepted (lab). DESIGNED: the agent install and sync scope are documented steps (`lab/scripts/dc/README.md`); not yet run against a tenant.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Contoso Health keeps Active Directory for its on-premises workloads. The
lab models this with DC01: Vault rotates real AD accounts over LDAPS, and
the Tier-0 and service accounts live only in AD. HR provisioning writes
workers into department OUs in AD, so something has to carry them up to
Entra ID. Everything downstream depends on that path: dynamic groups,
access packages, Conditional Access and the leaver disable.

Microsoft has two sync engines. They differ in where the engine runs, who
patches it and what it can sync.

## Options considered

1. **Entra Connect Sync.** A Windows server with a SQL database and a
   sync-rules editor; the widest feature set. The server is Tier 0 in its
   own right: it holds the AD connector account and directory-wide
   credentials.
2. **Entra Cloud Sync (chosen).** A lightweight on-premises provisioning
   agent, with the engine and configuration in Entra. Several agents can
   run for availability. Fewer features (see Consequences).
3. **Cloud-only identities, no AD in the user path.** Simplest, but it
   leaves the AD-dependent workloads and the PAM rotation targets without
   workforce accounts.
4. **Both engines side by side** for different OUs. A migration pattern, not
   an end state.

## Decision

Use **Cloud Sync**, scoped by OU to `OU=Workforce` (with its department
sub-OUs) and `OU=Disabled`. `OU=ServiceAccounts` and `OU=PrivilegedAccounts`
are deliberately out of scope, so Tier-0 and service accounts never reach
Entra.

The deciding factor: **one agent does two jobs.** The provisioning agent
serves both Cloud Sync and API-driven inbound provisioning to AD (ADR 0006):
one agent and one gMSA, no sync server and no SQL instance to patch and
protect.

## Consequences

- **AD stays the source of authority.** Entra rejects cloud writes to synced
  attributes, so department, title and enabled state change only through
  HR → AD. That keeps HR as the single writer.
- **The leaver path depends on scoping.** If `OU=Disabled` isn't in scope, a
  leaver moved there falls out of scope and is soft-deleted in Entra instead
  of showing as disabled. It is a configuration invariant to check
  (`lab/scripts/dc/README.md`, step 6).
- **Latency sets a floor on the HR-to-disable SLA.** Users sync on a roughly
  10–20 minute cycle, so `04-Leaver.ps1` revokes sessions directly instead
  of waiting, and urgent cases use *Provision on demand*.
- **Feature gaps to track before production:** device-object sync for hybrid
  join, Exchange hybrid writeback, large-group and object-count limits, and
  custom sync-rule depth (verify each against current Microsoft docs).
- **The agent host is Tier 0.** In the lab it runs on DC01 because the
  budget allows one VM, behind an operator-only NSG with nightly shutdown.
  Production runs at least two agents on dedicated, hardened Tier-0 member
  servers.
- **Single forest.** An acquired clinic's forest would be a second Cloud
  Sync configuration; its Okta users are handled in
  [`okta-migration-runbook.md`](../okta-migration-runbook.md).

## Revisit trigger

- A requirement Cloud Sync can't meet: device sync for hybrid join, Exchange
  hybrid writeback or a complex attribute transform.
- Object or group counts near Cloud Sync's documented limits.
- An acquisition brings a forest with conflicting UPNs or source anchors.

## Evidence

- `lab/terraform/modules/dc-vm/main.tf` (header: HR → AD → Cloud Sync → Entra)
- `lab/scripts/dc/README.md` (step 4: one agent for sync and provisioning;
  step 6: OU scoping and the `OU=Disabled` soft-delete trap)
- `lab/scripts/mock-hr/README.md`, `lab/scripts/demo/README.md` (sync timing)
