# ADR 0019: PAM vault high availability and disaster recovery

- **Status:** Accepted (lab). **RAN · harness** (local Docker), with hashed run records: a separate 3-node rehearsal cluster holding test markers, leader failover, a timed snapshot-restore drill and a rolling upgrade. It is not the single-node vault that holds the PAM flow's AD credentials. Not built on Azure: no Key Vault seal, no snapshot schedule, no second site. **Partly supersedes ADR 0007** on the production unseal.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The vault is Tier 0 twice over: it holds the Tier-0 AD passwords, rotated at
every check-in so nobody knows them, and every brokered DC session starts
with a check-out. If the vault is down, the only way into a DC is the RID-500
break-glass account; if its data is lost, every password it rotated is lost
with it. The lab vault is one node with one unseal key (R09). This ADR
decides how a self-run vault survives losing a node, a disk or the whole
cluster. Whether to buy SaaS PAM instead is `vendor-evaluation.md`; if SaaS
wins, this ADR is superseded.

## Options considered

1. **A single node with nightly backups.** Every patch or crash is an outage
   of Tier-0 access, and restore is manual.
2. **A Raft cluster with Shamir unseal.** A restarted node stays sealed until
   key holders gather: at 03:00 during an incident, three custodians. HA in
   name only.
3. **An external storage backend (Consul).** A second distributed system to
   run and secure.
4. **Vault Enterprise replication to a second region.** The answer for
   losing a site, but it needs a licence; recorded as the revisit path.
5. **Three Raft voters, auto-unseal from a key outside the cluster, and a
   timed snapshot-restore drill (chosen).**

## Decision

- **Cluster.** Lab: three Raft voters, tolerating one failed node.
  **Production: five voters across three zones (2 + 2 + 1),** which survives
  two failed nodes or a whole zone (HashiCorp's reference architecture).
  Autopilot health gates every change.
- **Unseal.** Lab: a transit "unsealer" Vault stands in. Production:
  `seal "azurekeyvault"` with an HSM-backed key in a zone-redundant Key
  Vault, reached by managed identity, with soft-delete and purge protection,
  and recovery keys split 3-of-5 between named custodians.
- **Snapshots** with `vault operator raft snapshot save`, sha256 recorded;
  in production on a schedule to the WORM evidence store (not built).
- **Restore order, learned by running it.** Restore with `-force` into a new
  one-node cluster, restart it, then let the other two join. In any other
  order the Raft TLS keyring disagrees and the cluster splits on the next
  restart. **A restore brings back the vault as it was:** recovery keys,
  root tokens and leases valid at the snapshot work again, so before
  check-outs reopen, revoke any restored root token and the check-out
  path's tokens and leases, and redo any rekey made since. The drill doesn't
  do this yet.
- **Upgrades:** snapshot first; followers one at a time, then the leader
  after `operator step-down`. Rollback is a snapshot restore on the old
  version.
- **Drill pass criteria:** the marker and policy written before the snapshot
  are restored, the write made after it is gone, and RTO is within target
  (`--target-rto`, default 300 s).

## Consequences

- **In a PAM vault, RPO is about passwords, not just data.** A password
  rotated after the last snapshot is live in AD but missing from the
  restored vault. After every restore: `reconcile.sh --verify --strict`,
  then rotate each account that fails (Vault resets it through the rotator
  account, without the old password). **The drill doesn't exercise this
  yet:** it writes KV markers, not LDAP-engine credentials.
- **The seal key is the crown jewel.** Deleting it bricks every node and
  snapshot; hence purge protection and an admin path separate from the
  vault's own operators.
- **Laptop timings say nothing about latency between zones;** re-measure in
  production.
- **R09 stays open for the lab stack:** the PAM scripts still use the
  single-node vault.

## How it is measured

| Measure | Source | Result |
|---|---|---|
| Leader killed → new leader accepts a write | `vault-ha.sh failover` | 2–4 s (five laptop runs, 2026-10-20) |
| Killed node rejoins as a healthy voter | Same | 1–4 s (same runs) |
| RTO: all nodes and disks gone → data served again | `dr-drill.sh` report | **40.5 s, 32.5 s and 42.1 s** in three hashed drills (`lab/evidence/pam-dr/20261020T184052Z/`, `…T204851Z/`, `…T220031Z/`), all PASS against a 300 s target, for a rehearsal cluster holding one KV marker and one policy |
| RPO: snapshot age at the disaster | Same | 2.2 s in each drill, set by the drill's own 2 s pause: it shows the mechanism, not a planning RPO. Production RPO is the snapshot interval (fill in once a schedule exists) |
| Accounts failing verify after a restore | `reconcile.sh --verify` | Not yet drilled |

Each drill report (`dr-drill.json` / `.md`, `SHA256SUMS`) was written by
`test/run-all.sh --publish` and re-checks with `dr-drill.sh --verify DIR`.

## Revisit trigger

- A SaaS PAM is chosen: supersede this ADR.
- A drill fails or misses its RTO target.
- A Vault Enterprise licence: add replication to a second region.
- A Vault upgrade changes the restore procedure.
- The business-continuity plan sets an RPO shorter than the snapshot
  interval.

## Evidence

- `lab/pam/vault-ha.sh` (up, status, failover, upgrade), `lab/pam/dr-drill.sh`
- `lab/pam/docker-compose.ha.yml`, `lab/pam/ha/`
- `lab/pam/README.md` §8 (timings, Key Vault seal, upgrade runbook)
- `lab/pam/test/e2e.sh` section (o) (HA/DR assertions)
- `lab/evidence/pam-dr/` (hashed drill reports) and `lab/evidence/pam/`
  (the runs they came from)
- `lab/pam/reconcile.sh` (`--verify`)

## Sources (checked 2026-10-20)

- https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture
