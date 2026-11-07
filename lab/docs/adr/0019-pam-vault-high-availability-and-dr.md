# ADR 0019: PAM vault high availability and disaster recovery

- **Status:** **Superseded by [ADR 0027](0027-microsoft-native-pam.md)** (2026-11-06): Azure Key Vault is a managed service with built-in replication, so the lab needs no self-run vault cluster. Kept as the record of the rehearsal. Was: Accepted (lab). **RAN · harness** (local Docker) on 2026-10-20: a separate 3-node rehearsal cluster holding test markers, leader failover, a timed snapshot-restore drill and a rolling-upgrade rehearsal. It is not the single-node vault that holds the PAM flow's AD credentials. Not built on Azure: no Key Vault seal, no snapshot schedule and no second site. **Partly supersedes ADR 0007** on the production unseal: auto-unseal only, because Shamir is rejected below.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The vault is Tier 0 twice over:

- **It holds the Tier-0 AD passwords.** They are rotated at every check-in,
  and nobody knows them.
- **Every brokered DC session starts with a check-out.**

So if the vault is down, nobody can reach a DC through the sanctioned path,
and the only way in is the RID-500 break-glass account. If the vault's data
is lost, every password it rotated is lost with it.

The lab vault is a single node with one unseal key (risk R09). ADR 0007
chose Vault as the PAM vault stand-in and left the production unseal open
(Shamir or auto-unseal). This ADR
decides how a self-run vault survives losing a node, a disk or the whole
cluster. Whether to buy a SaaS PAM instead is a separate question, in
`vendor-evaluation.md`; if SaaS wins, this ADR is superseded.

## Options considered

1. **A single node with nightly backups.** Simple. Rejected: every patch or
   crash is an outage of Tier-0 access, and restore is manual.
2. **A Raft cluster with Shamir unseal.** Rejected: a node that restarts
   stays sealed until key holders gather. At 03:00, during an incident,
   that means finding three custodians. It is HA in name only.
3. **An external storage backend (Consul).** Rejected: it is a second
   distributed system to run and secure. HashiCorp recommends integrated
   storage (verify).
4. **Vault Enterprise replication to a second region.** This is the answer
   for losing a whole site, but it needs a licence the lab doesn't have.
   It is recorded as the revisit path.
5. **Three Raft voters, auto-unseal from a key outside the cluster, and a
   timed snapshot-restore drill (chosen).**

## Decision

- **Cluster.** In the lab, three Raft voters with `performance_multiplier =
  1` and `retry_join` to every peer; they tolerate one failed node.
  **Production: five voters across three zones (2 + 2 + 1),** the size
  HashiCorp's reference architecture calls ideal for integrated storage.
  It survives two failed nodes or a whole zone; three voters survive one
  node and not a zone. Autopilot health is the gate before and after every
  change.
- **Unseal.** In the lab, a transit "unsealer" Vault stands in. In
  production it is `seal "azurekeyvault"`:
  - an HSM-backed key in a zone-redundant Key Vault, reached by managed
    identity
  - soft-delete and purge protection on that vault
  - recovery keys split 3-of-5 between named custodians
- **Snapshots.** `vault operator raft snapshot save`, with the sha256
  recorded. In production, they run on a schedule to the evidence store's
  WORM container. Not built; verify whether Vault Community has a built-in
  scheduler.
- **Restore procedure, learned by running it.**
  - Restore with `-force` into a new one-node cluster.
  - Restart that node, then let the other two join.
  - In any other order, the Raft TLS keyring disagrees between nodes and
    the cluster splits on the next restart (`tls: unrecognized name`).
  - **After a restore, the vault is as it was at the snapshot.** Recovery
    keys and any root token valid then work again, and tokens revoked after
    the snapshot come back. Before check-outs reopen: revoke any restored
    root token, redo any recovery-key rekey made after the snapshot, and
    revoke the tokens and leases issued through the check-out path. The
    drill doesn't do this yet (verify: the commands for the version run).
- **Upgrades.** Take a snapshot first. Upgrade the followers one at a time,
  then the leader after `operator step-down`. Rollback means restoring the
  snapshot on the old version, because a node can't be downgraded in place.
- **Drill pass criteria.** The marker and policy written before the
  snapshot are restored, the write made after it is gone, and RTO is within
  the target (`--target-rto`, default 300 s).

## Consequences

- **In a PAM vault, RPO is about passwords, not just data.** Any password
  the vault rotated after the last snapshot is live in AD but missing from
  the restored vault, so the vault would hand out stale passwords. After
  every restore: run `reconcile.sh --verify --strict`, then rotate each
  account that fails. Vault resets it through the rotator account and
  doesn't need the old password. **The drill doesn't exercise this yet.** It
  writes KV markers to a separate compose project, not the LDAP engine.
- **The seal key is now the crown jewel.** Deleting it bricks every node and
  every snapshot. Hence purge protection, and an admin path separate from
  the vault's own operators.
- **Laptop timings say nothing about latency between zones.** Re-measure in
  production.
- **R09 stays open for the lab stack.** The PAM scripts still use the
  single-node lab Vault; the HA cluster is a separate rehearsal.

## How it is measured

| Measure | Source | Result |
|---|---|---|
| Leader killed → new leader accepts a write | `vault-ha.sh failover` | 2–4 s (five laptop runs, 2026-10-20) |
| Killed node rejoins as a healthy voter | Same | 1–4 s (same runs) |
| RTO: all nodes and disks gone → data served again | `dr-drill.sh` report | 32.5, 40.5 and 42.1 s in the three hashed drills (`lab/evidence/pam-dr/`), on the laptop, for a rehearsal cluster holding one KV marker and one policy; target 300 s |
| RPO: snapshot age at the disaster | Same | A few seconds, set by the drill's own timing, so not a planning number. Production RPO is the snapshot interval (fill in once a schedule exists) |
| Accounts failing verify after a restore | `reconcile.sh --verify` | 0 after rotation. Not yet drilled |

The timings are the ones recorded in `lab/pam/README.md` §8. The drill's
own reports are committed as hashed run records in `lab/evidence/pam-dr/`
(`dr-drill.json` / `.md`, `SHA256SUMS`), written by `test/run-all.sh
--publish` and re-checked with `dr-drill.sh --verify DIR`. Three records,
all PASS against the 300 s target: `20261020T184052Z` (RTO 40.5 s),
`20261020T204851Z` (RTO 32.5 s) and `20261020T220031Z` (RTO 42.1 s), each
with RPO 2.2 s. That RPO is set by the drill's own 2 s pause between the
snapshot and the disaster, so it shows the mechanism, not a planning RPO. The break-glass drill log in `lab/evidence/drills/` is a separate log
with different columns.

## Revisit trigger

- A SaaS PAM is chosen: supersede this ADR.
- A drill fails, or misses its RTO target.
- A Vault Enterprise licence becomes available: add replication to a
  second region.
- A Vault upgrade changes the restore procedure.
- The business-continuity plan sets an RPO shorter than the snapshot
  interval.

## Evidence

- `lab/pam/vault-ha.sh` (up, status, failover, upgrade)
- `lab/pam/dr-drill.sh` (timed drill and its RTO/RPO report)
- `lab/pam/docker-compose.ha.yml`, `lab/pam/ha/vault-node.hcl`,
  `lab/pam/ha/unsealer.hcl`, `lab/pam/ha/ha-lib.sh`
- `lab/pam/README.md` §8 (recorded timings, Key Vault seal, upgrade
  runbook)
- `lab/pam/test/e2e.sh`, section (o) (HA/DR assertions)
- `lab/evidence/pam-dr/` (hashed DR drill reports) and `lab/evidence/pam/`
  (the e2e run records they came from)
- `lab/pam/reconcile.sh` (`--verify`)
- `lab/docs/risk-register.md` (R09)

## Sources (checked 2026-10-20)

- https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture
  (five nodes across three availability zones; survives the loss of two
  nodes or one zone)
