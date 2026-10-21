# Vault DR drill - 2026-10-20T22:04:26Z

Lab: 3-node Raft cluster on one Docker host, transit auto-unseal (stand-in for Azure Key Vault). vault-1=2.1.1 vault-2=2.1.1 vault-3=2.1.1 

| Measure | Result |
|---|---|
| **RTO** (disks gone -> data served) | **42.1s** (target 300s: PASS) |
| **RPO** (snapshot age at the disaster) | **2.2s** - writes in that window are lost. Set by the drill's own 2 s pause, so it shows the mechanism, not a planning RPO (that is the snapshot interval) |
| Snapshot | dr-20261020T220339Z.snap, 16130 bytes, 0.3s, sha256 `8c21f951fee06677323986e0b31666332bf614980dcd40cb55d4bdc96a3cf30a` |
| Marker written before the snapshot: restored | PASS |
| Policy written before the snapshot: restored | PASS |
| Write made after the snapshot: gone after the restore | PASS |

## Timeline (UTC)

| Time | Step |
|---|---|
| 22:03:40 | markers written on vault-2 (ha-test/dr-marker, policy dr-drill-check) |
| 22:03:40 | snapshot saved in 0.3s (16130 bytes, sha256 8c21f951fee06677...) |
| 22:03:42 | post-snapshot write ha-test/after-snapshot (expected to be LOST) |
| 22:03:53 | DISASTER: vault-1/2/3 containers and volumes destroyed |
| 22:03:55 | new cluster initialised on vault-1 |
| 22:03:56 | snapshot restored (-force) in 0.2s on a one-node cluster |
| 22:04:03 | vault-1 restarted on the restored keyring; vault-2/3 rebuilt and joining |
| 22:04:25 | RECOVERED: data served again (RTO 42.1s) |

Production differences: nodes in three availability zones, TLS, recovery keys 3-of-5 with custodians, snapshots on a schedule to immutable storage (the evidence-store WORM container), and the restore rehearsed on an isolated network.
