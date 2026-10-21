# Vault DR drill - 2026-10-20T20:51:58Z

Lab: 3-node Raft cluster on one Docker host, transit auto-unseal (stand-in for Azure Key Vault). vault-1=2.1.1 vault-2=2.1.1 vault-3=2.1.1 

| Measure | Result |
|---|---|
| **RTO** (disks gone -> data served) | **32.5s** (target 300s: PASS) |
| **RPO** (snapshot age at the disaster) | **2.2s** - writes in that window are lost. Set by the drill's own 2 s pause, so it shows the mechanism, not a planning RPO (that is the snapshot interval) |
| Snapshot | dr-20261020T205122Z.snap, 16130 bytes, 0.3s, sha256 `2a73529722ce446684df7cf44cae5a46f7490cb0bb4eccf9a6a12925d3383175` |
| Marker written before the snapshot: restored | PASS |
| Policy written before the snapshot: restored | PASS |
| Write made after the snapshot: gone after the restore | PASS |

## Timeline (UTC)

| Time | Step |
|---|---|
| 20:51:22 | markers written on vault-3 (ha-test/dr-marker, policy dr-drill-check) |
| 20:51:22 | snapshot saved in 0.3s (16130 bytes, sha256 2a73529722ce4466...) |
| 20:51:25 | post-snapshot write ha-test/after-snapshot (expected to be LOST) |
| 20:51:26 | DISASTER: vault-1/2/3 containers and volumes destroyed |
| 20:51:28 | new cluster initialised on vault-1 |
| 20:51:28 | snapshot restored (-force) in 0.2s on a one-node cluster |
| 20:51:35 | vault-1 restarted on the restored keyring; vault-2/3 rebuilt and joining |
| 20:51:57 | RECOVERED: data served again (RTO 32.5s) |

Production differences: nodes in three availability zones, TLS, recovery keys 3-of-5 with custodians, snapshots on a schedule to immutable storage (the evidence-store WORM container), and the restore rehearsed on an isolated network.
