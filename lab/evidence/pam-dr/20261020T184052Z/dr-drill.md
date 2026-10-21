# Vault DR drill - 2026-10-20T18:44:26Z

Lab: 3-node Raft cluster on one Docker host, transit auto-unseal (stand-in for Azure Key Vault). vault-1=2.1.1 vault-2=2.1.1 vault-3=2.1.1 

| Measure | Result |
|---|---|
| **RTO** (disks gone -> data served) | **40.5s** (target 300s: PASS) |
| **RPO** (snapshot age at the disaster) | **2.2s** - writes in that window are lost |
| Snapshot | dr-20261020T184341Z.snap, 16121 bytes, 0.3s, sha256 `a8ad500ffe21774e3393dc77660ed2c4736f30c19b2d1990477e3fb62ce95a97` |
| Marker written before the snapshot | PASS |
| Policy written before the snapshot | PASS |
| Write made after the snapshot is gone | PASS |

## Timeline (UTC)

| Time | Step |
|---|---|
| 18:43:42 | markers written on vault-3 (ha-test/dr-marker, policy dr-drill-check) |
| 18:43:42 | snapshot saved in 0.3s (16121 bytes, sha256 a8ad500ffe21774e...) |
| 18:43:44 | post-snapshot write ha-test/after-snapshot (expected to be LOST) |
| 18:43:54 | DISASTER: vault-1/2/3 containers and volumes destroyed |
| 18:43:56 | new cluster initialised on vault-1 |
| 18:43:57 | snapshot restored (-force) in 0.2s on a one-node cluster |
| 18:44:04 | vault-1 restarted on the restored keyring; vault-2/3 rebuilt and joining |
| 18:44:25 | RECOVERED: data served again (RTO 40.5s) |

Production differences: nodes in three availability zones, TLS, recovery keys 3-of-5 with custodians, snapshots on a schedule to immutable storage (the evidence-store WORM container), and the restore rehearsed on an isolated network.
