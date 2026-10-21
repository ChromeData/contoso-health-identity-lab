# PAM reconciliation report

Generated 2026-10-20T18:42:44Z from `out/e2e/discovery-latest.json` (discovery 2026-10-20T18:42:41Z) and Vault. Lab evidence: account names only, no secrets.

| KPI | Value |
|---|---|
| Privileged accounts discovered | 14 |
| Eligible for vaulting (excl. documented exceptions) | 6 |
| Vaulted | 6 (100% of eligible) |
| Rotated within policy | 6 (100% of vaulted) |
| Verified (vaulted password binds) | not run (--verify) |
| Documented exceptions | 8 |
| Held (unresolved dependencies) | 0 |
| **GAP** (not vaulted, no exception) | **0** |
| ORPHAN (in Vault, not in AD) | 0 |

| Account | Tier | Status | Vault object | Last rotation | Policy | Within | Verified | Exception / note | Next action |
|---|---|---|---|---|---|---|---|---|---|
| Administrator | tier0 | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: RID-500 built-in: break-glass, held offline under dual control, rotated by the break-glass drill | owner review (see exception) |
| svc-legacy-da | tier0 | EXCEPTION | - | - | - | n/a | n/a | Tier-0 account with an SPN (Kerberoastable domain admin): remove from Tier-0 groups or move to a gMSA before vaulting | owner review (see exception) |
| svc-vault-rotator | tier0 | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: Vault's own bind (reconcile) account: rotated by ldap/rotate-root, never a static role | owner review (see exception) |
| t0-never-admin | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (never logged on, created 200d ago (grace 30d)): disable, then remove from groups | owner review (see exception) |
| t0-stale-admin | tier0 | EXCEPTION | - | - | - | n/a | n/a | stale privileged account (last logon 400d ago (>= 90d)): disable, then remove from groups | owner review (see exception) |
| tier0-admin-01 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T18:42:07Z | on check-in; idle <= 30d | yes | skipped | - | - |
| tier0-admin-02 | tier0 | VAULTED | library:tier0-admins | AD pwdLastSet 2026-10-20T18:42:10Z | on check-in; idle <= 30d | yes | skipped | - | - |
| t1-srvadmin-01 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T18:42:24Z | on check-in; idle <= 30d | yes | skipped | - | - |
| t1-srvadmin-02 | tier1 | VAULTED | library:tier1-admins | AD pwdLastSet 2026-10-20T18:42:20Z | on check-in; idle <= 30d | yes | skipped | - | - |
| krbtgt | svc | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: KDC account: reset twice with the krbtgt reset procedure (runbook), never vaulted | owner review (see exception) |
| svc-backup | svc | VAULTED | static:svc-backup | 2026-10-20T18:41:51.137434652Z | every 24h | yes | skipped | - | - |
| svc-pam-discovery | svc | EXCEPTION | - | - | - | n/a | n/a | policy exclusion: read-only discovery bind account: credential in Key Vault for discover.sh | owner review (see exception) |
| svc-sql01 | svc | VAULTED | static:svc/svc-sql01 | 2026-10-20T18:42:38.569404032Z | every 720h | yes | skipped | onboard-forced by ops-alice at 2026-10-20T18:42:38Z: CHG0031337: DBA updates the MSSQLSERVER logon in the window | - |
| former-admin-01 | - | EXCEPTION | - | - | - | n/a | n/a | orphaned adminCount=1 (left the protected groups, SDProp ACL remains): clear adminCount, re-enable inheritance | owner review (see exception) |
