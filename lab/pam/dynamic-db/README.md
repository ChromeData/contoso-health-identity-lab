# Dynamic database credentials (zero standing privilege on infrastructure)

Nobody holds a password to the clinical database. A person asks Vault for
access, Vault creates a **brand-new Postgres login** for them with a 1-hour
lease (4 hours at most), and the login is dropped when the lease is revoked
or runs out. Revoking it also ends the person's open sessions.

| Here | Stands in for |
|---|---|
| Vault Community 2.1.1, **database secrets engine** (`database/`) | Zero-standing-privilege database access / dynamic secrets. The Microsoft way (ADR 0027) removes the database password: Microsoft Entra authentication to Azure Database for PostgreSQL, with a managed identity for apps and a PIM-eligible group for people |
| PostgreSQL 16.15 `clinical-db`, synthetic data only | The clinical database (an EHR reporting replica, for example) |
| `clinical-app` (psql on the same internal network) | The analyst workstation or reporting app that logs in |
| A Vault token minted by the script | Signing in to Vault with OIDC (Microsoft Entra ID), with an Entra group mapped to the policy (tenant time, below) |

It runs as its own compose project (`contoso-dyndb`, its own Vault on
`127.0.0.1:8220`). The shared `contoso-pam` stack is never touched, so the
AD-backed Vault keeps its configuration and can be restarted at any time.

## Run

```bash
cd lab/pam
./dynamic-db/setup.sh          # idempotent; prints no secret
./dynamic-db/demo.sh           # [--operator NAME], default ops-alice
./test/e2e-dynamic-db.sh       # 60 assertions; rebuilds the project from scratch; writes a run record
./test/e2e-dynamic-db.sh --verify out/dynamic-db/<UTC>   # re-check a run record
./dynamic-db/setup.sh --teardown   # or: ./test/e2e-dynamic-db.sh --cleanup
```

Needs Docker (Colima or Docker Desktop), `jq`, `curl` and `openssl`. Bash 3.2
(the macOS default) is fine.

## What setup.sh builds

| Object | Setting | Why |
|---|---|---|
| `database/` mount | default lease 1h, max 4h | Same TTLs as the Tier-0 check-out standard |
| Password policy `clinical-db` | 32 alphanumerics | Used for every generated password, root rotation included |
| Connection `clinical-db` | admin `vault_admin`, `password_authentication=scram-sha-256` | Vault sends Postgres a SCRAM verifier, not the password, so no generated password can reach a Postgres log |
| `vault_admin` (on the DB) | `CREATEROLE`; **ADMIN** on `clinical_reader` with INHERIT and SET off; `pg_signal_backend` | Can create and drop the dynamic logins and end their sessions. It **cannot read clinical data itself** |
| rotate-root | runs immediately after the connection is written | From then on only Vault knows `vault_admin`'s password |
| Bootstrap superuser `postgres` | `PASSWORD NULL` at the end of the first run | No standing login to the database is left outside Vault |
| Role `clinical-readonly` | new login per request, member of `clinical_reader` (SELECT on schema `clinical` only), `VALID UNTIL` = lease end, `CONNECTION LIMIT 5`, named `v-<person>-<random>-<time>` | Least privilege, and the database's own connection log names the person |
| Revocation | `NOLOGIN`, then `pg_terminate_backend` on its sessions, then `DROP ROLE` | Revoking the lease also ends sessions that are already open |
| Policy `clinical-readonly-requester` | read `database/creds/clinical-readonly`; look up leases under that path; `lookup-self` / `revoke-self`. **No renew, no revoke** | A Vault ACL cannot limit a lease to the token that created it, so per-lease renew or revoke would let one analyst extend or cut off another's access (and revoke kills their sessions). A person ends their own access with `vault token revoke -self`, which revokes every lease under their token |
| Tokens without Vault's `default` policy | `-no-default-policy` (tenant time: OIDC role `token_no_default_policy=true`) | Vault's built-in `default` policy allows `sys/leases/renew` on **any** lease; with it attached, the requester policy above would not hold |
| Policy `clinical-db-responder` | look up, renew and revoke any `clinical-readonly` lease; issues none | Security on-call (incident response). The demo and the test revoke with this token |
| Database statement audit | `log_statement = all` on database `clinical`; `log_line_prefix` carries `user=%u db=%d`; `postgres` and `vault_admin` exempt (role settings override the database setting) | The Postgres log records *which* PHI query a `v-<person>-*` login ran (HIPAA 164.312(b)); Vault's own DDL, which carries password verifiers, is not logged |
| Other databases | `CONNECT` and `TEMPORARY` revoked from `PUBLIC` on `postgres` and `template1` | A dynamic login can open `clinical` only, not the maintenance database |
| Audit device | file, `/vault/logs/audit.log` | Each issue is recorded with the requester's name. Secrets are HMAC'd |

## What the e2e test proves

**Status: RAN · harness.** Verified by `../test/e2e-dynamic-db.sh`: 60 PASS,
0 FAIL in the hashed run record
[`../../evidence/dynamic-db/20261020T163436Z/`](../../evidence/dynamic-db/20261020T163436Z/)
(`run.log`, `results.json` with every check's name and status and no
password or token, `SHA256SUMS`; the hashes check out with
`shasum -a 256 -c SHA256SUMS`; part of the next commit), and again 60/60 in
the full `../test/run-all.sh` run at 2026-10-20 19:48 UTC (macOS bash 3.2,
Colima).
Ordinary runs write their record to the gitignored
`lab/pam/out/dynamic-db/<UTC>/`; `--evidence-dir` publishes one under
`lab/evidence/`, and `--verify <dir>` re-checks a record offline.
**RAN · tenant: nothing** (the Entra OIDC sign-in to Vault below is
DESIGNED).

- **Root credential.** `vault_admin`'s bootstrap password and the superuser's
  bootstrap password are both refused by Postgres (`password authentication
  failed`). Reading the Vault config never returns the admin password.
- **Credentials work.** The login is a real network login that reads
  `clinical`.
- **Least privilege.** Reading `billing`, INSERT and CREATE are all refused.
  The login is not a superuser, and `vault_admin` can't read the clinical
  tables.
- **Unique per request.** Each request gets a different username, password
  and lease.
- **Other databases.** The login is refused on `postgres` and `template1`
  (`permission denied for database`).
- **TTLs.** The lease is at most 3600 s and Postgres `VALID UNTIL` is set. The
  responder asking to renew for 8 h is capped at 4 h.
- **Policy scope.** Other roles, the connection config and other paths' leases
  are all denied. The requester can renew or revoke no lease, not even its
  own, and a second requester can neither renew nor revoke the first one's.
  Neither token carries Vault's `default` policy. The responder cannot issue
  credentials or read the connection config.
- **Revocation.** The responder revoking a lease ends a live `pg_sleep` session with
  `terminating connection due to administrator command`. The same username
  and password are then refused, the role is gone, and other leases keep
  working. Revoking the person's Vault token revokes every lease issued under
  it.
- **Statement audit.** Postgres logs the dynamic login's `SELECT` on
  `clinical.encounters` under its `v-<person>-*` name, and logs no
  `vault_admin` statement and no `CREATE`/`ALTER ROLE`.
- **No plaintext passwords in either log.** Neither Vault's audit log nor
  Postgres's log contains either generated password or either bootstrap
  password (all four checked in both logs).
- **Demo.** `demo.sh` runs end to end.

## Lab limits (production differs)

- One unseal key, and the root token stays in `.secrets/vault-init.json` (0600,
  gitignored). Production uses split custody or auto-unseal, with the root
  token revoked.
- `sslmode=disable` between Vault and Postgres, on an `internal: true` network
  with no published DB port. Production uses `sslmode=verify-full` with the
  DB's CA (`tls_ca`).
- `VALID UNTIL` is only a backstop for *new* logins if Vault is down at
  expiry. Postgres does not end a session that is already open when it
  passes. Vault's revocation does that.
- `pg_signal_backend` lets `vault_admin` terminate any non-superuser session,
  not only Vault's own logins. That's the price of "revoke ends the session".
- Lease **lookup** is left to requesters: read-only metadata (TTL, expiry), and
  it also answers for another requester's lease ID if they know it. The
  responder can extend anyone's lease up to the 4 h max - an on-call right.
- Statement audit uses `log_statement = all` (no pgaudit in the stock image):
  one line per statement, no object-level filtering.
- The two `*-bootstrap` files stay in `.secrets/` after setup. Both passwords
  are dead by then (the test proves it), and the test needs them to prove it.
- **Break-glass:** there is no standing DB password. Recovering from a lost
  Vault means host access (`docker compose exec` into `clinical-db`, a
  temporary `pg_hba.conf` change). In this lab that's simply
  `setup.sh --teardown`, then `setup.sh`.

## Tenant time (DESIGNED, not run: no tenant exists)

1. Enable Vault's OIDC auth method against an Entra app registration, and map
   an Entra group (for example a PIM-eligible `GRP-PAM-ClinicalDB-Readers`)
   to `clinical-readonly-requester` with an external group, and set
   `token_no_default_policy=true` on the OIDC role (see the table above). That
   replaces `mint_requester_token`; a second group (security on-call) maps to
   `clinical-db-responder`.
2. Forward `/vault/logs/audit.log` to Sentinel, the same way
   `lab/scripts/monitoring/ingest-vault-audit.sh` does for the main Vault.
3. Azure-native alternative for Azure Database for PostgreSQL flexible server:
   Microsoft Entra authentication. The Entra access token is the password, a
   user token is valid for up to 1 hour, database permissions can be managed
   through Entra groups, and password authentication can be switched off
   (Microsoft Learn, "Microsoft Entra Authentication in Azure Database for
   PostgreSQL Flexible Server", checked 2026-10-20). One difference from the
   Vault pattern: a user deleted in Entra can still sign in until their token
   expires (up to 60 minutes) unless their database role is also removed.
   Vault's revocation is immediate.
