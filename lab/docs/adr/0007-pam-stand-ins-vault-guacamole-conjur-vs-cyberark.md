# ADR 0007: PAM stand-ins (HashiCorp Vault + Guacamole + Conjur OSS) vs. CyberArk

- **Status:** Accepted (lab). It does not select a production PAM vendor. The decision is unchanged; the mapping table, Consequences and Evidence describe what the stand-in does as of 2026-10-20. Everything described as having run ran locally in Docker (the Samba AD harness and the dynamic-database harness), never against DC01 or a tenant.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Tier-0 accounts on DC01 (Domain Admins `tier0-admin-01/02`) and service
accounts (`svc-backup`) need vaulting, rotation, exclusive check-out and
recorded sessions. Workloads need secrets without a static credential in
their code. The scenario's reference product is CyberArk: Digital Vault, CPM,
PSM and Secrets Manager (Conjur). CyberArk has no individual trial. The lab
needs something that actually rotates real AD passwords, not slides.

## Options considered

1. **CyberArk Privilege Cloud or self-hosted PAM.** The target vocabulary,
   but no licence is available for an individual lab.
2. **Another commercial suite's trial** (BeyondTrust, Delinea). verify:
   whether an individual can get a trial today. It would teach a second
   vendor's model, not CyberArk's.
3. **Open-source and community equivalents** run locally against the real
   DC01: Vault Community (LDAP secrets engine), Apache Guacamole (brokered,
   recorded RDP) and CyberArk Conjur OSS (workload secrets).
4. **Describe PAM in documents only.** Nothing to execute or test. Rejected.

## Decision

Option 3. Each component stands in for one CyberArk function and is named on
camera (`STAND-INS.md`). The mapping below is the contract: what the lab
really does under each CyberArk term, and the gap that remains.

### CyberArk vocabulary → this lab

| CyberArk term | What it is in CyberArk | What the lab does | Gap vs. production |
|---|---|---|---|
| **Digital Vault** | Hardened credential store, with its own audit trail | Vault Community 2.1, real init/unseal, file storage, file audit device (`pam/vault/vault.hcl`, `pam-up.sh`). A separate 3-node Raft cluster with transit auto-unseal (`docker-compose.ha.yml`, `vault-ha.sh`, `dr-drill.sh`) rehearses leader failover, a timed snapshot-restore DR drill and a rolling upgrade; all three ran in the harness ([ADR 0019](0019-pam-vault-high-availability-and-dr.md)) | The Vault the scripts use is single node, one unseal key, no TLS (loopback only); HA exists only as the rehearsal cluster. Production (ADR 0019): HA with auto-unseal from an HSM-backed Key Vault key, recovery keys split 3-of-5. Shamir unseal alone was rejected there: a restarted node stays sealed until custodians gather |
| **Safe** | Container of accounts with its own member permissions | A library set (`tier0-admins`, `tier1-admins`) or a static-role prefix (`svc/*`) plus its Vault policies (`<tier>-checkout`, `<tier>-static-read`), created by `onboard.sh`. Members are named per person in `operators.json` and checked before every check-out | Safe membership is a local file, not a directory group |
| **Platform** | Per-account-type settings: rotation interval, password rules, connection components | A tier in `pam-policy.json` (`tier0`, `tier1`, `svc`): rotation period, check-out TTL, maximum password age, whether a ticket and a dependency check are required. `schema=ad` on the LDAP engine | Vault's default password generation (no custom password policy on the AD engine). Only one platform type, AD |
| **Master Policy** | Global rules: exclusive access, one-time passwords, dual control, session recording | Exclusive check-out (`disable_check_in_enforcement=false`), rotate-on-check-in (one-time password), every Tier-0 connection recorded. Check-out needs an approved change in Implement, inside its window and assigned to the person asking (ServiceNow Table API v2, `itsm_validate` in `lib.sh`); a missing or unparsable ticket rule stops the check-out (fails closed). **Dual control:** `itsm_validate` also counts the change's approval records (`sysapproval_approver`) against `approvals_required` in `pam-policy.json` (Tier 0: two, Tier 1: one); an approval counts only if it is approved, not from the requester or the change's `requested_by`, and from someone `operators.json` allows to approve for that Safe; any rejection stops the check-out. Exclusions (`krbtgt`, RID-500, the bind accounts) are documented in `pam-policy.json` | Approvals and tickets come from a local mock; the ServiceNow PDI is a tenant-time step. Approver rights are a local file, not a directory group |
| **Accounts Discovery and onboarding** | Find privileged accounts, then bring them under management in bulk | `discover.sh` (read-only AD scan: nested and primary-group membership, SPNs, `adminCount`, stale) and `onboard.sh` (dry run, then bulk onboarding per tier, idempotent). Ran against the Samba DC | Not yet run against DC01 |
| **CPM plugin** | Code that changes, verifies and reconciles a password on a target type | The Vault LDAP engine writing `unicodePwd` over LDAPS, verified against the lab root CA. `rotate.sh` refuses to rotate while `accounts-dependencies.json` lists an unresolved consumer; `reconcile.sh --verify` is CPM's Verify, and `rotate.sh` after a failed verify is the Reconcile | Covers AD accounts only. No local Windows, network-device or database-account rotation plugins |
| **Reconcile account** | Privileged account the CPM uses to reset a password that has drifted | `svc-vault-rotator`: Reset Password plus `pwdLastSet`/`lockoutTime` writes on `OU=ServiceAccounts` and on AdminSDHolder (`02-Configure-Domain.ps1`). Effectively Tier 0. Vaulted, and rotated by Vault itself with `--rotate-root` | One account does both logon and reconcile. CyberArk can separate them |
| **PSM connector** | Component that launches a session with the vaulted credential injected | Guacamole RDP connection per account, "DC01 - <account> (recorded)". `psm-session.sh checkout --operator NAME --ticket CHG…` mints a per-check-out Vault token named after the operator and carrying the ticket and its approvers, injects the password and gives that one person connect-only (READ) access through their own Guacamole user. The shared `t0-operator` is gone. In the harness, `--target rdp-target` connects to a **Linux xrdp stand-in** for DC01 (`rdp-target/`; logon only with the AD password, checked by Kerberos against the Samba DC): a recorded RDP session ran and its recording plays back | The password sits in `guac-db` until check-in, so `guacadmin` can read it; PSM fetches it when the session starts. In the lab each operator signs in to Guacamole with a local password; Entra OIDC sign-in is a tenant-time step. The stand-in is not Windows: an RDP session to DC01 itself needs DC01 (Samba has no RDP) |
| **PSMP** (PSM for SSH) | SSH proxy with recording | Guacamole SSH connection plus Vault's SSH CA (`psm-ssh.sh`): a 10-minute certificate for one principal, injected so the operator never holds the key; graphical recording plus a text typescript; the target's sshd log names the certificate key ID and serial. A recorded session ran in the harness | One Linux target (`ssh-target`), in Docker |
| **CCP / Conjur** (Secrets Manager) | Applications fetch secrets over an API (CCP) or by policy-defined workload identity (Conjur) | Conjur OSS policy as code: host `apps/nightly-report` may read `servicenow-api-key`, and `apps/unapproved-job` is denied (`conjur-demo.sh`). The Kubernetes segment shows the authn-k8s pattern with Vault's Kubernetes auth (ADR 0010) | Conjur hosts use API keys, not authn-jwt or authn-k8s, because a GitHub runner can't reach a laptop Conjur |
| **Zero standing privilege for databases** (verify: CyberArk's current product name) | A database login created per request and removed afterwards | Vault's database secrets engine against PostgreSQL, in its own project (`docker-compose.dynamic-db.yml`, `dynamic-db/`): a new login per request, a 1-hour lease, sessions ended and the login dropped on revoke. `test/e2e-dynamic-db.sh` passed 60/60 (hashed run record: `lab/evidence/dynamic-db/20261020T163436Z/`) | One synthetic database, with its own Vault; not joined to the AD stack |
| **PTA** | Privileged threat analytics | Two correlation rules, each with an SPL twin, both deployed by `modules/monitoring` when enabled: `tier0-logon-without-checkout.kql` (a Tier-0 logon on DC01 that no Vault check-out covers) and `vault-privileged-access-anomaly.kql` (a Tier-0 credential read outside a ticketed check-out, a check-out without a ticket, a failed rotation, root-token use, login bursts; behind `enable_itdr_detections_v2`) | Neither has run on a tenant or fired. Both ran on the local Kusto-emulator harness against synthetic events (2026-10-21, all cases PASS; `lab/evidence/kusto/20261021T001217Z/`), which is not a Log Analytics workspace. The vault-side rule needs `ingest-vault-audit.sh --signals all` and the extended table columns (`vault_feed_v2_columns`); the feed is tested offline only. No behavioural baselining |

## Consequences

**Positive**
- AD passwords rotate and are verified by an LDAPS bind (executed against
  the Samba AD harness; the Azure DC01 run is still open). The old
  password must be refused with `invalidCredentials`, so a negative check
  can't pass by accident.
- The whole AD-dependent flow is rehearsable with no Azure. `test/e2e.sh`
  runs the real scripts against a Samba AD DC, with only `az` stubbed. Its
  latest run passed 284/284 (2026-10-20, the author's working copy; hashed
  run record `lab/evidence/pam/20261020T220031Z/`: `results.json`,
  `reconcile.md` with GAP 0, `rdp-recording.json`, `SHA256SUMS`):
  discovery, bulk onboarding, the dependency gate, reconciliation,
  ticket-gated per-person check-out under Tier-0 dual control, a recorded
  SSH session, a recorded RDP session to the Linux xrdp stand-in and the
  HA/DR drill. The earlier records `20261020T184052Z` and
  `20261020T204851Z` (241/241 each) predate dual control and the RDP step.
  A run from a fresh clone is still to do.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| `svc-vault-rotator` is Tier 0, because it can reset Domain Admin passwords through AdminSDHolder | Its password lives in Key Vault, then only in Vault after `--rotate-root`. It is never on a command line. Treat it as Tier 0 in every review |
| Unseal key and root token in `.secrets/vault-init.json` | Lab only. Mode 0600 and gitignored. Production: Key Vault auto-unseal with recovery keys in split custody (ADR 0019), and the root token revoked after setup |
| Attribution depends on the broker sign-in | Each operator has their own Guacamole user, and each check-out its own Vault token named after the operator and carrying the ticket, so the vault's audit log names the person. In the lab that Guacamole sign-in is a local password. Tenant time: Entra OIDC sign-in with phishing-resistant MFA (`docker-compose.oidc.yml`; `test/e2e.sh` proves locally that OIDC mode refuses the old local password) |
| The stand-in fails differently from CyberArk under load or failover | Failover and restore were measured only on a separate laptop rehearsal cluster holding test markers, not the vault that holds the AD credentials (new writable leader in 2–4 s; restore RTO 32.5, 40.5 and 42.1 s in the three hashed drills in `lab/evidence/pam-dr/`). That is a rehearsal of the procedure, not a load or production failover test |

**Not proven yet:** the run against the Azure DC01 (a real Windows RDP
session and playing back its recording) is unchecked in `pam/README.md`.
The Samba harness runs, including the RDP session to the Linux stand-in,
are the only executed evidence. Fill in after running:
check-out, check-in and rotation lines from the Vault audit log, plus
`PasswordLastSet` on DC01.

## Revisit trigger

- A CyberArk (or other commercial PAM) licence becomes available. Rebuild
  the same three flows natively and keep this table as the migration map.
- The scenario adds Linux/SSH or database accounts beyond one demonstration
  target each. The SSH CA and the dynamic database credentials prove the
  patterns, not the scale; move to a commercial suite.
- An audit finding on attribution. Move operator sign-in to Entra OIDC
  first.

## Evidence

- `lab/pam/README.md`: run order, harness, security notes, definition of done
- `lab/pam/vault-onboard-ad.sh`, `lab/pam/lib.sh`, `lab/pam/psm-session.sh`,
  `lab/pam/psm-ssh.sh`
- `lab/pam/pam-policy.json`, `lab/pam/operators.json`,
  `lab/pam/accounts-dependencies.json`
- `lab/pam/discover.sh`, `lab/pam/onboard.sh`, `lab/pam/rotate.sh`,
  `lab/pam/reconcile.sh`
- `lab/pam/vault-ha.sh`, `lab/pam/dr-drill.sh`, `lab/pam/docker-compose.ha.yml`
- `lab/pam/docker-compose.oidc.yml` (tenant-time OIDC sign-in)
- `lab/pam/docker-compose.dynamic-db.yml`, `lab/pam/dynamic-db/`
- `lab/pam/conjur/policy.yml`, `lab/pam/conjur-demo.sh`
- `lab/pam/vault/vault.hcl`, `lab/pam/docker-compose.yml`
- `lab/pam/test/run-all.sh`, `lab/pam/test/e2e.sh`,
  `lab/pam/test/e2e-dynamic-db.sh`, `lab/pam/test/samba-ad/`
- `lab/pam/rdp-target/` (the Linux xrdp stand-in), `lab/pam/itsm-ticket.sh`,
  `lab/pam/tools/mock_servicenow.py` (tickets and approval records),
  `lab/pam/test/itsm-dual-control.test.sh`
- `lab/evidence/pam/20261020T220031Z/`: the e2e run record (`results.json`
  284 pass / 0 fail, `reconcile.md`, `rdp-recording.json`, `SHA256SUMS`);
  `lab/evidence/pam-dr/20261020T220031Z/`: the DR drill report from the
  same run
- `lab/evidence/dynamic-db/20261020T163436Z/`: the dynamic-credential run
  record (`results.json`, `run.log`, `SHA256SUMS`)
- `lab/kql/tier0-logon-without-checkout.kql`,
  `lab/kql/vault-privileged-access-anomaly.kql`,
  `lab/scripts/monitoring/ingest-vault-audit.sh`
- `lab/scripts/dc/02-Configure-Domain.ps1`: OUs, accounts, delegation
- `lab/docs/STAND-INS.md`: Vault, Guacamole and Conjur rows
