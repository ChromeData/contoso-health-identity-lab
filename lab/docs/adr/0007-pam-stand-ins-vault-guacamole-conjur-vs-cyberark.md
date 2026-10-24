# ADR 0007: PAM stand-ins (HashiCorp Vault + Guacamole + Conjur OSS) vs. CyberArk

- **Status:** Accepted (lab). It does not select a production PAM vendor (`vendor-evaluation.md` does). RAN · harness: everything below that ran, ran in Docker against a Samba AD DC (locally; the default suites also nightly on GitHub's runners), never against DC01 or a tenant.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Tier-0 accounts on DC01 (Domain Admins `tier0-admin-01/02`) and service
accounts (`svc-backup`) need vaulting, rotation, exclusive check-out and
recorded sessions. Workloads need secrets without a static credential in
code. The scenario's reference product is CyberArk (Digital Vault, CPM, PSM,
Secrets Manager), which has no individual trial. The lab needs something
that actually rotates real AD passwords, not slides.

## Options considered

1. **CyberArk Privilege Cloud or self-hosted PAM.** The target vocabulary,
   but no licence for an individual lab.
2. **Another commercial suite's trial** (BeyondTrust, Delinea). It would
   teach a second vendor's model, not CyberArk's.
3. **Open-source and community equivalents** run locally against AD: Vault
   Community (LDAP secrets engine), Apache Guacamole (brokered, recorded
   sessions) and CyberArk Conjur OSS (workload secrets).
4. **Describe PAM in documents only.** Nothing to execute. Rejected.

## Decision

Option 3. Each component stands in for one CyberArk function and is named
in `STAND-INS.md`. The mapping below is the contract: what the lab really
does under each CyberArk term, and the gap that remains.

### CyberArk vocabulary → this lab

| CyberArk term: what it is | What the lab does | Gap vs. production |
|---|---|---|
| **Digital Vault**: hardened credential store with its own audit trail | Vault Community 2.1, real init/unseal, file storage, file audit device (`pam/vault/vault.hcl`, `pam-up.sh`). HA and DR are a separate rehearsal cluster: [ADR 0019](0019-pam-vault-high-availability-and-dr.md) | The vault the scripts use is one node, one unseal key, loopback only, no TLS |
| **Safe**: accounts plus member permissions | A library set (`tier0-admins`, `tier1-admins`) or static-role prefix (`svc/*`) with its policies, created by `onboard.sh`; members named per person in `operators.json`, checked before every check-out | Membership is a local file, not a directory group |
| **Platform**: per-account-type rotation, password and connection settings | A tier in `pam-policy.json` (`tier0`, `tier1`, `svc`): rotation period, check-out TTL, maximum password age, whether a ticket and a dependency check are required | Vault's default password generation; one platform type, AD |
| **Master Policy**: exclusive access, one-time passwords, dual control, recording | Exclusive check-out; rotate on check-in (one-time password); every Tier-0 connection recorded. Check-out needs an approved ServiceNow change in its window and assigned to the requester; a missing or unparsable rule fails closed. **Dual control:** Tier 0 needs two approvals, Tier 1 one, from people `operators.json` allows, never the requester; any rejection stops the check-out | Tickets and approvals come from a local Table API mock; the ServiceNow PDI is a tenant-time step |
| **Accounts Discovery and onboarding**: find privileged accounts, bring them under management in bulk | `discover.sh` (read-only AD scan: nested and primary-group membership, SPNs, `adminCount`, stale) and `onboard.sh` (dry run, then idempotent bulk onboarding per tier) | Not yet run against DC01 |
| **CPM plugin**: changes, verifies and reconciles a password on one target type | The LDAP engine writing `unicodePwd` over LDAPS. `rotate.sh` refuses while `accounts-dependencies.json` lists an unresolved consumer; `reconcile.sh --verify` is CPM's Verify, and a rotate after a failed verify is the Reconcile | AD accounts only: no local Windows, network-device or database plugins |
| **Reconcile account**: resets a password that has drifted | `svc-vault-rotator`: Reset Password plus `pwdLastSet`/`lockoutTime` on `OU=ServiceAccounts` and AdminSDHolder. Effectively Tier 0; vaulted and rotated by Vault itself | One account does both logon and reconcile |
| **PSM connector**: launches a session with the vaulted credential injected | `psm-session.sh checkout --operator NAME --ticket CHG…` mints a per-check-out Vault token carrying the operator, ticket and approvers, injects the password and gives that one person connect-only access through their own Guacamole user. In the harness the RDP target is a **Linux xrdp stand-in** for DC01, and its recording plays back | The password sits in `guac-db` until check-in, so `guacadmin` can read it. Operators sign in to Guacamole with local passwords until Entra OIDC runs. An RDP session to Windows needs DC01 |
| **PSMP**: SSH proxy with recording | Guacamole SSH plus Vault's SSH CA (`psm-ssh.sh`): a 10-minute certificate for one principal, never held by the operator; graphical recording plus a typescript | One Linux target, in Docker |
| **CCP / Conjur**: secrets for applications and workloads | Conjur OSS policy as code: `apps/nightly-report` may read `servicenow-api-key`, `apps/unapproved-job` is denied (`conjur-demo.sh`). The Kubernetes segment shows the authn-k8s pattern with Vault's Kubernetes auth (ADR 0011) | Conjur hosts use API keys, not authn-jwt or authn-k8s |
| **Zero standing privilege for databases**: a login created per request | Vault's database engine against PostgreSQL: a new login per request, 1-hour lease, sessions ended and the login dropped on revoke | One synthetic database with its own Vault |
| **PTA**: privileged threat analytics | `tier0-logon-without-checkout.kql` (a Tier-0 logon on DC01 with no check-out) and `vault-privileged-access-anomaly.kql` (credential read outside a ticketed check-out, check-out without a ticket, failed rotation, root-token use, login bursts), each with an SPL twin | Neither has run in a workspace; both passed their cases on the local Kusto emulator (`lab/evidence/kusto/`). No behavioural baselining |

## Consequences

**Positive**
- AD passwords rotate and are verified by an LDAPS bind; the old password
  must be refused with `invalidCredentials`, so a negative check can't pass
  by accident.
- The whole AD-dependent flow is rehearsable with no Azure. Latest harness
  run (`lab/evidence/pam/20261020T220031Z/`): 284 passed, 0 failed,
  reconciliation GAP 0: discovery, onboarding, the dependency gate,
  ticket-gated check-out under dual control, recorded SSH and RDP, HA/DR.
- **At scale:** the same discover → onboard → dependency check → rotate →
  reconcile scripts ran over 500 synthetic privileged accounts plus 250
  ordinary staff: 79 passed; 515 discovered, 263 vaulted, 128 documented
  exceptions, 124 held on unresolved dependencies, GAP 0, ORPHAN 0
  (`lab/evidence/pam-scale/20261020T193913Z/`). Passwords weren't verified
  by bind in that run.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| `svc-vault-rotator` is Tier 0 (it can reset Domain Admin passwords through AdminSDHolder) | Its password lives in Key Vault, then only in Vault after `--rotate-root`; never on a command line |
| Unseal key and root token in `.secrets/vault-init.json` | Lab only, mode 0600, gitignored. Production: auto-unseal with split recovery keys (ADR 0019), root token revoked after setup |
| Attribution depends on the broker sign-in | Per-operator Guacamole users and per-check-out Vault tokens name the person in the audit log. Tenant time: Entra OIDC with phishing-resistant MFA (`docker-compose.oidc.yml`; the harness proves OIDC mode refuses the old local password) |
| The stand-in fails differently from CyberArk under load | Failover and restore were timed only on a laptop rehearsal cluster (ADR 0019): a procedure rehearsal, not a load test |

**Not proven yet:** the run against DC01 (a Windows RDP session and its
recording). Fill in after running: check-out, check-in and rotation lines
from the Vault audit log, and `PasswordLastSet` on DC01. The harness itself
now runs from a fresh clone: `pam-harness.yml` passes nightly on GitHub's
runners
([latest run](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39937464414)),
still against the stand-ins (RAN · harness).

## Revisit trigger

- A CyberArk (or other commercial PAM) licence: rebuild the flows natively
  and keep this table as the migration map.
- Linux, SSH or database accounts beyond one demonstration target each.
- An audit finding on attribution: move operator sign-in to Entra OIDC
  first.

## Evidence

- `lab/pam/README.md` (run order, harness, security notes)
- `lab/pam/`: `vault-onboard-ad.sh`, `lib.sh`, `psm-session.sh`, `psm-ssh.sh`,
  `pam-policy.json`, `operators.json`, `accounts-dependencies.json`,
  `discover.sh`, `onboard.sh`, `rotate.sh`, `reconcile.sh`,
  `docker-compose.oidc.yml`, `dynamic-db/`, `conjur/policy.yml`,
  `conjur-demo.sh`, `rdp-target/`, `itsm-ticket.sh`,
  `tools/mock_servicenow.py`
- `lab/pam/test/`: `run-all.sh`, `e2e.sh`, `e2e-scale.sh`,
  `e2e-dynamic-db.sh`, `itsm-dual-control.test.sh`
- `lab/evidence/pam/`, `pam-scale/`, `dynamic-db/` (hashed run records;
  index `lab/evidence/README.md`)
- `lab/kql/tier0-logon-without-checkout.kql`,
  `vault-privileged-access-anomaly.kql`;
  `lab/scripts/monitoring/ingest-vault-audit.sh`
- `lab/scripts/dc/02-Configure-Domain.ps1` (OUs, accounts, delegation)
