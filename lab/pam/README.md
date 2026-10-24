# PAM / IGA stand-ins — local Docker stack

CyberArk, SailPoint and Saviynt are enterprise-licensed, and the author holds
no licence. This folder runs the closest **real, open-source or community**
equivalents on your laptop for $0. It is built to run against DC01, the lab's
AD domain controller in Azure; today it runs against a Samba AD DC harness
(status below). Every stand-in, and what it replaces, is listed in
[`../docs/STAND-INS.md`](../docs/STAND-INS.md).

| Container | Real product | Stands in for | What the demo proves |
|---|---|---|---|
| `vault` | HashiCorp Vault Community 2.1 | CyberArk **Digital Vault + CPM** | AD account discovery → bulk onboarding → dependency-gated rotation → reconciliation; exclusive check-out, rotate-on-check-in, audit log |
| `guacd` + `guacamole` | Apache Guacamole 1.6 | CyberArk **PSM** (+ PSM for SSH) | Brokered SSH to a Linux host and brokered RDP to a Linux xrdp stand-in (both RAN · harness), RDP to DC01 itself (BUILT, needs DC01); each session belongs to one named operator who never sees the credential, recorded, and the recording checked for playback |
| `itsm-mock` | ServiceNow Table API v2 mock (`tools/mock_servicenow.py`), incl. the `sysapproval_approver` table | **ServiceNow** change tickets + approvals (a ServiceNow PDI at tenant time) | Check-out only with an approved, current change assigned to the person asking, under **dual control** for Tier 0: two distinct approvers, neither of them the requester (Tier 1: one) |
| `ssh-target` (profile `ssh`) | OpenSSH on Debian, trusting only Vault's SSH CA | A Tier-1 **Linux server** behind PSMP | Ephemeral 10-minute certificates; the target's own log names the operator |
| `rdp-target` (profile `rdp`, harness only) | xrdp 0.10 + xorgxrdp on Debian, AD logon by Kerberos (`rdp-target/`) | **A Linux STAND-IN for an RDP session to DC01**. It is not Windows: Samba AD has no RDP, so this gives the brokered RDP path something real to connect to | A Tier-0 AD account checked out of Vault logs on over RDP through Guacamole with the injected password; the session is recorded and the recording plays back; after check-in the password no longer works ([RDP without DC01](#rdp-recording-without-dc01-linux-xrdp-stand-in)) |
| `vault-1/2/3` + `vault-unsealer` (`docker-compose.ha.yml`) | Vault integrated storage (Raft) + transit auto-unseal | CyberArk **Vault HA / DR Vault**; Azure Key Vault auto-unseal | Leader failover, a timed snapshot-restore DR drill (RTO/RPO), a rolling upgrade |
| `conjur` + `conjur-cli` | CyberArk Conjur OSS 1.27 | Conjur Enterprise / **Secrets Manager** | Workload secrets by policy-as-code: one host allowed, one denied |
| `midpoint` | Evolveum midPoint 4.10 | **SailPoint / Saviynt** | A risk-tiered certification campaign run headless over REST, with detective SoD and automated remediation ([`midpoint/README.md`](midpoint/README.md)); Entra users aggregated through the Graph connector at tenant time |
| `contoso-dyndb` project (`docker-compose.dynamic-db.yml`): its own Vault + PostgreSQL `clinical-db` | Vault database secrets engine | CyberArk **zero-standing-privilege database access** / dynamic secrets | A new Postgres login per request, 1-hour lease, dropped (and its sessions ended) on revoke; nobody holds a standing password ([`dynamic-db/README.md`](dynamic-db/README.md)) |
| `samba-dc` (harness only, `test/docker-compose.samba.yml`) | Samba 4.22 AD DC on Debian | **DC01**, the lab's Windows Server domain controller in Azure | The real scripts run against a real AD (LDAPS, `pwdLastSet`, nested groups, SPNs) without a tenant |
| `contoso-vaultanom` project (harness only) | Vault 2.1.1 + its own Samba DC | The Vault audit feed into **Sentinel** (`VaultCheckout_CL`) | Real Vault audit events become the rows the PAM anomaly detection reads; the KQL itself does not run here |

> **Status: RAN · harness.** Every full default run of
> [`test/run-all.sh`](#test-suites-and-the-runner) on 2026-10-20 (Colima on
> Apple Silicon, the author's working copy, not a fresh clone) passed
> **8 of 8 suites, 610 checks passed, 0 failed, 1 skipped**; from a fresh
> clone on GitHub's runners, the nightly runs give the same totals (below).
> Of the 610, **498 ran end to end in Docker**: the PAM flow against a local Samba AD DC
> 284/284 (with Tier-0 dual control and a recorded RDP session to the Linux
> xrdp stand-in), the midPoint campaign 91/91, dynamic database credentials
> 60/60 and the Vault audit feed for the anomaly detection 63 (+1 SKIP: no
> local Splunk). **112 are offline unit and fixture checks**: the
> dual-control suite 45/45 (against the ServiceNow mock run locally), the
> recording-format check 29/29 (fixtures), the audit ingest script 30/30 and
> the dependency-scan matching logic 8/8 (Pester; `Get-AccountDependencies.ps1`
> itself has never run on a Windows host). The optional scale suite
> (`--scale`, 500 synthetic accounts) is not part of a default run; its last
> run is the hashed record `20261020T193913Z` (79/79, GAP 0).
>
> Where each number is held: the `--publish` run `20261020T220031Z` wrote the
> hashed flow and DR records below and re-verified them (8/8 record checks).
> `test/e2e.sh` changed after that run (a fix for the first run on a fresh
> stack; it adds no assertion), so that record's verifier now reports
> `test/e2e.sh` as changed. The latest default run on the current code is
> held in the newest record under
> [`../evidence/offline-tests/`](../evidence/offline-tests/) (the
> [evidence index](../evidence/README.md) names it): per-suite counts and
> run-all's console output, not each suite's own log. Those logs stay in the
> gitignored `out/test-runs/`, because they name lab accounts and operators.
>
> Hashed run records are in [`../evidence/`](../evidence/) (each with a
> `SHA256SUMS`; the harness records also have a `--verify` mode):
> `midpoint/` (two campaign runs), `dynamic-db/` (60/60), `pam/` (the PAM
> flow; latest `20261020T220031Z`: 284/284 with the HA/DR segment, plus
> `rdp-recording.json` for the RDP session), `pam-dr/` (the DR drill's RTO/RPO
> report; RTO 32.5, 40.5 and 42.1 s in its three records, target 300 s, on a
> separate rehearsal cluster holding test markers, not the vault that holds
> the AD credentials) and `pam-scale/` (`20261020T193913Z`: 500 accounts,
> 79/79, GAP 0). From a fresh clone with no `.env` and no volumes,
> `.github/workflows/pam-harness.yml` runs the default suites on a GitHub
> runner every night: three runs so far (2026-10-21 to 2026-10-23, on the
> published commit), each 8/8 suites, 610 passed, 0 failed, 1 skipped
> ([latest run](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39937464414);
> all three in the
> [evidence index](../evidence/README.md#runs-on-githubs-runners)). That is
> still RAN · harness: containers on a runner, not a tenant.
>
> **RAN · tenant: nothing.** Nothing here has run against the Azure DC01,
> Entra ID or ServiceNow. The `az` calls are exercised through a stub; the
> approvals come from the ServiceNow mock; the recorded RDP session is to
> `rdp-target`, a **Linux xrdp stand-in** for DC01, so an RDP recording of a
> Windows session still needs DC01; the Entra OIDC sign-in and the ServiceNow
> PDI are tenant-time steps (BUILT, marked below).

---

## Prerequisites

- Docker (Colima or Docker Desktop) with **4 CPUs and at least 4 GiB** for
  the VM, 6 GiB or more if `lab/splunk` runs at the same time, 8 GiB for the
  whole harness including the HA cluster. The stack idles at about 2.5 GiB and
  midPoint's heap can grow to 2 GiB, so Colima's default VM (2 CPU / 2 GiB)
  is too small. **Apple Silicon:** Conjur ships amd64 images only. Start
  Colima with `colima start --vm-type vz --vz-rosetta --cpu 4 --memory 8`. If
  Colima is already running, `colima stop` first: a running VM keeps its old
  size. On Docker Desktop, turn Rosetta on and set Resources > Memory to match.
- `jq`, `openssl`, `curl`, `perl` (timings), `ssh-keygen`, `python3` (the
  harness's Guacamole session driver, the recording check and the ITSM mock in
  the offline dual-control test) and the `az` CLI signed in (for the DC
  steps). `pam-up.sh` builds two small images from Debian's apt repository
  (`tools/`, `ssh-target/`) and `test/e2e.sh` a third (`rdp-target/`, xrdp +
  Xorg), so the first run needs network access.
- DC01 built (`../scripts/dc/README.md`) and your IP in `operator_ip_ranges`
  (NSG: RDP 3389 + LDAPS 636).

## Run order

```bash
cd lab/pam
./pam-up.sh                                   # .env, schemas, images, containers, Vault init/unseal/audit, guacadmin, ITSM mock
./vault-onboard-ad.sh -k <key-vault> -d corp.<domain>   # LDAP engine, svc-backup static role, tier0 library

# PAM operations pack (section below): discovery -> onboarding -> reconciliation
az keyvault secret show --vault-name <key-vault> -n svc-pam-discovery --query value -o tsv | ./discover.sh
./onboard.sh --dry-run && ./onboard.sh
./reconcile.sh --verify

# Ticket-gated, dual-controlled, per-person session (lab: raise + approve the change in the mock;
# tenant time: in ServiceNow). Tier 0 needs two distinct approvers, neither of them the requester.
./itsm-ticket.sh add "$(./itsm-ticket.sh next)" --operator ops-alice --approver ops-carol --approver ops-dana
./psm-session.sh checkout --operator ops-alice --ticket CHG00400NN
#   -> open http://127.0.0.1:8081/guacamole as ops-alice (lab password: .secrets/operators/ops-alice-password),
#      connect "DC01 - tier0-admin-01 (recorded)", do the admin task
./psm-session.sh checkin                      # Vault rotates the password; recording is in Settings -> History (as guacadmin)

./psm-ssh.sh setup                            # Vault SSH CA + Linux target + recorded SSH connection
./conjur-demo.sh                              # allowed vs denied workload
./vault-ha.sh up && ./dr-drill.sh             # HA cluster + timed DR drill (separate compose project)
./midpoint/run-campaign.sh                    # certification campaign over REST -> lab/evidence/midpoint/ (midpoint/README.md)
./dynamic-db/setup.sh && ./dynamic-db/demo.sh # 1-hour database logins (own compose project; dynamic-db/README.md)
```

After a laptop restart, re-run `./pam-up.sh`. It's idempotent and unseals Vault.
Each run also re-checks the stored guacadmin password and rotates it again if
`guac-db` was reset, adds anything a newer version needs to an existing `.env`
(the ITSM keys), and retires the old shared `t0-operator` user and the old
shared broker token (`.secrets/broker-token`, revoked) if they are still
there.

Every session now belongs to **one named person** from
[`operators.json`](operators.json) (CyberArk: Safe members). `psm-session.sh
checkout --operator NAME` creates that person's Guacamole user on first use,
with no system permissions, and grants READ on the checked-out account's
connection to **that user only**, so they can connect but cannot read the
stored password. The grant goes at check-in. Lab limit: `guacadmin` and the
`guac-db` table can still read the stored value until check-in.
midPoint needs a few minutes on its first start before it answers.

Each Tier-0 account gets its own connection (`DC01 - <account> (recorded)`),
so two check-outs can be open at once. With two open, `checkin` needs the
account name: `./psm-session.sh checkin tier0-admin-02`. A third check-out
says `no Tier-0 account available` only when Vault reports the pool
exhausted. Any other Vault error is printed as it is.

Session recordings live on the `guac-recordings` volume. The one-shot
`guac-recordings-init` service gives it to guacd (uid 1000, writes) and the
web app's group (gid 1001, plays back), mode 2750. A fresh volume is
root-owned, so without that step guacd can't write and sessions run
unrecorded with only a warning in the guacd log.

Tear down: `test/e2e.sh --cleanup` (if you ran the harness; it also removes
`rdp-target`), then `docker compose --profile ssh --profile rdp down -v`,
`./vault-ha.sh down --volumes`, and
remove `.env`, `.secrets/`, `out/`, `itsm/data/` and `guacamole/` (or just
`initdb.sql`; `pam-up.sh` recreates the folder) for a truly fresh start.
Running only `docker compose down -v` is safe for Guacamole: `pam-up.sh`
detects the reset database and rotates guacadmin again.

After onboarding the real DC01, prefer `docker compose down` without `-v`: it
keeps the `vault-data` volume, and `./pam-up.sh` brings Vault back unsealed.
`-v` (or removing `.secrets/vault-init.json`, which holds the unseal key)
loses the only copies of the svc-backup and tier0-admin-01/02 passwords.
That's fine, because the next onboarding rotates them again. **If you used
`--rotate-root`**, it also loses the only valid svc-vault-rotator password,
and the Key Vault copy is stale. The next `./vault-onboard-ad.sh` then fails
with `invalidCredentials` and Vault stays locked out of AD until you reset
svc-vault-rotator on DC01 by hand (`02-Configure-Domain.ps1` skips accounts
that already exist), write the new value to the Key Vault secret
`svc-vault-rotator` (never on a command line), and re-run with
`--reset-bindpass`.

Re-running `./vault-onboard-ad.sh` (for example after DC01 gets a new public
IP) is safe. Against the same DC it keeps the bind password Vault already
holds, because after `--rotate-root` the Key Vault copy is stale and writing it
back would lock Vault out of AD. Pass `--reset-bindpass` only after you reset
`svc-vault-rotator` in AD and Key Vault.

---

## PAM operations pack

The operations layer on top of the Vault stand-in: how the accounts were
found, how 500 were onboarded without an outage, how to prove all are under
management, who approved a session, and what happens if Vault dies.

```
discover.sh ──> onboard.sh ──> rotate.sh (dependency-gated) ──> reconcile.sh
 (AD, read-only)  (Vault API,     (accounts-dependencies.json)    (discovered / vaulted /
                   Safe per tier)                                  rotated / exception)
psm-session.sh / psm-ssh.sh: operator + ticket gate -> per-person, recorded session
vault-ha.sh / dr-drill.sh:   3-node Raft, failover, timed snapshot-restore drill
```

### CyberArk vocabulary map

What each piece is called in a CyberArk shop (BeyondTrust Password Safe and
Delinea Secret Server names in brackets where they differ).

| CyberArk | Here | Notes |
|---|---|---|
| Digital Vault (+ Vault HA cluster, DR Vault) | Vault Community; 3-node Raft cluster in `docker-compose.ha.yml` | Raft replicates every write; DR = snapshots, drilled by `dr-drill.sh` |
| Master Policy | `pam-policy.json` top level: `stale_days`, `exclusions`, `require_ticket` per tier | Exclusions are documented exceptions, each with a reason |
| Platform (rotation interval, check-out rules) [BeyondTrust: Functional Account / Platform; Delinea: Secret Template + Password Changer] | a **tier** in `pam-policy.json` (`tier0`, `tier1`, `svc`) | `rotation_period`, `checkout_ttl`, `max_password_age_days`, `dependency_check` |
| Safe [Delinea: Folder] | a library set (humans) or a static-role prefix (`svc/*`) **plus** its Vault policy (`<tier>-checkout`, `<tier>-static-read`) | Created by `onboard.sh` |
| Safe members | `operators.json` (`libraries`, `ssh_roles`) | Checked before every check-out |
| Accounts Discovery / Pending Accounts | `discover.sh` → `out/discovery-*.csv` | Nested + primary-group membership, SPNs, `adminCount`, stale |
| Account usages (CPM updates them) | `accounts-dependencies.json` + `dependency-scan/Get-AccountDependencies.ps1` | Vault cannot update a Windows service, so rotation is **refused** until each usage reads from Vault |
| CPM: Change / Verify / Reconcile | `rotate.sh` (change), `reconcile.sh --verify` (verify), `rotate.sh` after a failed verify (reconcile) | The reconcile account is `svc-vault-rotator` (`ldap/rotate-root`) |
| PSM (RDP) | Guacamole RDP connection per account, injected credential | Recording + History playback. In the harness the RDP session runs against `rdp-target`, a Linux xrdp stand-in for DC01 (`psm-session.sh --target rdp-target`) |
| PSM for SSH / PSMP, SSH Key Manager | Guacamole SSH connection + **Vault SSH CA** (`psm-ssh.sh`) | Ephemeral cert, never a standing key |
| Ticketing integration (ServiceNow) | `itsm_validate` in `lib.sh` → Table API v2 | Approved, Implement, in window, assigned to the requester, enough approvals |
| Central Credential Provider (CCP) / Credential Provider | `<tier>-static-read` policies (applications read `ldap/static-cred/<prefix>/*`) | What makes a static role safe to rotate |
| Exclusive access | Vault library exclusive check-out | One person per account at a time; a third Tier-0 check-out is refused |
| Dual control (access approval by N confirmers) | `itsm_validate` counts ServiceNow approval records (`sysapproval_approver`); `pam-policy.json` `approvals_required` (tier0 2, tier1 1); approvers in `operators.json` `approves` | Two distinct approvers for Tier 0, neither the operator nor the change's requester, each allowed to approve for the Safe; any rejection stops it ([section 5](#5-ticket-validation-servicenow--dual-control)). verify: the exact CyberArk Master Policy / Safe setting names for your PVWA version |
| PTA (Privileged Threat Analytics) | Not here: the ITDR detections in `lab/kql` correlate DC logons with Vault check-outs | |

### 1. Discovery — `discover.sh`

Runs `tools/discover.py` in the `pam-tools` container, which has the same DC
host mapping and AD root CA as Vault (so `./vault-onboard-ad.sh` must have run
first). It binds as **`svc-pam-discovery`, a plain Domain User**: discovery
must not need the Tier-0 keys it is looking for. The password comes on stdin
(`az keyvault secret show ... | ./discover.sh`), never argv. Read-only.

A candidate is any user that is: a member of a privileged group in
`pam-policy.json`, found **transitively** with
`LDAP_MATCHING_RULE_IN_CHAIN` (1.2.840.113556.1.4.1941) so nested groups
count, **or** whose `primaryGroupID` is that group's RID (`memberOf` never
lists the primary group); an account with a `servicePrincipalName`
(Kerberoastable); `adminCount=1`; or anything in the PAM OUs. Searches are
paged (500 per page; AD caps a page at 1000). Computers and gMSAs are out of
scope: AD rotates those itself. `description` is never collected, because real
directories keep passwords there.

Each candidate gets a tier and a proposed action (first match wins):

| Finding | Action |
|---|---|
| In `exclusions` (krbtgt, RID-500 Administrator, the rotator, the discovery account) | exception, with the policy's reason |
| Disabled | exception: remove rights, don't vault |
| `adminCount=1` but in no privileged group | exception: **orphaned adminCount** (SDProp's ACL is still there) |
| Privileged and stale (no logon in `stale_days`, or never logged on and older than `never_logged_on_grace_days`) | exception: disable |
| Tier 0 **and** an SPN | exception: **Kerberoastable domain admin**; remove from Tier 0 or move to a gMSA |
| Human (no SPN, not in a service OU) | library set of the tier |
| Service account | static role `<tier prefix>/<sam>` |

Output (gitignored): `out/discovery-<UTC>.{json,csv}` and
`out/discovery-latest.*`. "Stale" uses `lastLogonTimestamp`, which replicates
(about every 14 days), not the per-DC `lastLogon`.

**Tenant time (DC01):** `lab/scripts/dc/02-Configure-Domain.ps1` creates
`svc-pam-discovery` as a plain user in `OU=ServiceAccounts` and stores its
password in Key Vault as `svc-pam-discovery` (never on a command line); it is
already in the policy exclusions here, so Vault never onboards or rotates it.

### 2. Bulk onboarding — `onboard.sh`

Reads the latest discovery report and onboards through the **Vault HTTP API**
(curl, token in a header file on a pipe, never argv), one Safe per tier:

- humans → their tier's **library set** (`tier0-admins`, `tier1-admins`).
  Creating or extending a set makes Vault set a new password for each added
  account immediately (checked on Vault 2.1.1 against Samba AD).
- service accounts → **static role** `svc/<sam>` (hierarchical role names, so
  one policy path glob covers a tier). Creating a static role rotates
  immediately, so it is created **only if every dependency is resolved**.
  The rest are **HELD** and show up in the reconcile report.
- Vault policies per tier: `<tier>-checkout` (library check-out/in/status),
  `<tier>-static-read` (`ldap/static-cred/<prefix>/*`, the CCP equivalent),
  and `pam-reconcile` (read-only, for `reconcile.sh`).

`--dry-run` prints the plan and changes nothing. Re-runs are idempotent.
One held account can be forced, with a justification that names a change:

```bash
./onboard.sh --only svc-sql01 --force --operator ops-alice \
  --justification "CHG0031337: DBA updates the MSSQLSERVER logon in the window"
```

`--force` refuses to run without `--only` (no blanket overrides) and without
a justification of at least 20 characters containing `CHG#######`. Overrides
go to the **exception register**, Vault KV v2 `pam-meta/exceptions/<sam>`
(versioned, and every write is in Vault's audit log), and to
`out/pam-audit.jsonl`.

### 3. Dependency gate — `rotate.sh` + `accounts-dependencies.json`

```json
"svc-sql01": [
  { "type": "windows-service", "host": "sql01.corp.test.local", "name": "MSSQLSERVER",
    "owner": "dba-team", "resolved": false }
]
```

`resolved: true` means the consumer reads the password from Vault at run time
(Vault Agent template, the API, a CSI driver) or was decommissioned. Rotation
of a static role (`./rotate.sh <sam>`) is **refused** while any dependency is
unresolved, **and when the account has no record at all**: unknown is not
"none" (an empty list `[]` is the explicit "reviewed, no consumers").
Override for one account with `--force --justification "...CHG#######..."`.
Refusals and overrides are audited.

Vault rotates static roles on its own schedule without asking anyone. That is
why the gate sits where a person starts a rotation: onboarding (creating the
role rotates) and `rotate.sh`. CyberArk's CPM can update a usage as part of the
change; Vault can't, so the operating rule is "no static role until every
consumer reads from Vault".

**Dependency discovery on DC01 / member servers (tenant time).**
`dependency-scan/Get-AccountDependencies.ps1` runs on a Windows server and
lists the services, scheduled tasks and IIS application pools that run as the
given accounts, in this file's format, every finding `resolved: false` (a scan
cannot know that a consumer already reads from Vault). It never reads a
password. Its matching logic is covered by Pester offline
(`test/Get-AccountDependencies.Tests.ps1`); the scan itself has not run on
Windows yet.

```bash
az vm run-command invoke -g rg-identity-lab -n vm-dc01 --command-id RunPowerShellScript \
  --scripts @dependency-scan/Get-AccountDependencies.ps1 \
  --parameters "Accounts=svc-backup" "Domain=CORP" --query 'value[0].message' -o tsv > out/deps-dc01.json
# merge a host's findings into the committed map (review, then set resolved by hand):
jq -s '.[0].accounts as $old | .[1].accounts as $new
       | .[0] | .accounts = ($old * ($new | with_entries(.value = (($old[.key] // []) + .value))))' \
  accounts-dependencies.json out/deps-dc01.json > accounts-dependencies.json.new
```

verify: how `az vm run-command` passes `--parameters` to a script's named
parameters on Windows, and that `Get-ScheduledTask` runs under the run-command
SYSTEM context.

### 4. Reconciliation — `reconcile.sh`

Joins discovery, Vault (static roles, library sets, the exception register)
and the dependency map, and states for every account:

| Status | Meaning |
|---|---|
| VAULTED | in a library set or a static role; plus *rotated within policy* and, with `--verify`, *verified* |
| EXCEPTION | documented: a policy exclusion or a discovery finding (stale, orphaned adminCount, Kerberoastable Tier 0, disabled) |
| HELD | eligible service account kept out by an unresolved dependency |
| **GAP** | discovered, eligible, not vaulted, no exception: **must be 0** |
| ORPHAN | in Vault but not found in AD (deleted, renamed or out of scope) |

*Rotated within policy*: a static role's `last_vault_rotation` is younger than
its `rotation_period` (+5 min); a library account is checked out right now, or
its AD `pwdLastSet` is younger than the tier's `max_password_age_days`.
`--verify` is CPM's **Verify**: an LDAPS bind as the account with the vaulted
password, piped from Vault into the `pam-tools` container, never printed. A
password changed outside Vault fails it, and `./rotate.sh <sam>` (Vault resets
it with the reconcile account) is the **Reconcile**.

It runs with a 15-minute token holding only `pam-reconcile`. Output:
`out/reconcile-<UTC>.{csv,md}` with KPIs at the top (% of eligible accounts
vaulted, % rotated within policy, verified, GAP, ORPHAN). `--strict` exits 3
on any GAP, ORPHAN, out-of-policy rotation or failed verify, for a scheduled
job or CI.

### 5. Ticket validation (ServiceNow) + dual control

Check-out needs `--ticket CHG#######` when the tier has `require_ticket:
true`. The broker asks the Table API for the change and refuses unless it is
**approved**, in **Implement** (`state = -1`), **inside its planned window**
(UTC), **assigned to the operator asking** (no borrowing a colleague's
change) and carries **enough approvals** (dual control, below). Each refusal
names its reason.

```
GET {ITSM_URL}/api/now/v2/table/change_request?sysparm_query=number=CHG0040001
    &sysparm_fields=number,state,approval,start_date,end_date,assigned_to.user_name,requested_by.user_name,short_description
    &sysparm_limit=1&sysparm_display_value=false&sysparm_exclude_reference_link=true
GET {ITSM_URL}/api/now/v2/table/sysapproval_approver?sysparm_query=sysapproval.number=CHG0040001
    &sysparm_fields=approver.user_name,state&sysparm_limit=100&...
```

**Dual control (the CyberArk dual-control equivalent).** The change's
`approval` field alone is not enough. The broker reads ServiceNow's own
approval records (`sysapproval_approver`, one row per approver) and counts an
approval only if it is in state `approved`, comes from someone who is **not
the requester** (neither the operator asking for the account nor the change's
`requested_by`), and comes from someone allowed to approve for that Safe
(`approves` in [`operators.json`](operators.json); CyberArk: the Safe
permission to authorise account requests). Each person counts once.
`pam-policy.json` sets how many distinct approvals a tier needs:

| Tier | `approvals_required` | Safe checked | Example that passes | Refused |
|---|---|---|---|---|
| tier0 (`psm-session.sh`) | **2** | `tier0-admins` | ops-alice's change approved by ops-carol + ops-dana | self-approval, one approver, the same approver twice, an approver without `approves: tier0-admins`, the change's requester approving, a pending approval, any rejection |
| tier1 (`psm-ssh.sh`) | **1** | `linux-admin` | ops-alice's change approved by ops-bob | no approver, self-approval, an approver without `approves: linux-admin` |

It fails closed: a missing, zero or non-integer `approvals_required`, or an
approvals table ITSM cannot serve, stops the check-out. The approvers that
counted go into the check-out token's metadata (`approvers`, so Vault's own
audit log names them next to the operator and the ticket), the PAM audit line
and the check-out state. `./itsm-ticket.sh add ... --approver NAME[:state]`
raises a change with its approvals in the mock; `./itsm-ticket.sh approve
CHG####### --by NAME [--state rejected]` acts as one approver afterwards.
Lab personas: ops-dana is an approver only (she never checks anything out, so
she never gets a Guacamole user). Not built: CyberArk's approval *workflow*
(request, notify, approve in PVWA); here the approvals are made in the ITSM
and the broker only enforces them.

**Pinned to Table API v2**: v2 answers a query with no match with 200 and an
empty `result`, v1 with 404 (ServiceNow's Table API docs, "Versioning"); the
broker treats both "not found" cleanly but v2 keeps errors and absences apart.
`sysparm_display_value=false` returns stored values, so dates are UTC and
`state` is the number, not a localized label.

- **Lab:** `itsm-mock` serves that subset from `itsm/data/tickets.json`
  (gitignored). `./itsm-ticket.sh add CHG####### --operator NAME
  [--approver NAME[:approved|requested|rejected]]... [--requested-by NAME]
  [--approval requested] [--state scheduled] [--start-in-hours N --hours N]`
  raises one; `approve`, `list`, `remove`, `next`. The lab file keeps a
  change's approvals inline; the mock serves them only as
  `sysapproval_approver` rows, with the dot-walked fields a real instance
  returns. The mock holds only SHA-256("user:password") from `.env`; the
  password is in `.secrets/itsm-password`.
- **Tenant time (ServiceNow PDI):** create an integration user (web service
  access only) that can read `change_request`, `sysapproval_approver` and
  `sys_user.user_name` (verify: the least role — `itil` reads changes, a
  custom ACL is tighter); put its password in `.secrets/itsm-password`, set
  `ITSM_URL=https://devNNNNN.service-now.com` and `ITSM_USER` in `.env`, and
  raise a change in the PDI assigned to the operator and approved by two
  other people (whose ServiceNow `user_name`s must equal the names in
  `operators.json`, i.e. the Entra UPNs once OIDC is on). verify: change
  `state` values (-1 = Implement), the dot-walked fields
  `assigned_to.user_name` / `requested_by.user_name`, the query on
  `sysapproval.number`, and the approval `state` values on the PDI's
  release.

### 6. Per-person sign-in (Entra OIDC) — replaces the shared `t0-operator`

Lab: each person in `operators.json` gets a local Guacamole user with a
generated password (`.secrets/operators/<name>-password`). The check-out also
mints a **per-check-out Vault token** with display name `psm-<name>` and
metadata `operator`, `ticket`: Vault's own audit log then names the person and
the ticket on the check-out itself (`auth.display_name =
token-psm-ops-alice`), not a shared broker. Only that token can check the
account back in (Vault's check-in enforcement), and it is revoked at check-in.

**Tenant time — Guacamole signs people in through Entra ID (with MFA and
Conditional Access), no local passwords:**

1. **As code:** `enable_pam_oidc_app = true` in `lab.tfvars` (needs
   `enable_sso_apps`) makes `modules/apps/guacamole.tf` create the
   `guacamole-psm` registration (single tenant, platform **Web**, redirect URI
   `http://localhost:8081/guacamole/`, **ID tokens** only: Guacamole's OpenID
   extension uses the implicit `id_token` flow, so there is no client secret),
   the `PAM-Operators` group as its only assignment, and *Assignment required
   = Yes*. Add the operators to `PAM-Operators` by hand. The portal click-path
   is the fallback only.
2. Conditional Access, also from the same flag: **CA022** (report-only first;
   it was numbered CA009 before the CA set grew) requires the admin
   phishing-resistant authentication strength for `guacamole-psm` and the
   admin portals, so a PSM session always starts with phishing-resistant MFA.
   Graduate it like any other policy, one PR.
3. `.env`: `OIDC_TENANT_ID`, `OIDC_CLIENT_ID`; then
   `docker compose -f docker-compose.yml -f docker-compose.oidc.yml up -d guacamole`
   (`docker-compose.oidc.yml`: authorization, JWKS and issuer endpoints for
   the tenant, `preferred_username` as the Guacamole username,
   `POSTGRESQL_AUTO_CREATE_ACCOUNTS` so SSO users get a record that per-
   connection READ grants can attach to, `EXTENSION_PRIORITY "*, openid"` so
   guacadmin keeps the local form for break-glass and History playback).
4. Rename the `operators.json` keys to the operators' UPNs (names may contain
   `@`). With `OIDC_CLIENT_ID` in `.env` (or `PAM_OIDC=1`) the scripts run in
   **OIDC mode** (`lib.sh` `pam_oidc_mode`): `ensure_guac_operator` never
   creates a user and never sets a password. The person signs in through
   Entra once (auto-create makes the record), then `psm-session.sh` /
   `psm-ssh.sh` grant READ to that record; before that they refuse with "sign
   in through Entra first". Any local password on the record (a lab leftover
   or one typed in by an admin) is overwritten with a random value that is
   never stored, and `.secrets/operators/<name>-password` is deleted, because
   the local form stays on the page for guacadmin and `/api/tokens` would
   otherwise accept an operator's database password and skip Entra MFA and
   Conditional Access. `test/e2e.sh` step g3 proves this locally (old
   password refused by `/api/tokens`, attributes kept, no user for someone
   who never signed in). verify: whether a Guacamole 1.6 auto-created record
   has a usable password at all (if not, the overwrite is belt-and-braces).

verify: Guacamole 1.6.0 docker variable names (`OPENID_*`,
`POSTGRESQL_AUTO_CREATE_ACCOUNTS`, `EXTENSION_PRIORITY`) and whether 1.6 added
an authorization-code flow (the 1.6 OpenID docs still describe implicit).

### 7. Vault SSH CA + recorded SSH session — `psm-ssh.sh`

`setup` enables Vault's SSH secrets engine as a **user CA** (`ssh-client-signer`,
ed25519 key generated inside Vault), role `linux-admin` (principal
`linux-admin` only, 10-minute certificates, `permit-pty` only, key ID =
`{{token_display_name}}-{{role_name}}`), starts `ssh-target` (trusts only that
CA's public key, maps principal `linux-admin` to the local `labadmin`,
passwords and `authorized_keys` off), and creates the Guacamole connection
`LINUX - ssh-target (recorded)` with **graphical recording and a text
typescript** and the target's **host key pinned**.

`checkout --operator NAME --ticket CHG#######` (Safe: `ssh_roles` in
`operators.json`; ticket: tier1 policy) generates a fresh key pair, has Vault
sign it with a per-session token (`psm-NAME`), injects key + certificate into
the connection (the operator never holds either) and grants READ to NAME. The
certificate dies in 10 minutes whatever happens. `checkin` wipes both and
revokes READ. sshd logs at VERBOSE, so the target's own log says
`Accepted publickey for labadmin ... ID token-psm-ops-alice-linux-admin
(serial N)`: the person survives all the way to the server, and the serial
joins that line to `out/pam-audit.jsonl`.

### 8. HA / DR — `vault-ha.sh`, `dr-drill.sh`

A separate compose project (`contoso-pam-ha`, ports 127.0.0.1:8210-8212) so the
lab Vault the scripts use is never touched.

- `./vault-ha.sh up` — `vault-unsealer` (file storage, 1 key share, transit key
  `autounseal`, an orphan periodic token allowed only `encrypt`/`decrypt` on
  that key), then `vault-1/2/3`: initialised once with **recovery** keys
  (auto-unseal means no unseal keys exist), the others join via `retry_join`
  and unseal themselves. Waits for 3 voters and autopilot healthy.
  `performance_multiplier = 1`, `disable_mlock = true` (HashiCorp's guidance for
  integrated storage).
- `./vault-ha.sh failover` — SIGKILLs the leader and times how long until a
  new leader **accepts a write**, then restarts the old node and times its
  rejoin. Measured on the laptop (2026-10-20, five runs): **2-4 s** to a new
  writable leader, 1-4 s to rejoin.
- `./dr-drill.sh` — the timed drill: write a marker and a policy, raft
  snapshot (sha256 recorded), write a second marker, then **delete all three
  nodes and their volumes**. Rebuild: a fresh one-node cluster, `snapshot
  restore -force`, restart that node (see below), then join the other two.
  Verifies with the OLD root token that the marker and policy are back and
  that the post-snapshot write is **gone** (that is the RPO, demonstrated).
  Report: `out/dr-drill-<UTC>.md/.json` with **RTO** (disks gone → data
  served; 32.5, 40.5 and 42.1 s in the three hashed drills in
  `lab/evidence/pam-dr/`) and **RPO** (snapshot age at the disaster).
  Exit 1 if a check fails or RTO exceeds `--target-rto` (default 300 s).
- Two things learned by running it, both in the scripts: restore into a
  **one-node** cluster and **restart that node before the others join**.
  Otherwise the joiners and the restored node disagree on the Raft TLS keyring
  and the cluster splits on the next restart (`tls: unrecognized name`).
  verify: against HashiCorp's restore runbook for the version you run.
  Also, after a restore the **old** recovery key and root token are valid
  again (the keyring came back with the data).

**Production: Azure Key Vault auto-unseal** instead of the transit unsealer.
The key lives in an HSM-backed, zone-redundant service outside the cluster's
blast radius, and the nodes authenticate with a **managed identity**, so no
credential exists to leak:

```hcl
seal "azurekeyvault" {
  tenant_id  = "<tenant id>"            # or AZURE_TENANT_ID
  vault_name = "kv-idlab-unseal"        # or VAULT_AZUREKEYVAULT_VAULT_NAME
  key_name   = "vault-unseal"           # or VAULT_AZUREKEYVAULT_KEY_NAME
  # no client_id / client_secret: Vault on an Azure VM / AKS uses its managed identity
}
```

The identity needs wrap/unwrap on that key only (verify: the RBAC role, e.g.
*Key Vault Crypto Service Encryption User*, and the supported key types
RSA-2048/3072/4096 / RSA-HSM). Turn on soft-delete and purge protection on that
Key Vault: deleting the key deletes every Vault cluster and snapshot it
protects. Moving an existing Shamir cluster is a **seal migration**: add the
stanza, restart each node, `vault operator unseal -migrate` with the old
shares (verify: HashiCorp's seal-migration steps for your version; it turns
unseal keys into recovery keys). Recovery keys go 3-of-5 to named custodians.

### Upgrade runbook (rolling, zero downtime)

`./vault-ha.sh upgrade --to hashicorp/vault:<new>` scripts it; without `--to`
it re-deploys the current image as a rehearsal of exactly these steps.

1. **Read the release notes** and upgrade guide for every version in between
   (deprecations, storage migrations, plugin changes). Upgrade one minor
   version at a time unless the notes say a skip is supported.
2. **Rehearse** on a copy: restore last night's snapshot into a scratch
   cluster on the new version and run the smoke test (unseal, auth, read a
   secret, a library check-out/check-in).
3. **Change window + ticket**, and a fresh **snapshot** (`vault operator raft
   snapshot save`), sha256 recorded. This snapshot plus the old image is the
   rollback.
4. Check health first: 3 voters, `vault operator raft autopilot state` healthy,
   failure tolerance ≥ 1. Never start degraded.
5. **Followers first, one at a time:** replace the node (new image, same data
   volume), wait until it is unsealed, a voter again and autopilot-healthy,
   then the next. Quorum (2 of 3) holds throughout.
6. **Leader last:** `vault operator step-down` so the election happens on your
   schedule, wait for a new leader, then replace the old leader the same way.
7. Verify: every node reports the new version (`vault status`), autopilot
   healthy, audit device writing, a check-out/check-in and a static-role
   rotation succeed, `./reconcile.sh --strict` passes.
8. **Rollback** if any step fails: stop, restore the step-3 snapshot on the old
   version (a new cluster + `snapshot restore -force`, as in the DR drill).
   Downgrading a node in place is not supported once the new version has
   written to storage.

---

## midPoint: Entra aggregation (tenant time, about 10 min, in the UI)

The certification campaign itself is automated and has run locally:
[`midpoint/README.md`](midpoint/README.md) (`run-campaign.sh`, risk tier T2
from ADR 0012, evidence in `../evidence/midpoint/`, `test/e2e-midpoint.sh`).
Its users come from object files built from the mock-HR personas. What still
needs a tenant is reading the users from Entra, below. After that, point the
campaign's scope at the aggregated users instead of the persona files.

The Microsoft Graph connector is **not bundled** in `evolveum/midpoint:4.10.4`.
Its REST API (`GET /midpoint/ws/rest/connectors`, checked by `test/e2e.sh`)
lists only the LDAP bundle 3.9.4 (`LdapConnector`, `AdLdapConnector`), CSV 2.9,
DatabaseTable 1.5.3.0 and the built-in Manual/Async connectors. Evolveum
publishes the Graph connector separately: Maven
`com.evolveum.polygon:connector-msgraph`, latest release **1.2.0.0**
(2023-10-12), connector class
`com.evolveum.polygon.connector.msgraphapi.MSGraphConnector`, source
[Evolveum/connector-microsoft-graph-api](https://github.com/Evolveum/connector-microsoft-graph-api).
Whether 1.2.0.0 loads cleanly in midPoint 4.10 is *verify*: it hasn't been
deployed here yet.

0. **By hand:** deploy the connector. midPoint scans
   `/opt/midpoint/var/connid-connectors`, which lives on the `midpoint-home`
   volume, so this survives restarts. The JAR goes to a temp directory, never
   into the repo, and is copied in only if it matches Nexus's published SHA-1:
   ```bash
   jar=connector-msgraph-1.2.0.0.jar; tmp=$(mktemp -d)
   curl -fL -o "$tmp/$jar" "https://nexus.evolveum.com/nexus/repository/public/com/evolveum/polygon/connector-msgraph/1.2.0.0/$jar" &&
     echo "22ac00a1778595a253992d0cb1e2faefdb2053d8  $tmp/$jar" | shasum -a 1 -c - &&
     docker compose cp "$tmp/$jar" midpoint:/opt/midpoint/var/connid-connectors/ &&
     docker compose restart midpoint
   rm -rf "$tmp"
   ```
1. **By hand (portal):** Entra → App registrations → New `midpoint-reader`.
   Grant Graph **application** permissions `User.Read.All` and
   `Group.Read.All`, then grant admin consent. *verify:* this read-only pair
   is untested. Evolveum's connector page lists a wider "required" set,
   including `GroupMember.Read.All` and `Directory.Read.All` plus ReadWrite
   permissions a read-only import shouldn't need. If *Test connection* or the
   import fails, add the read-only `GroupMember.Read.All` /
   `Directory.Read.All` first, and record the set that works. Create a client
   secret and paste it **only** into midPoint in the next step. The secret
   lives in the IGA tool's credential store, which is where SailPoint keeps
   connector credentials too.
2. `http://127.0.0.1:8082/midpoint`: sign in as `administrator` with
   `MIDPOINT_ADMIN_PASSWORD` from `.env`.
3. *Resources → New resource*, then pick `MSGraphConnector`
   (`com.evolveum.polygon.connector.msgraphapi.MSGraphConnector`). Enter the
   tenant id, client id and secret, then *Test connection*. Add an object type
   *Account* with an **import** task.
4. Run the import, then open *Users* (shadows linked to owners).
5. *Certifications → Campaign definitions → New*: scope *Users with
   department = Nursing*. Start it, make one approve and one revoke decision,
   then close it.

## RDP recording without DC01 (Linux xrdp stand-in)

Samba AD has no RDP, so until now the brokered RDP session could only be shown
against DC01 in Azure. `rdp-target/` closes that gap in the harness **without
pretending to be Windows**: it is a **Linux xrdp stand-in for an RDP session
to DC01**, labelled as such everywhere it appears (container, connection name
`RDP-TARGET (Linux xrdp stand-in for DC01) - <account> (recorded)`, the
session's own banner, the run record).

- **Image:** `rdp-target/Dockerfile`, Debian's xrdp 0.10 + xorgxrdp on the same
  Debian image as the other local images, pinned by tag **and** digest
  (`debian:trixie-20260918-slim@sha256:a99cfc51...`). Compose profile `rdp`,
  no host port: only guacd reaches it.
- **Logon = the AD password, nothing else.** `xrdp-sesman`'s PAM stack is
  `pam_krb5` only (Kerberos AS-REQ to the DC that `.env`'s `DC_FQDN` →
  `DC_PUBLIC_IP` mapping names, the same mapping Vault uses). The local
  accounts (`tier0-admin-01/02`) exist only for a uid and a home; their
  password field is `*`. Only `rdp-admins` may log on, never root; clipboard,
  drive, sound and RemoteApp channels are off; a fresh TLS certificate per
  start; a disconnected session is killed at once.
- **The session** is one light xterm filling the 1024x768 screen (no window
  manager). Typing `exit` ends the session and xrdp drops the connection.
- **Brokered exactly like DC01:** `./psm-session.sh checkout --operator NAME
  --ticket CHG####### --target rdp-target` runs the same gates (Safe, ticket,
  dual control), the same Vault check-out and the same injection; only the
  connection differs (`rdp-target:3389`, `security=tls` because xrdp has no
  NLA, no domain). Check-in rotates the password as usual.

**Headless session and playback (`test/e2e.sh` step g4).** The harness signs
in to Guacamole as the operator (her own token, READ on the one connection)
and drives a real RDP session over Guacamole's HTTP tunnel with
`test/guac_tunnel.py` (`--mouse` puts the pointer over the xterm, keys are
sent as keysyms, `id > rdp-proof; hostname >> rdp-proof; exit` is typed).
guacd writes the recording to `${HISTORY_PATH}/${HISTORY_UUID}/recording`,
where the History page looks. "Plays back" is shown three ways, none of them
a video:

1. `test/guac_recording.py`, the **guacamole-recording format check**: the
   file is a complete Guacamole protocol stream (strict framing, no
   truncation), the screen is 1024x768, every image stream decodes (PNG:
   chunk CRCs and inflated pixel data; JPEG: SOI/SOF/EOI), `sync` timestamps
   never go backwards and span the session, and the drawing reaches the
   screen (the share of pixels painted). `test/guac_recording.test.py` proves
   the check is not vacuous: it passes 6 well-formed recordings and fails 23
   broken ones (offline suite `recording-format`, 29 checks).
2. The web app's History lists the recording for that session and serves its
   player **the same bytes** guacd wrote (sha256 compared), while the operator
   herself gets 403/404 for it: playback is for reviewers.
3. The session itself happened as the AD account: the typed `id` wrote
   `uid=...(tier0-admin-0N)` on `rdp-target`, `xrdp-sesman` logged the
   Kerberos logon, and after check-in the KDC answers `Password incorrect` for
   the password the session used.

No video: `guacenc` is not in the `guacamole/guacd:1.6.0` image and Debian
trixie does not package guacamole-server; building it from Apache's source
release is the way to get one (not done). The run record keeps
`rdp-recording.json` (operator, account, approvers, history id, the
recording's size, sha256, frames, duration, image counts, screen painted),
never the recording.

**What it does not prove:** anything Windows-specific: NLA/CredSSP, the
Windows logon and its event log, an RDP session to a domain controller,
Restricted Admin / Remote Credential Guard. Those still need DC01 (Verify list
below).

```bash
# by hand, after test/e2e.sh (samba-dc up, .env pointing at it)
docker compose --profile rdp up -d --build rdp-target
./itsm-ticket.sh add "$(./itsm-ticket.sh next)" --operator ops-alice --approver ops-carol --approver ops-dana
./psm-session.sh checkout --operator ops-alice --ticket CHG00400NN --target rdp-target
#   -> http://127.0.0.1:8081/guacamole as ops-alice: "RDP-TARGET (Linux xrdp stand-in for DC01) - tier0-admin-0N (recorded)"
./psm-session.sh checkin tier0-admin-0N        # recording: Settings -> History (as guacadmin)
```

## Test suites and the runner

`test/run-all.sh` runs every PAM suite from one entry point, in this order,
and prints a per-suite and total PASS / FAIL / SKIP table. A suite passes only
if it exits 0 **and** printed no `FAIL` line; `SKIP` lines are counted
separately, never as passes. It starts the shared stack with `./pam-up.sh`
first when `e2e` or `midpoint` is selected. The `scale` suite is optional
and off by default (several minutes): it runs only with `--scale` or when
named in `--only`.

| Suite | Script | What it proves | Needs | Every default run on 2026-10-20 (latest: the newest `../evidence/offline-tests/` record; the same in the nightly fresh-clone runs on GitHub's runners) |
|---|---|---|---|---|
| `dependency-scan` | `test/Get-AccountDependencies.Tests.ps1` (Pester) | The Windows dependency scan's matching logic, offline, on fixtures (the scan itself has never run on a Windows host; rotation is gated on the hand-maintained `accounts-dependencies.json`) | `pwsh` + Pester 5 | 8 passed |
| `ingest` | `../scripts/monitoring/tests/ingest-vault-audit.test.sh` | The Vault audit → `VaultCheckout_CL` feed script, against fixtures and stubs | `jq` | 30 passed |
| `itsm-dual-control` (new) | `test/itsm-dual-control.test.sh` | Ticket validation and **dual control**, offline: the real `lib.sh` `itsm_validate` against the real ServiceNow mock (started on 127.0.0.1) with the committed policy and operators. Tier 0: two distinct authorised approvers accepted; self-approval, one approver, the same approver twice, an approver without the Safe right, the change's requester, a pending approval, any rejection refused; a missing / 0 / string / fractional `approvals_required` and an approvals table answering 500 refused (fail closed). Tier 1: one approver accepted, none / self / unauthorised refused. The older gates, the mock's ServiceNow shape | `python3`, `jq`, `curl` | 45 passed |
| `recording-format` (new) | `test/guac_recording.test.py` | The guacamole-recording format check (`test/guac_recording.py`) passes 6 well-formed recordings and fails 23 broken ones (truncation, bad framing, bad base64, PNG CRC / pixel-size errors, streams never opened, wrong screen size, no images, off-screen-only drawing, time going backwards, too short, JPEG without SOF / EOI, unknown image type, not UTF-8, empty), so e2e's "plays back" is a real check | `python3` | 29 passed |
| `e2e` | `test/e2e.sh` | The AD-dependent PAM flow against a Samba AD DC: onboarding, check-out gates + **dual control**, PSM, **a recorded RDP session to the Linux xrdp stand-in that plays back** (g4), discovery, onboarding at scale, dependency gate, reconciliation, SSH CA (one approver), HA/DR (section below) | shared stack (+ `rdp-target`, built by the run) | 284 passed (was 241 before dual control and g4) |
| `midpoint` | `test/e2e-midpoint.sh` | Two certification campaigns, the evidence, and the live state after remediation ([`midpoint/README.md`](midpoint/README.md)) | shared stack (midPoint) | 91 passed |
| `dynamic-db` | `test/e2e-dynamic-db.sh` | Vault dynamic database credentials, rebuilt from scratch ([`dynamic-db/README.md`](dynamic-db/README.md)) | Docker (own project `contoso-dyndb`) | 60 passed |
| `vault-anomaly` | `test/e2e-vault-anomaly.sh` | Real Vault audit events (ticketed and unticketed check-outs, a read with no check-out, a 403, failed logins, a rotation failure with the DC down) → `ingest-vault-audit.sh --signals all` → rows; the detection's six signal predicates re-stated in `jq` over those rows; no secret in the log or the rows | Docker (own project `contoso-vaultanom`) | 63 passed, 1 skipped (the SPL twin runs only when a local Splunk is up) |
| `scale` (optional) | `test/e2e-scale.sh` | 500 synthetic privileged accounts (plus 250 ordinary staff) in a Samba AD DC, through the real discover → onboard → dependency check → rotate → reconcile scripts, every stage timed: everything in scope vaulted, held accounts untouched, blocked rotations refused, GAP 0, ORPHAN 0 | Docker (own project `contoso-pamscale`) | not in a default run (optional); last run on its own 2026-10-20 19:39 UTC: 83 passed (the 79 checks in its hashed record `../evidence/pam-scale/20261020T193913Z/`, plus 4 that verify the record) |
| **Total** | | | | **610 passed, 0 failed, 1 skipped; 8/8 suites (scale not selected): 498 end to end in Docker, 112 offline. With `--publish` (`20261020T220031Z`), record checks 8 passed, 0 failed (the e2e + DR records re-verified)** |

```bash
cd lab/pam
test/run-all.sh                          # everything except scale (~6-7 min; e2e alone is ~4-4.5 min)
test/run-all.sh --scale                  # also the 500-account run (adds about 3.5 min)
test/run-all.sh --only dependency-scan,ingest,itsm-dual-control,recording-format   # offline suites only, no containers
test/run-all.sh --skip-ha                # e2e without the 3-node Raft / DR drill
test/run-all.sh --publish                # also write hashed run records to ../evidence/ (below)
test/run-all.sh --cleanup                # afterwards: e2e.sh --cleanup + e2e-dynamic-db.sh --cleanup
```

Logs and `summary.json` go to `out/test-runs/<UTC>/` (gitignored: they name
lab accounts and operators). Test runs write to `../evidence/` only with
`--publish`: then `e2e.sh` writes its run record to `pam/<UTC>/`,
`dr-drill.sh` its RTO/RPO record to `pam-dr/<UTC>/` and the scale suite its
timed record to `pam-scale/<UTC>/`, each re-checked with `--verify` straight
after (a record that does not verify fails the suite). The other records
come from `midpoint/run-campaign.sh` and `test/e2e-dynamic-db.sh
--evidence-dir`. Every record has a `SHA256SUMS`.

What the harnesses do **not** prove: anything about Entra ID, DC01, an RDP
recording of a Windows session (the RDP session in the harness is the Linux
xrdp stand-in), ServiceNow itself (the approvals come from the mock), or
whether the KQL / SPL detections fire. Those are tenant-time captures in
[`../docs/evidence-capture-plan.md`](../docs/evidence-capture-plan.md).

## Rehearse without Azure (Samba AD harness)

`test/e2e.sh` builds a **real Active Directory DC** (Samba 4.22 AD DC from
Debian's own packages on the official `debian:trixie-20260918-slim` image, no
third-party Samba images). It is `dc01.corp.test.local` with the DC01 layout:
`OU=ServiceAccounts` holds `svc-vault-rotator` and `svc-backup`,
`OU=PrivilegedAccounts` holds `tier0-admin-01/02` in Domain Admins, and every
CN equals its sAMAccountName. On top of that it plants **one account per
discovery finding**: `svc-pam-discovery` (the read-only bind), `svc-sql01`
(SPN, two unresolved dependencies), `svc-iis-app` (SPN, resolved),
`svc-legacy-da` (SPN + Domain Admins), `t1-srvadmin-01/02` (a custom tier-1
group), `t0-stale-admin` (last logon backdated 400 days), `t0-never-admin`
(Administrators through a nested group, created 200 days ago, never used) and
`former-admin-01` (orphaned `adminCount`). The harness then runs the real
scripts against it, only `az` stubbed (`test/stub-az/az`). Each assertion
prints PASS or FAIL, checked over LDAPS binds and `pwdLastSet`. Passwords are
never printed. Reports go to `out/e2e/`, never mixed with real evidence.

```bash
cd lab/pam
./pam-up.sh               # the stack must be up
test/e2e.sh               # ~4-4.5 min (284 checks); exits 1 on any FAIL; samba-dc stays up afterwards
test/e2e.sh --skip-ha     # same without the HA/DR section (~1 min less)
test/e2e.sh --cleanup     # remove samba-dc + volume, the harness's tickets, ssh-target and the
                          # HA cluster if the harness made them, empty DC_FQDN/DC_PUBLIC_IP
```

What it proves:

- **Onboarding** (the real script, first run) installs the DC's root CA
  (delivered with CRLF line endings, as PowerShell prints it), points Vault at
  the DC through the `.env` host mapping and reads the bind password from
  "Key Vault". It rotates `svc-backup`: the old password is rejected and the
  Vault one binds.
- **Guardrails:** a second directory is refused before anything changes, and
  a failed Key Vault read stops the run before an empty bind password
  reaches Vault.
- **`--rotate-root`** takes the bind password away from Key Vault, and
  re-runs don't write the stale copy back. Vault can still rotate afterwards.
- **Check-out gates:** no operator, an unknown operator, an operator outside
  the Safe, no ticket, an unapproved / expired / still-scheduled / someone
  else's / unknown / malformed ticket are each refused with their own reason,
  before anything is checked out. A `pam-policy.json` with the
  `require_ticket` key missing, or one that does not parse, stops the
  check-out instead of skipping the ticket (fail closed). The shared
  `t0-operator` is gone.
- **Dual control:** through the real `psm-session.sh`, a self-approved
  Tier-0 change, a single approver and an approver without the Safe right are
  refused, and so is a valid change when `approvals_required` is missing from
  the policy; the check-outs succeed only with two distinct approvers, neither
  the requester, and those approvers reach Vault's audit log (token metadata)
  and the PAM audit line. Tier 1 (`psm-ssh.sh`): no approver and
  self-approval refused, one authorised approver accepted. Every other branch
  of the rule runs offline in `test/itsm-dual-control.test.sh`.
- **OIDC mode** (step g3, `PAM_OIDC=1`): an operator's local Guacamole
  password stops working at `/api/tokens`, its file is deleted, admin-set
  attributes survive, and someone who never signed in through Entra gets no
  local user at all.
- **PSM:** check-out injects a working password into Guacamole; **only** the
  named operator sees the connection, and gets 403 on its parameters; Vault's
  audit log names the operator and the ticket; the second person gets the
  other account; a third check-out is refused because Vault says the pool is
  exhausted. Check-in rotates the password, wipes the connection, removes the
  grant, revokes the check-out token and returns the account to the library.
- **Recordings volume:** guacd can write a recording and the web app can
  read it back.
- **RDP without DC01 (step g4):** a dual-approved check-out `--target
  rdp-target` injects the Vault password into a recorded RDP connection to the
  Linux xrdp stand-in; a real RDP session runs through Guacamole as the
  operator, the typed command runs as the AD account (Kerberos logon to the
  Samba DC), the recording passes the format check and is the file the web
  app's History serves (the operator cannot fetch it), and after check-in the
  KDC refuses the old password ([section](#rdp-recording-without-dc01-linux-xrdp-stand-in)).
- **Discovery** classifies every planted finding (nested and primary-group
  membership, SPNs, stale, never used, orphaned `adminCount`, exclusions), and
  a wrong discovery password fails cleanly.
- **Onboarding at scale:** dry run changes nothing; the bulk run creates the
  static role and the tier-1 library (passwords really change), holds
  `svc-sql01` (password untouched) and also a library candidate that a
  scheduled task runs as, or that has no dependency record (tier
  `dependency_check`), writes the Safe policies, and each Safe's
  token can do exactly its own job and nothing in another tier. Re-runs are
  idempotent; `--force` needs `--only` and a CHG-referenced justification.
- **Dependency gate:** resolved → rotates; a new unresolved consumer, or no
  record at all → refused, password untouched, refusal audited. The Windows
  scan's logic passes its Pester tests.
- **Reconciliation:** `--verify --strict` passes (GAP 0); a password reset
  outside Vault fails *verify* and `rotate.sh` repairs it; a forced onboarding
  lands in the exception register and on the report row; an account deleted
  in AD becomes an ORPHAN.
- **SSH:** a key without a certificate, a certificate for `root`, and an
  expired certificate are all refused; a real SSH session runs **through
  Guacamole as ops-alice** (the harness drives Guacamole's HTTP tunnel with
  `test/guac_tunnel.py`), and the typescript holds the command output, the
  graphical recording exists and passes the same format check as the RDP one,
  Guacamole's history says ops-alice, and sshd's log names the certificate
  key ID and serial. The SSH check-out needs one approver (Tier 1).
- **HA/DR:** 3 voters; leader crash → new writable leader; the DR drill's
  marker/policy are restored, the post-snapshot write is lost, RTO within
  target; a rolling upgrade leaves the cluster healthy.
- **Conjur** allow/deny, **midPoint** REST login (a wrong password gets a
  401) and the connector inventory.

"Rejected" always means the DC answered `invalidCredentials` (LDAP 49). An
unreachable DC or an empty password fails that check, so a negative check
can't pass by accident.

Where the test DC differs from DC01 (on purpose):

- `svc-vault-rotator` is a **Domain Admin** there. DC01 grants it only Reset
  Password plus `pwdLastSet`/`lockoutTime` writes, on `OU=ServiceAccounts` and
  on AdminSDHolder (`../scripts/dc/02-Configure-Domain.ps1`). Samba doesn't
  run SDProp, so copying that ACL wouldn't prove anything. For the same reason
  the seed sets `adminCount=1` itself on protected-group members, as SDProp
  would within an hour on Windows.
- LDAPS uses a lab CA minted at first start. Samba's own auto-generated
  certificate is rejected by Vault's Go TLS stack: the CA has a negative
  serial number, and the host certificate has no subjectAltName.
- `old password allowed period = 0`. By default Samba keeps accepting the
  previous password for 60 minutes after a change or reset, LDAP simple binds
  included. Windows has a shorter, NTLM-only window: 5 minutes by default
  after a password change (`OldPasswordAllowedPeriod`, Microsoft KB 906305),
  and only when Enforce Password History remembers two or more passwords.
  *verify:* whether that window also applies to Vault's administrative reset
  on DC01.
- No RDP. The harness checks the DC01-style injected credential with an LDAPS
  bind, and runs the RDP session itself against `rdp-target`, the Linux xrdp
  stand-in (step g4): a real RDP session and a real recording, but not a
  Windows one. An RDP recording of a Windows session still needs DC01.
- No DNS alias for `dc01.corp.test.local` on the Docker network. As with
  DC01, Vault finds the DC only through the `extra_hosts` mapping that
  onboarding writes to `.env`. The harness checks that guacd, which has no
  mapping, can't resolve the name.

The harness owns Vault's `ldap/` mount while it runs. It refuses to start if
Vault or `.env` already point at another DC, unless you pass `--force`.
`--cleanup` removes the mount: if test roles were left behind, a later real
onboarding would skip its first rotation.

## Verify (definition of done)

- [x] `test/run-all.sh --publish`: 8/8 suites, 610 passed, 0 failed, 1 skipped; record checks 8/8 (2026-10-20 22:00 UTC, run `20261020T220031Z`, Colima, author's working copy). The same totals in every later default run on the current code (latest: the newest `../evidence/offline-tests/` record). From a fresh clone: `.github/workflows/pam-harness.yml`, nightly on GitHub's runners, the same totals in each of its three runs so far (2026-10-21 to 2026-10-23; latest [39937464414](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39937464414))
- [x] `test/e2e.sh` against the Samba AD harness: 284/284 PASS (same run, incl. Tier-0 dual control, the RDP session to the Linux xrdp stand-in (g4), OIDC mode g3 and the fail-closed policy gates; hashed record `../evidence/pam/20261020T220031Z/` with `rdp-recording.json`; earlier 241/241 records `20261020T184052Z`, `20261020T204851Z` predate dual control and g4)
- [x] Dual control: `test/itsm-dual-control.test.sh` 45/45 offline; through `psm-session.sh` / `psm-ssh.sh` in e2e: Tier-0 self-approval and single approver refused, two distinct approvers accepted, Tier-1 single approver accepted (same run)
- [x] Recorded RDP session through Guacamole to `rdp-target` (**Linux xrdp stand-in for DC01**, not Windows): the Vault-injected AD password logs on (Kerberos), the recording passes the format check (`recording-format` 29/29 proves the check) and the History API serves the same bytes; the old password is refused after check-in (same run)
- [x] `test/e2e-midpoint.sh`: 91/91 PASS; `test/e2e-dynamic-db.sh`: 60/60 PASS (hashed record in `../evidence/dynamic-db/`); `test/e2e-vault-anomaly.sh`: 63 PASS, 1 SKIP (no local Splunk) (same run)
- [x] `test/e2e-scale.sh` (`--scale`): 500 synthetic accounts, 79/79 in the hashed record `../evidence/pam-scale/20261020T193913Z/`, GAP 0, ORPHAN 0 (2026-10-20 19:39 UTC)
- [x] `./pam-up.sh` ends with the endpoint list and no `ERROR` (2026-10-20, upgraded in place from the 2026-10-19 stack)
- [x] Vault HA: failover, DR drill (RTO/RPO report, latest `../evidence/pam-dr/20261020T220031Z/`: RTO 42.1 s, target 300 s), rolling-upgrade rehearsal (2026-10-20, in the harness, on the separate rehearsal cluster; restoring the credential vault and reconciling drift after a restore is not drilled)
- [x] Recorded SSH session through Guacamole with a Vault SSH certificate; its recording passes the same format check (2026-10-20, in the harness)
- [ ] **Tenant time:** `svc-pam-discovery` created on DC01 + Key Vault secret; `./discover.sh` against DC01; `./onboard.sh` and `./reconcile.sh --verify --strict` pass
- [ ] **Tenant time:** `Get-AccountDependencies.ps1` run on DC01 through `az vm run-command`; findings merged into `accounts-dependencies.json`
- [ ] Vault UI: `ldap/` engine, static roles `svc-backup` + `svc/*`, libraries `tier0-admins`, `tier1-admins`
- [ ] Audit log records each check-out (with `token-psm-<operator>` and the ticket), check-in and rotation. Vault's UI has no audit view, so read the file device `pam-up.sh` enables (values are HMAC'd):
      `docker compose exec -T vault tail -n 500 /vault/logs/audit.log | jq -c 'select(.type=="response") | {time, path: .request.path, op: .request.operation, who: .auth.display_name, ticket: .auth.metadata.ticket}' | grep -E 'check-out|check-in|static-cred|rotate'`
- [ ] On DC01, `Get-ADUser svc-backup -Properties PasswordLastSet` matches `last_vault_rotation`
- [ ] `./psm-session.sh checkout --operator ... --ticket ...` twice → the second call gets `tier0-admin-02`; a third fails (exclusive)
- [ ] Guacamole session to DC01, signed in as the operator, works **without typing a password**; after `checkin` the RDP recording of the **Windows** session plays back (the harness's RDP session is to the Linux xrdp stand-in)
- [ ] After `checkin`, the account's `PasswordLastSet` has changed (rotate-on-check-in)
- [ ] **Tenant time:** Guacamole sign-in through Entra OIDC with phishing-resistant MFA; History shows the UPN
- [ ] **Tenant time:** check-out validated against a change in the ServiceNow PDI (`ITSM_URL` pointed at it), approved there by two people other than the requester (dual control on real `sysapproval_approver` records)
- [ ] `./conjur-demo.sh` prints *fetched* for nightly-report and *denied (403)* for unapproved-job
- [x] midPoint: a closed certification campaign with accept, revoke and no-response decisions, remediation applied, hashed evidence (`midpoint/run-campaign.sh`, 2026-10-20, mock-HR persona users)
- [ ] **Tenant time:** midPoint aggregates the Entra users through the Graph connector (section above)

## Security notes

- Every port binds to **127.0.0.1**. Nothing is exposed to the network.
- `.env`, `.secrets/` and `out/` are gitignored, mode 0600/0700. Vault's unseal
  key and root token live in `.secrets/vault-init.json`, the HA cluster's
  recovery key and root token in `.secrets/ha/init.json`, its snapshots in
  `.secrets/ha/snapshots/` (0600: a snapshot is the whole vault, encrypted, and
  is only as safe as the seal key). **Lab only.** Production uses Shamir 3-of-5
  across custodians or `seal "azurekeyvault"` auto-unseal (above).
  Deliberate exceptions hold public material, or lab-only material that a
  container user must read: `.secrets/vault-ca/` (755, the AD root CA),
  `.secrets/ha/seal.hcl` (644 inside `.secrets/`, which stays 0700: the transit
  token, valid only for encrypt/decrypt on one key of an unsealer that is not
  published), `guacamole/initdb.sql` (644, the stock schema) and
  `itsm/data/tickets.json` (644, mock tickets).
- The bind password is piped into Vault on **stdin** (never a command-line
  argument) and read from Key Vault. After `--rotate-root`, only Vault knows it.
- No secret goes on a command line. Vault tokens are forwarded as environment
  variables (`docker compose exec -e NAME`) or handed to curl as a header file
  on a pipe (`vault_api`); passwords go through stdin or curl config read from
  stdin; the discovery password and the vaulted password `reconcile.sh
  --verify` tests are piped into the container. The one exception is
  test-only: the Samba harness gives `samba-tool provision` a throwaway
  Administrator password, which is replaced immediately.
- `svc-vault-rotator` is effectively **Tier 0** (it can reset Domain Admin
  passwords via AdminSDHolder). That's the same position as a CyberArk CPM
  reconcile account, and it's why its credential is vaulted and rotated.
  Discovery deliberately uses a separate, read-only account.
- Each check-out uses its **own short-lived Vault token** (policy
  `tier0-checkout`, named after the operator, carrying the ticket), not a
  shared broker token and never the root token; it is revoked at check-in.
  `reconcile.sh` runs with a 15-minute read-only `pam-reconcile` token.
- SSH access is by **10-minute certificates** only; the target has no
  `authorized_keys` and no passwords. The session key pair exists on disk
  only in `.secrets/psm-ssh/` (0700) between generation and injection.
- Reports and the audit trail (`out/`) name accounts and operators, never a
  password, token or key.
