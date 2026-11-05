# Monitoring scripts: notify, ITDR containment, PAM check-out feed

Identity Threat Detection and Response (ITDR) for the Contoso Health lab:
eleven detections (KQL for Sentinel / Log Analytics, SPL twins for Splunk), a
human-approved containment playbook, and the telemetry the hybrid Tier-0
detections need.

> **Status.** The detections run in Sentinel (see `lab.tfvars` for the ones
> held back). **RAN · tenant (2026-11-05, capture-log E40, E40a, E41):** both
> playbooks are deployed in `rg-identity-lab` and were run from a drill
> incident: the notify card reached the SOC team's Identity-SecOps channel and
> opened a ServiceNow ticket; the containment card ignored a non-approver,
> did nothing on an approver's Reject, and on the approver's Contain revoked
> sessions, confirmed the user compromised and disabled the account (record:
> `lab/evidence/itdr/20261105T102000Z/`). The automation rules that start
> them on their own are code in `modules/monitoring` and exist once the apply
> has run with `TF_SENTINEL_PLAYBOOK_ID` / `TF_CONTAINMENT_PLAYBOOK_ID` and
> `enable_itdr_containment` (`lab.tfvars`). Lines marked `verify:` still
> depend on behaviour only the tenant can confirm.

| File | What it does |
|---|---|
| `Deploy-Playbook.ps1` | Deploys `lab/monitoring/playbook-notify.json` (Teams card to the SOC channel + ServiceNow ticket on every incident; for the break-glass rule also on every alert that joins an open incident - `modules/monitoring`, `notify_on_alert_added_rule_keys`). |
| `authorize-teams-connection.mjs` | Authorizes a playbook's Teams API connection once, headless, as `svc-soc-automation` (ARM `listConsentLinks` / `confirmConsentCode`, staff sign-in toolkit), and fails unless the connection reads back Connected as that account. |
| `answer-teams-card.mjs` | Drill aid: answers a containment card in Teams on the web as a lab TEST user (the playbook still decides whether that answer counts). |
| `../demo/containment-drill.sh` | Arms the on-camera drill (throwaway user, one incident, the card waiting) and disarms it; see `lab/scripts/demo/README.md`. |
| `Deploy-ContainmentPlaybook.ps1` | Deploys `lab/monitoring/playbook-contain.json` and grants its managed identity exactly the rights it uses. |
| `Invoke-AdContainment.ps1` | The AD half of containment: disables / re-enables an AD account on DC01 through `az vm run-command`, writes an evidence record. |
| `ingest-vault-audit.sh` | Ships Vault check-out / check-in evidence (lab/pam audit log) to the `VaultCheckout_CL` table through the Logs Ingestion API. |
| `tests/` | Offline tests: `Itdr.Tests.ps1` (Pester) and `ingest-vault-audit.test.sh` (stubbed `az`/`curl`, synthetic audit log). |

## Detections

> **Reading the rules back.** The break-glass sign-in rule is a
> near-real-time (NRT) rule since 2026-11-05 (`contoso-break-glass-signin-nrt`).
> The GA `alertRules` API versions do not return NRT rules (Learn REST
> *Alert Rules - List*: no NRT kind in any GA version up to 2025-09-01; live,
> 2024-09-01 lists 17 rules and 2025-01-01-preview 18). Every script that reads
> rules uses `api-version=2025-01-01-preview`: `Invoke-BreakGlassDrill.ps1`,
> `post-apply/Convert-BuildAccountToEligible.ps1`,
> `../demo/containment-drill.sh`. Incidents from NRT rules are listed by the GA
> incidents API as usual.

All eleven live in `lab/kql/` with an SPL twin in `lab/splunk/detections/` and
are deployed by `lab/terraform/modules/monitoring` (`itdr.tf`). Each rule maps
ONE account entity: the identity containment would act on. Targets and victims
are custom details, never entities, so an approval can't disable the person
who was attacked.

| Rule | Source tables | High when | MITRE ATT&CK | Containment subject |
|---|---|---|---|---|
| `app-credential-added` | AuditLogs | credential on a service principal object, or a new federated credential, outside the CI identity | T1098.001 | actor |
| `app-consent-granted` | AuditLogs | tenant-wide grant (admin consent / all users / application permission) of a high-risk scope | T1528, T1098.003 | consenting actor |
| `ca-policy-changed` | AuditLogs | CA policy deleted, disabled, moved to report-only, or exclusions changed; named location deleted, a country removed or a range newly trusted; authentication strength deleted, given a phishable combination, or its combination configuration (AAGUIDs) changed - outside the CI identity | T1556.009, T1562.001 | actor |
| `role-assigned-outside-pim` | AuditLogs | any standing role assignment not written by PIM, or a PERMANENT active assignment made in PIM (time-bound active = Medium), outside the CI identity | T1098.003 | actor |
| `pim-group-member-added-outside-pim` | AuditLogs | a member added directly (or permanently active through PIM) to a role-holding / PIM group - always for Break-Glass-Admins | T1098.003 | actor |
| `auth-method-changed-by-admin` | AuditLogs | an admin changes the MFA / passwordless methods (TAP included) of a privileged account - by object id (break-glass, PIM-group members, role holders), naming as fallback | T1556.006, T1098.005 | admin actor |
| `identity-risk` | AADUserRiskEvents, AADRiskyUsers, SigninLogs | open high risk or confirmed compromised (CA006/CA007 did not close it) | T1078.004 | risky user |
| `tier0-logon-without-checkout` | SecurityEvent (DC01), VaultCheckout_CL | always: a vaulted Tier-0 logon no check-out covers, the RID-500 break-glass Administrator (by SID), or any other account with special privileges (4672) the vault does not manage | T1078.002, T1550.002 | AD account (flagged, not touched) |
| `ad-privileged-group-change` | SecurityEvent (DC01) | a member added to a Tier-0 AD group (by well-known SID / RID) | T1098.007 | AD actor (flagged) |
| `kerberoast-rc4-service-ticket` | SecurityEvent (DC01) | RC4 tickets for 3+ user SPNs from one requester, or for a Tier-0 SPN | T1558.003 | requester (flagged) |
| `dcsync-replication-request` | SecurityEvent (DC01) | always (replication rights used by a non-DC account) | T1003.006 | AD actor (flagged) |

**Second wave (six more, behind `enable_itdr_detections_v2`).** `lab/kql` and
`lab/splunk/detections` also hold `device-code-signin`,
`security-info-registered-risky`, `sod-violation-granted`,
`pim-activation-without-auth-context`, `vault-privileged-access-anomaly` and
`dc-logon-outside-operator-allowlist`. Splunk schedules all of them (its 22
saved searches). `modules/monitoring/itdr_v2.tf` deploys them when
`enable_itdr_detections_v2` is on: two are Sentinel-only (14-day look-backs the
Log Analytics alert path can't run), and the vault anomaly needs the extended
`VaultCheckout_CL` columns (`Ticket`, `Operator`, `ErrorText`, flag
`vault_feed_v2_columns` with `ingest-vault-audit.sh --signals all`). While the
flag is off, run them by hand in Logs as hunting queries, and never present
them as live rules.

Severity is **dynamic**: each query computes a `Severity` column that the
Sentinel rule uses per alert (one alert per result row). Incidents group per
identity **and** per severity, so a High alert never hides inside an older
Medium incident, because containment only triggers on incident creation.

Changes made by the CI apply identity drop to Low/Medium but always alert.
"CI apply identity" means its IMMUTABLE ids (service principal object id +
client id, `envs/bootstrap` output `iac_principal_ids`, rendered into the KQL
by Terraform and into the Splunk lookup `contoso_iac_principals.csv`), never
its display name: anyone who owns an app can rename it
`gh-oidc-entra-apply (write)`. An app that carries the name without the id is
**High** (`IacNameSpoof`). With no ids configured nothing counts as IaC (fail
closed).

## How the Tier-0 detection gets its evidence

```
lab/pam Vault (file audit device)
   └─ ingest-vault-audit.sh  (operator laptop, --follow 60)
        reads new audit lines (byte offset), keeps check-out/check-in,
        resolves HMAC'd account names via sys/audit-hash, + 1 heartbeat row
   └─ Logs Ingestion API  (Entra token from `az login`, no shared key)
   └─ dce-idlab-itdr ─> dcr-idlab-vault-checkout ─> VaultCheckout_CL

vm-dc01 ─ Azure Monitor Agent ─> dcr-idlab-dc01-security ─> SecurityEvent
                                   (4624, 4672 + the AD ITDR event set)

tier0-logon-without-checkout.kql: logon NOT inside
  [check-out - 5m, min(first check-in, check-out + 1h) + 5m]  → High incident
```

* **Fail-safe.** No evidence means an alert. If the feed is down, every Tier-0
  logon alerts, and `VaultFeedHealthy` (from the heartbeat rows) tells the
  analyst which case it is. Logons younger than 15 minutes aren't judged yet,
  which leaves the feed time to deliver.
* **HMAC resolution (documented Vault behaviour; verify: against the harness
  Vault).** The audit device HMACs `service_account_name`, and
  `sys/audit-hash/file` returns the identical HMAC, so the script maps names
  back without the mount being reconfigured. The offline test resolves them
  from a stub (`tests/fixtures/hash-map.json`); no test runs it against a real
  Vault yet.
  The cleaner production setting is `vault secrets tune
  -audit-non-hmac-response-keys=service_account_name
  -audit-non-hmac-response-keys=check_ins ldap/`, after which names arrive in
  clear and the script uses them as they are.
* **Why not the HTTP Data Collector API:** Microsoft retired it in September
  2026 (verify: retirement notice). The Logs Ingestion API authenticates with
  Entra, so there's no workspace key to leak.
* **Stand-in.** This replaces the agent-based path production would use
  (CyberArk Vault / PTA syslog → AMA (CEF) → Sentinel). The STAND-INS row
  exists (`lab/docs/STAND-INS.md`); only the spoken line in the verbatim
  script is pending.

## Containment playbook (Teams approval)

`High` incident from an ITDR rule → automation rule (order 2, after notify) →
`pb-identity-contain`, for each account entity, one at a time:

1. **No Entra object id** (AD-only account, such as the Tier-0 rule's): no
   action. The playbook comments "AD disable required" with the exact
   `Invoke-AdContainment.ps1` command. AD is the authority there.
2. **Protected account** (a Break-Glass-Admins member's OBJECT ID, baked in
   at deploy): refused. Automation never locks out break-glass. The
   `bg-admin-` UPN prefix is only a warning on the card: whoever can rename
   users could otherwise make a compromised account uncontainable.
   `Deploy-ContainmentPlaybook.ps1 -VerifyProtectedList` reports drift when
   the group changes.
3. **Restricted-management AU member** (the account's
   `memberOf/microsoft.graph.administrativeUnit` with
   `isMemberManagementRestricted = true`): no approval card. Graph
   application permissions don't apply to RMAU members, so the playbook
   comments *ESCALATED, NOT CONTAINED* and the RMAU-scoped responder (a
   person holding a role scoped to that AU, such as the VIP-support PIM
   group) revokes and disables by hand. If that read fails, the playbook
   records it and continues to the approval.
4. **Teams adaptive card** to the Identity-SecOps channel of the SOC team
   (Teams connector, *Post adaptive card and wait for a response* as the Flow
   bot): *Contain*, *Revoke sessions only*, *Reject*. No answer in 4 h means
   no action. The answer
   counts only if Teams returns the responder's object id and UPN, the id is
   a member of the containment approver group (`approverObjectIds`, from
   `-ApproverGroupName ITDR-Containment-Approvers`), and the responder is not
   the subject (four-eyes). Anything else is ignored and logged - an empty
   approver list ignores every answer (fail closed).
5. **Contain:** `revokeSignInSessions`, then Identity Protection
   `confirmCompromised` (user risk High, so CA006 applies at the next sign-in
   and the verdict trains ID Protection), then `accountEnabled=false` for
   cloud-only users. For synced users the playbook only flags the AD disable,
   because Entra rejects the write and the next sync would undo it.
6. Every outcome, with the approver's UPN and object id and the HTTP status codes, goes to
   a Sentinel incident comment and a ServiceNow **work note on the same
   ticket** notify opened (matched by `correlation_id` = incident name). If
   that ticket isn't found, a new one is opened.

The playbook never deletes credentials, removes consents or edits role
assignments. Those are owner decisions with production blast radius, so they
stay runbook steps.

### Least privilege

| Identity | Permission | Why |
|---|---|---|
| Playbook managed identity | Graph `User.Read.All` | read UPN and sync state before acting |
| | Graph `AdministrativeUnit.Read.All` | read the account's restricted-management AUs, to escalate RMAU members instead of asking for an approval it cannot act on (verify: least privilege for this read) |
| | Graph `User.RevokeSessions.All` | revoke refresh tokens / session cookies |
| | Graph `User.EnableDisableAccount.All` | `accountEnabled=false` |
| | Graph `IdentityRiskyUser.ReadWrite.All` | `confirmCompromised` on Contain (Entra ID P2; 403 without it, logged) |
| | *Opt-in* `-GrantDisableRole`: Authentication Administrator (tenant or AU-scoped) - **not needed, keep it off** | The design assumed Graph's sensitive-action rule makes an app-only disable need a directory role. RAN · tenant 2026-11-05 (E41): without any directory role, `accountEnabled=false` on a non-admin cloud-only user answered 204. The role would add only reach (method resets and Temporary Access Passes for every non-admin user, R16). Admins stay out of scope: containing an admin needs Privileged Authentication Administrator, which would make this Logic App Tier 0 (not tried live, by design). Granting the role would trip `role-assigned-outside-pim` once (expected). |
| | Microsoft Sentinel Responder (workspace) | incident comments, entity extraction |
| Azure Security Insights app | Microsoft Sentinel Automation Contributor (RG) | lets automation rules run playbooks |
| Operator running `ingest-vault-audit.sh` | Monitoring Metrics Publisher on `dcr-idlab-vault-checkout` | Logs Ingestion API. The CI apply identity can't grant it (it isn't on its ABAC-delegable list), so this is a human step |
| Operator running `Invoke-AdContainment.ps1` | Virtual Machine Contributor on vm-dc01 (run-command) | AD writes happen on the DC as SYSTEM; no domain credential on the laptop |

Secrets: the ServiceNow password comes from Key Vault at deploy time as an ARM
`securestring` (0600 temp parameter file, deleted), and ServiceNow calls have
`secureData` on in run history. The Teams connector is OAuth and holds no
secret in the template. Both playbooks' Teams connections are authorized once,
as the cloud-only SOC automation account `svc-soc-automation` (it owns the
SOC team; E5 with only the Teams service plan on; password and authenticator
seed in the operator's Keychain), never as a person, with
`node lab/scripts/monitoring/authorize-teams-connection.mjs teams-pb-identity-contain`
(and `teams-pb-identity-notify`). A re-deploy keeps the authorization (checked
2026-11-05: Connected as the same account after a redeploy). The notify card
used to go through a Teams Workflows webhook URL: that URL was a bearer
credential (anyone holding it could post into the SOC channel) and needed a
flow owned by a person, so the notify playbook now uses the same connector.
What the connection adds to R16: whoever can edit either Logic App can act in
Teams as `svc-soc-automation` (post, read the SOC channel, manage the team it
owns). That is no new reach - the same editors can already change the
workflow itself (R16, `rg-identity-lab` is Tier 0) - and adding someone to the
team never makes them an approver: approvers are object ids baked in at deploy
from `ITDR-Containment-Approvers`.

### The SOC team (one-time, as the lab operator, 2026-11-05)

Graph, app-only (operator rights `Team.Create`, `TeamMember.ReadWrite.All`,
`User.ReadWrite.All`, `GroupMember.ReadWrite.All`):

1. `POST /users` `svc-soc-automation@ContosoHealthLab.onmicrosoft.com`,
   cloud-only, password generated into the Keychain (`contoso-lab-svc-soc-automation`),
   then `assignLicense` E5 with every service plan disabled except `TEAMS1`
   (a Teams connector call acts as a Teams user). Its authenticator app:
   `node lab/scripts/demo/signin/enroll.mjs svc-soc-automation@ContosoHealthLab.onmicrosoft.com`.
2. `POST /teams` (template `standard`, owner = that account: an app-only
   team needs a user owner) named **Contoso SOC**, with the channel
   **Identity-SecOps** in the same body.
3. Members: the containment approvers that are lab test users
   (`test-user-a`, also added to `ITDR-Containment-Approvers`) and one channel
   member who is not an approver (`test-user-b`), for the "ignored" drill.
   The owner's own account is in `ITDR-Containment-Approvers` but is NOT
   added to the team by automation: whoever presents adds themselves.
4. Deploy both playbooks with `-TeamsGroupId <team id> -TeamsChannelId '<channel id>'`,
   then authorize both Teams connections (above).

## Staging order (flags live in `lab/terraform/envs/dev`)

1. `enable_itdr_detections = true`. This creates only telemetry: the
   `VaultCheckout_CL` table, the DCE and DCR, and, with `enable_dc`, AMA plus
   the Security-event DCR on DC01. **No trial starts.** Set
   `iac_principal_ids` (TF_IAC_PRINCIPAL_IDS) from the bootstrap output, or
   every CI change alerts as non-IaC.
2. Bootstrap (human): add `RiskyUsers` and `UserRiskEvents` (and, for
   workload-identity risk, `RiskyServicePrincipals` and
   `ServicePrincipalRiskEvents`) to the Entra diagnostic setting. Grant
   yourself Monitoring Metrics Publisher on the DCR, then run
   `./ingest-vault-audit.sh --follow 60`.
3. Wait until the AuditLogs-based tables and `VaultCheckout_CL` have data.
   Hold back any empty one with `itdr_exclude_rules` (Sentinel rejects rules
   over never-populated tables). verify: per Microsoft Learn, DC01 Security
   events reach `SecurityEvent` only once Sentinel and its "Windows Security
   Events via AMA" connector are on (they land in `Event` before that), so
   do NOT wait for SecurityEvent here: keep `tier0_logon_without_checkout`,
   `ad_privileged_group_change`, `kerberoast_rc4_service_ticket` and
   `dcsync_replication_request` (and `identity_risk` until risk events exist)
   in `itdr_exclude_rules`.
4. `enable_sentinel = true` (**starts the 31-day Sentinel trial**). The core
   rules plus every ITDR rule whose table has data deploy. Enable the
   connector, wait for DC01 rows in SecurityEvent, then remove those
   exclusions in a second PR.
5. `./Deploy-ContainmentPlaybook.ps1 …`, then authorize the Teams connection
   (`authorize-teams-connection.mjs`). Done 2026-11-05.
6. `containment_playbook_id = "<printed id>"` (repo variable
   `TF_CONTAINMENT_PLAYBOOK_ID`) and `enable_itdr_containment = true`
   (`lab.tfvars`, on since 2026-11-05).

Inputs and lookups the second-wave rules (`enable_itdr_detections_v2`) need:

- **`operator_ips` is Terraform-owned** (`modules/monitoring/itdr_v2.tf`,
  built from `operator_ip_ranges` with `ExpiresOn` =
  `operator_ips_expires_on`). Change the variable, never the watchlist by
  hand: the next apply would put it back.
- **`sod_holdings`** (read by `sod-violation-granted` for access granted
  before its 14-day AuditLogs window) is written by
  `09-SoD-Report.ps1 -HoldingsSnapshotPath <gitignored path>`. Uploading it
  as the Sentinel watchlist, and copying it to the Splunk lookup
  `contoso_sod_holdings.csv`, are tenant-time steps by hand.
- **`azure_pim_group_ids`** (PIM-Azure-RG-Contributors, passed by
  `envs/dev`): a direct member add to that group is its intended path, so
  `pim-group-member-added-outside-pim` reports it as Medium
  (`AzurePimEligibleMember`), not High.

After the Sentinel trial, the same eleven queries run as Log Analytics alerts
(`enable_la_alerts`). That path has no containment, because automation rules
are a Sentinel feature, and the SecurityEvent rules need an Event-table
variant there (verify above).

## Offline validation (re-runnable)

```bash
# Terraform module: fmt, validate, 32 mocked runs (flags off = nothing created,
# columns mapped by Sentinel exist in each .kql, containment gating, DC01 + LA
# paths, immutable-id rendering, the opt-in alert-added trigger, the
# operator_ips watchlist)
cd lab/terraform/modules/monitoring && terraform init -backend=false && terraform validate && terraform test

# Playbooks, detections, IaC-by-id, mocked audit rows, Splunk conf sync, PSScriptAnalyzer
pwsh -c 'Invoke-Pester ./lab/scripts/monitoring/tests/Itdr.Tests.ps1 -Output Detailed'

# Vault feed transform, offsets, 403 handling (stubbed az/curl; also under macOS bash 3.2)
lab/scripts/monitoring/tests/ingest-vault-audit.test.sh

# Splunk twins rendered into the app
lab/splunk/render-savedsearches.sh --check
```

KQL is checked structurally (brackets, `let` terminators, Severity column,
entity columns). On top of
that, `tests/fixtures/itdr-cases.json` holds mocked audit rows: each case's
operation string must be one the rule and its SPL twin match, the regexes
that classify a row (hyphenated permissions, removed countries, newly trusted
ranges, phishable auth-strength combinations) are pulled out of the KQL and
run on sample text, and `tests/KqlLite.ps1` (a small, deliberately partial
KQL interpreter) runs each rule's own row-level pipeline over those rows.
The Kusto-emulator harness (`lab/monitoring/kusto-harness/`) ran all 22
rules on a real KQL engine on 2026-10-21 (RAN · harness): the Azure Data
Explorer Kusto emulator in a local container, synthetic tables and events,
Sentinel's `_GetWatchlist` shimmed. 22/22 rules and 223/223 cases passed,
and it imported 94 of these fixture rows as engine cases (12 stage-level or
derived-`let` rows were skipped; see its README). Record:
`lab/evidence/kusto/20261021T001217Z/`. The emulator is not a Log Analytics
workspace and not a tenant: scheduling, entity mapping and real log shapes
get checked in the tenant (the steps below).

## Tenant-time steps and evidence to capture

| # | Step | Evidence |
|---|---|---|
| 1 | Run each KQL once in Log Analytics before enabling the rule. Copy real `OperationName` / `ResultReason` / modifiedProperty strings into the queries if Microsoft's differ | query results screenshots |
| 2 | Generate one event per rule: add an app secret, consent to a test app, set a CA policy to report-only, assign a role outside PIM, issue a TAP to a test user, confirm a test user compromised in ID Protection, log on to DC01 as tier0-admin-01 **without** a check-out | one Sentinel incident per rule, with severity |
| 3 | Log on with a proper `psm-session.sh checkout` and confirm **no** tier0 alert | the absence, plus the `VaultCheckout_CL` rows |
| 4 | Stop the ingest script for 30 min and log on: the alert says `VaultFeedHealthy = false` | incident custom details |
| 5 | Containment drill on a cloud-only test user: Contain → card → 204/204 → comment + ServiceNow work note. **RAN · tenant 2026-11-05 (E41)** on a throwaway user: revoke 200, confirmCompromised 204, disable 204; a Reject before it changed nothing | `lab/evidence/itdr/20261105T102000Z/` (run records, incident comments, Entra audit rows, ServiceNow work notes, card screenshots) |
| 6 | Same on a synced user: revoke 204 + "AD disable required", then `Invoke-AdContainment.ps1` | evidence JSON in `lab/evidence/out/itdr/` |
| 7 | Break-glass refusal, self-approval refusal, and an answer from a channel member who is NOT an approver (ignored). **The non-approver case RAN · tenant 2026-11-05 (E41)**; the break-glass and self-approval cases have not run | incident comments |
| 8 | Contain on a test user: `confirmCompromised` 204, user risk High in ID Protection, CA006 prompt at next sign-in | risky-user blade, sign-in log |

## verify: (only the tenant can confirm)

- Sentinel accepts `techniques` with parent IDs only, and the tactic sets
  chosen for each rule.
- FederatedIdentityCredentials, consent and grant modifiedProperty names. The
  `ResultReason` wording for TAP and FIDO2. CA policy JSON keys
  (`state`, `excludeUsers`, `excludeGroups`) in AuditLogs.
- That `Microsoft-SecurityEvent` via AMA needs Sentinel + its connector on
  the workspace (Microsoft Learn says so). Then the post-trial LA path loses
  DC01 events and the four SecurityEvent rules must read the `Event` table.
- The AMA extension's current `type_handler_version` (1.0 pinned, minor
  auto-upgrade).
- ~~Whether app-only `accountEnabled=false` needs the directory role for
  non-admin users~~ - answered 2026-11-05 (E41): it does not (204 with the
  app roles only); `revokeSignInSessions` needed none either (200). Still
  open: Graph's answer for an ADMIN target (never tried, by design).
- Which containment calls a restricted-management AU blocks for an app-only
  caller, and the AD-disable path (`Invoke-AdContainment.ps1`, then Cloud
  Sync) for a synced VIP.
- ~~The Teams *Post adaptive card and wait for a response* action shape~~ -
  answered 2026-11-05 (E41): the response carries `responder.objectId`,
  `responder.userPrincipalName` and `data.decision`; Logic Apps refuses a
  `method` on that webhook action's inputs.
- The `PropertyArrayChanged` (Alerts / Added) automation-rule condition used
  by `containment_on_alert_added`.
- DC01 audit policy logs Logon and Special Logon success (`auditpol /get
  /subcategory:"Logon","Special Logon"`).
- Log Analytics alert window PT3H with frequency PT5M for the Tier-0 rule on
  the post-trial path.
