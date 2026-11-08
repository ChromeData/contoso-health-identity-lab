# KQL detections

24 identity detections for Contoso Health, one `.kql` file each. These files
are the single source: `lab/terraform/modules/monitoring` deploys them as
Microsoft Sentinel scheduled rules (during the Sentinel trial) or as Log
Analytics scheduled query alerts (after it), and each one has an SPL twin in
[`../splunk/detections/`](../splunk/detections/) with the same window,
threshold and output columns.

**Scope.** Splunk is the optional second SIEM. Its SPL column was frozen at
22; the two rules ported on 2026-11-06 got twins anyway, on request, so every
rule here still has one. Entra Agent ID is
optional scope ([ADR 0018](../docs/adr/0018-nhi-ownership-and-agent-identity-sponsorship.md)):
no rule here watches agent identities.

**Status: BUILT, and RAN · harness on a local KQL engine.** The 22 rules of
that day ran on the Azure Data Explorer Kusto emulator on 2026-10-21 (below).
The two added on 2026-11-06 (third set, below) have not run on the emulator:
their cases ran on the Log Analytics query engine instead (RAN · harness,
on the workspace's engine, E114). In the tenant, the Sentinel analytics
rules list read on 2026-11-06 showed 16 of the first 22 as enabled
scheduled rules (plus Microsoft's Fusion rule); the five in
`itdr_exclude_rules`, the break-glass rule (being moved to a near-real-time
rule, `main.tf`) and the two third-set rules were not in it. (This paragraph
said until 2026-11-06 that no workspace existed; that was out of date.) What
has run offline (on
2026-10-20, unless marked otherwise):

- `modules/monitoring`'s mocked `terraform test` (32 runs) checks that every
  rule the module deploys exists here, that entity mappings and custom
  details name columns the query really returns, and that the identity ids
  rules judge by are rendered in as immutable ids, never display names.
- The ITDR Pester suite (`lab/scripts/monitoring/tests/Itdr.Tests.ps1`, 284
  passed, 0 skipped, 2026-10-20 21:28 UTC) checks the eleven ITDR rules
  structurally:
  an SPL twin exists, a MITRE section, balanced brackets, terminated `let`
  statements, no "IaC" decided by display name, and the classifying regexes
  give the expected answer on mocked audit rows. KqlLite (its small offline
  interpreter) also runs each rule's row-level pipeline on those rows. KQL
  semantics need a real engine or a tenant.
- **RAN · harness, 2026-10-21:** the Kusto-emulator harness
  ([`../monitoring/kusto-harness/`](../monitoring/kusto-harness/README.md))
  ran all 22 rules, rendered as `modules/monitoring` deploys them, on the
  Azure Data Explorer Kusto emulator: a local container, with tables typed
  from Learn's column lists, synthetic positive and negative events, and
  Sentinel's `_GetWatchlist` shimmed. Result PASS: 22/22 rules, cases PASS
  223, FAIL 0, ERROR 0, XFAIL 0, XPASS 0. Record:
  [`../evidence/kusto/20261021T001217Z/`](../evidence/kusto/20261021T001217Z/)
  (hashed; `shasum -a 256 -c SHA256SUMS` inside it). This is a real KQL
  engine but **not a Log Analytics workspace, not Sentinel and not a
  tenant**: no rule was scheduled, no incident raised, no real log read.
  Writing its fixtures found three rule bugs, fixed here and in the SPL
  twins, and their cases passed on the engine: `sod-violation-granted`
  missed PIM-for-Groups eligibility (Learn's activity string says "role",
  not "group") and
  removals that name the group only in `oldValue`; `app-credential-added`
  dropped every new federated identity credential (`to typeof(string)` is a
  cast, so objects became null; it now uses `tostring()`).
- `lab/pam/test/e2e-vault-anomaly.sh` (RAN · harness, 63 passed, 1 skipped)
  turns **real** Vault audit events into `VaultCheckout_CL` rows and checks
  the six signal predicates of `vault-privileged-access-anomaly.kql`,
  re-stated in `jq`. The KQL itself does not run there.
- `09-SoD-Report.Tests.ps1` checks that the SoD tripwire in
  `sod-violation-granted.kql` and its SPL twin mirror `lab/iga/sod-rules.json`.

Which tenant captures prove each rule fires, and on which day:
[`../docs/evidence-capture-plan.md`](../docs/evidence-capture-plan.md).

## Inventory

**Severity** is the rule's default in Sentinel. "Per row" means the query
returns a `Severity` column and Sentinel takes the alert's severity from it
(the condition for High is given). **Deployed by** is the `envs/dev` flag that
makes `modules/monitoring` create the rule; every flag is `false` in the
committed `lab.tfvars`, so nothing is deployed until a PR flips it.
**Containment**: whether a High incident from this rule can start the
approval-gated containment playbook (`enable_itdr_containment`).

### Core (5)

| Detection | Catches | Severity | Tables | Runs every / looks back | SPL twin | Deployed by | Containment |
|---|---|---|---|---|---|---|---|
| `pim-activation.kql` | A PIM for Groups / PIM for roles activation completed (T1078); expected for approved changes, every one reviewed | Medium | AuditLogs | 5 min / 1 h | `pim-activation.spl` | `enable_sentinel` or `enable_la_alerts` | no |
| `break-glass-signin.kql` | Any sign-in attempt by an emergency-access account (T1078), matched by the accounts' immutable object ids (a rename does not blind it) or the bg-admin-NN name; one incident per account per day | High | SigninLogs, AADNonInteractiveUserSignInLogs | 5 min / 1 h | `break-glass-signin.spl` | `enable_sentinel` or `enable_la_alerts` | no |
| `blocked-country-signin.kql` | Sign-in from a blocked or watched country; flags a success from a block-list country (a CA gap) (T1078) | Medium | SigninLogs | 5 min / 1 h | `blocked-country-signin.spl` | `enable_sentinel` or `enable_la_alerts` | no |
| `failed-signin-spike.kql` | 10+ failed sign-ins from one IP in one 10-minute bin: spray or brute force (T1110) | Medium | SigninLogs (interactive only; the rule header shows the AADNonInteractiveUserSignInLogs union to add) | 5 min / 1 h | `failed-signin-spike.spl` | `enable_sentinel` or `enable_la_alerts` | no |
| `legacy-auth.kql` | Sign-ins over legacy protocols that cannot do MFA; `StillSucceeding` means CA003 is not holding (T1078) | Low | SigninLogs, AADNonInteractiveUserSignInLogs | 1 h / 1 day | `legacy-auth.spl` | `enable_sentinel` or `enable_la_alerts` | no |

### ITDR (11)

| Detection | Catches | Severity | Tables | Runs every / looks back | SPL twin | Deployed by | Containment |
|---|---|---|---|---|---|---|---|
| `app-credential-added.kql` | New secret, certificate or federated credential on a workload identity (T1098.001) | Medium; per row High on a service principal object or a new federated credential outside the CI apply identity | AuditLogs | 5 min / 1 h | `app-credential-added.spl` | `enable_itdr_detections` | yes |
| `app-consent-granted.kql` | Delegated consent, grant or application permission given to an app (T1528, T1098.003) | Medium; per row High when tenant-wide and high-risk | AuditLogs | 5 min / 1 h | `app-consent-granted.spl` | `enable_itdr_detections` | yes |
| `ca-policy-changed.kql` | CA policy, named location or authentication strength changed outside IaC (T1556.009, T1562.001) | Medium; per row High when the change weakens a control | AuditLogs | 5 min / 1 h | `ca-policy-changed.spl` | `enable_itdr_detections` | yes |
| `role-assigned-outside-pim.kql` | Standing directory role assignment not written by PIM, or an active PIM assignment (T1098.003) | High unless the CI apply identity (by immutable id) made it | AuditLogs | 5 min / 1 h | `role-assigned-outside-pim.spl` | `enable_itdr_detections` | yes |
| `pim-group-member-added-outside-pim.kql` | Direct or permanent membership on a role-holding or PIM-governed group (T1098.003); Break-Glass-Admins always High | High | AuditLogs | 5 min / 1 h | `pim-group-member-added-outside-pim.spl` | `enable_itdr_detections` | yes |
| `auth-method-changed-by-admin.kql` | An admin registered, updated or deleted another user's MFA method, TAP included (T1556.006, T1098.005) | Medium; per row High for every privileged target | AuditLogs | 5 min / 2 days | `auth-method-changed-by-admin.spl` | `enable_itdr_detections` | yes |
| `identity-risk.kql` | Open medium/high ID Protection risk not closed by CA006/CA007 or an admin (T1078.004) | High (per row) | AADUserRiskEvents, AADRiskyUsers, SigninLogs | 5 min / 1 h | `identity-risk.spl` | `enable_itdr_detections` (+ bootstrap `enable_identity_protection_logs`, P2) | yes |
| `tier0-logon-without-checkout.kql` | Tier-0 logon on DC01 that PAM does not account for: no Vault check-out, the RID-500 Administrator, or an unmanaged account with special privileges (T1078.002, T1550) | High (per row) | SecurityEvent, VaultCheckout_CL | 5 min / 3 h | `tier0-logon-without-checkout.spl` | `enable_itdr_detections` | yes |
| `ad-privileged-group-change.kql` | Member added to a Tier-0 AD group (4728/4732/4756; Tier1-Server-Admins = Medium) (T1098.007) | High (per row) | SecurityEvent | 5 min / 1 h | `ad-privileged-group-change.spl` | `enable_itdr_detections` | yes |
| `kerberoast-rc4-service-ticket.kql` | RC4 service tickets for user-account SPNs (4769) (T1558.003) | Medium; per row High for 3+ services per requester or a Tier-0 SPN account | SecurityEvent | 5 min / 1 h | `kerberoast-rc4-service-ticket.spl` | `enable_itdr_detections` | yes |
| `dcsync-replication-request.kql` | Directory replication rights used by a non-DC account (4662) (T1003.006) | High (per row) | SecurityEvent | 5 min / 1 h | `dcsync-replication-request.spl` | `enable_itdr_detections` | yes |

### ITDR, second wave (6)

| Detection | Catches | Severity | Tables | Runs every / looks back | SPL twin | Deployed by | Containment |
|---|---|---|---|---|---|---|---|
| `device-code-signin.kql` | Sign-in with the device code flow, or a token from such a session: device-code phishing (T1528, T1566.002, T1078.004); the detective twin of CA010 | Medium; per row High for a privileged user or a medium/high-risk sign-in, Low when blocked | SigninLogs, AADNonInteractiveUserSignInLogs | 5 min / 1 h | `device-code-signin.spl` | `enable_itdr_detections_v2` | yes |
| `security-info-registered-risky.kql` | A user registered their own MFA method from a risky sign-in, a new country or an unmanaged device (T1098.005, T1556.006) | Medium; per row High for every privileged registration | AuditLogs, sign-in logs | 1 h / 14 days | `security-info-registered-risky.spl` | `enable_itdr_detections_v2` (**Sentinel only**: Log Analytics alerts look back 2 days at most) | yes |
| `dc-logon-outside-operator-allowlist.kql` | RDP on DC01, or a network logon from a public IP, not from an unexpired `operator_ips` entry ([ADR 0013](../docs/adr/0013-tier0-domain-controller-exposure.md)) (T1133, T1021.001) | High; per row Medium for failures only | SecurityEvent, `operator_ips` watchlist | 5 min / 1 h | `dc-logon-outside-operator-allowlist.spl` (enabled; an empty `contoso_operator_ips.csv` lookup = every source alerts) | `enable_itdr_detections_v2` (the watchlist with `enable_dc`) | yes |
| `vault-privileged-access-anomaly.kql` | PAM vault misuse: Tier-0 read outside a ticketed check-out, check-out without a ticket, rotation failure, root-token use, failed-login burst, Tier-0 access denied (T1555, T1078, T1110, T1562) | Medium (per row) | VaultCheckout_CL | 5 min / 6 h | `vault-privileged-access-anomaly.spl` | `enable_itdr_detections_v2` + `vault_feed_v2_columns` | **never** (the account is a Vault identity, not an AD one) |
| `sod-violation-granted.kql` | A grant that completes a pair in `lab/iga/sod-rules.json` (SOD-01 to SOD-09) (T1098) | Medium; per row the rule's own risk, Low under an approved exception | AuditLogs, `sod_holdings` watchlist (from `09-SoD-Report.ps1 -HoldingsSnapshotPath`; the upload is tenant-time) | 1 h / 14 days | `sod-violation-granted.spl` (enabled; an empty `contoso_sod_holdings.csv` = grants inside the 14-day window only) | `enable_itdr_detections_v2` (**Sentinel only**) | **never** (disabling a clinician over an SoD conflict is a patient-safety event, [ADR 0012](../docs/adr/0012-access-review-no-response-and-clinical-lockout.md)) |
| `pim-activation-without-auth-context.kql` | A Tier-0 PIM activation that PIM let through on plain MFA because authentication context `c1` was not satisfied or CA021 was not enforced (T1078.004, T1556.009). Preview: activation strings still `verify:` | High (per row) | AuditLogs, sign-in logs | 1 h / 1 day | `pim-activation-without-auth-context.spl` | `enable_itdr_detections_v2` (keep in `itdr_exclude_rules` until verified) | yes |

### ITDR, third set (2): ported 2026-11-06, not deployed

Rewritten from the owner's older Sentinel-Privileged-Access repo. Fixed on
the way: the old dormant rule asked for a 90-day look-back (Sentinel allows
14 days, Learn "Create scheduled analytics rules"), compared the string
`ResultType` with a number, and judged privilege by a UPN watchlist; the old
Key Vault rule spelled its tactic `Credentialaccess` (Sentinel's name is
`CredentialAccess`), keyed callers on UPN only (the lab's Key Vault callers
are mostly managed identities, which have none) and counted HTTP 404s as
reads.

| Detection | Catches | Severity | Tables | Runs every / looks back | SPL twin | Deployed by | Containment |
|---|---|---|---|---|---|---|---|
| `dormant-privileged-account-reactivation.kql` | An admin account (adm-* or tier0-admin-NN naming, or a `PrivilegedUserIds` object id) with no successful sign-in, interactive or not, in the 14-day look-back signs in interactively (T1078.004). bg-admin-NN is left to `break-glass-signin` | High; per row Medium when the account was created inside the look-back | SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs | 1 h / 14 days | `dormant-privileged-account-reactivation.spl` | `enable_itdr_detections_v3` (**Sentinel only**; off in `lab.tfvars`) | yes |
| `keyvault-bulk-secret-read.kql` | One Key Vault caller, keyed on object id, then app id, then UPN: successful reads above max(20, 5x its own 14-day hourly mean), or 20+ refused reads (T1555.006, T1552.001) | Medium; per row High across 5+ distinct secrets | AzureDiagnostics (Key Vault AuditEvent) | 1 h / 14 days | `keyvault-bulk-secret-read.spl` (no data in Splunk: no feed sends AzureDiagnostics) | `enable_itdr_detections_v3` (**Sentinel only**; off in `lab.tfvars`) | **never** (the caller is usually a managed identity; the playbook acts on Entra users) |

What has run for these two (2026-11-06): both queries, unchanged, read-only
on loga-idlab (they compile against the real tables and returned no rows);
their 25 harness cases on the Log Analytics query engine, PASS 25/25
([`../evidence/kusto/20261106T074249Z-workspace/`](../evidence/kusto/20261106T074249Z-workspace/),
E114); `modules/monitoring`'s mocked `terraform test` (`itdr_v3.tftest.hcl`);
both SPL twins as one-off searches on the local Splunk (they parse; the
dormant twin gave the same five accounts and counts as the KQL on the same
shortened window with the dormancy filter removed). Not run: the Kusto
emulator, a Sentinel rule, an incident.

## Before a rule can be deployed

Sentinel validates a rule's query when it creates it, and a rule over a table
that has never received data is rejected (and fails the whole apply). So:

- Turn on `enable_itdr_detections` before `enable_sentinel`: it creates the
  telemetry (`VaultCheckout_CL`, its DCR, AMA on DC01) without starting the
  trial.
- Keep any rule whose table is still empty in `itdr_exclude_rules`. The
  usual candidates: `identity_risk` (needs P2 and the bootstrap risk log
  categories), the four DC01 `SecurityEvent` rules (need the Sentinel
  "Windows Security Events via AMA" connector; verify), `vault_privileged_access_anomaly`
  and `pim_activation_without_auth_context`.
- Turn `vault_feed_v2_columns` on in the same PR that runs
  `lab/scripts/monitoring/ingest-vault-audit.sh --signals all`; otherwise
  every Tier-0 check-out without a ticket column alerts.

The identity lists rules judge by (the CI apply identity, privileged groups,
privileged users) are Terraform variables rendered into the query as object
ids. Empty lists fail closed: nothing counts as the CI identity, and the
detections fall back to naming, which can only raise severity. Splunk reads
the same ids from lookups (`../splunk/README.md`).

## Related

- Response playbooks: [`../monitoring/`](../monitoring/) (notify;
  approval-gated containment, [ADR 0017](../docs/adr/0017-approval-gated-identity-containment.md)).
- Operations and the vault feed: [`../scripts/monitoring/README.md`](../scripts/monitoring/README.md).
- The attacks each rule answers: [`../docs/threat-model.md`](../docs/threat-model.md).
