# ADR 0023: Defender for Identity as the native AD-attack detection layer

- **Status:** Accepted. Code BUILT (validated offline), staged behind `enable_defender_for_identity = false`. Not applied: it needs a Defender licence (free 90-day trial) and a sensor on DC01, neither of which Terraform can create.
- **Date:** 2026-10-31 (amended 2026-11-05: the Splunk twins run on live tenant events, see the amendment below)
- **Decision owner:** Detection lead (in the lab, the repository maintainer)
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The lab detects identity attacks in three places today. Entra ID Protection
scores cloud identity risk and feeds `AADUserRiskEvents` / `AADRiskyUsers`
(`enable_identity_protection_ca`, `identity-risk.kql`). Sentinel runs 22
hand-written KQL rules over the Entra logs and the DC01 Security log. Four of
those rules watch the native on-prem AD-attack plane, read from DC01
`SecurityEvent` through the Azure Monitor Agent:

- `lab/kql/kerberoast-rc4-service-ticket.kql` (4769 RC4 service tickets)
- `lab/kql/dcsync-replication-request.kql` (4662 replication rights)
- `lab/kql/ad-privileged-group-change.kql` (4728/4732/4756 group adds)
- the recon / lateral-movement half of
  `lab/kql/tier0-logon-without-checkout.kql` and
  `lab/kql/dc-logon-outside-operator-allowlist.kql`

Microsoft Defender for Identity (MDI) is purpose-built for exactly this plane.
Its sensor runs on the domain controller, reads the same events plus network
traffic and the directory, and ships detections for Kerberoasting, DCSync,
lateral movement and reconnaissance that Microsoft writes and maintains. Hospital
IAM job postings name it directly.

The question is not "MDI or the KQL rules". It is which one is the *primary*
detector for the native AD signatures, and what the KQL rules are *for* once
MDI is in the design.

## Options considered

1. **Hand-written KQL only (the state before this ADR).** The lab keeps its
   four SecurityEvent rules as the primary AD-attack detector. Rejected: it
   reimplements signatures Microsoft already writes and tunes, on a thinner
   signal (the Security log alone, no network sensor, no directory context),
   and the lab carries the maintenance.
2. **MDI only; drop the four KQL rules.** Rejected: it loses the portable
   twins (the Splunk SPL twin and the offline Kusto-emulator tests), which is
   how the lab proves the detection logic without a tenant or a licence; it
   loses the two correlations MDI cannot make (below); and it ties on-prem
   detection to a licence the lab does not keep past the 90-day trial.
3. **MDI primary for the native signatures; the KQL rules kept as twins and
   as the two genuinely custom correlations (chosen).**

## Decision

**Option 3.**

- **MDI is the primary detector for the native AD-attack signatures** —
  Kerberoasting, DCSync, lateral movement and reconnaissance — because it is
  purpose-built for them and Microsoft maintains the signatures.
- **The four SecurityEvent KQL rules are kept as the portable, offline-testable
  twins** of those signatures. Each has an SPL twin (second SIEM, migration
  state) and runs on the Azure Data Explorer Kusto emulator with synthetic
  events, so the detection logic is provable with no tenant and no licence.
  Their headers now say MDI is the primary detector and the rule is the twin.
- **Two rules stay genuinely custom**, because they correlate against signals
  MDI cannot see:
  - `tier0-logon-without-checkout.kql` joins each Tier-0 DC logon to the PAM
    Vault check-out feed (`VaultCheckout_CL`). MDI does not know whether a
    logon sat inside an approved check-out window.
  - `dc-logon-outside-operator-allowlist.kql` judges each DC logon against the
    `operator_ips` watchlist (ADR 0013). MDI does not hold the lab's operator
    allowlist.
  These are the lab's own detections, not twins.
  **Update 2026-11-08 (round 2, R24 / round 1 D7):** the Vault stand-in and
  its `VaultCheckout_CL` feed were retired by ADR 0036, so
  `tier0-logon-without-checkout.kql` has no source in the lab any more. Only
  `dc-logon-outside-operator-allowlist.kql` remains a live custom
  correlation. Read "two" in this ADR as "two when written; one today".
- **The codifiable piece is wired in Terraform; the rest is a runbook.** MDI
  alerts reach the same Log Analytics workspace the KQL rules use through the
  Microsoft Defender XDR data connector
  (`azurerm_sentinel_data_connector_microsoft_threat_protection`,
  `lab/terraform/modules/monitoring/mdi.tf`), landing in `SecurityAlert`. The
  sensor install, the MDI workspace, the directory service account and the
  licence are portal / human steps
  (`lab/docs/runbooks/deploy-defender-for-identity-dc01.md`).

**The trade-off.** MDI needs a sensor installed on DC01 and a Defender licence.
The lab has only the free 90-day trial, and the sensor cannot be installed by
`azurerm` / `azuread`. So the layer is **staged, not applied**:
`enable_defender_for_identity` defaults to `false`, and it only adds the
connector (it needs `enable_sentinel`). Nothing starts a trial clock or touches
the tenant until a human runs the runbook.

## Consequences

- **Layering, stated once.** Entra ID Protection = cloud identity risk (live);
  Defender for Identity = native AD attacks (staged); custom detection-as-code
  on Sentinel with Splunk twins = portable, plus the two correlations MDI
  cannot make. `STAND-INS.md` and the README capability table
  both say this.
- **The twins are not dead weight.** They keep the Splunk migration path and
  the offline tests working, and they are the post-trial fallback when the MDI
  licence lapses. The lab can run the AD-attack detections with or without a
  Defender licence.
- **Response is unchanged for the twins.** The KQL twins keep the AD
  containment path (`Invoke-AdContainment.ps1` by a human, ADR 0017). MDI's own
  alerts arrive as Defender XDR incidents; the `notify` automation rule in
  `modules/monitoring` deliberately filters to lab analytic-rule ids, so an MDI
  incident is not double-notified (MDI has its own response actions).
- **The connector brings all Defender XDR alerts, not only MDI.** There is no
  standalone MDI Sentinel connector any more; MDI flows through the Defender
  XDR connector. In the unified Defender portal that connector may be managed
  for you once Sentinel is onboarded there. `verify:` both on the first apply
  (`mdi.tf` header).
- **Residual risk:** the sensor and licence are the human steps the runbook
  carries; a staged flag that is never applied leaves the native layer unproven
  in a tenant. It stays an open gap until the runbook runs.

## How it is measured

Nothing has run in a tenant, so each measure has a placeholder.

| Measure | Source | Target |
|---|---|---|
| MDI sensor health on DC01 | Defender portal, Identity sensors | Healthy; `<fill after running>` |
| An MDI Kerberoasting / DCSync alert reaches `SecurityAlert` | Log Analytics `SecurityAlert` | one of each; `<fill after running>` |
| The twin KQL rule fires on the same event | Sentinel incident from the twin rule | fires; `<fill after running>` |
| The two custom correlations have no MDI equivalent | manual review | confirmed; `<fill after running>` |

Offline today: the twins run on the Kusto emulator (22/22 rules,
`lab/evidence/kusto/`), and `mdi.tf` is covered by the module's mocked
`terraform test`.

## Amendment 2026-11-05: the Splunk twins run on live tenant events

**Context.** The Decision keeps the twins as "the Splunk migration path" and
"the post-trial fallback". Until today the Splunk side had only ever run on
synthetic harness rows (E61) and could not back the closing line that the lab
is "watched by two camera systems": Sentinel watched the tenant, Splunk watched
recordings.

**Decision.** Splunk gets a live feed from the same workspace Sentinel reads.
`lab/scripts/monitoring/feed-splunk-live.py` runs every 5 minutes as a per-user
LaunchAgent on the operator Mac and posts the rows Log Analytics received since
its watermark to the local Splunk HEC, as the lab operator (no person's
session, no new Azure permission: Owner on the lab subscription includes Log
Analytics read).

- **Source: the Log Analytics tables, not Graph.** The SPL twins search the
  Log Analytics schema (`azure:loganalytics:<table>`, `ResultType`,
  `LocationDetails.countryOrRegion`, ...). Graph's `auditLogs/signIns` and
  `auditLogs/directoryAudits` carry the same Entra sign-in and directory-audit
  events in another shape and cover two of the seven tables the twins read
  (`SecurityEvent`, the risk tables and `VaultCheckout_CL` are not in Graph).
  Feeding the workspace rows gives both SIEMs identical input, so a difference
  in what fires is a difference in the rules, never in the data.
- **Each row once.** Watermark on `ingestion_time()` minus a 10-minute overlap,
  de-duplicated by the workspace's own record id (`_ItemId`); the state is
  saved after every accepted HEC batch; an HEC failure stops the run and keeps
  the watermark at the last accepted batch. A batch Splunk may have indexed
  (reply lost, error part-way) is never resent blindly: the next run asks
  Splunk which of its record ids it holds and sends only the others. A Log
  Analytics result marked partial is refused whole.
- **Proven, not assumed.** A heartbeat event after every clean run;
  `lab/scripts/demo/preflight.sh` fails when the feed's newest event in Splunk
  is 15 minutes old or more.
- **Least privilege on the Splunk side.** The feed's own HEC token, pinned to
  `index=entra` and kept in the Keychain; the preflight searches as a user whose
  only capability is `search` on `entra`.

**Consequences.**

- The twins now fire on real events. First proof (capture-log E113): twelve
  wrong passwords for two lab test users from one IP in one 10-minute bin
  (16:30Z) reached Splunk by the 16:41Z feed run, and the *Failed sign-in
  spike* alert fired at 16:45Z with the same row Sentinel's KQL rule produced
  at 16:42Z (incident #57): FailedCount 12, two users, likely brute force.
- **Lag:** Entra reaches the workspace 2-15 minutes after an event, then up to
  5 minutes to the next poll, then up to 5 minutes to the next scheduled
  search. Sentinel's NRT break-glass rule is faster; the scheduled twins are
  comparable to their Sentinel counterparts.
- **The feed lives on the operator Mac.** When the Mac sleeps, Docker is
  stopped or the operator certificate lapses, Splunk stops seeing the tenant
  and the preflight says so; the watermark resumes where it stopped (rows
  older than a day before the watermark would need `--backfill-hours`).
  Production would stream from an Event Hub (`lab/docs/STAND-INS.md`).
- **Lookups differ until filled.** Splunk's operator-IP and SoD-holdings
  lookups are header-only by design (`lab/splunk/README.md`); Sentinel's
  watchlist is rendered by Terraform. Those two twins can therefore judge the
  same rows differently until the lookups are filled by hand.

## Revisit trigger

- The 90-day trial ends: decide licence or fall back to the twins.
- A second domain controller (each needs a sensor).
- MDI deprecates or renames a signature the twins mirror.
- The twins drift from MDI's coverage (a signature MDI adds, or one it drops).

## Evidence

- `lab/terraform/modules/monitoring/mdi.tf`: `enable_defender_for_identity`,
  the Defender XDR data connector
- `lab/terraform/modules/monitoring/variables.tf`:
  `enable_defender_for_identity` (needs `enable_sentinel`)
- `lab/terraform/modules/monitoring/outputs.tf`:
  `defender_for_identity_connector_id`
- `lab/terraform/envs/dev/lab.tfvars`: `enable_defender_for_identity = false`
- `lab/docs/runbooks/deploy-defender-for-identity-dc01.md`: the human steps
- `lab/kql/kerberoast-rc4-service-ticket.kql`,
  `lab/kql/dcsync-replication-request.kql`,
  `lab/kql/ad-privileged-group-change.kql`: twin headers
- `lab/kql/tier0-logon-without-checkout.kql`,
  `lab/kql/dc-logon-outside-operator-allowlist.kql`: custom-correlation headers
- `lab/docs/STAND-INS.md`: the DC01 SecurityEvent / MDI row
- `lab/docs/adr/0013-tier0-domain-controller-exposure.md`: the operator
  allowlist the custom rule reads
- `lab/scripts/monitoring/feed-splunk-live.py`,
  `lab/scripts/monitoring/launchd/com.contoso.splunk-live-feed.plist`,
  `lab/scripts/monitoring/tests/test_feed_splunk_live.py`: the live feed
  (amendment 2026-11-05); capture-log E113
- `lab/docs/adr/0017-approval-gated-identity-containment.md`: the AD
  containment path the twins keep

## Sources (Microsoft Learn, checked 2026-10-31; all `verify:` before an apply)

- `verify:` Defender for Identity offers a free 90-day trial, and the sensor is
  installed on the domain controller with a directory service account:
  https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity
- `verify:` MDI ships built-in detections for Kerberoasting (and other
  Kerberos attacks), DCSync, lateral movement and reconnaissance:
  https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview
- `verify:` the standalone MDI Sentinel data connector is retired; MDI alerts
  reach Microsoft Sentinel through the Microsoft Defender XDR connector, and in
  the unified portal that connection may be managed once Sentinel is onboarded:
  https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender
