# Evidence capture plan: the 30-day E5 + Entra ID Governance window

> **Status: plan only. Nothing in the E-numbered tables has run.** No tenant
> exists yet. Every E capture is something to do *during* the trial window.
> None of it is evidence until the capture log has a row with a real UTC time
> and a SHA-256. Don't cite any result from this plan until that row exists.
> The only things that have run are the four local harnesses listed under
> [Already run locally](#already-run-locally-no-tenant), and they prove the
> stand-ins, not the tenant.

## Why this plan exists

The trials are the scarce resource: 30 days of Microsoft 365 E5 (Entra ID P2,
Intune, Defender) and 30 days of Entra ID Governance, plus 31 days of
Sentinel. All the code is written offline before Day 0, so the window is spent
**capturing evidence, not coding**. The plan fixes three things in advance:

- **the order**, because some captures depend on others (Sentinel needs a few
  hours of sign-in data, and CA graduation needs report-only data first: in
  this window about five days, a recorded exception to the lab's 14-day rule,
  see [Days 7 to 13](#days-7-to-13-graduate-review-contain));
- **the day** each step happens, so nothing important falls off the end of
  the trial;
- **exactly what to capture**, so each piece of evidence is captured once, at
  the moment it happens, and never rebuilt afterwards.

## Capture rules

1. **Capture it when it happens, once.** Never re-stage a screenshot after the
   event. If a capture is missed, write `missed` in the capture log. A later
   real re-run gets a new capture ID and its own timestamp, marked
   `re-run of Exx`.
2. **Every capture gets a log row:** `lab/evidence/capture-log.csv`, created at
   the first capture, with columns `id,utc,what,sha256,stored_at,public,operator`.
   It must stay public-safe, so no tenant identifiers go in it.
3. **Originals are private.** They go to `lab/evidence/out/captures/<id>/`
   (gitignored) and are uploaded to the WORM store the same day, under
   `captures/<id>/`. Upload with
   `az storage blob upload-batch --auth-mode login --overwrite false -d evidence --destination-path captures/<id> -s <folder> --account-name <name>`
   (verify: `upload-batch` flags on the installed az version).
4. **Hash before anything else touches the file:**
   `shasum -a 256 <file>`. The scripts hash their own outputs. For a public
   copy, redact a *copy* (tenant ID, domain, object IDs, IPs, real UPNs) and
   hash that copy too. Never edit an original.
5. **Screenshots show when and where.** Include the portal breadcrumb and a
   timestamp column or the clock. Record the time in UTC.
6. **Report-only is reported as report-only.** A "would have blocked" result
   is never described as "blocked". Thresholds aren't lowered just to get a
   screenshot. If CA007 (sign-in risk **High**) doesn't fire because the
   simulated risk is Medium, that's the result, and it gets recorded.
7. **Stand-ins are named** in the capture note, as in
   [`STAND-INS.md`](STAND-INS.md).
8. **Test accounts only** for attack simulations (Tor, failed sign-ins,
   confirmCompromised, legacy auth). Never use the operator's or a
   break-glass account.

## The clocks

| Clock | Starts | Length | Ends | Notes |
|---|---|---|---|---|
| Microsoft 365 E5 trial (Entra ID P2, Intune, Defender) | Day 0, activated in the M365 admin center | 30 days | Day 30 | verify: trial length and any one-time extension shown at activation |
| Entra ID Governance trial | Day 0, same hour as E5 | 30 days | Day 30 | Access packages, Lifecycle Workflows, access reviews |
| Microsoft Sentinel trial | Day 2, when `enable_sentinel` applies | 31 days | Day 33 | Flip to `enable_la_alerts` by Day 32 (`modules/monitoring`) |
| Azure spend (DC01, Windows 11 VM, storage) | When each flag applies | No clock | n/a | Auto-shutdown nightly. The evidence store costs cents a month |

**Day 0 is the day both trials are activated.** Days below count from there.

## Staging flags: when each one flips

Each flip is its own PR, planned and applied by the pipeline. `lab.tfvars`
keeps every flag `false` until its day, so no trial or cost starts early.
The names below are the module variables. `envs/dev` has to declare and pass
each one through (`envs/dev/variables.tf`, `main.tf`); the P5 plan check
proves that before Day 0.

| Flag | Day | Starts or needs |
|---|---|---|
| `enable_evidence_store` | P2 (before Day 0) | Azure Storage only. Must exist before the Day 1 baseline |
| `enable_premium` | 1 | P1/P2: groups, break-glass, CA001-CA005, PIM |
| `enable_identity_protection_ca` | 1 | CA006/CA007, report-only (P2) |
| `enable_phishing_resistant_all_users` | 1 | CA008, report-only pilot |
| `enable_registration_ca` | 1 | CA009 (register security info: one-time TAP or a phishing-resistant method), report-only (P1) |
| `enable_device_code_block` | 1 | CA010 (block device code flow), report-only. Before it is ever enforced, the operator stops using `--use-device-code` for `az login` and `Invoke-BaselineAssessment.ps1`, or is put in the CA010 exception group through the exception process |
| `enable_admin_session_controls` | 1 | CA020 (sign-in every 4 h on the admin portals for Tier-0/1 admins), report-only |
| `enable_itdr_detections` | 1 | Telemetry only (VaultCheckout_CL, DCE/DCR, DC01 AMA), **no trial**. Set `iac_principal_ids` (TF_IAC_PRINCIPAL_IDS) in the same PR |
| `enable_itdr_detections_v2` | 3-5 (E15c) | The six second-wave rules (`modules/monitoring/itdr_v2.tf`). Needs `enable_itdr_detections`. Two are Sentinel-only (14-day look-back), so they have no post-trial Log Analytics path |
| `enable_sentinel` | 2 | **Starts the Sentinel trial.** Only after sign-in logs have flowed for a few hours, with `itdr_exclude_rules` holding back every ITDR rule whose table is still empty (E15) |
| `enable_pim_tiers` | 2 | P2. Brings the privileged role → tier map, the Tier-0 approver group, eligibility expiry (Tier 0 180 days, Tier 1 365 days), no permanent active assignment, and notifications to the security mailbox (`pim_alert_mailbox`) |
| `enable_global_admin_pim_policy` | 2 | Global Administrator's own PIM policy, applied by `post-apply/Set-DirectoryRolePimPolicies.ps1` (direct eligibility per named admin, never a group). Break-glass stays permanent active |
| `enable_helpdesk_au_scoping` | 2 | `AU-Workforce-Standard` and PIM-Tier1-Helpdesk's Helpdesk and Authentication Administrator roles scoped to it (`modules/pim/helpdesk.tf`; P1 for each AU administrator). Needs `enable_pim_tiers` |
| `enable_pim_auth_context` | 2, report-only | CA021, written by `post-apply/Set-AuthContextPolicies.ps1` from the bodies Terraform renders (auth context `c1` + the policy). PIM keeps its MFA requirement: `tier0_activation_auth_context_id` stays empty until CA021 is **enforced** (E36b), because a report-only policy on the context removes PIM's MFA fallback (Microsoft Learn, "Configure PIM for Groups settings", checked 2026-10-20: the MFA fallback doesn't apply when the context's policy is off, report-only, or excludes the eligible users) |
| `enable_governance` + `enable_nhi_governance` | 3 | Governance trial; App-Consent-Reviewers, which the consent policy (E21) needs |
| bootstrap `enable_identity_protection_logs` (local apply) | 1 | Risk tables for `identity-risk.kql` (P2) |
| bootstrap `enable_app_management_roles` (local apply) | 4, before `enable_sso_apps` | Graph app-management roles for APPLY, incl. Tier-0 `AppRoleAssignment.ReadWrite.All` (ADR 0005) |
| `enable_sso_apps`, `enable_scim_provisioning` | 4 | SCIM to AWS IAM Identity Center (`enable_scim_provisioning` = a local seeding apply first) |
| `clinical_portal_preauthorize_azure_cli` | 4, for E25 only | Off again in the next PR |
| `enable_access_reviews` | 8 | Governance |
| `enable_b2b_governance` | 8 | Governance |
| `enable_pim_azure_resources` | 8 | P2 |
| `enable_itdr_containment` | 13 | Logic App + Teams approval (approver group `ITDR-Containment-Approvers` populated first) |
| `containment_on_alert_added` | 14, only if E18/E41 show Defender correlating ITDR alerts into older incidents | Second automation-rule trigger |
| `enable_intune_vm` | 17, or earlier if the CA005 demo is filmed | Azure compute. Do the Intune prerequisites first (`lab/scripts/intune/README.md`) |
| `enable_shared_clinical_ca` | 17, only if a station enrolled with the `CH-SharedClinical` Autopilot profile exists | CA060, report-only. Needs `enable_phishing_resistant_all_users` (the workforce strength). Without such a device the policy matches nothing, and that is what gets recorded (E50b) |
| `enable_dc` | Before Day 0 (with the DC build in `lab/scripts/dc/`): Cloud Sync and the HR joiner (E20) need AD before Day 3 | Azure compute, no Entra licence; auto-shutdown nightly |
| `enable_pam_oidc_app` | With the PAM segment | guacamole-psm + CA022 (admin phishing-resistant strength for the PAM broker and admin portals; numbered CA009 before the CA number ranges, never applied), report-only; `lab/pam` then runs in OIDC mode. Before the flip, check that `ca_policy_states` in `lab.tfvars` keys this policy `CA022`: `CA009` is now the registration policy |
| `enable_agent_identity` | 19 | `uami-agent-runtime` for Entra Agent ID (preview, E53b) |
| `enable_la_alerts` (with `enable_sentinel = false`) | 32 | Post-Sentinel-trial path |

## Already run locally (no tenant)

These ran on 2026-10-20 on the author's laptop (Colima), against local
stand-ins only. When `capture-log.csv` is created, they become its first
rows, marked `local, no tenant`. They are never described as tenant results.
Every default run of `lab/pam/test/run-all.sh` that day passed 8 of 8
suites (610 checks passed, 0 failed, 1 skipped: no local Splunk). The
committed evidence is the hashed run records in `lab/evidence/`, indexed in
[`lab/evidence/README.md`](../evidence/README.md): the per-feature records
below, and the newest `offline-tests/` record, which holds the latest
default-suite counts and the runner's console output (the per-suite logs
stay in the gitignored `lab/pam/out/test-runs/`).

| ID | What ran | Result | Evidence |
|---|---|---|---|
| L01 | **midPoint certification campaign** (the SailPoint / Saviynt stand-in) for ADR 0012's T2 tier, headless over the REST API: `lab/pam/midpoint/run-campaign.sh`, checked by `lab/pam/test/e2e-midpoint.sh` (91/91) | 7 items: 4 accept, 2 revoke (one an SoD conflict midPoint flagged before the review), 1 left unanswered on purpose and removed. Completion 85.7%, below the 95% T2 target by design; revocation 33.3%; rubber-stamp rate not measurable (no reviewer had 10 items). A script records each decision inside the assigned reviewer's own security context; no reviewer signs in, and the evidence says so | `lab/evidence/midpoint/20261020T162116Z/` (`summary.json`, `decisions.csv`, `SHA256SUMS`); an earlier run of the same campaign in `20261020T152623Z/` (before the ADR 0012 threshold; its `rubber_stamp_flagged` uses the superseded definition) |
| L02 | **Vault dynamic database credentials** (`lab/pam/dynamic-db/`, checked by `lab/pam/test/e2e-dynamic-db.sh`, 60/60) | A new PostgreSQL login per request, SELECT on schema `clinical` only, 1-hour lease capped at 4 hours; revoking the lease ends a live session and drops the role; the bootstrap superuser password is nulled | Hashed run record from a standalone run of the same harness: `lab/evidence/dynamic-db/20261020T163436Z/` (`results.json`: 60 pass, 0 fail; `run.log`; `SHA256SUMS`) |
| L03 | **PAM stand-ins against a Samba AD DC** (`lab/pam/test/e2e.sh`, 284/284): discovery → onboarding → dependency-gated rotation → reconciliation, ticket-gated per-person check-out under Tier-0 dual control (two distinct approvers, neither the requester), OIDC-mode password lock-out, recorded SSH through the Vault SSH CA, a recorded RDP session to a Linux xrdp stand-in for DC01, HA failover, the timed DR drill and a rolling upgrade | All checks PASS. Reconciliation GAP 0. The DR drill measured RTO 42.1 s (target 300 s) and RPO 2.2 s (set by the drill's own 2 s pause: the mechanism, not a planning RPO). The drill runs on a separate 3-node rehearsal cluster holding test markers, not the vault that holds the AD credentials; restoring rotated credentials and reconciling drift after a restore is not drilled (ADR 0019) | `lab/evidence/pam/20261020T220031Z/` (`results.json` 284 pass / 0 fail, `reconcile.csv` / `.md`, `rdp-recording.json`, `run.log`, `SHA256SUMS`) and `lab/evidence/pam-dr/20261020T220031Z/` (`dr-drill.json` / `.md`). Earlier records `20261020T184052Z` and `20261020T204851Z` (241/241; RTO 40.5 s and 32.5 s) predate dual control and the RDP step |
| L04 | **Kubernetes workload identity on kind** (`lab/k8s/`, 64/64) | A pod gets its database password through Vault Kubernetes auth with a 10-minute audience-bound token and no Kubernetes Secret. 12/12 pipeline stages PASS; the cluster is deleted after each run | `lab/evidence/k8s/20261020T202112Z/` (`results.json`, `run.log`, `README.md`, `SHA256SUMS`) |
| L05 | **PAM discovery and onboarding at scale** (`lab/pam/test/e2e-scale.sh`, 79/79): 500 synthetic privileged accounts plus 250 ordinary staff in a Samba AD DC, through the same discover → onboard → dependency check → rotate → reconcile scripts | 515 privileged accounts discovered, 263 vaulted (100% of them rotated in policy), 128 documented exceptions, 124 held on unresolved dependencies; GAP 0, ORPHAN 0 | `lab/evidence/pam-scale/20261020T193913Z/` (`scale.json`, `results.json`, `reconcile.csv` / `.md`, `run.log`, `SHA256SUMS`) |

## Pre-window: no trial clock running (days P1 to P5)

| ID | Day | Do | Capture exactly | Stored |
|---|---|---|---|---|
| E01 | P1 | Open a PR that touches `lab/terraform/**` (free tier only) | The PR's plan comment from the PLAN identity, and the job log line that shows the OIDC login | Private + redacted public copy |
| E02 | P1 | Merge, then approve the `prod` environment | The required-reviewer approval screen, then the APPLY run summary with resources added | Private + redacted public copy |
| E03 | P1 | **Negative path:** start the APPLY workflow from a branch or event the federated credential doesn't match | The failed `azure/login` step with the AADSTS error (verify: expected code AADSTS70021, "no matching federated identity record"). This proves the trust is subject-scoped | Public copy, redacted |
| E04 | P2 | PR: `enable_evidence_store = true` + the root provider `storage { data_plane_available = false }` | `az storage account show -n <name> --query "{sharedKey:allowSharedKeyAccess, publicNet:publicNetworkAccess, worm:immutableStorageWithVersioning, minTls:minimumTlsVersion}"`, saved as JSON | Private |
| E05 | P2 | Human grant: Storage Blob Data Contributor with the no-delete ABAC condition (the `modules/evidence-store` header gives the command) | `az role assignment list --scope <evidence_container_id> -o json`, showing `condition` and `conditionVersion: 2.0` | Private |
| E06 | P2 | **Prove WORM:** upload `canary.txt`, try to delete it, try to overwrite it | The delete error, verbatim with its timestamp. The overwrite result (a new version). `az storage blob list --include v` showing both versions. The canary stays for the full retention period: that's the point | Private + public summary line |
| E07 | P3 | Apply the bootstrap `entra-diagnostics` (AuditLogs flow on free; sign-in logs need P1, so from Day 0) | The diagnostic-setting categories, and `AuditLogs \| summarize count() by bin(TimeGenerated, 1h)` | Private |
| n/a | P4 | Prepare a Windows x64 assessment host with Windows PowerShell 5.1 and PowerShell 7. ScubaGear is Windows-only, and the Zero Trust Assessment doesn't support Windows on ARM. Use any Windows PC you control, or a temporary Azure VM. Never DC01, because Tier-0 hosts don't run tooling downloaded from the internet. Install ScubaGear and run `Install-ScubaDependencies`. Install the ZeroTrustAssessment module. Do a dry run: `Invoke-BaselineAssessment.ps1 -Phase before -WhatIf` | Nothing. This is rehearsal, not evidence | n/a |
| n/a | P5 | Run the offline checks one last time: `terraform test` in every module, Pester, and `lab/pam/test/run-all.sh`. Then run the mocked plan test of `envs/dev` (`envs/dev/tests/mock_plan.tftest.hcl`) once with every flag in the table above set to `true`, so a flag the root module doesn't declare, or a `ca_policy_states` key the module rejects, fails now and not on Day 1 | Nothing new. These are build checks, not tenant evidence | n/a |

## Days 0 to 2: licences, baseline, report-only apply

| ID | Day | Do | Capture exactly | Stored |
|---|---|---|---|---|
| E08 | 0 | Activate the E5 and Governance trials in the same hour. Assign licences to the operator admin, the test users and the pilot users | M365 admin center: Billing > Your products, showing both trials and their **end dates**. Write the dates at the top of the capture log | Private (shows the tenant name) |
| E09 | 0 | Wait for sign-ins to appear | `SigninLogs \| summarize count() by bin(TimeGenerated, 1h)` showing rows arriving | Private |
| E10 | 1 | **Baseline before any premium config.** Run `Invoke-BaselineAssessment.ps1 -Phase before -StorageAccountName <name>`. Use the same licences as the "after" run, so the delta is configuration only | Generated by the script: public `lab/evidence/assessments/<run>-before/` (summary.json, SUMMARY.md, raw hashes) and private raw ScubaGear + Zero Trust reports in WORM. Commit the public folder that day | Public summary + WORM |
| E11 | 1 | KPI baseline: `08-Measure-KPIs.ps1 -Label baseline` | The dated snapshot in `lab/evidence/kpis/` with its `.sha256` sidecar (review completion = decisions a person made only, the same rule as `10-Review-KPIs.ps1`; service-applied defaults reported separately). Upload the private detail to WORM `kpis/` | Public + WORM |
| E12 | 1 | PR #1: `enable_premium`, `enable_identity_protection_ca`, `enable_phishing_resistant_all_users`, `enable_registration_ca`, `enable_device_code_block` and `enable_admin_session_controls` | The plan comment showing CA001-CA010 and CA020, every one `enabledForReportingButNotEnforced`, with the break-glass group excluded from each. Then the apply run | Redacted public copy |
| E13 | 1 | Run human step 6 (break-glass passkeys), then `01-Verify-Baseline.ps1` | The script's full output: every check PASS, including break-glass excluded from **every** CA policy in the tenant. No key serials or object IDs in the public copy | Redacted public copy |
| E14 | 2 | Optional checkpoint run: `Invoke-BaselineAssessment.ps1 -Phase checkpoint` | Generated. Shows that report-only policies **don't** move ScubaGear's CA results: an honest midpoint | Public summary + WORM |
| E15a | 1 | PR: `enable_itdr_detections` (telemetry only, no trial) + `iac_principal_ids`. Start `ingest-vault-audit.sh --follow 60` if the Vault stand-in is up | Plan/apply; `VaultCheckout_CL \| take 5` heartbeat rows | Private |
| E15 | 2 | PR #2: `enable_sentinel`, once sign-in logs have flowed for a few hours, with `itdr_exclude_rules = ["identity_risk", "tier0_logon_without_checkout", "ad_privileged_group_change", "kerberoast_rc4_service_ticket", "dcsync_replication_request"]` (their tables are empty: no risk events before E27, and DC01 Security events reach `SecurityEvent` only once Sentinel + the "Windows Security Events via AMA" connector are on - verify: Microsoft Learn) | Every core rule plus the ITDR rules whose tables have data, listed as Enabled, and the trial start date. verify: a tenant onboarding its first workspace since July 2025 is managed in the **Defender portal** (Microsoft Sentinel > Configuration > Analytics); Azure-portal Sentinel management ends 2027-03-31 - capture whichever the tenant shows | Private |
| E15b | 3-5 | Enable the "Windows Security Events via AMA" connector; once `SecurityEvent \| where Computer startswith "DC01"` has rows (and after E27 for `identity_risk`), a PR that empties `itdr_exclude_rules` | The rows, then the remaining ITDR rules Enabled | Private |
| E15c | 3-5 | PR: `enable_itdr_detections_v2` (the six second-wave rules and the `operator_ips` watchlist), with `itdr_exclude_rules` holding back `dc_logon_outside_operator_allowlist` until DC01 rows exist, `vault_privileged_access_anomaly` until `ingest-vault-audit.sh` ships the extended feed (`vault_feed_v2_columns`), and `pim_activation_without_auth_context` (preview) until E36b | The rules listed as Enabled, the watchlist, and which were held back and why | Private |
| E16 | 2 | PR #3: `enable_pim_tiers`, `enable_global_admin_pim_policy` and `enable_helpdesk_au_scoping`, then `post-apply/Set-PimGroupEligibility.ps1` | Script output: eligible members per tier group, each with an **end date** (Tier 0 180 days, Tier 1 365 days); none permanent | Private |
| E16a | 2 | Read back the PIM settings of one Tier-0 and one Tier-1 group (Graph `roleManagementPolicies` rules, and the portal settings page) | Approver = the Tier-0 approver **group**; eligibility expiry required; active assignment expiry required (no permanent active); activation notifications to the security mailbox; MFA (not yet `c1`) on activation. In the PIM blade, an active member can be added only with an end date (at most 15 days), never as permanent. Then the first notification email arriving in that mailbox | Private |
| E16b | 2 | Global Administrator: `post-apply/Set-DirectoryRolePimPolicies.ps1` (`-WhatIf` first) applies the role's own PIM policy and grants the named admin's **direct** eligibility (180 days). Then `post-apply/Convert-BuildAccountToEligible.ps1 -WhatIf`, then for real: it refuses unless break-glass, the second Global Administrator path, alerting and the activation policy all check out | Both scripts' check output; the eligibility schedules with end dates. `privileged_role_assignments.json` from a quick `Export-EvidencePack.ps1` run showing no standing Global Administrator except Break-Glass-Admins (flagged) | Private + public count |
| E16c | 2 | The help-desk administrative unit `AU-Workforce-Standard`: apply its membership rule (rendered by `modules/pim`, a Graph PATCH), list its members and the scoped role assignments | The AU's membership rule and members (HR-provisioned workforce only), and PIM-Tier1-Helpdesk's Helpdesk and Authentication Administrator assignments scoped to `/administrativeUnits/<id>` rather than `/`. Optional: `post-apply/New-RestrictedAdminUnit.ps1` for the VIP restricted-management AU, noting that its members drop out of PIM, reviews and Lifecycle Workflows | Private |

## Days 2 to 6: features run for the first time

| ID | Day | Do | Capture exactly | Stored |
|---|---|---|---|---|
| E17 | 2 | **PIM activation:** activate PIM-Tier0-CA-Admins with a justification and ticket number. A member of the Tier-0 approver group approves ([`runbooks/pim-activation-support.md`](runbooks/pim-activation-support.md)) | (1) the activation request with justification; (2) the approver's screen, and the requester **not** offered their own request (Microsoft Learn: approvers can't approve their own activation); (3) "Activated" with its end time (4-hour cap); (4) `AuditLogs \| where LoggedByService == "PIM"` rows; (5) the copied `ActivityDisplayName` strings, used to fix `pim-activation.kql` if Microsoft renamed them; (6) the activation email in the security mailbox | Private |
| E17b | 2 | An in-scope admin signs in to the Entra admin center | Sign-in log, Conditional Access tab: CA020's **report-only** result and its 4-hour sign-in frequency, exactly as shown | Private |
| E17c | 2 | `enable_pim_auth_context`, then `post-apply/Set-AuthContextPolicies.ps1 -WhatIf`, then for real | Its output: authentication context `c1` published (`isAvailable = true`) and CA021 created **report-only**, break-glass excluded, the admin strength with sign-in every time. PIM still asks for MFA, not `c1` (see the flag table) | Private |
| E18 | 2 | Wait for the rule | **First KQL alert firing:** the Sentinel incident from `pim-activation.kql`, with its entities, the Teams card and the ServiceNow INC number. verify: in the Defender portal (Incidents & alerts > Incidents) the correlation engine may merge alerts into an existing incident - note whether it did, it decides `containment_on_alert_added` | Private + one public line |
| E19 | 3 | PR #4: `enable_governance`, then `post-apply/Set-AutoAssignmentPolicies.ps1`, `post-apply/Set-IncompatibleAccessPackages.ps1 -Prune` (each `-WhatIf` first; they supersede `Set-AccessPackageSoD.ps1`, `lab/iga/README.md`) and `New-LifecycleWorkflows.ps1` | Script outputs; the access-package list with each package's review tier (ADR 0012); one automatic assignment policy per birthright package with its HR-attribute rule; the incompatibility links, showing that **no** link sits on a birthright package (one direction only, by design) | Private |
| E20 | 3 | **Joiner:** add an HR-feed row (a nurse), run `Invoke-InboundProvisioning.ps1`, then `02-Joiner.ps1` | Provisioning log for the bulk upload (Create: success). Account created, with the time from HR row to account in minutes. TAP issued (the event, **never the TAP value**). `Nurse - Clinical Apps` assigned by the **automatic** policy, with no request or approval, and the minutes from account to assignment. The joiner registers a passkey with the TAP: CA009's report-only result (expected: satisfied) | Private |
| E20b | 3 | A test user who holds only password + SMS tries to register a new method | CA009's report-only result exactly as shown (expected: would fail, because SMS is not in the bootstrap strength), and whether `security-info-registered-risky.kql` raised anything | Private |
| E21 | 3 | Run `Set-AuthenticationMethodsPolicy.ps1` and `Set-ConsentPolicy.ps1` in dry-run first (`Set-AuthenticationMethodsPolicy.ps1` with no switch = PLAN; `Set-ConsentPolicy.ps1 -WhatIf`), then for real (`-Apply` / no `-WhatIf`). `post-apply/Invoke-PostApply.ps1 -Only auth-methods,consent` runs both (dry run unless `-Execute`). `Set-AppGovernancePolicy.ps1` waits for Day 4, after the AWS SAML signing certificate is active (E22), because the app management policy's certificate cap could block that certificate (verify) | Each script's PLAN output and `-Apply` output. Neither script saves the policy it replaces, so the PLAN output, which shows the current value of each setting it will change, is hashed as the before-state. On Day 4 the same for `Set-AppGovernancePolicy.ps1`, plus the pre-change backup it writes | Private |
| E22 | 4 | PR #5: `enable_sso_apps` + `enable_scim_provisioning`. Start the SCIM job | **SAML SSO:** My Apps to the AWS access portal as a test user. The Entra sign-in log entry for the AWS IAM Identity Center app (Basic info and the Conditional Access tab). The decoded SAML assertion's NameID and session-tag claims, redacted | Redacted public copy |
| E23 | 4 | Run provision-on-demand for one test user | **SCIM provisioning log:** each step (import, scope, match, action Create) succeeds. AWS Identity Center shows the user and the `App-AWS-IdentityCenter-Users` group | Private |
| E24 | 4 | Human apply of the `aws/` root (permission set) | The apply output, and the test user signing in to the AWS console as ViewOnly through SSO | Redacted public copy |
| E25 | 4 | **OIDC app:** sign in to the Contoso Clinical Portal registration | The decoded ID token's `roles` and groups claims, redacted | Redacted public copy |
| E26 | 5 | **Risk simulation, report-only.** Test user A, not yet MFA-registered, signs in to `myapps.microsoft.com` through Tor Browser (Microsoft's documented anonymous-IP simulation) | After 10-15 minutes: the ID Protection risk detection "Anonymous IP address" **with the risk level it actually got**. The sign-in log Conditional Access tab showing CA007's **report-only** result exactly as displayed. CA007 triggers only on High; if the detection is Medium, record "not applied" | Private |
| E27 | 5 | Test user B: `POST /identityProtection/riskyUsers/confirmCompromised` (Graph, test account only), then B signs in | riskyUsers showing B as High / confirmedCompromised. CA006's report-only result on B's sign-in. The `identity-risk.kql` incident (**KQL alert 2**) | Private |
| E28 | 6 | **CA report-only insights:** the Conditional Access "Insights and reporting" workbook over loga-idlab, with about five days of data | Per policy (CA001-CA010, CA020, CA021, and CA022 once the PAM app exists): Success, Failure, User action required and Not applied counts, screenshot plus export. This is the go/no-go evidence for each graduation | Redacted public copy |
| E28b | 6 | From a lab test box, a test account signs in with device code (for example `az login --use-device-code`) | CA010's report-only result on that sign-in, and the `device-code-signin.kql` incident (Success, so the block would have had work to do) | Private |
| E29 | 6 | `07-Passwordless-Rollout.ps1` (Pilot) | Registration status per group and the go/no-go readiness verdict for CA008 | Private + public summary |

## Days 7 to 13: graduate, review, contain

Graduate one policy per PR with [`runbooks/graduate-a-ca-policy.md`](runbooks/graduate-a-ca-policy.md)
and [`runbooks/ca-change-review-checklist.md`](runbooks/ca-change-review-checklist.md).
Each PR's plan must show **one state change and nothing else**.

**The trial breaks the 14-day rule, on the record.** The runbook asks for at
least 14 days in report-only, covering nights and a weekend. A 30-day trial
can't hold that and still capture the graduations, so E30–E38b graduate
after 5 to 11 days of report-only data. That is a deviation limited to this
trial window: it goes through [`standards/exception-process.md`](standards/exception-process.md)
before E30, with the E28 counts attached, and each graduation PR states its
real number of report-only days. Outside the trial the 14-day rule holds
([`roadmap.md`](roadmap.md), Phase 1).

| ID | Day | Do | Capture exactly | Stored |
|---|---|---|---|---|
| E30 | 7 | Graduate CA003 (block legacy authentication) | The PR, the filled-in checklist, and the plan diff (one `state` line) | Public (PR) |
| E31 | 7 | A test account attempts a legacy protocol (verify: which legacy client still produces a sign-in event in 2026, for example SMTP AUTH) | The sign-in failure with the CA003 block. The `legacy-auth.kql` incident (**KQL alert 3**) | Private |
| E32 | 8 | PR: `enable_access_reviews`, then `post-apply/New-AccessReviewDefinitions.ps1 -DefinitionsPath reviews.json` (start date today; `terraform output -json access_review_definitions > reviews.json`). Built and Pester-tested offline (`tests/PostApply.Tests.ps1`); run `-WhatIf` first. The T1 reviews of PIM-eligible membership come from `modules/pim` (output `pim_eligible_review_bodies`, same shape, same script); before relying on them, create one in the portal, read its definition back and diff it against the rendered body (verify: whether an API-created review expands eligible members) | The created review definitions: privileged-group (including every tier group and Global Administrator eligibility) and inactive-user reviews, with deny by default and auto-apply, and the portal-vs-API diff | Private |
| E33 | 8 | PR: `enable_b2b_governance`, then the connected-organization post-apply (`post-apply/New-B2BConnectedOrganization.ps1 -PostApplyPath b2b.json`, `-WhatIf` first; it prints the id for `b2b_connected_organization_id`). A guest requests the "Affiliated Physicians" package and the sponsor approves | Request, approval and the guest's assignment **with its expiry date**. The external collaboration settings | Private |
| E34 | 8 | PR: `enable_pim_azure_resources`. Activate eligible Contributor on `rg-identity-lab` | The activation and the matching `AzureActivity` entry | Private |
| E35 | 9 | Graduate CA001 (MFA for all users) | PR, checklist and plan diff. One sign-in showing CA001 enforced | Public (PR) |
| E36 | 10 | Graduate CA002 (phishing-resistant MFA for admins) and CA007 (sign-in risk High: block), one PR each | Each PR. An admin sign-in that satisfies CA002's authentication strength with a passkey (sign-in log, Authentication details tab) | Public (PRs) + private |
| E36b | 10-11 | **Tier-0 activation step-up.** Graduate CA021 (its own PR). Only then switch the Tier-0 PIM policy from MFA to `c1`, in two applies: MFA off with the context still empty, then `tier0_activation_auth_context_id = "c1"` (the provider can't make that switch in one apply). Activate a Tier-0 group | Each PR's plan diff. The activation forcing a fresh phishing-resistant sign-in that carries `c1` (sign-in log, Authentication details and Conditional Access tabs). Then release `pim_activation_without_auth_context` from `itdr_exclude_rules` (fix its activity strings from E17 first) and activate once more: the rule (preview) should stay quiet; any alert means its field mapping needs fixing, and is recorded as such | Private + public PRs |
| E37 | 11 | Repeat the Tor sign-in with test user A, CA007 now enforced | The result exactly as shown: blocked if the risk is High, otherwise "not applied" with the risk level. Record either way | Private |
| E38 | 12 | Graduate CA006 (user risk High). Test user B (still confirmedCompromised) signs in | The forced MFA + secure password change (CA006's grant; passwordless risk remediation needs a provider the lab doesn't have yet), B's risk state moving to **remediated**, and the time taken | Private |
| E38b | 12 | Graduate CA009, CA010 and CA020, one PR each, after E28 shows no unexpected failures | Each PR's plan diff (one `state` line). Then: a TAP holder registers a method (allowed), the password + SMS user from E20b is refused; the device-code sign-in from E28b is blocked and `device-code-signin.kql` shows it as a failure; an admin is asked to sign in again after 4 hours on the admin portal | Public (PRs) + private |
| E39 | 12 | **Access review result** on a **T2 (requestable)** package - Pharmacy - Controlled Substances Apps. ADR 0012 certifies T2 by its 180-day expiry and adds a half-yearly policy review only when the package allows extension, which no default package does: turn on `extension_enabled` for it in a PR before Day 12 (verify: how `envs/dev` passes `access_packages`). Reviewers approve one person, deny one and leave one unanswered. Stop the instance early (portal) so decisions apply. Nurse - Clinical Apps (T3 birthright) has no request policy and no review by design: show that too | Decisions with justifications, the default-deny removal of the unanswered person, the audit-log membership removals, and the Nurse package showing only its automatic assignment policy, with no review | Private |
| E39b | 13 | `10-Review-KPIs.ps1` over the E32 and E39 decisions | The hashed snapshot `lab/evidence/kpis/reviews-<UTC>.json`: completion and revocation per tier and per reviewer, clinical lockouts (target 0), and the rubber-stamp rate reported as **not measurable** where no reviewer has 10 items. Compare with the midPoint run (L01) | Public + WORM |
| E39c | 13 | **SoD:** a nurse test user requests Pharmacy - Controlled Substances Apps (refused by the incompatibility link). Then an admin adds the same user **directly** to the group behind that package, and removes them afterwards. Before the test, `09-SoD-Report.ps1 -HoldingsSnapshotPath <gitignored path>` writes the holdings snapshot (refused inside the public evidence tree); by hand, upload it as the Sentinel watchlist `sod_holdings` and copy it to the Splunk lookup `contoso_sod_holdings.csv` | The refusal; the `sod-violation-granted.kql` incident naming SOD-01; `09-SoD-Report.ps1` run while the user was in the group (its exit code is the number of open violations; this one is in `lab/evidence/sod/<UTC>/` with its `manifest.sha256`); the same report after removal, one violation fewer | Private + public counts |
| E40 | 13 | PR: `enable_itdr_containment` (deploys the containment playbook) | Plan and apply, and the playbook's managed identity with its Graph permissions | Private |

## Days 14 to 19: ITDR, drills, lifecycle

| ID | Day | Do | Capture exactly | Stored |
|---|---|---|---|---|
| E41 | 14 | **Containment playbook run:** confirmCompromised on test user C, an incident is raised; FIRST a Teams-channel member who is NOT in `ITDR-Containment-Approvers` answers Contain (must be ignored), then a listed approver approves ([`runbooks/compromised-identity.md`](runbooks/compromised-identity.md)). verify: in the Defender portal the incident may be correlated into an older one - if Created never fires, run the playbook from the incident or turn on `containment_on_alert_added` | The incident, the "IGNORED ... not on the containment approver list" comment, the Teams card with the approver (UPN + object id) and time, the Logic App run history (every action and its result: revoke 204, **confirmCompromised 204**, disable 204), the audit-log entries, C's risk state confirmed compromised, C's next sign-in failing, and the incident closed with comments. **KPI: incident to contained, in minutes** | Private + public KPI line |
| E42 | 15 | Add a certificate credential to a test app. The app-governance policy blocks new secrets: capture that refusal too | The `app-credential-added.kql` incident (**KQL alert 4**), and the policy refusing the secret | Private |
| E43 | 15 | An admin grants consent to a test app | The `app-consent-granted.kql` incident (**KQL alert 5**) | Private |
| E44 | 15 | **Deliberate drift:** in the portal, edit one report-only CA policy outside the pipeline. Then open a PR | The `ca-policy-changed.kql` incident (**KQL alert 6**). The next plan showing the drift. The apply that reverts it | Private + public PR |
| E45 | 15 | Directly assign Helpdesk Administrator, active, to a test user in the portal (not through PIM). Remove it afterwards. Then, in the PIM blade, make a **permanent ACTIVE** assignment of the same role and remove it | The `role-assigned-outside-pim.kql` incidents (**KQL alert 7**: AssignmentPath Direct, then PimPermanentActive) and the removals. Copy the PIM record's exact `OperationName` and TargetResources shape into the rule if Microsoft's differ | Private |
| E45b | 15 | **The PIM-for-Groups bypass:** add a test user DIRECTLY as a member of Privileged-IAM-Admins (Groups blade, not PIM), remove it; then the same on Break-Glass-Admins with a disposable test user, removed at once | The `pim-group-member-added-outside-pim.kql` incidents (**KQL alert 7b**), Break-Glass-Admins always High; the removals | Private |
| E46 | 15 | An admin adds a phone method to a test user | The `auth-method-changed-by-admin.kql` incident (**KQL alert 8**) | Private |
| E46b | 15 | **Help-desk scope:** a test service-desk member activates PIM-Tier1-Helpdesk (roles scoped to `AU-Workforce-Standard`), resets the methods of a standard workforce user, then tries the same on a Tier-1 admin | The first succeeding and the second refused (portal error and audit log), with the role assignment's AU scope shown. `auth-method-changed-by-admin.kql` severity for the allowed change | Private |
| E46c | 15 | A test account registers a new Authenticator method from an unmanaged device through a VPN exit in a country it has not used in 14 days | The `security-info-registered-risky.kql` incident (**KQL alert 8b**) with the signals it counted | Private |
| E47 | 15 | From one IP, make 10 or more failed sign-ins within 10 minutes, **spread across three test accounts** so smart lockout doesn't lock one of them | The `failed-signin-spike.kql` incident (**KQL alert 9**) | Private |
| E48 | 15 | Optional: sign in through a VPN exit in a blocked country with a test account | The CA004 result and the `blocked-country-signin.kql` incident (**KQL alert 10**) | Private |
| E49 | 16 | **Break-glass drill:** each account with each key, 4 sign-ins ([`runbooks/break-glass-drill.md`](runbooks/break-glass-drill.md)) | Four rows in [`../evidence/drills/README.md`](../evidence/drills/README.md) (public-safe fields only). Private: each sign-in, the `break-glass-signin.kql` incident (**KQL alert 11**), the Teams card, the ServiceNow INC, the minutes from sign-in to incident, and the audit check that nothing was changed | Public rows + private |
| E50 | 17 | If the Windows 11 VM is built: mark it compliant (`New-IntuneComplianceBaseline.ps1`) and sign in to an admin portal from it, then from a non-compliant device | Intune device compliance, and CA005's result on both sign-ins as displayed (pilot scope) | Private |
| E50b | 17 | **Shared clinical workstation (CA060, ADR 0014):** only if a device enrolled with the `CH-SharedClinical` Autopilot profile exists (verify: whether the lab VM can be enrolled that way). Two clinician test users sign in one after the other with their own keys | CA060's report-only result for each sign-in, its 8-hour sign-in frequency and non-persistent browser session. If no such device exists, record "device filter not exercised: no CH-SharedClinical device" and the plan showing the policy; do not point the filter at another device to get a result | Private |
| E51 | 17 | If DC01 and the Vault audit ingestion are running: log on to DC01 as a Tier-0 admin **without** a Vault check-out | The `tier0-logon-without-checkout.kql` incident (**KQL alert 12**, Class Vaulted). Then a logon **with** a check-out that does **not** alert | Private |
| E51a | 17 | **PAM on DC01** (`lab/pam/README.md`): `vault-onboard-ad.sh`, `discover.sh` → `Get-AccountDependencies.ps1` through `az vm run-command` → `onboard.sh` → `reconcile.sh --verify --strict`; then `enable_pam_oidc_app`, an operator signs in to Guacamole through Entra, checks out against a ServiceNow PDI change (`ITSM_URL` pointed at the PDI) and records an RDP session to DC01 | The reconciliation report (GAP 0, held accounts named), the dependency scan output (names only), the Guacamole History row with the operator's UPN, the Vault audit line with the change number, the recording playing back, CA022's report-only result on the operator's sign-in. Stand-ins named | Private + public counts |
| E51f | 17 | With the Vault audit feed carrying the ticket and operator columns (`vault_feed_v2_columns`), release `vault_privileged_access_anomaly` and `dc_logon_outside_operator_allowlist` from `itdr_exclude_rules` (one PR), then: (1) read a Tier-0 credential with a token that has no ticketed check-out; (2) expire one entry in the `operator_ips` watchlist and RDP to DC01 from that address | `vault-privileged-access-anomaly.kql` (Signal `Tier0CredReadUncovered`) and `dc-logon-outside-operator-allowlist.kql` incidents. Restore the watchlist entry afterwards | Private |
| E51b | 17 | DC01, from a lab test box only: (1) add a disposable test account to Domain Admins and log on with it; (2) a lab Kerberoast of the planted SPN accounts (Rubeus `kerberoast /tgtdeleg` or Impacket `GetUserSPNs.py -request`, RC4); (3) one Purple Knight (Community) or PingCastle (free) run; remove the test account afterwards | `ad-privileged-group-change.kql` (4728) and `tier0-logon-without-checkout.kql` Class Unvaulted incidents; `kerberoast-rc4-service-ticket.kql` (High: 3+ SPNs); the AD assessment report, hashed into the capture log (raw report private: it maps the domain). verify: "Audit Kerberos Service Ticket Operations" and "Audit Security Group Management" on DC01 | Private + public hash |
| E51c | 17 | Optional, lab DC only: DCSync with Impacket `secretsdump.py -just-dc-user krbtgt` from a test account granted the replication rights for the drill (removed afterwards); then the krbtgt double reset | `dcsync-replication-request.kql` incident; the removed rights. verify: the domain SACL audits the replication rights (no 4662 otherwise) | Private |
| E51d | 18 | **CA restore drill** (Microsoft Entra Backup and Recovery, preview - verify: availability in the trial tenant): change a report-only CA policy's exclusions in the portal, restore it from the backup, then let `terraform plan` confirm no drift | The restore job, the `ca-policy-changed.kql` incident for the change, the clean plan. If the product isn't available, the same drill with `lab/scripts/powershell/Invoke-CaRestoreDrill.ps1` (Snapshot → Compare → Restore `-Apply`, timed; stand-in row in STAND-INS.md): its snapshot, `.sha256` and printed restore time. Restore refuses a snapshot whose `.sha256` sidecar is missing or doesn't match, and a body without the break-glass exclusion; re-creating a deleted policy as enforced needs `-AllowEnabledRecreate`. The restore record goes to the gitignored `lab/evidence/out/ca-restore/ca-restore-<utc>.json` | Private |
| E51e | 18 | **Token protection pilot (CA011).** `Set-TokenProtectionPolicy.ps1` owns **CA011**: it finds its policy by the `CA011 - ` prefix and patches only a policy carrying that full prefix (ownership guard), so it never touches the CA010 device-code block. If the CA005 pilot device exists: the script without `-Apply` first (plan only), then `-Apply` (report-only), and sign in to Outlook/Teams from the device and from a browser | The plan output showing it creates CA011 and leaves CA010 alone. Then the report-only result per sign-in (Token Protection: satisfied / would fail) | Private |
| E51g | 18 | **Protected actions (CA023 + `c2`).** CA023 and authentication context `c2` are BUILT offline (`enable_protected_actions_ca`, report-only; `Invoke-PostApply` step 3b). Only after CA023 is **enforced**: bind `c2` to the protected actions for Conditional Access policies and named locations (update and delete). verify: the Graph beta `resourceActions` PATCH shape | `Set-AuthContextPolicies.ps1` output for CA023; the binding; one CA policy edit that now asks for the step-up. Until CA023 is enforced, record `not bound: CA023 report-only` | Private |
| E52 | 18 | **Mover**, then **leaver:** change the test nurse's HR department, push the feed, and let the automatic policies act (`03-Mover.ps1` verifies and is the fallback); then mark the HR row terminated, then `04-Leaver.ps1` | The new birthright package assigned by policy, and the old one removed only after the 72-hour grace (read it again on Day 21). Disable time (**KPI: HR row to account disabled, minutes**). SCIM provisioning log "Disable" to AWS. The NHI-owner reassignment step | Private + public KPI line |
| E53 | 19 | `06-NHI-Inventory.ps1` and `Find-ShadowAdmins.ps1` | Findings counts by OWASP NHI ID and by path type, plus the hashed CSV/JSON | Private + public counts |
| E53b | 19 | PR `enable_agent_identity`, then `post-apply/New-AgentIdentity.ps1` (preview; `-OfflinePreview` first) | The blueprint and agent identity with its human sponsor and managed-identity federated credential, and **no** secret or permission. Say "identity-only" | Private |
| E53c | 19 | Optional: midPoint aggregates the Entra users through the Graph connector (`lab/pam/README.md`, midPoint section) | The import task result and the users linked to their shadows | Private |

## Days 20 to 24: buffer

Use these days for re-takes and anything that failed. A re-take filmed for
the video is a **new live run**, so it gets a new capture ID marked
`re-run of Exx`. Optional, because the detection needs 14 days or 10
sign-ins of history: Microsoft's atypical-travel simulation on test user A.

## Days 25 to 29: measure "after", hash, close

| ID | Day | Do | Capture exactly | Stored |
|---|---|---|---|---|
| E54 | 25 | `08-Measure-KPIs.ps1 -Label after -CompareTo <baseline file>` | The snapshot, its sidecar and the delta table: standing vs eligible admins, % phishing-resistant, CA coverage, review completion (decisions a person made only, the same rule as `10-Review-KPIs.ps1`; service-applied defaults reported separately) and revocation, stale accounts, HR-to-disable minutes, NHI credential findings | Public + WORM |
| E55 | 26 | `Invoke-BaselineAssessment.ps1 -Phase after -StorageAccountName <name>` | Generated, including the **before/after delta** per MS.AAD control and the Zero Trust pass rate. Expect CA008 / MS.AAD.3.1 to stay failing (pilot) and the documented gaps (3.8, 5.1) to stay failing. MS.AAD.5.2 (only administrators consent) may fail while users can still consent to verified publishers for low-impact scopes (ADR 0018); record what ScubaGear reports, verify. MS.AAD.3.9 (block device code flow) should move to pass only if CA010 was enforced at E38b; if it doesn't, record why. That's honest, not a defect | Public summary + WORM |
| E56 | 27 | `Export-EvidencePack.ps1` (its manifest also hashes the companion evidence: NHI inventory, shadow admins, KPI snapshots, drill records, review definitions, assessment summaries, containment records), then upload `lab/evidence/out/` to WORM `packs/<utc>/`, and `lab/evidence/kpis/`, `drills/` and `access-reviews/` (each file with its `.sha256`) to `captures/E56/`, all with `upload-batch --overwrite false` | The pack's `manifest.json` SHA-256 written into the capture log, so the private pack is verifiable from the public log | Public hash + WORM |
| E57 | 28 | Close-out: every Exx has a log row or `missed`. Commit the public artefacts. **WORM lock decision:** either lock (`immutability_state = "Locked"` + `immutability_lock_acknowledged = true`, a second apply that is irreversible; shorten the period first if this is a throwaway lab) or stay Unlocked and say so | The decision with its reason in the capture log, and `az storage account show` of the policy state afterwards | Public line + private |
| E58 | 29 | Post-trial PRs ready: `enable_la_alerts` replaces `enable_sentinel` by Day 32. Decide each CA policy's state for after the P2 licences lapse (verify: how risk-based CA behaves when the P2 licence expires) | The PRs (opened, not merged early) | Public |

## Coverage index: required captures

| Required capture | IDs |
|---|---|
| CA report-only insights | E12, E14, E28 (then E30, E35-E38, E36b, E38b as each policy graduates) |
| CA009 register security info | E20 (TAP holder), E20b (password + SMS), E38b (enforced) |
| CA010 block device code flow | E28b (report-only), E38b (enforced) |
| CA020 admin sign-in frequency | E17b, E38b |
| CA021 + PIM step-up on auth context `c1` | E17c (report-only, PIM still on MFA), E36b (enforced, then PIM switched to `c1`) |
| CA060 shared clinical workstations | E50b (or "not exercised", stated) |
| PIM activation log | E17, E34, E36b |
| PIM approver groups, eligibility expiry, no permanent active, notifications | E16, E16a, E17 |
| Global Administrator direct eligibility; build account made eligible | E16b |
| Help-desk administrative-unit scoping | E16c, E46b |
| Birthright by automatic assignment (joiner, mover grace) | E19, E20, E52 |
| SoD: preventive links, detective report, detection | E19, E39c |
| Access review result | E32, E39; midPoint stand-in L01 |
| Review KPIs (ADR 0012) | E39b; L01 |
| SSO sign-in + SCIM provisioning log | E22, E23, E24, E25, E52 (deprovision) |
| PAM on the real DC (discovery → reconcile, ticket-gated OIDC session, RDP recording) | E51a; harness L03 (and L05 at 500-account scale) |
| Dynamic database credentials | L02 (local only; no tenant step) |
| NHI + Agent ID | E21, E42, E43, E53, E53b |
| Risk detection simulation | E26, E27, E37, E38 |
| KQL alerts firing (22 rules) | E18, E27, E28b, E31, E39c, E42-E48 (incl. E45b, E46c), E49, E51, E51b, E51c, E51f, E36b (`pim-activation-without-auth-context`, expected quiet) |
| AD plane (Kerberoast, privileged-group add, DCSync, AD assessment) | E51b, E51c |
| CA restore / token protection | E51d; E51e |
| Protected actions (CA023 + `c2`) | E51g |
| Containment playbook run | E41 |
| KPI baseline vs after | E11, E54 (plus the E41 and E52 timing KPIs) |
| ScubaGear + Zero Trust before/after | E10, E14 (checkpoint), E55 |
| Break-glass drill record | E49 |
| WORM proof and pipeline trust | E03, E04, E05, E06, E57 |

## Where everything lives

| What | Public (committed) | Private |
|---|---|---|
| Assessment runs | `lab/evidence/assessments/<run>/` (summary.json, SUMMARY.md: results, mapping, raw hashes) | `lab/evidence/out/assessments/<run>/` + WORM `assessments/<run>/raw/` |
| KPI snapshots | `lab/evidence/kpis/` + `.sha256` sidecars | `lab/evidence/out/kpis/` + WORM `kpis/` |
| Evidence pack | Its `manifest.json` hash in the capture log | `lab/evidence/out/` + WORM `packs/<utc>/` |
| Screenshots and exports | Redacted copies only, if any | `lab/evidence/out/captures/<id>/` + WORM `captures/<id>/` |
| Drill record | `lab/evidence/drills/README.md` rows | Ticket + WORM `drills/<utc>/` |
| Capture log | `lab/evidence/capture-log.csv` | n/a |

The WORM store is `lab/terraform/modules/evidence-store`: version-level
immutability, Entra authentication only, and writers who can add but never
delete. Run integrity checks against it, not against the laptop copy.
