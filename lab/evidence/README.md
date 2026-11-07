# Evidence: hashed run records

This folder holds the lab's **hashed run records**: what a local run
actually did, written by the harness itself (`offline-tests/` and `k8s/`: by
a wrapper around the repository's own commands), with a `SHA256SUMS` file in
every record folder. They are not all the same kind of evidence:

- `midpoint/`, `dynamic-db/`, `pam/`, `pam-dr/`, `pam-scale/` and `k8s/` are
  **RAN · harness**: run end to end on local Docker or a kind cluster on the
  author's machine, with synthetic accounts and data.
- `kusto/` is **RAN · harness** for the 22 KQL detections of 2026-10-21 and 2026-10-31 (the `-workspace` record is the two newer rules on the Log Analytics query engine instead): they ran on the
  Azure Data Explorer Kusto emulator, a local container, against synthetic
  tables and events, with Sentinel's `_GetWatchlist` shimmed. It is a real
  KQL engine, but it is **not a Log Analytics workspace, not Sentinel and
  not a tenant**.
- `offline-tests/` is the evidence for **BUILT**: offline checks (validate,
  lint, tests with every Terraform provider and Graph call mocked). Only one
  row in each of its records, `pam-run-all` (the PAM runner's default suites
  on local Docker), is **RAN · harness**.

**RAN · tenant** records sit next to them since the tenant run (from
2026-10-27): `kpis/` (KPI snapshots and one-pagers), `assessments/` (the
Zero Trust Assessment "before"), `access-reviews/`, `config-snapshots/`,
`nhi/` (robot-account inventory, counts only) and `sod/` (blocked
combinations, pseudonymised). Each is listed in
[`capture-log.csv`](capture-log.csv) with its E-row; the tenant captures
that name people stay in the private WORM store. The harness records above
are still harness evidence: the Kusto record shows how the KQL engine
evaluates the rules, not how Sentinel schedules them.

Status words are the ones the repository uses everywhere: RAN · tenant,
RAN · harness, BUILT, DESIGNED (see the [README](../../README.md)).

## Records

All records date from 2026-10-20 (UTC) except two from early on 2026-10-21:
the newest offline-tests run finished at 00:06 UTC, and the Kusto run
started at 00:12 UTC. Each folder name is the run's UTC start time.

| Folder | What ran | Result | What it does NOT prove |
|---|---|---|---|
| [`midpoint/20261020T162116Z/`](midpoint/20261020T162116Z/) | A T2 certification campaign in Evolveum midPoint 4.10 (the SailPoint / Saviynt stand-in), driven over its REST API by `lab/pam/midpoint/run-campaign.sh` | Campaign closed. 7 items: 4 accepted, 2 revoked (one an SoD conflict midPoint flagged first), 1 left unanswered on purpose and removed. Completion 85.7% (T2 target 95%, missed by design), revocation 33.3%, rubber-stamp rate not measurable (no reviewer had 10 items) | Reviewer behaviour: a script records each decision inside the assigned reviewer's own security context, milliseconds apart; no reviewer signed in. Users are mock-HR personas, not Entra users. No Entra access review has run |
| [`midpoint/20261020T152623Z/`](midpoint/20261020T152623Z/) | An earlier run of the same campaign | Same outcomes and KPIs | Written before the ADR 0012 rubber-stamp threshold (a minimum of 10 items per reviewer): its `rubber_stamp_flagged` list uses the superseded definition. The files are left unchanged |
| [`dynamic-db/20261020T163436Z/`](dynamic-db/20261020T163436Z/) | Vault's database secrets engine against PostgreSQL (`lab/pam/test/e2e-dynamic-db.sh`) | 60 passed, 0 failed: a new login per request, `SELECT` on schema `clinical` only, 1-hour lease capped at 4 hours; revoking the lease ends a live session and drops the role | One synthetic database with its own Vault, not joined to the AD stack. No production database, no PAM product |
| [`pam/20261020T220031Z/`](pam/20261020T220031Z/) (latest) | The AD-dependent PAM flow against a Samba AD domain controller (`lab/pam/test/e2e.sh`, from `test/run-all.sh --publish`): discovery, onboarding, dependency-gated rotation, reconciliation, ticket-gated per-person check-out with Tier-0 dual control, recorded SSH (Vault SSH CA), a recorded RDP session to a Linux xrdp stand-in, OIDC-mode lock-out, the 3-node HA cluster, the DR drill and a rolling upgrade | 284 passed, 0 failed. Reconciliation GAP 0, ORPHAN 0. `rdp-recording.json`: the session recording's format check and its playback through Guacamole's History API. `code.sha256sums`: the 90 `lab/pam` files the run used. One harness file changed after it: `test/e2e.sh` (a fix for a first run on a fresh stack; see `offline-tests/20261020T230108Z/`), so its verifier now notes `test/e2e.sh` as changed | Windows behaviour: Samba is not Windows Server, and the RDP target is a Linux container, not DC01. Tickets and approvals come from a mock ServiceNow Table API. Everything ran on one Docker host. Operators sign in to Guacamole with local passwords (Entra sign-in is BUILT, not run) |
| [`pam/20261020T204851Z/`](pam/20261020T204851Z/), [`pam/20261020T184052Z/`](pam/20261020T184052Z/) | Earlier runs of the same flow | 241 passed, 0 failed each; GAP 0 | They predate dual control and the RDP step. `184052Z` has no code fingerprint, so it does not name the script version it ran |
| [`pam-dr/20261020T220031Z/`](pam-dr/20261020T220031Z/) (latest), [`20261020T204851Z/`](pam-dr/20261020T204851Z/), [`20261020T184052Z/`](pam-dr/20261020T184052Z/) | The timed Vault DR drill, from the same runs as the `pam/` records: snapshot, destroy all three nodes and their volumes, rebuild, restore | PASS each against a 300 s RTO target: RTO 42.1 s, 32.5 s and 40.5 s; RPO 2.2 s each | The vault that matters: the drilled cluster is a separate rehearsal cluster holding test markers (a 16 KB snapshot: one KV marker and one policy), not the single-node vault that holds the PAM flow's AD credentials. Restoring rotated credentials and reconciling password drift after a restore (`reconcile.sh --verify --strict`) is not drilled (ADR 0019). A planning RPO: the 2.2 s is set by the drill's own pause between the snapshot and the disaster (production RPO is the snapshot interval). A transit-engine auto-unseal stands in for Azure Key Vault; one Docker host, no availability zones, no TLS |
| [`pam-scale/20261020T193913Z/`](pam-scale/20261020T193913Z/) | `lab/pam/test/e2e-scale.sh` (`run-all.sh --scale`): 500 synthetic privileged accounts plus 250 ordinary staff in a Samba AD DC, through the real discover → onboard → dependency check → rotate → reconcile scripts, every stage timed | 79 passed, 0 failed. 515 privileged accounts discovered, 263 vaulted (all rotated within policy), 128 documented exceptions, 124 held on unresolved dependencies; GAP 0, ORPHAN 0 | A real estate: the population and its dependencies are generated from a fixed seed. Passwords were not verified by bind in this run (`--verify` not run), and the timings belong to one laptop |
| [`offline-tests/20261106T074026Z-scanner-selftest/`](offline-tests/20261106T074026Z-scanner-selftest/) | **RAN · harness** (2026-11-06, capture log L09): the merge gate's scanner positive control (`lab/pipelines/scanner-selftest/selftest.sh`, ADR 0026) run locally with the gate's own digest-pinned Checkov 3.3.3 and TruffleHog 3.97.9 images; its stub test; and one sabotage run (the Checkov image swapped for alpine). Files: three console outputs (counts only, never the generated key) and `SHA256SUMS` | PASS: bad fixture 2 Checkov failures and 1 TruffleHog finding, good fixture 0 and 0; stub test 11/11; the sabotage run failed with ERROR (exit 1), as it must | Not CI: the `scanner-positive-control` job had not run yet. TruffleHog ran with `--no-verification`, so this does not test the gate's verified-only mode, which no planted key can trigger |
| [`offline-tests/20261020T235044Z/`](offline-tests/20261020T235044Z/) (latest) | Every offline check on a copy of the working tree (its own [README](offline-tests/20261020T235044Z/README.md) has the table): Terraform fmt / validate / test in all 18 directories, Checkov, PowerShell parse + PSScriptAnalyzer, the ScubaGear fixture's pinned hashes, the lab Pester suite on Pester 5.7.1 and 6.2.0, ITDR Pester, shellcheck, actionlint, JSON, the Splunk render check, the ingest test, the Kusto harness's offline `check`, and the hashes and verifiers of the records above. Then `lab/pam/test/run-all.sh` (default suites, no `--publish`, run `20261021T000019Z`) on the same `lab/pam` | All 19 suite rows PASS: `terraform test` 325 passed, 0 failed; Checkov 46 passed, **0 failed**, 10 skipped (each an inline skip with its reason); lab Pester 917 passed on both versions, ITDR 284; PSScriptAnalyzer 0 errors (19 warnings in `lab/scripts/powershell`, 101 lab-wide); shellcheck 0 findings on 41 scripts; actionlint clean on 6 workflows; PAM 8/8 suites, 610 passed, 0 failed, 1 skipped (498 end to end in Docker, 112 offline unit tests). `code.sha256sums`: the 503 `lab/` and `.github/` files it tested | Anything in a tenant: every provider and Graph call is mocked, so the offline rows are BUILT evidence, not RAN · harness. No KQL ran on an engine (the Kusto check validates case files only). For the PAM suites it holds the counts and run-all's console output, not the per-suite logs (the harness keeps those gitignored). Not a fresh clone: the PAM run reused the shared stack's containers and `.env` from the `--cleanup` state |
| [`offline-tests/20261020T230108Z/`](offline-tests/20261020T230108Z/) | The same checks one run earlier (PAM run `20261020T230641Z`), before the Checkov inline skips, the NTDS disk fix and the wording fixes in this pass | All 18 suite rows PASS: `terraform test` 325 passed; Checkov 8 failed, all the then-documented baseline (0 new); lab Pester 917 on both versions, ITDR 284; PSScriptAnalyzer 0 errors; shellcheck 0 findings on 41 scripts; PAM 8/8 suites, 610 passed, 0 failed, 1 skipped | As above. Its `results.json` labels the whole run RAN · harness: only its `pam-run-all` row is. Edited once after the run, for publication (each file's hash from before path normalisation, the build source's commit id and eight random 32-hex temp names were removed or normalised), then re-sealed; its README lists the edits. No count or verdict changed |
| [`kusto/20261106T074249Z-workspace/`](kusto/20261106T074249Z-workspace/) | **RAN · harness, on the Log Analytics query engine** (2026-11-06, capture log E114): the 25 cases of the two detections ported from Sentinel-Privileged-Access (`dormant-privileged-account-reactivation`, `keyvault-bulk-secret-read`), each sent by `lab/monitoring/kusto-harness/run-on-workspace.py` as one read-only query to loga-idlab with the case's synthetic rows bound by `let` over the real table names. Files: `results.json` (each case, its first rows, the rule and case-file sha256) and `SHA256SUMS` | **PASS** 25/25 (11 positive, 14 negative), FAIL 0, ERROR 0, SKIPPED 0 | No rule was created in Sentinel: no query period, entity mapping, grouping or incident was tested. Every row is synthetic. Not run on the Kusto emulator |
| [`okta-migration/20261107T010713Z/`](okta-migration/20261107T010713Z/) | **RAN · tenant** (2026-11-07, capture log E115): Okta -> Entra app migration Phase 0 and the wave-1 *before* sign-in. Files: `inventory.json` (3 clinic apps from the Okta API: sign-on mode, groups, users, authentication policy rules, group rules with their Entra translation; admins' factors), `tracker.csv`, the test result (`*-okta.json`), `syslog-clinic-lab-results.json` (the System Log query), `SHA256SUMS` | **PASS**: test-user-b reached Clinic Lab Results through Okta and Entra; the app verified Okta's ID token | No cut-over yet: the Entra app (PR #219) was not applied when this ran |
| [`kusto/20261021T001217Z/`](kusto/20261021T001217Z/) | The 22 `lab/kql` detections on a real KQL engine: the Azure Data Explorer Kusto emulator (`lab/monitoring/kusto-harness/run.sh --accept-eula`, run by the operator after accepting Microsoft's emulator licence), a local amd64 container under Rosetta with the image pinned by digest. One database with the 7 tables the rules read (Learn's column types, only the columns the rules use) and 2 watchlist store tables. Each of 223 cases clears the tables, ingests its own synthetic rows, runs the rule as `modules/monitoring` renders it and checks the rows; plus 13 engine-semantics probes. Files: `results.json`, `run.log`, `setup.kql`, 31 rendered queries, `guids.txt` (none) and `SHA256SUMS` over all 35 | **PASS**: rules 22/22 passed, 0 not run; cases PASS 223 (131 positive, 92 negative), FAIL 0, ERROR 0, XFAIL 0, XPASS 0. The three CODE NEEDED fixes passed their cases. **Imports skipped 12**: rows of the offline KqlLite fixture file that are not whole raw table rows (8 stage-level rows, 4 with derived-`let` `joinRows`), so they were never sent to the engine and are not among the 223; each is listed with its reason in `skippedImports`, and hand-written raw-event cases cover the same situations. One probe (`negative-array-index`) did not answer: its own query has a syntax error. The sha256 of every rule and case file it ran is in `results.json` `inputs` | Anything in Sentinel or Log Analytics: the emulator is **not a Log Analytics workspace, not Sentinel and not a tenant**. No analytics rule was scheduled, so no query period, lookback, entity mapping, grouping, suppression or incident was tested. No real sign-in, audit or Windows event was read: every row is synthetic. The Sentinel-only function the rules call, `_GetWatchlist`, is shimmed (3 variants, in `shims.kql` and `results.json` `shims`), and Sentinel's rejection of a rule over a table that has never received data is not emulated. The SPL twins did not run. Under the emulator's licence the record holds no timings, so it says nothing about query performance |
| [`k8s/20261020T202112Z/`](k8s/20261020T202112Z/) | One full run of `lab/k8s/ci/pipeline.sh` on a throwaway kind cluster (its own [README](k8s/20261020T202112Z/README.md) has the stage table) | Exit 0: 12/12 stages, teardown PASS, end-to-end 64/64 | AKS or Entra Workload ID (that mapping is BUILT, never applied), and the GitHub Actions job (never run). Local paths in the logs were normalized before publishing. After the run, each file's hash from before that normalisation and the build source's commit id were removed for publication and the folder re-sealed; its README lists the edit. No result or log line changed |
| [`k8s-rbac-lint/20261106T071006Z/`](k8s-rbac-lint/20261106T071006Z/run.txt) | **RAN · harness** (capture log L07): the RBAC linter (`lab/k8s/rbac-lint`), old and new, on two exports of a throwaway k3s v1.31.4 cluster in Docker with `fixtures/risky-rbac.yaml` applied | Raw API `ClusterRoleList` (73 items, none with a `kind`): old linter `No risky RBAC found`, exit 0; new linter 11 findings, exit 1. `kubectl -o json` List: old 21 (9 of them false alarms on k3s's own roles), new 12, every planted role in both | The lab's kind cluster or AKS (the linter is not part of `ci/pipeline.sh`); RoleBindings; who holds the roles |
| [`conjur-state-leak/20261106T071613Z/`](conjur-state-leak/20261106T071613Z/run.txt) | **RAN · harness** (capture log L08; historical record: ADR 0027 removed Conjur and this code, and the Key Vault redo is `lab/secrets/state-leak/`): `lab/pam/conjur/state-leak/run.sh` on the lab Mac: a throwaway Conjur OSS 1.27.0 in Docker, HashiCorp Terraform 1.16.5, provider `cyberark/conjur` 0.9.15, a random 40-character value | Exit 0. `conjur_secret` data source: the value is in `terraform.tfstate` (1), its backup (1) and the saved plan (2). Ephemeral resource: 0 in all three, and its precondition proved the value was read (a wrong-length negative control failed first). Neither printed it | Conjur Enterprise / CyberArk Secrets Manager; any real credential; anything in the lab's own Terraform (none of it reads Conjur) |
| [`aws-admin/20261105T1057Z/`](aws-admin/20261105T1057Z/) | **RAN · tenant** (2026-11-05, capture log E95-E99): AWS administration without root (ADR 0025). Non-secret read-backs: `adm-labops` (sponsor, methods, no licence), `PIM-AWS-Lab-Admins` and its PIM policy, the eligibility, the PIM audit (activation 10:44Z, end 11:01Z), the SCIM provisioning log, the AWS permission sets and assignments, CloudTrail writes (guardrails v2 `PutRolePolicy` and the `idlab-admin` removal by `.../adm-labops@...`; the operator's AccessDenied attempts) and the operator's `simulate-principal-policy` results | 20 admin-path writes explicitDeny for the operator, reads allowed; AWS admin reached only through a 2-hour PIM activation | That root is protected (no MFA device yet; owner step); anything about sessions other than the one recorded |
| [`azure-guardrails/20261106T0726Z/`](azure-guardrails/20261106T0726Z/) | **Read-only checks + a plan, nothing applied** (2026-11-06, capture log E106): the real Owner `roleDefinitionId` format, the two standing Owners, Key Vault protection, Contributor's policy-write exclusion, no Azure PIM eligibilities, and the targeted plan of `modules/azure-guardrails` | Plan: 4 to add, 0 to change, 0 to destroy, both guardrails in Audit | That the policies evaluate as written in Azure, what Audit reports, and whether a PIM Owner activation is judged: all after an apply |
| [`aws-audit-baseline/20261106T0720Z/`](aws-audit-baseline/20261106T0720Z/) | **Read-only checks + a plan, nothing applied** (2026-11-06, capture log E105): no CloudTrail trail and no Access Analyzer in 182002546409; the operator (guardrails v2) may stop or delete a trail and empty a bucket; the targeted plan of `aws/audit-trail.tf` + guardrails v3 | 9 to add, 1 to change, 0 to destroy; operator `iam:CreateServiceLinkedRole` explicitDeny (so the apply needs LabAdministrator) | That the trail delivers, that validate-logs passes, that v3 denies in practice: all after an apply |
| [`aws-session-manager/20261107T0113Z/`](aws-session-manager/20261107T0113Z/) | **RAN · tenant** (2026-11-07, capture log E125-E127): the AWS server path behind PIM (ADR 0025, Session Manager section). The shell as typed, the same shell as CloudWatch Logs stored it (Entra person as `userIdentity`), CloudTrail StartSession / TerminateSession / SendCommand events with their AccessDenied rows, and a shell held open across the PIM deactivation | Server with 0 ingress rules, no public IP, no key; shell only, tagged server only, own sessions only; new credentials refused ~9 min after the activation ended | That only PIM gets in: the lab operator also opened a shell (guardrails v4 built, not applied). That access ends at once: issued 1-hour credentials and an open shell outlived the activation until ended by hand; the 60-minute cap was configured, not observed |

[`drills/`](drills/README.md) is the break-glass drill log. It is an empty
template: no drill has been run, because no tenant exists.

## Tenant reports (`kpis/`, `nhi/`, `sod/`)

Run read-only against the tenant, app-only as the lab operator
(`lab/scripts/operator/op pwsh <script> -UseAzureCliToken`), each with a
hash file beside it:

| Folder | Script | What is public | Re-check |
|---|---|---|---|
| `kpis/<UTC>.json` (+ `-onepager.md`) | `08-Measure-KPIs.ps1`, `New-KpiOnePager.ps1` | KPI values and counts; per-object detail stays in `out/kpis/` | `shasum -a 256 -c <UTC>.json.sha256` |
| `nhi/<UTC>/nhi-summary.json` | `06-NHI-Inventory.ps1 -PublicSummaryDirectory` | counts by kind, severity, OWASP NHI id and finding id; the SHA-256 of each private `out/nhi_*` file | `shasum -a 256 -c SHA256SUMS` |
| `sod/<UTC>/` | `09-SoD-Report.ps1` | rule status and violations under pseudonyms (`U-` + hash prefix) | `shasum -a 256 -c manifest.sha256` |

The 2026-11-05 runs are capture-log E70 (NHI), E71 (SoD) and E72 (KPIs); the first evidence pack with all 7 records is E74.

## Re-checking a record

1. **Hashes.** Inside a record folder:

   ```bash
   shasum -a 256 -c SHA256SUMS    # Linux: sha256sum -c SHA256SUMS
   ```

   Every line must end in `OK`. All 14 record folders above passed this
   check on 2026-10-21 (UTC), after the Kusto record was added. For that
   record:

   ```bash
   cd lab/evidence/kusto/20261021T001217Z && shasum -a 256 -c SHA256SUMS
   ```

   prints 35 `OK` lines. To see whether a detection has changed since the
   run, compare `shasum -a 256 lab/kql/<rule>.kql` with that rule's entry in
   the record's `results.json` `inputs.rules`. On 2026-10-21 all 43 recorded
   inputs (22 rules, 21 harness and case files) still matched the tree.

2. **Content.** The harness that wrote a record can re-check it without
   Docker or a network (hashes, an all-PASS result, nothing secret-shaped in
   the files). From `lab/pam/`:

   ```bash
   test/e2e.sh --verify ../evidence/pam/<UTC>
   ./dr-drill.sh --verify ../evidence/pam-dr/<UTC>
   test/e2e-scale.sh --verify ../evidence/pam-scale/<UTC>
   test/e2e-dynamic-db.sh --verify ../evidence/dynamic-db/<UTC>
   test/e2e-midpoint.sh --verify ../evidence/midpoint/<UTC>
   ```

   All ten PAM, DR, scale, dynamic-database and midPoint records passed
   their verifier on 2026-10-20. Where a record carries a code fingerprint
   (`code.sha256sums`), the verifier also says whether `lab/pam` has changed
   since that run: a record proves the code it names, not the current tree.
   The Kubernetes, offline-tests and Kusto records have no verifier of their
   own; check their hashes. For the offline-tests record, `shasum -a 256 -c
   lab/evidence/offline-tests/<UTC>/code.sha256sums` from the repo root also
   shows whether any file it tested has changed since.

3. **Re-run.** The stronger check is to run the harness again from a fresh
   clone: `cd lab/pam && ./test/run-all.sh` (add `--scale` for the
   500-account run, `--publish` to write a new record here) and
   `bash lab/k8s/ci/pipeline.sh`. The Kusto run is
   `lab/monitoring/kusto-harness/run.sh --accept-eula`: read the emulator's
   licence in the harness README first, because passing the flag accepts it.

## What a hash does and does not show

- `SHA256SUMS` shows that the files in a folder still match each other as
  the harness wrote them (or, for the two records marked above, as they were
  re-sealed after a publication edit). It does not show when or where the
  run happened, or that it ran as described. The public repository is
  published as one commit, so a commit date only shows that a record existed
  by then: nothing here independently dates a run.
- Independent runs are the next step. Once the repository is public, the
  credential-free workflows run on GitHub's runners: `lab-tests.yml` (the
  Terraform, Pester, ITDR and shell tests), `k8s-identity.yml` (the kind
  pipeline) and `pam-harness.yml` (`lab/pam/test/run-all.sh` from a fresh
  clone, with no `.env` and no Docker volumes, on demand and nightly). Their
  run URLs, with GitHub's timestamps, will be listed here. None has run yet.
- A record covers its own run only. The offline totals quoted in the README
  (Terraform, Checkov, Pester, PSScriptAnalyzer, shellcheck, actionlint) and
  the PAM default-suite totals come from `offline-tests/20261020T235044Z/`.
  For the PAM suites other than the flow and the 500-account run, that
  record holds counts and run-all's console output, not each suite's own
  log.
- The records hold synthetic lab accounts and lab hostnames only: no
  secret, no tenant identifier, no public IP address.

## Configuration snapshots (`config-snapshots/`)

Where `Export-IdentityConfig.ps1 -Public` writes the tenant's configuration
as code sees it (Conditional Access, named locations, authentication
strengths and methods, PIM policies, consent / app-management /
cross-tenant policies, break-glass exclusion facts): one
`<UTC>.json` per export, normalised so an unchanged tenant gives the same
bytes, every object id and IP range hashed, no name, UPN or mailbox, plus
one `SHA256SUMS` for the folder (`shasum -a 256 -c SHA256SUMS`). The
reviewed first export is also committed as the baseline in
[`../config-baseline/`](../config-baseline/), and the nightly
`config-drift.yml` run compares each new export with it. Nightly exports
are run artifacts (30 days), not commits: a snapshot lands here only when a
person reviews it, normally in the same PR that updates the baseline.

Two reviewed exports are here (2026-10-29, the first baseline, and
2026-11-05, the baseline refresh after Microsoft's schema change, #113). A
fixture replay (`-Offline`) is refused in
this folder and goes to `out/config-snapshots/`; a snapshot without
`-Public` (object ids) is refused here too.

## Evidence pack from GitHub Actions (`evidence-pack.yml`)

The logbook, one click: *Actions → evidence-pack → Run workflow* on `main`.
GitHub signs in as **EVIDENCE** over OIDC (no secret), pulls the auditor
evidence pack out of Entra read-only (`Export-EvidencePack.ps1
-UseAzureCliToken`: PIM activations and live assignments, the PIM audit
trail, access-review decisions, Conditional Access, MFA registration,
privileged role holders, each SHA-256 hashed in `manifest.json`, plus a
`SUMMARY.md` whose every finding is computed from those records: standing
privileged holders outside break-glass, CA states, MFA registration, robot
accounts without an owner; counts only, never a fixed claim), and files
it in the WORM container as **new files only**
(`Publish-EvidencePack.ps1`). The job summary, for someone who is not an
identity engineer:

> **Evidence pack filed — 7 records, each fingerprinted**
> (one row per record with its entry count)
> Stored in the locked evidence store: nobody can change or delete these
> files for 2190 days. [Open the evidence store in the Azure portal]

"N days" is what the store itself reported for the files just uploaded
(the earliest retention expiry), never a configured number; while the
policy is still Unlocked the summary says an administrator could shorten
it. Every stored file is downloaded again and its SHA-256 compared: a
read-back that does not finish (time-out, expired sign-in) fails the run
as "could not be checked", never "filed". Technical details (store,
folder, every SHA-256, read-back result,
lock mode) are folded underneath. Counts only: no name, UPN, raw Graph
error or token, in the summary or the log. The pack files name people, so
they exist only in the job's temp folder (emptied after the job) and in the
private container, never as a GitHub artifact.

**Where it lands:** `evidence/evidence-packs/<UTC date>/<HHMMSS>Z-run<run id>-<attempt>/`:
the seven JSON records, `SUMMARY.md` and `manifest.json`, each blob with
metadata `sha256`, `runid` and `commit` (the commit whose companion
evidence the manifest hashed). Every file is checked against the manifest
before upload and downloaded and re-hashed after it. To re-check later,
download the folder and compare `shasum -a 256` with `manifest.json`.

**Who may write there:** EVIDENCE holds Storage Blob Data Contributor on
the evidence container only, with an ABAC condition that denies
`blobs/write` and `blobs/delete` there, so what is left is create-new
(`blobs/add/action`) and read. It cannot overwrite, re-tier or delete a
file, even one whose retention has expired (stricter than the operator's
E05 grant). Graph: six application read roles, nothing that changes the
tenant (`lab/terraform/modules/pipeline-identity/main.tf` lists each one's
use).

### One-time setup (an admin)

1. **Bootstrap apply** (local, as the tenant admin). In
   `lab/terraform/envs/bootstrap/terraform.tfvars`:
   ```hcl
   enable_evidence_pack          = true
   evidence_storage_account_name = "<envs/dev output evidence_storage_account_name>"
   ```
   ```bash
   cd lab/terraform/envs/bootstrap
   terraform plan -out evidence.tfplan   # expect: EVIDENCE app + SP + federated credential
                                         # (ref:refs/heads/main), 6 app role assignments,
                                         # 1 role assignment on .../containers/evidence (condition 2.0)
   terraform apply evidence.tfplan
   ```
2. **Consent check:** *Enterprise applications → EVIDENCE (gh-oidc evidence
   pack) → Permissions* shows the six read roles as *Granted*.
3. **Repository variable** (an identifier, not a secret; `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID` and `TF_EVIDENCE_STORAGE_ACCOUNT_NAME` exist
   already):
   ```bash
   gh variable set EVIDENCE_CLIENT_ID --body "$(terraform output -raw github_oidc_evidence_client_id)"
   ```
4. **Network.** The account's firewall admits only `TF_OPERATOR_IP_RANGES`,
   and a GitHub-hosted runner is outside it: there the upload is refused
   ("the evidence store refused the connection") after the records were
   collected. Pick one:
   - a **self-hosted runner** on an admitted network (*Settings → Actions →
     Runners → New self-hosted runner*, with `pwsh` and `az` installed), then
     `gh variable set EVIDENCE_RUNNER --body <its label>`. The job keeps its
     Azure CLI profile and the Graph modules in its own temp folder, so the
     machine's own sign-ins and modules are not touched;
   - **private networking for GitHub-hosted runners** (GitHub Team or
     Enterprise: an Azure VNet for the runners plus the module's
     `enable_private_endpoint`).
   Opening the firewall to GitHub's address ranges is not an option: they
   are far wider than the `/24` the module accepts.
5. **First run:** confirm the summary, then the role assignment as evidence
   (like E05): `az role assignment list --scope <evidence_container_id> --assignee <EVIDENCE service principal id> -o json`
   shows the condition and `conditionVersion: 2.0`.

*verify (first real run):* that a new blob uploads with only
`blobs/add/action` left by the condition, and that `az storage blob show`
reports the inherited account policy per blob (`immutabilityPolicy`); if it
does not, the summary says the lock could not be read back instead of
printing a number. Whether `Directory.Read.All` is needed for the expanded
principals on the role rows: a 403 shows as a failed record in the manifest.

## Not here yet

- Sentinel evidence for the detections: a rule deployed to a workspace,
  scheduled, and firing an incident on real tenant data. The Kusto record
  above stops at the engine.
- Drill rows (`drills/`) and a Zero Trust Assessment "after" (the
  assessment needs an interactive admin sign-in; see
  [`../docs/evidence-capture-plan.md`](../docs/evidence-capture-plan.md) E55).
- `out/` is gitignored. Anything with identity detail (names, UPNs, object
  ids, raw tenant exports) goes there and never into a record.
