# Evidence: hashed run records

This folder holds the lab's **hashed run records**: what a local run
actually did, written by the harness itself (`offline-tests/` and `k8s/`: by
a wrapper around the repository's own commands), with a `SHA256SUMS` file in
every record folder. They are not all the same kind of evidence:

- `midpoint/`, `dynamic-db/`, `pam/`, `pam-dr/`, `pam-scale/` and `k8s/` are
  **RAN · harness**: run end to end on local Docker or a kind cluster on my
  laptop, with synthetic accounts and data.
- `kusto/` is **RAN · harness** for the 22 KQL detections: they ran on the
  Azure Data Explorer Kusto emulator, a local container, against synthetic
  tables and events, with Sentinel's `_GetWatchlist` shimmed. It is a real
  KQL engine, but it is **not a Log Analytics workspace, not Sentinel and
  not a tenant**: no rule has been scheduled in Sentinel or fired.
- `offline-tests/` is the evidence for **BUILT**: offline checks (validate,
  lint, tests with every Terraform provider and Graph call mocked). Only one
  row in each of its records, `pam-run-all` (the PAM runner's default suites
  on local Docker), is **RAN · harness**.

**RAN · tenant: none.** No Microsoft tenant exists yet, so nothing here is
evidence of Entra, Azure or Sentinel behavior. The Kusto record shows how
the KQL engine evaluates the rules, not how Sentinel schedules them or what
a tenant's logs contain.

Status words, used the same way everywhere in this repository:
**RAN · tenant** (run against a real Microsoft tenant: nothing yet),
**RAN · harness** (run end to end on my laptop in Docker, a kind cluster or
a local KQL engine, or in Docker on a GitHub runner, against stand-ins, with
synthetic data), **BUILT** (code
that passes offline tests with every cloud call mocked, never applied) and
**DESIGNED** (documented, not built). The [README](../../README.md) carries
the same key.

## Records

All records date from 2026-10-20 (UTC) except three from 2026-10-21: an
offline-tests run that finished at 00:06 UTC, the Kusto run, which started at
00:12 UTC, and the newest offline-tests run, from 07:47 to 08:01 UTC. Each
folder name is the run's UTC start time.

| Folder | What ran | Result | What it does NOT prove |
|---|---|---|---|
| [`midpoint/20261020T162116Z/`](midpoint/20261020T162116Z/) | A T2 certification campaign in Evolveum midPoint 4.10 (the SailPoint / Saviynt stand-in), driven over its REST API by `lab/pam/midpoint/run-campaign.sh` | Campaign closed. 7 items: 4 accepted, 2 revoked (one an SoD conflict midPoint flagged first), 1 left unanswered on purpose and removed. Completion 85.7% (T2 target 95%, missed by design), revocation 33.3%, rubber-stamp rate not measurable (no reviewer had 10 items). The reviewers' decisions, as midPoint recorded them, are in [`decisions.csv`](midpoint/20261020T162116Z/decisions.csv). The midPoint test suite's 91 checks are counted in `offline-tests/20261021T074732Z/`, not here | Reviewer behavior: a script records each decision inside the assigned reviewer's own security context, milliseconds apart; no reviewer signed in. Users are mock-HR personas, not Entra users. No Entra access review has run |
| [`midpoint/20261020T152623Z/`](midpoint/20261020T152623Z/) | An earlier run of the same campaign | Same outcomes and KPIs | Written before the ADR 0012 rubber-stamp threshold (a minimum of 10 items per reviewer): its `rubber_stamp_flagged` list uses the superseded definition. The files are left unchanged |
| [`dynamic-db/20261020T163436Z/`](dynamic-db/20261020T163436Z/) | Vault's database secrets engine against PostgreSQL (`lab/pam/test/e2e-dynamic-db.sh`) | 60 passed, 0 failed: a new login per request, `SELECT` on schema `clinical` only, 1-hour lease capped at 4 hours; revoking the lease ends a live session and drops the role | One synthetic database with its own Vault, not joined to the AD stack. No production database, no PAM product |
| [`pam/20261020T220031Z/`](pam/20261020T220031Z/) (latest) | The AD-dependent PAM flow against a Samba AD domain controller (`lab/pam/test/e2e.sh`, from `test/run-all.sh --publish`): discovery, onboarding, dependency-gated rotation, reconciliation, ticket-gated per-person check-out with Tier-0 dual control, recorded SSH (Vault SSH CA), a recorded RDP session to a Linux xrdp stand-in, OIDC-mode lock-out, the 3-node HA cluster, the DR drill, a rolling upgrade and the Conjur OSS check | 284 passed, 0 failed. Reconciliation GAP 0, ORPHAN 0 ([`reconcile.md`](pam/20261020T220031Z/reconcile.md)). `run.log` line 176: `conjur-demo.sh`, the approved job reads its secret, an unapproved one gets 403. `rdp-recording.json`: the session recording's format check and its playback through Guacamole's History API. `code.sha256sums`: the 90 `lab/pam` files the run used. One harness file changed after it: `test/e2e.sh` (a fix for a first run on a fresh stack; see `offline-tests/20261020T230108Z/`), so its verifier now notes `test/e2e.sh` as changed | Windows behavior: Samba is not Windows Server, and the RDP target is a Linux container, not DC01. Tickets and approvals come from a mock ServiceNow Table API. Everything ran on one Docker host. Operators sign in to Guacamole with local passwords (Entra sign-in is BUILT, not run) |
| [`pam/20261020T204851Z/`](pam/20261020T204851Z/), [`pam/20261020T184052Z/`](pam/20261020T184052Z/) | Earlier runs of the same flow | 241 passed, 0 failed each; GAP 0 | They predate dual control and the RDP step. `184052Z` has no code fingerprint, so it does not name the script version it ran |
| [`pam-dr/20261020T220031Z/`](pam-dr/20261020T220031Z/) (latest), [`20261020T204851Z/`](pam-dr/20261020T204851Z/), [`20261020T184052Z/`](pam-dr/20261020T184052Z/) | The timed Vault DR drill, from the same runs as the `pam/` records: snapshot, destroy all three nodes and their volumes, rebuild, restore | PASS each against a 300 s RTO target: RTO 42.1 s, 32.5 s and 40.5 s; RPO 2.2 s each ([`dr-drill.md`](pam-dr/20261020T220031Z/dr-drill.md)) | The vault that matters: the drilled cluster is a separate rehearsal cluster holding test markers (a 16 KB snapshot: one KV marker and one policy), not the single-node vault that holds the PAM flow's AD credentials. Restoring rotated credentials and reconciling password drift after a restore (`reconcile.sh --verify --strict`) is not drilled (ADR 0019). A planning RPO: the 2.2 s is set by the drill's own pause between the snapshot and the disaster (production RPO is the snapshot interval). A transit-engine auto-unseal stands in for Azure Key Vault; one Docker host, no availability zones, no TLS |
| [`pam-scale/20261020T193913Z/`](pam-scale/20261020T193913Z/) | `lab/pam/test/e2e-scale.sh` (`run-all.sh --scale`): 500 synthetic privileged accounts plus 250 ordinary staff in a Samba AD DC, through the real discover → onboard → dependency check → rotate → reconcile scripts, every stage timed | 79 passed, 0 failed. 515 privileged accounts discovered (the 500 plus 15 from the base layout) in 2.0 s. Onboarding vaulted 257 of the 500, held 123 on dependencies and skipped 120 documented exceptions. At reconciliation ([`reconcile.md`](pam-scale/20261020T193913Z/reconcile.md)): 263 vaulted (the 257 plus 6 base-layout accounts; all rotated within policy), 128 documented exceptions, 124 held on unresolved dependencies; GAP 0, ORPHAN 0. 25 sampled accounts rotated through `rotate.sh`: the new password binds and the old one is rejected on 25 of 25; 10 dependency-blocked accounts were refused. The five pipeline stages (discovery, onboarding, dependency check, rotation, reconcile) took 139 s in total (`pipeline_seconds`); the seeding and an idempotence re-run (25.2 s) are not counted in it | A real estate: the population and its dependencies are generated from a fixed seed. Reconcile's bind check over every vaulted account (`--verify`) was not run; the 25 rotated accounts were bind-tested. The timings belong to one laptop |
| [`offline-tests/20261021T074732Z/`](offline-tests/20261021T074732Z/) (latest) | Every offline check on a copy of the working tree (its own [README](offline-tests/20261021T074732Z/README.md) has the table): Terraform fmt / validate / test in all 18 directories, Checkov with its graph checks (PyPI 3.3.20) on `lab/terraform` and on `lab/k8s/manifests`, PowerShell parse + PSScriptAnalyzer, the ScubaGear fixture's pinned hashes, the lab Pester suite on Pester 5.7.1 and 6.2.0, ITDR Pester, shellcheck, actionlint, JSON, the Splunk render check, the ingest test, the Kusto harness's offline `check`, the tests of the skip-or-run gate in front of every Azure sign-in job, and the hashes and verifiers of the other records. Then `lab/pam/test/run-all.sh` (default suites, no `--publish`, run `20261021T075546Z`) on the same `lab/pam` | All 21 suite rows PASS: `terraform validate` in all 18 directories; `terraform test` 326 passed, 0 failed (303 in the Entra, Azure and AWS roots and modules, 23 in the three Kubernetes roots); Checkov 61 passed, **0 failed**, 15 skipped on `lab/terraform` (each skip inline with its reason, listed in `checkov-skips.txt`; the committed HEAD gives 56 passed, 4 failed, 12 skipped, as GitHub's first runs did) and 89 passed, 0 failed on `lab/k8s/manifests`; lab Pester 1074 passed, 0 failed, 0 skipped on both versions, ITDR 284 (292 in CI's step, with the dependency-scan tests); PSScriptAnalyzer 0 errors (19 warnings in `lab/scripts/powershell`; lab-wide, 87 files: 101 warnings, 727 information); `shellcheck -x` 0 findings on 41 scripts; actionlint 0 errors on 6 workflows; 63 JSON files parse; the Splunk searches match the 22 detections; ingest test 30 passed; Kusto check 223 cases over 22 rules; Azure sign-in gate tests 16 passed; the other 14 records hash-checked OK and the 10 verifiers PASSED; PAM 8/8 suites, 610 passed, 0 failed, 1 skipped (498 end to end in Docker, 112 offline unit tests; [per suite below](#the-pam-runners-eight-suites)). `code.sha256sums`: the 514 `lab/` and `.github/` files it tested | Anything in a tenant: every provider and Graph call is mocked, so the offline rows are BUILT evidence, not RAN · harness. No KQL ran on an engine (the Kusto check validates case files only). That GitHub's runners agree: the Checkov fixes and the new Azure sign-in gate have not run there yet. That the `nightly-report` NetworkPolicy is enforced: Checkov reads the manifest, and the Kubernetes pipeline was not part of this run. For the PAM suites it holds the counts and run-all's console output, not the per-suite logs (the harness keeps those gitignored). Not a fresh clone: the PAM run reused the stopped shared stack's volumes and `.env` (the fresh-clone runs are GitHub's nightly ones, [below](#runs-on-githubs-runners)) |
| [`offline-tests/20261020T235044Z/`](offline-tests/20261020T235044Z/) | The same checks one run earlier (PAM run `20261021T000019Z`), without the `checkov-k8s` and Azure sign-in gate rows, and before the Checkov graph-check fixes, the Key Vault subnet's NSG and its test, the `nightly-report` NetworkPolicy and the tenant-day runner's tests | All 19 suite rows PASS: `terraform test` 325 passed (302 in the Entra, Azure and AWS roots and modules, 23 in the Kubernetes roots); Checkov 46 passed, **0 failed**, 10 skipped; lab Pester 917 on both versions, ITDR 284; PSScriptAnalyzer 0 errors; shellcheck 0 findings on 41 scripts; actionlint clean on 6 workflows; PAM 8/8 suites, 610 passed, 0 failed, 1 skipped. `code.sha256sums`: the 503 files it tested | The same limits as the newest record (no tenant, no KQL engine, no PAM per-suite logs, not a fresh clone). Its Checkov row came from a Checkov install without its graph checks ([below](#checkov-in-these-records)), so it shows 0 failed where GitHub's Checkov found 4 |
| [`offline-tests/20261020T230108Z/`](offline-tests/20261020T230108Z/) | The same checks one run earlier (PAM run `20261020T230641Z`), before the Checkov inline skips, the NTDS disk fix and the wording fixes in this pass | All 18 suite rows PASS: `terraform test` 325 passed; Checkov 8 failed, all the then-documented baseline (0 new); lab Pester 917 on both versions, ITDR 284; PSScriptAnalyzer 0 errors; shellcheck 0 findings on 41 scripts; PAM 8/8 suites, 610 passed, 0 failed, 1 skipped | As above, including the Checkov caveat. Its `results.json` labels the whole run RAN · harness: only its `pam-run-all` row is. Edited once after the run, for publication (each file's hash from before path normalization, the build source's commit id and eight random 32-hex temp names were removed or normalized), then re-sealed; its README lists the edits. No count or verdict changed |
| [`kusto/20261021T001217Z/`](kusto/20261021T001217Z/) | The 22 `lab/kql` detections on a real KQL engine: the Azure Data Explorer Kusto emulator (`lab/monitoring/kusto-harness/run.sh --accept-eula`, run by the operator after accepting Microsoft's emulator license), a local amd64 container under Rosetta with the image pinned by digest. One database with the 7 tables the rules read (Learn's column types, only the columns the rules use) and 2 watchlist store tables. Each of 223 cases clears the tables, ingests its own synthetic rows, runs the rule as `modules/monitoring` renders it and checks the rows; plus 13 engine-semantics probes. Files: `results.json`, `run.log`, `setup.kql`, 31 rendered queries, `guids.txt` (none) and `SHA256SUMS` over all 35 | **PASS**: rules 22/22 passed, 0 not run; cases PASS 223 (131 positive, 92 negative), FAIL 0, ERROR 0, XFAIL 0, XPASS 0. The three CODE NEEDED fixes passed their cases. **Imports skipped 12**: rows of the offline KqlLite fixture file that are not whole raw table rows (8 stage-level rows, 4 with derived-`let` `joinRows`), so they were never sent to the engine and are not among the 223; each is listed with its reason in `skippedImports`, and hand-written raw-event cases cover the same situations. One probe (`negative-array-index`) did not answer: its own query has a syntax error. The sha256 of every rule and case file it ran is in `results.json` `inputs` | Anything in Sentinel or Log Analytics: the emulator is **not a Log Analytics workspace, not Sentinel and not a tenant**. No analytics rule was scheduled, so no query period, lookback, entity mapping, grouping, suppression or incident was tested. No real sign-in, audit or Windows event was read: every row is synthetic. The Sentinel-only function the rules call, `_GetWatchlist`, is shimmed (3 variants, in `shims.kql` and `results.json` `shims`), and Sentinel's rejection of a rule over a table that has never received data is not emulated. The SPL twins did not run. Under the emulator's license the record holds no timings, so it says nothing about query performance |
| [`k8s/20261020T202112Z/`](k8s/20261020T202112Z/) | One full run of `lab/k8s/ci/pipeline.sh` on a throwaway kind cluster (its own [README](k8s/20261020T202112Z/README.md) has the stage table) | Exit 0: 12/12 stages, teardown PASS, end-to-end 64/64 | AKS or Entra Workload ID (that mapping is BUILT, never applied), and the GitHub Actions job (it failed both runs at its Checkov stage; see [Runs on GitHub's runners](#runs-on-githubs-runners)). The `nightly-report` NetworkPolicy: it was added after this run, so it is not in the record's code list (BUILT; see [`lab/k8s/README.md`](../k8s/README.md#what-each-piece-proves)). Local paths in the logs were normalized before publishing. After the run, each file's hash from before that normalization and the build source's commit id were removed for publication and the folder re-sealed; its README lists the edit. No result or log line changed |

Markdown files updated after `offline-tests/20261021T074732Z/`, to quote its
numbers, differ from its `code.sha256sums`. One code file does too:
`lab/scripts/powershell/tests/Invoke-BreakGlassDrill.Tests.ps1`, where a
test's sample IPv6 address moved into the documentation range
(`2001:db8::/32`) after the new IPv6 release gate flagged it. The assertion
is unchanged.

[`drills/`](drills/README.md) is the break-glass drill log. It is an empty
template: no drill has been run, because no tenant exists.

### The PAM runner's eight suites

`offline-tests/20261021T074732Z/` counts one run of `lab/pam/test/run-all.sh`
(run `20261021T075546Z`, default suites): 610 checks passed, 0 failed,
1 skipped, per suite in its `pam-results.tsv`. The three nightly
`pam-harness.yml` runs on GitHub's runners, each from a fresh clone, report
the same counts, suite by suite ([below](#runs-on-githubs-runners)).

- **498 ran end to end in Docker:** the PAM flow against a Samba AD domain
  controller (284, including Tier-0 dual control and a recorded RDP session
  to the Linux xrdp stand-in for the domain controller), the midPoint review
  (91), dynamic database credentials (60) and the Vault audit feed for the
  PAM anomaly detection (63, plus 1 skipped: no local Splunk).
- **112 are offline unit and fixture tests:** dual control against a local
  ServiceNow mock (45), the session-recording format check (29), the audit
  ingest script (30) and the dependency-scan matching logic (8; the scan
  itself, `Get-AccountDependencies.ps1`, has never run on a Windows host).

The PAM flow, the 500-account run, the DR drill, the Kubernetes run and the
Kusto run have their own records, above. For the other suites the record
holds the counts and the runner's console output; per-suite logs are not
published (they name lab accounts), so re-run the suites to check them.

### Checkov in these records

The two earlier offline-tests records' Checkov rows came from a Homebrew
build of Checkov 3.3.20 that lacked Checkov's graph checks. GitHub's Checkov
has them and found 4 failed checks those rows do not show
([terraform-plan, below](#runs-on-githubs-runners)). The newest record,
`offline-tests/20261021T074732Z/`, runs PyPI Checkov 3.3.20 with its graph
checks (196 Terraform, 6 Kubernetes). After the fixes it gives 61 passed,
0 failed, 15 skipped on `lab/terraform` (every skip and its reason in its
`checkov-skips.txt`) and 89 passed, 0 failed on `lab/k8s/manifests`; on the
committed HEAD, before the fixes, the same Checkov gives GitHub's 56 passed,
4 failed, 12 skipped. The CI image's own Checkov (3.3.3) re-runs on the next
push; until then its result on the fixed tree is not recorded.

## Runs on GitHub's runners

The public repository's workflows run on GitHub's hosted runners from a
fresh checkout, so GitHub's run page dates each run and names the commit it
tested. Nothing from these runs is copied into a record folder: the run page
and its log are the evidence. Every run of the repository's workflows so far
is listed, red ones included (checked 2026-10-24, 00:33 UTC). The four
Dependabot pull requests are open, not merged.

| Workflow | Run | Result, as the run log shows it | What it does NOT prove |
|---|---|---|---|
| `lab-tests.yml`: Terraform fmt, validate and mocked tests; the lab Pester suite and PSScriptAnalyzer; the ITDR tests; the Vault audit ingest test and the Splunk render check | [39523030602](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523030602): push to `main` (the published commit), 2026-10-21, 00:43 to 00:48 UTC | **Passed.** `terraform validate` in 18 directories; `terraform test` 325 passed, 0 failed; lab Pester 917 passed, 0 failed, 0 analyzer errors; the ITDR step 292 passed, 0 failed (the ITDR suite and the dependency-scan tests together); the Vault audit ingest test passed; the Splunk saved searches match the 22 SPL detections. These are the counts of the commit the run tested; the working tree now measures 326 Terraform runs and 1074 Pester tests (`offline-tests/20261021T074732Z/`), and the ITDR step is still 292 | Anything in a tenant: every provider and Graph call is mocked, so this is BUILT evidence, run on a second machine, not RAN · harness |
| `lab-tests.yml` on the Dependabot pull requests | Four runs, 2026-10-21 | Passed on the actions bump ([39523281308](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523281308)) and the Vault provider bump ([39523266718](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523266718)). Failed on the two that bump azurerm to 5.x ([39523190994](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523190994), [39523246384](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523246384)): `terraform init` failed in the root each one bumps (`envs/bootstrap`, `envs/dev`); the Pester job passed | The tree has not moved to azurerm 5.x |
| `k8s-identity.yml`: the kind pipeline | Two runs on Dependabot pull requests, 2026-10-21 ([39523266695](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523266695), [39523281383](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523281383)) | **Failed both runs at stage 3/12, Checkov (CKV2_K8S_6):** the nightly-report pod had no NetworkPolicy (Kubernetes manifests: 88 passed, 1 failed). Preflight and the 23 Terraform test runs passed first. Fixed in the tree (the NetworkPolicy; Checkov 89 passed, 0 failed in `offline-tests/20261021T074732Z/`), not re-run | No kind cluster has been built on GitHub's runners yet |
| `terraform-plan.yml`: TruffleHog, Checkov, `terraform plan` | Four runs on Dependabot pull requests, 2026-10-21 ([39523191093](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523191093), [39523246316](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523246316), [39523266661](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523266661), [39523281349](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523281349)) | TruffleHog passed. **Checkov 56 passed, 4 failed, 12 skipped** in all four (the action's image 3.3.3; 3.3.29 on the actions bump): CKV_AZURE_119 on the `dc-vm` and `intune-vm` network interfaces, CKV2_AZURE_21 on the evidence container, CKV2_AZURE_31 on the Key Vault private-endpoint subnet. The plan job stopped at the Azure sign-in (`azure/login`: no tenant wired). Fixed in the tree (61 passed, 0 failed, 15 skipped in `offline-tests/20261021T074732Z/`), not re-run | No plan has run against a tenant |
| `terraform-apply.yml` | [39523030605](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523030605): push to `main`, 2026-10-21, 00:43 UTC | Waiting at the `prod` reviewer gate since then; no step has run | No apply has run against a tenant |
| `ai-review.yml`: the advisory AI review | Three runs on Dependabot pull requests, 2026-10-21 | Failed at its Azure sign-in (no tenant and no Azure OpenAI reviewer wired) | — |
| `pam-harness.yml`: `lab/pam/test/run-all.sh` from a fresh clone, with no `.env` and no Docker volumes, on demand and nightly | Three nightly runs on `main` (the published commit): [39583567447](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39583567447), 2026-10-21, 10:18 to 10:27 UTC; [39762149772](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39762149772), 2026-10-22, 10:18 to 10:28 UTC; [39937464414](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39937464414), 2026-10-23, 10:12 to 10:20 UTC | **Passed all three:** 610 passed, 0 failed, 1 skipped; 8 suites passed (`scale` not selected). Per suite, the same in all three: e2e 284, midpoint 91, dynamic-db 60, vault-anomaly 63 plus 1 skipped, itsm-dual-control 45, recording-format 29, ingest 30, dependency-scan 8 | Anything in a tenant or on Windows: these are containers on a GitHub runner (Samba AD, the Linux RDP target, the ServiceNow mock), so this is RAN · harness, not RAN · tenant. They ran the published commit, not the current tree |

`terraform-plan.yml` and `terraform-apply.yml` need a tenant and its OIDC
identities: until one is wired, their Azure jobs skip with a notice (the
first Dependabot runs, before that change, stopped at the Azure sign-in).
`ai-review.yml` skips the same way while no reviewer is wired. Neither plan
nor apply has run against a tenant. These workflow changes are in the tree
and have not run on GitHub yet.

## Re-checking a record

1. **Hashes.** Inside a record folder:

   ```bash
   shasum -a 256 -c SHA256SUMS    # Linux: sha256sum -c SHA256SUMS
   ```

   Every line must end in `OK`. All 15 record folders above passed this
   check on 2026-10-24 (UTC). For the Kusto record:

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
   their verifier on 2026-10-20, and again on 2026-10-21 in
   `offline-tests/20261021T074732Z/`. Where a record carries a code fingerprint
   (`code.sha256sums`), the verifier also says whether `lab/pam` has changed
   since that run: a record proves the code it names, not the current tree.
   The Kubernetes, offline-tests and Kusto records have no verifier of their
   own; check their hashes. For the offline-tests record, `shasum -a 256 -c
   lab/evidence/offline-tests/<UTC>/code.sha256sums` from the repo root also
   shows whether any file it tested has changed since.

3. **Re-run.** The stronger check is to run the checks again, from a fresh
   clone. None of them needs a tenant or a cloud credential. Each line runs
   from the repository root:

   ```bash
   # Terraform: validate + mocked tests (HashiCorp Terraform 1.16.5, not tofu)
   cd lab/terraform/modules/pim && terraform init -backend=false && terraform test

   # PowerShell: PSScriptAnalyzer + every Pester suite, Graph mocked
   pwsh lab/scripts/powershell/tests/Invoke-LabTests.ps1

   # PAM: every harness from one entry point (Docker; about 6 minutes once the images are pulled)
   cd lab/pam && ./test/run-all.sh   # --scale adds the 500-account run, --publish writes a new record here

   # Kubernetes (optional, self-contained, nothing in it talks to Azure or Entra):
   # builds a kind cluster, tests it and deletes it
   bash lab/k8s/ci/pipeline.sh
   ```

   The KQL rules run on the Kusto emulator with
   `lab/monitoring/kusto-harness/run.sh --accept-eula`: read the emulator's
   license in the harness README first, because passing the flag accepts it.
   `.github/workflows/lab-tests.yml` runs the Terraform and PowerShell checks
   with no credential on every pull request and every push to `main` (the
   badge on the README), and `pam-harness.yml` runs the PAM runner from a
   fresh clone on demand and nightly. The Kubernetes segment's design and
   limits are in [`lab/k8s/README.md`](../k8s/README.md); each folder's
   README has the details of its own checks.

## What a hash does and does not show

- `SHA256SUMS` shows that the files in a folder still match each other as
  the harness wrote them (or, for the two records marked above, as they were
  re-sealed after a publication edit). It does not show when or where the
  run happened, or that it ran as described. The public repository is
  published as one commit, so a commit date only shows that a record existed
  by then: nothing here independently dates a run.
- Independent runs date themselves: the workflows on GitHub's runners are
  listed, with their run pages, under
  [Runs on GitHub's runners](#runs-on-githubs-runners). So far `lab-tests.yml`
  has passed there on `main`, and the PAM harness workflow has passed three
  nightly runs from a fresh clone; the Kubernetes workflow stopped at its
  Checkov stage.
- A record covers its own run only. The local offline totals quoted in the
  README and here (Terraform, Checkov, Pester, PSScriptAnalyzer, shellcheck,
  actionlint) and the local PAM default-suite totals come from
  `offline-tests/20261021T074732Z/`, the Checkov counts after the graph-check
  fixes included. For the PAM suites other than the flow and the 500-account
  run, that record holds counts and run-all's console output, not each
  suite's own log.
- The records hold synthetic lab accounts and lab hostnames only: no
  secret, no tenant identifier, no public IP address.

## Not here yet

- Sentinel evidence for the detections: a rule deployed to a workspace,
  scheduled, and firing an incident on real tenant data. The Kusto record
  above stops at the engine.
- Splunk: no SPL search has run. The Splunk container is BUILT and has
  never been started.
- A break-glass drill: none has run (no tenant), so `drills/` is empty.
- Tenant evidence (`kpis/`, `assessments/`, `sod/`, drill rows): written
  during the tenant run, as planned in
  [`../docs/evidence-capture-plan.md`](../docs/evidence-capture-plan.md),
  which also says what each day captures. Tenant KPI values, Entra review
  outcomes and break-glass drill times will be added only from that run;
  until then the documents use placeholders such as
  `<measured: HR-to-disable minutes>`.
- `out/` is gitignored. Anything with identity detail (names, UPNs, object
  ids, raw tenant exports) goes there and never into a record.
