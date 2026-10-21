# Offline test run 20261020T235044Z

One run of every offline check in the repository, on a copy of the working
tree, followed by the PAM harness's default suites on local Docker.
`code.sha256sums` lists the 503 files under `lab/` (except `lab/evidence/`)
and `.github/` exactly as they were tested: it is the fingerprint to check a
tree against.

**What kind of evidence this is.** Every row except the last is **BUILT**
evidence: offline checks, with every Terraform provider mocked (`terraform
test`) and every Graph and `az` call in the PowerShell suites a Pester mock.
Only the last row, `pam-run-all`, is **RAN · harness**: the PAM suites on
local Docker against a Samba AD domain controller. **RAN · tenant: none.** No
Microsoft tenant exists. `results.json` gives each row's `evidence_level`.

**Result: all 19 suite rows PASS.**
The folder is named for 23:50:44Z on 2026-10-20, when the wrapper made the
tested copy and took the Checkov baseline at the committed HEAD. The offline
suites ran 23:50:58Z to 23:59:14Z, and the PAM harness from 00:00:19Z to
00:06:33Z on 2026-10-21.

| Suite | Command (short form; full command in `results.json`) | Result |
|---|---|---|
| terraform-fmt | `terraform fmt -check -recursive lab/terraform` | PASS, exit 0 |
| terraform | in each of 18 directories: `init -backend=false` (`-lockfile=readonly` on the committed root locks), `validate`, `test` (`-var-file=lab.tfvars` where present) | 18/18 init and validate; **325 passed, 0 failed** |
| checkov | `checkov -d lab/terraform --framework terraform` (3.3.20) | 46 passed, **0 failed**, 10 skipped. Each skip is an inline `#checkov:skip` with its reason (`checkov-skips.txt`). The committed HEAD, before those skips, fails 8 |
| ps-parse | PowerShell parser on every `lab/**/*.ps1` | 83 files, 0 parse errors |
| ps-analyzer (all of `lab/`) | PSScriptAnalyzer 1.25.0 on the same 83 files | **0 errors**, 101 warnings, 693 information |
| scuba-fixture | `Get-ScubaSample.ps1`: the ScubaGear v1.8.0 sample against its pinned SHA-256 hashes (CI fetches it before the Pester suite) | 3 of 3 files verified, nothing downloaded |
| pester-lab 5.7.1 | `Invoke-LabTests.ps1 -CI` with Pester 5.7.1 (CI's pin) | **917 passed, 0 failed, 0 skipped**; its analyzer pass (`lab/scripts/powershell`): 0 errors, 19 warnings |
| pester-lab 6.2.0 | the same with Pester 6.2.0 | **917 passed, 0 failed, 0 skipped**; 0 errors, 19 warnings |
| pester-itdr (CI step) | `Itdr.Tests.ps1` + `lab/pam/test/Get-AccountDependencies.Tests.ps1` (Pester 5.7.1) | 292 passed, 0 failed |
| pester-itdr only | `Itdr.Tests.ps1` alone | **284 passed**, 0 failed |
| shellcheck | `shellcheck -x` from the repo root on the 41 `lab/**/*.sh` files, all severities | 41 files, 0 findings |
| actionlint | `actionlint -verbose` (1.7.12) | 6 workflows, 0 errors |
| json-parse | `json.load` on every git-trackable `*.json` under `lab/` and `.github/` | 61 files, 0 errors |
| splunk-render-check | `lab/splunk/render-savedsearches.sh --check` | 22 detections in sync |
| ingest test | `lab/scripts/monitoring/tests/ingest-vault-audit.test.sh` | 30 passed, 0 failed |
| kusto-harness-check | `harness.py check` (offline validation only) | 223 cases over 22 rules valid. **No KQL ran on an engine**: the emulator run waits for the operator to accept Microsoft's licence. There is no Kusto record, so there was nothing for a `--verify` |
| evidence hashes | `shasum -a 256 -c SHA256SUMS` in every existing record folder | 12/12 OK |
| record verifiers | each harness's `--verify` on its records | 10/10 PASSED (offline, no Docker) |
| pam-run-all | `cd lab/pam && ./test/e2e.sh --cleanup; ./test/run-all.sh` (no `--publish`, no `--scale`) | **8/8 suites, 610 passed, 0 failed, 1 skipped** (run id `20261021T000019Z`) |

Terraform by directory (`terraform.tsv`): `envs/dev` 13, `envs/bootstrap` 3,
`aws` 7, `k8s/platform` 5, `k8s/identity` 11, `k8s/aks-mapping` 7; modules
`apps` 31, `conditional-access` 71, `dc-vm` 11, `entitlement` 26,
`entra-diagnostics` 7, `evidence-store` 13, `groups` 4, `intune-vm` 41,
`keyvault` 6, `monitoring` 32, `pim` 32, `pipeline-identity` 5. That is 302
in the Entra, Azure and AWS directories plus 23 in the Kubernetes roots. No
provider was downloaded: every `init` reused providers already installed.

PAM suites (`pam-results.tsv`). End to end in Docker, 498: e2e 284, midpoint
91, dynamic-db 60, vault-anomaly 63 + 1 skipped (the Splunk step: no local
Splunk). Offline unit and fixture tests, 112: itsm-dual-control 45 (against
the ServiceNow mock run locally), recording-format 29, ingest 30 and
dependency-scan 8 (the scan's matching logic in Pester; the scan itself has
never run on a Windows host).

How the PAM run started. No container was running (`environment.txt`): the
shared stack had been stopped earlier, with its volumes and `.env` kept. So
the pre-run `./test/e2e.sh --cleanup` exited 1
(`logs/pam-e2e-cleanup-before.log`: "Vault did not come up": there was
nothing running to clean), and `run-all.sh` then started the stack with
`pam-up.sh`. The e2e suite's own log (gitignored) shows the Samba DC volume
created fresh and `vault-onboard-ad.sh` passing its first-run checks. This
is not a fresh clone: the generated `.env` and the other volumes were
reused.
`environment.txt` confirms that the `lab/pam` the harness ran (93 files) is
byte-identical to the tested copy.

## Changed in the tree since the previous record

`offline-tests/20261020T230108Z/` is the run before this one. Since it:

- **Checkov.** The 8 failed checks of the old documented baseline are gone:
  seven have an inline `#checkov:skip` with a reason, and one is fixed. The
  NTDS data disk in `modules/dc-vm` now has `public_network_access_enabled =
  false` and `network_access_policy = "DenyAll"`, and `dc-vm`'s tests assert
  both (still 11 runs: the assertion was added to an existing run).
  `terraform-plan.yml` runs Checkov with `soft_fail: false`.
- **A sixth workflow**, `pam-harness.yml`: `lab/pam/test/run-all.sh` from a
  fresh clone on a GitHub runner, on demand and nightly, with no
  credentials. BUILT, not run.
- **Wording only, no assertion changed:** `00-Preflight.ps1`'s build-source
  warning and its test, comments in `lab/pam/test/e2e.sh` and
  `lab/kql/device-code-signin.kql`, and documentation under `lab/`.

## Tools

Terraform 1.16.5, Checkov 3.3.20, PowerShell 7.6.1 with Pester 5.7.1 and
6.2.0, PSScriptAnalyzer 1.25.0 and Microsoft.Graph.Authentication 2.41.2.
ShellCheck 0.11.0, actionlint 1.7.12, Python 3.13.3 with PyYAML 6.0.3, jq
1.7.1, git 2.50.1, bash 3.2.57. Docker 29.9.0 client and 29.5.2 server on
Colima 0.10.3 (4 CPU, 8 GiB). macOS 26.5.2 on arm64. Paths are in
`tool-versions.txt`.

## How this record was made

- A wrapper script copied the working tree into a scratch folder (every
  git-trackable file as it was on disk, plus the gitignored ScubaGear sample
  that CI fetches), ran each suite there, and wrote each suite's stdout and
  stderr to `logs/`. The per-suite command, exit code, counts and duration
  are in `results.json` (`suites`). The PAM suites ran in the real
  `lab/pam`, because the shared Docker stack's bind mounts and secrets live
  there.
- The record does not include the PAM per-suite logs. `run-all.sh` keeps
  them gitignored in `lab/pam/out/test-runs/20261021T000019Z/` because they
  name lab accounts and operators. `logs/pam-run-all.log` is run-all's own
  console output.
- **Path normalisation, nothing else.** These local paths were rewritten:
  - the tested copy and the live repository became `<repo>`;
  - the scratch folder became `<scratch>`;
  - the temp root became `<tmp>`;
  - the home directory became `~`.

  Random temp names became numbered placeholders, per log in order of first
  appearance: Pester scratch folders named with dashed GUIDs became
  `tmpdir-N`, and 32-hex names (a `run-<hex>` folder and `hr_feed_<hex>.csv`
  files, from `[guid]::NewGuid().ToString('N')`) became `tmpid-N`.
  `results.json` (`normalisation`) gives the number of substitutions per
  file. No hash of any file from before normalisation is kept: with the
  normalised text, it would let a reader confirm a guessed local path. No
  line was removed or redacted.
- Pester's output was set to plain text (`$PesterPreference.Output.RenderMode
  = 'Plaintext'`, `$PSStyle.OutputRendering = 'PlainText'`) so the logs carry
  no colour codes. No test setting was changed.
- Checkov ran twice: once for `logs/checkov.log`, and once with `-o json`
  for `checkov-skips.txt`, which also compares with a Checkov run on `git
  archive HEAD lab/terraform` from the same session (36 passed, 8 failed, 1
  skipped).
- `guids.txt`: the three GUID-shaped values left in the record are a
  placeholder and two ids the code under test documents. None was generated
  by this run.
- gitleaks 8.30.1 (`gitleaks dir`) found nothing in this folder. A search for
  Vault tokens, JWTs and private-key headers found none either.

## What this run does not show

- That Entra, Azure, AWS or ServiceNow accept any of these calls. The mocked
  tests prove the code does what its comments say; the tenant run proves the
  rest.
- That any KQL rule works on a real KQL engine. `harness.py check` only
  validates the case files.
- That the PAM stand-ins behave like Windows. Samba is not Windows Server,
  the RDP target is a Linux container, and everything ran on one Docker host.
- That the PAM harness runs from a fresh clone (see "How the PAM run
  started").
- When or where this ran. The hashes show only that the files still match
  each other. The public repository is published as one commit, so its date
  shows only that this record existed by then.

Verify: `shasum -a 256 -c SHA256SUMS` in this folder. To check whether the
code has changed since this run, run `shasum -a 256 -c
lab/evidence/offline-tests/20261020T235044Z/code.sha256sums` from the repo
root.
