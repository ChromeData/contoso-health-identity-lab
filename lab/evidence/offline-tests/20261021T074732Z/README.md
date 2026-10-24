# Offline test run 20261021T074732Z

One run of every offline check in the repository, on a copy of the working
tree, followed by the PAM harness's default suites on local Docker.
`code.sha256sums` lists the 514 files under `lab/` (except `lab/evidence/`)
and `.github/` exactly as they were tested: it is the fingerprint to check a
tree against.

**What kind of evidence this is.** Every row except the last is **BUILT**
evidence: offline checks, with every Terraform provider mocked (`terraform
test`) and every Graph and `az` call in the PowerShell suites a Pester mock.
Only the last row, `pam-run-all`, is **RAN · harness**: the PAM suites on
local Docker against a Samba AD domain controller. **RAN · tenant: none.** No
Microsoft tenant exists. `results.json` gives each row's `evidence_level`.

**Result: all 21 suite rows PASS.**
The folder is named for 07:47:32Z on 2026-10-21, when the wrapper made the
tested copy and took the Checkov baseline at the committed HEAD. The offline
suites ran 07:47:43Z to 07:54:40Z, and the PAM harness from 07:55:46Z to
08:01:29Z.

| Suite | Command (short form; full command in `results.json`) | Result |
|---|---|---|
| terraform-fmt | `terraform fmt -check -recursive lab/terraform` | PASS, exit 0 |
| terraform | in each of 18 directories: `init -backend=false` (`-lockfile=readonly` on the committed root locks), `validate`, `test` (`-var-file=lab.tfvars` where present) | 18/18 init and validate; **326 passed, 0 failed** |
| checkov | `checkov -d lab/terraform --framework terraform` (3.3.20 from PyPI, with its 196 Terraform graph checks) | 61 passed, **0 failed**, 15 skipped. Each skip is an inline `#checkov:skip` with its reason (`checkov-skips.txt`). The committed HEAD, before this tree's skips and fix, gives 56 passed, 4 failed, 12 skipped: the result GitHub's `checkov (IaC scan)` reported on the first Dependabot pull requests |
| checkov-k8s | `checkov -d lab/k8s/manifests --framework kubernetes --skip-path /negative/` (6 Kubernetes graph checks) | 89 passed, **0 failed**, 0 skipped |
| ps-parse | PowerShell parser on every `lab/**/*.ps1` | 87 files, 0 parse errors |
| ps-analyzer (all of `lab/`) | PSScriptAnalyzer 1.25.0 on the same 87 files | **0 errors**, 101 warnings, 727 information |
| scuba-fixture | `Get-ScubaSample.ps1`: the ScubaGear v1.8.0 sample against its pinned SHA-256 hashes (CI fetches it before the Pester suite) | 3 of 3 files verified, nothing downloaded |
| pester-lab 5.7.1 | `Invoke-LabTests.ps1 -CI` with Pester 5.7.1 (CI's pin) | **1074 passed, 0 failed, 0 skipped**; its analyzer pass (`lab/scripts/powershell`): 0 errors, 19 warnings |
| pester-lab 6.2.0 | the same with Pester 6.2.0 | **1074 passed, 0 failed, 0 skipped**; 0 errors, 19 warnings |
| pester-itdr (CI step) | `Itdr.Tests.ps1` + `lab/pam/test/Get-AccountDependencies.Tests.ps1` (Pester 5.7.1) | 292 passed, 0 failed |
| pester-itdr only | `Itdr.Tests.ps1` alone | **284 passed**, 0 failed |
| shellcheck | `shellcheck -x` from the repo root on the 41 `lab/**/*.sh` files, all severities | 41 files, 0 findings |
| actionlint | `actionlint -verbose` (1.7.12) | 6 workflows, 0 errors |
| json-parse | `json.load` on every git-trackable `*.json` under `lab/` and `.github/` | 63 files, 0 errors |
| splunk-render-check | `lab/splunk/render-savedsearches.sh --check` | 22 detections in sync |
| ingest test | `lab/scripts/monitoring/tests/ingest-vault-audit.test.sh` | 30 passed, 0 failed |
| kusto-harness-check | `harness.py check` (offline validation only) | 223 cases over 22 rules valid. No KQL ran on an engine in this run: the engine run is its own record, `lab/evidence/kusto/20261021T001217Z/` |
| azure-config-gate-test | `.github/scripts/azure-config.test.sh` (the skip-or-run gate in front of every Azure sign-in job; `lab-tests.yml` runs it) | 16 passed, 0 failed |
| evidence hashes | `shasum -a 256 -c SHA256SUMS` in every existing record folder | 14/14 OK |
| record verifiers | each harness's `--verify` on its records | 10/10 PASSED (offline, no Docker) |
| pam-run-all | `cd lab/pam && ./test/e2e.sh --cleanup; ./test/run-all.sh` (no `--publish`, no `--scale`) | **8/8 suites, 610 passed, 0 failed, 1 skipped** (run id `20261021T075546Z`) |

Terraform by directory (`terraform.tsv`): `envs/dev` 13, `envs/bootstrap` 3,
`aws` 7, `k8s/platform` 5, `k8s/identity` 11, `k8s/aks-mapping` 7; modules
`apps` 31, `conditional-access` 71, `dc-vm` 11, `entitlement` 26,
`entra-diagnostics` 7, `evidence-store` 13, `groups` 4, `intune-vm` 41,
`keyvault` 7, `monitoring` 32, `pim` 32, `pipeline-identity` 5. That is 303
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
`pam-up.sh`. This is not a fresh clone: the generated `.env` and the volumes
were reused. `environment.txt` confirms that the `lab/pam` the harness ran
(93 files) is byte-identical to the tested copy. After this record was
written, `e2e.sh --cleanup` and `e2e-dynamic-db.sh --cleanup` removed the
harness's test state and the shared stack was stopped (volumes kept).

## Changed in the tree since the previous record

`offline-tests/20261020T235044Z/` is the run before this one. Since it:

- **Checkov now has its graph checks.** The earlier records ran a Homebrew
  Checkov 3.3.20 whose package lacks every JSON-defined graph check, so they
  show 0 failed where GitHub's first runs found 4 Terraform findings and 1
  Kubernetes finding. This run uses Checkov 3.3.20 from PyPI. The findings
  are closed: inline skips with reasons on CKV_AZURE_119 (the `dc-vm` and
  `intune-vm` network interfaces) and CKV2_AZURE_21 (the evidence
  container); a real network security group on the Key Vault
  private-endpoint subnet for CKV2_AZURE_31, asserted by a new `keyvault`
  test (6 to 7 runs, so 325 to 326 in all); and a NetworkPolicy for the
  `nightly-report` pod in `lab/k8s/manifests/` for CKV2_K8S_6.
- **Pester 917 to 1074.** 151 are the new `Invoke-LabDay.Tests.ps1` (the
  tenant-day runner and its evidence module, all mocked). The other 6 come
  from `ScriptAnalyzerScope.Tests.ps1`, which runs two checks per script: the
  three new scripts added them.
- **Two new rows:** `checkov-k8s` and `azure-config-gate-test`.
- **CI.** Azure jobs skip with a notice when nothing is configured and fail
  closed on a partial configuration (`.github/scripts/azure-config.sh`).
  Dependabot no longer proposes major provider bumps. `k8s-identity.yml` and
  the Kubernetes pipeline's preflight refuse a Checkov without graph checks,
  and the pipeline's Checkov stage fails when a scan reports nothing.
- **Public-record checks** in `Invoke-BreakGlassDrill.ps1` and
  `Convert-BuildAccountToEligible.ps1` now also catch compressed IPv6
  addresses (`::`).
- **Wording only, no assertion changed:** comments in
  `lab/pam/docker-compose.yml` and `lab/terraform/k8s/identity/versions.tf`,
  the architecture diagram, and documentation under `lab/`.

## Tools

Terraform 1.16.5; Checkov 3.3.20 (PyPI, in a Python 3.12.4 virtual
environment, with 196 Terraform and 6 Kubernetes graph checks); PowerShell
7.6.1 with Pester 5.7.1 and 6.2.0, PSScriptAnalyzer 1.25.0 and
Microsoft.Graph.Authentication 2.41.2. ShellCheck 0.11.0, actionlint 1.7.12,
Python 3.12.4 with PyYAML 6.0.3, jq 1.7.1, git 2.50.1, bash 3.2.57. Docker
29.9.0 client and 29.5.2 server on Colima 0.10.3 (4 CPU, 8 GiB). macOS
26.5.2 on arm64. Paths are in `tool-versions.txt`.

## Files

- `results.json`: every suite row (command, exit code, counts, seconds,
  verdict, evidence level), Terraform by directory, the Checkov comparison,
  the PAM suites and the path-normalization counts.
- `logs/`: each suite's stdout and stderr, path-normalized.
- `terraform.tsv`, `pam-results.tsv`, `checkov-skips.txt`, `environment.txt`,
  `tool-versions.txt`, `guids.txt`, `code.sha256sums`; `SHA256SUMS` covers
  every other file in this folder.

## How this record was made

- A wrapper script copied the working tree into a scratch folder (every
  git-trackable file as it was on disk, plus the gitignored ScubaGear sample
  that CI fetches), ran each suite there, and wrote each suite's stdout and
  stderr to `logs/`. The PAM suites ran in the real `lab/pam`, because the
  shared Docker stack's bind mounts and secrets live there.
- The record does not include the PAM per-suite logs. `run-all.sh` keeps
  them gitignored in `lab/pam/out/test-runs/20261021T075546Z/` because they
  name lab accounts and operators. `logs/pam-run-all.log` is run-all's own
  console output.
- **Path normalization, nothing else.** Local paths were rewritten: the
  tested copy and the live repository became `<repo>`, the scratch folder
  `<scratch>`, the temp root `<tmp>` and the home directory `~`. Random temp
  names became numbered placeholders, per log in order of first appearance:
  Pester scratch folders named with dashed GUIDs became `tmpdir-N`, and
  32-hex names became `tmpid-N`. `results.json` (`normalisation`) gives the
  number of substitutions per file. No hash of any file from before
  normalization is kept: with the normalized text, it would let a reader
  confirm a guessed local path. No line was removed or redacted.
- Pester's output was set to plain text so the logs carry no color codes. No
  test setting was changed.
- Checkov ran twice on the tested copy (once for `logs/checkov.log`, once
  with `-o json` for `checkov-skips.txt`) and once on `git archive HEAD
  lab/terraform` from the same session, for the comparison above.

## Checks on this record

- `guids.txt`: the three GUID-shaped values left in the record are the
  all-zero placeholder, a test fixture, and a role id the code under test
  documents (Restricted Guest User). None was generated by this run.
- gitleaks (`gitleaks dir`) found nothing in this folder.

## What this run does not show

- That Entra, Azure, AWS or ServiceNow accept any of these calls. The mocked
  tests prove the code does what its comments say; the tenant run proves the
  rest.
- That GitHub's runners agree. The Checkov fixes and the new CI gate have
  not run on GitHub yet.
- That the NetworkPolicy is enforced. Checkov reads the manifest; the
  Kubernetes pipeline was not part of this run.
- That the PAM stand-ins behave like Windows. Samba is not Windows Server,
  the RDP target is a Linux container, and everything ran on one Docker host.
- That the PAM harness runs from a fresh clone (see "How the PAM run
  started").
- When or where this ran. The hashes show only that the files still match
  each other.

Verify: `shasum -a 256 -c SHA256SUMS` in this folder. To check whether the
code has changed since this run, run `shasum -a 256 -c
lab/evidence/offline-tests/20261021T074732Z/code.sha256sums` from the repo
root.
