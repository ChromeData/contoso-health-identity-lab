# Offline test run 20261020T230108Z

One run of every offline check in the repository, on a copy of the working
tree, followed by the PAM harness's default suites on local Docker.
`code.sha256sums` lists the 502 files under `lab/` (except `lab/evidence/`) and
`.github/` exactly as they were tested: it is the fingerprint to check a tree
against.

**RAN · tenant: none.** No Microsoft tenant exists. Every Terraform provider
is mocked (`terraform test`), every Graph and `az` call in the PowerShell
suites is a Pester mock, and the PAM suites ran against a Samba AD domain
controller in Docker.

**Result: all 18 suite rows PASS.**
Offline suites ran 23:01:08Z to 23:06:35Z, and the PAM harness 23:06:41Z to
23:12:29Z, on 2026-10-20.

| Suite | Command (short form; full command in `results.json`) | Result |
|---|---|---|
| terraform-fmt | `terraform fmt -check -recursive lab/terraform` | PASS, exit 0 |
| terraform | in each of 18 directories: `init -backend=false` (`-lockfile=readonly` on the committed root locks), `validate`, `test` (`-var-file=lab.tfvars` where present) | 18/18 init and validate; **325 passed, 0 failed** |
| checkov | `checkov -d lab/terraform --framework terraform` (3.3.20) | 45 passed, **8 failed**, 3 skipped. The 8 are the documented baseline, and the committed HEAD fails the same 8: **0 new** (`checkov-baseline.txt`) |
| ps-parse | PowerShell parser on every `lab/**/*.ps1` | 83 files, 0 parse errors |
| ps-analyzer (all of `lab/`) | PSScriptAnalyzer 1.25.0 on the same 83 files | **0 errors**, 101 warnings, 693 information |
| pester-lab 5.7.1 | `Invoke-LabTests.ps1 -CI` with Pester 5.7.1 (CI's pin) | **917 passed, 0 failed, 0 skipped**; its analyzer pass (`lab/scripts/powershell`): 0 errors, 19 warnings |
| pester-lab 6.2.0 | the same with Pester 6.2.0 | **917 passed, 0 failed, 0 skipped**; 0 errors, 19 warnings |
| pester-itdr (CI step) | `Itdr.Tests.ps1` + `lab/pam/test/Get-AccountDependencies.Tests.ps1` (Pester 5.7.1) | 292 passed, 0 failed |
| pester-itdr only | `Itdr.Tests.ps1` alone | **284 passed**, 0 failed |
| shellcheck | `shellcheck -x` from the repo root on the 41 `lab/**/*.sh` files, all severities | 41 files, 0 findings |
| actionlint | `actionlint -verbose` (1.7.12) | 5 workflows, 0 errors |
| json-parse | `json.load` on every git-trackable `*.json` | 60 files (all under `lab/` and `.github/`), 0 errors |
| splunk-render-check | `lab/splunk/render-savedsearches.sh --check` | 22 detections in sync |
| ingest test | `lab/scripts/monitoring/tests/ingest-vault-audit.test.sh` | 30 passed, 0 failed |
| kusto-harness-check | `harness.py check` (offline validation only) | 223 cases over 22 rules valid. **No KQL ran on an engine**: the emulator run waits for the operator to accept Microsoft's licence |
| evidence hashes | `shasum -a 256 -c SHA256SUMS` in every existing record folder | 11/11 OK |
| record verifiers | each harness's `--verify` on its records | 10/10 PASSED (offline, no Docker) |
| pam-run-all | `cd lab/pam && ./test/e2e.sh --cleanup && ./test/run-all.sh` (no `--publish`, no `--scale`) | **8/8 suites, 610 passed, 0 failed, 1 skipped** (run id `20261020T230641Z`) |

Terraform by directory (`terraform.tsv`): `envs/dev` 13, `envs/bootstrap` 3,
`aws` 7, `k8s/platform` 5, `k8s/identity` 11, `k8s/aks-mapping` 7; modules
`apps` 31, `conditional-access` 71, `dc-vm` 11, `entitlement` 26,
`entra-diagnostics` 7, `evidence-store` 13, `groups` 4, `intune-vm` 41,
`keyvault` 6, `monitoring` 32, `pim` 32, `pipeline-identity` 5. That is 302
in the Entra, Azure and AWS directories plus 23 in the Kubernetes roots. No
provider was downloaded: every `init` reused providers already installed.

PAM suites (`pam-results.tsv`): dependency-scan 8, ingest 30,
itsm-dual-control 45, recording-format 29, e2e 284, midpoint 91, dynamic-db
60, vault-anomaly 63 + 1 skipped (the Splunk step: no local Splunk). The run
started from the `--cleanup` state on purpose. The DC settings in `.env` were
empty, as on a fresh stack, which is the case the `e2e.sh` fix below covers.
`environment.txt` confirms that the `lab/pam` the harness ran (93 files) is
byte-identical to the tested copy.

## Fixed during this verification, before this run

- **`lab/pam/test/e2e.sh`.** The first `e2e.sh` run on a fresh stack, or after
  `--cleanup`, aborted at step g4 ("rdp-target builds and starts").
  `load_env` exports the `.env` values once at start, and on a fresh stack
  `DC_FQDN` is still empty then. `vault-onboard-ad.sh` later writes the DC to
  `.env` in its own process, but `docker compose` prefers the exported empty
  value. So rdp-target started with no `DC_FQDN` and restarted in a loop. The
  failure was reproduced twice: runs `20261020T224341Z` and
  `20261020T225031Z`, logs in the gitignored `lab/pam/out/test-runs/`. The fix
  re-reads `.env` right after the onboarding check. It adds no assertion, so
  the count is still 284. The fixed script passed from the cleanup state in
  `20261020T225332Z` (284/284) and again in this record. Earlier runs had
  passed only because `.env` already named the DC when they started.
  Consequence: the verifier of `pam/20261020T220031Z` now notes
  `changed test/e2e.sh` (see `logs/evidence-verifiers.log`).
- **`lab/.shellcheckrc`** (`source-path=SCRIPTDIR`). Run from the repo root,
  `shellcheck -x` could not follow `source "$(dirname "$0")/lib.sh"`. It
  reported SC1091 (info) 18 times on 15 scripts. ShellCheck now looks in each
  script's own folder, so the helpers are checked in context.

## Tools

Terraform 1.16.5, Checkov 3.3.20, PowerShell 7.6.1 with Pester 5.7.1 and
6.2.0, PSScriptAnalyzer 1.25.0 and Microsoft.Graph.Authentication 2.41.2.
ShellCheck 0.11.0, actionlint 1.7.12, Python 3.13.3 with PyYAML 6.0.3, jq
1.7.1, git 2.50.1, bash 3.2.57. Docker 29.9.0 client and 29.5.2 server on
Colima 0.10.3 (4 CPU, 8 GiB). macOS 26.5.2 on arm64. Paths are in
`tool-versions.txt`.

## How this record was made

- A wrapper script cloned the working tree into a scratch folder, ran each
  suite there, and wrote each suite's stdout and stderr to `logs/`. The
  per-suite command, exit code, counts and duration are in `results.json`
  (`suites`). The PAM suites ran in the real `lab/pam`, because the shared
  Docker stack's bind mounts and secrets live there.
- The record does not include the PAM per-suite logs. `run-all.sh` keeps
  them gitignored in `lab/pam/out/test-runs/20261020T230641Z/` because they
  name lab accounts and operators. `logs/pam-run-all.log` is run-all's own
  console output.
- **Path normalisation, nothing else.** These local paths were rewritten:
  - the tested copy and the live repository became `<repo>`;
  - the scratch folder became `<scratch>`;
  - the temp root became `<tmp>`;
  - the home directory became `~`.

  Pester creates scratch folders named with random GUIDs
  (`[guid]::NewGuid()`); those names became `tmpdir-N`, numbered per log in
  order of first appearance. `results.json` (`normalisation`) gives the
  number of substitutions per file. No line was removed or redacted.
- Pester's output was set to plain text (`$PesterPreference.Output.RenderMode
  = 'Plaintext'`, `$PSStyle.OutputRendering = 'PlainText'`) so the logs carry
  no colour codes. No test setting was changed.
- Checkov ran twice: once for `logs/checkov.log`, and once with `-o json` for
  the comparison in `checkov-baseline.txt`. The baseline is a Checkov run on
  `git archive HEAD lab/terraform` from the same session (36 passed, 8 failed,
  1 skipped).
- `guids.txt`: the three GUID-shaped values left in the logs are a
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
- When or where this ran. The hashes show only that the files still match
  each other. The public repository is published as one commit, so its date
  shows only that this record existed by then.

## Publication edits (after the run, 2026-10-20T23:45Z)

This record was edited once after the run, for publication, and then
re-sealed (`SHA256SUMS` regenerated). Every count, exit code and verdict, and
every other log line, is unchanged. `results.json`
(`publication_edits_after_run`) lists the same edits:

- each file's sha256 from before path normalisation was removed: with the
  normalised text, it let a reader confirm a guessed local path by re-hashing;
- the build source's commit id and its count of uncommitted paths were
  removed: that commit is not in the published history, and
  `code.sha256sums` is the fingerprint to check;
- the random 32-hex temp names in the two `pester-lab` logs (4 and 4) became
  `tmpid-N`, as the run already did for dashed GUIDs;
- the json-parse row and the dating sentence above were reworded.

Verify: `shasum -a 256 -c SHA256SUMS` in this folder. To check whether the
code has changed since this run, run `shasum -a 256 -c
lab/evidence/offline-tests/20261020T230108Z/code.sha256sums` from the repo
root.
