# Kubernetes workload identity: pipeline run 20261020T202112Z

One full, unmodified run of [`lab/k8s/ci/pipeline.sh`](../../../k8s/ci/pipeline.sh)
on the lab Mac (per-file hashes of the code under test in
`code-under-test.sha256`).
`KEEP_CLUSTER` and `STOP_AFTER` were unset, so all 12 stages ran and the EXIT
trap destroyed both Terraform roots and the kind cluster. No tenant: a local
kind cluster on Colima, no Azure, Entra or CyberArk, synthetic values only.

**Result: exit 0. 12/12 stages PASS, teardown PASS, `K8S E2E PASSED (64/64)`.**
Run 2026-10-20 20:21:20Z to 20:23:35Z (135 s wall clock; the pipeline's own
stage total is 133 s).

| Stage | s | Result | Evidence (from `run.log`) |
|---|---:|---|---|
| [1/12] preflight | 4 | PASS | kind + kubectl sha256 match the pins |
| [2/12] terraform fmt / validate / test | 3 | PASS | 3 roots, 23 tftest runs passed |
| [3/12] checkov | 10 | PASS | 11 terraform + 88 k8s passed, 0 failed |
| [4/12] kind cluster | 30 | PASS | |
| [5/12] terraform apply platform | 19 | PASS | 4 added; Vault 2.1.1 up |
| [6/12] terraform apply identity | 2 | PASS | 13 added; live VAP: [Deny], 4 rules |
| [7/12] seed secret | 0 | PASS | kv version 1, value never printed |
| [8/12] deploy workload | 14 | PASS | |
| [9/12] rotate secret (no restart) | 7 | PASS | new value live in ~7s, same pod, restart counts 0 = 0 |
| [10/12] drift: detect + heal | 3 | PASS | DRIFT DETECTED (plan 2) -> healed (0); apply removed User/mallory |
| [11/12] e2e tests | 23 | PASS | 64/64 assertions passed |
| [12/12] secrets out of state | 1 | PASS | 0 secret hits: 2 states + audit log |
| teardown | 17 | PASS | identity 13 destroyed, platform 4 destroyed, cluster deleted |

e2e assertions by section (all PASS, 0 FAIL): (a) platform 6, (b) workload 6,
(c) Vault Kubernetes auth 11, (d) namespace + name + object 4, (e) no static
secret 3, (f) RBAC 15, (g) admission 14, (h) audit log 5. The pipeline's own
assertions in stages 6, 9, 10 and 12: 7 PASS, 0 FAIL. Stage 12 counted the KV
value (both stored versions) and the Vault root token, plain and base64, in
both Terraform states and the API-server audit log: all 0; control string
`clinical-apps` found 6 / 38 / 539 times.

## Tools

kind v0.33.0, kubectl v1.37.1 (both sha256-matched to the pipeline's pins),
terraform 1.16.5, checkov 3.3.20, Docker 29.5.2 on Colima v0.10.3 (4 CPU,
7.7 GiB visible to Docker, arm64), bash 3.2.57. Node image
`kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed`.
Vault chart 0.34.1 via the Terraform helm provider 3.3.0 (no `helm` CLI is
installed or used), Vault 2.1.1 and vault-k8s 1.7.6 pinned by digest.
Everything else, with binary hashes and provider versions: `tool-versions.txt`
and `results.json` (`tools`).

## How this record was made

- A wrapper captured tool versions, ran `lab/k8s/ci/pipeline.sh` from the repo
  root, and wrote the merged stdout + stderr to `run.log` and a copy of stderr
  alone to `stderr.log` (kind's progress lines). The merged order of stderr
  lines relative to stdout can differ slightly from a terminal's.
- `environment.txt`: running containers before and after (none from other
  projects at either point), and the teardown check after exit: no kind
  cluster, 0 `contoso-k8s` containers, 0 Terraform state files, no
  `lab/k8s/ci/.state`.
- `results.json`: the stage table, every PASS/FAIL line (pipeline and e2e)
  parsed from `run.log`, tool versions, the log scan and the normalization below.
- **Path normalization, nothing else:** before publishing, the local home
  directory was replaced by `~` and the repository's local path by `<repo>`
  (11 substitutions, counted per file in `results.json`). No log line was
  removed or redacted.
- **Secrets in the logs:** none found, no redaction applied. `run.log` and
  `stderr.log` hold no JWT, no Vault token (`hvs.`/`hvb.`/`hvr.` or legacy),
  no `X-Vault-Token`, no private key, none of the pipeline's `***` mask or the
  e2e test's `<... redacted>` markers, and no hex run shaped like the root token
  (48) or a KV value (32). The only long hex runs are 24 sha256 strings, each
  identified (image digests, the e2e test's fake image digest, the Helm values
  hash). This is a shape search: the run never stored the token or the values,
  so the logs could not be searched for them by value (stage 12 does that for
  the states and the audit log).
- `guids.txt` lists the 9 GUID-shaped ids in `run.log`: object uids of the
  deleted kind cluster and one Terraform `terraform_data` id. Kept as recorded.

What this run does not show: it is the lab Mac, not the GitHub Actions job
(`.github/workflows/k8s-identity.yml`); see the segment
[README](../../../k8s/README.md) section 6 for the design's own limits.

Publication edit (after the run, 2026-10-20T23:45Z): each file's sha256 from before
path normalisation and the build source's commit id were removed from
`results.json`, `tool-versions.txt` and this README (a pre-normalisation hash
let a reader confirm a guessed local path; the commit is not in the published
history, and `code-under-test.sha256` is the fingerprint to check). Then
`SHA256SUMS` was regenerated. No stage result, count or log line changed
(`results.json`, `publication_edits_after_run`).

Verify: `shasum -a 256 -c SHA256SUMS` in this folder.
