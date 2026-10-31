# New engineer onboarding

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). This guide
is for an engineer joining the identity team that owns the lab.

## State of the lab today (read this first)

| Part | Status, per its own README |
|---|---|
| Entra / Azure Terraform (`terraform/envs/dev`, `envs/bootstrap`, `aws/`) | `fmt` and `validate` clean, and the mocked `terraform test` files listed in the Terraform README (*Validate / fmt status*) pass. **Applied in the lab tenant: 64 merged pull requests.** |
| PowerShell JML, governance and reports (`scripts/`, `iga/`) | Written to deploy, **not run** against a tenant. Some have offline modes (`-OfflinePreview`, `-RenderOnly`, synthetic fixtures) and Pester tests |
| PAM stand-ins (`pam/`) | RAN · harness on 2026-10-20 on the author's working copy, in one `test/run-all.sh --publish` run (its summary stays in the gitignored `pam/out/test-runs/`): 8 of 8 suites, including the Samba AD harness `test/e2e.sh` 284/284 (with Tier-0 dual control and a recorded RDP session to a Linux xrdp stand-in), `test/e2e-midpoint.sh` 91/91 (a midPoint certification campaign) and `test/e2e-dynamic-db.sh` 60/60; separately, the 500-account scale run 79/79. Hashed run records: `evidence/pam/20261020T220031Z/`, `evidence/pam-dr/20261020T220031Z/`, `evidence/pam-scale/`, `evidence/midpoint/`, `evidence/dynamic-db/` (index: `evidence/README.md`). Still to verify: a run from a fresh clone, and anything against DC01 |
| Kubernetes workload identity (`k8s/`) | RAN · harness: `ci/pipeline.sh` ran green locally (12/12 stages, end-to-end stage 64/64; hashed record `evidence/k8s/20261020T202112Z/`). Still to verify: the first GitHub Actions run |
| Detections (`kql/`, `splunk/detections/`) | 22 KQL rules, each with an SPL twin, written. `modules/monitoring` deploys the five core rules and the ITDR set. All 22 ran (RAN · harness) on the local Azure Data Explorer Kusto emulator against synthetic events, 22/22 rules and 277/277 cases PASS (`evidence/kusto/20261021T001217Z/`). That is a KQL engine, not a Log Analytics workspace or a tenant: 17 are now scheduled in Sentinel by the tenant run (E15, E15b) |

Treat anything that has no recorded run as unproven. Never present it as
working.

## Where things are (paths relative to `lab/`)

| Path | What it holds |
|---|---|
| `docs/architecture.md`, `docs/STAND-INS.md` | The system on one page, and every stand-in with the product it replaces |
| `docs/runbooks/` | Operational procedures (this folder) |
| `terraform/` | Identity as code: modules, `envs/dev` (CI-applied), `envs/bootstrap` (human-applied), `aws/`, `k8s/`. Start with the README: module map, licensing, human steps, apply order |
| `terraform/envs/dev/lab.tfvars` | The committed policy knobs: staging flags, CA states, blocked countries |
| `pipelines/` + `.github/workflows/` | The OIDC plan/apply pipeline. PLAN identity is read-only; APPLY is gated by the `prod` environment |
| `scripts/` | The HR mock, joiner/mover/leaver, post-apply Graph steps, reports, evidence pack |
| `kql/`, `splunk/`, `monitoring/` | 22 detections in KQL with their SPL twins: five core rules and the ITDR set. The notify playbook (Teams + ServiceNow) and the Teams-approved containment playbook |
| `iga/` | Birthright rules, SoD rules and the access catalog behind the governance scripts |
| `pam/` | Vault (CPM stand-in, with discovery, onboarding, reconciliation and an HA/DR rehearsal), Guacamole (PSM and PSMP stand-in), Conjur, midPoint, dynamic database credentials |
| `k8s/` | kind-based workload identity: Vault Kubernetes auth, admission policy, drift test |
| `evidence/` | `drills/` (the break-glass drill log, an empty template) and hashed local-harness records: `midpoint/` (certification campaigns) and `dynamic-db/` (dynamic database credentials). `out/` is gitignored and holds tenant data |

## House rules

1. **One owner per object.** Terraform owns groups, CA, PIM policy and packages. HR owns workers. Scripts verify and fill the Graph gaps (`scripts/README.md`).
2. **No secrets in the repo.** It is public. Identifiers go in GitHub Variables. The operator IP and the alert email are repo secrets only so the logs mask them.
3. **CA ships report-only.** One policy graduates per PR ([graduate-a-ca-policy.md](graduate-a-ca-policy.md)).
4. **Name every stand-in.** A new one needs a row in `docs/STAND-INS.md`.
5. **Write `verify:` when you aren't sure.** Never guess a fact or a result.

## Run what runs without a tenant

**Tools:** Terraform **1.16.5** (the version the lock files were made with; use `terraform`, not `tofu`), PowerShell 7 with the Microsoft Graph modules, Docker (Colima on Apple Silicon), `jq`, `openssl`, `curl`. The sizing and extra tools for each stack are listed in `pam/README.md`, `k8s/README.md` and `splunk/README.md`.

```bash
# Terraform: format, validate, mocked tests (no backend, no tenant)
terraform -chdir=lab/terraform fmt -recursive -check
terraform -chdir=lab/terraform/envs/dev init -backend=false
terraform -chdir=lab/terraform/envs/dev validate
terraform -chdir=lab/terraform/envs/dev test -var-file=lab.tfvars

# PAM stand-ins + real AD rotation against a Samba AD DC
cd lab/pam && ./pam-up.sh && test/e2e.sh && test/e2e.sh --cleanup
# midPoint certification campaign, and dynamic database credentials
test/e2e-midpoint.sh && test/e2e-dynamic-db.sh && test/e2e-dynamic-db.sh --cleanup

# Kubernetes workload identity, 12 stages, cluster destroyed at the end
lab/k8s/ci/pipeline.sh

# Splunk detections: committed .conf matches the .spl files
lab/splunk/render-savedsearches.sh --check
```

```powershell
# Lifecycle Workflow JSON with no tenant connection
./lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1 -OfflinePreview
```

The other mocked tests are listed in the Terraform README, under *Validate / fmt status*. Tenant work follows that README's *Apply order*, and it starts trial licences that run on a clock.

## First week

| Day | Do | Done when |
|---|---|---|
| 1 | Read `docs/architecture.md`, `docs/STAND-INS.md`, and the Terraform and pipelines READMEs | You can explain why APPLY is effectively Tier 0, and what limits it |
| 2 | Run the offline checks above | Every check passes, or you have filed an issue with the output |
| 3 | Read the five core KQL rules and the ITDR rules beside their SPL twins, then the runbooks in this folder | You can say what each rule catches and what it misses |
| 4 | Pick one `verify:` item in `lab/` and close it with a primary source, or record why you can't | A PR with the source linked |
| 5 | Run a tabletop of [compromised-identity.md](compromised-identity.md) with a teammate. Then review a CA PR with [ca-change-review-checklist.md](ca-change-review-checklist.md) | Gaps found during the tabletop are filed as issues |

Ask before you touch `terraform/envs/bootstrap` (human-applied, Tier 0 grants) or anything that starts a trial.
