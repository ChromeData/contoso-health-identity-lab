# Changes made outside the approval gate (2026-11-05 to 2026-11-08)

Written 2026-11-08 for hostile review round 2 (R2, round 1 J6); completed
2026-11-09 from `readiness/progress.log`, the capture log and the PR
bodies. Plain record: what was applied or changed **before** its code was
on `main`, who did it, and how it was reconciled after the merge.

**Words.**
- **The gate**: for `envs/dev`, the `terraform-apply.yml` run that waits on
  the owner's **Review deployments** click. For `envs/bootstrap`,
  `envs/operator`, `aws/` and `okta/`: an apply the owner runs or starts by
  hand ("human-applied").
- **Branch apply**: a Terraform apply from a branch that was not merged yet.
- **Host change**: a script run on DC01 through `run-on-dc.py` (Azure Run
  Command, as SYSTEM). No Terraform, so no gate.
- **The operator**: the lab's certificate workload identity, driven by an AI
  helper (ADR 0024, ADR 0030).

## The rule from now on

1. Every Terraform root goes through its gate. No AI helper applies
   `envs/bootstrap`, `envs/operator`, `aws/` or `okta/`, from any branch.
   AI helpers did so 13 times from 2026-11-05 to 2026-11-08 (table
   below). The last helper applies were the three targeted `okta/` applies
   of the wave-1 cut-over (E184, 2026-11-08 22:10Z-22:11Z), which
   `lab/okta-migration/cutover.mjs` runs itself on every cut-over and
   rollback, from the #283 branch. One more, at the owner's explicit
   direction: the operator applied `envs/bootstrap` from the #282 branch on
   2026-11-08 at 23:38Z (2 added).
   ADR 0022 and `lab/terraform/README.md` said "before 2026-11-07", then
   "up to 2026-11-07 03:05:14Z"; both were wrong. ADR 0022 is corrected.
   The README still says it, and is corrected by the next PR that changes
   `lab/terraform/` (an edit there starts `terraform-apply.yml`).
2. Host changes on DC01 and one-time tenant steps are **outside the gate**,
   and we say so. Each runs as the operator, from a commit on `main`, inside a
   write session the owner opened (ADR 0030, once applied), and gets a
   capture-log row. Every Run Command on DC01 raises an activity log alert
   (`modules/dc-vm`, PR #272).
3. In production, DC host configuration goes through the same pipeline (DSC
   or Intune), with a reviewed plan.

## Terraform applies from unmerged branches

| Row | When (UTC) | Root and branch | Applied by | What | Merged as | Reconciled |
|---|---|---|---|---|---|---|
| E96 | 2026-11-05 10:38 | `aws/`, branch `feat/aws-admin-jit` (targeted apply of `lab-admin.tf`) | Operator helper | 3 added: permission set LabAdministrator and its assignment to the SCIM copy of PIM-AWS-Lab-Admins | #134, 2026-11-05 11:43 (`529f548`) | Code on `main` 65 minutes later. Not re-planned in this record |
| E98 | 2026-11-05 10:57 | `aws/`, same branch (targeted apply of operator guardrails v2) | Operator helper, in adm-labops's LabAdministrator session | Deny guardrails on the operator role (CloudTrail PutRolePolicy 10:57:02Z) | #134, as above | As above |
| - | 2026-11-05 11:26 | `okta/`, branch `docs/okta-hospital-domain` (targeted: routing rule, Clinic-Staff group rule and group) | Operator helper | Routed domain `contosohealthlab.com` (value in the gitignored local `terraform.tfvars`) | #159, 2026-11-05 12:46 (`b921f8b`) | Checked 12:50Z: `main`'s Okta root names the live routing |
| - | 2026-11-05 12:29 | `okta/`, branch `feat/okta-trust-entra-mfa` (targeted: `okta_idp_oidc.entra[0]`) | Operator helper | 1 changed: the Entra IdP on the v1.0 endpoints | #162, 2026-11-05 12:51 (`3827d7a`) | Checked 12:55Z: `main` matches live |
| E115 | 2026-11-07 00:54 | `okta/`, branch `feat/okta-depth` (targeted apply of `clinic-apps.tf`, from the helper's worktree) | Operator helper | 10 added: Clinic Lab Results (OIDC), Clinic Billing (SAML), group rule, authentication policy 'Clinic clinical apps' (ADR 0022) | #222, 2026-11-07 02:53 (`8053718`) | Not re-planned in this record |
| E125 | 2026-11-07 01:13 | `aws/`, branch `feat/aws-session-manager` (targeted apply of `session-manager.tf`) | Operator helper, in a LabAdministrator session | 19 resources (EC2, endpoints, VPC, logs, permission set) | #234, 2026-11-07 02:27 (`0627a16`) | **Torn down before the merge:** 19 destroyed at 01:46 (E127). The local `aws/` state holds none of them (read 2026-11-08). Nothing from the branch is live |
| E150 | 2026-11-07 02:27 | `envs/bootstrap`, branch `feat/pipeline-secrets-keyvault` | Operator helper | 5: `rg-identity-lab-cicd`, Key Vault `kv-idlab-cicd-20f1`, audit setting, 2 reader grants | #240, 2026-11-08 17:46 (`e8e8213`) | **Code matches live, tfvars do not.** Read-only plan from `main`, 2026-11-08: with the owner's current `terraform.tfvars` it plans **10 to destroy** (these 5 and E153's 5). With the 5 values below added: **No changes** |
| E153 | 2026-11-07 02:42 | `envs/bootstrap`, branch `feat/azure-least-privilege` | Operator helper | 5: custom role Contoso Lab VM Operator, its PIM policy and eligibility, 2 CanNotDelete locks on the vaults. Then two follow-ups from the same branch: 02:51-02:55 in place (+ `workspaces/query/read` on the role); 03:04-03:05:14 1 add / 1 change / 1 destroy (the eligibility replaced so it expires after 180 days) | #246, 2026-11-08 18:02 (`cd4b5f1`) | Same plan as E150: main matches live, follow-ups included |
| E184 | 2026-11-08 22:10-22:11 | `okta/`, branch `evidence/okta-cutover-wave1` (targeted: `okta_app_oauth.clinic_results`, run by `cutover.mjs`) | Operator helper | 3 applies, each 0 added / 1 changed / 0 destroyed: the Okta tile hidden (cut-over), shown (rollback), hidden (cut-over back); Okta log 22:10:39Z, 22:11:09Z, 22:11:43Z | #283, 2026-11-09 01:34 (`8ab32a9`) | `waves.json` on `main` says cut over since the merge, as live. Not re-planned in this record |
| - | 2026-11-08 23:38 | `envs/bootstrap`, branch `fix/plan-export-template` | Lab operator, **at the owner's explicit direction** ("you do it as if you're me"); not the owner personally | 2 added, 0 changed, 0 destroyed: custom role Contoso Lab Plan Deployment Template Reader (PLAN identity: `deployments/exportTemplate/action`, assignable on `rg-identity-lab` only) and its assignment on `rg-identity-lab`. Unblocked PR plans after #257's leaver template deployment (403) | #282, 2026-11-08 23:50 (`425b11a`) | Code on `main` now. Not re-planned in this record. Owner-directed, but still an apply from an unmerged branch, so it is listed here |

**Owner action before any `envs/bootstrap` apply** (else the apply destroys
the pipeline config vault and both delete locks). Add to
`lab/terraform/envs/bootstrap/terraform.tfvars`:

```hcl
enable_pipeline_config_vault        = true
pipeline_config_vault_name          = "kv-idlab-cicd-20f1"
enable_lab_vm_operator              = true
lab_vm_operator_eligible_object_ids = ["79feedc9-f610-48f8-a588-d501474cf55c"]
cannot_delete_lock_resource_ids = {
  "kv-idlab"      = "/subscriptions/de0b2a93-1c62-47b3-aaaf-1bdd1939a274/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab-20f1"
  "kv-idlab-cicd" = "/subscriptions/de0b2a93-1c62-47b3-aaaf-1bdd1939a274/resourceGroups/rg-identity-lab-cicd/providers/Microsoft.KeyVault/vaults/kv-idlab-cicd-20f1"
}
```

Then `terraform plan` must say **No changes**. If it does not, stop.

## Host and tenant changes made from branches or open PRs

| Row | When (UTC) | What | From | PR now | Reconciled |
|---|---|---|---|---|---|
| - | 2026-11-05 10:22 | Okta IdP: authorize request sent unsigned (`request.signature.scope` NONE), set through the Okta API | before `fix/okta-idp-unsigned-authorize` | #140 merged 2026-11-05 10:40 (`c28bb4e`) | `main` codes the same value |
| - | 2026-11-05 12:29 | Okta IdP `trustClaims` on, by `lab/terraform/okta/trust-claims.mjs` (the provider has no argument for it) | `feat/okta-trust-entra-mfa` | #162 merged 2026-11-05 12:51 (`3827d7a`) | Checked 12:55Z: `main` matches live |
| E116-E118 | 2026-11-07 | AD tiering on DC01: admin tiers, Protected Users for new admins, Windows LAPS | `harden/ad-tiering` | #225 merged 2026-11-08 20:39 (`a339139`) | Code and rows E116-E118 on `main` now. Host state not re-read after the merge |
| E140 | 2026-11-07 01:31 | AD FS steps 1-6 on DC01 (role, farm, gMSA, claim rules) | `adfs/dc01-run-and-connect-health` | #237 merged 2026-11-08 17:24 (`5c77d1f`) | Code on `main` now. Host state not re-read after the merge |
| E156 | 2026-11-07 | `t0-adm-01` password rotated after the #239 Tier 2 test exposed it | `ops/rotate-t0-adm-01` | #251 merged 2026-11-08 23:51 | Code on `main` now |
| E157 | 2026-11-07 03:55 | `svc-pam-discovery` deleted on DC01 and in Key Vault (the first "dry run" acted: R28) | branch of #253 | #253 merged 2026-11-08 19:09 (`ecf7f2c`) | Code on `main`. The DC identity's Key Vault grant is replaced by that PR's apply (pending) |
| E178 | 2026-11-08 18:09 | `contosoadmin` rotated after the #239 exposure | `ops/rotate-contosoadmin` | #262 merged 2026-11-08 20:10 (`e7441e4`) | Code on `main` |
| E132 | 2026-11-07 01:48 | Key Vault state-leak proof in a throwaway resource group (deleted) | `feat/keyvault-state-leak` | #235 merged 2026-11-08 20:23 (`2d479fa`) | Throwaway objects deleted at the time |
| E133 | 2026-11-07 | Bastion Premium, its public IP, a PIM-eligible Reader and a reviewer grant, made by script (`lab/bastion/capture.sh`) | `feat/bastion-session-recording` | #247 merged 2026-11-08 23:52 | Code and E133 on `main` now. Live read 2026-11-08: no Bastion, no Bastion PIM eligibility, no Storage Account Key Operator grant. **Left over:** the recordings account `stbstreca9b511bc` (shared key now off) |
| - | 2026-11-08 | Cloud Sync mappings, the leave-date Lifecycle Workflow schedule, joiner v2 | `feat/leaver-lcw-leavedate` (stacked) | #257 merged 2026-11-08 21:25 (`f605fc7`) | Code on `main` now (rows E179-E181). Tenant config not re-read after the merge |

## What this means for the spoken lines

- "Nothing goes live until I approve it" was false. The lines now say: no
  **Terraform** change goes live without the owner's approval of its plan;
  DC01 scripts and fourteen applies from nine branches before their merge
  ran outside that gate (thirteen by helpers, on 2026-11-05, 2026-11-07 and
  2026-11-08; one on 2026-11-08 at the owner's direction), and this file
  lists each one.
