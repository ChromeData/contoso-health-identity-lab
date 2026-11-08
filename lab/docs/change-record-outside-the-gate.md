# Changes made outside the approval gate (2026-11-05 to 2026-11-08)

Written 2026-11-08 for hostile review round 2 (R2, round 1 J6). Plain record:
what was applied or changed **before** its code was on `main`, who did it,
and how it was reconciled after the merge.

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
   The last helper applies of those roots were E150 and E153 (2026-11-07
   02:27Z and 02:42Z). ADR 0022 and `lab/terraform/README.md` said "before
   2026-11-07"; that was wrong by those two applies, and is corrected.
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
| E125 | 2026-11-07 01:13 | `aws/`, branch `feat/aws-session-manager` (targeted apply of `session-manager.tf`) | Operator helper, in a LabAdministrator session | 19 resources (EC2, endpoints, VPC, logs, permission set) | #234, 2026-11-07 02:27 (`0627a16`) | **Torn down before the merge:** 19 destroyed at 01:46 (E127). The local `aws/` state holds none of them (read 2026-11-08). Nothing from the branch is live |
| E150 | 2026-11-07 02:27 | `envs/bootstrap`, branch `feat/pipeline-secrets-keyvault` | Operator helper | 5: `rg-identity-lab-cicd`, Key Vault `kv-idlab-cicd-20f1`, audit setting, 2 reader grants | #240, 2026-11-08 17:46 (`e8e8213`) | **Code matches live, tfvars do not.** Read-only plan from `main`, 2026-11-08: with the owner's current `terraform.tfvars` it plans **10 to destroy** (these 5 and E153's 5). With the 5 values below added: **No changes** |
| E153 | 2026-11-07 02:42 | `envs/bootstrap`, branch `feat/azure-least-privilege` | Operator helper | 5: custom role Contoso Lab VM Operator, its PIM policy and eligibility, 2 CanNotDelete locks on the vaults | #246, 2026-11-08 18:02 (`cd4b5f1`) | Same plan as E150 |
| - | 2026-11-07 00:54 | `okta/` (PR #222) | Operator helper | Okta side of the clinic coexistence (ADR 0022) | #222 | Not re-planned in this record |

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
| E116-E118 | 2026-11-07 | AD tiering on DC01: admin tiers, Protected Users for new admins, Windows LAPS | `harden/ad-tiering` | **#225 OPEN** | **Not reconciled.** Live on DC01; the code is not on `main`. The capture-log rows are in #225 only |
| E140 | 2026-11-07 01:31 | AD FS steps 1-6 on DC01 (role, farm, gMSA, claim rules) | `adfs/dc01-run-and-connect-health` | #237 merged 2026-11-08 17:24 (`5c77d1f`) | Code on `main` now. Host state not re-read after the merge |
| E156 | 2026-11-07 | `t0-adm-01` password rotated after the #239 Tier 2 test exposed it | `ops/rotate-t0-adm-01` | **#251 OPEN** | **Not reconciled.** Rotation done; the tool is not on `main` |
| E157 | 2026-11-07 03:55 | `svc-pam-discovery` deleted on DC01 and in Key Vault (the first "dry run" acted: R28) | branch of #253 | #253 merged 2026-11-08 19:09 (`ecf7f2c`) | Code on `main`. The DC identity's Key Vault grant is replaced by that PR's apply (pending) |
| E178 | 2026-11-08 18:09 | `contosoadmin` rotated after the #239 exposure | `ops/rotate-contosoadmin` | #262 merged 2026-11-08 20:10 (`e7441e4`) | Code on `main` |
| E132 | 2026-11-07 01:48 | Key Vault state-leak proof in a throwaway resource group (deleted) | `feat/keyvault-state-leak` | #235 merged 2026-11-08 20:23 (`2d479fa`) | Throwaway objects deleted at the time |
| E133 | 2026-11-07 | Bastion Premium, its public IP, a PIM-eligible Reader and a reviewer grant, made by script (`lab/bastion/capture.sh`) | `feat/bastion-session-recording` | **#247 OPEN** | Live read 2026-11-08: no Bastion, no Bastion PIM eligibility, no Storage Account Key Operator grant. **Left over:** the recordings account `stbstreca9b511bc` (shared key now off) |
| - | 2026-11-08 | Cloud Sync mappings, the leave-date Lifecycle Workflow schedule, joiner v2 | `feat/leaver-lcw-leavedate` (stacked) | **#257 OPEN** | **Not reconciled.** Live in the tenant; not on `main` |

## What this means for the spoken lines

- "Nothing goes live until I approve it" was false. The lines now say: no
  **Terraform** change goes live without the owner's approval of its plan;
  DC01 scripts and three early branch applies ran outside that gate, and
  this file lists each one.
