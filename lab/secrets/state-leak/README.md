# Key Vault secrets and Terraform state: the leak, measured

**The finding.** Terraform is the lab's blueprint tool. The usual way to hand
it a secret from Azure Key Vault is the azurerm provider's
`azurerm_key_vault_secret` **data source**. Terraform keeps every data source
result in its state file, `terraform.tfstate`. So the secret ends up in that
file in plaintext, even when nothing uses the value. Marking things
`sensitive` only hides them on screen, not in the file. The fix is the
provider's `azurerm_key_vault_secret` **ephemeral resource** (Terraform
1.10+). An ephemeral resource is read for one run and never written to state
or to a plan file.

> **Status: RAN · tenant.** `run.sh` ran on the lab Mac on 2026-11-07 as the
> lab operator, against a real Key Vault that it created in the lab
> subscription and deleted afterwards (HashiCorp Terraform 1.16.5, provider
> `hashicorp/azurerm` 4.81.0, the version `envs/dev` pins). Record:
> [`lab/evidence/keyvault-state-leak/20261107T014803Z/`](../../evidence/keyvault-state-leak/20261107T014803Z/run.txt)
> (capture log E132). It uses a random value, never a real credential.
> Nothing in the lab's own Terraform reads a Key Vault secret with a data
> source.

This replaces the Conjur version of the same measurement (PR #210, capture
log L08). The lab dropped CyberArk on 2026-11-06
([ADR 0036](../../docs/adr/0036-microsoft-native-pam.md)). The numbers are
the same, because the cause is in Terraform, not in the vault.

## Result

Times the random 40-character value appears in each file (2026-11-07 run):

| Path | `terraform.tfstate` | `terraform.tfstate.backup` | saved plan (`plan -out`) | Terraform's screen output |
|---|---|---|---|---|
| `datasource/` (data source) | **1** | **1** | **2** | 0 |
| `ephemeral/` (ephemeral resource) | 0 | 0 | 0 | 0 |

- The leak is also in the **backup** and in **saved plan files**. A CI job
  that keeps its plan as an artifact keeps the secret with it.
- The ephemeral path really did read the value. A precondition checks its
  length. A plan told to expect the wrong length fails on that precondition
  first. So "0" means "read and not kept", not "never read".
- Neither path printed the value on screen. That is why the leak is easy to
  miss: the console looks clean while the file holds the secret.

## Timings (2026-11-07 run, for the script)

| Step | Time |
|---|---|
| Create the resource group and the vault | 38 s |
| RBAC takes effect, value stored | 5 s |
| Data source path (init, 2 applies, saved plan) | 59 s |
| Negative control (wrong length must fail) | 10 s |
| Ephemeral path (init, 2 applies, saved plan) | 50 s |
| Delete the group, purge the vault, read back | 75 s |
| **Total** | **239 s (4 min)** |

## Run it

**Needs an operator write session (since ADR 0030, 2026-11-08).** Between
sessions the operator is read-only. The vault and the operator's grant on it
are created in the sandbox resource group `rg-lab-sandbox`, where a session
gives the operator Contributor plus an RBAC Administrator limited to data
roles (`envs/operator/sandbox.tf`, PR #249). Without a session, the script
stops before creating anything. The 2026-11-07 run below predates ADR 0030:
it used its own throwaway resource group under the operator's then Owner
role.

```bash
lab/scripts/operator/op bash lab/secrets/state-leak/run.sh
TF_BIN=/path/to/terraform lab/scripts/operator/op bash lab/secrets/state-leak/run.sh
KEEP=1 lab/scripts/operator/op bash lab/secrets/state-leak/run.sh   # keep the vault to look around; delete it yourself
python3 -I -m unittest discover -s lab/secrets/state-leak/tests -v   # the counter's tests (offline)
```

Needs az, openssl, python3 and HashiCorp Terraform 1.10 or later. OpenTofu is
refused, because the lab's CI runs Terraform. It refuses any subscription or
tenant other than the lab's. Exit 0 means every number in the table held.
Exit 1 means one did not, and the script says which. Exit 2 means it could
not run.

What it does:

1. It checks that the session's two sandbox grants are active, then creates
   a vault `kv-stateleak-<random>` in `rg-lab-sandbox`, tagged. The vault uses
   **Azure RBAC** for access (no access policies). Purge protection is off,
   so the script can purge it.
2. It gives the operator **Key Vault Secrets Officer** on that one vault. It
   waits until RBAC takes effect, then stores a random value from a 0600
   file (`--file`, never a command-line argument). Every `az` call that
   could echo the value runs with `-o none`.
3. It runs both Terraform folders: init with the committed lock file, apply,
   apply with a change (so a backup is written), and plan to a file. Then it
   counts the value in every file Terraform wrote
   ([`count_secret.py`](count_secret.py)).
4. It removes the operator's grant, deletes and purges the vault, and reads
   back that it is gone (neither listed nor soft-deleted). A soft-deleted
   vault would otherwise stay for 7 days. The sandbox group stays.

Cost: well under $0.01 per run (Key Vault Standard: $0.03 per 10,000
operations, Azure retail price list, 2026-11-07).

CI runs the static half only: `terraform fmt`, `terraform validate` and the
counter's tests. The measurement creates Azure objects, and CI holds no
identity that may write to the sandbox.

## Lessons for policy and pipelines

1. **Do not read secrets with data sources.** Use `ephemeral
   "azurerm_key_vault_secret"` wherever the value only feeds a provider
   configuration or a write-only argument.
2. **An ephemeral resource is read during plan.** The secret must already
   exist before the plan that reads it. Create it in a separate
   configuration or an earlier run.
3. **If a data source is unavoidable, the state is a secret.** That means a
   locked, encrypted, access-controlled backend, no state or plan files in CI
   artifacts, and rotation if a state file leaks. The lab's own Terraform
   already works this way for its `random_password` values
   ([`lab/terraform/README.md`](../../terraform/README.md)).
4. **Grant on the vault, for reading only.** A pipeline that only reads gets
   **Key Vault Secrets User** on its own vault. People get write access
   (Secrets Officer) only through a PIM activation (see PR #232 for the
   eligible path on the lab vault).
