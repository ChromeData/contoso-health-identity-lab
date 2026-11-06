# Conjur secrets and Terraform state: the leak, measured

**The finding.** The obvious way to hand Terraform a secret from Conjur is the
provider's `conjur_secret` **data source**. Terraform keeps every data source
result in `terraform.tfstate`, so the secret ends up in that file in
plaintext. That happens even when nothing uses the value as an output or a
resource argument. Marking things `sensitive` only hides them on screen, not
in the file. The intuitive wiring moves the credential from one plaintext file
to another. The fix is the provider's `conjur_secret` **ephemeral resource**
(Terraform 1.10+, provider 0.8.2+), which Terraform never writes to state or
to a plan file.

> **Status: RAN · harness.** `run.sh` ran on the lab Mac on 2026-11-06
> (HashiCorp Terraform 1.16.5, provider `cyberark/conjur` 0.9.15, Conjur OSS
> 1.27.0 in Docker), record
> [`lab/evidence/conjur-state-leak/20261106T071613Z/`](../../../evidence/conjur-state-leak/20261106T071613Z/run.txt)
> (capture log L08), and it runs on every pull request in `lab-tests.yml`.
> It uses a throwaway local Conjur and a random value. It has **not** run
> against Conjur Enterprise / CyberArk Secrets Manager, and nothing in the
> lab's own Terraform reads Conjur.

## Result

Times the random 40-character value appears in each file (2026-11-06 run):

| Path | `terraform.tfstate` | `terraform.tfstate.backup` | saved plan (`plan -out`) | Terraform's screen output |
|---|---|---|---|---|
| `datasource/` (data source) | **1** | **1** | **2** | 0 |
| `ephemeral/` (ephemeral resource) | 0 | 0 | 0 | 0 |

- The leak is in the **backup** and in **saved plan files** too, not only in
  the state file. A CI job that keeps its plan as an artifact keeps the
  secret with it. (The earlier lab left the backup as an open question; this
  answers it.)
- The ephemeral path really did read the value: a precondition checks its
  length, and a plan told to expect the wrong length fails on that
  precondition first. So "0" means "read and not kept", not "never read".
- Neither path printed the value on screen. That is why the leak is easy to
  miss: the console looks clean while the file holds the secret.

## Run it

```bash
bash lab/pam/conjur/state-leak/run.sh            # ~30 s once the images are pulled
TF_BIN=/path/to/terraform bash lab/pam/conjur/state-leak/run.sh
KEEP=1 bash lab/pam/conjur/state-leak/run.sh     # keep Conjur and the work folder to look around
python3 -I -m unittest discover -s lab/pam/conjur/state-leak/tests -v   # the counter's tests
```

Needs Docker, curl, openssl, python3 and HashiCorp Terraform 1.10 or later.
OpenTofu is refused (the lab's CI runs Terraform). Exit 0 means every number in the
table above held (the data source's three files each hold the value, the
ephemeral path's are all clean and present, nothing was printed). 1 means
one did not, and the script says which. 2 means the script could not run.
That includes finding a `contoso-stateleak` stack already there, which it
leaves alone. The compose project name is pinned, so an exported
`COMPOSE_PROJECT_NAME` cannot point it at another stack.

What it does: it starts its own Conjur (compose project `contoso-stateleak`,
on 127.0.0.1:8093, separate from the `lab/pam` stack) and loads
[`policy.yml`](policy.yml): one variable and one runner host allowed to read
it through a layer. It stores a random value and checks the runner can fetch
it. Then it runs both Terraform folders (init with the committed lock file,
apply, apply with a change, plan to a file) and counts the value in every
file Terraform wrote ([`count_secret.py`](count_secret.py)). Finally it
deletes Conjur, its volume and the work folder. The value, the API keys and
the tokens never appear on a command line or on screen: they go to curl on
stdin or through a 0600 header file, and to Terraform as `CONJUR_*`
environment variables.

## Lessons for policy and pipelines

1. **Do not read secrets with data sources.** Use `ephemeral
   "conjur_secret"` (and ephemeral resources in general) wherever the value
   only feeds a provider configuration or a write-only argument.
2. **An ephemeral resource is read during plan.** The provider's docs say
   `depends_on` does not delay it, so the secret must already exist before
   the plan that reads it. Create it in a separate configuration or an
   earlier run.
3. **If a data source is unavoidable, the state is a secret.** That means a
   locked, encrypted, access-controlled backend, no state or plan files in CI
   artifacts, and rotation if a state file ever leaks. The lab's own
   Terraform already works this way for its `random_password` values
   ([`lab/terraform/README.md`](../../../terraform/README.md)).
4. **Grant through a layer, and read only.** The runner host gets `read` +
   `execute` on one variable through the `runners` layer. A second runner
   is one `!grant`.
5. **From the earlier lab, not re-run here** (Conjur OSS 1.24, 2026-08-12):
   a `!permit` that spans two policy branches cannot be declared inside
   either branch (a relative id is not found; an absolute id is rejected as
   "Illegal absolute id"). It has to be loaded at root. That is also the
   better shape for review: "who can read this secret" has one answer, in
   one file.

## What is not ported

The earlier Conjur-Terraform-AWS lab also built a VPC, a bastion and an IAM
user with long-lived access keys, and used Summon to inject those keys. None
of it is ported: this lab gives people AWS access through Entra and IAM
Identity Center
([ADR 0025](../../../docs/adr/0025-aws-admin-just-in-time-through-entra.md)),
not through IAM users.
The ephemeral resource now does what Summon did there, inside Terraform.
