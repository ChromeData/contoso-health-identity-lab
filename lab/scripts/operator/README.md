# Lab operator

The identity the lab's unattended admin work runs as, instead of the admin's
own account (decision and risk: [ADR 0024](../../docs/adr/0024-lab-operator-workload-identity.md),
risk register R18). One certificate, kept in the Mac's login Keychain, signs
in to Azure directly and to AWS through Entra.

## Every day

```bash
lab/scripts/operator/op az ad sp list --display-name gh-oidc -o table
lab/scripts/operator/op tofu -chdir=lab/terraform/envs/bootstrap plan
lab/scripts/operator/op aws sts get-caller-identity
```

`op` signs in when needed and runs one command as the operator. It never
touches your own `az login` (the operator has its own az profile in
`~/.contoso-operator/azure`).

## Write sessions (ADR 0030)

Every day the operator can only READ (Graph reads, Azure Reader, the state
data role, Key Vault Secrets User). Work that writes (demo resets, TAPs,
group changes, Key Vault secret writes, `az vm run-command`, bootstrap
applies) needs a **write session**. Only the owner opens one, signed in as
himself, never as the operator:

```bash
# open: at most 8 hours, with a reason
tofu -chdir=lab/terraform/envs/operator apply \
  -var 'operator_write_session={opened_utc="2026-11-07T14:00:00Z",expires_utc="2026-11-07T18:00:00Z",reason="recording day: demo resets"}'
# close: same root, no session variable
tofu -chdir=lab/terraform/envs/operator apply
```

The Azure part ends at `expires_utc` by itself (time-bound PIM). The Graph
part ends only with the closing apply: close in the same sitting.
`envs/bootstrap` role-assignment changes are owner applies again (the
operator has no Owner).

## Turn it off

```bash
lab/scripts/operator/kill-switch.sh          # as yourself: disables it in Azure and AWS
lab/scripts/operator/kill-switch.sh --undo
```

## Set up or rotate (human, once every ~6 months)

1. `lab/scripts/operator/new-operator-cert.sh` — new key (Keychain) and
   public certificate (`~/.contoso-operator/operator.crt`), valid 179 days.
2. As the owner (never as the operator, ADR 0030): `tofu -chdir=lab/terraform/envs/operator init -backend-config=storage_account_name=<sa>`,
   then `apply` with `terraform.tfvars` from the example.
3. As an AWS admin: in `lab/terraform/aws`, set `enable_entra_operator = true`
   and the three ids from step 2's outputs, then
   `tofu apply -target=aws_iam_openid_connect_provider.entra -target=aws_iam_role.entra_operator -target=aws_iam_role_policy_attachment.entra_operator_admin -target=aws_iam_role_policy.entra_operator_guardrails`.
4. `lab/scripts/operator/save-config.sh lab/terraform/envs/operator lab/terraform/aws`
5. `lab/scripts/operator/lab-signin.sh` — must print the operator in the lab
   tenant and AWS account 182002546409.

## Files

| File | What it does |
|---|---|
| `new-operator-cert.sh` | Makes the key and certificate; key to the Keychain over stdin |
| `save-config.sh` | Writes the ids (nothing secret) to `~/.contoso-operator/config` |
| `lab-signin.sh` | Signs in to Azure with the certificate, sets up the AWS profile `idlab-operator`, checks both |
| `aws-credentials.sh` | AWS `credential_process`: Entra token → one-hour STS session |
| `op` | Runs one command as the operator |
| `lab-signout.sh` | Ends the session and deletes the session key copy |
| `kill-switch.sh` | Disables the operator in both clouds |

## The bot: a separate GitHub identity for AI coding agents (karen-review A1)

Agents must not push, open PRs or merge as the owner's login (ChromeData),
or GitHub cannot tell the author from the approver. `github-bot/` gives them
a GitHub App identity, `<slug>[bot]`.

1. **Owner, once:** `lab/scripts/operator/github-bot/new-bot-app.sh`. It opens
   github.com with the App manifest; you click "Create GitHub App". The key
   goes into Keychain item `contoso-lab-bot-key`; ids go to
   `~/.contoso-operator/bot.env`. Then install the App on this repo only
   (the script prints the link). An agent must not run this step.
2. **Agents, every time:** `github-bot/bot-gh push <branch>`,
   `bot-gh gh pr create ...`, `bot-gh gh pr merge ...`,
   `bot-gh git commit ...` (bot as author). The token lives 1 hour, is
   scoped to this repo, and is never in argv or printed.
3. **Owner, at a PR merge:** set repo Variable `APPLY_BOT_LOGIN` to
   `<slug>[bot]`. The apply gate then enforces the split (see
   `lab/pipelines/README.md`, section 3).

The App has no Azure, Entra or AWS rights. GitHub roles and Entra roles are
separate systems. Tests: `.github/scripts/tests/test_bot_gh.py` (stubs only).
