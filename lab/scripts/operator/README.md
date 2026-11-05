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

## Turn it off

```bash
lab/scripts/operator/kill-switch.sh          # as yourself: disables it in Azure and AWS
lab/scripts/operator/kill-switch.sh --undo
```

## Set up or rotate (human, once every ~6 months)

1. `lab/scripts/operator/new-operator-cert.sh` — new key (Keychain) and
   public certificate (`~/.contoso-operator/operator.crt`), valid 179 days.
2. As the admin: `tofu -chdir=lab/terraform/envs/operator init -backend-config=storage_account_name=<sa>`,
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
