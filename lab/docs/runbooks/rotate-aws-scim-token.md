# Runbook: rotate the AWS IAM Identity Center SCIM token

- **Status:** DESIGNED (written 2026-11-07; not yet run). The current token was
  stored in Key Vault on 2026-10-28 (`aws-scim-token`, `attributes.created`).
  AWS SCIM access tokens are valid for one year, so it is due by **2027-10-28**
  (`lab/iga/nhi-secrets-register.json`).
- **Owner role:** iam-engineering.
- **Why this runbook exists:** a hostile review (2026-11-06, finding H1) asked
  for the rotation story of every long-lived secret. This token is the one that
  breaks JML silently: when it expires, Entra can no longer create, update or
  disable users in AWS. Leavers then keep their AWS account until someone
  notices.
- **Who does it:** a person. The token is shown once in the AWS console. Key
  Vault's writers are human Secrets Officers by design, and the CI APPLY
  identity has no data-plane role on the vault (`modules/keyvault`). The lab
  operator holds only Key Vault Secrets User (read), so it cannot write the new
  value.

## When

1. **The monthly check warns.** `.github/workflows/secret-expiry.yml` runs on
   the 1st of each month. It fails when a secret expires within 60 days, so this
   token shows up by about 2027-08-29 at the latest.
2. **On any exposure**, at once. For example, a token pasted into a chat, a
   log, a ticket or argv.
3. **When the person who made it leaves**, within 7 days. The owner is a role,
   but the person who saw the token once has seen a working credential.

## Steps

1. **Book a window.** The provisioning cycle is about 40 minutes. Rotation does
   not stop sign-in, only user provisioning, and only between steps 4 and 6.
2. **Make a second token in AWS.** IAM Identity Center > Settings > Identity
   source > Automatic provisioning > Manage > Access tokens > Generate token.
   AWS allows two active tokens (verify: on the console), so the old token keeps
   working until step 7. Copy the token straight into the next step. Never
   paste it into a terminal command line, a chat or a file.
3. **Store it in Key Vault** as a new version of `aws-scim-token`, with an
   expiry one year out, so Key Vault also knows the date:
   `az keyvault secret set --vault-name kv-idlab-20f1 --name aws-scim-token --file /dev/stdin --expires <YYYY-MM-DDT00:00:00Z>`,
   then paste the token and press Ctrl-D. `--file /dev/stdin` keeps the value
   out of argv and shell history. Use a Secrets Officer session, not the
   operator.
4. **Write it to Entra** with the seeding apply that modules/apps documents
   (`lab/terraform/modules/apps/README.md`, "SCIM credential", step 6):
   export `TF_VAR_aws_scim_credentials` from Key Vault for this run only, then
   `terraform apply -replace='module.apps[0].azuread_synchronization_secret.aws[0]'`.
   The plan must show only that one replacement. The owner approves it.
5. **Test Connection** on the AWS enterprise app's Provisioning page. Expect
   success.
6. **Provision on demand** one test user (for example test-user-b). Expect
   "Update" or "No change", not an authorization error.
7. **Delete the old token** in AWS. From now on, any copy of the old token
   (Terraform state, an old Key Vault version) is useless.
8. **Disable the old Key Vault version** of `aws-scim-token`. Keep it for the
   audit trail, but it can no longer be read as current.
9. **Update the register** in a pull request: `createdOn` (the new Key Vault
   `attributes.created` date), `expiresOn` (+ P365D), and `dateSource`. The
   monthly check then goes green.
10. **Capture a row** in `lab/evidence/capture-log.csv`: date, the new
    `expiresOn`, Test Connection and the on-demand result. Never record the
    token, its length or any part of it.

## If it already expired

- **Symptom:** the provisioning job goes into quarantine with an
  authorization error, and new joiners do not appear in AWS.
- **Fix:** do steps 2-6 now. Then run **Restart provisioning** once, so the
  missed changes go through.
- **Leavers first:** until the job catches up, disable any AWS user whose
  Entra account is disabled. Do this by hand, in IAM Identity Center >
  Users. Then record what you did.

## Production difference

In production the token would sit in a vault with an expiry notification. AWS
also publishes an AWS Health event before a SCIM token expires (verify: the
event name and lead time). Route that event to the IAM team's queue, so there
are two independent warnings: the register check and AWS's own notice.
