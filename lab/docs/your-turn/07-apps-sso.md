# 07 · Apps and single sign-on (stage `apps`)

Ran in the lab tenant on 2026-10-28 (stages `apps`, `servicenow`, `okta` in `turn`). What the first run taught, kept short:

- Step 2 is real: without the bootstrap app-management roles the apply gets 403s.
- The tenant's own 180-day key-credential policy rejects Entra's 3-year signing certificate: `saml_signing_cert_end_date` and `servicenow_saml_signing_cert_end_date` now live in `lab.tfvars` (PR #59).
- The gallery app ships with a Web redirect-URI set and the first apply leaves the Clinical Portal app behind: both are one-time `terraform import`s (PR #59 description).
- AWS shows the SCIM token once and the page splits it: copy it with the Copy button, then check it with `curl -H "Authorization: Bearer ..." <endpoint>/ServiceProviderConfig` (200) before Key Vault. A truncated token fails **Test Connection** with `SystemForCrossDomainIdentityManagementCredentialValidationFailure`.
- The seeding apply (step 15) must be targeted (`-target` the synchronization job and secret): a full local apply also tries to reconcile governance objects your user cannot read.
- Step 19 (the `aws/` root): once the identity source is Entra, the `idlab-admin` SSO profile cannot sign in. The first run created `ViewOnlyAccess` and the group assignment in the console instead (E24). Either apply `aws/` **before** step 12 with an Identity Center user, or accept the console path.
- ServiceNow: install *Integration - Multiple Provider Single Sign-On Installer* from the Application Manager first; the IdP record can be created by API from the Entra metadata (`sso_properties` / `saml2_update1_properties`, NameID unspecified, `user_name`), then `TF_SERVICENOW_SSO_SYS_ID` + an apply.
- ServiceNow, 2026-11-05: the instance switch (`glide.authenticate.multisso.enabled`) is refused until an Account Recovery user exists, and once it is on only recovery users sign in locally (password + authenticator code): the lab's is `acr.breakglass`, and the built-in `admin` stays API-only. A record made by API also needs *SSO Script* `MultiSSOv2_SAML2_custom` and an `idp_certificate` row for the Entra signing certificate (without it every sign-in fails: "Unable to locate the SAML 2.0 Certificate"). Accounts come from a second, hidden gallery app (`enable_servicenow_provisioning`) whose credential is written by a local seeding apply before the CI apply. All of it: `lab/terraform/modules/apps/README.md`, *ServiceNow side door* and *ServiceNow provisioning*.
- Okta: the tenant default app-management policy blocks client secrets. `okta_idp_client_secret_command` only works after a per-app exception policy (one `passwordAddition` allowance, 180-day lifetime) is assigned to `okta-clinic-idp`; the Okta root apply then needs `OKTA_API_TOKEN` and `TF_VAR_entra_client_secret` in the shell only.

The `apps` stage is added to `turn` when it is first built.

**What you build:** one front desk for other buildings. AWS IAM Identity Center
trusts Entra for sign-in (SAML) and gets its accounts from Entra (SCIM), and the
Contoso Clinical Portal signs people in with OIDC and three roles. Entra
decides who gets in; AWS decides what they get.

**Whisperglass:** *Contoso 04 · Apps*.

**Starts from:** `turn where` says `dc`, and run sheet 06 is done: Dana holds
**Nurse - Clinical Apps**, which puts her in `App-AWS-IdentityCenter-Users`.
(That is how the first run went. Nurses no longer get AWS: on a rebuild, use
a cloud engineer holding **IT - Cloud Engineering Apps** wherever this sheet
says Dana.)

**Heads-up:** step 2 gives the pipeline's APPLY identity a second Tier-0
permission (`AppRoleAssignment.ReadWrite.All`, ADR 0005). AWS shows the SCIM
token only once: have Key Vault ready and keep it off camera.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 04*. | the lab map | the apps station: AWS IAM Identity Center, ServiceNow, Okta |
| 2 | Off camera, widen the pipeline first. In `lab/terraform/envs/bootstrap/terraform.tfvars` set `enable_app_management_roles = true`. Then, with `<state account>` from `gh variable get TFSTATE_STORAGE_ACCOUNT`: `az lock delete -n lock-tfstate-readonly -g rg-identity-lab-tfstate --resource <state account> --resource-type Microsoft.Storage/storageAccounts`, `terraform -chdir=lab/terraform/envs/bootstrap apply`, `az lock create -n lock-tfstate-readonly --lock-type ReadOnly -g rg-identity-lab-tfstate --resource <state account> --resource-type Microsoft.Storage/storageAccounts` | the terminal | the plan adds four Graph roles for APPLY and two read roles for PLAN; type `yes`; the lock is back. Do not run `after-signup.sh` step B for this: it rewrites the file with the flag off. |
| 3 | `turn pr apps` | the terminal | `enable_sso_apps` `false -> true` (verify: any other flag the stage carries), then the mocked test passing |
| 4 | Press **Enter**, wait for green checks, show the **Terraform plan** comment | the PR | the AWS IAM Identity Center app with its signing certificate, claims policy and one group assignment; the Contoso Clinical Portal with its roles |
| 5 | **Merge pull request**, **Confirm merge** | the PR | "Merged" |
| 6 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the issue closes as approved; the apply ends in a green tick |
| 7 | `turn outputs` | the terminal | `saved (... bytes)` |
| 8 | Activate the signing certificate: `terraform -chdir=lab/terraform/envs/dev output -raw aws_saml_signing_cert_activation_command` prints one `Update-MgServicePrincipal` line. In `pwsh`: `Connect-MgGraph -TenantId <tenant id> -Scopes Application.ReadWrite.All`, then run that line | the terminal | no error; the app's new certificate is the active one (verify: where the portal shows it) |
| 9 | AWS console: **IAM Identity Center → Settings → Identity source → Actions → Change identity source → External identity provider**. Keep the page open | the AWS console | **Service provider metadata**: the Issuer URL, the ACS URL and the access portal URL |
| 10 | Save them as repo variables: `gh variable set TF_AWS_SAML_ENTITY_ID --body '<Issuer URL>'`, `gh variable set TF_AWS_SAML_ACS_URLS --body '["<ACS URL>"]'`, `gh variable set TF_AWS_ACCESS_PORTAL_URL --body '<access portal URL>'` | the terminal | no errors |
| 11 | Re-run the apply so it picks them up: `turn open actions`, **terraform-apply**, **Run workflow**, then `turn approve` and `turn watch` | GitHub Actions (verify: the click path), then the terminal | a green tick; the AWS app now has its Identifier and Reply URL |
| 12 | `terraform -chdir=lab/terraform/envs/dev output -raw aws_federation_metadata_url`: open it and save the file. On the AWS page: **IdP SAML metadata**, upload the file, type `ACCEPT`, **Change identity source** | the AWS console | the identity source is now the external identity provider (verify) |
| 13 | AWS: **Settings → Automatic provisioning → Enable**. Off camera, put the **SCIM endpoint** and the **access token** straight into Key Vault: `az keyvault secret set --vault-name <kv> --name aws-scim-tenant-url ...` and `--name aws-scim-token ...` | the AWS console, then the terminal | Key Vault holds both names. The token never goes into the repo or a variable. |
| 14 | `terraform -chdir=lab/terraform/envs/dev output -raw aws_scim_template_lookup_command`; run the printed line in `pwsh` (verify: the Graph scopes it needs). Then `gh variable set TF_AWS_SCIM_TEMPLATE_ID --body '<id>'` | the terminal | one `id` and its `factoryTag` (verify: the id) |
| 15 | The SCIM seeding apply, locally (the Key Vault firewall admits only you). In your copy, set `enable_scim_provisioning = true` in `lab/terraform/envs/dev/lab.tfvars`, and put `aws_saml_entity_id`, `aws_saml_acs_urls`, `aws_access_portal_url` and `aws_scim_template_id` in `lab/terraform/envs/dev/terraform.tfvars` so this apply matches the pipeline (verify). Then run the block under *SCIM credential*, step 2, in `lab/terraform/modules/apps/README.md` | the terminal | the plan creates the provisioning job, **stopped**, and its credential (shown as sensitive); the apply succeeds; `unset` clears the token from the shell |
| 16 | **Enterprise applications → AWS IAM Identity Center → Provisioning**: **Test Connection**, then **Provision on demand** for Dana | the Entra admin center (verify: the click path) | each step succeeds: import, scope, match, action **Create** (E23) |
| 17 | AWS: **IAM Identity Center → Users**, then **Groups** | the AWS console (verify: the click path) | Dana and `App-AWS-IdentityCenter-Users`, created by SCIM |
| 18 | Open a PR that commits `enable_scim_provisioning = true` and `aws_scim_job_enabled = true` in `lab.tfvars` (verify: this may become its own `turn` stage). Merge, `turn approve`, `turn watch` | the PR, then the terminal | a green tick; the job now runs on its own, about every 40 minutes |
| 19 | The AWS permission set, a human apply: `cd lab/terraform/aws`, `aws sso login --profile idlab-admin`, `terraform init`, `terraform plan -out aws.tfplan`, `terraform apply aws.tfplan` | the terminal | `3 to add`: the `ViewOnlyAccess` permission set with a 4-hour session, its policy, and the group's account assignment (E24) |
| 20 | As Dana, in a private window: **myapps.microsoft.com → AWS tile → access portal → the account → ViewOnlyAccess** | the browser | the AWS console opens. Listing works; creating anything, an S3 bucket say, is **AccessDenied** (E22, E24) |
| 21 | Entra sign-in logs, filtered on the AWS IAM Identity Center app | Dana's sign-in (verify: the click path) | **Basic info**, and the **Conditional Access** tab with the policies that applied (E22) |
| 22 | **Enterprise applications → Contoso Clinical Portal** | the app (verify: the click path) | assignment required; three roles: Clinician, Pharmacist, Auditor |
| 23 | Read the Proof part | | |

## Say this, in your own words

- One front desk: nobody gets a second password for a second building.
- Each app is assigned exactly one group. That one assignment is both who may
  sign in and who gets an AWS account: provisioning only sees who is assigned.
- Claims are code: the sign-in name is pinned to the same value SCIM sends, so
  the two can never drift apart.
- The department travels in every sign-in, so a mover's new tag reaches AWS at
  their next session.
- The AWS token never goes near the pipeline: AWS to Key Vault to one local
  apply.
- ServiceNow and the clinic's Okta trust the same front desk. ServiceNow also
  gets its accounts from Entra, through a second app that only provisions and
  is assigned the same group, so who may sign in and who has an account never
  drift apart.

## If something goes wrong

| What you see | Do this |
|---|---|
| The apply fails with 403 on applications or app role assignments | Step 2 is missing. Do it, wait two minutes, then **Re-run failed jobs**. |
| The plan says `enable_scim_provisioning = true needs aws_scim_template_id` | Step 14: the template id, as a repo variable and in your local `terraform.tfvars`. |
| The PR apply in step 18 fails on the SCIM credential | The local seeding apply (step 15) must come first. The gated apply refuses to create the credential without it. |
| Dana's AWS sign-in fails | Check the certificate was activated (step 8) before the metadata was uploaded (step 12), and that Dana exists in AWS (step 17). |
| **Test Connection** fails | The token was copied wrong. Make a new one in AWS, update Key Vault, then follow *Rotation* under *SCIM credential* in `lab/terraform/modules/apps/README.md`. |
| The `aws` plan fails: no Identity Center instance | `aws_region` in `lab/terraform/aws/terraform.tfvars` is not the instance's region. |
| Someone outside the group is refused at the AWS tile | Expected: assignment is required. |

## Do it again

Once `apps` is a stage (verify): `lab/scripts/demo/rewind-lab.sh dc --open-pr`,
merge, do the cleanup it prints, then start from step 3. AWS keeps its
settings, the repo variables stay set and Key Vault keeps the token, so steps 9
to 11 and 13 can be skipped. The app and its certificate are new, so do steps
8, 12 and 14 to 18 again (verify). `terraform destroy` in `lab/terraform/aws`
removes the AWS grant.
