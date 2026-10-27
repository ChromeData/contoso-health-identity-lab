# modules/apps — SSO and provisioning as code

**No stand-in.** This module builds real Entra objects for the real AWS IAM
Identity Center connector and a ServiceNow developer instance, and a real
OIDC app registration.

**Status: BUILT** (AWS SAML + SCIM, ServiceNow SAML, Clinical Portal OIDC,
guacamole-psm, okta-clinic-idp; `validate` and 46 mocked `terraform test`
runs pass, 2026-10-26). **DESIGNED:** ServiceNow provisioning (below).
**Nothing in it has run against a tenant yet.** Everything below comes from
`terraform validate`, the mocked `terraform test` in `tests/`, provider
source, or Microsoft and AWS documentation. Anything not yet proven is
marked *verify:*. The tenant-time list at the end is the evidence to capture
during the trial.

| # | What | Resources | Staging |
|---|---|---|---|
| 1 | **AWS IAM Identity Center, SAML.** Gallery app, SAML mode, assignment required, Identifier and Reply URL, an Entra-minted signing certificate, a claims-mapping policy (NameID plus ABAC session tags), and **one** assignment: `App-AWS-IdentityCenter-Users` | `azuread_application_from_template`, `azuread_service_principal` (`use_existing`), `azuread_application_identifier_uri`, `azuread_application_redirect_uris`, `azuread_service_principal_token_signing_certificate`, `azuread_claims_mapping_policy` + assignment, `azuread_app_role_assignment` | envs/dev `enable_sso_apps` |
| 2 | **AWS IAM Identity Center, SCIM.** Provisioning job, created **stopped**, and its credential from Key Vault | `azuread_synchronization_job`, `azuread_synchronization_secret` | envs/dev `enable_scim_provisioning`; the job starts only when `aws_scim_job_enabled` is set |
| 3 | **Contoso Clinical Portal, OIDC.** App roles Clinician, Pharmacist and Auditor; a `Clinical.Read` scope; a groups claim limited to app-assigned groups; assignment required; group-to-role grants | `azuread_application`, `azuread_application_identifier_uri`, `azuread_service_principal`, `azuread_app_role_assignment`, optional `azuread_application_pre_authorized` | envs/dev `enable_sso_apps` |
| 4 | **guacamole-psm, OIDC sign-in for the PSM stand-in** ([`guacamole.tf`](guacamole.tf)). Implicit **id_token only** (Guacamole 1.6's OpenID extension), no client secret, redirect `http://localhost:8081/guacamole/`, assignment required, **one** assignment: the new `PAM-Operators` group. Replaces the portal click-path in `lab/pam/README.md` §6 | `azuread_group`, `azuread_application`, `azuread_service_principal`, `azuread_app_role_assignment` (default access role) | envs/dev `enable_pam_oidc_app` (needs `enable_sso_apps`) |
| 5 | **ServiceNow, SAML** ([`servicenow.tf`](servicenow.tf)). Non-gallery SAML app with the settings Microsoft's ServiceNow tutorial documents, assignment required, an Entra-minted signing certificate, NameID = UPN, and **one** assignment: `App-ServiceNow-Users`. Provisioning is DESIGNED, not built ([below](#servicenow-pdi-saml)) | `azuread_application_from_template` (non-gallery template), `azuread_service_principal` (`use_existing`), `azuread_application_identifier_uri`, `azuread_application_redirect_uris`, `azuread_service_principal_token_signing_certificate`, `azuread_claims_mapping_policy` + assignment, `azuread_app_role_assignment` | envs/dev `enable_servicenow_sso` (needs `enable_sso_apps` and `servicenow_instance_url`) |
| 6 | **okta-clinic-idp, OIDC: Entra as the identity provider for the acquired clinic's Okta org** ([`okta.tf`](okta.tf)). Single tenant, implicit grants off, **one** redirect URI (the Okta authorize callback on `okta_org_domain`, https by construction), the Graph scopes Okta asks for declared, assignment required, **one** assignment: `App-Okta-Federation-Users`. The client secret is NOT created: a human mints it post-apply, bounded to 180 days ([below](#okta-coexistence-entra-side)). The Okta half is the human-applied root [`../../okta`](../../okta/README.md) | `azuread_application`, `azuread_service_principal`, `azuread_app_role_assignment` (default access role) | envs/dev `enable_okta_federation` (needs `enable_sso_apps` and `okta_org_domain`); ADR 0022 |

Provider: **azuread `~> 3.10`** (checked against 3.10.0 source and schema).
No other provider is used. App-role and scope ids are fixed GUIDs, and Entra
holds the signing certificate's private key.

---

## The design decisions, and why

- **Entra decides who reaches AWS. AWS decides what they get.** The one
  assignment on the AWS app does two jobs. It is the SSO gate, and it is the
  SCIM scope, because provisioning syncs assigned principals only.
  [`lab/terraform/aws`](../../aws/README.md) then grants that group a
  permission set. Adding a second principal is deliberately a code change
  (a new SCIM scope and a new AWS principal), not one more list element.
- **`azuread_application_from_template`, not `azuread_application` with
  `template_id`.** The first resource manages nothing on the objects it
  creates, so Terraform can never strip the template's `User` and
  `msiam_access` app roles. Graph says not to modify or remove those.
- **The adopted service principal sets every attribute explicitly.** With
  `use_existing`, the provider PATCHes the whole object from config (read in
  the 3.10.0 source). An unset `app_role_assignment_required` would be sent as
  `false`, letting any user in the tenant get a token. An unset `tags` would be
  sent empty, and the app would drop out of Enterprise applications. Both are
  pinned, and the mocked test asserts both.
- **The Reply URL replaces the template's wildcard.** The template ships
  `https://*.signin.aws.amazon.com/platform/saml/acs/*`. After apply, Entra
  posts assertions only to this Identity Center instance. Wildcards are
  rejected at plan.
- **Claims are code.** A claims-mapping policy supersedes the portal's
  *Attributes & Claims* blade, which becomes read-only. NameID is pinned to
  `userPrincipalName`, the value the connector's default mapping sends as the
  SCIM `userName`. If the two ever differ, every AWS sign-in fails. So the
  claims are protected from a well-meant portal edit.
- **ABAC comes from SAML, not SCIM.** `Department` is sent as
  `https://aws.amazon.com/SAML/Attributes/AccessControl:Department` on every
  sign-in. AWS documents that an attribute *removed* in Entra is not removed
  from the SCIM-synced user, so a SCIM-sourced tag can go stale. Sent per
  sign-in, a mover (Nursing → ICU) carries the new tag at their next AWS
  session.
- **The OIDC app's groups claim is `ApplicationGroup`.** Only groups assigned
  to the app are emitted. That keeps tokens small (no 200-group overage) and
  tells the app nothing about unrelated memberships.
- **Roles are user-only and fixed.** `allowed_member_types = ["User"]`, so
  there are no app-only (daemon) grants. Role ids are GUIDs that never change,
  because tokens and assignments key off them. Clinician and Pharmacist are
  the same separation-of-duties pair as the Nurse and Pharmacy access
  packages.
- **The implicit flow stays off.** Demos decode a real access token from the
  CLI instead (see *Demo* below).
- **Every app has a human owner.** The applying identity is always an owner,
  which `Application.ReadWrite.OwnedBy` requires, alongside
  `app_owner_object_ids`. A `check` warns on every plan without a human
  owner, and `nhi_inventory` exports owner and credential expiry for the NHI
  evidence pack.

---

## Staged order (tenant time)

Each stage is its own PR, so one reviewer sees one change.

| Stage | Who | What | Evidence to capture |
|---|---|---|---|
| 0 | done offline | Module, tests, wiring contract | `terraform test` output |
| 1 | PR → CI apply | `enable_sso_apps = true` (needs `enable_premium`). Creates both apps, the signing certificate, claims policy and assignments. The AWS app **cannot sign anyone in yet**: no Identifier, which fails closed. | Plan comment; Enterprise apps list |
| 1a | operator | **Activate the signing certificate**: run the `aws_saml_signing_cert_activation_command` output (`Update-MgServicePrincipal … -PreferredTokenSigningKeyThumbprint …`). azuread 3.10 cannot set `preferredTokenSigningKeyThumbprint`, and Graph requires it. | Screenshot of the active certificate |
| 2 | operator, AWS console | *IAM Identity Center → Settings → Identity source → Change identity source → External identity provider.* Copy the **Issuer URL**, **ACS URL(s)** and **access portal URL** from *Service provider metadata*. AWS shows them before you commit. | — |
| 2a | PR → CI apply | Set `aws_saml_entity_id`, `aws_saml_acs_urls` and `aws_access_portal_url` (`TF_VAR_`/`terraform.tfvars`; tenant values, never `lab.tfvars`). | Plan comment |
| 2b | operator, AWS console | Upload the Entra metadata from output `aws_federation_metadata_url` under *IdP SAML metadata*, type `ACCEPT`, then *Change identity source*. | AWS settings page |
| 3 | operator | Dana (a member of the App group): My Apps → AWS IAM Identity Center → access portal. Before SCIM, she must already exist in AWS. Either finish Stage 4 first, or create her by hand once and delete her afterwards. | SAML trace: NameID and `AccessControl:Department` |
| 4 | operator, AWS console | *Settings → Automatic provisioning → Enable.* Put the **SCIM endpoint** and **access token** straight into Key Vault: `az keyvault secret set --vault-name <kv> --name aws-scim-tenant-url …` and `--name aws-scim-token …`. AWS shows them once. | — |
| 4a | operator | Run the `aws_scim_template_lookup_command` output. Put the returned `id` in `aws_scim_template_id`. *verify:* the id. | Command output |
| 4b | operator, local apply | `enable_scim_provisioning = true`. Run the **seeding apply locally**, where the Key Vault firewall admits you (*SCIM credential* below). It creates the job, **stopped**, and writes the credential once. | Plan/apply log (token redacted) |
| 4c | operator, portal | *Provisioning → Test Connection*, then **Provision on demand** for Dana. *verify:* on-demand works while the job is stopped. | Provisioning log entry |
| 4d | PR → CI apply | `aws_scim_job_enabled = true`, which starts the ~40-minute cycle. | Provisioning logs; AWS Users "Created by SCIM" |
| 5 | operator | Apply [`lab/terraform/aws`](../../aws/README.md): the permission set on the SCIM-created group. | `aws sso-admin list-account-assignments` |
| 6 | operator | Leaver: `04-Leaver.ps1 -ProvisionOnDemandApps 'AWS IAM Identity Center'`. The name matches `aws_app_display_name`. | Leaver CSV; AWS user disabled |

---

## SCIM credential

The AWS token is a real credential. It is shown once and is valid for one
year (*verify:*). It is handled like this:

1. **System of record: Key Vault.** The secrets are `aws-scim-tenant-url` and
   `aws-scim-token`. Nothing goes in git, `lab.tfvars` or GitHub variables.
2. **Only the run that creates the credential reads it.**
   ```bash
   export TF_VAR_aws_scim_credentials="$(jq -n \
     --arg u "$(az keyvault secret show --vault-name <kv> --name aws-scim-tenant-url --query value -o tsv)" \
     --arg t "$(az keyvault secret show --vault-name <kv> --name aws-scim-token     --query value -o tsv)" \
     '{tenant_url:$u, secret_token:$t}')"
   export TF_VAR_require_scim_credentials=true
   terraform apply -var-file=lab.tfvars     # in envs/dev, as the documented local deployment
   unset TF_VAR_aws_scim_credentials
   ```
   It runs locally because the Key Vault firewall admits only the operator IP
   and the private endpoint. GitHub-hosted runners cannot reach it, and the
   lab does not punch a hole for them.
3. **PR plans never see it.** The PLAN identity has no vault access, by
   design: anyone who can open a PR controls what a plan prints. A PR that
   turns SCIM on gets one *warning* (`check.scim_credential_supplied_on_create`).
4. **The gated apply fails closed.** With `require_scim_credentials = true`
   (wiring: set it in `terraform-apply.yml`), a run that would *create* the
   credential without a value fails its plan. The postcondition reads the
   planned value. After creation, that is the stored value, so later runs pass.
5. **Written once, then ignored.** `lifecycle { ignore_changes = [credential] }`.
   Graph never returns the token (it answers `*`), so routine plans need
   nothing.
6. **Rotation.** AWS allows two active tokens (*verify:*). Create a new one,
   update Key Vault, then
   `terraform apply -replace='module.apps[0].azuread_synchronization_secret.aws[0]'`
   with step 2's exports. Test Connection, then delete the old token in AWS.
7. **Residual risk, accepted for the lab.** The token is in Terraform state,
   marked sensitive. State is readable by the CI identities. That is the same
   accepted risk the root README records for the break-glass passwords.
   Revoking the token in AWS makes any copy useless.

---

## Signing-certificate rotation

`end_date` defaults to Entra's three years. Microsoft mails
`saml_cert_notification_emails` before expiry (*verify:* the 60/30/7-day
schedule). A rotation is a **coordinated change**, never a routine apply. A
plan that shows `-/+` on
`azuread_service_principal_token_signing_certificate.aws` means:

1. Merge in a window you control.
2. Activate the new certificate (Stage 1a command).
3. Re-upload `aws_federation_metadata_url` in AWS straight away. AWS trusts
   one IdP certificate (*verify:*), so sign-ins fail between steps 2 and 3.

---

## Graph permissions (wiring: `envs/bootstrap` / `modules/pipeline-identity`)

The APPLY identity today has **no `Application.*` write role**. Its comment
says "envs/dev creates no app registrations". This module changes that.

| Identity | Add | Why | Least privilege per Graph docs |
|---|---|---|---|
| APPLY | `Application.ReadWrite.OwnedBy` | Instantiate the template, SP settings, signing certificate, identifier and reply URLs, sync job, sync secret, claims-policy assignment. Reaches **only apps it owns**, which is why it is always an owner. | Yes for instantiate, sync job, secrets and provisionOnDemand. The provider docs list `Application.ReadWrite.All` for the sync job. *verify:* OwnedBy suffices on first run, and fall back to `Application.ReadWrite.All` if not. |
| APPLY | `Policy.ReadWrite.ApplicationConfiguration` | Create and update the claims-mapping policy | Yes |
| APPLY | `AppRoleAssignment.ReadWrite.All` + `Application.Read.All` | Group → app grants, and `prevent_duplicate_names` | Yes. **High privilege:** it can grant any app role, including Graph roles, so it is Tier 0 like `RoleManagement.ReadWrite.Directory`. Add it to the APPLY risk acceptance. The alternative is to assign groups by hand in a post-apply step and drop the permission. |
| PLAN | `Application.Read.All` | Refresh apps, SPs, assignments and templates | Yes |
| PLAN | `Synchronization.Read.All` | Refresh the sync job and secret metadata | *verify:* least-privileged read for `GET …/synchronization/jobs` and `/secrets` |

---

## Demo: see the roles and groups claims (optional flag)

With `clinical_portal_preauthorize_azure_cli = true` and a Clinician grant to
a group Dana is in:

```bash
az login --tenant <tenant> --allow-no-subscriptions        # as Dana
az account get-access-token --scope "$(terraform output -raw clinical_portal_identifier_uri)/Clinical.Read" \
  --query accessToken -o tsv | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{aud, roles, groups, acct}'
```

Expected: `roles: ["Clinician"]`, `groups` = the assigned group's id only, and
`acct: 0`. An unassigned user gets `AADSTS50105` (*verify:* the code), because
assignment is required. *verify:* Azure CLI obtains tokens for a
pre-authorized third-party scope.

---

## ServiceNow (PDI) SAML

**BUILT, flag off** (`enable_servicenow_sso`, [`servicenow.tf`](servicenow.tf),
13 mocked runs in `tests/servicenow.tftest.hcl`). The ServiceNow Personal
Developer Instance is free, and it is also where the PAM broker validates
change tickets at tenant time (`lab/pam/README.md` §5). Same shape as the AWS
app: one assignment, assignment required, an Entra-minted certificate,
claims as code.

**Non-gallery template, on purpose.** Microsoft publishes the non-gallery
template id in the Graph docs; neither the Learn ServiceNow tutorial nor the
Graph docs publish the ServiceNow *gallery* template id, and an unverified
id is not committed. The gallery app would add Learn's "Configure Now"
automatic setup and the ServiceNow provisioning connector. Moving to it later
is a replacement (new client id, certificate and ServiceNow IdP metadata), so
it is a design change, not a variable flip.

| Setting (Microsoft Learn, *ServiceNow SSO tutorial*) | Value |
|---|---|
| Identifier | `servicenow_instance_url`, e.g. `https://devNNNNN.service-now.com` (no trailing `/`) |
| Reply URL | `<instance>/navpage.do`, exactly one, no wildcard |
| Sign-on URL | `<instance>/login_with_sso.do?glide_sso_id=<sys_id>` once `servicenow_sso_sys_id` is set; `<instance>/navpage.do` before |
| NameID | `userPrincipalName`, format *unspecified* (claims-mapping policy) |
| Logout URL | not managed here (the provider exposes it only on `azuread_application`); sign-in does not need it |

Staged order (tenant time, after the AWS stages):

| Stage | Who | What | Evidence to capture |
|---|---|---|---|
| S1 | PR → CI apply | `enable_servicenow_sso = true`, with `servicenow_instance_url` in `terraform.tfvars` / `TF_VAR_` (never `lab.tfvars`) | Plan comment; Enterprise apps list |
| S1a | operator | Activate the signing certificate: output `servicenow_saml_signing_cert_activation_command` | Screenshot of the active certificate |
| S2 | operator, ServiceNow | Activate *Integration – Multiple Provider Single Sign-On Installer*; create a SAML identity provider by importing output `servicenow_federation_metadata_url`; NameID policy `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`; *User Field* = `user_name` (ServiceNow `user_name` = Entra UPN, the lab's convention) | IdP record |
| S3 | PR → CI apply | `servicenow_sso_sys_id` = the IdP record's sys_id, so the My Apps tile signs in through it | Plan comment |
| S4 | operator | A member of `App-ServiceNow-Users` signs in from My Apps; a non-member is refused | SAML trace (NameID); sign-in log entries |

**Provisioning: DESIGNED, not built.** Learn's ServiceNow provisioning uses
the gallery app's connector, which signs in to the instance with a
ServiceNow admin user name and password, not a bearer token. The design: a
second, gallery "ServiceNow" instance for provisioning only, assigned to the
same `App-ServiceNow-Users` group so the SSO and provisioning scopes can
never drift; the integration account in Key Vault, written once like the AWS
SCIM credential; the job created stopped; `userPrincipalName` → `user_name`
so provisioned accounts match the NameID. *verify:* the gallery template id
and the connector's credential keys, in the tenant.

A PDI hibernates when idle and is reclaimed after a period of inactivity
(*verify:* the current policy), so the flag stays off until the trial window
and nothing in CI depends on the instance.

---

## Validation status (offline only)

| Check | Result |
|---|---|
| `terraform fmt -check -recursive` | clean |
| `terraform init -backend=false` + `validate` (HashiCorp Terraform 1.16.5, azuread 3.10.0) | **Success** |
| `terraform test` (`tests/apps.tftest.hcl` + `tests/servicenow.tftest.hcl` + `tests/okta.tftest.hcl`, mocked azuread) | **46 passed, 0 failed** (18 + 13 + 15): plan runs plus four mocked applies that exercise the provider's own id parsing (2026-10-26, the working tree; 31 on 2026-10-20 before `okta.tftest.hcl`) |
| Checkov 3.3.20 (`-d modules/apps`) | 0 failed |

The tests pin:

- one assignment, to the App group;
- assignment required, SAML mode and the enterprise tag kept;
- wrong gallery template refused;
- wildcard reply URL refused;
- NameID and Department claims present;
- exactly three user-only roles;
- `ApplicationGroup` groups claim, implicit flow off;
- grants map to the fixed role ids, and an unknown role is refused;
- no SCIM objects unless enabled;
- the job is created stopped;
- a template id is required;
- an empty token fails the gated apply and only warns in a PR plan;
- a malformed SCIM endpoint is refused;
- guacamole-psm is absent by default; when on it issues id tokens only, is
  single tenant, requires assignment, is assigned only to PAM-Operators, and a
  plain-http non-localhost redirect is refused;
- ServiceNow is absent by default; when on it plans the app, the service
  principal (SAML, assignment required), one assignment and the certificate;
  the sign-on URL uses the IdP `sys_id`; the claims policy can be turned off;
  the flag without an instance URL or without the group fails the plan; a
  wildcard, trailing-slash, path or Reply-URL, non-ServiceNow or plain-http
  instance URL and a malformed `sys_id` are refused; the assignment prefers
  the app's `User` role.
- okta-clinic-idp is absent by default; when on it plans one app (single
  tenant, implicit grants off, exactly the delegated Graph scopes Okta asks
  for), one service principal (assignment required), one assignment to
  App-Okta-Federation-Users and one redirect URI, the Okta authorize
  callback; the ITSM reference is stamped; the flag without an org host or
  without the group fails the plan; a scheme, path, wildcard, non-Okta host,
  look-alike suffix or `-admin` host is refused and preview / EMEA cells are
  accepted; a secret lifetime over 180 days is refused; the mocked apply
  builds the ids, the bounded secret-minting command and the NHI row from
  the applied values.

**guacamole-psm at tenant time:** apply with `enable_pam_oidc_app = true`, add
the operators to `PAM-Operators` (and to `CA008-Pilot-PhishingResistant`, so
the PSM sign-in needs a phishing-resistant method while CA008 runs in pilot
scope), put output `guacamole_psm_client_id` in `lab/pam/.env` as
`OIDC_CLIENT_ID`, then follow `lab/pam/README.md` §6 from step 3. Evidence: an
operator's Entra sign-in log entry for `guacamole-psm` (CA result + method),
a refused sign-in by a non-operator (AADSTS50105, *verify:* code), and the
Guacamole History row naming the UPN. The same flag also creates **CA022** in
`modules/conditional-access` (`admins.tf`, report-only first): guacamole-psm
and the admin portals need the admin phishing-resistant authentication
strength, so a PSM session always starts with phishing-resistant MFA.

---

## Tenant-time verify list

- [ ] Template `21ed01d2-ec13-4e9e-86c1-cd546719ebc4` resolves to *AWS IAM Identity Center (successor to AWS Single Sign-On)*, so the plan passes the postcondition.
- [ ] The instantiated SP carries roles `User` / `msiam_access` and tag `WindowsAzureActiveDirectoryIntegratedApp`. A second `terraform plan` shows **No changes**.
- [ ] Certificate activated. The federation metadata carries the new thumbprint.
- [ ] A SAML trace of Dana shows NameID = UPN (record the NameID format) and `AccessControl:Department`. The portal blade shows claims as policy-managed (read-only).
- [ ] An unassigned user is refused at the AWS tile: assignment required works.
- [ ] Sync template id recorded. Test Connection passes. Provision on demand (Dana) succeeds while the job is stopped.
- [ ] After `aws_scim_job_enabled`, the provisioning logs show the group and members created. AWS lists them as *Created by SCIM*.
- [ ] `ExternalIds` on the AWS group = the Entra group object id. This enables the `entra_group_object_id` pin in `lab/terraform/aws`.
- [ ] `Application.ReadWrite.OwnedBy` was enough for the sync job (else record the fallback).
- [ ] Leaver: Dana is out of the App group, deprovisioned on demand, and gone from the AWS portal.
- [ ] OIDC: the token shows `roles`, `groups` (app groups only) and `acct`.
- [ ] ServiceNow: the identifier URI is accepted (the SP is already in SAML mode; identifier-URI policy); the instantiated roles include `User`; NameID value and format as ServiceNow receives them; a non-member is refused at the tile.
- [ ] okta-clinic-idp: admin consent on the four delegated Graph scopes is accepted and no clinic user sees a consent prompt; `Add-MgApplicationPassword` with `Application.ReadWrite.OwnedBy` is enough for an owner (else record the fallback); a non-member of App-Okta-Federation-Users is refused by Entra before Okta sees them (record the AADSTS code); the Entra sign-in log row for `okta-clinic-idp` shows the CA result; the redirect URI equals the Okta root's `okta_callback_uri`.

---

## Okta coexistence (Entra side)

**BUILT, flag off** (`enable_okta_federation`, [`okta.tf`](okta.tf), 15
mocked runs in `tests/okta.tftest.hcl`; [ADR 0022](../../docs/adr/0022-okta-coexistence-as-code.md)).
This is Phase 1 of [`lab/docs/okta-migration-runbook.md`](../../docs/okta-migration-runbook.md)
("Okta trusts Entra") as code: the acquired clinic keeps its Okta org for the
apps that have not moved yet, its users sign in at Entra (so Conditional
Access applies), and Okta accepts the Entra identity through this app. The
Okta half (the identity provider, the routing rule, `Clinic-Staff`, the legacy
app) is the separate, human-applied root [`lab/terraform/okta`](../../okta/README.md),
applied **after** this one. **Nothing has been applied: no tenant and no Okta
org exist.**

| Setting (runbook Phase 1, step 1 and 4) | Value |
|---|---|
| App registration | `okta-clinic-idp` (`okta_idp_app_display_name`), single tenant, Web platform, implicit grants off |
| Redirect URI | `https://<okta_org_domain>/oauth2/v1/authorize/callback`, exactly one; `okta_org_domain` is the bare org host (`*.okta.com`, `*.oktapreview.com`, `*.okta-emea.com`; Integrator Free orgs are `integrator-NNNNNNN.okta.com`), never the `-admin` host |
| API permissions (declared, consent is human) | Microsoft Graph delegated `openid`, `profile`, `email`, `User.Read` (*verify:* Okta's current list for a generic OIDC IdP) |
| Enterprise app | assignment required; **one** assignment: `App-Okta-Federation-Users` (`okta_federation_users_group_object_id`, from `modules/groups`) |
| Client secret | **not created by Terraform.** Output `okta_idp_client_secret_command` mints one with `Add-MgApplicationPassword`, bounded to `okta_idp_secret_lifetime_days` (default and maximum 180: the `P180D` rotation in `lab/iga/nhi-secrets-register.json`), and prints it once for `TF_VAR_entra_client_secret` in the Okta root |
| Hand-off to the Okta root | outputs `okta_idp_client_id` and `okta_idp_endpoints` (the tenant's v2.0 issuer, authorize, token, JWKS and userinfo URLs) |
| NHI inventory row | `okta_clinic_idp`: credential type *client-secret, human-minted, bounded*, no outbound secret |

**Why there is no `okta_idp_secret_mode = "keyvault"`.** It was considered and
not built, because it does not fit the lab's Key Vault: an
`azuread_application_password` puts the secret value in `envs/dev` state,
which the PLAN identity can read (`lab/pipelines/README.md`); the
`modules/keyvault` module takes no secret input (only the names its UAMI may
read), its writers are human Secrets Officers by design, the CI APPLY identity
holds no data-plane role on the vault, the vault sits behind a private
endpoint with a deny-by-default firewall a hosted runner cannot reach, and
this module declares `azuread` only. So the secret follows the runbook: one
human, one bounded secret, entered once into Okta, deleted with the app in
Phase 4. (`okta.tf` header.)

Staged order (tenant time, after `enable_sso_apps`):

| Stage | Who | What | Evidence to capture |
|---|---|---|---|
| O1 | PR → CI apply | `enable_okta_federation = true`, with `okta_org_domain` in `terraform.tfvars` / `TF_VAR_` (never `lab.tfvars`) | Plan comment; the app and its one assignment in Enterprise applications |
| O1a | operator (Tier 0) | Grant admin consent on `okta-clinic-idp` (Enterprise applications → Permissions), so no clinic user is prompted | Screenshot of the granted delegated permissions |
| O1b | operator | Run output `okta_idp_client_secret_command`; keep the value only in the shell that applies the Okta root (`read -s`) | The secret's `displayName` and `endDateTime` in the app's Certificates & secrets (never the value) |
| O2 | operator, Okta | Apply [`lab/terraform/okta`](../../okta/README.md) with `enable_entra_federation = true`: `entra_client_id` = output `okta_idp_client_id`, `entra_tenant_id` from `okta_idp_endpoints`, the secret as `TF_VAR_entra_client_secret` | The Okta root's plan; outputs `entra_idp_id`, `routing_rule_id` |
| O3 | operator | Cross-check: `terraform output -raw okta_idp_redirect_uri` here equals `terraform -chdir=../../okta output -raw okta_callback_uri` | The two strings side by side |
| O4 | operator | Runbook Phase 1 *Validate*: a member of `App-Okta-Federation-Users` with a clinic login signs in to Okta and is sent to Entra; a non-member is refused at Entra | Entra sign-in log row for `okta-clinic-idp` with the CA result; Okta System Log IdP event |
| O5 | operator | Runbook Phase 1 *Rollback* rehearsal: `routing_rule_active = false` in the Okta root, timed, then back | The timed rollback in the evidence log |
