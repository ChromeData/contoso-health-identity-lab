# okta — the Okta side of "Okta trusts Entra" (separately applied)

**Real product, free plan.** This root targets an **Okta Integrator Free**
org: the real Okta product on its free plan, standing in for the acquired
clinic's enterprise Okta tenant (the Okta row in
[`lab/docs/STAND-INS.md`](../../docs/STAND-INS.md)).

> **Status: RAN · tenant, verified end to end** (capture-log E102). Applied to
> the lab's Okta Integrator Free org (E58); the authorize-request fix (#140), the
> routing domain `contosohealthlab.com` (#159) and Entra's v1.0 endpoints with
> trust claims (#162) went live on 2026-11-05. That day a clinic user typed her
> hospital address at Okta, was sent to Entra, signed in with her password and
> an authenticator code (CA001 applied), and landed on the Okta dashboard with
> the clinic's legacy app - with no Okta factor enrolled: Okta's *Any two
> factors* was met by the MFA Entra asserted (`amr`). Runtime statements still
> marked *verify:* are not proven by that run.

It is Phase 1 of [`lab/docs/okta-migration-runbook.md`](../../docs/okta-migration-runbook.md)
as code, decided in [ADR 0022](../../docs/adr/0022-okta-coexistence-as-code.md).
Entra decides **who** may federate (`modules/apps` `okta.tf`: the
`okta-clinic-idp` app, assigned to `App-Okta-Federation-Users` only). This
root decides **which sign-ins Okta sends to Entra** and **what they reach**:

| Object | Terraform | Value |
|---|---|---|
| The clinic's group | `okta_group.clinic_staff` | `Clinic-Staff`; membership by the rule below, never by Terraform |
| Group rule | `okta_group_rule.clinic_staff` | `String.substringAfter(user.login, "@") == "<clinic_login_domain>"` → Clinic-Staff |
| Legacy app | `okta_app_bookmark.clinic_scheduling` | *Clinic Scheduling (legacy)*, a bookmark to `legacy_app_url` (the app Phase 2 moves) |
| Its one assignment | `okta_app_group_assignment.clinic_scheduling_staff` | Clinic-Staff, nobody else |
| Identity provider (flag) | `okta_idp_oidc.entra` | generic OIDC, the tenant's **v1.0** endpoints (only their ID token carries `amr`; no userinfo), scopes `openid profile email`, link by email, JIT on (lab) |
| Routing rule (flag) | `okta_policy_rule_idp_discovery.clinic_to_entra` | priority 1, username **suffix** = `clinic_login_domain` → that IdP; attached to Okta's built-in IdP discovery policy, read by `data.okta_default_policy` and never managed, so Okta's **Default Rule stays the fallback** |

Provider: **okta/okta `~> 4.0`**, validated and mock-tested against **4.20.0**
(the committed lock file; current on the Terraform registry on 2026-10-26).
Terraform **>= 1.8** (the tests use `issensitive()`); CI pins 1.16.5.

---

## Why a separate root (and not `envs/dev`)

1. **Different product, different credential.** The pipeline's identities are
   Entra apps with GitHub OIDC federation. They have no Okta trust, and an
   Okta API token in GitHub would widen the credential surface for one lab
   org. The token lives only in the shell of the human who applies.
2. **It depends on a human step Terraform cannot see.** The client secret is
   minted by a person on the Entra app and entered once; the Entra apply has
   to finish first, and its outputs are typed into this root's inputs.
3. **Isolated state and blast radius.** The Okta provider stores the IdP's
   client secret in state. That state is local to one laptop and holds the
   one secret of the coexistence; `envs/dev` state, readable by the PLAN
   identity, never does.
4. **Human-applied, like `aws/` and `envs/bootstrap`.** Small, rarely
   changed, applied from a short-lived admin session.

CI still *checks* it: `lab-tests.yml` runs `fmt`, `init -backend=false`,
`validate` and the mocked tests here on every PR (the root is in its
`dirs=` list), and `terraform-plan.yml` runs Checkov over `lab/terraform/**`.
It is never planned or applied by CI.

---

## Integrator Free limits (verify: the current terms at apply time)

- Meant for building and testing integrations: a handful of users and
  apps, no production use, no SLA. This root needs 1 IdP, 1 rule, 1 group,
  1 app and the lab's 1 to 3 clinic users.
- No custom domain: the org host is `integrator-NNNNNNN.okta.com`, so the
  IdP uses `issuer_mode = "ORG_URL"` and the callback is on that host. A
  custom domain would change the callback on **both** sides (a design
  change, not a variable).
- SSWS API tokens (Security → API → Tokens), bound to the admin who created
  them; they expire after 30 days unused. **[prod]** an OAuth 2.0 service app
  with scoped grants, which the provider also supports.
- The org is deactivated after a period without an admin sign-in. Plan the
  Phase 1 window so the org is alive when the Entra apply lands.
- Which IdP flavours and authentication policies the free plan exposes is the
  runbook's own *verify in the lab* item. This root uses the generic OIDC IdP
  (explicit endpoints, reviewable); the runbook's "Add → Microsoft" is the
  social-IdP flavour of the same exchange. If the OIDC type is missing, the
  runbook's SAML fallback is a different resource (`okta_idp_saml`) and a
  non-gallery Entra SAML app: a new PR, not a variable.

---

## Apply order

Entra first, then Okta. The Entra app has to exist before Okta can trust it,
and this root takes its client id as input.

1. **Entra, by PR → CI apply** (`envs/dev`): `enable_okta_federation = true`
   with `okta_org_domain` (the org host, e.g. `integrator-1234567.okta.com`)
   in `terraform.tfvars` / `TF_VAR_`, never `lab.tfvars`. The staged order is
   O1–O1b in [`modules/apps/README.md`](../modules/apps/README.md#okta-coexistence-entra-side):
   apply, grant admin consent, mint the secret with output
   `okta_idp_client_secret_command`.
2. **This root, first apply, the clinic's estate** (a human, locally):

   ```bash
   cd lab/terraform/okta
   cp terraform.tfvars.example terraform.tfvars   # org name, cell, clinic_login_domain
   read -s OKTA_API_TOKEN && export OKTA_API_TOKEN  # Security -> API -> Tokens, never in a file
   terraform init            # local state, okta/okta 4.20.0 from the lock file
   terraform plan            # group, group rule, bookmark app, one assignment; no IdP
   terraform apply
   ```

   This is the state the runbook's Phase 0 inventories: in the lab there is no
   pre-existing clinic org, so the "legacy" estate is created here first.
3. **This root, second apply, Phase 1 federation:**

   ```bash
   terraform -chdir=../envs/dev output -raw okta_idp_client_id     # -> entra_client_id
   terraform -chdir=../envs/dev output -json okta_idp_endpoints    # the tenant id in every URL -> entra_tenant_id
   read -s TF_VAR_entra_client_secret && export TF_VAR_entra_client_secret   # the value the Entra command printed
   # terraform.tfvars: enable_entra_federation = true, entra_tenant_id, entra_client_id
   terraform plan            # + the IdP and ONE routing rule; the secret never appears in the plan
   terraform apply
   unset TF_VAR_entra_client_secret
   ```

4. **Cross-check** (the one thing that silently breaks federation if wrong):

   ```bash
   terraform output -raw okta_callback_uri
   terraform -chdir=../envs/dev output -raw okta_idp_redirect_uri   # must be the same string
   ```

5. **Runbook Phase 1 validate / rollback / evidence**, below.

The plan fails, before anything is created, when `enable_entra_federation`
is on without `entra_tenant_id`, `entra_client_id` or the secret
(preconditions on the IdP), so a half-configured IdP can never lock the
clinic domain out.

---

## Trust the Entra MFA (post-apply step)

Okta's own dashboard policy (catch-all *Any two factors*) stays as it is: MFA
is required. What changes is that Okta **accepts the MFA Entra already
enforced** (CA001) instead of asking a clinic user to enroll an Okta factor on
top. Two pieces:

1. **The IdP is on Entra's v1.0 endpoints** (`main.tf` locals). Only the v1.0
   ID token carries `amr` (read live: `["pwd","mfa"]`; the v2.0 one has none,
   and its Graph access token cannot be verified by a third party). Users Okta
   already linked stay linked: `sub` is the same on both. The Entra app adds
   the `email` optional claim (modules/apps `okta.tf`), because the v1.0 ID
   token has no email for members and Okta's JIT and account link need it.
2. **`trustClaims` on the IdP**, set by `trust-claims.mjs` (okta/okta 4.20 has
   no argument for it):

   ```bash
   node lab/terraform/okta/trust-claims.mjs --dry-run   # what would change
   node lab/terraform/okta/trust-claims.mjs             # set + read back
   ```

   Idempotent (a second run changes nothing), refuses while the IdP is still
   on v2.0 (Okta warns that trusting claims an IdP does not send breaks
   sign-in), sends the IdP back with only `policy.trustClaims` changed and
   checks that nothing else moved. Token: `OKTA_API_TOKEN` or the Keychain item
   `contoso-lab-okta-token`. **Run it after every apply that updates
   `okta_idp_oidc.entra`** (*verify:* whether such an apply resets the flag;
   the script's read-back shows it).

Rollback: `node lab/terraform/okta/trust-claims.mjs --off` (Okta then asks for
its own second factor again).

## What the runbook's Phase 1 maps to

| Runbook Phase 1 | Was | Now |
|---|---|---|
| 1. App registration `okta-clinic-idp`, redirect URI, client secret | portal | `modules/apps/okta.tf` behind `enable_okta_federation`; the secret stays a human step (output `okta_idp_client_secret_command`, bounded to 180 days) |
| 2. Okta → Identity Providers → Add → Microsoft | Okta console | `okta_idp_oidc.entra` (`enable_entra_federation`, the secret as `TF_VAR_entra_client_secret`) |
| 3. Routing rule for the clinic login domain, default rule kept below | Okta console | `okta_policy_rule_idp_discovery.clinic_to_entra` (suffix match on `clinic_login_domain`, priority 1); the Default Rule is Okta's own and stays |
| 4. Assign `App-Okta-Federation-Users` to `okta-clinic-idp` | portal | `azuread_app_role_assignment.okta_federation_users` in `okta.tf` |
| 5. Conditional Access applies | — | unchanged: the sign-in happens at Entra |
| **Validate** | private window, Okta → Entra → MFA → Okta dashboard | the same, as a person: a member of `App-Okta-Federation-Users` with a `clinic_login_domain` login opens Okta, is routed to Entra (routing rule), signs in with MFA (CA), returns to the Okta dashboard and sees *Clinic Scheduling (legacy)* (Clinic-Staff by the group rule). A non-member is refused at Entra. Evidence: the Entra sign-in log row for `okta-clinic-idp` with the CA result; the Okta System Log IdP event carrying output `entra_idp_id` |
| **Rollback** | disable the routing rule | `routing_rule_active = false` → `terraform apply`: the rule goes INACTIVE, the IdP stays, clinic users fall back to Okta passwords at the next sign-in. A `check` warns on every plan while it is false, so a rollback is never forgotten. Rehearse it, timed, during validation (ADR 0022 measures ≤ 5 minutes); then set it back to `true` |
| **Evidence** | screenshot of the routing rule + an Entra sign-in log row | `terraform output` (`routing_rule_id`, `routing_rule_status`, `routed_login_domain`, `entra_idp_id`) plus the two log rows; the timed rollback in the drill log |

Phases 2 to 4 (moving the legacy app, users and MFA, decommission) stay
runbook steps. Moving *Clinic Scheduling (legacy)* is its own PR: an Entra
app in `modules/apps`, then `hide_web = true` here for one sign-in cycle, then
`status = "INACTIVE"`, then removal.

---

## Verify list (tenant time, nothing run yet)

- [ ] `terraform plan` after each apply shows **No changes** (no drift between code and console; in particular the bookmark app's computed `authentication_policy` and the IdP's request-signature defaults).
- [ ] Okta Admin → Security → Identity Providers lists the IdP with the id of output `entra_idp_id`; its redirect URI equals output `okta_callback_uri` and the Entra app's `okta_idp_redirect_uri`.
- [ ] Security → Identity Providers → Routing Rules: the rule is first, ACTIVE, condition *username ends with* `clinic_login_domain`, and the **Default Rule** is still below it (*verify:* that the SUFFIX value is the bare domain, as in Okta's policy example, not `@domain`).
- [ ] A clinic-domain user is sent to Entra; a user outside the domain gets the Okta password page (the fallback works). The Okta System Log shows `user.authentication.auth_via_IDP` (*verify:* event name) for the first and a plain Okta sign-in for the second.
- [ ] The Entra sign-in log row for `okta-clinic-idp` shows the CA policies applied; a non-member of `App-Okta-Federation-Users` is refused at Entra (record the AADSTS code).
- [ ] `String.substringAfter(user.login, "@")` evaluates as expected: the clinic user is in Clinic-Staff and sees the bookmark; a non-clinic user is not and does not.
- [ ] Rollback: `routing_rule_active = false` applied and timed; the next sign-in uses an Okta password; then `true` again.
- [x] The first sign-in exchange succeeds with the provider's default request-signature settings; if the authorize call fails at Entra, set `request_signature_scope = "NONE"` and record it. **Resolved 2026-11-05:** the default (`REQUEST`, HS256) failed at Entra with AADSTS70013 (*the 'request' request parameter is not supported*) on the first clinic sign-in; `main.tf` now sets `NONE`, and the live IdP was set to match through the Okta API (the step this item documents).
- [x] The routed domain is the one users type at Okta **and** the domain of their Entra email (Okta names a JIT user after `idpuser.email`, and the next sign-in is routed by it). **Decided 2026-11-05:** after the acquisition, clinic staff use hospital accounts, so `clinic_login_domain = contosohealthlab.com`: Okta sends staff with a hospital address to the hospital login. Okta's own admin (an `onmicrosoft.com` login) matches neither the routing rule nor the group rule, so it keeps the Default Rule.
- [x] Okta's own sign-on policy for the Okta dashboard (catch-all *Any two factors*) counts the Entra MFA. **Decided and verified 2026-11-05:** MFA stays required in Okta; Okta accepts Entra's: the IdP is on Entra's v1.0 endpoints (its ID token carries `amr`) and `trust-claims.mjs` sets `trustClaims`. Before that, a JIT-created clinic user was asked to enroll Okta Verify or a passkey; after it, she reached the dashboard with no Okta factor (E102).
- [ ] Users need a first and last name in Entra: Okta's JIT refuses a user without them (`firstName`/`lastName` *cannot be left blank*, seen live). HR-fed users always have both.
- [ ] Integrator Free exposed everything used here (OIDC IdP, routing rules, group rules, bookmark apps, API tokens).
- [ ] The state file holds the client secret: it stayed on the applier's laptop, and `terraform.tfstate*` is gitignored (`git status` shows nothing from this directory except the lock file and code).

---

## Validate / fmt status (offline only)

Run on 2026-10-26 with **HashiCorp Terraform v1.16.5**, provider
**okta/okta 4.20.0** (lock file generated with `terraform providers lock
-platform=linux_amd64 -platform=darwin_arm64 -platform=darwin_amd64`).
Nothing here contacted Okta.

| Check | Result |
|---|---|
| `terraform init -backend=false` | ok (okta/okta 4.20.0 from the committed lock file) |
| `terraform validate` | **Success** |
| `terraform fmt -check` | clean |
| `terraform test` (`tests/okta_federation.tftest.hcl`, `mock_provider "okta"`) | **16 passed, 0 failed** |

What the tests pin (read each in `tests/okta_federation.tftest.hcl`):

- by default only the clinic's estate is planned: Clinic-Staff, its
  login-domain rule, the legacy bookmark app and its one assignment; no IdP,
  no routing rule; the org host and callback outputs derived from the org
  name and cell;
- with the flag on: one OIDC IdP on the tenant's v1.0 endpoints (issuer,
  authorize, token, JWKS built from `entra_tenant_id`; no userinfo), scopes
  `openid profile email`, link by email, JIT on, groups never copied from the
  IdP; one routing rule, priority 1, ACTIVE, matching the clinic domain as a
  SUFFIX only and routing to exactly one IdP of type OIDC, attached to
  Okta's built-in discovery policy by data source;
- the client secret is sensitive as a variable and on the resource
  (`issensitive()`), and required when the flag is on, as are the client id
  and tenant id (the plan fails on the IdP's preconditions);
- the mocked apply wires the rule to the IdP it created, the assignment to
  the bookmark and the group, and the group rule to the group;
- the rollback sets the rule INACTIVE, keeps the IdP and raises the warning
  check; JIT can be turned off;
- an `@` or scheme in the login domain, a plain-http legacy app URL, a cell
  outside Okta's three, an org name that is a host or the `-admin` host, and
  a non-GUID client id are refused.

Lock-file rule, as for the other roots: the committed `.terraform.lock.hcl`
was written by HashiCorp Terraform 1.16.5 for three platforms; `tofu init`
would rewrite it with `registry.opentofu.org` entries, so validate with tofu
in a scratch copy and never commit a tofu-written one.

---

## Why the Entra client secret stays (checked 2026-11-07)

`okta-clinic-idp` holds the lab's **last Entra client secret** (one, ends
2027-04-26). It cannot be swapped for a certificate today:

- Okta's generic OIDC identity provider can sign in with `private_key_jwt`,
  but Microsoft Entra ID needs the `x5t#S256` header in that client
  assertion, and Okta does not send it. Entra refuses the token (AADSTS700027).
  Okta's own article says the integration is not supported and the fix is a
  client secret ("Error invalid social token and Azure error 700027 when using
  private key JWT with Okta OIDC identity provider and Microsoft Entra ID",
  support.okta.com, last updated 2026-08-04).
- There is no federated credential path either: Okta is not a workload that
  holds a token Entra can trust.

**The way to zero (DESIGNED, not built):** switch the federation from OIDC to
**SAML 2.0**. Entra signs the SAML response with a certificate it holds; Okta
needs only the public signing certificate. Steps: a non-gallery SAML app in
`modules/apps` (same one assigned group), `okta_idp_saml` + `okta_idp_saml_key`
here, the routing rule moved to the new IdP, one clinic sign-in proved, then
`okta-clinic-idp` and its secret deleted. It changes the live clinic sign-in,
so it waits until after the recording.

Until then the secret is bounded (180 days at most), entered once into
Okta, never in this repo, and listed with its owner and end date in
`lab/iga/nhi-secrets-register.json`.

## Production option (described, not built)

- Remote state with encryption at rest and access limited to the IdP owners
  (the secret is in state); or keep the secret out of state entirely by
  creating the IdP with the secret once and `lifecycle { ignore_changes =
  [client_secret] }` after rotation through the console.
- Provider authentication by an OAuth 2.0 service app (`client_id`,
  `private_key`, `scopes = ["okta.idps.manage", "okta.policies.manage",
  "okta.groups.manage", "okta.apps.manage"]`) instead of an SSWS token.
- `jit_provisioning = false`: only pre-linked accounts sign in, so an
  Okta-only user with no HR record (Phase 0) is never created by accident.
- Waves of 10 to 20 apps per the runbook, one PR per app moved, with the
  change ticket number in each PR.

## Sources (checked 2026-10-26)

- Okta provider 4.20.0 schema (`terraform providers schema -json`):
  `okta_idp_oidc`, `okta_policy_rule_idp_discovery`, `okta_default_policy`,
  `okta_group`, `okta_group_rule`, `okta_app_bookmark`,
  `okta_app_group_assignment`.
- Okta developer documentation: *Add an external Identity Provider* (the
  `/oauth2/v1/authorize/callback` redirect URI), *Identity Provider discovery
  policy* (IDENTIFIER / SUFFIX routing, the Default Rule), *Okta Expression
  Language* (`String.substringAfter`), *Integrator Free Plan* (limits;
  *verify:* current terms).
- Microsoft Learn: the v1.0 endpoint URLs (`https://sts.windows.net/<tenant>/`,
  `/oauth2/authorize`, `/oauth2/token`, `/discovery/keys`) and the *ID token
  claims reference* (no `amr` listed for ID tokens; `email` for members only as
  an optional claim). Read live 2026-11-05: the v2.0 ID token carries no `amr`,
  the v1.0 one carries `["pwd","mfa"]`.
- Okta developer docs, *Configure claims sharing* > *third-party OIDC IdP*: the
  IdP "must send an `amr` array with AMR claims in the OpenID Connect ID token";
  enabled with `trustClaims: true` in the IdP PUT; "The `mfa` AMR claim ... is
  defined to satisfy the app sign-in policy **Any two factors** configuration".
