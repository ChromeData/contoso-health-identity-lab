# Runbook — Okta → Microsoft Entra ID migration (acquired clinic)

**Scenario.** Contoso Health has acquired a clinic whose workforce signs in
through **Okta**. Target state: one identity plane (Entra ID), with HR as the
source of truth, and the Okta tenant decommissioned. Constraints: nobody loses
access on day one, every application moves individually with a rollback, and
every step leaves audit evidence.

**Lab vs. production.** The lab uses an **Okta Integrator Free** org, the
real Okta product, standing in for the clinic's enterprise Okta tenant. Every
step below runs for real in the lab, at a scale of 1–3 apps and a handful of
users. What production adds is called out as **[prod]**.

---

## Phase 0 — Inventory and decide (no user impact)

| Inventory item | Where to get it | Lab |
|---|---|---|
| Apps in Okta + protocol (SAML / OIDC / SWA / bookmark) | Okta Admin → Applications; Okta API `GET /api/v1/apps` | 1 SAML/bookmark app "Clinic Scheduling (legacy)" |
| Assignment model per app (groups vs. individuals) | Okta app → Assignments | 1 group |
| Okta groups and rules | Directory → Groups / Group rules | Clinic-Staff |
| MFA factors in use | Security → Authenticators | Okta Verify |
| Okta sign-on and session policies | Security → Authentication policies | default |
| Any Okta-mastered profile attributes | Directory → Profile editor | none, HR is the source |
| Inbound federation / SCIM *into* apps from Okta | App → Provisioning | none |

**Decisions recorded:** (1) Entra is the target IdP. (2) Coexistence uses
**Entra as an identity provider for Okta**, so users authenticate once against
Entra, Conditional Access applies, and Okta keeps serving the apps that
haven't moved yet. (3) Users come from **HR → AD → Cloud Sync**, exactly like
Contoso staff, not from an Okta export.

**[prod]** Export the full app inventory with the Okta API, classify by
sign-in volume (Okta System Log), and plan waves of 10–20 apps. Identify
**Okta-only users** (no HR record) before anything else.

---

## Phase 1 — Coexistence: Okta trusts Entra (day-one safety)

Goal: clinic users sign in with their **Entra** identity and still reach every
Okta app. No app changes yet.

**Status: RAN · tenant** (E58; [ADR 0022](adr/0022-okta-coexistence-as-code.md)). The
steps below are Terraform, validated and mock-tested offline and **applied**
against the lab tenant and an Okta Integrator Free org. The Entra
side is `lab/terraform/modules/apps/okta.tf` (`enable_okta_federation` in
`lab/terraform/envs/dev/lab.tfvars`, CI-applied by PR); the Okta side is the
separate, human-applied root `lab/terraform/okta/` (its README has the apply
order). The client secret stays a manual hand-off, on purpose.

1. Entra: app registration `okta-clinic-idp` (single tenant), redirect URI
   (Web) `https://<okta-org>.okta.com/oauth2/v1/authorize/callback`, the
   Graph scopes Okta asks for, assignment required —
   `modules/apps/okta.tf`, with the org host as `okta_org_domain`. **The
   client secret is not created by Terraform:** a human mints it post-apply
   with output `okta_idp_client_secret_command` (bounded to 180 days) and
   enters it once into the Okta root in step 2. It lives in Okta's
   credential store (and the Okta root's local state), never in the repo.
2. Okta: the **Microsoft Entra ID identity provider** (OIDC; client id from
   `envs/dev` output `okta_idp_client_id`, the secret as
   `TF_VAR_entra_client_secret` at apply time, scopes `openid profile
   email`) — `lab/terraform/okta/main.tf`, `okta_idp_oidc.entra`, behind
   `enable_entra_federation`. *Account link*: match on email. *JIT
   provisioning*: on (lab) / off with pre-linked accounts **[prod]**
   (`jit_provisioning = false`).
3. Okta: the **routing rule** — users whose login domain is
   `clinic_login_domain` → the Entra IdP (`okta_policy_rule_idp_discovery.clinic_to_entra`,
   priority 1, suffix match). Okta's default rule (Okta login) is never
   managed and stays **below** it as the fallback.
4. Entra: `App-Okta-Federation-Users` assigned to `okta-clinic-idp`, the
   only assignment — `azuread_app_role_assignment.okta_federation_users` in
   `okta.tf` (the group is created by Terraform `modules/groups`). That's the
   *allow-list* of who may federate.
5. Conditional Access already applies, because the sign-in happens at Entra.

**Validate:** in a private window, open Okta, enter
`dana.okafor@<domain>`, and you're sent to Entra → MFA → back to the Okta
dashboard. Okta System Log shows the IdP sign-in. Entra sign-in logs show app
`okta-clinic-idp` with the CA result. Then rehearse the rollback, timed.
**Rollback:** `routing_rule_active = false` in `lab/terraform/okta`, one
apply: the rule goes INACTIVE, users fall back to Okta passwords at the next
sign-in, and a `check` warns on every plan until it is `true` again.
**Evidence:** `terraform output` of the Okta root (`routing_rule_id`,
`routing_rule_status`, `entra_idp_id`), the Entra sign-in log row with CA
applied, and the timed rollback.

**Verify in the lab:** that the Integrator Free plan exposes Identity
Providers and routing rules in your org. If the Microsoft IdP type isn't
available, use **SAML 2.0 IdP** in Okta against a non-gallery Entra
enterprise app. The flow is the same.

---

## Phase 2 — Move applications one at a time

Per app (repeat for each wave):

| Step | Action | Rollback |
|---|---|---|
| 1. Pre-stage | Create the Entra enterprise app (gallery if available, else non-gallery SAML/OIDC) with the same entity ID / redirect URIs. Assign an **app group** (`App-<name>-Users`) that an access package grants, not individuals. | Delete the unused enterprise app |
| 2. Test with a pilot | Add the pilot users to the app group. Test with **Entra My Apps** while production still trusts Okta (or use a staging instance of the app). | Remove pilot users |
| 3. Cut over | In the **application**, swap the IdP metadata (cert, SSO URL, entity ID) from Okta to Entra. **Keep the Okta app assigned but hidden** for one sign-in cycle. | Swap the metadata back (keep the old cert/metadata file saved for this) |
| 4. Provisioning | If Okta provisioned the app (SCIM), turn Okta provisioning **off**, then turn Entra provisioning **on** with matching attributes. Run *provision on demand* for one user. | Re-enable Okta provisioning |
| 5. Confirm | Entra sign-in logs show the app. Okta System Log shows **zero** sign-ins to it for 7 days. | — |
| 6. Retire | Unassign and deactivate the Okta app. | Reactivate (it was kept) |

**Lab:** move "Clinic Scheduling (legacy)" from Okta to an Entra non-gallery
app and show steps 1, 3 and 5. **[prod]** Run this per wave with a change
ticket per app (ServiceNow). Freeze windows apply.

---

## Phase 3 — Users and MFA

- **Users:** clinic staff arrive through the **HR feed** like everyone else
  (`hr_feed.csv` → API-driven provisioning → AD → Cloud Sync). Okta accounts
  are linked by email during coexistence. There's no password migration:
  users never had Entra passwords to migrate, and they set one through a
  **Temporary Access Pass** issued by the joiner Lifecycle Workflow.
- **MFA:** users register Microsoft Authenticator (passkey preferred) on first
  Entra sign-in, through the combined registration experience. Okta Verify
  enrollment is retired with the Okta tenant. **[prod]** Run a registration
  campaign and track coverage with `05-Reports.ps1` (no-MFA report) before
  cutting off Okta.
- **Groups:** Okta groups map to Entra **access packages**, not copied 1:1.
  That's the moment to remove access nobody can justify.

---

## Phase 4 — Decommission Okta

1. Okta System Log: zero app sign-ins for 30 days **[prod]** (7 in the lab).
2. Remove the routing rule and the Microsoft IdP in Okta. Delete
   `okta-clinic-idp` in Entra, which also revokes the client secret.
3. Export the Okta System Log and the app/assignment inventory for the audit
   archive (retention per HIPAA policy).
4. Deactivate users. Downgrade, then close, the Okta contract.

**Evidence pack additions:** the inventory sheet, per-app cutover tickets,
the zero-sign-in report, and the deletion record of the federation app.

---

## Risks and how this runbook handles them

| Risk | Control |
|---|---|
| Users locked out on day one | Phase 1 changes *who authenticates*, not *what apps trust*; the routing rule is a one-click rollback |
| Okta-only users with no HR record | Found in Phase 0 inventory; they get an HR record or an expiry, never a silent orphan |
| Over-privileged access copied across | Groups become access packages with 180-day expiry plus an access review, not a copy |
| Secret sprawl during migration | One client secret (Okta → Entra federation), stored in Okta, deleted in Phase 4 |
| App owner can't swap metadata | The app stays on Okta (federated through Entra) until they can. Coexistence has no deadline pressure |

## Alternative direction (not used here)

Microsoft also documents the reverse coexistence: **Okta federating the Entra
domain** (Okta as the IdP for Microsoft 365), then moving to managed
authentication with **staged rollout** and password hash sync. That's the right
choice when Microsoft 365 already depends on Okta sign-in. It doesn't fit an
acquired clinic whose Microsoft 365 is being consolidated into Contoso's
tenant, which is this scenario.
