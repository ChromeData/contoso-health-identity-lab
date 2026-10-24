# Runbook — Okta → Microsoft Entra ID migration (acquired clinic)

**Scenario.** Contoso Health has acquired a clinic whose workforce signs in
through **Okta**. Target state: one identity plane (Entra ID), with HR as the
source of truth, and the Okta tenant decommissioned. Constraints: nobody loses
access on day one, every application moves individually with a rollback, and
every step leaves audit evidence.

**Status: DESIGNED.** Nothing here has run. The runbook is written to run
in an **Okta Integrator Free** org (the real Okta product, standing in for
the clinic's enterprise tenant) at a scale of 1–3 apps and a handful of
users; what production adds is marked **[prod]**.

---

## Phase 0 — Inventory and decide (no user impact)

| Inventory item | Where to get it |
|---|---|
| Apps and protocol (SAML / OIDC / SWA / bookmark), assignment model per app | Okta Admin → Applications; `GET /api/v1/apps` |
| Groups, group rules, MFA factors, sign-on policies | Directory → Groups; Security → Authenticators and Authentication policies |
| Okta-mastered profile attributes, provisioning *into* apps | Profile editor; each app's Provisioning tab |

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

1. Entra → App registrations → **New registration** `okta-clinic-idp`
   (single tenant). Redirect URI (Web):
   `https://<okta-org>.okta.com/oauth2/v1/authorize/callback`.
   Add a client secret, entered once by hand into Okta in the next step.
   It lives in Okta's credential store, never in the repo.
2. Okta Admin → Security → **Identity Providers → Add → Microsoft** (OIDC).
   Client ID + secret from step 1, scopes `openid profile email`.
   *Account link*: match on email. *JIT provisioning*: on (lab) / off with
   pre-linked accounts **[prod]**.
3. Okta → Security → Identity Providers → **Routing rules → Add**: users whose
   login domain is `<custom domain>` → the Microsoft IdP. Keep the default rule
   (Okta login) **below** it as the fallback.
4. Entra: assign `App-Okta-Federation-Users` to `okta-clinic-idp`. That's the
   *allow-list* of who may federate (the group is created by Terraform
   `modules/groups`).
5. Conditional Access already applies, because the sign-in happens at Entra.

**Validate:** in a private window, open Okta, enter
`dana.okafor@<domain>`, and you're sent to Entra → MFA → back to the Okta
dashboard. Okta System Log shows the IdP sign-in. Entra sign-in logs show app
`okta-clinic-idp` with the CA result.
**Rollback:** disable the routing rule. Users fall back to Okta passwords
instantly.
**Evidence:** screenshot of the routing rule, and an Entra sign-in log row
with CA applied.

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
