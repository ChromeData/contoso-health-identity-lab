# Okta to Entra app migration (runbook Phase 2, as code)

The acquired clinic signs in through Okta. Okta already trusts Entra
(Phase 1, [ADR 0022](../docs/adr/0022-okta-coexistence-as-code.md)). This
folder moves the clinic's **apps** from Okta to Entra, one wave at a time,
and keeps the record of it: an inventory read from both APIs, a tracker, a
test sign-in per step, and the System Log query that proves the sign-ins moved.

Runbook: [`lab/docs/okta-migration-runbook.md`](../docs/okta-migration-runbook.md) Phase 2.

## Status

| Part | Status | Evidence |
|---|---|---|
| The clinic's three apps in Okta, the *Clinic clinical apps* authentication policy, the *Clinic billing by department* group rule | **RAN · tenant** (Okta org, 2026-11-07) | capture-log E115; `lab/terraform/okta` `clinic-apps.tf` |
| Inventory and tracker from the Okta API and Graph | **RAN · tenant** | `tracker.csv`, `tracker.md`, `status.html`, `inventory.json` |
| Wave 1 *before*: a clinic user opens Clinic Lab Results through Okta | **RAN · tenant** | `results/2026-11-07T005908Z-clinic-lab-results-okta.json` |
| Wave 1 Entra side: app, its API, group, CA061 | **RAN · tenant** (PRs #219, #264, #277) | `lab/terraform/modules/apps/clinic_results.tf`, CA061 |
| Wave 1 cut-over, test through Entra with CA061, timed rollback, cut-over back | **RAN · tenant** (2026-11-08): cut-over 30 s, rollback 34 s, back 26 s | capture-log E182 |
| Okta Admin Console demands a phishing-resistant factor | **BUILT, off** (the owner's switch) | `admin_console_phishing_resistant` |
| Okta Workflows / event hook | **Not built** | See "Not built" below |

## The apps (wave plan)

| App | Protocol in Okta | Assigned to | Wave | Why this wave |
|---|---|---|---|---|
| Clinic Lab Results | OIDC, public client (PKCE, no secret) | Clinic-Staff | 1 | A real app that runs here (`clinic-results/app.mjs`), standard protocol, one group |
| Clinic Billing | SAML 2.0 | Clinic-Billing (group rule: department) | 2 | Its service provider does not exist in the lab; its users arrive with an HR department |
| Clinic Scheduling (legacy) | Bookmark | Clinic-Staff | 2 | The vendor has no SSO; it becomes an Entra linked sign-on tile |

Decisions (owner, wave, pilot users, the cut-over switch) are in
[`waves.json`](waves.json). Facts are read from the APIs. A cut-over is a PR
that sets `"cutover": true`. The Okta root reads the same file.

## How to run it

Every command reads the Okta token from the Keychain item
`contoso-lab-okta-token` into the process. Graph calls go through the lab
operator (`lab/scripts/operator/op`). Nothing prints a secret.

```bash
node lab/okta-migration/inventory.mjs            # tracker.csv / .md / status.html / inventory.json
node lab/okta-migration/cutover.mjs status
node lab/okta-migration/cutover.mjs prestage     # after PR #219 is applied: consent + pilot, read back
node lab/okta-migration/cutover.mjs test --idp entra   # staging: the pilot through Entra, production still on Okta
# PR: waves.json "cutover": true for Clinic Lab Results
node lab/okta-migration/cutover.mjs cutover      # app -> Entra, Okta tile hidden, test, timed
node lab/okta-migration/syslog.mjs               # Okta System Log + Entra sign-in log, before / after
node lab/okta-migration/inventory.mjs            # the row moves to "cut over"
```

Rollback: set `"cutover": false` in `waves.json`, then
`node lab/okta-migration/cutover.mjs rollback`. The app trusts Okta again,
the Okta tile comes back, and a test sign-in runs. The command prints the
time it took. In an incident, run
`node lab/okta-migration/cutover.mjs rollback --emergency` before the PR: it
does the full rollback (the app trusts Okta again, the Okta apply carries
`waves_override`, a test sign-in runs), then make the PR that sets
`"cutover": false`.

## How the cut-over works

The app's trust is config, as in a real application. The file
`~/.contoso-operator/clinic-results/idp.json` holds both IdPs and names the
active one. It is outside the repo because it is org-specific (client ids,
tenant id). It holds no secret: both sides are public clients.

| Step (runbook) | What changes | Undo |
|---|---|---|
| 1 Pre-stage | Entra app, its API (the CA061 target: CA cannot target a public client), group, assignments, CA061 | Remove the flag |
| 2 Pilot | `prestage`: consent, the pilot user in App-ClinicResults-Users. `test --idp entra` signs the pilot in through Entra while production still trusts Okta | Remove the pilot |
| 3 Cut over | `cutover`: the app trusts Entra; the Okta app is hidden but stays active and assigned | `rollback` |
| 5 Confirm | `syslog.mjs`: zero Okta sign-ins to the app after the cut-over, Entra sign-ins with CA061 | - |
| 6 Retire | `"retired": true`: the Okta app goes INACTIVE (kept) | `"retired": false` |

Through Entra the sign-in also requests the API's `Results.Read` scope, and a test passes only if the API token arrived (that token is where CA061 is evaluated). The app checks the ID token itself: signature against the IdP's keys,
issuer, audience, expiry and nonce. After the cut-over it refuses a token
from Okta. That is what makes the cut-over real, not a redirect change
(`tests/lib.test.mjs`).

## Group rules: why Clinic-Staff is not copied

Okta fills `Clinic-Staff` with the rule `String.substringAfter(user.login,
"@") == "contosohealthlab.com"`. The exact Entra translation is
`(user.userPrincipalName -endsWith "@contosohealthlab.com")`. After the
acquisition that is every hospital user. A 1:1 copy would give lab results
to the whole hospital. So the Entra app uses an assigned group
(`App-ClinicResults-Users`), and an access package can hand it out. The
billing rule (`user.department == "Clinic Billing"`) does translate safely and
is copied when Clinic Billing moves. `inventory.mjs` writes both decisions
into `tracker.md`.

## Phishing-resistant factors (Okta)

Read live on 2026-11-07 (`inventory.json`):
- The org's default policy (*Any two factors*) already demands a
  phishing-resistant, device-bound factor.
- The **Okta Admin Console** rule asks only for a password plus any second
  factor. That is weaker than the default.
- The one super admin has Okta Verify FastPass (`signed_nonce`) enrolled,
  which is phishing-resistant.

`admin_console_phishing_resistant = true` (with
`okta_admin_console_app_id`) adds a first rule to the console policy: a
phishing-resistant, device-bound factor at every console sign-in. It is off.
It changes how the owner signs in to the Okta Admin Console, so the owner
turns it on after checking FastPass works on the device they use. The clinic
apps do not demand phishing resistance: the clinic users' Entra MFA is an
authenticator code today, and a phishing-resistant rule would refuse them.
That step belongs to the passkey rollout, at Entra.

## Not built

- **Okta event hook.** It needs a public HTTPS endpoint that answers Okta's
  verification call. The lab has none that is free and safe to expose.
- **Okta Workflows.** The org lists the Workflows apps, but flows have no
  Terraform resource or public API to create them as code. A console-built
  flow would be the one hand-made object in this estate.

## Files

| File | What it does |
|---|---|
| `waves.json` | The plan: owner, wave, pilot, `cutover`, `retired` per app |
| `inventory.mjs` | Reads both APIs; writes the tracker files |
| `cutover.mjs` | `status`, `prestage`, `test`, `cutover`, `rollback` |
| `syslog.mjs` | Okta System Log and Entra sign-in log for one app, before and after |
| `clinic-results/app.mjs` | The wave-1 app: an OIDC relying party with no dependencies |
| `lib.mjs` | Shared code: Okta client, EL-to-Entra translator, tracker writers |
| `tests/lib.test.mjs` | Offline tests (CI: `lab-tests.yml`) |
| `results/` | One JSON per test sign-in (no tokens) |
| `tracker.csv`, `tracker.md`, `status.html`, `inventory.json` | Generated. Do not edit |
