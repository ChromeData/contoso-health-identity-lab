# Staff sign-in toolkit — `enroll.mjs`, `signin.mjs`

**Status: RAN · tenant** (2026-11-05, capture-log E100): `test-user-a` and
`test-user-b` were enrolled and then signed in headless with password +
authenticator code through Entra (My Apps, My Account).

The lab's staff accounts have no phone. These two scripts give a lab user a
real, phone-free MFA sign-in, so the demo and the evidence runs can show a
**staff member** signing in (to the AWS access portal, to Okta, to My Apps)
with Conditional Access evaluated for real, instead of an admin session.

| Script | What it does |
|---|---|
| `enroll.mjs <upn> [--force] [--headed] [--no-verify]` | Checks first, changes after: Playwright/Chromium must load and the password must be known (or settable) before anything on the account changes. Keeps the user's Keychain password (or sets a random one through Graph), issues a **one-time Temporary Access Pass** (60 min, the TAP policy minimum), signs in with it at `mysignins.microsoft.com/security-info`, adds an **authenticator app** ("Set up a different authentication app" → "Can't scan image?"), reads the secret key, stores it in the Keychain, enters the computed code, deletes any pass left, checks Graph lists the method, then proves a password + code sign-in reaches My Apps. `--force` replaces an authenticator the Keychain has no seed for: the new one is registered **first** and the old one deleted only once Graph lists the new one. The pass is deleted in a `finally`. |
| `signin.mjs <upn> <start-url> [--fresh] [--headed] [--identifier <name>] [--until <regex>] [--denied <regex>] [--no-kmsi] [--shot <name>]` | Opens the start URL and answers Entra's pages as the user (username, password, authenticator code, *Stay signed in?*, postponable nudges; Okta's identifier box when the start URL is Okta). Prints `{ok, landed, title, screenshot, storageState}`. |
| `lib.mjs` | Keychain read/write, TOTP (RFC 6238, node:crypto), Graph as the operator, Playwright loader, secret-blurring screenshots. |

As a module (other scripts):

```js
import { signIn } from './lab/scripts/demo/signin/signin.mjs';
const { page, context, browser, close } = await signIn('test-user-a@contosohealthlab.com',
  'https://d-90666212c7.awsapps.com/start', { headless: true, until: async (p) => /awsapps\.com\/start/.test(p.url()) });
// ... use page ...
await close();
```

Options: `fresh` (ignore the saved cookies), `until` (the app's own "signed
in" test), `landing` (`{ url, text, denied }` RegExps). Success needs a
**positive** landing signal: `APPS` in `signin.mjs` holds one per app the lab
signs in to (My Apps, My Account, My Sign-ins, AWS access portal and console,
Okta's dashboard, ServiceNow) together with that app's known **refusal** pages
(ServiceNow "user not found", Okta's factor-enrollment wall...), which fail the
run even after a clean Entra round trip. An app not in `APPS` needs `until` /
`--until` (and `--denied`); without one the run is an error, never "ok" (see
`landing()` / `verdict()`),
`identifier` (what to type in Okta's box; default the UPN), `kmsi` (answer to
*Stay signed in?*, default yes), `browser` (reuse a launched browser; the
caller closes it), `timeoutMs`.

## Where things live

| Thing | Where | Why |
|---|---|---|
| Password | Keychain `contoso-lab-pw-<local>`; the test users' older `contoso-lab-test-user-a/b/c` are used as they are. Every item (password, seed, pending) is read by service **and account = the full UPN** | Secrets only in the login Keychain (AGENT-RULES); the lab has two domains, so the local part alone could name two people |
| Authenticator seed | Keychain `contoso-lab-totp-<local>` (account = UPN), written over stdin to `security -i` **before** the code is submitted | A crash after Entra accepts the code cannot lose the seed |
| Temporary Access Pass | This process's memory only; deleted through Graph afterwards | One-time, never printed or stored |
| Cookies | `~/.contoso-operator/session/browser/<local>.json`, mode 600, with the owner's full UPN inside | The operator's private session folder; reused by the next `signIn` **only for that UPN** (a same-named user on the other lab domain, an owner-less or unreadable file starts clean) |
| Last code used | `~/.contoso-operator/session/browser/<local>.totp-step` (a counter, not a secret) and a `.totp-lock` while a code is chosen | Entra refuses a code twice: a second sign-in inside 30 s waits for the next code, also when two run at once (lock; a lock older than 90 s is taken over) |
| Failure screenshots | `$SIGNIN_SHOTS_DIR` (default `$TMPDIR/signin-shots`) | Seeds, QR codes and inputs are blurred before every screenshot |

## Why it is built this way

- **TAP, not password, to add the authenticator.** CA009 allows security-info
  registration only with a TAP or a phishing-resistant method. The script uses
  the same door a new hire uses on day one, so it proves that door works.
- **The operator issues the pass** (`op az rest`, UserAuthenticationMethod.ReadWrite.All),
  never the owner's account. Request bodies go to `az` on stdin
  (`--body @/dev/stdin`), so a password is never in argv.
- **TOTP in node:crypto.** No extra package to vet; the seed never leaves
  memory and the Keychain. `tests/lib.test.mjs` checks it against the RFC
  6238 and RFC 4226 test vectors.
- **A pass active on the account** (issued by someone else) is left alone: a password sign-in takes *Use your password instead*, as a user would.
- **Fail closed.** A Keychain that cannot be read (locked) stops the run; only
  "item not found" (exit 44) counts as "no password yet", so a working
  password is never overwritten by mistake. Graph errors stop the run.
- **Refused accounts.** The owner's account and break-glass accounts (`bg-*`)
  are refused by `checkUpn`, as are UPNs outside the lab's two domains.
- **Entra's hidden fields.** Entra keeps the other steps' inputs in the DOM
  (class `moveOffScreen`, opacity 0, `aria-hidden`); the driver acts only on
  what is really on screen.

## One sign-in for every lab identity: `identity.mjs`, `identities.json`, `doctor.mjs`

**Status: RAN · tenant** (2026-11-05, capture-log E103). The recording
browser signs itself in as any lab identity, with no human. GitHub is the one
exception: it stays the owner's own sign-in.

```js
import { signIn, keepSignedIn, activatePim } from './lab/scripts/demo/signin/identity.mjs';
// In the cockpit's own (persistent, headful) context - never closed by us:
const { page } = await signIn('adm-presenter', 'https://entra.microsoft.com/', { context });
const stop = keepSignedIn(context, 'adm-presenter');   // silent re-sign-in on expiry / CA020
await activatePim('adm-presenter', 'PIM-Demo-Readers', 8, 'INC-1234: demo, read-only', { context });
```

| Identity | Method | Used for |
|---|---|---|
| `adm-presenter` | passkey (virtual authenticator, Keychain credential) | read-only portals through PIM-Demo-Readers |
| `adm-ava.lin`, `adm-raj.patel`, `adm-mei.tanaka` | passkey | the PIM piece (admin badges) |
| `adm-labops`, `svc-soc-automation`, `test-user-a`, `test-user-b` | password + authenticator code | lab ops, SOC team, staff (My Apps, AWS, Teams), clinic (Okta) |
| `test-user-c` | one-time pass per sign-in | joiner user: no authenticator on purpose |
| `acr.breakglass` | ServiceNow `login.do` + ServiceNow authenticator code | ServiceNow admin side door |
| `splunk-admin`, `splunk-feed-check` | Splunk login form | Splunk Web |

- **`identities.json`** holds who and how. It contains **no secrets**, only
  references: Keychain `{service, account}`, or `{file, key}` for Splunk's own
  `.env`. `validateRegistry()` refuses a plain string where a reference
  belongs, any extra field in a reference, the owner's and break-glass
  accounts, and file paths outside the repo.
- **`signIn(id, url, { context, page, allowTap, until, landing })`** picks the
  method from the registry.
  - With `context` it works inside the caller's context and never closes it.
    A passkey identity gets a CDP virtual authenticator on the page being
    signed in (and its popups) only. The new signature counter is written back
    to the Keychain.
  - `allowTap` lets an identity with `fallback: "tap"` use a one-time pass if
    its own method fails. It is off by default because a pass is a credential
    issued in the tenant.
- **One Entra identity per context.** `signIn` refuses a context that is
  already signed in to Entra as someone else; switching users inside one
  context would let an app keep the old account silently. A context with an
  Entra session the tool did not make is checked once, on My Account. The
  cockpit therefore uses one context (or profile) per Entra identity.
  ServiceNow and Splunk identities can share any context.
- **Local passwords and codes are typed only into the exact origin** (scheme,
  host, port) of the identity's `loginUrl`.
- **`keepSignedIn(context, id)`** watches every page of the context, including
  pages already on a sign-in screen when it starts. When an
  app sends one back to a sign-in page, it signs in again where the page is:
  an expired session, CA020's 4-hour re-authentication, ServiceNow's or
  Splunk's login form. This was seen live after wiping the session.
  "Stay signed in?" is answered yes.
- **`activatePim(id, group, hours, reason)`** (**BUILT**, not yet run live: its first live run is adm-presenter → PIM-Demo-Readers after that group's apply). The duration must be set and read back. Success means the group's row under *Active assignments* with Deactivate; otherwise it throws and records nothing. It goes through Entra admin center →
  PIM → My roles → Groups → Activate, with duration and justification. If the
  blade asks for a fresh MFA, the identity's own method answers it in place.
  The end time is recorded in `~/.contoso-operator/session/browser/<id>.pim.json`
  for the doctor. The operator cannot read active PIM assignments, and isn't
  given that right.
- **`doctor.mjs`** (signin-doctor) tries every identity with a fresh headless
  sign-in and prints: identity, method, works, session age, PIM state, next
  expiry. `--summary` is the line `preflight.sh` prints, `--json` gives one
  object per identity, and `--with-tap` also tries the pass-based identities.
- **Success needs a positive landing signal** (`APPS` in `signin.mjs`, now
  including the admin portals, Teams, Splunk and ServiceNow's Next Experience
  shell). A sign-in page never counts: ServiceNow's `navpage.do` "Log in to
  your account" was a false positive found live and is now a test.

## Known limits (seen live)

- **`--force` on an account that already has an authenticator** stops at
  *Security info*: after the one-time pass sign-in, My Signins cannot get its
  Graph token (AADSTS90202, *A transient error has occurred*; sign-in log row
  *My Signins -> Microsoft Graph*, 2026-11-05, twice in a row on test-user-b).
  The run fails in seconds and leaves the account exactly as it was: the old
  method stays registered, the old seed stays in the Keychain (checked: it
  still signs in), no `-pending` item is left and the pass is deleted. To
  replace a seed the Keychain has lost, an operator removes the old method
  first (`DELETE .../softwareOathMethods/<id>`, see *Undo*) and runs
  `enroll.mjs` without `--force`: a first-time enrollment works (E100's runs).
- The Okta and AWS demo runs need the user to have a first and last name in
  Entra: both AWS IAM Identity Center (SCIM) and Okta (JIT) refuse to create a
  user without them.

## Tests

```bash
node --test lab/scripts/demo/signin/tests/lib.test.mjs lab/scripts/demo/signin/tests/enroll.test.mjs lab/scripts/demo/signin/tests/identity.test.mjs   # offline: no tenant, browser or Keychain
```

CI runs them in `lab-tests.yml` (*Shell tests (no containers)*).

## Undo

```bash
# as the operator: remove the authenticator app (the Keychain seed is then useless)
lab/scripts/operator/op az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<upn>/authentication/softwareOathMethods"
lab/scripts/operator/op az rest --method DELETE --url "https://graph.microsoft.com/v1.0/users/<upn>/authentication/softwareOathMethods/<id>"
security delete-generic-password -s contoso-lab-totp-<local>
rm ~/.contoso-operator/session/browser/<local>.*
```
