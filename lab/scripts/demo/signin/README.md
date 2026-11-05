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
| `signin.mjs <upn> <start-url> [--fresh] [--headed] [--identifier <name>] [--until <regex>] [--no-kmsi] [--shot <name>]` | Opens the start URL and answers Entra's pages as the user (username, password, authenticator code, *Stay signed in?*, postponable nudges; Okta's identifier box when the start URL is Okta). Prints `{ok, landed, title, screenshot, storageState}`. |
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
in" test - recommended; without it, success needs a round trip through Entra
in this run, no password box on the app page and a URL steady for 2.5 s, and
an app reached without any Entra visit is an error, never "ok"; see
`verdict()`),
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
node --test lab/scripts/demo/signin/tests/lib.test.mjs lab/scripts/demo/signin/tests/enroll.test.mjs   # offline: no tenant, browser or Keychain
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
