#!/usr/bin/env node
// capture.mjs - sign a user in to the Contoso Claims Viewer through whichever
// IdP it trusts right now (cutover.sh), and save the claims it received.
//
//   node lab/adfs/compare/capture.mjs <upn> <out.json> [--headed]
//
// Before the cutover the app sends the browser to AD FS; after it, to Entra.
// The same command captures both sides, so lab/adfs/compare/compare_claims.py
// compares like with like: the claims the APP received, from the app's own
// ?format=json page (SimpleSAMLphp has already checked the signature).
//
// AD FS side: needs enable_adfs_https (443 to DC01 from the operator's /32).
//   ADFS_HOST (default sts.corp.contosohealthlab.com) and ADFS_IP (DC01's
//   public IP) map the name in Chromium only (--host-resolver-rules), so no
//   /etc/hosts edit. ADFS_PIN is the AD FS certificate's SPKI pin
//   (fetch-metadata.sh pin); Chromium trusts that ONE self-signed key
//   (--ignore-certificate-errors-spki-list), not every bad certificate.
// Entra side: the lab staff sign-in toolkit (password + authenticator code,
//   lab/scripts/demo/signin); the user must be enrolled (enroll.mjs).
// Password: Keychain contoso-lab-pw-<local part>, account = UPN. Never printed.
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { signIn } from '../../scripts/demo/signin/signin.mjs';
import { playwright, passwordFor, checkUpn } from '../../scripts/demo/signin/lib.mjs';

const [upn, out] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const headed = process.argv.includes('--headed');
if (!upn || !out) { console.error('usage: capture.mjs <upn> <out.json> [--headed]'); process.exit(2); }
checkUpn(upn);

const APP = 'https://localhost:8443/';
const host = process.env.ADFS_HOST || 'sts.corp.contosohealthlab.com';
const args = [];
// TLS: two self-signed keys are trusted BY PIN, nothing else is relaxed. The
// Claims Viewer's loopback key (read from the running container) and, when
// set, the AD FS key. Entra's pages keep normal certificate checks.
// verify: Chromium honours --ignore-certificate-errors-spki-list only with a
// user data dir; Playwright's launch() passes a temporary one.
const pins = [cvPin()];
if (process.env.ADFS_IP) args.push(`--host-resolver-rules=MAP ${host} ${process.env.ADFS_IP}`);
if (process.env.ADFS_PIN) pins.push(process.env.ADFS_PIN);
args.push(`--ignore-certificate-errors-spki-list=${pins.join(',')}`);

const browser = await playwright().chromium.launch({ headless: !headed, args });
const onApp = (p) => p.url().startsWith(APP) && !p.url().includes('/simplesaml/');
let page;
let close = async () => browser.close();
try {
  // Which IdP? Follow the app's redirect once without signing in.
  const probeCtx = await browser.newContext();
  const probe = await probeCtx.newPage();
  await probe.goto(APP, { waitUntil: 'domcontentloaded' });
  const idpUrl = probe.url();
  await probeCtx.close();

  if (idpUrl.includes(host)) {
    // AD FS forms sign-in (the default AD FS page: #userNameInput, #passwordInput).
    const ctx = await browser.newContext();
    page = await ctx.newPage();
    await page.goto(APP, { waitUntil: 'domcontentloaded' });
    await page.fill('#userNameInput', upn);
    const pw = passwordFor(upn);   // { service, value } or null (lib.mjs)
    if (!pw) throw new Error(`no Keychain password for ${upn} (contoso-lab-pw-<local part>, account = UPN)`);
    await page.fill('#passwordInput', pw.value);
    await Promise.all([page.waitForURL((u) => onApp({ url: () => u.toString() }), { timeout: 60000 }), page.click('#submitButton')]);
  } else if (idpUrl.includes('login.microsoftonline.com')) {
    const r = await signIn(upn, APP, { browser, headless: !headed, fresh: true, until: async (p) => onApp(p) });
    page = r.page;
    const prev = close; close = async () => { await r.close(); await prev(); };
  } else {
    throw new Error(`the app sent the browser to an unexpected place: ${new URL(idpUrl).host}`);
  }

  await page.goto(`${APP}?format=json`, { waitUntil: 'domcontentloaded' });
  const claims = JSON.parse(await page.locator('body').innerText());
  fs.writeFileSync(out, JSON.stringify(claims, null, 2));
  console.log(JSON.stringify({ ok: true, source: claims.source, issuer: claims.issuer, claimTypes: Object.keys(claims.attributes).length, out }));
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: String(e.message || e).replace(/\s+/g, ' ').slice(0, 300) }));
  process.exitCode = 1;
} finally {
  await close();
}

// SPKI pin (base64 SHA-256 of the public key) of the Claims Viewer's TLS key.
function cvPin() {
  const r = spawnSync('docker', ['exec', 'contoso-claims-viewer', 'sh', '-c',
    'openssl x509 -in /etc/ssl/certs/cv.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64'], { encoding: 'utf8' });
  const pin = (r.stdout || '').trim();
  if (r.status !== 0 || !/^[A-Za-z0-9+/]{43}=$/.test(pin)) throw new Error('cannot read the Claims Viewer TLS pin (is the container running? cutover.sh status)');
  return pin;
}
