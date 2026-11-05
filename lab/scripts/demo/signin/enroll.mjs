#!/usr/bin/env node
// =============================================================================
// lab/scripts/demo/signin/enroll.mjs - give a lab user a phone-free MFA sign-in
// -----------------------------------------------------------------------------
//   node enroll.mjs <upn> [--force] [--headed] [--no-verify]
//
// What it does, in order (each step says why):
//   1. Password. If the Keychain already holds one for the user
//      (contoso-lab-pw-<local> or, for the test users, contoso-lab-<local> with
//      the UPN as account), it is kept. Otherwise a strong random password is
//      set through Graph (as the lab operator, body on stdin) and stored as
//      contoso-lab-pw-<local>. Nobody ever sees it.
//   2. Temporary Access Pass. The operator issues a ONE-TIME pass with the
//      shortest lifetime the tenant allows (60 minutes, the TAP policy's
//      minimum). It is held in this process's memory only. Why a TAP:
//      CA009 lets security info be registered only with a TAP or a
//      phishing-resistant method, so a password alone cannot add an
//      authenticator - which is exactly what stops an attacker who has only
//      the password.
//   3. Registration, as the user, in headless Chromium at
//      https://mysignins.microsoft.com/security-info: Add sign-in method ->
//      Microsoft Authenticator -> "I want to use a different authenticator
//      app" -> "Can't scan image?" -> the secret key is read from the page,
//      stored in the Keychain as contoso-lab-totp-<local> (before the code is
//      submitted, so a crash after Entra accepts it cannot lose the seed), the
//      RFC 6238 code is computed and entered, and the method is saved.
//   4. Clean-up and proof: any pass left on the account is deleted, Graph
//      must list the new software OATH method, and (unless --no-verify) a
//      fresh password + code sign-in through signin.mjs must reach My Apps.
//
// Graph calls (all as the lab operator, Microsoft Learn "authentication
// methods" API reference, v1.0):
//   GET/DELETE /users/{id}/authentication/softwareOathMethods[/{id}]
//   GET/POST/DELETE /users/{id}/authentication/temporaryAccessPassMethods
//     (UserAuthenticationMethod.ReadWrite.All; verified live 2026-11-05, E71)
//   PATCH /users/{id} passwordProfile - only for a user with no Keychain
//     password. NOT exercised live (the test users have Keychain passwords);
//     if the operator may not reset that user's password, Graph answers 403
//     and the run stops before any pass is issued.
//
// --force replaces an authenticator-app method that the Keychain has no seed
// for (deletes it through Graph first). Without it such an account is left
// alone. The owner's and break-glass accounts are refused (lib.mjs).
// Failure screenshots (seed, QR and inputs blurred) go to $SIGNIN_SHOTS_DIR.
// =============================================================================
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  checkUpn, localPart, graph, keychainRead, keychainWrite, passwordFor, pwService, totpService,
  randomPassword, totp, markTotpStep, playwright, shot, pageText, sleep, log,
} from './lib.mjs';
import { drive, signIn } from './signin.mjs';

const SECURITY_INFO = 'https://mysignins.microsoft.com/security-info';
const SEED_RE = /\b((?:[A-Z2-7]{4}\s?){4,}[A-Z2-7]*)\b/;

// Names of what is on screen (buttons, links, headings), seeds filtered out:
// the trail a failure message carries.
async function ui(page) {
  const out = [];
  for (const f of page.frames()) {
    const t = await f.evaluate(() => [...document.querySelectorAll('h1,h2,h3,[role=heading],button,a,[role=button],[role=link],[role=menuitem],[role=option]')]
      .filter((e) => e.offsetParent !== null).map((e) => (e.innerText || e.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ')).filter((x) => x && x.length < 90)).catch(() => []);
    out.push(...t);
  }
  return [...new Set(out)].filter((x) => !SEED_RE.test(x)).slice(0, 40).join(' | ');
}
async function clickText(page, re, { timeout = 20000, roles = ['button', 'link', 'menuitem', 'option'] } = {}) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    for (const f of page.frames()) {
      for (const r of roles) {
        const l = f.getByRole(r, { name: re }).first();
        if (await l.isVisible().catch(() => false)) { await l.click(); return true; }
      }
      const t = f.getByText(re).first();
      if (await t.isVisible().catch(() => false)) { await t.click(); return true; }
    }
    await sleep(500);
  }
  throw new Error(`no "${re.source}" on the page. On screen: ${await ui(page)}`);
}
async function waitText(page, re, timeout = 30000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (re.test(await pageText(page))) return true; await sleep(700); }
  throw new Error(`"${re.source}" never appeared. On screen: ${await ui(page)}`);
}

export async function enroll(upn, { force = false, headless = true, verify = true } = {}) {
  upn = checkUpn(upn);
  const local = localPart(upn);
  const user = graph('GET', `users/${encodeURIComponent(upn)}?$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled`);
  if (!user.accountEnabled) throw new Error(`${upn} is disabled`);
  const uid = user.id;

  // ---- 0. already enrolled? ----------------------------------------------------
  const oath = graph('GET', `users/${uid}/authentication/softwareOathMethods`).value || [];
  const haveSeed = !!keychainRead(totpService(upn));
  if (oath.length && haveSeed && !force) { log(`${local}: already enrolled (authenticator app + Keychain seed); --force to redo`); return { upn, already: true }; }
  if (oath.length && !force) throw new Error(`${upn} has an authenticator-app method the Keychain has no seed for; re-run with --force to replace it`);
  for (const m of oath) { graph('DELETE', `users/${uid}/authentication/softwareOathMethods/${m.id}`); log(`${local}: removed the old authenticator-app method`); }

  // ---- 1. password -------------------------------------------------------------
  let pw = passwordFor(upn);
  if (pw) log(`${local}: keeping the password in Keychain item ${pw.service}`);
  else {
    if (user.onPremisesSyncEnabled) throw new Error(`${upn} is synced from AD: its password belongs to AD, not Graph`);
    const value = randomPassword();
    graph('PATCH', `users/${uid}`, { passwordProfile: { password: value, forceChangePasswordNextSignIn: false } });
    keychainWrite(pwService(upn), upn, `Contoso lab password for ${upn}`, value);
    pw = { service: pwService(upn), value };
    log(`${local}: set a new random password (Keychain ${pw.service})`);
  }

  // ---- 2. one-time Temporary Access Pass --------------------------------------
  const removeTaps = () => { for (const m of graph('GET', `users/${uid}/authentication/temporaryAccessPassMethods`).value || []) graph('DELETE', `users/${uid}/authentication/temporaryAccessPassMethods/${m.id}`); };
  removeTaps();
  let tap = graph('POST', `users/${uid}/authentication/temporaryAccessPassMethods`, { lifetimeInMinutes: 60, isUsableOnce: true }).temporaryAccessPass;
  if (!tap) throw new Error('the Temporary Access Pass was not issued');
  log(`${local}: one-time Temporary Access Pass issued (60 min, single use; held in memory)`);

  const browser = await playwright().chromium.launch({ headless });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US' });
  const page = await context.newPage();
  let seed = null;
  try {
    // ---- 3. sign in with the pass and register the authenticator app ---------
    await page.goto(SECURITY_INFO, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await drive(page, upn, { tap, kmsi: false, until: async (p) => /mysignins\.microsoft\.com/.test(p.url()) && /Security info/i.test(await pageText(p)) });
    tap = null;
    log(`${local}: on Security info`);
    await sleep(2500);

    await clickText(page, /Add sign-in method/i);
    await sleep(1500);
    // The chooser: a list of methods (newer UI) or a drop-down (older UI).
    const combo = page.getByRole('combobox').first();
    if (await combo.isVisible().catch(() => false)) {
      await combo.click(); await sleep(500);
      await clickText(page, /^Authenticator app$|^Microsoft Authenticator$/i, { roles: ['option'] });
      await clickText(page, /^Add$/i);
    } else {
      await clickText(page, /^Microsoft Authenticator\b/i);
    }
    await sleep(1500);
    // The link's wording changed in 2026 ("Set up a different authentication app"); both are accepted.
    await clickText(page, /I want to use a different authenticator app|Set up a different authenticat(ion|or) app/i);
    await sleep(1200);
    // "Set up your account" -> Next, until the QR page.
    const CANT_SCAN = /Can.t scan (the )?(image|QR code)\??|Enter code manually|Set up manually/i;
    for (let i = 0; i < 3 && !CANT_SCAN.test(await pageText(page)); i++) { await clickText(page, /^Next$/i); await sleep(1500); }
    await clickText(page, CANT_SCAN);
    await sleep(1000);
    const txt = await pageText(page);
    const m = txt.match(/Secret key:?\s*\n?\s*([A-Z2-7 ]{16,})/i) || txt.match(SEED_RE);
    if (!m) throw new Error(`no secret key on the page. On screen: ${await ui(page)}`);
    seed = m[1].replace(/\s+/g, '').toUpperCase();
    totp(seed); // throws if it is not base32
    keychainWrite(totpService(upn), upn, `Contoso lab authenticator seed for ${upn}`, seed);
    log(`${local}: secret key read and stored in Keychain ${totpService(upn)}`);
    await clickText(page, /^Next$/i);
    await sleep(1500);

    // The code. A fresh one (not inside the last 5 s of its window).
    let t = totp(seed); if (t.secondsLeft < 6) { await sleep(t.secondsLeft * 1000 + 500); t = totp(seed); }
    const box = page.locator('input[type=text], input[type=tel], input[inputmode=numeric], input[aria-label*="code" i]').filter({ visible: true }).first();
    await box.fill(t.code);
    markTotpStep(upn, t.counter); // this code is spent: the first sign-in waits for the next one
    await clickText(page, /^Next$/i);
    await waitText(page, /successfully registered|was registered|Authenticator app\b[\s\S]*added|Default sign-in method/i, 30000);
    log(`${local}: authenticator app registered`);
    await sleep(1500);
    const done = await shot(page, `enroll-ok-${local}`);

    // ---- 4. clean-up and proof -------------------------------------------------
    removeTaps();
    const after = graph('GET', `users/${uid}/authentication/softwareOathMethods`).value || [];
    if (!after.length) throw new Error('Graph lists no authenticator-app method after registration');
    log(`${local}: Graph lists ${after.length} authenticator-app method(s); no pass left`);
    await context.close(); await browser.close();

    let verified = null;
    if (verify) {
      const r = await signIn(upn, 'https://myapps.microsoft.com/', { fresh: true, until: async (p) => /myapps\.microsoft\.com|myapplications\.microsoft\.com/.test(p.url()) && /Apps|My Apps/i.test(await pageText(p)) });
      verified = { landed: r.page.url(), screenshot: await shot(r.page, `verify-myapps-${local}`) };
      await r.close();
      log(`${local}: password + authenticator code sign-in reached My Apps`);
    }
    return { upn, enrolled: true, passwordItem: pw.service, seedItem: totpService(upn), screenshot: done, verified };
  } catch (e) {
    const f = await shot(page, `enroll-fail-${local}`);
    await context.close().catch(() => {}); await browser.close().catch(() => {});
    try { removeTaps(); } catch {}
    e.message += ` [screenshot: ${f}]`;
    throw e;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const a = process.argv.slice(2);
  const flag = (n) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
  const force = flag('--force'), headed = flag('--headed'), noVerify = flag('--no-verify');
  const [upn] = a;
  if (!upn) { console.error('usage: node enroll.mjs <upn> [--force] [--headed] [--no-verify]'); process.exit(2); }
  try { console.log(JSON.stringify({ ok: true, ...(await enroll(upn, { force, headless: !headed, verify: !noVerify })) })); }
  catch (e) { console.log(JSON.stringify({ ok: false, upn, error: e.message })); process.exit(1); }
}
