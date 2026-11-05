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
//     (UserAuthenticationMethod.ReadWrite.All; verified live 2026-11-05, E100)
//   PATCH /users/{id} passwordProfile - only for a user with no Keychain
//     password. NOT exercised live (the test users have Keychain passwords);
//     if the operator may not reset that user's password, Graph answers 403
//     and the run stops before any pass is issued.
//
// --force replaces an authenticator-app method that the Keychain has no seed
// for: the new one is registered first and the old one deleted only after
// Graph lists the new one, so a failed run never leaves the account without
// working MFA. Without --force such an account is left alone. Nothing changes
// on the account until Playwright, Chromium and the password check pass, and
// the pass is deleted in a `finally`, whatever happens (a failed deletion is
// an error that names the pass, never silent). A new password and a new seed
// each wait in a "-pending" Keychain item until the account / Entra has
// accepted them, so the real items always hold what works. The owner's and break-glass accounts are refused (lib.mjs).
// Failure screenshots (seed, QR and inputs blurred) go to $SIGNIN_SHOTS_DIR.
// =============================================================================
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  checkUpn, localPart, graph, keychain, keychainRead, passwordFor, pwService, pendingService, totpService,
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

// ---- the three steps that touch secrets, each keeping the Keychain true ------
// Exported with injectable Graph / Keychain so tests/enroll.test.mjs can make
// every step fail and check what is left behind.

// A new random password is stored (pending item) and READ BACK before the
// account changes, so a Keychain failure can never leave the account with a
// password nobody holds. Only after Graph accepts it is it promoted to the
// real item; if promotion fails, the error names the pending item that holds it.
export function setRandomPassword({ upn, uid, g = graph, kc = keychain, gen = randomPassword }) {
  const final = pwService(upn), pending = pendingService(final);
  const value = gen();
  kc.write(pending, upn, `Contoso lab password for ${upn} (pending)`, value);
  if (kc.read(pending) !== value) throw new Error(`Keychain item ${pending} did not read back: the account was not changed`);
  try { g('PATCH', `users/${uid}`, { passwordProfile: { password: value, forceChangePasswordNextSignIn: false } }); }
  catch (e) { kc.del(pending); throw e; } // the account kept its old password; the unused one goes
  try { kc.write(final, upn, `Contoso lab password for ${upn}`, value); }
  catch (e) { throw new Error(`the account's new password is in force and saved ONLY in Keychain item ${pending} (promoting it to ${final} failed: ${e.message})`); }
  kc.del(pending);
  return { service: final, value };
}

// The authenticator seed waits in a pending item while Entra checks the code;
// the real item (what sign-ins use) is replaced only after Entra confirmed
// the registration and Graph lists the new method. A failed --force run so
// keeps the working seed of the method that is still registered.
export function stageSeed({ upn, seed, kc = keychain }) {
  const p = pendingService(totpService(upn));
  kc.write(p, upn, `Contoso lab authenticator seed for ${upn} (pending)`, seed);
  return p;
}
export function promoteSeed({ upn, seed, kc = keychain }) {
  kc.write(totpService(upn), upn, `Contoso lab authenticator seed for ${upn}`, seed);
  kc.del(pendingService(totpService(upn)));
}

// The pass we issued, and its removal. Only a pass that is confirmed gone (404)
// counts as removed; any other failure keeps its id (so a later call retries)
// and throws, naming the pass and the command that deletes it.
export function tapCleaner({ upn, uid, g = graph }) {
  let id = null;
  const notFound = (e) => /\b404\b|Not ?Found|ResourceNotFound|does not exist/i.test(String(e && e.message));
  return {
    get id() { return id; },
    set(v) { id = v; },
    remove() {
      if (!id) return;
      try { g('DELETE', `users/${uid}/authentication/temporaryAccessPassMethods/${id}`); id = null; } catch (e) {
        if (notFound(e)) { id = null; return; }
        throw new Error(`could not delete the Temporary Access Pass ${id} on ${upn} - it stays valid until it expires (${String(e.message).split('\n').filter(Boolean).slice(-1)[0].slice(0, 200)}). Delete it: lab/scripts/operator/op az rest --method DELETE --url "https://graph.microsoft.com/v1.0/users/${uid}/authentication/temporaryAccessPassMethods/${id}"`);
      }
    },
  };
}

export async function enroll(upn, { force = false, headless = true, verify = true } = {}) {
  upn = checkUpn(upn);
  const local = localPart(upn);
  const user = graph('GET', `users/${encodeURIComponent(upn)}?$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled`);
  if (!user.accountEnabled) throw new Error(`${upn} is disabled`);
  const uid = user.id;

  // ---- 0. already enrolled? ----------------------------------------------------
  const oldOath = (graph('GET', `users/${uid}/authentication/softwareOathMethods`).value || []).map((m) => m.id);
  const haveSeed = !!keychainRead(totpService(upn));
  if (oldOath.length && haveSeed && !force) { log(`${local}: already enrolled (authenticator app + Keychain seed); --force to redo`); return { upn, already: true }; }
  if (oldOath.length && !force) throw new Error(`${upn} has an authenticator-app method the Keychain has no seed for; re-run with --force to replace it`);

  // ---- 1. everything that can fail without changing the account, first ----------
  // Playwright and Chromium must load, and the password must be known or
  // settable, BEFORE any pass is issued or any method touched: a run that
  // cannot finish must leave the account as it found it.
  const pwLib = playwright();
  let pw = passwordFor(upn);
  if (!pw && user.onPremisesSyncEnabled) throw new Error(`${upn} is synced from AD and has no Keychain password: its password belongs to AD, not Graph`);
  const browser = await pwLib.chromium.launch({ headless });

  const tapc = tapCleaner({ upn, uid });
  let page = null, context = null, failed = null;
  try {
    if (pw) log(`${local}: keeping the password in Keychain item ${pw.service}`);
    else {
      pw = setRandomPassword({ upn, uid });
      log(`${local}: set a new random password (saved and read back first; Keychain ${pw.service})`);
    }

    // ---- 2. one-time Temporary Access Pass ----------------------------------------
    // Entra holds one pass per user, so an existing one is deleted first (logged).
    for (const m of graph('GET', `users/${uid}/authentication/temporaryAccessPassMethods`).value || []) {
      graph('DELETE', `users/${uid}/authentication/temporaryAccessPassMethods/${m.id}`);
      log(`${local}: removed an existing Temporary Access Pass (created ${m.createdDateTime})`);
    }
    const issued = graph('POST', `users/${uid}/authentication/temporaryAccessPassMethods`, { lifetimeInMinutes: 60, isUsableOnce: true });
    tapc.set(issued.id);
    let tap = issued.temporaryAccessPass;
    if (!tap) throw new Error('the Temporary Access Pass was not issued');
    log(`${local}: one-time Temporary Access Pass issued (60 min, single use; held in memory)`);

    context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US' });
    page = await context.newPage();

    // ---- 3. sign in with the pass and register the authenticator app -----------
    // My Signins reports one failure only in its console: AADSTS90202 on its
    // Graph token, seen live (2026-11-05) on an account that ALREADY has an
    // authenticator and signs in with a one-time pass. It is turned into an
    // immediate error (other AADSTS codes in the console are normal silent-SSO
    // noise and are ignored).
    let failSecurityInfo;
    const securityInfoFailed = new Promise((_, rej) => { failSecurityInfo = rej; });
    securityInfoFailed.catch(() => {});
    page.on('console', (m) => { const x = m.text().match(/AADSTS90202[^\n]*/); if (x) failSecurityInfo(new Error(`Security info did not load: ${x[0].slice(0, 160)} - My Signins could not get its Graph token after the one-time pass sign-in (seen when the account already has an authenticator; README "Known limits")`)); });
    await page.goto(SECURITY_INFO, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await Promise.race([securityInfoFailed, drive(page, upn, { tap, kmsi: false, until: async (p) => /mysignins\.microsoft\.com/.test(p.url()) && /Security info/i.test(await pageText(p)) })]);
    tap = null;
    log(`${local}: on Security info`);
    await sleep(2500);

    await clickText(page, /Add sign-in method/i);
    await sleep(1500);
    // The chooser: a list of methods (2026 UI) or a drop-down (older UI).
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
    const seed = m[1].replace(/\s+/g, '').toUpperCase();
    totp(seed); // throws if it is not base32
    const pendingItem = stageSeed({ upn, seed });
    log(`${local}: secret key read; held in Keychain ${pendingItem} until Entra accepts it`);
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
    const now = (graph('GET', `users/${uid}/authentication/softwareOathMethods`).value || []).map((x) => x.id);
    const added = now.filter((id) => !oldOath.includes(id));
    if (!added.length) throw new Error(`Graph lists no NEW authenticator-app method after registration (the seed stays in Keychain ${pendingItem})`);
    // Entra confirmed and Graph lists it: now the seed sign-ins use is replaced.
    promoteSeed({ upn, seed });
    log(`${local}: seed promoted to Keychain ${totpService(upn)}`);
    tapc.remove();
    // --force: the old method(s) go only now, after the new one is in place,
    // so a failed run never leaves the account without its working MFA.
    for (const id of oldOath) { graph('DELETE', `users/${uid}/authentication/softwareOathMethods/${id}`); log(`${local}: removed the replaced authenticator-app method`); }
    log(`${local}: Graph lists the new authenticator-app method; no pass of ours left`);
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
    failed = e;
    const f = page ? await shot(page, `enroll-fail-${local}`) : null;
    if (f) e.message += ` [screenshot: ${f}]`;
    throw e;
  } finally {
    // Whatever happened, no pass of ours outlives the run - or the run says so, loudly.
    try { tapc.remove(); } catch (ce) {
      console.error(`[signin] ${local}: ERROR ${ce.message}`);
      if (failed) failed.message += ` | ALSO: ${ce.message}`; else throw ce; // eslint-disable-line no-unsafe-finally
    } finally { await browser.close().catch(() => {}); }
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
