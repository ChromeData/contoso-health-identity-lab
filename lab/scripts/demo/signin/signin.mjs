#!/usr/bin/env node
// =============================================================================
// lab/scripts/demo/signin/signin.mjs - sign a lab user in through Entra
// -----------------------------------------------------------------------------
//   node signin.mjs <upn> <start-url> [--headed] [--fresh] [--identifier <name>] [--until <regex>] [--no-kmsi]
//
//   import { signIn } from '<repo>/lab/scripts/demo/signin/signin.mjs';
//   const { page, context, browser, close } = await signIn(upn, url, { headless: true });
//
// Opens <start-url> (any app that sends people to Entra: the AWS access
// portal, Okta, My Apps, ServiceNow...), answers Entra's pages as the user
// would - username, password (Keychain), the authenticator-app code (TOTP from
// the Keychain seed enroll.mjs stored), "Stay signed in?" - and returns the
// signed-in Playwright page once the browser is back on the app.
//
// WHY headless + Keychain: the lab's staff accounts have no phone; their MFA is
// a software authenticator whose seed only this Mac holds. Conditional Access
// still runs for real (CA001 "MFA for all users" is satisfied by that code),
// so a sign-in made here is a real staff sign-in in the Entra sign-in log.
//
// The storage state (cookies) is saved per user, mode 600, under
// ~/.contoso-operator/session/browser/<local-part>.json and reused on the next
// call (pass { fresh: true } / --fresh to start clean). A failure leaves a
// screenshot (secrets blurred) in $SIGNIN_SHOTS_DIR and names it in the error.
// =============================================================================
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  checkUpn, localPart, keychainRead, passwordFor, totpService, freshTotp, playwright,
  statePath, saveState, shot, pageText, sleep, log,
} from './lib.mjs';

const LOGIN_HOST = /(^|\.)(login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com|login\.windows\.net|autologon\.microsoftazuread-sso\.com|device\.login\.microsoftonline\.com)$/i;
const OKTA_HOST = /\.(okta|oktapreview|okta-emea)\.com$/i;
const host = (u) => { try { return new URL(u).hostname; } catch { return ''; } };

// A locator that is really on screen. Entra keeps the boxes of the other
// steps in the DOM for password managers - class moveOffScreen, opacity 0,
// aria-hidden, 10 px wide in a corner - so isVisible() alone is not enough.
async function onScreen(scope, sel) {
  const all = scope.locator(sel);
  const n = Math.min(await all.count().catch(() => 0), 8);
  for (let i = 0; i < n; i++) {
    const l = all.nth(i);
    if (!(await l.isVisible().catch(() => false))) continue;
    const real = await l.evaluate((e) => {
      const r = e.getBoundingClientRect();
      if (r.width < 16 || r.height < 8 || r.x < -5 || r.y < -5) return false;
      if (e.closest('[aria-hidden="true"], .moveOffScreen')) return false;
      for (let x = e; x; x = x.parentElement) if (Number(getComputedStyle(x).opacity) < 0.05) return false;
      return true;
    }).catch(() => false);
    if (real) return l;
  }
  return null;
}
async function clickSubmit(page) {
  const b = await onScreen(page, '#idSIButton9, button[type=submit]:not([disabled]), input[type=submit]:not([disabled])');
  if (b) await b.click(); else await page.keyboard.press('Enter');
}

// One pass over the page: do the single thing Entra (or Okta's identifier page)
// is asking for, and say what it was. Null = nothing to do on this pass.
async function step(page, upn, s) {
  const h = host(page.url());
  if (OKTA_HOST.test(h)) {
    const id = await onScreen(page, 'input[name="identifier"], input[name="username"]');
    if (id) {
      const want = s.identifier || upn;
      if ((await id.inputValue().catch(() => '')) !== want) await id.fill(want);
      const go = await onScreen(page, 'input[type=submit][value="Next"], button[type=submit], input[type=submit]');
      if (go) await go.click(); else await page.keyboard.press('Enter');
      return `okta identifier (${want})`;
    }
    return null;
  }
  if (!LOGIN_HOST.test(h)) return null;

  const text = await pageText(page);
  const aadsts = text.match(/AADSTS\d+[^\n]*/);
  if (aadsts && !(await onScreen(page, 'input[name=loginfmt], input[name=passwd], input[name=otc]'))) throw new Error(`Entra refused the sign-in: ${aadsts[0].slice(0, 300)}`);

  // Pick an account.
  if (await onScreen(page, '#tilesHolder, [data-test-id="tilesHolder"]')) {
    const tile = await onScreen(page, `[data-test-id="${upn}"], div[role=button]:has-text("${upn}")`);
    if (tile) { await tile.click(); return 'picked the account tile'; }
    const other = await onScreen(page, '#otherTile, [data-test-id="otherTile"], div[role=button]:has-text("Use another account")');
    if (other) { await other.click(); return 'use another account'; }
  }

  // Temporary Access Pass (enroll.mjs only).
  const tapBox = await onScreen(page, 'input[name=accesspass], #accesspass');
  if (tapBox) {
    if (!s.tap) {
      // A pass is active on the account (someone issued one) and Entra offers
      // it first. A password sign-in takes "Use your password instead", as a
      // user would; the pass is left alone (it is not ours to delete).
      const sw = await onScreen(page, '#idA_PWD_SwitchToPassword, a:has-text("Use your password instead"), button:has-text("Use your password instead")');
      if (sw && !s.switchedToPassword) { s.switchedToPassword = true; await sw.click(); return 'a pass is active on the account: use your password instead'; }
      throw new Error('Entra asked for a Temporary Access Pass, this sign-in has none, and there is no "Use your password instead"');
    }
    if (s.tapUsed) throw new Error('Entra asked for the Temporary Access Pass twice: it was refused');
    await tapBox.fill(s.tap); s.tapUsed = true; await clickSubmit(page); return 'temporary access pass';
  }

  // Password.
  const pw = await onScreen(page, 'input[name=passwd], #i0118');
  if (pw) {
    if (s.tap && !s.password) {
      // A TAP sign-in that landed on the password page: switch to the pass.
      const sw = await onScreen(page, '#idA_PWD_SwitchToCredPicker, a:has-text("Other ways to sign in"), a:has-text("Sign in another way")');
      if (sw) { await sw.click(); s.credPicker = true; return 'other ways to sign in'; }
      throw new Error('Entra asked for a password during a Temporary Access Pass sign-in');
    }
    if (!s.password) throw new Error(`no password in the Keychain for ${upn} (contoso-lab-pw-${localPart(upn)})`);
    if (s.pwTries++ > 1) throw new Error('Entra refused the password twice');
    await pw.fill(s.password); await clickSubmit(page);
    await sleep(1500);
    const err = await onScreen(page, '#passwordError, #i0118Error');
    if (err) throw new Error(`password refused: ${(await err.innerText().catch(() => '')).slice(0, 200)}`);
    return 'password';
  }

  // Credential picker (after "Other ways to sign in").
  if (s.credPicker && s.tap) {
    const t = await onScreen(page, 'div[role=button]:has-text("Temporary Access Pass"), [data-test-cred-id="accesspass"]');
    if (t) { await t.click(); s.credPicker = false; return 'chose temporary access pass'; }
  }

  // Authenticator-app code.
  const otc = await onScreen(page, 'input[name=otc], #idTxtBx_SAOTCC_OTC');
  if (otc) {
    const seed = s.seed || keychainRead(totpService(upn));
    if (!seed) throw new Error(`no authenticator seed in the Keychain for ${upn} (${totpService(upn)}): run enroll.mjs first`);
    if (s.otcTries++ > 2) throw new Error('Entra refused the authenticator code three times');
    const code = await freshTotp(upn, seed);
    await otc.fill(code);
    const sub = await onScreen(page, '#idSubmit_SAOTCC_Continue, #idSIButton9, button[type=submit], input[type=submit]');
    if (sub) await sub.click(); else await page.keyboard.press('Enter');
    await sleep(2000);
    const err = await onScreen(page, '#idSpan_SAOTCC_Error_OTC');
    if (err) log('code refused, retrying with the next code:', (await err.innerText().catch(() => '')).slice(0, 120));
    return 'authenticator code';
  }

  // "Verify your identity": choose the authenticator-app code.
  const proofs = await onScreen(page, '#idDiv_SAOTCS_Proofs, [data-test-id="proofList"]');
  if (proofs) {
    const p = await onScreen(page, '[data-value="PhoneAppOTP"], div[role=button]:has-text("verification code"), div[role=button]:has-text("Use a verification code")');
    if (p) { await p.click(); return 'chose verification code'; }
  }
  // A push-approval page (Microsoft Authenticator): go to the other methods.
  const other = await onScreen(page, '#signInAnotherWay, a:has-text("I can\'t use my Microsoft Authenticator app right now")');
  if (other) { await other.click(); return 'sign in another way'; }

  // "Stay signed in?"
  if (await onScreen(page, '#KmsiCheckboxField, #KmsiDescription') || /Stay signed in\?/.test(text)) {
    const b = await onScreen(page, s.kmsi ? '#idSIButton9, button:has-text("Yes"), input[value="Yes"]' : '#idBtn_Back, button:has-text("No"), input[value="No"]');
    if (b) { await b.click(); return `stay signed in: ${s.kmsi ? 'yes' : 'no'}`; }
  }

  // Nudges that can be postponed (registration campaign, SSPR).
  const later = await onScreen(page, '#btnAskLater, a:has-text("Skip for now"), button:has-text("Skip for now"), a:has-text("Ask later"), button:has-text("Not now")');
  if (later) { await later.click(); return 'postponed a nudge'; }

  // Username (last: it stays in the DOM, off screen, on later pages).
  const user = await onScreen(page, 'input[name=loginfmt], #i0116');
  if (user) {
    const want = s.entraUsername || upn;
    const cur = await user.inputValue().catch(() => '');
    const wrong = await onScreen(page, '#usernameError');
    if (cur.toLowerCase() !== want.toLowerCase() || wrong) { await user.fill(want); }
    if (s.userTries++ > 2) throw new Error(`Entra refused the username ${want}: ${wrong ? await wrong.innerText().catch(() => '') : ''}`);
    await clickSubmit(page);
    return 'username';
  }
  if (/More information required|Let's keep your account secure|Action Required/i.test(text)) throw new Error('Entra wants security info registered first (run enroll.mjs)');
  return null;
}

// When is the browser "signed in"? A pure decision, so it is unit-tested
// (tests/lib.test.mjs). An app's own sign-in or access-denied page is also
// "off the login hosts with a steady URL", so that alone proves nothing:
//   * with an `until` test, only `until` decides;
//   * without one, Entra must have been visited in THIS run (the app sent
//     the browser to Entra and Entra sent it back), no password box may be
//     on screen (a signed-out app page), and the URL must be steady 2.5 s.
//   * no Entra visit and no `until` = cannot tell: an error, never "ok".
export function verdict({ onApp, untilGiven, untilOk, visitedLogin, passwordOnScreen, steadyMs }) {
  if (!onApp) return 'wait';
  if (untilGiven) return untilOk ? 'done' : 'wait';
  if (passwordOnScreen) return 'signed-out';
  if (steadyMs < 2500) return 'wait';
  return visitedLogin ? 'done' : 'unproven';
}

// Drive Entra until the browser is back on the app (see verdict()).
export async function drive(page, upn, opts = {}) {
  const s = { kmsi: true, pwTries: 0, otcTries: 0, userTries: 0, ...opts };
  const deadline = Date.now() + (opts.timeoutMs || 180000);
  let steadyUrl = '', steadySince = 0, visitedLogin = false;
  while (Date.now() < deadline) {
    await page.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
    if (LOGIN_HOST.test(host(page.url()))) visitedLogin = true;
    const did = await step(page, upn, s);
    if (did) { visitedLogin = true; log(`${localPart(upn)}: ${did}`); steadyUrl = ''; await sleep(1500); continue; }
    const h = host(page.url());
    const onApp = !LOGIN_HOST.test(h) && !(OKTA_HOST.test(h) && await onScreen(page, 'input[name="identifier"], input[name="username"], input[name="credentials.passcode"]'));
    if (onApp && page.url() !== steadyUrl) { steadyUrl = page.url(); steadySince = Date.now(); }
    const v = verdict({
      onApp, untilGiven: !!opts.until, untilOk: onApp && opts.until ? await opts.until(page).catch(() => false) : false,
      visitedLogin, passwordOnScreen: onApp && !opts.until ? !!(await onScreen(page, 'input[type=password]')) : false,
      steadyMs: onApp ? Date.now() - steadySince : 0,
    });
    if (v === 'done') return;
    if (v === 'signed-out') throw new Error(`back on ${h} but it shows a password box: the app did not accept the sign-in`);
    if (v === 'unproven') throw new Error(`no Entra sign-in happened and no "until" test was given: cannot tell whether ${h} is signed in (pass until / --until)`);
    await sleep(700);
  }
  throw new Error(`sign-in did not finish in ${(opts.timeoutMs || 180000) / 1000}s (at ${host(page.url())})`);
}

// signIn(upn, url, { headless, fresh, identifier, until, kmsi, timeoutMs, browser, contextOptions })
//   identifier : what to type on a non-Entra front door (Okta's identifier box); default the UPN
//   until      : async (page) => boolean, the app-specific "signed in" test
//   browser    : reuse an already-launched Playwright browser (the caller closes it)
// Returns { browser, context, page, statePath, close }.
export async function signIn(upn, url, opts = {}) {
  upn = checkUpn(upn);
  const { headless = true, fresh = false, browser: given, contextOptions = {} } = opts;
  const pw = passwordFor(upn);
  const browser = given || await playwright().chromium.launch({ headless });
  const st = statePath(upn);
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 }, locale: 'en-US',
    ...(fresh || !fs.existsSync(st) ? {} : { storageState: st }), ...contextOptions,
  });
  const page = await context.newPage();
  const close = async () => { await context.close().catch(() => {}); if (!given) await browser.close().catch(() => {}); };
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await drive(page, upn, { ...opts, password: pw && pw.value });
    const saved = await saveState(context, upn);
    log(`${localPart(upn)}: signed in at ${host(page.url())}`);
    return { browser, context, page, statePath: saved, close };
  } catch (e) {
    const f = await shot(page, `signin-fail-${localPart(upn)}`);
    await close();
    e.message += ` [screenshot: ${f}]`;
    throw e;
  }
}

// ---- CLI ----------------------------------------------------------------------
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const a = process.argv.slice(2);
  const flag = (n) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
  const val = (n) => { const i = a.indexOf(n); if (i < 0) return undefined; const v = a[i + 1]; a.splice(i, 2); return v; };
  const headed = flag('--headed'), fresh = flag('--fresh'), noKmsi = flag('--no-kmsi');
  const identifier = val('--identifier'), shotName = val('--shot'), untilRe = val('--until');
  const [upn, url] = a;
  if (!upn || !url) { console.error('usage: node signin.mjs <upn> <start-url> [--headed] [--fresh] [--identifier <name>] [--until <regex>] [--no-kmsi] [--shot <name>]'); process.exit(2); }
  try {
    // --until <regex>: signed in only when the URL or the page text matches.
    const until = untilRe ? async (p) => new RegExp(untilRe, 'i').test(p.url()) || new RegExp(untilRe, 'i').test(await pageText(p)) : undefined;
    const r = await signIn(upn, url, { headless: !headed, fresh, identifier, kmsi: !noKmsi, until });
    await sleep(2000);
    const f = await shot(r.page, shotName || `signin-ok-${localPart(upn)}`);
    console.log(JSON.stringify({ ok: true, upn, landed: r.page.url(), title: await r.page.title(), screenshot: f, storageState: r.statePath }));
    await r.close();
  } catch (e) {
    console.log(JSON.stringify({ ok: false, upn, error: e.message }));
    process.exit(1);
  }
}
