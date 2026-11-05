// =============================================================================
// lab/scripts/demo/signin/identity.mjs - ONE way to sign in as any lab identity
// -----------------------------------------------------------------------------
//   import { signIn, keepSignedIn, activatePim } from '<repo>/lab/scripts/demo/signin/identity.mjs';
//   const { page } = await signIn('adm-presenter', 'https://entra.microsoft.com/', { context });
//   const stop = keepSignedIn(context, 'adm-presenter');          // silent re-sign-in
//   await activatePim('adm-presenter', 'PIM-Demo-Readers', 8, 'INC-1234 demo', { context });
//
// WHO and HOW come from identities.json (no secrets there - Keychain item
// names only). One registry entry per identity, one method each:
//   password+totp  Entra: password + authenticator code (enroll.mjs seeds)
//   passkey        Entra: a CDP virtual authenticator loaded with the Keychain
//                  credential passkey.mjs registered (no password is typed)
//   tap            Entra: a one-time Temporary Access Pass issued by the lab
//                  operator for this sign-in only, deleted afterwards
//   password(+totp) for the two non-Entra kinds: ServiceNow's local login.do
//                  (+ its own authenticator code) and Splunk's login form
// `fallback: "tap"` lets a passkey identity fall back to a pass, only when
// the caller asks (allowTap) - a pass is a credential issued in the tenant.
//
// WHY IN THE CALLER'S CONTEXT: the cockpit records with ONE headful,
// persistent Chromium profile. signIn() works inside that context (opts.context)
// and never closes it; keepSignedIn() watches its pages and signs in again,
// silently, whenever an app sends one back to a sign-in page (an expired
// session, CA020's 4-hour re-authentication on the admin portals, ServiceNow
// or Splunk logging out). "Stay signed in?" is answered yes (signin.mjs).
//
// GitHub is deliberately absent: it stays the owner's own sign-in.
// =============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { drive, landing } from './signin.mjs';
import { keychainRead, keychainWrite, playwright, saveState, readOwnedState, shot, pageText, sleep, log, graph, freshTotp, STATE_DIR, REPO } from './lib.mjs';
import { tapCleaner } from './enroll.mjs';
import { decodeRecord, encodeRecord, AUTHENTICATOR } from './passkey.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REGISTRY_FILE = process.env.SIGNIN_REGISTRY || path.join(HERE, 'identities.json');
const LOGIN_HOST = /(^|\.)(login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com|login\.windows\.net)$/i;
const host = (u) => { try { return new URL(u).hostname; } catch { return ''; } };
export const KINDS = ['entra', 'servicenow-local', 'splunk-local'];
export const METHODS = { entra: ['password+totp', 'passkey', 'tap'], 'servicenow-local': ['password+totp', 'password'], 'splunk-local': ['password'] };
const NEEDS = { 'password+totp': ['password', 'totp'], passkey: ['passkey'], tap: [], password: ['password'] };

// ---- the registry (pure validation, unit-tested) -------------------------------
// A secret REFERENCE is { service, account } (Keychain) or { file, key } (a
// gitignored env file). Anything else - above all a plain string where a
// reference belongs - is refused: it could be a secret pasted by mistake.
export function validateRegistry(reg) {
  const p = [];
  if (!reg || typeof reg.identities !== 'object') return ['no "identities" object'];
  for (const [id, e] of Object.entries(reg.identities)) {
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(id)) p.push(`${id}: bad id`);
    if (!KINDS.includes(e.kind)) { p.push(`${id}: kind must be one of ${KINDS.join(', ')}`); continue; }
    if (!(METHODS[e.kind] || []).includes(e.method)) p.push(`${id}: method ${e.method} is not valid for ${e.kind}`);
    if (e.kind === 'entra' && !/^[^@\s]+@contosohealthlab\.(com|onmicrosoft\.com)$/.test(e.upn || '')) p.push(`${id}: upn must be a lowercase lab UPN`);
    if (e.kind === 'entra' && /^michaelwilliams@|^bg-admin-/i.test(e.upn || '')) p.push(`${id}: the owner's and break-glass accounts never go in the registry`);
    if (e.kind !== 'entra' && (!e.username || !/^https?:\/\//.test(e.loginUrl || ''))) p.push(`${id}: local kinds need username and loginUrl`);
    if (e.fallback && e.fallback !== 'tap') p.push(`${id}: the only fallback is "tap"`);
    if (e.fallback && e.kind !== 'entra') p.push(`${id}: a pass fallback exists only for Entra identities`);
    for (const need of NEEDS[e.method] || []) if (!e.secrets || !e.secrets[need]) p.push(`${id}: method ${e.method} needs secrets.${need}`);
    for (const [name, ref] of Object.entries(e.secrets || {})) {
      const ok = ref && typeof ref === 'object' && ((typeof ref.service === 'string' && typeof ref.account === 'string' && Object.keys(ref).length === 2)
        || (typeof ref.file === 'string' && typeof ref.key === 'string' && Object.keys(ref).length === 2 && !path.isAbsolute(ref.file) && !ref.file.includes('..')));
      if (!ok) p.push(`${id}: secrets.${name} must be {service, account} or {file, key} - never a value`);
    }
    if (!/^https?:\/\//.test(e.home || '')) p.push(`${id}: home must be a URL`);
  }
  return p;
}
export function loadRegistry(file = REGISTRY_FILE) {
  const reg = JSON.parse(fs.readFileSync(file, 'utf8'));
  const p = validateRegistry(reg);
  if (p.length) throw new Error(`identities.json is invalid: ${p.join('; ')}`);
  return reg.identities;
}
export function identity(id, reg = loadRegistry()) {
  const e = reg[id];
  if (!e) throw new Error(`no identity "${id}" in identities.json (known: ${Object.keys(reg).join(', ')})`);
  return { id, ...e };
}

// ---- secrets, resolved only in this process --------------------------------------
// A {file, key} reference reads KEY=VALUE from the file in this checkout, else
// in the main checkout (a git worktree has no gitignored files).
export function readEnvFileKey(text, key) {
  for (const line of text.split('\n')) { const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/); if (m && m[1] === key) return m[2].replace(/^["']|["']$/g, ''); }
  return null;
}
export function secret(ref) {
  if (ref.service) {
    const v = keychainRead(ref.service, ref.account);
    if (v === null) throw new Error(`Keychain item ${ref.service} (account ${ref.account}) not found`);
    return v;
  }
  for (const root of [REPO, path.join(os.homedir(), 'contoso-health-identity-lab')]) {
    const f = path.join(root, ref.file);
    if (!fs.existsSync(f)) continue;
    const v = readEnvFileKey(fs.readFileSync(f, 'utf8'), ref.key);
    if (v) return v;
    throw new Error(`${ref.file} has no ${ref.key}`);
  }
  throw new Error(`${ref.file} not found (it is generated per machine)`);
}

// ---- passkey: a virtual authenticator in the CALLER's context ------------------------
// The credential comes from the Keychain record passkey.mjs wrote. One
// authenticator on the page being signed in (and pages it opens); the new
// signature counter is written back so the next sign-in's counter keeps rising.
async function attachPasskey(context, page, e) {
  const ref = e.secrets.passkey;
  const rec = decodeRecord(secret(ref));
  const cdps = [];
  const add = async (p) => {
    const cdp = await context.newCDPSession(p);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATOR });
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: { credentialId: rec.credentialId, isResidentCredential: true, rpId: rec.rpId, privateKey: rec.privateKey, userHandle: rec.userHandle, signCount: rec.signCount } });
    cdps.push({ cdp, authenticatorId });
  };
  await add(page);
  const onPopup = (p) => { add(p).catch((err) => log(`${e.id}: no authenticator on a popup: ${err.message}`)); };
  page.on('popup', onPopup);
  return async function finish() {
    page.off('popup', onPopup);
    let count = rec.signCount;
    for (const { cdp, authenticatorId } of cdps) {
      try {
        const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
        for (const c of credentials) if (c.credentialId === rec.credentialId) count = Math.max(count, c.signCount);
        await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      } catch { /* page closed */ }
      await cdp.detach().catch(() => {});
    }
    if (count > rec.signCount) {
      const latest = decodeRecord(secret(ref)); // another run may have moved it on
      keychainWrite(ref.service, ref.account, 'Contoso lab passkey (base64 JSON record)', encodeRecord({ ...latest, signCount: Math.max(count, latest.signCount), lastUsedUtc: new Date().toISOString() }));
    }
    return count;
  };
}

// ---- the sign-in pages, per kind -------------------------------------------------
async function onScreen(page, sel) {
  const l = page.locator(sel).first();
  return (await l.isVisible().catch(() => false)) ? l : null;
}
async function entra(page, e, opts) {
  const base = { kmsi: opts.kmsi !== false, until: opts.until, landing: opts.landing, timeoutMs: opts.timeoutMs };
  const method = opts.method || e.method;
  if (method === 'password+totp') return drive(page, e.upn, { ...base, password: secret(e.secrets.password), seed: secret(e.secrets.totp) });
  if (method === 'passkey') {
    const finish = await attachPasskey(page.context(), page, e);
    try { return await drive(page, e.upn, { ...base, mode: 'passkey' }); } finally { await finish(); }
  }
  if (method === 'tap') {
    const uid = graph('GET', `users/${encodeURIComponent(e.upn)}?$select=id`).id;
    const t = tapCleaner({ upn: e.upn, uid });
    if ((graph('GET', `users/${uid}/authentication/temporaryAccessPassMethods`).value || []).length) throw new Error(`${e.upn} already has a Temporary Access Pass (someone else's): not replaced`);
    const issued = graph('POST', `users/${uid}/authentication/temporaryAccessPassMethods`, { lifetimeInMinutes: 60, isUsableOnce: true });
    t.set(issued.id);
    try { return await drive(page, e.upn, { ...base, tap: issued.temporaryAccessPass }); } finally { t.remove(); }
  }
  throw new Error(`${e.id}: unknown method ${method}`);
}
// ServiceNow login.do -> (validate_multifactor_auth_code.do) -> the app.
// Splunk /account/login -> the app. Done when landing() sees the signed-in app.
// A local password or code is typed only into a page of EXACTLY the origin of
// the identity's loginUrl (scheme, host and port): never a look-alike host, a
// redirect target or another service on 127.0.0.1.
export const sameOrigin = (url, loginUrl) => { try { return new URL(url).origin === new URL(loginUrl).origin; } catch { return false; } };
function assertOrigin(page, e) {
  if (!sameOrigin(page.url(), e.loginUrl)) throw new Error(`${e.id}: a sign-in form at ${new URL(page.url()).origin} is not ${new URL(e.loginUrl).origin}: nothing typed`);
}
async function local(page, e, opts) {
  const deadline = Date.now() + (opts.timeoutMs || 120000);
  const target = page.url();
  let typed = 0, coded = 0, sentToLogin = false;
  while (Date.now() < deadline) {
    await page.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
    const text = await pageText(page);
    const land = landing(page.url(), text, opts.landing);
    if (land.startsWith('denied')) throw new Error(`${e.id}: refused (${land}): ${text.replace(/\s+/g, ' ').slice(0, 160)}`);
    if (opts.until ? await opts.until(page).catch(() => false) : land === 'ok') return;
    const user = await onScreen(page, '#user_name, input[name="user_name"], input[name="username"]');
    const pass = await onScreen(page, '#user_password, input[name="user_password"], input[name="password"]');
    if (user && pass) {
      assertOrigin(page, e);
      if (typed++ > 1) throw new Error(`${e.id}: the login form came back: username or password refused`);
      await user.fill(e.username); await pass.fill(secret(e.secrets.password));
      const b = await onScreen(page, '#sysverb_login, button[type=submit], input[type=submit]'); if (b) await b.click(); else await pass.press('Enter');
      log(`${e.id}: username and password`); await sleep(2500); continue;
    }
    // A username-first or SSO-first sign-in page (ServiceNow navpage.do with
    // SSO on): the local account signs in at loginUrl, which has both boxes.
    if (user && !pass && !sentToLogin) { sentToLogin = true; await page.goto(e.loginUrl, { waitUntil: 'domcontentloaded' }); log(`${e.id}: to ${new URL(e.loginUrl).pathname}`); continue; }
    if (/validate_multifactor_auth_code|Verify your identity|authenticator app/i.test(page.url() + ' ' + text) && e.secrets.totp) {
      const box = await onScreen(page, '#txtResponse, input[name="txtResponse"], input[autocomplete="one-time-code"]');
      if (box) {
        assertOrigin(page, e);
        if (coded++ > 2) throw new Error(`${e.id}: the authenticator code was refused three times`);
        await box.fill(await freshTotp(`${e.username}@${host(e.loginUrl)}`, secret(e.secrets.totp)));
        const b = await onScreen(page, '#sysverb_validate_mfa_code, button:has-text("Verify"), button[type=submit]'); if (b) await b.click(); else await box.press('Enter');
        log(`${e.id}: authenticator code`); await sleep(4000);
        // Signed in: back to the page that was asked for, if it was not the login page.
        if (!needsSignIn(target, e) && !/navpage\.do/.test(target) && host(page.url()) === host(target) && /login|validate_multifactor/.test(page.url())) await page.goto(target, { waitUntil: 'domcontentloaded' }).catch(() => {});
        continue;
      }
    }
    await sleep(700);
  }
  throw new Error(`${e.id}: sign-in did not finish (at ${host(page.url())}${new URL(page.url()).pathname})`);
}

// ---- signIn ---------------------------------------------------------------------
// signIn(id, url, { context, page, headless, fresh, until, landing, allowTap, timeoutMs, kmsi })
//   context : a Playwright (persistent) context the CALLER owns; it is never closed
//   page    : a page in that context to use (else a new one is opened)
//   allowTap: let a passkey/password identity with fallback "tap" use a pass if
//             its own method fails (a pass is issued in the tenant; off by default)
// Returns { page, context, browser, close, id, method, landed }.
// One Entra identity per browser context. A context this tool signed in as
// someone else is refused (switching users inside one context would let an app
// keep the old account silently); a context with an Entra session the tool did
// not make is checked first: My Account names its account.
const contextOwner = new WeakMap();
export function ownerConflict(current, wanted) { return current && current.toLowerCase() !== wanted.toLowerCase() ? `this context is already signed in to Entra as ${current}, not ${wanted}: use a separate context` : null; }
async function entraAccountOf(context) {
  const hasSession = (await context.cookies('https://login.microsoftonline.com')).some((c) => /^ESTSAUTH/.test(c.name));
  if (!hasSession) return null;
  const p = await context.newPage();
  try {
    await p.goto('https://myaccount.microsoft.com/', { waitUntil: 'domcontentloaded', timeout: 60000 });
    // My Account can stay blank after a redirect (seen live): reload it, at
    // most twice, as drive() does - and still refuse to go on until the
    // account is known.
    for (let i = 0, reloads = 0; i < 75; i++) {
      if (LOGIN_HOST.test(host(p.url()))) return null; // the session did not sign anyone in silently
      const t = await pageText(p);
      const m = t.match(/[A-Za-z0-9._%+-]+@contosohealthlab\.(com|onmicrosoft\.com)/i);
      if (m) return m[0].toLowerCase();
      if (!t.trim() && i > 0 && i % 20 === 0 && reloads < 2) { reloads++; await p.reload({ waitUntil: 'domcontentloaded' }).catch(() => {}); }
      await sleep(1000);
    }
    throw new Error('could not tell which Entra account this context is signed in as (My Account showed no account)');
  } finally { await p.close().catch(() => {}); }
}
export async function signIn(id, url, opts = {}) {
  const e = identity(id);
  if (opts.context && e.kind === 'entra') {
    const known = contextOwner.get(opts.context);
    const conflict = ownerConflict(known || await entraAccountOf(opts.context), e.upn);
    if (conflict) throw new Error(`${id}: ${conflict}`);
  }
  const own = !opts.context;
  const browser = own ? await playwright().chromium.launch({ headless: opts.headless !== false }) : null;
  let context = opts.context, page = opts.page || null, usedMethod = e.method;
  const close = async () => {
    if (own) { await context?.close().catch(() => {}); await browser.close().catch(() => {}); }
    else if (!opts.page && page) await page.close().catch(() => {});
  };
  try {
    if (own) {
      const saved = opts.fresh || e.kind !== 'entra' ? null : readOwnedState(e.upn);
      context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US', ...(saved ? { storageState: saved } : {}) });
    }
    page = page || await context.newPage();
    await page.goto(url || e.home, { waitUntil: 'domcontentloaded', timeout: 60000 });
    if (e.kind === 'entra') {
      try { await entra(page, e, opts); } catch (err) {
        if (!(opts.allowTap && e.fallback === 'tap' && e.method !== 'tap')) throw err;
        log(`${id}: ${e.method} failed (${err.message.slice(0, 120)}); falling back to a one-time pass`);
        usedMethod = 'tap';
        await page.goto(url || e.home, { waitUntil: 'domcontentloaded', timeout: 60000 });
        await entra(page, e, { ...opts, method: 'tap' });
      }
      if (own) await saveState(context, e.upn);
    } else await local(page, e, opts);
    if (e.kind === 'entra') contextOwner.set(context, e.upn);
    log(`${id}: signed in (${usedMethod}) at ${host(page.url())}`);
    return { page, context, browser, close, id, method: usedMethod, landed: page.url() };
  } catch (err) {
    const f = page ? await shot(page, `identity-fail-${id}`).catch(() => null) : null;
    await close();
    if (f) err.message += ` [screenshot: ${f}]`;
    throw err;
  }
}

// ---- keepSignedIn: silent re-sign-in inside the caller's context -----------------
// Any page of the context that lands on a sign-in page for this identity (Entra's,
// ServiceNow's login.do, Splunk's login form) is signed in again where it is, and
// sent on to wherever the app redirects. Returns stop().
export function needsSignIn(url, e) {
  const h = host(url);
  if (e.kind === 'entra') return LOGIN_HOST.test(h);
  if (!sameOrigin(url, e.loginUrl)) return false;
  return e.kind === 'servicenow-local' ? /\/(login\.do|validate_multifactor_auth_code\.do)/i.test(url) : /\/account\/login/i.test(url);
}
export function keepSignedIn(context, id, { onEvent = (m) => log(m) } = {}) {
  const e = identity(id);
  const busy = new Set();
  const handlers = new Map();
  const watch = (page) => {
    const h = async (frame) => {
      if (frame !== page.mainFrame() || busy.has(page)) return;
      if (!needsSignIn(page.url(), e)) {
        // A local app can show its sign-in form at an ordinary URL (ServiceNow
        // navpage.do with SSO on, seen live): look at the page itself.
        if (e.kind === 'entra' || !sameOrigin(page.url(), e.loginUrl)) return;
        await page.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
        if (!(await onScreen(page, '#user_name, input[name="user_name"], input[name="username"]'))) return;
      }
      if (busy.has(page)) return;
      busy.add(page);
      try {
        onEvent(`${id}: sign-in page on ${host(page.url())} - signing in again`);
        // Done = off every sign-in page AND no sign-in form on screen (a local
        // app's form can sit at an ordinary URL).
        const backOnApp = async (p) => !needsSignIn(p.url(), e) && !LOGIN_HOST.test(host(p.url()))
          && !(await onScreen(p, '#user_name, input[name="user_name"], input[name="username"], input[name="loginfmt"], #txtResponse'));
        if (e.kind === 'entra') await entra(page, e, { until: backOnApp, timeoutMs: 120000 });
        else await local(page, e, { until: backOnApp, timeoutMs: 120000 });
        onEvent(`${id}: signed in again (${host(page.url())})`);
      } catch (err) { onEvent(`${id}: could not sign in again: ${err.message}`); } finally { busy.delete(page); }
    };
    handlers.set(page, h); page.on('framenavigated', h);
  };
  context.pages().forEach(watch);
  context.on('page', watch);
  // Pages already sitting on a sign-in page when the watcher starts: check once.
  for (const [p, h] of handlers) h(p.mainFrame()).catch(() => {});
  return () => { context.off('page', watch); for (const [p, h] of handlers) p.off('framenavigated', h); };
}

// ---- PIM for Groups: activate through the portal, as the person would --------------
// Entra admin center > PIM > My roles > Groups > Eligible assignments > Activate.
// MFA for the activation is the passkey/code the identity signs in with; if the
// blade asks to verify again, that sign-in happens in place. The end time is
// recorded under ~/.contoso-operator/session/browser/<id>.pim.json (not a
// secret) for signin-doctor; the operator cannot read active PIM assignments.
export const PIM_URL = 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup';
const pimFile = (id) => path.join(STATE_DIR, `${id}.pim.json`);
export function pimRecords(id) { try { return JSON.parse(fs.readFileSync(pimFile(id), 'utf8')); } catch { return []; } }
function recordPim(id, rec) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const all = pimRecords(id).filter((r) => r.group !== rec.group && Date.parse(r.endsUtc) > Date.now());
  fs.writeFileSync(pimFile(id), JSON.stringify([...all, rec], null, 1), { mode: 0o600 });
}
async function inFrames(page, fn) {
  for (const f of page.frames()) { const r = await fn(f).catch(() => null); if (r) return r; }
  return null;
}
export async function activatePim(id, group, hours, reason, opts = {}) {
  const e = identity(id);
  if (e.kind !== 'entra') throw new Error(`${id} is not an Entra identity`);
  if (!reason || reason.length < 5) throw new Error('a justification is required');
  const r = await signIn(id, PIM_URL, { ...opts, until: async (p) => /entra\.microsoft\.com/.test(p.url()) && /Eligible assignments|Active assignments/i.test(await pageText(p)) });
  const page = r.page;
  try {
    const row = async () => inFrames(page, async (f) => { const l = f.getByRole('row').filter({ hasText: group }).first(); return (await l.isVisible()) ? l : null; });
    // Already active? (the Active assignments tab lists it with Deactivate)
    const activeTab = await inFrames(page, async (f) => { const t = f.getByRole('tab', { name: /Active assignments/i }).first(); return (await t.isVisible()) ? t : null; });
    if (activeTab) {
      await activeTab.click(); await sleep(3000);
      const a = await row();
      if (a && /Deactivate|Extend/i.test(await a.innerText())) { log(`${id}: ${group} is already active`); return { ...r, group, already: true }; }
      const el = await inFrames(page, async (f) => { const t = f.getByRole('tab', { name: /Eligible assignments/i }).first(); return (await t.isVisible()) ? t : null; });
      if (el) { await el.click(); await sleep(3000); }
    }
    let target = null;
    for (let i = 0; i < 20 && !target; i++) { target = await row(); if (!target) await sleep(1500); }
    if (!target) throw new Error(`${id} has no eligible assignment for ${group} on the PIM page`);
    await target.getByRole('button', { name: /^Activate$/ }).or(target.getByRole('link', { name: /^Activate$/ })).first().click();
    await sleep(4000);
    const fill = async (sel, v) => inFrames(page, async (f) => { const l = f.locator(sel).first(); if (!(await l.isVisible())) return null; await l.fill(String(v)); await l.press('Tab').catch(() => {}); return l; });
    // The duration must be set AND read back: never record an end time the blade did not take.
    const dur = await fill('input[aria-label*="slider value"], input[aria-label*="Duration" i], input[type="number"]', hours);
    if (!dur) throw new Error('no duration box on the activation blade: not activating with an unknown duration');
    const got = Number(await dur.inputValue().catch(() => NaN));
    if (got !== Number(hours)) throw new Error(`the blade took ${Number.isNaN(got) ? 'no' : got} hours, not ${hours} (above the group's maximum?): not activating`);
    if (!(await fill('textarea', reason))) throw new Error('no justification box on the activation blade');
    const submit = async () => inFrames(page, async (f) => { const b = f.getByRole('button', { name: /^Activate$/ }).last(); if (!(await b.isVisible()) || !(await b.isEnabled())) return null; await b.click(); return true; });
    if (!(await submit())) throw new Error('the Activate button on the blade is not available');
    // Proof = the group's row under Active assignments with Deactivate/Extend.
    // A fresh MFA can be asked for first: it is answered in place.
    let proven = false;
    for (let i = 0; i < 45 && !proven; i++) {
      await sleep(2000);
      const text = await pageText(page);
      if (/pending approval|requires approval/i.test(text)) throw new Error(`${group} needs an approver: not a self-service activation`);
      const verify = await inFrames(page, async (f) => { const b = f.getByRole('button', { name: /Verify your identity|Additional verification/i }).first(); return (await b.isVisible()) ? b : null; });
      if (verify) {
        const [pop] = await Promise.all([page.context().waitForEvent('page', { timeout: 15000 }).catch(() => null), verify.click()]);
        const where = pop || page;
        await entra(where, e, { until: async (p) => !LOGIN_HOST.test(host(p.url())) || p.isClosed(), timeoutMs: 120000 }).catch((err) => { if (!where.isClosed()) throw err; });
        await sleep(2000); await submit(); continue;
      }
      if (i % 5 === 4) {
        const tab = await inFrames(page, async (f) => { const t = f.getByRole('tab', { name: /Active assignments/i }).first(); return (await t.isVisible()) ? t : null; });
        if (tab) { await tab.click().catch(() => {}); await sleep(2500); const a = await row(); proven = !!(a && /Deactivate|Extend/i.test(await a.innerText().catch(() => ''))); }
      }
    }
    if (!proven) throw new Error(`no active row for ${group} after activating: not recorded as active`);
    const endsUtc = new Date(Date.now() + hours * 3600000).toISOString();
    recordPim(id, { group, activatedUtc: new Date().toISOString(), endsUtc, reason });
    log(`${id}: ${group} activated for ${hours} h (until ${endsUtc})`);
    return { ...r, group, endsUtc };
  } catch (err) {
    const f = await shot(page, `pim-fail-${id}`).catch(() => null);
    if (f) err.message += ` [screenshot: ${f}]`;
    if (!opts.context) await r.close();
    throw err;
  }
}
