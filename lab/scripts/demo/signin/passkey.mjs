#!/usr/bin/env node
// =============================================================================
// lab/scripts/demo/signin/passkey.mjs - lab software passkeys for admin and
// emergency (break-glass) accounts
// -----------------------------------------------------------------------------
//   node passkey.mjs register <upn> [--via tap|graph] [--break-glass] [--replace] [--headed]
//   node passkey.mjs prove    <upn> [--break-glass] [--start-url <url>] [--headed]
//   node passkey.mjs status   <upn> [--break-glass]
//
// WHAT IT IS FOR
//   Conditional Access CA002 (phishing-resistant MFA for admins) and CA021
//   (phishing-resistant strength for role activation) can only be switched on
//   once every account they cover holds a phishing-resistant method; and the
//   two break-glass accounts need a method that actually signs in, or a real
//   lockout could not reach the admin portals (Microsoft enforces MFA there).
//   PRODUCTION: two FIDO2 hardware keys per account, attested, in separate
//   safes (lab/docs/runbooks/break-glass-drill.md). LAB DEVIATION: one SOFTWARE
//   passkey per account, made by Chromium's virtual WebAuthn authenticator and
//   kept in this Mac's login Keychain. The Keychain item IS the key: whoever
//   can read contoso-lab-passkey-bg-admin-NN can sign in as a Global
//   Administrator. That is why the break-glass accounts need --break-glass on
//   every command and why nothing here prints, logs or files the key.
//
// HOW (each step says why)
//   register --via tap   (default for everyone except break-glass)
//     1. A one-time Temporary Access Pass, the shortest lifetime the TAP policy
//        allows, held in this process only. CA009 lets security info be
//        registered only with a TAP or a phishing-resistant method.
//     2. Headless Chromium with a virtual authenticator (CDP WebAuthn domain:
//        ctap2, usb, resident key, user verification, UV true) signs in at
//        https://mysignins.microsoft.com/security-info with the pass and adds
//        a passkey there, exactly as the user would with a security key.
//   register --via graph (always for break-glass)
//     The TAP policy excludes Break-Glass-Admins (ADR 0016: a TAP is never
//     issued to break-glass), so the admin-provisioning API is used instead:
//     GET  /users/{id}/authentication/fido2Methods/creationOptions
//     POST /users/{id}/authentication/fido2Methods
//     (Learn: fido2authenticationmethod-creationoptions and
//     authentication-post-fido2methods; application permission
//     UserAuthenticationMethod.ReadWrite.All, which the lab operator holds).
//     The credential is still made by the virtual authenticator, on a page
//     served by Playwright at https://login.microsoft.com (the rp.id Entra
//     returns), so clientDataJSON carries the origin Entra expects.
//   Both paths export the credential (WebAuthn.getCredentials: credentialId,
//   privateKey, rpId, userHandle, signCount) to the Keychain (base64 JSON,
//   written with `security -i` over STDIN - never argv - and read back),
//   first as contoso-lab-passkey-<local-part>-pending. Only once Graph lists
//   the new method does it become contoso-lab-passkey-<local-part>. A POST
//   that fails or returns no id is checked against Graph's list before the
//   pending key is ever deleted (the response can be lost after Entra
//   registered the key).
//   --replace never deletes the working key first: the new key must sign in
//   (as in `prove`) before it replaces the old one in the Keychain, and the
//   old method is deleted last. On break-glass that proof raises the
//   break-glass incident, on purpose.
//   prove
//     A FRESH browser context, a new virtual authenticator, the credential
//     loaded from the Keychain (WebAuthn.addCredential), and a passkey-only
//     sign-in to https://myaccount.microsoft.com (no password is typed). The
//     screenshot goes to $PASSKEY_SHOTS_DIR. It fails unless the
//     authenticator's counter rose, the browser went through Entra's sign-in
//     pages, it ended on the app, and My Account shows the account. The new
//     signCount is written back so the next sign-in's counter keeps rising
//     (a relying party may reject a counter that goes backwards).
//
// WHY A SOFTWARE KEY REGISTERS FOR ADMINS AT ALL
//   The Admin-Accounts and Break-Glass-Admins targets carry the attested
//   "Contoso - Admins" profile, but all_users carries the unattested Default
//   profile, and Learn (how-to-authentication-passkeys-fido2, "Apply a passkey
//   profile to a targeted group"): "registration and authentication with a
//   passkey are allowed if the passkey fully satisfies the requirements of at
//   least one of the scoped passkey profiles". `status` prints which profiles
//   cover the account. This script never changes the policy.
//
// GUARDS: lab tenant domains only; the owner's account is refused outright;
// bg-admin-NN needs --break-glass; a TAP, private key or Keychain value is
// never printed; failure screenshots blur every input first.
// =============================================================================
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../../../..');
const OP = process.env.CONTOSO_OP || path.join(REPO, 'lab/scripts/operator/op');
const SHOTS_DIR = process.env.PASSKEY_SHOTS_DIR || path.join(os.tmpdir(), 'passkey-shots');
const SECURITY_INFO = 'https://mysignins.microsoft.com/security-info';
const BETA = 'https://graph.microsoft.com/beta';
const DEFAULT_PROOF_URL = 'https://myaccount.microsoft.com/';
// Entra keeps the first 30 characters of a passkey name (seen 2026-11-05).
export const DISPLAY_NAME = 'Lab passkey (Keychain)';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => { if (!process.env.PASSKEY_QUIET) console.error('[passkey]', ...a); };

// ---- who may be touched (pure) ----------------------------------------------
const LAB_DOMAINS = /@(contosohealthlab\.com|contosohealthlab\.onmicrosoft\.com)$/i;
const OWNER = /^michaelwilliams@/i;
export const BREAK_GLASS = /^bg-admin-\d{2}@/i;
export function checkUpn(upn, { breakGlass = false } = {}) {
  if (!upn || !/^[^@\s"'\\]+@[^@\s"'\\]+$/.test(upn)) throw new Error(`not a user principal name: ${upn}`);
  if (!LAB_DOMAINS.test(upn)) throw new Error(`${upn} is not in the lab tenant's domains`);
  if (OWNER.test(upn)) throw new Error(`${upn} is the owner's account: refused (AGENT-RULES hard limit)`);
  if (BREAK_GLASS.test(upn) && !breakGlass) throw new Error(`${upn} is a break-glass account: pass --break-glass to confirm you mean it`);
  if (!BREAK_GLASS.test(upn) && breakGlass) throw new Error(`--break-glass given but ${upn} is not a bg-admin-NN account`);
  return upn.toLowerCase();
}
export const localPart = (upn) => upn.split('@')[0].toLowerCase();
export const keychainService = (upn) => `contoso-lab-passkey-${localPart(upn)}`;
// Break-glass never gets a TAP (policy exclusion + ADR 0016); everyone else
// registers the way a user would, unless --via graph is asked for.
export function chooseVia(upn, asked) {
  if (asked && !['tap', 'graph'].includes(asked)) throw new Error(`--via must be tap or graph, not ${asked}`);
  if (BREAK_GLASS.test(upn)) {
    if (asked === 'tap') throw new Error('break-glass accounts never get a Temporary Access Pass (TAP policy excludes Break-Glass-Admins; ADR 0016): use --via graph');
    return 'graph';
  }
  return asked || 'tap';
}

// ---- encodings (pure) --------------------------------------------------------
export const b64ToB64url = (s) => String(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const b64urlToB64 = (s) => { const t = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, ''); return t + '='.repeat((4 - (t.length % 4)) % 4); };

// The Keychain record: everything WebAuthn.addCredential needs, plus where it
// is registered. base64(JSON) so it is one token for `security -i`.
const RECORD_FIELDS = ['credentialId', 'privateKey', 'rpId', 'userHandle'];
export function encodeRecord(rec) {
  for (const f of RECORD_FIELDS) if (!rec[f]) throw new Error(`passkey record is missing ${f}`);
  if (!Number.isInteger(rec.signCount) || rec.signCount < 0) throw new Error('passkey record signCount must be a non-negative integer');
  return Buffer.from(JSON.stringify({ v: 1, ...rec }), 'utf8').toString('base64');
}
export function decodeRecord(b64) {
  let rec;
  try { rec = JSON.parse(Buffer.from(String(b64), 'base64').toString('utf8')); } catch { throw new Error('the Keychain passkey item is not base64 JSON'); }
  if (!rec || rec.v !== 1) throw new Error('the Keychain passkey item has an unknown format');
  for (const f of RECORD_FIELDS) if (!rec[f]) throw new Error(`the Keychain passkey item is missing ${f}`);
  if (!Number.isInteger(rec.signCount) || rec.signCount < 0) throw new Error('the Keychain passkey item has a bad signCount');
  return rec;
}

// Graph's creationOptions -> the JSON the page turns into a
// PublicKeyCredentialCreationOptions (binary fields stay base64url here).
//   * excludeCredentials is emptied: it only stops an authenticator that
//     already holds one of the listed credentials from registering again, and
//     the virtual authenticator is brand new and empty. (Learn also documents
//     a "padding number suffix" on those ids that is ambiguous to decode.)
//   * enforceCredentialProtectionPolicy is dropped when the policy is
//     userVerificationOptional: Chromium refuses that pair with
//     NotSupportedError ("Requested protection policy is inconsistent"), and
//     enforcing the lowest credProtect level is a no-op (CTAP 2.1 credProtect,
//     level 1 is the default).
//   * timeout 0 (Graph) means "none given"; the page uses two minutes.
export function toBrowserCreationOptions(graphOptions) {
  const pk = graphOptions && (graphOptions.publicKey || (graphOptions.value && graphOptions.value.publicKey));
  if (!pk || !pk.challenge || !pk.rp || !pk.rp.id || !pk.user || !pk.user.id) throw new Error('creationOptions has no publicKey challenge / rp.id / user.id');
  const ext = { ...(pk.extensions || {}) };
  if (ext.credentialProtectionPolicy === 'userVerificationOptional') delete ext.enforceCredentialProtectionPolicy;
  return {
    challenge: pk.challenge,
    rp: { id: pk.rp.id, name: pk.rp.name || pk.rp.id },
    user: { id: pk.user.id, name: pk.user.name, displayName: pk.user.displayName || pk.user.name },
    pubKeyCredParams: pk.pubKeyCredParams || [{ type: 'public-key', alg: -7 }],
    timeout: pk.timeout ? pk.timeout : 120000,
    attestation: pk.attestation || 'direct',
    authenticatorSelection: pk.authenticatorSelection || {},
    excludeCredentials: [],
    extensions: ext,
  };
}
// The challenge Entra issued must come back in clientDataJSON unchanged.
export function checkClientData(clientDataJSONb64url, expectChallenge, expectOrigin) {
  const cd = JSON.parse(Buffer.from(b64urlToB64(clientDataJSONb64url), 'base64').toString('utf8'));
  if (cd.type !== 'webauthn.create') throw new Error(`clientDataJSON type is ${cd.type}`);
  if (b64ToB64url(b64urlToB64(cd.challenge)) !== b64ToB64url(b64urlToB64(expectChallenge))) throw new Error('clientDataJSON challenge differs from the one Entra issued');
  if (cd.origin !== expectOrigin) throw new Error(`clientDataJSON origin is ${cd.origin}, expected ${expectOrigin}`);
  return cd;
}
// Pick the one credential the virtual authenticator(s) hold for Entra.
export function pickCredential(creds, rpId = 'login.microsoft.com') {
  const mine = (creds || []).filter((c) => c && c.rpId === rpId && c.privateKey && c.credentialId);
  if (mine.length !== 1) throw new Error(`expected exactly one ${rpId} credential on the virtual authenticator, found ${mine.length}`);
  const c = mine[0];
  if (!c.isResidentCredential) throw new Error('the credential is not discoverable (resident): a passkey-only sign-in could not find it');
  return c;
}

// Passkey methods Graph lists now that it did not list before.
export const newMethods = (before, after) => (after || []).filter((m) => !(before || []).some((b) => b.id === m.id));
// What a POST /fido2Methods outcome means for the pending key. A failed or
// empty response does NOT prove Entra rejected the key (the response can be
// lost after Entra registered it), so Graph's list decides:
//   methodId  - registered (from the response, or the one new method listed)
//   rejected  - nothing new is listed: the pending key is useless, delete it
//   ambiguous - several new methods: keep the pending key, a person decides
export function resolvePost(postResult, added) {
  if (postResult && postResult.id) return { methodId: postResult.id };
  if ((added || []).length === 1) return { methodId: added[0].id };
  if (!(added || []).length) return { rejected: true };
  return { ambiguous: true };
}
// Did a proof really sign in with the passkey? All of: the authenticator's
// counter rose (an assertion was made), the browser went through Entra's
// sign-in pages, it ended on the app, no Temporary Access Pass was used, and
// (when given) the app shows the account. A public landing page passes none
// of the first two.
export function proofVerdict({ signCountBefore, signCountAfter, sawLogin, landedHost, targetHost, trail = [], expectText = null, text = '' }) {
  const reasons = [];
  if (!(Number.isInteger(signCountAfter) && signCountAfter > signCountBefore)) reasons.push(`the passkey was not used (signCount ${signCountBefore} -> ${signCountAfter})`);
  if (!sawLogin) reasons.push('the browser never went through the Entra sign-in pages');
  if (landedHost !== targetHost) reasons.push(`ended on ${landedHost}, not ${targetHost}`);
  if (trail.includes('temporary access pass')) reasons.push('a Temporary Access Pass was used, not the passkey');
  if (expectText && !String(text).toLowerCase().includes(String(expectText).toLowerCase())) reasons.push(`the app does not show ${expectText}`);
  return { ok: !reasons.length, reasons };
}

// ---- Keychain ------------------------------------------------------------------
// Read: value into this process only. Null = no such item ("not found" and
// "could not read" are told apart by the exit code: 44 is errSecItemNotFound).
export function keychainRead(service) {
  try {
    return execFileSync('security', ['find-generic-password', '-s', service, '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).replace(/\n$/, '');
  } catch (e) {
    if (e.status === 44) return null;
    throw new Error(`could not read Keychain item ${service} (security exit ${e.status})`);
  }
}
// Write (create or replace, -U) over STDIN. One token only: the `security -i`
// parser splits on spaces and quotes, so anything else is refused.
export function keychainWrite(service, account, label, secret) {
  if (!secret || /[\s"'\\]/.test(secret)) throw new Error('keychainWrite: the value must be one token without quotes, backslashes or spaces');
  if (/[\s"'\\]/.test(service + account) || /["'\\]/.test(label)) throw new Error('keychainWrite: bad service/account/label');
  execFileSync('security', ['-i'], { input: `add-generic-password -U -s ${service} -a ${account} -l "${label}" -w ${secret}\n`, stdio: ['pipe', 'ignore', 'pipe'] });
  if (keychainRead(service) !== secret) throw new Error(`Keychain write to ${service} did not read back`);
}
function keychainDelete(service) {
  try { execFileSync('security', ['delete-generic-password', '-s', service], { stdio: 'ignore' }); } catch (e) { if (e.status !== 44) throw new Error(`could not delete Keychain item ${service}`); }
}
// A key being registered (or replacing the current one) lives in the
// -pending item until Graph confirms it (and, on --replace, until it has
// signed in); only then does it become contoso-lab-passkey-<local>. So the
// key in use is never overwritten or deleted before its successor works.
export const pendingService = (upn) => `${keychainService(upn)}-pending`;
const saveRecord = (upn, rec, service = keychainService(upn)) => keychainWrite(service, upn, `Contoso lab passkey for ${upn}${service === keychainService(upn) ? '' : ' (pending)'}`, encodeRecord(rec));

// ---- Graph, as the lab operator ---------------------------------------------------
// Bodies reach az on STDIN, so nothing secret is in argv. A failed call
// throws (fail closed); the error text is az's, which never holds a TAP.
export function graph(method, url, body) {
  const full = url.startsWith('https://') ? url : `https://graph.microsoft.com/v1.0/${url.replace(/^\//, '')}`;
  const args = ['az', 'rest', '--method', method, '--url', full, '--only-show-errors'];
  let input;
  if (body !== undefined) { args.push('--headers', 'Content-Type=application/json', '--body', '@/dev/stdin'); input = JSON.stringify(body); }
  let out;
  try {
    out = execFileSync(OP, args, { input, encoding: 'utf8', stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], maxBuffer: 32 << 20 });
  } catch (e) {
    throw new Error(`Graph ${method} ${full.replace(/\?.*$/, '')} failed: ${String(e.stderr || e.message).trim().slice(0, 400)}`);
  }
  return out.trim() ? JSON.parse(out) : null;
}
function getUser(upn) {
  const u = graph('GET', `users/${encodeURIComponent(upn)}?$select=id,userPrincipalName,accountEnabled`);
  if (!u || !u.id) throw new Error(`${upn}: Graph returned no user`);
  if (!u.accountEnabled) throw new Error(`${upn} is disabled`);
  return u;
}
const fido2Methods = (uid) => graph('GET', `users/${uid}/authentication/fido2Methods`).value || [];

// Which passkey targets and profiles cover the account (read-only, for status).
function passkeyCoverage(uid) {
  const cfg = graph('GET', 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2');
  const ids = [...new Set([...(cfg.includeTargets || []), ...(cfg.excludeTargets || [])].map((t) => t.id).filter((i) => i !== 'all_users'))];
  const member = ids.length ? new Set(graph('POST', `users/${uid}/checkMemberGroups`, { groupIds: ids }).value || []) : new Set();
  const excluded = (cfg.excludeTargets || []).filter((t) => member.has(t.id)).map((t) => t.id);
  const targets = (cfg.includeTargets || []).filter((t) => t.id === 'all_users' || member.has(t.id));
  const profiles = (cfg.passkeyProfiles || []).filter((p) => targets.some((t) => (t.allowedPasskeyProfiles || []).includes(p.id)));
  return {
    state: cfg.state, excluded,
    targets: targets.map((t) => t.id),
    profiles: profiles.map((p) => ({ name: p.name, attestationEnforcement: p.attestationEnforcement, passkeyTypes: p.passkeyTypes, keyRestrictionsEnforced: !!(p.keyRestrictions && p.keyRestrictions.isEnforced) })),
    // Learn: any ONE scoped profile satisfied is enough.
    unattestedAllowed: profiles.some((p) => p.attestationEnforcement === 'disabled' && !(p.keyRestrictions && p.keyRestrictions.isEnforced)),
  };
}

// ---- Playwright + the virtual authenticator ------------------------------------------
function playwright() {
  const cands = [process.env.PLAYWRIGHT_PACKAGE_JSON, path.join(REPO, 'lab/setup/signup-assist/package.json'),
    path.join(os.homedir(), 'contoso-health-identity-lab/lab/setup/signup-assist/package.json')].filter(Boolean);
  for (const c of cands) if (fs.existsSync(path.join(path.dirname(c), 'node_modules', 'playwright'))) return createRequire(c)('playwright');
  throw new Error('Playwright not found: run `npm run setup` in lab/setup/signup-assist');
}
// CDP WebAuthn domain (Chrome DevTools Protocol, WebAuthn.addVirtualAuthenticator
// / getCredentials / addCredential). One authenticator per page: Entra may open
// the ceremony in a new page, so every page in the context gets one.
export const AUTHENTICATOR = { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };
async function withAuthenticators(context, { credential } = {}) {
  const auths = [];
  // page -> its attach promise, so the 'page' event and the explicit call
  // below never put two authenticators on one page.
  const attaching = new Map();
  const attach = (page) => {
    if (!attaching.has(page)) {
      attaching.set(page, (async () => {
        const cdp = await context.newCDPSession(page);
        await cdp.send('WebAuthn.enable', { enableUI: false });
        const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATOR });
        if (credential) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
        auths.push({ cdp, authenticatorId, page });
      })());
    }
    return attaching.get(page);
  };
  context.on('page', (p) => { attach(p).catch((e) => log('could not attach an authenticator to a new page:', e.message)); });
  if (process.env.PASSKEY_DEBUG) {
    // What the page asks the authenticator for (no challenge, no user id).
    await context.addInitScript(() => {
      const wrap = (name) => { const orig = navigator.credentials[name].bind(navigator.credentials); navigator.credentials[name] = (o) => { try { const pk = (o && o.publicKey) || {}; console.log(`[webauthn ${name}] ${JSON.stringify({ rpId: pk.rpId || (pk.rp && pk.rp.id), authenticatorSelection: pk.authenticatorSelection, hints: pk.hints, attestation: pk.attestation, timeout: pk.timeout, allow: (pk.allowCredentials || []).length, mediation: o && o.mediation, extensions: pk.extensions })}`); } catch {} return orig(o); }; };
      if (navigator.credentials) { wrap('create'); wrap('get'); }
      const P = window.PublicKeyCredential;
      if (P) for (const k of ['isUserVerifyingPlatformAuthenticatorAvailable', 'isConditionalMediationAvailable', 'getClientCapabilities']) {
        if (typeof P[k] === 'function') { const o = P[k].bind(P); P[k] = async (...a) => { const r = await o(...a); console.log(`[webauthn ${k}] ${JSON.stringify(r)}`); return r; }; }
      }
    });
    context.on('console', (m) => { if (/\[webauthn /.test(m.text())) log(m.text()); });
    context.on('weberror', (e) => log(`debug page error: ${String(e.error()).slice(0, 200)}`));
  }
  const page = await context.newPage();
  await attach(page);
  const credentials = async () => {
    const all = [];
    for (const a of auths) { try { all.push(...(await a.cdp.send('WebAuthn.getCredentials', { authenticatorId: a.authenticatorId })).credentials); } catch { /* page closed */ } }
    return all;
  };
  return { page, credentials };
}

// ---- screenshots (inputs blurred first) -----------------------------------------------
async function shot(page, name, dir = SHOTS_DIR) {
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, `${new Date().toISOString().replace(/[:.]/g, '-')}-${name.replace(/[^a-z0-9_.-]/gi, '_')}.png`);
  for (const fr of page.frames()) await fr.evaluate(() => { for (const e of document.querySelectorAll('input, textarea')) e.style.filter = 'blur(8px)'; }).catch(() => {});
  await page.screenshot({ path: f }).catch(() => {});
  return f;
}
async function pageText(page) {
  const parts = await Promise.all(page.frames().map((f) => f.locator('body').innerText({ timeout: 1500 }).catch(() => '')));
  return parts.join('\n');
}
// Names of what is on screen, for failure messages (inputs' values never).
async function ui(page) {
  const out = [];
  for (const f of page.frames()) {
    // Entra's buttons are often <input type=submit>: their VALUE is the
    // label (a button's value is never a secret; text inputs are skipped).
    out.push(...await f.evaluate(() => [...document.querySelectorAll('h1,h2,h3,[role=heading],button,a,[role=button],[role=link],[role=menuitem],[role=option],[role=radio],label,input[type=submit],input[type=button]')]
      .filter((e) => e.offsetParent !== null).map((e) => (e.tagName === 'INPUT' ? `[${e.value}]` : (e.innerText || e.getAttribute('aria-label') || '')).trim().replace(/\s+/g, ' ')).filter((x) => x && x.length < 90)).catch(() => []));
  }
  return [...new Set(out)].slice(0, 45).join(' | ');
}
// A locator really on screen (Entra keeps other steps' boxes in the DOM, off
// screen or transparent, for password managers).
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
async function clickText(page, re, { timeout = 20000, roles = ['button', 'link', 'menuitem', 'option', 'radio'] } = {}) {
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

// ---- driving Entra's sign-in pages ---------------------------------------------------
const LOGIN_HOST = /(^|\.)(login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com|login\.windows\.net)$/i;
const host = (u) => { try { return new URL(u).hostname; } catch { return ''; } };
const PASSKEY_CHOICE = /Face, fingerprint, PIN,? or security key|Sign in with a passkey|Use a passkey|^Passkey$|security key/i;
// One pass: do the one thing Entra is asking for. s.mode is 'tap' or 'passkey'.
async function step(page, upn, s) {
  if (!LOGIN_HOST.test(host(page.url()))) return null;
  s.sawLogin = true;
  const text = await pageText(page);
  const aadsts = text.match(/AADSTS\d+[^\n]*/);
  if (aadsts && !(await onScreen(page, 'input[name=loginfmt], input[name=accesspass]'))) throw new Error(`Entra refused the sign-in: ${aadsts[0].slice(0, 300)}`);
  if (/couldn.t sign you in with (a|your) passkey|passkey (was|is) not recogni[sz]ed|We couldn.t find a passkey/i.test(text)) throw new Error('Entra did not accept the passkey');

  // Account picker.
  if (await onScreen(page, '#tilesHolder, [data-test-id="tilesHolder"]')) {
    const tile = await onScreen(page, `[data-test-id="${upn}"], div[role=button]:has-text("${upn}")`);
    if (tile) { await tile.click(); return 'picked the account tile'; }
    const other = await onScreen(page, '#otherTile, [data-test-id="otherTile"], div[role=button]:has-text("Use another account")');
    if (other) { await other.click(); return 'use another account'; }
  }
  // Temporary Access Pass box.
  const tapBox = await onScreen(page, 'input[name=accesspass], #accesspass');
  if (tapBox) {
    if (s.mode !== 'tap') throw new Error('Entra asked for a Temporary Access Pass in a passkey sign-in (a pass is still active on the account?)');
    // Asked again after the pass was used: the first sign-in did not stick
    // (seen 2026-11-05: AADSTS90202 "transient error" on the app's code
    // redemption, Security info blank; twice in a row once). The single-use
    // pass is spent, so a NEW one is issued - at most twice.
    if (s.tapUsed) {
      if (!s.reissue || (s.reissued || 0) >= 2) throw new Error('Entra asked for the Temporary Access Pass again: it was refused');
      s.reissued = (s.reissued || 0) + 1; s.tap = s.reissue(); s.tapUsed = false;
    }
    if (!s.tap) throw new Error('no Temporary Access Pass in hand');
    await tapBox.fill(s.tap); s.tapUsed = true; s.tap = null;
    const b = await onScreen(page, '#idSIButton9, button[type=submit], input[type=submit]'); if (b) await b.click(); else await page.keyboard.press('Enter');
    return 'temporary access pass';
  }
  // Password page: never typed here. Go to the other ways to sign in.
  const pw = await onScreen(page, 'input[name=passwd], #i0118');
  if (pw) {
    if (s.switches++ > 2) throw new Error(`Entra keeps asking for a password. On screen: ${await ui(page)}`);
    // A passkey sign-in: the direct link first ("Use your face, fingerprint,
    // PIN, or security key instead", seen 2026-11-05 for an account whose
    // passkey was never used), else the list of other ways.
    if (s.mode === 'passkey') {
      const pk = await onScreen(page, 'a:has-text("security key instead"), [role=link]:has-text("security key instead"), a:has-text("passkey instead"), #idA_PWD_SwitchToFido');
      if (pk) { await pk.click(); return 'use a passkey instead'; }
    }
    const sw = await onScreen(page, '#idA_PWD_SwitchToCredPicker, a:has-text("Other ways to sign in"), a:has-text("Sign in another way"), a:has-text("Sign-in options")');
    if (sw) { await sw.click(); return 'other ways to sign in'; }
    throw new Error(`Entra asked for a password and offers no other way. On screen: ${await ui(page)}`);
  }
  // Credential picker / "Sign-in options": choose the passkey or the pass.
  const want = s.mode === 'tap' ? /Temporary Access Pass/i : PASSKEY_CHOICE;
  for (const sel of ['div[role=button]', '[role=listitem] [role=button]', 'button', '[data-test-cred-id]', 'a']) {
    const all = page.locator(sel);
    const n = Math.min(await all.count().catch(() => 0), 30);
    for (let i = 0; i < n; i++) {
      const l = all.nth(i);
      const t = ((await l.innerText().catch(() => '')) || '').trim();
      if (t && want.test(t) && !/^Back$|Cancel/i.test(t) && await l.isVisible().catch(() => false)) {
        if (s.picks++ > 4) throw new Error(`Entra keeps offering "${t}". On screen: ${await ui(page)}`);
        await l.click(); return `chose "${t.split('\n')[0].slice(0, 60)}"`;
      }
    }
  }
  // "Stay signed in?" - no (nothing persists past this run anyway).
  if (await onScreen(page, '#KmsiCheckboxField, #KmsiDescription') || /Stay signed in\?/.test(text)) {
    const b = await onScreen(page, '#idBtn_Back, button:has-text("No"), input[value="No"]');
    if (b) { await b.click(); return 'stay signed in: no'; }
  }
  // Postponable nudges (registration campaign).
  const later = await onScreen(page, '#btnAskLater, a:has-text("Skip for now"), button:has-text("Skip for now"), a:has-text("Ask later"), button:has-text("Not now")');
  if (later) { await later.click(); return 'postponed a nudge'; }
  // Username (last: the box stays in the DOM, off screen, on later pages).
  const user = await onScreen(page, 'input[name=loginfmt], #i0116');
  if (user) {
    if (s.userTries++ > 2) throw new Error(`Entra refused the username ${upn}`);
    if ((await user.inputValue().catch(() => '')).toLowerCase() !== upn) await user.fill(upn);
    const b = await onScreen(page, '#idSIButton9, button[type=submit], input[type=submit]'); if (b) await b.click(); else await page.keyboard.press('Enter');
    return 'username';
  }
  return null;
}
// retryUrl: the app page to open again, once, if the browser is back on the
// app but the app never renders (seen 2026-11-05: Security info stayed blank
// after the redirect; the session cookie is set by then, so a reload works).
async function drive(page, upn, s, until, { timeoutMs = 180000, retryUrl = null } = {}) {
  Object.assign(s, { switches: 0, picks: 0, userTries: 0, trail: [] });
  const deadline = Date.now() + timeoutMs;
  let onAppSince = 0, retried = 0;
  while (Date.now() < deadline) {
    await page.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});
    const did = await step(page, upn, s);
    if (did) { s.trail.push(did); log(`${localPart(upn)}: ${did}`); onAppSince = 0; await sleep(1500); continue; }
    if (!LOGIN_HOST.test(host(page.url()))) {
      if (await until(page).catch(() => false)) return s.trail;
      if (process.env.PASSKEY_DEBUG && (!onAppSince || Date.now() - onAppSince > 5000 * (s.dbg = (s.dbg || 0) + 1) / 4)) {
        const u = new URL(page.url());
        log(`debug drive: ${u.host}${u.pathname} (${(await pageText(page)).length} chars) | ${await ui(page)}`);
        await shot(page, `debug-drive-${localPart(upn)}`);
      }
      onAppSince = onAppSince || Date.now();
      if (retryUrl && retried < 3 && Date.now() - onAppSince > 25000) {
        retried++; onAppSince = 0; s.trail.push('reopened the app page'); log(`${localPart(upn)}: the app page stayed empty; opening it again`);
        await page.goto(retryUrl, { waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => {});
      }
    } else onAppSince = 0;
    await sleep(700);
  }
  throw new Error(`sign-in did not finish in ${timeoutMs / 1000}s (at ${host(page.url())}). On screen: ${await ui(page)}`);
}

// In the "add a passkey" wizard: an on-screen choice that leads to a security
// key (USB) rather than Microsoft Authenticator, not clicked before.
export const SECURITY_KEY_CHOICE = /security key|another device|other device|USB|other passkey|different (device|way)/i;
async function securityKeyChoice(page, chose) {
  for (const f of page.frames()) {
    for (const sel of ['[role=radio]', '[role=option]', '[role=menuitem]', '[role=button]', 'button', 'a', 'label']) {
      const all = f.locator(sel);
      const n = Math.min(await all.count().catch(() => 0), 40);
      for (let i = 0; i < n; i++) {
        const l = all.nth(i);
        const t = ((await l.innerText().catch(() => '')) || (await l.getAttribute('aria-label').catch(() => '')) || '').trim().replace(/\s+/g, ' ');
        if (!t || t.length > 120 || chose.has(t) || !SECURITY_KEY_CHOICE.test(t) || /Authenticator|Having trouble|Learn more|Cancel|Back/i.test(t)) continue;
        if (await l.isVisible().catch(() => false)) return { l, t };
      }
    }
  }
  return null;
}

// Click the first visible method entry matching the preferences in order,
// skipping anything that names Microsoft Authenticator.
async function clickMethod(page, prefs, timeout = 20000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const seen = [];
    for (const f of page.frames()) {
      for (const sel of ['[role=option]', '[role=listitem]', '[role=menuitem]', '[role=button]', 'button', 'a']) {
        const all = f.locator(sel);
        const n = Math.min(await all.count().catch(() => 0), 40);
        for (let i = 0; i < n; i++) {
          const l = all.nth(i);
          if (!(await l.isVisible().catch(() => false))) continue;
          // Only what is ON TOP at its own centre: the page behind the "Add a
          // sign-in method" dialog lists the methods already registered
          // ("Passkey (Device bound) ... Delete"), covered by the dialog's
          // overlay, and must never be picked (seen 2026-11-05 on --replace).
          if (!(await l.evaluate((e) => { const r = e.getBoundingClientRect(); const t = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2); return !!t && (t === e || e.contains(t)); }).catch(() => false))) continue;
          const t = ((await l.innerText().catch(() => '')) || (await l.getAttribute('aria-label').catch(() => '')) || '').trim().replace(/\s+/g, ' ');
          if (t && t.length < 160 && !/Authenticator/i.test(t)) seen.push({ l, t });
        }
      }
    }
    for (const re of prefs) { const hit = seen.find((x) => re.test(x.t)); if (hit) { log(`chose method "${hit.t.slice(0, 70)}"`); await hit.l.click(); return hit.t; } }
    await sleep(700);
  }
  throw new Error(`no security-key / passkey method offered. On screen: ${await ui(page)}`);
}

// ---- register --------------------------------------------------------------------------
function existingState(upn, uid) {
  const methods = fido2Methods(uid);
  const raw = keychainRead(keychainService(upn));
  const rec = raw ? decodeRecord(raw) : null;
  const registered = rec && rec.methodId ? methods.find((m) => m.id === rec.methodId) : null;
  return { methods, rec, registered };
}

async function registerViaGraph(upn, uid, before, { headless }) {
  // BETA on purpose: on v1.0 this tenant answers 400 "Invalid value for KeyId:
  // creationOptions(...)" (2026-11-05); the beta function is the documented one.
  const optsResp = graph('GET', `${BETA}/users/${uid}/authentication/fido2Methods/creationOptions(challengeTimeoutInMinutes=10)`);
  const opts = toBrowserCreationOptions(optsResp);
  if (opts.rp.id !== 'login.microsoft.com') throw new Error(`creationOptions rp.id is ${opts.rp.id}; this script only serves https://login.microsoft.com`);
  const origin = `https://${opts.rp.id}`;
  const browser = await playwright().chromium.launch({ headless });
  try {
    const context = await browser.newContext({ locale: 'en-US' });
    // A blank page AT the relying party's origin, served by Playwright (no
    // network, no Microsoft script), so WebAuthn's origin check passes and
    // clientDataJSON says https://login.microsoft.com.
    const PAGE = `${origin}/contoso-lab-passkey-provision`;
    await context.route(PAGE, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><meta charset="utf-8"><title>Contoso lab passkey provisioning</title>' }));
    const { page, credentials } = await withAuthenticators(context);
    await page.goto(PAGE);
    const made = await page.evaluate(async (o) => {
      const dec = (s) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); const b = atob(t + '='.repeat((4 - (t.length % 4)) % 4)); return Uint8Array.from(b, (c) => c.charCodeAt(0)); };
      const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const c = await navigator.credentials.create({ publicKey: { ...o, challenge: dec(o.challenge), user: { ...o.user, id: dec(o.user.id) }, excludeCredentials: [] } });
      return { id: c.id, clientDataJSON: enc(c.response.clientDataJSON), attestationObject: enc(c.response.attestationObject) };
    }, opts);
    checkClientData(made.clientDataJSON, opts.challenge, origin);
    const cred = pickCredential(await credentials(), opts.rp.id);
    // Keychain FIRST (pending item, methodId unknown yet), then register: a
    // crash after Entra accepts the key can then never lose it.
    const rec = { upn, rpId: cred.rpId, credentialId: cred.credentialId, privateKey: cred.privateKey, userHandle: cred.userHandle, signCount: cred.signCount, via: 'graph', createdUtc: new Date().toISOString(), methodId: null };
    saveRecord(upn, rec, pendingService(upn));
    let m = null, postError = null;
    try {
      // No "@odata.type" although Learn's example has one: with it, beta
      // answers 400 "The request is missing a fido2AuthenticationMethod
      // entity..." (probed 2026-11-05 with invalid bodies); without it the
      // body is parsed.
      m = graph('POST', `${BETA}/users/${uid}/authentication/fido2Methods`, {
        displayName: DISPLAY_NAME,
        publicKeyCredential: { id: made.id, response: { clientDataJSON: made.clientDataJSON, attestationObject: made.attestationObject } },
      });
    } catch (e) { postError = e; }
    let r = resolvePost(m, []);
    if (!r.methodId) {
      // No id back: ask Graph what is registered now before touching the key.
      let added;
      try { added = newMethods(before, fido2Methods(uid)); } catch (e) {
        throw new Error(`the passkey POST ${postError ? `failed (${postError.message})` : 'returned no id'} and Graph could not be read (${e.message}); the key is KEPT in Keychain ${pendingService(upn)} - check the account's passkey methods before deleting it`);
      }
      r = resolvePost(m, added);
      if (r.rejected) { keychainDelete(pendingService(upn)); throw postError || new Error('Graph did not register the passkey'); }
      if (r.ambiguous) throw new Error(`the passkey POST outcome is unclear and Graph lists ${added.length} new passkey methods; the key is KEPT in Keychain ${pendingService(upn)} for a person to match`);
      log(`${localPart(upn)}: the POST ${postError ? 'failed' : 'returned no id'}, but Graph lists the new method: keeping the key`);
    }
    const done = { ...rec, methodId: r.methodId, aaGuid: (m && m.aaGuid) || null, attestationLevel: (m && m.attestationLevel) || null };
    saveRecord(upn, done, pendingService(upn));
    return { rec: done };
  } finally { await browser.close().catch(() => {}); }
}

async function registerViaTap(upn, uid, before, { headless }) {
  const tapCfg = graph('GET', 'policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass');
  if (tapCfg.state !== 'enabled') throw new Error('the Temporary Access Pass method is not enabled: use --via graph');
  const ex = (tapCfg.excludeTargets || []).map((t) => t.id);
  if (ex.length && (graph('POST', `users/${uid}/checkMemberGroups`, { groupIds: ex }).value || []).length) throw new Error(`${upn} is in a group the TAP policy excludes: use --via graph`);
  const removeTaps = () => { for (const t of graph('GET', `users/${uid}/authentication/temporaryAccessPassMethods`).value || []) graph('DELETE', `users/${uid}/authentication/temporaryAccessPassMethods/${t.id}`); };
  const minutes = Math.max(10, Number(tapCfg.minimumLifetimeInMinutes) || 60);
  const issue = () => {
    removeTaps();
    const t = graph('POST', `users/${uid}/authentication/temporaryAccessPassMethods`, { lifetimeInMinutes: minutes, isUsableOnce: true }).temporaryAccessPass;
    if (!t) throw new Error('the Temporary Access Pass was not issued');
    log(`${localPart(upn)}: one-time Temporary Access Pass issued (${minutes} min, single use, held in memory)`);
    return t;
  };
  // The browser first, the pass second: nothing that can fail sits between
  // issuing the pass and the try/finally that removes it.
  const browser = await playwright().chromium.launch({ headless });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US' });
  const { page, credentials } = await withAuthenticators(context);
  const s = { mode: 'tap', tap: null, reissue: issue };
  let failed = null;
  try {
    s.tap = issue();
    await page.goto(SECURITY_INFO, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await drive(page, upn, s, async (p) => /mysignins\.microsoft\.com/.test(p.url()) && /Security info/i.test(await pageText(p)), { retryUrl: SECURITY_INFO });
    log(`${localPart(upn)}: on Security info`);
    await sleep(2500);
    await clickText(page, /Add sign-in method/i);
    await sleep(1500);
    if (process.env.PASSKEY_DEBUG) { log(`debug chooser: ${await ui(page)}`); await shot(page, `debug-${localPart(upn)}-chooser`); }
    // The method list (2026-11-05) offers "Passkey in Microsoft Authenticator"
    // and a separate security-key / other-passkey entry. The phone-app one is
    // never wanted here: pick by preference, Authenticator entries excluded.
    const combo = page.getByRole('combobox').first();
    if (await combo.isVisible().catch(() => false)) { await combo.click(); await sleep(500); }
    await clickMethod(page, [/^Security key\b/i, /^Passkey$/i, /^Passkey\b(?![\s\S]*Authenticator)/i, /security key|other device|another device/i]);
    if (await combo.isVisible().catch(() => false)) await clickText(page, /^Add$/i);
    // From here Entra asks a few questions (where the passkey lives, USB or
    // NFC, a heads-up), then runs the WebAuthn ceremony, then asks for a name.
    // Answer whatever is on screen until the authenticator holds a credential.
    const deadline = Date.now() + 120000;
    const chose = new Set();
    let named = false, n = 0, settingUpSince = 0, nudges = 0;
    while (Date.now() < deadline) {
      await sleep(1500);
      const creds = (await credentials()).filter((c) => c.rpId === 'login.microsoft.com');
      const txt = await pageText(page);
      // PASSKEY_DEBUG=1: a screenshot (inputs blurred) and the on-screen names
      // per pass, for when Microsoft changes the wizard.
      if (process.env.PASSKEY_DEBUG) { log(`debug ${n}: ${host(page.url())} | ${await ui(page)}`); await shot(page, `debug-${localPart(upn)}-${String(n++).padStart(2, '0')}`); }
      if (/No passkey was saved|you must use Microsoft Authenticator/i.test(txt)) throw new Error(`Entra refused the passkey: ${txt.match(/No passkey was saved[^\n]*|To save a passkey[^\n]*/i)?.[0] || 'no passkey saved'}`);
      if (creds.length && !named) {
        const nameBox = await onScreen(page, 'input[type=text]');
        if (nameBox && /name/i.test(txt)) { await nameBox.fill(DISPLAY_NAME); await sleep(300); await clickText(page, /^Next$|^Done$|^Save$|^OK$/i); named = true; continue; }
      }
      if (creds.length && (named || /passkey (is|was) (now )?(added|registered|saved|ready)|You.re all set|successfully/i.test(txt))) {
        if (/^\s*Done\s*$/m.test(txt)) await clickText(page, /^Done$/i, { timeout: 3000 }).catch(() => {});
        break;
      }
      if (LOGIN_HOST.test(host(page.url()))) { const did = await step(page, upn, s); if (did) { log(`${localPart(upn)}: ${did}`); continue; } }
      // "Setting up your passkey..." that never starts the ceremony: press its
      // primary button (at most twice), which starts it with a user gesture.
      if (LOGIN_HOST.test(host(page.url())) && /Setting up your passkey/i.test(txt) && !creds.length) {
        settingUpSince = settingUpSince || Date.now();
        if (Date.now() - settingUpSince > 8000 && nudges < 2) {
          const b = await onScreen(page, '#idSIButton9, input[type=submit], button[type=submit]');
          if (b) { nudges++; settingUpSince = Date.now(); log(`${localPart(upn)}: pressed "${await b.getAttribute('value').catch(() => '') || await b.innerText().catch(() => '')}" on the set-up page`); await b.click(); continue; }
        }
      } else settingUpSince = 0;
      // The security-key choice FIRST: the wizard pre-selects Microsoft
      // Authenticator, and "Next" on that leads to "you must use Microsoft
      // Authenticator" (seen 2026-11-05).
      const choice = await securityKeyChoice(page, chose);
      if (choice) { await choice.l.click(); chose.add(choice.t); log(`${localPart(upn)}: chose "${choice.t}"`); await sleep(800); }
      const next = await onScreen(page, 'button:has-text("Next"), button:has-text("Continue"), [role=button]:has-text("Next")');
      if (next) { await next.click(); log(`${localPart(upn)}: next`); continue; }
    }
    await sleep(2000);
    const cred = pickCredential(await credentials(), 'login.microsoft.com');
    const rec = { upn, rpId: cred.rpId, credentialId: cred.credentialId, privateKey: cred.privateKey, userHandle: cred.userHandle, signCount: cred.signCount, via: 'tap', createdUtc: new Date().toISOString(), methodId: null };
    saveRecord(upn, rec, pendingService(upn));
    log(`${localPart(upn)}: credential exported to Keychain ${pendingService(upn)}`);
    // Graph must list a NEW passkey method; its id ties the Keychain copy to
    // it. A Graph read that fails throws here and KEEPS the pending key.
    let added = [];
    for (let i = 0; i < 10 && !added.length; i++) { added = newMethods(before, fido2Methods(uid)); if (!added.length) await sleep(3000); }
    if (!added.length) { keychainDelete(pendingService(upn)); throw new Error(`Graph lists no new passkey method after registration (the key was discarded). On screen: ${await ui(page)}`); }
    if (added.length > 1) throw new Error(`Graph lists ${added.length} new passkey methods (expected 1); the key is KEPT in Keychain ${pendingService(upn)} for a person to match`);
    const done = { ...rec, methodId: added[0].id, aaGuid: added[0].aaGuid || null, attestationLevel: added[0].attestationLevel || null };
    saveRecord(upn, done, pendingService(upn));
    return { rec: done, screenshot: await shot(page, `register-ok-${localPart(upn)}`) };
  } catch (e) {
    const f = await shot(page, `register-fail-${localPart(upn)}`);
    e.message += ` [screenshot: ${f}]`;
    failed = e;
    throw e;
  } finally {
    await browser.close().catch(() => {});
    // Fail closed: a pass the clean-up could not remove is a live credential
    // for up to an hour, so it is never just a warning.
    try { removeTaps(); } catch (e) {
      const msg = `could not remove the Temporary Access Pass from ${upn} (delete it in Entra now): ${e.message}`;
      if (failed) failed.message += `; ALSO ${msg}`; else throw new Error(`the passkey was registered, but ${msg}`);
    }
  }
}

// --replace never removes the working key first (break-glass has only one):
// the new key is registered next to it, kept in the -pending item, and must
// sign in (passkey only, My Account) before it becomes the Keychain key; the
// old method is deleted last. For a break-glass account that proof is a real
// break-glass sign-in and raises the Sentinel incident, on purpose.
export async function register(upn, { via, breakGlass = false, replace = false, headless = true } = {}) {
  upn = checkUpn(upn, { breakGlass });
  via = chooseVia(upn, via);
  const user = getUser(upn);
  const st = existingState(upn, user.id);
  if (keychainRead(pendingService(upn)) !== null) throw new Error(`${upn}: Keychain item ${pendingService(upn)} holds a key from an unfinished run. Check \`status\`: if its methodId is listed, use or delete that method in Entra; then remove the item (security delete-generic-password -s ${pendingService(upn)}) and run again`);
  if (st.registered && !replace) { log(`${localPart(upn)}: already has the lab passkey (method ${st.registered.id}); --replace to make a new one`); return { upn, already: true, methodId: st.registered.id }; }
  if (st.rec && !st.registered && !replace) throw new Error(`${upn}: the Keychain holds a passkey whose method is not registered any more; --replace to make a new one`);
  // Only the method this script made is ever deleted; any other key stays.
  const before = fido2Methods(user.id);
  const r = via === 'graph' ? await registerViaGraph(upn, user.id, before, { headless }) : await registerViaTap(upn, user.id, before, { headless });
  let rec = r.rec;
  const listed = fido2Methods(user.id).find((m) => m.id === rec.methodId);
  if (!listed) throw new Error(`${upn}: Graph does not list the new passkey method ${rec.methodId}; the key is KEPT in Keychain ${pendingService(upn)}`);
  log(`${localPart(upn)}: passkey registered (${via}); Graph lists it as "${listed.displayName}" (${listed.model || 'no model'}, ${listed.attestationLevel || 'attestation n/a'})`);
  let proof = null;
  if (replace && st.rec) {
    try { proof = await proveRecord(upn, rec, { headless }); } catch (e) {
      throw new Error(`the new passkey (method ${rec.methodId}) is registered but did not sign in: ${e.message}. The old key and method are untouched; the new key is KEPT in Keychain ${pendingService(upn)}`);
    }
    rec = { ...rec, signCount: proof.signCount, lastProvedUtc: new Date().toISOString() };
  }
  // Promote: the new key becomes the Keychain key, then the pending copy goes.
  saveRecord(upn, rec);
  keychainDelete(pendingService(upn));
  if (replace && st.registered) {
    try { graph('DELETE', `users/${user.id}/authentication/fido2Methods/${st.registered.id}`); } catch (e) {
      throw new Error(`the new passkey is in use (Keychain ${keychainService(upn)}), but the old method ${st.registered.id} could not be deleted: ${e.message}. Delete it in Entra`);
    }
    log(`${localPart(upn)}: removed the old lab passkey method (after the new one signed in)`);
  }
  return { upn, via, methodId: rec.methodId, displayName: listed.displayName, model: listed.model || null, aaGuid: listed.aaGuid || null, attestationLevel: listed.attestationLevel || null, keychainItem: keychainService(upn), screenshot: r.screenshot || null, proof };
}

// ---- prove -----------------------------------------------------------------------------
export async function prove(upn, { breakGlass = false, startUrl = DEFAULT_PROOF_URL, headless = true } = {}) {
  upn = checkUpn(upn, { breakGlass });
  const raw = keychainRead(keychainService(upn));
  if (!raw) throw new Error(`no Keychain item ${keychainService(upn)}: run register first`);
  const rec = decodeRecord(raw);
  if (rec.upn && rec.upn.toLowerCase() !== upn) throw new Error(`Keychain item ${keychainService(upn)} belongs to ${rec.upn}`);
  const r = await proveRecord(upn, rec, { startUrl, headless });
  // Keep the counter rising: write the authenticator's new signCount back
  // (a relying party may refuse a counter that goes backwards).
  saveRecord(upn, { ...rec, signCount: r.signCount, lastProvedUtc: new Date().toISOString() });
  return r;
}

// One passkey-only sign-in with `rec` in a fresh browser; throws unless
// proofVerdict says the passkey really signed in.
async function proveRecord(upn, rec, { startUrl = DEFAULT_PROOF_URL, headless = true } = {}) {
  const startedUtc = new Date().toISOString();
  const browser = await playwright().chromium.launch({ headless });
  // A fresh context: no cookies, no session, nothing but the Keychain copy.
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US' });
  const { page, credentials } = await withAuthenticators(context, {
    credential: { credentialId: rec.credentialId, isResidentCredential: true, rpId: rec.rpId, privateKey: rec.privateKey, userHandle: rec.userHandle, signCount: rec.signCount },
  });
  try {
    await page.goto(startUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const targetHost = host(startUrl);
    const s = { mode: 'passkey' };
    const trail = await drive(page, upn, s, async (p) => host(p.url()) === targetHost && (await pageText(p)).length > 200, { retryUrl: startUrl });
    await sleep(4000);
    const f = await shot(page, `prove-${localPart(upn)}`);
    const now = (await credentials()).find((c) => c.credentialId === rec.credentialId);
    // My Account shows the signed-in account's UPN; another app may not.
    const v = proofVerdict({
      signCountBefore: rec.signCount, signCountAfter: now ? now.signCount : null, sawLogin: !!s.sawLogin,
      landedHost: host(page.url()), targetHost, trail, expectText: startUrl === DEFAULT_PROOF_URL ? upn : null, text: await pageText(page),
    });
    if (!v.ok) throw new Error(`not proven: ${v.reasons.join('; ')}`);
    log(`${localPart(upn)}: passkey-only sign-in reached ${host(page.url())}`);
    return { upn, startedUtc, landed: page.url(), title: await page.title(), trail, signCount: now.signCount, screenshot: f };
  } catch (e) {
    const f = await shot(page, `prove-fail-${localPart(upn)}`);
    e.message += ` [screenshot: ${f}]`;
    throw e;
  } finally { await browser.close().catch(() => {}); }
}

// ---- status (read-only) --------------------------------------------------------------------
export function status(upn, { breakGlass = false } = {}) {
  upn = checkUpn(upn, { breakGlass });
  const user = getUser(upn);
  const st = existingState(upn, user.id);
  return {
    upn,
    passkeyMethods: st.methods.map((m) => ({ id: m.id, displayName: m.displayName, model: m.model || null, aaGuid: m.aaGuid || null, attestationLevel: m.attestationLevel || null, createdDateTime: m.createdDateTime })),
    keychainItem: st.rec ? { service: keychainService(upn), via: st.rec.via, methodId: st.rec.methodId, signCount: st.rec.signCount, registered: !!st.registered } : null,
    pendingItem: (() => { const raw = keychainRead(pendingService(upn)); if (raw === null) return null; const p = decodeRecord(raw); return { service: pendingService(upn), via: p.via, methodId: p.methodId, registered: !!(p.methodId && st.methods.some((m) => m.id === p.methodId)) }; })(),
    coverage: passkeyCoverage(user.id),
  };
}

// ---- CLI ----------------------------------------------------------------------------------
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const a = process.argv.slice(2);
  const flag = (n) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
  const val = (n) => { const i = a.indexOf(n); if (i < 0) return undefined; const v = a[i + 1]; a.splice(i, 2); return v; };
  const breakGlass = flag('--break-glass'), replace = flag('--replace'), headed = flag('--headed');
  const via = val('--via'), startUrl = val('--start-url');
  const [cmd, upn] = a;
  const usage = 'usage: node passkey.mjs register|prove|status <upn> [--break-glass] [--via tap|graph] [--replace] [--start-url <url>] [--headed]';
  if (!['register', 'prove', 'status'].includes(cmd) || !upn) { console.error(usage); process.exit(2); }
  try {
    const r = cmd === 'register' ? await register(upn, { via, breakGlass, replace, headless: !headed })
      : cmd === 'prove' ? await prove(upn, { breakGlass, startUrl: startUrl || DEFAULT_PROOF_URL, headless: !headed })
        : status(upn, { breakGlass });
    console.log(JSON.stringify({ ok: true, cmd, ...r }));
  } catch (e) {
    console.log(JSON.stringify({ ok: false, cmd, upn, error: e.message }));
    process.exit(1);
  }
}
