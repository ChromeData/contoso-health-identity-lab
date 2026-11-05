// =============================================================================
// lab/scripts/demo/signin/lib.mjs - shared pieces of the staff sign-in toolkit
// -----------------------------------------------------------------------------
// enroll.mjs gives a lab user a password + authenticator-app (TOTP) sign-in;
// signin.mjs signs that user in through Entra, headless, on any app that
// sends people to Entra (AWS access portal, Okta, My Apps, ServiceNow...).
// Both are recording and evidence aids: they let the lab show a REAL staff
// sign-in (password + MFA, Conditional Access evaluated) without a phone.
//
// WHY THESE RULES (AGENT-RULES / ADR 0024):
//   * Secrets live only in the macOS login Keychain. They are read with
//     `security find-generic-password -s <name> -w` into this process and
//     written with `security -i` over STDIN - never on a command line (argv
//     is visible to every process), never printed, never in a file the repo
//     or a log could pick up. The one exception is the browser storage state
//     (session cookies), written mode 600 under ~/.contoso-operator/session,
//     the operator's private session folder.
//   * Every Graph call goes through the lab operator (`op az rest`): one
//     auditable workload identity, never the owner's account. Request bodies
//     reach az on STDIN (`--body @/dev/stdin`), so a password never sits in
//     argv either.
//   * The TOTP is computed here with node:crypto (RFC 6238, HMAC-SHA1, 30 s,
//     6 digits): no extra package to vet, and the seed never leaves memory.
//   * The owner's account and the break-glass accounts are refused outright:
//     an automated sign-in or an auth-method change on them is never right.
// =============================================================================
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '../../../..');
export const OP = process.env.CONTOSO_OP || path.join(REPO, 'lab/scripts/operator/op');
const OP_HOME = process.env.CONTOSO_OPERATOR_HOME || path.join(os.homedir(), '.contoso-operator');
// Per-user browser storage state (cookies), mode 600, in the operator's
// private session folder (lab-signout.sh is where a session ends).
export const STATE_DIR = path.join(OP_HOME, 'session', 'browser');
// Failure screenshots. Secret-bearing elements are blurred first (redact()).
export const SHOTS_DIR = process.env.SIGNIN_SHOTS_DIR || path.join(os.tmpdir(), 'signin-shots');

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const log = (...a) => { if (!process.env.SIGNIN_QUIET) console.error('[signin]', ...a); };

// ---- who may be signed in --------------------------------------------------
// The lab tenant's two domains only. The owner's account (AGENT-RULES hard
// limit) and break-glass accounts are refused for every operation.
const LAB_DOMAINS = /@(contosohealthlab\.com|contosohealthlab\.onmicrosoft\.com)$/i;
const REFUSED = [/^michaelwilliams@/i, /^bg-/i, /^breakglass/i];
export function checkUpn(upn) {
  if (!upn || !/^[^@\s]+@[^@\s]+$/.test(upn)) throw new Error(`not a user principal name: ${upn}`);
  if (!LAB_DOMAINS.test(upn)) throw new Error(`${upn} is not in the lab tenant's domains`);
  if (REFUSED.some((r) => r.test(upn))) throw new Error(`${upn} is the owner's or a break-glass account: refused`);
  return upn.toLowerCase();
}
export const localPart = (upn) => upn.split('@')[0].toLowerCase();

// ---- Keychain --------------------------------------------------------------
// Fail closed: `security` exits 44 (errSecItemNotFound) when the item does
// not exist - that, and only that, is "not there" (null). Any other failure
// (Keychain locked, access denied) throws, so a caller can never mistake
// "couldn't read" for "no password yet" and overwrite a working password.
const ITEM_NOT_FOUND = 44;
// CONTOSO_SECURITY_BIN: a test seam only (tests/lib.test.mjs points it at a
// fake that exits 44 or 36), never set in normal use.
const SECURITY = process.env.CONTOSO_SECURITY_BIN || 'security';
function security(args) {
  try {
    return execFileSync(SECURITY, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    if (e.status === ITEM_NOT_FOUND) return null;
    throw new Error(`Keychain read failed (security exit ${e.status}) for ${args[args.indexOf('-s') + 1]}: unlock the login Keychain and retry`);
  }
}
// Read: value straight into this process. Null when the item is missing.
// With `account`, the item must ALSO have that account attribute: the
// secrets are named by the UPN's local part, and the lab has two domains
// (contosohealthlab.com, contosohealthlab.onmicrosoft.com), so the account
// (the full UPN) is what tells two same-named users apart.
export function keychainRead(service, account) {
  const out = security(['find-generic-password', '-s', service, ...(account ? ['-a', account] : []), '-w']);
  return out === null ? null : out.replace(/\n$/, '');
}
// Write (create or update, -U) over STDIN to `security -i`. The value must be
// a single token: the interactive parser splits on spaces and quotes, so a
// value that needs quoting is refused rather than mangled.
export function keychainWrite(service, account, label, secret) {
  if (!secret || /[\s"'\\]/.test(secret)) throw new Error('keychainWrite: the value must be one token without quotes, backslashes or spaces');
  if (/[\s"'\\]/.test(service + account + label.replace(/ /g, ''))) throw new Error('keychainWrite: bad service/account/label');
  try {
    execFileSync(SECURITY, ['-i'], {
      input: `add-generic-password -U -s ${service} -a ${account} -l "${label}" -w ${secret}\n`,
      stdio: ['pipe', 'ignore', 'ignore'], // stderr dropped: a parser error could echo the line, secret included
    });
  } catch (e) { throw new Error(`Keychain write to ${service} failed (security exit ${e.status})`); }
  if (keychainRead(service, account) !== secret) throw new Error(`Keychain write to ${service} did not read back`);
}

// Delete an item (no secret in argv). Missing (exit 44) is fine; anything
// else throws.
export function keychainDelete(service, account) {
  try { execFileSync(SECURITY, ['delete-generic-password', '-s', service, ...(account ? ['-a', account] : [])], { stdio: ['ignore', 'ignore', 'ignore'] }); return true; } catch (e) {
    if (e.status === ITEM_NOT_FOUND) return false;
    throw new Error(`Keychain delete failed (security exit ${e.status}) for ${service}`);
  }
}
// The default Keychain, as one object, so steps can be tested with a fake.
export const keychain = { read: (s, a) => keychainRead(s, a), write: (s, a, l, v) => keychainWrite(s, a, l, v), del: (s, a) => keychainDelete(s, a) };

// Names used for a user's secrets.
export const totpService = (upn) => `contoso-lab-totp-${localPart(upn)}`;
export const pwService = (upn) => `contoso-lab-pw-${localPart(upn)}`;
// A secret that is not yet in force on the account waits here, so the item
// above always holds what Entra accepts (see enroll.mjs).
export const pendingService = (svc) => `${svc}-pending`;
// The user's password: contoso-lab-pw-<local> (set by enroll.mjs), else the
// older contoso-lab-<local> items (the test users' contoso-lab-test-user-a/b/c).
// Both are read by service AND account = this UPN, so a same-named user on
// the other lab domain never gets this user's password.
export function passwordFor(upn) {
  for (const svc of [pwService(upn), `contoso-lab-${localPart(upn)}`]) {
    const v = keychainRead(svc, upn);
    if (v) return { service: svc, value: v };
  }
  return null;
}
// The user's authenticator seed (enroll.mjs), by service AND account.
export const seedFor = (upn) => keychainRead(totpService(upn), upn);

// ---- TOTP (RFC 6238 over RFC 4226), node:crypto only -----------------------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Decode(s) {
  const clean = String(s).replace(/[\s=-]/g, '').toUpperCase();
  if (!clean || /[^A-Z2-7]/.test(clean)) throw new Error('not a base32 secret');
  let bits = 0, val = 0; const out = [];
  for (const c of clean) {
    val = (val << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
export function hotp(key, counter, digits = 6) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  const bin = h.readUInt32BE(o) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, '0');
}
export function totp(secretB32, { now = Date.now(), step = 30, digits = 6 } = {}) {
  const counter = Math.floor(now / 1000 / step);
  return { code: hotp(base32Decode(secretB32), counter, digits), counter, secondsLeft: step - Math.floor(now / 1000) % step };
}
// Entra refuses a code that was already used. The last time step used per
// user (a counter, not a secret) is kept next to the storage state, so two
// sign-ins inside one 30-second window wait for the next code. Read, wait
// and reservation happen under a per-user lock file (exclusive create), so
// overlapping sign-ins - in one process or several - never get the same
// code (see recoverStaleLock for a crashed holder's lock).
const stepFile = (upn) => path.join(STATE_DIR, `${localPart(upn)}.totp-step`);
const lockFile = (upn) => path.join(STATE_DIR, `${localPart(upn)}.totp-lock`);
const realClock = { now: () => Date.now(), sleep };
export function markTotpStep(upn, counter) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(stepFile(upn), String(counter), { mode: 0o600 });
}
// The lock file holds its owner's token. Only the owner removes it. A lock
// older than STALE_MS (a crashed holder; a live one holds it < 40 s) is
// recovered by renaming it aside - rename is atomic, so of two recoverers
// only one moves it - and the mover checks it moved the stale lock it saw;
// if a fresh lock had replaced it in between, it is put back (link = create
// only if the slot is still free) and nobody else's lock is lost.
const STALE_MS = 90000;
function recoverStaleLock(f) {
  let seen, st;
  try { st = fs.statSync(f); seen = fs.readFileSync(f, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return true; throw e; }
  if (Date.now() - st.mtimeMs <= STALE_MS) return false;
  const aside = `${f}.${crypto.randomUUID()}`;
  try { fs.renameSync(f, aside); } catch (e) { if (e.code === 'ENOENT') return true; throw e; }
  let moved = null; try { moved = fs.readFileSync(aside, 'utf8'); } catch {}
  if (moved !== seen) { try { fs.linkSync(aside, f); } catch (e) { if (e.code !== 'EEXIST') throw e; } }
  fs.rmSync(aside, { force: true });
  return true;
}
async function withTotpLock(upn, clock, fn) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const f = lockFile(upn);
  const me = `${process.pid}:${crypto.randomUUID()}`;
  const giveUp = clock.now() + 120000;
  for (;;) {
    try { fs.writeFileSync(f, me, { flag: 'wx', mode: 0o600 }); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (recoverStaleLock(f)) continue;
      if (clock.now() > giveUp) throw new Error(`another sign-in for ${upn} holds ${f}`);
      await clock.sleep(200);
    }
  }
  try { return await fn(); } finally {
    try { if (fs.readFileSync(f, 'utf8') === me) fs.rmSync(f, { force: true }); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}
// `clock` is a test seam (a fake now/sleep); callers leave it out.
export async function freshTotp(upn, seed, clock = realClock) {
  return withTotpLock(upn, clock, async () => {
    let last = -1;
    try { last = Number(fs.readFileSync(stepFile(upn), 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    let t = totp(seed, { now: clock.now() });
    // Too close to the end of the window: the code could expire in flight.
    while (t.counter <= last || t.secondsLeft < 4) { await clock.sleep(Math.max(1, t.secondsLeft) * 1000 + 300); t = totp(seed, { now: clock.now() }); }
    markTotpStep(upn, t.counter);
    return t.code;
  });
}

// A strong random password from an alphabet the Keychain writer accepts
// (no quotes, backslashes or spaces) that Entra's complexity rules also accept.
export function randomPassword(len = 28) {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#$%&()*+,-./:;<=>?@[]^_{|}~'];
  const all = sets.join('');
  const pick = (s) => s[crypto.randomInt(s.length)];
  const chars = sets.map(pick);
  while (chars.length < len) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}

// ---- Graph, as the lab operator -------------------------------------------
export function graph(method, url, body) {
  const full = url.startsWith('https://') ? url : `https://graph.microsoft.com/v1.0/${url.replace(/^\//, '')}`;
  const args = ['az', 'rest', '--method', method, '--url', full, '--only-show-errors'];
  let input;
  if (body !== undefined) { args.push('--headers', 'Content-Type=application/json', '--body', '@/dev/stdin'); input = JSON.stringify(body); }
  const out = execFileSync(OP, args, { input, encoding: 'utf8', stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], maxBuffer: 32 << 20 });
  return out.trim() ? JSON.parse(out) : null;
}

// ---- Playwright --------------------------------------------------------------
// The lab's one Playwright install is lab/setup/signup-assist. A git worktree
// has no node_modules, so the main checkout is the fallback.
export function playwright() {
  const cands = [process.env.PLAYWRIGHT_PACKAGE_JSON, path.join(REPO, 'lab/setup/signup-assist/package.json'),
    path.join(os.homedir(), 'contoso-health-identity-lab/lab/setup/signup-assist/package.json')].filter(Boolean);
  for (const c of cands) if (fs.existsSync(path.join(path.dirname(c), 'node_modules', 'playwright'))) return createRequire(c)('playwright');
  throw new Error('Playwright not found: run `npm run setup` in lab/setup/signup-assist');
}

// ---- storage state -------------------------------------------------------------
// One file per local part (~/.contoso-operator/session/browser/<local>.json,
// mode 600). The file records its owner (the full UPN): a file written for a
// same-named user on the other lab domain, a file from before owners were
// recorded, or an unreadable file is ignored, and the sign-in starts clean.
export const statePath = (upn) => path.join(STATE_DIR, `${localPart(upn)}.json`);
export function readOwnedState(upn) {
  let st;
  try { st = JSON.parse(fs.readFileSync(statePath(upn), 'utf8')); } catch { return null; }
  if (!st || typeof st !== 'object' || st.owner !== upn.toLowerCase()) return null;
  return { cookies: st.cookies || [], origins: st.origins || [] };
}
export async function saveState(context, upn) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const f = statePath(upn);
  const st = await context.storageState();
  fs.writeFileSync(f, JSON.stringify({ owner: upn.toLowerCase(), ...st }), { mode: 0o600 });
  fs.chmodSync(f, 0o600);
  return f;
}

// ---- screenshots (secrets blurred first) ---------------------------------------
// A TOTP secret is 16-32 base32 characters, often in groups of four; QR codes
// are images or canvases; password and code fields are inputs. All are blurred
// before any screenshot, so a failure picture can never carry a seed.
const REDACT = `(() => {
  const SEED = /\\b(?:[A-Z2-7]{4}[ ]?){4,}\\b/;
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n;
  while ((n = w.nextNode())) { if (SEED.test(n.nodeValue || '')) { const p = n.parentElement; if (p) p.style.filter = 'blur(10px)'; } }
  for (const e of document.querySelectorAll('canvas, img[src^="data:"], svg[aria-label*="QR" i], [aria-label*="QR code" i] img, input')) e.style.filter = 'blur(10px)';
})()`;
export async function redact(page) {
  for (const f of page.frames()) await f.evaluate(REDACT).catch(() => {});
}
export async function shot(page, name, { redacted = true } = {}) {
  fs.mkdirSync(SHOTS_DIR, { recursive: true });
  const f = path.join(SHOTS_DIR, `${new Date().toISOString().replace(/[:.]/g, '-')}-${name.replace(/[^a-z0-9_.-]/gi, '_')}.png`);
  if (redacted) await redact(page);
  await page.screenshot({ path: f, fullPage: false }).catch(() => {});
  return f;
}
// The visible text of the page and its frames, for decisions and messages.
export async function pageText(page) {
  const parts = await Promise.all(page.frames().map((f) => f.locator('body').innerText({ timeout: 1500 }).catch(() => '')));
  return parts.join('\n');
}
