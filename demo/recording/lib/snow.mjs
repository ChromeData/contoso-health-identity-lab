// ServiceNow in the recording browser.
//
// Admin view (the user list that shows the accounts Entra provisioning
// created): ServiceNow's local web login now works only for the account-
// recovery user acr.breakglass (slice 2, capture-log E80; `admin` is API-only).
// The cockpit signs that account into the recording browser itself, as a
// SETUP step before recording: password and authenticator seed are read from
// the login Keychain inside this process (contoso-lab-servicenow-acr and
// contoso-lab-servicenow-acr-totp, account acr.breakglass), the code is
// computed here, both are put straight into the page's fields (no typing
// animation; the code box is masked first) and dropped. Neither is shown,
// logged or put on a command line.
//
// Never the owner's account: the cockpit only ever goes to login.do for this
// one user, and before it shows any ServiceNow page it checks who the
// ServiceNow session belongs to (current_user) and refuses anyone but
// acr.breakglass.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

export const SNOW = 'https://dev459905.service-now.com';
const ACR = 'acr.breakglass';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function keychain(service, account) {
  try { return execFileSync('security', ['find-generic-password', '-s', service, '-a', account, '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).replace(/\n$/, ''); }
  catch { throw new Error(`Keychain item ${service} (${account}) could not be read (locked or missing)`); }
}

// RFC 6238 TOTP (SHA-1, 30 s, 6 digits); checked against the RFC test vector
// in tools/check-steps.mjs.
export function totp(secretB32, now = Date.now()) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(secretB32).replace(/[\s=-]/g, '').toUpperCase();
  let bits = 0, val = 0; const bytes = [];
  for (const ch of clean) { const i = A.indexOf(ch); if (i < 0) throw new Error('authenticator seed is not base32'); val = (val << 5) | i; bits += 5; if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 0xff); bits -= 8; } }
  const counter = Math.floor(now / 30000);
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', Buffer.from(bytes)).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  return { code: String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'), secondsLeft: 30 - Math.floor(now / 1000) % 30 };
}

// Who is the ServiceNow session in this browser context? null = nobody.
// Asked from a scratch tab on login.do (ServiceNow's own form: it never
// starts single sign-on, so it can't sign anyone in by accident).
export async function snowUser(context) {
  const page = await context.newPage();
  try {
    await page.goto(`${SNOW}/login.do`, { waitUntil: 'domcontentloaded', timeout: 60000 });
    if (!/service-now\.com/.test(page.url())) return null;
    // The page's own user object. An account-recovery session shows as
    // "acr.breakglass@ACR" (role acr_admin); a signed-out page as guest.
    const id = await page.evaluate(() => (window.NOW && window.NOW.user && window.NOW.user.userID) || (window.g_user && window.g_user.userName) || null);
    // A signed-out page belongs to ServiceNow's built-in guest user, which some
    // pages report by its sys_id (5136503cc611227c0183e96598c4f706 on every
    // instance) instead of its name: both mean "nobody". Seen 2026-11-05 after
    // the recovery session timed out.
    const name = id ? String(id).replace(/@ACR$/i, '') : null;
    if (!name || name === 'guest' || /^[0-9a-f]{32}$/i.test(name)) return null;
    return name;
  } finally { await page.close().catch(() => {}); }
}

// Sign acr.breakglass in at login.do (local login + authenticator code).
export async function signInRecovery(page, { log = console.log } = {}) {
  const who = await snowUser(page.context());
  if (who === ACR) return 'already signed in';
  if (who) throw new Error(`the recording browser's ServiceNow session belongs to ${who}, not ${ACR}: sign it out first`);
  await page.goto(`${SNOW}/login.do`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  if (!/service-now\.com\/login\.do/.test(page.url())) throw new Error(`login.do went to ${new URL(page.url()).host} instead of ServiceNow's own login form`);
  await page.locator('#user_name').waitFor({ timeout: 20000 });
  let pw = keychain('contoso-lab-servicenow-acr', ACR);
  try {
    await page.locator('#user_name').fill(ACR);
    await page.locator('#user_password').fill(pw);
  } finally { pw = null; }
  await page.locator('#sysverb_login').click();
  // The authenticator page (validate_multifactor_auth_code.do).
  const box = page.locator('input#txtResponse, input[name="txtResponse"], input[autocomplete="one-time-code"], input[type="number"]').first();
  await box.waitFor({ timeout: 30000 });
  await box.evaluate((el) => { el.style.webkitTextSecurity = 'disc'; el.setAttribute('autocomplete', 'off'); });
  let seed = keychain('contoso-lab-servicenow-acr-totp', ACR);
  try {
    let t = totp(seed);
    if (t.secondsLeft < 4) { await sleep((t.secondsLeft + 1) * 1000); t = totp(seed); }
    await box.fill(t.code);
  } finally { seed = null; }
  await box.press('Enter');
  for (let k = 0; k < 30; k++) {
    await sleep(1000);
    if ((await snowUser(page.context())) === ACR) { log('ServiceNow: recovery account signed in to the recording browser (setup)'); return 'signed in'; }
  }
  throw new Error('ServiceNow did not accept the recovery sign-in (wrong or reused code? try again in 30 s)');
}

// The user list filtered to the accounts Entra provisioning created, newest first.
export const PROVISIONED_USERS = `${SNOW}/sys_user_list.do?sysparm_query=${encodeURIComponent('sys_created_by=svc-entra-provisioning^ORDERBYDESCsys_created_on')}`;

// The reset's ServiceNow delete, as the instance admin (Keychain item
// contoso-lab-servicenow-admin, account "admin"; the lead's instruction of
// 2026-11-06): the recovery account can't see inactive users. Table API with
// basic auth, the secret read in-process and never logged or put in argv.
// Only the hire's exact user_name, only records Entra provisioning created,
// and read back afterwards.
export async function deleteProvisionedUserAsAdmin(upn, { dry = false, log = console.log } = {}) {
  // Sam, or a v2 preview's test hire (test.<name>@...; lib/engine.mjs initV2).
  if (!/^(sam\.rivera|test\.[a-z]+)@contosohealthlab\.com$/i.test(upn)) throw new Error(`refusing to delete ${upn}: only the preview's test hire`);
  let pw = keychain('contoso-lab-servicenow-admin', 'admin');
  const auth = `Basic ${Buffer.from(`admin:${pw}`).toString('base64')}`; pw = null;
  const api = async (method, url) => { const r = await fetch(`${SNOW}${url}`, { method, headers: { Accept: 'application/json', Authorization: auth } }); return { status: r.status, body: r.status === 204 ? null : await r.json().catch(() => null) }; };
  const q = encodeURIComponent(`user_name=${upn}`);
  const found = await api('GET', `/api/now/table/sys_user?sysparm_query=${q}&sysparm_fields=sys_id,user_name,active,sys_created_by`);
  if (found.status !== 200) throw new Error(`ServiceNow user read as admin answered ${found.status}`);
  const rows = (found.body?.result || []).filter((r) => r.user_name.toLowerCase() === upn.toLowerCase());
  if (!rows.length) return `no ServiceNow user ${upn} (read as admin, inactive users included)`;
  if (rows.some((r) => r.sys_created_by !== 'svc-entra-provisioning')) throw new Error(`a ServiceNow user ${upn} was not created by Entra provisioning: left alone`);
  if (dry) return `dry run: would delete ${rows.length} ServiceNow user(s) ${upn} (active ${rows.map((r) => r.active).join(',')})`;
  for (const r of rows) {
    const d = await api('DELETE', `/api/now/table/sys_user/${r.sys_id}`);
    if (d.status !== 204 && d.status !== 200) throw new Error(`ServiceNow refused the delete (${d.status})`);
  }
  const again = await api('GET', `/api/now/table/sys_user?sysparm_query=${q}&sysparm_fields=sys_id`);
  if ((again.body?.result || []).length) throw new Error('the ServiceNow user is still there after the delete');
  log(`teardown: ServiceNow user ${upn} deleted as admin (${rows.length}); read back: none`);
  return `deleted ${rows.length} ServiceNow user(s) as admin, read back: none`;
}

// The reset (preview 2 review): Entra's leaver only switches Sam's ServiceNow
// account off, so the next take's provisioning "updates" the old record
// instead of creating one. This deletes the test hire's record, as the
// recovery account, through ServiceNow's Table API from its own signed-in
// page (session token g_ck; no password in any request). Only records that
// Entra provisioning created (sys_created_by = svc-entra-provisioning) and
// whose user name or email is exactly the hire's are touched.
export async function deleteProvisionedUser(context, upn, { dry = false, log = console.log } = {}) {
  if (!/^sam\.rivera@contosohealthlab\.com$/i.test(upn)) throw new Error(`refusing to delete ${upn}: only the preview's test hire`);
  const page = await context.newPage();
  try {
    await signInRecovery(page, { log });
    await page.goto(`${SNOW}/sys_user_list.do`, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const api = (method, url) => page.evaluate(async ({ method, url }) => {
      const r = await fetch(url, { method, headers: { Accept: 'application/json', 'X-UserToken': window.g_ck } });
      return { status: r.status, body: r.status === 204 ? null : await r.json().catch(() => null) };
    }, { method, url });
    const local = upn.split('@')[0];
    const q = encodeURIComponent(`user_name=${upn}^ORuser_name=${local}^ORemail=${upn}`);
    const found = await api('GET', `/api/now/table/sys_user?sysparm_query=${q}&sysparm_fields=sys_id,user_name,email,sys_created_by,active`);
    if (found.status !== 200) throw new Error(`ServiceNow user read answered ${found.status}`);
    const rows = found.body?.result || [];
    // ServiceNow's "user query" business rule hides INACTIVE users from
    // accounts without admin/user_admin (the recovery account has neither),
    // and the leaver has just made Sam inactive: an empty answer proves
    // nothing (seen 2026-11-06). Said so, not reported as deleted.
    if (!rows.length) throw new Error(`the recovery account sees no ServiceNow user for ${upn}; ServiceNow hides inactive users from accounts without the user_admin or admin role, so the record (deactivated by the leaver) may still be there: delete it as a user_admin`);
    const theirs = rows.filter((r) => r.sys_created_by === 'svc-entra-provisioning');
    if (theirs.length !== rows.length) throw new Error(`a ServiceNow record for ${upn} was not created by Entra provisioning: left alone, check by hand`);
    if (dry) return `dry run: would delete ${rows.length} ServiceNow record(s) (${rows.map((r) => `${r.user_name}, active ${r.active}`).join('; ')})`;
    for (const r of theirs) {
      const d = await api('DELETE', `/api/now/table/sys_user/${r.sys_id}`);
      if (d.status !== 204 && d.status !== 200) throw new Error(`ServiceNow refused the delete (${d.status}${d.status === 403 ? ': the recovery account lacks delete on sys_user' : ''})`);
    }
    const again = await api('GET', `/api/now/table/sys_user?sysparm_query=${q}&sysparm_fields=sys_id`);
    if ((again.body?.result || []).length) throw new Error('the ServiceNow record is still there after the delete');
    log(`teardown: ServiceNow record(s) for ${upn} deleted (${theirs.length}); read back: none`);
    return `deleted ${theirs.length} ServiceNow record(s), read back: none`;
  } finally { await page.close().catch(() => {}); }
}
