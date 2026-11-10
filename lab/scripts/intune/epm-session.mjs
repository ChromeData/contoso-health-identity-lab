// =============================================================================
// epm-session.mjs - the Intune EPM proof's desktop session on CH-WIN11-01,
// through Azure Bastion (run after lab/bastion/capture.sh up)
//
//   node lab/scripts/intune/epm-session.mjs --out DIR [--port 8765]
//
// The portal identity is adm-presenter (Reader through its existing
// PIM-Demo-Readers eligibility: the transport only). The WINDOWS sign-in is the
// local STANDARD account epm-standard; its password goes from the Keychain
// item contoso-lab-epm-standard straight into Bastion's password box (never
// printed, logged or put on a command line).
//
// The remote desktop is a canvas: no DOM to script. So after connecting the
// script waits for one command at a time on 127.0.0.1:<port> and answers with
// a screenshot name. The operator looks at each screenshot and picks the next
// click (headless, the Windows key does not reach the session; right-click
// and typing do):
//   GET /shot?name=N            raw screenshot of the session
//   GET /click?x=&y=[&button=right][&double=1]
//   GET /type?text=...          GET /key?k=Enter     GET /mark?what=...
//   GET /close                  ends the session (Bastion uploads the recording)
// Loopback is not private on a shared Mac (any local OS user can connect), so
// every request must carry a random per-run token, written only to
// DIR/.control-header (mode 0600, never printed or put on a command line):
//   curl -H @DIR/.control-header 'http://127.0.0.1:8765/shot?name=x'
// Every step is written to DIR/session.json with a UTC time; the browser
// records a video (Playwright recordVideo).
// =============================================================================
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { signIn, activatePim } from '../demo/signin/identity.mjs';
import { pageText, sleep, playwright, keychainRead, redact, passwordFor, seedFor, freshTotp } from '../demo/signin/lib.mjs';
// /typesecret types an Entra test user's password or a fresh authenticator
// code, read from the Keychain in this process (never in a URL, log or argv).
const TYPE_SECRET_USERS = { 'test-user-a': 'test-user-a@contosohealthlab.com' };

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const OUT = path.resolve(opt('--out', 'epm-session'));
const PORT = Number(opt('--port', '8765'));
fs.mkdirSync(OUT, { recursive: true });

const SUB = 'de0b2a93-1c62-47b3-aaaf-1bdd1939a274';
const VM_ID = `/subscriptions/${SUB}/resourceGroups/rg-identity-lab/providers/Microsoft.Compute/virtualMachines/vm-win11-01`;
const portal = (id, blade = '') => `https://portal.azure.com/#@contosohealthlab.onmicrosoft.com/resource${id}${blade}`;
const WIN_USER = 'epm-standard'; // Bastion sends 'HOST\\user' as one user name (4625 0xc0000064)
const SECRET = { service: 'contoso-lab-epm-standard', account: 'epm-standard' };

const T0 = Date.now();
const rec = { started: new Date().toISOString(), steps: [] };
const mark = (what, extra = {}) => {
  const r = { what, utc: new Date().toISOString(), t_s: Math.round((Date.now() - T0) / 1000), ...extra };
  rec.steps.push(r); console.log(JSON.stringify(r));
  fs.writeFileSync(path.join(OUT, 'session.json'), JSON.stringify(rec, null, 1));
};
async function inFrames(page, fn) { for (const f of page.frames()) { const r = await fn(f).catch(() => null); if (r) return r; } return null; }
const visible = (page, mk) => inFrames(page, async (f) => { const l = mk(f).first(); return (await l.isVisible()) ? l : null; });

const browser = await playwright().chromium.launch({ headless: !process.env.HEADED });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US', recordVideo: { dir: path.join(OUT, 'video'), size: { width: 1440, height: 900 } } });
let sess = null;
try {
  const { page } = await signIn('adm-presenter', 'https://portal.azure.com/', { context: ctx });
  mark('adm-presenter signed in to the Azure portal (transport identity)');
  await activatePim('adm-presenter', 'PIM-Demo-Readers', 1, 'CHG: Intune EPM proof - Bastion session to CH-WIN11-01 as a local standard user (ADR 0036)', { context: ctx, page });
  mark('PIM-Demo-Readers active for adm-presenter (Reader on the subscription)');
  let form = null;
  for (let i = 0; i < 40 && !form; i++) {
    await page.goto(portal(VM_ID, '/bastionHost'), { waitUntil: 'domcontentloaded' });
    await sleep(12000);
    form = await visible(page, (f) => f.getByRole('textbox', { name: /^Username/i }));
  }
  if (!form) throw new Error('the Bastion connect form never appeared for vm-win11-01');
  await redact(page).catch(() => {});
  await page.screenshot({ path: path.join(OUT, '00-bastion-form.png') });
  await form.fill(WIN_USER);
  const pw = await visible(page, (f) => f.locator('input[type="password"]'));
  if (!pw) throw new Error('no password box');
  await pw.fill(keychainRead(SECRET.service, SECRET.account));
  const connect = await visible(page, (f) => f.getByRole('button', { name: /^Connect$/ }));
  [sess] = await Promise.all([ctx.waitForEvent('page', { timeout: 60000 }), connect.click()]);
  mark('Connect clicked: Bastion session to CH-WIN11-01 as CH-WIN11-01\\epm-standard', { session_started_utc: new Date().toISOString() });
  await sess.waitForLoadState('domcontentloaded');
  await sleep(45000);
  await sess.screenshot({ path: path.join(OUT, '01-session.png') });
  mark('session page after 45 s', { shot: '01-session.png', host: new URL(sess.url()).host, text: (await pageText(sess).catch(() => '')).replace(/\s+/g, ' ').slice(0, 200) });
} catch (e) {
  mark('FAILED', { error: String(e.message || e).slice(0, 500) });
  await browser.close(); process.exit(1);
}

// Per-run control token: only the operator (who can read DIR) can drive the
// desktop or make it type a Keychain secret. The file is created 0600 before
// the token is written, and removed when the session closes.
const TOKEN = crypto.randomBytes(32).toString('hex');
const TOKEN_FILE = path.join(OUT, '.control-header');
fs.rmSync(TOKEN_FILE, { force: true });
fs.writeFileSync(TOKEN_FILE, `X-Session-Token: ${TOKEN}\n`, { mode: 0o600, flag: 'wx' });
const authorized = (req) => {
  const got = Buffer.from(String(req.headers['x-session-token'] || ''));
  const want = Buffer.from(TOKEN);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
};

let n = 2;
const server = http.createServer(async (req, res) => {
  if (!authorized(req)) { res.statusCode = 401; res.end('missing or wrong X-Session-Token\n'); return; }
  const u = new URL(req.url, 'http://x'); const q = (k) => u.searchParams.get(k);
  try {
    if (u.pathname === '/click') {
      const o = { button: q('button') || 'left' };
      if (q('double')) await sess.mouse.dblclick(Number(q('x')), Number(q('y')), o); else await sess.mouse.click(Number(q('x')), Number(q('y')), o);
    } else if (u.pathname === '/type') await sess.keyboard.type(q('text') || '', { delay: 70 });
    else if (u.pathname === '/key') await sess.keyboard.press(q('k'));
    else if (u.pathname === '/typesecret') {
      const upn = TYPE_SECRET_USERS[q('id')]; if (!upn) throw new Error('unknown id');
      const v = q('what') === 'totp' ? await freshTotp(upn, seedFor(upn)) : (passwordFor(upn) || {}).value;
      if (!v) throw new Error('no secret in the Keychain');
      await sess.keyboard.type(v, { delay: 70 });
      rec.steps.push({ what: `typed ${q('what') === 'totp' ? 'authenticator code' : 'password'} of ${q('id')} from the Keychain`, utc: new Date().toISOString() });
    }
    else if (u.pathname === '/mark') { mark(q('what') || ''); }
    else if (u.pathname === '/close') {
      mark('session tab closed'); fs.rmSync(TOKEN_FILE, { force: true });
      await sess.close(); await ctx.close(); await browser.close();
      res.end('closed\n'); server.close(); return;
    }
    await sleep(Number(q('wait') || 2500));
    const name = `${String(n++).padStart(2, '0')}-${q('name') || u.pathname.slice(1)}.png`;
    await sess.screenshot({ path: path.join(OUT, name) });
    if (u.pathname !== '/shot' && u.pathname !== '/mark') rec.steps.push({ what: `${u.pathname} ${u.search}`, utc: new Date().toISOString(), shot: name });
    fs.writeFileSync(path.join(OUT, 'session.json'), JSON.stringify(rec, null, 1));
    res.end(path.join(OUT, name) + '\n');
  } catch (e) { res.statusCode = 500; res.end(String(e.message || e) + '\n'); }
});
server.listen(PORT, '127.0.0.1', () => console.log(`READY on 127.0.0.1:${PORT} (send -H @${TOKEN_FILE})`));
