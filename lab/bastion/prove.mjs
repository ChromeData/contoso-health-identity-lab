// =============================================================================
// prove.mjs - the Bastion proof, as the two admins (run after capture.sh up)
//
//   node lab/bastion/prove.mjs [--out DIR] [--step all|before|activate|connect|playback]
//
// What it proves, each step with a screenshot and a UTC time (out/proof.json):
//   1. before   adm-ava.lin opens DC01 in the Azure portal: "You don't have
//               access" (403). She holds no Azure role.
//   2. activate She activates her PIM-eligible Reader on rg-identity-lab in the
//               Entra admin center (My roles > Azure resources), 1 hour, with a
//               reason. Read back: the row under Active assignments.
//   3. connect  DC01's Bastion page now opens. She connects with DC01's
//               domain admin account (the password comes from the Keychain
//               straight into the browser's password box; never printed or
//               logged), tries to run `whoami & hostname` in the session,
//               and closes it. Bastion records the whole session.
//   4. playback adm-mei.tanaka (the reviewer, time-bound Storage Blob Data
//               Reader) opens the Bastion's Session recordings and plays the
//               recording in the portal's player. The admin who was recorded
//               has no access to the recordings.
// Every browser context records a video (Playwright recordVideo) for the
// script writers; screenshots blur inputs (lib.mjs redact).
//
// WHY the portal and not the native client: Learn, "Record Bastion sessions":
// "Session recording isn't available via native client at this time." The
// capture's Bastion has tunnelling OFF, so the only way in is recorded.
// WHY a password and not Entra sign-in to the VM: Learn says Entra ID RDP in
// the portal "can't be used concurrently with graphical session recording".
// =============================================================================
import fs from 'node:fs';
import path from 'node:path';
import { signIn } from '../scripts/demo/signin/identity.mjs';
import { pageText, sleep, playwright, keychainRead, redact } from '../scripts/demo/signin/lib.mjs';

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const OUT = path.resolve(opt('--out', 'bastion-proof'));
const STEP = opt('--step', 'all');
fs.mkdirSync(OUT, { recursive: true });

const SUB = 'de0b2a93-1c62-47b3-aaaf-1bdd1939a274';
const TENANT_DOMAIN = 'contosohealthlab.onmicrosoft.com';
const RG = 'rg-identity-lab';
const VM_ID = `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachines/vm-dc01`;
const BASTION_ID = `/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Network/bastionHosts/bastion-capture`;
const portal = (id, blade = '') => `https://portal.azure.com/#@${TENANT_DOMAIN}/resource${id}${blade}`;
const PIM_AZURE = 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/azurerbac';
const DC_USER = 'contosoadmin';
const DC_SECRET = { service: 'contoso-lab-dc01-admin', account: 'contosoadmin' };
const REASON = 'CHG: Bastion capture - Tier-0 session on DC01, recorded (lab/bastion)';

const T0 = Date.now();
const proof = { started: new Date().toISOString(), steps: [] };
const mark = (step, what, extra = {}) => {
  const r = { step, what, utc: new Date().toISOString(), t_s: Math.round((Date.now() - T0) / 1000), ...extra };
  proof.steps.push(r); console.log(JSON.stringify(r));
  fs.writeFileSync(path.join(OUT, 'proof.json'), JSON.stringify(proof, null, 1));
};
const snap = async (page, name) => { await redact(page).catch(() => {}); const f = path.join(OUT, `${name}.png`); await page.screenshot({ path: f }); return path.basename(f); };
const text = async (page) => (await pageText(page)).replace(/\s+/g, ' ');
async function inFrames(page, fn) {
  for (const f of page.frames()) { const r = await fn(f).catch(() => null); if (r) return r; }
  return null;
}
const visible = (page, mk) => inFrames(page, async (f) => { const l = mk(f).first(); return (await l.isVisible()) ? l : null; });
async function waitFor(page, re, ms = 60000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (re.test(await text(page))) return true; await sleep(2000); }
  return false;
}

const browser = await playwright().chromium.launch({ headless: process.env.HEADED ? false : true });
const ctxFor = async (who) => browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US', recordVideo: { dir: path.join(OUT, `video-${who}`), size: { width: 1440, height: 900 } } });

try {
  const ava = await ctxFor('admin');
  const { page } = await signIn('adm-ava.lin', 'https://portal.azure.com/', { context: ava });
  mark('signin', 'adm-ava.lin signed in to the Azure portal (passkey)');

  // ---- 1. before ------------------------------------------------------------
  if (STEP === 'all' || STEP === 'before') {
    await page.goto(portal(VM_ID, '/bastionHost'), { waitUntil: 'domcontentloaded' });
    const denied = await waitFor(page, /You don't have access|No access/i, 45000);
    mark('before', denied ? 'DC01 Bastion page: "You don\'t have access" (403) before PIM' : 'NOT DENIED before PIM', { ok: denied, shot: await snap(page, '01-before-pim-no-access') });
    if (!denied) throw new Error('the admin could open DC01 before activating PIM: the proof is void');
  }

  // ---- 2. activate ----------------------------------------------------------
  if (STEP === 'all' || STEP === 'activate') {
    await page.goto(PIM_AZURE, { waitUntil: 'domcontentloaded' });
    let row = null;
    for (let i = 0; i < 30 && !row; i++) {
      row = await visible(page, (f) => f.getByRole('row').filter({ hasText: 'Reader' }).filter({ hasText: RG }));
      if (!row) await sleep(2000);
    }
    if (!row) throw new Error(`no eligible Reader on ${RG} on the PIM page`);
    mark('activate', 'PIM My roles > Azure resources: eligible Reader on rg-identity-lab', { shot: await snap(page, '02-pim-eligible') });
    await row.getByRole('button', { name: /^Activate$/ }).or(row.getByRole('link', { name: /^Activate$/ })).first().click();
    await sleep(5000);
    const dur = await visible(page, (f) => f.locator('input[aria-label*="slider value" i], input[aria-label*="Duration" i], input[type="number"]'));
    if (dur) { await dur.fill('1'); await dur.press('Tab').catch(() => {}); }
    const got = dur ? Number(await dur.inputValue().catch(() => NaN)) : NaN;
    if (got !== 1) throw new Error(`the activation blade took ${got} hours, not 1: not activating`);
    const why = await visible(page, (f) => f.locator('textarea'));
    if (!why) throw new Error('no justification box');
    await why.fill(REASON);
    mark('activate', 'activation request: 1 hour, reason given', { shot: await snap(page, '03-pim-request') });
    const go = await visible(page, (f) => f.getByRole('button', { name: /^Activate$/ }).last());
    await go.click();
    const tReq = Date.now();
    let active = false;
    for (let i = 0; i < 60 && !active; i++) {
      await sleep(3000);
      const t = await text(page);
      if (/pending approval/i.test(t)) throw new Error('activation needs approval (policy changed?)');
      if (i % 4 === 3) {
        const tab = await visible(page, (f) => f.getByRole('tab', { name: /Active assignments/i }));
        if (tab) {
          await tab.click().catch(() => {}); await sleep(3000);
          const a = await visible(page, (f) => f.getByRole('row').filter({ hasText: 'Reader' }).filter({ hasText: RG }));
          active = !!(a && /Deactivate|Extend/i.test(await a.innerText().catch(() => '')));
        }
      }
    }
    if (!active) throw new Error('no active Reader row after activating');
    mark('activate', 'PIM: Reader on rg-identity-lab ACTIVE (Active assignments row, Deactivate)', { activation_s: Math.round((Date.now() - tReq) / 1000), shot: await snap(page, '04-pim-active') });
  }

  // ---- 3. connect -----------------------------------------------------------
  if (STEP === 'all' || STEP === 'connect') {
    const tWait = Date.now();
    let form = null;
    for (let i = 0; i < 40 && !form; i++) {
      await page.goto(portal(VM_ID, '/bastionHost'), { waitUntil: 'domcontentloaded' });
      await sleep(12000);
      form = await visible(page, (f) => f.getByRole('textbox', { name: /^Username/i }));
      if (!form && /You don't have access/i.test(await text(page))) await sleep(8000);
    }
    if (!form) throw new Error('the Bastion connect form never appeared after activation');
    mark('connect', 'DC01 Bastion page opens after activation', { rbac_wait_s: Math.round((Date.now() - tWait) / 1000), shot: await snap(page, '05-bastion-form') });
    await form.fill(DC_USER);
    const pw = await visible(page, (f) => f.locator('input[type="password"]'));
    if (!pw) throw new Error('no password box on the Bastion form');
    const secret = keychainRead(DC_SECRET.service, DC_SECRET.account);
    await pw.fill(secret);
    // Open in a new tab (the default): the session page is a separate page.
    const connect = await visible(page, (f) => f.getByRole('button', { name: /^Connect$/ }));
    const [sess] = await Promise.all([ava.waitForEvent('page', { timeout: 60000 }), connect.click()]);
    const tConn = Date.now();
    await sess.waitForLoadState('domcontentloaded');
    // The RDP desktop is a canvas; give Windows time to log on and draw.
    await sleep(45000);
    mark('connect', 'session open on DC01 through Bastion (browser, recorded)', { host: new URL(sess.url()).host, connect_s: Math.round((Date.now() - tConn) / 1000), shot: await snap(sess, '06-session-desktop') });
    // The Windows key does not reach the session from a headless browser
    // (2026-11-07 run: Meta+R opened Server Manager's Help menu instead of
    // Run). So click the taskbar's "Type here to search" box (bottom-left of
    // the 1440x900 session, seen in the recording) and type there.
    // verify: next run (this path has not run yet).
    const svp = sess.viewportSize() || { width: 1440, height: 900 };
    await sess.mouse.click(140, svp.height - 20);
    await sleep(3000);
    await sess.keyboard.type('cmd', { delay: 80 }); await sleep(2000); await sess.keyboard.press('Enter');
    await sleep(5000);
    await sess.keyboard.type('whoami & hostname', { delay: 80 }); await sess.keyboard.press('Enter');
    await sleep(5000);
    mark('connect', 'keystrokes sent: whoami & hostname (check the recording: the 2026-11-07 run did not reach a prompt)', { shot: await snap(sess, '07-session-whoami') });
    await sleep(10000);
    await sess.close();
    mark('connect', 'session tab closed: the session ends and Bastion uploads the recording', { session_s: Math.round((Date.now() - tConn) / 1000) });
  }
  await ava.close();

  // ---- 4. playback ----------------------------------------------------------
  if (STEP === 'all' || STEP === 'playback') {
    const mei = await ctxFor('reviewer');
    const r = await signIn('adm-mei.tanaka', 'https://portal.azure.com/', { context: mei });
    const p = r.page;
    let link = null; const tList = Date.now();
    for (let i = 0; i < 30 && !link; i++) {
      // No deep link: '/sessionRecordings' falls back to Overview (seen live
      // 2026-11-07). Open Settings in the resource menu, then the blade.
      await p.goto(portal(BASTION_ID), { waitUntil: 'domcontentloaded' });
      await sleep(10000);
      const menu = await visible(p, (f) => f.getByRole('treeitem', { name: /^Session recordings/i }).or(f.getByRole('link', { name: /^Session recordings/i })));
      if (!menu) {
        const settings = await visible(p, (f) => f.getByRole('treeitem', { name: /^Settings$/ }).or(f.getByText('Settings', { exact: true })));
        if (settings) { await settings.click(); await sleep(2000); }
      }
      const item = menu || await visible(p, (f) => f.getByRole('treeitem', { name: /^Session recordings/i }).or(f.getByText('Session recordings', { exact: true })));
      if (item) { await item.click(); await sleep(12000); }
      link = await visible(p, (f) => f.getByRole('button', { name: /View recording/i }).or(f.getByRole('link', { name: /View recording/i })));
    }
    mark('playback', link ? 'Session recordings lists the DC01 session' : 'NO recording listed', { ok: !!link, list_wait_s: Math.round((Date.now() - tList) / 1000), shot: await snap(p, '08-recordings-list') });
    if (!link) throw new Error('no recording listed');
    // "View recording" opens the player in a NEW TAB (seen live 2026-11-07:
    // the list page itself does not change). Fall back to the same page.
    const [pop] = await Promise.all([mei.waitForEvent('page', { timeout: 20000 }).catch(() => null), link.click()]);
    const player = pop || p;
    if (pop) await pop.waitForLoadState('domcontentloaded').catch(() => {});
    await sleep(20000);
    // No redaction here: the player shows the recorded desktop, never a secret box.
    const raw = async (pg, name) => { const f = path.join(OUT, `${name}.png`); await pg.screenshot({ path: f }); return path.basename(f); };
    // The player opens paused at 0:00 with a play button bottom-left and a
    // seek bar along the bottom (seen live 2026-11-07). Press play, then jump
    // to about three quarters in, where the admin typed `whoami & hostname`.
    const vp = player.viewportSize() || { width: 1440, height: 900 };
    const play = await visible(player, (f) => f.getByRole('button', { name: /play/i }));
    if (play) await play.click(); else await player.mouse.click(33, vp.height - 32);
    await sleep(15000);
    mark('playback', 'recording playing in the portal player', { host: new URL(player.url()).host, new_tab: !!pop, shot: await raw(player, '09-playback-start') });
    await player.mouse.click(Math.round(25 + (vp.width - 50) * 0.75), vp.height - 62);
    await sleep(6000);
    mark('playback', 'playback at about 75% (the whoami step)', { shot: await raw(player, '10-playback-whoami') });
    await sleep(15000);
    mark('playback', 'playback near the end', { shot: await raw(player, '11-playback-end') });
    await mei.close();
  }
  proof.ok = true;
} catch (err) {
  proof.ok = false; proof.error = String(err.message || err).slice(0, 600);
  console.error('FAILED:', proof.error);
  process.exitCode = 1;
} finally {
  fs.writeFileSync(path.join(OUT, 'proof.json'), JSON.stringify(proof, null, 1));
  await browser.close();
}
