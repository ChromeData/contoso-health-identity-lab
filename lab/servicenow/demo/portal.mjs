// =============================================================================
// lab/servicenow/demo/portal.mjs - a hospital staff member uses ServiceNow
// through Entra single sign-on, in a real (headless) browser.
//
//   node portal.mjs request <identity> <appChoiceText> <reason> <start> <end> <shotDir>
//        -> prints {"request":"REQ0010xxx"} after "Order Now"
//   node portal.mjs approve <identity> <RITM number> <shotDir>
//        -> the manager opens My Approvals in the portal and clicks Approve
//   node portal.mjs task <identity> <sc_task sys_id> <shotDir>
//        -> the IAM engineer opens a leaver task and clicks "Remove access in Entra"
//   node portal.mjs shot <identity> <path-after-instance> <shotFile>
//        -> signs in and screenshots one page (queue views, reports)
//
// Sign-in is the lab's one sign-in tool (lab/scripts/demo/signin/identity.mjs):
// SP-initiated SAML through the ServiceNow IdP record, Entra checks the person
// and Conditional Access, and ServiceNow lands them in the account Entra
// provisioned. The personas have no authenticator, so each run uses a
// one-time Temporary Access Pass the operator issues and deletes.
// No patient data is typed anywhere.
// =============================================================================
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { signIn } from '../../scripts/demo/signin/identity.mjs';

const SN = process.env.SN_INSTANCE_URL || 'https://dev459905.service-now.com';
// The Entra IdP record on the instance (TF_SERVICENOW_SSO_SYS_ID).
const IDP = process.env.SN_SSO_SYS_ID || 'c5d8b9d49354571025167bfdfaba10b0';
const HERE = path.dirname(fileURLToPath(import.meta.url));

async function session(id) {
  // Signed in = back on the instance, past every login page. The first try
  // reuses this person's saved session (the sign-in tool's per-UPN cookie
  // file), so a run does not issue a new one-time pass for every screen:
  // many passes in a short time is when Entra answered AADSTS90202 most.
  const until = async (p) => p.url().startsWith(SN) && !/login|saml|sso/i.test(new URL(p.url()).pathname);
  let last;
  for (let i = 0; i < 4; i++) {
    try { return await signIn(id, `${SN}/login_with_sso.do?glide_sso_id=${IDP}`, { until, fresh: i > 0 }); }
    catch (e) {
      last = e;
      // AADSTS90202 is Entra's own "transient error, try again" (seen in this
      // lab before, more often right after a pass is issued): wait, then a
      // fresh browser and a fresh pass.
      if (!/AADSTS90202/.test(e.message)) throw e;
      console.error(`[portal] ${id}: AADSTS90202, retry ${i + 1} in 30 s`);
      await new Promise((r) => setTimeout(r, 30000));
    }
  }
  throw last;
}

async function open(page, rel) {
  await page.goto(`${SN}/${rel}`, { waitUntil: 'networkidle', timeout: 90000 });
  await page.waitForTimeout(2500);
}

async function request([id, appText, reason, start, end, shots]) {
  const { page, close } = await session(id);
  try {
    await open(page, 'sp?id=sc_cat_item&sys_id=' + (process.env.SN_ITEM_SYS_ID || ''));
    await page.locator('#s2id_sp_formfield_app_access').click();
    await page.locator('.select2-result-label', { hasText: appText }).first().click();
    await page.locator('#sp_formfield_business_reason').fill(reason);
    for (const [sel, v] of [['#sp_formfield_start_date', start], ['#sp_formfield_end_date', end]]) {
      // Typed key by key: the portal's date field parses on keystrokes;
      // fill() alone left it marked invalid (seen 2026-11-07).
      await page.locator(sel).click();
      await page.locator(sel).pressSequentially(v, { delay: 40 });
      await page.locator('#sp_formfield_business_reason').click();
    }
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(shots, '01-nurse-request-form.png'), fullPage: true });
    await page.locator('#submit-btn').click();
    // The portal's "Order Confirmation" box (Request for: the signed-in person).
    const checkout = page.getByRole('button', { name: /^Checkout$/ });
    await checkout.waitFor({ timeout: 30000 });
    await checkout.click();
    await page.waitForURL(/id=(order_status|ticket|sc_request)/, { timeout: 90000 });
    await page.waitForTimeout(4000);
    await page.screenshot({ path: path.join(shots, '02-nurse-request-submitted.png'), fullPage: true });
    const text = await page.locator('body').innerText();
    const m = text.match(/REQ\d{7}/);
    if (!m) throw new Error('no REQ number on the confirmation page');
    console.log(JSON.stringify({ request: m[0] }));
  } finally { await close(); }
}

async function approve([id, ritmNumber, shots]) {
  // "My Approvals" in the portal: one card per pending approval, with the
  // request's answers under "Options" and Approve / Reject buttons.
  const { page, close } = await session(id);
  try {
    await open(page, 'sp?id=approvals');
    // The smallest element holding both this request's number and an Approve button.
    const card = page.locator(`xpath=//*[contains(normalize-space(.), '${ritmNumber}')][.//button[normalize-space()='Approve']][not(.//*[contains(normalize-space(.), '${ritmNumber}')][.//button[normalize-space()='Approve']])]`).first();
    await card.waitFor({ timeout: 30000 });
    const opts = card.getByText(/Options/).first();
    if (await opts.isVisible().catch(() => false)) { await opts.click(); await page.waitForTimeout(1500); }
    await page.screenshot({ path: path.join(shots, '03-manager-my-approvals.png'), fullPage: true });
    await card.locator("xpath=.//button[normalize-space()='Approve']").first().click();
    await page.waitForTimeout(5000);
    await page.screenshot({ path: path.join(shots, '04-manager-approved.png'), fullPage: true });
    console.log(JSON.stringify({ approved: ritmNumber }));
  } finally { await close(); }
}

async function task([id, taskSysId, shots]) {
  // The IAM engineer's view of a leaver task (classic form, as fulfillers use
  // it) and the "Remove access in Entra" button (UI action, itil only).
  const { page, close } = await session(id);
  try {
    await open(page, `sc_task.do?sys_id=${taskSysId}`);
    await page.screenshot({ path: path.join(shots, '10-iam-leaver-task.png'), fullPage: true });
    await page.locator('#contoso_remove_in_entra, button:has-text("Remove access in Entra")').first().click();
    await page.waitForLoadState('networkidle', { timeout: 90000 }).catch(() => {});
    await page.waitForTimeout(3000);
    await page.screenshot({ path: path.join(shots, '11-iam-leaver-task-sent.png'), fullPage: true });
    console.log(JSON.stringify({ clicked: taskSysId }));
  } finally { await close(); }
}

async function shot([id, rel, file]) {
  const { page, close } = await session(id);
  try {
    await open(page, rel);
    await page.screenshot({ path: file, fullPage: true });
    console.log(JSON.stringify({ shot: file }));
  } finally { await close(); }
}

const [cmd, ...args] = process.argv.slice(2);
const run = { request, approve, task, shot }[cmd];
if (!run) { console.error('usage: portal.mjs request|approve|task|shot ...'); process.exit(2); }
run(args).catch((e) => { console.error(e.message); process.exit(1); });
