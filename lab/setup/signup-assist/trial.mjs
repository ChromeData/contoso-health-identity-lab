// Start a trial from the Microsoft 365 admin center catalog, signed in via the saved profile.
//   node trial.mjs "<search text>" "<offer name as in 'View details for X'>" [--go] [--headed]
// Without --go it stops on the details page and lists the buttons (discovery).
import { chromium } from 'playwright';
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const [search, offer] = process.argv.slice(2);
const GO = process.argv.includes('--go'), HEADED = process.argv.includes('--headed');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
fs.mkdirSync(path.join(HERE, 'shots'), { recursive: true });
const shot = async (page, tag) => { const f = path.join(HERE, 'shots', `trial-${tag}-${Date.now()}.png`); await page.screenshot({ path: f }); console.log('shot:', f); };
const buttons = async (page) => page.locator('button:visible, a:visible, [role=button]:visible').evaluateAll((els) => els.map((el) => ({ text: (el.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 70), aria: el.getAttribute('aria-label') || '', auto: el.getAttribute('data-automation-id') || '' })).filter((b) => b.text || b.aria));

const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), { headless: !HEADED, viewport: { width: 1400, height: 950 }, args: ['--disable-blink-features=AutomationControlled'] });
const page = ctx.pages()[0] || (await ctx.newPage());
try {
  await page.goto('https://admin.cloud.microsoft/?#/catalog', { waitUntil: 'domcontentloaded' });
  const box = page.getByRole('searchbox', { name: /Search all product categories/i });
  await box.waitFor({ timeout: 40000 });
  await box.fill(search); await box.press('Enter');
  let cards = [], want = null;
  for (let t = 0; t < 10 && !want; t++) {   // the catalog search is async: poll up to ~30 s for the exact card
    await sleep(3000);
    cards = (await buttons(page)).filter((b) => /View details for/i.test(b.aria)).map((b) => b.aria.replace(/[\u200e\u200f]/g, ''));
    want = cards.find((c) => c.toLowerCase() === `view details for ${offer.toLowerCase()}`);  // exact only
    if (!want && t === 4) { await box.fill(''); await box.fill(search); await box.press('Enter'); }
  }
  await shot(page, 'search');
  console.log('offers found:', cards.join(' | '));
  if (!want) { console.log('OFFER NOT FOUND'); await ctx.close(); process.exit(3); }
  console.log('opening:', want);
  await page.locator(`button[aria-label]`).filter({ has: page.locator(':scope') }).evaluateAll(() => 0); // no-op keeps locator warm
  const btn = page.locator('button[aria-label]').filter({ hasText: /Details/ }).filter({ has: page.locator(':scope') });
  const all = page.locator('button[aria-label]');
  const n = await all.count(); let clicked = false;
  for (let i = 0; i < n; i++) { const a = ((await all.nth(i).getAttribute('aria-label')) || '').replace(/[‎‏]/g, ''); if (a === want) { await all.nth(i).click(); clicked = true; break; } }
  if (!clicked) { console.log('could not click details'); await ctx.close(); process.exit(3); }
  await sleep(5000); await shot(page, 'details');
  const bs = await buttons(page);
  console.log('buttons on details page:'); for (const b of bs) if (/trial|try|buy|start|confirm|next|place order|get started|cancel|close/i.test(b.text + b.aria)) console.log(`   "${b.text}" ${b.aria ? 'aria=' + b.aria : ''} ${b.auto ? 'auto=' + b.auto : ''}`);
  if (!GO) { await ctx.close(); process.exit(0); }
  // --go: Start free trial → confirm chain
  const clickText = async (re) => { try { const b = page.locator('button:visible, a:visible, [role=button]:visible').filter({ hasText: re }).first(); if (await b.count()) { const t = (await b.innerText()).trim(); if (await b.isDisabled().catch(() => false)) { console.log('disabled (waiting):', t); return 'disabled'; } console.log('click:', t); await b.click({ timeout: 8000 }); return true; } } catch (e) { console.log('click skipped:', e.message.split('\n')[0]); } return false; };
  if (!(await clickText(/start free trial|free trial/i))) { console.log('no Start free trial button'); await ctx.close(); process.exit(4); }
  await sleep(5000); await shot(page, 'after-start');
  const codeBox = () => page.locator('input[name*="code" i]:visible, input[placeholder*="code" i]:visible, input[aria-label*="code" i]:visible, input[autocomplete="one-time-code"]:visible');
  const overlay = (t) => page.evaluate((t) => { let el = document.getElementById('__wg'); if (!el) { el = document.createElement('div'); el.id = '__wg'; document.documentElement.appendChild(el); } el.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:2147483647;background:#E8703A;color:#fff;font:600 17px/1.4 system-ui;padding:14px 20px;pointer-events:none'; el.textContent = t; }, t).catch(() => {});
  const clearOverlay = () => page.evaluate(() => document.getElementById('__wg')?.remove()).catch(() => {});
  const waitHuman = async () => {
    // phone verification: the human types the code; we wait up to 10 minutes
    if (!(await codeBox().count())) { const t = await page.locator('body').innerText().catch(() => ''); if (!/verification code|text me|call me|send verification/i.test(t)) return; }
    console.log('YOUR TURN: phone verification on screen'); await overlay('YOUR TURN: choose Text me / Call me, enter the code, press Verify. I continue automatically.');
    const start = Date.now();
    while (Date.now() - start < 600000) { await sleep(3000); if (!(await codeBox().count())) { const t = await page.locator('body').innerText().catch(() => ''); if (!/enter the code|verification code/i.test(t)) break; } }
    await clearOverlay();
  };
  await waitHuman();
  for (let i = 0; i < 24; i++) {
    await waitHuman();
    const bs2 = await buttons(page); console.log('now:', bs2.filter((b) => /trial|try|start|confirm|place|continue|next|agree|done|close/i.test(b.text)).map((b) => b.text).join(' | '));
    const body = await page.locator('body').innerText().catch(() => '');
    if (/processing your order/i.test(body)) { console.log('order processing, waiting'); await sleep(8000); continue; }
    if (/thank you|order (is )?complete|successfully|has been placed|you're all set|licenses? (are|is) ready/i.test(body)) { console.log('order confirmed'); break; }
    const r = await clickText(/^try now$|^start trial$|^start your free trial$|^place order$|^confirm$|^continue$|^next$|^i agree|^text me$|^send verification code$|^verify$/i);
    if (r === 'disabled') { await sleep(5000); continue; }
    if (r) { await sleep(6000); await shot(page, `confirm${i}`); } else break;
  }
  console.log('final url:', page.url());
  const txt = (await page.locator('body').innerText()).slice(0, 2000); console.log('page says:', txt.replace(/\s+/g, ' ').slice(0, 600));
} finally { await ctx.close(); }
