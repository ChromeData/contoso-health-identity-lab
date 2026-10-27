// Assign a licence to a user from the admin center Licenses page (signed-in profile).
//   node assign-license.mjs "<product name>" "<user display name or upn>" [--go]
import { chromium } from 'playwright'; import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const [product, user] = process.argv.slice(2); const GO = process.argv.includes('--go');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = async (page, tag) => { const f = path.join(HERE, 'shots', `lic-${tag}-${Date.now()}.png`); await page.screenshot({ path: f }); console.log('shot:', f); };
const list = async (page) => page.locator('button:visible, a:visible, [role=button]:visible, input:visible').evaluateAll((els) => els.map((el) => ({ tag: el.tagName.toLowerCase(), text: (el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 60), aria: el.getAttribute('aria-label') || '', ph: el.placeholder || '' })).filter((b) => b.text || b.aria || b.ph));
const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), { headless: true, viewport: { width: 1400, height: 950 } });
const page = ctx.pages()[0] || (await ctx.newPage());
try {
  await page.goto('https://admin.cloud.microsoft/?#/licenses', { waitUntil: 'domcontentloaded' });
  const row = page.getByRole('link', { name: product, exact: true }).or(page.getByText(product, { exact: true })).first();
  await row.waitFor({ timeout: 45000 }); await row.click(); await sleep(5000); await shot(page, 'product');
  const bs = await list(page);
  console.log('on product page:', bs.filter((b) => /assign|add|user|search|name|license/i.test(b.text + b.aria + b.ph)).map((b) => `[${b.tag}] ${b.text || b.aria || b.ph}`).join(' | '));
  const assign = page.locator('button:visible').filter({ hasText: /Assign licenses/i }).first();
  if (!(await assign.count())) { console.log('no Assign licenses button'); process.exit(3); }
  await assign.click(); await sleep(4000); await shot(page, 'panel');
  const bs2 = await list(page);
  console.log('panel:', bs2.filter((b) => /assign|user|search|name|email|picker|license|apps/i.test(b.text + b.aria + b.ph)).map((b) => `[${b.tag}] ${b.text || b.aria || b.ph}`).join(' | '));
  if (!GO) process.exit(0);
  const box = page.getByLabel('People picker').first();
  await box.waitFor({ timeout: 15000 });
  await box.click(); await box.pressSequentially(user, { delay: 50 }); await sleep(5000); await shot(page, 'typed');
  // suggestions: anything clickable that shows the name, excluding the input itself
  const cand = page.locator('[role=option], [role=listbox] [role=presentation], .ms-Suggestions-item, .ms-PeoplePicker-personaContent, [class*="suggestion" i], [class*="persona" i]').filter({ hasText: new RegExp(user.split(' ')[0], 'i') }).first();
  const dump = await page.locator('[role=option]:visible, [class*="uggestion"]:visible, [class*="ersona"]:visible').evaluateAll((els) => els.slice(0, 8).map((el) => `${el.tagName.toLowerCase()}.${(el.className || '').toString().slice(0, 40)}: ${(el.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 60)}`));
  console.log('suggestions:', dump.join(' | '));
  if (await cand.count()) { await cand.click(); console.log('picked suggestion'); } else { await box.press('ArrowDown'); await box.press('Enter'); console.log('ArrowDown+Enter'); }
  await sleep(3000); await shot(page, 'picked');
  const go = page.locator('button:visible').filter({ hasText: /Assign licenses|^Assign$|Save changes/i }).last();
  if (!(await go.count())) { console.log('no Assign button'); process.exit(4); }
  console.log('click:', (await go.innerText()).trim()); await go.click(); await sleep(6000); await shot(page, 'done');
  console.log('page says:', (await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 400));
} finally { await ctx.close(); }
