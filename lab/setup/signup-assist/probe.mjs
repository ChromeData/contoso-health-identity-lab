// probe: open a URL in the saved (signed-in) profile, wait, screenshot, list what's clickable/typeable.
//   node probe.mjs <url> [waitMs] [headed]
import { chromium } from 'playwright';
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const [url, waitMs = '8000', headed] = process.argv.slice(2);
const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), { headless: !headed, viewport: { width: 1400, height: 950 }, args: ['--disable-blink-features=AutomationControlled'] });
const page = ctx.pages()[0] || (await ctx.newPage());
await page.goto(url, { waitUntil: 'domcontentloaded' }).catch((e) => console.log('goto:', e.message));
await page.waitForTimeout(Number(waitMs));
fs.mkdirSync(path.join(HERE, 'shots'), { recursive: true });
const f = path.join(HERE, 'shots', `probe-${Date.now()}.png`); await page.screenshot({ path: f }); console.log('url:', page.url()); console.log('shot:', f);
const items = await page.locator('input:visible, textarea:visible, button:visible, a:visible, [role=button]:visible, [role=searchbox]:visible, [role=combobox]:visible').evaluateAll((els) => els.slice(0, 120).map((el) => ({
  tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || '', text: (el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 60),
  ph: el.placeholder || '', aria: el.getAttribute('aria-label') || '', id: el.id || '', auto: el.getAttribute('data-automation-id') || el.getAttribute('data-automationid') || '' })));
for (const i of items) if (i.text || i.ph || i.aria) console.log(`  [${i.tag}${i.role ? '/' + i.role : ''}] ${i.text || ''} ${i.ph ? 'ph=' + i.ph : ''} ${i.aria ? 'aria=' + i.aria : ''} ${i.auto ? 'auto=' + i.auto : ''} ${i.id ? 'id=' + i.id : ''}`);
await ctx.close();
