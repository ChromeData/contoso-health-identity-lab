// dump visible page text lines matching a regex: node text.mjs <url> <regex> [waitMs]
import { chromium } from 'playwright'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const [url, re, waitMs = '30000'] = process.argv.slice(2);
const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), { headless: true, viewport: { width: 1400, height: 950 } });
const page = ctx.pages()[0] || (await ctx.newPage());
await page.goto(url, { waitUntil: 'domcontentloaded' }); await page.waitForTimeout(Number(waitMs));
const t = await page.locator('body').innerText().catch(() => '');
console.log('url:', page.url());
console.log(t.split('\n').map((l) => l.trim()).filter((l) => new RegExp(re, 'i').test(l)).slice(0, 40).join('\n'));
await ctx.close();
