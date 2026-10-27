import { chromium } from 'playwright'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), { headless: true, viewport: { width: 1400, height: 950 } });
const page = ctx.pages()[0] || (await ctx.newPage());
await page.goto(process.argv[2], { waitUntil: 'domcontentloaded' }); await page.waitForTimeout(Number(process.argv[3] || 40000));
const t = await page.locator('body').innerText();
const lines = t.split('\n').map((l) => l.trim()).filter((l) => /subscription|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|tenant|directory/i.test(l));
console.log(lines.slice(0, 30).join('\n')); await ctx.close();
