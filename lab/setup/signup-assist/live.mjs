// Act on the browser the assistant is driving RIGHT NOW (no restart):
//   node live.mjs fill "<label regex>" "<value>"     node live.mjs click "<button text regex>"
//   node live.mjs check "<label regex>"              node live.mjs select "<label regex>" "<option text>"
//   node live.mjs text "<regex>"                     node live.mjs shot
import { chromium } from 'playwright'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const [cmd, a, b] = process.argv.slice(2);
const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
const ctx = browser.contexts()[0]; const pages = ctx.pages().filter((p) => !/^about:|chrome:/.test(p.url()));
const page = process.env.LIVE_PAGE != null ? ctx.pages()[Number(process.env.LIVE_PAGE)] : pages[pages.length - 1];
console.log('page:', page.url());
const re = (x) => new RegExp(x, 'i');
try {
  if (cmd === 'goto') { await page.goto(a, { waitUntil: 'domcontentloaded' }); await page.waitForTimeout(4000); console.log('now at', page.url()); }
  else if (cmd === 'fill') { const loc = a.startsWith('name:') ? page.locator(`[name="${a.slice(5)}"]`).first() : page.getByLabel(re(a)).first().or(page.getByPlaceholder(re(a)).first()); await loc.waitFor({ timeout: 8000 }); await loc.click(); await loc.fill(''); await loc.pressSequentially(b, { delay: 25 }); console.log('filled', a); }
  else if (cmd === 'click') { const loc = page.locator('button:visible, a:visible, [role=button]:visible, input[type=submit]:visible').filter({ hasText: re(a) }).first(); await loc.waitFor({ timeout: 8000 }); await loc.click(); console.log('clicked', (await loc.innerText().catch(() => a)).trim()); }
  else if (cmd === 'check') { const loc = page.getByLabel(re(a)).first().or(page.locator('input[type=checkbox]:visible').first()); await loc.check({ force: true }); console.log('checked', a); }
  else if (cmd === 'select') {
    const loc = a.startsWith('name:') ? page.locator(`[name="${a.slice(5)}"]`).first() : page.getByLabel(re(a)).first();
    const tag = await loc.evaluate((el) => el.tagName.toLowerCase()).catch(() => '');
    if (tag === 'select') { await loc.selectOption({ label: b }); }
    else { await loc.click(); await page.waitForTimeout(600); const opt = page.locator('[role=option], li, [class*="option" i]').filter({ hasText: re('^' + b + '$') }).first(); if (await opt.count()) await opt.click(); else { await loc.pressSequentially(b, { delay: 40 }); await page.keyboard.press('Enter'); } }
    console.log('selected', b);
  }
  else if (cmd === 'radio') { const loc = page.locator(`input[type=radio][value="${a}"]`).first(); await loc.check({ force: true }); console.log('radio', a); }
  else if (cmd === 'buttons') { const items = await page.locator('button:visible').evaluateAll((els) => els.map((el, i) => `${i} "${el.innerText.trim().slice(0, 50)}" dialog=${!!el.closest('[role=dialog]')} type=${el.type}`)); console.log(items.filter((x) => re(a).test(x)).join('\n')); }
  else if (cmd === 'dialogclick') { const loc = page.locator('[role=dialog] button:visible').filter({ hasText: re(a) }).last(); await loc.waitFor({ timeout: 8000 }); await loc.click(); console.log('dialog clicked', (await loc.innerText()).trim()); }
  else if (cmd === 'link') { const loc = page.getByRole('link', { name: re(a) }).first(); await loc.waitFor({ timeout: 8000 }); await loc.click(); console.log('link clicked', (await loc.innerText()).trim()); }
  else if (cmd === 'bytext') { const loc = page.getByText(re(a)).first(); await loc.waitFor({ timeout: 8000 }); await loc.click(); console.log('text clicked', (await loc.innerText()).trim()); }
  else if (cmd === 'xy') { await page.mouse.click(Number(a), Number(b)); console.log('clicked at', a, b); }
  else if (cmd === 'key') { await page.keyboard.press(a); console.log('key', a); }
  else if (cmd === 'cssfill') { const loc = page.locator(a).last(); await loc.click(); await loc.fill(''); await loc.pressSequentially(b, { delay: 25 }); console.log('cssfilled', a); }
  else if (cmd === 'uncheck') { const loc = page.getByLabel(re(a)).first(); await loc.uncheck({ force: true }); console.log('unchecked', a); }
  else if (cmd === 'href') { const hs = await page.getByRole('link', { name: re(a) }).evaluateAll((els) => els.map((e) => e.href)); console.log(hs.join('\n')); }
  else if (cmd === 'html') { const h = await page.content(); console.log('frames:', page.frames().map((f) => f.url()).join(' | ')); console.log(h.length, h.replace(/\s+/g, ' ').slice(0, Number(a) || 1500)); }
  else if (cmd === 'val') { const v = await page.locator(a).last().inputValue(); if (b === 'keychain') { const { execFileSync } = await import('node:child_process'); execFileSync('security', ['add-generic-password', '-U', '-a', process.env.USER, '-s', process.argv[5], '-w', v]); console.log('saved to keychain', process.argv[5], 'len', v.length); } else console.log(v); }
  else if (cmd === 'cssclick') { await page.locator(a).last().click(); console.log('cssclicked', a); }
  else if (cmd === 'pages') { console.log(ctx.pages().map((p, i) => `${i} ${p.url()}`).join('\n')); }
  else if (cmd === 'text') { const t = await page.locator('body').innerText(); console.log(t.split('\n').map((l) => l.trim()).filter((l) => re(a).test(l)).slice(0, 20).join('\n')); }
  else if (cmd === 'shot') { const f = path.join(HERE, 'shots', `live-${Date.now()}.png`); await page.screenshot({ path: f }); console.log(f); }
  else if (cmd === 'fields') { const items = await page.locator('input:visible, select:visible, [role=combobox]:visible, [role=button][aria-haspopup]:visible').evaluateAll((els) => els.map((el) => `${el.tagName.toLowerCase()}:${el.type || ''} ${el.name || ''} "${el.id ? (document.querySelector(`label[for="${el.id}"]`)?.innerText || '') : ''}" ph="${el.placeholder || ''}" val="${(el.value || '').slice(0, 20)}"`)); console.log(items.join('\n')); }
  else console.log('unknown command');
} catch (e) { console.log('ERROR', e.message.split('\n')[0]); }
await browser.close();
