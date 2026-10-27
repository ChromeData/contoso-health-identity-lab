// Sign in to developer.servicenow.com (profile.json email + password) and request a PDI.
//   node servicenow-instance.mjs [--go]
import { chromium } from 'playwright'; import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url)); const GO = process.argv.includes('--go');
const P = JSON.parse(fs.readFileSync(path.join(HERE, 'profile.json'), 'utf8'));
import { execFileSync } from 'node:child_process';
try { P.password = execFileSync('security', ['find-generic-password', '-s', 'contoso-lab-servicenow', '-w'], { encoding: 'utf8' }).trim(); } catch { console.error('no Keychain item contoso-lab-servicenow'); process.exit(1); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = async (page, tag) => { const f = path.join(HERE, 'shots', `snow-${tag}-${Date.now()}.png`); await page.screenshot({ path: f }); console.log('shot:', f); };
const list = async (page) => page.locator('button:visible, a:visible, [role=button]:visible, input:visible').evaluateAll((els) => els.map((el) => ({ tag: el.tagName.toLowerCase(), text: (el.innerText || el.value || '').trim().replace(/\s+/g, ' ').slice(0, 60), aria: el.getAttribute('aria-label') || '', ph: el.placeholder || '', name: el.name || '' })).filter((b) => b.text || b.aria || b.ph || b.name));
const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), { headless: true, viewport: { width: 1400, height: 950 } });
const page = ctx.pages()[0] || (await ctx.newPage());
try {
  await page.goto('https://developer.servicenow.com/dev.do', { waitUntil: 'domcontentloaded' }); await sleep(8000);
  const signIn = page.locator('button:visible, a:visible').filter({ hasText: /^Sign In$/i }).first();
  if (await signIn.count()) { await signIn.click(); await sleep(6000); }
  await shot(page, 'login');
  console.log('login page:', page.url());
  const fields = await list(page); console.log('fields:', fields.filter((f) => f.tag === 'input' || /sign|log|next|continue/i.test(f.text)).map((f) => `[${f.tag}] ${f.text || f.aria || f.ph || f.name}`).join(' | '));
  const email = page.locator('input[type=email]:visible, input[name*="user" i]:visible, input[id*="user" i]:visible, input[placeholder*="mail" i]:visible').first();
  if (await email.count()) { await email.fill(P.email); const next = page.locator('button:visible').filter({ hasText: /next|continue|sign in|log in/i }).first(); if (await next.count()) await next.click(); await sleep(4000); }
  const pw = page.locator('input[type=password]:visible').first();
  await pw.waitFor({ timeout: 15000 }).catch(() => {});
  if (await pw.count()) { await pw.fill(P.password); const go = page.locator('button:visible').filter({ hasText: /sign in|log in|next|continue/i }).first(); if (await go.count()) await go.click(); await sleep(8000); }
  await shot(page, 'after-login'); console.log('after login:', page.url());
  const bs = await list(page); console.log('buttons:', bs.filter((b) => /instance|start|request|build|release|yes|sign/i.test(b.text + b.aria)).map((b) => `[${b.tag}] ${b.text || b.aria}`).join(' | '));
  if (!GO) process.exit(0);
  // cookie banner + the first-login "tune your experience" wizard
  const cookie = page.locator('button:visible').filter({ hasText: /accept and proceed/i }).first(); if (await cookie.count()) { await cookie.click().catch(() => {}); await sleep(1000); }
  for (let i = 0; i < 6; i++) {
    const modal = page.locator('dps-user-profile-modal, [role=dialog]:visible').first();
    if (!(await modal.count())) break;
    const tile = modal.locator('text=/^Yes$|^Other$|^Developer$|^Admin/i').first(); if (await tile.count()) { await tile.click({ force: true }).catch(() => {}); await sleep(600); }
    for (const lab of [/IT Admin/i, /agree/i]) { const cb = modal.locator('label, span, div').filter({ hasText: lab }).locator('input[type=checkbox]').first().or(modal.locator('input[type=checkbox]').filter({ has: page.locator(':scope') }).first()); const box = modal.getByLabel(lab).first(); const target = (await box.count()) ? box : cb; if (await target.count()) { await target.check({ force: true }).catch(() => target.click({ force: true }).catch(() => {})); await sleep(400); } }
    const nxt = modal.locator('button:visible').filter({ hasText: /^next$|^finish setup$|^finish$|^done$|^submit$|^save$|^continue$|^get started$/i }).first();
    if (!(await nxt.count())) { const close = modal.locator('button[aria-label*="close" i], button:has-text("Skip")').first(); if (await close.count()) await close.click({ force: true }).catch(() => {}); else break; }
    else await nxt.click({ force: true }).catch(() => {});
    await sleep(2500); await shot(page, `wizard${i}`);
  }
  const req = page.locator('button:visible, a:visible').filter({ hasText: /request instance|start building|get an instance|request an instance/i }).first();
  await req.waitFor({ timeout: 15000 }).catch(() => {});
  if (!(await req.count())) { console.log('no Request Instance button'); process.exit(3); }
  await req.click(); await sleep(6000); await shot(page, 'request');
  const bs2 = await list(page); console.log('modal:', bs2.filter((b) => /request|release|yes|confirm|select|latest|instance/i.test(b.text + b.aria)).map((b) => `[${b.tag}] ${b.text || b.aria}`).join(' | '));
  const confirm = page.locator('button:visible').filter({ hasText: /request your instance|setup .* instance|^request$|confirm/i }).first();
  if (await confirm.count()) { await confirm.click(); console.log('clicked:', (await confirm.innerText()).trim()); }
  for (let i = 0; i < 20; i++) { await sleep(10000); const t = (await page.locator('body').innerText().catch(() => '')); const m = t.match(/https:\/\/dev\d{5,7}\.service-now\.com/); if (m) { console.log('INSTANCE:', m[0]); const pwm = t.match(/password[^\n]*\n\s*([^\s]{8,})/i); if (pwm) console.log('INSTANCE_PASSWORD:', pwm[1]); await shot(page, 'instance'); break; } }
  await shot(page, 'end'); console.log('page says:', (await page.locator('body').innerText()).replace(/\s+/g, ' ').slice(0, 500));
} finally { await ctx.close(); }
