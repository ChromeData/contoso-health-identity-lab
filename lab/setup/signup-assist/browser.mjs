// Keeps the persistent lab browser profile open (hidden) with CDP on 9222 for live.mjs.
import { chromium } from 'playwright';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), {
  headless: false, viewport: { width: 1280, height: 900 },
  args: ['--disable-blink-features=AutomationControlled', '--remote-debugging-port=9222'],
});
const page = ctx.pages()[0] || await ctx.newPage();
await page.goto(process.argv[2] || 'about:blank', { waitUntil: 'domcontentloaded' }).catch(() => {});
if (process.argv.includes('--hide')) setTimeout(() => execFile('osascript', ['-e', 'tell application "System Events" to set visible of (first process whose name contains "Chrome for Testing") to false']), 1500);
console.log('browser up on 9222');
setInterval(() => {}, 1 << 30);
