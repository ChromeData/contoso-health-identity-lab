// One-time setup with plain pop-ups: GitHub sign-in in the recording browser, then OBS permission.
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
const req = createRequire(path.join(os.homedir(), 'contoso-health-identity-lab/lab/setup/signup-assist/package.json'));
const { chromium } = req('playwright');
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const dialog = (text, buttons = ['OK']) => {
  const b = buttons.map((x) => `"${x}"`).join(', ');
  try { return execFileSync('osascript', ['-e', `button returned of (display dialog "${text}" buttons {${b}} default button 1 with title "Contoso demo setup")`], { encoding: 'utf8' }).trim(); } catch { return 'Cancel'; }
};
const note = (text) => { try { execFileSync('osascript', ['-e', `display notification "${text}" with title "Contoso demo setup"`]); } catch {} };

// ---- 1. GitHub -------------------------------------------------------------
if (dialog('Step 1 of 2: a Chrome window will open on GitHub. Sign in there the way you normally do. It closes by itself when you are in.', ['Open GitHub', 'Skip']) === 'Open GitHub') {
  const ctx = await chromium.launchPersistentContext(path.join(ROOT, '.recording-profile'), { channel: 'chrome', headless: false, viewport: null, args: ['--window-size=1280,900'] });
  const page = ctx.pages()[0] || await ctx.newPage();
  await page.goto('https://github.com/login');
  let ok = false;
  for (let i = 0; i < 300 && !ok; i++) {          // up to 10 minutes
    const c = await ctx.cookies('https://github.com');
    ok = c.some((x) => x.name === 'logged_in' && x.value === 'yes');
    if (!ok) await new Promise((r) => setTimeout(r, 2000));
  }
  if (ok) { await page.goto('https://github.com/ChromeData/contoso-health-identity-lab'); await new Promise((r) => setTimeout(r, 2500)); }
  await ctx.close();
  note(ok ? 'GitHub: signed in ✓' : 'GitHub: not signed in yet');
  console.log('GITHUB', ok ? 'OK' : 'NOT-SIGNED-IN');
}

// ---- 2. OBS permission -------------------------------------------------------
if (dialog('Step 2 of 2: a Settings window will open. Find OBS in the list and switch it ON. (If a second window opens for Microphone, switch OBS on there too.)', ['Open Settings', 'Skip']) === 'Open Settings') {
  try { execFileSync('open', ['-a', 'OBS']); } catch {}
  execFileSync('open', ['x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture']);
  dialog('Switch OBS ON for Screen Recording, then click Next.', ['Next']);
  execFileSync('open', ['x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone']);
  dialog('Switch OBS ON for Microphone, then click Done. (If macOS asks to quit and reopen OBS, click Quit & Reopen.)', ['Done']);
  console.log('OBS', 'DONE');
}
note('Setup finished. Claude takes it from here.');
