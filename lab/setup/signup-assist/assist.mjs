// signup-assist: opens a real browser window, fills sign-up forms from
// profile.json, and hands over to YOU only when a page needs a human:
// a CAPTCHA, a code sent to your phone/email, or a payment card.
//
//   npm run setup                 (once)
//   node assist.mjs microsoft     | azure | okta | aws | servicenow
//   node assist.mjs <service> --scan   (headless: list the fields it sees, fill nothing)
//
// How it works: after every page change it (1) fills every visible field it
// recognises (name, email, phone, company, country, username, domain, password),
// (2) if it sees a CAPTCHA, a verification-code box or a card field it stops and
// prints YOUR TURN, (3) otherwise it clicks the obvious Next / Continue / Sign up
// button, and repeats. You can always type a command at the prompt:
//   enter      continue (after you did your part)
//   fill       fill again (e.g. after you changed something)
//   click X    click the button whose text contains X
//   url        print the current page URL
//   done       stop; prints what to copy into handback.env
// The browser profile persists in ./browser-profile so logins survive.
// Card numbers are NEVER read from any file: that field is always yours.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const service = process.argv[2];
const SCAN = process.argv.includes('--scan');
const AUTO = process.argv.includes('--auto');   // no terminal: messages appear IN the browser; continues when you've done your part
const LOG = path.join(HERE, 'assist.log');
const log = (...a) => { const line = a.join(' '); console.log(line); try { fs.appendFileSync(LOG, `${new Date().toISOString()} ${line.replace(/\x1b\[[0-9;]*m/g, '')}\n`); } catch {} };
const SERVICES = {
  microsoft: {
    title: 'Microsoft tenant (Intune Plan 1 trial → creates the tenant with Entra ID P2)',
    url: 'https://go.microsoft.com/fwlink/?linkid=2019088',
    done: /admin\.microsoft\.com|intune\.microsoft\.com|portal\.office\.com/,
    handback: ['ONMICROSOFT_DOMAIN=<username>@<domain>.onmicrosoft.com', 'ADMIN_UPN=admin@<domain>.onmicrosoft.com', 'LAB_SUFFIX=<the 4 characters>'],
    after: 'Then in https://admin.microsoft.com → Billing → Purchase services: start the "Microsoft 365 E5" trial, then "Step-Up for Microsoft Entra ID P2" (Entra ID Governance).',
  },
  m365e5: {
    title: 'Microsoft 365 E5 trial (adds Entra ID P2 etc. to the tenant; signs in as the tenant admin)',
    url: 'https://signup.microsoft.com/get-started/signup?products=101bde18-5ffb-4d79-a47b-f5b2c62525b3',
    done: /admin\.microsoft\.com|portal\.office\.com/,
    handback: ['(nothing: the E5 licences are in the tenant)'],
    after: 'Then: Entra ID Governance → https://admin.microsoft.com → Billing → Purchase services → "Step-Up for Microsoft Entra ID P2" → Start free trial.',
    login: true,
  },
  trials: {
    title: 'E5 + Entra ID Governance trials, from the admin center catalog (signed in)',
    url: 'https://admin.microsoft.com/#/catalog',
    done: /never-matches-x/,
    handback: ['(nothing: licences land in the tenant)'],
    after: 'Both trials started.',
    login: true,
    hint: 'YOUR TURN (3 clicks, twice):  1) in the search box type  Microsoft 365 E5  → Details → Start free trial → confirm.   2) search  Entra ID Governance  → "Step-Up for Microsoft Entra ID P2" → Details → Start free trial → confirm.  Then close this window.',
  },
  azure: {
    title: 'Azure free account (sign in with the admin@ account you just made)',
    url: 'https://signup.azure.com/signup?offer=ms-azr-0044p&appId=102&l=en-us',
    done: /portal\.azure\.com/,
    handback: ['AZURE_SUBSCRIPTION_ID=<Subscriptions blade → the GUID>'],
    after: 'Portal → Subscriptions → copy the subscription id.',
  },
  okta: {
    title: 'Okta Integrator Free Plan',
    login: true, // Okta refuses consumer mailboxes: sign up with the tenant mailbox
    email: 'okta@ContosoHealthLab.onmicrosoft.com', // alias on the admin mailbox; the first org's activation mail was lost
    url: 'https://developer.okta.com/signup/',
    done: /okta\.com\/admin|-admin\.okta\.com/,
    handback: ['OKTA_ORG_NAME=integrator-NNNNNNN', 'OKTA_BASE_URL=okta.com', 'export OKTA_API_TOKEN=<Security → API → Tokens → Create token "terraform">'],
    after: 'Pick "Workforce Identity → Integrator Free Plan" if asked. Activate from the email.',
  },
  aws: {
    title: 'AWS account (Free plan)',
    emailSuffix: '+contoso', // the plain Gmail already owns an AWS account; a plus-address is a new email to AWS, same inbox
    url: 'https://signin.aws.amazon.com/signup?request_type=register',
    done: /console\.aws\.amazon\.com/,
    handback: ['AWS_ACCOUNT_ID=<12 digits, top right of the console>', 'AWS_REGION=us-east-1'],
    after: 'Choose the FREE plan. Then IAM Identity Center → Enable (us-east-1) and copy the access portal URL.',
  },
  servicenow: {
    title: 'ServiceNow developer instance',
    url: 'https://signon.service-now.com/x_snc_sso_auth.do?pageId=sign-up',
    done: /developer\.servicenow\.com/,
    handback: ['SERVICENOW_INSTANCE_URL=https://devNNNNNN.service-now.com'],
    after: 'Sign in at developer.servicenow.com → Request Instance → latest release.',
  },
};
if (!SERVICES[service]) {
  console.error(`usage: node assist.mjs <${Object.keys(SERVICES).join('|')}> [--scan]`); process.exit(2);
}
const S = SERVICES[service];
const profilePath = path.join(HERE, 'profile.json');
if (!fs.existsSync(profilePath)) { console.error('No profile.json: cp profile.example.json profile.json and fill it in.'); process.exit(1); }
const P = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
for (const k of ['firstName', 'lastName', 'email', 'company']) if (!P[k]) { console.error(`profile.json: ${k} is empty`); process.exit(1); }
if (Object.keys(P).some((k) => /^(card|cardnumber|cvv|cvc|pan|expiry)$/i.test(k))) { console.error('profile.json must not contain card details.'); process.exit(1); }

// ---- what we know how to fill: [regex on label/placeholder/name/aria, value] ----
function buildFields() { const upn = P.adminUpn || P.email; const mail = S.email ? S.email : S.login ? upn : (S.emailSuffix ? P.email.replace('@', S.emailSuffix + '@') : P.email); return [
  [/^email, phone, or skype$|^email address$|sign in|someone@example/i, mail],
  [/first\s*name|given/i, P.firstName],
  [/state, province|state\/province|^state\b/i, (P.state || '').length === 2 ? ({ FL: 'Florida' }[P.state.toUpperCase()] || P.state) : P.state],
  [/last\s*name|surname|family/i, P.lastName],
  [/full\s*name|^name$|your name|account holder/i, `${P.firstName} ${P.lastName}`],
  [/e-?mail|work email|business email/i, mail],
  [/phone|mobile|telephone/i, P.phone],
  [/company|organization|organisation|business name|account name/i, P.company],
  [/^country$|country\b/i, P.country || 'United States'],
  [/job title|title/i, P.jobTitle || 'IAM Engineer'],
  [/address line 1|address 1|street|^address/i, P.address || ''],
  [/city/i, P.city || ''],
  [/zip|postal/i, P.zip || ''],
  [/state|province|region$/i, P.state || ''],
  [/^user\s*name$|username/i, P.username || 'admin'],
  [/domain name|your domain|domain$/i, P.domain || ''],
  [/confirm password|re-?enter password|repeat password|confirmpassword/i, P.password || ''],
  [/password/i, P.password || ''],
]; }
const FIELDS = buildFields();
const US_STATES = { AL: 'Alabama', AK: 'Alaska', AZ: 'Arizona', AR: 'Arkansas', CA: 'California', CO: 'Colorado', CT: 'Connecticut', DE: 'Delaware', FL: 'Florida', GA: 'Georgia', HI: 'Hawaii', ID: 'Idaho', IL: 'Illinois', IN: 'Indiana', IA: 'Iowa', KS: 'Kansas', KY: 'Kentucky', LA: 'Louisiana', ME: 'Maine', MD: 'Maryland', MA: 'Massachusetts', MI: 'Michigan', MN: 'Minnesota', MS: 'Mississippi', MO: 'Missouri', MT: 'Montana', NE: 'Nebraska', NV: 'Nevada', NH: 'New Hampshire', NJ: 'New Jersey', NM: 'New Mexico', NY: 'New York', NC: 'North Carolina', ND: 'North Dakota', OH: 'Ohio', OK: 'Oklahoma', OR: 'Oregon', PA: 'Pennsylvania', RI: 'Rhode Island', SC: 'South Carolina', SD: 'South Dakota', TN: 'Tennessee', TX: 'Texas', UT: 'Utah', VT: 'Vermont', VA: 'Virginia', WA: 'Washington', WV: 'West Virginia', WI: 'Wisconsin', WY: 'Wyoming', DC: 'District of Columbia' };
const stateName = (P.state || '').length === 2 ? US_STATES[(P.state || '').toUpperCase()] || P.state : P.state;
const SELECTS = [
  [/country|region/i, [P.country || 'United States', /^United States/i]],
  [/company size|employees|size/i, [P.companySize || '25-49', /25/, /^1[0-9]-|^11-|^10-/]],
  [/^state\b|province/i, [stateName, P.state, /./]],
  [/department/i, [P.department || '', /information technology|^it$|it &|security|engineering/i, /./]],
  [/role|job function|title/i, [P.jobTitle || '', /engineer|security|identity|other/i, /./]],
  [/industry/i, [P.industry || '', /health|technology|software/i, /./]],
  [/how did you hear|referr?al|source/i, [/other|search|web/i, /./]],
];
const HUMAN = {
  captcha: 'iframe[src*="captcha"], iframe[src*="arkose"], iframe[src*="funcaptcha"], [class*="captcha" i], #captcha, [data-sitekey]',
  code: 'input[name*="code" i], input[name*="otp" i], input[placeholder*="code" i], input[aria-label*="code" i], input[autocomplete="one-time-code"]',
  card: 'input[autocomplete="cc-number"], input[name*="card" i], input[placeholder*="card number" i], iframe[src*="payment"], iframe[name*="card" i]',
};
const NEXT = /^(next|continue|sign up|set up account|create account|get started|start free trial|try now|submit|verify|send verification code|send code|agree and continue|i agree|save|finish|register|try now|try for free|try azure for free|start free|start your free trial|verify email address|verify email|choose free plan|complete sign up|agree and continue|continue \(step \d of \d\)|yes)$/i;

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((r) => rl.question(q, (a) => r(a.trim())));
const banner = (t) => console.log(`\n\x1b[1;33m${'='.repeat(64)}\n${t}\n${'='.repeat(64)}\x1b[0m`);

async function visibleInputs(page) {
  return page.locator('input:visible, select:visible, textarea:visible').evaluateAll((els) => els.map((el) => {
    const id = el.id; const lab = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`)?.innerText : '';
    const wrap = el.closest('label')?.innerText || '';
    return { tag: el.tagName.toLowerCase(), type: el.type || '', name: el.name || '', id, placeholder: el.placeholder || '',
      aria: el.getAttribute('aria-label') || '', label: (lab || wrap || '').trim().slice(0, 60), value: el.value || '', autocomplete: el.autocomplete || '' };
  }));
}
function describe(f) { return [f.label, f.placeholder, f.aria, f.name, f.id].filter(Boolean).join(' | '); }

async function autofill(page) {
  const inputs = await visibleInputs(page);
  let filled = 0;
  for (let i = 0; i < inputs.length; i++) {
    const f = inputs[i]; const text = describe(f);
    if (!text || f.value) continue;
    if (/card|cvv|cvc|expir/i.test(text)) continue;                      // never ours
    const loc = page.locator('input:visible, select:visible, textarea:visible').nth(i);
    try {
      if (f.tag === 'select') {
        const hit = SELECTS.find(([re]) => re.test(text)); if (!hit || !hit[1]) continue;
        const wants = Array.isArray(hit[1]) ? hit[1] : [hit[1]];
        const opts = await loc.locator('option').evaluateAll((os) => os.map((o) => ({ v: o.value, t: (o.textContent || '').trim() })));
        const pick = wants.map((w) => opts.find((o) => (w instanceof RegExp ? w.test(o.t) : o.t.toLowerCase() === String(w).toLowerCase()))).find(Boolean);
        if (!pick) continue;
        await loc.selectOption(pick.v); filled++; console.log(`   chose   ${text.slice(0, 48).padEnd(48)} ← ${pick.t}`);
      } else if (f.type === 'radio') {
        if (!/solution|other|developer|engineer|it |business|basic support|free/i.test(text)) continue;
        if (await loc.isChecked().catch(() => false)) continue;
        await loc.check({ force: true }).catch(() => loc.click({ force: true })); filled++; console.log(`   picked  ${text.slice(0, 48)}`);
      } else if (f.type === 'checkbox') {
        if (/agree|terms|accept|privacy|tnc|t&c/i.test(text)) { await loc.check(); filled++; }
      } else if (['text', 'email', 'tel', 'password', ''].includes(f.type)) {
        if (f.type === 'password' && !P.password) continue;
        const hit = FIELDS.find(([re]) => re.test(text)); if (!hit || !hit[1]) continue;
        try { await loc.fill(hit[1], { timeout: 8000 }); } catch { await loc.click({ timeout: 3000 }); await loc.pressSequentially(hit[1], { delay: 30 }); }
        filled++;
        console.log(`   filled  ${text.slice(0, 48).padEnd(48)} ← ${f.type === 'password' ? '••••••' : hit[1]}`);
      }
    } catch (e) { console.log(`   skip    ${text.slice(0, 48)}: ${e.message.split('\n')[0]}`); }
  }
  return filled;
}
async function pickTiles(page) {
  try {
    const t = await page.locator('body').innerText();
    if (/select your role/i.test(t)) {
      const tile = page.getByText(/^(Solution builders|Other)/i).first();
      if (await tile.count()) { await tile.click({ timeout: 3000 }); console.log('   picked  role tile'); }
    }
  } catch {}
}
async function needsHuman(page) {
  for (const [why, sel] of Object.entries(HUMAN)) {
    const n = await page.locator(sel).filter({ visible: true }).count().catch(() => 0);
    if (n) return why;
  }
  const t = (await page.locator('body').innerText().catch(() => '')).slice(0, 4000);
  if (/enter the code|verification code|we sent (a|you a) code|check your (email|phone)/i.test(t) && !/send (me )?(a )?(verification )?code/i.test(t)) return 'code';
  return null;
}
async function clickNext(page, text) {
  const buttons = page.locator('button:visible, input[type=submit]:visible, a[role=button]:visible, [role=button]:visible, a:visible');
  const n = await buttons.count();
  for (let i = 0; i < n; i++) {
    const b = buttons.nth(i); const label = ((await b.innerText().catch(() => '')) || (await b.getAttribute('value')) || '').trim();
    if (await b.evaluate((el) => !!el.closest('footer, nav, header, [role=contentinfo], [role=navigation]')).catch(() => false)) continue;
    if (text ? label.toLowerCase().includes(text.toLowerCase()) : NEXT.test(label)) {
      console.log(`   click   "${label}"`); await b.click({ timeout: 5000 }).catch((e) => console.log('   click failed:', e.message.split('\n')[0])); return label;
    }
  }
  return null;
}

async function overlay(page, text, kind = 'turn') {
  const color = kind === 'done' ? '#2E9E5B' : kind === 'wait' ? '#2F6BFF' : '#E8703A';
  await page.evaluate(([t, c]) => {
    let el = document.getElementById('__wg_assist');
    if (!el) { el = document.createElement('div'); el.id = '__wg_assist'; document.documentElement.appendChild(el); }
    el.style.cssText = `position:fixed;left:0;right:0;top:0;z-index:2147483647;background:${c};color:#fff;font:600 17px/1.4 -apple-system,system-ui,sans-serif;padding:14px 20px;box-shadow:0 6px 24px rgba(0,0,0,.35);pointer-events:none;white-space:pre-wrap`;
    el.textContent = t;
  }, [text, color]).catch(() => {});
}
async function shot(page, tag) {
  try { fs.mkdirSync(path.join(HERE, 'shots'), { recursive: true }); const f = path.join(HERE, 'shots', `${Date.now()}-${tag}.png`); await page.screenshot({ path: f, fullPage: false }); log('   shot', f); } catch {}
}
import { execFile } from 'node:child_process';
const osa = (script) => new Promise((r) => execFile('osascript', ['-e', script], () => r()));
async function hideBrowser() { await osa('tell application "System Events" to set visible of (first process whose name contains "Chrome for Testing") to false'); }
async function showBrowser() { await osa('tell application "System Events" to set frontmost of (first process whose name contains "Chrome for Testing") to true'); }
async function clearOverlay(page) { await page.evaluate(() => document.getElementById('__wg_assist')?.remove()).catch(() => {}); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function autoLoop(getPage) {
  let page = getPage();
  let lastUrl = '', idle = 0, lastSig = '';
  const TURN = { captcha: 'YOUR TURN: solve the CAPTCHA on this page. I continue automatically.', code: 'YOUR TURN: enter the code they sent you, then press its Next/Verify button. I continue automatically.', card: 'YOUR TURN: enter your card (verification only), then press its button. I continue automatically.' };
  for (;;) {
    page = getPage();
    const url = page.url();
    if (S.done.test(url)) { await showBrowser(); await overlay(page, `DONE. ${S.after}\n\nCopy into handback.env:\n${S.handback.join('\n')}`, 'done'); log('DONE', url); return; }
    if (url !== lastUrl) { log('→', url); lastUrl = url; idle = 0; await sleep(1800); await clearOverlay(page); const n = await autofill(page); log(`   filled ${n}`); }
    const why = await needsHuman(page);
    if (why) {
      await autofill(page); await pickTiles(page);
      await overlay(page, TURN[why]); await showBrowser(); log('WAIT', why); await shot(page, why);
      // wait until the human-needed condition clears or the page moves on
      const start = page.url();
      for (;;) { await sleep(2000); if (page.url() !== start) break; if (!(await needsHuman(page))) break; }
      await clearOverlay(page); await hideBrowser(); idle = 0; await autofill(page); continue;
    }
    // fields we could not fill (empty required-looking inputs) → ask the human for those
    const empties = (await visibleInputs(page)).filter((f) => !f.value && ['text', 'email', 'tel', 'password', ''].includes(f.type) && describe(f));
    const sig = page.url() + '|' + empties.map(describe).join(',');
    if (empties.length && sig === lastSig) {
      idle++;
      if (idle >= 2) {
        await overlay(page, `YOUR TURN: I could not fill: ${empties.map((f) => describe(f).split(' | ')[0]).join(', ')}. Fill them and press the page's Next button. I continue automatically.`, 'wait');
        log('WAIT fields', empties.map(describe).join(', ')); await shot(page, 'fields'); await showBrowser();
        const start = page.url();
        for (;;) {
          await sleep(2000); if (page.url() !== start) break;
          try { Object.assign(P, JSON.parse(fs.readFileSync(profilePath, 'utf8'))); FIELDS.splice(0, FIELDS.length, ...buildFields()); } catch {}
          const n = await autofill(page); if (n) log(`   filled ${n} from updated profile.json`);
          const e2 = (await visibleInputs(page)).filter((f) => !f.value && ['text', 'email', 'tel', 'password', ''].includes(f.type) && describe(f)); if (!e2.length) break;
        }
        await clearOverlay(page); await hideBrowser(); idle = 0; continue;
      }
    }
    lastSig = sig;
    const hit = S.hint ? null : await clickNext(page);
    if (!hit) {
      await overlay(page, S.hint || 'YOUR TURN: I see no Next button here. Do this page yourself; I continue when the page changes.', 'wait'); log('WAIT no-next'); await shot(page, 'no-next'); await showBrowser();
      const start = page.url(); while (page.url() === start) await sleep(2000);
      await clearOverlay(page); await hideBrowser(); continue;
    }
    await sleep(3500);
    if (page.url() === lastUrl) { const again = await autofill(page); if (again) log(`   filled ${again} more`); }
  }
}

(async () => {
  banner(`${S.title}\n${S.url}`);
  const ctx = await chromium.launchPersistentContext(path.join(HERE, 'browser-profile'), {
    headless: SCAN, viewport: { width: 1280, height: 900 }, args: ['--disable-blink-features=AutomationControlled', '--remote-debugging-port=9222'],
  });
  let page = ctx.pages()[0] || (await ctx.newPage());
  ctx.on('page', async (p) => {
    try { await p.waitForLoadState('domcontentloaded'); } catch {}
    const u = p.url();
    if (/privacy|legal|trademark|support|feedback|third-party|terms|docs\.|learn\.microsoft|go\.microsoft\.com\/fwlink/i.test(u)) { log('   side tab closed:', u); try { await p.close(); } catch {} return; }
    log('   new tab:', u); page = p;
  });
  await page.goto(S.url, { waitUntil: 'domcontentloaded' }).catch((e) => console.log('goto:', e.message));
  await page.waitForTimeout(2500);

  if (SCAN) {
    console.log('fields on the first page:');
    for (const f of await visibleInputs(page)) console.log(`   [${f.tag}${f.type ? ':' + f.type : ''}] ${describe(f)}`);
    console.log('needs human:', await needsHuman(page));
    await ctx.close(); rl.close(); return;
  }

  if (AUTO) { await sleep(1500); await hideBrowser(); await autoLoop(() => page); await ask('Done. Press Enter to close the browser (session saved). '); await ctx.close(); rl.close(); return; }

  let lastUrl = '';
  for (;;) {
    const url = page.url();
    if (S.done.test(url)) { banner(`Looks done: ${url}`); break; }
    if (url !== lastUrl) { console.log(`\n→ ${url}`); lastUrl = url; await page.waitForTimeout(1500); await autofill(page); }
    const why = await needsHuman(page);
    if (why) {
      banner(`YOUR TURN: ${{ captcha: 'solve the CAPTCHA', code: 'enter the code they sent you', card: 'enter your card (verification only)' }[why]} in the browser window, then press Enter here.`);
    }
    const cmd = await ask(why ? '> ' : '(Enter = click Next · fill · click <text> · url · done) > ');
    if (cmd === 'done') break;
    if (cmd === 'url') { console.log(page.url()); continue; }
    if (cmd === 'fill') { await autofill(page); continue; }
    if (cmd.startsWith('click ')) { await clickNext(page, cmd.slice(6)); await page.waitForTimeout(2500); continue; }
    if (!why) { const hit = await clickNext(page); if (!hit) console.log('   no obvious Next button; type: click <button text>'); }
    await page.waitForTimeout(3000);
    if (page.url() === lastUrl) { const again = await autofill(page); if (again) console.log(`   (filled ${again} more)`); }
  }
  banner(`Copy into lab/setup/handback.env:\n  ${S.handback.join('\n  ')}\n\n${S.after}`);
  await ask('Press Enter to close the browser (your session is saved in browser-profile/). ');
  await ctx.close(); rl.close();
})().catch((e) => { console.error(e); process.exit(1); });
