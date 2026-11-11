// The recording browser: Google Chrome with its OWN persistent profile
// (~/contoso-demo/cockpit/.recording-profile), headful, sized for the
// recording display, bookmarks bar hidden, no "controlled by automated test
// software" bar, page zoom 125%. The owner signs in to Entra, Azure, GitHub,
// AWS and ServiceNow in it ONCE (their own accounts and MFA); the cockpit
// never types the owner's credentials.
//
// On-screen helpers (an overlay injected into every page, never part of the
// site): a neutral highlight box (white outline, the script card's dark label style) with an optional tag, a click ripple,
// the leaver stopwatch, and (only with --mouse dom, the old way) a drawn
// pointer that glides to what is clicked. By default the REAL system pointer
// moves, clicks, scrolls and types like a person (lib/human.mjs).
import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, execFile } from 'node:child_process';
import { windows } from './winshot.mjs';
import { localUrl, localBase } from './localurl.mjs';

const req = createRequire(path.join(os.homedir(), 'contoso-health-identity-lab/lab/setup/signup-assist/package.json'));
export const { chromium } = req('playwright');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// An expert's hand (owner, 2026-11-10 #2: still human, but brisk).
export const HAND = +(process.env.COCKPIT_HAND_SPEED || 1.3);

export const OVERLAY = `(() => {
  if (window.__ck) return;
  const isTop = window.top === window;
  const GUID = /\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b/i;
  // A personal mailbox (e.g. the AWS account's root email on the access
  // portal, seen in preview 2's piece 4) is blurred like ids and IPs.
  const PERSONAL = /@(gmail|googlemail|outlook|hotmail|live|icloud|me|yahoo|proton(mail)?)\\.[a-z.]+\\b/i;
  const PUBIP = /\\b(?!10\\.)(?!192\\.168\\.)(?!172\\.(?:1[6-9]|2\\d|3[01])\\.)(?!127\\.)(?:\\d{1,3}\\.){3}\\d{1,3}\\b/;
  function redact(root) {
    if (!window.__ckRedact) return;
    const w = document.createTreeWalker(root || document.body, NodeFilter.SHOW_TEXT);
    let n; while ((n = w.nextNode())) { const t = n.nodeValue; if (!t || t.length > 400) continue;
      if (GUID.test(t) || PUBIP.test(t) || PERSONAL.test(t)) { const p = n.parentElement; if (p && !p.closest('#__ck_root')) p.style.filter = 'blur(6px)'; } }
  }
  window.__ckRedact = true;
  let pend = false;
  const obs = new MutationObserver(() => { if (pend) return; pend = true; requestAnimationFrame(() => { pend = false; try { redact(); } catch {} }); });
  function boot() {
    if (!document.body) return;
    try { redact(); } catch {}
    obs.observe(document.body, { subtree: true, childList: true, characterData: true });
    if (!isTop || document.getElementById('__ck_root')) return;
    const st = document.createElement('style');
    st.textContent = \`
      #__ck_root{position:fixed;inset:0;pointer-events:none;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
      #__ck_ring{position:absolute;border:2px solid rgba(255,255,255,.85);border-radius:12px;background:rgba(255,255,255,.04);box-shadow:0 0 0 1.5px rgba(18,18,18,.62),0 0 0 6px rgba(128,128,128,.14),0 6px 24px rgba(0,0,0,.26);opacity:0;transform:scale(.985);transition:left .45s cubic-bezier(.2,.8,.2,1),top .45s cubic-bezier(.2,.8,.2,1),width .45s cubic-bezier(.2,.8,.2,1),height .45s cubic-bezier(.2,.8,.2,1),opacity .35s ease,transform .35s cubic-bezier(.2,.8,.2,1)}
      #__ck_ring.on{opacity:1;transform:scale(1)}
      #__ck_tag{position:absolute;background:rgba(18,18,18,.82);color:rgba(255,255,255,.92);font-weight:600;font-size:14px;line-height:1.25;letter-spacing:.01em;padding:7px 13px;border-radius:16px;border:1px solid rgba(255,255,255,.10);opacity:0;transform:translateY(3px) scale(.97);transition:opacity .35s ease,transform .35s cubic-bezier(.2,.8,.2,1);white-space:nowrap;box-shadow:0 8px 24px rgba(0,0,0,.28);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}
      #__ck_tag.on{opacity:1;transform:none}
      #__ck_cur{position:absolute;left:0;top:0;width:26px;height:26px;opacity:0;transition:transform .7s cubic-bezier(.3,.7,.2,1),opacity .3s;filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}
      #__ck_cur.on{opacity:1}
      #__ck_rip{position:absolute;width:40px;height:40px;margin:-20px 0 0 -20px;border-radius:50%;border:1.5px solid rgba(255,255,255,.8);background:rgba(255,255,255,.10);box-shadow:0 0 0 1px rgba(18,18,18,.25);opacity:0}
      #__ck_rip.go{animation:ckrip .6s ease-out}
      @keyframes ckrip{0%{opacity:.7;transform:scale(.35)}100%{opacity:0;transform:scale(1.25)}}
      #__ck_sw{position:absolute;right:22px;bottom:22px;background:rgba(18,18,18,.82);color:rgba(255,255,255,.96);border-radius:16px;border:1px solid rgba(255,255,255,.10);padding:10px 18px;font:600 30px/1.1 ui-monospace,"SF Mono",Menlo,monospace;box-shadow:0 10px 30px rgba(0,0,0,.3);display:none}
      #__ck_sw small{display:block;font:600 12px/1.2 -apple-system,system-ui,sans-serif;letter-spacing:.08em;color:rgba(255,255,255,.55);margin-bottom:4px}
    \`;
    const root = document.createElement('div'); root.id = '__ck_root';
    root.innerHTML = '<div id="__ck_ring"></div><div id="__ck_tag"></div><div id="__ck_rip"></div><div id="__ck_sw"><small>SINCE HR SAID "LEAVER"</small><span>0:00</span></div>' +
      '<svg id="__ck_cur" viewBox="0 0 28 28"><path d="M5 3l17 10.5-7.6 1.6 4.6 8.6-3.3 1.7-4.6-8.6L5 22.6z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    document.documentElement.appendChild(st); document.documentElement.appendChild(root);
    const $ = (id) => document.getElementById(id);
    let swTimer = null;
    window.__ck = {
      ring(x, y, w, h, tag) { const r = $('__ck_ring'), p = 8; Object.assign(r.style, { left: (x - p) + 'px', top: (y - p) + 'px', width: (w + 2 * p) + 'px', height: (h + 2 * p) + 'px' }); r.classList.add('on');
        const g = $('__ck_tag'); if (tag) { g.textContent = tag; const ty = y - p - 40 < 8 ? y + h + p + 10 : y - p - 40; g.style.top = ty + 'px'; g.style.left = '0px'; const tw = g.offsetWidth; g.style.left = Math.max(8, Math.min(innerWidth - tw - 8, x + w + p - tw)) + 'px'; g.classList.add('on'); } else g.classList.remove('on'); },
      unring() { $('__ck_ring').classList.remove('on'); $('__ck_tag').classList.remove('on'); },
      cursor(x, y) { const c = $('__ck_cur'); c.classList.add('on'); c.style.transform = 'translate(' + (x - 5) + 'px,' + (y - 3) + 'px)'; },
      hideCursor() { $('__ck_cur').classList.remove('on'); },
      ripple(x, y) { const r = $('__ck_rip'); r.classList.remove('go'); r.style.left = x + 'px'; r.style.top = y + 'px'; void r.offsetWidth; r.classList.add('go'); },
      banner(t) { let b = document.getElementById('__ck_banner'); if (!b) { b = document.createElement('div'); b.id = '__ck_banner'; b.style.cssText = 'position:absolute;left:50%;top:14px;transform:translateX(-50%);background:rgba(18,18,18,.82);color:rgba(255,255,255,.94);font:600 15px/1.25 -apple-system,system-ui,sans-serif;padding:9px 18px;border-radius:16px;border:1px solid rgba(255,255,255,.10);box-shadow:0 8px 24px rgba(0,0,0,.3);transition:opacity .4s;white-space:nowrap'; root.appendChild(b); }
        b.textContent = t; b.style.opacity = t ? 1 : 0; clearTimeout(b._t); if (t) b._t = setTimeout(() => { b.style.opacity = 0; }, 9000); },
      stopwatch(t0) { const el = $('__ck_sw'); clearInterval(swTimer); if (!t0) { el.style.display = 'none'; return; } el.style.display = 'block';
        const tick = () => { const s = Math.max(0, Math.floor((Date.now() - t0) / 1000)); el.querySelector('span').textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }; tick(); swTimer = setInterval(tick, 250); },
    };
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();`;

// Pop-ups the portals throw at a fresh session (from lab/scripts/demo/video/rec.mjs).
const DISMISS = `(() => {
  // + review 1: AWS's "Service menu" tour, Defender's "Custom columns" bubble, Splunk's AI toast.
  const titles = [/Give feedback to Microsoft/i, /Mandatory Azure MFA/i, /How likely are you/i, /We.d love your feedback/i, /Welcome to (the )?Microsoft Defender/i, /What.s new/i, /Tasks Panel Remains Unchanged/i,
    /Service menu/i, /Custom columns/i, /Splunk AI Assistant/i, /Introducing the new/i, /Take a tour/i,
    /Try the new pull requests Overview/i, /Upcoming change to GitHub App installation token/i];   // 2026-11-10: GitHub's PR page popover (Not now)
  let n = 0;
  for (const el of document.querySelectorAll('div,section,aside,[role=dialog]')) {
    const t = el.innerText || ''; if (t.length > 900 || !titles.some((r) => r.test(t))) continue;
    const b = [...el.querySelectorAll('button,[role=button]')].find((b) => /^(close|dismiss|got it|done|skip|skip tour|not now|maybe later|×|x)$/i.test((b.getAttribute('aria-label') || b.title || b.innerText || '').trim()) || /close|dismiss/i.test(b.getAttribute('aria-label') || ''));
    if (b) { b.click(); n++; }
  }
  // Preview 2, piece 4: AWS's console tour ("Service menu ... Next") has no
  // close button, only Next on each step and an end button on the last. On an
  // AWS console page only, a SMALL tour pop-up (dialog / popover / tour box,
  // under 500 characters) is ended, or stepped through with Next; a table's
  // "Next page" is never in such a box.
  if (/(^|\.)console\.aws\.amazon\.com$/.test(location.host)) {
    for (const el of document.querySelectorAll('[role=dialog],[class*="popover" i],[class*="tour" i],[class*="tutorial" i],[class*="hotspot" i]')) {
      const t = (el.innerText || '').trim(); if (!t || t.length > 500 || el.querySelector('table')) continue;
      const btns = [...el.querySelectorAll('button,[role=button]')];
      const label = (b) => (b.getAttribute('aria-label') || b.innerText || '').trim();
      const end = btns.find((b) => /^(done|finish|end tour|got it|close|dismiss|skip|skip tour|close tour)$/i.test(label(b)));
      const next = btns.find((b) => /^next$/i.test((b.innerText || '').trim()));
      if (end) { end.click(); n++; } else if (next) { next.click(); n++; }
    }
  }
  return n;
})()`;

// Sign-in pages: the step can't do its job until the owner signs in once.
const SIGNIN = [
  [/login\.microsoftonline\.com|login\.live\.com/, 'Microsoft (Entra / Azure / Defender)'],
  [/github\.com\/(login|session)/, 'GitHub'],
  [/signin\.aws\.amazon\.com|\.signin\.aws|awsapps\.com\/start\/?#?\/?$/, 'AWS'],
  [/service-now\.com\/(login|navpage\.do\?.*login)/, 'ServiceNow'],
  [/127\.0\.0\.1:8000\/en-US\/account\/login/, 'Splunk'],
];

const ZOOM_125 = Math.log(1.25) / Math.log(1.2);   // Chrome stores zoom as log base 1.2

export class Browser {
  constructor({ profileDir, width = 1920, height = 1080, zoom = 1.25, shotsDir, log = console.log } = {}) {
    Object.assign(this, { profileDir, width, height, zoom, shotsDir, log });
    this.ctx = null; this.page = null; this.stopwatchT0 = null; this.priv = null; this.human = null;
  }

  seedProfile() {
    const pref = path.join(this.profileDir, 'Default', 'Preferences');
    // Never hand a link to a desktop app: Chrome blocks these schemes outright
    // (protocol_handler.excluded_schemes: true = blocked). A teams.microsoft.com
    // link once opened the DESKTOP Teams app, signed in to the owner's own
    // organisation (2026-11-05); Teams must only ever be web Teams here.
    const BLOCK = { msteams: true, 'ms-teams': true, 'ms-teams-classic': true };
    if (fs.existsSync(pref)) {
      try {
        const j = JSON.parse(fs.readFileSync(pref, 'utf8'));
        j.protocol_handler = { ...(j.protocol_handler || {}), excluded_schemes: { ...(j.protocol_handler?.excluded_schemes || {}), ...BLOCK } };
        // Entra's user Properties page is three columns wide: at 125% its
        // right column (Account enabled, On-premises sync) is cut off, so
        // that one site is shown at 100% (review 1, item 11).
        j.partition = j.partition || {};
        j.partition.per_host_zoom_levels = j.partition.per_host_zoom_levels || {};
        j.partition.per_host_zoom_levels.x = { ...(j.partition.per_host_zoom_levels.x || {}), 'entra.microsoft.com': { last_modified: '13406000000000000', zoom_level: 0.0 } };
        fs.writeFileSync(pref, JSON.stringify(j));
      } catch (e) { this.log(`profile prefs: ${e.message}`); }
      return;
    }
    fs.mkdirSync(path.dirname(pref), { recursive: true });
    fs.writeFileSync(pref, JSON.stringify({
      bookmark_bar: { show_on_all_tabs: false },
      browser: { show_home_button: false, check_default_browser: false },
      credentials_enable_service: false,
      profile: { password_manager_enabled: false, default_content_setting_values: { notifications: 2 } },
      translate: { enabled: false },
      partition: { default_zoom_level: { x: this.zoom === 1.25 ? ZOOM_125 : Math.log(this.zoom) / Math.log(1.2) } },
      session: { restore_on_startup: 5 },
      protocol_handler: { excluded_schemes: BLOCK },
    }));
  }

  async launch() {
    if (this.ctx) return this;
    fs.mkdirSync(this.profileDir, { recursive: true });
    this.seedProfile();
    this.ctx = await chromium.launchPersistentContext(this.profileDir, {
      channel: 'chrome', headless: false, viewport: null,
      // No "controlled by automated test software" bar, no "--no-sandbox" warning bar.
      ignoreDefaultArgs: ['--enable-automation', '--no-startup-window', '--no-sandbox'],
      args: [`--window-size=${this.width},${this.height}`, '--window-position=0,0',
        '--hide-crash-restore-bubble', '--no-default-browser-check', '--no-first-run', '--disable-features=Translate,PasswordLeakDetection'],
    });
    await this.ctx.addInitScript(OVERLAY);
    this.ctx.on('page', (p) => this._wire(p));
    this.page = this.ctx.pages()[0] || await this.ctx.newPage();
    for (const p of this.ctx.pages()) this._wire(p);
    this.ctx.on('close', () => { this.ctx = null; this.page = null; });
    return this;
  }
  get up() { return !!this.ctx; }

  _wire(p) {
    p.on('load', () => { if (this.stopwatchT0) p.evaluate((t) => window.__ck && window.__ck.stopwatch(t), this.stopwatchT0).catch(() => {}); });
  }

  // The Chrome process that owns this profile (for bringing its window forward).
  pid() {
    try {
      const out = execFileSync('pgrep', ['-f', `user-data-dir=${this.profileDir}`], { encoding: 'utf8' }).trim().split('\n');
      const tops = out.filter((p) => { try { return !/--type=/.test(execFileSync('ps', ['-o', 'command=', '-p', p], { encoding: 'utf8' })); } catch { return false; } }).map(Number);
      // More than one (seen once with a brand-new profile): the one with a window.
      if (tops.length > 1) { try { const w = windows(); const t = tops.find((p) => w.some((x) => x.pid === p && x.layer === 0)); if (t) return t; } catch {} }
      if (tops.length) return tops[0];
    } catch {}
    return null;
  }

  // Bring the recording browser window to the front (macOS app activation by pid).
  async activate() {
    await this.page?.bringToFront().catch(() => {});
    const pid = this.pid();
    if (!pid) return false;
    await new Promise((r) => execFile('osascript', ['-l', 'JavaScript', '-e',
      `ObjC.import('AppKit'); const a = $.NSRunningApplication.runningApplicationWithProcessIdentifier(${pid}); a.activateWithOptions($.NSApplicationActivateAllWindows | $.NSApplicationActivateIgnoringOtherApps);`], () => r()));
    return true;
  }

  async open(url, { settle = 2500, onHuman = null, prefetchOnly = false } = {}) {
    // A local screen (a captured image, a card, a local page) through the
    // cockpit's server, never as file:///Users/... (lib/localurl.mjs).
    url = localUrl(url);
    if (!this.ctx) await this.launch();
    if (this.page.isClosed()) this.page = await this.ctx.newPage();
    // Owner, 2026-11-10: page swaps looked machine-made. With the real
    // pointer and this window in front, the site changes as a person changes
    // it: its tab clicked (opened earlier in the background, off camera),
    // or through the lab map's link. Never an address typed (owner,
    // 2026-11-10 #2: no typing on screen). Anything odd: the old way.
    if (await this.humanOpen(url, onHuman).catch((e) => { this.log(`tabs: ${e.message.split('\n')[0]}: opened directly`); return false; })) {
      await this.settle(this._switchedToLoaded ? Math.min(settle, 300) : settle);
      await this.dismiss();
      return this.signinNeeded();
    }
    await this.reachForToolbar();
    for (let a = 0; a < 3; a++) {
      try { await this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 }); break; }
      catch (e) { this.log(`goto (try ${a + 1}): ${e.message.split('\n')[0]}`); if (a === 2) throw e; await sleep(3000); }
    }
    await this.settle(settle);
    await this.dismiss();
    return this.signinNeeded();
  }

  // After a page change: not a fixed sleep (2026-11-10 #2: 2.5-5 s of still
  // picture per step), but until the page is quiet, capped (the next action
  // waits for its own element anyway). COCKPIT_SETTLE=full: the old fixed wait.
  async settle(ms = 2500, page = this.page) {
    if (process.env.COCKPIT_SETTLE === 'full') { await sleep(ms); return; }
    const cap = Math.max(150, Math.min(ms, +(process.env.COCKPIT_SETTLE_CAP || 1500)));
    await sleep(Math.min(150, cap));
    await Promise.race([page?.waitForLoadState('networkidle', { timeout: cap }).catch(() => {}), sleep(cap)]);
  }

  // ---- tabs, as a person uses them ------------------------------------------
  static norm(u) { return Browser.normUrl(u); }   // hash-aware (see normUrl)
  tabFor(url) { const want = Browser.norm(url); return this.ctx?.pages().find((p) => !p.isClosed() && Browser.norm(p.url()) === want) || (this.prefetched?.get(want)?.page && !this.prefetched.get(want).page.isClosed() ? this.prefetched.get(want).page : null); }
  // Open a page in a BACKGROUND tab (Chrome's own Target.createTarget with
  // background: true): the tab in front stays in front, so this can run while
  // the camera rolls. The step that needs the page then just clicks its tab.
  // At most 6 tabs: the oldest prefetched tab not in front is closed first.
  async prefetch(url, { reload = false } = {}) {
    url = localUrl(url);
    if (!this.ctx || !/^(https?|file):/.test(url)) return null;
    const want = Browser.norm(url);
    this.prefetched ||= new Map();
    const have = this.tabFor(url);
    if (have) {
      const ent = this.prefetched.get(want);
      if (reload && have !== this.page) { await have.reload({ waitUntil: 'domcontentloaded', timeout: 60000 }).catch(() => {}); if (ent) ent.at = Date.now(); }
      return have;
    }
    const pages = this.ctx.pages().filter((p) => !p.isClosed());
    if (pages.length >= 6) {
      const old = [...this.prefetched.values()].filter((e) => e.page !== this.page && !e.page.isClosed()).sort((a, b) => a.at - b.at)[0];
      if (old) { await old.page.close().catch(() => {}); }
    }
    let page = null;
    try {
      const anchor = this.page && !this.page.isClosed() ? this.page : pages[0];
      const cdp = await this.ctx.newCDPSession(anchor);
      const ev = this.ctx.waitForEvent('page', { timeout: 20000 }).catch(() => null);
      await cdp.send('Target.createTarget', { url, background: true });
      page = await ev;
      await cdp.detach().catch(() => {});
      if (!page) throw new Error('the new tab did not show up in 20 s');
    } catch (e) {
      this.log(`tabs: background tab for ${url.slice(0, 80)}: ${e.message.split('\n')[0]}`);
      return null;
    }
    this.prefetched.set(want, { page, at: Date.now() });
    // The tab loads by itself; callers that need it loaded await this.
    page._ckLoaded = page.waitForLoadState('domcontentloaded', { timeout: 60000 }).catch(() => {});
    this.log(`tabs: ${url.slice(0, 90)} opened in a background tab`);
    return page;
  }

  // true when the page was reached the human way (tab click or map link).
  async humanOpen(url, onHuman = null) {
    const H = this.H;
    this._switchedToLoaded = false;
    if (!H || process.env.COCKPIT_TABS === '0') return false;
    const pid = this.pid(); if (!pid) return false;
    const w = await H.win(pid);
    if (!w.front) return false;   // never click unless this window is in front
    await this.ensureMapTab().catch(() => {});   // before the camera rolls: a new tab flashes
    // The hash is part of the address: Entra and the Azure portal route by it
    // (#view/..., #blade/...). Without it every Entra page matched the first
    // Entra tab or map link (2026-11-10 walkthrough: n00-trust landed on
    // Entra's home page instead of Enterprise apps). A tenant prefix
    // (#@contoso.onmicrosoft.com/...) the portal adds by itself is ignored.
    const norm = Browser.norm;
    const want = norm(url);
    const cur = this.page;
    // 1. Already open in a tab (opened earlier in the background): click it.
    //    The one in front is used as it is: no reload on camera.
    let have = this.tabFor(url);
    if (have && have === cur) { if (onHuman) await onHuman(); this._switchedToLoaded = true; this.humanNavs = (this.humanNavs || 0) + 1; return true; }
    // 1b. Through the lab map, when the map tab is the page in front (the
    //     hand is already on it): its stop's bubble, then the card's link.
    const mp = this.mapPage();
    if (!have && mp && mp === cur) {
      if (onHuman) await onHuman();
      const viaMap = await this.mapLinkOpen(url, want, norm, this.ctx.pages().filter((p) => !p.isClosed()), w, pid).catch((e) => { this.log(`tabs: map link: ${e.message.split('\n')[0]}`); return false; });
      if (viaMap) { this.humanNavs = (this.humanNavs || 0) + 1; return true; }
    }
    // 2. Not open yet: opened in a background tab now (the picture in front
    //    does not change), then its tab is clicked like any other. No address
    //    is ever typed. A local page (the map, a file) is opened directly.
    if (!have) {
      if (/^file:/.test(url) || (Browser.MAP_URL && url.startsWith(Browser.MAP_URL)) || (localBase() && url.startsWith(localBase() + '/'))) return false;   // the maps, cards and captured screens too (served locally)
      have = await this.prefetch(url);
      if (!have) return false;
    }
    await have._ckLoaded;
    // The camera rolls for the tab click only once that tab has really loaded
    // (N17: a GitHub tab still "Untitled" was clicked on camera); otherwise
    // the page is opened the old way, camera still paused.
    const ready = await this.waitReady(have, 30000);
    if (ready !== 'ok') { this.log(`tabs: the background tab for ${url.slice(0, 80)} is ${ready} after 30 s: opened directly`); return false; }
    if (onHuman) await onHuman();   // e.g. the camera rolls: the viewer sees the hand go to the tab
    await this.clickTab(have, this.ctx.pages().filter((p) => !p.isClosed()), w, pid);
    this._switchedToLoaded = true;
    if (norm(have.url()) !== want && !this.signinUrl(have.url())) {
      this.log(`tabs: the tab shows ${have.url().slice(0, 100)}: opening ${url.slice(0, 100)} in it`);
      await have.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
      this._switchedToLoaded = false;
    }
    this.humanNavs = (this.humanNavs || 0) + 1;
    return true;
  }
  // The lab map (map/lab-map.html, hooks in map/README-links.md): kept open
  // in a tab of this window, so a person can go from the map to each site.
  static MAP_FILE = new URL('../map/lab-map.html', import.meta.url).pathname;
  // Served by the cockpit's own server (cockpit.mjs sets this to
  // http://localhost:<port>/map), so the address bar on camera shows a
  // neutral address, not this Mac's /Users/... path. No key in it: /map is
  // a read-only route that serves only the two map pages, to this Mac only.
  static MAP_URL = null;
  static mapHref() { return Browser.MAP_URL || `file://${Browser.MAP_FILE}`; }
  static isMapUrl(u) { u = String(u || '').split(/[?#]/)[0]; return (!!Browser.MAP_URL && u === Browser.MAP_URL) || (u.startsWith('file://') && u.endsWith('/map/lab-map.html')); }
  mapPage() { return this.ctx?.pages().find((p) => !p.isClosed() && Browser.isMapUrl(p.url())) || null; }
  // Off camera (piece start): the map tab is there (opened behind the page in
  // front if it was missing; the page in front stays in front).
  async ensureMapTab() {
    if (!this.ctx || this.mapPage() || !fs.existsSync(Browser.MAP_FILE)) return;
    const cur = this.page;
    const mp = await this.ctx.newPage();
    await mp.goto(Browser.mapHref(), { waitUntil: 'load', timeout: 30000 }).catch(() => {});
    if (cur && !cur.isClosed()) await cur.bringToFront().catch(() => {});
  }
  // The site through the map: the map's tab clicked, the stop's bubble
  // clicked (its card opens), the card's link clicked (the site opens in a
  // new tab). false when no map link goes to this address.
  async mapLinkOpen(url, want, norm, pages, w, pid) {
    const mp = this.mapPage(); if (!mp) return false;
    const links = await mp.evaluate(() => (window.__mapLinks?.stops || []).flatMap((s) => (s.links || []).map((l) => ({ n: s.n, id: l.id, url: new URL(l.url, location.href).href })))).catch(() => []);
    const hit = links.find((l) => norm(l.url) === want) || null;
    if (!hit) return false;
    // At most 6 tabs, as for a typed address: every map link opens a new tab
    // (2026-11-10 walkthrough, N10 reached 10 tabs). The oldest one that is
    // neither the map nor in front is closed first, off the strip's edge.
    for (let open = this.ctx.pages().filter((p) => !p.isClosed()); open.length >= 6; open = this.ctx.pages().filter((p) => !p.isClosed())) {
      const old = open.find((p) => p !== mp && p !== this.page); if (!old) break;
      await old.close().catch(() => {});
    }
    pages = this.ctx.pages().filter((p) => !p.isClosed());
    if (mp !== this.page) await this.clickTab(mp, pages, w, pid);
    this.page = mp;
    await sleep(150 + Math.random() * 200);
    // The bubble a viewer can see: the first visible one of this stop.
    const bubble = await this.find({ css: `[data-stop="${hit.n}"][data-bubble]` }, { timeout: 5000 }).then(() => true, () => false);
    if (bubble) await this.click({ css: `[data-stop="${hit.n}"][data-bubble]` });
    else await mp.evaluate((n) => window.__mapLinks.open(n), hit.n);
    const link = { css: `#panel a[data-stop="${hit.n}"][data-link="${hit.id}"]` };
    await this.find(link, { timeout: 6000 });
    await sleep(180 + Math.random() * 220);
    const ev = this.ctx.waitForEvent('page', { timeout: 8000 }).catch(() => null);
    await this.click(link);
    const target = (await ev) || mp;
    if (target !== mp) this.placeAfter(target, mp);
    await target.waitForLoadState('domcontentloaded', { timeout: 60000 }).catch(() => {});
    this.page = target;
    if (norm(target.url()) !== want && !this.signinUrl(target.url())) await target.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    this.log(`tabs: reached ${url.slice(0, 90)} through the map (stop ${hit.n}, ${hit.id})`);
    return true;
  }
  signinUrl(u) { return SIGNIN.some(([re]) => re.test(u)); }
  static normUrl(u) {
    try {
      const x = new URL(u);
      const h = x.hash.replace(/^#@[^/]+\/?/, '#').replace(/^#\/?$/, '');
      return x.origin + x.pathname.replace(/\/$/, '') + x.search + h;
    } catch { return u; }
  }

  // Click a tab in Chrome's tab strip with the real pointer. The strip is
  // laid out from the window's width (macOS Chrome: tabs start after the
  // window buttons, at most ~240 pt wide); the click is checked (the tab's
  // page must be the visible one) and falls back to Cmd+<n>, then to
  // Playwright's bringToFront.
  // The tab strip's order as Chrome lays it out: a tab opened from a map
  // link sits right after the map tab, a Cmd+T tab at the end (pages() is
  // creation order, which is not the strip's).
  stripOrder() {
    const open = this.ctx.pages().filter((p) => !p.isClosed());
    this.strip = (this.strip || []).filter((p) => open.includes(p));
    for (const p of open) if (!this.strip.includes(p)) this.strip.push(p);
    return this.strip;
  }
  placeAfter(page, after) {
    const st = this.stripOrder().filter((p) => p !== page);
    const k = st.indexOf(after);
    st.splice(k >= 0 ? k + 1 : st.length, 0, page);
    this.strip = st;
  }
  async clickTab(page, pages, w, pid) {
    pages = this.stripOrder();
    const i = pages.indexOf(page), n = pages.length;
    const left = w.x + 80, avail = w.w - 80 - 100, tw = Math.min(240, avail / n);
    const cx = left + tw * (i + 0.5) + (Math.random() * 2 - 1) * Math.min(20, tw * 0.15), cy = w.y + 20 + (Math.random() * 2 - 1) * 3;
    await this.H.move(cx, cy, { w: Math.max(40, tw * 0.6), speed: HAND });
    await sleep(60 + Math.random() * 90);
    await this.H.click(undefined, undefined, { pid });
    // Which tab is in front is read from the WINDOW's title (Chrome names
    // its window after the active tab): Playwright's pages all report
    // visibilityState "visible", and the strip's order is not pages() order
    // (a tab opened from the map sits next to the map tab). 2026-11-10
    // walkthrough, N09: the click landed on another tab, the check passed, and
    // the highlight went to a tab nobody could see.
    const want = (await page.title().catch(() => '')).trim();
    const front = async () => { try { const t = (windows().find((x) => +x.pid === +pid && x.layer === 0 && x.h > 300)?.title || '').trim(); return !!want && t.startsWith(want.slice(0, 40)); } catch { return false; } };
    await sleep(250);
    if (!(await front())) {
      this.log(`tabs: the tab strip click missed "${want.slice(0, 40)}": brought to the front directly`);
      await page.bringToFront().catch(() => {});
    }
    this.page = page;
    // The hand comes back down into the page: left on the tab strip it kept
    // Chrome's tab hover card (file name, "Memory usage") on camera
    // (2026-11-10 walkthrough, N04b).
    await sleep(80 + Math.random() * 100);
    await this.H.move(w.x + w.w * (0.55 + Math.random() * 0.1), w.y + w.h * (0.5 + Math.random() * 0.1), { w: 200 }).catch(() => {});
    await sleep(120 + Math.random() * 150);
  }

  // Is this page fit to film? 'ok' | 'blank' (about:blank, a new tab, an
  // error page) | 'empty' (loaded, nothing drawn) | 'loading' | 'gone'.
  // 2026-11-11 clips: an about:blank window (N06) and a GitHub tab still
  // "Untitled" (N17) were on camera.
  async pageState(page = this.page) {
    if (!page || page.isClosed()) return 'gone';
    const u = page.url();
    if (!u || /^(about:blank|about:srcdoc|chrome:\/\/newtab|chrome-error:)/.test(u)) return 'blank';
    const st = await Promise.race([
      page.evaluate(() => ({ rs: document.readyState, ct: document.contentType, n: ((document.body && document.body.innerText) || '').trim().length, m: document.querySelectorAll('img,video,canvas,svg,iframe').length })).catch(() => null),
      sleep(800).then(() => null)]);
    if (!st || st.rs === 'loading') return 'loading';
    if (/^(image|video)\//.test(st.ct || '')) return 'ok';
    return st.n || st.m ? 'ok' : 'empty';
  }
  async waitReady(page = this.page, ms = 20000) {
    const end = Date.now() + ms;
    let st = await this.pageState(page);
    while (st !== 'ok' && st !== 'gone' && Date.now() < end) { await sleep(300); st = await this.pageState(page); }
    return st;
  }
  // Leftover about:blank tabs (the window's first tab, a tab that never
  // loaded) closed off camera: Chrome's hover card for one ("about:blank,
  // Memory usage") hung over N11. Never the page in front, never the last tab.
  async closeBlankTabs() {
    if (!this.ctx) return 0;
    let n = 0;
    for (const p of this.ctx.pages()) {
      if (p === this.page || p.isClosed() || !/^about:blank$/.test(p.url())) continue;
      if (this.ctx.pages().filter((x) => !x.isClosed() && x !== p).length < 1) break;
      await p.close().catch(() => {}); n++;
    }
    return n;
  }

  // null when the page is a real page; the system name when it is a sign-in
  // page (or GitHub's 404, which is what a private repo shows when signed out).
  async signinNeeded(page = this.page) {
    const u = page.url();
    for (const [re, name] of SIGNIN) if (re.test(u)) return name;
    if (/^https:\/\/github\.com\//.test(u)) {
      const t = await page.title().catch(() => '');
      if (/Page not found/i.test(t)) return 'GitHub';
    }
    return null;
  }

  async dismiss(page = this.page) {
    let n = 0;
    for (const f of page.frames()) n += await f.evaluate(DISMISS).catch(() => 0);
    return n;
  }

  async ov(fn, ...a) { return this.page.evaluate(([fn, a]) => window.__ck && window.__ck[fn](...a), [fn, a]).catch(() => {}); }

  // A visible element by text / CSS / role, in any frame (the Entra portal is all iframes).
  async find(target, { timeout = 15000, page = this.page } = {}) {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      for (const f of page.frames()) {
        let loc;
        if (target.css) { loc = f.locator(target.css); if (target.hasText) loc = loc.filter({ hasText: target.hasText instanceof RegExp ? target.hasText : new RegExp(target.hasText, 'i') }); if (target.last) loc = loc.last(); }
        else if (target.role) loc = f.getByRole(target.role, { name: target.name, exact: target.exact ?? false });
        else if (target.placeholder) loc = f.getByPlaceholder(target.placeholder);
        else loc = f.getByText(target.re ? new RegExp(target.re, 'i') : target.text, { exact: target.exact ?? false });
        const n = Math.min(await loc.count().catch(() => 0), 30);
        for (let i = 0; i < n; i++) {
          const el = loc.nth(target.nth ?? i);
          if (await el.isVisible().catch(() => false)) {
            let bb = await el.boundingBox().catch(() => null);
            if (bb && bb.width > 0) {
              if (target.row) {
                const rb = await el.locator('xpath=ancestor::*[@role="row" or self::tr][1]').boundingBox().catch(() => null);
                if (rb && rb.width > bb.width) bb = { x: rb.x, width: rb.width, y: bb.y - 6, height: bb.height + 12 };
              }
              if (target.block) {
                const b2 = await el.locator(`xpath=ancestor::*[self::${target.block}][1]`).boundingBox().catch(() => null);
                if (b2) bb = b2;
              }
              return { el, bb, frame: f };
            }
          }
          if (target.nth != null) break;
        }
      }
      await sleep(200);
    }
    throw new Error(`not on the page: ${describe(target)}`);
  }

  get vh() { return this.page.viewportSize()?.height || this.height - 120; }
  async viewport() { return this.page.evaluate(() => ({ w: innerWidth, h: innerHeight, dpr: devicePixelRatio, outerW: outerWidth, outerH: outerHeight })); }

  // ---- the pointer ----------------------------------------------------------
  // With the real-pointer driver (lib/human.mjs, set by the engine as
  // this.human) the SYSTEM cursor moves, clicks, scrolls and types; the drawn
  // in-page pointer is never shown. Without it (--mouse dom, or no
  // Accessibility access) everything is as before: the drawn pointer glides,
  // Playwright clicks.
  get H() { return this.human && this.human.real && !this.human.guide ? this.human : null; }
  get G() { return this.human && this.human.guide ? this.human : null; }

  // Page coordinates (CSS px of the main frame, what boundingBox gives) to
  // screen points. zoom = devicePixelRatio / the display's backing scale
  // (Chrome at 125% on a 2x Retina display: 2.5 / 2); the page's top is the
  // window's bottom minus the page's height (what is above it is Chrome's
  // tab strip and toolbar). The window's place comes from the macOS window
  // list (its real place, on whichever display), not from the page.
  async toScreen(bb, page = this.page) {
    const pid = this.pid(); if (!pid) throw new Error('no window for this browser');
    const [w, v] = await Promise.all([this.human.win(pid), page.evaluate(() => ({ iw: innerWidth, ih: innerHeight, dpr: devicePixelRatio }))]);
    const z = v.dpr / w.scale, bar = w.h - v.ih * z;
    if (!(z > 0.3 && z < 4) || !(bar >= 0 && bar < 240)) throw new Error(`the window's geometry does not add up (toolbar ${Math.round(bar)} pt, zoom ${z.toFixed(2)})`);
    const top = w.y + bar, left = w.x + Math.max(0, (w.w - v.iw * z) / 2);
    return { x: left + bb.x * z, y: top + bb.y * z, w: (bb.width || 0) * z, h: (bb.height || 0) * z, z, front: w.front, win: w, bar };
  }
  // Where a hand would put the pointer on a thing: near the middle of a small
  // one, toward the start of a long one, never twice on the same pixel.
  _spot(bb) {
    const x = bb.x + Math.min(bb.width / 2, 60) + (Math.random() * 2 - 1) * Math.min(bb.width * 0.12, 7);
    const y = bb.y + bb.height / 2 + (Math.random() * 2 - 1) * Math.min(bb.height * 0.18, 3);
    return { x, y };
  }
  _hint(target, verb = 'Click') {
    const t = target.name instanceof RegExp ? '' : (target.text || target.name || target.placeholder || '');
    return t && String(t).length <= 40 ? `${verb} “${t}”` : `${verb} here`;
  }
  async _rect(target, opts) { const f = await this.find(target, { ...opts, timeout: 3000 }); const s = await this.toScreen(f.bb); return { x: s.x, y: s.y, w: s.w, h: s.h }; }

  // Scroll the element into the middle, like a person: real trackpad flicks
  // over the page (the old way: Playwright wheel turns).
  async reveal(target, opts) {
    let f = await this.find(target, opts);
    const vp = await this.viewport();
    // Sideways (wide portal blades): the page brings it into view first. With
    // the real pointer only when it really is off to the side (that jump is
    // instant, a person's scroll isn't).
    const sideways = f.bb.x < 0 || f.bb.x + Math.min(f.bb.width, 40) > vp.w;
    if (!this.human?.real || sideways) { await f.el.scrollIntoViewIfNeeded({ timeout: 3000 }).catch(() => {}); f = await this.find(target, opts); }
    const out = () => f.bb.y < 80 || f.bb.y + f.bb.height > vp.h - 80;
    if (out() && this.G) {
      // Guide: he scrolls. A hint at the pointer; after 20 s the cockpit does it.
      const down = f.bb.y > vp.h / 2;
      const p = await this.G.pos().catch(() => null);
      if (p) await this.G.ghost({ x: p.x - 10, y: p.y - 10, w: 20, h: 20 }, down ? 'Scroll down ↓' : 'Scroll up ↑').catch(() => {});
      for (const end = Date.now() + 20000; out() && Date.now() < end && this.G;) { await sleep(500); f = await this.find(target, opts); }
      await this.human.ghostOff().catch(() => {});
    }
    for (let k = 0; k < 8 && out(); k++) {
      const dy = f.bb.y + f.bb.height / 2 - vp.h * 0.45;
      const px = Math.min(f.bb.x + 40, vp.w - 40), py = vp.h * 0.5;
      let done = false;
      if (this.human?.real) {
        try {
          const s = await this.toScreen({ x: px, y: py });
          const p = await this.human.pos();
          const far = Math.hypot(p.x - s.x, p.y - s.y) > 160 || p.y < s.y - (py * s.z) || p.y > s.y + (vp.h - py) * s.z;
          await this.human.scroll(dy * s.z, far ? { x: s.x + (Math.random() - 0.5) * 60, y: s.y + (Math.random() - 0.5) * 80 } : {});
          done = true;
        } catch (e) { this.log(`pointer: real scroll not possible (${e.message})`); }
      }
      if (!done) {
        await this.page.mouse.move(px, py);
        for (let i = 0; i < Math.abs(dy) / 80; i++) { await this.page.mouse.wheel(0, Math.sign(dy) * 80); await sleep(30); }
      }
      await sleep(250); f = await this.find(target, opts);
    }
    return f;
  }

  // widen: stretch the box right over the value next to a label (portal
  // property pages aren't tables, so there is no row to take).
  // A tour is stepped through one Next per pass: up to 8 passes.
  async dismissAll() { for (let k = 0; k < 8; k++) { if (!(await this.dismiss().catch(() => 0))) break; await new Promise((r) => setTimeout(r, 500)); } }

  async highlight(target, tag = '', opts) {
    await this.dismissAll(); const { bb } = await this.reveal(target, opts); const w = bb.width + (target.widen || 0); await this.ov('ring', bb.x, bb.y, w, bb.height, tag);
    // Preview 3, Okta: a page's CSP blocked the overlay's styles and it drew
    // as raw text. The step fails rather than film that.
    const ok = await this.page.evaluate(() => { const r = document.getElementById('__ck_root'); return !!r && getComputedStyle(r).position === 'fixed'; }).catch(() => false);
    if (!ok) throw new Error('the highlight overlay did not render on this page (its content security policy blocks it)');
    return bb;
  }
  async unhighlight() { await this.ov('unring'); }

  async pointAt(target, opts) {
    const r = await this.reveal(target, opts);
    const { x, y } = this._spot(r.bb);
    if (this.G) {
      const res = await this.G.guideHover(() => this._rect(target, opts), opts?.hint || this._hint(target, 'Point at')).catch(() => 'timeout');
      if (res === 'hovered' || res === 'timeout' || res === 'guide') return { ...r, x, y };
    }
    if (this.H) {
      try {
        const s = await this.toScreen({ x, y });
        await this.H.move(s.x, s.y, { w: Math.min(r.bb.width, r.bb.height) * s.z });
        await sleep(70 + Math.random() * 110);
        return { ...r, x, y, screen: s };
      } catch (e) { this.log(`pointer: real move not possible (${e.message}): drawn pointer`); }
    }
    await this.ov('cursor', x, y); await sleep(750);
    return { ...r, x, y };
  }

  // A real click: the hand travels, lands, the target is measured again (a
  // page that moved meanwhile is followed), a short settle, press, release.
  async click(target, opts) {
    if (this.G) {
      await this.reveal(target, opts);
      const res = await this.G.guideClick(() => this._rect(target, opts), opts?.hint || this._hint(target)).catch((e) => { this.log(`guide: ${e.message}`); return 'dom'; });
      if (res === 'clicked') return;
      // Switched out of guide while waiting: done the other way.
    }
    if (this.H) {
      const r = await this.reveal(target, opts);
      let { x, y } = this._spot(r.bb);
      try {
        let s = await this.toScreen({ x, y });
        const w = Math.min(r.bb.width, r.bb.height) * s.z;
        await this.H.move(s.x, s.y, { w });
        const f2 = await this.find(target, { ...opts, timeout: 3000 }).catch(() => null);
        if (f2 && !(x >= f2.bb.x && x <= f2.bb.x + f2.bb.width && y >= f2.bb.y && y <= f2.bb.y + f2.bb.height)) {
          ({ x, y } = this._spot(f2.bb)); s = await this.toScreen({ x, y }); await this.H.move(s.x, s.y, { w });
        }
        await this.H.click(undefined, undefined, { pid: this.pid() });
        this.ov('ripple', x, y);
        return;
      } catch (e) { this.log(`pointer: real click not possible (${e.message}): Playwright click`); }
      await r.el.click({ timeout: 10000 });
      return;
    }
    const { el, x, y } = await this.pointAt(target, opts);
    await this.ov('ripple', x, y); await sleep(150);
    await el.click({ timeout: 10000 });
  }

  // Typing: real keys, a person's rhythm, into the field just clicked, only
  // while this window is in front (else the rest goes in through Playwright,
  // which can only reach this page). synthetic: always Playwright (sign-in
  // pages: nothing typed there may ever land in another window).
  async type(target, text, { delay = 70, clear = false, synthetic = false } = {}) {
    if (this.human?.real && !synthetic) {
      const { el } = await this.find(target);
      const before = clear ? '' : await el.inputValue().catch(() => null);
      if (this.G) {
        await this.click(target, { hint: `Click, then type “${text.length > 30 ? text.slice(0, 30) + '…' : text}”` });
        if (this.G) {
          const r = await this._rect(target).catch(() => null);
          if (r) await this.G.ghost(r, `Type: ${text.length > 40 ? text.slice(0, 40) + '…' : text}`).catch(() => {});
          const want = (before ?? '') + text;
          for (const end = Date.now() + 60000; Date.now() < end && this.G;) { const v = await el.inputValue().catch(() => ''); if (v === want || (!clear && v.endsWith(text))) break; await sleep(400); }
          await this.human.ghostOff().catch(() => {});
          const v = await el.inputValue().catch(() => '');
          if (v === want || (!clear && v.endsWith(text))) return;
          this.log('guide: the text is not in the field yet: the cockpit types it');
          await el.fill(want).catch(() => {});
          return;
        }
      } else await this.click(target);
      const pid = this.pid();
      try {
        if (!this.H) throw new Error('the real pointer is off');
        await sleep(120 + Math.random() * 200);
        if (clear) { await this.H.key('a', ['cmd'], { pid }); await sleep(80 + Math.random() * 120); await this.H.key('backspace', [], { pid }); }
        await this.H.type(text, { pid, mean: this.human.constructor.mean(delay) });
        return;
      } catch (e) { this.log(`typing: ${e.message}: the text goes in through Playwright`); }
      if (before != null) await el.fill(before + text); else { await el.focus(); await this.page.keyboard.type(text, { delay: 30 }); }
      return;
    }
    const { el } = await this.pointAt(target);
    await el.click({ timeout: 10000 });
    if (clear) { await this.page.keyboard.press('Meta+A'); await this.page.keyboard.press('Backspace'); }
    for (const ch of text) { await this.page.keyboard.type(ch); await sleep(Math.round(delay * (0.6 + Math.random() * 0.8))); }
  }
  async focusBox(target) {
    if (this.human?.real) { await this.click(target); return; }
    const { el } = await this.pointAt(target); await el.click({ timeout: 10000 }); await this.ov('hideCursor');
  }

  async scrollTop() {
    if (this.H) {
      try {
        const y = await this.page.evaluate(() => scrollY);
        if (y > 0) {
          const vp = await this.viewport();
          const s = await this.toScreen({ x: vp.w * (0.35 + Math.random() * 0.3), y: vp.h * (0.4 + Math.random() * 0.2) });
          await this.H.scroll(-y * s.z, { x: s.x, y: s.y });
          await sleep(300);
        }
        if (!(await this.page.evaluate(() => scrollY).catch(() => 0))) return;
      } catch (e) { this.log(`pointer: real scroll not possible (${e.message})`); }
    }
    await this.page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' })).catch(() => {});
  }

  // Before a page change in a window that is already showing a page: the
  // hand goes up toward the tab strip and address bar, as a person's does to
  // open the next page.
  async reachForToolbar() {
    if (!this.H || !this.page || this.page.isClosed() || /^about:/.test(this.page.url())) return;
    try {
      const vp = await this.viewport();
      const s = await this.toScreen({ x: vp.w * (0.18 + Math.random() * 0.3), y: 0 });
      if (!s.front) return;
      await this.H.move(s.x, s.y - s.bar * (0.35 + Math.random() * 0.25), { w: 160 });
      await sleep(80 + Math.random() * 120);
    } catch {}
  }

  async startStopwatch(t0 = Date.now()) {
    this.stopwatchT0 = t0;
    for (const p of this.ctx?.pages() || []) await p.evaluate((t) => window.__ck && window.__ck.stopwatch(t), t0).catch(() => {});
  }
  async stopStopwatch() {
    this.stopwatchT0 = null;
    for (const p of this.ctx?.pages() || []) await p.evaluate(() => window.__ck && window.__ck.stopwatch(0)).catch(() => {});
  }

  async shot(name, page = this.page) {
    if (!this.shotsDir || !page) return null;
    fs.mkdirSync(this.shotsDir, { recursive: true });
    const f = path.join(this.shotsDir, `${name}.png`);
    await page.screenshot({ path: f }).catch((e) => this.log(`screenshot ${name}: ${e.message}`));
    return f;
  }

  // A separate, clean window for signing in AS a demo person (Sam, Ava): a
  // fresh Chrome with no cookies, so the owner's admin session is untouched.
  async privateWindow() {
    if (this.priv?.page && !this.priv.page.isClosed()) return this.priv;
    // Its pid (for the stage): the one new top-level Chrome process.
    const tops = () => { try { return execFileSync('pgrep', ['-f', 'playwright_chromiumdev_profile'], { encoding: 'utf8' }).trim().split('\n').filter((p) => p && !/--type=/.test(execFileSync('ps', ['-o', 'command=', '-p', p], { encoding: 'utf8' }))).map(Number); } catch { return []; } };
    const before = new Set(tops());
    const b = await chromium.launch({ channel: 'chrome', headless: false, ignoreDefaultArgs: ['--enable-automation', '--no-sandbox'],
      args: [`--window-size=${this.width},${this.height}`, '--window-position=0,0', '--no-first-run'] });
    const ctx = await b.newContext({ viewport: null });
    await ctx.addInitScript(OVERLAY);
    const page = await ctx.newPage();
    this.priv = { browser: b, ctx, page, pid: tops().find((p) => !before.has(p)) || null };
    return this.priv;
  }
  async closePrivate() { try { await this.priv?.browser.close(); } catch {} this.priv = null; }

  async close() { await this.closePrivate(); try { await this.ctx?.close(); } catch {} this.ctx = null; }
}

export function describe(t) { return t.text || t.re || t.css || t.placeholder || `${t.role} "${t.name}"`; }
