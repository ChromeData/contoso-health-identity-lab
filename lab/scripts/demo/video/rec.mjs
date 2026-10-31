// Recorder library for the lab demo video. Each scene is recorded as one
// browser page (Playwright recordVideo). Every narration beat has a `prep`
// (navigate, wait, dismiss pop-ups: cut from the final video) and a `run`
// (what the viewer sees while the beat's narration plays). The recorder writes
// a timeline of beat windows in video time; assemble.py cuts and muxes them.
//
// Nothing secret is recorded: the admin session comes from a storageState file
// (chmod 600, gitignored), GUIDs and public IPs are blurred on every page, and
// the live PIM demo signs in with a one-time Temporary Access Pass read from
// the macOS Keychain inside this process.
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const here = path.dirname(new URL(import.meta.url).pathname);
const req = createRequire(path.join(here, '../../../setup/signup-assist/package.json'));
export const { chromium } = req('playwright');
export const REPO = path.resolve(here, '../../../..');
export const OUT = path.join(REPO, 'lab/evidence/out/video');
export const STATE = path.join(OUT, 'state/admin.json');
export const FFMPEG = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
export const CDP = process.env.VIDEO_CDP || 'http://127.0.0.1:9222';
const W = 1920, H = 1080;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- in-page overlay: lower-third chip, highlight ring, cursor, redaction ----
const OVERLAY = `(() => {
  const isTop = window.top === window;
  const GUID = /\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b/i;
  const PUBIP = /\\b(?!10\\.)(?!192\\.168\\.)(?!172\\.(?:1[6-9]|2\\d|3[01])\\.)(?!127\\.)(?:\\d{1,3}\\.){3}\\d{1,3}\\b/;
  const SUB = /\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-/i;   // truncated GUIDs too
  const IP6 = /\\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\\b/i;
  function redact(root) {
    if (window.__vNoRedact) return;
    const w = document.createTreeWalker(root || document.body, NodeFilter.SHOW_TEXT);
    let n; while ((n = w.nextNode())) {
      const t = n.nodeValue; if (!t || t.length > 400) continue;
      if (GUID.test(t) || PUBIP.test(t) || SUB.test(t) || IP6.test(t)) { const p = n.parentElement; if (p && !p.closest('#__v_root')) p.style.filter = 'blur(6px)'; }
    }
    for (const i of document.querySelectorAll('input')) { const v = i.value || ''; if (GUID.test(v) || PUBIP.test(v)) i.style.filter = 'blur(6px)'; }
  }
  let pend = false;
  const obs = new MutationObserver(() => { if (pend) return; pend = true; requestAnimationFrame(() => { pend = false; try { redact(); } catch {} }); });
  function boot() {
    if (!document.body) return;
    try { redact(); } catch {}
    obs.observe(document.body, { subtree: true, childList: true, characterData: true });
    if (!isTop || document.getElementById('__v_root')) return;
    const st = document.createElement('style');
    st.textContent = \`
      #__v_root{position:fixed;inset:0;pointer-events:none;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",sans-serif}
      #__v_chip{position:absolute;left:28px;bottom:28px;display:flex;align-items:center;gap:14px;background:rgba(23,23,28,.92);color:#fff;border-radius:999px;padding:12px 26px 12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.28);opacity:0;transform:translateY(12px);transition:opacity .45s,transform .45s}
      #__v_chip.on{opacity:1;transform:none}
      #__v_chip .dot{width:30px;height:30px;border-radius:50%;background:#2A2A30;display:grid;place-items:center}
      #__v_chip .dot i{width:11px;height:11px;border-radius:50%;border:3px solid #F06A35;box-sizing:content-box;display:block}
      #__v_chip b{font-size:22px;font-weight:700;letter-spacing:-.01em} #__v_chip span{font-size:19px;color:#C9C7C1;margin-left:4px}
      #__v_ring{position:absolute;border:4px solid #F06A35;border-radius:12px;box-shadow:0 0 0 6px rgba(240,106,53,.18),0 0 34px rgba(240,106,53,.45);opacity:0;transition:all .45s cubic-bezier(.2,.8,.2,1)}
      #__v_ring.on{opacity:1}
      #__v_tag{position:absolute;background:#F06A35;color:#fff;font-weight:700;font-size:19px;padding:7px 14px;border-radius:9px;opacity:0;transition:opacity .35s;white-space:nowrap;box-shadow:0 6px 18px rgba(0,0,0,.2)}
      #__v_tag.on{opacity:1}
      #__v_cur{position:absolute;left:0;top:0;width:28px;height:28px;transition:transform .75s cubic-bezier(.3,.7,.2,1);filter:drop-shadow(0 2px 3px rgba(0,0,0,.35))}
      #__v_def{position:absolute;right:28px;top:96px;width:560px;background:rgba(23,23,28,.94);color:#fff;border-radius:16px;padding:16px 22px 18px;box-shadow:0 12px 34px rgba(0,0,0,.32);opacity:0;transform:translateY(-10px);transition:opacity .45s,transform .45s;border-left:5px solid #F06A35}
      #__v_def.on{opacity:1;transform:none} #__v_def.br{top:auto;bottom:28px;right:96px}
      #__v_def small{display:block;font-size:13px;letter-spacing:.14em;color:#F06A35;font-weight:700;margin-bottom:6px}
      #__v_def b{display:block;font-size:24px;font-weight:700;letter-spacing:-.01em;margin-bottom:4px} #__v_def span{font-size:19px;line-height:1.35;color:#DAD8D2}
      #__v_rip{position:absolute;width:44px;height:44px;margin:-22px 0 0 -22px;border-radius:50%;border:3px solid #F06A35;opacity:0}
      #__v_rip.go{animation:vrip .55s ease-out}
      @keyframes vrip{0%{opacity:.9;transform:scale(.3)}100%{opacity:0;transform:scale(1.4)}}
    \`;
    const root = document.createElement('div'); root.id = '__v_root';
    root.innerHTML = '<div id="__v_ring"></div><div id="__v_tag"></div><div id="__v_rip"></div><div id="__v_def"><small>WHAT THAT MEANS</small><b></b><span></span></div>' +
      '<svg id="__v_cur" viewBox="0 0 28 28"><path d="M5 3l17 10.5-7.6 1.6 4.6 8.6-3.3 1.7-4.6-8.6L5 22.6z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg>' +
      '<div id="__v_chip"><div class="dot"><i></i></div><div><b></b><span></span></div></div>';
    document.documentElement.appendChild(st); document.documentElement.appendChild(root);
    const $ = (id) => document.getElementById(id);
    window.__v = {
      chip(t, s) { const c = $('__v_chip'); if (!t) { c.classList.remove('on'); return; } c.querySelector('b').textContent = t; c.querySelector('span').textContent = s ? '· ' + s : ''; c.classList.add('on'); },
      ring(x, y, w, h, tag) { const r = $('__v_ring'), p = 10; Object.assign(r.style, { left: (x - p) + 'px', top: (y - p) + 'px', width: (w + 2 * p) + 'px', height: (h + 2 * p) + 'px' }); r.classList.add('on');
        const g = $('__v_tag'); if (tag) { g.textContent = tag; const ty = y - p - 46 < 8 ? y + h + p + 10 : y - p - 46; g.style.top = ty + 'px'; g.style.left = '0px'; const tw = g.offsetWidth; g.style.left = Math.max(8, Math.min(innerWidth - tw - 8, x + w + p - tw)) + 'px'; g.classList.add('on'); } else g.classList.remove('on'); },
      unring() { $('__v_ring').classList.remove('on'); $('__v_tag').classList.remove('on'); },
      cursor(x, y, instant) { const c = $('__v_cur'); if (instant) { c.style.transition = 'none'; requestAnimationFrame(() => (c.style.transition = '')); } c.style.transform = 'translate(' + (x - 5) + 'px,' + (y - 3) + 'px)'; },
      ripple(x, y) { const r = $('__v_rip'); r.classList.remove('go'); r.style.left = x + 'px'; r.style.top = y + 'px'; void r.offsetWidth; r.classList.add('go'); },
      hideCursor(h) { $('__v_cur').style.opacity = h ? 0 : 1; },
      define(term, text, pos) { const d = $('__v_def'); if (!term) { d.classList.remove('on'); return; } d.querySelector('b').textContent = term; d.querySelector('span').textContent = text; d.classList.toggle('br', pos === 'br'); d.classList.add('on'); },
    };
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();`;

// Pop-ups the portals throw at a fresh context: feedback surveys, MFA notices,
// teaching bubbles. Close them by finding the titled container's close button.
const DISMISS = `(() => {
  const titles = [/Tasks Panel Remains Unchanged/i, /Filter your timeline/i, /Give feedback to Microsoft/i, /Mandatory Azure MFA/i, /Custom columns/i, /How likely are you/i, /We.d love your feedback/i, /Welcome to (the )?Microsoft Defender/i, /What.s new/i];
  let n = 0;
  for (const el of document.querySelectorAll('div,section,aside,[role=dialog]')) {
    const t = el.innerText || ''; if (t.length > 900 || !titles.some((r) => r.test(t))) continue;
    const b = [...el.querySelectorAll('button,[role=button]')].find((b) => /^(close|dismiss|got it|done|×|x)$/i.test((b.getAttribute('aria-label') || b.title || b.innerText || '').trim()) || /close|dismiss/i.test(b.getAttribute('aria-label') || ''));
    if (b) { b.click(); n++; }
  }
  return n;
})()`;

export async function dismiss(page) {
  let n = 0;
  for (const f of page.frames()) n += await f.evaluate(DISMISS).catch(() => 0);
  // Teaching bubbles (Fluent) want a real pointer click on their own button.
  for (const f of page.frames()) {
    const bubbles = f.locator('[role=dialog], .ms-TeachingBubble, [class*="teachingBubble" i]').filter({ hasText: /Tasks Panel|Filter your timeline|Custom columns|Refresh to update the queue/i });
    for (let i = 0; i < Math.min(await bubbles.count().catch(() => 0), 3); i++) {
      const b = bubbles.nth(i).getByRole('button', { name: /^(Done|Got it|Close|Dismiss)$/i }).first();
      if (await b.isVisible().catch(() => false)) { await b.click({ timeout: 3000 }).catch(() => {}); n++; }
    }
  }
  return n;
}

// ---- recorder --------------------------------------------------------------
export class Rec {
  constructor(sceneId, kind, opts = {}) { this.id = sceneId; this.kind = kind; this.opts = opts; this.beats = []; this.cur = { x: W * 0.62, y: H * 0.55 }; this.chipNow = null; }

  async open() {
    this.dir = path.join(OUT, 'raw', this.id);
    fs.rmSync(this.dir, { recursive: true, force: true }); fs.mkdirSync(this.dir, { recursive: true });
    const z = this.opts.zoom || 1;
    const common = { viewport: { width: Math.round(W / z), height: Math.round(H / z) }, deviceScaleFactor: z, recordVideo: { dir: this.dir, size: { width: W, height: H } }, colorScheme: 'light', locale: 'en-US', timezoneId: 'UTC' };
    if (this.kind === 'local') { this.browser = await chromium.launch(); this.ctx = await this.browser.newContext(common); }
    else {
      this.browser = await chromium.connectOverCDP(CDP);
      this.ctx = await this.browser.newContext({ ...common, ...(this.kind === 'portal' ? { storageState: STATE } : {}) });
    }
    await this.ctx.addInitScript(OVERLAY);
    this.page = await this.ctx.newPage();
    // A window smaller than the viewport makes Chrome send undersized screencast
    // frames (grey padding in the video), and new windows reuse the last size.
    // Make the window roomy, then re-apply the viewport and scale.
    if (this.kind !== 'local') {
      const s = await this.ctx.newCDPSession(this.page);
      const { windowId } = await s.send('Browser.getWindowForTarget');
      await s.send('Browser.setWindowBounds', { windowId, bounds: { windowState: 'normal', width: 2000, height: 1300 } });
      const vp = common.viewport;
      await s.send('Emulation.setDeviceMetricsOverride', { width: vp.width, height: vp.height, deviceScaleFactor: z, mobile: false, screenWidth: vp.width, screenHeight: vp.height });
    }
    this.t0 = Date.now();
    // Calibration marker: a magenta frame whose first appearance in the video
    // pins wall-clock time to video time.
    await this.page.setContent('<body style="margin:0;background:#ff00ff"></body>');
    await this.page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    this.tMarker = (Date.now() - this.t0) / 1000;
    await sleep(600);
    return this;
  }

  now() { return (Date.now() - this.t0) / 1000; }
  get scale() { return this.opts.zoom || 1; }

  // Find a visible element by text (or a CSS selector) in any frame.
  async find(target, { timeout = 15000 } = {}) {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      for (const f of this.page.frames()) {
        let loc;
        if (typeof target === 'function') loc = target(f);
        else if (target.css) loc = f.locator(target.css);
        else if (target.role) loc = f.getByRole(target.role, { name: target.name, exact: target.exact ?? false });
        else loc = f.getByText(target.text, { exact: target.exact ?? false });
        const n = await loc.count().catch(() => 0);
        for (let i = 0; i < n; i++) {
          const el = loc.nth(target.nth ?? i);
          if (await el.isVisible().catch(() => false)) {
            let bb = await el.boundingBox().catch(() => null);
            if (bb && bb.width > 0) {
              // Row highlight: the cell's own height, stretched to its row's width.
              if (target.row) {
                const rb = await el.locator('xpath=ancestor::*[@role="row" or self::tr][1]').boundingBox().catch(() => null);
                if (rb && rb.width > bb.width) bb = { x: rb.x, width: rb.width, y: bb.y - 7, height: bb.height + 14 };
              }
              return { el, bb, frame: f };
            }
          }
          if (target.nth != null) break;
        }
      }
      await sleep(400);
    }
    throw new Error(`[${this.id}] not found: ${JSON.stringify(target.text || target.css || target.name || 'fn')}`);
  }

  async ov(fn, ...a) { return this.page.evaluate(([fn, a]) => window.__v && window.__v[fn](...a), [fn, a]).catch(() => {}); }
  async chip() { }
  // Plain-words definition card (top-right on portals, bottom-right on local pages). Cleared at every beat.
  // Definitions and chips are OFF (2026-10-29): terms are said once in the narration and live in lab/docs/glossary.md.
  async define() { }
  async undefine() { this.defNow = null; await this.ov('define', ''); }
  get vh() { return Math.round(H / this.scale); }
  // Bring an element into view with real wheel scrolling (on camera, like a person would).
  async reveal(target) {
    let f = await this.find(target);
    for (let k = 0; k < 6 && (f.bb.y < 70 || f.bb.y + f.bb.height > this.vh - 90); k++) {
      const dy = f.bb.y + f.bb.height / 2 - this.vh * 0.5;
      await this.wheel(dy, { x: Math.min(f.bb.x + 40, Math.round(W / this.scale) - 40), y: this.vh * 0.5 }); await sleep(500); f = await this.find(target);
    }
    return f;
  }
  async ring(target, tag) { const { bb } = await this.reveal(target); await this.ov('ring', bb.x, bb.y, bb.width, bb.height, tag || ''); return bb; }
  async unring() { await this.ov('unring'); }
  async move(target, { dx = 0, dy = 0 } = {}) {
    const { el, bb } = await this.reveal(target);
    const x = bb.x + Math.min(bb.width / 2, 60) + dx, y = bb.y + bb.height / 2 + dy;
    await this.ov('cursor', x, y); this.cur = { x, y }; await sleep(800); return { el, bb, x, y };
  }
  async click(target, opts = {}) {
    const { el, x, y } = await this.move(target, opts);
    await this.ov('ripple', x, y); await sleep(150);
    await el.click({ timeout: 10000, ...(opts.force ? { force: true } : {}) });
  }
  async type(target, text, delay = 75) { await this.click(target); await this.page.keyboard.type(text, { delay }); }
  async wheel(dy, at) { const p = at || this.cur; await this.page.mouse.move(p.x, p.y); for (let i = 0; i < Math.abs(dy) / 60; i++) { await this.page.mouse.wheel(0, Math.sign(dy) * 60); await sleep(35); } }
  async goto(url, settle = 9000) {
    for (let a = 0; a < 3; a++) {
      try { await this.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 }); break; }
      catch (e) { console.log(`[${this.id}] goto (try ${a + 1}): ${e.message.split('\n')[0]}`); await sleep(5000); }
    }
    await sleep(settle);
  }
  async settle(ms = 1500) { await dismiss(this.page); await sleep(ms); await dismiss(this.page); }

  // Run one narration beat. prep happens off-camera (cut), run is on-camera.
  async beat(i, dur, { prep, run, minHold = 0 }) {
    if (prep) await prep(this);
    await dismiss(this.page);
    if (this.chipNow) await this.ov('chip', ...this.chipNow);
    this.defNow = null; await this.ov('define', '');
    await this.ov('cursor', this.cur.x, this.cur.y, true);
    await sleep(350);
    const start = this.now();
    if (run) await run(this, { dur, start, until: (frac) => sleep(Math.max(0, (start + frac * dur - this.now()) * 1000)) });
    // Hold for the narration, and always ~1 s after the last on-camera action.
    const left = Math.max(start + Math.max(dur + 0.35, minHold) - this.now(), 1.0);
    await sleep(left * 1000);
    const end = this.now();
    this.beats.push({ i, start, end, dur });
    console.log(`[${this.id}] beat ${i}: ${start.toFixed(2)}-${end.toFixed(2)} (audio ${dur.toFixed(2)}s)`);
  }

  async close() {
    const video = this.page.video();
    await this.page.close();
    const raw = await video.path();
    await this.ctx.close().catch(() => {});
    await this.browser.close().catch(() => {});
    // Locate the calibration marker in the video (first magenta frame).
    const buf = execFileSync(FFMPEG, ['-v', 'error', '-t', '6', '-i', raw, '-vf', 'fps=50,scale=4:4', '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-'], { maxBuffer: 64 << 20 });
    let vMarker = null;
    for (let f = 0; f * 48 < buf.length; f++) { const o = f * 48 + 5 * 3; if (buf[o] > 200 && buf[o + 1] < 70 && buf[o + 2] > 200) { vMarker = f / 50; break; } }
    const offset = vMarker == null ? 0 : vMarker - this.tMarker;
    const tl = { id: this.id, raw, offset, vMarker, tMarker: this.tMarker, beats: this.beats.map((b) => ({ ...b, vStart: b.start + offset, vEnd: b.end + offset })) };
    // Frame check: the bottom-right corner should be page content, not the grey padding.
    tl.padded = [];
    for (const b of tl.beats) {
      const px = execFileSync(FFMPEG, ['-v', 'error', '-ss', ((b.vStart + b.vEnd) / 2).toFixed(2), '-i', raw, '-frames:v', '1', '-vf', 'crop=4:4:1914:1074', '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-']);
      const [r, g, bl] = px; if (Math.abs(r - g) < 6 && Math.abs(g - bl) < 6 && r > 100 && r < 150) tl.padded.push(b.i);
    }
    if (tl.padded.length) console.log(`[${this.id}] WARNING undersized frames in beats ${tl.padded.join(',')} - re-record`);
    fs.writeFileSync(path.join(OUT, 'raw', `${this.id}.timeline.json`), JSON.stringify(tl, null, 2));
    console.log(`[${this.id}] video ${path.basename(raw)} offset ${offset.toFixed(3)}s`);
    return tl;
  }
}

// Keychain read inside this process (never on a command line or in logs).
export const keychain = (svc) => execFileSync('security', ['find-generic-password', '-s', svc, '-w'], { encoding: 'utf8' }).trim();
export function totp(secretB32) {
  const crypto = req('crypto');
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of secretB32.replace(/[\s=]/g, '').toUpperCase()) bits += A.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', key).update(ctr).digest(); const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}
