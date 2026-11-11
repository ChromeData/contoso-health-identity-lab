// The real pointer and keyboard (tools/human-input.swift): the cockpit moves
// the SYSTEM cursor, the one OBS records, with a person's motion, and types
// and scrolls like one. Three modes, chosen with --mouse and switchable live
// (POST /api/mouse?mode=..., /api/guide toggles guide):
//
//   human  (default) the cockpit drives the real pointer and keyboard.
//   guide  the cockpit shows the presenter where to go next (a ghost arrow,
//          a pulsing target and a short hint, drawn in a window that screen
//          capture leaves out) and waits for HIS click there.
//   dom    the old way: a drawn in-page pointer and Playwright clicks
//          (also the automatic fallback when the helper can't post events).
//
// Every real click and keystroke is guarded: the window under the pointer
// (or in front, for keys) must belong to the target window's process, or the
// action falls back to Playwright, which can only ever reach that page.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

const here = path.dirname(new URL(import.meta.url).pathname);
const SRC = path.join(here, '..', 'tools', 'human-input.swift');
const BIN = path.join(here, '..', 'tools', 'human-input');
export const MODES = ['human', 'guide', 'dom'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = (a, b) => a + Math.random() * (b - a);
// An expert user's hand: still curved, eased and slightly uneven, but brisk
// (owner, 2026-11-10 #2). COCKPIT_HAND_SPEED=1 is the old pace.
const SPEED = +(process.env.COCKPIT_HAND_SPEED || 1.3);

export class Human {
  constructor({ log = console.log, mode = 'human' } = {}) {
    this.log = log; this.want = MODES.includes(mode) ? mode : 'human'; this.mode = this.want;
    this.proc = null; this.n = 0; this.wait = new Map(); this.ok = false; this.trusted = false;
  }
  // Pointer and keys go through the helper (human or guide).
  get real() { return this.ok && this.mode !== 'dom'; }
  get guide() { return this.ok && this.mode === 'guide'; }

  build() {
    if (fs.existsSync(BIN) && fs.statSync(BIN).mtimeMs >= fs.statSync(SRC).mtimeMs) return;
    execFileSync('swiftc', ['-O', SRC, '-o', BIN], { stdio: 'ignore', timeout: 240000 });
  }

  async start() {
    if (this.want === 'dom') { this.mode = 'dom'; return this; }
    if (this.proc) return this;
    try { this.build(); } catch (e) { return this.down(`could not build tools/human-input (${e.message.split('\n')[0]})`); }
    this.proc = spawn(BIN, [], { stdio: ['pipe', 'pipe', 'ignore'] });
    this.proc.on('exit', () => { this.proc = null; this.ok = false; for (const [, w] of this.wait) w.reject(new Error('human-input exited')); this.wait.clear(); });
    readline.createInterface({ input: this.proc.stdout }).on('line', (l) => {
      let j; try { j = JSON.parse(l); } catch { return; }
      const w = this.wait.get(j.id); if (!w) return;
      this.wait.delete(j.id); clearTimeout(w.t);
      if (j.ok) w.resolve(j); else w.reject(new Error(j.error || 'failed'));
    });
    try {
      const h = await this.raw('hello', {}, 10000);
      this.trusted = !!h.trusted; this.screens = h.screens;
      if (!h.trusted) return this.down('macOS has not given Accessibility access to the app that started the cockpit (System Settings > Privacy & Security > Accessibility: turn on Terminal / iTerm / Visual Studio Code, whichever ran "node cockpit.mjs")');
      this.ok = true; this.mode = this.want;
      this.log(`pointer: ${this.mode === 'guide' ? 'GUIDE mode: you click, the cockpit shows where' : 'the real pointer, moved like a person'} (${h.screens.map((s) => `${s.name} ${s.w}x${s.h}@${s.scale}x`).join(', ')})`);
    } catch (e) { return this.down(`human-input did not answer (${e.message})`); }
    return this;
  }
  down(why) { this.ok = false; this.mode = 'dom'; this.log(`pointer: falling back to the drawn pointer: ${why}`); try { this.proc?.kill(); } catch {} this.proc = null; return this; }
  stop() { try { this.proc?.stdin.end(); this.proc?.kill(); } catch {} this.proc = null; this.ok = false; }

  setMode(m) {
    if (!MODES.includes(m)) throw new Error(`mouse mode must be one of ${MODES.join(', ')}`);
    this.want = m;
    if (m !== 'dom' && !this.ok) { this.log(`pointer: ${m} needs the helper, which is not running: staying on dom`); return this.mode; }
    if (this.mode === 'guide' && m !== 'guide') this.ghostOff().catch(() => {});
    this.mode = m; this.log(`pointer: mode ${m}`);
    return m;
  }

  raw(cmd, args = {}, timeout = 60000) {
    if (!this.proc) return Promise.reject(new Error('human-input is not running'));
    const id = ++this.n;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.wait.delete(id); reject(new Error(`human-input ${cmd}: timed out`)); }, timeout);
      this.wait.set(id, { resolve, reject, t });
      this.proc.stdin.write(JSON.stringify({ id, cmd, ...args }) + '\n');
    });
  }
  cancel() { return this.proc ? this.raw('cancel', { upTo: this.n + 1 }, 3000).catch(() => {}) : Promise.resolve(); }

  pos() { return this.raw('pos'); }
  win(pid) { return this.raw('win', { pid }, 8000); }
  move(x, y, { w = 30, speed = SPEED } = {}) { return this.raw('move', { x, y, w, speed }); }
  click(x, y, { w = 30, pid = 0, count = 1, speed = SPEED } = {}) { return this.raw('click', { x, y, w, pid, count, speed }); }
  scroll(dy, { x, y, dx = 0 } = {}) { return this.raw('scroll', { dy, dx, ...(x != null ? { x, y } : {}) }, 120000); }
  type(text, { pid = 0, mean = 150 } = {}) { return this.raw('type', { text, pid, mean }, 30000 + text.length * 2000); }
  key(key, mods = [], { pid = 0 } = {}) { return this.raw('key', { key, mods, pid }); }
  // The guide's ghost (hidden from screen capture unless COCKPIT_GHOST_CAPTURE=1).
  ghost(r, hint = '', from = null) { return this.raw('ghost', { x: r.x, y: r.y, w: r.w, h: r.h, hint, ...(from ? { fx: from.x, fy: from.y } : {}), capture: process.env.COCKPIT_GHOST_CAPTURE === '1' }, 5000); }
  ghostOff() { return this.proc ? this.raw('ghostOff', {}, 5000) : Promise.resolve(); }
  waitClick(r, timeout = 1000) { return this.raw('waitclick', { x: r.x, y: r.y, w: r.w, h: r.h, timeout }, timeout + 5000); }
  waitHover(r, timeout = 1000, dwell = 250) { return this.raw('waithover', { x: r.x, y: r.y, w: r.w, h: r.h, timeout, dwell }, timeout + 5000); }

  // Typing speed from the old per-key delay (ms): a person's 50-90 wpm.
  static mean(delay = 70) { return Math.min(190, Math.max(95, delay * 1.7)); }

  // Switching windows, as a person does it: the hand leaves what it was on
  // (a short drift toward the top of the screen, where tabs and title bars
  // are) and there is a beat before the next window is there. No Dock and no
  // Cmd-Tab: both would show every app on this Mac.
  async beforeSwitch() {
    if (!this.real || this.guide) { await sleep(rnd(250, 450)); return; }
    try {
      const p = await this.pos();
      const s = (this.screens || []).find((d) => p.x >= d.x && p.x < d.x + d.w && p.y >= d.y && p.y < d.y + d.h) || this.screens?.[0];
      if (s) await this.move(Math.min(s.x + s.w - 40, Math.max(s.x + 40, p.x + rnd(-160, 160))), s.y + rnd(60, 110), { w: 120, speed: SPEED * rnd(0.9, 1.15) });
    } catch {}
    await sleep(rnd(90, 180));
  }
  async afterSwitch() { await sleep(rnd(80, 160)); }

  // Guide mode: show where to click and wait for the person's own click there.
  // rect() gives the current screen rectangle (it is re-read now and then, the
  // page may move); returns 'clicked', or the mode it was switched to.
  async guideClick(rect, hint = 'Click here') {
    let r = await rect(); let k = 0;
    await this.ghost(r, hint).catch(() => {});
    try {
      while (this.mode === 'guide') {
        const res = await this.waitClick(r, 900).catch(() => ({ hit: false }));
        if (res.hit) return 'clicked';
        if (++k % 3 === 0) { const r2 = await rect().catch(() => null); if (r2 && (Math.abs(r2.x - r.x) > 3 || Math.abs(r2.y - r.y) > 3)) { r = r2; await this.ghost(r, hint).catch(() => {}); } }
      }
      return this.mode;
    } finally { await this.ghostOff().catch(() => {}); }
  }
  async guideHover(rect, hint = 'Point here', timeout = 20000) {
    const r = await rect();
    await this.ghost(r, hint).catch(() => {});
    try {
      for (const end = Date.now() + timeout; Date.now() < end && this.mode === 'guide';) if ((await this.waitHover(r, 900).catch(() => ({}))).hit) return 'hovered';
      return this.mode === 'guide' ? 'timeout' : this.mode;
    } finally { await this.ghostOff().catch(() => {}); }
  }
}
