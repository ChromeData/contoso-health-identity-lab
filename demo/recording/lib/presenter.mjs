// The presenter's view (tools/script-overlay.swift), in every mode: a card at
// the top centre of the screen, under the camera, that screen capture never
// sees. It is fed the engine's state (and the speech tracker's points) and
// sends back the global hotkeys (next, back, redo, pause).
//
// Light on the card:
//   green  talk (the screen is up, or the hand is moving with your words)
//   amber  the cockpit is busy: loading a page, waiting on GitHub/Microsoft
//   red    it needs you: a failed step, a hand step, the presenter's pause
// Unattended runs (--watch) have no speech tracker: each point is ticked off
// by the narration clip's clock instead.
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { pointsFor, loadPointsFile } from './points.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const SRC = path.join(here, '..', 'tools', 'script-overlay.swift');
const BIN = path.join(here, '..', 'tools', 'script-overlay');

export function buildOverlay() {
  if (fs.existsSync(BIN) && fs.statSync(BIN).mtimeMs >= fs.statSync(SRC).mtimeMs) return BIN;
  execFileSync('swiftc', ['-O', SRC, '-o', BIN], { stdio: 'ignore', timeout: 240000 });
  return BIN;
}

const clean = (t) => String(t || '').replace(/\[[^\]]*\]/g, ' ').replace(/\s+/g, ' ').trim();
const short = (t, n = 26) => { const x = clean(t); return x.length > n ? `${x.slice(0, n - 1)}…` : x; };

export class Presenter {
  constructor(ck, { root, log = console.log, clicker = false, compact = false, ready = null } = {}) {
    Object.assign(this, { ck, root, log, clicker, compact });
    this.pfile = loadPointsFile(root);
    this.readyText = ready;   // before the first step: e.g. "READY"
    this.proc = null; this.last = '';
  }
  start() {
    let bin;
    try { bin = buildOverlay(); } catch (e) { this.log(`presenter card: could not build tools/script-overlay (${e.message.split('\n')[0]})`); return this; }
    this.proc = spawn(bin, this.clicker ? ['--clicker'] : [], { stdio: ['pipe', 'pipe', 'ignore'] });
    this.proc.on('exit', () => { this.proc = null; });
    readline.createInterface({ input: this.proc.stdout }).on('line', (l) => {
      let j; try { j = JSON.parse(l); } catch { return; }
      if (j.warn) this.log(`presenter card: ${j.warn}`);
      if (j.key) this.key(j.key);
    });
    this.off = this.ck.on(() => this.push());
    this.timer = setInterval(() => this.push(), 250);   // the narration clock ticks points off
    this.push(true);
    return this;
  }
  key(k) {
    const ck = this.ck;
    const acts = { next: () => ck.next(), back: () => ck.back(), redo: () => ck.redo(), pause: () => ck.togglePause() };
    if (!acts[k]) return;
    this.log(`presenter card: ${k}`);
    acts[k]().catch((e) => this.log(`presenter card ${k}: ${e.message}`));
  }
  send(o) { try { this.proc?.stdin.write(JSON.stringify(o) + '\n'); } catch {} }

  // Each point of the step: done / missed / hot (the one to say now) / todo.
  points(st) {
    const s = this.ck.list?.[st.i]; if (!s) return [];
    const pts = pointsFor(s, this.pfile).map((p) => ({ text: clean(p.text) }));
    const sp = st.speech;
    if (sp && sp.allowed && sp.points?.length === pts.length && sp.status !== 'off') {
      pts.forEach((p, k) => { p.state = sp.points[k].state; });
    } else if (this.ck.unattended && this.ck.narration?.[s.id]?.dur && st.lineStarted && st.lineStarted >= (this.stepAt || 0) - 1000) {
      // The narration's clock: each point's share of the clip.
      const dur = this.ck.narration[s.id].dur * 1000, t = Date.now() - st.lineStarted;
      const tot = pts.reduce((n, p) => n + p.text.length, 0) || 1;
      let acc = 0;
      pts.forEach((p) => { acc += p.text.length; p.state = t >= (acc / tot) * dur ? 'done' : 'todo'; });
    } else pts.forEach((p) => { p.state = 'todo'; });
    const hot = pts.findIndex((p) => p.state === 'todo' || p.state === 'missed');
    if (hot >= 0 && pts[hot].state === 'todo') pts[hot].state = 'hot';
    return pts;
  }
  light(st) {
    if (st.held) return ['red', 'Paused'];
    if (st.light?.color === 'red' || st.error) return ['red', st.step?.hand && !st.error ? 'Your hand' : 'Needs you'];
    if (st.i < 0) return st.preflight?.running ? ['amber', 'Preflight'] : ['green', this.readyText || 'READY'];
    if (st.done) return ['green', 'All done'];
    if (st.light?.color === 'yellow') return ['amber', short(st.light.text.split(/[·:]/)[0], 22) || 'Waiting'];
    if (st.cue) return [st.cue.color, st.cue.reason];
    if (st.busy) return ['amber', 'Working'];
    return ['green', 'Talk'];
  }
  push(force = false) {
    if (!this.proc) return;
    let st; try { st = this.ck.state(); } catch { return; }
    if (st.i !== this.lastI) { this.lastI = st.i; this.stepAt = Date.now(); }
    const s = st.step, piece = s ? `N${String(s.piece).replace('.5', 'b').padStart(2, '0')} · ${s.pieceTitle || ''}` : (st.i < 0 ? 'Contoso recording cockpit' : '');
    const [light, reason] = this.light(st);
    const sp = st.speech;
    const o = {
      part: piece,
      step: s ? `step ${st.inPiece?.k || 1} of ${st.inPiece?.n || 1} · ${st.i + 1} / ${st.total}` : `${st.total} steps`,
      partProg: st.inPiece ? st.inPiece.k / st.inPiece.n : 0,
      points: s ? this.points(st) : (st.next ? [{ text: clean(st.next.say), state: 'hot' }] : []),
      next: st.next && s ? clean(st.next.say) : '', nextNew: !!st.next?.newPiece,
      light, reason,
      resay: sp?.lastMissed ? `${sp.lastMissed.n} point${sp.lastMissed.n > 1 ? 's' : ''} to re-say in ${sp.lastMissed.id}` : '',
      banner: st.error ? short(st.error, 110) : (s?.hand ? `You: ${short(s.hand, 100)}` : ''),
      t0: st.takeT0 || 0, paused: !!st.held, pausedAt: st.heldAt || 0,
    };
    const j = JSON.stringify(o);
    if (!force && j === this.last) return;
    this.last = j;
    this.send(o);
  }
  stop() { clearInterval(this.timer); this.off?.(); this.send({ hide: true }); try { this.proc?.kill('SIGTERM'); } catch {} this.proc = null; }
}

export function attachPresenter(ck, opts) { return new Presenter(ck, opts).start(); }
