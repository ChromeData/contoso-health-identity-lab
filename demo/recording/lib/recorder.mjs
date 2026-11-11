// One recording file per piece: ~/contoso-demo/recordings/<date>/NN-piece.mkv
// (+ .mp4 remuxed when the piece ends).
//   OBS (preferred): start / pause on yellow WAIT / resume on green / stop.
//   Fallback when OBS can't be controlled: macOS `screencapture -v` (records
//   the main display + default microphone). It has NO pause, so waits stay in
//   the file and must be cut by hand; the teleprompter says so.
import fs from 'node:fs';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { Obs, CaptureWatch, isRunning, remux, mainDisplayPixels } from './obs.mjs';

const FFMPEG = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const today = () => new Date().toLocaleDateString('en-CA');   // the Mac's local date

export class Recorder {
  // silent: record the screen with the microphone muted (the --preview
  // video gets its narration mixed in afterwards).
  // cursor: the system pointer in the capture (OBS show_cursor); see Obs.setCursor.
  constructor({ root, dir = null, display = '', log = console.log, enabled = true, silent = false, cursor = true }) {
    // dir: a fixed folder (--out), instead of <root>/<today>.
    Object.assign(this, { root, fixedDir: dir, display, log, enabled, silent, cursor });
    this.watch = null; this.stale = false; this.healing = null;
    this.kind = 'none';       // 'obs' | 'screencapture' | 'none'
    this.obs = null; this.proc = null;
    this.piece = null;        // { n, slug, file, startedAt }
    this.paused = false; this.note = '';
    this.files = [];          // finished pieces this session
  }

  get dir() { return this.fixedDir || path.join(this.root, today()); }

  async init() {
    if (!this.enabled) {
      this.kind = 'none'; this.note = 'recording off (dry run / rehearsal without --record)';
      // OBS open anyway (the owner watches its preview): keep its capture live
      // too, or it shows a stopped stream's last frame without the ring/overlays.
      if (isRunning()) {
        try { this.obs = new Obs({ log: this.log }); await this.obs.connect({ launch: false, timeoutMs: 8000 }); await this.obs.refreshCapture(); this.watchCapture(); this.note += '; OBS preview kept live'; }
        catch (e) { this.log(`recorder: OBS preview not refreshed (${e.message})`); this.obs?.close(); this.obs = null; }
      }
      return this;
    }
    try {
      this.obs = new Obs({ log: this.log });
      await this.obs.connect();
      const st = await this.obs.status();
      const sc = st.outputActive ? { capture: await this.obs.captureOk() } : await this.obs.ensureScene({ display: this.display, recordDir: this.dir, cursor: this.cursor });
      if (!st.outputActive) { const px = mainDisplayPixels(); if (px) await this.obs.fitCanvas(px.w, px.h); }
      if (!st.outputActive) await this.obs.refreshCapture().catch((e) => this.log(`recorder: capture refresh: ${e.message}`));
      this.kind = 'obs';
      this.watchCapture();
      this.note = sc.capture ? `OBS ready: scene "Contoso demo" (${sc.display || 'main display'} + microphone)`
        : 'OBS connected, but it cannot see the screen yet: System Settings > Privacy & Security > Screen & System Audio Recording > turn on OBS, then restart OBS';
      this.captureOk = !!sc.capture;
      if (this.silent) { await this.obs.req('SetInputMute', { inputName: 'Microphone', inputMuted: true }).catch((e) => this.log(`recorder: mute: ${e.message}`)); this.muted = true; }
    } catch (e) {
      this.log(`recorder: OBS not available (${e.message}); falling back to screencapture (no pause)`);
      this.obs = null; this.kind = 'screencapture';
      this.note = 'OBS not reachable: recording with macOS screencapture (no pause: cut the waits by hand)';
    }
    return this;
  }

  // OBS never restarts a screen capture stream that macOS stopped (display
  // slept / went offline, error -3805): the take would freeze on one frame and
  // the ring, highlight box and in-page pointer would be missing. Watch OBS's
  // log and restart the stream as soon as it stops.
  watchCapture() {
    this.watch?.stop();
    this.watch = new CaptureWatch({ onStop: (line) => {
      this.stale = true;
      this.log(`recording: OBS screen capture stopped ("${line.replace(/^.*mac-screencapture \]: /, '')}"): restarting it`);
      this.heal().catch(() => {});
    } }).start();
  }

  // Restart the capture until it holds (the display may still be waking up).
  // While a piece records, OBS is paused meanwhile so no frozen frames land
  // in the file.
  heal() {
    if (this.healing) return this.healing;
    const run = async () => {
      const pausedHere = !!(this.piece && !this.paused && this.kind === 'obs');
      if (pausedHere) await this.obs.pause().catch(() => {});
      try {
        for (let k = 0; k < 20; k++) {
          try {
            await this.obs.refreshCapture();
            const again = this.watch?.check() || [];
            if (!again.length && (await this.obs.captureOk())) { await sleep(1000); /* the restarted stream's first frame can be an old one */ this.stale = false; this.log('recording: OBS screen capture running again'); return true; }
          } catch (e) { if (!this.obs?.connected) break; }
          await sleep(3000);
        }
        this.log('recording: OBS screen capture did not come back: check the display is awake, then restart OBS');
        return false;
      } finally { if (pausedHere && this.piece && !this.paused) await this.obs.resume().catch(() => {}); }
    };
    this.healing = run().finally(() => { this.healing = null; });
    return this.healing;
  }

  status() {
    return { kind: this.kind, note: this.note, recording: !!this.piece, paused: this.paused, piece: this.piece && { n: this.piece.n, slug: this.piece.slug, since: this.piece.startedAt }, files: this.files.slice(-12), dir: this.dir };
  }

  base(p) { return /^N\d\d-/.test(p.slug) ? p.slug : `${String(p.n).padStart(2, '0')}-${p.slug}`; }   // v2 slugs carry their number (N05-...)

  async startPiece(p) {
    if (this.kind === 'none') return;
    if (this.piece) await this.endPiece();
    fs.mkdirSync(this.dir, { recursive: true });
    const base = this.base(p);
    for (const ext of ['.mkv', '.mp4', '.mov']) fs.rmSync(path.join(this.dir, base + ext), { force: true });   // a fresh take replaces the old one
    if (this.kind === 'obs') {
      this.watch?.check();
      if (this.stale || this.healing) await this.heal();
      await this.obs.req('SetRecordDirectory', { recordDirectory: this.dir }).catch(() => {});
      await this.obs.start(base);
      this.piece = { ...p, file: path.join(this.dir, base + '.mkv'), startedAt: Date.now() };
    } else {
      const file = path.join(this.dir, base + '.mov');
      // -v video, -C show the cursor, -g record the default microphone, -x no shutter sound.
      this.proc = spawn('screencapture', ['-v', '-C', '-g', '-x', file], { stdio: 'ignore' });
      this.piece = { ...p, file, startedAt: Date.now() };
    }
    this.paused = false;
    this.log(`recording: piece ${p.n} started (${this.kind})`);
  }

  async pause() {
    if (!this.piece || this.paused) return;
    if (this.kind === 'obs') { await this.obs.pause(); this.paused = true; this.log('recording: paused for a wait'); }
    // screencapture cannot pause: leave it running, the teleprompter says so.
  }
  async resume() {
    if (!this.piece || !this.paused) return;
    if (this.kind === 'obs') { await this.obs.resume(); this.paused = false; this.log('recording: resumed'); }
  }

  async endPiece() {
    if (!this.piece) return null;
    const p = this.piece; this.piece = null; this.paused = false;
    let file = p.file;
    if (this.kind === 'obs') {
      const out = await this.obs.stop();
      if (out && out !== p.file && fs.existsSync(out)) { fs.renameSync(out, p.file); }
    } else if (this.proc) {
      const proc = this.proc; this.proc = null;
      await new Promise((r) => { proc.once('exit', r); proc.kill('SIGINT'); setTimeout(r, 8000); });
    }
    if (!fs.existsSync(file)) { this.log(`recording: piece ${p.n} produced no file`); return null; }
    let mp4 = null;
    try {
      mp4 = this.kind === 'obs' ? await remux(file) : await new Promise((res, rej) => {
        const out = file.replace(/\.mov$/, '.mp4');
        execFile(FFMPEG, ['-v', 'error', '-y', '-i', file, '-c', 'copy', '-movflags', '+faststart', out], (e) => (e ? rej(e) : res(out)));
      });
    } catch (e) { this.log(`recording: remux failed (${e.message}); the ${path.extname(file)} is kept`); }
    this.files.push({ n: p.n, file, mp4 });
    this.log(`recording: piece ${p.n} saved ${path.basename(mp4 || file)}`);
    return mp4 || file;
  }

  // Retake: stop and throw away the current piece's file.
  async discardPiece() {
    const p = this.piece;
    if (!p) return;
    this.piece = null; this.paused = false;
    if (this.kind === 'obs') { const out = await this.obs.stop().catch(() => null); if (out) fs.rmSync(out, { force: true }); }
    else if (this.proc) { const proc = this.proc; this.proc = null; await new Promise((r) => { proc.once('exit', r); proc.kill('SIGINT'); setTimeout(r, 8000); }); }
    for (const ext of ['.mkv', '.mp4', '.mov']) fs.rmSync(p.file.replace(/\.(mkv|mov)$/, ext), { force: true });
    this.log(`recording: piece ${p.n} take discarded`);
    await sleep(300);
  }

  // Where the current piece's recording is now, in seconds of recorded time
  // (OBS leaves the paused spans out of the file, and out of this number).
  async position() {
    if (!this.piece) return null;
    if (this.kind === 'obs') { const st = await this.obs.status(); return (st.outputDuration || 0) / 1000; }
    return (Date.now() - this.piece.startedAt) / 1000;
  }

  async close() {
    if (this.piece) await this.endPiece().catch(() => {});
    this.watch?.stop(); this.watch = null;
    if (this.muted) await this.obs?.req('SetInputMute', { inputName: 'Microphone', inputMuted: false }).catch(() => {});
    this.obs?.close();
  }
}
