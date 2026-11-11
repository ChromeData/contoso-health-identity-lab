// Live, on-device speech to text for the teleprompter.
//
//   ffmpeg (the Mac's microphone, 16 kHz mono)  ->  a small voice detector
//   here (energy over an adaptive noise floor)  ->  whisper.cpp's
//   whisper-server on 127.0.0.1 (model loaded once, Metal)  ->  text.
//
// While he speaks, the open utterance is sent again about every second
// ('partial'); when he pauses, the whole utterance once more ('final').
// Nothing leaves this Mac. A file can stand in for the microphone
// ({ file }: the tests feed recorded speech through the same path).
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

const RATE = 16000, FRAME = 320;                 // 20 ms frames
const FF = ['/opt/homebrew/bin/ffmpeg', '/usr/local/bin/ffmpeg'].find((f) => fs.existsSync(f)) || 'ffmpeg';
const WS = ['/opt/homebrew/bin/whisper-server', '/usr/local/bin/whisper-server'].find((f) => fs.existsSync(f)) || 'whisper-server';
// whisper's usual words for silence and noise: never a line.
const NOISE = /^\s*(\[[^\]]*\]|\([^)]*\)|\*[^*]*\*|you\.?|\.+|thank you\.?)\s*$/i;

export function wav(pcm) {   // Int16 mono 16 kHz -> WAV bytes
  const h = Buffer.alloc(44), n = pcm.length * 2;
  h.write('RIFF', 0); h.writeUInt32LE(36 + n, 4); h.write('WAVEfmt ', 8); h.writeUInt32LE(16, 16); h.writeUInt16LE(1, 20); h.writeUInt16LE(1, 22);
  h.writeUInt32LE(RATE, 24); h.writeUInt32LE(RATE * 2, 28); h.writeUInt16LE(2, 32); h.writeUInt16LE(16, 34); h.write('data', 36); h.writeUInt32LE(n, 40);
  return Buffer.concat([h, Buffer.from(pcm.buffer, pcm.byteOffset, n)]);
}

const freePort = () => new Promise((res, rej) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); s.on('error', rej); });

export class Listener extends EventEmitter {
  // mic: an avfoundation audio device (name or index); file: a recording instead.
  constructor({ root, log = () => {}, model = 'base.en', mic = 'default', file = null, realtime = true, prompt = '' } = {}) {
    super();
    Object.assign(this, { root, log, mic, file, realtime, prompt });
    this.modelFile = path.join(root, 'models', `ggml-${model}.bin`);
    this.state = 'off'; this.note = ''; this.speaking = false;
    this.q = []; this.partialWanted = null; this.inflight = false; this.uid = 0;
  }

  async start() {
    if (this.state === 'listening' || this.state === 'starting') return;
    this.set('starting', 'loading the speech model');
    if (!fs.existsSync(this.modelFile)) { this.set('error', `no speech model at ${path.relative(this.root, this.modelFile)} (see README: Speech-aware teleprompter)`); return; }
    try { await this.startServer(); } catch (e) { this.set('error', `whisper-server: ${e.message}`); return; }
    this.startCapture();
  }

  set(state, note = '') { if (this.state !== state || this.note !== note) { this.state = state; this.note = note; this.emit('state', { state, note }); } }

  async startServer() {
    if (this.server && this.port) return;
    this.port = await freePort();
    this.server = spawn(WS, ['-m', this.modelFile, '--host', '127.0.0.1', '--port', String(this.port), '-nt', '-t', '4', '-l', 'en'], { stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    this.server.stderr.on('data', (d) => { err = (err + d).slice(-2000); });
    this.server.on('exit', (code) => { this.server = null; if (this.state !== 'off') this.set('error', `whisper-server stopped (${code}): ${err.trim().split('\n').pop()}`); });
    for (let k = 0; k < 120; k++) {   // up to 30 s (the first run compiles Metal kernels)
      await new Promise((r) => setTimeout(r, 250));
      if (!this.server) throw new Error(err.trim().split('\n').pop() || 'exited');
      try { const r = await fetch(`http://127.0.0.1:${this.port}/`); if (r.ok) return; } catch {}
    }
    throw new Error('did not start in 30 s');
  }

  startCapture() {
    const input = this.file ? [...(this.realtime ? ['-re'] : []), '-i', this.file] : ['-f', 'avfoundation', '-i', `:${this.mic}`];
    this.ff = spawn(FF, ['-hide_banner', '-loglevel', 'error', '-nostdin', ...input, '-ac', '1', '-ar', String(RATE), '-f', 's16le', 'pipe:1'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let err = '', got = 0;
    this.ff.stderr.on('data', (d) => { err = (err + d).slice(-2000); });
    this.vadReset();
    let rest = Buffer.alloc(0);
    this.ff.stdout.on('data', (d) => {
      got += d.length;
      if (this.state === 'starting') this.set('listening', this.file ? `file ${path.basename(this.file)}` : `microphone ${this.mic}`);
      rest = Buffer.concat([rest, d]);
      const n = Math.floor(rest.length / (FRAME * 2));
      for (let i = 0; i < n; i++) this.frame(new Int16Array(rest.buffer.slice(rest.byteOffset + i * FRAME * 2, rest.byteOffset + (i + 1) * FRAME * 2)));
      rest = rest.subarray(n * FRAME * 2);
    });
    this.ff.on('exit', (code) => {
      this.ff = null;
      if (this.utt) this.endUtterance();
      if (this.file) { this.drain().then(() => this.emit('eof')); return; }
      if (this.state === 'off') return;
      // No audio at all: macOS did not let this app use the microphone.
      this.set('error', got ? `microphone stopped (${err.trim().split('\n').pop() || code})` : `no microphone audio: allow the app that runs the cockpit in System Settings > Privacy & Security > Microphone (${err.trim().split('\n').pop() || `ffmpeg ${code}`})`);
    });
    // A microphone that never sends a byte (permission prompt not answered).
    if (!this.file) setTimeout(() => { if (!got && this.ff && this.state === 'starting') this.set('error', 'no microphone audio yet: allow the app that runs the cockpit in System Settings > Privacy & Security > Microphone'); }, 6000);
  }

  // ---- voice detector -------------------------------------------------------
  vadReset() { this.floor = -60; this.run = 0; this.quiet = 0; this.utt = null; this.pre = []; this.lastPartialAt = 0; this.t = 0; }
  frame(f) {
    this.t += FRAME / RATE;
    let s = 0; for (let i = 0; i < f.length; i++) s += f[i] * f[i];
    const db = 10 * Math.log10(s / f.length / (32768 * 32768) + 1e-12);
    // macOS hands a denied app pure digital silence, not an error.
    if (!this.file) { this.zeros = s === 0 ? (this.zeros || 0) + 1 : 0; if (this.zeros === 400) this.set('error', 'the microphone sends only silence: allow the app that runs the cockpit in System Settings > Privacy & Security > Microphone (or pick another mic in .state/speech.json)'); else if (this.zeros === 0 && this.state === 'error' && this.ff) this.set('listening', `microphone ${this.mic}`); }
    const thr = Math.max(this.floor + 10, -50);
    const voiced = db > thr;
    if (!this.utt) {
      // The noise floor follows the room while nobody speaks (fast down, slow up).
      this.floor = db < this.floor ? this.floor * 0.9 + db * 0.1 : this.floor * 0.995 + db * 0.005;
      this.pre.push(f); if (this.pre.length > 15) this.pre.shift();   // 300 ms before the first word
      this.run = voiced ? this.run + 1 : 0;
      if (this.run >= 3) { this.utt = { id: ++this.uid, frames: [...this.pre], voiced: this.run, t0: this.t }; this.pre = []; this.quiet = 0; this.speaking = true; this.emit('speaking', true); }
      return;
    }
    this.utt.frames.push(f);
    if (voiced) { this.utt.voiced++; this.quiet = 0; } else this.quiet++;
    const secs = this.utt.frames.length * FRAME / RATE;
    if (this.quiet >= 35 || secs >= 15) { this.endUtterance(); return; }          // 700 ms pause, or 15 s
    if (secs >= 0.8 && this.t - this.lastPartialAt >= 0.9) { this.lastPartialAt = this.t; this.partialWanted = { id: this.utt.id, frames: this.utt.frames.slice() }; this.pump(); }
  }
  endUtterance() {
    const u = this.utt; this.utt = null; this.run = 0; this.speaking = false; this.lastSpeechEnd = Date.now(); this.emit('speaking', false);
    if (this.partialWanted?.id === u.id) this.partialWanted = null;
    if (u.voiced < 15) return;                                             // under 300 ms of voice: a click or a cough
    this.q.push({ id: u.id, frames: u.frames, final: true }); this.pump();
  }

  // ---- whisper ----------------------------------------------------------------
  async pump() {
    if (this.inflight) return;
    const job = this.q.shift() || (this.partialWanted && { ...this.partialWanted, final: false });
    if (!job) return;
    if (!job.final) this.partialWanted = null;
    this.inflight = true;
    try {
      const pcm = new Int16Array(job.frames.reduce((n, f) => n + f.length, 0)); let o = 0; for (const f of job.frames) { pcm.set(f, o); o += f.length; }
      const t0 = Date.now(), text = await this.transcribe(pcm);
      if (text && !NOISE.test(text)) this.emit(job.final ? 'final' : 'partial', { id: job.id, text, ms: Date.now() - t0, secs: pcm.length / RATE });
    } catch (e) { this.log(`speech: whisper: ${e.message}`); }
    this.inflight = false;
    if (this.q.length || this.partialWanted) this.pump(); else this.emit('idle');
  }
  async transcribe(pcm) {
    const fd = new FormData();
    fd.append('file', new Blob([wav(pcm)], { type: 'audio/wav' }), 'a.wav');
    fd.append('response_format', 'json'); fd.append('temperature', '0'); fd.append('temperature_inc', '0');
    if (this.prompt) fd.append('prompt', this.prompt);
    const r = await fetch(`http://127.0.0.1:${this.port}/inference`, { method: 'POST', body: fd, signal: AbortSignal.timeout(20000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return String((await r.json()).text || '').replace(/\s+/g, ' ').trim();
  }
  async drain() { while (this.inflight || this.q.length) await new Promise((r) => setTimeout(r, 50)); }

  stopCapture() { if (this.ff) { this.ff.kill('SIGTERM'); this.ff = null; } if (this.speaking) { this.speaking = false; this.emit('speaking', false); } this.utt = null; }
  stop() { this.set('off'); this.stopCapture(); }
  close() { this.stop(); if (this.server) { this.server.kill('SIGTERM'); this.server = null; } this.port = null; }
}
