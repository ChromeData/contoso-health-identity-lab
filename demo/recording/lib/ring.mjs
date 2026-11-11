// The cursor ring (tools/cursor-ring.swift): a yellow ring that follows the
// system pointer on every Space, click-through, seen by OBS. The cockpit
// starts it with itself, stops it on close, and the teleprompter's C key
// turns it on and off. Built on first use (swiftc ships with the Xcode
// command line tools).
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname);
const SRC = path.join(here, '..', 'tools', 'cursor-ring.swift');
const BIN = path.join(here, '..', 'tools', 'cursor-ring');

export class Ring {
  constructor({ log = console.log, size = 40 } = {}) { this.log = log; this.size = size; this.proc = null; }
  get on() { return !!this.proc; }
  build() {
    if (fs.existsSync(BIN) && fs.statSync(BIN).mtimeMs >= fs.statSync(SRC).mtimeMs) return;
    execFileSync('swiftc', ['-O', SRC, '-o', BIN], { stdio: 'ignore', timeout: 180000 });
  }
  start() {
    if (this.proc) return true;
    try { this.build(); } catch (e) { this.log(`cursor ring: could not build (${e.message.split('\n')[0]})`); return false; }
    this.proc = spawn(BIN, ['--size', String(this.size)], { stdio: 'ignore' });
    this.proc.on('exit', () => { this.proc = null; });
    this.log('cursor ring: on');
    return true;
  }
  stop() { if (!this.proc) return; this.proc.kill('SIGTERM'); this.proc = null; this.log('cursor ring: off'); }
  toggle() { return this.on ? (this.stop(), false) : this.start(); }
}
