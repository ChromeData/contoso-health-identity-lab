// The curtain (--watch / clips, 2026-11-11 review): before anything records,
// every app that is not part of the demo is HIDDEN (System Events "visible
// false", never quit), and the Dock is put out of reach (autohide on, a long
// reveal delay). The first full clips run showed the Claude desktop app (another
// project's chat) for 0.5-1 s in N01, N02 and N04b and the Dock in N01, N04
// and N04b.
//
// Kept visible: the cockpit's own Chrome windows (by pid), VS Code (its demo
// window; the lead's own windows are minimized by clearOthers), OBS (the stage
// hides it itself), and the cockpit's helpers (presenter card, ring, pointer).
//
// Everything is put back as it was: the hidden apps shown again and the
// user's Dock settings restored, at the end, on Ctrl-C and on a crash
// (process 'exit'). The state is also written to .state/curtain.json, so a
// run killed outright (SIGKILL) is put back by the next cockpit start.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const KEEP_BUNDLES = new Set(['com.microsoft.VSCode', 'com.obsproject.obs-studio']);
const KEEP_NAMES = /^(script-overlay|cursor-ring|human-input|OBS|obs)$/;
// Dock: shown only after this many seconds of the pointer at the screen edge.
const DOCK_DELAY = 1000;

let stateFile = null;
let state = null;   // { dock: { autohide, delay }, hidden: [{ pid, name }] }
let logf = () => {};

const osa = (script, args = []) => { try { return execFileSync('osascript', ['-e', script, ...args.map(String)], { encoding: 'utf8', timeout: 20000 }).trim(); } catch (e) { return `error: ${String(e.stderr || e.message).trim().split('\n')[0]}`; } };
const save = () => { try { if (state) fs.writeFileSync(stateFile, JSON.stringify(state, null, 1), { mode: 0o600 }); } catch {} };

// Visible apps with a UI: [{ pid, name, bundle }].
export function visibleApps() {
  // One bulk read (a "repeat with p in ..." loop broke as soon as the set changed).
  const js = "const ps = Application('System Events').processes.whose({ backgroundOnly: false, visible: true }); JSON.stringify({ pid: ps.unixId(), name: ps.name(), b: ps.bundleIdentifier() })";
  try {
    const r = JSON.parse(execFileSync('osascript', ['-l', 'JavaScript', '-e', js], { encoding: 'utf8', timeout: 20000 }));
    return r.pid.map((pid, k) => ({ pid: +pid, name: r.name[k], bundle: r.b[k] || '' }));
  } catch { return []; }
}
const hidePid = (pid) => osa(`tell application "System Events" to set visible of (first process whose unix id is ${+pid}) to false`);
const showPid = (pid) => osa(`tell application "System Events" to if exists (first process whose unix id is ${+pid}) then set visible of (first process whose unix id is ${+pid}) to true`);

function readDock() {
  const rd = (k) => { try { return execFileSync('defaults', ['read', 'com.apple.dock', k], { encoding: 'utf8' }).trim(); } catch { return null; } };
  return { autohide: rd('autohide'), delay: rd('autohide-delay') };
}
function writeDock({ autohide, delay }) {
  const w = (k, type, v) => { try { if (v == null) execFileSync('defaults', ['delete', 'com.apple.dock', k], { stdio: 'ignore' }); else execFileSync('defaults', ['write', 'com.apple.dock', k, type, String(v)]); } catch {} };
  w('autohide', '-bool', autohide == null ? null : (/^(1|true|yes)$/i.test(autohide) ? 'true' : 'false'));
  w('autohide-delay', '-float', delay);
  try { execFileSync('killall', ['Dock'], { stdio: 'ignore' }); } catch {}
}

// Before recording. keepPids: the cockpit's Chrome pids. Returns a line for the log.
export function curtainUp({ root, keepPids = [], log = () => {} }) {
  logf = log;
  stateFile = path.join(root, '.state', 'curtain.json');
  curtainRecover(root, log);   // a previous run that never put things back
  state = { at: new Date().toISOString(), dock: readDock(), hidden: [] };
  save();
  writeDock({ autohide: '1', delay: DOCK_DELAY });
  const keep = new Set(keepPids.map(Number));
  for (const a of visibleApps()) {
    if (keep.has(a.pid) || KEEP_BUNDLES.has(a.bundle) || KEEP_NAMES.test(a.name) || a.pid === process.pid) continue;
    const r = hidePid(a.pid);
    if (r.startsWith('error')) { log(`curtain: could not hide ${a.name}: ${r}`); continue; }
    state.hidden.push({ pid: a.pid, name: a.name });
  }
  save();
  installExitRestore();
  return `curtain: Dock autohide on (was ${state.dock.autohide ?? 'unset'}); hidden: ${state.hidden.map((x) => x.name).join(', ') || 'nothing'}`;
}

// The stage watchdog found another app's window on screen: hidden at once
// (and put back with the others at the end).
export function curtainHide(pid, name = '') {
  if (!state) return false;
  const r = hidePid(pid);
  if (r.startsWith('error')) return false;
  if (!state.hidden.some((x) => x.pid === +pid)) { state.hidden.push({ pid: +pid, name }); save(); }
  return true;
}
export const curtainActive = () => !!state;

// After the run (and from process 'exit'): the hidden apps shown again, the Dock as it was.
export function curtainDown() {
  if (!state) return null;
  const s = state; state = null;
  for (const h of s.hidden) showPid(h.pid);
  writeDock(s.dock);
  try { fs.rmSync(stateFile, { force: true }); } catch {}
  const line = `curtain: put back: ${s.hidden.map((x) => x.name).join(', ') || 'no apps'} shown again, Dock autohide ${s.dock.autohide ?? 'unset'}, delay ${s.dock.delay ?? 'unset'}`;
  try { logf(line); } catch {}
  return line;
}

// A run killed before it could put things back (its state file is still there).
export function curtainRecover(root, log = () => {}) {
  const f = path.join(root, '.state', 'curtain.json');
  if (!fs.existsSync(f) || state) return null;
  try {
    const s = JSON.parse(fs.readFileSync(f, 'utf8'));
    for (const h of s.hidden || []) showPid(h.pid);
    if (s.dock) writeDock(s.dock);
    fs.rmSync(f, { force: true });
    const line = `curtain: an earlier run's hidden apps and Dock setting put back (${(s.hidden || []).map((x) => x.name).join(', ') || 'no apps'})`;
    log(line);
    return line;
  } catch (e) { log(`curtain: could not put back an earlier run's state: ${e.message}`); return null; }
}

let installed = false;
function installExitRestore() {
  if (installed) return;
  installed = true;
  // 'exit' runs on process.exit (Ctrl-C goes through bye -> exit) and after an
  // uncaught exception; synchronous calls only.
  process.on('exit', () => { try { curtainDown(); } catch {} });
  process.on('uncaughtException', (e) => { try { console.error(e); curtainDown(); } catch {} process.exit(1); });
  process.on('SIGHUP', () => { try { curtainDown(); } catch {} process.exit(1); });
}
