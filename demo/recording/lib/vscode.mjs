// VS Code side of the cockpit: opens the demo workspace with the `code` CLI
// (which also brings that window to the front) and talks to the window's
// cockpit-bridge extension (vscode-ext/) over 127.0.0.1 with its token.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const CODE = process.env.CODE_CLI || '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code';
const REG_DIR = path.join(os.homedir(), 'contoso-demo', 'cockpit', '.state', 'bridges');

function alive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }

function bridges() {
  let files = [];
  try { files = fs.readdirSync(REG_DIR).filter((f) => f.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const f of files) {
    try {
      const e = JSON.parse(fs.readFileSync(path.join(REG_DIR, f), 'utf8'));
      if (alive(e.pid)) out.push(e); else fs.rmSync(path.join(REG_DIR, f), { force: true });
    } catch {}
  }
  return out.sort((a, b) => (a.started < b.started ? 1 : -1));
}

// Every demo window opens in the owner's VS Code profile "Contoso Demo"
// (theme, icons, the demo's extensions), never the default profile.
export const PROFILE = process.env.COCKPIT_VSCODE_PROFILE || 'Contoso Demo';
// Which profile VS Code has this workspace in (its own storage.json:
// userDataProfiles + profileAssociations); 'Default' when none.
export function profileOf(ws) {
  try {
    const d = JSON.parse(fs.readFileSync(path.join(process.env.HOME, 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'storage.json'), 'utf8'));
    const loc = d.profileAssociations?.workspaces?.[`file://${path.resolve(ws)}`];
    if (!loc || loc === '__default__profile__') return 'Default';
    return (d.userDataProfiles || []).find((p) => p.location === loc)?.name || loc;
  } catch { return 'unknown'; }
}
function codeCli(args) {
  return new Promise((resolve, reject) => execFile(CODE, ['--profile', PROFILE, ...args], { timeout: 30000 }, (e, so, se) => (e ? reject(new Error(se || e.message)) : resolve(so))));
}

export class VsCode {
  constructor(workspaceFile, { log = console.log } = {}) { this.ws = path.resolve(workspaceFile); this.log = log; }

  find() { return bridges().find((b) => b.workspaceFile === this.ws) || null; }
  get ready() { return !!this.find(); }

  // Open (or bring forward) the workspace window and wait for its bridge.
  // VS Code appends the profile's name to the title of a window in a
  // non-default profile ("contoso-demo (Workspace) — Contoso Demo").
  get title() { return `${path.basename(this.ws, '.code-workspace')} (Workspace)${PROFILE && PROFILE !== 'Default' ? ` — ${PROFILE}` : ''}`; }

  async open({ timeoutMs = 45000 } = {}) {
    // A window of this workspace open in another profile (e.g. the default
    // one) is closed first, then reopened in the demo profile.
    if (this.find() && profileOf(this.ws) !== PROFILE) {
      this.log(`VS Code: ${path.basename(this.ws)} is open in the "${profileOf(this.ws)}" profile: reopening it in "${PROFILE}"`);
      await this.closeWindow();
    }
    // Already open with its bridge: don't call the CLI (it activates the whole
    // VS Code app, which can bring another window or Space on camera).
    if (this.find()) { try { const info = await this.call('ping'); const want = JSON.parse(fs.readFileSync(new URL('../vscode-ext/package.json', import.meta.url), 'utf8')).version; if (info.version === want) return this.find(); } catch {} }
    await codeCli([this.ws]);
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const b = this.find();
      if (b) {
        let info = null;
        try { info = await this.call('ping'); } catch {}
        if (info) {
          // A window opened before the bridge was rebuilt still runs the old
          // code: reload it once so it picks up the installed version.
          const want = JSON.parse(fs.readFileSync(new URL('../vscode-ext/package.json', import.meta.url), 'utf8')).version;
          if (info.version !== want && !this.reloaded) {
            this.reloaded = true;
            this.log(`VS Code bridge ${info.version || '(old)'} is older than ${want}: reloading the demo window once`);
            // The window reloads before it can answer, so no answer is expected here.
            await this.call('command', { id: 'workbench.action.reloadWindow' }).catch(() => {});
            await sleep(4000);
            continue;
          }
          return b;
        }
      }
      await sleep(700);
    }
    throw new Error(`VS Code bridge did not come up for ${path.basename(this.ws)}: in that window run "Developer: Reload Window" (if it is not installed: vscode-ext/build-vsix.sh)`);
  }

  // Size the demo window to the recording area (same size as the recording
  // browser). VS Code has no API for its window size, so this goes through
  // macOS System Events; the process is matched by bundle id because it is
  // named "Electron", and the window by its title "<workspace> (Workspace)".
  async fit(w, h) {
    const needle = this.title;
    const script = [
      'on run argv',
      '  set needle to item 1 of argv',
      '  tell application "System Events"',
      '    set p to first process whose bundle identifier is "com.microsoft.VSCode"',
      '    repeat with win in windows of p',
      '      if (name of win) ends with needle then',
      '        set position of win to {0, 0}',
      '        set size of win to {(item 2 of argv) as integer, (item 3 of argv) as integer}',
      '        set sz to size of win',
      '        return ((item 1 of sz) as string) & "x" & ((item 2 of sz) as string)',
      '      end if',
      '    end repeat',
      '  end tell',
      '  return "not found"',
      'end run'].join('\n');
    // A window that just opened can take a moment to show up to System Events.
    let out = 'not found';
    for (let k = 0; k < 6 && out === 'not found'; k++) {
      if (k) await sleep(1000);
      out = await new Promise((resolve) => execFile('osascript', ['-e', script, needle, String(w), String(h)], { timeout: 15000 }, (e, so, se) => resolve(e ? `error: ${(se || e.message).trim()}` : so.trim())));
    }
    this.log(`VS Code demo window: ${out === 'not found' ? 'not on this screen (could not size it)' : out.startsWith('error') ? `could not size it (${out})` : `sized to ${out}`}`);
    return out;
  }

  // Close this workspace's window (through its own bridge).
  async closeWindow() {
    const b = this.find(); if (!b) return false;
    await this.call('command', { id: 'workbench.action.closeWindow' }).catch(() => {});
    for (let k = 0; k < 30 && this.find(); k++) await sleep(500);
    return !this.find();
  }

  // The cockpit's own old windows (rehearsal / preview copies whose
  // workspace is not `keep`) are closed: they only clutter the screen.
  static async closeStale(keep, log = () => {}) {
    for (const b of bridges()) {
      if (b.workspaceFile === keep || !/\/contoso-demo\/cockpit\/(rehearsal|preview)\//.test(b.workspaceFile)) continue;
      const v = new VsCode(b.workspaceFile, { log });
      try {
        const info = await v.call('ping');
        const want = JSON.parse(fs.readFileSync(new URL('../vscode-ext/package.json', import.meta.url), 'utf8')).version;
        if (info.version !== want) { await v.call('command', { id: 'workbench.action.reloadWindow' }).catch(() => {}); for (let k = 0; k < 40; k++) { await sleep(750); const nb = v.find(); if (nb && nb.pid !== b.pid) break; } }
        if (await v.closeWindow()) log(`closed the old VS Code window ${path.basename(b.workspaceFile)}`);
      } catch (e) { log(`could not close ${path.basename(b.workspaceFile)}: ${e.message}`); }
    }
  }

  // Bring the window forward without reopening anything else.
  async focus() { await codeCli([this.ws]); await sleep(400); }

  async goto(file, line = 1) { await codeCli(['--reuse-window', '--goto', `${file}:${line}`]); }

  async call(op, args = {}) {
    const b = this.find();
    if (!b) throw new Error('VS Code demo window is not open (no bridge)');
    const res = await fetch(`http://127.0.0.1:${b.port}/cmd`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: b.token, op, args }), signal: AbortSignal.timeout(180000) });
    const j = await res.json();
    if (!j.ok) throw new Error(`VS Code ${op}: ${j.error}`);
    return j.result;
  }
}
