// Contoso cockpit bridge: lets the local recording cockpit (../cockpit.mjs)
// drive the Contoso demo window of VS Code, so the presenter only talks.
//
// Scope, on purpose:
//  - It only switches on in a window whose workspace FILE lives under
//    ~/contoso-demo (the demo workspace and the cockpit's rehearsal
//    workspace). Every other VS Code window ignores it.
//  - It listens on 127.0.0.1 only (random port), and every request must carry
//    the window's random token. Port + token are written to
//    ~/contoso-demo/cockpit/.state/bridges/<pid>.json (chmod 600), which only
//    this macOS user can read; the file is removed when the window closes.
//  - It only touches files inside the window's own workspace folders, never
//    commits or pushes on main/master, and runs only allow-listed commands.
'use strict';
const vscode = require('vscode');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const DEMO_ROOT = path.join(os.homedir(), 'contoso-demo');
const REG_DIR = path.join(DEMO_ROOT, 'cockpit', '.state', 'bridges');
const COMMANDS = new Set([
  'workbench.view.scm', 'workbench.view.explorer', 'workbench.action.closeAllEditors',
  'workbench.action.focusActiveEditorGroup', 'workbench.action.closeUnmodifiedEditors', 'workbench.action.closePanel', 'workbench.action.closeAuxiliaryBar',
  'workbench.files.action.collapseExplorerFolders', 'revealInExplorer', 'workbench.action.files.saveAll',
  'notifications.clearAll', 'workbench.action.closeSidebar', 'workbench.action.toggleSidebarVisibility',
  'workbench.action.reloadWindow',   // picks up a newer bridge after vscode-ext/build-vsix.sh
  'workbench.action.closeWindow',    // the cockpit closes its own stale rehearsal/preview windows, and reopens the demo window on the recording Space
  // Owner setup (2026-11-06): start the two extension sign-ins (the browser
  // page is finished outside VS Code), show the panels for the "connected"
  // screenshots, and hide AWS Toolkit's Application Builder in the Explorer.
  'pr.signin', 'azureResourceGroups.logIn',
  'workbench.view.extension.github-pull-requests', 'workbench.view.extension.azure', 'workbench.view.extension.aws-explorer',
  'aws.appBuilderForFileExplorer.removeView', 'aws.amazonq.codewhisperer.removeView', 'aws.cdk.removeView', 'aws.cloudformation.removeView',
  'aws.appBuilder.removeView', 'aws.codecatalyst.removeView', 'aws.smus.rootView.removeView',
  // The AWS Explorer's first row is its connection node; Enter on it (re)validates the profile.
  'aws.explorer.focus', 'list.focusFirst', 'list.select',
]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The only commands runCheck may type (v2 N17): read-only checks.
const CHECKS = { preflight: 'lab/scripts/demo/preflight.sh --check' };
const checkRuns = {};

let server = null, guideServer = null, regFile = null, token = null, out = null, deco = null, decoTimer = null;

function demoWorkspace() {
  const wf = vscode.workspace.workspaceFile;
  return !!(wf && wf.scheme === 'file' && wf.fsPath.startsWith(DEMO_ROOT + path.sep) && wf.fsPath.endsWith('.code-workspace'));
}
function folders() { return (vscode.workspace.workspaceFolders || []).map((f) => ({ name: f.name, path: f.uri.fsPath })); }
function insideWorkspace(file) {
  const real = path.resolve(file);
  return folders().some((f) => real === f.path || real.startsWith(f.path + path.sep));
}
function mustBeInside(file) { if (!file || !insideWorkspace(file)) throw new Error(`not inside this workspace: ${file}`); return path.resolve(file); }
function gitApi() {
  const ext = vscode.extensions.getExtension('vscode.git');
  if (!ext || !ext.isActive) throw new Error('the built-in Git extension is not active');
  return ext.exports.getAPI(1);
}
function repoFor(folder) {
  const f = mustBeInside(folder);
  const repo = gitApi().repositories.find((r) => r.rootUri.fsPath === f) || gitApi().getRepository(vscode.Uri.file(f));
  if (!repo) throw new Error(`no git repository at ${f}`);
  return repo;
}
function protectedBranch(name) { return !name || /^(main|master)$/i.test(name); }

// ---- editor helpers -----------------------------------------------------------
async function editorFor(file) {
  const f = mustBeInside(file);
  // scheme 'file': the real file, never the read-only "before" side of a diff
  // (a git: document with the same path).
  const open = vscode.window.visibleTextEditors.find((e) => e.document.uri.scheme === 'file' && e.document.uri.fsPath === f);
  if (open) return vscode.window.showTextDocument(open.document, { viewColumn: open.viewColumn, preview: false });
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(f));
  return vscode.window.showTextDocument(doc, { preview: false });
}
function range(line, endLine) { return new vscode.Range(Math.max(0, line - 1), 0, Math.max(0, (endLine || line) - 1), Number.MAX_SAFE_INTEGER); }
function reveal(ed, line, endLine) {
  const r = range(line, endLine);
  ed.selection = new vscode.Selection(r.start, r.start);
  ed.revealRange(r, vscode.TextEditorRevealType.InCenter);
}
function highlight(ed, line, endLine, ms) {
  setSoft(ed, [range(line, endLine)], ms);
}
// The owner's view (2026-11-06): no red/green diff, the finished file, and a
// soft warm tint (plus a thin bar) on just the lines being talked about.
function setSoft(ed, ranges, ms) {
  if (!deco) deco = vscode.window.createTextEditorDecorationType({
    isWholeLine: true, backgroundColor: 'rgba(255,214,102,0.14)',
    borderWidth: '0 0 0 3px', borderStyle: 'solid', borderColor: 'rgba(240,170,40,0.75)',
    overviewRulerColor: 'rgba(240,170,40,0.8)', overviewRulerLane: vscode.OverviewRulerLane.Full,
  });
  for (const e of vscode.window.visibleTextEditors) e.setDecorations(deco, []);
  ed.setDecorations(deco, ranges);
  clearTimeout(decoTimer);
  if (ms > 0) decoTimer = setTimeout(() => ed.setDecorations(deco, []), ms);
}
function clearHighlight() { if (deco) for (const e of vscode.window.visibleTextEditors) e.setDecorations(deco, []); }
// A person types unevenly: a little slower after spaces and commas.
function keyDelay(base, ch) { const j = base * (0.6 + Math.random() * 0.8); return Math.round(j + (ch === ',' || ch === ' ' ? base * 0.8 : 0)); }

// On camera the code gets the whole window: no side bar, panel, chat or
// pop-up notifications (e.g. "install the recommended CSV extension?").
async function cleanStage() {
  for (const id of ['workbench.action.closeSidebar', 'workbench.action.closePanel', 'workbench.action.closeAuxiliaryBar', 'notifications.clearAll']) {
    await vscode.commands.executeCommand(id).then(() => {}, () => {});
  }
}

// ---- lab guide stops (vscode://contoso-lab.cockpit-bridge/open?stop=<id or n>) ----
// The Lab Guide page has one "Open in VS Code" button per stop. It carries
// only the stop id; the files and line ranges come from the local copy of
// stops.json (readiness/lab-guide), so a link cannot name any other file.
// Each file opens as its own tab (preview off) in ONE editor group, the key
// lines get the same soft warm tint as the cockpit (no red/green), and the
// first file ends up focused. Ctrl+Alt+Cmd+] / [ step through the stop's files.
const STOPS_FILE = path.join(DEMO_ROOT, 'readiness', 'lab-guide', 'stops.json');
const LIVE_WS = path.join(DEMO_ROOT, 'contoso-demo.code-workspace');
let stopDeco = null, stop = null, stopBar = null;   // stop = { id, n, title, items: [{ file, ranges, look, first }] }

function parseLines(spec) {
  const out = [];
  for (const part of String(spec || '').split(',')) {
    const m = part.trim().match(/^(\d+)(?:\s*-\s*(\d+))?$/);
    if (!m) continue;
    const a = +m[1], b = m[2] ? +m[2] : a;
    out.push(range(Math.min(a, b), Math.max(a, b)));
  }
  return out;
}
function loadStop(key) {
  const d = JSON.parse(fs.readFileSync(STOPS_FILE, 'utf8'));
  const s = (d.stops || []).find((x) => x.id === key || String(x.n) === String(key));
  if (!s) throw new Error(`no stop "${key}" in stops.json`);
  const items = [];
  for (const f of s.files || []) {
    const root = d.roots && d.roots[f.root];
    if (!root) throw new Error(`stop ${s.n}: unknown root ${f.root}`);
    const file = path.resolve(root, f.path);
    if (!file.startsWith(DEMO_ROOT + path.sep)) throw new Error(`stop ${s.n}: ${f.path} is outside ~/contoso-demo`);
    if (!fs.existsSync(file)) throw new Error(`stop ${s.n}: missing ${file}`);
    const ranges = parseLines(f.lines);
    items.push({ file, ranges, look: f.look || '', first: ranges.length ? ranges[0].start.line + 1 : 1 });
  }
  if (!items.length) throw new Error(`stop ${s.n} (${s.title}) has no files`);
  return { id: s.id, n: s.n, title: s.title, items };
}
function paintStop(editors) {
  if (!stop || !stopDeco) return;
  for (const ed of editors || vscode.window.visibleTextEditors) {
    if (ed.document.uri.scheme !== 'file') continue;
    const it = stop.items.find((x) => x.file === ed.document.uri.fsPath);
    if (it) ed.setDecorations(stopDeco, it.ranges.map((r) => ({ range: r, hoverMessage: it.look })));
  }
}
function showBar() {
  if (!stopBar) return;
  const ed = vscode.window.activeTextEditor;
  const k = stop && ed ? stop.items.findIndex((x) => x.file === ed.document.uri.fsPath) : -1;
  if (k < 0) { stopBar.hide(); return; }
  stopBar.text = `$(location) Stop ${stop.n} · ${k + 1}/${stop.items.length}`;
  stopBar.tooltip = `${stop.title}: ${stop.items[k].look}\nCtrl+Alt+Cmd+] next file, Ctrl+Alt+Cmd+[ previous`;
  stopBar.show();
}
async function showItem(it, focus) {
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(it.file));
  const ed = await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One, preview: false, preserveFocus: !focus });
  if (it.ranges.length) {
    const r = it.ranges[0], all = new vscode.Range(r.start, it.ranges[it.ranges.length - 1].end);
    ed.selection = new vscode.Selection(r.start, r.start);
    ed.revealRange(all.end.line - all.start.line < 40 ? all : r, vscode.TextEditorRevealType.InCenter);
  }
  paintStop([ed]);
  return ed;
}
async function forwardStop(key) {
  let regs = [];
  try { regs = fs.readdirSync(REG_DIR).map((f) => { try { return JSON.parse(fs.readFileSync(path.join(REG_DIR, f), 'utf8')); } catch { return null; } }); } catch { return null; }
  for (const r of regs.filter((x) => x && x.workspaceFile === LIVE_WS && x.pid !== process.pid)) {
    try {
      const body = JSON.stringify({ token: r.token, op: 'openStop', args: { stop: String(key) } });
      const res = await new Promise((resolve, reject) => {
        const q = http.request({ host: '127.0.0.1', port: r.port, path: '/cmd', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: 15000 }, (rs) => {
          let t = ''; rs.on('data', (c) => (t += c)); rs.on('end', () => { try { resolve(JSON.parse(t)); } catch (e) { reject(e); } });
        });
        q.on('error', reject); q.on('timeout', () => q.destroy(new Error('timeout'))); q.end(body);
      });
      if (res.ok) { out.appendLine(`${new Date().toISOString()} stop ${key}: sent to the demo window (pid ${r.pid})`); return res.result; }
      throw new Error(res.error);
    } catch (e) { out.appendLine(`${new Date().toISOString()} stop ${key}: demo window pid ${r.pid} did not take it: ${e.message}`); }
  }
  return null;
}
async function openStop(key) {
  if (!demoWorkspace()) {
    // The browser hands a vscode:// link to the LAST ACTIVE window, often the
    // owner's own (default profile) window. Pass the stop on to the Contoso
    // Demo window's bridge, then bring that window to the front (VS Code
    // focuses the window that already has the workspace open).
    const r = await forwardStop(key);
    if (r) { await vscode.commands.executeCommand('vscode.openFolder', vscode.Uri.file(LIVE_WS), { forceNewWindow: true }); return r; }
    const pick = await vscode.window.showWarningMessage('Lab stops open in the Contoso Demo window, and it is not open. Open it, then click the button again.', 'Open the Contoso Demo window');
    if (pick) await vscode.commands.executeCommand('vscode.openFolder', vscode.Uri.file(LIVE_WS), { forceNewWindow: true });
    return null;
  }
  const next = loadStop(key);
  // One group, only this stop's tabs: close every tab that has no unsaved
  // change, then fold any split back into one group.
  const keep = vscode.window.tabGroups.all.flatMap((g) => g.tabs).filter((t) => !t.isDirty);
  if (keep.length) await vscode.window.tabGroups.close(keep, true);
  if (vscode.window.tabGroups.all.length > 1) await vscode.commands.executeCommand('workbench.action.joinAllGroups');
  for (const e of vscode.window.visibleTextEditors) if (stopDeco) e.setDecorations(stopDeco, []);
  stop = next;
  for (let i = 0; i < stop.items.length; i++) await showItem(stop.items[i], false);
  const ed = await showItem(stop.items[0], true);
  await vscode.commands.executeCommand('setContext', 'cockpitBridge.stopOpen', true);
  showBar();
  out.appendLine(`${new Date().toISOString()} stop ${stop.n} (${stop.id}): ${stop.items.length} file(s)`);
  return { stop: stop.id, n: stop.n, files: stop.items.map((x) => x.file), active: ed.document.uri.fsPath };
}
async function stepStop(dir) {
  if (!stop) { vscode.window.showInformationMessage('No lab stop is open. Click "Open in VS Code" on the Lab Guide first.'); return null; }
  const ed = vscode.window.activeTextEditor;
  const k = ed ? stop.items.findIndex((x) => x.file === ed.document.uri.fsPath) : -1;
  const it = stop.items[(k + dir + stop.items.length) % stop.items.length];
  await showItem(it, true);
  showBar();
  return { active: it.file };
}
function tabsReport() {
  return vscode.window.tabGroups.all.map((g) => ({
    group: g.viewColumn, active: g.isActive,
    tabs: g.tabs.map((t) => ({ label: t.label, file: t.input && t.input.uri ? t.input.uri.fsPath : null, preview: t.isPreview, active: t.isActive, dirty: t.isDirty })),
  }));
}

// ---- operations ----------------------------------------------------------------
const ops = {
  async ping() {
    return { version: require('./package.json').version, pid: process.pid, workspaceFile: vscode.workspace.workspaceFile.fsPath, folders: folders(), focused: vscode.window.state.focused };
  },

  async open({ file, line, endLine, highlightMs = 0 }) {
    await cleanStage();
    const ed = await editorFor(file);
    if (line) { reveal(ed, line, endLine); if (highlightMs) highlight(ed, line, endLine, highlightMs); }
    return { file: ed.document.uri.fsPath, lines: ed.document.lineCount };
  },

  // The change as a before/after diff: HEAD on the left, the file on disk on the right.
  async diff({ file, line, endLine, highlightMs = 0, title }) {
    const f = mustBeInside(file);
    const uri = vscode.Uri.file(f);
    const left = gitApi().toGitUri(uri, 'HEAD');
    await cleanStage();
    await vscode.commands.executeCommand('vscode.diff', left, uri, title || `${path.basename(f)} (before ↔ after)`, { preview: false });
    await sleep(700);
    const ed = vscode.window.activeTextEditor;
    if (line && ed && ed.document.uri.fsPath === f) { reveal(ed, line, endLine); if (highlightMs) highlight(ed, line, endLine, highlightMs); }
    return { file: f, diff: true };
  },

  // side: 'after' (the file as changed, default) or 'before' (the left side
  // of the diff, e.g. to point at the line being taken away).
  async highlight({ file, line, endLine, ms = 6000, side = 'after' }) {
    const f = file ? mustBeInside(file) : null;
    const scheme = side === 'before' ? 'git' : 'file';
    const ed = f ? vscode.window.visibleTextEditors.find((e) => e.document.uri.scheme === scheme && e.document.uri.fsPath === f) : vscode.window.activeTextEditor;
    if (!ed) throw new Error('that file is not on screen');
    ed.revealRange(range(line, endLine), vscode.TextEditorRevealType.InCenter);
    highlight(ed, line, endLine, ms);
    return { highlighted: [line, endLine || line] };
  },

  async clearHighlight() { clearHighlight(); return {}; },

  // The Lab Guide's "Open in VS Code" (same code as the vscode:// link).
  async openStop({ stop: key }) { return openStop(String(key)); },
  async stopTabs() {
    const ed = vscode.window.activeTextEditor;
    return { stop: stop && stop.id, groups: tabsReport(), activeFile: ed ? ed.document.uri.fsPath : null, preview: vscode.workspace.getConfiguration('workbench.editor').get('enablePreview') };
  },

  // The finished file in a normal editor, its changed lines (git diff -U0
  // against HEAD, new-side line numbers) softly tinted; from/to keep only
  // the lines of the part being talked about. No diff view.
  async changes({ file, from = 1, to = 1e9, line, ms = 0 }) {
    const f = mustBeInside(file);
    await cleanStage();
    const ed = await editorFor(f);
    const out = await new Promise((resolve, reject) => require('child_process').execFile('git', ['-C', path.dirname(f), 'diff', '-U0', 'HEAD', '--', f], { maxBuffer: 8 << 20 }, (e, so) => (e ? reject(e) : resolve(so))));
    const lines = [];
    for (const m of out.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
      const start = +m[1], n = m[2] === undefined ? 1 : +m[2];
      for (let k = 0; k < n; k++) if (start + k >= from && start + k <= to) lines.push(start + k);
    }
    if (!lines.length) throw new Error(`no changed lines in ${path.basename(f)} between ${from} and ${to}`);
    const ranges = lines.map((l) => range(l, l));
    const first = line || lines[0];
    ed.selection = new vscode.Selection(range(first, first).start, range(first, first).start);
    ed.revealRange(range(lines[0], lines[lines.length - 1]), vscode.TextEditorRevealType.InCenter);
    setSoft(ed, ranges, ms);
    return { file: f, lines };
  },

  // Type text at human speed. Either at the end of the file (a new line), or
  // replacing `find` inside the first line that matches `lineMatch`.
  async type({ file, text, at = 'end', lineMatch, find, delayMs = 70, trailingNewline = false }) {
    const ed = await editorFor(file);
    const doc = ed.document;
    let pos;
    if (lineMatch) {
      const re = new RegExp(lineMatch);
      let ln = -1;
      for (let i = 0; i < doc.lineCount; i++) if (re.test(doc.lineAt(i).text)) { ln = i; break; }
      if (ln < 0) throw new Error(`no line matches ${lineMatch}`);
      const lineText = doc.lineAt(ln).text;
      const col = find ? lineText.indexOf(find) : lineText.length;
      if (col < 0) throw new Error(`"${find}" not on line ${ln + 1}`);
      const sel = new vscode.Range(ln, col, ln, col + (find ? find.length : 0));
      ed.selection = new vscode.Selection(sel.start, sel.end);
      ed.revealRange(sel, vscode.TextEditorRevealType.InCenter);
      await sleep(900);   // the viewer sees the old word selected
      if (find) await ed.edit((eb) => eb.delete(sel), { undoStopBefore: true, undoStopAfter: false });
      pos = sel.start;
    } else {
      const last = doc.lineAt(doc.lineCount - 1);
      if (last.text.length) await ed.edit((eb) => eb.insert(last.range.end, '\n'), { undoStopBefore: true, undoStopAfter: false });
      pos = new vscode.Position(ed.document.lineCount - 1, 0);
    }
    for (const ch of text) {
      const p = pos;
      await ed.edit((eb) => eb.insert(p, ch), { undoStopBefore: false, undoStopAfter: false });
      pos = ch === '\n' ? new vscode.Position(pos.line + 1, 0) : pos.translate(0, 1);
      ed.selection = new vscode.Selection(pos, pos);
      ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
      await sleep(keyDelay(delayMs, ch));
    }
    if (trailingNewline) await ed.edit((eb) => eb.insert(new vscode.Position(ed.document.lineCount, 0), '\n'), { undoStopBefore: false, undoStopAfter: true });
    return { typed: text.length, line: pos.line + 1 };
  },

  async save({ file }) {
    const ed = await editorFor(file);
    const ok = await ed.document.save();
    if (!ok) throw new Error('save failed');
    return { saved: ed.document.uri.fsPath };
  },

  async state({ folder }) {
    const repo = repoFor(folder);
    await repo.status();
    const h = repo.state.HEAD || {};
    return {
      branch: h.name, commit: h.commit, upstream: h.upstream ? `${h.upstream.remote}/${h.upstream.name}` : null, ahead: h.ahead, behind: h.behind,
      changes: repo.state.workingTreeChanges.map((c) => path.relative(repo.rootUri.fsPath, c.uri.fsPath)),
      staged: repo.state.indexChanges.map((c) => path.relative(repo.rootUri.fsPath, c.uri.fsPath)),
    };
  },

  // Stage + commit, on screen: the Source Control view opens, the message is
  // typed into its box, the files move to "Staged Changes", then the commit.
  // typeOnly: type the message in the box and stop there (the proof clip:
  // the commit message on screen, nothing committed).
  async commit({ folder, message, files = [], delayMs = 45, allowBranch, typeOnly = false }) {
    const repo = repoFor(folder);
    await repo.status();
    const head = repo.state.HEAD || {};
    if (protectedBranch(head.name)) throw new Error(`refusing to commit on ${head.name || 'a detached HEAD'}`);
    if (allowBranch && !new RegExp(allowBranch).test(head.name)) throw new Error(`refusing to commit on ${head.name}: expected ${allowBranch}`);
    const paths = files.length ? files.map((f) => mustBeInside(path.join(repo.rootUri.fsPath, f))) : repo.state.workingTreeChanges.map((c) => c.uri.fsPath);
    if (!paths.length) throw new Error('nothing to commit');
    await vscode.commands.executeCommand('workbench.view.scm');
    await sleep(600);
    repo.inputBox.value = '';
    for (let i = 1; i <= message.length; i++) { repo.inputBox.value = message.slice(0, i); await sleep(keyDelay(delayMs, message[i - 1])); }
    await sleep(500);
    if (typeOnly) return { typed: true, branch: head.name };
    await repo.add(paths);
    await sleep(1000);
    await repo.commit(message);
    await repo.status();
    return { sha: repo.state.HEAD.commit, branch: repo.state.HEAD.name };
  },

  async push({ folder, branch, remote = 'origin', setUpstream = true }) {
    const repo = repoFor(folder);
    await repo.status();
    const head = repo.state.HEAD || {};
    if (head.name !== branch) throw new Error(`on ${head.name}, expected ${branch}`);
    if (protectedBranch(branch)) throw new Error(`refusing to push ${branch}`);
    await repo.push(remote, branch, setUpstream);
    await repo.status();
    await vscode.commands.executeCommand('notifications.clearAll').then(() => {}, () => {});
    return { pushed: `${remote}/${branch}`, sha: repo.state.HEAD.commit };
  },

  // Recording look: the activity bar and status bar are hidden while the
  // cockpit records (written to this window's workspace file) and removed
  // again afterwards, so the owner's own window is a normal VS Code.
  async chrome({ hidden }) {
    const cfg = vscode.workspace.getConfiguration();
    const T = vscode.ConfigurationTarget.Workspace;
    await cfg.update('workbench.activityBar.location', hidden ? 'hidden' : undefined, T);
    await cfg.update('workbench.statusBar.visible', hidden ? false : undefined, T);
    const i = (k) => cfg.inspect(k)?.workspaceValue;
    return { hidden: !!hidden, activityBar: i('workbench.activityBar.location') ?? null, statusBar: i('workbench.statusBar.visible') ?? null };
  },

  // v2 N17 (0.1.16): a read-only check, run in VS Code's own terminal so the
  // viewer sees it. Only the checks listed here can run: the cockpit sends a
  // name, never a command line.
  async runCheck({ check }) {
    const C = CHECKS[check];
    if (!C) throw new Error(`no such check: ${check}`);
    const root = (vscode.workspace.workspaceFolders || [])[0];
    if (!root) throw new Error('no workspace folder');
    await vscode.commands.executeCommand('workbench.action.closeSidebar').then(() => {}, () => {});
    for (const t of vscode.window.terminals) if (t.name === 'Read-only check') t.dispose();
    const term = vscode.window.createTerminal({ name: 'Read-only check', cwd: root.uri.fsPath });
    checkRuns[check] = { done: false, exit: null, started: Date.now() };
    term.show(false);
    await vscode.commands.executeCommand('workbench.action.toggleMaximizedPanel').then(() => {}, () => {});
    const run = checkRuns[check];
    // Shell integration tells when the command ends; without it, give it a fixed time.
    for (let k = 0; k < 20 && !term.shellIntegration; k++) await sleep(250);
    if (term.shellIntegration) {
      const ex = term.shellIntegration.executeCommand(C);
      const sub = vscode.window.onDidEndTerminalShellExecution((e) => { if (e.execution === ex) { run.done = true; run.exit = e.exitCode; sub.dispose(); } });
    } else { term.sendText(C, true); setTimeout(() => { run.done = true; }, 300000); }
    return { terminal: 'Read-only check', shellIntegration: !!term.shellIntegration };
  },
  async checkStatus({ check }) { return checkRuns[check] || { done: false }; },
  async command({ id, args = [] }) {
    if (!COMMANDS.has(id)) throw new Error(`command not allowed: ${id}`);
    const a = id === 'revealInExplorer' ? [vscode.Uri.file(mustBeInside(args[0]))] : args;
    await vscode.commands.executeCommand(id, ...a);
    return { ran: id };
  },
};

// ---- server -------------------------------------------------------------------
function handler(req, res) {
  const send = (code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  // Only same-machine callers that name 127.0.0.1 (no DNS-rebinding pages).
  if (req.method !== 'POST' || req.url !== '/cmd' || !/^(127\.0\.0\.1|localhost):\d+$/.test(req.headers.host || '')) return send(404, { ok: false });
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 1e6) req.destroy(); });
  req.on('end', async () => {
    let msg;
    try { msg = JSON.parse(body); } catch { return send(400, { ok: false, error: 'bad json' }); }
    const a = Buffer.from(String(msg.token || '')), b = Buffer.from(token);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return send(403, { ok: false, error: 'bad token' });
    const op = ops[msg.op];
    if (!op) return send(400, { ok: false, error: `unknown op ${msg.op}` });
    try {
      const result = await op(msg.args || {});
      out.appendLine(`${new Date().toISOString()} ${msg.op} ok`);
      send(200, { ok: true, result });
    } catch (e) {
      out.appendLine(`${new Date().toISOString()} ${msg.op} FAILED: ${e.message}`);
      send(200, { ok: false, error: e.message });
    }
  });
}

function activate(ctx) {
  out = vscode.window.createOutputChannel('Contoso cockpit bridge');
  ctx.subscriptions.push(out, vscode.commands.registerCommand('cockpitBridge.status', () => {
    vscode.window.showInformationMessage(server ? `Cockpit bridge on (port ${server.address().port})` : 'Cockpit bridge off in this window (not a Contoso demo workspace)');
  }));
  stopDeco = vscode.window.createTextEditorDecorationType({
    isWholeLine: true, backgroundColor: 'rgba(255,214,102,0.14)',
    borderWidth: '0 0 0 3px', borderStyle: 'solid', borderColor: 'rgba(240,170,40,0.75)',
    overviewRulerColor: 'rgba(240,170,40,0.8)', overviewRulerLane: vscode.OverviewRulerLane.Full,
  });
  stopBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  const fail = (e) => { out.appendLine(`${new Date().toISOString()} stop FAILED: ${e.message}`); vscode.window.showErrorMessage(`Lab stop: ${e.message}`); };
  ctx.subscriptions.push(stopDeco, stopBar,
    vscode.window.onDidChangeVisibleTextEditors((eds) => paintStop(eds)),
    vscode.window.onDidChangeActiveTextEditor(() => showBar()),
    vscode.window.registerUriHandler({
      handleUri(uri) {
        const q = new URLSearchParams(uri.query);
        if (uri.path === '/open' && q.get('stop')) return openStop(q.get('stop')).catch(fail);
        if (uri.path === '/next') return stepStop(+1).catch(fail);
        fail(new Error(`unknown link ${uri.path}?${uri.query}`));
      },
    }),
    vscode.commands.registerCommand('cockpitBridge.openStop', async (key) => {
      if (!key) key = await vscode.window.showInputBox({ prompt: 'Lab Guide stop number or id', placeHolder: '2 or pipeline' });
      if (key) return openStop(String(key)).catch(fail);
    }),
    vscode.commands.registerCommand('cockpitBridge.nextStopFile', () => stepStop(+1).catch(fail)),
    vscode.commands.registerCommand('cockpitBridge.prevStopFile', () => stepStop(-1).catch(fail)),
    vscode.commands.registerCommand('cockpitBridge.clearStop', () => { for (const e of vscode.window.visibleTextEditors) e.setDecorations(stopDeco, []); stop = null; showBar(); vscode.commands.executeCommand('setContext', 'cockpitBridge.stopOpen', false); }),
  );
  if (!demoWorkspace()) { out.appendLine('Not a Contoso demo workspace: bridge stays off.'); return; }
  token = crypto.randomBytes(24).toString('hex');
  server = http.createServer(handler);
  server.listen(0, '127.0.0.1', () => {
    fs.mkdirSync(REG_DIR, { recursive: true, mode: 0o700 });
    regFile = path.join(REG_DIR, `${process.pid}.json`);
    const entry = { pid: process.pid, port: server.address().port, token, workspaceFile: vscode.workspace.workspaceFile.fsPath, folders: folders(), started: new Date().toISOString() };
    fs.writeFileSync(regFile, JSON.stringify(entry, null, 2), { mode: 0o600 });
    out.appendLine(`Bridge on 127.0.0.1:${entry.port} for ${entry.workspaceFile}`);
  });
  // Fixed local port for the Lab Guide's "Open in VS Code" button. Browsers
  // often drop vscode:// links from embedded pages; a plain local link works.
  // GET only, stop ids only (no paths), 127.0.0.1 only.
  if (vscode.workspace.workspaceFile && vscode.workspace.workspaceFile.fsPath === LIVE_WS) {
    guideServer = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://127.0.0.1');
      const key = u.searchParams.get('stop') || '';
      const page = (msg) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(`<!doctype html><meta charset=utf-8><title>Lab stop</title><body style="font:16px -apple-system,sans-serif;padding:24px;background:#111;color:#eee">${msg}<script>setTimeout(()=>window.close(),900)</script>`); };
      if (req.method !== 'GET' || u.pathname !== '/open' || !/^[a-z0-9-]{1,40}$/i.test(key)) { res.writeHead(404); return res.end(); }
      openStop(key).then((r) => page(r ? `Opened stop ${r.n} in VS Code. This tab closes itself.` : 'Stop not found.'))
        .catch((e) => { out.appendLine(`guide link FAILED: ${e.message}`); page('Could not open that stop. See the bridge output in VS Code.'); });
    });
    guideServer.on('error', (e) => out.appendLine(`Guide port 47821 not available: ${e.message}`));
    guideServer.listen(47821, '127.0.0.1', () => out.appendLine('Guide links on http://127.0.0.1:47821/open?stop=<id>'));
  }
  ctx.subscriptions.push({ dispose: deactivate });
}

function deactivate() {
  try { if (regFile) fs.rmSync(regFile, { force: true }); } catch {}
  try { server && server.close(); } catch {}
  try { guideServer && guideServer.close(); } catch {}
  guideServer = null;
  server = null; regFile = null;
}

module.exports = { activate, deactivate };
