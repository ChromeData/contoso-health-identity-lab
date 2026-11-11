#!/usr/bin/env node
// Contoso recording cockpit: one command, then the presenter only reads the
// line on the teleprompter and presses NEXT.
//
//   node cockpit.mjs                 live (records with OBS, one file per piece)
//   node cockpit.mjs --dry           dry run: every action against the current
//                                    state, nothing changed, nothing recorded
//   node cockpit.mjs --rehearse      piece 1 for real on a throwaway branch,
//                                    PR closed without merging
//   options: --port 4747  --record / --no-record  --display "DELL"  --no-open
//            --mouse human|guide|dom  (default human: the real pointer, moved
//            like a person; guide: you click, the cockpit shows where;
//            dom: the old drawn pointer). --guide = --mouse guide,
//            --old-mouse = --mouse dom.
//            --auto (dry/rehearse: press NEXT by itself, for unattended tests)
//   node cockpit.mjs --proof 1       piece 1's VS Code part only, on a throwaway
//                                    copy, recorded into the preview folder as
//                                    01-vscode-proof.mp4 (no commit, push or PR)
//   node cockpit.mjs --tour-extra    piece 11's four extra stops only (VS Code,
//                                    read only), as 11-tour-extra.narrated.mp4
//
// The teleprompter is served on this Mac AND the local network (for a phone
// or iPad). Every request needs the pairing key in the URL (?k=...), kept in
// .state/ui-key so a bookmarked phone keeps working.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { Cockpit } from './lib/engine.mjs';
import { makeNarration } from './lib/narration.mjs';
import { attachSpeech } from './lib/speech.mjs';
import { attachPresenter } from './lib/presenter.mjs';
import { Browser } from './lib/browser.mjs';
import { curtainUp, curtainDown, curtainRecover } from './lib/curtain.mjs';
import { setLocalBase, resolveLocal } from './lib/localurl.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const argv = process.argv.slice(2);
// --watch: the owner just watches. Autopilot dry run (changes nothing in the
// lab), OBS records, each step's narration plays aloud, and the script shows
// in a floating card that OBS cannot see (tools/script-overlay.swift).
const watch = argv.includes('--watch');
// --watch --no-record: the same hands-free dry run (real pointer, voice,
// stage watchdog) with OBS left alone, to prove the pointer path.
if (watch) for (const f of ['--dry', '--auto', argv.includes('--no-record') ? null : '--record', '--no-open', '--no-preflight']) if (f && !argv.includes(f)) argv.push(f);
const flag = (f) => argv.includes(f);
const opt = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
// --preview: the whole demo on autopilot, recorded silently, narrated
// afterwards, then the lab put back (see README). --preview --dry: the same
// flow as a dry run (nothing changed, nothing recorded).
// --storyboard N13: the part's steps on autopilot with no recording and no
// narration audio; one screenshot at each step's hold point, then a contact
// sheet (PNG grid + Markdown table) in recordings/storyboards/. Minutes, not
// hours: the way to check a fix. --check N13: pass/fail, no screenshots
// (tools/check-part.mjs).
const storyboard = opt('--storyboard', null);
if (opt('--check', null)) {
  const { execFileSync } = await import('node:child_process');
  try { execFileSync(process.execPath, [new URL('./tools/check-part.mjs', import.meta.url).pathname, opt('--check')], { stdio: 'inherit' }); process.exit(0); } catch { process.exit(1); }
}
const preview = flag('--preview') || !!storyboard;
const mode = preview ? (flag('--dry') ? 'dry' : 'preview') : flag('--dry') ? 'dry' : flag('--rehearse') ? 'rehearse' : 'live';
const port = +opt('--port', 4747);
const record = storyboard ? false : flag('--record') ? true : flag('--no-record') ? false : null;

fs.mkdirSync(path.join(here, '.state'), { recursive: true, mode: 0o700 });
const keyFile = path.join(here, '.state', 'ui-key');
if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, crypto.randomBytes(6).toString('hex'), { mode: 0o600 });
const KEY = fs.readFileSync(keyFile, 'utf8').trim();
const logFile = path.join(here, '.state', `cockpit-${new Date().toISOString().slice(0, 10)}.log`);
// --quiet (npm run record / npm run watch): the terminal shows only what the
// presenter must do (lines marked "» "); everything goes to the log file.
const quiet = argv.includes('--quiet');
const log = (line) => { if (!quiet || /» /.test(line)) console.log(quiet ? String(line).replace(/^\d\d:\d\d:\d\d /, '') : line); fs.appendFileSync(logFile, line + '\n'); };
const tell = (line) => log(`» ${line}`);
// An earlier run killed before it could show the hidden apps again and put
// the Dock back (lib/curtain.mjs): done now.
curtainRecover(here, log);

// --preview-reset: only the teardown, from the last preview's saved state
// (when a preview stopped half-way). With --dry it says what it would do.
// --v2: the 18 parts of segments/V2-RUNNING-ORDER.md. --part 2,3,4,8 runs
// those parts only; --out <dir> records there; --include-pending also loads
// the PENDING BUILD parts (they stop on their TODO); --raj-ticket INC... is
// the real ServiceNow incident in Raj's reason (N05, live only).
const v2 = flag('--v2') || !!storyboard;
const parts = (opt('--part', null) || storyboard) ? (opt('--part', null) || storyboard).split(',').map((x) => +x.trim().replace(/^N/i, '').replace(/^(\d+)b$/i, '$1.5')).filter((x) => Number.isFinite(x)) : null;
const outDir = opt('--out', null) ? path.resolve(opt('--out').replace(/^~(?=\/)/, os.homedir())) : null;

if (v2 && flag('--preview-reset')) {
  // The v2 preview's test hire, from .state/v2-hire.json (hireReset refuses anyone else).
  const { hireReset } = await import('./lib/teardown.mjs');
  const f = path.join(here, '.state', 'v2-hire.json');
  if (!fs.existsSync(f)) { log('--v2 --preview-reset: no test hire recorded (.state/v2-hire.json)'); process.exit(0); }
  const h = JSON.parse(fs.readFileSync(f, 'utf8'));
  const r = await hireReset({ root: here, id: h.hireId, upn: h.upn, name: h.name, dry: flag('--dry'), log });
  for (const x of r) log(`${x.ok ? 'OK ' : 'FAILED'} ${x.name}${x.note ? `: ${String(x.note).split('\n')[0]}` : ''}`);
  if (r.every((x) => x.ok) && !flag('--dry')) fs.rmSync(f, { force: true });
  process.exit(r.every((x) => x.ok) ? 0 : 1);
}

if (flag('--preview-reset')) {
  const { previewReset } = await import('./lib/teardown.mjs');
  const f = path.join(here, '.state', 'preview-last.json');
  const c = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : { hr: path.join(os.homedir(), 'contoso-demo', 'hr') };
  const r = await previewReset({ root: here, c, dry: flag('--dry'), log });
  for (const x of r) log(`${x.ok ? 'OK ' : 'FAILED'} ${x.name}${x.note ? `: ${String(x.note).split('\n')[0]}` : ''}`);
  process.exit(r.every((x) => x.ok) ? 0 : 1);
}

// --proof 1: piece 1's VS Code part only (diff, nurse, cloud, rule, the
// commit message typed), on a throwaway rehearsal copy, recorded silently and
// narrated into the preview's folder as 01-vscode-proof.mp4. Nothing is
// committed, pushed or opened on GitHub; the copy is removed afterwards.
if (opt('--proof', null)) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  if (+opt('--proof') !== 1) { log('--proof: only piece 1 has a VS Code part (--proof 1)'); process.exit(1); }
  const pk = new Cockpit({ mode: 'rehearse', record: true, root: here, port: +opt('--port', 4747), log, proof: true });
  await pk.init();
  const ids = ['1-diff', '1-nurse', '1-cloud', '1-rule', '1-commit'];
  pk.list = pk.list.filter((x) => ids.includes(x.id))
    .map((x) => x.id === '1-commit' ? { ...x, do: x.do.map((a) => a.do === 'code.commit' ? { ...a, typeOnly: true } : a) } : x);
  if (pk.list.length !== ids.length) { log(`--proof: expected ${ids.join(', ')}`); process.exit(1); }
  if (pk.rec.kind !== 'obs') { log(`--proof: OBS is not ready (${pk.rec.note})`); await pk.close(); process.exit(1); }
  await pk.prepareStage();
  pk.narration = await makeNarration(pk.list, path.join(here, 'narration'), log);
  for (let k = 0; k < pk.list.length; k++) {
    await pk.go(k);
    await sleep((pk.narration[pk.list[k].id]?.dur ?? 2) * 1000 + 700);
    while (pk.busy) await sleep(500);
    if (pk.error) { log(`--proof: [${pk.list[k].id}] failed: ${pk.error}`); break; }
  }
  const f = await pk.rec.endPiece();
  let ok = false;
  if (f && !pk.error) {
    const { mixPiece } = await import('./lib/mix.mjs');
    const clips = pk.timeline.filter((t) => pk.narration[t.id]).map((t) => ({ file: pk.narration[t.id].file, at: t.at }));
    const out = path.join(pk.rec.dir, '01-vscode-proof.mp4');
    const r = await mixPiece(f.replace(/\.(mkv|mov)$/i, '.mp4'), clips, out);
    log(`proof: ${out} (${r.clips} clips, ${r.len.toFixed(1)} s)`);
    fs.appendFileSync(path.join(os.homedir(), 'contoso-demo', 'readiness', 'progress.log'), `${new Date().toISOString().replace(/\.\d+Z$/, 'Z')} | cockpit | piece 1 VS Code proof clip recorded (rehearsal copy: diff, nurse, cloud, rule, commit message typed; no commit, push or PR) | ${out} | ${Math.floor(r.len / 60)} min ${Math.round(r.len % 60)} s\n`);
    ok = true;
  }
  // The throwaway copy: its window closed, its worktree and local branch removed.
  await pk.code.closeWindow().catch(() => {});
  const { sh, LAB } = await import('./lib/live.mjs');
  await sh('git', ['-C', LAB, 'worktree', 'remove', '--force', pk.c.bp]).catch((e) => log(`proof: worktree remove: ${e.message}`));
  await sh('git', ['-C', LAB, 'branch', '-D', pk.c.bpBranch]).catch((e) => log(`proof: branch delete: ${e.message}`));
  await pk.close();
  process.exit(ok ? 0 : 1);
}

// --tour-extra: piece 11's four extra stops only (the lab at origin/main
// and the live read-only checks, in the tour's VS Code window of the
// "Contoso Demo" profile), recorded silently and narrated into the preview's
// folder as 11-tour-extra.narrated.mp4. Run tools/tour-extra-checks.sh first
// (the stops show its output). Nothing is changed anywhere.
if (flag('--tour-extra')) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const out = path.join(here, 'tour', 'out');
  const fresh = ['1-rbac-lint.txt', '2-scanner-selftest-ci.txt', '4-not-yet-on.txt'].every((f) => fs.existsSync(path.join(out, f)) && Date.now() - fs.statSync(path.join(out, f)).mtimeMs < 3 * 3600000);
  if (!fresh) { log('--tour-extra: run tools/tour-extra-checks.sh first (its output must be under 3 hours old)'); process.exit(1); }
  const pk = new Cockpit({ mode: 'rehearse', record: true, root: here, port: +opt('--port', 4747), log, proof: true, tour: true });
  await pk.init();
  if (pk.list.length !== 4) { log(`--tour-extra: expected 4 stops, found ${pk.list.map((x) => x.id).join(', ')}`); process.exit(1); }
  if (pk.rec.kind !== 'obs') { log(`--tour-extra: OBS is not ready (${pk.rec.note})`); await pk.close(); process.exit(1); }
  if (flag('--ring')) pk.startRing();
  await pk.prepareStage();
  pk.narration = await makeNarration(pk.list, path.join(here, 'narration'), log);
  // Its own file name: the accepted tour (11-the-tour.*) is never replaced.
  pk.pieceSlug = 'tour-extra-raw';
  for (let k = 0; k < pk.list.length; k++) {
    await pk.go(k);
    if (k === 0 && pk.rec.piece && pk.rec.piece.slug !== pk.pieceSlug) { log('--tour-extra: recording started under the wrong name: stopping'); await pk.close(); process.exit(1); }
    for (const end = Date.now() + (pk.narration[pk.list[k].id]?.dur ?? 2) * 1000 + 700; Date.now() < end;) { await pk.stageGuard(); await sleep(400); }
    while (pk.busy) await sleep(500);
    if (pk.error) { log(`--tour-extra: [${pk.list[k].id}] failed: ${pk.error}`); break; }
  }
  const f = await pk.rec.endPiece();
  let ok = false;
  if (f && !pk.error) {
    const { mixPiece } = await import('./lib/mix.mjs');
    const clips = pk.timeline.filter((t) => pk.narration[t.id]).map((t) => ({ file: pk.narration[t.id].file, at: t.at }));
    const mixed = path.join(pk.rec.dir, '11-tour-extra.narrated.mp4');
    const r = await mixPiece(f.replace(/\.(mkv|mov)$/i, '.mp4'), clips, mixed);
    fs.writeFileSync(path.join(pk.rec.dir, '11-tour-extra.timeline.json'), JSON.stringify({ at: new Date().toISOString(), steps: pk.timeline }, null, 1));
    log(`tour-extra: ${mixed} (${r.clips} clips, ${r.len.toFixed(1)} s)`);
    ok = r.clips === 4;
  }
  await pk.recordingLook(false);
  await pk.code.closeWindow().catch(() => {});
  await pk.close();
  process.exit(ok ? 0 : 1);
}

// --ohrm-login: the recording browser opened at OrangeHRM's login page for
// the owner to sign in by hand (the cockpit never types that password); it
// closes once the session is there (10 minutes at most).
if (flag('--ohrm-login')) {
  const { OHRM_LOGIN } = await import('./lib/engine.mjs');
  const B = new Browser({ profileDir: path.join(here, '.recording-profile'), shotsDir: path.join(here, 'shots'), log });
  await B.launch();
  await B.page.goto(OHRM_LOGIN, { waitUntil: 'domcontentloaded' }).catch((e) => tell(`OrangeHRM: ${e.message.split('\n')[0]}`));
  tell(`Sign in to OrangeHRM in the window that just opened (${OHRM_LOGIN}); it closes by itself once you are in.`);
  let ok = false;
  for (let k = 0; k < 600 && !ok; k++) { await new Promise((r) => setTimeout(r, 1000)); ok = !!B.page && !B.page.isClosed() && /127\.0\.0\.1:8585\/web\/index\.php\/(?!auth\/)/.test(B.page.url()); }
  tell(ok ? 'OrangeHRM: signed in (recording browser)' : 'OrangeHRM: no session after 10 minutes');
  await B.close();
  process.exit(ok ? 0 : 1);
}

const resumeFrom = opt('--resume-from', null) ? +opt('--resume-from') : null;
// --only N (with --resume-from N): retake just that piece, then join the
// preview again; --no-teardown: don't put the lab back afterwards.
const only = opt('--only', null) ? +opt('--only') : null;
const mouse = flag('--old-mouse') ? 'dom' : flag('--guide') ? 'guide' : opt('--mouse', 'human');
if (!['human', 'guide', 'dom'].includes(mouse)) { log(`--mouse must be human, guide or dom (not ${mouse})`); process.exit(1); }
const ck = new Cockpit({ mode, record, root: here, display: opt('--display', ''), port, log, preview, resumeFrom, only, teardown: !flag('--no-teardown') && !storyboard, readyLabel: opt('--ready-label', null),
  v2, parts, includePending: flag('--include-pending'), outDir, rajTicket: opt('--raj-ticket', null), mouse, watch });
await ck.init();
// --pim-since <ISO time>: a run resumed at piece 7 looks for the alarm on
// Raj's activation from piece 6 of an earlier run (not an older one).
if (opt('--pim-since', null)) { ck.c.pimActivatedAt = Date.parse(opt('--pim-since')); log(`piece 7 looks for incidents about Raj from ${new Date(ck.c.pimActivatedAt).toISOString()} on`); }
// --skip 4-snow-staff,...: leave steps out of this run (e.g. a step blocked
// by something outside the cockpit), said in the log.
if (opt('--skip', null)) {
  const skip = new Set(opt('--skip').split(',').map((x) => x.trim()).filter(Boolean));
  const unknown = [...skip].filter((id) => !ck.list.some((x) => x.id === id));
  if (unknown.length) { log(`--skip: no such step: ${unknown.join(', ')}`); process.exit(1); }
  ck.list = ck.list.filter((x) => !skip.has(x.id));
  log(`steps left out of this run: ${[...skip].join(', ')}`);
}

// The speech-aware teleprompter (lib/speech.mjs): checks each point off as it
// is said, in his own words; auto-advance presses NEXT when all are. Never in
// unattended runs. --no-listen: off for this run (L on the teleprompter toggles it).
const speech = await attachSpeech(ck, { root: here, log, enabled: !flag('--no-listen') && !preview && !flag('--auto') });

// The presenter's card (tools/script-overlay.swift): top centre under the
// camera, invisible to OBS, global hotkeys. Every mode; --no-card turns it off.
// --clicker: a presentation clicker's PageDown / PageUp work from anywhere.
const card = flag('--no-card') ? null : attachPresenter(ck, { root: here, log, clicker: flag('--clicker'), compact: flag('--compact') });

const lan = Object.values(os.networkInterfaces()).flat().find((i) => i && i.family === 'IPv4' && !i.internal)?.address;
const page = fs.readFileSync(path.join(here, 'ui', 'index.html'), 'utf8');

// The lab maps, served read-only without the pairing key (the recording
// browser shows this address on camera: http://localhost:<port>/map, not a
// /Users/... file path, and no key). Only these two pages, only to this Mac.
const MAP_PAGES = { '/map': 'lab-map.html', '/map/v24': 'v24.html' };
Browser.MAP_URL = `http://localhost:${port}/map`;
// The cards (/card#...) and captured screens (/shots/...), the same way
// (lib/localurl.mjs): no key, no /Users/... path, this Mac only.
setLocalBase(`http://localhost:${port}`);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const mapPage = MAP_PAGES[url.pathname.replace(/\/$/, '')];
  if (mapPage && (req.method === 'GET' || req.method === 'HEAD')) {
    const local = /^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/.test(req.socket.remoteAddress || '');
    if (!local) { res.writeHead(403, { 'content-type': 'text/plain' }); res.end('The map is served to this Mac only.'); return; }
    fs.readFile(path.join(here, 'map', mapPage), (e, buf) => {
      if (e) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' });
      res.end(req.method === 'HEAD' ? undefined : buf);
    });
    return;
  }
  const loc = (req.method === 'GET' || req.method === 'HEAD') ? resolveLocal(url.pathname) : null;
  if (loc) {
    const local = /^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/.test(req.socket.remoteAddress || '');
    if (!local) { res.writeHead(403, { 'content-type': 'text/plain' }); res.end('Served to this Mac only.'); return; }
    fs.readFile(loc.file, (e, buf) => {
      if (e) { res.writeHead(404); res.end(); return; }
      const head = { 'content-type': loc.type, 'accept-ranges': 'bytes', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' };
      // Ranges: a captured video (web.video) is played from a point.
      const r = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
      if (r && (r[1] || r[2])) {
        let a = r[1] ? +r[1] : buf.length - +r[2], b = r[1] && r[2] ? Math.min(+r[2], buf.length - 1) : buf.length - 1;
        if (a < 0) a = 0;
        if (a > b || a >= buf.length) { res.writeHead(416, { 'content-range': `bytes */${buf.length}` }); res.end(); return; }
        res.writeHead(206, { ...head, 'content-range': `bytes ${a}-${b}/${buf.length}`, 'content-length': b - a + 1 });
        res.end(req.method === 'HEAD' ? undefined : buf.subarray(a, b + 1));
        return;
      }
      res.writeHead(200, { ...head, 'content-length': buf.length });
      res.end(req.method === 'HEAD' ? undefined : buf);
    });
    return;
  }
  const cookieKey = /(?:^|;\s*)ck=([0-9a-f]+)/.exec(req.headers.cookie || '')?.[1];
  const k = url.searchParams.get('k') || cookieKey;
  const keyOk = k && k.length === KEY.length && crypto.timingSafeEqual(Buffer.from(k), Buffer.from(KEY));
  if (!keyOk) { res.writeHead(403, { 'content-type': 'text/plain' }); res.end('Open the link the cockpit printed (it has the pairing key).'); return; }
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'set-cookie': `ck=${KEY}; Path=/; SameSite=Strict; Max-Age=2592000`, 'cache-control': 'no-store' });
    res.end(page); return;
  }
  if (req.method === 'GET' && url.pathname === '/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
    const send = (s) => res.write(`data: ${JSON.stringify(s)}\n\n`);
    send(ck.state());
    const off = ck.on(send);
    const ping = setInterval(() => res.write(': ping\n\n'), 15000);
    req.on('close', () => { off(); clearInterval(ping); });
    return;
  }
  if (req.method === 'POST' && url.pathname.startsWith('/api/')) {
    const what = url.pathname.slice(5);
    const acts = { next: () => ck.next(), back: () => ck.back(), redo: () => ck.redo(), retake: () => ck.retake(), ring: async () => ck.toggleRing(),
      listen: () => speech.toggleListen(), autoadvance: () => speech.toggleAuto(),
      preflight: () => ck.runPreflight(), signins: () => ck.checkSignins(), jump: () => ck.jump(+url.searchParams.get('to')),
      // The pointer, live: /api/mouse?mode=human|guide|dom, /api/guide toggles guide.
      mouse: () => ck.setMouse(url.searchParams.get('mode') || 'human'), guide: () => ck.setMouse('toggle-guide'), pause: () => ck.togglePause() };
    if (!acts[what]) { res.writeHead(404); res.end(); return; }
    res.writeHead(202, { 'content-type': 'application/json' }); res.end('{"ok":true}');
    acts[what]().catch((e) => log(`${what}: ${e.stack || e.message}`));
    return;
  }
  res.writeHead(404); res.end();
});
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') { log(`Port ${port} is taken (another cockpit is running?): close it, or start this one with --port <another>`); process.exit(1); }
  throw e;
});
server.listen(port, '0.0.0.0', () => {
  log(`\nContoso recording cockpit · ${mode.toUpperCase()}`);
  log(`  this Mac:      http://localhost:${port}/?k=${KEY}`);
  if (lan) log(`  phone / iPad:  http://${lan}:${port}/?k=${KEY}   (same Wi-Fi)`);
  log(`  keys: Space / → / PageDown = NEXT · ← / PageUp = BACK · R = redo step · T = retake piece · C = cursor ring on/off · L = listening on/off · A = auto-advance on/off · M = pointer human/guide/dom\n`);
  if (flag('--ring')) ck.startRing();   // off by default (owner, 2026-11-10): --ring or C turns it on
  if (!flag('--no-open')) execFile('open', [`http://localhost:${port}/?k=${KEY}`], () => {});
  // --no-preflight: skip the 4-minute lab preflight (a dry run or a preview of parts that need no lab check).
  if (flag('--no-preflight')) { ck.preflight = { running: false, skipped: true, checks: [] }; log('preflight skipped (--no-preflight)'); }
  else ck.runPreflight().catch((e) => log(`preflight: ${e.message}`));
  if (flag('--start') && !watch) startSequence().catch((e) => tell(`start: ${e.message}`));
  if (preview) previewRun().catch((e) => log(`preview: ${e.stack}`));
  else if (flag('--auto')) autoRun().catch((e) => log(`auto: ${e.stack}`));
});

// npm run record: preflight, the stage set, sign-ins checked, the first
// page opened in a background tab, then READY on the presenter card. The
// terminal says only what he must do.
async function startSequence() {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  tell(`${mode.toUpperCase()} · getting ready (lab preflight, stage, sign-ins): watch the card at the top of the screen`);
  // N16's n16-off says "a read-only check just before recording shows none
  // is on": tools/tour-extra-checks.sh (reads only: list / describe / GET as
  // the lab operator, plus the RBAC linter run here) refreshes tour/out,
  // which N16 shows. Runs while the lab preflight runs.
  const tourChecks = new Promise((resolve) => execFile('bash', [path.join(here, 'tools', 'tour-extra-checks.sh')], { cwd: here, timeout: 300000, maxBuffer: 4 << 20 }, (e, so, se) => {
    if (!e) { log(`tour-extra checks: ${String(so).trim().split('\n').pop()}`); resolve(null); return; }
    const why = (String(se).trim().split('\n').pop() || e.message).slice(0, 200);
    log(`tour-extra checks failed: ${why}`); resolve(`N16 read-only checks (tools/tour-extra-checks.sh): ${why}`);
  }));
  while (ck.preflight?.running !== false) await sleep(1000);
  const todo = [];
  const tourFail = await tourChecks; if (tourFail) todo.push(tourFail);
  if (ck.preflight && !ck.preflight.skipped && !ck.preflight.ready) for (const l of ck.preflight.lines || []) if (l.mark === '✗') todo.push(l.text);
  const sig = await ck.checkSignins().catch((e) => ({ sites: [{ name: 'sign-ins', ok: false, note: e.message }] }));
  for (const x of sig?.sites || []) if (!x.ok) todo.push(`${x.name}: ${x.note}`);
  if (ck.recordWanted && !(ck.rec.kind === 'obs' && ck.rec.captureOk)) todo.push(`OBS: ${ck.rec.note}`);
  await ck.browser.launch().catch(() => {});
  await ck.browser.ensureMapTab().catch(() => {});
  await ck.prefetchStep(0).catch(() => {});
  if (todo.length) {
    ck.setLight('red', `${todo.length} thing(s) to do first`);
    tell(`NOT READY: ${todo.length} thing(s) to do first:`);
    for (const t of todo) tell(`  - ${t}`);
    tell('then press ⌃⌥→ (or the teleprompter\'s NEXT) to start anyway');
  } else {
    ck.setLight('off', 'READY');
    tell('READY. Look at the camera. Say each line in your own words; the card ticks it off and the cockpit moves on.');
  }
  tell('Keys (anywhere): ⌃⌥→ next · ⌃⌥← back · ⌃⌥R redo · ⌃⌥P pause · ⌃⌥C compact card' + (flag('--clicker') ? ' · clicker PageDown/PageUp' : '') + ' · Ctrl-C here to stop (the take is saved)');
}

// Unattended test driver (dry / rehearse only): presses NEXT whenever the
// step is done and its light is not yellow.
async function autoRun() {
  if (mode === 'live') throw new Error('--auto is for --dry and --rehearse only');
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  while (ck.preflight?.running !== false) await sleep(1000);
  // --piece N: just that piece (a standalone single-piece dry run).
  const piece = opt('--piece', null) != null ? +opt('--piece') : null;
  if (piece != null) {
    if (mode === 'dry') await ck.checkSignins().catch((e) => log(`sign-ins: ${e.message}`));
    await ck.jump(ck.list.findIndex((x) => x.piece === piece));
    while (ck.list[ck.i + 1]?.piece === piece) {
      while (ck.busy || ck.light.color === 'blue') await sleep(1000);
      await ck.next();
      while (ck.busy) await sleep(1000);
    }
    ck.writeDryReport();
    log(`auto: piece ${piece} finished`);
    await ck.close();
    process.exit(0);
  }
  if (watch) return watchRun();
  for (;;) {
    // A dry run checks each wait once and never blocks on it.
    while (ck.busy || ck.light.color === 'blue' || (mode !== 'dry' && ck.light.color === 'yellow')) await sleep(1500);
    if (ck.done) break;
    await sleep(mode === 'dry' ? 1500 : 4000);
    await ck.next();
  }
  log('auto: finished');
  await ck.close();
  process.exit(0);
}

// --watch: hands-free show. Each step: card up, its action runs, its
// narration plays from the moment its screen is up (or with the action, for
// lineWithAction steps), held for the clip's length, then the next step.
// The camera follows the unattended rules (engine.unattended): it is paused
// while pages load and while a long check runs (n17-check: ~3.5 min of dead
// time before), starts/rolls only when the stage window is in front, and a
// watchdog pauses it the moment anything else comes forward (2026-11-10: the
// lead's own full-screen VS Code window was on camera in N16 and N17).
// The on-screen caption of a step (silent clips): its line, placeholders out.
function captionText(s) {
  return (s.caption || s.say.join(' ')).replace(/\[[^\]]*\]/g, '').replace(/\s+/g, ' ').trim();
}
const silent = argv.includes('--silent');

// --watch / clips: before anything records, every sign-in the selected parts
// need is done (adm-presenter with PIM-Demo-Readers activated, ServiceNow's
// recovery account, splunk-admin, the staff window) and OrangeHRM's session
// (the owner's own) is checked. Any failure: the exact list, and no recording
// (2026-11-11 clips: an expired PIM-Demo-Readers showed "You don't have
// access" in N04, N04b, N09, N10, N11; Splunk an empty login page in N07).
async function watchSignins() {
  const need = ck.watchNeeds();
  log(`watch: signing in before recording: ${[...need].join(', ') || 'nothing needed'}`);
  const bad = [];
  const sites = [...need].filter((n) => n !== 'OrangeHRM');
  if (sites.length) {
    const sig = await ck.checkSignins({ need: new Set(sites) }).catch((e) => ({ sites: [], error: e.message.split('\n')[0] }));
    for (const n of sites) {
      const x = (sig.sites || []).find((y) => y.name === n);
      if (!x) bad.push(`${n}: not signed in${sig.error ? ` (${sig.error})` : ''}`);
      else if (!x.ok) bad.push(`${n}: ${x.note}`);
      else log(`watch: sign-in ${n}: ${x.note}`);
    }
  } else await ck.prepareStage();
  if (need.has('OrangeHRM')) {
    const r = await ck.orangeHrmSession().catch((e) => ({ ok: false, note: e.message.split('\n')[0] }));
    if (!r.ok) bad.push(`OrangeHRM: ${r.note}`); else log(`watch: OrangeHRM: ${r.note}`);
  }
  return bad;
}

async function watchRun() {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const bad = await watchSignins();
  if (bad.length) {
    tell(`watch: REFUSED, nothing recorded: ${bad.length} sign-in(s) the selected parts need failed:`);
    for (const b of bad) tell(`  - ${b}`);
    ck.setLight('red', `Refused: ${bad.length} sign-in(s) failed (see the log)`);
    card?.stop();
    await ck.close();
    process.exit(1);
  }
  // Before anything records: every app not part of the demo hidden (never
  // quit) and the Dock out of reach (lib/curtain.mjs; put back at the end, on
  // Ctrl-C and on a crash), the lead's VS Code windows minimized (out of full
  // screen first).
  await ck.browser.launch().catch(() => {});
  log(curtainUp({ root: here, keepPids: ck.cockpitPids(), log }));
  await ck.clearOthers();
  ck.startStageWatch();
  const narr = silent ? {} : await makeNarration(ck.list, path.join(here, 'narration'), log).catch((e) => { log(e.message); return {}; });
  ck.narration = narr;
  // The first page, opened in a background tab before anything records.
  await ck.browser.launch().catch(() => {});
  await ck.browser.ensureMapTab().catch(() => {});
  await ck.prefetchStep(0).catch(() => {});
  tell('watch: READY · hands-free; ⌃⌥P pauses, Ctrl-C stops');
  const total = ck.list.length;
  // Gaps for the report: each line's recorded start and length (timeline.json).
  const lines = [];
  for (let k = 0; ; k++) {
    while (ck.busy || ck.held) await sleep(150);
    if (ck.done || (k > 0 && ck.i >= total - 1)) break;
    const t0 = Date.now();
    const was = ck.i;
    let settled = false;
    const go = ck.next().catch((e) => log(`watch: ${e.message}`)).finally(() => { settled = true; });
    for (let w = 0; w < 120 && ck.i === was; w++) await sleep(250);
    const s = ck.list[ck.i]; if (!s) { log(`watch: no step after NEXT (i=${ck.i})`); break; }
    const clip = silent ? null : narr[s.id];
    // --silent: no voice; each step is held long enough to read its caption
    // (tools/caption.py burns the step's line in afterwards).
    const text = captionText(s);
    const readMs = Math.max(3500, text.split(/\s+/).filter(Boolean).length / 2.6 * 1000 + 1200);
    const dur = Math.max(clip?.dur ? clip.dur * 1000 : silent ? readMs : Math.max(4000, s.say.join(' ').split(/\s+/).length / 2.5 * 1000), (s.hold || 0) * 1000);
    // The line starts with the step's first on-screen action (lineStarted):
    // the hand moves while the line is said.
    while (!settled && !((ck.lineStarted || 0) >= t0)) await sleep(50);
    const from = Date.now();
    const voice = clip?.file ? spawn('afplay', [clip.file], { stdio: 'ignore' }) : null;
    const at = await ck.rec.position().catch(() => null);
    lines.push({ id: s.id, piece: s.piece, at, clip: clip?.dur || 0, hold: s.hold || 0, text });
    await go;
    while (ck.busy) await sleep(100);
    for (const end = from + dur; Date.now() < end;) { await ck.stageGuard(); await sleep(100); }
    if (voice && voice.exitCode === null) await new Promise((r) => voice.on('exit', r));
    lines[lines.length - 1].end = await ck.rec.position().catch(() => null);
    await sleep(120);
  }
  if (ck.rec.dir) try { fs.writeFileSync(path.join(ck.rec.dir, 'watch-lines.json'), JSON.stringify(lines, null, 1)); } catch {}
  ck.stopStageWatch();
  card?.stop();
  log('watch: finished');
  await ck.close();
  curtainDown();
  process.exit(0);
}

// --preview autopilot: refuses to start until every sign-in and OBS are
// ready; then each step runs for real, is held for its narration clip's
// length, waits for its WAIT light (OBS paused meanwhile), and moves on.
async function previewRun() {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  while (ck.preflight?.running !== false) await sleep(1000);
  log('preview: checking sign-ins in the recording browser and OBS');
  const missing = (await ck.previewPreconditions()).filter((m) => !(storyboard && /^OBS:/.test(m)));
  if (missing.length) {
    log(`preview: ${mode === 'dry' ? 'NOT READY for a real preview (dry run goes on)' : 'REFUSED: not ready'}:`);
    for (const m of missing) log(`  - ${m}`);
    if (mode !== 'dry') { ck.setLight('red', `Preview refused: ${missing.length} thing(s) to do first (see the log)`); await ck.close(); process.exit(1); }
  }
  ck.narration = storyboard ? {} : await makeNarration(ck.list, path.join(here, 'narration'), log);
  const shots = [];
  const sbDir = storyboard ? path.join(os.homedir(), 'contoso-demo', 'recordings', 'storyboards', `${String(storyboard).toUpperCase()}`) : null;
  if (sbDir) { fs.rmSync(sbDir, { recursive: true, force: true }); fs.mkdirSync(sbDir, { recursive: true }); }
  const startAt = resumeFrom ? ck.list.findIndex((x) => x.piece === resumeFrom) : 0;
  // Preview 2 review: a piece with a FAILED step is retaken in the same lab
  // state before anything moves on: at once and automatically for view-only
  // pieces (once); otherwise the autopilot stops and says so (BLOCKED).
  const AUTO_RETAKE = v2 ? new Set(ck.pieces.filter((p) => p.autoRetake).map((p) => p.n)) : new Set([3, 4, 5, 8]);
  const retaken = {};
  const progress = (line) => fs.appendFileSync(path.join(os.homedir(), 'contoso-demo', 'readiness', 'progress.log'), `${new Date().toISOString().replace(/\.\d+Z$/, 'Z')} | cockpit | ${line}\n`);
  const pieceDone = async (n) => {   // 'ok' | 'again' | stops the run
    const bad = (ck.failedSteps || {})[n] || [];
    if (!bad.length || mode === 'dry' || storyboard) return 'ok';
    if (AUTO_RETAKE.has(n) && !retaken[n]) {
      retaken[n] = true;
      progress(`piece ${n} retake (automatic, same lab state) | FAILED: ${bad.join(', ')}`);
      log(`preview: piece ${n} had FAILED steps (${bad.join(', ')}): taking it again`);
      await ck.autoRetake(n);
      return 'again';
    }
    progress(`BLOCKED | piece ${n} needs a retake before the run goes on | FAILED: ${bad.join(', ')}; autopilot stopped`);
    log(`preview: STOPPED: piece ${n} still has FAILED steps (${bad.join(', ')})`);
    ck.setLight('red', `Piece ${n} needs a retake: autopilot stopped`);
    await ck.close(); process.exit(2);
  };
  const firstOf = (n) => ck.list.findIndex((x) => x.piece === n);
  for (let k = startAt; ;) {
    // The run's end (or --only's): the last piece is checked like any other.
    if (k >= ck.list.length || (only && ck.list[k].piece > only)) {
      const last = ck.list[ck.i];
      if (last && (await pieceDone(last.piece)) === 'again') { k = firstOf(last.piece); continue; }
      break;
    }
    const s = ck.list[k], clip = ck.narration[s.id];
    const before = ck.list[ck.i];
    if (before && before.piece !== s.piece && (await pieceDone(before.piece)) === 'again') { k = firstOf(before.piece); continue; }
    // The step's actions run first (its page is up when go() returns); its
    // line is spoken from then on, for the clip's length (review 1: the
    // screen lagged the narration).
    await ck.go(k);
    // A FAILED step's line is never played over whatever is left on screen:
    // the piece is retaken (or the run stops) right away.
    if (mode !== 'dry' && ((ck.failedSteps || {})[s.piece] || []).includes(s.id)) {
      while (ck.busy) await sleep(500);
      if ((await pieceDone(s.piece)) === 'again') { k = firstOf(s.piece); continue; }
    }
    // While the line plays, nothing but the stage may come forward.
    // hold: a line the owner says in his own words (no clip) is held this long.
    // The line started when the step's screen was up (ck.lineStarted), not
    // when go() returned (its picture for the log comes after): hold from there.
    if (storyboard) {
      // The hold point: the step's screen is up and its line would start now.
      while (ck.busy) await sleep(300);
      await sleep(700);
      const f = path.join(sbDir, `${String(shots.length + 1).padStart(2, '0')}-${s.id}.png`);
      await new Promise((r) => execFile('screencapture', ['-x', '-m', f], () => r()));
      shots.push({ s, f, failed: ((ck.failedSteps || {})[s.piece] || []).includes(s.id) });
      log(`storyboard: [${s.id}] shot ${path.basename(f)}`);
    }
    for (const end = storyboard ? 0 : (v2 && ck.lineStarted ? ck.lineStarted : Date.now()) + Math.max(clip ? clip.dur * 1000 : 2000, (s.hold || 0) * 1000) + (v2 ? 250 : 700); Date.now() < end;) { await ck.stageGuard(); await sleep(400); }
    while (ck.busy) await sleep(500);
    if (mode !== 'dry') {
      const end = Date.now() + (storyboard ? 5 : 90) * 60000;
      while ((ck.light.color === 'yellow' || ck.waitActive) && Date.now() < end) await sleep(2000);
      if (ck.light.color === 'yellow' || ck.waitActive) {
        // Never move on past a result that isn't there.
        progress(`BLOCKED | [${s.id}] still waiting after 90 minutes (${ck.light.text}); autopilot stopped`);
        log(`preview: STOPPED: [${s.id}] still waiting after 90 minutes`);
        await ck.close(); process.exit(2);
      }
    }
    k++;
  }
  if (storyboard) { await writeStoryboard(shots, sbDir); await ck.close(); process.exit(0); }
  await ck.finish();
  log('preview: finished');
  await ck.close();
  process.exit(0);
}

// The contact sheet: a PNG grid (4 across, each shot numbered by its step)
// and a Markdown table of step, line and screenshot.
async function writeStoryboard(shots, dir) {
  const md = [`# Storyboard: ${ck.pieces.find((p) => p.n === shots[0]?.s.piece)?.slug || storyboard} (${new Date().toISOString().replace(/\.\d+Z$/, 'Z')})`, '',
    'One screenshot per step, taken at its hold point (the moment its line starts). No recording, no narration audio.', '',
    `![grid](${path.basename(dir)}/grid.png)`, '', '| # | Step | Line | Screenshot |', '|---|---|---|---|',
    ...shots.map((x, i) => `| ${i + 1} | ${x.s.id}${x.failed ? ' **FAILED**' : ''} | ${x.s.say.join(' ').replace(/\|/g, '/')} | [${path.basename(x.f)}](${path.basename(dir)}/${path.basename(x.f)}) |`)].join('\n');
  const FF = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
  const cols = 4, rows = Math.ceil(shots.length / cols);
  if (shots.length) await new Promise((r) => execFile(FF, ['-v', 'error', '-y', '-pattern_type', 'glob', '-i', path.join(dir, '[0-9]*.png'), '-vf', `scale=640:-1,tile=${cols}x${rows}:padding=6:color=white`, '-frames:v', '1', path.join(dir, 'grid.png')], () => r()));
  fs.writeFileSync(`${dir}.md`, md + '\n');
  log(`storyboard: ${shots.length} shots, ${shots.filter((x) => x.failed).length} failed · ${dir}.md`);
}

const bye = async () => { log('cockpit: closing (saving any recording in progress)'); card?.stop(); speech.close(); await ck.close().catch(() => {}); curtainDown(); process.exit(0); };
process.on('SIGINT', bye); process.on('SIGTERM', bye);
// A stray rejection (e.g. a background tab that never showed up) is logged,
// never fatal: a crash would leave OBS recording and VS Code's bars hidden.
process.on('unhandledRejection', (e) => log(`cockpit: unhandled: ${e?.stack?.split('\n').slice(0, 2).join(' ') || e}`));
