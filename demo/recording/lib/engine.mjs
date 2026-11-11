// The cockpit engine: walks the steps (steps.mjs), performs each step's
// actions on NEXT, polls its WAIT, drives the recording, and keeps the state
// the teleprompter shows.
//
// Modes
//   live       everything for real. Approvals are ALWAYS typed by the
//              presenter; the cockpit only opens the approval issue.
//   dry        every action against the current state, but nothing that
//              changes anything (no typing into files, commits, pushes, PRs,
//              merges, workflow runs, sign-ins): it says what it WOULD do.
//              Waits are checked once and never block.
//   rehearse   piece 1 for real on a throwaway branch in a separate worktree:
//              commit, push, open the PR, wait for its plan, show it, then
//              close the PR without merging. Never approves, never merges.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile, execFileSync } from 'node:child_process';
import { steps as buildSteps, PIECES, stepsV2, PIECES_V2 } from '../steps.mjs';
import * as L from './live.mjs';
import { Browser, OVERLAY } from './browser.mjs';
import { Human } from './human.mjs';
import { VsCode } from './vscode.mjs';
import { Recorder } from './recorder.mjs';
import { prepareRehearsal, closeRehearsal } from './rehearsal.mjs';
import { winshot, windows } from './winshot.mjs';
import { Ring } from './ring.mjs';
import { snowUser, signInRecovery, PROVISIONED_USERS } from './snow.mjs';
import { labMain, previewReset, hireReset, v2Worktrees } from './teardown.mjs';
import { buildPreview } from './mix.mjs';
import { signinTool, assertNotOwner, PRESENTER, STAFF, SPLUNK, AVA, AWS_ADMIN } from './identities.mjs';
import { stage, clearCodeWindows, restoreFullScreen, codeWindowHere, clearNotifications, parkPointer, foreignOnScreen } from './stage.mjs';
import { curtainActive, curtainHide } from './curtain.mjs';
import { localUrl } from './localurl.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const HOME = os.homedir();
// Text that means the browser is signed in to a different organisation's Teams
// (set COCKPIT_OTHER_ORG to a regex source; by default nothing matches).
const OTHER_ORG = process.env.COCKPIT_OTHER_ORG ? new RegExp(process.env.COCKPIT_OTHER_ORG, 'i') : /(?!)/;
const DEMO = path.join(HOME, 'contoso-demo');
const GH = 'https://github.com/ChromeData/contoso-health-identity-lab';
const LIVE_WS = path.join(DEMO, 'contoso-demo.code-workspace');
// OrangeHRM: the owner's own sign-in in the recording browser (N02, N08).
export const OHRM_LOGIN = 'http://127.0.0.1:8585/web/index.php/auth/login';
const OHRM_PROBE = 'http://127.0.0.1:8585/web/index.php/pim/viewEmployeeList';
// The v24 presenter map (copy of the published artifact), in video mode.
// Served at http://localhost:<port>/map/v24 when the cockpit's server runs
// (Browser.MAP_URL): the address bar shows no /Users/... path on camera.
const mapV24 = () => Browser.MAP_URL ? `${Browser.MAP_URL}/v24?video` : `file://${path.join(DEMO, 'cockpit', 'map', 'v24.html')}?video`;
// The local PAM harness the tour shows (a worktree of the lab, its stack on
// the Splunk Colima VM); override with COCKPIT_PAM_DIR.
const PAM_DIR = process.env.COCKPIT_PAM_DIR || path.join(DEMO, 'cockpit', '.pam-tour', 'lab', 'pam');
// Piece 11's extra stops (2026-11-06): the lab at origin/main (a detached
// worktree, read only) and the live read-only checks, in their own window of
// the "Contoso Demo" profile (tools/tour-extra-checks.sh writes tour/out).
const TOUR_LAB = process.env.COCKPIT_TOUR_LAB || path.join(DEMO, 'cockpit', '.tour-main');
const TOUR_WS = path.join(DEMO, 'cockpit', 'tour', 'contoso-demo-tour.code-workspace');
// Actions that change something. In a dry run they are described, not done.
const WRITE = new Set(['cloudsync.restart', 'pod', 'code.type', 'code.save', 'code.commit', 'code.push', 'gh.createPr', 'gh.merge', 'gh.closePr', 'gh.runWorkflow', 'tap.signin', 'staff.signin',
  'drill.ensure', 'preview.approve', 'preview.contain', 'preview.secondCheck', 'identity.signin', 'pim.deactivate', 'hr.hire', 'hr.leave']);
// Clicks and typing are writes inside a step marked write (e.g. PIM Activate).
const CLICKY = new Set(['web.click', 'web.type', 'private.click', 'private.type']);
// The only accounts the cockpit may issue a one-time pass for: demo people.
const TAP_USERS = { ava: 'adm-ava.lin@contosohealthlab.onmicrosoft.com', raj: 'adm-raj.patel@contosohealthlab.onmicrosoft.com' };
// Sam's start date = the recording day, the Mac's own local date (YYYY-MM-DD),
// computed when the cockpit starts: the birthright rules only match a hire
// date of today or earlier, so a fixed future date would give him no access.
const localDate = () => new Date().toLocaleDateString('en-CA');

export class Cockpit {
  // preview: true for --preview. With mode 'preview' everything runs for real
  // (on a copy of the blueprints) and the cockpit also does the presenter's
  // hand steps, labelled on screen; with mode 'dry' it is a dry run of that
  // same flow.
  constructor({ mode = 'dry', record = null, root, display = '', port, log, preview = false, resumeFrom = null, only = null, teardown = true, readyLabel = null, proof = false, tour = false, v2 = false, parts = null, includePending = false, outDir = null, rajTicket = null, mouse = 'human', watch = false }) {
    // --watch: a dry autopilot that records; its camera follows the
    // unattended rules (paused while nothing live is on screen, rolls only
    // when the stage window is in front).
    this.watch = watch;
    // mouse: 'human' (the real pointer, moved like a person), 'guide' (the
    // presenter clicks, the cockpit shows where) or 'dom' (the old drawn
    // pointer and Playwright clicks). lib/human.mjs; switchable live.
    this.mouseWanted = mouse;
    // --v2: the 18 parts of segments/V2-RUNNING-ORDER.md (steps.mjs stepsV2).
    // parts: the part numbers to run (--part 2,3); pending (PENDING BUILD)
    // parts and steps only with --include-pending (they stop on their TODO).
    this.v2 = v2; this.silent = process.argv.includes('--silent'); this.parts = parts; this.includePending = includePending; this.outDir = outDir; this.rajTicket = rajTicket;
    this.pieces = v2 ? PIECES_V2 : PIECES;
    this.readyLabel = readyLabel;
    // --proof: a rehearsal of piece 1's VS Code part only, recorded silently
    // into the preview's folder as 01-vscode-proof (no commit, push or PR).
    this.proof = proof;
    // --tour-extra: piece 11's extra stops only (VS Code, read only).
    this.tour = tour;
    this.resumeFrom = resumeFrom; this.only = only; this.teardownWanted = teardown; this.mixed = {};
    this.mode = mode; this.root = root; this.port = port; this.preview = preview || mode === 'preview';
    this.timeline = []; this.simStart = {};
    this.lines = []; this.listeners = new Set();
    this.log = (m) => { const line = `${new Date().toLocaleTimeString('en-GB')} ${m}`; this.lines.push(line); if (this.lines.length > 400) this.lines.shift(); (log || console.log)(line); this.emit(); };
    this.recordWanted = record ?? (mode === 'live' || mode === 'preview');
    this.display = display;
    this.i = -1; this.busy = false; this.light = { color: 'off', text: '' }; this.error = null;
    this.armed = null; this.pollId = 0; this.preflight = null; this.signins = null; this.done = false;
    this.dryReport = [];
    // Owner, 2026-11-10 #2 (dead time): the line starts with the step's first
    // on-screen action (the hand moves as he starts talking), the next step's
    // page is opened in a background tab while the current line is said, and
    // a live take also pauses OBS while a page really has to load.
    // COCKPIT_LINE_EARLY=0, COCKPIT_PREFETCH=0, COCKPIT_LIVE_CUTS=0 turn these off.
    this.lineEarly = process.env.COCKPIT_LINE_EARLY !== '0';
    this.prefetchOn = process.env.COCKPIT_PREFETCH !== '0';
    this.liveCuts = process.env.COCKPIT_LIVE_CUTS !== '0';
    // The presenter's pause (⌃⌥P on the presenter card, P on the teleprompter).
    this.held = false;
    // The presenter card's light: { color: green|amber|red, reason } (cue()).
    this.cueState = null;
  }
  // The camera is run by the cockpit (pauses, stage checks), not a presenter.
  get unattended() { return this.preview || this.proof || this.watch; }

  // ---- setup ------------------------------------------------------------------
  async init() {
    const c = this.c = { mode: this.mode, today: localDate(), hr: path.join(DEMO, 'hr'), tourLab: TOUR_LAB, tourOut: path.join(DEMO, 'cockpit', 'tour', 'out'), tourWs: TOUR_WS };
    if (this.v2) await this.initV2(c);
    else if (this.tour) {
      // Nothing to copy or branch: the stops only view files.
      Object.assign(c, { bp: TOUR_LAB, bpBranch: 'origin/main (read only)', wsFile: TOUR_WS });
    } else if (this.mode === 'rehearse') {
      const r = await prepareRehearsal({ root: this.root, liveFolder: path.join(DEMO, 'blueprints'), liveWs: LIVE_WS, log: this.log });
      Object.assign(c, { bp: r.dir, bpBranch: r.branch, bpBranchRe: '^rehearsal/cockpit-', wsFile: r.ws,
        prTitle: "REHEARSAL (closed, never merged): cloud engineers get AWS, nurses don't",
        prBody: 'Recording-cockpit rehearsal of piece 1. The cockpit closes this pull request without merging as soon as the plan is shown. Nothing is applied.\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)' });
    } else if (this.mode === 'preview' && this.resumeFrom) {
      // Carry on a preview that stopped: same copy, branch, PR and merge.
      const st = JSON.parse(fs.readFileSync(path.join(this.root, '.state', 'preview-last.json'), 'utf8'));
      const ws = fs.readdirSync(path.join(this.root, 'preview')).filter((f) => /^contoso-demo-preview-.*\.code-workspace$/.test(f)).sort().pop();
      // After the preview's reset the copy is gone: a later piece only views
      // files there, so the owner's own folder (read only) stands in.
      const copy = ws && fs.existsSync(st.previewDir);
      Object.assign(c, { bp: copy ? st.previewDir : path.join(DEMO, 'blueprints'), previewDir: copy ? st.previewDir : null, bpBranch: st.bpBranch, bpBranchRe: '^preview/cockpit-',
        wsFile: copy ? path.join(this.root, 'preview', ws) : LIVE_WS, pr: st.pr, mergeSha: st.mergeSha, prTitle: '', prBody: '' });
      this.log(`preview: resuming from piece ${this.resumeFrom} (PR #${st.pr?.number}, merge ${st.mergeSha?.slice(0, 7)})`);
    } else if (this.mode === 'preview') {
      // A copy of the blueprints (the owner's folder and its two uncommitted
      // files stay untouched); the real HR folder, reset by the teardown.
      const r = await prepareRehearsal({ root: this.root, liveFolder: path.join(DEMO, 'blueprints'), liveWs: LIVE_WS, log: this.log, kind: 'preview', hrFolder: c.hr });
      Object.assign(c, { bp: r.dir, previewDir: r.dir, bpBranch: r.branch, bpBranchRe: '^preview/cockpit-', wsFile: r.ws,
        prTitle: "Cloud engineers get AWS, nurses don't",
        prBody: "Nurses had AWS access they never use. Cloud engineers run the hospital's patient portal in AWS, so AWS moves from \"Nurse - Clinical Apps\" to a new automatic package, \"IT - Cloud Engineering Apps\", given to every Cloud Engineer from HR's job title.\n\n_Recording preview: the cockpit reverts this afterwards through a reviewed revert pull request._" });
    } else {
      c.bp = path.join(DEMO, 'blueprints');
      c.bpBranch = (await L.sh('git', ['-C', c.bp, 'rev-parse', '--abbrev-ref', 'HEAD'])).trim();
      if (/^(main|master|HEAD)$/.test(c.bpBranch)) throw new Error(`the blueprints folder is on ${c.bpBranch}; the live change must be on its own branch`);
      c.bpBranchRe = `^${c.bpBranch.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`;
      c.wsFile = LIVE_WS;
      c.prTitle = "Cloud engineers get AWS, nurses don't";
      c.prBody = "Nurses had AWS access they never use. Cloud engineers run the hospital's patient portal in AWS, so AWS moves from \"Nurse - Clinical Apps\" to a new automatic package, \"IT - Cloud Engineering Apps\", given to every Cloud Engineer from HR's job title.";
    }
    this.code = new VsCode(c.wsFile, { log: this.log });
    const vp = screenFit();
    this.browser = new Browser({ profileDir: path.join(this.root, '.recording-profile'), width: vp.w, height: vp.h, shotsDir: path.join(this.root, 'shots'), log: this.log });
    // test-user-a's own window (My Apps, Teams): one context per Entra identity.
    this.staffBrowser = new Browser({ profileDir: path.join(this.root, '.staff-profile'), width: vp.w, height: vp.h, shotsDir: path.join(this.root, 'shots'), log: this.log });
    // adm-labops's window: the AWS admin view, through PIM-AWS-Lab-Admins
    // (LabAdministrator borrowed for two hours, ADR 0025).
    this.awsBrowser = new Browser({ profileDir: path.join(this.root, '.aws-profile'), width: vp.w, height: vp.h, shotsDir: path.join(this.root, 'shots'), log: this.log });
    // Rehearsal and dry-run takes go to recordings/practice/, never next to the real ones.
    this.human = await new Human({ log: this.log, mode: this.mouseWanted }).start();
    for (const b of [this.browser, this.staffBrowser, this.awsBrowser]) b.human = this.human;
    // OBS shows the system pointer, except with the old drawn one (--mouse dom),
    // so a take never has two pointers.
    this.rec = new Recorder({ cursor: this.human.mode !== 'dom', root: path.join(DEMO, 'recordings', ...(this.mode === 'live' ? [] : (this.preview || this.proof) ? ['preview'] : ['practice'])), dir: this.outDir, display: this.display, log: this.log, enabled: this.recordWanted, silent: this.preview || this.proof });
    await this.rec.init();
    this.list = this.buildList();
    if (this.resumeFrom) {
      // The earlier pieces' recordings and step times, kept.
      const tl = path.join(this.rec.dir, 'timeline.json');
      const redo = (n) => n >= this.resumeFrom && n <= (this.only || 99);
      if (fs.existsSync(tl)) this.timeline = JSON.parse(fs.readFileSync(tl, 'utf8')).steps.filter((t) => !redo(t.piece));
      for (const p of this.pieces.filter((x) => !redo(x.n))) {
        const f = path.join(this.rec.dir, `${String(p.n).padStart(2, '0')}-${p.slug}.mp4`);
        if (fs.existsSync(f)) { this.rec.files.push({ n: p.n, file: f.replace(/\.mp4$/, '.mkv'), mp4: f }); const nm = f.replace(/\.mp4$/, '.narrated.mp4'); if (fs.existsSync(nm)) this.mixed[p.n] = nm; }
      }
      this.log(`preview: kept ${this.rec.files.length} recorded pieces and ${this.timeline.length} step times`);
    }
    if (this.mode === 'dry' || (this.v2 && this.preview)) await this.dryStandIns().catch((e) => this.log(`stand-ins: ${e.message}`));
    // --v2 --preview: the hire is the preview's own test hire, never a stand-in.
    if (this.v2 && this.preview && c.sam && !c.sam.hire) delete c.sam;
    this.log(`cockpit ${this.mode}: ${this.list.length} steps, blueprints ${c.bp} (${c.bpBranch}), recorder ${this.rec.kind}`);
    return this;
  }

  // A dry run has no PR, apply run, HR run or Sam of its own: it borrows the
  // latest real ones (read-only) so every page and highlight still gets
  // exercised. The report says which stand-ins it used.
  async dryStandIns() {
    const c = this.c, used = [];
    const prs = await L.ghJson(['pr', 'list', '-R', L.REPO, '--state', 'all', '--limit', '8', '--json', 'number,url,headRefName,state']);
    for (const p of prs) { const r = await L.prChecks(p.number); if (r.plan) { c.pr = p; c.planUrl = r.planUrl; used.push(`PR #${p.number}`); break; } }
    const latest = async (wf) => (await L.runsFor(wf, { limit: 1 }))[0];
    const ap = await latest('terraform-apply.yml'); if (ap) { c.applyRun = { id: ap.databaseId, url: ap.url }; used.push('the latest apply run'); }
    const hr = await latest('hr-feed.yml'); if (hr) { c.hrRun = { id: hr.databaseId, url: hr.url }; used.push('the latest HR feed run'); }
    const ev = await latest('evidence-pack.yml'); if (ev) { c.evRun = { id: ev.databaseId, url: ev.url }; used.push('the latest evidence run'); }
    const iss = await L.ghJson(['issue', 'list', '-R', L.REPO, '--state', 'all', '--search', '"Approve: apply" in:title', '--limit', '1', '--json', 'number,url,state,title']);
    if (iss[0]) { c.issue = iss[0]; used.push(`approval issue #${iss[0].number}`); }
    const sam = this.v2 ? null : await L.samUser(this.c.hireId);
    if (sam) c.sam = { id: sam.id, upn: sam.userPrincipalName };
    else { const sofia = await L.samUser('100488'); if (sofia) { c.sam = { id: sofia.id, upn: sofia.userPrincipalName, standIn: sofia.displayName }; used.push(`${sofia.displayName} in place of Sam`); } }
    // The containment drill's latest card (read-only status), for the Teams step.
    try {
      const main = await labMain(this.root);
      const st = await L.sh(path.join(main, 'lab/scripts/demo/containment-drill.sh'), ['status'], { cwd: main, timeout: 300000 });
      const nums = [...st.matchAll(/^\s+\S+ (\d+) (?:Closed|New|Active)/gm)].map((m) => +m[1]);
      if (nums.length) { c.drill = { incident: Math.max(...nums), upn: 'itdr-drill (closed, stand-in)', standIn: true }; used.push(`drill card #${c.drill.incident}`); }
    } catch (e) { this.log(`dry run: drill stand-in: ${e.message.split('\n')[0]}`); }
    // v2: part one's stand-ins are the earlier real run of the SAME change
    // (the cloud-engineer PR the 2026-11-05 preview merged, its gate and its
    // apply), read only. Override with COCKPIT_STANDIN_PR.
    if (this.v2) {
      try {
        const n = +(process.env.COCKPIT_STANDIN_PR || 204);
        const v = await L.ghJson(['pr', 'view', String(n), '-R', L.REPO, '--json', 'number,url,headRefName,state,mergeCommit']);
        const r = await L.prChecks(n);
        c.pr = { number: v.number, url: v.url, headRefName: v.headRefName, state: v.state }; c.planUrl = r.planUrl;
        const sha = v.mergeCommit?.oid;
        if (sha) {
          const iss = await L.approvalIssue(sha); if (iss) c.issue = iss;
          const ap = (await L.runsFor('terraform-apply.yml', { sha, limit: 200 })).find((r) => r.conclusion === 'success'); if (ap) c.applyRun = { id: ap.databaseId, url: ap.url }; else used.push('(no apply run found for PR #' + n + ')');
        }
        used.push(`part one: PR #${n}${c.issue ? `, gate #${c.issue.number}` : ''}${c.applyRun ? ', its apply run' : ''}`);
      } catch (e) { this.log(`stand-ins: part one: ${e.message.split('\n')[0]}`); }
    }
    this.standIns = used;
    this.log(`dry run stand-ins (read-only): ${used.join(', ') || 'none'}`);
  }

  buildList() {
    if (this.v2) {
      const pend = new Set(this.pieces.filter((p) => p.status === 'pending').map((p) => p.n));
      // previewSay (v24, 2026-11-07): a preview that shows a stand-in (an
      // earlier real run) says what is on screen instead of the live line.
      return stepsV2(this.c).filter((x) => (!this.parts || this.parts.includes(x.piece)) && (this.includePending || (!pend.has(x.piece) && !x.pending)) && !(this.silent && x.silentSkip))
        .map((x) => (this.preview && x.previewSay ? { ...x, say: x.previewSay } : x));
    }
    const all = buildSteps(this.c);
    if (this.tour) return all.filter((x) => x.tour);
    if (this.mode !== 'rehearse') return all;
    const p1 = [];
    for (const s of all.filter((x) => x.piece === 1)) {
      if (s.rehearsal === 'close') {
        p1.push({ id: '1-close', piece: 1, write: true, say: ['Rehearsal ends here.', 'The pull request is closed without merging; nothing is applied.'], do: [{ do: 'gh.closePr' }, { do: 'web.open', url: (x) => x.pr.url }] });
        break;
      }
      p1.push(s);
    }
    return p1;
  }


  // ---- v2 (2026-11-07) --------------------------------------------------------
  // The v2 parts work on the owner's own folders, read only, plus read-only
  // checkouts of the open PRs their screens come from (cockpit/.v2/*). A
  // --preview makes no lab change but the HR test hire (removed afterwards).
  async initV2(c) {
    c.bp = path.join(DEMO, 'blueprints');
    c.bpBranch = (await L.sh('git', ['-C', c.bp, 'rev-parse', '--abbrev-ref', 'HEAD'])).trim();
    c.bpBranchRe = `^${c.bpBranch.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`;
    c.wsFile = LIVE_WS;
    c.prTitle = "Cloud engineers get AWS, nurses don't";
    c.prBody = "Nurses had AWS access they never use. Cloud engineers run the hospital's patient portal in AWS, so AWS moves from \"Nurse - Clinical Apps\" to a new automatic package, \"IT - Cloud Engineering Apps\", given to every Cloud Engineer from HR's job title.";
    if (this.mode === 'live' && /^(main|master|HEAD)$/.test(c.bpBranch)) throw new Error(`the blueprints folder is on ${c.bpBranch}; the live change must be on its own branch`);
    // Who is hired in N02 and leaves in N08. The preview's test hire is a
    // nurse (the nurse package exists today; the cloud engineering package
    // only after N01's change is applied), named so nobody takes it for staff.
    // 2026-11-07 (OrangeHRM): previews hire Sam Rivera himself in OrangeHRM
    // (400104), so the screens show Sam; COCKPIT_TEST_FIRST/LAST name a test
    // nurse instead. The reset is readiness/hr-flow.md's (purge, free-id,
    // reset-demo-hire.sh, ServiceNow).
    c.hire = this.preview && process.env.COCKPIT_TEST_FIRST
      ? { first: process.env.COCKPIT_TEST_FIRST, last: process.env.COCKPIT_TEST_LAST || 'Preview', dept: 'Nursing', job: 'Registered Nurse', pkg: 'Nurse - Clinical Apps' }
      : { first: 'Sam', last: 'Rivera', dept: 'Information Technology', job: 'Cloud Engineer', pkg: 'IT - Cloud Engineering Apps' };
    c.hire.name = `${c.hire.first} ${c.hire.last}`;
    const st = path.join(this.root, '.state', 'v2-hire.json');
    if (fs.existsSync(st)) { const h = JSON.parse(fs.readFileSync(st, 'utf8')); if (h.name === c.hire.name && !!h.preview === !!this.preview) { c.hireId = h.hireId; this.log(`v2: ${h.name} is hired from an earlier run (employee number ${h.hireId})`); } }
    c.rajTicket = this.rajTicket || null;
    c.v2 = await v2Worktrees(this.root, this.log);
  }

  // The HR form: started from the read-only checkout of PR #224 (or
  // COCKPIT_HR_FORM_DIR, e.g. a checkout whose rules list Cloud Engineer)
  // when nothing answers on 127.0.0.1:8484. It uses gh's own sign-in.
  async hrFormUp() {
    const up = async () => { try { const r = await fetch('http://127.0.0.1:8484/api/workers', { signal: AbortSignal.timeout(4000) }); return r.ok; } catch { return false; } };
    if (await up()) return;
    const dir = process.env.COCKPIT_HR_FORM_DIR || this.c.v2.hr;
    const server = path.join(dir, 'lab', 'hr-app', 'server.mjs');
    if (!fs.existsSync(server)) throw new Error(`the HR form is not there: ${server}`);
    const { spawn } = await import('node:child_process');
    const out = fs.openSync(path.join(this.root, '.state', 'hr-form.log'), 'a');
    this.hrForm = spawn(process.execPath, [server], { cwd: dir, stdio: ['ignore', out, out], detached: false });
    for (let k = 0; k < 30 && !(await up()); k++) await sleep(1000);
    if (!(await up())) throw new Error('the HR form did not start (see .state/hr-form.log)');
    this.log(`HR form started from ${dir} (pid ${this.hrForm.pid})`);
  }

  // Before a hire: never a second one, never over a leftover account.
  async hrSafeToHire() {
    const c = this.c, h = c.hire;
    if (this.preview && !/^Test /.test(h.name)) throw new Error(`a preview hires only a test worker, not ${h.name}`);
    if (c.hireId) throw new Error(`${h.name} is already hired in this run (${c.hireId}): reset first`);
    const upn = `${h.first}.${h.last}@contosohealthlab.com`.toLowerCase();
    const r = await L.graph(`users?$filter=userPrincipalName eq '${encodeURIComponent(upn)}'&$select=id`);
    if (r.value.length) throw new Error(`${upn} is already in Entra: remove the leftover first`);
  }

  // The hr-feed commit the form just wrote (its message names the worker).
  async hrCommitFor(re, since) {
    for (let k = 0; k < 15; k++) {
      const list = await L.api(`repos/${L.REPO}/commits?sha=hr-feed&per_page=10`);
      const hit = list.find((x) => re.test(x.commit.message) && Date.parse(x.commit.committer.date) >= since - 120000);
      if (hit) return hit.sha;
      await sleep(2000);
    }
    throw new Error(`no hr-feed commit matching ${re} after the save`);
  }

  // --v2 --preview, at the end: the test hire removed the way
  // readiness/hr-flow.md says (E123), every place read back; the HR form
  // stopped; DC01 put back to deallocated if this run started it.
  async v2Teardown(dry) {
    const c = this.c, out = [];
    const st = path.join(this.root, '.state', 'v2-hire.json');
    if (c.hireId && this.teardownWanted) {
      const upn = `${c.hire.first}.${c.hire.last}@contosohealthlab.com`.toLowerCase();
      out.push(...await hireReset({ root: this.root, id: c.hireId, upn, name: c.hire.name, dry, log: this.log }));
      if (out.every((x) => x.ok) && !dry) fs.rmSync(st, { force: true });
    } else if (c.hireId) out.push({ name: `test hire ${c.hire.name} (${c.hireId}) kept for the next part (--no-teardown)`, ok: true, note: 'remove it with --v2 --preview-reset' });
    if (this.hrForm) { this.hrForm.kill(); out.push({ name: 'stop the HR form', ok: true, note: `pid ${this.hrForm.pid}` }); this.hrForm = null; }
    if (this.startedDc01 && !dry && this.teardownWanted) {
      try { await L.sh(path.join(L.LAB, 'lab/scripts/operator/op'), ['az', 'vm', 'deallocate', '-g', 'rg-identity-lab', '-n', 'vm-dc01', '--no-wait'], { cwd: L.LAB, timeout: 300000 }); out.push({ name: 'DC01 back to deallocated (this run started it)', ok: true, note: 'deallocate sent' }); }
      catch (e) { out.push({ name: 'DC01 back to deallocated (this run started it)', ok: false, note: e.message.split('\n')[0] }); }
    }
    return out;
  }

  // DC01 runs the provisioning agent the hire needs. A preview with HR parts
  // starts it if it is off, and deallocates it again at the end.
  async dc01ForHire() {
    const op = path.join(L.LAB, 'lab/scripts/operator/op');
    const power = async () => (await L.sh(op, ['az', 'vm', 'get-instance-view', '-g', 'rg-identity-lab', '-n', 'vm-dc01', '--query', "instanceView.statuses[?starts_with(code,'PowerState/')].displayStatus | [0]", '-o', 'tsv'], { cwd: L.LAB, timeout: 180000 })).trim();
    const p = await power();
    if (this.mode === 'dry') return `DC01 is '${p}' (a real preview starts it)`;
    if (p !== 'VM running') { this.startedDc01 = true; this.log(`v2: DC01 is '${p}': the lab preflight starts it for the test hire (deallocated again at the end)`); }
    // The lab's own preflight (fix mode): starts DC01, waits for the
    // provisioning agent, clears Cloud Sync's pause from DC01 being off.
    const main = await labMain(this.root);
    const out = await new Promise((res) => execFile(path.join(main, 'lab/scripts/demo/preflight.sh'), [], { cwd: main, timeout: 1500000, maxBuffer: 8 << 20 }, (e, so, se) => res(`${so}${se}`)));
    const plain = out.replace(/\x1b\[[0-9;]*m/g, '');
    for (const l of plain.split('\n').filter((x) => /DC01|agent|Cloud Sync|HR front door/.test(x))) this.log(`v2 preflight: ${l.trim()}`);
    if (!/Sync agent on DC01 is connected/.test(plain)) throw new Error('the provisioning agent on DC01 is not connected yet');
    if (!/Cloud Sync \(Active Directory → Entra\) is running/.test(plain)) throw new Error('Cloud Sync is not running');
    return `DC01 running, agent connected, Cloud Sync running${this.startedDc01 ? ' (DC01 started by this run)' : ''}`;
  }


  // ---- state for the teleprompter --------------------------------------------
  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit() { if (this._t) return; this._t = setTimeout(() => { this._t = null; const s = this.state(); for (const fn of this.listeners) fn(s); }, 60); }
  state() {
    const s = this.list?.[this.i], n = this.list?.[this.i + 1];
    const piece = (p) => this.pieces.find((x) => x.n === p);
    return {
      mode: this.mode, i: this.i, total: this.list?.length || 0, busy: this.busy, done: this.done,
      step: s ? { id: s.id, piece: s.piece, pieceTitle: piece(s.piece).title, say: s.say, hand: s.hand || '', fallback: s.fallback || '', write: !!s.write, optional: !!s.optional } : null,
      next: n ? { piece: n.piece, pieceTitle: piece(n.piece).title, say: n.say[0], newPiece: !s || n.piece !== s.piece } : null,
      light: this.light, error: this.error, armed: this.armed?.what || null,
      held: this.held, heldAt: this.heldAt || 0, cue: this.cueState, takeT0: this.takeT0 || 0, lineStarted: this.lineStarted || 0,
      inPiece: s ? { k: this.list.filter((x, j) => x.piece === s.piece && j <= this.i).length, n: this.list.filter((x) => x.piece === s.piece).length } : null,
      mouse: this.human ? { mode: this.human.mode, want: this.human.want, real: this.human.ok } : null,
      rec: this.rec?.status(), preflight: this.preflight, signins: this.signins,
      stopwatch: this.c?.sw ? { t0: this.c.sw.t0, laps: this.c.sw.laps } : null,
      log: this.lines.slice(-60), dryReport: this.dryReport.slice(-80),
      pieces: this.pieces.map((p) => ({ n: p.n, title: p.title, status: p.status, first: this.list?.findIndex((x) => x.piece === p.n) ?? -1 })),
    };
  }
  setLight(color, text) { this.light = { color, text }; this.emit(); }
  // The presenter card's light and its 2-3 word reason.
  cue(color, reason) { if (this.cueState?.color === color && this.cueState?.reason === reason) return; this.cueState = color ? { color, reason } : null; this.emit(); }

  // ⌃⌥P: the presenter's pause. OBS pauses (if it is rolling), auto-advance
  // and the autopilot hold; again resumes.
  async togglePause() {
    this.held = !this.held;
    if (this.held) {
      this.heldAt = Date.now();
      if (this.rec?.piece && !this.rec.paused) { this.heldRec = true; await this.rec.pause().catch(() => {}); }
      this.log('PAUSED by the presenter (press pause again to go on)');
    } else {
      if (this.takeT0 && this.heldAt) this.takeT0 += Date.now() - this.heldAt;
      this.heldAt = 0;
      if (this.heldRec) { this.heldRec = false; if (this.unattended) await this.safeResume(); else await this.rec.resume().catch(() => {}); }
      this.log('going on');
    }
    this.emit();
  }

  // ---- the next step's page, opened while this line is said ----------------
  // Each web.open (and gh.openJob) of step k: its page in a background tab of
  // its window, so the step itself is a tab click, not a load on camera.
  async prefetchStep(k, { reload = false } = {}) {
    if (!this.prefetchOn || !this.human?.real) return;
    const s = this.list?.[k]; if (!s) return;
    const standIn = this.preview && (s.cloud || (this.v2 && s.previewStandIn));
    const acts = standIn ? (s.standIn || []) : s.do || [];
    for (const a of acts) {
      try {
        let url = null, B = a.ctx === 'aws' ? this.awsBrowser : (a.ctx === 'staff') ? this.staffBrowser : this.browser;
        if (a.do === 'web.open') url = this.val(a.url);
        else if (a.do === 'gh.openJob') url = await this.jobUrl(a);
        else continue;
        if (!url || !B?.up || !/^https:/.test(url)) continue;
        await B.prefetch(url, { reload });
      } catch (e) { if (!/earlier live step/.test(e.message)) this.log(`prefetch [${s.id}]: ${e.message.split('\n')[0]}`); }
    }
  }
  async jobUrl(a) {
    const key = `${a.workflow}|${a.job}`;
    if ((this.jobUrls ||= {})[key]) return this.jobUrls[key];
    const runs = await L.runsFor(a.workflow, { branch: 'main', limit: 20 });
    const run = runs.find((r) => r.status === 'completed' && r.conclusion === 'success' && r.event === 'push') || runs.find((r) => r.status === 'completed');
    if (!run) throw new Error(`no finished ${a.workflow} run on main`);
    const jobs = await L.api(`repos/${L.REPO}/actions/runs/${run.databaseId}/jobs?per_page=100`);
    const j = (jobs.jobs || []).find((x) => new RegExp(a.job, 'i').test(x.name));
    if (!j) throw new Error(`no job like "${a.job}" in ${a.workflow} run ${run.databaseId}`);
    return (this.jobUrls[key] = j.html_url);
  }

  // The line's clock, for actions that follow his words. Live: the speech
  // tracker (first words, each point said). Unattended: the narration clip
  // (each point's share of the clip, from when the line started).
  async gate(kind, k = 0, s = this.list[this.i]) {
    const clip = this.narration?.[s?.id];
    if (this.unattended && clip?.dur && this.lineStarted) {
      if (kind === 'start') return;
      const pts = (s.say || []).join(' ').split(/(?<=[.!?])\s+/).filter(Boolean);
      const tot = pts.reduce((n, x) => n + x.length, 0) || 1;
      const at = this.lineStarted + clip.dur * 1000 * pts.slice(0, Math.min(k, pts.length)).reduce((n, x) => n + x.length, 0) / tot;
      const wait = Math.min(6000, at - Date.now());
      if (wait > 0) await sleep(wait);
      return;
    }
    if (this.speechHook && !this.unattended) {
      if (kind === 'start') await this.speechHook.waitSpeaking(2500);
      else await this.speechHook.waitPoint(k - 1, 8000);
    }
  }

  // ---- navigation (one key) --------------------------------------------------
  // NEXT while a wait is still yellow (or a step is still running) needs a
  // second press within 6 s: the first only warns.
  confirm(what) {
    if (this.armed && this.armed.what === what && Date.now() - this.armed.at < 6000) { this.armed = null; return true; }
    this.armed = { what, at: Date.now() }; this.emit();
    setTimeout(() => { if (this.armed?.what === what) { this.armed = null; this.emit(); } }, 6000);
    return false;
  }

  async next() {
    if (this.busy) { this.log('busy: the current step is still running'); return; }
    if (this.light.color === 'yellow' && this.mode !== 'dry' && !this.confirm('next')) return;
    if (this.i + 1 >= this.list.length) { await this.finish(); return; }
    await this.go(this.i + 1);
  }

  async back() {
    if (this.busy || this.i <= 0) return;
    this.stopPoll();
    this.i -= 1; this.error = null;
    await this.run(this.list[this.i], { viewOnly: true });
  }

  async redo() {
    if (this.busy || this.i < 0) return;
    const s = this.list[this.i];
    if (s.write && this.mode !== 'dry' && !this.confirm('redo')) return;
    this.stopPoll();
    await this.run(s, {});
  }

  async jump(k) {   // the piece picker: go to a piece's first step (not run)
    if (this.busy || k < 0 || k >= this.list.length) return;
    this.stopPoll();
    if (this.rec.piece && this.rec.piece.n !== this.list[k].piece) await this.rec.endPiece();
    this.i = k - 1; this.error = null; this.done = false; this.setLight('off', `Ready: press NEXT to start piece ${this.list[k].piece}`);
  }

  async go(k) {
    this.stopPoll();
    const s = this.list[k], prev = this.list[this.i];
    if (!prev || prev.piece !== s.piece) {
      this.pendingStart = null;
      if (this.rec.piece) { const f = await this.rec.endPiece(); if (f && this.preview) await this.mixNow(prev.piece, f); }
      // Between pieces, off camera: the piece's clean-up (e.g. give Raj's
      // help-desk power back after piece 6).
      if (prev) for (const a of (this.pieces.find((p) => p.n === prev.piece)?.after || []).filter((x) => !(x.liveOnly && this.mode !== 'live'))) await this.act(a, prev).catch((e) => this.log(`after piece ${prev.piece}: ${a.do}: ${e.message.split('\n')[0]}`));
      // Preview 2 review, piece 8: Splunk's session had timed out (about an
      // hour) and its login page showed on camera. Before every piece, camera
      // off, each site the piece uses is checked and signed in again.
      await this.freshSessions(s.piece).catch((e) => this.log(`sessions: ${e.message}`));
      // Preview 2 review, piece 4: another VS Code window (the lead's) showed
      // while a step had nothing on screen. Before every piece, every VS Code
      // window but the demo one is minimized again.
      await this.clearOthers();
      // Leftover about:blank tabs closed (their hover card hung over N11).
      for (const W of [this.browser, this.staffBrowser, this.awsBrowser]) if (W?.up) await W.closeBlankTabs().catch(() => {});
      // The proof clip never overwrites the piece's real take (startPiece
      // replaces files of the same name): its own file name.
      const P = this.pieces.find((p) => p.n === s.piece);
      const PP = this.pieceSlug ? { ...P, slug: this.pieceSlug } : this.proof ? { ...P, slug: 'vscode-proof-silent' } : P;
      // Preview 2 review: every piece's first frames showed the previous page
      // (OBS records a moment before a pause lands). Unattended, the piece's
      // recording starts only when its first page is up and on stage
      // (safeResume starts it); live, it starts here as before.
      if (this.unattended) { this.pendingStart = PP; this.log(`recording: piece ${P.n} starts when its first page is up`); }
      else await this.rec.startPiece(PP).catch((e) => this.log(`recording: could not start (${e.message})`));
    }
    if (!prev || prev.piece !== s.piece) this.takeT0 = Date.now();
    this.i = k; this.error = null; this.done = false;
    // Where this step starts in its piece's recording (seconds, waits left
    // out): the preview puts the step's narration clip here.
    if (!prev || prev.piece !== s.piece) this.simStart[s.piece] = Date.now();
    await this.run(s, {});
  }

  async finish() {
    this.stopPoll();
    if (this.rec.piece) { const n = this.rec.piece.n; const f = await this.rec.endPiece(); if (f && this.preview) await this.mixNow(n, f); }
    this.done = true; this.setLight('green', this.mode === 'dry' ? 'Dry run finished: see the report' : 'All done');
    if (this.mode === 'dry') this.writeDryReport();
    if (this.mode === 'live' && this.giveBacks?.length) for (const g of await this.giveBackAll()) this.log(`${g.ok ? 'OK' : 'NOT DONE'} ${g.name}: ${g.note}`);
    if (this.preview) await this.previewFinish().catch((e) => this.log(`preview: post step failed: ${e.stack || e.message}`));
  }

  async giveBackAll() {
    const out = [];
    for (const g of this.giveBacks || []) {
      try {
        const T = await signinTool(this.root);
        const r = await T.signIn(g.id, T.PIM_URL, { headless: true });
        const page = r.page;
        const inFrames = async (fn) => { for (const f of page.frames()) { const x = await fn(f).catch(() => null); if (x) return x; } return null; };
        for (let i = 0; i < 20; i++) { await sleep(2000); const t = await inFrames(async (f) => { const l = f.getByRole('tab', { name: /Active assignments/i }).first(); return (await l.isVisible()) ? l : null; }); if (t) { await t.click(); break; } }
        await sleep(5000);
        const row = await inFrames(async (f) => { const l = f.getByRole('row').filter({ hasText: g.group }).first(); return (await l.isVisible()) ? l : null; });
        if (row) {
          await row.getByRole('button', { name: /Deactivate/ }).first().or(row.getByText('Deactivate', { exact: true }).first()).click(); await sleep(3000);
          const ok = await inFrames(async (f) => { const b = f.getByRole('button', { name: /^Deactivate$/ }).last(); return (await b.isVisible()) ? b : null; });
          if (ok) await ok.click();
        }
        await r.close();
        const u = await L.userByUpn(g.upn);
        let off = false;
        for (let k = 0; k < 24 && !off; k++) { off = !(await L.isGroupMember(g.group, u.id)); if (!off) await sleep(5000); }
        out.push({ name: `give ${g.group} back (${g.id})`, ok: off, note: off ? 'deactivated' : 'still active: it ends by itself' });
      } catch (e) { out.push({ name: `give ${g.group} back (${g.id})`, ok: false, note: e.message.split('\n')[0] }); }
    }
    this.giveBacks = [];
    return out;
  }

  // --preview: narrate a piece the moment its recording is saved, so the end
  // is only a join.
  async mixNow(n, file) {
    if (this.mode === 'dry') return;
    try {
      const { mixPiece } = await import('./mix.mjs');
      const clips = this.timeline.filter((t) => t.piece === n && this.narration?.[t.id]).map((t) => ({ file: this.narration[t.id].file, at: t.at }));
      const out = file.replace(/\.(mp4|mkv|mov)$/i, '.narrated.mp4');
      const r = await mixPiece(file.replace(/\.(mkv|mov)$/i, '.mp4'), clips, out);
      this.mixed[n] = out;
      fs.writeFileSync(path.join(this.rec.dir, 'timeline.json'), JSON.stringify({ at: new Date().toISOString(), mode: this.mode, recorder: this.rec.kind, steps: this.timeline }, null, 1));
      this.log(`preview: piece ${n} narrated (${r.clips} clips, ${r.len.toFixed(1)} s): ${out}`);
      // The lead reviews each piece while the next one records.
      fs.appendFileSync(path.join(DEMO, 'readiness', 'progress.log'), `${new Date().toISOString().replace(/\.\d+Z$/, 'Z')} | cockpit | piece ${n} recorded | ${out} | ${Math.floor(r.len / 60)} min ${Math.round(r.len % 60)} s\n`);
    } catch (e) { this.log(`preview: mixing piece ${n} failed: ${e.message}`); }
  }

  // --preview, after the last step: narration mixed in at each step's start
  // (recorded time), one file per piece + preview-full.mp4, then the
  // teardown that puts the lab back. A dry run mixes onto a plain test
  // picture as long as each piece took, to prove the timing and the mix.
  async previewFinish() {
    const dry = this.mode === 'dry';
    const dir = dry ? path.join(DEMO, 'recordings', 'preview', `${localDate()}-dry`) : this.rec.dir;
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'timeline.json'), JSON.stringify({ at: new Date().toISOString(), mode: this.mode, recorder: this.rec.kind, steps: this.timeline }, null, 1));
    let pieces = this.rec.files.map((f) => ({ n: f.n, video: f.mp4 || f.file }));
    if (!pieces.length && dry) pieces = await this.testCardPieces(dir);
    if (pieces.length) {
      // Pieces not narrated yet (e.g. kept from before a resume) are mixed now.
      for (const p of pieces) if (!this.mixed[p.n] && !dry) await this.mixNow(p.n, p.video);
      const { concat } = await import('./mix.mjs');
      const ready = pieces.map((p) => this.mixed[p.n]).filter(Boolean);
      const out = !dry && ready.length === pieces.length
        ? { full: await concat(ready.sort(), path.join(dir, 'preview-full.mp4')) }
        : await buildPreview({ pieces, timeline: this.timeline, narration: this.narration || {}, dir, log: this.log });
      // The owner wants it the moment it exists: say so BEFORE the reset.
      const want = this.v2 ? new Set(this.list.map((x) => x.piece)).size : this.pieces.length;
      if (!dry && pieces.length === want) {
        const { duration } = await import('./mix.mjs');
        const len = await duration(out.full).catch(() => 0);
        fs.appendFileSync(path.join(DEMO, 'readiness', 'progress.log'), `${new Date().toISOString().replace(/\.\d+Z$/, 'Z')} | cockpit | ${this.readyLabel || 'PREVIEW READY'} | ${out.full} | ${Math.floor(len / 60)} min ${Math.round(len % 60)} s\n`);
      } else if (!dry) this.log(`preview: ${pieces.length} of ${want} pieces so far (no READY line yet)`);
    }
    if (!this.teardownWanted && !this.v2) {
      if (!dry) { const main = await labMain(this.root); const out = await L.sh(path.join(main, 'lab/scripts/demo/containment-drill.sh'), ['disarm'], { cwd: main, timeout: 1200000 }).catch((e) => e.message); this.log(`retake: drill disarmed: ${String(out).trim().split('\n').slice(-1)[0]}`); }
      this.setLight('green', `Retake done: ${path.join(dir, 'preview-full.mp4')}`);
      return;
    }
    if (this.v2) {
      // v2 previews change nothing in the lab but the test hire: no revert
      // PR, no drill. The test hire is removed the way readiness/hr-flow.md says.
      this.setLight('blue', 'Preview recorded: removing the test hire');
      this.teardown = await this.v2Teardown(dry);
      fs.writeFileSync(path.join(dir, 'teardown.json'), JSON.stringify(this.teardown, null, 1));
      const bad = this.teardown.filter((x) => !x.ok);
      this.setLight(bad.length ? 'red' : 'green', bad.length ? `Teardown needs a hand: ${bad.map((x) => x.name).join(', ')}` : `Preview done: ${path.join(dir, 'preview-full.mp4')}`);
      return;
    }
    this.setLight('blue', 'Preview recorded: putting the lab back (revert PR, Sam, drill)');
    this.teardown = await previewReset({ root: this.root, c: this.c, dry, log: this.log, snowContext: this.browser?.up ? this.browser.ctx : null });
    if (!dry) this.teardown.push(...await this.giveBackAll());
    if (!dry && this.awsAdminActive) {
      try { this.teardown.push({ name: 'give LabAdministrator back (PIM-AWS-Lab-Admins)', ok: true, note: await this.awsAdminDeactivate() }); }
      catch (e) { this.teardown.push({ name: 'give LabAdministrator back (PIM-AWS-Lab-Admins)', ok: false, note: e.message }); }
    }
    fs.writeFileSync(path.join(dir, 'teardown.json'), JSON.stringify(this.teardown, null, 1));
    const bad = this.teardown.filter((x) => !x.ok);
    this.setLight(bad.length ? 'red' : 'green', bad.length ? `Teardown needs a hand: ${bad.map((x) => x.name).join(', ')}` : `Preview done: ${path.join(dir, 'preview-full.mp4')}`);
  }

  async testCardPieces(dir) {
    const { execFile: ef } = await import('node:child_process');
    const FF = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
    const out = [];
    const ids = [...new Set(this.timeline.map((t) => t.piece))];
    for (const n of ids) {
      const steps = this.timeline.filter((t) => t.piece === n);
      const last = steps[steps.length - 1];
      const len = Math.max(3, last.at + ((this.narration || {})[last.id]?.dur || 3) + 1);
      const p = this.pieces.find((x) => x.n === n);
      const f = path.join(dir, `${String(n).padStart(2, '0')}-${p.slug}.mp4`);
      await new Promise((res, rej) => ef(FF, ['-v', 'error', '-y', '-f', 'lavfi', '-i', `testsrc2=size=1280x720:rate=30`, '-t', len.toFixed(2), '-c:v', 'libx264', '-preset', 'veryfast', '-pix_fmt', 'yuv420p', f], (e) => (e ? rej(e) : res())));
      out.push({ n, video: f });
    }
    return out;
  }

  // What `node cockpit.mjs --preview-reset` needs if the preview stopped
  // half-way: the PR, the merge commit, the copy's branch and folder.
  savePreviewState() {
    const c = this.c;
    fs.writeFileSync(path.join(this.root, '.state', 'preview-last.json'), JSON.stringify({ at: new Date().toISOString(), pr: c.pr, mergeSha: c.mergeSha || null, bpBranch: c.bpBranch, previewDir: c.previewDir, hr: c.hr }, null, 1), { mode: 0o600 });
  }

  // --preview refuses to start until these are all true.
  async previewPreconditions() {
    const sig = await this.checkSignins();
    const need = this.v2 ? this.v2Needs() : ['GitHub', 'Entra', 'Azure portal', 'Defender', 'AWS console', 'Teams', 'ServiceNow', 'Splunk', 'My Apps'];
    const missing = sig.sites.filter((x) => need.includes(x.name) && !x.ok).map((x) => `${x.name}: ${x.note}`);
    if (this.rec.kind !== 'obs' || !this.rec.captureOk) missing.push(`OBS: ${this.rec.note}`);
    if (!(await codeWindowHere(this.code.title))) missing.push(`VS Code: the window ${this.code.title} is not on the recording screen`);
    if (this.v2 && this.list.some((x) => this.pieces.find((p) => p.n === x.piece)?.hr)) {
      try { this.log(`v2: ${await this.dc01ForHire()}`); } catch (e) { missing.push(`DC01 (the HR provisioning agent): ${e.message.split('\n')[0]}`); }
    }
    return missing;
  }
  // The sign-ins a v2 run needs, from the parts it runs.
  v2Needs() {
    const ps = new Set(this.list.map((x) => x.piece)), need = new Set(['GitHub']);
    const by = { entra: ['Entra', 'Azure portal'], snow: ['ServiceNow'], staff: ['My Apps'], teams: ['Teams'], splunk: ['Splunk'] };
    for (const p of this.pieces.filter((x) => ps.has(x.n))) for (const u of p.sessions || []) for (const n of by[u] || []) need.add(n);
    if (ps.has(6)) need.add('Defender');
    return [...need];
  }
  // The sign-ins the steps themselves need, read from the addresses they open
  // and the site actions they run (2026-11-11 clips: N11 opens Entra pages but
  // lists no sessions, and showed "You don't have access"). Names as in
  // autoSignIn, plus 'OrangeHRM' (the owner's own sign-in, never the cockpit's).
  siteNeeds(steps = this.list) {
    const need = new Set();
    const byHost = [[/^(entra\.microsoft\.com|portal\.azure\.com)$/, 'Entra'], [/^portal\.azure\.com$/, 'Azure portal'], [/^security\.microsoft\.com$/, 'Defender'],
      [/\.service-now\.com$/, 'ServiceNow'], [/^(127\.0\.0\.1|localhost):8000$/, 'Splunk'], [/^(127\.0\.0\.1|localhost):8585$/, 'OrangeHRM'],
      [/^myapps\.microsoft\.com$/, 'My Apps'], [/^teams\.microsoft\.com$/, 'Teams'], [/^github\.com$/, 'GitHub']];
    for (const s of steps) {
      const standIn = this.preview && (s.cloud || (this.v2 && s.previewStandIn));
      const acts = standIn ? (s.standIn || []) : [...(s.do || []), ...(this.preview ? s.preview || [] : [])];
      for (const a of acts) {
        if (a.do === 'snow.adminList') need.add('ServiceNow');
        if (/^teams\./.test(a.do)) need.add('Teams');
        if (['sam.servicenow', 'staff.signin'].includes(a.do) || a.ctx === 'staff') need.add('My Apps');
        if (a.do === 'gh.openJob' || a.do === 'gh.planComment') need.add('GitHub');
        if (a.do !== 'web.open' && a.do !== 'web.video') continue;
        let u = null; try { u = this.val(a.url); } catch { continue; }
        let host = ''; try { host = new URL(u).host; } catch { continue; }
        for (const [re, n] of byHost) if (re.test(host)) need.add(n);
      }
    }
    return need;
  }
  // --watch / clips: every sign-in the selected parts need (their sessions and
  // their own addresses). Entra and the Azure portal share adm-presenter.
  watchNeeds() {
    const need = new Set([...(this.v2 ? this.v2Needs() : []), ...this.siteNeeds()]);
    if (need.has('Entra') || need.has('Azure portal')) { need.add('Entra'); need.add('Azure portal'); }
    return need;
  }
  // OrangeHRM (N02, N08) is the owner's own sign-in: the cockpit only checks
  // that the recording browser has a session (an off-camera tab), never signs in.
  async orangeHrmSession() {
    await this.browser.launch();
    const pg = await this.browser.ctx.newPage();
    try {
      try { await pg.goto(OHRM_PROBE, { waitUntil: 'domcontentloaded', timeout: 30000 }); }
      catch (e) { return { ok: false, note: `OrangeHRM does not answer at http://127.0.0.1:8585 (${e.message.split('\n')[0]}): start it first` }; }
      for (let k = 0; k < 10 && !/\/auth\/login/.test(pg.url()) && !/\/pim\//.test(pg.url()); k++) await sleep(500);
      if (/\/auth\/login/.test(pg.url())) return { ok: false, note: `the recording browser has no OrangeHRM session: the owner must sign in once at ${OHRM_LOGIN} in the recording browser (node cockpit.mjs --ohrm-login opens it there)` };
      return { ok: true, note: 'signed in (recording browser)' };
    } finally { await pg.close().catch(() => {}); }
  }

  // ---- one step ---------------------------------------------------------------
  async run(s, { viewOnly = false }) {
    this.busy = true; this.setLight('blue', 'Working…'); this.cue('amber', 'Setting up');
    this.log(`[${s.id}]${viewOnly ? ' (back)' : ''} ${s.say[0]}`);
    let failed = null, failedWrite = false;
    this.stageLost = false; this.notLoaded = false;
    // --preview: the presenter's hand steps are done by the cockpit, after
    // the step's own actions, labelled on screen.
    // --v2 --preview: a step that changes the lab is never done; its
    // stand-in (read-only, labelled PREVIEW on screen) runs instead.
    const standIn = this.preview && (s.cloud || (this.v2 && s.previewStandIn));
    if (standIn) this.log(`[${s.id}] PREVIEW: not done (it changes the lab): showing its stand-in`);
    const acts = standIn ? (s.standIn || [{ do: 'banner', text: `PREVIEW · not done: ${s.id} changes the lab` }]) : this.preview && s.preview && !viewOnly ? [...s.do, ...s.preview] : s.do;
    // Preview 2 review: no silent footage longer than ~10 s. Unattended
    // (--preview, or a proof clip), the camera stops rolling once a step's
    // actions (page loads, sign-ins) run past 6 s, and starts again only when
    // the page is up, right before the line.
    // Typing is what the viewer watches: never cut, and the 6 s count starts
    // again after it.
    const unattended = this.unattended;
    const TYPING = new Set(['code.type', 'code.commit', 'web.type', 'private.type', 'hr.fill']);
    let since = Date.now(), typing = false;
    const capTimer = unattended && !viewOnly ? setInterval(() => {
      // Once the line has started the viewer is listening: never cut it.
      if (this.navHuman || earlyAt != null) since = Date.now();
      else if (!typing && Date.now() - since > 6000 && this.rec.piece && !this.rec.paused) this.rec.pause().catch(() => {});
    }, 1000) : null;
    // Preview 2 review (pieces 7, 8): prep showed on camera (a GitHub page, a
    // session check, a stale Defender page while the next one loaded).
    // Unattended, the camera is off while a page loads or a window changes,
    // and rolls again for what the viewer should see: clicks, highlights,
    // typing, a diff.
    // A card is local and draws at once: the camera keeps rolling over it
    // (preview 2026-11-07: pausing for it left ~3 s of silence per card).
    const NAV = new Set(['card.aws', 'code.stop', 'code.check', 'hr.open', 'gh.openJob', 'gh.planComment', 'web.open', 'private.open', 'activate', 'find', 'require', 'teams.guard', 'drill.ensure', 'identity.signin', 'code.open', 'code.closeAll', 'pim.showActive', 'signin.openTap', 'web.waitFor', 'web.find', 'pam.vault', 'pam.guac', 'okta.signin']);
    const VISUAL = new Set(['map.focus', 'web.video', 'web.show', 'web.click', 'web.highlight', 'private.click', 'private.highlight', 'code.highlight', 'preview.contain', 'hr.fill', 'hr.hire', 'hr.leave', 'code.command', 'code.tree']);
    // Presentational actions that follow the line: the k-th of them in a step
    // waits for the k-th point (his words live, the clip's share unattended).
    const FOLLOW = new Set(['web.highlight', 'private.highlight', 'code.highlight']);
    let follows = 0;
    // An action the viewer sees at once (no load): the line can start with it.
    const quick = (a) => {
      const top = () => { try { return windows().find((w) => w.layer === 0 && w.w > 400 && w.h > 300) || {}; } catch { return {}; } };
      if (a.do === 'map.focus') return this.c.front === 'browser' && +top().pid === +this.browser.pid() && !!this.browser.page && !this.browser.page.isClosed() && this.browser.page.url().split('?')[0] === mapV24().split('?')[0];
      if (VISUAL.has(a.do) || TYPING.has(a.do)) return true;
      // Only when that window really is the one in front (code.open sets
      // c.front before the window is staged).
      if (['code.file', 'code.changes', 'code.diff', 'code.stop'].includes(a.do)) return this.c.front === 'code' && !!this.code?.ready && (top().title || '').endsWith(this.code.title);
      if (a.do === 'web.open' || a.do === 'gh.openJob') {
        if (a.ctx && a.ctx !== 'browser') return false;
        try { const u = a.do === 'web.open' ? this.val(a.url) : this.jobUrls?.[`${a.workflow}|${a.job}`]; const t = u && this.browser.tabFor(u); return !!t && this.c.front === 'browser' && +top().pid === +this.browser.pid(); } catch { return false; }
      }
      return a.do === 'card';
    };
    // A file or diff opening in VS Code: the camera rolls once it is open
    // (piece 7 began on an empty editor for a second).
    const VISUAL_AFTER = new Set(['code.diff', 'code.file', 'code.changes', 'code.stop', 'code.check']);
    // v2 previews (2026-11-07: 5-14 s of silence per portal step): clicks
    // that only get to the page run with the camera off; it rolls for the
    // highlight, and the line starts right after it. A hand step (typing on
    // the HR form) says its line WHILE it happens (lineWithAction).
    const navNow = (d) => NAV.has(d) || (this.v2 && /^(web\.click|web\.clickIf|private\.click)$/.test(d) && !s.showClicks);
    let earlyAt = null;
    for (const a of acts) {
      if (viewOnly && (WRITE.has(a.do) || (s.write && CLICKY.has(a.do)))) continue;
      // Live (2026-11-10 #2): OBS pauses while a page that is NOT already
      // loaded in a tab has to load, and rolls again for the visible action.
      if (!unattended && this.liveCuts && this.mode === 'live' && this.rec.piece && !viewOnly) {
        if (navNow(a.do) && !quick(a) && !this.rec.paused && earlyAt == null) { await this.rec.pause().catch(() => {}); this.liveCutOn = true; }
        else if (this.liveCutOn && (VISUAL.has(a.do) || quick(a))) { this.liveCutOn = false; await this.rec.resume().catch(() => {}); }
      }
      if (unattended && (this.rec.piece || this.pendingStart)) {
        if (navNow(a.do) && !quick(a) && earlyAt == null && this.rec.piece && !this.rec.paused) await this.rec.pause().catch(() => {});
        else if (VISUAL.has(a.do) && (this.rec.paused || this.pendingStart)) { since = Date.now(); await this.safeResume(); }
      }
      typing = TYPING.has(a.do);
      // A typing action right after a pause: the camera rolls again first.
      if (typing && unattended && (this.pendingStart || (this.rec.piece && this.rec.paused))) await this.safeResume();
      const early = (s.lineWithAction && (VISUAL.has(a.do) || typing)) || (this.v2 && this.lineEarly && !s.lineAfter && quick(a));
      if (early && earlyAt == null && !viewOnly && unattended && (this.pendingStart || (this.rec.piece && this.rec.paused))) { since = Date.now(); await this.safeResume(); }
      if (early && earlyAt == null && !viewOnly && (unattended ? (this.rec.piece && !this.rec.paused) : true)) {
        // A quick action right after a pause: the camera rolls first, then the line.
        earlyAt = (this.rec.piece ? await this.rec.position().catch(() => null) : null) ?? (Date.now() - (this.simStart[s.piece] || Date.now())) / 1000;
        this.lineStarted = Date.now(); this.cue('green', 'Talk'); this.emit();
        // The next step's page loads in the background while this line is said.
        if (!viewOnly) this.prefetchStep(this.i + 1, { reload: !!s.wait }).catch(() => {});
        if (!unattended) await this.gate('start', 0, s);
      } else if (earlyAt == null && NAV.has(a.do)) this.cue('amber', /^code\./.test(a.do) ? 'Opening VS Code' : 'Loading page');
      if (earlyAt != null && FOLLOW.has(a.do) && !viewOnly) { if (follows > 0) await this.gate('point', follows, s); follows++; }
      else if (earlyAt != null && a.atPoint != null && !viewOnly) await this.gate('point', a.atPoint, s);
      if (this.ringParked && !['map.focus', 'web.show', 'web.video'].includes(a.do)) { this.ringParked = false; this.startRing(); }
      try {
        await this.act(a, s);
        if (unattended && VISUAL_AFTER.has(a.do) && (this.pendingStart || (this.rec.piece && this.rec.paused))) { await sleep(250); since = Date.now(); await this.safeResume(); }
      }
      catch (e) {
        failed = e.message.split('\n')[0];
        failedWrite = WRITE.has(a.do);
        this.log(`[${s.id}] ${a.do} FAILED: ${failed}`);
        this.report(s, a, await this.classify(a, failed, s), failed);
        // Later actions depend on this one. A dry run goes on past a failed
        // highlight or click (to report them all), not past a page that didn't open.
        if (this.mode !== 'dry' || /^(web\.open|private\.open|find|code\.open)$/.test(a.do)) break;
      }
      finally { if (typing) since = Date.now(); typing = false; }
    }
    if (capTimer) clearInterval(capTimer);
    if (this.liveCutOn) { this.liveCutOn = false; await this.rec.resume().catch(() => {}); }
    // A failed step leaves the stage as it was: its cockpit window in front
    // (the recording browser if that window has gone), never whatever window
    // macOS brings forward next.
    if (failed && unattended && !viewOnly) {
      const app = this.c.front === 'private' && !this.browser.priv ? 'browser' : (this.c.front || 'browser');
      await this.front(app).catch((e) => this.log(`stage: after the failure: ${e.message}`));
    }
    // The window just put on stage needs a moment to paint (8-rule showed the
    // previous page in its first frames).
    if (unattended && !viewOnly && (this.pendingStart || (this.rec.piece && this.rec.paused))) { await sleep(350); await this.safeResume(); }
    if (unattended && this.stageLost && !failed) { failed = this.notLoaded ? 'the page in front never loaded (about:blank, empty or still loading): camera kept paused' : 'another window stayed in front of the stage: camera kept paused'; this.log(`[${s.id}] FAILED: ${failed}`); }
    this.stageLost = false; this.notLoaded = false;
    this.busy = false;
    // Review 1: the screen lagged the narration. A step's line starts only
    // now, when its actions are done and its page is up (highlights wait for
    // their element), so its recorded time is stamped here.
    if (!viewOnly) {
      const at = earlyAt ?? await this.rec.position().catch(() => null);
      this.timeline.push({ id: s.id, piece: s.piece, at: at ?? (Date.now() - (this.simStart[s.piece] || Date.now())) / 1000 });
      if (earlyAt == null) { this.lineStarted = Date.now(); this.prefetchStep(this.i + 1, { reload: !!s.wait }).catch(() => {}); }
    }
    if (failed) this.cue('red', 'Step failed'); else if (s.hand && this.mode !== 'preview') this.cue('red', 'Your hand'); else this.cue('green', 'Talk');
    if (failed) { this.error = `${failed}${s.fallback ? ` · ${s.fallback}` : ''}`; this.setLight('red', 'Step needs a hand: see below'); if (!viewOnly) ((this.failedSteps ||= {})[s.piece] ||= []).push(s.id); }
    // No point waiting on a result whose cause (commit, push, PR...) failed.
    // A dry run checks the wait once and waits for that answer before moving on.
    // --preview: a failed step doesn't wait on its result (nobody is there to fix it).
    if (s.wait && !standIn && !(s.wait.liveOnly && this.preview) && !viewOnly && !(failedWrite && this.mode !== 'dry') && !(failed && this.mode === 'preview')) { const w = this.startWait(s); if (this.mode === 'dry') await w; }
    else if (!failed) this.setLight('green', this.i + 1 < this.list.length ? 'Ready for the next step' : 'Last step');
    if (this.mode !== 'live') await this.shotStep(s, viewOnly ? 'back' : '');
    this.emit();
  }

  // Dry run and rehearsal: a picture of the window the step ended on.
  async shotStep(s, suffix = '') {
    const name = `${this.mode}-${s.id}${suffix ? '-' + suffix : ''}`;
    const file = path.join(this.root, 'shots', `${name}.png`);
    await sleep(600);
    if (this.c.front === 'code') winshot({ owner: /^Code$/, title: new RegExp(path.basename(this.c.wsFile, '.code-workspace')) }, file);
    else if (this.c.front === 'browser' && this.browser.up) { if (!winshot({ pid: this.browser.pid() }, file)) await this.browser.shot(name); }
  }

  // Why an action failed, for the dry-run report: the owner's one-time
  // sign-in, something only a live run creates (Sam, a PR, Sam's own
  // sign-in), or a real problem with the step.
  async classify(a, msg, s = {}) {
    if (/sign in once/.test(msg)) return 'SIGN-IN';
    if (this.mode === 'dry' && s.needs && !this.c[s.needs]) return 'NEEDS LIVE';
    if (/earlier live step|not ready:/.test(msg)) return 'NEEDS LIVE';
    if (a.do.startsWith('private.') && this.mode === 'dry') return 'NEEDS LIVE';
    // Looking for Sam on a page while he isn't hired (the dry run's stand-in).
    if (this.mode === 'dry' && this.c.sam?.standIn && /not on the page/.test(msg) && /sam/i.test(JSON.stringify(a.target || ''))) return 'NEEDS LIVE';
    if (a.do.startsWith('web.') && this.browser.up && this.browser.page && await this.browser.signinNeeded().catch(() => null)) return 'SIGN-IN';
    return 'FAILED';
  }

  report(s, a, result, note = '') { this.dryReport.push({ step: s.id, action: a.do, result, note }); }

  // ---- waits ------------------------------------------------------------------
  stopPoll() { this.pollId++; this.waitActive = false; }
  startWait(s) {
    const id = ++this.pollId, w = s.wait;
    // Still waiting, even while a check error shows red (preview 2, piece 7:
    // one failed read turned the light red and the autopilot moved on).
    this.waitActive = true;
    const nextSamePiece = this.list[this.i + 1]?.piece === s.piece;
    this.setLight('yellow', w.waiting);
    // The recording pauses only while nobody is doing anything on screen. A
    // check answers hold: true while it waits on the PRESENTER (typing
    // approve): then the camera keeps rolling.
    // The step's line is still being spoken: keep the camera rolling until
    // it ends (the narration clip's length, or ~15 characters a second).
    const lineMs = ((this.narration?.[s.id]?.dur) ?? (s.say || []).join(' ').length / 15) * 1000 + 600;
    const holdUntil = (this.lineStarted || Date.now()) + lineMs;
    const camera = async (hold) => {
      if (this.mode === 'dry' && !this.watch) return;
      // hold = the presenter acts on camera (types approve, presses Contain).
      // Unattended the cockpit has already done that in the step itself, so
      // nothing more happens on screen: the camera pauses when the line ends
      // (preview 2 review: a 27 s silent gap during the apply).
      if (hold && !this.unattended) { await this.rec.resume().catch(() => {}); return; }
      if (Date.now() < holdUntil) await sleep(holdUntil - Date.now());
      if (id !== this.pollId) return;
      await this.rec.pause().catch((e) => this.log(`recording: pause failed (${e.message})`));
    };
    // Unattended: the camera pauses when the line ends even if the first
    // check is still running (preview 2, 5-second: a 55 s Graph read kept it
    // rolling over a stale page).
    const unattended = this.unattended;
    if (unattended && (this.mode !== 'dry' || this.watch)) setTimeout(() => { if (id === this.pollId && this.light.color !== 'green') this.rec.pause().catch(() => {}); }, Math.max(0, holdUntil - Date.now()));
    const started = Date.now(); let nudgedAt = 0;
    const loop = async () => {
      while (id === this.pollId) {
        let r;
        try { r = await this.check(w.check); }
        catch (e) { r = { state: 'error', text: e.message.split('\n')[0] }; }
        if (id !== this.pollId) return;
        if (r.state === 'ready') {
          this.waitActive = false;
          if (this.mode !== 'dry') for (const a of w.onReady || []) await this.act(a, s).catch((e) => this.log(`[${s.id}] onReady ${a.do}: ${e.message}`));
          // Unattended, the camera stays paused: the next step's run() starts
          // it once its page (the result) is up.
          if (this.mode !== 'dry' && nextSamePiece && !this.unattended) await this.rec.resume().catch(() => {});
          this.setLight('green', `${w.ready}${r.text ? ` · ${r.text}` : ''}`);
          this.report(s, { do: `wait:${w.check}` }, 'READY', r.text || '');
          return;
        }
        await camera(!!r.hold);
        // --preview does the fallback the run sheet gives the presenter: after
        // 3 minutes, provision Sam on demand instead of waiting for the cycle.
        // Again every 4 minutes while it still waits (a first nudge can land
        // before the account it needs exists).
        if (this.mode === 'preview' && w.nudge && Date.now() - nudgedAt > 240000 && Date.now() - started > (w.nudgeAfterMs ?? 90000)) {
          nudgedAt = Date.now();
          if (w.nudge === 'lcw') {
            // The day-1 joiner workflow runs on its own schedule (up to 3
            // hours): a preview runs it on demand for its test hire only.
            await this.needSam().then((u) => L.sh(path.join(L.LAB, 'lab/scripts/operator/op'), ['az', 'rest', '--method', 'POST', '--url', 'https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/1022035a-37ee-4284-af02-48472617080b/activate', '--headers', 'Content-Type=application/json', '--body', JSON.stringify({ subjects: [{ id: u.id }] })], { cwd: L.LAB, timeout: 120000 }))
              .then(() => this.log('preview: joiner workflow run on demand for the test hire'), (e) => this.log(`preview: joiner on demand: ${e.message.split('\n')[0]}`));
          } else if (w.nudge === 'cloudsync') {
            await this.needSam().then(async (u) => { const dn = await L.onPremDn(u.id); if (!dn) throw new Error('no on-site DN for Sam'); return L.cloudSyncOnDemand(dn); })
              .then((m) => this.log(`preview: Cloud Sync on demand for Sam: ${String(m).slice(0, 120)}`), (e) => this.log(`preview: Cloud Sync on demand: ${e.message.split('\n')[0]}`));
          } else {
            const sp = { aws: 'AWS IAM Identity Center', snow: 'ServiceNow - Provisioning' }[w.nudge];
            await this.needSam().then((u) => L.provisionOnDemand(sp, u.id)).then((m) => this.log(`preview: provisioned Sam on demand in ${sp}: ${String(m).slice(0, 120)}`), (e) => this.log(`preview: provision on demand (${sp}): ${e.message.split('\n')[0]}`));
            // The user on demand carries no group: the group, with Sam in it.
            if (w.nudge === 'aws' && w.check === 'samInAws') await this.needSam().then((u) => L.provisionGroupOnDemand(sp, L.AWS_STAFF_GROUP, u.id)).then((m) => this.log(`preview: ${L.AWS_STAFF_GROUP} on demand with Sam: ${String(m).slice(0, 120)}`), (e) => this.log(`preview: group on demand: ${e.message.split('\n')[0]}`));
          }
        }
        this.setLight(r.state === 'error' ? 'red' : 'yellow', `${w.waiting}${r.text ? ` · ${r.text}` : ''}`);
        if (this.mode === 'dry') {
          // A dry run has no merge, no drill and no Sam of its own: a wait that
          // only a live run can answer says so instead of ERROR.
          const live = /no merge commit|no drill in this session|not in Entra at all|no HR push/.test(r.text || '');
          this.report(s, { do: `wait:${w.check}` }, r.state === 'error' ? (live ? 'NEEDS LIVE' : 'ERROR') : 'NOT YET', r.text || '');
          return;
        }
        await sleep(12000);
      }
    };
    return loop();
  }

  // Each check: { state: 'wait' | 'ready' | 'error', text }. Reads only.
  async check(name) {
    const c = this.c;
    switch (name) {
      case 'prChecks': {
        if (!c.pr) return { state: 'wait', text: 'no pull request yet' };
        const r = await L.prChecks(c.pr.number);
        c.planUrl = r.planUrl;
        if (r.failed.length) return { state: 'error', text: `failed: ${r.failed.join(', ')}` };
        if (r.plan && r.total && r.done === r.total) return { state: 'ready', text: r.headline };
        return { state: 'wait', text: `${r.done} of ${r.total} checks done${r.plan ? ', plan posted' : ''}` };
      }
      case 'approvalIssue': {
        await this.findMerge();
        if (!c.mergeSha) return { state: 'wait', text: 'not merged yet' };
        const runs = await L.runsFor('terraform-apply.yml', { sha: c.mergeSha });
        if (runs[0]) c.applyRun = { id: runs[0].databaseId, url: runs[0].url };
        else return { state: 'wait', text: 'the build has not started yet' };
        if (runs[0].status === 'completed' && runs[0].conclusion !== 'success') return { state: 'error', text: `the build ${runs[0].conclusion}` };
        const issue = await L.approvalIssue(c.mergeSha);
        if (issue) { c.issue = issue; return { state: 'ready', text: `issue #${issue.number}` }; }
        return { state: 'wait', text: 'build running, approval request not open yet' };
      }
      case 'applyDone': {
        if (!c.mergeSha) await this.findMerge();
        if (!c.mergeSha) return { state: 'error', text: 'no merge commit (was the PR merged?)' };
        const runs = await L.runsFor('terraform-apply.yml', { sha: c.mergeSha });
        const r = runs[0];
        if (!r) return { state: 'wait', text: 'no build run yet' };
        c.applyRun = { id: r.databaseId, url: r.url };
        if (r.status === 'completed') return r.conclusion === 'success' ? { state: 'ready', text: '' } : { state: 'error', text: `the build ${r.conclusion}` };
        const issue = await L.approvalIssue(c.mergeSha);
        const waitingOnYou = !!issue && issue.state === 'OPEN';
        return { state: 'wait', hold: waitingOnYou, text: waitingOnYou ? 'waiting for your "approve" comment (still recording)' : 'building' };
      }
      case 'hrRunDone': {
        if (!c.hrSha) return { state: c.mode === 'dry' ? 'wait' : 'error', text: 'no HR push in this session' };
        const runs = await L.runsFor('hr-feed.yml', { branch: 'hr-feed', sha: c.hrSha });
        const r = runs[0];
        if (!r) return { state: 'wait', text: 'run not started yet' };
        c.hrRun = { id: r.databaseId, url: r.url };
        if (r.status !== 'completed') return { state: 'wait', text: r.status };
        return r.conclusion === 'success' ? { state: 'ready', text: '' } : { state: 'error', text: `the HR run ${r.conclusion}` };
      }
      case 'samProvLog': {
        // Only rows from this take's HR push (earlier takes leave rows too).
        const rows = (await L.provisioningRows(c.hireId || '400104')).filter((r) => !c.hrPushedAt || Date.parse(r.when) >= c.hrPushedAt - 60000);
        return rows.length ? { state: 'ready', text: `${rows[0].action} ${rows[0].status}` } : { state: 'wait', text: 'not in the log yet' };
      }
      case 'samInEntra': {
        const u = await L.samUser(this.c.hireId);
        if (!u) return { state: 'wait', text: 'not in Entra yet' };
        c.sam = { id: u.id, upn: u.userPrincipalName };
        return u.onPremisesSyncEnabled ? { state: 'ready', text: u.userPrincipalName } : { state: 'wait', text: 'in Entra, not marked synced yet' };
      }
      case 'samHasPackage': {
        const u = await this.needSam();
        const a = await L.assignmentsFor(u.id);
        const pkg = c.hire?.pkg || 'IT - Cloud Engineering Apps';
        const hit = a.find((x) => x.pkg === pkg);
        if (hit?.state === 'delivered') return { state: 'ready', text: `${pkg} delivered` };
        return { state: 'wait', text: hit ? `package ${hit.state}` : 'no package yet' };
      }
      case 'samInAws': {
        const u = await this.needSam();
        const a = await L.awsUser(u.upn);
        if (a?.status !== 'ENABLED') return { state: 'wait', text: a ? `in AWS, ${a.status}` : 'not in AWS yet' };
        // Preview 2: in AWS but in no group = "ViewOnlyAccess: No access" on
        // camera. Ready only once AWS has him in the group that carries the
        // account access (operator read of Identity Center).
        if (!(await L.awsUserInGroup(u.upn, L.AWS_STAFF_GROUP))) return { state: 'wait', text: `in AWS, not yet in ${L.AWS_STAFF_GROUP} (no account access yet)` };
        return { state: 'ready', text: `in AWS and in ${L.AWS_STAFF_GROUP}` };
      }
      case 'samOffEntra': {
        const u = await L.samUser(this.c.hireId);
        if (!u) return { state: 'error', text: 'Sam is not in Entra at all' };
        return u.accountEnabled === false ? { state: 'ready', text: this.lap() } : { state: 'wait', text: 'still on' };
      }
      case 'samOffAws': {
        const u = await this.needSam();
        const a = await L.awsUser(u.upn);
        if (!a) return { state: 'ready', text: `gone from AWS ${this.lap()}` };
        return a.status === 'DISABLED' ? { state: 'ready', text: this.lap() } : { state: 'wait', text: 'still enabled in AWS' };
      }
      // ServiceNow: sign-in through Entra on (SAML) and Sam created by the
      // ServiceNow provisioning job (slice 2).
      case 'snowReady': {
        const sso = await L.servicePrincipal('ServiceNow');
        if (sso.preferredSingleSignOnMode !== 'saml' || !sso.loginUrl) return { state: 'error', text: 'ServiceNow sign-in through Entra is not switched on' };
        c.snowLogin = sso.loginUrl;
        const prov = await L.servicePrincipal('ServiceNow - Provisioning');
        const job = await L.syncJob(prov.id);
        if (!job) return { state: 'error', text: 'ServiceNow provisioning has no job' };
        // Only rows about THIS Sam (created after his current Entra account).
        const sam = await L.samUser(this.c.hireId).catch(() => null);
        const born = sam?.createdDateTime ? Date.parse(sam.createdDateTime) : 0;
        const rows = (await L.provisioningRows(c.hire?.name || 'Sam Rivera', prov.id)).filter((r) => Date.parse(r.when) >= born - 60000);
        const ok = rows.find((r) => /success/i.test(r.status || ''));
        if (ok) return { state: 'ready', text: `Sam created in ServiceNow (${ok.action})` };
        if (job.code !== 'Active') return { state: 'error', text: `ServiceNow provisioning is ${job.code} (last cycle ${job.last || '?'}): it has to be on before Sam can reach ServiceNow` };
        return { state: 'wait', text: rows.length ? `ServiceNow log: ${rows[0].action} ${rows[0].status}` : 'not in ServiceNow yet (next provisioning cycle, or Provision on demand)' };
      }
      // Slice 5's containment drill: an approval card must be waiting for a
      // THROWAWAY drill account (itdr-drill-*) and for nothing else. A card
      // for anyone real fails closed: the cockpit never shows it on camera.
      case 'drillPending': {
        const pend = await L.pendingContainment();
        if (!pend.length) return { state: 'wait', text: "no containment card is waiting: arm slice 5's drill first (throwaway itdr-drill user + drill incident)" };
        const isDrill = (x) => x.accounts.length > 0 && x.accounts.every((a) => /^itdr-drill-/i.test(a.name));
        const other = pend.filter((x) => !isDrill(x));
        if (other.length) return { state: 'error', text: `a containment card is waiting for a non-drill account (incident #${other[0].incident}): answer it off camera first; the cockpit won't show it` };
        const d = pend[0], acct = d.accounts[0];
        const u = await L.userById(acct.aadUserId);
        if (!/^itdr-drill-/i.test(u.userPrincipalName) || u.onPremisesSyncEnabled) throw new Error(`the card's account ${u.userPrincipalName} is not a cloud-only drill account`);
        c.drill = { incident: d.incident, upn: u.userPrincipalName, id: u.id };
        return { state: 'ready', text: `card waiting for drill incident #${d.incident} (${u.userPrincipalName})` };
      }
      case 'drillContained': {
        if (!c.drill) return { state: 'error', text: 'no drill in this session' };
        const u = await L.userById(c.drill.id).catch(() => null);
        if (!u) return { state: 'error', text: 'the drill account is gone' };
        // hold: the presenter is pressing the button on camera, keep recording.
        if (u.accountEnabled !== false) return { state: 'wait', hold: true, text: 'press Contain on the card' };
        // Preview 2 review: never narrate an approval nobody gave. Unattended,
        // ready only when the account is off AND the card was answered (the
        // Logic App rewrote it to "Decision recorded").
        if ((this.preview || this.proof) && !c.drill.cardUpdated) {
          const t = this.staffBrowser?.up ? await this.staffBrowser.page.locator('body').innerText().catch(() => '') : '';
          if (!/Decision recorded/.test(t)) return { state: 'wait', text: 'account is off, but the card does not show the decision yet' };
        }
        return { state: 'ready', text: `${u.userPrincipalName} is switched off` };
      }
      // The alarm Raj's activation raised (the rule runs on a timer): a
      // "PIM activation" incident created after piece 6's activation.
      case 'pimIncident': {
        // Preview 2 review: the newest "PIM activation" incident was the
        // cockpit's own AWS-admin activation (adm-labops), shown as Raj's. It
        // must be an incident whose Account entities include Raj, newest
        // first, created after his activation in piece 6.
        const since = c.pimActivatedAt || 0;
        // A v2 preview activates nothing: the newest earlier incident about Raj may be far down the list.
        const cands = (await L.sentinelIncidents(this.v2 && this.preview ? 200 : 20)).filter((x) => /PIM activation/i.test(x.title) && Date.parse(x.created) >= since - 60000);
        for (const inc of cands) {
          const accts = await L.incidentAccounts(inc.name).catch(() => []);
          if (accts.some((a) => a.startsWith('adm-raj.patel@'))) {
            c.pimIncident = { ...inc, accounts: accts };
            return { state: 'ready', text: `incident #${inc.number} (Defender ${inc.providerIncidentId}): ${accts.join(', ')}` };
          }
        }
        return { state: 'wait', text: cands.length ? `${cands.length} PIM activation incident(s) since, none about Raj yet` : "no incident for Raj's activation yet" };
      }
      case 'samSignin': {
        // Ready once the log has THIS take's sign-in with his one-time pass;
        // its place in the newest-first list is the row 5-second opens.
        const u = await this.needSam();
        const r = await L.signInsDetailed(u.id);
        const since = c.tapAt ? c.tapAt - 120000 : 0;
        const k = r.findIndex((x) => Date.parse(x.when) >= since && x.methods.includes('Temporary Access Pass'));
        if (k < 0) return { state: 'wait', text: r.length ? 'his one-time-pass sign-in is not in the log yet' : 'not in the log yet' };
        c.samTapRow = k;
        // The portal lists newer "Previously satisfied" sign-ins above it, so
        // its row is found by its own date and time, as the portal shows them
        // (local time, e.g. "11/5/2026, 8:51:58 PM"), with the row number as
        // a fallback.
        const d = new Date(r[k].when);
        const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true }).formatToParts(d).map((x) => [x.type, x.value]));
        c.samTapDateRe = `^${parts.month}/${parts.day}/(${parts.year}|${String(parts.year).slice(2)}),?\\s+${parts.hour}:${parts.minute}:${parts.second}\\s*${parts.dayPeriod}$`;
        c.samTapWhen = r[k].when;
        return { state: 'ready', text: `one-time-pass sign-in logged at ${r[k].when} (row ${k + 1})` };
      }
      case 'samGone': {
        const u = await L.samUser(this.c.hireId);
        return u ? { state: 'wait', text: 'Sam is still in Entra (Cloud Sync removes him on its next run, about 20 minutes)' } : { state: 'ready', text: '' };
      }
      case 'evidenceDone': {
        const runs = await L.runsFor('evidence-pack.yml', { event: 'workflow_dispatch', limit: 5 });
        const r = runs.find((x) => !c.evStarted || Date.parse(x.createdAt) >= c.evStarted - 60000);
        if (!r) return { state: 'wait', text: 'run not started yet' };
        c.evRun = { id: r.databaseId, url: r.url };
        if (r.status !== 'completed') return { state: 'wait', text: r.status };
        return r.conclusion === 'success' ? { state: 'ready', text: '' } : { state: 'error', text: `evidence run ${r.conclusion}` };
      }
      // N05 (Karen A4): Raj's reason names a real ServiceNow incident.
      case 'rajTicket': return /^INC\d{7}$/.test(c.rajTicket || '') ? { state: 'ready', text: c.rajTicket } : { state: 'error', text: "no ServiceNow incident for Raj's reason: start the cockpit with --raj-ticket INC00xxxxx (a real one)" };
      default: throw new Error(`unknown check ${name}`);
    }
  }
  lap() { const sw = this.c.sw; if (!sw) return ''; const s = Math.round((Date.now() - sw.t0) / 1000); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} after the push`; }
  async needSam() {
    if (this.c.sam?.upn) return this.c.sam;
    const u = await L.samUser(this.c.hireId);
    if (!u) throw new Error('Sam is not in Entra');
    this.c.sam = { id: u.id, upn: u.userPrincipalName };
    return this.c.sam;
  }
  async findMerge() {
    const c = this.c;
    if (c.mergeSha || !c.pr) return;
    const v = await L.ghJson(['pr', 'view', String(c.pr.number), '-R', L.REPO, '--json', 'state,mergeCommit']);
    if (v.state === 'MERGED' && v.mergeCommit?.oid) c.mergeSha = v.mergeCommit.oid;
  }

  // ---- actions ------------------------------------------------------------------
  val(v) {
    if (typeof v !== 'function') return v;
    try { const r = v(this.c); if (r == null) throw new Error(); return r; }
    catch { throw new Error('needs a value from an earlier live step (PR, run or Sam) that this run does not have'); }
  }

  // Exactly one cockpit window in front (lib/stage.mjs): the others hidden.
  cockpitPids() { return [this.browser?.up && this.browser.pid(), this.staffBrowser?.up && this.staffBrowser.pid(), this.awsBrowser?.up && this.awsBrowser.pid(), this.browser?.priv?.pid].filter(Boolean); }
  async front(app) {
    // A window change as a person makes it (lib/human.mjs beforeSwitch): the
    // hand leaves the page, a beat, the window is there, a beat.
    const switching = this.human?.real && this.c.front && this.c.front !== app;
    if (switching) await this.human.beforeSwitch();
    await this._front(app);
    if (switching) await this.human.afterSwitch();
  }
  async _front(app) {
    // Already on stage (2026-11-07: each extra stage() pass cost 1-2 s of
    // silent footage): nothing to do.
    if (this.v2 && this.c.front === app && app !== 'private') {
      const st = this.onStage();
      const W = app === 'code' ? null : (app === 'staff' ? this.staffBrowser : app === 'aws' ? this.awsBrowser : this.browser);
      const mine = app === 'code' ? (st.top?.title || '').endsWith(this.code?.title || '\u0000') : (W?.up && +st.top?.pid === +W.pid());
      if (st.ok && mine) return;
    }
    if (app === 'code') {
      if (!this.code.ready) await this.code.open();
      await stage({ kind: 'code', title: this.code.title }, this.cockpitPids(), this.log);
      // Extensions' toasts ("Sign in to GitHub ...", "Node runtime
      // auto-detected ...") arrive late, e.g. after the window reloads: they
      // are cleared every time VS Code comes on stage (preview 2, piece 9).
      await this.code.call('command', { id: 'notifications.clearAll' }).catch(() => {});
      await this.recordingLook(true);
    } else {
      const B = app === 'staff' ? this.staffBrowser : app === 'aws' ? this.awsBrowser : app === 'private' ? null : this.browser;
      if (B) {
        if (!B.up) await B.launch();
        await B.page?.bringToFront().catch(() => {});
        await stage({ kind: 'chrome', pid: B.pid() }, this.cockpitPids(), this.log);
      } else if (this.browser.priv) {
        await (this.privPage || this.browser.priv.page)?.bringToFront().catch(() => {});
        if (this.browser.priv.pid) await stage({ kind: 'chrome', pid: this.browser.priv.pid }, this.cockpitPids(), this.log);
      }
    }
    this.c.front = app;
  }

  async act(a, s) {
    const c = this.c, dry = this.mode === 'dry';
    // A presenter's hand step that --preview does for him, in its place in
    // the step (e.g. pressing Contain on camera before 7-contained's line).
    if (a.previewOnly && !this.preview && a.do !== 'pod') return;
    const isWrite = WRITE.has(a.do) || (s.write && CLICKY.has(a.do));
    if (dry && isWrite) {
      const what = describe(a, this);
      this.log(`[${s.id}] WOULD ${what}`); this.report(s, a, 'WOULD', what);
      if (a.do === 'code.type' && a.lineMatch) {   // show where the edit would land
        const txt = fs.readFileSync(a.file, 'utf8').split('\n');
        const ln = txt.findIndex((l) => new RegExp(a.lineMatch).test(l));
        this.report(s, a, ln >= 0 ? 'WOULD' : 'NOTE', ln >= 0 ? `edit line ${ln + 1}` : `no line matches ${a.lineMatch} right now (Sam is added in piece 2)`);
      }
      return;
    }
    // Web actions run in the recording window, or in test-user-a's staff
    // window when the step says ctx: 'staff' (AWS, Teams).
    const staff = a.ctx === 'staff' || a.ctx === 'aws';
    const B = a.ctx === 'aws' ? this.awsBrowser : a.ctx === 'staff' ? this.staffBrowser : this.browser, V = this.code;
    if (staff && /^web\./.test(a.do) && !B.up) await B.launch();
    switch (a.do) {
      case 'code.open': {
        // A step in another window of the profile (the tour's): that window
        // becomes the stage's VS Code window; the last one gets its bars back.
        if (a.ws && path.resolve(a.ws) !== this.code.ws) {
          await this.recordingLook(false);
          this.code = new VsCode(a.ws, { log: this.log }); c.wsFile = this.code.ws; c.codeFitted = false; this.lookHidden = false;
          // Left on another Space by an earlier run (2026-11-10 walkthrough:
          // the v2 and tour windows were out of reach, N04's sign-in log
          // stayed on the demo window): reopened here, as prepareStage does.
          for (let k = 0; k < 2 && this.code.find() && !(await codeWindowHere(this.code.title)); k++) {
            this.log(`stage: ${this.code.title} is on another screen: reopening it here`);
            await this.code.closeWindow();
            await this.code.open();
          }
        }
        await this.code.open(); c.front = 'code';
        if (!c.codeFitted) { const fit = screenFit(); await sleep(500); c.codeFitted = !/not found|error/.test(await this.code.fit(fit.w, fit.h)); }
        // 2026-11-10 walkthrough: a window switched to here (the v2 and tour
        // windows) kept its activity bar, status bar ("AWS: profile ..." in
        // red) and toasts, because c.front = 'code' made _front skip its
        // on-stage look. Same look as every stage VS Code window.
        await this.code.call('command', { id: 'notifications.clearAll' }).catch(() => {});
        await this.recordingLook(true);
        break;
      }
      case 'code.closeAll': await this.front('code'); await V.call('command', { id: 'workbench.action.closeUnmodifiedEditors' }); break;
      case 'code.diff': await this.front('code'); await V.call('diff', { file: a.file, line: a.line, endLine: a.endLine, highlightMs: a.highlight ? -1 : 0 }); break;
      // The finished file with its changed lines softly tinted (no diff view).
      case 'code.changes': { await this.front('code'); const r = await V.call('changes', { file: a.file, from: a.from, to: a.to, line: a.line }); this.log(`[${s.id}] ${path.basename(a.file)}: changed lines ${r.lines.join(',')}`); break; }
      case 'code.file': await this.front('code'); await V.call('open', { file: a.file, line: a.line, endLine: a.endLine, highlightMs: a.highlight ? -1 : 0 }); break;
      case 'code.highlight': await this.front('code'); await V.call('highlight', { file: a.file, line: a.line, endLine: a.endLine, ms: 0, side: a.side || 'after' }); break;
      case 'code.type': await this.front('code'); await V.call('type', { file: a.file, text: a.text, lineMatch: a.lineMatch, find: a.find, trailingNewline: a.trailingNewline }); break;
      case 'code.save': await V.call('save', { file: a.file }); break;
      case 'code.commit': {
        await this.front('code');
        const r = await V.call('commit', { folder: a.folder, message: a.message, files: a.files, allowBranch: a.allowBranch, typeOnly: !!a.typeOnly });
        if (a.typeOnly) { if (!r.typed) throw new Error('the VS Code bridge is older than 0.1.7: it committed instead of only typing'); this.log(`[${s.id}] typed the commit message on ${r.branch} (nothing committed)`); break; }
        if (a.folder === c.hr) c.hrSha = r.sha;
        this.log(`[${s.id}] committed ${r.sha.slice(0, 7)} on ${r.branch}`);
        break;
      }
      case 'code.push': {
        if (a.folder === c.bp && a.branch !== c.bpBranch) throw new Error(`refusing to push ${a.branch}`);
        if (a.folder === c.hr && a.branch !== 'hr-feed') throw new Error(`refusing to push ${a.branch} from the HR folder`);
        const r = await V.call('push', { folder: a.folder, branch: a.branch });
        if (a.folder === c.hr) { c.hrSha = r.sha; c.hrPushedAt = Date.now(); }
        this.log(`[${s.id}] pushed ${r.sha.slice(0, 7)} to ${r.pushed}`);
        break;
      }
      case 'web.open': {
        await this.front(a.ctx === 'aws' ? 'aws' : staff ? 'staff' : 'browser');
        // Unattended with the real pointer: the camera rolls while the page is
        // reached by hand (tab click or typed address, lib/browser.mjs
        // humanOpen) and loads; the capTimer does not cut it.
        let need;
        try { need = await B.open(this.val(a.url), { settle: a.settle ?? 2500, onHuman: this.humanNavHook() }); } finally { this.navHuman = false; }
        if (need) throw new Error(`${need}: sign in once in the ${staff ? 'staff' : 'recording'} browser`);
        // A page that opened but refuses this identity (e.g. AWS's "You need
        // permissions"): say so instead of hunting for rows that can't be there.
        if (a.deny && new RegExp(a.deny, 'i').test(await B.page.locator('body').innerText().catch(() => ''))) throw new Error(`the page refuses ${a.ctx === 'aws' ? AWS_ADMIN.id : staff ? STAFF.id : 'this identity'}: it needs a role that can see it`);
        break;
      }
      // A check on the page, nothing drawn: the target must show up in time
      // (e.g. Splunk's result count above 0), or the step fails.
      case 'web.find': { await B.find(this.val(a.target), { timeout: a.timeout ?? 15000 }); break; }
      // Camera off: wait for something to show on the page, reloading it now
      // and then (e.g. GitHub's run summary appears only once the run is done).
      case 'web.waitFor': {
        const end = Date.now() + (a.timeout ?? 180000); let found = false;
        while (!found && Date.now() < end) {
          found = await B.find(this.val(a.target), { timeout: 8000 }).then(() => true, () => false);
          if (!found) { await B.page.reload({ waitUntil: 'domcontentloaded' }).catch(() => {}); await sleep(a.every ?? 12000); }
        }
        if (!found) throw new Error(`not on the page after ${Math.round((a.timeout ?? 180000) / 1000)} s: ${JSON.stringify(this.val(a.target))}`);
        break;
      }
      case 'web.highlight': {
        const ts = [].concat(this.val(a.target)); let last;
        for (const t of ts) { try { await B.highlight(t, this.val(a.tag) || ''); last = null; break; } catch (e) { last = e; } }
        if (last) throw last;
        break;
      }
      // target may be a list: the first one that shows up within the timeout
      // (e.g. a tab by role/name, then by its text).
      case 'web.click': {
        await B.unhighlight();
        const ts = [].concat(this.val(a.target)); let err;
        for (const t of ts) {
          try { await B.find(t, { timeout: Math.round((a.timeout ?? 15000) / ts.length) }); await B.click(t); err = null; break; } catch (e) { err = e; }
        }
        if (err) throw err;
        await B.settle(a.settle ?? 2500); break;
      }
      // A click that may not be needed (e.g. Teams' "use the web app instead").
      case 'web.clickIf': { const t = this.val(a.target); if (await B.find(t, { timeout: a.timeout ?? 6000 }).then(() => true, () => false)) { await B.click(t); await B.settle(a.settle ?? 3000); } break; }
      case 'web.type': await B.type(a.target, a.text); break;
      case 'web.focus': await B.focusBox(a.target); break;
      case 'private.open': { const p = await this.priv(); await this.front('private'); await p.open(this.val(a.url), { settle: a.settle ?? 3000 }); break; }
      case 'private.click': { const p = await this.priv(); await p.click(a.target); await p.settle(a.settle ?? 2500); break; }
      case 'private.highlight': {
        const p = await this.priv(); const ts = [].concat(this.val(a.target)); let last;
        for (const t of ts) { try { await p.highlight(t, this.val(a.tag) || ''); last = null; break; } catch (e) { last = e; } }
        if (last) throw last;
        break;
      }
      // Run one live check now; stop the step (red light, its reason shown)
      // if it isn't ready. A dry run only reports it.
      case 'require': {
        // A live read, nothing to see: off camera.
        const wasRec = !!this.rec.piece && !this.rec.paused;
        if (wasRec) await this.rec.pause().catch(() => {});
        let r = await this.check(a.check).catch((e) => ({ state: 'error', text: e.message.split('\n')[0] }));
        // Unattended (preview 2, piece 4: "ServiceNow log: create skipped",
        // the log row of Sam's real update had not reached Graph yet): keep
        // checking for up to 10 minutes, camera off, ServiceNow provisioned on
        // demand once, instead of failing the step on camera.
        if (this.mode === 'preview' && r.state !== 'ready') {
          const until = Date.now() + 15 * 60000; let nudged = false;
          while (r.state !== 'ready' && Date.now() < until) {
            if (a.check === 'snowReady' && !nudged) { nudged = true; await this.needSam().then((u) => L.provisionOnDemand('ServiceNow - Provisioning', u.id)).then((m) => this.log(`preview: ServiceNow on demand for Sam: ${String(m).slice(0, 120)}`), (e) => this.log(`preview: ServiceNow on demand: ${e.message.split('\n')[0]}`)); }
            this.setLight('yellow', `checking ${a.check}: ${r.text}`);
            await sleep(20000);
            r = await this.check(a.check).catch((e) => ({ state: 'error', text: e.message.split('\n')[0] }));
          }
        }
        if (wasRec) await this.rec.resume().catch(() => {});
        if (r.state !== 'ready') {
          if (dry) { this.report(s, a, 'NOT YET', r.text); return; }
          throw new Error(`not ready: ${r.text}`);
        }
        break;
      }
      case 'private.type': { const p = await this.priv(); await p.type(a.target, this.val(a.text)); break; }
      case 'activate':
        if (a.app === 'private') await this.priv();
        await this.front(a.app);
        break;
      case 'find':
        if (a.what === 'sam') {
          if (dry && c.sam?.standIn) { this.report(s, a, 'NOTE', `Sam is not in Entra now: showing stand-in ${c.sam.standIn}`); break; }
          await this.needSam();
        }
        break;
      case 'stopwatch.start': c.sw = { t0: Date.now(), laps: [] }; await B.startStopwatch(c.sw.t0); break;
      case 'stopwatch.lap': if (c.sw) c.sw.laps.push({ label: a.label, s: Math.round((Date.now() - c.sw.t0) / 1000) }); break;
      case 'stopwatch.stop': await B.stopStopwatch(); break;
      case 'gh.createPr': await this.createPr(a); break;
      case 'gh.merge': await this.merge(); break;
      case 'gh.closePr': {
        if (this.mode !== 'rehearse') throw new Error('closing the PR is only for rehearsals');
        await closeRehearsal({ branch: c.bpBranch, pr: c.pr, log: this.log });
        break;
      }
      case 'gh.runWorkflow': await this.runWorkflow(a.workflow); break;
      case 'tap.signin': await this.tapSignin(a.who, a.url); break;
      // A registry identity (PR #196) in a fresh window of its own, e.g. Ava's
      // admin badge with her passkey. Without the tool: her one-time pass.
      case 'identity.signin': {
        const T = await signinTool(this.root).catch(() => null);
        if (!T) { await this.tapSignin(a.fallback || 'ava', a.url); break; }
        const pw = await this.browser.privateWindow();
        const ctx = await pw.browser.newContext({ viewport: null });
        await ctx.addInitScript(OVERLAY);
        const page = await ctx.newPage();
        await page.bringToFront();
        await T.signIn(a.id, a.url, { context: ctx, page });
        // The portal is still drawing when sign-in returns (piece 6 opened on
        // Entra's loading spinner): wait until it has settled.
        await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});
        await sleep(2500);
        this.privPage = page;
        this.log(`${a.id} signed in in a window of its own (${a.id === AVA.id ? 'passkey' : 'registry method'})`);
        break;
      }
      // ServiceNow admin view: only ever as the recovery account. The session
      // is checked BEFORE any ServiceNow page opens in the recording browser:
      // opening one without it would start single sign-on with whatever
      // Entra session the browser has (the owner's), which must never happen.
      case 'snow.adminList': {
        await this.front('browser');
        let who = await snowUser(B.ctx);
        if (who && who !== 'acr.breakglass') throw new Error(`the recording browser's ServiceNow session belongs to ${who}: not shown`);
        if (!who) {
          if (dry) { this.report(s, a, 'WOULD', 'sign the ServiceNow recovery account in first (a setup step on the start screen)'); throw new Error('not ready: ServiceNow recovery account not signed in yet (start screen: Check sign-ins)'); }
          await this.rec.pause().catch(() => {});
          await signInRecovery(B.page, { log: this.log });
          await this.rec.resume().catch(() => {});
          who = await snowUser(B.ctx);
          if (who !== 'acr.breakglass') throw new Error('ServiceNow recovery sign-in did not stick');
        }
        const need = await B.open(PROVISIONED_USERS, { settle: a.settle ?? 5000 });
        if (need || !/service-now\.com\/sys_user_list\.do/.test(B.page.url())) throw new Error(`ServiceNow list did not open (${need || new URL(B.page.url()).host})`);
        break;
      }
      case 'staff.signin': await this.staffSignin(a.upn, a.app); break;
      // Sam's own session in ServiceNow: My Apps in his window, the tile, then
      // his ServiceNow profile page (shows his name and address).
      case 'sam.servicenow': {
        // Dry run: Sam isn't hired, so test-user-a's staff window stands in
        // to prove the path (My Apps, the tile, the profile page).
        const standIn = dry;
        const p = standIn ? this.staffBrowser : await this.priv();
        if (standIn && !p.up) await p.launch();
        await this.front(standIn ? 'staff' : 'private');
        await p.open('https://myapps.microsoft.com/?tenantId=86a2e327-4951-4348-a3c4-6f4b79ffd8f2', { settle: 4000 });
        // Unattended: the camera rolls from Sam's My Apps page on.
        if (this.unattended && (this.pendingStart || (this.rec.piece && this.rec.paused))) await this.safeResume();
        await p.highlight({ text: 'ServiceNow', exact: true }, 'His apps, from his job', { timeout: 40000 });
        await sleep(1500);
        // My Apps' "Tell us what you think" survey can pop up over the tiles
        // (seen 2026-11-06): closed before the click.
        await p.dismissAll();
        const [app] = await Promise.all([p.page.context().waitForEvent('page', { timeout: 60000 }), p.click({ text: 'ServiceNow', exact: true })]);
        await app.waitForURL(/service-now\.com/, { timeout: 90000 });
        // Preview 2: going to the profile as soon as the URL reached
        // ServiceNow cut the single sign-on hand-off short, and the portal
        // showed its login form. Let the landing finish first; if the portal
        // still asks, use its "Log in with Microsoft Entra ID" button (Sam's
        // Entra session answers it).
        await snowLanding(app);
        await app.goto('https://dev459905.service-now.com/sp?id=user_profile', { waitUntil: 'domcontentloaded' });
        await sleep(3000);
        if (await snowLoginForm(app)) {
          this.log(`[${s.id}] ServiceNow showed its login form: signing in through Entra (Sam's session)`);
          await app.getByText(/Log in with Microsoft Entra ID/).first().click({ timeout: 10000 });
          // Only Sam's existing Entra session may answer: any prompt (account
          // picker, password, MFA, stay signed in) stops the step.
          for (let k = 0; k < 45; k++) {
            await sleep(1000);
            const u = app.url();
            if (/service-now\.com/.test(u) && !/saml/i.test(u)) break;
            if (/login\.microsoftonline\.com/.test(u)) {
              const t = await app.locator('body').innerText().catch(() => '');
              if (/Pick an account|Enter password|Stay signed in|Verify your identity|Approve sign in|Enter code|Sign in/i.test(t) && k > 4) {
                const f = path.join(this.root, 'shots', `fail-${s.id}-entra-prompt-${Date.now()}.png`);
                await app.screenshot({ path: f }).catch(() => {});
                throw new Error(`Entra asked Sam for more than his session (${f})`);
              }
            }
          }
          await snowLanding(app);
          if (!/sp\?id=user_profile/.test(app.url())) await app.goto('https://dev459905.service-now.com/sp?id=user_profile', { waitUntil: 'domcontentloaded' });
          await sleep(3000);
        }
        if (!standIn) this.privPage = app;
        await app.bringToFront();
        await app.evaluate(OVERLAY).catch(() => {});
        const ap = Object.create(this.browser); ap.page = app;
        try { await ap.highlight({ re: standIn ? '^Test User A$' : `^${this.c.hire?.name || 'Sam Rivera'}$` }, standIn ? 'Stand-in: Test User A, signed in with the hospital login' : `Signed in as ${this.c.hire?.first || 'Sam'}, with the hospital login`, { timeout: 30000 }); }
        catch (e) {
          // What the page really is (an Entra prompt, ServiceNow's login or
          // "user not found", or the profile with the name shown differently).
          const f = path.join(this.root, 'shots', `fail-${s.id}-${Date.now()}.png`);
          await app.screenshot({ path: f }).catch(() => {});
          this.log(`[${s.id}] page at the failure: ${app.url()} (screenshot ${f})`);
          throw e;
        }
        if (standIn) await app.close().catch(() => {});
        break;
      }
      // PIM's Active tab right after an activation can be empty: refresh until
      // the person's row is there (up to 3 minutes), then point at it.
      case 'pim.showActive': {
        c.pimActivatedAt ||= Date.now();
        const p = await this.priv();
        await this.front('private');
        for (let k = 0; k < 12; k++) {
          await p.click({ role: 'tab', name: /Active assignments/i }).catch(() => p.click({ text: 'Active assignments', exact: true })).catch(() => {});
          await sleep(3000);
          if (await p.find({ text: a.group, row: true }, { timeout: 4000 }).then(() => true, () => false)) { await p.highlight({ text: a.group, row: true }, a.tag || ''); return void this.report(s, a, 'DONE', a.group); }
          await p.page.reload({ waitUntil: 'domcontentloaded' }).catch(() => {});
          await sleep(10000);
        }
        throw new Error(`${a.group} never showed under Active assignments`);
      }
      // Arm slice 5's containment drill if no drill card is waiting yet
      // (containment-drill.sh arm: throwaway user + one High incident +
      // the approval card). Takes minutes: the recording pauses meanwhile.
      case 'drill.ensure': {
        const now = await this.check('drillPending').catch((e) => ({ state: 'error', text: e.message }));
        if (now.state === 'ready') break;
        if (now.state === 'error') throw new Error(now.text);
        const wasRec = !!this.rec.piece && !this.rec.paused;
        if (wasRec) await this.rec.pause().catch(() => {});
        this.setLight('blue', 'Arming the containment drill (a few minutes; recording paused)');
        const main = await labMain(this.root);
        const out = await L.sh(path.join(main, 'lab/scripts/demo/containment-drill.sh'), ['arm'], { cwd: main, timeout: 1200000 });
        this.log(`drill: ${out.trim().split('\n').slice(-2).join(' | ')}`);
        if (wasRec) await this.rec.resume().catch(() => {});
        break;
      }
      // Sam's one-time-pass sign-in in the portal's sign-in log: its row (by
      // its own date and time), then Authentication Details, checked to show
      // "Temporary Access Pass". The log's grid recycles its rows while it
      // loads, so a click can land on a neighbour: then it tries again.
      case 'signin.openTap': {
        if (!c.samTapDateRe) throw new Error('no one-time-pass sign-in found in the log (check samSignin first)');
        const row = { re: c.samTapDateRe, row: true };
        let ok = false;
        for (let k = 0; k < 4 && !ok; k++) {
          await B.unhighlight();
          await B.find(row, { timeout: 30000 });
          await sleep(2000);
          await B.click(row);
          await sleep(3000);
          for (const t of [{ role: 'tab', name: 'Authentication Details' }, { text: 'Authentication Details', exact: true }]) {
            if (await B.find(t, { timeout: 8000 }).then(() => true, () => false)) { await B.click(t); break; }
          }
          await sleep(2500);
          ok = await B.find({ text: 'Temporary Access Pass' }, { timeout: 6000 }).then(() => true, () => false);
          if (!ok) this.log(`[${s.id}] the opened sign-in is not the one-time-pass one: again`);
        }
        if (!ok) throw new Error('could not open the one-time-pass sign-in in the log');
        break;
      }
      // Piece 11, the tour. The PAM stand-ins run on this Mac (lab/pam,
      // local Docker harness); their lab sign-ins are read in-process from
      // the stack's own .secrets and typed into masked fields, never shown.
      case 'pam.vault': {
        await this.front('browser');
        const fsm = await import('node:fs');
        await B.page.goto('http://127.0.0.1:8200/ui/vault/auth?with=token', { waitUntil: 'domcontentloaded' });
        await sleep(3000);
        if (await B.page.getByRole('button', { name: /^Sign in$/ }).isVisible().catch(() => false)) {
          let tok = JSON.parse(fsm.readFileSync(path.join(PAM_DIR, '.secrets', 'vault-init.json'), 'utf8')).root_token;
          await B.page.locator('input[name=token], input#token, input[type=password]').first().fill(tok); tok = null;
          await B.page.getByRole('button', { name: /^Sign in$/ }).click();
          await sleep(5000);
        }
        // The UI keeps its token only in memory: from here by its own links.
        await B.page.getByRole('link', { name: /^ldap\/?/ }).first().click(); await sleep(3500);
        await B.page.getByRole('link', { name: /^Libraries$/ }).first().click(); await sleep(3500);
        await B.page.getByRole('link', { name: /tier0-admins/ }).first().click(); await sleep(4000);
        break;
      }
      case 'pam.guac': {
        await this.front('browser');
        const fsm = await import('node:fs');
        await B.page.goto('http://127.0.0.1:8081/guacamole/', { waitUntil: 'networkidle' }).catch(() => {});
        await sleep(3000);
        if (!/ALL CONNECTIONS/.test(await B.page.locator('body').innerText().catch(() => ''))) {
          await B.page.locator('input[type=text]').first().fill('guacadmin');
          let gp = fsm.readFileSync(path.join(PAM_DIR, '.secrets', 'guacadmin-password'), 'utf8').trim();
          await B.page.locator('input[type=password]').first().fill(gp); gp = null;
          await B.page.keyboard.press('Enter'); await sleep(5000);
        }
        await B.page.getByText('guacadmin', { exact: true }).first().click(); await sleep(1000);
        await B.page.getByText('Settings', { exact: true }).first().click(); await sleep(3000);
        await B.page.getByText('History', { exact: true }).first().click(); await sleep(4000);
        break;
      }
      // test-user-b (clinic user) signs in to the Okta org through Entra
      // (Okta's identity-provider route), in a window of its own.
      case 'okta.signin': {
        const T = await signinTool(this.root);
        const pw = await this.browser.privateWindow();
        // Okta's content security policy blocked the overlay's styles (the
        // tag and the leaver timer showed as raw text): this window lets the
        // cockpit's own styles through.
        const ctx = await pw.browser.newContext({ viewport: null, bypassCSP: true });
        await ctx.addInitScript(OVERLAY);
        const page = await ctx.newPage();
        this.privPage = page;
        await this.front('private');
        await T.signIn('test-user-b', 'https://integrator-8288815.okta.com/sso/idps/0oa199lwoygFZWTfm698?fromURI=%2Fapp%2FUserHome', { context: ctx, page });
        for (let k = 0; k < 30 && !/okta\.com\/app\/UserHome/.test(page.url()); k++) await sleep(1000);
        await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});
        await sleep(3000);
        await page.evaluate(() => window.scrollTo(0, 0)).catch(() => {});
        await page.bringToFront();
        break;
      }
      case 'preview.approve': await this.previewApprove(); break;
      // Web Teams only, as test-user-a in the Contoso tenant: quit the desktop
      // app, check whose Microsoft session the staff window has, and after the
      // page opens, that it is Contoso's channel (never another organisation).
      case 'teams.guard': {
        const wasRec = !!this.rec.piece && !this.rec.paused && a.phase === 'before';
        if (wasRec) await this.rec.pause().catch(() => {});
        try { await this.teamsGuard(a); } finally { if (wasRec) await this.rec.resume().catch(() => {}); }
        break;
      }
      // In web Teams: the Teams list, then the team's channel (opened by
      // clicks, so no launcher page and no desktop app).
      case 'teams.channel': {
        const SB = this.staffBrowser;
        await SB.click({ role: 'button', name: /^Teams\b/ }).catch(() => SB.click({ re: '^Teams$' })).catch(() => {});
        await sleep(3000);
        const ch = { text: a.channel, exact: true };
        if (!(await SB.find(ch, { timeout: 6000 }).then(() => true, () => false))) { await SB.click({ text: a.team, exact: true }); await sleep(2500); }
        await SB.click(ch);
        await sleep(8000);
        break;
      }
      case 'cloudsync.restart': { if (this.mode !== 'preview' && a.previewOnly) break; this.log(`preview: ${await L.cloudSyncRestart(a.scope || 'None')}`); break; }
      case 'pod': {
        if (this.mode !== 'preview' && a.previewOnly) break;
        const sp = { aws: 'AWS IAM Identity Center', snow: 'ServiceNow - Provisioning' }[a.app];
        const u = await this.needSam();
        this.log(`preview: provision on demand, Sam -> ${sp}: ${String(await L.provisionOnDemand(sp, u.id)).slice(0, 120)}`);
        break;
      }
      // Give a PIM group back (Deactivate in My roles, in the person's own
      // window), then check Entra no longer lists them as a member.
      // Give a PIM group back. PIM refuses a deactivation in the first five
      // minutes after an activation, so it is queued and done at the end of
      // the take / preview (giveBackAll), as the person, in a headless window.
      case 'pim.deactivate': { (this.giveBacks ||= []).push({ id: a.id || 'adm-raj.patel', upn: a.upn, group: a.group }); this.log(`${a.group}: given back at the end (PIM's five-minute rule)`); break; }
      case 'preview.contain': await this.previewContain(); break;
      case 'preview.secondCheck': await this.previewSecondCheck(); break;
      // ---- v2 (2026-11-07) ------------------------------------------------
      // A drawn screen (ui/card.html, the card in the URL's hash), in the
      // recording browser.
      case 'card': {
        // Card after card: the page is already up, so only its hash changes
        // (it redraws at once; no load, no window change).
        const url = localUrl(a.url);
        const onCard = c.front === 'browser' && B.page && !B.page.isClosed() && B.page.url().split('#')[0] === url.split('#')[0];
        if (onCard && this.onStage().ok) { await B.page.evaluate((h) => { location.hash = h; }, url.split('#')[1]); await sleep(150); break; }
        await this.front('browser');
        await B.open(url, { settle: a.settle ?? 250 });
        break;
      }
      // A captured screen (a local image of an earlier real run): opened with
      // the camera rolling, like a page already loaded (it draws at once).
      case 'web.show': {
        // steps.mjs names the file (file://); it is shown through the cockpit's
        // server (http://localhost:<port>/shots/...), never as a /Users/... path.
        if (!/^file:/.test(a.url)) throw new Error('web.show is for local captured screens (a file:// address in steps.mjs)');
        if (/^file:/.test(localUrl(a.url))) throw new Error(`web.show: ${path.basename(a.url)} is outside the folders the cockpit serves: it would show a /Users/... path`);
        await this.front('browser');
        if (this.ring?.on) { this.ring.stop(); this.ringParked = true; }
        await parkPointer();
        await B.open(a.url, { settle: a.settle ?? 300 });
        // A captured screen is shown whole: Chrome's image view at the
        // window's 125% zoom cut both sides off (2026-11-10 walkthrough, N04b).
        await B.page.evaluate(() => { if (/^image\//.test(document.contentType) && !document.getElementById('__ck_fit')) { const st = document.createElement('style'); st.id = '__ck_fit'; st.textContent = 'img{max-width:100vw!important;max-height:100vh!important;width:auto!important;height:auto!important;object-fit:contain;cursor:default!important}'; document.head.appendChild(st); } }).catch(() => {});
        // Reaching it by its tab moved the hand: parked again, off the page.
        await parkPointer();
        break;
      }
      // A captured video (e.g. a Bastion session recording), played in the
      // recording browser from a point (a.at seconds), muted. No card around it.
      case 'web.video': {
        await this.front('browser');
        if (this.ring?.on) { this.ring.stop(); this.ringParked = true; }
        await parkPointer();
        await B.open(a.url, { settle: 600 });
        await B.page.evaluate(async (at) => { const v = document.querySelector('video'); if (!v) throw new Error('no video on the page'); v.muted = true; v.currentTime = at || 0; await v.play(); }, a.at || 0);
        break;
      }
      // The v24 map (the only explanatory visual, 2026-11-07): fly to a stop or
      // tile (window.__mapFocus). The first open runs with the camera off; the
      // fly itself is on camera, and the line starts when it has landed.
      case 'map.focus': {
        const base = mapV24().split('?')[0];
        const onMap = c.front === 'browser' && B.page && !B.page.isClosed() && B.page.url().split('?')[0] === base && this.onStage().ok;
        if (!onMap) {
          const rolling = this.unattended && this.rec.piece && !this.rec.paused;
          if (rolling) await this.rec.pause().catch(() => {});
          const k = await clearNotifications(); if (k > 0) this.log(`stage: ${k} notification(s) closed`);
          await this.front('browser');
          await B.open(mapV24(), { settle: 300 });
          await B.page.waitForFunction(() => typeof window.__mapFocus === 'function', null, { timeout: 15000 });
          await sleep(1100);
          // A freshly opened map starts on the whole drawing, far too small to
          // read, and only then flies to its overview (2026-11-11 clips: the
          // closing map of N01 and N02). The camera rolls once the normal
          // overview has landed; the fly to the target starts from there.
          await B.page.evaluate(() => window.__mapFocus('overview')).catch((e) => this.log(`[${s.id}] map overview: ${e.message.split('\n')[0]}`));
          if (rolling || unattendedNow(this)) await this.safeResume();
        }
        // No pointer or cursor ring on the map: both parked off screen until
        // the next action that is not a map move.
        if (this.ring?.on) { this.ring.stop(); this.ringParked = true; }
        await parkPointer();
        const r = await B.page.evaluate((t) => window.__mapFocus(t), a.target);
        this.log(`[${s.id}] map: ${r}`);
        break;
      }
      // A label on the page ("PREVIEW · ..."), so a stand-in is never taken
      // for the real thing. banner.previewOnly: only in --preview.
      case 'banner': case 'banner.previewOnly': {
        if (a.do === 'banner.previewOnly' && !this.preview) break;
        const page = a.ctx === 'private' ? (this.privPage || this.browser.priv?.page) : (a.ctx === 'staff' ? this.staffBrowser : a.ctx === 'aws' ? this.awsBrowser : this.browser).page;
        await this.banner(this.val(a.text), page);
        break;
      }
      // The lab guide stop's tabs (bridge openStop, readiness/lab-guide/stops.json).
      case 'code.stop': {
        await this.front('code');
        const r = await V.call('openStop', { stop: a.stop });
        await V.call('command', { id: 'workbench.action.closeSidebar' }).catch(() => {});
        this.log(`[${s.id}] lab guide stop ${r?.n} (${r?.stop}): ${r?.files?.length} tab(s)`);
        break;
      }
      case 'code.command': await this.front('code'); await V.call('command', { id: a.id, args: a.args || [] }); break;
      // The repo tree: the Explorer, each folder revealed in turn.
      case 'code.tree': {
        await this.front('code');
        await V.call('command', { id: 'workbench.view.explorer' });
        await V.call('command', { id: 'workbench.files.action.collapseExplorerFolders' }).catch(() => {});
        if (unattendedNow(this)) await this.safeResume();
        for (const f of a.reveal || []) { await V.call('command', { id: 'revealInExplorer', args: [path.join(a.folder, f)] }); await sleep(a.every ?? 2200); }
        break;
      }
      // A read-only check in VS Code's terminal (bridge 0.1.16 runCheck: only
      // the checks the bridge itself lists). The camera is off while it runs
      // and rolls on its result.
      case 'code.check': {
        await this.front('code');
        const r = await V.call('runCheck', { check: a.check });
        const end = Date.now() + (a.timeout ?? 420000);
        let done = null;
        while (!done && Date.now() < end) { await sleep(3000); done = await V.call('checkStatus', { check: a.check }).then((x) => (x.done ? x : null)).catch(() => null); }
        if (!done) throw new Error(`the ${a.check} check did not finish in ${Math.round((a.timeout ?? 420000) / 60000)} minutes`);
        this.log(`[${s.id}] ${a.check} check finished (exit ${done.exit}, terminal ${r?.terminal || '?'})`);
        break;
      }
      // The Contoso HR form (PR #224): opened in the recording browser; the
      // cockpit starts it from its read-only checkout when it is not running.
      case 'hr.open': {
        await this.hrFormUp();
        await this.front('browser');
        await B.open('http://127.0.0.1:8484/', { settle: 2500 });
        await B.find({ text: 'Hire a worker', exact: true }, { timeout: 15000 });
        break;
      }
      case 'hr.fill': {
        const h = c.hire;
        if (!h) throw new Error('no hire set for this run');
        await this.hrSafeToHire();
        await B.type({ css: 'form#hire input[name=givenName]' }, h.first, { clear: true });
        await B.type({ css: 'form#hire input[name=surname]' }, h.last, { clear: true });
        for (const [name, value] of [['dept', h.dept], ['jobTitle', h.job]]) {
          const f = await B.pointAt({ css: `form#hire select[name=${name}]` });
          await f.el.selectOption({ label: value }, { timeout: 10000 });
          await sleep(900);
        }
        const mgr = await B.page.locator('form#hire select[name=manager]').evaluate((e) => e.options[e.selectedIndex]?.text || '').catch(() => '');
        this.log(`[${s.id}] HR form: ${h.first} ${h.last}, ${h.dept}, ${h.job}; manager filled in: ${mgr || '(none)'}`);
        break;
      }
      case 'hr.hire': {
        const h = c.hire;
        await this.hrSafeToHire();
        const before = Date.now();
        await B.click({ css: 'form#hire button[type=submit]' });
        const line = B.page.locator('#statusText p').first();
        await line.waitFor({ timeout: 60000 });
        const txt = await line.innerText();
        const m = /Employee number (\d{6})/.exec(txt);
        if (!m || !txt.includes(`${h.first} ${h.last}`)) throw new Error(`the HR form did not confirm the hire: "${txt.slice(0, 120)}"`);
        c.hireId = m[1]; c.hrPushedAt = before;
        c.hrSha = await this.hrCommitFor(new RegExp(`^HR: hire ${h.first} ${h.last}\\b`), before);
        fs.writeFileSync(path.join(this.root, '.state', 'v2-hire.json'), JSON.stringify({ at: new Date().toISOString(), hireId: c.hireId, name: h.name, upn: `${h.first}.${h.last}@contosohealthlab.com`.toLowerCase(), sha: c.hrSha, preview: this.preview }, null, 1), { mode: 0o600 });
        this.log(`[${s.id}] hired ${h.name}: employee number ${c.hireId}, commit ${c.hrSha.slice(0, 7)} on hr-feed`);
        break;
      }
      case 'hr.leave': {
        const h = c.hire;
        if (!c.hireId) throw new Error('no hire in this run to make a leaver');
        const row = B.page.locator('#rows tr').filter({ has: B.page.locator('td', { hasText: new RegExp(`^${c.hireId}$`) }) }).first();
        await row.waitFor({ timeout: 20000 });
        await B.click({ css: `#rows tr:has(td:text-is("${c.hireId}")) button` });
        await sleep(1200);
        const st = await B.pointAt({ css: 'dialog#edit select[name=status]' });
        await st.el.selectOption('leaver'); await sleep(1200);
        await B.pointAt({ css: 'dialog#edit input[name=endDate]' }); await sleep(1200);
        const before = Date.now();
        await B.click({ css: 'dialog#edit button[value=save]' });
        const line = B.page.locator('#statusText p').first();
        await B.page.waitForFunction((n) => /^Leaver recorded for/.test(document.querySelector('#statusText p')?.textContent || '') && document.querySelector('#statusText p').textContent.includes(n), `${h.first} ${h.last}`, { timeout: 60000 });
        this.log(`[${s.id}] HR form: ${(await line.innerText()).slice(0, 120)}`);
        c.hrPushedAt = before;
        c.hrSha = await this.hrCommitFor(new RegExp(`${h.first} ${h.last}`), before);
        break;
      }
      // AWS facts read as the lab operator, shown on a card: the preview
      // borrows no AWS admin role (that is a PIM activation, a lab change).
      case 'card.aws': {
        let spec;
        if (a.what === 'hireStatus') {
          const u = await this.needSam(); const x = await L.awsUser(u.upn);
          spec = { kicker: 'PREVIEW · AWS IAM Identity Center, read now as the lab operator', title: `${u.upn}: ${x ? x.status : 'removed'}`, sub: 'In the take this is the AWS console, as adm-labops (LabAdministrator borrowed through PIM).' };
        } else if (a.what === 'idc') {
          spec = { kicker: 'PREVIEW · AWS IAM Identity Center (stand-in card)', title: 'Identity source: External identity provider, Microsoft Entra ID', sub: 'Users arrive from Entra by SCIM. In the take this is the console Settings page, as adm-labops.' };
        } else {
          const ps = await L.awsPermissionSets().catch(() => []);
          spec = { kicker: 'PREVIEW · AWS permission sets, read now as the lab operator', title: 'ViewOnlyAccess: read-only', chips: ps.length ? ps : ['ViewOnlyAccess'], sub: 'In the take this is the console Permission sets page, as adm-labops.' };
        }
        await this.front('browser');
        await B.open(cardUrlFor(spec), { settle: 900 });
        break;
      }
      // One job of the newest run of a workflow on main (read only).
      case 'gh.openJob': {
        const url = await this.jobUrl(a);
        await this.front('browser');
        try { await B.open(url, { settle: 5000, onHuman: this.humanNavHook() }); } finally { this.navHuman = false; }
        break;
      }
      // A pull request's plan comment (read only).
      case 'gh.planComment': {
        const r = await L.prChecks(a.pr).catch(() => ({}));
        await this.front('browser');
        await B.open(r.planUrl || `${GH}/pull/${a.pr}`, { settle: 5000 });
        break;
      }
      // PENDING BUILD: the step's screens do not exist yet.
      case 'todo': throw new Error(`PENDING BUILD: ${a.what}`);
      case 'pause': await sleep(a.ms || 1000); break;
      default: throw new Error(`unknown action ${a.do}`);
    }
    this.report(s, a, 'DONE', describe(a, this));
  }

  async priv() {
    const p = await this.browser.privateWindow();
    const pb = Object.create(this.browser);
    // Sam's window in pieces 4-5; Ava's own window after 6-signin.
    pb.page = this.privPage && !this.privPage.isClosed() ? this.privPage : p.page;
    // Its own window's process, for the real pointer's window checks.
    pb.pid = () => p.pid;
    pb.open = async (url, o) => { await p.page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 }); await sleep(o?.settle ?? 2500); };
    return pb;
  }

  // The pull request: on camera through GitHub's "compare" page and its
  // Create button; with gh when the recording browser isn't signed in.
  async createPr(a) {
    const c = this.c;
    if (a.branch !== c.bpBranch) throw new Error(`refusing a PR from ${a.branch}`);
    const existing = await L.prForBranch(a.branch);
    if (existing && existing.state === 'OPEN') { c.pr = existing; this.log(`PR #${existing.number} already open`); }
    else {
      await this.front('browser');
      const url = `${GH}/compare/main...${encodeURIComponent(a.branch).replace(/%2F/g, '/')}?expand=1&title=${encodeURIComponent(a.title)}&body=${encodeURIComponent(a.body)}`;
      const need = await this.browser.open(url, { settle: 3000 });
      if (!need) {
        await this.browser.click({ role: 'button', name: 'Create pull request', exact: true });
        await this.browser.page.waitForURL(/\/pull\/\d+/, { timeout: 30000 });
      } else {
        this.log(`recording browser not signed in to GitHub: creating the PR with gh`);
        await L.gh(['pr', 'create', '-R', L.REPO, '--base', 'main', '--head', a.branch, '--title', a.title, '--body', a.body]);
      }
      c.pr = await L.prForBranch(a.branch);
      if (!c.pr) throw new Error('the pull request did not appear');
    }
    this.log(`PR #${c.pr.number}: ${c.pr.url}`);
    if (this.mode === 'preview') this.savePreviewState();
    const need = await this.browser.open(c.pr.url, { settle: 2500 });
    if (need) this.log(`(the PR page needs the GitHub sign-in in the recording browser)`);
  }

  // Merge: LIVE mode only, only the live branch's own PR. Never in a rehearsal.
  async merge() {
    const c = this.c;
    if (this.mode !== 'live' && this.mode !== 'preview') throw new Error('merging happens only in live mode (and in --preview, on its own copy)');
    if (!c.pr) throw new Error('no pull request');
    const v = await L.ghJson(['pr', 'view', String(c.pr.number), '-R', L.REPO, '--json', 'headRefName,baseRefName,state']);
    if (v.headRefName !== c.bpBranch || v.baseRefName !== 'main' || v.state !== 'OPEN') throw new Error(`PR #${c.pr.number} is not the open live change (${v.headRefName} -> ${v.baseRefName}, ${v.state})`);
    await this.front('browser');
    const need = await this.browser.open(c.pr.url, { settle: 2500 });
    let viaWeb = false;
    if (!need) {
      try {
        await this.browser.click({ role: 'button', name: /^(Squash and merge|Merge pull request|Rebase and merge)$/ });
        await sleep(1200);
        await this.browser.click({ role: 'button', name: /^Confirm (squash and merge|merge|rebase and merge)$/ });
        viaWeb = true;
      } catch (e) { this.log(`merge button: ${e.message.split('\n')[0]}: merging with gh`); }
    }
    if (!viaWeb) {
      await sleep(3000);
      const st = await L.ghJson(['pr', 'view', String(c.pr.number), '-R', L.REPO, '--json', 'state']);
      if (st.state === 'OPEN') await L.gh(['pr', 'merge', String(c.pr.number), '-R', L.REPO, '--squash']);
    }
    for (let k = 0; k < 20 && !c.mergeSha; k++) { await sleep(1500); await this.findMerge(); }
    this.log(`merged: ${c.mergeSha?.slice(0, 7) || '(merge commit not seen yet)'}`);
    if (this.mode === 'preview') this.savePreviewState();
  }

  async runWorkflow(wf) {
    if (wf !== 'evidence-pack.yml') throw new Error(`not a workflow the cockpit runs: ${wf}`);
    this.c.evStarted = Date.now();
    await this.front('browser');
    const need = await this.browser.open(`${GH}/actions/workflows/${wf}`, { settle: 3000 });
    let viaWeb = false;
    if (!need) {
      try {
        await this.browser.click({ re: '^Run workflow$', nth: 0 });
        await sleep(1500);
        await this.browser.click({ css: 'details[open] button.btn-primary, form button[type=submit].btn-primary, [role=dialog] button[type=submit]' });
        viaWeb = true;
      } catch (e) { this.log(`Run workflow button: ${e.message.split('\n')[0]}: starting it with gh`); }
    }
    if (!viaWeb) await L.gh(['workflow', 'run', wf, '-R', L.REPO, '--ref', 'main']);
  }

  // Sign in AS a demo person with a one-time Temporary Access Pass, in a
  // clean separate window. The pass is issued by the lab operator, kept only
  // in this process's memory, typed into Microsoft's box and dropped: never
  // shown, logged, or put on a command line. Only Sam (found by his
  // employeeId) and Ava's admin account are allowed.
  async tapSignin(who, url) {
    const upn = who === 'sam' ? (await this.needSam()).upn : TAP_USERS[who];
    if (!upn || !/@contosohealthlab\.(com|onmicrosoft\.com)$/i.test(upn) || /^michaelwilliams@/i.test(upn)) throw new Error(`no one-time pass for ${who}`);
    let pass = await issueTap(upn);
    if (who === 'sam') this.c.tapAt = Date.now();
    try {
      const p = await this.priv();
      await p.open(url, { settle: 4000 });
      // Sign-in pages: Playwright typing only (never real keys there).
      await p.type({ css: 'input[name=loginfmt]' }, upn, { delay: 45, synthetic: true });
      await p.click({ css: 'input[type=submit]' });
      await sleep(4000);
      const box = 'input[name=accesspass], input#accesspass, input[name=passwd]';
      await p.find({ css: box }, { timeout: 20000 });
      await p.pointAt({ css: box });
      await p.page.locator(box).first().click();
      for (const ch of pass) { await p.page.keyboard.type(ch); await sleep(40 + Math.random() * 60); }
      pass = null;
      await sleep(400);
      await p.click({ css: 'input[type=submit]' });
      // "Stay signed in?" after the pass (seen on camera in piece 4): Yes.
      for (let k = 0; k < 8; k++) {
        await sleep(1000);
        const t = await p.page.locator('body').innerText().catch(() => '');
        if (/Stay signed in\?/.test(t)) { await p.page.locator('input[type=submit][value=Yes], #idSIButton9').first().click({ timeout: 5000 }).catch(() => {}); break; }
        if (!/login\.microsoftonline\.com/.test(p.page.url())) break;
      }
    } finally { pass = null; }
    this.log(`signed in as ${who} with a one-time pass (not shown)`);
  }

  // A staff member's real Entra sign-in landing in an app, through My Apps,
  // with slice 1's staff sign-in toolkit (password + authenticator code from
  // the Keychain, answered on Entra's own pages; lab/scripts/demo/signin).
  // Only the lab's test users: never the owner, never a real person.
  async staffSignin(upn, app = 'ServiceNow') {
    if (!/^test-user-[a-z]@contosohealthlab\.com$/i.test(upn)) throw new Error(`staff sign-in is only for the lab's test users, not ${upn}`);
    const T = await signinTool(this.root).catch(() => null);
    if (T && upn.toLowerCase().startsWith(`${STAFF.id}@`)) return this.staffViaWindow(T, app);
    const candidates = [`${L.LAB}/lab/scripts/demo/signin/signin.mjs`, `${HOME}/lab-wt-signin/lab/scripts/demo/signin/signin.mjs`];
    const mod = candidates.find((f) => fs.existsSync(f));
    if (!mod) throw new Error('the staff sign-in toolkit (lab/scripts/demo/signin) is not on this Mac');
    const { signIn } = await import(mod);
    const pw = await this.browser.privateWindow();
    const r = await signIn(upn, 'https://myapps.microsoft.com/?tenantId=86a2e327-4951-4348-a3c4-6f4b79ffd8f2', {
      browser: pw.browser, until: async (p) => /myapps\.microsoft\.com|myapplications\.microsoft\.com/.test(p.url()) && (await p.getByText(app, { exact: true }).count().catch(() => 0)) > 0,
      contextOptions: { viewport: null }, timeoutMs: 150000,
    });
    this.staff = r;
    // The toolkit made its own browser context: give it the cockpit's
    // on-screen highlight too (this page now, the app's tab when it opens).
    await r.context.addInitScript(OVERLAY);
    await r.page.evaluate(OVERLAY).catch(() => {});
    const sb = Object.create(this.browser); sb.page = r.page;
    await r.page.bringToFront();
    await sb.highlight({ text: app, exact: true }, 'One tile per app he or she may use').catch(() => {});
    await sleep(1500);
    const [appPage] = await Promise.all([r.context.waitForEvent('page', { timeout: 60000 }), sb.click({ text: app, exact: true })]);
    await appPage.waitForURL(/service-now\.com/, { timeout: 90000 });
    await appPage.waitForLoadState('domcontentloaded').catch(() => {});
    await sleep(6000);
    const ab = Object.create(this.browser); ab.page = appPage;
    await appPage.bringToFront();
    // ServiceNow shows the person as an avatar (initials) whose label carries
    // the name; the shadow DOM is pierced by Playwright's CSS engine.
    await ab.highlight({ css: '[aria-label*="Test User" i], [title*="Test User" i]' }, 'Test User A: signed in with the hospital login')
      .catch(() => ab.highlight({ re: 'Test User [A-Z]' }, 'Signed in with the hospital login'))
      .catch((e) => this.log(`staff view: ${e.message}`));
    this.log(`staff sign-in: ${upn} reached ${app} through My Apps`);
  }

  // Web Teams only, as test-user-a in the Contoso tenant (review 1 / the
  // lead): the desktop app quit; before, the staff window's Microsoft account
  // must be test-user-a; after, the page must be Contoso's Identity-SecOps
  // channel in web Teams and nothing from another organisation.
  async teamsGuard(a) {
    await new Promise((r) => execFile('osascript', ['-e', 'if application "Microsoft Teams" is running then quit app "Microsoft Teams"'], () => r()));
    const SB = this.staffBrowser;
    if (a.phase === 'before') {
      const who = await entraAccount(SB.ctx);
      if (who !== 'test-user-a@contosohealthlab.com') throw new Error(`Teams: the staff window is signed in as ${who || 'nobody'}, not test-user-a@contosohealthlab.com: step stopped`);
      return;
    }
    // Web Teams names the open channel in its title ("... | Contoso SOC |
    // Identity-SecOps | Microsoft Teams"); Chrome's "Open Microsoft Teams?"
    // prompt is a window of its own, which must not be there.
    let title = '';
    for (let k = 0; k < 15; k++) { title = await SB.page.title().catch(() => ''); if (/Contoso SOC \| Identity-SecOps/.test(title)) break; await sleep(2000); }
    const prompt = windows().some((w) => w.pid === SB.pid() && /Open Microsoft Teams\?/.test(w.title));
    const body = await SB.page.locator('body').innerText().catch(() => '');
    const host = new URL(SB.page.url()).host;
    if (prompt || !/Contoso SOC \| Identity-SecOps/.test(title) || OTHER_ORG.test(body) || !/^teams\.(cloud\.microsoft|microsoft\.com)$/.test(host)) {
      throw new Error(`Teams: not Contoso SOC / Identity-SecOps in web Teams (title "${title}"${prompt ? ', desktop-app prompt up' : ''}): step stopped, nothing else shown`);
    }
  }


  // ---- --preview: the presenter's hand steps, done by the cockpit -------------------
  // Each is labelled on screen ("PREVIEW · ...") so nobody mistakes it for
  // the presenter's own hand.
  async banner(text, page = this.browser.page) { await page?.evaluate((t) => window.__ck && window.__ck.banner(t), text).catch(() => {}); }

  // "approve" on the apply gate, as the delegated reviewer, in the merge
  // captain's note format. Fails closed if the plan touches Conditional
  // Access or the issue isn't this preview's gate.
  async previewApprove() {
    // 2026-11-07 rule (coordinator): the cockpit never types an approval, in
    // preview mode or otherwise. Only the owner approves.
    throw new Error('the cockpit never approves: only the owner types the approval');
    if (this.mode !== 'preview') throw new Error('only --preview approves for the presenter');
    const c = this.c;
    if (!c.issue || !c.mergeSha) throw new Error('no approval request from this preview');
    const iss = await L.ghJson(['issue', 'view', String(c.issue.number), '-R', L.REPO, '--json', 'title,state']);
    if (iss.title !== `Approve: apply ${c.mergeSha.slice(0, 7)} to prod` || iss.state !== 'OPEN') throw new Error(`issue #${c.issue.number} is not this preview's open gate`);
    const comments = await L.ghJson(['api', `repos/${L.REPO}/issues/${c.pr.number}/comments?per_page=100`]);
    const plan = comments.find((x) => x.user?.login === 'github-actions[bot]' && (x.body || '').startsWith('## Terraform plan'));
    if (!plan) throw new Error('no plan comment to review');
    const summary = plan.body.split('<details>')[0];
    if (/conditional access/i.test(summary)) throw new Error('the plan touches Conditional Access: the preview does not approve that, a person does');
    const head = ((/\*\*What this change does:\*\*\s*([^\n]+)/.exec(summary) || [])[1] || '').trim().replace(/\.$/, '');
    const bullets = summary.split('\n').filter((l) => /^- /.test(l)).map((l) => l.slice(2).replace(/\*\*/g, '').trim());
    const note = `approve — reviewed by Claude for @ChromeData (delegated, recording preview): #${c.pr.number} ${head}: ${bullets.join('; ')}. No Conditional Access change. The cockpit reverts it after the preview through a reviewed revert PR.`;
    await this.front('browser');
    await this.banner('PREVIEW · the cockpit approves for you, as the delegated reviewer');
    try {
      await this.browser.type({ css: 'textarea' }, note, { delay: 12 });
      await this.browser.click({ role: 'button', name: /^Comment$/ });
    } catch (e) {
      this.log(`preview: typing in the issue failed (${e.message.split('\n')[0]}): commenting with gh`);
      await L.gh(['issue', 'comment', String(c.issue.number), '-R', L.REPO, '--body', note]);
    }
    this.log(`preview: approved gate #${c.issue.number} as the delegated reviewer`);
  }

  // Contain on the drill card: only when the waiting card is the drill's
  // (drillPending checked it is an itdr-drill-* cloud-only account).
  async previewContain() {
    if (this.mode !== 'preview') throw new Error('only --preview presses Contain for the presenter');
    const r = await this.check('drillPending');
    if (r.state !== 'ready' || !this.c.drill || !/^itdr-drill-/i.test(this.c.drill.upn)) throw new Error(`no drill card to answer (${r.text})`);
    // Teams is in test-user-a's staff window (a listed containment approver).
    await this.banner('PREVIEW · the cockpit presses Contain for you (drill account only)', this.staffBrowser.page);
    const SB = this.staffBrowser, n = this.c.drill.incident, page = SB.page;
    // Preview 2 review, piece 7: the card's buttons sat below the visible part
    // of the posts pane and were never pressed. The lab's own card answerer
    // (answer-teams-card.mjs) method: the newest card for THIS incident that
    // still has the button; the button is tagged in the page and clicked only
    // through that tag (a re-render drops the tag: the click then fails rather
    // than hit another card), after scrolling it into view.
    const want = 'Contain (revoke + disable)', title = 'ITDR containment approval - Sentinel incident #', tag = `ck-${Date.now()}`;
    const pick = () => page.locator('button').evaluateAll((bs, { want, title, n, tag }) => {
      const esc = title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const mine = new RegExp(`${esc}${n}(?!\\d)`);
      let last = null;
      for (const b of bs) {
        b.removeAttribute('data-ck-contain');
        if ((b.innerText || '').trim() !== want) continue;
        for (let e = b.parentElement; e; e = e.parentElement) {
          const t = e.innerText || '';
          if (!t.includes(title)) continue;
          if (t.split(title).length === 2 && mine.test(t)) last = b;
          break;
        }
      }
      if (last) last.setAttribute('data-ck-contain', tag);
      return !!last;
    }, { want, title, n, tag });
    let ok = false;
    for (let i = 0; i < 20 && !ok; i++) { ok = await pick().catch(() => false); if (!ok) await sleep(2000); }
    if (!ok) throw new Error(`the Contain button on the card for incident #${n} is not on the page`);
    const btn = page.locator(`button[data-ck-contain="${tag}"]`);
    await btn.scrollIntoViewIfNeeded({ timeout: 10000 });
    await sleep(800);
    // Still not inside the window: Teams at 80% for this tab, then again.
    const inView = async () => { const bb = await btn.boundingBox().catch(() => null); const vh = await page.evaluate(() => window.innerHeight); return bb && bb.y >= 0 && bb.y + bb.height <= vh ? bb : null; };
    let bb = await inView();
    if (!bb) { await page.evaluate(() => { document.body.style.zoom = '0.8'; }); await sleep(1500); await btn.scrollIntoViewIfNeeded({ timeout: 10000 }).catch(() => {}); bb = await inView(); }
    if (!bb) throw new Error(`the Contain button on the card for incident #${n} is still outside the window`);
    if (!(await pick())) throw new Error(`the card for incident #${n} changed before the click`);
    // The real pointer goes to the button (the drawn one with --mouse dom).
    let realAt = null;
    if (SB.H && page === SB.page) {
      try { const sp = await SB.toScreen({ x: bb.x + 20, y: bb.y + bb.height / 2 }); await SB.H.move(sp.x, sp.y, { w: bb.height * sp.z }); realAt = sp; }
      catch (e) { this.log(`pointer: real move to Contain not possible (${e.message})`); }
    }
    if (!realAt) { await SB.ov('cursor', bb.x + 20, bb.y + bb.height / 2); await sleep(700); await SB.ov('ripple', bb.x + 20, bb.y + bb.height / 2); }
    const recorded = async () => ((await page.locator('body').innerText().catch(() => '')).match(/Decision recorded/g) || []).length;
    const before = await recorded();
    // Mark this card's message (a few levels above the card, which Teams
    // rewrites in place) so 7-contained shows THIS card's decision, never an
    // older one (preview 2 scrolled to a 9:42 PM card).
    const mark = `ck-${Date.now()}`;
    await btn.evaluate((b, { title, mark }) => {
      let card = b; while (card && !((card.innerText || '').includes(title))) card = card.parentElement;
      let m = card; for (let k = 0; k < 3 && m && m.parentElement; k++) m = m.parentElement;
      if (m) m.setAttribute('data-ck-decided', mark);
    }, { title, mark }).catch(() => {});
    this.c.drill.cardMark = mark;
    if (realAt) {
      try { await SB.H.click(undefined, undefined, { pid: SB.pid() }); SB.ov('ripple', bb.x + 20, bb.y + bb.height / 2); }
      catch (e) { this.log(`pointer: real click on Contain not possible (${e.message}): Playwright click`); await btn.click({ timeout: 10000 }); }
    } else await btn.click({ timeout: 10000 });
    this.c.drill.containClickedAt = Date.now();
    let updated = false;
    for (let i = 0; i < 30 && !updated; i++) { await sleep(2000); updated = (await recorded()) > before; }
    this.c.drill.cardUpdated = updated;
    this.log(`preview: pressed Contain on the card for ${this.c.drill.upn}`);
  }

  // Sam's second-check setup in his own window: answers Microsoft's
  // "more information required" pages the way a new hire would, when they
  // show up. Best effort, logged step by step.
  async previewSecondCheck() {
    if (this.mode !== 'preview') throw new Error('only --preview does Sam\'s setup for the presenter');
    const p = await this.priv();
    await this.banner('PREVIEW · the cockpit answers Sam\'s second-check prompt for you', p.page);
    const txt = await p.page.locator('body').innerText().catch(() => '');
    if (!/More information required|Keep your account secure|security info|Set up your account/i.test(txt)) { this.log('preview: Sam was not asked to set up a second check (his one-time pass already counts as one)'); return; }
    for (const name of [/^Next$/, /^Ask later$/, /^Skip setup$/, /^Done$/]) {
      const b = p.page.getByRole('button', { name }).first();
      if (await b.isVisible().catch(() => false)) { await p.click({ role: 'button', name }); await sleep(2500); }
    }
    this.log('preview: answered Sam\'s second-check pages');
  }

  // The staff view in test-user-a's own window (already signed in by
  // autoSignIn, kept signed in): My Apps, the app's tile, the app.
  async staffViaWindow(T, app) {
    const SB = this.staffBrowser;
    if (!SB.up) await SB.launch();
    await this.front('staff');
    await SB.open(STAFF.url, { settle: 4000 });
    if (await SB.signinNeeded()) await T.signIn(STAFF.id, STAFF.url, { context: SB.ctx, page: SB.page });
    await SB.highlight({ text: app, exact: true }, 'One tile per app she may use');
    await sleep(1500);
    const [appPage] = await Promise.all([SB.ctx.waitForEvent('page', { timeout: 60000 }), SB.click({ text: app, exact: true })]);
    await appPage.waitForURL(/service-now\.com/, { timeout: 90000 });
    await sleep(6000);
    const ab = Object.create(SB); ab.page = appPage;
    await appPage.bringToFront();
    await ab.highlight({ css: '[aria-label*="Test User" i], [title*="Test User" i]' }, 'Test User A: signed in with the hospital login')
      .catch(() => ab.highlight({ re: 'Test User [A-Z]' }, 'Signed in with the hospital login'))
      .catch((e) => this.log(`staff view: ${e.message}`));
    this.log(`staff view: ${STAFF.id} reached ${app} from My Apps in her own window`);
  }

  // ---- retake ---------------------------------------------------------------------
  async retake() {
    if (this.busy || this.i < 0) return;
    const piece = this.list[this.i].piece;
    if (!this.confirm('retake')) return;
    this.stopPoll(); this.busy = true; this.setLight('blue', `Retake piece ${piece}: resetting…`);
    try {
      await this.rec.discardPiece();
      const wait = await this.resetPiece(this.pieces.find((p) => p.n === piece));
      const first = this.list.findIndex((x) => x.piece === (wait?.piece || piece));
      this.i = first - 1; this.error = null; this.c.sw = null;
      await this.browser.stopStopwatch().catch(() => {});
      this.busy = false;
      if (wait?.check) this.startWait({ piece: wait.piece || piece, wait: { check: wait.check, waiting: wait.waiting, ready: wait.ready } });
      else this.setLight('green', `Piece ${piece} reset: press NEXT to take it again`);
    } catch (e) {
      this.busy = false; this.error = `Retake reset failed: ${e.message}`; this.setLight('red', 'Retake needs a hand: see below');
    }
  }

  // The sites each piece opens, checked (and signed in again through the
  // sign-in toolkit) before the piece starts, off camera. Entra, Azure and
  // Defender share adm-presenter's session; ServiceNow is the recovery
  // account; the staff window is test-user-a; Splunk its local admin.
  async freshSessions(n) {
    // --watch (a dry autopilot that records) keeps its sessions fresh too.
    if ((this.mode === 'dry' && !this.watch) || this.mode === 'rehearse') return;
    const T = await signinTool(this.root).catch(() => null);
    if (!T || !this.browser?.up) return;
    // v2: the part's listed sessions plus the sites its own steps open.
    const SESSION_OF = { Entra: 'entra', 'Azure portal': 'entra', Defender: 'entra', ServiceNow: 'snow', 'My Apps': 'staff', Teams: 'teams', Splunk: 'splunk' };
    const uses = this.v2 ? [...new Set([...(this.pieces.find((p) => p.n === n)?.sessions || []), ...[...this.siteNeeds(this.list.filter((x) => x.piece === n))].map((x) => SESSION_OF[x]).filter(Boolean)])] : { 1: ['entra'], 2: ['entra'], 3: ['entra'], 4: ['entra', 'snow', 'staff'], 5: ['entra'], 6: [], 7: ['entra', 'staff', 'teams'], 8: ['splunk'], 9: ['entra'], 10: ['entra'], 11: ['entra'] }[n] || [];
    const probe = async (ctx, url, re) => {
      const pg = await ctx.newPage();
      try { await pg.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 }); await sleep(5000); return re.test(pg.url()); }
      finally { await pg.close().catch(() => {}); }
    };
    for (const u of uses) {
      try {
        if (u === 'splunk') {
          if (await probe(this.browser.ctx, SPLUNK.url, /\/account\/login/)) { const r = await T.signIn(SPLUNK.id, SPLUNK.url, { context: this.browser.ctx }); await r.close?.(); this.log('sessions: Splunk had signed out: splunk-admin signed in again'); }
          else this.log('sessions: Splunk ok');
        } else if (u === 'snow') {
          const who = await snowUser(this.browser.ctx);
          if (who && who !== 'acr.breakglass') throw new Error(`the ServiceNow session belongs to ${who}`);
          if (!who) { const pg = await this.browser.ctx.newPage(); try { await signInRecovery(pg, { log: this.log }); } finally { await pg.close().catch(() => {}); } this.log('sessions: ServiceNow had signed out: recovery account signed in again'); }
          else this.log('sessions: ServiceNow ok');
        } else if (u === 'entra') {
          if (await probe(this.browser.ctx, PRESENTER.url, /login\.microsoftonline\.com/)) { const r = await T.signIn(PRESENTER.id, PRESENTER.url, { context: this.browser.ctx }); await r.close?.(); this.log('sessions: adm-presenter signed in again'); }
          else this.log('sessions: Entra ok');
        } else if (u === 'teams' && this.staffBrowser?.up) {
          await this.teamsGuard({ phase: 'before' }); this.log('sessions: Teams window is test-user-a (checked off camera)');
        } else if (u === 'staff' && this.staffBrowser?.up) {
          if (await probe(this.staffBrowser.ctx, STAFF.url, /login\.microsoftonline\.com/)) { const r = await T.signIn(STAFF.id, STAFF.url, { context: this.staffBrowser.ctx }); await r.close?.(); this.log('sessions: test-user-a signed in again'); }
          else this.log('sessions: staff window ok');
        }
      } catch (e) { this.log(`sessions: ${u}: ${e.message.split('\n')[0]}`); }
    }
    // The probes' tabs are closed; each window keeps the one tab the steps drive.
    for (const W of [this.browser, this.staffBrowser]) if (W?.up) for (const pg of W.ctx.pages()) if (pg !== W.page && pg !== W.mapPage() && ![...(W.prefetched?.values() || [])].some((e) => e.page === pg)) await pg.close().catch(() => {});
  }

  // Browser.open's hook when a page is reached by hand: the camera rolls
  // (stage checked by safeResume) and the 6 s cut timer waits.
  humanNavHook() { return this.unattended && (this.rec.piece || this.pendingStart) ? async () => { this.navHuman = true; await this.safeResume(); } : null; }
  // Every VS Code window the run puts on stage (the demo window and any
  // step's code.open window, e.g. the tour's): never minimized.
  stageCodeTitles() {
    const t = new Set([this.code?.title]);
    for (const s of this.list || []) for (const a of [...(s.do || []), ...(s.standIn || [])]) if (a.do === 'code.open' && typeof a.ws === 'string') t.add(new VsCode(a.ws).title);
    return [...t].filter(Boolean);
  }
  // Every other VS Code window minimized (the lead's own, with its chat).
  // Unattended runs (--watch, --preview, --storyboard, proofs) also take a
  // full-screen one out of full screen first (else each VS Code activation
  // switches to its Space: 2026-11-10 walkthrough, N04's sign-in log steps
  // stayed on the wrong window); close() puts it back.
  async clearOthers() {
    const r = await clearCodeWindows(this.stageCodeTitles(), { leaveFullScreen: this.unattended }).catch((e) => ({ error: e.message }));
    if (r.error) { this.log(`stage: other VS Code windows: ${r.error}`); return; }
    if (r.fullScreen.length) (this.unFullScreened ||= []).push(...r.fullScreen);
    this.log(`stage: other VS Code windows: ${r.minimized} minimized${r.fullScreen.length ? ` (${r.fullScreen.length} taken out of full screen first)` : ''}`);
  }
  // --watch: a watchdog while the camera rolls (also during a step's actions,
  // which stageGuard does not cover): anything but the stage in front pauses
  // the camera at once; the next resume (safeResume) puts the stage back.
  startStageWatch(ms = 600) {
    this.stopStageWatch();
    let busy = false;
    this.stageWatchId = setInterval(async () => {
      if (busy) return;
      busy = true;
      try {
        const rolling = !!this.rec?.piece && !this.rec.paused;
        let list = null;
        try { list = windows(); } catch {}
        // The curtain is up (cockpit.mjs watchRun): another app's window on
        // screen (2026-11-11: the Claude app flashed in N01, N02, N04b) pauses
        // the camera at once, rolling or not, and is hidden again.
        if (curtainActive() && list) {
          const f = foreignOnScreen({ ownPids: this.cockpitPids(), list });
          if (f.length) {
            if (rolling) await this.rec.pause().catch(() => {});
            for (const w of f) curtainHide(w.pid, w.owner);
            this.log(`stage watch: ${f.map((w) => w.owner).join(', ')} on screen: ${rolling ? 'camera paused, ' : ''}hidden again`);
            if (rolling && !this.busy) await this.safeResume();
            return;
          }
        }
        if (!rolling) return;
        const st = this.onStage(list);
        // A blank or empty page in front pauses the camera at once; one still
        // loading after ~2 s too. safeResume rolls again once it has loaded.
        if (st.ok) {
          const f = this.frontPage(st.top);
          const ps = f?.page ? await f.B.pageState(f.page) : 'ok';
          this.notReadyTicks = ps === 'loading' ? (this.notReadyTicks || 0) + 1 : 0;
          if (ps === 'blank' || ps === 'empty' || this.notReadyTicks >= 3) {
            this.notReadyTicks = 0;
            if (!this.rec.piece || this.rec.paused) return;
            await this.rec.pause().catch(() => {});
            this.log(`stage watch: the page in front is ${ps} (${String(f.page.url()).slice(0, 80)}): camera paused`);
            if (!this.busy) await this.safeResume();
            return;
          }
        }
        if (!st.ok) {
          await this.rec.pause().catch(() => {});
          this.log(`stage watch: "${st.top?.owner}: ${st.top?.title}" came forward: camera paused`);
          if (st.top?.owner === 'Code') await this.clearOthers();
          if (!this.busy) await this.safeResume();
        }
      } finally { busy = false; }
    }, ms);
  }
  stopStageWatch() { if (this.stageWatchId) clearInterval(this.stageWatchId); this.stageWatchId = null; }

  // Preview 2, piece 10: another app's window (the lead's own VS Code, with
  // its chat) came forward. The stage is the cockpit's Chrome windows and
  // the demo VS Code window, nothing else.
  onStage(list = null) {
    let top;
    try { top = (list || windows()).find((w) => w.layer === 0 && w.w > 400 && w.h > 300); } catch { return { ok: true }; }
    if (!top) return { ok: true };
    const ours = this.cockpitPids().map(Number);
    const ok = ours.includes(+top.pid) || (!!this.code?.title && (top.title || '').endsWith(this.code.title));
    // A Claude window is never on camera, whatever its title says.
    if (/claude/i.test(top.owner || '')) return { ok: false, top };
    return { ok, top };
  }
  // The page the window in front shows (a cockpit Chrome window), or null
  // (VS Code, or not a cockpit window).
  frontPage(top) {
    if (!top?.pid) return null;
    const pid = +top.pid;
    if (this.browser?.priv?.pid && +this.browser.priv.pid === pid) return { B: this.browser, page: this.privPage || this.browser.priv?.page || null };
    for (const B of [this.browser, this.staffBrowser, this.awsBrowser]) if (B?.up && +B.pid() === pid) return { B, page: B.page };
    return null;
  }
  // The camera never rolls on a page that is about:blank, empty or still
  // loading (2026-11-11 clips: N06 about:blank, N17 an "Untitled" GitHub
  // tab): waits for it (20 s at most), false when it never got there.
  async waitFrontReady(top) {
    const f = this.frontPage(top);
    if (!f?.page) return true;
    let st = await f.B.pageState(f.page);
    if (st === 'ok') return true;
    this.log(`stage: the page in front is ${st} (${String(f.page.isClosed() ? '' : f.page.url()).slice(0, 80)}): camera waits for it`);
    st = await f.B.waitReady(f.page, 20000);
    if (st === 'ok') return true;
    this.log(`stage: the page in front is still ${st} after 20 s: camera kept paused`);
    return false;
  }
  // Every unattended camera resume goes through here: the camera rolls only
  // when the stage window is in front; otherwise the stage is put back and
  // checked again (twice), and the step fails rather than film another app.
  async safeResume() {
    if (this.pendingStart) {
      for (let k = 0; k < 3; k++) {
        const st = this.onStage();
        if (st.ok) {
          if (!(await this.waitFrontReady(st.top))) { this.notLoaded = true; this.stageLost = true; return false; }
          const P = this.pendingStart; this.pendingStart = null; await clearNotifications(); await this.rec.startPiece(P).catch((e) => this.log(`recording: could not start (${e.message})`)); return true;
        }
        this.log(`stage: "${st.top?.owner}: ${st.top?.title}" is in front, not the stage: recording not started yet, stage put back (${k + 1})`);
        if (st.top?.owner === 'Code') await this.clearOthers();
        else if (st.top?.pid && curtainActive()) curtainHide(st.top.pid, st.top.owner);
        await this.front(this.c.front || 'browser').catch(() => {});
        await sleep(700);
      }
      this.stageLost = true;
      return false;
    }
    if (!this.rec.piece || !this.rec.paused) return true;
    for (let k = 0; k < 3; k++) {
      const st = this.onStage();
      if (st.ok) {
        if (!(await this.waitFrontReady(st.top))) { this.notLoaded = true; this.stageLost = true; return false; }
        await this.rec.resume().catch(() => {}); return true;
      }
      this.log(`stage: "${st.top?.owner}: ${st.top?.title}" is in front, not the stage: camera stays paused, stage put back (${k + 1})`);
      if (st.top?.owner === 'Code') await this.clearOthers();
      else if (st.top?.pid && curtainActive()) curtainHide(st.top.pid, st.top.owner);
      await this.front(this.c.front || 'browser').catch(() => {});
      await sleep(700);
    }
    this.stageLost = true;
    return false;
  }
  // While a line plays (unattended): anything but the stage coming forward
  // pauses the camera at once; the stage is put back, then it rolls on.
  async stageGuard() {
    if (!this.unattended || !this.rec.piece || this.rec.paused) return true;
    const st = this.onStage();
    if (st.ok) return true;
    await this.rec.pause().catch(() => {});
    this.log(`stage: "${st.top?.owner}: ${st.top?.title}" came forward during a line: camera paused`);
    return this.safeResume();
  }

  // --preview: a piece with a FAILED step is taken again at once, in the same
  // lab state (view-only pieces only): the take is discarded, the piece's
  // reset runs, and the autopilot goes back to its first step.
  async autoRetake(n) {
    this.stopPoll(); this.pendingStart = null;
    await this.rec.discardPiece();
    await this.resetPiece(this.pieces.find((p) => p.n === n)).catch((e) => this.log(`retake ${n}: reset: ${e.message}`));
    if (this.failedSteps) this.failedSteps[n] = [];
    this.timeline = this.timeline.filter((t) => t.piece !== n);
    this.i = this.list.findIndex((x) => x.piece === n) - 1; this.error = null;
    this.log(`preview: piece ${n} taken again (a step had FAILED)`);
  }

  // What "retake" puts back. Returns an optional wait before the piece can restart.
  async resetPiece(p) {
    const c = this.c, dry = this.mode === 'dry';
    const say = (m) => this.log(`retake ${p.n}: ${m}`);
    switch (p.reset) {
      case 'blueprints': {
        if (this.mode === 'rehearse') {
          await closeRehearsal({ branch: c.bpBranch, pr: c.pr, log: this.log }).catch((e) => say(e.message));
          const r = await prepareRehearsal({ root: this.root, liveFolder: path.join(DEMO, 'blueprints'), liveWs: LIVE_WS, log: this.log });
          Object.assign(c, { bp: r.dir, bpBranch: r.branch, pr: null, planUrl: null });
          this.list = this.buildList();
          return null;
        }
        const pr = await L.prForBranch(c.bpBranch);
        if (pr?.state === 'MERGED') throw new Error('piece 1 is merged (live): a retake would need a revert pull request. Record from piece 2 on, or revert by hand first.');
        if (dry) { say(`WOULD close PR ${pr ? '#' + pr.number : '(none)'}, delete origin/${c.bpBranch}, and undo the commit (files stay changed, uncommitted)`); return null; }
        if (pr?.state === 'OPEN') { await L.gh(['pr', 'close', String(pr.number), '-R', L.REPO, '--comment', 'Closed for a retake of the recording.']); say(`closed PR #${pr.number}`); }
        await L.sh('git', ['-C', c.bp, 'push', 'origin', '--delete', c.bpBranch]).then(() => say(`deleted origin/${c.bpBranch}`)).catch(() => {});
        const msg = (await L.sh('git', ['-C', c.bp, 'log', '-1', '--format=%s'])).trim();
        if (msg === "Cloud engineers get AWS, nurses don't") { await L.sh('git', ['-C', c.bp, 'reset', '--soft', 'HEAD~1']); await L.sh('git', ['-C', c.bp, 'reset', '-q']); say('commit undone: the change is uncommitted again'); }
        c.pr = null; c.planUrl = null; c.mergeSha = null; c.issue = null; c.applyRun = null;
        return null;
      }
      case 'hire': case 'leave': {
        const args = [c.hireId || '400104', ...(dry ? [] : ['--apply'])];
        say(`${dry ? 'dry run of' : 'running'} reset-demo-hire.sh ${args.join(' ')}`);
        // Through the lab operator (its DC01 run command must not use this Mac's own az login).
        const out = await L.sh(`${L.LAB}/lab/scripts/operator/op`, [`${L.LAB}/lab/scripts/demo/reset-demo-hire.sh`, ...args], { cwd: L.LAB, timeout: 600000 });
        for (const line of out.trim().split('\n').slice(-8)) say(line);
        if (!dry) {
          await L.sh('git', ['-C', c.hr, 'fetch', '-q', 'origin', 'hr-feed']);
          const local = (await L.sh('git', ['-C', c.hr, 'status', '--porcelain'])).trim();
          if (local && local !== `M ${'lab/scripts/mock-hr/hr_feed.csv'}` && local !== ' M lab/scripts/mock-hr/hr_feed.csv') throw new Error(`the HR folder has other local changes: ${local}`);
          await L.sh('git', ['-C', c.hr, 'checkout', '--', 'lab/scripts/mock-hr/hr_feed.csv']);
          await L.sh('git', ['-C', c.hr, 'merge', '--ff-only', 'origin/hr-feed']).catch(async () => {
            // Only our own unpushed Sam commits may be dropped.
            const mine = (await L.sh('git', ['-C', c.hr, 'log', '--format=%s', 'origin/hr-feed..HEAD'])).trim().split('\n').filter(Boolean);
            if (!mine.every((m) => /^HR: (hire Sam Rivera|Sam Rivera leaves)/.test(m) || (c.hire && m.includes(c.hire.name)))) throw new Error('the HR folder has commits that are not the demo hire: fix by hand');
            await L.sh('git', ['-C', c.hr, 'reset', '--hard', 'origin/hr-feed']);
          });
          say('HR folder is back in step with origin/hr-feed');
        }
        c.sam = null; c.hrSha = null; c.hrRun = null; if (this.v2) c.hireId = null;
        return { piece: 2, check: 'samGone', waiting: 'Waiting for Cloud Sync to remove the old Sam (about 20 minutes)', ready: 'Sam is gone: ready to hire him again' };
      }
      case 'private-window': await this.browser.closePrivate(); return null;
      case 'pim': await this.browser.closePrivate(); say("Ava's role stays active until it ends: deactivate it in My roles, or retake after it ends"); return null;
      default: return null;
    }
  }

  // ---- start screen: preflight + sign-ins ------------------------------------------
  async runPreflight() {
    this.preflight = { running: true, lines: [], ready: null };
    this.emit();
    const out = await new Promise((resolve) => execFile(`${L.LAB}/lab/scripts/demo/preflight.sh`, ['--check'], { cwd: L.LAB, timeout: 300000 }, (e, so, se) => resolve({ code: e ? e.code ?? 1 : 0, text: `${so}${se}` })));
    const clean = out.text.replace(/\x1b\[[0-9;]*m/g, '');
    const lines = clean.split('\n').filter((l) => /^\s+[✓✗!…]/.test(l)).map((l) => ({ mark: l.trim()[0], text: l.trim().slice(1).trim() }));
    const ready = out.code === 0 && /^READY$/m.test(clean);
    // The cockpit's own readiness on top.
    const own = [];
    own.push(this.code.ready ? { mark: '✓', text: 'VS Code demo window is open (bridge on)' } : { mark: '!', text: 'VS Code demo window not open yet (opens on the first step)' });
    // The on-camera change must still merge into main, or GitHub runs no
    // checks on its pull request (found by a rehearsal on 2026-11-05).
    try { own.push(...await liveBranchCheck(path.join(DEMO, 'blueprints'))); } catch (e) { own.push({ mark: '✗', text: `could not check the blueprints branch against main: ${e.message}` }); }
    // The cockpit can't resize VS Code's window (that needs Accessibility
    // rights): it only checks that it fills the screen.
    try {
      const fit = screenFit();
      const re = new RegExp(`${path.basename(this.c.wsFile, '.code-workspace')} \\(Workspace\\)`);
      const w = windows().find((x) => x.owner === 'Code' && re.test(x.title));
      if (w) own.push(w.w >= fit.w * 0.9 && w.h >= fit.h * 0.85 ? { mark: '✓', text: `VS Code demo window fills the screen (${w.w}×${w.h})` }
        : { mark: '!', text: `VS Code demo window is ${w.w}×${w.h}: make it fill the screen (Window > Zoom, or double-click its title bar)` });
    } catch {}
    own.push(this.rec.kind === 'obs' && this.rec.captureOk ? { mark: '✓', text: this.rec.note } : { mark: this.rec.kind === 'none' ? '!' : '✗', text: this.rec.note });
    const ownBad = own.filter((l) => l.mark === '✗').length;
    const allReady = ready && !ownBad;
    this.preflight = { running: false, ready: allReady, verdict: allReady ? 'READY' : ready ? `NOT READY (${ownBad} to fix)` : (clean.match(/NOT READY.*$/m) || ['NOT READY'])[0], lines: [...lines, ...own] };
    this.log(`preflight: ${this.preflight.verdict}`);
    this.emit();
    return this.preflight;
  }

  // The start screen's sign-in check. With PR #196's sign-in tool on main the
  // cockpit signs every lab identity in by itself (autoSignIn) and only
  // GitHub is left to the owner; without it, it lists what needs a hand.
  // Before recording (review 1, items 1, 8, 12): the cockpit's old VS Code
  // windows closed, the demo window on THIS screen (reopened here if it sits
  // on another Space), sized, every other VS Code window minimized.
  async prepareStage() {
    try {
      await VsCode.closeStale(this.c.wsFile, this.log);
      // A NEW VS Code window opens on the Space of VS Code's active window:
      // put the owner's demo window (on this screen) in front first, so a
      // preview's or rehearsal's window opens here too (preview 2, piece 1
      // showed the demo window instead of the preview copy's diff).
      if (this.c.wsFile !== LIVE_WS) {
        const demo = new VsCode(LIVE_WS, { log: this.log });
        if (demo.find() && await codeWindowHere(demo.title)) await stage({ kind: 'code', title: demo.title }, this.cockpitPids(), this.log);
      }
      for (let k = 0; k < 2; k++) {
        if (this.code.find() && !(await codeWindowHere(this.code.title))) { this.log(`stage: ${this.code.title} is on another screen: reopening it here`); await this.code.closeWindow(); }
        await this.code.open();
        if (await codeWindowHere(this.code.title)) break;
      }
      if (!(await codeWindowHere(this.code.title))) throw new Error(`the VS Code window ${this.code.title} is not on this screen: move it here before recording`);
      const fit = screenFit(); await this.code.fit(fit.w, fit.h);
      await this.code.call('command', { id: 'workbench.action.closeAuxiliaryBar' }).catch(() => {});
      await this.recordingLook(true);
      await this.clearOthers();
    } catch (e) { this.log(`stage: ${e.message}`); }
  }

  // need: optional Set of site names (watchNeeds): only those are signed in.
  async checkSignins({ need = null } = {}) {
    await this.prepareStage();
    const T = await signinTool(this.root).catch(() => null);
    if (T) return this.autoSignIn(T, { need });
    return this.manualSigninCheck();
  }

  async autoSignIn(T, { need = null } = {}) {
    this.signins = { running: true, auto: true, sites: [] }; this.emit();
    const add = (name, ok, note) => { this.signins.sites.push({ name, ok, note }); this.emit(); };
    const want = (...names) => !need || names.some((n) => need.has(n));
    // Never the owner's own account: every identity signed in here is a lab
    // identity from the sign-in tool's registry (which refuses the owner too).
    for (const id of [PRESENTER.id, SPLUNK.id, STAFF.id]) assertNotOwner(id, T);
    await this.browser.launch();
    // GitHub: the owner's own sign-in, the only one left to them.
    if (want('GitHub')) {
      try { const need = await this.browser.open(`${GH}/pulls`, { settle: 2500 }); add('GitHub', !need, need ? 'Sign in to GitHub once (in the recording browser)' : 'signed in (yours)'); }
      catch (e) { add('GitHub', false, e.message.split('\n')[0]); }
    }
    // adm-presenter in the recording window, kept signed in, PIM-Demo-Readers on.
    const portals = ['Entra', 'Azure portal', 'Defender'];
    if (want(...portals)) try {
      // In a tab of its own, closed after (the tool's passkey flow timed out
      // on the window's existing first tab; on a fresh tab it signs in).
      const sp = await T.signIn(PRESENTER.id, PRESENTER.url, { context: this.browser.ctx }); await sp.close?.();
      this.stopKeep?.(); this.stopKeep = T.keepSignedIn(this.browser.ctx, PRESENTER.id, { onEvent: (m) => this.log(`sign-in: ${m}`) });
      try {
        const r = await T.activatePim(PRESENTER.id, PRESENTER.pim.group, PRESENTER.pim.hours, PRESENTER.pim.reason, { context: this.browser.ctx });
        for (const n of portals) add(n, true, `adm-presenter, ${PRESENTER.pim.group} ${r.already ? 'already active' : 'activated'}${r.endsUtc ? ` until ${r.endsUtc}` : ''}`);
      } catch (e) { for (const n of portals) add(n, false, `adm-presenter signed in, but ${PRESENTER.pim.group} could not be activated: ${e.message.split('\n')[0]}`); }
    } catch (e) { for (const n of portals) add(n, false, `adm-presenter: ${e.message.split('\n')[0]}`); }
    // ServiceNow admin view: the recovery account (lib/snow.mjs).
    if (want('ServiceNow')) try {
      const who = await snowUser(this.browser.ctx);
      if (who && who !== 'acr.breakglass') add('ServiceNow', false, `signed in as ${who}: sign that out (only the recovery account is used)`);
      else { if (!who) await signInRecovery(this.browser.page, { log: this.log }); add('ServiceNow', true, 'acr.breakglass (recovery account)'); }
    } catch (e) { add('ServiceNow', false, e.message.split('\n')[0]); }
    // Splunk: its own admin, in the recording window.
    if (want('Splunk')) {
      try { const r = await T.signIn(SPLUNK.id, SPLUNK.url, { context: this.browser.ctx }); await r.close?.(); add('Splunk', true, 'splunk-admin'); }
      catch (e) { add('Splunk', false, `splunk-admin: ${e.message.split('\n')[0]}`); }
    }
    // test-user-a's staff window: My Apps, AWS, Teams.
    if (want('Teams', 'My Apps')) try {
      await this.staffBrowser.launch();
      const st = await T.signIn(STAFF.id, STAFF.url, { context: this.staffBrowser.ctx }); await st.close?.();
      this.stopKeepStaff?.(); this.stopKeepStaff = T.keepSignedIn(this.staffBrowser.ctx, STAFF.id, { onEvent: (m) => this.log(`sign-in (staff): ${m}`) });
      for (const n of ['Teams', 'My Apps']) add(n, true, 'test-user-a (staff window)');
    } catch (e) { for (const n of ['Teams', 'My Apps']) add(n, false, `test-user-a: ${e.message.split('\n')[0]}`); }
    // AWS admin view: adm-labops borrows LabAdministrator for two hours
    // (PIM-AWS-Lab-Admins, ADR 0025), is provisioned into AWS on demand, then
    // opens the console through the access portal. Live and preview only:
    // a dry run doesn't borrow admin rights.
    // A retake of a piece that doesn't show AWS doesn't borrow LabAdministrator.
    // (Only runs that show piece 4 or 9: every activation also raises a PIM
    // alarm, noise for piece 7.)
    const from = this.resumeFrom || 1, to = this.only || 10;
    // v2: only a LIVE take of N04 or N08 borrows it; a v2 preview changes
    // nothing in the lab, so it shows the AWS facts on cards instead.
    const awsPieces = this.v2 ? (this.mode === 'live' && this.list.some((x) => x.piece === 4 || x.piece === 8)) : (from <= 4 && to >= 4) || (from <= 9 && to >= 9);
    if ((this.mode === 'live' || this.mode === 'preview') && awsPieces) {
      try { add('AWS console', true, await this.awsAdminSetup(T)); }
      catch (e) { add('AWS console', false, `adm-labops: ${e.message.split('\n')[0]}`); }
    } else add('AWS console', true, this.v2 && this.preview ? 'v2 preview: no AWS admin activation (AWS facts shown on cards, read as the lab operator)' : 'adm-labops borrows LabAdministrator when a live take or preview starts (not in a dry run)');
    // Review 1: a PIM page left open by a sign-in step showed up on camera.
    // Every cockpit window keeps exactly one tab, the one the steps drive.
    for (const W of [this.browser, this.staffBrowser, this.awsBrowser]) {
      if (!W?.up) continue;
      for (const pg of W.ctx.pages()) if (pg !== W.page) await pg.close().catch(() => {});
    }
    this.signins.running = false; this.emit();
    this.log(`sign-ins (automatic): ${this.signins.sites.map((x) => `${x.name} ${x.ok ? 'ok' : 'NOT OK'}`).join(', ')}`);
    return this.signins;
  }

  async awsAdminSetup(T) {
    const A = this.awsBrowser;
    await A.launch();
    const r = await T.signIn(AWS_ADMIN.id, 'https://myaccount.microsoft.com/', { context: A.ctx }); await r.close?.();
    this.stopKeepAws?.(); this.stopKeepAws = T.keepSignedIn(A.ctx, AWS_ADMIN.id, { onEvent: (m) => this.log(`sign-in (aws): ${m}`) });
    let act = await T.activatePim(AWS_ADMIN.id, AWS_ADMIN.pim.group, AWS_ADMIN.pim.hours, AWS_ADMIN.pim.reason, { context: A.ctx });
    // A run resumed later (preview 2: piece 4 retaken, then 9 and 10) finds
    // the 2-hour activation of an earlier run: if it ends within 50 minutes
    // it would lapse mid-piece, so it is given back and borrowed again.
    const endsFile = path.join(this.root, '.state', 'aws-admin-ends.json');
    if (act.already) {
      const prevEnd = (() => { try { return Date.parse(JSON.parse(fs.readFileSync(endsFile, 'utf8')).endsUtc); } catch { return NaN; } })();
      if (!Number.isFinite(prevEnd) || prevEnd - Date.now() < 50 * 60000) {
        this.log(`aws: ${AWS_ADMIN.pim.group} ends ${Number.isFinite(prevEnd) ? new Date(prevEnd).toISOString() : 'at an unknown time'}: giving it back and borrowing it again for 2 h`);
        this.awsAdminActive = true;
        this.log(`aws: ${await this.awsAdminDeactivate().catch((e) => `give back: ${e.message}`)}`);
        act = await T.activatePim(AWS_ADMIN.id, AWS_ADMIN.pim.group, AWS_ADMIN.pim.hours, AWS_ADMIN.pim.reason, { context: A.ctx });
      }
    }
    if (!act.already) fs.writeFileSync(endsFile, JSON.stringify({ endsUtc: act.endsUtc || new Date(Date.now() + AWS_ADMIN.pim.hours * 3600000).toISOString() }));
    this.awsAdminActive = true;
    const u = await L.userByUpn(AWS_ADMIN.upn);
    const pod = await L.provisionOnDemand('AWS IAM Identity Center', u.id).catch((e) => `provision on demand: ${e.message.split('\n')[0]}`);
    this.log(`aws: ${AWS_ADMIN.id} provisioned into AWS on demand: ${String(pod).slice(0, 160)}`);
    // Review 1: "LabAdministrator No access" on camera. Before recording,
    // wait until AWS Identity Center has him in the group (operator read),
    // then until a federation to the role really lands on the users page.
    for (let k = 0; k < 20; k++) {
      if (await L.awsUserInGroup(AWS_ADMIN.upn, AWS_ADMIN.pim.group).catch(() => false)) break;
      // A user on demand carries no group: the group, with him in it.
      if (k % 4 === 0) await L.provisionGroupOnDemand('AWS IAM Identity Center', AWS_ADMIN.pim.group, u.id).then((m) => this.log(`aws: ${AWS_ADMIN.pim.group} on demand with ${AWS_ADMIN.id}: ${String(m).slice(0, 100)}`), (e) => this.log(`aws: group on demand: ${e.message.split('\n')[0]}`));
      await sleep(15000);
    }
    const role = process.env.COCKPIT_AWS_ROLE || 'LabAdministrator';
    const dest = 'https://us-east-1.console.aws.amazon.com/singlesignon/home?region=us-east-1#/users';
    for (let k = 0; k < 12; k++) {
      await A.open(`https://d-90666212c7.awsapps.com/start/#/console?account_id=182002546409&role_name=${role}&destination=${encodeURIComponent(dest)}`, { settle: 12000 });
      const t = await A.page.locator('body').innerText().catch(() => '');
      const host = new URL(A.page.url()).host;
      if (/^us-east-1\.console\.aws\.amazon\.com$/.test(host) && /singlesignon/.test(A.page.url()) && !/sign in error|No access|You need .*permission|not authorized|AccessDenied/i.test(t) && /Users/.test(t)) {
        return `adm-labops, ${AWS_ADMIN.pim.group} ${act.already ? 'already active' : 'activated'}${act.endsUtc ? ` until ${act.endsUtc}` : ''}, ${role}, Identity Center users page opens`;
      }
      await sleep(20000);
    }
    throw new Error(`${role} console view did not open for ${AWS_ADMIN.id} (not in the AWS group yet?)`);
  }

  // End of a preview: give LabAdministrator back (Deactivate in PIM, as
  // adm-labops), then check Entra no longer lists him in the group.
  async awsAdminDeactivate() {
    const T = await signinTool(this.root).catch(() => null);
    if (!this.awsBrowser.up || !T) return 'nothing to give back';
    const A = this.awsBrowser;
    await A.open(T.PIM_URL, { settle: 9000 });
    await A.click({ role: 'tab', name: /Active assignments/i }).catch(() => {});
    await sleep(4000);
    await A.click({ role: 'button', name: /^Deactivate$/ });
    await sleep(2500);
    await A.click({ role: 'button', name: /^Deactivate$/, nth: 1 }).catch(() => {});
    const u = await L.userByUpn(AWS_ADMIN.upn);
    for (let k = 0; k < 24; k++) { if (!(await L.isGroupMember(AWS_ADMIN.pim.group, u.id))) { this.awsAdminActive = false; return `${AWS_ADMIN.pim.group} deactivated`; } await sleep(5000); }
    throw new Error(`${AWS_ADMIN.pim.group} still active for ${AWS_ADMIN.id} after 2 minutes: deactivate it in PIM (it ends by itself after 2 hours)`);
  }

  async manualSigninCheck() {
    const sites = [
      ['GitHub', `${GH}/pulls`], ['Entra', 'https://entra.microsoft.com/#home'], ['Azure portal', 'https://portal.azure.com/#home'],
      ['AWS console', 'https://us-east-1.console.aws.amazon.com/singlesignon/home?region=us-east-1'], ['Defender', 'https://security.microsoft.com/?tid=86a2e327-4951-4348-a3c4-6f4b79ffd8f2'],
      ['Splunk', 'http://127.0.0.1:8000/en-US/app/search/search'],
      ['Teams', 'https://teams.microsoft.com/v2/'],
    ];
    this.signins = { running: true, sites: [] }; this.emit();
    await this.browser.launch();
    for (const [name, url] of sites) {
      let ok, note = '';
      try { const need = await this.browser.open(url, { settle: 5000 }); ok = !need; note = need ? 'sign in once here' : 'signed in'; }
      catch (e) { ok = false; note = e.message.split('\n')[0]; }
      this.signins.sites.push({ name, ok, note }); this.emit();
    }
    // ServiceNow: the cockpit signs its recovery account in itself (setup,
    // never on camera, never the owner's account).
    try {
      const who = await snowUser(this.browser.ctx);
      if (who === 'acr.breakglass') this.signins.sites.push({ name: 'ServiceNow', ok: true, note: 'signed in as the recovery account (acr.breakglass)' });
      else if (who) this.signins.sites.push({ name: 'ServiceNow', ok: false, note: `signed in as ${who}: sign that out (only the recovery account is used)` });
      else { await signInRecovery(this.browser.page, { log: this.log }); this.signins.sites.push({ name: 'ServiceNow', ok: true, note: 'the cockpit signed in the recovery account (setup)' }); }
    } catch (e) { this.signins.sites.push({ name: 'ServiceNow', ok: false, note: e.message.split('\n')[0] }); }
    this.signins.running = false; this.emit();
    this.log(`sign-ins: ${this.signins.sites.map((s) => `${s.name} ${s.ok ? 'ok' : 'NEEDED'}`).join(', ')}`);
    return this.signins;
  }

  writeDryReport() {
    const f = path.join(this.root, 'shots', 'dry-run-report.json');
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, JSON.stringify({ at: new Date().toISOString(), mode: this.mode, standIns: this.standIns || [], steps: this.dryReport }, null, 2));
    this.log(`dry-run report: ${f}`);
  }

  // The cursor ring follows the pointer on screen while the cockpit runs
  // (off by default since 2026-11-10: --ring turns it on; the teleprompter's C key toggles it).
  // The pointer's mode, live: 'human' | 'guide' | 'dom' (POST /api/mouse?mode=,
  // /api/guide toggles guide on and off).
  async setMouse(mode) {
    if (!this.human) return;
    if (mode === 'toggle-guide') mode = this.human.mode === 'guide' ? 'human' : 'guide';
    const was = this.human.mode;
    const m = this.human.setMode(mode);
    if (was === 'dom' && m !== 'dom') for (const b of [this.browser, this.staffBrowser, this.awsBrowser]) if (b?.up) await b.ov('hideCursor');
    if ((was === 'dom') !== (m === 'dom')) await this.rec?.obs?.setCursor?.(m !== 'dom').catch((e) => this.log(`OBS pointer: ${e.message}`));
    this.emit();
  }
  startRing() { (this.ring ||= new Ring({ log: this.log })).start(); this.emit(); }
  toggleRing() { (this.ring ||= new Ring({ log: this.log })).toggle(); this.emit(); }
  // The activity bar and status bar are hidden only while the cockpit runs
  // (bridge 0.1.10 writes them to the window's workspace file); close() takes
  // them out again so the owner's demo window is a normal VS Code.
  async recordingLook(hidden) {
    if (!this.code?.find()) return;
    if (hidden && this.lookHidden) return;
    try { await this.code.call('chrome', { hidden }); this.lookHidden = hidden; this.log(`VS Code: activity bar and status bar ${hidden ? 'hidden for recording' : 'back'}`); }
    catch (e) { this.log(`VS Code: could not ${hidden ? 'hide' : 'restore'} the activity bar and status bar: ${e.message}`); }
  }

  // The take is saved FIRST: putting the bars back or the lead's window back
  // in full screen must never be filmed (watch run 2026-11-10 caught both).
  async close() { this.stopStageWatch(); if (this.rec?.piece) await this.rec.endPiece().catch(() => {}); if (this.hrForm) { try { this.hrForm.kill(); } catch {} this.hrForm = null; } if (this.lookHidden) await this.recordingLook(false); this.ring?.stop(); this.human?.stop(); this.stopPoll(); this.stopKeep?.(); this.stopKeepStaff?.(); this.stopKeepAws?.(); await this.rec?.close(); await this.browser?.close(); await this.staffBrowser?.close(); await this.awsBrowser?.close(); if (this.unFullScreened?.length) { this.log(`stage: ${await restoreFullScreen(this.unFullScreened).catch((e) => e.message)}`); this.unFullScreened = []; } }
}

// Issue a one-time pass (60 min, usable once) through the lab operator; the
// request body has no secret, the answer stays in memory. Old passes for the
// same person are removed first (a person has at most one).
// ServiceNow after a single sign-on hand-off: wait until the page has left
// Microsoft's and ServiceNow's SAML pages and has settled.
async function snowLanding(page) {
  for (let k = 0; k < 40; k++) {
    const u = page.url();
    if (/service-now\.com/.test(u) && !/saml|login\.do|navpage\.do\?.*sso/i.test(u)) break;
    await sleep(1000);
  }
  await page.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {});
  await sleep(2000);
}
async function snowLoginForm(page) {
  return page.getByText(/Log in with Microsoft Entra ID/).first().isVisible().catch(() => false);
}

async function issueTap(upn) {
  const base = `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(upn)}/authentication/temporaryAccessPassMethods`;
  const OP = `${L.LAB}/lab/scripts/operator/op`;
  const old = JSON.parse(await L.sh(OP, ['az', 'rest', '--method', 'GET', '--url', base, '-o', 'json'], { cwd: L.LAB }));
  for (const m of old.value || []) await L.sh(OP, ['az', 'rest', '--method', 'DELETE', '--url', `${base}/${m.id}`], { cwd: L.LAB });
  const res = await L.sh(OP, ['az', 'rest', '--method', 'POST', '--url', base, '--headers', 'Content-Type=application/json', '--body', '{"lifetimeInMinutes":60,"isUsableOnce":true}', '-o', 'json'], { cwd: L.LAB });
  const pass = JSON.parse(res).temporaryAccessPass;
  if (!pass || !/^\S{8,}$/.test(pass)) throw new Error('the one-time pass was not issued');
  return pass;
}

function describe(a, ck) {
  const v = (x) => { try { return typeof x === 'function' ? x(ck.c) : x; } catch { return '(from an earlier live step)'; } };
  const base = (f) => (f ? path.basename(f) : '');
  switch (a.do) {
    case 'code.type': return a.lineMatch ? `type "${a.text}" into ${base(a.file)} on the line matching ${a.lineMatch}${a.find ? ` (replacing "${a.find}")` : ''}` : `type "${a.text}" at the end of ${base(a.file)}`;
    case 'code.save': return `save ${base(a.file)}`;
    case 'hr.hire': return `click Hire on the HR form (${ck.c?.hire?.name || 'the hire'}): one commit to hr-feed, sent to Entra`;
    case 'hr.leave': return `make ${ck.c?.hire?.name || 'the hire'} a leaver on the HR form (Change, Leaver, Save)`;
    case 'code.commit': return `commit ${a.files?.join(', ')} with "${a.message}"`;
    case 'code.push': return `push ${a.branch} to GitHub`;
    case 'gh.createPr': return `open a pull request from ${a.branch}: "${a.title}"`;
    case 'gh.merge': return 'click Merge pull request, then Confirm merge';
    case 'gh.closePr': return 'close the rehearsal pull request without merging';
    case 'gh.runWorkflow': return `click Run workflow on ${a.workflow}`;
    case 'tap.signin': return `issue a one-time pass for ${a.who} and sign in with it in a clean window (pass never shown)`;
    case 'web.open': return `open ${v(a.url)}`;
    case 'web.click': case 'private.click': case 'web.clickIf': return `click ${JSON.stringify(v(a.target))}`;
    case 'require': return `check ${a.check}`;
    case 'web.type': case 'private.type': return `type "${a.text}"`;
    case 'web.highlight': case 'private.highlight': return `highlight ${JSON.stringify(v(a.target))}${a.tag ? ` "${v(a.tag)}"` : ''}`;
    case 'code.diff': return `show the change in ${base(a.file)} (lines ${a.line}-${a.endLine})`;
    case 'code.file': return `open ${base(a.file)} at line ${a.line}`;
    case 'code.highlight': return `highlight ${base(a.file)} lines ${a.line}-${a.endLine}`;
    default: return a.do;
  }
}

// Does the live blueprints branch (its commits + the uncommitted on-camera
// change) still apply on top of main?
async function liveBranchCheck(folder) {
  const g = (args) => L.sh('git', ['-C', folder, ...args]);
  await g(['fetch', '-q', 'origin', '+refs/heads/main:refs/remotes/origin/main']);
  const head = (await g(['rev-parse', 'HEAD'])).trim();
  const branch = (await g(['rev-parse', '--abbrev-ref', 'HEAD'])).trim();
  const out = [];
  const clean = await g(['merge-tree', '--write-tree', 'origin/main', head]).then(() => true, () => false);
  out.push(clean ? { mark: '✓', text: `The blueprints branch (${branch}) merges cleanly with main` }
    : { mark: '✗', text: `The blueprints branch (${branch}) conflicts with main: rebase it before recording, or GitHub runs no checks on the pull request` });
  const base = (await g(['merge-base', 'origin/main', head])).trim();
  const staged = (await g(['diff', '--name-only'])).split('\n').filter(Boolean);
  const moved = [];
  for (const f of staged) if (!(await g(['diff', '--quiet', base, 'origin/main', '--', f]).then(() => true, () => false))) moved.push(f);
  if (moved.length) out.push({ mark: '!', text: `Main changed ${moved.join(', ')} since this branch was cut: after the rebase, check the on-camera change still applies` });
  return out;
}

// Which Entra account a browser context is signed in as (My Account in a
// scratch tab; null when it isn't signed in).
async function entraAccount(context) {
  const p = await context.newPage();
  try {
    await p.goto('https://myaccount.microsoft.com/', { waitUntil: 'domcontentloaded', timeout: 60000 });
    for (let i = 0; i < 40; i++) {
      if (/login\.microsoftonline\.com/.test(p.url())) return null;
      const m = (await p.locator('body').innerText().catch(() => '')).match(/[A-Za-z0-9._%+-]+@contosohealthlab\.(com|onmicrosoft\.com)/i);
      if (m) return m[0].toLowerCase();
      await sleep(1000);
    }
    return null;
  } finally { await p.close().catch(() => {}); }
}

// The browser window: 1920x1080 when the display is that big, else the
// display's usable size (a 16-inch MacBook is 1728 x 1117 points; the menu
// bar takes 37).
function screenFit() {
  let w = 1920, h = 1080;
  try {
    const j = JSON.parse(execFileSync('system_profiler', ['SPDisplaysDataType', '-json'], { encoding: 'utf8', timeout: 20000 }));
    for (const g of j.SPDisplaysDataType || []) for (const d of g.spdisplays_ndrvs || []) {
      if (d.spdisplays_main !== 'spdisplays_yes') continue;
      const m = /(\d+)\s*x\s*(\d+)/.exec(d._spdisplays_resolution || '');
      if (m) { w = Math.min(1920, +m[1]); h = Math.min(1080, +m[2] - 37); }
    }
  } catch {}
  return { w, h };
}

// A card spec as the file:// URL of ui/card.html (the same encoding as steps.mjs).
function cardUrlFor(spec) {
  const f = new URL('../ui/card.html', import.meta.url).pathname;
  return `file://${f}#${Buffer.from(JSON.stringify(spec), 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}
const unattendedNow = (ck) => ck.unattended && (ck.pendingStart || (ck.rec.piece && ck.rec.paused));
