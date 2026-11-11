// Static check of steps.mjs (no browser, no network): every step has a line
// to say, known actions, a known wait check, a real piece; files and line
// numbers it points VS Code at exist; write steps are marked. Run it after
// editing steps.mjs:  node tools/check-steps.mjs
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { steps as stepsV1, PIECES as PIECES_V1, stepsV2, PIECES_V2 } from '../steps.mjs';
// --v2: check the v2 parts (segments/V2-RUNNING-ORDER.md) instead.
const V2 = process.argv.includes('--v2');
const PIECES = V2 ? PIECES_V2 : PIECES_V1;
const steps = V2 ? stepsV2 : stepsV1;

const ACTIONS = new Set(['map.focus', 'web.video', 'web.show', 'code.open', 'code.closeAll', 'code.diff', 'code.file', 'code.highlight', 'code.type', 'code.save', 'code.commit', 'code.push',
  'web.open', 'web.highlight', 'web.click', 'web.clickIf', 'require', 'web.type', 'web.focus', 'private.open', 'private.click', 'private.highlight', 'private.type',
  'activate', 'find', 'stopwatch.start', 'stopwatch.lap', 'stopwatch.stop', 'gh.createPr', 'gh.merge', 'gh.closePr', 'gh.runWorkflow', 'tap.signin', 'pause', 'snow.adminList', 'staff.signin', 'drill.ensure', 'preview.approve', 'preview.contain', 'preview.secondCheck', 'identity.signin', 'pim.deactivate', 'teams.guard', 'cloudsync.restart', 'pod', 'teams.channel', 'sam.servicenow', 'pim.showActive', 'signin.openTap', 'web.find', 'web.waitFor', 'pam.vault', 'pam.guac', 'okta.signin', 'code.changes',
  'card', 'card.aws', 'banner', 'banner.previewOnly', 'code.stop', 'code.command', 'code.tree', 'code.check', 'hr.open', 'hr.fill', 'hr.hire', 'hr.leave', 'gh.openJob', 'gh.planComment', 'todo']);
const CHECKS = new Set(['prChecks', 'approvalIssue', 'applyDone', 'hrRunDone', 'samProvLog', 'samInEntra', 'samHasPackage', 'samInAws', 'samOffEntra', 'samOffAws', 'samGone', 'evidenceDone', 'snowReady', 'drillPending', 'drillContained', 'samSignin', 'pimIncident', 'rajTicket']);
const WRITES = new Set(['code.type', 'code.save', 'code.commit', 'code.push', 'gh.createPr', 'gh.merge', 'gh.closePr', 'gh.runWorkflow', 'tap.signin', 'staff.signin', 'drill.ensure', 'identity.signin', 'hr.hire', 'hr.leave']);

const DEMO = path.join(os.homedir(), 'contoso-demo');
const c = { mode: 'dry', today: '2026-11-05', bp: path.join(DEMO, 'blueprints'), hr: path.join(DEMO, 'hr'), bpBranch: 'x', bpBranchRe: '^x$', prTitle: 't', prBody: 'b',
  tourLab: path.join(DEMO, 'cockpit', '.tour-main'), tourOut: path.join(DEMO, 'cockpit', 'tour', 'out'), tourWs: path.join(DEMO, 'cockpit', 'tour', 'contoso-demo-tour.code-workspace'),
  v2: { ...Object.fromEntries(['ad', 'okta', 'hr', 'pam', 'k8skv', 'kvleak', 'bastion', 'adfs', 'cicd', 'azlp', 'ssm', 'snow'].map((k) => [k, path.join(DEMO, 'cockpit', '.v2', k)])), ws: path.join(DEMO, 'cockpit', 'v2', 'contoso-demo-v2.code-workspace') } };
const list = steps(c);
const bad = [];
const ids = new Set();
for (const s of list) {
  const at = `[${s.id}]`;
  if (ids.has(s.id)) bad.push(`${at} duplicate id`); ids.add(s.id);
  if (!PIECES.some((p) => p.n === s.piece)) bad.push(`${at} unknown piece ${s.piece}`);
  if (!Array.isArray(s.say) || !s.say.length || s.say.some((l) => typeof l !== 'string' || l.length > 120)) bad.push(`${at} say must be 1+ short lines (<=120 chars)`);
  if (s.previewSay && (!Array.isArray(s.previewSay) || s.previewSay.some((l) => typeof l !== 'string' || l.length > 120))) bad.push(`${at} previewSay must be short lines`);
  if (s.cloud && V2 && !s.standIn) bad.push(`${at} a cloud step needs a standIn for --preview`);
  if (V2) for (const a of s.do) if (a.do === 'code.stop') { const st = JSON.parse(fs.readFileSync(path.join(DEMO, 'readiness', 'lab-guide', 'stops.json'), 'utf8')).stops; if (!st.some((x) => x.id === a.stop)) bad.push(`${at} no lab guide stop ${a.stop}`); }
  for (const a of [...s.do, ...(s.preview || []), ...(s.standIn || [])]) {
    if (!ACTIONS.has(a.do)) bad.push(`${at} unknown action ${a.do}`);
    if (a.do.startsWith('preview.') && !a.previewOnly && !(s.preview || []).includes(a)) bad.push(`${at} ${a.do} belongs in the step's preview list`);
    if (WRITES.has(a.do) && !s.write) bad.push(`${at} ${a.do} changes something: mark the step write: true`);
    if (a.file && !fs.existsSync(a.file)) bad.push(`${at} ${a.do}: no such file ${a.file}`);
    if (a.file && a.endLine && fs.existsSync(a.file) && a.endLine > fs.readFileSync(a.file, 'utf8').split('\n').length) bad.push(`${at} ${a.do}: line ${a.endLine} is past the end of ${path.basename(a.file)}`);
  }
  if (s.wait && !CHECKS.has(s.wait.check)) bad.push(`${at} unknown wait check ${s.wait.check}`);
  for (const a of s.do) if (a.do === 'require' && !CHECKS.has(a.check)) bad.push(`${at} require: unknown check ${a.check}`);
  if (s.wait && (!s.wait.waiting || !s.wait.ready)) bad.push(`${at} a wait needs waiting + ready texts`);
}
for (const p of PIECES) if (!list.some((s) => s.piece === p.n)) bad.push(`piece ${p.n} has no steps`);
// Pieces must be in order (one file per piece).
for (let i = 1; i < list.length; i++) if (list[i].piece < list[i - 1].piece) bad.push(`[${list[i].id}] piece order goes backwards`);
if (V2) for (const p of PIECES) console.log(`  N${String(p.n).padStart(2, '0')} ${p.status.padEnd(7)} ${String(list.filter((x) => x.piece === p.n).length).padStart(2)} steps  ${p.title}`);
console.log(`${list.length} steps in ${PIECES.length} ${V2 ? 'v2 parts' : 'pieces'}`);
if (bad.length) { console.log(bad.map((b) => '  ✗ ' + b).join('\n')); process.exit(1); }
console.log('  ✓ steps.mjs is consistent');
