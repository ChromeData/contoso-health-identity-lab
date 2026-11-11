// Precision / recall of the meaning matcher (lib/points.mjs) on the offline
// test set tests/points-testset.json: paraphrases of real say lines (each a
// positive for its point and a negative for the step's other points) and
// off-topic talk (a negative for every point of every step).
//   node tools/points-eval.mjs          report with lib/points.mjs's TUNE
//   node tools/points-eval.mjs --tune   grid-search TUNE on split A, report A / B
//   --misses                            list every miss and false check
import fs from 'node:fs';
import path from 'node:path';
import { derivePoints, scorePoints, Embedder, TUNE, isShort } from '../lib/points.mjs';
import { allSteps } from './build-points.mjs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import { Listener } from '../lib/listen.mjs';

const root = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const T = JSON.parse(fs.readFileSync(path.join(root, 'tests', 'points-testset.json'), 'utf8'));
const emb = await new Embedder({ root }).load();
const byId = Object.fromEntries(allSteps().map((s) => [s.id, derivePoints(s.say)]));
for (const [id, say] of Object.entries(T.extraSteps || {})) byId[id] = derivePoints(say);

// --spoken: every sentence of the set is spoken by macOS `say` and written
// down by whisper (the cockpit's own speech path) before it is matched, so
// the numbers include speech-to-text errors.
if (process.argv.includes('--spoken')) {
  const L = new Listener({ root, prompt: 'Contoso Health, Entra ID, Azure, Intune, AWS, Okta, PIM, ServiceNow, OrangeHRM, Active Directory, DC01, Cloud Sync, Key Vault, Bastion, Sentinel, Splunk, SIEM, KQL, SPL, GitHub, Terraform, VS Code, Checkov, TruffleHog, Conditional Access, LAPS, AD FS.' });
  await L.startServer();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'points-spoken-'));
  const voices = ['Samantha', 'Daniel', 'Karen'];
  let k = 0, changed = 0;
  for (const x of [...T.pos, ...T.off]) {
    const f = path.join(dir, `${k}.wav`);
    execFileSync('/usr/bin/say', ['-v', voices[k++ % voices.length], '-o', f, '--data-format=LEI16@16000', x.say]);
    const raw = execFileSync('/opt/homebrew/bin/ffmpeg', ['-v', 'error', '-i', f, '-f', 's16le', '-ac', '1', '-ar', '16000', 'pipe:1'], { maxBuffer: 64 << 20 });
    const heard = await L.transcribe(new Int16Array(raw.buffer, raw.byteOffset, raw.length / 2));
    if (heard.toLowerCase().replace(/[^a-z0-9]/g, '') !== x.say.toLowerCase().replace(/[^a-z0-9]/g, '')) changed++;
    x.written = x.say; x.say = heard;
  }
  L.close();
  console.log(`spoken: ${k} sentences said by macOS voices (${voices.join(', ')}) and written down by whisper; ${changed} came back with different words`);
}

// Features per W_COV (which point owns a window depends on it): every
// (utterance, point) pair that matters, with its winning window's sem / cov.
const raw = { T: -9, SEM_FLOOR: -9, SHORT_T: -9 };
const feat = async (pts, say, W) => (await scorePoints(emb, pts, say, '', { ...raw, W_COV: W })).map((r, i) => ({ sem: r.sem, cov: r.cov, short: isShort(pts[i]), text: pts[i].text }));
const allPts = Object.entries(byId).filter(([id]) => !(id in (T.extraSteps || {})));
async function features(W) {
  const pairs = [];
  for (const x of T.pos) {
    const pts = byId[x.step];
    if (!pts || !pts[x.p]) throw new Error(`test set: no point ${x.step}#${x.p}`);
    (await feat(pts, x.say, W)).forEach((f, i) => pairs.push({ ...f, pos: i === x.p, kind: i === x.p ? 'pos' : 'cross', split: x.split, say: x.say, step: x.step }));
  }
  let offPairs = { A: 0, B: 0 };
  for (const x of T.off) for (const [id, pts] of allPts) (await feat(pts, x.say, W)).forEach((f) => {
    offPairs[x.split]++;
    // Only an off-topic pair that some setting in the grid could pass is kept.
    if (f.sem >= 0.25) pairs.push({ ...f, pos: false, kind: 'off', split: x.split, say: x.say, step: id });
  });
  pairs.offPairs = offPairs;
  return pairs;
}
let pairs;
const decide = (p, t) => p.short ? p.sem >= t.SHORT_T : p.sem + t.W_COV * p.cov >= t.T && p.sem >= t.SEM_FLOOR;
function report(t, split) {
  const P = pairs.filter((p) => !split || p.split === split);
  const tp = P.filter((p) => p.pos && decide(p, t)).length, fn = P.filter((p) => p.pos && !decide(p, t)).length;
  const fpc = P.filter((p) => p.kind === 'cross' && decide(p, t)).length, fpo = P.filter((p) => p.kind === 'off' && decide(p, t)).length;
  const fp = fpc + fpo, prec = tp / Math.max(1, tp + fp), rec = tp / Math.max(1, tp + fn);
  const offU = new Set(P.filter((p) => p.kind === 'off' && decide(p, t)).map((p) => p.say)).size;
  return { tp, fn, fpCross: fpc, fpOff: fpo, offUtterancesThatCheckedSomething: offU, offUtterances: T.off.filter((x) => !split || x.split === split).length,
    crossPairs: P.filter((p) => p.kind === 'cross').length, offPairs: split ? pairs.offPairs[split] : pairs.offPairs.A + pairs.offPairs.B, precision: +prec.toFixed(3), recall: +rec.toFixed(3), f1: +(2 * prec * rec / Math.max(1e-9, prec + rec)).toFixed(3) };
}

// How far the bars are from the nearest positive below / negative above
// them: short points and the rest each have their own bar, so the sum.
function margin(t, split) {
  const m = { true: Infinity, false: Infinity };
  for (const p of pairs) {
    if (split && p.split !== split) continue;
    const d = p.short ? p.sem - t.SHORT_T : Math.min(p.sem + t.W_COV * p.cov - t.T, p.sem - t.SEM_FLOOR);
    m[p.short] = Math.min(m[p.short], p.pos ? d : -d);
  }
  return (Number.isFinite(m.true) ? m.true : 0) + (Number.isFinite(m.false) ? m.false : 0);
}
let tune = TUNE;
// --tune-all: the same on both splits (the values to ship; its numbers are in-sample).
const TS = process.argv.includes('--tune-all') ? null : 'A';
if (process.argv.includes('--tune') || !TS) {
  let best = null;
  for (let W = 0; W <= 0.8001; W += 0.05) { pairs = await features(+W.toFixed(2)); for (let t = 0.5; t <= 1.2001; t += 0.01) for (let f = 0.1; f <= 0.6001; f += 0.04) for (let st = 0.3; st <= 0.9001; st += 0.02) {
    const c = { W_COV: +W.toFixed(2), T: +t.toFixed(2), SEM_FLOOR: +f.toFixed(2), SHORT_T: +st.toFixed(2) }, r = report(c, TS);
    // Off-topic talk must never check a point; then the best F1, then precision,
    // then the widest margin (the bar in the middle of the gap, not at its edge).
    const key = [r.fpOff === 0 ? 1 : 0, r.f1, r.precision, +margin(c, TS).toFixed(3)];
    const better = !best || (() => { for (let i = 0; i < key.length; i++) if (key[i] !== best.key[i]) return key[i] > best.key[i]; return false; })();
    if (better) best = { key, c };
  } }
  tune = best.c;
  console.log(`tuned on ${TS ? 'split A' : 'both splits'}:`, JSON.stringify(tune));
}
pairs = await features(tune.W_COV);
console.log('TUNE', JSON.stringify(tune));
for (const s of ['A', 'B', null]) console.log(s ? `split ${s} (${s === 'A' ? 'tuning' : 'held out'})` : 'all', JSON.stringify(report(tune, s)));
if (process.argv.includes('--misses')) {
  for (const p of pairs.filter((p) => p.pos && !decide(p, tune))) console.log(`MISS  [${p.step}] "${p.say}"  ~ "${p.text}"  sem ${p.sem.toFixed(2)} cov ${p.cov.toFixed(2)}`);
  for (const p of pairs.filter((p) => !p.pos && decide(p, tune))) console.log(`FALSE ${p.kind} [${p.step}] "${p.say}"  ~ "${p.text}"  sem ${p.sem.toFixed(2)} cov ${p.cov.toFixed(2)}`);
}
if (process.argv.includes('--dist')) {
  const W = tune.W_COV, sc = (p) => p.short ? p.sem : p.sem + W * p.cov;
  console.log('lowest positives:'); for (const p of pairs.filter((p) => p.pos).sort((a, b) => sc(a) - sc(b)).slice(0, 12)) console.log(`  ${sc(p).toFixed(3)} sem ${p.sem.toFixed(2)} cov ${p.cov.toFixed(2)}  "${p.say}" ~ "${p.text}"`);
  console.log('highest negatives:'); for (const p of pairs.filter((p) => !p.pos).sort((a, b) => sc(b) - sc(a)).slice(0, 12)) console.log(`  ${sc(p).toFixed(3)} sem ${p.sem.toFixed(2)} cov ${p.cov.toFixed(2)} ${p.kind} "${p.say}" ~ "${p.text}"`);
}
