// Key points of a step's lines, and whether a spoken sentence conveyed one.
//
// The say lines are an outline: the presenter says them in his own words.
// A point is one sentence of the step's lines (lines that the teleprompter
// split mid-sentence are joined again). A point counts as conveyed when a
// window of what he said (one sentence, two in a row, or the whole utterance)
// means the same thing:
//   sem  cosine similarity of sentence embeddings (all-mpnet-base-v2, on this
//        Mac, transformers.js), and
//   cov  how many of the point's key concepts were said (stems + synonyms +
//        the usual speech-to-text spellings of the lab's names).
// score = sem + W_COV * cov, conveyed when score >= T and sem >= SEM_FLOOR
// (a point of one or two concepts: sem >= SHORT_T alone), and only by a
// window it matches better than any other point of the step
// (tools/points-eval.mjs tunes W_COV / T / SEM_FLOOR on tests/points-testset.json).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// all-mpnet-base-v2 over all-MiniLM-L6-v2: on the test set MiniLM let 2 of 17
// held-out off-topic sentences check a point, mpnet none (about 60 ms an utterance).
export const MODEL = process.env.COCKPIT_EMBED_MODEL || 'Xenova/all-mpnet-base-v2';
// Tuned on tests/points-testset.json (node tools/points-eval.mjs --tune-all;
// --tune tunes on split A only and reports the held-out split B). With
// all-mpnet-base-v2 the meaning alone separates them (W_COV ends up ~0): the
// concepts still name what was heard in the log and the take report.
export const TUNE = { W_COV: 0.05, T: 0.5, SEM_FLOOR: 0.58, SHORT_T: 0.48 };

const STOP = new Set(('a an the and or but so if then than that this these those it its it\'s is are was were be been being am do does did done ' +
  'to of in on at by for from with as into onto up out off over under about after before again also just only very really here there ' +
  'i me my we our us you your he she her his him they them their what which who whom whose when where why how all any each every ' +
  'some no not nor can could will would shall should may might must have has had having one s t now well okay ok right yeah ' +
  'like get got go goes going gets let lets let\'s say says said thing things way kind sort bit lot actually basically everybody everyone ' +
  'anyone someone somebody gonna don\'t doesn\'t didn\'t isn\'t aren\'t wasn\'t haven\'t hasn\'t can\'t won\'t it\'s that\'s there\'s here\'s i\'m i\'ve we\'re we\'ve you\'ll you\'re he\'s she\'s they\'re um uh').split(/\s+/));

// Speech-to-text spellings of the lab's names (whisper, before the glossary
// prompt caught most of them), mapped to the name.
const ALIAS = [
  [/\bin ?tra\b/g, 'entra'], [/\bentra id\b/g, 'entra'], [/\boct?a\b/g, 'okta'], [/\bv'?s ?code\b/g, 'vscode'], [/\bvs code\b/g, 'vscode'],
  [/\ba ?w ?s\b/g, 'aws'], [/\bamazon web services\b/g, 'aws'], [/\bp ?i ?m\b/g, 'pim'], [/\bprivileged identity management\b/g, 'pim'],
  [/\bd ?c ?(?:0|zero|o) ?(?:1|one)\b/g, 'dc01'], [/\bdc-01\b/g, 'dc01'], [/\bservice ?now\b/g, 'servicenow'], [/\borange ?h ?r ?m\b/g, 'orangehrm'],
  [/\bgit ?hub\b/g, 'github'], [/\bterra ?form\b/g, 'terraform'], [/\bin ?tune\b/g, 'intune'], [/\bad ?fs\b/g, 'adfs'], [/\ba ?d f ?s\b/g, 'adfs'],
  [/\bactive directory\b/g, 'ad'], [/\bkey ?vault\b/g, 'keyvault'], [/\bcloud ?sync\b/g, 'cloudsync'], [/\bpull requests?\b/g, 'pr'],
  [/\bsplunk\b/g, 'splunk'], [/\bsentinel\b/g, 'sentinel'], [/\bsiem\b|\bseem\b/g, 'siem'], [/\bgrep ?tile\b/g, 'greptile'],
  [/\bcheck ?off\b/g, 'checkov'], [/\btruffle ?hog\b/g, 'trufflehog'], [/\bsession manager\b/g, 'ssm'], [/\bmulti-?factor\b/g, 'mfa'],
  [/\bpcs\b/g, 'pc'], [/\bcut[ -]?over\b/g, 'cutover'], [/\b(?:second|2nd|two|2)[ -]?(?:factor|check|step)s?\b|\b2fa\b/g, 'mfa'],
  [/\b(?:on (?:its|their|his|her) own|by (?:itself|themselves|himself|herself)|itself|automatically)\b/g, 'automatic'],
  [/\bmitre att&?ck\b|\bmiter attack\b|\bmitre attack\b/g, 'mitre'], [/\bconditional access\b/g, 'conditionalaccess'],
];

// Synonym groups, as stems (see stem()). A key concept is said when any
// word of its group is.
const GROUPS = [
  'server machine vm host box computer', 'hub center centre core heart central middle main', 'hire hired join joiner starter onboard new',
  'leave leaver left quit depart offboard exit gone', 'account login logon identity user', 'access permission right entitlement',
  'package bundle', 'admin administrator privileged root', 'alarm alert detection rule', 'log record audit trail', 'camera monitor watch',
  'password secret credential key', 'app application', 'staff employee people worker person', 'hospital clinic', 'change edit update modify fix',
  'check test scan verify validate', 'show display see look', 'copy sync synchronize replicate mirror', 'sign signin login logon',
  'build create make set', 'proof evidence', 'store storage bucket container', 'ticket request incident case', 'approve approval accept okay',
  'manager boss lead', 'code blueprint file', 'turn activate enable switch', 'stop block lock disable contain', 'delete remove destroy tear',
  'record capture', 'cost money price expensive', 'hour hours', 'day daily', 'automatic automatically auto itself', 'cloud azure',
  'gateway door entry', 'refuse deny denied block reject', 'hold have keep own', 'expire end ends', 'nurse clinician', 'catch caught detect spot', 'borrow lend loan temporary', 'trust trusts accept',
  'pc laptop computer device', 'error mistake wrong', 'reason justification why', 'green pass passed', 'fast quick minute',
];
const SYN = new Map();
for (const g of GROUPS) { const ws = g.split(' ').map(stem); for (const w of ws) SYN.set(w, [...new Set([...(SYN.get(w) || []), ...ws])]); }

const NUM = { zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15,
  sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19, twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70, eighty: 80, ninety: 90 };
// "about five thousand" / "twenty-two" / "5,000" -> digits.
function numbers(t) {
  t = t.replace(/(\d),(\d{3})/g, '$1$2');
  return t.replace(/\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand)(?:[\s-]+|\b))+/g, (m) => {
    let total = 0, cur = 0;
    for (const w of m.trim().split(/[\s-]+/)) {
      if (w === 'hundred') cur = (cur || 1) * 100; else if (w === 'thousand') { total += (cur || 1) * 1000; cur = 0; } else cur += NUM[w] ?? 0;
    }
    return `${total + cur} `;
  });
}

export function stem(w) {
  w = w.toLowerCase().replace(/'s$/, '').replace(/’s$/, '');
  if (/^\d/.test(w) || w.length <= 3) return w;
  if (w.endsWith('ies') && w.length > 4) return w.slice(0, -3) + 'y';
  if (w.endsWith('ing') && w.length > 5) { w = w.slice(0, -3); return /(.)\1$/.test(w) ? w.slice(0, -1) : w; }
  if (w.endsWith('ed') && w.length > 4) { w = w.slice(0, -2); return /(.)\1$/.test(w) ? w.slice(0, -1) : w; }
  if (w.endsWith('es') && /(ss|sh|ch|x)es$/.test(w)) return w.slice(0, -2);
  if (w.endsWith('s') && !w.endsWith('ss') && w.length > 3) return w.slice(0, -1);
  return w;
}

// What whisper wrote -> the lab's spelling, before the meaning model reads it.
const RESPELL = [[/\bin ?tra\b/gi, 'Entra'], [/\boct?a\b/gi, 'Okta'], [/\bv'?s code\b/gi, 'VS Code'], [/\ba ?w ?s\b/gi, 'AWS'], [/\bd ?c ?(?:0|zero|o) ?(?:1|one)\b/gi, 'DC01'],
  [/\bservice now\b/gi, 'ServiceNow'], [/\borange h ?r ?m\b/gi, 'OrangeHRM'], [/\bin tune\b/gi, 'Intune'], [/\bterra form\b/gi, 'Terraform'], [/\bgrep tile\b/gi, 'Greptile'], [/\bcheck off\b/gi, 'Checkov']];
// And a word one letter off a lab name ("Entune", "Splonk") is that name.
const NAMES = ['Entra', 'Intune', 'Okta', 'Azure', 'Splunk', 'Sentinel', 'Terraform', 'Checkov', 'Bastion', 'Kubernetes', 'OrangeHRM', 'ServiceNow', 'GitHub', 'TruffleHog', 'Greptile', 'Contoso'];
function lev1(a, b) {   // edit distance <= 1
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0, j = 0, d = 0;
  while (i < a.length && j < b.length) { if (a[i] === b[j]) { i++; j++; continue; } if (++d > 1) return false; if (a.length > b.length) i++; else if (b.length > a.length) j++; else { i++; j++; } }
  return d + (a.length - i) + (b.length - j) <= 1;
}
export const respell = (t) => RESPELL.reduce((x, [re, to]) => x.replace(re, to), String(t))
  .replace(/[A-Za-z]{5,}/g, (w) => NAMES.find((n) => n.toLowerCase() !== w.toLowerCase() && lev1(n.toLowerCase(), w.toLowerCase())) || w);

export function normalize(t) {
  let x = ' ' + String(t).toLowerCase().replace(/\[[^\]]*\]/g, ' ').replace(/[“”"]/g, ' ').replace(/’/g, "'") + ' ';
  x = numbers(respell(x).toLowerCase());
  for (const [re, to] of ALIAS) x = x.replace(re, to);
  return x.replace(/[^a-z0-9&' ]+/g, ' ').replace(/\s+/g, ' ').trim();
}
export const tokens = (t) => normalize(t).split(' ').filter((w) => w && !STOP.has(w)).map(stem).filter((w) => w && !STOP.has(w));

// A point's key concepts: its content words, the lab's names and numbers
// weighted double (they carry the meaning a paraphrase still has to name).
export function concepts(text) {
  const named = new Set();
  // Capitalised words that are not the sentence's first word, acronyms, digits.
  String(text).replace(/\[[^\]]*\]/g, ' ').split(/(?<=[.!?:;])\s+/).forEach((s) => s.split(/\s+/).slice(1).forEach((w) => { if (/^[A-Z][a-zA-Z]|[A-Z]{2,}|\d/.test(w)) tokens(w).forEach((x) => named.add(x)); }));
  tokens(text).forEach((x) => { if (/\d/.test(x) || ALIAS.some(([, to]) => to === x)) named.add(x); });
  const seen = new Set(), out = [];
  for (const k of tokens(text)) if (!seen.has(k)) { seen.add(k); out.push({ k, w: named.has(k) ? 2 : 1 }); }
  return out;
}

export function coverage(con, said) {
  if (!con.length) return 0;
  const have = new Set(said);
  let got = 0, all = 0;
  for (const { k, w } of con) { all += w; if (have.has(k) || (SYN.get(k) || []).some((s) => have.has(s))) got += w; }
  return got / all;
}

// The step's say lines -> points: one sentence each (a line that ends without
// a full stop runs on into the next one).
export function derivePoints(say) {
  const pts = [];
  let cur = null;
  (say || []).forEach((line, i) => {
    const t = String(line).replace(/\[[^\]]*\]/g, ' ').replace(/\s+/g, ' ').trim();
    if (!t) return;
    if (!cur) cur = { text: '', lines: [] };
    cur.text = (cur.text ? cur.text + ' ' : '') + t; cur.lines.push(i);
    if (/[.!?]["')\]]*$/.test(t)) { pts.push(cur); cur = null; }
  });
  if (cur) pts.push(cur);
  return pts.map((p) => ({ ...p, key: concepts(p.text) }));
}

export const srcHash = (say) => crypto.createHash('sha1').update(JSON.stringify(say)).digest('hex').slice(0, 12);

// steps.points.json: { id: { src, points: [{ text, lines, key }] } }, written
// by tools/build-points.mjs. A step whose lines changed since (src differs)
// is derived again on the fly.
export function loadPointsFile(root) {
  try { return JSON.parse(fs.readFileSync(path.join(root, 'steps.points.json'), 'utf8')); } catch { return {}; }
}
export function pointsFor(step, file = {}) {
  const e = file[step.id];
  if (e && e.src === srcHash(step.say)) return e.points;
  return derivePoints(step.say);
}

// ---- embeddings ---------------------------------------------------------------
// One local model, loaded once; vectors of the points cached on disk by text.
export class Embedder {
  constructor({ root, log = () => {} } = {}) { this.root = root; this.log = log; this.mem = new Map(); this.cacheFile = root ? path.join(root, 'models', `points-emb-${MODEL.replace(/\W+/g, '_')}.json`) : null; this.dirty = false; }
  async load() {
    if (this.fe) return this;
    const { pipeline, env } = await import('@huggingface/transformers');
    env.cacheDir = path.join(this.root || '.', 'models', 'hf');
    const t0 = Date.now();
    this.fe = await pipeline('feature-extraction', MODEL, { dtype: 'fp32' });
    try { for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(this.cacheFile, 'utf8')))) this.mem.set(k, Float32Array.from(v)); } catch {}
    await this.embed(['warm up']);
    this.log(`speech: meaning model ready (${MODEL}, ${Date.now() - t0} ms)`);
    return this;
  }
  async embed(texts) {
    const need = [...new Set(texts.filter((t) => !this.mem.has(t)))];
    for (let i = 0; i < need.length; i += 32) {
      const part = need.slice(i, i + 32);
      const o = await this.fe(part, { pooling: 'mean', normalize: true });
      const d = o.dims[1];
      part.forEach((t, j) => this.mem.set(t, o.data.slice(j * d, (j + 1) * d)));
      this.dirty = true;
    }
    return texts.map((t) => this.mem.get(t));
  }
  save(keep) {   // only the points' vectors are worth keeping
    if (!this.cacheFile || !this.dirty) return;
    const out = {};
    for (const t of keep) if (this.mem.has(t)) out[t] = Array.from(this.mem.get(t), (x) => +x.toFixed(5));
    fs.mkdirSync(path.dirname(this.cacheFile), { recursive: true });
    fs.writeFileSync(this.cacheFile, JSON.stringify(out));
    this.dirty = false;
  }
}
export const isShort = (p) => p.key.length <= 2;
const cos = (a, b) => { let s = 0; for (let i = 0; i < a.length; i++) s += a[i] * b[i]; return s; };

// What he said -> the windows to compare: each sentence, two sentences in a
// row, and the whole utterance (with the end of the one before it).
export function windows(text, before = '') {
  text = respell(text); before = respell(before);
  const sents = String(text).split(/(?<=[.!?;])\s+|\s+(?:and then|and so|so then)\s+/i).map((s) => s.trim()).filter((s) => s.split(/\s+/).length >= 2);
  const w = new Set(sents);
  for (let i = 0; i + 1 < sents.length; i++) w.add(`${sents[i]} ${sents[i + 1]}`);
  if (text.trim()) w.add(text.trim());
  const tail = String(before).split(/(?<=[.!?])\s+/).slice(-1)[0];
  if (tail && sents[0]) w.add(`${tail} ${sents[0]}`);
  return [...w].filter((x) => tokens(x).length >= 1);
}

// Score every point of the step against every window. A window counts only
// for the point it matches best (already-said points compete too), so saying
// one point, or saying it again, never checks its neighbour.
export async function scorePoints(emb, points, text, before = '', tune = TUNE) {
  const ws = windows(text, before);
  const none = () => ({ score: 0, sem: 0, cov: 0, ok: false, win: '' });
  if (!ws.length || !points.length) return points.map(none);
  const [pv, wv] = [await emb.embed(points.map((p) => p.text)), await emb.embed(ws)];
  const wt = ws.map(tokens);
  const m = points.map((p, i) => ws.map((w, j) => { const sem = cos(pv[i], wv[j]), cov = coverage(p.key, wt[j]); return { sem, cov, score: sem + tune.W_COV * cov, win: w }; }));
  const owner = ws.map((w, j) => m.reduce((b, row, i) => (row[j].score > m[b][j].score ? i : b), 0));
  return points.map((p, i) => {
    let best = null;
    ws.forEach((w, j) => { if (owner[j] === i && (!best || m[i][j].score > best.score)) best = m[i][j]; });
    if (!best) return none();
    // A very short point ("All green.", "Let's start.") is too easy to cover
    // by accident: it needs the meaning alone (sem), no concept bonus.
    return { ...best, ok: isShort(p) ? best.sem >= tune.SHORT_T : best.score >= tune.T && best.sem >= tune.SEM_FLOOR };
  });
}
