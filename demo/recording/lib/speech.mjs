// The speech-aware teleprompter: it listens (lib/listen.mjs), checks each
// key point of the step off when its MEANING was said (lib/points.mjs), keeps
// the points not said faintly marked, writes a report per take, and (setting,
// on by default) presses NEXT by itself once every point of the step is said.
//
// Hooks into the cockpit without changing the engine: it reads the step from
// the cockpit's own state events, adds `speech` to the teleprompter's state,
// and auto-advance calls the same ck.next() as the NEXT key.
import fs from 'node:fs';
import path from 'node:path';
import { Listener } from './listen.mjs';
import { Embedder, loadPointsFile, pointsFor, scorePoints, TUNE } from './points.mjs';

// Names whisper should spell the lab's way (a glossary, never script lines:
// a prompt of whole sentences makes it "hear" them in silence).
const GLOSSARY = 'Contoso Health, Entra ID, Azure, Intune, AWS, Okta, PIM, ServiceNow, OrangeHRM, Active Directory, DC01, Cloud Sync, Key Vault, Bastion, Sentinel, Splunk, SIEM, KQL, SPL, MITRE ATT&CK, GitHub, Terraform, VS Code, Checkov, TruffleHog, Greptile, Conditional Access, LAPS, AD FS, Kubernetes, Sam Rivera, Raj Patel.';
const SKIPPED_AFTER = 5000;   // a point passed over this long while a later one is said: marked "not said yet"
// auto-advance waits until he has been quiet this long (2026-11-10 #2: was
// 1.2 s; the next step's page is already loaded, so a short beat is enough).
const ADVANCE_QUIET = +(process.env.COCKPIT_ADVANCE_QUIET || 600);

export async function attachSpeech(ck, { root, log = console.log, enabled = true, file = null, takesDir = null } = {}) {
  const T = new Tracker(ck, { root, log, enabled, file, takesDir });
  await T.init();
  return T;
}

class Tracker {
  constructor(ck, { root, log, enabled, file, takesDir }) {
    Object.assign(this, { ck, root, log, file });
    this.takesDir = takesDir || path.join(root, 'takes');
    this.settingsFile = path.join(root, '.state', 'speech.json');
    const saved = (() => { try { return JSON.parse(fs.readFileSync(this.settingsFile, 'utf8')); } catch { return {}; } })();
    // listen / autoAdvance are the presenter's settings (L and A keys); model and mic only in the file.
    this.cfg = { listen: true, autoAdvance: true, model: 'base.en', mic: 'default', ...saved };
    this.allowed = enabled;           // off for unattended runs (--preview, --auto, --no-listen)
    this.visit = null; this.history = {}; this.heard = ''; this.speaking = false; this.lastFinal = '';
    this.take = { started: new Date(), visits: [] };
    this.pfile = loadPointsFile(root);
    this.work = Promise.resolve();
  }

  async init() {
    // The teleprompter's state gets a `speech` part; step changes come from the cockpit's own events.
    const base = this.ck.state.bind(this.ck);
    this.ck.state = () => ({ ...base(), speech: this.state() });
    this.ck.on((s) => this.onCockpit(s));
    // The engine's line clock (actions that follow his words): his first
    // words, each point said.
    this.ck.speechHook = this;
    this.timer = setInterval(() => this.tick(), 300);
    if (this.allowed && this.cfg.listen) this.start().catch((e) => this.log(`speech: ${e.message}`));
  }

  saveCfg() { try { fs.writeFileSync(this.settingsFile, JSON.stringify(this.cfg, null, 1)); } catch {} }

  async start() {
    if (!this.allowed) { this.log('speech: listening is off for unattended runs'); return; }
    this.emb ||= new Embedder({ root: this.root, log: this.log });
    if (!this.listener) {
      this.listener = new Listener({ root: this.root, log: this.log, model: this.cfg.model, mic: this.cfg.mic, file: this.file, prompt: GLOSSARY });
      this.listener.on('state', ({ state, note }) => { this.log(`speech: ${state}${note ? ` (${note})` : ''}`); this.ck.emit(); });
      this.listener.on('speaking', (v) => { this.speaking = v; if (!v) this.quietSince = Date.now(); this.ck.emit(); });
      this.listener.on('partial', (u) => this.heardText(u, false));
      this.listener.on('final', (u) => this.heardText(u, true));
    }
    await Promise.all([this.emb.load(), this.listener.start()]);
    this.ck.emit();
  }
  async toggleListen() {
    this.cfg.listen = !this.cfg.listen; this.saveCfg();
    if (this.cfg.listen) await this.start(); else this.listener?.stop();
    this.log(`speech: listening ${this.cfg.listen ? 'on' : 'off'}`); this.ck.emit();
  }
  async toggleAuto() { this.cfg.autoAdvance = !this.cfg.autoAdvance; this.saveCfg(); this.log(`speech: auto-advance ${this.cfg.autoAdvance ? 'on' : 'off'}`); this.ck.emit(); }
  get listening() { return this.listener?.state === 'listening'; }
  // Resolves when he starts talking (or a point is said), or after ms.
  // Immediately when nobody is listening.
  waitSpeaking(ms = 2500) { return this.until(() => this.speaking || this.visit?.points.some((p) => p.done), ms); }
  // Resolves when point k of this step is said (or a later one), or after ms.
  waitPoint(k, ms = 8000) { return this.until(() => { const ps = this.visit?.points || []; return k < 0 || k >= ps.length || ps.slice(k).some((p) => p.done); }, ms); }
  async until(fn, ms) {
    if (!this.allowed || !this.listening) return;
    for (const end = Date.now() + ms; Date.now() < end && !fn();) await new Promise((r) => setTimeout(r, 60));
  }

  // ---- steps ------------------------------------------------------------------
  onCockpit(s) {
    const id = s.step?.id || null;
    if (this.visit && this.visit.id === id && this.visit.i === s.i) return;
    if (this.visit) this.leave();
    if (!id) { this.visit = null; return; }
    const step = this.ck.list[s.i];
    const points = pointsFor(step, this.pfile).map((p) => ({ ...p, done: false }));
    // Points this step missed the last time (BACK, a retake): marked from the start.
    const before = this.history[id];
    if (before) points.forEach((p, k) => { p.priorMissed = before.missed.includes(p.text); });
    this.visit = { id, i: s.i, piece: step.piece, points, at: Date.now(), said: [], advanced: false };
    if (this.emb?.fe) this.emb.embed(points.map((p) => p.text)).catch(() => {});
  }
  leave() {
    const v = this.visit; this.visit = null;
    const missed = v.points.filter((p) => !p.done).map((p) => p.text);
    const rec = { step: v.id, piece: v.piece, at: new Date(v.at).toISOString(), secs: Math.round((Date.now() - v.at) / 1000), listening: this.listening,
      points: v.points.map((p) => ({ text: p.text, said: p.done, heard: p.heard || null, score: p.score ?? null })), missed, transcript: v.said.join(' ') };
    // Only a visit that was listened to says anything about what was said.
    if (!rec.listening && !v.said.length) return;
    this.history[v.id] = rec;
    this.take.visits.push(rec);
    this.lastLeft = missed.length ? { id: v.id, n: missed.length, texts: missed } : null;
    this.writeReport();
  }

  // ---- what he said -------------------------------------------------------------
  heardText(u, final) {
    this.heard = u.text;
    this.ck.emit();
    const v = this.visit;
    if (!v) return;
    if (final) v.said.push(u.text);
    if (process.env.COCKPIT_SPEECH_DEBUG) this.log(`speech: heard${final ? '' : ' (so far)'} "${u.text}"`);
    // One match at a time, in order (the embedder is single-threaded anyway).
    this.work = this.work.then(() => this.match(v, u.text, final)).catch((e) => this.log(`speech: match: ${e.message}`));
  }
  async match(v, text, final) {
    if (this.visit !== v || !this.emb?.fe) return;
    if (!v.points.some((p) => !p.done)) return;
    const before = final ? v.said.slice(-2, -1)[0] || '' : v.said.slice(-1)[0] || '';
    const r = await scorePoints(this.emb, v.points, text, before, TUNE);
    if (process.env.COCKPIT_SPEECH_DEBUG) this.log(`speech: scores ${JSON.stringify(r.map((x) => [+x.sem.toFixed(2), x.ok]))}`);
    let n = 0;
    r.forEach((x, k) => {
      const p = v.points[k];
      if (!x.ok || p.done) return;
      Object.assign(p, { done: true, at: Date.now(), heard: x.win, score: +x.score.toFixed(3) }); n++;
      this.log(`speech: ✓ "${p.text}"  (heard "${x.win}", ${x.sem.toFixed(2)}/${x.cov.toFixed(2)})`);
    });
    if (n) this.ck.emit();
  }

  // ---- auto-advance ---------------------------------------------------------------
  tick() {
    const v = this.visit, ck = this.ck;
    if (!v) return;
    // A point he went past: a later one is said, this one is not (yet).
    let changed = false;
    v.points.forEach((p, k) => {
      const later = v.points.slice(k + 1).find((q) => q.done && Date.now() - q.at > SKIPPED_AFTER);
      const skipped = !p.done && !!later;
      if (skipped !== !!p.skipped) { p.skipped = skipped; changed = true; }
    });
    if (changed) ck.emit();
    if (!this.cfg.autoAdvance || !this.listening || v.advanced || !v.points.length || v.points.some((p) => !p.done)) return;
    if (this.speaking || Date.now() - (this.quietSince || 0) < ADVANCE_QUIET) return;
    if (ck.held || ck.busy || ck.done || ck.armed || ['yellow', 'blue', 'red'].includes(ck.light?.color) || ck.waitActive) return;
    if (ck.i + 1 >= ck.list.length) return;   // the last step: finishing stays a key press
    v.advanced = true;
    this.log(`speech: all ${v.points.length} points of [${v.id}] said: NEXT`);
    ck.next().catch((e) => this.log(`speech: next: ${e.message}`));
  }

  // ---- the take report ---------------------------------------------------------------
  // takes/<date>/<time>-<mode>.json (every visit) and .md (what still needs
  // saying: each step's LATEST visit with points not said).
  writeReport() {
    const t = this.take.started, day = t.toISOString().slice(0, 10), stamp = t.toTimeString().slice(0, 8).replace(/:/g, '');
    const dir = path.join(this.takesDir, day);
    try {
      fs.mkdirSync(dir, { recursive: true });
      const base = path.join(dir, `${stamp}-${this.ck.mode}`);
      fs.writeFileSync(`${base}.json`, JSON.stringify({ started: t.toISOString(), mode: this.ck.mode, tune: TUNE, visits: this.take.visits }, null, 1));
      const latest = Object.values(this.history);
      const todo = latest.filter((r) => r.missed.length);
      const md = [`# Take report ${day} ${t.toTimeString().slice(0, 5)} (${this.ck.mode})`, '',
        `${latest.length} steps heard · ${latest.reduce((n, r) => n + r.points.length, 0)} points · ${todo.reduce((n, r) => n + r.missed.length, 0)} not said`, '',
        todo.length ? '## Still to say (re-record)' : '## Every point was said', '',
        ...todo.flatMap((r) => [`- **${r.step}** (piece ${r.piece}, ${r.missed.length} of ${r.points.length})`, ...r.missed.map((m) => `  - ${m}`)]), ''].join('\n');
      fs.writeFileSync(`${base}.md`, md);
      fs.writeFileSync(path.join(this.takesDir, 'latest.md'), md);
    } catch (e) { this.log(`speech: report: ${e.message}`); }
  }

  state() {
    const v = this.visit, L = this.listener;
    return {
      allowed: this.allowed, listen: this.cfg.listen, auto: this.cfg.autoAdvance,
      status: !this.allowed ? 'off' : !this.cfg.listen ? 'paused' : (L?.state || 'starting'), note: L?.note || '',
      speaking: this.speaking, heard: this.heard.slice(-90),
      points: v ? v.points.map((p) => ({ lines: p.lines, state: p.done ? 'done' : (p.skipped || p.priorMissed) ? 'missed' : 'todo' })) : [],
      said: v ? v.points.filter((p) => p.done).length : 0, total: v ? v.points.length : 0, advanced: !!v?.advanced,
      lastMissed: this.lastLeft && this.lastLeft.id !== v?.id ? this.lastLeft : null,
    };
  }
  close() { clearInterval(this.timer); if (this.visit) this.leave(); this.listener?.close(); this.emb?.save([...new Set(Object.values(this.pfile).flatMap((e) => e.points.map((p) => p.text)))]); }
}
