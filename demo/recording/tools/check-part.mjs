// check-part.mjs: a fast pass/fail check of one v2 part, nothing recorded,
// no screenshots, nothing in the lab changed.
//   node cockpit.mjs --check N13        (or: node tools/check-part.mjs N13)
// For every step it checks what can be checked before a take:
//   - files (code.file / code.highlight / code.diff, captured screens, videos):
//     they exist, the lines exist, and VS Code files sit inside the window's
//     workspace (the bridge refuses others);
//   - map targets: each map.focus target resolves on cockpit/map/v24.html;
//   - links: every fixed http(s) page loads in the signed-in recording
//     profile (headless), with no sign-in page and no "You don't have access";
//     links built during the run (the PR, an incident) are listed as RUNTIME;
//   - narration: each spoken line has its clip in narration/ (by text).
// Writes recordings/storyboards/<part>-check.md and prints the list.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { stepsV2, PIECES_V2 } from '../steps.mjs';
import { chromium } from '../lib/browser.mjs';

const ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const DEMO = path.join(os.homedir(), 'contoso-demo');
const arg = (process.argv[2] || '').replace(/^N/i, '').replace(/^(\d+)b$/i, '$1.5');
const n = +arg;
const piece = PIECES_V2.find((p) => p.n === n);
if (!piece) { console.error(`check: no such part ${process.argv[2]}`); process.exit(1); }

// The same folders the cockpit gives stepsV2 (read-only PR copies).
const v2 = { ws: path.join(ROOT, 'v2', 'contoso-demo-v2.code-workspace') };
for (const d of fs.readdirSync(path.join(ROOT, '.v2'))) v2[d] = path.join(ROOT, '.v2', d);
const c = { v2, bp: path.join(DEMO, 'blueprints'), tourLab: path.join(ROOT, '.tour-main'), tourOut: path.join(ROOT, 'tour', 'out'), tourWs: path.join(ROOT, 'tour', 'contoso-demo-tour.code-workspace'), hire: null };
const steps = stepsV2(c).filter((s) => s.piece === n);

const wsFolders = (ws) => { try { const j = JSON.parse(fs.readFileSync(ws, 'utf8').replace(/^\s*\/\/.*$/gm, '')); return j.folders.map((f) => path.resolve(path.dirname(ws), f.path)); } catch { return []; } };
const DEMO_WS = path.join(DEMO, 'contoso-demo.code-workspace');
const rows = [];
const add = (id, what, ok, note = '') => rows.push({ id, what, ok, note });
const lines = (f) => { try { return fs.readFileSync(f, 'utf8').split('\n').length; } catch { return 0; } };

const mapTargets = [], links = [];
let ws = DEMO_WS;   // the VS Code window carries over from step to step, as in the cockpit
for (const s of steps) {
  const acts = [...(s.do || []), ...(s.standIn || [])];
  for (const a of acts) {
    if (a.do === 'code.open' && a.ws) ws = a.ws;
    if (['code.file', 'code.highlight', 'code.diff', 'code.changes'].includes(a.do) && typeof a.file === 'string') {
      const exists = fs.existsSync(a.file);
      const inWs = wsFolders(ws).some((f) => a.file.startsWith(f + path.sep));
      const tooShort = exists && a.endLine && lines(a.file) < a.endLine;
      add(s.id, `${a.do} ${path.basename(a.file)}${a.line ? ` ${a.line}-${a.endLine || a.line}` : ''}`, exists && inWs && !tooShort,
        !exists ? 'file missing' : !inWs ? `not inside ${path.basename(ws)} (VS Code refuses it)` : tooShort ? `file has ${lines(a.file)} lines` : '');
    }
    if (['web.show', 'web.video'].includes(a.do) || (a.do === 'web.open' && typeof a.url === 'string' && a.url.startsWith('file:'))) {
      const f = decodeURIComponent(String(a.url).replace(/^file:\/\//, '').split('#')[0].split('?')[0]);
      add(s.id, `${a.do} ${path.basename(f)}`, fs.existsSync(f), fs.existsSync(f) ? '' : 'file missing');
    }
    if (a.do === 'map.focus') mapTargets.push({ id: s.id, t: a.target });
    if (a.do === 'web.open' && typeof a.url === 'string' && /^https?:/.test(a.url)) links.push({ id: s.id, url: a.url, ctx: a.ctx });
    if (a.do === 'web.open' && typeof a.url === 'function') add(s.id, 'web.open (link built during the run)', true, 'RUNTIME: checked when the part runs');
  }
  // Narration: the clip for this exact text.
  const text = s.say.join(' ').replace(/\[[^\]]*\]/g, ' ').replace(/\s+/g, ' ').trim();
  if (/[A-Za-z]/.test(text)) {
    const h = crypto.createHash('sha1').update('am_michael|' + text).digest('hex').slice(0, 12);
    const ok = fs.existsSync(path.join(ROOT, 'narration', `${h}.wav`));
    add(s.id, 'narration clip', ok, ok ? '' : 'not generated yet (made at the next render)');
  }
  if (s.previewSay) {
    const t2 = s.previewSay.join(' ').replace(/\s+/g, ' ').trim();
    const h2 = crypto.createHash('sha1').update('am_michael|' + t2).digest('hex').slice(0, 12);
    add(s.id, 'narration clip (preview line)', fs.existsSync(path.join(ROOT, 'narration', `${h2}.wav`)), '');
  }
}

// Map targets and links, in one headless browser on the recording profile.
if (mapTargets.length || links.length) {
  const ctx = await chromium.launchPersistentContext(path.join(ROOT, '.recording-profile'), { channel: 'chrome', headless: true, viewport: { width: 1728, height: 958 } })
    .catch((e) => { add('-', 'recording profile', false, `${e.message.split('\n')[0]} (is a cockpit running? close it first)`); return null; });
  if (ctx) {
    const p = await ctx.newPage();
    if (mapTargets.length) {
      await p.goto(`file://${path.join(ROOT, 'map', 'v24.html')}?video`); await p.waitForFunction(() => typeof window.__mapFocus === 'function', null, { timeout: 15000 }); await p.waitForTimeout(1500);
      for (const m of mapTargets) {
        const r = await p.evaluate(async (t) => { try { await window.__mapFocus(t); const z = window.__lab.cam.z; return { ok: true, z }; } catch (e) { return { ok: false, e: String(e.message || e) }; } }, m.t);
        add(m.id, `map ${m.t}`, r.ok, r.ok ? `zoom ${r.z.toFixed(2)}` : r.e);
      }
    }
    for (const l of links) {
      if (l.ctx) { add(l.id, `web.open ${new URL(l.url).host}`, true, `opens in the ${l.ctx} browser: not checked here`); continue; }
      try {
        await p.goto(l.url, { timeout: 45000, waitUntil: 'domcontentloaded' }); await p.waitForTimeout(8000);
        const body = (await Promise.all(p.frames().map((f) => f.evaluate(() => document.body?.innerText || '').catch(() => '')))).join('\n');
        const signin = /login\.microsoftonline|signin|\/login/i.test(p.url()) && !/entra\.microsoft\.com|portal\.azure/.test(p.url());
        const denied = /You don't have access|don't have permission|AccessDenied|401|403 Forbidden/i.test(body);
        add(l.id, `web.open ${new URL(l.url).host}`, !signin && !denied, signin ? `sign-in page (${p.url().slice(0, 60)})` : denied ? 'the page says no access' : '');
      } catch (e) { add(l.id, `web.open ${new URL(l.url).host}`, false, e.message.split('\n')[0]); }
    }
    await ctx.close();
  }
}

const bad = rows.filter((r) => !r.ok);
const md = [`# Check: ${piece.slug} (${new Date().toISOString().replace(/\.\d+Z$/, 'Z')})`, '', `${rows.length - bad.length} pass, ${bad.length} fail.`, '', '| Step | What | Result | Note |', '|---|---|---|---|',
  ...rows.map((r) => `| ${r.id} | ${r.what} | ${r.ok ? 'PASS' : '**FAIL**'} | ${r.note} |`)].join('\n');
const out = path.join(DEMO, 'recordings', 'storyboards'); fs.mkdirSync(out, { recursive: true });
const name = piece.slug.split('-')[0];
fs.writeFileSync(path.join(out, `${name}-check.md`), md + '\n');
for (const r of rows) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.id.padEnd(18)} ${r.what}${r.note ? `  (${r.note})` : ''}`);
console.log(`\n${rows.length - bad.length} pass, ${bad.length} fail · ${path.join(out, `${name}-check.md`)}`);
process.exit(bad.length ? 1 : 0);
