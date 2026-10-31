#!/usr/bin/env node
// Lab demo video director.
//   node director.mjs state               copy the signed-in admin session from Chrome (out/video/state, chmod 600)
//   node director.mjs clean               delete that session copy (do this when recording is done)
//   node director.mjs ids                 resolve tenant object ids (cached in out/video/ids.json)
//   node director.mjs map                 build out/video/map-video.html (map with tenant status)
//   node director.mjs tts                 narration audio per beat (cached by text)
//   node director.mjs record [scene...]   record scenes (all when none given); --dry = 2 s beats + stills
//   python3 assemble.py                   cut, mux, crossfade, subtitles -> out/video/*.mp4
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Rec, OUT, REPO, STATE, CDP, chromium } from './rec.mjs';
import { scenes } from './scenes.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const [cmd, ...rest] = process.argv.slice(2);
const DRY = rest.includes('--dry');
const want = rest.filter((a) => !a.startsWith('--'));
const az = (...a) => execFileSync('az', a, { encoding: 'utf8' }).trim();
const graph = (u) => JSON.parse(az('rest', '--method', 'GET', '--url', `https://graph.microsoft.com/v1.0/${u}`));
fs.mkdirSync(OUT, { recursive: true });

function ids() {
  const f = path.join(OUT, 'ids.json');
  if (fs.existsSync(f) && cmd !== 'ids') return JSON.parse(fs.readFileSync(f, 'utf8'));
  const env = Object.fromEntries(fs.readFileSync(path.join(REPO, 'lab/setup/handback.env'), 'utf8').split('\n').filter((l) => /^[A-Z_]+=/.test(l)).map((l) => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1).replace(/^"|"$/g, '')]; }));
  const dom = env.CUSTOM_DOMAIN || 'contosohealthlab.com';
  const user = (u) => graph(`users/${u}@${dom}?$select=id`).id;
  const raj = graph(`users?$filter=startswith(userPrincipalName,'adm-raj')&$select=userPrincipalName`).value[0].userPrincipalName;
  const sp = graph(`servicePrincipals/${env.HR_PROV_SP_ID}?$select=appId`);
  const o = {
    tenantId: az('account', 'show', '--query', 'tenantId', '-o', 'tsv'),
    dana: user('dana.okafor'), priya: user('priya.nair'), rajUpn: raj,
    hrSpId: env.HR_PROV_SP_ID, hrAppId: sp.appId,
    vmId: az('vm', 'list', '--query', "[?name=='vm-dc01'].id|[0]", '-o', 'tsv'),
    stId: az('storage', 'account', 'list', '--query', "[?starts_with(name,'stidlabevidence')].id|[0]", '-o', 'tsv'),
  };
  fs.writeFileSync(f, JSON.stringify(o, null, 2)); fs.chmodSync(f, 0o600);
  return o;
}

// The Whisperglass lab map, with the tiles that now run in the tenant marked
// "RAN · tenant" (blue) and the "nothing in a tenant yet" copy updated.
const RAN_HARNESS = ['SPLUNK']; // proven on this machine's Splunk replay, not a tenant (E61)
const RAN_TENANT = ['HR', 'AGENT', 'AD', 'SYNC', 'ENTRA', 'LCW', 'DYNGRP', 'BIRTH', 'AP', 'SOD', 'CABASE', 'CARISK', 'CASESS', 'BG', 'PIM', 'HDAU', 'KV', 'LA', 'LEAVER', 'NHI', 'EVID', 'WORM', 'KPI'];
// Sheet mode: one white grid sheet, chips top-left, zoom top-right, compact panel bottom-left (pages/sheet.css + sheet.js).
function injectSheet(s) {
  const here = path.dirname(new URL(import.meta.url).pathname);
  const css = fs.readFileSync(path.join(here, 'pages', 'sheet.css'), 'utf8'), js = fs.readFileSync(path.join(here, 'pages', 'sheet.js'), 'utf8');
  const nums = fs.readFileSync(path.join(here, 'pages', 'sheet-numbers.js'), 'utf8');
  const ovr = JSON.parse(fs.readFileSync(path.join(here, 'pages', 'map-overrides.json'), 'utf8'));
  // plain names, purposes and definitions (the same file the map artifact uses)
  const re = /(<script type="application\/json" id="lab-data">)([\s\S]*?)(<\/script>)/;
  const d = JSON.parse(s.match(re)[2]);
  for (const st of d.stations) if (ovr.stations[st.id]) st.purpose = ovr.stations[st.id];
  for (const n of d.nodes) { if (ovr.nodes[n.id]) { n.definition = ovr.nodes[n.id][0]; n.analogy = ovr.nodes[n.id][1]; } if (ovr.names[n.id]) n.name = ovr.names[n.id]; }
  s = s.replace(re, (_, a, __, c) => a + JSON.stringify(d).replace(/</g, '\\u003c') + c);
  // numbering 7..16 on pills and chips, and a handle for sheet-numbers.js (safe to run twice)
  s = s.replace('pillShape(pin, s.title, s.pillW, PILL_H);', 'pillShape(pin, (s.i + 7) + " · " + s.title, s.pillW + 46, PILL_H);');
  s = s.replace('data-go="station:${esc(s.id)}">${esc(s.title)}</button>`))', 'data-go="station:${esc(s.id)}">${s.i + 7} ${esc(s.title)}</button>`))');
  s = s.replace('data-go="delivery">Delivery</button>', 'data-go="delivery">16 Delivery</button>');
  if (!s.includes('window.__lab = ')) s = s.replace('  function flyTo(', "  window.__lab = { flyTo, fitRect, select, W, L, NB, get cam() { return cam; }, panel: document.getElementById('panel'), chips: document.getElementById('chips'), svg };\n  function flyTo(");
  s = s.replace(/<style id="sheet">[\s\S]*?<\/style>\n?/, '').replace(/<script id="sheetjs">[\s\S]*?<\/script>\n?/, '').replace(/<script id="sheetnum">[\s\S]*?<\/script>\n?/, '');
  return s.replace('</body>', `<style id="sheet">\n${css}</style>\n<script id="sheetjs">\n${js}</script>\n<script id="sheetnum">\n${nums}</script>\n</body>`);
}
function buildMap() {
  const src = process.env.LAB_MAP_HTML || path.join(process.env.HOME, 'whisperglass/labs/contoso-health/map.html');
  let s = fs.readFileSync(src, 'utf8');
  const re = /(<script type="application\/json" id="lab-data">)([\s\S]*?)(<\/script>)/;
  const d = JSON.parse(s.match(re)[2]);
  for (const n of d.nodes) if (RAN_TENANT.includes(n.id)) n.status = 'RAN · tenant';
  for (const n of d.nodes) if (RAN_HARNESS.includes(n.id)) n.status = 'RAN · harness';
  for (const st of d.delivery.steps) st.status = 'RAN · tenant';
  s = s.replace(re, (_, a, __, c) => a + JSON.stringify(d).replace(/</g, '\\u003c') + c);
  s = s.replace('RAN · tenant: none yet', 'RAN · tenant').replace('RAN · tenant: nothing yet.', 'RAN · tenant: running in the lab tenant now.').replace("Plan and apply haven't run: no tenant yet.", 'Plan and apply now run against the lab tenant.').replace(/Nothing has run in a Microsoft tenant yet: that's the\s+next step\./, 'Now running in a real Microsoft Entra tenant.');
  s = injectSheet(s);
  fs.writeFileSync(path.join(OUT, 'map-video.html'), s);
  console.log('map-video.html written', RAN_TENANT.length, 'tiles marked RAN · tenant');
}

const AUD = path.join(OUT, 'audio');
const voice = process.env.VIDEO_VOICE || 'onyx';
const hash = (t) => crypto.createHash('sha256').update(voice + '|' + t).digest('hex').slice(0, 16);
const dur = (f) => parseFloat(execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', f], { encoding: 'utf8' }));

async function tts() {
  fs.mkdirSync(AUD, { recursive: true });
  const all = scenes(ids()).filter((s) => s.kind !== 'clip').flatMap((s) => s.beats.map((b, i) => ({ s: s.id, i, say: b.say, audio: b.audio })));
  // A beat may bring its own recording (b.audio): copied into the cache under its text hash, never synthesized.
  for (const x of all) { if (x.audio && !fs.existsSync(path.join(AUD, hash(x.say) + '.mp3'))) fs.copyFileSync(x.audio, path.join(AUD, hash(x.say) + '.mp3')); }
  const todo = all.filter((x) => !fs.existsSync(path.join(AUD, hash(x.say) + '.mp3')));
  console.log(`${all.length} beats, ${todo.length} to synthesize`);
  const run = promisify(execFile);
  for (let k = 0; k < todo.length; k += 4) {
    await Promise.all(todo.slice(k, k + 4).map(async (x) => {
      const txt = path.join(AUD, hash(x.say) + '.txt'); fs.writeFileSync(txt, x.say);
      await run('python3', [path.join(here, 'tts.py'), path.join(AUD, hash(x.say) + '.mp3'), voice, txt]);
      console.log('tts', x.s, x.i);
    }));
  }
  const index = {};
  for (const x of all) { const f = path.join(AUD, hash(x.say) + '.mp3'); (index[x.s] ||= [])[x.i] = { file: f, dur: dur(f), say: x.say }; }
  fs.writeFileSync(path.join(AUD, 'index.json'), JSON.stringify(index, null, 2));
  const total = Object.values(index).flat().reduce((a, b) => a + b.dur, 0);
  console.log(`narration total ${(total / 60).toFixed(1)} min`);
}

// The admin session for portal scenes: copied from the signed-in Chrome on the
// debugging port, kept chmod 600 in a gitignored folder, deleted by `clean`.
async function exportState() {
  const b = await chromium.connectOverCDP(CDP);
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  await b.contexts()[0].storageState({ path: STATE }); fs.chmodSync(STATE, 0o600);
  await b.close(); console.log('admin session copied (delete with: node director.mjs clean)');
}

async function record() {
  const I = ids();
  if (!fs.existsSync(STATE)) await exportState();
  const index = DRY ? null : JSON.parse(fs.readFileSync(path.join(AUD, 'index.json'), 'utf8'));
  for (const sc of scenes(I).filter((s) => !want.length || want.some((w) => s.id.startsWith(w)))) {
    if (sc.kind === 'clip') {   // an external clip (e.g. the presenter): no recording, assemble.py drops it in as-is
      fs.mkdirSync(path.join(OUT, 'raw'), { recursive: true });
      fs.writeFileSync(path.join(OUT, 'raw', `${sc.id}.timeline.json`), JSON.stringify({ id: sc.id, clip: sc.clip, beats: [] }));
      console.log(`[${sc.id}] clip ${sc.clip}`); continue;
    }
    const r = new Rec(sc.id, sc.kind, { zoom: sc.zoom ?? (sc.kind === 'local' ? 1 : 1.25) });
    try {
      await r.open();
      for (let i = 0; i < sc.beats.length; i++) {
        const d = DRY ? 2 : index[sc.id][i].dur;
        const first = i === 0, last = i === sc.beats.length - 1;
        const hold = d + 0.35 + (first ? 0.5 : 0) + (last ? 0.8 : 0);
        await r.beat(i, d, { ...sc.beats[i], minHold: Math.max(hold, sc.beats[i].minHold || 0) });
        if (DRY) await r.page.screenshot({ path: path.join(OUT, 'raw', `${sc.id}-${i}.png`) });
      }
    } catch (e) {
      console.log(`[${sc.id}] ERROR ${e.message.split('\n')[0]}`);
      await r.page?.screenshot({ path: path.join(OUT, 'raw', `${sc.id}-error.png`) }).catch(() => {});
    } finally { await r.close().catch((e) => console.log(`[${sc.id}] close: ${e.message}`)); }
  }
}

if (cmd === 'ids') console.log(Object.keys(ids()).join(', '));
else if (cmd === 'map') buildMap();
else if (cmd === 'sheet') { const f = path.join(OUT, 'map-video.html'); fs.writeFileSync(f, injectSheet(fs.readFileSync(f, 'utf8'))); console.log('sheet injected'); }
else if (cmd === 'tts') await tts();
else if (cmd === 'record') await record();
else if (cmd === 'state') await exportState();
else if (cmd === 'clean') { fs.rmSync(STATE, { force: true }); console.log('admin session copy deleted'); }
else console.log('usage: director.mjs state|clean|ids|map|tts|record [scene...] [--dry]');
