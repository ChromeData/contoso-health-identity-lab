// Writes a part's script-v2 table (time | screen | line) from steps.mjs and the
// preview's timeline, with times mapped through tighten.py's cuts.
//   node tools/script-table.mjs <piece> <untightened.mp4> <timeline.json>
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { stepsV2 } from '../steps.mjs';
const [piece, untight, tl] = process.argv.slice(2);
const FF = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
let log = ''; try { execFileSync(FF, ['-i', untight, '-af', 'silencedetect=noise=-40dB:d=1.6', '-f', 'null', '-'], { stdio: ['ignore', 'ignore', 'pipe'] }); } catch (e) { log = String(e.stderr || ''); }
if (!log) log = execFileSync('/bin/sh', ['-c', `"${FF}" -i "${untight}" -af silencedetect=noise=-40dB:d=1.6 -f null - 2>&1`]).toString();
const st = [...log.matchAll(/silence_start: ([\d.]+)/g)].map((m) => +m[1]), en = [...log.matchAll(/silence_end: ([\d.]+)/g)].map((m) => +m[1]);
const skip = +piece === 0 ? 16 : 0, cuts = [];
st.forEach((s, i) => { const e = en[i] ?? 1e9; if (e - s > 1.6 && s >= skip) cuts.push([s + 0.8, e - 0.8]); });
const map = (t) => t - cuts.reduce((a, [x, y]) => a + (t > y ? y - x : t > x ? t - x : 0), 0);
const at = Object.fromEntries(JSON.parse(fs.readFileSync(tl, 'utf8')).steps.filter((s) => s.piece === +piece).map((s) => [s.id, s.at]));
const screen = (s) => s.do.map((a) => a.do === 'map.focus' ? `v24 map: ${a.target}` : a.do === 'web.open' ? (typeof a.url !== 'string' ? 'Live page (this run)' : a.url.startsWith('file:') ? `Captured screen: ${a.url.split('/').slice(-1)[0]}` : `Live page: ${a.url.replace(/^https?:\/\/([^/]+).*/, '$1')}`) : a.do === 'web.highlight' ? `highlight "${typeof a.tag === 'string' ? a.tag : ''}"` : a.do === 'code.file' ? `VS Code: ${String(a.file).split('/').pop()} ${a.line}-${a.endLine}` : a.do).join('; ');
const mmss = (t) => `${Math.floor(t / 60)}:${String(Math.round(t % 60)).padStart(2, '0')}`;
const rows = stepsV2({ v2: {}, bp: '', tourOut: '' }).filter((s) => s.piece === +piece).map((s) => (s.previewSay ? { ...s, say: [...s.previewSay, `(Live take: ${s.say.join(' ')})`] } : s))
  .map((s) => `| ${at[s.id] != null ? mmss(map(at[s.id])) : '?'} | ${screen(s)} | ${s.say.join(' ')} |`);
console.log('| Time | Screen | Line |\n|---|---|---|\n' + rows.join('\n'));
