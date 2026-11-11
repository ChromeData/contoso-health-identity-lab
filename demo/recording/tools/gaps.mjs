#!/usr/bin/env node
// Dead time in a recorded part: still picture that nobody talks over.
//
//   node tools/gaps.mjs <part>.mp4 [watch-lines.json] [--min 1.5]
//
// The picture: ffmpeg freezedetect (still for at least --min seconds). The
// talk: each line's recorded start and length (watch-lines.json, written by
// --watch next to its recordings; the narration clip's length). A still
// stretch is dead where no line is being said. Prints each dead gap, the
// longest, and the totals.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const min = argv.includes('--min') ? +argv[argv.indexOf('--min') + 1] : 1.5;
const [video, linesFile] = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--min');
if (!video) { console.error('usage: node tools/gaps.mjs <part>.mp4 [watch-lines.json] [--min 1.5]'); process.exit(1); }
const FF = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
const len = +execFileSync(FF.replace(/ffmpeg$/, 'ffprobe'), ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', video], { encoding: 'utf8' }).trim();
const out = (() => { try { return execFileSync('sh', ['-c', `"${FF}" -hide_banner -nostats -i "${video}" -vf "scale=640:-1,freezedetect=n=0.003:d=${min}" -an -f null - 2>&1`], { encoding: 'utf8', maxBuffer: 64 << 20 }); } catch (e) { return String(e.stdout || ''); } })();
const freezes = [];
let start = null;
for (const l of out.split('\n')) {
  const s = /freeze_start: ([\d.]+)/.exec(l); if (s) start = +s[1];
  const e = /freeze_end: ([\d.]+)/.exec(l); if (e && start != null) { freezes.push([start, +e[1]]); start = null; }
}
if (start != null) freezes.push([start, len]);
const uniq = [...new Map(freezes.map((f) => [f.join(), f])).values()].sort((a, b) => a[0] - b[0]);
const part = path.basename(video).match(/^(N\d+)/)?.[1];
let talk = [];
if (linesFile && fs.existsSync(linesFile)) {
  const L = JSON.parse(fs.readFileSync(linesFile, 'utf8')).filter((x) => x.at != null && (!part || `N${String(x.piece).padStart(2, '0')}` === part));
  talk = L.map((x) => [x.at, x.at + (x.clip || 0)]);
}
// Freeze minus talk.
const dead = [];
for (const [a, b] of uniq) {
  let segs = [[a, b]];
  for (const [ta, tb] of talk) segs = segs.flatMap(([x, y]) => (tb <= x || ta >= y ? [[x, y]] : [[x, Math.max(x, ta)], [Math.min(y, tb), y]]).filter(([p, q]) => q - p > 0.05));
  dead.push(...segs.filter(([x, y]) => y - x >= min));
}
const talkLen = talk.reduce((n, [a, b]) => n + Math.max(0, Math.min(b, len) - a), 0);
const deadLen = dead.reduce((n, [a, b]) => n + b - a, 0);
const longest = dead.reduce((m, [a, b]) => Math.max(m, b - a), 0);
// Any recorded time with no line being said (moving or not), and its longest stretch.
const marks = [...talk].sort((a, b) => a[0] - b[0]); let cur = 0, quietMax = 0, quiet = 0;
for (const [a, b] of marks) { if (a > cur) { quiet += a - cur; quietMax = Math.max(quietMax, a - cur); } cur = Math.max(cur, b); }
if (len > cur) { quiet += len - cur; quietMax = Math.max(quietMax, len - cur); }
console.log(`${path.basename(video)}: ${len.toFixed(1)} s recorded${talk.length ? `, ${talkLen.toFixed(1)} s of lines, ${quiet.toFixed(1)} s with no line (longest ${quietMax.toFixed(1)} s)` : ''}; still for ${min}+ s with nobody talking: ${dead.length} gap(s), ${deadLen.toFixed(1)} s, longest ${longest.toFixed(1)} s`);
for (const [a, b] of dead) console.log(`  ${a.toFixed(1)}-${b.toFixed(1)} s  (${(b - a).toFixed(1)} s)`);
