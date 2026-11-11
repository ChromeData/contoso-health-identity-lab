// Preview post step: put each step's stand-in narration clip at the moment
// the step started in the recording (OBS's own recorded time, so the spans
// paused during waits are already left out), one file per piece, then one
// preview-full.mp4. Video is copied, never re-encoded.
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';

const FFMPEG = fs.existsSync('/opt/homebrew/bin/ffmpeg') ? '/opt/homebrew/bin/ffmpeg' : 'ffmpeg';
const FFPROBE = fs.existsSync('/opt/homebrew/bin/ffprobe') ? '/opt/homebrew/bin/ffprobe' : 'ffprobe';
const run = (cmd, args) => new Promise((resolve, reject) => execFile(cmd, args, { maxBuffer: 64 << 20 }, (e, so, se) => (e ? reject(new Error(`${path.basename(cmd)}: ${(se || e.message).trim().split('\n').slice(-2).join(' ')}`)) : resolve(so))));

export async function duration(file) {
  return parseFloat(await run(FFPROBE, ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', file]));
}

// clips: [{ file, at }] with at in seconds from the start of `video`.
export async function mixPiece(video, clips, out) {
  const len = await duration(video);
  const use = clips.filter((c) => c.at < len);
  const args = ['-v', 'error', '-y', '-i', video];
  let filter, map;
  if (!use.length) {
    args.push('-f', 'lavfi', '-t', String(len), '-i', 'anullsrc=r=48000:cl=stereo');
    filter = null; map = ['-map', '0:v', '-map', '1:a'];
  } else {
    for (const c of use) args.push('-i', c.file);
    const parts = use.map((c, i) => `[${i + 1}:a]aresample=48000,adelay=${Math.round(c.at * 1000)}:all=1[a${i}]`);
    filter = `${parts.join(';')};${use.map((_, i) => `[a${i}]`).join('')}amix=inputs=${use.length}:normalize=0:dropout_transition=0,apad,atrim=0:${len.toFixed(3)}[aout]`;
    map = ['-map', '0:v', '-map', '[aout]'];
  }
  if (filter) args.push('-filter_complex', filter);
  args.push(...map, '-c:v', 'copy', '-c:a', 'aac', '-b:a', '160k', '-ac', '2', '-ar', '48000', '-movflags', '+faststart', out);
  await run(FFMPEG, args);
  return { out, len, clips: use.length, dropped: clips.length - use.length };
}

export async function concat(files, out) {
  const list = `${out}.txt`;
  fs.writeFileSync(list, files.map((f) => `file '${f.replace(/'/g, "'\\''")}'`).join('\n') + '\n');
  await run(FFMPEG, ['-v', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', list, '-c', 'copy', '-movflags', '+faststart', out]);
  fs.rmSync(list, { force: true });
  return out;
}

// pieces: [{ n, video }]; timeline: [{ id, piece, at }]; narration: {id: {file, dur}}
export async function buildPreview({ pieces, timeline, narration, dir, log = console.log }) {
  const mixed = [];
  for (const p of pieces.sort((a, b) => a.n - b.n)) {
    const clips = timeline.filter((t) => t.piece === p.n && narration[t.id]).map((t) => ({ file: narration[t.id].file, at: t.at }));
    const out = path.join(dir, `${path.basename(p.video).replace(/\.(mp4|mkv|mov)$/i, '')}.narrated.mp4`);
    const r = await mixPiece(p.video, clips, out);
    log(`preview: piece ${p.n}: ${r.clips} narration clips over ${r.len.toFixed(1)} s${r.dropped ? ` (${r.dropped} started after the piece ended, dropped)` : ''}`);
    mixed.push(out);
  }
  const full = path.join(dir, 'preview-full.mp4');
  if (mixed.length) await concat(mixed, full);
  log(`preview: ${full} (${mixed.length} pieces, ${(mixed.length ? await duration(full) : 0).toFixed(1)} s)`);
  return { full, pieces: mixed };
}
