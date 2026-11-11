// Stand-in narration for --preview: one clip per step from its teleprompter
// lines (tools/narrate.py, Kokoro am_michael in ~/.venvs/tts). Cached by text.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';

const PY = path.join(os.homedir(), '.venvs/tts/bin/python');

export async function makeNarration(list, dir, log = console.log) {
  fs.mkdirSync(dir, { recursive: true });
  const linesFile = path.join(dir, 'lines.json');
  fs.writeFileSync(linesFile, JSON.stringify(list.map((s) => ({ id: s.id, text: s.say.join(' ').replace(/\[[^\]]*\]/g, ' ').replace(/\s+/g, ' ').trim() })).filter((x) => /[A-Za-z]/.test(x.text)), null, 1));
  const script = new URL('../tools/narrate.py', import.meta.url).pathname;
  await new Promise((resolve, reject) => {
    const p = execFile(PY, ['-I', script, linesFile, dir], { timeout: 3600000, maxBuffer: 16 << 20 }, (e, so, se) => (e ? reject(new Error(`narration: ${(se || e.message).trim().split('\n').slice(-3).join(' ')}`)) : resolve(so)));
    p.stdout.on('data', (d) => String(d).split('\n').filter(Boolean).forEach((l) => log(`narration: ${l}`)));
  });
  return JSON.parse(fs.readFileSync(path.join(dir, 'index.json'), 'utf8'));
}
