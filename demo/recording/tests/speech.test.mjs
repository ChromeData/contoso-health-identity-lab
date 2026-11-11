// End to end, no microphone: speech made with macOS `say` (paraphrases, not
// the script's words, plus off-topic talk) goes through the same path as the
// microphone (ffmpeg -> voice detector -> whisper-server -> meaning matcher)
// into a stand-in cockpit. Skipped when the speech model is not downloaded.
//   node --test tests/speech.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { attachSpeech } from '../lib/speech.mjs';
import { derivePoints } from '../lib/points.mjs';

const root = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const ready = fs.existsSync(path.join(root, 'models', 'ggml-base.en.bin')) && fs.existsSync('/usr/bin/say');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Sentences -> one 16 kHz WAV with a second of silence between them.
function speak(lines, file) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'speech-test-'));
  const parts = lines.map((l, i) => { const f = path.join(dir, `${i}.wav`); execFileSync('/usr/bin/say', ['-v', 'Samantha', '-o', f, '--data-format=LEI16@16000', l]); return f; });
  const sil = path.join(dir, 'sil.wav');
  execFileSync('/opt/homebrew/bin/ffmpeg', ['-v', 'error', '-y', '-f', 'lavfi', '-i', 'anullsrc=r=16000:cl=mono', '-t', '1.2', '-c:a', 'pcm_s16le', sil]);
  const list = path.join(dir, 'list.txt');
  fs.writeFileSync(list, [sil, ...parts.flatMap((p) => [p, sil])].map((p) => `file '${p}'`).join('\n'));
  execFileSync('/opt/homebrew/bin/ffmpeg', ['-v', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', list, '-ar', '16000', '-ac', '1', '-c:a', 'pcm_s16le', file]);
  return file;
}

// The smallest cockpit the tracker needs: a step list, state events, NEXT.
function fakeCockpit(list) {
  const ls = new Set();
  const ck = { list, i: 0, mode: 'dry', busy: false, done: false, armed: null, light: { color: 'green', text: '' }, nexts: 0, lines: [],
    on(fn) { ls.add(fn); return () => ls.delete(fn); },
    state() { const s = list[this.i]; return { i: this.i, step: s ? { id: s.id, say: s.say } : null }; },
    emit() { const s = this.state(); for (const fn of ls) fn(s); },
    async next() { this.nexts++; this.i++; this.emit(); } };
  return ck;
}

async function run(step, lines, tmp) {
  const wavFile = speak(lines, path.join(tmp, `${step.id}.wav`));
  const ck = fakeCockpit([step, { id: 'after', piece: 0, say: ['The end.'] }]);
  const log = (m) => ck.lines.push(m);
  // Settings of this test only (not the presenter's .state/speech.json).
  const sp = await attachSpeech(ck, { root, log, enabled: true, file: wavFile, takesDir: path.join(tmp, 'takes') });
  sp.cfg = { ...sp.cfg, listen: true, autoAdvance: true };
  ck.emit();
  const eof = new Promise((r) => sp.listener.once('eof', r));
  await eof; await sp.work; await sleep(6500);     // past the "passed over" mark and the auto-advance pause
  const st = sp.state(), left = sp.take.visits.find((v) => v.step === step.id);
  sp.close();
  return { ck, st, left, tmp };
}

test('paraphrases check every point; off-topic talk checks none; auto-advance presses NEXT', { skip: !ready && 'no speech model (models/ggml-base.en.bin)', timeout: 180000 }, async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'speech-'));
  const step = { id: 'n00-azure', piece: 0, say: ['Head piece three: Azure and Intune.', 'Azure runs DC01, the evidence store, and the logs.', 'Intune manages the PCs.'] };
  const { ck, left } = await run(step, [
    'Okay, let me just wait for this page to load.',
    'The third main piece is Azure, together with Intune.',
    'My dog keeps barking in the other room.',
    'Azure is where we keep DC01, the evidence storage and all the logs.',
    'And Intune takes care of managing the computers.',
  ], tmp);
  assert.equal(ck.nexts, 1, `auto-advance should press NEXT once\n${ck.lines.join('\n')}`);
  assert.deepEqual(left.missed, [], ck.lines.join('\n'));
});

test('a point passed over stays marked, is in the take report, and NEXT is not pressed', { skip: !ready && 'no speech model', timeout: 180000 }, async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'speech-'));
  const step = { id: 'n01-nurse', piece: 1, say: ['Here is a real gap.', 'Nurses had AWS access they never use.', 'So I take AWS off the nurse package.'] };
  const { ck, st, tmp: t2 } = await run(step, ['So here is a real gap.', 'The weather is really nice out today.', 'So I am removing AWS from the nurse package.'], tmp);
  assert.equal(ck.nexts, 0, ck.lines.join('\n'));
  assert.deepEqual(st.points.map((p) => p.state), ['done', 'missed', 'done'], ck.lines.join('\n'));
  const md = fs.readFileSync(path.join(t2, 'takes', 'latest.md'), 'utf8');
  assert.match(md, /Nurses had AWS access they never use/);
});

test('points: a line split mid-sentence joins the next one', async () => {
  const p = derivePoints(['And the rule: every cloud engineer gets that package on day one,', 'straight from their job title in HR.', 'All green.']);
  assert.equal(p.length, 2); assert.deepEqual(p[0].lines, [0, 1]);
});
