// Precompute each step's key points (lib/points.mjs) into steps.points.json,
// next to steps.mjs, and cache their sentence vectors (models/points-emb.json).
// Run it after editing the say lines:  node tools/build-points.mjs
// (The cockpit derives a changed step's points on the fly anyway.)
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { steps, stepsV2 } from '../steps.mjs';
import { derivePoints, srcHash, Embedder } from '../lib/points.mjs';

const root = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const DEMO = path.join(os.homedir(), 'contoso-demo');
const c = { mode: 'dry', today: '2026-11-05', bp: path.join(DEMO, 'blueprints'), hr: path.join(DEMO, 'hr'), bpBranch: 'x', bpBranchRe: '^x$', prTitle: 't', prBody: 'b',
  tourLab: path.join(root, '.tour-main'), tourOut: path.join(root, 'tour', 'out'), v2: {} };
export function allSteps() { return [...steps(c), ...stepsV2(c)]; }
if (import.meta.url === `file://${process.argv[1]}`) {
  const out = {};
  for (const s of allSteps()) out[s.id] = { src: srcHash(s.say), points: derivePoints(s.say) };
  fs.writeFileSync(path.join(root, 'steps.points.json'), JSON.stringify(out, null, 1) + '\n');
  const texts = Object.values(out).flatMap((e) => e.points.map((p) => p.text));
  console.log(`${Object.keys(out).length} steps, ${texts.length} points -> steps.points.json`);
  if (!process.argv.includes('--no-embed')) {
    const emb = await new Embedder({ root, log: console.log }).load();
    await emb.embed(texts); emb.save(texts);
    console.log(`vectors cached in models/points-emb.json`);
  }
}
