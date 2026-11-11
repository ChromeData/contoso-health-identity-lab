// The presenter card's state: points, light and reason from the engine state.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { Presenter } from '../lib/presenter.mjs';

const root = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const step = { id: 'x-1', piece: 16, say: ['First point here.', 'Second point there.'] };
const fake = (extra = {}) => ({ list: [step], unattended: false, narration: {}, on: () => () => {}, state: () => ({}), ...extra });
const base = { i: 0, total: 1, busy: false, done: false, step: { id: 'x-1', piece: 16, pieceTitle: 'Checks' }, light: { color: 'green', text: '' }, inPiece: { k: 1, n: 1 } };

test('speech points map onto the card, the first unsaid one is hot', () => {
  const P = new Presenter(fake(), { root });
  const pts = P.points({ ...base, speech: { allowed: true, status: 'listening', points: [{ state: 'done' }, { state: 'todo' }] } });
  assert.deepEqual(pts.map((p) => p.state), ['done', 'hot']);
});

test('a skipped point shows as missed', () => {
  const P = new Presenter(fake(), { root });
  const pts = P.points({ ...base, speech: { allowed: true, status: 'listening', points: [{ state: 'missed' }, { state: 'done' }] } });
  assert.deepEqual(pts.map((p) => p.state), ['missed', 'done']);
});

test('unattended: the narration clock ticks points off', () => {
  const ck = fake({ unattended: true, narration: { 'x-1': { dur: 2 } } });
  const P = new Presenter(ck, { root }); P.stepAt = Date.now() - 1900;
  const pts = P.points({ ...base, lineStarted: Date.now() - 1500 });
  assert.equal(pts[0].state, 'done');
  assert.equal(pts[1].state, 'hot');
});

test('light: paused red, yellow wait amber with a short reason, cue wins otherwise', () => {
  const P = new Presenter(fake(), { root });
  assert.deepEqual(P.light({ ...base, held: true }), ['red', 'Paused']);
  assert.equal(P.light({ ...base, light: { color: 'yellow', text: 'GitHub is testing the change (about 3 minutes)' } })[0], 'amber');
  assert.deepEqual(P.light({ ...base, cue: { color: 'amber', reason: 'Loading page' } }), ['amber', 'Loading page']);
  assert.deepEqual(P.light({ ...base, i: -1, preflight: { running: false } }), ['green', 'READY']);
  assert.deepEqual(P.light({ ...base, error: 'boom' }), ['red', 'Needs you']);
});
