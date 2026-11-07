// Tests for the Contoso HR app: roster rules, the HTTP API (on a local file
// store), and the GitHub store's requests (with a fake `gh`). No network.
//   node --test lab/hr-app/tests/hr-app.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { parseRoster, serialiseRoster, hire, change, describe, nextEmployeeId, jobCatalogue, HEADER } from '../lib/roster.mjs';
import { FileStore, GitHubStore } from '../lib/store.mjs';
import { makeApp } from '../server.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CSV = join(here, '..', '..', 'scripts', 'mock-hr', 'hr_feed.csv');
const RULES = JSON.parse(await readFile(join(here, '..', '..', 'iga', 'birthright-rules.json'), 'utf8'));
const shipped = await readFile(CSV, 'utf8');

function fresh() { const r = parseRoster(shipped); return { r, cat: jobCatalogue(RULES, r.workers) }; }

test('the shipped roster round-trips byte for byte (the header comments stay)', () => {
  assert.equal(serialiseRoster(parseRoster(shipped)), shipped.endsWith('\n') ? shipped : shipped + '\n');
});

test('HR issues the employee number: next IT hire is 400104, next nurse 100493', () => {
  const { r } = fresh();
  assert.equal(nextEmployeeId(r.workers, 'Information Technology', 'Cloud Engineer'), '400104');
  assert.equal(nextEmployeeId(r.workers, 'Nursing', 'Registered Nurse'), '100493');
  assert.equal(nextEmployeeId(r.workers, 'Billing', 'Billing Manager'), '200031');
  assert.equal(nextEmployeeId(r.workers, 'Administration', 'Chief Medical Officer'), '300002');
});

test('hire: a joiner row with the issued number, status joiner, no end date', () => {
  const { r, cat } = fresh();
  const out = hire(r, { givenName: ' Alex ', surname: 'Kim', dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', startDate: '2026-11-09' }, cat);
  assert.equal(out.kind, 'hired');
  assert.deepEqual(out.worker, { employeeId: '100493', givenName: 'Alex', surname: 'Kim', dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', status: 'joiner', startDate: '2026-11-09', endDate: '' });
  assert.match(serialiseRoster(out.roster), /\n100493,Alex,Kim,Nursing,Registered Nurse,200015,joiner,2026-11-09,\n$/);
  assert.equal(describe(out), 'HR: hire Alex Kim, Registered Nurse (Nursing)');
});

test('hire refuses: commas or quotes in names, unknown jobs, bad dates, left managers, duplicates', () => {
  const { r, cat } = fresh();
  const ok = { givenName: 'Alex', surname: 'Kim', dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', startDate: '2026-11-09' };
  assert.throws(() => hire(r, { ...ok, surname: 'Kim,leaver' }, cat), /letters only/);
  assert.throws(() => hire(r, { ...ok, givenName: '"x' }, cat), /letters only/);
  assert.throws(() => hire(r, { ...ok, jobTitle: 'Global Administrator' }, cat), /not in the job catalogue/);
  assert.throws(() => hire(r, { ...ok, startDate: '2026-02-30' }, cat), /real date/);
  assert.throws(() => hire(r, { ...ok, manager: '100205' }, cat), /has left/);
  assert.throws(() => hire(r, { ...ok, manager: '999999' }, cat), /not on the roster/);
  assert.throws(() => hire(r, { ...ok, givenName: 'Grace', surname: 'Mwangi' }, cat), (e) => e.status === 409);
});

test('change: leaver needs a last day, keeps the number, and refuses a manager with reports', () => {
  const { r, cat } = fresh();
  const h = hire(r, { givenName: 'Alex', surname: 'Kim', dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', startDate: '2026-11-02' }, cat);
  const out = change(h.roster, '100493', { status: 'leaver', endDate: '2026-11-06' }, cat);
  assert.equal(out.kind, 'left');
  assert.equal(out.worker.status, 'leaver');
  assert.equal(out.worker.endDate, '2026-11-06');
  assert.equal(describe(out), 'HR: Alex Kim leaves');
  assert.throws(() => change(h.roster, '100493', { status: 'leaver', endDate: '2026-11-01' }, cat), /before the start date/);
  assert.throws(() => change(r, '200015', { status: 'leaver', endDate: '2026-11-06' }, cat), /still manages/);
  assert.throws(() => change(r, '123456', { status: 'leaver' }, cat), (e) => e.status === 404);
  assert.throws(() => change(r, '100310', { status: 'active' }, cat), /Nothing changed/);
});

test('change: a new job is a mover; a leaver set back to active is a return and loses the end date', () => {
  const { r, cat } = fresh();
  const m = change(r, '100310', { dept: 'Nursing', jobTitle: 'Registered Nurse' }, cat);
  assert.equal(m.kind, 'moved');
  assert.equal(describe(m), 'HR: Marcus Bello moves from Registered Nurse (ICU) to Registered Nurse (Nursing)');
  const back = change(r, '100205', { status: 'active' }, cat);
  assert.equal(back.kind, 'rehired');
  assert.equal(back.worker.endDate, '');
});

test('nothing in the model or the page asks for or shows a password', async () => {
  const page = await readFile(join(here, '..', 'public', 'index.html'), 'utf8');
  assert.doesNotMatch(page, /password|passwd|secret/i);
  assert.ok(!HEADER.toLowerCase().includes('pass'));
});

// ---- HTTP API on a local file store ----------------------------------------
async function serve() {
  const dir = await mkdtemp(join(tmpdir(), 'hrapp-'));
  const file = join(dir, 'roster.csv');
  await writeFile(file, shipped);
  const app = makeApp({ store: new FileStore({ file }), rules: RULES, token: 't0k', today: () => '2026-11-06' });
  const srv = createServer(app);
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const post = (p, b, h = {}) => fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Form-Token': 't0k', ...h }, body: JSON.stringify(b) });
  return { srv, base, file, post };
}

test('API: the page carries the form token; hire then leave writes the roster', async (t) => {
  const s = await serve(); t.after(() => s.srv.close());
  const page = await (await fetch(s.base + '/')).text();
  assert.match(page, /const TOKEN = 't0k'/);
  assert.match(page, /value="2026-11-06"/);
  const list = await (await fetch(s.base + '/api/workers')).json();
  assert.ok(list.jobs.some((j) => j.dept === 'Nursing' && j.jobTitle === 'Registered Nurse'));
  const r1 = await s.post('/api/workers', { givenName: 'Alex', surname: 'Kim', dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', startDate: '2026-11-06' });
  assert.equal(r1.status, 201);
  const j1 = await r1.json();
  assert.equal(j1.worker.employeeId, '100493');
  const d = await (await fetch(`${s.base}/api/delivery/${j1.commit}`)).json();
  assert.equal(d.state, 'local');
  const r2 = await s.post('/api/workers/100493', { status: 'leaver', endDate: '2026-11-06' });
  assert.equal(r2.status, 200);
  assert.match(await readFile(s.file, 'utf8'), /\n100493,Alex,Kim,Nursing,Registered Nurse,200015,leaver,2026-11-06,2026-11-06\n$/);
});

test('API: a write without the form token, or not JSON, is refused and changes nothing', async (t) => {
  const s = await serve(); t.after(() => s.srv.close());
  const before = await readFile(s.file, 'utf8');
  const r1 = await s.post('/api/workers', { givenName: 'A', surname: 'B' }, { 'X-Form-Token': 'nope' });
  assert.equal(r1.status, 403);
  const r2 = await fetch(s.base + '/api/workers', { method: 'POST', headers: { 'Content-Type': 'text/plain', 'X-Form-Token': 't0k' }, body: '{}' });
  assert.equal(r2.status, 415);
  const r3 = await s.post('/api/workers', { givenName: 'Alex', surname: 'Kim', dept: 'Nursing', jobTitle: 'IT Director', startDate: '2026-11-06' });
  assert.equal(r3.status, 400);
  assert.equal(await readFile(s.file, 'utf8'), before);
});

// ---- GitHub store with a fake gh --------------------------------------------
test('GitHubStore: reads the hr-feed file, writes with its sha over stdin, maps a 409 to a conflict', async () => {
  const calls = [];
  let fail = false;
  const run = async (args, input) => {
    calls.push({ args, input });
    if (args.includes('PUT')) {
      if (fail) { const e = new Error('x'); e.stderr = 'gh: HTTP 409: is at abc but expected def'; throw e; }
      return JSON.stringify({ commit: { sha: 'c0ffee', committer: { date: '2026-11-07T01:00:00Z' } } });
    }
    if (args[1].includes('/actions/')) return JSON.stringify({ workflow_runs: [{ status: 'completed', conclusion: 'success', html_url: 'u', updated_at: '2026-11-07T01:01:00Z' }] });
    return JSON.stringify({ sha: 'blob1', content: Buffer.from(shipped).toString('base64') });
  };
  const g = new GitHubStore({ repo: 'o/r', branch: 'hr-feed', run });
  const { text, version } = await g.read();
  assert.equal(text, shipped);
  assert.equal(version, 'blob1');
  assert.match(calls[0].args[1], /contents\/lab\/scripts\/mock-hr\/hr_feed\.csv\?ref=hr-feed$/);
  const c = await g.write('x\n', 'blob1', 'HR: hire Alex Kim, Registered Nurse (Nursing)');
  assert.equal(c.commit, 'c0ffee');
  const body = JSON.parse(calls[1].input);
  assert.deepEqual([body.sha, body.branch, Buffer.from(body.content, 'base64').toString()], ['blob1', 'hr-feed', 'x\n']);
  assert.ok(!calls[1].args.join(' ').includes(body.content), 'content goes over stdin, not argv');
  assert.equal((await g.delivery('c0ffee')).state, 'accepted', 'a green run is accepted, not confirmed');
  assert.match(calls.at(-1).args[1], /head_sha=c0ffee&event=push&/, 'a manual dry run on the same commit must not count as delivered');
  fail = true;
  await assert.rejects(g.write('y\n', 'blob1', 'm'), (e) => e.conflict === true);
});

test('change: a stale edit (the record changed after HR opened it) is refused', () => {
  const { r, cat } = fresh();
  const opened = r.workers.find((w) => w.employeeId === '100310');
  const left = change(r, '100310', { status: 'leaver', endDate: '2026-11-06' }, cat).roster;
  assert.throws(() => change(left, '100310', { expected: opened, status: 'active', dept: 'Nursing', jobTitle: 'Registered Nurse' }, cat), (e) => e.status === 409 && /changed by someone else/.test(e.message));
  assert.equal(change(r, '100310', { expected: opened, dept: 'Nursing', jobTitle: 'Registered Nurse' }, cat).kind, 'moved');
});

test('API: a foreign Host or Origin (DNS rebinding) is refused, page and token included', async (t) => {
  const s = await serve(); t.after(() => s.srv.close());
  const { request } = await import('node:http');
  const get = (headers) => new Promise((ok, no) => {
    const u = new URL(s.base);
    request({ host: u.hostname, port: u.port, path: '/', headers }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => ok({ status: res.statusCode, body: b })); }).on('error', no).end();
  });
  const evil = await get({ Host: 'attacker.example:8484' });
  assert.equal(evil.status, 404);
  assert.doesNotMatch(evil.body, /t0k/);
  assert.equal((await get({ Host: 'localhost:8484' })).status, 200);
  const r = await s.post('/api/workers', {}, { Origin: 'http://attacker.example' });
  assert.equal(r.status, 403);
});

test('API: two hires at once both land, with different numbers (saves are queued)', async (t) => {
  const s = await serve(); t.after(() => s.srv.close());
  const h = (g) => s.post('/api/workers', { givenName: g, surname: 'Kim', dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', startDate: '2026-11-06' });
  const [a, b] = await Promise.all([h('Alex'), h('Blair')]);
  assert.deepEqual([a.status, b.status], [201, 201]);
  const ids = [(await a.json()).worker.employeeId, (await b.json()).worker.employeeId].sort();
  assert.deepEqual(ids, ['100493', '100494']);
  const text = await readFile(s.file, 'utf8');
  assert.match(text, /Alex,Kim/); assert.match(text, /Blair,Kim/);
});

test('hire refuses an account name that is already taken (other split, or a leaver) and names with a space', () => {
  const { r, cat } = fresh();
  const ok = { dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', startDate: '2026-11-09' };
  const a = hire(r, { ...ok, givenName: 'Alex.J', surname: 'Kim' }, cat);
  assert.throws(() => hire(a.roster, { ...ok, givenName: 'Alex', surname: 'J.Kim' }, cat), (e) => e.status === 409 && /alex\.j\.kim already belongs to Alex\.J Kim/.test(e.message));
  // Dana Okafor is a leaver: her disabled account still exists in AD.
  assert.throws(() => hire(r, { ...ok, givenName: 'Dana', surname: 'Okafor' }, cat), (e) => e.status === 409 && /a leaver whose account still exists/.test(e.message));
  assert.throws(() => hire(r, { ...ok, givenName: 'Mary Ann', surname: 'Kim' }, cat), /hyphen/);
  assert.equal(hire(r, { ...ok, givenName: 'Mary-Ann', surname: 'Kim' }, cat).worker.employeeId, '100493');
});

test('change: a future last day is refused (Leaver switches the account off now); today or earlier is fine', () => {
  const { r, cat } = fresh();
  assert.throws(() => change(r, '100310', { status: 'leaver', endDate: '2026-12-01' }, cat, '2026-11-06'), /switches the account off now/);
  assert.equal(change(r, '100310', { status: 'leaver', endDate: '2026-11-06' }, cat, '2026-11-06').kind, 'left');
  assert.equal(change(r, '100310', { status: 'leaver', endDate: '2026-11-01' }, cat, '2026-11-06').kind, 'left');
});

test('change: a manager who reports to the worker (a loop) is refused', () => {
  const { r, cat } = fresh();
  // Marcus Bello (100310) reports to Grace Mwangi (200015), who reports to Helen Carter (300001).
  assert.throws(() => change(r, '200015', { manager: '100310' }, cat), /reports to this worker/);
  assert.throws(() => change(r, '300001', { manager: '100310' }, cat), /reports to this worker/);
  assert.equal(change(r, '100310', { manager: '200021' }, cat).worker.manager, '200021');
});
