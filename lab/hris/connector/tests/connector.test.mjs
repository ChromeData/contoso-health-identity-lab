// Tests for the HR connector (OrangeHRM -> the hr-feed outbox): the
// reconcile rules, the GitHub store's requests (fake `gh`), the seed load
// and the view's column list. No database, no network, no npm install.
//   node --test lab/hris/connector/tests/connector.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFeed, serialiseFeed, reconcile, describe, hospitalToday, MAX_ACCESS_CHANGES, FeedError } from '../lib/feed.mjs';
import { GitHubStore } from '../lib/store.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CSV = join(here, '..', '..', '..', 'scripts', 'mock-hr', 'hr_feed.csv');
const shipped = await readFile(CSV, 'utf8');
const TODAY = '2026-11-09';

// What OrangeHRM's view returns for a feed row (the go-live load).
const asView = (w) => ({
  employee_id: w.employeeId, first_name: w.givenName, last_name: w.surname, department: w.dept,
  job_title: w.jobTitle, manager_id: w.manager || null, joined_date: w.startDate,
  termination_date: w.status === 'leaver' ? w.endDate : null,
});
const ADMIN = { employee_id: '0001', first_name: 'HR', last_name: 'Administrator', department: null, job_title: null, manager_id: null, joined_date: null, termination_date: null };
function live() {
  const feed = parseFeed(shipped);
  return { feed, view: [ADMIN, ...feed.workers.map(asView)] };
}
const SAM = { employee_id: '400104', first_name: 'Sam', last_name: 'Rivera', department: 'Information Technology', job_title: 'IAM Engineer', manager_id: '400100', joined_date: '2026-11-09', termination_date: null };

test('the shipped feed round-trips byte for byte (the header comments stay)', () => {
  assert.equal(serialiseFeed(parseFeed(shipped)), shipped.endsWith('\n') ? shipped : shipped + '\n');
});

test('go-live: OrangeHRM loaded with the roster finds nothing to send; its own admin record is never sent', () => {
  const { feed, view } = live();
  const out = reconcile(feed, view, TODAY);
  assert.deepEqual(out.changes, []);
  assert.deepEqual(out.held, []);
  assert.equal(serialiseFeed(out.feed), serialiseFeed(feed));
});

test('hire: a new OrangeHRM worker becomes one joiner row; the commit line names job and department only', () => {
  const { feed, view } = live();
  const out = reconcile(feed, [...view, SAM], TODAY);
  assert.equal(out.changes.length, 1);
  const c = out.changes[0];
  assert.equal(c.kind, 'hired');
  assert.deepEqual(c.worker, { employeeId: '400104', givenName: 'Sam', surname: 'Rivera', dept: 'Information Technology', jobTitle: 'IAM Engineer', manager: '400100', status: 'joiner', startDate: '2026-11-09', endDate: '' });
  assert.match(serialiseFeed(out.feed), /\n400104,Sam,Rivera,Information Technology,IAM Engineer,400100,joiner,2026-11-09,\n$/);
  assert.equal(describe(c), 'HR: hire Sam Rivera, IAM Engineer (Information Technology)');
  assert.ok(!/400104|400100|2026/.test(describe(c)), 'no number or date in the public commit message');
});

test('a hire HR has not finished (no Job tab yet) is held, and nothing is written for it', () => {
  const { feed, view } = live();
  const out = reconcile(feed, [...view, { ...SAM, department: null, job_title: null, joined_date: null }], TODAY);
  assert.deepEqual(out.changes, []);
  assert.equal(out.held.length, 1);
  assert.match(out.held[0].why, /Job tab is not finished/);
});

test('held: a space in a name, an account name already taken (a leaver too), a supervisor who has left', () => {
  const { feed, view } = live();
  const why = (row) => reconcile(feed, [...view, row], TODAY).held[0]?.why ?? '';
  assert.match(why({ ...SAM, first_name: 'Mary Ann' }), /space/);
  assert.match(why({ ...SAM, employee_id: '100493', first_name: 'Dana', last_name: 'Okafor' }), /dana\.okafor already belongs to employee 100492/);
  assert.match(why({ ...SAM, manager_id: '100492' }), /not a current worker/);
  assert.match(why({ ...SAM, first_name: 'Sam,' }), /character/);
  assert.match(why({ ...SAM, manager_id: null }), /no supervisor yet/);
});

test('job change: a new Job Title or Sub Unit is a mover; the status stays', () => {
  const { feed, view } = live();
  const v = view.map((r) => (r.employee_id === '100310' ? { ...r, department: 'Nursing' } : r));
  const out = reconcile(feed, v, TODAY);
  assert.equal(out.changes.length, 1);
  assert.equal(out.changes[0].kind, 'moved');
  assert.equal(out.changes[0].worker.status, 'active');
  assert.equal(describe(out.changes[0]), 'HR: Marcus Bello moves from Registered Nurse (ICU) to Registered Nurse (Nursing)');
});

test('leaver: Terminate Employment dated today sends a leaver with that end date', () => {
  const { feed, view } = live();
  const out = reconcile(feed, view.map((r) => (r.employee_id === '100488' ? { ...r, termination_date: TODAY } : r)), TODAY);
  assert.equal(out.changes[0].kind, 'left');
  assert.equal(out.changes[0].worker.status, 'leaver');
  assert.equal(out.changes[0].worker.endDate, TODAY);
});

test('leaver dated in the future: nothing is written until that day, then it is sent', () => {
  const { feed, view } = live();
  const v = view.map((r) => (r.employee_id === '100488' ? { ...r, termination_date: '2026-11-20' } : r));
  const before = reconcile(feed, v, TODAY);
  assert.deepEqual(before.changes.filter((c) => c.write), []);
  assert.equal(before.changes[0].kind, 'scheduled');
  assert.equal(serialiseFeed(before.feed), serialiseFeed(feed));
  const onTheDay = reconcile(feed, v, '2026-11-20');
  assert.equal(onTheDay.changes[0].kind, 'left');
});

test('rehire: a feed leaver whose termination HR reverses comes back as active, with no end date', () => {
  const { feed, view } = live();
  const out = reconcile(feed, view.map((r) => (r.employee_id === '100205' ? { ...r, termination_date: null } : r)), TODAY);
  assert.equal(out.changes[0].kind, 'rehired');
  assert.equal(out.changes[0].worker.status, 'active');
  assert.equal(out.changes[0].worker.endDate, '');
});

test('a worker missing from OrangeHRM (deleted or purged) is never removed from the feed and sends nothing', () => {
  const { feed, view } = live();
  const out = reconcile(feed, view.filter((r) => r.employee_id !== '100477'), TODAY);
  assert.deepEqual(out.changes, []);
  assert.deepEqual(out.notInHris, ['100477']);
  assert.equal(out.feed.workers.length, feed.workers.length);
});

test(`mass-change guard: more than ${MAX_ACCESS_CHANGES} leavers or movers in one sync writes nothing`, () => {
  const feed = parseFeed(shipped);
  const extra = Array.from({ length: 11 }, (_, i) => ({ employeeId: String(100600 + i), givenName: 'Test', surname: `Worker${'abcdefghijk'[i]}`, dept: 'Nursing', jobTitle: 'Registered Nurse', manager: '200015', status: 'active', startDate: '2024-01-01', endDate: '' }));
  const big = { ...feed, workers: [...feed.workers, ...extra] };
  const view = [...big.workers.map(asView)].map((r) => (r.employee_id.startsWith('1006') ? { ...r, termination_date: TODAY } : r));
  assert.throws(() => reconcile(big, view, TODAY), (e) => e instanceof FeedError && /11 leavers or job changes/.test(e.message));
});

test('hospitalToday uses the hospital time zone, not UTC', () => {
  assert.equal(hospitalToday(new Date('2026-11-08T02:30:00Z')), '2026-11-07');
});

test('GitHubStore: reads the hr-feed file, writes with its sha over stdin with the connector trailer, maps a 409 to a conflict', async () => {
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
  const c = await g.write('x\n', 'blob1', 'HR: hire Sam Rivera, IAM Engineer (Information Technology)');
  assert.equal(c.commit, 'c0ffee');
  const body = JSON.parse(calls[1].input);
  assert.deepEqual([body.sha, body.branch, Buffer.from(body.content, 'base64').toString()], ['blob1', 'hr-feed', 'x\n']);
  assert.match(body.message, /Entered in OrangeHRM; written by the HR connector/);
  assert.ok(!calls[1].args.join(' ').includes(body.content), 'content goes over stdin, not argv');
  assert.equal((await g.delivery('c0ffee')).state, 'accepted', 'a green run is accepted, not confirmed');
  assert.match(calls.at(-1).args[1], /head_sha=c0ffee&event=push&/, 'a manual dry run on the same commit must not count as delivered');
  fail = true;
  await assert.rejects(g.write('y\n', 'blob1', 'm'), (e) => e.conflict === true);
});

test('the seed load puts every feed worker into OrangeHRM, leavers with a termination, and carries no password', () => {
  const sql = execFileSync(process.execPath, [join(here, '..', '..', 'orangehrm', 'seed.mjs'), CSV], { encoding: 'utf8' });
  for (const w of parseFeed(shipped).workers) assert.ok(sql.includes(`'${w.employeeId}', '${w.givenName}', '${w.surname}'`), w.employeeId);
  assert.equal((sql.match(/INSERT INTO ohrm_emp_termination/g) ?? []).length, parseFeed(shipped).workers.filter((w) => w.status === 'leaver').length);
  assert.ok(!/password/i.test(sql));
});

test('the connector view has exactly the eight feed fields, and the code reads only that view', async () => {
  const view = await readFile(join(here, '..', '..', 'orangehrm', 'connector-view.sql'), 'utf8');
  const select = view.slice(view.indexOf('AS\nSELECT'), view.indexOf('\nFROM orangehrm.hs_hr_employee e'));
  const cols = [...select.matchAll(/\bAS (\w+)\s*,?\s*$/gm)].map((m) => m[1]);
  assert.deepEqual(cols, ['employee_id', 'first_name', 'last_name', 'department', 'job_title', 'manager_id', 'joined_date', 'termination_date']);
  const hris = await readFile(join(here, '..', 'lib', 'hris.mjs'), 'utf8');
  assert.deepEqual([...hris.matchAll(/FROM ([\w.]+)/g)].map((m) => m[1]), ['hr_feed.v_worker_feed']);
  const sh = await readFile(join(here, '..', '..', 'orangehrm', 'hris.sh'), 'utf8');
  assert.match(sh, /GRANT SELECT ON hr_feed\.v_worker_feed TO 'hr_connector'/);
  assert.ok(!/GRANT [^\n]*orangehrm\.[^\n]*hr_connector/.test(sh), 'no grant on OrangeHRM tables');
});

test('a due leaver goes out even when a hold would stop them (their supervisor left too, or a field was cleared)', () => {
  const { feed, view } = live();
  const nurse = feed.workers.find((w) => w.status !== 'leaver' && w.manager && feed.workers.some((m) => m.employeeId === w.manager && m.status !== 'leaver'));
  const rows = view.map((r) => (r.employee_id === nurse.employeeId || r.employee_id === nurse.manager ? { ...r, termination_date: TODAY } : r));
  const out = reconcile(feed, rows, TODAY);
  const mine = out.changes.find((c) => c.worker.employeeId === nurse.employeeId);
  assert.equal(mine?.kind, 'left');
  assert.equal(mine.worker.status, 'leaver');
  assert.equal(mine.worker.endDate, TODAY);
  assert.equal(mine.worker.dept, nurse.dept, 'sent from the last valid feed row');
  const cleared = reconcile(feed, view.map((r) => (r.employee_id === nurse.employeeId ? { ...r, department: null, termination_date: TODAY } : r)), TODAY);
  assert.equal(cleared.changes.find((c) => c.worker.employeeId === nurse.employeeId)?.kind, 'left');
  // Sent once: the next sync, with the feed now saying leaver, finds nothing.
  assert.deepEqual(reconcile(out.feed, rows, TODAY).changes.filter((c) => c.worker.employeeId === nurse.employeeId), []);
});

test('a finished hire with OrangeHRM\'s own number (not 6 digits) is held and named, never silently dropped; the admin record stays silent', () => {
  const { feed, view } = live();
  const out = reconcile(feed, [...view, { ...SAM, employee_id: '0015' }], TODAY);
  assert.equal(out.changes.length, 0);
  assert.equal(out.held.length, 1);
  assert.match(out.held[0].why, /6-digit hospital number/);
  assert.deepEqual(reconcile(feed, view, TODAY).held, [], 'the unfinished admin record (0001) is not reported');
});

