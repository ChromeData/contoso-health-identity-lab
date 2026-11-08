// Offline tests for lab/servicenow/server/ContosoEntraAccess.js: the code that
// grants, removes and closes. It runs in a node:vm sandbox with small fakes of
// the ServiceNow globals it uses (GlideRecord, gs, GlideDateTime, sn_ws, sn_auth)
// and a scripted Graph. No instance, no tenant, no network.
//   node --test lab/servicenow/tests/entra-access.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
// Objects built inside the vm come from another realm: compare as plain data.
const plain = (o) => JSON.parse(JSON.stringify(o));
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(path.join(HERE, '..', 'server', 'ContosoEntraAccess.js'), 'utf8');
const PKGS = {
  icu_float: { accessPackageId: 'pkg-icu', assignmentPolicyId: 'pol-icu', label: 'ICU - Float Access' },
  pharmacy: { accessPackageId: 'pkg-ph', assignmentPolicyId: 'pol-ph', label: 'Pharmacy - Controlled Substances Apps' },
};

// ---- a GlideElement / GlideRecord stand-in ----------------------------------
function element(v, display, ref) {
  const val = v === undefined || v === null ? '' : String(v);
  const e = { toString: () => val, valueOf: () => val, nil: () => val === '', getDisplayValue: () => display ?? val, getJournalEntry: () => '' };
  return ref ? Object.assign(e, ref) : e;
}
function makeEnv({ graph, now = '2026-11-07 10:00:00' }) {
  const db = { sc_req_item: {}, sc_task: {}, sysapproval_approver: {}, sys_user_group: { g1: { sys_id: 'g1', name: 'IAM Operations' } } };
  const calls = [];
  class GlideRecord {
    constructor(table) { this._t = table; this._q = []; this._rows = []; this._i = -1; this._rec = null; }
    _wrap(rec) {
      this._rec = rec;
      return true;
    }
    get(a, b) {
      const rows = Object.values(db[this._t] || {});
      const r = b === undefined ? (db[this._t] || {})[a] : rows.find((x) => String(x[a]) === String(b));
      return r ? this._wrap(r) : false;
    }
    addQuery(f, op, v) { if (v === undefined) { v = op; op = '='; } this._q.push([f, op, v]); return { addOrCondition() {} }; }
    orderByDesc() {}
    query() { this._rows = Object.values(db[this._t] || {}).filter((r) => this._q.every(([f, op, v]) => op === 'IN' ? String(v).split(',').includes(String(r[f])) : String(r[f]) === String(v))); this._i = -1; }
    next() { this._i++; return this._i < this._rows.length ? this._wrap(this._rows[this._i]) : false; }
    getUniqueValue() { return this._rec.sys_id; }
    getValue(f) { return this._rec[f] === undefined ? null : String(this._rec[f]); }
    update() { calls.push(['update', this._t, { ...this._rec }]); }
  }
  const proxied = (Base) => new Proxy(Base, {
    construct(T, args) {
      const g = new T(...args);
      return new Proxy(g, {
        get(o, p) {
          if (p in o || typeof p === 'symbol') return typeof o[p] === 'function' ? o[p].bind(o) : o[p];
          const rec = o._rec || {};
          if (p === 'variables') return Object.fromEntries(Object.entries(rec.variables || {}).map(([k, v]) => [k, element(v)]));
          if (p === 'requested_for') return element(rec.requested_for?.sys_id, rec.requested_for?.name, { u_entra_object_id: element(rec.requested_for?.oid) });
          if (p === 'approver') return element(rec.approver, rec.approver);
          return element(rec[p]);
        },
        set(o, p, v) {
          if (p.startsWith('_')) { o[p] = v; return true; }
          if (p === 'work_notes') { (o._rec.notes ||= []).push(String(v)); return true; }
          o._rec[p] = typeof v === 'object' && v !== null ? String(v) : (typeof v === 'number' ? String(v) : v);
          return true;
        },
      });
    },
  });
  class GlideDateTime {
    constructor(x) { this.ms = x instanceof GlideDateTime ? x.ms : Date.parse(now.replace(' ', 'T') + 'Z'); }
    setDisplayValue(s) { this.ms = Date.parse(s.replace(' ', 'T') + 'Z'); }
    after(o) { return this.ms > o.ms; }
    addDaysUTC(n) { this.ms += n * 86400000; }
    getValue() { return new Date(this.ms).toISOString().slice(0, 19).replace('T', ' '); }
  }
  const sandbox = {
    GlideRecord: proxied(GlideRecord), GlideDateTime,
    Class: { create: () => function (...a) { this.initialize(...a); } },
    gs: { getProperty: (n, d) => ({ 'contoso.entra.tenant_id': 't', 'contoso.entra.fulfilment.client_id': 'c', 'contoso.entra.fulfilment.jwt_provider': 'p', 'contoso.entra.fulfilment.packages': JSON.stringify(PKGS), 'contoso.entra.iam_queue': 'IAM Operations' })[n] ?? d, generateGUID: () => 'guid' },
    GlideStringUtil: { base64Decode: (s) => Buffer.from(s, 'base64').toString() },
    encodeURIComponent, JSON, Math, String, Date,
  };
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox);
  const x = new sandbox.ContosoEntraAccess();
  // Token and Graph are stubbed at the method boundary: the code under test is
  // what decides WHAT to call and what to do with the answer.
  x.getToken = () => 'token';
  x.graph = (method, url, body) => { calls.push([method, url, body]); return graph(method, url, body); };
  const rec = (table, id) => { const g = new sandbox.GlideRecord(table); g.get(id); return g; };
  return { db, calls, x, rec, sandbox };
}

const ritm = (over = {}) => ({
  sys_id: 'r1', number: 'RITM0010099', approval: 'approved', active: 'true', state: '2', correlation_id: '',
  variables: { app_access: 'icu_float', business_reason: 'ICU float cover', start_date: '2026-11-07', end_date: '2026-11-21' },
  requested_for: { sys_id: 'u1', name: 'Sofia Reyes', oid: '4c4258f6-fa16-4d95-a421-af69a51adbb9' }, ...over,
});

test('approved request -> one adminAdd with the ticket number, package ref stored', () => {
  const env = makeEnv({ graph: () => ({ id: 'req-1', state: 'submitted' }) });
  env.db.sc_req_item.r1 = ritm();
  env.db.sysapproval_approver.a1 = { sys_id: 'a1', sysapproval: 'r1', state: 'approved', approver: 'Grace Mwangi' };
  assert.equal(env.x.fulfil(env.rec('sc_req_item', 'r1')), 'req-1');
  const posts = env.calls.filter((c) => c[0] === 'post');
  assert.equal(posts.length, 1);
  assert.equal(posts[0][2].requestType, 'adminAdd');
  assert.match(posts[0][2].justification, /^RITM0010099 \(ServiceNow\): approved by Grace Mwangi/);
  assert.deepEqual(plain(posts[0][2].assignment), { targetId: '4c4258f6-fa16-4d95-a421-af69a51adbb9', assignmentPolicyId: 'pol-icu', accessPackageId: 'pkg-icu' });
  assert.equal(env.db.sc_req_item.r1.correlation_id, 'pkg-icu/req-1');
});

for (const [why, over] of [
  ['rejected after the event was queued', { approval: 'rejected', active: 'false', state: '4' }],
  ['closed by someone', { active: 'false', state: '3' }],
  ['already sent once', { correlation_id: 'pkg-icu/req-0' }],
]) {
  test(`no grant when the request is ${why}`, () => {
    const env = makeEnv({ graph: () => { throw new Error('Graph must not be called'); } });
    env.db.sc_req_item.r1 = ritm(over);
    assert.equal(env.x.fulfil(env.rec('sc_req_item', 'r1')), null);
    assert.equal(env.calls.filter((c) => c[0] === 'post').length, 0);
    assert.match(env.db.sc_req_item.r1.notes.at(-1), /^Not sent to Entra/);
  });
}

test('end date more than 180 days after the start -> refused, sent to the IAM queue', () => {
  const env = makeEnv({ graph: () => { throw new Error('Graph must not be called'); } });
  env.db.sc_req_item.r1 = ritm({ variables: { app_access: 'icu_float', start_date: '2026-11-07', end_date: '2027-06-01' } });
  assert.equal(env.x.fulfil(env.rec('sc_req_item', 'r1')), null);
  assert.equal(env.db.sc_req_item.r1.assignment_group, 'g1');
  assert.match(env.db.sc_req_item.r1.notes.join('\n'), /more than 180 days/);
});

test('180 days exactly is allowed (boundary)', () => {
  const env = makeEnv({ graph: () => ({ id: 'req-2', state: 'submitted' }), now: '2026-11-07 00:00:00' });
  env.db.sc_req_item.r1 = ritm({ variables: { app_access: 'icu_float', start_date: '2026-11-07', end_date: '2027-05-05' } });
  assert.equal(env.x.fulfil(env.rec('sc_req_item', 'r1')), 'req-2');
});

test('Entra refusal (400) -> nothing stored as sent, ticket to IAM with the reason', () => {
  const env = makeEnv({ graph: () => { throw 'Graph POST /x -> 400 InvalidRequest: {"accessPackageAssignments":["ICU - Critical Care Apps"]}'; } });
  env.db.sc_req_item.r1 = ritm({ variables: { app_access: 'pharmacy', start_date: '2026-11-07', end_date: '2026-12-07' } });
  assert.equal(env.x.fulfil(env.rec('sc_req_item', 'r1')), null);
  assert.equal(env.db.sc_req_item.r1.correlation_id, '');
  assert.equal(env.db.sc_req_item.r1.assignment_group, 'g1');
  assert.match(env.db.sc_req_item.r1.notes.join('\n'), /400 InvalidRequest.*ICU - Critical Care Apps/);
});

test('"another app" maps to no package -> IAM decides by hand, no Graph call', () => {
  const env = makeEnv({ graph: () => { throw new Error('Graph must not be called'); } });
  env.db.sc_req_item.r1 = ritm({ variables: { app_access: 'other', start_date: '2026-11-07', end_date: '2026-11-21' } });
  assert.equal(env.x.fulfil(env.rec('sc_req_item', 'r1')), null);
  assert.match(env.db.sc_req_item.r1.notes.join('\n'), /No Entra access package is mapped/);
});

test('leaver: a later failure keeps the removal already accepted (tracked + shown)', () => {
  const env = makeEnv({
    graph: (m, url) => {
      if (m === 'get' && url.includes("pkg-icu")) return { value: [{ id: 'asg-1', state: 'delivered' }] };
      if (m === 'post') return { id: 'rm-1' };
      throw 'Graph GET -> 503 ServiceUnavailable';
    },
  });
  env.db.sc_task.t1 = { sys_id: 't1', number: 'SCTASK0010099', state: '1', correlation_id: '' };
  const person = { u_entra_object_id: 'ed258a73-ff42-4bb3-9144-15330b67fe0e' };
  assert.deepEqual(plain(env.x.removeAll(env.rec('sc_task', 't1'), person)), ['pkg-icu/rm-1']);
  const t = env.db.sc_task.t1;
  assert.equal(t.correlation_id, 'pkg-icu/rm-1', 'the poller must still follow the accepted removal');
  assert.equal(t.correlation_display, 'Entra ID Governance - partial');
  assert.equal(t.assignment_group, 'g1');
  assert.notEqual(String(t.state), '3', 'not closed while something failed');
  assert.match(t.notes.at(-1), /remove ICU - Float Access[\s\S]*Entra removal stopped: Graph GET -> 503/);
  const post = env.calls.find((c) => c[0] === 'post');
  assert.equal(post[2].justification, 'SCTASK0010099 (ServiceNow): leaver access removal');
});

test('leaver with nothing to remove closes the task', () => {
  const env = makeEnv({ graph: () => ({ value: [] }) });
  env.db.sc_task.t1 = { sys_id: 't1', number: 'SCTASK0010099', state: '1', correlation_id: '' };
  assert.deepEqual(plain(env.x.removeAll(env.rec('sc_task', 't1'), { u_entra_object_id: 'ed258a73-ff42-4bb3-9144-15330b67fe0e' })), []);
  assert.equal(String(env.db.sc_task.t1.state), '3');
});

test('poller: delivered closes; a failed read or a failed request goes to IAM, never closes', () => {
  for (const [answer, closed] of [[() => ({ value: [{ state: 'delivered' }] }), true], [() => ({ value: [{ state: 'deliveryFailed', status: 'x' }] }), false], [() => { throw 'Graph GET -> 403'; }, false], [() => ({ value: [] }), false]]) {
    const env = makeEnv({ graph: answer });
    env.db.sc_req_item.r1 = ritm({ correlation_id: 'pkg-icu/req-1', correlation_display: 'Entra ID Governance' });
    env.x._check(env.rec('sc_req_item', 'r1'));
    const r = env.db.sc_req_item.r1;
    assert.equal(String(r.state) === '3', closed);
    if (!closed) { assert.equal(r.assignment_group, 'g1'); assert.equal(r.correlation_display, 'Entra ID Governance - needs IAM'); }
    const get = env.calls.find((c) => c[0] === 'get');
    assert.match(get[1], /accessPackage%2Fid%20eq%20'pkg-icu'%20and%20id%20eq%20'req-1'/, 'every read names the package (catalog-role 403 otherwise)');
  }
});

test('partial leaver removal: the next poll sees Delivered but does NOT close the task', () => {
  const env = makeEnv({ graph: () => ({ value: [{ state: 'delivered' }] }) });
  env.db.sc_task.t1 = { sys_id: 't1', number: 'SCTASK0010099', state: '2', correlation_id: 'pkg-icu/rm-1', correlation_display: 'Entra ID Governance - partial' };
  env.x._check(env.rec('sc_task', 't1'));
  const t = env.db.sc_task.t1;
  assert.notEqual(String(t.state), '3');
  assert.equal(t.correlation_display, 'Entra ID Governance - needs IAM');
  assert.equal(t.assignment_group, 'g1');
  assert.match(t.notes.at(-1), /never sent: a person must finish it/);
});

test('poller looks at plain and partial tickets', () => {
  const env = makeEnv({ graph: () => ({ value: [{ state: 'delivered' }] }) });
  env.db.sc_req_item.r1 = ritm({ correlation_id: 'pkg-icu/req-1', correlation_display: 'Entra ID Governance' });
  env.db.sc_task.t1 = { sys_id: 't1', active: 'true', correlation_display: 'Entra ID Governance - partial' };
  env.db.sc_task.t2 = { sys_id: 't2', active: 'true', correlation_display: 'Entra ID Governance - needs IAM' };
  const seen = [];
  env.x._check = (gr) => seen.push(gr.getUniqueValue());
  env.x.checkInFlight();
  assert.deepEqual(plain(seen), ['r1', 't1'], 'needs-IAM tickets are left to people');
});

test('leaver removes assignments still delivering or partially delivered, skips expired', () => {
  const env = makeEnv({
    graph: (m, url) => {
      if (m === 'get' && url.includes('pkg-icu')) return { value: [{ id: 'a-del', state: 'delivering' }, { id: 'a-old', state: 'expired' }] };
      if (m === 'get' && url.includes('pkg-ph')) return { value: [{ id: 'a-part', state: 'partiallyDelivered' }] };
      if (m === 'post') return { id: 'rm-' + Math.random().toString(36).slice(2, 6) };
      return { value: [] };
    },
  });
  env.db.sc_task.t1 = { sys_id: 't1', number: 'SCTASK0010099', state: '1', correlation_id: '' };
  const refs = plain(env.x.removeAll(env.rec('sc_task', 't1'), { u_entra_object_id: 'ed258a73-ff42-4bb3-9144-15330b67fe0e' }));
  const removed = env.calls.filter((c) => c[0] === 'post').map((c) => c[2].assignment.id);
  assert.deepEqual(plain(removed), ['a-del', 'a-part']);
  assert.equal(refs.length, 2);
  assert.notEqual(String(env.db.sc_task.t1.state), '3', 'not closed: the removals are followed first');
  assert.equal(env.db.sc_task.t1.correlation_display, 'Entra ID Governance');
});
