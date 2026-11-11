// node --test tests/teardown.test.mjs — clearAutoAssignment (the merge
// captain's revert-preparation sequence) against a fake Graph.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clearAutoAssignment, policyPutBody } from '../lib/teardown.mjs';

const PKG = 'IT - Cloud Engineering Apps';
const autoPolicy = (over = {}) => ({ id: 'pol1', displayName: 'birthright', '@odata.context': 'x', createdDateTime: 'c', modifiedDateTime: 'm', catalog: { id: 'cat' },
  description: 'd', allowedTargetScope: 'specificDirectoryUsers', automaticRequestSettings: { requestAccessForAllowedTargets: true, removeAccessWhenTargetLeavesAllowedTargets: true, gracePeriodBeforeAccessRemoval: 'P3D' }, accessPackage: { id: 'P1' }, ...over });

function fake({ pkgs = [{ id: 'P1', displayName: PKG }], policies = [autoPolicy()], assignments = [[{ id: 'A1', state: 'delivered', target: { principalName: 'sam.rivera@contosohealthlab.com', displayName: 'Sam Rivera' } }], [], []], failRead = null, putChanges = {} } = {}) {
  const calls = { put: [], post: [], del: [] };
  let pol = policies.map((p) => ({ ...p })), reads = 0;
  const get = async (path) => {
    if (failRead && path.includes(failRead)) return null;
    if (path.includes('/accessPackages?')) return { value: pkgs };
    if (path.includes('/assignmentPolicies?')) return { value: pol };
    if (path.includes('/assignments?')) { const v = assignments[Math.min(reads, assignments.length - 1)]; reads++; return { value: v }; }
    const m = /assignmentPolicies\/(\w+)$/.exec(path);
    if (m) { const p = pol.find((x) => x.id === m[1]); if (!p) throw new Error('NotFound'); return p; }
    throw new Error(`unexpected GET ${path}`);
  };
  const put = async (path, body) => { calls.put.push({ path, body }); const id = path.split('/').pop(); pol = pol.map((p) => (p.id === id ? { ...p, ...body, ...putChanges, id } : p)); };
  const post = async (path, body) => { calls.post.push({ path, body }); return { state: 'submitted', status: 'Accepted' }; };
  const del = async (path) => { calls.del.push(path); const id = path.split('/').pop(); pol = pol.filter((p) => p.id !== id); };
  return { get, put, post, del, calls };
}
const resolveSam = async () => '72de28cb3073428cb1face2b1b905fe6sam.rivera@contosohealthlab.com';
const run = (g, extra = {}) => clearAutoAssignment({ pkgName: PKG, get: g.get, put: g.put, post: g.post, del: g.del, resolveDeleted: resolveSam, wait: async () => {}, log: () => {}, ...extra });

test('PUT body: drops server fields, keeps the rest, switches only the automatic flag off', () => {
  const b = policyPutBody(autoPolicy(), 'P1');
  for (const k of ['id', 'createdDateTime', 'modifiedDateTime', 'catalog', '@odata.context']) assert.equal(k in b, false, k);
  assert.deepEqual(b.accessPackage, { id: 'P1' });
  assert.equal(b.automaticRequestSettings.requestAccessForAllowedTargets, false);
  assert.equal(b.automaticRequestSettings.removeAccessWhenTargetLeavesAllowedTargets, true);
  assert.equal(b.description, 'd');
});

test('full sequence: switch off, remove, two zero reads, delete, nothing left', async () => {
  const g = fake();
  const r = await run(g);
  assert.equal(g.calls.put.length, 1);
  assert.deepEqual(g.calls.post.map((c) => c.body), [{ requestType: 'adminRemove', assignment: { id: 'A1' } }]);
  assert.deepEqual(g.calls.del, ['identityGovernance/entitlementManagement/assignmentPolicies/pol1']);
  assert.match(r, /0 assignments left/);
});

test('a hard-deleted hire (empty target) is removed once the audit log says it was the hire', async () => {
  const g = fake({ assignments: [[{ id: 'A9', state: 'delivered', target: { objectId: 'o1' } }], [], []] });
  await run(g);
  assert.equal(g.calls.post[0].body.assignment.id, 'A9');
});

test('empty target, audit log says the owner: stop before any change', async () => {
  const g = fake({ assignments: [[{ id: 'A9', state: 'delivered', target: { objectId: 'o1' } }]] });
  await assert.rejects(run(g, { resolveDeleted: async () => 'MichaelWilliams@ContosoHealthLab.onmicrosoft.com' }), /not the preview's test hire/);
  assert.equal(g.calls.put.length + g.calls.post.length + g.calls.del.length, 0);
});

test('empty target that cannot be resolved: stop before any change', async () => {
  const g = fake({ assignments: [[{ id: 'A9', state: 'delivered', target: null }]] });
  await assert.rejects(run(g, { resolveDeleted: async () => null }), /unresolved deleted object/);
  assert.equal(g.calls.put.length + g.calls.post.length + g.calls.del.length, 0);
});

test('stops before any change when someone else holds the package', async () => {
  const g = fake({ assignments: [[{ id: 'A2', state: 'delivered', target: { principalName: 'dana.okafor@contosohealthlab.com', displayName: 'Dana Okafor' } }]] });
  await assert.rejects(run(g), /not the preview's test hire/);
  assert.equal(g.calls.put.length + g.calls.post.length + g.calls.del.length, 0);
});

test('stops when the package has a non-automatic policy', async () => {
  const g = fake({ policies: [autoPolicy(), { id: 'req', displayName: 'request', automaticRequestSettings: null }] });
  await assert.rejects(run(g), /non-automatic policies/);
  assert.equal(g.calls.put.length, 0);
});

test('stops when the read-back shows another field changed', async () => {
  const g = fake({ putChanges: { description: 'changed by someone' } });
  await assert.rejects(run(g), /description changed too/);
  assert.equal(g.calls.post.length, 0);
});

test('needs two zero reads in a row (a single empty read is not enough)', async () => {
  const g = fake({ assignments: [[{ id: 'A1', state: 'delivered', target: { objectId: 'o1' } }], [], [{ id: 'A1', state: 'delivering', target: { objectId: 'o1' } }], [], []] });
  await run(g);
  assert.equal(g.calls.del.length, 1);
});

test('fails closed when a read fails', async () => {
  const g = fake({ failRead: '/assignmentPolicies?' });
  await assert.rejects(run(g), /could not read the assignment policies/);
  assert.equal(g.calls.put.length + g.calls.del.length, 0);
});

test('never claims 0 on a timeout', async () => {
  const g = fake({ assignments: [[{ id: 'A1', state: 'delivered', target: { objectId: 'o1' } }], [{ id: 'A1', state: 'delivering', target: { objectId: 'o1' } }]] });
  await assert.rejects(run(g, { timeoutMs: -1 }), /1 assignment\(s\) still/);
  assert.equal(g.calls.del.length, 0);
});

test('package already gone: nothing to do', async () => {
  const g = fake({ pkgs: [] });
  assert.match(await run(g), /nothing to clear/);
});
