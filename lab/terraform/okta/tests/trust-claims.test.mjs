// Offline tests for trust-claims.mjs: a fake Okta API in memory; no org, no
// token. Run: node --test lab/terraform/okta/tests/trust-claims.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planTrust, putBody, readBackProblems, run, defaultIdpName, sameJson } from '../trust-claims.mjs';

const V1 = 'https://sts.windows.net/11111111-1111-1111-1111-111111111111/';
const V2 = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0';
const idp = (issuer, trustClaims = false) => ({
  id: '0oaTEST', name: 'Microsoft Entra ID (Contoso Health)', type: 'OIDC', status: 'ACTIVE', issuerMode: 'ORG_URL',
  created: '2026-10-28T23:05:00Z', lastUpdated: '2026-11-05T10:22:37Z', _links: { self: {} },
  protocol: {
    type: 'OIDC', scopes: ['openid', 'profile', 'email'], issuer: { url: issuer },
    endpoints: { authorization: { url: 'https://login.microsoftonline.com/t/oauth2/authorize' }, token: { url: 'https://login.microsoftonline.com/t/oauth2/token' } },
    algorithms: { request: { signature: { algorithm: 'HS256', scope: 'NONE' } } },
    credentials: { client: { client_id: 'cid', client_secret: 'not-a-real-secret' } },
  },
  policy: { trustClaims, maxClockSkew: 0, provisioning: { action: 'AUTO' }, subject: { matchType: 'EMAIL' } },
});

// A fake Okta: one IdP, records calls; `mutate` lets a test make the PUT change more than asked.
function fakeOkta(start, { mutate } = {}) {
  let cur = structuredClone(start);
  const calls = [];
  const fetchFn = async (url, { method = 'GET', body } = {}) => {
    const u = new URL(url); calls.push(`${method} ${u.pathname}${u.search}`);
    const ok = (j) => ({ ok: true, status: 200, json: async () => structuredClone(j) });
    if (method === 'GET' && u.pathname === '/api/v1/idps') return ok([cur, { ...structuredClone(cur), id: 'other', name: 'Other IdP' }]);
    if (method === 'GET' && u.pathname === `/api/v1/idps/${cur.id}`) return ok(cur);
    if (method === 'PUT' && u.pathname === `/api/v1/idps/${cur.id}`) { const b = JSON.parse(body); cur = { ...cur, ...b, id: cur.id }; if (mutate) mutate(cur); return ok(cur); }
    return { ok: false, status: 404, json: async () => ({ errorCode: 'E0000007', errorSummary: 'Not found' }) };
  };
  return { fetchFn, calls, get: () => cur };
}
const args = (f) => ({ org: 'example.okta.com', idpName: 'Microsoft Entra ID (Contoso Health)', token: 't', fetchFn: f.fetchFn, log: () => {} });

test('planTrust refuses to trust claims while the IdP is on Entra v2.0 (its ID token has no amr)', () => {
  const p = planTrust(idp(V2), true);
  assert.equal(p.action, 'refuse');
  assert.match(p.reason, /no amr/);
});
test('planTrust: v1.0 issuer and trust off = change; already on = none; --off always allowed', () => {
  assert.deepEqual(planTrust(idp(V1), true), { action: 'change', current: false, desired: true });
  assert.deepEqual(planTrust(idp(V1, true), true), { action: 'none', current: true });
  assert.equal(planTrust(idp(V2, true), false).action, 'change');
});
test('putBody changes only policy.trustClaims and drops read-only fields', () => {
  const b = putBody(idp(V1), true);
  assert.equal(b.policy.trustClaims, true);
  for (const k of ['id', 'created', 'lastUpdated', '_links']) assert.equal(k in b, false, k);
  const back = { ...b, policy: { ...b.policy, trustClaims: false } };
  const { id, created, lastUpdated, _links, ...orig } = idp(V1);
  assert.deepEqual(back, orig);
});
test('run: dry run reads only (no PUT)', async () => {
  const f = fakeOkta(idp(V1));
  await run({ ...args(f), dryRun: true });
  assert.equal(f.calls.some((c) => c.startsWith('PUT')), false);
  assert.equal(f.get().policy.trustClaims, false);
});
test('run: sets trustClaims, reads it back; a second run changes nothing (idempotent)', async () => {
  const f = fakeOkta(idp(V1));
  assert.deepEqual(await run(args(f)), { changed: true });
  assert.equal(f.get().policy.trustClaims, true);
  assert.deepEqual(await run(args(f)), { changed: false });
  assert.equal(f.calls.filter((c) => c.startsWith('PUT')).length, 1);
});
test('run: refuses (no PUT) while the IdP is on v2.0', async () => {
  const f = fakeOkta(idp(V2));
  await assert.rejects(run(args(f)), /not Entra's v1\.0 issuer/);
  assert.equal(f.calls.some((c) => c.startsWith('PUT')), false);
});
test('run: a read-back that differs anywhere else fails loudly (never prints the secret)', async () => {
  const f = fakeOkta(idp(V1), { mutate: (c) => { c.protocol.credentials.client.client_secret = 'changed'; } });
  await assert.rejects(run(args(f)), (e) => /client_secret \(compared, not printed\)/.test(e.message) && !/not-a-real-secret|changed/.test(e.message));
});
test('run: the IdP is found by exact name; zero or several matches stop the run', async () => {
  const f = fakeOkta(idp(V1));
  await assert.rejects(run({ ...args(f), idpName: 'Nope' }), /exactly one OIDC IdP named "Nope", found 0/);
});
test('readBackProblems: identical apart from the flag = no problems', () => {
  const before = idp(V1), after = { ...idp(V1), policy: { ...idp(V1).policy, trustClaims: true } };
  assert.deepEqual(readBackProblems(before, after, true), []);
});

test('readBackProblems ignores key order: the same values in another order are not a change', () => {
  const before = idp(V1);
  const after = structuredClone(before);
  after.policy = { trustClaims: true, subject: after.policy.subject, provisioning: after.policy.provisioning, maxClockSkew: 0 };
  after.protocol = { credentials: after.protocol.credentials, algorithms: after.protocol.algorithms, endpoints: { token: after.protocol.endpoints.token, authorization: after.protocol.endpoints.authorization }, issuer: after.protocol.issuer, scopes: after.protocol.scopes, type: 'OIDC' };
  assert.deepEqual(readBackProblems(before, after, true), []);
  assert.equal(sameJson({ a: 1, b: { c: 2, d: 3 } }, { b: { d: 3, c: 2 }, a: 1 }), true);
  assert.equal(sameJson({ a: [1, 2] }, { a: [2, 1] }), false, 'array order still matters');
});

test('defaultIdpName reads the default from this root\'s variables.tf (no tfvars needed)', () => {
  const tf = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'variables.tf'), 'utf8');
  assert.equal(defaultIdpName(tf), 'Microsoft Entra ID (Contoso Health)');
  assert.equal(defaultIdpName('variable "other" { default = "x" }'), null);
});
