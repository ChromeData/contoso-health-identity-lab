// node --test lab/adfs/connect-health/tests/get-agent-token.test.mjs
// Offline tests for the pure parts of get-agent-token.mjs (ADR 0031): the
// PKCE pair, the authorize URL and the claim checks that refuse a wrong
// token. Nothing signs in, calls Entra or touches the Keychain (importing the
// module runs no command: its CLI is guarded).
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pkce, authorizeUrl, claimsOf, CLIENT_ID, SCOPE, REDIRECT, TENANT } from '../get-agent-token.mjs';

const UPN = 'adm-connecthealth-reg@contosohealthlab.onmicrosoft.com';
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (claims) => `${b64url({ alg: 'none' })}.${b64url(claims)}.sig`;
const good = { aud: 'https://management.core.windows.net', tid: TENANT, upn: UPN, appid: CLIENT_ID, amr: ['fido', 'mfa'], wids: ['8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'], exp: 2000000000 };

test('PKCE: S256 challenge of the verifier, URL-safe, 43 chars', () => {
  const { verifier, challenge } = pkce();
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  const want = crypto.createHash('sha256').update(verifier).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  assert.equal(challenge, want);
  assert.notEqual(pkce().verifier, verifier);
});

test('authorize URL: the agent client, its scope and redirect, PKCE S256, the lab tenant, fresh sign-in, no offline_access', () => {
  const u = new URL(authorizeUrl(UPN, 'CHALLENGE', 'STATE'));
  assert.equal(u.origin + u.pathname, `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`);
  const q = u.searchParams;
  assert.equal(q.get('client_id'), 'cf6d7e68-f018-4e0a-a7b3-126e053fb88d');
  assert.equal(q.get('scope'), SCOPE);
  assert.ok(!/offline_access/.test(q.get('scope')), 'no refresh token is asked for');
  assert.equal(q.get('redirect_uri'), REDIRECT);
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.equal(q.get('code_challenge'), 'CHALLENGE');
  assert.equal(q.get('state'), 'STATE');
  assert.equal(q.get('prompt'), 'login');
  assert.equal(q.get('login_hint'), UPN);
});

test('claims: a passkey (mfa) token for the agent client, lab tenant and named user passes; only non-secret claims come back', () => {
  const c = claimsOf(jwt(good), UPN);
  assert.deepEqual(Object.keys(c).sort(), ['amr', 'appid', 'aud', 'exp', 'tid', 'upn', 'wids']);
  assert.equal(c.wids, 1);
});

test('claims: refuses a token without mfa (a password-only sign-in)', () => {
  assert.throws(() => claimsOf(jwt({ ...good, amr: ['pwd'] }), UPN), /no mfa/);
});

test('claims: refuses another tenant, another client, another user, and a non-JWT', () => {
  assert.throws(() => claimsOf(jwt({ ...good, tid: '00000000-0000-0000-0000-000000000000' }), UPN), /tenant/);
  assert.throws(() => claimsOf(jwt({ ...good, appid: '04b07795-8ddb-461a-bbee-02f9e1bf7b46' }), UPN), /client/);
  assert.throws(() => claimsOf(jwt(good), 'adm-presenter@contosohealthlab.onmicrosoft.com'), /is not/);
  assert.throws(() => claimsOf('not-a-token', UPN), /not a JWT/);
});
