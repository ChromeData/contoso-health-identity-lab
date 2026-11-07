// node --test lab/okta-migration/tests/lib.test.mjs
// Pure parts of the Okta -> Entra migration tools: no network, no Keychain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  oktaElToEntra, protocolOf, isClinicApp, statusOf, buildRow, toCsv, toMarkdown, toHtml,
  systemLogFilter, entraSigninKql, okta,
} from '../lib.mjs';
import { verifyIdToken, authorizeUrl, pkcePair, signinRecord, page } from '../clinic-results/app.mjs';

test('the clinic login-domain rule translates to an endsWith on the UPN', () => {
  assert.deepEqual(oktaElToEntra('String.substringAfter(user.login, "@") == "contosohealthlab.com"'), { rule: '(user.userPrincipalName -endsWith "@contosohealthlab.com")' });
});

test('attribute equality, inequality, && and || translate', () => {
  assert.equal(oktaElToEntra('user.department == "Clinic Billing"').rule, '(user.department -eq "Clinic Billing")');
  assert.equal(oktaElToEntra('user.title != "Contractor"').rule, '(user.jobTitle -ne "Contractor")');
  assert.equal(oktaElToEntra('user.department == "Lab" && user.city == "Boston"').rule, '(user.department -eq "Lab") -and (user.city -eq "Boston")');
  assert.equal(oktaElToEntra('user.department == "Lab" || user.department == "Path"').rule, '(user.department -eq "Lab") -or (user.department -eq "Path")');
});

test('what cannot be translated exactly says why, never guesses', () => {
  assert.equal(oktaElToEntra('isMemberOfAnyGroup("00g1")').rule, null);
  assert.match(oktaElToEntra('isMemberOfAnyGroup("00g1")').reason, /cannot reference groups/);
  assert.equal(oktaElToEntra('user.department == "A" && user.city == "B" || user.title == "C"').rule, null);
  assert.equal(oktaElToEntra('user.favouriteColour == "blue"').rule, null);
  assert.equal(oktaElToEntra('').rule, null);
  assert.equal(oktaElToEntra('Arrays.contains(user.x, "y")').rule, null);
});

test('protocols and Okta system apps', () => {
  assert.equal(protocolOf({ signOnMode: 'OPENID_CONNECT' }), 'OIDC');
  assert.equal(protocolOf({ signOnMode: 'SAML_2_0' }), 'SAML 2.0');
  assert.equal(protocolOf({ signOnMode: 'BOOKMARK' }), 'Bookmark');
  assert.equal(protocolOf({ signOnMode: 'AUTO_LOGIN' }), 'SWA (password vaulting)');
  assert.equal(isClinicApp({ name: 'saasure' }), false);
  assert.equal(isClinicApp({ name: 'okta_enduser' }), false);
  assert.equal(isClinicApp({ name: 'oidc_client' }), true);
});

test('status comes from what the APIs say', () => {
  assert.equal(statusOf({ okta: { status: 'ACTIVE', hidden: false }, entra: null, appTrusts: 'okta' }), 'inventoried');
  assert.equal(statusOf({ okta: { status: 'ACTIVE' }, entra: { servicePrincipalId: 's', assignedPrincipals: 1, groupMembers: 0 }, appTrusts: 'okta' }), 'pre-staged');
  assert.equal(statusOf({ okta: { status: 'ACTIVE' }, entra: { servicePrincipalId: 's', assignedPrincipals: 1, groupMembers: 1 }, appTrusts: 'okta' }), 'piloting');
  assert.equal(statusOf({ okta: { status: 'ACTIVE', hidden: true }, entra: { servicePrincipalId: 's', assignedPrincipals: 1, groupMembers: 1 }, appTrusts: 'entra' }), 'cut over');
  // Trusting Entra while the Okta tile is still visible is NOT cut over yet.
  assert.equal(statusOf({ okta: { status: 'ACTIVE', hidden: false }, entra: { servicePrincipalId: 's', assignedPrincipals: 1, groupMembers: 1 }, appTrusts: 'entra' }), 'piloting');
  assert.equal(statusOf({ okta: { status: 'INACTIVE', hidden: true }, entra: null, appTrusts: 'entra' }), 'retired');
});

test('a tracker row carries the seven columns and the next step', () => {
  const r = buildRow({ app: { id: '0oaAAAAAAAAAAAAAAAAA', label: 'X', signOnMode: 'SAML_2_0' }, plan: { owner: 'O', wave: 2, blocker: 'no SP' }, okta: { status: 'ACTIVE', userCount: 3, groups: ['G'], policy: 'P' }, entra: null, appTrusts: 'okta', test: null });
  assert.deepEqual([r.app, r.owner, r.protocol, r.users, r.wave, r.status, r.test_result], ['X', 'O', 'SAML 2.0', 3, 2, 'inventoried', 'not tested']);
  assert.match(r.next_step, /blocker: no SP/);
  const t = buildRow({ app: { id: '0oaAAAAAAAAAAAAAAAAA', label: 'Y', signOnMode: 'OPENID_CONNECT' }, plan: {}, okta: { status: 'ACTIVE', userCount: 1, groups: [], policy: '' }, entra: null, appTrusts: 'okta', test: { result: 'PASS', idp: 'okta', at: '2026-11-07T00:00:00Z' } });
  assert.equal(t.owner, 'UNASSIGNED');
  assert.equal(t.test_result, 'PASS okta 2026-11-07T00:00:00Z');
});

test('CSV quotes commas and quotes; markdown escapes pipes; HTML escapes markup', () => {
  const row = { app: 'A, "quoted"', owner: 'o|p', protocol: 'OIDC', users: 1, wave: 1, status: 'cut over', test_result: '<b>x</b>' };
  const csv = toCsv([row], ['app', 'owner']);
  assert.equal(csv, 'app,owner\n"A, ""quoted""",o|p\n');
  assert.match(toMarkdown([{ ...row, okta_app_id: 'i', okta_groups: '', okta_policy: '', entra_app: '', next_step: 'n' }], { generatedAt: 't', sources: [] }), /o\\\|p/);
  const html = toHtml([row], { generatedAt: 't' });
  assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;') && !html.includes('<b>x</b>'));
  assert.match(html, /<b>1<\/b><span>cut over<\/span>/);
});

test('the System Log filter names the app and refuses anything that is not an app id', () => {
  assert.equal(systemLogFilter('0oa19mje0oyLEHh1U698'), '(eventType eq "user.authentication.sso" or eventType eq "app.oauth2.authorize.code") and target.id eq "0oa19mje0oyLEHh1U698"');
  assert.throws(() => systemLogFilter('0oa1" or "1" eq "1'));
  assert.match(entraSigninKql('Clinic "Lab" Results'), /AppDisplayName == "Clinic Lab Results"/);
});

test('the Okta client pages, stops on an empty System Log page, and never puts the token in a URL', async () => {
  const calls = [];
  const pages = [[{ id: 1 }], [{ id: 2 }], []];
  const fetchFn = async (url, init) => {
    calls.push({ url, auth: init.headers.Authorization });
    const data = pages.shift();
    return { status: 200, text: async () => JSON.stringify(data), headers: { get: (h) => (h === 'link' ? `<https://o.okta.com/api/v1/logs?after=${calls.length}>; rel="next"` : null) } };
  };
  const c = okta({ org: 'o.okta.com', token: 'tok-123', fetchFn });
  const out = await c.list('/api/v1/logs?since=x');
  assert.deepEqual(out.map((x) => x.id), [1, 2]);
  assert.equal(calls.length, 3);
  assert.ok(calls.every((x) => x.auth === 'SSWS tok-123' && !x.url.includes('tok-123')));
});

// ---- the app's ID token check -----------------------------------------------
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };
const jwks = { keys: [jwk] };
function sign(claims, { kid = 'k1', alg = 'RS256', key = privateKey } = {}) {
  const h = Buffer.from(JSON.stringify({ alg, kid, typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const s = crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), key).toString('base64url');
  return `${h}.${p}.${s}`;
}
const now = 1_800_000_000;
const good = { iss: 'https://login.microsoftonline.com/t/v2.0', aud: 'client-1', exp: now + 600, nonce: 'n1', preferred_username: 'test-user-b@contosohealthlab.com' };
const opts = { jwks, issuer: good.iss, audience: 'client-1', nonce: 'n1', now };

test('a correctly signed ID token from the trusted issuer is accepted', () => {
  assert.equal(verifyIdToken(sign(good), opts).preferred_username, 'test-user-b@contosohealthlab.com');
});

test('the app refuses a token from the OTHER IdP: this is what makes the cut-over real', () => {
  assert.throws(() => verifyIdToken(sign({ ...good, iss: 'https://integrator-1.okta.com' }), opts), /not the trusted/);
});

test('wrong audience, expired, nonce, unknown key, bad signature and alg none are refused', () => {
  assert.throws(() => verifyIdToken(sign({ ...good, aud: 'other' }), opts), /audience/);
  assert.throws(() => verifyIdToken(sign({ ...good, exp: now - 1000 }), opts), /expired/);
  assert.throws(() => verifyIdToken(sign({ ...good, nonce: 'n2' }), opts), /nonce/);
  assert.throws(() => verifyIdToken(sign(good, { kid: 'k9' }), opts), /no JWKS key/);
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  assert.throws(() => verifyIdToken(sign(good, { key: other }), opts), /does not verify/);
  const t = sign(good).split('.'); const none = Buffer.from(JSON.stringify({ alg: 'none', kid: 'k1' })).toString('base64url');
  assert.throws(() => verifyIdToken(`${none}.${t[1]}.`, opts), /unexpected alg/);
});

test('authorize URL carries PKCE S256, state and nonce, and no secret', () => {
  const { verifier, challenge } = pkcePair();
  assert.equal(challenge, crypto.createHash('sha256').update(verifier).digest('base64url'));
  const u = new URL(authorizeUrl({ authorization_endpoint: 'https://idp/authorize', client_id: 'c' }, { state: 's', nonce: 'n', challenge }));
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('redirect_uri'), 'http://localhost:8471/callback');
  assert.equal(u.searchParams.get('client_secret'), null);
});

test('the sign-in record holds no token, and the page escapes the user name', () => {
  const r = signinRecord('entra', { ...good, amr: ['pwd', 'mfa'] }, new Date('2026-11-07T00:00:00Z'));
  assert.deepEqual(Object.keys(r).sort(), ['amr', 'at', 'audience', 'auth_time', 'idp', 'issuer', 'user']);
  assert.ok(page({ user: '<script>x</script>', idp: 'entra', issuer: 'i' }).includes('&lt;script&gt;'));
  assert.match(page({ user: 'u', idp: 'entra', issuer: 'i' }), /through <b>Microsoft Entra ID<\/b>/);
  assert.match(page({ active: 'okta' }), /trusts <b>Okta<\/b>/);
});
