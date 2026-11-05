// Offline tests for identity.mjs (registry, secrets references, sign-in page
// detection), the landing rules it relies on, and doctor.mjs's helpers.
// No tenant, browser or Keychain. Run:
//   node --test lab/scripts/demo/signin/tests/identity.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

process.env.CONTOSO_OPERATOR_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-test-'));
process.env.SIGNIN_QUIET = '1';
const { validateRegistry, readEnvFileKey, needsSignIn, loadRegistry } = await import('../identity.mjs');
const { landing } = await import('../signin.mjs');
const { age, nextExpiry, sessionCookieExpiry, table } = await import('../doctor.mjs');
const HERE = path.dirname(fileURLToPath(import.meta.url));

const ok = (extra = {}) => ({ identities: { 'x-user': { kind: 'entra', upn: 'x-user@contosohealthlab.com', method: 'password+totp', home: 'https://myapps.microsoft.com/', secrets: { password: { service: 's', account: 'x-user@contosohealthlab.com' }, totp: { service: 't', account: 'x-user@contosohealthlab.com' } }, ...extra } } });

// ---- the shipped registry --------------------------------------------------------
test('the shipped identities.json is valid and covers every identity the cockpit uses', () => {
  const reg = loadRegistry(path.join(HERE, '..', 'identities.json'));
  for (const id of ['adm-presenter', 'test-user-a', 'acr.breakglass', 'adm-ava.lin', 'adm-labops', 'adm-raj.patel', 'adm-mei.tanaka', 'test-user-b', 'test-user-c', 'svc-soc-automation', 'splunk-admin', 'splunk-feed-check']) assert.ok(reg[id], id);
  assert.equal(Object.values(reg).some((e) => /github/i.test(JSON.stringify(e))), false, 'GitHub stays the owner\'s own sign-in');
});
test('the shipped registry holds references only: no value-like strings under secrets', () => {
  const raw = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'identities.json'), 'utf8'));
  for (const e of Object.values(raw.identities)) for (const ref of Object.values(e.secrets)) assert.deepEqual(Object.keys(ref).sort(), ref.service ? ['account', 'service'] : ['file', 'key']);
});

// ---- validateRegistry -------------------------------------------------------------
test('validateRegistry: a good entry has no problems', () => assert.deepEqual(validateRegistry(ok()), []));
test('validateRegistry refuses a plain string where a secret reference belongs', () => {
  const r = ok(); r.identities['x-user'].secrets.password = 'Hunter2!';
  assert.match(validateRegistry(r).join(), /secrets\.password must be \{service, account\} or \{file, key\} - never a value/);
});
test('validateRegistry refuses extra fields in a reference (a "value" next to the name)', () => {
  const r = ok(); r.identities['x-user'].secrets.password = { service: 's', account: 'a', value: 'oops' };
  assert.match(validateRegistry(r).join(), /never a value/);
});
test('validateRegistry refuses the owner\'s and break-glass accounts, and non-lab UPNs', () => {
  assert.match(validateRegistry(ok({ upn: 'michaelwilliams@contosohealthlab.onmicrosoft.com' })).join(), /owner's and break-glass/);
  assert.match(validateRegistry(ok({ upn: 'bg-admin-01@contosohealthlab.onmicrosoft.com' })).join(), /owner's and break-glass/);
  assert.match(validateRegistry(ok({ upn: 'someone@example.com' })).join(), /lowercase lab UPN/);
});
test('validateRegistry: a method needs its secrets; methods must fit the kind; only a tap fallback', () => {
  const r = ok({ method: 'passkey' });
  assert.match(validateRegistry(r).join(), /method passkey needs secrets\.passkey/);
  assert.match(validateRegistry(ok({ method: 'sms' })).join(), /method sms is not valid for entra/);
  assert.match(validateRegistry(ok({ fallback: 'sms' })).join(), /only fallback is "tap"/);
});
test('validateRegistry: a file reference must stay inside the repo (relative, no ..)', () => {
  const r = { identities: { 's': { kind: 'splunk-local', username: 'admin', method: 'password', loginUrl: 'http://127.0.0.1:8000/en-US/account/login', home: 'http://127.0.0.1:8000/', secrets: { password: { file: '../../etc/passwd', key: 'X' } } } } };
  assert.match(validateRegistry(r).join(), /never a value/);
});

// ---- secrets from an env file -------------------------------------------------------
test('readEnvFileKey reads one key (quotes stripped) and nothing else', () => {
  const t = '# comment\nSPLUNK_HEC_TOKEN=abc\nSPLUNK_PASSWORD="Sp-x-9a"\n';
  assert.equal(readEnvFileKey(t, 'SPLUNK_PASSWORD'), 'Sp-x-9a');
  assert.equal(readEnvFileKey(t, 'MISSING'), null);
});

// ---- when does a page need signing in again? ------------------------------------------
test('needsSignIn: Entra sign-in hosts for Entra identities; login.do / MFA page for ServiceNow; /account/login for Splunk', () => {
  const entra = { kind: 'entra' };
  const snow = { kind: 'servicenow-local', loginUrl: 'https://dev459905.service-now.com/login.do' };
  const splunk = { kind: 'splunk-local', loginUrl: 'http://127.0.0.1:8000/en-US/account/login' };
  assert.equal(needsSignIn('https://login.microsoftonline.com/x/oauth2/v2.0/authorize?x', entra), true);
  assert.equal(needsSignIn('https://myapps.microsoft.com/', entra), false);
  assert.equal(needsSignIn('https://dev459905.service-now.com/validate_multifactor_auth_code.do', snow), true);
  assert.equal(needsSignIn('https://dev459905.service-now.com/now/nav/ui/home', snow), false);
  assert.equal(needsSignIn('https://other.service-now.com/login.do', snow), false, 'another instance is not ours');
  assert.equal(needsSignIn('http://127.0.0.1:8000/en-US/account/login?return_to=x', splunk), true);
  assert.equal(needsSignIn('http://127.0.0.1:8000/en-US/app/search/search', splunk), false);
});

// ---- landing rules added for the recording browser ------------------------------------
test('landing: ServiceNow sign-in pages never count as signed in, whatever their URL (seen live: navpage.do)', () => {
  assert.equal(landing('https://dev459905.service-now.com/navpage.do', 'ServiceNow Home Page Log in to your account Username Next'), 'wait');
  assert.equal(landing('https://dev459905.service-now.com/login.do', 'ServiceNow Log in User name Password'), 'wait');
  assert.equal(landing('https://dev459905.service-now.com/validate_multifactor_auth_code.do', 'Verify your identity'), 'wait');
});
test('landing: ServiceNow signed in = the Next Experience shell URL, even with no readable text (shadow DOM)', () => {
  assert.equal(landing('https://dev459905.service-now.com/now/nav/ui/home', ''), 'ok');
});
test('landing: Splunk signed in = an app page, never the login form', () => {
  assert.equal(landing('http://127.0.0.1:8000/en-US/app/search/search', 'Search Splunk'), 'ok');
  assert.equal(landing('http://127.0.0.1:8000/en-US/account/login', 'Splunk Forgot your password'), 'wait');
  assert.match(landing('http://127.0.0.1:8000/en-US/account/login', 'Login failed'), /^denied: Splunk/);
});
test('landing: the admin portals and Teams have positive signals', () => {
  assert.equal(landing('https://entra.microsoft.com/#home', 'Microsoft Entra admin center Home'), 'ok');
  assert.equal(landing('https://portal.azure.com/#home', 'Azure services'), 'ok');
  assert.equal(landing('https://security.microsoft.com/homepage', 'Microsoft Defender'), 'ok');
});

// ---- doctor helpers ---------------------------------------------------------------------
test('doctor: age reads like a person would say it', () => {
  assert.equal(age(null), 'none'); assert.equal(age(5 * 60000), '5 min'); assert.equal(age(3 * 3600000), '3 h'); assert.equal(age(3 * 86400000), '3 d');
});
test('doctor: nextExpiry picks the earliest future one and labels it', () => {
  const now = Date.parse('2026-11-05T12:00:00Z');
  assert.equal(nextExpiry([{ label: 'session', at: '2027-02-03T12:00:00Z' }, { label: 'PIM X', at: '2026-11-05T20:00:00Z' }, { label: 'old', at: '2026-11-01T00:00:00Z' }], now), 'PIM X 2026-11-05 20:00Z');
  assert.equal(nextExpiry([], now), '-');
});
test('doctor: sessionCookieExpiry reads Entra\'s persistent cookie only', () => {
  const st = { cookies: [{ name: 'ESTSAUTHPERSISTENT', expires: 1800000000 }, { name: 'other', expires: 1900000000 }, { name: 'ESTSAUTH', expires: -1 }] };
  assert.equal(sessionCookieExpiry(st), 1800000000 * 1000);
  assert.equal(sessionCookieExpiry({ cookies: [] }), null);
});
test('doctor: the table has the six asked-for columns', () => {
  const t = table([{ identity: 'a', method: 'passkey', works: 'yes', 'session age': '1 min', 'PIM state': '-', 'next expiry': '-' }]);
  assert.match(t.split('\n')[0], /^identity\s+method\s+works\s+session age\s+PIM state\s+next expiry/);
});
