// Offline tests for the staff sign-in toolkit (lib.mjs): no tenant, no
// browser, no Keychain. Run: node --test lab/scripts/demo/signin/tests/
// CI runs them in lab-tests.yml ("Shell tests (no containers)").
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Point the per-user state at a throwaway folder BEFORE lib.mjs is loaded.
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'signin-test-'));
process.env.CONTOSO_OPERATOR_HOME = home;
process.env.SIGNIN_QUIET = '1';
const lib = await import('../lib.mjs');

// RFC 6238 Appendix B, SHA-1 rows: seed "12345678901234567890" (base32 below), 8 digits.
const RFC_SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const RFC_ROWS = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'],
  [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];

test('totp matches the RFC 6238 SHA-1 test vectors', () => {
  for (const [t, code] of RFC_ROWS) assert.equal(lib.totp(RFC_SEED, { now: t * 1000, digits: 8 }).code, code, `T=${t}`);
});

test('totp gives 6 digits by default, the last 6 of the RFC value', () => {
  assert.equal(lib.totp(RFC_SEED, { now: 59000 }).code, '287082');
});

test('totp reports the 30-second counter and the seconds left in it', () => {
  const r = lib.totp(RFC_SEED, { now: 59000 });
  assert.equal(r.counter, 1);
  assert.equal(r.secondsLeft, 1);
});

test('hotp matches RFC 4226 Appendix D (counter 0 and 9)', () => {
  const key = Buffer.from('12345678901234567890');
  assert.equal(lib.hotp(key, 0), '755224');
  assert.equal(lib.hotp(key, 9), '520489');
});

test('base32 decoding ignores spaces, case and padding (as Entra shows the key in groups)', () => {
  const grouped = 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq==';
  assert.equal(lib.base32Decode(grouped).toString(), '12345678901234567890');
});

test('base32 decoding refuses characters outside the alphabet', () => {
  assert.throws(() => lib.base32Decode('ABC1DEF8'), /not a base32 secret/);
  assert.throws(() => lib.base32Decode(''), /not a base32 secret/);
});

test('checkUpn accepts the lab domains and lower-cases', () => {
  assert.equal(lib.checkUpn('Test-User-A@ContosoHealthLab.com'), 'test-user-a@contosohealthlab.com');
  assert.equal(lib.checkUpn('dana.okafor@contosohealthlab.onmicrosoft.com'), 'dana.okafor@contosohealthlab.onmicrosoft.com');
});

test('checkUpn refuses the owner account, break-glass accounts and other tenants', () => {
  assert.throws(() => lib.checkUpn('MichaelWilliams@ContosoHealthLab.onmicrosoft.com'), /refused/);
  assert.throws(() => lib.checkUpn('bg-admin-01@contosohealthlab.onmicrosoft.com'), /refused/);
  assert.throws(() => lib.checkUpn('someone@contoso.com'), /not in the lab tenant/);
  assert.throws(() => lib.checkUpn('not-an-upn'), /not a user principal name/);
});

test('Keychain item names follow the documented pattern', () => {
  assert.equal(lib.totpService('test-user-a@contosohealthlab.com'), 'contoso-lab-totp-test-user-a');
  assert.equal(lib.pwService('Test-User-B@contosohealthlab.com'), 'contoso-lab-pw-test-user-b');
});

test('keychainWrite refuses a value the security -i parser would split (before calling security)', () => {
  assert.throws(() => lib.keychainWrite('contoso-lab-x', 'a@b', 'label', 'two words'), /one token/);
  assert.throws(() => lib.keychainWrite('contoso-lab-x', 'a@b', 'label', 'quo"te'), /one token/);
  assert.throws(() => lib.keychainWrite('contoso-lab-x', 'a@b', 'label', ''), /one token/);
});

test('randomPassword: length, all four character classes, nothing keychainWrite refuses', () => {
  for (let i = 0; i < 200; i++) {
    const p = lib.randomPassword();
    assert.equal(p.length, 28);
    assert.match(p, /[A-Z]/); assert.match(p, /[a-z]/); assert.match(p, /[0-9]/); assert.match(p, /[^A-Za-z0-9]/);
    assert.doesNotMatch(p, /[\s"'\\]/);
  }
});

test('freshTotp never hands out a code from a window already used', async () => {
  const upn = 'test-user-c@contosohealthlab.com';
  const now = lib.totp(RFC_SEED);
  // A window far in the future is "already used": freshTotp must not return
  // the current code. Use the current window and check the wait instead.
  lib.markTotpStep(upn, now.counter);
  const t0 = Date.now();
  const code = await lib.freshTotp(upn, RFC_SEED);
  const after = lib.totp(RFC_SEED);
  assert.ok(Date.now() - t0 >= (now.secondsLeft - 1) * 1000, 'it waited for the next window');
  assert.equal(code, after.code);
  assert.equal(fs.readFileSync(path.join(home, 'session', 'browser', 'test-user-c.totp-step'), 'utf8'), String(after.counter));
});

// ---- Keychain fail-closed, through a fake `security` (CONTOSO_SECURITY_BIN) ----
function fakeSecurity(exitCode, stdout = '') {
  const f = path.join(home, `fake-security-${exitCode}.sh`);
  fs.writeFileSync(f, `#!/bin/sh\nprintf '%s' '${stdout}'\nexit ${exitCode}\n`, { mode: 0o755 });
  return f;
}
async function withFake(bin, fn) {
  // lib.mjs reads the variable at load time: load a fresh copy per fake.
  process.env.CONTOSO_SECURITY_BIN = bin;
  try { return await fn(await import(`../lib.mjs?fake=${path.basename(bin)}`)); }
  finally { delete process.env.CONTOSO_SECURITY_BIN; }
}

test('keychainRead: "item not found" (exit 44) is null, not an error', async () => {
  await withFake(fakeSecurity(44), (l) => { assert.equal(l.keychainRead('contoso-lab-x'), null); assert.equal(l.passwordFor('test-user-a@contosohealthlab.com'), null); });
});

test('keychainRead: any other failure (e.g. 36, Keychain locked) throws - never read as "no password"', async () => {
  await withFake(fakeSecurity(36), (l) => {
    assert.throws(() => l.keychainRead('contoso-lab-x'), /Keychain read failed \(security exit 36\)/);
    assert.throws(() => l.passwordFor('test-user-a@contosohealthlab.com'), /Keychain read failed/);
  });
});

// A fake `security` that holds ONE item: service `svc`, account `acct`,
// value `val`. A lookup must match both (-s and, when given, -a), as the real
// Keychain does; anything else is "not found" (exit 44).
function fakeItem(svc, acct, val) {
  const f = path.join(home, `fake-item-${Math.random().toString(36).slice(2)}.sh`);
  fs.writeFileSync(f, `#!/bin/sh
s=""; a=""; while [ $# -gt 0 ]; do case "$1" in -s) s="$2"; shift;; -a) a="$2"; shift;; esac; shift; done
[ "$s" = "${svc}" ] || exit 44
[ -z "$a" ] || [ "$a" = "${acct}" ] || exit 44
printf '%s' '${val}'
`, { mode: 0o755 });
  return f;
}

test('passwordFor: an older contoso-lab-<user> item is used only when its account is the UPN', async () => {
  await withFake(fakeItem('contoso-lab-test-user-a', 'someone-else@contosohealthlab.com', 'pw-x'), (l) => {
    assert.equal(l.passwordFor('test-user-a@contosohealthlab.com'), null);
  });
  await withFake(fakeItem('contoso-lab-test-user-a', 'test-user-a@contosohealthlab.com', 'pw-a'), (l) => {
    assert.deepEqual(l.passwordFor('test-user-a@contosohealthlab.com'), { service: 'contoso-lab-test-user-a', value: 'pw-a' });
  });
});

test('same local part on the two lab domains: secrets never cross over (password and seed)', async () => {
  await withFake(fakeItem('contoso-lab-pw-dana.okafor', 'dana.okafor@contosohealthlab.com', 'pw-com'), (l) => {
    assert.equal(l.passwordFor('dana.okafor@contosohealthlab.onmicrosoft.com'), null);
    assert.equal(l.passwordFor('dana.okafor@contosohealthlab.com').value, 'pw-com');
  });
  await withFake(fakeItem('contoso-lab-totp-dana.okafor', 'dana.okafor@contosohealthlab.com', 'SEEDCOM'), (l) => {
    assert.equal(l.seedFor('dana.okafor@contosohealthlab.onmicrosoft.com'), null);
    assert.equal(l.seedFor('dana.okafor@contosohealthlab.com'), 'SEEDCOM');
  });
});

// ---- saved sessions belong to one UPN ------------------------------------------
test('readOwnedState: only the owner gets the saved cookies; foreign, legacy and broken files are ignored', () => {
  const f = lib.statePath('dana.okafor@contosohealthlab.com');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  const st = { cookies: [{ name: 'ESTSAUTH', value: 'x', domain: '.login.microsoftonline.com', path: '/' }], origins: [] };
  fs.writeFileSync(f, JSON.stringify({ owner: 'dana.okafor@contosohealthlab.com', ...st }));
  assert.deepEqual(lib.readOwnedState('dana.okafor@contosohealthlab.com'), st);
  assert.equal(lib.readOwnedState('dana.okafor@contosohealthlab.onmicrosoft.com'), null, 'same file name, other domain');
  fs.writeFileSync(f, JSON.stringify(st));
  assert.equal(lib.readOwnedState('dana.okafor@contosohealthlab.com'), null, 'a file without an owner');
  fs.writeFileSync(f, '{"owner":"dana.okafor@contosohealthlab.com","cookies":[');
  assert.equal(lib.readOwnedState('dana.okafor@contosohealthlab.com'), null, 'a truncated file');
  fs.rmSync(f);
  assert.equal(lib.readOwnedState('dana.okafor@contosohealthlab.com'), null, 'no file');
});

test('keychainWrite: a failing security -i reports the exit code, never its output', async () => {
  await withFake(fakeSecurity(1, 'add-generic-password ... -w SECRETVALUE'), (l) => {
    assert.throws(() => l.keychainWrite('contoso-lab-x', 'a@b', 'label', 'SECRETVALUE'), (e) => /security exit 1/.test(e.message) && !/SECRETVALUE/.test(e.message));
  });
});

// ---- overlapping sign-ins never share a code (per-user lock) ------------------
test('freshTotp: two overlapping calls for one user get codes from different windows', async () => {
  const upn = 'test-user-b@contosohealthlab.com';
  let t = 1_700_000_010_000; // 10 s into a 30-s window
  const clock = { now: () => t, sleep: async (ms) => { t += ms; await new Promise((r) => setImmediate(r)); } };
  fs.rmSync(path.join(home, 'session', 'browser', 'test-user-b.totp-step'), { force: true });
  const [a, b] = await Promise.all([lib.freshTotp(upn, RFC_SEED, clock), lib.freshTotp(upn, RFC_SEED, clock)]);
  assert.notEqual(a, b, 'the second caller must wait for the next window');
  const first = Math.floor(1_700_000_010_000 / 30000);
  assert.ok([a, b].includes(lib.hotp(lib.base32Decode(RFC_SEED), first)), 'one caller uses the current window');
  assert.ok([a, b].includes(lib.hotp(lib.base32Decode(RFC_SEED), first + 1)), 'the other uses the next one');
  assert.equal(fs.existsSync(path.join(home, 'session', 'browser', 'test-user-b.totp-lock')), false, 'the lock is released');
});

test('freshTotp: a lock left by a crashed run (older than 90 s) is taken over', async () => {
  const upn = 'test-user-c@contosohealthlab.com';
  const lock = path.join(home, 'session', 'browser', 'test-user-c.totp-lock');
  fs.writeFileSync(lock, '');
  const old = (Date.now() - 120000) / 1000; fs.utimesSync(lock, old, old);
  fs.rmSync(path.join(home, 'session', 'browser', 'test-user-c.totp-step'), { force: true });
  let t = 1_700_000_010_000;
  const code = await lib.freshTotp(upn, RFC_SEED, { now: () => t, sleep: async (ms) => { t += ms; } });
  assert.equal(code, lib.hotp(lib.base32Decode(RFC_SEED), Math.floor(1_700_000_010_000 / 30000)));
});

// ---- when is a browser "signed in"? (signin.mjs landing + verdict) ----------
const { verdict, landing } = await import('../signin.mjs');
const base = { onApp: true, untilGiven: false, untilOk: false, land: 'ok', passwordOnScreen: false, steadyMs: 3000 };

test('landing: each known app has a positive signal', () => {
  assert.equal(landing('https://myapps.microsoft.com/', 'Apps dashboard'), 'ok');
  assert.equal(landing('https://myaccount.microsoft.com/', 'My Account Overview'), 'ok');
  assert.equal(landing('https://d-90666212c7.awsapps.com/start/#/', 'AWS access portal Accounts'), 'ok');
  assert.equal(landing('https://integrator-8288815.okta.com/app/UserHome', 'My Apps'), 'ok');
  assert.equal(landing('https://integrator-8288815.okta.com/oauth2/v1/authorize/callback', 'Connecting to'), 'wait', 'Okta mid-flow is not the dashboard');
});

test('landing: an app\'s own refusal page is a failure, not a sign-in (ServiceNow user with no account; Okta factor wall)', () => {
  assert.match(landing('https://dev459905.service-now.com/navpage.do', 'User: test-user-c@contosohealthlab.com not found'), /^denied: ServiceNow/);
  assert.match(landing('https://dev459905.service-now.com/', 'Ensure that the user you are logging in with is active, not locked out'), /^denied/);
  assert.match(landing('https://integrator-8288815.okta.com/oauth2/v1/authorize/callback', 'Set up security methods Okta Verify Required now'), /^denied: Okta/);
});

test('landing: an app with no known signal is "unknown"; a custom signal or refusal pattern can be given', () => {
  assert.equal(landing('https://example.org/home', 'Welcome'), 'unknown');
  assert.equal(landing('https://example.org/home', 'Welcome', { text: /Welcome/ }), 'ok');
  assert.match(landing('https://example.org/home', 'Access denied', { text: /Welcome/, denied: /Access denied/ }), /^denied/);
});

test('landing: a caller\'s refusal pattern adds to the app\'s built-in ones (never replaces them)', () => {
  const custom = { denied: /session expired/i };
  assert.match(landing('https://dev459905.service-now.com/', 'ServiceNow User: x@contosohealthlab.com not found', custom), /^denied: ServiceNow/);
  assert.match(landing('https://dev459905.service-now.com/', 'ServiceNow - your session expired', custom), /^denied: ServiceNow/);
});

test('verdict: the app\'s positive signal = signed in (also when saved cookies skipped Entra)', () => {
  assert.equal(verdict(base), 'done');
});
test('verdict: a refusal page after the Entra round trip is "denied", never done - with or without until', () => {
  assert.equal(verdict({ ...base, land: 'denied: ServiceNow' }), 'denied');
  assert.equal(verdict({ ...base, land: 'denied: ServiceNow', untilGiven: true, untilOk: true }), 'denied');
});
test('verdict: an app with no known signal and no until is an error, not ok', () => {
  assert.equal(verdict({ ...base, land: 'unknown' }), 'unknown-app');
  assert.equal(verdict({ ...base, land: 'unknown', steadyMs: 1000 }), 'wait');
});
test('verdict: a known app not yet showing its signal = wait (times out as an error)', () => {
  assert.equal(verdict({ ...base, land: 'wait' }), 'wait');
});
test('verdict: an app page showing a password box (its own sign-in page) is signed out', () => {
  assert.equal(verdict({ ...base, land: 'wait', passwordOnScreen: true }), 'signed-out');
});
test('verdict: with an until test, until decides (after the refusal check)', () => {
  assert.equal(verdict({ ...base, untilGiven: true, untilOk: false }), 'wait');
  assert.equal(verdict({ ...base, land: 'unknown', untilGiven: true, untilOk: true }), 'done');
});
test('verdict: still on Entra = wait', () => {
  assert.equal(verdict({ ...base, onApp: false }), 'wait');
});

// ---- stale-lock recovery against a lock replaced mid-inspection ----------------
test('recoverStaleLock never removes a fresh lock that replaced the stale one, even with the same token', () => {
  const f = path.join(home, 'session', 'browser', 'race.totp-lock');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, 'tok'); const old = (Date.now() - 120000) / 1000; fs.utimesSync(f, old, old);
  // Between inspection and rename, another process recovers the stale lock and
  // takes a FRESH one (a new file) - here with the same token text, the case a
  // content-only check would get wrong.
  const r = lib.recoverStaleLock(f, { afterInspect: () => { fs.rmSync(f); fs.writeFileSync(f, 'tok'); } });
  assert.equal(r, true);
  assert.equal(fs.existsSync(f), true, 'the fresh lock is still there');
  assert.ok(Date.now() - fs.statSync(f).mtimeMs < 60000, 'and it is the fresh one');
  assert.deepEqual(fs.readdirSync(path.dirname(f)).filter((n) => n.startsWith('race.totp-lock.')), [], 'nothing left aside');
  fs.rmSync(f);
});

test('recoverStaleLock removes a lock that really is stale, and leaves a fresh one alone', () => {
  const f = path.join(home, 'session', 'browser', 'race2.totp-lock');
  fs.writeFileSync(f, 'crashed'); const old = (Date.now() - 120000) / 1000; fs.utimesSync(f, old, old);
  assert.equal(lib.recoverStaleLock(f), true);
  assert.equal(fs.existsSync(f), false);
  fs.writeFileSync(f, 'live');
  assert.equal(lib.recoverStaleLock(f), false);
  assert.equal(fs.readFileSync(f, 'utf8'), 'live');
  fs.rmSync(f);
});

// ---- pages where Entra stops the sign-in (signin.mjs entraBlocker) ------------
const { entraBlocker } = await import('../signin.mjs');
test('entraBlocker: an AADSTS error is reported with its code', () => {
  assert.match(entraBlocker('Sign in\nAADSTS70013: The \'request\' request parameter is not supported.\n'), /Entra refused the sign-in: AADSTS70013/);
});
test('entraBlocker: an admin-consent wall names the app and the fix (seen live on okta-clinic-idp)', () => {
  const m = entraBlocker('test-user-b@contosohealthlab.com\nApproval required\nokta-clinic-idp\nThis app requires your admin\'s approval to:');
  assert.match(m, /admin to consent to the app "okta-clinic-idp"/);
  assert.match(m, /Grant admin consent/);
});
test('entraBlocker: a registration interrupt points at enroll.mjs', () => {
  assert.match(entraBlocker('More information required\nYour organization needs more information'), /run enroll\.mjs/);
});
test('entraBlocker: ordinary sign-in pages are not blockers', () => {
  assert.equal(entraBlocker('Sign in\nCan\'t access your account?\nNext'), null);
  assert.equal(entraBlocker('Enter code\nEnter the code displayed in your authenticator app'), null);
});

// ---- the lock across processes ------------------------------------------------
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
function child(env) {
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, [fileURLToPath(new URL('./totp-child.mjs', import.meta.url))], { env: { ...process.env, ...env } });
    let out = '', err = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { err += d; });
    c.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(err))));
  });
}

test('two processes recovering the same stale lock still get different codes, and leave no lock behind', async () => {
  const upn = 'test-user-a@contosohealthlab.com';
  const dir = path.join(home, 'session', 'browser');
  const lock = path.join(dir, 'test-user-a.totp-lock');
  fs.rmSync(path.join(dir, 'test-user-a.totp-step'), { force: true });
  fs.writeFileSync(lock, 'crashed-holder'); const old = (Date.now() - 120000) / 1000; fs.utimesSync(lock, old, old);
  const env = { UPN: upn, SEED: RFC_SEED, T0: String(1_700_000_010_000), START: String(Date.now()) };
  const [a, b] = await Promise.all([child(env), child(env)]);
  assert.notEqual(a, b, 'the second process must wait for the next window');
  assert.equal(fs.existsSync(lock), false, 'no lock left behind');
  assert.deepEqual(fs.readdirSync(dir).filter((n) => n.startsWith('test-user-a.totp-lock.')), [], 'no renamed-aside lock left behind');
});

test('a holder never removes a lock it does not own', async () => {
  const upn = 'test-user-b@contosohealthlab.com';
  const lock = path.join(home, 'session', 'browser', 'test-user-b.totp-lock');
  fs.rmSync(path.join(home, 'session', 'browser', 'test-user-b.totp-step'), { force: true });
  let t = 1_700_000_010_000;
  // While "we" hold the lock, someone else's lock replaces it (as after a wrong
  // stale recovery). Our release must leave theirs in place.
  const clock = { now: () => t, sleep: async (ms) => { t += ms; fs.writeFileSync(lock, 'someone-else'); } };
  fs.writeFileSync(path.join(home, 'session', 'browser', 'test-user-b.totp-step'), String(Math.floor(t / 30000))); // force one wait
  await lib.freshTotp(upn, RFC_SEED, clock);
  assert.equal(fs.readFileSync(lock, 'utf8'), 'someone-else');
  fs.rmSync(lock);
});

test('keychainDelete: missing (exit 44) is false, other failures throw', async () => {
  await withFake(fakeSecurity(44), (l) => assert.equal(l.keychainDelete('contoso-lab-x'), false));
  await withFake(fakeSecurity(36), (l) => assert.throws(() => l.keychainDelete('contoso-lab-x'), /Keychain delete failed \(security exit 36\)/));
  await withFake(fakeSecurity(0), (l) => assert.equal(l.keychainDelete('contoso-lab-x'), true));
});
