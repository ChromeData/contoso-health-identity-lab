// Offline tests for enroll.mjs's secret-handling steps: a fake Graph and a
// fake Keychain record every call, and each step is made to fail at each
// point. Run: node --test lab/scripts/demo/signin/tests/enroll.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.CONTOSO_OPERATOR_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'enroll-test-'));
process.env.SIGNIN_QUIET = '1';
const { setRandomPassword, stageSeed, promoteSeed, tapCleaner } = await import('../enroll.mjs');

const UPN = 'test-user-c@contosohealthlab.com', UID = 'u-c';
const PW = 'contoso-lab-pw-test-user-c', PW_PENDING = 'contoso-lab-pw-test-user-c-pending';
const SEED = 'contoso-lab-totp-test-user-c', SEED_PENDING = 'contoso-lab-totp-test-user-c-pending';

// A Keychain in memory; `failWrite` names an item whose write throws.
function fakeKeychain(start = {}, { failWrite } = {}) {
  const items = { ...start }, ops = [];
  return {
    items, ops,
    read: (s) => { ops.push(`read ${s}`); return s in items ? items[s] : null; },
    write: (s, _a, _l, v) => { ops.push(`write ${s}`); if (s === failWrite) throw new Error(`Keychain write to ${s} failed (security exit 36)`); items[s] = v; },
    del: (s) => { ops.push(`del ${s}`); const had = s in items; delete items[s]; return had; },
  };
}
// A Graph that records calls; `fail` = { 'METHOD url-part': Error }.
function fakeGraph(ops, fail = {}) {
  return (method, url) => {
    ops.push(`${method} ${url}`);
    for (const [k, e] of Object.entries(fail)) if (`${method} ${url}`.includes(k)) throw e;
    return {};
  };
}

// ---- password ------------------------------------------------------------------
test('setRandomPassword: saved and read back BEFORE the account changes, then promoted', () => {
  const kc = fakeKeychain();
  const r = setRandomPassword({ upn: UPN, uid: UID, kc, g: fakeGraph(kc.ops), gen: () => 'Pw-1' });
  assert.deepEqual(kc.ops, [`write ${PW_PENDING}`, `read ${PW_PENDING}`, `PATCH users/${UID}`, `write ${PW}`, `del ${PW_PENDING}`]);
  assert.deepEqual(r, { service: PW, value: 'Pw-1' });
  assert.deepEqual(kc.items, { [PW]: 'Pw-1' });
});

test('setRandomPassword: a Keychain that cannot save means the account is never changed', () => {
  const kc = fakeKeychain({}, { failWrite: PW_PENDING });
  assert.throws(() => setRandomPassword({ upn: UPN, uid: UID, kc, g: fakeGraph(kc.ops), gen: () => 'Pw-2' }), /failed/);
  assert.equal(kc.ops.some((o) => o.startsWith('PATCH')), false, 'no PATCH after a failed save');
});

test('setRandomPassword: if Graph refuses the new password, the unused one is removed and the real item untouched', () => {
  const kc = fakeKeychain({ [PW]: 'old' });
  const g = fakeGraph(kc.ops, { PATCH: new Error('Forbidden (403)') });
  assert.throws(() => setRandomPassword({ upn: UPN, uid: UID, kc, g, gen: () => 'Pw-3' }), /403/);
  assert.deepEqual(kc.items, { [PW]: 'old' });
});

test('setRandomPassword: if promotion fails after the account changed, the error names the item that holds the password', () => {
  const kc = fakeKeychain({}, { failWrite: PW });
  assert.throws(() => setRandomPassword({ upn: UPN, uid: UID, kc, g: fakeGraph(kc.ops), gen: () => 'Pw-4' }),
    (e) => e.message.includes(`saved ONLY in Keychain item ${PW_PENDING}`));
  assert.equal(kc.items[PW_PENDING], 'Pw-4', 'the password in force is still held');
});

// ---- authenticator seed ------------------------------------------------------------
test('stageSeed never touches the seed sign-ins use', () => {
  const kc = fakeKeychain({ [SEED]: 'OLDSEED' });
  assert.equal(stageSeed({ upn: UPN, seed: 'NEWSEED', kc }), SEED_PENDING);
  assert.deepEqual(kc.items, { [SEED]: 'OLDSEED', [SEED_PENDING]: 'NEWSEED' });
});

test('promoteSeed replaces the seed only when called (after Entra confirmed), and clears the pending item', () => {
  const kc = fakeKeychain({ [SEED]: 'OLDSEED', [SEED_PENDING]: 'NEWSEED' });
  promoteSeed({ upn: UPN, seed: 'NEWSEED', kc });
  assert.deepEqual(kc.items, { [SEED]: 'NEWSEED' });
  assert.deepEqual(kc.ops, [`write ${SEED}`, `del ${SEED_PENDING}`]);
});

// ---- the Temporary Access Pass ------------------------------------------------------
test('tapCleaner: nothing issued, nothing deleted', () => {
  const ops = [];
  tapCleaner({ upn: UPN, uid: UID, g: fakeGraph(ops) }).remove();
  assert.deepEqual(ops, []);
});

test('tapCleaner: a pass confirmed gone (404) counts as removed', () => {
  const ops = [];
  const t = tapCleaner({ upn: UPN, uid: UID, g: fakeGraph(ops, { DELETE: new Error('ERROR: Not Found({"error":{"code":"Request_ResourceNotFound"}})') }) });
  t.set('tap-1'); t.remove();
  assert.equal(t.id, null);
});

test('tapCleaner: any other failure is loud, names the pass and the fix, and keeps the id for a retry', () => {
  const ops = []; let fail = true;
  const g = (m, u) => { ops.push(`${m} ${u}`); if (fail) throw new Error('ERROR: Forbidden({"error":{"code":"Authorization_RequestDenied"}})'); return {}; };
  const t = tapCleaner({ upn: UPN, uid: UID, g });
  t.set('tap-2');
  assert.throws(() => t.remove(), (e) => /Temporary Access Pass tap-2/.test(e.message) && /stays valid/.test(e.message) && /--method DELETE/.test(e.message));
  assert.equal(t.id, 'tap-2', 'id kept');
  fail = false; t.remove();
  assert.equal(t.id, null);
  assert.equal(ops.length, 2, 'the second call retried the delete');
});
