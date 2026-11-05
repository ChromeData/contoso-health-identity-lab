// node --test lab/scripts/demo/tests/passkey.test.mjs
// Offline tests for the pure parts of lab/scripts/demo/signin/passkey.mjs:
// who may be touched, which registration path an account gets, the Graph ->
// browser option mapping, the clientDataJSON check, the credential pick and
// the Keychain record format. Nothing here signs in, calls Graph or touches
// the Keychain (importing the module runs no command: its CLI is guarded).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checkUpn, chooseVia, keychainService, b64ToB64url, b64urlToB64, encodeRecord, decodeRecord,
  toBrowserCreationOptions, checkClientData, pickCredential, SECURITY_KEY_CHOICE, DISPLAY_NAME, AUTHENTICATOR,
  pendingService, newMethods, resolvePost, proofVerdict,
} from '../signin/passkey.mjs';

const BG = 'bg-admin-01@ContosoHealthLab.onmicrosoft.com';
const ADM = 'adm-ava.lin@contosohealthlab.onmicrosoft.com';

test('the owner is always refused, break-glass only with --break-glass, other tenants never', () => {
  assert.throws(() => checkUpn('MichaelWilliams@ContosoHealthLab.onmicrosoft.com'), /owner/);
  assert.throws(() => checkUpn('MichaelWilliams@ContosoHealthLab.onmicrosoft.com', { breakGlass: true }), /owner/);
  assert.throws(() => checkUpn(BG), /--break-glass/);
  assert.equal(checkUpn(BG, { breakGlass: true }), BG.toLowerCase());
  assert.throws(() => checkUpn(ADM, { breakGlass: true }), /not a bg-admin-NN/);
  assert.equal(checkUpn(ADM), ADM);
  assert.throws(() => checkUpn('someone@contoso.com'), /lab tenant/);
  assert.throws(() => checkUpn('a"b@contosohealthlab.com'), /not a user principal name/);
  assert.equal(keychainService(BG), 'contoso-lab-passkey-bg-admin-01');
});

test('break-glass never gets a Temporary Access Pass; others default to the TAP path', () => {
  assert.equal(chooseVia(BG.toLowerCase()), 'graph');
  assert.throws(() => chooseVia(BG.toLowerCase(), 'tap'), /never get a Temporary Access Pass/);
  assert.equal(chooseVia(ADM), 'tap');
  assert.equal(chooseVia(ADM, 'graph'), 'graph');
  assert.throws(() => chooseVia(ADM, 'sms'), /tap or graph/);
});

test('base64 and base64url round-trip', () => {
  const b = Buffer.from([251, 255, 0, 1, 2]);
  const url = b64ToB64url(b.toString('base64'));
  assert.equal(url, '-_8AAQI');
  assert.deepEqual(Buffer.from(b64urlToB64(url), 'base64'), b);
});

test('the Keychain record carries what addCredential needs and refuses anything less', () => {
  const rec = { upn: ADM, rpId: 'login.microsoft.com', credentialId: 'Y3JlZA==', privateKey: 'cHJpdg==', userHandle: 'dXNlcg==', signCount: 1, methodId: null };
  const enc = encodeRecord(rec);
  assert.match(enc, /^[A-Za-z0-9+/=]+$/); // one token for `security -i`
  assert.deepEqual(decodeRecord(enc), { v: 1, ...rec });
  assert.throws(() => encodeRecord({ ...rec, privateKey: '' }), /privateKey/);
  assert.throws(() => encodeRecord({ ...rec, signCount: -1 }), /signCount/);
  assert.throws(() => decodeRecord(Buffer.from('{"v":2}').toString('base64')), /unknown format/);
  assert.throws(() => decodeRecord('not json at all'), /base64 JSON/);
});

// The shape GET .../fido2Methods/creationOptions returned on 2026-11-05 (beta).
const graphOptions = {
  challengeTimeoutDateTime: '2026-11-05T10:47:41Z',
  publicKey: {
    attestation: 'direct',
    authenticatorSelection: { authenticatorAttachment: 'cross-platform', requireResidentKey: true, userVerification: 'required' },
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    excludeCredentials: [{ id: '0S64X8KwFmCeJjHzK1oE/39T+JYhfYbhFurwOxMMjtvRWc/sLYq8AMJVuva823XQ1', type: 'public-key', transports: [] }],
    extensions: { credentialProtectionPolicy: 'userVerificationOptional', enforceCredentialProtectionPolicy: true, hmacCreateSecret: true },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }, { alg: -257, type: 'public-key' }],
    rp: { id: 'login.microsoft.com', name: 'Microsoft' },
    timeout: 0,
    user: { displayName: 'BG ADMIN 01', id: 'T0Y6J-OihlFJ', name: BG },
  },
};

test('Graph creation options map to what Chromium accepts', () => {
  const o = toBrowserCreationOptions(graphOptions);
  assert.equal(o.rp.id, 'login.microsoft.com');
  assert.equal(o.challenge, graphOptions.publicKey.challenge);
  assert.deepEqual(o.excludeCredentials, []); // the virtual authenticator is new and empty
  assert.equal(o.timeout, 120000); // Graph's 0 = none given
  assert.equal(o.extensions.enforceCredentialProtectionPolicy, undefined); // Chromium: NotSupportedError with UV-optional
  assert.equal(o.extensions.credentialProtectionPolicy, 'userVerificationOptional');
  assert.equal(o.authenticatorSelection.requireResidentKey, true);
  // A stricter credProtect level keeps its enforcement flag.
  const strict = toBrowserCreationOptions({ value: { publicKey: { ...graphOptions.publicKey, extensions: { credentialProtectionPolicy: 'userVerificationRequired', enforceCredentialProtectionPolicy: true } } } });
  assert.equal(strict.extensions.enforceCredentialProtectionPolicy, true);
  assert.throws(() => toBrowserCreationOptions({ publicKey: { rp: { id: 'x' } } }), /challenge/);
});

test('clientDataJSON must echo the issued challenge and the relying party origin', () => {
  const cd = (o) => b64ToB64url(Buffer.from(JSON.stringify(o)).toString('base64'));
  const ok = cd({ type: 'webauthn.create', challenge: 'Y2hhbGxlbmdlLWJ5dGVz', origin: 'https://login.microsoft.com', crossOrigin: false });
  assert.equal(checkClientData(ok, 'Y2hhbGxlbmdlLWJ5dGVz', 'https://login.microsoft.com').type, 'webauthn.create');
  assert.throws(() => checkClientData(cd({ type: 'webauthn.create', challenge: 'b3RoZXI', origin: 'https://login.microsoft.com' }), 'Y2hhbGxlbmdlLWJ5dGVz', 'https://login.microsoft.com'), /challenge differs/);
  assert.throws(() => checkClientData(cd({ type: 'webauthn.create', challenge: 'Y2hhbGxlbmdlLWJ5dGVz', origin: 'https://evil.example' }), 'Y2hhbGxlbmdlLWJ5dGVz', 'https://login.microsoft.com'), /origin/);
  assert.throws(() => checkClientData(cd({ type: 'webauthn.get', challenge: 'Y2hhbGxlbmdlLWJ5dGVz', origin: 'https://login.microsoft.com' }), 'Y2hhbGxlbmdlLWJ5dGVz', 'https://login.microsoft.com'), /type/);
});

test('exactly one discoverable Entra credential is exported', () => {
  const c = { credentialId: 'aWQ=', privateKey: 'cGs=', rpId: 'login.microsoft.com', userHandle: 'dQ==', signCount: 1, isResidentCredential: true };
  assert.equal(pickCredential([c, { ...c, rpId: 'example.com' }]), c);
  assert.throws(() => pickCredential([]), /found 0/);
  assert.throws(() => pickCredential([c, { ...c, credentialId: 'b3RoZXI=' }]), /found 2/);
  assert.throws(() => pickCredential([{ ...c, isResidentCredential: false }]), /not discoverable/);
});

test('the wizard choice prefers a security key; the passkey name fits Entra and the authenticator is UV-capable', () => {
  assert.ok(SECURITY_KEY_CHOICE.test('Security key or another device'));
  assert.ok(!SECURITY_KEY_CHOICE.test('Microsoft Authenticator'));
  assert.ok(DISPLAY_NAME.length <= 30); // Entra keeps 30 characters
  assert.deepEqual([AUTHENTICATOR.protocol, AUTHENTICATOR.hasResidentKey, AUTHENTICATOR.hasUserVerification, AUTHENTICATOR.isUserVerified], ['ctap2', true, true, true]);
});

test('a new key waits in the -pending item; only methods Graph did not list before count as new', () => {
  assert.equal(pendingService(BG), 'contoso-lab-passkey-bg-admin-01-pending');
  assert.deepEqual(newMethods([{ id: 'old' }], [{ id: 'old' }, { id: 'new' }]).map((m) => m.id), ['new']);
  assert.deepEqual(newMethods([], undefined), []);
});

test('a lost POST response never discards a key Entra registered', () => {
  assert.deepEqual(resolvePost({ id: 'm1' }, []), { methodId: 'm1' });
  // The POST failed or came back empty, but Graph now lists exactly one new method: keep the key.
  assert.deepEqual(resolvePost(null, [{ id: 'm2' }]), { methodId: 'm2' });
  assert.deepEqual(resolvePost({}, [{ id: 'm2' }]), { methodId: 'm2' });
  // Nothing new is listed: Entra really refused it, the pending key may go.
  assert.deepEqual(resolvePost(null, []), { rejected: true });
  // Two new methods: a person decides, the key is kept.
  assert.deepEqual(resolvePost(null, [{ id: 'a' }, { id: 'b' }]), { ambiguous: true });
});

test('a proof only passes when the passkey really signed in', () => {
  const ok = { signCountBefore: 1, signCountAfter: 2, sawLogin: true, landedHost: 'myaccount.microsoft.com', targetHost: 'myaccount.microsoft.com', trail: ['username'], expectText: ADM, text: `Welcome back ${ADM.toUpperCase()}` };
  assert.deepEqual(proofVerdict(ok), { ok: true, reasons: [] });
  // A public landing page: right host, plenty of text, but no assertion and no Entra.
  const landing = proofVerdict({ ...ok, signCountAfter: 1, sawLogin: false, expectText: null });
  assert.equal(landing.ok, false);
  assert.match(landing.reasons.join(' '), /not used/);
  assert.match(landing.reasons.join(' '), /never went through/);
  assert.equal(proofVerdict({ ...ok, signCountAfter: null }).ok, false); // credential vanished
  assert.match(proofVerdict({ ...ok, landedHost: 'login.microsoftonline.com' }).reasons.join(' '), /ended on/);
  assert.match(proofVerdict({ ...ok, trail: ['username', 'temporary access pass'] }).reasons.join(' '), /Temporary Access Pass/);
  assert.match(proofVerdict({ ...ok, text: 'Welcome back, someone else' }).reasons.join(' '), /does not show/);
});
