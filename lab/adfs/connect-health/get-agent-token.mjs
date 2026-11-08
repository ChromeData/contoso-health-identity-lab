#!/usr/bin/env node
// =============================================================================
// get-agent-token.mjs - sign in as a lab admin WITH A PASSKEY and get the
// access token the Microsoft Entra Connect Health agent's own registration
// asks for, so Register-MicrosoftEntraConnectHealthAgent -AadToken can run
// on DC01 with no person at the server. ADR 0031.
//
//   node lab/adfs/connect-health/get-agent-token.mjs <upn> [--dry-run]
//
// WHAT IT ASKS FOR (read from the agent itself, 4.5.2487.0 on DC01,
// 2026-11-07, its registration log line "Obtaining token using credential"):
//   client id  cf6d7e68-f018-4e0a-a7b3-126e053fb88d  (the agent's public client)
//   scope      https://management.core.windows.net/.default
//   redirect   https://login.microsoftonline.com/common/oauth2/nativeclient
// The agent then calls Azure Resource Manager
// (https://management.azure.com/providers/Microsoft.ADHybridHealthService/).
//
// WHY A PASSKEY SIGN-IN AND NOT -Credential: ARM enforces Microsoft's
// mandatory MFA (Phase 2, from 2025-10-01) on every create/update/delete by a
// USER, "regardless of ... user exclusions" (Learn, "Plan for mandatory
// Microsoft Entra MFA"). -Credential is a password-only (ROPC) sign-in, so it
// cannot pass that check even with a Conditional Access exclusion. A passkey
// sign-in is MFA (phishing-resistant), so CA001 and the ARM check are both met
// and no Conditional Access policy changes.
//
// FLOW: OAuth 2.0 authorization code + PKCE (RFC 7636) for a public client.
// The passkey sign-in runs in headless Chromium (lab/scripts/demo/signin/
// passkey.mjs authorize()); the redirect is caught in the browser, never
// followed; the code is redeemed here with the code_verifier.
//
// SECRETS: the access token goes straight into the Keychain item
// contoso-lab-connecthealth-token (stdin to `security -i`), is read from there
// by run-on-dc.py as a PROTECTED run-command parameter, and is deleted by
// register.sh right after. It is never printed: only its non-secret claims
// (aud, upn, amr, roles count, exp) are shown. No refresh token is requested
// (no offline_access), so nothing outlives the access token's ~1 hour.
//
// --dry-run: sign in and show the claims, but do NOT store the token.
// =============================================================================
import crypto from 'node:crypto';
import { authorize } from '../../scripts/demo/signin/passkey.mjs';
import { keychainWrite } from '../../scripts/demo/signin/lib.mjs';

export const CLIENT_ID = 'cf6d7e68-f018-4e0a-a7b3-126e053fb88d';
export const SCOPE = 'https://management.core.windows.net/.default';
export const REDIRECT = 'https://login.microsoftonline.com/common/oauth2/nativeclient';
export const TENANT = '86a2e327-4951-4348-a3c4-6f4b79ffd8f2';
export const KEYCHAIN = 'contoso-lab-connecthealth-token';

const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function pkce() {
  const verifier = b64url(crypto.randomBytes(32));
  return { verifier, challenge: b64url(crypto.createHash('sha256').update(verifier).digest()) };
}

export function authorizeUrl(upn, challenge, state) {
  const q = new URLSearchParams({
    client_id: CLIENT_ID, response_type: 'code', redirect_uri: REDIRECT, scope: SCOPE,
    code_challenge: challenge, code_challenge_method: 'S256', state, login_hint: upn, prompt: 'login',
  });
  return `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize?${q}`;
}

// Non-secret claims only. Fails closed on anything unexpected.
export function claimsOf(token, upn) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('not a JWT');
  const c = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
  const out = { aud: c.aud, tid: c.tid, upn: c.upn || c.unique_name, appid: c.appid || c.azp, amr: c.amr, wids: (c.wids || []).length, exp: new Date(c.exp * 1000).toISOString() };
  if (out.tid !== TENANT) throw new Error(`token tenant ${out.tid} is not the lab tenant`);
  if (out.appid !== CLIENT_ID) throw new Error(`token client ${out.appid} is not the agent's`);
  if (String(out.upn).toLowerCase() !== upn.toLowerCase()) throw new Error(`token user ${out.upn} is not ${upn}`);
  if (!Array.isArray(out.amr) || !out.amr.includes('mfa')) throw new Error(`token amr ${JSON.stringify(out.amr)} has no mfa`);
  return out;
}

async function main() {
  const [upn, ...flags] = process.argv.slice(2);
  if (!upn || !/^[^@\s]+@[^@\s]+$/.test(upn)) { console.error('usage: get-agent-token.mjs <upn> [--dry-run]'); process.exit(2); }
  const dry = flags.includes('--dry-run');
  const { verifier, challenge } = pkce();
  const state = b64url(crypto.randomBytes(16));
  const redirected = new URL(await authorize(upn, authorizeUrl(upn, challenge, state), REDIRECT));
  if (redirected.searchParams.get('state') !== state) throw new Error('state mismatch on the redirect');
  if (redirected.searchParams.get('error')) throw new Error(`Entra refused: ${redirected.searchParams.get('error')}: ${redirected.searchParams.get('error_description')}`);
  const code = redirected.searchParams.get('code');
  if (!code) throw new Error('no code on the redirect');
  const res = await fetch(`https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, scope: SCOPE }),
  });
  const j = await res.json();
  if (!res.ok || !j.access_token) throw new Error(`token endpoint ${res.status}: ${j.error || ''} ${(j.error_description || '').split('\r\n')[0]}`);
  const claims = claimsOf(j.access_token, upn);
  if (!dry) keychainWrite(KEYCHAIN, upn, 'Connect Health agent registration token (temporary, ~1 h)', j.access_token);
  console.log(JSON.stringify({ ok: true, stored: dry ? false : KEYCHAIN, claims }, null, 2));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // Exit explicitly: the sign-in driver's loop keeps timers alive until its
  // own deadline after the code is caught (seen 2026-11-07, ~3 min idle).
  main().then(() => process.exit(0), (e) => { console.error(`get-agent-token: ${e.message}`); process.exit(1); });
}
