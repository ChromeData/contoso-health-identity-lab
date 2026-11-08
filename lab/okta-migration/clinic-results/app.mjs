#!/usr/bin/env node
// =============================================================================
// lab/okta-migration/clinic-results/app.mjs - "Clinic Lab Results"
// -----------------------------------------------------------------------------
//   node lab/okta-migration/clinic-results/app.mjs        # http://localhost:8471
//
// The acquired clinic's lab results viewer, the app wave 1 moves from Okta to
// Entra. It is a real OpenID Connect relying party with no dependencies:
//   * /login     authorization code + PKCE (S256) + state + nonce, sent to
//                the IdP the config names as "active";
//   * /callback  code -> token at that IdP's token endpoint (public client:
//                no secret), then the ID token is VERIFIED: RS256 signature
//                against the IdP's JWKS (node:crypto), iss, aud, exp, nonce;
//   * /          the results page for the signed-in user, with a banner that
//                says which IdP signed them in and the issuer it trusted.
//
// THE TRUST IS CONFIG, AS IN A REAL APP: ~/.contoso-operator/clinic-results/
// idp.json holds the two IdPs (okta, entra) and which one is active. The
// cut-over (cutover.mjs cutover) changes "active" from okta to entra; the
// rollback changes it back. That is the "swap the IdP metadata" step of the
// runbook (Phase 2 step 3), and the saved Okta block is the rollback file.
// The config is outside the repo because it is org-specific (client ids,
// tenant id) - not secret: a public client has no secret.
//
// Every successful sign-in is appended to signins.jsonl next to the config
// (time, idp, issuer, audience, user, amr): cutover.mjs reads it as the test
// result, and nothing in it is a token.
//
// The patient data on the page is fictional, fixed and the same for every
// user: this is a sign-in demo, not a health record.
// =============================================================================
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const CONF_DIR = process.env.CLINIC_RESULTS_DIR || path.join(os.homedir(), '.contoso-operator', 'clinic-results');
export const CONF = path.join(CONF_DIR, 'idp.json');
export const SIGNINS = path.join(CONF_DIR, 'signins.jsonl');
export const PORT = Number(process.env.CLINIC_RESULTS_PORT || 8471);
export const REDIRECT = `http://localhost:${PORT}/callback`;

const b64u = (b) => Buffer.from(b).toString('base64url');

export function pkcePair() {
  const verifier = b64u(crypto.randomBytes(32));
  const challenge = b64u(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

export function authorizeUrl(idp, { state, nonce, challenge, redirect = REDIRECT }) {
  const u = new URL(idp.authorization_endpoint);
  u.search = new URLSearchParams({
    client_id: idp.client_id, response_type: 'code', redirect_uri: redirect,
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256',
  }).toString();
  return u.toString();
}

// Verify an ID token. Pure apart from the JWKS it is given, so it is
// unit-tested with a key made in the test.
export function verifyIdToken(idToken, { jwks, issuer, audience, nonce, now = Math.floor(Date.now() / 1000), skew = 300 }) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) throw new Error('ID token is not a JWS');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  if (header.alg !== 'RS256') throw new Error(`unexpected alg ${header.alg}`);
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no JWKS key for kid ${header.kid}`);
  const key = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new Error('ID token signature does not verify');
  if (claims.iss !== issuer) throw new Error(`issuer ${claims.iss} is not the trusted ${issuer}`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(audience)) throw new Error(`audience ${claims.aud} is not this app (${audience})`);
  if (typeof claims.exp !== 'number' || claims.exp + skew < now) throw new Error('ID token expired');
  if (nonce !== undefined && claims.nonce !== nonce) throw new Error('nonce mismatch');
  return claims;
}

export function signinRecord(idpName, claims, at = new Date()) {
  return {
    at: at.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    idp: idpName,
    issuer: claims.iss,
    audience: Array.isArray(claims.aud) ? claims.aud[0] : claims.aud,
    user: claims.preferred_username || claims.email || claims.upn || claims.sub,
    amr: claims.amr || null,
    auth_time: claims.auth_time || null,
  };
}

// Is this callback the end of a login THIS browser started, with the IdP the
// app trusts now? The login cookie (cr_login, HttpOnly, set by /login) must
// match the one stored with the state: a callback URL carried to another
// browser is refused before the code is exchanged. Pure: unit-tested.
export function checkCallback(pendingEntry, loginCookie, active) {
  if (!pendingEntry) return { ok: false, code: 400, why: 'unknown or used state' };
  if (!loginCookie || !pendingEntry.browser || !crypto.timingSafeEqual(Buffer.from(String(loginCookie).padEnd(64).slice(0, 64)), Buffer.from(String(pendingEntry.browser).padEnd(64).slice(0, 64)))) return { ok: false, code: 400, why: 'this sign-in was started in another browser' };
  if (pendingEntry.idp !== active) return { ok: false, code: 409, why: `the app now trusts ${active}; this sign-in was started with ${pendingEntry.idp}` };
  if (Date.now() - pendingEntry.t > 10 * 60 * 1000) return { ok: false, code: 400, why: 'sign-in took longer than 10 minutes' };
  return { ok: true };
}

// One login id per browser: a second /login (another tab) reuses the
// browser's existing cr_login value instead of replacing it, so the first
// tab's callback still matches. A missing or malformed value gets a new one.
export function browserLoginId(existing, make = () => b64u(crypto.randomBytes(24))) {
  return existing && /^[A-Za-z0-9_-]{32}$/.test(existing) ? existing : make();
}

// The login-id cookie. Path=/ on purpose: /login must SEE it to reuse it
// (a cookie scoped to /callback is never sent to /login). HttpOnly, Lax,
// 10 minutes - it names a browser, it is not a session.
export const loginCookieHeader = (id) => `cr_login=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`;

// Every cr_login value the browser sent. A browser may send two (an old
// Path=/callback cookie from an earlier version next to the Path=/ one, the
// longer path first), so the callback matches against ALL of them.
export function loginCookies(cookieHeader) {
  return [...String(cookieHeader || '').matchAll(/(?:^|;\s*)cr_login=([A-Za-z0-9_-]+)/g)].map((m) => m[1]);
}
// Expires the Path=/callback cookie earlier versions set, so it stops
// shadowing the current one.
export const LEGACY_LOGIN_COOKIE_CLEAR = 'cr_login=; Path=/callback; Max-Age=0';

export function readConf(file = CONF) {
  if (!fs.existsSync(file)) throw new Error(`no IdP config at ${file}: run node lab/okta-migration/cutover.mjs prestage`);
  const c = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!c[c.active]) throw new Error(`config names "${c.active}" active but has no such IdP`);
  return c;
}

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));

export function page({ user, idp, issuer, amr, active }) {
  const who = user
    ? `<div class="banner ${esc(idp)}">Signed in as <b>${esc(user)}</b> through <b>${idp === 'entra' ? 'Microsoft Entra ID' : 'Okta'}</b><br><small>Trusted issuer: ${esc(issuer)}${amr ? ` &middot; amr: ${esc(amr.join(', '))}` : ''}</small></div>`
    : `<div class="banner none">Not signed in. This app trusts <b>${active === 'entra' ? 'Microsoft Entra ID' : 'Okta'}</b>. <a href="/login">Sign in</a></div>`;
  const rows = user ? [
    ['Hemoglobin', '13.8 g/dL', '12.0 - 15.5', 'normal'],
    ['White cell count', '11.9 x10^9/L', '4.5 - 11.0', 'high'],
    ['Potassium', '4.1 mmol/L', '3.5 - 5.1', 'normal'],
    ['Creatinine', '0.9 mg/dL', '0.6 - 1.1', 'normal'],
  ].map((r) => `<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td class="${r[3]}">${r[3]}</td></tr>`).join('') : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clinic Lab Results</title><style>
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f5f7fa;color:#1b1f24}
header{background:#1f3a5f;color:#fff;padding:14px 20px;font-size:18px}main{max-width:820px;margin:20px auto;padding:0 16px}
.banner{padding:12px 14px;border-radius:8px;margin-bottom:16px}.banner.okta{background:#e8eefc;border:1px solid #9db2e8}.banner.entra{background:#e6f4ea;border:1px solid #8cc79d}.banner.none{background:#fff;border:1px solid #d8dde3}
table{border-collapse:collapse;width:100%;background:#fff}td,th{padding:8px;border-bottom:1px solid #e3e7ec;text-align:left}.high{color:#b7791f;font-weight:600}
small{color:#4a5568}footer{color:#6b7280;font-size:13px;margin-top:14px}
</style></head><body><header>Clinic Lab Results</header><main>${who}
${user ? `<h3>Recent results - patient Jordan Example (fictional)</h3><table><tr><th>Test</th><th>Result</th><th>Range</th><th>Flag</th></tr>${rows}</table><p><a href="/logout">Sign out</a></p>` : ''}
<footer>Lab app for the Contoso Health identity lab. Fictional data.</footer></main></body></html>`;
}

async function getJson(url, opts) {
  const r = await fetch(url, opts);
  const t = await r.text();
  if (r.status >= 300) throw new Error(`${url.split('?')[0]}: HTTP ${r.status} ${t.slice(0, 300)}`);
  return JSON.parse(t);
}

export function serve({ port = PORT, conf = CONF } = {}) {
  const pending = new Map(); // state -> { verifier, nonce, idp }
  const sessions = new Map(); // sid -> record
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);
    const sid = (req.headers.cookie || '').match(/(?:^|;\s*)cr_sid=([A-Za-z0-9_-]+)/)?.[1];
    const send = (code, body, headers = {}) => { res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...headers }); res.end(body); };
    try {
      const c = readConf(conf);
      if (url.pathname === '/login') {
        const { verifier, challenge } = pkcePair();
        const state = b64u(crypto.randomBytes(16)); const nonce = b64u(crypto.randomBytes(16));
        // The Path=/ cookie is the one /login can see (the legacy one is
        // scoped to /callback and never sent here).
        const browser = browserLoginId(loginCookies(req.headers.cookie)[0]);
        pending.set(state, { verifier, nonce, idp: c.active, t: Date.now(), browser });
        return send(302, '', { location: authorizeUrl(c[c.active], { state, nonce, challenge, redirect: `http://localhost:${port}/callback` }), 'set-cookie': [loginCookieHeader(browser), LEGACY_LOGIN_COOKIE_CLEAR] });
      }
      if (url.pathname === '/callback') {
        if (url.searchParams.get('error')) return send(400, `<p>Sign-in refused by the IdP: ${esc(url.searchParams.get('error'))}: ${esc(url.searchParams.get('error_description') || '')}</p>`);
        const p = pending.get(url.searchParams.get('state'));
        const sent = loginCookies(req.headers.cookie);
        const loginCookie = sent.find((v) => p && v === p.browser) || sent[0];
        const chk = checkCallback(p, loginCookie, c.active);
        // A callback from another browser does not consume the state: the
        // browser that started the login can still finish it.
        if (p && !/another browser/.test(chk.why || '')) pending.delete(url.searchParams.get('state'));
        if (!chk.ok) return send(chk.code, `<p>Sign-in refused: ${esc(chk.why)}. <a href="/login">Sign in again</a>.</p>`);
        const idp = c[p.idp];
        const tok = await getJson(idp.token_endpoint, {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
          body: new URLSearchParams({ grant_type: 'authorization_code', client_id: idp.client_id, code: url.searchParams.get('code'), redirect_uri: `http://localhost:${port}/callback`, code_verifier: p.verifier, scope: 'openid profile email' }).toString(),
        });
        const jwks = await getJson(idp.jwks_uri);
        const claims = verifyIdToken(tok.id_token, { jwks, issuer: idp.issuer, audience: idp.client_id, nonce: p.nonce });
        const rec = signinRecord(p.idp, claims);
        fs.mkdirSync(path.dirname(conf), { recursive: true, mode: 0o700 });
        fs.appendFileSync(path.join(path.dirname(conf), 'signins.jsonl'), JSON.stringify(rec) + '\n', { mode: 0o600 });
        const id = b64u(crypto.randomBytes(18)); sessions.set(id, rec);
        return send(302, '', { location: '/', 'set-cookie': `cr_sid=${id}; HttpOnly; SameSite=Lax; Path=/` });
      }
      if (url.pathname === '/logout') { if (sid) sessions.delete(sid); return send(302, '', { location: '/', 'set-cookie': 'cr_sid=; Max-Age=0; Path=/' }); }
      if (url.pathname === '/') {
        let s = sid && sessions.get(sid);
        // A session from the IdP the app no longer trusts ends here.
        if (s && s.idp !== c.active) { sessions.delete(sid); s = null; }
        return send(200, page(s ? { ...s, active: c.active } : { active: c.active }));
      }
      return send(404, 'not found');
    } catch (e) {
      return send(500, `<pre>${esc(e.message)}</pre>`);
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`port ${port} is in use (is app.mjs already running? stop it first)`) : e));
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  serve().then(() => console.error(`Clinic Lab Results on http://localhost:${PORT} (trusts: ${readConf().active})`));
}
