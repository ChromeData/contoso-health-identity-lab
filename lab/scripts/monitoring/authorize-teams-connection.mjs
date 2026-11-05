#!/usr/bin/env node
// =============================================================================
// lab/scripts/monitoring/authorize-teams-connection.mjs
//   authorize a playbook's Teams API connection once, headless, AS THE SOC
//   AUTOMATION ACCOUNT (never as a person)
// -----------------------------------------------------------------------------
//   node lab/scripts/monitoring/authorize-teams-connection.mjs <connection> [--as <upn>] [--rg <rg>] [--force] [--headed]
//     <connection>  teams-pb-identity-notify | teams-pb-identity-contain (printed by the deploy scripts)
//     --as          the account the cards come from (default svc-soc-automation@ContosoHealthLab.onmicrosoft.com)
//     --force       re-authorize even when the connection is already Connected
//
// WHAT IT DOES (the portal's "Edit API connection > Authorize", without the
// portal):
//   1. reads the connection as the lab operator and refuses anything that is
//      not a Teams connection in the lab resource group;
//   2. asks ARM for the connection's consent link (listConsentLinks). ARM only
//      hands out a link for the CALLER's own object id, so the request names
//      the operator; the link itself is then completed by whoever signs in;
//   3. signs in at that link as --as with the staff sign-in toolkit
//      (lab/scripts/demo/signin: password + authenticator code from the
//      Keychain, Conditional Access evaluated as for any sign-in), and catches
//      the redirect that carries the one-time consent code;
//   4. hands the code back to ARM (confirmConsentCode), then reads the
//      connection again and FAILS unless it is Connected and its
//      authenticatedUser is exactly --as.
//
// WHY a service account and not a person: whoever authorizes the connection
// is who Teams posts and reads card answers for. A person's leave, password
// reset or MFA re-registration would silently stop containment cards. The
// account owns the SOC team (Team.Create app-only needs a user owner) and holds
// only the Teams service plan of the E5 licence. It has no Azure role: it never
// sees the connection, it only completes the consent ARM started.
//
// WHY these calls (checked 2026-11-05):
//   * listConsentLinks / confirmConsentCode are the ARM actions on
//     Microsoft.Web/connections (api-version 2016-06-01) that the Logic Apps
//     team's sample uses to authorize a connection without the portal
//     (github.com/logicappsio/LogicAppConnectionAuth, LogicAppConnectionAuth.ps1:
//     parameterName "token", the same redirect URL, then confirmConsentCode
//     with the code; read 2026-11-05). Live 2026-11-05: listConsentLinks
//     answers InvalidConsentLinkParameter unless objectId is the CALLER's own
//     ("The client can only request consent links for their own identity"),
//     and confirmConsentCode with { objectId, tenantId, code } leaves the
//     connection Connected as the account that signed in at the link.
//   * The consent code is a short-lived credential: it goes to az on STDIN,
//     never on a command line, and is never printed.
// =============================================================================
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../../..');
const OP = process.env.CONTOSO_OP || path.join(REPO, 'lab/scripts/operator/op');
// The staff sign-in toolkit. SIGNIN_TOOLKIT_DIR lets a run use a checkout of
// it that is not merged here yet.
const TOOLKIT = process.env.SIGNIN_TOOLKIT_DIR || path.join(REPO, 'lab/scripts/demo/signin');
const { drive } = await import(pathToFileURL(path.join(TOOLKIT, 'signin.mjs')).href);
const { checkUpn, passwordFor, playwright, shot, pageText, sleep, log } = await import(pathToFileURL(path.join(TOOLKIT, 'lib.mjs')).href);

const DEFAULT_AS = 'svc-soc-automation@ContosoHealthLab.onmicrosoft.com';
const REDIRECT = 'https://ema1.exp.azure.com/ema/default/authredirect';
const API = '2016-06-01';

// ---- az as the lab operator --------------------------------------------------
function az(args, input) {
  const out = execFileSync(OP, ['az', ...args, '--only-show-errors'], {
    input, encoding: 'utf8', stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], maxBuffer: 32 << 20,
  });
  return out.trim() ? JSON.parse(out) : null;
}
const armPost = (url, body) => az(['rest', '--method', 'POST', '--url', url, '--headers', 'Content-Type=application/json', '--body', '@/dev/stdin', '-o', 'json'], JSON.stringify(body));

function readConnection(rg, name) {
  const c = az(['resource', 'show', '-g', rg, '-n', name, '--resource-type', 'Microsoft.Web/connections', '-o', 'json']);
  if (!c || !c.id) throw new Error(`connection ${name} not found in ${rg}`);
  return {
    id: c.id,
    api: (c.properties?.api?.name || c.properties?.api?.id || '').split('/').pop(),
    status: (c.properties?.statuses || []).map((s) => s.status).join(',') || 'unknown',
    user: c.properties?.authenticatedUser?.name || '',
  };
}

// ---- CLI ---------------------------------------------------------------------
const a = process.argv.slice(2);
const flag = (n) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
const val = (n, d) => { const i = a.indexOf(n); if (i < 0) return d; const v = a[i + 1]; a.splice(i, 2); return v; };
const force = flag('--force'), headed = flag('--headed');
const upn = checkUpn(val('--as', DEFAULT_AS)); // refuses the owner's and break-glass accounts
const rg = val('--rg', 'rg-identity-lab');
const [name] = a;
if (!name || a.length !== 1) { console.error('usage: node authorize-teams-connection.mjs <connection> [--as <upn>] [--rg <rg>] [--force] [--headed]'); process.exit(2); }

const result = (o) => { console.log(JSON.stringify({ connection: name, ...o })); };
try {
  let conn = readConnection(rg, name);
  // Fail closed: this script only ever authorizes Teams connections.
  if (conn.api !== 'teams') throw new Error(`${name} is a '${conn.api}' connection, not Teams: refused`);
  if (conn.status === 'Connected' && conn.user.toLowerCase() === upn && !force) {
    result({ ok: true, status: conn.status, authenticatedUser: conn.user, note: 'already authorized as this account' });
    process.exit(0);
  }
  if (conn.status === 'Connected' && !force) throw new Error(`${name} is Connected as ${conn.user || 'an unknown account'}, not ${upn}: pass --force to re-authorize it as ${upn}`);

  const acct = az(['account', 'show', '-o', 'json']);
  const tenantId = acct.tenantId;
  const opOid = az(['ad', 'sp', 'show', '--id', acct.user.name, '--query', '{id:id}', '-o', 'json']).id;
  if (!tenantId || !opOid) throw new Error('could not read the operator identity (az account show / az ad sp show)');

  const links = armPost(`https://management.azure.com${conn.id}/listConsentLinks?api-version=${API}`, {
    parameters: [{ parameterName: 'token', redirectUrl: REDIRECT, objectId: opOid, tenantId }],
  });
  const link = links?.value?.[0]?.link;
  if (!link) throw new Error('ARM returned no consent link');

  const pw = passwordFor(upn);
  if (!pw) throw new Error(`no password in the Keychain for ${upn}`);
  const browser = await playwright().chromium.launch({ headless: !headed });
  let code = null;
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-US' });
    // The redirect only carries the code: read it off the navigation request.
    // It arrives as a 302 hop from <region>.consent.azure-apim.net, and
    // Playwright does not route redirect hops (seen live 2026-11-05: a
    // context.route() on it never fired), so the request event is the hook.
    // The page itself never loads (the host does not resolve): that is fine.
    const grab = (url) => {
      if (code !== null || !url.startsWith(REDIRECT)) return;
      const u = new URL(url);
      const err = u.searchParams.get('error');
      code = u.searchParams.get('code') || { error: `${err || 'no code'}: ${u.searchParams.get('error_description') || ''}`.slice(0, 300) };
    };
    context.on('request', (r) => { if (r.isNavigationRequest()) grab(r.url()); });
    const page = await context.newPage();
    await page.goto(link, { waitUntil: 'domcontentloaded', timeout: 60000 });
    // Entra's consent prompt ("Permissions requested") is not a sign-in step
    // the toolkit answers: accept it for this account only (never "on behalf
    // of your organization": that box is left unticked).
    const consentWatch = (async () => {
      while (code === null) {
        const t = await pageText(page).catch(() => '');
        if (/Permissions requested/i.test(t)) {
          const b = page.locator('#idSIButton9, input[type=submit][value="Accept"], button:has-text("Accept")').first();
          if (await b.isVisible().catch(() => false)) { log(`${upn}: accepted the connector's permission prompt for this account`); await b.click().catch(() => {}); }
        }
        await sleep(1000);
      }
    })();
    try {
      await drive(page, upn, { password: pw.value, until: async () => code !== null, timeoutMs: 180000 });
    } catch (e) {
      if (code === null) { const f = await shot(page, `authorize-fail-${name}`); e.message += ` [screenshot: ${f}]`; throw e; }
    }
    for (let i = 0; i < 30 && code === null; i++) await sleep(1000);
    if (code === null) code = { error: 'no redirect with a consent code' };
    await consentWatch.catch(() => {});
  } finally {
    await browser.close().catch(() => {});
  }
  if (typeof code !== 'string') throw new Error(`consent failed: ${code.error}`);

  armPost(`https://management.azure.com${conn.id}/confirmConsentCode?api-version=${API}`, { objectId: opOid, tenantId, code });
  code = null;

  // Read back: Connected AND as exactly this account, or it did not happen.
  for (let i = 0; i < 10; i++) { conn = readConnection(rg, name); if (conn.status === 'Connected') break; await sleep(3000); }
  const ok = conn.status === 'Connected' && conn.user.toLowerCase() === upn;
  result({ ok, status: conn.status, authenticatedUser: conn.user });
  process.exit(ok ? 0 : 1);
} catch (e) {
  result({ ok: false, error: String(e.message || e).slice(0, 600) });
  process.exit(1);
}
