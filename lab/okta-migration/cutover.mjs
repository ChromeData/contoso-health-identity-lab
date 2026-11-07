#!/usr/bin/env node
// =============================================================================
// lab/okta-migration/cutover.mjs - move one app from Okta to Entra, and back
// -----------------------------------------------------------------------------
//   node lab/okta-migration/cutover.mjs status
//   node lab/okta-migration/cutover.mjs prestage            # runbook step 1-2
//   node lab/okta-migration/cutover.mjs test [--idp okta|entra] [--as <upn>]
//   node lab/okta-migration/cutover.mjs cutover             # step 3
//   node lab/okta-migration/cutover.mjs rollback [--emergency]  # step 3, reversed
//   (--app "<Okta label>", default "Clinic Lab Results")
//
// WHAT EACH STEP DOES (runbook Phase 2, lab/docs/okta-migration-runbook.md):
//   prestage  Reads the Okta app (client id) and the Entra app (by display
//             name, Graph as the operator) and writes the app's IdP config
//             (~/.contoso-operator/clinic-results/idp.json; "active" stays
//             okta). In Entra: admin consent on openid/profile/email
//             (AllPrincipals, so no pilot sees a prompt) and the waves.json
//             pilot users added to the app group. Every write is read back.
//   test      Starts the app, signs the pilot in headless (the staff sign-in
//             toolkit: password + authenticator code from the Keychain, so
//             Conditional Access runs for real) and checks the app's own
//             verdict: the ID token it verified came from the expected
//             issuer. --idp entra while production still trusts Okta = a
//             STAGING run (a temporary config, same app, same redirect):
//             the runbook's "test with a pilot before the cut-over".
//             Writes results/<time>-<app>-<idp>.json (no tokens in it).
//   cutover   Needs waves.json "cutover": true for the app (the reviewed
//             change). Applies the Okta root for this app only (the Okta app
//             becomes HIDDEN, still active and assigned), switches the app's
//             config to Entra (the Okta block stays in the file: it is the
//             rollback), then runs `test` as the pilot. Timed.
//   rollback  Needs waves.json "cutover": false. The same in reverse: config
//             back to Okta, Okta app visible again, test. Timed.
//
// SECRETS: none are handled here except through the toolkit (Keychain) and
// the Okta token (Keychain, into this process and the terraform child's
// environment only - never argv, never printed).
// =============================================================================
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { HERE, REPO, OKTA_ROOT, okta, nowIso, graphAll } from './lib.mjs';
import { CONF, CONF_DIR, readConf, serve } from './clinic-results/app.mjs';
import { graph } from '../scripts/demo/signin/lib.mjs';

const WAVES = path.join(HERE, 'waves.json');

// The test starts its own copy of the app on 8471. Check the port BEFORE any
// live change, so a running app.mjs can never leave a cut-over half done.
function portFree(port = 8471) {
  return new Promise((resolve) => {
    const s = net.createServer().once('error', () => resolve(false)).once('listening', () => s.close(() => resolve(true)));
    s.listen(port, '127.0.0.1');
  });
}
const RESULTS = path.join(HERE, 'results');
const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
const SCOPES = 'openid profile email';

const args = process.argv.slice(2);
const cmd = args[0];
const opt = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const appLabel = opt('--app', 'Clinic Lab Results');
const log = (...a) => console.error('[cutover]', ...a);

const waves = () => JSON.parse(fs.readFileSync(WAVES, 'utf8')).apps;
const plan = () => { const p = waves()[appLabel]; if (!p) throw new Error(`"${appLabel}" is not in waves.json`); return p; };

async function oktaApp(o) {
  const apps = await o.list(`/api/v1/apps?q=${encodeURIComponent(appLabel)}&limit=20`);
  const a = apps.find((x) => x.label === appLabel);
  if (!a) throw new Error(`Okta has no app labelled "${appLabel}"`);
  return a;
}

function entraApp(displayName) {
  const r = graph('GET', `applications?$filter=displayName eq '${displayName.replace(/'/g, "''")}'&$select=id,appId,displayName,publicClient`);
  if (!r.value.length) return null;
  if (r.value.length > 1) throw new Error(`more than one Entra app is named "${displayName}"`);
  const app = r.value[0];
  const sp = graph('GET', `servicePrincipals?$filter=appId eq '${app.appId}'&$select=id,appId,displayName,appRoleAssignmentRequired`).value[0] || null;
  const tenant = graph('GET', 'organization?$select=id').value[0].id;
  return { app, sp, tenant };
}

function idpBlocks({ org, oktaClientId, entra }) {
  const blocks = {
    okta: {
      issuer: `https://${org}`,
      client_id: oktaClientId,
      authorization_endpoint: `https://${org}/oauth2/v1/authorize`,
      token_endpoint: `https://${org}/oauth2/v1/token`,
      jwks_uri: `https://${org}/oauth2/v1/keys`,
    },
  };
  if (entra) {
    const a = `https://login.microsoftonline.com/${entra.tenant}`;
    blocks.entra = {
      issuer: `${a}/v2.0`,
      client_id: entra.app.appId,
      authorization_endpoint: `${a}/oauth2/v2.0/authorize`,
      token_endpoint: `${a}/oauth2/v2.0/token`,
      jwks_uri: `${a}/discovery/v2.0/keys`,
    };
  }
  return blocks;
}

function writeConf(c) {
  fs.mkdirSync(CONF_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${CONF}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, CONF);
}

function ensureConsent(spId) {
  const graphSp = graph('GET', `servicePrincipals?$filter=appId eq '${GRAPH_APP_ID}'&$select=id`).value[0];
  const grants = graph('GET', `servicePrincipals/${spId}/oauth2PermissionGrants`).value.filter((g) => g.consentType === 'AllPrincipals' && g.resourceId === graphSp.id);
  if (grants.length && SCOPES.split(' ').every((s) => grants[0].scope.split(' ').includes(s))) return `consent already granted (${grants[0].scope})`;
  if (grants.length) graph('PATCH', `oauth2PermissionGrants/${grants[0].id}`, { scope: SCOPES });
  else graph('POST', 'oauth2PermissionGrants', { clientId: spId, consentType: 'AllPrincipals', resourceId: graphSp.id, scope: SCOPES });
  const back = graph('GET', `servicePrincipals/${spId}/oauth2PermissionGrants`).value.find((g) => g.consentType === 'AllPrincipals' && g.resourceId === graphSp.id);
  if (!back || !SCOPES.split(' ').every((s) => back.scope.split(' ').includes(s))) throw new Error('consent read-back differs');
  return `consent granted and read back (${back.scope})`;
}

function ensurePilots(spId, pilots) {
  const assigned = graph('GET', `servicePrincipals/${spId}/appRoleAssignedTo?$select=principalId,principalType,principalDisplayName`).value.filter((a) => a.principalType === 'Group');
  if (assigned.length !== 1) throw new Error(`expected exactly one group assigned to the Entra app, found ${assigned.length}`);
  const gid = assigned[0].principalId;
  const out = [];
  for (const upn of pilots) {
    const u = graph('GET', `users/${encodeURIComponent(upn)}?$select=id,userPrincipalName`);
    const members = graphAll(graph, `groups/${gid}/members?$select=id&$top=999`).map((m) => m.id);
    if (members.includes(u.id)) { out.push(`${upn} already in ${assigned[0].principalDisplayName}`); continue; }
    graph('POST', `groups/${gid}/members/$ref`, { '@odata.id': `https://graph.microsoft.com/v1.0/directoryObjects/${u.id}` });
    const again = graphAll(graph, `groups/${gid}/members?$select=id&$top=999`).map((m) => m.id);
    if (!again.includes(u.id)) throw new Error(`${upn} not in the group after the add`);
    out.push(`${upn} added to ${assigned[0].principalDisplayName} (read back)`);
  }
  return out;
}

async function prestage() {
  const o = okta();
  const a = await oktaApp(o);
  const p = plan();
  const e = entraApp(p.entra_app);
  const prev = fs.existsSync(CONF) ? JSON.parse(fs.readFileSync(CONF, 'utf8')) : null;
  const blocks = idpBlocks({ org: o.org, oktaClientId: a.credentials.oauthClient.client_id, entra: e && e.sp ? e : null });
  const conf = { app: appLabel, active: prev?.active || 'okta', ...blocks, history: prev?.history || [] };
  if (conf.active === 'entra' && !conf.entra) throw new Error('config says entra is active but the Entra app is gone: run rollback');
  writeConf(conf);
  log(`config written (${CONF}): active = ${conf.active}; okta client ${blocks.okta.client_id}${blocks.entra ? `; entra client ${blocks.entra.client_id}` : ''}`);
  if (!e || !e.sp) { log(`Entra app "${p.entra_app}" does not exist yet: the Entra pre-stage PR has not been applied. Okta side only.`); return; }
  if (!e.sp.appRoleAssignmentRequired) throw new Error('the Entra enterprise app does not require assignment');
  log(ensureConsent(e.sp.id));
  for (const l of ensurePilots(e.sp.id, p.pilot)) log(l);
}

async function test({ idp, as }) {
  if (!(await portFree())) throw new Error('port 8471 is in use (app.mjs running?): stop it first');
  const conf = readConf();
  const want = idp || conf.active;
  if (!conf[want]) throw new Error(`no ${want} block in the config: run prestage`);
  const upn = as || plan().pilot[0];
  if (!upn) throw new Error('no pilot user in waves.json and no --as');
  // A staging run (--idp differs from production) uses a temporary config
  // with the other IdP active: the same app code, the same redirect URI.
  let confFile = CONF;
  if (want !== conf.active) {
    confFile = path.join(CONF_DIR, `staging-${want}.json`);
    fs.writeFileSync(confFile, JSON.stringify({ ...conf, active: want }, null, 2), { mode: 0o600 });
  }
  const signinsFile = path.join(CONF_DIR, 'signins.jsonl');
  const before = fs.existsSync(signinsFile) ? fs.readFileSync(signinsFile, 'utf8').split('\n').filter(Boolean).length : 0;
  const started = Date.now();
  let verdict, server = null;
  try {
    server = await serve({ conf: confFile });
    const { signIn } = await import('../scripts/demo/signin/signin.mjs');
    const s = await signIn(upn, 'http://localhost:8471/login', {
      headless: true, fresh: true,
      until: async (pg) => /^http:\/\/localhost:8471\/$/.test(pg.url()) && /Signed in as/.test(await pg.content()),
      landing: { url: /^http:\/\/localhost:8471\//, text: /Signed in as/, denied: /Sign-in refused by the IdP|HTTP 4\d\d|not the trusted|does not verify|unknown state/ },
    });
    const text = await s.page.innerText('body').catch(() => '');
    await s.close();
    const lines = fs.readFileSync(signinsFile, 'utf8').split('\n').filter(Boolean);
    const rec = lines.length > before ? JSON.parse(lines[lines.length - 1]) : null;
    const ok = rec && rec.idp === want && rec.user.toLowerCase() === upn.toLowerCase() && rec.issuer === conf[want].issuer;
    verdict = { result: ok ? 'PASS' : 'FAIL', idp: want, staging: want !== conf.active, app: appLabel, user: upn, issuer: rec?.issuer || null, amr: rec?.amr || null, at: nowIso(), seconds: Math.round((Date.now() - started) / 1000), banner: (text.match(/Signed in as[^\n]*/) || [''])[0] };
  } catch (e) {
    verdict = { result: 'FAIL', idp: want, staging: want !== conf.active, app: appLabel, user: upn, error: String(e.message).slice(0, 400), at: nowIso(), seconds: Math.round((Date.now() - started) / 1000) };
  } finally {
    if (server) server.close();
    if (confFile !== CONF) fs.rmSync(confFile, { force: true });
  }
  fs.mkdirSync(RESULTS, { recursive: true });
  const f = path.join(RESULTS, `${verdict.at.replace(/[:]/g, '')}-${appLabel.replace(/\W+/g, '-').toLowerCase()}-${want}.json`);
  fs.writeFileSync(f, JSON.stringify(verdict, null, 2) + '\n');
  console.log(JSON.stringify(verdict, null, 2));
  log(`result written: ${path.relative(REPO, f)}`);
  return verdict;
}

// Apply the Okta root for this app only. Targeted on purpose: the IdP in
// the same root holds a client secret that is supplied only at a full apply
// (TF_VAR_entra_client_secret), and the cut-over must never touch the IdP.
function applyOkta(override) {
  const env = { ...process.env, OKTA_API_TOKEN: process.env.OKTA_API_TOKEN || execFileSync('security', ['find-generic-password', '-s', 'contoso-lab-okta-token', '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() };
  const out = execFileSync('terraform', ['apply', '-input=false', '-no-color', '-auto-approve', '-target=okta_app_oauth.clinic_results', ...(override ? [`-var=waves_override=${override}`] : [])], { cwd: OKTA_ROOT, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const line = (out.match(/Apply complete![^\n]*/) || ['(no summary)'])[0];
  if (!/0 added, [01] changed, 0 destroyed/.test(line)) throw new Error(`unexpected Okta apply result: ${line}`);
  return line;
}

async function switchTo(target) {
  const t0 = Date.now();
  const p = plan();
  const wantCutover = target === 'entra';
  // --emergency (rollback only): restore Okta now, before the waves.json PR.
  // The Okta apply then carries waves_override; make the PR right after.
  const emergency = target === 'okta' && args.includes('--emergency');
  if (p.cutover !== wantCutover && !emergency) throw new Error(`waves.json says cutover = ${p.cutover} for "${appLabel}": set it to ${wantCutover} first (the reviewed change), then run ${cmd} again${target === 'okta' ? ' - or, in an incident, rollback --emergency' : ''}`);
  const conf = readConf();
  if (!conf.entra) throw new Error('no Entra block in the config: run prestage after the Entra PR is applied');
  if (!(await portFree())) throw new Error('port 8471 is in use (app.mjs running?): stop it first - nothing was changed');
  if (conf.active === target) log(`the app already trusts ${target}`);
  // Order matters. Cut-over: app to Entra FIRST, then hide the Okta tile -
  // nobody is left with a tile that leads to an app that no longer trusts
  // Okta. Rollback: the same order works, because the app trusts Okta again
  // before the tile reappears.
  conf.history.push({ at: nowIso(), from: conf.active, to: target, by: cmd });
  conf.active = target;
  writeConf(conf);
  log(`app config: active = ${target} (Okta block kept for rollback)`);
  log(`okta root: ${applyOkta(emergency ? JSON.stringify({ [appLabel]: { cutover: false, retired: false } }) : null)}`);
  if (emergency) log('EMERGENCY rollback applied with waves_override: now make the PR that sets waves.json cutover = false');
  const o = okta();
  const a = await oktaApp(o);
  log(`okta app now: status ${a.status}, hidden on the dashboard: ${a.visibility.hide.web}`);
  const v = await test({});
  const seconds = Math.round((Date.now() - t0) / 1000);
  log(`${cmd} took ${seconds} s end to end (config + Okta apply + test sign-in)`);
  return { ...v, step: cmd, total_seconds: seconds };
}

async function status() {
  const p = plan();
  const conf = fs.existsSync(CONF) ? readConf() : null;
  const o = okta();
  const a = await oktaApp(o);
  const e = entraApp(p.entra_app);
  console.log(JSON.stringify({
    app: appLabel, wave: p.wave, waves_cutover: p.cutover,
    app_trusts: conf?.active || '(no config yet: prestage)',
    okta: { id: a.id, status: a.status, hidden: a.visibility.hide.web, policy: a._links?.accessPolicy?.href?.split('/').pop() },
    entra: e?.sp ? { appId: e.app.appId, servicePrincipal: e.sp.id, assignmentRequired: e.sp.appRoleAssignmentRequired } : '(not created yet)',
  }, null, 2));
}

const main = { status, prestage, test: () => test({ idp: opt('--idp'), as: opt('--as') }), cutover: () => switchTo('entra'), rollback: () => switchTo('okta') }[cmd];
if (!main) { console.error('usage: cutover.mjs status|prestage|test [--idp okta|entra] [--as upn]|cutover|rollback [--emergency] [--app "<label>"]'); process.exit(2); }
main().then((r) => { if (r && r.result === 'FAIL') process.exit(1); }).catch((e) => { console.error(`[cutover] ERROR: ${e.message}`); process.exit(1); });
