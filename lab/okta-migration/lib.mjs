// =============================================================================
// lab/okta-migration/lib.mjs - shared parts of the Okta -> Entra app migration
// -----------------------------------------------------------------------------
// Two kinds of code live here:
//   * PURE functions (no network, no Keychain): the Okta EL -> Entra
//     dynamic-group rule translator, the app classifier, the tracker
//     builder, the CSV/markdown/HTML writers, the System Log filter builder.
//     tests/lib.test.mjs covers them; CI runs it.
//   * Thin clients: Okta (SSWS token from the macOS Keychain item
//     contoso-lab-okta-token, read into this process only) and Microsoft
//     Graph (through the lab operator, lab/scripts/operator/op, via the
//     sign-in toolkit's graph()).
//
// SECRETS: the Okta token is never printed, logged, written or put in argv.
// The inventory never calls GET /api/v1/idps: that endpoint returns the IdP's
// client secret, and Okta logs every such read
// (system.idp.lifecycle.read_client_secret, seen live 2026-11-07).
// =============================================================================
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '../..');
export const OKTA_ROOT = path.join(REPO, 'lab/terraform/okta');

// ---- Okta org and token -------------------------------------------------------

// The org host comes from the Okta root's gitignored terraform.tfvars (the
// same place trust-claims.mjs reads), or OKTA_ORG (e.g.
// integrator-1234567.okta.com). Nothing org-specific is committed.
export function oktaOrg(env = process.env, root = OKTA_ROOT) {
  if (env.OKTA_ORG) return env.OKTA_ORG;
  for (const f of [path.join(root, 'terraform.tfvars'), path.join(process.env.HOME || '', 'contoso-health-identity-lab/lab/terraform/okta/terraform.tfvars')]) {
    if (!fs.existsSync(f)) continue;
    const t = {};
    for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
      const m = line.match(/^\s*(okta_org_name|okta_base_url)\s*=\s*"([^"]*)"/);
      if (m) t[m[1]] = m[2];
    }
    if (t.okta_org_name) return `${t.okta_org_name}.${t.okta_base_url || 'okta.com'}`;
  }
  throw new Error('Okta org unknown: set OKTA_ORG or fill lab/terraform/okta/terraform.tfvars');
}

function oktaToken() {
  if (process.env.OKTA_API_TOKEN) return process.env.OKTA_API_TOKEN;
  const t = execFileSync('security', ['find-generic-password', '-s', 'contoso-lab-okta-token', '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  if (!t) throw new Error('no Okta API token (OKTA_API_TOKEN or Keychain contoso-lab-okta-token)');
  return t;
}

// Okta REST client. Follows `Link: <...>; rel="next"` pagination for lists.
export function okta({ org = oktaOrg(), token = oktaToken(), fetchFn = fetch } = {}) {
  const base = `https://${org}`;
  const H = { Authorization: `SSWS ${token}`, Accept: 'application/json', 'Content-Type': 'application/json' };
  async function req(method, p, body, attempt = 0) {
    const r = await fetchFn(p.startsWith('https://') ? p : base + p, { method, headers: H, body: body === undefined ? undefined : JSON.stringify(body) });
    // Rate limit: wait until Okta's reset time (x-rate-limit-reset, epoch
    // seconds), at most 60 s, then try again - three times.
    if (r.status === 429 && attempt < 3) {
      const reset = Number(r.headers.get('x-rate-limit-reset')) * 1000;
      await new Promise((res) => setTimeout(res, Math.min(60000, Math.max(1000, (reset || Date.now() + 5000) - Date.now() + 500))));
      return req(method, p, body, attempt + 1);
    }
    if (r.status === 204) return { data: null, next: null };
    const text = await r.text();
    if (r.status >= 300) throw new Error(`Okta ${method} ${p.replace(base, '')}: HTTP ${r.status} ${text.slice(0, 300)}`);
    const link = r.headers.get('link') || '';
    const next = (link.match(/<([^>]+)>;\s*rel="next"/) || [])[1] || null;
    return { data: text ? JSON.parse(text) : null, next };
  }
  return {
    org,
    get: async (p) => (await req('GET', p)).data,
    // The System Log in ASCENDING order is a polling stream: it ALWAYS
    // returns a next link, so paging stops at the first empty page.
    list: async (p, maxPages = 50) => {
      const out = []; let u = p;
      for (let i = 0; u && i < maxPages; i++) { const { data, next } = await req('GET', u); if (!data || !data.length) break; out.push(...data); u = next; }
      return out;
    },
    post: async (p, b) => (await req('POST', p, b)).data,
    put: async (p, b) => (await req('PUT', p, b)).data,
  };
}

// ---- Graph, every page ---------------------------------------------------------
// Graph lists are paged (@odata.nextLink); a first page alone would report a
// partial count as the full window. graphFn = the toolkit's graph(method, url).
export function graphAll(graphFn, url, maxPages = 50) {
  const out = []; let u = url;
  for (let i = 0; u; i++) {
    if (i >= maxPages) throw new Error(`more than ${maxPages} pages at ${url.split('?')[0]}: narrow the window`);
    const r = graphFn('GET', u); out.push(...(r.value || [])); u = r['@odata.nextLink'] || null;
  }
  return out;
}

// ---- Okta EL -> Entra dynamic membership rule ---------------------------------

// Translates the Okta group-rule expressions this estate uses (and the common
// shapes around them) into Entra's dynamic membership rule syntax. Anything
// it cannot translate exactly returns { rule: null, reason } - a wrong
// translation would silently grant or drop access, so "unknown" is the
// honest answer. Okta EL reference: String.substringAfter, ==, &&, ||,
// isMemberOfAnyGroup; Entra: -eq, -endsWith, -and, -or (no group-membership
// operator outside the preview memberOf).
const OKTA_TO_ENTRA_ATTR = {
  'user.login': 'user.userPrincipalName',
  'user.email': 'user.mail',
  'user.department': 'user.department',
  'user.title': 'user.jobTitle',
  'user.division': 'user.companyName',
  'user.employeeNumber': 'user.employeeId',
  'user.city': 'user.city',
  'user.countryCode': 'user.country',
  'user.userType': 'user.employeeType',
};

function translateTerm(term) {
  const t = term.trim().replace(/^\((.*)\)$/, '$1').trim();
  let m = t.match(/^String\.substringAfter\(\s*(user\.\w+)\s*,\s*"@"\s*\)\s*==\s*"([^"]+)"$/);
  if (m) {
    const a = OKTA_TO_ENTRA_ATTR[m[1]];
    return a ? { rule: `(${a} -endsWith "@${m[2]}")` } : { rule: null, reason: `no Entra attribute for ${m[1]}` };
  }
  m = t.match(/^(user\.\w+)\s*==\s*"([^"]*)"$/);
  if (m) {
    const a = OKTA_TO_ENTRA_ATTR[m[1]];
    return a ? { rule: `(${a} -eq "${m[2]}")` } : { rule: null, reason: `no Entra attribute for ${m[1]}` };
  }
  m = t.match(/^(user\.\w+)\s*!=\s*"([^"]*)"$/);
  if (m) {
    const a = OKTA_TO_ENTRA_ATTR[m[1]];
    return a ? { rule: `(${a} -ne "${m[2]}")` } : { rule: null, reason: `no Entra attribute for ${m[1]}` };
  }
  if (/isMemberOf/i.test(t)) return { rule: null, reason: 'group-membership condition: Entra dynamic rules cannot reference groups (memberOf is preview) - model it as an access package or nested assignment' };
  return { rule: null, reason: `expression not recognised: ${t.slice(0, 80)}` };
}

export function oktaElToEntra(expr) {
  if (!expr || typeof expr !== 'string') return { rule: null, reason: 'empty expression' };
  if (/\|\|/.test(expr) && /&&/.test(expr)) return { rule: null, reason: 'mixed && and || without a parser: translate by hand' };
  const op = /&&/.test(expr) ? '&&' : (/\|\|/.test(expr) ? '||' : null);
  const parts = op ? expr.split(op) : [expr];
  const out = [];
  for (const p of parts) { const r = translateTerm(p); if (!r.rule) return r; out.push(r.rule); }
  return { rule: out.join(op === '&&' ? ' -and ' : ' -or ') };
}

// ---- App classification -------------------------------------------------------

// Okta's own apps (admin console, dashboard, Workflows, ...) are part of the
// Okta product, not the clinic's estate: they retire with the tenant.
const OKTA_SYSTEM_APP_NAMES = new Set(['saasure', 'okta_enduser', 'okta_browser_plugin', 'okta_oin_submission_tester_app', 'okta_flow_sso', 'flow', 'okta_iga_reviewer']);
export const isClinicApp = (app) => !OKTA_SYSTEM_APP_NAMES.has(app.name);

export function protocolOf(app) {
  switch (app.signOnMode) {
    case 'OPENID_CONNECT': return 'OIDC';
    case 'SAML_2_0': return 'SAML 2.0';
    case 'SAML_1_1': return 'SAML 1.1';
    case 'BOOKMARK': return 'Bookmark';
    case 'BROWSER_PLUGIN': case 'SECURE_PASSWORD_STORE': case 'AUTO_LOGIN': return 'SWA (password vaulting)';
    case 'WS_FEDERATION': return 'WS-Fed';
    default: return app.signOnMode || 'unknown';
  }
}

// The Entra pattern per Okta protocol (Microsoft Learn "Migrate applications
// from Okta to Microsoft Entra ID"): what the target looks like.
export function entraTargetFor(protocol) {
  if (protocol === 'OIDC') return 'App registration (same client type and redirect URIs) + enterprise app';
  if (protocol.startsWith('SAML')) return 'Non-gallery SAML enterprise app (same entity id + ACS) + claims mapping';
  if (protocol === 'Bookmark') return 'Linked-sign-on enterprise app (My Apps tile) until the app gets real SSO';
  if (protocol.startsWith('SWA')) return 'Password-based SSO enterprise app, or modernise to SAML/OIDC';
  return 'decide with the app owner';
}

// ---- The tracker ----------------------------------------------------------------

export const TRACKER_COLUMNS = ['app', 'owner', 'protocol', 'users', 'wave', 'status', 'test_result'];
export const TRACKER_EXTRA = ['okta_app_id', 'okta_groups', 'okta_policy', 'entra_app', 'entra_assignment', 'entra_ca', 'okta_sso_last_7d', 'entra_signins_last_7d', 'next_step'];

// Status, from what the two APIs say (never from a hand-edited cell):
//   inventoried  - in Okta, nothing in Entra yet
//   pre-staged   - the Entra enterprise app exists and is assigned
//   piloting     - pre-staged and the app group has members
//   cut over     - the app trusts Entra; the Okta app is hidden (still active)
//   retired      - the Okta app is INACTIVE
export function statusOf({ okta, entra, appTrusts }) {
  if (okta && okta.status === 'INACTIVE') return 'retired';
  if (appTrusts === 'entra' && okta && okta.hidden) return 'cut over';
  if (entra && entra.servicePrincipalId) {
    if (entra.assignedPrincipals > 0 && entra.groupMembers > 0) return 'piloting';
    if (entra.assignedPrincipals > 0) return 'pre-staged';
  }
  return 'inventoried';
}

const NEXT = {
  inventoried: 'pre-stage the Entra app (PR), owner sign-off',
  'pre-staged': 'add pilot users (cutover.mjs prestage), test through Entra',
  piloting: 'test through Entra, then cut over (cutover.mjs cutover)',
  'cut over': 'watch the Okta System Log for 7 days of zero sign-ins, then retire',
  retired: 'remove the Okta app code (retire PR)',
};

export function buildRow({ app, plan = {}, okta, entra, appTrusts, test, oktaSso7d = null, entraSignins7d = null }) {
  const status = statusOf({ okta, entra, appTrusts });
  return {
    app: app.label,
    owner: plan.owner || 'UNASSIGNED',
    protocol: protocolOf(app),
    users: okta ? okta.userCount : 0,
    wave: plan.wave ?? '',
    status,
    test_result: test ? `${test.result} ${test.idp} ${test.at}` : (status === 'inventoried' ? 'not tested' : 'not tested yet'),
    okta_app_id: app.id,
    okta_groups: okta ? okta.groups.join('; ') : '',
    okta_policy: okta ? okta.policy : '',
    entra_app: entra ? entra.displayName : '',
    entra_assignment: entra ? entra.assignedGroups.join('; ') : '',
    entra_ca: entra ? entra.ca.join('; ') : '',
    okta_sso_last_7d: oktaSso7d ?? '',
    entra_signins_last_7d: entraSignins7d ?? '',
    next_step: plan.blocker ? `${NEXT[status]} - blocker: ${plan.blocker}` : NEXT[status],
  };
}

const csvCell = (v) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
export function toCsv(rows, cols = [...TRACKER_COLUMNS, ...TRACKER_EXTRA]) {
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n') + '\n';
}

const mdCell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
export function toMarkdown(rows, { generatedAt, sources }) {
  const head = TRACKER_COLUMNS;
  const lines = [
    '# Okta -> Entra app migration tracker',
    '',
    `Generated ${generatedAt} by \`node lab/okta-migration/inventory.mjs\` from the Okta API and Microsoft Graph. Do not edit by hand: re-run the script.`,
    '',
    `| ${head.join(' | ')} |`,
    `|${head.map(() => '---').join('|')}|`,
    ...rows.map((r) => `| ${head.map((c) => mdCell(r[c])).join(' | ')} |`),
    '',
    '## Detail per app',
    '',
    ...rows.flatMap((r) => [
      `### ${r.app}`,
      '',
      `- Okta: app \`${r.okta_app_id}\`, groups ${r.okta_groups || 'none'}, authentication policy *${r.okta_policy || 'default'}*, SSO events in the last 7 days: ${r.okta_sso_last_7d}`,
      `- Entra: ${r.entra_app ? `enterprise app *${r.entra_app}*, assigned to ${r.entra_assignment || 'nobody'}, Conditional Access ${r.entra_ca || 'baseline only'}, sign-ins in the last 7 days: ${r.entra_signins_last_7d}` : 'not built yet'}`,
      `- Next: ${r.next_step}`,
      '',
    ]),
    '## Sources',
    '',
    ...sources.map((s) => `- ${s}`),
    '',
  ];
  return lines.join('\n');
}

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
export function toHtml(rows, { generatedAt, extra = {} }) {
  const order = ['inventoried', 'pre-staged', 'piloting', 'cut over', 'retired'];
  const counts = Object.fromEntries(order.map((s) => [s, rows.filter((r) => r.status === s).length]));
  const tiles = order.map((s) => `<div class="tile"><b>${counts[s]}</b><span>${esc(s)}</span></div>`).join('');
  const body = rows.map((r) => `<tr><td>${esc(r.app)}</td><td>${esc(r.owner)}</td><td>${esc(r.protocol)}</td><td class="n">${esc(r.users)}</td><td class="n">${esc(r.wave)}</td><td><span class="s s-${order.indexOf(r.status)}">${esc(r.status)}</span></td><td>${esc(r.test_result)}</td></tr>`).join('\n');
  const extraHtml = Object.entries(extra).map(([k, v]) => `<h2>${esc(k)}</h2><pre>${esc(v)}</pre>`).join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Okta to Entra tracker</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#5b6470;--line:#d8dde3;--tile:#f4f6f8;--s0:#8a94a3;--s1:#b7791f;--s2:#2b6cb0;--s3:#2f855a;--s4:#4a5568}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0f1216;--fg:#e6e9ed;--mut:#9aa4b1;--line:#2a3038;--tile:#171b21}}
:root[data-theme="dark"]{--bg:#0f1216;--fg:#e6e9ed;--mut:#9aa4b1;--line:#2a3038;--tile:#171b21}
body{background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:24px 16px;max-width:1100px;margin-inline:auto}
h1{font-size:22px;margin:0 0 4px}p.m{color:var(--mut);margin:0 0 18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:18px}
.tile{background:var(--tile);border-radius:8px;padding:12px}.tile b{display:block;font-size:26px}.tile span{color:var(--mut)}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:640px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}td.n{text-align:right}
.s{display:inline-block;padding:2px 8px;border-radius:99px;color:#fff;font-size:13px}.s-0{background:var(--s0)}.s-1{background:var(--s1)}.s-2{background:var(--s2)}.s-3{background:var(--s3)}.s-4{background:var(--s4)}
pre{background:var(--tile);padding:12px;border-radius:8px;overflow-x:auto;font-size:13px}
</style></head><body>
<h1>Okta to Entra app migration</h1>
<p class="m">Generated ${esc(generatedAt)} from the Okta API and Microsoft Graph by lab/okta-migration/inventory.mjs.</p>
<div class="tiles">${tiles}</div>
<div class="wrap"><table><thead><tr><th>App</th><th>Owner</th><th>Protocol</th><th>Users</th><th>Wave</th><th>Status</th><th>Test result</th></tr></thead><tbody>
${body}
</tbody></table></div>
${extraHtml}
</body></html>
`;
}

// ---- System Log ---------------------------------------------------------------

// The filter for "who signed in to this app" in the Okta System Log. For an
// OIDC app the per-app events are app.oauth2.authorize.code (the user was
// sent to the app) and user.authentication.sso; target.id is the app id.
export function systemLogFilter(appId, eventTypes = ['user.authentication.sso', 'app.oauth2.authorize.code']) {
  if (!/^0oa[A-Za-z0-9]{17}$/.test(appId)) throw new Error(`not an Okta app id: ${appId}`);
  const ev = eventTypes.map((e) => `eventType eq "${e}"`).join(' or ');
  return `(${ev}) and target.id eq "${appId}"`;
}

// The KQL the Entra side shows for the same question (SigninLogs in the
// lab's Log Analytics workspace).
export function entraSigninKql(appDisplayName) {
  return `SigninLogs\n| where TimeGenerated > ago(7d)\n| where AppDisplayName == "${appDisplayName.replace(/"/g, '')}"\n| project TimeGenerated, UserPrincipalName, ResultType, ConditionalAccessStatus, AuthenticationRequirement\n| order by TimeGenerated desc`;
}

export const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
