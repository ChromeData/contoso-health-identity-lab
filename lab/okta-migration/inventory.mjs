#!/usr/bin/env node
// =============================================================================
// lab/okta-migration/inventory.mjs - the migration tracker, from both APIs
// -----------------------------------------------------------------------------
//   node lab/okta-migration/inventory.mjs [--out lab/okta-migration] [--no-entra]
//
// Runbook Phase 0 ("inventory and decide") as a script. It reads:
//   OKTA (API token, Keychain): every app that is not part of Okta itself -
//     sign-on mode, status, dashboard visibility, assigned groups and users,
//     its authentication policy and that policy's rules, SAML attribute
//     statements, the group rules that fill its groups (with the Entra
//     dynamic-rule translation, or why there is none), and its sign-in
//     events in the System Log for the last 7 days; plus the org's
//     phishing-resistant posture (admins' factors, which rules demand a
//     phishing-resistant factor).
//   ENTRA (Graph, as the lab operator): for each app's planned Entra twin
//     (waves.json entra_app) - the enterprise app, assignment required, the
//     groups assigned and their member counts, the Conditional Access
//     policies that name its client id, and its sign-ins for 7 days.
//   THE APP's config (~/.contoso-operator/clinic-results/idp.json): which IdP
//     it trusts now. And results/*.json: the latest test sign-in per app.
// and writes, in --out:
//   tracker.csv   app, owner, protocol, users, wave, status, test_result (+ detail)
//   tracker.md    the same table, per-app detail, group-rule translations,
//                 the phishing-resistant posture
//   status.html   the small status view (counts per status + the table)
//   inventory.json the raw inventory (no secrets: no IdP or app credentials
//                 are ever requested)
// Owners and waves come from waves.json (decisions); everything else from
// the APIs (facts). Re-run after every step; never edit the outputs by hand.
// =============================================================================
import fs from 'node:fs';
import path from 'node:path';
import {
  HERE, okta, isClinicApp, protocolOf, entraTargetFor, oktaElToEntra, buildRow,
  toCsv, toMarkdown, toHtml, systemLogFilter, nowIso, graphAll,
} from './lib.mjs';
import { CONF } from './clinic-results/app.mjs';
import { graph } from '../scripts/demo/signin/lib.mjs';

const a = process.argv.slice(2);
const outDir = path.resolve(a.includes('--out') ? a[a.indexOf('--out') + 1] : HERE);
const noEntra = a.includes('--no-entra');
const log = (...m) => console.error('[inventory]', ...m);

const waves = JSON.parse(fs.readFileSync(path.join(HERE, 'waves.json'), 'utf8')).apps;
const o = okta();
const since = new Date(Date.now() - 7 * 86400e3).toISOString();

// ---- Okta ------------------------------------------------------------------------
const allApps = await o.list('/api/v1/apps?limit=200');
const apps = allApps.filter(isClinicApp);
const groupsById = Object.fromEntries((await o.list('/api/v1/groups?limit=200')).map((g) => [g.id, g]));
const rules = await o.list('/api/v1/groups/rules?limit=200');
const policyCache = {};
async function policy(id) {
  if (!id) return null;
  if (!policyCache[id]) {
    const p = await o.get(`/api/v1/policies/${id}`);
    const rs = await o.list(`/api/v1/policies/${id}/rules`);
    policyCache[id] = {
      id, name: p.name,
      rules: rs.map((r) => ({
        name: r.name, priority: r.priority, status: r.status, access: r.actions?.appSignOn?.access,
        factorMode: r.actions?.appSignOn?.verificationMethod?.factorMode,
        reauthenticateIn: r.actions?.appSignOn?.verificationMethod?.reauthenticateIn,
        constraints: r.actions?.appSignOn?.verificationMethod?.constraints || [],
        groups: (r.conditions?.people?.groups?.include || []).map((g) => groupsById[g]?.profile?.name || g),
      })),
    };
  }
  return policyCache[id];
}

const inv = [];
for (const app of apps) {
  const groups = (await o.list(`/api/v1/apps/${app.id}/groups?limit=200`)).map((g) => groupsById[g.id]?.profile?.name || g.id);
  const users = await o.list(`/api/v1/apps/${app.id}/users?limit=200`);
  const pol = await policy(app._links?.accessPolicy?.href?.split('/').pop());
  const appGroupIds = Object.entries(groupsById).filter(([, g]) => groups.includes(g.profile.name)).map(([id]) => id);
  const feeding = rules.filter((r) => (r.actions?.assignUserToGroups?.groupIds || []).some((id) => appGroupIds.includes(id))).map((r) => {
    const expr = r.conditions?.expression?.value;
    const t = oktaElToEntra(expr);
    return { name: r.name, status: r.status, okta: expr, entra: t.rule, why_not: t.reason || null, into: (r.actions.assignUserToGroups.groupIds || []).map((id) => groupsById[id]?.profile?.name || id) };
  });
  const sso = await o.list(`/api/v1/logs?since=${encodeURIComponent(since)}&limit=200&filter=${encodeURIComponent(systemLogFilter(app.id, ['user.authentication.sso']))}`);
  const protocol = protocolOf(app);
  inv.push({
    okta: {
      id: app.id, label: app.label, signOnMode: app.signOnMode, protocol, status: app.status,
      hidden: !!app.visibility?.hide?.web, groups, userCount: users.length,
      users: users.map((u) => u.credentials?.userName || u.id),
      policy: pol ? pol.name : 'default', policyRules: pol ? pol.rules : [],
      samlAttributes: (app.settings?.signOn?.attributeStatements || []).map((s) => `${s.name} = ${(s.values || []).join(',')}`),
      groupRules: feeding, sso7d: sso.length,
      entraPattern: entraTargetFor(protocol),
    },
    _app: app,
  });
}

// Phishing-resistant posture: who administers Okta, with which factors, and
// which rules demand a phishing-resistant factor.
const PR_FACTORS = new Set(['signed_nonce', 'webauthn']);
const admins = [];
for (const u of await o.list('/api/v1/users?limit=200')) {
  const roles = await o.list(`/api/v1/users/${u.id}/roles`).catch(() => []);
  if (!roles.length) continue;
  const f = await o.list(`/api/v1/users/${u.id}/factors`);
  admins.push({ login: u.profile.login, roles: roles.map((r) => r.type), factors: f.filter((x) => x.status === 'ACTIVE').map((x) => x.factorType), phishing_resistant: f.some((x) => x.status === 'ACTIVE' && PR_FACTORS.has(x.factorType)) });
}
const prRules = [];
for (const p of await o.list('/api/v1/policies?type=ACCESS_POLICY')) {
  for (const r of await o.list(`/api/v1/policies/${p.id}/rules`)) {
    const c = r.actions?.appSignOn?.verificationMethod?.constraints || [];
    prRules.push({ policy: p.name, rule: r.name, priority: r.priority, demands_phishing_resistant: r.actions?.appSignOn?.access !== 'DENY' && c.some((x) => x.possession?.phishingResistant === 'REQUIRED'), factorMode: r.actions?.appSignOn?.verificationMethod?.factorMode, access: r.actions?.appSignOn?.access });
  }
}

// ---- Entra -----------------------------------------------------------------------
let caPolicies = [];
if (!noEntra) {
  try { caPolicies = graph('GET', 'identity/conditionalAccess/policies?$select=id,displayName,state,conditions').value; } catch (e) { log(`CA policies not readable: ${String(e.message).split('\n')[0]}`); }
}
function entraFor(name) {
  if (noEntra || !name) return null;
  const r = graph('GET', `applications?$filter=displayName eq '${name.replace(/'/g, "''")}'&$select=appId,displayName`);
  if (!r.value.length) return null;
  const appId = r.value[0].appId;
  const sp = graph('GET', `servicePrincipals?$filter=appId eq '${appId}'&$select=id,displayName,appRoleAssignmentRequired`).value[0];
  if (!sp) return { displayName: name, appId, servicePrincipalId: null, assignedPrincipals: 0, assignedGroups: [], groupMembers: 0, ca: [] };
  const asg = graph('GET', `servicePrincipals/${sp.id}/appRoleAssignedTo?$select=principalId,principalType,principalDisplayName`).value;
  let members = 0;
  for (const g of asg.filter((x) => x.principalType === 'Group')) members += graphAll(graph, `groups/${g.principalId}/members?$select=id&$top=999`).length;
  const ca = caPolicies.filter((p) => (p.conditions?.applications?.includeApplications || []).includes(appId)).map((p) => `${p.displayName.split(' - ')[0]} (${p.state === 'enabled' ? 'on' : p.state === 'disabled' ? 'off' : 'report-only'})`);
  let signins = null;
  try { signins = graphAll(graph, `auditLogs/signIns?$filter=appId eq '${appId}' and createdDateTime ge ${since.replace(/\.\d+Z$/, 'Z')}&$top=200&$select=id`).length; } catch { signins = null; }
  return { displayName: sp.displayName, appId, servicePrincipalId: sp.id, assignmentRequired: sp.appRoleAssignmentRequired, assignedPrincipals: asg.length, assignedGroups: asg.map((x) => x.principalDisplayName), groupMembers: members, ca, signins7d: signins };
}

const conf = fs.existsSync(CONF) ? JSON.parse(fs.readFileSync(CONF, 'utf8')) : null;
const resultsDir = path.join(HERE, 'results');
const results = fs.existsSync(resultsDir) ? fs.readdirSync(resultsDir).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(fs.readFileSync(path.join(resultsDir, f), 'utf8'))) : [];

const rows = [];
for (const item of inv) {
  const label = item.okta.label;
  const plan = waves[label] || {};
  const entra = entraFor(plan.entra_app);
  item.entra = entra;
  const appTrusts = conf && conf.app === label ? conf.active : 'okta';
  item.appTrusts = appTrusts;
  const test = results.filter((r) => r.app === label && !r.staging).pop() || results.filter((r) => r.app === label).pop() || null;
  rows.push(buildRow({ app: item._app, plan, okta: item.okta, entra, appTrusts, test, oktaSso7d: item.okta.sso7d, entraSignins7d: entra ? entra.signins7d : null }));
  delete item._app;
}
rows.sort((x, y) => (x.wave - y.wave) || x.app.localeCompare(y.app));

// ---- Write ---------------------------------------------------------------------
const generatedAt = nowIso();
const sources = [
  `Okta API on ${o.org}: /api/v1/apps, /apps/{id}/groups, /apps/{id}/users, /policies/{id}/rules, /groups/rules, /logs (7 days), /users/{id}/roles, /users/{id}/factors`,
  noEntra ? 'Entra: skipped (--no-entra)' : 'Microsoft Graph as the lab operator: applications, servicePrincipals, appRoleAssignedTo, groups/{id}/members, identity/conditionalAccess/policies, auditLogs/signIns (7 days)',
  'Decisions (owner, wave, pilot, cut-over switch): lab/okta-migration/waves.json',
  'Test results: lab/okta-migration/results/*.json (cutover.mjs test)',
];
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'tracker.csv'), toCsv(rows));

const ruleMd = ['## Group rules: Okta to Entra', '', '| Okta rule | Okta expression | Entra dynamic rule | Decision |', '|---|---|---|---|',
  ...inv.flatMap((i) => i.okta.groupRules).filter((r, idx, all) => all.findIndex((x) => x.name === r.name) === idx).map((r) => {
    const decision = r.entra && /endsWith "@/.test(r.entra) ? 'Not copied: a login-domain rule means every hospital user after the acquisition. Assigned app group + access package instead.' : (r.entra ? 'Copy as a dynamic group when the app moves (HR owns the attribute).' : `No exact translation: ${r.why_not}`);
    return `| ${r.name} | \`${r.okta}\` | ${r.entra ? `\`${r.entra}\`` : '-'} | ${decision} |`;
  }), ''];
const prMd = ['## Phishing-resistant posture (Okta)', '', '| Admin | Roles | Active factors | Phishing-resistant factor enrolled |', '|---|---|---|---|',
  ...admins.map((x) => `| ${x.login} | ${x.roles.join(', ')} | ${x.factors.join(', ')} | ${x.phishing_resistant ? 'yes' : 'NO'} |`), '',
  '| Policy | Rule | Factors | Demands phishing-resistant |', '|---|---|---|---|',
  ...prRules.map((r) => `| ${r.policy} | ${r.rule} | ${r.access === 'DENY' ? 'deny' : (r.factorMode || '-')} | ${r.demands_phishing_resistant ? 'yes' : 'no'} |`), ''];
const md = toMarkdown(rows, { generatedAt, sources }).replace('## Sources', [...ruleMd, ...prMd, '## Sources'].join('\n'));
fs.writeFileSync(path.join(outDir, 'tracker.md'), md);
fs.writeFileSync(path.join(outDir, 'status.html'), toHtml(rows, { generatedAt, extra: { 'Group rules (Okta to Entra)': ruleMd.slice(4).join('\n'), 'Phishing-resistant posture': prMd.slice(4).join('\n') } }));
fs.writeFileSync(path.join(outDir, 'inventory.json'), JSON.stringify({ generatedAt, org: o.org, apps: inv, admins, accessPolicyRules: prRules }, null, 2) + '\n');
log(`${rows.length} apps -> ${path.relative(process.cwd(), outDir) || '.'}/tracker.csv, tracker.md, status.html, inventory.json`);
for (const r of rows) log(`  wave ${r.wave}  ${r.app.padEnd(28)} ${r.protocol.padEnd(9)} users ${String(r.users).padEnd(3)} ${r.status.padEnd(12)} ${r.test_result}`);
