#!/usr/bin/env node
// =============================================================================
// lab/okta-migration/syslog.mjs - did the sign-ins really move?
// -----------------------------------------------------------------------------
//   node lab/okta-migration/syslog.mjs [--app "Clinic Lab Results"] [--days 7] [--json]
//
// The runbook's Phase 2 step 5 ("Okta System Log shows zero sign-ins to it for
// 7 days") and its Entra mirror, side by side, for one app:
//   * OKTA SYSTEM LOG (GET /api/v1/logs) with the filter
//       (eventType eq "user.authentication.sso" or
//        eventType eq "app.oauth2.authorize.code") and target.id eq "<app id>"
//     - every time Okta sent someone to the app - and the admin events on the
//     app itself (application.lifecycle.update: the hide at the cut-over);
//   * ENTRA SIGN-IN LOG (Graph auditLogs/signIns, appId eq the Entra app's
//     client id) - every sign-in to the Entra app, with the CA result;
//   * the cut-over moments from the app's own config history
//     (~/.contoso-operator/clinic-results/idp.json), so each event is
//     labelled BEFORE or AFTER the cut-over.
// The query strings are printed too: the same filter pasted into Okta Admin
// > Reports > System Log, and the KQL for the lab's Sentinel workspace.
// Read-only. The Okta token stays in this process (Keychain).
// =============================================================================
import fs from 'node:fs';
import { okta, systemLogFilter, entraSigninKql, nowIso } from './lib.mjs';
import { CONF } from './clinic-results/app.mjs';
import { graph } from '../scripts/demo/signin/lib.mjs';

const a = process.argv.slice(2);
const opt = (k, d) => { const i = a.indexOf(k); return i >= 0 ? a[i + 1] : d; };
const label = opt('--app', 'Clinic Lab Results');
const days = Number(opt('--days', '7'));
const asJson = a.includes('--json');

const since = new Date(Date.now() - days * 86400e3).toISOString();
const o = okta();
const app = (await o.list(`/api/v1/apps?q=${encodeURIComponent(label)}&limit=20`)).find((x) => x.label === label);
if (!app) { console.error(`Okta has no app labelled "${label}"`); process.exit(1); }

const filter = systemLogFilter(app.id);
const sso = await o.list(`/api/v1/logs?since=${encodeURIComponent(since)}&limit=200&sortOrder=ASCENDING&filter=${encodeURIComponent(filter)}`);
const admin = await o.list(`/api/v1/logs?since=${encodeURIComponent(since)}&limit=200&sortOrder=ASCENDING&filter=${encodeURIComponent(`eventType sw "application." and target.id eq "${app.id}"`)}`);

const conf = fs.existsSync(CONF) ? JSON.parse(fs.readFileSync(CONF, 'utf8')) : null;
const cutovers = (conf?.history || []).filter((h) => h.to === 'entra').map((h) => h.at);
const lastCut = cutovers.length ? cutovers[cutovers.length - 1] : null;
const rollbacks = (conf?.history || []).filter((h) => h.to === 'okta').map((h) => h.at);
const phase = (t) => (lastCut && t >= lastCut ? 'AFTER cut-over' : 'BEFORE cut-over');

const oktaRows = sso.map((e) => ({ time: e.published.replace(/\.\d+Z$/, 'Z'), event: e.eventType, user: e.actor?.alternateId, result: e.outcome?.result, phase: phase(e.published) }));
const adminRows = admin.map((e) => ({ time: e.published.replace(/\.\d+Z$/, 'Z'), event: e.eventType, by: e.actor?.alternateId, change: e.debugContext?.debugData?.changedAttributes || e.displayMessage }));

let entraRows = [], entraNote = '';
const entraId = conf?.entra?.client_id;
if (entraId) {
  try {
    const r = graph('GET', `https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=appId eq '${entraId}' and createdDateTime ge ${since.replace(/\.\d+Z$/, 'Z')}&$top=50&$select=createdDateTime,userPrincipalName,status,conditionalAccessStatus,appliedConditionalAccessPolicies,authenticationRequirement`);
    entraRows = r.value.map((s) => ({
      time: s.createdDateTime, user: s.userPrincipalName, result: s.status?.errorCode === 0 ? 'SUCCESS' : `error ${s.status?.errorCode}`,
      ca: s.conditionalAccessStatus, mfa: s.authenticationRequirement,
      policies: (s.appliedConditionalAccessPolicies || []).filter((p) => p.result === 'success' || p.result === 'failure').map((p) => `${p.displayName.split(' - ')[0]}:${p.result}`).join(' '),
      phase: phase(s.createdDateTime),
    })).sort((x, y) => x.time.localeCompare(y.time));
  } catch (e) { entraNote = `Entra sign-in log not readable: ${String(e.message).split('\n')[0].slice(0, 200)}`; }
} else entraNote = 'no Entra app in the config yet (cutover.mjs prestage after the Entra PR is applied)';

const out = {
  generated: nowIso(), app: label, okta_app_id: app.id, window_days: days,
  okta_filter: filter, entra_kql: entraSigninKql(label),
  cutover_at: lastCut, rollbacks,
  okta_sso: { before: oktaRows.filter((r) => r.phase.startsWith('BEFORE')).length, after: oktaRows.filter((r) => r.phase.startsWith('AFTER')).length, events: oktaRows },
  okta_admin_events: adminRows,
  entra_signins: { before: entraRows.filter((r) => r.phase.startsWith('BEFORE')).length, after: entraRows.filter((r) => r.phase.startsWith('AFTER')).length, events: entraRows, note: entraNote || undefined },
};

if (asJson) { console.log(JSON.stringify(out, null, 2)); process.exit(0); }
console.log(`${label}: sign-ins in the last ${days} days${lastCut ? `, cut over at ${lastCut}` : ' (not cut over yet)'}\n`);
console.log(`Okta System Log filter:\n  ${filter}\n`);
console.log(`Okta sent users to the app: ${out.okta_sso.before} before, ${out.okta_sso.after} after the cut-over`);
for (const r of oktaRows) console.log(`  ${r.time}  ${r.event.padEnd(26)} ${String(r.user).padEnd(36)} ${r.result}  ${r.phase}`);
console.log(`\nOkta admin events on the app:`);
for (const r of adminRows) console.log(`  ${r.time}  ${r.event.padEnd(32)} ${r.by}  ${typeof r.change === 'string' ? r.change.slice(0, 80) : ''}`);
console.log(`\nEntra sign-ins to the app: ${out.entra_signins.before} before, ${out.entra_signins.after} after${entraNote ? ` (${entraNote})` : ''}`);
for (const r of entraRows) console.log(`  ${r.time}  ${String(r.user).padEnd(36)} ${r.result}  CA ${r.ca}  ${r.policies}  ${r.phase}`);
console.log(`\nThe same question in Sentinel (KQL):\n${out.entra_kql.split('\n').map((l) => `  ${l}`).join('\n')}`);
