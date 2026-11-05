#!/usr/bin/env node
// =============================================================================
// lab/scripts/demo/signin/doctor.mjs - signin-doctor: can every lab identity
// still sign in, right now, with no human?
// -----------------------------------------------------------------------------
//   node lab/scripts/demo/signin/doctor.mjs                 # every identity, table
//   node lab/scripts/demo/signin/doctor.mjs --only adm-presenter,test-user-a
//   node lab/scripts/demo/signin/doctor.mjs --json          # one JSON object per identity
//   node lab/scripts/demo/signin/doctor.mjs --with-tap      # also the pass-based ones
//   node lab/scripts/demo/signin/doctor.mjs --summary       # one line (preflight.sh)
//
// For each identity in identities.json: a FRESH headless sign-in with its
// method (no saved cookies, so the method itself is proven), then
//   session age  how old the saved session was before this run (the one a
//                script could have reused); "none" if there was none
//   PIM state    eligible groups (and until when), and which are active now
//                (group membership; end time from activatePim's record)
//   next expiry  the earliest of: an active PIM activation's end, a PIM
//                eligibility's end, the saved session's persistent cookie
// Identities whose method is "tap" are skipped unless --with-tap: their sign-in
// issues a one-time pass in the tenant. Reads Graph as the lab operator
// (eligibility: PrivilegedEligibilitySchedule.Read.AzureADGroup; membership:
// Directory.Read.All). Exit 0 = every identity tried signed in.
// =============================================================================
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadRegistry, signIn, pimRecords } from './identity.mjs';
import { graph, statePath, readOwnedState } from './lib.mjs';

// ---- pure helpers (unit-tested) ---------------------------------------------------
export function age(ms) {
  if (ms == null) return 'none';
  const m = Math.round(ms / 60000);
  return m < 60 ? `${m} min` : m < 2880 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} d`;
}
// The earliest of several {label, at} (at = ISO string or epoch ms); null when none.
export function nextExpiry(items, now = Date.now()) {
  const future = items.filter((i) => i && i.at != null).map((i) => ({ ...i, t: typeof i.at === 'number' ? i.at : Date.parse(i.at) }))
    .filter((i) => Number.isFinite(i.t) && i.t > now).sort((a, b) => a.t - b.t);
  return future.length ? `${future[0].label} ${new Date(future[0].t).toISOString().slice(0, 16).replace('T', ' ')}Z` : '-';
}
// The persistent Entra session cookie's expiry in a saved storage state.
export function sessionCookieExpiry(state) {
  const c = (state && state.cookies || []).filter((x) => /^ESTSAUTHPERSISTENT$|^ESTSAUTH$/.test(x.name) && x.expires > 0);
  return c.length ? Math.max(...c.map((x) => x.expires * 1000)) : null;
}
export function table(rows) {
  const cols = ['identity', 'method', 'works', 'session age', 'PIM state', 'next expiry'];
  const w = cols.map((c) => Math.max(c.length, ...rows.map((r) => String(r[c] ?? '').length)));
  const line = (vals) => vals.map((v, i) => String(v ?? '').padEnd(w[i])).join('  ');
  return [line(cols), line(w.map((n) => '-'.repeat(n))), ...rows.map((r) => line(cols.map((c) => r[c])))].join('\n');
}

// ---- PIM state, read as the operator ---------------------------------------------------
const names = new Map();
function groupName(gid) {
  if (!names.has(gid)) { try { names.set(gid, graph('GET', `groups/${gid}?$select=displayName`).displayName); } catch { names.set(gid, gid.slice(0, 8)); } }
  return names.get(gid);
}
function pimState(id, upn) {
  const uid = graph('GET', `users/${encodeURIComponent(upn)}?$select=id`).id;
  const elig = graph('GET', `identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?$filter=principalId eq '${uid}'`).value || [];
  if (!elig.length) return { text: 'no eligibility', expiries: [] };
  const rec = pimRecords(id);
  const parts = [], expiries = [];
  for (const g of elig) {
    const name = groupName(g.groupId);
    const members = graph('GET', `groups/${g.groupId}/members?$select=id&$top=999`).value || [];
    const active = members.some((m) => m.id === uid);
    const r = rec.find((x) => x.group === name);
    parts.push(`${name}: ${active ? `ACTIVE${r ? ` to ${r.endsUtc.slice(11, 16)}Z` : ''}` : 'eligible'}`);
    if (active && r) expiries.push({ label: `PIM ${name}`, at: r.endsUtc });
    if (g.endDateTime) expiries.push({ label: `eligibility ${name}`, at: g.endDateTime });
  }
  return { text: parts.join('; '), expiries };
}

export async function doctor({ only = null, withTap = false, headless = true, onRow = () => {} } = {}) {
  const reg = loadRegistry();
  const rows = [];
  for (const [id, e] of Object.entries(reg)) {
    if (only && !only.includes(id)) continue;
    const row = { identity: id, method: e.method, works: '', 'session age': '-', 'PIM state': '-', 'next expiry': '-', note: '' };
    const expiries = [];
    if (e.kind === 'entra') {
      try { const f = statePath(e.upn); const st = readOwnedState(e.upn); row['session age'] = st ? age(Date.now() - fs.statSync(f).mtimeMs) : 'none'; const c = sessionCookieExpiry(st); if (c) expiries.push({ label: 'session', at: c }); } catch { row['session age'] = 'none'; }
      try { const p = pimState(id, e.upn); row['PIM state'] = p.text; expiries.push(...p.expiries); } catch (err) { row['PIM state'] = `unread (${err.message.slice(0, 40)})`; }
    }
    if (e.method === 'tap' && !withTap) { row.works = 'skipped'; row.note = 'issues a one-time pass: --with-tap'; }
    else {
      const t0 = Date.now();
      try { const r = await signIn(id, e.home, { fresh: true, headless, timeoutMs: 120000 }); row.works = `yes (${Math.round((Date.now() - t0) / 1000)} s)`; row.method = r.method; await r.close(); }
      catch (err) { row.works = 'NO'; row.note = err.message.replace(/\s*\[screenshot: ([^\]]+)\]/, ' (screenshot $1)').slice(0, 300); }
    }
    row['next expiry'] = nextExpiry(expiries);
    rows.push(row); onRow(row);
  }
  return rows;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const a = process.argv.slice(2);
  const flag = (n) => { const i = a.indexOf(n); if (i < 0) return false; a.splice(i, 1); return true; };
  const val = (n) => { const i = a.indexOf(n); if (i < 0) return undefined; const v = a[i + 1]; a.splice(i, 2); return v; };
  const json = flag('--json'), withTap = flag('--with-tap'), headed = flag('--headed'), summary = flag('--summary');
  const only = val('--only');
  if (a.length) { console.error('usage: node doctor.mjs [--only id,id] [--with-tap] [--json] [--summary] [--headed]'); process.exit(2); }
  process.env.SIGNIN_QUIET = process.env.SIGNIN_QUIET || '1';
  const rows = await doctor({ only: only ? only.split(',') : null, withTap, headless: !headed, onRow: (r) => { if (json) console.log(JSON.stringify(r)); } });
  const bad = rows.filter((r) => r.works === 'NO');
  if (summary) console.log(bad.length ? `${bad.length} of ${rows.length} identities cannot sign in: ${bad.map((r) => r.identity).join(', ')}` : `All ${rows.filter((r) => r.works.startsWith('yes')).length} identities sign in with no human (${rows.filter((r) => r.works === 'skipped').length} skipped)`);
  else if (!json) {
    console.log(table(rows));
    for (const r of rows) if (r.note) console.log(`  ${r.identity}: ${r.note}`);
  }
  process.exit(bad.length ? 1 : 0);
}
