#!/usr/bin/env node
// =============================================================================
// lab/scripts/monitoring/answer-teams-card.mjs
//   answer a containment approval card in Teams, headless, as a lab TEST user
// -----------------------------------------------------------------------------
//   node lab/scripts/monitoring/answer-teams-card.mjs --as <upn> --incident <n> --choice contain|revoke|reject
//        [--playbook pb-identity-contain] [--rg rg-identity-lab] [--workspace loga-idlab] [--headed]
//
// A drill and evidence aid (ADR 0017, evidence plan E41): it does what an
// approver does by hand - opens the SOC team's Identity-SecOps channel in
// Teams on the web, finds the newest UNANSWERED card for Sentinel incident
// #<n>, and clicks one button. It decides nothing itself: the playbook still
// checks who answered (a listed approver who is not the subject, by object
// id, from the identity Teams returns), so an answer from anyone else is
// ignored exactly as it would be by hand. That is what the drill proves.
//
// FAIL CLOSED: an answer that ACTS (contain, revoke) is given only when EVERY
// account entity on the incident is a lab test or drill account, read from
// trusted sources - the incident's entities in Sentinel, then each account's
// UPN from Graph by its object id - never from the card's text (a display
// name can contain anything, including a fake address). Reject is always
// allowed: it changes nothing.
//
// WHY headless and a test user: the drill needs a real Teams answer (the
// responder identity comes from Teams, it cannot be typed into the Logic App),
// without a person's account. The sign-in is the staff sign-in toolkit's
// (password + authenticator code from the Keychain, Conditional Access
// evaluated); the toolkit refuses the owner's and break-glass accounts.
//
// Where the card goes is read from the DEPLOYED playbook's parameters
// (teamsGroupId / teamsChannelId), so the drill always looks where the
// playbook posts. Card text and button titles are the ones in
// lab/monitoring/playbook-contain.json (Compose_approval_card).
// =============================================================================
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../../..');
const OP = process.env.CONTOSO_OP || path.join(REPO, 'lab/scripts/operator/op');
const TOOLKIT = process.env.SIGNIN_TOOLKIT_DIR || path.join(REPO, 'lab/scripts/demo/signin');
const { signIn } = await import(pathToFileURL(path.join(TOOLKIT, 'signin.mjs')).href);
const { checkUpn, shot, sleep } = await import(pathToFileURL(path.join(TOOLKIT, 'lib.mjs')).href);

// Button titles from Compose_approval_card (playbook-contain.json).
const BUTTONS = { contain: 'Contain (revoke + disable)', revoke: 'Revoke sessions only', reject: 'Reject - no action' };
const CARD_TITLE = 'ITDR containment approval - Sentinel incident #';
// Accounts a drill may Contain / Revoke: the lab test users and throwaway
// drill users (itdr-drill-<date>), in the lab tenant's domains only.
const DRILL_SUBJECT = /^(test-user-[a-z0-9]+|itdr-drill-[0-9a-z-]+)@(contosohealthlab\.com|contosohealthlab\.onmicrosoft\.com)$/i;
// True only for a non-empty list of UPNs that are ALL drill subjects.
function drillOnly(upns) {
  return Array.isArray(upns) && upns.length > 0 && upns.every((u) => typeof u === 'string' && DRILL_SUBJECT.test(u));
}
// A desktop Chrome user agent: Teams on the web serves headless Chromium's
// default "HeadlessChrome" agent an unsupported-browser page.
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const a = process.argv.slice(2);
const val = (n, d) => { const i = a.indexOf(n); if (i < 0) return d; const v = a[i + 1]; a.splice(i, 2); return v; };
const headed = (() => { const i = a.indexOf('--headed'); if (i < 0) return false; a.splice(i, 1); return true; })();
const upnArg = val('--as'), incident = val('--incident'), choice = val('--choice');
const playbook = val('--playbook', 'pb-identity-contain'), rg = val('--rg', 'rg-identity-lab'), workspace = val('--workspace', 'loga-idlab');
if (!upnArg || !/^\d+$/.test(incident || '') || !BUTTONS[choice] || a.length) {
  console.error('usage: node answer-teams-card.mjs --as <upn> --incident <n> --choice contain|revoke|reject [--playbook pb-identity-contain] [--rg rg-identity-lab] [--workspace loga-idlab] [--headed]');
  process.exit(2);
}
const result = (o) => console.log(JSON.stringify({ as: upnArg, incident: Number(incident), choice, ...o }));

// az as the lab operator; a failed call throws (never a silent default).
const az = (args, input) => {
  const out = execFileSync(OP, ['az', ...args, '--only-show-errors', '-o', 'json'], {
    input, encoding: 'utf8', stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'], maxBuffer: 32 << 20,
  });
  return out.trim() ? JSON.parse(out) : null;
};

// The incident's account entities -> their UPNs, from Sentinel and Graph
// (incidents list + entities: Microsoft.SecurityInsights 2024-09-01, the
// version modules/monitoring and the drill used; read live 2026-11-05).
function incidentSubjects() {
  const ws = az(['monitor', 'log-analytics', 'workspace', 'show', '-g', rg, '-n', workspace, '--query', '{id:id}']).id;
  const base = `https://management.azure.com${ws}/providers/Microsoft.SecurityInsights/incidents`;
  const api = 'api-version=2024-09-01';
  const found = az(['rest', '--method', 'GET', '--url', `${base}?${api}&$filter=properties/incidentNumber eq ${incident}`]);
  const inc = (found?.value || []).filter((i) => i?.properties?.incidentNumber === Number(incident));
  if (inc.length !== 1) throw new Error(`incident #${incident}: ${inc.length} matches in ${workspace}`);
  const ents = az(['rest', '--method', 'POST', '--url', `${base}/${inc[0].name}/entities?${api}`])?.entities || [];
  return ents.filter((e) => e.kind === 'Account').map((e) => {
    const id = e.properties?.aadUserId;
    // No Entra object id = an AD-only account: never a drill subject.
    if (!id || !/^[0-9a-f-]{36}$/i.test(id)) return '';
    return az(['rest', '--method', 'GET', '--url', `https://graph.microsoft.com/v1.0/users/${id}?$select=userPrincipalName`])?.userPrincipalName || '';
  });
}

let r = null;
try {
  const upn = checkUpn(upnArg);
  let subjects = null;
  if (choice !== 'reject') {
    // A brand-new incident can answer the entities read with no Account for
    // a moment (seen 2026-11-05 on drill incident #51): retry an EMPTY answer
    // only, a few times; anything still empty is refused below.
    for (let i = 0; i < 4; i++) {
      subjects = incidentSubjects();
      if (subjects.length) break;
      await sleep(5000);
    }
    if (!drillOnly(subjects)) throw new Error(`refused: incident #${incident} names ${JSON.stringify(subjects)}; --choice ${choice} is only for incidents whose every account is a lab test or drill account (reject is always allowed)`);
  }
  const params = az(['resource', 'show', '-g', rg, '-n', playbook, '--resource-type', 'Microsoft.Logic/workflows', '--query', 'properties.parameters']);
  const groupId = params?.teamsGroupId?.value, channelId = params?.teamsChannelId?.value;
  if (!groupId || !channelId) throw new Error(`${playbook} has no teamsGroupId / teamsChannelId: nothing to answer`);
  const tenantId = az(['account', 'show', '--query', '{t:tenantId}']).t;

  r = await signIn(upn, 'https://teams.microsoft.com/v2/', {
    headless: !headed, contextOptions: { userAgent: UA }, timeoutMs: 180000,
    until: async (p) => /(^|\.)teams\.(microsoft\.com|cloud\.microsoft)$/.test(new URL(p.url()).hostname),
  });
  const page = r.page;
  await sleep(6000);
  // The channel deep link opens a launcher first ("Use the web app instead").
  await page.goto(`https://teams.microsoft.com/l/channel/${encodeURIComponent(channelId)}/Identity-SecOps?groupId=${groupId}&tenantId=${tenantId}`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  for (let i = 0; i < 20; i++) {
    const web = page.getByText('Use the web app instead');
    if (await web.isVisible().catch(() => false)) { await web.click(); break; }
    if (/\/v2\//.test(page.url())) break;
    await sleep(1000);
  }

  // Newest card for THIS incident that still has the button: earlier runs'
  // cards are rewritten to "Decision recorded" and have no buttons left.
  // The chosen button is TAGGED in the page and clicked through that tag,
  // never by a page-wide index (another answer elsewhere would shift it); a
  // re-render drops the tag, so the click fails instead of hitting a
  // different button.
  const want = BUTTONS[choice];
  const tag = crypto.randomUUID();
  const pick = () => page.locator('button').evaluateAll((bs, { want, title, n, tag }) => {
    const esc = title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const mine = new RegExp(`${esc}${n}(?!\\d)`);
    let last = null;
    for (const b of bs) {
      b.removeAttribute('data-soc-drill');
      if ((b.innerText || '').trim() !== want) continue;
      for (let e = b.parentElement; e; e = e.parentElement) {
        const t = e.innerText || '';
        if (!t.includes(title)) continue;
        // The nearest ancestor holding a card title is this card.
        if (t.split(title).length === 2 && mine.test(t)) last = b;
        break;
      }
    }
    if (last) last.setAttribute('data-soc-drill', tag);
    return !!last;
  }, { want, title: CARD_TITLE, n: incident, tag });
  let ok = false;
  for (let i = 0; i < 45 && !ok; i++) { ok = await pick(); if (!ok) await sleep(2000); }
  if (!ok) throw new Error(`no unanswered card for incident #${incident} with "${want}" in the channel`);
  const btn = page.locator(`button[data-soc-drill="${tag}"]`);
  await btn.scrollIntoViewIfNeeded();
  // Scrolling can re-render: tag again, and click only the tagged button.
  if (!(await pick())) throw new Error(`the card for incident #${incident} changed before the click`);
  // Teams rewrites the answered card to the playbook's updateMessage once the
  // Logic App accepted the answer: one more "Decision recorded" than before.
  const recorded = async () => ((await page.locator('body').innerText().catch(() => '')).match(/Decision recorded/g) || []).length;
  const before = await recorded();
  await btn.click({ timeout: 10000 });
  let updated = false;
  for (let i = 0; i < 30 && !updated; i++) { await sleep(2000); updated = (await recorded()) > before; }
  const f = await shot(page, `card-${choice}-${incident}`, { redacted: false });
  result({ ok: true, clicked: want, subjects, cardUpdated: updated, screenshot: f });
  await r.close();
} catch (e) {
  let f = '';
  if (r) { f = await shot(r.page, `card-fail-${incident}`).catch(() => ''); await r.close(); }
  result({ ok: false, error: String(e.message || e).slice(0, 500), screenshot: f });
  process.exit(1);
}
