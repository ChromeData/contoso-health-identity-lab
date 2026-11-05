#!/usr/bin/env node
// =============================================================================
// lab/scripts/monitoring/answer-teams-card.mjs
//   answer a containment approval card in Teams, headless, as a lab TEST user
// -----------------------------------------------------------------------------
//   node lab/scripts/monitoring/answer-teams-card.mjs --as <upn> --incident <n> --choice contain|revoke|reject [--playbook pb-identity-contain]
//
// A drill and evidence aid (ADR 0017, evidence plan E41): it does what an
// approver does by hand - opens the SOC team's Identity-SecOps channel in
// Teams on the web, finds the newest UNANSWERED card for Sentinel incident
// #<n>, and clicks one button. It decides nothing itself: the playbook still
// checks who answered (a listed approver who is not the subject, by object
// id, from the identity Teams returns), so an answer from anyone else is
// ignored exactly as it would be by hand. That is what the drill proves.
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
// The card's Account fact is "<display name> (<UPN>)", followed by the
// "Entra object id" fact. The UPN is the LAST parenthesised address in that
// span: a display name can contain anything, including a fake "(x@y)".
function subjectOf(cardText) {
  const m = /Account([\s\S]*?)Entra object id/.exec(cardText || '');
  const all = m ? [...m[1].matchAll(/\(([^()\s]+@[^()\s]+)\)/g)] : [];
  return all.length ? all[all.length - 1][1] : '';
}
// A desktop Chrome user agent: Teams on the web serves headless Chromium's
// default "HeadlessChrome" agent an unsupported-browser page.
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const a = process.argv.slice(2);
const val = (n, d) => { const i = a.indexOf(n); if (i < 0) return d; const v = a[i + 1]; a.splice(i, 2); return v; };
const headed = (() => { const i = a.indexOf('--headed'); if (i < 0) return false; a.splice(i, 1); return true; })();
const upnArg = val('--as'), incident = val('--incident'), choice = val('--choice'), playbook = val('--playbook', 'pb-identity-contain'), rg = val('--rg', 'rg-identity-lab');
if (!upnArg || !/^\d+$/.test(incident || '') || !BUTTONS[choice] || a.length) {
  console.error('usage: node answer-teams-card.mjs --as <upn> --incident <n> --choice contain|revoke|reject [--playbook pb-identity-contain] [--rg rg-identity-lab] [--headed]');
  process.exit(2);
}
const result = (o) => console.log(JSON.stringify({ as: upnArg, incident: Number(incident), choice, ...o }));

let r = null;
try {
  const upn = checkUpn(upnArg);
  const params = JSON.parse(execFileSync(OP, ['az', 'resource', 'show', '-g', rg, '-n', playbook, '--resource-type', 'Microsoft.Logic/workflows',
    '--query', 'properties.parameters', '-o', 'json', '--only-show-errors'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  const groupId = params?.teamsGroupId?.value, channelId = params?.teamsChannelId?.value;
  if (!groupId || !channelId) throw new Error(`${playbook} has no teamsGroupId / teamsChannelId: nothing to answer`);
  const tenantId = JSON.parse(execFileSync(OP, ['az', 'account', 'show', '--query', '{t:tenantId}', '-o', 'json', '--only-show-errors'], { encoding: 'utf8' })).t;

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
  const want = BUTTONS[choice];
  let idx = -1, cardText = '';
  for (let i = 0; i < 45 && idx < 0; i++) {
    [idx, cardText] = await page.locator('button').evaluateAll((bs, { want, title, n }) => {
      let last = -1, text = '';
      bs.forEach((b, k) => {
        if ((b.innerText || '').trim() !== want) return;
        for (let e = b.parentElement; e; e = e.parentElement) {
          const t = e.innerText || '';
          if (!t.includes(title)) continue;
          // The nearest ancestor holding a card title is this card.
          if (new RegExp(`${title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}${n}(?!\\d)`).test(t) && t.split(title).length === 2) { last = k; text = t; }
          break;
        }
      });
      return [last, text];
    }, { want, title: CARD_TITLE, n: incident });
    if (idx < 0) await sleep(2000);
  }
  if (idx < 0) throw new Error(`no unanswered card for incident #${incident} with "${want}" in the channel`);
  // Fail closed for a drill tool: an answer that ACTS (Contain, Revoke) is
  // given only for a card about a lab test or drill account. A card about
  // anyone else - the owner's admin account, a real person - is never
  // approved by automation; Reject is always allowed (it changes nothing).
  const subject = subjectOf(cardText);
  if (choice !== 'reject' && !DRILL_SUBJECT.test(subject)) throw new Error(`refused: the card is about '${subject || 'an unreadable account'}', not a lab test or drill account; only --choice reject is allowed for it`);
  const btn = page.locator('button').nth(idx);
  await btn.scrollIntoViewIfNeeded();
  // Teams rewrites the answered card to the playbook's updateMessage once the
  // Logic App accepted the answer: one more "Decision recorded" than before.
  const recorded = async () => ((await page.locator('body').innerText().catch(() => '')).match(/Decision recorded/g) || []).length;
  const before = await recorded();
  await btn.click();
  let updated = false;
  for (let i = 0; i < 30 && !updated; i++) { await sleep(2000); updated = (await recorded()) > before; }
  const f = await shot(page, `card-${choice}-${incident}`, { redacted: false });
  result({ ok: true, clicked: want, subject, cardUpdated: updated, screenshot: f });
  await r.close();
} catch (e) {
  let f = '';
  if (r) { f = await shot(r.page, `card-fail-${incident}`).catch(() => ''); await r.close(); }
  result({ ok: false, error: String(e.message || e).slice(0, 500), screenshot: f });
  process.exit(1);
}
