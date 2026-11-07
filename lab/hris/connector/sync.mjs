#!/usr/bin/env node
// =============================================================================
// sync.mjs - the HR connector: OrangeHRM -> the provisioning feed -> Entra.
// -----------------------------------------------------------------------------
//   node lab/hris/connector/sync.mjs --dry-run      show what would be sent; write nothing
//   node lab/hris/connector/sync.mjs                one sync
//   node lab/hris/connector/sync.mjs --watch 60     sync every 60 seconds (the schedule)
//
// One sync:
//  1. Read OrangeHRM's provisioning view (lib/hris.mjs: 8 fields, read-only).
//  2. Read the feed on hr-feed (lib/store.mjs, through `gh`).
//  3. Work out who was hired, moved, left or came back (lib/feed.mjs).
//  4. If anything changed: ONE commit to the feed. hr-feed.yml then signs in
//     as HR-SYNC (GitHub OIDC, no stored secret) and sends only those
//     workers to Entra API-driven inbound provisioning (bulkUpload).
//  5. In --watch mode, report each commit's send result as it finishes.
//
// WHY a schedule and not a webhook: OrangeHRM open source has no outbound
// webhook. WHY GitHub in the middle: it is how the send gets a workload
// identity with no stored secret. Both: ADR 0028.
//
// Options: --repo OWNER/NAME (default: this checkout's origin), --branch
// (default hr-feed), --store file:PATH (a local copy: sends nothing).
// Above the mass-change limit nothing is written; a reviewed bulk change is
// IT's job (hr-feed.yml run by hand, Invoke-InboundProvisioning.ps1 -Force).
// Every sync appends one JSON line to .state/sync-log.jsonl (gitignored):
// the time, what changed, the commit. Those lines are the timing evidence.
// =============================================================================
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFeed, serialiseFeed, reconcile, describe, hospitalToday, MAX_ACCESS_CHANGES } from './lib/feed.mjs';
import { GitHubStore, FileStore } from './lib/store.mjs';
import { readHris } from './lib/hris.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
const flag = (name) => args.includes(name);
const dryRun = flag('--dry-run');
const watch = Number(opt('--watch', 0));
const storeArg = opt('--store', '');

function defaultRepo() {
  const url = execFileSync('git', ['-C', here, 'remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim();
  return url.replace(/^.*github\.com[:/]/, '').replace(/\.git$/, '');
}
const store = storeArg.startsWith('file:')
  ? new FileStore({ file: storeArg.slice(5) })
  : new GitHubStore({ repo: opt('--repo', defaultRepo()), branch: opt('--branch', 'hr-feed') });

const logDir = join(here, '.state');
const log = (entry) => { mkdirSync(logDir, { recursive: true }); appendFileSync(join(logDir, 'sync-log.jsonl'), JSON.stringify(entry) + '\n'); };
const stamp = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');
const say = (line) => console.log(`${stamp()}  ${line}`);

const pending = new Map(); // commit -> summary, until its hr-feed run ends

async function syncOnce() {
  const at = stamp();
  const rows = await readHris();
  const { text, version } = await store.read();
  const feed = parseFeed(text);
  const out = reconcile(feed, rows, hospitalToday());
  for (const h of out.held) say(`HELD  ${h.who} (employee ${h.employeeId}): ${h.why}.`);
  for (const c of out.changes.filter((x) => !x.write)) say(`WAIT  ${describe(c)}: leaves on ${c.on}; the sync on that day sends it.`);
  const writes = out.changes.filter((c) => c.write);
  if (!writes.length) { say(`No change in OrangeHRM (${rows.length} records read, ${out.held.length} held).`); log({ at, read: rows.length, changes: [], held: out.held.length }); return; }
  const lines = writes.map(describe);
  for (const l of lines) say(`${dryRun ? 'WOULD SEND' : 'SEND'}  ${l.replace(/^HR: /, '')}`);
  if (dryRun) { log({ at, dryRun: true, changes: writes.map((c) => ({ kind: c.kind, employeeId: c.worker.employeeId })) }); return; }
  const message = lines.length === 1 ? lines[0] : `HR: ${lines.length} changes from OrangeHRM\n\n${lines.map((l) => `- ${l.replace(/^HR: /, '')}`).join('\n')}`;
  try {
    const { commit, at: committed } = await store.write(serialiseFeed(out.feed), version, message);
    say(`Written to the feed: commit ${commit.slice(0, 7)} at ${committed}. hr-feed.yml sends it as HR-SYNC.`);
    log({ at, committed, commit, changes: writes.map((c) => ({ kind: c.kind, employeeId: c.worker.employeeId })) });
    pending.set(commit, lines.join('; '));
  } catch (e) {
    if (e.conflict) { say('The feed changed while this sync ran. Nothing written; the next sync re-reads it.'); return; }
    throw e;
  }
}

async function checkDeliveries() {
  for (const [commit, what] of pending) {
    const d = await store.delivery(commit);
    if (d.state === 'accepted' || d.state === 'failed') {
      say(`${d.state === 'accepted' ? 'ACCEPTED' : 'FAILED'}  ${what} (run ended ${d.finishedAt}). ${d.state === 'accepted' ? 'Microsoft answered 202 and logged no failure while the run waited; the provisioning log is the confirmation.' : 'Nothing is half-done. IT reads the run, fixes the cause and re-runs it.'} ${d.run}`);
      log({ at: stamp(), commit, delivery: d.state, finishedAt: d.finishedAt, run: d.run });
      pending.delete(commit);
    }
  }
}

async function cycle() {
  try { await syncOnce(); } catch (e) { say(`ERROR  ${e.message}`); log({ at: stamp(), error: e.message }); if (!watch) process.exitCode = 1; }
  if (watch) { try { await checkDeliveries(); } catch (e) { say(`ERROR reading the send result: ${e.message}`); } }
}

say(`HR connector: OrangeHRM -> ${storeArg || `${store.repo}@${store.branch}`}${dryRun ? ' (dry run)' : ''}${watch ? `, every ${watch} s` : ''}. Limit: ${MAX_ACCESS_CHANGES} leavers or job changes per sync.`);
await cycle();
if (watch) setInterval(cycle, watch * 1000);
