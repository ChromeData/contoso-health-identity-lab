#!/usr/bin/env node
// =============================================================================
// server.mjs - "Contoso HR", the lab's stand-in for an HR system (Workday,
// SuccessFactors). A plain web form for HR staff: hire a worker, change a
// worker's job or department, make a worker a leaver.
// -----------------------------------------------------------------------------
//   node lab/hr-app/server.mjs                      # the lab: roster on hr-feed, sends for real
//   node lab/hr-app/server.mjs --store file:/tmp/r.csv   # rehearsal: a local copy, sends nothing
//   then open http://127.0.0.1:8484
//
// WHAT A SAVE DOES: one commit to the roster on the hr-feed branch (the HR
// app's own data store, never edited by a person). hr-feed.yml runs on that
// commit and sends ONLY the changed worker to Microsoft Entra's API-driven
// inbound provisioning API (POST .../synchronization/jobs/{id}/bulkUpload),
// signed in as HR-SYNC over GitHub OIDC. The provisioning agent writes the
// account into Active Directory on DC01; Cloud Sync copies it to Entra ID;
// group rules, auto-assignment, AWS SCIM and ServiceNow follow. ADR 0027.
//
// SAFETY: listens on 127.0.0.1 only (not the network). Every write needs the
// per-start form token the page was served with (a page from another site
// cannot post here). Never asks for, stores or shows a password: none of
// the fields exist.
// =============================================================================
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseRoster, serialiseRoster, hire, change, describe, jobCatalogue, publicWorker, HrError } from './lib/roster.mjs';
import { GitHubStore, FileStore } from './lib/store.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const RULES = join(here, '..', 'iga', 'birthright-rules.json');

export function makeApp({ store, rules, today = () => new Date().toLocaleDateString('en-CA'), token = randomBytes(24).toString('hex') }) {
  const page = readFile(join(here, 'public', 'index.html'), 'utf8');
  const saves = new Map(); // commit -> { employeeId, kind, at }

  async function load() {
    const { text, version } = await store.read();
    const roster = parseRoster(text);
    return { roster, version, catalogue: jobCatalogue(rules, roster.workers) };
  }

  // Saves run one at a time in this process (a queue), so two clicks can
  // never read the same roster and overwrite each other. Across processes
  // the store's own version check catches it (GitHub: the blob sha).
  let queue = Promise.resolve();
  function save(apply) {
    const run = queue.then(() => saveNow(apply));
    queue = run.catch(() => {});
    return run;
  }

  // Apply one HR action and save it; on a write conflict re-read and re-apply once.
  async function saveNow(apply) {
    for (let attempt = 0; attempt < 2; attempt++) {
      const { roster, version, catalogue } = await load();
      const result = apply(roster, catalogue);
      try {
        const c = await store.write(serialiseRoster(result.roster), version, describe(result));
        saves.set(c.commit, { employeeId: result.worker.employeeId, kind: result.kind, at: c.at });
        return { ...result, commit: c.commit, savedAt: c.at };
      } catch (e) { if (!e.conflict || attempt) throw e; }
    }
  }

  async function body(req) {
    let raw = '';
    for await (const chunk of req) { raw += chunk; if (raw.length > 16384) throw new HrError('Request too large.', 413); }
    try { return JSON.parse(raw || '{}'); } catch { throw new HrError('Not JSON.'); }
  }

  function send(res, status, obj, type = 'application/json') {
    const data = type === 'application/json' ? JSON.stringify(obj) : obj;
    res.writeHead(status, {
      'Content-Type': `${type}; charset=utf-8`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    });
    res.end(data);
  }

  // DNS rebinding guard: a foreign page that points its own hostname at
  // 127.0.0.1 still sends its own name in Host (and Origin). Only this
  // machine's loopback names are served; the form token stays unreadable.
  const LOCAL = /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/;
  function localOnly(req) {
    if (!LOCAL.test(req.headers.host ?? '')) throw new HrError('Not found.', 404);
    const origin = req.headers.origin;
    if (origin && origin !== 'null' && !LOCAL.test(origin.replace(/^https?:\/\//, ''))) throw new HrError('Not allowed from another site.', 403);
  }

  return async function handle(req, res) {
    try {
      localOnly(req);
      const url = new URL(req.url, 'http://127.0.0.1');
      if (req.method === 'GET' && url.pathname === '/') {
        return send(res, 200, (await page).replace('__FORM_TOKEN__', token).replace('__TODAY__', today()), 'text/html');
      }
      if (req.method === 'GET' && url.pathname === '/api/workers') {
        const { roster, catalogue } = await load();
        return send(res, 200, { workers: roster.workers.map(publicWorker), jobs: catalogue, today: today() });
      }
      const m = url.pathname.match(/^\/api\/delivery\/([\w-]{1,64})$/);
      if (req.method === 'GET' && m) {
        if (!saves.has(m[1])) throw new HrError('Unknown save.', 404);
        return send(res, 200, { ...saves.get(m[1]), ...(await store.delivery(m[1])) });
      }
      if (req.method === 'POST') {
        if (req.headers['x-form-token'] !== token) throw new HrError('This form has expired. Reload the page.', 403);
        if (!/^application\/json/.test(req.headers['content-type'] ?? '')) throw new HrError('Expected JSON.', 415);
        const input = await body(req);
        if (url.pathname === '/api/workers') {
          const r = await save((roster, cat) => hire(roster, input, cat));
          return send(res, 201, { worker: publicWorker(r.worker), kind: r.kind, commit: r.commit, savedAt: r.savedAt });
        }
        const w = url.pathname.match(/^\/api\/workers\/(\d{6})$/);
        if (w) {
          const r = await save((roster, cat) => change(roster, w[1], input, cat, today()));
          return send(res, 200, { worker: publicWorker(r.worker), kind: r.kind, commit: r.commit, savedAt: r.savedAt });
        }
      }
      throw new HrError('Not found.', 404);
    } catch (e) {
      const status = e instanceof HrError ? e.status : 500;
      // Unexpected errors: a generic line to the page, the detail to this terminal only.
      if (status === 500) console.error(e.stderr || e.message);
      send(res, status, { error: status === 500 ? 'The HR system could not save. Nothing was sent.' : e.message });
    }
  };
}

async function main() {
  const args = process.argv.slice(2);
  const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
  const storeArg = opt('--store', 'github:ChromeData/contoso-health-identity-lab@hr-feed');
  const port = Number(opt('--port', '8484'));
  let store;
  if (storeArg.startsWith('file:')) store = new FileStore({ file: storeArg.slice(5) });
  else {
    const [, repo, branch] = storeArg.match(/^github:([\w.-]+\/[\w.-]+)@([\w./-]+)$/) ?? [];
    if (!repo) throw new Error('--store must be github:OWNER/REPO@BRANCH or file:PATH');
    store = new GitHubStore({ repo, branch });
  }
  const rules = JSON.parse(await readFile(RULES, 'utf8'));
  createServer(makeApp({ store, rules })).listen(port, '127.0.0.1', () => {
    console.log(`Contoso HR: http://127.0.0.1:${port}  (roster: ${storeArg}${storeArg.startsWith('file:') ? ', rehearsal, sends nothing' : ', saves are sent to Microsoft'})`);
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
