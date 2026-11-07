// =============================================================================
// store.mjs - the connector's outbox (the feed file), and how it hears back.
// -----------------------------------------------------------------------------
// GitHubStore (the lab): the feed file on the hr-feed branch, read and
// written through the GitHub contents API with the `gh` CLI. Each sync that
// changes a worker is one commit. That commit is the outbound integration
// event: hr-feed.yml runs on it, signs in as HR-SYNC over GitHub OIDC (no
// secret) and sends only the changed workers to Entra's API-driven inbound
// provisioning API (bulkUpload). Why this route and not a direct call with
// a stored secret: ADR 0028, "Decision 3".
//
// Optimistic concurrency: the write carries the file's blob sha, so a write
// made on an old read cannot overwrite a newer file (GitHub answers 409; the
// connector re-reads on its next cycle).
//
// No token passes through this process's argv or environment: `gh` uses
// its own stored sign-in. The request body goes over stdin.
//
// FileStore: a local file, for tests and an offline rehearsal. It sends
// nothing anywhere.
// =============================================================================
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const digest = (t) => createHash('sha256').update(t).digest('hex');

export const ROSTER_PATH = 'lab/scripts/mock-hr/hr_feed.csv';

function gh(args, input) {
  return new Promise((resolve, reject) => {
    const child = execFile('gh', args, { maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) { err.stderr = String(stderr); return reject(err); }
      resolve(String(stdout));
    });
    if (input !== undefined) child.stdin.end(input); else child.stdin.end();
  });
}

export class GitHubStore {
  constructor({ repo, branch = 'hr-feed', path = ROSTER_PATH, run = gh, trailer = 'Entered in OrangeHRM; written by the HR connector (lab/hris/connector).' }) {
    Object.assign(this, { repo, branch, path, run, trailer });
  }

  async read() {
    const out = await this.run(['api', `repos/${this.repo}/contents/${this.path}?ref=${encodeURIComponent(this.branch)}`]);
    const j = JSON.parse(out);
    return { text: Buffer.from(j.content, 'base64').toString('utf8'), version: j.sha };
  }

  async write(text, version, message) {
    const body = JSON.stringify({
      message: `${message}\n\n${this.trailer}`,
      content: Buffer.from(text, 'utf8').toString('base64'),
      sha: version,
      branch: this.branch,
    });
    try {
      const out = await this.run(['api', '-X', 'PUT', `repos/${this.repo}/contents/${this.path}`, '--input', '-'], body);
      const j = JSON.parse(out);
      return { commit: j.commit.sha, at: j.commit.committer?.date ?? new Date().toISOString() };
    } catch (e) {
      if (/HTTP 409|HTTP 422.*sha|does not match/i.test(e.stderr ?? '')) { const c = new Error('conflict'); c.conflict = true; throw c; }
      throw e;
    }
  }

  // The delivery status of one outbox commit: the hr-feed run on that
  // commit (push runs only: a manual dry run on the same commit sends
  // nothing and must never read as delivered).
  async delivery(commit) {
    const out = await this.run(['api', `repos/${this.repo}/actions/workflows/hr-feed.yml/runs?head_sha=${commit}&event=push&per_page=1`]);
    const r = JSON.parse(out).workflow_runs?.[0];
    if (!r) return { state: 'queued' };
    if (r.status !== 'completed') return { state: 'sending', run: r.html_url };
    // A green run means Microsoft accepted the change (202) and logged no
    // failure while the run waited. It does NOT mean Microsoft confirmed it:
    // Write-HrFeedSummary.ps1 stays green when the provisioning log is not
    // readable or has no entry yet. So the state is 'accepted', never
    // 'delivered'; the confirmation is IT's to read in the provisioning log.
    return { state: r.conclusion === 'success' ? 'accepted' : 'failed', run: r.html_url, finishedAt: r.updated_at };
  }
}

export class FileStore {
  constructor({ file }) { this.file = file; this.commits = 0; }
  async read() { const text = await readFile(this.file, 'utf8'); return { text, version: digest(text) }; }
  async write(text, version) {
    const cur = await readFile(this.file, 'utf8');
    if (digest(cur) !== version) { const c = new Error('conflict'); c.conflict = true; throw c; }
    await writeFile(this.file, text);
    this.commits += 1;
    return { commit: `local-${this.commits}`, at: new Date().toISOString() };
  }
  async delivery() { return { state: 'local', note: 'Rehearsal store: nothing is sent.' }; }
}
