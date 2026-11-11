// Rehearsal mode: piece 1 for real, on a throwaway branch, never merged.
//
// A separate git worktree (~/contoso-demo/cockpit/rehearsal/blueprints) gets
// the same commit as the live "1 · The blueprints" folder plus a copy of its
// two uncommitted files, so the live folder (the real on-camera change) is
// never touched. A separate workspace file opens it in its own VS Code window
// with the demo window's settings. The PR is closed without merging and the
// remote branch deleted at the end; old rehearsal worktrees and branches are
// cleaned up at the start of the next rehearsal.
import fs from 'node:fs';
import path from 'node:path';
import { sh, gh, REPO, LAB } from './live.mjs';

const git = (args, cwd = LAB) => sh('git', ['-C', cwd, ...args]);

// kind 'rehearsal' (piece 1 only) or 'preview' (the whole demo, --preview:
// its workspace also holds the real HR folder, the preview pushes Sam's rows
// to hr-feed for real and its teardown puts them back).
export async function prepareRehearsal({ root, liveFolder, liveWs, log = console.log, kind = 'rehearsal', hrFolder = null }) {
  const rdir = path.join(root, kind);
  const dir = path.join(rdir, 'blueprints');
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '-');
  const branch = `${kind}/cockpit-${stamp}`;

  // Clean up the previous rehearsal (only things this module made).
  if (fs.existsSync(dir)) {
    await git(['worktree', 'remove', '--force', dir]).catch(() => fs.rmSync(dir, { recursive: true, force: true }));
  }
  await git(['worktree', 'prune']);
  const old = (await git(['branch', '--list', `${kind}/cockpit-*`, '--format=%(refname:short)'])).split('\n').filter(Boolean);
  for (const b of old) await git(['branch', '-D', b]).catch(() => {});

  const base = (await git(['rev-parse', 'HEAD'], liveFolder)).trim();
  const changed = (await git(['diff', '--name-only'], liveFolder)).split('\n').filter(Boolean);
  if (!changed.length) throw new Error(`the live folder ${liveFolder} has no uncommitted change to rehearse`);
  fs.mkdirSync(rdir, { recursive: true });
  await git(['worktree', 'add', '-b', branch, dir, base]);
  for (const f of changed) fs.copyFileSync(path.join(liveFolder, f), path.join(dir, f));

  // Same settings as the demo window, one folder: the rehearsal copy.
  const hrEntry = hrFolder ? `,\n    { "name": "2 · HR's list (hire and leave)", "path": ${JSON.stringify(hrFolder)} }` : '';
  const wsText = fs.readFileSync(liveWs, 'utf8').replace(/"folders"\s*:\s*\[[\s\S]*?\]\s*,/, `"folders": [\n    { "name": "1 · The blueprints (the AWS fix)", "path": "blueprints" }${hrEntry}\n  ],`);
  // A new workspace file (so a new VS Code window) per rehearsal: a window
  // whose extension host has given up (VS Code stops restarting it after 3
  // crashes) can't be revived from outside, but a fresh window always works.
  for (const f of fs.readdirSync(rdir)) if (/^contoso-demo-(rehearsal|preview).*\.code-workspace$/.test(f)) fs.rmSync(path.join(rdir, f), { force: true });
  const ws = path.join(rdir, `contoso-demo-${kind}-${stamp}.code-workspace`);
  fs.writeFileSync(ws, wsText);
  log(`rehearsal: worktree ${dir} on ${branch} (from ${base.slice(0, 7)}, ${changed.length} changed files copied)`);
  return { dir, branch, ws, base, changed };
}

// Close the PR without merging, delete the remote branch. Never merges.
export async function closeRehearsal({ branch, pr, log = console.log }) {
  if (!/^(rehearsal|preview)\/cockpit-/.test(branch)) throw new Error(`not a rehearsal or preview branch: ${branch}`);
  if (pr?.number) {
    const st = JSON.parse(await gh(['pr', 'view', String(pr.number), '-R', REPO, '--json', 'state,headRefName']));
    if (st.headRefName !== branch) throw new Error(`PR #${pr.number} is not the rehearsal PR`);
    if (st.state === 'OPEN') await gh(['pr', 'close', String(pr.number), '-R', REPO, '--comment', 'Cockpit rehearsal finished: closed without merging. Nothing was applied.']);
    log(`rehearsal: PR #${pr.number} closed without merging`);
  }
  await sh('git', ['-C', LAB, 'push', 'origin', '--delete', branch]).then(() => log(`rehearsal: remote branch ${branch} deleted`)).catch((e) => log(`rehearsal: remote branch delete: ${e.message}`));
}
