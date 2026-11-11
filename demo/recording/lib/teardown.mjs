// After a --preview: put the lab back exactly as it was, so the owner's real
// take starts from today's state.
//   1. The AWS change the preview merged and applied is reverted through a
//      REVIEWED revert PR: opened and labelled ready-for-merge. The merge
//      captain merges it and approves its apply; the cockpit never does.
//   2. Sam: reset-demo-hire.sh 400104 --apply, then (once Cloud Sync has
//      removed him from Entra, ~20 min) --apply --purge-entra --skip-git --skip-ad.
//   3. containment-drill.sh disarm (the drill user, rule and incident).
//   4. close-build-noise.sh as a DRY RUN: lists what the preview raised, closes nothing.
//   5. The HR folder back in step with origin/hr-feed; the preview's copy of
//      the blueprints folder and its branch removed. ~/contoso-demo/blueprints
//      (the owner's two uncommitted files) is never touched.
// Scripts run from a detached worktree at origin/main (.lab-main), so they
// are always the merged versions, whatever the main checkout has.
import fs from 'node:fs';
import path from 'node:path';
import * as L from './live.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Before the REVERT PR of a preview (merge captain's spec, 2026-11-05): the
// on-camera apply's access-rules step created an AUTOMATIC assignment policy
// on the new package (not in Terraform state; Set-AutoAssignmentPolicies.ps1
// never removes it), and it assigned the test hire. Graph refuses to delete a
// policy that still has grants (400 InvalidDeletePolicyHasGrants) and a
// package with assignments, so a plain revert apply fails. In order:
//   0. read the package's policies + assignments: only automatic policies and
//      only the preview's test hire(s) may be there, anything else stops it;
//   1. switch each automatic policy off (PUT with
//      requestAccessForAllowedTargets=false, body built like
//      Set-AutoAssignmentPolicies.ps1 Merge-AutoPolicyBody) and read it back:
//      only that flag may have changed;
//   2. adminRemove every delivered assignment (expect submitted/Accepted);
//   3. poll until 0 assignments not expired, on 2 reads in a row;
//   4. DELETE the policy (then NotFound, 0 policies left);
//   5. only then may the revert PR open.
// Graph calls are injected (tests/teardown.test.mjs runs it on a fake).
const DROP = ['id', 'createdDateTime', 'modifiedDateTime', 'catalog', 'customExtensionStageSettings', 'accessPackage'];
export function policyPutBody(policy, pkgId) {
  const b = {};
  for (const [k, v] of Object.entries(policy)) if (!DROP.includes(k) && !k.startsWith('@odata')) b[k] = v;
  b.accessPackage = { id: pkgId };
  b.automaticRequestSettings = { ...(policy.automaticRequestSettings || {}), requestAccessForAllowedTargets: false };
  return b;
}
export async function clearAutoAssignment({ pkgName, hires = ['sam.rivera@contosohealthlab.com', 'Sam Rivera'], get, put, post, del, resolveDeleted = null, wait = sleep, log = console.log, note = () => {}, timeoutMs = 20 * 60000, pollMs = 30000 }) {
  const pk = await get(`identityGovernance/entitlementManagement/accessPackages?$filter=displayName eq '${pkgName}'&$select=id,displayName`);
  if (!pk || !Array.isArray(pk.value)) throw new Error(`could not read access package ${pkgName}`);
  if (!pk.value.length) return 'package not there: nothing to clear';
  if (pk.value.length > 1) throw new Error(`more than one access package named ${pkgName}`);
  const id = pk.value[0].id;
  // 0. what is there
  const pols = await get(`identityGovernance/entitlementManagement/assignmentPolicies?$filter=accessPackage/id eq '${id}'&$expand=accessPackage`);
  if (!pols || !Array.isArray(pols.value)) throw new Error('could not read the assignment policies');
  const auto = pols.value.filter((p) => p.automaticRequestSettings);
  const other = pols.value.filter((p) => !p.automaticRequestSettings);
  if (other.length) throw new Error(`stopped: ${pkgName} has non-automatic policies (${other.map((p) => p.displayName).join(', ')}): not the preview's alone`);
  const readAssignments = async () => {
    const a = await get(`identityGovernance/entitlementManagement/assignments?$filter=accessPackage/id eq '${id}'&$expand=target`);
    if (!a || !Array.isArray(a.value)) throw new Error('could not read the package assignments');
    return a.value;
  };
  const first = await readAssignments();
  // A target that names someone is checked by name. A hard-deleted user
  // keeps a delivered assignment with an EMPTY target, and a deleted object
  // could be anyone (the owner too): it is resolved by object id through
  // Entra's deleted items or the directory audit log (merge captain,
  // 2026-11-05), and only the test hire passes. Unresolvable = stop.
  const named = (t) => t && (t.principalName || t.displayName || t.email);
  const isHireName = (vals) => vals.filter(Boolean).map((v) => v.toLowerCase().replace(/^[0-9a-f]{32}/, '')).some((v) => hires.some((h) => v === h.toLowerCase()));
  const stranger = [];
  for (const x of first) {
    if (named(x.target)) { if (!isHireName([x.target.principalName, x.target.displayName, x.target.email])) stranger.push(x.target.displayName || x.target.principalName); continue; }
    const oid = x.target?.objectId || x.targetId;
    const upn = oid && resolveDeleted ? await resolveDeleted(oid).catch(() => null) : null;
    if (!upn || !isHireName([upn])) stranger.push(upn || `unresolved deleted object ${oid || '(no id)'}`);
  }
  if (stranger.length) throw new Error(`stopped: ${pkgName} is assigned to someone who is not the preview's test hire (${stranger.join(', ')})`);
  note(`step 0: ${auto.length} automatic polic${auto.length === 1 ? 'y' : 'ies'}, ${first.length} assignment(s), all the preview's`);
  // 1. switch the automatic policies off, read back
  for (const p of auto) {
    const full = await get(`identityGovernance/entitlementManagement/assignmentPolicies/${p.id}`);
    if (!full || full.id !== p.id) throw new Error(`could not read policy ${p.id}`);
    const body = policyPutBody(full, id);
    await put(`identityGovernance/entitlementManagement/assignmentPolicies/${p.id}`, body);
    const back = await get(`identityGovernance/entitlementManagement/assignmentPolicies/${p.id}`);
    if (!back || back.automaticRequestSettings?.requestAccessForAllowedTargets !== false) throw new Error(`policy ${p.id}: automatic assignment still on after the update`);
    for (const k of Object.keys(body)) if (!['automaticRequestSettings', 'accessPackage'].includes(k) && JSON.stringify(back[k]) !== JSON.stringify(full[k])) throw new Error(`policy ${p.id}: ${k} changed too (only the automatic flag may)`);
    note(`step 1: policy "${p.displayName}" switched off (read back)`);
  }
  // 2. remove what is delivered
  for (const x of first.filter((x) => x.state === 'delivered')) {
    const r = await post('identityGovernance/entitlementManagement/assignmentRequests', { requestType: 'adminRemove', assignment: { id: x.id } });
    if (r && r.state && !/submitted|accepted/i.test(`${r.state} ${r.status || ''}`)) throw new Error(`adminRemove ${x.id}: ${r.state}/${r.status}`);
    note(`step 2: adminRemove ${x.id} (${x.target?.displayName || 'deleted user'})`);
  }
  // 3. until 0 (not expired) twice in a row
  const end = Date.now() + timeoutMs;
  let zeros = 0;
  for (;;) {
    const live = (await readAssignments()).filter((x) => x.state !== 'expired' && x.state !== 'deleted');
    zeros = live.length ? 0 : zeros + 1;
    if (zeros >= 2) break;
    if (Date.now() > end) throw new Error(`${live.length} assignment(s) still on ${pkgName} after ${Math.round(timeoutMs / 60000)} min`);
    await wait(pollMs);
  }
  note('step 3: 0 assignments on two reads in a row');
  // 4. delete the policies, then check they are gone
  for (const p of auto) {
    await del(`identityGovernance/entitlementManagement/assignmentPolicies/${p.id}`);
    const gone = await get(`identityGovernance/entitlementManagement/assignmentPolicies/${p.id}`).catch((e) => (/NotFound|404/.test(String(e.message)) ? null : Promise.reject(e)));
    if (gone && gone.id) throw new Error(`policy ${p.id} still there after DELETE`);
  }
  const after = await get(`identityGovernance/entitlementManagement/assignmentPolicies?$filter=accessPackage/id eq '${id}'&$expand=accessPackage`);
  if (!after || !Array.isArray(after.value) || after.value.length) throw new Error('policies still on the package after the delete');
  note(`step 4: ${auto.length} automatic polic${auto.length === 1 ? 'y' : 'ies'} deleted, 0 left on the package`);
  return `${auto.length} automatic polic${auto.length === 1 ? 'y' : 'ies'} switched off and deleted; 0 assignments left`;
}

export async function labMain(root) {
  const dir = path.join(root, '.lab-main');
  await L.sh('git', ['-C', L.LAB, 'fetch', '-q', 'origin', '+refs/heads/main:refs/remotes/origin/main']);
  if (!fs.existsSync(path.join(dir, '.git'))) await L.sh('git', ['-C', L.LAB, 'worktree', 'add', '-q', '--detach', dir, 'origin/main']);
  else await L.sh('git', ['-C', dir, 'checkout', '-q', '--detach', 'origin/main']);
  return dir;
}

async function script(dir, rel, args, log, timeout = 900000) {
  const f = path.join(dir, rel);
  if (!fs.existsSync(f)) throw new Error(`${rel} is not on main yet`);
  // Through the lab operator wrapper: the scripts' own az calls (the DC01
  // run command, the Entra purge) must run as the operator, not as whatever
  // `az login` this Mac has (found 2026-11-05: step 2 failed without it).
  const out = await L.sh(path.join(dir, 'lab/scripts/operator/op'), [f, ...args], { cwd: dir, timeout });
  for (const line of out.trim().split('\n').slice(-12)) log(`  ${line}`);
  return out;
}

// The revert PR for the preview's merge commit (squash merge = one commit).
export async function openRevertPr({ root, mergeSha, pr, dry, log }) {
  if (!mergeSha) { log('teardown: nothing merged by the preview: no revert needed'); return null; }
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '-');
  const branch = `preview/revert-${stamp}`;
  if (dry) { log(`teardown: WOULD open a revert PR for ${mergeSha.slice(0, 7)} on ${branch} and label it ready-for-merge`); return null; }
  // The package must be deletable before the revert exists (captain's spec).
  const progress = path.join(path.dirname(path.dirname(root)), 'contoso-demo', 'readiness', 'progress.log');
  const noteP = (m) => { log(`teardown: auto policy ${m}`); try { fs.appendFileSync(path.join(process.env.HOME, 'contoso-demo', 'readiness', 'progress.log'), `${new Date().toISOString().replace(/\.\d+Z$/, 'Z')} | cockpit | preview reset | IT - Cloud Engineering Apps auto policy ${m} | cockpit teardown\n`); } catch {} };
  void progress;
  const resolveDeleted = async (oid) => {
    const soft = await L.graph(`directory/deletedItems/${oid}`).catch(() => null);
    if (soft?.userPrincipalName) return soft.userPrincipalName;
    const aud = await L.graph(`auditLogs/directoryAudits?$filter=targetResources/any(t:t/id eq '${oid}')&$top=20`);
    const del = (aud.value || []).find((e) => /Delete user/i.test(e.activityDisplayName || ''));
    return del?.targetResources?.find((t) => t.id === oid)?.userPrincipalName || null;
  };
  log(`teardown: ${await clearAutoAssignment({ pkgName: 'IT - Cloud Engineering Apps', get: L.graph, put: L.graphPut, post: L.graphPostPublic, del: L.graphDelete, resolveDeleted, log, note: noteP })}`);
  const dir = path.join(root, 'preview', 'revert');
  if (fs.existsSync(dir)) await L.sh('git', ['-C', L.LAB, 'worktree', 'remove', '--force', dir]).catch(() => fs.rmSync(dir, { recursive: true, force: true }));
  await L.sh('git', ['-C', L.LAB, 'worktree', 'prune']);
  await L.sh('git', ['-C', L.LAB, 'worktree', 'add', '-q', '-b', branch, dir, 'origin/main']);
  const title = `Revert recording preview: cloud engineers get AWS (#${pr})`;
  const msg = `${title}\n\nThe owner's recording preview merged and applied #${pr} for real. This puts the\nlab back to the state before the preview, so the real take starts from today's\nstate (AWS back on Nurse - Clinical Apps, no IT - Cloud Engineering Apps).\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
  await L.sh('git', ['-C', dir, 'revert', '--no-edit', mergeSha]);
  await L.sh('git', ['-C', dir, 'commit', '--amend', '-m', msg]);
  await L.sh('git', ['-C', dir, 'push', '-q', '-u', 'origin', branch]);
  const body = [
    `Reverts #${pr}, which the recording cockpit's **preview** run merged and applied for real (the preview shows the owner exactly how the live take will look).`,
    '', '**Merging this** removes the access package *IT - Cloud Engineering Apps* and puts AWS back on *Nurse - Clinical Apps*: the lab returns to the state the real take starts from. Its apply changes the tenant (the reverse of #' + pr + "'s apply).",
    '', 'Opened by the cockpit after the preview; for the merge captain to merge and approve the apply gate.',
    '', '🤖 Generated with [Claude Code](https://claude.com/claude-code)'].join('\n');
  const url = (await L.gh(['pr', 'create', '-R', L.REPO, '--base', 'main', '--head', branch, '--title', title, '--body', body])).trim();
  await L.gh(['label', 'create', 'ready-for-merge', '-R', L.REPO, '--color', '0E8A16']).catch(() => {});
  await L.gh(['pr', 'edit', url, '-R', L.REPO, '--add-label', 'ready-for-merge']);
  log(`teardown: revert PR ${url} opened and labelled ready-for-merge (the merge captain merges it and approves its apply)`);
  return url;
}

// snowContext: a browser context with the recovery account's ServiceNow
// session (the cockpit's recording browser); without one, the recording
// profile is opened here (the cockpit must not be running).
export async function previewReset({ root, c, dry, log = console.log, waitForSync = true, snowContext = null }) {
  const report = [];
  const step = async (name, fn) => {
    log(`teardown: ${name}`);
    try { const r = await fn(); report.push({ name, ok: true, note: r || '' }); }
    catch (e) { log(`teardown: ${name} FAILED: ${e.message}`); report.push({ name, ok: false, note: e.message }); }
  };
  const main = await labMain(root);
  await step('revert PR for the AWS change', () => openRevertPr({ root, mergeSha: c.mergeSha, pr: c.pr?.number, dry, log }));
  await step('reset Sam (HR file + on-site account)', () => script(main, 'lab/scripts/demo/reset-demo-hire.sh', ['400104', ...(dry ? [] : ['--apply'])], log));
  if (!dry && waitForSync) {
    await step('wait for Cloud Sync to remove Sam from Entra, then purge him', async () => {
      const end = Date.now() + 75 * 60000;
      while (Date.now() < end) { if (!(await L.samUser())) break; await sleep(60000); }
      if (await L.samUser()) throw new Error('Sam is still in Entra after 75 minutes: run reset-demo-hire.sh 400104 --apply --purge-entra --skip-git --skip-ad later');
      return script(main, 'lab/scripts/demo/reset-demo-hire.sh', ['400104', '--apply', '--purge-entra', '--skip-git', '--skip-ad'], log);
    });
  } else if (dry) log('teardown: WOULD wait for Cloud Sync, then run reset-demo-hire.sh 400104 --apply --purge-entra --skip-git --skip-ad');
  // As the ServiceNow admin (the recovery account can't see inactive users;
  // the leaver has just made Sam inactive): exact user_name, read back.
  await step("delete Sam's ServiceNow record (Entra's leaver only switches it off)", async () => {
    const { deleteProvisionedUserAsAdmin } = await import('./snow.mjs');
    return deleteProvisionedUserAsAdmin('sam.rivera@contosohealthlab.com', { dry, log });
  });
  await step(dry ? 'containment drill status (dry: disarm would run here)' : 'disarm the containment drill', () => script(main, 'lab/scripts/demo/containment-drill.sh', [dry ? 'status' : 'disarm'], log));
  // Read-only, but many Azure reads: one retry after a throttled minute.
  await step('build noise (dry run: list only)', () => script(main, 'lab/scripts/demo/close-build-noise.sh', [], log)
    .catch(async (e) => { if (!/Too Many Requests|429/i.test(e.message)) throw e; log('teardown: Azure throttled the noise list; trying again in 60 s'); await sleep(60000); return script(main, 'lab/scripts/demo/close-build-noise.sh', [], log); }));
  await step('HR folder back in step with origin/hr-feed', async () => {
    const hr = c.hr;
    await L.sh('git', ['-C', hr, 'fetch', '-q', 'origin', 'hr-feed']);
    if (dry) return 'dry run: unchanged';
    const mine = (await L.sh('git', ['-C', hr, 'log', '--format=%s', 'origin/hr-feed..HEAD'])).trim().split('\n').filter(Boolean);
    if (!mine.every((m) => /^HR: (hire Sam Rivera|Sam Rivera leaves)/.test(m))) throw new Error('the HR folder has commits that are not the preview\'s: fix by hand');
    const dirty = (await L.sh('git', ['-C', hr, 'status', '--porcelain'])).trim();
    if (dirty && !/^ ?M lab\/scripts\/mock-hr\/hr_feed\.csv$/.test(dirty)) throw new Error(`the HR folder has other local changes: ${dirty}`);
    await L.sh('git', ['-C', hr, 'reset', '-q', '--hard', 'origin/hr-feed']);
    return 'at origin/hr-feed';
  });
  await step('remove the preview copy of the blueprints', async () => {
    if (dry || !c.previewDir) return 'dry run: kept';
    await L.sh('git', ['-C', L.LAB, 'worktree', 'remove', '--force', c.previewDir]).catch(() => {});
    await L.sh('git', ['-C', L.LAB, 'branch', '-D', c.bpBranch]).catch(() => {});
    await L.sh('git', ['-C', L.LAB, 'push', '-q', 'origin', '--delete', c.bpBranch]).catch(() => {});
    return 'removed';
  });
  return report;
}

// ---- v2 (2026-11-07) ----------------------------------------------------------
// Read-only checkouts of the open PRs the v2 screens come from, detached at
// each PR branch's tip (cockpit/.v2/<name>). Nothing is ever committed here.
// Merged branches are read from main (the fetch of a deleted branch fails
// and the copy falls back to main).
const V2_BRANCHES = { hr: 'feat/hr-form-inbound', ad: 'harden/ad-tiering', okta: 'feat/okta-depth',
  pam: 'feat/microsoft-native-pam', k8skv: 'feat/k8s-keyvault', kvleak: 'feat/keyvault-state-leak', bastion: 'feat/bastion-session-recording',
  adfs: 'adfs/dc01-run-and-connect-health', cicd: 'feat/pipeline-secrets-keyvault', azlp: 'feat/azure-least-privilege', ssm: 'main', snow: 'feat/servicenow-depth' };
export async function v2Worktrees(root, log = console.log) {
  const base = path.join(root, '.v2'), out = { ws: path.join(root, 'v2', 'contoso-demo-v2.code-workspace') };
  fs.mkdirSync(base, { recursive: true });
  for (const [k, br] of Object.entries(V2_BRANCHES)) {
    const dir = path.join(base, k);
    try {
      await L.sh('git', ['-C', L.LAB, 'fetch', '-q', 'origin', `+refs/heads/${br}:refs/remotes/origin/${br}`]);
      if (!fs.existsSync(path.join(dir, '.git'))) await L.sh('git', ['-C', L.LAB, 'worktree', 'add', '-q', '--detach', dir, `origin/${br}`]);
      else await L.sh('git', ['-C', dir, 'checkout', '-q', '--detach', `origin/${br}`]);
    } catch (e) {
      // Merged and deleted: main has it now.
      log(`v2: ${br}: ${e.message.split('\n')[0]}; using main`);
      out[k] = await labMain(root); continue;
    }
    out[k] = dir;
  }
  return out;
}

// --v2 --preview's test hire, removed the way readiness/hr-flow.md and E123
// did it, each place read back:
//   1. reset-demo-hire.sh <id> --apply (as the operator): the hr-feed row and
//      the AD account go;
//   2. Cloud Sync deletes the Entra user (minutes), then --purge-entra
//      empties Deleted users;
//   3. the ServiceNow record is deleted as the ServiceNow admin (exact user
//      name, created by Entra provisioning only);
//   4. AWS removes its user on the next SCIM cycle (up to 40 minutes);
//   5. read back: Entra 0, Deleted users 0, AWS 0, hr-feed rows 0, ServiceNow 0.
// Only a test worker (Test ...) can be removed this way.
export async function hireReset({ root, id, upn, name, dry, log = console.log }) {
  const report = [];
  const step = async (n, fn) => { log(`teardown: ${n}`); try { const r = await fn(); report.push({ name: n, ok: true, note: r || '' }); } catch (e) { log(`teardown: ${n} FAILED: ${e.message}`); report.push({ name: n, ok: false, note: e.message }); } };
  // 2026-11-07: previews hire Sam Rivera himself (400104) through OrangeHRM;
  // exactly that worker may be removed too.
  const sam = id === '400104' && name === 'Sam Rivera' && upn === 'sam.rivera@contosohealthlab.com';
  if (!sam && (!/^\d{6}$/.test(id) || !/^Test /.test(name) || !/^test\.[a-z]+@contosohealthlab\.com$/.test(upn))) throw new Error(`refusing to remove ${name} (${id}, ${upn}): only a preview's test hire`);
  const main = await labMain(root);
  await step(`remove ${name} (${id}) from hr-feed and AD`, () => script(main, 'lab/scripts/demo/reset-demo-hire.sh', [id, ...(dry ? [] : ['--apply'])], log));
  if (dry) return report;
  await step(`wait for Cloud Sync to delete ${name} in Entra, then purge Deleted users`, async () => {
    const end = Date.now() + 75 * 60000;
    while (Date.now() < end && (await L.samUser(id))) await sleep(60000);
    if (await L.samUser(id)) throw new Error(`still in Entra after 75 minutes: run reset-demo-hire.sh ${id} --apply --purge-entra --skip-git --skip-ad later`);
    return script(main, 'lab/scripts/demo/reset-demo-hire.sh', [id, '--apply', '--purge-entra', '--skip-git', '--skip-ad'], log);
  });
  await step(`delete ${upn} in ServiceNow (as the admin)`, async () => { const { deleteProvisionedUserAsAdmin } = await import('./snow.mjs'); return deleteProvisionedUserAsAdmin(upn, { log }); });
  await step(`wait for AWS to remove ${upn} (next SCIM cycle)`, async () => {
    const end = Date.now() + 60 * 60000;
    while (Date.now() < end && (await L.awsUser(upn))) await sleep(120000);
    if (await L.awsUser(upn)) throw new Error('still in AWS after 60 minutes: AWS removes it on a later SCIM cycle; read it back then');
    return 'gone from AWS';
  });
  await step('read back every place', async () => {
    const entra = (await L.graph(`users?$filter=employeeId eq '${id}'&$select=id`)).value.length;
    // A deleted user's UPN carries its object id in front: match the local part.
    const deleted = (await L.graph('directory/deletedItems/microsoft.graph.user?$select=id,userPrincipalName&$top=999')).value.filter((u) => (u.userPrincipalName || '').toLowerCase().includes(upn.split('@')[0])).length;
    const aws = (await L.awsUser(upn)) ? 1 : 0;
    const csv = (await L.sh('git', ['-C', L.LAB, 'show', 'origin/hr-feed:lab/scripts/mock-hr/hr_feed.csv']).catch(async () => { await L.sh('git', ['-C', L.LAB, 'fetch', '-q', 'origin', 'hr-feed']); return L.sh('git', ['-C', L.LAB, 'show', 'origin/hr-feed:lab/scripts/mock-hr/hr_feed.csv']); }));
    await L.sh('git', ['-C', L.LAB, 'fetch', '-q', 'origin', '+refs/heads/hr-feed:refs/remotes/origin/hr-feed']).catch(() => {});
    const rows = (await L.sh('git', ['-C', L.LAB, 'show', 'origin/hr-feed:lab/scripts/mock-hr/hr_feed.csv'])).split('\n').filter((l) => l.startsWith(`${id},`)).length;
    void csv;
    const { deleteProvisionedUserAsAdmin } = await import('./snow.mjs');
    const snow = await deleteProvisionedUserAsAdmin(upn, { dry: true, log });
    const line = `Entra users with employeeId ${id}: ${entra}; Deleted users ${upn}: ${deleted}; AWS: ${aws}; hr-feed rows ${id}: ${rows}; ServiceNow: ${snow}`;
    if (entra || deleted || aws || rows || !/^no ServiceNow user/.test(snow)) throw new Error(`not clean: ${line}`);
    return line;
  });
  return report;
}
