// Live-state reads for the WAIT lights and for finding things to open (the
// PR, the apply run, the approval issue, Sam's object id...). READ-ONLY:
//   - GitHub through `gh` (already signed in on this Mac)
//   - Microsoft Graph and AWS through the lab operator wrapper
//     (~/contoso-health-identity-lab/lab/scripts/operator/op), GET only.
// Fail closed: a read that fails throws (the light goes red with the reason);
// "not there yet" is a normal answer (the light stays yellow). The two are
// never mixed up.
import { execFile } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

export const REPO = 'ChromeData/contoso-health-identity-lab';
export const LAB = path.join(os.homedir(), 'contoso-health-identity-lab');
const OP = `${LAB}/lab/scripts/operator/op`;
export const AWS_ACCOUNT = '182002546409';
export const IDSTORE = 'd-90666212c7';
export const HR_SP = '876b6339-1332-422c-8c56-3783ad828d50';   // the HR door (API-driven inbound provisioning app)

function run(cmd, args, { timeout = 60000, cwd } = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout, cwd, maxBuffer: 32 << 20, env: process.env }, (e, so, se) => {
      if (e) reject(new Error(`${cmd.split('/').pop()} ${args.slice(0, 3).join(' ')}: ${(se || e.message).trim().split('\n').slice(-2).join(' ')}`));
      else resolve(so);
    });
  });
}
export const sh = run;

// ---- GitHub -------------------------------------------------------------------
export async function gh(args, opts) { return run('gh', args, opts); }
export async function ghJson(args) { return JSON.parse(await gh(args)); }
export const api = (path) => ghJson(['api', path]);

export async function prForBranch(branch) {
  const list = await ghJson(['pr', 'list', '-R', REPO, '--head', branch, '--state', 'all', '--json', 'number,url,state,headRefName,mergeCommit,title', '--limit', '5']);
  return list.find((p) => p.state === 'OPEN') || list[0] || null;
}

// All checks done + the plan comment posted (its first line is the marker
// heading written by .github/workflows/terraform-plan.yml).
export async function prChecks(pr) {
  const v = await ghJson(['pr', 'view', String(pr), '-R', REPO, '--json', 'statusCheckRollup,state,url,mergeable']);
  // A PR that conflicts with main gets no pull_request runs at all: say so
  // instead of waiting for checks that will never start.
  if (v.mergeable === 'CONFLICTING') return { total: 0, done: 0, failed: ['the branch conflicts with main (rebase it)'], plan: false, planUrl: null, headline: '' };
  // Advisory reviewers (Greptile, the AI security review) never block a merge
  // and can take longer than the plan: they don't hold the light yellow.
  const checks = (v.statusCheckRollup || []).filter((c) => !/greptile|advisory/i.test(c.name || c.context || ''));
  const done = checks.filter((c) => (c.status || c.state) === 'COMPLETED' || ['SUCCESS', 'FAILURE', 'NEUTRAL', 'SKIPPED', 'ERROR'].includes(c.state || c.conclusion));
  const failed = checks.filter((c) => ['FAILURE', 'ERROR', 'TIMED_OUT', 'CANCELLED', 'ACTION_REQUIRED'].includes(c.conclusion || c.state));
  const comments = await ghJson(['api', `repos/${REPO}/issues/${pr}/comments?per_page=100`]);
  const plan = comments.find((c) => c.user?.login === 'github-actions[bot]' && (c.body || '').startsWith('## Terraform plan'));
  const headline = plan ? ((/\*\*What this change does:\*\*\s*([^\n]+)/.exec(plan.body) || [])[1] || '').trim() : '';
  return { total: checks.length, done: done.length, failed: failed.map((c) => c.name || c.context), plan: !!plan, planUrl: plan?.html_url || null, headline };
}

export async function runsFor(workflow, { branch, sha, event, limit = 10 } = {}) {
  const args = ['run', 'list', '-R', REPO, '--workflow', workflow, '--limit', String(limit), '--json', 'databaseId,headSha,status,conclusion,url,displayTitle,createdAt,event'];
  if (branch) args.push('--branch', branch);
  if (event) args.push('--event', event);
  const runs = await ghJson(args);
  return sha ? runs.filter((r) => r.headSha === sha) : runs;
}

export async function approvalIssue(sha) {
  const short = sha.slice(0, 7);
  const list = await ghJson(['issue', 'list', '-R', REPO, '--state', 'all', '--search', `"Approve: apply ${short}" in:title`, '--json', 'number,url,state,title', '--limit', '5']);
  return list.find((i) => i.title === `Approve: apply ${short} to prod`) || null;
}

// ---- Microsoft Graph (GET only, as the lab operator) ---------------------------
export async function graph(path) {
  if (!/^[\w/$?=&'(). ,:-]+$/.test(path.replace(/%[0-9A-F]{2}/gi, ''))) throw new Error(`refusing odd Graph path ${path}`);
  const args = ['az', 'rest', '--method', 'GET', '--url', `https://graph.microsoft.com/${path.startsWith('beta/') ? '' : 'v1.0/'}${path}`, '-o', 'json'];
  // One retry: a read can fail once in a while (seen 2026-11-05 on
  // entitlementManagement/assignments); a second failure is reported.
  const out = await run(OP, args, { cwd: LAB, timeout: 90000 }).catch(async () => { await new Promise((r) => setTimeout(r, 2500)); return run(OP, args, { cwd: LAB, timeout: 90000 }); });
  return JSON.parse(out);
}

export async function samUser(employeeId = '400104') {
  const r = await graph(`users?$filter=employeeId eq '${employeeId}'&$select=id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,createdDateTime`);
  if (r.value.length > 1) throw new Error(`more than one user with employeeId ${employeeId}`);
  return r.value[0] || null;
}

export async function accessPackageId(displayName) {
  const r = await graph(`identityGovernance/entitlementManagement/accessPackages?$filter=displayName eq '${displayName}'&$select=id,displayName`);
  return r.value[0]?.id || null;
}

// Sam's access-package assignments. Learn: "List assignments" supports
// $filter=target/objectId eq '{id}' and $expand=accessPackage.
export async function assignmentsFor(objectId) {
  const r = await graph(`identityGovernance/entitlementManagement/assignments?$filter=target/objectId eq '${objectId}'&$expand=accessPackage`);
  return r.value.map((a) => ({ pkg: a.accessPackage?.displayName, state: a.state, status: a.status }));
}

// A provisioning app's log rows for one person (AuditLog.Read.All). Default:
// the HR door.
export async function provisioningRows(name, spId = HR_SP) {
  const r = await graph(`auditLogs/provisioning?$filter=servicePrincipal/id eq '${spId}'&$top=50`);
  // The HR door logs a person by employee id with an empty display name
  // (seen 2026-11-05), so a number matches the source id exactly.
  return r.value.filter((x) => (/^\d+$/.test(name) ? x.sourceIdentity?.id === name : JSON.stringify([x.sourceIdentity, x.targetIdentity]).includes(name)))
    .map((x) => ({ when: x.activityDateTime, action: x.provisioningAction, status: x.provisioningStatusInfo?.status }));
}

export async function signIns(userId) {
  const r = await graph(`auditLogs/signIns?$filter=userId eq '${userId}'&$top=5`);
  return r.value.map((s) => ({ when: s.createdDateTime, app: s.appDisplayName, ca: s.conditionalAccessStatus, ok: s.status?.errorCode === 0 }));
}

// Newest first, with the methods used (beta: authenticationDetails) and the
// Conditional Access results, for the sign-in log steps.
export async function signInsDetailed(userId, top = 10) {
  const r = await graph(`beta/auditLogs/signIns?$filter=userId eq '${userId}'&$top=${top}`);
  return r.value.map((s) => ({ when: s.createdDateTime, app: s.appDisplayName, code: s.status?.errorCode,
    methods: (s.authenticationDetails || []).map((a) => a.authenticationMethod),
    ca: (s.appliedConditionalAccessPolicies || []).filter((p) => p.result === 'success' || p.result === 'failure').map((p) => `${p.displayName}: ${p.result}`) }));
}

// ---- AWS (read only, as the lab operator; account checked every time) ----------
async function aws(args) {
  const acct = (await run(OP, ['aws', 'sts', 'get-caller-identity', '--query', 'Account', '--output', 'text'], { cwd: LAB })).trim();
  if (acct !== AWS_ACCOUNT) throw new Error(`AWS answered as account ${acct}, not the lab account ${AWS_ACCOUNT}: stopped`);
  return JSON.parse(await run(OP, ['aws', ...args, '--region', 'us-east-1', '--output', 'json'], { cwd: LAB }));
}

// null = not in AWS; otherwise { id, status } (UserStatus ENABLED / DISABLED).
export async function awsUser(upn) {
  const r = await aws(['identitystore', 'list-users', '--identity-store-id', IDSTORE, '--filters', `AttributePath=UserName,AttributeValue=${upn}`]);
  const u = r.Users?.[0];
  if (!u) return null;
  const d = await aws(['identitystore', 'describe-user', '--identity-store-id', IDSTORE, '--user-id', u.UserId]);
  return { id: u.UserId, status: d.UserStatus || 'ENABLED' };
}

export async function servicePrincipal(displayName) {
  const r = await graph(`servicePrincipals?$filter=displayName eq '${displayName}'&$select=id,appId,displayName,loginUrl,preferredSingleSignOnMode`);
  if (r.value.length !== 1) throw new Error(`expected one service principal named "${displayName}", found ${r.value.length}`);
  return r.value[0];
}
export async function syncJob(spId) {
  const r = await graph(`servicePrincipals/${spId}/synchronization/jobs`);
  const j = r.value[0];
  return j ? { code: j.status?.code, last: j.status?.lastExecution?.state } : null;
}
export async function userById(id) {
  return graph(`users/${id}?$select=id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled`);
}

// ---- Azure Resource Manager (GET only, as the lab operator) --------------------
export const SUB = 'de0b2a93-1c62-47b3-aaaf-1bdd1939a274';
async function arm(pathAndQuery) {
  const out = await run(OP, ['az', 'rest', '--method', 'GET', '--url', `https://management.azure.com/${pathAndQuery}`, '-o', 'json'], { cwd: LAB, timeout: 90000 });
  return JSON.parse(out);
}

// Containment approval cards still waiting for an answer: the Running runs of
// pb-identity-contain (slice 5) and the Account entities of the incident each
// run was started for. The run's trigger outputs come through a short-lived
// signed link that is used here and never logged or kept.
// Learn: Logic Apps "Workflow Runs - List" ($filter=status eq 'Running').
export async function pendingContainment() {
  const base = `subscriptions/${SUB}/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain`;
  const runs = await arm(`${base}/runs?api-version=2016-06-01&$filter=status eq 'Running'`);
  const out = [];
  for (const r of runs.value || []) {
    const one = await arm(`${base}/runs/${r.name}?api-version=2016-06-01`);
    const link = one.properties?.trigger?.outputsLink?.uri;
    if (!link) throw new Error(`containment run ${r.name}: no trigger outputs to read`);
    const res = await fetch(link, { signal: AbortSignal.timeout(30000) });
    if (!res.ok) throw new Error(`containment run ${r.name}: trigger outputs answered ${res.status}`);
    const inc = (await res.json()).body?.object;
    const accounts = (inc?.properties?.relatedEntities || []).filter((e) => e.kind === 'Account')
      .map((e) => ({ name: e.properties?.accountName || '', upnSuffix: e.properties?.upnSuffix || '', aadUserId: e.properties?.aadUserId || '' }));
    out.push({ run: r.name, started: r.properties?.startTime, incident: inc?.properties?.incidentNumber, title: inc?.properties?.title || '', accounts });
  }
  return out;
}

// ---- writes the cockpit makes on purpose (as the lab operator) --------------
// Provision on demand: one user, now, instead of waiting for the app's next
// provisioning cycle (what the run sheet's fallback asks the presenter to do
// by hand). Learn: synchronizationJob: provisionOnDemand (POST, body
// parameters[{ subjects[{objectId, objectTypeName}], ruleId }]; ruleId from
// the job's schema synchronizationRules). Needs Synchronization.ReadWrite.All.
async function graphPost(pathAndQuery, body) {
  const out = await run(OP, ['az', 'rest', '--method', 'POST', '--url', `https://graph.microsoft.com/v1.0/${pathAndQuery}`, '--headers', 'Content-Type=application/json', '--body', JSON.stringify(body), '-o', 'json'], { cwd: LAB, timeout: 120000 });
  return out.trim() ? JSON.parse(out) : {};
}
export async function provisionOnDemand(spDisplayName, userId) {
  const sp = await servicePrincipal(spDisplayName);
  const jobs = await graph(`servicePrincipals/${sp.id}/synchronization/jobs`);
  const job = jobs.value[0];
  if (!job) throw new Error(`${spDisplayName} has no provisioning job`);
  const schema = await graph(`servicePrincipals/${sp.id}/synchronization/jobs/${job.id}/schema`);
  const ruleId = schema.synchronizationRules?.[0]?.id;
  if (!ruleId) throw new Error(`${spDisplayName}: no synchronization rule in the job's schema`);
  const r = await graphPost(`servicePrincipals/${sp.id}/synchronization/jobs/${job.id}/provisionOnDemand`, { parameters: [{ subjects: [{ objectId: userId, objectTypeName: 'User' }], ruleId }] });
  const value = r.value?.[0]?.value || r.value || '';
  return typeof value === 'string' ? value.slice(0, 300) : JSON.stringify(value).slice(0, 300);
}
// On-demand provisioning of a USER does not carry its group memberships
// (preview 2, piece 4: Sam reached AWS with no group, so "ViewOnlyAccess: No
// access"). This provisions the GROUP on demand with that one member, so the
// membership (and the account access hanging off the group) arrives now.
export async function provisionGroupOnDemand(spDisplayName, groupName, userId) {
  const sp = await servicePrincipal(spDisplayName);
  const jobs = await graph(`servicePrincipals/${sp.id}/synchronization/jobs`);
  const job = jobs.value[0];
  if (!job) throw new Error(`${spDisplayName} has no provisioning job`);
  const schema = await graph(`servicePrincipals/${sp.id}/synchronization/jobs/${job.id}/schema`);
  const ruleId = schema.synchronizationRules?.[0]?.id;
  if (!ruleId) throw new Error(`${spDisplayName}: no synchronization rule in the job's schema`);
  const g = await graph(`groups?$filter=displayName eq '${groupName}'&$select=id`);
  if (g.value.length !== 1) throw new Error(`expected one group named ${groupName}, found ${g.value.length}`);
  const r = await graphPost(`servicePrincipals/${sp.id}/synchronization/jobs/${job.id}/provisionOnDemand`, { parameters: [{ subjects: [{ objectId: g.value[0].id, objectTypeName: 'Group', links: { members: [{ objectId: userId, objectTypeName: 'User' }] } }], ruleId }] });
  const value = r.value?.[0]?.value || r.value || '';
  return typeof value === 'string' ? value.slice(0, 300) : JSON.stringify(value).slice(0, 300);
}
export const AWS_STAFF_GROUP = 'App-AWS-IdentityCenter-Users';   // ViewOnlyAccess on 182002546409

export async function userByUpn(upn) {
  return graph(`users/${encodeURIComponent(upn)}?$select=id,userPrincipalName,accountEnabled`);
}
export async function isGroupMember(groupName, userId) {
  const g = await graph(`groups?$filter=displayName eq '${groupName}'&$select=id`);
  if (!g.value[0]) throw new Error(`no group named ${groupName}`);
  const m = await graph(`groups/${g.value[0].id}/members?$select=id&$top=999`);
  return m.value.some((x) => x.id === userId);
}

// Cloud Sync (AD -> Entra) for one on-site account, now: provision on demand
// on the Cloud Sync job, subject = the account's distinguished name (Learn:
// "Cloud Sync: provision on demand" uses the AD DN). For a synced user the DN
// is Entra's onPremisesDistinguishedName.
export const CLOUDSYNC_SP = '4c0d0455-9356-4954-b8ef-48edc1713efe';
export async function cloudSyncOnDemand(dn) {
  const jobs = await graph(`servicePrincipals/${CLOUDSYNC_SP}/synchronization/jobs`);
  const job = jobs.value.find((j) => j.templateId === 'AD2AADProvisioning') || jobs.value[0];
  const schema = await graph(`servicePrincipals/${CLOUDSYNC_SP}/synchronization/jobs/${job.id}/schema`);
  const ruleId = schema.synchronizationRules?.[0]?.id;
  const r = await graphPost(`servicePrincipals/${CLOUDSYNC_SP}/synchronization/jobs/${job.id}/provisionOnDemand`, { parameters: [{ subjects: [{ objectId: dn, objectTypeName: 'user' }], ruleId }] });
  return JSON.stringify(r).slice(0, 200);
}
export async function onPremDn(userId) {
  const u = await graph(`users/${userId}?$select=onPremisesDistinguishedName`);
  return u.onPremisesDistinguishedName || null;
}

// Cloud Sync: start a cycle now. Learn: synchronizationJob: restart, body
// criteria.resetScope (None = just run; QuarantineState also clears a pause).
export async function cloudSyncRestart(scope = 'None') {
  const jobs = await graph(`servicePrincipals/${CLOUDSYNC_SP}/synchronization/jobs`);
  const job = jobs.value.find((j) => j.templateId === 'AD2AADProvisioning') || jobs.value[0];
  await graphPost(`servicePrincipals/${CLOUDSYNC_SP}/synchronization/jobs/${job.id}/restart`, { criteria: { resetScope: scope } });
  return `Cloud Sync job ${job.id} restarted (${scope})`;
}

export const graphPostPublic = (pathAndQuery, body) => graphPost(pathAndQuery, body);
export async function graphDelete(pathAndQuery) {
  await run(OP, ['az', 'rest', '--method', 'DELETE', '--url', `https://graph.microsoft.com/v1.0/${pathAndQuery}`], { cwd: LAB, timeout: 120000 });
}
export async function graphPut(pathAndQuery, body) {
  const out = await run(OP, ['az', 'rest', '--method', 'PUT', '--url', `https://graph.microsoft.com/v1.0/${pathAndQuery}`, '--headers', 'Content-Type=application/json', '--body', JSON.stringify(body), '-o', 'json'], { cwd: LAB, timeout: 120000 });
  return out.trim() ? JSON.parse(out) : {};
}

// Is this user a member of this group in AWS IAM Identity Center? (operator
// read, account checked by aws()).
export async function awsUserInGroup(upn, groupName) {
  const g = await aws(['identitystore', 'list-groups', '--identity-store-id', IDSTORE, '--filters', `AttributePath=DisplayName,AttributeValue=${groupName}`]);
  const gid = g.Groups?.[0]?.GroupId; if (!gid) return false;
  const u = await aws(['identitystore', 'list-users', '--identity-store-id', IDSTORE, '--filters', `AttributePath=UserName,AttributeValue=${upn}`]);
  const uid = u.Users?.[0]?.UserId; if (!uid) return false;
  const m = await aws(['identitystore', 'list-group-memberships-for-member', '--identity-store-id', IDSTORE, '--member-id', `UserId=${uid}`]);
  return (m.GroupMemberships || []).some((x) => x.GroupId === gid);
}

// Sentinel incidents (operator, ARM read): newest first.
export async function sentinelIncidents(top = 20) {
  const r = await arm(`subscriptions/${SUB}/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab/providers/Microsoft.SecurityInsights/incidents?api-version=2024-09-01&$orderby=properties/createdTimeUtc desc&$top=${top}`);
  return (r.value || []).map((x) => ({ name: x.name, number: x.properties.incidentNumber, title: x.properties.title, created: x.properties.createdTimeUtc, status: x.properties.status, providerIncidentId: x.properties.providerIncidentId }));
}
// The user accounts an incident is about (its Account entities, Sentinel's
// "entities" action; operator, read only): ["adm-raj.patel@...", ...].
export async function incidentAccounts(name) {
  if (!/^[0-9a-f-]{36}$/i.test(name)) throw new Error(`odd incident name ${name}`);
  const out = await run(OP, ['az', 'rest', '--method', 'POST', '--url', `https://management.azure.com/subscriptions/${SUB}/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab/providers/Microsoft.SecurityInsights/incidents/${name}/entities?api-version=2024-09-01`, '-o', 'json'], { cwd: LAB, timeout: 90000 });
  return (JSON.parse(out).entities || []).filter((e) => e.kind === 'Account').map((e) => `${e.properties.accountName}@${e.properties.upnSuffix || ''}`.toLowerCase());
}

// The permission sets' names in the lab's Identity Center (read only).
export async function awsPermissionSets() {
  const inst = await aws(['sso-admin', 'list-instances']);
  const arn = inst.Instances?.[0]?.InstanceArn;
  if (!arn) return [];
  const l = await aws(['sso-admin', 'list-permission-sets', '--instance-arn', arn]);
  const out = [];
  for (const ps of l.PermissionSets || []) out.push((await aws(['sso-admin', 'describe-permission-set', '--instance-arn', arn, '--permission-set-arn', ps])).PermissionSet?.Name);
  return out.filter(Boolean).sort();
}
