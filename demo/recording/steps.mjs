// Every on-camera step of the live demo, in order. Source: the run sheet
// (10 pieces: screens / do / say / point at) and the spoken script
// (showcase-build/script_lines.py), rewritten for live narration: short,
// plain, one idea per step.
//
// A step:
//   say       the line(s) the presenter reads (shown huge on the teleprompter)
//   do        what the cockpit does on NEXT, in order (see lib/engine.mjs)
//   wait      a live check polled after `do`; the light is yellow while it is
//             not ready (the recording PAUSES), green when the next screen is
//             ready (the recording RESUMES). `onReady` runs before resuming.
//   hand      what the presenter does with their own hands (shown in orange)
//   fallback  what to do if the automation can't (shown small)
//   write     on the step: it changes something (commit, push, PR, merge,
//             sign-in, workflow run). Dry run never does these; it says what
//             it would do.
//   preview   --preview only: the presenter's hand step, done by the cockpit
//             after `do` and labelled on screen (approve, Contain, Sam's setup).
// Values that only exist at run time (the PR, the apply run, Sam's id) are
// functions of the cockpit context `c`.
//
// Pieces carry `reset`: what the "retake this piece" key runs before the
// piece starts again (see lib/engine.mjs resetPiece).

import fs from 'node:fs';

// The first line of `file` that matches `re` (1 when the file or line is not
// there yet: the step still opens the file, at its top).
const lineOf = (file, re) => { try { const k = fs.readFileSync(file, 'utf8').split('\n').findIndex((l) => re.test(l)); return k >= 0 ? k + 1 : 1; } catch { return 1; } };

const E = 'https://entra.microsoft.com/#view/';
const GH = 'https://github.com/ChromeData/contoso-health-identity-lab';
const AWS_USERS = 'https://us-east-1.console.aws.amazon.com/singlesignon/home?region=us-east-1#/users';
// The staff window reaches the AWS console through the access portal's
// shortcut link (account + permission set + destination). The role is
// config: test-user-a's ViewOnlyAccess can NOT list Identity Center users
// (AccessDenied, seen 2026-11-05), so this view needs a role that can.
const AWS_ROLE = process.env.COCKPIT_AWS_ROLE || 'LabAdministrator';
const AWS_USERS_VIA_PORTAL = `https://d-90666212c7.awsapps.com/start/#/console?account_id=182002546409&role_name=${AWS_ROLE}&destination=${encodeURIComponent(AWS_USERS)}`;
const PKGS = `${E}Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement`;
const HR_APP = `${E}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/appId/784ded74-ab2e-4f49-bece-e913a429ff59/objectId/876b6339-1332-422c-8c56-3783ad828d50`;
const userPage = (c) => `${E}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${c.sam.id}/hidePreviewBanner~/true`;
// The Contoso SOC team's Identity-SecOps channel (slice 5, drill.json "team").
// The web app's OWN route to the channel (/_#/l/channel/...). A /l/ link
// (even with &web=1) goes through Teams' launcher page, which asks Chrome to
// open the desktop app; the desktop app once opened signed in to the owner's
// own organisation (2026-11-05). This route opens the channel in web Teams
// directly: no launcher, no "Open Microsoft Teams?" (proven 2026-11-05).
const SOC_CHANNEL = 'https://teams.cloud.microsoft/_#/l/channel/19%3A4082dd6ec333491786083ed4b1299843%40thread.tacv2/Identity-SecOps?groupId=6bf33a4b-865b-43fb-9dba-c1a031e36bd0&tenantId=86a2e327-4951-4348-a3c4-6f4b79ffd8f2';
// The web client itself: a /l/ deep link goes through Teams' launcher page,
// which asks Chrome to open the desktop app ("Open Microsoft Teams?", seen on
// 2026-11-05 even with &web=1). The cockpit opens the web client and clicks to
// the channel instead.
const TEAMS_WEB = 'https://teams.microsoft.com/v2/?tenantId=86a2e327-4951-4348-a3c4-6f4b79ffd8f2';
const EVIDENCE = 'https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource/subscriptions/de0b2a93-1c62-47b3-aaaf-1bdd1939a274/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence20f1/containersList';

const VARS = 'lab/terraform/modules/entitlement/variables.tf';
const RULES = 'lab/iga/birthright-rules.json';
const CSV = 'lab/scripts/mock-hr/hr_feed.csv';
// Key Vault leak proof (lab PR #235): exists in the tour copy once #235 is merged
// and cockpit/.tour-main is moved to the new origin/main.
const LEAK = (c) => `${c.tourLab}/lab/evidence/keyvault-state-leak/20261107T014803Z/run.txt`;
// Bastion capture of 2026-11-07 (lab PR #247): the reviewer's playback frame, kept on this Mac.
const BASTION_SHOT = path.join(os.homedir(), 'contoso-demo/captures/bastion/2026-11-07/proof-playback/10-playback-whoami.png');
export const SAM_ROW = (c) => `400104,Sam,Rivera,Information Technology,Cloud Engineer,400100,joiner,${c.today},`;

export const PIECES = [
  { n: 1, slug: 'the-blueprints', title: 'The blueprints', reset: 'blueprints' },
  { n: 2, slug: 'hired', title: 'Hired', reset: 'hire' },
  { n: 3, slug: 'the-badge-list', title: 'The badge list', reset: null },
  { n: 4, slug: 'first-day-doors', title: 'First-day doors', reset: 'private-window' },
  { n: 5, slug: 'the-guard', title: 'The guard at every door', reset: null },
  // after: run between this piece's file and the next one's (never recorded).
  { n: 6, slug: 'the-master-key', title: 'The master key', reset: 'pim', after: [{ do: 'pim.deactivate', group: 'PIM-Tier1-Helpdesk', upn: 'adm-raj.patel@contosohealthlab.onmicrosoft.com' }] },
  { n: 7, slug: 'the-cameras', title: 'The cameras', reset: null },
  { n: 8, slug: 'second-camera-system', title: 'A second camera system', reset: null },
  { n: 9, slug: 'leaving', title: 'Leaving', reset: 'leave' },
  { n: 10, slug: 'the-logbook', title: 'The logbook', reset: null },
  { n: 11, slug: 'the-tour', title: 'The tour', reset: null },
];

export function steps(c) {
  const bp = (f) => `${c.bp}/${f}`;
  const hr = (f) => `${c.hr}/${f}`;
  const tout = (f) => `${c.tourOut}/${f}`;
  return [
    // ===================================================================== 1
    { id: '1-diff', piece: 1,
      say: ['Every change starts as code.', 'This file is the blueprint for who gets which apps.'],
      // The owner's view (2026-11-06): the finished file, not a red/green
      // diff; only the changed lines softly tinted, part by part.
      do: [{ do: 'code.open' }, { do: 'code.closeAll' }, { do: 'code.changes', file: bp(VARS), line: 59 }] },
    { id: '1-nurse', piece: 1,
      say: ["I'm fixing a real gap: nurses had AWS access they never use.", 'So AWS comes off the nurse package.'],
      do: [{ do: 'code.changes', file: bp(VARS), from: 60, to: 70 }] },
    { id: '1-cloud', piece: 1,
      say: ["Cloud engineers run the hospital's patient portal in AWS.", 'So they get a new package that has it.'],
      do: [{ do: 'code.changes', file: bp(VARS), from: 71, to: 95 }] },
    { id: '1-rule', piece: 1,
      say: ['And the rule: every cloud engineer gets that package on day one,', "straight from their job title in HR."],
      do: [{ do: 'code.closeAll' }, { do: 'code.changes', file: bp(RULES) }] },
    { id: '1-commit', piece: 1, write: true,
      say: ['I save the change, with a note that says why.'],
      do: [{ do: 'code.commit', folder: c.bp, files: [VARS, RULES], message: "Cloud engineers get AWS, nurses don't", allowBranch: c.bpBranchRe }] },
    { id: '1-push', piece: 1, write: true,
      say: ['And send it to GitHub.'],
      do: [{ do: 'code.push', folder: c.bp, branch: c.bpBranch }] },
    { id: '1-pr', piece: 1, write: true,
      say: ['On GitHub it becomes a pull request:', 'the change, line by line, before anything is built.'],
      do: [{ do: 'gh.createPr', branch: c.bpBranch, title: c.prTitle, body: c.prBody }],
      wait: { check: 'prChecks', waiting: 'GitHub is testing the change (about 3 minutes)', ready: 'Tests done, plan posted',
        onReady: [{ do: 'web.open', url: (x) => x.pr.url }] },
      fallback: 'If the browser is not signed in to GitHub, the cockpit makes the PR with gh and opens it.' },
    // The clean before-and-after, on GitHub (the owner's request, 2026-11-06).
    { id: '1-files', piece: 1,
      say: ['Here is the whole change on GitHub, line by line, before and after.'],
      do: [{ do: 'web.open', url: (x) => `${x.pr.url}/files`, settle: 6000 }, { do: 'web.highlight', target: { re: 'variables\\.tf$', nth: 0 }, tag: 'Before and after' }] },
    { id: '1-checks', piece: 1,
      say: ['GitHub tests it first: the plan, the automated tests, and two security scans.', 'All green.'],
      do: [{ do: 'web.open', url: (x) => x.pr.url }, { do: 'web.highlight', target: { re: 'All checks have passed|checks? passed|successful checks', block: 'div' }, tag: 'All green' }],
      fallback: 'Scroll to the checks box at the bottom of the conversation.' },
    { id: '1-plan', piece: 1,
      say: ['And it says in plain words what will change:', 'a new package for cloud engineers, and AWS comes off the nurse package.'],
      do: [{ do: 'web.open', url: (x) => x.planUrl || x.pr.url }, { do: 'web.highlight', target: { re: 'What this change does', block: "*[contains(@class,'comment-body')]" }, tag: 'In plain words' }] },
    { id: '1-merge', piece: 1, write: true, rehearsal: 'close', cloud: true, standIn: [{ do: 'web.open', url: (x) => x.pr.url }, { do: 'banner', text: 'PREVIEW · not merged: only the owner approves an apply, so a preview stops before it' }],
      say: ['A teammate would review it here.', 'I merge it, and that starts the build.'],
      do: [{ do: 'gh.merge' }],
      wait: { check: 'approvalIssue', waiting: 'The build is getting ready (about 3 minutes to the approval request)', ready: 'Approval request is open' },
      fallback: 'Click "Merge pull request", then "Confirm merge".' },
    { id: '1-gate', piece: 1,
      say: ['But the build stops at a human gate.', 'Nothing changes until a person types approve. Here, that person is me.'],
      hand: 'Type approve in the comment box, then click Comment.',
      // 2026-11-07 rule: the cockpit NEVER types an approval, in any mode.
      // A preview stops at the gate (cloud: its stand-in) and skips the apply.
      cloud: true, standIn: [{ do: 'banner', text: "PREVIEW · stops at the approval: only the owner approves; the apply is skipped" }],
      do: [{ do: 'web.open', url: (x) => x.issue.url }, { do: 'web.highlight', target: { re: 'is waiting for a human decision' }, tag: 'The human gate' }, { do: 'web.focus', target: { css: 'textarea' } }],
      wait: { check: 'applyDone', waiting: 'Waiting for your approve, then building (about 4 minutes)', ready: 'Built: the change is live',
        onReady: [{ do: 'web.open', url: (x) => x.applyRun.url }] } },
    { id: '1-applied', piece: 1, cloud: true, standIn: [{ do: 'banner', text: 'PREVIEW · skipped: there is no apply in a preview' }],
      say: ['Approved, and built.', 'The run says what changed, in plain words.'],
      do: [{ do: 'web.open', url: (x) => x.applyRun.url }, { do: 'web.highlight', target: { re: 'Applied:' }, tag: 'What changed' }],
      fallback: 'Scroll to the run summary.' },
    { id: '1-entra-new', piece: 1, cloud: true, standIn: [{ do: 'banner', text: 'PREVIEW · skipped: there is no apply in a preview' }],
      say: ['And here it is, live in Entra:', 'the new package for cloud engineers.'],
      do: [{ do: 'web.open', url: PKGS, settle: 6000 }, { do: 'web.highlight', target: { text: 'IT - Cloud Engineering Apps', row: true }, tag: 'New' }] },
    { id: '1-entra-nurse', piece: 1, cloud: true, standIn: [{ do: 'banner', text: 'PREVIEW · skipped: there is no apply in a preview' }],
      say: ['And the nurse package no longer has AWS.'],
      do: [{ do: 'web.click', target: { text: 'Nurse - Clinical Apps' } }, { do: 'web.click', target: { text: 'Resource roles', exact: true } }, { do: 'web.highlight', target: { re: 'ServiceNow', row: true }, tag: 'ServiceNow only' }],
      fallback: 'Open Nurse - Clinical Apps, then Resource roles.' },

    // ===================================================================== 2
    { id: '2-file', piece: 2,
      say: ["HR is the source of truth.", "This is HR's list of everyone who works here."],
      do: [{ do: 'code.open' }, { do: 'code.closeAll' }, { do: 'code.file', file: hr(CSV), line: 61, endLine: 61 }] },
    { id: '2-type', piece: 2, write: true,
      say: ['I add Sam Rivera, a new cloud engineer starting today.', "That's the only thing anyone does by hand."],
      do: [{ do: 'code.type', file: hr(CSV), text: SAM_ROW(c), trailingNewline: true }, { do: 'code.save', file: hr(CSV) }] },
    { id: '2-send', piece: 2, write: true,
      say: ['Save it, and send it.'],
      do: [{ do: 'code.commit', folder: c.hr, files: [CSV], message: 'HR: hire Sam Rivera, Cloud Engineer', allowBranch: '^hr-feed$' }, { do: 'code.push', folder: c.hr, branch: 'hr-feed' }],
      wait: { check: 'hrRunDone', waiting: 'GitHub is sending it to Microsoft (about 1 minute)', ready: 'Sent' } },
    { id: '2-run', piece: 2,
      say: ["GitHub sends it to Microsoft's front door for HR.", 'The run says it in plain words: hired, Sam Rivera, cloud engineer.'],
      do: [{ do: 'web.open', url: (x) => x.hrRun.url }, { do: 'web.highlight', target: { re: 'Hired:?\\s*Sam Rivera|Sam Rivera, Cloud Engineer', block: 'li' }, tag: 'Hired' }],
      wait: { check: 'samProvLog', waiting: "Microsoft's log catches up (5 to 10 minutes)", ready: "Sam is in the HR door's log" } },
    { id: '2-log', piece: 2,
      say: ["And Microsoft's own log shows Sam's account created, automatically."],
      do: [{ do: 'web.open', url: HR_APP, settle: 6000 }, { do: 'web.click', target: { text: 'Provisioning logs', exact: true } }, { do: 'web.highlight', target: { text: 'Create', exact: true, row: true }, tag: 'Sam Rivera (HR id 400104): created' }],
      // The HR door logs the HR id ("Source ID 400104"), not the name; newest
      // first, so the first Create row is this take's (preview 2: no highlight).
      wait: { check: 'samInEntra', waiting: 'Cloud Sync is copying Sam up to Entra (runs about every 20 minutes)', ready: 'Sam is in Entra' },
      fallback: 'Too slow? Entra > Cloud Sync > Provision on demand, for Sam.' },

    // ===================================================================== 3
    { id: '3-sam', piece: 3,
      say: ['Sam lands in the on-site directory first, the one hospital PCs use.', 'Cloud Sync copies him up to Entra. One account, both places.'],
      do: [{ do: 'find', what: 'sam' }, { do: 'web.open', url: userPage, settle: 6000 }, { do: 'web.click', target: { role: 'tab', name: 'Properties' } }, { do: 'web.highlight', target: { re: '^On-premises sync enabled', widen: 220 }, tag: 'Yes: synced from on-site' }],
      wait: { check: 'samHasPackage', waiting: "Entra is adding Sam's access package (a few minutes)", ready: 'Package delivered' } },

    // ===================================================================== 4
    { id: '4-package', piece: 4,
      say: ["Sam's job decides his access on day one, with no ticket.", 'The cloud engineering package was added to him automatically.'],
      do: [{ do: 'web.open', url: PKGS, settle: 6000 }, { do: 'web.click', target: { text: 'IT - Cloud Engineering Apps' } }, { do: 'web.click', target: { text: 'Assignments', exact: true } }, { do: 'web.highlight', target: { text: 'Sam Rivera', row: true }, tag: 'Added automatically' }],
      wait: { check: 'samInAws', waiting: 'AWS is adding Sam (up to 40 minutes; Provision on demand makes it seconds)', ready: 'Sam is in AWS', nudge: 'aws' },
      fallback: "Speed up AWS: Entra > Enterprise apps > AWS IAM Identity Center > Provision on demand > Sam, then the GROUP App-AWS-IdentityCenter-Users with Sam as its member (a user alone gets no account access)." },
    { id: '4-aws', piece: 4,
      say: ['He is in AWS too, where the hospital runs its patient portal.', 'AWS never stored a password for him. It trusts his hospital login.'],
      do: [{ do: 'web.open', ctx: 'aws', url: AWS_USERS_VIA_PORTAL, settle: 10000, deny: 'You need .*permission|not authorized|AccessDenied' }, { do: 'web.highlight', ctx: 'aws', target: { re: 'sam\\.rivera', row: true }, tag: 'Arrived by himself' }] },
    { id: '4-signin', piece: 4, write: true,
      say: ['Here is Sam signing in for the first time,', 'with a one-time pass instead of a password.'],
      do: [{ do: 'tap.signin', who: 'sam', url: 'https://d-90666212c7.awsapps.com/start' }],
      preview: [{ do: 'preview.secondCheck' }],
      hand: 'If Microsoft asks Sam to set up a second check, answer it on screen (Ask later / Skip setup).',
      fallback: 'The one-time pass is typed for you and never shown.' },
    // Sam's own console session, straight into the patient portal's bucket
    // (the access portal's shortcut link: account + his permission set +
    // destination); clicking the account row didn't open the role list.
    { id: '4-portal', piece: 4,
      say: ['He opens the AWS account,', 'and there is the patient portal his team runs.'],
      do: [{ do: 'private.open', url: `https://d-90666212c7.awsapps.com/start/#/console?account_id=182002546409&role_name=ViewOnlyAccess&destination=${encodeURIComponent('https://s3.console.aws.amazon.com/s3/buckets/contoso-health-patient-portal-182002546409?region=us-east-1&tab=objects')}`, settle: 12000 },
        { do: 'private.highlight', target: { re: 'contoso-health-patient-portal' }, tag: 'The patient portal, as Sam' }],
      hand: 'If AWS asks which role, pick ViewOnlyAccess.',
      wait: { check: 'snowReady', waiting: "ServiceNow is getting Sam's account (next provisioning cycle; Provision on demand is faster)", ready: 'Sam is in ServiceNow', nudge: 'snow' } },
    // ServiceNow, two views. Admin: the user list as the ServiceNow recovery
    // account (signed in by the cockpit as a setup step; never the owner's
    // account). Staff: a lab test user's real Entra sign-in through My Apps.
    { id: '4-snow-admin', piece: 4,
      say: ['The IT help desk, ServiceNow, got his account on its own.', 'Entra creates it there, and switches it off when he leaves.'],
      do: [{ do: 'require', check: 'snowReady' }, { do: 'snow.adminList' }, { do: 'web.highlight', target: { re: 'Sam Rivera|sam\\.rivera', row: true }, tag: 'Created by Entra' }],
      fallback: "Red light: ServiceNow hasn't received Sam yet. Entra > Enterprise apps > ServiceNow - Provisioning > Provision on demand > Sam." },
    // Review 1: land on a page that shows SAM's own signed-in session (his
    // ServiceNow profile), not the instance's start page.
    { id: '4-snow-staff', piece: 4,
      say: ['Sam opens ServiceNow, the IT help desk, from My Apps.', 'Same hospital login, no second password.'],
      do: [{ do: 'require', check: 'snowReady' }, { do: 'sam.servicenow' }],
      fallback: "If ServiceNow isn't in his My Apps yet: wait for the package, or Provision on demand in ServiceNow - Provisioning." },

    // ===================================================================== 5
    // Preview 2 review: 5-second played over the AWS error page left from
    // piece 4. It now shows the proof: Sam's sign-in with his one-time pass,
    // Authentication Details (the pass satisfied the MFA requirement); 5-log
    // the Conditional Access tab (the MFA policy, Success). The log is opened
    // only once Graph has THIS take's pass sign-in (camera off meanwhile).
    { id: '5-second', piece: 5,
      say: ['Even with the right password, Sam needs a second check.', 'Here, his one-time pass counted as that check.'],
      do: [{ do: 'require', check: 'samSignin' }, { do: 'activate', app: 'browser' }, { do: 'find', what: 'sam' }, { do: 'web.open', url: userPage, settle: 6000 },
        { do: 'web.click', target: { text: 'Sign-in logs', exact: true } },
        { do: 'signin.openTap' },
        { do: 'web.highlight', target: { text: 'Temporary Access Pass', row: true }, tag: 'One-time pass: his second check' }],
      fallback: 'Sign-in logs take a few minutes to show up.' },
    { id: '5-log', piece: 5,
      say: ['The sign-in log shows every rule that looked at him,', 'and why he got in.'],
      do: [{ do: 'web.click', target: [{ role: 'tab', name: 'Conditional Access' }, { text: 'Conditional Access', exact: true, nth: 1 }], timeout: 20000 },
        { do: 'web.highlight', target: { re: 'Require MFA for all users', row: true }, tag: 'MFA rule: Success' }],
      fallback: 'Sign-in logs take a few minutes to show up.' },

    // ===================================================================== 6
    { id: '6-signin', piece: 6, write: true,
      // Raj (help desk): PIM-Tier1-Helpdesk is self-service (MFA + reason, no
      // approver). Ava's groups are Tier 0 and wait for an approver.
      say: ['No IT admin here holds admin power all day.', 'Raj from the help desk signs in to his separate admin account.'],
      do: [{ do: 'identity.signin', id: 'adm-raj.patel', fallback: 'raj', url: `${E}Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup` }] },
    { id: '6-activate', piece: 6, write: true,
      say: ['He switches on help-desk power for one task, and gives a reason.'],
      do: [{ do: 'private.highlight', target: { text: 'PIM-Tier1-Helpdesk', row: true }, tag: 'Eligible: he may borrow it' }, { do: 'private.click', target: { role: 'button', name: 'Activate', exact: true } }, { do: 'private.type', target: { css: 'textarea' }, text: "INC-5102: unlock Sam Rivera's account before his first shift" }, { do: 'private.click', target: { role: 'button', name: 'Activate', exact: true, nth: 1 } }] },
    { id: '6-active', piece: 6,
      say: ["It's on now, with an end time.", 'When that passes, it switches off on its own.'],
      // Review 1: the Active tab was empty right after activating; refresh
      // until his row is there.
      do: [{ do: 'pim.showActive', group: 'PIM-Tier1-Helpdesk', tag: 'Active, ends on its own' }],
      fallback: 'PIM reloads the page once the activation finishes; wait for it.' },

    // ===================================================================== 7
    { id: '7-rule', piece: 7,
      say: ['Every sign-in and every change is watched.', 'This alarm rule is code I wrote.'],
      do: [{ do: 'code.open' }, { do: 'code.closeAll' }, { do: 'code.file', file: bp('lab/kql/pim-activation.kql'), line: 59, endLine: 67, highlight: true }],
      // The rule runs on a timer: the incident for Raj's activation may take
      // ~15 minutes (13 on 2026-11-05). The next step opens it directly.
      wait: { check: 'pimIncident', waiting: "Waiting for the alarm on Raj's activation (the rule runs on a timer, about 15 minutes)", ready: 'The incident is there' } },
    { id: '7-incident', piece: 7,
      say: ['And here it fired,', 'on the admin power Raj just switched on.'],
      // Review 1: the incident list is filtered (priority score) and showed 0;
      // the incident itself opens directly.
      // Preview 2: the heading is cut ("PIM activation (just-in…"): the
      // highlight matches its start, "ID <n>:" (the incident's own id).
      // Preview 2 review: the incident is the one whose Account entities
      // include Raj (pimIncident, Sentinel entities); on screen, its Assets >
      // Users list with Raj highlighted, not the title.
      do: [{ do: 'web.open', url: (x) => `https://security.microsoft.com/incidents/${x.pimIncident.providerIncidentId}/overview?tid=86a2e327-4951-4348-a3c4-6f4b79ffd8f2`, settle: 12000 },
        { do: 'web.click', target: [{ role: 'tab', name: /^Assets/ }, { re: '^Assets \\(\\d+\\)$', nth: 0 }], timeout: 20000, settle: 4000 },
        { do: 'web.click', target: { re: '^Users \\(\\d+\\)$', nth: 0 }, settle: 4000 },
        { do: 'web.highlight', target: [{ re: '^ADM Raj Patel$', nth: 0 }, { re: 'adm-raj\\.patel', nth: 0 }], tag: 'Raj, who switched it on' }],
      fallback: 'Alarm rules run on a timer: if it is not there yet, wait for the light.' },
    // Optional: the alarm acts, with a person's yes. ONLY against slice 5's
    // throwaway drill account (itdr-drill-*); the require step refuses
    // anything else, and the presenter presses the button, not the cockpit.
    { id: '7-teams', piece: 7, optional: true, write: true,
      say: ['An alarm about a stolen account goes to the security team in Teams.', 'Nothing happens to the account until an approver says yes. This one is a drill account.'],
      hand: 'Press "Contain (revoke + disable)" on the card.',
      // Preview 2 review: the card, with its Contain button in view and
      // highlighted, is on camera while this line plays; the press comes next
      // (the presenter's hand live; --preview presses it at the start of
      // 7-contained, on camera).
      do: [{ do: 'drill.ensure' }, { do: 'require', check: 'drillPending' }, { do: 'teams.guard', phase: 'before' }, { do: 'web.open', ctx: 'staff', url: SOC_CHANNEL, settle: 12000 },
        { do: 'teams.guard', phase: 'after' },
        { do: 'web.highlight', ctx: 'staff', target: [{ css: 'button', hasText: /^Contain \(revoke \+ disable\)$/, last: true }, { role: 'button', name: /^Contain \(revoke \+ disable\)$/ }], tag: 'Nothing happens until someone says yes' }],
      wait: { check: 'drillContained', waiting: 'Waiting for your Contain on the card (still recording)', ready: 'Drill account switched off', liveOnly: true },
      fallback: "Red light: no drill card is waiting. Arm slice 5's containment drill first (throwaway itdr-drill user + drill incident)." },
    { id: '7-contained', piece: 7, optional: true, needs: 'drill',
      say: ['Approved: the drill account is signed out everywhere and switched off.', 'The decision is written on the incident and the help desk ticket.'],
      // The answered card is rewritten to "Decision recorded - see the
      // Sentinel incident comments." (no incident number left on it): the
      // newest such card, the last in the channel, is this one; an older
      // card is never tagged (preview 2: the fallback picked the first one).
      // Preview 2 review: the line played while nothing had been approved.
      // Its claim is checked first, camera off: the drill account is off in
      // Entra (Graph) and the card shows the decision. Unchecked: no line.
      do: [{ do: 'preview.contain', previewOnly: true }, { do: 'require', check: 'drillContained' }, { do: 'web.highlight', ctx: 'staff', target: (x) => [...(x.drill?.cardMark ? [{ css: `[data-ck-decided="${x.drill.cardMark}"] div`, hasText: /^Decision recorded/, last: true }] : []), { css: 'div', hasText: /^Decision recorded/, last: true }], tag: 'Done, with a name on it' }] },

    // ===================================================================== 8
    { id: '8-rule', piece: 8,
      say: ['Some hospitals use Splunk instead of Sentinel.', 'Here is the same rule, written for Splunk.'],
      do: [{ do: 'code.file', file: bp('lab/splunk/detections/pim-activation.spl'), line: 73, endLine: 74, highlight: true }] },
    { id: '8-run', piece: 8,
      // Preview 2 review: "it found it" was tagged on "0 events" (the SPL looks
      // back one hour). Only a count above 0 AND a row with Raj as the actor
      // may be tagged; otherwise the step fails.
      say: ["In Splunk I run it on the live log, and it finds Raj's activation.", 'Twenty-two of my rules run here too, so the hospital keeps its alarms whichever tool it uses.'],
      do: [{ do: 'web.open', url: 'http://127.0.0.1:8000/en-US/app/search/search?s=' + encodeURIComponent('Contoso - PIM activation (just-in-time elevation)') + '&earliest=0&latest=now', settle: 8000 },
        { do: 'web.find', target: { re: '^[1-9][\\d,]* (events?|results?)\\b', nth: 0 }, timeout: 45000 },
        { do: 'web.highlight', target: { re: 'adm-raj\\.patel', nth: 0 }, tag: "It found Raj's activation" }],
      fallback: 'The Splunk rule looks back one hour (earliest=-1h is in the search): if it finds nothing, re-run pieces 6-8 back to back.' },

    // ===================================================================== 9
    { id: '9-edit', piece: 9, write: true,
      say: ['Sam leaves.', 'HR changes one word.'],
      do: [{ do: 'code.open' }, { do: 'code.closeAll' }, { do: 'code.type', file: hr(CSV), lineMatch: '^400104,', find: 'joiner', text: 'leaver' }, { do: 'code.type', file: hr(CSV), lineMatch: '^400104,', text: c.today }, { do: 'code.save', file: hr(CSV) }] },
    { id: '9-send', piece: 9, write: true,
      say: ['I send it, and start the clock.'],
      do: [{ do: 'code.commit', folder: c.hr, files: [CSV], message: 'HR: Sam Rivera leaves', allowBranch: '^hr-feed$' }, { do: 'code.push', folder: c.hr, branch: 'hr-feed' }, { do: 'stopwatch.start' }],
      wait: { check: 'hrRunDone', waiting: 'GitHub is sending it (about 1 minute)', ready: 'Sent',
        // --preview: start a Cloud Sync cycle as soon as HR has sent it.
        onReady: [{ do: 'cloudsync.restart', previewOnly: true }] } },
    { id: '9-run', piece: 9,
      say: ['The run says it plainly: left, Sam Rivera.'],
      do: [{ do: 'activate', app: 'browser' }, { do: 'web.open', url: (x) => x.hrRun.url }, { do: 'web.highlight', target: { re: 'Left:?\\s*Sam Rivera', block: 'li' }, tag: 'Left' }],
      // --preview: after a minute, push it through Cloud Sync on demand (his
      // on-site DN); the job restart alone didn't move him in 5 minutes.
      wait: { check: 'samOffEntra', waiting: 'Sam is being switched off in the cloud (under 3 minutes last time)', ready: 'Off in Entra', nudge: 'cloudsync', nudgeAfterMs: 60000,
        // --preview: the moment he is off in Entra, tell AWS and ServiceNow now.
        onReady: [{ do: 'pod', app: 'aws', previewOnly: true }, { do: 'pod', app: 'snow', previewOnly: true }] } },
    { id: '9-entra', piece: 9,
      say: ['In Entra, his account is already off.'],
      do: [{ do: 'stopwatch.lap', label: 'Entra' }, { do: 'web.open', url: userPage, settle: 6000 }, { do: 'web.click', target: { role: 'tab', name: 'Properties' } }, { do: 'web.highlight', target: { re: '^Account enabled', widen: 220 }, tag: 'No: switched off' }],
      wait: { check: 'samOffAws', waiting: 'AWS follows (9 minutes last time; Provision on demand is faster)', ready: 'Off in AWS', nudge: 'aws', nudgeAfterMs: 60000 } },
    { id: '9-aws', piece: 9,
      say: ['And AWS has switched him off too.', 'Nobody filed a ticket.'],
      do: [{ do: 'stopwatch.lap', label: 'AWS' }, { do: 'web.open', ctx: 'aws', url: AWS_USERS_VIA_PORTAL, settle: 10000, deny: 'You need .*permission|not authorized|AccessDenied' }, { do: 'web.highlight', ctx: 'aws', target: { re: 'sam\\.rivera', row: true }, tag: 'Disabled' }, { do: 'stopwatch.stop' }] },

    // ===================================================================== 10
    { id: '10-run', piece: 10, write: true,
      say: ['Every step leaves a record.', 'One click files the proof.'],
      do: [{ do: 'gh.runWorkflow', workflow: 'evidence-pack.yml' }],
      wait: { check: 'evidenceDone', waiting: 'Filing the evidence (a few minutes)', ready: 'Filed',
        onReady: [{ do: 'web.open', url: (x) => x.evRun.url }] } },
    { id: '10-summary', piece: 10,
      say: ['The run says what it filed.'],
      // Preview 2 review: the run still showed "Queued" while this line played.
      // Camera off until the run's summary says "Evidence pack filed - N
      // records"; then the line, and the tag on that heading only.
      do: [{ do: 'web.open', url: (x) => x.evRun.url }, { do: 'web.waitFor', target: { re: '^Evidence pack filed', nth: 0 }, timeout: 300000 }, { do: 'web.highlight', target: { re: '^Evidence pack filed', nth: 0 }, tag: 'Filed' }] },
    { id: '10-store', piece: 10,
      // Preview 2 review: the evidence container's version-level immutability
      // is in its UNLOCKED (trial) setting, so "not even me" was not true.
      say: ["Here it is in the write-once store: a filed record can't be changed or deleted.", 'In the lab the lock stays in its trial setting; production locks it for good.', 'So an auditor can check it, instead of taking my word.'],
      do: [{ do: 'web.open', url: EVIDENCE, settle: 9000 }, { do: 'web.highlight', target: { text: 'evidence', exact: true, row: true }, tag: 'Write once (trial lock)' }] },

    // ===================================================================== 11
    // The tour (2026-11-07): read-only stops. PAM is Microsoft-native now
    // (lab ADR 0036): the Vault and Guacamole stops are replaced by one
    // Bastion stop that shows the real 2026-11-07 capture (lab PR #247).
    // Bastion is deleted after each capture (Premium costs $0.45 an hour), so
    // the stop shows the recorded playback, not a live portal.
    { id: '11-bastion', piece: 11,
      say: ['Piece eleven, a quick tour of the rest. First, recorded admin sessions.', 'An admin could not open the domain controller until she turned on her admin role in PIM, for one hour.', 'Then she connected through Azure Bastion, which recorded the whole session, and a second admin played it back.', 'Bastion runs only for a capture, because it costs forty-five cents an hour.'],
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.closeAll' }, { do: 'code.file', file: BASTION_SHOT }] },
    { id: '11-review', piece: 11,
      say: ['Who-has-what reviews.', 'Every quarter, a named reviewer group checks who can borrow each admin role.', 'Anything nobody vouches for is removed automatically. The first round found no standing admins to review.'],
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_ERM/DashboardBlade/~/Controls`, settle: 8000 }, { do: 'web.click', target: { text: 'Access reviews', exact: true } },
        { do: 'web.highlight', target: { text: 'Privileged access review: PIM-Tier1-Helpdesk', row: true }, tag: 'Every quarter; no answer = removed' }] },
    { id: '11-request', piece: 11,
      say: ['Requested extras.', 'Test User C asked for ICU float access, with a reason.', 'Her manager approved it, and it expires on its own after a hundred and eighty days.'],
      do: [{ do: 'web.open', url: PKGS, settle: 8000 }, { do: 'web.click', target: { text: 'ICU - Float Access', exact: true } }, { do: 'web.click', target: { text: 'Requests', exact: true } },
        { do: 'web.highlight', target: { text: 'Test User C', row: true }, tag: 'Manager approved; ends after 180 days' }] },
    { id: '11-sod', piece: 11,
      say: ['Some doors never open together.', 'Pharmacy is marked incompatible with the nurse and ICU packages, so no one can hold both.', "The system enforces it, not a manager's memory."],
      do: [{ do: 'web.open', url: PKGS, settle: 8000 }, { do: 'web.click', target: { text: 'Pharmacy - Controlled Substances Apps', exact: true } }, { do: 'web.click', target: { re: '^Separation of duties' } },
        { do: 'web.highlight', target: { text: 'Nurse - Clinical Apps', row: true }, tag: 'Never together' }] },
    { id: '11-passkey', piece: 11,
      say: ["Each IT staff member's separate admin login has a passkey registered. The rule that requires it is still report-only."],
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/UserAuthMethods/userId/3b1f4493-6390-4fd2-afcf-ac4e7fdc620c/hidePreviewBanner~/true`, settle: 8000 },
        { do: 'web.highlight', target: { text: 'Passkey', exact: true }, tag: 'Passkey (software)' }] },
    { id: '11-breakglass', piece: 11,
      say: ['The two emergency accounts sit outside every sign-in rule, so a bad rule can always be undone,', 'and any use raises an alarm.'],
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/7817077c-7e46-4a45-a599-7ddf685e9a9c`, settle: 8000 },
        { do: 'web.click', target: { text: 'All users included and specific users excluded', exact: true } }, { do: 'web.click', target: { text: 'Exclude', exact: true } },
        { do: 'web.highlight', target: { text: 'Break-Glass-Admins' }, tag: 'Left out of all 11 rules' }] },
    { id: '11-robots', piece: 11,
      say: ['Robot accounts: the identities apps use to talk to each other.', "The everyday apps have two named admins as owners; the pipeline's own identities answer to the platform owner, by role."],
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Owners/objectId/8c181694-e578-42b4-8f42-f2ad4fc8f3f1/appId/f152e129-4c0e-45b1-bb5b-f92837abbb70`, settle: 8000 },
        { do: 'web.highlight', target: { text: 'ADM Ava Lin', exact: true }, tag: 'Named owners' }] },
    { id: '11-okta', piece: 11,
      say: ['Okta is the login of a clinic the hospital bought, and it trusts Entra.', 'A clinic user signs in once with her hospital login, through Entra, and lands in Okta.'],
      do: [{ do: 'okta.signin' }, { do: 'private.highlight', target: [{ text: 'My Apps', exact: true }, { re: '^Clinic Scheduling' }], tag: 'Signed in through Entra' }] },
    // The tour's extra stops (2026-11-06): what PRs #209-#212, #214 and #215
    // added, in the "Contoso Demo" VS Code profile, read only. The window is
    // the lab at origin/main (cockpit/.tour-main) plus the live read-only
    // checks that tools/tour-extra-checks.sh writes to cockpit/tour/out just
    // before recording; every line below was checked against that output.
    // Things that are off are said as off. `node cockpit.mjs --tour-extra`
    // records these four alone.
    { id: '11-rbac', piece: 11, tour: true,
      say: ['Four more stops, all new today.', 'A checker for Kubernetes, the system that runs app containers, flags roles that could grab more power:', 'eleven risky rules in a planted bad file, none in the clean one.'],
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.closeAll' }, { do: 'code.file', file: tout('1-rbac-lint.txt'), line: 1 },
        { do: 'code.highlight', file: tout('1-rbac-lint.txt'), line: lineOf(tout('1-rbac-lint.txt'), /planted bad file/), endLine: lineOf(tout('1-rbac-lint.txt'), /clean file +:/) }] },
    { id: '11-selftest', piece: 11, tour: true,
      say: ['A scanner that never fails proves nothing.', 'So on every change, GitHub feeds the two security scanners a deliberately unsafe file.', 'Today, both caught it and passed the clean one.'],
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.closeAll' }, { do: 'code.file', file: tout('2-scanner-selftest-ci.txt'), line: 1 },
        { do: 'code.highlight', file: tout('2-scanner-selftest-ci.txt'), line: lineOf(tout('2-scanner-selftest-ci.txt'), /^fixtures\/bad/), endLine: lineOf(tout('2-scanner-selftest-ci.txt'), /^RESULT PASS/) }] },
    { id: '11-leak', piece: 11, tour: true,
      say: ['Next, a measured leak. Terraform, the blueprint tool, can read passwords from Azure Key Vault.', 'The usual way leaves the password in plain text in three of its files;', 'the ephemeral way, used and never kept, in none. Measured on November seventh, against a real key vault.'],
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.closeAll' }, { do: 'code.file', file: LEAK(c), line: 1 },
        { do: 'code.highlight', file: LEAK(c), line: lineOf(LEAK(c), /^path +terraform\.tfstate/), endLine: lineOf(LEAK(c), /^ephemeral +0/) }] },
    { id: '11-notyet', piece: 11, tour: true,
      say: ['Last, three things built and tested, not switched on yet:', 'Azure rules, report-only, for a new permanent Owner or a key vault without delete protection;', 'an AWS audit trail of who did what; and two alarms, for an admin idle two weeks signing in again,', 'or a burst of key vault secret reads. A read-only check just before recording: none is on.'],
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.closeAll' }, { do: 'code.file', file: tout('4-not-yet-on.txt'), line: 1 },
        { do: 'code.highlight', file: tout('4-not-yet-on.txt'), line: lineOf(tout('4-not-yet-on.txt'), /^RESULT: none/), endLine: lineOf(tout('4-not-yet-on.txt'), /^  Two new alarms +: off/) }] },
  ];
}

// =============================================================================
// v2 (2026-11-07): the 18 parts of segments/V2-RUNNING-ORDER.md, N00 to N17.
// `node cockpit.mjs --v2` walks these instead of the 11 pieces above.
//
// Every line is the v2 script's line (segments/<part>/script-v2.md), split
// into teleprompter lines; a [BRACKETED] part is a placeholder that is shown,
// never read out (the narration leaves it out). Each part names its lab
// guide stop(s); a VS Code part opens its stop with the bridge's openStop
// (readiness/lab-guide/stops.json), so VS Code shows that stop's tabs.
//
// Step fields added for v2 (lib/engine.mjs):
//   cloud     the step changes the lab (merge, apply, PIM activation, drill,
//             evidence run). --v2 --preview never does it: it runs `standIn`
//             (read-only screens of an earlier real run, labelled PREVIEW on
//             screen) and skips the step's wait. The HR test hire is the one
//             change a preview makes (and cleans up, readiness/hr-flow.md).
//   standIn   what --v2 --preview shows instead of a cloud step.
//   hold      seconds the step is held at least (a line the owner says in
//             his own words, with no narration clip).
// Parts carry `status` ('built' | 'pending'), `stops`, `sessions` (the
// sites checked before the part, off camera) and `autoRetake` (view-only:
// a FAILED step retakes the part once, automatically).
// PENDING BUILD parts (N11, N13, N15) are stubs: their lines are here, their
// screens are `todo` actions, and the cockpit refuses to run them.
// =============================================================================
import os from 'node:os';
import path from 'node:path';

const V2 = {
  demo: path.join(os.homedir(), 'contoso-demo'),
  stops: path.join(os.homedir(), 'contoso-demo', 'readiness', 'lab-guide', 'stops.json'),
  card: new URL('./ui/card.html', import.meta.url).pathname,
};
const HR_FORM = 'http://127.0.0.1:8484/';
// The demo window (the owner's two folders): v2 steps name it, so a part that
// follows a part in another window (N16's tour window) comes back to it.
const DEMO_WS = path.join(os.homedir(), 'contoso-demo', 'contoso-demo.code-workspace');
const IDC = 'https://us-east-1.console.aws.amazon.com/singlesignon/home?region=us-east-1#';
const viaPortal = (role, dest) => `https://d-90666212c7.awsapps.com/start/#/console?account_id=182002546409&role_name=${role}&destination=${encodeURIComponent(dest)}`;
const CA_POLICIES = `${E}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`;
const AWS_APP_OWNERS = `${E}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Owners/objectId/8c181694-e578-42b4-8f42-f2ad4fc8f3f1/appId/f152e129-4c0e-45b1-bb5b-f92837abbb70`;
const SPLUNK_PIM = 'http://127.0.0.1:8000/en-US/app/search/search?s=' + encodeURIComponent('Contoso - PIM activation (just-in-time elevation)') + '&earliest=0&latest=now';

// A script line as teleprompter lines: one sentence each, none over 120
// characters (long ones break at a comma or colon).
const S = (...texts) => texts.flatMap((t) => {
  const out = [];
  for (let x of t.split(/(?<=[.!?])\s+(?=[A-Z[])/)) {
    x = x.trim();
    while (x.length > 120) { const k = Math.max(x.lastIndexOf(', ', 118), x.lastIndexOf(': ', 118), x.lastIndexOf('; ', 118)); const cut = k > 40 ? k + 1 : 118; out.push(x.slice(0, cut).trim()); x = x.slice(cut).trim(); }
    if (x) out.push(x);
  }
  return out;
});
// A drawn screen (ui/card.html), the whole card in the URL's hash.
const cardUrl = (spec) => `file://${V2.card}#${Buffer.from(JSON.stringify(spec), 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
const card = (spec) => ({ do: 'card', url: cardUrl(spec), title: spec.title || spec.kicker || 'card' });
const banner = (text, ctx) => ({ do: 'banner', text, ctx });
// The setup map (stops 1-5) and the lab map (6-15), from the lab guide's
// stops.json; lit = the stop numbers (or tile indexes) to light.
const stopsJson = () => { try { return JSON.parse(fs.readFileSync(V2.stops, 'utf8')); } catch { return { stops: [] }; } };
const mapCard = (row, lit, sub) => {
  const st = stopsJson().stops.filter((s) => s.row === row);
  return card({ kicker: row === 'setup' ? 'The setup' : 'The lab', title: row === 'setup' ? 'The pieces, and how they connect' : 'The lab, in the order a person moves through it', sub,
    tiles: st.map((s) => ({ k: `Stop ${s.n}`, t: s.short || s.title })), lit: lit == null ? null : [].concat(lit).map((n) => st.findIndex((s) => s.n === n)).filter((i) => i >= 0) });
};
const SETUP_TILES = [{ k: 'Accounts', t: 'Entra ID' }, { k: 'Cloud', t: 'Azure' }, { k: 'Source', t: 'HR' }, { k: 'App', t: 'AWS' }, { k: 'App', t: 'ServiceNow' }, { k: 'App', t: 'Okta' }, { k: 'Code', t: 'GitHub' }];
const stop1 = (lit) => card({ kicker: 'Setup · stop 1', title: 'The accounts', tiles: SETUP_TILES, lit });
const CONNECT = ['HR', 'Active Directory', 'Entra ID', 'AWS + ServiceNow'];
// N07: the one-page table of the 24 rules, from that part's deep dive.
const rulesTable = () => {
  try {
    const rows = fs.readFileSync(path.join(V2.demo, 'segments', '08-second-camera-system', 'script-deep.md'), 'utf8').split('\n')
      .filter((l) => /^\| \d+ \|/.test(l)).map((l) => l.split('|').slice(1, -1).map((x) => x.trim()));
    return rows.length ? { head: ['#', 'Rule', 'What it catches'], rows } : null;
  } catch { return null; }
};
const todo = (what) => ({ do: 'todo', what });
// The v24 map: fly to a stop or tile (engine map.focus, window.__mapFocus).
const M = (target) => ({ do: 'map.focus', target });

export const PIECES_V2 = [
  { n: 0, slug: 'N00-intro', title: 'Who I am, and the whole lab on one map', status: 'built', stops: ['1-21'], sessions: [], autoRetake: true, reset: null },
  { n: 1, slug: 'N01-the-blueprints', title: 'The blueprints', status: 'built', stops: ['pipeline'], sessions: ['entra'], reset: 'blueprints' },
  { n: 2, slug: 'N02-hired', title: 'Hired', status: 'built', stops: ['hr-to-entra', 'people'], sessions: ['entra'], autoRetake: true, reset: null },
  { n: 3, slug: 'N03-one-account-two-directories', title: 'One account, two directories', status: 'built', stops: ['ad-to-entra'], sessions: ['entra'], autoRetake: true, reset: null },
  { n: 4, slug: 'N04-first-day-doors', title: 'First-day doors and the guard', status: 'built', stops: ['joiner', 'apps', 'signin'], sessions: ['entra'], autoRetake: true, reset: 'private-window' },
  { n: 4.5, slug: 'N04b-the-service-desk', title: 'The service desk: what staff ask IT for', status: 'built', stops: ['apps', 'joiner', 'leaver'], sessions: ['entra'], autoRetake: true, reset: null },
  { n: 5, slug: 'N05-the-master-key', title: 'The master key', status: 'built', autoRetake: true, stops: ['privileged'], sessions: [], reset: 'pim',
    after: [{ do: 'pim.deactivate', group: 'PIM-Tier1-Helpdesk', upn: 'adm-raj.patel@contosohealthlab.onmicrosoft.com', liveOnly: true }] },
  { n: 6, slug: 'N06-the-cameras', title: 'The cameras (Sentinel)', status: 'built', autoRetake: true, stops: ['detect'], sessions: ['entra', 'staff', 'teams'], reset: null },
  { n: 7, slug: 'N07-the-second-camera', title: 'The second camera (Splunk)', status: 'built', stops: ['detect'], sessions: ['splunk'], autoRetake: true, reset: null },
  { n: 8, slug: 'N08-leaving', title: 'Leaving', status: 'built', stops: ['leaver'], sessions: ['entra'], autoRetake: true, reset: null },
  { n: 9, slug: 'N09-the-logbook', title: 'The logbook', status: 'built', stops: ['proof'], sessions: ['entra'], autoRetake: true, reset: null },
  { n: 10, slug: 'N10-microsoft-features', title: 'The Microsoft features showcase', status: 'built', stops: ['joiner', 'signin', 'privileged'], sessions: ['entra'], autoRetake: true, reset: null },
  { n: 11, slug: 'N11-admin-passwords-and-sessions', title: 'Admin passwords and recorded sessions, the Microsoft way', status: 'built', autoRetake: true, stops: ['pam-microsoft'], sessions: [], reset: null },
  { n: 12, slug: 'N12-hardening-ad', title: 'Hardening Active Directory', status: 'built', stops: ['ad-hardening'], sessions: [], autoRetake: true, reset: null },
  { n: 13, slug: 'N13-adfs-to-entra', title: 'Moving an app off AD FS', status: 'built', autoRetake: true, stops: ['adfs'], sessions: [], reset: null },
  { n: 14, slug: 'N14-okta', title: 'Okta: the clinic the hospital bought', status: 'built', stops: ['okta', 'apps'], sessions: [], autoRetake: true, reset: null },
  { n: 15, slug: 'N15-aws-server-access-and-azure-least-privilege', title: 'Server access in AWS, and least privilege in Azure', status: 'built', autoRetake: true, stops: ['ssm-least-priv'], sessions: [], reset: null },
  { n: 16, slug: 'N16-code-checks', title: 'Checks that prove the code is safe', status: 'built', stops: ['delivery'], sessions: [], autoRetake: true, reset: null },
  { n: 17, slug: 'N17-close-vscode-github', title: 'Close: the whole lab from VS Code and GitHub', status: 'built', stops: ['delivery', 'pipeline'], sessions: [], autoRetake: true, reset: null },
];

// c.hire: who is hired in N02 and leaves in N08. Live: Sam Rivera, Cloud
// Engineer (needs N01's package applied). --v2 --preview: a clearly named
// test nurse (the nurse package exists today), labelled on screen, removed
// afterwards.
export function stepsV2(c) {
  const bp = (f) => `${c.bp}/${f}`;
  const tout = (f) => `${c.tourOut}/${f}`;
  const h = c.hire || { first: 'Sam', last: 'Rivera', dept: 'Information Technology', job: 'Cloud Engineer', pkg: 'IT - Cloud Engineering Apps', name: 'Sam Rivera' };
  const hireRe = h.name.replace(/\s+/g, '\\s+');
  const P = (t) => `PREVIEW · ${t}`;
  const ad = (f) => `${c.v2?.ad}/lab/evidence/ad-hardening/20261107T0057Z/${f}`;
  const okta = (f) => `${c.v2?.okta}/${f}`;
  const v2f = (k, f) => `${c.v2?.[k]}/${f}`;
  const BASTION = (f) => `file://${path.join(V2.demo, 'captures', 'bastion', '2026-11-07', f)}`;
  // N02/N08: the captured OrangeHRM run (2026-11-07, E170-E173) and OrangeHRM itself.
  const OHRMEV_F = (f) => path.join(V2.demo, 'captures', 'E170-E173-orangehrm', f);
  // OrangeHRM's own screens, recaptured for Sam Rivera (400104) with the connector stopped (nothing sent).
  const NURSEEV = (f) => `file://${path.join(V2.demo, 'captures', 'test-nurse-run-2026-11-07', f)}`;
  const RULES_MD = path.join(V2.demo, 'segments', '08-second-camera-system', 'script-deep.md');
  const SAMSIGNIN = path.join(V2.demo, 'captures', 'sam-signin-2026-11-07', 'sam-first-signin.json');
  const DRILLEV = (f) => `file://${path.join(V2.demo, 'captures', 'drill-2026-11-05', f)}`;
  const SAMHR = (f) => `file://${path.join(V2.demo, 'captures', 'orangehrm-sam-2026-11-07', f)}`;
  const OHRMEV = (f) => `file://${OHRMEV_F(f)}`;
  const OHRM_LIST = 'http://127.0.0.1:8585/web/index.php/pim/viewEmployeeList';
  const GHR = 'https://github.com/ChromeData/contoso-health-identity-lab';
  // N04b: the live proof's captured ServiceNow screens and read-back (PR #254 copy).
  const SNOWEV = (f) => `file://${c.v2?.snow}/lab/evidence/servicenow/${f}`;
  const SNOWRB = `${c.v2?.snow}/lab/evidence/servicenow/20261107T182703Z/readback.json`;
  return [
    // ================================================================= N00
    // The on-camera intro (2026-11-11): the only spoken part. The rest of the
    // video is silent captioned clips, so this walks every stop of the lab
    // guide (1-21) on the v24 map, in order: what it is, why it is there, and
    // what it hands to the next. Guide stop -> map target: 1-5 setup:1-5,
    // 6 tile:HR, 7-15 lab:6-14, 16-20 tile:KV/ADTIER/ADFS/OKTAMIG/SSM,
    // 21 delivery. Every fact is from the checked N01-N17 lines, the lab guide
    // (readiness/lab-guide/stops.json) or the lab repo.
    { id: 'n00-hello', piece: 0, hold: 14, say: S("Hi, I'm Michael.", "I'm an identity and privileged access engineer. I build IAM, PAM and cloud security labs, and this is my biggest one.", "IAM is identity and access management. PAM is privileged access management: how admin power is guarded."),
      hand: 'Say this in your own words (the owner on camera, over the map).', do: [M('overview')] },
    { id: 'n00-lab', piece: 0, say: S("This is my identity lab. It runs the logins and the access for Contoso Health, a made-up hospital of about five thousand staff. Identity means who you are. Access means what you may open."), do: [M('overview')] },
    { id: 'n00-four', piece: 0, say: S('The lab proves four things. Access follows HR. Admin power is borrowed, not kept. Misuse gets caught. And an auditor can check all of it.'), do: [M('overview')] },
    { id: 'n00-map', piece: 0, say: S("This map is the whole lab. The top row is how it was built. The bottom row is the lab running, from hire to leaving."), do: [M('overview')] },
    // guide 1: the sign-ups
    { id: 'n00-signups', piece: 0, say: S("Stop one: the sign-ups. Each piece is a real account, on a free trial or a free developer edition. AWS is pay as you go."), do: [M('setup:1')] },
    { id: 'n00-entra', piece: 0, say: S("The center is Microsoft Entra ID, Microsoft's cloud login. It is the work badge every other app trusts. A nurse signs in once, and the badge opens what she needs."), do: [M('setup:1.2')] },
    { id: 'n00-pieces', piece: 0, say: S("Around it: OrangeHRM for HR, ServiceNow for the IT service desk, and Azure, Microsoft's cloud. AWS, Amazon's cloud, and Okta trust the Entra login. GitHub holds the code, and builds the rest."), do: [M('setup:1')] },
    // guide 2: the pipeline
    { id: 'n00-pipeline', piece: 0, say: S("Stop two: the pipeline. The lab is written as code, and Terraform makes each real system match it. Every change is a pull request. GitHub runs a dry run and two security scans. Then nothing changes until I approve it."), do: [M('setup:2')] },
    { id: 'n00-gate', piece: 0, say: S("Why: an auditor sees what changed and who approved it. To be plain, the domain controller scripts, and fourteen applies from branches before merge, ran outside that gate. The change record lists each one."), do: [M('setup:2.3')] },
    // guide 3: the directory
    { id: 'n00-dc01', piece: 0, say: S("Stop three: the directory. Hospital PCs still sign in to Active Directory, an older on-site login system. Here it runs on DC01, a Windows server in Azure. Cloud Sync copies each account up to Entra, so one person has one login, on old PCs and in cloud apps."), do: [M('setup:3')] },
    // guide 4: the people
    { id: 'n00-people', piece: 0, say: S("Stop four: the people. Thirteen staff and three admins, all from HR. Each IT admin also has a separate admin account, only for admin work, so an everyday login never carries admin power."), do: [M('setup:4')] },
    // guide 5: the watchers
    { id: 'n00-watchers', piece: 0, say: S("Stop five: the watchers. A SIEM, a security information and event management system, collects logs and runs alarm rules on them. Microsoft Sentinel is one. I wrote the rules as code. Fifteen run there, plus Microsoft's Fusion rule. Each matches a technique in MITRE ATT&CK, a public catalog of how attackers work."), do: [M('setup:5')] },
    { id: 'n00-splunk', piece: 0, say: S("Splunk is another SIEM. It gets the same logs every five minutes, and twenty-two rules ran there. Why both: the rules move with the hospital, whichever tool it owns."), do: [M('setup:5.2')] },
    // guide 6: the HR form
    { id: 'n00-hr', piece: 0, say: S("Now the lab, in the order a person moves through it. It starts in HR. HR works in OrangeHRM, an open-source HR system that stands in for the hospital's own. HR sets the job, the department and the manager. There is no password field. Why: HR is the source of truth for who works here."), do: [M('tile:HR')] },
    // guide 7: HR to Entra
    { id: 'n00-feed', piece: 0, say: S("A connector reads one view of eight fields from HR, once each minute, so private HR data stays in HR. It signs in as a robot identity with no stored password. An agent on DC01 creates the account in Active Directory. In the test run, that took about a minute and a half."), do: [M('lab:6')] },
    // guide 8: Active Directory to Entra
    { id: 'n00-onelogin', piece: 0, say: S("Cloud Sync carries the account up to Entra. One account, one password, two directories. Disable it in Active Directory, and it is disabled in the cloud too."), do: [M('lab:7')] },
    // guide 9: access by job
    { id: 'n00-joiner', piece: 0, say: S("Access by job. An access package is a bundle of app access for one job, given on day one, with no ticket. Extras need a manager's approval, and they expire. Nurse and pharmacy packages are incompatible, so no one holds both."), do: [M('lab:8')] },
    // guide 10: the outside systems
    { id: 'n00-apps', piece: 0, say: S("The outside systems: AWS, ServiceNow and Okta. Entra creates the accounts in AWS and ServiceNow. Each app accepts only a sign-in that Entra signed. So one switch in Entra stops new sign-ins everywhere."), do: [M('lab:9')] },
    // guide 11: sign-in rules
    { id: 'n00-ca', piece: 0, say: S("Sign-in rules. Conditional Access, or CA, checks every sign-in: who, from where, and how it was proven. Nine rules are enforced, so a stolen password alone gets nobody in."), do: [M('lab:10')] },
    { id: 'n00-ca-report', piece: 0, say: S("New rules start report-only: they log what they would block, and block nothing. CA002, a phishing-proof sign-in for admins, and CA021, an extra check when the top admins switch on their power, are still report-only. Two emergency accounts sit outside every rule, so a bad rule can be undone."), do: [M('tile:CAPR')] },
    // guide 12: admin power
    { id: 'n00-pim', piece: 0, say: S("Admin power. PIM, Privileged Identity Management, lends it for a few hours, with a reason and a second check. When the time ends, it switches off on its own. Why: a stolen admin account that holds nothing gets nothing. In Entra, no IT admin holds an admin role all day. In Active Directory, four Domain Admin accounts are still standing, and PIM cannot reach them."), do: [M('lab:11')] },
    // guide 13: alarms
    { id: 'n00-detect', piece: 0, say: S("Alarms. My Sentinel rule caught that admin power-up and opened an incident, and the same rule runs in Splunk. Nothing is locked until a person approves it in Teams, because a wrong lockout can stop a nurse at a bedside."), do: [M('lab:12')] },
    // guide 14: leaving
    { id: 'n00-leaver', piece: 0, say: S("Leaving. HR ends the job, and in the test run Active Directory switched the account off within a minute. Entra, ServiceNow and AWS followed, each on its own sync. IT's leaver workflow is live, but its package removal has not passed its test yet."), do: [M('lab:13')] },
    // guide 15: proof
    { id: 'n00-proof', piece: 0, say: S("Proof. One click runs the evidence workflow. It files each record with a fingerprint, into a write-once store in Azure. In the lab, its lock stays in its unlocked trial mode, so the lab can be torn down. Why: an auditor can check, instead of taking my word."), do: [M('lab:14')] },
    // guide 16: admin passwords and recorded sessions
    { id: 'n00-kv', piece: 0, say: S("Now the newer pieces. Key Vault holds the lab's secrets, so no password sits in the code. Azure Bastion recorded an admin session for replay. It is created only to show that, then deleted, because it costs money every hour."), do: [M('tile:KV')] },
    // guide 17: hardening Active Directory
    { id: 'n00-tiers', piece: 0, say: S("Hardening Active Directory. A tier is a trust zone for admin work. A policy denies the top admin accounts any sign-in to lower-tier computers. Those tiers hold no computers yet, so today it denies nothing. PingCastle, a free scanner, scored the domain fifty-eight before and fifty after. Lower is better."), do: [M('tile:ADTIER')] },
    // guide 18: moving an app off AD FS
    { id: 'n00-adfs', piece: 0, say: S("AD FS, Active Directory Federation Services, is an older sign-in server. Its signing key can forge a sign-in for anyone, which is why companies move off it. One app's move off it, to Entra, is built and tested. The cut-over has not run yet."), do: [M('tile:ADFS')] },
    // guide 19: Okta
    { id: 'n00-okta', piece: 0, say: S("Okta is the login of a clinic the hospital bought. Moving its three apps to Entra is built. The cut-over has not run yet."), do: [M('tile:OKTAMIG')] },
    // guide 20: server access in AWS, least privilege in Azure
    { id: 'n00-ssm', piece: 0, say: S("Server access in AWS goes through Session Manager, only during a PIM loan, with no SSH key and no open port. SSH is the usual way to log in to a server. The test server ran, and was then torn down. In Azure, a narrow operator role can start a server but not change its network. It is borrowed through PIM too."), do: [M('tile:SSM')] },
    // guide 21: delivery
    { id: 'n00-delivery', piece: 0, say: S("Last, delivery. A scanner that never fails proves nothing, so on every change, GitHub feeds the scanners a deliberately unsafe file. More than a hundred and thirty changes are merged. Three things are built but switched off: Azure Policy in audit mode, an AWS audit trail, and two new alarms."), do: [M('delivery')] },
    // close
    { id: 'n00-close', piece: 0, say: S("I built this with an AI coding assistant, and I own every decision. The rest of this video shows each piece working, with on-screen text. Let's start."), do: [M('overview')] },

    // ================================================================= N01
    { id: 'n01-file', piece: 1, say: S('This is a Terraform file. Terraform reads it and makes Entra match it. The lab is built from many files like this one, plus scripts for what Terraform cannot set.'),
      do: [{ do: 'code.open', ws: DEMO_WS }, { do: 'code.stop', stop: 'pipeline' }, { do: 'code.changes', file: bp(VARS), line: 54 }] },
    { id: 'n01-block', piece: 1, say: S("This part lists the access packages. An access package is a bundle of apps that one job gets. This is where today's change starts."),
      do: [{ do: 'code.changes', file: bp(VARS), from: 50, to: 58 }] },
    { id: 'n01-nurse', piece: 1, say: S('Here is a real gap. Nurses had AWS access they never use. So I take AWS off the nurse package.'),
      do: [{ do: 'code.changes', file: bp(VARS), from: 60, to: 70 }] },
    { id: 'n01-cloud', piece: 1, say: S('Cloud engineers run the patient portal in AWS. So I add a package for them that has it.'),
      do: [{ do: 'code.changes', file: bp(VARS), from: 71, to: 95 }] },
    { id: 'n01-rules', piece: 1, say: S('This second tab is the rules file. It is JSON, not Terraform. A script reads it right after Terraform runs. This rule gives every cloud engineer that package on day one, from the job title HR sends.'),
      do: [{ do: 'code.changes', file: bp(RULES) }] },
    { id: 'n01-commit', piece: 1, write: true, cloud: true,
      say: S('Now I commit. A commit saves a change in my copy, with a note. In this graph, each dot is one commit. The top one is mine, and its note says why.'),
      do: [{ do: 'code.commit', folder: c.bp, files: [VARS, RULES], message: "Cloud engineers get AWS, nurses don't", allowBranch: c.bpBranchRe }, { do: 'code.command', id: 'workbench.view.scm' }],
      standIn: [{ do: 'code.command', id: 'workbench.view.scm' }] },
    { id: 'n01-push', piece: 1, write: true, cloud: true, say: S('Then I push. A push sends my commits to GitHub.'),
      do: [{ do: 'code.push', folder: c.bp, branch: c.bpBranch }], standIn: [{ do: 'code.command', id: 'workbench.view.scm' }] },
    { id: 'n01-pr', piece: 1, write: true, cloud: true,
      say: S('Now the change is on GitHub. This page is the pull request. It asks: please add my change to the main copy. Nothing in the lab changes yet.'),
      do: [{ do: 'gh.createPr', branch: c.bpBranch, title: c.prTitle, body: c.prBody }, { do: 'web.open', url: (x) => x.pr.url }],
      wait: { check: 'prChecks', waiting: 'GitHub is testing the change (about 3 minutes)', ready: 'Tests done, plan posted' },
      standIn: [{ do: 'web.open', url: (x) => x.pr.url }] },
    { id: 'n01-checks', piece: 1, say: S("GitHub Actions runs the checks on GitHub's own machines. First a plan: a dry run against the real tenant, with a read-only identity. It lists what would change, and changes nothing."),
      do: [{ do: 'web.open', url: (x) => `${x.pr.url}/checks` }, { do: 'web.highlight', target: [{ re: '^Terraform plan', nth: 0 }, { re: 'plan', nth: 0 }], tag: 'The plan: a dry run' }] },
    { id: 'n01-scanners', piece: 1, say: S('Then the automated tests, and two scanners. Checkov looks for unsafe settings. TruffleHog looks for passwords left in the code. Green means each check passed.'),
      do: [{ do: 'web.open', url: (x) => x.pr.url }, { do: 'web.highlight', target: { re: 'All checks have passed|checks? passed|successful checks', block: 'div' }, tag: 'Tests and two scanners: green' }] },
    { id: 'n01-plan', piece: 1, say: S('The plan comment says it in plain words. One new package for cloud engineers. AWS comes off the nurse package. Nothing else changes.'),
      do: [{ do: 'web.open', url: (x) => x.planUrl || x.pr.url }, { do: 'web.highlight', target: { re: 'What this change does', block: "*[contains(@class,'comment-body')]" }, tag: 'In plain words' }] },
    { id: 'n01-merge', piece: 1, write: true, cloud: true, say: S('A teammate would review it here. I merge it, and that starts the build.'),
      do: [{ do: 'gh.merge' }],
      wait: { check: 'approvalIssue', waiting: 'The build is getting ready (about 3 minutes to the approval request)', ready: 'Approval request is open' },
      standIn: [{ do: 'web.open', url: (x) => x.pr.url }] },
    // PENDING BUILD (N01 note): Review deployments is not available on this
    // private repo (readiness/approve-howto.md); the gate is the "Approve:
    // apply" issue, and PR #228 (open) makes the owner name the exact saved
    // plan. The approval is ALWAYS the owner's own hand, never the cockpit's.
    { id: 'n01-gate', piece: 1, cloud: true,
      say: S('The build stops and waits for me. I check the plan it will apply, and I approve it in GitHub. Only then does Terraform change the tenant.'),
      hand: 'Approve in GitHub yourself: open the run, click Review deployments, then Approve and deploy.',
      do: [{ do: 'web.open', url: (x) => x.issue.url }, { do: 'web.highlight', target: { re: 'is waiting for a human decision|waiting for' }, tag: 'The human gate' }, { do: 'web.focus', target: { css: 'textarea' } }],
      wait: { check: 'applyDone', waiting: 'Waiting for your approval, then building (about 4 minutes)', ready: 'Built: the change is live', onReady: [{ do: 'web.open', url: (x) => x.applyRun.url }] },
      standIn: [{ do: 'web.open', url: (x) => x.issue.url }] },
    { id: 'n01-applied', piece: 1, say: S('Approved and built. The run says what changed.'),
      do: [{ do: 'web.open', url: (x) => x.applyRun.url }, { do: 'web.highlight', target: { re: 'Applied:' }, tag: 'What changed' }] },
    { id: 'n01-entra', piece: 1, cloud: true, say: S('In Entra, this list is where the new package appears once it is built, next to the nurse package without AWS.'),
      do: [{ do: 'web.open', url: PKGS, settle: 6000 }, { do: 'web.highlight', target: { text: 'IT - Cloud Engineering Apps', row: true }, tag: 'New' }],
      standIn: [{ do: 'web.open', url: PKGS, settle: 6000 }] },
    { id: 'n01-strip', piece: 1, say: S('So, in ten seconds. Change the file. Commit. Push. Pull request. Checks. Merge. My approval. Terraform builds it. Entra shows it.'),
      do: [M('setup:2')] },

    // ================================================================= N02
    // OrangeHRM (PR #255, ADR 0028; readiness/hr-flow.md). HR clicks in
    // OrangeHRM by hand in the take (the presenter, or hr-clicks.mjs). A
    // preview hires nobody: it shows the captured OrangeHRM run of
    // 2026-11-07 (captures/E170-E173-orangehrm) and the real chain after it.
    // Times: AD about 1.5 min after HR's save; Entra "on its next sync cycle".
    { id: 'n02-hr', piece: 2, say: S("This is where hiring starts. HR works in OrangeHRM, a real HR system, the open-source edition. It runs on this Mac and stands in for the hospital's own HR system."), do: [M('tile:HR')] },
    { id: 'n02-list', piece: 2, cloud: true, say: S("This is HR's employee list: each worker's number, job, department and manager. Numbers come from the hospital's ranges, and IT numbers start with 400."),
      hand: 'OrangeHRM (signed in before recording, zoom 110%): PIM > Employee List.',
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 2000 }], standIn: [{ do: 'web.show', url: SAMHR('hire-01-employee-list.png'), settle: 400 }] },
    { id: 'n02-add', piece: 2, cloud: true, say: S('HR types his first and last name and his employee number, 400104.'),
      hand: 'PIM > Add Employee: Sam, Rivera, Employee Id 400104 (replace the pre-filled counter), Save.',
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 1000 }], standIn: [{ do: 'web.show', url: SAMHR('hire-02-add-employee.png'), settle: 400 }] },
    { id: 'n02-job', piece: 2, cloud: true, say: S('On the Job tab, HR sets the start date, the job title and the department. There is no password field. HR never sees one.'),
      hand: 'Add Employee: Sam Rivera, Employee Id 400104, Save. Job tab: Joined Date today, Job Title Cloud Engineer, Sub Unit Information Technology, Full-Time Permanent, Save.',
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 1000 }], standIn: [{ do: 'web.show', url: SAMHR('hire-03-job.png'), settle: 400 }] },
    { id: 'n02-manager', piece: 2, cloud: true, say: S('On the Report-to tab, HR sets the manager. Nothing goes to IT until the job and the manager are both saved, so the hire goes out once, complete.'),
      hand: 'Report-to tab: Assigned Supervisors + Add, Joan Ferris, Direct, Save. This Save is the last HR click.',
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 1000 }], standIn: [{ do: 'web.show', url: SAMHR('hire-04-report-to.png'), settle: 400 }] },
    { id: 'n02-saved', piece: 2, cloud: true, say: S('HR saves. That is the last click a person makes.'),
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 1000 }], standIn: [{ do: 'web.show', url: SAMHR('hire-05-report-to-saved.png'), settle: 400 }] },
    { id: 'n02-connector', piece: 2, say: S("Within a minute, a connector picks up the change and sends it on, through HR-SYNC, a robot identity with no stored password. The connector itself still needs a GitHub sign-in to write the change. This log is from a test run of the same chain, with a test worker."),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: OHRMEV_F('connector.log'), line: lineOf(OHRMEV_F('connector.log'), /SEND {2}hire/), endLine: lineOf(OHRMEV_F('connector.log'), /ACCEPTED {2}HR: hire/), highlight: true }] },
    { id: 'n02-least', piece: 2, say: S("The connector reads one view of eight fields and nothing else. Asking it for a birthday or a salary is refused. HR's private data stays in HR."),
      do: [{ do: 'code.file', file: OHRMEV_F('least-data-proof.txt'), line: 1, endLine: 6, highlight: true }] },
    { id: 'n02-run', piece: 2, say: S("Here is the test run's send on GitHub. Microsoft's HR provisioning API answered: accepted."),
      do: [{ do: 'web.open', url: `${GHR}/actions/runs/42398357477`, settle: 4000 }] },
    { id: 'n02-ad', piece: 2, say: S("Microsoft's provisioning agent on DC01 creates the account in Active Directory. In the test run, that took about a minute and a half from HR's last click."),
      do: [{ do: 'code.file', file: OHRMEV_F('watch-hire.log'), line: 1, endLine: 2, highlight: true }] },
    { id: 'n02-entra', piece: 2, say: S("Entra picks it up on its next sync cycle. In the test run, group rules, the access package for the job, ServiceNow and AWS then followed, each on its own schedule."),
      do: [{ do: 'code.file', file: OHRMEV_F('watch-hire.log'), line: 3, endLine: lineOf(OHRMEV_F('watch-hire.log'), /AWS IdC user/), highlight: true }] },
    { id: 'n02-follow', piece: 2, say: S('From here on, nobody touches it. Nobody creates an account by hand.'), do: [M('lab:8')] },

    // ================================================================= N03
    { id: 'n03-sam', piece: 3, say: S('Sam now lives in two directories. Active Directory, for hospital PCs and older systems. And Entra, for cloud apps.'),
      do: [{ do: 'find', what: 'sam' }, { do: 'web.open', url: userPage, settle: 6000 }, { do: 'web.click', target: { role: 'tab', name: 'Properties' } }, { do: 'web.highlight', target: { re: '^On-premises sync enabled', widen: 220 }, tag: 'One account, both places' }] },
    { id: 'n03-sync', piece: 3, say: S('Cloud Sync keeps them as one account, with one password. Disable him in Active Directory, and he is disabled in the cloud too.'),
      do: [M('tile:SYNC')] },
    { id: 'n03-agent', piece: 3, say: S("I chose Cloud Sync over the older Connect Sync because it is a light agent. The same agent also carries HR's hires into Active Directory."),
      do: [M('tile:AGENT')] },

    // ================================================================= N04
    // v24 (2026-11-07): Sam (a Cloud Engineer) has no package until N01's
    // change is applied (the owner's approval), so AWS and ServiceNow are shown
    // from the earlier real test-nurse run (captures/test-nurse-run-2026-11-07),
    // and the lines say so. Sam's own first sign-in and his Conditional Access
    // log are real. Timings: hr-flow.md (ServiceNow ~27 min, AWS ~46 min).
    { id: 'n04-package', piece: 4, say: S("Sam's job decides his access on day one. No ticket. Sam's own cloud-engineer access arrives once the change from part one is approved."), do: [M('tile:BIRTH')] },
    { id: 'n04-nurse', piece: 4, say: S("In a test run, a nurse was hired the same way. Her job's package was added by itself, by policy."), do: [{ do: 'web.show', url: NURSEEV('01-nurse-package-assignment.png'), settle: 400 }] },
    { id: 'n04-trust', piece: 4, say: S("AWS trusts Entra through IAM Identity Center, AWS's sign-in hub. Entra creates each user there, because the package puts them in the AWS app group."), do: [M('tile:SSO')] },
    { id: 'n04-aws', piece: 4, say: S('The nurse signed in to the AWS access portal with the hospital login.'), do: [{ do: 'web.show', url: NURSEEV('02-aws-access-portal.png'), settle: 400 }] },
    { id: 'n04-portal', piece: 4, say: S('This is the patient portal the cloud team runs. In the lab it is a stand-in: one private storage bucket, with no patient data. Her access is read-only. That is least privilege: the smallest access that does the job.'),
      do: [{ do: 'web.show', url: NURSEEV('03-aws-patient-portal-readonly.png'), settle: 400 }] },
    { id: 'n04-snow', piece: 4, say: S('ServiceNow got her account on its own, from Entra.'), do: [{ do: 'web.show', url: NURSEEV('04-servicenow-created-by-entra.png'), settle: 400 }] },
    { id: 'n04-snow-own', piece: 4, say: S('Same hospital login, no second password. In test runs, ServiceNow came within about half an hour, and AWS within about forty-five minutes.'),
      do: [{ do: 'web.show', url: NURSEEV('05-servicenow-signed-in.png'), settle: 400 }] },
    { id: 'n04-signin', piece: 4, write: true,
      say: S('Now Sam himself. He signs in for the first time with a Temporary Access Pass. That is a one-time code IT issues for a first sign-in. It also counts as his second check.'),
      do: [{ do: 'tap.signin', who: 'sam', url: 'https://myapps.microsoft.com/' }], preview: [{ do: 'preview.secondCheck' }],
      hand: 'If Microsoft asks Sam to set up a second check, answer it on screen (Ask later / Skip setup).' },
    // Preview: the presenter's portal view of sign-in logs answered 401 on
    // 2026-11-07, so a preview shows Sam's real first sign-in as Entra logged
    // it (read-only by the lab operator: captures/sam-signin-2026-11-07).
    { id: 'n04-guard', piece: 4, say: S("Now the guard. Conditional Access rules check every sign-in: who, from where, and how it was proven. Sam's sign-in log lists each rule that looked at him."),
      previewSay: S("Now the guard. Conditional Access rules check every sign-in: who, from where, and how it was proven. This is Sam's real first sign-in from earlier, as Entra logged it: the one-time pass, then each rule that looked at him."),
      previewStandIn: true, standIn: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: SAMSIGNIN, line: lineOf(SAMSIGNIN, /"authenticationDetails"/), endLine: lineOf(SAMSIGNIN, /"Temporary Access Pass"/) + 2, highlight: true }],
      do: [{ do: 'require', check: 'samSignin' }, { do: 'activate', app: 'browser' }, { do: 'find', what: 'sam' }, { do: 'web.open', url: userPage, settle: 6000 }, { do: 'web.click', target: { text: 'Sign-in logs', exact: true } }, { do: 'signin.openTap' },
        { do: 'web.click', target: [{ role: 'tab', name: 'Conditional Access' }, { text: 'Conditional Access', exact: true, nth: 1 }], timeout: 20000 }, { do: 'web.highlight', target: { re: 'Require MFA for all users', row: true }, tag: 'Every rule that looked at him' }] },
    { id: 'n04-ca', piece: 4, lineWithAction: true, say: S('CA001 asks everyone for a second check. CA003 blocks old sign-in methods that cannot do one. Both are enforced.'),
      previewSay: S('CA001 asks everyone for a second check, and his pass met it. CA003 blocks old sign-in methods that cannot do one. Both are enforced.'),
      previewStandIn: true, standIn: [{ do: 'code.file', file: SAMSIGNIN, line: lineOf(SAMSIGNIN, /CA001 - Require MFA/) - 1, endLine: lineOf(SAMSIGNIN, /CA003 - Block legacy/) + 1, highlight: true }],
      do: [{ do: 'web.highlight', target: { re: 'CA001 - Require MFA for all users', row: true }, tag: 'CA001: Success' }, { do: 'pause', ms: 3500 }, { do: 'web.highlight', target: { re: 'CA003 - Block legacy authentication', row: true }, tag: 'CA003: enforced' }] },
    { id: 'n04-why', piece: 4, say: S('Why these rules? HIPAA requires each person to be proven. NIST and the CIS Controls name a second check as the standard way. So a stolen password alone must not work.'), do: [M('lab:10')] },

    // ================================================================= N04b
    // ServiceNow depth (readiness/servicenow-depth.md, PR #254, read-only copy
    // .v2/snow). The tickets of the live proof (2026-11-07) were deleted after
    // it, so a preview shows its captured ServiceNow screens and its read-back;
    // the take runs it live after the owner applies #254. ServiceNow asks,
    // Entra decides and grants: never "ServiceNow grants".
    { id: 'n04b-desk', piece: 4.5, say: S("This is ServiceNow, the hospital's IT service desk. Every staff member has it, through the hospital login, so there is no second password."), do: [M('tile:SNOW')] },
    { id: 'n04b-ask', piece: 4.5, say: S('What do staff ask IT for? Three things, most days. Access to an app. Help when they cannot sign in. And, for managers: this person is leaving.'), do: [M('tile:SNOWREQ')] },
    { id: 'n04b-form', piece: 4.5, say: S('Sofia is a nurse. She will cover ICU night shifts for two weeks, so she asks for the ICU apps. She gives a reason and an end date. No patient details go in here.'),
      do: [{ do: 'web.show', url: SNOWEV('20261107T182703Z/01-nurse-request-form.png'), settle: 400 }] },
    { id: 'n04b-req', piece: 4.5, say: S('She gets a request number. Now her manager must say yes.'), do: [{ do: 'web.show', url: SNOWEV('20261107T182703Z/02-nurse-request-submitted.png'), settle: 400 }] },
    { id: 'n04b-approve', piece: 4.5, say: S('Grace is her manager. ServiceNow knows that because Entra sends it, from HR. So there is one org chart, not two. Grace approves.'),
      do: [{ do: 'web.show', url: SNOWEV('20261107T182703Z/03-manager-my-approvals.png'), settle: 400 }] },
    { id: 'n04b-sent', piece: 4.5, say: S("Now ServiceNow asks Entra to grant it. ServiceNow grants nothing itself. It asks for Entra's access package, ICU float access, with the ticket number as the reason. Entra adds her within a few minutes, and the ticket closes by itself."),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: SNOWRB, line: lineOf(SNOWRB, /"work_notes"/), endLine: lineOf(SNOWRB, /Closed automatically/), highlight: true }] },
    { id: 'n04b-why', piece: 4.5, say: S("Entra's record names the ticket and the manager. The access ends by itself on the end date. ServiceNow's app holds one role on one catalog: it may add or remove people on any package in the Clinical catalog. If ServiceNow were broken into, that catalog would be too. It signs in with a certificate, not a password."),
      do: [{ do: 'code.file', file: SNOWRB, line: lineOf(SNOWRB, /"justification"/), endLine: lineOf(SNOWRB, /"requestor"/), highlight: true }] },
    { id: 'n04b-test', piece: 4.5, say: S('This run used a test app, deleted afterwards. The lasting app is built as code, and goes live when I approve its change.'),
      do: [{ do: 'web.open', url: PKGS, settle: 6000 }, { do: 'web.highlight', target: [{ text: 'ICU - Float Access', row: true }, { re: '^ICU - Float', row: true }], tag: 'The package she asked for' }] },
    { id: 'n04b-queue', piece: 4.5, say: S('Ava is the IAM engineer. This is her queue: whatever automation cannot finish. Here a nurse in ICU asked for pharmacy dispensing. Her manager said yes. Entra said no. ICU and pharmacy dispensing are a forbidden pair, so one person cannot hold both. Nothing was granted.'),
      do: [{ do: 'web.show', url: SNOWEV('20261107T185146Z/20-iam-queue.png'), settle: 400 }] },
    { id: 'n04b-inc', piece: 4.5, say: S('A sign-in ticket. Marcus lost his phone, so his second check is gone. Raj on the help desk takes it. In the next part, Raj types a ticket number as his reason when he switches on his admin power.'),
      do: [{ do: 'web.show', url: SNOWEV('20261107T180451Z/20-iam-queue.png'), settle: 400 }] },
    { id: 'n04b-leaver', piece: 4.5, say: S("When someone leaves, Entra's leaver workflow removes the standard access. The extras someone asked for, Ava removes from here, with one button."),
      do: [{ do: 'web.show', url: SNOWEV('20261107T180451Z/10-iam-leaver-task.png'), settle: 400 }] },
    { id: 'n04b-leaver-sent', piece: 4.5, say: S('Again, the task number goes into Entra.'), do: [{ do: 'web.show', url: SNOWEV('20261107T180451Z/11-iam-leaver-task-sent.png'), settle: 400 }] },
    { id: 'n04b-report', piece: 4.5, say: S('And the IAM lead sees it all in one list: requests by status, and how long each took.'),
      do: [{ do: 'web.show', url: SNOWEV('20261107T185146Z/21-access-requests-by-status.png'), settle: 400 }] },
    { id: 'n04b-close', piece: 4.5, say: S('So staff ask, managers approve, Entra decides, and the IAM queue catches the rest.'), do: [M('tile:SNOWQ')] },

    // ================================================================= N05
    { id: 'n05-signin', piece: 5, write: true, say: S('Raj works on the help desk. This is his own admin account, adm-raj.patel. Nobody shares it, so the log always shows who acted.'),
      do: [{ do: 'identity.signin', id: 'adm-raj.patel', fallback: 'raj', url: `${E}Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup` }] },
    { id: 'n05-eligible', piece: 5, say: S('It holds no admin power until he switches it on. The tool for that is PIM, Privileged Identity Management.'),
      do: [{ do: 'private.highlight', target: { text: 'PIM-Tier1-Helpdesk', row: true }, tag: 'Eligible: he may borrow it' }] },
    // Karen A4: Raj's reason names a REAL ServiceNow incident (--raj-ticket).
    { id: 'n05-activate', piece: 5, write: true, cloud: true,
      say: S('He switches on help-desk power for his shift, up to eight hours. He types a reason and passes a second check.'),
      previewSay: S('Here he would switch on help-desk power for his shift, up to eight hours, with a reason and a second check. A preview does not switch it on.'),
      do: [{ do: 'require', check: 'rajTicket' }, { do: 'private.click', target: { role: 'button', name: 'Activate', exact: true } }, { do: 'private.type', target: { css: 'textarea' }, text: (x) => `${x.rajTicket}: help-desk shift` }, { do: 'private.click', target: { role: 'button', name: 'Activate', exact: true, nth: 1 } }],
      standIn: [{ do: 'private.highlight', target: { role: 'button', name: 'Activate', exact: true }, tag: 'Activate: a reason, then a second check' }] },
    { id: 'n05-active', piece: 5, cloud: true, say: S('It is on now, with an end time. When that passes, it switches off on its own.'),
      do: [{ do: 'pim.showActive', group: 'PIM-Tier1-Helpdesk', tag: 'Active, ends on its own' }],
      previewSay: S('In an earlier run, Ava borrowed admin power the same way. Here it shows as active. When its hour passes, it switches off on its own.'),
      standIn: [{ do: 'web.show', url: BASTION('proof-admin/04-pim-active.png'), settle: 400 }] },
    { id: 'n05-why', piece: 5, say: S("Why? A stolen admin account that holds nothing gets nothing. This is least privilege and just-in-time access, from NIST and Microsoft's own privileged access guidance."),
      do: [M('tile:PIM')] },
    { id: 'n05-exceptions', piece: 5, say: S('In Entra, no IT admin holds an admin role all day. The exceptions are the build account, the two emergency accounts, and the robot identities that build and run the lab. In Active Directory, four Domain Admin accounts are still standing, and PIM cannot reach them.'),
      do: [M('tile:BG')] },
    { id: 'n05-keys', piece: 5, say: S("In the lab I play every person, so one machine holds the test accounts' keys. In a hospital, Raj holds his own hardware key."),
      do: [M('tile:HDAU')] },

    // ================================================================= N06
    { id: 'n06-header', piece: 6, say: S("This is an alarm rule. It is a file in the repo, written in KQL, Microsoft's language for searching logs. The header says what it catches and which log it reads."),
      do: [{ do: 'code.open', ws: DEMO_WS }, { do: 'code.stop', stop: 'detect' }, { do: 'code.file', file: bp('lab/kql/pim-activation.kql'), line: 5, endLine: 20, highlight: true }] },
    { id: 'n06-filter', piece: 6, say: S('The query reads the AuditLogs table, where PIM writes every activation. It keeps the ones that completed.'),
      do: [{ do: 'code.highlight', file: bp('lab/kql/pim-activation.kql'), line: 58, endLine: 67 }] },
    { id: 'n06-output', piece: 6, say: S('It returns who, which role, the reason given, and when. The rule carries its MITRE ATT&CK tag: valid accounts, used to gain more power.'),
      do: [{ do: 'code.highlight', file: bp('lab/kql/pim-activation.kql'), line: 86, endLine: 90 }] },
    { id: 'n06-strip', piece: 6, say: S('How does it get into Sentinel? Terraform reads every rule file and creates one Sentinel rule from each. It ships through the same pull request and approval as everything else.'),
      do: [M('tile:LA')],
      wait: { check: 'pimIncident', waiting: "Waiting for the alarm on Raj's activation (the rule runs every 5 minutes; about 13 minutes last time)", ready: 'The incident is there' } },
    // 07.4: the incident's Alerts tab first, then the user. A preview has no
    // activation of its own: pimIncident then finds the newest earlier
    // incident about Raj (read only), and the banner says so.
    { id: 'n06-incident', piece: 6, say: S("Raj's activation wrote a row in AuditLogs. The rule runs every five minutes. It found the row, and Sentinel opened this incident. Last time, that took about thirteen minutes end to end."),
      previewSay: S("This incident is from an earlier activation of Raj's. It wrote a row in AuditLogs. The rule runs every five minutes, found the row, and Sentinel opened this incident."),
      do: [{ do: 'web.open', url: (x) => `https://security.microsoft.com/incidents/${x.pimIncident.providerIncidentId}/alerts?tid=86a2e327-4951-4348-a3c4-6f4b79ffd8f2`, settle: 12000 },
        { do: 'web.click', target: [{ role: 'tab', name: /^Alerts/ }, { re: '^Alerts \\(\\d+\\)$', nth: 0 }], timeout: 20000, settle: 4000 },
        { do: 'web.highlight', target: [{ re: '^Contoso - PIM activation', nth: 0, row: true }, { re: 'PIM activation \\(just-in-time', nth: 1, row: true }], tag: 'The alert' }] },
    { id: 'n06-entities', piece: 6, say: S("The alert names Raj's account and shows his reason. Here, every activation opens an incident. At hospital scale that is too noisy, so a pending change raises only the risky ones."),
      do: [{ do: 'web.click', target: [{ role: 'tab', name: /^Assets/ }, { re: '^Assets \\(\\d+\\)$', nth: 0 }], timeout: 20000, settle: 4000 },
        { do: 'web.click', target: { re: '^Users \\(\\d+\\)$', nth: 0 }, settle: 4000 },
        { do: 'web.highlight', target: [{ re: '^ADM Raj Patel$', nth: 0 }, { re: 'adm-raj\\.patel', nth: 0 }], tag: 'Raj, who switched it on' }] },
    // The drill (slice 5): a throwaway itdr-drill account and one test
    // incident. Arming it creates both: a lab change, so a preview shows the
    // newest answered drill card instead.
    { id: 'n06-drill', piece: 6, write: true, cloud: true, say: S('Next is a drill. A script makes a throwaway account and raises one test incident about it. Nothing was stolen.'),
      do: [{ do: 'drill.ensure' }, { do: 'require', check: 'drillPending' }, { do: 'teams.guard', phase: 'before' }, { do: 'web.open', ctx: 'staff', url: SOC_CHANNEL, settle: 12000 }, { do: 'teams.guard', phase: 'after' }],
      standIn: [{ do: 'web.show', url: DRILLEV('01-drill-card-contain.png') }],
      previewSay: S('Next is a drill. A script makes a throwaway account and raises one test incident about it. This is the card from an earlier drill, on November fifth. Nothing was stolen.') },
    { id: 'n06-contain', piece: 6, write: true, cloud: true,
      say: S('The alert goes to the security team in Teams. The playbook never acts on its own. A person must press Contain, because a wrong lockout of a clinician hurts patient care.'),
      hand: 'Press "Contain (revoke + disable)" on the card.',
      do: [{ do: 'web.highlight', ctx: 'staff', target: [{ css: 'button', hasText: /^Contain \(revoke \+ disable\)$/, last: true }, { role: 'button', name: /^Contain \(revoke \+ disable\)$/ }], tag: 'Nothing happens until someone says yes' }],
      wait: { check: 'drillContained', waiting: 'Waiting for your Contain on the card (still recording)', ready: 'Drill account switched off' },
      previewSay: S('The alert goes to the security team in Teams. The playbook never acts on its own. A person must press Contain, because a wrong lockout of a clinician hurts patient care. A preview presses nothing.'),
      standIn: [{ do: 'web.show', url: DRILLEV('01-drill-card-contain.png') }] },
    { id: 'n06-contained', piece: 6, needs: 'drill', cloud: true,
      say: S('Approved. The drill account is signed out everywhere and switched off. The decision is written on the incident and on the ServiceNow ticket.'),
      do: [{ do: 'require', check: 'drillContained' }, { do: 'web.highlight', ctx: 'staff', target: (x) => [...(x.drill?.cardMark ? [{ css: `[data-ck-decided="${x.drill.cardMark}"] div`, hasText: /^Decision recorded/, last: true }] : []), { css: 'div', hasText: /^Decision recorded/, last: true }], tag: 'Done, with a name on it' }],
      previewSay: S('In an earlier drill, a person approved. The drill account was signed out everywhere and switched off, and the decision was written on the incident and on the ServiceNow ticket.'),
      standIn: [{ do: 'web.show', url: DRILLEV('02-decision-recorded.png') }] },

    // ================================================================= N07
    { id: 'n07-rule', piece: 7, say: S("Here is the same rule in SPL, Splunk's search language. Each KQL rule has an SPL twin."),
      do: [{ do: 'code.open', ws: DEMO_WS }, { do: 'code.stop', stop: 'detect' }, { do: 'code.file', file: bp('lab/splunk/detections/pim-activation.spl'), line: 73, endLine: 74, highlight: true }] },
    { id: 'n07-strip', piece: 7, say: S('A script turns the SPL files into Splunk settings and loads them. This Splunk runs on my Mac. Every five minutes it pulls the tenant\'s logs from Azure.'),
      do: [M('tile:SPLUNK')] },
    { id: 'n07-run', piece: 7, say: S("It finds Raj's activation too. Twenty-two rules ran here at recording, and each one fired on test events."),
      do: [{ do: 'web.open', url: SPLUNK_PIM, settle: 8000 }, { do: 'web.find', target: { re: '^[1-9][\\d,]* (events?|results?)\\b', nth: 0 }, timeout: 45000 }, { do: 'web.highlight', target: { re: 'adm-raj\\.patel', nth: 0 }, tag: "It found Raj's activation" }],
      // The rule looks back one hour: only a take with Raj's activation (N05)
      // within the hour has his row. A preview activates nothing, so it shows
      // the live search and its count, labelled.
      previewStandIn: true,
      standIn: [{ do: 'web.open', url: SPLUNK_PIM, settle: 8000 }, { do: 'web.highlight', target: { re: '^\\d[\\d,]* (events?|results?)\\b', nth: 0 }, tag: 'The same rule, on the live log' }],
      previewSay: S("This is the same rule, run on the live log. Twenty-two rules ran here at recording, and each one fired on test events.") },
    { id: 'n07-both', piece: 7, say: S('Most hospitals run one SIEM. Building both shows the rules move with the hospital, whichever tool it owns.'), do: [] },
    { id: 'n07-table', piece: 7, say: S('This table lists all twenty-four rules and what each one catches. It is in the lab guide.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: RULES_MD, line: lineOf(RULES_MD, /^\| 1 \|/) - 2, endLine: lineOf(RULES_MD, /^\| 24 \|/), highlight: true }] },

    // ================================================================= N08
    // OrangeHRM leaver (readiness/hr-flow.md): HR to Active Directory took
    // 39 s; Entra on its next Cloud Sync cycle. A preview shows the captured
    // run of 2026-11-07. Do not say "a leaver gets no new access" (the ICU
    // package gap in hr-flow.md).
    { id: 'n08-record', piece: 8, cloud: true, say: S("Sam leaves. HR opens his record in OrangeHRM, on the Job tab."),
      hand: 'OrangeHRM: PIM > Employee List, Sam Rivera, Job tab.',
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 2000 }], standIn: [{ do: 'web.show', url: SAMHR('leave-00-job-tab.png'), settle: 400 }] },
    { id: 'n08-terminate', piece: 8, cloud: true, say: S('HR clicks Terminate Employment, keeps today as the date, picks the reason, and saves. HR never commits anything.'),
      hand: 'Terminate Employment: date today, reason Resigned, Save.',
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 1000 }], standIn: [{ do: 'web.show', url: SAMHR('leave-01-terminate.png'), settle: 400 }] },
    { id: 'n08-past', piece: 8, cloud: true, say: S('OrangeHRM now lists him as a past employee.'),
      do: [{ do: 'web.open', url: OHRM_LIST, settle: 1000 }], standIn: [{ do: 'web.show', url: SAMHR('leave-02-terminated.png'), settle: 400 }] },
    { id: 'n08-connector', piece: 8, say: S("Within seconds, the connector sends it on: not active. The reason for leaving stays in HR. These logs are from the test run of the same chain."),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: OHRMEV_F('connector.log'), line: lineOf(OHRMEV_F('connector.log'), /SEND {2}Test Hris leaves/), endLine: lineOf(OHRMEV_F('connector.log'), /ACCEPTED {2}HR: Test Hris leaves/), highlight: true }] },
    { id: 'n08-ad', piece: 8, say: S("In the test run, the account was switched off in Active Directory within a minute of HR's save."),
      do: [{ do: 'code.file', file: OHRMEV_F('watch-leave.log'), line: lineOf(OHRMEV_F('watch-leave.log'), /HR->AD .* other skipped/), endLine: lineOf(OHRMEV_F('watch-leave.log'), /HR->AD .* update success/), highlight: true }] },
    { id: 'n08-entra', piece: 8, say: S("Entra followed on its next sync cycle: account enabled, no. The department groups dropped the worker."),
      do: [{ do: 'code.file', file: OHRMEV_F('watch-leave.log'), line: lineOf(OHRMEV_F('watch-leave.log'), /enabled=False/), endLine: lineOf(OHRMEV_F('watch-leave.log'), /enabled=False/) + 1, highlight: true }] },
    { id: 'n08-apps', piece: 8, say: S("ServiceNow marked the worker inactive, and AWS showed the account disabled, each on its own sync. Nobody filed a ticket."),
      do: [{ do: 'code.file', file: OHRMEV_F('watch-leave.log'), line: lineOf(OHRMEV_F('watch-leave.log'), /ServiceNow .* disable success/), endLine: lineOf(OHRMEV_F('watch-leave.log'), /PROVLOG AWS .* disable success/), highlight: true }] },
    { id: 'n08-two', piece: 8, say: S("Two things are separate. The HR change switches the account off. IT's leaver workflow then removes his access packages and ends his open sessions. That workflow is live, from pull request 257, but its package removal has not passed its test yet."), do: [M('tile:LEAVER')] },

    // ================================================================= N09
    { id: 'n09-run', piece: 9, write: true, cloud: true, say: S('Every step leaves a record. One click runs the evidence workflow. It reads Entra with a read-only identity.'),
      previewSay: S("Every step leaves a record. One click runs the evidence workflow. It reads Entra with a read-only identity. A preview does not click it, so an earlier run is shown next."),
      do: [{ do: 'gh.runWorkflow', workflow: 'evidence-pack.yml' }],
      wait: { check: 'evidenceDone', waiting: 'Filing the evidence (a few minutes)', ready: 'Filed', onReady: [{ do: 'web.open', url: (x) => x.evRun.url }] },
      standIn: [{ do: 'web.open', url: `${GH}/actions/workflows/evidence-pack.yml`, settle: 5000 }, { do: 'web.highlight', target: { re: '^Run workflow$', nth: 0 }, tag: 'One click' }] },
    { id: 'n09-summary', piece: 9, say: S('It files seven records. PIM activations. Live admin assignments. The PIM audit trail. Access review decisions. Sign-in rules. MFA registration. And who holds admin roles.'),
      do: [{ do: 'web.open', url: (x) => x.evRun.url }, { do: 'web.waitFor', target: { re: '^Evidence pack filed', nth: 0 }, timeout: 300000 }, { do: 'web.highlight', target: { re: '^Evidence pack filed', nth: 0 }, tag: 'Seven records' }] },
    { id: 'n09-hashes', piece: 9, say: S('Each file gets a fingerprint, a hash that changes if one byte changes. Raj\'s activation from part five is in the PIM records.'),
      do: [{ do: 'web.clickIf', target: { re: 'SHA-?256|fingerprint', nth: 0 } }, { do: 'web.highlight', target: [{ re: 'SHA-?256', nth: 0 }, { re: 'fingerprint', nth: 0 }], tag: 'A fingerprint per file' }] },
    { id: 'n09-store', piece: 9, lineWithAction: true, say: S("Here is the store. It has three folders. The evidence folder holds the packs. The change feed is Azure's own ordered log of every add, change or delete. The logs folder is Azure's older logging; the lab sends its access logs to Log Analytics instead."),
      do: [{ do: 'web.open', url: EVIDENCE, settle: 9000 }, { do: 'web.highlight', target: { text: 'evidence', exact: true, row: true }, tag: 'The packs' }, { do: 'pause', ms: 5000 }, { do: 'web.highlight', target: { text: '$blobchangefeed', exact: true, row: true }, tag: "Azure's ordered change log" }, { do: 'pause', ms: 5000 }, { do: 'web.highlight', target: { text: '$logs', exact: true, row: true }, tag: 'Older logging (unused)' }] },
    // BLOCKER (2026-11-07 dry run): adm-presenter has no blob read on the
    // evidence container ("Showing all 0 items" with an error). Until the
    // owner grants a read-only data role (Storage Blob Data Reader on that
    // container, a lab change), the pack's contents are shown on the run's
    // own summary, which lists what it filed.
    { id: 'n09-pack', piece: 9, say: S('Inside a pack: the records, the fingerprint list, and a summary that maps each record to a control.'),
      do: [{ do: 'web.open', url: (x) => x.evRun.url, settle: 5000 }, { do: 'web.highlight', target: [{ re: 'SUMMARY\\.md', nth: 0 }, { re: 'SHA256SUMS', nth: 0 }, { re: '^Evidence pack filed', nth: 0 }], tag: 'Records, fingerprints, summary' }] },
    { id: 'n09-lock', piece: 9, say: S('The store is set to write-once. In the lab the lock stays in its trial setting, so the lab can be torn down. A hospital locks it for good. So an auditor can check it, instead of taking my word.'),
      do: [{ do: 'web.open', url: EVIDENCE, settle: 9000 }, { do: 'web.highlight', target: { text: 'evidence', exact: true, row: true }, tag: 'Write once (trial lock: Unlocked)' }] },

    // ================================================================= N10
    { id: 'n10-title', piece: 10, say: S('Now a showcase of the Entra features a hospital uses. Each one is set up as code. For each: what it is, and why it is here.'),
      do: [M('overview')] },
    { id: 'n10-review', piece: 10, say: S('First, access reviews. A review asks: does this person still need this access? This one runs every quarter on help-desk admin power. A named reviewer group says keep or remove. No answer means removed.'),
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_ERM/DashboardBlade/~/Controls`, settle: 8000 }, { do: 'web.click', target: { text: 'Access reviews', exact: true } }, { do: 'web.highlight', target: { text: 'Privileged access review: PIM-Tier1-Helpdesk', row: true }, tag: 'Every quarter; no answer = removed' }] },
    { id: 'n10-request', piece: 10, say: S('Requested extras. Test User C, a nurse, asked for ICU float access: the ICU apps for nurses who cover ICU shifts. Her manager approved it. It expires by itself after a hundred and eighty days.'),
      hand: "Read Test User C's request reason off this screen (11.3).",
      do: [{ do: 'web.open', url: PKGS, settle: 8000 }, { do: 'web.click', target: { text: 'ICU - Float Access', exact: true } }, { do: 'web.click', target: { text: 'Requests', exact: true } }, { do: 'web.highlight', target: { text: 'Test User C', row: true }, tag: 'Manager approved; ends after 180 days' }] },
    { id: 'n10-sod', piece: 10, say: S("Blocked combinations. Pharmacy dispensing is marked incompatible with the nurse and ICU packages. No one can hold both. The system enforces it, not a manager's memory."),
      do: [{ do: 'web.open', url: PKGS, settle: 8000 }, { do: 'web.click', target: { text: 'Pharmacy - Controlled Substances Apps', exact: true } }, { do: 'web.click', target: { re: '^Separation of duties' } }, { do: 'web.highlight', target: { text: 'Nurse - Clinical Apps', row: true }, tag: 'Never together' }] },
    { id: 'n10-passkey', piece: 10, say: S('Passkeys. A passkey is a sign-in key stored on a device. It works only on the real website, so a fake site cannot use it. Each IT admin login has one registered, because admins are the biggest target. In this lab they are software passkeys, and the rule that requires them is still report-only.'),
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/UserAuthMethods/userId/3b1f4493-6390-4fd2-afcf-ac4e7fdc620c/hidePreviewBanner~/true`, settle: 8000 }, { do: 'web.highlight', target: { text: 'Passkey', exact: true }, tag: 'Passkey (software)' }] },
    { id: 'n10-ca002', piece: 10, say: S('In the lab these are software passkeys. The rule that will require them is still report-only.'),
      do: [{ do: 'web.open', url: CA_POLICIES, settle: 8000 }, { do: 'web.highlight', target: { re: '^CA002 - Require phishing-resistant MFA for admins', row: true }, tag: 'Report-only' }] },
    { id: 'n10-breakglass', piece: 10, say: S('Emergency accounts, also called break-glass accounts. The lab has two. They sit outside every sign-in rule, so if a bad rule ever locks everyone out, someone can still get in. Any use raises an alarm at once.'),
      do: [{ do: 'web.open', url: `${E}Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/7817077c-7e46-4a45-a599-7ddf685e9a9c`, settle: 8000 }, { do: 'web.click', target: { text: 'All users included and specific users excluded', exact: true } }, { do: 'web.click', target: { text: 'Exclude', exact: true } }, { do: 'web.highlight', target: { text: 'Break-Glass-Admins' }, tag: 'Outside every sign-in rule' }] },
    { id: 'n10-robots', piece: 10, say: S('Robot accounts are identities that programs use, not people. Entra uses one to create users in AWS. GitHub uses one to apply Terraform. The lab has twenty, and each has a named owner.'),
      do: [M('tile:NHI')] },
    { id: 'n10-owners', piece: 10, say: S('This is the AWS app in Entra. Its owners may change its settings, including how people sign in, so each app needs accountable names. Here: two named admins, plus the pipeline identity that manages it as code.'),
      do: [{ do: 'web.open', url: AWS_APP_OWNERS, settle: 8000 }, { do: 'web.highlight', target: { text: 'ADM Ava Lin', exact: true, row: true }, tag: 'Named owners' }] },

    // ================================================================= N11
    // 2026-11-07 (readiness/pam-microsoft.md, ADR 0036): Key Vault for
    // Kubernetes RAN (PR #232), the Key Vault leak measured (PR #235, E132),
    // Bastion session recording RAN once (PR #247, E133; Bastion is deleted
    // after each capture, so the screens are that run's own frames and the
    // reviewer's playback video), Windows LAPS on DC01 RAN (PR #225), Intune
    // EPM RAN on a test PC (E188, PR #293: default-response approval; the
    // per-app rule never reached the PC), PC LAPS backed up to Entra. Lines from the hand-off's fixes; never
    // "a few minutes" for EPM (an approval lasts 24 hours).
    { id: 'n11-title', piece: 11, say: S('PAM means privileged access management: how admin power and admin passwords are guarded. The hospital already runs on Microsoft, so these jobs use Microsoft products. PIM, from part five, stays the core.'),
      do: [M('lab:11')] },
    { id: 'n11-k8s', piece: 11, say: S('Azure Key Vault holds secrets: passwords and keys that programs need. Here, an app in Kubernetes reads one secret from Key Vault, with no stored password. It is refused the secret next to it.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.stop', stop: 'pam-microsoft' }, { do: 'code.file', file: v2f('k8skv', 'lab/evidence/k8s-keyvault/20261107T013045Z/run.log'), line: 1304, endLine: 1326, highlight: true }] },
    { id: 'n11-state', piece: 11, say: S('Terraform writes notes as it works, in a state file. Read a password the usual way, and it lands in those notes in plain text. An ephemeral read is short-lived. Terraform gets the password only while it runs, and never writes it down.'),
      do: [M('tile:DYN')] },
    { id: 'n11-leak', piece: 11, say: S('Measured on Key Vault: the usual way left the password in three files. The ephemeral way, in none.'),
      do: [{ do: 'code.file', file: v2f('kvleak', 'lab/evidence/keyvault-state-leak/20261107T014803Z/run.txt'), line: 18, endLine: 21, highlight: true }] },
    { id: 'n11-bastion-pim', piece: 11, lineWithAction: true, say: S('An admin could not open the domain controller until she turned on her admin role in PIM, for one hour.'),
      do: [{ do: 'web.show', url: BASTION('proof-admin/01-before-pim-no-access.png'), settle: 400 }, { do: 'pause', ms: 3500 }, { do: 'web.show', url: BASTION('proof-admin/04-pim-active.png'), settle: 400 }] },
    { id: 'n11-bastion', piece: 11, say: S("Then she connected through Azure Bastion, a gateway into servers, from the browser. Bastion recorded the whole session, and a second admin played it back like a video. It records that session only, not the admin's own computer."),
      do: [{ do: 'web.video', url: BASTION('proof-playback/video-reviewer/page@36c5d32a298a0a846569c4ac6b57b052.webm'), at: 38 }] },
    { id: 'n11-premium', piece: 11, say: S('Recording needs the Premium tier, so the lab creates Bastion to show it, then deletes it. It costs forty-five cents an hour. In the lab it is a demonstration, not an always-on control.'),
      do: [{ do: 'web.show', url: BASTION('proof-admin/08-recordings-list.png'), settle: 400 }] },
    { id: 'n11-laps', piece: 11, say: S('Windows LAPS gives a computer a long random admin password, changes it on a schedule, and stores it encrypted. On DC01 it now rotates the repair password. Part twelve shows it.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.file', file: ad('06-laps-apply-and-rotation.log'), line: 7, endLine: 10, highlight: true }] },
    { id: 'n11-epm', piece: 11, say: S('Intune Endpoint Privilege Management lets a user run one approved app as admin, without being an admin. On a test PC, a standard user asked to run one app as admin. An IT admin approved it, and the app ran with admin rights while the user stayed standard. The rule for that one app never reached the PC, so the request went through the default approval setting.'),
      do: [{ do: 'code.file', file: v2f('bastion', 'lab/scripts/intune/New-IntuneEpmAndLaps.ps1'), line: 142, endLine: 173, highlight: true }] },
    { id: 'n11-lost', piece: 11, say: S('One thing is lost. A PAM vault lets one person check out a shared password. Microsoft has no direct match. Here, each admin has a named account and borrows power through PIM, so admins do not need a shared password. One exception: the built-in domain administrator is still a shared account, and the recorded session signed in with it.'),
      do: [M('tile:PIM')] },

    // ================================================================= N12
    // RAN · tenant on DC01 (E116-E118). The DC01 console screens (Active
    // Directory Users and Computers, Group Policy Management) have no cockpit
    // driver yet: these steps show the run's own evidence (PR #225, read
    // only, cockpit/.v2/ad) in the v2 VS Code window.
    { id: 'n12-tiers', piece: 12, say: S('Now Active Directory itself. A tier is a trust zone for admin work. Tier 0 controls Active Directory. Tier 1 runs the servers. Tier 2 is the help desk and staff PCs.'),
      do: [M('setup:3.2')] },
    { id: 'n12-why', piece: 12, say: S('Why tiers? When an admin signs in to a computer, Windows leaves a reusable credential there. If a domain admin signs in to an infected nurse PC, the attacker can take the whole domain. With tiers, a Tier 0 login never touches a lower tier.'),
      do: [M('tile:ADTIER')] },
    { id: 'n12-built', piece: 12, say: S('On DC01 I built the three tiers: folders, groups, and one new admin account per tier.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: ad('07-verify-and-signin.log'), line: 3, endLine: 19, highlight: true }] },
    { id: 'n12-gpo', piece: 12, say: S('This Group Policy, a set of settings that Active Directory pushes to computers, denies Tier 0 accounts any sign-in to Tier 1 and Tier 2 computers. Those tiers hold no computers yet, so today it denies nothing. It is ready for the first one.'),
      do: [{ do: 'code.file', file: ad('03-tiering-apply.log'), line: 12, endLine: 16, highlight: true }] },
    { id: 'n12-protected', piece: 12, say: S('The new admins are in Protected Users, a built-in group that blocks older, weaker sign-in methods. Three older admins stay out on purpose. The current remote path to DC01 still needs NTLM, an older sign-in protocol.'),
      do: [{ do: 'code.file', file: ad('03-tiering-apply.log'), line: 9, endLine: 11, highlight: true }] },
    { id: 'n12-laps', piece: 12, say: S("Windows LAPS now manages DC01's repair password. It is long, random, encrypted in Active Directory, and changes every thirty days. One change ran and was logged."),
      do: [{ do: 'code.file', file: ad('06-laps-apply-and-rotation.log'), line: 7, endLine: 10, highlight: true }] },
    { id: 'n12-score', piece: 12, say: S('PingCastle, a free Active Directory health scanner, scored the domain fifty-eight before and fifty after. Lower is better. Thirty-five checks passed, and normal users still sign in.'),
      do: [{ do: 'code.file', file: ad('08-pingcastle-after.log'), line: 3, endLine: 3, highlight: true }] },
    { id: 'n12-left', piece: 12, say: S('What is left: move the remote path to Kerberos. Then the older admins can join Protected Users.'),
      do: [M('setup:3.3')] },

    // ================================================================= N13
    // 2026-11-07 (readiness/adfs-migration.md): PR #221 merged (the code);
    // steps 1-6 RAN on DC01 (PR #237, E140): AD FS installed, the app's five
    // claim rules, 5 real sign-ins with valid signatures. The Entra side and
    // the cut-over are BUILT. The Connect Health readiness report is NOT
    // registered yet (ADR 0031). Never say "migrated" or "identical".
    { id: 'n13-what', piece: 13, say: S('AD FS is a Windows server role. It lets staff sign in to web apps with their company password. The app trusts AD FS, and AD FS vouches for the person.'),
      do: [M('tile:ADFS')] },
    { id: 'n13-why', piece: 13, say: S('Companies move off it. It is servers to patch and certificates to renew. Its signing key can forge a sign-in for anyone. That attack is called Golden SAML.'),
      do: [M('tile:ADFS')] },
    { id: 'n13-ran', piece: 13, say: S('AD FS runs on our domain controller for this exercise. In production it would be a dedicated AD FS server, never a DC. The test app gets all five claims from AD FS: five real sign-ins, each with a valid signature.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.stop', stop: 'adfs' }, { do: 'code.file', file: v2f('adfs', 'lab/evidence/adfs-migration/20261107T0131Z/06-before-adfs.json'), line: 1, endLine: 38, highlight: true }] },
    { id: 'n13-rule', piece: 13, say: S("A claim is one fact about the person, like a department. A claim rule is AD FS's recipe for one claim. This custom rule cuts the domain off the sign-in name."),
      do: [{ do: 'code.file', file: v2f('ssm', 'lab/adfs/claims-viewer.rules.txt'), line: 21, endLine: 23, highlight: true }] },
    { id: 'n13-entra', piece: 13, say: S('Entra has no free-form version, so the Entra app, written as code, uses its built-in step instead.'),
      do: [{ do: 'code.file', file: v2f('ssm', 'lab/terraform/modules/apps/claims_viewer.tf'), line: 183, endLine: 189, highlight: true }] },
    { id: 'n13-next', piece: 13, say: S("Microsoft's readiness report would mark each rule like this. Its agent is installed on DC01, but not registered yet, so there is no report. One command will point the app at Entra, and one command points it back. That cut-over has not run yet."),
      do: [M('tile:ADFS')] },
    { id: 'n13-refuse', piece: 13, say: S('A way back stays ready. The removal script refuses to remove AD FS while it still has sign-ins. Only after a quiet period does it go.'),
      do: [{ do: 'code.file', file: v2f('ssm', 'lab/adfs/scripts/19-Remove-Adfs.ps1'), line: 114, endLine: 117, highlight: true }] },

    // ================================================================= N14
    // RAN · tenant for the clinic estate (E115); the Okta admin console has
    // no cockpit sign-in (no Okta admin in the sign-in tool), so its screens
    // show the code that built them (PR #222, cockpit/.v2/okta). Rows 7 and
    // 8 (cut-over, rollback) are PENDING BUILD.
    { id: 'n14-tracker', piece: 14, say: S('Okta is the sign-in service the clinic used before the hospital bought it. The clinic has three apps in Okta. A script reads Okta and Entra and builds this tracker. Nobody types the status by hand.'),
      do: [{ do: 'web.open', url: (x) => `file://${x.v2.okta}/lab/okta-migration/status.html`, settle: 3000 }] },
    { id: 'n14-apps', piece: 14, say: S('Each app uses a different sign-in method. Lab Results uses OpenID Connect. Billing uses SAML. Scheduling is only a bookmark.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.closeAll' }, { do: 'code.file', file: okta('lab/terraform/okta/clinic-apps.tf'), line: 117, endLine: 125, highlight: true }] },
    { id: 'n14-policy', piece: 14, say: S("This is Okta's authentication policy, its rule for how a person proves who they are. Clinic staff need two factors, and they sign in again after eight hours, one shift. Anyone else is denied."),
      do: [{ do: 'code.file', file: okta('lab/terraform/okta/clinic-apps.tf'), line: 81, endLine: 100, highlight: true }] },
    { id: 'n14-rules', piece: 14, say: S('Okta fills the billing group from the department. The clinic-staff rule matches every hospital address. Copied to Entra, it would give lab results to the whole hospital. So Entra gets an assigned group instead.'),
      do: [{ do: 'code.file', file: okta('lab/okta-migration/tracker.md'), line: 31, endLine: 37, highlight: true }] },
    { id: 'n14-before', piece: 14, say: S("This is the before. A clinic user opens Lab Results. Okta sends her to Entra for her password and code. She comes back, and the app checks Okta's token. It took twenty-four seconds."),
      do: [{ do: 'code.file', file: okta('lab/okta-migration/results/2026-11-07T005908Z-clinic-lab-results-okta.json'), line: 1, endLine: 14, highlight: true }] },
    { id: 'n14-plan', piece: 14, say: S('The Entra side is code. One app, one group, one Conditional Access rule. The plan adds five things and changes nothing else.'),
      do: [{ do: 'gh.planComment', pr: 219 }, { do: 'web.highlight', target: { re: '5 to add, 0 to change, 0 to destroy|Plan: 5 to add', nth: 0 }, tag: '5 to add, 0 to change' }] },
    // Rows 7 and 8: no cut-over has run (no results/*-entra.json): said as
    // built, not run.
    { id: 'n14-cutover', piece: 14, say: S('The cut-over is built: one command switches the app to Entra, and one command rolls it back. It has not run yet. It runs after the Entra side is applied.'),
      do: [M('tile:OKTAMIG')] },

    // ================================================================= N15
    // 2026-11-07 (readiness/cloud-least-priv.md): Session Manager RAN, then
    // torn down (PR #234 merged, E125-E127): no server runs now, so the
    // screens are that run's transcript and record. Azure least privilege:
    // the custom role, PIM and locks RAN (PR #246, open); the pipeline's
    // narrower scope is BUILT. The honest gaps are said.
    { id: 'n15-ssm', piece: 15, say: S('Session Manager is AWS\'s way to open a shell on a server with no SSH key and no open port. The only way in is Session Manager, and only during a PIM activation. Every command is in the log, under the person\'s name.'),
      do: [{ do: 'code.open', ws: c.v2?.ws }, { do: 'code.stop', stop: 'ssm-least-priv' }, { do: 'code.file', file: v2f('ssm', 'lab/evidence/aws-session-manager/20261107T0113Z/session-terminal.txt'), line: 1, endLine: 12, highlight: true }] },
    { id: 'n15-refused', piece: 15, say: S('Port forwarding, remote commands, an untagged server and someone else\'s session were all refused.'),
      do: [{ do: 'code.file', file: v2f('ssm', 'lab/evidence/aws-session-manager/20261107T0113Z/record.json'), line: 60, endLine: 76, highlight: true }] },
    { id: 'n15-gaps', piece: 15, say: S('The gaps, plainly. When the activation ends, AWS refuses new access within about eight minutes, but a token already issued can last up to an hour, and an open shell stays open. The server user can use sudo. The server ran for the test and was torn down.'),
      do: [{ do: 'code.file', file: v2f('ssm', 'lab/evidence/aws-session-manager/20261107T0113Z/record.json'), line: 111, endLine: 117, highlight: true }] },
    { id: 'n15-azure', piece: 15, say: S('In Azure, least privilege means the smallest role that does the job. The operations role can start and stop the lab servers and read their logs. It cannot change their network or run commands on them. Nobody holds it all day: you activate it in PIM with MFA and a reason.'),
      do: [{ do: 'code.file', file: v2f('azlp', 'lab/evidence/azure-least-privilege/20261107T0230Z/pim-vm-operator.txt'), line: 2, endLine: 13, highlight: true }] },
    { id: 'n15-locks', piece: 15, say: S('The key vaults have delete locks the pipeline cannot remove. The pipeline\'s narrower scope, the lab resource group only, is in code; it goes live after merge.'),
      do: [M('tile:AZROLE')] },

    // ================================================================= N16
    // Stop 15 (fixed 2026-11-07): its leak tab is the Key Vault record now.
    { id: 'n16-rbac', piece: 16, say: S('Kubernetes runs app containers. Roles there say who may do what. This checker reads role files and flags seven kinds of risky permission: for example, give yourself more power, act as someone else, or read every secret.'),
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.stop', stop: 'delivery' }, { do: 'code.file', file: tout('1-rbac-lint.txt'), line: 1 }] },
    { id: 'n16-count', piece: 16, say: S("Think of a cleaner's key that also opens the safe. In a deliberately bad test file, it found eleven risky lines. In the clean file, none."),
      do: [{ do: 'code.highlight', file: tout('1-rbac-lint.txt'), line: lineOf(tout('1-rbac-lint.txt'), /planted bad file/), endLine: lineOf(tout('1-rbac-lint.txt'), /clean file +:/) }] },
    { id: 'n16-scanners', piece: 16, say: S('Next, the two scanners from part one. A scanner that never fails proves nothing. So on every change, GitHub feeds them a deliberately unsafe file. Both must fail on it, and pass a clean one.'),
      do: [{ do: 'gh.openJob', workflow: 'lab-tests.yml', job: 'scanner positive control' }, { do: 'web.highlight', target: [{ text: 'Self-test (pinned images, as the gate runs them)', row: true }, { re: '^scanner positive control', nth: 0 }, { re: 'must fail on bad', nth: 0 }], tag: 'Must fail on the unsafe file, pass the clean one' }] },
    { id: 'n16-off', piece: 16, say: S('Last, three things are built and tested, but switched off: Azure Policy rules in audit mode, an AWS audit trail, and two new alarms. A read-only check just before recording shows none is on.'),
      do: [{ do: 'code.open', ws: c.tourWs }, { do: 'code.closeAll' }, { do: 'code.file', file: tout('4-not-yet-on.txt'), line: 1 }, { do: 'code.highlight', file: tout('4-not-yet-on.txt'), line: lineOf(tout('4-not-yet-on.txt'), /^RESULT: none/), endLine: lineOf(tout('4-not-yet-on.txt'), /^  Two new alarms +: off/) }] },

    // ================================================================= N17
    { id: 'n17-tree', piece: 17, lineWithAction: true, say: S('This is the whole lab in VS Code. Terraform for Entra, Azure, AWS and Okta. Scripts for what Terraform cannot set. Workflows for GitHub Actions. Alarm rules in two languages.'),
      do: [{ do: 'code.open', ws: DEMO_WS }, { do: 'code.closeAll' }, { do: 'code.tree', folder: c.bp, reveal: ['lab/terraform', 'lab/scripts', '.github/workflows', 'lab/kql', 'lab/splunk'] }] },
    { id: 'n17-check', piece: 17, silentSkip: true, // silent clips: the servers are off to save cost, so the check is red (owner, 2026-11-11)
      say: S('I run a read-only check from here. It reads the live lab and changes nothing. Here is the result.'),
      do: [{ do: 'code.check', check: 'preflight' }] },
    { id: 'n17-actions', piece: 17, say: S('On GitHub, the Actions tab shows every run: plans, applies, the HR sync and the evidence pack. Each one has a plain-word summary.'),
      do: [{ do: 'web.open', url: `${GH}/actions`, settle: 5000 }, { do: 'web.highlight', target: { re: '^\\d[\\d,]* workflow runs?$', nth: 0 }, tag: 'Every run' }] },
    { id: 'n17-pr', piece: 17, say: S('Every change is a pull request. More than a hundred and thirty are merged, each with its checks and its plan.'),
      do: [{ do: 'web.open', url: `${GH}/pulls?q=is%3Apr+is%3Amerged`, settle: 5000 }, { do: 'web.highlight', target: { re: '^\\d[\\d,]* Closed$|Closed', nth: 0 }, tag: 'Merged, each with checks and a plan' }] },
    { id: 'n17-gate', piece: 17, cloud: true, say: S('And every Terraform apply waits for my approval, here.'),
      previewSay: S("And every Terraform apply waits for my approval, here. This is an earlier gate."),
      do: [{ do: 'web.open', url: (x) => x.issue.url }, { do: 'web.highlight', target: { re: 'is waiting for a human decision|waiting for' }, tag: 'My approval' }],
      standIn: [{ do: 'web.open', url: (x) => x.issue.url }] },
    { id: 'n17-thanks', piece: 17, hold: 15, say: S('I built this with an AI coding assistant, and the history says so. I set the goals, made the design calls, and I own every decision. Thanks for watching.'),
      do: [M('overview')] },
  ];
}
