// Scenes for the lab demo video: narration beats + what the camera does.
// Narration states only what the tenant shows (checked 2026-10-27).
import fs from 'node:fs';
import path from 'node:path';
import { OUT, REPO, sleep } from './rec.mjs';
import { execFileSync } from 'node:child_process';

const PAGES = path.join(path.dirname(new URL(import.meta.url).pathname), 'pages');
const TERM = 'file://' + path.join(PAGES, 'term.html');
const CARD = 'file://' + path.join(PAGES, 'card.html');
const STEPS = 'file://' + path.join(PAGES, 'steps.html');
const INTRO = `file://${REPO}/lab/scripts/demo/video/pages/intro.html`;
const INTRO_RESULT_AUDIO = `${OUT}/clips/result-line.mp3`;
const INTRO_FACE_CLIP = `${OUT}/clips/face.mp4`;
const SR = 'file://' + path.join(PAGES, 'speedrun.html');
const BIMGDIR = `${OUT}/build`;
const BMAP = 'file://' + path.join(PAGES, 'build-map.html');
const bmapGo = (r, i) => r.page.evaluate((i) => window.bmap.go(i), i);
const BIMG = (n) => 'file://' + path.join(OUT, 'build', n + '.png');
// The speed run: one real screen per key point, no maps (the maps come once each, right after).
function srSlides() {
  const im = (n) => `file://${BIMGDIR}/${n}.png`;
  return [
    { img: im('entra'), tag: 'BY HAND', kind: 'hand', n: 'Setup 1 of 6', h: 'Six real <em>sign-ups</em>', p: 'Microsoft, Azure, AWS, ServiceNow, Okta, GitHub. Each one a real account on a trial.' },
    { img: im('domain'), tag: 'BY HAND', kind: 'hand', n: 'Setup 2 of 6', h: 'One <em>domain</em>', p: 'contosohealthlab.com, proven to Microsoft with a DNS record.' },
    { glyph: 'PLAN · APPLY', tag: 'AS CODE', kind: 'code', n: 'Setup 3 of 6', h: 'Two <em>robot identities</em>', p: 'No passwords. GitHub signs a token, Entra trusts it, nothing to steal.' },
    { img: im('github'), tag: 'AS CODE', kind: 'code', n: 'Setup 4 of 6', h: 'Every change is a <em>pull request</em>', p: '13 checks, a human approves, Terraform applies.' },
    { img: im('dc01'), tag: 'AS CODE', kind: 'code', n: 'Setup 5 of 6', h: 'A Windows <em>domain controller</em>', p: 'Built by the pipeline, synced to the cloud by Cloud Sync.' },
    { img: im('users'), tag: 'AS CODE', kind: 'code', n: 'Setup 6 of 6', h: 'Thirteen fake <em>staff</em>', p: 'A spreadsheet stands in for HR and feeds the directory.' },
    { img: im('hrapp'), tag: 'REAL SCREEN', n: 'The lab', h: 'HR decides who gets <em>in</em> and who is <em>out</em>', p: 'Hired: an account, the right apps. Gone: everything off.' },
    { img: im('ca'), tag: 'REAL SCREEN', n: 'Sign-in rules', h: 'Nine policies <em>enforced</em>', p: 'Each graduated from report-only by its own reviewed pull request.' },
    { img: im('pim'), tag: 'REAL SCREEN', n: 'Privileged access', h: 'Admin power only while it is <em>used</em>', p: 'Eligible, not standing. Activation needs a reason and a ticket.' },
    { glyph: 'ALERT', tag: 'REAL SCREEN', n: 'Detect and respond', h: 'Sentinel raises the <em>alarm</em>', p: 'Sixteen rules live: break-glass use, risky sign-ins, role changes outside PIM.' },
    { glyph: 'PROOF', tag: 'REAL SCREEN', n: 'Proof', h: 'Evidence an auditor can <em>check</em>', p: 'Write-once store, hashed packs, a drift check against the code.' },
    { img: im('aws'), tag: 'REAL SCREEN', n: 'Leaver', h: 'Gone from AWS in <em>nine minutes</em>', p: 'HR to AD to Entra to AWS, measured from timestamps.' },
  ];
}

function buildMapData() {
  return {
    kick: 'How the lab was built', title: 'From six sign-ups to <em>one running tenant</em>', sub: 'The wiring is half the work. Read it left to right, like the lab map.',
    foot: 'Orange: done by a person. Blue: written as code and applied by the pipeline. Screens are real pages from this lab.',
    stations: [
      { title: 'Sign-ups', kicker: 'Six platforms, by hand', goal: 'Real accounts on every platform', text: 'Every platform is a real account with a trial licence. Opening them is the one step a person has to do: a card, a phone, a verification mail.',
        bullets: ['Microsoft Entra: the cloud directory (E5, Governance and Intune trials)', 'Azure: the servers and storage, on a free-trial subscription', 'AWS, ServiceNow, Okta: the apps staff will sign in to', 'GitHub: every line of code, in a private repository'],
        chips: [{ text: 'BY HAND', kind: 'hand' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'Microsoft Entra', note: 'Where every staff login lives', img: BIMG('entra'), kind: 'hand' }, { name: 'Azure', note: 'Hosts the server and the evidence files', img: BIMG('azure'), kind: 'hand' }, { name: 'AWS', note: 'The cloud console engineers sign into', img: BIMG('aws'), kind: 'hand' },
                { name: 'ServiceNow', note: 'The IT help desk', img: BIMG('servicenow'), kind: 'hand' }, { name: 'Okta', note: "A partner clinic's own login system", img: BIMG('okta'), kind: 'hand' }, { name: 'GitHub', note: 'Where the code and the change history live', img: BIMG('github'), kind: 'hand' }],
        outs: ['<b>6</b> accounts', '<b>3</b> free trials', '<b>1</b> private repo'] },
      { title: 'The name', kicker: 'A verified domain', goal: 'Sign-ins look like the hospital', text: 'A real internet name, bought from a registrar and proven to Microsoft by a DNS record only the owner can set.',
        bullets: ['contosohealthlab.com, verified in Entra', 'Also the name of the on-site directory: corp.contosohealthlab.com', 'Without it, every account would end in onmicrosoft.com'],
        chips: [{ text: 'BY HAND', kind: 'hand' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'contosohealthlab.com', note: 'Verified custom domain', img: BIMG('domain'), kind: 'hand' }, { name: 'DNS proof', note: 'TXT record only the owner can set', glyph: 'TXT', kind: 'hand' }],
        outs: ['<b>1</b> verified domain', '<b>$11</b> a year'] },
      { title: 'Robot identities', kicker: 'No passwords, anywhere', goal: 'Nothing to steal', text: 'One run from a laptop created two identities for the pipeline. GitHub vouches for them with a token that lasts minutes; Microsoft trusts it only from the approved path.',
        bullets: ['PLAN: may read the tenant and propose changes', 'APPLY: may make them, only from the production path', 'A test from a throwaway branch was refused, and that refusal is kept as evidence'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'PLAN identity', note: 'Proposes changes', glyph: 'PLAN', kind: 'code' }, { name: 'APPLY identity', note: 'Makes them', glyph: 'APPLY', kind: 'code' }, { name: 'GitHub trust', note: 'Minutes-long token, no secret', glyph: 'OIDC', kind: 'code' }],
        outs: ['<b>2</b> identities · <b>0</b> passwords', 'Refused from any other branch'] },
      { title: 'The pipeline', kicker: '64 reviewed changes', goal: 'Reviewed, repeatable, provable', text: 'Every change is a pull request. Checks rehearse it, a person approves it, Terraform applies it. That is how all of the lab was built, in days.',
        bullets: ['Day 1: sign-in rules, report-only', 'Day 2: admin tiers (PIM)', 'Day 3: access governance (packages, workflows)', 'Then: 17 detection rules, then the domain controller, then single sign-on for AWS, ServiceNow and Okta, with automatic accounts for AWS'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'Pull request', note: 'A change plus a reviewer', img: BIMG('github'), kind: 'code' }, { name: 'Checks', note: '13 mocked tests', glyph: '13 ✓', kind: 'code' }, { name: 'Approve', note: 'A person types it', glyph: 'approve', kind: 'hand' }, { name: 'Terraform apply', note: 'Makes the tenant match', glyph: 'TF', kind: 'code' }],
        outs: ['<b>64</b> merged pull requests', '<b>13</b> checks on each one'] },
      { title: 'The directory', kicker: 'DC01 + Cloud Sync', goal: 'On-site accounts flow to the cloud', text: 'A Windows server in Azure was promoted to a domain controller, the on-site directory most hospitals still run. The Cloud Sync agent on it copies accounts up to Entra.',
        bullets: ['DC01: Windows Server 2022, created by the pipeline, shuts down nightly', 'Cloud Sync: copies the Workforce and Disabled folders every few minutes', 'One password in both places, carried as a scrambled hash'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'AGENT BY SCRIPT', kind: 'hand' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'DC01', note: 'Windows Server 2022 in Azure', img: BIMG('dc01'), kind: 'code' }, { name: 'Cloud Sync agent', note: 'Installed on DC01', img: BIMG('cloudsync'), kind: 'hand' }, { name: 'Entra ID', note: 'The cloud directory', img: BIMG('entra'), kind: 'code' }],
        outs: ['<b>1</b> domain controller', 'Sync every few minutes'] },
      { title: 'The people', kicker: '13 staff, 3 admins', goal: 'Access follows HR from day one', text: 'A spreadsheet of thirteen fake staff stands in for HR. It went through Microsoft\'s HR front door into the directory, each person in the right department, then up to the cloud.',
        bullets: ['HR row → inbound provisioning API → Active Directory → Cloud Sync → Entra', 'One leaver (Priya) arrives disabled, in the Disabled folder', 'Three IT staff get separate admin logins (adm-)'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'HR spreadsheet', note: '13 staff, 1 leaver', glyph: 'CSV', kind: 'hand' }, { name: 'HR front door', note: 'Inbound provisioning app', img: BIMG('hrapp'), kind: 'code' }, { name: 'People in Entra', note: 'Synced up from AD', img: BIMG('users'), kind: 'code' }, { name: 'Admin accounts', note: '3 separate logins', glyph: 'adm-', kind: 'code' }],
        outs: ['<b>13</b> staff in AD and Entra', '<b>3</b> admin accounts', '<b>4</b> nurses auto-assigned'] },
    ],
    overview: { title: 'Six sign-ups, one pipeline, one tenant', goal: "That's the wiring.", text: 'Built with an AI engineering assistant doing the heavy typing. Every change still went through the same review and the same tests.',
      bullets: ['Everything from here is a tour of what it does', 'Glossary: lab/docs/glossary.md', 'Every script that built this is in the repo'], chips: [{ text: 'RAN · TENANT', kind: 'code' }, { text: 'GLOSSARY IN REPO', kind: 'done' }] },
  };
}
const MAP = 'file://' + path.join(OUT, 'map-video.html');
const T = (f) => fs.readFileSync(path.join(OUT, 'term', f), 'utf8');
const ENTRA = 'https://entra.microsoft.com/#view/';

const card = (c) => async (r) => { await r.page.goto(CARD); await r.ov('hideCursor', true); await r.page.evaluate((c) => window.card(c), c); };
const stepsOpen = (c) => async (r) => { await r.page.goto(STEPS); await r.ov('hideCursor', true); await r.page.evaluate((c) => window.steps.init(c), c); await sleep(300); };
const step = (r, i) => r.page.evaluate((i) => window.steps.show(i), i);
const termOpen = async (r) => { await r.page.goto(TERM); await r.ov('hideCursor', true); await sleep(300); };
const cmd = (r, c, cps) => r.page.evaluate(([c, cps]) => window.term.cmd(c, cps), [c, cps]);
const out = (r, t, lps) => r.page.evaluate(([t, lps]) => window.term.out(t, lps), [t, lps]);
const mark = (r, re) => r.page.evaluate((re) => window.term.mark(re), re);
const unmark = (r) => r.page.evaluate(() => window.term.unmark());
const clear = (r) => r.page.evaluate(() => window.term.clear());
const mapGo = (r, go) => r.page.evaluate((go) => { const b = document.createElement('button'); b.setAttribute('data-go', go); b.style.cssText = 'position:fixed;left:-9999px'; document.body.appendChild(b); b.click(); b.remove(); }, go);

export function scenes(ids) {
  const userBlade = (id) => `${ENTRA}Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/${id}/hidePreviewBanner~/true`;
  return [
  { id: '00-face', kind: 'clip', clip: INTRO_FACE_CLIP, beats: [] },
  { id: '01-built', kind: 'local', beats: [
    { say: "Entra is the directory, and E5 because the sign-in rules, admin controls and risk alerts all need it. Azure runs the servers. Then the apps staff sign in to. AWS is the cloud console, where I prove accounts appear and disappear on their own. ServiceNow is the help desk. Okta stands in for a partner clinic that signs in with its own identity provider. GitHub holds all the code, written as Terraform.",
      audio: `${OUT}/clips/built-1.mp3`, prep: async (r) => { await r.page.goto(BMAP); await r.ov('hideCursor', true); await r.page.evaluate((d) => window.bmap.init(d), buildMapData()); await sleep(1400); await r.page.evaluate(() => window.bmap.overview(false)); await sleep(300); },
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 0); } },
    { say: "Two robot identities run the pipeline, one that proposes, one that applies. No passwords. GitHub vouches with a token that lasts minutes, and Microsoft only trusts it from the main branch. I tried it from another branch, it was refused, and I kept the refusal as proof.",
      audio: `${OUT}/clips/built-3.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 2); } },
    { say: "Every change is a pull request. Tests run, a person types approve, Terraform makes the tenant match. Sign-in rules first, in report-only. Then admin tiers. Then access packages. Then detection and the domain controller. Then single sign-on for AWS, ServiceNow and Okta. Sixty-four merged.",
      audio: `${OUT}/clips/built-4.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 3); } },
    { say: "Most hospitals still run on-site Active Directory, so the lab does too. Terraform built DC01 in Azure and a script made it a domain controller. Cloud Sync on it copies accounts up to Entra every few minutes. It shuts down every night to save money.",
      audio: `${OUT}/clips/built-5.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 4); } },
    { say: "Thirteen fake staff in a spreadsheet stand in for HR. A script feeds each row through Microsoft's HR connector into Active Directory, and Cloud Sync carries them to the cloud. One leaver lands disabled. Three IT staff get separate admin logins.",
      audio: `${OUT}/clips/built-6.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 5); } },
    { say: "That's the wiring. Every piece went through the same review, and all of it is in the repo. Now the lab itself.",
      audio: `${OUT}/clips/built-close.mp3`,
      run: async (r) => { await r.page.evaluate(() => { window.bmap.enterAll(); window.bmap.overview(false); }); } },
  ] },
  { id: '02-map', kind: 'local', beats: [
    { say: "Now the lab itself. Ten stops, numbered seven to sixteen so you can find them on the map in the repo. Read it left to right, the way a person moves through the hospital: hired, given access, signing in, doing admin work, watched, leaving, and finally proven to an auditor. I'll walk each one properly in a minute. Here's the short version.",
      audio: `${OUT}/clips/lab-0.mp3`, prep: async (r) => { await r.page.goto(MAP); await r.ov('hideCursor', true); await sleep(2500); await r.page.evaluate(() => { const st = document.createElement('style'); st.textContent = '@keyframes vin{from{opacity:0}to{opacity:1}} #map > g > * { animation: vin .6s ease both; }'; document.head.appendChild(st); document.querySelectorAll('#map > g > *').forEach((e, k) => { e.style.animationDelay = Math.min(k * 20, 1200) + 'ms'; }); }); await mapGo(r, 'overview'); await sleep(1600); },
      run: async (r) => {} },
    { say: "Seven, the source of truth. Everything starts with HR, the official list of who works here. In the lab a spreadsheet plays that part. Access flows out of that list and never back into it, so if HR says you've gone, you're gone.",
      audio: `${OUT}/clips/lab-1.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:source').catch(() => {}); } },
    { say: "Eight, the directory. Two of them, kept in step. Active Directory on the Windows server is what the hospital's PCs still check against. Entra is the cloud copy every modern app checks. Cloud Sync carries accounts up from one to the other, so you fix a person once and it's fixed everywhere.",
      audio: `${OUT}/clips/lab-2.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:directory').catch(() => {}); } },
    { say: "Nine, joiner and mover. A new nurse gets nurse systems on day one, automatically, because of her job title. Anything extra she asks for, a manager approves, and it expires on its own. A few combinations are blocked outright, because one person holding both would be a fraud risk.",
      audio: `${OUT}/clips/lab-3.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:joiner').catch(() => {}); } },
    { say: "Ten, the apps. This is where staff actually go after they sign in. Engineers go to AWS to run servers. Everyone goes to ServiceNow to raise a ticket. And a partner clinic comes in through its own Okta. All three trust the hospital login instead of keeping their own passwords, and for AWS the account appears and disappears with HR.",
      audio: `${OUT}/clips/lab-4.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:apps').catch(() => {}); } },
    { say: "Eleven, the sign-in rules. The checks at the door, every single time. Where you are, what device, how risky it looks, and whether you proved it's you with more than a password. Eleven rules, nine live. Every new one starts in report-only mode, and that's deliberate: a bad rule in a hospital locks out a clinician mid-shift.",
      audio: `${OUT}/clips/lab-5.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:signin').catch(() => {}); } },
    { say: "Twelve, privileged access. Nobody keeps admin power all day. You ask for it, say why, hold it for a few hours, and it switches itself off. Server passwords live in a vault that rotates them and hands them out only against an approved ticket, and the admin works through a recorded session without ever seeing the password. Two honest exceptions: the two emergency accounts that sit outside every rule, and the account that built the lab, which still holds a standing role and is the next thing on the list to move to just-in-time.",
      audio: `${OUT}/clips/lab-6.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:privileged').catch(() => {}); } },
    { say: "Thirteen, detect and respond. Every sign-in and every change lands in Sentinel. Splunk runs the same rules on synthetic test events, not a live feed yet, which shows the detections aren't tied to one product. Rules written as code raise the alarm, say an admin signing in from a new country. And a person approves the lockout before it happens, because locking out the wrong clinician is itself an incident.",
      audio: `${OUT}/clips/lab-7.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:detect').catch(() => {}); } },
    { say: "Fourteen, the leaver, and the robot accounts. HR flips one field. The account goes off, sessions are cut, app access is gone, each step timed. Nine minutes from HR to AWS. The rule is two human owners per robot account so nothing is orphaned; the inventory found four that don't have them yet, and that's the list being worked.",
      audio: `${OUT}/clips/lab-8.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:leaver').catch(() => {}); } },
    { say: "Fifteen, proof. Showing an auditor it works, on demand. Regular reviews of who has what, an evidence binder where every page is fingerprinted and stored where nobody can edit it, and a nightly check that nothing drifted from the approved setup.",
      audio: `${OUT}/clips/lab-9.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:proof').catch(() => {}); } },
    { say: "And sixteen, delivery, runs above all of it: every change is code, reviewed and applied with no stored password. That's the lab at a glance. From here the narrated walkthrough takes over, station by station, on the real screens.",
      audio: `${OUT}/clips/lab-10.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'overview').catch(() => {}); } },
  ] },
  { id: '03-delivery', kind: 'local', beats: [
    { say: "Here is the delivery history: sixty-four merged pull requests. A pull request is a proposed change, shown line by line, with someone named to review it. Merged means it was accepted into the live version. Read the titles like chapters. Day one turned on the sign-in rules in report-only mode. Day two built the admin tiers. Day three added access governance. Then came the detection rules, then the domain controller, then the scripts that wire it all together.",
      prep: termOpen,
      run: async (r, b) => { await cmd(r, 'gh pr list --state merged --limit 40'); await out(r, T('prs.txt'), 22); await r.define('Pull request', 'A proposed change plus a reviewer. Merged means accepted.'); await b.until(0.55); await mark(r, 'Day 1'); await b.until(0.65); await mark(r, 'Day 2'); await b.until(0.72); await mark(r, 'Day 3'); await b.until(0.8); await mark(r, 'enable_sentinel'); await b.until(0.86); await mark(r, 'enable_dc'); await b.until(0.92); await mark(r, '^#3[5-7]|^#36'); } },
    { say: "Before any human looks, the proposal is tested. Thirteen checks run it against a mock copy of the tenant. Some are guard rails that stop a dangerous combination. This one refuses to demand the strongest sign-in for admin activation until the rule that provides it is actually switched on. Otherwise the demand would be hollow, and lock every admin out.",
      run: async (r, b) => { await clear(r); await cmd(r, 'terraform test -var-file=lab.tfvars'); await out(r, T('tf-test.txt'), 9); await r.define('Mocked test', 'The change is rehearsed against a fake tenant first.'); await b.until(0.5); await mark(r, 'pim_auth_context_refused_while'); } },
    { say: "Then it waits at a human gate. The pipeline opens an issue, and the owner types approve. Only then does the robot sign in to Azure, with a token that lasts minutes, and apply the change. There is no stored password anywhere in this pipeline.",
      run: async (r, b) => { await clear(r); await cmd(r, 'gh run view 40549067405');
        await out(r, T('apply-run-view.txt').split('\n').filter((l) => !/ubuntu-latest|^approval \(human gate\): \.github#1|^terraform apply \(prod, reviewer-gated\): \.github#1/.test(l)).join('\n').replace(/\n{3,}/g, '\n\n'), 25);
        await mark(r, 'approval \\(human gate\\)'); await r.define('Apply', 'Terraform makes the tenant match the approved code.'); await b.until(0.45); await cmd(r, "gh issue view 34 --comments | grep -E '^(author|approve|Approved)'");
        await out(r, T('issue34.txt'), 12); await unmark(r); await mark(r, '^approve$|Approved by'); } },
    { say: "And that trust is tested, not assumed. A throwaway branch, a temporary copy of the code made just for this test, tried to sign in as the pipeline's identity. Microsoft refused it, because the robot is only trusted when it runs from the approved production path. That refusal is saved as evidence.",
      run: async (r) => { await clear(r); await cmd(r, 'grep ^E03 lab/evidence/capture-log.csv | fold -s -w 100');
        await out(r, T('e03.txt'), 10); await mark(r, 'AADSTS700213|environment:prod'); await r.define('Throwaway branch', 'A copy of the code made only for a test, then deleted.'); } },
  ] },
  { id: '04-hr-feed', kind: 'local', beats: [
    { say: "Meet Dana Okafor, a new registered nurse. HR is the source of truth, so her record is what starts everything. Here it goes to Microsoft's inbound provisioning API, the front door for HR data, in a standard package called SCIM: her name, title, department, manager, and hire date.",
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => { window.term.title('pwsh — lab/scripts/mock-hr'); document.getElementById('scr').style.fontSize = '18px'; }); },
      run: async (r, b) => { await cmd(r, './Invoke-InboundProvisioning.ps1 -CsvPath dana.csv -UpnDomain contosohealthlab.com -WhatIf');
        await out(r, T('hr-whatif.txt').split('\n').filter((l) => !/What if:|--- \[WhatIf\]|Content-Type|Dry run/.test(l)).join('\n'), 14);
        await r.define('SCIM', "The standard format for sending 'here is a person' between systems."); await b.until(0.5); await mark(r, '"title"|"department"|"hireDate"|"userName"'); } },
    { say: "Before anything is sent, a guard counts the changes. A push that would disable, or move, more than ten people stops cold, because a broken HR export looks exactly like a mass layoff. Here the limit is set to zero on purpose, to show it refusing.",
      run: async (r, b) => { await clear(r); await cmd(r, './Invoke-InboundProvisioning.ps1 -StatusFilter leaver -MaxChanges 0 -WhatIf');
        await out(r, T('hr-guard.txt').replace(/\/Users\/[^:]+\/lab/, 'lab'), 10); await b.until(0.35); await mark(r, 'Mass-change guard: this run|Nothing was sent'); } },
  ] },
  { id: '05-hr-app', kind: 'portal', beats: [
    { say: "In the tenant, the HR provisioning app receives Dana. Its log shows every record it processed and wrote into the on-site directory, Active Directory. Filtering on her employee number shows her being created, and the updates that followed.",
      prep: async (r) => { await r.chip('Source of truth', 'HR owns who works here');
        await r.goto(`${ENTRA}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/appId/${ids.hrAppId}/objectId/${ids.hrSpId}`, 12000); await r.settle();
        await r.click({ text: 'Provisioning logs', exact: true }); await sleep(6000); await r.settle(); },
      run: async (r, b) => { await r.define('Active Directory', "Microsoft's on-site list of accounts. Most hospitals still run one."); await b.until(0.3);
        await r.type({ css: 'input[placeholder="Search Identity"]' }, '100492', 110); await r.page.keyboard.press('Enter'); await sleep(3500);
        await r.ring({ text: /Source ID 100492/, nth: 0, row: true }, 'Dana · HR → AD').catch(() => {}); } },
  ] },
  { id: '06-ad', kind: 'local', beats: [
    { say: "This is a live query on DC01, the lab's domain controller: the server that holds those accounts. The command travels through Azure's run-command, so no password ever appears on a screen or in a log. Thirteen staff, each filed in their department's folder, which Active Directory calls an organizational unit.",
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => window.term.title('zsh — DC01 via managed run command')); },
      run: async (r, b) => { await cmd(r, 'lab/scripts/dc/run-on-dc.py ad-roster.ps1'); await out(r, T('ad-roster.txt').replace(/^run command .*$/m, 'run command lab-c21e072e: ad-roster.ps1 on vm-dc01'), 6); await r.define('Organizational unit', 'A folder in Active Directory. Here, one per department.'); await b.until(0.7); await mark(r, 'dana.okafor'); } },
    { say: "And Priya Nair, who has left, is disabled and parked in the Disabled folder.",
      run: async (r) => { await unmark(r); await mark(r, 'priya.nair'); } },
  ] },
  { id: '07-directory', kind: 'portal', beats: [
    { say: "DC01 itself is a virtual machine: a computer rented in Azure instead of sitting in a server room. It runs Windows Server 2022, it was created by the same pipeline, and it shuts itself down on a schedule to keep the lab cheap.",
      prep: async (r) => { await r.chip('Directory', 'AD is the master, Entra is the hub');
        await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.vmId}/overview`, 14000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'vm-dc01', exact: true, nth: 0 }); await r.define('Virtual machine', 'A computer rented in the cloud, not in a server room.'); await b.until(0.4); await r.ring({ text: /Windows Server 2022 Datacenter/, nth: 0 }, 'Domain controller'); } },
    { say: "Microsoft Entra Cloud Sync is the bridge. It's a small agent installed on DC01 that copies accounts up to Entra ID, the cloud directory, every few minutes. The connection is healthy. It copies only the Workforce and Disabled folders, and it carries a scrambled form of each password, so people have one password in both places.",
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/CloudSync`, 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'corp.contosohealthlab.com', row: true }); await r.define('Cloud Sync', 'The bridge that copies on-site accounts into the cloud directory.'); await b.until(0.45); await r.ring({ text: 'Healthy', exact: true }, 'Healthy'); } },
  ] },
  { id: '08-joiner', kind: 'portal', beats: [
    { say: "Here's Dana in Entra ID, the cloud directory. Nobody created her here by hand. Trace the path: HR record, into Active Directory, over the Cloud Sync bridge, into the cloud. Her job title and department came from HR, and her hire date made the whole trip, which matters next.",
      prep: async (r) => { await r.chip('Joiner & mover', 'Access follows HR'); await r.goto(userBlade(ids.dana), 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'Dana Okafor', exact: true, nth: 0 }); await b.until(0.22); await r.unring(); await r.click({ role: 'tab', name: 'Properties' }); await sleep(2500);
        await r.wheel(330, { x: 1100, y: 560 }); await sleep(1300);
        await r.ring({ text: 'On-premises sync enabled', exact: true }, 'Synced from AD').catch(() => {}); await b.until(0.58);
        await r.ring({ text: 'Registered Nurse', exact: true }, 'Job title from HR').catch(() => {}); await b.until(0.8);
        await r.ring({ text: 'Employee hire date', exact: true }, 'Hire date from HR').catch(() => {}); } },
    { say: "An access package is a bundle of access for one job: the apps and groups it needs, wrapped with rules about who gets it and for how long. There are four. Nurse Clinical Apps and ICU Critical Care are given automatically from the HR department and job title. ICU Float is requested, needs a manager's approval, and expires after a hundred and eighty days. Pharmacy Controlled Substances is request-only. Because Dana is in Nursing, she got the nurse package on her own: no ticket, no request. Four nurses, four assignments.",
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement`, 12000); await r.settle(); },
      run: async (r, b) => { await r.define('Access package', 'A bundle of access for one job, with rules on who gets it and for how long.'); await b.until(0.28); await r.ring({ text: 'Nurse - Clinical Apps', row: true }, 'Automatic'); await b.until(0.38); await r.ring({ text: 'ICU - Critical Care Apps', row: true }, 'Automatic'); await b.until(0.5); await r.ring({ text: 'ICU - Float Access', row: true }, 'Request · approval · 180 days'); await b.until(0.63); await r.ring({ text: /Pharmacy - Controlled Substances/, row: true }, 'Request only'); await b.until(0.75); await r.ring({ text: 'Nurse - Clinical Apps', row: true }, 'Dana · 4 active'); } },
    { say: "Some doors never open together. The nurse package and the pharmacy package are marked incompatible, so nobody can hold both. That's called separation of duties, and the system enforces it rather than a manager remembering to.",
      prep: async (r) => { await r.unring(); await r.click({ text: 'Nurse - Clinical Apps', exact: true }); await sleep(5000); await r.settle(200);
        await r.click({ text: /^Separation of duties$/i }); await sleep(3500); await r.click({ text: 'Incompatible With', exact: true }); await sleep(2500); },
      run: async (r, b) => { await b.until(0.3); await r.ring({ text: /Pharmacy - Controlled Substances/, row: true }, 'Never together').catch(() => {}); await b.until(0.55); await r.define('Separation of duties', 'Two kinds of access that must never sit on one person.'); } },
    { say: "Lifecycle workflows are checklists that run on HR dates: a joiner workflow on a nursing hire's first day, and a leaver workflow that runs the moment HR says someone has gone.",
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_LifecycleManagement/CommonMenuBlade/~/workflows`, 12000); await r.settle(); },
      run: async (r, b) => { await r.define('Lifecycle workflow', 'A checklist that runs on an HR date: first day, or last.'); await r.ring({ text: /Contoso - Joiner/, row: true }, 'Day 1'); await b.until(0.55); await r.ring({ text: /Contoso - Leaver/, row: true }, 'Real time'); } },
  ] },
  { id: '09-signin', kind: 'portal', beats: [
    { say: "Conditional Access is the bouncer at every sign-in. Each policy is one rule: who it applies to, and what it demands. There are eleven. Everyone must prove it's them with a second factor. Admins need the phishing-resistant kind, like a security key. Old protocols that cannot do a second factor are blocked. And a sign-in that looks high-risk is stopped.",
      prep: async (r) => { await r.chip('Sign-in rules', 'No lockout'); await r.goto(`${ENTRA}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`, 12000); await r.settle();
        for (const f of r.page.frames()) await f.evaluate(() => { for (const b of document.querySelectorAll('button[aria-label*="lose" i], button[title*="lose" i]')) { const t = (b.closest('div') || {}).innerText || ''; if (/policy plans|Migrate to Conditional Access/i.test(b.parentElement?.parentElement?.innerText || t)) b.click(); } }).catch(() => {});
        await sleep(800); await r.wheel(420, { x: 1000, y: 600 }); await sleep(1000); },
      run: async (r, b) => { await r.define('Conditional Access', 'Rules checked at every sign-in: who you are, what you must prove.'); await b.until(0.28); await r.ring({ text: /^CA001 - / , row: true }, 'Everyone: second factor'); await b.until(0.45); await r.ring({ text: /^CA002 - /, row: true }, 'Admins: phishing-resistant'); await b.until(0.68); await r.ring({ text: /^CA003 - /, row: true }, 'Old protocols blocked'); await b.until(0.85); await r.ring({ text: /^CA007 - /, row: true }, 'High risk: blocked'); } },
    { say: "Nine of the eleven are enforced now. Each one started in report-only, which watches and logs without blocking, and graduated through its own reviewed change once the report showed it would not lock out a clinician. Two stay report-only on purpose, because they demand passkeys the admins don't hold yet. And two break-glass accounts, emergency logins kept in a safe, are excluded from all of them, so there is always a way back in.",
      run: async (r, b) => { await r.ring({ text: 'State', exact: true }, 'Report-only').catch(() => {}); await r.define('Report-only', 'The rule logs what it would block, without blocking yet.'); await b.until(0.62); await r.unring(); await r.define('Break-glass account', 'An emergency login kept in a safe, excluded from every rule.'); } },
  ] },
  { id: '10-pim', kind: 'portal', beats: [
    { say: "Admin power is tiered, and never permanent. The tool is Privileged Identity Management, PIM. Instead of being an admin all day, you're eligible, and you switch the power on for a short window when you need it. Tier zero holds the roles that could change security itself. Switching one on needs a ticket number, a second factor, and another person's approval, for four hours at most.",
      prep: async (r) => { await r.chip('Privileged access', 'No standing privilege'); await r.goto(`${ENTRA}Microsoft_Azure_PIMCommon/CommonMenuBlade/~/aadgroup`, 12000); await r.settle(); },
      run: async (r, b) => { await r.define('PIM', 'Admin power you switch on for a short window. It switches itself off.'); await r.type({ css: 'input[placeholder*="Search by group"]' }, 'PIM-Tier', 90); await sleep(3000); await r.ring({ text: 'PIM-Tier0-CA-Admins', row: true }, 'Tier 0 · approval + ticket · 4h'); } },
    { say: "Tier one is the service desk. Raj Patel has a separate admin account, and it is eligible for Helpdesk, but only over the everyday workforce accounts. He cannot touch another admin, and he cannot touch an executive.",
      prep: async (r) => { await r.unring(); await r.click({ css: 'input[placeholder*="Search by group"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('PIM-Tier1', { delay: 30 }); await sleep(2500);
        await r.click({ text: 'PIM-Tier1-Helpdesk', exact: true }); await sleep(5000); await r.settle(200);
        await r.click({ text: 'Assignments', exact: true }); await sleep(4000); await r.click({ text: 'Eligible assignments', exact: true }); await sleep(3000); },
      run: async (r, b) => { await b.until(0.25); await r.ring({ text: /adm-raj\.patel/, nth: 0, row: true }, 'Eligible · not active').catch(() => {}); await b.until(0.6); await r.define('Eligible vs active', 'Eligible: may switch it on. Active: it is on, with an end time.'); } },
  ] },
  { id: '11-pim-live', kind: 'fresh', beats: [
    { say: "Now watch it live. Raj signs in as his admin account with a Temporary Access Pass: a one-time code issued for this demo that works exactly once, so there is no password to steal.",
      prep: async (r) => { await r.chip('Privileged access', 'Live activation');
        // One-time pass, held only in this process's memory.
        r.secret = execFileSync('pwsh', ['-NoProfile', '-File', path.join(path.dirname(new URL(import.meta.url).pathname), 'issue-tap.ps1'), '-Upn', ids.rajUpn, '-TenantId', ids.tenantId], { encoding: 'utf8' }).trim();
        if (!/^\S{8,}$/.test(r.secret)) throw new Error('TAP issue failed');
        await r.goto(`${ENTRA}Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup`, 8000); },
      run: async (r) => { await r.define('Temporary Access Pass', 'A one-time code that signs you in once, instead of a password.'); await r.type({ css: 'input[name=loginfmt]' }, ids.rajUpn, 55); await r.click({ css: 'input[type=submit]' }); await sleep(4500);
        const box = await r.find({ css: 'input[name=accesspass], input#accesspass, input[type=password]' }); await r.click({ css: 'input[name=accesspass], input#accesspass, input[type=password]' });
        await r.page.keyboard.type(r.secret, { delay: 60 }); r.secret = null; await sleep(400); await r.click({ css: 'input[type=submit]' }); } , minHold: 0 },
    { say: "Under My roles, he holds no admin rights at all. Just one eligible group, Helpdesk. He clicks Activate.",
      prep: async (r) => { for (let i = 0; i < 10; i++) { const t = await r.page.locator('body').innerText().catch(() => ''); if (/Stay signed in/i.test(t)) { await r.page.locator('#idBtn_Back, input[value="No"]').first().click().catch(() => {}); }
          if (/Skip for now|Ask later|Not now/i.test(t)) await r.page.getByText(/Skip for now|Ask later|Not now/i).first().click().catch(() => {});
          if (/ActivationMenuBlade/.test(r.page.url()) && /Eligible assignments|PIM-Tier1-Helpdesk/i.test(t + (await Promise.all(r.page.frames().map((f) => f.locator('body').innerText().catch(() => '')))).join(' '))) break; await sleep(4000); }
        await sleep(5000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'PIM-Tier1-Helpdesk', row: true }, 'Eligible'); await b.until(0.75); await r.unring();
        await r.click((f) => f.getByRole('button', { name: 'Activate', exact: true }).first()); } },
    { say: "He asks for one hour instead of the eight allowed, and types a reason, which lands in the audit log. Tier one needs no approver, so this takes seconds.",
      prep: async (r) => { await sleep(4000); await r.settle(200); },
      run: async (r, b) => { await r.click({ css: 'input[aria-label*="slider value"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('1', { delay: 120 }); await r.page.keyboard.press('Tab');
        await b.until(0.3); await r.type({ css: 'textarea' }, 'INC-4821: unlock a nurse on 4 West before shift change', 40); await b.until(0.8);
        await r.click((f) => f.getByRole('button', { name: 'Activate', exact: true }).last()); } },
    { say: "He's active now, with an end time. When it passes, the power simply disappears. No one has to remember to take it away.",
      prep: async (r) => {
        // PIM reloads the browser by itself once the activation stages finish; wait that out first.
        const allText = async () => (await Promise.all(r.page.frames().map((f) => f.locator('body').innerText().catch(() => '')))).join(' ');
        for (let k = 0; k < 60; k++) { if (!/Refresh in \d+ second|Processing your request|Validating (your )?request|Activating role/i.test(await allText())) break; await sleep(2000); }
        await sleep(12000); await r.settle();
        for (let k = 0; k < 6; k++) {
          await r.find({ text: 'Active assignments', exact: true }, { timeout: 20000 }).catch(() => {}); await sleep(1500);
          await r.click({ text: 'Active assignments', exact: true }).catch(() => {}); await sleep(4000);
          // Only the Active tab offers Deactivate, so this proves the tab and the activation.
          const ok = await r.find({ text: 'Deactivate', exact: true }, { timeout: 6000 }).then(() => true).catch(() => false);
          if (ok) break; await r.page.reload({ waitUntil: 'domcontentloaded' }).catch(() => {}); await sleep(10000);
        } await sleep(1500); await r.settle(); },
      run: async (r, b) => { await b.until(0.1); await r.ring({ text: 'PIM-Tier1-Helpdesk', row: true }, 'Active · ends in 1 hour').catch(() => {}); } },
  ] },
  { id: '12-detect', kind: 'portal', beats: [
    { say: "Detection. Microsoft Defender is the security console where incidents are worked. Microsoft Sentinel is the alarm system behind it: every sign-in and every settings change is written to a log store, and rules read that log looking for trouble. Eleven rules were written for this hospital. Five are everyday watches: a break-glass login, a sign-in from a blocked country, a flood of failed passwords from one address, old protocols still being tried, and every admin activation.",
      prep: async (r) => { await r.chip('Detect & respond', 'Contained in minutes'); await r.goto(`https://security.microsoft.com/sentinel/analytics?tid=${ids.tenantId}`, 16000); await r.settle(); },
      run: async (r, b) => { await r.define('Sentinel', 'The alarm system: rules that read the logs and raise incidents.'); await b.until(0.3); await r.ring({ text: 'Active rules', exact: true }, '11 rules for this hospital').catch(() => {}); await b.until(0.6); await r.unring();
        await r.type({ css: 'input[placeholder*="Search by ID"]' }, 'Contoso -', 70); await sleep(3500); await r.ring({ text: /^Contoso - /, nth: 0, row: true }, 'Everyday watches').catch(() => {}); } },
    { say: "The other six are identity threat detection, ITDR for short: the moves an attacker makes once they're inside. An admin role handed out without PIM. A privileged group gaining a member outside PIM. An app being given permissions. A credential added to an app, which is a back door. A sign-in rule changed outside the pipeline. And an admin changing someone else's sign-in method. Each is a known attacker move: get standing power, or plant a way back in.",
      prep: async (r) => { await r.unring(); await r.click({ css: 'input[placeholder*="Search by ID"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('ITDR', { delay: 40 }); await sleep(3500); },
      run: async (r, b) => { await r.define('ITDR', "Identity threat detection: spotting an attacker's moves inside the directory."); await b.until(0.22);
        for (let i = 0; i < 6; i++) { await r.ring({ text: /^Contoso ITDR/, nth: i, row: true }).catch(() => {}); await b.until(0.22 + 0.12 * (i + 1)); } } },
    { say: "And these incidents are real. While the lab was being built, a role was handed to the sync service account directly, and an app was granted permissions. Both were legitimate setup steps, and Sentinel flagged both anyway. And this very demo raised two more: the one-time pass issued to Raj, and his activation. That is the point: the rules don't know who you are.",
      prep: async (r) => { await r.unring(); await r.goto(`https://security.microsoft.com/incidents?tid=${ids.tenantId}`, 16000); await r.settle();
        // Defender sometimes adds a default "Priority score" filter that hides low-score incidents: clear it.
        for (const f of r.page.frames()) { const x = f.getByRole('button', { name: /^Clear priority/i }).first(); if (await x.isVisible().catch(() => false)) await x.click().catch(() => {}); }
        await sleep(4000); await r.settle(); },
      run: async (r, b) => { await r.define('Incident', 'One case: its alerts, the accounts involved, and the raw log lines.'); await r.ring({ text: /Directory role assigned outside PIM/, nth: 0, row: true }, 'High'); await b.until(0.4); await r.ring({ text: /Permission granted to an applicati/, nth: 0, row: true }, 'App permissions'); await b.until(0.62); await r.ring({ text: /Authentication method changed/, nth: 0, row: true }, 'The pass issued to Raj').catch(() => {}); await b.until(0.8); await r.ring({ text: /PIM activation/, nth: 0, row: true }, "Raj's activation").catch(() => {}); } },
    { say: "Each incident opens with its alerts, the accounts involved, and the raw log evidence, ready for an analyst to work.",
      prep: async (r) => { await r.unring(); },
      run: async (r) => { await r.click({ text: /Directory role assigned outside PIM/, nth: 0 }); await sleep(6000); await r.settle(200); } },
  ] },
  { id: '13-leaver', kind: 'portal', beats: [
    { say: "When HR says someone is gone, the same path runs in reverse. Priya Nair's HR record was marked as a leaver. The provisioning app disabled her in Active Directory, moved her to the Disabled folder, and Cloud Sync carried that up to the cloud.",
      prep: async (r) => { await r.chip('Leaver', 'No way back in, timed'); await r.goto(userBlade(ids.priya), 12000); await r.settle(); },
      run: async (r, b) => { await r.define('Leaver', 'HR marks someone gone; the account is disabled everywhere, automatically.'); await r.ring({ text: 'Priya Nair', exact: true, nth: 0 }); await b.until(0.55); await r.ring({ text: /^\W*Disabled$/, nth: 0 }, 'Disabled by HR'); } },
    { say: "Her cloud account is disabled, and she holds no groups, apps, or roles. Nobody filed a ticket for any of it.",
      run: async (r) => { await r.ring({ text: 'Group memberships', exact: true }); } },
  ] },
  { id: '14-worm', kind: 'portal', beats: [
    { say: "Proof goes into a write-once evidence store. WORM stands for write once, read many: once a file is in, nobody can delete or alter it. Every capture, baseline, and verification run lands here.",
      prep: async (r) => { await r.chip('Proof', 'Proof on demand'); await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.stId}/containersList`, 14000); await r.settle();
        await r.click({ text: 'evidence', exact: true }); await sleep(6000); await r.settle(); },
      run: async (r, b) => { await r.define('WORM store', 'Write once, read many: evidence nobody can delete or change.'); await b.until(0.3); await r.ring({ text: 'captures', exact: true, row: true }, 'Hashed evidence'); } },
    { say: "The retention policy is six years, the HIPAA documentation window. Anyone who writes evidence can add, but cannot delete, and an overwrite only creates a new version next to the old one.",
      prep: async (r) => { await r.unring(); await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.stId}/dataProtection`, 12000); await r.settle();
        await r.reveal({ text: /version-level immutability/i, nth: 0 }); await sleep(800); },
      run: async (r, b) => { await b.until(0.15); await r.ring({ text: /version-level immutability/i, nth: 0 }, '2190 days · WORM'); await b.until(0.6); await r.ring({ text: /Enable versioning for blobs/i, nth: 0 }, 'Overwrite = new version').catch(() => {}); } },
  ] },
  { id: '15-evidence', kind: 'local', beats: [
    { say: "Every step leaves a numbered evidence row: what happened, when, a fingerprint of the file, and where it is stored. The before baseline, the admin settings read back, the WORM test, and even the test where the pipeline's own identity was refused.",
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => { document.getElementById('scr').style.fontSize = '18px'; }); },
      run: async (r, b) => { await cmd(r, 'grep ^E lab/evidence/capture-log.csv | cut -c1-140');
        await out(r, T('elog.txt'), 8); await r.define('Hash', 'A fingerprint of a file. Change one byte and it changes.'); await b.until(0.55); await mark(r, '^E10|^E16a|^E06|^E03'); } },
  ] },
  { id: '17-close', kind: 'local', beats: [
    { say: "Contoso Health. Access follows HR, admin power is temporary, and every change is proven. The glossary and every script are in the repo. Thanks for watching.",
      prep: card({ kick: 'Contoso Health identity lab', title: 'Access follows HR.<br>Admin power is <em>temporary</em>.<br>Every change is proven.', sub: 'Glossary: lab/docs/glossary.md', chips: [] }) },
  ] },
  ];
}
