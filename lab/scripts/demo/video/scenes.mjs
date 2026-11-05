// Scenes for the lab demo video: narration beats + what the camera does.
// Narration states only what the tenant shows (checked 2026-10-27; corrected 2026-11-05 from the readiness reports).
import fs from 'node:fs';
import path from 'node:path';
import { OUT, REPO, sleep } from './rec.mjs';
import { execFileSync } from 'node:child_process';

const PAGES = path.join(path.dirname(new URL(import.meta.url).pathname), 'pages');
const TERM = 'file://' + path.join(PAGES, 'term.html');
const CARD = 'file://' + path.join(PAGES, 'card.html');
const STEPS = 'file://' + path.join(PAGES, 'steps.html');
const SHOT = 'file://' + path.join(PAGES, 'shot.html');
const CODE = 'file://' + path.join(PAGES, 'code.html');
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
      { title: 'Sign-ups', kicker: 'Six platforms, by hand', goal: 'Real accounts on every platform', text: 'Every platform is a real account, on a free trial or a free developer edition; AWS is pay-as-you-go. Opening them is the one step a person has to do: a card, a phone, a verification mail.',
        bullets: ['Microsoft Entra: the cloud directory (E5, Governance and Intune trials)', 'Azure: the servers and storage, on a free-trial subscription', 'AWS, ServiceNow, Okta: the apps staff will sign in to', 'GitHub: every line of code, in a private repository', 'contosohealthlab.com: the hospital\'s own web name, so logins look like the hospital'],
        chips: [{ text: 'BY HAND', kind: 'hand' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'Microsoft Entra', note: 'Where every staff login lives', img: BIMG('entra'), kind: 'hand' }, { name: 'Azure', note: 'Hosts the server and the evidence files', img: BIMG('azure'), kind: 'hand' }, { name: 'AWS', note: "Amazon's cloud, where hospitals run their own apps", img: BIMG('aws'), kind: 'hand' },
                { name: 'ServiceNow', note: 'The IT help desk', img: BIMG('servicenow'), kind: 'hand' }, { name: 'Okta', note: "A partner clinic's own login system", img: BIMG('okta'), kind: 'hand' }, { name: 'GitHub', note: 'Where the code and the change history live', img: BIMG('github'), kind: 'hand' }],
        outs: ['<b>6</b> accounts', '<b>1</b> verified domain'] },
      { title: 'The pipeline', kicker: 'More than 100 reviewed changes', goal: 'Reviewed, repeatable, provable', text: 'Every change is a pull request. Checks rehearse it, a person approves it, Terraform applies it. That is how the lab was built, in days.',
        bullets: ['Day 1: sign-in rules, report-only', 'Day 2: admin tiers (PIM)', 'Day 3: access governance (packages, workflows)', 'Then: 17 detection rules, then the domain controller, then single sign-on for AWS, ServiceNow and Okta, with automatic accounts for AWS and ServiceNow'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'Pull request', note: 'A change, its plan and an AI review', img: BIMG('github'), kind: 'code' }, { name: 'Checks', note: 'Automatic, on every change', glyph: '✓', kind: 'code' }, { name: 'Approve', note: 'A person types it', glyph: 'approve', kind: 'hand' }, { name: 'Terraform apply', note: 'Makes the tenant match', glyph: 'TF', kind: 'code' }],
        outs: ['<b>100+</b> reviewed changes', 'Automatic checks on every change'] },
      { title: 'The directory', kicker: 'DC01 + Cloud Sync', goal: 'On-site accounts flow to the cloud', text: 'A Windows server in Azure was promoted to a domain controller, the on-site directory most hospitals still run. The Cloud Sync agent on it copies accounts up to Entra.',
        bullets: ['DC01: Windows Server 2022, created by the pipeline, shuts down nightly', 'Cloud Sync: copies the Workforce and Disabled folders up to Entra on a schedule', 'One password in both places, carried as a scrambled hash'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'AGENT BY SCRIPT', kind: 'hand' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'DC01', note: 'Windows Server 2022 in Azure', img: BIMG('dc01'), kind: 'code' }, { name: 'Cloud Sync agent', note: 'Installed on DC01', img: BIMG('cloudsync'), kind: 'hand' }, { name: 'Entra ID', note: 'The cloud directory', img: BIMG('entra'), kind: 'code' }],
        outs: ['<b>1</b> domain controller', 'One login, both places'] },
      { title: 'The people', kicker: '13 staff, 3 admins', goal: 'Access follows HR from day one', text: 'A spreadsheet of thirteen fake staff stands in for HR. It went through Microsoft\'s HR front door into the directory, each person in the right department, then up to the cloud.',
        bullets: ['HR row → inbound provisioning API → Active Directory → Cloud Sync → Entra', 'One leaver (Priya) arrives disabled, in the Disabled folder', 'Three IT staff get separate admin logins (adm-)'],
        chips: [{ text: 'AS CODE', kind: 'code' }, { text: 'DONE', kind: 'done' }],
        tiles: [{ name: 'HR spreadsheet', note: '13 fake staff', glyph: 'CSV', kind: 'hand' }, { name: 'HR front door', note: 'Inbound provisioning app', img: BIMG('hrapp'), kind: 'code' }, { name: 'People in Entra', note: 'Synced up from AD', img: BIMG('users'), kind: 'code' }, { name: 'Admin accounts', note: '3 separate logins', glyph: 'adm-', kind: 'code' }],
        outs: ['<b>13</b> staff in AD and Entra', '<b>3</b> admin accounts', 'Nurses get their apps by rule'] },
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
    { say: "Here's how it's wired. One, the sign-ups. Microsoft is the center: Entra is everyone's work badge, and Azure runs the servers. HR decides who works here, and everything else plugs into Entra: ServiceNow, AWS and Okta. GitHub holds the code.", audio: `${OUT}/clips/km/01-built-0.mp3`, prep: async (r) => { await r.page.goto(BMAP); await r.ov('hideCursor', true); await r.page.evaluate((d) => window.bmap.init(d), buildMapData()); await sleep(1400); await r.page.evaluate(() => window.bmap.overview(false)); await sleep(300); },
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 0); } },
    { say: "Two, the pipeline. Every change is written as code, tested, and approved by a person before it goes live. More than a hundred reviewed changes, so anyone can see what changed and who approved it.", audio: `${OUT}/clips/km/01-built-1.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 1); } },
    { say: "Three, the directory. Hospital PCs still use an older on-site login system, Active Directory. Cloud Sync copies it to Entra, so one login works on old PCs and new cloud apps.", audio: `${OUT}/clips/km/01-built-2.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 2); } },
    { say: "Four, the people. Thirteen fake staff in a spreadsheet play HR. Each one flows in automatically. Nobody creates an account by hand.", audio: `${OUT}/clips/km/01-built-3.mp3`,
      run: async (r, b) => { await b.until(0.02); await bmapGo(r, 3); } },
    { say: "That's the setup. Now what it does.", audio: `${OUT}/clips/km/01-built-4.mp3`,
      run: async (r) => { await r.page.evaluate(() => { window.bmap.enterAll(); window.bmap.overview(false); }); } },
  ] },
  { id: '02-map', kind: 'local', beats: [
    { say: "Here's the lab running, in the order a person moves through it. At each stop: what connects to Entra, and why.", audio: `${OUT}/clips/km/02-map-0.mp3`, prep: async (r) => { await r.page.goto(MAP); await r.ov('hideCursor', true); await sleep(2500); await r.page.evaluate(() => { const st = document.createElement('style'); st.textContent = '@keyframes vin{from{opacity:0}to{opacity:1}} #map > g > * { animation: vin .6s ease both; }'; document.head.appendChild(st); document.querySelectorAll('#map > g > *').forEach((e, k) => { e.style.animationDelay = Math.min(k * 20, 1200) + 'ms'; }); }); await mapGo(r, 'overview'); await sleep(1600); },
      run: async (r) => {} },
    { say: "Five, HR to Entra. When HR hires someone, their login is made automatically. Why: access starts and stops with HR, not with a ticket.", audio: `${OUT}/clips/km/02-map-1.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:source').catch(() => {}); } },
    { say: "Six, Active Directory to Entra. One person, one login, on-site and in the cloud. Why: fix someone once and it's fixed everywhere.", audio: `${OUT}/clips/km/02-map-2.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:directory').catch(() => {}); } },
    { say: "Seven, Entra to the apps a job needs. A nurse gets nurse apps on day one. Extras need a manager's OK, and they expire. Why: no waiting on day one, and no access piling up.", audio: `${OUT}/clips/km/02-map-3.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:joiner').catch(() => {}); } },
    { say: "Eight, Entra to outside systems. ServiceNow is the IT help desk. AWS is Amazon's cloud, where hospitals run their own apps. Okta is the login of a clinic the hospital bought. All three trust Entra. Why: one switch turns someone off in every app that trusts Entra.", audio: `${OUT}/clips/km/02-map-4.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:apps').catch(() => {}); } },
    { say: "Nine, sign-in rules. A password isn't enough: everyone needs a second check, and the IT admins have phishing-proof passkeys. Why: a stolen password gets nobody in.", audio: `${OUT}/clips/km/02-map-5.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:signin').catch(() => {}); } },
    { say: "Ten, admin power. No admin keeps it day to day, in Entra or in AWS; they borrow it for a few hours, with a reason, and it switches off. Only the build account and a few system and emergency accounts hold it. Why: a stolen admin account can't do damage all day.", audio: `${OUT}/clips/km/02-map-6.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:privileged').catch(() => {}); } },
    { say: "Eleven, alarms. Microsoft Sentinel watches every sign-in and change. I wrote twenty-two alarm rules, and all twenty-two fire in Splunk too. Why: catch misuse fast, whatever tool the hospital owns.", audio: `${OUT}/clips/km/02-map-7.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:detect').catch(() => {}); } },
    { say: "Twelve, leaving. HR marks Dana as gone, and everything closes on its own: on-site in seven seconds, the cloud in three minutes, AWS in nine. Why: no access after the last day.", audio: `${OUT}/clips/km/02-map-8.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:leaver').catch(() => {}); } },
    { say: "Thirteen, proof. The evidence is filed where nobody can edit it. Why: an auditor can check it instead of taking my word.", audio: `${OUT}/clips/km/02-map-9.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'station:proof').catch(() => {}); } },
    { say: "And fourteen, delivery: all of it ships as reviewed code, and the pipeline's own identities are set up by hand, on purpose. Now each piece, live.", audio: `${OUT}/clips/km/02-map-10.mp3`,
      run: async (r, b) => { await b.until(0.02); await mapGo(r, 'delivery').catch(() => {}); } },
  ] },
  { id: '03-delivery', kind: 'local', beats: [
    { say: "Piece one, the blueprints. This is the change history: more than a hundred approved changes. Each one is a pull request, a proposed edit shown line by line before anything is built. Read the titles like chapters: sign-in rules, then admin power, then access, then the cameras, the server and the outside doors. From here I follow one nurse, Dana, from her first day to her last.", audio: `${OUT}/clips/km/03-delivery-0.mp3`,
      prep: termOpen,
      run: async (r, b) => { await cmd(r, 'gh pr list --state merged --limit 40'); await out(r, T('prs.txt'), 22); await r.define('Pull request', 'A proposed change plus a reviewer. Merged means accepted.'); await b.until(0.55); await mark(r, 'Day 1'); await b.until(0.65); await mark(r, 'Day 2'); await b.until(0.72); await mark(r, 'Day 3'); await b.until(0.8); await mark(r, 'enable_sentinel'); await b.until(0.86); await mark(r, 'enable_dc'); await b.until(0.92); await mark(r, '^#3[5-7]|^#36'); } },
    { say: "Before a person even looks, the change is tested. Thirteen tests rehearse it against a fake copy of the hospital. Some are guard rails. This one refuses to demand the strongest sign-in for admins while the rule that provides it is switched off. Otherwise every admin would be locked out.", audio: `${OUT}/clips/km/03-delivery-1.mp3`,
      run: async (r, b) => { await clear(r); await cmd(r, 'terraform test -var-file=lab.tfvars'); await out(r, T('tf-test.txt'), 9); await r.define('Mocked test', 'The change is rehearsed against a fake tenant first.'); await b.until(0.5); await mark(r, 'pim_auth_context_refused_while'); } },
    { say: "Then it stops at a human gate. A person types approve, and only then is the change built, signing in with a pass that lasts minutes, with no stored password. One honest caveat: here I'm both the author and the approver. In production that's a different person, enforced by the system.", audio: `${OUT}/clips/km/03-delivery-2.mp3`,
      run: async (r, b) => { await clear(r); await cmd(r, 'gh run view 40549067405');
        await out(r, T('apply-run-view.txt').split('\n').filter((l) => !/ubuntu-latest|^approval \(human gate\): \.github#1|^terraform apply \(prod, reviewer-gated\): \.github#1/.test(l)).join('\n').replace(/\n{3,}/g, '\n\n'), 25);
        await mark(r, 'approval \\(human gate\\)'); await r.define('Apply', 'Terraform makes the tenant match the approved code.'); await b.until(0.45); await cmd(r, "gh issue view 34 --comments | grep -E '^(author|approve|Approved)'");
        await out(r, T('issue34.txt'), 12); await unmark(r); await mark(r, '^approve$|Approved by'); } },
    { say: "And the gate is tested, not assumed. A throwaway copy of the code tried to build anyway. Microsoft refused it, because only the approved path is trusted. That refusal is kept as evidence.", audio: `${OUT}/clips/km/03-delivery-3.mp3`,
      run: async (r) => { await clear(r); await cmd(r, 'grep ^E03 lab/evidence/capture-log.csv | fold -s -w 100');
        await out(r, T('e03.txt'), 10); await mark(r, 'AADSTS700213|environment:prod'); await r.define('Throwaway branch', 'A copy of the code made only for a test, then deleted.'); } },
  ] },
  { id: '04-hr-feed', kind: 'local', beats: [
    { say: "Piece two, hired. Meet Dana Okafor, a new registered nurse. Everything starts with HR, so her record is the first thing that moves. It goes to Microsoft's front door for HR data, in a standard format called SCIM: her name, title, department, manager and start date.", audio: `${OUT}/clips/km/04-hr-feed-0.mp3`,
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => { window.term.title('pwsh — lab/scripts/mock-hr'); document.getElementById('scr').style.fontSize = '18px'; }); },
      run: async (r, b) => { await cmd(r, './Invoke-InboundProvisioning.ps1 -CsvPath dana.csv -UpnDomain contosohealthlab.com -WhatIf');
        await out(r, T('hr-whatif.txt').split('\n').filter((l) => !/What if:|--- \[WhatIf\]|Content-Type|Dry run/.test(l)).join('\n'), 14);
        await r.define('SCIM', "The standard format for sending 'here is a person' between systems."); await b.until(0.5); await mark(r, '"title"|"department"|"hireDate"|"userName"'); } },
    { say: "Before anything is sent, a guard counts the changes. If a push would switch off or move more than ten people, it stops, because a broken HR file looks exactly like a mass layoff. Here the limit is set to zero on purpose, so you can see it refuse.", audio: `${OUT}/clips/km/04-hr-feed-1.mp3`,
      run: async (r, b) => { await clear(r); await cmd(r, './Invoke-InboundProvisioning.ps1 -StatusFilter leaver -MaxChanges 0 -WhatIf');
        await out(r, T('hr-guard.txt').replace(/\/Users\/[^:]+\/lab/, 'lab'), 10); await b.until(0.35); await mark(r, 'Mass-change guard: this run|Nothing was sent'); } },
  ] },
  { id: '05-hr-app', kind: 'portal', beats: [
    { say: "In the badge system, HR's front door receives Dana. Its log shows every record it processed and wrote into the badge list. Filter on her employee number and you see her created, and every update after.", audio: `${OUT}/clips/km/05-hr-app-0.mp3`,
      prep: async (r) => { await r.chip('Source of truth', 'HR owns who works here');
        await r.goto(`${ENTRA}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/appId/${ids.hrAppId}/objectId/${ids.hrSpId}`, 12000); await r.settle();
        await r.click({ text: 'Provisioning logs', exact: true }); await sleep(6000); await r.settle(); },
      run: async (r, b) => { await r.define('Active Directory', "Microsoft's on-site list of accounts. Most hospitals still run one."); await b.until(0.3);
        await r.type({ css: 'input[placeholder="Search Identity"]' }, '100492', 110); await r.page.keyboard.press('Enter'); await sleep(3500);
        await r.ring({ text: /Source ID 100492/, nth: 0, row: true }, 'Dana · HR → AD').catch(() => {}); } },
  ] },
  { id: '06-ad', kind: 'local', beats: [
    { say: "This is the badge list itself, Active Directory, queried live on the server. The command goes through Azure, so no password ever shows on screen. Thirteen staff, each filed in their department's folder.", audio: `${OUT}/clips/km/06-ad-0.mp3`,
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => window.term.title('zsh — DC01 via managed run command')); },
      run: async (r, b) => { await cmd(r, 'lab/scripts/dc/run-on-dc.py ad-roster.ps1'); await out(r, T('ad-roster.txt').replace(/^run command .*$/m, 'run command lab-c21e072e: ad-roster.ps1 on vm-dc01'), 6); await r.define('Organizational unit', 'A folder in Active Directory. Here, one per department.'); await b.until(0.7); await mark(r, 'dana.okafor'); } },
    { say: "And Priya Nair, who has already left, sits switched off in the Disabled folder.", audio: `${OUT}/clips/km/06-ad-1.mp3`,
      run: async (r) => { await unmark(r); await mark(r, 'priya.nair'); } },
  ] },
  { id: '07-directory', kind: 'portal', beats: [
    { say: "Piece three, the badge list. Hospitals still run this older list because their PCs check it. Here it lives on DC01, a Windows server rented in Azure, the server room. The blueprints created it, and it shuts itself down at night to keep costs down.", audio: `${OUT}/clips/km/07-directory-0.mp3`,
      prep: async (r) => { await r.chip('Directory', 'AD is the master, Entra is the hub');
        await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.vmId}/overview`, 14000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'vm-dc01', exact: true, nth: 0 }); await r.define('Virtual machine', 'A computer rented in the cloud, not in a server room.'); await b.until(0.4); await r.ring({ text: /Windows Server 2022 Datacenter/, nth: 0 }, 'Domain controller'); } },
    { say: "Cloud Sync is the bridge. A small agent on that server copies everyone up to Entra on a schedule. The connection is healthy. It carries a scrambled form of each password, so staff have one password for both. Fix a person once, fixed everywhere.", audio: `${OUT}/clips/km/07-directory-1.mp3`,
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/CloudSync`, 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'corp.contosohealthlab.com', row: true }); await r.define('Cloud Sync', 'The bridge that copies on-site accounts into the cloud directory.'); await b.until(0.45); await r.ring({ text: 'Healthy', exact: true }, 'Healthy'); } },
  ] },
  { id: '08-joiner', kind: 'portal', beats: [
    { say: "Piece four, first-day doors. Here's Dana in Entra, the badge system. Nobody typed her in. She came from HR, through the badge list, across the bridge. Her job title and department came with her, and so did her start date, which matters next.", audio: `${OUT}/clips/km/08-joiner-0.mp3`,
      prep: async (r) => { await r.chip('Joiner & mover', 'Access follows HR'); await r.goto(userBlade(ids.dana), 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'Dana Okafor', exact: true, nth: 0 }); await b.until(0.22); await r.unring(); await r.click({ role: 'tab', name: 'Properties' }); await sleep(2500);
        await r.wheel(330, { x: 1100, y: 560 }); await sleep(1300);
        await r.ring({ text: 'On-premises sync enabled', exact: true }, 'Synced from AD').catch(() => {}); await b.until(0.58);
        await r.ring({ text: 'Registered Nurse', exact: true }, 'Job title from HR').catch(() => {}); await b.until(0.8);
        await r.ring({ text: 'Employee hire date', exact: true }, 'Hire date from HR').catch(() => {}); } },
    { say: "An access package is a bundle of doors for one job, with rules for who gets it and for how long. There are four. Nurse and ICU are handed out automatically from HR's job title. ICU Float needs a manager's yes and expires after a hundred and eighty days. Pharmacy is request-only. Dana is a nurse, so the nurse doors were added to her badge on their own: ServiceNow, the IT help desk, and AWS. No ticket.", audio: `${OUT}/clips/km/08-joiner-1.mp3`,
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement`, 12000); await r.settle(); },
      run: async (r, b) => { await r.define('Access package', 'A bundle of access for one job, with rules on who gets it and for how long.'); await b.until(0.28); await r.ring({ text: 'Nurse - Clinical Apps', row: true }, 'Automatic'); await b.until(0.38); await r.ring({ text: 'ICU - Critical Care Apps', row: true }, 'Automatic'); await b.until(0.5); await r.ring({ text: 'ICU - Float Access', row: true }, 'Request · approval · 180 days'); await b.until(0.63); await r.ring({ text: /Pharmacy - Controlled Substances/, row: true }, 'Request only'); await b.until(0.75); await r.ring({ text: 'Nurse - Clinical Apps', row: true }, 'Dana · added on her own'); } },
    { say: "Some doors never open together. Nurse and pharmacy are marked incompatible, so no one can hold both. That's separation of duties, and the system enforces it, not a manager's memory.", audio: `${OUT}/clips/km/08-joiner-2.mp3`,
      prep: async (r) => { await r.unring(); await r.click({ text: 'Nurse - Clinical Apps', exact: true }); await sleep(5000); await r.settle(200);
        await r.click({ text: /^Separation of duties$/i }); await sleep(3500); await r.click({ text: 'Incompatible With', exact: true }); await sleep(2500); },
      run: async (r, b) => { await b.until(0.3); await r.ring({ text: /Pharmacy - Controlled Substances/, row: true }, 'Never together').catch(() => {}); await b.until(0.55); await r.define('Separation of duties', 'Two kinds of access that must never sit on one person.'); } },
    { say: "Lifecycle workflows are checklists. The first-day one runs on its own on a nurse's start date. The last-day one, for cutting someone off at once, is started on demand.", audio: `${OUT}/clips/km/08-joiner-3.mp3`,
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_LifecycleManagement/CommonMenuBlade/~/workflows`, 12000); await r.settle(); },
      run: async (r, b) => { await r.define('Lifecycle workflow', 'A checklist that runs on an HR date: first day, or last.'); await r.ring({ text: /Contoso - Joiner/, row: true }, 'Day 1'); await b.until(0.55); await r.ring({ text: /Contoso - Leaver/, row: true }, 'Real time'); } },
  ] },
  { id: '09-signin', kind: 'portal', beats: [
    { say: "Piece five, the guard at every door. This is Conditional Access: each policy is one rule for who it covers and what it demands. There are eleven. Everyone proves it's them with a second step. Admins need the phishing-proof kind, like a security key. Old sign-in methods that can't do that are blocked, and anything that looks high-risk is turned away.", audio: `${OUT}/clips/km/09-signin-0.mp3`,
      prep: async (r) => { await r.chip('Sign-in rules', 'No lockout'); await r.goto(`${ENTRA}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`, 12000); await r.settle();
        for (const f of r.page.frames()) await f.evaluate(() => { for (const b of document.querySelectorAll('button[aria-label*="lose" i], button[title*="lose" i]')) { const t = (b.closest('div') || {}).innerText || ''; if (/policy plans|Migrate to Conditional Access/i.test(b.parentElement?.parentElement?.innerText || t)) b.click(); } }).catch(() => {});
        await sleep(800); await r.wheel(420, { x: 1000, y: 600 }); await sleep(1000); },
      run: async (r, b) => { await r.define('Conditional Access', 'Rules checked at every sign-in: who you are, what you must prove.'); await b.until(0.28); await r.ring({ text: /^CA001 - / , row: true }, 'Everyone: second factor'); await b.until(0.45); await r.ring({ text: /^CA002 - /, row: true }, 'Admins: phishing-resistant'); await b.until(0.68); await r.ring({ text: /^CA003 - /, row: true }, 'Old protocols blocked'); await b.until(0.85); await r.ring({ text: /^CA007 - /, row: true }, 'High risk: blocked'); } },
    { say: "Nine of the eleven are live. Each started by only watching and logging what it would have blocked, and went live through its own reviewed change once it was clear no nurse would be locked out. The two strictest, for admins, are in that watching stage. And two emergency badges, kept locked away, are exempt, so there's always a way back in.", audio: `${OUT}/clips/km/09-signin-1.mp3`,
      run: async (r, b) => { await r.ring({ text: 'State', exact: true }, 'Report-only').catch(() => {}); await r.define('Report-only', 'The rule logs what it would block, without blocking anything.'); await b.until(0.62); await r.unring(); await r.define('Break-glass account', 'An emergency login kept locked away, excluded from every rule.'); } },
  ] },
  { id: '10-pim', kind: 'portal', beats: [
    { say: "Admin power works like a master key on loan. The tool is PIM, Privileged Identity Management. You're allowed to borrow the key, but you don't carry it. The most powerful keys, the ones that could change security itself, need a ticket, a second proof and someone else's approval, for four hours at most. Two exceptions: the emergency badges, kept locked away, and the account that built the lab.", audio: `${OUT}/clips/km/10-pim-0.mp3`,
      prep: async (r) => { await r.chip('Privileged access', 'No standing privilege'); await r.goto(`${ENTRA}Microsoft_Azure_PIMCommon/CommonMenuBlade/~/aadgroup`, 12000); await r.settle(); },
      run: async (r, b) => { await r.define('PIM', 'Admin power you switch on for a short window. It switches itself off.'); await r.type({ css: 'input[placeholder*="Search by group"]' }, 'PIM-Tier', 90); await sleep(3000); await r.ring({ text: 'PIM-Tier0-CA-Admins', row: true }, 'Tier 0 · approval + ticket · 4h'); } },
    { say: "The help desk gets a smaller key. Raj Patel has a separate admin badge that can borrow help-desk power, but only over staff accounts that came from HR. He can't touch an admin account or an executive's.", audio: `${OUT}/clips/km/10-pim-1.mp3`,
      prep: async (r) => { await r.unring(); await r.click({ css: 'input[placeholder*="Search by group"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('PIM-Tier1', { delay: 30 }); await sleep(2500);
        await r.click({ text: 'PIM-Tier1-Helpdesk', exact: true }); await sleep(5000); await r.settle(200);
        await r.click({ text: 'Assignments', exact: true }); await sleep(4000); await r.click({ text: 'Eligible assignments', exact: true }); await sleep(3000); },
      run: async (r, b) => { await b.until(0.25); await r.ring({ text: /adm-raj\.patel/, nth: 0, row: true }, 'Eligible · not active').catch(() => {}); await b.until(0.6); await r.define('Eligible vs active', 'Eligible: may switch it on. Active: it is on, with an end time.'); } },
  ] },
  { id: '11-pim-live', kind: 'fresh', beats: [
    { say: "Piece six, the master key, live. Raj signs in to his admin badge with a one-time pass that works exactly once, so there's no password to steal.", audio: `${OUT}/clips/km/11-pim-live-0.mp3`,
      prep: async (r) => { await r.chip('Privileged access', 'Live activation');
        // One-time pass, held only in this process's memory.
        r.secret = execFileSync('pwsh', ['-NoProfile', '-File', path.join(path.dirname(new URL(import.meta.url).pathname), 'issue-tap.ps1'), '-Upn', ids.rajUpn, '-TenantId', ids.tenantId], { encoding: 'utf8' }).trim();
        if (!/^\S{8,}$/.test(r.secret)) throw new Error('TAP issue failed');
        await r.goto(`${ENTRA}Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup`, 8000); },
      run: async (r) => { await r.define('Temporary Access Pass', 'A one-time code that signs you in once, instead of a password.'); await r.type({ css: 'input[name=loginfmt]' }, ids.rajUpn, 55); await r.click({ css: 'input[type=submit]' }); await sleep(4500);
        const box = await r.find({ css: 'input[name=accesspass], input#accesspass, input[type=password]' }); await r.click({ css: 'input[name=accesspass], input#accesspass, input[type=password]' });
        await r.page.keyboard.type(r.secret, { delay: 60 }); r.secret = null; await sleep(400); await r.click({ css: 'input[type=submit]' }); } , minHold: 0 },
    { say: "Under My roles, he holds no admin power at all. Just one key he's allowed to borrow: Helpdesk. He clicks Activate.", audio: `${OUT}/clips/km/11-pim-live-1.mp3`,
      prep: async (r) => { for (let i = 0; i < 10; i++) { const t = await r.page.locator('body').innerText().catch(() => ''); if (/Stay signed in/i.test(t)) { await r.page.locator('#idBtn_Back, input[value="No"]').first().click().catch(() => {}); }
          if (/Skip for now|Ask later|Not now/i.test(t)) await r.page.getByText(/Skip for now|Ask later|Not now/i).first().click().catch(() => {});
          if (/ActivationMenuBlade/.test(r.page.url()) && /Eligible assignments|PIM-Tier1-Helpdesk/i.test(t + (await Promise.all(r.page.frames().map((f) => f.locator('body').innerText().catch(() => '')))).join(' '))) break; await sleep(4000); }
        await sleep(5000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'PIM-Tier1-Helpdesk', row: true }, 'Eligible'); await b.until(0.75); await r.unring();
        await r.click((f) => f.getByRole('button', { name: 'Activate', exact: true }).first()); } },
    { say: "He asks for one hour, not the eight allowed, and types a reason, which goes in the audit log. This level needs no approver, so it takes seconds.", audio: `${OUT}/clips/km/11-pim-live-2.mp3`,
      prep: async (r) => { await sleep(4000); await r.settle(200); },
      run: async (r, b) => { await r.click({ css: 'input[aria-label*="slider value"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('1', { delay: 120 }); await r.page.keyboard.press('Tab');
        await b.until(0.3); await r.type({ css: 'textarea' }, 'INC-4821: unlock a nurse on 4 West before shift change', 40); await b.until(0.8);
        await r.click((f) => f.getByRole('button', { name: 'Activate', exact: true }).last()); } },
    { say: "He's active now, with an end time. When it passes, the key simply goes back. Nobody has to remember to take it away.", audio: `${OUT}/clips/km/11-pim-live-3.mp3`,
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
    { say: "Piece seven, the cameras. Microsoft Sentinel records every badge swipe and every settings change, and alarm rules read that record looking for trouble. Defender is the desk where alarms get worked. Twenty-two rules were written for this hospital, and seventeen run live here: things like an emergency badge being used, a sign-in from a blocked country, or a flood of wrong passwords.", audio: `${OUT}/clips/km/12-detect-0.mp3`,
      prep: async (r) => { await r.chip('Detect & respond', 'Contained in minutes'); await r.goto(`https://security.microsoft.com/sentinel/analytics?tid=${ids.tenantId}`, 16000); await r.settle(); },
      run: async (r, b) => { await r.define('Sentinel', 'The alarm system: rules that read the logs and raise incidents.'); await b.until(0.3); await r.ring({ text: 'Active rules', exact: true }, 'Live alarm rules').catch(() => {}); await b.until(0.6); await r.unring();
        await r.type({ css: 'input[placeholder*="Search by ID"]' }, 'Contoso -', 70); await sleep(3500); await r.ring({ text: /^Contoso - /, nth: 0, row: true }, 'Everyday watches').catch(() => {}); } },
    { say: "Most watch for what an attacker does once inside: admin power handed out without the loan system, someone slipped into a powerful group, a secret back door added to an app, a door rule changed outside the blueprints. Each is a known move: get permanent power, or plant a way back in.", audio: `${OUT}/clips/km/12-detect-1.mp3`,
      prep: async (r) => { await r.unring(); await r.click({ css: 'input[placeholder*="Search by ID"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('ITDR', { delay: 40 }); await sleep(3500); },
      run: async (r, b) => { await r.define('ITDR', "Identity threat detection: spotting an attacker's moves inside the directory."); await b.until(0.22);
        for (let i = 0; i < 6; i++) { await r.ring({ text: /^Contoso ITDR/, nth: i, row: true }).catch(() => {}); await b.until(0.22 + 0.12 * (i + 1)); } } },
    { say: "And these alarms are real. While I built the lab, two legitimate setup steps tripped them, and the cameras flagged both anyway. This demo set off two more: the one-time pass issued to Raj, and his key loan. The rules don't care who you are.", audio: `${OUT}/clips/km/12-detect-2.mp3`,
      prep: async (r) => { await r.unring(); await r.goto(`https://security.microsoft.com/incidents?tid=${ids.tenantId}`, 16000); await r.settle();
        // Defender sometimes adds a default "Priority score" filter that hides low-score incidents: clear it.
        for (const f of r.page.frames()) { const x = f.getByRole('button', { name: /^Clear priority/i }).first(); if (await x.isVisible().catch(() => false)) await x.click().catch(() => {}); }
        await sleep(4000); await r.settle(); },
      run: async (r, b) => { await r.define('Incident', 'One case: its alerts, the accounts involved, and the raw log lines.'); await r.ring({ text: /Directory role assigned outside PIM/, nth: 0, row: true }, 'High'); await b.until(0.4); await r.ring({ text: /Permission granted to an applicati/, nth: 0, row: true }, 'App permissions'); await b.until(0.62); await r.ring({ text: /Authentication method changed/, nth: 0, row: true }, 'The pass issued to Raj').catch(() => {}); await b.until(0.8); await r.ring({ text: /PIM activation/, nth: 0, row: true }, "Raj's activation").catch(() => {}); } },
    { say: "Each alarm opens with what fired, who was involved, and the raw evidence, ready for an analyst. A break-glass sign-in alarms within minutes, every time, each with its own Teams card and ServiceNow ticket.", audio: `${OUT}/clips/km/12-detect-3.mp3`,
      prep: async (r) => { await r.unring(); },
      run: async (r) => { await r.click({ text: /Directory role assigned outside PIM/, nth: 0 }); await sleep(6000); await r.settle(200); } },
  ] },
  { id: '12b-splunk', kind: 'local', beats: [
    { say: "One more thing on the cameras. These rules aren't tied to Microsoft. All twenty-two were rewritten for Splunk, a second camera system, and replayed against test footage. Every one fired. So the hospital keeps its detections even if it switches brands.", audio: `${OUT}/clips/km/12b-splunk-0.mp3`,
      prep: async (r) => { await r.page.goto(SHOT); await r.ov('hideCursor', true); await r.page.evaluate((src) => window.shot(src), BIMG('splunk')); await sleep(600); },
      run: async (r, b) => { await b.until(0.9); } },
  ] },
  { id: '13-leaver', kind: 'portal', beats: [
    { say: "Piece nine, leaving. The same path runs in reverse, and this time it was timed. HR flipped Dana to leaver. Seven seconds later her badge was off in the badge list. Under three minutes later, off in the cloud. And at nine minutes, AWS had switched her off too. Nobody filed a ticket.", audio: `${OUT}/clips/km/13-leaver-0.mp3`,
      prep: async (r) => { await r.chip('Leaver', 'No way back in, timed'); await r.goto(userBlade(ids.priya), 12000); await r.settle(); },
      run: async (r, b) => { await r.define('Leaver', 'HR marks someone gone; the account is disabled everywhere, automatically.'); await r.ring({ text: 'Priya Nair', exact: true, nth: 0 }); await b.until(0.55); await r.ring({ text: /^\W*Disabled$/, nth: 0 }, 'Disabled by HR'); } },
    { say: "Priya is the other case. HR sent her already marked as gone, so her badge was created switched off, with no doors at all. A leaver who never gets a working day one.", audio: `${OUT}/clips/km/13-leaver-1.mp3`,
      run: async (r) => { await r.ring({ text: 'Group memberships', exact: true }); } },
  ] },
  { id: '14-worm', kind: 'portal', beats: [
    { say: "Proof goes into a logbook nobody can edit. The term is WORM, write once, read many: once a page is in, it can't be deleted or changed. Every capture and every check lands here.", audio: `${OUT}/clips/km/14-worm-0.mp3`,
      prep: async (r) => { await r.chip('Proof', 'Proof on demand'); await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.stId}/containersList`, 14000); await r.settle();
        await r.click({ text: 'evidence', exact: true }); await sleep(6000); await r.settle(); },
      run: async (r, b) => { await r.define('WORM store', 'Write once, read many: evidence nobody can delete or change.'); await b.until(0.3); await r.ring({ text: 'captures', exact: true, row: true }, 'Hashed evidence'); } },
    { say: "It keeps everything for six years, the HIPAA record window. Anyone writing evidence can add pages, never remove them, and a rewrite only adds a new version. In the lab the lock stays in its trial setting; production locks it for good.", audio: `${OUT}/clips/km/14-worm-1.mp3`,
      prep: async (r) => { await r.unring(); await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.stId}/dataProtection`, 12000); await r.settle();
        await r.reveal({ text: /version-level immutability/i, nth: 0 }); await sleep(800); },
      run: async (r, b) => { await b.until(0.15); await r.ring({ text: /version-level immutability/i, nth: 0 }, '6 years · WORM'); await b.until(0.6); await r.ring({ text: /Enable versioning for blobs/i, nth: 0 }, 'Overwrite = new version').catch(() => {}); } },
  ] },
  { id: '15-evidence', kind: 'local', beats: [
    { say: "Piece ten, the logbook. Every step leaves a numbered row: what happened, when, a fingerprint of the file, and where it's stored. Here's the row that closes Dana's story: off on-site in seven seconds, out of the cloud in under three minutes, switched off in AWS in nine. Every number comes from a real timestamp.", audio: `${OUT}/clips/km/15-evidence-0.mp3`,
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => { document.getElementById('scr').style.fontSize = '18px'; }); },
      run: async (r, b) => { await cmd(r, 'grep ^E lab/evidence/capture-log.csv | cut -c1-140');
        await out(r, T('elog.txt'), 8); await r.define('Hash', 'A fingerprint of a file. Change one byte and it changes.'); await b.until(0.55); await mark(r, '^E52|^E06|^E03'); } },
  ] },
  { id: '17-close', kind: 'local', beats: [
    { say: "That's Contoso Health. One badge per person, made from HR on day one, opening the right doors in every building, checked at each one, watched by two camera systems, and locked out of every building within nine minutes of leaving, with a logbook to prove it. More than a hundred reviewed changes. The code is available on request. Thanks for watching.", audio: `${OUT}/clips/km/17-close-0.mp3`,
      prep: card({ kick: 'Contoso Health identity lab', title: 'Access follows HR.<br>Admin power is <em>temporary</em>.<br>Every change is proven.', sub: 'Glossary: lab/docs/glossary.md', chips: [] }) },
  ] },
  { id: '20-tf-pipeline', kind: 'local', beats: [
    { say: "Nothing in this lab is clicked together in a portal. It is all written as code, in Terraform, like this. This file defines the two robot identities that run the pipeline, and notice there are no passwords anywhere. GitHub proves who they are with a short-lived token, and Microsoft only trusts it from the exact branch and environment named here. One identity can read and propose changes from a pull request. The other can make them, and only from the protected production path.",
      audio: `${OUT}/clips/wk-20-0.mp3`,
      prep: async (r) => { await r.page.goto(CODE); await r.ov('hideCursor', true); const src = fs.readFileSync(path.join(REPO, 'lab/terraform/modules/pipeline-identity/main.tf'), 'utf8').split('\n').slice(0, 33).join('\n'); await r.page.evaluate(({ f, c }) => window.code({ file: f, code: c }), { f: 'terraform/modules/pipeline-identity/main.tf', c: src }); await sleep(700); },
      run: async (r, b) => { await b.until(0.95); } },
  ] },
  { id: '21-tf-pim', kind: 'local', beats: [
    { say: "And here is privileged access, written the same way. This is a tiered admin model, not a single all-powerful account. Tier zero is the control plane, the roles that can change security itself, and activating one needs approval, a ticket, and multi-factor, for four hours at most. Tier one is the service desk, time-boxed to a shift. Change any of it, and the change is a reviewed pull request with a history, not a setting someone quietly flipped.",
      audio: `${OUT}/clips/wk-21-0.mp3`,
      prep: async (r) => { await r.page.goto(CODE); await r.ov('hideCursor', true); const src = fs.readFileSync(path.join(REPO, 'lab/terraform/modules/pim/tiers.tf'), 'utf8').split('\n').slice(0, 31).join('\n'); await r.page.evaluate(({ f, c }) => window.code({ file: f, code: c }), { f: 'terraform/modules/pim/tiers.tf', c: src }); await sleep(700); },
      run: async (r, b) => { await b.until(0.95); } },
  ] },
  { id: '22-splunk-search', kind: 'local', beats: [
    { say: "Piece eight, a second camera system. This is Splunk, the one many hospitals already own, running on my own machine, not Microsoft's cloud. The same kinds of events flow in, nearly a thousand of them: failed sign-ins, vault check-outs, password reads. This is test footage, not a live feed.", audio: `${OUT}/clips/km/22-splunk-search-0.mp3`,
      prep: async (r) => { await r.page.goto(SHOT); await r.ov('hideCursor', true); await r.page.evaluate((src) => window.shot(src), BIMG('splunk')); await sleep(600); },
      run: async (r, b) => { await b.until(0.95); } },
  ] },
  { id: '23-splunk-rules', kind: 'local', beats: [
    { say: "And here are all twenty-two alarm rules, rewritten in Splunk's own language: emergency-badge sign-ins, attacks on service passwords, admin power granted outside the loan system, and forbidden pairs of doors. I replayed the test attacks, and all twenty-two fired. The logic is mine, and it moves with the hospital.", audio: `${OUT}/clips/km/23-splunk-rules-0.mp3`,
      prep: async (r) => { await r.page.goto(SHOT); await r.ov('hideCursor', true); await r.page.evaluate((src) => window.shot(src), BIMG('splunk-rules')); await sleep(600); },
      run: async (r, b) => { await b.until(0.95); } },
  ] },
  ];
}
