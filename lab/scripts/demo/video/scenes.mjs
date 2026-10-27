// Scenes for the lab demo video: narration beats + what the camera does.
// Narration states only what the tenant shows (checked 2026-10-27).
import fs from 'node:fs';
import path from 'node:path';
import { OUT, REPO, sleep } from './rec.mjs';
import { execFileSync } from 'node:child_process';

const PAGES = path.join(path.dirname(new URL(import.meta.url).pathname), 'pages');
const TERM = 'file://' + path.join(PAGES, 'term.html');
const CARD = 'file://' + path.join(PAGES, 'card.html');
const MAP = 'file://' + path.join(OUT, 'map-video.html');
const T = (f) => fs.readFileSync(path.join(OUT, 'term', f), 'utf8');
const ENTRA = 'https://entra.microsoft.com/#view/';

const card = (c) => async (r) => { await r.page.goto(CARD); await r.ov('hideCursor', true); await r.page.evaluate((c) => window.card(c), c); };
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
  // 1 ------------------------------------------------------------------------
  { id: '01-title', kind: 'local', beats: [
    { say: "This is the Contoso Health identity lab: a fictional, five-thousand-person hospital, running in a real Microsoft Entra tenant, and built entirely from code. Everything you're about to see is live.",
      prep: card({ kick: 'Live lab tour', title: 'Contoso Health,<br>from hire to <em>proof</em>', sub: 'An identity platform on Microsoft Entra ID, built from code and running in a real tenant.',
        chips: ['HR-driven joiners &amp; leavers', 'Hybrid AD + Cloud Sync', 'Conditional Access', 'PIM tiers', 'Sentinel ITDR', 'WORM evidence'] }) },
  ] },
  // 2 ------------------------------------------------------------------------
  { id: '02-map', kind: 'local', beats: [
    { say: "Here's the whole platform on one map. Left to right is a person's path through the hospital: hired by HR, given an account, handed the access their job needs, checked at every sign-in, watched for threats, and removed the day they leave. At the far end is the proof an auditor asks for.",
      prep: async (r) => { await r.page.goto(MAP); await r.ov('hideCursor', true); await sleep(2500); await mapGo(r, 'overview'); await sleep(1200); } },
    { say: "Above it all runs delivery. Every change is a pull request, a human approves it, and the pipeline applies it without a stored password.",
      run: async (r) => { await mapGo(r, 'delivery'); } },
    { say: "The first rule: access follows HR. If HR says you work here, you get in. If HR says you've left, you're out.",
      run: async (r) => { await mapGo(r, 'station:source'); } },
    { say: "Second: nobody keeps admin power when they're not using it.",
      run: async (r) => { await mapGo(r, 'station:privileged'); } },
    { say: "And every control can be proven the moment an auditor asks. Blue badges mark what's running in the tenant today. Let's walk it, start to finish.",
      run: async (r) => { await mapGo(r, 'station:proof'); } },
  ] },
  // 3 ------------------------------------------------------------------------
  { id: '03-delivery', kind: 'local', beats: [
    { say: "Nothing in this tenant was clicked into place. Twenty-five merged pull requests built it: report-only Conditional Access on day one, privileged access tiers on day two, governance on day three, then Sentinel, and a domain controller.",
      prep: termOpen,
      run: async (r, b) => { await cmd(r, 'gh pr list --state merged --limit 40'); await out(r, T('prs.txt'), 22); await b.until(0.55); await mark(r, 'Day 1|Day 2|Day 3|enable_sentinel|enable_dc'); } },
    { say: "Every pull request runs format, validate, a plan, and thirteen mocked tests. Some are guard rails. This one refuses to make PIM require the phishing-resistant authentication context until the Conditional Access policy behind it is actually enforced, so the requirement can never be hollow.",
      run: async (r, b) => { await clear(r); await cmd(r, 'terraform test -var-file=lab.tfvars'); await out(r, T('tf-test.txt'), 9); await b.until(0.5); await mark(r, 'pim_auth_context_refused_while'); } },
    { say: "Apply waits at a human gate. The repo is private on a free plan, so the gate is an issue: the owner comments approve, and only then does the runner sign in to Azure, with a short-lived OIDC token. There is no client secret anywhere in the pipeline.",
      run: async (r, b) => { await clear(r); await cmd(r, 'gh run view 40549067405');
        await out(r, T('apply-run-view.txt').split('\n').filter((l) => !/ubuntu-latest|^approval \(human gate\): \.github#1|^terraform apply \(prod, reviewer-gated\): \.github#1/.test(l)).join('\n').replace(/\n{3,}/g, '\n\n'), 25);
        await mark(r, 'approval \\(human gate\\)'); await b.until(0.45); await cmd(r, "gh issue view 34 --comments | grep -E '^(author|approve|Approved)'");
        await out(r, T('issue34.txt'), 12); await unmark(r); await mark(r, '^approve$|Approved by'); } },
    { say: "And that trust is narrow. When a throwaway branch tried to sign in as the apply identity, Entra refused it: the federated credential only trusts the production environment.",
      run: async (r) => { await clear(r); await cmd(r, 'grep ^E03 lab/evidence/capture-log.csv | fold -s -w 100');
        await out(r, T('e03.txt'), 10); await mark(r, 'AADSTS700213|environment:prod'); } },
  ] },
  // 4 ------------------------------------------------------------------------
  { id: '04-hr-feed', kind: 'local', beats: [
    { say: "Meet Dana Okafor, a new registered nurse. HR is the source of truth, so her record goes to Entra's API-driven inbound provisioning as a SCIM bulk request: name, title, department, manager, and her hire date.",
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => { window.term.title('pwsh — lab/scripts/mock-hr'); document.getElementById('scr').style.fontSize = '18px'; }); },
      run: async (r, b) => { await cmd(r, './Invoke-InboundProvisioning.ps1 -CsvPath dana.csv -UpnDomain contosohealthlab.com -WhatIf');
        await out(r, T('hr-whatif.txt').split('\n').filter((l) => !/What if:|--- \[WhatIf\]|Content-Type|Dry run/.test(l)).join('\n'), 14);
        await b.until(0.5); await mark(r, '"title"|"department"|"hireDate"|"userName"'); } },
    { say: "Before anything is sent, a guard counts the changes. A push that would disable, or re-department, more than ten people stops cold, because a bad HR export looks exactly like a mass layoff. Here the limit is set to zero, to show it refusing.",
      run: async (r, b) => { await clear(r); await cmd(r, './Invoke-InboundProvisioning.ps1 -StatusFilter leaver -MaxChanges 0 -WhatIf');
        await out(r, T('hr-guard.txt').replace(/\/Users\/[^:]+\/lab/, 'lab'), 10); await b.until(0.35); await mark(r, 'Mass-change guard: this run|Nothing was sent'); } },
  ] },
  { id: '05-hr-app', kind: 'portal', beats: [
    { say: "In the tenant, the Contoso HR Inbound Provisioning app picks it up. Its provisioning logs show each record it processed, written straight into on-premises Active Directory.",
      prep: async (r) => { await r.chip('Source of truth', 'HR owns who works here');
        await r.goto(`${ENTRA}Microsoft_AAD_IAM/ManagedAppMenuBlade/~/ProvisioningManagement/appId/${ids.hrAppId}/objectId/${ids.hrSpId}`, 12000); await r.settle();
        await r.click({ text: 'Provisioning logs', exact: true }); await sleep(6000); await r.settle(); },
      run: async (r, b) => { await b.until(0.3);
        await r.type({ css: 'input[placeholder="Search Identity"]' }, '100492', 110); await r.page.keyboard.press('Enter'); await sleep(3500);
        await r.ring({ text: /Source ID 100492/, nth: 0, row: true }, 'Dana · HR → AD').catch(() => {}); } },
  ] },
  // 5 ------------------------------------------------------------------------
  { id: '06-ad', kind: 'local', beats: [
    { say: "This is a live query on DC01, the lab's domain controller, sent through Azure's managed run command, so no password ever touches a command line. Thirteen staff, each in their department's organizational unit.",
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => window.term.title('zsh — DC01 via managed run command')); },
      run: async (r, b) => { await cmd(r, 'lab/scripts/dc/run-on-dc.py ad-roster.ps1'); await out(r, T('ad-roster.txt').replace(/^run command .*$/m, 'run command lab-c21e072e: ad-roster.ps1 on vm-dc01'), 6); await b.until(0.7); await mark(r, 'dana.okafor'); } },
    { say: "And Priya Nair, who has left, is disabled and parked in the Disabled OU.",
      run: async (r) => { await unmark(r); await mark(r, 'priya.nair'); } },
  ] },
  { id: '07-directory', kind: 'portal', beats: [
    { say: "DC01 is a Windows Server 2022 virtual machine in Azure, deployed by the same pipeline, with an auto-shutdown schedule to keep the lab cheap.",
      prep: async (r) => { await r.chip('Directory', 'AD is the master, Entra is the hub');
        await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.vmId}/overview`, 14000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'vm-dc01', exact: true, nth: 0 }); await b.until(0.4); await r.ring({ text: /Windows Server 2022 Datacenter/, nth: 0 }, 'Domain controller'); } },
    { say: "Microsoft Entra Cloud Sync carries those accounts up to Entra ID. The configuration for corp dot contosohealthlab dot com is healthy. It syncs only the Workforce and Disabled OUs, with password hash sync.",
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_Connect_Provisioning/AADConnectMenuBlade/~/CloudSync`, 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'corp.contosohealthlab.com', row: true }); await b.until(0.45); await r.ring({ text: 'Healthy', exact: true }, 'Healthy'); } },
  ] },
  // 6 ------------------------------------------------------------------------
  { id: '08-joiner', kind: 'portal', beats: [
    { say: "Here's Dana in Entra ID. Nobody created her here by hand. She came from HR, through Active Directory, through Cloud Sync: Registered Nurse, Nursing, with her hire date carried all the way through.",
      prep: async (r) => { await r.chip('Joiner & mover', 'Access follows HR'); await r.goto(userBlade(ids.dana), 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'Dana Okafor', exact: true, nth: 0 }); await b.until(0.22); await r.unring(); await r.click({ role: 'tab', name: 'Properties' }); await sleep(2500);
        await r.wheel(330, { x: 1100, y: 560 }); await sleep(1300);
        await r.ring({ text: 'On-premises sync enabled', exact: true }, 'Synced from AD').catch(() => {}); await b.until(0.58);
        await r.ring({ text: 'Registered Nurse', exact: true }, 'Job title from HR').catch(() => {}); await b.until(0.8);
        await r.ring({ text: 'Employee hire date', exact: true }, 'Hire date from HR').catch(() => {}); } },
    { say: "Because she's in Nursing, an automatic assignment policy gave her the Nurse Clinical Apps package on her own. No ticket, no request. Four nurses, four assignments.",
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement`, 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'Nurse - Clinical Apps', row: true }, 'Automatic · 4 active'); } },
    { say: "Some doors never open together. The nurse package and the pharmacy controlled-substances package are marked incompatible, so nobody can hold both.",
      prep: async (r) => { await r.unring(); await r.click({ text: 'Nurse - Clinical Apps', exact: true }); await sleep(5000); await r.settle(200);
        await r.click({ text: /^Separation of duties$/i }); await sleep(3500); await r.click({ text: 'Incompatible With', exact: true }); await sleep(2500); },
      run: async (r, b) => { await b.until(0.3); await r.ring({ text: /Pharmacy - Controlled Substances/, row: true }, 'Never together').catch(() => {}); } },
    { say: "Lifecycle workflows hang off the same HR dates: a joiner workflow for nursing hires on day one, and a real-time leaver workflow for the day HR says someone has gone.",
      prep: async (r) => { await r.unring(); await r.goto(`${ENTRA}Microsoft_AAD_LifecycleManagement/CommonMenuBlade/~/workflows`, 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: /Contoso - Joiner/, row: true }, 'Day 1'); await b.until(0.55); await r.ring({ text: /Contoso - Leaver/, row: true }, 'Real time'); } },
  ] },
  // 7 ------------------------------------------------------------------------
  { id: '09-signin', kind: 'portal', beats: [
    { say: "Sign-in is governed by eleven Conditional Access policies: MFA for everyone, phishing-resistant MFA for admins, legacy authentication and device code flow blocked, and high-risk sign-ins stopped.",
      prep: async (r) => { await r.chip('Sign-in rules', 'No lockout'); await r.goto(`${ENTRA}Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies`, 12000); await r.settle();
        for (const f of r.page.frames()) await f.evaluate(() => { for (const b of document.querySelectorAll('button[aria-label*="lose" i], button[title*="lose" i]')) { const t = (b.closest('div') || {}).innerText || ''; if (/policy plans|Migrate to Conditional Access/i.test(b.parentElement?.parentElement?.innerText || t)) b.click(); } }).catch(() => {});
        await sleep(800); await r.wheel(420, { x: 1000, y: 600 }); await sleep(1000); },
      run: async (r, b) => { await r.ring({ text: /^CA001 - / , row: true }); await b.until(0.3); await r.ring({ text: /^CA002 - /, row: true }); await b.until(0.55); await r.ring({ text: /^CA003 - /, row: true }); await b.until(0.75); await r.ring({ text: /^CA007 - /, row: true }); } },
    { say: "Every one is in report-only mode for now, and that's deliberate. Each policy graduates to on through its own pull request, once its report shows it won't lock out a single clinician. And two break-glass accounts are excluded from all of them, so there's always a way back in.",
      run: async (r, b) => { await r.ring({ text: 'State', exact: true }, 'Report-only').catch(() => {}); await b.until(0.5); await r.unring(); } },
  ] },
  // 8 ------------------------------------------------------------------------
  { id: '10-pim', kind: 'portal', beats: [
    { say: "Admin power is tiered, and never permanent. Every admin role sits behind a Privileged Identity Management group. Tier zero, like Conditional Access or Security admin, needs a ticket number, MFA, and a second person's approval, for four hours at most.",
      prep: async (r) => { await r.chip('Privileged access', 'No standing privilege'); await r.goto(`${ENTRA}Microsoft_Azure_PIMCommon/CommonMenuBlade/~/aadgroup`, 12000); await r.settle(); },
      run: async (r, b) => { await r.type({ css: 'input[placeholder*="Search by group"]' }, 'PIM-Tier', 90); await sleep(3000); await r.ring({ text: 'PIM-Tier0-CA-Admins', row: true }, 'Tier 0 · approval + ticket · 4h'); } },
    { say: "Tier one is the service desk. Raj Patel's separate admin account is eligible for Helpdesk, but only over an administrative unit of HR-sourced workforce accounts. He can't touch another admin.",
      prep: async (r) => { await r.unring(); await r.click({ css: 'input[placeholder*="Search by group"]' }); await r.page.keyboard.press('Meta+A'); await r.page.keyboard.type('PIM-Tier1', { delay: 30 }); await sleep(2500);
        await r.click({ text: 'PIM-Tier1-Helpdesk', exact: true }); await sleep(5000); await r.settle(200);
        await r.click({ text: 'Assignments', exact: true }); await sleep(4000); await r.click({ text: 'Eligible assignments', exact: true }); await sleep(3000); },
      run: async (r, b) => { await b.until(0.25); await r.ring({ text: /adm-raj\.patel/, nth: 0, row: true }, 'Eligible · not active').catch(() => {}); } },
  ] },
  { id: '11-pim-live', kind: 'fresh', beats: [
    { say: "Now watch it live. Raj signs in to the admin center as his admin account, with a one-time Temporary Access Pass issued for this demo.",
      prep: async (r) => { await r.chip('Privileged access', 'Live activation');
        // One-time pass, held only in this process's memory.
        r.secret = execFileSync('pwsh', ['-NoProfile', '-File', path.join(path.dirname(new URL(import.meta.url).pathname), 'issue-tap.ps1'), '-Upn', ids.rajUpn, '-TenantId', ids.tenantId], { encoding: 'utf8' }).trim();
        if (!/^\S{8,}$/.test(r.secret)) throw new Error('TAP issue failed');
        await r.goto(`${ENTRA}Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup`, 8000); },
      run: async (r) => { await r.type({ css: 'input[name=loginfmt]' }, ids.rajUpn, 55); await r.click({ css: 'input[type=submit]' }); await sleep(4500);
        const box = await r.find({ css: 'input[name=accesspass], input#accesspass, input[type=password]' }); await r.click({ css: 'input[name=accesspass], input#accesspass, input[type=password]' });
        await r.page.keyboard.type(r.secret, { delay: 60 }); r.secret = null; await sleep(400); await r.click({ css: 'input[type=submit]' }); } , minHold: 0 },
    { say: "In PIM, under My roles, he holds no admin rights at all. Just one eligible group: Helpdesk. He clicks activate.",
      prep: async (r) => { for (let i = 0; i < 10; i++) { const t = await r.page.locator('body').innerText().catch(() => ''); if (/Stay signed in/i.test(t)) { await r.page.locator('#idBtn_Back, input[value="No"]').first().click().catch(() => {}); }
          if (/Skip for now|Ask later|Not now/i.test(t)) await r.page.getByText(/Skip for now|Ask later|Not now/i).first().click().catch(() => {});
          if (/ActivationMenuBlade/.test(r.page.url()) && /Eligible assignments|PIM-Tier1-Helpdesk/i.test(t + (await Promise.all(r.page.frames().map((f) => f.locator('body').innerText().catch(() => '')))).join(' '))) break; await sleep(4000); }
        await sleep(5000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'PIM-Tier1-Helpdesk', row: true }, 'Eligible'); await b.until(0.75); await r.unring();
        await r.click((f) => f.getByRole('button', { name: 'Activate', exact: true }).first()); } },
    { say: "He asks for one hour instead of the eight allowed, and gives a reason, which goes into the audit log. Tier one needs no approver, so this takes effect in seconds.",
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
  // 9 ------------------------------------------------------------------------
  { id: '12-detect', kind: 'portal', beats: [
    { say: "Detection runs in Microsoft Sentinel. Entra's sign-in and audit logs stream to Log Analytics, and eleven custom analytics rules watch for identity attacks: a role granted outside PIM, consent to an app, a credential added to an app, a Conditional Access policy changed.",
      prep: async (r) => { await r.chip('Detect & respond', 'Contained in minutes'); await r.goto(`https://security.microsoft.com/sentinel/analytics?tid=${ids.tenantId}`, 16000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'Active rules', exact: true }, '11 Contoso rules').catch(() => {}); await b.until(0.55); await r.ring({ text: /^Contoso ITDR/, nth: 0, row: true }).catch(() => {}); } },
    { say: "And these incidents are real. While the lab was being built, a directory role went to the Cloud Sync service account outside PIM, and admin consent was granted to the Graph command-line app. Sentinel caught both.",
      prep: async (r) => { await r.unring(); await r.goto(`https://security.microsoft.com/incidents?tid=${ids.tenantId}`, 16000); await r.settle();
        // Defender sometimes adds a default "Priority score" filter that hides low-score incidents: clear it.
        for (const f of r.page.frames()) { const x = f.getByRole('button', { name: /^Clear priority/i }).first(); if (await x.isVisible().catch(() => false)) await x.click().catch(() => {}); }
        await sleep(4000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: /Directory role assigned outside PIM/, nth: 0, row: true }, 'High'); await b.until(0.6); await r.ring({ text: /Permission granted to an applicati/, nth: 0, row: true }, 'App consent'); } },
    { say: "Each incident opens with its alerts, the accounts involved, and the raw audit evidence, ready for an analyst.",
      prep: async (r) => { await r.unring(); },
      run: async (r) => { await r.click({ text: /Directory role assigned outside PIM/, nth: 0 }); await sleep(6000); await r.settle(200); } },
  ] },
  // 10 -----------------------------------------------------------------------
  { id: '13-leaver', kind: 'portal', beats: [
    { say: "When HR says someone is gone, the same path runs in reverse. Priya Nair's HR record was marked as a leaver. The agent disabled her in Active Directory, moved her to the Disabled OU, and Cloud Sync carried it up.",
      prep: async (r) => { await r.chip('Leaver', 'No way back in, timed'); await r.goto(userBlade(ids.priya), 12000); await r.settle(); },
      run: async (r, b) => { await r.ring({ text: 'Priya Nair', exact: true, nth: 0 }); await b.until(0.55); await r.ring({ text: /^\W*Disabled$/, nth: 0 }, 'Disabled by HR'); } },
    { say: "Her Entra account is disabled, and she holds no groups, apps, or roles. Nobody filed a ticket for any of it.",
      run: async (r) => { await r.ring({ text: 'Group memberships', exact: true }); } },
  ] },
  // 11 -----------------------------------------------------------------------
  { id: '14-worm', kind: 'portal', beats: [
    { say: "Proof goes into a write-once evidence store: one storage container, where every capture, baseline and verification run lands.",
      prep: async (r) => { await r.chip('Proof', 'Proof on demand'); await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.stId}/containersList`, 14000); await r.settle();
        await r.click({ text: 'evidence', exact: true }); await sleep(6000); await r.settle(); },
      run: async (r, b) => { await b.until(0.3); await r.ring({ text: 'captures', exact: true, row: true }, 'Hashed evidence'); } },
    { say: "The account carries a six-year, version-level retention policy, the HIPAA documentation window. Writers can add evidence but can't delete it, and an overwrite only creates a new version.",
      prep: async (r) => { await r.unring(); await r.goto(`https://portal.azure.com/#@ContosoHealthLab.onmicrosoft.com/resource${ids.stId}/dataProtection`, 12000); await r.settle();
        await r.reveal({ text: /version-level immutability/i, nth: 0 }); await sleep(800); },
      run: async (r, b) => { await b.until(0.15); await r.ring({ text: /version-level immutability/i, nth: 0 }, '2190 days · WORM'); await b.until(0.6); await r.ring({ text: /Enable versioning for blobs/i, nth: 0 }, 'Overwrite = new version').catch(() => {}); } },
  ] },
  { id: '15-evidence', kind: 'local', beats: [
    { say: "Every step leaves a numbered evidence row: what happened, when, its hash, and where it's stored. The baseline assessment, the PIM settings read back, the WORM test, and even the test where the pipeline's own identity was refused.",
      prep: async (r) => { await termOpen(r); await r.page.evaluate(() => { document.getElementById('scr').style.fontSize = '18px'; }); },
      run: async (r, b) => { await cmd(r, 'grep ^E lab/evidence/capture-log.csv | cut -c1-140');
        await out(r, T('elog.txt'), 8); await b.until(0.55); await mark(r, '^E10|^E16a|^E06|^E03'); } },
  ] },
  // 12 -----------------------------------------------------------------------
  { id: '16-next', kind: 'local', beats: [
    { say: "What's left is wired, and waiting on one limit. A brand-new Entra tenant can only hold a few hundred directory objects for its first two days. When that lifts, single sign-on and provisioning to AWS, ServiceNow and Okta go live, along with the containment playbook and an Intune-managed device.",
      prep: card({ kick: "What's next", title: 'Wired, and waiting on<br>one <em>tenant limit</em>', sub: 'New tenants are capped at 600 directory objects for their first 48 hours. These go live when it lifts.',
        chips: ['SSO + SCIM: AWS · ServiceNow · Okta', 'Containment playbook', 'Intune device trust', 'CA graduations', 'Access reviews'] }) },
  ] },
  { id: '17-close', kind: 'local', beats: [
    { say: "Contoso Health. Access follows HR, admin power is temporary, and every change can be proven. Thanks for watching.",
      prep: card({ kick: 'Contoso Health identity lab', title: 'Access follows HR.<br>Admin power is <em>temporary</em>.<br>Every change is proven.', sub: '', chips: [] }) },
  ] },
  ];
}
