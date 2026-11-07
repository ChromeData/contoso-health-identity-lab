#!/usr/bin/env node
// =============================================================================
// hr-clicks.mjs - a rehearsal driver: HR's own clicks in OrangeHRM, done by a
// headless browser, with a screenshot of each screen and the UTC time of
// the click that finishes each task.
// -----------------------------------------------------------------------------
// It clicks only what a person in HR clicks (README.md, "What HR clicks").
// It never touches the database or an API. Use it to rehearse, to capture
// evidence, or to reset a take; on camera, HR clicks by hand.
//
//   node hr-clicks.mjs hire  --id 100493 --first Test --last Hris \
//        --job "Registered Nurse" --unit Nursing --joined 2026-11-07 --supervisor "Grace Mwangi"
//   node hr-clicks.mjs move  --id 100493 --job "Registered Nurse" --unit ICU
//   node hr-clicks.mjs leave --id 100493 --date 2026-11-07 [--reason Resigned]
//   node hr-clicks.mjs purge --id 100493    (Maintenance > Purge Records: the
//                                            retake reset; past employees only)
//   --shots DIR   where screenshots go (default ./shots)
//
// Signs in as OrangeHRM's Admin. The password is read from the Keychain
// (contoso-hris-admin) into memory; it is never printed or passed in argv.
// Playwright comes from lab/setup/signup-assist (already installed there).
// =============================================================================
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// PLAYWRIGHT_FROM: another checkout's signup-assist folder (a git worktree
// has no node_modules of its own).
const { chromium } = createRequire(join(process.env.PLAYWRIGHT_FROM || join(here, '..', '..', 'setup', 'signup-assist'), 'package.json'))('playwright');
const [cmd, ...rest] = process.argv.slice(2);
const opt = (n, d) => { const i = rest.indexOf(`--${n}`); return i >= 0 ? rest[i + 1] : d; };
const BASE = opt('url', 'http://127.0.0.1:8585/web/index.php');
const shots = opt('shots', join(process.cwd(), 'shots'));
mkdirSync(shots, { recursive: true });
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');
const report = {};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.setDefaultTimeout(60000);
let n = 0;
const shot = async (name) => { n += 1; const f = join(shots, `${cmd}-${String(n).padStart(2, '0')}-${name}.png`); await page.screenshot({ path: f }); return f; };
const group = (label) => page.locator('.oxd-input-group').filter({ has: page.locator('label', { hasText: new RegExp(`^\\s*${label}\\s*$`) }) });
async function choose(label, text) {
  await group(label).locator('.oxd-select-text').click();
  await page.locator('.oxd-select-option').filter({ hasText: new RegExp(`^\\s*${text}\\s*$`) }).first().click();
}
async function typeDate(value, scope = page) {
  // OrangeHRM's date boxes show the format (yyyy-mm-dd) as their placeholder.
  const input = scope.locator('input[placeholder="yyyy-mm-dd"]').first();
  await input.fill(value);
  // Close the date picker by clicking a heading (Tab would open the next list).
  await scope.locator('h6, .oxd-text--h6, p.oxd-text--card-title').first().click();
}
const saved = () => page.locator('.oxd-toast--success').first().waitFor();

async function signIn() {
  const pw = execFileSync('security', ['find-generic-password', '-s', 'contoso-hris-admin', '-w'], { encoding: 'utf8' }).replace(/\n$/, '');
  await page.goto(`${BASE}/auth/login`);
  await page.fill('input[name=username]', 'Admin');
  await page.fill('input[name=password]', pw);
  await page.click('button[type=submit]');
  await page.waitForURL(/dashboard/);
}

async function openEmployee(id) {
  await page.goto(`${BASE}/pim/viewEmployeeList`);
  await group('Employee Id').locator('input').fill(id);
  await group('Include').locator('.oxd-select-text').click();
  await page.locator('.oxd-select-option').filter({ hasText: 'Current and Past Employees' }).click();
  await page.getByRole('button', { name: 'Search' }).click();
  const row = page.locator('.oxd-table-card').filter({ hasText: id }).first();
  await row.waitFor();
  await row.click();
  await page.waitForURL(/viewPersonalDetails\/empNumber\/(\d+)/);
  return page.url().match(/empNumber\/(\d+)/)[1];
}

async function hire() {
  await page.goto(`${BASE}/pim/viewEmployeeList`);
  await page.locator('.oxd-table-card').first().waitFor();
  await shot('employee-list');
  await page.getByRole('button', { name: 'Add' }).click();
  await page.waitForURL(/addEmployee/);
  await page.fill('input[name=firstName]', opt('first'));
  await page.fill('input[name=lastName]', opt('last'));
  await group('Employee Id').locator('input').fill(opt('id'));
  await shot('add-employee');
  report.addEmployeeSavedAt = now();
  await page.getByRole('button', { name: 'Save' }).click();
  await page.waitForURL(/viewPersonalDetails\/empNumber\/(\d+)/);
  const emp = page.url().match(/empNumber\/(\d+)/)[1];
  await page.goto(`${BASE}/pim/viewJobDetails/empNumber/${emp}`);
  await group('Job Title').waitFor();
  await page.waitForTimeout(1500);
  await typeDate(opt('joined'));
  await choose('Job Title', opt('job'));
  await choose('Sub Unit', opt('unit'));
  await choose('Employment Status', opt('status', 'Full-Time Permanent'));
  await shot('job');
  report.jobSavedAt = now();
  await page.locator('form').first().getByRole('button', { name: 'Save' }).click();
  await saved();
  await page.goto(`${BASE}/pim/viewReportToDetails/empNumber/${emp}`);
  await page.getByText('Assigned Supervisors').waitFor();
  await page.locator('h6', { hasText: 'Assigned Supervisors' }).locator('xpath=..').getByRole('button', { name: 'Add' }).click();
  const sup = opt('supervisor');
  await page.getByPlaceholder('Type for hints...').fill(sup.split(' ')[0]);
  await page.locator('.oxd-autocomplete-option').filter({ hasText: sup }).first().click();
  await choose('Reporting Method', 'Direct');
  await shot('report-to');
  report.hrClickAt = now(); // the click that finishes the hire record
  await page.getByRole('button', { name: 'Save' }).click();
  await saved();
  await shot('report-to-saved');
  report.empNumber = emp;
}

async function move() {
  const emp = await openEmployee(opt('id'));
  await page.goto(`${BASE}/pim/viewJobDetails/empNumber/${emp}`);
  await group('Job Title').waitFor();
  await page.waitForTimeout(1500);
  if (opt('job')) await choose('Job Title', opt('job'));
  if (opt('unit')) await choose('Sub Unit', opt('unit'));
  await shot('job-change');
  report.hrClickAt = now();
  await page.locator('form').first().getByRole('button', { name: 'Save' }).click();
  await saved();
  await shot('job-change-saved');
}

async function leave() {
  const emp = await openEmployee(opt('id'));
  await page.goto(`${BASE}/pim/viewJobDetails/empNumber/${emp}`);
  await page.getByRole('button', { name: 'Terminate Employment' }).click();
  const dlg = page.locator('.oxd-dialog-sheet');
  await dlg.waitFor();
  await typeDate(opt('date'), dlg);
  await dlg.locator('.oxd-select-text').click();
  await page.locator('.oxd-select-option').filter({ hasText: new RegExp(`^\\s*${opt('reason', 'Resigned')}\\s*$`) }).click();
  await shot('terminate');
  report.hrClickAt = now();
  await dlg.getByRole('button', { name: 'Save' }).click();
  await saved();
  await page.waitForTimeout(1000);
  await shot('terminated');
}

async function purge() {
  await page.goto(`${BASE}/maintenance/purgeEmployee`);
  // OrangeHRM asks for the admin password again before Maintenance.
  const gate = page.locator('input[type=password]');
  const list = page.getByPlaceholder('Type for hints...');
  await Promise.race([gate.waitFor(), list.waitFor()]);
  if (await gate.count()) {
    const pw = execFileSync('security', ['find-generic-password', '-s', 'contoso-hris-admin', '-w'], { encoding: 'utf8' }).replace(/\n$/, '');
    await gate.fill(pw);
    await page.getByRole('button', { name: 'Confirm' }).click();
  }
  const name = opt('name');
  await page.getByPlaceholder('Type for hints...').fill(name.split(' ')[0]);
  await page.locator('.oxd-autocomplete-option').filter({ hasText: name }).first().click();
  await page.getByRole('button', { name: 'Search' }).click();
  await page.getByRole('button', { name: 'Purge' }).click();
  await page.locator('.oxd-dialog-sheet').getByRole('button', { name: /Yes, Purge/ }).click();
  await saved();
  report.purgedAt = now();
}

try {
  await signIn();
  const fn = { hire, move, leave, purge }[cmd];
  if (!fn) throw new Error('usage: hr-clicks.mjs hire|move|leave|purge ...');
  await fn();
  console.log(JSON.stringify({ cmd, id: opt('id'), ...report, shots }));
} catch (e) {
  await shot('error').catch(() => {});
  console.error(`hr-clicks ${cmd} failed: ${e.message.split('\n')[0]}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
