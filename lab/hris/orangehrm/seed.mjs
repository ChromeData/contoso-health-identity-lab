// =============================================================================
// seed.mjs - the go-live data load: the Contoso roster into OrangeHRM.
// -----------------------------------------------------------------------------
// A hospital that moves to a new HRIS loads its current workers once. This
// does that for the lab: it reads lab/scripts/mock-hr/hr_feed.csv (the
// roster Entra already holds) and prints SQL for OrangeHRM's own tables:
// sub units (departments), job titles, employees, their manager ("Report
// to", Direct) and, for leavers, a termination record.
//
// WHY the same roster: the connector compares OrangeHRM with that file. A
// faithful load means the first sync finds NOTHING to send (proved by
// `node ../connector/sync.mjs --dry-run`), so go-live changes no account.
//
// Run through hris.sh (`./hris.sh seed`), which pipes this to MariaDB. hris.sh
// refuses to run it twice (it stops if OrangeHRM already has a department).
// =============================================================================
import { readFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) { console.error('usage: node seed.mjs <hr_feed.csv> | mariadb orangehrm'); process.exit(2); }
const rows = readFileSync(file, 'utf8').split('\n').filter((l) => l && !l.startsWith('#')).slice(1).map((l) => {
  const [employeeId, givenName, surname, dept, jobTitle, manager, status, startDate, endDate] = l.split(',');
  return { employeeId, givenName, surname, dept, jobTitle, manager, status, startDate, endDate };
});
const q = (v) => (v ? `'${String(v).replace(/\\/g, '\\\\').replace(/'/g, "''")}'` : 'NULL');
const rules = JSON.parse(readFileSync(new URL('../../iga/birthright-rules.json', import.meta.url), 'utf8'));

const depts = [...new Set([...rules.jobProfiles.map((p) => p.department), ...rows.map((r) => r.dept)])];
const jobs = [...new Set([...rules.jobProfiles.map((p) => p.jobTitle), ...rows.map((r) => r.jobTitle)])].sort();

const out = [];
out.push('START TRANSACTION;');
// Org chart: the root ("Contoso Health", made by the installer) and one sub
// unit per department, as a nested set (OrangeHRM's own model).
out.push(`UPDATE ohrm_subunit SET rgt = ${2 + 2 * depts.length} WHERE level = 0;`);
depts.forEach((d, i) => out.push(`INSERT INTO ohrm_subunit (name, unit_id, description, lft, rgt, level) VALUES (${q(d)}, NULL, NULL, ${2 + 2 * i}, ${3 + 2 * i}, 1);`));
for (const j of jobs) out.push(`INSERT INTO ohrm_job_title (job_title, is_deleted) VALUES (${q(j)}, 0);`);
out.push("INSERT INTO ohrm_employment_status (name) SELECT 'Full-Time Permanent' WHERE NOT EXISTS (SELECT 1 FROM ohrm_employment_status WHERE name = 'Full-Time Permanent');");
for (const r of rows) {
  out.push(`INSERT INTO hs_hr_employee (employee_id, emp_firstname, emp_lastname, emp_middle_name, job_title_code, work_station, emp_status, joined_date)
  SELECT ${q(r.employeeId)}, ${q(r.givenName)}, ${q(r.surname)}, '',
    (SELECT id FROM ohrm_job_title WHERE job_title = ${q(r.jobTitle)} AND is_deleted = 0),
    (SELECT id FROM ohrm_subunit WHERE name = ${q(r.dept)} AND level = 1),
    (SELECT id FROM ohrm_employment_status WHERE name = 'Full-Time Permanent'),
    ${q(r.startDate)};`);
}
const num = (id) => `(SELECT emp_number FROM hs_hr_employee WHERE employee_id = ${q(id)} AND purged_at IS NULL)`;
for (const r of rows.filter((x) => x.manager)) {
  out.push(`INSERT INTO hs_hr_emp_reportto (erep_sup_emp_number, erep_sub_emp_number, erep_reporting_mode) SELECT ${num(r.manager)} AS s, ${num(r.employeeId)} AS e, 1;`);
}
for (const r of rows.filter((x) => x.status === 'leaver')) {
  out.push(`INSERT INTO ohrm_emp_termination (emp_number, reason_id, termination_date, note) SELECT ${num(r.employeeId)}, (SELECT id FROM ohrm_emp_termination_reason WHERE name = 'Resigned'), ${q(r.endDate)}, NULL;`);
  out.push(`UPDATE hs_hr_employee SET termination_id = LAST_INSERT_ID() WHERE employee_id = ${q(r.employeeId)};`);
}
// OrangeHRM keeps its own counter of the last employee record number
// (hs_hr_unique_id). A load that inserts rows itself must move it on, or
// the next "Add Employee" would reuse a taken record number.
out.push("UPDATE hs_hr_unique_id SET last_id = (SELECT MAX(emp_number) FROM hs_hr_employee) WHERE table_name = 'hs_hr_employee' AND field_name = 'emp_number';");
out.push('COMMIT;');
process.stdout.write(out.join('\n') + '\n');
