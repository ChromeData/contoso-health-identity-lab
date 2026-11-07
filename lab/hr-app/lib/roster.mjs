// =============================================================================
// roster.mjs - the "Contoso HR" system of record: the worker roster, and the
// three things HR does to it (hire, change, leave).
// -----------------------------------------------------------------------------
// WHY a roster file at all: the HR app needs somewhere to keep its workers.
// It keeps them in lab/scripts/mock-hr/hr_feed.csv on the hr-feed branch,
// the same file hr-feed.yml already reads. HR never sees or edits that file:
// it is the HR app's database table, written only by this code. Keeping the
// same file means the send path (hr-feed.yml -> Invoke-InboundProvisioning.ps1
// -> Entra's bulkUpload API) and its mass-change guard stay exactly as they
// are and as they were proven (capture log E52).
//
// Everything here is pure (no network, no disk): the store modules do I/O.
// No password field exists anywhere in this model. Entra's provisioning
// service sets the new account's first password itself; HR never handles one.
// =============================================================================

export const HEADER = 'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate';
const COLUMNS = HEADER.split(',');
const STATUSES = new Set(['joiner', 'active', 'leaver']);

// Employee number ranges. The shipped roster already follows them
// (100xxx staff, 200xxx managers, 300xxx executives, 400xxx IT), so the HR
// app keeps to them: the next IT hire after Mei Tanaka (400103) is 400104.
// That answers "where did 400104 come from": HR issued it, it was not typed.
export function idSeries(dept, jobTitle) {
  if (dept === 'Information Technology') return 400000;
  if (/\bChief\b/i.test(jobTitle)) return 300000;
  if (/\b(Manager|Director)\b/i.test(jobTitle)) return 200000;
  return 100000;
}

// Next free number in the series: one above the highest number in it.
// A real HR system never reuses a number. Here a number comes back only when
// the retake reset (reset-demo-hire.sh) deletes the demo row on purpose, so
// a re-recorded demo hire gets the same number as the first take.
export function nextEmployeeId(workers, dept, jobTitle) {
  const base = idSeries(dept, jobTitle);
  let max = base;
  for (const w of workers) {
    const n = Number(w.employeeId);
    if (n > base && n < base + 100000 && n > max) max = n;
  }
  if (max + 1 >= base + 100000) throw new HrError(`No free employee number left in the ${base} range.`);
  return String(max + 1);
}

export class HrError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

// The file: comment block and header kept byte for byte, data rows parsed.
export function parseRoster(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines[0] !== HEADER) throw new HrError('The roster does not start with the expected header.', 500);
  const head = [lines[0]];
  const workers = [];
  let i = 1;
  for (; i < lines.length && lines[i].startsWith('#'); i++) head.push(lines[i]);
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    if (line.startsWith('#')) continue; // a stray comment later in the file: the sender ignores it too
    const cells = line.split(',');
    if (cells.length !== COLUMNS.length) throw new HrError(`Roster line ${i + 1} has ${cells.length} fields, not ${COLUMNS.length}.`, 500);
    workers.push(Object.fromEntries(COLUMNS.map((c, k) => [c, cells[k]])));
  }
  return { head, workers };
}

export function serialiseRoster({ head, workers }) {
  return [...head, ...workers.map((w) => COLUMNS.map((c) => w[c] ?? '').join(','))].join('\n') + '\n';
}

// Free-text fields go into a CSV cell and a SCIM payload: letters, spaces,
// hyphen, apostrophe, dot only. No comma, quote or newline can reach the file.
const NAME = /^[\p{L}][\p{L} .'\-]{0,39}$/u;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

function clean(v) { return typeof v === 'string' ? v.trim().replace(/\s+/g, ' ') : ''; }

function checkDate(v, label) {
  if (!DATE.test(v) || Number.isNaN(Date.parse(`${v}T00:00:00Z`)) || new Date(`${v}T00:00:00Z`).toISOString().slice(0, 10) !== v) {
    throw new HrError(`${label} must be a real date (YYYY-MM-DD).`);
  }
}

// The job catalogue: HR picks a department and job from a list, as in a real
// HRIS. It comes from lab/iga/birthright-rules.json (the jobs IT has written
// access rules for) plus any job already on the roster.
export function jobCatalogue(rules, workers) {
  const jobs = new Map();
  for (const p of rules?.jobProfiles ?? []) if (p.department && p.jobTitle) jobs.set(`${p.department}|${p.jobTitle}`, { dept: p.department, jobTitle: p.jobTitle });
  for (const w of workers) if (w.dept && w.jobTitle) jobs.set(`${w.dept}|${w.jobTitle}`, { dept: w.dept, jobTitle: w.jobTitle });
  return [...jobs.values()].sort((a, b) => a.dept.localeCompare(b.dept) || a.jobTitle.localeCompare(b.jobTitle));
}

function checkJob(catalogue, dept, jobTitle) {
  if (!catalogue.some((j) => j.dept === dept && j.jobTitle === jobTitle)) {
    throw new HrError(`"${jobTitle}" in "${dept}" is not in the job catalogue.`);
  }
}

function checkManager(workers, manager, self) {
  if (!manager) return;
  const m = workers.find((w) => w.employeeId === manager);
  if (!m) throw new HrError('The manager is not on the roster.');
  if (m.status === 'leaver') throw new HrError('The manager has left the organisation.');
  if (manager === self) throw new HrError('A worker cannot be their own manager.');
}

// HIRE. HR gives name, job, department, manager, start date. The HR app
// issues the employee number. Status is 'joiner' (SCIM active=true).
export function hire(roster, input, catalogue) {
  const givenName = clean(input.givenName);
  const surname = clean(input.surname);
  const dept = clean(input.dept);
  const jobTitle = clean(input.jobTitle);
  const manager = clean(input.manager);
  const startDate = clean(input.startDate);
  if (!NAME.test(givenName)) throw new HrError('First name: letters only (up to 40).');
  if (!NAME.test(surname)) throw new HrError('Last name: letters only (up to 40).');
  checkJob(catalogue, dept, jobTitle);
  checkDate(startDate, 'Start date');
  checkManager(roster.workers, manager, null);
  const dupe = roster.workers.find((w) => w.status !== 'leaver' && w.givenName.toLowerCase() === givenName.toLowerCase() && w.surname.toLowerCase() === surname.toLowerCase());
  if (dupe) throw new HrError(`${givenName} ${surname} already works here. Change their record instead.`, 409);
  const employeeId = nextEmployeeId(roster.workers, dept, jobTitle);
  const worker = { employeeId, givenName, surname, dept, jobTitle, manager, status: 'joiner', startDate, endDate: '' };
  return { roster: { ...roster, workers: [...roster.workers, worker] }, worker, kind: 'hired' };
}

// CHANGE. New job / department / manager (a mover), or status -> leaver with
// an end date, or a leaver back to active (a rehire on the same number).
export function change(roster, employeeId, input, catalogue) {
  const idx = roster.workers.findIndex((w) => w.employeeId === employeeId);
  if (idx < 0) throw new HrError('No worker with that employee number.', 404);
  const before = roster.workers[idx];
  const after = { ...before };
  const status = clean(input.status) || before.status;
  if (!STATUSES.has(status)) throw new HrError('Status must be joiner, active or leaver.');
  if (input.dept !== undefined || input.jobTitle !== undefined) {
    after.dept = clean(input.dept) || before.dept;
    after.jobTitle = clean(input.jobTitle) || before.jobTitle;
    if (after.dept !== before.dept || after.jobTitle !== before.jobTitle) checkJob(catalogue, after.dept, after.jobTitle);
  }
  if (input.manager !== undefined) { after.manager = clean(input.manager); checkManager(roster.workers, after.manager, employeeId); }
  after.status = status;
  if (status === 'leaver') {
    after.endDate = clean(input.endDate) || before.endDate;
    checkDate(after.endDate, 'Last working day');
    if (after.endDate < after.startDate) throw new HrError('The last working day is before the start date.');
    const reports = roster.workers.filter((w) => w.manager === employeeId && w.status !== 'leaver');
    if (reports.length && before.status !== 'leaver') {
      throw new HrError(`${before.givenName} ${before.surname} still manages ${reports.length} worker(s). Give them a new manager first.`, 409);
    }
  } else {
    after.endDate = '';
  }
  const same = COLUMNS.every((c) => after[c] === before[c]);
  if (same) throw new HrError('Nothing changed.', 409);
  const kind = after.status === 'leaver' && before.status !== 'leaver' ? 'left'
    : before.status === 'leaver' && after.status !== 'leaver' ? 'rehired'
    : after.dept !== before.dept || after.jobTitle !== before.jobTitle ? 'moved' : 'updated';
  const workers = roster.workers.slice();
  workers[idx] = after;
  return { roster: { ...roster, workers }, worker: after, before, kind };
}

// One line for the HR system's change history (the commit message). Names,
// job and department only: never the employee number, manager or dates,
// the same rule hr-feed.yml's summary follows.
export function describe({ kind, worker, before }) {
  const who = `${worker.givenName} ${worker.surname}`;
  switch (kind) {
    case 'hired': return `HR: hire ${who}, ${worker.jobTitle} (${worker.dept})`;
    case 'left': return `HR: ${who} leaves`;
    case 'rehired': return `HR: ${who} comes back, ${worker.jobTitle} (${worker.dept})`;
    case 'moved': return `HR: ${who} moves from ${before.jobTitle} (${before.dept}) to ${worker.jobTitle} (${worker.dept})`;
    default: return `HR: update ${who}`;
  }
}

// What the form lists. No password, no account name, nothing IT-side: HR
// sees only HR's own fields.
export function publicWorker(w) {
  return { employeeId: w.employeeId, givenName: w.givenName, surname: w.surname, dept: w.dept, jobTitle: w.jobTitle, manager: w.manager, status: w.status, startDate: w.startDate, endDate: w.endDate };
}
