// =============================================================================
// feed.mjs - turn what HR did in OrangeHRM into rows of the provisioning feed.
// -----------------------------------------------------------------------------
// The feed is lab/scripts/mock-hr/hr_feed.csv on the hr-feed branch: the
// connector's outbox. hr-feed.yml reads it, signs in as HR-SYNC (GitHub OIDC,
// no secret) and sends only the changed rows to Entra API-driven inbound
// provisioning (bulkUpload). WHY an outbox file and not a direct call: ADR
// 0028, "Decision 3". Nobody edits the file by hand: only this connector
// writes it, and each sync that changes something is one commit.
//
// reconcile() is pure (no network, no disk). It compares OrangeHRM's view
// (connector-view.sql: eight HR fields per worker) with the feed and
// returns the new feed, one change per worker, and the workers it held back
// with the reason. It never deletes a row: HR marks a leaver, it does not
// delete one (a deleted or purged OrangeHRM record sends nothing).
//
// No password exists anywhere in this model. Entra's provisioning service
// sets the new AD account's first password itself; HR never handles one.
// =============================================================================

export const HEADER = 'employeeId,givenName,surname,dept,jobTitle,manager,status,startDate,endDate';
const COLUMNS = HEADER.split(',');

// The feed's employee numbers are six digits (100xxx staff, 200xxx managers,
// 300xxx executives, 400xxx IT). OrangeHRM's own "HR Administrator" record
// (0001, made by the installer) is not a Contoso worker and is never sent.
const EMPLOYEE_ID = /^\d{6}$/;
// Names go into a CSV cell and a SCIM payload: letters, spaces, hyphen,
// apostrophe, dot only. No comma, quote or newline can reach the file.
const NAME = /^[\p{L}][\p{L} .'\-]{0,39}$/u;
const TEXT = /^[\p{L}\p{N}][\p{L}\p{N} .&'()\/\-]{0,79}$/u;

// Above this many leavers or movers in ONE sync, the connector writes
// nothing and asks for a person to look (risk register R10). The sender has
// the same guard (Invoke-InboundProvisioning.ps1 -MaxChanges 10); stopping
// here as well keeps a bad HRIS edit out of the outbox entirely.
export const MAX_ACCESS_CHANGES = 10;

export class FeedError extends Error {}

// The file: comment block and header kept byte for byte, data rows parsed.
export function parseFeed(text) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines[0] !== HEADER) throw new FeedError('The feed does not start with the expected header.');
  const head = [lines[0]];
  const workers = [];
  let i = 1;
  for (; i < lines.length && lines[i].startsWith('#'); i++) head.push(lines[i]);
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.startsWith('#')) continue; // the sender ignores comments too
    const cells = line.split(',');
    if (cells.length !== COLUMNS.length) throw new FeedError(`Feed line ${i + 1} has ${cells.length} fields, not ${COLUMNS.length}.`);
    workers.push(Object.fromEntries(COLUMNS.map((c, k) => [c, cells[k]])));
  }
  return { head, workers };
}

export function serialiseFeed({ head, workers }) {
  return [...head, ...workers.map((w) => COLUMNS.map((c) => w[c] ?? '').join(','))].join('\n') + '\n';
}

// The local part of the userName the sender builds (given.surname, lowercased).
export function accountName(givenName, surname) {
  return `${givenName}.${surname}`.toLowerCase();
}

const str = (v) => (v === null || v === undefined ? '' : String(v).trim().replace(/\s+/g, ' '));
const day = (v) => (v ? String(v).slice(0, 10) : '');

// One OrangeHRM view row -> the feed's fields (status decided later).
function fromHris(r) {
  return {
    employeeId: str(r.employee_id),
    givenName: str(r.first_name),
    surname: str(r.last_name),
    dept: str(r.department),
    jobTitle: str(r.job_title),
    manager: str(r.manager_id),
    startDate: day(r.joined_date),
    terminationDate: day(r.termination_date),
  };
}

// RECONCILE. hrisRows: the view's rows. feed: parseFeed() of the outbox.
// today: YYYY-MM-DD in the hospital's time zone.
//
// Status rules (the feed's contract, hr_feed.csv header):
//  - Terminated in OrangeHRM with a termination date today or earlier ->
//    'leaver' with that endDate (SCIM active:false; the account goes off).
//  - Terminated with a FUTURE date -> not yet: the worker stays as they
//    are and the sync says "leaves on <date>". On that day the next sync
//    sends the leaver. (The old form could not do this; it refused a
//    future last day.)
//  - Not terminated: a worker new to the feed is a 'joiner'; one already in
//    the feed keeps 'joiner' or 'active'; a feed 'leaver' who is no longer
//    terminated (HR used "Activate Employment") comes back as 'active'.
//
// A worker is HELD BACK (nothing about them is written) when HR has not
// finished the record (no Sub Unit, Job Title or Joined Date yet), when the
// name cannot make a directory account name, when that account name is
// another worker's, when a new hire has no supervisor yet, or when the
// manager is not a current worker. Held-back
// workers are reported on every sync until HR fixes them.
export function reconcile(feed, hrisRows, today) {
  const held = [];
  const changes = [];
  const workers = feed.workers.map((w) => ({ ...w }));
  const byId = new Map(workers.map((w) => [w.employeeId, w]));
  const hris = hrisRows.map(fromHris).filter((h) => EMPLOYEE_ID.test(h.employeeId));
  const hrisById = new Map(hris.map((h) => [h.employeeId, h]));
  const current = (id) => { const h = hrisById.get(id); return h && !(h.terminationDate && h.terminationDate <= today); };

  for (const h of hris) {
    const who = `${h.givenName} ${h.surname}`.trim();
    const hold = (why) => held.push({ employeeId: h.employeeId, who, why });
    const before = byId.get(h.employeeId);
    if (!h.dept || !h.jobTitle || !h.startDate) {
      // A new record HR is still filling in. An existing worker whose job
      // fields were cleared by mistake is held too: never blank a feed row.
      hold('the Job tab is not finished (Sub Unit, Job Title and Joined Date are all needed)');
      continue;
    }
    if (!NAME.test(h.givenName) || !NAME.test(h.surname)) { hold('the first or last name has a character a directory name cannot hold'); continue; }
    if (!TEXT.test(h.dept) || !TEXT.test(h.jobTitle)) { hold('the Sub Unit or Job Title has a character the feed cannot hold'); continue; }
    const account = accountName(h.givenName, h.surname);
    if (/\s/.test(account)) { hold('a name with a space cannot make a directory account name; HR uses a hyphen (Mary-Ann)'); continue; }
    // The sender builds userName from the name alone, so two workers with the
    // same first.last would share ONE account. Leavers count: their disabled
    // AD account still exists.
    const clash = workers.find((w) => w.employeeId !== h.employeeId && accountName(w.givenName, w.surname) === account);
    if (clash) { hold(`the account name ${account} already belongs to employee ${clash.employeeId}; IT must give a different one`); continue; }
    // Every new hire reports to someone. HR sets the supervisor last (the
    // Report-to tab), so a new worker waits for it rather than going out
    // twice (once without a manager, then again with one).
    if (!before && !h.manager) { hold('no supervisor yet (the Report-to tab)'); continue; }
    if (h.manager && !current(h.manager)) { hold(`the supervisor (employee ${h.manager}) is not a current worker`); continue; }
    if (h.manager === h.employeeId) { hold('a worker cannot be their own supervisor'); continue; }

    const leaving = h.terminationDate && h.terminationDate <= today;
    let status;
    if (leaving) status = 'leaver';
    else if (!before) status = 'joiner';
    else if (before.status === 'leaver') status = 'active';
    else status = before.status;
    const after = {
      employeeId: h.employeeId, givenName: h.givenName, surname: h.surname, dept: h.dept,
      jobTitle: h.jobTitle, manager: h.manager, status, startDate: h.startDate,
      endDate: leaving ? h.terminationDate : '',
    };
    const scheduled = h.terminationDate && !leaving ? h.terminationDate : '';
    if (before && COLUMNS.every((c) => (before[c] ?? '') === after[c])) {
      if (scheduled) changes.push({ kind: 'scheduled', worker: after, before, on: scheduled, write: false });
      continue;
    }
    const kind = !before ? 'hired'
      : after.status === 'leaver' && before.status !== 'leaver' ? 'left'
      : before.status === 'leaver' && after.status !== 'leaver' ? 'rehired'
      : after.dept !== before.dept || after.jobTitle !== before.jobTitle ? 'moved'
      : 'updated';
    if (before) Object.assign(before, after); else { workers.push(after); byId.set(after.employeeId, after); }
    changes.push({ kind, worker: after, before: before ? { ...feed.workers.find((w) => w.employeeId === h.employeeId) } : undefined, write: true, ...(scheduled ? { on: scheduled } : {}) });
  }

  const written = changes.filter((c) => c.write);
  const accessChanges = written.filter((c) => c.kind === 'left' || c.kind === 'moved').length;
  if (accessChanges > MAX_ACCESS_CHANGES) {
    throw new FeedError(`This sync would make ${accessChanges} leavers or job changes at once (the limit is ${MAX_ACCESS_CHANGES}). Nothing was written. Check OrangeHRM. If the change is real, IT sends it as a reviewed bulk change (lab/scripts/mock-hr/README.md).`);
  }
  return { feed: { ...feed, workers }, changes, held, notInHris: feed.workers.filter((w) => !hrisById.has(w.employeeId)).map((w) => w.employeeId) };
}

// One line for the change history (the commit message). Names, job and
// department only: never the employee number, manager or dates, the same
// rule hr-feed.yml's summary follows (the repo is public).
export function describe({ kind, worker, before }) {
  const who = `${worker.givenName} ${worker.surname}`;
  switch (kind) {
    case 'hired': return `HR: hire ${who}, ${worker.jobTitle} (${worker.dept})`;
    case 'left': return `HR: ${who} leaves`;
    case 'rehired': return `HR: ${who} comes back, ${worker.jobTitle} (${worker.dept})`;
    case 'moved': return `HR: ${who} moves from ${before.jobTitle} (${before.dept}) to ${worker.jobTitle} (${worker.dept})`;
    case 'scheduled': return `HR: ${who} is due to leave (not sent yet)`;
    default: return `HR: update ${who}`;
  }
}

// Today's date in the hospital's time zone (the lab: US Eastern), as
// OrangeHRM shows dates. A leaver dated today goes out today.
export function hospitalToday(now = new Date(), timeZone = 'America/New_York') {
  return new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);
}
