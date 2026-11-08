# ADR 0028: OrangeHRM is the lab's HR system; a scheduled connector feeds Entra API-driven inbound provisioning

- **Status:** RAN · tenant (2026-11-07, capture log E174-E177): a test worker was hired, moved and made a leaver in OrangeHRM's own screens, and the connector carried each change to Entra. Timings are in "Measured in the tenant" below. Option "Workday personal tenant" is DESIGNED only (an owner step).
- **Date:** 2026-11-07
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-07, or when a Workday personal development tenant is granted to the owner
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.
- **Supersedes:** [ADR 0027](0027-hr-form-as-the-hr-system.md) decisions 1 and 3 (the "Contoso HR" form and where it runs). ADR 0027 decision 2 stands: the target stays on-premises AD through the provisioning agent. The form (`lab/hr-app/`) is retired.

## Context

ADR 0027 replaced "HR edits a CSV in VS Code" with a small web form. The
owner then asked for more: a **real HR platform** in the demo, so that the
video can show HR's own workflow for a hire in a real HRIS screen, and then
how it pushes down into the technical chain (Entra API-driven inbound
provisioning → AD → Cloud Sync → Entra → group rules → AWS, ServiceNow).
The form was honest, but it was ours: it looked like what it was, a lab page.

The constraints: $0, and never buy anything (program brief 2026-11-06).
No fakery: a hire, a job change and a leaver must travel through the real
Microsoft path. Secrets only in the macOS Keychain, and no stored client
secret on the Entra side where we can avoid one.

## Research (2026-11-07)

| Option | Looks like a real hospital HRIS | $0 | Hire, job change, leaver to Entra without fakery | Cost to keep running | Verdict |
|---|---|---|---|---|---|
| **Workday** personal development tenant | Yes: it is Workday | Free (Workday Developer Program, "open access beta") | Best possible: Entra's native "Workday to on-premises AD" app pulls from Workday's own web services. Not proven: Workday says "not all functional areas are turned on by default", and the FAQ does not say that Core HCM hire and terminate run there | **A tenant with no activity for 7 consecutive days is deleted, permanently, with no warning.** One tenant per account. Approval "depends on current availability" | **Not now. DESIGNED, owner step** (see "Revisit") |
| **OrangeHRM** Open Source 5.9, in Colima on this Mac | Yes: PIM employee list, Add Employee, Job (title, sub unit, joined date), Report-to, Terminate Employment, Maintenance > Purge. Hospitals are among its users | Yes: GPLv3, self-hosted, no account to sign up for | Yes: the connector reads what HR saved and sends it through the real API | Free. About 0.6 GB of memory while it runs; stop it with `hris.sh down` | **Chosen** |
| **ServiceNow HR Service Delivery** in the lab's PDI | Partly: HRSD is HR case management (an HR portal, onboarding cases). It is not the system of record; in real hospitals Workday or SuccessFactors feed it | Community posts say the plugin `com.sn_hr_core` can be activated on a personal developer instance for free; others report entitlement errors and roles that do not activate | Weak: there is no "hire" business process to start from, and ServiceNow is already a **target** of Entra provisioning in this lab. Making it the source as well makes `sys_user` both ends of one loop | The PDI hibernates when idle and is reclaimed after inactivity | Rejected |
| **BambooHR** / **Zoho People** | Yes | No. BambooHR has no free plan, only a trial. Zoho People's free plan covers 5 users, and its own pricing table lists no API and no webhook on that plan | Only during a trial, with an owner sign-up | A trial ends, then it is paid. Over the cost cap | Rejected |
| **Microsoft samples** (Logic Apps "CSV2SCIMBulkUpload", PowerShell CSV-to-SCIM) | No: no HR screens at all. They are the plumbing between an HR extract and `bulkUpload` | The PowerShell sample is free; the Logic App runs in Azure (a small charge per run) | Yes, but there is nothing for HR to click | n/a | **Used as the pattern**, not as the HRIS. Our sender (`Invoke-InboundProvisioning.ps1`) is already the PowerShell equivalent |

**A correction to the brief.** The brief said "Workday has no free
individual tenant". That was true until 2026. The Workday Developer
Program now offers a free personal development tenant to anyone with a
personal email, in an open-access beta ([Workday blog](https://blog.workday.com/en-us/workday-open-developer-platform-generally-available.html),
[program FAQ](https://github.com/Workday/WorkdayDeveloperProgram/blob/main/FAQ.md)).
We did not choose it today, for three reasons. Only the owner can sign up
(his own email and identity). Approval depends on availability. And a
tenant left alone for seven days is deleted, while the recording is
planned for 2026-11-22. Whether its Core HCM can hire and terminate is not
documented, so it would need a test before any claim.

## Decision 1: OrangeHRM Open Source is the HR system

`lab/hris/orangehrm/` runs OrangeHRM 5.9 and MariaDB 11.4 in Colima on this
Mac (`hris.sh up`). Both listen on **127.0.0.1 only**.

- **Native image.** The official `orangehrm/orangehrm` image is amd64 only.
  Under emulation its PHP workers crashed ("Segmentation fault", an empty
  sign-in page). `Dockerfile` repeats the official image's own build steps
  on the multi-arch PHP 8.3.31 base: same PHP, same extensions, same release
  zip from SourceForge, checked against the official image's MD5 and our
  SHA-256. The PHP and MariaDB bases are pinned by digest.
- **Go-live load.** `hris.sh seed` loads the roster Entra already holds
  (the `hr-feed` file: 13 workers, 2 of them leavers, departments, job
  titles, managers) into OrangeHRM's own tables, as a hospital loads its
  workers once when it moves to a new HRIS. The first connector sync after
  the load found **nothing to send**, so go-live changed no account.
- **The employee number.** HR types it on Add Employee. OrangeHRM proposes
  only its own record counter (0015, 0016 ...), which has no ranges.
  Contoso's HR keeps the hospital's ranges: 100xxx staff, 200xxx managers,
  300xxx executives, 400xxx IT. So the next IT hire after Mei Tanaka
  (400103) is **400104**: HR gives it, in the HR system.
- **Secrets.** Four passwords (MariaDB root, OrangeHRM's own database
  account, OrangeHRM's Admin sign-in, the connector's database account).
  `hris.sh` makes each with openssl, keeps it only in the Keychain, and hands
  it over as a compose secret file or on stdin. None is in the repo, in
  argv, in `docker inspect` or in a log.

## Decision 2: the target is unchanged

As ADR 0027 decision 2: Entra API-driven inbound provisioning, app
"Contoso HR Inbound Provisioning" (`API2AD`), writes to on-premises AD
through the provisioning agent on DC01. Cloud Sync copies AD to Entra.

## Decision 3: a scheduled connector, reading one view, sending as HR-SYNC

`lab/hris/connector/sync.mjs --watch 60` runs one sync a minute:

1. **Read** OrangeHRM's view `hr_feed.v_worker_feed`
   (`lab/hris/orangehrm/connector-view.sql`): eight fields per worker
   (employee id, first and last name, sub unit, job title, the direct
   supervisor's employee id, joined date, termination date).
2. **Compare** with the feed file on `hr-feed` and decide, per worker:
   hired, moved, left, came back, or held (`lib/feed.mjs`).
3. **Write** one commit when anything changed. `hr-feed.yml` runs on it,
   signs in as **HR-SYNC** over GitHub OIDC and sends only the changed
   workers to `bulkUpload` (unchanged since E52; ADR 0027).

**Why a schedule, not a webhook.** OrangeHRM Open Source has no outbound
webhook. A one-minute poll of one small view is cheap and adds at most a
minute.

**Why a database view, not OrangeHRM's REST API.** Least data, enforced by
the database. The connector's account `hr_connector` has `SELECT` on the
view and nothing else. Measured: `SELECT emp_birthday FROM
orangehrm.hs_hr_employee` and a read of the salary table both return
"access denied". So a date of birth, address, salary, national ID or
termination reason can never reach the connector or Microsoft, whatever the
connector's code does. OrangeHRM's API (OAuth 2.0 since 5.4) uses the
authorization-code flow with PKCE: a person signs in and the client holds
that person's refresh token. Its employee calls return whole records. That
is more data and a person's token, for no gain here.

**Why GitHub in the middle, not a direct call from this Mac.** It keeps
**no stored client secret on the Entra side**. A direct call needs an app
that holds `SynchronizationData-User.Upload` and a credential on this
laptop (a secret or a certificate): a standing HR write credential on a
laptop. HR-SYNC needs none: GitHub's OIDC token is short-lived and its
federated credential trusts only the `hr-feed` branch. The lab operator
cannot send at all (403, E120) and should not (ADR 0027: HR data comes from
an HR identity, not IT's Tier-0 tool). The cost is about 40 seconds for
the GitHub runner (measured below).

**Rules the connector keeps** (each has a test in
`tests/connector.test.mjs`):

- **Hire.** A worker new to the feed goes out as a `joiner` only when HR
  has finished the record: Job tab (sub unit, job title, joined date) and
  Report-to (a supervisor). Until then the sync prints "HELD ... the Job tab
  is not finished" or "no supervisor yet". So a hire goes out once,
  complete.
- **Job change.** A new job title or sub unit is a mover. The status stays.
- **Leaver.** "Terminate Employment" with a date **today or earlier** sends
  a leaver (SCIM `active:false`). A **future** date waits: the sync prints
  "due to leave on ..." each minute and sends it on that day. (OrangeHRM
  lists the worker as a past employee at once; the connector goes by the
  date.) The retired form could not do this; it refused future dates.
- **Came back.** "Activate Employment" on a leaver sends an `active` row.
- **Never deletes.** A purged or deleted OrangeHRM record sends nothing.
  HR marks leavers; the retake reset removes demo rows on purpose.
- **Account name.** The sender builds `first.last`. A clash with anyone on
  the feed (leavers too, because their disabled AD account exists) or a
  space in a name holds the worker with a reason HR can act on.
- **Mass change.** More than 10 leavers or job changes in one sync writes
  nothing (risk register R10; the sender has the same guard).
- **Public repo.** Commit messages carry names, job and department only:
  never the employee number, manager or dates.

**The production shape (DESIGNED).** The same connector as an Azure
Function with a managed identity that holds
`SynchronizationData-User.Upload.OwnedBy`, calling `bulkUpload` directly
and reading the HRIS over a private endpoint. Or, for Workday or
SuccessFactors, no connector at all: Entra's native app pulls.

## What HR does (the screens)

All in OrangeHRM, signed in as an HR administrator. Full click list:
`lab/hris/README.md` and `readiness/hr-flow.md` (outside the repo).

| HR task | OrangeHRM screens | What the connector sends |
|---|---|---|
| Hire | PIM > Add Employee (name, Employee Id) > Save; Job tab (Joined Date, Job Title, Sub Unit, Employment Status) > Save; Report-to > Assigned Supervisors > Add (supervisor, Direct) > Save | One joiner, once Report-to is saved |
| Job change | PIM > the worker > Job > new Job Title or Sub Unit > Save | One mover |
| Leaver | PIM > the worker > Job > Terminate Employment (date, reason) > Save | One leaver, on the termination date |

## Measured in the tenant (2026-11-07)

Test worker "Test Hris", Registered Nurse, Nursing, employee number
100493 (typed by HR). Every HR action was done in OrangeHRM's own screens
by `hr-clicks.mjs` (a headless browser doing HR's clicks; screenshots kept).
The connector ran with `--watch 60`. Times are UTC; "+" counts from HR's
last click (the Save that finishes the task).

**Hire** (capture log E174)

| UTC | + | Step |
|---|---|---|
| 17:50:37 | 0:00 | HR saves Report-to (Add Employee 17:50:30, Job 17:50:35 before it) |
| 17:51:23 | 0:46 | Connector: "SEND hire Test Hris, Registered Nurse (Nursing)"; commit `ba3d029` on `hr-feed` |
| 17:52:04 | 1:27 | `bulkUpload` answers 202 (run 42398357477, HR-SYNC) |
| 17:52:08 | 1:31 | Provisioning log: created in on-premises AD |
| 18:07:13 | 16:36 | Cloud Sync: Entra user created, enabled (its user cycle is 20 minutes; this hire waited most of one) |
| by 18:08:07 | 17:30 | Dynamic groups: All-Nurses and the nurse auto-assignment group |
| 18:08:33 | 17:56 | IT runs the joiner Lifecycle Workflow **on demand** (its schedule is every 3 hours). 18:08:43 account enabled; "email the TAP to the manager" **failed** (no manager mail; known lab gap); package requested |
| 18:10:03 | 19:26 | "Nurse - Clinical Apps" delivered: App-AWS-IdentityCenter-Users, App-ServiceNow-Users |
| 18:17:23 | 26:46 | ServiceNow: user created (40-minute cycle) |
| 18:36:28 | 45:51 | AWS IAM Identity Center: user created (SCIM, 40-minute cycle), UserStatus ENABLED |

**Job change** (E175): Sub Unit Nursing to ICU

| UTC | + | Step |
|---|---|---|
| 18:20:15 | 0:00 | HR saves the Job tab |
| 18:20:23 | 0:08 | Connector: "SEND Test Hris moves from Registered Nurse (Nursing) to Registered Nurse (ICU)"; commit `0ff3f36` |
| 18:20:56 | 0:41 | `bulkUpload` 202 (run 42400791317) |
| 18:21:00 | 0:45 | AD account updated |
| 18:22:30 | 2:15 | Cloud Sync: Entra department ICU |
| by 18:23:37 | 3:22 | Dynamic groups: out of All-Nurses, into All-ICU and the ICU auto-assignment group |
| 18:55:10 | 34:55 | "ICU - Critical Care Apps" delivered by its auto-assignment policy (see the leaver: by then the account was already off) |

**Leaver** (E176): Terminate Employment, date today, reason Resigned

| UTC | + | Step |
|---|---|---|
| 18:37:19 | 0:00 | HR saves Terminate Employment (date 2026-11-07, Resigned) |
| 18:37:23 | 0:04 | Connector: "SEND Test Hris leaves"; commit `a4ec768` |
| 18:37:55 | 0:36 | `bulkUpload` 202 (run 42402205564), SCIM `active:false` |
| 18:37:58 | 0:39 | AD account disabled |
| 18:47:56 | 10:37 | Cloud Sync: Entra "Account enabled: No" |
| by 18:50:47 | 13:28 | Dynamic groups: out of All-ICU and the ICU auto-assignment group |
| 18:55:10 | 17:51 | **Gap seen:** the ICU auto-assignment policy delivered "ICU - Critical Care Apps" (App-ICU-CriticalCare-Users) to the already-disabled account, 35 minutes after the job change. Correction (PR #256): the rule and the live policy DO require `accountEnabled -eq true`. Entitlement management evaluated the rule late and acted on an old state (it created the request at 18:53:55, 6 minutes after the disable). The account cannot sign in (Entra disabled), and the user was deleted at clean-up. The leaver fix is ADR 0029 (PR #257). "Nurse - Clinical Apps" went into its 3-day grace period, as before |
| 18:57:24 | 20:05 | ServiceNow: user disabled (40-minute cycle) |
| 19:16:29 | 39:10 | AWS IAM Identity Center: user disabled (SCIM, 40-minute cycle) |

**Clean-up** (E177): OrangeHRM Terminate then Maintenance > Purge (19:17:02;
OrangeHRM keeps an anonymised "Purged Employee" row, so `hris.sh free-id
100493` freed the number for retakes); `reset-demo-hire.sh 100493 --apply`
as the operator removed the `hr-feed` row and the AD account; the
ServiceNow record was deleted as the ServiceNow admin (read back: none);
Cloud Sync deleted the Entra user, `--purge-entra` emptied Deleted users,
and SCIM removed the AWS user (Entra gone by 19:29:32, AWS by 19:57:04; read back 0 everywhere at 19:57:16, E177). DC01 was deallocated again.

**Read the timings this way.** HR's part, OrangeHRM to Active Directory,
took 1:31 for the hire, 0:45 for the job change and 0:39 for the leaver.
The connector added 4 to 46 seconds (its one-minute poll), and the GitHub
runner about 35 seconds. Everything after AD runs on Microsoft's
schedules: Cloud Sync (20 minutes), the joiner workflow (3 hours; run on
demand here), app provisioning (40 minutes).

## Consequences

**Positive**
- The demo starts in a real HRIS, with HR's own screens and words.
- Least data is enforced by the database, not promised by code.
- No new Entra identity, permission or secret. HR-SYNC still sends.
- A future-dated leaver now works.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| The HRIS runs on one Mac; if it is off, nothing is sent | Nothing is lost either: the next sync sends everything changed since the last one (the feed is compared, not a queue). `hris.sh status` and the connector's first line show it is up |
| One OrangeHRM Admin sign-in for all of HR | Lab scale. OrangeHRM can give each HR person a named user with the Admin or ESS role (Admin > User Management). Production: Entra SSO in front of the HRIS |
| The connector's database password is a stored secret | Keychain only; the account reads one view and listens on 127.0.0.1. The Entra side has no stored secret |
| The GitHub runner adds time | Measured below. A Function App with a managed identity removes the hop (DESIGNED) |
| OrangeHRM's screens show an "Upgrade" button (its paid edition) | Said plainly: "This is OrangeHRM, the open-source edition, running on this Mac." Nothing is bought |

## Revisit trigger

- The owner signs up at developer.workday.com and gets a personal tenant:
  test a hire and a termination there. If both work, add Entra's
  "Workday to on-premises Active Directory user provisioning" app and
  compare. Keep OrangeHRM as the fallback (no 7-day deletion).
- The lab gets a budget line: move the connector to an Azure Function with
  a managed identity.

## Evidence

- `lab/hris/` (OrangeHRM, connector, rehearsal driver) and
  `lab/hris/connector/tests/connector.test.mjs` (CI: `lab-tests.yml`)
- Capture log E174-E177; screenshots in `~/contoso-demo/captures/hris/2026-11-07/` (outside the repo)
- Workday: [developer program](https://blog.workday.com/en-us/workday-open-developer-platform-generally-available.html), [FAQ](https://github.com/Workday/WorkdayDeveloperProgram/blob/main/FAQ.md)
- OrangeHRM: [release notes (OAuth 2.0 in 5.4)](https://sourceforge.net/projects/orangehrm/files/stable/), [registering an OAuth client](https://api-starter-orangehrm.readme.io/reference/registering-a-client)
- ServiceNow HRSD on a PDI: [community thread](https://www.servicenow.com/community/hrsd-forum/hr-plugin-activation-on-personal-dev/m-p/1321028)
- Zoho People: [pricing](https://www.zoho.com/people/pricing.html)
- Microsoft: [inbound provisioning with Logic Apps](https://learn.microsoft.com/entra/identity/app-provisioning/inbound-provisioning-api-logic-apps), [with PowerShell](https://learn.microsoft.com/entra/identity/app-provisioning/inbound-provisioning-api-powershell), [bulkUpload permissions](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationjob-post-bulkupload?view=graph-rest-1.0#permissions)
