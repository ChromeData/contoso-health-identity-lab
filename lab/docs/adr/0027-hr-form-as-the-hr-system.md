# ADR 0027: An HR form stands in for the HR system; it sends through API-driven inbound provisioning to AD

- **Status:** RAN · tenant (2026-11-07, capture log E120-E123): a test worker was hired and made a leaver from the form, then removed with the retake reset. Timings are in "Measured in the tenant" below. Option D is DESIGNED only.
- **Date:** 2026-11-07
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-07, or when the lab gets a hosted HR app or a real HRIS tenant
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.
- **Partly supersedes:** [ADR 0006](0006-api-driven-inbound-provisioning-vs-workday-connector.md), only its "source" line (`hr_feed.csv` edited by hand). The rest of 0006 stands.

## Context

The owner pointed out a gap: real HR staff never edit a CSV in VS Code.
Until now the lab's joiner, mover and leaver flow started when a person
edited `lab/scripts/mock-hr/hr_feed.csv` on the `hr-feed` branch and pushed
it. Everything after that push was already the real Microsoft product:

1. `hr-feed.yml` signs in as **HR-SYNC** (GitHub OIDC, no secret) and sends
   only the changed rows to **Entra API-driven inbound provisioning**
   (`POST /servicePrincipals/{id}/synchronization/jobs/{jobId}/bulkUpload`).
2. The provisioning app "Contoso HR Inbound Provisioning" (template
   `API2AD`) writes the account into Active Directory on DC01 through the
   **provisioning agent** (the Cloud Sync agent).
3. **Cloud Sync** copies AD to Entra ID. Group rules, the access-package
   auto-assignment, AWS SCIM and ServiceNow provisioning follow.

So the unrealistic part was only the first step: who changes the HR data,
and with what tool. Three questions had to be answered.

## Decision 1: the source is a small HR web form ("Contoso HR")

`lab/hr-app/` is a plain web form that stands in for Workday or
SuccessFactors. HR can do three things:

- **Hire:** first name, last name, department, job, manager, start date.
- **Change:** a new department, job or manager (a mover).
- **Leave:** set the status to Leaver and give the last working day.

The department and job come from a list: the jobs IT has access rules for
(`lab/iga/birthright-rules.json`) plus the jobs already on the roster. A real
HRIS has a job catalogue too. The form has no password field, and it never
shows one. Entra's provisioning service sets the first password of the AD
account itself, and nobody sees it.

**The HR system issues the employee number.** It takes the next free number
in the worker's range. The roster already uses these ranges: 100xxx staff,
200xxx managers, 300xxx executives, 400xxx IT. The last IT number in use is
400103 (Mei Tanaka), so the next IT hire gets **400104**. This answers the
owner's question about where 400104 came from. Before this change, a person
typed it in the README's example row. Now the HR system issues it.

A real HRIS never reuses a number. In the lab a number can come back only
when the retake reset (`reset-demo-hire.sh`) deletes a demo row on purpose.
Then a re-recorded hire gets the same number as the first take.

## Decision 2: the target stays on-premises AD, through the provisioning agent

Entra offers two API-driven apps: "to Microsoft Entra ID" (cloud-only users)
and "to on-premises Active Directory" (through the provisioning agent). We
keep the **AD** target, for these reasons:

- **The agent supports it, and it is already proven.** The lab's job is
  `API2AD`. Its agent is the Cloud Sync agent on DC01. It wrote joiners and
  leavers into AD on 2026-10-28 (E52) and many times on 2026-11-05.
- **A hospital is hybrid.** Clinical workstations, file shares and the
  Windows LAPS and PAM work need the person in AD. A cloud-only Entra user
  has no AD account.
- **One owner per attribute.** Cloud Sync makes AD the owner of the synced
  user's core attributes and of `accountEnabled`. If HR wrote straight to
  Entra, the same person would need a second, cloud-only account, or the AD
  account would be made by hand.
- **The cost is time.** AD-first adds the Cloud Sync step (2 min 35 s for
  the hire, 46 s for the leaver, measured below). A cloud-only target would
  skip it. We accept the delay.

## Decision 3: where it runs - a local page that sends through HR-SYNC

| Option | Can it send today? | Cost | Verdict |
|---|---|---|---|
| **A. Local page (127.0.0.1); each save is a commit to the roster on `hr-feed`; `hr-feed.yml` sends it as HR-SYNC** | Yes: HR-SYNC already holds `SynchronizationData-User.Upload.OwnedBy` and has sent since 2026-11-05 | $0 | **Chosen** |
| B. Local page that calls bulkUpload through the lab operator | No. The operator has `Synchronization.ReadWrite.All`, which bulkUpload does not accept. A live call returned **403** "User doesn't have required access" (2026-11-07, an empty batch, nothing sent). Microsoft lists only `SynchronizationData-User.Upload(.OwnedBy)` for this API | $0 | Rejected |
| C. Azure Static Web App with its managed functions | Not as designed. Managed functions have **no managed identity** (Microsoft's "API support in Azure Static Web Apps" table). They would need a stored client secret | Free plan | Rejected |
| D. Static Web App + its own Function App, or a Function App alone, with a managed identity holding `SynchronizationData-User.Upload.OwnedBy` and Entra sign-in for HR staff | After new code and a bootstrap apply | Linking your own Function App needs the paid Static Web Apps Standard plan (a monthly fee per app). A Function App alone on a consumption plan costs close to $0 at this volume | **DESIGNED**: the production shape, next step |

**Why A.** It is free. It uses the only identity that can already send. It
keeps everything after the HR save the same as before, and that path is
proven: the "only changed rows" logic, the mass-change guard (more than 10
leavers or movers in one save stops the send), and the plain-English run
summary.

**Why not B.** Even with the permission, B would be wrong. The lab operator
is the IT admin's tool (Tier 0, ADR 0024). HR data should come from an HR
identity. Then the provisioning logs and the commit history show that the
change came from HR, not from IT. Giving the operator the upload permission
would also let IT create and disable workers with no HR record. That is the
segregation-of-duties gap a hospital auditor looks for.

**What HR sees.** HR never sees GitHub or the file. HR sees "Saved", then
"Sending to IT systems", then "Delivered to IT systems at 7:50:43 PM" (from
the `hr-feed` push run's result). If Microsoft logs a failure, the run turns red,
and the form says "Not delivered. IT has the details and will contact HR."

**The roster file is the HR app's database table.** The file stays
`hr_feed.csv` on `hr-feed`. Only the HR app writes it, and each save is one
commit with a plain message, such as "HR: hire Sam Rivera, Cloud Engineer
(Information Technology)". The commit history is the HR system's change
history. The write sends the file's blob sha, so two saves at the same time
cannot overwrite each other. The CSV path stays working for the existing
pieces (Pester suites, `reset-demo-hire.sh`, the dry run). It is no longer
the way HR makes a change.

## Measured in the tenant (2026-11-07)

Test worker "Test Hrform", Registered Nurse, Nursing. The form issued
employee number 100493. Times are UTC. "+" counts from HR's click.

**Hire** (capture log E121)

| UTC | + | Step |
|---|---|---|
| 00:44:56 | 0:00 | HR clicks Hire; commit `bd188ae` on `hr-feed` |
| 00:45:33 | 0:37 | `bulkUpload` answers 202 (run 42320098716, HR-SYNC) |
| 00:45:40 | 0:44 | Provisioning log: created in on-premises AD |
| 00:48:15 | 3:19 | Cloud Sync: Entra user created, enabled |
| 00:49:32 | 4:36 | Dynamic groups: All-Nurses and the nurse auto-assignment group |
| 00:50:43 | 5:47 | The form shows "Delivered" (the run waits for the provisioning log, which appeared about 4 minutes after the event) |
| 01:10:33 | 25:37 | The joiner Lifecycle Workflow runs: account enabled, a Temporary Access Pass added, package requested (01:11:01). Its "email the TAP to the manager" task **failed**: the manager has no mail attribute (a lab gap, not caused by this change) |
| 01:15:07 | 30:11 | "Nurse - Clinical Apps" delivered: App-AWS-IdentityCenter-Users and App-ServiceNow-Users |
| 01:15:20 | 30:24 | AWS IAM Identity Center: user created (SCIM) |
| 01:20:17 | 35:21 | ServiceNow: user created |

The auto-assignment policy had not assigned the package after 21 minutes;
the joiner workflow's request did. The slowest steps are the schedules
after Entra (the workflow and the 40-minute app provisioning cycles), not
the HR send.

**Leaver** (capture log E122)

| UTC | + | Step |
|---|---|---|
| 01:26:04 | 0:00 | HR sets Status to Leaver; commit `ada86b0` |
| 01:26:33 | 0:29 | `bulkUpload` answers 202 (run 42324043896, attempt 1) |
| 01:26:38 | 0:34 | Provisioning log: **failure**, `HybridIdentityServiceNoActiveAgents` (the agent on DC01 timed out). The run turned red; the form showed "Not delivered. IT has the details and will contact HR." The agent read "active" again at 01:32 |
| 01:32:43 | 6:39 | IT re-runs the failed run (the documented recovery) |
| 01:33:11 | 7:07 | `bulkUpload` 202 again (attempt 2) |
| 01:33:14 | 7:10 | AD account disabled |
| 01:34:00 | 7:56 | Cloud Sync: Entra "Account enabled: No" |
| 01:34:26 | 8:22 | Removed from All-Nurses and the auto-assignment group |
| 01:39:03 | 12:59 | The form's status for this save reads "delivered" |
| 01:37:10 | 11:06 | ServiceNow: user disabled |
| __AWSL__ | __AWSLD__ | AWS: user disabled (SCIM) |

With the agent answering, the leaver took 49 seconds from the send to
"Account enabled: No" in Entra. The failure shows the safety net works:
nothing was half-done, HR was told, and one re-run finished it.

## Consequences

**Positive**
- The on-camera story is true end to end: HR clicks Hire, and Microsoft's
  real HR API creates the worker.
- Nothing new is privileged: no new identity, no new permission, no new
  Azure resource, no cost.
- The employee number has a plain answer.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| Anyone who can reach the form can hire or remove workers | It listens on 127.0.0.1 only. Every write needs the per-start form token in the page, so a page from another site cannot post. The form's local `gh` sign-in is the repo admin's. Option D replaces this with Entra sign-in and an HR group |
| The send waits for a GitHub runner | Measured: about 37 seconds from Save to bulkUpload. A queued runner can add more. HR sees "Sending" until the run ends |
| A local page is not how a real HR SaaS is hosted | Said plainly on camera: "This form stands in for the HR system." Option D is the hosted shape |
| The HR app's `gh` sign-in is a person's token, not a workload identity | The token only writes a commit. The send is still HR-SYNC's, over OIDC. Option D removes the person's token |

## Revisit trigger

- The lab gets an HR group and a budget line for option D: build the
  Function App with a managed identity, and retire the commit step.
- The scenario gets a real HRIS tenant: switch employees to the native
  connector (ADR 0006, option 3).

## Evidence

- `lab/hr-app/` (form, API, roster rules, stores) and its tests
  `lab/hr-app/tests/hr-app.test.mjs` (CI: `lab-tests.yml`, shell tests step)
- Capture log E120-E123: the 403 probe, the hire, the leaver, the clean-up
- Microsoft: [bulkUpload permissions](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationjob-post-bulkupload?view=graph-rest-1.0#permissions),
  [Static Web Apps managed functions vs. your own](https://learn.microsoft.com/en-us/azure/static-web-apps/apis-functions)
