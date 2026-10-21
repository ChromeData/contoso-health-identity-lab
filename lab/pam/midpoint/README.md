# midPoint certification campaign (SailPoint / Saviynt stand-in)

One access-certification campaign in the local Evolveum midPoint 4.10
container (`../docker-compose.yml`), run headless over midPoint's REST API
and exported as hashed evidence.

> **Status: RAN · harness.** Run locally on 2026-10-20 against midPoint
> 4.10.4 (Colima, Apple Silicon). Two hashed evidence runs are in
> [`../../evidence/midpoint/`](../../evidence/midpoint/) (`20261020T152623Z`
> and the current-definition run `20261020T162116Z`). `../test/e2e-midpoint.sh`
> passed 91/91 in every `../test/run-all.sh` run on 2026-10-20. The latest
> count is held in the newest record under
> [`../../evidence/offline-tests/`](../../evidence/offline-tests/) (counts
> and run-all's console output; the suite's own log is gitignored because it
> names lab accounts).
> Latest campaign: 7 work items, 6 decided by the assigned reviewer, 1 left
> unanswered on purpose; 4 accepted, 2 revoked, 1 removed for no response;
> completion 85.7% against the T2 target of 95%. **RAN · tenant: nothing.**
> The users come from object files built from the mock HR personas, not from
> Entra. Aggregating Entra users through the Microsoft Graph connector is a
> tenant-time step (BUILT as instructions only, `../README.md`, midPoint
> section).

## What the campaign does

The definition (`objects/40-certdef-requestable-roles.xml`) implements tier
**T2, requestable access**, from
[ADR 0012](../../docs/adr/0012-access-review-no-response-and-clinical-lockout.md),
specifically its branch for requestable access that does **not** expire: ADR
0012 certifies ordinary T2 access through the 180-day assignment expiry (no
campaign), and allows a campaign only where access lives longer or can be
self-extended. These midPoint role assignments carry no `validTo`, so that
branch applies. The halfyearly cadence and the mandatory justification it calls
for are not modelled in this one-off run.
It certifies the requestable business roles held by enabled users. The holder's
manager reviews each item, with the access governance lead as the fallback.
Remediation is automated, and an unanswered item is **removed**.

| Holder | Role | Reviewer (how midPoint chose them) | Decision | Result |
|---|---|---|---|---|
| marcus.bello | ICU Nurse | grace.mwangi (org manager) | accept | kept |
| marcus.bello | **Pharmacist** | grace.mwangi | **revoke**: SoD conflict with Nurse, flagged by midPoint before the review | removed |
| dana.okafor | ICU Nurse | grace.mwangi | **none** (left unanswered on purpose) | removed: T2 rule |
| sofia.reyes | ICU Nurse | grace.mwangi | accept | kept |
| grace.mwangi | ICU Nurse | helen.carter (manager's manager: a manager never reviews herself) | accept | kept |
| daniel.osei | **AP Clerk** | helen.carter | **revoke**: stale temporary cover | removed |
| helen.carter | ICU Nurse | access-governance-lead (no manager, so the fallback) | accept | kept |

These are out of scope on purpose, and the test proves each one:

- **Birthright `Nurse`** is T3 (`requestable=false`). HR data certifies it, not a
  reviewer.
- **priya.nair** is a leaver whose account is disabled. The HR leaver path removes
  her access, not a review.
- **midPoint's own `Reviewer` role** is a system role, not business access.

**Detective SoD.** The Pharmacist role carries a `record`-only exclusion rule
against Nurse, using the built-in "Exclusion violation" mark (the 4.10
segregation-of-duties pattern). The conflicting assignments are flagged before
the review, nothing is blocked, and the mark is gone once remediation removes
Pharmacist.

## How the lifecycle is driven (all REST, as `administrator`)

| Step | Call | midPoint mechanism |
|---|---|---|
| Dataset | `PUT /ws/rest/{orgs,roles,users}/{oid}` | create or replace. Every run resets the users to this baseline |
| Definition | `PUT /ws/rest/accessCertificationDefinitions/{oid}` + `PATCH` | `lastCampaignIdUsed` is kept, so campaign names never collide |
| Create + open stage 1 | `PUT /ws/rest/tasks/{oid}` (`tasks/1-create-campaign.xml`) | campaign-creation task handler. On 4.10.4 it also opened stage 1 in the same run |
| Decisions | `POST /ws/rest/rpc/executeScript` (`record-decisions.groovy`) | `AccessCertificationService.recordDecision`, in each assigned reviewer's security context |
| Close stage | `PUT /ws/rest/tasks/{oid}` (`tasks/2-close-stage.xml`) | activity `certificationCloseCurrentStage` |
| Remediation + close | `PUT /ws/rest/tasks/{oid}` (`tasks/3-remediation.xml`) | activity `certificationRemediation`, which closes the campaign |

**How decisions are recorded.** midPoint 4.10's REST API has no endpoint for
certification decisions. The campaign endpoint documents get, search, modify and
delete only
([REST docs](https://docs.evolveum.com/midpoint/reference/support-4.10/interfaces/rest/endpoints/access-certification-campaign-type/)).
The GUI's decision buttons call `AccessCertificationService.recordDecision`
(checked in `admin-gui-4.10.4.jar`), and `record-decisions.groovy` makes that
same call. For each decision it switches to the reviewer midPoint assigned
(`SecurityContextManager.runAsChecked`), so midPoint applies **that reviewer's**
authorizations and stores them as `performerRef`.

It is still a script standing in for the reviewer's click. No reviewer signs
in. Two probes show the gate is midPoint's own, not the script's:

- a user without the Reviewer role is refused (`not authorized ... #completeWorkItem`)
- a reviewer who isn't the assignee is refused the same way

## Run it

```bash
cd lab/pam
./pam-up.sh                           # or: docker compose up -d midpoint (midPoint alone)
midpoint/run-campaign.sh              # -> lab/evidence/midpoint/<UTC timestamp>/
test/e2e-midpoint.sh                  # two runs into out/e2e/midpoint/ (gitignored) + assertions
test/e2e-midpoint.sh --verify ../evidence/midpoint/<ts>   # re-check a hashed run record offline
```

Each run is idempotent. It resets the dataset and opens a new campaign named
`<name> N+1`. Earlier campaigns stay closed in midPoint as history. A run stages
its output in `out/midpoint/<ts>/`, raw API responses included, and copies it to
the evidence folder only when every step passed.

## Evidence files

| File | Content |
|---|---|
| `summary.json` | counts, routing, remediation, probes, ADR 0012 KPIs |
| `campaign.json` | the closed campaign as midPoint returns it, including cases and work items: reviewer, performer, decision, comment, timestamps, `remediedTimestamp` |
| `decisions.csv` | one row per work item, flattened from `campaign.json` |
| `decisions-run.json` | what `record-decisions.groovy` reported, probes included |
| `users-before.json` / `users-after.json` | the 8 users before the review (SoD marks) and after remediation |
| `definition.json`, `tasks.json` | the definition, and a projection of the 3 lifecycle tasks |
| `guids.txt` | every GUID in the folder and what it is |
| `run.log`, `SHA256SUMS` | the run's console output and the hash of every file |

## Limits (say these on camera)

- **Not Entra data.** The identities are object files, not aggregated from Entra.
- **Scripted reviewers.** Decisions land milliseconds apart, so their timing
  says nothing about a human. The rubber-stamp KPI now uses the same
  definition and thresholds as `../../scripts/powershell/10-Review-KPIs.ps1`
  (read from `../../iga/access-catalog.json` `reviewTiers.rubberStamp`): only
  reviewers with at least 10 items are eligible, for both clauses. No reviewer
  here has 10 items, so a new run reports the rate as **not measured**.
- **Two evidence runs, two rubber-stamp rules.** The first folder
  (`20261020T152623Z`) predates that alignment: its `summary.json` has
  `rubber_stamp_flagged: [helen.carter, grace.mwangi]`, computed with the
  median rule and no item minimum. It is kept unedited as the genuine output
  of that run, and `../test/e2e-midpoint.sh --verify` accepts it as
  pre-alignment evidence. The second folder (`20261020T162116Z`) uses the
  current rule and reports the rate as `not-measured`. Quote the second one.
- **Stage closed early.** The driver closes stage 1 at once, not at the 14-day
  deadline. No mail transport is configured, so the `notifyBeforeDeadline`
  reminder is never sent.
- **Administrator as the driver.** The driver authenticates as `administrator`
  and runs Groovy through `rpc/executeScript`. Production would use a scoped
  service account and restrict script execution through expression profiles.
- verify: the campaign-creation handler opening stage 1 by itself was
  observed on 4.10.4 but isn't stated on the "Automated campaign scheduling"
  page. Re-check after a midPoint upgrade (the run fails loudly if the state
  isn't `inReviewStage`).
