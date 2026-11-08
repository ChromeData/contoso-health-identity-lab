# ADR 0006: API-driven inbound provisioning vs. the Workday connector

- **Status:** Accepted (lab). Production recommendation below. Partly superseded by [ADR 0027](0027-hr-form-as-the-hr-system.md): HR now makes changes in the Contoso HR form, not by editing `hr_feed.csv`.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

HR is the source of truth for joiner, mover and leaver. The lab's design is
HR → AD (department OU) → Cloud Sync → Entra, and everything downstream
(Lifecycle Workflows, access packages, Conditional Access, PIM) keys off the
worker attributes that path writes.

The scenario's HR system would be Workday or SAP SuccessFactors. Neither has a
sandbox an individual can get, so the lab needs a source it can actually run.
Entra offers two inbound routes into the same provisioning service:

- **Native HR connectors** (Workday, SuccessFactors). The provisioning service
  *pulls* from the HRIS API on a schedule.
- **API-driven inbound provisioning.** Any source *pushes* SCIM payloads to
  `/servicePrincipals/{id}/synchronization/jobs/{jobId}/bulkUpload`.

A hospital also has workers who are not in the HRIS: agency nurses,
affiliated physicians credentialed by the medical staff office, and, in this
scenario, an acquired clinic's staff until its HR is consolidated.

## Options considered

1. **Native Workday connector only.** Pull model, Microsoft-maintained
   connector, scoping filters, and write-back of email/phone to Workday
   (verify: current write-back attributes). Covers HRIS workers only. Can't
   be demonstrated without a Workday tenant.
2. **API-driven inbound only.** One push endpoint for every source. Whoever
   owns the integration also owns the extract, the schedule, batching (50
   records per call), and checking outcomes, because the POST returns 202
   and results only show up in the provisioning logs.
3. **Native connector for the HRIS, API-driven for everything else.** Two
   integration patterns feeding one provisioning service and one attribute
   contract.
4. **Custom scripts writing directly to AD/Entra (Graph or LDAP).** No
   provisioning service, no provisioning logs, no quarantine handling.
   Rejected.

## Decision

- **Lab:** option 2. `hr_feed.csv` plus `Invoke-InboundProvisioning.ps1`
  push SCIM Enterprise User records to the API-driven *to on-premises AD*
  app. This is the stand-in for Workday (row 1 of `STAND-INS.md`). Only the
  source is substituted. The endpoint, the provisioning service, the AD OU
  placement and the Cloud Sync path are the real products.
- **Production recommendation (scenario):** option 3. Use the native Workday
  (or SuccessFactors) connector for employees. Use API-driven provisioning
  for sources with no gallery connector: agency staff, medical staff office
  credentialing, and the acquired clinic's HR until it moves into Workday.
  Every source maps to the same attribute contract (`employeeId` as anchor,
  `department`, `jobTitle`, `manager`, start and end dates), so the
  downstream automation doesn't care which route a worker came in on.

## Consequences

**Positive**
- The whole JML story runs end to end without a paid HR sandbox, against
  real Entra provisioning.
- Movers are found by diffing the feed against the directory, not by a
  status flag. A mover is an `active` row whose department changed, which
  is what an HRIS extract really looks like.
- Re-runs are safe. Records upsert on `externalId == employeeId`, and
  leavers are sent with `active:false`.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| The push caller is a powerful non-human identity. The app-only `SynchronizationData-User.Upload` permission reaches every API-driven job in the tenant. | Prefer `SynchronizationData-User.Upload.OwnedBy` where the ownership model allows it (verify: whether making the caller an owner of an admin-created app is enough). Use a credential with no client secret (certificate or federated credential). Give the caller a named owner and an expiry review. |
| A silent partial failure: the 202 hides per-record errors. | Read `GET /auditLogs/provisioning` or the Provisioning logs blade after every run. In production, alert on provisioning failures in the SIEM. |
| A source pushes a bad batch, such as mass leavers. | Entra's accidental-deletions threshold on the provisioning job (verify: availability for the API-driven to-AD app). Rehearse with `-WhatIf` (the script prints the payloads and sends nothing). Keep the 50-record chunking. |
| Two routes drift apart in their attribute mappings. | One documented attribute contract, and a mapping change goes through review like any other identity change. |
| The lab's interactive run uses a delegated scope plus the User Administrator role. | Lab only. The production caller is app-only with no human role. |

**Not proven yet:** no tenant run has been captured. Fill in after running:
the provisioning-log entry for a joiner, and the minutes from HR row to
enabled account.

## Revisit trigger

- The scenario gets a real HRIS tenant. Switch employees to the native
  connector and keep API-driven provisioning for the other sources.
- Microsoft changes licensing or limits for API-driven provisioning (the lab
  README says P1/P2; verify: current licensing page).
- A new worker population has no HRIS record (for example a research
  partner). Add it as another API-driven source; don't create those
  accounts by hand.

## Evidence

- `lab/scripts/mock-hr/README.md`: endpoint, permissions, limits, mover and
  hybrid-ownership notes
- `lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1`,
  `lab/scripts/mock-hr/hr_feed.csv`
- `lab/scripts/dc/README.md`: provisioning agent, OU-placement expression,
  Cloud Sync scope
- `lab/scripts/powershell/02-Joiner.ps1`, `03-Mover.ps1`, `04-Leaver.ps1`
- `lab/docs/STAND-INS.md`: row 1
