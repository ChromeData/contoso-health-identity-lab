# ADR 0034: Contractors and agency staff

- **Status:** DESIGNED. The HR feed has no worker type or sponsor today. The HR form (lab/hr-app, another change) owns the feed; this record says what it needs.
- **Date:** 2026-11-07
- **Risk owner:** Identity platform owner, with HR and Nursing Operations
- **Next review:** 2027-02-07
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

- Hospitals depend on agency nurses, travelling nurses, locum doctors and
  IT contractors. They come and go often, and an agency may not tell the
  hospital when a person stops working.
- `standards/iam-standard.md` lists "employee, contractor" under HR. The
  feed cannot tell them apart. A contractor who leaves without an HR
  leaver row keeps an enabled account.
- B2B physicians (`modules/entitlement/b2b.tf`) are code only.

## Options considered

1. **Treat contractors as employees.** Rejected: no end date, no sponsor.
2. **Make every contractor a B2B guest.** Rejected for agency clinicians:
   they need an AD account and the shared clinical stations (ADR 0014).
   Kept for visiting physicians who have their own organisation's account.
3. **Member accounts with a worker type, an end date and a sponsor
   (chosen).**

## Decision

1. **Two new HR attributes:**
   - `workerType`: `Employee`, `Contractor`, `Agency` or `Locum`.
   - `sponsor`: the employee number of a hospital manager who vouches for
     the person.
   Both go to AD and Entra (for example `employeeType` and an extension
   attribute). The sponsor is mandatory for every worker type except
   `Employee`.
2. **A mandatory end date.** For non-employees the HR system refuses a row
   with no end date, or an end date more than **90 days** away. Extending
   it needs the sponsor.
3. **Automatic leaver on the end date.** A Lifecycle Workflow "leaver" task
   runs on `employeeLeaveDateTime`, whether or not a leaver row arrives.
4. **Sponsor re-attestation.** Every 30 days an access review asks the
   sponsor: "Does this person still work here?" No answer means the
   account is disabled, not deleted (the clinic can re-enable it in
   minutes).
5. **Conditional Access CA063:** users with a non-employee worker type
   cannot be PIM-eligible or hold any admin role. A dynamic group on
   `employeeType` feeds the policy and a PIM eligibility check.
6. **Birthright access** is the same job-based access (ADR 0012, T3), but
   requestable packages such as `ICU - Float Access` (T2) expire at the
   worker's end date at the latest.

## Consequences

- HR or the agency coordinator must enter end dates and sponsors. Rows
  without them are refused, so the first weeks will need help.
- A sponsor who leaves leaves their contractors without a sponsor. The
  leaver flow re-assigns them to the sponsor's manager.

## Revisit trigger

- More than 5% of non-employee accounts are disabled by re-attestation
  while the person is still working (the review is too strict).
- The hospital uses a vendor-management system (VMS) as a second HR source.
