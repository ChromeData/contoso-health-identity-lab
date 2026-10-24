# ADR 0012: Risk-tiered certification, reviewer non-response and clinical lockout

- **Status:** Accepted (lab). BUILT: a tier and an assignment model on every package, one review flag per tier, the T3 automatic assignment script and the review KPIs, with mocked tests; never applied. Not built: the T3 drift report and its exception review. RAN · harness: a T2 campaign in the midPoint stand-in (ADR 0008).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Every certification has to say who decides, and what happens when they
don't. One answer for the whole tenant fails both ways:

- **Unanswered = removed.** Applied to clinical access, a manager on leave
  becomes a nurse locked out of the EHR at shift start. That is a
  patient-safety event.
- **Unanswered = kept.** Applied to admin access, certification becomes
  optional where it matters most.
- **Volume.** About 3,500 clinical users reviewed quarterly is about 14,000
  decisions a year, nearly all "still a nurse on my unit", which HR already
  knows. Volume like that produces rubber-stamping.

Reviews are not the leaver control: terminated users are removed by the HR
leaver path (60-minute target). Reviews catch people who are still employed
but no longer need the access.

## Options considered

1. **One policy: quarterly, manager reviews, unanswered = removed.** The
   module default. Rejected for the lockout risk and the volume.
2. **One policy: unanswered = kept.** Rejected: privileged certification
   becomes optional.
3. **One policy: take the recommendation** (`acceptAccessRecommendation`).
   Rejected as a default: it denies anyone with no sign-in for 30 days, so a
   nurse back from leave loses her apps on her first shift.
4. **Risk tiers, each with its own non-response rule (chosen).** If HR
   attributes can say who needs access, HR certifies it. If a person
   approved it, a person re-certifies it.

## Decision

| | T1 Privileged | T2 Requestable | T3 Birthright clinical |
|---|---|---|---|
| Scope | Eligible and active members of PIM-governed groups | Access someone requests and an approver grants: `Pharmacy - Controlled Substances Apps`, ICU float access | Core access by department and job: `Nurse - Clinical Apps`, ICU apps for ICU staff, `All-<Dept>` |
| Cadence | Quarterly, 14-day instance | Every 180 days | Every HR change, plus a monthly drift report |
| Reviewer | A governance group (never the admins themselves), plus a mandatory fallback | Requestor's manager, plus a fallback group | The HR record. Exceptions go to the manager, then the access governance lead |
| No response | **Removed**, applied automatically | **Removed** | **Kept**, escalated, time-boxed |
| Way back in | Re-request eligibility ([pim-activation-support.md](../runbooks/pim-activation-support.md)) | Re-request the package | Not needed |

**T1** is a standalone review definition (`reviews.tf`): default decision
`Deny`, auto-apply on, 30-day recommendations, justification required,
14-day instance. Microsoft warns that auto-apply plus a default decision
revokes everything nobody answered; that is the intent, and why the
fallback reviewer is mandatory. `Break-Glass-Admins` is never in scope: a
default-deny review would remove the recovery path. The 90-day drill checks
it instead.

**T2** is certified by the 180-day assignment expiry: the person
re-requests and the approver re-approves; an unapproved request times out
after 14 days. A package that lives longer than 180 days or allows
extension gets a half-yearly policy review instead, with
`expirationBehavior = removeAccess`, recommendations on, justification
required and no self-review.

**T3** has no human campaign.

- **Granted by an automatic assignment policy** from HR attributes
  (`department` and `jobTitle` today; an HR job code is the target, because
  titles are free text), never before `employeeHireDate`.
- **No expiry.** Someone who moves out of scope keeps access for a 72-hour
  grace period, so a mover isn't cut off mid-shift.
- **No `memberOf` in any rule:** Microsoft quarantines automatic assignment
  policies that use it from 2026-11-03.
- **Drift report:** holders with no HR record, on leave over 30 days, or with
  no sign-in for 90 days. Each finding goes to the manager (5 business days),
  then the governance lead (5 business days), then to Clinical Operations as
  a governance finding. If it ever runs as an Entra review, it is
  multi-stage with no default decision.
- **Removal goes through HR.** A confirmed removal is made by fixing the HR
  record; the policy re-adds anyone whose attribute still matches.

**What a reviewer sees:** one row per person with the last sign-in and the
30-day recommendation, a mandatory justification, a halfway reminder, and
never their own access. The T1 prompt reads: "Can this person still justify
being able to activate this admin role? If you are unsure, deny: they can
re-request eligibility."

## How it is measured

`10-Review-KPIs.ps1` computes these per tier and per reviewer from the
review decisions that `Export-EvidencePack.ps1` exports. Tested offline
against a synthetic fixture only. Fill in after the first cycle.

| KPI | Definition | Target |
|---|---|---|
| Completion | Decisions made by a person ÷ items in scope. A service-applied default doesn't count, or "unanswered = removed" would read as 100%; defaults are reported separately | T1 100%, T2 ≥ 95% |
| Revocation rate | `Deny` ÷ reviewed items | Watched, not targeted |
| Rubber-stamp rate | Among reviewers with ≥ 10 items: those who approved everything, or whose median gap between decisions is under 5 seconds (thresholds in `lab/iga/access-catalog.json`) | < 10% |
| Approve against recommendation | `Approve` where the recommendation was `Deny` | Reported; each needs a justification |
| Clinical lockouts caused by governance | Still-employed clinicians who lost a birthright package through a review or an expiry | 0 |

The midPoint stand-in campaign computes the same KPIs for its seven items
(completion 85.7%, below the 95% T2 target by design; revocation 33.3%;
rubber-stamp rate not measurable, no reviewer had 10 items). Its decisions
were scripted, so they say nothing about how reviewers behave.

## Consequences

- **Clinical availability no longer depends on reviewer diligence.** The
  price: T3 trusts HR data with no human checking each grant (R10).
- **Fewer, sharper decisions:** reviewer time goes to privilege and to
  discretionary access.
- **Built as code:** each package carries `tier` and `assignment`; T3
  packages get no request policy, so no expiry and no day-180 lockout, and
  a birthright package with a request policy is refused at plan. The review
  flags are independent (`enable_access_reviews_privileged`, `_requestable`,
  `_inactive`); mocked tests assert the T1 flag never reviews a clinical
  package.
- **HR start date has to reach `employeeHireDate`** (provisioning, then
  Cloud Sync) before birthright goes live; the script refuses to run while
  no in-scope user has a hire date, and refuses any rule that reaches
  privileged access.

## Revisit trigger

- A clinical lockout traced to a review or an expiry.
- The rubber-stamp rate stays above 10% for two cycles.
- An auditor rejects HR-attribute validation as certification for
  birthright access.

## Evidence

- `lab/terraform/modules/entitlement/` (`main.tf`, `variables.tf`,
  `reviews.tf`, `tests/governance.tftest.hcl`)
- `lab/iga/birthright-rules.json`, `access-catalog.json`
- `lab/scripts/powershell/post-apply/Set-AutoAssignmentPolicies.ps1`,
  `10-Review-KPIs.ps1`, `Export-EvidencePack.ps1`
- `lab/scripts/mock-hr/hr_feed.csv` (`startDate` → `employeeHireDate`)
- `lab/evidence/midpoint/20261020T162116Z/` (the T2 stand-in campaign)

## Sources (Microsoft Learn)

- https://learn.microsoft.com/en-us/graph/api/resources/accessreviewschedulesettings
  (setting names, `Deny` default, auto-apply warning; checked 2026-10-20)
- https://learn.microsoft.com/en-us/graph/api/resources/accesspackageassignmentreviewsettings
  (`expirationBehavior`; checked 2026-10-20)
- https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-auto-assignment-policy
  (grace period; `memberOf` policies quarantined from 2026-11-03; checked
  2026-10-21)
- https://learn.microsoft.com/en-us/entra/id-governance/create-access-review
  (non-response options, multi-stage reviews; checked 2026-10-20)
