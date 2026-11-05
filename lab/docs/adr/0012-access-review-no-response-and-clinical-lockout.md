# ADR 0012: Risk-tiered certification, reviewer non-response and clinical lockout

- **Status:** Accepted (lab). RAN · tenant: the T1 privileged review series since 2026-10-28 (capture-log E53); from 2026-11-05 all three tier flags are on in `lab.tfvars` - the inactive-user review of the clinic's Okta-federated staff is created by the post-apply step (E110), and the two T2 packages stay certified by their 180-day expiry and manager re-approval, so no T2 campaign is rendered for them (by design, below). The T3 automatic assignment script is built and run; the T3 drift report and exception review are not (see Consequences). A T2 campaign ran in the midPoint stand-in (ADR 0008).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Every certification has to say who decides, and what happens when they
don't. One answer for the whole tenant fails both ways:

- **Unanswered = removed.** Applied to clinical access, a manager on leave
  becomes a nurse locked out of the EHR at shift start. That is a
  patient-safety event (`standards/conditional-access-design-principles.md`
  §1).
- **Unanswered = kept.** Applied to admin access, certification becomes
  optional where it matters most.
- **Volume.** Assume about 3,500 clinical users. A quarterly review of
  their core bundle is about 14,000 decisions a year, nearly all of them
  "still a nurse on my unit", which HR already knows. Volume like that
  produces rubber-stamping.

**What the code did when this was decided.** One switch,
`enable_access_reviews`, did two things at once:

- It put the same review on every package policy: quarterly, the manager
  reviews, and an unanswered review means `removeAccess`.
- It rendered the privileged and inactive-user reviews.

What is built since is under Consequences.

**Where birthright access lives.** Birthright access is the dynamic
`All-<Dept>` groups. A review can't remove a dynamic-group member.

**What reviews are for.** Terminated users are removed by the HR leaver
path, which has a 60-minute target. Reviews catch people who are still
employed but no longer need the access.

## Options considered

1. **One policy: quarterly, the manager reviews, unanswered = removed.**
   This is the module default. Rejected for the lockout risk and the volume
   above.
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
| Scope | Eligible and active members of PIM-governed groups | Access someone requests and an approver grants: `Pharmacy - Controlled Substances Apps`, ICU apps for float and agency staff | Core access by department and job: `Nurse - Clinical Apps`, ICU apps for ICU staff, `All-<Dept>` |
| Cadence | Quarterly, 14-day instance | Every 180 days | Every HR change, plus a monthly drift report |
| Reviewer | Governance group (never the admins themselves), plus a mandatory fallback | Requestor's manager, plus a fallback group | HR record. Exceptions go to the manager, then the access governance lead |
| No response | **Removed**, applied automatically | **Removed** | **Kept**, escalated, time-boxed |
| Way back in | Re-request eligibility ([pim-activation-support.md](../runbooks/pim-activation-support.md)) | Re-request the package in My Access | Not needed |

**T1** is a standalone review definition, rendered in `reviews.tf`:

- `defaultDecisionEnabled = true`, `defaultDecision = "Deny"`
- `autoApplyDecisionsEnabled = true`
- `recommendationsEnabled = true`, `recommendationLookBackDuration = "P30D"`
- `justificationRequiredOnApproval = true`
- `instanceDurationInDays = 14`

Microsoft warns that auto-apply plus a default decision revokes everything
nobody answered. That is the intent here, and it is why the fallback
reviewer is mandatory. `Break-Glass-Admins` is never in scope: a
default-deny review would remove the recovery path. The 90-day drill checks
it instead.

**T2** is certified by the 180-day assignment expiry. The person
re-requests, the approver re-approves, and a request nobody approves times
out after 14 days. A review campaign on a 180-day package would ask the
same question twice, so none runs.

A package that lives longer than 180 days, or that allows self-extension,
gets a policy review instead:

- `halfyearly`
- `expirationBehavior = removeAccess` (the provider calls it
  `access_review_timeout_behavior`)
- `isRecommendationEnabled = true`
- `isReviewerJustificationRequired = true`
- no self-review

**T3** has no human campaign.

- **How access is granted.** An entitlement-management automatic assignment
  policy assigns the package from HR attributes. That's `department` and
  `jobTitle` today; the target is an HR job code, because titles are free
  text.
- **No expiry.** When someone moves out of scope, a 72-hour grace period
  means a mover isn't cut off mid-shift.
- **No `memberOf`.** Rules never use it, because Microsoft quarantines
  `memberOf` rules from 2026-11-03.
- **Drift report.** It lists holders with no HR record, on leave longer than
  30 days, or with no sign-in for 90 days. Each finding goes to the manager
  (5 business days), then to the governance lead (5 business days). A
  finding still open after 10 business days is reported to Clinical
  Operations as a governance finding.
- **If the drift queue runs as an Entra review:** it is multi-stage with
  `defaultDecisionEnabled = false` ("No change").
- **Removal goes through HR.** A confirmed removal is made by fixing the HR
  record. The automatic policy re-adds anyone whose attribute still
  matches.

**What a reviewer sees:**

- one row per person, with the last sign-in date and the 30-day
  recommendation
- a mandatory justification box
- a reminder at the halfway point
- never their own access

The T1 prompt reads: "Can this person still justify being able to activate
this admin role? If you are unsure, deny: they can re-request eligibility."

## How it is measured

`10-Review-KPIs.ps1` computes these per tier and per reviewer from the
review decisions (fields `decision`, `recommendation`, `reviewedBy`,
`reviewedDateTime`), the same data `Export-EvidencePack.ps1` exports as
`access_review_decisions.json`. It is tested offline against a synthetic
fixture only. Fill this in after the first cycle.

| KPI | Definition | Target |
|---|---|---|
| Completion | Decisions made by a person ÷ items in scope, per tier. A default the service applied doesn't count, or "unanswered = removed" would read as 100%. Same rule in `08-Measure-KPIs.ps1` (`access_review_completion_pct`); service-applied defaults are reported separately | T1 100%, T2 ≥ 95% |
| Revocation rate | `Deny` ÷ reviewed items, per tier and per reviewer | Watched, not targeted |
| Rubber-stamp rate | Among reviewers with ≥ 10 items (the minimum applies to both clauses): those who approved them all, or whose median gap between decisions is under 5 seconds. The thresholds live in `lab/iga/access-catalog.json` (`reviewTiers.rubberStamp`), read by both `10-Review-KPIs.ps1` and `lab/pam/midpoint/run-campaign.sh` | < 10% |
| Approve against recommendation | `Approve` where `recommendation = Deny` ÷ items recommended `Deny` | Reported. Each needs a justification |
| Clinical lockouts caused by governance | Still-employed clinicians who lost a birthright package through a review (in any tier) or an expiry, and don't hold it another way | 0 |

The midPoint stand-in campaign (ADR 0008) computes the same KPIs for its
seven items: six scripted decisions and one left unanswered on purpose
(`lab/evidence/midpoint/`). Scripted decisions say nothing about how
reviewers behave, so they don't fill this table.

## Consequences

- **Clinical availability no longer depends on reviewer diligence.** The
  price is that T3 trusts HR data, with no human checking each grant (R10).
- **Fewer, sharper decisions.** Reviewer time goes to privilege and to
  discretionary access.
- **Built since (code with mocked tests; never applied):**
  - **A tier and an assignment model on every package.** Each entry in
    `access_packages` (`modules/entitlement`) carries `tier` and
    `assignment`. `Nurse - Clinical Apps` and `ICU - Critical Care Apps` are
    T3 and automatic: Terraform creates no request policy for them, so they
    have no expiry and no review, and the day-180 lockout is gone. Float and
    agency staff request `ICU - Float Access` (T2), a separate package so
    that SoD links can sit on the requestable side. A birthright package
    with a request policy is refused at plan.
  - **One flag per tier, independent.** `enable_access_reviews_privileged`
    (T1 package reviews plus the standalone privileged reviews in
    `reviews.tf`), `enable_access_reviews_requestable` (the half-yearly
    policy review, only on a T2 package that lives longer than 180 days or
    allows extension) and `enable_access_reviews_inactive`. T3 has no flag.
    The old single `enable_access_reviews` survives only as a deprecated
    alias that spares birthright packages. Mocked tests in
    `governance.tftest.hcl` assert that the T1 flag never reviews a
    clinical package.
  - **The T3 automatic assignment policy.** `Set-AutoAssignmentPolicies.ps1`
    builds one policy per birthright package from
    `lab/iga/birthright-rules.json`, with the 72-hour grace period. Its rules
    also require `employeeHireDate` on or before today, so nobody gets
    clinical access before day one. The mock HR feed sends `startDate` as
    `hireDate` in a custom SCIM extension (`Invoke-InboundProvisioning.ps1`).
    The two mappings into `employeeHireDate` (provisioning →
    `msDS-cloudExtensionAttribute1`, then Cloud Sync) are tenant-time steps
    (verify: on the first run). The script refuses to run while no in-scope
    user has a hire date. It refuses to hand out privileged access by
    attribute.
    azuread 3.10's `azuread_access_package_assignment_policy` has no
    automatic-assignment settings (checked against the provider schema), so
    this Graph post-apply script is the path.
  - **The KPIs:** `10-Review-KPIs.ps1` (above).
- **Not built yet:** the rest of T3, the drift report and the exception
  review.
- `standards/iam-standard.md` §4 and the roadmap's Phase 3 row point here.
- verify: whether package-policy reviews appear in the review definitions
  that the evidence pack reads.

## Revisit trigger

- A clinical lockout traced to a review or an expiry.
- The rubber-stamp rate stays above 10% for two cycles.
- An auditor rejects HR-attribute validation as certification for
  birthright access.

## Evidence

- `lab/terraform/modules/entitlement/main.tf`: the review block, the
  180-day expiry and the 14-day approval timeout
- `lab/terraform/modules/entitlement/variables.tf`
- `lab/terraform/modules/entitlement/reviews.tf`
- `lab/terraform/modules/entitlement/tests/governance.tftest.hcl`
- `lab/terraform/modules/groups/main.tf`: dynamic birthright groups
- `lab/iga/birthright-rules.json`, `lab/iga/access-catalog.json`
- `lab/scripts/powershell/post-apply/Set-AutoAssignmentPolicies.ps1`
- `lab/scripts/powershell/10-Review-KPIs.ps1`
- `lab/scripts/mock-hr/hr_feed.csv`: `dept`, `jobTitle`, `status`,
  `startDate` (→ `employeeHireDate`)
- `lab/scripts/powershell/Export-EvidencePack.ps1`
- `lab/pam/midpoint/README.md`: the T2 stand-in campaign

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/graph/api/resources/accessreviewschedulesettings
  (setting names, `Deny` default, auto-apply warning)
- https://learn.microsoft.com/en-us/graph/api/resources/accesspackageassignmentreviewsettings
  (`expirationBehavior`)
- https://learn.microsoft.com/en-us/graph/api/resources/accessreviewinstancedecisionitem
  (decision fields)
- https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-auto-assignment-policy
  (grace period, `memberOf` quarantine)
- https://learn.microsoft.com/en-us/entra/id-governance/create-access-review
  ("If reviewers don't respond" options, multi-stage reviews)
