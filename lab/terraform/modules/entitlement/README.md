# modules/entitlement

Entra ID Governance for Contoso Health: who may **request** access, who
**approves** it, when it **expires**, and who **re-certifies** it. Decisions:
[ADR 0008](../../../docs/adr/0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md)
and [ADR 0012](../../../docs/adr/0012-access-review-no-response-and-clinical-lockout.md)
(risk-tiered certification; birthright clinical access is never removed on
silence).

**Status: BUILT.** `validate` and 26 mocked `terraform test` runs pass
(HashiCorp Terraform 1.16.5, 2026-10-20). **Nothing has been applied: no
tenant exists yet.** Every step marked **TENANT-TIME** needs the Entra ID
Governance trial, and every claim marked *verify:* is checked during that
window.

| File | Flag in `envs/dev` (default) | What it builds |
|------|------------------------------|----------------|
| `main.tf` | `enable_governance` (false) | Internal catalog "Clinical" and the packages in `var.access_packages`, matching `lab/iga/access-catalog.json`: **T3 birthright** "Nurse - Clinical Apps" and "ICU - Critical Care Apps" (no Terraform policy: their only policy is the HR-attribute automatic assignment that `post-apply/Set-AutoAssignmentPolicies.ps1` creates), **T2 requestable** "ICU - Float Access" and "Pharmacy - Controlled Substances Apps" (approval, justification, 180-day expiry) |
| `main.tf` | `enable_access_reviews_privileged` (false) | ADR 0012 **T1**: a quarterly policy review on any T1 package, governance group reviews, unanswered = removed |
| `main.tf` | `enable_access_reviews_requestable` (false) | ADR 0012 **T2**: a half-yearly `removeAccess` policy review, **only** on a requestable package that lives longer than 180 days or allows extension (a plain 180-day package is certified by its expiry and re-approval) |
| — | (no flag) | ADR 0012 **T3**: a birthright clinical package is never reviewed by a person. HR attributes certify it, so a silent reviewer can never lock a nurse out |
| `reviews.tf` | `enable_access_reviews_privileged` / `enable_access_reviews_inactive` (false) | **Rendered only** (output `access_review_definitions`): the quarterly **privileged** reviews (eligible + active members of every PIM-governed group, merged with `modules/pim`'s bodies) and the **inactive-user** review, created by `post-apply/New-AccessReviewDefinitions.ps1` |
| `b2b.tf` | `enable_b2b_governance` (false) | Externally visible catalog "Affiliated Partners" and the **"Affiliated Physicians"** package: connected-org requestors, sponsor approval, 90-day expiry, monthly sponsor review |

`enable_access_reviews` is kept only as a deprecated alias for the three
tier flags; it still never reviews a birthright package.

## Design decisions

- **Deny by default.** Every review this module defines removes access
  nobody vouches for: `removeAccess` on the package policies, and
  `defaultDecision = Deny` with `autoApplyDecisionsEnabled = true` on the
  standalone reviews. The fallback reviewer group is mandatory, and a
  precondition fails the plan or apply without it. A review with no one able
  to answer would otherwise revoke everything.
- **Privileged access is reviewed by a governance group**, never by the
  admins themselves. The output precondition rejects a reviewer group that
  is also a reviewed group. The reviewers are not the group owners either:
  PIM-for-Groups reviews resolve only *active* owners, and these groups have
  none at rest.
- **The inactive-user review targets groups that no access package owns**
  (default wiring: `App-Okta-Federation-Users`). If a review removes a member
  from a package-granted group, entitlement management is bypassed and the
  package assignment is left orphaned. Package groups are already covered by
  the policy review's sign-in recommendation (deny if no sign-in for 30 days).
- **Only one catalog is externally visible.** Clinical packages, including
  controlled-substance dispensing, can never be requested by a guest, and
  "enabled for external users" is decided in one place.
- **No hand-made guest invitations.** Guests arrive only through a request
  from a *configured* connected organization, never a `proposed` one (the
  service auto-creates those when a stranger requests a package). A guest is
  approved by a sponsor, holds access for at most 90 days, and is reviewed
  monthly. With the lifecycle setting below, the guest is blocked and then
  deleted when their last assignment ends.

## Day one: which mechanism delivers the birthright package (measured 2026-11-07)

The joiner Lifecycle Workflow, not the automatic assignment policy. In the
first HR-form hire (capture log E121, E121b) the user joined the policy's
dynamic group at +4:36, the policy had created no assignment by +25 min, and
the workflow's request task assigned the package at 01:11:01Z (audit,
initiated by Lifecycle Workflows). The workflow runs on the tenant's 3-hour
schedule, so day-one delivery takes up to about 3 hours. The automatic
policy keeps access in line with HR attributes afterwards (movers, and
removal after its 3-day grace). Details: `lab/scripts/mock-hr/README.md`,
"Three gaps from the first HR-form run".

## Provider gaps, and how they are closed

The azuread provider 3.10 schema was checked on 2026-10-20 and has **no**
resource for:

| Graph object | Closed by |
|--------------|-----------|
| `incompatibleAccessPackages` / `incompatibleGroups` (SoD) | `lab/iga/sod-rules.json` → `post-apply/Set-IncompatibleAccessPackages.ps1` (links only on requestable packages; `Set-AccessPackageSoD.ps1` is now a forwarding shim) |
| automatic assignment policy (birthright) | `lab/iga/birthright-rules.json` → `post-apply/Set-AutoAssignmentPolicies.ps1` |
| `accessReviewScheduleDefinition` (standalone reviews) | output `access_review_definitions` → **`post-apply/New-AccessReviewDefinitions.ps1`** (spec below) |
| `connectedOrganization` + its sponsors | output `b2b_post_apply` → **`post-apply/New-B2BConnectedOrganization.ps1`** (spec below) |
| `entitlementManagementSettings` (external-user lifecycle) | output `b2b_post_apply.entitlement_settings_body` → same script |

Terraform renders the exact request bodies from real object ids, so the
definition stays code-reviewed here and only the HTTP call happens outside
Terraform.

## Post-apply scripts (BUILT, Pester-tested with Graph mocked)

Both follow the house style of `post-apply/Set-PimGroupEligibility.ps1`
(`SupportsShouldProcess`, a required-scopes check, `[+]` / `[=]` output,
`exit 1` on any failure) and are run in order by
`post-apply/Invoke-PostApply.ps1` (steps 12 and 13).

| | `New-AccessReviewDefinitions.ps1` | `New-B2BConnectedOrganization.ps1` |
|---|---|---|
| Input | `-DefinitionsPath`: `terraform -chdir=lab/terraform/envs/dev output -json access_review_definitions > reviews.json` (a map of key → JSON string) | `-PostApplyPath`: `terraform output -json b2b_post_apply` |
| Scopes | `AccessReview.ReadWrite.All`, `Group.Read.All`, `PrivilegedEligibilitySchedule.Read.AzureADGroup` (+ `RoleEligibilitySchedule.Read.Directory` for the Global Administrator review). Role: Identity Governance Administrator; PIM-for-Groups reviews need GA, Identity Governance Administrator or Privileged Role Administrator | `EntitlementManagement.ReadWrite.All`, `GroupMember.Read.All`. Role: Identity Governance Administrator |
| Idempotency | An existing definition with the same `displayName` is skipped (`[=]`), never edited; settings drift is reported (`-FailOnDrift` makes it an error) | An existing connected org is reused; `proposed` is promoted to `configured`; an existing sponsor is not re-added |
| Guards | Refuses a body whose silence does not mean Deny; self-review guard: warns about anyone both eligible and a reviewer | The tenant-wide lifecycle `PATCH` is `ConfirmImpact = 'High'` and prints the current values first; `-SkipTenantSettings` skips it |
| Evidence | `lab/evidence/access-reviews/definitions-<yyyyMMdd>.json` + `.sha256` (public-safe); full record with ids to the gitignored `lab/evidence/out/access-reviews/` | Prints the connected org id (for `b2b_connected_organization_id`) and the My Access link |
| `-WhatIf` | Prints each body, no write | No write |

## TENANT-TIME steps (in order; capture the evidence listed)

1. **Reviews**: apply the tier flags one PR at a time (`enable_access_reviews_privileged`, then `_requestable`, then `_inactive`). For the trial, set
   `access_review_start_date` to today and `access_review_duration_days` to
   about 3 so an instance closes inside the trial. Run
   `New-AccessReviewDefinitions.ps1 -WhatIf`, then run it for real.
   *Evidence:* the Graph GET of each policy's `reviewSettings` (see `main.tf`,
   including the open *verify:* about the fallback reviewer under
   `reviewerType = Manager`), the created definition ids, one completed
   privileged review in which an **eligible** member is denied and their
   eligibility disappears, and one instance closing with no response that
   removes access.
2. **Inactive review**: the scope only contains users inactive for 90 days
   who were *created* more than 90 days ago, so a fresh trial tenant shows an
   empty review. *Evidence:* the definition and an empty instance, plus a
   statement that the logic is proven by configuration. Do **not** fake sign-in
   dates.
3. **B2B**: apply `enable_b2b_governance = true`, add real people to
   `B2B-Sponsors-MedicalStaffOffice`, then run
   `New-B2BConnectedOrganization.ps1`. Set `b2b_connected_organization` to a
   domain you control, or to a second free Entra tenant (`tenant_id`). Request
   the package as an identity from that organization, approve it as a sponsor,
   then trigger the monthly review.
   *Evidence:* the request, the approval with justification, the guest user
   created by entitlement management, the assignment expiry date (90 days),
   and the review decision.
4. **Off-switch caveat**: turning a review flag off does not remove the
   policy reviews, because the provider suppresses the diff. Turn them off in
   the portal (`lab/terraform/README.md`, human step 12). Standalone reviews are deleted
   in the portal.

## verify: (open until the trial)

- Policy-attached reviews apply decisions themselves when an instance closes.
  Learn does not state this explicitly on the access-package review page.
- Under `reviewerType = Manager`, the fallback group survives; and a *group*
  is accepted as a fallback reviewer (both noted in `main.tf`).
- A Graph-created "Teams + Groups" review of a PIM-governed group includes
  **eligible** members. Learn documents this for the portal flow; the
  feature is still labelled preview.
- PIM-for-Groups reviews and inactive-user reviews need Entra ID Governance
  (licensing-fundamentals page).
- `descriptionForAdmins` / `descriptionForReviewers` length limits. The
  rendered strings are under 256 characters.
- A group is accepted as a connected organization's internal sponsor.
- The accepted range of `durationUntilExternalUserDeletedAfterBlocked`, and
  whether deleting a package that still has assignments is refused.
- B2B monthly-active-user billing (free tier size, and the subscription
  linking it needs).

## Offline tests

```bash
cd lab/terraform/modules/entitlement
terraform init -backend=false && terraform test   # HashiCorp Terraform 1.16.5
```

`tests/governance.tftest.hcl` (mock azuread, **26 runs, all passing on
2026-10-20**) covers:

- defaults create nothing new and match `lab/iga/access-catalog.json`;
  birthright packages have no policy and no expiry;
- the ADR 0012 tiers: T1 never reviews clinical packages, T2 reviews only
  long or extendable packages, a T1 package is reviewed quarterly by the
  governance group, the inactive flag is independent, the deprecated alias
  spares birthright, the privileged cadence cannot be relaxed;
- rendered bodies deny by default; a PIM body replaces the same-key group
  review; duplicate display names refused; PIM bodies need the T1 flag; a
  body that keeps access on silence is refused;
- failures: no fallback reviewer, a privileged reviewer reviewing itself,
  break-glass as a review target (by name or id), a requested birthright
  package, an expiring automatic package, an automatic privileged package, an
  extension without approval, an SoD pair of two birthright packages;
- the B2B package (external catalog, configured-orgs scope, sponsor approval,
  90-day expiry, monthly `removeAccess` review), the specific-org two-stage
  variant, and rejection of guest access longer than 180 days.
