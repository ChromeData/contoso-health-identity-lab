# ADR 0003: Conditional Access exclusions and break-glass strategy

- **Status:** Accepted (lab). BUILT: code validated offline; no policy has been applied and no drill has run.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Conditional Access (CA) is the most effective control in the tenant and the
easiest way to lock everyone out of it: MFA required before admins have
registered methods, or a location block that catches the on-call admin. In
a hospital, losing admin access during an incident affects patient care. The
design needs a way back in that doesn't depend on CA, that way back in being
visible every time it is used, and policy changes that can be observed
before they're enforced.

## Options considered

1. **No exclusions.** Rejected: a policy mistake or an MFA outage leaves no
   recovery path.
2. **Named break-glass users excluded on each policy.** A new policy that
   forgets one breaks the invariant without anyone noticing.
3. **One break-glass group, excluded from every policy, with two cloud-only
   accounts (chosen).** A single invariant that can be checked.
4. **Keep break-glass in scope through a dedicated phishing-resistant
   policy.** Stronger if FIDO2 always works, but it fails closed if the
   policy engine or the method itself is the problem.

## Decision

- **Two accounts,** `bg-admin-01` and `bg-admin-02`, cloud-only on the
  `*.onmicrosoft.com` domain, so they don't depend on AD, sync or a custom
  domain. Both are in the role-assignable `Break-Glass-Admins` group, which
  holds **standing Global Administrator**: the only standing privileged
  assignment in the design.
- **Credential:** two FIDO2 keys per account in separate safes. The seeded
  password is rotated after apply and kept only as sealed backup material.
  Microsoft's mandatory admin-portal MFA still applies to them.
- **Exclusion:** `Break-Glass-Admins` is excluded from **every** CA policy,
  by object ID. It is the **only** exclusion the standard allows; any other
  carve-out is done by scoping inclusion (CA005 targets a pilot group rather
  than excluding everyone else).
- **Rollout:** every policy starts report-only and is promoted one per PR.
  CA002 is enforced only after every in-scope admin has a phishing-resistant
  method.
- **Alerting:** any break-glass sign-in, successful or failed, interactive or
  not, alerts. Threshold 1.

## Consequences

- **A checkable invariant.** `01-Verify-Baseline.ps1` check 4 fails if any
  policy doesn't exclude the group, and says not to enforce CA until it
  passes.
- **The excluded accounts rely on their credential, not on CA:** FIDO2,
  mandatory admin-portal MFA, and the threshold-1 alert across
  `SigninLogs` and `AADNonInteractiveUserSignInLogs`.
- **Group membership grants GA plus a CA bypass.** Limits: only privileged
  admins and owners can change a role-assignable group; Terraform declares
  the members, so an out-of-band add shows as drift;
  `pim-group-member-added-outside-pim.kql` is always High for this group,
  and `ca-policy-changed.kql` alerts when exclusions change outside the CI
  apply identity. The APPLY identity can change the group (ADR 0005).
- **The seeded password sits in Terraform state,** readable by the PLAN
  identity and same-repo PRs, until the post-apply rotation (human step 6).
- **The tenant-creation account is a standing Global Administrator** until
  `Convert-BuildAccountToEligible.ps1` makes it eligible (it refuses unless
  break-glass, the exclusion, alerting and the GA activation policy check
  out). Until then `01-Verify-Baseline.ps1` flags it.
- **The detection matches the naming pattern** (`bg-admin-NN@`), so a
  rename blinds it. The production fix is object IDs from a watchlist.
- **No drill has run.** The quarterly drill is
  [`runbooks/break-glass-drill.md`](../runbooks/break-glass-drill.md); its
  log is an empty template.
- **Workload identities are out of scope:** user-scoped CA doesn't apply to
  service principals (ADR 0004, ADR 0005).

## Revisit trigger

- Microsoft changes its emergency-access guidance or the mandatory-MFA
  scope.
- A break-glass alert fires outside a logged drill: incident review.
- Anyone asks for a second CA exclusion. The answer is scoping, or a new ADR.
- Any new CA policy: re-run `01-Verify-Baseline.ps1` check 4 before it
  leaves report-only.

## Evidence

- `lab/terraform/modules/groups/main.tf`, `variables.tf` (accounts, group,
  standing GA, onmicrosoft.com domain, at least two accounts)
- `lab/terraform/modules/conditional-access/` (`excluded_groups` on every
  policy; `policy_states` validation); `lab/terraform/envs/dev/lab.tfvars`
- `lab/kql/break-glass-signin.kql`, `pim-group-member-added-outside-pim.kql`,
  `ca-policy-changed.kql`
- `lab/scripts/powershell/01-Verify-Baseline.ps1` (checks 2–5),
  `Invoke-BreakGlassDrill.ps1`, `post-apply/Convert-BuildAccountToEligible.ps1`
  (never run)
- `lab/terraform/README.md` (human step 6); `lab/evidence/drills/README.md`
  (empty drill log)
