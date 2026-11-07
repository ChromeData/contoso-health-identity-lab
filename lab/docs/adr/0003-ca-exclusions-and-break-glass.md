# ADR 0003: Conditional Access exclusions and break-glass strategy

- **Status:** Accepted (lab). RAN · tenant: the 11 CA policies exclude `Break-Glass-Admins` (E12, E13); the first lab drill ran on 2026-11-05 (E49). Lab deviations, recorded: one software passkey per account, kept on the operator Mac, not two hardware keys in separate safes (E11d); the seeded passwords were not rotated (E11f, PR #226). Not run: `Convert-BuildAccountToEligible.ps1`.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Conditional Access (CA) is the most effective control in the tenant, and the
easiest way to lock everyone out of it. One wrong policy can do it: MFA
required for all users before admins have registered methods, or a location
block that catches the on-call admin. In a hospital, losing admin access
during an incident affects patient care. The design needs:

- a way back in that doesn't depend on CA
- that way back in being visible every time anyone uses it
- policy changes that can be observed before they're enforced

## Options considered

1. **No exclusions.** Rely on admins' own MFA. Rejected: a policy mistake or
   an MFA-provider outage leaves no recovery path.
2. **Exclude named break-glass users on each policy.** It works, but every
   policy carries its own list, and a new policy that forgets one breaks the
   invariant without anyone noticing.
3. **One break-glass group, excluded from every policy, with two cloud-only
   accounts (chosen).** A single invariant that can be checked.
4. **Keep break-glass in scope through a dedicated policy that requires a
   phishing-resistant authentication strength,** instead of excluding it.
   It's stronger if FIDO2 always works, and it fails closed if the policy
   engine or the method itself is the problem (verify: current Microsoft
   emergency-access guidance on exclusion vs. dedicated policy).

## Decision

**Break-glass accounts:**

- Two accounts, `bg-admin-01` and `bg-admin-02`, cloud-only on the
  `*.onmicrosoft.com` domain, so they don't depend on AD, sync or a custom
  domain.
- Both are members of the role-assignable `Break-Glass-Admins` group, which
  holds **standing Global Administrator**. This is the only standing
  privileged assignment for people in the design. Two workload
  identities also hold standing Tier-0 rights: APPLY (ADR 0005) and the
  lab operator (ADR 0024).
- Their credential is **FIDO2 security keys**: two per account, kept in
  separate safes. The seeded password is rotated after apply and kept only
  as sealed backup material. Microsoft's mandatory MFA for admin portals
  still applies to them.

**Exclusions:**

- `Break-Glass-Admins` is excluded from **every** CA policy, by object ID.
- That is the **only** exclusion the standard allows. Any other carve-out is
  done by **scoping inclusion** instead. For example, CA005 targets a pilot
  group rather than excluding everyone who isn't in it.

**Rollout:** every policy starts **report-only**. Promotion to enforced is
one policy per PR, through `lab.tfvars`. CA002 (phishing-resistant MFA for
admins) is enforced only after every in-scope admin has a phishing-resistant
method registered.

**Alerting:** any break-glass sign-in, successful or failed, interactive or
non-interactive, triggers an alert. The threshold is 1.

## Consequences

- **A checkable invariant.** `01-Verify-Baseline.ps1` check 4 FAILs and
  exits 1 if any policy doesn't exclude the group. The script says not to
  enforce CA until it passes.
- **The excluded accounts rely on their credential, not on CA.** The
  compensating controls are FIDO2 keys, mandatory admin-portal MFA, and the
  threshold-1 alert across `SigninLogs` and `AADNonInteractiveUserSignInLogs`.
- **Risk: group membership grants GA plus a CA bypass.** Adding anyone to
  `Break-Glass-Admins` gives them both. Three things limit this:
  - Role-assignable groups restrict who can change membership (verify).
  - Terraform declares the members, so an out-of-band addition shows up as
    drift on the next plan.
  - `pim-group-member-added-outside-pim.kql` alerts High on any addition to
    the group, matched by its object ID. `ca-policy-changed.kql` alerts when
    a policy's exclusions change outside the CI apply identity. Both are
    deployed by `modules/monitoring` (`itdr.tf`) and have not fired in a
    tenant.

  The APPLY pipeline identity can change this group (ADR 0005).
- **Risk: the seeded password is in Terraform state,** which the PLAN
  identity and any same-repo PR can read. It stays exposed until the
  post-apply rotation in human step 6 is done.
- **Risk: the tenant-creation account is also a standing Global
  Administrator** until it is converted. `Convert-BuildAccountToEligible.ps1`
  turns it into a 180-day eligible assignment, and refuses unless
  break-glass, the CA exclusion, alerting and the Global Administrator
  activation policy all check out first. It has never run; until it does,
  `01-Verify-Baseline.ps1` flags the account.
- **Risk: the detection matches the naming pattern** (`bg-admin-NN@`), so
  renaming an account blinds it. The production fix is matching on object
  IDs from a Sentinel watchlist.
- **Drills.** The design calls for one sign-in drill per key every 90
  days (`lab/docs/runbooks/break-glass-drill.md`). `Invoke-BreakGlassDrill.ps1`
  automates the checks around it: a read-only preflight, then reading the
  sign-ins and alerts back from Log Analytics and writing the record. The
  first drill ran in the lab on 2026-11-05 with one software passkey per
  account (the runbook's lab deviation): Pass, Sentinel incident #42 for
  both sign-ins, no changes made (`lab/evidence/drills/README.md`, E49). In
  production the sign-ins stay manual, with hardware keys.
- **Workload identities are out of scope.** User-scoped CA doesn't apply to
  service principals, including the pipeline identities. CA for workload
  identities is a separate licence (verify: Workload ID Premium). Pipeline
  identities are covered in ADR 0004 and ADR 0005.

## Revisit trigger

- Microsoft changes its emergency-access guidance or the mandatory-MFA
  scope.
- A break-glass alert fires outside a logged drill, which means an incident
  review.
- Anyone asks for a second CA exclusion. The answer is scoping, or a new ADR.
- Passwordless for all users (risk-based CA) is added. Re-check that
  break-glass is still excluded from the new policies.

## Evidence

- `lab/terraform/modules/groups/main.tf` (`bg-admin-01`/`02`,
  `Break-Glass-Admins`, standing GA)
- `lab/terraform/modules/groups/variables.tf` (onmicrosoft.com domain; at
  least two accounts)
- `lab/terraform/modules/conditional-access/` (header in `main.tf`, and
  `excluded_groups` on every policy)
- `lab/terraform/modules/conditional-access/variables.tf` (`policy_states`
  validation)
- `lab/terraform/envs/dev/lab.tfvars` (every policy in `ca_policy_states`
  report-only)
- `lab/kql/break-glass-signin.kql`, `lab/kql/pim-group-member-added-outside-pim.kql`,
  `lab/kql/ca-policy-changed.kql`
- `lab/scripts/powershell/01-Verify-Baseline.ps1` (checks 2–5)
- `lab/terraform/README.md` (human step 6)
- `lab/docs/runbooks/break-glass-drill.md` (drill procedure; first lab drill 2026-11-05, E49)
- `lab/scripts/powershell/Invoke-BreakGlassDrill.ps1` (drill checks; ran
  2026-11-05, E49)
- `lab/scripts/powershell/post-apply/Convert-BuildAccountToEligible.ps1`
  (never run)
- `lab/evidence/drills/README.md` (drill log; first entry 2026-11-05, E49)
