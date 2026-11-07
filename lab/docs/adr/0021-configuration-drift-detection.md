# ADR 0021: Configuration drift detection (nightly reconcile of tenant state against the code)

- **Status:** Accepted (lab). BUILT: `Export-IdentityConfig.ps1`, `Compare-IdentityConfig.ps1`, their Pester suites and `.github/workflows/config-drift.yml`, all tested offline against mocked Graph. **RAN · tenant:** nightly since 2026-10-29 against a reviewed baseline (#98); it caught a real Microsoft schema change (#112), and the baseline was refreshed by PR (#113).
- **Date:** 2026-10-26
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Every identity control in this repository is code: Conditional Access,
PIM policies, authentication methods, consent and app-management policies,
named locations. A pull request is the only sanctioned way to change them
(ADR 0004). But a tenant can be changed by hand, by a Graph script, by
Microsoft's own defaults rolling forward, or by a compromised admin, and the
code would never know. Two existing controls cover part of that gap:

- **Real-time detection.** `ca-policy-changed.kql`, `role-assigned-outside-pim.kql`
  and the other ITDR rules (ADR 0017) alert when a change *happens*, if the
  audit log carries it and Sentinel is running.
- **`terraform plan` on every PR.** It shows the difference between the
  code and the state *file*, not the tenant: a change made in the portal
  is invisible until a resource is refreshed, and the Graph-managed
  settings (CA021, CA023, the PIM role policies, the methods policy) are not
  in Terraform state at all (ADR 0020).

What was missing is the third leg: a **periodic reconcile** that reads the
whole tenant configuration the code claims to own, compares it with the
committed baseline and the declared intent, and raises a finding when they
differ, whether or not a detection fired at the time.

Senior and architect postings read in October 2026 name this directly:
"automation that detects drift and triggers remediation" and "identity
guardrails embedded in Terraform and CI/CD".

## Options considered

| Question | Chosen | Rejected, and why |
|---|---|---|
| Where the reconcile runs | **A scheduled GitHub workflow** using the read-only PLAN identity over OIDC (ADR 0004), nightly and on demand, uploading the export as a run artifact | **Inside Sentinel only:** depends on the audit log capturing every change and on the rule set staying complete; it cannot see a default Microsoft rolled forward. **`terraform plan -refresh-only` nightly:** blind to everything Terraform does not manage, which is where the most dangerous settings live (ADR 0020) |
| What counts as the baseline | **A committed, hashed export from the tenant** (`lab/config-baseline/identity-config.json`), replaced only by a PR, plus the declared intent already in code (`ca_policy_states` in `lab.tfvars`) | **The last export:** drift would baseline itself the night after it happened. **The Terraform state file:** not readable by PLAN in production and incomplete |
| How a finding is handled | **An issue, not an automatic revert.** One open `identity-drift` issue per repository, updated nightly; Tier-0 findings fail the run | **Auto-remediation (re-apply):** the apply identity is Tier 0 (ADR 0005), and an automatic apply at 02:00 against a tenant someone changed by hand during an incident is the lockout the clinicians cannot afford (R12). Remediation is a PR, reviewed |
| Accepted differences | **An exceptions file with an owner and an expiry date** (`drift-exceptions.json`), under the exception standard (`standards/exception-process.md`); an expired exception reactivates the finding | **Suppress in the compare logic:** invisible to the audit, never expires |
| Sensitivity of the export | **Public-safe by default:** stable ids only, personal identifiers hashed, no credential material is ever read; the raw export is a run artifact with a short retention, never committed | **Commit every export:** the evidence folder is public and a full export names people |

## Decision

- **Scope of the export** (`Export-IdentityConfig.ps1`): Conditional Access
  policies, named locations, authentication strengths, the authentication
  methods policy, PIM role-management policies for directory roles and
  PIM-for-Groups, the consent and app-management policies, cross-tenant
  access defaults, and the break-glass exclusion facts. Each section records
  `ok` or `failed` with the error; a section that could not be read is never
  written as empty (the rule from `08-Measure-KPIs.ps1`).
- **Classification** (`Compare-IdentityConfig.ps1`): **High** for anything
  that changes who gets in or how sign-in is protected (a CA policy state or
  exclusion, a missing break-glass exclusion, a PIM activation setting, the
  methods policy); **Medium** for the rest of the owned settings; **Low**
  for cosmetic differences. High or Medium exits non-zero; the workflow
  opens or updates the issue with the Markdown summary.
- **Three legs, one loop.** Real-time detection (Sentinel) says *when* and
  *who*; the nightly reconcile says *what is different now*; the PR is the
  only way back. The runbook for a High finding is
  `runbooks/compromised-identity.md` if the change was not a known action,
  and `runbooks/ca-change-review-checklist.md` if it was.
- **Baseline ownership.** IAM Engineering owns the baseline file and the
  exceptions file; a change to either is a PR reviewed like any policy
  change (RACI: "CA policy change"). The first baseline is captured on the
  tenant's Day 1 (E59 in `evidence-capture-plan.md`).

## Consequences

- A nightly read of the tenant by CI is a new, read-only, scheduled use of
  the PLAN identity. Its scope does not change (Graph read, Reader on the
  subscription); the schedule is visible in the workflow file.
- Drift that happens and is reverted within the same day is seen only by
  the real-time rules. That is accepted: the reconcile is the backstop, not
  the alarm.
- The compare can only judge settings the code claims. A new policy created
  by hand shows as "not in baseline" (Medium), which is the intended signal
  that someone is working outside the pipeline.

## How it is measured

| Measure | Source | Target |
|---|---|---|
| Nights with a completed reconcile | Workflow run history | 100% of nights after the baseline exists |
| Open High findings older than one business day | The `identity-drift` issue | 0 |
| Exceptions past their expiry date | `drift-exceptions.json` against the current date | 0 |
| Time from drift to finding | Compare of the finding's first appearance with the audit event | ≤ 24 h (nightly), ≤ 15 min where a real-time rule exists |

Results: fill after running. Nothing has been measured.

## Revisit trigger

- Microsoft ships a native configuration-baseline feature for Entra that
  covers the Graph-managed settings; the export then becomes a read of that
  feature.
- The lab moves to a split Tier-0 apply identity (ADR 0005, option 3): a
  narrowly scoped auto-revert for Low findings could then be considered.

## Evidence

- `lab/scripts/powershell/Export-IdentityConfig.ps1`, `Compare-IdentityConfig.ps1`
- `lab/scripts/powershell/tests/Export-IdentityConfig.Tests.ps1`, `Compare-IdentityConfig.Tests.ps1`
- `.github/workflows/config-drift.yml` (no run yet)
- `lab/config-baseline/` (placeholder until E59)
- Real-time twins: `lab/kql/ca-policy-changed.kql`, `role-assigned-outside-pim.kql`, `pim-activation-without-auth-context.kql`

## Sources

- Microsoft Learn, "Conditional Access: What's new" and the Graph
  `identity/conditionalAccess` resource (verify: the fields the export
  treats as volatile).
- Microsoft Learn, "PIM role settings" Graph resources
  `unifiedRoleManagementPolicy` (verify: which settings are readable with
  `RoleManagement.Read.Directory`).
