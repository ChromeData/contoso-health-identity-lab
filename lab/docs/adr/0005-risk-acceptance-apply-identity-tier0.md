# ADR 0005: Risk acceptance — the APPLY identity holds `RoleManagement.ReadWrite.Directory` (Tier 0)

- **Status:** Accepted, as a time-boxed risk acceptance for the lab. Not acceptable for production as written (see Revisit trigger).
- **Date:** 2026-10-20
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-01-20, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

`envs/dev` manages three things that need the Graph application permission
`RoleManagement.ReadWrite.Directory`: the role-assignable groups
(`Break-Glass-Admins`, `Privileged-IAM-Admins`, the PIM tier groups), the
standing Global Administrator assignment for break-glass, and the roles
those groups hold. So the APPLY identity (ADR 0004) holds it, and can assign
**any** directory role to **any** principal, itself included. With
subscription Contributor it could also delete or cap the log workspace, or
give admin sign-in to any Entra-joined VM.

**A second Tier-0 permission is opt-in.** `enable_app_management_roles` in
`envs/bootstrap` (off by default; a human apply) adds what the SSO apps
need, including `AppRoleAssignment.ReadWrite.All`, which can grant any app
role, Graph application permissions included, to any principal. This
acceptance covers it only while that flag is on.

## Options considered

1. **Move every role-bearing resource to the human-applied bootstrap root.**
   APPLY drops the permission, but break-glass and PIM bindings leave the
   PR-reviewed path.
2. **A narrower Graph permission or scoped grant.** As far as the lab found,
   none creates role-assignable groups or role assignments short of this
   one, and administrative-unit scoping doesn't cover it (verify).
3. **A third, Tier-0-only pipeline identity** with its own subject (for
   example `environment:prod-tier0`), two required reviewers and only the
   role-bearing resources in its root. Ordinary APPLY drops to Tier 1. This
   is the production target.
4. **Accept it in the lab with compensating controls (chosen).**

## Decision

Accept the risk for the lab, with the controls below, until the review date
or a revisit trigger. Option 3 is the documented production design.

## Compensating controls

| Control | What it does | Status |
|---|---|---|
| Human-applied bootstrap | APPLY's own app, federated credential, Graph roles and RBAC, and the tenant log export, live in `envs/bootstrap`, which no PR can change | BUILT |
| Environment-scoped subject | APPLY is reachable only from a job declaring `environment: prod`, with numeric-ID subjects | BUILT |
| `prod` reviewer gate, `main` only | A required reviewer approves each apply; deployments only from `main` | DESIGNED (`lab/pipelines/README.md` §5E); configured after the first push |
| Plan before merge | Required checks: `terraform plan` as a PR comment, Checkov, TruffleHog | BUILT |
| Constrained Azure RBAC | APPLY can delegate only Key Vault Secrets User/Officer and VM Administrator Login (ABAC) | BUILT |
| State account lock | ReadOnly lock blocks Contributor's `listKeys` and setting writes | DESIGNED (human step) |
| Detections on APPLY misuse | APPLY's changes still alert, matched by immutable id, at Low or Medium (an app that only carries its name is High); the analyst ties each to a PR. Not written: APPLY signing in outside GitHub Actions, and a diagnostic-setting change | Partly BUILT; never fired in a tenant |

## Consequences and residual risk

- **This is change control, not a privilege boundary.** Anyone who
  compromises the reviewer's GitHub account, or a pinned action inside the
  apply job, holds Tier 0.
- **Solo-lab gap.** One person can merge and approve their own deployment
  until a second maintainer exists.
- **The approved run applies a fresh plan, not the PR's plan.** Drift since
  the PR is applied without a second look; it shows only in the run log.
- **Detection is partial** for the reasons in the table.

## Revisit trigger

- **The review date: 2027-01-20.**
- Any move beyond the lab: implement option 3.
- A second maintainer joins: "Prevent self-review" and one PR approval.
- Microsoft ships a narrower Graph permission for role-assignable groups.
- Any detection or incident involving the APPLY service principal.

## Evidence

- `lab/terraform/modules/pipeline-identity/variables.tf` (Graph roles; inline
  Tier-0 warning)
- `lab/terraform/envs/bootstrap/main.tf` ("change-control boundary, not a
  privilege boundary"; ABAC condition; `app_management_apply_roles`) and
  `variables.tf` (`enable_app_management_roles`)
- `lab/kql/role-assigned-outside-pim.kql`, `app-consent-granted.kql`,
  `app-credential-added.kql`, `ca-policy-changed.kql`
- `lab/terraform/README.md` (security notes); `lab/pipelines/README.md`
  (§2, §5 A–C, §5E, §5F); `.github/workflows/terraform-apply.yml`
