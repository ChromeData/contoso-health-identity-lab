# ADR 0005: Risk acceptance — the APPLY identity holds `RoleManagement.ReadWrite.Directory` (Tier 0)

- **Status:** Accepted, as a time-boxed risk acceptance for the lab. Not acceptable for production as written (see Revisit trigger).
- **Date:** 2026-10-20
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-01-20, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

`envs/dev` manages three things that require the Graph application
permission `RoleManagement.ReadWrite.Directory`:

- the role-assignable groups (`Break-Glass-Admins`, `Privileged-IAM-Admins`,
  and the PIM tier groups when `enable_pim_tiers` is on)
- the standing Global Administrator assignment for break-glass
- the role bindings those PIM groups hold (User Administrator, and one role
  per tier group)

So the APPLY identity (ADR 0004) holds it. That permission lets its holder
assign **any** directory role to **any** principal, itself included.
Combined with subscription Contributor, APPLY could:

- grant itself Global Administrator
- delete the tenant's diagnostic setting, or delete or cap the Log Analytics
  workspace
- give admin sign-in to any Entra-joined VM in the subscription

**A second Tier-0 permission is opt-in.** `enable_app_management_roles` in
`envs/bootstrap` (off by default; a human apply) adds what `modules/apps`
needs for the SSO apps: `Application.ReadWrite.OwnedBy`,
`Application.Read.All`, `Policy.ReadWrite.ApplicationConfiguration` and
`AppRoleAssignment.ReadWrite.All`. The last one can grant any app role,
Microsoft Graph application permissions included, to any principal. That is
a second path to Tier 0 next to `RoleManagement.ReadWrite.Directory`, and
this acceptance covers it only while that flag is on.

**APPLY is effectively Tier 0.** The repo already says so inline. This ADR
makes the acceptance formal.

## Options considered

1. **Move every role-bearing resource to the human-applied `envs/bootstrap`
   root.** APPLY then drops the permission. The cost: break-glass and PIM
   bindings leave the PR-reviewed path, and the pipeline demo loses its
   most important resources.
2. **A narrower Graph permission or a scoped grant.** As far as the lab
   found, no Graph application permission creates role-assignable groups or
   directory role assignments short of this one, and administrative-unit
   scoping doesn't cover it (verify).
3. **A third, Tier-0-only pipeline identity.** Its own federated subject
   (for example `environment:prod-tier0`), two required reviewers, and only
   the role-bearing resources in its root. Ordinary APPLY drops to Tier 1.
   This is the production target.
4. **Accept it in the lab with compensating controls (chosen).**

## Decision

Accept the risk for the lab, with the controls below, until the review date
or a revisit trigger, whichever comes first. Option 3 is the documented
production design.

## Compensating controls

| Control | What it does | Status |
|---|---|---|
| Human-applied bootstrap | APPLY's own app, federated credential, Graph roles and RBAC are in `envs/bootstrap`, which no PR can change. So does the tenant log export. | Built (code) |
| Environment-scoped subject | APPLY is reachable only from a job declaring `environment: prod`, with numeric-ID subjects | Built (code) |
| `prod` reviewer gate, `main` only | A required reviewer approves each apply run; the deployment-branch policy allows `main` only | Documented (`lab/pipelines/README.md` §5E); configured after the first push |
| Plan before merge | Required checks: `terraform plan` (posted as a PR comment), Checkov, TruffleHog | Built (workflows) |
| Constrained Azure RBAC | APPLY can delegate only Key Vault Secrets User/Officer and VM Administrator Login (ABAC condition) | Built (code) |
| State account lock | ReadOnly lock blocks Contributor's `listKeys` and account-setting writes | Documented (`lab/terraform/README.md`); human step |
| Detections on APPLY misuse | Data is exported (`AuditLogs`, `ServicePrincipalSignInLogs`). Changes APPLY makes still alert, at a lower severity, matched by its immutable ids (an app that only carries its name is High): role assignments (`role-assigned-outside-pim.kql`, Medium), app-role grants (`app-consent-granted.kql`, Low), new credentials (`app-credential-added.kql`, Low) and CA changes (`ca-policy-changed.kql`, Low). The analyst ties each one to a PR by hand. Rules still to write: APPLY signing in from outside GitHub Actions, and a change to the diagnostic setting | **Partly built** (code; deployed by `modules/monitoring`, never fired in a tenant) |

## Consequences and residual risk

- **This is change control, not a privilege boundary.** Anyone who
  compromises the reviewer's GitHub account, or a pinned action running
  inside the apply job, holds Tier 0.
- **Solo-lab gap.** One person can merge and approve their own deployment
  ("Prevent self-review" has to stay off while there's no second reviewer). The
  two-person rule this design assumes doesn't hold until a second
  maintainer exists.
- **The approved run applies a fresh plan, not the PR's plan.** Drift since
  the PR, from portal edits or other merges, is applied without a second
  look; it's visible only in the run log.
- **Detection is partial.** APPLY's directory changes alert, but at Low or
  Medium, because most of them are expected: telling a reviewed change from
  misuse means matching each alert to a PR. Nothing alerts on APPLY signing
  in from outside GitHub Actions, or on a change to the diagnostic setting.

## Revisit trigger

- **The review date: 2027-01-20.**
- Any move beyond the lab: production can't use this acceptance. Implement
  option 3.
- A second maintainer joins: turn on "Prevent self-review" and require one
  PR approval.
- Microsoft ships a narrower Graph permission for role-assignable groups or
  role assignments.
- Any detection or incident involving the APPLY service principal.

## Evidence

- `lab/terraform/modules/pipeline-identity/variables.tf` (APPLY Graph roles;
  inline Tier-0 warning)
- `lab/terraform/envs/bootstrap/main.tf` (header: "change-control boundary,
  not a privilege boundary"; ABAC RBAC-admin condition;
  `app_management_apply_roles`) and `variables.tf`
  (`enable_app_management_roles`)
- `lab/kql/role-assigned-outside-pim.kql`, `app-consent-granted.kql`,
  `app-credential-added.kql`, `ca-policy-changed.kql` (APPLY matched by
  immutable ids)
- `lab/terraform/README.md` (security notes; remote-state lock and residual
  risk)
- `lab/pipelines/README.md` (§2 keystone subject, §5 A–C Tier-0 note, §5E,
  §5F)
- `.github/workflows/terraform-apply.yml` (`environment: prod`, `if: main`,
  concurrency)
- `lab/terraform/modules/entra-diagnostics/variables.tf` (exported
  categories)
