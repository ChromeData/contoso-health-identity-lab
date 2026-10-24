# ADR 0004: Workload identity federation (OIDC) for the pipeline, with PLAN and APPLY split by subject

- **Status:** Accepted (lab). BUILT: code and workflows validated offline. On GitHub, the credential-free `lab-tests` workflow passed on `main` on 2026-10-21 ([run](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523030602)); plan and apply have never run against a tenant, because none exists.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Every change to the tenant arrives as a PR and is applied by GitHub
Actions, so CI needs Entra and Azure credentials. A stored CI credential is
a classic non-human-identity failure: it leaks through logs, forks or a
compromised action, nobody rotates it, and it works from anywhere. The repo
is also **public on purpose** (`lab/pipelines/README.md` §3), so anything
in it or reachable from it is exposed.

## Options considered

1. **Client secret in GitHub Secrets.** Long-lived, usable from any network,
   needs rotation, and the most valuable thing to steal from the repo.
2. **Certificate credential.** Better, but still a key someone stores,
   renews and protects.
3. **OIDC federation with one identity for plan and apply.** No stored
   secret, but every PR run, unreviewed code included, would hold write
   access.
4. **OIDC federation with two identities split by token subject (chosen).**
   PLAN is read-only and trusts only `pull_request`; APPLY can write and
   trusts only `environment:prod`.

A self-hosted runner with a managed identity was ruled out: a VM to patch,
and still a standing credential on the runner.

## Decision

GitHub mints a short-lived OIDC token per job. Entra exchanges it only when
issuer, audience and **subject** match a federated credential exactly:

| Identity | Federated subject | Access |
|---|---|---|
| PLAN | `repo:OWNER@OWNER_ID/REPO@REPO_ID:pull_request` | Graph read, subscription Reader, Storage Blob Data **Reader** on the state container |
| APPLY | `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:prod` | Graph write, Contributor, RBAC Administrator limited by an ABAC condition to three roles, Storage Blob Data Contributor on the state container |

- **Subjects use numeric owner and repo IDs,** so a deleted and
  re-registered name can't mint a matching token.
- **`prod`** has a required reviewer and deploys from `main` only.
- **Both identities are created in the human-applied `envs/bootstrap`
  root,** never by the pipeline, so no PR can widen its own permissions.
- **AWS stays out of CI:** the `aws/` root is applied by a human from a
  short-lived SSO session.

## Consequences

- **No credential to store, rotate or leak.** The repo holds identifiers
  only; its five repo secrets are identifiers kept as secrets so GitHub
  masks them in public logs.
- **Fork PRs can't plan:** they get no OIDC token, so the required plan
  check fails by design until a maintainer re-pushes the branch.
- **PLAN can read state, and state holds generated passwords** (break-glass
  seeds, VM local admins). Compensating controls: PR plans run with
  `-lock=false` on a Reader role, break-glass passwords are rotated after
  apply (ADR 0003), and only maintainers push same-repo branches.
- **The `environment:prod` subject has no branch in it.** The
  deployment-branch policy (main only) is what ties APPLY to merged code; it
  is a human setup step (`lab/pipelines/README.md` §5E), now set on the
  public repo: `prod` deploys from `main` only.
- **Trust moves to GitHub:** issuer, subject format and environment
  protections. A subject-format change fails closed.
- **Supply chain becomes the main path in.** Actions are pinned to full
  SHAs with Dependabot bumps; the TruffleHog image is pinned by digest.
- **APPLY is Tier 0,** a separate, explicit risk acceptance (ADR 0005).
- **Not covered:** CA for workload identities (Workload ID Premium), and a
  rule for either identity signing in from outside GitHub (the data,
  `ServicePrincipalSignInLogs`, is already exported).
  `app-credential-added.kql` alerts High on a new federated credential added
  by anyone but the CI apply identity.

## Revisit trigger

- A second maintainer joins: require one PR approval and turn on "Prevent
  self-review" on `prod`.
- The repo goes private: environment protection then needs a paid plan.
- GitHub changes its OIDC subject or claim format.
- A third deployment target: a new identity per subject, never a wider one.

## Evidence

- `lab/terraform/modules/pipeline-identity/main.tf`, `variables.tf`
- `lab/terraform/envs/bootstrap/main.tf` (Reader, Contributor, ABAC
  RBAC-admin condition, container-scoped state roles)
- `.github/workflows/terraform-plan.yml`, `terraform-apply.yml`
- `lab/pipelines/README.md` (§1 two identities, §2 OIDC trust, §4 pinning,
  §5 A–F setup)
- `lab/terraform/modules/entra-diagnostics/variables.tf`;
  `lab/kql/app-credential-added.kql`
