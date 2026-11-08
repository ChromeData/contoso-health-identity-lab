# ADR 0004: Workload identity federation (OIDC) for the pipeline, with PLAN and APPLY split by subject

- **Status:** Accepted (lab). Code and workflows validated offline; no pipeline run yet (the repo isn't pushed).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Every change to the tenant arrives as a PR and is applied by GitHub Actions.
CI therefore needs Entra and Azure credentials. A stored CI credential is a
classic non-human-identity failure: it leaks through logs, forks or a
compromised action, nobody rotates it, and it can be used from anywhere.

The repo is also **public on purpose** (`lab/pipelines/README.md` §3). Any
secret in it, or reachable from it, is exposed to the internet.

## Options considered

1. **Client secret in GitHub Secrets.** It's simple, but the secret is
   long-lived, usable from any network, and needs a rotation process. It
   also becomes the most valuable thing an attacker can steal from the repo.
2. **Certificate credential.** Better than a secret, but it's still a key
   someone stores, renews and protects.
3. **OIDC federation with one identity for both plan and apply.** No stored
   secret, but every PR run, including unreviewed code, would hold write
   access.
4. **OIDC federation with two identities split by token subject (chosen).**
   PLAN is read-only and trusts only `pull_request`. APPLY can write and
   trusts only `environment:prod`.

A fifth option, a self-hosted runner with a managed identity, was ruled out
for the lab. It means a VM to patch and protect, and it's still a standing
credential on the runner.

## Decision

GitHub mints a short-lived OIDC token for each job. Entra exchanges it only
when the issuer, audience and **subject** match a federated credential
exactly:

| Identity | Federated subject | Access |
|---|---|---|
| PLAN | `repo:OWNER@OWNER_ID/REPO@REPO_ID:pull_request` | Graph read, subscription Reader, Storage Blob Data **Reader** on the state container |
| APPLY | `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:prod` | Graph write, Contributor, RBAC Administrator limited by an ABAC condition to three roles, Storage Blob Data Contributor on the state container |

Supporting choices:

- **The subjects use numeric owner and repo IDs,** so a deleted and
  re-registered name can't mint a matching token.
- **The `prod` environment** has a required reviewer and allows deployments
  from `main` only.
- **Both identities are created in the human-applied `envs/bootstrap` root,**
  never by the pipeline itself, so no PR can widen its own permissions.
- **AWS stays out of CI.** The `aws/` root is applied by a human from a
  short-lived SSO session, and CI holds no AWS credentials.

## Consequences

- **No credential to store, rotate or leak.** The repo and its settings hold
  only identifiers (repo Variables). There are no repo or Dependabot
  secrets (since 2026-11-07, senior gap 6). The five privacy values that used
  to be repo secrets only so GitHub masked them (operator IP ranges, alert
  email, app owner object ids, SAML certificate emails, PIM alert mailbox)
  are read at run time from the pipeline config vault
  (`envs/bootstrap/pipeline-config.tf`) with the same OIDC sign-in, masked
  per element, and logged per read.
- **Fork PRs can't plan.** They get no OIDC token, so the required
  `terraform plan` check fails by design until a maintainer re-pushes the
  branch.
- **Risk: PLAN can read state, and state holds generated passwords**
  (break-glass seeds and VM local admins). That makes them readable by any
  same-repo PR. **Compensating controls:**
  - PR plans run with `-lock=false` on a Reader role, so they can't write
    state.
  - Break-glass passwords are rotated after apply (ADR 0003).
  - Only maintainers can push same-repo branches.
- **Risk: the `environment:prod` subject has no branch in it.** The
  deployment-branch policy (main only) is what ties APPLY to merged code;
  the job's `if:` is only a second layer. If that setting is misconfigured,
  any branch can reach APPLY after approval. The setting is a human step
  (§5E) and isn't configured yet.
- **Trust moves to GitHub.** The control now depends on GitHub's issuer, the
  subject-claim format and the environment protections. If the subject
  format changes, sign-in fails (fails closed). (verify: the subject preview
  before the first PR, per `lab/pipelines/README.md` §2.)
- **Supply chain becomes the main path in.** All actions are pinned to a
  full SHA and Dependabot proposes bumps. The TruffleHog image is pinned by
  digest. The Checkov image tag can't be overridden; that's an accepted
  residual risk.
- **The APPLY identity is Tier 0.** That's a separate, explicit risk
  acceptance: ADR 0005.
- **Not covered:** Conditional Access for workload identities (verify:
  licensing). The detection that would flag either identity signing in from
  outside GitHub isn't built yet; its data source, `ServicePrincipalSignInLogs`,
  is already exported by `entra-diagnostics`. The trust itself is watched:
  `app-credential-added.kql` alerts High on a new federated credential (a
  new subject that could mint tokens) added by anyone other than the CI
  apply identity. It is deployed by `modules/monitoring` and has not fired
  in a tenant.

## Revisit trigger

- A second maintainer joins: require one PR approval and turn on "Prevent
  self-review" on `prod`.
- The repo goes private: environment protection then needs a paid GitHub
  plan (`lab/pipelines/README.md` §3).
- GitHub changes its OIDC subject or claim format.
- A third deployment target is added. Add a new identity per subject; don't
  widen an existing one.

## Evidence

- `lab/terraform/modules/pipeline-identity/main.tf` (issuer, audience,
  `plan_subject`, `apply_subject`)
- `lab/terraform/modules/pipeline-identity/variables.tf` (Graph roles for
  each identity)
- `lab/terraform/envs/bootstrap/main.tf` (header; Reader, Contributor, ABAC
  RBAC-admin condition, container-scoped state roles)
- `.github/workflows/terraform-plan.yml` and
  `.github/workflows/terraform-apply.yml` (`id-token: write`,
  `environment: prod`, `if: main`, concurrency)
- `lab/pipelines/README.md` (§1 two identities, §2 OIDC trust, §4 SHA
  pinning, §5 A–F setup)
- `lab/terraform/modules/entra-diagnostics/variables.tf`
  (`ServicePrincipalSignInLogs`)
- `lab/kql/app-credential-added.kql`
