# ADR 0010: Kubernetes workload identity scope

- **Status:** Accepted. The segment is frozen at this scope.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Clinical batch jobs on Kubernetes need database credentials. The common
patterns are a Kubernetes Secret, an environment variable, or a legacy
service-account token Secret. All three are "secret zero": a long-lived
credential protected only by nobody copying it.

Kubernetes is a minor part of an IAM role compared with Entra, PAM and
governance. The segment has to prove the identity pattern without turning
into a platform-engineering project or needing a paid AKS cluster in CI.

## Options considered

1. **Real AKS with Entra Workload ID and the Key Vault CSI driver.** It is the
   production target. It needs cloud spend and cloud credentials in CI, and
   the cluster's OIDC issuer must be public.
2. **kind, rebuilt for every run, with Vault's Kubernetes auth and the Agent
   Injector,** plus the AKS/Entra mapping written as Terraform that is
   tested offline and never applied.
3. **A full workload-identity platform:** SPIFFE/SPIRE or service-mesh mTLS,
   multi-cluster, External Secrets, and policy engines (Kyverno,
   Gatekeeper). Broader, but each piece adds operational surface and moves
   the work away from identity.
4. **Leave Kubernetes out.** Loses the non-human-identity story for
   containerised workloads.

## Decision

Option 2, scoped to **one workload, one secret, one exchange**.

**In scope (built and tested):**
- A projected service-account token, audience `vault`, 600 s, mounted only
  into the agent containers
- Vault Kubernetes auth with TokenReview, bound to service account plus
  namespace plus audience. It returns a 15-minute token that can read one
  path.
- The secret rendered to a tmpfs file, with no Kubernetes Secret and no
  environment variable
- Rotation without a restart
- Human RBAC for two impersonated groups
- A ValidatingAdmissionPolicy with four rules. It ties the identity to the
  approved image digests (rule 2), requires digest pinning (rule 1) and
  disabled token automount (rule 3), and lets only the release pipeline
  create or change a workload that runs as that identity (rule 4).
- Drift detect-and-heal through `terraform plan -detailed-exitcode`
- An audit policy that never logs a token or Secret body
- A zero count of secrets in Terraform state

**Mapped, not applied:** the Entra Workload ID federated identity credential
for `system:serviceaccount:clinical-apps:nightly-report`. It is in
`terraform/k8s/aks-mapping`, checked with `fmt`, `validate` and a mocked
`terraform test`.

**Out of scope:**
- SPIFFE/SPIRE and mesh mTLS
- Multi-cluster trust
- External Secrets Operator. Its secret lands in etcd, which would need a
  written trade-off.
- Kyverno and Gatekeeper
- Conditional Access for workload identities (verify: licensing, Workload
  ID Premium)
- Node and cloud IAM

## Consequences

**Positive**
- $0, no cloud credentials, and reproducible. One script (`ci/pipeline.sh`,
  12 stages) builds the cluster, asserts, and tears it down.
- The admission policy is upstream Kubernetes (VAP, GA since 1.30), so the
  same object applies on AKS.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| kind is not AKS. The audit policy is a file the lab chooses, whereas AKS manages its own policy and exposes it through diagnostic settings. | Stated in the `STAND-INS.md` kind row (verify: AKS audit categories). Claims are limited to upstream behaviour. |
| Entra validates the token offline against the issuer's JWKS. A token whose service account was deleted stays exchangeable until it expires, unlike Vault's TokenReview. | Documented side by side in `aks-mapping/README.md` (verify: current Entra behaviour). Keep token lifetimes short. |
| The Vault injector's webhook is in the admission path | `failurePolicy: Fail` on purpose: a pod with no credential must not start silently |
| The dev-mode Vault root token exists for the run | Ephemeral cluster. Stage 12 counts the token and every value in the state files and the audit log, and each count must be 0 |
| Scope creep: Kubernetes keeps taking time from Entra, PAM and IGA work | This ADR freezes the segment. It appears only as a box on the architecture map and in the separate Kubernetes companion clip (`STAND-INS.md`). |

**Executed so far:** the local pipeline ran green on the lab Mac on
2026-10-20, its end-to-end stage passing 64/64 (details in
`lab/k8s/README.md`). Not yet run: the
`k8s identity pipeline` GitHub Actions job (fill after running: run URL and
result).

## Revisit trigger

- The scenario gets a real AKS cluster. Apply `aks-mapping` against it and
  swap the Vault role for the Key Vault CSI driver and Workload ID.
- Workloads must call each other with mutual authentication. Reopen
  option 3 (SPIFFE or mesh).
- An application can only read environment variables or Secrets. Write an
  ADR that accepts External Secrets with the value stored in etcd.

## Evidence

- `lab/k8s/README.md`: problem, architecture, tests, and §3 decisions
  (injector vs. CSI vs. ESO, projected tokens, TokenReview vs. JWKS, the
  four admission rules)
- `lab/k8s/ci/pipeline.sh`, `lab/k8s/test/k8s-e2e.sh`,
  `lab/k8s/kind/audit-policy.yaml`, `lab/k8s/manifests/`
- `lab/terraform/k8s/platform/`, `lab/terraform/k8s/identity/`,
  `lab/terraform/k8s/aks-mapping/`
- `lab/docs/STAND-INS.md`: the three Kubernetes rows and the "never
  applied" note
