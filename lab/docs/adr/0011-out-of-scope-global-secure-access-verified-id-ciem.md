# ADR 0011: Scope boundaries: Kubernetes kept small; Global Secure Access, Verified ID and CIEM left out

- **Status:** Accepted. The Kubernetes segment is frozen at the scope below. **Absorbs ADR 0010** (Kubernetes workload identity scope), merged on 2026-10-21; [0010](0010-kubernetes-workload-identity-scope.md) is kept as a pointer.
- **Date:** 2026-10-20 (merged 2026-10-21)
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The scenario's priorities are HR-driven JML, Conditional Access, zero
standing admin, vaulted Tier-0 credentials, governance, and detection and
response. Four adjacent areas compete for the same build and trial time.
Saying what is kept small, what is left out and what would bring each back
is part of the design: a reviewer can't otherwise tell an omission from a
miss.

## Options considered

1. **Build a small demo of each.** Breadth without depth; each needs its own
   licence or trial and no scenario requirement backs it.
2. **A full workload-identity platform** (SPIFFE/SPIRE, mesh mTLS,
   multi-cluster, External Secrets, Kyverno or Gatekeeper). Each piece adds
   operational surface and moves the work away from identity.
3. **Real AKS with Entra Workload ID and the Key Vault CSI driver.** The
   production target, but it needs cloud spend and credentials in CI, and a
   public OIDC issuer.
4. **Keep Kubernetes to one workload on a throwaway cluster, leave the other
   three out, and record a trigger for each (chosen).**
5. **Say nothing.** Rejected.

## Decision

**Kubernetes: one workload, one secret, one exchange.** kind, rebuilt on
every run, with Vault's Kubernetes auth and the Agent Injector:

- a projected service-account token, audience `vault`, 600 s, mounted only
  into the agent containers;
- Vault Kubernetes auth with TokenReview, bound to service account,
  namespace and audience, returning a 15-minute token that reads one path;
- the secret rendered to a tmpfs file, with no Kubernetes Secret and no
  environment variable, rotated without a restart;
- a ValidatingAdmissionPolicy that ties the identity to approved image
  digests and lets only the release pipeline create or change a workload
  that runs as it;
- an audit policy that never logs a token or Secret body, and zero secrets
  in Terraform state.

The Entra Workload ID federated credential for
`system:serviceaccount:clinical-apps:nightly-report` is written
(`lab/terraform/k8s/aks-mapping`) and checked offline, **never applied**.
Out of scope: SPIFFE/SPIRE, mesh mTLS, multi-cluster trust, External
Secrets Operator (its secret lands in etcd), Kyverno and Gatekeeper.
Technical detail: `lab/k8s/README.md` §3.

**Left out:**

| Capability | Why it is out | What covers the need today | Revisit trigger |
|---|---|---|---|
| **Global Secure Access** (Entra Private Access / Internet Access) | The only on-prem admin path is RDP to DC01, NSG-limited to the operator and brokered through recorded sessions (ADR 0013). No on-prem apps are published for remote clinicians | CA on every cloud app; Tier-0 access only through vaulted, recorded sessions (ADR 0007) | A VPN replacement project, or on-prem clinical apps that need remote access |
| **Entra Verified ID** | No requirement for portable credentials or remote identity proofing: HR vouches for joiners, and day 1 uses a TAP from the joiner workflow | HR as the source of truth (ADR 0006) and the TAP joiner workflow | Fully remote hiring that needs proofing, or credential exchange with affiliated hospitals or agencies |
| **CIEM** | Microsoft retired Entra Permissions Management on 2025-11-01. The scenario's cloud permissions are small and already code: one AWS `ViewOnlyAccess` permission set, Entra roles through PIM, PIM for Azure resource roles (`modules/pim/azure.tf`, off by default) | Permission sets and PIM as reviewed code; access reviews (ADR 0008) | Multi-account AWS or multi-subscription Azure beyond what PR review can reason about, or a finding of unused high-privilege cloud permissions |

## Consequences

- **Kubernetes costs $0 and no cloud credentials, and it is reproducible.**
  One script (`ci/pipeline.sh`, 12 stages) builds, asserts and tears down.
  RAN · harness: 12/12 stages, end-to-end 64/64
  (`lab/evidence/k8s/20261020T202112Z/`). The GitHub Actions job has not
  passed yet; it has run only on Dependabot pull requests.
- **kind is not AKS.** The audit policy is a file the lab chooses; AKS
  manages its own. Claims are limited to upstream behaviour, and
  `STAND-INS.md` says so.
- **Entra validates a federated token against the issuer's keys,** so a
  token whose service account was deleted stays usable until it expires,
  unlike Vault's TokenReview. Keep token lifetimes short
  (`aks-mapping/README.md`).
- **The injector's webhook is in the admission path** with
  `failurePolicy: Fail` on purpose: a pod with no credential must not start
  silently.
- **Trial and build time go to the controls the scenario depends on,** and
  each omission is visible as a decision with its reversal named.
- **Unused cloud permissions can build up without CIEM.** Keep them as code
  with PR review; turn on PIM for Azure resources when there are any to
  protect.

## Revisit trigger

- The scenario gets a real AKS cluster: apply `aks-mapping`, swap the Vault
  role for Workload ID and the Key Vault CSI driver.
- Workloads must authenticate to each other: reopen SPIFFE or mesh mTLS.
- An application can read only environment variables or Secrets: a new ADR
  that accepts External Secrets with the value in etcd.
- Any trigger in the table above, or a scenario change: an acquisition, a
  new cloud, a regulatory requirement for identity proofing.

## Evidence

- `lab/k8s/README.md` (problem, architecture, tests, §3 decisions),
  `lab/k8s/ci/pipeline.sh`, `lab/k8s/test/k8s-e2e.sh`,
  `lab/k8s/kind/audit-policy.yaml`, `lab/k8s/manifests/`
- `lab/terraform/k8s/platform/`, `identity/`, `aks-mapping/`
- `lab/evidence/k8s/20261020T202112Z/` (hashed run record)
- `lab/terraform/aws/main.tf` (`aws_ssoadmin_permission_set.view_only`)
- `lab/terraform/modules/dc-vm/main.tf` (NSG: RDP and LDAPS from the
  operator only); `lab/terraform/modules/pim/azure.tf`
- `lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1` (joiner TAP)

## Sources (checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/permissions-management/overview
  (Permissions Management retired 2025-11-01)
