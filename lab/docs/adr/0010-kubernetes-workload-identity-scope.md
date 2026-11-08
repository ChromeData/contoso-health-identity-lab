# ADR 0010: Kubernetes workload identity scope

- **Status:** Accepted. Amended 2026-11-06: Azure Key Vault, Microsoft Entra
  Workload ID and the Secrets Store CSI Driver replace the HashiCorp Vault
  stand-in (ADR 0036, "Microsoft-native PAM"). The scope (one workload, one
  secret, one exchange) is unchanged.
- **Date:** 2026-10-20 (amended 2026-11-06)
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Clinical batch jobs on Kubernetes need database credentials. The common
patterns are a Kubernetes Secret, an environment variable, or a legacy
service-account token Secret. All three are "secret zero": a long-lived
credential protected only by nobody copying it.

Kubernetes is a minor part of an IAM role compared with Entra, PAM and
governance. The segment has to prove the identity pattern without turning
into a platform-engineering project or needing a paid AKS cluster.

## Options considered

1. **Real AKS with Entra Workload ID and the Key Vault CSI driver.** It is
   the production target. It needs a paid cluster for every run.
2. **kind, rebuilt for every run, with the same Microsoft identity path:**
   the cluster's service-account issuer published on a public HTTPS URL,
   an Entra federated credential that trusts it, and the Key Vault CSI
   driver in the cluster. Only the cluster is a stand-in.
3. **kind with HashiCorp Vault's Kubernetes auth and the Agent Injector.**
   The original choice (2026-10-20). Retired 2026-11-06: Microsoft offers
   the product (Key Vault + Workload ID), and the lab uses Microsoft where
   Microsoft has one (ADR 0036).
4. **A full workload-identity platform:** SPIFFE/SPIRE or service-mesh mTLS,
   multi-cluster, External Secrets, and policy engines (Kyverno,
   Gatekeeper). Broader, but each piece adds operational surface and moves
   the work away from identity.
5. **Leave Kubernetes out.** Loses the non-human-identity story for
   containerised workloads.

## Decision

Option 2, scoped to **one workload, one secret, one exchange**.

**In scope (built and tested):**
- The CSI driver requests a service-account token for the pod, audience
  `api://AzureADTokenExchange`, at most 10 minutes. No container ever holds
  it, and the Kubernetes API refuses it.
- Microsoft Entra ID exchanges it for a Key Vault access token. The trust is
  one federated credential: one issuer, one subject
  (`system:serviceaccount:clinical-apps:nightly-report`), one audience. The
  app registration has no client secret and no certificate.
- Azure RBAC: **Key Vault Secrets User on one secret** (`clinical-db`), not
  on the vault. A decoy secret in the same vault is refused.
- The secret is a file in a tmpfs CSI volume. No Kubernetes Secret (no
  `secretObjects`, Secret sync off) and no environment variable.
- Rotation without a restart (the driver re-reads every 10 s).
- Human RBAC for two impersonated groups.
- A ValidatingAdmissionPolicy with four rules. It ties the identity to the
  approved image digest (rule 2), requires digest pinning (rule 1) and
  disabled token automount (rule 3), and lets only the release pipeline
  create or change a workload that runs as that identity (rule 4).
- Drift detect-and-heal through `terraform plan -detailed-exitcode`.
- An audit policy that never logs a token or Secret body.
- A zero count of secret values in three Terraform states and the audit log.
- Human access to the LAB vault (kv-idlab) through PIM: an eligible
  Key Vault Secrets Officer group, flag off
  (`modules/pim/keyvault.tf`, `enable_pim_keyvault_officers`).

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
- The identity path is the production one: the same federated credential,
  RBAC role and SecretProviderClass work on AKS with only the issuer URL
  changed (AKS publishes its own).
- The admission policy is upstream Kubernetes (VAP, GA since 1.30), so the
  same object applies on AKS.
- Cents per run: one throwaway resource group (storage static website +
  Key Vault Standard), deleted and the vault purged at teardown, read back
  as gone.

**Negative, said plainly**
- **CI no longer builds the cluster.** The live stages create an app
  registration, which needs a Tier-0-class identity. The lab will not put a
  standing one in GitHub Actions (ADR 0024: one operator, one kill switch).
  CI runs the static stages; the live run is the operator on the lab Mac.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| kind is not AKS. The audit policy is a file the lab chooses, whereas AKS manages its own policy and exposes it through diagnostic settings. | Stated in the `STAND-INS.md` kind row (verify: AKS audit categories). Claims are limited to upstream behaviour. |
| Entra validates the token offline against the issuer's JWKS. A token whose service account was deleted stays exchangeable until it expires, unlike Vault's TokenReview. | Token lifetime is capped at 10 minutes (the driver's request). The e2e test shows the API server itself refuses such a token (401). verify: measure the Entra side with a second federated credential. |
| The issuer's keys are on a public website. Whoever can write that container can make Entra trust their own keys. | The website is a throwaway storage account per run; only the operator (Storage Blob Data Contributor) writes it, and it is deleted at teardown. Production: AKS's managed issuer. |
| The CSI node plugin runs privileged, and its ClusterRole may create service-account tokens (for rotation). | Its own namespace, PSA enforce privileged with warn and audit at baseline. Its tokens carry only the exchange audience, which the API server refuses; Entra accepts one only for a service account with a federated credential. |
| A per-secret role assignment is "not recommended" by Microsoft Learn outside listed exceptions; it recommends a vault per app per environment. | The lab does both: the vault is per run and holds this app's secret and a decoy, and the role is on the one secret, so the test can prove the decoy is refused. Production: a vault per app, role at vault scope. |
| Scope creep: Kubernetes keeps taking time from Entra, PAM and IGA work | This ADR freezes the segment. It appears only as a box on the architecture map and in the separate Kubernetes companion clip (`STAND-INS.md`). |

**Executed so far:** RAN · tenant on 2026-11-07, the full pipeline as the
lab operator: 12/12 stages, `K8S E2E PASSED (66/66)`, 0 secret hits in three
states and the audit log, teardown read back clean, 507 s
(`lab/evidence/k8s-keyvault/20261107T013045Z/`). Measured: the Entra access
token for Key Vault lives 65 minutes (the Vault token lived 15); the
driver's service-account token lives 10. The Vault version ran green on
2026-10-20 (64/64, `lab/evidence/k8s/20261020T202112Z/`); that record stays
as history.

## Revisit trigger

- The scenario gets a real AKS cluster. Point `keyvault-trust` at its OIDC
  issuer and move the role to vault scope on a vault per app.
- Workloads must call each other with mutual authentication. Reopen
  option 4 (SPIFFE or mesh).
- An application can only read environment variables or Secrets. Write an
  ADR that accepts Secret sync (`secretObjects`) with the value in etcd.

## Evidence

- `lab/k8s/README.md`: problem, architecture, tests, decisions
- `lab/k8s/ci/pipeline.sh`, `lab/k8s/ci/azure.sh`, `lab/k8s/test/k8s-e2e.sh`,
  `lab/k8s/kind/`, `lab/k8s/manifests/`
- `lab/terraform/k8s/platform/`, `lab/terraform/k8s/identity/`,
  `lab/terraform/k8s/keyvault-trust/`
- `lab/terraform/modules/pim/keyvault.tf` (human path, flag off)
- `lab/docs/STAND-INS.md`: the Kubernetes rows
