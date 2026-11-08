# k8s — Kubernetes workload identity as code (three applied roots)

**What is real, said up front:** Azure Key Vault holds the secret,
Microsoft Entra Workload ID trusts the cluster's service-account tokens, and
the Secrets Store CSI Driver with the Azure provider mounts the value into
the pod. The cluster is **kind** (Kubernetes in Docker), standing in for
**AKS**, and the human groups are **impersonated** Kubernetes groups
standing in for Entra groups. See
[`lab/docs/STAND-INS.md`](../../docs/STAND-INS.md). Until 2026-11-06 an
in-cluster HashiCorp Vault stood in for the secret store; ADR 0036 retired it.

The segment as a whole (cluster config, workload manifests, the one pipeline
script, the e2e test, the CI workflow) is described in
[`lab/k8s/README.md`](../../k8s/README.md). This directory holds only its
Terraform.

| Root | Applied in | Owns | Providers |
|---|---|---|---|
| [`keyvault-trust/`](keyvault-trust/README.md) | stage 4, as the operator | app registration (no credential), one federated identity credential for `system:serviceaccount:clinical-apps:nightly-report` (audience `api://AzureADTokenExchange`), Key Vault Secrets User on ONE secret | `hashicorp/azuread ~> 3.10`, `hashicorp/azurerm ~> 4.0` |
| [`platform/`](platform/README.md) | stage 6 | namespaces `secrets-store` + `clinical-apps` with Pod Security Admission labels; the Secrets Store CSI Driver + Azure Key Vault provider Helm release | `hashicorp/helm ~> 3.3.0`, `hashicorp/kubernetes ~> 3.3.0` |
| [`identity/`](identity/README.md) | stage 7 | the two workload service accounts; the SecretProviderClass for the one secret; human RBAC (Roles + RoleBindings for two groups; pods and ReplicaSets read-only for the deployer); ValidatingAdmissionPolicy `clinical-apps-workload-identity` | `hashicorp/kubernetes ~> 3.3.0` |

## Why separate roots

- **keyvault-trust** talks to Entra and Azure, the other two to the
  cluster. Separate state, separate credentials: the cluster roots never
  hold an Azure identity.
- **platform before identity:** the SecretProviderClass is a custom
  resource. `kubernetes_manifest` needs its CRD at plan time, and the CSI
  driver chart installs that CRD. The Kubernetes provider docs say the
  resources a provider's configuration depends on should not be created in
  the same module that uses them (verify: wording on the current page).

```
azure objects + keyvault-trust ─► kind create (public issuer) ─► platform ─► identity ─► kubectl apply ─► e2e
 (vault, secret value via az,       (discovery doc + JWKS          (CSI         (SA, SPC,
  never in state)                    copied to the website)         driver)      RBAC, VAP)
```

## Secrets and state

- **State is local** (no backend) and lives exactly as long as the run;
  `lab/k8s/ci/pipeline.sh` destroys all three. `*.tfstate` is gitignored.
- **No secret value is in any state file.** The pipeline sets the value in
  Key Vault through az (stage 4) and rotates it there (stage 9); Terraform
  never sees it. No client secret exists. Stage 12 counts every version of
  the secret and the decoy in all three states and the audit log: 0.
- The **lock files are committed**, generated with Terraform 1.16.5:
  `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64`.
  `keyvault-trust` locks azuread 3.10.0 and azurerm 4.81.0, the builds the
  rest of the lab locks.

## Running

The supported path is the pipeline, as the lab operator (it creates and
deletes throwaway Azure objects):

```bash
lab/scripts/operator/op lab/k8s/ci/pipeline.sh
```

Offline checks only (no cluster, no Azure, mocked providers):

```bash
for r in platform identity keyvault-trust; do
  terraform -chdir=lab/terraform/k8s/$r init -backend=false -lockfile=readonly
  terraform -chdir=lab/terraform/k8s/$r validate
  terraform -chdir=lab/terraform/k8s/$r test
done
terraform -chdir=lab/terraform fmt -check -recursive
```
