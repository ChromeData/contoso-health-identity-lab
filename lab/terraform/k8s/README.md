# k8s — Kubernetes workload identity as code (two applied roots + one plan-only)

**Stand-ins, said up front:** the cluster is **kind** (Kubernetes in Docker),
standing in for **AKS**. Vault's Kubernetes auth method and Agent Injector
stand in for **Entra Workload ID + the Key Vault CSI driver** on AKS (the
target, ADR 0036). The human groups are **impersonated** Kubernetes groups standing in for
Entra groups. Nothing in Azure runs here. See
[`lab/docs/STAND-INS.md`](../../docs/STAND-INS.md).

The segment as a whole (cluster config, workload manifests, the one pipeline
script, the e2e test, the CI workflow) is described in
[`lab/k8s/README.md`](../../k8s/README.md). This directory holds only its
Terraform.

| Root | Stage | Owns | Providers |
|---|---|---|---|
| [`platform/`](platform/README.md) | 1 | namespaces `vault` + `clinical-apps` with Pod Security Admission labels; the Vault Helm release (dev-mode server + Agent Injector) | `hashicorp/helm ~> 3.3.0`, `hashicorp/kubernetes ~> 3.3.0` |
| [`identity/`](identity/README.md) | 2 | Vault KV v2 mount, read-only policy, Kubernetes auth method + role; the two workload service accounts; human RBAC (Roles + RoleBindings for two groups; pods and ReplicaSets read-only for the deployer); ValidatingAdmissionPolicy `clinical-apps-workload-identity` | `hashicorp/vault ~> 5.12.0`, `hashicorp/kubernetes ~> 3.3.0` |
| [`aks-mapping/`](aks-mapping/README.md) | never applied | the Entra Workload ID equivalent of the Vault role: one federated identity credential for `system:serviceaccount:clinical-apps:nightly-report`, audience `api://AzureADTokenExchange`. `fmt`/`validate`/mocked `test` only: Entra must fetch the issuer's JWKS, and kind's issuer is not public | `hashicorp/azuread ~> 3.10` |

## Why two stages

A Terraform provider is configured before any resource in its root is
created. The Vault provider connects to Vault when it starts (it reads the
server version), so it cannot live in the same root that installs Vault:
on a fresh cluster there is nothing to connect to yet. Splitting the roots
makes the dependency explicit and keeps each plan honest:

```
kind create cluster ─► platform apply ─► identity apply ─► seed secret ─► kubectl apply ─► e2e test
                       (Vault exists)    (Vault configured)  (value via API,
                                                              never in state)
```

The alternatives (one root applied twice with `-target`, or a provider
configured from a resource attribute) both leave a plan that cannot be
computed on a fresh cluster. Separate roots follow HashiCorp's own guidance:
the Kubernetes provider docs say the resources a provider's configuration
depends on should not be created in the same module that uses that provider
(verify: wording on the current provider docs page).

## Secrets and state

- **State is local** (no backend) and lives exactly as long as the kind
  cluster; `lab/k8s/ci/pipeline.sh` destroys both. `*.tfstate` is gitignored
  by `lab/terraform/.gitignore`.
- **No secret value is in either state file.** The Vault dev root token is an
  ephemeral variable that reaches Helm only through the write-only `set_wo`
  (stage 1) and the Vault provider block (stage 2). The workload secret's value
  is seeded by the pipeline through the Vault HTTP API after stage 2, so
  Terraform never sees it.
- The **lock files are committed** (`.terraform.lock.hcl` in each of the
  three roots), generated with Terraform 1.16.5:
  `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64`.
  `aks-mapping` locks `hashicorp/azuread` 3.10.0, the version the lab's other
  Entra roots lock.

## Running

The supported path is the pipeline, which does everything in order and tears
it down afterwards (`KEEP_CLUSTER=1` keeps the cluster for poking around):

```bash
lab/k8s/ci/pipeline.sh
```

Offline checks only (no cluster, no Vault, mocked providers):

```bash
for r in platform identity aks-mapping; do
  terraform -chdir=lab/terraform/k8s/$r init -backend=false
  terraform -chdir=lab/terraform/k8s/$r validate
  terraform -chdir=lab/terraform/k8s/$r test
done
terraform -chdir=lab/terraform fmt -check -recursive
```
