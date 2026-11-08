# k8s/keyvault-trust — the Entra and Key Vault side of the workload's identity

**Applied for real, one run at a time.** `lab/k8s/ci/pipeline.sh` applies this
root in stage 4, as the lab operator, and destroys it at teardown. Until
2026-11-06 it was `aks-mapping`, a plan-only mapping of the HashiCorp Vault
role. ADR 0036 replaced Vault with Azure Key Vault, and the kind cluster now
publishes its service-account issuer on a public HTTPS URL. So the same
federated credential is now used, not just written.

| Object | Terraform | What it is |
|---|---|---|
| App registration | `azuread_application.nightly_report` | `k8s-nightly-report-<run id>`. No password, no certificate. It can sign in only with a federated token. |
| Service principal | `azuread_service_principal.nightly_report` | The app's identity in the tenant (the RBAC assignee). |
| Federated identity credential | `azuread_application_federated_identity_credential.nightly_report` | Trusts ONE issuer (`var.issuer_url`, this run's storage static website), ONE subject (`system:serviceaccount:clinical-apps:nightly-report`), ONE audience (`api://AzureADTokenExchange`). Entra matches all three exactly. |
| Role assignment | `azurerm_role_assignment.secret_reader` | **Key Vault Secrets User** (`4633458b-…`, by id) on `<vault id>/secrets/clinical-db`: one secret, not the vault. |

Providers: `hashicorp/azuread` 3.10.0 and `hashicorp/azurerm` 4.81.0 (the
lab's locked builds), hashes for `linux_amd64` and `darwin_arm64`.

## How a pod uses it

1. The Secrets Store CSI Driver requests a token for the pod's service
   account, audience `api://AzureADTokenExchange`.
2. The Azure provider sends it to Entra as a client assertion.
3. Entra reads `<issuer>/.well-known/openid-configuration`, follows
   `jwks_uri`, checks the signature, then issuer, subject and audience
   against this credential. It returns a Key Vault access token.
4. Key Vault checks Azure RBAC: this service principal may read one secret.

Sources (Microsoft Learn): "Workload identity federation", "Access Azure Key
Vault with the CSI Driver Identity Provider" (Workload ID), "Grant
permission to applications to access an Azure key vault using Azure RBAC".

## Why the role is on one secret (the trade-off)

Microsoft Learn recommends a vault per application per environment, with
roles at **vault** scope, and calls per-secret assignments "not
recommended" outside a few exceptions. The lab does both: the vault exists
for one run and holds this app's secret plus a decoy, and the role is on the
one secret. That lets the e2e test prove that a second secret in the same
vault is refused. Production: a vault per app per environment, role at vault
scope.

## Vault role ↔ this root (for reviewers who knew the Vault version)

| Vault (retired 2026-11-06) | Here |
|---|---|
| Role bound to one SA + namespace + audience `vault` | Federated credential: exact subject + audience `api://AzureADTokenExchange` |
| Vault calls TokenReview at every login (live) | Entra checks the issuer's JWKS (offline): a token stays exchangeable until its `exp`, service account deleted or not (verify: current Entra behaviour) |
| Policy `nightly-report-read` on one path | Key Vault Secrets User on one secret |
| Vault token TTL 15 min | Entra access token; its lifetime is set by Entra (the e2e test prints it) |

Both trust namespace + name, not the service account's UID.

## Run the checks offline

```bash
terraform -chdir=lab/terraform/k8s/keyvault-trust init -backend=false -lockfile=readonly
terraform -chdir=lab/terraform/k8s/keyvault-trust validate
terraform -chdir=lab/terraform/k8s/keyvault-trust test     # mocked azuread + azurerm, 6 runs
```

`tests/keyvault_trust.tftest.hcl` pins: the subject, the one audience, the
issuer verbatim, the role (by id) on the one secret, the assignee, that
`../identity` still creates `clinical-apps/nightly-report`, and that the
kind default issuer, a trailing slash and plain HTTP are refused.

## On AKS

Set `issuer_url` to the cluster's `oidcIssuerProfile.issuerUrl` and drop
the throwaway vault for a vault per app. Nothing else changes.
