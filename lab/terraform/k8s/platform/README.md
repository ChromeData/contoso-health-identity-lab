# k8s/platform — namespaces, Pod Security, the Key Vault CSI driver

**What is real:** the Secrets Store CSI Driver (Kubernetes SIG Auth) and the
Azure Key Vault provider (Microsoft), installed from Microsoft's chart. kind
stands in for AKS. See [`lab/docs/STAND-INS.md`](../../../docs/STAND-INS.md).

Applied in pipeline stage 6, after `../keyvault-trust` and the cluster, and
before [`../identity`](../identity/README.md).

| Object | Terraform | Value |
|---|---|---|
| Namespace `secrets-store` | `kubernetes_namespace_v1.secrets_store` | PSA `enforce=privileged`, `warn`/`audit=baseline` (`v1.36`): the CSI node plugin needs privileged hostPath mounts; the warn/audit labels keep the exception visible |
| Namespace `clinical-apps` | `kubernetes_namespace_v1.clinical_apps` | PSA `enforce`/`warn`/`audit=restricted` (`v1.36`) |
| CSI driver + Azure provider | `helm_release.csi_secrets_store_provider_azure` | chart `csi-secrets-store-provider-azure` **1.8.2** (2026-06-11) with its dependency `secrets-store-csi-driver` **1.5.6**; every image from `mcr.microsoft.com/oss/v2/…` pinned by digest (provider `v1.8.2@sha256:6be39190…`, driver `sha256:5f91243c…`, registrar, liveness probe, CRD job) |

## Decisions

**One token audience.** The driver asks the kubelet for service-account
tokens with audience `api://AzureADTokenExchange` only (CSIDriver
`tokenRequests`). The chart default also lists `api://AKSIdentityBinding`,
an AKS-only feature; it is dropped. The Kubernetes API refuses tokens with
this audience, so they open nothing in the cluster.

**Rotation on, every 10 s.** `enableSecretRotation` + `rotationPollInterval
= 10s`: a new version in Key Vault becomes the new file content in the same
pod (pipeline stage 9). The cost is one Key Vault read per pod every 10 s
(Key Vault Standard: $0.03 per 10,000 operations). Production: minutes.

**No Secret sync.** `syncSecret.enabled = false`, and no SecretProviderClass
declares `secretObjects`. A Key Vault value never becomes a Kubernetes
Secret in etcd.

**What the driver may do, said plainly.** Its ClusterRole may create
service-account tokens (`serviceaccounts/token`), so rotation can fetch a
value without the kubelet. Those tokens carry only the exchange audience,
and Entra accepts one only for a service account with a federated
credential (`../keyvault-trust`).

**Pinned, not signed.** The chart is pinned by version and its digest is
recorded in `main.tf`; Helm provenance (`verify = true`) is not enabled (no
chart signing key is wired in). Accepted residual risk for an ephemeral lab
cluster.

## Tests

`tests/platform.tftest.hcl` (mocked providers, 3 runs): PSA levels per
namespace; chart and version; every image digest-pinned; exactly one token
audience; Secret sync off; rotation on at 10 s; the release waits; the
driver is not in `clinical-apps`; a non-kind context is refused.
