# k8s/identity — workload service accounts, the Key Vault SecretProviderClass, human RBAC, admission policy

**What is real:** the SecretProviderClass is served by the Azure Key Vault
provider through Microsoft Entra Workload ID. The two human groups are
**impersonated** Kubernetes groups standing in for **Entra groups via AKS
Entra integration**. kind stands in for AKS. See
[`lab/docs/STAND-INS.md`](../../../docs/STAND-INS.md).

Applied in pipeline stage 7, after [`../platform`](../platform/README.md)
(the SecretProviderClass CRD comes from the CSI driver chart:
[`../README.md`](../README.md#why-separate-roots)).

| Object | Terraform | Value |
|---|---|---|
| Service accounts | `kubernetes_service_account_v1.workload` | `nightly-report` (approved; annotated `azure.workload.identity/client-id=<app>`), `unapproved-job` (negative control); `automountServiceAccountToken: false` on both |
| SecretProviderClass | `kubernetes_manifest.secret_provider_class` | `nightly-report-db`: provider `azure`, `usePodIdentity: "false"`, `clientID` = the app from `../keyvault-trust`, `keyvaultName`, `tenantId`; ONE object (secret `clinical-db`, file `db`); no `secretObjects` |
| Roles | `kubernetes_role_v1.human` | `app-deployer`, `auditor` (namespaced, `clinical-apps`); pods are read-only for both, ReplicaSets read-only for `app-deployer` |
| RoleBindings | `kubernetes_role_binding_v1.human` | `app-deployer` → Group `k8s-clinical-deployers`; `auditor` → Group `k8s-clinical-auditors`. No ClusterRoleBinding |
| Admission policy | `kubernetes_manifest.workload_identity_policy` + `kubernetes_manifest.workload_identity_policy_binding` | ValidatingAdmissionPolicy `clinical-apps-workload-identity` (`admissionregistration.k8s.io/v1`), `failurePolicy: Fail`, binding `validationActions: [Deny]`; CREATE/UPDATE of Pods (+ `pods/ephemeralcontainers`), Deployments, ReplicaSets in `clinical-apps` only. Four CEL rules, below |

Inputs (`TF_VAR_*` from the pipeline, identifiers only): `tenant_id`,
`workload_client_id`, `key_vault_name`, `secret_name` (default
`clinical-db`).

## The exchange this sets up

```
kubelet mounts the CSI volume ─► CSI driver: TokenRequest for SA nightly-report,
                                 aud=api://AzureADTokenExchange, <= 10 min (never in a container)
Azure provider ─► Microsoft Entra ID: client_credentials + that token as client assertion
Entra: issuer JWKS signature, issuer, subject, audience = the federated credential? ─► Key Vault token
Key Vault: Azure RBAC, Secrets User on clinical-db only ─► value
CSI driver ─► /mnt/secrets-store/db (tmpfs, read-only, in the pod); re-read every 10 s
```

No Kubernetes Secret, env var or manifest value holds the password at any
point, and neither does Terraform state.

## Decisions (and the alternatives)

| Decision | Why | Alternative not taken |
|---|---|---|
| **CSI volume, not an SDK in the app** | The app reads a file; it holds no token and needs no Azure library (Microsoft Learn: the CSI flow needs neither MSAL nor Azure Identity) | The Workload ID webhook + Azure Identity in the app: the app then holds a token |
| **No `secretObjects`** | The value never becomes a Kubernetes Secret in etcd | Secret sync: needed only for apps that can read env vars or Secrets alone (ADR 0010 revisit trigger) |
| **`clientID` in the SecretProviderClass, annotation on the SA** | The provider reads the client id from the class (Learn, Workload ID tab); the SA annotation records the pairing on the identity and is what AKS's webhook reads | Annotation only: the CSI provider would not find it |
| **One SA trusted, one decoy SA** | `unapproved-job` proves an identity in the same namespace gets nothing (Entra refuses it, and a real pod naming this class never starts) | Wildcards: a classic federated credential has none, by design |
| **Secret value outside Terraform** | State never holds it; the pipeline sets it in Key Vault and keeps only its SHA-256 for the test | `azurerm_key_vault_secret` with a value: it would sit in state |
| **Namespaced Roles + RoleBindings only** | A grant cannot reach beyond `clinical-apps` | ClusterRole + RoleBinding (fine, not needed); ClusterRoleBinding (cluster-wide, never for app teams) |
| **No `secretproviderclasses` for humans** | Editing the class could point it at another vault object | Letting the deployer manage it |
| **Pods and ReplicaSets read-only for `app-deployer`** | Writing a pod is how a running container's image gets swapped and how a bare pod runs as any SA; deleting a ReplicaSet makes the Deployment controller recreate it, a restart rule 4 otherwise refuses | Keep pod / ReplicaSet writes and rely on admission alone |
| **ValidatingAdmissionPolicy (CEL, in the API server)** | No extra pod, no TLS, cannot be "down" and fail open; GA since 1.30 | A validating webhook or Kyverno/Gatekeeper |
| **Policy compares digests, not image strings** | The kubelet verifies content against the digest, so the digest is the code | Exact string match: brittle, and no safer |
| **`kubernetes_manifest` with `force_conflicts = true`** | Terraform is the authority on every field it declares, so an out-of-band edit is detected by `plan` and healed by `apply` | Without it, a kubectl edit takes field ownership and `apply` stops on a conflict |

**Human RBAC rules.** `app-deployer`: get/list/watch/create/update/patch/delete
on deployments, configmaps, services; **get/list/watch only on pods and
replicasets**; get on `pods/log`. `auditor`: get/list/watch on pods,
deployments, services, configmaps, events. Neither role has `secrets`,
`secretproviderclasses`, any RBAC resource, `serviceaccounts` /
`serviceaccounts/token`, `pods/exec|attach|portforward|proxy|ephemeralcontainers`,
`nodes` / `nodes/proxy`, the impersonation targets, or the verbs
`impersonate` / `escalate` / `bind`.

## Who can act as nightly-report

Kubernetes lets anyone who can create a pod in a namespace run it as **any**
service account in that namespace, and a running pod's container image can
be changed in place. Left alone, "can deploy" would mean "can be
nightly-report" and so "can read `/mnt/secrets-store/db`". Three layers stop
that, and the e2e test exercises each:

1. **RBAC:** `app-deployer` cannot create, update, patch or delete pods or
   ReplicaSets.
2. **Admission:** ValidatingAdmissionPolicy `clinical-apps-workload-identity`
   (Deny, fail closed). Rules, in the order they are reported:

   | # | Rule (CEL) | Message starts with |
   |---|---|---|
   | 1 | every container, init container and ephemeral container image ends in `@sha256:<64 hex>` | `image not pinned by digest:` |
   | 2 | a workload running as `nightly-report` runs only the approved app digest (`var.nightly_report_app_image`) | `service account nightly-report may run only the approved app image` |
   | 3 | `spec.automountServiceAccountToken` is `false` in the pod spec | `automountServiceAccountToken must be false in the pod spec` |
   | 4 | a workload running as `nightly-report` is created or changed only by `var.nightly_report_launcher_groups` (default `kubeadm:cluster-admins`, the kind admin = the pipeline) or the kube-system controllers; on an UPDATE, "running as" is checked on the object before (`oldObject`) **and** after | `only the release pipeline may create or change a workload that runs as service account nightly-report` |

   Rule 2 binds the identity to **code**; rule 4 binds it to **who deploys
   it**. Rule 4 closes "same approved image, different command" (the app
   image is a general-purpose busybox, so rule 2 alone would let a deployer
   patch the `args` to print the file into `pods/log`). Rule 4 reads both
   sides of an UPDATE, so one patch cannot move the live Deployment to
   another SA and rewrite it at the same time.
3. **Entra + Key Vault:** the federated credential trusts one subject; the
   role is on one secret. Naming the SecretProviderClass is not enough: the
   CSI driver always asks for a token for the POD's own service account.

**Nothing is injected.** The CSI driver adds no container, so rule 2's
allowlist is the app digest alone. (The Vault version also allowed the
injected agent's digest.)

**Pod Security still answers first.** PSA is a built-in validating plugin
ordered before ValidatingAdmissionPolicy, so the privileged negative pod is
rejected with the `violates PodSecurity "restricted:v1.36"` message.

**What the policy does not stop, said out loud:** the deployer can still
delete the nightly-report Deployment (availability, not identity: DELETE is
not matched) and then create one of that name under another service
account, which no federated credential trusts; and it can run its own
digest-pinned workloads as the namespace's other service accounts. A
cluster admin can delete the policy itself; that is an audited admission
change, not a quiet one.

## Limits (said out loud)

- **The policy protects one identity.** Rules 2 and 4 name `nightly-report`.
  A second secret-bearing service account needs its own entries.
- **The launcher group is a lab stand-in.** `kubeadm:cluster-admins` is the
  kind admin certificate, i.e. the pipeline. On AKS it would be the GitOps
  controller's or release pipeline's identity, never a human team's group.
- **One drift case `apply` cannot heal in place:** `validationActions` is a
  set-typed list; a kubectl patch to `["Warn"]` is detected by `plan` but
  `apply` would produce the invalid `["Warn","Deny"]`. Heal it with
  `terraform apply -replace=kubernetes_manifest.workload_identity_policy_binding`.
- **Groups are impersonated** (`kubectl --as=<user> --as-group=<group>`): kind
  has no Entra sign-in. The RBAC evaluation is the same one an
  Entra-authenticated user would hit.

## What changes on AKS

| Here (kind) | AKS |
|---|---|
| Impersonated groups | **AKS-managed Microsoft Entra integration**: the same RoleBindings name the Entra group's **object ID**, or Azure RBAC for Kubernetes authorization expresses the same intent as Azure role assignments. Disable local accounts |
| Public issuer = a storage static website the pipeline fills | The cluster's own OIDC issuer (`--enable-oidc-issuer`); point `../keyvault-trust` `issuer_url` at it |
| CSI driver from Microsoft's Helm chart | The AKS add-on `azure-keyvault-secrets-provider` (same driver and provider) |
| ValidatingAdmissionPolicy | **Unchanged** (upstream Kubernetes); Azure Policy for AKS is the managed alternative for org-wide rules |

## Running

Normally via `lab/k8s/ci/pipeline.sh` (stage 7). `kubernetes_manifest`
needs the API server and the CRD at plan time; both exist by then.

## Offline checks

```bash
terraform -chdir=lab/terraform/k8s/identity init -backend=false -lockfile=readonly
terraform -chdir=lab/terraform/k8s/identity validate
terraform -chdir=lab/terraform/k8s/identity test     # mocked kubernetes provider, 8 runs
```

`tests/identity.tftest.hcl` pins: the SecretProviderClass (Azure provider,
Workload ID, this tenant, vault and client id, exactly one object
`clinical-db` as file `db`, no `secretObjects`), and that the Deployment
mounts it at `/mnt/secrets-store/db`; only `nightly-report` carries the
client id; both SAs have token automount off; no human rule grants
`secrets`, `secretproviderclasses`, SA tokens, RBAC, exec/attach/port-forward/
proxy, ephemeral containers, nodes, impersonation targets, the
impersonate/escalate/bind verbs, or wildcards; `app-deployer` can only
get/list/watch pods and ReplicaSets and keeps create/patch on Deployments;
`auditor` is read-only; every binding is a namespaced RoleBinding to a Role
with Group subjects; no `.tf` file declares a ClusterRole(Binding); the
admission policy is `v1`, `failurePolicy: Fail`, bound with exactly
`[Deny]`, matches CREATE+UPDATE of pods and deployments, is scoped to
`clinical-apps` twice, has the four rules in order (rule 4 reading
`oldObject`), and its allowlist is exactly the app digest, in agreement
with `lab/k8s/manifests/nightly-report.yaml`; a non-kind context, a
tag-only app image and a catch-all launcher group are rejected.

## Sources

- Microsoft Learn: "Access Azure Key Vault with the CSI Driver Identity
  Provider" (Workload ID tab: `usePodIdentity`, `clientID`, the
  SecretProviderClass and pod YAML); "Grant permission to applications to
  access an Azure key vault using Azure RBAC" (Key Vault Secrets User,
  secret-scope assignments); AKS Microsoft Entra integration.
- ValidatingAdmissionPolicy: kubernetes.io docs (*Validating Admission
  Policy*).
- Resource schemas: `terraform providers schema -json` for
  `hashicorp/kubernetes` 3.3.0.
