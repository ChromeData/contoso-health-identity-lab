# k8s/identity — Vault Kubernetes auth, workload service accounts, human RBAC, admission policy (stage 2 of 2)

**Stand-ins:** Vault's Kubernetes auth method stands in for **Entra Workload
ID + Azure Key Vault** on AKS (the target, ADR 0027). The two human groups are **impersonated** Kubernetes groups
standing in for **Entra groups via AKS Entra integration**. kind stands in for
AKS. See [`lab/docs/STAND-INS.md`](../../../docs/STAND-INS.md).

Applied after [`../platform`](../platform/README.md) (Vault must exist before
the Vault provider can connect: [`../README.md`](../README.md#why-two-stages)).

| Object | Terraform | Value |
|---|---|---|
| KV v2 mount | `vault_mount.clinical` | `clinical/` (the value of `clinical/db` is seeded by the pipeline, not here) |
| Policy | `vault_policy.nightly_report_read` | `nightly-report-read`: `read` on `clinical/data/db`, nothing else |
| Auth method | `vault_auth_backend.kubernetes` + `vault_kubernetes_auth_backend_config.in_cluster` | `auth/kubernetes`, host `https://kubernetes.default.svc:443`, Vault's own SA token as TokenReview reviewer |
| Vault role | `vault_kubernetes_auth_backend_role.nightly_report` | `nightly-report`: SA `nightly-report` in ns `clinical-apps` only, audience `vault`, policy `nightly-report-read`, token TTL = max TTL = 900 s |
| Service accounts | `kubernetes_service_account_v1.workload` | `nightly-report` (approved), `unapproved-job` (negative control); `automountServiceAccountToken: false` on both |
| Roles | `kubernetes_role_v1.human` | `app-deployer`, `auditor` (namespaced, `clinical-apps`); pods are read-only for both, ReplicaSets read-only for `app-deployer` |
| RoleBindings | `kubernetes_role_binding_v1.human` | `app-deployer` → Group `k8s-clinical-deployers`; `auditor` → Group `k8s-clinical-auditors`. No ClusterRoleBinding |
| Admission policy | `kubernetes_manifest.workload_identity_policy` + `kubernetes_manifest.workload_identity_policy_binding` | ValidatingAdmissionPolicy `clinical-apps-workload-identity` (`admissionregistration.k8s.io/v1`), `failurePolicy: Fail`, binding `validationActions: [Deny]`; CREATE/UPDATE of Pods (+ `pods/ephemeralcontainers`), Deployments, ReplicaSets in `clinical-apps` only. Four CEL rules, below |

## The exchange this sets up

```
kubelet ──projects──► 10-min token, sub=system:serviceaccount:clinical-apps:nightly-report, aud=vault
                                   │  (pod volume "vault-token", lab/k8s/manifests)
Vault Agent (injected sidecar) ────┴─► POST auth/kubernetes/login  role=nightly-report
Vault ──TokenReview (its own SA)──► API server: valid? audience "vault"? which SA?
Vault: SA name + namespace match the role? ──► Vault token, TTL 900 s, policy nightly-report-read
Agent ──► read clinical/data/db ──► /vault/secrets/db (memory-backed volume)
```

No Kubernetes Secret, env var or manifest value holds the password at any
point, and neither does Terraform state.

## Decisions (and the alternatives)

| Decision | Why | Alternative not taken |
|---|---|---|
| Role requires **audience `vault`** | A token the API server would accept (default audience) is refused by Vault, and a Vault-audience token is useless at the API server: neither can be replayed at the other | No audience check: any SA token, including one lifted from a pod's default mount, would log in |
| **TTL = max TTL = 15 min** | The agent renews inside the window and re-logs in with a fresh projected token at max TTL; a leaked Vault token is dead within 15 minutes | Long or periodic tokens: a leak stays useful until someone notices |
| **One SA, one namespace** | The role is the authorisation decision; `unapproved-job` proves an identity in the same namespace still gets nothing | Wildcards or `bound_service_account_namespace_selector`: convenient, and exactly how a role ends up trusting more than intended |
| **Alias keyed on SA UID** (`alias_name_source = serviceaccount_uid`) | A deleted-and-recreated SA with the same name gets a new Vault entity, not the old one's identity | Keying on the name (`serviceaccount_name`) |
| **Vault's own SA as TokenReview reviewer** (`disable_local_ca_jwt = false`, needs the chart's `system:auth-delegator` binding) | No long-lived reviewer JWT stored in Vault config | A dedicated reviewer SA with a static token Secret: the very thing this segment removes |
| **Policy written as JSON** | `tests/identity.tftest.hcl` can `jsondecode()` it and assert the exact path set and capabilities | HCL heredoc: readable, but only pattern-matchable in tests |
| **Secret value outside Terraform** | State never holds it; the pipeline seeds it via the Vault HTTP API and keeps only its SHA-256 for the test | `vault_kv_secret_v2` with the value: it would sit in state |
| **Namespaced Roles + RoleBindings only** | A grant cannot reach beyond `clinical-apps` | ClusterRole + RoleBinding (fine, but not needed); ClusterRoleBinding (cluster-wide, never for app teams) |
| **Pods and ReplicaSets read-only for `app-deployer`** | Writing a pod is how a running container's image gets swapped and how a bare pod runs as any SA; deleting a ReplicaSet makes the Deployment controller recreate it, a restart rule 4 otherwise refuses. Deployments still ship (the controllers write ReplicaSets and pods) | Keep pod / ReplicaSet writes and rely on admission alone |
| **ValidatingAdmissionPolicy (CEL, in the API server)** | No extra pod, no TLS, cannot be "down" and fail open; GA since 1.30 | A validating webhook or Kyverno/Gatekeeper: more expressive, but another service to run and secure |
| **Policy compares digests, not image strings** | The kubelet verifies content against the digest, so the digest is the code; `busybox@sha256:X` and `docker.io/library/busybox:1.37.0@sha256:X` are the same bytes | Exact string match: brittle, and no safer |
| **`kubernetes_manifest` with `force_conflicts = true`** | The provider has no typed binding resource; server-side apply with forced conflicts makes Terraform the authority on every field it declares, so an out-of-band edit is both detected by `plan` and healed by `apply` | Without it, a kubectl edit takes field ownership and `apply` stops on a conflict (seen on a scratch cluster) |

**Human RBAC rules.** `app-deployer`: get/list/watch/create/update/patch/delete
on deployments, configmaps, services; **get/list/watch only on pods and
replicasets**; get on `pods/log`. `auditor`: get/list/watch on pods, deployments,
services, configmaps, events. Neither role has `secrets`, any RBAC resource,
`serviceaccounts` / `serviceaccounts/token`,
`pods/exec|attach|portforward|proxy|ephemeralcontainers`, `nodes` /
`nodes/proxy`, the impersonation targets `users` / `groups` / `userextras/*`,
or the verbs `impersonate` / `escalate` / `bind`; the test pins all of that,
plus "no wildcards" and "no pod or ReplicaSet writes for the deployer".

## Who can act as nightly-report

Kubernetes lets anyone who can create a pod in a namespace run it as **any**
service account in that namespace, and a running pod's container image can
be changed in place. Left alone, "can deploy" would mean "can be
nightly-report" and so "can read `/vault/secrets/db`". Three layers stop
that, and the e2e test exercises each:

1. **RBAC:** `app-deployer` cannot create, update, patch or delete pods or
   ReplicaSets.
2. **Admission:** ValidatingAdmissionPolicy `clinical-apps-workload-identity`
   (Deny, fail closed) on Pods, `pods/ephemeralcontainers`, Deployments and
   ReplicaSets in `clinical-apps`. Rules, in the order they are reported (the
   API server returns the first one that fails):

   | # | Rule (CEL) | Message starts with |
   |---|---|---|
   | 1 | every container, init container and ephemeral container image ends in `@sha256:<64 hex>` | `image not pinned by digest:` |
   | 2 | a workload running as `nightly-report` runs only the approved app digest (`var.nightly_report_app_image`) and the Vault Agent digest (`var.vault_agent_image`) | `service account nightly-report may run only the approved app image and the Vault Agent image` |
   | 3 | `spec.automountServiceAccountToken` is `false` in the pod spec | `automountServiceAccountToken must be false in the pod spec` |
   | 4 | a workload running as `nightly-report` is created or changed only by `var.nightly_report_launcher_groups` (default `kubeadm:cluster-admins`, the kind admin = the pipeline) or the kube-system controllers; on an UPDATE, "running as" is checked on the object before (`oldObject`) **and** after | `only the release pipeline may create or change a workload that runs as service account nightly-report` |

   Rule 2 binds the identity to **code**; rule 4 binds it to **who deploys
   it**. Rule 4 is what closes "same approved image, different command": the
   app image is a general-purpose busybox, so with rule 2 alone a deployer
   could still patch the Deployment's `args` (or add a
   `vault.hashicorp.com/agent-inject-command-*` annotation) to print the file
   into `pods/log`. Rule 2 still matters: it limits what even the pipeline
   may run as nightly-report to a reviewed digest.

   Rule 4 reads both sides of an UPDATE because review found the gap when it
   read only the new object: one deployer patch that moved the live
   Deployment to `serviceAccountName: default` (or `unapproved-job`) was
   admitted, and in the same patch could replace its image, command and
   annotations. Not an identity borrow (the result runs as an SA no Vault
   role trusts), but a takeover of the workload object. Now refused; rule 2
   stays new-side only, because it is about what runs *as* nightly-report
   and the pipeline moving a workload off it is a legitimate change.
3. **Vault:** the role trusts one SA in one namespace, audience `vault`.

**The injected agent is judged too.** The Agent Injector is a mutating
webhook, and mutating admission runs before validating admission, so the
policy sees `vault-agent-init` and `vault-agent` already in the pod. That is
why [`../platform`](../platform/README.md) pins the agent image by digest
(the chart renders `<repository>:<tag>`, so the tag carries
`2.1.1@sha256:...`) and why rule 2 allows it. `tests/identity.tftest.hcl`
checks that `var.vault_agent_image`'s digest is the one `../platform` pins
and that `var.nightly_report_app_image` is the image
`lab/k8s/manifests/nightly-report.yaml` runs.

**Pod Security still answers first.** PSA is a built-in validating plugin
ordered before ValidatingAdmissionPolicy, so the privileged negative pod is
still rejected with the `violates PodSecurity "restricted:v1.36"` message.

**What the policy does not stop, said out loud:** the deployer can still
delete the nightly-report Deployment (availability, not identity: the policy
does not match DELETE, because a pod's last DELETE comes from the kubelet
and would need its own exemption) and then create one of that name under
another service account; and it can run its own digest-pinned workloads as
the namespace's *other* service accounts, which no Vault role trusts. Every
other write to the nightly-report workload, including `rollout restart`, a
replicas patch and moving it to another SA, is refused, and it has no
ReplicaSet or `deployments/scale` write. A cluster admin can delete the
policy itself; that is an audited admission change, not a quiet one.

**Checked on a scratch cluster before handing over** (kindest/node v1.36.4,
no Vault, 2026-10-20): admin dry-run pods for each rule were denied with the
messages above; a pod with a digest-pinned `vault-agent-init` was admitted;
the real `nightly-report` Deployment rolled out (controllers create the
ReplicaSet and pods); the deployer was denied on `set image`, an `args`
patch, an `agent-inject-command` annotation, `rollout restart`, and a new
Deployment or ReplicaSet as `nightly-report`, and allowed to create a probe
Deployment under the default SA; `kubectl debug` with an unapproved image was
denied; a `privileged` pod got the PSA message. A copy of this whole root
was then applied to that cluster with a throwaway dev Vault outside it (only
the auth backend's CA/JWT settings adapted for that): `terraform plan` after
apply was clean (exit 0); a kubectl patch adding User `mallory` to the
`app-deployer` RoleBinding made `plan -detailed-exitcode` exit 2 on
`kubernetes_role_binding_v1.human["app-deployer"]`, `apply` healed it, and
the next plan exited 0; kubectl edits to the policy itself were detected and
healed the same way; the root token occurred 0 times in `terraform state
pull`. Nothing was applied to the lab cluster.

**Re-checked after review on the kept lab cluster** (2026-10-20): before the
fix, a deployer patch moving `nightly-report` to SA `default` with new `args`
was admitted (server dry run) and `delete rs` was allowed; after it, the same
patch is denied with rule 4's message, the pipeline identity's own move is
admitted, `can-i delete replicasets` is `no`, the policy's type checking
reports no warnings, and an admin `rollout restart` still rolled out (the
controllers' ReplicaSet and pod writes pass rule 4 on both sides).

## Limits (said out loud)

- **The policy protects one identity.** Rules 2 and 4 name
  `nightly-report`. A second secret-bearing service account needs its own
  entries (or a policy parameter / SA label listing protected identities).
  The other SAs in the namespace can still be used by anyone who can deploy,
  which is fine only because no Vault role trusts them.
- **The launcher group is a lab stand-in.** `kubeadm:cluster-admins` is the
  kind admin certificate, i.e. the pipeline. On AKS it would be the GitOps
  controller's or release pipeline's identity, never a human team's group;
  the variable refuses catch-all groups and the deployer group.
- **One drift case `apply` cannot heal in place:** `validationActions` is a
  set-typed list, and server-side apply merges set members from different
  field managers, so a kubectl patch to `["Warn"]` is detected by `plan` but
  `apply` would produce the invalid `["Warn","Deny"]`. Heal it with
  `terraform apply -replace=kubernetes_manifest.workload_identity_policy_binding`
  (seen on the scratch cluster).
- **Groups are impersonated** (`kubectl --as=<user> --as-group=<group>`): kind
  has no Entra sign-in. The RBAC evaluation is the same one an
  Entra-authenticated user would hit.
- **`token_bound_cidrs` is not set**, because the e2e test logs in from the
  host through the NodePort. In production, bind Vault tokens to the pod CIDR.
- **Dev-mode Vault** (in-memory, HTTP, root token): see
  [`../platform/README.md`](../platform/README.md#decisions).

## What changes on AKS

| Here (kind) | AKS |
|---|---|
| Impersonated groups `k8s-clinical-deployers` / `k8s-clinical-auditors` | **AKS-managed Microsoft Entra integration.** With Kubernetes RBAC, the same RoleBindings name the Entra group's **object ID** (a GUID) as the `Group` subject. With **Azure RBAC for Kubernetes authorization**, the same intent becomes Azure role assignments (e.g. *Azure Kubernetes Service RBAC Reader*) scoped to the namespace. Disable local accounts so the cluster-admin client certificate cannot bypass Entra |
| Projected SA token, audience `vault`, validated by Vault via TokenReview | **Microsoft Entra Workload ID**: the cluster's OIDC issuer signs the projected token (audience `api://AzureADTokenExchange`); a **federated identity credential** trusts subject `system:serviceaccount:clinical-apps:nightly-report` from that issuer, on an **app registration** in [`../aks-mapping`](../aks-mapping/README.md) (a user-assigned managed identity is the other common carrier); the SA is annotated with that identity's client ID and the pod labelled `azure.workload.identity/use: "true"` |
| Vault policy `read` on `clinical/data/db` | **Key Vault RBAC**: *Key Vault Secrets User* on the one secret (the lab's Azure side already scopes this with an ABAC condition, `lab/terraform/modules/keyvault`) |
| Vault Agent Injector renders `/vault/secrets/db` | **Secrets Store CSI driver + Azure Key Vault provider** (AKS add-on) mounts the secret as a file. Leave its optional "sync as Kubernetes Secret" off, or the no-Secret property is lost |
| ValidatingAdmissionPolicy `clinical-apps-workload-identity` | **Unchanged**: VAP is upstream Kubernetes and runs on AKS as-is; rule 4's launcher group becomes the GitOps/pipeline identity (an Entra group object ID or the controller's SA group). **Azure Policy for AKS** (Gatekeeper) is the managed alternative for org-wide rules such as "digest-pinned images only" |

The Workload ID row is written as plan-only Terraform, with tests, in
[`../aks-mapping`](../aks-mapping/README.md): the federated identity
credential that is the Entra equivalent of the Vault role above.

## Microsoft mapping (ADR 0027)

- **Entra Workload ID** does the same job: a Kubernetes identity in, a
  scoped secret out. A federated identity credential pins the issuer,
  namespace and service account (the role's `bound_service_account_*`
  here), and an Azure RBAC role (*Key Vault Secrets User*) on one secret
  replaces the Vault policy. The Key Vault provider for the Secrets Store
  CSI driver mounts the secret, like the Vault Agent does here.
- **Worth knowing for an interview:** Workload ID never sees a cluster
  credential. Entra validates the pod's projected service-account token
  against the cluster's public OIDC discovery document, which is the same
  token-validation model this lab shows with Vault's Kubernetes auth.

## Running

Normally via `lab/k8s/ci/pipeline.sh` (its "terraform apply identity"
stage, after `../platform`). `kubernetes_manifest` needs the API server at
plan time as well as apply time; the cluster exists by then.
By hand, with the **same** token `../platform` booted Vault with:

```bash
# TF_VAR_vault_dev_root_token already exported for ../platform (never echo it)
terraform -chdir=lab/terraform/k8s/identity init
terraform -chdir=lab/terraform/k8s/identity apply
```

`vault_addr` defaults to `http://127.0.0.1:18200`; plain HTTP is refused for
anything but loopback. Destroying needs the live token too (the provider
deletes the Vault objects through the API).

## Offline checks

```bash
terraform -chdir=lab/terraform/k8s/identity init -backend=false
terraform -chdir=lab/terraform/k8s/identity validate
terraform -chdir=lab/terraform/k8s/identity test     # mocked vault + kubernetes providers
```

`tests/identity.tftest.hcl` pins: the role bound only to `nightly-report` in
`clinical-apps`, audience `vault`, TTL and max TTL ≤ 900 s, only the
`nightly-report-read` policy, UID-keyed aliases; the policy is exactly
`read` on `clinical/data/db`; both SAs have token automount off; no human
rule grants `secrets` (or SA tokens, RBAC, exec/attach/port-forward/proxy,
ephemeral containers, nodes, impersonation targets, the
impersonate/escalate/bind verbs, wildcards); `app-deployer` can only
get/list/watch pods and ReplicaSets and only `get` `pods/log`, and keeps
create/patch on Deployments; `auditor` is read-only; every binding is a namespaced
RoleBinding to a Role with Group subjects; no `.tf` file declares a
ClusterRole(Binding), typed or via `kubernetes_manifest`; the admission
policy is `admissionregistration.k8s.io/v1`, `failurePolicy: Fail`, bound
with exactly `[Deny]`, matches CREATE+UPDATE of pods and apps/v1
deployments, is scoped to `clinical-apps` in both policy and binding, has
the four rules in order (rule 4 reading `oldObject` too), and its allowlist is exactly the app and agent
digests, non-empty, `sha256:` only, in agreement with `../platform/main.tf`
and `lab/k8s/manifests/nightly-report.yaml`; a weak token, a non-kind
context, plain HTTP off loopback, a tag-only app image and a catch-all
launcher group are rejected. The core assertions were checked to fail
against deliberately broken copies of the configuration (`secrets` added to
app-deployer, a ClusterRoleBinding added, audience changed, TTL raised,
`update` added or a wildcard path added to the policy, both SAs bound, token
automount on, `pods/exec` granted, `delete` given to auditor; and for this
pass: `patch` on pods, pods back in the write rule, `list` on `pods/log`,
`Warn` instead of `Deny`, `failurePolicy: Ignore`, deployments or UPDATE
dropped from the match, an empty or wrong namespace selector, rule 1, 3 or
4 replaced by `true`, an extra digest in the allowlist, a different agent
digest in `../platform`, a ClusterRoleBinding via `kubernetes_manifest`;
after review: write verbs back on replicasets, rule 4 without the
`oldObject` side, the old-side variable reading `object` instead).

## Sources

- Resource schemas: `terraform providers schema -json` for
  `hashicorp/vault` 5.12.0 and `hashicorp/kubernetes` 3.3.0, 2026-10-19.
- ValidatingAdmissionPolicy: kubernetes.io docs (*Validating Admission
  Policy*), behaviour confirmed on kindest/node v1.36.4 (first failing
  validation's message is returned; `Invalid` reason → HTTP 422 "is
  invalid", `Forbidden` → 403).
- vault-k8s 1.7.6 source (`agent-inject/agent/container_sidecar.go`:
  `Image: a.ImageName`) for the agent image string being used verbatim.
- Vault Kubernetes auth method and Agent Injector docs (developer.hashicorp.com);
  Microsoft Learn: AKS Microsoft Entra integration, Microsoft Entra Workload
  ID on AKS, Azure Key Vault provider for Secrets Store CSI driver.
  verify: re-read before recording; names of AKS built-in roles change.
