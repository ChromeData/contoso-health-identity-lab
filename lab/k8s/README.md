# Kubernetes workload identity: secrets with no static secret in the workload's path

A local, fully-as-code Kubernetes segment of the Contoso Health identity lab.
A clinical workload (`nightly-report`) gets its database password **without a
Kubernetes Secret, an environment variable or a value in any manifest**. It
proves who it is with a short-lived, audience-bound service-account token, and
Vault's Kubernetes auth method trades that for a 15-minute Vault token that
can read exactly one secret path. Around that one exchange:

- **who may be `nightly-report`** is decided per workload, not per node or per
  namespace: RBAC keeps human deployers away from pods, and a
  ValidatingAdmissionPolicy binds the identity to one reviewed image digest
  and to the release pipeline;
- **the value rotates without a restart**: a new value in Vault becomes the
  new file content in the same pod;
- **drift is detected and healed**: an out-of-band RoleBinding edit makes
  `terraform plan` exit 2, and applying the reviewed plan puts it back;
- **the evidence is in the API-server audit log**, which records who tried
  and changed what, and is shown to hold no secret value or token;
- **no secret is in Terraform state**, counted on every run.

**Stand-ins, said out loud** (rows in [`../docs/STAND-INS.md`](../docs/STAND-INS.md)):

| What runs here | Stands in for |
|---|---|
| **kind** cluster `contoso-k8s` (one node, Kubernetes 1.36) | **AKS** |
| HashiCorp **Vault** Kubernetes auth + **Vault Agent Injector** | **Microsoft Entra Workload ID** + **Azure Key Vault** through the **Key Vault CSI driver** on AKS (the target, ADR 0027) |
| Kubernetes groups via `kubectl --as-group` (impersonation) | **Entra ID groups** through AKS's Entra integration |

Nothing in this folder talks to Azure or Entra. It runs for $0 on a
laptop or a GitHub-hosted runner, and the cluster is deleted after every run.
The Entra side of the same trust is written as Terraform in
[`lab/terraform/k8s/aks-mapping`](../terraform/k8s/aks-mapping/README.md) and
checked offline (`fmt`, `validate`, mocked `terraform test`), **never applied**
(section 4).

> **Status:** the 12-stage `ci/pipeline.sh` ran green on the lab Mac (Colima,
> Apple Silicon, `kindest/node:v1.36.4`, Vault chart 0.34.1, Vault 2.1.1,
> vault-k8s 1.7.6) on 2026-10-20, after the review fixes in sections 3 and 6:
> a fresh run that destroyed everything at the end (128 s,
> `K8S E2E PASSED (64/64)`) and a `KEEP_CLUSTER=1` run that built a cluster
> (111 s; runs that reuse a kept cluster took about 65 s before the fixes).
> On that kept cluster the Vault root token and every stored version of the
> KV value, plain and base64, were counted in the run logs, both Terraform
> state files, the API-server audit log and the repo's `lab/` and `.github/`
> trees: zero hits, with the kept token file as the positive control (stage
> 12 repeats the state + audit-log half on every run). The run logs also
> hold no JWT, no Vault token and no string shaped like the root token or a
> KV value. The first, 9-stage version of this segment ran green on
> 2026-10-19/20 (94-96 s, 39/39). A later full, unmodified run is recorded
> and hashed in
> [`../evidence/k8s/20261020T202112Z/`](../evidence/k8s/20261020T202112Z/README.md)
> (12/12 stages, teardown PASS, `K8S E2E PASSED (64/64)`, 135 s).
> verify: the first run of the `k8s identity pipeline` GitHub Actions job
> (on ubuntu-latest the preinstalled kind/kubectl are hashed against the
> linux-amd64 pins, which match the published checksums, and replaced by
> the verified downloads if they differ).

---

## 1. The problem

The usual ways a pod gets a database password are all static secrets:

- **A Kubernetes Secret.** Base64, not encryption. It sits in etcd (encrypted
  at rest only if someone configured it), anyone with `get secrets` in the
  namespace reads it, it lands in Helm release records and backups, and it is
  rotated by hand, i.e. rarely.
- **An environment variable.** Visible in `kubectl describe` and the pod spec,
  inherited by every child process, dumped by crash reporters and debug
  endpoints, and fixed for the container's whole life.
- **A legacy service-account token Secret** (`kubernetes.io/service-account-token`)
  to authenticate to a vault. It never expires, has no audience, works against
  the Kubernetes API itself, and outlives every pod that used it.

All three are "secret zero": a long-lived credential whose only protection is
that nobody copies it. This segment removes it from the workload. The one
bootstrap credential that remains, the dev-mode Vault root token the platform
itself runs with, is described in section 6.

Removing the static secret moves the question to **who can become the
workload**. In plain Kubernetes, anyone who can create a pod in a namespace
can run it as any service account there, and a running pod's image can be
swapped in place. Section 3 shows how that is closed here, and section 6
what is left.

## 2. Architecture

```
 host: macOS + Colima, or the GitHub runner (one script: ci/pipeline.sh)
 ├─ terraform  lab/terraform/k8s/platform ─► namespaces + PSA labels, Helm: Vault (dev) + Agent Injector
 │             lab/terraform/k8s/identity ─► Vault: kv-v2 "clinical", policy, auth/kubernetes + role
 │                                           K8s:   ServiceAccounts, Roles + RoleBindings (groups),
 │                                                  ValidatingAdmissionPolicy + binding
 │             lab/terraform/k8s/aks-mapping ─► Entra federated credential: tested offline, never applied
 ├─ 127.0.0.1:18200 ──────────────────────► NodePort 30820 ─► vault-0          (namespace vault)
 └─ docker: kind node contoso-k8s-control-plane  (kindest/node v1.36.4, pinned by digest)
     kube-apiserver ─► /var/log/kubernetes/audit/audit.log
                       (Secrets + tokens: Metadata only; RBAC, pod entry, admission writes: with bodies)
     admission, in order: Vault injector (mutating) ─► Pod Security "restricted"
                          ─► ValidatingAdmissionPolicy clinical-apps-workload-identity (Deny)

     namespace clinical-apps   PSA enforce=restricted
     ┌── pod nightly-report (ServiceAccount nightly-report, no default API token) ─────────┐
     │  volume vault-token: projected SA token, audience "vault", 10 min, kubelet-rotated  │
     │                                                                                    │
     │  vault-agent-init ─┐  1. read token (mounted ONLY in the agent containers)         │
     │  vault-agent ──────┤  2. POST auth/kubernetes/login role=nightly-report ─► Vault   │
     │   (injected by the │        Vault ─► TokenReview ─► kube-apiserver: genuine?       │
     │    mutating        │        bound SA + namespace + audience match? ─► Vault token  │
     │    webhook; image  │        (policy nightly-report-read, TTL 15 min)               │
     │    pinned by       └  3. read clinical/data/db ─► /vault/secrets/db, re-read      │
     │    digest)               every 10 s (memory emptyDir, 0400, uid 10001)            │
     │  nightly-report (busybox @sha256) ─► reads /vault/secrets/db. No token, no env.    │
     └────────────────────────────────────────────────────────────────────────────────────┘

     humans (impersonated):  group k8s-clinical-deployers ─► Role app-deployer (Deployments; pods and
                                                              ReplicaSets read-only; no secrets,
                                                              no RBAC, no exec)
                             group k8s-clinical-auditors  ─► Role auditor      (read-only, no secrets)
```

### What each piece proves

| Concern | Mechanism | Where |
|---|---|---|
| Workload identity | Projected service-account token, audience `vault`, 600 s, bound to the pod and to the ServiceAccount object | [`manifests/nightly-report.yaml`](manifests/nightly-report.yaml) |
| Authentication | Vault Kubernetes auth: TokenReview + bound SA name, namespace and audience | `lab/terraform/k8s/identity` |
| Authorization | Vault policy `nightly-report-read`: `read` on `clinical/data/db`, nothing else | `lab/terraform/k8s/identity` |
| Delivery | Vault Agent Injector renders one file to tmpfs; the sidecar renews its login and re-reads the value | [`manifests/nightly-report.yaml`](manifests/nightly-report.yaml) |
| Who may be the workload | `app-deployer` has no pod or ReplicaSet write verbs; ValidatingAdmissionPolicy `clinical-apps-workload-identity` (four rules, below) | `lab/terraform/k8s/identity` |
| Admission guardrails | PSA `restricted` on `clinical-apps`, then the policy | `lab/terraform/k8s/platform` + `identity`, [`manifests/negative/`](manifests/negative/privileged-pod.yaml) |
| Rotation without restart | `vault.hashicorp.com/template-static-secret-render-interval: "10s"` | manifest; `ci/pipeline.sh` stage 9 |
| Drift detection | `terraform plan -detailed-exitcode` after an out-of-band RoleBinding edit; the reviewed plan heals it | `ci/pipeline.sh` stage 10 |
| No secret in state | Terraform creates the KV mount, never the value; the pipeline writes random values over Vault's API, then counts them in both states (0) | `ci/pipeline.sh` stages 7, 9, 12 |
| Human least privilege | Namespaced Roles bound to groups; no Secrets, no RBAC, no `serviceaccounts/token`, no exec, no ClusterRoleBindings | `lab/terraform/k8s/identity` |
| Evidence | Audit policy: Secrets / TokenRequest / TokenReview at Metadata only; RBAC objects, pod entry (exec, attach, port-forward, debug) and admission-config writes at RequestResponse | [`kind/audit-policy.yaml`](kind/audit-policy.yaml) |
| The AKS equivalent | Entra federated identity credential for `system:serviceaccount:clinical-apps:nightly-report` | [`lab/terraform/k8s/aks-mapping`](../terraform/k8s/aks-mapping/README.md) (plan-only) |

### The admission policy

`clinical-apps-workload-identity` is a `ValidatingAdmissionPolicy`
(`admissionregistration.k8s.io/v1`, CEL inside the API server) bound with
`validationActions: [Deny]` and `failurePolicy: Fail`. It matches CREATE and
UPDATE of Pods (and `pods/ephemeralcontainers`, i.e. `kubectl debug`),
Deployments and ReplicaSets in the namespace whose
`kubernetes.io/metadata.name` is `clinical-apps` (a label the API server sets
and nobody can change). The API server reports the first failing rule:

| # | Rule | Denial starts with |
|---|---|---|
| 1 | Every container, init container and ephemeral container image is pinned by digest (`@sha256:<64 hex>`) | `image not pinned by digest:` |
| 2 | A workload running as `nightly-report` runs only the approved app digest (`var.nightly_report_app_image`) and the Vault Agent digest | `service account nightly-report may run only the approved app image and the Vault Agent image` |
| 3 | `automountServiceAccountToken: false` in the pod spec | `automountServiceAccountToken must be false in the pod spec` |
| 4 | Only the release pipeline's group (`var.nightly_report_launcher_groups`, here `kubeadm:cluster-admins`) and the kube-system controllers may create a workload that runs as `nightly-report`, or change one that does. On an UPDATE both the object before (`oldObject`) and after are checked, so moving the workload to another service account is a change too | `only the release pipeline may create or change a workload that runs as service account nightly-report` |

The Vault injector is a **mutating** webhook, and mutating admission runs
before validating admission, so the policy judges the pod *with* the injected
`vault-agent-init` and `vault-agent` containers. That is why
`lab/terraform/k8s/platform` pins the agent image by digest (the chart's
`agentImage.tag` carries `2.1.1@sha256:…`, which vault-k8s 1.7.6 copies into
the pod verbatim) and rule 2 allows exactly that digest next to the app.

### The tests

The pipeline asserts as it goes (stages 9, 10, 12) and then runs
[`test/k8s-e2e.sh`](test/k8s-e2e.sh) (stage 11). Every check prints one
PASS/FAIL line; every "denied" must be the server's own refusal naming the
reason, with a positive control run first. The e2e test never has the Vault
root token: Vault assertions use the workload's own login, RBAC assertions
impersonate the identity under test.

**e2e test, 64 assertions:**

- **(a) platform:** node, Vault and injector Ready; Vault healthy and 2.1.1;
  PSA labels on both namespaces.
- **(b) workload:** the pod Ready with the agent injected; the rendered
  file's SHA-256 (hashed inside the pod) equals the current value's; the app
  container has no Kubernetes token; only the agent mounts the `aud: vault`
  token; the Deployment holds no env value or Secret reference.
- **(c) Vault:** a `nightly-report` token with audience `vault` logs in and
  gets only `nightly-report-read` with a TTL ≤ 900 s; it reads
  `clinical/data/db` but gets 403 on `clinical/data/other` and on a write; an
  `unapproved-job` token is refused, and so is a `nightly-report` token with
  the default (Kubernetes API) audience; the API server in turn refuses the
  `aud: vault` token (401, while a default-audience token gets 200); a
  revoked Vault token is refused.
- **(d) identity is namespace + name + object:** a ServiceAccount also called
  `nightly-report` in a fixture namespace `other-team` is refused by Vault
  (`namespace not authorized`); a token for a ServiceAccount that is deleted
  and recreated under the same name gets 401 (fixtures cleaned up).
- **(e) no static secret:** the value is in no Secret, ConfigMap, Deployment,
  ReplicaSet or Pod (plain, base64, decoded); no legacy token Secrets; both
  ServiceAccounts opt out of automount.
- **(f) RBAC:** the can-i matrix below, every cell enforced; the deployer can
  ship a Deployment and read pods, ReplicaSets and logs, but cannot create,
  update, patch or delete pods or ReplicaSets, read Secrets, list
  `kube-system`, mint the workload's token, create RoleBindings, or exec /
  attach / port-forward / debug; the auditor
  reads but cannot read or list Secrets or delete; no ClusterRoleBinding
  names either group.
- **(g) admission** (server-side dry runs, nothing persisted, the cluster
  admin included): the running pod's images are all digest-pinned; denied:
  `nightly-report` with any other digest (even for the pipeline identity), a
  tag-only image, an automounted API token, the deployer creating a
  Deployment as `nightly-report`, re-pointing its image, keeping the image
  and swapping the command to print the file, or moving it to another
  service account with a new command in one patch; admitted controls for
  each (including the pipeline identity making that last move). PSA still
  rejects the privileged pod in `manifests/negative/`.
- **(h) audit log:** the deployer's forbidden Secret read (403, impersonated
  user and group); Secret, TokenRequest and TokenReview events all at
  Metadata with no body (and each present, so "no body" is not an empty log);
  the drift drill's RoleBinding patch by the kind admin with `mallory` in the
  request and response bodies, and the revert after it, by Terraform's user
  agent (Terraform uses the same kind admin credentials); the policy write,
  logged with its body.

```
                   create    patch     get       create    imper-    pods/     list pods
                   deploys   pods      secrets   rolebind  sonate    exec      kube-sys
deployer           yes       no        no        no        no        no        no
auditor            no        no        no        no        no        no        no
SA nightly-report  no        no        no        no        no        no        no
SA unapproved-job  no        no        no        no        no        no        no
```

**Pipeline stages that assert:**

- **6, terraform apply identity:** reads the policy back from the API server
  after the apply: the binding's `validationActions` must be exactly
  `[Deny]` and the policy must match CREATE + UPDATE of pods and
  Deployments, so the summary line is evidence, not a restatement of the
  `.tf`.
- **9, rotate secret (no restart):** writes a new random value to
  `clinical/data/db` as root (check-and-set against the seeded version), waits
  up to 45 s for the in-pod SHA-256 to change (about 8-9 s observed with a
  10 s interval), then asserts the same pod name and UID, still Ready, and
  unchanged restart counts on every container, init included.
- **10, drift: detect + heal:** as the kind admin, adds `User mallory` to
  `app-deployer--k8s-clinical-deployers` and shows mallory can now create
  Deployments (waiting up to 20 s: the RBAC authorizer reads bindings
  through a cache); `terraform plan -detailed-exitcode` must exit 2 with exactly
  one change, `kubernetes_role_binding_v1.human["app-deployer"]` (update),
  removing `User/mallory` (`DRIFT DETECTED`); applying that saved plan and
  planning again must exit 0, and mallory has no access (`drift healed`).
- **12, secrets out of state:** counts every stored version of the KV value
  and the Vault root token, each plain and base64, in `terraform state pull`
  of both roots and in the audit log. All counts must be 0, and a control
  string must be found in every haystack. Counts only, never a value.

## 3. Decisions and alternatives

### Vault Agent Injector vs. Secrets Store CSI driver vs. External Secrets Operator

| | **Agent Injector** (chosen) | **Secrets Store CSI driver** (+ Vault or Azure provider) | **External Secrets Operator** |
|---|---|---|---|
| Where the value lives | tmpfs file in the pod only | tmpfs file in the pod (optional sync to a K8s Secret) | a **Kubernetes Secret** (etcd) |
| Kubernetes Secret created? | No | Only if you turn sync on | Yes, by design |
| Rotation / renewal | Sidecar renews its login and re-reads the value on an interval | Optional rotation poll (driver feature) | Refresh interval, then the app must reload |
| Cost | A sidecar per pod, a mutating webhook in the admission path | A node DaemonSet + provider, no sidecar | One controller |
| Templating | Full (render exactly the bytes the app expects) | Object/key selection only | Templates into Secret keys |

The injector is the only one of the three where the credential never becomes
a Kubernetes object, which is the claim this segment makes and tests. Its cost
is the webhook: if the injector is down, pods in opted-in namespaces cannot
start (the platform root sets `failurePolicy: Fail` on purpose; the chart
default `Ignore` would start the pod *without* its credential, a silent
failure). The CSI driver is the natural AKS answer (managed add-on, no
sidecar) and stays Secret-free as long as sync stays off. External Secrets is
the right tool when an app can only read env vars or Secrets, and that trade
should be written down, because the value then sits in etcd.

### Projected, audience-bound tokens vs. legacy service-account token Secrets

The projected token is minted by the kubelet through the TokenRequest API:

- **Expires** (600 s here, the API server's minimum) and is refreshed by the
  kubelet before it does. A legacy token Secret never expires.
- **Has an audience.** `aud: vault` means Vault accepts it and the Kubernetes
  API does not, so a token leaked from Vault's side cannot drive `kubectl`.
  Both directions are tested.
- **Is bound to the pod and the ServiceAccount object.** Delete either and
  TokenReview rejects the token before it expires; a ServiceAccount recreated
  under the same name does not revive it (tested, section d).
- **Is mounted only into the agent containers.** The app container has
  `automountServiceAccountToken: false` and no token mount at all, so the
  process that holds the database password cannot authenticate to anything.

Kubernetes stopped auto-creating legacy token Secrets in 1.24; this segment
creates none.

### Why Vault calls TokenReview (and when not to)

Vault's Kubernetes auth asks the API server whether a token is genuine and
still bound to a live pod. That catches revocation (pod or ServiceAccount
deleted) but means Vault needs network reach to the API server and a reviewer
identity with `system:auth-delegator`. The alternative is Vault's JWT auth
against the cluster's OIDC issuer (JWKS): no API call, works across clusters,
but a deleted pod's token stays valid until it expires. Entra Workload ID uses
the second model: Entra trusts the cluster's OIDC issuer.

### Closing identity borrowing: RBAC, then a policy with four rules

The first version of this segment documented a gap: `app-deployer` could
create and patch pods, so it could start a pod as `nightly-report`, or swap a
running container's image for one that prints `/vault/secrets/db` and read
it with `kubectl logs`. Three layers now close it, each tested:

1. **RBAC:** `app-deployer` keeps create/update/patch/delete on Deployments,
   ConfigMaps and Services, but only get/list/watch on pods and ReplicaSets
   and `get` on `pods/log`. The controllers make ReplicaSets and pods. (The
   first cut of this pass kept ReplicaSet writes; review showed that
   deleting nightly-report's ReplicaSet makes the Deployment controller
   recreate it, a restart rule 4 refuses as `rollout restart`.)
2. **Rules 1-3** bind the identity to code: whoever deploys it,
   `nightly-report` runs one reviewed digest plus the Vault Agent, with no API
   token.
3. **Rule 4** binds it to who deploys it. Rule 2 alone is not enough: the
   approved image is busybox, a general-purpose shell, so a deployer could
   keep the approved digest and change the Deployment's `args` (or an
   `agent-inject-command` annotation) to print the file. Using the
   `nightly-report` identity is a release-pipeline decision, so only the
   pipeline's group and the kube-system controllers (which turn the
   pipeline's Deployment into pods) may create or change such a workload.
   Rule 4 reads the object before an update as well as after: review found
   that, judging only the new object, one deployer patch could move the live
   Deployment to `serviceAccountName: default` and in the same patch rewrite
   its image and command (a takeover of the object, not of the identity: no
   Vault role trusts `default`). That patch is now denied and tested.

**Why a ValidatingAdmissionPolicy and not a webhook** (Kyverno, Gatekeeper):
it runs inside the API server, so there is no extra pod to keep alive, no TLS
to manage and no webhook that can be down and fail open. It is GA since
Kubernetes 1.30 and upstream, so the same object works on AKS. It lives in
the identity Terraform root because it is identity policy, reviewed with the
Vault role it protects. **Why Deny:** Warn or Audit would record the borrow
and let it happen.

### Rotation without a restart

A KV v2 value has no lease, so nothing tells the agent it changed. The
annotation `vault.hashicorp.com/template-static-secret-render-interval`
(vault-k8s 1.7.6 maps it to `template_config.static_secret_render_interval`;
the agent's default is 5 minutes) makes the sidecar re-read it and rewrite the
file (temp file + rename) in the running pod. 10 s keeps stage 9 short at the
price of one KV read per pod every 10 s; production would use minutes, sized
to how fast a rotated credential must be live. Whether the app picks the new
file up is the app's business (this one reads it on every loop); a connection
pool needs its own reload.

### Drift: plan -detailed-exitcode, then apply the reviewed plan

Terraform owns the human RBAC and the policy, so IaC is a control only if a
change made around it is noticed and undone. Stage 10 makes such a change as
the cluster admin, requires `plan -detailed-exitcode` to exit 2 on exactly
the tampered resource, applies the saved plan (what is applied is what was
shown), and requires a clean plan (0) afterwards. The policy resources use
`kubernetes_manifest` with `force_conflicts`, so an out-of-band kubectl edit
of a field Terraform declares is reverted by apply instead of stopping on a
field-manager conflict. One exception, documented in the root: a binding
switched to `Warn` is detected but needs `terraform apply -replace` to heal.

### Audit policy: what gets a body, and what never does

First matching rule wins, so the order is part of the policy:

- **Secrets, `serviceaccounts/token` and TokenReviews are pinned to Metadata
  first**, whatever the verb or user. A TokenRequest *response* is a live JWT
  (the one Vault accepts) and a TokenReview *request* carries the token under
  review; at Request or RequestResponse level the audit log would become a
  second secret store, readable by whoever reads logs. Stage 12 and section
  (h) check that it is not.
- **RequestResponse** for RBAC objects (an investigation sees which subject
  was added, not just "rolebinding patched"), the ways into a running pod
  (exec, attach, port-forward, ephemeral containers) and writes of admission
  policies and webhook configurations (a weakened guardrail is on record with
  its new content; their `/status` subresource, written by the controller
  manager, stays at Metadata).
- **Metadata** for everything else; heartbeat, lease, endpoint and event
  churn dropped; `omitManagedFields` on.

### Why two applied Terraform roots (and one that is never applied)

The Vault provider must be configured with Vault's address and a token at
plan time, and Vault does not exist until the platform stage has installed it.
`platform` (Helm, namespaces) and `identity` (Vault objects, service accounts,
RBAC, admission policy) are therefore separate roots, applied in order by the
pipeline. Local state only: the cluster is ephemeral. `aks-mapping` is a third
root that only exists to make the AKS mapping typed, tested code (section 4).

### Smaller choices

- **The secret value is not in Terraform.** Anything Terraform writes is in its
  state. Terraform owns the mount, the policy and the role; the pipeline writes
  random values over Vault's API and keeps only their SHA-256 for the checks.
- **0400, uid 10001.** The agent runs as the app's uid/gid
  (`agent-run-as-user/-group`), so the rendered file can be owner-read-only.
  The same uid in every container makes the kubelet write the projected token
  0600 instead of 0644.
- **No trailing newline.** The template renders the bare password, so
  `sha256sum /vault/secrets/db` in the pod equals
  `printf '%s' "$value" | sha256sum` at write time.
- **Pinned by digest:** the kind node image, busybox, the Vault server, the
  injector and the injected agent (multi-arch indexes, so one pin serves the
  amd64 runner and an arm64 Mac). Rule 1 makes this a requirement for every
  workload in `clinical-apps`, not a habit.
- **Vault published on the host only at `127.0.0.1:18200`**, never on the
  LAN. It is still reachable from the local Docker bridge network (the kind
  node's IP, NodePort 30820) and from every pod in the cluster (no network
  policy, section 6).

## 4. What changes on AKS

| Here (kind) | On AKS |
|---|---|
| `kubectl --as --as-group` impersonation, kind admin cert | **AKS-managed Entra ID integration**, local accounts disabled, humans sign in with `kubelogin` (so Conditional Access and MFA apply). Either **Kubernetes RBAC** with RoleBindings to **Entra group object IDs** (these same Roles, `subjects[].name` = the group's object ID) or **Azure RBAC for Kubernetes Authorization**. Note the built-ins: *Azure Kubernetes Service RBAC Reader* excludes Secrets, but *RBAC Writer* can read them, which is why a deployer role without Secrets has to be custom (as `app-deployer` is here) |
| Standing group membership | **PIM for Groups**: the deployer group is eligible, activated for hours with approval, the same pattern the lab uses for Tier-0 |
| Launcher group `kubeadm:cluster-admins` (the kind admin = the pipeline) | The GitOps controller's or release pipeline's own identity, never a human group, in `nightly_report_launcher_groups` |
| Vault Kubernetes auth (TokenReview) | **Microsoft Entra Workload ID**: OIDC issuer + workload identity enabled on the cluster, a **federated identity credential** trusting `system:serviceaccount:clinical-apps:nightly-report` with audience `api://AzureADTokenExchange`, the ServiceAccount annotated with the identity's client ID, pods labelled `azure.workload.identity/use: "true"`. [`aks-mapping`](../terraform/k8s/aks-mapping/README.md) writes it on an **app registration** (`azuread_application_federated_identity_credential`, the lab's `modules/pipeline-identity` pattern); the other common carrier is a **user-assigned managed identity** (`azurerm_federated_identity_credential`), which cannot hold a client secret at all. Same issuer + subject + audience either way |
| Vault KV + Agent Injector | **Azure Key Vault** (RBAC mode, *Key Vault Secrets User* scoped to the one secret, or at vault scope with the lab's ABAC secret-name condition as in `lab/terraform/modules/keyvault`) through the **Key Vault provider for the Secrets Store CSI driver** add-on, sync to Kubernetes Secrets left off. |
| ValidatingAdmissionPolicy | The same object (upstream API); **Azure Policy for Kubernetes** (Gatekeeper) for organisation-wide guardrails on top |
| Audit policy file in the node container | Control-plane **diagnostic settings** (`kube-audit-admin` / `kube-audit`) to Log Analytics, then the same Sentinel / KQL path as the rest of the lab. The audit policy itself is AKS-managed, so the per-resource levels chosen here are not a setting there (verify: category names, resource-specific tables and what each category leaves out) |
| PSA namespace labels | The same labels |

**Why `aks-mapping` is never applied:** Entra does not call the cluster; it
fetches the issuer's discovery document and JWKS itself, so the issuer must be
a public HTTPS URL. kind's issuer is
`https://kubernetes.default.svc.cluster.local`, which nothing outside the
cluster can resolve. The root's variables refuse such an issuer.

ADR 0027 (Microsoft-native PAM) makes the right-hand column the lab's
target. CyberArk and Conjur are not part of the lab.

## 5. Run it

Prerequisites: Docker (Colima with at least 4 CPU / 8 GiB on a Mac),
`terraform` 1.16.5, `checkov`, `jq`, `curl`, `openssl`. `kind` v0.33.0 and
`kubectl` v1.37.1 are hashed on every run and replaced by the pinned,
sha256-verified release builds if missing, at another version or not
byte-identical to them. Host port `127.0.0.1:18200` must be free. Use a
terminal at least 100 columns wide (the RBAC matrix and the summary table fit).

```bash
lab/k8s/ci/pipeline.sh                  # all 12 stages, then destroys everything (EXIT trap)
KEEP_CLUSTER=1 lab/k8s/ci/pipeline.sh   # keep (or reuse) the cluster to explore
STOP_AFTER=3 lab/k8s/ci/pipeline.sh     # static checks only, no cluster
```

| Stage | What it does |
|---|---|
| `[1/12]` preflight | tool versions; kind + kubectl hashed against the pins |
| `[2/12]` terraform fmt / validate / test | `platform`, `identity` and `aks-mapping` (mocked providers, 23 test runs) |
| `[3/12]` checkov | terraform + kubernetes frameworks; any inline skip must give a reason |
| `[4/12]` kind cluster | `contoso-k8s` with the audit policy |
| `[5/12]` terraform apply platform | namespaces + PSA labels, Vault + injector (digest-pinned) |
| `[6/12]` terraform apply identity | Vault KV / policy / role, ServiceAccounts, human RBAC, the admission policy (read back live: `[Deny]`) |
| `[7/12]` seed secret | a random value to `clinical/data/db` over Vault's API |
| `[8/12]` deploy workload | `kubectl apply -f manifests/` + rollout status |
| `[9/12]` rotate secret (no restart) | new value, same pod, no restart |
| `[10/12]` drift: detect + heal | `DRIFT DETECTED` (plan 2) → apply → plan 0 |
| `[11/12]` e2e tests | `test/k8s-e2e.sh`, `K8S E2E PASSED (64/64)` |
| `[12/12]` secrets out of state | 0 hits in both states and the audit log |

It ends with a per-stage table (seconds, PASS/FAIL, one line of evidence per
stage) and exits non-zero if anything failed. A full run takes about 2 minutes
on the lab Mac. The same script is the GitHub Actions job
(`.github/workflows/k8s-identity.yml`), with no cloud credentials at all.

### Exploring (or attacking) a kept cluster

After a `KEEP_CLUSTER=1` run, `lab/k8s/ci/.state/` (gitignored, 0600 files)
holds the kept cluster's Vault dev root token (`vault-root-token`) and the
SHA-256 of the current KV value (`seed.sha256`). Read the token into the
environment without printing it; never pass it as a command-line argument
(`ps` shows those to every local user):

```bash
k() { kubectl --context kind-contoso-k8s "$@"; }
export VAULT_ADDR=http://127.0.0.1:18200
export VAULT_TOKEN="$(cat lab/k8s/ci/.state/vault-root-token)"   # never echo it
# For curl, put it in a 0600 header file instead of on curl's argv:
(umask 077; printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN" > /tmp/vault.hdr)
curl -s -H @/tmp/vault.hdr "$VAULT_ADDR/v1/clinical/metadata/db" | jq '.data.current_version'

# The workload, without the root token and without printing the password:
k -n clinical-apps get pod -l app.kubernetes.io/name=nightly-report \
  -o jsonpath='{range .items[0].spec.containers[*]}{.name}{"\n"}{end}'   # nightly-report, vault-agent
k -n clinical-apps exec deploy/nightly-report -c nightly-report -- ls -ln /vault/secrets/
k -n clinical-apps exec deploy/nightly-report -c nightly-report -- ls /var/run/secrets  # no such file: no token
# Log in as the workload would (audience vault): 15-minute token, policies default + nightly-report-read
k -n clinical-apps create token nightly-report --audience vault --duration 10m \
  | jq -Rc '{role:"nightly-report", jwt:.}' \
  | curl -s -X POST "$VAULT_ADDR/v1/auth/kubernetes/login" --data @- \
  | jq '.auth | {policies, lease_duration}'

# Try to change nightly-report as a deployer (expect rule 4's denial; this is
# the patch `kubectl rollout restart` sends, which has no --dry-run flag):
DEP=(--as=someone@contosohealth.io --as-group=k8s-clinical-deployers)
k -n clinical-apps patch deployment nightly-report --dry-run=server "${DEP[@]}" \
  -p '{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"probe"}}}}}'
# ...or take it over by moving it to another service account in the same patch
# (rule 4 reads the object before the update too):
k -n clinical-apps patch deployment nightly-report --dry-run=server "${DEP[@]}" --type=json \
  -p '[{"op":"replace","path":"/spec/template/spec/serviceAccountName","value":"default"}]'
# ...and a debug container with an unapproved image, even as the admin (rule 2):
k -n clinical-apps debug "$(k -n clinical-apps get pod -l app.kubernetes.io/name=nightly-report -o name)" \
  --attach=false --profile=restricted --image="registry.invalid/x@sha256:$(printf x | shasum -a 256 | cut -d' ' -f1)"

# Who tried to read Secrets and was refused; who changed RBAC (with bodies)
docker exec contoso-k8s-control-plane cat /var/log/kubernetes/audit/audit.log \
  | jq -c 'select(.objectRef.resource=="secrets" and .responseStatus.code==403)
           | {user: .user.username, as: .impersonatedUser, verb, ns: .objectRef.namespace}'
docker exec contoso-k8s-control-plane cat /var/log/kubernetes/audit/audit.log \
  | jq -c 'select(.objectRef.resource=="rolebindings" and .verb=="patch")
           | {at: .requestReceivedTimestamp, user: .user.username, subjects: .responseObject.subjects}'

lab/k8s/test/k8s-e2e.sh                  # re-run only the tests (never uses the root token)
rm -f /tmp/vault.hdr; unset VAULT_TOKEN
kind delete cluster --name contoso-k8s   # when done (or re-run without KEEP_CLUSTER)
```

A standalone `k8s-e2e.sh` run expects the pipeline's drift drill (stage 10)
in the audit log, which a kept cluster has. If you write a new value to
`clinical/data/db` yourself, update `.state/seed.sha256` (the SHA-256 of the
new value, no trailing newline) or sections (b) and (c) will fail, correctly.

## 6. What this does NOT show

- **No AKS, no Entra ID.** kind, impersonated groups and Vault are
  labelled stand-ins. No Entra token ever reaches this cluster; group
  membership is asserted by the cluster admin with `--as-group`, which is
  exactly what Entra integration replaces. The Entra federated credential is
  written and tested offline only.
- **Vault runs in dev mode:** in memory, one pod, no TLS, unsealed, with a root
  token. The root token is the one bootstrap credential, and it can read
  `clinical/data/db`: generated per cluster (reused only by `KEEP_CLUSTER=1`
  runs), never printed, and gone with the cluster. For that lifetime it sits
  in the Vault pod spec (env), Helm's release record and the vault-0 startup
  log inside the cluster, and, with `KEEP_CLUSTER=1` only, in
  `lab/k8s/ci/.state/vault-root-token` (0600, gitignored) on the developer's
  disk. Full list: `lab/terraform/k8s/platform/README.md`. Production is
  HA Raft storage, TLS, auto-unseal through a KMS/HSM, the root token revoked
  after setup, and admins authenticating through OIDC.
- **Identity borrowing is closed for the deployer, not for the trust root.**
  The tests show a deployer cannot write pods or ReplicaSets, cannot create a
  workload as `nightly-report`, and cannot change its image or its command or
  move it to another service account. What remains:
  - The launcher group is the trust root. Here it is `kubeadm:cluster-admins`,
    the kind admin certificate that the pipeline *and* a human at the laptop
    both use. Its holders can run the approved busybox image with any command
    as `nightly-report` (rule 2 limits the image, not the command) or delete
    the policy (an audited change, at RequestResponse). On AKS that group is a
    GitOps controller's identity, and humans hold no cluster-admin standing.
  - Rule 4 is checked on Pods, Deployments and ReplicaSets. Jobs, CronJobs,
    StatefulSets and DaemonSets are not matched, and their pods are created by
    kube-system controllers, which rule 4 trusts (rules 1-3 still apply to the
    pods). No role here can create those kinds; granting one means adding it
    to the policy first.
  - The deployer can still delete the `nightly-report` Deployment
    (availability, not identity), then create a Deployment of that name
    under another service account, which no Vault role trusts. The policy
    does not match DELETE: a pod's last DELETE comes from the kubelet
    (`system:node:*`) and would need its own exemption. Every other write to
    that workload (image, command, annotations, replicas, `rollout restart`,
    moving it to another service account) is refused by rule 4, and the
    deployer has no ReplicaSet or `deployments/scale` write.
  - Rule 2 compares digests: the same bytes under another registry name pass.
    A digest proves which bytes run, not who built them: no image signature
    verification (cosign / Notation, Ratify) here.
  - Vault's role trusts namespace + name. Only Terraform or a cluster admin
    can recreate `clinical-apps/nightly-report` (the deployer cannot create
    ServiceAccounts); a recreated one gets the same access, under a new Vault
    entity (`alias_name_source = serviceaccount_uid`).
- **Drift detection only sees what Terraform manages, when the pipeline runs.**
  An edit to a managed object is caught at the next plan; a brand-new
  RoleBinding created out of band is not in state, so plan cannot see it (the
  audit log does, at RequestResponse). Nothing watches between runs.
- **Rotation is of the Vault value, not of a database password.** The agent
  re-renders the file in the same pod; there is no real database for Vault's
  database secrets engine to rotate against (the Docker PAM stack shows
  rotation against real AD instead), and the app must re-read the file.
- **No network policy.** Pod-to-pod traffic in the cluster is not restricted;
  segmentation is a separate control from identity.
- **The audit log stays in the node container** and dies with the cluster; it
  is not shipped to a SIEM here.
- **etcd encryption at rest** is not configured: the design does not depend on
  it, because no Secret holds the value.

## Files

```
lab/k8s/
├── README.md                     ← you are here
├── kind/
│   ├── cluster.yaml              ← TEMPLATE: pinned node image, 127.0.0.1:18200 → 30820, audit flags;
│   │                               pipeline.sh substitutes __AUDIT_POLICY_PATH__ (absolute path)
│   └── audit-policy.yaml         ← Secrets/tokens Metadata only; RBAC, pod entry, admission writes with bodies
├── manifests/                    ← `kubectl apply -f` (not -R)
│   ├── nightly-report.yaml       ← Deployment: injector annotations (10 s re-render), projected vault-token,
│   │                               digest-pinned image, restricted-PSA contexts
│   └── negative/
│       └── privileged-pod.yaml   ← deliberately insecure; only for `--dry-run=server`; Checkov skips it
├── rbac-lint/                    ← offline RBAC linter + its canary and fixtures (rbac-lint/README.md);
│                                   not part of pipeline.sh, runs in lab-tests.yml
├── ci/pipeline.sh                ← the one script (CI and humans), 12 stages
├── ci/lib.sh                     ← shared names + helpers
└── test/k8s-e2e.sh               ← PASS/FAIL checks, "K8S E2E PASSED (n/n)"
lab/terraform/k8s/{platform,identity}/   ← the two applied Terraform roots
lab/terraform/k8s/aks-mapping/           ← Entra federated credential, plan-only, never applied
```
