# Kubernetes workload identity: secrets with no static secret in the workload's path

A local, fully-as-code Kubernetes segment of the Contoso Health identity lab.
A clinical workload (`nightly-report`) gets its database password **without a
Kubernetes Secret, an environment variable, a token or a value in any
manifest**. The Secrets Store CSI Driver asks for a short-lived service-account
token for the pod, Microsoft Entra ID exchanges it for a Key Vault token
(Entra Workload ID: a federated credential, no client secret), and Azure Key
Vault returns exactly one secret, because Azure RBAC grants exactly one. The
driver writes it to a tmpfs file in the pod. Around that one exchange:

- **who may be `nightly-report`** is decided per workload: RBAC keeps human
  deployers away from pods, a ValidatingAdmissionPolicy binds the identity to
  one reviewed image digest and to the release pipeline, and Entra trusts
  exactly one namespace + name;
- **the value rotates without a restart**: a new version in Key Vault becomes
  the new file content in the same pod;
- **drift is detected and healed**: an out-of-band RoleBinding edit makes
  `terraform plan` exit 2, and applying the reviewed plan puts it back;
- **the evidence is in the API-server audit log**, which records who tried
  and changed what, and is shown to hold no secret value or token;
- **no secret is in Terraform state**, counted on every run.

**What is real and what stands in** (rows in [`../docs/STAND-INS.md`](../docs/STAND-INS.md)):

| What runs here | Real or stand-in |
|---|---|
| **Azure Key Vault** (RBAC, Standard), **Microsoft Entra Workload ID** (app registration + federated credential), **Secrets Store CSI Driver + Azure Key Vault provider** | **Real.** A throwaway vault and app registration per run, deleted (and the vault purged) at teardown |
| **kind** cluster `contoso-k8s` (one node, Kubernetes 1.36) | Stand-in for **AKS** |
| The cluster's service-account issuer on a **storage static website** the pipeline fills | Stand-in for AKS's managed OIDC issuer |
| Kubernetes groups via `kubectl --as-group` (impersonation) | Stand-in for **Entra ID groups** through AKS's Entra integration |

Until 2026-11-06 an in-cluster HashiCorp Vault (dev mode) stood in for the
secret store. ADR 0036 ("Microsoft-native PAM") retired it: where Microsoft
offers the product, the lab uses it. The Vault run's record stays as history
in [`../evidence/k8s/20261020T202112Z/`](../evidence/k8s/20261020T202112Z/README.md).

> **Status: RAN · tenant** on 2026-11-07 (run 864b1cef): the 12-stage
> pipeline ran green on the lab Mac as the lab operator, against the real
> tenant and a throwaway Key Vault, in 507 s, `K8S E2E PASSED
> (66/66)`, teardown read back clean. Record:
> [`../evidence/k8s-keyvault/20261107T013045Z/`](../evidence/k8s-keyvault/20261107T013045Z/run.log).
> GitHub Actions runs the static stages only (section 5).

---

## 1. The problem

The usual ways a pod gets a database password are all static secrets:

- **A Kubernetes Secret.** Base64, not encryption. It sits in etcd, anyone
  with `get secrets` in the namespace reads it, it lands in Helm release
  records and backups, and it is rotated by hand, i.e. rarely.
- **An environment variable.** Visible in `kubectl describe` and the pod spec,
  inherited by every child process, dumped by crash reporters, and fixed for
  the container's whole life.
- **A client secret for a cloud identity**, mounted to call Key Vault. It
  never expires on its own and works from anywhere.

All three are "secret zero": a long-lived credential whose only protection is
that nobody copies it. This segment removes it. The workload's app
registration has **no** password or certificate; the only way to sign in as
it is a token signed by this cluster, for this one service account.

Removing the static secret moves the question to **who can become the
workload**. In plain Kubernetes, anyone who can create a pod in a namespace
can run it as any service account there. Section 3 shows how that is closed.

## 2. Architecture

```
 host: macOS + Colima (one script: lab/scripts/operator/op lab/k8s/ci/pipeline.sh)
 ├─ az (as the lab operator)  rg-lab-sandbox, tagged run-id: storage static website (the issuer) + Key Vault
 │                                                 (clinical-db + a decoy)
 ├─ terraform  lab/terraform/k8s/keyvault-trust ─► Entra: app (no credential) + federated credential
 │                                                 Azure RBAC: Key Vault Secrets User on clinical-db only
 │             lab/terraform/k8s/platform       ─► namespaces + PSA labels, Helm: CSI driver + Azure provider
 │             lab/terraform/k8s/identity       ─► SAs, SecretProviderClass, Roles + RoleBindings,
 │                                                 ValidatingAdmissionPolicy + binding
 └─ docker: kind node contoso-k8s-control-plane (kindest/node v1.36.4, pinned by digest)
     kube-apiserver  --service-account-issuer=https://stk8skv<run>.z<N>.web.core.windows.net
                     ─► /var/log/kubernetes/audit/audit.log
     (its discovery document + JWKS are copied to that website and read back anonymously)

     namespace secrets-store  PSA enforce=privileged (CSI node plugin), warn/audit=baseline
       secrets-store-csi-driver (DaemonSet)  +  csi-secrets-store-provider-azure (DaemonSet)

     namespace clinical-apps  PSA enforce=restricted
     ┌── pod nightly-report (SA nightly-report, no API token, NOTHING injected) ───────────────┐
     │ volume secrets-store: CSI, SecretProviderClass nightly-report-db                        │
     │   1. kubelet ─► driver: token for SA nightly-report, aud api://AzureADTokenExchange      │
     │   2. Azure provider ─► login.microsoftonline.com: client_credentials + that token        │
     │      Entra: JWKS from the issuer website; issuer + subject + audience = the credential?  │
     │   3. ─► <vault>.vault.azure.net: GET secrets/clinical-db (RBAC: Secrets User, 1 secret)  │
     │   4. driver ─► /mnt/secrets-store/db (tmpfs, read-only); re-read every 10 s              │
     │ nightly-report (busybox @sha256) reads the file. No token, no env, no SDK.               │
     └─────────────────────────────────────────────────────────────────────────────────────────┘

     humans (impersonated):  group k8s-clinical-deployers ─► Role app-deployer (Deployments; pods and
                                                              ReplicaSets read-only; no secrets,
                                                              no RBAC, no exec)
                             group k8s-clinical-auditors  ─► Role auditor      (read-only, no secrets)
```

### What each piece proves

| Concern | Mechanism | Where |
|---|---|---|
| Workload identity | A TokenRequest for the pod's SA, audience `api://AzureADTokenExchange`, 600 s; requested by the CSI driver, never mounted in a container | [`../terraform/k8s/platform`](../terraform/k8s/platform/README.md) (CSIDriver `tokenRequests`) |
| Authentication | Entra Workload ID: a federated credential trusting one issuer + subject + audience; the app has no secret | [`../terraform/k8s/keyvault-trust`](../terraform/k8s/keyvault-trust/README.md) |
| Authorization | Azure RBAC: Key Vault Secrets User on `clinical-db` only (a decoy in the same vault is refused) | `keyvault-trust` |
| Delivery | CSI volume, one object, tmpfs; no `secretObjects`, Secret sync off | `identity` (SecretProviderClass), [`manifests/nightly-report.yaml`](manifests/nightly-report.yaml) |
| Who may be the workload | `app-deployer` has no pod or ReplicaSet write verbs; ValidatingAdmissionPolicy `clinical-apps-workload-identity` (four rules); Entra trusts one namespace + name | `identity`, `keyvault-trust` |
| Admission guardrails | PSA `restricted` on `clinical-apps`, then the policy | `platform` + `identity`, [`manifests/negative/`](manifests/negative/privileged-pod.yaml) |
| Rotation without restart | driver `--enable-secret-rotation`, every 10 s | `platform`; `ci/pipeline.sh` stage 9 |
| Drift detection | `terraform plan -detailed-exitcode` after an out-of-band RoleBinding edit; the reviewed plan heals it | `ci/pipeline.sh` stage 10 |
| No secret in state | Terraform never sees the value (az sets it in Key Vault); stage 12 counts every version in three states + the audit log (0) | `ci/pipeline.sh` stages 4, 9, 12 |
| Human least privilege | Namespaced Roles bound to groups; no Secrets, no SecretProviderClasses, no RBAC, no `serviceaccounts/token`, no exec | `identity` |
| Human access to the LAB vault | PIM: an eligible Key Vault Secrets Officer group on kv-idlab, flag off | `lab/terraform/modules/pim/keyvault.tf` |
| Evidence | Audit policy: Secrets / TokenRequest / TokenReview at Metadata only; RBAC objects, pod entry and admission-config writes at RequestResponse | [`kind/audit-policy.yaml`](kind/audit-policy.yaml) |

### The admission policy

`clinical-apps-workload-identity` is a `ValidatingAdmissionPolicy`
(`admissionregistration.k8s.io/v1`, CEL inside the API server) bound with
`validationActions: [Deny]` and `failurePolicy: Fail`. It matches CREATE and
UPDATE of Pods (and `pods/ephemeralcontainers`), Deployments and ReplicaSets
in `clinical-apps`. The API server reports the first failing rule:

| # | Rule | Denial starts with |
|---|---|---|
| 1 | Every container, init container and ephemeral container image is pinned by digest | `image not pinned by digest:` |
| 2 | A workload running as `nightly-report` runs only the approved app digest | `service account nightly-report may run only the approved app image` |
| 3 | `automountServiceAccountToken: false` in the pod spec | `automountServiceAccountToken must be false in the pod spec` |
| 4 | Only the release pipeline's group and the kube-system controllers may create a workload that runs as `nightly-report`, or change one that does (both sides of an UPDATE are checked) | `only the release pipeline may create or change a workload that runs as service account nightly-report` |

The CSI driver injects no container, so the policy judges exactly what the
Deployment declares.

### The tests

The pipeline asserts as it goes (stages 5-10, 12) and then runs
[`test/k8s-e2e.sh`](test/k8s-e2e.sh) (stage 11). Every check prints one
PASS/FAIL line; every "denied" must be the server's own refusal naming the
reason (an Entra `AADSTS` code, Key Vault's `ForbiddenByRbac`), with a
positive control first. **The e2e test uses no operator credential and no
az**: it mints the workload's own token and exchanges it itself.

**e2e test, 66 assertions:**

- **(a) platform:** node, CSI driver and Azure provider Ready; the CSIDriver
  requests exactly one audience; PSA labels; the public issuer serves the API
  server's own discovery document and JWKS (same SHA-256).
- **(b) workload:** Ready, nothing injected; the mounted file hashes (inside
  the pod) to the current value; no API token and no projected token at all
  in the pod; no env value or Secret reference; the SecretProviderClass
  names this app and syncs nothing.
- **(c) Entra + Key Vault:** a `nightly-report` token (issuer = the public
  website, audience `api://AzureADTokenExchange`, 600 s) is exchanged for a
  Key Vault token of this app in this tenant; it reads `clinical-db`; Key
  Vault refuses it the decoy in the same vault, a write and a list (403
  `ForbiddenByRbac`); Entra refuses `unapproved-job`'s token (`AADSTS700213`,
  no matching subject) and `nightly-report`'s default-audience token
  (`AADSTS700212`, no matching audience); the API server refuses the
  exchange-audience token (401) and accepts a default-audience one (200).
- **(d) identity is namespace + name:** a ServiceAccount also called
  `nightly-report` in a fixture namespace `other-team` is refused by Entra
  (`AADSTS700213`); a token for a ServiceAccount that is deleted and
  recreated under the same name gets 401 at the API server; **a real pod**
  running as `unapproved-job` that names the same SecretProviderClass never
  starts (FailedMount: Entra `AADSTS700213`).
- **(e) no static secret:** the value is in no Secret, ConfigMap, Deployment,
  ReplicaSet or Pod (plain, base64, decoded); no legacy token Secrets; both
  ServiceAccounts opt out of automount.
- **(f) RBAC:** the can-i matrix below, every cell enforced; the deployer can
  ship a Deployment and read pods and logs, but cannot write pods or
  ReplicaSets, read Secrets, list `kube-system`, mint the workload's token,
  create RoleBindings, or exec / attach / port-forward / debug; the auditor
  reads but cannot read or list Secrets or delete.
- **(g) admission** (server-side dry runs, nothing persisted): denials and
  admitted controls for each rule, including the deployer borrowing or
  hijacking the identity four ways. PSA still rejects the privileged pod.
- **(h) audit log:** the deployer's forbidden Secret read; Secret and
  TokenRequest events at Metadata with no body; the drift drill's patch and
  Terraform's revert; the policy write with its body.

```
                   create    patch     get       create    imper-    pods/     list pods
                   deploys   pods      secrets   rolebind  sonate    exec      kube-sys
deployer           yes       no        no        no        no        no        no
auditor            no        no        no        no        no        no        no
SA nightly-report  no        no        no        no        no        no        no
SA unapproved-job  no        no        no        no        no        no        no
```

**Measured in the 2026-11-07 run** (lab Mac, Colima, eastus2):

| Step | Time |
|---|---|
| Stage 4: resource group, storage issuer, Key Vault, two secrets, app + federated credential + role | 127 s |
| Stage 5: kind cluster, issuer published and read back | 54 s |
| Stage 6: CSI driver + Azure provider installed | 21 s |
| Stage 8: pod Ready (first Entra exchange + Key Vault read included) | 34 s |
| Stage 9: new Key Vault version live in the same pod | ~5 s |
| Whole run, teardown included (vault purged, app deleted, read back) | 507 s |
| Entra access token lifetime (from its claims) | 3900 (Entra `expires_in` 3599) s |

## 3. Decisions and alternatives

### CSI driver vs. the Workload ID webhook + SDK vs. External Secrets

| | **CSI driver + Azure provider** (chosen) | **Workload ID webhook + Azure Identity in the app** | **External Secrets Operator** |
|---|---|---|---|
| Where the value lives | tmpfs file in the pod | in the app's memory | a **Kubernetes Secret** (etcd) |
| Token in the pod? | No (the driver holds it) | Yes (projected, the app uses it) | No |
| App changes | None: read a file | Azure SDK, token handling | None, but must reload |
| Rotation | Driver poll, same pod | The app's own logic | Refresh, then reload |

The CSI driver is the only one where the app holds neither a token nor a
Kubernetes Secret, which is the claim this segment makes and tests. It is
also the AKS managed add-on.

### Entra checks the JWKS, not the API server

Vault's Kubernetes auth asked the API server (TokenReview) at every login,
so a deleted pod's token stopped working at once. Entra Workload ID reads
the issuer's public JWKS and validates the token itself, so a token stays
exchangeable until it expires. Compensations: the driver's token lives 10
minutes; the API server itself rejects it (tested); and only one subject is
trusted. verify: measure Entra's behaviour with a deleted service account.

### Closing identity borrowing: RBAC, then a policy with four rules

`app-deployer` cannot write pods or ReplicaSets (RBAC). Rules 1-3 bind
`nightly-report` to one reviewed digest with no API token; rule 4 binds it
to who deploys it, so a deployer cannot keep the approved busybox image and
swap the command to print the file. Entra adds the last layer: naming the
SecretProviderClass from another service account gets nothing, because the
driver asks for the POD's token (tested with a real pod, section d).

### Rotation without a restart

The driver re-reads every mounted object every 10 s (`rotationPollInterval`)
with a fresh token and rewrites the file. Stage 9 writes a new version with
az and waits for the in-pod SHA-256 to change, then checks the same pod UID
and unchanged restart counts. 10 s costs one Key Vault read per pod every
10 s; production would use minutes. The app must re-read the file.

### Drift: plan -detailed-exitcode, then apply the reviewed plan

Stage 10 changes a RoleBinding as the cluster admin, requires
`plan -detailed-exitcode` to exit 2 on exactly that resource, applies the
saved plan, and requires a clean plan (0) after.

### Audit policy: what gets a body, and what never does

Secrets, `serviceaccounts/token` (the response is a live JWT, the very token
Entra exchanges) and TokenReviews are pinned to Metadata first. RBAC objects,
pod entry and admission-config writes are logged with bodies. Stage 12 and
section (h) check the log holds no value and no body.

### Why three Terraform roots

`keyvault-trust` talks to Entra and Azure; `platform` and `identity` to the
cluster. The SecretProviderClass is a CRD the platform's chart installs, so
`identity` comes after `platform`. Separate state means the cluster roots
never hold an Azure identity.

### Smaller choices

- **The secret value is not in Terraform.** az sets it in Key Vault from a
  0600 file (never argv); the pipeline keeps only its SHA-256.
- **No trailing newline.** `sha256sum /mnt/secrets-store/db` in the pod
  equals `printf '%s' "$value" | sha256sum` at write time.
- **Pinned by digest:** the kind node image, busybox, and every CSI driver
  and provider image (multi-arch indexes). Rule 1 makes this a requirement.
- **The issuer website holds public keys only.** Only the operator can write
  it, and it is deleted at teardown.
- **A fixed API server port** (`127.0.0.1:16443`), so a manual port forward
  can be set up before the cluster exists (section 5).

## 4. What changes on AKS

| Here (kind) | On AKS |
|---|---|
| `kubectl --as --as-group` impersonation, kind admin cert | **AKS-managed Entra ID integration**, local accounts disabled; RoleBindings to **Entra group object IDs**, or Azure RBAC for Kubernetes |
| Standing group membership | **PIM for Groups**: the deployer group is eligible, activated for hours |
| Launcher group `kubeadm:cluster-admins` | The GitOps controller's or release pipeline's own identity |
| Issuer on a storage static website | AKS's managed OIDC issuer (`--enable-oidc-issuer`); set `keyvault-trust`'s `issuer_url` to it |
| CSI driver from Microsoft's Helm chart | The `azure-keyvault-secrets-provider` add-on (same driver and provider) |
| A throwaway vault, role on one secret | A vault per app per environment, role at vault scope (Microsoft Learn's recommendation) |
| ValidatingAdmissionPolicy | The same object; **Azure Policy for Kubernetes** for organisation-wide guardrails |
| Audit policy file in the node | Control-plane diagnostic settings (`kube-audit-admin` / `kube-audit`) to Log Analytics (verify: category names) |

## 5. Run it

Prerequisites: Docker (Colima with at least 4 CPU / 8 GiB on a Mac),
`terraform` 1.16.5, `checkov`, `jq`, `curl`, `openssl`, `az`, and the lab
operator (`lab/scripts/operator/op`; ADR 0024). `kind` v0.33.0 and `kubectl`
v1.37.1 are hashed against the pins on every run. Use a terminal at least
100 columns wide.

**Needs an operator write session (since ADR 0030).** The operator is
read-only between sessions. Stage 4 creates a storage account, a vault and
role assignments, so it runs only while the owner has a write session open:
`envs/operator` then gives the operator Contributor and RBAC Administrator on
the sandbox resource group `rg-lab-sandbox` only (`sandbox.tf`, PR #249).
Without one, preflight stops with the reason. `STOP_AFTER=3` needs no
session.

```bash
lab/scripts/operator/op lab/k8s/ci/pipeline.sh                  # all 12 stages, then deletes everything
KEEP_CLUSTER=1 lab/scripts/operator/op lab/k8s/ci/pipeline.sh   # keep cluster + Azure objects to explore
lab/scripts/operator/op lab/k8s/ci/pipeline.sh --teardown       # delete what a kept run left
STOP_AFTER=3 lab/k8s/ci/pipeline.sh                             # static checks only (no cluster, no Azure)
```

**Port forward on the lab Mac (seen 2026-11-07).** Colima's own forwarder
stopped forwarding newly published ports on the default profile (its ssh
control socket was stale). Workaround, no VM restart: forward the fixed API
port with a separate ssh connection, then run the pipeline with
`DOCKER_CONTEXT=colima`:

```bash
ssh -F <(colima ssh-config -p default) -o ControlMaster=no -o ControlPath=none \
  -f -N -L 127.0.0.1:16443:127.0.0.1:16443 colima
```

| Stage | What it does |
|---|---|
| `[1/12]` preflight | tool versions; kind + kubectl hashed; az must be the operator service principal |
| `[2/12]` terraform fmt / validate / test | `platform`, `identity`, `keyvault-trust` (mocked providers, 17 test runs) |
| `[3/12]` checkov | terraform + kubernetes frameworks; any inline skip must give a reason |
| `[4/12]` azure | in the sandbox resource group (tagged per run): storage static website, Key Vault, `clinical-db` + decoy; `keyvault-trust` apply |
| `[5/12]` kind cluster + public issuer | `contoso-k8s` with that issuer; discovery doc + JWKS published, read back |
| `[6/12]` terraform apply platform | namespaces + PSA, CSI driver + Azure provider (read back: one token audience) |
| `[7/12]` terraform apply identity | SAs, SecretProviderClass, human RBAC, the admission policy (read back live: `[Deny]`) |
| `[8/12]` deploy workload | `kubectl apply -f manifests/` + rollout status (Ready only if Entra and Key Vault said yes) |
| `[9/12]` rotate secret (no restart) | new Key Vault version, same pod, no restart |
| `[10/12]` drift: detect + heal | `DRIFT DETECTED` (plan 2) → apply → plan 0 |
| `[11/12]` e2e tests | `test/k8s-e2e.sh` |
| `[12/12]` secrets out of state | 0 hits in three states and the audit log |

**GitHub Actions** (`.github/workflows/k8s-identity.yml`) runs stages 1-3
only. The live stages create an app registration, which needs a Tier-0-class
identity; the lab does not keep one in CI (ADR 0024). Said plainly: CI no
longer builds the cluster.

## 6. What this does NOT show

- **No AKS and no Entra sign-in for humans.** kind and impersonated groups
  are labelled stand-ins; the workload's Entra and Key Vault calls are real.
- **The issuer is a lab construction.** A storage static website the
  operator fills; whoever could write it could make Entra trust their keys.
  It lives one run. AKS manages its own issuer.
- **Entra does not see a deleted service account** until the token expires
  (section 3). Not measured here (verify).
- **Identity borrowing is closed for the deployer, not for the trust root.**
  The launcher group (here the kind admin certificate, used by the pipeline
  and the human at the laptop) can run the approved image with any command as
  `nightly-report`, or delete the policy (an audited change). Rule 4 matches
  Pods, Deployments and ReplicaSets, not Jobs, CronJobs, StatefulSets or
  DaemonSets (no role here can create those). The deployer can still delete
  the Deployment (availability, not identity). Rule 2 compares digests; no
  image signature verification here.
- **Drift detection only sees what Terraform manages, when the pipeline runs.**
- **Rotation is of the Key Vault value, not of a database password.** There
  is no real database; the app must re-read the file.
- **No egress policy.** Only ingress to the pod is denied (NetworkPolicy).
- **The audit log stays in the node container** and dies with the cluster.
- **CI runs static checks only** (section 5).

## Files

```
lab/k8s/
├── README.md                     ← you are here
├── kind/
│   ├── cluster.yaml              ← TEMPLATE: pinned node image, fixed API port 127.0.0.1:16443, audit flags,
│   │                               public service-account issuer (__SA_ISSUER__, __AUDIT_POLICY_PATH__)
│   └── audit-policy.yaml         ← Secrets/tokens Metadata only; RBAC, pod entry, admission writes with bodies
├── manifests/                    ← `kubectl apply -f` (not -R)
│   ├── nightly-report.yaml       ← Deployment: one CSI volume (SecretProviderClass nightly-report-db),
│   │                               digest-pinned image, restricted-PSA contexts
│   ├── nightly-report-networkpolicy.yaml
│   └── negative/privileged-pod.yaml ← deliberately insecure; only for `--dry-run=server`; Checkov skips it
├── rbac-lint/                    ← offline RBAC linter (rbac-lint/README.md); runs in lab-tests.yml
├── ci/pipeline.sh                ← the one script, 12 stages
├── ci/azure.sh                   ← the throwaway Azure side (operator only)
├── ci/lib.sh                     ← shared names + helpers
└── test/k8s-e2e.sh               ← PASS/FAIL checks, "K8S E2E PASSED (n/n)"
lab/terraform/k8s/{keyvault-trust,platform,identity}/   ← the three applied Terraform roots
```
