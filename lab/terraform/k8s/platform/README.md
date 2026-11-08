# k8s/platform — namespaces, Pod Security, Vault Helm release (stage 1 of 2)

**Stand-ins:** kind stands in for AKS. In-cluster Vault (dev mode) stands in
for the Azure-native target on AKS: Entra Workload ID + the Key Vault CSI
driver (ADR 0036). See
[`lab/docs/STAND-INS.md`](../../../docs/STAND-INS.md).

Stage 2 is [`../identity`](../identity/README.md). Why there are two stages:
[`../README.md`](../README.md#why-two-stages).

| Object | Terraform | Value |
|---|---|---|
| Namespace `vault` | `kubernetes_namespace_v1.vault` | PSA `enforce=baseline`, `warn`/`audit=restricted`, policy version pinned `v1.36` |
| Namespace `clinical-apps` | `kubernetes_namespace_v1.clinical_apps` | PSA `enforce`/`warn`/`audit=restricted` (`v1.36`); label `contoso.health/vault-agent-injection=enabled` |
| Vault server + Agent Injector | `helm_release.vault` | chart `hashicorp/vault` **0.34.1**, image `hashicorp/vault:2.1.1@sha256:47f14a6a…` (server and injected agent; same version as the Docker PAM stack), injector `hashicorp/vault-k8s:1.7.6@sha256:55e27b08…`, dev mode, service NodePort **30820** |
| Release inputs | `terraform_data.vault_release_inputs` | values hash + chart version + token revision; any change reinstalls the release (see below) |

Output `vault_addr` = `http://127.0.0.1:18200` (kind maps host
127.0.0.1:18200 to NodePort 30820, `lab/k8s/kind/cluster.yaml`). Output
`vault_agent_image` = the exact, digest-pinned image string the injector
writes into app pods (`hashicorp/vault:2.1.1@sha256:47f14a6a…`); the pipeline
can hand it to `../identity` as `TF_VAR_vault_agent_image`.

## Decisions

**Dev mode, on purpose and only here.** In-memory storage, auto-unsealed,
plain HTTP, a root token. That is acceptable only because the cluster lives
for one pipeline run. Production Vault is HA on Raft with TLS and auto-unseal,
and the root token is revoked after setup.

**Where the root token is, precisely.** It is generated per cluster by
`lab/k8s/ci/pipeline.sh` (a fresh one every time the cluster is created; only
a `KEEP_CLUSTER=1` run that reuses a kept cluster reuses its token) and passed
as `TF_VAR_vault_dev_root_token`.

| Place | Holds the token? | Why |
|---|---|---|
| git | no | never committed; the variable has no default |
| Terraform plan file / state | **no** | `ephemeral = true` variable, delivered through the write-only `set_wo` (Terraform 1.11+) |
| CI / pipeline logs | no | never echoed; Terraform redacts sensitive values; the pipeline also masks it in Terraform and diagnostic output and registers it with `::add-mask::` on GitHub |
| Vault StatefulSet env (`VAULT_DEV_ROOT_TOKEN_ID`) and Helm's release record (a Secret in ns `vault`) | **yes** | that is how the chart's dev mode works; both die with the cluster; no RBAC in this lab grants anyone in `clinical-apps` access to ns `vault` |
| `vault-0` container log | **yes** | dev mode prints `Root Token:` in its startup banner; the pipeline never reads that log (its failure diagnostics skip the vault-0 pod on purpose); dies with the cluster |
| `lab/k8s/ci/.state/vault-root-token` (`KEEP_CLUSTER=1` only) | **yes** | 0600, gitignored, on the developer's disk so the next `KEEP_CLUSTER=1` run can drive the kept Vault; deleted by the next full (non-`KEEP_CLUSTER`) run. Never written in CI |

**Reinstall instead of upgrade.** The Helm provider applies `set_wo` only on
create, or on an update that raises `set_wo_revision`. A plain `helm upgrade`
would re-render the chart without the token and fall back to the chart default
`root`. So every input change replaces `terraform_data.vault_release_inputs`,
which (`replace_triggered_by`) reinstalls the release, and create always
applies `set_wo`. Vault loses its data on reinstall, which costs nothing in
dev mode: stage 2 and the seed step recreate it. The token itself must be
24+ characters from `[A-Za-z0-9._-]` (Helm's `--set` parser would split on a
comma), which also rejects the chart default `root`.

**The injector webhook fails closed, and only where opted in.** The chart's
default `failurePolicy` is `Ignore`: if the injector is down, pods start
without the Vault Agent, silently. Here it is `Fail`, and the webhook's
`namespaceSelector` matches only namespaces labelled
`contoso.health/vault-agent-injection=enabled` (just `clinical-apps`), so an
injector outage blocks the opted-in workloads instead of every pod in the
cluster. Labelling a namespace is a cluster-admin action; the human roles in
stage 2 grant nothing on namespaces.

**Pod Security.** `clinical-apps` enforces `restricted`: the app and the
injected agent containers run non-root, drop all capabilities, no privilege
escalation, `RuntimeDefault` seccomp. `vault` enforces `baseline` (all the
chart needs), but the server and injector security contexts are restated with
`seccompProfile: RuntimeDefault` and `capabilities.drop: [ALL]` so they also
meet `restricted`; `warn`/`audit=restricted` on the namespace would surface a
regression as a warning without breaking the install. The PSA policy version
is pinned to `v1.36` (the node image's minor), so a node bump cannot silently
change what `restricted` means.

**`wait = true`, `timeout = 600`, not atomic.** Stage 2 and the workload
rollout must not race a half-started Vault or a missing webhook backend. A
failed install keeps its pods for `kubectl describe` (the pipeline tears the
cluster down regardless).

**Every image pinned by digest, and why the agent's pin is load-bearing.**
The server, the injector and the injected Vault Agent all run by the
multi-arch index digest of their tag (resolved from `registry-1.docker.io`
on 2026-10-20; both indexes cover `linux/amd64` and `linux/arm64`), so a
re-pushed tag cannot change what runs. The agent pin is more than hygiene:
`../identity`'s ValidatingAdmissionPolicy rejects any container in
`clinical-apps` whose image lacks `@sha256:`, and the injector's mutating
webhook runs *before* validating admission, so the policy judges the
injected `vault-agent-init` / `vault-agent` containers too. The chart has no
digest field; it renders `"<repository>:<tag>"`
(`templates/injector-deployment.yaml`, env `AGENT_INJECT_VAULT_IMAGE`), and
vault-k8s 1.7.6 copies that string verbatim into the agent containers, so
the tag carries it: `2.1.1@sha256:<digest>`. Checked on a scratch kind
cluster that such a pod passes the policy and a tag-only agent does not.

**Pinned constants, not variables.** Chart version, image versions and
digests, ports and PSA levels are `locals` in `main.tf`, asserted by
`tests/platform.tftest.hcl`, so they change only by a reviewed edit.

## Running

Normally via `lab/k8s/ci/pipeline.sh` (its "terraform apply platform"
stage). By hand, against an
existing `kind-contoso-k8s` cluster:

```bash
export TF_VAR_vault_dev_root_token="$(openssl rand -hex 32)"   # never echo it
# export TF_VAR_kubeconfig_path="$KUBECONFIG"                  # only if KUBECONFIG is set
terraform -chdir=lab/terraform/k8s/platform init
terraform -chdir=lab/terraform/k8s/platform apply
```

**Re-running against a kept cluster (`KEEP_CLUSTER=1`):** Terraform cannot
see a write-only value, so a *new* token alone changes nothing and Vault keeps
the token it booted with. Either reuse the token from the first run, or pass a
higher revision so the release is reinstalled with the new token:
`TF_VAR_vault_dev_root_token_revision="$(date +%s)"`.

**Destroy** needs a value for the token variable too (Terraform requires every
variable without a default), but does not use it; any valid-format value works.

## Offline checks

```bash
terraform -chdir=lab/terraform/k8s/platform init -backend=false
terraform -chdir=lab/terraform/k8s/platform validate
terraform -chdir=lab/terraform/k8s/platform test     # mocked helm + kubernetes providers
```

`tests/platform.tftest.hcl` pins: PSA levels per namespace; chart 0.34.1,
dev mode, server and agent at 2.1.1 with the same digest, server, agent and
injector tags all `<version>@sha256:<64 hex>`, output `vault_agent_image`
equal to what the injector writes, NodePort 30820; the root token absent from the
plain values and `set_wo_revision >= 1`; webhook `Fail` with a non-empty
selector that matches `clinical-apps` and not `vault`; a weak token and a
non-kind context rejected.

## What changes on AKS

The namespaces and PSA labels carry over unchanged (PSA is upstream
Kubernetes). The Vault release would not: on AKS the Azure-native design
drops in-cluster Vault for **Entra Workload ID** (OIDC issuer + workload
identity webhook) and the **Key Vault Secrets Store CSI driver** add-on, or
keeps Vault as an HA, TLS, auto-unsealed service outside the dev-mode
shortcut. See [`../identity/README.md`](../identity/README.md#what-changes-on-aks).

## Sources

- Chart values and templates read from `vault-0.34.1.tgz`
  (`https://helm.releases.hashicorp.com`), 2026-10-19: `server.dev.*`,
  `server.image`, `server.service.type/nodePort`, `server.authDelegator`,
  `server.statefulSet.securityContext`, `injector.agentImage`,
  `injector.webhook.failurePolicy/namespaceSelector`,
  `injector.securityContext`. The rendered manifest was checked with the Helm
  provider's `helm_template` data source.
- `set_wo` / `set_wo_revision` behaviour: `helm/resource_helm_release.go` in
  `hashicorp/terraform-provider-helm` v3.3.0.
- Provider release dates: the GitHub releases pages of the three providers.
- Image digests: `HEAD https://registry-1.docker.io/v2/<repo>/manifests/<tag>`
  (`Docker-Content-Digest`, media type
  `application/vnd.docker.distribution.manifest.list.v2+json`), 2026-10-20;
  `hashicorp/vault:2.1.1` matches the locally pulled image's RepoDigest.
- Agent image handling: vault-k8s v1.7.6
  `agent-inject/agent/container_sidecar.go` (`Image: a.ImageName`).
