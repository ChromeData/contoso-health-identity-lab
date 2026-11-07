# =============================================================================
# k8s/platform :: main.tf
# -----------------------------------------------------------------------------
# WHAT (stage 1 of 2 - stage 2 is ../identity):
#   * namespace "vault"          PSA enforce=baseline (warn/audit=restricted)
#   * namespace "clinical-apps"  PSA enforce/warn/audit=restricted, and the
#                                opt-in label the Agent Injector webhook
#                                selects on
#   * helm_release "vault"       chart hashicorp/vault 0.34.1: a dev-mode Vault
#                                server (image hashicorp/vault:2.1.1, the same
#                                version as the Docker PAM stack, pinned by
#                                digest like every image here) + the Vault
#                                Agent Injector, server exposed on NodePort
#                                30820 -> 127.0.0.1:18200 on the host (kind
#                                extraPortMappings in lab/k8s/kind/cluster.yaml)
#
# STAND-IN: Vault (Kubernetes auth + Agent Injector) stands in for the
# Azure-native target on AKS: Entra Workload ID + the Key Vault CSI driver
# (ADR 0027, lab/docs/STAND-INS.md). kind stands in for AKS.
#
# DEV MODE IS A LAB SHORTCUT, AND IT IS ONLY ACCEPTABLE BECAUSE THE CLUSTER IS
# EPHEMERAL: in-memory storage, auto-unsealed, plain HTTP, and a root token.
# Production Vault runs HA with Raft storage, TLS, auto-unseal, and the root
# token is revoked after initial setup (Terraform then authenticates with a
# short-lived token from an auth method, e.g. JWT/OIDC from CI).
#
# WHERE THE ROOT TOKEN LIVES (be precise about it in an interview):
#   * NOT in git, NOT in a Terraform plan file, NOT in Terraform state: the
#     variable is ephemeral and reaches Helm only via the write-only set_wo.
#   * IT IS inside the cluster: the chart puts it in the Vault StatefulSet as
#     the VAULT_DEV_ROOT_TOKEN_ID env var, and Helm keeps every release's
#     values in its release record (a Secret in namespace "vault"), and dev
#     mode prints it ("Root Token:") in the vault-0 container's startup log,
#     which the pipeline never reads. All three die with the kind cluster.
#     Nothing in clinical-apps can read namespace "vault" (no RBAC grants it).
#   * With KEEP_CLUSTER=1 only, lab/k8s/ci/pipeline.sh also keeps it on the
#     developer's disk (lab/k8s/ci/.state/vault-root-token, 0600, gitignored)
#     so the next KEEP_CLUSTER=1 run can drive the kept Vault; the next full
#     run deletes it. In that case the token is per cluster, not per run.
#
# WHY THE WEBHOOK FAILS CLOSED: the chart's default injector failurePolicy is
# Ignore, which means "if the injector is down, create the pod WITHOUT the
# Vault Agent" - a silent failure. Here it is Fail, and the webhook only
# matches namespaces that opt in with a label (clinical-apps), so an injector
# outage blocks only the opted-in workloads instead of every pod in the
# cluster (kube-system included).
# =============================================================================

locals {
  # ---- Pinned versions (bump deliberately, one PR each) ---------------------
  vault_chart_repository = "https://helm.releases.hashicorp.com"
  vault_chart_version    = "0.34.1"          # chart appVersion is 2.0.4; image overridden below
  vault_image_repository = "hashicorp/vault" # Docker Hub official HashiCorp image
  vault_image_version    = "2.1.1"           # same as lab/pam/docker-compose.yml
  injector_image_version = "1.7.6"           # hashicorp/vault-k8s, the 0.34.1 chart default, pinned explicitly

  # Image DIGESTS: the multi-arch index (manifest list) digest of each tag,
  # resolved from registry-1.docker.io on 2026-10-20 (HEAD on
  # /v2/<repo>/manifests/<tag>, Docker-Content-Digest header; both indexes
  # cover linux/amd64 for CI and linux/arm64 for Apple Silicon). The tag stays
  # in the reference for humans; the kubelet pulls by the digest, so a re-
  # pushed tag cannot change what runs.
  #
  # WHY THIS MATTERS BEYOND HYGIENE: ../identity installs a
  # ValidatingAdmissionPolicy on clinical-apps that rejects any container image
  # without "@sha256:", and the Vault Agent containers the injector adds to app
  # pods are containers too. The injector's mutating webhook runs BEFORE
  # validating admission, so the policy sees (and judges) the injected agent.
  # The chart renders the agent image as "<repository>:<tag>"
  # (templates/injector-deployment.yaml, env AGENT_INJECT_VAULT_IMAGE), and
  # vault-k8s 1.7.6 copies that string verbatim into the agent containers
  # (agent-inject/agent/container_sidecar.go: Image: a.ImageName), so putting
  # "<version>@sha256:<digest>" in `tag` yields a digest-pinned agent with no
  # chart fork. ../identity's var.vault_agent_image must equal the output
  # vault_agent_image below (its test checks this file for the digest).
  vault_image_digest    = "sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
  injector_image_digest = "sha256:55e27b080c9b0469fd420dfb3631243488c6319504b779423caa46c529a95490"
  vault_image_tag       = "${local.vault_image_version}@${local.vault_image_digest}"
  injector_image_tag    = "${local.injector_image_version}@${local.injector_image_digest}"

  # ---- Names / ports shared with the rest of lab/k8s -------------------------
  vault_namespace    = "vault"
  clinical_namespace = "clinical-apps"
  vault_node_port    = 30820 # containerPort in lab/k8s/kind/cluster.yaml
  vault_host_port    = 18200 # hostPort (127.0.0.1 only) in lab/k8s/kind/cluster.yaml

  # Pod Security Admission policy version. Pinned instead of "latest" so a
  # node-image bump cannot silently change what "restricted" means; bump it
  # together with the kindest/node image (v1.36.x). verify: on a node image
  # bump, re-check the PSA profile changelog for the new minor version.
  psa_version = "v1.36"

  # Namespaces opt in to Vault Agent injection with this label (the webhook's
  # namespaceSelector below). Only cluster-scoped namespace writers (cluster
  # admins, this Terraform) can set it; the human RBAC in ../identity grants
  # nothing on namespaces.
  injection_label_key   = "contoso.health/vault-agent-injection"
  injection_label_value = "enabled"

  common_labels = {
    "app.kubernetes.io/part-of"    = "contoso-health-identity-lab"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  # ---- Helm values (everything except the root token) ------------------------
  # Kept as one HCL object so it is reviewable in one place, yamlencode()d into
  # `values`, and asserted on by tests/platform.tftest.hcl. Keys checked against
  # values.yaml + templates/ of the vault-0.34.1 chart.
  #
  # Security contexts: the chart's defaults already satisfy PSA "baseline"
  # (non-root uid 100, allowPrivilegeEscalation=false, no added capabilities).
  # They are restated here WITH seccompProfile=RuntimeDefault and
  # capabilities.drop=[ALL] so Vault's own pods also meet "restricted"; the
  # namespace enforces baseline (contract) and only warns/audits restricted,
  # so a regression shows up as a warning instead of a broken install.
  # Overriding securityContext.pod REPLACES the chart default object, which is
  # why runAsUser/runAsGroup/fsGroup are restated with the chart's values.
  vault_values = {
    global = {
      enabled    = true
      tlsDisable = true # dev mode serves plain HTTP; production enables TLS
    }

    server = {
      image = {
        repository = local.vault_image_repository
        tag        = local.vault_image_tag
      }

      # Dev mode: in-memory storage, auto-unsealed, root token from
      # server.dev.devRootToken (supplied write-only via set_wo, never here).
      dev = {
        enabled = true
      }
      # dataStorage is only used by standalone/raft modes; off for clarity.
      dataStorage = {
        enabled = false
      }

      # NodePort so Terraform (stage 2), the seed step and the tests reach
      # Vault at 127.0.0.1:18200 through kind's port mapping. Bound to
      # 127.0.0.1 on the host, never to a public interface.
      service = {
        type     = "NodePort"
        nodePort = local.vault_node_port
      }

      # ClusterRoleBinding of Vault's service account to system:auth-delegator.
      # Required: the Kubernetes auth method (../identity) runs without a
      # separate reviewer JWT, so Vault calls the TokenReview API with its OWN
      # pod service-account token. This is the chart default; stated here
      # because stage 2 depends on it.
      authDelegator = {
        enabled = true
      }

      # Requests sized for a 2-4 vCPU CI runner. No CPU limit (throttling a
      # single dev server only makes the run flaky); memory is capped.
      resources = {
        requests = { cpu = "100m", memory = "128Mi" }
        limits   = { memory = "512Mi" }
      }

      statefulSet = {
        securityContext = {
          pod = {
            runAsNonRoot   = true
            runAsUser      = 100
            runAsGroup     = 1000
            fsGroup        = 1000
            seccompProfile = { type = "RuntimeDefault" }
          }
          container = {
            allowPrivilegeEscalation = false
            capabilities             = { drop = ["ALL"] }
            # No readOnlyRootFilesystem: `vault server -dev` writes the token
            # helper file (~/.vault-token) in the container. verify: if a
            # future image moves HOME to an emptyDir, tighten this.
          }
        }
      }
    }

    injector = {
      enabled  = true
      replicas = 1

      image = {
        repository = "hashicorp/vault-k8s"
        tag        = local.injector_image_tag
      }

      # The Vault Agent sidecar/init containers the injector adds to app pods.
      # Same Vault image (and digest) as the server. The tag carries the
      # digest: see vault_image_digest above for why that works and why the
      # clinical-apps admission policy needs it.
      agentImage = {
        repository = local.vault_image_repository
        tag        = local.vault_image_tag
      }

      # Smaller than the chart defaults (250m/64Mi requests) so the app pod
      # schedules comfortably on a CI runner.
      agentDefaults = {
        cpuRequest = "50m"
        cpuLimit   = "500m"
        memRequest = "32Mi"
        memLimit   = "128Mi"
      }

      webhook = {
        # Fail closed (see header). The chart default is Ignore.
        failurePolicy = "Fail"
        namespaceSelector = {
          matchLabels = {
            (local.injection_label_key) = local.injection_label_value
          }
        }
        # objectSelector keeps the chart default (excludes the injector's own
        # pods); Helm deep-merges this map with the chart's webhook defaults.
      }

      resources = {
        requests = { cpu = "50m", memory = "64Mi" }
        limits   = { memory = "256Mi" }
      }

      securityContext = {
        pod = {
          runAsNonRoot   = true
          runAsUser      = 100
          runAsGroup     = 1000
          fsGroup        = 1000
          seccompProfile = { type = "RuntimeDefault" }
        }
        container = {
          allowPrivilegeEscalation = false
          capabilities             = { drop = ["ALL"] }
        }
      }
    }

    ui = {
      enabled = false # API only; the lab drives Vault from Terraform and curl
    }
    csi = {
      enabled = false # the injector is the delivery path (README: injector vs CSI)
    }
  }
}

# -----------------------------------------------------------------------------
# Namespaces + Pod Security Admission
# -----------------------------------------------------------------------------

resource "kubernetes_namespace_v1" "vault" {
  metadata {
    name = local.vault_namespace
    labels = merge(local.common_labels, {
      # Vault's chart needs nothing beyond baseline, so baseline is enforced.
      # warn/audit at restricted record any drift from the hardened contexts
      # above without blocking the install.
      "pod-security.kubernetes.io/enforce"         = "baseline"
      "pod-security.kubernetes.io/enforce-version" = local.psa_version
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/warn-version"    = local.psa_version
      "pod-security.kubernetes.io/audit"           = "restricted"
      "pod-security.kubernetes.io/audit-version"   = local.psa_version
    })
  }
}

resource "kubernetes_namespace_v1" "clinical_apps" {
  metadata {
    name = local.clinical_namespace
    labels = merge(local.common_labels, {
      # Workload namespace: restricted, enforced. The injected Vault Agent
      # containers must pass too (they run non-root, drop ALL, no privilege
      # escalation; seccomp comes from the pod-level RuntimeDefault in
      # lab/k8s/manifests). A privileged pod is rejected at admission - the
      # e2e test proves it with lab/k8s/manifests/negative/privileged-pod.yaml.
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = local.psa_version
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/warn-version"    = local.psa_version
      "pod-security.kubernetes.io/audit"           = "restricted"
      "pod-security.kubernetes.io/audit-version"   = local.psa_version

      # Opt in to Vault Agent injection (webhook namespaceSelector).
      (local.injection_label_key) = local.injection_label_value
    })
  }
}

# -----------------------------------------------------------------------------
# Vault (dev mode) + Agent Injector
# -----------------------------------------------------------------------------

# Every input that defines the release, in one non-secret object. When any of
# it changes - values, chart version, or the root-token revision - this object
# is replaced, and replace_triggered_by below turns that into a full
# reinstall of the release instead of an in-place `helm upgrade`.
#
# WHY reinstall instead of upgrade: the Helm provider only merges set_wo
# values on create, or on an update that bumps set_wo_revision. An ordinary
# upgrade would therefore re-render the chart WITHOUT devRootToken, i.e. with
# the chart's default token "root". Reinstalling always goes through create,
# which always applies set_wo. Losing Vault's data on reinstall costs nothing:
# dev mode is in-memory anyway, and stage 2 + the seed step recreate it.
resource "terraform_data" "vault_release_inputs" {
  triggers_replace = {
    chart_version  = local.vault_chart_version
    values_sha256  = sha256(yamlencode(local.vault_values))
    token_revision = var.vault_dev_root_token_revision
  }
}

resource "helm_release" "vault" {
  name             = "vault"
  namespace        = kubernetes_namespace_v1.vault.metadata[0].name
  create_namespace = false # owned by kubernetes_namespace_v1.vault (PSA labels)

  repository = local.vault_chart_repository
  chart      = "vault"
  version    = local.vault_chart_version
  # verify: the chart is fetched over HTTPS and pinned by version, but not by
  # digest, and Helm provenance (`verify = true`) is not enabled because no
  # HashiCorp chart signing key is wired into the lab. Accepted residual risk
  # for an ephemeral lab cluster.

  values = [yamlencode(local.vault_values)]

  # The root token: write-only (never in plan or state). type = "string" stops
  # Helm from coercing an all-digit token into a number.
  set_wo = [
    {
      name  = "server.dev.devRootToken"
      value = var.vault_dev_root_token
      type  = "string"
    },
  ]
  # Must be >= 1 or the provider silently skips set_wo (and Vault would boot
  # with the chart default token "root").
  set_wo_revision = var.vault_dev_root_token_revision

  # Block until the Vault server and the injector are Ready, so stage 2 and the
  # workload rollout never race a half-started Vault or a missing webhook
  # backend (the webhook fails closed).
  wait    = true
  timeout = 600

  # Not atomic: on a failed install, keep the pods so `kubectl describe` /
  # logs show why. The pipeline's EXIT trap tears the cluster down anyway.
  atomic          = false
  cleanup_on_fail = false
  max_history     = 3

  # The injector's webhook targets clinical-apps by label; create that
  # namespace first so the first pod there is guaranteed to be selected.
  depends_on = [kubernetes_namespace_v1.clinical_apps]

  lifecycle {
    replace_triggered_by = [terraform_data.vault_release_inputs]
  }
}
