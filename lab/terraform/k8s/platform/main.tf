# =============================================================================
# k8s/platform :: main.tf
# -----------------------------------------------------------------------------
# WHAT (stage 1 of 2 - stage 2 is ../identity):
#   * namespace "secrets-store"  the Secrets Store CSI Driver + the Azure Key
#                                Vault provider (node plugins: PSA privileged,
#                                see below)
#   * namespace "clinical-apps"  PSA enforce/warn/audit=restricted
#   * helm_release "csi_secrets_store_provider_azure"
#                                chart csi-secrets-store-provider-azure 1.8.2
#                                (Microsoft), which also installs its pinned
#                                dependency secrets-store-csi-driver 1.5.6
#                                (Kubernetes SIG Auth). Every image pinned by
#                                digest.
#
# HOW A POD GETS ITS SECRET (Microsoft Learn, "Access Azure Key Vault with
# the CSI Driver Identity Provider", Workload ID tab): when the kubelet mounts
# the pod's CSI volume, the driver requests a service-account token for the
# POD's service account, audience api://AzureADTokenExchange (CSIDriver
# spec.tokenRequests, set below). The Azure provider sends that token to
# Microsoft Entra ID, which checks it against the federated credential in
# ../keyvault-trust and returns an access token for Key Vault. The provider
# reads the one secret and the driver writes it to a tmpfs file in the pod.
# The app reads a file. It holds no token and no client library.
#
# This replaces the earlier HashiCorp Vault (dev mode) + Agent Injector
# stand-in. ADR 0027 ("Microsoft-native PAM"): where Microsoft offers the
# product, the lab uses it. kind still stands in for AKS (STAND-INS.md).
#
# WHY THE DRIVER NAMESPACE IS PRIVILEGED (said out loud): the CSI node plugin
# mounts into the kubelet's pod directories (hostPath /var/lib/kubelet with
# Bidirectional mount propagation) and runs privileged. That is the job of
# every CSI node plugin; Pod Security "baseline" forbids it. So the namespace
# ENFORCES privileged and only WARNS/AUDITS at baseline, which records the
# exception on every change. Nothing else runs there. clinical-apps stays
# restricted: the app pod itself needs no privilege for a CSI volume.
#
# WHAT THE DRIVER CAN DO (also said out loud): its ClusterRole may create
# service-account tokens (serviceaccounts/token) so rotation can fetch a new
# Key Vault value without the kubelet. Tokens it mints carry only the
# api://AzureADTokenExchange audience (this file), which the Kubernetes API
# refuses, so they open nothing in the cluster. Entra accepts one only for a
# service account that has a federated credential.
# =============================================================================

locals {
  # ---- Pinned versions (bump deliberately, one PR each) ---------------------
  # Chart index https://azure.github.io/secrets-store-csi-driver-provider-azure/charts
  # read 2026-11-06: 1.8.2 created 2026-06-11 (older than two weeks), digest
  # sha256:6ec47f4dfb81a49a5cc426ca965a97519551a020dbe3dafe49962a2f565cfbcb,
  # appVersion 1.8.2, dependency secrets-store-csi-driver 1.5.6.
  chart_repository = "https://azure.github.io/secrets-store-csi-driver-provider-azure/charts"
  chart_name       = "csi-secrets-store-provider-azure"
  chart_version    = "1.8.2"

  # Image DIGESTS: the multi-arch index of each tag (linux/amd64 for CI,
  # linux/arm64 for Apple Silicon), read from mcr.microsoft.com on 2026-11-06
  # (HEAD /v2/<repo>/manifests/<tag>, Docker-Content-Digest). The kubelet
  # pulls by digest, so a re-pushed tag cannot change what runs.
  # The driver sub-chart has a `digest` field (renders repository@digest);
  # the provider chart renders "<repository>:<tag>", so its digest rides in
  # the tag, the same trick the Vault chart needed.
  mcr = "mcr.microsoft.com/oss/v2"
  images = {
    provider = {
      repository = "${local.mcr}/azure/secrets-store/provider-azure"
      tag        = "v1.8.2"
      digest     = "sha256:6be3919093995af5754e4cd0e2dad5f8659baa594b27e9d6f5c2866f893ee26a"
    }
    driver = {
      repository = "${local.mcr}/kubernetes-csi/secrets-store/driver"
      tag        = "v1.5.6"
      digest     = "sha256:5f91243cfd60dcf82b744a87279eda9b9ae0a7ca18828472ba91b366af415430"
    }
    registrar = {
      repository = "${local.mcr}/kubernetes-csi/csi-node-driver-registrar"
      tag        = "v2.14.0"
      digest     = "sha256:6cb172e3de7e9ec36dfca179dbfd6be8c9bf7a14374afe780c2dd11ea7512ab1"
    }
    liveness = {
      repository = "${local.mcr}/kubernetes-csi/livenessprobe"
      tag        = "v2.15.0"
      digest     = "sha256:59b9d034842849bdae41ca5be7c52b5e9ab2a4d18485dfdf16521f3ec74c047a"
    }
    crds = {
      repository = "${local.mcr}/kubernetes-csi/secrets-store/driver-crds"
      tag        = "v1.5.6"
      digest     = "sha256:cb0112636dc4d22c38fa4ef8d46c6eb1d6e4c8b4d2228a233474769a0cd2048c"
    }
  }

  # ---- Names shared with the rest of lab/k8s -------------------------------
  csi_namespace      = "secrets-store"
  clinical_namespace = "clinical-apps"

  # The ONE audience the driver may request tokens for. The chart default
  # also lists api://AKSIdentityBinding (an AKS-only feature); dropped, so
  # the driver mints nothing the lab does not use.
  token_exchange_audience = "api://AzureADTokenExchange"

  # Rotation: the driver re-reads every mounted object on this interval and
  # rewrites the file in place (same pod, no restart; pipeline stage 9).
  # 10s keeps stage 9 short; the price is one Key Vault read per pod every
  # 10 s (Key Vault Standard: $0.03 per 10,000 operations). Production:
  # minutes, sized to how fast a rotated credential must be live.
  rotation_poll_interval = "10s"

  psa_version = "v1.36" # bump together with the kindest/node image

  common_labels = {
    "app.kubernetes.io/part-of"    = "contoso-health-identity-lab"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  # ---- Helm values -----------------------------------------------------------
  # One HCL object, yamlencode()d into `values`, asserted on by
  # tests/platform.tftest.hcl. Keys checked against values.yaml and
  # templates/ of csi-secrets-store-provider-azure-1.8.2.tgz (and its bundled
  # charts/secrets-store-csi-driver).
  csi_values = {
    linux = {
      image = {
        repository = local.images.provider.repository
        tag        = "${local.images.provider.tag}@${local.images.provider.digest}"
      }
    }
    windows = { enabled = false }

    "secrets-store-csi-driver" = {
      install = true
      linux = {
        image = {
          repository = local.images.driver.repository
          tag        = local.images.driver.tag
          digest     = local.images.driver.digest
        }
        registrarImage = {
          repository = local.images.registrar.repository
          tag        = local.images.registrar.tag
          digest     = local.images.registrar.digest
        }
        livenessProbeImage = {
          repository = local.images.liveness.repository
          tag        = local.images.liveness.tag
          digest     = local.images.liveness.digest
        }
        crds = {
          image = {
            repository = local.images.crds.repository
            tag        = "${local.images.crds.tag}@${local.images.crds.digest}"
          }
        }
      }
      windows = { enabled = false }

      enableSecretRotation = true
      rotationPollInterval = local.rotation_poll_interval

      # Never copy a Key Vault value into a Kubernetes Secret (it would sit in
      # etcd, base64 only). No SecretProviderClass here declares
      # secretObjects either; the e2e test checks the namespace holds none.
      syncSecret = { enabled = false }

      tokenRequests = [{ audience = local.token_exchange_audience }]
    }
  }
}

# -----------------------------------------------------------------------------
# Namespaces + Pod Security Admission
# -----------------------------------------------------------------------------

resource "kubernetes_namespace_v1" "secrets_store" {
  metadata {
    name = local.csi_namespace
    labels = merge(local.common_labels, {
      # CSI node plugins need privileged hostPath mounts (header). Enforce
      # privileged; warn + audit at baseline so the exception stays visible.
      "pod-security.kubernetes.io/enforce"         = "privileged"
      "pod-security.kubernetes.io/enforce-version" = local.psa_version
      "pod-security.kubernetes.io/warn"            = "baseline"
      "pod-security.kubernetes.io/warn-version"    = local.psa_version
      "pod-security.kubernetes.io/audit"           = "baseline"
      "pod-security.kubernetes.io/audit-version"   = local.psa_version
    })
  }
}

resource "kubernetes_namespace_v1" "clinical_apps" {
  metadata {
    name = local.clinical_namespace
    labels = merge(local.common_labels, {
      # Workload namespace: restricted, enforced. A privileged pod is
      # rejected at admission - the e2e test proves it with
      # lab/k8s/manifests/negative/privileged-pod.yaml.
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = local.psa_version
      "pod-security.kubernetes.io/warn"            = "restricted"
      "pod-security.kubernetes.io/warn-version"    = local.psa_version
      "pod-security.kubernetes.io/audit"           = "restricted"
      "pod-security.kubernetes.io/audit-version"   = local.psa_version
    })
  }
}

# -----------------------------------------------------------------------------
# Secrets Store CSI Driver + Azure Key Vault provider
# -----------------------------------------------------------------------------

resource "helm_release" "csi_secrets_store_provider_azure" {
  name             = "csi-azure"
  namespace        = kubernetes_namespace_v1.secrets_store.metadata[0].name
  create_namespace = false # owned above (PSA labels)

  repository = local.chart_repository
  chart      = local.chart_name
  version    = local.chart_version
  # verify: the chart is fetched over HTTPS and pinned by version; its
  # digest is recorded above but Helm provenance (`verify = true`) is not
  # enabled (no chart signing key is wired in). Accepted residual risk for
  # an ephemeral lab cluster.

  values = [yamlencode(local.csi_values)]

  # Block until the driver and provider DaemonSets are Ready and the
  # SecretProviderClass CRD exists, so ../identity can create one.
  wait    = true
  timeout = 600

  atomic          = false # keep failed pods for `kubectl describe`
  cleanup_on_fail = false
  max_history     = 3
}
