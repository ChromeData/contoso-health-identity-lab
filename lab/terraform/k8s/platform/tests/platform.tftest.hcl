# Stage 1 (platform) guard rails, checked offline against mocked providers:
# PSA labels per namespace, the CSI driver + Azure provider Helm values the
# rest of the segment depends on (digest-pinned images, rotation on, no
# Secret sync, exactly one token audience), and the guard that keeps a
# non-kind context out.
# Run offline: terraform init -backend=false && terraform test

mock_provider "kubernetes" {}
mock_provider "helm" {}

run "namespaces_carry_the_pod_security_levels" {
  command = plan

  assert {
    condition     = kubernetes_namespace_v1.clinical_apps.metadata[0].labels["pod-security.kubernetes.io/enforce"] == "restricted"
    error_message = "clinical-apps must ENFORCE the restricted Pod Security profile"
  }
  assert {
    condition = alltrue([
      for mode in ["warn", "audit"] :
      kubernetes_namespace_v1.clinical_apps.metadata[0].labels["pod-security.kubernetes.io/${mode}"] == "restricted"
    ])
    error_message = "clinical-apps must also warn and audit at restricted"
  }
  # The driver namespace is the one privileged exception; it must keep
  # warning and auditing at baseline so the exception stays visible.
  assert {
    condition = (
      kubernetes_namespace_v1.secrets_store.metadata[0].labels["pod-security.kubernetes.io/enforce"] == "privileged" &&
      kubernetes_namespace_v1.secrets_store.metadata[0].labels["pod-security.kubernetes.io/warn"] == "baseline" &&
      kubernetes_namespace_v1.secrets_store.metadata[0].labels["pod-security.kubernetes.io/audit"] == "baseline"
    )
    error_message = "secrets-store enforces privileged (CSI node plugin) but must warn + audit at baseline"
  }
}

run "csi_release_is_pinned_and_wired_for_the_lab" {
  command = plan

  assert {
    condition = (
      helm_release.csi_secrets_store_provider_azure.chart == "csi-secrets-store-provider-azure" &&
      helm_release.csi_secrets_store_provider_azure.version == "1.8.2"
    )
    error_message = "the chart must be pinned to csi-secrets-store-provider-azure 1.8.2"
  }
  # Every image pinned by digest: the provider and CRD job through the tag
  # (their templates render repository:tag), the driver containers through
  # the sub-chart's digest field.
  assert {
    condition = alltrue([
      for tag in [
        yamldecode(helm_release.csi_secrets_store_provider_azure.values[0]).linux.image.tag,
        yamldecode(helm_release.csi_secrets_store_provider_azure.values[0])["secrets-store-csi-driver"].linux.crds.image.tag,
      ] : can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+@sha256:[0-9a-f]{64}$", tag))
    ])
    error_message = "provider and CRD job images must be <version>@sha256:<64 hex>"
  }
  assert {
    condition = alltrue([
      for k in ["image", "registrarImage", "livenessProbeImage"] :
      can(regex("^sha256:[0-9a-f]{64}$", yamldecode(helm_release.csi_secrets_store_provider_azure.values[0])["secrets-store-csi-driver"].linux[k].digest))
    ])
    error_message = "driver, registrar and liveness-probe images must carry a sha256 digest"
  }
  assert {
    condition     = yamldecode(helm_release.csi_secrets_store_provider_azure.values[0])["secrets-store-csi-driver"].tokenRequests == [{ audience = "api://AzureADTokenExchange", expirationSeconds = 600 }]
    error_message = "the driver must request tokens for exactly one audience: api://AzureADTokenExchange"
  }
  assert {
    condition     = yamldecode(helm_release.csi_secrets_store_provider_azure.values[0])["secrets-store-csi-driver"].syncSecret.enabled == false
    error_message = "Secret sync must stay off (a Key Vault value must never be copied into a Kubernetes Secret)"
  }
  assert {
    condition = (
      yamldecode(helm_release.csi_secrets_store_provider_azure.values[0])["secrets-store-csi-driver"].enableSecretRotation == true &&
      yamldecode(helm_release.csi_secrets_store_provider_azure.values[0])["secrets-store-csi-driver"].rotationPollInterval == "10s"
    )
    error_message = "rotation must be on, every 10s (pipeline stage 9 waits for it)"
  }
  assert {
    condition     = helm_release.csi_secrets_store_provider_azure.wait == true && helm_release.csi_secrets_store_provider_azure.timeout == 600
    error_message = "the release must wait (up to 600s) for the driver, the provider and the CRDs"
  }
  assert {
    condition     = helm_release.csi_secrets_store_provider_azure.namespace == "secrets-store"
    error_message = "the driver runs in its own namespace, never in clinical-apps"
  }
}

run "non_kind_context_is_rejected" {
  command = plan

  variables {
    kube_context = "aks-contoso-prod"
  }

  expect_failures = [var.kube_context]
}
