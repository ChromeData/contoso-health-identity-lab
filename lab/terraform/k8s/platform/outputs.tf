# =============================================================================
# k8s/platform :: outputs.tf
# -----------------------------------------------------------------------------
# Identifiers only. No secret passes through this root.
# =============================================================================

output "csi_namespace" {
  description = "Namespace of the Secrets Store CSI Driver and the Azure Key Vault provider."
  value       = kubernetes_namespace_v1.secrets_store.metadata[0].name
}

output "clinical_namespace" {
  description = "Workload namespace (PSA restricted)."
  value       = kubernetes_namespace_v1.clinical_apps.metadata[0].name
}

output "csi_release" {
  description = "Helm release name, chart version and the digest-pinned provider and driver images."
  value = {
    name           = helm_release.csi_secrets_store_provider_azure.name
    chart_version  = local.chart_version
    provider_image = "${local.images.provider.repository}:${local.images.provider.tag}@${local.images.provider.digest}"
    driver_image   = "${local.images.driver.repository}@${local.images.driver.digest}"
  }
}

output "token_exchange_audience" {
  description = "The only audience the CSI driver requests service-account tokens for (the Entra token-exchange audience)."
  value       = local.token_exchange_audience
}

output "pod_security" {
  description = "Pod Security Admission enforce level per namespace."
  value = {
    (local.csi_namespace)      = kubernetes_namespace_v1.secrets_store.metadata[0].labels["pod-security.kubernetes.io/enforce"]
    (local.clinical_namespace) = kubernetes_namespace_v1.clinical_apps.metadata[0].labels["pod-security.kubernetes.io/enforce"]
  }
}
