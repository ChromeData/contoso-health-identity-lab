# =============================================================================
# k8s/platform :: outputs.tf
# -----------------------------------------------------------------------------
# Identifiers only. vault_addr is what ../identity (TF_VAR_vault_addr), the
# seed step and the e2e test use; it is a plain-HTTP loopback address because
# the dev-mode server has no TLS and kind publishes it on 127.0.0.1 only.
# =============================================================================

output "vault_addr" {
  description = "Vault API address from the host (kind hostPort 18200 -> NodePort 30820). Feed it to ../identity as TF_VAR_vault_addr."
  value       = "http://127.0.0.1:${local.vault_host_port}"
}

output "vault_namespace" {
  description = "Namespace of the Vault server and the Agent Injector."
  value       = kubernetes_namespace_v1.vault.metadata[0].name
}

output "clinical_namespace" {
  description = "Workload namespace (PSA restricted, opted in to Vault Agent injection)."
  value       = kubernetes_namespace_v1.clinical_apps.metadata[0].name
}

output "vault_release" {
  description = "Helm release name, chart version and the (digest-pinned) Vault image it runs."
  value = {
    name          = helm_release.vault.name
    chart_version = local.vault_chart_version
    vault_image   = "${local.vault_image_repository}:${local.vault_image_tag}"
  }
}

# The exact string the injector writes into every Vault Agent container it
# adds to a clinical-apps pod. ../identity's admission policy allow-lists it
# for the nightly-report service account (var.vault_agent_image there); the
# pipeline may pass it across as TF_VAR_vault_agent_image so the two roots can
# never disagree. Not a secret: an image reference.
output "vault_agent_image" {
  description = "Digest-pinned Vault Agent image the injector adds to app pods (feed to ../identity as TF_VAR_vault_agent_image)."
  value       = "${local.vault_image_repository}:${local.vault_image_tag}"
}

output "pod_security" {
  description = "Pod Security Admission enforce level per namespace."
  value = {
    (local.vault_namespace)    = kubernetes_namespace_v1.vault.metadata[0].labels["pod-security.kubernetes.io/enforce"]
    (local.clinical_namespace) = kubernetes_namespace_v1.clinical_apps.metadata[0].labels["pod-security.kubernetes.io/enforce"]
  }
}
