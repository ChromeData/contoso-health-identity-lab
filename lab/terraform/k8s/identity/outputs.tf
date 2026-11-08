# =============================================================================
# k8s/identity :: outputs.tf
# -----------------------------------------------------------------------------
# Identifiers and paths only - never a secret value (Terraform does not know
# the Key Vault value; the pipeline sets it). The e2e test and the README verify
# list use these names.
# =============================================================================

output "secret_provider_class" {
  description = "The SecretProviderClass the Deployment's CSI volume names, and what it serves (identifiers only)."
  value = {
    name         = kubernetes_manifest.secret_provider_class.manifest.metadata.name
    key_vault    = var.key_vault_name
    secret       = var.secret_name
    mounted_file = "/mnt/secrets-store/${local.mounted_file_name}"
    client_id    = var.workload_client_id
  }
}

output "service_accounts" {
  description = "Workload service accounts in clinical-apps (neither auto-mounts an API token)."
  value       = sort([for sa in kubernetes_service_account_v1.workload : sa.metadata[0].name])
}

output "human_rbac" {
  description = "Namespaced Role -> bound group (Kubernetes group names; Entra group object IDs on AKS)."
  value       = { for k, v in local.human_roles : kubernetes_role_v1.human[k].metadata[0].name => v.group }
}
