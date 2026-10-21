# =============================================================================
# k8s/identity :: outputs.tf
# -----------------------------------------------------------------------------
# Identifiers and paths only - never a secret value (Terraform does not know
# the KV value; the pipeline seeds it). The e2e test and the README verify
# list use these names.
# =============================================================================

output "kv_mount_path" {
  description = "KV v2 mount for clinical app secrets."
  value       = vault_mount.clinical.path
}

output "secret_api_path" {
  description = "Vault API path of the workload secret (the path, not the value): what the agent template reads and the pipeline seeds."
  value       = "${vault_mount.clinical.path}/data/${local.app_secret_name}"
}

output "vault_auth_path" {
  description = "Mount path of the Kubernetes auth method (login at auth/<this>/login; matches the injector's authPath)."
  value       = "auth/${vault_auth_backend.kubernetes.path}"
}

output "vault_role" {
  description = "The one Vault role that trusts a Kubernetes identity, and what it is bound to."
  value = {
    name                    = vault_kubernetes_auth_backend_role.nightly_report.role_name
    bound_service_accounts  = vault_kubernetes_auth_backend_role.nightly_report.bound_service_account_names
    bound_namespaces        = vault_kubernetes_auth_backend_role.nightly_report.bound_service_account_namespaces
    audience                = vault_kubernetes_auth_backend_role.nightly_report.audience
    token_policies          = vault_kubernetes_auth_backend_role.nightly_report.token_policies
    token_ttl_seconds       = vault_kubernetes_auth_backend_role.nightly_report.token_ttl
    token_max_ttl_seconds   = vault_kubernetes_auth_backend_role.nightly_report.token_max_ttl
    identity_alias_keyed_by = vault_kubernetes_auth_backend_role.nightly_report.alias_name_source
  }
}

output "vault_policy_name" {
  description = "Policy attached to tokens issued by the nightly-report role."
  value       = vault_policy.nightly_report_read.name
}

output "service_accounts" {
  description = "Workload service accounts in clinical-apps (neither auto-mounts an API token)."
  value       = sort([for sa in kubernetes_service_account_v1.workload : sa.metadata[0].name])
}

output "human_rbac" {
  description = "Namespaced Role -> bound group (Kubernetes group names; Entra group object IDs on AKS)."
  value       = { for k, v in local.human_roles : kubernetes_role_v1.human[k].metadata[0].name => v.group }
}
