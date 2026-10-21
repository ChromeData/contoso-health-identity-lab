# =============================================================================
# modules/pipeline-identity :: outputs.tf
# -----------------------------------------------------------------------------
# These client ids + tenant id are the three values GitHub Actions needs for
# azure/login with OIDC (client-id, tenant-id, subscription-id).
# =============================================================================

output "plan_application_client_id" {
  description = "Client (app) id of the read-only PLAN identity - set as AZURE_CLIENT_ID for PR workflows."
  value       = azuread_application.plan.client_id
}

output "plan_service_principal_object_id" {
  description = "Object id of the PLAN service principal."
  value       = azuread_service_principal.plan.object_id
}

output "apply_application_client_id" {
  description = "Client (app) id of the write APPLY identity - set as AZURE_CLIENT_ID for prod workflows."
  value       = azuread_application.apply.client_id
}

output "apply_service_principal_object_id" {
  description = "Object id of the APPLY service principal."
  value       = azuread_service_principal.apply.object_id
}

output "plan_federated_subject" {
  description = "Subject claim the PLAN credential trusts."
  value       = azuread_application_federated_identity_credential.plan_pr.subject
}

output "apply_federated_subject" {
  description = "Subject claim the APPLY credential trusts."
  value       = azuread_application_federated_identity_credential.apply_prod.subject
}

output "plan_graph_roles" {
  description = "Effective Graph application roles of the PLAN identity (baseline + opt-in extras) - for the risk register and the NHI inventory."
  value       = sort(local.plan_roles)
}

output "apply_graph_roles" {
  description = "Effective Graph application roles of the APPLY identity (baseline + opt-in extras). Every entry beyond the baseline widens a Tier-0 identity."
  value       = sort(local.apply_roles)
}
