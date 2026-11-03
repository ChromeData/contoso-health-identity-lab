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

output "plan_main_federated_subject" {
  description = "Subject claim of the PLAN main-branch credential (config-drift on main: schedule / workflow_dispatch)."
  value       = azuread_application_federated_identity_credential.plan_main.subject
}

# HR-SYNC (null when hr_sync_enabled = false).
output "hr_sync_application_client_id" {
  description = "Client (app) id of the HR-SYNC identity - set as the HR_SYNC_CLIENT_ID repo variable for hr-feed.yml. Null when disabled."
  value       = one(azuread_application.hr_sync[*].client_id)
}

output "hr_sync_service_principal_object_id" {
  description = "Object id of the HR-SYNC service principal. Null when disabled."
  value       = one(azuread_service_principal.hr_sync[*].object_id)
}

output "hr_sync_federated_subject" {
  description = "Subject claim the HR-SYNC credential trusts (the hr-feed branch ref). Null when disabled."
  value       = one(azuread_application_federated_identity_credential.hr_sync_branch[*].subject)
}

output "hr_sync_graph_roles" {
  description = "Effective Graph application roles of the HR-SYNC identity (empty when disabled) - for the risk register and the NHI inventory."
  value       = sort(local.hr_sync_roles)
}

output "hr_provisioning_service_principal_object_id" {
  description = "Object id of the HR provisioning app's service principal (the bulkUpload target). Null unless hr_sync_upload_scope = \"owned\"."
  value       = one(data.azuread_service_principal.hr_provisioning[*].object_id)
}

# EVIDENCE (null when evidence_enabled = false).
output "evidence_application_client_id" {
  description = "Client (app) id of the EVIDENCE identity - set as the EVIDENCE_CLIENT_ID repo variable for evidence-pack.yml. Null when disabled."
  value       = one(azuread_application.evidence[*].client_id)
}

output "evidence_service_principal_object_id" {
  description = "Object id of the EVIDENCE service principal (the principal of the evidence-container grant in envs/bootstrap). Null when disabled."
  value       = one(azuread_service_principal.evidence[*].object_id)
}

output "evidence_federated_subject" {
  description = "Subject claim the EVIDENCE credential trusts (the main-branch ref). Null when disabled."
  value       = one(azuread_application_federated_identity_credential.evidence_main[*].subject)
}

output "evidence_graph_roles" {
  description = "Effective Graph application roles of the EVIDENCE identity (empty when disabled) - for the risk register and the NHI inventory."
  value       = sort(local.evidence_roles)
}
