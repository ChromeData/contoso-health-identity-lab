# =============================================================================
# envs/bootstrap :: outputs.tf
# -----------------------------------------------------------------------------
# Copy these into GitHub -> Settings -> Secrets and variables -> Actions ->
# VARIABLES (they are identifiers, not secrets).
# =============================================================================

output "github_oidc_plan_client_id" {
  description = "AZURE_PLAN_CLIENT_ID for pull_request (plan / AI review) workflows."
  value       = module.pipeline_identity.plan_application_client_id
}

output "github_oidc_apply_client_id" {
  description = "AZURE_APPLY_CLIENT_ID for the prod (apply) workflow."
  value       = module.pipeline_identity.apply_application_client_id
}

# The APPLY identity by IMMUTABLE id, for the ITDR detections
# (envs/dev iac_principal_ids -> TF_IAC_PRINCIPAL_IDS repo variable, and the
# Splunk lookup contoso_iac_principals.csv). They decide "this change came from
# the reviewed pipeline" by these ids, never by the display name, which any app
# owner could copy.
output "iac_principal_ids" {
  description = "APPLY service principal object id + application (client) id - the only identities the ITDR rules treat as IaC."
  value = [
    module.pipeline_identity.apply_service_principal_object_id,
    module.pipeline_identity.apply_application_client_id,
  ]
}

output "github_oidc_subjects" {
  description = "The two federated subject claims (immutable repo:OWNER@OWNER-ID/REPO@REPO-ID form) - must match the emitted sub exactly."
  value = {
    plan  = module.pipeline_identity.plan_federated_subject
    apply = module.pipeline_identity.apply_federated_subject
  }
}

output "subscription_id" {
  description = "AZURE_SUBSCRIPTION_ID."
  value       = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  description = "AZURE_TENANT_ID."
  value       = data.azurerm_subscription.current.tenant_id
}

output "entra_diagnostic_setting_id" {
  description = "Tenant-level Entra diagnostic setting (null until log_analytics_workspace_id is set)."
  value       = one(module.entra_diagnostics[*].diagnostic_setting_id)
}

output "pipeline_graph_roles" {
  description = "Effective Graph application roles of the PLAN and APPLY identities (evidence: what the pipeline can do, after any opt-in widening)."
  value = {
    plan  = module.pipeline_identity.plan_graph_roles
    apply = module.pipeline_identity.apply_graph_roles
  }
}
