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
  description = "The federated subject claims (immutable repo:OWNER@OWNER-ID/REPO@REPO-ID form) - must match the emitted sub exactly. hr_sync is null until enable_hr_sync, evidence until enable_evidence_pack."
  value = {
    plan      = module.pipeline_identity.plan_federated_subject
    plan_main = module.pipeline_identity.plan_main_federated_subject
    apply     = module.pipeline_identity.apply_federated_subject
    hr_sync   = module.pipeline_identity.hr_sync_federated_subject
    evidence  = module.pipeline_identity.evidence_federated_subject
  }
}

output "github_oidc_hr_sync_client_id" {
  description = "HR_SYNC_CLIENT_ID for .github/workflows/hr-feed.yml (null until enable_hr_sync)."
  value       = module.pipeline_identity.hr_sync_application_client_id
}

output "github_oidc_evidence_client_id" {
  description = "EVIDENCE_CLIENT_ID for .github/workflows/evidence-pack.yml (null until enable_evidence_pack)."
  value       = module.pipeline_identity.evidence_application_client_id
}

output "evidence_writer_scope" {
  description = "The evidence container EVIDENCE may add files to (null until enable_evidence_pack)."
  value       = one(azurerm_role_assignment.evidence_writer[*].scope)
}

# azuread cannot add an owner to a service principal it does not manage, and
# the bulkUpload URL is on the provisioning app's SERVICE PRINCIPAL. One admin
# command, built from ids only (no secret), run once after the apply:
#   terraform output -raw hr_sync_service_principal_owner_command   # read it
#   eval "$(terraform output -raw hr_sync_service_principal_owner_command)"
# Re-running it answers "One or more added object references already exist".
output "hr_sync_service_principal_owner_command" {
  description = "az rest call that adds HR-SYNC as an owner of the HR provisioning app's service principal (null unless enable_hr_sync with hr_sync_upload_scope = \"owned\")."
  value = (module.pipeline_identity.hr_provisioning_service_principal_object_id == null || module.pipeline_identity.hr_sync_service_principal_object_id == null ? null : join(" ", [
    "az rest --method POST",
    "--url 'https://graph.microsoft.com/v1.0/servicePrincipals/${module.pipeline_identity.hr_provisioning_service_principal_object_id}/owners/$ref'",
    "--body '{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/${module.pipeline_identity.hr_sync_service_principal_object_id}\"}'",
  ]))
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
  description = "Effective Graph application roles of the PLAN, APPLY, HR-SYNC and EVIDENCE identities (evidence: what the pipeline can do, after any opt-in widening)."
  value = {
    plan     = module.pipeline_identity.plan_graph_roles
    apply    = module.pipeline_identity.apply_graph_roles
    hr_sync  = module.pipeline_identity.hr_sync_graph_roles
    evidence = module.pipeline_identity.evidence_graph_roles
  }
}
