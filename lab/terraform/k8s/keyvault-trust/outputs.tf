# =============================================================================
# k8s/keyvault-trust :: outputs.tf
# -----------------------------------------------------------------------------
# Both halves of the trust, so a reviewer sees what Entra trusts AND what the
# cluster must carry for a pod to use it. Identifiers only.
# =============================================================================

output "client_id" {
  description = "Client (application) id the SecretProviderClass and the service-account annotation name (../identity, TF_VAR_workload_client_id)."
  value       = azuread_application.nightly_report.client_id
}

output "service_principal_object_id" {
  description = "Object id of the workload's service principal (the Key Vault role assignee)."
  value       = azuread_service_principal.nightly_report.object_id
}

output "entra_trust" {
  description = "What Entra will accept: a token from this issuer, for this subject, with this audience."
  value = {
    issuer    = azuread_application_federated_identity_credential.nightly_report.issuer
    subject   = azuread_application_federated_identity_credential.nightly_report.subject
    audiences = azuread_application_federated_identity_credential.nightly_report.audiences
  }
}

output "key_vault_grant" {
  description = "The one Azure RBAC grant the workload holds."
  value = {
    role  = "Key Vault Secrets User"
    scope = azurerm_role_assignment.secret_reader.scope
  }
}
