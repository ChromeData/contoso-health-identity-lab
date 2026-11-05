# =============================================================================
# envs/operator :: outputs.tf
# -----------------------------------------------------------------------------
# Nothing secret: ids only. lab/scripts/operator/lab-signin.sh reads these
# (`tofu output -json`) into ~/.contoso-operator/config, and
# lab/terraform/aws takes operator_client_id + operator_object_id.
# =============================================================================

output "tenant_id" {
  value = var.tenant_id
}

output "subscription_id" {
  value = var.subscription_id
}

output "operator_client_id" {
  description = "Client id. Also the audience AWS checks (aws: operator_client_id)."
  value       = azuread_application.operator.client_id
}

output "operator_object_id" {
  description = "Service principal object id = the token subject AWS checks (aws: operator_object_id)."
  value       = azuread_service_principal.operator.object_id
}

output "operator_token_scope" {
  description = "Scope the operator asks Entra for when it signs in to AWS."
  value       = "${azuread_application_identifier_uri.operator.identifier_uri}/.default"
}

output "operator_certificate_key_id" {
  description = "Entra key id of the uploaded certificate."
  value       = azuread_application_certificate.operator.key_id
}
