# =============================================================================
# k8s/aks-mapping :: outputs.tf
# -----------------------------------------------------------------------------
# Both halves of the trust, so a reviewer sees what Entra trusts AND what the
# cluster must carry for a pod to use it. Identifiers only.
# =============================================================================

output "entra_trust" {
  description = "What Entra will accept: a token from this issuer, for this subject, with this audience."
  value = {
    issuer    = azuread_application_federated_identity_credential.nightly_report.issuer
    subject   = azuread_application_federated_identity_credential.nightly_report.subject
    audiences = azuread_application_federated_identity_credential.nightly_report.audiences
  }
}

output "kubernetes_side" {
  description = "What the AKS workload needs to use the trust (Entra Workload ID webhook conventions)."
  value = {
    namespace       = local.namespace
    service_account = local.service_account
    # On the ServiceAccount (Terraform: ../identity's kubernetes_service_account_v1 on AKS).
    service_account_annotations = {
      "azure.workload.identity/client-id" = var.application_client_id
    }
    # On the pod template: opts the pod in to the workload identity webhook,
    # which projects a token with the Entra audience and sets AZURE_CLIENT_ID,
    # AZURE_TENANT_ID, AZURE_FEDERATED_TOKEN_FILE, AZURE_AUTHORITY_HOST.
    pod_labels = {
      "azure.workload.identity/use" = "true"
    }
    projected_token_audience = local.entra_token_exchange_audience
  }
}
