# =============================================================================
# modules/evidence-store :: outputs.tf
# =============================================================================

output "storage_account_id" {
  description = "Resource id of the evidence storage account."
  value       = azurerm_storage_account.evidence.id
}

output "storage_account_name" {
  description = "Evidence storage account name (Invoke-BaselineAssessment.ps1 -StorageAccountName)."
  value       = azurerm_storage_account.evidence.name
}

output "primary_blob_endpoint" {
  description = "Blob endpoint (Entra auth only; shared key is disabled)."
  value       = azurerm_storage_account.evidence.primary_blob_endpoint
}

output "evidence_container_name" {
  description = "Container that holds evidence packs and assessment runs (-ContainerName)."
  value       = azurerm_storage_container.evidence.name
}

output "evidence_container_id" {
  description = "Resource Manager id of the evidence container: the --scope for the human writer role assignment."
  value       = azurerm_storage_container.evidence.id
}

output "immutability" {
  description = "The account-level WORM policy as configured (state, retention days, append writes)."
  value = {
    state                         = var.immutability_state
    period_since_creation_in_days = var.immutability_period_days
    allow_protected_append_writes = var.allow_protected_append_writes
  }
}

output "writer_abac_condition" {
  description = "ABAC condition for evidence writers (no delete in the evidence container). Pass it verbatim to az role assignment create --condition."
  value       = local.writer_abac_condition
}
