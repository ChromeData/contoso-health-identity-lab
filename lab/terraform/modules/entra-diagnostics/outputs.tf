# =============================================================================
# modules/entra-diagnostics :: outputs.tf
# =============================================================================

output "diagnostic_setting_id" {
  description = "Id of the tenant-level Entra diagnostic setting."
  value       = azurerm_monitor_aad_diagnostic_setting.entra.id
}

output "categories" {
  description = "Entra log categories the diagnostic setting exports (baseline + opt-in risk categories + extra_categories), sorted."
  value       = local.effective_categories
}

output "identity_protection_logs_enabled" {
  description = "True when all four ID Protection risk categories are exported (via enable_identity_protection_logs or extra_categories)."
  value       = alltrue([for c in local.identity_protection_categories : contains(local.effective_categories, c)])
}
