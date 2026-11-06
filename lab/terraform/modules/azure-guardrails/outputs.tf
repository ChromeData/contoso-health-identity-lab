# =============================================================================
# modules/azure-guardrails :: outputs.tf
# =============================================================================

output "standing_owner_assignment_id" {
  description = "Policy assignment id of the no-new-standing-Owner guardrail (az policy state list --policy-assignment <name>)."
  value       = azurerm_subscription_policy_assignment.no_standing_owner.id
}

output "keyvault_protection_assignment_id" {
  description = "Policy assignment id of the Key Vault deletion-protection guardrail."
  value       = azurerm_subscription_policy_assignment.keyvault_protection.id
}

output "effects" {
  description = "The effect each guardrail runs with (Audit until someone deliberately switches it)."
  value = {
    standing_owner      = var.standing_owner_effect
    keyvault_protection = var.keyvault_protection_effect
  }
}
