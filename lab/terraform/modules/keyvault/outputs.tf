# =============================================================================
# modules/keyvault :: outputs.tf
# =============================================================================

output "key_vault_id" {
  description = "Resource id of the Key Vault."
  value       = azurerm_key_vault.idlab.id
}

output "key_vault_uri" {
  description = "Data-plane URI (resolves privately via the private endpoint)."
  value       = azurerm_key_vault.idlab.vault_uri
}

output "uami_id" {
  description = "Resource id of the user-assigned managed identity."
  value       = azurerm_user_assigned_identity.kv_reader.id
}

output "uami_principal_id" {
  description = "Principal (object) id of the UAMI - Key Vault Secrets User, ABAC-limited to uami_readable_secret_names."
  value       = azurerm_user_assigned_identity.kv_reader.principal_id
}

output "uami_client_id" {
  description = "Client id of the UAMI (for workload federation / app config)."
  value       = azurerm_user_assigned_identity.kv_reader.client_id
}

output "private_endpoint_ip" {
  description = "Private IP assigned to the Key Vault private endpoint NIC."
  value       = azurerm_private_endpoint.kv.private_service_connection[0].private_ip_address
}

output "key_vault_name" {
  description = "Name of the Key Vault (scripts address secrets by vault name)."
  value       = azurerm_key_vault.idlab.name
}

output "vnet_name" {
  description = "Lab VNet name - other modules add their subnets here (e.g. the DC)."
  value       = azurerm_virtual_network.lab.name
}

output "vnet_id" {
  description = "Lab VNet id (linked to the vault's private DNS zone)."
  value       = azurerm_virtual_network.lab.id
}
