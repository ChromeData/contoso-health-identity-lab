# =============================================================================
# modules/dc-vm :: outputs.tf
# =============================================================================

output "vm_id" {
  description = "Resource id of the DC VM."
  value       = azurerm_windows_virtual_machine.dc.id
}

output "vm_name" {
  description = "Azure name of the DC VM (for az vm run-command / start / deallocate)."
  value       = azurerm_windows_virtual_machine.dc.name
}

output "private_ip" {
  description = "Static private IP of the DC (LDAPS target for Vault, DNS for future member servers)."
  value       = azurerm_network_interface.dc.private_ip_address
}

output "public_ip" {
  description = "Static public IP (RDP / LDAPS from the operator's allowed IPs only)."
  value       = azurerm_public_ip.dc.ip_address
}

output "admin_username" {
  description = "Initial local admin user name."
  value       = var.admin_username
}

output "admin_password" {
  description = "Initial local admin password (state only). Rotate after first sign-in and keep the new one in Key Vault."
  value       = random_password.admin.result
  sensitive   = true
}

output "identity_principal_id" {
  description = "Object id of the DC's system-assigned identity (Key Vault Secrets Officer, ABAC-limited to its three build secrets)."
  value       = azurerm_windows_virtual_machine.dc.identity[0].principal_id
}
