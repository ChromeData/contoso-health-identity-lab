# =============================================================================
# modules/intune-vm :: outputs.tf
# =============================================================================

output "vm_id" {
  description = "Resource id of the Windows 11 VM."
  value       = azurerm_windows_virtual_machine.vm.id
}

output "vm_name" {
  description = "Azure name of the VM (az vm start / deallocate / run-command)."
  value       = azurerm_windows_virtual_machine.vm.name
}

output "computer_name" {
  description = "Windows hostname = Entra device name (search for it in Entra Devices and Intune)."
  value       = azurerm_windows_virtual_machine.vm.computer_name
}

output "private_ip" {
  description = "Private IP in snet-endpoints."
  value       = azurerm_network_interface.vm.private_ip_address
}

output "public_ip" {
  description = "Static public IP (RDP from the operator's allowed IPs only). Map it to computer_name in /etc/hosts for Entra RDP."
  value       = azurerm_public_ip.vm.ip_address
}

output "admin_username" {
  description = "Local break-glass admin user name (day-to-day sign-in is Entra)."
  value       = var.admin_username
}

output "admin_password" {
  description = "Local break-glass admin password (state only). Use only if Entra sign-in fails."
  value       = random_password.admin.result
  sensitive   = true
}

output "identity_principal_id" {
  description = "Object id of the VM's system-assigned identity (used by AADLoginForWindows for the Entra join)."
  value       = azurerm_windows_virtual_machine.vm.identity[0].principal_id
}

output "intune_enrollment_enabled" {
  description = "Whether the Entra-login extension was given the Intune mdmId (auto-enrollment)."
  value       = var.enable_intune_enrollment
}

output "rdp_file_content" {
  description = <<-EOT
    Minimal .rdp for Entra sign-in (enablerdsaadauth). full address is the
    HOSTNAME on purpose - Entra RDP rejects IP addresses - so map the public
    IP to it in /etc/hosts first. Save with:
    terraform output -raw intune_vm_rdp_file > ch-win11-01.rdp
  EOT
  value       = <<-EOT
    full address:s:${azurerm_windows_virtual_machine.vm.computer_name}
    enablerdsaadauth:i:1
    screen mode id:i:1
  EOT
}
