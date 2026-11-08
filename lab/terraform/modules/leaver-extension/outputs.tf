output "logic_app_name" {
  description = "Logic App name, for New-LifecycleWorkflows.ps1 -LeaverExtensionLogicAppName."
  value       = var.name
}

output "principal_id" {
  description = "Object id of the Logic App's system-assigned managed identity."
  value       = local.principal_id
}

output "catalog_role_assignment_ids" {
  description = "Catalog name => role assignment id (Access package assignment manager)."
  value       = { for k, v in azuread_access_package_catalog_role_assignment.assignment_manager : k => v.id }
}
