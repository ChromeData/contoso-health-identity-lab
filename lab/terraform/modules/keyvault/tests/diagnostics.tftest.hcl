# Key Vault audit logs must always stream to Log Analytics. The variable has
# no default (plan-time error when omitted) and the precondition on
# azurerm_monitor_diagnostic_setting.kv rejects an explicit empty string.
# Run offline: terraform init -backend=false && terraform test

mock_provider "azurerm" {
  mock_resource "azurerm_key_vault" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab" }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/virtualNetworks/vnet-identity-lab" }
  }
  mock_resource "azurerm_subnet" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/virtualNetworks/vnet-identity-lab/subnets/snet-private-endpoints" }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net" }
  }
  mock_data "azurerm_client_config" {
    defaults = { tenant_id = "11111111-1111-1111-1111-111111111111" }
  }
}

variables {
  resource_group_name = "rg-identity-lab"
}

run "empty_workspace_id_is_rejected" {
  command = plan

  variables {
    log_analytics_workspace_id = ""
  }

  expect_failures = [azurerm_monitor_diagnostic_setting.kv]
}

run "workspace_id_given_plans_the_setting" {
  command = plan

  variables {
    log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
  }

  assert {
    condition     = azurerm_monitor_diagnostic_setting.kv.name == "diag-kv-idlab"
    error_message = "Key Vault diagnostic setting not planned."
  }
}

run "wide_ip_range_is_rejected" {
  command = plan

  variables {
    log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
    allowed_ip_ranges          = ["0.0.0.0/0"]
  }

  expect_failures = [var.allowed_ip_ranges]
}
