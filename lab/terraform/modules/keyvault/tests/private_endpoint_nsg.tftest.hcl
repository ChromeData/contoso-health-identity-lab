# snet-private-endpoints has its own NSG (Checkov CKV2_AZURE_31), and the NSG
# really applies to the vault's private endpoint: Azure exempts private
# endpoints from NSG rules unless the subnet sets
# private_endpoint_network_policies (default "Disabled"). These runs pin the
# attachment, that setting, the defaults-only rule set and that the vault's
# endpoint sits in that subnet.
# Run offline: terraform init -backend=false && terraform test

# Path-form ids where another resource's argument parses them (the provider
# still validates ids under a mock).
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
  mock_resource "azurerm_network_security_group" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-private-endpoints" }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net" }
  }
  mock_resource "azurerm_user_assigned_identity" {
    defaults = { principal_id = "44444444-4444-4444-4444-444444444444" }
  }
  mock_data "azurerm_client_config" {
    defaults = { tenant_id = "11111111-1111-1111-1111-111111111111" }
  }
}

variables {
  resource_group_name        = "rg-identity-lab"
  log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
}

# A MOCKED apply (nothing leaves this machine): the association's ids and the
# NSG's empty rule set are only known after apply.
run "private_endpoint_subnet_has_an_nsg_that_applies" {
  command = apply

  assert {
    condition     = azurerm_subnet_network_security_group_association.private_endpoints.subnet_id == azurerm_subnet.private_endpoints.id && azurerm_subnet_network_security_group_association.private_endpoints.network_security_group_id == azurerm_network_security_group.private_endpoints.id
    error_message = "the NSG must be attached to snet-private-endpoints (Checkov CKV2_AZURE_31)"
  }
  assert {
    condition     = azurerm_subnet.private_endpoints.private_endpoint_network_policies == "NetworkSecurityGroupEnabled"
    error_message = "private_endpoint_network_policies must be NetworkSecurityGroupEnabled, or Azure exempts the private endpoint from the NSG"
  }
  assert {
    condition     = length(azurerm_network_security_group.private_endpoints.security_rule) == 0
    error_message = "no custom rules: the NSG defaults allow VNet traffic and deny inbound from the internet; review any new rule here"
  }
  assert {
    condition     = azurerm_private_endpoint.kv.subnet_id == azurerm_subnet.private_endpoints.id
    error_message = "the vault's private endpoint must sit in the NSG-protected subnet"
  }
}
