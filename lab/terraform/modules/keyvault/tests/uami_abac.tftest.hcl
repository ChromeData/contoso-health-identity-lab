# The workload identity (UAMI) must only ever read its own secret name(s).
# The vault also holds Tier-0 material (svc-vault-rotator, dc01-dsrm-password)
# and playbook secrets, so its Secrets User assignment carries an ABAC
# condition. These runs pin that: the condition exists, names exactly the
# configured secrets, and an empty allow-list is rejected.
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

run "uami_read_is_abac_limited_to_its_secret" {
  command = plan

  assert {
    condition     = azurerm_role_assignment.kv_secrets_user.condition_version == "2.0"
    error_message = "the UAMI's Secrets User assignment must carry an ABAC condition"
  }
  assert {
    condition     = strcontains(azurerm_role_assignment.kv_secrets_user.condition, "StringEquals 'demo-app-config'")
    error_message = "the condition must name the default demo secret"
  }
  assert {
    condition     = !strcontains(azurerm_role_assignment.kv_secrets_user.condition, "svc-vault-rotator")
    error_message = "the Tier-0 reconcile secret must never be readable by the UAMI"
  }
}

run "custom_secret_names_flow_into_the_condition" {
  command = plan

  variables {
    uami_readable_secret_names = ["app-a-config", "app-b-config"]
  }

  assert {
    condition     = strcontains(azurerm_role_assignment.kv_secrets_user.condition, "'app-a-config' OR @Resource[Microsoft.KeyVault/vaults/secrets:name] StringEquals 'app-b-config'")
    error_message = "every allowed name must appear, OR-joined"
  }
}

run "empty_allow_list_is_rejected" {
  command = plan

  variables {
    uami_readable_secret_names = []
  }

  expect_failures = [var.uami_readable_secret_names]
}
