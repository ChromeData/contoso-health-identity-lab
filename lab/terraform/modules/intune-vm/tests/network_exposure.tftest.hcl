# Offline mocked plan/apply of modules/intune-vm (no tenant, no subscription,
# no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins the Windows 11 Intune VM's network exposure since 2026-11-08:
#   * NO inbound NSG rule at all: the only admin path is Azure Bastion from
#     inside the VNet (the NSG default AllowVnetInBound admits it). Nothing
#     depends on the operator's home IP any more.
#   * The NIC has no public IP. pip-vm-win11-01 stays in config, unreferenced,
#     for one apply (step 1 of 2: detach before delete).
#   * Outbound: the endpoint subnet can be attached to a NAT gateway
#     (attach_nat_gateway + nat_gateway_id), with a clear error if the id is
#     missing.
mock_provider "azurerm" {
  mock_resource "azurerm_subnet" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/virtualNetworks/vnet-identity-lab/subnets/snet-endpoints" }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/networkSecurityGroups/nsg-vm-win11-01" }
  }
  mock_resource "azurerm_public_ip" {
    defaults = {
      id         = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/publicIPAddresses/pip-vm-win11-01"
      ip_address = "192.0.2.10"
    }
  }
  mock_resource "azurerm_network_interface" {
    defaults = {
      id                 = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/networkInterfaces/nic-vm-win11-01"
      private_ip_address = "10.42.3.4"
    }
  }
  mock_resource "azurerm_windows_virtual_machine" {
    defaults = {
      id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Compute/virtualMachines/vm-win11-01"
      identity = {
        principal_id = "33333333-3333-3333-3333-333333333333"
        tenant_id    = "11111111-1111-1111-1111-111111111111"
      }
    }
  }
}

# The rule-shape runs use a MOCKED apply (nothing leaves this machine): an
# empty dynamic security_rule is only known after apply. At apply the provider
# checks admin_password complexity, so the mock needs a value that passes -
# an obvious placeholder, never a real credential.
mock_provider "random" {
  mock_resource "random_password" {
    defaults = { result = "mock-NOT-a-secret-0" }
  }
}

variables {
  resource_group_name = "rg-identity-lab"
  vnet_name           = "vnet-identity-lab"
}

# ---- accepted -----------------------------------------------------------------

run "no_inbound_rule_and_no_public_ip" {
  command = apply

  assert {
    condition     = length(azurerm_network_security_group.endpoints.security_rule) == 0
    error_message = "no inbound NSG rule: the PC is reached through Azure Bastion only"
  }
  assert {
    condition     = azurerm_network_interface.vm.ip_configuration[0].public_ip_address_id == null
    error_message = "the NIC must not reference a public IP"
  }
  assert {
    condition     = azurerm_public_ip.vm.name == "pip-vm-win11-01" && azurerm_public_ip.vm.sku == "Standard" && azurerm_public_ip.vm.allocation_method == "Static"
    error_message = "step 1 of 2: pip-vm-win11-01 stays in config, unchanged and unreferenced, for one apply"
  }
  assert {
    condition     = output.public_ip == null
    error_message = "the public_ip output is null: there is no public address to use"
  }
  assert {
    condition     = length(azurerm_subnet_nat_gateway_association.endpoints) == 0
    error_message = "no NAT gateway association unless attach_nat_gateway is true"
  }
}

run "nat_gateway_attached_when_asked" {
  command = plan

  variables {
    attach_nat_gateway = true
    nat_gateway_id     = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/natGateways/natgw-vm-dc01"
  }

  assert {
    condition     = length(azurerm_subnet_nat_gateway_association.endpoints) == 1 && azurerm_subnet_nat_gateway_association.endpoints[0].nat_gateway_id == var.nat_gateway_id
    error_message = "attach_nat_gateway = true attaches the endpoint subnet to the given NAT gateway"
  }
}

run "subnet_defaults_and_outbound_config" {
  command = plan

  assert {
    condition     = azurerm_subnet.endpoints.name == "snet-endpoints" && azurerm_subnet.endpoints.address_prefixes == tolist(["10.42.3.0/24"])
    error_message = "the default endpoint subnet must be snet-endpoints, 10.42.3.0/24 (lab VNet plan)"
  }
  assert {
    condition     = azurerm_subnet.endpoints.default_outbound_access_enabled == null
    error_message = "pins the CONFIG only: default_outbound_access_enabled stays unset in this module (the mock provider applies no SDK default). Outbound is the NAT gateway (attach_nat_gateway) or Azure default outbound access."
  }
  assert {
    condition     = azurerm_network_security_group.endpoints.name == "nsg-vm-win11-01" && azurerm_network_interface.vm.name == "nic-vm-win11-01"
    error_message = "network resource names derive from vm_name"
  }
}

# ---- rejected -----------------------------------------------------------------

run "empty_subnet_prefix_is_rejected" {
  command = plan

  variables {
    subnet_prefix = []
  }

  expect_failures = [var.subnet_prefix]
}

run "malformed_subnet_prefix_is_rejected" {
  command = plan

  variables {
    subnet_prefix = ["10.42.3.0"]
  }

  expect_failures = [var.subnet_prefix]
}

run "attach_without_id_is_rejected" {
  command = plan

  variables {
    attach_nat_gateway = true
  }

  expect_failures = [azurerm_subnet_nat_gateway_association.endpoints]
}

run "malformed_nat_gateway_id_is_rejected" {
  command = plan

  variables {
    nat_gateway_id = "natgw-vm-dc01"
  }

  expect_failures = [var.nat_gateway_id]
}
