# Offline mocked plan/apply of modules/intune-vm (no tenant, no subscription,
# no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins the Windows 11 Intune VM's network exposure as main.tf codes it:
#   * RDP (TCP 3389) is the ONLY inbound allow, and only when
#     allowed_ip_ranges is non-empty. An empty list (the default) means no
#     inbound rule at all.
#   * The rule's sources are exactly the operator entries; its destination is
#     the endpoint subnet (subnet_prefix) only.
#   * Entries up to /24 are accepted. That is what this module's validation
#     does: envs/dev passes it operator_ip_ranges, which ADR 0013 documents
#     as shared with the Key Vault firewall and the evidence store and kept at
#     /24 or narrower. ADR 0013's single-/32 rule is enforced in
#     modules/dc-vm (Tier-0 DC) only, not here. /23 and wider, any-address,
#     service tags, bare addresses, IPv6 and garbage fail at plan.
#   * One Standard static public IP with no DNS label; the NIC's private IP is
#     dynamic and sits in the endpoint subnet.

# Path-form ids where another resource's argument parses them (the provider
# still validates ids under a mock).
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

run "empty_list_means_no_inbound_rules" {
  command = apply

  variables {
    allowed_ip_ranges = []
  }

  assert {
    condition     = length(azurerm_network_security_group.endpoints.security_rule) == 0
    error_message = "an empty allowlist must create no inbound rule at all (the default; serial console only)"
  }
  assert {
    condition     = azurerm_subnet_network_security_group_association.endpoints.network_security_group_id == azurerm_network_security_group.endpoints.id && azurerm_subnet_network_security_group_association.endpoints.subnet_id == azurerm_subnet.endpoints.id
    error_message = "the NSG must still be attached to the endpoint subnet when it has no rules (NSG defaults deny inbound)"
  }
}

run "single_slash32_opens_rdp_only" {
  command = apply

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = length(azurerm_network_security_group.endpoints.security_rule) == 1
    error_message = "a non-empty allowlist must plan exactly one inbound rule"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.endpoints.security_rule : r.destination_port_range == "3389" && try(length(r.destination_port_ranges), 0) == 0])
    error_message = "the only inbound port must be 3389 (RDP), with no extra port list"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.endpoints.security_rule : r.name == "allow-rdp-operator" && r.priority == 100 && r.access == "Allow" && r.direction == "Inbound" && r.protocol == "Tcp" && r.source_port_range == "*"])
    error_message = "the rule must be allow-rdp-operator: priority 100, inbound TCP allow"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.endpoints.security_rule : toset(r.source_address_prefixes) == toset(["203.0.113.7/32"]) && r.source_address_prefix == null])
    error_message = "the rule's source must be exactly the operator entry - no single-prefix source such as * or Internet"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.endpoints.security_rule : toset(r.destination_address_prefixes) == toset(["10.42.3.0/24"]) && r.destination_address_prefix == null])
    error_message = "the rule must target only the endpoint subnet (10.42.3.0/24 by default)"
  }
}

run "slash24_and_slash32_entries_pass_through_unchanged" {
  command = apply

  variables {
    # /24 is the widest entry this module accepts (shared operator_ip_ranges).
    allowed_ip_ranges = ["203.0.113.7/32", "198.51.100.0/24"]
  }

  assert {
    condition     = length(azurerm_network_security_group.endpoints.security_rule) == 1
    error_message = "several entries must still produce one RDP rule, not one rule per entry"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.endpoints.security_rule : toset(r.source_address_prefixes) == toset(["203.0.113.7/32", "198.51.100.0/24"])])
    error_message = "every accepted entry must be passed through to the rule unchanged"
  }
}

run "custom_subnet_prefix_is_the_rule_destination" {
  command = apply

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
    subnet_prefix     = ["10.42.30.0/24"]
    subnet_name       = "snet-endpoints-b"
  }

  assert {
    condition     = azurerm_subnet.endpoints.address_prefixes == tolist(["10.42.30.0/24"]) && azurerm_subnet.endpoints.name == "snet-endpoints-b" && azurerm_subnet.endpoints.virtual_network_name == "vnet-identity-lab"
    error_message = "the subnet must use the given name and prefix inside the given VNet"
  }
  assert {
    condition     = length(azurerm_network_security_group.endpoints.security_rule) == 1 && alltrue([for r in azurerm_network_security_group.endpoints.security_rule : toset(r.destination_address_prefixes) == toset(["10.42.30.0/24"])])
    error_message = "the RDP rule's destination must follow subnet_prefix"
  }
}

run "public_ip_and_nic_shape" {
  command = apply

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = azurerm_public_ip.vm.sku == "Standard" && azurerm_public_ip.vm.allocation_method == "Static" && azurerm_public_ip.vm.name == "pip-vm-win11-01"
    error_message = "the VM's public IP must be one Standard static IP (operator RDP + explicit outbound)"
  }
  assert {
    condition     = azurerm_public_ip.vm.domain_name_label == null
    error_message = "the public IP must not publish a DNS name (no <label>.<region>.cloudapp.azure.com record)"
  }
  assert {
    condition     = length(azurerm_network_interface.vm.ip_configuration) == 1
    error_message = "the NIC must have exactly one IP configuration"
  }
  assert {
    condition     = azurerm_network_interface.vm.ip_configuration[0].private_ip_address_allocation == "Dynamic" && azurerm_network_interface.vm.ip_configuration[0].subnet_id == azurerm_subnet.endpoints.id
    error_message = "the NIC must take a dynamic private IP from the endpoint subnet"
  }
  assert {
    condition     = azurerm_network_interface.vm.ip_configuration[0].public_ip_address_id == azurerm_public_ip.vm.id
    error_message = "the NIC must carry this module's public IP and no other"
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.network_interface_ids == tolist([azurerm_network_interface.vm.id])
    error_message = "the VM must have exactly one NIC (this module's)"
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
    error_message = "pins the CONFIG only: default_outbound_access_enabled stays unset in this module (the mock provider applies no SDK default). The public IP is the VM's explicit outbound method; setting it is a design change."
  }
  assert {
    condition     = azurerm_network_security_group.endpoints.name == "nsg-vm-win11-01" && azurerm_network_interface.vm.name == "nic-vm-win11-01"
    error_message = "network resource names derive from vm_name"
  }
}

# ---- rejected -----------------------------------------------------------------

run "slash23_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.112.0/23"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "any_address_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "one_wide_entry_among_narrow_ones_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.7/32", "198.51.0.0/16"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "service_tag_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["Internet"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "wildcard_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["*"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "bare_address_without_prefix_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.7"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "ipv6_host_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["2001:db8::7/128"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "malformed_address_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.700/32"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

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
