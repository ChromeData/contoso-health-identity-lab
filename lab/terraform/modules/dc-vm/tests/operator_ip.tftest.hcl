# Offline mocked plan of modules/dc-vm (no tenant, no subscription, no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins ADR 0013's allowlist rule: the DC's NSG admits RDP (3389) and LDAPS
# (636) only from single IPv4 /32 entries. /24, /31, 0.0.0.0/0, a bare
# address, IPv6 and garbage fail at plan, before any NSG change. Also pins
# what the tightening must NOT change: an empty list still means no inbound
# rule at all, the rules still target only the DC's private IP, and the
# public IP stays the DC's explicit (Standard, static) outbound method.

# Path-form ids where another resource's argument parses them (the provider
# still validates ids under a mock).
mock_provider "azurerm" {
  mock_resource "azurerm_subnet" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/virtualNetworks/vnet-identity-lab/subnets/snet-identity" }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/networkSecurityGroups/nsg-vm-dc01" }
  }
  mock_resource "azurerm_public_ip" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/publicIPAddresses/pip-vm-dc01" }
  }
  mock_resource "azurerm_network_interface" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/networkInterfaces/nic-vm-dc01" }
  }
  mock_resource "azurerm_windows_virtual_machine" {
    defaults = {
      id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Compute/virtualMachines/vm-dc01"
      identity = {
        principal_id = "33333333-3333-3333-3333-333333333333"
        tenant_id    = "11111111-1111-1111-1111-111111111111"
      }
    }
  }
  mock_resource "azurerm_managed_disk" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Compute/disks/datadisk-vm-dc01-ntds" }
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
  key_vault_id        = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab"
}

# ---- accepted -----------------------------------------------------------------

run "empty_list_means_no_inbound_rules" {
  command = apply

  variables {
    allowed_ip_ranges = []
  }

  assert {
    condition     = length(azurerm_network_security_group.dc.security_rule) == 0
    error_message = "an empty allowlist must create no inbound rule at all"
  }
}

run "single_slash32_is_accepted" {
  command = apply

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = length(azurerm_network_security_group.dc.security_rule) == 2
    error_message = "a /32 must plan exactly the RDP and LDAPS rules"
  }
  assert {
    condition     = toset([for r in azurerm_network_security_group.dc.security_rule : r.destination_port_range]) == toset(["3389", "636"])
    error_message = "the only inbound ports must be 3389 (RDP) and 636 (LDAPS)"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.dc.security_rule : toset(r.source_address_prefixes) == toset(["203.0.113.7/32"])])
    error_message = "every rule's source must be exactly the operator /32"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.dc.security_rule : r.destination_address_prefix == "10.42.2.4" && r.access == "Allow" && r.direction == "Inbound" && r.protocol == "Tcp"])
    error_message = "the rules must allow inbound TCP to the DC's private IP only"
  }
}

run "several_slash32_entries_are_accepted" {
  command = apply

  variables {
    allowed_ip_ranges = ["203.0.113.7/32", "198.51.100.23/32"]
  }

  assert {
    condition     = alltrue([for r in azurerm_network_security_group.dc.security_rule : toset(r.source_address_prefixes) == toset(["203.0.113.7/32", "198.51.100.23/32"])])
    error_message = "each /32 must be passed through to both rules unchanged"
  }
}

run "unchanged_outbound_and_dc_disk_shape" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = azurerm_public_ip.dc.sku == "Standard" && azurerm_public_ip.dc.allocation_method == "Static"
    error_message = "the public IP must stay a Standard static IP (the DC's explicit outbound method)"
  }
  assert {
    condition     = azurerm_subnet.dc.default_outbound_access_enabled == null
    error_message = "pins the CONFIG only: default_outbound_access_enabled stays unset in this module (the mock provider applies no SDK default; the real azurerm plan sends its documented default, true). Setting it is a design change - see the main.tf header."
  }
  assert {
    condition     = azurerm_virtual_machine_data_disk_attachment.ntds.caching == "None"
    error_message = "the NTDS data disk must keep host caching None"
  }
  assert {
    condition     = azurerm_managed_disk.ntds.public_network_access_enabled == false && azurerm_managed_disk.ntds.network_access_policy == "DenyAll"
    error_message = "the NTDS data disk must have no public network access and no SAS export path (CKV_AZURE_251)"
  }
}

# ---- rejected -----------------------------------------------------------------

run "slash24_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.0/24"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "slash31_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.6/31"]
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

run "one_wide_entry_among_slash32s_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.7/32", "198.51.100.0/24"]
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
