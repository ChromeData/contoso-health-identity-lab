# Offline mocked plan of modules/dc-vm (no tenant, no subscription, no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins ADR 0013 as amended 2026-11-08 (karen-review round 2, R5):
#   * RDP (3389) and LDAPS (636) are NEVER opened to the internet, and the
#     DC's NIC has NO public IP, whatever allowed_ip_ranges holds.
#   * Outbound goes through a NAT gateway on snet-identity (outbound only).
#   * The one exception: 443 while adfs_https_enabled, from /32 entries only,
#     with a public IP for that window only.
#   * The allowlist still accepts single IPv4 /32 entries only: /24, /31,
#     0.0.0.0/0, a bare address, IPv6 and garbage fail at plan.
#   * Every Run Command on the DC raises an activity log alert.

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
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/publicIPAddresses/pip-mock" }
  }
  mock_resource "azurerm_nat_gateway" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/natGateways/natgw-vm-dc01" }
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

run "slash32_opens_no_rdp_or_ldaps_and_no_public_ip" {
  command   = apply
  state_key = "slash32_no_admin_ports"

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = length(azurerm_network_security_group.dc.security_rule) == 0
    error_message = "R5: an operator /32 alone must open NOTHING (no RDP, no LDAPS from the internet)"
  }
  assert {
    condition     = length(azurerm_public_ip.adfs_https) == 0 && azurerm_network_interface.dc.ip_configuration[0].public_ip_address_id == null
    error_message = "R5: the DC's NIC must have no public IP outside the AD FS window"
  }
  assert {
    condition     = output.public_ip == null
    error_message = "the public_ip output must be null outside the AD FS window"
  }
}

run "rdp_and_ldaps_never_open_even_in_adfs_window" {
  command   = apply
  state_key = "adfs_window_ports"

  variables {
    allowed_ip_ranges  = ["203.0.113.7/32", "198.51.100.23/32"]
    adfs_https_enabled = true
  }

  assert {
    condition     = toset([for r in azurerm_network_security_group.dc.security_rule : r.destination_port_range]) == toset(["443"])
    error_message = "R5: during the AD FS window the ONLY inbound port is 443; 3389 and 636 stay closed"
  }
  assert {
    condition     = alltrue([for r in azurerm_network_security_group.dc.security_rule : toset(r.source_address_prefixes) == toset(["203.0.113.7/32", "198.51.100.23/32"])])
    error_message = "each /32 must be passed through to the 443 rule unchanged"
  }
  assert {
    condition     = length(azurerm_public_ip.adfs_https) == 1
    error_message = "the AD FS window gets its own public IP (and only then)"
  }
}

run "outbound_is_nat_gateway_and_dc_disk_shape" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = length(azurerm_nat_gateway.dc) == 1 && azurerm_nat_gateway.dc[0].sku_name == "Standard" && length(azurerm_subnet_nat_gateway_association.dc) == 1 && length(azurerm_nat_gateway_public_ip_association.dc) == 1
    error_message = "snet-identity must get a Standard NAT gateway (the DC's explicit outbound method) by default"
  }
  assert {
    condition     = azurerm_public_ip.nat[0].sku == "Standard" && azurerm_public_ip.nat[0].allocation_method == "Static"
    error_message = "the NAT gateway's public IP must be Standard static"
  }
  assert {
    condition     = azurerm_subnet.dc.default_outbound_access_enabled == null
    error_message = "pins the CONFIG only: default_outbound_access_enabled stays unset in this module (the NAT gateway takes precedence). Setting it is a design change - see the main.tf header."
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

run "nat_gateway_can_be_switched_off" {
  command = plan

  variables {
    nat_gateway_enabled = false
  }

  assert {
    condition     = length(azurerm_nat_gateway.dc) == 0 && length(azurerm_public_ip.nat) == 0
    error_message = "nat_gateway_enabled = false must plan no NAT gateway and no NAT IP"
  }
}

run "run_command_alerts_on_both_operations" {
  command = plan

  assert {
    condition     = toset([for a in azurerm_monitor_activity_log_alert.dc_run_command : a.criteria[0].operation_name]) == toset(["Microsoft.Compute/virtualMachines/runCommand/action", "Microsoft.Compute/virtualMachines/runCommands/write"])
    error_message = "R5: every Run Command path on the DC (invoke and managed) must raise an activity log alert"
  }
  assert {
    condition     = alltrue([for a in azurerm_monitor_activity_log_alert.dc_run_command : a.criteria[0].category == "Administrative" && a.location == "global"])
    error_message = "activity log alerts must use the Administrative category, location global"
  }
}

# The live transition (Greptile on #272): the SAME state first holds rules,
# then the window closes. With a dynamic block the old rules stayed
# (Optional + Computed); the explicit empty list must remove them.
run "transition_window_open" {
  command   = apply
  state_key = "transition"

  variables {
    allowed_ip_ranges  = ["203.0.113.7/32"]
    adfs_https_enabled = true
  }

  assert {
    condition     = length(azurerm_network_security_group.dc.security_rule) == 1
    error_message = "setup: the AD FS window has one rule"
  }
}

run "transition_window_closed_removes_rules" {
  command   = apply
  state_key = "transition"

  variables {
    allowed_ip_ranges  = ["203.0.113.7/32"]
    adfs_https_enabled = false
  }

  assert {
    condition     = length(azurerm_network_security_group.dc.security_rule) == 0
    error_message = "R5 / Greptile P1: closing the window must REMOVE existing rules from the same state, not keep them"
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

# ---- AD FS exercise: 443 only with the flag, only from the allowlist ------------

run "https_closed_by_default" {
  command   = apply
  state_key = "https_default"

  variables {
    allowed_ip_ranges = ["203.0.113.7/32"]
  }

  assert {
    condition     = length([for r in azurerm_network_security_group.dc.security_rule : r if r.destination_port_range == "443"]) == 0
    error_message = "Port 443 must stay closed unless adfs_https_enabled = true."
  }
}

run "https_open_only_with_flag_and_only_from_allowlist" {
  command   = apply
  state_key = "https_flag"

  variables {
    allowed_ip_ranges  = ["203.0.113.7/32"]
    adfs_https_enabled = true
  }

  assert {
    condition = length([
      for r in azurerm_network_security_group.dc.security_rule : r
      if r.destination_port_range == "443" && r.access == "Allow" && toset(r.source_address_prefixes) == toset(["203.0.113.7/32"]) && r.destination_address_prefix == "10.42.2.4"
    ]) == 1
    error_message = "adfs_https_enabled must add exactly one 443 allow rule, from the /32 allowlist, to the DC's private IP only."
  }
}

run "https_flag_with_empty_allowlist_opens_nothing" {
  command = apply
  # Own state: security_rule is Optional+Computed in azurerm, so a run that
  # follows one with rules would keep them in the shared test state.
  state_key = "https_empty_allowlist"

  variables {
    allowed_ip_ranges  = []
    adfs_https_enabled = true
  }

  assert {
    condition     = length(azurerm_network_security_group.dc.security_rule) == 0
    error_message = "With no allowlist there must be no inbound rule at all, flag or not."
  }
}
