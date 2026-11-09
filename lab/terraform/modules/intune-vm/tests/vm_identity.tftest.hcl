# Offline mocked plan/apply of modules/intune-vm (no tenant, no subscription,
# no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins the VM itself as main.tf codes it:
#   * Size Standard_B2s and image MicrosoftWindowsDesktop / windows-11 /
#     win11-25h2-ent by default. The SKU is pinned; the image VERSION is
#     "latest" (a new deploy takes the newest build of that SKU).
#   * Windows_Client licence, Trusted Launch (Secure Boot + vTPM), managed
#     boot diagnostics.
#   * OS disk: Standard_LRS, ReadWrite caching, and NO disk-encryption
#     option set in code (no disk encryption set, no encryption at host, no
#     confidential OS-disk encryption) - it gets Azure's default server-side
#     encryption only. A change there must change this test.
#   * System-assigned identity only (the AADLoginForWindows extension joins
#     Entra with it). The extension passes Intune's mdmId only when
#     enable_intune_enrollment is true, and never protected settings.
#   * "Virtual Machine Administrator Login" at VM scope: one assignment per
#     user / group given, none by default. Owner/Contributor never.
#   * Nightly deallocate; tags on every taggable resource; outputs (the local
#     admin password stays sensitive; the .rdp file names the hostname, never
#     an IP).
#   * Input validation for the image SKU, hostname, admin name, object ids and
#     shutdown time.

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

# At apply the provider checks admin_password complexity, so the mock needs a
# value that passes - an obvious placeholder, never a real credential.
mock_provider "random" {
  mock_resource "random_password" {
    defaults = { result = "mock-NOT-a-secret-0" }
  }
}

variables {
  resource_group_name = "rg-identity-lab"
  vnet_name           = "vnet-identity-lab"
}

# ---- VM shape -----------------------------------------------------------------

run "defaults_pin_size_image_licence_and_trusted_launch" {
  command = plan

  assert {
    condition     = azurerm_windows_virtual_machine.vm.size == "Standard_B2s"
    error_message = "the default size must stay Standard_B2s (smallest size meeting the Windows 11 minimum)"
  }
  assert {
    condition = (
      azurerm_windows_virtual_machine.vm.source_image_reference[0].publisher == "MicrosoftWindowsDesktop" &&
      azurerm_windows_virtual_machine.vm.source_image_reference[0].offer == "windows-11" &&
      azurerm_windows_virtual_machine.vm.source_image_reference[0].sku == "win11-25h2-ent"
    )
    error_message = "the default image must be MicrosoftWindowsDesktop / windows-11 / win11-25h2-ent (Enterprise single-session)"
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.source_image_reference[0].version == "latest"
    error_message = "pins the CODE: the image version floats to latest of the pinned SKU. Pinning a build number is a design change - update this test with it."
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.license_type == "Windows_Client"
    error_message = "license_type must be Windows_Client (Windows 11 Enterprise multitenant hosting rights, see main.tf header)"
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.secure_boot_enabled == true && azurerm_windows_virtual_machine.vm.vtpm_enabled == true
    error_message = "Trusted Launch (Secure Boot + vTPM) must stay on - Windows 11 and the compliance health checks need it"
  }
  assert {
    condition     = length(azurerm_windows_virtual_machine.vm.boot_diagnostics) == 1 && azurerm_windows_virtual_machine.vm.boot_diagnostics[0].storage_account_uri == null
    error_message = "boot diagnostics must use the managed storage account (no storage_account_uri) - serial console fallback"
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.name == "vm-win11-01" && azurerm_windows_virtual_machine.vm.computer_name == "CH-WIN11-01" && azurerm_windows_virtual_machine.vm.location == "eastus2"
    error_message = "defaults: vm-win11-01 / hostname CH-WIN11-01 / eastus2"
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.admin_username == "contosolocal"
    error_message = "the default local break-glass admin must be contosolocal"
  }
}

run "size_and_sku_overrides_flow_through" {
  command = plan

  variables {
    vm_size   = "Standard_B2as_v2"
    image_sku = "win11-24h2-ent"
  }

  assert {
    condition     = azurerm_windows_virtual_machine.vm.size == "Standard_B2as_v2"
    error_message = "vm_size must reach the VM unchanged"
  }
  assert {
    condition     = azurerm_windows_virtual_machine.vm.source_image_reference[0].sku == "win11-24h2-ent" && azurerm_windows_virtual_machine.vm.source_image_reference[0].offer == "windows-11"
    error_message = "image_sku must reach the VM; publisher and offer stay fixed"
  }
}

run "os_disk_and_encryption_as_coded" {
  command = plan

  assert {
    condition = (
      azurerm_windows_virtual_machine.vm.os_disk[0].storage_account_type == "Standard_LRS" &&
      azurerm_windows_virtual_machine.vm.os_disk[0].caching == "ReadWrite" &&
      azurerm_windows_virtual_machine.vm.os_disk[0].name == "osdisk-vm-win11-01"
    )
    error_message = "OS disk must be osdisk-<vm_name>, Standard_LRS, ReadWrite caching"
  }
  assert {
    condition = (
      azurerm_windows_virtual_machine.vm.encryption_at_host_enabled == null &&
      azurerm_windows_virtual_machine.vm.os_disk[0].disk_encryption_set_id == null &&
      azurerm_windows_virtual_machine.vm.os_disk[0].secure_vm_disk_encryption_set_id == null &&
      azurerm_windows_virtual_machine.vm.os_disk[0].security_encryption_type == null
    )
    error_message = "pins the CODE: no disk encryption set, no encryption at host and no confidential OS-disk encryption are configured (Azure default server-side encryption only). Adding one is a design change - update this test with it."
  }
}

run "identity_is_system_assigned_only" {
  command = plan

  assert {
    condition     = length(azurerm_windows_virtual_machine.vm.identity) == 1 && azurerm_windows_virtual_machine.vm.identity[0].type == "SystemAssigned"
    error_message = "the VM must have a system-assigned identity - AADLoginForWindows uses it for the Entra join"
  }
  assert {
    condition     = try(length(azurerm_windows_virtual_machine.vm.identity[0].identity_ids), 0) == 0
    error_message = "no user-assigned identity may be attached to the endpoint VM"
  }
}

run "local_admin_password_shape" {
  command = plan

  assert {
    condition = (
      random_password.admin.length == 24 &&
      random_password.admin.special == true &&
      random_password.admin.min_lower == 2 &&
      random_password.admin.min_upper == 2 &&
      random_password.admin.min_numeric == 2 &&
      random_password.admin.min_special == 2
    )
    error_message = "the break-glass password must be 24 characters with at least 2 lower, 2 upper, 2 digits and 2 specials"
  }
  assert {
    condition     = random_password.admin.override_special == "!#%*()-_=+[]{}:?"
    error_message = "the special-character set must stay as coded (override_special)"
  }
}

# ---- Entra join + Intune enrollment --------------------------------------------

run "intune_enrollment_on_by_default" {
  command = plan

  assert {
    condition = (
      azurerm_virtual_machine_extension.aad_login.name == "AADLoginForWindows" &&
      azurerm_virtual_machine_extension.aad_login.publisher == "Microsoft.Azure.ActiveDirectory" &&
      azurerm_virtual_machine_extension.aad_login.type == "AADLoginForWindows" &&
      azurerm_virtual_machine_extension.aad_login.type_handler_version == "1.0" &&
      azurerm_virtual_machine_extension.aad_login.auto_upgrade_minor_version == true
    )
    error_message = "the Entra login extension must be Microsoft.Azure.ActiveDirectory / AADLoginForWindows 1.0 with minor auto-upgrade"
  }
  assert {
    condition     = jsondecode(azurerm_virtual_machine_extension.aad_login.settings) == { mdmId = "0000000a-0000-0000-c000-000000000000" }
    error_message = "with enrollment on, settings must be exactly { mdmId = Intune's MDM app id } so the join also enrolls in Intune"
  }
  assert {
    condition     = azurerm_virtual_machine_extension.aad_login.protected_settings == null
    error_message = "the extension takes no secrets (it joins with the VM's managed identity)"
  }
  assert {
    condition     = output.intune_enrollment_enabled == true
    error_message = "output intune_enrollment_enabled must report the default (true)"
  }
}

run "entra_join_only_when_enrollment_off" {
  command = plan

  variables {
    enable_intune_enrollment = false
  }

  assert {
    condition     = azurerm_virtual_machine_extension.aad_login.type == "AADLoginForWindows"
    error_message = "the Entra join extension must still be installed with enrollment off"
  }
  assert {
    condition     = azurerm_virtual_machine_extension.aad_login.settings == null
    error_message = "with enrollment off the extension must carry no mdmId (Entra join only)"
  }
  assert {
    condition     = output.intune_enrollment_enabled == false
    error_message = "output intune_enrollment_enabled must report false"
  }
}

# ---- Who may sign in -----------------------------------------------------------

run "no_login_role_assignments_by_default" {
  command = plan

  assert {
    condition     = length(azurerm_role_assignment.vm_admin_login_user) == 0 && length(azurerm_role_assignment.vm_admin_login_group) == 0
    error_message = "with no user or group ids, no VM login role may be assigned"
  }
}

run "one_login_assignment_per_user_and_group_at_vm_scope" {
  command = apply

  variables {
    # The repeated id must collapse to one assignment (toset).
    admin_login_user_object_ids = [
      "aaaaaaaa-0000-4000-8000-000000000001",
      "aaaaaaaa-0000-4000-8000-000000000002",
      "aaaaaaaa-0000-4000-8000-000000000001",
    ]
    admin_login_group_object_ids = { ca005_pilot = "bbbbbbbb-0000-4000-8000-000000000001" }
  }

  assert {
    condition     = length(azurerm_role_assignment.vm_admin_login_user) == 2
    error_message = "one assignment per distinct user id (duplicates collapse)"
  }
  assert {
    condition     = keys(azurerm_role_assignment.vm_admin_login_group) == ["ca005_pilot"]
    error_message = "group assignments must be keyed by the static map label (plannable while the group id is unknown)"
  }
  assert {
    condition = alltrue(concat(
      [for a in values(azurerm_role_assignment.vm_admin_login_user) : a.role_definition_name == "Virtual Machine Administrator Login" && a.principal_type == "User" && a.scope == azurerm_windows_virtual_machine.vm.id],
      [for a in values(azurerm_role_assignment.vm_admin_login_group) : a.role_definition_name == "Virtual Machine Administrator Login" && a.principal_type == "Group" && a.scope == azurerm_windows_virtual_machine.vm.id],
    ))
    error_message = "every assignment must be Virtual Machine Administrator Login, scoped to this VM only, with the right principal type"
  }
  assert {
    condition     = toset([for a in values(azurerm_role_assignment.vm_admin_login_user) : a.principal_id]) == toset(["aaaaaaaa-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000002"]) && azurerm_role_assignment.vm_admin_login_group["ca005_pilot"].principal_id == "bbbbbbbb-0000-4000-8000-000000000001"
    error_message = "principal ids must be passed through unchanged"
  }
}

# ---- Auto-shutdown and tags ------------------------------------------------------

run "nightly_deallocate_by_default" {
  command = plan

  assert {
    condition = (
      azurerm_dev_test_global_vm_shutdown_schedule.vm.enabled == true &&
      azurerm_dev_test_global_vm_shutdown_schedule.vm.daily_recurrence_time == "1900" &&
      azurerm_dev_test_global_vm_shutdown_schedule.vm.timezone == "Eastern Standard Time"
    )
    error_message = "the VM must deallocate daily at 19:00 Eastern by default"
  }
  assert {
    condition     = azurerm_dev_test_global_vm_shutdown_schedule.vm.notification_settings[0].enabled == false
    error_message = "shutdown notifications stay off as coded (no email or webhook target is configured)"
  }
}

run "shutdown_time_override_and_tags_everywhere" {
  command = plan

  variables {
    auto_shutdown_time = "2230"
    tags               = { project = "contoso-health-identity-lab", env = "lab" }
  }

  assert {
    condition     = azurerm_dev_test_global_vm_shutdown_schedule.vm.daily_recurrence_time == "2230"
    error_message = "auto_shutdown_time must reach the schedule"
  }
  assert {
    condition = alltrue([
      for t in [
        azurerm_network_security_group.endpoints.tags,
        azurerm_public_ip.vm.tags,
        azurerm_network_interface.vm.tags,
        azurerm_windows_virtual_machine.vm.tags,
        azurerm_virtual_machine_extension.aad_login.tags,
        azurerm_dev_test_global_vm_shutdown_schedule.vm.tags,
      ] : t == tomap({ project = "contoso-health-identity-lab", env = "lab" })
    ])
    error_message = "every taggable resource must carry var.tags"
  }
}

# ---- Outputs -------------------------------------------------------------------

run "outputs" {
  command = apply

  assert {
    condition     = output.vm_id == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Compute/virtualMachines/vm-win11-01"
    error_message = "vm_id must be the VM's resource id"
  }
  assert {
    condition     = output.vm_name == "vm-win11-01" && output.computer_name == "CH-WIN11-01" && output.admin_username == "contosolocal"
    error_message = "name outputs must come from the VM"
  }
  assert {
    condition     = output.private_ip == "10.42.3.4" && output.public_ip == null
    error_message = "private_ip comes from the NIC; public_ip is null (no public address since 2026-11-08)"
  }
  assert {
    condition     = output.identity_principal_id == "33333333-3333-3333-3333-333333333333"
    error_message = "identity_principal_id must be the system-assigned identity's object id"
  }
  assert {
    condition     = issensitive(output.admin_password)
    error_message = "the local admin password output must stay sensitive"
  }
  assert {
    condition     = nonsensitive(output.admin_password) == random_password.admin.result
    error_message = "admin_password must be the generated break-glass password"
  }
  assert {
    condition     = output.rdp_file_content == "full address:s:CH-WIN11-01\nenablerdsaadauth:i:1\nscreen mode id:i:1\n"
    error_message = "the .rdp must name the HOSTNAME (Entra RDP rejects IPs) with enablerdsaadauth:i:1"
  }
  assert {
    condition     = !strcontains(output.rdp_file_content, "192.0.2.10") && !strcontains(output.rdp_file_content, output.private_ip)
    error_message = "the .rdp must never carry an IP address"
  }
}

run "rdp_file_follows_computer_name" {
  command = plan

  variables {
    computer_name = "CH-WIN11-02"
  }

  assert {
    condition     = startswith(output.rdp_file_content, "full address:s:CH-WIN11-02\n")
    error_message = "the .rdp full address must follow computer_name"
  }
}

# ---- rejected inputs -----------------------------------------------------------

run "multi_session_sku_is_rejected" {
  command = plan

  variables {
    image_sku = "win11-24h2-avd"
  }

  expect_failures = [var.image_sku]
}

run "pro_sku_is_rejected" {
  command = plan

  variables {
    image_sku = "win11-24h2-pro"
  }

  expect_failures = [var.image_sku]
}

run "windows10_sku_is_rejected" {
  command = plan

  variables {
    image_sku = "win10-22h2-ent"
  }

  expect_failures = [var.image_sku]
}

run "hostname_over_15_chars_is_rejected" {
  command = plan

  variables {
    computer_name = "CH-WIN11-0123456"
  }

  expect_failures = [var.computer_name]
}

run "all_digit_hostname_is_rejected" {
  command = plan

  variables {
    computer_name = "12345"
  }

  expect_failures = [var.computer_name]
}

run "hostname_with_leading_hyphen_is_rejected" {
  command = plan

  variables {
    computer_name = "-CHWIN11"
  }

  expect_failures = [var.computer_name]
}

run "hostname_with_underscore_is_rejected" {
  command = plan

  variables {
    computer_name = "CH_WIN11_01"
  }

  expect_failures = [var.computer_name]
}

run "reserved_admin_name_is_rejected_any_case" {
  command = plan

  variables {
    admin_username = "Administrator"
  }

  expect_failures = [var.admin_username]
}

run "user_object_id_must_be_a_guid" {
  command = plan

  variables {
    admin_login_user_object_ids = ["admin@contoso.example"]
  }

  expect_failures = [var.admin_login_user_object_ids]
}

run "group_object_id_must_be_a_guid" {
  command = plan

  variables {
    admin_login_group_object_ids = { ca005_pilot = "CA005-Pilot-CompliantDevice" }
  }

  expect_failures = [var.admin_login_group_object_ids]
}

run "shutdown_hour_24_is_rejected" {
  command = plan

  variables {
    auto_shutdown_time = "2400"
  }

  expect_failures = [var.auto_shutdown_time]
}

run "shutdown_time_with_colon_is_rejected" {
  command = plan

  variables {
    auto_shutdown_time = "19:00"
  }

  expect_failures = [var.auto_shutdown_time]
}
