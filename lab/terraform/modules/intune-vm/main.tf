# =============================================================================
# modules/intune-vm :: main.tf
# -----------------------------------------------------------------------------
# The demo "COMPLIANT DEVICE": one Windows 11 Enterprise VM that is Microsoft
# Entra joined and auto-enrolled in Microsoft Intune. It is the device that
# satisfies CA005 (compliant device required for the admin portals, pilot
# group only - modules/conditional-access) once the Intune compliance baseline
# (lab/scripts/intune/New-IntuneComplianceBaseline.ps1) marks it compliant.
# Not a stand-in: Entra join, Intune and Conditional Access are the real
# products - only the "corporate laptop" is a VM.
#
#   * Subnet snet-endpoints (10.42.3.0/24) in the lab VNet var.vnet_name
#   * NSG: NO inbound rule (since 2026-11-08); admins use Azure Bastion from
#     inside the VNet
#   * No public IP on the NIC (since 2026-11-08); outbound to Entra/Intune
#     through DC01's NAT gateway (attach_nat_gateway), because Azure no
#     longer gives new VMs default outbound access
#   * Windows 11 Enterprise (win11-25h2-ent), Standard HDD, Trusted Launch
#     (Secure Boot + vTPM - which is also what the compliance policy's
#     Secure Boot / code integrity health-attestation checks read; the
#     BitLocker check is opt-in, see lab/scripts/intune/README.md)
#   * System-assigned identity + the AADLoginForWindows extension: the
#     extension uses that identity to Entra-JOIN the VM and, with mdmId set,
#     to auto-ENROLL it in Intune
#   * "Virtual Machine Administrator Login" at VM scope for the given users /
#     the CA005 pilot group, so people sign in with Entra credentials (no
#     shared local password)
#   * Auto-shutdown (deallocate) every evening
#
# LICENSING (say it out loud on camera):
#   * license_type = "Windows_Client" attests Windows 11 Enterprise
#     multitenant-hosting rights. Microsoft lists Microsoft 365 E3/E5 as a
#     qualifying entitlement; in this lab that is the M365 E5 TRIAL. Whether a
#     trial licence confers hosting rights for anything beyond dev/test is a
#     licensing question (verify: with your Microsoft licensing contact) - this
#     VM is dev/test only, and should be deallocated or destroyed when the
#     trial ends.
#   * Intune automatic enrollment needs Entra ID P1/P2 (Microsoft: "MDM
#     autoenrollment requires Microsoft Entra ID P1 licenses") + Intune -
#     both inside M365 E5.
#
# HUMAN STEPS (no provider resource exists for these tenant-wide settings).
# Do 1 and 2 BEFORE applying enable_intune_vm = true: the extension attempts
# the Intune enrollment DURING the join, when it installs at apply time -
# before any user has signed in to the VM. (Community-reported, not in
# Microsoft docs: a device that joined before MDM auto-enrollment was set up
# does not enroll on its own later.)
#   1. Intune admin center -> Devices -> Device onboarding -> Enrollment ->
#      Windows -> Automatic Enrollment -> MDM user scope = Some ->
#      CA005-Pilot-CompliantDevice, or All (simplest in a throwaway lab
#      tenant). WIP user scope = None. (Older docs: Entra -> Mobility (MDM and
#      WIP) -> Microsoft Intune - same setting.)
#      verify: whether scope "Some" is honoured for this extension-driven
#      (no-user-at-join) enrollment is not documented; if the VM never shows
#      up in Intune, set the scope to All, delete the device from Entra, and
#      re-create the VM (terraform apply -replace on the VM).
#   2. Assign the pilot user an M365 E5 (trial) licence.
#   3. Recommended: Intune -> Devices -> Compliance -> Compliance policy
#      settings -> "Mark devices with no compliance policy assigned as" =
#      Not compliant, so "compliant" in the demo means "passed a policy".
#   4. After `destroy`: delete the device from Intune (Devices -> Windows) AND
#      Entra (Devices -> All devices). Terraform does not own those objects,
#      and Microsoft documents that a re-join fails if a device with the same
#      hostname still exists.
#
# ADMIN ACCESS (since 2026-11-08): Azure Bastion only. The PC has no public
#   IP and no inbound NSG rule; lab/bastion/capture.sh brings Bastion up for a
#   session and deletes it after. The .rdp output below remains for a client
#   that reaches the PC privately (it names the hostname, as Entra RDP needs).
#   verify: Microsoft documents enablerdsaadauth for "Remote PC connections"
#   and says the CLIENT needs no domain or Entra join for the web-account
#   option, but does not list Windows App for macOS for this path by name;
#   community guidance says it works.
#   Last-resort fallback (NOT Microsoft-documented for a standalone VM): add
#   `targetisaadjoined:i:1` to the .rdp and sign in as AzureAD\<upn> with a
#   password. Microsoft documents targetisaadjoined for Azure Virtual Desktop
#   host pools only, and documents the password path to a standalone Entra-
#   joined VM only from Windows PCs registered/joined to the same tenant.
#   It is password-only, so once CA001 (MFA) is ENFORCED it fails.
#   The Mac itself never needs to be enrolled or compliant for RDP - CA005
#   targets the admin portals, not the RDP / VM sign-in resources
#   ("Microsoft Remote Desktop" a4a365df-50f1-4397-bc59-1a1564b8bb9c).
#
# COST (eastus2, approximate): B2s billed at the base (Linux) compute rate
# with Windows_Client ~ $0.04/hr running; deallocated ~ $6 (127 GiB Standard
# HDD OS disk) + $3.65 static IP per month.
# =============================================================================

locals {
  # Microsoft Intune's MDM application id. Passing it as the extension's mdmId
  # makes the Entra join also enroll the VM in Intune. Source: Microsoft's own
  # Azure Virtual Desktop ARM templates (github.com/Azure/RDS-Templates,
  # ARM-wvd-templates/nestedtemplates/managedDisks-galleryvm.json:
  # settings = createObject('mdmId','0000000a-0000-0000-c000-000000000000')
  # when "intune" is selected).
  intune_mdm_app_id = "0000000a-0000-0000-c000-000000000000"
}

# -----------------------------------------------------------------------------
# Network.
# -----------------------------------------------------------------------------
resource "azurerm_subnet" "endpoints" {
  name                 = var.subnet_name
  resource_group_name  = var.resource_group_name
  virtual_network_name = var.vnet_name
  address_prefixes     = var.subnet_prefix
}

resource "azurerm_network_security_group" "endpoints" {
  name                = "nsg-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  # NO inbound rule from the internet (2026-11-08). The only admin path is
  # Azure Bastion from inside the VNet (AzureBastionSubnet), which the NSG's
  # default AllowVnetInBound rule admits; there is nothing to allow-list, so
  # this no longer depends on the operator's changing home IP. Outbound stays
  # at the NSG default (allow Internet): Entra join, Intune check-in and
  # device health attestation all need it.
}

resource "azurerm_subnet_network_security_group_association" "endpoints" {
  subnet_id                 = azurerm_subnet.endpoints.id
  network_security_group_id = azurerm_network_security_group.endpoints.id
}

# STEP 1 OF 2 (same pattern as dc-vm, #280): pip-vm-win11-01 stays in config
# for ONE apply, referenced by nothing. The NIC's state still lists it, so
# deleting it in the same apply would be ordered before the NIC update that
# detaches it, and Azure refuses (PublicIPAddressCannotBeDeleted). With the
# resource kept, the plan is "NIC updated in place" (public_ip_address_id ->
# null) and nothing is destroyed. STEP 2 (follow-up PR, after this apply):
# delete this block; the plan is then a lone destroy of pip-vm-win11-01,
# which frees the subscription's third eastus2 public IP for Bastion.
# Exposure meanwhile: none inbound (no NSG allow rule, NIC detached).
resource "azurerm_public_ip" "vm" {
  name                = "pip-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.endpoints.id
    private_ip_address_allocation = "Dynamic" # an endpoint, not a server
    # No public IP: people reach the PC through Azure Bastion only.
  }
}

# Explicit outbound for the endpoint subnet through DC01's existing NAT
# gateway (one NAT gateway serves several subnets in a VNet; no extra public
# IP). Without it the PC would rely on Azure's implicit default outbound
# access, which Microsoft is retiring. A plain bool switches it, so count is
# always known at plan.
resource "azurerm_subnet_nat_gateway_association" "endpoints" {
  count          = var.attach_nat_gateway ? 1 : 0
  subnet_id      = azurerm_subnet.endpoints.id
  nat_gateway_id = var.nat_gateway_id

  lifecycle {
    precondition {
      condition     = var.nat_gateway_id != null
      error_message = "attach_nat_gateway = true needs nat_gateway_id (modules/dc-vm output nat_gateway_id; is DC01's NAT gateway enabled?)."
    }
  }
}

# -----------------------------------------------------------------------------
# The VM.
# -----------------------------------------------------------------------------
resource "random_password" "admin" {
  length           = 24
  special          = true
  override_special = "!#%*()-_=+[]{}:?"
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_windows_virtual_machine" "vm" {
  #checkov:skip=CKV_AZURE_151:Encryption at host needs the EncryptionAtHost feature registered on the subscription; the lab endpoint's disks use platform-managed server-side encryption (lab/terraform/README.md, Checkov baseline).
  #checkov:skip=CKV_AZURE_50:The Entra join needs the AADLoginForWindows VM extension (see the identity block below); blocking extensions would make the VM unjoinable.
  name                = var.vm_name
  computer_name       = var.computer_name
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = var.vm_size
  # v6/v7 sizes are NVMe-only (no SCSI controller); Azure defaults to SCSI,
  # so they need the controller named. null keeps the Azure default for the
  # older SCSI sizes. The image must list NVMe in DiskControllerTypes (both
  # Windows Server 2022 Azure Edition and Windows 11 25H2 do).
  disk_controller_type  = can(regex("_v[67]$", var.vm_size)) ? "NVMe" : null
  admin_username        = var.admin_username
  admin_password        = random_password.admin.result
  network_interface_ids = [azurerm_network_interface.vm.id]
  tags                  = var.tags

  # Windows 11 Enterprise multitenant-hosting rights (M365 E5) - see header.
  license_type = "Windows_Client"

  # Trusted Launch: Secure Boot + vTPM. Windows 11 needs TPM 2.0 + Secure
  # Boot, and the compliance policy's health-attestation checks read them.
  secure_boot_enabled = true
  vtpm_enabled        = true

  os_disk {
    name                 = "osdisk-${var.vm_name}"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS" # cheapest; the lab is idle most of the time
  }

  source_image_reference {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "windows-11"
    sku       = var.image_sku
    version   = "latest"
  }

  # REQUIRED before the AADLoginForWindows extension: it authenticates the
  # Entra join with this identity (no cross-tenant support).
  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {} # managed storage account - serial console + screenshots

  lifecycle {
    # Local admin is break-glass only; if you rotate it, never put the
    # generated one back.
    ignore_changes = [admin_password]
  }
}

# -----------------------------------------------------------------------------
# Entra join (+ Intune auto-enrollment) via the Microsoft Entra login
# extension. Publisher/type/handler version as in Microsoft's documentation
# (Microsoft.Azure.ActiveDirectory / AADLoginForWindows / 1.0). Requires the
# VM to reach enterpriseregistration.windows.net, login.microsoftonline.com,
# pas.windows.net and the instance metadata service (default outbound allows).
# Troubleshoot on the VM: `dsregcmd /status` (AzureAdJoined : YES) and
# C:\WindowsAzure\Logs\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows\.
# -----------------------------------------------------------------------------
resource "azurerm_virtual_machine_extension" "aad_login" {
  name                       = "AADLoginForWindows"
  virtual_machine_id         = azurerm_windows_virtual_machine.vm.id
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADLoginForWindows"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  tags                       = var.tags

  # mdmId = Intune => the join also enrolls the device in Intune (needs the
  # MDM user scope human step). null = Entra join only.
  settings = var.enable_intune_enrollment ? jsonencode({ mdmId = local.intune_mdm_app_id }) : null
}

# -----------------------------------------------------------------------------
# Who may sign in (Entra RDP) - as local administrator. Owner/Contributor do
# NOT grant sign-in; one of the two VM login roles is required. Scoped to
# this VM only. CI's APPLY identity may create these assignments because
# envs/bootstrap lists this role (1c0163c0-47e6-4577-8991-ea5c82e286e4) in
# its ABAC-constrained delegable_role_ids.
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "vm_admin_login_user" {
  for_each = toset(var.admin_login_user_object_ids)

  scope                = azurerm_windows_virtual_machine.vm.id
  role_definition_name = "Virtual Machine Administrator Login"
  principal_id         = each.value
  principal_type       = "User"
}

resource "azurerm_role_assignment" "vm_admin_login_group" {
  for_each = var.admin_login_group_object_ids

  scope                = azurerm_windows_virtual_machine.vm.id
  role_definition_name = "Virtual Machine Administrator Login"
  principal_id         = each.value
  # Explicit type avoids a PrincipalNotFound race when the group was created
  # moments earlier in the same apply (replication delay).
  principal_type = "Group"
}

# Deallocate every evening - the single biggest lever on the lab budget.
resource "azurerm_dev_test_global_vm_shutdown_schedule" "vm" {
  virtual_machine_id    = azurerm_windows_virtual_machine.vm.id
  location              = var.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone
  tags                  = var.tags

  notification_settings {
    enabled = false
  }
}
