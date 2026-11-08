# =============================================================================
# modules/dc-vm :: main.tf
# -----------------------------------------------------------------------------
# The on-premises half of the hybrid story: one Windows Server VM that becomes
# the AD DS domain controller (+ AD CS for LDAPS) for corp.<domain>. HR
# provisions workers INTO this AD; Entra Cloud Sync carries them up to Entra.
#
#   * Subnet snet-identity in the lab VNet (same VNet as the Key Vault private
#     endpoint, so the DC reaches the vault privately)
#   * NSG: NO inbound allow rule from the internet (karen-review round 2,
#     R5; ADR 0013 amended 2026-11-08). RDP 3389 and LDAPS 636 from the
#     operator IP are gone: the laptop Vault (LDAPS) and Guacamole (RDP) they
#     served were retired for Key Vault and Azure Bastion (ADR 0036). Traffic
#     from inside the VNet still reaches the DC (NSG default AllowVnetInBound):
#     that is how Azure Bastion and the Tier 2 member server reach it.
#     The ONE exception is HTTPS 443, only while adfs_https_enabled (the
#     temporary AD FS exercise, lab/adfs), only from allowed_ip_ranges (/32).
#   * No public IP on the DC's NIC, except that same AD FS window
#     (azurerm_public_ip.adfs_https, count 0 by default).
#   * Outbound (Entra provisioning agent, Windows Update, activation,
#     Defender for Identity) goes through a NAT gateway on snet-identity
#     (nat_gateway_enabled, default true). A NAT gateway is outbound only:
#     nothing on the internet can open a connection through it
#     (learn.microsoft.com/azure/nat-gateway/nat-overview, "NAT Gateway
#     doesn't allow unsolicited inbound connections"). Why explicit egress:
#     for the Microsoft.Network API version released after 2026-03-31,
#     subnets in NEW virtual networks default to private (no default outbound
#     IP); a NAT gateway is an explicit method either way
#     (learn.microsoft.com/azure/virtual-network/ip-services/
#     default-outbound-access). snet-identity's
#     default_outbound_access_enabled stays unset (pinned in the test): the
#     NAT gateway takes precedence over default outbound access.
#   * How people and scripts reach the DC now (lab/scripts/dc/README.md,
#     "Ways in"): scripts use `az vm run-command` through the Azure control
#     plane (runs as SYSTEM, so it is a Tier-0 action and an activity-log
#     alert fires on it below); a person uses Azure Bastion, created on
#     demand (lab/bastion), from inside the VNet.
#   * Windows Server 2022 Azure Edition, smalldisk image, Standard HDD,
#     Trusted Launch (Secure Boot + vTPM)
#   * Separate data disk, host caching NONE, for NTDS/SYSVOL (Microsoft's
#     guidance for DCs on Azure - write-back caching can corrupt the AD DB)
#   * System-assigned identity with Key Vault Secrets Officer, so the build
#     scripts store the DSRM + service-account passwords straight into the
#     vault over the private endpoint - no human or pipeline ever sees them.
#     An ABAC condition limits it to those three secret names: the DC cannot
#     read or change any other secret's value in the vault
#   * Auto-shutdown (deallocate) every evening to keep the lab inside budget
#
# The VM is infrastructure only. Promotion to a DC is done by
# lab/scripts/dc/01-Install-ADDSForest.ps1 and 02-Configure-Domain.ps1 via
# `az vm run-command invoke` (see lab/scripts/dc/README.md) - promotion needs
# a reboot between phases, which Terraform extensions handle badly.
#
# COST (eastus2, approximate): ~$0.05-0.10/hr running (B2s + Windows),
# deallocated ~ $2 disks per month. The NAT gateway bills whether the DC runs
# or not: ~$0.045/hr (~$33/month, ~$1.10/day) plus its Standard public IP
# ($3.65/month) plus $0.045/GB processed (azure.microsoft.com/pricing/details/
# azure-nat-gateway). Under the program's $5/day line; it goes away with
# enable_dc = false.
# =============================================================================

# -----------------------------------------------------------------------------
# Network.
# -----------------------------------------------------------------------------
resource "azurerm_subnet" "dc" {
  name                 = "snet-identity"
  resource_group_name  = var.resource_group_name
  virtual_network_name = var.vnet_name
  address_prefixes     = var.subnet_prefix
}

resource "azurerm_network_security_group" "dc" {
  name                = "nsg-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  # No inbound allow rule from the internet (R5). Everything not listed is
  # denied by the NSG defaults, except traffic from inside the VNet
  # (AllowVnetInBound), which is how Azure Bastion reaches the DC.
  # HTTPS (443) only while adfs_https_enabled: the TEMPORARY lab AD FS on
  # DC01 (lab/adfs), so the operator's test browser can sign in to it. Same
  # /32 allowlist; switch it off again when AD FS is decommissioned. RDP and
  # LDAPS are never opened to the internet any more, whatever the flags.
  # ATTRIBUTE syntax, not a dynamic block (Greptile on #272, P1):
  # security_rule is Optional + Computed in azurerm, so ZERO dynamic blocks
  # means "keep whatever rules exist" and the live RDP/LDAPS rules would
  # stay. An explicit list, empty when the window is closed, makes Terraform
  # remove them (azurerm r/network_security_group docs: "security_rule = []"
  # removes all inline rules). Attribute syntax needs every field of the
  # object, hence the empty lists and the description.
  security_rule = local.adfs_window ? [{
    name                                       = "allow-adfs-https-operator"
    description                                = "AD FS exercise only (adfs_https_enabled): HTTPS 443 from the operator /32 (ADR 0013 amendment 2026-11-08)."
    priority                                   = 120
    direction                                  = "Inbound"
    access                                     = "Allow"
    protocol                                   = "Tcp"
    source_port_range                          = "*"
    source_port_ranges                         = []
    destination_port_range                     = "443"
    destination_port_ranges                    = []
    source_address_prefix                      = null
    source_address_prefixes                    = var.allowed_ip_ranges
    source_application_security_group_ids      = []
    destination_address_prefix                 = var.private_ip
    destination_address_prefixes               = []
    destination_application_security_group_ids = []
  }] : []
}

locals {
  # The only reason the DC ever gets a public listener: the AD FS exercise,
  # and only with a /32 to admit. Flag on with an empty list = nothing.
  adfs_window = var.adfs_https_enabled && length(var.allowed_ip_ranges) > 0
}

resource "azurerm_subnet_network_security_group_association" "dc" {
  subnet_id                 = azurerm_subnet.dc.id
  network_security_group_id = azurerm_network_security_group.dc.id
}

# Outbound only. The DC's own public IP (pip-vm-dc01) is removed (R5).
resource "azurerm_public_ip" "nat" {
  count               = var.nat_gateway_enabled ? 1 : 0
  name                = "pip-natgw-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_nat_gateway" "dc" {
  count                   = var.nat_gateway_enabled ? 1 : 0
  name                    = "natgw-${var.vm_name}"
  location                = var.location
  resource_group_name     = var.resource_group_name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 4
  tags                    = var.tags
}

resource "azurerm_nat_gateway_public_ip_association" "dc" {
  count                = var.nat_gateway_enabled ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.dc[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "dc" {
  count          = var.nat_gateway_enabled ? 1 : 0
  subnet_id      = azurerm_subnet.dc.id
  nat_gateway_id = azurerm_nat_gateway.dc[0].id
}

# The AD FS window only (see local.adfs_window). Count 0 by default, so the
# NIC has no public address at all.
resource "azurerm_public_ip" "adfs_https" {
  count               = local.adfs_window ? 1 : 0
  name                = "pip-${var.vm_name}-adfs"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "dc" {
  #checkov:skip=CKV2_AZURE_39:Public IP only during the time-boxed AD FS exercise (adfs_https_enabled, 443 from one /32); boot diagnostics keep the serial console for a DC with no other console path.
  #checkov:skip=CKV_AZURE_119:The NIC has a public IP only during the time-boxed AD FS exercise (adfs_https_enabled, 443 from one /32; ADR 0013 amendment 2026-11-08). By default it has none.
  name                = "nic-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.dc.id
    private_ip_address_allocation = "Static" # a DC's address must never change
    private_ip_address            = var.private_ip
    public_ip_address_id          = one(azurerm_public_ip.adfs_https[*].id)
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

resource "azurerm_windows_virtual_machine" "dc" {
  #checkov:skip=CKV_AZURE_151:Encryption at host needs the EncryptionAtHost feature registered on the subscription; the lab DC's disks use platform-managed server-side encryption (lab/terraform/README.md, Checkov baseline).
  #checkov:skip=CKV_AZURE_50:The forest is built with az vm run-command (lab/scripts/dc/README.md), which runs through the VM agent's extension path; extensions stay allowed.
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
  network_interface_ids = [azurerm_network_interface.dc.id]
  tags                  = var.tags

  # Trusted Launch: Secure Boot + vTPM (Gen2 Azure Edition image).
  secure_boot_enabled = true
  vtpm_enabled        = true

  os_disk {
    name                 = "osdisk-${var.vm_name}"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS" # cheapest; the lab is idle most of the time
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition-smalldisk"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {} # managed storage account - serial console + screenshots

  lifecycle {
    # The password is rotated after first sign-in (and becomes the domain
    # Administrator's); never let a plan try to put the generated one back.
    ignore_changes = [admin_password]
  }
}

# NTDS / SYSVOL data disk - host caching MUST be None for a domain controller.
resource "azurerm_managed_disk" "ntds" {
  #checkov:skip=CKV_AZURE_93:Platform-managed keys by design in the lab; a customer-managed key adds a Key Vault key whose loss makes the DC's NTDS disk unreadable (same trade-off as the evidence store).
  name                 = "datadisk-${var.vm_name}-ntds"
  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = var.ntds_disk_size_gb
  tags                 = var.tags

  # The directory database is never exported or uploaded through a SAS URL:
  # no public network path and no export at all (Checkov CKV_AZURE_251).
  # verify: at apply, `az disk show --query "{pna:publicNetworkAccess, nap:networkAccessPolicy}"`.
  public_network_access_enabled = false
  network_access_policy         = "DenyAll"
}

resource "azurerm_virtual_machine_data_disk_attachment" "ntds" {
  managed_disk_id    = azurerm_managed_disk.ntds.id
  virtual_machine_id = azurerm_windows_virtual_machine.dc.id
  lun                = 0
  caching            = "None"
}

# Deallocate every evening - the single biggest lever on the lab budget.
resource "azurerm_dev_test_global_vm_shutdown_schedule" "dc" {
  virtual_machine_id    = azurerm_windows_virtual_machine.dc.id
  location              = var.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone
  tags                  = var.tags

  notification_settings {
    enabled = false
  }
}

# The build scripts write the DSRM and service-account passwords straight
# into Key Vault using this identity (over the private endpoint).
#
# Unconditioned, Secrets Officer at vault scope lets anything with an IMDS
# token on the DC (local admin, malware, whoever owns the forest) read EVERY
# secret in the vault - an on-prem compromise would become a cloud one. The
# ABAC condition allows each secret data action only on the three names the
# scripts write (setSecret/restore match the requested name, the rest the
# existing secret's name); anything else is ForbiddenByRbac. Lowercase names
# only - Key Vault normalises them. ARM control-plane reads (secret NAMES,
# never values) are not data actions and stay readable.
# verify: Key Vault ABAC is preview (learn.microsoft.com/azure/key-vault/general/rbac-abac).
# If the condition is rejected, the apply fails - it never silently widens.
locals {
  # svc-pam-discovery was the third name until 2026-11-07: the read-only
  # discovery bind for the Vault stand-in, retired with it (ADR 0036). Its
  # account and secret were deleted on DC01 by Remove-PamDiscoveryAccount.ps1
  # BEFORE this change, while the DC still had the right to delete the secret.
  dc_kv_secret_names = ["dc01-dsrm-password", "svc-vault-rotator"]

  dc_kv_request_name  = join(" OR ", [for n in local.dc_kv_secret_names : "@Request[Microsoft.KeyVault/vaults/secrets:name] StringEquals '${n}'"])
  dc_kv_resource_name = join(" OR ", [for n in local.dc_kv_secret_names : "@Resource[Microsoft.KeyVault/vaults/secrets:name] StringEquals '${n}'"])

  dc_kv_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/setSecret/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/restore/action'})
     )
     OR
     (
      ${local.dc_kv_request_name}
     )
    )
    AND
    (
     (
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/readMetadata/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/update/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/delete'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/backup/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/recover/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/purge/action'})
     )
     OR
     (
      ${local.dc_kv_resource_name}
     )
    )
  EOT
}

# CHANGING THE CONDITION REPLACES THIS ASSIGNMENT (delete, then create).
# azurerm marks `condition` ForceNew (provider 4.81 source), so a narrower name
# list is a replace, not an update. Measured on a throwaway resource group,
# 2026-11-08, as the lab operator:
#   * create_before_destroy does NOT help: Azure refuses a second assignment
#     with the same principal, role and scope whatever its condition
#     (409 RoleAssignmentExists), so the apply would fail. Do not add it.
#   * ARM itself CAN update a condition in place (a PUT to the same assignment
#     name changed it, createdOn kept). Only an azapi_update_resource could use
#     that; the lab does not carry the azapi provider for this one change.
# Impact of the replace: for the seconds between delete and create, DC01 cannot
# write, read or delete its own build secrets. Nothing on DC01 uses Key Vault
# continuously: only 02-Configure-Domain.ps1 and the run-command scripts do,
# by hand. Apply while none of them runs (DC01 is deallocated most of the time).
resource "azurerm_role_assignment" "dc_kv_secrets_officer" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_windows_virtual_machine.dc.identity[0].principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.dc_kv_condition
}

# -----------------------------------------------------------------------------
# Run Command on the DC is a Tier-0 action (karen-review round 2, R5): it runs
# as SYSTEM on a domain controller, outside Bastion and its recording. Azure
# writes every call to the subscription activity log; this alert fires on each
# one (classic run-command action and managed runCommands writes). Free: an
# activity log alert has no per-rule charge. With no action group it shows in
# Azure Monitor > Alerts only; pass run_command_alert_action_group_ids to mail.
# Operation names: learn.microsoft.com/azure/role-based-access-control/
# permissions/compute (checked 2026-11-08).
# -----------------------------------------------------------------------------
resource "azurerm_monitor_activity_log_alert" "dc_run_command" {
  for_each = var.run_command_alert_enabled ? {
    invoke  = "Microsoft.Compute/virtualMachines/runCommand/action"
    managed = "Microsoft.Compute/virtualMachines/runCommands/write"
  } : {}

  name                = "ala-${var.vm_name}-runcommand-${each.key}"
  resource_group_name = var.resource_group_name
  location            = "global"
  scopes              = [azurerm_windows_virtual_machine.dc.id]
  description         = "Tier-0 action: Run Command (${each.value}) on domain controller ${var.vm_name}. Runs as SYSTEM outside Bastion. Check it matches a capture-log row."
  tags                = var.tags

  criteria {
    category       = "Administrative"
    operation_name = each.value
  }

  dynamic "action" {
    for_each = toset(var.run_command_alert_action_group_ids)
    content {
      action_group_id = action.value
    }
  }
}
