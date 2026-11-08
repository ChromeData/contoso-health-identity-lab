# =============================================================================
# modules/dc-vm :: main.tf
# -----------------------------------------------------------------------------
# The on-premises half of the hybrid story: one Windows Server VM that becomes
# the AD DS domain controller (+ AD CS for LDAPS) for corp.<domain>. HR
# provisions workers INTO this AD; Entra Cloud Sync carries them up to Entra.
#
#   * Subnet snet-identity in the lab VNet (same VNet as the Key Vault private
#     endpoint, so the DC reaches the vault privately)
#   * NSG: RDP + LDAPS from the operator's IP(s) ONLY - each a single IPv4
#     /32 (variables.tf rejects anything wider; ADR 0013); nothing else inbound
#   * Standard static public IP: operator access, and the DC's EXPLICIT
#     outbound method (the Entra provisioning agent, Windows Update and
#     activation need egress). Why explicit: for the Microsoft.Network API
#     version released after 2026-03-31, subnets in NEW virtual networks
#     default to defaultOutboundAccess = false (private subnets), so VMs in
#     them get no default outbound IP. Existing VNets, and deployments that
#     use an earlier API version, keep the old default. A public IP on the
#     NIC is an explicit method either way, so the DC never relies on
#     default outbound access (learn.microsoft.com/azure/virtual-network/
#     ip-services/default-outbound-access, checked 2026-10-20). This module
#     does not set default_outbound_access_enabled on snet-identity, so the
#     azurerm provider's own default applies: the r/subnet docs say
#     "Defaults to `true`" (checked 2026-10-20), i.e. snet-identity is sent as
#     a NON-private subnet and Azure's new private-by-default never applies
#     here. The public IP is the explicit egress either way; making the
#     subnet private (= false) is a separate design call (ADR 0013).
#     Production has no public IP: NAT gateway or Azure Firewall for egress,
#     Bastion + PAM broker for admin (ADR 0013)
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
# deallocated ~ $2 disks + $3.65 static IP per month.
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

  # RDP (operator + Guacamole recorded sessions) and LDAPS (Vault password
  # rotation) - from the operator's IP(s) only. Empty list = no inbound rules
  # at all; everything else is denied by the NSG defaults.
  # HTTPS (443) only while adfs_https_enabled: the TEMPORARY lab AD FS on
  # DC01 (lab/adfs), so the operator's test browser can sign in to it. Same
  # /32 allowlist; switch it off again when AD FS is decommissioned.
  dynamic "security_rule" {
    for_each = length(var.allowed_ip_ranges) > 0 ? merge(
      {
        rdp   = { priority = 100, port = "3389" }
        ldaps = { priority = 110, port = "636" }
      },
      var.adfs_https_enabled ? { adfs-https = { priority = 120, port = "443" } } : {},
    ) : {}
    content {
      name                       = "allow-${security_rule.key}-operator"
      priority                   = security_rule.value.priority
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = security_rule.value.port
      source_address_prefixes    = var.allowed_ip_ranges
      destination_address_prefix = var.private_ip
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "dc" {
  subnet_id                 = azurerm_subnet.dc.id
  network_security_group_id = azurerm_network_security_group.dc.id
}

resource "azurerm_public_ip" "dc" {
  name                = "pip-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "dc" {
  #checkov:skip=CKV_AZURE_119:The lab DC is reached over RDP from the operator IP only (NSG below); there is no Bastion or VPN in a one-person lab. Public IP is the documented stand-in (lab/docs/STAND-INS.md).
  name                = "nic-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.dc.id
    private_ip_address_allocation = "Static" # a DC's address must never change
    private_ip_address            = var.private_ip
    public_ip_address_id          = azurerm_public_ip.dc.id
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
  # svc-pam-discovery: the read-only discovery bind (02-Configure-Domain.ps1,
  # lab/pam/discover.sh) - a plain Domain User, but its password is still
  # generated on the DC and handed over only through the vault.
  dc_kv_secret_names = ["dc01-dsrm-password", "svc-vault-rotator", "svc-pam-discovery"]

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

resource "azurerm_role_assignment" "dc_kv_secrets_officer" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azurerm_windows_virtual_machine.dc.identity[0].principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.dc_kv_condition
}
