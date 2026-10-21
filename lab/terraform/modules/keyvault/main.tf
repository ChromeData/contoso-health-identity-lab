# =============================================================================
# modules/keyvault :: main.tf
# -----------------------------------------------------------------------------
# A hardened Key Vault for the IAM lab:
#   * RBAC data-plane authorization (NOT legacy access policies)
#   * Public network access DISABLED unless var.allowed_ip_ranges is set
#     (lab compromise: operator IP only - see variables.tf)
#   * Private endpoint + private DNS so the vault resolves privately
#   * User-assigned managed identity granted "Key Vault Secrets User"
#   * Audit logs streamed to Log Analytics (loga-idlab)
#
# LICENSING: none of this needs an Entra P1/P2 SKU - it is pure Azure RBAC +
# networking. Private endpoints + private DNS do incur normal Azure cost.
# =============================================================================

data "azurerm_client_config" "current" {}

locals {
  # Prefer an explicit tenant id; otherwise inherit from the current creds.
  tenant_id = var.tenant_id != "" ? var.tenant_id : data.azurerm_client_config.current.tenant_id
}

# -----------------------------------------------------------------------------
# Networking for the private endpoint.
# -----------------------------------------------------------------------------
resource "azurerm_virtual_network" "lab" {
  name                = var.vnet_name
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.vnet_address_space
  tags                = var.tags
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = var.private_endpoint_subnet_prefix
}

# -----------------------------------------------------------------------------
# The vault.
# -----------------------------------------------------------------------------
resource "azurerm_key_vault" "idlab" {
  name                = var.key_vault_name
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = local.tenant_id
  sku_name            = "standard"

  # ---- Hardening ----------------------------------------------------------
  # RBAC auth: permissions come from Azure role assignments, not per-vault
  # access policies. This is the modern, auditable model.
  # (azurerm 4.x name; was `enable_rbac_authorization`, removed in v5.0.)
  rbac_authorization_enabled = true

  # Production posture: no public data plane, PE only. The lab may admit the
  # operator's IP (var.allowed_ip_ranges) because there is no VNet-connected
  # workstation; the firewall below still denies everything else.
  #checkov:skip=CKV_AZURE_189:Public access is opened only to allowed_ip_ranges (operator IP) in the lab; empty list = disabled.
  public_network_access_enabled = length(var.allowed_ip_ranges) > 0

  # Soft delete is always on in current API versions; purge protection is the
  # toggle that stops a hard delete inside the retention window.
  purge_protection_enabled   = var.purge_protection_enabled
  soft_delete_retention_days = var.soft_delete_retention_days

  # Deny by default. With a private endpoint the data plane is reached through
  # the PE regardless of these ACLs; AzureServices bypass lets first-party
  # services (e.g. diagnostics) still function; ip_rules admits the operator.
  #
  # CI NOTE: GitHub-hosted runners are NOT in ip_rules. If a PR plan fails
  # refreshing this vault's data plane, that is the cause - verify on the first
  # pipeline run (azurerm 4.x should only need the management plane here).
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.allowed_ip_ranges
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# User-assigned managed identity + "Key Vault Secrets User" RBAC role, narrowed
# by an ABAC condition to the secret NAMES in var.uami_readable_secret_names.
# On its own, Secrets User at vault scope reads EVERY secret - and this vault
# also holds Tier-0 material (svc-vault-rotator, dc01-dsrm-password) and the
# playbook's Teams URL / ServiceNow password. The condition makes this the
# workload-least-privilege demo it is meant to be: the identity can read only
# its own secret(s); everything else is denied at the data plane.
# verify: Key Vault ABAC (learn.microsoft.com/azure/key-vault/general/rbac-abac);
# if the condition is rejected the apply fails - it never silently widens.
# -----------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "kv_reader" {
  name                = var.uami_name
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

locals {
  uami_secret_match = join(" OR ", [
    for n in var.uami_readable_secret_names :
    "@Resource[Microsoft.KeyVault/vaults/secrets:name] StringEquals '${n}'"
  ])

  uami_kv_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'})
      AND
      !(ActionMatches{'Microsoft.KeyVault/vaults/secrets/readMetadata/action'})
     )
     OR
     (
      ${local.uami_secret_match}
     )
    )
  EOT
}

resource "azurerm_role_assignment" "kv_secrets_user" {
  scope                = azurerm_key_vault.idlab.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.kv_reader.principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.uami_kv_condition
}

# Human custodians who store secrets (the operator's admin account). The
# break-glass password is NOT kept here (README human step 6): Tier-0 break-glass
# credentials stay offline / in a separate custody, never in a lab vault.
resource "azurerm_role_assignment" "kv_secrets_officer" {
  for_each = toset(var.secrets_officer_principal_ids)

  scope                = azurerm_key_vault.idlab.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = each.value
}

# -----------------------------------------------------------------------------
# Private DNS so "<vault>.vault.azure.net" resolves to the private endpoint.
# -----------------------------------------------------------------------------
resource "azurerm_private_dns_zone" "vault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "vault" {
  name                  = "link-${var.vnet_name}-vault"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.vault.name
  virtual_network_id    = azurerm_virtual_network.lab.id
  registration_enabled  = false
  tags                  = var.tags
}

# -----------------------------------------------------------------------------
# Private endpoint for the vault's "vault" sub-resource.
# -----------------------------------------------------------------------------
resource "azurerm_private_endpoint" "kv" {
  name                = "pe-${var.key_vault_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-${var.key_vault_name}"
    private_connection_resource_id = azurerm_key_vault.idlab.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "kv-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.vault.id]
  }
}

# -----------------------------------------------------------------------------
# Stream Key Vault audit logs to Log Analytics (loga-idlab). Always on: no
# `count`, because the root passes the id of a workspace created in the same
# apply, and a count derived from a not-yet-known id fails the first plan
# ("Invalid count argument"). The precondition rejects an empty id instead.
# -----------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "diag-${var.key_vault_name}"
  target_resource_id         = azurerm_key_vault.idlab.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category_group = "audit"
  }

  # Metrics stream (azurerm 4.x uses the `enabled_metric` block).
  enabled_metric {
    category = "AllMetrics"
  }

  lifecycle {
    precondition {
      condition     = var.log_analytics_workspace_id != ""
      error_message = "log_analytics_workspace_id is required: Key Vault audit logs must stream to loga-idlab."
    }
  }
}
