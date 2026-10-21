# =============================================================================
# modules/keyvault :: variables.tf
# =============================================================================

variable "key_vault_name" {
  type        = string
  description = <<-EOT
    Globally-unique Key Vault name (3-24 chars, alphanumeric + hyphens).
    Contract default is "kv-idlab" but the global namespace means you will
    likely need a suffix, e.g. "kv-idlab-7f3a".
  EOT
  default     = "kv-idlab"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.key_vault_name))
    error_message = "Key Vault name must be 3-24 chars, start with a letter, alphanumeric/hyphens only."
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group that holds the vault + networking (contract: rg-identity-lab)."
}

variable "location" {
  type        = string
  description = "Azure region (contract: eastus2)."
  default     = "eastus2"
}

variable "tenant_id" {
  type        = string
  description = <<-EOT
    Entra ID tenant id used for Key Vault data-plane auth. Leave empty to
    auto-detect from the current azurerm credentials (data.azurerm_client_config).
  EOT
  default     = ""
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource id of loga-idlab (required). Key Vault audit logs + AllMetrics always stream here."
}

variable "uami_name" {
  type        = string
  description = "Name of the user-assigned managed identity granted Key Vault Secrets User."
  default     = "id-kv-idlab-reader"
}

variable "vnet_name" {
  type        = string
  description = "Virtual network that hosts the Key Vault private endpoint subnet."
  default     = "vnet-identity-lab"
}

variable "vnet_address_space" {
  type        = list(string)
  description = "Address space for the lab VNet."
  default     = ["10.42.0.0/16"]
}

variable "private_endpoint_subnet_prefix" {
  type        = list(string)
  description = "Subnet CIDR dedicated to private endpoints."
  default     = ["10.42.1.0/24"]
}

variable "allowed_ip_ranges" {
  type        = list(string)
  description = <<-EOT
    Public IPv4 addresses/CIDRs allowed to reach the vault data plane (e.g. the
    operator's home IP as "203.0.113.7/32"). EMPTY = public network access is
    disabled entirely and the vault is reachable only through the private
    endpoint (production posture). A non-empty list is the lab compromise: the
    operator has no VNet-connected workstation, so the firewall admits only
    their IP; everything else is still denied.
  EOT
  default     = []

  validation {
    condition     = alltrue([for c in var.allowed_ip_ranges : can(cidrnetmask(c)) && try(tonumber(split("/", c)[1]) >= 24, false)])
    error_message = "Each entry must be an IPv4 CIDR no wider than /24, e.g. 203.0.113.7/32."
  }
}

variable "uami_readable_secret_names" {
  type        = list(string)
  description = <<-EOT
    The ONLY secret names the workload identity (UAMI) may read. Enforced by an
    ABAC condition on its Key Vault Secrets User assignment, so Tier-0 secrets
    in the same vault (svc-vault-rotator, dc01-dsrm-password) and the playbook
    secrets stay unreadable to it. Create the secret(s) yourself; the identity
    can read nothing else.
  EOT
  default     = ["demo-app-config"]

  validation {
    condition = length(var.uami_readable_secret_names) > 0 && alltrue([
      for n in var.uami_readable_secret_names : can(regex("^[0-9A-Za-z-]{1,127}$", n))
    ])
    error_message = "Provide at least one Key Vault secret name (1-127 chars: letters, digits, hyphens)."
  }
}

variable "secrets_officer_principal_ids" {
  type        = list(string)
  description = <<-EOT
    Object ids of HUMANS who may write secrets (Key Vault Secrets Officer).
    Keep this to the operator's admin account; workloads get Secrets User
    (read) only. The break-glass password is not stored in this vault
    (README human step 6).
  EOT
  default     = []
}

variable "soft_delete_retention_days" {
  type        = number
  description = "Key Vault soft-delete retention (7-90). 90 is the hardened default."
  default     = 90
}

variable "purge_protection_enabled" {
  type        = bool
  description = <<-EOT
    Purge protection blocks permanent deletion during the retention window.
    TRUE is correct for anything near production; kept as a toggle because a
    throwaway lab vault with purge protection cannot be fully removed for up
    to 90 days.
  EOT
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to every resource in this module."
  default = {
    project = "contoso-health-identity-lab"
    tier    = "security"
  }
}
