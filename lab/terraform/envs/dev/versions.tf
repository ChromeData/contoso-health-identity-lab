# =============================================================================
# envs/dev :: versions.tf
# -----------------------------------------------------------------------------
# Root module: pins Terraform + every provider used across the composition.
# Child modules inherit these providers (they declare required_providers but
# NOT configuration).
# =============================================================================

terraform {
  # >= 1.9: modules/monitoring uses cross-variable validation
  # (enable_itdr_containment checks enable_sentinel). CI pins 1.16.5.
  required_version = ">= 1.9.0"

  required_providers {
    # Microsoft Graph / Entra ID.
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }

    # Azure Resource Manager (Key Vault, networking, Log Analytics).
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.11"
    }

    # Initial password generation for lab/break-glass accounts.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
