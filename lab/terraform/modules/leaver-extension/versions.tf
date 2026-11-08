# =============================================================================
# modules/leaver-extension :: versions.tf
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }
    # time_sleep only: the managed identity must replicate to entitlement
    # management before its catalog role is assigned (main.tf).
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}
