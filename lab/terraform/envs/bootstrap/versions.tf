# =============================================================================
# envs/bootstrap :: versions.tf
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.13"
    }
  }
}
