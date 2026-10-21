# =============================================================================
# modules/dc-vm :: versions.tf
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }

    # Initial local-admin password (becomes the domain Administrator after
    # promotion). Lives only in state; rotate after first sign-in.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
