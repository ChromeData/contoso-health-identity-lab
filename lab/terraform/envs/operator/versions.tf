# =============================================================================
# envs/operator :: versions.tf
# =============================================================================

terraform {
  required_version = ">= 1.9.0" # cross-variable validation (enable_operator_workload_ca) needs 1.9

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }

    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}
