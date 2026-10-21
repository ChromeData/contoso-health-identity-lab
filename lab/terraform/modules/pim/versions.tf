# =============================================================================
# modules/pim :: versions.tf
# -----------------------------------------------------------------------------
# azurerm is needed only by azure.tf (PIM for Azure resources). The root's
# provider configuration is inherited; with enable_pim_azure_resources = false
# no azurerm resource is planned.
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
      version = "~> 4.0"
    }
  }
}
