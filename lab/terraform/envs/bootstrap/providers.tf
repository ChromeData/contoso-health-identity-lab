# =============================================================================
# envs/bootstrap :: providers.tf
# -----------------------------------------------------------------------------
# Applied LOCALLY by a human admin (`az login` as admin@<tenant>), never by CI.
# =============================================================================

provider "azuread" {
  tenant_id = var.tenant_id != "" ? var.tenant_id : null
}

provider "azurerm" {
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
  tenant_id       = var.tenant_id != "" ? var.tenant_id : null

  features {}
}
