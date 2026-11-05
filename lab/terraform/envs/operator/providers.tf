# =============================================================================
# envs/operator :: providers.tf
# -----------------------------------------------------------------------------
# Applied LOCALLY by a human Global Administrator (`az login` as the admin),
# never by CI and never by the operator identity this root creates.
# =============================================================================

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  features {}
}
