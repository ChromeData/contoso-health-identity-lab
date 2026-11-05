# =============================================================================
# envs/operator :: providers.tf
# -----------------------------------------------------------------------------
# Applied LOCALLY, never by CI. First apply: a human Global Administrator.
# Since 2026-11-05, by the owner's standing approval (ADR 0024), later
# changes may be applied by the operator itself (`op tofu apply`) after the
# pull request is reviewed and merged - the same review every other change gets.
# =============================================================================

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  features {}
}
