# =============================================================================
# envs/operator :: providers.tf
# -----------------------------------------------------------------------------
# Applied LOCALLY, never by CI, and only by the OWNER signed in as himself
# (ADR 0030, 2026-11-06). The 2026-11-05 amendment to ADR 0024 that let the
# operator apply its own grants is retired: an identity must not approve or
# apply changes to its own permissions. Without Owner the operator also
# cannot: this root writes Azure role assignments.
# =============================================================================

provider "azuread" {
  tenant_id = var.tenant_id
}

provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  features {}
}
