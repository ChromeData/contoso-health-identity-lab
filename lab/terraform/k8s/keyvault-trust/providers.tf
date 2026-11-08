# =============================================================================
# k8s/keyvault-trust :: providers.tf
# -----------------------------------------------------------------------------
# No credential here. The pipeline runs as the lab operator
# (lab/scripts/operator/op): both providers sign in through the operator's
# az CLI profile, and op exports ARM_SUBSCRIPTION_ID (azurerm 4 needs it).
# `terraform validate` and the mocked `terraform test` never configure the
# providers, so neither needs a tenant.
# =============================================================================

provider "azuread" {}

provider "azurerm" {
  features {}
  # The operator is not allowed to register resource providers; the lab
  # subscription already has Microsoft.KeyVault and Microsoft.Authorization.
  resource_provider_registrations = "none"
}
