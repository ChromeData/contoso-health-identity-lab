# =============================================================================
# envs/dev :: providers.tf
# -----------------------------------------------------------------------------
# Provider configuration. Authentication is supplied by the environment
# (az login, a service principal, or the GitHub OIDC identities from
# modules/pipeline-identity) - NEVER hardcode credentials here.
#
# `tofu/terraform validate` does not contact Azure, so empty auth is fine for
# validation. `plan`/`apply` require real credentials + subscription_id.
# =============================================================================

provider "azuread" {
  # tenant_id is read from ARM_TENANT_ID / AZURE_TENANT_ID or `az login`.
  # Set explicitly only if you target a non-default tenant:
  tenant_id = var.tenant_id != "" ? var.tenant_id : null
}

provider "azurerm" {
  # azurerm v4 REQUIRES a subscription id at plan/apply time. Supply it via
  # var.subscription_id or the ARM_SUBSCRIPTION_ID environment variable.
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
  tenant_id       = var.tenant_id != "" ? var.tenant_id : null

  # The PLAN identity is Reader-only, so the provider must not try to
  # register resource providers on every run (that needs write). Providers
  # are registered once during bootstrap (az provider register).
  resource_provider_registrations = "none"

  # Provider-wide behaviour toggles.
  features {
    # modules/evidence-store disables Shared Key (Entra auth only). With the
    # default (true) the provider reads queue / static-website properties
    # over the storage DATA PLANE with an account key, which then fails - and
    # CI runners sit outside the store's firewall anyway. false keeps every
    # azurerm_storage_* read on Resource Manager, which the Reader-only PLAN
    # identity can do. No other storage account lives in this root.
    # verify: first real plan/apply of enable_evidence_store (read from the
    # azurerm 4.81.0 source, not yet proven against Azure).
    storage {
      data_plane_available = false
    }
  }
}

provider "random" {}
