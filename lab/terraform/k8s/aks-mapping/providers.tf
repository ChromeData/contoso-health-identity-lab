# =============================================================================
# k8s/aks-mapping :: providers.tf
# -----------------------------------------------------------------------------
# Deliberately empty. `terraform validate` and the mocked `terraform test`
# never configure the provider, so neither needs a tenant. A real `plan`
# would sign in from the environment (ARM_TENANT_ID + an OIDC/managed
# identity login in CI, or `az login` locally), exactly like envs/dev; nothing
# in this lab runs one, and no credential belongs in this file.
# =============================================================================

provider "azuread" {}
