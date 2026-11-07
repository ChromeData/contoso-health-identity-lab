# =============================================================================
# k8s/keyvault-trust :: versions.tf
# -----------------------------------------------------------------------------
# APPLIED BY THE PIPELINE, ONE RUN AT A TIME. This root is the Entra and Key
# Vault side of the nightly-report workload's identity (README.md). It used
# to be "aks-mapping", plan-only. Since Vault was replaced by Azure Key Vault
# (ADR 0027), the kind cluster publishes its issuer on a public HTTPS URL, so
# the same federated credential is now applied and used for real.
#
# PROVIDERS: the same constraints and locked builds as the rest of the lab
# (lab/terraform/envs/dev): hashicorp/azuread "~> 3.10" (3.10.0) and
# hashicorp/azurerm "~> 4.0" (4.81.0), hashes for linux_amd64 (CI) and
# darwin_arm64 (the dev Mac):
#   terraform providers lock -platform=linux_amd64 -platform=darwin_arm64
#
# STATE: no backend block, so state is LOCAL and lives exactly as long as the
# run (the pipeline destroys it with the cluster). It holds identifiers only:
# no client secret exists, and no secret value passes through this root.
# =============================================================================

terraform {
  required_version = ">= 1.11.0"

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
