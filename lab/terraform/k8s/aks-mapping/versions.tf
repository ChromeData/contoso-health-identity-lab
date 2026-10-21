# =============================================================================
# k8s/aks-mapping :: versions.tf
# -----------------------------------------------------------------------------
# PLAN-ONLY, NEVER APPLIED IN THIS LAB. This root is the Entra side of the
# same trust the lab builds with Vault: Microsoft Entra Workload ID's
# federated identity credential for the nightly-report service account.
# It exists so the mapping is real, typed, tested code instead of a slide.
# Why it is never applied here: README.md ("Why it is never applied").
#
# PROVIDER: hashicorp/azuread "~> 3.10", the same constraint as the rest of
# the lab (lab/terraform/envs/dev/versions.tf, modules/pipeline-identity).
# The committed .terraform.lock.hcl pins 3.10.0 (the version the lab's other
# Entra roots lock) for linux_amd64 (CI) and darwin_arm64 (the dev Mac):
#   terraform providers lock -platform=linux_amd64 -platform=darwin_arm64
#
# TERRAFORM >= 1.11.0: nothing here needs more than 1.7 (mock_provider in the
# tests); the floor is kept identical to ../platform and ../identity so the
# segment has one minimum version.
#
# NO BACKEND: there is no state worth keeping, because nothing is applied.
# =============================================================================

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }
  }
}
