# =============================================================================
# envs/bootstrap :: backend.tf
# -----------------------------------------------------------------------------
# Same versioned storage account as envs/dev, but a SEPARATE container with no
# CI role assignment. The CI identities get roles on the `tfstate` container
# (envs/dev) only - never here: APPLY Storage Blob Data Contributor, PLAN
# Storage Blob Data Reader. That holds only because the account has
# AllowSharedKeyAccess=false and a ReadOnly lock that CI's subscription
# Contributor cannot remove (README "Remote-state bootstrap"); without them
# Contributor's listKeys reaches every container.
#
# Pass the real storage account name at init:
#   terraform init -backend-config="storage_account_name=<your-unique-sa>"
# =============================================================================

terraform {
  backend "azurerm" {
    resource_group_name  = "rg-identity-lab-tfstate"
    storage_account_name = "stidlabtfstate" # must be globally unique; override at init
    container_name       = "tfstate-bootstrap"
    key                  = "entra-identity-lab/bootstrap.terraform.tfstate"
    use_azuread_auth     = true
  }
}
