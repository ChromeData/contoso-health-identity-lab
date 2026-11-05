# =============================================================================
# envs/operator :: backend.tf
# -----------------------------------------------------------------------------
# Same container as envs/bootstrap (no CI role on it), its own key. Pass the
# real storage account name at init:
#   tofu init -backend-config="storage_account_name=<your-unique-sa>"
# =============================================================================

terraform {
  backend "azurerm" {
    resource_group_name  = "rg-identity-lab-tfstate"
    storage_account_name = "stidlabtfstate" # must be globally unique; override at init
    container_name       = "tfstate-bootstrap"
    key                  = "entra-identity-lab/operator.terraform.tfstate"
    use_azuread_auth     = true
  }
}
