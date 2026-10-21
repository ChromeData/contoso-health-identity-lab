# =============================================================================
# modules/monitoring :: versions.tf
# =============================================================================

terraform {
  # 1.9+: variables.tf validates enable_itdr_containment against other
  # variables (cross-variable validation). CI pins Terraform 1.16.5
  # (setup-terraform in the workflows); the lock files pin the providers.
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}
