# =============================================================================
# modules/intune-vm :: versions.tf
# -----------------------------------------------------------------------------
# Child modules declare the providers they consume (but NOT provider config).
# Provider configuration is inherited from the root module (envs/dev).
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }

    # Initial LOCAL admin password - the break-glass way into the VM if Entra
    # sign-in ever fails. Lives only in state; day-to-day sign-in is Entra.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
