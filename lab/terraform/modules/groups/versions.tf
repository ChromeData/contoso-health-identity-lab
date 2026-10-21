# =============================================================================
# modules/groups :: versions.tf
# -----------------------------------------------------------------------------
# Child modules declare the providers they consume (but NOT provider config).
# Provider configuration is inherited from the root module (envs/dev).
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    # Microsoft Graph (Entra ID) is driven through the azuread provider.
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }

    # Used only to generate strong initial passwords for the cloud-only
    # break-glass accounts. The custodian rotates them out-of-band after
    # apply (FIDO2 passkeys + rotated, vaulted password - README human step 6);
    # state is the only place they exist.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
