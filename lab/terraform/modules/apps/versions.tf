# =============================================================================
# modules/apps :: versions.tf
# -----------------------------------------------------------------------------
# Child module: declares the provider it consumes, never its configuration
# (that is inherited from envs/dev, like every other module here).
#
# Only azuread. Nothing in this module needs random/time/tls: app role and
# scope ids are fixed GUIDs (they must never change once tokens carry them),
# and the SAML signing certificate is minted by Entra itself
# (addTokenSigningCertificate), so no private key ever exists in Terraform.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }
  }
}
