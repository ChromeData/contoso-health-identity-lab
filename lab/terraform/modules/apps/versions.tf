# =============================================================================
# modules/apps :: versions.tf
# -----------------------------------------------------------------------------
# Child module: declares the provider it consumes, never its configuration
# (that is inherited from envs/dev, like every other module here).
#
# azuread, plus hashicorp/time for two time_sleep waits (servicenow_fulfilment.tf,
# clinic_results.tf): a new SP must replicate before it is used elsewhere.
# Nothing else needs random/time/tls: app role and
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
    # time_sleep only: the ServiceNow fulfilment SP must replicate to
    # entitlement management before its catalog role is assigned
    # (servicenow_fulfilment.tf).
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}
