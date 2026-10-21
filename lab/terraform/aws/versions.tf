# =============================================================================
# aws :: versions.tf
# -----------------------------------------------------------------------------
# Separately-applied root for the AWS side of the Entra -> AWS IAM Identity
# Center integration. No stand-in: this targets the real AWS IAM Identity
# Center. See README.md for why it is NOT part of envs/dev or the pipeline.
#
# PROVIDER: hashicorp/aws 6.x (6.69.1 was current on the Terraform and
# OpenTofu registries on 2026-10-19). Every resource and data source used
# here is documented in the 6.x provider docs (see README "Sources").
#
# STATE: there is deliberately NO backend block, so state is LOCAL
# (terraform.tfstate in this directory, gitignored by lab/terraform/.gitignore).
# It holds no secrets - only ARNs, the Identity Store group id and the target
# account id - and this root is applied by one human from one laptop. The S3
# remote-state option for a team/CI setup is described (not built) in the
# README "Production option".
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
