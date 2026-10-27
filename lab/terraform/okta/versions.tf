# =============================================================================
# okta :: versions.tf
# -----------------------------------------------------------------------------
# Separately-applied root for the Okta side of the Okta -> Entra coexistence
# (lab/docs/okta-migration-runbook.md Phase 1, ADR 0022). The target is an
# Okta Integrator Free org: the real product on its free plan, standing in
# for the acquired clinic's enterprise Okta tenant (lab/docs/STAND-INS.md).
# See README.md for why it is NOT part of envs/dev or the pipeline.
#
# PROVIDER: okta/okta 4.x. Validated and mock-tested against 4.20.0 (the
# version the committed lock file pins; current on the Terraform registry on
# 2026-10-26). Every resource and data source used here is in the 4.20
# provider schema (checked with `terraform providers schema -json`).
#
# TERRAFORM >= 1.8: the tests use issensitive() to prove the client secret
# stays sensitive end to end (1.8 added the function). CI pins 1.16.5.
#
# STATE: deliberately NO backend block, so state is LOCAL (terraform.tfstate
# in this directory, gitignored by lab/terraform/.gitignore). READ THIS: the
# Okta provider stores the IdP's client secret in state, so this root's
# state file holds the one secret of the coexistence. It is applied by one
# human from one laptop, the same laptop that would otherwise hold the
# secret in a browser session while typing it into the Okta console. Never
# copy the state anywhere a second person or CI can read it; [prod] uses a
# remote backend with encryption at rest and access limited to the IdP
# owners (README "Production option").
# =============================================================================

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
  }
}
