# =============================================================================
# k8s/identity :: versions.tf
# -----------------------------------------------------------------------------
# Stage 2 of 2 for the Kubernetes workload-identity segment. Applied AFTER
# ../platform, because the Vault provider configures itself against a running
# Vault (it reads the server version when it starts) - which only exists once
# stage 1 has installed it. See README.md "Why two stages".
#
# What this root owns: the Vault side of workload identity (KV v2 mount,
# read-only policy, Kubernetes auth method + the one role that binds the
# nightly-report service account), the two Kubernetes service accounts, the
# human RBAC (two namespaced Roles bound to groups), and the
# ValidatingAdmissionPolicy that decides who may run what as nightly-report.
# The secret VALUE is not here: the pipeline seeds it, so it never enters
# Terraform state.
#
# STAND-IN: Vault Kubernetes auth stands in for Entra Workload ID + Azure
# Key Vault on AKS (ADR 0036); the impersonated groups stand in
# for Entra groups surfaced through AKS Entra integration.
# lab/docs/STAND-INS.md has the on-camera lines.
#
# PROVIDERS (checked on the GitHub releases pages, 2026-10-19):
#   hashicorp/vault      ~> 5.12.0 (5.12.0 released 2026-09-17; 5.13.0 from
#                                   2026-10-14 is NOT allowed yet - under two
#                                   weeks old)
#   hashicorp/kubernetes ~> 3.3.0  (3.3.0 released 2026-10-01; NOT 3.4.0,
#                                   released 2026-10-19)
# The committed .terraform.lock.hcl pins the exact builds and hashes for
# linux_amd64 (CI) and darwin_arm64 (the dev Mac).
#
# TERRAFORM >= 1.11: same floor as ../platform (ephemeral input variable for
# the Vault token; 1.10+ would do here, 1.11 keeps the two roots identical).
#
# STATE: local, no backend - it lives exactly as long as the kind cluster.
# It holds no secret value: the KV secret is seeded outside Terraform and the
# Vault token is an ephemeral variable used only in the provider block.
# =============================================================================

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.12.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.3.0"
    }
  }
}
