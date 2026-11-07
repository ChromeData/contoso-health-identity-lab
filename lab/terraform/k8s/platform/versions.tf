# =============================================================================
# k8s/platform :: versions.tf
# -----------------------------------------------------------------------------
# Stage 1 of 2 for the Kubernetes workload-identity segment (stage 2 is
# ../identity). This root builds what has to exist BEFORE Vault can be
# configured: the two namespaces (with Pod Security Admission labels) and the
# Vault Helm release (dev-mode server + Agent Injector) on the local kind
# cluster contoso-k8s. See README.md for why there are two stages.
#
# STAND-IN: kind stands in for AKS, and in-cluster Vault stands in for
# Azure Key Vault via Entra Workload ID (ADR 0027) - lab/docs/STAND-INS.md.
#
# PROVIDERS (checked on the GitHub releases pages, 2026-10-19):
#   hashicorp/helm       ~> 3.3.0  (3.3.0 released 2026-09-02)
#   hashicorp/kubernetes ~> 3.3.0  (3.3.0 released 2026-10-01; 3.4.0 came out
#                                   on 2026-10-19 and is deliberately NOT
#                                   allowed until it has aged two weeks)
# The pessimistic "~> 3.3.0" admits 3.3.x patches only. The committed
# .terraform.lock.hcl pins the exact build and its hashes for linux_amd64 (CI)
# and darwin_arm64 (the dev Mac).
#
# TERRAFORM >= 1.11: the Vault dev root token reaches Helm through a
# write-only attribute (helm_release.set_wo) fed by an ephemeral variable, so
# it is never written to a plan file or to state. Write-only attributes need
# Terraform 1.11+ (ephemeral input variables need 1.10+).
#
# STATE: no backend block, so state is LOCAL and lives exactly as long as the
# kind cluster it describes (lab/k8s/ci/pipeline.sh destroys both). It holds
# no secret: the root token is write-only (see main.tf).
# =============================================================================

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.3.0"
    }
  }
}
