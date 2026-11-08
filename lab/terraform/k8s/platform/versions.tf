# =============================================================================
# k8s/platform :: versions.tf
# -----------------------------------------------------------------------------
# Stage 1 of 2 for the Kubernetes workload-identity segment (stage 2 is
# ../identity). This root builds what has to exist BEFORE a workload can mount
# a Key Vault secret: the two namespaces (with Pod Security Admission labels)
# and the Secrets Store CSI Driver + Azure Key Vault provider Helm release on
# the local kind cluster contoso-k8s. See README.md for why there are two
# stages.
#
# STAND-IN: kind stands in for AKS (lab/docs/STAND-INS.md). Azure Key Vault,
# Microsoft Entra Workload ID and the Azure provider are the real products.
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
# TERRAFORM >= 1.11: kept from the Vault version (write-only arguments);
# the lab pins 1.16.5 everywhere, so nothing is gained by lowering it.
#
# STATE: no backend block, so state is LOCAL and lives exactly as long as the
# kind cluster it describes (lab/k8s/ci/pipeline.sh destroys both). It holds
# no secret: none is an input (see variables.tf).
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
      version = "~> 3.5.0"
    }
  }
}
