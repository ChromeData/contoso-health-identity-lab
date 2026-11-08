# =============================================================================
# k8s/identity :: versions.tf
# -----------------------------------------------------------------------------
# Stage 2 of 2 for the Kubernetes workload-identity segment. Applied AFTER
# ../platform, because the SecretProviderClass is a custom resource whose CRD
# the CSI driver chart installs (kubernetes_manifest needs the CRD at plan
# time). See README.md "Why two stages".
#
# What this root owns: the two Kubernetes service accounts, the
# SecretProviderClass for the one Key Vault secret, the human RBAC (two
# namespaced Roles bound to groups), and the ValidatingAdmissionPolicy that
# decides who may run what as nightly-report. The secret VALUE is not here:
# the pipeline sets it in Key Vault, so it never enters Terraform state.
#
# STAND-IN: the impersonated groups stand in for Entra groups surfaced
# through AKS Entra integration; kind stands in for AKS.
# lab/docs/STAND-INS.md has the on-camera lines.
#
# PROVIDER (checked on the GitHub releases page, 2026-10-19):
#   hashicorp/kubernetes ~> 3.3.0  (3.3.0 released 2026-10-01)
# The committed .terraform.lock.hcl pins the exact build and hashes for
# linux_amd64 (CI) and darwin_arm64 (the dev Mac).
#
# TERRAFORM >= 1.11: same floor as ../platform.
#
# STATE: local, no backend - it lives exactly as long as the kind cluster.
# It holds no secret value: Key Vault holds the value, and the
# SecretProviderClass holds identifiers only.
# =============================================================================

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.5.0"
    }
  }
}
