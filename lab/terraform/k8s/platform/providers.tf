# =============================================================================
# k8s/platform :: providers.tf
# -----------------------------------------------------------------------------
# Both providers read the SAME kubeconfig file and are pinned to the SAME named
# context. Pinning config_context (instead of trusting whatever
# `kubectl config current-context` happens to be) is the Kubernetes version of
# the AWS root's allowed_account_ids guard: this root installs a dev-mode
# Vault with a root token, and it must never land on a real cluster just
# because someone's current context pointed at one. variables.tf additionally
# refuses any context that is not a kind context.
#
# NO CREDENTIALS HERE: kind writes a client certificate for its cluster-admin
# user into the kubeconfig when the cluster is created. That file stays on the
# machine (or CI runner) that created the cluster and dies with it.
#
# KUBECONFIG: the Terraform Kubernetes and Helm providers do NOT read the
# KUBECONFIG environment variable, so the pipeline passes
# TF_VAR_kubeconfig_path when KUBECONFIG is set (default: ~/.kube/config).
#
# `terraform validate` and the mocked `terraform test` never configure these
# providers, so neither needs a running cluster.
# =============================================================================

provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}

provider "helm" {
  # Helm provider 3.x: `kubernetes` is an attribute (object), not a block.
  kubernetes = {
    config_path    = pathexpand(var.kubeconfig_path)
    config_context = var.kube_context
  }
}
