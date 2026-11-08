# =============================================================================
# k8s/identity :: providers.tf
# -----------------------------------------------------------------------------
# KUBERNETES only: same pinned file + context as ../platform. See that root's
# providers.tf for why config_context is pinned and why KUBECONFIG is passed
# as TF_VAR_kubeconfig_path. Nothing here talks to Azure: the Key Vault and
# Entra objects are ../keyvault-trust's.
#
# `terraform validate` and the mocked `terraform test` never configure the
# provider, so neither needs a cluster.
# =============================================================================

provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}
