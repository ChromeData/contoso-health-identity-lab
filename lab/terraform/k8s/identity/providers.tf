# =============================================================================
# k8s/identity :: providers.tf
# -----------------------------------------------------------------------------
# VAULT: talks to the dev-mode server through kind's port mapping
# (http://127.0.0.1:18200 -> NodePort 30820). The token is the per-run dev
# root token the pipeline generated for ../platform; it is an EPHEMERAL
# variable, which Terraform allows in provider configuration and never writes
# to a plan file or to state.
#
# The provider does not use that root token directly for its work: by default
# (skip_child_token = false) it mints a child token of the given one, with
# its TTL capped here at 10 minutes, each time the provider is configured
# (once for `apply`, once again for `destroy`), and does that command's work
# with the child token (verify: whether the provider also revokes the child
# token at exit, rather than letting it expire, is not relied on here). The
# pipeline also uses the root token directly, outside Terraform: one
# auth/token/lookup-self after stage 1, and the write that seeds
# clinical/data/db in stage 7. In production the root token
# would not exist at all after setup; Terraform would log in through an auth
# method (for example JWT/OIDC from the CI runner) and get the same kind of
# short-lived token.
#
# KUBERNETES: same pinned file + context as ../platform. See that root's
# providers.tf for why config_context is pinned and why KUBECONFIG is passed
# as TF_VAR_kubeconfig_path.
#
# `terraform validate` and the mocked `terraform test` never configure either
# provider, so neither needs Vault or a cluster.
# =============================================================================

provider "vault" {
  address = var.vault_addr
  token   = var.vault_dev_root_token

  # Lifetime of the provider's own child token (seconds). A full stage-2 apply
  # takes well under a minute.
  max_lease_ttl_seconds = 600
}

provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}
