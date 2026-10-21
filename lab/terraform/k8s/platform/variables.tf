# =============================================================================
# k8s/platform :: variables.tf
# -----------------------------------------------------------------------------
# Only vault_dev_root_token is sensitive, and it has no default on purpose:
# lab/k8s/ci/pipeline.sh generates a fresh random one per run and exports it
# as TF_VAR_vault_dev_root_token. Nothing in the repo knows its value.
# Versions and names are NOT variables: they are pinned constants in main.tf
# (locals) so a reviewer sees them in one place and nobody can override a pin
# from the command line.
# =============================================================================

variable "kube_context" {
  type        = string
  description = <<-EOT
    kubeconfig context both providers are pinned to. kind names the context
    "kind-<cluster name>", so the lab cluster contoso-k8s is kind-contoso-k8s.
    Only kind contexts are accepted: this root installs a dev-mode Vault with
    a root token and must never be pointed at a real (AKS or other) cluster.
  EOT
  default     = "kind-contoso-k8s"

  validation {
    condition     = startswith(var.kube_context, "kind-")
    error_message = "kube_context must be a kind context (kind-<cluster>). This root deploys a dev-mode Vault and is lab-only."
  }
}

variable "kubeconfig_path" {
  type        = string
  description = <<-EOT
    Path to the kubeconfig file that holds kube_context (a leading ~ is
    expanded). The providers ignore the KUBECONFIG environment variable, so
    the pipeline sets TF_VAR_kubeconfig_path when KUBECONFIG is set. A single
    path only, not a colon-separated list.
  EOT
  default     = "~/.kube/config"

  validation {
    condition     = length(trimspace(var.kubeconfig_path)) > 0 && !strcontains(var.kubeconfig_path, ":")
    error_message = "kubeconfig_path must be one non-empty file path (not a colon-separated KUBECONFIG list)."
  }
}

variable "vault_dev_root_token" {
  type        = string
  description = <<-EOT
    Root token the dev-mode Vault server boots with (VAULT_DEV_ROOT_TOKEN_ID).
    Generated per run by lab/k8s/ci/pipeline.sh, never committed, never
    printed. EPHEMERAL + reaches Helm only through the write-only set_wo, so it
    is not stored in the plan or in state. At least 24 characters from
    [A-Za-z0-9._-]: long enough not to be guessable, and no commas, braces or
    quotes that Helm's --set parser would split or reinterpret. The chart's
    own default ("root") is rejected by that rule. On destroy the value is
    unused, but Terraform still requires one: any valid-format value works.
  EOT
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{24,}$", var.vault_dev_root_token))
    error_message = "vault_dev_root_token must be at least 24 characters from [A-Za-z0-9._-] (for example: openssl rand -hex 32)."
  }
}

variable "vault_dev_root_token_revision" {
  type        = number
  description = <<-EOT
    Revision of the write-only root token. Terraform cannot see a write-only
    value, so it cannot notice a NEW token on its own. Bumping this number is
    how a new token is delivered: it changes the release inputs, which
    reinstalls the (in-memory, dev-mode) Vault with the new token - see
    terraform_data.vault_release_inputs in main.tf. A fresh cluster per run
    needs nothing here; a KEEP_CLUSTER=1 re-run with a new token must pass a
    larger value (for example the epoch seconds) or reuse the old token.
  EOT
  default     = 1

  validation {
    condition     = var.vault_dev_root_token_revision >= 1 && floor(var.vault_dev_root_token_revision) == var.vault_dev_root_token_revision
    error_message = "vault_dev_root_token_revision must be a whole number >= 1 (the Helm provider ignores set_wo when it is 0)."
  }
}
