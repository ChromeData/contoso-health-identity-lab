# =============================================================================
# k8s/platform :: variables.tf
# -----------------------------------------------------------------------------
# No secret is an input here: the cluster gets its Key Vault value through
# Workload ID at mount time, never through Terraform. Versions and names are
# NOT variables: they are pinned constants in main.tf (locals), so a reviewer
# sees them in one place and nobody can override a pin from the command line.
# =============================================================================

variable "kube_context" {
  type        = string
  description = <<-EOT
    kubeconfig context both providers are pinned to. kind names the context
    "kind-<cluster name>", so the lab cluster contoso-k8s is kind-contoso-k8s.
    Only kind contexts are accepted: this root is lab-only and must never be
    pointed at a real (AKS or other) cluster.
  EOT
  default     = "kind-contoso-k8s"

  validation {
    condition     = startswith(var.kube_context, "kind-")
    error_message = "kube_context must be a kind context (kind-<cluster>). This root is lab-only."
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
