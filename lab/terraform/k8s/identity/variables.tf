# =============================================================================
# k8s/identity :: variables.tf
# -----------------------------------------------------------------------------
# Nothing here is secret. The Key Vault identifiers come from the pipeline
# (TF_VAR_*: this run's throwaway vault and ../keyvault-trust's outputs).
# Names, audiences and paths are pinned constants in main.tf (locals), not
# variables, so the security-relevant values cannot be widened from the
# command line and tests/identity.tftest.hcl can pin them.
# =============================================================================

variable "tenant_id" {
  type        = string
  description = "Microsoft Entra tenant id that holds the workload's app registration and the Key Vault."

  validation {
    condition     = can(regex("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", var.tenant_id))
    error_message = "tenant_id must be a lowercase GUID."
  }
}

variable "workload_client_id" {
  type        = string
  description = "Client (application) id of the workload's app registration (../keyvault-trust output client_id). Named in the SecretProviderClass (clientID) and on the nightly-report service account."

  validation {
    condition     = can(regex("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", var.workload_client_id))
    error_message = "workload_client_id must be a lowercase GUID."
  }
}

variable "key_vault_name" {
  type        = string
  description = "Name of this run's Key Vault (the SecretProviderClass keyvaultName)."

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.key_vault_name))
    error_message = "key_vault_name must be a valid Key Vault name (3-24 characters, letters, digits and dashes)."
  }
}

variable "secret_name" {
  type        = string
  description = "The ONE Key Vault secret the workload mounts (the only secret ../keyvault-trust grants it)."
  default     = "clinical-db"

  validation {
    condition     = can(regex("^[0-9A-Za-z-]{1,127}$", var.secret_name))
    error_message = "secret_name must be a Key Vault secret name (letters, digits, dashes)."
  }
}

variable "kube_context" {
  type        = string
  description = <<-EOT
    kubeconfig context the Kubernetes provider is pinned to (kind names it
    kind-<cluster>). Only kind contexts are accepted: the RBAC here is written
    for impersonated groups on the lab cluster. On AKS the subjects would be
    Entra group object IDs (README "What changes on AKS").
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
    expanded). The provider ignores KUBECONFIG, so the pipeline sets
    TF_VAR_kubeconfig_path when KUBECONFIG is set. A single path only.
  EOT
  default     = "~/.kube/config"

  validation {
    condition     = length(trimspace(var.kubeconfig_path)) > 0 && !strcontains(var.kubeconfig_path, ":")
    error_message = "kubeconfig_path must be one non-empty file path (not a colon-separated KUBECONFIG list)."
  }
}

# -----------------------------------------------------------------------------
# Admission policy inputs (main.tf, ValidatingAdmissionPolicy
# clinical-apps-workload-identity). Image references, not secrets. Variables
# rather than locals because they move with releases (a new app build = a new
# digest), but each one is validated so it can only ever be a digest-pinned
# reference, and the launcher list cannot be widened to "everyone".
# -----------------------------------------------------------------------------

variable "nightly_report_app_image" {
  type        = string
  description = <<-EOT
    The ONE application image the nightly-report service account may run, as
    a digest-pinned reference (<repo>[:tag]@sha256:<64 hex>). Default: the
    busybox 1.37.0 multi-arch index digest that lab/k8s/manifests/
    nightly-report.yaml runs. Shipping a new build means changing this value
    (a reviewed Terraform change) BEFORE the Deployment can use it: that is the
    point. The policy compares digests, so the same bytes under another
    registry name or tag still match, and nothing else does.
  EOT
  default     = "docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

  validation {
    condition     = can(regex("^[^@\\s]+@sha256:[0-9a-f]{64}$", var.nightly_report_app_image))
    error_message = "nightly_report_app_image must be pinned by digest: <repo>[:tag]@sha256:<64 lowercase hex>."
  }
}

variable "nightly_report_launcher_groups" {
  type        = list(string)
  description = <<-EOT
    Kubernetes groups whose members may CREATE or UPDATE a Pod, Deployment or
    ReplicaSet that runs as the nightly-report service account (the
    kube-system controllers that turn a Deployment into pods are always
    allowed). Default: kubeadm:cluster-admins, the group of the admin client
    certificate kind writes to the kubeconfig (kubeadm >= 1.29; checked with
    `kubectl auth whoami` on kindest/node v1.36.4), i.e. the lab pipeline. On
    AKS this would be the GitOps controller's or the release pipeline's
    identity, never a human team's group. Human deployers are deliberately
    NOT here: using a service account is a deployment-time decision, and this
    is the list of who may make it.
  EOT
  default     = ["kubeadm:cluster-admins"]

  validation {
    condition     = length(var.nightly_report_launcher_groups) > 0 && alltrue([for g in var.nightly_report_launcher_groups : length(trimspace(g)) > 0])
    error_message = "nightly_report_launcher_groups needs at least one non-empty group name."
  }
  validation {
    # Groups that would make the rule meaningless: every authenticated caller,
    # every service account (in the namespace or anywhere), or the human
    # deployer group the rule exists to keep out.
    condition = length(setintersection(toset(var.nightly_report_launcher_groups), toset([
      "system:authenticated", "system:unauthenticated", "system:serviceaccounts",
      "system:serviceaccounts:clinical-apps", "k8s-clinical-deployers",
    ]))) == 0
    error_message = "nightly_report_launcher_groups must not include a catch-all group (system:authenticated, system:serviceaccounts...) or the human deployer group."
  }
}
