# =============================================================================
# k8s/keyvault-trust :: variables.tf
# -----------------------------------------------------------------------------
# Identifiers only, none secret. No defaults: lab/k8s/ci/pipeline.sh passes
# the values of the throwaway objects it created for this run (TF_VAR_*).
# =============================================================================

variable "run_id" {
  type        = string
  description = "The pipeline run id (8 lowercase hex or digits); names the app registration so a leftover is easy to find and delete."

  validation {
    condition     = can(regex("^[0-9a-f]{8,12}$", var.run_id))
    error_message = "run_id must be 8-12 lowercase hex characters."
  }
}

variable "issuer_url" {
  type        = string
  description = <<-EOT
    The kind cluster's PUBLIC service-account issuer: the static website of
    this run's storage account, with no trailing slash (for example
    https://stk8skv1234abcd.z20.web.core.windows.net). Entra compares it to
    the token's `iss` claim as an exact string and fetches the signing keys
    from <issuer>/.well-known/openid-configuration -> jwks_uri, so it must
    be public HTTPS. On AKS it would be the cluster's oidcIssuerProfile URL.
  EOT

  validation {
    condition     = can(regex("^https://[^/\\s]+(/[^\\s]*)?[^/]$", var.issuer_url))
    error_message = "issuer_url must be an https:// URL without a trailing slash (it must equal the API server's --service-account-issuer)."
  }
  validation {
    # kind's default issuer, loopback, private IPv4 literals and private
    # suffixes cannot be fetched by Entra: it would accept the credential and
    # then fail every exchange. A denylist, not proof of "public".
    condition     = !can(regex("^https://([^/]*\\.)?(localhost|127\\.[0-9.]+|10\\.[0-9.]+|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9.]+|192\\.168\\.[0-9.]+|169\\.254\\.[0-9.]+|\\[::1\\]|kubernetes\\.default\\.svc[^/]*|[^/]*\\.local|[^/]*\\.internal)(:[0-9]+)?(/|$)", var.issuer_url))
    error_message = "issuer_url must be publicly reachable (not loopback, a private or link-local IPv4 address, kubernetes.default.svc, *.local or *.internal): Entra fetches its JWKS over the internet."
  }
}

variable "key_vault_id" {
  type        = string
  description = "Resource id of this run's throwaway Key Vault (RBAC permission model)."

  validation {
    condition     = can(regex("^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\\.KeyVault/vaults/[A-Za-z0-9-]{3,24}$", var.key_vault_id))
    error_message = "key_vault_id must be a Key Vault resource id."
  }
}

variable "secret_name" {
  type        = string
  description = "The ONE secret the workload may read (Key Vault Secrets User is assigned on it, not on the vault)."
  default     = "clinical-db"

  validation {
    condition     = can(regex("^[0-9A-Za-z-]{1,127}$", var.secret_name))
    error_message = "secret_name must be a Key Vault secret name (letters, digits, dashes)."
  }
}
