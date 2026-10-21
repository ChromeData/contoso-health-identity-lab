# =============================================================================
# k8s/aks-mapping :: variables.tf
# -----------------------------------------------------------------------------
# Identifiers only, none secret. No defaults on purpose: there is no real AKS
# cluster or app registration behind this lab, and a made-up default would
# read like one. The tests supply obviously-placeholder values.
# =============================================================================

variable "aks_oidc_issuer_url" {
  type        = string
  description = <<-EOT
    The AKS cluster's OIDC issuer URL, copied verbatim from
    `az aks show -g <rg> -n <cluster> --query oidcIssuerProfile.issuerUrl -o tsv`
    (cluster created/updated with --enable-oidc-issuer --enable-workload-identity).
    Entra compares it to the token's `iss` claim as an exact string, trailing
    slash included, and fetches the signing keys from
    <issuer>/.well-known/openid-configuration -> jwks_uri, so it must be
    public HTTPS. verify: AKS issuer URLs currently look like
    https://<region>.oic.prod-aks.azure.com/<tenant-id>/<guid>/.
  EOT

  validation {
    condition     = can(regex("^https://[^/\\s]+(/[^\\s]*)?$", var.aks_oidc_issuer_url))
    error_message = "aks_oidc_issuer_url must be an https:// URL (Entra only federates with HTTPS issuers)."
  }
  validation {
    # The kind cluster's issuer (https://kubernetes.default.svc.cluster.local)
    # and anything on loopback, a private IPv4 literal (RFC 1918, link-local)
    # or a private suffix cannot be fetched by Entra: it would accept the
    # configuration and then fail every token exchange. A denylist, not
    # proof of "public": a DNS name that resolves to a private address still
    # passes (Terraform cannot resolve names in a validation).
    condition     = !can(regex("^https://([^/]*\\.)?(localhost|127\\.[0-9.]+|10\\.[0-9.]+|172\\.(1[6-9]|2[0-9]|3[01])\\.[0-9.]+|192\\.168\\.[0-9.]+|169\\.254\\.[0-9.]+|\\[::1\\]|kubernetes\\.default\\.svc[^/]*|[^/]*\\.local|[^/]*\\.internal)(:[0-9]+)?(/|$)", var.aks_oidc_issuer_url))
    error_message = "aks_oidc_issuer_url must be publicly reachable (not loopback, a private or link-local IPv4 address, kubernetes.default.svc, *.local or *.internal): Entra fetches its JWKS over the internet."
  }
}

variable "application_object_id" {
  type        = string
  description = <<-EOT
    OBJECT id (not the client/app id) of the Entra application registration
    the workload signs in as. azuread 3.x wants the application's resource
    id, /applications/<object id>; main.tf builds it, so the bare GUID goes
    here. A client id cannot be told apart from an object id by format (both
    are GUIDs), so the validation only catches a resource id or a non-GUID.
    In a real deployment it would come from the azuread_application resource
    or the modules/pipeline-identity pattern, not a hand-typed GUID.
  EOT

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.application_object_id))
    error_message = "application_object_id must be a GUID (the application's object id)."
  }
}

variable "application_client_id" {
  type        = string
  description = <<-EOT
    CLIENT (application) id of the same app registration. Not used by Entra's
    trust; it is what the Kubernetes side needs: the service account is
    annotated azure.workload.identity/client-id=<this>, and the workload
    identity webhook puts it in the pod as AZURE_CLIENT_ID. Rendered in the
    kubernetes_side output so both halves of the mapping sit in one place.
  EOT

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.application_client_id))
    error_message = "application_client_id must be a GUID (the application's client id)."
  }
}
