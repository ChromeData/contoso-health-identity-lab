# =============================================================================
# k8s/aks-mapping :: main.tf
# -----------------------------------------------------------------------------
# WHAT: one Microsoft Entra federated identity credential (FIC) on an app
# registration, trusting the AKS cluster's projected service-account tokens
# for exactly clinical-apps/nightly-report.
#
# IT IS THE ENTRA WORKLOAD ID EQUIVALENT OF THE VAULT ROLE in ../identity
# (vault_kubernetes_auth_backend_role.nightly_report). Side by side:
#
#   Vault role nightly-report (built + tested)    Entra FIC (this file, plan-only)
#   ------------------------------------------    ---------------------------------------------
#   bound SA name + namespace                     subject system:serviceaccount:clinical-apps:
#                                                 nightly-report (exact string match)
#   audience "vault"                              audiences ["api://AzureADTokenExchange"]
#   Vault calls TokenReview on the API server     Entra checks the JWT signature with keys from
#   at login (live: a deleted SA's token can      the issuer's public JWKS (offline: a token
#   no longer log in)                             stays exchangeable until its exp; verify)
#   kubernetes_host = in-cluster API server       issuer = the cluster's public OIDC issuer URL
#   policy nightly-report-read                    Key Vault RBAC: Key Vault Secrets User on the
#                                                 one secret, assigned to this app's service
#                                                 principal (not built here)
#   Vault token, TTL 15 min                       Entra access token, lifetime set by Entra
#                                                 (about an hour; not configurable per FIC; verify)
#
# NEVER APPLIED IN THIS LAB: the kind cluster's issuer is
# https://kubernetes.default.svc.cluster.local, which Entra cannot reach to
# fetch the JWKS. See README.md. The variables refuse such an issuer.
#
# ALTERNATIVE NOT TAKEN: on AKS the more common carrier for the FIC is a
# user-assigned managed identity (azurerm_federated_identity_credential),
# which cannot have a client secret at all. The app-registration flavour is
# used here because the lab's Entra code is azuread throughout
# (modules/pipeline-identity uses the same resource for GitHub OIDC). For the
# app registration, add "no password credentials" to its review: a FIC does
# not stop someone adding a client secret to the same app.
# =============================================================================

locals {
  # Must match ../identity (local.clinical_namespace / local.approved_sa);
  # tests/aks_mapping.tftest.hcl checks that statically.
  namespace       = "clinical-apps"
  service_account = "nightly-report"

  # The `sub` claim of a Kubernetes service-account token.
  subject = "system:serviceaccount:${local.namespace}:${local.service_account}"

  # The audience Entra requires for workload identity federation (the AKS
  # workload identity webhook requests projected tokens for it). Same value
  # modules/pipeline-identity uses for GitHub Actions OIDC.
  entra_token_exchange_audience = "api://AzureADTokenExchange"
}

resource "azuread_application_federated_identity_credential" "nightly_report" {
  # azuread 3.x: the application's resource id, not its client id.
  application_id = "/applications/${var.application_object_id}"

  display_name = "aks-${local.namespace}-${local.service_account}"
  description  = "AKS workload identity: only SA ${local.namespace}/${local.service_account} on this cluster's OIDC issuer. Entra equivalent of the lab's Vault role nightly-report."

  # Exactly one audience, one issuer, one subject: Entra matches all three
  # exactly. No wildcards exist in a classic FIC, so this cannot quietly
  # widen to "any service account in the namespace".
  audiences = [local.entra_token_exchange_audience]
  issuer    = var.aks_oidc_issuer_url
  subject   = local.subject
}
