# =============================================================================
# k8s/keyvault-trust :: main.tf
# -----------------------------------------------------------------------------
# WHAT: the Microsoft side of the nightly-report workload's identity.
#
#   azuread_application          k8s-nightly-report-<run id>: the identity the
#                                workload signs in as. No client secret, no
#                                certificate: it can ONLY sign in with a
#                                federated token.
#   azuread_service_principal    its enterprise application in the tenant
#   azuread_application_federated_identity_credential
#                                trust ONE subject from ONE issuer:
#                                system:serviceaccount:clinical-apps:nightly-report,
#                                tokens with audience api://AzureADTokenExchange,
#                                from this kind cluster's public issuer
#   azurerm_role_assignment      Key Vault Secrets User on ONE SECRET
#                                (<vault id>/secrets/clinical-db), not the vault
#
# HOW IT IS USED (Microsoft Learn, "Workload identity federation" and
# "Access Azure Key Vault with the CSI Driver Identity Provider"): the CSI
# driver gets a service-account token for the pod, the Azure provider sends
# it to Entra as a client assertion, Entra fetches the issuer's JWKS, checks
# signature, issuer, subject and audience against this federated credential,
# and returns an access token for https://vault.azure.net. Key Vault then
# checks Azure RBAC: this service principal may read one secret.
#
# WHO APPLIES IT: lab/k8s/ci/pipeline.sh, stage 4, run as the lab operator
# (lab/scripts/operator/op). It is a throwaway: the pipeline destroys it with
# the cluster. The vault and storage it points at are throwaway too (one
# resource group per run, created and deleted by the pipeline).
#
# WHY SECRET SCOPE, AND THE TRADE-OFF (said out loud): Microsoft Learn
# ("Grant permission to applications to access an Azure key vault using
# Azure RBAC", best practices) recommends a vault per application per
# environment with roles at VAULT scope, and calls per-secret assignments
# "not recommended" outside a few exceptions. This lab does both: the vault
# is per run and holds only this app's secret plus a decoy, AND the role is
# on the one secret, so the e2e test can prove the decoy in the same vault
# is refused. Production: a vault per app per environment, role at vault
# scope (fewer assignments to review, one place for network rules).
#
# WHAT THE VAULT ROLE USED TO BE (for reviewers who knew the Vault version):
#   Vault role nightly-report             -> this federated credential
#   bound SA + namespace + audience       -> subject + audience (exact match)
#   Vault TokenReview (live, per login)   -> Entra checks the JWKS (offline):
#                                            a token stays exchangeable until
#                                            its exp, SA deleted or not
#                                            (verify: current Entra behaviour)
#   policy nightly-report-read            -> Key Vault Secrets User on one secret
#   Vault token TTL 15 min                -> Entra access token (lifetime set by
#                                            Entra; the e2e test reports it)
# =============================================================================

locals {
  # Must match ../identity (local.clinical_namespace / local.approved_sa);
  # tests/keyvault_trust.tftest.hcl checks that statically.
  namespace       = "clinical-apps"
  service_account = "nightly-report"

  # The `sub` claim of a Kubernetes service-account token.
  subject = "system:serviceaccount:${local.namespace}:${local.service_account}"

  # The audience Entra requires for workload identity federation. Same value
  # modules/pipeline-identity uses for GitHub Actions OIDC, and the only
  # audience ../platform lets the CSI driver request.
  entra_token_exchange_audience = "api://AzureADTokenExchange"

  # Key Vault Secrets User (built-in, Microsoft Learn RBAC guide). By id, not
  # name: a renamed role cannot silently change what is granted.
  key_vault_secrets_user_role_id = "4633458b-17de-408a-b874-0445c86b69e6"

  secret_scope = "${var.key_vault_id}/secrets/${var.secret_name}"
}

data "azurerm_subscription" "current" {}

resource "azuread_application" "nightly_report" {
  display_name = "k8s-nightly-report-${var.run_id}"
  description  = "Throwaway workload identity for the lab's kind cluster (lab/k8s/ci/pipeline.sh run ${var.run_id}). Federated credential only; deleted with the cluster."
  # Sign-in audience: this tenant only. A federated credential needs no
  # redirect URIs, API permissions or app roles: Key Vault access is Azure
  # RBAC on the service principal, not a Graph permission.
  sign_in_audience = "AzureADMyOrg"
  notes            = "Owner: the lab operator (pipeline). Never add a password or certificate credential: the only way in is the federated credential."
}

resource "azuread_service_principal" "nightly_report" {
  client_id = azuread_application.nightly_report.client_id
  # Nobody signs in to it interactively; it is not a gallery app.
  app_role_assignment_required = true
  notes                        = "Throwaway workload identity (lab/k8s/ci/pipeline.sh run ${var.run_id})."
}

resource "azuread_application_federated_identity_credential" "nightly_report" {
  # azuread 3.x: the application's resource id, not its client id.
  application_id = azuread_application.nightly_report.id

  display_name = "kind-${local.namespace}-${local.service_account}"
  description  = "Only SA ${local.namespace}/${local.service_account} on this run's kind issuer."

  # Exactly one audience, one issuer, one subject: Entra matches all three
  # exactly. A classic federated credential has no wildcards, so this cannot
  # quietly widen to "any service account in the namespace".
  audiences = [local.entra_token_exchange_audience]
  issuer    = var.issuer_url
  subject   = local.subject
}

resource "azurerm_role_assignment" "secret_reader" {
  scope              = local.secret_scope
  role_definition_id = "${data.azurerm_subscription.current.id}/providers/Microsoft.Authorization/roleDefinitions/${local.key_vault_secrets_user_role_id}"
  principal_id       = azuread_service_principal.nightly_report.object_id
  # Stated so Azure does not have to look the principal up in Entra; a new
  # service principal may not have replicated yet when this runs.
  principal_type = "ServicePrincipal"
  description    = "nightly-report (kind run ${var.run_id}) may read this one secret."
}
