# =============================================================================
# modules/pipeline-identity :: main.tf
# -----------------------------------------------------------------------------
# Two GitHub Actions OIDC identities (NO client secrets - federated creds only):
#   * PLAN  identity - read-only Graph roles, trusted from PULL REQUESTS.
#   * APPLY identity - read/write Graph roles, trusted only from the protected
#                      "prod" GitHub ENVIRONMENT.
#
# Why two apps: PR runs can read/plan without ever being able to mutate the
# tenant; only a run inside the gated prod environment can obtain write scope.
# Subject-claim scoping is the security boundary - see the federated creds.
#
# LICENSING: app registrations, service principals and federated credentials
# are FREE (Entra ID Free). The *actions these apps perform* need P1/P2/
# Governance (that is a property of the target resources, not these identities).
#
# WHERE THIS RUNS: only from envs/bootstrap, applied LOCALLY by a human admin.
# The pipeline these identities power (envs/dev) can therefore never widen its
# own Graph permissions or federation trust.
#
# HUMAN STEP: azuread_app_role_assignment grants application permissions, but a
# Global Admin / Privileged Role Admin must still have rights to create them,
# and in some tenants admin consent is surfaced separately. Confirm the grants
# show as "Granted" under Enterprise App > Permissions after apply. See README.
# =============================================================================

locals {
  # Well-known first-party Microsoft Graph application (client) id.
  microsoft_graph_app_id = "00000003-0000-0000-c000-000000000000"

  # GitHub OIDC issuer (fixed).
  github_oidc_issuer = "https://token.actions.githubusercontent.com"

  # Token audience Entra expects for GitHub federation.
  github_oidc_audience = "api://AzureADTokenExchange"

  # Subject claims. The PLAN identity trusts PR runs; the APPLY identity trusts
  # only the protected prod environment. Entra matches the subject exactly, and
  # GitHub.com issues the immutable form repo:OWNER@OWNER-ID/REPO@REPO-ID:...
  # for every repo created, renamed or transferred after 2026-07-15, so a
  # name-only subject never matches this repo. The ids are never reused, so a
  # recycled owner/repo name cannot mint a token these credentials accept.
  # verify: GitHub documents only the :ref: example of this form; confirm the
  # :pull_request and :environment: subjects with GitHub's OIDC subject preview
  # before the first pipeline run.
  github_repo_path = "${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
  plan_subject     = "repo:${local.github_repo_path}:pull_request"
  apply_subject    = "repo:${local.github_repo_path}:environment:${var.prod_environment_name}"
}

# -----------------------------------------------------------------------------
# Microsoft Graph service principal in THIS tenant - the resource we assign app
# roles against. Looked up by the well-known Graph app id. Its `app_role_ids`
# map lets us resolve role names to GUIDs instead of hardcoding them.
# -----------------------------------------------------------------------------
data "azuread_service_principal" "msgraph" {
  client_id = local.microsoft_graph_app_id
}

# Effective role sets = the reviewed baseline + the opt-in extras.
locals {
  plan_roles  = distinct(concat(var.plan_graph_roles, var.extra_plan_graph_roles))
  apply_roles = distinct(concat(var.apply_graph_roles, var.extra_apply_graph_roles))
}

# =============================================================================
# PLAN identity (read-only, pull_request)
# =============================================================================
resource "azuread_application" "plan" {
  display_name     = var.plan_app_display_name
  sign_in_audience = "AzureADMyOrg"

  # Declare the delegated/app permissions the app needs (documentation + the
  # consent experience). The actual grant is the app_role_assignment below.
  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(local.plan_roles)
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role" # "Role" = application permission (vs "Scope" = delegated)
      }
    }
  }
}

resource "azuread_service_principal" "plan" {
  client_id = azuread_application.plan.client_id
}

# Federated credential: trust GitHub tokens from PULL REQUESTS of this repo.
resource "azuread_application_federated_identity_credential" "plan_pr" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's pull_request events (local.plan_subject, the immutable owner/repo form); Checkov's subject pattern does not recognise that form.
  application_id = azuread_application.plan.id
  display_name   = "github-pr"
  description    = "GitHub Actions OIDC - pull_request runs (read-only plan)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.plan_subject
}

# Grant the read-only Graph app roles to the PLAN service principal.
resource "azuread_app_role_assignment" "plan" {
  for_each = toset(local.plan_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.plan.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# =============================================================================
# APPLY identity (read/write, environment:prod)
# =============================================================================
resource "azuread_application" "apply" {
  display_name     = var.apply_app_display_name
  sign_in_audience = "AzureADMyOrg"

  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(local.apply_roles)
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }
}

resource "azuread_service_principal" "apply" {
  client_id = azuread_application.apply.client_id
}

# Federated credential: trust GitHub tokens ONLY from the protected prod
# environment. This is what stops a PR from obtaining write scope.
resource "azuread_application_federated_identity_credential" "apply_prod" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's prod environment (local.apply_subject, the immutable owner/repo form); Checkov's subject pattern does not recognise that form.
  application_id = azuread_application.apply.id
  display_name   = "github-env-prod"
  description    = "GitHub Actions OIDC - prod environment runs (write apply)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.apply_subject
}

# Grant the read/write Graph app roles to the APPLY service principal.
resource "azuread_app_role_assignment" "apply" {
  for_each = toset(local.apply_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.apply.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}
