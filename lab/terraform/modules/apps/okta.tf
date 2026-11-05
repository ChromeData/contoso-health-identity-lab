# =============================================================================
# modules/apps :: okta.tf
# -----------------------------------------------------------------------------
# 6. okta-clinic-idp (OIDC; enable_okta_federation, off by default) - the
#    Entra half of the Okta coexistence in lab/docs/okta-migration-runbook.md
#    Phase 1 ("Okta trusts Entra") and ADR 0022. The acquired clinic keeps its
#    Okta org for the apps that have not moved yet; its users sign in at
#    Entra, so Conditional Access applies, and Okta accepts the Entra identity
#    through this app registration. The Okta half (the Microsoft IdP, the
#    routing rule, Clinic-Staff and the legacy app) is the separate,
#    human-applied root lab/terraform/okta - applied AFTER this, with output
#    okta_idp_client_id.
#
# WHAT THIS BUILDS (runbook Phase 1, steps 1 and 4):
#   * app registration okta-clinic-idp: single tenant, Web platform, ONE
#     redirect URI https://<okta_org_domain>/oauth2/v1/authorize/callback
#     (the callback Okta documents for an OIDC identity provider). The
#     variable is the bare org host and the scheme is added here, so the URI
#     is https by construction; implicit grants off (authorization code +
#     client secret is the only flow Okta uses);
#   * the delegated Microsoft Graph permissions behind the scopes Okta asks
#     for (openid, profile, email; plus User.Read, the registration default)
#     declared on the app, so admin consent is one reviewed post-apply step
#     and no clinic user meets a consent prompt (verify: Okta's current scope
#     list for a generic OIDC IdP, and that User.Read is needed for the
#     userinfo endpoint);
#   * its service principal with assignment required;
#   * exactly ONE assignment: App-Okta-Federation-Users (modules/groups, key
#     "okta") - the allow-list of who may federate. Not a list, as for every
#     app in this module: a second principal is a design change.
#
# THE CLIENT SECRET IS NOT CREATED HERE (runbook step 1: "entered once by
# hand into Okta"). A human mints it post-apply with output
# okta_idp_client_secret_command, bounded to okta_idp_secret_lifetime_days
# (180 at most: the P180D rotation recorded for okta-clinic-idp-client-secret
# in lab/iga/nhi-secrets-register.json), hands it once to the Okta root as
# TF_VAR_entra_client_secret, and it lives in Okta's credential store and
# nowhere in this repository.
#   Why there is no okta_idp_secret_mode = "keyvault" option: an
#   azuread_application_password puts the secret VALUE in envs/dev state,
#   which the PLAN identity can read (lab/pipelines/README.md), and writing
#   it to the lab Key Vault does not fit modules/keyvault: that module takes
#   no secret input (only the names its UAMI may read), its writers are
#   human Secrets Officers by design, the APPLY identity holds no data-plane
#   role on the vault, the vault's firewall is deny-by-default behind a
#   private endpoint a hosted runner cannot reach, and this module declares
#   azuread only. Manual is the one mode, on purpose (ADR 0022).
#
# NOT HERE: a Conditional Access policy aimed at this app. CA001-CA010 cover
# every app, so a clinic sign-in gets the same baseline as Contoso staff
# (runbook step 5); an Okta-specific policy would be a new CA number in
# modules/conditional-access, not a side effect here.
#
# LICENSING: an app registration is Entra ID Free; the GROUP assignment needs
# Entra ID P1 (envs/dev gates this module on enable_premium).
#
# Nothing here has run against a tenant or an Okta org. Runtime claims not
# proven by Microsoft or Okta documentation are marked "verify:".
# =============================================================================

locals {
  okta_enabled = var.enable_okta_federation

  # Okta's authorize callback for an OIDC identity provider (Okta developer
  # docs, "Add an external Identity Provider" / "Add Microsoft as an Identity
  # Provider": https://<org>/oauth2/v1/authorize/callback).
  okta_idp_redirect_uri = "https://${var.okta_org_domain}/oauth2/v1/authorize/callback"

  # Microsoft Graph's first-party app id and the delegated permission ids
  # behind the scopes Okta requests. The ids are Graph's well-known
  # oauth2PermissionScopes (verify: GET /servicePrincipals?$filter=appId eq
  # '00000003-0000-0000-c000-000000000000'&$select=oauth2PermissionScopes).
  msgraph_app_id = "00000003-0000-0000-c000-000000000000"
  okta_idp_delegated_scopes = {
    openid      = "37f7f235-527c-4136-accd-4a02d197296e"
    profile     = "14dad69e-099b-42c9-810b-d002981feec1"
    email       = "64a6cdd6-997a-4b52-ad60-8e8b9f49d1ab"
    "User.Read" = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
  }

  # The tenant's v1.0 endpoints the Okta root's okta_idp_oidc uses (the Okta
  # provider has no discovery-URL field, provider 4.20). v1.0, not v2.0:
  # only the v1.0 ID token carries the `amr` claim Okta's "trust claims"
  # reads to count the MFA Entra enforced (lab/terraform/okta main.tf locals,
  # read live 2026-11-05). No userinfo URL: Graph's userinfo refuses the
  # v1.0 access token (401); the ID token carries the profile instead.
  # Output as a map so the human copies values, not a URL they typed.
  entra_authority = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}"
  okta_idp_endpoints = {
    issuer_url        = "https://sts.windows.net/${data.azuread_client_config.current.tenant_id}/"
    authorization_url = "${local.entra_authority}/oauth2/authorize"
    token_url         = "${local.entra_authority}/oauth2/token"
    jwks_url          = "${local.entra_authority}/discovery/keys"
  }
}

# The app registration Okta signs users in through. The precondition fails
# the PLAN, before anything is created, if the flag is on without an Okta org
# host (an app with a redirect URI nobody can be sent back to).
resource "azuread_application" "okta_idp" {
  count = local.okta_enabled ? 1 : 0

  display_name     = var.okta_idp_app_display_name
  sign_in_audience = "AzureADMyOrg" # single tenant: Contoso workforce only
  owners           = local.app_owners

  # A duplicate is how an orphaned, ownerless copy appears in an NHI inventory.
  prevent_duplicate_names = true

  service_management_reference = var.service_management_reference != "" ? var.service_management_reference : null
  notes                        = "Entra as the OIDC identity provider for the acquired clinic's Okta org (okta-migration-runbook Phase 1, ADR 0022). Authorization code + client secret; the secret is minted by a human and held by Okta. Access = App-Okta-Federation-Users only. Managed by Terraform - modules/apps (okta.tf)."

  web {
    # Exactly one callback, on exactly this org: no wildcard, no second host.
    redirect_uris = [local.okta_idp_redirect_uri]

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false # Okta uses the authorization code flow
    }
  }

  # The v1.0 ID token Okta now reads carries given_name, family_name and upn
  # but NOT email for members of the tenant (Microsoft Learn, "ID token claims
  # reference": email is "present by default for guest accounts"; managed
  # users get it through the `email` optional claim). Okta needs it: JIT
  # names the new Okta user after idpuser.email and links accounts by email.
  # Emitted only for users with a mail attribute on a verified domain.
  optional_claims {
    id_token {
      name = "email"
    }
  }

  # Declared, not consented: granting admin consent is a Tier-0 post-apply
  # step (README "Okta coexistence"). Without it each clinic user is asked to
  # consent at first sign-in (verify: the user-consent policy in the tenant).
  required_resource_access {
    resource_app_id = local.msgraph_app_id

    dynamic "resource_access" {
      for_each = local.okta_idp_delegated_scopes
      content {
        id   = resource_access.value
        type = "Scope"
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.okta_org_domain != ""
      error_message = "enable_okta_federation = true needs okta_org_domain (the Okta org host, e.g. integrator-1234567.okta.com): it is the host of the one redirect URI. Set it in terraform.tfvars / TF_VAR_okta_org_domain, never in lab.tfvars."
    }
  }
}

resource "azuread_service_principal" "okta_idp" {
  count = local.okta_enabled ? 1 : 0

  client_id = azuread_application.okta_idp[0].client_id

  # Only assigned principals get a token. With the single assignment below,
  # that is App-Okta-Federation-Users and nobody else - the runbook's
  # allow-list of who may federate.
  app_role_assignment_required = true

  owners = local.app_owners
  notes  = "Okta coexistence: Entra is the IdP, Okta the relying party. Access = membership of App-Okta-Federation-Users. Managed by Terraform - modules/apps (okta.tf)."

  feature_tags {
    enterprise = true
  }
}

# The single assignment: App-Okta-Federation-Users. The app defines no app
# roles, so the DEFAULT ACCESS role id (all zeros) means "assigned, no
# specific role", as for guacamole-psm.
resource "azuread_app_role_assignment" "okta_federation_users" {
  count = local.okta_enabled ? 1 : 0

  app_role_id         = "00000000-0000-0000-0000-000000000000"
  principal_object_id = var.okta_federation_users_group_object_id
  resource_object_id  = azuread_service_principal.okta_idp[0].object_id

  lifecycle {
    precondition {
      condition     = var.okta_federation_users_group_object_id != ""
      error_message = "enable_okta_federation = true needs okta_federation_users_group_object_id (App-Okta-Federation-Users, modules/groups app_access_group_object_ids[\"okta\"]). Assignment is required, so an app with no assignment federates nobody."
    }
  }
}
