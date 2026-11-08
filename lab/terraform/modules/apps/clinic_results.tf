# =============================================================================
# modules/apps :: clinic_results.tf
# -----------------------------------------------------------------------------
# 8. Clinic Lab Results (OIDC; enable_clinic_results_app, off by default) -
#    the first app the acquired clinic moves OFF Okta and onto Entra
#    (lab/docs/okta-migration-runbook.md Phase 2, wave 1; the tracker in
#    lab/okta-migration/). Until now the app trusted the clinic's Okta org
#    (lab/terraform/okta clinic-apps.tf, okta_app_oauth.clinic_results); this
#    file is its Entra twin, built BEFORE the cut-over (runbook step 1,
#    "pre-stage"), so the cut-over itself is a config switch in the app and
#    the rollback is the same switch back.
#
# WHAT THIS BUILDS
#   * App registration "Clinic Lab Results": single tenant, PUBLIC client
#     (the "Mobile and desktop" platform), ONE loopback redirect URI
#     http://localhost:8471/callback. The app is a small results viewer that
#     runs on the clinic workstation (lab/okta-migration/clinic-results/
#     app.mjs). It signs people in with the authorization code flow + PKCE
#     (RFC 7636) and a loopback redirect (RFC 8252), so it holds NO client
#     secret and NO certificate: there is nothing to leak, rotate or vault
#     (NHI row: credential_type none). It is the same shape it had in Okta
#     (a native app, token_endpoint_auth_method none, PKCE required).
#   * Its service principal, assignment REQUIRED: Entra refuses an ID token
#     to anyone who is not assigned, before the app sees them.
#   * The group App-ClinicResults-Users and ONE assignment of it. Assigned
#     membership on purpose, NOT a copy of the Okta group: in Okta the app is
#     assigned to Clinic-Staff, whose rule is "login domain =
#     contosohealthlab.com" - after the acquisition that is every hospital
#     user, so a 1:1 translation into an Entra dynamic group would hand lab
#     results to the whole hospital. The runbook's rule (Phase 3, "Groups"):
#     Okta groups become access packages, not copies. Pilot members are added
#     post-apply by lab/okta-migration/cutover.mjs (runbook step 2); an
#     access package can hand the group out later. Member drift is ignored.
#   * Delegated Microsoft Graph openid + profile + email, declared here and
#     consented post-apply by the operator (DelegatedPermissionGrant, the
#     same step O1a as okta-clinic-idp), so no clinic user meets a consent
#     prompt.
#
# CONDITIONAL ACCESS: CA061 (modules/conditional-access clinical.tf) targets
# this app: MFA and sign-in every 8 hours - the same rule the app had in
# Okta ("Clinic clinical apps" authentication policy: two factors,
# re-authenticate after 8 hours). The migration keeps the control; it does
# not quietly weaken it.
#
# LICENSING: app registration Entra ID Free; group assignment and CA need P1
# (envs/dev gates this module on enable_premium).
#
# Runtime claims not proven by Microsoft documentation are marked "verify:".
# =============================================================================

locals {
  clinic_results_enabled = var.enable_clinic_results_app

  # openid, profile, email: what the app asks for at sign-in. No User.Read:
  # the app reads nothing from Graph; the ID token is all it needs.
  clinic_results_delegated_scopes = {
    openid  = "37f7f235-527c-4136-accd-4a02d197296e"
    profile = "14dad69e-099b-42c9-810b-d002981feec1"
    email   = "64a6cdd6-997a-4b52-ad60-8e8b9f49d1ab"
  }
}

# The people allowed to open Clinic Lab Results. Assigned, not dynamic (see
# the header): access is a decision, not a side effect of a login domain.
resource "azuread_group" "clinic_results_users" {
  count = local.clinic_results_enabled ? 1 : 0

  display_name     = "App-ClinicResults-Users"
  mail_nickname    = "app-clinicresults-users"
  description      = "May sign in to Clinic Lab Results (moved from the clinic's Okta, okta-migration wave 1). Assigned membership: pilot users first, an access package later. Managed by Terraform - modules/apps."
  security_enabled = true
  mail_enabled     = false

  lifecycle {
    ignore_changes = [members]
  }
}

resource "azuread_application" "clinic_results" {
  count = local.clinic_results_enabled ? 1 : 0

  display_name     = var.clinic_results_display_name
  sign_in_audience = "AzureADMyOrg" # single tenant: Contoso workforce only
  owners           = local.app_owners

  prevent_duplicate_names = true

  service_management_reference = var.service_management_reference != "" ? var.service_management_reference : null
  notes                        = "Acquired clinic's lab results viewer, moved from Okta (okta-migration wave 1). Public client, auth code + PKCE, loopback redirect, no secret. Access = App-ClinicResults-Users only; CA061. Managed by Terraform - modules/apps (clinic_results.tf)."

  # Public client ("Mobile and desktop applications"): PKCE, no secret.
  # Entra accepts http only for loopback, which is what a workstation app
  # uses (verify: Learn "Redirect URI restrictions" - loopback port is
  # ignored for public clients; the app always listens on 8471 anyway).
  public_client {
    redirect_uris = var.clinic_results_redirect_uris
  }

  # No ROPC or device code: the browser sign-in is the only door, so CA
  # (MFA, sign-in frequency) always sees an interactive sign-in.
  fallback_public_client_enabled = false

  required_resource_access {
    resource_app_id = local.msgraph_app_id

    dynamic "resource_access" {
      for_each = local.clinic_results_delegated_scopes
      content {
        id   = resource_access.value
        type = "Scope"
      }
    }
  }
}

resource "azuread_service_principal" "clinic_results" {
  count = local.clinic_results_enabled ? 1 : 0

  client_id = azuread_application.clinic_results[0].client_id

  # No assignment, no ID token.
  app_role_assignment_required = true

  owners = local.app_owners
  notes  = "Clinic Lab Results (moved from Okta). Access = App-ClinicResults-Users. Managed by Terraform - modules/apps."

  feature_tags {
    enterprise = true
  }
}

# Default access role (all zeros): the app defines no app roles.
resource "azuread_app_role_assignment" "clinic_results_users" {
  count = local.clinic_results_enabled ? 1 : 0

  app_role_id         = "00000000-0000-0000-0000-000000000000"
  principal_object_id = azuread_group.clinic_results_users[0].object_id
  resource_object_id  = azuread_service_principal.clinic_results[0].object_id
}
