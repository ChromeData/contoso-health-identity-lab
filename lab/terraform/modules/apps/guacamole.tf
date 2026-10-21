# =============================================================================
# modules/apps :: guacamole.tf
# -----------------------------------------------------------------------------
# 4. guacamole-psm - the PSM stand-in (lab/pam, Apache Guacamole) signs people
#    in through Entra ID instead of local Guacamole passwords
#    (lab/pam/README.md "Per-person sign-in (Entra OIDC)", which used to be a
#    portal click-path; this file is that click-path as code).
#
# WHY THIS MATTERS: the PSM is the door to Tier-0 sessions (DC01 RDP, the
# Linux SSH target). With local passwords the door bypasses MFA and
# Conditional Access entirely. Behind Entra, every PSM session starts with
# the tenant's MFA / CA, the Guacamole user name is the Entra UPN (the key
# in lab/pam/operators.json and the ServiceNow assignee), and a leaver loses
# PSM access when Entra disables them - no second account to forget.
#
# DESIGN
#   * Single-tenant app registration, Web platform, redirect
#     http://localhost:8081/guacamole/ (the local stand-in; Entra accepts
#     http only for localhost).
#   * ID TOKEN implicit grant ON, access-token implicit grant OFF:
#     Guacamole 1.6's OpenID extension uses response_type=id_token
#     (verify: lab/pam/README.md - whether 1.6 added an authorization-code
#     flow). An id token is an authentication artefact only; it grants no API
#     access, and no client secret exists, so there is nothing to leak or
#     rotate (NHI: credential_type = none).
#   * Assignment required + ONE assignment: PAM-Operators. Only operators get
#     an id token at all; everyone else is refused by Entra before Guacamole
#     sees them.
#   * groups claim = only groups assigned to this app (PAM-Operators), so the
#     token says "is a PAM operator" and nothing about unrelated memberships.
#
# NOT HERE (deliberately): a Conditional Access policy aimed at this app.
#   CA008 (phishing-resistant, workforce) covers PSM sign-ins once its scope
#   includes the operators; a dedicated "PSM requires phishing-resistant
#   strength" policy is a candidate CA009, outside the CA001-CA008 contract
#   of modules/conditional-access. Until then the operator demo uses CA008
#   in pilot scope with the operators in CA008-Pilot-PhishingResistant.
#
# Off by default (enable_guacamole_psm_app; root flag enable_pam_oidc_app).
# Nothing here has run against a tenant.
# =============================================================================

# PAM-Operators: the people allowed to START a PSM session. Membership is an
# access decision with a human approver, so it is set post-apply (or by an
# access package later), never by Terraform - member drift is ignored.
# Not role-assignable: being a PSM operator grants no Entra directory role;
# the Tier-0 power lives in the vaulted AD credential, which is checked out
# per ticket (lab/pam/itsm-ticket.sh) and rotated on check-in.
resource "azuread_group" "pam_operators" {
  count = var.enable_guacamole_psm_app ? 1 : 0

  display_name     = "PAM-Operators"
  mail_nickname    = "pam-operators"
  description      = "May sign in to the PSM stand-in (guacamole-psm). Assigned membership, approved per person. Managed by Terraform - modules/apps."
  security_enabled = true
  mail_enabled     = false

  # No extra owners on purpose: a group owner can add members, and adding a
  # member here opens the PSM door. Only the Terraform identity owns it (the
  # azuread default), same as every group in modules/groups.

  lifecycle {
    ignore_changes = [members]
  }
}

resource "azuread_application" "guacamole_psm" {
  count = var.enable_guacamole_psm_app ? 1 : 0

  display_name     = "guacamole-psm"
  sign_in_audience = "AzureADMyOrg" # single tenant: Contoso workforce only
  owners           = local.app_owners

  prevent_duplicate_names = true

  service_management_reference = var.service_management_reference != "" ? var.service_management_reference : null
  notes                        = "PSM stand-in (lab/pam Guacamole) sign-in. Implicit id_token only, no secret. Assigned to PAM-Operators only. Managed by Terraform - modules/apps."

  # Only the app-assigned group (PAM-Operators) appears in the groups claim
  # Guacamole reads (OPENID_GROUPS_CLAIM_TYPE=groups).
  group_membership_claims = ["ApplicationGroup"]

  web {
    redirect_uris = var.guacamole_redirect_uris

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = true # Guacamole's response_type=id_token
    }
  }
}

resource "azuread_service_principal" "guacamole_psm" {
  count = var.enable_guacamole_psm_app ? 1 : 0

  client_id = azuread_application.guacamole_psm[0].client_id

  # No assignment, no id token: Entra refuses non-operators.
  app_role_assignment_required = true

  owners = local.app_owners
  notes  = "PSM stand-in sign-in. Access = membership of PAM-Operators. Managed by Terraform - modules/apps."

  feature_tags {
    enterprise = true
  }
}

# The app defines no app roles, so the assignment uses the DEFAULT ACCESS role
# id (all zeros), which is how Entra represents "assigned, no specific role".
resource "azuread_app_role_assignment" "guacamole_pam_operators" {
  count = var.enable_guacamole_psm_app ? 1 : 0

  app_role_id         = "00000000-0000-0000-0000-000000000000"
  principal_object_id = azuread_group.pam_operators[0].object_id
  resource_object_id  = azuread_service_principal.guacamole_psm[0].object_id
}
