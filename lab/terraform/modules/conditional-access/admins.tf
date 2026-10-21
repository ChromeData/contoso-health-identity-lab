# =============================================================================
# modules/conditional-access :: admins.tf
# -----------------------------------------------------------------------------
# Admin / privileged-access range (020-039):
#
#   CA020  Admin portals: sign-in frequency for Tier-0/1 admins (session only)
#   CA021  PIM activation step-up on authentication context c1 - RENDERED here,
#          written to the tenant by post-apply/Set-AuthContextPolicies.ps1
#   CA022  PAM session broker + admin portals require the ADMIN strength
#   CA023  Protected actions (CA policies, named locations) step-up on
#          authentication context c2 - RENDERED here, written like CA021
#          (numbered CA009 before the CA design-principle ranges existed; it
#          never reached a tenant, so the renumber costs nothing)
#
# Each is behind its own staging flag (default off) and starts REPORT-ONLY via
# policy_states; the key is required while the flag is on.
# =============================================================================

# -----------------------------------------------------------------------------
# CA020 - Require sign-in every N hours (default 4) on the admin portals for
# Tier-0 / Tier-1 admins.
#
# WHY: an admin session cookie or refresh token is the most valuable token in
# the tenant. Learn recommends time-based sign-in frequency (or a PIM
# authentication context - CA021) for the Azure portal and the Entra admin
# center. 4 hours matches the Tier-0 PIM activation cap (modules/pim).
#
# TARGET: the CA005 resource set (var.admin_portal_applications) -
# "MicrosoftAdminPortals" + Windows Azure Service Management API. That second
# one is Azure Resource Manager, so `az` / Azure PowerShell sessions of an
# in-scope admin re-authenticate every N hours too (expected, not a lockout).
#
# WHO: Tier-0/1 directory roles (var.admin_session_role_template_ids) PLUS the
# admin groups (var.admin_scope_group_object_ids) - AU-scoped role holders are
# invisible to the role condition, same reasoning as CA002.
#
# SESSION-ONLY: no grant_controls block. The provider accepts a policy whose
# only control is a session setting with an effective value. verify: first
# real plan (the provider's CustomizeDiff is not exercised by mocked tests).
#
# NOT HERE, on purpose:
#   * Token protection (secureSignInSession) and CAE strict location have no
#     azuread 3.10 attribute. Do NOT add them to this policy by script: the
#     provider rebuilds sessionControls from scratch on every update, so the
#     next apply would very likely wipe them (verify). Such controls live in
#     their own Graph-managed policy under their own number. Token protection
#     also does not cover the Entra / M365 admin centers (Learn, 2026-08-14).
#   * Persistent-browser "never": Graph/Learn require All resources for it,
#     and this policy is scoped to the admin portals.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "admin_session_controls" {
  count = var.enable_admin_session_controls ? 1 : 0

  display_name = "${var.policy_name_prefix}020 - Require sign-in every ${var.admin_session_sign_in_frequency_hours}h on admin portals for Tier-0/1 admins"
  state        = local.ca020_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = var.admin_portal_applications
    }

    users {
      included_roles  = var.admin_session_role_template_ids
      included_groups = local.admin_scope_group_ids
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  session_controls {
    sign_in_frequency        = var.admin_session_sign_in_frequency_hours
    sign_in_frequency_period = "hours"
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA020")
      error_message = "enable_admin_session_controls = true requires an explicit CA020 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }
  }
}

# -----------------------------------------------------------------------------
# CA021 - Require the ADMIN phishing-resistant strength, with a fresh sign-in
# every time, for PRIVILEGED ROLE ACTIVATION (authentication context c1).
#
# WHY GRAPH, NOT A RESOURCE: azuread 3.10.0 (the latest release) has no
# authenticationContextClassReference resource, and its applications block
# cannot target an authentication context (included_applications /
# included_user_actions are ExactlyOneOf; the SDK's
# IncludeAuthenticationContextClassReferences is never exposed). So, like the
# access reviews in modules/entitlement, Terraform RENDERS the two Graph v1.0
# request bodies from real ids (output pim_auth_context_requests) and
# post-apply/Set-AuthContextPolicies.ps1:
#   1. PATCH /identity/conditionalAccess/authenticationContextClassReferences/c1
#      (create-or-update; isAvailable = true, or PIM cannot use it), then
#   2. creates or updates CA021, matched by its "CA021 - " display-name prefix.
# The definition stays code-reviewed in this file; only the HTTP call is not.
#
# SHAPE (Learn: PIM for Groups role settings, auth context guidance):
#   * Users: All users minus break-glass. NEVER the PIM group itself - the
#     requester is not a member yet while activating. An auth-context policy
#     only fires when a resource (PIM) asks for the context, so "All users"
#     changes nothing at ordinary sign-in.
#   * Grant: the ADMIN strength (narrowed to issued key models by
#     admin_fido2_allowed_aaguids), by bare object id - Graph's
#     authenticationStrength.id.
#   * Session: sign-in frequency "every time", so each activation forces a
#     fresh phishing-resistant sign-in. verify: the Graph
#     signInFrequencySessionControl page lists a narrower set of every-time
#     cases than Learn (which names "privileged role elevation in PIM").
#   * No compliant-device grant: it would lock the operator's unmanaged Mac out
#     of activation exactly as CA005 would. Add it once PAWs exist.
#
# ORDER (Learn): create and ENABLE the CA policy before PIM requires the
# context. Learn, PIM for Groups role settings
# (learn.microsoft.com/entra/id-governance/privileged-identity-management/groups-role-settings):
# the MFA backup "isn't triggered if the Conditional Access policy is turned
# off, is in report-only mode, or has an eligible user excluded". So a
# report-only (or not yet written) CA021 behind the context leaves activation
# with NO step-up at all - weaker than today's MFA flag.
#
# THE GATE CHECKS TENANT STATE, NOT ONLY CODE. `terraform apply` writes the
# Tier-0 PIM policies; post-apply/Set-AuthContextPolicies.ps1 writes CA021
# only AFTER the apply. So "CA021 = enabled" in the same change that sets the
# PIM context is not enough: during that apply the tenant still holds the
# report-only CA021. output pim_activation_auth_context_ready is therefore
# true only when CA021 is declared "enabled" AND var.ca021_enforced_in_tenant
# (a human attestation, set in a LATER change after the script reported
# CA021 enabled in the tenant). The module refuses a plan where modules/pim
# would use the context without both. Switching a tier from MFA to c1 is two
# applies in modules/pim (MFA false first, then the context) - see that module.
#
# verify (first tenant run): Graph v1.0 accepting
# includeAuthenticationContextClassReferences on POST (it is in the live v1.0
# $metadata; the v1.0 docs page lists it under beta - the script has
# -GraphVersion beta for that case), and whether includeApplications must be
# present, empty or omitted.
# -----------------------------------------------------------------------------
locals {
  ca021_display_name = "${var.policy_name_prefix}021 - Require phishing-resistant strength for privileged role activation (auth context ${var.pim_auth_context_id})"

  # Graph authenticationContextClassReference (PATCH .../authenticationContextClassReferences/<id>).
  ca021_auth_context_body = {
    displayName = "Privileged role activation"
    description = "PIM Tier-0 activation step-up: phishing-resistant strength, fresh sign-in (${var.policy_name_prefix}021)"
    isAvailable = true
  }

  # Graph conditionalAccessPolicy (POST/PATCH /identity/conditionalAccess/policies).
  ca021_policy_body = {
    displayName = local.ca021_display_name
    state       = local.ca021_state
    conditions = {
      clientAppTypes = ["all"]
      applications = {
        includeAuthenticationContextClassReferences = [var.pim_auth_context_id]
      }
      users = {
        includeUsers  = ["All"]
        excludeGroups = [var.break_glass_group_object_id]
      }
    }
    grantControls = {
      operator = "OR"
      authenticationStrength = {
        id = azuread_authentication_strength_policy.phishing_resistant.object_id
      }
    }
    sessionControls = {
      signInFrequency = {
        isEnabled          = true
        frequencyInterval  = "everyTime"
        authenticationType = "primaryAndSecondaryAuthentication"
      }
    }
  }

  pim_auth_context_requests = var.enable_pim_auth_context ? {
    policy_key          = "CA021"
    auth_context_id     = var.pim_auth_context_id
    auth_context_body   = jsonencode(local.ca021_auth_context_body)
    policy_match_prefix = "${var.policy_name_prefix}021 - "
    policy_display_name = local.ca021_display_name
    policy_state        = local.ca021_state
    policy_body         = jsonencode(local.ca021_policy_body)
  } : null

  # True only when the code says CA021 is ENFORCED *and* the operator has
  # attested that the tenant already holds the enforced CA021 (written by the
  # post-apply script after an EARLIER apply). Declared state alone is not
  # enough: see ORDER above.
  pim_activation_auth_context_ready = var.enable_pim_auth_context && local.ca021_state == "enabled" && var.ca021_enforced_in_tenant
}

# -----------------------------------------------------------------------------
# CA023 - PROTECTED ACTIONS step-up: the ADMIN phishing-resistant strength, with
# a fresh sign-in every time, before anyone may UPDATE or DELETE a Conditional
# Access policy or a named location (authentication context c2).
#
# WHY: changing CA is the fastest way to switch the whole access model off,
# and today the lab only DETECTS it (lab/kql/ca-policy-changed.kql). Microsoft
# Entra "protected actions" bind a directory permission to an authentication
# context: whoever holds the permission must satisfy the context's CA policy
# at the moment of the change, even inside an already-signed-in session.
#
# SAME PATH AS CA021: the provider can create neither the context nor a policy
# that targets it, so Terraform RENDERS both bodies (output
# protected_actions_auth_context_requests) and
# post-apply/Set-AuthContextPolicies.ps1 writes them (it takes either output).
#
# TENANT-TIME (verify: the Graph shape on the first run): bind c2 to the
# protected actions, e.g. Entra admin center -> Roles & admins -> Protected
# actions, or Graph beta PATCH
#   /roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions/<id>
#   { "authenticationContextId": "c2" }
# for microsoft.directory/conditionalAccessPolicies/basic/update,
# .../conditionalAccessPolicies/delete, .../namedLocations/basic/update and
# .../namedLocations/delete. Do it only after CA023 is ENFORCED: with a
# report-only policy behind the context the step-up is not applied. Learn:
# break-glass must stay excluded (it is, below) so a broken CA021/CA023 can be
# repaired; and the CI APPLY identity is a workload identity, which
# user-scoped CA never covers - the pipeline keeps working.
# -----------------------------------------------------------------------------
locals {
  ca023_display_name = "${var.policy_name_prefix}023 - Require phishing-resistant strength for protected actions (auth context ${var.protected_actions_auth_context_id})"

  ca023_auth_context_body = {
    displayName = "Protected actions"
    description = "Step-up for Conditional Access policy and named-location changes: phishing-resistant strength, fresh sign-in (${var.policy_name_prefix}023)"
    isAvailable = true
  }

  ca023_policy_body = {
    displayName = local.ca023_display_name
    state       = local.ca023_state
    conditions = {
      clientAppTypes = ["all"]
      applications = {
        includeAuthenticationContextClassReferences = [var.protected_actions_auth_context_id]
      }
      users = {
        includeUsers  = ["All"]
        excludeGroups = [var.break_glass_group_object_id]
      }
    }
    grantControls = {
      operator = "OR"
      authenticationStrength = {
        id = azuread_authentication_strength_policy.phishing_resistant.object_id
      }
    }
    sessionControls = {
      signInFrequency = {
        isEnabled          = true
        frequencyInterval  = "everyTime"
        authenticationType = "primaryAndSecondaryAuthentication"
      }
    }
  }

  protected_actions_auth_context_requests = var.enable_protected_actions_ca ? {
    policy_key          = "CA023"
    auth_context_id     = var.protected_actions_auth_context_id
    auth_context_body   = jsonencode(local.ca023_auth_context_body)
    policy_match_prefix = "${var.policy_name_prefix}023 - "
    policy_display_name = local.ca023_display_name
    policy_state        = local.ca023_state
    policy_body         = jsonencode(local.ca023_policy_body)
  } : null
}

# -----------------------------------------------------------------------------
# CA022 - PAM session broker + admin portals require the ADMIN strength.
#
# The Tier-0 session door (guacamole-psm, the PSM stand-in that brokers DC01
# RDP and SSH: modules/apps, enable_pam_oidc_app) and the admin portals must
# demand the same assurance as an active admin role. CA002 cannot do it: it
# targets directory ROLES, and a PAM operator - or a PIM-eligible engineer
# BEFORE activation - holds none. CA008 cannot either: its workforce strength
# accepts synced passkeys. So CA022 targets the APPLICATIONS for every user
# and grants with the ADMIN strength (azuread_authentication_strength_policy.
# phishing_resistant, narrowed to issued key models by
# admin_fido2_allowed_aaguids).
#
# HONEST LIMIT: "device-bound only" is enforced at sign-in ONLY through that
# AAGUID allow-list (with attestation enforced in the Passkey policy), which
# means the organisation names - in practice buys - its key models. Without
# it CA022 still demands phishing-resistant MFA, but a synced passkey
# satisfies it. verify: whether authentication strengths can now distinguish
# synced from device-bound passkeys without AAGUIDs (passkey-profile
# targeting is a methods-policy feature, not a CA grant).
#
# EXCLUSIONS: break-glass; guests (no PAM access for external users).
# State: report-only first (policy_states CA022, required when the flag is on).
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "pam_session_admin_strength" {
  count = var.enable_pam_session_ca ? 1 : 0

  display_name = "${var.policy_name_prefix}022 - Require admin phishing-resistant strength for PAM session broker + admin portals"
  state        = local.ca022_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = distinct(concat(var.pam_session_app_ids, ["MicrosoftAdminPortals"]))
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_object_id]

      excluded_guests_or_external_users {
        guest_or_external_user_types = local.guest_or_external_user_types
        external_tenants {
          membership_kind = "all"
        }
      }
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = []
    authentication_strength_policy_id = azuread_authentication_strength_policy.phishing_resistant.id
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA022")
      error_message = "enable_pam_session_ca = true requires an explicit CA022 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state. (This policy was numbered CA009 before the CA design-principle ranges; CA009 is now security-info registration.)"
    }
  }
}
