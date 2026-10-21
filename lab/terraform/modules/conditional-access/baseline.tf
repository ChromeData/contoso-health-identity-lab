# =============================================================================
# modules/conditional-access :: baseline.tf
# -----------------------------------------------------------------------------
# Baseline-range policies (001-019, all users) added after CA001-CA008:
#
#   CA009  Register security info -> TAP or phishing-resistant strength
#   CA010  Block device code flow
#
# Both are behind their own staging flag (default off) and start REPORT-ONLY
# through policy_states, exactly like CA006-CA008: the policy_states key is
# required while the flag is on (precondition), and the lookup() fallback in
# main.tf is never applied.
# =============================================================================

# -----------------------------------------------------------------------------
# "Bootstrap and recovery" authentication strength (CA009 only).
#
# Microsoft Learn (authentication strength, how it works) documents this
# pattern for the registration user action: a one-time Temporary Access Pass
# OR a phishing-resistant method. A new joiner holds only the TAP the joiner
# flow issues; an existing user holds a passkey / Windows Hello / CBA. Either
# can register security info - a password plus a phishable second factor
# cannot, so a stolen password + SMS can never add an attacker's method.
#
# Multi-use TAP is deliberately absent: the lab issues ONE-TIME TAPs only
# (Set-AuthenticationMethodsPolicy.ps1 sets TapIsUsableOnce = $true), and the
# help-desk runbook forbids multi-use TAPs.
# -----------------------------------------------------------------------------
resource "azuread_authentication_strength_policy" "bootstrap_recovery" {
  count = var.enable_registration_ca ? 1 : 0

  display_name         = "Bootstrap and recovery (lab)"
  description          = "One-time TAP or a phishing-resistant method - CA009 (register security info) only"
  allowed_combinations = var.registration_strength_combinations
}

# -----------------------------------------------------------------------------
# CA009 - Require a TAP or a phishing-resistant method to REGISTER security
# info (user action "urn:user:registersecurityinfo").
#
# WHY: combined registration is the door to every other credential. Without a
# policy on it, anyone holding a password (+ an existing phishable factor)
# can add their own authenticator and keep it after the password is reset.
#
# SHAPE (Microsoft's "Securing security info registration" template, with
# two lab decisions):
#   * Users: All users; exclude break-glass and every guest/external type
#     (a TAP cannot be issued to a guest, so the strength is unattainable for
#     them - Microsoft's template excludes them too).
#   * Target: the user action, not cloud apps. The provider declares
#     included_user_actions ExactlyOneOf included_applications, so this
#     policy can never also target apps.
#   * Network: Microsoft's template excludes TRUSTED locations. The lab has
#     no trusted named location, so the condition is dropped and the policy
#     applies everywhere - stricter than the template.
#   * Grant: the bootstrap-and-recovery strength above. Never combine the
#     "mfa" grant with an authentication strength in one policy (Learn:
#     unsupported; the provider does not stop it).
#
# INTERPLAY:
#   * CA001 (MFA, All resources) still applies at registration and is met by
#     the TAP (the built-in MFA strength lists one-time TAP).
#   * CA008 enforced: in Interrupt mode a strength that targets the
#     registration user action is preferred over strengths on All resources,
#     so a joiner with only a TAP can register the passkey CA008 then wants.
#   * Every policy that targets the user action must be satisfied - keep this
#     the only one.
#   * Since 2026-07-06 (Learn) registration policies also govern Windows Hello
#     for Business and macOS Platform SSO registration. A password+push user
#     who provisions Windows Hello then needs a TAP or an existing
#     phishing-resistant method. MEASURE this in report-only before enforcing;
#     if the gap is real, the softer interim is Microsoft's built-in
#     "Multifactor authentication" strength - a reviewed code change to this
#     grant, never a default (registration_strength_combinations refuses
#     phishable combinations on purpose).
#
# LICENSING: Entra ID P1 (Conditional Access + authentication strengths).
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "register_security_info" {
  count = var.enable_registration_ca ? 1 : 0

  display_name = "${var.policy_name_prefix}009 - Require TAP or phishing-resistant strength to register security info"
  state        = local.ca009_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_user_actions = ["urn:user:registersecurityinfo"]
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
    built_in_controls                 = [] # the authentication strength IS the control
    authentication_strength_policy_id = azuread_authentication_strength_policy.bootstrap_recovery[0].id
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA009")
      error_message = "enable_registration_ca = true requires an explicit CA009 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }
  }
}

# -----------------------------------------------------------------------------
# CA010 - Block device code flow for all users.
#
# WHY: device code phishing ("enter this code at microsoft.com/devicelogin")
# hands the attacker the victim's tokens after a perfectly real MFA prompt.
# Few workloads need the flow; it closes CISA SCuBA MS.AAD.3.9.
#
# ATTRIBUTE: conditions.authentication_flow_transfer_methods (azuread 3.7.0+,
# set of "deviceCodeFlow" / "authenticationTransfer"). The provider joins the
# set into Graph conditions.authenticationFlows.transferMethods (a flags enum).
#
# OPERATOR GOTCHA - read before enforcing:
#   * The lab's own bootstrap uses device code: the operator's first
#     `az login --use-device-code` and Invoke-BaselineAssessment.ps1
#     -UseDeviceCode. Enforced CA010 breaks both. Switch those to interactive
#     browser sign-in first, or put the operator in a CA010-Exclusion-<reason>
#     group through the exception process (var.ca010_exception_group_object_ids).
#   * Protocol tracking: a session that STARTED with device code is blocked on
#     refresh too (AADSTS530036). Leaving report-only does not revoke tokens
#     already issued.
#   * Since September 2024 these policies also cover the Device Registration
#     Service - but only when the policy targets All resources (it does).
#     Exclude that service (var.ca010_excluded_applications) only if devices
#     are registered through device code.
#   * To retire CA010, set its state to "disabled"; do NOT delete the
#     transfer-methods attribute. verify: removing the attribute may send
#     authenticationFlows as nil and leave the condition behind in Graph.
#
# Guests are included: blocking a flow needs nothing from the guest.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "block_device_code_flow" {
  count = var.enable_device_code_block ? 1 : 0

  display_name = "${var.policy_name_prefix}010 - Block device code flow for all users"
  state        = local.ca010_state

  conditions {
    client_app_types                     = ["all"]
    authentication_flow_transfer_methods = ["deviceCodeFlow"]

    applications {
      included_applications = ["All"]
      excluded_applications = var.ca010_excluded_applications
    }

    users {
      included_users  = ["All"]
      excluded_groups = distinct(concat([var.break_glass_group_object_id], var.ca010_exception_group_object_ids))
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA010")
      error_message = "enable_device_code_block = true requires an explicit CA010 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }
  }
}
