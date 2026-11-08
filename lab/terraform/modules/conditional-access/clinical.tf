# =============================================================================
# modules/conditional-access :: clinical.tf
# -----------------------------------------------------------------------------
# Clinical and device range (060-079):
#
#   CA060  Shared clinical workstations: phishing-resistant strength, sign-in
#          every 8 h (one shift), browser sessions never persistent
#   CA061  Clinic Lab Results (moved from Okta): MFA, sign-in every 8 h
#
# Design: ADR 0014 (shared clinical workstation authentication). Clinical
# availability rule (CA design principles section 1): enforcement needs
# Clinical Operations sign-off and a documented fallback (a one-time TAP from
# the service desk, help-desk runbook level V2-C).
# =============================================================================

# -----------------------------------------------------------------------------
# CA060 - Require the workforce phishing-resistant strength on shared clinical
# workstations.
#
# DEVICE FILTER: device.enrollmentProfileName -eq "CH-SharedClinical".
#   * Users cannot change it (a display name can be renamed, so it is not used).
#   * Learn's device-filter table: the property is set ONLY from a Windows
#     Autopilot deployment profile (or Apple ADE / Google enrollment). ADR
#     0014's "dedicated Intune enrollment profile CH-SharedClinical" must
#     therefore be an AUTOPILOT DEPLOYMENT PROFILE. A station enrolled any
#     other way has a null value, and with a positive (include) operator the
#     policy then silently does NOT apply - check the Report-only tab shows
#     the stations before enforcing. verify: whether Autopilot device
#     preparation (v2) sets enrollmentProfileName.
#   * Removing the devices block later forces the provider to RECREATE the
#     policy (new id) - change the rule, do not drop the block.
#
# GRANT: the CA008 WORKFORCE strength (synced passkeys allowed, so a clinician
# can use a FIDO2 key or a badge-sized NFC key). It exists only while
# enable_phishing_resistant_all_users is on - precondition below.
#
# SESSION:
#   * sign-in frequency 8 hours = one shift. On Entra-joined Windows the
#     Primary Refresh Token is refreshed about every 4 hours by unlock /
#     sign-in and can satisfy the frequency, and Learn's known issue says the
#     strength and the frequency can be met at different times - so this
#     mostly bounds browser and app sessions. The REAL session control is the
#     5-minute screen lock, which is Intune, not CA: Settings catalog ->
#     Local Policies Security Options -> "Interactive Logon Machine
#     Inactivity Limit" = 300 seconds (CSP ./Device/Vendor/MSFT/Policy/Config/
#     LocalPoliciesSecurityOptions/InteractiveLogon_MachineInactivityLimit).
#   * persistent browser "never": the next clinician must never inherit a
#     browser session. Graph and Learn require All resources for this
#     control, hence included_applications = ["All"].
#
# OVERLAP WITH CA008: once CA008 is enforced for all users it already demands
# the strength everywhere. CA060's own value is the session controls, and
# letting Clinical Operations enforce station group by station group first.
#
# EXCLUSIONS: break-glass. Users are the clinical groups only - never "All".
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "shared_clinical_workstation" {
  count = var.enable_shared_clinical_ca ? 1 : 0

  display_name = "${var.policy_name_prefix}060 - Require phishing-resistant strength on shared clinical workstations"
  state        = local.ca060_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"] # persistent-browser control requires All resources
    }

    devices {
      filter {
        mode = "include"
        rule = "device.enrollmentProfileName -eq \"${var.ca060_enrollment_profile_name}\""
      }
    }

    users {
      included_groups = var.ca060_clinical_group_object_ids
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = [] # the authentication strength IS the control
    authentication_strength_policy_id = one(azuread_authentication_strength_policy.phishing_resistant_workforce[*].id)
  }

  session_controls {
    sign_in_frequency        = 8
    sign_in_frequency_period = "hours"
    persistent_browser_mode  = "never"
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA060")
      error_message = "enable_shared_clinical_ca = true requires an explicit CA060 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }

    precondition {
      condition     = var.enable_phishing_resistant_all_users
      error_message = "CA060 grants with the CA008 WORKFORCE phishing-resistant strength, which exists only while enable_phishing_resistant_all_users = true. Turn that on (CA008 can stay report-only) before enable_shared_clinical_ca."
    }

    precondition {
      condition     = length(var.ca060_clinical_group_object_ids) > 0
      error_message = "enable_shared_clinical_ca = true needs at least one clinical group in ca060_clinical_group_object_ids (CA060 never targets All users)."
    }
  }
}

# -----------------------------------------------------------------------------
# CA061 - Clinic Lab Results: require MFA and a fresh sign-in every 8 hours.
#
# WHY: the app moved from the clinic's Okta org to Entra (okta-migration wave
# 1, modules/apps clinic_results.tf). In Okta its authentication policy
# ("Clinic clinical apps", lab/terraform/okta clinic-apps.tf) said: two
# factors, re-authenticate after 8 hours, everyone else denied. CA061 is
# that rule in Entra, so the move keeps the control instead of quietly
# dropping it:
#   * "two factors"           -> the built-in Multifactor authentication
#                                strength (any MFA method);
#   * "re-auth after 8 hours" -> sign-in frequency 8 hours (one shift);
#   * "everyone else denied"  -> not CA's job: the enterprise app requires
#                                assignment, so a non-member gets no token
#                                (AADSTS50105) before CA runs.
# CA001 already asks every user for MFA; CA061's own value is the 8-hour
# session bound on this app, and that the control is named after the app a
# reviewer looks for.
#
# SCOPE: the app only (its client id), the app group only, break-glass
# excluded. Never All users, never All resources.
#
# STATE: enforced from the start in the lab (lab.tfvars CA061 = "enabled"),
# against this module's report-only-first default, on purpose: report-only
# would make the Entra side WEAKER than the Okta side it replaces during the
# cut-over. The blast radius is one app and its pilot group.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "clinic_results" {
  count = var.enable_clinic_results_ca ? 1 : 0

  display_name = "${var.policy_name_prefix}061 - Require MFA and sign-in every 8h for Clinic Lab Results"
  state        = local.ca061_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = var.ca061_app_ids
    }

    users {
      included_groups = var.ca061_group_object_ids
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = []
    authentication_strength_policy_id = "/policies/authenticationStrengthPolicies/00000000-0000-0000-0000-000000000002" # built-in "Multifactor authentication"
  }

  session_controls {
    sign_in_frequency        = 8
    sign_in_frequency_period = "hours"
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA061")
      error_message = "enable_clinic_results_ca = true requires an explicit CA061 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }

    precondition {
      condition     = length(var.ca061_app_ids) == 1 && !contains(var.ca061_app_ids, "All")
      error_message = "CA061 targets exactly one app, Clinic Lab Results (ca061_app_ids = [its client id]); never All resources."
    }

    precondition {
      condition     = length(var.ca061_group_object_ids) > 0
      error_message = "CA061 needs the app group in ca061_group_object_ids (never All users)."
    }
  }
}
