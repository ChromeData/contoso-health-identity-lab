# CA008 - phishing-resistant authentication strength for the workforce, plus
# the optional admin key-model restriction on CA002's strength. Mocked.
# Run offline: terraform init -backend=false && terraform test
#
# What these runs pin down:
#   * flag off => no CA008, no workforce strength, no pilot group;
#   * default = report-only MEASUREMENT across all users, with break-glass and
#     every guest/external type excluded, using the WORKFORCE strength (not
#     the admin one - they are separate so admins can be narrowed alone);
#   * pilot scope includes only the pilot group (module-created or supplied);
#   * tenant-wide enforcement needs the separate acknowledgement variable;
#   * a "phishing-resistant" strength cannot be fed a phishable combination;
#   * break-glass is excluded from EVERY policy with every flag on.
#
# The two strengths get distinct ids via override_resource so an assert can
# tell which one CA008 points at.

mock_provider "azuread" {
  mock_resource "azuread_authentication_strength_policy" {
    defaults = {
      id        = "/policies/authenticationStrengthPolicies/44444444-4444-4444-4444-444444444444"
      object_id = "44444444-4444-4444-4444-444444444444"
    }
  }
  mock_resource "azuread_named_location" {
    defaults = {
      id        = "/identity/conditionalAccess/namedLocations/11111111-1111-1111-1111-111111111111"
      object_id = "11111111-1111-1111-1111-111111111111"
    }
  }
  mock_resource "azuread_group" {
    defaults = {
      object_id = "88888888-8888-8888-8888-888888888888"
    }
  }
}

override_resource {
  target = azuread_authentication_strength_policy.phishing_resistant_workforce
  values = {
    id        = "/policies/authenticationStrengthPolicies/55555555-5555-5555-5555-555555555555"
    object_id = "55555555-5555-5555-5555-555555555555"
  }
}

variables {
  break_glass_group_object_id = "22222222-2222-2222-2222-222222222222"
  ca005_pilot_group_object_id = "33333333-3333-3333-3333-333333333333"
  # The workforce rollout needs the admin key-model allow-list (or an explicit
  # risk acceptance) - see workforce_rollout_without_admin_aaguids_is_refused.
  admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
}

run "flag_off_creates_nothing" {
  command = plan

  variables {
    admin_fido2_allowed_aaguids = []
  }

  assert {
    condition = (
      length(coalesce(azuread_conditional_access_policy.phishing_resistant_all_users, [])) == 0 &&
      length(coalesce(azuread_authentication_strength_policy.phishing_resistant_workforce, [])) == 0 &&
      length(coalesce(azuread_group.ca008_pilot, [])) == 0 &&
      length(coalesce(azuread_authentication_strength_policy_fido2_combination_configuration.admin_device_bound, [])) == 0
    )
    error_message = "With every new flag off the module must create none of the CA008 / admin-AAGUID resources."
  }

  assert {
    condition     = output.ca008_pilot_group_object_id == null && output.workforce_authentication_strength_policy_id == null
    error_message = "CA008 outputs must be null while the flag is off."
  }
}

run "default_measures_all_users_report_only" {
  command = apply

  variables {
    enable_phishing_resistant_all_users = true
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA008 must default to report-only."
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].display_name == "CA008 - Phishing-resistant authentication strength - all users (report-only)"
    error_message = "CA008's name must state its real scope and state (default: all users, report-only)."
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].included_users == tolist(["All"]) && length(coalesce(azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].included_groups, [])) == 0
    error_message = "Default CA008 scope must be All users (measurement), with no group include."
  }

  assert {
    condition     = contains(azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].excluded_groups, "22222222-2222-2222-2222-222222222222")
    error_message = "CA008 must exclude break-glass."
  }

  assert {
    condition = (
      length(azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].excluded_guests_or_external_users) == 1 &&
      length(azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].excluded_guests_or_external_users[0].guest_or_external_user_types) == 6
    )
    error_message = "CA008 must exclude every guest/external user type (they can only satisfy a phishing-resistant strength from their home tenant)."
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].grant_controls[0].authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/55555555-5555-5555-5555-555555555555"
    error_message = "CA008 must require the WORKFORCE strength, not the admin strength."
  }

  assert {
    condition     = length(coalesce(azuread_conditional_access_policy.phishing_resistant_all_users[0].grant_controls[0].built_in_controls, [])) == 0
    error_message = "CA008's only control must be the authentication strength (no generic mfa OR-ed in)."
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_phishing_resistant.grant_controls[0].authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/44444444-4444-4444-4444-444444444444"
    error_message = "CA002 must keep the admin strength."
  }

  assert {
    condition     = azuread_group.ca008_pilot[0].display_name == "CA008-Pilot-PhishingResistant" && azuread_group.ca008_pilot[0].mail_nickname == "ca008-pilot-phishingresistant" && azuread_group.ca008_pilot[0].security_enabled
    error_message = "The module must create the CA008 pilot security group under its contract name and mail_nickname."
  }

  assert {
    condition     = output.ca008_pilot_group_object_id == "88888888-8888-8888-8888-888888888888" && output.ca008_scope == "all_users"
    error_message = "Outputs must expose the pilot group id and the CA008 scope."
  }
}

run "pilot_scope_targets_module_group_only" {
  command = apply

  variables {
    enable_phishing_resistant_all_users = true
    ca008_scope                         = "pilot"
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].included_groups == tolist(["88888888-8888-8888-8888-888888888888"]) && length(coalesce(azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].included_users, [])) == 0
    error_message = "Pilot scope must include only the module's pilot group."
  }
}

run "supplied_pilot_group_is_used_and_not_created" {
  command = apply

  variables {
    enable_phishing_resistant_all_users = true
    ca008_scope                         = "pilot"
    ca008_pilot_group_object_id         = "99999999-9999-9999-9999-999999999999"
  }

  assert {
    condition     = length(coalesce(azuread_group.ca008_pilot, [])) == 0
    error_message = "A supplied pilot group must suppress the module-created one."
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].conditions[0].users[0].included_groups == tolist(["99999999-9999-9999-9999-999999999999"])
    error_message = "Pilot scope must include the supplied group."
  }
}

# Roots often default optional ids to "" - that must mean "not supplied".
run "empty_string_pilot_means_module_group" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    ca008_pilot_group_object_id         = ""
  }

  assert {
    condition     = length(azuread_group.ca008_pilot) == 1
    error_message = "An empty pilot id must fall back to the module-created group."
  }
}

run "pilot_enforcement_is_allowed" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    ca008_scope                         = "pilot"
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA008 = "enabled"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].state == "enabled"
    error_message = "Enforcing CA008 for the pilot must be a single state flip."
  }
  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].display_name == "CA008 - Phishing-resistant authentication strength - pilot group (enforced)"
    error_message = "An enforced pilot CA008 must not be named 'report-only' or 'all users' (sign-in logs and screenshots read the name)."
  }
}

run "all_users_enforcement_without_ack_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    ca008_scope                         = "all_users"
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA008 = "enabled"
    }
  }

  expect_failures = [azuread_conditional_access_policy.phishing_resistant_all_users]
}

run "all_users_enforcement_with_ack_is_allowed" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    ca008_scope                         = "all_users"
    ca008_allow_all_users_enforcement   = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA008 = "enabled"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].state == "enabled"
    error_message = "With the acknowledgement set, tenant-wide enforcement must plan."
  }
  assert {
    condition     = azuread_conditional_access_policy.phishing_resistant_all_users[0].display_name == "CA008 - Phishing-resistant authentication strength - all users (enforced)"
    error_message = "Tenant-wide enforced CA008 must be named as such."
  }
}

run "flag_on_without_ca008_key_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [azuread_conditional_access_policy.phishing_resistant_all_users]
}

run "phishable_workforce_combination_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users       = true
    workforce_phishing_resistant_combinations = ["fido2", "password,microsoftAuthenticatorPush"]
  }

  expect_failures = [var.workforce_phishing_resistant_combinations]
}

run "phishable_admin_combination_is_refused" {
  command = plan

  variables {
    phishing_resistant_combinations = ["password,sms"]
  }

  expect_failures = [var.phishing_resistant_combinations]
}

run "admin_aaguid_restriction_uses_bare_object_id" {
  command = apply

  variables {
    admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
  }

  assert {
    condition     = azuread_authentication_strength_policy_fido2_combination_configuration.admin_device_bound[0].authentication_strength_policy_id == "44444444-4444-4444-4444-444444444444"
    error_message = "The AAGUID restriction must attach to the ADMIN strength by bare object_id (GUID), not the path-form id."
  }
}

run "admin_aaguid_restriction_needs_fido2" {
  command = plan

  variables {
    phishing_resistant_combinations = ["windowsHelloForBusiness", "x509CertificateMultiFactor"]
    admin_fido2_allowed_aaguids     = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
  }

  expect_failures = [azuread_authentication_strength_policy_fido2_combination_configuration.admin_device_bound]
}

# Lockout regression guard: every policy, every flag on, break-glass excluded -
# the Terraform-managed ones AND the Graph-managed CA021 body Terraform renders.
run "break_glass_excluded_from_every_policy" {
  command = apply

  variables {
    enable_identity_protection_ca       = true
    enable_phishing_resistant_all_users = true
    enable_pam_session_ca               = true
    enable_registration_ca              = true
    enable_device_code_block            = true
    enable_admin_session_controls       = true
    enable_pim_auth_context             = true
    enable_protected_actions_ca         = true
    enable_shared_clinical_ca           = true
    ca060_clinical_group_object_ids     = ["66666666-6666-6666-6666-666666666666"]
    enable_clinic_results_ca            = true
    ca061_app_ids                       = ["abababab-abab-abab-abab-abababababab"]
    ca061_group_object_ids              = ["cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd"]
    ca008_scope                         = "pilot"
  }

  assert {
    condition = alltrue([
      for p in [
        azuread_conditional_access_policy.require_mfa_all_users,
        azuread_conditional_access_policy.admin_phishing_resistant,
        azuread_conditional_access_policy.block_legacy_auth,
        azuread_conditional_access_policy.block_countries,
        azuread_conditional_access_policy.admin_portals_compliant_device,
        azuread_conditional_access_policy.user_risk_high_remediation[0],
        azuread_conditional_access_policy.sign_in_risk_block[0],
        azuread_conditional_access_policy.phishing_resistant_all_users[0],
        azuread_conditional_access_policy.register_security_info[0],
        azuread_conditional_access_policy.block_device_code_flow[0],
        azuread_conditional_access_policy.admin_session_controls[0],
        azuread_conditional_access_policy.pam_session_admin_strength[0],
        azuread_conditional_access_policy.shared_clinical_workstation[0],
        azuread_conditional_access_policy.clinic_results[0],
      ] : contains(p.conditions[0].users[0].excluded_groups, "22222222-2222-2222-2222-222222222222")
    ])
    error_message = "Break-glass must be excluded from every Terraform-managed Conditional Access policy (CA001..CA010, CA020, CA022, CA060, CA061)."
  }

  assert {
    condition = (
      contains(jsondecode(output.pim_auth_context_requests.policy_body).conditions.users.excludeGroups, "22222222-2222-2222-2222-222222222222") &&
      contains(jsondecode(output.protected_actions_auth_context_requests.policy_body).conditions.users.excludeGroups, "22222222-2222-2222-2222-222222222222")
    )
    error_message = "The rendered CA021 and CA023 bodies must exclude break-glass too."
  }

  assert {
    condition     = length(output.policy_display_names) == 16
    error_message = "With every flag on, all 16 policy keys (14 Terraform-managed + CA021 and CA023 rendered) must have a name."
  }

  assert {
    condition = alltrue([
      for k, v in output.policy_display_names : v != null && startswith(v, "${k} - ")
    ])
    error_message = "Every deployed policy's display name must start with its CA key (detections and evidence match on it)."
  }

  assert {
    condition = alltrue([
      for k, v in output.policy_ids : v != null
    ])
    error_message = "With every flag on, every Terraform-managed policy id must be set."
  }
}

# --- admin assurance under the workforce rollout ----------------------------
run "workforce_rollout_without_admin_aaguids_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    admin_fido2_allowed_aaguids         = []
  }

  expect_failures = [azuread_authentication_strength_policy.phishing_resistant_workforce]
}

run "workforce_rollout_with_recorded_risk_acceptance_plans" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    admin_fido2_allowed_aaguids         = []
    accept_admin_synced_passkey_risk    = true
  }

  assert {
    condition     = length(azuread_authentication_strength_policy.phishing_resistant_workforce) == 1
    error_message = "With the explicit risk acceptance the rollout must plan."
  }
}

# --- CA022: PAM session broker + admin portals (numbered CA009 before the ranges)
run "ca022_off_by_default" {
  command = plan

  assert {
    condition     = length(azuread_conditional_access_policy.pam_session_admin_strength) == 0 && output.policy_ids["pam_session_admin_strength"] == null
    error_message = "CA022 must not exist until enable_pam_session_ca."
  }
}

run "ca022_targets_the_psm_app_and_admin_portals_with_the_admin_strength" {
  command = plan

  variables {
    enable_pam_session_ca = true
    pam_session_app_ids   = ["77777777-7777-7777-7777-777777777777"]
  }

  assert {
    condition = (
      contains(azuread_conditional_access_policy.pam_session_admin_strength[0].conditions[0].applications[0].included_applications, "77777777-7777-7777-7777-777777777777") &&
      contains(azuread_conditional_access_policy.pam_session_admin_strength[0].conditions[0].applications[0].included_applications, "MicrosoftAdminPortals")
    )
    error_message = "CA022 must target the PSM app and the admin portals."
  }
  assert {
    condition     = azuread_conditional_access_policy.pam_session_admin_strength[0].grant_controls[0].authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/44444444-4444-4444-4444-444444444444"
    error_message = "CA022 must require the ADMIN strength (the one narrowed to issued key models), not the workforce strength."
  }
  assert {
    condition = (
      azuread_conditional_access_policy.pam_session_admin_strength[0].state == "enabledForReportingButNotEnforced" &&
      tolist(azuread_conditional_access_policy.pam_session_admin_strength[0].conditions[0].users[0].included_users) == tolist(["All"]) &&
      length(azuread_conditional_access_policy.pam_session_admin_strength[0].conditions[0].users[0].excluded_guests_or_external_users) == 1
    )
    error_message = "CA022: report-only first, every user (PAM operators hold no directory role), guests excluded."
  }
  assert {
    condition     = startswith(azuread_conditional_access_policy.pam_session_admin_strength[0].display_name, "CA022 - ")
    error_message = "The PAM session policy is CA022 (admin/privileged range); CA009 is security-info registration."
  }
}

run "ca022_without_key_is_refused" {
  command = plan

  variables {
    enable_pam_session_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      # An old caller still keying the PAM policy "CA009" must not plan it:
      # CA009 now governs security-info registration.
      CA009 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [azuread_conditional_access_policy.pam_session_admin_strength]
}
