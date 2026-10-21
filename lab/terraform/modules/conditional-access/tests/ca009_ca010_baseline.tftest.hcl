# CA009 (register security info -> TAP or phishing-resistant strength) and
# CA010 (block device code flow). Mocked; no tenant.
# Run offline: terraform init -backend=false && terraform test
#
# What these runs pin down:
#   * flags off => neither policy, nor the bootstrap strength, exists;
#   * report-only by default, and the policy_states key is required while the
#     flag is on (a missing key fails the plan instead of inheriting a state);
#   * break-glass excluded; CA009 also excludes every guest/external type;
#   * CA009 targets the registration USER ACTION (never apps) and grants with
#     the bootstrap strength by its path-form id - never "mfa" alongside it;
#   * the bootstrap strength holds one-time TAP + phishing-resistant methods
#     only; multi-use TAP and phishable combinations are refused;
#   * CA010 blocks exactly the deviceCodeFlow transfer method for all users and
#     all resources; exception groups only ADD exclusions next to break-glass.

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
}

override_resource {
  target = azuread_authentication_strength_policy.bootstrap_recovery
  values = {
    id        = "/policies/authenticationStrengthPolicies/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    object_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
  }
}

variables {
  break_glass_group_object_id = "22222222-2222-2222-2222-222222222222"
  ca005_pilot_group_object_id = "33333333-3333-3333-3333-333333333333"
}

run "new_flags_off_create_nothing" {
  command = plan

  assert {
    condition = (
      length(azuread_conditional_access_policy.register_security_info) == 0 &&
      length(azuread_authentication_strength_policy.bootstrap_recovery) == 0 &&
      length(azuread_conditional_access_policy.block_device_code_flow) == 0 &&
      length(azuread_conditional_access_policy.admin_session_controls) == 0 &&
      length(azuread_conditional_access_policy.pam_session_admin_strength) == 0 &&
      length(azuread_conditional_access_policy.shared_clinical_workstation) == 0
    )
    error_message = "With every new flag off the module must create none of CA009, CA010, CA020, CA022, CA060 or the bootstrap strength."
  }

  assert {
    condition = (
      output.policy_ids["register_security_info"] == null &&
      output.policy_ids["block_device_code_flow"] == null &&
      output.policy_display_names["CA009"] == null &&
      output.policy_display_names["CA010"] == null &&
      output.policy_display_names["CA021"] == null &&
      output.registration_authentication_strength_policy_id == null &&
      output.pim_auth_context_requests == null
    )
    error_message = "Outputs of flagged-off policies must be null."
  }
}

run "ca009_report_only_user_action_bootstrap_strength" {
  command = apply

  variables {
    enable_registration_ca = true
  }

  assert {
    condition     = azuread_conditional_access_policy.register_security_info[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA009 must default to report-only."
  }

  assert {
    condition     = azuread_conditional_access_policy.register_security_info[0].display_name == "CA009 - Require TAP or phishing-resistant strength to register security info"
    error_message = "CA009's display name must follow the CA naming standard."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.register_security_info[0].conditions[0].applications[0].included_user_actions == tolist(["urn:user:registersecurityinfo"]) &&
      length(coalesce(azuread_conditional_access_policy.register_security_info[0].conditions[0].applications[0].included_applications, [])) == 0
    )
    error_message = "CA009 must target only the 'Register security information' user action, never cloud apps."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.register_security_info[0].conditions[0].users[0].included_users == tolist(["All"]) &&
      azuread_conditional_access_policy.register_security_info[0].conditions[0].users[0].excluded_groups == tolist(["22222222-2222-2222-2222-222222222222"])
    )
    error_message = "CA009 must include All users and exclude exactly break-glass by group."
  }

  assert {
    condition = (
      length(azuread_conditional_access_policy.register_security_info[0].conditions[0].users[0].excluded_guests_or_external_users) == 1 &&
      length(azuread_conditional_access_policy.register_security_info[0].conditions[0].users[0].excluded_guests_or_external_users[0].guest_or_external_user_types) == 6 &&
      azuread_conditional_access_policy.register_security_info[0].conditions[0].users[0].excluded_guests_or_external_users[0].external_tenants[0].membership_kind == "all"
    )
    error_message = "CA009 must exclude every guest/external user type from every tenant (a TAP cannot be issued to a guest)."
  }

  assert {
    condition     = length(azuread_conditional_access_policy.register_security_info[0].conditions[0].locations) == 0
    error_message = "CA009 carries no location condition: the lab has no trusted location, so it applies everywhere (stricter than Microsoft's template)."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.register_security_info[0].grant_controls[0].authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" &&
      length(coalesce(azuread_conditional_access_policy.register_security_info[0].grant_controls[0].built_in_controls, [])) == 0
    )
    error_message = "CA009 must grant with the bootstrap strength (path-form id) and nothing else - never 'mfa' combined with a strength."
  }

  assert {
    condition = (
      azuread_authentication_strength_policy.bootstrap_recovery[0].allowed_combinations == toset(["temporaryAccessPassOneTime", "windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]) &&
      !contains(azuread_authentication_strength_policy.bootstrap_recovery[0].allowed_combinations, "temporaryAccessPassMultiUse")
    )
    error_message = "The bootstrap strength must be one-time TAP + phishing-resistant methods only."
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_phishing_resistant.grant_controls[0].authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/44444444-4444-4444-4444-444444444444"
    error_message = "CA002 must keep the ADMIN strength, not the bootstrap one."
  }

  assert {
    condition = (
      output.registration_authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" &&
      output.policy_display_names["CA009"] == azuread_conditional_access_policy.register_security_info[0].display_name
    )
    error_message = "CA009 outputs must expose its strength id and display name."
  }
}

run "ca009_without_key_is_refused" {
  command = plan

  variables {
    enable_registration_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [azuread_conditional_access_policy.register_security_info]
}

run "ca009_multi_use_tap_is_refused" {
  command = plan

  variables {
    enable_registration_ca             = true
    registration_strength_combinations = ["temporaryAccessPassOneTime", "temporaryAccessPassMultiUse", "fido2"]
  }

  expect_failures = [var.registration_strength_combinations]
}

run "ca009_phishable_combination_is_refused" {
  command = plan

  variables {
    enable_registration_ca             = true
    registration_strength_combinations = ["temporaryAccessPassOneTime", "password,sms"]
  }

  expect_failures = [var.registration_strength_combinations]
}

run "ca009_enforcement_is_a_single_state_flip" {
  command = plan

  variables {
    enable_registration_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA009 = "enabled"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.register_security_info[0].state == "enabled"
    error_message = "Graduating CA009 must be its own policy_states line."
  }
}

run "ca010_report_only_blocks_device_code_for_all" {
  command = apply

  variables {
    enable_device_code_block = true
  }

  assert {
    condition     = azuread_conditional_access_policy.block_device_code_flow[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA010 must default to report-only (enforcing it breaks the operator's device-code logins)."
  }

  assert {
    condition     = azuread_conditional_access_policy.block_device_code_flow[0].display_name == "CA010 - Block device code flow for all users"
    error_message = "CA010's display name must follow the CA naming standard."
  }

  assert {
    condition     = azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].authentication_flow_transfer_methods == toset(["deviceCodeFlow"])
    error_message = "CA010 must target exactly the deviceCodeFlow transfer method (authenticationTransfer is a separate decision)."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.block_device_code_flow[0].grant_controls[0].built_in_controls == tolist(["block"]) &&
      azuread_conditional_access_policy.block_device_code_flow[0].grant_controls[0].operator == "OR"
    )
    error_message = "CA010 must block."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].applications[0].included_applications == tolist(["All"]) &&
      length(coalesce(azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].applications[0].excluded_applications, [])) == 0 &&
      azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].client_app_types == tolist(["all"])
    )
    error_message = "CA010 must cover All resources (that also brings in the Device Registration Service) with no default app exclusion."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].users[0].included_users == tolist(["All"]) &&
      azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].users[0].excluded_groups == tolist(["22222222-2222-2222-2222-222222222222"])
    )
    error_message = "CA010 must include All users and, by default, exclude only break-glass."
  }
}

run "ca010_exception_group_is_added_next_to_break_glass" {
  command = plan

  variables {
    enable_device_code_block         = true
    ca010_exception_group_object_ids = ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
    ca010_excluded_applications      = ["cccccccc-cccc-cccc-cccc-cccccccccccc"]
  }

  assert {
    condition = (
      azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].users[0].excluded_groups == tolist(["22222222-2222-2222-2222-222222222222", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"])
    )
    error_message = "An exception group must be excluded IN ADDITION to break-glass, never instead of it."
  }

  assert {
    condition     = azuread_conditional_access_policy.block_device_code_flow[0].conditions[0].applications[0].excluded_applications == tolist(["cccccccc-cccc-cccc-cccc-cccccccccccc"])
    error_message = "ca010_excluded_applications must be passed through."
  }
}

run "ca010_without_key_is_refused" {
  command = plan

  variables {
    enable_device_code_block = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [azuread_conditional_access_policy.block_device_code_flow]
}

run "ca010_excluding_all_applications_is_refused" {
  command = plan

  variables {
    enable_device_code_block    = true
    ca010_excluded_applications = ["All"]
  }

  expect_failures = [var.ca010_excluded_applications]
}

run "policy_states_unknown_key_is_refused" {
  command = plan

  variables {
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA011 = "enabledForReportingButNotEnforced" # not a policy this module builds
    }
  }

  expect_failures = [var.policy_states]
}

run "policy_states_default_covers_every_new_key_report_only" {
  command = plan

  assert {
    condition = alltrue([
      for k in ["CA009", "CA010", "CA020", "CA021", "CA022", "CA060"] :
      output.policy_states[k] == "enabledForReportingButNotEnforced"
    ])
    error_message = "The module default must hold every new key as report-only."
  }
}
