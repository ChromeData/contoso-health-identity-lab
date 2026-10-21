# CA006 / CA007 - risk-based Conditional Access (Entra ID P2), mocked.
# Run offline: terraform init -backend=false && terraform test
#
# What these runs pin down, and why each matters on a real tenant:
#   * flag off => the module is exactly the five-policy module (no surprise
#     resources the day the flag PR is merged by mistake);
#   * report-only by default and break-glass excluded (lockout safety);
#   * CA006's grant matches Graph's hard rules for passwordChange (paired with
#     mfa under AND, All applications, no extra conditions) plus Microsoft's
#     "sign-in frequency every time" - a policy Graph would reject, or one an
#     old session could satisfy, fails here instead of at apply;
#   * guests are excluded from CA006 (they cannot remediate in our tenant) but
#     NOT from CA007 (blocking needs nothing from them);
#   * a flag turned on without its state key, or a bad risk-level list, is
#     refused at plan.

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

variables {
  break_glass_group_object_id = "22222222-2222-2222-2222-222222222222"
  ca005_pilot_group_object_id = "33333333-3333-3333-3333-333333333333"
}

run "flags_off_creates_no_risk_policies" {
  command = plan

  assert {
    condition     = length(coalesce(azuread_conditional_access_policy.user_risk_high_remediation, [])) == 0 && length(coalesce(azuread_conditional_access_policy.sign_in_risk_block, [])) == 0
    error_message = "CA006/CA007 must not exist while enable_identity_protection_ca is false."
  }
}

run "risk_policies_report_only_with_safe_shape" {
  command = apply

  variables {
    enable_identity_protection_ca = true
  }

  # --- CA006 -----------------------------------------------------------------
  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA006 must default to report-only."
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].display_name == "CA006 - User risk high - require MFA + secure password change"
    error_message = "CA006 display name drifted from the shared contract name."
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].user_risk_levels == tolist(["high"])
    error_message = "CA006 must trigger on user risk High only."
  }

  assert {
    condition     = length(coalesce(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].sign_in_risk_levels, [])) == 0
    error_message = "CA006 must not mix in sign-in risk (Graph allows only users, applications and userRiskLevels with passwordChange)."
  }

  assert {
    condition = (
      length(coalesce(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].locations, [])) == 0 &&
      length(coalesce(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].platforms, [])) == 0 &&
      length(coalesce(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].devices, [])) == 0
    )
    error_message = "CA006 must carry no location/platform/device condition (Graph rejects them with passwordChange)."
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].applications[0].included_applications == tolist(["All"]) && length(coalesce(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].applications[0].excluded_applications, [])) == 0
    error_message = "CA006 must target All applications with no exclusions (Graph requirement for passwordChange)."
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].grant_controls[0].operator == "AND" && toset(azuread_conditional_access_policy.user_risk_high_remediation[0].grant_controls[0].built_in_controls) == toset(["mfa", "passwordChange"])
    error_message = "CA006 grant must be mfa AND passwordChange."
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].session_controls[0].sign_in_frequency_interval == "everyTime" && azuread_conditional_access_policy.user_risk_high_remediation[0].session_controls[0].sign_in_frequency_authentication_type == "primaryAndSecondaryAuthentication"
    error_message = "CA006 must force a fresh sign-in (sign-in frequency every time, primary + secondary)."
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].users[0].included_users == tolist(["All"]) && contains(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].users[0].excluded_groups, "22222222-2222-2222-2222-222222222222")
    error_message = "CA006 must include All users and exclude break-glass."
  }

  assert {
    condition = (
      length(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].users[0].excluded_guests_or_external_users) == 1 &&
      length(azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].users[0].excluded_guests_or_external_users[0].guest_or_external_user_types) == 6 &&
      azuread_conditional_access_policy.user_risk_high_remediation[0].conditions[0].users[0].excluded_guests_or_external_users[0].external_tenants[0].membership_kind == "all"
    )
    error_message = "CA006 must exclude every guest/external user type from all tenants (they cannot remediate in a resource tenant)."
  }

  # --- CA007 -----------------------------------------------------------------
  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA007 must default to report-only."
  }

  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].display_name == "CA007 - Sign-in risk high - block"
    error_message = "CA007 display name drifted from the shared contract name."
  }

  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].conditions[0].sign_in_risk_levels == tolist(["high"]) && length(coalesce(azuread_conditional_access_policy.sign_in_risk_block[0].conditions[0].user_risk_levels, [])) == 0
    error_message = "CA007 must trigger on sign-in risk High only."
  }

  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].grant_controls[0].built_in_controls == tolist(["block"])
    error_message = "CA007 grant must be block."
  }

  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].conditions[0].users[0].included_users == tolist(["All"]) && contains(azuread_conditional_access_policy.sign_in_risk_block[0].conditions[0].users[0].excluded_groups, "22222222-2222-2222-2222-222222222222")
    error_message = "CA007 must include All users and exclude break-glass."
  }

  assert {
    condition     = length(coalesce(azuread_conditional_access_policy.sign_in_risk_block[0].conditions[0].users[0].excluded_guests_or_external_users, [])) == 0
    error_message = "CA007 must NOT exclude guests: blocking a risky guest sign-in needs nothing from the guest."
  }

  # --- outputs ---------------------------------------------------------------
  assert {
    condition     = output.policy_display_names["CA007"] == "CA007 - Sign-in risk high - block" && output.policy_ids["user_risk_high_remediation"] != null
    error_message = "Outputs must expose the deployed CA006/CA007 ids and names."
  }
}

run "risk_states_follow_policy_states_map" {
  command = plan

  variables {
    enable_identity_protection_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA006 = "disabled"
      CA007 = "enabled"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.user_risk_high_remediation[0].state == "disabled" && azuread_conditional_access_policy.sign_in_risk_block[0].state == "enabled"
    error_message = "CA006/CA007 states must come from policy_states."
  }
}

# The committed five-key lab.tfvars still plans while the flag is off ...
run "five_key_map_ok_while_flag_off" {
  command = plan

  variables {
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }
}

# ... but turning the flag on without CA006/CA007 entries is refused.
run "flag_on_without_state_keys_is_refused" {
  command = plan

  variables {
    enable_identity_protection_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [
    azuread_conditional_access_policy.user_risk_high_remediation,
    azuread_conditional_access_policy.sign_in_risk_block,
  ]
}

run "unknown_state_key_is_refused" {
  command = plan

  variables {
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA09  = "enabled"
    }
  }

  expect_failures = [var.policy_states]
}

# Report-only simulation knob: the name must follow the levels it matches.
run "ca007_medium_test_knob_renames_policy" {
  command = plan

  variables {
    enable_identity_protection_ca = true
    sign_in_risk_block_levels     = ["high", "medium"]
  }

  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].display_name == "CA007 - Sign-in risk medium+high - block"
    error_message = "CA007's display name must list every level it blocks, in low->high order."
  }

  assert {
    condition     = azuread_conditional_access_policy.sign_in_risk_block[0].conditions[0].sign_in_risk_levels == tolist(["medium", "high"])
    error_message = "CA007 must block exactly the configured levels."
  }
}

run "ca007_levels_without_high_are_refused" {
  command = plan

  variables {
    enable_identity_protection_ca = true
    sign_in_risk_block_levels     = ["medium"]
  }

  expect_failures = [var.sign_in_risk_block_levels]
}
