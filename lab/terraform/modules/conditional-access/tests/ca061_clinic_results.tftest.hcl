# CA061 - Clinic Lab Results, the first app moved from the clinic's Okta
# (modules/apps clinic_results.tf, lab/okta-migration wave 1). Mocked; no
# tenant. Run offline: terraform init -backend=false && terraform test
#
# What these runs pin down:
#   * off by default (no policy, null outputs);
#   * on: the ONE app and its ONE group, break-glass excluded, never All;
#   * grant = the built-in Multifactor authentication strength; session =
#     sign-in every 8 hours (the Okta rule "re-authenticate after 8 hours");
#   * state from policy_states CA061 (report-only when the key says so,
#     enforced when it says "enabled"); the key is required while on;
#   * All resources, two apps, or no group fail the plan.

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

variables {
  break_glass_group_object_id = "22222222-2222-2222-2222-222222222222"
  ca005_pilot_group_object_id = "33333333-3333-3333-3333-333333333333"
  ca061_app_ids               = ["abababab-abab-abab-abab-abababababab"]
  ca061_group_object_ids      = ["cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd"]
}

run "ca061_off_by_default" {
  command = plan

  assert {
    condition     = length(azuread_conditional_access_policy.clinic_results) == 0 && output.policy_ids["clinic_results"] == null && output.policy_display_names["CA061"] == null
    error_message = "CA061 must not exist until enable_clinic_results_ca."
  }
}

run "ca061_one_app_one_group_mfa_and_8h" {
  command = apply

  variables {
    enable_clinic_results_ca = true
    policy_states = {
      CA001 = "enabled"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabled"
      CA004 = "enabled"
      CA005 = "enabled"
      CA061 = "enabled"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.clinic_results[0].state == "enabled"
    error_message = "CA061 must take its state from policy_states (lab.tfvars enforces it from the start)."
  }
  assert {
    condition     = azuread_conditional_access_policy.clinic_results[0].display_name == "CA061 - Require MFA and sign-in every 8h for Clinic Lab Results"
    error_message = "CA061's display name must name the app."
  }
  assert {
    condition     = one(one(azuread_conditional_access_policy.clinic_results[0].conditions).applications).included_applications == tolist(["abababab-abab-abab-abab-abababababab"])
    error_message = "CA061 must target exactly the Clinic Lab Results client id."
  }
  assert {
    condition = (
      one(one(azuread_conditional_access_policy.clinic_results[0].conditions).users).included_groups == tolist(["cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd"])
      && one(one(azuread_conditional_access_policy.clinic_results[0].conditions).users).excluded_groups == tolist(["22222222-2222-2222-2222-222222222222"])
      && length(coalesce(one(one(azuread_conditional_access_policy.clinic_results[0].conditions).users).included_users, [])) == 0
    )
    error_message = "CA061 must include only the app group and exclude break-glass; never All users."
  }
  assert {
    condition     = one(azuread_conditional_access_policy.clinic_results[0].grant_controls).authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/00000000-0000-0000-0000-000000000002"
    error_message = "CA061's grant must be the built-in Multifactor authentication strength."
  }
  assert {
    condition     = one(azuread_conditional_access_policy.clinic_results[0].session_controls).sign_in_frequency == 8 && one(azuread_conditional_access_policy.clinic_results[0].session_controls).sign_in_frequency_period == "hours"
    error_message = "CA061 must ask for a fresh sign-in every 8 hours (the Okta rule it replaces)."
  }
}

run "ca061_report_only_when_the_key_says_so" {
  command = plan

  variables {
    enable_clinic_results_ca = true
    policy_states = {
      CA001 = "enabled"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabled"
      CA004 = "enabled"
      CA005 = "enabled"
      CA061 = "enabledForReportingButNotEnforced"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.clinic_results[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA061 must follow its policy_states entry."
  }
}

run "ca061_needs_its_state_key" {
  command = plan

  variables {
    enable_clinic_results_ca = true
    policy_states = {
      CA001 = "enabled"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabled"
      CA004 = "enabled"
      CA005 = "enabled"
    }
  }

  expect_failures = [azuread_conditional_access_policy.clinic_results]
}

run "ca061_refuses_all_resources" {
  command = plan

  variables {
    enable_clinic_results_ca = true
    ca061_app_ids            = ["All"]
    policy_states            = { CA001 = "enabled", CA002 = "enabled", CA003 = "enabled", CA004 = "enabled", CA005 = "enabled", CA061 = "enabled" }
  }

  expect_failures = [azuread_conditional_access_policy.clinic_results]
}

run "ca061_refuses_two_apps" {
  command = plan

  variables {
    enable_clinic_results_ca = true
    ca061_app_ids            = ["abababab-abab-abab-abab-abababababab", "efefefef-efef-efef-efef-efefefefefef"]
    policy_states            = { CA001 = "enabled", CA002 = "enabled", CA003 = "enabled", CA004 = "enabled", CA005 = "enabled", CA061 = "enabled" }
  }

  expect_failures = [azuread_conditional_access_policy.clinic_results]
}

run "ca061_refuses_no_group" {
  command = plan

  variables {
    enable_clinic_results_ca = true
    ca061_group_object_ids   = []
    policy_states            = { CA001 = "enabled", CA002 = "enabled", CA003 = "enabled", CA004 = "enabled", CA005 = "enabled", CA061 = "enabled" }
  }

  expect_failures = [azuread_conditional_access_policy.clinic_results]
}
