# CA060 - shared clinical workstations (ADR 0014). Mocked; no tenant.
# Run offline: terraform init -backend=false && terraform test
#
# What these runs pin down:
#   * off by default; report-only when on; policy_states key required;
#   * device filter = enrollmentProfileName equals the Autopilot profile
#     (include mode), never a renamable display name;
#   * the clinical groups only (never All users), break-glass excluded;
#   * grant = the CA008 WORKFORCE strength (path-form id), which must exist;
#   * session = sign-in every 8 hours + persistent browser never, on All
#     resources (the persistent-browser control requires All);
#   * the profile name cannot inject into the filter rule.

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
  # The workforce rollout (needed for CA060's strength) needs the admin
  # key-model allow-list - see the CA008 tests.
  admin_fido2_allowed_aaguids     = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
  ca060_clinical_group_object_ids = ["66666666-6666-6666-6666-666666666666", "77777777-7777-7777-7777-777777777777"]
}

run "ca060_off_by_default" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
  }

  assert {
    condition     = length(azuread_conditional_access_policy.shared_clinical_workstation) == 0 && output.policy_ids["shared_clinical_workstation"] == null && output.policy_display_names["CA060"] == null
    error_message = "CA060 must not exist until enable_shared_clinical_ca."
  }
}

run "ca060_report_only_device_filter_workforce_strength_session" {
  command = apply

  variables {
    enable_phishing_resistant_all_users = true
    enable_shared_clinical_ca           = true
  }

  assert {
    condition     = azuread_conditional_access_policy.shared_clinical_workstation[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA060 must default to report-only (enforcement needs Clinical Operations sign-off)."
  }

  assert {
    condition     = azuread_conditional_access_policy.shared_clinical_workstation[0].display_name == "CA060 - Require phishing-resistant strength on shared clinical workstations"
    error_message = "CA060's display name must be the ADR 0014 name."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].devices[0].filter[0].mode == "include" &&
      azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].devices[0].filter[0].rule == "device.enrollmentProfileName -eq \"CH-SharedClinical\""
    )
    error_message = "CA060 must include devices whose enrollmentProfileName is CH-SharedClinical (the Autopilot profile)."
  }

  assert {
    condition     = azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].applications[0].included_applications == tolist(["All"])
    error_message = "CA060 must target All resources (the persistent-browser control requires it)."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].users[0].included_groups == tolist(["66666666-6666-6666-6666-666666666666", "77777777-7777-7777-7777-777777777777"]) &&
      length(coalesce(azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].users[0].included_users, [])) == 0 &&
      azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].users[0].excluded_groups == tolist(["22222222-2222-2222-2222-222222222222"])
    )
    error_message = "CA060 must include only the clinical groups (never All users) and exclude break-glass."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.shared_clinical_workstation[0].grant_controls[0].authentication_strength_policy_id == "/policies/authenticationStrengthPolicies/55555555-5555-5555-5555-555555555555" &&
      length(coalesce(azuread_conditional_access_policy.shared_clinical_workstation[0].grant_controls[0].built_in_controls, [])) == 0
    )
    error_message = "CA060 must grant with the WORKFORCE strength (synced passkeys / NFC keys allowed), nothing else."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.shared_clinical_workstation[0].session_controls[0].sign_in_frequency == 8 &&
      azuread_conditional_access_policy.shared_clinical_workstation[0].session_controls[0].sign_in_frequency_period == "hours" &&
      azuread_conditional_access_policy.shared_clinical_workstation[0].session_controls[0].persistent_browser_mode == "never"
    )
    error_message = "CA060 must sign in every 8 hours (one shift) and never persist the browser session."
  }
}

run "ca060_custom_profile_name_flows_into_the_rule" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    enable_shared_clinical_ca           = true
    ca060_enrollment_profile_name       = "CH-SharedClinical-ED"
  }

  assert {
    condition     = azuread_conditional_access_policy.shared_clinical_workstation[0].conditions[0].devices[0].filter[0].rule == "device.enrollmentProfileName -eq \"CH-SharedClinical-ED\""
    error_message = "The filter rule must use ca060_enrollment_profile_name."
  }
}

run "ca060_profile_name_injection_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    enable_shared_clinical_ca           = true
    ca060_enrollment_profile_name       = "CH-SharedClinical\" -or device.trustType -eq \"AzureAD"
  }

  expect_failures = [var.ca060_enrollment_profile_name]
}

run "ca060_without_workforce_strength_is_refused" {
  command = plan

  variables {
    enable_shared_clinical_ca = true
  }

  expect_failures = [azuread_conditional_access_policy.shared_clinical_workstation]
}

run "ca060_without_clinical_groups_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    enable_shared_clinical_ca           = true
    ca060_clinical_group_object_ids     = []
  }

  expect_failures = [azuread_conditional_access_policy.shared_clinical_workstation]
}

run "ca060_without_key_is_refused" {
  command = plan

  variables {
    enable_phishing_resistant_all_users = true
    enable_shared_clinical_ca           = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA008 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [azuread_conditional_access_policy.shared_clinical_workstation]
}
