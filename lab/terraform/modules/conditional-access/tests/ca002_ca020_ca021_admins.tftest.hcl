# Admin / privileged-access policies: CA002's role list + admin groups, CA020
# (admin portal sign-in frequency) and CA021 (PIM activation step-up on an
# authentication context - Graph-managed, so Terraform only RENDERS its two
# request bodies). Mocked; no tenant.
# Run offline: terraform init -backend=false && terraform test
#
# What these runs pin down:
#   * CA002 targets Microsoft's 14 template roles + 8 lab extras, can be
#     widened but never narrowed below the template, and includes the admin
#     groups (AU-scoped role holders are invisible to the role condition);
#   * CA020 is session-only (no grant), report-only, sign-in every 4 h on the
#     admin portals for the Tier-0/1 roles + admin groups; > 4 h is refused;
#   * CA021's rendered body: report-only, auth context c1 only (no apps), All
#     users minus break-glass, the ADMIN strength by BARE object id, sign-in
#     frequency every time; the auth context is published (isAvailable);
#   * the ordering gate: PIM may only require the context once CA021 is
#     declared ENFORCED on that same context.

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

# --- CA002 ------------------------------------------------------------------
run "ca002_default_roles_template_plus_lab_extras_no_groups" {
  command = plan

  assert {
    condition     = length(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_roles) == 22
    error_message = "CA002 must target Microsoft's 14 template roles + 8 lab extras by default."
  }

  assert {
    condition = alltrue([
      for r in [
        "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
        "966707d0-3269-4727-9be2-8c3a10f19b9d", # Password Administrator
        "b0f54661-2d74-4c50-afa3-1ec803f12efe", # Billing Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8", # Helpdesk Administrator
        "c4e39bd9-1100-46d3-8c65-fb160da0071f", # Authentication Administrator
        "0526716b-113d-4c15-b2c8-68e3c22b9f80", # Authentication Policy Administrator (lab extra)
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # Hybrid Identity Administrator (lab extra)
      ] : contains(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_roles, r)
    ])
    error_message = "CA002 is missing a template role or a lab extra that the default must carry."
  }

  assert {
    condition     = length(coalesce(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_groups, [])) == 0
    error_message = "With no admin groups supplied, CA002 must leave included_groups unset."
  }

  assert {
    condition     = output.admin_role_template_ids == var.admin_role_template_ids
    error_message = "The CA002 role list must be exposed for the baseline assessment."
  }
}

run "ca002_includes_admin_groups_next_to_roles" {
  command = plan

  variables {
    admin_scope_group_object_ids = {
      "PIM-Tier0-CA-Admins"      = "cccccccc-cccc-cccc-cccc-cccccccccccc"
      "PIM-Tier1-ServiceDesk-AU" = "dddddddd-dddd-dddd-dddd-dddddddddddd"
    }
  }

  assert {
    condition = (
      contains(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_groups, "cccccccc-cccc-cccc-cccc-cccccccccccc") &&
      contains(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_groups, "dddddddd-dddd-dddd-dddd-dddddddddddd") &&
      length(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_roles) == 22
    )
    error_message = "CA002 must include the admin groups (AU-scoped help desk) IN ADDITION to the roles."
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].excluded_groups == tolist(["22222222-2222-2222-2222-222222222222"])
    error_message = "CA002 must still exclude break-glass."
  }
}

run "ca002_cannot_drop_a_template_role" {
  command = plan

  variables {
    # Microsoft's template minus Password Administrator.
    admin_role_template_ids = [
      "62e90394-69f5-4237-9190-012177145e10", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
      "c4e39bd9-1100-46d3-8c65-fb160da0071f", "b0f54661-2d74-4c50-afa3-1ec803f12efe",
      "158c047a-c907-4556-b7ef-446551a6b5f7", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
      "29232cdf-9323-42fd-ade2-1d097af3e4de", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
      "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "e8611ab8-c189-46e8-94e1-60213ab1f814",
      "194ae4cb-b126-40b2-bd5b-6091b380977d", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
      "fe930be7-5e62-47db-91af-98c3a49a38b1",
    ]
  }

  expect_failures = [var.admin_role_template_ids]
}

run "ca002_can_be_widened" {
  command = plan

  variables {
    # Exactly the template + Teams Administrator.
    admin_role_template_ids = [
      "62e90394-69f5-4237-9190-012177145e10", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
      "c4e39bd9-1100-46d3-8c65-fb160da0071f", "b0f54661-2d74-4c50-afa3-1ec803f12efe",
      "158c047a-c907-4556-b7ef-446551a6b5f7", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
      "29232cdf-9323-42fd-ade2-1d097af3e4de", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
      "966707d0-3269-4727-9be2-8c3a10f19b9d", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
      "e8611ab8-c189-46e8-94e1-60213ab1f814", "194ae4cb-b126-40b2-bd5b-6091b380977d",
      "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "fe930be7-5e62-47db-91af-98c3a49a38b1",
      "69091246-20e8-4a56-aa4d-066075b2a7a8",
    ]
  }

  assert {
    condition     = length(azuread_conditional_access_policy.admin_phishing_resistant.conditions[0].users[0].included_roles) == 15
    error_message = "Adding a role on top of the template must plan."
  }
}

# --- CA020 ------------------------------------------------------------------
run "ca020_off_by_default" {
  command = plan

  assert {
    condition     = length(azuread_conditional_access_policy.admin_session_controls) == 0 && output.policy_ids["admin_session_controls"] == null && output.policy_display_names["CA020"] == null
    error_message = "CA020 must not exist until enable_admin_session_controls."
  }
}

run "ca020_session_only_report_only_4h_on_admin_portals" {
  command = apply

  variables {
    enable_admin_session_controls = true
    admin_scope_group_object_ids = {
      "PIM-Tier1-Helpdesk" = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
    }
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_session_controls[0].state == "enabledForReportingButNotEnforced"
    error_message = "CA020 must default to report-only."
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_session_controls[0].display_name == "CA020 - Require sign-in every 4h on admin portals for Tier-0/1 admins"
    error_message = "CA020's name must state its frequency."
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_session_controls[0].conditions[0].applications[0].included_applications == tolist(["MicrosoftAdminPortals", "797f4846-ba00-4fd7-ba43-dac1f8f63013"])
    error_message = "CA020 must target the admin portals + Azure Service Management API (the CA005 set), never All."
  }

  assert {
    condition = (
      length(azuread_conditional_access_policy.admin_session_controls[0].conditions[0].users[0].included_roles) == 18 &&
      contains(azuread_conditional_access_policy.admin_session_controls[0].conditions[0].users[0].included_roles, "62e90394-69f5-4237-9190-012177145e10") &&
      contains(azuread_conditional_access_policy.admin_session_controls[0].conditions[0].users[0].included_roles, "729827e3-9c14-49f7-bb1b-9608f156bbb8") &&
      azuread_conditional_access_policy.admin_session_controls[0].conditions[0].users[0].included_groups == tolist(["eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"])
    )
    error_message = "CA020 must include the 18 Tier-0/1 roles and the admin groups."
  }

  assert {
    condition     = azuread_conditional_access_policy.admin_session_controls[0].conditions[0].users[0].excluded_groups == tolist(["22222222-2222-2222-2222-222222222222"])
    error_message = "CA020 must exclude break-glass."
  }

  assert {
    condition = (
      azuread_conditional_access_policy.admin_session_controls[0].session_controls[0].sign_in_frequency == 4 &&
      azuread_conditional_access_policy.admin_session_controls[0].session_controls[0].sign_in_frequency_period == "hours" &&
      azuread_conditional_access_policy.admin_session_controls[0].session_controls[0].persistent_browser_mode == null
    )
    error_message = "CA020 must set sign-in frequency 4 hours (persistent browser needs All resources, so it is not set here)."
  }

  assert {
    condition     = length(azuread_conditional_access_policy.admin_session_controls[0].grant_controls) == 0
    error_message = "CA020 is session-only: no grant control (CA002 already demands the strength)."
  }
}

run "ca020_longer_than_4h_is_refused" {
  command = plan

  variables {
    enable_admin_session_controls         = true
    admin_session_sign_in_frequency_hours = 8
  }

  expect_failures = [var.admin_session_sign_in_frequency_hours]
}

run "ca020_without_key_is_refused" {
  command = plan

  variables {
    enable_admin_session_controls = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [azuread_conditional_access_policy.admin_session_controls]
}

# --- CA021 (rendered for post-apply/Set-AuthContextPolicies.ps1) -------------
run "ca021_off_renders_nothing" {
  command = plan

  assert {
    condition = (
      output.pim_auth_context_requests == null &&
      output.policy_display_names["CA021"] == null &&
      output.pim_activation_auth_context_ready == false &&
      output.pim_activation_auth_context_id == ""
    )
    error_message = "With enable_pim_auth_context off nothing may be rendered, and PIM must not be handed a context."
  }
}

run "ca021_renders_report_only_auth_context_policy" {
  command = apply

  variables {
    enable_pim_auth_context = true
  }

  assert {
    condition = (
      output.pim_auth_context_requests.policy_key == "CA021" &&
      output.pim_auth_context_requests.auth_context_id == "c1" &&
      output.pim_auth_context_requests.policy_match_prefix == "CA021 - " &&
      output.pim_auth_context_requests.policy_display_name == "CA021 - Require phishing-resistant strength for privileged role activation (auth context c1)" &&
      output.pim_auth_context_requests.policy_state == "enabledForReportingButNotEnforced"
    )
    error_message = "CA021 must render under its key, prefix and name, report-only by default."
  }

  assert {
    condition = (
      jsondecode(output.pim_auth_context_requests.auth_context_body).isAvailable == true &&
      jsondecode(output.pim_auth_context_requests.auth_context_body).displayName == "Privileged role activation"
    )
    error_message = "The auth context must be published (isAvailable = true) or PIM cannot use it."
  }

  assert {
    condition = (
      jsondecode(output.pim_auth_context_requests.policy_body).state == "enabledForReportingButNotEnforced" &&
      jsondecode(output.pim_auth_context_requests.policy_body).displayName == output.pim_auth_context_requests.policy_display_name &&
      startswith(jsondecode(output.pim_auth_context_requests.policy_body).displayName, output.pim_auth_context_requests.policy_match_prefix)
    )
    error_message = "The CA021 body must carry the rendered state and a name that starts with the match prefix."
  }

  assert {
    condition = (
      jsondecode(output.pim_auth_context_requests.policy_body).conditions.applications.includeAuthenticationContextClassReferences == ["c1"] &&
      !contains(keys(jsondecode(output.pim_auth_context_requests.policy_body).conditions.applications), "includeApplications")
    )
    error_message = "CA021 must target only the authentication context, never apps."
  }

  assert {
    condition = (
      jsondecode(output.pim_auth_context_requests.policy_body).conditions.users.includeUsers == ["All"] &&
      jsondecode(output.pim_auth_context_requests.policy_body).conditions.users.excludeGroups == ["22222222-2222-2222-2222-222222222222"] &&
      !contains(keys(jsondecode(output.pim_auth_context_requests.policy_body).conditions.users), "includeGroups")
    )
    error_message = "CA021 must include All users (never the PIM group itself) and exclude break-glass."
  }

  assert {
    condition = (
      jsondecode(output.pim_auth_context_requests.policy_body).grantControls.authenticationStrength.id == "44444444-4444-4444-4444-444444444444" &&
      !contains(keys(jsondecode(output.pim_auth_context_requests.policy_body).grantControls), "builtInControls")
    )
    error_message = "CA021 must grant with the ADMIN strength by its bare object id (Graph authenticationStrength.id), with no built-in control beside it."
  }

  assert {
    condition = (
      jsondecode(output.pim_auth_context_requests.policy_body).sessionControls.signInFrequency.isEnabled == true &&
      jsondecode(output.pim_auth_context_requests.policy_body).sessionControls.signInFrequency.frequencyInterval == "everyTime" &&
      jsondecode(output.pim_auth_context_requests.policy_body).sessionControls.signInFrequency.authenticationType == "primaryAndSecondaryAuthentication"
    )
    error_message = "CA021 must force a fresh sign-in on every activation (sign-in frequency every time)."
  }

  assert {
    condition     = output.pim_activation_auth_context_ready == false && output.pim_activation_auth_context_id == ""
    error_message = "A report-only CA021 must not hand PIM the context."
  }

  assert {
    condition     = output.policy_display_names["CA021"] == output.pim_auth_context_requests.policy_display_name
    error_message = "policy_display_names must list the rendered CA021 name."
  }
}

run "ca021_without_key_is_refused" {
  command = plan

  variables {
    enable_pim_auth_context = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [output.pim_auth_context_requests]
}

run "pim_context_while_ca021_report_only_is_refused" {
  command = plan

  variables {
    enable_pim_auth_context              = true
    pim_tier0_activation_auth_context_id = "c1"
  }

  expect_failures = [output.pim_activation_auth_context_ready]
}

run "pim_context_without_ca021_is_refused" {
  command = plan

  variables {
    pim_tier0_activation_auth_context_id = "c1"
  }

  expect_failures = [output.pim_activation_auth_context_ready]
}

run "pim_context_on_a_different_context_is_refused" {
  command = plan

  variables {
    enable_pim_auth_context              = true
    pim_auth_context_id                  = "c2"
    pim_tier0_activation_auth_context_id = "c1"
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabled"
    }
  }

  expect_failures = [output.pim_activation_auth_context_ready]
}

# THE SAME-CHANGE GAP: one change that declares CA021 "enabled" AND sets the
# PIM context would have `terraform apply` point Tier-0 activation at c1
# before Set-AuthContextPolicies.ps1 writes the enforced CA021 (the tenant
# still holds the report-only one, and PIM's MFA backup does not fire for a
# report-only policy). Declared state alone is refused; the tenant attestation
# (set in a later change) is required.
run "pim_context_in_the_same_change_as_ca021_enabled_is_refused" {
  command = plan

  variables {
    enable_pim_auth_context              = true
    pim_tier0_activation_auth_context_id = "c1"
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabled"
    }
  }

  expect_failures = [output.pim_activation_auth_context_ready]
}

run "declared_enabled_without_attestation_is_not_ready" {
  command = apply

  variables {
    enable_pim_auth_context = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabled"
    }
  }

  assert {
    condition     = output.pim_activation_auth_context_ready == false && output.pim_activation_auth_context_id == ""
    error_message = "CA021 declared enabled but not yet attested in the tenant must NOT hand modules/pim the context."
  }
}

run "attestation_without_ca021_enabled_is_refused" {
  command = plan

  variables {
    enable_pim_auth_context  = true
    ca021_enforced_in_tenant = true
  }

  expect_failures = [output.pim_activation_auth_context_ready]
}

run "pim_context_after_ca021_enforced_plans" {
  command = apply

  variables {
    enable_pim_auth_context              = true
    ca021_enforced_in_tenant             = true
    pim_tier0_activation_auth_context_id = "c1"
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabled"
    }
  }

  assert {
    condition = (
      output.pim_activation_auth_context_ready == true &&
      output.pim_activation_auth_context_id == "c1" &&
      jsondecode(output.pim_auth_context_requests.policy_body).state == "enabled"
    )
    error_message = "With CA021 declared enforced on c1 AND attested in the tenant, PIM may require c1."
  }
}

run "auth_context_id_outside_graph_range_is_refused" {
  command = plan

  variables {
    enable_pim_auth_context = true
    pim_auth_context_id     = "c26"
  }

  expect_failures = [var.pim_auth_context_id]
}

# Contract with lab/scripts/powershell/tests/Set-AuthContextPolicies.Tests.ps1:
# the Pester fixture uses these EXACT strings (same placeholder ids). If the
# rendering changes, this run fails - update the Pester fixture in the same PR.
run "ca021_render_contract_with_the_post_apply_script_tests" {
  command = apply

  variables {
    enable_pim_auth_context = true
  }

  assert {
    condition     = output.pim_auth_context_requests.policy_body == "{\"conditions\":{\"applications\":{\"includeAuthenticationContextClassReferences\":[\"c1\"]},\"clientAppTypes\":[\"all\"],\"users\":{\"excludeGroups\":[\"22222222-2222-2222-2222-222222222222\"],\"includeUsers\":[\"All\"]}},\"displayName\":\"CA021 - Require phishing-resistant strength for privileged role activation (auth context c1)\",\"grantControls\":{\"authenticationStrength\":{\"id\":\"44444444-4444-4444-4444-444444444444\"},\"operator\":\"OR\"},\"sessionControls\":{\"signInFrequency\":{\"authenticationType\":\"primaryAndSecondaryAuthentication\",\"frequencyInterval\":\"everyTime\",\"isEnabled\":true}},\"state\":\"enabledForReportingButNotEnforced\"}"
    error_message = "CA021 policy_body changed - update the fixture in Set-AuthContextPolicies.Tests.ps1 to the new rendering."
  }

  assert {
    condition     = output.pim_auth_context_requests.auth_context_body == "{\"description\":\"PIM Tier-0 activation step-up: phishing-resistant strength, fresh sign-in (CA021)\",\"displayName\":\"Privileged role activation\",\"isAvailable\":true}"
    error_message = "auth_context_body changed - update the fixture in Set-AuthContextPolicies.Tests.ps1 to the new rendering."
  }
}

# =============================================================================
# CA023 - protected actions step-up (auth context c2), Graph-managed like CA021
# =============================================================================

run "ca023_off_renders_nothing" {
  command = plan

  assert {
    condition     = output.protected_actions_auth_context_requests == null && output.policy_display_names["CA023"] == null
    error_message = "CA023 must render nothing while enable_protected_actions_ca is off."
  }
}

run "ca023_renders_report_only_protected_actions_policy" {
  command = apply

  variables {
    enable_protected_actions_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA023 = "enabledForReportingButNotEnforced"
    }
  }

  assert {
    condition = (
      output.protected_actions_auth_context_requests.policy_key == "CA023" &&
      output.protected_actions_auth_context_requests.auth_context_id == "c2" &&
      output.protected_actions_auth_context_requests.policy_match_prefix == "CA023 - " &&
      jsondecode(output.protected_actions_auth_context_requests.policy_body).state == "enabledForReportingButNotEnforced" &&
      jsondecode(output.protected_actions_auth_context_requests.policy_body).conditions.applications.includeAuthenticationContextClassReferences == ["c2"] &&
      jsondecode(output.protected_actions_auth_context_requests.policy_body).conditions.users.excludeGroups == [var.break_glass_group_object_id] &&
      jsondecode(output.protected_actions_auth_context_requests.policy_body).sessionControls.signInFrequency.frequencyInterval == "everyTime" &&
      jsondecode(output.protected_actions_auth_context_requests.policy_body).grantControls.authenticationStrength.id == azuread_authentication_strength_policy.phishing_resistant.object_id &&
      jsondecode(output.protected_actions_auth_context_requests.auth_context_body).isAvailable == true
    )
    error_message = "CA023: report-only, auth context c2, break-glass excluded, ADMIN strength, sign-in every time."
  }
}

run "ca023_without_key_is_refused" {
  command = plan

  variables {
    enable_protected_actions_ca = true
    policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [output.protected_actions_auth_context_requests]
}

run "ca023_cannot_share_the_pim_context" {
  command = plan

  variables {
    enable_protected_actions_ca       = true
    protected_actions_auth_context_id = "c1"
  }

  expect_failures = [output.protected_actions_auth_context_requests]
}
