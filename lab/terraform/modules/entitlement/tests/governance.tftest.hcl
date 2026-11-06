# Offline mock tests for modules/entitlement (no tenant, no state):
#   terraform init -backend=false && terraform test
# Pins the ADR 0012 governance contract:
#   * T3 birthright packages (Nurse, ICU) have NO Terraform policy: no request
#     path, no expiry, no review. The automatic assignment policy comes from
#     post-apply/Set-AutoAssignmentPolicies.ps1.
#   * T2 request packages (ICU - Float Access, Pharmacy) expire after 180 days;
#     a policy review only when one outlives 180 days or allows extension.
#   * The review flags are INDEPENDENT: turning on T1 never puts a review (or
#     unanswered = removed) on a clinical package - the bug of the old single
#     enable_access_reviews switch, which is now a deprecated alias.
#   * The defaults agree with lab/iga/access-catalog.json (tier, assignment,
#     resources).
#   * The standalone review bodies, the PIM direct-role hand-off, the
#     break-glass guard, and the B2B guest package.
# Every feature defaults OFF.
#
# Mocked ids are GUID-shaped because the azuread provider still validates
# arguments such as group_id / object_id during a mocked apply.

mock_provider "azuread" {
  mock_resource "azuread_group" {
    defaults = {
      id        = "/groups/55555555-5555-5555-5555-555555555555"
      object_id = "55555555-5555-5555-5555-555555555555"
    }
  }
  mock_resource "azuread_access_package_catalog" {
    defaults = { id = "66666666-6666-6666-6666-666666666666" }
  }
  mock_resource "azuread_access_package" {
    defaults = { id = "77777777-7777-7777-7777-777777777777" }
  }
  mock_resource "azuread_access_package_assignment_policy" {
    defaults = { id = "88888888-8888-8888-8888-888888888888" }
  }
}

variables {
  catalog_group_object_ids = {
    servicenow          = "10000000-0000-0000-0000-000000000001"
    aws                 = "10000000-0000-0000-0000-000000000002"
    icu_critical_care   = "10000000-0000-0000-0000-000000000003"
    pharmacy_dispensing = "10000000-0000-0000-0000-000000000004"
  }

  # Test-only inputs (not module variables): the IGA catalog the post-apply
  # scripts read, and the group key -> catalog group name map.
  iga_catalog = jsondecode(file("../../../iga/access-catalog.json"))
  iga_group_names = {
    servicenow          = "App-ServiceNow-Users"
    aws                 = "App-AWS-IdentityCenter-Users"
    icu_critical_care   = "App-ICU-CriticalCare-Users"
    pharmacy_dispensing = "App-Pharmacy-Dispensing-Users"
  }

  # A valid T1 body as modules/pim is expected to render it (direct GA
  # eligibility, ADR 0002) - only the shape matters here.
  pim_ga_body = jsonencode({
    displayName = "Privileged access review: Global Administrator (direct eligibility)"
    scope = {
      "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
      query         = "/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal&$filter=(isof(principal,'microsoft.graph.user') and roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10')"
      queryType     = "MicrosoftGraph"
    }
    reviewers         = [{ query = "/groups/20000000-0000-0000-0000-000000000001/transitiveMembers", queryType = "MicrosoftGraph" }]
    fallbackReviewers = [{ query = "/groups/20000000-0000-0000-0000-000000000001/transitiveMembers", queryType = "MicrosoftGraph" }]
    settings = {
      defaultDecisionEnabled          = true
      defaultDecision                 = "Deny"
      autoApplyDecisionsEnabled       = true
      justificationRequiredOnApproval = true
      instanceDurationInDays          = 14
      recurrence                      = { pattern = { type = "absoluteMonthly", interval = 3 }, range = { type = "noEnd", startDate = null } }
    }
  })
}

# -----------------------------------------------------------------------------
# Defaults: nothing new is created or rendered (trials must not start early),
# and birthright packages have no Terraform policy at all.
# -----------------------------------------------------------------------------
run "defaults_create_nothing_new" {
  command = plan

  assert {
    condition     = length(azuread_access_package_catalog.b2b) == 0 && length(azuread_access_package_assignment_policy.b2b) == 0 && length(azuread_group.b2b_sponsors) == 0
    error_message = "B2B governance must be off by default."
  }
  assert {
    condition     = length(output.access_review_definitions) == 0 && output.access_review_settings == null
    error_message = "No review may be rendered while every review flag is false."
  }
  assert {
    condition     = output.b2b_post_apply == null
    error_message = "b2b_post_apply must be null while B2B governance is off."
  }
  assert {
    condition     = alltrue([for p in azuread_access_package_assignment_policy.this : length(p.assignment_review_settings) == 0])
    error_message = "Package policies must carry no review block while the review flags are off."
  }
  assert {
    condition     = azuread_access_package_catalog.clinical.externally_visible == false
    error_message = "The Clinical catalog must never be externally visible."
  }
}

run "birthright_packages_have_no_policy_no_expiry" {
  command = plan

  assert {
    condition     = length(azuread_access_package.this) == 4 && jsonencode(sort(keys(azuread_access_package_assignment_policy.this))) == jsonencode(["icu_float", "pharmacy"])
    error_message = "All four packages exist, but only the request packages (icu_float, pharmacy) get a Terraform policy: no requestable policy may compete with the automatic assignment policy on Nurse or ICU."
  }
  assert {
    condition = alltrue([for k in ["nurse", "icu"] :
      output.package_assignment_model[k].tier == "T3" &&
      output.package_assignment_model[k].assignment == "automatic" &&
      output.package_assignment_model[k].expires_after_days == null &&
      output.package_assignment_model[k].request_policy == false &&
      output.package_assignment_model[k].policy_review == null
    ])
    error_message = "Birthright (T3) packages must have no expiry, no request policy and no review."
  }
  assert {
    condition     = jsonencode(output.birthright_package_names) == jsonencode(["ICU - Critical Care Apps", "Nurse - Clinical Apps"])
    error_message = "birthright_package_names must list the two T3 packages Set-AutoAssignmentPolicies.ps1 has to cover."
  }
  assert {
    condition = alltrue([for k in ["icu_float", "pharmacy"] :
      azuread_access_package_assignment_policy.this[k].duration_in_days == 180 &&
      azuread_access_package_assignment_policy.this[k].extension_enabled == false &&
      azuread_access_package_assignment_policy.this[k].approval_settings[0].approval_required == true
    ])
    error_message = "T2 request packages: approval required, 180-day expiry, no extension (re-request = re-approval)."
  }
  assert {
    condition     = azuread_access_package_assignment_policy.this["icu_float"].display_name == "ICU - Float Access - 180 day"
    error_message = "Request policies keep the '<package> - <N> day' name 02-Joiner.ps1 matches."
  }
}

# The Terraform defaults and lab/iga/access-catalog.json must describe the
# same packages: the post-apply scripts and the SoD / KPI reports read the
# catalog, Terraform builds the tenant.
run "defaults_match_iga_catalog" {
  command = plan

  assert {
    condition = alltrue([for k, p in output.package_assignment_model :
      length([for e in var.iga_catalog.accessPackages : e if e.name == p.display_name && e.status == "terraform" && e.tier == p.tier && e.assignment == p.assignment]) == 1
    ])
    error_message = "Every Terraform package must appear once in lab/iga/access-catalog.json with status terraform and the same tier and assignment."
  }
  assert {
    condition = alltrue([for k, p in var.access_packages :
      sort([for g in p.group_keys : var.iga_group_names[g]]) == sort(one([for e in var.iga_catalog.accessPackages : e.resources if e.name == p.display_name]))
    ])
    error_message = "Each package's groups must match the catalog entry's resources (Set-AutoAssignmentPolicies.ps1 compares the counts in the tenant)."
  }
  assert {
    condition = alltrue([for e in var.iga_catalog.accessPackages :
      contains([for p in values(var.access_packages) : p.display_name], e.name)
      if e.status == "terraform" && e.name != "Affiliated Physicians"
    ])
    error_message = "A catalog package marked terraform (other than the B2B one in b2b.tf) is missing from var.access_packages."
  }
}

# -----------------------------------------------------------------------------
# THE REPORTED BUG: turning on T1 reviews must not touch clinical packages.
# Even with every request package made review-eligible (365 days + extension),
# the privileged flag alone attaches no policy review anywhere.
# -----------------------------------------------------------------------------
run "t1_flag_never_reviews_clinical_packages" {
  command = plan

  variables {
    enable_access_reviews_privileged       = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
    inactive_review_group_object_ids = {
      "App-Okta-Federation-Users" = "40000000-0000-0000-0000-000000000001"
    }
    access_packages = {
      nurse     = { display_name = "Nurse - Clinical Apps", description = "d", group_keys = ["servicenow", "aws"], tier = "T3", assignment = "automatic" }
      icu       = { display_name = "ICU - Critical Care Apps", description = "d", group_keys = ["servicenow", "icu_critical_care"], tier = "T3", assignment = "automatic" }
      icu_float = { display_name = "ICU - Float Access", description = "d", group_keys = ["servicenow", "icu_critical_care"], tier = "T2", assignment = "request", duration_in_days = 365, extension_enabled = true }
      pharmacy  = { display_name = "Pharmacy - Controlled Substances Apps", description = "d", group_keys = ["pharmacy_dispensing"], tier = "T2", assignment = "request", duration_in_days = 365, extension_enabled = true }
    }
  }

  assert {
    condition     = alltrue([for p in azuread_access_package_assignment_policy.this : length(p.assignment_review_settings) == 0])
    error_message = "enable_access_reviews_privileged alone must not attach a policy review (removeAccess) to any T2 or T3 package."
  }
  assert {
    condition     = !contains(keys(azuread_access_package_assignment_policy.this), "nurse") && !contains(keys(azuread_access_package_assignment_policy.this), "icu")
    error_message = "Birthright packages never get a Terraform policy, whatever the flags."
  }
  assert {
    condition     = jsonencode(keys(output.access_review_definitions)) == jsonencode(["privileged:Privileged-IAM-Admins"])
    error_message = "The T1 flag renders the privileged review only - not the inactive-user review (its own flag)."
  }
  assert {
    condition     = length(output.access_review_settings.package_reviews) == 0 && output.access_review_settings.requestable_enabled == false
    error_message = "access_review_settings must show no package review under the T1 flag."
  }
}

run "t2_flag_reviews_only_long_or_extendable_packages" {
  command = plan

  variables {
    enable_access_reviews_requestable      = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
    access_packages = {
      nurse     = { display_name = "Nurse - Clinical Apps", description = "d", group_keys = ["servicenow", "aws"], tier = "T3", assignment = "automatic" }
      icu_float = { display_name = "ICU - Float Access", description = "d", group_keys = ["servicenow", "icu_critical_care"], tier = "T2", assignment = "request" }
      pharmacy  = { display_name = "Pharmacy - Controlled Substances Apps", description = "d", group_keys = ["pharmacy_dispensing"], tier = "T2", assignment = "request", duration_in_days = 365 }
      extend    = { display_name = "Extendable T2", description = "d", group_keys = ["servicenow"], tier = "T2", assignment = "request", extension_enabled = true }
    }
  }

  assert {
    condition     = length(azuread_access_package_assignment_policy.this["icu_float"].assignment_review_settings) == 0
    error_message = "A 180-day, non-extendable T2 package is certified by expiry + re-approval: no review campaign (ADR 0012)."
  }
  assert {
    condition = alltrue([for k in ["pharmacy", "extend"] :
      azuread_access_package_assignment_policy.this[k].assignment_review_settings[0].review_frequency == "halfyearly" &&
      azuread_access_package_assignment_policy.this[k].assignment_review_settings[0].access_review_timeout_behavior == "removeAccess" &&
      azuread_access_package_assignment_policy.this[k].assignment_review_settings[0].review_type == "Manager"
    ])
    error_message = "A T2 package that outlives 180 days or allows extension gets a half-yearly manager review, unanswered = removed."
  }
  assert {
    condition = (
      azuread_access_package_assignment_policy.this["extend"].extension_enabled == true &&
      azuread_access_package_assignment_policy.this["extend"].approval_settings[0].approval_required_for_extension == true
    )
    error_message = "An extension must go through the same approval again."
  }
  assert {
    condition     = length(output.access_review_definitions) == 0
    error_message = "The T2 flag must not render the privileged or inactive standalone reviews."
  }
}

run "t1_package_reviewed_quarterly_by_governance_group" {
  command = plan

  variables {
    enable_access_reviews_privileged           = true
    access_review_fallback_group_object_id     = "20000000-0000-0000-0000-000000000001"
    privileged_review_reviewer_group_object_id = "22222222-2222-2222-2222-222222222222"
    sod_incompatible_pairs                     = []
    access_packages = {
      nurse     = { display_name = "Nurse - Clinical Apps", description = "d", group_keys = ["servicenow", "aws"], tier = "T3", assignment = "automatic" }
      ehr_admin = { display_name = "EHR - Admin Console", description = "d", group_keys = ["servicenow"], tier = "T1", assignment = "request", duration_in_days = 90 }
    }
  }

  assert {
    condition = (
      azuread_access_package_assignment_policy.this["ehr_admin"].assignment_review_settings[0].review_frequency == "quarterly" &&
      azuread_access_package_assignment_policy.this["ehr_admin"].assignment_review_settings[0].access_review_timeout_behavior == "removeAccess" &&
      azuread_access_package_assignment_policy.this["ehr_admin"].assignment_review_settings[0].review_type == "Reviewers"
    )
    error_message = "A T1 package is reviewed quarterly by named reviewers, unanswered = removed."
  }
  assert {
    condition = (
      azuread_access_package_assignment_policy.this["ehr_admin"].assignment_review_settings[0].reviewer[0].object_id == "22222222-2222-2222-2222-222222222222" &&
      azuread_access_package_assignment_policy.this["ehr_admin"].assignment_review_settings[0].reviewer[0].backup == false &&
      azuread_access_package_assignment_policy.this["ehr_admin"].assignment_review_settings[0].reviewer[1].backup == true
    )
    error_message = "T1 reviewers: the governance group first, the fallback group as backup - never the requestor's manager."
  }
}

run "inactive_flag_is_independent" {
  command = plan

  variables {
    enable_access_reviews_inactive         = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
    inactive_review_group_object_ids = {
      "App-Okta-Federation-Users" = "40000000-0000-0000-0000-000000000001"
    }
  }

  assert {
    condition     = jsonencode(keys(output.access_review_definitions)) == jsonencode(["inactive:App-Okta-Federation-Users"])
    error_message = "The inactive flag renders only the inactive-user review."
  }
  assert {
    condition     = alltrue([for p in azuread_access_package_assignment_policy.this : length(p.assignment_review_settings) == 0])
    error_message = "The inactive flag attaches no package review."
  }
}

# -----------------------------------------------------------------------------
# Standalone bodies (privileged + PIM direct-role + inactive).
# -----------------------------------------------------------------------------
run "reviews_render_deny_by_default" {
  command = apply

  variables {
    enable_access_reviews_privileged       = true
    enable_access_reviews_inactive         = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    access_review_start_date               = "2026-11-02T08:00:00Z"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins"     = "30000000-0000-0000-0000-000000000001"
      "PIM-Tier0-Security-Admins" = "30000000-0000-0000-0000-000000000002"
    }
    inactive_review_group_object_ids = {
      "App-Okta-Federation-Users" = "40000000-0000-0000-0000-000000000001"
    }
    pim_eligible_review_bodies = {
      "pim-role:Global Administrator" = var.pim_ga_body
    }
  }

  assert {
    condition     = length(output.access_review_definitions) == 4
    error_message = "Expected 2 privileged + 1 PIM direct-role + 1 inactive review definitions."
  }
  assert {
    condition     = jsondecode(output.access_review_definitions["privileged:Privileged-IAM-Admins"]).scope.query == "/groups/30000000-0000-0000-0000-000000000001/transitiveMembers"
    error_message = "Privileged review must scope the PIM-governed group's (eligible + active) members."
  }
  assert {
    condition = alltrue([for k, v in output.access_review_definitions :
      jsondecode(v).settings.defaultDecisionEnabled == true &&
      jsondecode(v).settings.defaultDecision == "Deny" &&
      jsondecode(v).settings.autoApplyDecisionsEnabled == true &&
    jsondecode(v).settings.justificationRequiredOnApproval == true])
    error_message = "Every standalone review (PIM hand-off included) must deny on no response and auto-apply decisions."
  }
  assert {
    condition     = output.access_review_definitions["pim-role:Global Administrator"] == var.pim_ga_body
    error_message = "The PIM direct-role body must pass through unchanged."
  }
  assert {
    condition     = jsondecode(output.access_review_definitions["privileged:PIM-Tier0-Security-Admins"]).reviewers[0].query == "/groups/20000000-0000-0000-0000-000000000001/transitiveMembers"
    error_message = "Privileged reviewers default to the fallback governance group."
  }
  assert {
    condition     = length(jsondecode(output.access_review_definitions["privileged:Privileged-IAM-Admins"]).fallbackReviewers) == 1
    error_message = "PIM-governed group reviews need a fallback reviewer (Microsoft Learn)."
  }
  assert {
    condition = (
      jsondecode(output.access_review_definitions["privileged:Privileged-IAM-Admins"]).settings.recurrence.pattern.type == "absoluteMonthly" &&
      jsondecode(output.access_review_definitions["privileged:Privileged-IAM-Admins"]).settings.recurrence.pattern.interval == 3 &&
      jsondecode(output.access_review_definitions["privileged:Privileged-IAM-Admins"]).settings.recurrence.range.startDate == "2026-11-02"
    )
    error_message = "Quarterly must render as absoluteMonthly / interval 3 starting on the configured date."
  }
  assert {
    condition     = jsondecode(output.access_review_definitions["inactive:App-Okta-Federation-Users"]).scope["@odata.type"] == "#microsoft.graph.accessReviewInactiveUsersQueryScope"
    error_message = "Inactive review must use accessReviewInactiveUsersQueryScope (the @odata.type is mandatory)."
  }
  assert {
    condition     = jsondecode(output.access_review_definitions["inactive:App-Okta-Federation-Users"]).scope.inactiveDuration == "P90D"
    error_message = "Inactive review must default to 90 days without sign-in."
  }
}

# modules/pim renders the PIM-group reviews under the same keys: its body
# wins, and each group still gets exactly one series.
run "pim_body_replaces_same_key_group_review" {
  command = plan

  variables {
    enable_access_reviews_privileged       = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
    pim_eligible_review_bodies = {
      "privileged:Privileged-IAM-Admins" = replace(replace(var.pim_ga_body, "Global Administrator (direct eligibility)", "Privileged-IAM-Admins"), "\"instanceDurationInDays\":14", "\"instanceDurationInDays\":10")
    }
  }

  assert {
    condition     = length(output.access_review_definitions) == 1 && jsondecode(output.access_review_definitions["privileged:Privileged-IAM-Admins"]).settings.instanceDurationInDays == 10
    error_message = "On a key clash the modules/pim body must replace the reviews.tf body (one series per group)."
  }
}

run "duplicate_review_display_names_are_refused" {
  command = plan

  variables {
    enable_access_reviews_privileged       = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
    pim_eligible_review_bodies = {
      "pim:iam" = replace(var.pim_ga_body, "Global Administrator (direct eligibility)", "Privileged-IAM-Admins")
    }
  }

  expect_failures = [output.access_review_definitions]
}

run "pim_bodies_need_the_t1_flag" {
  command = plan

  variables {
    enable_access_reviews_inactive         = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    pim_eligible_review_bodies = {
      "pim-role:Global Administrator" = var.pim_ga_body
    }
  }

  assert {
    condition     = length(output.access_review_definitions) == 0
    error_message = "PIM direct-role reviews are T1: they render only while enable_access_reviews_privileged is on."
  }
}

run "pim_body_that_keeps_access_on_silence_is_refused" {
  command = plan

  variables {
    enable_access_reviews_privileged       = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    pim_eligible_review_bodies = {
      "pim-role:Global Administrator" = replace(var.pim_ga_body, "\"Deny\"", "\"Approve\"")
    }
  }

  expect_failures = [var.pim_eligible_review_bodies]
}

# The deprecated alias still plans (envs/dev passes it), means all three
# flags - and still never reviews a birthright package.
run "deprecated_alias_spares_birthright" {
  command = plan

  variables {
    enable_access_reviews                  = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
    inactive_review_group_object_ids = {
      "App-Okta-Federation-Users" = "40000000-0000-0000-0000-000000000001"
    }
  }

  assert {
    condition     = length(output.access_review_definitions) == 2 && output.access_review_settings.privileged_enabled && output.access_review_settings.requestable_enabled && output.access_review_settings.inactive_enabled
    error_message = "enable_access_reviews = true must still render the privileged + inactive reviews (all three flags)."
  }
  assert {
    condition     = !contains(keys(azuread_access_package_assignment_policy.this), "nurse") && !contains(keys(azuread_access_package_assignment_policy.this), "icu")
    error_message = "Not even the deprecated alias may give a birthright package a policy (and so a review)."
  }
}

run "reviews_without_fallback_fail" {
  command = plan

  variables {
    enable_access_reviews_requestable = true
  }

  expect_failures = [azuread_access_package_catalog.clinical]
}

run "privileged_reviewer_cannot_review_itself" {
  # Fails at PLAN when the ids are known (as here and on a re-plan); on a
  # first plan with brand-new groups it fails at apply instead.
  command = plan

  variables {
    enable_access_reviews_privileged           = true
    access_review_fallback_group_object_id     = "20000000-0000-0000-0000-000000000001"
    privileged_review_reviewer_group_object_id = "30000000-0000-0000-0000-000000000001"
    privileged_review_group_object_ids = {
      "Privileged-IAM-Admins" = "30000000-0000-0000-0000-000000000001"
    }
  }

  expect_failures = [output.access_review_definitions]
}

run "break_glass_is_never_a_review_target_by_name" {
  command = plan

  variables {
    enable_access_reviews_inactive         = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    inactive_review_group_object_ids = {
      "Break-Glass-Admins" = "99999999-9999-9999-9999-999999999999"
    }
  }

  expect_failures = [output.access_review_definitions]
}

run "break_glass_is_never_a_review_target_by_id" {
  command = plan

  variables {
    enable_access_reviews_privileged       = true
    access_review_fallback_group_object_id = "20000000-0000-0000-0000-000000000001"
    break_glass_group_object_id            = "99999999-9999-9999-9999-999999999999"
    privileged_review_group_object_ids = {
      "Some-Renamed-Group" = "99999999-9999-9999-9999-999999999999"
    }
  }

  expect_failures = [output.access_review_definitions]
}

# -----------------------------------------------------------------------------
# Refusals at plan.
# -----------------------------------------------------------------------------
run "requested_birthright_is_refused" {
  command = plan

  variables {
    access_packages = {
      nurse = { display_name = "Nurse - Clinical Apps", description = "d", group_keys = ["servicenow"], tier = "T3", assignment = "request" }
    }
  }

  expect_failures = [var.access_packages]
}

run "automatic_package_with_expiry_is_refused" {
  command = plan

  variables {
    access_packages = {
      nurse = { display_name = "Nurse - Clinical Apps", description = "d", group_keys = ["servicenow"], tier = "T3", assignment = "automatic", duration_in_days = 180 }
    }
  }

  expect_failures = [var.access_packages]
}

run "automatic_privileged_package_is_refused" {
  command = plan

  variables {
    access_packages = {
      admin = { display_name = "Admin Console", description = "d", group_keys = ["servicenow"], tier = "T1", assignment = "automatic" }
    }
  }

  expect_failures = [var.access_packages]
}

run "extension_without_approval_is_refused" {
  command = plan

  variables {
    approval_required      = false
    sod_incompatible_pairs = []
    access_packages = {
      pharmacy = { display_name = "Pharmacy - Controlled Substances Apps", description = "d", group_keys = ["pharmacy_dispensing"], tier = "T2", assignment = "request", extension_enabled = true }
    }
  }

  expect_failures = [azuread_access_package_assignment_policy.this["pharmacy"]]
}

run "privileged_cadence_cannot_be_relaxed" {
  command = plan

  variables {
    access_review_frequency = "annual"
  }

  expect_failures = [var.access_review_frequency]
}

run "sod_pair_of_two_birthright_packages_is_refused" {
  command = plan

  variables {
    sod_incompatible_pairs = [["nurse", "icu"]]
  }

  expect_failures = [output.sod_incompatible_package_id_pairs]
}

# -----------------------------------------------------------------------------
# B2B guest governance.
# -----------------------------------------------------------------------------
run "b2b_guest_package" {
  command = apply

  variables {
    enable_b2b_governance = true
  }

  assert {
    condition     = azuread_access_package_catalog.b2b[0].externally_visible == true && azuread_access_package_catalog.clinical.externally_visible == false
    error_message = "Only the Affiliated Partners catalog may be externally visible."
  }
  assert {
    condition     = azuread_access_package.b2b[0].display_name == "Affiliated Physicians"
    error_message = "Guest package must be named Affiliated Physicians (contract)."
  }
  assert {
    condition     = azuread_access_package_assignment_policy.b2b[0].duration_in_days == 90
    error_message = "Guest assignments must expire after 90 days."
  }
  assert {
    condition     = azuread_access_package_assignment_policy.b2b[0].requestor_settings[0].scope_type == "AllConfiguredConnectedOrganizationSubjects"
    error_message = "Without a connected org id the policy must accept configured connected orgs only (never proposed ones / all external users)."
  }
  assert {
    condition = (
      length(azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_stage) == 1 &&
      azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_stage[0].primary_approver[0].subject_type == "InternalSponsors" &&
      azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_stage[0].primary_approver[1].backup == true
    )
    error_message = "Guest requests must be approved by internal sponsors with the Medical Staff Office as fallback."
  }
  assert {
    condition     = azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_required_for_extension == true
    error_message = "Extending guest access must be re-approved."
  }
  assert {
    condition = (
      azuread_access_package_assignment_policy.b2b[0].assignment_review_settings[0].review_frequency == "monthly" &&
      azuread_access_package_assignment_policy.b2b[0].assignment_review_settings[0].access_review_timeout_behavior == "removeAccess"
    )
    error_message = "Guest access must be reviewed monthly; unanswered = removed."
  }
  assert {
    condition     = jsondecode(output.b2b_post_apply.connected_organization_body).state == "configured"
    error_message = "The connected org must be created as configured, or AllConfiguredConnectedOrganizationSubjects never matches it."
  }
  assert {
    condition     = jsondecode(output.b2b_post_apply.connected_organization_body).identitySources[0]["@odata.type"] == "#microsoft.graph.domainIdentitySource"
    error_message = "Without a tenant id the connected org must use a domain identity source."
  }
  assert {
    condition     = jsondecode(output.b2b_post_apply.entitlement_settings_body).externalUserLifecycleAction == "blockSignInAndDelete"
    error_message = "Guests with no remaining assignment must be blocked, then deleted."
  }
}

run "b2b_specific_org_two_stage" {
  command = apply

  variables {
    enable_b2b_governance                 = true
    b2b_connected_organization_id         = "90000000-0000-0000-0000-000000000001"
    b2b_require_external_sponsor_approval = true
    b2b_connected_organization = {
      display_name = "Fabrikam Affiliated Clinic"
      domain_name  = "fabrikam-clinic.example"
      tenant_id    = "90000000-0000-0000-0000-0000000000aa"
    }
  }

  assert {
    condition = (
      azuread_access_package_assignment_policy.b2b[0].requestor_settings[0].scope_type == "SpecificConnectedOrganizationSubjects" &&
      azuread_access_package_assignment_policy.b2b[0].requestor_settings[0].requestor[0].subject_type == "ConnectedOrganizationMembers" &&
      azuread_access_package_assignment_policy.b2b[0].requestor_settings[0].requestor[0].object_id == "90000000-0000-0000-0000-000000000001"
    )
    error_message = "A known connected org id must narrow the policy to that organization."
  }
  assert {
    condition = (
      length(azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_stage) == 2 &&
      azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_stage[0].primary_approver[0].subject_type == "ExternalSponsors" &&
      azuread_access_package_assignment_policy.b2b[0].approval_settings[0].approval_stage[1].primary_approver[0].subject_type == "InternalSponsors"
    )
    error_message = "Two-stage approval must be clinic (external) sponsor first, Contoso internal sponsor last."
  }
  assert {
    condition     = jsondecode(output.b2b_post_apply.connected_organization_body).identitySources[0].tenantId == "90000000-0000-0000-0000-0000000000aa"
    error_message = "A tenant id must render an azureActiveDirectoryTenant identity source."
  }
}

run "b2b_rejects_long_guest_access" {
  command = plan

  variables {
    enable_b2b_governance        = true
    b2b_assignment_duration_days = 365
  }

  expect_failures = [var.b2b_assignment_duration_days]
}
