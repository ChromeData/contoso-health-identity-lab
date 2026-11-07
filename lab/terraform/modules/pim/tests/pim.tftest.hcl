# Offline mock tests for modules/pim (no tenant, no state):
#   terraform init -backend=false && terraform test
# Pins the privileged-access contract:
#   * the original Privileged-IAM-Admins binding, now with GROUP approvers,
#     expiring eligibility and guarded direct-active assignment;
#   * the full tier map (Tier 0 control plane / Tier 1 management plane),
#     per-tier activation strength, ticket, expiry and notifications;
#   * guardrails: no Global Administrator in a tier group, no Tier-0 role in a
#     Tier-1 group, no Tier-0 group without approval, no override longer than
#     the tier cap, no auth context before CA021 is enforced;
#   * help-desk AU scoping, the Global Administrator rule bodies and the
#     PIM-eligible review bodies (rendered JSON, decoded and checked);
#   * Azure-resource PIM: a GROUP eligible (never active), Tier-0 approvers;
#   * Key Vault Secrets Officer (keyvault.tf): a role-assignable GROUP eligible
#     at vault scope, 2-hour MFA + justification + Tier-0 approval activation;
#   * AWS admin (aws.tf): a role-assignable PIM group, eligible-only, 2-hour
#     MFA + justification activation, every activation mailed, reviewed
#     quarterly but outside the CA002 / CA020 scope;
#   * read-only presenter (demo-readers.tf): a role-assignable PIM group that
#     actively holds exactly Global Reader + Security Reader, eligible-only,
#     8-hour MFA + justification activation with NO approval, every
#     activation mailed, reviewed quarterly but outside the CA002 / CA020
#     scope and CA020's role list, tier map unchanged;
#   * every feature defaults OFF.
#
# Mocked ids are GUID-shaped because the providers still validate arguments
# such as group_id / principal_id during a mocked apply. Every mocked group
# shares one object id, so assertions compare against the resource's own id.

mock_provider "azuread" {
  mock_resource "azuread_group" {
    defaults = {
      id        = "/groups/55555555-5555-5555-5555-555555555555"
      object_id = "55555555-5555-5555-5555-555555555555"
    }
  }
  mock_resource "azuread_administrative_unit" {
    defaults = {
      id        = "/administrativeUnits/66666666-6666-6666-6666-666666666666"
      object_id = "66666666-6666-6666-6666-666666666666"
    }
  }
}

mock_provider "azurerm" {}

variables {
  priv_iam_admins_group_object_id = "11111111-1111-1111-1111-111111111111"
  approver_object_ids             = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
  # A governance fallback reviewer, as envs/dev passes one; runs about the
  # "no reviewer" path clear it.
  privileged_review_fallback_group_object_id = "88888888-8888-8888-8888-888888888888"
}

# =============================================================================
# Defaults
# =============================================================================

run "defaults_only_the_original_binding" {
  command = plan

  variables {
    privileged_review_fallback_group_object_id = ""
  }

  assert {
    condition     = azuread_directory_role_assignment.priv_admins.role_id == "fe930be7-5e62-47db-91af-98c3a49a38b1"
    error_message = "Privileged-IAM-Admins must still hold User Administrator."
  }
  assert {
    condition     = azuread_group_role_management_policy.member.activation_rules[0].maximum_duration == "PT4H"
    error_message = "The original activation policy must keep its 4h cap."
  }
  assert {
    condition     = length(azuread_group.pim_tier) == 0 && length(azuread_group.azure_pim) == 0 && length(azuread_administrative_unit.workforce_standard) == 0
    error_message = "No tier, Azure PIM group or administrative unit may exist while their flags are off."
  }
  assert {
    condition     = length(azurerm_pim_eligible_role_assignment.azure_pim) == 0 && length(azurerm_role_management_policy.azure_pim) == 0
    error_message = "No Azure PIM resource may be planned while enable_pim_azure_resources = false."
  }
  assert {
    condition     = length(azuread_group.keyvault_pim) == 0 && length(azurerm_pim_eligible_role_assignment.keyvault_pim) == 0 && length(azurerm_role_management_policy.keyvault_pim) == 0
    error_message = "No Key Vault PIM resource may be planned while enable_pim_keyvault_officers = false."
  }
  assert {
    condition     = length(azuread_group.aws_admin) == 0 && length(azuread_group_role_management_policy.aws_admin_member) == 0 && output.aws_admin_group_object_id == null
    error_message = "No AWS admin PIM group may exist while enable_pim_aws_admin = false."
  }
  assert {
    condition     = length(azuread_group.demo_readers) == 0 && length(azuread_directory_role_assignment.demo_readers) == 0 && length(azuread_group_role_management_policy.demo_readers_member) == 0 && output.demo_readers_group_object_id == null && output.demo_readers_activation_policy == null
    error_message = "No read-only presenter PIM group (nor its role bindings or policy) may exist while enable_pim_demo_readers = false."
  }
  assert {
    condition     = keys(output.privileged_review_targets) == ["Privileged-IAM-Admins"]
    error_message = "With every flag off, only Privileged-IAM-Admins is a review target."
  }
  assert {
    condition     = keys(azuread_group.pim_approvers) == ["tier1"] && azuread_group.pim_approvers["tier1"].assignable_to_role && azuread_group.pim_approvers["tier1"].display_name == "PIM-Approvers-Tier1"
    error_message = "Only the (role-assignable) Tier-1 approver group exists by default - it approves Privileged-IAM-Admins."
  }
  assert {
    condition     = toset(azuread_group.pim_approvers["tier1"].members) == toset(["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"])
    error_message = "approver_object_ids must become the members of PIM-Approvers-Tier1."
  }
  assert {
    condition     = one(azuread_group_role_management_policy.member.activation_rules[0].approval_stage[0].primary_approver).type == "groupMembers"
    error_message = "Approval must route to the approver GROUP (groupMembers), never singleUser."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.member.eligible_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.member.eligible_assignment_rules[0].expire_after == "P365D"
    )
    error_message = "Privileged-IAM-Admins eligibility must expire (Tier-1 cap, P365D)."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.member.active_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.member.active_assignment_rules[0].expire_after == "P15D" &&
      azuread_group_role_management_policy.member.active_assignment_rules[0].require_justification &&
      azuread_group_role_management_policy.member.active_assignment_rules[0].require_multifactor_authentication
    )
    error_message = "Direct active membership: never permanent (P15D), justification + MFA."
  }
  assert {
    condition     = length(azuread_group_role_management_policy.member.notification_rules) == 0
    error_message = "Without pim_alert_mailbox the notification rules stay at the tenant default."
  }
  assert {
    condition     = length(output.pim_eligible_review_bodies) == 0 && length(output.directory_role_pim_policies) == 0 && output.workforce_au_membership_body == null
    error_message = "Review bodies, Global Administrator rules and the AU body render nothing by default."
  }
}

run "one_approver_warns" {
  command = plan

  variables {
    approver_object_ids = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]
  }

  # A check is a warning, not a failure: the plan still succeeds.
  expect_failures = [check.approver_groups_have_two_members]
}

# =============================================================================
# Tier map
# =============================================================================

run "tier_groups" {
  command = apply

  variables {
    enable_pim_tiers          = true
    tier0_approver_object_ids = ["cccccccc-cccc-cccc-cccc-cccccccccccc", "dddddddd-dddd-dddd-dddd-dddddddddddd"]
  }

  assert {
    condition     = length(azuread_group.pim_tier) == 16 && alltrue([for g in azuread_group.pim_tier : g.assignable_to_role])
    error_message = "Sixteen role-assignable tier groups expected (8 Tier-0, 8 Tier-1)."
  }
  assert {
    condition = (
      azuread_directory_role_assignment.pim_tier["tier0_security_admins"].role_id == "194ae4cb-b126-40b2-bd5b-6091b380977d" &&
      azuread_directory_role_assignment.pim_tier["tier0_ca_admins"].role_id == "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" &&
      azuread_directory_role_assignment.pim_tier["tier0_privileged_role_admins"].role_id == "e8611ab8-c189-46e8-94e1-60213ab1f814" &&
      azuread_directory_role_assignment.pim_tier["tier0_privileged_auth_admins"].role_id == "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" &&
      azuread_directory_role_assignment.pim_tier["tier0_hybrid_identity_admins"].role_id == "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" &&
      azuread_directory_role_assignment.pim_tier["tier0_application_admins"].role_id == "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" &&
      azuread_directory_role_assignment.pim_tier["tier0_cloud_application_admins"].role_id == "158c047a-c907-4556-b7ef-446551a6b5f7" &&
      azuread_directory_role_assignment.pim_tier["tier0_auth_policy_admins"].role_id == "0526716b-113d-4c15-b2c8-68e3c22b9f80" &&
      azuread_directory_role_assignment.pim_tier["tier1_intune_admins"].role_id == "3a2c62db-5318-420d-8d74-23affee5d9d5" &&
      azuread_directory_role_assignment.pim_tier["tier1_helpdesk"].role_id == "729827e3-9c14-49f7-bb1b-9608f156bbb8" &&
      azuread_directory_role_assignment.pim_tier["tier1_groups_admins"].role_id == "fdd7a751-b60b-444a-984c-02652fe8fa1c" &&
      azuread_directory_role_assignment.pim_tier["tier1_exchange_admins"].role_id == "29232cdf-9323-42fd-ade2-1d097af3e4de" &&
      azuread_directory_role_assignment.pim_tier["tier1_sharepoint_admins"].role_id == "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" &&
      azuread_directory_role_assignment.pim_tier["tier1_teams_admins"].role_id == "69091246-20e8-4a56-aa4d-066075b2a7a8" &&
      azuread_directory_role_assignment.pim_tier["tier1_license_admins"].role_id == "4d6ac14f-3453-41d0-bef9-a3e0c569773a" &&
      azuread_directory_role_assignment.pim_tier["tier1_iga_admins"].role_id == "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e"
    )
    error_message = "Each tier group must be bound to its role template (the tier map in variables.tf pim_tier_groups)."
  }
  assert {
    condition = (
      azuread_directory_role_assignment.pim_tier_additional["tier1_helpdesk:c4e39bd9-1100-46d3-8c65-fb160da0071f"].role_id == "c4e39bd9-1100-46d3-8c65-fb160da0071f" &&
      azuread_directory_role_assignment.pim_tier_additional["tier1_iga_admins:59d46f88-662b-457b-bceb-5c3809e5908f"].role_id == "59d46f88-662b-457b-bceb-5c3809e5908f" &&
      length(azuread_directory_role_assignment.pim_tier_additional) == 2
    )
    error_message = "The service desk group must also hold Authentication Administrator, the IGA group Lifecycle Workflows Administrator - and nothing else extra."
  }
  assert {
    condition     = alltrue([for a in concat(values(azuread_directory_role_assignment.pim_tier), values(azuread_directory_role_assignment.pim_tier_additional)) : a.directory_scope_id == "/"])
    error_message = "With AU scoping off every tier role is tenant-wide."
  }
  assert {
    condition = alltrue([for k in ["tier0_security_admins", "tier0_ca_admins", "tier0_privileged_role_admins", "tier0_privileged_auth_admins", "tier0_hybrid_identity_admins", "tier0_application_admins", "tier0_cloud_application_admins", "tier0_auth_policy_admins"] :
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_approval &&
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_multifactor_authentication &&
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_justification &&
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_ticket_info &&
      one(azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].approval_stage[0].primary_approver).type == "groupMembers" &&
      one(azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].approval_stage[0].primary_approver).object_id == azuread_group.pim_approvers["tier0"].object_id &&
      azuread_group_role_management_policy.pim_tier_member[k].eligible_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.pim_tier_member[k].eligible_assignment_rules[0].expire_after == "P180D"
    ])
    error_message = "Tier 0 = MFA + justification + ticket + approval by PIM-Approvers-Tier0 (groupMembers); eligibility expires after 180 days."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.pim_tier_member["tier0_ca_admins"].activation_rules[0].maximum_duration == "PT4H" &&
      azuread_group_role_management_policy.pim_tier_member["tier0_privileged_auth_admins"].activation_rules[0].maximum_duration == "PT2H"
    )
    error_message = "Tier-0 cap is 4h; Privileged Authentication Administrator is shortened to 2h (help-desk runbook, V3)."
  }
  assert {
    condition = alltrue([for k in ["tier1_helpdesk", "tier1_groups_admins", "tier1_exchange_admins", "tier1_sharepoint_admins", "tier1_teams_admins", "tier1_license_admins"] :
      !azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_approval &&
      length(azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].approval_stage) == 0 &&
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_multifactor_authentication &&
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].require_justification &&
      azuread_group_role_management_policy.pim_tier_member[k].activation_rules[0].maximum_duration == "PT8H" &&
      azuread_group_role_management_policy.pim_tier_member[k].eligible_assignment_rules[0].expire_after == "P365D"
    ])
    error_message = "Tier 1 = MFA + justification, no approval, 8h max, eligibility expires after 365 days."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.pim_tier_member["tier1_intune_admins"].activation_rules[0].require_approval &&
      one(azuread_group_role_management_policy.pim_tier_member["tier1_intune_admins"].activation_rules[0].approval_stage[0].primary_approver).object_id == azuread_group.pim_approvers["tier1"].object_id
    )
    error_message = "Intune Administrator (LAPS / BitLocker keys) is Tier 1 WITH approval by PIM-Approvers-Tier1."
  }
  assert {
    # The roles that run the lab's own access automation (birthright policies,
    # catalogs, SoD links, the joiner TAP workflow) are just-in-time with approval.
    condition = (
      azuread_group_role_management_policy.pim_tier_member["tier1_iga_admins"].activation_rules[0].require_approval &&
      one(azuread_group_role_management_policy.pim_tier_member["tier1_iga_admins"].activation_rules[0].approval_stage[0].primary_approver).object_id == azuread_group.pim_approvers["tier1"].object_id &&
      contains(output.privileged_role_template_ids.tier1, "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e") &&
      contains(output.privileged_role_template_ids.tier1, "59d46f88-662b-457b-bceb-5c3809e5908f") &&
      contains(keys(output.privileged_review_targets), "PIM-Tier1-IGA-Admins")
    )
    error_message = "Identity Governance + Lifecycle Workflows Administrator: Tier-1 group WITH approval, in the CA020 role list and the privileged review."
  }
  assert {
    condition = alltrue([for p in azuread_group_role_management_policy.pim_tier_member :
      p.active_assignment_rules[0].expiration_required && p.active_assignment_rules[0].expire_after == "P15D" &&
    p.active_assignment_rules[0].require_justification && p.active_assignment_rules[0].require_multifactor_authentication])
    error_message = "Direct active membership of a tier group must always expire (P15D) and need justification + MFA."
  }
  assert {
    condition     = toset(azuread_group.pim_approvers["tier0"].members) == toset(["cccccccc-cccc-cccc-cccc-cccccccccccc", "dddddddd-dddd-dddd-dddd-dddddddddddd"]) && azuread_group.pim_approvers["tier0"].assignable_to_role
    error_message = "tier0_approver_object_ids must become the members of the role-assignable PIM-Approvers-Tier0."
  }
  assert {
    condition     = length(output.privileged_review_targets) == 17 && contains(keys(output.privileged_review_targets), "PIM-Tier0-Privileged-Role-Admins")
    error_message = "Every tier group (and Privileged-IAM-Admins) must feed the privileged access review."
  }
  assert {
    condition     = output.tier_group_mail_nicknames["PIM-Tier1-Helpdesk"] == "pim-tier1-helpdesk" && output.tier_activation_policies["PIM-Tier0-CA-Admins"].approver_group == "PIM-Approvers-Tier0"
    error_message = "Existing contract names (PIM-Tier1-Helpdesk / pim-tier1-helpdesk) must not change; the walkthrough output names the approver group."
  }
  assert {
    condition     = contains(output.privileged_role_template_ids.tier0, "62e90394-69f5-4237-9190-012177145e10") && contains(output.privileged_role_template_ids.tier1, "c4e39bd9-1100-46d3-8c65-fb160da0071f") && length(output.privileged_role_template_ids.tier0) == 9
    error_message = "privileged_role_template_ids: tier0 = GA + 8 control-plane roles; tier1 includes the help-desk roles."
  }
}

run "notifications_follow_the_tier" {
  command = plan

  variables {
    enable_pim_tiers  = true
    pim_alert_mailbox = "pim-alerts@contoso.test"
  }

  assert {
    condition = alltrue([for k in ["tier0_ca_admins", "tier1_intune_admins"] :
      length(azuread_group_role_management_policy.pim_tier_member[k].notification_rules[0].eligible_activations) == 1 &&
      contains(azuread_group_role_management_policy.pim_tier_member[k].notification_rules[0].eligible_activations[0].admin_notifications[0].additional_recipients, "pim-alerts@contoso.test")
    ])
    error_message = "Tier 0 and approval-gated Tier 1 alert the security mailbox on every activation."
  }
  assert {
    condition = (
      length(azuread_group_role_management_policy.pim_tier_member["tier1_helpdesk"].notification_rules[0].eligible_activations) == 0 &&
      contains(azuread_group_role_management_policy.pim_tier_member["tier1_helpdesk"].notification_rules[0].eligible_assignments[0].admin_notifications[0].additional_recipients, "pim-alerts@contoso.test") &&
      contains(azuread_group_role_management_policy.pim_tier_member["tier1_helpdesk"].notification_rules[0].active_assignments[0].admin_notifications[0].additional_recipients, "pim-alerts@contoso.test")
    )
    error_message = "A no-approval Tier-1 group alerts on assignments (eligible + direct active), not on every shift's activation."
  }
  assert {
    condition = alltrue([for p in azuread_group_role_management_policy.pim_tier_member :
    p.notification_rules[0].active_assignments[0].admin_notifications[0].notification_level == "All" && p.notification_rules[0].active_assignments[0].admin_notifications[0].default_recipients])
    error_message = "Direct active assignment (an activation bypass) alerts on every group, level All, default recipients kept."
  }
  assert {
    condition     = length(azuread_group_role_management_policy.member.notification_rules[0].eligible_activations) == 1
    error_message = "Privileged-IAM-Admins is approval-gated: activation alerts too."
  }
}

run "mailbox_must_be_an_address" {
  command = plan

  variables {
    pim_alert_mailbox = "not an address"
  }

  expect_failures = [var.pim_alert_mailbox]
}

# =============================================================================
# Tier-0 step-up: auth context c1 (CA021) and the two-apply switch-over
# =============================================================================

run "tier0_auth_context_needs_ca021_enforced" {
  command = plan

  variables {
    enable_pim_tiers                 = true
    tier0_activation_auth_context_id = "c1"
  }

  expect_failures = [azuread_group_role_management_policy.pim_tier_member]
}

run "tier0_auth_context_replaces_mfa" {
  command = plan

  variables {
    enable_pim_tiers                    = true
    tier0_activation_auth_context_id    = "c1"
    activation_auth_context_ca_enforced = true
  }

  # The plan itself proves MFA is unset: the provider rejects the two
  # arguments together (ConflictsWith), so this run would error otherwise.
  assert {
    condition     = azuread_group_role_management_policy.pim_tier_member["tier0_ca_admins"].activation_rules[0].required_conditional_access_authentication_context == "c1"
    error_message = "With an auth context, Tier 0 must use it instead of the plain MFA flag."
  }
  assert {
    condition     = azuread_group_role_management_policy.pim_tier_member["tier1_helpdesk"].activation_rules[0].require_multifactor_authentication == true
    error_message = "Tier 1 keeps plain MFA; the auth context is Tier-0 only."
  }
}

run "switchover_apply1_drops_mfa_and_warns" {
  command = plan

  variables {
    enable_pim_tiers                    = true
    tier0_auth_context_switchover_step1 = true
    activation_auth_context_ca_enforced = true
  }

  expect_failures = [check.tier0_step_up_switchover_in_progress]

  assert {
    condition     = azuread_group_role_management_policy.pim_tier_member["tier0_security_admins"].activation_rules[0].require_multifactor_authentication == false && azuread_group_role_management_policy.pim_tier_member["tier0_security_admins"].activation_rules[0].require_approval
    error_message = "Apply 1 sends MFA = false explicitly (so the Enablement rule is re-sent); approval stays."
  }
}

run "switchover_needs_ca021_enforced" {
  command = plan

  variables {
    enable_pim_tiers                    = true
    tier0_auth_context_switchover_step1 = true
  }

  expect_failures = [azuread_group_role_management_policy.pim_tier_member, check.tier0_step_up_switchover_in_progress]
}

run "auth_context_id_range" {
  command = plan

  variables {
    tier0_activation_auth_context_id = "c26"
  }

  expect_failures = [var.tier0_activation_auth_context_id]
}

# =============================================================================
# Guardrails on the tier map
# =============================================================================

run "tier0_without_approvers_fails" {
  command = plan

  variables {
    enable_pim_tiers    = true
    require_approval    = false
    approver_object_ids = []
  }

  expect_failures = [azuread_group_role_management_policy.pim_tier_member, check.approver_groups_have_two_members]
}

run "tier_groups_reject_global_admin" {
  command = plan

  variables {
    enable_pim_tiers = true
    pim_tier_groups = {
      oops = {
        display_name     = "PIM-Tier0-Global-Admins"
        mail_nickname    = "pim-tier0-global-admins"
        role_name        = "Global Administrator"
        role_template_id = "62e90394-69f5-4237-9190-012177145e10"
        tier             = 0
      }
    }
  }

  expect_failures = [var.pim_tier_groups]
}

run "tier_groups_reject_global_admin_as_additional_role" {
  command = plan

  variables {
    enable_pim_tiers = true
    pim_tier_groups = {
      sneaky = {
        display_name                 = "PIM-Tier0-Security-Admins"
        mail_nickname                = "pim-tier0-security-admins"
        role_name                    = "Security Administrator"
        role_template_id             = "194ae4cb-b126-40b2-bd5b-6091b380977d"
        tier                         = 0
        additional_role_template_ids = ["62e90394-69f5-4237-9190-012177145e10"]
      }
    }
  }

  expect_failures = [var.pim_tier_groups]
}

run "tier1_group_cannot_hold_a_tier0_role" {
  command = plan

  variables {
    enable_pim_tiers = true
    pim_tier_groups = {
      downgrade = {
        display_name     = "PIM-Tier1-CA-Admins"
        mail_nickname    = "pim-tier1-ca-admins"
        role_name        = "Conditional Access Administrator"
        role_template_id = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
        tier             = 1
      }
    }
  }

  expect_failures = [var.pim_tier_groups]
}

run "tier0_group_cannot_waive_approval" {
  command = plan

  variables {
    enable_pim_tiers = true
    pim_tier_groups = {
      noapproval = {
        display_name     = "PIM-Tier0-Security-Admins"
        mail_nickname    = "pim-tier0-security-admins"
        role_name        = "Security Administrator"
        role_template_id = "194ae4cb-b126-40b2-bd5b-6091b380977d"
        tier             = 0
        require_approval = false
      }
    }
  }

  expect_failures = [var.pim_tier_groups]
}

run "au_scope_only_for_au_assignable_roles" {
  command = plan

  variables {
    enable_pim_tiers = true
    pim_tier_groups = {
      intune_au = {
        display_name     = "PIM-Tier1-Intune-Admins"
        mail_nickname    = "pim-tier1-intune-admins"
        role_name        = "Intune Administrator"
        role_template_id = "3a2c62db-5318-420d-8d74-23affee5d9d5"
        tier             = 1
        au_scoped        = true
      }
    }
  }

  expect_failures = [var.pim_tier_groups]
}

run "override_cannot_lengthen_the_tier_cap" {
  command = plan

  variables {
    enable_pim_tiers = true
    pim_tier_groups = {
      long = {
        display_name            = "PIM-Tier1-License-Admins"
        mail_nickname           = "pim-tier1-license-admins"
        role_name               = "License Administrator"
        role_template_id        = "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
        tier                    = 1
        activation_max_duration = "PT12H"
      }
    }
  }

  expect_failures = [azuread_group_role_management_policy.pim_tier_member]
}

run "tier0_eligibility_capped_at_180_days" {
  command = plan

  variables {
    tier0_eligible_assignment_duration = "P365D"
  }

  expect_failures = [var.tier0_eligible_assignment_duration]
}

# =============================================================================
# Help-desk scoping (administrative unit)
# =============================================================================

run "helpdesk_au_scoping" {
  command = apply

  variables {
    enable_pim_tiers           = true
    enable_helpdesk_au_scoping = true
  }

  assert {
    condition     = azuread_administrative_unit.workforce_standard[0].display_name == "AU-Workforce-Standard" && azuread_administrative_unit.workforce_standard[0].prevent_duplicate_names
    error_message = "AU-Workforce-Standard must be created (duplicate names refused)."
  }
  assert {
    condition = (
      azuread_directory_role_assignment.pim_tier["tier1_helpdesk"].directory_scope_id == "/administrativeUnits/66666666-6666-6666-6666-666666666666" &&
      azuread_directory_role_assignment.pim_tier_additional["tier1_helpdesk:c4e39bd9-1100-46d3-8c65-fb160da0071f"].directory_scope_id == "/administrativeUnits/66666666-6666-6666-6666-666666666666"
    )
    error_message = "Helpdesk and Authentication Administrator must be assigned at AU-Workforce-Standard scope."
  }
  assert {
    condition     = alltrue([for k, a in azuread_directory_role_assignment.pim_tier : a.directory_scope_id == "/" if k != "tier1_helpdesk"])
    error_message = "Only au_scoped groups move to the AU; every other tier role stays tenant-wide."
  }
  assert {
    condition     = azuread_directory_role_assignment.pim_tier["tier1_helpdesk"].principal_object_id == azuread_group.pim_tier["tier1_helpdesk"].object_id && azuread_group.pim_tier["tier1_helpdesk"].assignable_to_role
    error_message = "The AU-scoped roles are held by the role-assignable service-desk PIM group, not by people."
  }
  assert {
    condition = (
      jsondecode(output.workforce_au_membership_body).membershipType == "Dynamic" &&
      jsondecode(output.workforce_au_membership_body).membershipRuleProcessingState == "On" &&
      strcontains(jsondecode(output.workforce_au_membership_body).membershipRule, "user.employeeId -ne null")
    )
    error_message = "The dynamic-membership PATCH body must be rendered for the tenant-time step."
  }
  assert {
    condition     = output.tier_activation_policies["PIM-Tier1-Helpdesk"].scope == "AU-Workforce-Standard"
    error_message = "The walkthrough output must show the service desk's AU scope."
  }
}

run "helpdesk_au_excludes_vips" {
  command = plan

  variables {
    enable_pim_tiers                   = true
    enable_helpdesk_au_scoping         = true
    workforce_au_excluded_employee_ids = ["300001", "400100"]
  }

  # The VIPs in RMAU-VIP are kept out of the help desk's AU by HR employee
  # id, AFTER the base rule (which still keeps adm- accounts and anyone
  # without an employeeId out).
  assert {
    condition     = jsondecode(output.workforce_au_membership_body).membershipRule == "(${var.workforce_au_membership_rule}) -and (user.employeeId -notIn [\"300001\",\"400100\"])"
    error_message = "The rendered AU rule must wrap the base rule and append the employeeId -notIn exclusion."
  }
}

run "helpdesk_au_exclusion_survives_an_or_rule" {
  command = plan

  variables {
    enable_pim_tiers                   = true
    enable_helpdesk_au_scoping         = true
    workforce_au_membership_rule       = "(user.department -eq \"Nursing\") -or (user.department -eq \"ICU\")"
    workforce_au_excluded_employee_ids = ["300001"]
  }

  # -and binds tighter than -or: unwrapped, the exclusion would cover only
  # the ICU branch and an excluded Nursing VIP would stay in the AU.
  assert {
    condition     = jsondecode(output.workforce_au_membership_body).membershipRule == "((user.department -eq \"Nursing\") -or (user.department -eq \"ICU\")) -and (user.employeeId -notIn [\"300001\"])"
    error_message = "A base rule with -or must be parenthesised as a whole before the exclusion is appended."
  }
}

run "helpdesk_au_default_rule_unchanged" {
  command = plan

  variables {
    enable_pim_tiers           = true
    enable_helpdesk_au_scoping = true
  }

  assert {
    condition     = jsondecode(output.workforce_au_membership_body).membershipRule == var.workforce_au_membership_rule && !strcontains(jsondecode(output.workforce_au_membership_body).membershipRule, "notIn")
    error_message = "With no excluded ids the AU rule is exactly workforce_au_membership_rule."
  }
}

run "helpdesk_au_excluded_id_must_be_plain" {
  command = plan

  variables {
    enable_pim_tiers                   = true
    enable_helpdesk_au_scoping         = true
    workforce_au_excluded_employee_ids = ["300001\"]) -or (user.userType -eq \"Guest"]
  }

  # An id that could break out of the quoted list is refused.
  expect_failures = [var.workforce_au_excluded_employee_ids]
}

run "au_scoping_without_tiers_warns_and_plans_nothing" {
  command = plan

  variables {
    enable_helpdesk_au_scoping = true
  }

  expect_failures = [check.helpdesk_au_scoping_needs_tiers]

  assert {
    condition     = length(azuread_administrative_unit.workforce_standard) == 0
    error_message = "No AU without a group to scope."
  }
}

# =============================================================================
# Global Administrator: rendered Graph rule bodies
# =============================================================================

run "global_admin_policy_bodies" {
  command = apply

  variables {
    enable_global_admin_pim_policy = true
    pim_alert_mailbox              = "pim-alerts@contoso.test"
  }

  assert {
    condition     = jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).eligibilityDuration == "P180D" && jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).allowNamedEligibility
    error_message = "Global Administrator: named eligibility, 180 days."
  }
  assert {
    condition = (
      contains([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.id], "Expiration_Admin_Eligibility") &&
      one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.maximumDuration if r.id == "Expiration_Admin_Eligibility"]) == "P180D" &&
      one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.isExpirationRequired if r.id == "Expiration_Admin_Eligibility"])
    )
    error_message = "GA eligibility must be required to expire (P180D)."
  }
  assert {
    condition     = one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.maximumDuration if r.id == "Expiration_EndUser_Assignment"]) == "PT2H"
    error_message = "GA activation is capped at 2 hours."
  }
  assert {
    condition     = toset(one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.enabledRules if r.id == "Enablement_EndUser_Assignment"])) == toset(["MultiFactorAuthentication", "Justification", "Ticketing"])
    error_message = "Without an auth context, GA activation needs MFA + justification + ticket."
  }
  assert {
    condition     = one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.isEnabled if r.id == "AuthenticationContext_EndUser_Assignment"]) == false
    error_message = "The auth-context rule stays off until CA021 is enforced."
  }
  assert {
    condition = (
      one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.setting.isApprovalRequired if r.id == "Approval_EndUser_Assignment"]) &&
      one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.setting.approvalStages[0].primaryApprovers[0] if r.id == "Approval_EndUser_Assignment"]) == { "@odata.type" = "#microsoft.graph.groupMembers", groupId = azuread_group.pim_approvers["tier0"].object_id }
    )
    error_message = "GA activation is approved by the PIM-Approvers-Tier0 GROUP."
  }
  assert {
    condition     = !contains([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.id], "Expiration_Admin_Assignment") && !contains([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.id], "Enablement_Admin_Assignment")
    error_message = "Direct-active GA rules are never rendered: break-glass's standing assignment must stay creatable."
  }
  assert {
    condition     = length([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r if startswith(r.id, "Notification_Admin_") && contains(r.notificationRecipients, "pim-alerts@contoso.test")]) == 3
    error_message = "Three GA admin notifications (activation, eligible, active) go to the security mailbox."
  }
  assert {
    condition     = keys(azuread_group.pim_approvers) == ["tier0", "tier1"]
    error_message = "The GA policy needs the Tier-0 approver group even with tier groups off."
  }
}

run "global_admin_with_auth_context" {
  command = apply

  variables {
    enable_global_admin_pim_policy      = true
    tier0_activation_auth_context_id    = "c1"
    activation_auth_context_ca_enforced = true
  }

  assert {
    condition     = toset(one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.enabledRules if r.id == "Enablement_EndUser_Assignment"])) == toset(["Justification", "Ticketing"])
    error_message = "With the context, MFA leaves the Enablement rule (the context replaces it)."
  }
  assert {
    condition = (
      one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.isEnabled if r.id == "AuthenticationContext_EndUser_Assignment"]) &&
      one([for r in jsondecode(output.directory_role_pim_policies["62e90394-69f5-4237-9190-012177145e10"]).rules : r.claimValue if r.id == "AuthenticationContext_EndUser_Assignment"]) == "c1"
    )
    error_message = "The context rule must be enabled with claim c1."
  }
}

run "global_admin_policy_needs_tier0_approvers" {
  command = plan

  variables {
    enable_global_admin_pim_policy = true
    require_approval               = false
    approver_object_ids            = []
  }

  expect_failures = [output.directory_role_pim_policies, check.approver_groups_have_two_members]
}

run "global_admin_policy_needs_ca021_for_context" {
  command = plan

  variables {
    enable_global_admin_pim_policy   = true
    tier0_activation_auth_context_id = "c1"
  }

  expect_failures = [output.directory_role_pim_policies]
}

# =============================================================================
# Reviews of PIM-eligible membership
# =============================================================================

run "pim_eligible_review_bodies" {
  command = apply

  variables {
    enable_pim_tiers                           = true
    enable_global_admin_pim_policy             = true
    privileged_review_reviewer_group_object_id = "77777777-7777-7777-7777-777777777777"
    privileged_review_fallback_group_object_id = "88888888-8888-8888-8888-888888888888"
  }

  assert {
    condition     = length(output.pim_eligible_review_bodies) == 18 && alltrue([for k in keys(output.pim_eligible_review_bodies) : startswith(k, "privileged:")])
    error_message = "One review per PIM-governed group (IAM + 16 tiers) + eligible GA, keyed privileged:<name>."
  }
  assert {
    condition = (
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).displayName == "Privileged access review: PIM-Tier0-CA-Admins" &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).scope.query == "/groups/${azuread_group.pim_tier["tier0_ca_admins"].object_id}/transitiveMembers" &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).reviewers[0].query == "/groups/77777777-7777-7777-7777-777777777777/transitiveMembers" &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).fallbackReviewers[0].query == "/groups/88888888-8888-8888-8888-888888888888/transitiveMembers"
    )
    error_message = "Group review: same display name as modules/entitlement, transitiveMembers scope, governance reviewer + fallback."
  }
  assert {
    condition = (
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).settings.defaultDecision == "Deny" &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).settings.autoApplyDecisionsEnabled &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).settings.justificationRequiredOnApproval &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).settings.instanceDurationInDays == 14 &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).settings.recurrence.pattern.interval == 3 &&
      jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Tier0-CA-Admins"]).settings.recurrence.range.startDate == null
    )
    error_message = "ADR 0012 T1: quarterly, 14-day instance, silence = deny (auto-applied), justification; startDate left to the script."
  }
  assert {
    condition = (
      strcontains(jsondecode(output.pim_eligible_review_bodies["privileged:Global Administrator (eligible)"]).scope.query, "/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal") &&
      strcontains(jsondecode(output.pim_eligible_review_bodies["privileged:Global Administrator (eligible)"]).scope.query, "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'") &&
      !strcontains(jsondecode(output.pim_eligible_review_bodies["privileged:Global Administrator (eligible)"]).scope.query, "/roleDefinitions/")
    )
    error_message = "The GA review covers ELIGIBLE users only - never the eligible+active role scope, which would put break-glass in a default-deny review."
  }
}

run "no_fallback_no_review_bodies" {
  command = plan

  variables {
    enable_pim_tiers                           = true
    privileged_review_fallback_group_object_id = ""
  }

  expect_failures = [check.pim_reviews_have_reviewers]

  assert {
    condition     = length(output.pim_eligible_review_bodies) == 0
    error_message = "Without a fallback reviewer nothing renders (default-deny with nobody to answer would revoke everything)."
  }
}

run "reviewer_group_cannot_be_a_reviewed_group" {
  command = plan

  variables {
    privileged_review_reviewer_group_object_id = "11111111-1111-1111-1111-111111111111" # Privileged-IAM-Admins itself
    privileged_review_fallback_group_object_id = "88888888-8888-8888-8888-888888888888"
  }

  expect_failures = [output.pim_eligible_review_bodies]
}

# =============================================================================
# PIM for Azure resources
# =============================================================================

run "azure_resource_pim" {
  command = apply

  variables {
    enable_pim_azure_resources = true
    azure_pim_scope_id         = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab"
  }

  assert {
    condition     = azurerm_pim_eligible_role_assignment.azure_pim[0].role_definition_id == "/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
    error_message = "Eligible role must be Contributor, as a subscription-scoped role definition id."
  }
  assert {
    condition     = azurerm_pim_eligible_role_assignment.azure_pim[0].scope == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab"
    error_message = "Eligibility must be scoped to the lab resource group only."
  }
  assert {
    condition     = azurerm_pim_eligible_role_assignment.azure_pim[0].principal_id == azuread_group.azure_pim[0].object_id
    error_message = "The eligible principal must be the PIM group, not a person."
  }
  assert {
    condition     = azuread_group.azure_pim[0].assignable_to_role
    error_message = "The Azure PIM group must be role-assignable (protected membership)."
  }
  assert {
    condition = (
      azurerm_role_management_policy.azure_pim[0].activation_rules[0].require_approval &&
      azurerm_role_management_policy.azure_pim[0].activation_rules[0].require_multifactor_authentication &&
      azurerm_role_management_policy.azure_pim[0].activation_rules[0].require_justification &&
      azurerm_role_management_policy.azure_pim[0].activation_rules[0].maximum_duration == "PT4H"
    )
    error_message = "Azure Contributor activation over the DC's RG must be Tier-0 strength."
  }
  assert {
    condition = (
      one(azurerm_role_management_policy.azure_pim[0].activation_rules[0].approval_stage[0].primary_approver).type == "Group" &&
      one(azurerm_role_management_policy.azure_pim[0].activation_rules[0].approval_stage[0].primary_approver).object_id == azuread_group.pim_approvers["tier0"].object_id
    )
    error_message = "Azure PIM approvals route to the PIM-Approvers-Tier0 GROUP (azurerm vocabulary: Group)."
  }
  assert {
    condition     = azurerm_role_management_policy.azure_pim[0].eligible_assignment_rules[0].expiration_required == false
    error_message = "The policy must allow permanent eligibility, or the no-schedule (group) eligible assignment is rejected."
  }
  assert {
    condition = (
      azurerm_role_management_policy.azure_pim[0].active_assignment_rules[0].expiration_required &&
      azurerm_role_management_policy.azure_pim[0].active_assignment_rules[0].require_justification &&
      azurerm_role_management_policy.azure_pim[0].active_assignment_rules[0].require_multifactor_authentication
    )
    error_message = "A direct active Contributor assignment must expire and need justification + MFA."
  }
  assert {
    condition     = contains(keys(output.privileged_review_targets), "PIM-Azure-RG-Contributors")
    error_message = "The Azure PIM group must feed the privileged access review."
  }
}

run "azure_pim_needs_scope" {
  command = plan

  variables {
    enable_pim_azure_resources = true
  }

  expect_failures = [azurerm_role_management_policy.azure_pim]
}

run "azure_pim_rejects_owner" {
  command = plan

  variables {
    enable_pim_azure_resources     = true
    azure_pim_scope_id             = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab"
    azure_pim_role_definition_guid = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
  }

  expect_failures = [var.azure_pim_role_definition_guid]
}

# =============================================================================
# Just-in-time Key Vault Secrets Officer (keyvault.tf)
# =============================================================================

run "keyvault_officers_pim" {
  command = apply

  variables {
    enable_pim_keyvault_officers = true
    keyvault_pim_scope_id        = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab-20f1"
  }

  assert {
    condition     = azurerm_pim_eligible_role_assignment.keyvault_pim[0].role_definition_id == "/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
    error_message = "The eligible role must be Key Vault Secrets Officer (b86a8fe4-...), as a subscription-scoped role definition id."
  }
  assert {
    condition     = azurerm_pim_eligible_role_assignment.keyvault_pim[0].scope == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab-20f1"
    error_message = "Eligibility must be scoped to the lab vault only, not its resource group."
  }
  assert {
    condition     = azurerm_pim_eligible_role_assignment.keyvault_pim[0].principal_id == azuread_group.keyvault_pim[0].object_id && azuread_group.keyvault_pim[0].assignable_to_role
    error_message = "The eligible principal must be the role-assignable PIM group, not a person."
  }
  assert {
    condition = (
      azurerm_role_management_policy.keyvault_pim[0].activation_rules[0].require_approval &&
      azurerm_role_management_policy.keyvault_pim[0].activation_rules[0].require_multifactor_authentication &&
      azurerm_role_management_policy.keyvault_pim[0].activation_rules[0].require_justification &&
      azurerm_role_management_policy.keyvault_pim[0].activation_rules[0].maximum_duration == "PT2H"
    )
    error_message = "Key Vault Secrets Officer activation must need approval, MFA and a reason, for at most 2 hours by default."
  }
  assert {
    condition     = one(azurerm_role_management_policy.keyvault_pim[0].activation_rules[0].approval_stage[0].primary_approver).object_id == azuread_group.pim_approvers["tier0"].object_id
    error_message = "Key Vault approvals route to PIM-Approvers-Tier0 (the vault holds Tier-0 secrets)."
  }
  assert {
    condition     = azurerm_role_management_policy.keyvault_pim[0].active_assignment_rules[0].expiration_required
    error_message = "A direct active Key Vault Secrets Officer assignment through PIM must expire."
  }
  assert {
    condition     = contains(keys(output.privileged_review_targets), "PIM-KeyVault-Secrets-Officers")
    error_message = "The Key Vault PIM group must feed the privileged access review."
  }
}

run "keyvault_pim_needs_scope" {
  command = plan

  variables {
    enable_pim_keyvault_officers = true
  }

  expect_failures = [azurerm_role_management_policy.keyvault_pim]
}

run "keyvault_pim_scope_must_be_a_vault" {
  command = plan

  variables {
    enable_pim_keyvault_officers = true
    keyvault_pim_scope_id        = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab"
  }

  expect_failures = [var.keyvault_pim_scope_id]
}

run "keyvault_pim_capped_at_tier0" {
  command = plan

  variables {
    enable_pim_keyvault_officers         = true
    keyvault_pim_scope_id                = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab-20f1"
    keyvault_pim_activation_max_duration = "PT8H"
  }

  expect_failures = [var.keyvault_pim_activation_max_duration]
}

# =============================================================================
# role_template_id (Privileged-IAM-Admins, Tier-1 rules) cannot be a Tier-0 role
# =============================================================================

run "priv_iam_admins_cannot_hold_global_admin" {
  command = plan

  variables {
    role_template_id = "62e90394-69f5-4237-9190-012177145e10"
  }

  expect_failures = [var.role_template_id]
}

run "priv_iam_admins_cannot_hold_a_tier0_role" {
  command = plan

  variables {
    role_template_id = "e8611ab8-c189-46e8-94e1-60213ab1f814" # Privileged Role Administrator
  }

  expect_failures = [var.role_template_id]
}

# =============================================================================
# AWS administration through PIM for Groups (aws.tf, ADR 0025)
# =============================================================================

run "aws_admin_group" {
  command = apply

  variables {
    enable_pim_aws_admin = true
    pim_alert_mailbox    = "security@contosohealthlab.onmicrosoft.com"
  }

  assert {
    condition = (
      azuread_group.aws_admin[0].display_name == "PIM-AWS-Lab-Admins" &&
      azuread_group.aws_admin[0].mail_nickname == "pim-aws-lab-admins" &&
      azuread_group.aws_admin[0].assignable_to_role &&
      azuread_group.aws_admin[0].security_enabled &&
      !azuread_group.aws_admin[0].mail_enabled
    )
    error_message = "PIM-AWS-Lab-Admins: role-assignable security group (only Privileged Role Administrators change who can become AWS admin), no mailbox."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.aws_admin_member[0].group_id == azuread_group.aws_admin[0].object_id &&
      azuread_group_role_management_policy.aws_admin_member[0].role_id == "member" &&
      azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].maximum_duration == "PT2H" &&
      azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].require_multifactor_authentication &&
      azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].require_justification &&
      !azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].require_approval
    )
    error_message = "Activation of MEMBERSHIP: 2 hours, MFA, justification; no approval by default (one human admin, ADR 0025)."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.aws_admin_member[0].eligible_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.aws_admin_member[0].eligible_assignment_rules[0].expire_after == "P180D" &&
      azuread_group_role_management_policy.aws_admin_member[0].active_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.aws_admin_member[0].active_assignment_rules[0].expire_after == "P15D" &&
      azuread_group_role_management_policy.aws_admin_member[0].active_assignment_rules[0].require_justification &&
      azuread_group_role_management_policy.aws_admin_member[0].active_assignment_rules[0].require_multifactor_authentication
    )
    error_message = "Eligibility expires at the Tier-0 cap (P180D); a direct ACTIVE member expires too and needs justification + MFA."
  }
  assert {
    condition = (
      length(azuread_group_role_management_policy.aws_admin_member[0].notification_rules[0].eligible_activations) == 1 &&
      contains(azuread_group_role_management_policy.aws_admin_member[0].notification_rules[0].eligible_activations[0].admin_notifications[0].additional_recipients, "security@contosohealthlab.onmicrosoft.com") &&
      contains(azuread_group_role_management_policy.aws_admin_member[0].notification_rules[0].eligible_assignments[0].admin_notifications[0].additional_recipients, "security@contosohealthlab.onmicrosoft.com") &&
      contains(azuread_group_role_management_policy.aws_admin_member[0].notification_rules[0].active_assignments[0].admin_notifications[0].additional_recipients, "security@contosohealthlab.onmicrosoft.com")
    )
    error_message = "With approval off, EVERY activation (and every eligibility / direct active change) is mailed to the security mailbox."
  }
  assert {
    condition     = !contains(keys(output.privileged_review_targets), "PIM-AWS-Lab-Admins")
    error_message = "PIM-AWS-Lab-Admins must stay out of privileged_review_targets: that output is the CA002 / CA020 group scope, changed only on purpose."
  }
  assert {
    condition     = jsondecode(output.pim_eligible_review_bodies["privileged:PIM-AWS-Lab-Admins"]).scope.query == "/groups/${azuread_group.aws_admin[0].object_id}/transitiveMembers"
    error_message = "PIM-AWS-Lab-Admins must be in the quarterly privileged review (eligible + active members)."
  }
  assert {
    condition     = !contains(keys(azuread_group.pim_approvers), "tier0")
    error_message = "With approval off nothing routes to PIM-Approvers-Tier0, so the module must not create it for this group."
  }
  assert {
    condition     = output.aws_admin_group_mail_nickname == "pim-aws-lab-admins" && output.aws_admin_activation_policy.maximum_duration == "PT2H" && output.aws_admin_activation_policy.in_ca_admin_scope == false
    error_message = "Outputs: the mail nickname for Set-PimGroupEligibility.ps1 and the evidence summary."
  }
}

run "aws_admin_approval_routes_to_tier0" {
  command = apply

  variables {
    enable_pim_aws_admin       = true
    aws_admin_require_approval = true
    pim_alert_mailbox          = "security@contosohealthlab.onmicrosoft.com"
  }

  assert {
    condition = (
      azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].require_approval &&
      one(azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].approval_stage[0].primary_approver).type == "groupMembers" &&
      one(azuread_group_role_management_policy.aws_admin_member[0].activation_rules[0].approval_stage[0].primary_approver).object_id == azuread_group.pim_approvers["tier0"].object_id
    )
    error_message = "When approval is on it routes to the PIM-Approvers-Tier0 GROUP (AWS management-account admin is Tier 0)."
  }
}

run "aws_admin_without_mailbox_warns" {
  command = plan

  variables {
    enable_pim_aws_admin = true
  }

  expect_failures = [check.aws_admin_activations_are_seen]
}

run "aws_admin_activation_capped" {
  command = plan

  variables {
    enable_pim_aws_admin              = true
    aws_admin_activation_max_duration = "PT8H"
    pim_alert_mailbox                 = "security@contosohealthlab.onmicrosoft.com"
  }

  expect_failures = [var.aws_admin_activation_max_duration]
}

run "aws_admin_eligibility_capped_at_180_days" {
  command = plan

  variables {
    enable_pim_aws_admin                   = true
    aws_admin_eligible_assignment_duration = "P365D"
    pim_alert_mailbox                      = "security@contosohealthlab.onmicrosoft.com"
  }

  expect_failures = [var.aws_admin_eligible_assignment_duration]
}

# =============================================================================
# Read-only presenter access through PIM for Groups (demo-readers.tf)
# =============================================================================

run "demo_readers_group" {
  command = apply

  variables {
    enable_pim_demo_readers = true
    pim_alert_mailbox       = "security@contosohealthlab.onmicrosoft.com"
  }

  assert {
    condition = (
      azuread_group.demo_readers[0].display_name == "PIM-Demo-Readers" &&
      azuread_group.demo_readers[0].mail_nickname == "pim-demo-readers" &&
      azuread_group.demo_readers[0].assignable_to_role &&
      azuread_group.demo_readers[0].security_enabled &&
      !azuread_group.demo_readers[0].mail_enabled
    )
    error_message = "PIM-Demo-Readers: role-assignable security group (only Privileged Role / Privileged Authentication Administrators can touch who is in it or their credentials), no mailbox."
  }
  assert {
    condition = (
      length(azuread_directory_role_assignment.demo_readers) == 2 &&
      azuread_directory_role_assignment.demo_readers["global_reader"].role_id == "f2ef992c-3afb-46b9-b7cf-a126ee74c451" &&
      azuread_directory_role_assignment.demo_readers["security_reader"].role_id == "5d6b6bb7-de71-4623-b4af-96380a352509" &&
      alltrue([for a in values(azuread_directory_role_assignment.demo_readers) : a.directory_scope_id == "/" && a.principal_object_id == azuread_group.demo_readers[0].object_id])
    )
    error_message = "The group must ACTIVELY hold exactly Global Reader + Security Reader, tenant-wide - nothing that can write."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.demo_readers_member[0].group_id == azuread_group.demo_readers[0].object_id &&
      azuread_group_role_management_policy.demo_readers_member[0].role_id == "member" &&
      azuread_group_role_management_policy.demo_readers_member[0].activation_rules[0].maximum_duration == "PT8H" &&
      azuread_group_role_management_policy.demo_readers_member[0].activation_rules[0].require_multifactor_authentication &&
      azuread_group_role_management_policy.demo_readers_member[0].activation_rules[0].require_justification
    )
    error_message = "Activation of MEMBERSHIP: at most 8 hours (PT8H), MFA, justification."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.demo_readers_member[0].activation_rules[0].require_approval == false &&
      length(azuread_group_role_management_policy.demo_readers_member[0].activation_rules[0].approval_stage) == 0 &&
      !contains(keys(azuread_group.pim_approvers), "tier0")
    )
    error_message = "No approval: the presenter activates alone (no approval stage, and no Tier-0 approver group is created for it)."
  }
  assert {
    condition = (
      azuread_group_role_management_policy.demo_readers_member[0].eligible_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.demo_readers_member[0].eligible_assignment_rules[0].expire_after == "P365D" &&
      azuread_group_role_management_policy.demo_readers_member[0].active_assignment_rules[0].expiration_required &&
      azuread_group_role_management_policy.demo_readers_member[0].active_assignment_rules[0].expire_after == "P15D" &&
      azuread_group_role_management_policy.demo_readers_member[0].active_assignment_rules[0].require_justification &&
      azuread_group_role_management_policy.demo_readers_member[0].active_assignment_rules[0].require_multifactor_authentication
    )
    error_message = "Eligibility expires at the Tier-1 duration (P365D, what Set-PimGroupEligibility.ps1 requests); a direct ACTIVE member expires too and needs justification + MFA."
  }
  assert {
    condition = (
      length(azuread_group_role_management_policy.demo_readers_member[0].notification_rules[0].eligible_activations) == 1 &&
      contains(azuread_group_role_management_policy.demo_readers_member[0].notification_rules[0].eligible_activations[0].admin_notifications[0].additional_recipients, "security@contosohealthlab.onmicrosoft.com") &&
      contains(azuread_group_role_management_policy.demo_readers_member[0].notification_rules[0].eligible_assignments[0].admin_notifications[0].additional_recipients, "security@contosohealthlab.onmicrosoft.com") &&
      contains(azuread_group_role_management_policy.demo_readers_member[0].notification_rules[0].active_assignments[0].admin_notifications[0].additional_recipients, "security@contosohealthlab.onmicrosoft.com")
    )
    error_message = "With approval off, EVERY activation (and every eligibility / direct active change) is mailed to the security mailbox."
  }
  assert {
    condition     = keys(output.privileged_review_targets) == ["Privileged-IAM-Admins"]
    error_message = "PIM-Demo-Readers must stay out of privileged_review_targets: that output is the CA002 / CA020 group scope, changed only on purpose."
  }
  assert {
    condition = (
      !contains(output.privileged_role_template_ids["tier0"], "f2ef992c-3afb-46b9-b7cf-a126ee74c451") &&
      !contains(output.privileged_role_template_ids["tier1"], "f2ef992c-3afb-46b9-b7cf-a126ee74c451") &&
      !contains(output.privileged_role_template_ids["tier0"], "5d6b6bb7-de71-4623-b4af-96380a352509") &&
      !contains(output.privileged_role_template_ids["tier1"], "5d6b6bb7-de71-4623-b4af-96380a352509")
    )
    error_message = "The reader roles must stay out of privileged_role_template_ids (envs/dev builds CA020's role list from it)."
  }
  assert {
    condition     = jsondecode(output.pim_eligible_review_bodies["privileged:PIM-Demo-Readers"]).scope.query == "/groups/${azuread_group.demo_readers[0].object_id}/transitiveMembers"
    error_message = "PIM-Demo-Readers must be in the quarterly privileged review (eligible + active members)."
  }
  assert {
    condition = (
      output.demo_readers_group_mail_nickname == "pim-demo-readers" &&
      output.demo_readers_group_object_id == azuread_group.demo_readers[0].object_id &&
      output.demo_readers_activation_policy.maximum_duration == "PT8H" &&
      output.demo_readers_activation_policy.approval == false &&
      output.demo_readers_activation_policy.in_ca_admin_scope == false &&
      output.demo_readers_activation_policy.activation_mail
    )
    error_message = "Outputs: the object id for envs/bootstrap, the mail nickname for Set-PimGroupEligibility.ps1 and the evidence summary."
  }
}

# With the tier map on as well: still 16 tier groups and the same CA scope.
run "demo_readers_leave_the_tier_map_alone" {
  command = apply

  variables {
    enable_pim_tiers          = true
    enable_pim_demo_readers   = true
    tier0_approver_object_ids = ["cccccccc-cccc-cccc-cccc-cccccccccccc", "dddddddd-dddd-dddd-dddd-dddddddddddd"]
    pim_alert_mailbox         = "security@contosohealthlab.onmicrosoft.com"
  }

  assert {
    condition     = length(azuread_group.pim_tier) == 16 && length(output.tier_group_mail_nicknames) == 16 && !contains(keys(output.tier_group_mail_nicknames), "PIM-Demo-Readers")
    error_message = "PIM-Demo-Readers is not a tier group: the tier map stays 8 Tier-0 + 8 Tier-1."
  }
  assert {
    condition     = length(output.privileged_review_targets) == 17 && !contains(keys(output.privileged_review_targets), "PIM-Demo-Readers")
    error_message = "The CA002 / CA020 group scope stays Privileged-IAM-Admins + the 16 tier groups."
  }
  assert {
    condition     = length(output.pim_eligible_review_bodies) == 18 && contains(keys(output.pim_eligible_review_bodies), "privileged:PIM-Demo-Readers")
    error_message = "One quarterly review per PIM-governed group: IAM + 16 tiers + PIM-Demo-Readers."
  }
}

run "demo_readers_without_mailbox_warns" {
  command = plan

  variables {
    enable_pim_demo_readers = true
  }

  expect_failures = [check.demo_readers_activations_are_seen]
}

run "demo_readers_activation_capped_at_8h" {
  command = plan

  variables {
    enable_pim_demo_readers              = true
    demo_readers_activation_max_duration = "PT9H"
    pim_alert_mailbox                    = "security@contosohealthlab.onmicrosoft.com"
  }

  expect_failures = [var.demo_readers_activation_max_duration]
}

run "demo_readers_never_longer_than_the_tier1_cap" {
  command = plan

  variables {
    enable_pim_demo_readers       = true
    tier1_activation_max_duration = "PT4H"
    pim_alert_mailbox             = "security@contosohealthlab.onmicrosoft.com"
  }

  expect_failures = [azuread_group_role_management_policy.demo_readers_member]
}
