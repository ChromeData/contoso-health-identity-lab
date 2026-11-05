# =============================================================================
# modules/pim :: outputs.tf
# =============================================================================

locals {
  # Every group whose membership grants admin rights, keyed by display name
  # (keys known at plan: they come from variables).
  privileged_review_targets = merge(
    { "Privileged-IAM-Admins" = var.priv_iam_admins_group_object_id },
    { for k, g in azuread_group.pim_tier : var.pim_tier_groups[k].display_name => g.object_id },
    { for g in azuread_group.azure_pim : var.azure_pim_group_name => g.object_id },
  )
}

output "role_assignment_id" {
  description = "Id of the active role assignment binding Privileged-IAM-Admins to the target role."
  value       = azuread_directory_role_assignment.priv_admins.id
}

output "group_role_management_policy_id" {
  description = "Id of the PIM-for-Groups member activation policy."
  value       = azuread_group_role_management_policy.member.id
}

# ---- Approver groups (approvers.tf) ------------------------------------------

output "approver_group_object_ids" {
  description = "PIM approver groups by tier (tier0 / tier1 => object id; a tier is absent when nothing routes approvals to it). Members are approver_object_ids / tier0_approver_object_ids."
  value       = { for t, g in azuread_group.pim_approvers : t => g.object_id }
}

output "approver_group_mail_nicknames" {
  description = "PIM approver groups by tier => mail_nickname (Set-PimGroupEligibility.ps1 / Set-DirectoryRolePimPolicies.ps1 warn when an eligible person is also an approver)."
  value       = { for t, g in local.approver_groups : t => g.mail_nickname }
}

# ---- PIM tier groups (tiers.tf) ---------------------------------------------

output "tier_group_object_ids" {
  description = "Map of tier group display name => object id ({} while enable_pim_tiers = false). Run post-apply/Set-PimGroupEligibility.ps1 per group."
  value       = { for k, g in azuread_group.pim_tier : var.pim_tier_groups[k].display_name => g.object_id }
}

output "tier_group_mail_nicknames" {
  description = "Map of tier group display name => mail_nickname (the -GroupMailNickname for Set-PimGroupEligibility.ps1)."
  value       = { for k, g in local.tier_groups : g.display_name => g.mail_nickname }
}

output "tier_activation_policies" {
  description = "Effective PIM rules per tier group, for the evidence pack and the on-camera tier walkthrough ({} when disabled)."
  value = {
    for k, g in local.tier_groups : g.display_name => {
      tier                  = g.tier
      role                  = g.role_name
      role_template_ids     = local.tier_group_settings[k].role_template_ids
      scope                 = local.tier_group_settings[k].au_scoped ? var.workforce_au_display_name : "tenant"
      max_duration          = local.tier_group_settings[k].maximum_duration
      require_approval      = local.tier_group_settings[k].require_approval
      approver_group        = local.tier_group_settings[k].require_approval ? local.approver_groups[local.tier_group_settings[k].approver_tier].display_name : null
      auth                  = local.tier_group_settings[k].auth_context != "" ? "auth context ${local.tier_group_settings[k].auth_context}" : (g.tier == 0 && var.tier0_auth_context_switchover_step1 ? "NONE (switch-over apply 1)" : "MFA")
      ticket_required       = local.tier_group_settings[k].require_ticket_info
      eligible_expire_after = local.tier_group_settings[k].eligible_expire_after
      active_expire_after   = var.active_assignment_max_duration
      notifications         = !local.pim_notifications_enabled ? "tenant default" : (local.tier_group_settings[k].notify_activations ? "activation + eligible + active" : "eligible + active")
      policy_id             = azuread_group_role_management_policy.pim_tier_member[k].id
    }
  }
}

output "privileged_role_template_ids" {
  description = <<-EOT
    Directory role template ids governed by this module, by tier (tier0
    includes Global Administrator; tier1 includes Privileged-IAM-Admins' role).
    Built from the variables, so it is known at plan even with tiers off:
    feed modules/conditional-access admin_session_role_template_ids (CA020)
    so CA020's role list and the PIM tier map cannot drift apart. NOT CA002:
    CA002 keeps its own admin_role_template_ids, whose validation requires
    Microsoft's template list (incl. Billing / Password Administrator, which
    no tier group holds).
  EOT
  value = {
    tier0 = distinct(concat(["62e90394-69f5-4237-9190-012177145e10"], flatten([for g in values(var.pim_tier_groups) : concat([g.role_template_id], g.additional_role_template_ids) if g.tier == 0])))
    tier1 = distinct(concat([var.role_template_id], flatten([for g in values(var.pim_tier_groups) : concat([g.role_template_id], g.additional_role_template_ids) if g.tier == 1])))
  }
}

# ---- Help-desk scoping (helpdesk.tf) ------------------------------------------

output "workforce_au_object_id" {
  description = "Object id of AU-Workforce-Standard (the service desk's role scope), or null."
  value       = one(azuread_administrative_unit.workforce_standard[*].object_id)
}

output "workforce_au_membership_body" {
  description = "TENANT-TIME Graph body that turns AU-Workforce-Standard into a dynamic AU: PATCH https://graph.microsoft.com/v1.0/directory/administrativeUnits/<workforce_au_object_id> (AdministrativeUnit.ReadWrite.All). null when the AU is off."
  value = local.workforce_au_enabled ? jsonencode({
    membershipType                = "Dynamic"
    membershipRule                = local.workforce_au_membership_rule
    membershipRuleProcessingState = "On"
  }) : null
}

# ---- Global Administrator policy (directory-roles.tf) -------------------------

output "directory_role_pim_policies" {
  description = "Role template id => JSON (rule bodies + eligibility duration) for post-apply/Set-DirectoryRolePimPolicies.ps1 -PolicyPath. {} unless enable_global_admin_pim_policy. Sensitive: the notification rules carry pim_alert_mailbox (terraform output -json still prints it for the script)."
  value       = local.directory_role_pim_policies
  sensitive   = true

  precondition {
    condition     = !var.enable_global_admin_pim_policy || length(local.tier0_approver_member_ids) > 0
    error_message = "enable_global_admin_pim_policy needs Tier-0 approvers (tier0_approver_object_ids or approver_object_ids): Global Administrator activation always requires approval."
  }
  precondition {
    condition     = local.duration_minutes[var.global_admin_activation_max_duration] <= local.duration_minutes[var.tier0_activation_max_duration]
    error_message = "global_admin_activation_max_duration may not exceed tier0_activation_max_duration."
  }
  precondition {
    condition     = !var.enable_global_admin_pim_policy || (var.tier0_activation_auth_context_id == "" && !var.tier0_auth_context_switchover_step1) || var.activation_auth_context_ca_enforced
    error_message = "Global Administrator would require the auth context before CA021 is enforced: set activation_auth_context_ca_enforced only from modules/conditional-access output pim_activation_auth_context_ready."
  }
}

# ---- PIM for Azure resources (azure.tf) --------------------------------------

output "azure_pim_group_object_id" {
  description = "Group eligible for the Azure role on the lab RG (add members post-apply), or null."
  value       = one(azuread_group.azure_pim[*].object_id)
}

output "azure_pim_eligible_assignment_id" {
  description = "Terraform id ({scope}|{roleDefinitionId}|{principalId}) of the Azure PIM eligible assignment, or null."
  value       = one(azurerm_pim_eligible_role_assignment.azure_pim[*].id)
}

output "azure_role_management_policy_id" {
  description = "Id of the Azure PIM activation policy for the role at the RG scope, or null."
  value       = one(azurerm_role_management_policy.azure_pim[*].id)
}

# ---- Input for modules/entitlement and modules/conditional-access -------------

# Wire straight into modules/entitlement var.privileged_review_group_object_ids
# and modules/conditional-access var.admin_scope_group_object_ids (CA002 /
# CA020 by GROUP: AU-scoped help-desk roles are invisible to CA's role
# condition, and group-held roles may be too - verify:).
output "privileged_review_targets" {
  description = "Display name => object id of every PIM-governed group (Privileged-IAM-Admins, tier groups, Azure PIM group): the privileged access review, and CA002/CA020 included_groups."
  value       = local.privileged_review_targets
}

output "pim_eligible_review_bodies" {
  description = <<-EOT
    "privileged:<name>" => Graph v1.0 accessReviewScheduleDefinition JSON for
    every PIM-governed group (eligible + active members) and, with
    enable_global_admin_pim_policy, ELIGIBLE Global Administrator users
    (break-glass excluded by design). Same shape/keys as modules/entitlement
    access_review_definitions: post-apply/New-AccessReviewDefinitions.ps1
    POSTs them (matched by displayName, so a group rendered by both modules
    yields one series). {} while privileged_review_fallback_group_object_id
    is empty. verify: API-created PIM-group reviews include eligible members.
  EOT
  value       = local.pim_eligible_review_bodies

  precondition {
    # Nobody certifies their own group (the reviewer group must not be one of
    # the groups under review).
    condition     = !local.review_enabled || (!contains(values(local.review_targets), local.review_reviewer_group_object_id) && !contains(values(local.review_targets), var.privileged_review_fallback_group_object_id))
    error_message = "The privileged review reviewer or fallback group is itself a PIM-governed group: reviewers would certify their own ability to activate."
  }
}

# ---- AWS administration through PIM for Groups (aws.tf) -----------------------

output "aws_admin_group_object_id" {
  description = "Object id of PIM-AWS-Lab-Admins (null unless enable_pim_aws_admin). envs/dev assigns it to the AWS IAM Identity Center app; lab/terraform/aws can pin the SCIM copy to it (lab_admin_entra_group_object_id)."
  value       = one(azuread_group.aws_admin[*].object_id)
}

output "aws_admin_group_mail_nickname" {
  description = "mail_nickname of PIM-AWS-Lab-Admins for Set-PimGroupEligibility.ps1 -GroupMailNickname (null unless enable_pim_aws_admin)."
  value       = local.aws_admin_enabled ? var.aws_admin_group_mail_nickname : null
}

output "aws_admin_activation_policy" {
  description = "Evidence summary of the PIM-AWS-Lab-Admins activation policy (null unless enable_pim_aws_admin)."
  value = local.aws_admin_enabled ? {
    group               = var.aws_admin_group_name
    maximum_duration    = var.aws_admin_activation_max_duration
    mfa                 = true
    justification       = true
    approval            = var.aws_admin_require_approval
    eligible_expire     = var.aws_admin_eligible_assignment_duration
    activation_mail     = local.pim_notifications_enabled
    in_ca_admin_scope   = false
    in_quarterly_review = local.review_enabled
  } : null
}
