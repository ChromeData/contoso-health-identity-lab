# =============================================================================
# modules/pim :: approvers.tf
# -----------------------------------------------------------------------------
# APPROVER GROUPS - one per tier, created here, routed as "groupMembers".
#
#   PIM-Approvers-Tier0  approves every Tier-0 activation: the tier = 0
#                        groups, Contributor on the lab RG (azure.tf) and
#                        Global Administrator (directory-roles.tf, applied by
#                        post-apply/Set-DirectoryRolePimPolicies.ps1)
#   PIM-Approvers-Tier1  approves Privileged-IAM-Admins (main.tf) and every
#                        tier = 1 group with require_approval (Intune)
#
# WHY A GROUP, NOT singleUser: the approver list is a control, not a person.
# Leavers, holidays and a second approver change the group's membership in a
# reviewed PR, not three policies. Microsoft Learn (PIM approval):
# approvers can't approve their own activation, requests expire after 24
# hours (fixed), and two or more approvers are recommended - a check below
# warns on fewer than two.
#
# WHY ROLE-ASSIGNABLE (both tiers): membership of a role-assignable group can
# only be changed by Privileged Role Administrator / Global Administrator
# (and its owners). As an ordinary security group, PIM-Approvers-Tier1 could
# be edited by a Groups Administrator or a User Administrator - the very
# roles it approves - who could then add a colluder as approver. Both
# groups are therefore role-assignable although neither holds a role.
#
# MEMBERS ARE CODE (unlike the tier groups, whose membership PIM owns):
# approver_object_ids / tier0_approver_object_ids - the existing tenant
# identifiers (terraform.tfvars, TF_PIM_*_APPROVER_OBJECT_IDS in CI) - are
# now the members of these groups, so envs/dev wiring is unchanged. A portal
# change shows up as drift on the next plan.
#
# NOT ENFORCEABLE HERE: approvers disjoint from the eligible people (who is
# eligible is set post-apply). Set-PimGroupEligibility.ps1 warns when a
# person it makes eligible is in the same tier's approver group, and the
# privileged access review's self-review guard flags reviewers who are
# eligible.
# =============================================================================

locals {
  tier0_approver_member_ids = length(var.tier0_approver_object_ids) > 0 ? var.tier0_approver_object_ids : var.approver_object_ids
  tier1_approver_member_ids = var.approver_object_ids

  # Create a tier's group only when something routes approvals to it.
  approver_group_needed = {
    tier0 = (
      length([for k, s in local.tier_group_settings : k if s.tier == 0]) > 0 ||
      (var.enable_pim_azure_resources && var.azure_pim_require_approval) ||
      (var.enable_pim_aws_admin && var.aws_admin_require_approval) ||
      var.enable_global_admin_pim_policy
    )
    tier1 = (
      var.require_approval ||
      length([for k, s in local.tier_group_settings : k if s.tier == 1 && s.require_approval]) > 0
    )
  }

  approver_groups = {
    for t, needed in local.approver_group_needed : t => {
      display_name  = t == "tier0" ? "PIM-Approvers-Tier0" : "PIM-Approvers-Tier1"
      mail_nickname = t == "tier0" ? "pim-approvers-tier0" : "pim-approvers-tier1"
      members       = t == "tier0" ? local.tier0_approver_member_ids : local.tier1_approver_member_ids
      approves      = t == "tier0" ? "Tier-0 PIM activations (tier-0 groups, Azure RG Contributor, Global Administrator)" : "Tier-1 PIM activations that require approval (Privileged-IAM-Admins, Intune)"
    } if needed
  }
}

resource "azuread_group" "pim_approvers" {
  for_each = local.approver_groups

  display_name       = each.value.display_name
  mail_nickname      = each.value.mail_nickname
  description        = "PIM approvers: ${each.value.approves}. Membership is Terraform-managed (reviewed PR); approvers never approve their own request."
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true
  members            = each.value.members
}

check "approver_groups_have_two_members" {
  assert {
    condition     = alltrue([for t, g in local.approver_groups : length(g.members) >= 2])
    error_message = "A PIM approver group has fewer than two members (${join(", ", [for t, g in local.approver_groups : "${g.display_name}=${length(g.members)}" if length(g.members) < 2])}). Microsoft recommends two or more approvers: one approver who is also eligible cannot approve their own request, and a single absence stalls every activation."
  }
}
