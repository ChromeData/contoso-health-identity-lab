# =============================================================================
# aws :: main.tf
# -----------------------------------------------------------------------------
# WHAT: the AWS half of "Entra decides who, AWS decides what". After SAML + SCIM
# are wired by hand (lab/terraform/aws/README.md, Order of operations step 2),
# this root codifies the part that used to be pure console clicks (the
# permission set and its assignment):
#
#   * one permission set, ViewOnlyAccess, 4-hour sessions
#   * the AWS managed job-function policy ViewOnlyAccess attached to it
#   * one account assignment: the SCIM-provisioned Entra group
#     App-AWS-IdentityCenter-Users -> ViewOnlyAccess -> the target account
#
# NO STAND-IN: this is the real AWS IAM Identity Center (listed under "Real
# products" in lab/docs/STAND-INS.md).
#
# THE IDENTITY CHAIN this completes (joiner/mover/leaver end to end):
#
#   HR feed -> AD -> Cloud Sync -> Entra user (Dana)
#     -> access package "Nurse - Clinical Apps" (modules/entitlement)
#     -> Entra group App-AWS-IdentityCenter-Users (modules/groups)
#     -> SCIM (Entra provisioning service, ~40-min cycle or on demand)
#     -> Identity Store group with the same DisplayName      <- READ here
#     -> account assignment + permission set                  <- OWNED here
#     -> IAM role AWSReservedSSO_ViewOnlyAccess_<suffix> in the target account
#
# OWNERSHIP BOUNDARY (the important design decision):
#   Terraform READS the group (data source) and never creates one. Creating an
#   aws_identitystore_group here would mint an AWS-local group outside the
#   Entra lifecycle: the leaver flow (04-Leaver.ps1 -> SCIM deprovision) could
#   never remove anyone from it. Entra owns WHO; this root owns WHAT they get.
#   Group MEMBERSHIP is never touched here either - SCIM owns it.
#
# ORDER: the group must already exist in the Identity Store. If SCIM has not
# provisioned it yet, the plan fails at the group lookup (provider error
# "reading IdentityStore Group (d-...)" wrapping the GetGroupId
# ResourceNotFoundException) - that is the intended, safe failure: wait for
# SCIM (or run Provision on demand in Entra) and plan again.
#
# LICENSING / COST: IAM Identity Center and AWS managed policies carry no
# additional AWS charge, and nothing here starts a trial clock - so the grant
# below has no enable_* flag: the whole root is opt-in by being a separate,
# human-applied root. The one exception is github-oidc.tf (a CI trust into
# this account), staged behind enable_github_oidc = false because a new trust
# relationship should be a deliberate, reviewed switch.
#
# PREREQUISITE: account assignments (permission sets on AWS accounts) need an
# ORGANIZATION instance of Identity Center (enabled in the AWS Organizations
# management account). An account instance only does application assignments.
#
# TARGET ACCOUNT = MANAGEMENT ACCOUNT BY DEFAULT (read this): the default
# target is the account the profile signs into. With an organization instance
# that is the Organizations MANAGEMENT account (the lab has no other account).
# Two consequences, both from the AWS IAM Identity Center User Guide:
#   1. Assigning access to the management account is a privileged action: the
#      applying profile needs AWSSSOMasterAccountAdministrator AND IAMFullAccess
#      (or AdministratorAccess). The guide states this for the console;
#      verify: that the API path (this root) enforces the same.
#   2. AWS recommends assigning USERS, not groups, to permission sets in the
#      management account, because whoever controls group membership (here:
#      Entra admins and the access-package approvers) then controls
#      management-account access. The lab accepts that deliberately: one
#      account, a view-only policy, and the group is exactly what the joiner /
#      leaver chain is meant to demonstrate. In production, set
#      var.target_account_id to a MEMBER account and keep the management
#      account on direct user assignments.
# =============================================================================

# Who am I? Default target account = the account the profile signs into.
data "aws_caller_identity" "current" {}

# aws / aws-us-gov / aws-cn, derived from the provider region (no API call).
# AWS managed policy ARNs carry the partition, so the policy ARN below is
# built from it rather than hardcoding "arn:aws:".
data "aws_partition" "current" {}

# -----------------------------------------------------------------------------
# The Identity Center instance in var.aws_region. Exactly one per account per
# region; an empty result almost always means the wrong region.
# -----------------------------------------------------------------------------
data "aws_ssoadmin_instances" "this" {
  lifecycle {
    postcondition {
      condition     = length(self.arns) > 0 && length(self.identity_store_ids) > 0
      error_message = "No IAM Identity Center instance found in this region/account. Set aws_region to the region shown under Identity Center -> Settings, and use a profile in the account that holds the instance (the Organizations management account or the delegated administrator)."
    }
  }
}

locals {
  # One element each in practice (one instance per account + region). The docs
  # call them sets, the 6.x schema returns lists; tolist()[0] is the
  # provider-documented accessor and works for either. The postcondition above
  # guarantees index 0 exists.
  instance_arn      = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]

  target_account_id = var.target_account_id != "" ? var.target_account_id : data.aws_caller_identity.current.account_id

  # AWS managed job-function policy. Verified 2026-10-19 against the AWS
  # Managed Policy Reference (Type: Job function policy); in the commercial
  # partition this is arn:aws:iam::aws:policy/job-function/ViewOnlyAccess.
  view_only_policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/job-function/ViewOnlyAccess"
}

# -----------------------------------------------------------------------------
# The Entra group, as SCIM created it in the Identity Store. Looked up by
# DisplayName (a unique attribute for Identity Store groups).
# -----------------------------------------------------------------------------
data "aws_identitystore_group" "aws_users" {
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = var.group_display_name
    }
  }

  lifecycle {
    # Optional lineage pin (var.entra_group_object_id). Off by default.
    postcondition {
      condition = (
        var.entra_group_object_id == ""
        || contains([for e in self.external_ids : lower(e.id)], lower(var.entra_group_object_id))
      )
      error_message = "The Identity Store group named by group_display_name does not carry entra_group_object_id as an external id. It was not provisioned by SCIM from the expected Entra group - do not grant it AWS access. Check the Entra provisioning logs, or clear entra_group_object_id if your connector does not map objectId -> externalId."
    }
  }
}

# Soft signal (warning only, never blocks): a group that SCIM created from
# Entra should carry an external id. An empty list suggests it was made by hand
# in the Identity Center console - which breaks the leaver chain.
# verify: confirm on first apply that SCIM-provisioned groups show ExternalIds
# (`aws identitystore describe-group`); if they never do, delete this check.
check "group_is_scim_provisioned" {
  assert {
    condition     = length(data.aws_identitystore_group.aws_users.external_ids) > 0
    error_message = "Identity Store group '${var.group_display_name}' has no external id - it may have been created by hand instead of by SCIM from Entra. Leaver deprovisioning only works for SCIM-owned groups."
  }
}

# -----------------------------------------------------------------------------
# Permission set: ViewOnlyAccess, 4-hour sessions.
# Changing it later re-provisions the permission set to every assigned account
# automatically (provider behavior).
# -----------------------------------------------------------------------------
resource "aws_ssoadmin_permission_set" "view_only" {
  name             = "ViewOnlyAccess"
  description      = "Contoso Health lab: read-only console view of resources and metadata. Granted to App-AWS-IdentityCenter-Users (SCIM from Entra). Managed by Terraform - lab/terraform/aws."
  instance_arn     = local.instance_arn
  session_duration = var.session_duration
}

# -----------------------------------------------------------------------------
# Account assignment: group -> permission set -> account.
# Creating it provisions the permission set into the target account as the
# IAM role AWSReservedSSO_ViewOnlyAccess_<suffix>.
# -----------------------------------------------------------------------------
resource "aws_ssoadmin_account_assignment" "view_only_users" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.view_only.arn

  principal_id   = data.aws_identitystore_group.aws_users.group_id
  principal_type = "GROUP"

  target_id   = local.target_account_id
  target_type = "AWS_ACCOUNT"
}

# -----------------------------------------------------------------------------
# AWS managed policy on the permission set.
#
# depends_on the assignment, as the provider docs require: destroying an
# attachment re-provisions the permission set to every account, so the
# attachment must be removed BEFORE the assignment on destroy. On create this
# means the assignment lands first with an empty permission set (no access -
# fails closed) and the attachment then re-provisions it with ViewOnlyAccess.
# -----------------------------------------------------------------------------
resource "aws_ssoadmin_managed_policy_attachment" "view_only" {
  depends_on = [aws_ssoadmin_account_assignment.view_only_users]

  instance_arn       = local.instance_arn
  managed_policy_arn = local.view_only_policy_arn
  permission_set_arn = aws_ssoadmin_permission_set.view_only.arn
}
