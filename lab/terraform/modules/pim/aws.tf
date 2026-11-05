# =============================================================================
# modules/pim :: aws.tf
# -----------------------------------------------------------------------------
# AWS ADMINISTRATION, JUST-IN-TIME THROUGH ENTRA (var.enable_pim_aws_admin,
# default false). ADR 0025.
#
#   PIM-AWS-Lab-Admins --(assigned to the AWS IAM Identity Center app;
#            ^            SCIM copies its ACTIVE members to AWS)-->
#            |          Identity Store group --(lab/terraform/aws)-->
#            |          permission set LabAdministrator (AdministratorAccess,
#            |          1-hour sessions) in the lab account
#            |
#            |  membership is ELIGIBLE-ONLY, activated just-in-time through
#            |  PIM for Groups: MFA + justification, 2-hour cap, every
#            |  activation mailed to the security mailbox
#          the lab-operations admin account (adm-labops, ADR 0025)
#
# WHY A PIM GROUP AND NOT A STANDING AWS ADMIN: before this, the only way to
# change IAM in the lab AWS account was the root user. Root cannot be scoped,
# time-boxed or switched off from Entra. Here AWS admin is the same thing as
# every other admin power in the lab: an eligible membership that someone
# activates for a stated reason, for a short time, in a log.
#
# ONE ACTIVATION PER ELEVATION, as in main.tf: the group never holds an Entra
# role; its MEMBERSHIP is the just-in-time step. Two things follow from it,
# both checked by Entra and AWS rather than by a script:
#   1. Sign-in. The AWS app requires assignment and the group is its admin
#      principal, so an eligible-but-inactive member cannot even reach the
#      AWS access portal (Entra refuses the SAML sign-in).
#   2. Provisioning. Activating membership TRIGGERS provisioning of the
#      membership (and of the user, if not yet provisioned) to the app over
#      SCIM, "in 2 - 10 minutes" for the first five activations per app per
#      10 seconds; plain group changes wait for the 40-minute cycle (Learn,
#      "PIM for Groups - Privileged Identity Management and app
#      provisioning", checked 2026-11-05). That page recommends exactly this
#      shape: an always-active "all users" group with a low role (here
#      App-AWS-IdentityCenter-Users, ViewOnlyAccess) and an ELIGIBLE
#      "privileged group" with the privileged role (this group).
#      verify: Learn documents the fast path for activation only; removal at
#      expiry is assumed to wait for the next cycle. An AWS session already
#      issued lasts up to the permission set's session length (1 hour,
#      lab/terraform/aws). So AWS admin can outlive an activation by up to
#      one cycle plus one session: ADR 0025 records that as residual risk.
#
# WHY ROLE-ASSIGNABLE: the group holds no Entra role, but its membership is
# admin of the AWS Organizations management account. Learn (same page,
# "What are Microsoft Entra role-assignable groups?") recommends
# role-assignable for any group that "provides access to sensitive
# resources": only Global Administrators, Privileged Role Administrators and
# the group's owners can manage it, and nobody else can change the
# credentials of its members - "including eligible members ... who haven't
# activated yet". That second point matters here because activation needs
# no approval (below): a Helpdesk or User Administrator cannot reset the
# admin account's credentials and activate on its behalf. It also answers
# AWS's own warning about group assignments in the management account
# ("whoever controls the group controls the account", lab/terraform/aws
# README): control of this group is Tier 0 in Entra.
#
# WHY NO APPROVAL BY DEFAULT (aws_admin_require_approval = false): the lab
# has one human admin, and PIM never lets a requester approve their own
# request. Approval would mean the AWS admin path needs a second person who
# does not exist. Compensating controls instead: the 2-hour cap, MFA and a
# written reason on every activation, a mail to the security mailbox on every
# activation and every eligibility change, and 1-hour AWS sessions. Turn
# approval on (PIM-Approvers-Tier0) as soon as a second admin exists - the
# revisit trigger in ADR 0025.
#
# WHY NOT IN privileged_review_targets: that output is also the CA002 / CA020
# group scope (envs/dev -> modules/conditional-access). Conditional Access
# changes are made separately and on purpose, so this group joins only the
# quarterly eligibility REVIEW here (reviews.tf), not the CA scope.
#
# WHO IS ELIGIBLE is operational data, as everywhere in this module: the
# post-apply step in ADR 0025 (Set-PimGroupEligibility.ps1
# -GroupMailNickname pim-aws-lab-admins -EligibilityDuration P180D).
#
# LICENSING: role-assignable groups need Entra ID P1; PIM for Groups needs
# Entra ID P2 for the eligible member (M365 E5 trial).
# =============================================================================

locals {
  aws_admin_enabled = var.enable_pim_aws_admin

  # Display name => object id; joins the quarterly privileged review
  # (reviews.tf) but not the CA scope (see the header).
  aws_admin_review_target = { for g in azuread_group.aws_admin : var.aws_admin_group_name => g.object_id }
}

resource "azuread_group" "aws_admin" {
  count = local.aws_admin_enabled ? 1 : 0

  display_name       = var.aws_admin_group_name
  mail_nickname      = var.aws_admin_group_mail_nickname
  description        = "PIM for Groups: eligible-only membership = administrator of the lab AWS account (IAM Identity Center permission set LabAdministrator, via SCIM). No standing members. ADR 0025."
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  # Membership is owned by PIM (eligibility schedules + activations).
  lifecycle {
    ignore_changes = [members]
  }
}

resource "azuread_group_role_management_policy" "aws_admin_member" {
  count = local.aws_admin_enabled ? 1 : 0

  group_id = azuread_group.aws_admin[0].object_id
  role_id  = "member"

  activation_rules {
    maximum_duration                   = var.aws_admin_activation_max_duration
    require_multifactor_authentication = true
    require_justification              = true
    require_approval                   = var.aws_admin_require_approval

    dynamic "approval_stage" {
      for_each = var.aws_admin_require_approval ? [1] : []
      content {
        primary_approver {
          object_id = azuread_group.pim_approvers["tier0"].object_id
          type      = "groupMembers"
        }
      }
    }
  }

  # Eligibility EXPIRES (default 180 days, the Tier-0 cap): admin of the AWS
  # management account is Tier 0 for AWS.
  eligible_assignment_rules {
    expiration_required = true
    expire_after        = var.aws_admin_eligible_assignment_duration
  }

  # Nobody parks a permanent ACTIVE member here: a direct active assignment
  # expires, and the admin making it justifies it and passes MFA.
  active_assignment_rules {
    expiration_required                = true
    expire_after                       = var.active_assignment_max_duration
    require_justification              = true
    require_multifactor_authentication = true
  }

  # Every activation is mailed, not only approval-gated ones: with approval
  # off, the mail is how a second person learns that AWS admin was used.
  dynamic "notification_rules" {
    for_each = local.pim_notifications_enabled ? [1] : []
    content {
      eligible_activations {
        admin_notifications {
          notification_level    = "All"
          default_recipients    = true
          additional_recipients = [var.pim_alert_mailbox]
        }
      }
      eligible_assignments {
        admin_notifications {
          notification_level    = "All"
          default_recipients    = true
          additional_recipients = [var.pim_alert_mailbox]
        }
      }
      active_assignments {
        admin_notifications {
          notification_level    = "All"
          default_recipients    = true
          additional_recipients = [var.pim_alert_mailbox]
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !var.aws_admin_require_approval || length(local.tier0_approver_member_ids) > 0
      error_message = "aws_admin_require_approval = true needs approvers in PIM-Approvers-Tier0: tier0_approver_object_ids (or approver_object_ids)."
    }
  }
}

# With approval off, the activation mail is the second pair of eyes. Say so
# when there is no mailbox to send it to.
check "aws_admin_activations_are_seen" {
  assert {
    condition     = !local.aws_admin_enabled || var.aws_admin_require_approval || local.pim_notifications_enabled
    error_message = "PIM-AWS-Lab-Admins activates without approval and pim_alert_mailbox is empty: nobody but the activating account learns that AWS admin was used. Set pim_alert_mailbox (or aws_admin_require_approval)."
  }
}
