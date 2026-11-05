# =============================================================================
# modules/pim :: main.tf
# -----------------------------------------------------------------------------
# PATTERN: "PIM for Groups as the elevation path" - ONE activation, not two.
#
#   Privileged-IAM-Admins --(ACTIVE, permanent)--> User Administrator role
#            ^
#            |  membership is ELIGIBLE-ONLY (expires after 365 days unless
#            |  renewed), activated just-in-time through PIM for Groups:
#            |  MFA + justification + approval (PIM-Approvers-Tier1) + 4h cap
#          an IT/IAM engineer's admin account
#
# Why not "group ELIGIBLE for the role" as well? Then a member would have to
# activate twice (group membership, then the role). Binding the role actively
# to an EMPTY group and making the MEMBERSHIP the just-in-time control gives a
# single, provider-managed activation policy (azuread_group_role_management_policy
# fully supports MFA / justification / approval / max duration - the directory-
# role activation policy is NOT expressible in the azuread provider).
#
# Zero standing access still holds: the group has no permanent members, so at
# rest no human holds User Administrator. The evidence pack shows the group as
# the only principal on the role, with zero active members outside activations.
#
# WHO IS ELIGIBLE is operational data (it references provisioned people), so
# it is set by lab/scripts/powershell/post-apply/Set-PimGroupEligibility.ps1
# rather than here - Terraform must not depend on provisioning having run.
# That script requests afterDuration eligibility, because this policy now
# REQUIRES eligible assignments to expire.
#
# OTHER FILES IN THIS MODULE (each behind its own staging flag, default false):
#   approvers.tf        PIM-Approvers-Tier0 / -Tier1 groups (groupMembers)
#   tiers.tf            the same pattern for every privileged role, by tier
#                       (var.enable_pim_tiers)
#   helpdesk.tf         AU-Workforce-Standard + AU-scoped help-desk roles
#                       (var.enable_helpdesk_au_scoping)
#   directory-roles.tf  Global Administrator's own PIM policy, rendered for
#                       post-apply/Set-DirectoryRolePimPolicies.ps1
#                       (var.enable_global_admin_pim_policy)
#   reviews.tf          access review bodies for PIM-eligible membership
#                       (output pim_eligible_review_bodies)
#   azure.tf            PIM for Azure RESOURCES (var.enable_pim_azure_resources)
#   aws.tf              PIM-AWS-Lab-Admins: AWS admin as a PIM-for-Groups
#                       activation (var.enable_pim_aws_admin, ADR 0025)
# =============================================================================

# -----------------------------------------------------------------------------
# (1) The role binding: Privileged-IAM-Admins actively holds the target role.
#     Default target is User Administrator (Tier-1), not Global Admin.
# -----------------------------------------------------------------------------
resource "azuread_directory_role_assignment" "priv_admins" {
  role_id             = var.role_template_id
  principal_object_id = var.priv_iam_admins_group_object_id
  directory_scope_id  = var.directory_scope_id
}

# -----------------------------------------------------------------------------
# (2) PIM for Groups: activation policy for the MEMBER role of the group.
#     THIS is the just-in-time control: MFA + justification + approval + 4h.
# -----------------------------------------------------------------------------
resource "azuread_group_role_management_policy" "member" {
  group_id = var.priv_iam_admins_group_object_id
  role_id  = "member" # "member" or "owner"

  activation_rules {
    # 4-hour cap on how long an activation lasts.
    maximum_duration = var.activation_max_duration

    # Require MFA at activation time.
    require_multifactor_authentication = var.require_mfa_on_activation

    # Require the activating user to record a justification.
    require_justification = var.require_justification

    # Require approver sign-off.
    require_approval = var.require_approval

    # Approval routes to the Tier-1 approver GROUP (approvers.tf). Only
    # emitted when approval is required.
    dynamic "approval_stage" {
      for_each = var.require_approval ? [1] : []
      content {
        primary_approver {
          object_id = azuread_group.pim_approvers["tier1"].object_id
          type      = "groupMembers"
        }
      }
    }
  }

  # Eligibility EXPIRES (Tier-1 cap, default 365 days): renewal is a fresh
  # request and approval, and the quarterly privileged access review
  # (reviews.tf / modules/entitlement) can remove it sooner.
  eligible_assignment_rules {
    expiration_required = true
    expire_after        = var.tier1_eligible_assignment_duration
  }

  # Direct ACTIVE membership (bypassing activation) must expire, and the
  # admin making it must give a justification and pass MFA.
  active_assignment_rules {
    expiration_required                = true
    expire_after                       = var.active_assignment_max_duration
    require_justification              = true
    require_multifactor_authentication = true
  }

  # Approval-gated, so activations are rare and worth a mail: all three admin
  # alerts go to the security mailbox (when one is set).
  dynamic "notification_rules" {
    for_each = local.pim_notifications_enabled ? [1] : []
    content {
      dynamic "eligible_activations" {
        for_each = var.require_approval ? [1] : []
        content {
          admin_notifications {
            notification_level    = "All"
            default_recipients    = true
            additional_recipients = [var.pim_alert_mailbox]
          }
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

  # Guardrail: approval requires at least one approver, or apply would create
  # an unapprovable (permanently blocked) activation path.
  lifecycle {
    precondition {
      condition     = var.require_approval == false || length(var.approver_object_ids) > 0
      error_message = "require_approval = true needs at least one entry in approver_object_ids (members of PIM-Approvers-Tier1)."
    }
  }
}
