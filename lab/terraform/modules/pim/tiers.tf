# =============================================================================
# modules/pim :: tiers.tf
# -----------------------------------------------------------------------------
# PIM TIER GROUPS (var.enable_pim_tiers, default false).
#
# One admin role is a demo; a tiered admin model is a design. Each group
# below repeats the main.tf pattern - the group ACTIVELY holds its directory
# role(s), its MEMBERSHIP is eligible-only and activated just-in-time through
# PIM for Groups - so there is still exactly one activation per elevation.
#
# Enterprise Access Model (var.pim_tier_groups holds the full map; role ids
# verified against Microsoft's built-in roles reference 2026-10-20):
#
#   Tier 0  control plane - can grant itself or others any access, or change
#           how sign-in is protected:
#             Security, Conditional Access, Privileged Role, Privileged
#             Authentication, Hybrid Identity, Application, Cloud Application,
#             Authentication Policy Administrator
#           activation: approval (PIM-Approvers-Tier0) + justification +
#           ticket + MFA (or auth context c1 once CA021 is enforced), 4h
#           (Privileged Authentication Administrator 2h); eligibility
#           expires after 180 days
#   Tier 1  management plane - devices, workloads, ordinary users:
#             Intune (WITH approval: it reads LAPS passwords and BitLocker
#             keys), Helpdesk + Authentication Administrator (the service
#             desk, AU-scoped by helpdesk.tf), Groups, Exchange, SharePoint,
#             Teams, License Administrator
#           activation: justification + MFA, 8h (a shift), no approval unless
#           the group asks for it - an approval queue on every helpdesk shift
#           trains people to rubber-stamp; eligibility expires after 365 days
#   (User Administrator stays on Privileged-IAM-Admins in main.tf; Global
#    Administrator is never a tier group - directory-roles.tf.)
#
# Every group, every tier: direct ACTIVE membership expires (P15D) and needs
# justification + MFA from the admin making it; admin notifications go to
# var.pim_alert_mailbox (see its description for which alerts per tier).
#
# Approvers: PIM does not let a requester approve their own activation
# (Microsoft Learn, PIM approval). Keep the approver groups (approvers.tf) and
# the eligible people disjoint anyway.
#
# Eligibility (WHO) is set post-apply, once per group:
# post-apply/Set-PimGroupEligibility.ps1 -GroupMailNickname <nickname>
# (output tier_group_mail_nicknames). It requests 180-day (tier 0) or
# 365-day (tier 1) eligibility; the policy here refuses anything longer.
#
# LICENSING: role-assignable groups need Entra ID P1; PIM for Groups needs
# Entra ID P2 for every eligible member (both in the M365 E5 trial). Every
# group here counts toward the tenant's role-assignable group limit (verify:
# 500 per tenant).
# =============================================================================

locals {
  tier_groups = var.enable_pim_tiers ? var.pim_tier_groups : {}

  # Whether a mailbox is set is not secret (the address is): a plain bool,
  # so it can drive dynamic blocks (for_each refuses sensitive values).
  pim_notifications_enabled = nonsensitive(var.pim_alert_mailbox != "")

  # ISO-8601 activation durations -> minutes, to keep per-group overrides
  # below the tier cap.
  duration_minutes = {
    for d in distinct(concat(
      [var.tier0_activation_max_duration, var.tier1_activation_max_duration, var.global_admin_activation_max_duration],
      [for g in values(var.pim_tier_groups) : coalesce(g.activation_max_duration, var.tier1_activation_max_duration)],
      )) : d => d == "P1D" ? 1440 : (
      tonumber(try(regex("([0-9]+)H", d)[0], "0")) * 60 + tonumber(try(regex("([0-9]+)M", d)[0], "0"))
    )
  }

  tier_defaults = {
    "0" = {
      maximum_duration      = var.tier0_activation_max_duration
      eligible_expire_after = var.tier0_eligible_assignment_duration
      require_ticket_info   = var.tier0_require_ticket_info
      auth_context          = var.tier0_activation_auth_context_id
    }
    "1" = {
      maximum_duration      = var.tier1_activation_max_duration
      eligible_expire_after = var.tier1_eligible_assignment_duration
      require_ticket_info   = false
      auth_context          = ""
    }
  }

  # Effective settings per group: tier default, then the group's own
  # (tightening-only) overrides.
  tier_group_settings = {
    for k, g in local.tier_groups : k => {
      tier                  = g.tier
      maximum_duration      = coalesce(g.activation_max_duration, local.tier_defaults[tostring(g.tier)].maximum_duration)
      tier_cap              = local.tier_defaults[tostring(g.tier)].maximum_duration
      require_approval      = g.tier == 0 ? true : coalesce(g.require_approval, false)
      require_ticket_info   = local.tier_defaults[tostring(g.tier)].require_ticket_info
      auth_context          = local.tier_defaults[tostring(g.tier)].auth_context
      eligible_expire_after = local.tier_defaults[tostring(g.tier)].eligible_expire_after
      approver_tier         = g.tier == 0 ? "tier0" : "tier1"
      # Activation alerts: Tier 0 and approval-gated groups always; other
      # Tier-1 groups only on request (volume).
      notify_activations = g.tier == 0 || coalesce(g.require_approval, false) || var.tier1_activation_notifications
      role_template_ids  = concat([g.role_template_id], g.additional_role_template_ids)
      au_scoped          = g.au_scoped && var.enable_helpdesk_au_scoping
    }
  }

  # MFA flag for Tier 0: null when the auth context replaces it (the provider
  # declares the two ConflictsWith - null, not false), false only during
  # apply 1 of the two-apply switch-over (variables.tf).
  tier0_mfa = var.tier0_activation_auth_context_id != "" ? null : (var.tier0_auth_context_switchover_step1 ? false : true)

  # One role assignment per (group, role). Primary roles keep the original
  # address (pim_tier[<group key>]); additional roles get "<group>:<role>".
  tier_role_assignments_extra = {
    for p in flatten([
      for k, g in local.tier_groups : [
        for r in g.additional_role_template_ids : { key = "${k}:${r}", group_key = k, role_template_id = r }
      ]
    ]) : p.key => p
  }
}

# Role-assignable so that only Privileged Role Administrators / Global Admins
# (and the group's owners) can change membership or owners - a Groups
# Administrator cannot add themselves to a tier group. Required anyway for
# AU-scoped role assignments to a group.
resource "azuread_group" "pim_tier" {
  for_each = local.tier_groups

  display_name       = each.value.display_name
  mail_nickname      = each.value.mail_nickname
  description        = "PIM for Groups, Tier ${each.value.tier}: eligible-only membership, actively holds ${each.value.role_name}${local.tier_group_settings[each.key].au_scoped ? " at ${var.workforce_au_display_name} scope" : ""}. No standing members."
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  # Membership is owned by PIM (eligibility schedules + activations).
  lifecycle {
    ignore_changes = [members]
  }
}

# The group actively holds the role; activation of MEMBERSHIP is the JIT step.
# Scope: tenant-wide, or AU-Workforce-Standard for au_scoped groups when
# enable_helpdesk_au_scoping is on (changing it replaces the assignment).
resource "azuread_directory_role_assignment" "pim_tier" {
  for_each = local.tier_groups

  role_id             = each.value.role_template_id
  principal_object_id = azuread_group.pim_tier[each.key].object_id
  directory_scope_id  = local.tier_group_settings[each.key].au_scoped ? "/administrativeUnits/${azuread_administrative_unit.workforce_standard[0].object_id}" : "/"
}

resource "azuread_directory_role_assignment" "pim_tier_additional" {
  for_each = local.tier_role_assignments_extra

  role_id             = each.value.role_template_id
  principal_object_id = azuread_group.pim_tier[each.value.group_key].object_id
  directory_scope_id  = local.tier_group_settings[each.value.group_key].au_scoped ? "/administrativeUnits/${azuread_administrative_unit.workforce_standard[0].object_id}" : "/"
}

resource "azuread_group_role_management_policy" "pim_tier_member" {
  for_each = local.tier_groups

  group_id = azuread_group.pim_tier[each.key].object_id
  role_id  = "member"

  activation_rules {
    maximum_duration = local.tier_group_settings[each.key].maximum_duration

    # The provider declares these two ConflictsWith each other (it fires
    # even for false), so the unused one must be null (unset).
    require_multifactor_authentication                 = each.value.tier == 0 ? local.tier0_mfa : true
    required_conditional_access_authentication_context = local.tier_group_settings[each.key].auth_context != "" ? local.tier_group_settings[each.key].auth_context : null

    require_justification = true
    require_ticket_info   = local.tier_group_settings[each.key].require_ticket_info
    require_approval      = local.tier_group_settings[each.key].require_approval

    dynamic "approval_stage" {
      for_each = local.tier_group_settings[each.key].require_approval ? [1] : []
      content {
        primary_approver {
          object_id = azuread_group.pim_approvers[local.tier_group_settings[each.key].approver_tier].object_id
          type      = "groupMembers"
        }
      }
    }
  }

  # Eligibility EXPIRES: 180 days (Tier 0) / 365 days (Tier 1). Renewal is a
  # new request + approval; the quarterly review (reviews.tf) can end it
  # sooner. verify: whether turning this on trims eligibilities that were
  # created permanent before it (Set-PimGroupEligibility.ps1 reports them).
  eligible_assignment_rules {
    expiration_required = true
    expire_after        = local.tier_group_settings[each.key].eligible_expire_after
  }

  # Nobody parks a permanent ACTIVE member in a tier group, and the admin who
  # makes a direct active assignment justifies it and passes MFA.
  active_assignment_rules {
    expiration_required                = true
    expire_after                       = var.active_assignment_max_duration
    require_justification              = true
    require_multifactor_authentication = true
  }

  dynamic "notification_rules" {
    for_each = local.pim_notifications_enabled ? [1] : []
    content {
      # Notification_Admin_EndUser_Assignment: someone activated.
      dynamic "eligible_activations" {
        for_each = local.tier_group_settings[each.key].notify_activations ? [1] : []
        content {
          admin_notifications {
            notification_level    = "All"
            default_recipients    = true
            additional_recipients = [var.pim_alert_mailbox]
          }
        }
      }
      # Notification_Admin_Admin_Eligibility: new eligibility granted.
      eligible_assignments {
        admin_notifications {
          notification_level    = "All"
          default_recipients    = true
          additional_recipients = [var.pim_alert_mailbox]
        }
      }
      # Notification_Admin_Admin_Assignment: direct ACTIVE = activation bypass.
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
      condition     = !local.tier_group_settings[each.key].require_approval || length(local.approver_groups[local.tier_group_settings[each.key].approver_tier].members) > 0
      error_message = "${each.value.display_name} requires approval: put at least one approver in ${local.tier_group_settings[each.key].approver_tier == "tier0" ? "tier0_approver_object_ids (or approver_object_ids)" : "approver_object_ids"}."
    }
    precondition {
      condition     = local.duration_minutes[local.tier_group_settings[each.key].maximum_duration] <= local.duration_minutes[local.tier_group_settings[each.key].tier_cap]
      error_message = "${each.value.display_name}: activation_max_duration may only shorten the Tier-${each.value.tier} cap (${local.tier_group_settings[each.key].tier_cap})."
    }
    precondition {
      # Never let PIM require a context before CA021 enforces it: with no
      # (or a report-only) policy behind it, activation may be WEAKER than MFA.
      condition     = each.value.tier != 0 || (var.tier0_activation_auth_context_id == "" && !var.tier0_auth_context_switchover_step1) || var.activation_auth_context_ca_enforced
      error_message = "tier0_activation_auth_context_id / tier0_auth_context_switchover_step1 need activation_auth_context_ca_enforced = true (CA021 state = enabled; wire it from modules/conditional-access output pim_activation_auth_context_ready)."
    }
  }
}

check "tier0_step_up_switchover_in_progress" {
  assert {
    condition     = !(var.tier0_auth_context_switchover_step1 && var.tier0_activation_auth_context_id == "")
    error_message = "Apply 1 of the MFA -> auth-context switch is planned: Tier-0 activation requires NEITHER MFA NOR an auth context until apply 2 sets tier0_activation_auth_context_id. Run apply 2 straight after; approvers deny any Tier-0 activation in between."
  }
}
