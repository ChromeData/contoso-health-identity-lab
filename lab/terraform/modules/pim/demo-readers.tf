# =============================================================================
# modules/pim :: demo-readers.tf
# -----------------------------------------------------------------------------
# READ-ONLY PRESENTER ACCESS, JUST-IN-TIME (var.enable_pim_demo_readers,
# default false).
#
#   PIM-Demo-Readers --(ACTIVE, tenant-wide)--> Global Reader
#            ^       --(ACTIVE, tenant-wide)--> Security Reader
#            |       --(ACTIVE, lab subscription; envs/bootstrap, see below)-->
#            |            Azure Reader, Microsoft Sentinel Reader,
#            |            Log Analytics Reader
#            |
#            |  membership is ELIGIBLE-ONLY, activated just-in-time through
#            |  PIM for Groups: MFA + justification, 8-hour cap, NO approval,
#            |  every activation mailed to the security mailbox
#          the demo presenter's admin account (adm-presenter,
#          lab/iga/admin-accounts.json: no HR owner, sponsored by the lab owner)
#
# WHY: whoever presents the lab live must be able to OPEN every admin page
# (Entra, Defender, Sentinel, the Azure portal) without being able to CHANGE
# anything, and without holding even that at rest. Same pattern as main.tf
# and tiers.tf: the group holds the roles, its MEMBERSHIP is the one
# just-in-time step - one activation, every read role at once.
#
# VERIFIED (Microsoft Learn, read 2026-11-05):
#   * Role template ids, and both roles labelled PRIVILEGED:
#     https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
#     Global Reader   f2ef992c-3afb-46b9-b7cf-a126ee74c451
#     Security Reader 5d6b6bb7-de71-4623-b4af-96380a352509
#   * A role-assignable group can be assigned Microsoft Entra roles "in the
#     same way as you assign roles to users" (no built-in role is excluded),
#     and PIM can make the group's MEMBERS eligible instead of standing:
#     https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept
#   * PIM for Groups: "Make active assignment of a role to a group and assign
#     users to be eligible to group membership" (option 2); groups govern
#     "Microsoft Entra roles, Azure roles, ..."; MFA, justification, approval
#     and maximum activation time are per-group policy settings:
#     https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups
#     The same page warns that SharePoint / Exchange / Purview permissions can
#     take "significant time" to arrive through option 2. Global Reader's
#     Entra, Defender, Sentinel and Azure portal views are what the demo
#     needs; verify: on the first activation how long the Microsoft 365
#     admin center views take to appear.
#
# WHY NO APPROVAL (the request was explicit, and it is a deliberate gap):
# Learn (the two pages above) recommends approval for groups "used for
# elevating into Microsoft Entra roles", because a less-privileged admin who
# can reset the member's credentials could activate on their behalf. The
# group is role-assignable, which closes that path: only Privileged
# Authentication Administrators (and Global Administrators) can change the
# credentials of its members, "including eligible members ... who haven't
# activated yet" (concept-pim-for-groups). PIM also never lets a requester
# approve their own request, and the presenter must be able to activate
# alone, on camera. Compensating controls: MFA (a passkey in practice) and a
# written reason on every activation, an 8-hour cap, eligibility that
# expires after the Tier-1 duration, EVERY activation mailed to
# var.pim_alert_mailbox (a check warns without one), the quarterly
# privileged review, and the ITDR rule for members added outside PIM
# (envs/dev itdr_privileged_group_ids).
#
# RESIDUAL RISK - SAY IT, DO NOT HIDE IT: both roles carry
# microsoft.directory/bitlockerKeys/key/read ("Read bitlocker metadata and
# key on devices", permissions-reference above), and Global Reader reads
# every directory setting. Neither reads LAPS passwords (only
# deviceLocalCredentials/standard/read). The lab requires approval for
# PIM-Tier1-Intune-Admins partly BECAUSE Intune reads BitLocker keys; here
# the same key read is reachable without approval, for a read-only role, as
# a recorded and mailed activation. Turn on approval (a second person in
# PIM-Approvers-Tier1) if the presenter account is ever used for anything
# but the demo.
#
# WHY A SEPARATE RESOURCE SET, NOT A pim_tier_groups ENTRY: every tier group
# lands in output privileged_review_targets, which envs/dev passes to
# modules/conditional-access as the CA002 / CA020 included_groups. Changes
# to Conditional Access are made separately and on purpose, so - like
# PIM-AWS-Lab-Admins (aws.tf) - this group joins the quarterly REVIEW
# (reviews.tf) but not the CA scope, and its two roles are kept out of
# output privileged_role_template_ids (CA020's role list). The tier map
# also stays "8 Tier 0 / 8 Tier 1".
#
# ACTIVATION POLICY = Tier-1 shape: 8-hour cap (var.tier1_activation_max_
# duration is the ceiling), MFA + justification; eligibility EXPIRES after
# var.tier1_eligible_assignment_duration (default 365 days) like every
# Tier-1 group - Set-PimGroupEligibility.ps1 already treats any nickname
# that is not pim-tier0-* as Tier 1 and requests exactly that duration, and
# a permanent eligibility would be the only non-expiring human eligibility
# in the module. Direct ACTIVE membership expires (P15D) and needs
# justification + MFA, as everywhere.
#
# AZURE RBAC IS NOT HERE: the subscription-scope Reader / Microsoft Sentinel
# Reader / Log Analytics Reader assignments need roleAssignments/write for
# those role ids. The CI APPLY identity's RBAC Administrator grant is
# ABAC-limited to three delegable roles (envs/bootstrap delegable_role_ids),
# and widening it would let CI hand out read access to every log in the
# subscription. So the three grants live in envs/bootstrap
# (enable_pim_demo_readers_azure_rbac), human-applied, fed with output
# demo_readers_group_object_id.
#
# WHO IS ELIGIBLE is operational data: Set-PimGroupEligibility.ps1
# -GroupMailNickname pim-demo-readers -UserPrincipalNames adm-presenter@...
#
# LICENSING: role-assignable groups need Entra ID P1; PIM for Groups needs
# Entra ID P2 for the eligible member (M365 E5 trial).
# =============================================================================

locals {
  demo_readers_enabled = var.enable_pim_demo_readers

  # Fixed, read-only by construction: no variable can add a role here.
  demo_readers_directory_roles = {
    global_reader   = "f2ef992c-3afb-46b9-b7cf-a126ee74c451" # Global Reader (PRIVILEGED label; reads BitLocker keys)
    security_reader = "5d6b6bb7-de71-4623-b4af-96380a352509" # Security Reader (PRIVILEGED label; reads BitLocker keys)
  }

  demo_readers_role_assignments = local.demo_readers_enabled ? local.demo_readers_directory_roles : {}

  # Display name => object id; joins the quarterly privileged review
  # (reviews.tf) but not the CA scope (see the header).
  demo_readers_review_target = { for g in azuread_group.demo_readers : var.demo_readers_group_name => g.object_id }
}

resource "azuread_group" "demo_readers" {
  count = local.demo_readers_enabled ? 1 : 0

  display_name       = var.demo_readers_group_name
  mail_nickname      = var.demo_readers_group_mail_nickname
  description        = "PIM for Groups: eligible-only membership, actively holds Global Reader + Security Reader (and, via envs/bootstrap, Azure Reader / Microsoft Sentinel Reader / Log Analytics Reader on the lab subscription). Read-only demo presenter access. No standing members."
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  # Membership is owned by PIM (eligibility schedules + activations).
  lifecycle {
    ignore_changes = [members]
  }
}

# The group actively holds the read roles; activation of MEMBERSHIP is the
# just-in-time step. Tenant-wide: Global Reader has no narrower scope.
resource "azuread_directory_role_assignment" "demo_readers" {
  for_each = local.demo_readers_role_assignments

  role_id             = each.value
  principal_object_id = azuread_group.demo_readers[0].object_id
  directory_scope_id  = "/"
}

resource "azuread_group_role_management_policy" "demo_readers_member" {
  count = local.demo_readers_enabled ? 1 : 0

  group_id = azuread_group.demo_readers[0].object_id
  role_id  = "member"

  activation_rules {
    maximum_duration                   = var.demo_readers_activation_max_duration
    require_multifactor_authentication = true
    require_justification              = true
    # Deliberately false (see the header); no approval_stage.
    require_approval = false
  }

  # Eligibility EXPIRES at the Tier-1 duration (default 365 days).
  eligible_assignment_rules {
    expiration_required = true
    expire_after        = var.tier1_eligible_assignment_duration
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
  # off, the mail is how a second person learns the read roles were used.
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
      # Read-only access never gets a longer window than a Tier-1 shift.
      condition     = local.duration_minutes[var.demo_readers_activation_max_duration] <= local.duration_minutes[var.tier1_activation_max_duration]
      error_message = "demo_readers_activation_max_duration may not exceed the Tier-1 cap (tier1_activation_max_duration)."
    }
  }
}

# With approval off, the activation mail is the second pair of eyes. Say so
# when there is no mailbox to send it to.
check "demo_readers_activations_are_seen" {
  assert {
    condition     = !local.demo_readers_enabled || local.pim_notifications_enabled
    error_message = "PIM-Demo-Readers activates without approval and pim_alert_mailbox is empty: nobody but the presenter learns that Global Reader / Security Reader were used. Set pim_alert_mailbox."
  }
}
