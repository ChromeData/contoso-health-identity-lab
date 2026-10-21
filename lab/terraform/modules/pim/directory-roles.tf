# =============================================================================
# modules/pim :: directory-roles.tf
# -----------------------------------------------------------------------------
# GLOBAL ADMINISTRATOR - DIRECT, NAMED, EXPIRING ELIGIBILITY
# (var.enable_global_admin_pim_policy, default false)
#
#   Break-Glass-Admins --(ACTIVE, standing)--> Global Administrator  (modules/groups, ADR 0003)
#   adm-<person>       --(ELIGIBLE, 180 days)--> Global Administrator (this file + script)
#        activation: approval (PIM-Approvers-Tier0) + justification + ticket
#                    + MFA (or auth context c1 once CA021 is enforced), 2h
#
# WHY NOT A TIER GROUP: a group that actively held GA would make its
# membership the most valuable object in the tenant, and the tier-map
# validation refuses it (variables.tf). Global Administrator eligibility is
# granted per named person, directly on the role.
#
# WHY GRAPH, NOT A RESOURCE: azuread 3.10.0 has no directory-role policy
# resource, and azuread_directory_role_eligibility_schedule_request always
# sends noExpiration (provider source) - which this policy refuses. So, like
# the access reviews, Terraform RENDERS the rule bodies from real ids (output
# directory_role_pim_policies) and post-apply/Set-DirectoryRolePimPolicies.ps1
#   1. finds the role's policy (GET /policies/roleManagementPolicyAssignments
#      ?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and
#      roleDefinitionId eq '<GA>'),
#   2. PATCHes each rule that differs (strengthening rules first: the auth
#      context is enabled BEFORE MFA is dropped, MFA re-added BEFORE the
#      context is switched off), stopping a role at its first failure,
#   3. grants NAMED eligibility with expiration afterDuration = P180D.
# Permission: RoleManagementPolicy.ReadWrite.Directory +
# RoleEligibilitySchedule.ReadWrite.Directory.
#
# DELIBERATELY NOT RENDERED: Expiration_Admin_Assignment and
# Enablement_Admin_Assignment (direct ACTIVE assignment rules). Break-glass
# holds standing GA through a Terraform role assignment (modules/groups);
# requiring active GA assignments to expire, or MFA from the admin making
# them, could block re-creating that assignment. verify: whether the
# roleAssignments API that azuread_directory_role_assignment uses honours
# these PIM rules - until then they stay at the tenant default, and the
# ITDR rule "role assigned outside PIM" watches direct GA assignments.
#
# Rule bodies follow Microsoft's documented examples (how-to-pim-update-rules:
# Expiration / Enablement / Approval / Expiration_Admin_Eligibility) and the
# resource pages for the AuthenticationContext and Notification rules (no
# documented example for those two - verify: first PATCH).
# =============================================================================

locals {
  global_admin_role_template_id = "62e90394-69f5-4237-9190-012177145e10"

  ga_auth_context = var.tier0_activation_auth_context_id

  ga_notification = {
    notificationType           = "Email"
    recipientType              = "Admin"
    notificationLevel          = "All"
    isDefaultRecipientsEnabled = true
    notificationRecipients     = [var.pim_alert_mailbox]
  }

  ga_rules = concat([
    {
      "@odata.type"        = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
      id                   = "Expiration_EndUser_Assignment"
      isExpirationRequired = true
      maximumDuration      = var.global_admin_activation_max_duration
      target               = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "EndUser", operations = ["All"], level = "Assignment", inheritableSettings = [], enforcedSettings = [] }
    },
    {
      "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
      id            = "Enablement_EndUser_Assignment"
      # MFA is replaced by the auth context, never combined with it (the
      # portal offers them as alternatives; verify: Graph rejects both).
      enabledRules = concat(
        local.ga_auth_context == "" ? ["MultiFactorAuthentication"] : [],
        ["Justification"],
        var.tier0_require_ticket_info ? ["Ticketing"] : [],
      )
      target = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "EndUser", operations = ["All"], level = "Assignment", inheritableSettings = [], enforcedSettings = [] }
    },
    {
      "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule"
      id            = "AuthenticationContext_EndUser_Assignment"
      isEnabled     = local.ga_auth_context != ""
      claimValue    = local.ga_auth_context != "" ? local.ga_auth_context : null
      target        = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "EndUser", operations = ["All"], level = "Assignment", inheritableSettings = [], enforcedSettings = [] }
    },
    {
      "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
      id            = "Approval_EndUser_Assignment"
      target        = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "EndUser", operations = ["All"], level = "Assignment", inheritableSettings = [], enforcedSettings = [] }
      setting = {
        "@odata.type"                    = "microsoft.graph.approvalSettings"
        isApprovalRequired               = true
        isApprovalRequiredForExtension   = false
        isRequestorJustificationRequired = true
        approvalMode                     = "SingleStage"
        approvalStages = [{
          approvalStageTimeOutInDays      = 1
          isApproverJustificationRequired = true
          escalationTimeInMinutes         = 0
          isEscalationEnabled             = false
          escalationApprovers             = []
          primaryApprovers = [{
            "@odata.type" = "#microsoft.graph.groupMembers"
            groupId       = try(azuread_group.pim_approvers["tier0"].object_id, null)
          }]
        }]
      }
    },
    {
      "@odata.type"        = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
      id                   = "Expiration_Admin_Eligibility"
      isExpirationRequired = true
      maximumDuration      = var.global_admin_eligible_duration
      target               = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "Admin", operations = ["All"], level = "Eligibility", inheritableSettings = [], enforcedSettings = [] }
    },
    ], local.pim_notifications_enabled ? [
    merge(local.ga_notification, {
      "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
      id            = "Notification_Admin_EndUser_Assignment" # role activation alert
      target        = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "EndUser", operations = ["All"], level = "Assignment", inheritableSettings = [], enforcedSettings = [] }
    }),
    merge(local.ga_notification, {
      "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
      id            = "Notification_Admin_Admin_Eligibility" # eligible assignment granted
      target        = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "Admin", operations = ["All"], level = "Eligibility", inheritableSettings = [], enforcedSettings = [] }
    }),
    merge(local.ga_notification, {
      "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
      id            = "Notification_Admin_Admin_Assignment" # direct ACTIVE assignment
      target        = { "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget", caller = "Admin", operations = ["All"], level = "Assignment", inheritableSettings = [], enforcedSettings = [] }
    }),
  ] : [])

  directory_role_pim_policies = var.enable_global_admin_pim_policy ? {
    (local.global_admin_role_template_id) = jsonencode({
      roleDefinitionId = local.global_admin_role_template_id
      roleName         = "Global Administrator"
      tier             = 0
      directoryScopeId = "/"
      # Set-DirectoryRolePimPolicies.ps1 grants eligibility to the named
      # people it is given, with this afterDuration - never noExpiration.
      allowNamedEligibility = true
      eligibilityDuration   = var.global_admin_eligible_duration
      rules                 = local.ga_rules
    })
  } : {}
}
