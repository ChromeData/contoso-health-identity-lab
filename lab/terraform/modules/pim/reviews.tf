# =============================================================================
# modules/pim :: reviews.tf
# -----------------------------------------------------------------------------
# ACCESS REVIEWS OF PIM-ELIGIBLE MEMBERSHIP - rendered here, created post-apply
# (output pim_eligible_review_bodies).
#
# Eligibility now EXPIRES (180 / 365 days), but expiry alone lets a person
# who changed jobs keep the ability to activate for months. ADR 0012 tier T1:
# a quarterly review of every PIM-governed group, by a governance group
# (never the admins themselves), with a mandatory fallback reviewer, where
# silence = DENY, applied automatically.
#
# WHAT IS RENDERED (map key => Graph v1.0 accessReviewScheduleDefinition JSON,
# the same shape and key convention as modules/entitlement's
# access_review_definitions, so post-apply/New-AccessReviewDefinitions.ps1
# can POST it unchanged and its "privileged:*" self-review guard applies):
#
#   privileged:<group>   every group in output privileged_review_targets
#                        (Privileged-IAM-Admins, each tier group, the Azure
#                        PIM group). Scope "/groups/<id>/transitiveMembers".
#                        Learn (create-access-review-pim-for-groups): for a
#                        PIM-managed group "the users under review ...
#                        include all eligible users and active users".
#                        verify: Graph documents no PIM-group-specific scope;
#                        whether an API-created definition expands ELIGIBLE
#                        members the way a portal-created one does is
#                        unconfirmed - create one review in the portal, GET
#                        its definition and diff it against this body before
#                        relying on it.
#   privileged:Global Administrator (eligible)
#                        only with enable_global_admin_pim_policy. Scope:
#                        ELIGIBLE user assignments only (Graph accessreviews
#                        scope concept, example 12.2:
#                        roleEligibilityScheduleInstances, principal is a
#                        user). NOT the documented eligible+active scope
#                        (/roleManagement/directory/roleDefinitions/<id>):
#                        that would put Break-Glass-Admins' standing GA in a
#                        default-deny, auto-apply review and could remove the
#                        recovery path (ADR 0012: break-glass is never in
#                        scope; the 90-day drill checks it instead).
#
# The display names match modules/entitlement's ("Privileged access review:
# <group>"), so if both modules render a group the post-apply script, which
# matches by displayName, creates ONE series, never two.
#
# LICENSING: reviews of PIM for Groups need Microsoft Entra ID Governance (or
# Entra Suite), not just P2, and are labelled PREVIEW on Learn (2026-10-20).
# Permission: AccessReview.ReadWrite.All. Nothing renders while
# privileged_review_fallback_group_object_id is empty.
# =============================================================================

locals {
  review_reviewer_group_object_id = (
    var.privileged_review_reviewer_group_object_id != ""
    ? var.privileged_review_reviewer_group_object_id
    : var.privileged_review_fallback_group_object_id
  )
  review_enabled    = var.privileged_review_fallback_group_object_id != ""
  review_start_date = var.privileged_review_start_date != "" ? var.privileged_review_start_date : null

  # ADR 0012, T1 decision policy.
  review_settings = {
    mailNotificationsEnabled        = true
    reminderNotificationsEnabled    = true
    justificationRequiredOnApproval = true
    defaultDecisionEnabled          = true
    defaultDecision                 = "Deny"
    autoApplyDecisionsEnabled       = true
    recommendationsEnabled          = true
    recommendationLookBackDuration  = "P30D"
    instanceDurationInDays          = var.privileged_review_instance_duration_days
    recurrence = {
      pattern = { type = "absoluteMonthly", interval = 3 }
      range   = { type = "noEnd", startDate = local.review_start_date }
    }
  }

  review_reviewers = [{
    query     = "/groups/${local.review_reviewer_group_object_id}/transitiveMembers"
    queryType = "MicrosoftGraph"
  }]
  review_fallback_reviewers = [{
    query     = "/groups/${var.privileged_review_fallback_group_object_id}/transitiveMembers"
    queryType = "MicrosoftGraph"
  }]

  group_review_bodies = {
    for name, group_id in local.privileged_review_targets :
    "privileged:${name}" => jsonencode({
      displayName             = "Privileged access review: ${name}"
      descriptionForAdmins    = "Terraform-rendered (modules/pim/reviews.tf). Quarterly review of ELIGIBLE and active members of a PIM-governed admin group (ADR 0012, T1). No answer = deny; decisions auto-apply."
      descriptionForReviewers = "Can this person still justify being able to activate this admin role? If you are unsure, deny: they can re-request eligibility."
      scope = {
        "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
        query         = "/groups/${group_id}/transitiveMembers"
        queryType     = "MicrosoftGraph"
      }
      reviewers         = local.review_reviewers
      fallbackReviewers = local.review_fallback_reviewers
      settings          = local.review_settings
    })
  }

  global_admin_review_body = var.enable_global_admin_pim_policy ? {
    "privileged:Global Administrator (eligible)" = jsonencode({
      displayName             = "Privileged access review: Global Administrator (eligible)"
      descriptionForAdmins    = "Terraform-rendered (modules/pim/reviews.tf). Quarterly review of ELIGIBLE Global Administrator assignments of users. Break-glass (standing, via Break-Glass-Admins) is deliberately out of scope. No answer = deny; decisions auto-apply."
      descriptionForReviewers = "Can this person still justify being able to activate Global Administrator? If you are unsure, deny: they can re-request eligibility."
      scope = {
        "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
        query         = "/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal&$filter=(isof(principal,'microsoft.graph.user') and roleDefinitionId eq '${local.global_admin_role_template_id}')"
        queryType     = "MicrosoftGraph"
      }
      reviewers         = local.review_reviewers
      fallbackReviewers = local.review_fallback_reviewers
      settings          = local.review_settings
    })
  } : {}

  pim_eligible_review_bodies = local.review_enabled ? merge(local.group_review_bodies, local.global_admin_review_body) : {}
}

check "pim_reviews_have_reviewers" {
  assert {
    condition     = local.review_enabled || length(local.tier_groups) == 0
    error_message = "PIM tier groups exist but privileged_review_fallback_group_object_id is empty, so output pim_eligible_review_bodies is {}: nothing reviews who may activate (ADR 0012, T1)."
  }
}
