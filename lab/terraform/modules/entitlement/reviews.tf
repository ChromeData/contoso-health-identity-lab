# =============================================================================
# modules/entitlement :: reviews.tf
# -----------------------------------------------------------------------------
# STANDALONE ACCESS REVIEWS - rendered by Terraform, created post-apply.
#
# Two review series sit outside the access-package policies:
#
#   (1) PRIVILEGED ACCESS REVIEW - every PIM-governed admin group
#       (Privileged-IAM-Admins, the PIM tier groups, the Azure-resource
#       eligible group from modules/pim). For a group managed by PIM for
#       Groups, a "Teams + Groups" review covers the ELIGIBLE members as well
#       as the active ones, so a denied person loses the ability to activate,
#       not just a live activation. This is the control that makes "zero
#       standing access" auditable: eligibility is permanent by design (see
#       modules/pim), so this review is what stops it being permanent in fact.
#
#   (1b) PIM DIRECT-ROLE REVIEWS - bodies modules/pim renders for the direct
#       role eligibility a group review cannot see (Global Administrator,
#       ADR 0002), passed in as var.pim_eligible_review_bodies and merged
#       into the same output under the same T1 flag and contract.
#
#   (2) INACTIVE-USER REVIEW - members of the listed groups who have not
#       signed in (interactively or not) for var.inactive_review_days. Stale
#       accounts are the population attackers reuse; a reviewer sees only
#       those people, and silence removes them.
#
# FLAGS (ADR 0012, independent): (1) and (1b) render only while
# enable_access_reviews_privileged is on; (2) only while
# enable_access_reviews_inactive is on. Neither ever targets an access
# package, so neither can review birthright (T3) clinical access.
# Break-Glass-Admins is refused as a target (output precondition): a
# default-deny review would remove the recovery path.
#
# WHY NOT A RESOURCE: azuread 3.10 has no accessReviewScheduleDefinition
# resource (verified against the provider schema: only policy-attached reviews
# via azuread_access_package_assignment_policy.assignment_review_settings).
# Rather than hide that gap, Terraform renders the exact Microsoft Graph v1.0
# request bodies from real object ids (output access_review_definitions), and
# lab/scripts/powershell/post-apply/New-AccessReviewDefinitions.ps1 (spec in
# this module's README.md) POSTs any that do not exist yet, matched by
# displayName. The definition stays code-reviewed in this file; only the HTTP
# call is outside Terraform.
#
# DECISION POLICY (both series, the "deny by default" contract):
#   defaultDecisionEnabled = true, defaultDecision = "Deny"  - silence = removed
#   autoApplyDecisionsEnabled = true                        - no admin step
#   justificationRequiredOnApproval = true                  - evidence pack
# Microsoft warns that auto-apply + default deny revokes everything nobody
# answered. That is the intent for privileged and stale access - and why the
# fallback reviewer group is mandatory (precondition on the output below).
#
# LICENSING: PIM-for-Groups reviews and inactive-user reviews both need
# Microsoft Entra ID Governance (verify: licensing-fundamentals page before
# the trial). PIM-for-Groups reviews are still labelled PREVIEW on Microsoft
# Learn (checked 2026-10-20).
#
# Nothing here is rendered while every review flag is false (the default).
# =============================================================================

locals {
  # Graph patternedRecurrence for the provider's frequency words, so one
  # vocabulary (access_review_frequency) drives both kinds of review. Graph
  # supports only weekly / absoluteMonthly (+ interval, dayOfMonth) here.
  review_recurrence_pattern = {
    weekly     = { type = "weekly", interval = 1 }
    monthly    = { type = "absoluteMonthly", interval = 1 }
    quarterly  = { type = "absoluteMonthly", interval = 3 }
    halfyearly = { type = "absoluteMonthly", interval = 6 }
    annual     = { type = "absoluteMonthly", interval = 12 }
  }

  # Graph wants a plain date for recurrence.range.startDate. null = the
  # post-apply script uses today's UTC date. timestamp() is deliberately not
  # used: it would change the rendered output on every plan.
  review_start_date = var.access_review_start_date != "" ? formatdate("YYYY-MM-DD", var.access_review_start_date) : null

  # (local.privileged_reviewer_group_object_id - who reviews privileged
  # access - is defined in main.tf: T1 package reviews use it too.)

  # Settings shared by both series. lookback is per series (see below).
  standalone_review_settings = {
    mailNotificationsEnabled        = true
    reminderNotificationsEnabled    = true
    justificationRequiredOnApproval = true
    defaultDecisionEnabled          = true
    defaultDecision                 = "Deny"
    autoApplyDecisionsEnabled       = true
    recommendationsEnabled          = true
    instanceDurationInDays          = var.access_review_duration_days
  }

  privileged_review_bodies = {
    for name, group_id in var.privileged_review_group_object_ids :
    "privileged:${name}" => jsonencode({
      displayName             = "Privileged access review: ${name}"
      descriptionForAdmins    = "Terraform-rendered (modules/entitlement/reviews.tf). ${title(var.privileged_review_frequency)} review of ELIGIBLE and active members of a PIM-governed admin group. No answer = deny; decisions auto-apply."
      descriptionForReviewers = "Can this person still justify being able to activate this admin role? If you are unsure, deny: they can re-request eligibility."
      scope = {
        "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
        query         = "/groups/${group_id}/transitiveMembers"
        queryType     = "MicrosoftGraph"
      }
      # Reviewers are a named governance group, never the admins themselves
      # (no self-certification of privilege) and not the group owners: PIM
      # for Groups reviews only resolve ACTIVE owners, and these groups have
      # none at rest.
      reviewers = [{
        query     = "/groups/${local.privileged_reviewer_group_object_id}/transitiveMembers"
        queryType = "MicrosoftGraph"
      }]
      # Microsoft Learn: reviews of PIM-governed groups need at least one
      # fallback reviewer.
      fallbackReviewers = [{
        query     = "/groups/${local.review_fallback_group_object_id}/transitiveMembers"
        queryType = "MicrosoftGraph"
      }]
      settings = merge(local.standalone_review_settings, {
        # Recommend deny for an admin who has not signed in for 30 days.
        recommendationLookBackDuration = "P30D"
        recurrence = {
          pattern = local.review_recurrence_pattern[var.privileged_review_frequency]
          range   = { type = "noEnd", startDate = local.review_start_date }
        }
      })
    })
  }

  inactive_review_bodies = {
    for name, group_id in var.inactive_review_group_object_ids :
    "inactive:${name}" => jsonencode({
      displayName             = "Inactive users review: ${name}"
      descriptionForAdmins    = "Terraform-rendered (modules/entitlement/reviews.tf). Members with no sign-in for ${var.inactive_review_days} days. No answer = removed from the group; decisions auto-apply."
      descriptionForReviewers = "These people have not signed in for ${var.inactive_review_days} days. Approve only if you know why they still need this access."
      scope = {
        # @odata.type is REQUIRED for the inactive-users scope (Graph docs).
        "@odata.type"    = "#microsoft.graph.accessReviewInactiveUsersQueryScope"
        query            = "/groups/${group_id}/transitiveMembers"
        queryType        = "MicrosoftGraph"
        inactiveDuration = "P${var.inactive_review_days}D"
      }
      # The resource owner reviews first (app/group owner knows the
      # population); with no owner set, the fallback group gets it.
      reviewers = [{
        query     = "/groups/${group_id}/owners"
        queryType = "MicrosoftGraph"
      }]
      fallbackReviewers = [{
        query     = "/groups/${local.review_fallback_group_object_id}/transitiveMembers"
        queryType = "MicrosoftGraph"
      }]
      settings = merge(local.standalone_review_settings, {
        recommendationLookBackDuration = "P${var.inactive_review_days}D"
        recurrence = {
          pattern = local.review_recurrence_pattern[var.inactive_review_frequency]
          range   = { type = "noEnd", startDate = local.review_start_date }
        }
      })
    })
  }

  # T1 set: PIM-group bodies rendered here + modules/pim's bodies (its own
  # PIM-group reviews and the direct Global Administrator eligibility review).
  # merge() order: on the same key the modules/pim body wins, so one series
  # per group. Inactive set: hygiene, its own flag.
  privileged_definitions = local.reviews_privileged ? merge(local.privileged_review_bodies, var.pim_eligible_review_bodies) : {}
  inactive_definitions   = local.reviews_inactive ? local.inactive_review_bodies : {}

  # map(string): key => JSON body. Strings (not objects) because the scope
  # shapes differ, and Terraform cannot put differently-shaped objects in one
  # map. The post-apply script ConvertFrom-Json's each value.
  access_review_definitions = merge(local.privileged_definitions, local.inactive_definitions)

  # Guard inputs for the output preconditions (outputs.tf).
  review_target_names = concat(
    local.reviews_privileged ? keys(var.privileged_review_group_object_ids) : [],
    local.reviews_inactive ? keys(var.inactive_review_group_object_ids) : [],
  )
  review_target_ids = concat(
    local.reviews_privileged ? values(var.privileged_review_group_object_ids) : [],
    local.reviews_inactive ? values(var.inactive_review_group_object_ids) : [],
  )
}
