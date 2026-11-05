# =============================================================================
# modules/entitlement :: main.tf
# -----------------------------------------------------------------------------
# Entra ID Entitlement Management (Identity Governance):
#   * Catalog "Clinical"
#   * Access packages (var.access_packages), each with an ADR 0012 tier and an
#     assignment model:
#       nurse     "Nurse - Clinical Apps"                 T3 automatic (birthright)
#       icu       "ICU - Critical Care Apps"              T3 automatic (birthright, mover target)
#       cloud_engineering "IT - Cloud Engineering Apps"   T3 automatic (birthright, ServiceNow + AWS)
#       icu_float "ICU - Float Access"                    T2 request   (float / agency ICU shifts)
#       pharmacy  "Pharmacy - Controlled Substances Apps" T2 request   (SoD side of SOD-01)
#   * A REQUEST policy only for request packages (T1/T2): approval,
#     justification, 180-day expiry, extension re-approved when allowed.
#   * NO Terraform policy for automatic (T3) packages. Their only policy is the
#     HR-attribute automatic assignment policy that
#     lab/scripts/powershell/post-apply/Set-AutoAssignmentPolicies.ps1 creates
#     from lab/iga/birthright-rules.json (azuread 3.10 has no
#     automaticRequestSettings). A Terraform request policy on the same
#     package would bring back the day-180 lockout ADR 0012 removes and give
#     the package two assignment paths.
#
# RESOURCES ARE ASSIGNED GROUPS ONLY. Entitlement management grants membership,
# so dynamic groups (All-Nurses / All-ICU) can never be package resources.
#
# LICENSING: Entitlement Management requires Entra ID GOVERNANCE (or legacy
# "Entra ID P2 / EMS E5"). Every user who is ASSIGNED a package - automatically
# or on request - consumes a Governance license. This is the highest license
# tier in the whole lab.
#
# SEPARATION OF DUTIES - PROVIDER LIMITATION (read this):
#   The azuread provider does NOT expose the access package "incompatible
#   access packages" relationship (Graph: incompatibleAccessPackages). The
#   ruleset is lab/iga/sod-rules.json; post-apply/Set-IncompatibleAccessPackages.ps1
#   writes the links, and ONLY on requestable packages: a link on a birthright
#   package could block its automatic assignment. That is why ICU is split -
#   "ICU - Float Access" is the requestable side SOD-01 can gate.
#   var.sod_incompatible_pairs is legacy (output for envs/dev only).
#
# ACCESS REVIEWS, RISK-TIERED (ADR 0012) - one flag per tier, all default false:
#   T1  enable_access_reviews_privileged   quarterly policy review on a T1
#                                          package (governance group reviews,
#                                          unanswered = removed) + the T1
#                                          standalone reviews in reviews.tf
#   T2  enable_access_reviews_requestable  half-yearly policy review ONLY on a
#                                          T2 package that lives longer than
#                                          180 days or allows extension;
#                                          otherwise the 180-day expiry + re-
#                                          approval is the certification
#   T3  (no flag)                          never reviewed by a person; HR
#                                          attributes certify it
#   The flags are independent: turning on T1 cannot put a review - let alone
#   unanswered = removed - on a clinical package (the reported bug of the old
#   single enable_access_reviews switch, kept only as a deprecated alias).
#
# OTHER FILES IN THIS MODULE (each behind its own staging flag, default false):
#   reviews.tf - standalone access reviews the provider cannot create (PIM-group
#                and PIM direct-role privileged reviews, inactive-user review),
#                rendered as Graph bodies (output access_review_definitions) and
#                created by post-apply/New-AccessReviewDefinitions.ps1.
#   b2b.tf     - B2B guest governance (var.enable_b2b_governance): a separate,
#                externally visible "Affiliated Partners" catalog with the
#                "Affiliated Physicians" package. Tenant-wide external
#                collaboration settings are post-apply/Set-ExternalCollaboration.ps1.
# =============================================================================

# -----------------------------------------------------------------------------
# Catalog.
# -----------------------------------------------------------------------------
resource "azuread_access_package_catalog" "clinical" {
  display_name = var.catalog_name
  description  = var.catalog_description

  # Internal-only, permanently: clinical packages (including controlled-
  # substance dispensing) must never be requestable by a guest. External
  # requests live in their own catalog (b2b.tf), so "enabled for external
  # users" is a per-catalog decision a reviewer can see in one place.
  externally_visible = false
  published          = true

  lifecycle {
    # Fail at PLAN when any review flag is on but nobody could finish a review
    # (users without a manager, PIM-group reviews that need a fallback).
    precondition {
      condition     = !local.any_review_flag || local.review_fallback_group_object_id != ""
      error_message = "An access-review flag is on (enable_access_reviews_privileged / _requestable / _inactive, or the deprecated enable_access_reviews) but there is no fallback reviewer group: set access_review_fallback_group_object_id (or approver_group_object_id)."
    }
  }
}

# -----------------------------------------------------------------------------
# Catalog resources: bring every referenced group INTO the catalog before a
# package can hand it out. One association per distinct group.
# -----------------------------------------------------------------------------
locals {
  # Only the groups some package actually uses go into the catalog.
  catalog_group_keys = toset(flatten([
    for p in values(var.access_packages) : p.group_keys
  ]))

  # Flattened (package, group) pairs => one package-resource association each.
  package_group_pairs = {
    for pair in flatten([
      for pkey, p in var.access_packages : [
        for gkey in p.group_keys : { package = pkey, group = gkey }
      ]
    ]) : "${pair.package}.${pair.group}" => pair
  }

  # Approval routing: a named approver group if supplied, else requestorManager.
  use_group_approver = var.approver_group_object_id != ""

  # ---- ADR 0012 assignment models -------------------------------------------
  request_packages   = { for k, p in var.access_packages : k => p if p.assignment == "request" }
  automatic_packages = { for k, p in var.access_packages : k => p if p.assignment == "automatic" }

  # Request lifetime per package (null = the module default, contract 180).
  package_duration_days = { for k, p in local.request_packages : k => coalesce(p.duration_in_days, var.assignment_duration_days) }

  # ADR 0012: a T2 assignment that expires within 180 days and cannot be
  # extended is re-certified by the re-request itself - no campaign.
  t2_expiry_certifies_days = 180

  # ---- Review flags (independent; the deprecated alias means all three) -----
  reviews_privileged  = var.enable_access_reviews_privileged || var.enable_access_reviews
  reviews_requestable = var.enable_access_reviews_requestable || var.enable_access_reviews
  reviews_inactive    = var.enable_access_reviews_inactive || var.enable_access_reviews
  any_review_flag     = local.reviews_privileged || local.reviews_requestable || local.reviews_inactive

  # Fallback reviewers: the dedicated group if given, else the approver group
  # (the people who grant access are a sensible second line to re-certify it).
  review_fallback_group_object_id = (
    var.access_review_fallback_group_object_id != ""
    ? var.access_review_fallback_group_object_id
    : var.approver_group_object_id
  )

  # Who reviews privileged access: a dedicated governance group if given,
  # else the fallback group. Never the requestor's manager, never the admins.
  privileged_reviewer_group_object_id = (
    var.privileged_review_reviewer_group_object_id != ""
    ? var.privileged_review_reviewer_group_object_id
    : local.review_fallback_group_object_id
  )

  # Reviewer user-sets.
  # T1 package: the privileged reviewer group (+ the fallback group as backup
  # when it is a different group), review_type Reviewers.
  t1_reviewers = concat(
    local.privileged_reviewer_group_object_id != "" ? [
      { subject_type = "groupMembers", object_id = local.privileged_reviewer_group_object_id, backup = false }
    ] : [],
    local.review_fallback_group_object_id != "" && local.review_fallback_group_object_id != local.privileged_reviewer_group_object_id ? [
      { subject_type = "groupMembers", object_id = local.review_fallback_group_object_id, backup = true }
    ] : [],
  )
  # T2 package (see var.access_review_reviewer_type):
  #   Manager   -> [fallback group (backup)]                    + review_type Manager
  #   Reviewers -> [requestorManager, fallback group (backup)]  + review_type Reviewers
  t2_reviewers = concat(
    var.access_review_reviewer_type == "Reviewers" ? [
      { subject_type = "requestorManager", object_id = null, backup = false }
    ] : [],
    local.review_fallback_group_object_id != "" ? [
      { subject_type = "groupMembers", object_id = local.review_fallback_group_object_id, backup = true }
    ] : [],
  )

  # Per request package: does a policy review apply, and how. Unanswered is
  # ALWAYS removeAccess here (T1 and T2 per ADR 0012); T3 packages have no
  # Terraform policy, so no setting anywhere can review or remove them.
  package_review = {
    for k, p in local.request_packages : k => {
      tier = p.tier
      enabled = (
        p.tier == "T1"
        ? local.reviews_privileged
        : local.reviews_requestable && (local.package_duration_days[k] > local.t2_expiry_certifies_days || p.extension_enabled)
      )
      frequency   = p.tier == "T1" ? var.access_review_frequency : var.requestable_review_frequency
      review_type = p.tier == "T1" ? "Reviewers" : var.access_review_reviewer_type
      reviewers   = p.tier == "T1" ? local.t1_reviewers : local.t2_reviewers
      reason = (
        p.tier == "T1" ? "T1 privileged: quarterly, governance group, unanswered = removed"
        : (local.package_duration_days[k] > local.t2_expiry_certifies_days || p.extension_enabled)
        ? "T2 that outlives 180 days or allows extension: half-yearly, manager, unanswered = removed"
        : "T2 within 180 days, no extension: the expiry + re-approval is the certification (no campaign)"
      )
    }
  }

  # Upper bound for duration_in_days per frequency: an instance must close
  # before the next one opens (monthly uses 28 to be safe in February).
  review_period_days = {
    weekly     = 7
    monthly    = 28
    quarterly  = 90
    halfyearly = 180
    annual     = 365
  }
}

# The old single switch (var.enable_access_reviews) is only an alias for the
# three flags now. Deliberately NOT a check block: `terraform test` fails a run
# on a failing check, and envs/dev's mock tests still pass the alias until
# envs/dev is rewired to the three flags (then add the check here).

resource "azuread_access_package_resource_catalog_association" "groups" {
  for_each = local.catalog_group_keys

  catalog_id             = azuread_access_package_catalog.clinical.id
  resource_origin_id     = var.catalog_group_object_ids[each.value]
  resource_origin_system = "AadGroup"
}

# -----------------------------------------------------------------------------
# Access packages (automatic and request alike).
# -----------------------------------------------------------------------------
resource "azuread_access_package" "this" {
  for_each = var.access_packages

  catalog_id   = azuread_access_package_catalog.clinical.id
  display_name = each.value.display_name
  description  = each.value.description
  hidden       = false
}

# Attach each group to its package as a Member grant. An assignment (automatic
# or approved) therefore adds the user to every group in the package.
resource "azuread_access_package_resource_package_association" "groups" {
  for_each = local.package_group_pairs

  access_package_id               = azuread_access_package.this[each.value.package].id
  catalog_resource_association_id = azuread_access_package_resource_catalog_association.groups[each.value.group].id
  access_type                     = "Member"
}

# -----------------------------------------------------------------------------
# REQUEST policy per request package (T1/T2): who can request, approval,
# expiry, extension. Automatic (T3) packages are deliberately absent.
# Admin direct assignment (adminAdd) is allowed by entitlement management on
# top of the requestor settings, on these policies only.
# -----------------------------------------------------------------------------
resource "azuread_access_package_assignment_policy" "this" {
  for_each = local.request_packages

  access_package_id = azuread_access_package.this[each.key].id
  # "<package> - <N> day": 02-Joiner.ps1 / New-LifecycleWorkflows.ps1 match it.
  display_name = "${each.value.display_name} - ${local.package_duration_days[each.key]} day"
  description  = "Request (ADR 0012 ${each.value.tier}): approval required; expires after ${local.package_duration_days[each.key]} days. ${each.value.extension_enabled ? "Extension goes through the same approval again." : "No extension: request again to keep it."}"

  duration_in_days = local.package_duration_days[each.key]

  # Extending before expiry is opt-in per package and always re-approved
  # (approval_required_for_extension below) - never a silent renewal.
  extension_enabled = each.value.extension_enabled

  # Who may request. AllExistingDirectoryMemberUsers = any internal member user.
  requestor_settings {
    requests_accepted = true
    scope_type        = "AllExistingDirectoryMemberUsers"
  }

  # Approval + justification.
  approval_settings {
    approval_required                = var.approval_required
    approval_required_for_extension  = each.value.extension_enabled
    requestor_justification_required = var.requestor_justification_required

    dynamic "approval_stage" {
      for_each = var.approval_required ? [1] : []
      content {
        approval_timeout_in_days        = var.approval_timeout_days
        approver_justification_required = true

        primary_approver {
          # Group of approvers when provided...
          subject_type = local.use_group_approver ? "groupMembers" : "requestorManager"
          object_id    = local.use_group_approver ? var.approver_group_object_id : null
          # ...otherwise the requestor's manager (set by HR provisioning).
          backup = false
        }
      }
    }
  }

  # ---------------------------------------------------------------------------
  # Policy review, per ADR 0012 tier (local.package_review). Renders NOTHING
  # unless the package's tier flag is on AND the tier rule asks for one, so a
  # default plan carries no review block at all.
  #
  # Each setting as it appears on the policy's Lifecycle tab:
  #   review_frequency / duration_in_days - Review frequency + Duration
  #   review_type + reviewer blocks       - Reviewers (+ fallback)
  #   access_review_timeout_behavior      - "If reviewers don't respond" = Remove access
  #   access_recommendation_enabled       - "Show reviewer decision helpers"
  #   approver_justification_required     - "Require reviewer justification"
  #
  # Decisions: entitlement management APPLIES review results itself when each
  # instance closes (end of duration, or an admin stops it early) - a denied
  # user is removed from the package then, not at the moment of the click.
  # Policy-attached reviews have no separate "auto-apply" switch in the
  # provider or in Graph (unlike standalone accessReviewScheduleDefinitions).
  #
  # verify: the provider sends the Graph BETA assignmentReviewSettings shape,
  # whose documented `reviewers` collection applies to reviewerType=Reviewers.
  # Whether the service keeps a backup reviewer under reviewerType=Manager is
  # not documented. Post-apply check (read-only):
  #   GET https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/{id}
  #   -> reviewSettings.primaryReviewers / fallbackReviewers.
  # If fallbackReviewers comes back empty, set access_review_reviewer_type =
  # "Reviewers" (requestorManager primary + backup group) and re-apply.
  # Symptom of a dropped reviewer: every later plan shows an in-place update
  # adding the reviewer block back (state has none, config has one).
  # verify: the portal's fallback-reviewer picker selects USERS; that a GROUP
  # (groupMembers) is accepted as the fallback is also unconfirmed. If it is
  # rejected, use a single named user id as the fallback instead.
  # ---------------------------------------------------------------------------
  dynamic "assignment_review_settings" {
    for_each = local.package_review[each.key].enabled ? [1] : []
    content {
      enabled          = true
      review_frequency = local.package_review[each.key].frequency
      duration_in_days = var.access_review_duration_days
      review_type      = local.package_review[each.key].review_type
      # ADR 0012: T1 and T2 - unanswered = removed. Not an input.
      access_review_timeout_behavior = "removeAccess"
      # null = the service starts the series now; immutable once created.
      starting_on = var.access_review_start_date != "" ? var.access_review_start_date : null

      # Decision helpers (approve if signed in within 30 days, else deny) and a
      # mandatory written reason - both end up in the evidence pack.
      access_recommendation_enabled   = true
      approver_justification_required = true

      dynamic "reviewer" {
        for_each = local.package_review[each.key].reviewers
        content {
          subject_type = reviewer.value.subject_type
          object_id    = reviewer.value.object_id
          backup       = reviewer.value.backup
        }
      }
    }
  }

  lifecycle {
    # Fail at PLAN, not halfway through an apply.
    precondition {
      condition     = !local.package_review[each.key].enabled || var.access_review_duration_days < local.review_period_days[local.package_review[each.key].frequency]
      error_message = "access_review_duration_days must be shorter than the review interval (${local.package_review[each.key].frequency} = ${local.review_period_days[local.package_review[each.key].frequency]} days)."
    }
    precondition {
      condition     = !local.package_review[each.key].enabled || length(local.package_review[each.key].reviewers) > 0
      error_message = "Access package '${each.key}' would get a review with no reviewer group: set access_review_fallback_group_object_id (and privileged_review_reviewer_group_object_id for T1)."
    }
    precondition {
      # "Re-approval" is the point of a T2 extension; without approval an
      # extension is a silent renewal.
      condition     = !each.value.extension_enabled || var.approval_required
      error_message = "Access package '${each.key}' allows extension but approval_required = false: an extension must be re-approved (ADR 0012)."
    }
    precondition {
      condition     = each.value.tier != "T1" || var.approval_required
      error_message = "Access package '${each.key}' is T1 (privileged): approval_required must stay true."
    }
  }
}
