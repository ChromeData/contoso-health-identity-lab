# =============================================================================
# modules/entitlement :: outputs.tf
# =============================================================================

output "catalog_id" {
  description = "Id of the Clinical catalog."
  value       = azuread_access_package_catalog.clinical.id
}

output "access_package_ids" {
  description = "Map of package key => access package id (automatic and request packages)."
  value       = { for k, p in azuread_access_package.this : k => p.id }
}

output "assignment_policy_ids" {
  description = "Map of package key => REQUEST assignment policy id, for request (T1/T2) packages only. Automatic (T3) packages have no Terraform policy: their automatic assignment policy comes from post-apply/Set-AutoAssignmentPolicies.ps1."
  value       = { for k, p in azuread_access_package_assignment_policy.this : k => p.id }
}

# ADR 0012 in one place: what each package is, how people get it, how long it
# lasts and how it is certified. For the evidence pack and the docs; the
# tftest checks the defaults against lab/iga/access-catalog.json.
output "package_assignment_model" {
  description = "Per package key: display_name, tier (T1/T2/T3), assignment (automatic/request), expires_after_days (null = never: automatic), extension_enabled, request_policy (whether Terraform creates one) and certification (how it is re-certified; policy_review is null when no campaign applies)."
  value = {
    for k, p in var.access_packages : k => {
      display_name       = p.display_name
      tier               = p.tier
      assignment         = p.assignment
      expires_after_days = p.assignment == "request" ? local.package_duration_days[k] : null
      extension_enabled  = p.assignment == "request" ? p.extension_enabled : false
      request_policy     = p.assignment == "request"
      certification = (
        p.assignment == "automatic"
        ? "T3 birthright: HR attributes via the automatic assignment policy (Set-AutoAssignmentPolicies.ps1); never reviewed by a person, never removed by reviewer silence"
        : local.package_review[k].reason
      )
      policy_review = p.assignment == "request" && local.package_review[k].enabled ? {
        frequency          = local.package_review[k].frequency
        review_type        = local.package_review[k].review_type
        no_response_action = "removeAccess"
      } : null
    }
  }
}

output "birthright_package_names" {
  description = "Display names of the automatic (T3) packages, sorted. Each needs exactly one automatic assignment policy from post-apply/Set-AutoAssignmentPolicies.ps1 (lab/iga/birthright-rules.json) - until that runs, nobody holds them."
  value       = sort([for p in values(local.automatic_packages) : p.display_name])
}

output "sod_incompatible_package_id_pairs" {
  description = "LEGACY package-id pairs (var.sod_incompatible_pairs), kept for envs/dev. Separation of duties is applied from lab/iga/sod-rules.json by post-apply/Set-IncompatibleAccessPackages.ps1 (Set-AccessPackageSoD.ps1 is a deprecation shim for it), with links only on the requestable side of each pair."
  value = [
    for pair in var.sod_incompatible_pairs :
    [azuread_access_package.this[pair[0]].id, azuread_access_package.this[pair[1]].id]
  ]

  precondition {
    condition     = alltrue([for pair in var.sod_incompatible_pairs : alltrue([for key in pair : contains(keys(var.access_packages), key)])])
    error_message = "Every sod_incompatible_pairs key must be an access_packages key."
  }
  precondition {
    # A link can only sit on a requestable package (ADR 0012), so a pair of
    # two birthright packages could never be enforced - say so instead of
    # pretending.
    condition = alltrue([for pair in var.sod_incompatible_pairs :
      anytrue([for key in pair : try(var.access_packages[key].assignment == "request", false)])
    ])
    error_message = "Every sod_incompatible_pairs entry must name at least one request (T1/T2) package: incompatibility links are never put on a birthright package, so a pair of two automatic packages cannot be enforced (detective only: 09-SoD-Report.ps1)."
  }
}

# Effective access-review configuration, or null while every review flag is
# off. Use it to cross-check the post-apply Graph read described in main.tf
# (reviewSettings on each policy id) and to quote the control in the evidence
# pack.
output "access_review_settings" {
  description = "Risk-tiered review configuration (ADR 0012): the three flags, duration, reviewers, and the per-package policy reviews actually attached (tier, frequency, review type, policy id; unanswered = removeAccess). null when every review flag is off."
  value = local.any_review_flag ? {
    privileged_enabled           = local.reviews_privileged
    requestable_enabled          = local.reviews_requestable
    inactive_enabled             = local.reviews_inactive
    duration_in_days             = var.access_review_duration_days
    fallback_group_object_id     = local.review_fallback_group_object_id
    privileged_reviewer_group_id = local.privileged_reviewer_group_object_id
    package_reviews = {
      for k, r in local.package_review : k => {
        tier               = r.tier
        frequency          = r.frequency
        review_type        = r.review_type
        no_response_action = "removeAccess"
        policy_id          = azuread_access_package_assignment_policy.this[k].id
      } if r.enabled
    }
    birthright_packages_never_reviewed = sort([for p in values(local.automatic_packages) : p.display_name])
  } : null
}

# ---- Standalone access reviews (reviews.tf) ---------------------------------

# Graph v1.0 accessReviewScheduleDefinition request bodies, keyed
# "privileged:<group>" / "inactive:<group>" / the pim_eligible_review_bodies
# keys. {} while the review flags are off. Consumed by
# post-apply/New-AccessReviewDefinitions.ps1:
#   terraform output -json access_review_definitions
# The preconditions fail the APPLY (outputs are evaluated after resources) if
# a rendered review could not work - better than a review nobody can finish.
output "access_review_definitions" {
  description = "Map of review key => JSON body for POST /identityGovernance/accessReviews/definitions: T1 privileged PIM-group reviews + pim_eligible_review_bodies (enable_access_reviews_privileged) and inactive-user reviews (enable_access_reviews_inactive). Empty while those flags are off."
  value       = local.access_review_definitions

  precondition {
    condition     = length(local.access_review_definitions) == 0 || (local.privileged_reviewer_group_object_id != "" && local.review_fallback_group_object_id != "")
    error_message = "Standalone access reviews need a reviewer and a fallback group: set access_review_fallback_group_object_id (or approver_group_object_id)."
  }
  precondition {
    # No self-certification: the people being reviewed must not be the
    # people deciding.
    condition     = !contains(values(var.privileged_review_group_object_ids), local.privileged_reviewer_group_object_id)
    error_message = "The privileged-access reviewer group must not be one of the groups it reviews."
  }
  precondition {
    condition = length(local.access_review_definitions) == 0 || (
      var.access_review_duration_days < local.review_period_days[var.privileged_review_frequency] &&
      var.access_review_duration_days < local.review_period_days[var.inactive_review_frequency]
    )
    error_message = "access_review_duration_days must be shorter than both privileged_review_frequency and inactive_review_frequency intervals."
  }
  precondition {
    # ADR 0012: Break-Glass-Admins is never in a default-deny review.
    condition = (
      !anytrue([for n in local.review_target_names : can(regex("(?i)break[-_ ]?glass", n))]) &&
      (var.break_glass_group_object_id == "" || !contains([for id in local.review_target_ids : lower(id)], lower(var.break_glass_group_object_id))) &&
      (var.break_glass_group_object_id == "" || !anytrue([for b in values(local.privileged_definitions) : strcontains(lower(b), lower(var.break_glass_group_object_id))]))
    )
    error_message = "A standalone review targets the break-glass group. ADR 0012 keeps Break-Glass-Admins out of every default-deny review (silence would remove the recovery path); the 90-day drill (Invoke-BreakGlassDrill.ps1) checks it instead."
  }
  precondition {
    # The post-apply script matches existing series by displayName: two
    # bodies with one name would create one series and report the other as
    # drift. (Unknown at a first plan with new groups; checked at apply.)
    condition     = length(distinct([for b in values(local.access_review_definitions) : jsondecode(b).displayName])) == length(local.access_review_definitions)
    error_message = "Two access review definitions share a displayName (reviews.tf and pim_eligible_review_bodies under different keys?). Give each series one key."
  }
}

# ---- B2B guest governance (b2b.tf) -------------------------------------------

output "b2b_catalog_id" {
  description = "Id of the externally visible Affiliated Partners catalog, or null when enable_b2b_governance = false."
  value       = one(azuread_access_package_catalog.b2b[*].id)
}

output "b2b_access_package_id" {
  description = "Id of the Affiliated Physicians access package (share its My Access link with the clinic), or null."
  value       = one(azuread_access_package.b2b[*].id)
}

output "b2b_assignment_policy_id" {
  description = "Id of the connected-org guest policy, or null."
  value       = one(azuread_access_package_assignment_policy.b2b[*].id)
}

output "b2b_access_group_object_id" {
  description = "Ext-Affiliated-Physicians group (assign to the guest-facing apps), or null."
  value       = one(azuread_group.b2b_access[*].object_id)
}

output "b2b_sponsor_group_object_id" {
  description = "B2B-Sponsors-MedicalStaffOffice group (fallback approvers + reviewers; add members post-apply), or null."
  value       = one(azuread_group.b2b_sponsors[*].object_id)
}

# Everything the provider cannot create, as ready-to-POST Graph bodies.
# Consumed by post-apply/New-B2BConnectedOrganization.ps1 (README.md).
output "b2b_post_apply" {
  description = "Inputs for the B2B post-apply step: connectedOrganization body (state configured), internal sponsor group, and the tenant external-user lifecycle settings body. null when enable_b2b_governance = false."
  value = local.b2b_enabled ? {
    # POST /identityGovernance/entitlementManagement/connectedOrganizations
    # state = configured: only configured orgs satisfy the policy's
    # AllConfiguredConnectedOrganizationSubjects scope.
    connected_organization_body = jsonencode({
      displayName     = var.b2b_connected_organization.display_name
      description     = "Affiliated clinic whose physicians may request ${var.b2b_access_package_name}. Managed via modules/entitlement (b2b.tf)."
      identitySources = [jsondecode(local.b2b_identity_source_json)]
      state           = "configured"
    })
    # POST .../connectedOrganizations/{id}/internalSponsors/$ref
    internal_sponsor_group_object_id = azuread_group.b2b_sponsors[0].object_id
    # PATCH /identityGovernance/entitlementManagement/settings (tenant-wide).
    entitlement_settings_body = jsonencode({
      externalUserLifecycleAction                  = "blockSignInAndDelete"
      durationUntilExternalUserDeletedAfterBlocked = "P${var.b2b_guest_deletion_after_block_days}D"
    })
    access_package_id    = azuread_access_package.b2b[0].id
    assignment_policy_id = azuread_access_package_assignment_policy.b2b[0].id
    requestor_scope      = local.b2b_scope_type
  } : null
}
