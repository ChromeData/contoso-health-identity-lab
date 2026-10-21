# =============================================================================
# modules/entitlement :: b2b.tf
# -----------------------------------------------------------------------------
# B2B GUEST GOVERNANCE (var.enable_b2b_governance, default false).
#
# Scenario: physicians at an affiliated clinic need time-boxed access to
# Contoso Health's clinical portal. Inviting them ad hoc is how guest sprawl
# starts (nobody owns the invitation, nothing expires). Instead:
#
#   connected organization  "<affiliated clinic>"  (post-apply, see below)
#        |  its users may REQUEST - nobody is invited by hand
#        v
#   catalog "Affiliated Partners"   externally_visible = true  (this catalog
#        |                          only; "Clinical" stays internal)
#        v
#   package "Affiliated Physicians" -> group Ext-Affiliated-Physicians
#        policy: connected-org requestors only, justification + a required
#        credentialing question, SPONSOR approval (internal sponsors of the
#        connected org, Medical Staff Office group as fallback), 90-day
#        expiry, extension needs re-approval, MONTHLY sponsor review where
#        no answer = access removed.
#
# The guest account is created by entitlement management on first approval
# and - with the tenant lifecycle setting in README.md applied - blocked and
# then deleted when its last assignment ends. So the guest lifecycle is
# joiner (request) -> mover (extension, re-approved) -> leaver (expiry or
# review), with no manual invite anywhere.
#
# PROVIDER GAPS (verified against the azuread 3.10 schema):
#   * no connectedOrganization resource, and
#   * no entitlementManagementSettings resource (external user lifecycle).
# Both are rendered as Graph request bodies (output b2b_post_apply) for
# lab/scripts/powershell/post-apply/New-B2BConnectedOrganization.ps1 (spec in
# README.md). The policy below works before the connected org exists: with
# AllConfiguredConnectedOrganizationSubjects it simply has no eligible
# requestors until one is "configured".
#
# LICENSING: Entra ID Governance for the package and review; B2B guests are
# billed on monthly active users (first 50,000 MAU free - verify: External ID
# pricing page; the tenant must be linked to a subscription for MAU billing).
# =============================================================================

locals {
  b2b_enabled = var.enable_b2b_governance

  # Specific connected org once its id is known (narrowest scope), otherwise
  # every connected org in state "configured" - never "proposed" ones, which
  # the service auto-creates when a stranger requests a package.
  b2b_scope_type = (
    var.b2b_connected_organization_id != ""
    ? "SpecificConnectedOrganizationSubjects"
    : "AllConfiguredConnectedOrganizationSubjects"
  )

  # Approval stages, in order. Stage 1 (optional): the clinic's own external
  # sponsor vouches for the requestor. Final stage (always): Contoso's
  # internal sponsor, i.e. the people accountable for the relationship.
  b2b_approval_stages = concat(
    var.b2b_require_external_sponsor_approval ? ["ExternalSponsors"] : [],
    ["InternalSponsors"],
  )

  # Encoded per branch: the two identity-source shapes differ, so a plain
  # conditional between two objects would be a type error.
  b2b_identity_source_json = (
    var.b2b_connected_organization.tenant_id != ""
    ? jsonencode({
      "@odata.type" = "#microsoft.graph.azureActiveDirectoryTenant"
      displayName   = var.b2b_connected_organization.display_name
      tenantId      = var.b2b_connected_organization.tenant_id
    })
    : jsonencode({
      "@odata.type" = "#microsoft.graph.domainIdentitySource"
      displayName   = var.b2b_connected_organization.domain_name
      domainName    = var.b2b_connected_organization.domain_name
    })
  )
}

# -----------------------------------------------------------------------------
# Groups (module-local: nothing outside B2B governance uses them).
# -----------------------------------------------------------------------------

# What the package grants. Assign this group to the clinical-portal enterprise
# app; never add it to an internal package or a CA exclusion.
resource "azuread_group" "b2b_access" {
  count = local.b2b_enabled ? 1 : 0

  display_name     = var.b2b_access_group_name
  mail_nickname    = "ext-affiliated-physicians"
  description      = "Granted ONLY by the Affiliated Physicians access package (90-day, sponsor-approved). Do not add members by hand."
  security_enabled = true
  mail_enabled     = false

  # Membership is owned by entitlement management.
  lifecycle {
    ignore_changes = [members]
  }
}

# Medical Staff Office: fallback approvers when a connected org has no
# internal sponsor, and the monthly reviewers of guest access. Members are
# real people (operational data) - set post-apply, so Terraform ignores them.
# An EMPTY group fails safe: requests time out (denied), reviews time out
# (removed).
resource "azuread_group" "b2b_sponsors" {
  count = local.b2b_enabled ? 1 : 0

  display_name     = var.b2b_sponsor_group_name
  mail_nickname    = "b2b-sponsors-medicalstaffoffice"
  description      = "Internal sponsors for affiliated-clinic guests: fallback approvers + monthly reviewers of the Affiliated Physicians package."
  security_enabled = true
  mail_enabled     = false

  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# Catalog: the ONLY externally visible catalog in the tenant.
# -----------------------------------------------------------------------------
resource "azuread_access_package_catalog" "b2b" {
  count = local.b2b_enabled ? 1 : 0

  display_name = var.b2b_catalog_name
  description  = "Externally requestable access for connected (affiliated) organizations. Guest-facing packages only."

  # Required for any package in it to accept requestors from outside the
  # tenant ("Enabled for external users" in the portal).
  externally_visible = true
  published          = true
}

resource "azuread_access_package_resource_catalog_association" "b2b" {
  count = local.b2b_enabled ? 1 : 0

  catalog_id             = azuread_access_package_catalog.b2b[0].id
  resource_origin_id     = azuread_group.b2b_access[0].object_id
  resource_origin_system = "AadGroup"
}

resource "azuread_access_package" "b2b" {
  count = local.b2b_enabled ? 1 : 0

  catalog_id   = azuread_access_package_catalog.b2b[0].id
  display_name = var.b2b_access_package_name
  description  = "Time-boxed clinical-portal access for physicians of affiliated clinics. Sponsor-approved, ${var.b2b_assignment_duration_days}-day expiry, monthly sponsor review."
  hidden       = false
}

resource "azuread_access_package_resource_package_association" "b2b" {
  count = local.b2b_enabled ? 1 : 0

  access_package_id               = azuread_access_package.b2b[0].id
  catalog_resource_association_id = azuread_access_package_resource_catalog_association.b2b[0].id
  access_type                     = "Member"
}

# -----------------------------------------------------------------------------
# The guest policy.
# -----------------------------------------------------------------------------
resource "azuread_access_package_assignment_policy" "b2b" {
  count = local.b2b_enabled ? 1 : 0

  access_package_id = azuread_access_package.b2b[0].id
  display_name      = "${var.b2b_access_package_name} - connected orgs - ${var.b2b_assignment_duration_days} day"
  description       = "Connected-organization users only; sponsor approval; expires after ${var.b2b_assignment_duration_days} days; monthly sponsor review."

  # Hard expiry: a guest never holds clinical access longer than this without
  # a fresh, approved extension.
  duration_in_days = var.b2b_assignment_duration_days

  # Guests get the 14-day / 1-day expiry email and can ask to extend; the
  # extension goes through the SAME approval stages again.
  extension_enabled = true

  requestor_settings {
    requests_accepted = true
    scope_type        = local.b2b_scope_type

    dynamic "requestor" {
      for_each = var.b2b_connected_organization_id != "" ? [var.b2b_connected_organization_id] : []
      content {
        subject_type = "ConnectedOrganizationMembers"
        object_id    = requestor.value
      }
    }
  }

  approval_settings {
    approval_required                = true
    approval_required_for_extension  = true
    requestor_justification_required = true

    dynamic "approval_stage" {
      for_each = local.b2b_approval_stages
      content {
        approval_timeout_in_days        = var.b2b_approval_timeout_days
        approver_justification_required = true

        # Sponsors of the requestor's connected organization...
        primary_approver {
          subject_type = approval_stage.value
          backup       = false
        }

        # ...and the Medical Staff Office as FALLBACK when the connected org
        # has no sponsor of that kind (the portal makes a fallback mandatory
        # for sponsor approvers).
        primary_approver {
          subject_type = "GroupMembers"
          object_id    = azuread_group.b2b_sponsors[0].object_id
          backup       = true
        }
      }
    }
  }

  # Monthly re-certification by the Medical Staff Office. With a 90-day hard
  # expiry, a quarterly review would rarely fire; monthly catches the
  # physician who left the clinic in week two. Unanswered = removed.
  assignment_review_settings {
    enabled                         = true
    review_frequency                = var.b2b_review_frequency
    duration_in_days                = var.b2b_review_duration_days
    review_type                     = "Reviewers"
    access_review_timeout_behavior  = "removeAccess"
    access_recommendation_enabled   = true
    approver_justification_required = true
    starting_on                     = var.access_review_start_date != "" ? var.access_review_start_date : null

    reviewer {
      subject_type = "GroupMembers"
      object_id    = azuread_group.b2b_sponsors[0].object_id
      backup       = false
    }
  }

  # Captured on the request and shown to approvers: who is this physician and
  # where is their credentialing record? Approvers should never approve a
  # name they cannot tie to a credentialing file.
  question {
    required = true
    sequence = 1

    text {
      default_text = "Medical Staff Office credentialing reference and your supervising physician at the affiliated clinic"
    }
  }

  lifecycle {
    precondition {
      condition     = var.b2b_review_duration_days < local.review_period_days[var.b2b_review_frequency]
      error_message = "b2b_review_duration_days must be shorter than the review interval (${var.b2b_review_frequency} = ${local.review_period_days[var.b2b_review_frequency]} days)."
    }
  }
}
