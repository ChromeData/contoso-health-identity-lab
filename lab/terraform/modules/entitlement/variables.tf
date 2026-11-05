# =============================================================================
# modules/entitlement :: variables.tf
# =============================================================================

variable "catalog_name" {
  type        = string
  description = "Access package catalog display name (contract: Clinical)."
  default     = "Clinical"
}

variable "catalog_description" {
  type        = string
  description = "Catalog description."
  default     = "Clinical application access packages for Contoso Health."
}

variable "catalog_group_object_ids" {
  type        = map(string)
  description = <<-EOT
    Map of group key => object id of the ASSIGNED groups packages may grant
    (servicenow/aws/okta/icu_critical_care/pharmacy_dispensing). Dynamic groups
    must not appear here - entitlement management cannot grant them.
  EOT
}

variable "access_packages" {
  type = map(object({
    display_name = string
    description  = string
    group_keys   = list(string) # keys into catalog_group_object_ids
    # ADR 0012 tier: T1 privileged, T2 requestable, T3 birthright clinical.
    tier = string
    # How people get it:
    #   automatic - HR attributes, through the automatic assignment policy that
    #               post-apply/Set-AutoAssignmentPolicies.ps1 creates from
    #               lab/iga/birthright-rules.json. Terraform creates NO policy
    #               for it: no request path, no expiry, no review (T3 only).
    #   request   - a person asks and an approver grants; Terraform creates the
    #               assignment policy with an expiry (T1 / T2 only).
    assignment = string
    # request only: lifetime in days (null = assignment_duration_days).
    duration_in_days = optional(number)
    # request only: allow "extend" before expiry. An extension always goes
    # through the same approval again (approval_required_for_extension), and a
    # T2 package that allows it gets a half-yearly policy review (ADR 0012).
    extension_enabled = optional(bool, false)
  }))
  description = <<-EOT
    Access packages in the Clinical catalog, keyed by a short stable id. Each
    carries its ADR 0012 tier and assignment model. The defaults mirror
    lab/iga/access-catalog.json (tests/governance.tftest.hcl checks that):
      nurse     T3 automatic  birthright for nursing staff
      icu       T3 automatic  birthright for ICU staff (the mover target)
      cloud_engineering
                T3 automatic  birthright for cloud engineers (ServiceNow + AWS)
      icu_float T2 request    ICU apps for float / agency nurses: the
                              requestable side, so SoD links can sit on it
      pharmacy  T2 request    controlled-substance dispensing
  EOT
  default = {
    nurse = {
      display_name = "Nurse - Clinical Apps"
      description  = "Clinical apps for nursing staff (ServiceNow). Assigned automatically from your HR department and job title; nothing to request."
      group_keys   = ["servicenow"]
      tier         = "T3"
      assignment   = "automatic"
    }
    icu = {
      display_name = "ICU - Critical Care Apps"
      description  = "Critical-care apps for ICU staff. Assigned automatically from your HR department and job title; float and agency nurses request ICU - Float Access instead."
      group_keys   = ["servicenow", "icu_critical_care"]
      tier         = "T3"
      assignment   = "automatic"
    }
    # Cloud engineers run the hospital's patient portal in AWS, so AWS is
    # their birthright - not the nurses'.
    cloud_engineering = {
      display_name = "IT - Cloud Engineering Apps"
      description  = "ServiceNow + AWS for cloud engineers, who run the patient portal in AWS. Assigned automatically from your HR department and job title; nothing to request."
      group_keys   = ["servicenow", "aws"]
      tier         = "T3"
      assignment   = "automatic"
    }
    icu_float = {
      display_name = "ICU - Float Access"
      description  = "ICU critical-care apps for float and agency nurses covering ICU shifts. Manager approval; expires after 180 days (request again to keep it). Cannot be held with Pharmacy - Controlled Substances Apps."
      group_keys   = ["servicenow", "icu_critical_care"]
      tier         = "T2"
      assignment   = "request"
    }
    pharmacy = {
      display_name = "Pharmacy - Controlled Substances Apps"
      description  = "Controlled-substance dispensing. SoD: must NOT be held with Nurse - Clinical Apps."
      group_keys   = ["pharmacy_dispensing"]
      tier         = "T2"
      assignment   = "request"
    }
  }

  validation {
    condition     = alltrue([for p in values(var.access_packages) : contains(["T1", "T2", "T3"], p.tier) && contains(["automatic", "request"], p.assignment)])
    error_message = "Every access package needs tier T1, T2 or T3 and assignment automatic or request (ADR 0012)."
  }
  validation {
    # Birthright is exactly "T3 + automatic". Privileged (T1) and discretionary
    # (T2) access is never handed out by an HR attribute, and T3 access is
    # never requested (a request policy brings back the day-180 lockout).
    condition     = alltrue([for p in values(var.access_packages) : (p.tier == "T3") == (p.assignment == "automatic")])
    error_message = "tier T3 and assignment automatic go together: a T3 (birthright) package must be automatic, and an automatic package must be T3 (ADR 0012)."
  }
  validation {
    condition = alltrue([for p in values(var.access_packages) :
      p.assignment == "request" || (p.duration_in_days == null && !p.extension_enabled)
    ])
    error_message = "duration_in_days and extension_enabled apply to request packages only: an automatic (birthright) package has no expiry and nothing to extend."
  }
  validation {
    condition = alltrue([for p in values(var.access_packages) :
      p.duration_in_days == null || try(p.duration_in_days >= 1 && p.duration_in_days <= 3660 && p.duration_in_days == floor(p.duration_in_days), false)
    ])
    error_message = "duration_in_days must be a whole number between 1 and 3660 (or null for assignment_duration_days)."
  }
  validation {
    condition     = length(distinct([for p in values(var.access_packages) : lower(p.display_name)])) == length(var.access_packages)
    error_message = "Access package display names must be unique: the post-apply scripts and lab/iga/*.json find packages by display name."
  }
  validation {
    condition     = alltrue([for p in values(var.access_packages) : length(p.group_keys) > 0])
    error_message = "Every access package must grant at least one group."
  }
}

variable "sod_incompatible_pairs" {
  type        = list(list(string))
  description = <<-EOT
    LEGACY. Kept so envs/dev's sod_incompatible_package_id_pairs output still
    resolves. The source of truth for separation of duties is
    lab/iga/sod-rules.json (SOD-01..09). SOD-01 supersedes this pair and adds
    ICU and ICU - Float Access; post-apply/Set-IncompatibleAccessPackages.ps1
    applies it. That script writes a link only ON the requestable side of a
    pair, because a link on a birthright package could block its automatic
    assignment (ADR 0012). So every pair here must contain at least one
    request package (precondition on the output). Set-AccessPackageSoD.ps1 is
    now a deprecation shim that runs Set-IncompatibleAccessPackages.ps1.
  EOT
  default     = [["nurse", "pharmacy"]]

  validation {
    condition     = alltrue([for pair in var.sod_incompatible_pairs : length(pair) == 2 && try(pair[0] != pair[1], false)])
    error_message = "Each sod_incompatible_pairs entry must name two different access_packages keys."
  }
}

variable "assignment_duration_days" {
  type        = number
  description = "Default lifetime of a REQUEST (T1/T2) assignment before it expires (contract: 180 days; per-package duration_in_days overrides it). Automatic (T3 birthright) assignments never expire. A T2 package that lives longer than 180 days gets a half-yearly policy review when enable_access_reviews_requestable is on (ADR 0012)."
  default     = 180

  validation {
    condition     = var.assignment_duration_days > 0 && var.assignment_duration_days <= 3660
    error_message = "duration_in_days must be between 1 and 3660."
  }
}

variable "approval_required" {
  type        = bool
  description = "Require approval before an assignment is granted."
  default     = true
}

variable "requestor_justification_required" {
  type        = bool
  description = "Require the requestor to supply a business justification."
  default     = true
}

variable "approval_timeout_days" {
  type        = number
  description = "Days an approval request waits before timing out."
  default     = 14
}

variable "approver_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of a group whose members approve requests. If empty, approval
    falls back to the requestor's MANAGER (subject_type requestorManager),
    which requires each requestor to have a manager set (HR provisioning does).
  EOT
  default     = ""
}

# =============================================================================
# Access reviews, risk-tiered (ADR 0012) - every flag OFF by default
# -----------------------------------------------------------------------------
# One flag per tier, so turning one on can never switch another on:
#
#   enable_access_reviews_privileged   T1  quarterly. reviews.tf renders the
#                                          PIM-group (eligible + active) and
#                                          PIM direct-role reviews: default
#                                          Deny + auto-apply. Also a quarterly
#                                          policy review on any T1 package.
#   enable_access_reviews_requestable  T2  certified by the 180-day expiry +
#                                          re-request / re-approval. A
#                                          half-yearly removeAccess policy
#                                          review ONLY on a T2 package that
#                                          lives longer than 180 days or
#                                          allows extension.
#   enable_access_reviews_inactive     --  inactive-user (stale account)
#                                          reviews, reviews.tf.
#   (none)                             T3  birthright clinical: never reviewed
#                                          by a person. HR attributes certify
#                                          it; silence never removes it.
#
# They create real, recurring campaigns that email reviewers (Entra ID
# Governance). Leave them off until the Governance trial runs and the HR
# personas exist with managers set.
#
# PROVIDER CAVEAT (azuread 3.10): turning a flag back to false does NOT switch
# a POLICY review off. The provider suppresses the diff when the block is
# removed (assignmentPolicyDiffSuppress), so existing review settings stay on
# the policy. To stop one: Entra admin center -> ID Governance -> Access
# packages -> <package> -> Policies -> <policy> -> Lifecycle -> Require access
# reviews = No. (Standalone reviews are stopped and deleted in the portal.)
# =============================================================================

variable "enable_access_reviews_privileged" {
  type        = bool
  description = "T1 (ADR 0012): render the quarterly privileged reviews (PIM-governed groups, eligible + active, and pim_eligible_review_bodies) with default Deny + auto-apply, and attach a quarterly removeAccess policy review to any T1 package. Never touches a T2 or T3 package."
  default     = false
}

variable "enable_access_reviews_requestable" {
  type        = bool
  description = "T2 (ADR 0012): attach a half-yearly removeAccess policy review to every T2 package that lives longer than 180 days or allows extension. A plain 180-day T2 package needs none: the expiry plus re-approval IS the certification. Never touches a T3 (birthright) package."
  default     = false
}

variable "enable_access_reviews_inactive" {
  type        = bool
  description = "Render the inactive-user (stale account) reviews in reviews.tf for inactive_review_group_object_ids. Default Deny + auto-apply; independent of the tier flags."
  default     = false
}

variable "enable_access_reviews" {
  type        = bool
  description = <<-EOT
    DEPRECATED - use the three flags above. Kept so an existing caller
    (envs/dev) still plans: true is read as all three of
    enable_access_reviews_privileged, _requestable and _inactive. Even then no
    T3 (birthright) package is ever reviewed - the old behaviour, where this one
    switch also put a quarterly removeAccess review on the clinical packages,
    is gone (ADR 0012). Switch callers to the three flags; the alias will then
    be removed.
  EOT
  default     = false
}

variable "requestable_review_frequency" {
  type        = string
  description = "Review cadence for the T2 packages that get a policy review (longer than 180 days or extendable). ADR 0012: half-yearly. Never less often than half-yearly."
  default     = "halfyearly"

  validation {
    condition     = contains(["monthly", "quarterly", "halfyearly"], var.requestable_review_frequency)
    error_message = "requestable_review_frequency must be monthly, quarterly or halfyearly (ADR 0012: at least every 180 days)."
  }
}

variable "access_review_frequency" {
  type        = string
  description = "How often T1 (privileged) PACKAGE policy reviews recur (ADR 0012: quarterly). Never less often than quarterly. T2 uses requestable_review_frequency; T3 is never reviewed by a person."
  default     = "quarterly"

  validation {
    # Exact (case-sensitive) values the azuread provider accepts. The portal
    # only offers monthly / quarterly / bi-annually / annually for
    # access-package reviews; weekly is API-only (verify: before using it).
    condition     = contains(["weekly", "monthly", "quarterly"], var.access_review_frequency)
    error_message = "access_review_frequency must be weekly, monthly or quarterly (ADR 0012: privileged access at least quarterly)."
  }
}

variable "access_review_duration_days" {
  type        = number
  description = <<-EOT
    Days each review instance stays open for decisions. Must be shorter than
    the recurrence interval (checked by a precondition in main.tf, e.g. < 90
    for quarterly). 14 gives managers two working weeks.
  EOT
  default     = 14

  validation {
    condition     = var.access_review_duration_days >= 1 && var.access_review_duration_days == floor(var.access_review_duration_days)
    error_message = "access_review_duration_days must be a whole number of at least 1."
  }
}

variable "access_review_reviewer_type" {
  type        = string
  description = <<-EOT
    T2 package reviews only (T1 package reviews always use the privileged
    reviewer group, review_type Reviewers - never the requestor's manager).
    How "the user's manager reviews, with a fallback" is expressed to the
    provider. azuread 3.10 maps this block to the Graph BETA
    assignmentReviewSettings shape, which has a reviewerType but no explicit
    fallbackReviewers field (that only exists in the v1.0 reviewSettings shape).
      Manager   (default) reviewerType = Manager; the fallback group is sent as
                a reviewer with backup = true.
      Reviewers reviewerType = Reviewers; reviewers = requestorManager
                (primary) + the fallback group (backup = true).
    Use Reviewers only if a real apply shows the service dropping the backup
    reviewer under Manager (see the post-apply check in main.tf).
  EOT
  default     = "Manager"

  validation {
    condition     = contains(["Manager", "Reviewers"], var.access_review_reviewer_type)
    error_message = "access_review_reviewer_type must be Manager or Reviewers (Self-review is deliberately not offered: users do not certify their own clinical access)."
  }
}

variable "access_review_fallback_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of the group whose members review when a user has no manager in
    the directory (the portal makes a fallback MANDATORY for manager reviews),
    and the fallback reviewer of every standalone review. Empty => falls back
    to approver_group_object_id. If both are empty while any review flag is on,
    plan fails with a precondition error rather than creating reviews nobody
    can complete.

    No-response behaviour is not an input any more: ADR 0012 fixes it per
    tier. T1 and T2 = removeAccess (removed when nobody answers); T3 is never
    in a review, so silence can never remove birthright access. (The old
    access_review_no_response_action variable allowed keepAccess on privileged
    access, which ADR 0012 option 2 rejects.)
  EOT
  default     = ""

  validation {
    condition     = var.access_review_fallback_group_object_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.access_review_fallback_group_object_id))
    error_message = "access_review_fallback_group_object_id must be empty or a group object id (GUID)."
  }
}

variable "access_review_start_date" {
  type        = string
  description = <<-EOT
    Optional RFC3339 UTC start of the first review (e.g. "2026-11-02T08:00:00Z").
    Empty = the service starts the series now. The start date cannot be changed
    once a review series exists.
  EOT
  default     = ""

  validation {
    condition     = var.access_review_start_date == "" || can(formatdate("YYYY", var.access_review_start_date))
    error_message = "access_review_start_date must be empty or an RFC3339 timestamp such as 2026-11-02T08:00:00Z."
  }
}

# =============================================================================
# Standalone access reviews (reviews.tf) - privileged bodies rendered only when
# enable_access_reviews_privileged, inactive-user bodies only when
# enable_access_reviews_inactive; created post-apply by
# post-apply/New-AccessReviewDefinitions.ps1.
# =============================================================================

variable "privileged_review_group_object_ids" {
  type        = map(string)
  description = <<-EOT
    PIM-governed admin groups whose ELIGIBLE + active membership is reviewed,
    keyed by group display name (the key becomes the review's displayName, so
    keep it stable). Wire from modules/pim output privileged_review_targets:
    Privileged-IAM-Admins, the PIM tier groups and the Azure-resource eligible
    group. Values may be unknown at plan (new groups) - they only feed the
    rendered JSON.
  EOT
  default     = {}

  validation {
    condition     = alltrue([for id in values(var.privileged_review_group_object_ids) : can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", id))])
    error_message = "privileged_review_group_object_ids values must be group object ids (GUIDs)."
  }
}

variable "privileged_review_reviewer_group_object_id" {
  type        = string
  description = <<-EOT
    Group whose members review privileged access (e.g. a security-governance
    group). Empty => the access-review fallback group. Must NOT be one of the
    reviewed groups (no self-certification of privilege; checked at apply).
  EOT
  default     = ""

  validation {
    condition     = var.privileged_review_reviewer_group_object_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.privileged_review_reviewer_group_object_id))
    error_message = "privileged_review_reviewer_group_object_id must be empty or a group object id (GUID)."
  }
}

variable "privileged_review_frequency" {
  type        = string
  description = "Recurrence of the standalone privileged access review (ADR 0012 T1: quarterly, the usual SOX / HITRUST cadence for admin access). Never less often than quarterly."
  default     = "quarterly"

  validation {
    condition     = contains(["weekly", "monthly", "quarterly"], var.privileged_review_frequency)
    error_message = "privileged_review_frequency must be weekly, monthly or quarterly (ADR 0012: privileged access at least quarterly)."
  }
}

variable "pim_eligible_review_bodies" {
  type        = map(string)
  description = <<-EOT
    Hand-off from modules/pim (output pim_eligible_review_bodies): Graph v1.0
    accessReviewScheduleDefinition bodies (key => JSON string) for privileged
    access the PIM-group reviews above cannot see - the DIRECT role
    eligibility kept for Global Administrator (ADR 0002), scoped with
    /roleManagement/directory/roleEligibilityScheduleInstances or
    /roleManagement/directory/roleDefinitions/<id>. They are merged into
    access_review_definitions ONLY while enable_access_reviews_privileged is
    on, so the one post-apply step (New-AccessReviewDefinitions.ps1) creates
    every T1 review. modules/pim renders the PIM-group reviews too, under the
    same "privileged:<group>" keys and display names as reviews.tf: on a key
    clash the modules/pim body wins, so each series is rendered once. Contract,
    checked here and again by the script: the displayName starts "Privileged
    access review:" (10-Review-KPIs.ps1 files it as T1; the script matches by
    displayName, so display names must be unique - output precondition),
    default decision Deny, auto-apply on, justification required, at least
    one reviewer and one fallback reviewer. Keys must not start "inactive:".
  EOT
  default     = {}

  validation {
    condition     = alltrue([for v in values(var.pim_eligible_review_bodies) : can(jsondecode(v))])
    error_message = "Every pim_eligible_review_bodies value must be a JSON string (the rendered Graph body)."
  }
  validation {
    condition = alltrue([for v in values(var.pim_eligible_review_bodies) :
      try(
        startswith(jsondecode(v).displayName, "Privileged access review:") &&
        jsondecode(v).settings.defaultDecisionEnabled == true &&
        jsondecode(v).settings.defaultDecision == "Deny" &&
        jsondecode(v).settings.autoApplyDecisionsEnabled == true &&
        jsondecode(v).settings.justificationRequiredOnApproval == true &&
        length(jsondecode(v).reviewers) > 0 &&
        length(jsondecode(v).fallbackReviewers) > 0,
      false)
    ])
    error_message = "Every pim_eligible_review_bodies body must follow the T1 contract (ADR 0012): displayName 'Privileged access review: ...', defaultDecisionEnabled true + defaultDecision Deny, autoApplyDecisionsEnabled true, justificationRequiredOnApproval true, at least one reviewer and one fallback reviewer."
  }
  validation {
    condition     = alltrue([for k in keys(var.pim_eligible_review_bodies) : !startswith(k, "inactive:")])
    error_message = "pim_eligible_review_bodies are T1 reviews: keys must not start with 'inactive:' (reserved for the inactive-user reviews)."
  }
}

variable "break_glass_group_object_id" {
  type        = string
  description = <<-EOT
    Break-Glass-Admins group (modules/groups). Used only as a guard: ADR 0012
    keeps break-glass out of every default-deny review (a review that removes
    the recovery path is worse than no review; the 90-day drill checks it
    instead). With it set, the review outputs refuse any standalone review
    that names this group. Empty = only the name check (no review target
    whose key contains "break-glass" / "breakglass").
  EOT
  default     = ""

  validation {
    condition     = var.break_glass_group_object_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.break_glass_group_object_id))
    error_message = "break_glass_group_object_id must be empty or a group object id (GUID)."
  }
}

variable "inactive_review_group_object_ids" {
  type        = map(string)
  description = <<-EOT
    Groups whose INACTIVE members (no sign-in for inactive_review_days) are
    reviewed, keyed by display name. Use groups whose membership is NOT owned
    by an access package (e.g. App-Okta-Federation-Users, the acquired-clinic
    population): removing a member from a package-granted group behind
    entitlement management's back leaves the package assignment orphaned -
    package groups are already covered by the policy review's sign-in-based
    recommendation. Dynamic groups cannot have members removed by a review.
  EOT
  default     = {}

  validation {
    condition     = alltrue([for id in values(var.inactive_review_group_object_ids) : can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", id))])
    error_message = "inactive_review_group_object_ids values must be group object ids (GUIDs)."
  }
}

variable "inactive_review_days" {
  type        = number
  description = "Days without any sign-in that put a member in scope of the inactive-user review (portal allows up to 730). 90 matches the stale-account KPI."
  default     = 90

  validation {
    condition     = var.inactive_review_days >= 1 && var.inactive_review_days <= 730 && var.inactive_review_days == floor(var.inactive_review_days)
    error_message = "inactive_review_days must be a whole number between 1 and 730."
  }
}

variable "inactive_review_frequency" {
  type        = string
  description = "Recurrence of the inactive-user review. Same vocabulary as access_review_frequency."
  default     = "quarterly"

  validation {
    condition     = contains(["weekly", "monthly", "quarterly", "halfyearly", "annual"], var.inactive_review_frequency)
    error_message = "inactive_review_frequency must be one of: weekly, monthly, quarterly, halfyearly, annual."
  }
}

# =============================================================================
# B2B guest governance (b2b.tf) - OPTIONAL, off by default
# =============================================================================

variable "enable_b2b_governance" {
  type        = bool
  description = <<-EOT
    Create the externally visible "Affiliated Partners" catalog and the
    "Affiliated Physicians" guest package (connected-org requestors, sponsor
    approval, 90-day expiry, monthly sponsor review). Needs Entra ID
    Governance. Leave false until the Governance trial runs; then run the
    connected-organization post-apply step (README.md) or the policy has no
    eligible requestors. Switching it back off destroys the package and
    catalog, so guests lose access at once (verify: whether the service
    refuses to delete a package that still has assignments).
  EOT
  default     = false
}

variable "b2b_catalog_name" {
  type        = string
  description = "Display name of the externally visible catalog."
  default     = "Affiliated Partners"
}

variable "b2b_access_package_name" {
  type        = string
  description = "Display name of the guest access package."
  default     = "Affiliated Physicians"
}

variable "b2b_access_group_name" {
  type        = string
  description = "Assigned group the guest package grants (assign it to the apps affiliated physicians use)."
  default     = "Ext-Affiliated-Physicians"
}

variable "b2b_sponsor_group_name" {
  type        = string
  description = "Medical Staff Office group: fallback approvers + monthly reviewers for guest access."
  default     = "B2B-Sponsors-MedicalStaffOffice"
}

variable "b2b_assignment_duration_days" {
  type        = number
  description = "Guest assignment lifetime (contract: 90 days). Capped at 180: longer guest access defeats the point of time-boxing it."
  default     = 90

  validation {
    condition     = var.b2b_assignment_duration_days >= 1 && var.b2b_assignment_duration_days <= 180 && var.b2b_assignment_duration_days == floor(var.b2b_assignment_duration_days)
    error_message = "b2b_assignment_duration_days must be a whole number between 1 and 180."
  }
}

variable "b2b_approval_timeout_days" {
  type        = number
  description = "Days a guest request waits for each approval stage before it is denied."
  default     = 7

  validation {
    condition     = var.b2b_approval_timeout_days >= 1 && var.b2b_approval_timeout_days <= 14
    error_message = "b2b_approval_timeout_days must be between 1 and 14 (the portal's range for approval timeouts)."
  }
}

variable "b2b_require_external_sponsor_approval" {
  type        = bool
  description = <<-EOT
    Add a first approval stage for the clinic's EXTERNAL sponsors (their own
    medical director vouches before Contoso's internal sponsor decides).
    Off by default: external sponsors must already exist as guests in this
    tenant, which the lab has no real clinic to provide.
  EOT
  default     = false
}

variable "b2b_connected_organization_id" {
  type        = string
  description = <<-EOT
    Object id of the connected organization, once the post-apply step has
    created it. Empty => the policy accepts members of ALL connected
    organizations in state "configured" (AllConfiguredConnectedOrganizationSubjects).
    Set it to narrow the policy to that one clinic (SpecificConnectedOrganizationSubjects).
  EOT
  default     = ""

  validation {
    condition     = var.b2b_connected_organization_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.b2b_connected_organization_id))
    error_message = "b2b_connected_organization_id must be empty or a GUID."
  }
}

variable "b2b_connected_organization" {
  type = object({
    display_name = string
    domain_name  = string
    tenant_id    = optional(string, "")
  })
  description = <<-EOT
    The affiliated clinic, rendered into the connectedOrganization request
    body for the post-apply step (no provider resource exists). tenant_id set
    => azureActiveDirectoryTenant identity source (the clinic has Entra ID);
    empty => domainIdentitySource on domain_name (email one-time passcode /
    other IdPs). The default is fictional and uses the reserved .example TLD.
  EOT
  default = {
    display_name = "Fabrikam Affiliated Clinic"
    domain_name  = "fabrikam-clinic.example"
  }

  validation {
    condition     = var.b2b_connected_organization.tenant_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.b2b_connected_organization.tenant_id))
    error_message = "b2b_connected_organization.tenant_id must be empty or a tenant id (GUID)."
  }
}

variable "b2b_review_frequency" {
  type        = string
  description = "Recurrence of the sponsor review on the guest package (monthly: shorter than the 90-day expiry, so it actually fires)."
  default     = "monthly"

  validation {
    condition     = contains(["weekly", "monthly", "quarterly", "halfyearly", "annual"], var.b2b_review_frequency)
    error_message = "b2b_review_frequency must be one of: weekly, monthly, quarterly, halfyearly, annual."
  }
}

variable "b2b_review_duration_days" {
  type        = number
  description = "Days each guest review instance stays open. Must be shorter than the interval (precondition in b2b.tf)."
  default     = 14

  validation {
    condition     = var.b2b_review_duration_days >= 1 && var.b2b_review_duration_days == floor(var.b2b_review_duration_days)
    error_message = "b2b_review_duration_days must be a whole number of at least 1."
  }
}

variable "b2b_guest_deletion_after_block_days" {
  type        = number
  description = <<-EOT
    Tenant entitlement-management setting rendered for the post-apply step:
    when a connected-org guest loses their LAST package assignment, block
    sign-in, then delete the guest account after this many days. Graph only
    accepts a duration; 30 keeps a recovery window for a mistaken removal.
  EOT
  default     = 30

  validation {
    # Graph documents no bounds for durationUntilExternalUserDeletedAfterBlocked
    # (verify: the portal's accepted range before changing the default).
    condition     = var.b2b_guest_deletion_after_block_days >= 1 && var.b2b_guest_deletion_after_block_days <= 365 && var.b2b_guest_deletion_after_block_days == floor(var.b2b_guest_deletion_after_block_days)
    error_message = "b2b_guest_deletion_after_block_days must be a whole number between 1 and 365."
  }
}
