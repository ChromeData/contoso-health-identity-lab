# =============================================================================
# modules/conditional-access :: variables.tf
# =============================================================================

variable "break_glass_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of the Break-Glass-Admins group. This group is excluded from
    EVERY policy below so a CA mistake can never lock all admins out. This is
    the single most important input to this module.
  EOT
}

variable "ca005_pilot_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of the CA005-Pilot-CompliantDevice group (modules/groups). CA005
    (compliant device for admin portals) applies to THIS group only - never to
    every admin, because the operator administers the lab from a personal Mac
    that will never be Intune-compliant. Membership is operational and set by
    lab/scripts/intune/New-IntuneComplianceBaseline.ps1 -PilotMemberUserPrincipalNames.
  EOT

  validation {
    # Unknown at plan time when the group is created in the same apply - the
    # check is deferred to apply in that case.
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.ca005_pilot_group_object_id))
    error_message = "ca005_pilot_group_object_id must be a group object id (GUID)."
  }
}

variable "admin_portal_applications" {
  type        = list(string)
  description = <<-EOT
    Target resources for CA005. Defaults:
      * "MicrosoftAdminPortals" - Graph keyword for Microsoft's admin-portal
        grouping (Azure portal, Exchange admin center, Microsoft 365 admin
        center, Security & Compliance center).
      * 797f4846-ba00-4fd7-ba43-dac1f8f63013 - Windows Azure Service Management
        API (Azure Resource Manager: portal, Azure CLI, Azure PowerShell).
  EOT
  default = [
    "MicrosoftAdminPortals",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013", # Windows Azure Service Management API
  ]

  validation {
    condition     = length(var.admin_portal_applications) > 0 && !contains(var.admin_portal_applications, "All")
    error_message = "admin_portal_applications must be non-empty and must not be \"All\" (CA005 is a scoped admin-portal policy, not a tenant-wide device gate)."
  }
}

variable "policy_name_prefix" {
  type        = string
  description = "Prefix for policy display names, used for ordering/grouping in the portal."
  default     = "CA"
}

variable "policy_states" {
  type        = map(string)
  nullable    = false # a caller passing null gets the report-only defaults
  description = <<-EOT
    State per policy, keyed by CA number (CA001..CA010, CA020..CA023, CA060).
    Every policy starts REPORT-ONLY (enabledForReportingButNotEnforced) so
    impact is visible in sign-in logs before anything is enforced. Graduating
    a policy = a PR that flips its entry to "enabled" (one policy per PR).
    "disabled" parks a policy.

    CA001..CA005 are always created, so their keys are always required: a
    reviewer sees each live policy's state in the diff, and a new policy can
    never silently inherit "enabled".
    Every other key is required exactly while its staging flag is on -
    enforced by a precondition on each policy (CA021: on its rendered output) -
    so a caller that predates them (a five-key lab.tfvars) keeps planning
    cleanly while the flags are off, and the same rule still holds for every
    live policy:
      CA006, CA007  enable_identity_protection_ca
      CA008         enable_phishing_resistant_all_users
      CA009         enable_registration_ca          (register security info)
      CA010         enable_device_code_block        (block device code flow)
      CA020         enable_admin_session_controls   (admin portal sign-in frequency)
      CA021         enable_pim_auth_context         (PIM activation, auth context; Graph-managed)
      CA022         enable_pam_session_ca           (PAM session broker; was CA009)
      CA023         enable_protected_actions_ca     (protected actions, auth context; Graph-managed)
      CA060         enable_shared_clinical_ca       (shared clinical workstations)
    CA011 is TAKEN but is not a key here: the token-protection pilot,
    Graph-managed by post-apply/Set-TokenProtectionPolicy.ps1 (report-only
    by default; -Enforce is its own second key). Never reuse the number.
  EOT
  default = {
    CA001 = "enabledForReportingButNotEnforced" # require MFA, all users
    CA002 = "enabledForReportingButNotEnforced" # phishing-resistant, admins
    CA003 = "enabledForReportingButNotEnforced" # block legacy auth
    CA004 = "enabledForReportingButNotEnforced" # block countries
    CA005 = "enabledForReportingButNotEnforced" # compliant device, admin portals (pilot)
    CA006 = "enabledForReportingButNotEnforced" # user risk high -> secure password change (P2)
    CA007 = "enabledForReportingButNotEnforced" # sign-in risk high -> block (P2)
    CA008 = "enabledForReportingButNotEnforced" # phishing-resistant, all users (rollout)
    CA009 = "enabledForReportingButNotEnforced" # register security info: TAP or phishing-resistant
    CA010 = "enabledForReportingButNotEnforced" # block device code flow
    CA020 = "enabledForReportingButNotEnforced" # admin portals: sign-in frequency, Tier-0/1
    CA021 = "enabledForReportingButNotEnforced" # PIM activation step-up, auth context (Graph-managed)
    CA022 = "enabledForReportingButNotEnforced" # PAM session broker + admin portals, admin strength
    CA023 = "enabledForReportingButNotEnforced" # protected actions step-up, auth context (Graph-managed)
    CA060 = "enabledForReportingButNotEnforced" # shared clinical workstations
  }

  validation {
    condition = alltrue([
      for k in ["CA001", "CA002", "CA003", "CA004", "CA005"] : contains(keys(var.policy_states), k)
    ])
    error_message = "policy_states must contain CA001, CA002, CA003, CA004 and CA005 (every other key is required only while its staging flag is on)."
  }

  # Reject unknown keys too (e.g. a typo "CA06" or "ca005"): an extra key would
  # otherwise be ignored silently while the reviewer believes it did something.
  validation {
    condition = alltrue([
      for k in keys(var.policy_states) : contains([
        "CA001", "CA002", "CA003", "CA004", "CA005", "CA006", "CA007", "CA008", "CA009", "CA010",
        "CA020", "CA021", "CA022", "CA023",
        "CA060",
      ], k)
    ])
    error_message = "policy_states accepts only the keys CA001..CA010, CA020..CA023 and CA060."
  }

  validation {
    condition = alltrue([
      for s in values(var.policy_states) :
      contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], s)
    ])
    error_message = "Each state must be enabled, disabled or enabledForReportingButNotEnforced."
  }
}

variable "admin_role_template_ids" {
  type        = list(string)
  description = <<-EOT
    Directory role TEMPLATE ids CA002 targets (phishing-resistant strength).
    Default = Microsoft's "Require phishing-resistant multifactor
    authentication for administrators" template list (14 roles, Learn
    2026-03-24) plus the lab's tier extras (8 roles that the PIM tier model
    treats as Tier 0 / Tier 1 or that Microsoft labels PRIVILEGED -
    permissions-reference 2026-07-17; the label itself is still preview).

    The 14 template roles are a FLOOR: validation refuses a list that drops
    one, so CA002 can be widened but never quietly narrowed below Microsoft's
    template. Every role added widens the lockout scope once CA002 is
    enforced - each holder needs a registered phishing-resistant method first.

    The role condition does NOT see AU-scoped or custom-role assignments, and
    matches only ACTIVE assignments (an eligible admin is caught after
    activation): cover those through admin_scope_group_object_ids.
  EOT
  default = [
    # --- Microsoft template list ---------------------------------------------
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f", # Authentication Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", # Billing Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", # Cloud Application Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8", # Helpdesk Administrator
    "966707d0-3269-4727-9be2-8c3a10f19b9d", # Password Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
    # --- lab extras (tier model) ---------------------------------------------
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # Hybrid Identity Administrator
    "0526716b-113d-4c15-b2c8-68e3c22b9f80", # Authentication Policy Administrator (not labelled privileged; Tier 0 here: it sets the methods policy CA008/CA009 rely on)
    "3a2c62db-5318-420d-8d74-23affee5d9d5", # Intune Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c", # Groups Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e", # Identity Governance Administrator
    "59d46f88-662b-457b-bceb-5c3809e5908f", # Lifecycle Workflows Administrator
    "8329153b-31d0-4727-b945-745eb3bc5f31", # Domain Name Administrator
    "be2f45a1-457d-42af-a067-6ec1fa63bc45", # External Identity Provider Administrator
  ]

  validation {
    condition = length(var.admin_role_template_ids) == length(distinct(var.admin_role_template_ids)) && alltrue([
      for r in var.admin_role_template_ids : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", r))
    ])
    error_message = "admin_role_template_ids must be distinct, lowercase directory role template GUIDs."
  }

  # The floor: Microsoft's template roles cannot be dropped from CA002.
  validation {
    condition = alltrue([
      for r in [
        "62e90394-69f5-4237-9190-012177145e10", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f", "b0f54661-2d74-4c50-afa3-1ec803f12efe",
        "158c047a-c907-4556-b7ef-446551a6b5f7", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "29232cdf-9323-42fd-ade2-1d097af3e4de", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "966707d0-3269-4727-9be2-8c3a10f19b9d", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        "e8611ab8-c189-46e8-94e1-60213ab1f814", "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "fe930be7-5e62-47db-91af-98c3a49a38b1",
      ] : contains(var.admin_role_template_ids, r)
    ])
    error_message = "admin_role_template_ids must keep every role of Microsoft's phishing-resistant-MFA-for-administrators template (CA002 may be widened, never narrowed below it)."
  }
}

variable "admin_scope_group_object_ids" {
  type        = map(string)
  nullable    = false
  description = <<-EOT
    Admin GROUPS that CA002 (phishing-resistant strength) and CA020 (admin
    portal sign-in frequency) include NEXT TO the role condition, keyed by a
    readable name (display name => object id; keys must be known at plan,
    values may be unknown). Pass the PIM tier groups, Privileged-IAM-Admins
    and the help-desk administrative-unit group - in envs/dev that is
    module.pim[0].privileged_review_targets.

    Why groups as well as roles (Learn, users-and-groups condition):
      * role assignments scoped to an ADMINISTRATIVE UNIT (the help desk's
        Authentication / Helpdesk Administrator) and custom roles are NOT
        evaluated by the directory-role condition;
      * unverified whether a role held through an activated role-assignable
        group is matched by it.
    The PIM-for-Groups groups carry no standing members, so including them
    adds only the person who ACTIVATED. A group with STANDING members (envs/dev
    passes PIM-Azure-RG-Contributors, whose members are eligible for an Azure
    role through the group) puts every member in CA002 / CA020 at every
    sign-in: each needs a registered, accepted phishing-resistant method
    before CA002 is enforced. Empty (default) = roles only.
  EOT
  default     = {}

  validation {
    # Unknown at plan time when the groups are created in the same apply -
    # the check is deferred to apply in that case.
    condition = alltrue([
      for id in values(var.admin_scope_group_object_ids) : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))
    ])
    error_message = "admin_scope_group_object_ids values must be group object ids (GUIDs)."
  }
}

variable "phishing_resistant_combinations" {
  type        = list(string)
  description = <<-EOT
    Allowed authentication method combinations for the ADMIN "phishing
    resistant" authentication strength (CA002). These three are the
    phishing-resistant set Microsoft recognises. Valid values must match Graph
    authenticationMethodModes.
  EOT
  default = [
    "windowsHelloForBusiness",
    "fido2",
    "x509CertificateMultiFactor",
  ]

  # A strength called "phishing resistant" that quietly accepts a phishable
  # combination (e.g. "password,microsoftAuthenticatorPush") is worse than no
  # strength at all: the CA policy reads as compliant while it is not.
  validation {
    condition = length(var.phishing_resistant_combinations) > 0 && alltrue([
      for c in var.phishing_resistant_combinations :
      contains(["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"], c)
    ])
    error_message = "phishing_resistant_combinations must be a non-empty subset of windowsHelloForBusiness, fido2, x509CertificateMultiFactor."
  }
}

variable "admin_fido2_allowed_aaguids" {
  type        = set(string)
  description = <<-EOT
    OPTIONAL hardening of the ADMIN strength (CA002): restrict its "fido2"
    combination to these authenticator models (AAGUIDs), e.g. the two
    security-key models the organisation issues to Tier-0 admins. Empty (the
    default) = no restriction, no resource - any passkey satisfies CA002.

    WHY admins only: Tier-0 sign-ins should come from a device-bound key the
    organisation issued, not a synced passkey in a personal cloud keychain.
    The workforce strength (CA008) deliberately does NOT restrict models, so
    synced passkeys stay usable for staff.

    CAVEAT: an AAGUID is self-asserted by the authenticator unless the
    Passkey (FIDO2) authentication-methods policy ENFORCES ATTESTATION. Turn
    attestation enforcement on (tenant-time, authentication-methods policy -
    not this module) before relying on this list, or it is only a hint.
  EOT
  default     = []

  validation {
    condition = alltrue([
      for a in var.admin_fido2_allowed_aaguids :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", a))
    ])
    error_message = "admin_fido2_allowed_aaguids must contain AAGUIDs (GUID format)."
  }
}

variable "blocked_named_location_name" {
  type        = string
  description = "Display name of the blocked-countries named location."
  default     = "Blocked Countries"
}

variable "blocked_countries" {
  type        = list(string)
  description = <<-EOT
    ISO 3166-1 alpha-2 country codes blocked by the location policy. Defaults
    are illustrative embargo/high-risk examples - set to your real list. An
    empty list is rejected (the named location requires at least one entry).
  EOT
  default     = ["KP", "IR", "SY", "CU"]

  validation {
    condition     = length(var.blocked_countries) > 0
    error_message = "Provide at least one country code for the blocked named location."
  }
}

variable "include_unknown_countries" {
  type        = bool
  description = <<-EOT
    Treat requests from unresolvable/unknown locations as part of the blocked
    set. Default false: unknown geolocation is common (some IPv6 ranges, new
    ISP blocks, VPN egress) and blocking it is a classic self-lockout. Turn on
    only after the sign-in logs show it would not hit legitimate users.
  EOT
  default     = false
}

# =============================================================================
# Staging flags for the newer policies. All default to false: no trial
# starts early, and a plan with the flags off creates only the five baseline
# policies CA001-CA005 (tests/ca009_ca010_baseline.tftest.hcl
# new_flags_off_create_nothing and the CA006-CA008 flag-off runs prove it).
# =============================================================================

variable "enable_identity_protection_ca" {
  type        = bool
  description = <<-EOT
    Create CA006 (user risk High -> secure password change) and CA007
    (sign-in risk High -> block). Needs Entra ID P2 for every user in scope
    (Microsoft 365 E5 trial). Without P2 the policies still save, but there is
    no risk signal to evaluate, so they never match - flip this only once the
    trial licence is assigned. Root flag: enable_identity_protection_ca.
  EOT
  default     = false
}

variable "sign_in_risk_block_levels" {
  type        = list(string)
  description = <<-EOT
    Sign-in risk levels CA007 blocks. Default ["high"] - the ADR'd threshold:
    High is where false positives are rare enough to BLOCK rather than
    challenge. "high" must always be included.

    Test knob, not a production dial: Microsoft's documented simulation (Tor
    -> "anonymous IP address") does not promise a High score. If the
    simulated sign-in lands at Medium, a report-only run with
    ["medium", "high"] proves the policy WOULD have blocked it. The display
    name follows the list, so the portal never claims "high" while matching
    medium too.
  EOT
  default     = ["high"]

  validation {
    condition = (
      contains(var.sign_in_risk_block_levels, "high") &&
      length(var.sign_in_risk_block_levels) == length(distinct(var.sign_in_risk_block_levels)) &&
      alltrue([for l in var.sign_in_risk_block_levels : contains(["low", "medium", "high"], l)])
    )
    error_message = "sign_in_risk_block_levels must be distinct values from low/medium/high and must include \"high\"."
  }
}

variable "enable_phishing_resistant_all_users" {
  type        = bool
  description = <<-EOT
    Create CA008 (phishing-resistant authentication strength for the
    workforce), its workforce authentication strength, and - unless
    ca008_pilot_group_object_id is given - the CA008-Pilot-PhishingResistant
    group. Custom authentication strengths need Entra ID P1. Root flag:
    enable_phishing_resistant_all_users.
  EOT
  default     = false
}

variable "workforce_phishing_resistant_combinations" {
  type        = list(string)
  description = <<-EOT
    Allowed combinations for the WORKFORCE strength used by CA008. Same
    phishing-resistant set as the admin strength, but a separate object on
    purpose: CA002 can later be narrowed to device-bound, attested security
    keys (admin_fido2_allowed_aaguids) without touching the workforce, where
    synced passkeys ("fido2") are acceptable.
  EOT
  default = [
    "windowsHelloForBusiness",
    "fido2",
    "x509CertificateMultiFactor",
  ]

  validation {
    condition = length(var.workforce_phishing_resistant_combinations) > 0 && alltrue([
      for c in var.workforce_phishing_resistant_combinations :
      contains(["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"], c)
    ])
    error_message = "workforce_phishing_resistant_combinations must be a non-empty subset of windowsHelloForBusiness, fido2, x509CertificateMultiFactor."
  }
}

variable "ca008_scope" {
  type        = string
  description = <<-EOT
    Who CA008 includes:
      * "all_users" (default) - All users (break-glass and guests excluded).
        In report-only this MEASURES the blast radius: every sign-in that
        lacks a phishing-resistant method shows up as "would fail", which is
        the registration-gap number the rollout is planned from.
      * "pilot" - only the CA008 pilot group. This is the scope you ENFORCE
        first; widen it by adding people (or nesting wave groups) into the
        pilot group, not by editing the policy.
    Enforcing "all_users" additionally needs ca008_allow_all_users_enforcement.
  EOT
  default     = "all_users"

  validation {
    condition     = contains(["all_users", "pilot"], var.ca008_scope)
    error_message = "ca008_scope must be \"all_users\" or \"pilot\"."
  }
}

variable "ca008_allow_all_users_enforcement" {
  type        = bool
  description = <<-EOT
    Second key for the one change that can lock the whole workforce out:
    CA008 "enabled" with ca008_scope = "all_users". Leave false until the
    method-registration report shows every in-scope user holds a
    phishing-resistant method (and the pilot has run enforced). Flipping it
    is a separate, reviewable line in the PR - one state flip alone can
    never enforce tenant-wide.
  EOT
  default     = false
}

variable "ca008_pilot_group_object_id" {
  type        = string
  nullable    = true
  description = <<-EOT
    Optional existing group to use as the CA008 pilot. null or "" (default)
    = this module creates CA008-Pilot-PhishingResistant itself (only this
    module consumes it, so it lives here rather than in modules/groups).
    Must be KNOWN at plan time (a literal id, not another resource's
    not-yet-created output): it decides whether the group resource exists.
  EOT
  default     = null

  validation {
    condition = (
      var.ca008_pilot_group_object_id == null ? true :
      var.ca008_pilot_group_object_id == "" ? true :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.ca008_pilot_group_object_id))
    )
    error_message = "ca008_pilot_group_object_id must be null, empty, or a group object id (GUID)."
  }
}

variable "accept_admin_synced_passkey_risk" {
  type        = bool
  description = <<-EOT
    Second key for enable_phishing_resistant_all_users WITHOUT
    admin_fido2_allowed_aaguids. The workforce rollout lets admins register
    synced passkeys too; with no AAGUID allow-list CA002 / CA022 then accept
    them. true = that is a reviewed, recorded risk acceptance (risk register),
    e.g. until the security-key models are bought. Default false.
  EOT
  default     = false
}

variable "enable_pam_session_ca" {
  type        = bool
  description = "Create CA022 (numbered CA009 before the CA design-principle ranges): the PAM session broker app(s) (pam_session_app_ids - guacamole-psm) and the admin portals require the ADMIN phishing-resistant strength for every user, excluding break-glass and guests. Report-only via policy_states CA022 (required while this is on)."
  default     = false
}

variable "pam_session_app_ids" {
  type        = list(string)
  description = "Application (client) ids of the PAM session broker(s) CA022 targets - modules/apps guacamole_psm_client_id. Empty = CA022 covers the admin portals only."
  default     = []

  validation {
    condition = alltrue([
      for a in var.pam_session_app_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", a))
    ])
    error_message = "pam_session_app_ids must be application (client) ids (GUIDs)."
  }
}

# =============================================================================
# CA009 - register security info (baseline.tf)
# =============================================================================

variable "enable_registration_ca" {
  type        = bool
  description = <<-EOT
    Create CA009 (the "Register security information" user action requires a
    one-time TAP or a phishing-resistant method) and its "Bootstrap and
    recovery (lab)" authentication strength. All users, break-glass and every
    guest/external type excluded (a TAP cannot be issued to a guest).
    Report-only via policy_states CA009 (required while this is on). Entra ID
    P1. Measure in report-only first: since 2026-07-06 registration policies
    also govern Windows Hello for Business / Platform SSO registration, so a
    password+push user provisioning Windows Hello would need a TAP. Root flag:
    enable_registration_ca. Default false.
  EOT
  default     = false
}

variable "registration_strength_combinations" {
  type        = list(string)
  description = <<-EOT
    Allowed combinations of the bootstrap-and-recovery strength CA009
    requires: a ONE-TIME Temporary Access Pass or a phishing-resistant
    method (Learn's documented "Bootstrap and recovery" pattern). Multi-use
    TAP and every phishable combination are refused - the lab issues
    one-time TAPs only.
  EOT
  default = [
    "temporaryAccessPassOneTime",
    "windowsHelloForBusiness",
    "fido2",
    "x509CertificateMultiFactor",
  ]

  validation {
    condition = length(var.registration_strength_combinations) > 0 && alltrue([
      for c in var.registration_strength_combinations :
      contains(["temporaryAccessPassOneTime", "windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"], c)
    ])
    error_message = "registration_strength_combinations must be a non-empty subset of temporaryAccessPassOneTime, windowsHelloForBusiness, fido2, x509CertificateMultiFactor (no multi-use TAP, nothing phishable)."
  }
}

# =============================================================================
# CA010 - block device code flow (baseline.tf)
# =============================================================================

variable "enable_device_code_block" {
  type        = bool
  description = <<-EOT
    Create CA010: block the device code flow for all users (break-glass
    excluded). Report-only via policy_states CA010 (required while this is
    on). Closes CISA SCuBA MS.AAD.3.9. Default false.

    OPERATOR GOTCHA: enforcing CA010 breaks every device-code sign-in the lab
    itself uses - the operator's bootstrap `az login --use-device-code` and
    Invoke-BaselineAssessment.ps1 -UseDeviceCode. Move those to
    interactive browser sign-in BEFORE flipping CA010 to "enabled", or add a
    CA010-Exclusion-<reason> group via ca010_exception_group_object_ids
    (exception process: owner, expiry, monthly review). A session that started
    with device code is also blocked on refresh (protocol tracking,
    AADSTS530036).
  EOT
  default     = false
}

variable "ca010_excluded_applications" {
  type        = list(string)
  description = <<-EOT
    Resources excluded from CA010. Default none. Add the Device Registration
    Service (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) ONLY if devices are
    registered through device code - since September 2024 a policy that
    targets All resources also covers device registration.
  EOT
  default     = []

  validation {
    condition = alltrue([
      for a in var.ca010_excluded_applications : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", a))
    ])
    error_message = "ca010_excluded_applications must be application ids (GUIDs) - never \"All\" or a keyword."
  }
}

variable "ca010_exception_group_object_ids" {
  type        = list(string)
  description = <<-EOT
    Exception groups excluded from CA010 next to break-glass, e.g. a
    CA010-Exclusion-OperatorBootstrap group while the operator still signs
    in with device code. Only through the exception process (CA design
    principles section 3: CA0NN-Exclusion-<reason>, owner, expiry, monthly
    review); make the group role-assignable so a Groups Administrator cannot
    add themselves. Default none.
  EOT
  default     = []

  validation {
    condition = alltrue([
      for g in var.ca010_exception_group_object_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", g))
    ])
    error_message = "ca010_exception_group_object_ids must be group object ids (GUIDs)."
  }
}

# =============================================================================
# CA020 - admin portal sign-in frequency (admins.tf)
# =============================================================================

variable "enable_admin_session_controls" {
  type        = bool
  description = <<-EOT
    Create CA020: sign-in frequency on the admin portals
    (admin_portal_applications) for the Tier-0/1 roles
    (admin_session_role_template_ids) and the admin groups
    (admin_scope_group_object_ids). Session control only, no grant.
    Report-only via policy_states CA020 (required while this is on). In-scope
    admins' Azure CLI / PowerShell sessions re-authenticate on the same
    cadence (Azure Service Management API is in the target set). Default false.
  EOT
  default     = false
}

variable "admin_session_sign_in_frequency_hours" {
  type        = number
  description = "CA020 sign-in frequency in whole hours (1-4). Default 4 = the Tier-0 PIM activation cap. Longer is refused: it would weaken the control the policy exists for."
  default     = 4

  validation {
    condition     = var.admin_session_sign_in_frequency_hours >= 1 && var.admin_session_sign_in_frequency_hours <= 4 && floor(var.admin_session_sign_in_frequency_hours) == var.admin_session_sign_in_frequency_hours
    error_message = "admin_session_sign_in_frequency_hours must be a whole number from 1 to 4."
  }
}

variable "admin_session_role_template_ids" {
  type        = list(string)
  description = <<-EOT
    Directory role template ids CA020 includes: the lab's Tier-0 and Tier-1
    roles (Enterprise Access Model - Tier 0 control plane, Tier 1 management
    plane). AU-scoped holders are covered by admin_scope_group_object_ids,
    not here.
  EOT
  default = [
    # --- Tier 0 ----------------------------------------------------------------
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # Hybrid Identity Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", # Cloud Application Administrator
    "0526716b-113d-4c15-b2c8-68e3c22b9f80", # Authentication Policy Administrator
    # --- Tier 1 ----------------------------------------------------------------
    "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c", # Groups Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f", # Authentication Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8", # Helpdesk Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5", # Intune Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
    "69091246-20e8-4a56-aa4d-066075b2a7a8", # Teams Administrator
    "4d6ac14f-3453-41d0-bef9-a3e0c569773a", # License Administrator
  ]

  validation {
    condition = length(var.admin_session_role_template_ids) > 0 && alltrue([
      for r in var.admin_session_role_template_ids : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", r))
    ])
    error_message = "admin_session_role_template_ids must be a non-empty list of lowercase directory role template GUIDs."
  }
}

# =============================================================================
# CA021 - PIM activation step-up on an authentication context (admins.tf;
# Graph-managed through post-apply/Set-AuthContextPolicies.ps1)
# =============================================================================

variable "enable_pim_auth_context" {
  type        = bool
  description = <<-EOT
    Render CA021 and the authentication context it targets (output
    pim_auth_context_requests) for post-apply/Set-AuthContextPolicies.ps1,
    which PATCHes the context (isAvailable = true) and creates/updates CA021
    by display-name prefix. azuread 3.10 can create neither, so nothing is
    written to the tenant by Terraform. The script refuses to run while this
    is false (null output). CA021 state via policy_states CA021 (required
    while this is on), report-only by default. Default false.
  EOT
  default     = false
}

variable "pim_auth_context_id" {
  type        = string
  description = "Authentication context id CA021 targets and PIM Tier-0 activation will require (default c1). Graph documents c1..c25 (Learn says up to c99 - verify); the stricter range is enforced."
  default     = "c1"

  validation {
    condition     = can(regex("^c([1-9]|1[0-9]|2[0-5])$", var.pim_auth_context_id))
    error_message = "pim_auth_context_id must be an authentication context id c1..c25."
  }
}

variable "pim_tier0_activation_auth_context_id" {
  type        = string
  description = <<-EOT
    The SAME value the caller passes to modules/pim
    tier0_activation_auth_context_id ("" = PIM keeps plain MFA). Passing it
    here lets this module refuse the plan when PIM would require a context
    that no ENFORCED CA021 targets: it must be "" unless
    enable_pim_auth_context = true, policy_states CA021 = "enabled" and the id
    equals pim_auth_context_id, AND ca021_enforced_in_tenant = true. Learn (PIM
    for Groups role settings): create and enable the CA policy before PIM uses
    the context; the MFA backup "isn't triggered" when that policy is
    report-only or off, so activation would have no step-up at all. Run
    Set-AuthContextPolicies.ps1 with CA021 enabled BEFORE the change that sets
    the PIM value. Default "".
  EOT
  default     = ""

  validation {
    condition     = var.pim_tier0_activation_auth_context_id == "" || can(regex("^c([1-9]|1[0-9]|2[0-5])$", var.pim_tier0_activation_auth_context_id))
    error_message = "pim_tier0_activation_auth_context_id must be empty or an authentication context id c1..c25."
  }
}

variable "ca021_enforced_in_tenant" {
  type        = bool
  description = <<-EOT
    TENANT-STATE attestation for the PIM ordering gate. Set true ONLY in a
    change AFTER the one that declared CA021 "enabled", once
    post-apply/Set-AuthContextPolicies.ps1 has run against that apply and
    reported CA021 enabled (and the context isAvailable) in the tenant.
    Declared state cannot gate PIM by itself: `terraform apply` writes the
    Tier-0 PIM policies BEFORE any post-apply step, so a single change that
    declares CA021 enabled AND sets the PIM context would point activation at
    the context while the tenant still holds the report-only CA021 - and
    Learn (PIM for Groups role settings) says PIM's MFA backup is not
    triggered when that policy is report-only, so activation would have no
    step-up. Output pim_activation_auth_context_ready (wired to modules/pim)
    needs this AND the declared "enabled" state; true while CA021 is not
    declared enabled is refused. Default false.
  EOT
  default     = false
}

# =============================================================================
# CA023 - protected actions step-up on a second authentication context
# (admins.tf; Graph-managed through post-apply/Set-AuthContextPolicies.ps1)
# =============================================================================

variable "enable_protected_actions_ca" {
  type        = bool
  description = <<-EOT
    Render CA023 and the authentication context it targets (output
    protected_actions_auth_context_requests): the ADMIN phishing-resistant
    strength with sign-in every time, for whoever performs a PROTECTED ACTION
    - Conditional Access policy and named-location updates and deletes. The
    same Graph path as CA021 (post-apply/Set-AuthContextPolicies.ps1 with this
    output); binding the context to the protected actions is a TENANT-TIME
    step (Invoke-PostApply.ps1 prints it). Today a CA change is only DETECTED
    (lab/kql/ca-policy-changed.kql); this makes the change itself need a fresh
    phishing-resistant sign-in. Report-only via policy_states CA023 (required
    while this is on). Default false.
  EOT
  default     = false
}

variable "protected_actions_auth_context_id" {
  type        = string
  description = "Authentication context id CA023 targets and the protected actions require (default c2; must differ from pim_auth_context_id). Graph documents c1..c25."
  default     = "c2"

  validation {
    condition     = can(regex("^c([1-9]|1[0-9]|2[0-5])$", var.protected_actions_auth_context_id))
    error_message = "protected_actions_auth_context_id must be an authentication context id c1..c25."
  }
}

# =============================================================================
# CA060 - shared clinical workstations (clinical.tf)
# =============================================================================

variable "enable_shared_clinical_ca" {
  type        = bool
  description = <<-EOT
    Create CA060 (ADR 0014): on devices whose enrollmentProfileName is
    ca060_enrollment_profile_name, the clinical groups need the CA008
    workforce phishing-resistant strength, sign in every 8 hours and never
    keep a persistent browser session. Needs enable_phishing_resistant_all_users
    (the workforce strength; CA008 may stay report-only) and at least one
    group in ca060_clinical_group_object_ids. Report-only via policy_states
    CA060 (required while this is on); enforcement needs Clinical Operations
    sign-off. Default false.
  EOT
  default     = false
}

variable "ca060_clinical_group_object_ids" {
  type        = list(string)
  description = "Clinical groups CA060 includes (e.g. modules/groups all_nurses_group_object_id, all_icu_group_object_id). Required (non-empty) while enable_shared_clinical_ca is on; CA060 never targets All users."
  default     = []

  validation {
    condition = alltrue([
      for g in var.ca060_clinical_group_object_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", g))
    ])
    error_message = "ca060_clinical_group_object_ids must be group object ids (GUIDs)."
  }
}

variable "ca060_enrollment_profile_name" {
  type        = string
  description = <<-EOT
    Windows Autopilot DEPLOYMENT PROFILE name that marks a shared clinical
    station (device.enrollmentProfileName). Only Autopilot / Apple ADE /
    Google enrollment set this property; a station enrolled any other way has
    a null value and CA060 silently does not apply to it. Default
    "CH-SharedClinical" (ADR 0014).
  EOT
  default     = "CH-SharedClinical"

  validation {
    # Interpolated into the device-filter rule: no quotes or operators.
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", var.ca060_enrollment_profile_name))
    error_message = "ca060_enrollment_profile_name must be 1-64 characters of letters, digits, '.', '_' or '-' (it is interpolated into the device filter rule)."
  }
}

variable "tags_note" {
  type        = string
  description = <<-EOT
    Entra groups carry no Azure tags; this string is surfaced in the CA008
    pilot group's description so the lab's intent is self-documenting (same
    convention as modules/groups).
  EOT
  default     = "contoso-health-identity-lab"
}
