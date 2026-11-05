# =============================================================================
# modules/pim :: variables.tf
# =============================================================================

variable "priv_iam_admins_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of the role-assignable Privileged-IAM-Admins group. The group is
    ACTIVELY assigned the target role, and its MEMBERSHIP is the just-in-time
    control governed by a PIM-for-Groups activation policy.
  EOT
}

variable "role_template_id" {
  type        = string
  description = <<-EOT
    Directory role TEMPLATE id Privileged-IAM-Admins holds ACTIVELY. Default
    "User Administrator" (a Tier-1 admin). The group gets TIER-1 activation
    rules (365-day eligibility, Tier-1 approvers, MFA - never the Tier-0
    auth context), and privileged_role_template_ids classifies this role as
    tier1, so Global Administrator and the Tier-0 (control-plane) roles are
    refused here: bind those through a tier = 0 pim_tier_groups entry.
  EOT
  default     = "fe930be7-5e62-47db-91af-98c3a49a38b1" # User Administrator

  validation {
    condition     = can(regex("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", var.role_template_id))
    error_message = "role_template_id must be a lowercase directory role template GUID."
  }
  validation {
    # Same guardrails as pim_tier_groups: no Global Administrator back door,
    # no control-plane role under Tier-1 activation rules.
    condition = !contains([
      "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
      "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
      "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
      "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
      "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
      "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # Hybrid Identity Administrator
      "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
      "158c047a-c907-4556-b7ef-446551a6b5f7", # Cloud Application Administrator
      "0526716b-113d-4c15-b2c8-68e3c22b9f80", # Authentication Policy Administrator
    ], var.role_template_id)
    error_message = "role_template_id (Privileged-IAM-Admins, Tier-1 activation rules) must not be Global Administrator or a Tier-0 role; bind those through a tier = 0 pim_tier_groups entry (or Set-DirectoryRolePimPolicies.ps1 for Global Administrator)."
  }
}

variable "directory_scope_id" {
  type        = string
  description = "Scope of the role assignment. \"/\" = tenant-wide (directory scope)."
  default     = "/"
}

variable "activation_max_duration" {
  type        = string
  description = <<-EOT
    Maximum activation duration as an ISO-8601 duration. Contract asks for a
    4-hour cap => "PT4H".
  EOT
  default     = "PT4H"

  validation {
    condition     = can(regex("^PT([0-9]+H)?([0-9]+M)?$", var.activation_max_duration))
    error_message = "Use an ISO-8601 time duration such as PT4H or PT30M."
  }
}

variable "active_assignment_max_duration" {
  type        = string
  description = <<-EOT
    Longest an admin may DIRECTLY assign active membership (bypassing
    activation). Never permanent: every policy in this module sets
    expiration_required = true on active assignments, plus justification and
    MFA for the admin making one. The provider accepts only the portal's
    fixed choices; P15D is the shortest.
  EOT
  default     = "P15D"

  validation {
    condition     = contains(["P15D", "P30D", "P90D", "P180D", "P365D"], var.active_assignment_max_duration)
    error_message = "Must be one of P15D, P30D, P90D, P180D, P365D."
  }
}

variable "require_approval" {
  type        = bool
  description = "Require approver sign-off before a Privileged-IAM-Admins activation succeeds (approvers: the PIM-Approvers-Tier1 group)."
  default     = true
}

variable "approver_object_ids" {
  type        = list(string)
  description = <<-EOT
    User object ids placed in the in-module, role-assignable PIM-Approvers-Tier1
    group (approvers.tf). Every approval-gated Tier-1 policy (Privileged-IAM-
    Admins, and Tier-1 groups with require_approval) routes to that GROUP
    (type "groupMembers"), never to single users. Also the Tier-0 approvers
    when tier0_approver_object_ids is empty. Non-empty when require_approval
    = true (precondition); at least two recommended (check) - Microsoft Learn:
    approvers cannot approve their own activation, so one approver who is
    also eligible blocks themselves.
  EOT
  default     = []

  validation {
    condition     = alltrue([for id in var.approver_object_ids : can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", id))])
    error_message = "approver_object_ids must be user object ids (GUIDs)."
  }
}

variable "require_justification" {
  type        = bool
  description = "Require the activating user to type a justification."
  default     = true
}

variable "require_mfa_on_activation" {
  type        = bool
  description = <<-EOT
    Require MFA at the moment of a Privileged-IAM-Admins activation. (Tier-0
    groups use tier0_activation_auth_context_id instead once CA021 is
    enforced; the provider declares the two arguments ConflictsWith.)
  EOT
  default     = true
}

# =============================================================================
# Approval, assignment expiry and notifications (all policies)
# =============================================================================

variable "tier0_approver_object_ids" {
  type        = list(string)
  description = <<-EOT
    User object ids placed in the in-module, role-assignable PIM-Approvers-Tier0
    group, which approves every Tier-0 activation (tier groups, Azure
    Contributor on the lab RG, Global Administrator via
    Set-DirectoryRolePimPolicies.ps1). Empty => approver_object_ids. Keep
    disjoint from the people made eligible (Set-PimGroupEligibility.ps1 warns).
  EOT
  default     = []

  validation {
    condition     = alltrue([for id in var.tier0_approver_object_ids : can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", id))])
    error_message = "tier0_approver_object_ids must be user object ids (GUIDs)."
  }
}

variable "tier0_eligible_assignment_duration" {
  type        = string
  description = <<-EOT
    How long a Tier-0 ELIGIBLE assignment lives before it must be renewed
    (re-requested and re-approved). Privileged-access standard: <= 365 days,
    renewed through review; Tier 0 is held to 180. P365D is refused here.
  EOT
  default     = "P180D"

  validation {
    condition     = contains(["P15D", "P30D", "P90D", "P180D"], var.tier0_eligible_assignment_duration)
    error_message = "Tier-0 eligibility must expire within 180 days: P15D, P30D, P90D or P180D."
  }
}

variable "tier1_eligible_assignment_duration" {
  type        = string
  description = "How long a Tier-1 ELIGIBLE assignment (and Privileged-IAM-Admins) lives before renewal. Standard: <= 365 days."
  default     = "P365D"

  validation {
    condition     = contains(["P15D", "P30D", "P90D", "P180D", "P365D"], var.tier1_eligible_assignment_duration)
    error_message = "Must be one of P15D, P30D, P90D, P180D, P365D (the provider's fixed choices)."
  }
}

variable "tier0_require_ticket_info" {
  type        = bool
  description = "Tier-0 activation (and Global Administrator) requires ticket information next to the justification (privileged-access standard section 2: ticket reference for Tier 0)."
  default     = true
}

variable "pim_alert_mailbox" {
  type        = string
  description = <<-EOT
    Security mailbox (one address) added to PIM's ADMIN notifications, as a
    second signal next to the KQL activation detections:
      * Tier 0 and every approval-gated group: activation alert, eligible
        assignment granted, direct active assignment (an activation bypass);
      * other Tier-1 groups: the two assignment alerts (activation alerts only
        with tier1_activation_notifications - a shift-length helpdesk role
        would flood the mailbox and teach the SOC to ignore it).
    Empty (default) = notification rules are left at the tenant default. A
    real address is tenant data: terraform.tfvars / a CI secret, never
    lab.tfvars. Sensitive, like envs/dev alert_email: the public plan
    comment shows "(sensitive value)", and output directory_role_pim_policies
    (which carries it) is sensitive too.
  EOT
  default     = ""
  sensitive   = true

  validation {
    condition     = var.pim_alert_mailbox == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.pim_alert_mailbox))
    error_message = "pim_alert_mailbox must be empty or one email address."
  }
}

variable "tier1_activation_notifications" {
  type        = bool
  description = "Also mail the security mailbox on every activation of Tier-1 groups that need no approval (default false: high volume, covered by the KQL detection)."
  default     = false
}

# =============================================================================
# PIM tier groups (tiers.tf) - OPTIONAL, off by default
# =============================================================================

variable "enable_pim_tiers" {
  type        = bool
  description = <<-EOT
    Create the PIM tier groups (role-assignable, each actively holding its
    directory role(s), membership eligible-only via PIM for Groups). Needs
    Entra ID P2 (M365 E5 trial). Tier 0 requires approvers
    (tier0_approver_object_ids or approver_object_ids) or plan fails.
  EOT
  default     = false
}

variable "pim_tier_groups" {
  type = map(object({
    display_name     = string
    mail_nickname    = string
    role_name        = string # documentation only; the template ids are what bind
    role_template_id = string
    tier             = number # 0 or 1 - selects the activation rules
    # More roles held by the same group (one activation elevates to all).
    additional_role_template_ids = optional(list(string), [])
    # true = assign the roles at AU-Workforce-Standard scope when
    # enable_helpdesk_au_scoping is on (tenant-wide otherwise). Only roles
    # Microsoft allows at administrative-unit scope.
    au_scoped = optional(bool, false)
    # Tier 1 only (Tier 0 ALWAYS requires approval). null = no approval.
    require_approval = optional(bool)
    # Shorter activation cap than the tier's (never longer). null = tier cap.
    activation_max_duration = optional(string)
  }))
  description = <<-EOT
    Tier groups keyed by a short stable id (the key is the Terraform address:
    never rename one). Enterprise Access Model: Tier 0 = control plane
    (can grant itself or others any access, or change how sign-in is
    protected), Tier 1 = management plane. Role template ids are identical in
    every tenant (Microsoft Entra built-in roles reference; checked
    2026-10-20).

    NOT HERE, on purpose:
      * Global Administrator - break-glass holds it standing (modules/groups);
        named-person eligibility is direct and set by
        post-apply/Set-DirectoryRolePimPolicies.ps1 (enable_global_admin_pim_policy).
      * User Administrator - stays on Privileged-IAM-Admins (main.tf).
  EOT
  default = {
    # ---- Tier 0: control plane ---------------------------------------------
    tier0_security_admins = {
      display_name     = "PIM-Tier0-Security-Admins"
      mail_nickname    = "pim-tier0-security-admins"
      role_name        = "Security Administrator" # creates/updates/deletes CA policies, ID Protection
      role_template_id = "194ae4cb-b126-40b2-bd5b-6091b380977d"
      tier             = 0
    }
    tier0_ca_admins = {
      display_name     = "PIM-Tier0-CA-Admins"
      mail_nickname    = "pim-tier0-ca-admins"
      role_name        = "Conditional Access Administrator" # can exclude anyone from any policy
      role_template_id = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
      tier             = 0
    }
    tier0_privileged_role_admins = {
      display_name     = "PIM-Tier0-Privileged-Role-Admins"
      mail_nickname    = "pim-tier0-privileged-role-admins"
      role_name        = "Privileged Role Administrator" # assigns any role, incl. GA; edits PIM settings
      role_template_id = "e8611ab8-c189-46e8-94e1-60213ab1f814"
      tier             = 0
    }
    tier0_privileged_auth_admins = {
      display_name     = "PIM-Tier0-Privileged-Auth-Admins"
      mail_nickname    = "pim-tier0-privileged-auth-admins"
      role_name        = "Privileged Authentication Administrator" # resets methods for ANY user, GA included
      role_template_id = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
      tier             = 0
      # IAM L2 (help-desk runbook level V3): approval and a 2-hour maximum.
      activation_max_duration = "PT2H"
    }
    tier0_hybrid_identity_admins = {
      display_name     = "PIM-Tier0-Hybrid-Identity-Admins"
      mail_nickname    = "pim-tier0-hybrid-identity-admins"
      role_name        = "Hybrid Identity Administrator" # domain federation = sign in as its users; sync config
      role_template_id = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
      tier             = 0
    }
    tier0_application_admins = {
      display_name     = "PIM-Tier0-Application-Admins"
      mail_nickname    = "pim-tier0-application-admins"
      role_name        = "Application Administrator" # adds credentials to ANY service principal, incl. APPLY (ADR 0005)
      role_template_id = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
      tier             = 0
    }
    tier0_cloud_application_admins = {
      display_name     = "PIM-Tier0-Cloud-Application-Admins"
      mail_nickname    = "pim-tier0-cloud-application-admins"
      role_name        = "Cloud Application Administrator" # same service-principal takeover path
      role_template_id = "158c047a-c907-4556-b7ef-446551a6b5f7"
      tier             = 0
    }
    tier0_auth_policy_admins = {
      display_name     = "PIM-Tier0-Auth-Policy-Admins"
      mail_nickname    = "pim-tier0-auth-policy-admins"
      role_name        = "Authentication Policy Administrator" # NOT labelled privileged by Microsoft; Tier 0 here: it sets the methods policy (TAP, passkey profiles) CA008/CA009 rely on
      role_template_id = "0526716b-113d-4c15-b2c8-68e3c22b9f80"
      tier             = 0
    }

    # ---- Tier 1: management plane ------------------------------------------
    tier1_intune_admins = {
      display_name     = "PIM-Tier1-Intune-Admins"
      mail_nickname    = "pim-tier1-intune-admins"
      role_name        = "Intune Administrator" # reads LAPS passwords and BitLocker keys
      role_template_id = "3a2c62db-5318-420d-8d74-23affee5d9d5"
      tier             = 1
      # Effectively Tier 0 once PAWs / DC-management devices are Intune-
      # managed; until then Tier 1 WITH approval.
      require_approval = true
    }
    tier1_helpdesk = {
      display_name     = "PIM-Tier1-Helpdesk"
      mail_nickname    = "pim-tier1-helpdesk"
      role_name        = "Helpdesk Administrator + Authentication Administrator (service desk)"
      role_template_id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
      tier             = 1
      # Authentication Administrator: methods + TAP for non-admin users
      # (help-desk-identity-verification.md, levels V1-V2-C).
      additional_role_template_ids = ["c4e39bd9-1100-46d3-8c65-fb160da0071f"]
      au_scoped                    = true
    }
    tier1_groups_admins = {
      display_name     = "PIM-Tier1-Groups-Admins"
      mail_nickname    = "pim-tier1-groups-admins"
      role_name        = "Groups Administrator" # cannot touch role-assignable groups
      role_template_id = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
      tier             = 1
    }
    tier1_exchange_admins = {
      display_name     = "PIM-Tier1-Exchange-Admins"
      mail_nickname    = "pim-tier1-exchange-admins"
      role_name        = "Exchange Administrator"
      role_template_id = "29232cdf-9323-42fd-ade2-1d097af3e4de"
      tier             = 1
    }
    tier1_sharepoint_admins = {
      display_name     = "PIM-Tier1-SharePoint-Admins"
      mail_nickname    = "pim-tier1-sharepoint-admins"
      role_name        = "SharePoint Administrator"
      role_template_id = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
      tier             = 1
    }
    tier1_teams_admins = {
      display_name     = "PIM-Tier1-Teams-Admins"
      mail_nickname    = "pim-tier1-teams-admins"
      role_name        = "Teams Administrator"
      role_template_id = "69091246-20e8-4a56-aa4d-066075b2a7a8"
      tier             = 1
    }
    tier1_license_admins = {
      display_name     = "PIM-Tier1-License-Admins"
      mail_nickname    = "pim-tier1-license-admins"
      role_name        = "License Administrator"
      role_template_id = "4d6ac14f-3453-41d0-bef9-a3e0c569773a"
      tier             = 1
    }
    tier1_iga_admins = {
      display_name     = "PIM-Tier1-IGA-Admins"
      mail_nickname    = "pim-tier1-iga-admins"
      role_name        = "Identity Governance Administrator + Lifecycle Workflows Administrator" # birthright automatic policies, catalogs, SoD links, the joiner 'Generate TAP' workflow
      role_template_id = "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e"
      tier             = 1
      # Both are labelled PRIVILEGED by Microsoft: whoever holds them can
      # rewrite who gets clinical (PHI) access by HR attribute and issue
      # TAPs through a workflow. Just-in-time, with approval, never standing.
      additional_role_template_ids = ["59d46f88-662b-457b-bceb-5c3809e5908f"]
      require_approval             = true
    }
  }

  validation {
    condition     = alltrue([for g in values(var.pim_tier_groups) : contains([0, 1], g.tier)])
    error_message = "Each tier group's tier must be 0 or 1."
  }
  validation {
    condition = alltrue(flatten([for g in values(var.pim_tier_groups) : [
      for id in concat([g.role_template_id], g.additional_role_template_ids) : can(regex("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", id))
    ]]))
    error_message = "Every role template id (role_template_id, additional_role_template_ids) must be a lowercase directory role template GUID."
  }
  validation {
    # Global Administrator stays break-glass-only (modules/groups) plus
    # direct, expiring, named eligibility (Set-DirectoryRolePimPolicies.ps1);
    # a PIM tier group must never be a back door to it.
    condition = !contains(flatten([for g in values(var.pim_tier_groups) : concat([g.role_template_id], g.additional_role_template_ids)]),
    "62e90394-69f5-4237-9190-012177145e10")
    error_message = "Global Administrator must not be bound to a PIM tier group (break-glass only; direct eligibility via Set-DirectoryRolePimPolicies.ps1)."
  }
  validation {
    # No silent downgrade: a control-plane role in a Tier-1 group would get
    # Tier-1 activation (no approval, 8h, 365-day eligibility).
    condition = alltrue([for g in values(var.pim_tier_groups) : g.tier == 0 || length(setintersection(
      toset(concat([g.role_template_id], g.additional_role_template_ids)),
      toset([
        "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", # Hybrid Identity Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7", # Cloud Application Administrator
        "0526716b-113d-4c15-b2c8-68e3c22b9f80", # Authentication Policy Administrator
      ])
    )) == 0])
    error_message = "A Tier-0 (control-plane) role must sit in a tier = 0 group: Tier-1 activation rules would downgrade it."
  }
  validation {
    condition     = alltrue([for g in values(var.pim_tier_groups) : g.tier == 1 || g.require_approval != false])
    error_message = "Tier-0 groups always require approval; require_approval = false is only valid on tier = 1."
  }
  validation {
    # Learn "Roles that can be assigned with administrative unit scope"
    # (manage-roles-portal.md, read 2026-10-20) - the subset this lab uses.
    condition = alltrue([for g in values(var.pim_tier_groups) : !g.au_scoped || alltrue([
      for id in concat([g.role_template_id], g.additional_role_template_ids) : contains([
        "c4e39bd9-1100-46d3-8c65-fb160da0071f", # Authentication Administrator
        "729827e3-9c14-49f7-bb1b-9608f156bbb8", # Helpdesk Administrator
        "966707d0-3269-4727-9be2-8c3a10f19b9d", # Password Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
        "fdd7a751-b60b-444a-984c-02652fe8fa1c", # Groups Administrator
        "4d6ac14f-3453-41d0-bef9-a3e0c569773a", # License Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
        "69091246-20e8-4a56-aa4d-066075b2a7a8", # Teams Administrator
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
      ], id)
    ])])
    error_message = "au_scoped groups may only hold roles Microsoft allows at administrative-unit scope (Authentication, Helpdesk, Password, User, Groups, License, SharePoint, Teams, Privileged Authentication Administrator)."
  }
  validation {
    condition     = alltrue([for g in values(var.pim_tier_groups) : g.activation_max_duration == null || can(regex("^(PT30M|PT([1-9]|1[0-9]|2[0-3])H(30M)?|P1D)$", coalesce(g.activation_max_duration, "x")))])
    error_message = "activation_max_duration must be null or PT30M..PT23H30M in 30-minute steps, or P1D."
  }
  validation {
    condition     = length(distinct([for g in values(var.pim_tier_groups) : g.display_name])) == length(var.pim_tier_groups) && length(distinct([for g in values(var.pim_tier_groups) : g.mail_nickname])) == length(var.pim_tier_groups)
    error_message = "display_name and mail_nickname must be unique across tier groups (outputs and scripts key on them)."
  }
}

variable "tier0_activation_max_duration" {
  type        = string
  description = "Tier-0 activation cap (contract: 4 hours). Provider accepts PT30M..PT23H30M in 30-minute steps, or P1D. A group may only shorten it (activation_max_duration)."
  default     = "PT4H"

  validation {
    condition     = can(regex("^(PT30M|PT([1-9]|1[0-9]|2[0-3])H(30M)?|P1D)$", var.tier0_activation_max_duration))
    error_message = "Use PT30M..PT23H30M in 30-minute steps, or P1D."
  }
}

variable "tier1_activation_max_duration" {
  type        = string
  description = "Tier-1 activation cap (contract: 8 hours, one shift)."
  default     = "PT8H"

  validation {
    condition     = can(regex("^(PT30M|PT([1-9]|1[0-9]|2[0-3])H(30M)?|P1D)$", var.tier1_activation_max_duration))
    error_message = "Use PT30M..PT23H30M in 30-minute steps, or P1D."
  }
}

# =============================================================================
# Tier-0 activation: Conditional Access authentication context (CA021)
# =============================================================================

variable "tier0_activation_auth_context_id" {
  type        = string
  description = <<-EOT
    Conditional Access authentication context id (e.g. "c1") that a Tier-0
    activation must satisfy INSTEAD of the plain MFA flag: CA021
    (modules/conditional-access, written by post-apply/Set-AuthContextPolicies.ps1)
    requires the admin phishing-resistant strength with sign-in frequency
    "every time" - no compliant-device grant until PAWs exist. Applies to
    every tier = 0 group and to Global Administrator
    (directory_role_pim_policies). Empty (default) = plain MFA.

    KEEP IT EMPTY until CA021 is ENFORCED IN THE TENANT. Learn, PIM for
    Groups role settings (learn.microsoft.com/entra/id-governance/
    privileged-identity-management/groups-role-settings): create and enable
    the CA policy before PIM requires the context; the MFA backup "isn't
    triggered if the Conditional Access policy is turned off, is in
    report-only mode, or has an eligible user excluded" - so a context
    behind a report-only CA021 means NO step-up. A precondition refuses a
    non-empty value unless activation_auth_context_ca_enforced = true, which
    modules/conditional-access sets only when CA021 is declared enabled AND
    attested in the tenant (ca021_enforced_in_tenant).

    SWITCHING AN EXISTING TIER-0 POLICY FROM MFA TO THE CONTEXT = TWO APPLIES
    (azuread 3.10.0 source: both activation arguments are Optional+Computed,
    so leaving one null keeps its PRIOR state value and the Enablement rule
    is never re-sent - Graph would keep MultiFactorAuthentication and may
    reject the change; the reverse switch leaves c1 enabled):
      Apply 1: tier0_auth_context_switchover_step1 = true, this variable
               still "" -> Tier 0 sends require_multifactor_authentication
               = false. Tier-0 activation now needs approval + justification
               (+ ticket) but NO step-up: run apply 2 straight after, with
               no Tier-0 activation pending (approvers deny any that arrive).
      Apply 2: this variable = "c1" -> the context replaces MFA (MFA is then
               null/unset, as the provider's ConflictsWith requires).
    Back to MFA: set "" and switchover false in one apply. Per the provider
    source above, that apply sends MFA but leaves the context rule ENABLED
    (Optional+Computed keeps the prior value), so activation stays on the
    context - stricter, not weaker - until you switch the
    AuthenticationContext_EndUser_Assignment rule off through Graph or the
    portal (verify: on the first tenant run whether Graph then needs both).
    A brand-new policy (first apply) can take "c1" directly.
  EOT
  default     = ""

  validation {
    # Graph allows c1..c25; Learn says up to c99 (unverified which applies),
    # so the stricter bound - accepted by both.
    condition     = var.tier0_activation_auth_context_id == "" || can(regex("^c([1-9]|1[0-9]|2[0-5])$", var.tier0_activation_auth_context_id))
    error_message = "tier0_activation_auth_context_id must be empty or an authentication context id c1..c25."
  }
}

variable "activation_auth_context_ca_enforced" {
  type        = bool
  description = <<-EOT
    true only when the CA policy that targets the context (CA021) is
    ENFORCED in the tenant. Wire it from modules/conditional-access output
    pim_activation_auth_context_ready (declared "enabled" AND attested by
    ca021_enforced_in_tenant); never hand-set it to true. Gates
    tier0_activation_auth_context_id and tier0_auth_context_switchover_step1.
  EOT
  default     = false
}

variable "tier0_auth_context_switchover_step1" {
  type        = bool
  description = "Apply 1 of the two-apply MFA -> auth-context switch (see tier0_activation_auth_context_id). Requires activation_auth_context_ca_enforced. A check warns while it leaves Tier 0 without a step-up."
  default     = false
}

# =============================================================================
# Help-desk scoping: administrative unit (helpdesk.tf) - OPTIONAL, off
# =============================================================================

variable "enable_helpdesk_au_scoping" {
  type        = bool
  description = <<-EOT
    Create AU-Workforce-Standard and assign the roles of every au_scoped tier
    group (default: PIM-Tier1-Helpdesk = Helpdesk + Authentication
    Administrator) at THAT scope instead of tenant-wide. Needs
    enable_pim_tiers. Licence: Entra ID P1 per AU administrator; a DYNAMIC
    AU rule needs P1 per member.
  EOT
  default     = false
}

variable "workforce_au_display_name" {
  type        = string
  description = "Display name of the help-desk scope administrative unit."
  default     = "AU-Workforce-Standard"
}

variable "workforce_au_membership_rule" {
  type        = string
  description = <<-EOT
    Dynamic membership rule rendered into output workforce_au_membership_body
    (the provider has no membershipType/membershipRule; applying it is a
    Graph PATCH, a TENANT-TIME step). Default: HR-provisioned members only
    (an employeeId), never an adm- admin account. Break-glass and service
    accounts carry no employeeId. verify: employeeId is populated by the
    inbound provisioning + Cloud Sync path; -notStartsWith is accepted in AU
    rules.
  EOT
  default     = "(user.userType -eq \"Member\") -and (user.employeeId -ne null) -and (user.userPrincipalName -notStartsWith \"adm-\")"
}

variable "workforce_au_excluded_employee_ids" {
  type        = list(string)
  description = <<-EOT
    HR employee ids (employeeId) kept OUT of AU-Workforce-Standard: the VIPs
    that post-apply/New-RestrictedAdminUnit.ps1 puts in the restricted
    management AU (RMAU-VIP). Rendered in output workforce_au_membership_body
    as (<workforce_au_membership_rule>) -and (user.employeeId -notIn [...]).
    WHY BOTH: the RMAU alone already stops the help desk (an RMAU member can
    be changed only by roles scoped to THAT RMAU - Learn, "Restricted
    management administrative units", Who can modify objects), but leaving a
    VIP in the help desk's own AU makes its member list say the opposite of
    the design and would hand the VIP straight back to the help desk if the
    RMAU were ever deleted. Keyed on employeeId (HR's key, written by the
    inbound provisioning path) rather than UPN, so no tenant domain sits in
    a tfvars file. Default empty = rule unchanged.
  EOT
  default     = []

  validation {
    condition     = alltrue([for id in var.workforce_au_excluded_employee_ids : can(regex("^[A-Za-z0-9-]{1,32}$", id))])
    error_message = "workforce_au_excluded_employee_ids: HR employee ids only (letters, digits, '-'; at most 32) - they are embedded in a dynamic membership rule."
  }
}

# =============================================================================
# Global Administrator: direct eligibility policy (directory-roles.tf) - OFF
# =============================================================================

variable "enable_global_admin_pim_policy" {
  type        = bool
  description = <<-EOT
    Render output directory_role_pim_policies: the Graph rule bodies for the
    Global Administrator role's own PIM policy (activation: approval by
    PIM-Approvers-Tier0, MFA or the Tier-0 auth context, justification,
    ticket, global_admin_activation_max_duration; eligibility expires after
    global_admin_eligible_duration; admin notifications). azuread 3.10 has no
    directory-role policy resource, so post-apply/Set-DirectoryRolePimPolicies.ps1
    PATCHes them and grants NAMED, expiring eligibility. Break-glass keeps
    its standing assignment (modules/groups).
  EOT
  default     = false
}

variable "global_admin_activation_max_duration" {
  type        = string
  description = "Global Administrator activation cap: 2h (privileged-access standard; the standard's Tier-0 cap is 4h, with 2h for Global Administrator and Privileged Authentication Administrator). Never longer than tier0_activation_max_duration (precondition)."
  default     = "PT2H"

  validation {
    condition     = can(regex("^(PT30M|PT([1-9]|1[0-9]|2[0-3])H(30M)?|P1D)$", var.global_admin_activation_max_duration))
    error_message = "Use PT30M..PT23H30M in 30-minute steps, or P1D."
  }
}

variable "global_admin_eligible_duration" {
  type        = string
  description = "How long a named person's Global Administrator eligibility lives (Expiration_Admin_Eligibility; the eligibility request uses the same afterDuration)."
  default     = "P180D"

  validation {
    condition     = contains(["P15D", "P30D", "P90D", "P180D"], var.global_admin_eligible_duration)
    error_message = "Global Administrator eligibility must expire within 180 days: P15D, P30D, P90D or P180D."
  }
}

# =============================================================================
# Review of PIM-eligible membership (reviews.tf)
# =============================================================================

variable "privileged_review_reviewer_group_object_id" {
  type        = string
  description = "Governance group that reviews PIM-eligible + active membership (never one of the reviewed groups). Empty => privileged_review_fallback_group_object_id."
  default     = ""
}

variable "privileged_review_fallback_group_object_id" {
  type        = string
  description = "Mandatory fallback reviewer group (Learn: reviews of PIM-governed groups need one). Empty => output pim_eligible_review_bodies is {} - default-deny without a fallback could revoke everything nobody answered."
  default     = ""
}

variable "privileged_review_instance_duration_days" {
  type        = number
  description = "Days each quarterly review instance stays open (ADR 0012, T1: 14)."
  default     = 14

  validation {
    condition     = var.privileged_review_instance_duration_days >= 1 && var.privileged_review_instance_duration_days <= 90 && floor(var.privileged_review_instance_duration_days) == var.privileged_review_instance_duration_days
    error_message = "privileged_review_instance_duration_days must be a whole number of days, 1..90."
  }
}

variable "privileged_review_start_date" {
  type        = string
  description = "YYYY-MM-DD for recurrence.range.startDate. Empty => null (the post-apply script uses today's UTC date; timestamp() would change the output on every plan)."
  default     = ""

  validation {
    condition     = var.privileged_review_start_date == "" || can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.privileged_review_start_date))
    error_message = "privileged_review_start_date must be empty or YYYY-MM-DD."
  }
}

# =============================================================================
# PIM for Azure resources (azure.tf) - OPTIONAL, off by default
# =============================================================================

variable "enable_pim_azure_resources" {
  type        = bool
  description = <<-EOT
    Make a role-assignable group ELIGIBLE for an Azure role (default
    Contributor) on the lab resource group, with an MFA + justification +
    approval activation policy (approvers: PIM-Approvers-Tier0). Needs
    azure_pim_scope_id, Entra ID P2 for the eligible people, and Owner /
    User Access Administrator for whoever applies it (the CI APPLY identity
    lacks roleEligibilityScheduleRequests write - see README.md).
  EOT
  default     = false
}

variable "azure_pim_scope_id" {
  type        = string
  description = "Resource id of the lab resource group the eligible assignment and policy apply to (/subscriptions/<sub>/resourceGroups/<name>)."
  default     = ""

  validation {
    condition     = var.azure_pim_scope_id == "" || can(regex("^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+$", var.azure_pim_scope_id))
    error_message = "azure_pim_scope_id must be empty or a resource group id: /subscriptions/<guid>/resourceGroups/<name>."
  }
}

variable "azure_pim_role_definition_guid" {
  type        = string
  description = "Azure built-in role definition GUID made eligible. Default Contributor (b24988ac-..., Azure built-in roles reference)."
  default     = "b24988ac-6180-42a0-ab88-20f7382dd24c"

  validation {
    # Owner / User Access Administrator / RBAC Administrator can grant
    # access: eligibility for them would be a JIT path to permanent access.
    condition = can(regex("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", var.azure_pim_role_definition_guid)) && !contains([
      "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
      "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", # User Access Administrator
      "f58310d9-a9f6-439a-9e8d-f62e7b41a168", # Role Based Access Control Administrator
    ], var.azure_pim_role_definition_guid)
    error_message = "azure_pim_role_definition_guid must be a lowercase role GUID and not a role that can grant access (Owner, User Access Administrator, RBAC Administrator)."
  }
}

variable "azure_pim_group_name" {
  type        = string
  description = "Display name of the group made eligible for the Azure role."
  default     = "PIM-Azure-RG-Contributors"
}

variable "azure_pim_group_mail_nickname" {
  type        = string
  description = "mail_nickname (stable lookup key for scripts) of the Azure PIM group."
  default     = "pim-azure-rg-contributors"
}

variable "azure_pim_activation_max_duration" {
  type        = string
  description = "Azure activation cap. Tier-0 strength by default (the RG holds the DC): PT4H."
  default     = "PT4H"

  validation {
    condition     = can(regex("^(PT30M|PT([1-9]|1[0-9]|2[0-3])H(30M)?|P1D)$", var.azure_pim_activation_max_duration))
    error_message = "Use PT30M..PT23H30M in 30-minute steps, or P1D."
  }
}

variable "azure_pim_require_approval" {
  type        = bool
  description = "Require approval (PIM-Approvers-Tier0) to activate the Azure role (default true: Contributor over the DC's RG is Tier 0)."
  default     = true
}

# =============================================================================
# AWS administration through PIM for Groups (aws.tf) - OPTIONAL, off by default
# =============================================================================

variable "enable_pim_aws_admin" {
  type        = bool
  description = <<-EOT
    Create PIM-AWS-Lab-Admins: a role-assignable group whose ELIGIBLE-only
    membership is administrator of the lab AWS account (envs/dev assigns it
    to the AWS IAM Identity Center app; lab/terraform/aws gives the
    SCIM-created copy the LabAdministrator permission set). Activation: MFA +
    justification, aws_admin_activation_max_duration, mailed to
    pim_alert_mailbox. ADR 0025.
  EOT
  default     = false
}

variable "aws_admin_group_name" {
  type        = string
  description = "Display name of the AWS admin PIM group. lab/terraform/aws looks the SCIM-created copy up by this exact name (var.lab_admin_group_display_name there)."
  default     = "PIM-AWS-Lab-Admins"
}

variable "aws_admin_group_mail_nickname" {
  type        = string
  description = "mail_nickname (stable lookup key for scripts, e.g. Set-PimGroupEligibility.ps1 -GroupMailNickname) of the AWS admin PIM group."
  default     = "pim-aws-lab-admins"
}

variable "aws_admin_activation_max_duration" {
  type        = string
  description = <<-EOT
    How long one activation of PIM-AWS-Lab-Admins lasts. Default PT2H: long
    enough for one change and its check, short enough that nobody keeps AWS
    admin "for the day". Capped at PT4H. The AWS permission set's session
    (lab/terraform/aws, PT1H) must stay shorter than this.
  EOT
  default     = "PT2H"

  validation {
    condition     = contains(["PT30M", "PT1H", "PT1H30M", "PT2H", "PT3H", "PT4H"], var.aws_admin_activation_max_duration)
    error_message = "aws_admin_activation_max_duration must be PT30M, PT1H, PT1H30M, PT2H, PT3H or PT4H (AWS admin is never a shift-length activation)."
  }
}

variable "aws_admin_require_approval" {
  type        = bool
  description = <<-EOT
    Require approval (PIM-Approvers-Tier0) to activate PIM-AWS-Lab-Admins.
    Default false while the lab has ONE human admin: PIM never lets a
    requester approve their own request, so approval would need a second
    person. Every activation is mailed to pim_alert_mailbox instead
    (ADR 0025). Turn on when a second admin exists.
  EOT
  default     = false
}

variable "aws_admin_eligible_assignment_duration" {
  type        = string
  description = "How long an ELIGIBLE membership of PIM-AWS-Lab-Admins lives before renewal. Admin of the AWS management account is Tier 0 for AWS: 180 days at most."
  default     = "P180D"

  validation {
    condition     = contains(["P15D", "P30D", "P90D", "P180D"], var.aws_admin_eligible_assignment_duration)
    error_message = "AWS admin eligibility must expire within 180 days: P15D, P30D, P90D or P180D."
  }
}

# =============================================================================
# Read-only presenter access through PIM for Groups (demo-readers.tf) - OFF
# =============================================================================

variable "enable_pim_demo_readers" {
  type        = bool
  description = <<-EOT
    Create PIM-Demo-Readers: a role-assignable group that ACTIVELY holds
    Global Reader + Security Reader tenant-wide, whose membership is
    ELIGIBLE-only (MFA + justification, demo_readers_activation_max_duration,
    no approval, every activation mailed to pim_alert_mailbox; eligibility
    expires after tier1_eligible_assignment_duration). Reviewed quarterly,
    NOT in privileged_review_targets (the CA002 / CA020 group scope). The
    group's Azure RBAC (Reader, Microsoft Sentinel Reader, Log Analytics
    Reader on the subscription) is granted by envs/bootstrap, human-applied.
  EOT
  default     = false
}

variable "demo_readers_group_name" {
  type        = string
  description = "Display name of the read-only presenter PIM group."
  default     = "PIM-Demo-Readers"
}

variable "demo_readers_group_mail_nickname" {
  type        = string
  description = "mail_nickname (stable lookup key: Set-PimGroupEligibility.ps1 -GroupMailNickname, admin-accounts.json eligibleFor) of the read-only presenter PIM group."
  default     = "pim-demo-readers"
}

variable "demo_readers_activation_max_duration" {
  type        = string
  description = <<-EOT
    How long one activation of PIM-Demo-Readers lasts. Default PT8H: one
    working day of demo and rehearsal, the Tier-1 shift. Never longer than
    PT8H (validation) or tier1_activation_max_duration (precondition).
  EOT
  default     = "PT8H"

  validation {
    condition     = can(regex("^(PT30M|PT[1-7]H(30M)?|PT8H)$", var.demo_readers_activation_max_duration))
    error_message = "demo_readers_activation_max_duration must be PT30M..PT8H in 30-minute steps (read-only access is never longer than a shift)."
  }
}
