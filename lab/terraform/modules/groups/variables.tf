# =============================================================================
# modules/groups :: variables.tf
# =============================================================================

variable "break_glass_domain" {
  type        = string
  description = <<-EOT
    The tenant's initial *.onmicrosoft.com domain, used for the break-glass
    UPNs so emergency access never depends on custom-domain DNS or federation.
  EOT

  validation {
    condition     = endswith(lower(var.break_glass_domain), ".onmicrosoft.com")
    error_message = "break_glass_domain must be the tenant's *.onmicrosoft.com domain."
  }
}

variable "all_nurses_department" {
  type        = string
  description = "Department value that drives the All-Nurses dynamic group rule."
  default     = "Nursing"
}

variable "icu_department" {
  type        = string
  description = "Department value that drives the All-ICU dynamic group rule (mover target)."
  default     = "ICU"
}

variable "break_glass_count" {
  type        = number
  description = "Number of cloud-only break-glass admin accounts (contract = 2)."
  default     = 2

  validation {
    condition     = var.break_glass_count >= 2
    error_message = "Keep at least two break-glass accounts so one can recover the other."
  }
}

variable "tags_note" {
  type        = string
  description = <<-EOT
    Entra ID groups/users do not carry Azure resource tags; this string is
    only surfaced in descriptions so the lab's intent is self-documenting.
  EOT
  default     = "contoso-health-identity-lab"
}

# ---- Optional groups (staging flags; nothing is created while false) --------

variable "enable_nhi_governance" {
  type        = bool
  description = <<-EOT
    Create App-Consent-Reviewers (mail_nickname app-consent-reviewers): the
    reviewers of the admin consent workflow that
    lab/scripts/powershell/post-apply/Set-ConsentPolicy.ps1 turns on. Users
    can no longer consent to unverified or high-impact apps, so someone must
    answer their "Need admin approval" requests. Plain security group - no
    licence needed for the group itself. Root flag: enable_nhi_governance.
  EOT
  default     = false
}

variable "enable_workforce_group" {
  type        = bool
  description = <<-EOT
    Create the dynamic All-Workforce group (mail_nickname all-workforce):
    every enabled, HR-synced MEMBER user. It is the staff target of the
    passkey profile set by post-apply/Set-AuthenticationMethodsPolicy.ps1
    -IncludeStaffRollout - a WORKFORCE group, never "all users", so the
    cloud-only break-glass accounts can never register a synced passkey.
    Dynamic membership needs Entra ID P1. Root flag:
    enable_phishing_resistant_all_users (the same rollout).
  EOT
  default     = false
}
