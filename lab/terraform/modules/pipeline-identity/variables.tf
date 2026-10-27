# =============================================================================
# modules/pipeline-identity :: variables.tf
# =============================================================================

variable "github_owner" {
  type        = string
  description = "GitHub org/user that owns the IaC repo (the OWNER in repo:OWNER@OWNER-ID/REPO@REPO-ID)."

  validation {
    condition     = can(regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", var.github_owner))
    error_message = "github_owner must be a GitHub user/org name."
  }
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name holding this Terraform (the REPO in repo:OWNER@OWNER-ID/REPO@REPO-ID)."

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,100}$", var.github_repo))
    error_message = "github_repo must be a GitHub repository name."
  }
}

# -----------------------------------------------------------------------------
# Immutable GitHub ids for the OIDC subjects (main.tf locals). Numeric and
# assigned once, so they exist only after the repo is created:
#   gh api repos/OWNER/REPO --jq '.owner.id, .id'
# -----------------------------------------------------------------------------
variable "github_owner_id" {
  type        = string
  description = "Numeric id of github_owner (OWNER-ID in repo:OWNER@OWNER-ID/REPO@REPO-ID)."

  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be the numeric owner id: gh api repos/OWNER/REPO --jq '.owner.id'."
  }
}

variable "github_repo_id" {
  type        = string
  description = "Numeric id of github_repo (REPO-ID in repo:OWNER@OWNER-ID/REPO@REPO-ID)."

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repo_id))
    error_message = "github_repo_id must be the numeric repository id: gh api repos/OWNER/REPO --jq '.id'."
  }
}

variable "prod_environment_name" {
  type        = string
  description = <<-EOT
    GitHub Environment gating the APPLY identity. The federated subject becomes
    repo:OWNER@OWNER-ID/REPO@REPO-ID:environment:<this>. Protect this
    environment in GitHub with required reviewers so only approved runs can
    mint a write token.
  EOT
  default     = "prod"
}

variable "plan_app_display_name" {
  type        = string
  description = "Display name of the read-only PLAN app registration."
  default     = "gh-oidc-entra-plan (read-only)"
}

variable "apply_app_display_name" {
  type        = string
  description = "Display name of the write APPLY app registration."
  default     = "gh-oidc-entra-apply (write)"
}

variable "plan_graph_roles" {
  type        = list(string)
  description = <<-EOT
    Microsoft Graph APPLICATION roles granted to the PLAN identity - read-only
    counterparts of the apply roles, enough to refresh every object envs/dev
    manages during `terraform plan`.
  EOT
  default = [
    "User.Read.All",                          # break-glass users
    "Group.Read.All",                         # groups + memberships
    "Policy.Read.All",                        # CA policies, named location, auth strength
    "EntitlementManagement.Read.All",         # catalog, packages, policies
    "RoleManagement.Read.Directory",          # directory role assignments
    "RoleManagementPolicy.Read.AzureADGroup", # PIM-for-Groups activation policy
    "RoleManagementPolicy.Read.Directory",    # PIM directory-role policies: the nightly drift export (ADR 0021)
  ]
}

variable "apply_graph_roles" {
  type        = list(string)
  description = <<-EOT
    Microsoft Graph APPLICATION roles granted to the APPLY identity - exactly
    what envs/dev manages. HIGH PRIVILEGE: RoleManagement.ReadWrite.Directory
    is effectively Tier 0 (it could grant itself Global Admin). Mitigations:
    the identity is only reachable from the reviewer-gated `prod` environment,
    and envs/dev does not manage its OWN app roles, federation or RBAC (those
    live in envs/bootstrap, applied by a human), though as a Tier-0 identity
    it could still escalate out of band. (lab/kql/pim-activation.kql sees PIM
    activations only, not a direct "Add member to role" by an app;
    lab/kql/role-assigned-outside-pim.kql does.)
    No Application.* write role by default: the app-management roles that
    modules/apps needs are added only through extra_apply_graph_roles
    (envs/bootstrap enable_app_management_roles), when the SSO apps are due.
  EOT
  default = [
    "User.ReadWrite.All",                          # break-glass users
    "Group.ReadWrite.All",                         # groups + memberships
    "Policy.Read.All",                             # required alongside CA write
    "Policy.ReadWrite.ConditionalAccess",          # CA policies, named location, auth strength
    "Application.Read.All",                        # READ-only: Graph requires it to set a CA policy's application condition (admin portals: CA005/CA020/CA022). Proven 2026-10-27: 403 "Application.Read.All scope is required to add/edit application condition" without it.
    "EntitlementManagement.ReadWrite.All",         # catalog, packages, policies
    "RoleManagement.ReadWrite.Directory",          # role-assignable groups + role assignments
    "RoleManagementPolicy.ReadWrite.AzureADGroup", # PIM-for-Groups activation policy
  ]
}

# -----------------------------------------------------------------------------
# Opt-in additions, appended to the lists above (distinct). Kept separate so
# the baseline lists stay the reviewed minimum and every widening is a
# visible, named change in envs/bootstrap (a human apply), never a default.
# -----------------------------------------------------------------------------
variable "extra_plan_graph_roles" {
  type        = list(string)
  description = "Additional read-only Microsoft Graph APPLICATION roles for the PLAN identity (e.g. Application.Read.All once envs/dev manages app registrations)."
  default     = []

  # The PLAN identity is reachable from any same-repo pull request: it must
  # never hold a role that CHANGES anything, whatever a caller passes. An
  # ALLOW-list shape, not a deny-list: write-capable Graph roles don't all say
  # "Write" (User.Invite.All, Group.Create, Mail.Send, Sites.Manage.All,
  # User.ManageIdentities.All, User.DeleteRestore.All ...). Accepted: names
  # whose permission verb is exactly Read / ReadBasic, optionally scoped
  # (.All, .Directory, .AzureADGroup, .OwnedBy, .Hidden).
  validation {
    condition = alltrue([
      for r in var.extra_plan_graph_roles :
      can(regex("^[A-Za-z]+(\\.[A-Za-z]+)*\\.(Read|ReadBasic)(\\.(All|Directory|AzureADGroup|OwnedBy|Hidden))?$", r))
    ])
    error_message = "extra_plan_graph_roles accepts read-only roles only (<Resource>.Read[Basic][.All|.Directory|.AzureADGroup|.OwnedBy|.Hidden]); anything else could change the tenant from a pull request."
  }
}

variable "extra_apply_graph_roles" {
  type        = list(string)
  description = "Additional Microsoft Graph APPLICATION roles for the APPLY identity. Every addition widens a Tier-0 identity: record it in the APPLY risk acceptance (lab/docs/risk-register.md)."
  default     = []
}
