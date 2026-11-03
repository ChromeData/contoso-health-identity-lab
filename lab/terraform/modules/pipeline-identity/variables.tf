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
    "AdministrativeUnit.Read.All",            # READ-only: plan must list AUs for the help-desk scoping (modules/pim/helpdesk.tf). Proven 2026-10-27: 403 Authorization_RequestDenied on the first Day-2 plan without it.
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
    "EntitlementManagement.ReadWrite.All",         # catalog, packages, policies; also the automatic assignment policies terraform-apply.yml writes after the apply (post-apply/Set-AutoAssignmentPolicies.ps1 -UseAzureCliToken, whose user/group reads User/Group.ReadWrite.All cover)
    "RoleManagement.ReadWrite.Directory",          # role-assignable groups + role assignments
    "RoleManagementPolicy.ReadWrite.AzureADGroup", # PIM-for-Groups activation policy
    "AdministrativeUnit.ReadWrite.All",            # AU-Workforce-Standard + the AU-scoped Helpdesk / Authentication Administrator assignments (enable_helpdesk_au_scoping)
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

# -----------------------------------------------------------------------------
# HR-SYNC identity (opt-in): .github/workflows/hr-feed.yml uploads changed HR
# rows to the API-driven inbound provisioning app. See main.tf for the
# permission reasoning and the trust boundary.
# -----------------------------------------------------------------------------
variable "hr_sync_enabled" {
  type        = bool
  description = "Create the HR-SYNC app registration, service principal, federated credential (hr_sync_branch) and its Graph roles. Off by default: a new identity that can create and disable workforce accounts is a deliberate, human bootstrap apply."
  default     = false
}

variable "hr_sync_app_display_name" {
  type        = string
  description = "Display name of the HR-SYNC app registration."
  default     = "HR-SYNC (gh-oidc hr-feed upload)"
}

variable "hr_sync_branch" {
  type        = string
  description = "The ONLY branch whose runs may sign in as HR-SYNC: subject repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/<this>. Protect it with a ruleset (only the HR owner pushes)."
  default     = "hr-feed"

  # Never main: every workflow on main could then upload HR data. A plain
  # branch name, not a ref path or a wildcard (Entra matches the subject
  # exactly anyway, so '*' would simply never match).
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$", var.hr_sync_branch)) && !contains(["main", "master"], var.hr_sync_branch) && !startswith(var.hr_sync_branch, "refs/")
    error_message = "hr_sync_branch must be a dedicated branch name (not main/master, not a refs/ path, no wildcards)."
  }
}

variable "hr_provisioning_app_client_id" {
  type        = string
  description = "Client (app) id of the API-driven inbound provisioning app (lab/scripts/mock-hr/New-InboundProvisioningApp.ps1). Needed when hr_sync_upload_scope = \"owned\": HR-SYNC becomes an owner of that app. Empty otherwise."
  default     = ""

  validation {
    condition     = var.hr_provisioning_app_client_id == "" || can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.hr_provisioning_app_client_id))
    error_message = "hr_provisioning_app_client_id must be a GUID (the provisioning app's client id) or empty."
  }
}

variable "hr_sync_upload_scope" {
  type        = string
  description = <<-EOT
    Which bulkUpload application permission HR-SYNC gets:
      "owned"  SynchronizationData-User.Upload.OwnedBy (least privileged):
               only provisioning apps HR-SYNC owns; HR-SYNC is made an owner
               of the app named by hr_provisioning_app_client_id.
      "tenant" SynchronizationData-User.Upload: every API-driven
               provisioning app in the tenant. Use only if "owned" is proven
               not to work (verify note in main.tf).
  EOT
  default     = "owned"

  validation {
    condition     = contains(["owned", "tenant"], var.hr_sync_upload_scope)
    error_message = "hr_sync_upload_scope must be \"owned\" or \"tenant\"."
  }
}

variable "hr_sync_log_read_graph_roles" {
  type        = list(string)
  description = "Read-only Graph APPLICATION roles HR-SYNC uses to read the provisioning log for the run summary. Default AuditLog.Read.All (the GET /auditLogs/provisioning page also lists Directory.Read.All; add it only if the first run proves it is needed). ProvisioningLog.Read.All is the narrower candidate (verify)."
  default     = ["AuditLog.Read.All"]

  # Same allow-list shape as extra_plan_graph_roles: read verbs only, so this
  # list can never become a second write path for HR-SYNC.
  validation {
    condition = alltrue([
      for r in var.hr_sync_log_read_graph_roles :
      can(regex("^[A-Za-z]+(\\.[A-Za-z]+)*\\.(Read|ReadBasic)(\\.(All|Directory|AzureADGroup|OwnedBy|Hidden))?$", r))
    ])
    error_message = "hr_sync_log_read_graph_roles accepts read-only roles only (<Resource>.Read[Basic][.All|...]); the upload permission comes from hr_sync_upload_scope."
  }
}

# -----------------------------------------------------------------------------
# EVIDENCE identity (opt-in): .github/workflows/evidence-pack.yml exports the
# evidence pack (read-only Graph) and files it in the WORM evidence store.
# See main.tf for each role's use and the trust boundary.
# -----------------------------------------------------------------------------
variable "evidence_enabled" {
  type        = bool
  description = "Create the EVIDENCE app registration, service principal, federated credential (ref:refs/heads/main) and its read-only Graph roles. Off by default: a new identity is a deliberate, human bootstrap apply. Its storage grant is made in envs/bootstrap."
  default     = false
}

variable "evidence_app_display_name" {
  type        = string
  description = "Display name of the EVIDENCE app registration."
  default     = "EVIDENCE (gh-oidc evidence pack)"
}

variable "evidence_graph_roles" {
  type        = list(string)
  description = "Read-only Graph APPLICATION roles EVIDENCE exports the evidence pack with: the six Export-EvidencePack.ps1 reads (main.tf lists what each covers). Read roles only (validated)."
  default = [
    "AuditLog.Read.All",
    "AccessReview.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "PrivilegedAssignmentSchedule.Read.AzureADGroup",
    "Directory.Read.All",
  ]

  # Same allow-list shape as extra_plan_graph_roles: read verbs only, so this
  # list can never become a write path into the tenant.
  validation {
    condition = alltrue([
      for r in var.evidence_graph_roles :
      can(regex("^[A-Za-z]+(\\.[A-Za-z]+)*\\.(Read|ReadBasic)(\\.(All|Directory|AzureADGroup|OwnedBy|Hidden))?$", r))
    ])
    error_message = "evidence_graph_roles accepts read-only roles only (<Resource>.Read[Basic][.All|.Directory|.AzureADGroup|.OwnedBy|.Hidden]); the evidence pack never changes the tenant."
  }
}
