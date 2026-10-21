# =============================================================================
# envs/bootstrap :: variables.tf
# =============================================================================

variable "subscription_id" {
  type        = string
  description = "Azure subscription the lab deploys into. Empty = ARM_SUBSCRIPTION_ID / az CLI default."
  default     = ""
}

variable "tenant_id" {
  type        = string
  description = "Entra ID tenant id. Empty = inherit from the ambient credentials."
  default     = ""
}

# ---- GitHub OIDC trust ------------------------------------------------------

variable "github_owner" {
  type        = string
  description = "GitHub user/org owning the PUBLIC lab repo (OWNER in repo:OWNER@OWNER-ID/REPO@REPO-ID)."
}

variable "github_repo" {
  type        = string
  description = "Public lab repo name (REPO in repo:OWNER@OWNER-ID/REPO@REPO-ID)."
  default     = "contoso-health-identity-lab"
}

variable "github_owner_id" {
  type        = string
  description = "Numeric id of github_owner (OWNER-ID in repo:OWNER@OWNER-ID/REPO@REPO-ID). After the repo exists: gh api repos/OWNER/REPO --jq '.owner.id'"
}

variable "github_repo_id" {
  type        = string
  description = "Numeric id of github_repo (REPO-ID in repo:OWNER@OWNER-ID/REPO@REPO-ID). After the repo exists: gh api repos/OWNER/REPO --jq '.id'"
}

variable "prod_environment_name" {
  type        = string
  description = "Protected GitHub environment gating the APPLY identity."
  default     = "prod"
}

# ---- Remote state the CI identities need ------------------------------------

variable "tfstate_resource_group_name" {
  type        = string
  description = "Resource group of the versioned state storage account."
  default     = "rg-identity-lab-tfstate"
}

variable "tfstate_storage_account_name" {
  type        = string
  description = "Name of the versioned state storage account (globally unique)."
}

variable "tfstate_container_name" {
  type        = string
  description = "Container holding envs/dev state - the ONLY container CI may touch."
  default     = "tfstate"
}

# ---- Optional: Azure OpenAI for the AI review step --------------------------

variable "azure_openai_resource_id" {
  type        = string
  description = <<-EOT
    Resource id of the Azure OpenAI account used by ai-review.yml. When set,
    the PLAN identity gets "Cognitive Services OpenAI User" on it (data-plane
    inference only). Empty = skip (create the resource first, then re-apply).
  EOT
  default     = ""
}

# ---- Tenant logging ---------------------------------------------------------

variable "log_analytics_workspace_id" {
  type        = string
  description = <<-EOT
    Resource id of loga-idlab (envs/dev output log_analytics_workspace_id).
    When set, the tenant-level Entra diagnostic setting streams sign-in, audit
    and provisioning logs there. Empty = skip (first bootstrap run, before
    envs/dev has created the workspace). Needs Entra P1/P2 for sign-in logs.
  EOT
  default     = ""
}

# ---- Opt-in widenings (each one a deliberate, human bootstrap apply) ----------

variable "enable_app_management_roles" {
  type        = bool
  description = <<-EOT
    Grant the pipeline the Graph roles modules/apps needs (envs/dev
    enable_sso_apps): APPLY gets Application.ReadWrite.OwnedBy,
    Application.Read.All, Policy.ReadWrite.ApplicationConfiguration and
    AppRoleAssignment.ReadWrite.All; PLAN gets Application.Read.All and
    Synchronization.Read.All. AppRoleAssignment.ReadWrite.All can grant ANY
    app role (Graph roles included), so it is Tier 0 like
    RoleManagement.ReadWrite.Directory: flip only when the SSO apps are due,
    and record it in the APPLY risk acceptance. Off by default.
  EOT
  default     = false
}

variable "enable_identity_protection_logs" {
  type        = bool
  description = <<-EOT
    Add the Identity Protection categories to the Entra diagnostic setting:
    RiskyUsers + UserRiskEvents (feed lab/kql/identity-risk.kql, the ITDR
    identity_risk rule) and RiskyServicePrincipals +
    ServicePrincipalRiskEvents (workload-identity risk for the NHI story).
    Needs Entra ID P2 (M365 E5 trial) and log_analytics_workspace_id. Off by
    default: with no P2 the tables stay empty and Sentinel rejects the rule.
  EOT
  default     = false
}
