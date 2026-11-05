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

variable "enable_hr_sync" {
  type        = bool
  description = <<-EOT
    Create HR-SYNC, the identity .github/workflows/hr-feed.yml signs in as
    (GitHub OIDC, subject ...:ref:refs/heads/hr-feed only): upload of HR rows
    to the API-driven inbound provisioning app + provisioning-log read. It can
    create and disable workforce accounts, so protect the hr-feed branch with
    a ruleset first (lab/scripts/mock-hr/README.md). Off by default.
  EOT
  default     = false
}

variable "hr_provisioning_app_client_id" {
  type        = string
  description = "Client (app) id of the HR provisioning app (handback.env: the last segment of HR_PROV_JOB_ID, API2AD.<tenant>.<client id>). HR-SYNC is made its owner when hr_sync_upload_scope = \"owned\"."
  default     = ""
}

variable "hr_sync_upload_scope" {
  type        = string
  description = "\"owned\" (default, least privileged: SynchronizationData-User.Upload.OwnedBy + ownership of the HR provisioning app) or \"tenant\" (SynchronizationData-User.Upload). See modules/pipeline-identity/main.tf."
  default     = "owned"
}

variable "hr_sync_log_read_graph_roles" {
  type        = list(string)
  description = "Read-only Graph roles HR-SYNC reads the provisioning log with (run summary). Default AuditLog.Read.All; add Directory.Read.All only if the first run's summary says the log is not readable. Read roles only (validated in the module)."
  default     = ["AuditLog.Read.All"]
}

variable "enable_evidence_pack" {
  type        = bool
  description = <<-EOT
    Create EVIDENCE, the identity .github/workflows/evidence-pack.yml signs in
    as (GitHub OIDC, subject ...:ref:refs/heads/main only): six read-only Graph
    roles for Export-EvidencePack.ps1, and Storage Blob Data Contributor on the
    evidence container with a create-only ABAC condition (no overwrite, no
    delete). Needs evidence_storage_account_name. Off by default.
  EOT
  default     = false
}

variable "evidence_storage_account_name" {
  type        = string
  description = "The WORM evidence storage account (envs/dev output evidence_storage_account_name; the TF_EVIDENCE_STORAGE_ACCOUNT_NAME repo variable). Required with enable_evidence_pack."
  default     = ""
}

variable "evidence_resource_group_name" {
  type        = string
  description = "Resource group of the evidence storage account (envs/dev: rg-identity-lab)."
  default     = "rg-identity-lab"
}

variable "evidence_container_name" {
  type        = string
  description = "The evidence container EVIDENCE may add files to (modules/evidence-store container_name)."
  default     = "evidence"
}

variable "pipeline_owner_object_ids" {
  type = object({
    plan     = optional(list(string), [])
    apply    = optional(list(string), [])
    hr_sync  = optional(list(string), [])
    evidence = optional(list(string), [])
    # Human owners of the HR provisioning app HR-SYNC uploads to (made by
    # lab/scripts/mock-hr/New-InboundProvisioningApp.ps1, looked up by client
    # id); only used while HR-SYNC owns it (hr_sync_upload_scope = "owned").
    hr_provisioning = optional(list(string), [])
  })
  description = "Accountable human owners (Entra USER object ids) of each CI identity, app registration + service principal, and of the HR provisioning app (modules/pipeline-identity owner_object_ids; ADR 0018: two people, Tier-0 identities only Tier-0 people). Who and why: lab/iga/nhi-owners.json. Empty list = no owners change planned for that identity. Not sensitive: this root is applied locally and never planned in a pull request (see the module variable)."
  default     = {}
}
