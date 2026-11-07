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

variable "hr_provisioning_owner_object_ids" {
  type        = list(string)
  description = "Entra USER object ids added as owners of the HR provisioning app's registration (modules/pipeline-identity; ADR 0018: two people, never the access governance lead - SOD-08). The CI identities themselves never get an Entra owner. Who and why: lab/iga/nhi-owners.json. Not sensitive: this root is applied locally and never planned in a pull request."
  default     = []
}

variable "enable_pim_demo_readers_azure_rbac" {
  type        = bool
  description = <<-EOT
    Grant PIM-Demo-Readers (envs/dev enable_pim_demo_readers) Reader,
    Microsoft Sentinel Reader and Log Analytics Reader on this subscription.
    Its members are eligible-only (PIM for Groups), so nobody holds the roles
    at rest. Here, not in envs/dev, because the APPLY identity may only hand
    out delegable_role_ids (main.tf). Needs pim_demo_readers_group_object_id.
    Off by default.
  EOT
  default     = false
}

variable "pim_demo_readers_group_object_id" {
  type        = string
  description = "Object id of PIM-Demo-Readers: terraform -chdir=../dev output -raw pim_demo_readers_group_object_id. Required with enable_pim_demo_readers_azure_rbac. Must be the role-assignable PIM group, never a person."
  default     = ""

  validation {
    condition     = var.pim_demo_readers_group_object_id == "" || can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.pim_demo_readers_group_object_id))
    error_message = "pim_demo_readers_group_object_id must be empty or a lowercase group object id (GUID)."
  }
}

variable "enable_azure_guardrails" {
  type        = bool
  description = <<-EOT
    Assign the two Azure Policy guardrails (modules/azure-guardrails) to the
    subscription: no new standing Owner, and Key Vaults keep deletion
    protection. Both start in Audit (standing_owner_effect,
    keyvault_protection_effect). Off by default.
  EOT
  default     = false
}

variable "standing_owner_effect" {
  type        = string
  description = "Audit (default), Deny or Disabled for the no-new-standing-Owner guardrail. Switch to Deny only after reading the Audit results; Deny needs owner_allowed_principal_ids."
  default     = "Audit"

  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.standing_owner_effect)
    error_message = "standing_owner_effect must be exactly Audit, Deny or Disabled."
  }
}

variable "keyvault_protection_effect" {
  type        = string
  description = "Audit (default), Deny or Disabled for the Key Vault deletion-protection guardrail."
  default     = "Audit"

  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.keyvault_protection_effect)
    error_message = "keyvault_protection_effect must be exactly Audit, Deny or Disabled."
  }
}

variable "owner_allowed_principal_ids" {
  type        = list(string)
  description = <<-EOT
    Object ids that may still be given Owner on the subscription: the lab
    owner's account and the lab operator's service principal. Read them with
    az role assignment list --scope /subscriptions/<id> --role Owner --query "[].principalId" -o tsv
    Keep the real values in terraform.tfvars (gitignored).
  EOT
  default     = []
}

# ---- Pipeline config vault (pipeline-config.tf) -------------------------------

variable "enable_pipeline_config_vault" {
  type        = bool
  description = <<-EOT
    Create the pipeline config Key Vault (pipeline-config.tf): the five privacy
    values the Terraform workflows read at run time over GitHub OIDC instead of
    from GitHub secrets. PLAN and APPLY get Key Vault Secrets User on it; the
    values are written by the operator or a human Secrets Officer
    (lab/scripts/operator/set-pipeline-config.sh). Off by default.
  EOT
  default     = false
}

variable "pipeline_config_vault_name" {
  type        = string
  description = "Globally unique name of the pipeline config vault (3-24 letters, digits, dashes), e.g. kv-idlab-cicd-20f1. Must equal the workflows' vars.TF_PIPELINE_CONFIG_VAULT (default kv-idlab-cicd-20f1)."
  default     = ""
}

variable "pipeline_config_writer_object_ids" {
  type        = list(string)
  description = "Object ids (humans) given Key Vault Secrets Officer on the pipeline config vault to seed the five values; after-signup.sh puts the setup admin here. Empty = writers come from a wider grant (the lab operator holds Secrets Officer at subscription scope)."
  default     = []

  validation {
    condition     = alltrue([for id in var.pipeline_config_writer_object_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "pipeline_config_writer_object_ids must be object id GUIDs."
  }
}

variable "pipeline_config_resource_group_name" {
  type        = string
  description = "Resource group for the pipeline config vault. Its own RG: the tfstate RG is ReadOnly-locked and rg-identity-lab belongs to envs/dev's APPLY identity."
  default     = "rg-identity-lab-cicd"
}

variable "pipeline_config_location" {
  type        = string
  description = "Azure region of the pipeline config vault."
  default     = "eastus2"
}
