# =============================================================================
# envs/bootstrap :: main.tf
# -----------------------------------------------------------------------------
# The trust anchor of the pipeline, applied LOCALLY by a human admin - once,
# and again only when the pipeline's own permissions must change.
#
#   * GitHub OIDC PLAN + APPLY app registrations (modules/pipeline-identity),
#     the opt-in HR-SYNC app for .github/workflows/hr-feed.yml and the opt-in
#     EVIDENCE app for .github/workflows/evidence-pack.yml (with its one
#     create-only grant on the WORM evidence container)
#   * Their Azure RBAC: what each may do to the subscription and to state
#   * The tenant's Entra diagnostic setting (modules/entra-diagnostics): no
#     envs/dev PR can edit or remove the log export
#
# Why a separate root: the identities CI runs as must not be managed BY that
# CI. If envs/dev owned them, a PR could widen the APPLY identity's Graph
# roles or federation subject. Here, every change to them (and to the tenant
# log export) is a deliberate, human, out-of-band apply.
#
# This is a CHANGE-CONTROL boundary, not a privilege boundary. APPLY is still
# Tier 0: RoleManagement.ReadWrite.Directory lets it assign itself any
# directory role (Security Administrator is enough to delete the diagnostic
# setting; Global Administrator is everything), and subscription Contributor
# lets it delete or cap loga-idlab, which envs/dev owns. What keeps PR code
# away from APPLY is the reviewer-gated `prod` environment and its
# environment-scoped OIDC subject - not this file.
#
# Chicken-and-egg solved: bootstrap first (local), then envs/dev via CI.
# =============================================================================

data "azurerm_subscription" "current" {}

# -----------------------------------------------------------------------------
# Entra side: the two OIDC identities + their Graph app roles.
# -----------------------------------------------------------------------------
module "pipeline_identity" {
  source = "../../modules/pipeline-identity"

  github_owner          = var.github_owner
  github_repo           = var.github_repo
  github_owner_id       = var.github_owner_id
  github_repo_id        = var.github_repo_id
  prod_environment_name = var.prod_environment_name

  # Opt-in: app-management roles for modules/apps (envs/dev enable_sso_apps).
  extra_apply_graph_roles = var.enable_app_management_roles ? local.app_management_apply_roles : []
  extra_plan_graph_roles  = var.enable_app_management_roles ? local.app_management_plan_roles : []

  # Opt-in: HR-SYNC, the hr-feed branch's identity (HR rows -> bulkUpload,
  # provisioning-log read). No Azure RBAC at all: hr-feed.yml signs in with
  # allow-no-subscriptions and only calls Microsoft Graph.
  hr_sync_enabled               = var.enable_hr_sync
  hr_provisioning_app_client_id = var.hr_provisioning_app_client_id
  hr_sync_upload_scope          = var.hr_sync_upload_scope
  hr_sync_log_read_graph_roles  = var.hr_sync_log_read_graph_roles

  # Opt-in: EVIDENCE, evidence-pack.yml's identity (main ref only): read-only
  # Graph for the evidence pack. Its only Azure right is the create-only
  # grant on the evidence container below.
  evidence_enabled = var.enable_evidence_pack

  # Human owners of the HR provisioning app's registration (ADR 0018). The CI
  # identities get none: their accountable owner is a role in
  # lab/iga/nhi-owners.json. Keep the list in terraform.tfvars: an apply
  # without it removes the owners it added.
  hr_provisioning_owner_object_ids = var.hr_provisioning_owner_object_ids
}

locals {
  # What modules/apps needs, and why (modules/apps/README.md, "Graph
  # permissions"):
  #   Application.ReadWrite.OwnedBy  instantiate the gallery app, SP settings,
  #       signing certificate, identifier / reply URLs, sync job + secret -
  #       ONLY on apps the identity owns (modules/apps always adds it as owner).
  #       verify: OwnedBy suffices for the sync job (provider docs list
  #       Application.ReadWrite.All); widen only if the first apply proves not.
  #   Application.Read.All           prevent_duplicate_names + template reads.
  #   Policy.ReadWrite.ApplicationConfiguration  the AWS claims-mapping policy.
  #   AppRoleAssignment.ReadWrite.All  group -> app grants. TIER 0: it can
  #       grant any app role, including Graph roles, to any principal - a
  #       SECOND Tier-0 path next to RoleManagement.ReadWrite.Directory, and
  #       one the formal risk acceptance (ADR 0005 / risk register R01) must
  #       name explicitly. Compensating controls: this flag is human-applied
  #       bootstrap only; every grant it makes is an "Add app role assignment
  #       to service principal" event that app-consent-granted.kql alerts on
  #       (High when tenant-wide + Tier-0 permission), with the APPLY identity
  #       recognised only by its immutable ids.
  app_management_apply_roles = [
    "Application.ReadWrite.OwnedBy",
    "Application.Read.All",
    "Policy.ReadWrite.ApplicationConfiguration",
    "AppRoleAssignment.ReadWrite.All",
  ]
  # PLAN refreshes the same objects read-only. verify: Synchronization.Read.All
  # is the least-privileged read for .../synchronization/jobs and /secrets.
  app_management_plan_roles = [
    "Application.Read.All",
    "Synchronization.Read.All",
  ]
}

locals {
  plan_sp  = module.pipeline_identity.plan_service_principal_object_id
  apply_sp = module.pipeline_identity.apply_service_principal_object_id

  # Built-in role definition ids the APPLY identity may hand out (and nothing
  # else):
  #   4633458b-17de-408a-b874-0445c86b69e6  Key Vault Secrets User
  #   b86a8fe4-44ce-4948-aee5-eccb2c155cd7  Key Vault Secrets Officer
  #   1c0163c0-47e6-4577-8991-ea5c82e286e4  Virtual Machine Administrator Login
  #       (modules/intune-vm grants it at the Windows 11 VM's scope so the
  #       CA005 pilot can RDP in with Entra credentials). Its actions are
  #       read-only (VM/network reads + Arc endpoint listCredentials); its
  #       data actions are VM/Arc login + loginAsAdmin - it cannot widen CI's
  #       own control-plane rights. Residual risk, accepted for the lab: the
  #       condition below constrains WHICH role, not the scope or the
  #       principal, so a compromised APPLY identity could grant anyone admin
  #       sign-in to every Entra-joined VM (or Arc machine) in the
  #       subscription - today that is only the Intune VM (the DC is not
  #       Entra joined). GUID verified against Microsoft's built-in role
  #       reference (also the id Microsoft's own "Virtual Machine Data Access
  #       Administrator" ABAC condition allow-lists).
  # Changing this list needs a bootstrap (human) apply - not an envs/dev PR.
  delegable_role_ids = "4633458b-17de-408a-b874-0445c86b69e6, b86a8fe4-44ce-4948-aee5-eccb2c155cd7, 1c0163c0-47e6-4577-8991-ea5c82e286e4"

  # ABAC condition: role assignment writes/deletes are allowed only for the
  # delegable roles above. Stops CI from granting itself (or anyone) Owner.
  rbac_admin_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
     )
     OR
     (
      @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.delegable_role_ids}}
     )
    )
    AND
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
     )
     OR
     (
      @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.delegable_role_ids}}
     )
    )
  EOT
}

# -----------------------------------------------------------------------------
# PLAN identity (pull_request): read the subscription and state.
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "plan_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = local.plan_sp
  principal_type       = "ServicePrincipal"
}

# -----------------------------------------------------------------------------
# APPLY identity (environment:prod): create/modify lab resources, and assign
# ONLY the three delegable roles above - the two Key Vault data-plane roles and
# Virtual Machine Administrator Login (Contributor cannot create role
# assignments at all).
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "apply_contributor" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = local.apply_sp
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "apply_rbac_admin_constrained" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = local.apply_sp
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.rbac_admin_condition
}

# -----------------------------------------------------------------------------
# Remote state, scoped to the envs/dev container only; the bootstrap container
# gets no CI role (Shared Key off + the ReadOnly lock in the README close
# Contributor's listKeys path; lift the lock before changing these
# assignments, since it blocks container-scoped role assignments).
#   * APPLY: Storage Blob Data Contributor - writes state and takes the blob
#     lease that locks it.
#   * PLAN: Storage Blob Data Reader - PR plans run with -lock=false (they are
#     advisory; terraform-apply.yml re-plans under a lock), so PR code cannot
#     overwrite or delete the state the next gated apply works from. It can
#     still READ state, which holds the generated break-glass and VM
#     local-admin passwords: treat those as readable by anyone who can open a
#     PR from a branch of this repo.
#   * The state blob must exist before the first PR plan: when the key is
#     missing, the azurerm backend writes an empty state (under a lease) during
#     `init`, which Reader cannot do. Seed it once with an admin `terraform
#     init` in envs/dev.
# -----------------------------------------------------------------------------
data "azurerm_storage_account" "tfstate" {
  name                = var.tfstate_storage_account_name
  resource_group_name = var.tfstate_resource_group_name
}

resource "azurerm_role_assignment" "state" {
  for_each = {
    plan  = { principal = local.plan_sp, role = "Storage Blob Data Reader" }
    apply = { principal = local.apply_sp, role = "Storage Blob Data Contributor" }
  }

  scope                = "${data.azurerm_storage_account.tfstate.id}/blobServices/default/containers/${var.tfstate_container_name}"
  role_definition_name = each.value.role
  principal_id         = each.value.principal
  principal_type       = "ServicePrincipal"
}

# -----------------------------------------------------------------------------
# AI review: PLAN identity may call the Azure OpenAI deployment (inference only).
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "plan_openai_user" {
  count = var.azure_openai_resource_id != "" ? 1 : 0

  scope                = var.azure_openai_resource_id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = local.plan_sp
  principal_type       = "ServicePrincipal"
}

# -----------------------------------------------------------------------------
# Tenant audit trail -> loga-idlab. Human-owned on purpose (see header).
# -----------------------------------------------------------------------------
module "entra_diagnostics" {
  source = "../../modules/entra-diagnostics"
  count  = var.log_analytics_workspace_id != "" ? 1 : 0

  log_analytics_workspace_id = var.log_analytics_workspace_id

  # The module's own switch adds the four ID Protection risk categories
  # (RiskyUsers, UserRiskEvents, RiskyServicePrincipals,
  # ServicePrincipalRiskEvents - the ITDR identity_risk rule and
  # workload-identity risk). One list, in the module, checked against the
  # categories Microsoft Learn documents.
  enable_identity_protection_logs = var.enable_identity_protection_logs
}

# Risk categories without a workspace would be a silent no-op.
check "identity_protection_logs_need_workspace" {
  assert {
    condition     = !var.enable_identity_protection_logs || var.log_analytics_workspace_id != ""
    error_message = "enable_identity_protection_logs = true has no effect until log_analytics_workspace_id is set (second bootstrap run)."
  }
}

# -----------------------------------------------------------------------------
# EVIDENCE (evidence-pack.yml): add new files to the WORM evidence container,
# read them back, never overwrite, delete or re-tier one. Human-applied here
# because envs/dev's APPLY identity may not hand out storage data roles
# (delegable_role_ids above), the same reason the operator's E05 grant is a
# human step.
#
# Storage Blob Data Contributor at CONTAINER scope + an ABAC condition. The
# condition denies, inside the evidence container, the three data actions
# that could change or remove a blob:
#   blobs/delete  delete (WORM refuses it anyway while retention runs; this
#                 also covers expired blobs)
#   blobs/write   overwrite, metadata, tier, tags-with-write: everything
#                 except creating a new blob
# What is left is blobs/read (the read-back check) and blobs/add/action,
# which Azure Storage documents as "create a new blob" only: a Put Blob or
# Put Block List to a NEW name. An upload to an existing name needs
# blobs/write and is refused. (move/action, rename, exists only with a
# hierarchical namespace, which version-level WORM rules out here.)
# Stricter than E05 (the operator may overwrite, which WORM turns into a new
# retained version); this identity may not even do that.
#   verify: on the first run, with a canary: a new name uploads, the same
#   name again is refused (403 or 409), a delete is refused.
# Residual (accepted for the lab, as for E05): the role's control-plane
# actions on the container (read, write metadata, delete - refused while it
# holds retained blobs) and generateUserDelegationKey. A custom role with only
# blobs/read + blobs/add/action would remove them; ABAC is kept to match E05.
# -----------------------------------------------------------------------------
data "azurerm_storage_account" "evidence" {
  count               = var.enable_evidence_pack ? 1 : 0
  name                = var.evidence_storage_account_name
  resource_group_name = var.evidence_resource_group_name

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z0-9]{3,24}$", var.evidence_storage_account_name))
      error_message = "enable_evidence_pack needs evidence_storage_account_name: the WORM account (envs/dev output evidence_storage_account_name, repo variable TF_EVIDENCE_STORAGE_ACCOUNT_NAME)."
    }
  }
}

locals {
  evidence_create_only_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete'})
      AND
      !(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'})
     )
     OR
     (
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringNotEquals '${var.evidence_container_name}'
     )
    )
  EOT
}

resource "azurerm_role_assignment" "evidence_writer" {
  count = var.enable_evidence_pack ? 1 : 0

  scope                = "${data.azurerm_storage_account.evidence[0].id}/blobServices/default/containers/${var.evidence_container_name}"
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = module.pipeline_identity.evidence_service_principal_object_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.evidence_create_only_condition
  description          = "EVIDENCE (evidence-pack.yml): create new blobs in the WORM evidence container and read them back; never overwrite, delete or re-tier one."
}
