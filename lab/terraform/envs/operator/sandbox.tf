# =============================================================================
# envs/operator :: sandbox.tf
# -----------------------------------------------------------------------------
# A SANDBOX resource group for throwaway test objects, and the operator's
# narrowly scoped write path into it (ADR 0030 follow-up, 2026-11-08).
#
# WHY: since ADR 0030 the operator holds Reader standing, and even a write
# session cannot create a storage account (the session role keeps the
# evidence store's storageAccounts/write in NotActions) or ANY role assignment
# (no Microsoft.Authorization write). Three proofs need both, for objects
# they create and delete in the same run:
#   * lab/k8s/ci/pipeline.sh  storage static website (the public OIDC issuer),
#                             a vault, the operator's Secrets Officer on it,
#                             the workload's Secrets User on one secret
#   * lab/secrets/state-leak  a vault and the operator's Secrets Officer on it
#   * lab/bastion/capture.sh  the recordings storage account and its grants
# Restoring subscription Owner is not an option (ADR 0030).
#
# WHAT: one standing resource group, rg-lab-sandbox, that holds ONLY such
# throwaway objects. During an owner-opened write session (and only then),
# the operator gets, at THAT resource group's scope:
#   Contributor (TIME-BOUND ACTIVE PIM, ends at expires_utc like the other
#     session grants): create and delete resources, storage accounts included
#   Role Based Access Control Administrator WITH A CONDITION (an ordinary
#     role assignment that exists only while operator_write_session is set;
#     the owner's closing apply deletes it): it may create or delete role
#     assignments ONLY for four data roles - Key Vault Secrets Officer, Key
#     Vault Secrets User, Storage Blob Data Contributor, Storage Blob Data
#     Reader. Owner, Contributor, RBAC Administrator and every other role are
#     refused.
#
# WHY NOT PIM FOR THE SECOND ONE: azurerm_pim_active_role_assignment takes no
# ABAC condition (provider 4.81 schema). An unconditioned RBAC Administrator
# would let the operator give itself an ordinary Owner on the sandbox that
# survives expires_utc and the closing apply (Greptile, 2026-11-08). The
# condition closes that: nothing the operator can assign carries management
# rights. Trade-off, said plainly: this grant does not expire on Azure's side
# at expires_utc; it ends with the owner's closing apply, as the session's
# Graph roles already do (ADR 0030 records that gap). A data-role assignment
# the operator made and did not delete can outlive the session; it reaches
# only sandbox objects, which each run deletes.
#
# Nothing lives here between runs: a run that finds the group non-empty at
# its start reports what is left (the scripts' read-back), and the owner can
# empty it with `az resource list -g rg-lab-sandbox`.
# =============================================================================

variable "sandbox_resource_group_name" {
  description = "Resource group for throwaway test objects (k8s pipeline, state-leak proof, Bastion capture). The operator can write here only during a write session."
  type        = string
  default     = "rg-lab-sandbox"

  validation {
    condition     = can(regex("^rg-[a-z0-9-]{3,60}$", var.sandbox_resource_group_name)) && var.sandbox_resource_group_name != "rg-identity-lab"
    error_message = "sandbox_resource_group_name must be an rg-* name and never the lab's own resource group (rg-identity-lab)."
  }
}

variable "sandbox_location" {
  description = "Region of the sandbox resource group (the lab's region)."
  type        = string
  default     = "eastus2"
}

resource "azurerm_resource_group" "sandbox" {
  name     = var.sandbox_resource_group_name
  location = var.sandbox_location
  tags = {
    purpose = "throwaway test objects only (envs/operator sandbox.tf)"
    owner   = "identity-platform"
    writes  = "operator during an owner-opened write session only (ADR 0030)"
  }
}

data "azurerm_role_definition" "sandbox_contributor" {
  name  = "Contributor"
  scope = data.azurerm_subscription.current.id
}

locals {
  # Built-in role GUIDs (Azure built-in roles reference; the same in every
  # tenant): the ONLY roles the operator may assign in the sandbox.
  sandbox_assignable_role_ids = [
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", # Key Vault Secrets Officer
    "4633458b-17de-408a-b874-0445c86b69e6", # Key Vault Secrets User
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe", # Storage Blob Data Contributor
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1", # Storage Blob Data Reader
  ]
  sandbox_role_list = join(", ", local.sandbox_assignable_role_ids)
  # Constrained delegation (the documented RBAC Administrator condition
  # shape): writes and deletes of role assignments only for those roles.
  sandbox_delegation_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
     )
     OR
     (
      @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.sandbox_role_list}}
     )
    )
    AND
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
     )
     OR
     (
      @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.sandbox_role_list}}
     )
    )
  EOT
}

resource "azurerm_role_assignment" "operator_sandbox_delegation" {
  count = local.write_session_open ? 1 : 0

  scope                = azurerm_resource_group.sandbox.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = azuread_service_principal.operator.object_id
  principal_type       = "ServicePrincipal"
  description          = "Operator write session, sandbox only, data roles only (ADR 0030): ${var.operator_write_session.reason}"
  condition_version    = "2.0"
  condition            = local.sandbox_delegation_condition

  depends_on = [terraform_data.operator_write_session_window]
}

resource "azurerm_pim_active_role_assignment" "operator_sandbox" {
  count = local.write_session_open ? 1 : 0

  scope              = azurerm_resource_group.sandbox.id
  role_definition_id = data.azurerm_role_definition.sandbox_contributor.id
  principal_id       = azuread_service_principal.operator.object_id
  justification      = "Operator write session, sandbox only (ADR 0030): ${var.operator_write_session.reason}"

  schedule {
    start_date_time = var.operator_write_session.opened_utc
    expiration {
      end_date_time = var.operator_write_session.expires_utc
    }
  }

  depends_on = [terraform_data.operator_write_session_window]
}
