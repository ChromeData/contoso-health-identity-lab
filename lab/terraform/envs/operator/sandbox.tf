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
# the operator gets two TIME-BOUND ACTIVE PIM assignments at THAT resource
# group's scope, ending at the session's expires_utc like the other session
# grants:
#   Contributor                            create and delete resources there,
#                                          storage accounts included
#   Role Based Access Control Administrator  create and delete role
#                                          assignments there
#
# THE LIMIT, SAID PLAINLY: azurerm_pim_active_role_assignment has no ABAC
# condition (provider 4.81 schema), so the RBAC Administrator grant is not
# narrowed to a list of data roles. Inside rg-lab-sandbox, during a session,
# the operator could assign any role, Owner included, to any principal. The
# blast radius is that resource group: a role assigned there reaches nothing
# outside it, and the group holds only objects a run creates and deletes. No
# subscription-scope or tenant-scope write comes with it.
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

data "azurerm_role_definition" "sandbox" {
  for_each = toset(["Contributor", "Role Based Access Control Administrator"])
  name     = each.value
  scope    = data.azurerm_subscription.current.id
}

resource "azurerm_pim_active_role_assignment" "operator_sandbox" {
  for_each = local.write_session_open ? toset(keys(data.azurerm_role_definition.sandbox)) : toset([])

  scope              = azurerm_resource_group.sandbox.id
  role_definition_id = data.azurerm_role_definition.sandbox[each.value].id
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
