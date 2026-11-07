# =============================================================================
# envs/operator :: write-session.tf
# -----------------------------------------------------------------------------
# WHAT: the operator's WRITE SESSION (ADR 0030). Between sessions the operator
# holds only read rights (variables.tf: operator_graph_roles,
# operator_azure_roles). The owner opens a session for a set window, does the
# work that needs writes, and closes it.
#
#   * Graph: the write permissions (operator_session_graph_roles) are granted
#     in main.tf while var.operator_write_session is set. Graph application
#     permissions have no expiry and no PIM, so the owner's closing apply
#     removes them. The plan check below refuses to re-apply a stale session.
#   * Azure: a custom role, "Contoso Lab Operator Session", plus Key Vault
#     Secrets Officer, as TIME-BOUND ACTIVE PIM assignments. Azure ends them
#     at expires_utc by itself.
#
# WHY time-bound ACTIVE and not ELIGIBLE: Microsoft Learn (Azure RBAC, "Eligible
# and time-bound role assignments"): "you can't create eligible role
# assignments for applications, service principals, or managed identities
# because they can't perform the activation steps." Time-bound active is the
# closest Azure offers a service principal.
#
# WHY a custom role and not Contributor or Owner: Contributor already has no
# Microsoft.Authorization/*/write or */delete, so it cannot create role
# assignments or remove a lock. On top of that, this role removes the
# deletes that would destroy audit evidence: the storage accounts (the WORM
# evidence store and Terraform state), their containers and immutability
# policies, and the Log Analytics workspace. So even inside a session, the
# operator cannot remove the evidence store's CanNotDelete lock, shorten its
# immutability policy, or delete the sign-in logs.
#
# The custom role DEFINITION exists all the time (it grants nothing on its
# own). Creating or changing it needs roleDefinitions/write, which only the
# owner holds: that is one more reason this root is owner-applied.
# =============================================================================

locals {
  # Contributor's own NotActions (Azure built-in roles reference, Contributor
  # b24988ac-6180-42a0-ab88-20f7382dd24c), kept so this role is never wider
  # than Contributor.
  contributor_not_actions = [
    "Microsoft.Authorization/*/Delete",
    "Microsoft.Authorization/*/Write",
    "Microsoft.Authorization/elevateAccess/Action",
    "Microsoft.Blueprint/blueprintAssignments/write",
    "Microsoft.Blueprint/blueprintAssignments/delete",
    "Microsoft.Compute/galleries/share/action",
    "Microsoft.Purview/consents/write",
    "Microsoft.Purview/consents/delete",
    "Microsoft.Resources/deploymentStacks/manageDenySetting/action",
    "Microsoft.Subscription/cancel/action",
    "Microsoft.Subscription/enable/action",
  ]

  # Evidence and audit-log protections (ADR 0030, finding E1). Each one is a
  # control-plane action an attacker with the operator would use to erase
  # evidence. Storage account WRITE is in the list because it can switch
  # account-level immutability and network rules.
  evidence_not_actions = [
    "Microsoft.Storage/storageAccounts/delete",
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/lock/action",
    "Microsoft.OperationalInsights/workspaces/delete",
    "Microsoft.OperationalInsights/workspaces/purge/action",
    "Microsoft.OperationalInsights/workspaces/tables/delete",
    "Microsoft.Insights/diagnosticSettings/delete",
  ]
}

resource "azurerm_role_definition" "operator_session" {
  #checkov:skip=CKV_AZURE_39:Not an owner role. actions "*" is narrowed by NotActions that remove every Microsoft.Authorization write and delete (no role assignments, no locks) plus the evidence and log deletes; tests/operator.tftest.hcl pins those NotActions. Assigned only time-bound in an owner-opened session (ADR 0030).
  name        = "Contoso Lab Operator Session"
  scope       = data.azurerm_subscription.current.id
  description = "Lab operator WRITE SESSION role (ADR 0030): Contributor minus evidence-store and audit-log deletes. Assigned only time-bound, by envs/operator."

  permissions {
    actions     = ["*"]
    not_actions = concat(local.contributor_not_actions, local.evidence_not_actions)
  }

  assignable_scopes = [data.azurerm_subscription.current.id]
}

data "azurerm_role_definition" "operator_session_builtin" {
  for_each = toset(var.operator_session_azure_roles)
  name     = each.value
  scope    = data.azurerm_subscription.current.id
}

locals {
  # role name -> full role definition id (/subscriptions/<id>/providers/
  # Microsoft.Authorization/roleDefinitions/<guid>, the form
  # azurerm_pim_active_role_assignment takes), for every Azure session role.
  operator_session_azure_role_ids = merge(
    { "Contoso Lab Operator Session" = azurerm_role_definition.operator_session.role_definition_resource_id },
    { for name, d in data.azurerm_role_definition.operator_session_builtin : name => d.id },
  )
}

# Fail the PLAN when the window has already ended: a stale session must not
# be re-applied by mistake. Close it by applying with operator_write_session
# unset. (variables.tf validates the window itself: at most 8 hours.)
resource "terraform_data" "operator_write_session_window" {
  count = local.write_session_open ? 1 : 0

  input = {
    opened_utc  = var.operator_write_session.opened_utc
    expires_utc = var.operator_write_session.expires_utc
    reason      = var.operator_write_session.reason
  }

  lifecycle {
    precondition {
      condition     = timecmp(plantimestamp(), var.operator_write_session.expires_utc) < 0
      error_message = "The operator write session ended at ${var.operator_write_session.expires_utc}. Close it: apply with operator_write_session unset (ADR 0030)."
    }
  }
}

resource "azurerm_pim_active_role_assignment" "operator_session" {
  for_each = local.write_session_open ? toset(keys(local.operator_session_azure_role_ids)) : toset([])

  scope              = data.azurerm_subscription.current.id
  role_definition_id = local.operator_session_azure_role_ids[each.value]
  principal_id       = azuread_service_principal.operator.object_id
  justification      = "Operator write session (ADR 0030): ${var.operator_write_session.reason}"

  schedule {
    start_date_time = var.operator_write_session.opened_utc
    expiration {
      end_date_time = var.operator_write_session.expires_utc
    }
  }

  depends_on = [terraform_data.operator_write_session_window]
}

