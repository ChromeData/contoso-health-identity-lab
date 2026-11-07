# =============================================================================
# envs/bootstrap :: least-privilege.tf  (senior gap 8)
# -----------------------------------------------------------------------------
# Three things, each opt-in:
#
# 1. APPLY's Azure scope (apply_azure_scope). The CI APPLY identity held
#    Contributor and the ABAC-limited Role Based Access Control Administrator
#    on the WHOLE subscription. Every Azure resource envs/dev manages lives in
#    rg-identity-lab (state census 2026-11-07: 70 azurerm instances, all
#    under /resourceGroups/rg-identity-lab; the only data source is
#    azurerm_client_config; resource_provider_registrations = "none"), so
#    "resource_group" gives both roles at that RG only. APPLY then has no
#    right at all on rg-identity-lab-tfstate (except the state container
#    grant), rg-identity-lab-ai, rg-identity-lab-cicd or anything new.
#    "subscription" stays the default ONLY for a first deployment: envs/dev
#    creates rg-identity-lab itself, which needs subscription scope once.
#    Changing the scope REPLACES both assignments (Azure has no in-place
#    scope change): apply it when no pipeline apply is running.
#
# 2. A custom role for the lab's operations task, ELIGIBLE through PIM for
#    Azure resources (enable_lab_vm_operator). "Contoso Lab VM Operator":
#    read, start, restart and deallocate the lab VMs and query their logs.
#    It has NO write: it cannot change an NSG, a disk, an extension or run a
#    command on a VM. Nobody holds it at rest. Eligible principals activate
#    it in PIM (MFA + reason, 2 hours at most).
#      WHY HERE: creating a role definition needs
#      Microsoft.Authorization/roleDefinitions/write and eligibility needs
#      roleEligibilityScheduleRequests/write. APPLY has neither (Contributor's
#      NotActions remove Microsoft.Authorization/*/Write; RBAC Administrator
#      grants only roleAssignments/write|delete), on purpose: a role PR code
#      could define and hand out would be a new path to Owner.
#
# 3. Delete locks APPLY cannot remove (cannot_delete_lock_resource_ids):
#    CanNotDelete on the two Key Vaults. APPLY cannot remove a lock because
#    none of its roles has Microsoft.Authorization/locks/delete (Contributor
#    NotActions: Microsoft.Authorization/*/Delete; RBAC Administrator:
#    roleAssignments/* only), and the ABAC condition in main.tf stops it
#    from granting itself a role that has (Owner, User Access Administrator).
#      What is NOT possible, checked 2026-11-07:
#      * An RBAC (ABAC) condition on lock deletion: Learn ("What is Azure
#        ABAC", read 2026-11-07) says conditions can be added only to role
#        assignments with blob or queue storage data actions; the other
#        supported case is the delegation condition on roleAssignments
#        write/delete (used in main.tf). Microsoft.Authorization/locks/* is
#        neither. The deny comes from the role definitions above, and the
#        delegation condition guards the escalation.
#      * A deny assignment of our own: Learn ("List Azure deny assignments",
#        updated 2026-11-05): "You can't directly create your own deny
#        assignments"; customer-managed ones are private preview. The GA way
#        is a deployment stack with deny settings. Not used here: it would
#        move these resources out of Terraform's ownership.
#      * A lock on loga-idlab: tried live (2026-11-07 02:30Z, a throwaway
#        watchlist): a CanNotDelete lock on the workspace refused deleting a
#        Sentinel watchlist under it (ScopeLocked). Locks inherit to
#        extension resources, so every Sentinel rule, automation rule or
#        watchlist item a PR removes or replaces would fail to apply. Not
#        locked. RESIDUAL: APPLY (Contributor on rg-identity-lab) can still
#        delete or cap the workspace; only a reviewed, gated apply does so.
#      * Who CAN still remove these locks: an Owner (the lab owner; the lab
#        operator until PR #227's Owner cut is applied). That is the point
#        of a lock: a deliberate human step, not a CI side effect.
#      Note: a lock on a vault also blocks deleting role assignments and the
#      diagnostic setting at the vault's scope (they are under its path).
#      Changing those then needs the lock lifted by an Owner first.
# =============================================================================

locals {
  apply_rg_id = "${data.azurerm_subscription.current.id}/resourceGroups/${var.apply_resource_group_name}"

  apply_azure_scope_id = var.apply_azure_scope == "resource_group" ? local.apply_rg_id : data.azurerm_subscription.current.id

  vm_operator_enabled = var.enable_lab_vm_operator

  # ISO 8601 policy cap -> days for the eligibility schedule (same value).
  vm_operator_eligibility_days = tonumber(trimsuffix(trimprefix(var.lab_vm_operator_eligibility_duration, "P"), "D"))

  # Verified against the live built-in definitions (az role definition list,
  # 2026-11-07): Virtual Machine Contributor uses these Compute action names;
  # Log Analytics Reader uses workspaces/analytics/query/action and
  # workspaces/search/action for queries.
  vm_operator_actions = [
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/instanceView/read",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/restart/action",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.OperationalInsights/workspaces/read",
    # query/read = run a query at all; query/*/read = read each table. The
    # first was missing in the first live run: Log Analytics answered
    # InsufficientAccessError (2026-11-07 02:49Z) until it was added.
    "Microsoft.OperationalInsights/workspaces/query/read",
    "Microsoft.OperationalInsights/workspaces/query/*/read",
    "Microsoft.OperationalInsights/workspaces/analytics/query/action",
    "Microsoft.OperationalInsights/workspaces/search/action",
  ]
}

check "apply_scope_rg_exists_first" {
  assert {
    condition     = var.apply_azure_scope == "subscription" || var.apply_resource_group_name != ""
    error_message = "apply_azure_scope = \"resource_group\" needs apply_resource_group_name (rg-identity-lab), created by a first envs/dev apply."
  }
}

# -----------------------------------------------------------------------------
# 2. Contoso Lab VM Operator, eligible through PIM.
# -----------------------------------------------------------------------------
resource "azurerm_role_definition" "lab_vm_operator" {
  count = local.vm_operator_enabled ? 1 : 0

  # A fixed id keeps the definition stable across re-creation (role
  # definition ids are GUIDs; this one is random, generated once).
  role_definition_id = "6c1f3d2e-8a47-4b9e-9c35-2f6a0e7b4d91"
  name               = "Contoso Lab VM Operator"
  scope              = local.apply_rg_id
  description        = "Contoso Health lab: start, restart, deallocate and read the lab VMs and query their logs. No write. Eligible only, through PIM (envs/bootstrap least-privilege.tf)."

  permissions {
    actions     = local.vm_operator_actions
    not_actions = []
  }

  assignable_scopes = [local.apply_rg_id]
}

resource "azurerm_role_management_policy" "lab_vm_operator" {
  count = local.vm_operator_enabled ? 1 : 0

  scope              = local.apply_rg_id
  role_definition_id = azurerm_role_definition.lab_vm_operator[0].role_definition_resource_id

  activation_rules {
    maximum_duration                   = var.lab_vm_operator_activation_max_duration
    require_multifactor_authentication = true
    require_justification              = true
    require_approval                   = false
  }

  # Eligibility EXPIRES (lab_vm_operator_eligibility_duration, default
  # P180D, as PIM-AWS-Lab-Admins): these are direct, named assignments that no
  # group access review covers, so the expiry is the review. Renewal is a
  # reviewed bootstrap apply (the schedule below restarts from that apply).
  eligible_assignment_rules {
    expiration_required = true
    expire_after        = var.lab_vm_operator_eligibility_duration
  }

  # A direct ACTIVE assignment must expire: nobody holds this role standing.
  active_assignment_rules {
    expiration_required                = true
    expire_after                       = "P15D"
    require_justification              = true
    require_multifactor_authentication = true
  }
}

resource "azurerm_pim_eligible_role_assignment" "lab_vm_operator" {
  for_each = local.vm_operator_enabled ? toset(var.lab_vm_operator_eligible_object_ids) : toset([])

  scope              = local.apply_rg_id
  role_definition_id = azurerm_role_definition.lab_vm_operator[0].role_definition_resource_id
  principal_id       = each.value
  justification      = "Lab operations: start/stop the lab VMs and read their logs, just in time (MFA + reason, ${var.lab_vm_operator_activation_max_duration} max)."

  schedule {
    expiration {
      duration_days = local.vm_operator_eligibility_days
    }
  }

  depends_on = [azurerm_role_management_policy.lab_vm_operator]
}

check "vm_operator_has_someone_eligible" {
  assert {
    condition     = !local.vm_operator_enabled || length(var.lab_vm_operator_eligible_object_ids) > 0
    error_message = "enable_lab_vm_operator is on but lab_vm_operator_eligible_object_ids is empty: the role exists and nobody can activate it."
  }
}

# -----------------------------------------------------------------------------
# 3. Delete locks APPLY cannot remove.
# -----------------------------------------------------------------------------
resource "azurerm_management_lock" "cannot_delete" {
  for_each = var.cannot_delete_lock_resource_ids

  name       = "lock-${each.key}-cannot-delete"
  scope      = each.value
  lock_level = "CanNotDelete"
  notes      = "Contoso Health lab (envs/bootstrap least-privilege.tf): CI's APPLY identity cannot remove this lock. Lifting it is a deliberate Owner step."
}
