# =============================================================================
# modules/pim :: azure.tf
# -----------------------------------------------------------------------------
# PIM FOR AZURE RESOURCES (var.enable_pim_azure_resources, default false).
#
#   PIM-Azure-RG-Contributors --(ELIGIBLE)--> Contributor on rg-identity-lab
#            ^
#            |  ordinary (active) membership, set post-apply; each member
#            |  ACTIVATES Contributor through Azure PIM:
#            |  MFA + justification + approval (PIM-Approvers-Tier0) + 4h cap
#          person
#
# The directory side (main.tf, tiers.tf) makes the GROUP active and the
# MEMBERSHIP eligible. Here it is the other way round - the group is eligible
# for the Azure role - because that is what azurerm_pim_eligible_role_assignment
# expresses, and it keeps the Azure activation (with its own policy below) as
# the single just-in-time step. Still one activation per elevation.
#
# WHY CONTRIBUTOR HERE IS TIER 0: rg-identity-lab holds the domain controller
# VM and kv-idlab. Contributor can run commands as SYSTEM on DC01
# (az vm run-command) - control of the RG is control of AD. So the
# activation policy is Tier-0 strength (approval on by default), not "just
# an infra role".
#
# STANDING ACCESS THAT REMAINS (say so, do not hide it): the CI APPLY
# identity (Contributor, envs/bootstrap) and whichever human account
# bootstrapped the subscription (usually Owner). The tenant-time step in
# README.md converts that human Owner to an eligible assignment once this
# path is proven, so humans reach RG write only through an activation.
#
# PROVIDER NOTES (azurerm 4.81, verified against the provider source):
#   * azurerm_role_management_policy auto-imports the policy Azure already
#     has for (scope, role) and its DELETE IS A NO-OP: removing this resource
#     (or flipping the flag off) leaves the last-applied settings in place.
#     Reset them in the portal (PIM -> Azure resources -> rg-identity-lab ->
#     Settings -> Contributor) if you ever need the defaults back.
#   * Omitting `schedule` on the eligible assignment requests NO EXPIRATION,
#     which Azure only accepts if the policy allows permanent eligibility -
#     hence depends_on the policy below (eligible_assignment_rules
#     expiration_required = false). This is the ONE permanent eligibility in
#     the module, on purpose: the eligible principal is the GROUP, declared
#     in code, not a person. An expiring group eligibility would simply be
#     re-created by the next apply (drift), so expiry would add no control.
#     The PEOPLE are the group's active members, and they are reviewed
#     quarterly (privileged access review, reviews.tf).
#   * Approvers are the PIM-Approvers-Tier0 GROUP (azurerm type "Group";
#     the provider documents User and Group). verify: first apply that an
#     RG-scope Azure PIM policy accepts a role-assignable group approver.
#   * role_definition_id uses the subscription-scoped form
#     /subscriptions/<sub>/providers/Microsoft.Authorization/roleDefinitions/<guid>,
#     the form the provider's own acceptance tests and import ids use for a
#     resource-scoped assignment (verify: on the first apply that the policy
#     lookup by roleDefinitionId resolves at RG scope).
#
# PERMISSIONS (tenant-time): creating eligibility schedule requests and
# updating role management policies needs Microsoft.Authorization/
# roleEligibilityScheduleRequests/write and roleManagementPolicies/write on
# the RG - Owner or User Access Administrator. The CI APPLY identity holds
# Contributor + an ABAC-constrained RBAC Administrator, which has neither
# (verify:), so the first apply of this flag is a human apply or needs an
# envs/bootstrap grant (README.md in this module).
#
# LICENSING: Entra ID P2 for each eligible person (M365 E5 trial).
# =============================================================================

locals {
  azure_pim_enabled = var.enable_pim_azure_resources

  # "/subscriptions/<sub>/resourceGroups/<rg>" -> "<sub>". Empty when unset
  # (the precondition below then explains what is missing).
  azure_pim_subscription_id = var.azure_pim_scope_id != "" ? split("/", var.azure_pim_scope_id)[2] : ""

  azure_pim_role_definition_id = "/subscriptions/${local.azure_pim_subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${var.azure_pim_role_definition_guid}"
}

# Role-assignable: membership of a group that can become Contributor over the
# DC's resource group must be as protected as a directory admin group.
resource "azuread_group" "azure_pim" {
  count = local.azure_pim_enabled ? 1 : 0

  display_name       = var.azure_pim_group_name
  mail_nickname      = var.azure_pim_group_mail_nickname
  description        = "Azure PIM: ELIGIBLE for Contributor on the lab resource group; members activate just-in-time (MFA + justification + approval)."
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  # Members are people (operational data), added post-apply.
  lifecycle {
    ignore_changes = [members]
  }
}

# Activation policy for Contributor at the RG scope.
resource "azurerm_role_management_policy" "azure_pim" {
  count = local.azure_pim_enabled ? 1 : 0

  scope              = var.azure_pim_scope_id
  role_definition_id = local.azure_pim_role_definition_id

  activation_rules {
    maximum_duration                   = var.azure_pim_activation_max_duration
    require_multifactor_authentication = true
    require_justification              = true
    require_approval                   = var.azure_pim_require_approval

    dynamic "approval_stage" {
      for_each = var.azure_pim_require_approval ? [1] : []
      content {
        primary_approver {
          object_id = azuread_group.pim_approvers["tier0"].object_id
          type      = "Group"
        }
      }
    }
  }

  # Permanent eligibility (reviewed), time-boxed activation - same model as
  # the directory side.
  eligible_assignment_rules {
    expiration_required = false
  }

  # A direct ACTIVE Contributor assignment through PIM must expire, and the
  # admin making it justifies it and passes MFA.
  active_assignment_rules {
    expiration_required                = true
    expire_after                       = var.active_assignment_max_duration
    require_justification              = true
    require_multifactor_authentication = true
  }

  lifecycle {
    precondition {
      condition     = var.azure_pim_scope_id != ""
      error_message = "enable_pim_azure_resources = true needs azure_pim_scope_id (the lab resource group id)."
    }
    precondition {
      condition     = !var.azure_pim_require_approval || length(local.tier0_approver_member_ids) > 0
      error_message = "azure_pim_require_approval = true needs approvers in PIM-Approvers-Tier0: tier0_approver_object_ids (or approver_object_ids)."
    }
  }
}

resource "azurerm_pim_eligible_role_assignment" "azure_pim" {
  count = local.azure_pim_enabled ? 1 : 0

  scope              = var.azure_pim_scope_id
  role_definition_id = local.azure_pim_role_definition_id
  principal_id       = azuread_group.azure_pim[0].object_id
  justification      = "Lab: ${var.azure_pim_group_name} eligible for Contributor on the lab RG - activation requires MFA, justification${var.azure_pim_require_approval ? ", approval" : ""}, ${var.azure_pim_activation_max_duration} max."

  # No schedule block = no expiration; the policy must allow that first.
  depends_on = [azurerm_role_management_policy.azure_pim]
}
