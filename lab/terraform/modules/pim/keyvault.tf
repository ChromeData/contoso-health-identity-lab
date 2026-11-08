# =============================================================================
# modules/pim :: keyvault.tf
# -----------------------------------------------------------------------------
# JUST-IN-TIME HUMAN ACCESS TO THE LAB KEY VAULT
# (var.enable_pim_keyvault_officers, default false).
#
#   PIM-KeyVault-Secrets-Officers --(ELIGIBLE)--> Key Vault Secrets Officer
#            ^                                     on kv-idlab-<suffix> (vault scope)
#            |  ordinary (active) membership, set post-apply; each member
#            |  ACTIVATES the role through Azure PIM:
#            |  MFA + justification + approval (PIM-Approvers-Tier0) + 2 h cap
#          person
#
# WHY: Azure Key Vault replaces HashiCorp Vault in the lab (ADR 0036,
# "Microsoft-native PAM"). A person who stores or changes a secret must not
# hold that power all day. "Key Vault Secrets Officer" can read, write and
# delete every secret in the vault (Microsoft Learn, "Azure built-in roles
# for Key Vault data plane operations", role id
# b86a8fe4-44ce-4948-aee5-eccb2c155cd7). So the group is only ELIGIBLE;
# a member gets the role for at most 2 hours after an approved activation.
#
# WHY TIER-0 STRENGTH (approval on by default): kv-idlab holds Tier-0
# material (svc-vault-rotator, dc01-dsrm-password; see modules/keyvault
# main.tf). Reading those is control of the domain controller.
#
# SAME SHAPE AS azure.tf on purpose: the GROUP is eligible for the Azure
# role (that is what azurerm_pim_eligible_role_assignment expresses), the
# eligibility has no end date because the eligible principal is code, and
# the PEOPLE are the group's active members, reviewed quarterly. See
# azure.tf for the provider notes (policy auto-import, delete is a no-op,
# subscription-scoped role_definition_id form). They apply here unchanged.
#
# STANDING ACCESS THAT REMAINS (say so): envs/dev still passes
# key_vault_secrets_officer_ids to modules/keyvault, which grants the same
# role ACTIVELY. Empty that list only after a member's activation has been
# seen to work, or the lab loses its last way to write a secret.
#
# PERMISSIONS (tenant-time): roleEligibilityScheduleRequests/write and
# roleManagementPolicies/write at the vault scope (Owner or User Access
# Administrator). The CI APPLY identity lacks them (azure.tf), so the first
# apply with this flag on is a human apply or needs an envs/bootstrap grant.
#
# LICENSING: Microsoft Entra ID P2 for each eligible person (in the
# Microsoft 365 E5 trial).
# =============================================================================

locals {
  keyvault_pim_enabled = var.enable_pim_keyvault_officers

  # "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>"
  # -> "<sub>". Empty when unset (the precondition below says what is missing).
  keyvault_pim_subscription_id = var.keyvault_pim_scope_id != "" ? split("/", var.keyvault_pim_scope_id)[2] : ""

  # Key Vault Secrets Officer (built-in). Not a variable: this file exists
  # for exactly this role. A different role is a different review.
  keyvault_secrets_officer_guid = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"

  keyvault_pim_role_definition_id = "/subscriptions/${local.keyvault_pim_subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${local.keyvault_secrets_officer_guid}"
}

# Role-assignable: membership of a group that can read Tier-0 secrets must be
# as protected as a directory admin group (only Privileged Role
# Administrators and Global Administrators can change it).
resource "azuread_group" "keyvault_pim" {
  count = local.keyvault_pim_enabled ? 1 : 0

  display_name       = var.keyvault_pim_group_name
  mail_nickname      = var.keyvault_pim_group_mail_nickname
  description        = "Azure PIM: ELIGIBLE for Key Vault Secrets Officer on the lab vault; members activate just-in-time (MFA + justification + approval)."
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  # Members are people (operational data), added post-apply.
  lifecycle {
    ignore_changes = [members]
  }
}

# Activation policy for Key Vault Secrets Officer at the vault scope.
resource "azurerm_role_management_policy" "keyvault_pim" {
  count = local.keyvault_pim_enabled ? 1 : 0

  scope              = var.keyvault_pim_scope_id
  role_definition_id = local.keyvault_pim_role_definition_id

  activation_rules {
    maximum_duration                   = var.keyvault_pim_activation_max_duration
    require_multifactor_authentication = true
    require_justification              = true
    require_approval                   = var.keyvault_pim_require_approval

    dynamic "approval_stage" {
      for_each = var.keyvault_pim_require_approval ? [1] : []
      content {
        primary_approver {
          object_id = azuread_group.pim_approvers["tier0"].object_id
          type      = "Group"
        }
      }
    }
  }

  # Permanent eligibility of the GROUP (code), time-boxed activation of a
  # PERSON (reviewed membership) - the azure.tf model.
  eligible_assignment_rules {
    expiration_required = false
  }

  # A direct ACTIVE assignment through PIM must expire, with MFA and a reason.
  active_assignment_rules {
    expiration_required                = true
    expire_after                       = var.active_assignment_max_duration
    require_justification              = true
    require_multifactor_authentication = true
  }

  lifecycle {
    precondition {
      condition     = var.keyvault_pim_scope_id != ""
      error_message = "enable_pim_keyvault_officers = true needs keyvault_pim_scope_id (the lab Key Vault's resource id)."
    }
    precondition {
      condition     = !var.keyvault_pim_require_approval || length(local.tier0_approver_member_ids) > 0
      error_message = "keyvault_pim_require_approval = true needs approvers in PIM-Approvers-Tier0: tier0_approver_object_ids (or approver_object_ids)."
    }
  }
}

resource "azurerm_pim_eligible_role_assignment" "keyvault_pim" {
  count = local.keyvault_pim_enabled ? 1 : 0

  scope              = var.keyvault_pim_scope_id
  role_definition_id = local.keyvault_pim_role_definition_id
  principal_id       = azuread_group.keyvault_pim[0].object_id
  justification      = "Lab: ${var.keyvault_pim_group_name} eligible for Key Vault Secrets Officer on the lab vault - activation requires MFA, justification${var.keyvault_pim_require_approval ? ", approval" : ""}, ${var.keyvault_pim_activation_max_duration} max."

  # No schedule block = no expiration; the policy must allow that first.
  depends_on = [azurerm_role_management_policy.keyvault_pim]
}
