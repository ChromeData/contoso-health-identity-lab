# =============================================================================
# modules/azure-guardrails :: main.tf
# -----------------------------------------------------------------------------
# WHAT: two Azure Policy guardrails on the lab subscription, each a custom
# definition plus a subscription assignment, both in AUDIT mode by default:
#
#   1. No new standing Owner. A new Owner role assignment for anyone not on
#      owner_allowed_principal_ids is recorded as non-compliant (Audit) or
#      refused (Deny). Admin power on Azure should be borrowed through PIM
#      for a few hours, not held forever.
#   2. Key Vaults keep deletion protection. A vault created or updated with
#      soft delete off, or without purge protection, is recorded (Audit) or
#      refused (Deny). A vault that can be purged is one whose secrets can be
#      destroyed for good, to cover tracks.
#
# Policies don't fix what already exists: they judge creates and updates. The
# two standing Owners today (the owner's account and the lab operator, read
# 2026-11-06) keep their access in every mode.
#
# PORTED FROM the owner's old Azure-Landing-Zone-Guardrails repo, with its
# Owner bug fixed. The old rule said
#     roleDefinitionId  equals  "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-..."
# but a role assignment's roleDefinitionId carries the subscription in front:
#     /subscriptions/de0b2a93-.../providers/Microsoft.Authorization/roleDefinitions/8e3af657-...
# (read 2026-11-06 from both Owner assignments on the lab subscription). So
# `equals` never matched, and the old policy would have deployed, shown as
# assigned and blocked nothing. Now it uses `like "*/providers/.../<Owner
# GUID>"`, which matches the id at any scope; Azure Policy string comparisons
# other than match/notMatch are case-insensitive and `like` takes one
# wildcard (Learn, "policy definition structure: policy rule", read
# 2026-11-06). tests/guardrails.tftest.hcl replays the real id against the
# rule. Owner = 8e3af657-a8ff-443c-a75c-2fe8c4bcb635 (Azure built-in roles).
#
# The old Key Vault rule had a second, quieter bug: `enableSoftDelete
# notEquals "true"` flags a vault whose request simply leaves the field out,
# which is normal now that soft delete can't be turned off. The rule below
# is Microsoft's own built-in "Key vaults should have deletion protection
# enabled" (0b60c0b2-2dc2-4e1c-b5c9-abbed971de53, v2.1.0, read 2026-11-06
# with az policy definition show), copied so its effect and message can be
# ours. It skips a vault being recovered (createMode = recover).
#
# CAN IT LOCK OUT THE LAB? Checked against every identity that touches the
# subscription:
#   * PLAN (Reader) and APPLY (Contributor + Role Based Access Control
#     Administrator limited by ABAC to two Key Vault data roles and VM
#     Administrator Login, envs/bootstrap): neither holds nor can create an
#     Owner assignment, so the Owner policy never sees them. The one vault
#     APPLY manages, kv-idlab-20f1, has purge protection on (read
#     2026-11-06; modules/keyvault defaults purge_protection_enabled = true),
#     so its updates stay compliant.
#   * The lab operator (envs/operator grants it Owner) and the owner's
#     account: on owner_allowed_principal_ids, so even under Deny their Owner
#     grant can be re-created. A Deny with an empty list is refused at plan
#     (precondition below).
#   * Sign-in and existing rights: a policy only judges new or changed
#     resources. Nobody loses access they have.
#   * PIM for Azure resources: there are no Azure role eligibilities on the
#     subscription today (roleEligibilitySchedules read 2026-11-06: empty).
#     Whether a PIM activation of Owner is judged by this policy is not
#     tested; find out in Audit mode before any switch to Deny.
#
# WHAT IT DOESN'T STOP: any Owner can delete these assignments. They are a
# guardrail against mistakes and drift, and a record, not a wall against an
# Owner. The applier needs Microsoft.Authorization/policyDefinitions/write and
# policyAssignments/write, which Contributor lacks (its NotActions include
# Microsoft.Authorization/*/Write, read 2026-11-06), so this module is called
# from the human-applied envs/bootstrap, never envs/dev.
#
# COST: Azure Policy on Azure resources has no charge.
# =============================================================================

locals {
  owner_role_definition_guid = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

  # One wildcard, in front: matches /providers/... and
  # /subscriptions/<id>/providers/... alike.
  owner_role_definition_like = "*/providers/Microsoft.Authorization/roleDefinitions/${local.owner_role_definition_guid}"

  effect_parameter = {
    effect = {
      type          = "String"
      defaultValue  = "Audit"
      allowedValues = ["Audit", "Deny", "Disabled"]
      metadata      = { displayName = "Effect", description = "Audit first; Deny once the compliance results are understood." }
    }
  }
}

# -----------------------------------------------------------------------------
# 1. No new standing Owner
# -----------------------------------------------------------------------------
resource "azurerm_policy_definition" "no_standing_owner" {
  name         = "contoso-lab-no-standing-owner"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Contoso lab: no new standing Owner role assignments"
  description  = "Audits or denies new Owner (${local.owner_role_definition_guid}) role assignments for anyone not on the allowed list. Admin power on Azure is borrowed through PIM, not held. Managed by Terraform - modules/azure-guardrails (envs/bootstrap)."

  metadata = jsonencode({ category = "Security", version = "2.0.0", source = "lab/terraform/modules/azure-guardrails" })

  parameters = jsonencode(merge(local.effect_parameter, {
    allowedPrincipalIds = {
      type         = "Array"
      defaultValue = []
      metadata     = { displayName = "Principals that may be given Owner", description = "Object ids: the lab owner and the lab operator." }
    }
  }))

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Authorization/roleAssignments" },
        { field = "Microsoft.Authorization/roleAssignments/roleDefinitionId", like = local.owner_role_definition_like },
        { field = "Microsoft.Authorization/roleAssignments/principalId", notIn = "[parameters('allowedPrincipalIds')]" },
      ]
    }
    "then" = { effect = "[parameters('effect')]" }
  })
}

resource "azurerm_subscription_policy_assignment" "no_standing_owner" {
  name                 = "lab-no-standing-owner"
  display_name         = "Contoso lab: no new standing Owner (${var.standing_owner_effect})"
  subscription_id      = var.subscription_id
  policy_definition_id = azurerm_policy_definition.no_standing_owner.id

  parameters = jsonencode({
    effect              = { value = var.standing_owner_effect }
    allowedPrincipalIds = { value = var.owner_allowed_principal_ids }
  })

  non_compliance_message {
    content = "Owner is not handed out permanently in this lab. Ask for it through PIM (time-limited, approved, logged)."
  }

  lifecycle {
    precondition {
      condition     = var.standing_owner_effect != "Deny" || length(var.owner_allowed_principal_ids) > 0
      error_message = "standing_owner_effect = \"Deny\" needs owner_allowed_principal_ids (at least the lab operator's service principal, whose Owner grant envs/operator manages). Refusing to plan a Deny that could block it."
    }
  }
}

# -----------------------------------------------------------------------------
# 2. Key Vaults keep deletion protection
# -----------------------------------------------------------------------------
resource "azurerm_policy_definition" "keyvault_protection" {
  name         = "contoso-lab-keyvault-deletion-protection"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Contoso lab: Key Vaults must keep soft delete and purge protection"
  description  = "Audits or denies a Key Vault without soft delete or purge protection, so its secrets cannot be destroyed for good. Rule copied from the built-in 0b60c0b2-2dc2-4e1c-b5c9-abbed971de53 (v2.1.0). Managed by Terraform - modules/azure-guardrails (envs/bootstrap)."

  metadata = jsonencode({ category = "Key Vault", version = "2.0.0", source = "lab/terraform/modules/azure-guardrails" })

  parameters = jsonencode(local.effect_parameter)

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.KeyVault/vaults" },
        { field = "Microsoft.KeyVault/vaults/createMode", notEquals = "recover" },
        {
          anyOf = [
            # Old API versions: soft delete could be off or left out.
            {
              allOf = [
                { value = "[requestContext().apiVersion]", less = "2019-09-01" },
                {
                  anyOf = [
                    { field = "Microsoft.KeyVault/vaults/enableSoftDelete", equals = "false" },
                    { field = "Microsoft.KeyVault/vaults/enableSoftDelete", exists = "false" },
                  ]
                },
              ]
            },
            # Current API versions: soft delete is on unless set to false.
            {
              allOf = [
                { value = "[requestContext().apiVersion]", greaterOrEquals = "2019-09-01" },
                { field = "Microsoft.KeyVault/vaults/enableSoftDelete", equals = "false" },
              ]
            },
            # Purge protection must be present AND on.
            { field = "Microsoft.KeyVault/vaults/enablePurgeProtection", exists = "false" },
            { field = "Microsoft.KeyVault/vaults/enablePurgeProtection", equals = "false" },
          ]
        },
      ]
    }
    "then" = { effect = "[parameters('effect')]" }
  })
}

resource "azurerm_subscription_policy_assignment" "keyvault_protection" {
  name                 = "lab-keyvault-deletion-protection"
  display_name         = "Contoso lab: Key Vaults keep deletion protection (${var.keyvault_protection_effect})"
  subscription_id      = var.subscription_id
  policy_definition_id = azurerm_policy_definition.keyvault_protection.id

  parameters = jsonencode({
    effect = { value = var.keyvault_protection_effect }
  })

  non_compliance_message {
    content = "Key Vaults in this lab keep soft delete and purge protection on, so secrets cannot be destroyed for good."
  }
}
