# Offline mocked plan of modules/azure-guardrails (no tenant, no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins:
#   * both guardrails go out in Audit unless someone sets Deny on purpose;
#   * the Owner rule MATCHES a real role assignment's roleDefinitionId, which
#     carries /subscriptions/<id> in front (the old repo's `equals` on the
#     bare /providers/... id never did - these runs fail against it), and
#     does not match another role such as Contributor;
#   * the allowed principals reach the assignment, and a Deny with nobody
#     allowed is refused at plan;
#   * the Key Vault rule is Microsoft's built-in logic: purge protection
#     must exist and be on, a vault being recovered is skipped, and a vault
#     that merely leaves enableSoftDelete out on a current API is fine
#     (the branch structure is checked, not just the strings).

mock_provider "azurerm" {}

variables {
  subscription_id = "/subscriptions/22222222-2222-2222-2222-222222222222"
}

run "audit_by_default" {
  command = plan

  assert {
    condition = (
      jsondecode(azurerm_subscription_policy_assignment.no_standing_owner.parameters).effect.value == "Audit" &&
      jsondecode(azurerm_subscription_policy_assignment.keyvault_protection.parameters).effect.value == "Audit"
    )
    error_message = "both guardrails must be assigned in Audit unless Deny is chosen deliberately"
  }
  assert {
    condition = (
      jsondecode(azurerm_policy_definition.no_standing_owner.parameters).effect.defaultValue == "Audit" &&
      jsondecode(azurerm_policy_definition.keyvault_protection.parameters).effect.defaultValue == "Audit"
    )
    error_message = "an assignment that forgets the effect must also land in Audit"
  }
  assert {
    condition = (
      azurerm_subscription_policy_assignment.no_standing_owner.subscription_id == "/subscriptions/22222222-2222-2222-2222-222222222222" &&
      azurerm_subscription_policy_assignment.keyvault_protection.subscription_id == "/subscriptions/22222222-2222-2222-2222-222222222222"
    )
    error_message = "both are assigned at the lab subscription"
  }
}

# The Owner rule, replayed against role definition ids the way Azure Policy
# would compare them (equals = case-insensitive equality; like with a single
# leading * = case-insensitive "ends with").
run "owner_rule_matches_the_real_assignment_id" {
  command = plan

  variables {
    owner_allowed_principal_ids = ["33333333-3333-3333-3333-333333333333"]
  }

  assert {
    condition = alltrue([
      for c in jsondecode(azurerm_policy_definition.no_standing_owner.policy_rule)["if"].allOf :
      (
        lower(try(c.equals, "")) == lower("/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
        || (startswith(try(c.like, ""), "*") && endswith(lower("/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"), lower(trimprefix(try(c.like, ""), "*"))))
      )
      if try(c.field, "") == "Microsoft.Authorization/roleAssignments/roleDefinitionId"
    ])
    error_message = "the Owner rule must match an Owner assignment's real roleDefinitionId (/subscriptions/<id>/providers/...): an exact match on /providers/... never fires"
  }
  assert {
    condition = alltrue([
      for c in jsondecode(azurerm_policy_definition.no_standing_owner.policy_rule)["if"].allOf :
      (
        endswith(lower(trimprefix(try(c.like, ""), "*")), "/providers/microsoft.authorization/roledefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635") &&
        !endswith(lower("/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"), lower(trimprefix(try(c.like, ""), "*"))) &&
        length(regexall("\\*", c.like)) == 1
      )
      if try(c.field, "") == "Microsoft.Authorization/roleAssignments/roleDefinitionId"
    ]) && length([for c in jsondecode(azurerm_policy_definition.no_standing_owner.policy_rule)["if"].allOf : c if try(c.field, "") == "Microsoft.Authorization/roleAssignments/roleDefinitionId"]) == 1
    error_message = "exactly one roleDefinitionId condition: a single leading wildcard on the Owner GUID, which does not also catch Contributor (b24988ac-...)"
  }
  assert {
    condition = anytrue([
      for c in jsondecode(azurerm_policy_definition.no_standing_owner.policy_rule)["if"].allOf :
      try(c.field, "") == "Microsoft.Authorization/roleAssignments/principalId" && try(c.notIn, "") == "[parameters('allowedPrincipalIds')]"
    ])
    error_message = "the allowed principals must be excluded by principalId"
  }
  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.no_standing_owner.parameters).allowedPrincipalIds.value == ["33333333-3333-3333-3333-333333333333"]
    error_message = "owner_allowed_principal_ids must reach the assignment"
  }
}

run "deny_with_nobody_allowed_is_refused" {
  command = plan

  variables {
    standing_owner_effect = "Deny"
  }

  expect_failures = [azurerm_subscription_policy_assignment.no_standing_owner]
}

run "deny_with_the_operator_allowed_plans" {
  command = plan

  variables {
    standing_owner_effect       = "Deny"
    keyvault_protection_effect  = "Deny"
    owner_allowed_principal_ids = ["33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444"]
  }

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.no_standing_owner.parameters).effect.value == "Deny" && jsondecode(azurerm_subscription_policy_assignment.keyvault_protection.parameters).effect.value == "Deny"
    error_message = "Deny is passed through when chosen"
  }
}

run "keyvault_rule_is_the_builtin_logic" {
  command = plan

  assert {
    condition     = strcontains(azurerm_policy_definition.keyvault_protection.policy_rule, jsonencode({ field = "Microsoft.KeyVault/vaults/enablePurgeProtection", exists = "false" }))
    error_message = "a vault without purge protection set at all must be caught"
  }
  assert {
    condition     = strcontains(azurerm_policy_definition.keyvault_protection.policy_rule, jsonencode({ field = "Microsoft.KeyVault/vaults/enablePurgeProtection", equals = "false" }))
    error_message = "a vault with purge protection off must be caught"
  }
  assert {
    condition     = strcontains(azurerm_policy_definition.keyvault_protection.policy_rule, jsonencode({ field = "Microsoft.KeyVault/vaults/createMode", notEquals = "recover" }))
    error_message = "a vault being recovered from soft delete must be skipped (built-in behaviour)"
  }
  assert {
    condition     = !strcontains(azurerm_policy_definition.keyvault_protection.policy_rule, "notEquals\":\"true")
    error_message = "no notEquals \"true\": it flags a vault that just leaves enableSoftDelete out, which is normal on current API versions"
  }
  assert {
    condition     = azurerm_policy_definition.keyvault_protection.mode == "Indexed" && azurerm_policy_definition.no_standing_owner.mode == "All"
    error_message = "Key Vault: Indexed (as the built-in); role assignments carry no location or tags, so the Owner rule must be All"
  }
}

# The branch structure, not just the strings: the "soft delete missing"
# check must sit only under the old-API guard, or a compliant vault on a
# current API (which leaves enableSoftDelete out) would be flagged.
run "keyvault_rule_branches_are_guarded_by_api_version" {
  command = plan

  assert {
    condition = alltrue([
      for b in jsondecode(azurerm_policy_definition.keyvault_protection.policy_rule)["if"].allOf[2].anyOf :
      strcontains(jsonencode(b), jsonencode({ less = "2019-09-01", value = "[requestContext().apiVersion]" }))
      if strcontains(jsonencode(b), jsonencode({ exists = "false", field = "Microsoft.KeyVault/vaults/enableSoftDelete" }))
    ])
    error_message = "enableSoftDelete exists=false may only be checked under apiVersion < 2019-09-01"
  }
  assert {
    condition = length([
      for b in jsondecode(azurerm_policy_definition.keyvault_protection.policy_rule)["if"].allOf[2].anyOf : b
      if strcontains(jsonencode(b), jsonencode({ exists = "false", field = "Microsoft.KeyVault/vaults/enableSoftDelete" }))
    ]) == 1
    error_message = "exactly one branch checks a missing enableSoftDelete (the old-API one)"
  }
  assert {
    condition = anytrue([
      for b in jsondecode(azurerm_policy_definition.keyvault_protection.policy_rule)["if"].allOf[2].anyOf :
      jsonencode(b) == jsonencode({ allOf = [{ greaterOrEquals = "2019-09-01", value = "[requestContext().apiVersion]" }, { equals = "false", field = "Microsoft.KeyVault/vaults/enableSoftDelete" }] })
    ])
    error_message = "on a current API only an explicit enableSoftDelete = false is caught"
  }
  assert {
    condition = length(setintersection(
      toset([for b in jsondecode(azurerm_policy_definition.keyvault_protection.policy_rule)["if"].allOf[2].anyOf : jsonencode(b)]),
      toset([jsonencode({ exists = "false", field = "Microsoft.KeyVault/vaults/enablePurgeProtection" }), jsonencode({ equals = "false", field = "Microsoft.KeyVault/vaults/enablePurgeProtection" })])
    )) == 2
    error_message = "the two purge-protection checks are top-level branches (any API version)"
  }
  assert {
    condition     = length(jsondecode(azurerm_policy_definition.keyvault_protection.policy_rule)["if"].allOf[2].anyOf) == 4
    error_message = "four branches, as in the built-in: old API, current API, purge protection missing, purge protection off"
  }
}

run "bad_inputs_are_refused" {
  command = plan

  variables {
    standing_owner_effect       = "deny-ish"
    owner_allowed_principal_ids = ["not-a-guid"]
  }

  expect_failures = [var.standing_owner_effect, var.owner_allowed_principal_ids]
}
