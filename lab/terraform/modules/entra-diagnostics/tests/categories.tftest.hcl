# Offline mocked plan of modules/entra-diagnostics (no tenant, no state):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).
#
# Pins the tenant log export contract:
#   * the baseline exports the user, workload-identity (service principal +
#     managed identity) and Microsoft Graph activity categories the ITDR and
#     NHI detections need, and NO risk category (P2 tables stay opt-in);
#   * enable_identity_protection_logs (or the older extra_categories path
#     envs/bootstrap uses) ADDS the four risk categories to the baseline,
#     never instead of it, and never duplicates one;
#   * a typo'd or table-name category, and a baseline without AuditLogs or
#     SignInLogs, fail at plan instead of at apply in the tenant.

mock_provider "azurerm" {}

variables {
  log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
}

run "baseline_exports_user_nhi_and_graph_categories" {
  command = plan

  assert {
    condition = toset(output.categories) == toset([
      "AuditLogs",
      "SignInLogs",
      "NonInteractiveUserSignInLogs",
      "ServicePrincipalSignInLogs",
      "ManagedIdentitySignInLogs",
      "ProvisioningLogs",
      "MicrosoftGraphActivityLogs",
    ])
    error_message = "baseline must be exactly the seven user / workload-identity / provisioning / Graph activity categories"
  }
  assert {
    condition     = toset([for l in azurerm_monitor_aad_diagnostic_setting.entra.enabled_log : l.category]) == toset(output.categories)
    error_message = "the planned enabled_log blocks must match the categories output"
  }
  assert {
    condition     = alltrue([for c in ["RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals", "ServicePrincipalRiskEvents"] : !contains(output.categories, c)])
    error_message = "risk categories (Entra ID P2) must not be exported by default"
  }
  assert {
    condition     = !output.identity_protection_logs_enabled
    error_message = "identity_protection_logs_enabled must be false by default"
  }
  assert {
    condition     = azurerm_monitor_aad_diagnostic_setting.entra.log_analytics_workspace_id == var.log_analytics_workspace_id
    error_message = "the setting must target the lab workspace"
  }
}

run "identity_protection_switch_adds_risk_categories" {
  command = plan

  variables {
    enable_identity_protection_logs = true
  }

  assert {
    condition     = alltrue([for c in ["RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals", "ServicePrincipalRiskEvents"] : contains(output.categories, c)])
    error_message = "enable_identity_protection_logs must add all four risk categories"
  }
  assert {
    condition     = alltrue([for c in ["AuditLogs", "SignInLogs", "ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs", "MicrosoftGraphActivityLogs"] : contains(output.categories, c)])
    error_message = "the risk categories must be added to, not replace, the baseline"
  }
  assert {
    condition     = length(output.categories) == 11 && length(azurerm_monitor_aad_diagnostic_setting.entra.enabled_log) == 11
    error_message = "baseline (7) + risk (4) = 11 enabled_log blocks"
  }
  assert {
    condition     = output.identity_protection_logs_enabled
    error_message = "identity_protection_logs_enabled must be true when the switch is on"
  }
}

# envs/bootstrap now uses enable_identity_protection_logs; the older
# extra_categories path must keep working, and combining both switches must
# not duplicate.
run "extra_categories_path_and_both_switches_deduplicate" {
  command = plan

  variables {
    enable_identity_protection_logs = true
    extra_categories                = ["RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals", "ServicePrincipalRiskEvents", "AuditLogs"]
  }

  assert {
    condition     = length(output.categories) == 11 && length(azurerm_monitor_aad_diagnostic_setting.entra.enabled_log) == 11
    error_message = "overlapping categories must be de-duplicated"
  }
  assert {
    condition     = output.identity_protection_logs_enabled
    error_message = "the extra_categories path must also count as risk logs enabled"
  }
}

run "table_name_instead_of_category_is_rejected" {
  command = plan

  variables {
    extra_categories = ["AADRiskyUsers"]
  }

  expect_failures = [azurerm_monitor_aad_diagnostic_setting.entra]
}

run "case_typo_is_rejected" {
  command = plan

  variables {
    categories = ["AuditLogs", "SignInLogs", "ManagedIdentitySigninLogs"]
  }

  expect_failures = [azurerm_monitor_aad_diagnostic_setting.entra]
}

run "dropping_audit_logs_is_rejected" {
  command = plan

  variables {
    categories = ["SignInLogs", "NonInteractiveUserSignInLogs"]
  }

  expect_failures = [azurerm_monitor_aad_diagnostic_setting.entra]
}

run "dropping_graph_activity_is_allowed_for_cost" {
  command = plan

  variables {
    categories = ["AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs", "ManagedIdentitySignInLogs", "ProvisioningLogs"]
  }

  assert {
    condition     = !contains(output.categories, "MicrosoftGraphActivityLogs") && length(output.categories) == 6
    error_message = "an operator must be able to drop the high-volume Graph activity category"
  }
}
