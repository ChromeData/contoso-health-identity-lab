# Offline regression guard for the third ITDR set (itdr_v3.tf): the dormant
# admin sign-in rule and the Key Vault bulk secret-read rule, ported on
# 2026-11-06 from Sentinel-Privileged-Access. No tenant, no state:
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (CI's version).
#
# What it proves:
#   * the v3 flag adds nothing by default and refuses to run without the
#     v1 flag;
#   * both rules' schedule (1 h / 14 days), severity, MITRE mapping, and
#     the Key Vault rule's tactic spelled as Sentinel names it
#     (CredentialAccess; the old repo had "Credentialaccess");
#   * every entity / custom-detail column is in the .kql text, and the Key
#     Vault rule keys callers on the object id before the UPN;
#   * the dormant rule judges privileged users by the rendered object ids;
#   * both stay off the Log Analytics path (14-day look-back > P2D);
#   * the Key Vault rule never triggers containment, by default or by key
#     list; the dormant rule does (it only asks).

mock_provider "azurerm" {
  mock_resource "azurerm_monitor_data_collection_endpoint" {
    defaults = {
      id                      = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Insights/dataCollectionEndpoints/dce-idlab-itdr"
      logs_ingestion_endpoint = "https://dce-idlab-itdr-abcd.eastus2-1.ingest.monitor.azure.com"
    }
  }
  mock_resource "azurerm_monitor_data_collection_rule" {
    defaults = {
      id           = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Insights/dataCollectionRules/dcr-idlab"
      immutable_id = "dcr-00000000000000000000000000000000"
    }
  }
  mock_resource "azurerm_monitor_action_group" {
    defaults = {
      id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Insights/actionGroups/ag-identity-secops"
    }
  }
  mock_resource "azurerm_sentinel_watchlist" {
    defaults = {
      id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab/providers/Microsoft.SecurityInsights/watchlists/operator_ips"
    }
  }
}

variables {
  resource_group_name        = "rg-identity-lab"
  log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
}

run "v3_off_by_default" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
  }

  assert {
    condition = (
      length(azurerm_sentinel_alert_rule_scheduled.this) == 21 &&
      !anytrue([for k in keys(azurerm_sentinel_alert_rule_scheduled.this) : contains(["dormant_privileged_account_reactivation", "keyvault_bulk_secret_read"], k)])
    )
    error_message = "v1 + v2 alone must keep today's 21 scheduled rules: the v3 set is opt-in."
  }
}

run "v3_needs_v1" {
  command = plan
  variables {
    enable_itdr_detections_v3 = true
  }
  expect_failures = [var.enable_itdr_detections_v3]
}

run "sentinel_v3_rules" {
  command = apply
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    enable_itdr_detections_v3 = true
    privileged_user_ids       = ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 23 && length(azurerm_sentinel_alert_rule_nrt.this) == 1 && length(output.itdr_rule_keys) == 19
    error_message = "Expected 5 core + 11 ITDR + 6 v2 + 2 v3 rules (23 scheduled + the break-glass NRT rule)."
  }
  assert {
    condition = alltrue([
      for k in ["dormant_privileged_account_reactivation", "keyvault_bulk_secret_read"] :
      azurerm_sentinel_alert_rule_scheduled.this[k].query_frequency == "PT1H" &&
      azurerm_sentinel_alert_rule_scheduled.this[k].query_period == "P14D" &&
      azurerm_sentinel_alert_rule_scheduled.this[k].alert_details_override[0].severity_column_name == "Severity" &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, "| extend Severity") &&
      azurerm_sentinel_alert_rule_scheduled.this[k].event_grouping[0].aggregation_method == "AlertPerResult" &&
      contains(azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].by_entities, "Account") &&
      alltrue([for em in azurerm_sentinel_alert_rule_scheduled.this[k].entity_mapping : alltrue([for fm in em.field_mapping : strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, fm.column_name)])]) &&
      alltrue([for col in values(azurerm_sentinel_alert_rule_scheduled.this[k].custom_details) : strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, col)])
    ])
    error_message = "Both v3 rules: 1 h / 14 days (Sentinel's longest look-back), dynamic severity, one alert per row, grouped per Account, and every mapped column in the KQL."
  }
  assert {
    condition = (
      azurerm_sentinel_alert_rule_scheduled.this["dormant_privileged_account_reactivation"].severity == "High" &&
      azurerm_sentinel_alert_rule_scheduled.this["dormant_privileged_account_reactivation"].techniques == toset(["T1078"]) &&
      azurerm_sentinel_alert_rule_scheduled.this["keyvault_bulk_secret_read"].severity == "Medium" &&
      azurerm_sentinel_alert_rule_scheduled.this["keyvault_bulk_secret_read"].tactics == toset(["CredentialAccess"]) &&
      azurerm_sentinel_alert_rule_scheduled.this["keyvault_bulk_secret_read"].techniques == toset(["T1555", "T1552"])
    )
    error_message = "Static severities and MITRE: the Key Vault rule's tactic is CredentialAccess, as Sentinel names it (the old repo's \"Credentialaccess\" is not a Sentinel tactic)."
  }
  assert {
    condition = strcontains(
      azurerm_sentinel_alert_rule_scheduled.this["keyvault_bulk_secret_read"].query,
      "coalesce(identity_claim_oid_g, identity_claim_appid_g, tolower(identity_claim_upn_s), \"(unknown)\")"
    )
    error_message = "The Key Vault rule keys callers on object id, then app id, then UPN: managed identities have no UPN."
  }
  assert {
    condition     = strcontains(azurerm_sentinel_alert_rule_scheduled.this["dormant_privileged_account_reactivation"].query, "let PrivilegedUserIds = dynamic([\"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\"]); // @@PRIVILEGED_USER_IDS@@")
    error_message = "The dormant rule judges privileged users by the rendered immutable object ids."
  }
}

run "la_path_skips_v3" {
  command = plan
  variables {
    enable_la_alerts          = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    enable_itdr_detections_v3 = true
    alert_email               = "secops@example.com"
  }

  assert {
    condition = (
      length(azurerm_monitor_scheduled_query_rules_alert_v2.this) == 20 &&
      !contains(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this), "dormant_privileged_account_reactivation") &&
      !contains(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this), "keyvault_bulk_secret_read") &&
      toset(output.sentinel_only_rule_keys) == toset(["security_info_registered_risky", "sod_violation_granted", "dormant_privileged_account_reactivation", "keyvault_bulk_secret_read"])
    )
    error_message = "The LA path carries 24 - 4 rules: the four 14-day rules are Sentinel only."
  }
}

run "containment_never_keyvault" {
  command = apply
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    enable_itdr_detections_v3 = true
    enable_itdr_containment   = true
    containment_playbook_id   = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
  }

  assert {
    condition = (
      length(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues) == 16 &&
      !contains(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_scheduled.this["keyvault_bulk_secret_read"].id) &&
      contains(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_scheduled.this["dormant_privileged_account_reactivation"].id)
    )
    error_message = "Containment covers the 19 ITDR rules minus SoD, vault and Key Vault (16); the dormant rule is in, the Key Vault rule is not."
  }
}

run "containment_keys_refuse_keyvault" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v3 = true
    enable_itdr_containment   = true
    containment_rule_keys     = ["dormant_privileged_account_reactivation", "keyvault_bulk_secret_read"]
  }
  expect_failures = [var.containment_rule_keys]
}

run "exclude_accepts_v3_keys" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v3 = true
    itdr_exclude_rules        = ["dormant_privileged_account_reactivation", "keyvault_bulk_secret_read"]
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 15
    error_message = "Both v3 keys are valid exclusions; excluding them leaves the 5 core + 11 ITDR rules (15 scheduled + NRT)."
  }
}
