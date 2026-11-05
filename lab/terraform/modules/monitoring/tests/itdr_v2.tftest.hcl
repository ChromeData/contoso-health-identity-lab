# Offline regression guard for the second ITDR set (itdr_v2.tf), the
# operator_ips watchlist, the extended vault feed columns and the
# auth-method-changed-by-admin severity fix. No tenant, no state:
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (cross-variable validation needs >= 1.9).
#
# What it proves:
#   * the v2 flag adds nothing by default and refuses to run without the
#     v1 flag (whose telemetry it reads);
#   * each v2 rule's severity, schedule and MITRE mapping, and that every
#     entity / custom-detail / severity column is in its .kql text;
#   * the two 14-day rules never reach the Log Analytics path (its window
#     stops at P2D), and the LA mute matches how long a hit stays matchable;
#   * the SoD and vault rules never trigger containment, by default or by
#     key list;
#   * the operator_ips watchlist: alias = what the KQL reads, one row per
#     /32 with Owner + ExpiresOn, IPs only as sensitive values, wide ranges
#     refused, an expiry required and an expired date warned about;
#   * the extended vault columns stay off until asked for, and the table and
#     DCR stream stay identical either way;
#   * auth-method-changed-by-admin carries the privileged-group grant leg.

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
  # watchlist_id on the items is parsed by the provider, so a path-form id.
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

run "v2_off_by_default" {
  command = plan
  variables {
    enable_sentinel        = true
    enable_itdr_detections = true
  }

  assert {
    condition = (
      length(azurerm_sentinel_alert_rule_scheduled.this) == 15 && length(azurerm_sentinel_alert_rule_nrt.this) == 1 &&
      !anytrue([for k in keys(azurerm_sentinel_alert_rule_scheduled.this) : contains(["device_code_signin", "security_info_registered_risky", "dc_logon_outside_operator_allowlist", "vault_privileged_access_anomaly", "sod_violation_granted", "pim_activation_without_auth_context"], k)])
    )
    error_message = "enable_itdr_detections alone must keep the 5 core + 11 ITDR rules: the v2 set is opt-in."
  }
  assert {
    condition     = length(azurerm_sentinel_watchlist.operator_ips) == 0 && length(azurerm_sentinel_watchlist_item.operator_ips) == 0 && output.operator_ips_watchlist_id == null
    error_message = "No watchlist without enable_itdr_detections_v2."
  }
  assert {
    condition     = !contains([for c in azurerm_log_analytics_workspace_table_custom_log.vault_checkout[0].column : c.name], "Ticket")
    error_message = "The extended vault columns are opt-in (vault_feed_v2_columns)."
  }
}

run "v2_needs_v1" {
  command = plan
  variables {
    enable_itdr_detections_v2 = true
  }
  expect_failures = [var.enable_itdr_detections_v2]
}

run "sentinel_v2_rules" {
  command = apply
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    operator_ip_ranges        = ["203.0.113.7/32", "198.51.100.4/32"]
    operator_ips_expires_on   = "2027-01-20"
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 21 && length(azurerm_sentinel_alert_rule_nrt.this) == 1 && length(output.itdr_rule_keys) == 17
    error_message = "Expected 5 core + 11 ITDR + 6 ITDR v2 Sentinel rules."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_sentinel_alert_rule_scheduled.this : alltrue([
        for em in r.entity_mapping : alltrue([for fm in em.field_mapping : strcontains(r.query, fm.column_name)])
      ])
    ])
    error_message = "Every mapped entity column must appear in the rule's KQL."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_sentinel_alert_rule_scheduled.this :
      r.custom_details == null ? true : alltrue([for col in values(r.custom_details) : strcontains(r.query, col)])
    ])
    error_message = "Every custom-detail column must appear in the rule's KQL."
  }
  assert {
    condition = alltrue([
      for k in output.itdr_rule_keys :
      length(azurerm_sentinel_alert_rule_scheduled.this[k].alert_details_override) == 1 &&
      azurerm_sentinel_alert_rule_scheduled.this[k].alert_details_override[0].severity_column_name == "Severity" &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, "| extend Severity") &&
      azurerm_sentinel_alert_rule_scheduled.this[k].event_grouping[0].aggregation_method == "AlertPerResult" &&
      azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].entity_matching_method == "Selected" &&
      contains(azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].by_alert_details, "Severity") &&
      contains(azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].by_entities, "Account") &&
      length(azurerm_sentinel_alert_rule_scheduled.this[k].techniques) > 0 &&
      alltrue([for t in azurerm_sentinel_alert_rule_scheduled.this[k].techniques : can(regex("^T[0-9]{4}$", t))])
    ])
    error_message = "Every ITDR rule, v2 included, needs dynamic severity, one alert per row, per-identity+severity grouping and parent MITRE technique ids."
  }
  # Static (fallback) severity per v2 rule; the Severity column overrides it
  # per alert.
  assert {
    condition = (
      azurerm_sentinel_alert_rule_scheduled.this["device_code_signin"].severity == "Medium" &&
      azurerm_sentinel_alert_rule_scheduled.this["security_info_registered_risky"].severity == "Medium" &&
      azurerm_sentinel_alert_rule_scheduled.this["dc_logon_outside_operator_allowlist"].severity == "High" &&
      azurerm_sentinel_alert_rule_scheduled.this["vault_privileged_access_anomaly"].severity == "Medium" &&
      azurerm_sentinel_alert_rule_scheduled.this["sod_violation_granted"].severity == "Medium" &&
      azurerm_sentinel_alert_rule_scheduled.this["pim_activation_without_auth_context"].severity == "High"
    )
    error_message = "v2 static severities changed."
  }
  # Schedules: each period covers the history its .kql reads.
  assert {
    condition = (
      azurerm_sentinel_alert_rule_scheduled.this["device_code_signin"].query_frequency == "PT5M" &&
      azurerm_sentinel_alert_rule_scheduled.this["device_code_signin"].query_period == "PT1H" &&
      azurerm_sentinel_alert_rule_scheduled.this["security_info_registered_risky"].query_frequency == "PT1H" &&
      azurerm_sentinel_alert_rule_scheduled.this["security_info_registered_risky"].query_period == "P14D" &&
      azurerm_sentinel_alert_rule_scheduled.this["dc_logon_outside_operator_allowlist"].query_period == "PT1H" &&
      azurerm_sentinel_alert_rule_scheduled.this["vault_privileged_access_anomaly"].query_period == "PT6H" &&
      azurerm_sentinel_alert_rule_scheduled.this["sod_violation_granted"].query_frequency == "PT1H" &&
      azurerm_sentinel_alert_rule_scheduled.this["sod_violation_granted"].query_period == "P14D" &&
      azurerm_sentinel_alert_rule_scheduled.this["pim_activation_without_auth_context"].query_frequency == "PT1H" &&
      azurerm_sentinel_alert_rule_scheduled.this["pim_activation_without_auth_context"].query_period == "P1D"
    )
    error_message = "v2 schedules must match the look-back each .kql documents."
  }
  assert {
    condition = (
      contains(azurerm_sentinel_alert_rule_scheduled.this["device_code_signin"].techniques, "T1528") &&
      contains(azurerm_sentinel_alert_rule_scheduled.this["dc_logon_outside_operator_allowlist"].techniques, "T1133") &&
      contains(azurerm_sentinel_alert_rule_scheduled.this["dc_logon_outside_operator_allowlist"].tactics, "LateralMovement") &&
      contains(azurerm_sentinel_alert_rule_scheduled.this["vault_privileged_access_anomaly"].techniques, "T1555") &&
      contains(azurerm_sentinel_alert_rule_scheduled.this["security_info_registered_risky"].techniques, "T1556")
    )
    error_message = "v2 MITRE mapping lost a technique its .kql header names."
  }
  # The watchlist is the one the KQL reads, with the columns it reads.
  assert {
    condition = (
      length(azurerm_sentinel_watchlist.operator_ips) == 1 &&
      azurerm_sentinel_watchlist.operator_ips[0].name == "operator_ips" &&
      azurerm_sentinel_watchlist.operator_ips[0].item_search_key == "IpRange" &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["dc_logon_outside_operator_allowlist"].query, "_GetWatchlist('${azurerm_sentinel_watchlist.operator_ips[0].name}')") &&
      output.operator_ips_watchlist_id == azurerm_sentinel_watchlist.operator_ips[0].id
    )
    error_message = "The watchlist alias must be operator_ips with SearchKey IpRange - the name dc-logon-outside-operator-allowlist.kql reads."
  }
  assert {
    condition = (
      length(azurerm_sentinel_watchlist_item.operator_ips) == 2 &&
      alltrue([for i in azurerm_sentinel_watchlist_item.operator_ips : sort(keys(i.properties)) == tolist(["ExpiresOn", "IpRange", "Owner"])]) &&
      alltrue([for i in azurerm_sentinel_watchlist_item.operator_ips : i.properties["ExpiresOn"] == "2027-01-20" && i.properties["Owner"] == "lab-operator"]) &&
      alltrue([for i in azurerm_sentinel_watchlist_item.operator_ips : i.watchlist_id == azurerm_sentinel_watchlist.operator_ips[0].id]) &&
      azurerm_sentinel_watchlist_item.operator_ips[0].properties["IpRange"] == "203.0.113.7/32"
    )
    error_message = "One watchlist row per operator range, each with IpRange, Owner and ExpiresOn."
  }
  assert {
    condition = alltrue([
      for i in azurerm_sentinel_watchlist_item.operator_ips :
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", i.name))
    ])
    error_message = "Watchlist item names must be deterministic UUIDs (never derived from the IP)."
  }
  # auth-method-changed-by-admin severity fix: the grant leg is there and
  # its privileged-group list is rendered like the other rules'.
  assert {
    condition = (
      azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].query_period == "P2D" &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].query, "let PrivilegedGroupIds = dynamic([]); // @@PRIVILEGED_GROUP_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].query, "let GrantHistory = 2d;") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].query, "PrivilegedById or PrivilegedByName or PrivilegedByGrant") &&
      azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].custom_details["PrivilegeBasis"] == "PrivilegeBasis"
    )
    error_message = "auth-method-changed-by-admin must judge privilege by id list, a role / privileged-group grant in its 2-day period, and naming."
  }
}

run "v2_rules_render_id_lists" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    iac_principal_ids         = ["11111111-1111-1111-1111-111111111111"]
    privileged_group_ids      = ["33333333-3333-3333-3333-333333333333"]
    break_glass_group_ids     = ["44444444-4444-4444-4444-444444444444"]
    privileged_user_ids       = ["55555555-5555-5555-5555-555555555555"]
    azure_pim_group_ids       = ["66666666-6666-6666-6666-666666666666"]
  }

  assert {
    condition = alltrue([
      for k in ["device_code_signin", "security_info_registered_risky", "auth_method_changed_by_admin"] :
      strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, "dynamic([\"55555555-5555-5555-5555-555555555555\"]); // @@PRIVILEGED_USER_IDS@@")
    ])
    error_message = "privileged_user_ids must be rendered into every rule that judges privileged users by id."
  }
  assert {
    condition     = strcontains(azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].query, "dynamic([\"33333333-3333-3333-3333-333333333333\"]); // @@PRIVILEGED_GROUP_IDS@@")
    error_message = "privileged_group_ids must reach auth-method-changed-by-admin's grant leg."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_sentinel_alert_rule_scheduled.this : !strcontains(r.query, "dynamic([]); // @@")
    ])
    error_message = "With every list set, no rule (v2 included) may keep an unrendered empty placeholder."
  }
}

run "la_path_skips_sentinel_only_rules" {
  command = plan
  variables {
    enable_la_alerts          = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    alert_email               = "secops@example.com"
  }

  assert {
    condition = (
      length(azurerm_monitor_scheduled_query_rules_alert_v2.this) == 20 &&
      !contains(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this), "security_info_registered_risky") &&
      !contains(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this), "sod_violation_granted") &&
      output.sentinel_only_rule_keys == ["security_info_registered_risky", "sod_violation_granted"]
    )
    error_message = "The LA path carries 22 - 2 rules: the two 14-day rules are Sentinel only."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_monitor_scheduled_query_rules_alert_v2.this :
      contains(["PT5M", "PT15M", "PT30M", "PT1H", "PT2H", "PT3H", "PT6H", "P1D", "P2D"], r.window_duration)
    ])
    error_message = "A log search alert looks back at most P2D."
  }
  assert {
    condition = (
      azurerm_monitor_scheduled_query_rules_alert_v2.this["auth_method_changed_by_admin"].window_duration == "P2D" &&
      azurerm_monitor_scheduled_query_rules_alert_v2.this["auth_method_changed_by_admin"].mute_actions_after_alert_duration == "PT1H" &&
      azurerm_monitor_scheduled_query_rules_alert_v2.this["vault_privileged_access_anomaly"].mute_actions_after_alert_duration == "PT1H" &&
      azurerm_monitor_scheduled_query_rules_alert_v2.this["pim_activation_without_auth_context"].mute_actions_after_alert_duration == "PT1H" &&
      azurerm_monitor_scheduled_query_rules_alert_v2.this["device_code_signin"].mute_actions_after_alert_duration == "PT1H" &&
      azurerm_monitor_scheduled_query_rules_alert_v2.this["dc_logon_outside_operator_allowlist"].mute_actions_after_alert_duration == "PT1H"
    )
    error_message = "LA mute = how long one hit stays matchable (1 h), not the wider window - one hit, one email."
  }
  assert {
    condition     = length(azurerm_sentinel_watchlist.operator_ips) == 0
    error_message = "The watchlist is a Sentinel object: none on the LA path."
  }
}

run "containment_never_sod_or_vault" {
  command = apply
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    enable_itdr_containment   = true
    containment_playbook_id   = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
  }

  assert {
    condition = (
      length(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues) == 15 &&
      !contains(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_scheduled.this["sod_violation_granted"].id) &&
      !contains(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_scheduled.this["vault_privileged_access_anomaly"].id) &&
      contains(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_scheduled.this["device_code_signin"].id)
    )
    error_message = "Containment covers the 17 ITDR rules minus sod_violation_granted and vault_privileged_access_anomaly."
  }
}

run "containment_keys_refuse_sod" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    enable_itdr_containment   = true
    containment_rule_keys     = ["identity_risk", "sod_violation_granted"]
  }
  expect_failures = [var.containment_rule_keys]
}

run "exclude_accepts_every_rule_key" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    itdr_exclude_rules = [
      "app_credential_added", "app_consent_granted", "ca_policy_changed", "role_assigned_outside_pim",
      "pim_group_member_added_outside_pim", "auth_method_changed_by_admin", "identity_risk",
      "tier0_logon_without_checkout", "ad_privileged_group_change", "kerberoast_rc4_service_ticket",
      "dcsync_replication_request",
      "device_code_signin", "security_info_registered_risky", "dc_logon_outside_operator_allowlist",
      "vault_privileged_access_anomaly", "sod_violation_granted", "pim_activation_without_auth_context",
    ]
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 4 && length(azurerm_sentinel_alert_rule_nrt.this) == 1 && length(output.itdr_rule_keys) == 0
    error_message = "Every ITDR key (v1 + v2) must be a valid exclusion; excluding all leaves the 5 core rules (4 scheduled + the break-glass NRT rule)."
  }
}

run "watchlist_before_dc_rule" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    itdr_exclude_rules        = ["dc_logon_outside_operator_allowlist", "pim_activation_without_auth_context"]
  }

  assert {
    condition = (
      length(azurerm_sentinel_watchlist.operator_ips) == 1 &&
      length(azurerm_sentinel_watchlist_item.operator_ips) == 0 &&
      !contains(keys(azurerm_sentinel_alert_rule_scheduled.this), "dc_logon_outside_operator_allowlist") &&
      length(azurerm_sentinel_alert_rule_scheduled.this) == 19
    )
    error_message = "The watchlist exists (empty without ranges) while the DC01 rule is still held back."
  }
}

run "operator_ips_reject_wide_range" {
  command = plan
  variables {
    operator_ip_ranges = ["203.0.113.7/32", "203.0.113.0/24"]
  }
  expect_failures = [var.operator_ip_ranges]
}

run "operator_ips_reject_any" {
  command = plan
  variables {
    operator_ip_ranges = ["0.0.0.0/0"]
  }
  expect_failures = [var.operator_ip_ranges]
}

run "operator_ips_reject_bare_ip" {
  command = plan
  variables {
    operator_ip_ranges = ["203.0.113.7"]
  }
  expect_failures = [var.operator_ip_ranges]
}

run "operator_ips_need_expiry" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    operator_ip_ranges        = ["203.0.113.7/32"]
  }
  expect_failures = [azurerm_sentinel_watchlist_item.operator_ips]
}

run "operator_ips_expiry_must_be_a_date" {
  command = plan
  variables {
    operator_ips_expires_on = "2027-02-30"
  }
  expect_failures = [var.operator_ips_expires_on]
}

run "operator_ips_expired_warns" {
  command = plan
  variables {
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    operator_ip_ranges        = ["203.0.113.7/32"]
    operator_ips_expires_on   = "2020-01-01"
  }
  expect_failures = [check.operator_ips_not_expired]
}

run "operator_ips_owner_is_a_role_not_an_email" {
  command = plan
  variables {
    operator_ips_owner = "someone@example.com"
  }
  expect_failures = [var.operator_ips_owner]
}

run "vault_feed_v2_columns" {
  command = apply
  variables {
    enable_itdr_detections = true
    vault_feed_v2_columns  = true
  }

  assert {
    condition = (
      [for c in azurerm_log_analytics_workspace_table_custom_log.vault_checkout[0].column : c.name] ==
      [for c in one(azurerm_monitor_data_collection_rule.vault_checkout[0].stream_declaration).column : c.name]
    )
    error_message = "Table columns and DCR stream columns must stay identical (transform_kql = source)."
  }
  assert {
    condition = alltrue([
      for n in ["Ticket", "Operator", "ErrorText"] :
      contains([for c in azurerm_log_analytics_workspace_table_custom_log.vault_checkout[0].column : c.name], n)
    ])
    error_message = "vault_feed_v2_columns must add Ticket, Operator and ErrorText (vault-privileged-access-anomaly.kql)."
  }
}
