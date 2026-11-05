# Offline regression guard for the ITDR pack (itdr.tf, telemetry.tf) and the
# staging contract of the whole module. No tenant, no state:
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform 1.16.5 (cross-variable validation needs >= 1.9).
#
# What it proves:
#   * flags off -> the module creates NOTHING new (no trial clock, no cost);
#   * enable_itdr_detections alone -> only the telemetry plumbing;
#   * every entity / custom-detail / severity column a Sentinel rule maps
#     appears in that rule's .kql text (a renamed column in the KQL would
#     otherwise only fail at Sentinel rule creation, in the tenant);
#   * containment fires only for High ITDR incidents and refuses to be
#     switched on without Sentinel + detections;
#   * DC01 telemetry needs the VM id; the LA path keeps its mute rules.

# Path-form ids where another resource's argument validates them (the provider
# still parses ids under a mock). Sentinel rule ids stay random on purpose: the
# containment test needs them distinct.
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
}

variables {
  resource_group_name        = "rg-identity-lab"
  log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
}

run "defaults_create_nothing" {
  command = plan

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 0 && length(azurerm_monitor_scheduled_query_rules_alert_v2.this) == 0
    error_message = "With every flag at its default the module must create no detection rules."
  }
  assert {
    condition = (
      length(azurerm_log_analytics_workspace_table_custom_log.vault_checkout) == 0 &&
      length(azurerm_monitor_data_collection_endpoint.itdr) == 0 &&
      length(azurerm_monitor_data_collection_rule.vault_checkout) == 0 &&
      length(azurerm_virtual_machine_extension.dc_ama) == 0 &&
      length(azurerm_sentinel_automation_rule.contain) == 0 &&
      length(azurerm_sentinel_data_connector_microsoft_threat_protection.mdi) == 0
    )
    error_message = "ITDR telemetry, containment and the Defender for Identity connector must stay off by default."
  }
  assert {
    condition     = length(output.itdr_rule_keys) == 0 && output.vault_ingestion == null
    error_message = "ITDR outputs must be empty by default."
  }
}

run "itdr_telemetry_before_sentinel" {
  command = apply
  variables {
    enable_itdr_detections = true
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 0
    error_message = "enable_itdr_detections alone must not create Sentinel rules (no trial clock)."
  }
  assert {
    condition     = length(azurerm_log_analytics_workspace_table_custom_log.vault_checkout) == 1 && azurerm_log_analytics_workspace_table_custom_log.vault_checkout[0].name == "VaultCheckout_CL"
    error_message = "The VaultCheckout_CL table must be created so it has data before Sentinel validates the tier0 rule."
  }
  assert {
    condition     = azurerm_monitor_data_collection_rule.vault_checkout[0].data_flow[0].output_stream == "Custom-VaultCheckout_CL"
    error_message = "The DCR must write to Custom-VaultCheckout_CL."
  }
  assert {
    condition = (
      [for c in azurerm_log_analytics_workspace_table_custom_log.vault_checkout[0].column : c.name] ==
      [for c in one(azurerm_monitor_data_collection_rule.vault_checkout[0].stream_declaration).column : c.name]
    )
    error_message = "Table columns and DCR stream columns must be identical (transform_kql = source)."
  }
  assert {
    condition     = output.vault_ingestion.stream == "Custom-VaultCheckout" && output.vault_ingestion.table == "VaultCheckout_CL"
    error_message = "vault_ingestion output must name the stream and table ingest-vault-audit.sh posts to."
  }
}

run "sentinel_with_itdr_columns_match_kql" {
  command = apply
  variables {
    enable_sentinel        = true
    enable_itdr_detections = true
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 15 && length(azurerm_sentinel_alert_rule_nrt.this) == 1
    error_message = "Expected 5 core + 11 ITDR Sentinel rules: 15 scheduled + the break-glass NRT rule."
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
      for k, r in azurerm_sentinel_alert_rule_scheduled.this :
      alltrue([for o in r.alert_details_override : strcontains(r.query, "| extend Severity") && o.severity_column_name == "Severity"])
    ])
    error_message = "Dynamic-severity rules must compute a Severity column."
  }
  assert {
    condition = alltrue([
      for k in output.itdr_rule_keys :
      length(azurerm_sentinel_alert_rule_scheduled.this[k].alert_details_override) == 1 &&
      azurerm_sentinel_alert_rule_scheduled.this[k].event_grouping[0].aggregation_method == "AlertPerResult" &&
      azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].entity_matching_method == "Selected" &&
      contains(azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].by_alert_details, "Severity") &&
      contains(azurerm_sentinel_alert_rule_scheduled.this[k].incident[0].grouping[0].by_entities, "Account") &&
      length(azurerm_sentinel_alert_rule_scheduled.this[k].techniques) > 0
    ])
    error_message = "ITDR rules need dynamic severity, one alert per row, per-identity+severity grouping and MITRE techniques."
  }
  assert {
    condition     = azurerm_sentinel_alert_rule_scheduled.this["pim_activation"].incident[0].grouping[0].entity_matching_method == "AllEntities"
    error_message = "Core rules keep their original AllEntities grouping."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_sentinel_alert_rule_scheduled.this :
      alltrue([for t in coalesce(r.techniques, []) : can(regex("^T[0-9]{4}$", t))])
    ])
    error_message = "Sentinel techniques must be parent ids (T1234), not sub-techniques."
  }
  assert {
    condition     = azurerm_sentinel_alert_rule_scheduled.this["tier0_logon_without_checkout"].query_period == "PT3H"
    error_message = "tier0 rule needs a 3 h period to see the Vault history its KQL reads."
  }
  assert {
    condition     = length(azurerm_sentinel_automation_rule.contain) == 0
    error_message = "Containment must stay off until enable_itdr_containment."
  }
}

run "containment_high_itdr_only" {
  command = apply
  variables {
    enable_sentinel         = true
    enable_itdr_detections  = true
    enable_itdr_containment = true
    containment_playbook_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
  }

  assert {
    condition     = length(azurerm_sentinel_automation_rule.contain) == 1
    error_message = "Containment automation rule expected."
  }
  assert {
    condition = (
      jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[1].conditionProperties.propertyName == "IncidentSeverity" &&
      jsonencode(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[1].conditionProperties.propertyValues) == jsonencode(["High"])
    )
    error_message = "Containment must be gated on IncidentSeverity == High."
  }
  assert {
    condition = (
      length(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues) == 11 &&
      !contains(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_scheduled.this["pim_activation"].id)
    )
    error_message = "Containment must cover exactly the 11 ITDR rules and never a core rule."
  }
  assert {
    condition     = azurerm_sentinel_automation_rule.contain[0].order == 2 && azurerm_sentinel_automation_rule.contain[0].triggers_when == "Created"
    error_message = "Containment runs after notify (order 2), on incident creation."
  }
  assert {
    condition     = length(azurerm_sentinel_automation_rule.contain_on_alert_added) == 0
    error_message = "The alert-added trigger is opt-in (containment_on_alert_added defaults to false)."
  }
}

run "containment_subset_of_rules" {
  command = apply
  variables {
    enable_sentinel         = true
    enable_itdr_detections  = true
    enable_itdr_containment = true
    containment_rule_keys   = ["identity_risk"]
    containment_playbook_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
  }

  assert {
    condition     = jsonencode(jsondecode(azurerm_sentinel_automation_rule.contain[0].condition_json)[0].conditionProperties.propertyValues) == jsonencode([azurerm_sentinel_alert_rule_scheduled.this["identity_risk"].id])
    error_message = "containment_rule_keys must narrow the trigger to the listed rules."
  }
}

run "containment_refuses_without_sentinel" {
  command = plan
  variables {
    enable_itdr_detections  = true
    enable_itdr_containment = true
  }
  expect_failures = [var.enable_itdr_containment]
}

run "unknown_exclude_key_rejected" {
  command = plan
  variables {
    itdr_exclude_rules = ["no_such_rule"]
  }
  expect_failures = [var.itdr_exclude_rules]
}

run "exclude_holds_back_one_rule" {
  command = plan
  variables {
    enable_sentinel        = true
    enable_itdr_detections = true
    itdr_exclude_rules     = ["tier0_logon_without_checkout", "identity_risk"]
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.this) == 13 && !contains(keys(azurerm_sentinel_alert_rule_scheduled.this), "identity_risk")
    error_message = "itdr_exclude_rules must hold rules back (15 scheduled - 2 = 13; break-glass is NRT)."
  }
}

run "dc_security_events" {
  command = apply
  variables {
    enable_itdr_detections     = true
    collect_dc_security_events = true
    dc_vm_id                   = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Compute/virtualMachines/vm-dc01"
  }

  assert {
    condition = (
      length(azurerm_virtual_machine_extension.dc_ama) == 1 &&
      length(azurerm_monitor_data_collection_rule_association.dc_security) == 1 &&
      azurerm_monitor_data_collection_rule.dc_security[0].kind == "Windows"
    )
    error_message = "DC01 needs the AMA extension, a Windows DCR and the association."
  }
  assert {
    condition = (
      strcontains(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries[0], "EventID=4624") &&
      strcontains(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries[0], "EventID=4672") &&
      azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].streams == tolist(["Microsoft-SecurityEvent"])
    )
    error_message = "The DC01 DCR must collect 4624 + 4672 into SecurityEvent (the tier0 rule reads them)."
  }
  assert {
    condition = alltrue([
      for id in ["4728", "4732", "4756", "4769"] :
      strcontains(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries[0], "EventID=${id}")
    ])
    error_message = "The AD rules need 4728/4732/4756 (privileged group adds) and 4769 (Kerberoasting)."
  }
  assert {
    condition = (
      length(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries) == 2 &&
      strcontains(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries[1], "EventID=4662") &&
      strcontains(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries[1], "'0x100'") &&
      !strcontains(azurerm_monitor_data_collection_rule.dc_security[0].data_sources[0].windows_event_log[0].x_path_queries[0], "4662")
    )
    error_message = "4662 must be collected ONLY filtered to control access (0x100) - DCSync - never unfiltered."
  }
}

run "dc_security_events_need_vm_id" {
  command = plan
  variables {
    enable_itdr_detections     = true
    collect_dc_security_events = true
  }
  expect_failures = [azurerm_virtual_machine_extension.dc_ama]
}

run "la_path_with_itdr" {
  command = plan
  variables {
    enable_la_alerts       = true
    enable_itdr_detections = true
    alert_email            = "secops@example.com"
  }

  assert {
    condition     = length(azurerm_monitor_scheduled_query_rules_alert_v2.this) == 16
    error_message = "The post-trial LA path must carry the ITDR rules too."
  }
  assert {
    condition = (
      azurerm_monitor_scheduled_query_rules_alert_v2.this["tier0_logon_without_checkout"].mute_actions_after_alert_duration == "PT1H" &&
      azurerm_monitor_scheduled_query_rules_alert_v2.this["legacy_auth"].mute_actions_after_alert_duration == "P1D"
    )
    error_message = "la_mute overrides the mute only where set; others mute for their period."
  }
}

# --- immutable-id rendering (IaC identity, privileged groups / users) --------
run "id_lists_default_fail_closed" {
  command = plan
  variables {
    enable_sentinel        = true
    enable_itdr_detections = true
  }

  assert {
    condition = alltrue([
      for k in ["ca_policy_changed", "role_assigned_outside_pim", "pim_group_member_added_outside_pim", "app_consent_granted", "app_credential_added"] :
      strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, "let IacPrincipalIds = dynamic([]); // @@IAC_PRINCIPAL_IDS@@")
    ])
    error_message = "With no ids configured every IaC-aware rule keeps the EMPTY list: nothing counts as IaC (fail closed)."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_sentinel_alert_rule_scheduled.this :
      !strcontains(r.query, "ActorApp in (") && !strcontains(r.query, "IacActors")
    ])
    error_message = "No rule may decide 'IaC' by display name (ActorApp in (...)) - display names are not unique or protected."
  }
}

run "id_lists_rendered" {
  command = plan
  variables {
    enable_sentinel        = true
    enable_itdr_detections = true
    iac_principal_ids      = ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"]
    privileged_group_ids   = ["33333333-3333-3333-3333-333333333333"]
    break_glass_group_ids  = ["44444444-4444-4444-4444-444444444444"]
    privileged_user_ids    = ["55555555-5555-5555-5555-555555555555"]
    azure_pim_group_ids    = ["66666666-6666-6666-6666-666666666666"]
  }

  assert {
    condition = alltrue([
      for k in ["ca_policy_changed", "role_assigned_outside_pim", "pim_group_member_added_outside_pim", "app_consent_granted", "app_credential_added"] :
      strcontains(azurerm_sentinel_alert_rule_scheduled.this[k].query, "dynamic([\"11111111-1111-1111-1111-111111111111\",\"22222222-2222-2222-2222-222222222222\"]); // @@IAC_PRINCIPAL_IDS@@")
    ])
    error_message = "iac_principal_ids must be rendered into every IaC-aware rule."
  }
  assert {
    condition = (
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["pim_group_member_added_outside_pim"].query, "dynamic([\"33333333-3333-3333-3333-333333333333\"]); // @@PRIVILEGED_GROUP_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["pim_group_member_added_outside_pim"].query, "dynamic([\"44444444-4444-4444-4444-444444444444\"]); // @@BREAK_GLASS_GROUP_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["auth_method_changed_by_admin"].query, "dynamic([\"55555555-5555-5555-5555-555555555555\"]); // @@PRIVILEGED_USER_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["pim_group_member_added_outside_pim"].query, "dynamic([\"66666666-6666-6666-6666-666666666666\"]); // @@AZURE_PIM_GROUP_IDS@@")
    )
    error_message = "Privileged group / break-glass / user / Azure PIM group ids must be rendered into their rules."
  }
  assert {
    condition = alltrue([
      for k, r in azurerm_sentinel_alert_rule_scheduled.this : !strcontains(r.query, "dynamic([]); // @@")
    ])
    error_message = "With every list set, no rule may keep an unrendered empty placeholder."
  }
}

run "iac_ids_reject_display_names" {
  command = plan
  variables {
    iac_principal_ids = ["gh-oidc-entra-apply (write)"]
  }
  expect_failures = [var.iac_principal_ids]
}

run "containment_on_alert_added_is_opt_in" {
  command = apply
  variables {
    enable_sentinel            = true
    enable_itdr_detections     = true
    enable_itdr_containment    = true
    containment_on_alert_added = true
    containment_playbook_id    = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
  }

  assert {
    condition = (
      length(azurerm_sentinel_automation_rule.contain_on_alert_added) == 1 &&
      azurerm_sentinel_automation_rule.contain_on_alert_added[0].triggers_when == "Updated" &&
      jsondecode(azurerm_sentinel_automation_rule.contain_on_alert_added[0].condition_json)[0].conditionType == "PropertyArrayChanged" &&
      jsondecode(azurerm_sentinel_automation_rule.contain_on_alert_added[0].condition_json)[0].conditionProperties.changeType == "Added" &&
      jsonencode(jsondecode(azurerm_sentinel_automation_rule.contain_on_alert_added[0].condition_json)[2].conditionProperties.propertyValues) == jsonencode(["High"])
    )
    error_message = "containment_on_alert_added: a second, Updated-trigger rule for 'High ITDR alert added'."
  }
}

# Defender for Identity (mdi.tf, ADR 0023): the flag only adds the Microsoft
# Defender XDR connector, and only with enable_sentinel. The sensor, workspace
# and licence are human steps the runbook carries, not Terraform.
run "defender_for_identity_connector_needs_both_flags" {
  command = plan
  variables {
    enable_defender_for_identity = true
    # enable_sentinel stays false
  }

  # Variable validation refuses the flag without enable_sentinel.
  expect_failures = [var.enable_defender_for_identity]
}

run "defender_for_identity_connector_created" {
  command = apply
  variables {
    enable_sentinel              = true
    enable_defender_for_identity = true
  }

  assert {
    condition = (
      length(azurerm_sentinel_data_connector_microsoft_threat_protection.mdi) == 1 &&
      azurerm_sentinel_data_connector_microsoft_threat_protection.mdi[0].log_analytics_workspace_id == azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
    )
    error_message = "enable_defender_for_identity + enable_sentinel must create exactly one Defender XDR connector on the onboarded workspace."
  }
  assert {
    condition     = output.defender_for_identity_connector_id != null
    error_message = "defender_for_identity_connector_id output must be set once the connector exists."
  }
}

run "defender_for_identity_off_with_sentinel_on" {
  command = plan
  variables {
    enable_sentinel = true
    # enable_defender_for_identity stays false
  }

  assert {
    condition     = length(azurerm_sentinel_data_connector_microsoft_threat_protection.mdi) == 0 && output.defender_for_identity_connector_id == null
    error_message = "Sentinel on but the MDI flag off must create no Defender XDR connector."
  }
}
