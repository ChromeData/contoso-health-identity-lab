# Offline guard for the notify automation (main.tf): every incident from the
# lab's rules runs the notify playbook on creation, and a break-glass sign-in
# that JOINS an open incident runs it again (incident Updated + Alerts added),
# because incident grouping would otherwise swallow the second sign-in
# (found 2026-11-05, incidents #42 / #48). No tenant, no state:
#   terraform init -backend=false && terraform test -filter=tests/notify.tftest.hcl

mock_provider "azurerm" {}

variables {
  resource_group_name        = "rg-identity-lab"
  log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
  enable_sentinel            = true
  playbook_logic_app_id      = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-notify"
}

run "break_glass_notifies_again_when_an_alert_joins" {
  command = apply

  assert {
    condition     = length(azurerm_sentinel_automation_rule.notify) == 1 && azurerm_sentinel_automation_rule.notify[0].triggers_when == "Created"
    error_message = "The creation-time notify rule must stay."
  }
  assert {
    condition     = length(azurerm_sentinel_automation_rule.notify_on_alert_added) == 1
    error_message = "Break-glass needs the alert-added notify rule by default."
  }
  assert {
    condition = (
      azurerm_sentinel_automation_rule.notify_on_alert_added[0].triggers_on == "Incidents" &&
      azurerm_sentinel_automation_rule.notify_on_alert_added[0].triggers_when == "Updated" &&
      jsondecode(azurerm_sentinel_automation_rule.notify_on_alert_added[0].condition_json)[0].conditionType == "PropertyArrayChanged" &&
      jsondecode(azurerm_sentinel_automation_rule.notify_on_alert_added[0].condition_json)[0].conditionProperties.arrayType == "Alerts" &&
      jsondecode(azurerm_sentinel_automation_rule.notify_on_alert_added[0].condition_json)[0].conditionProperties.changeType == "Added"
    )
    error_message = "The second notify rule must fire on 'incident updated: alerts added'."
  }
  assert {
    condition = (
      jsonencode(jsondecode(azurerm_sentinel_automation_rule.notify_on_alert_added[0].condition_json)[1].conditionProperties.propertyValues) ==
      jsonencode([azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].id])
    )
    error_message = "Only the break-glass rule's incidents notify again (a re-alerting rule would post a card every five minutes)."
  }
  assert {
    condition     = azurerm_sentinel_automation_rule.notify_on_alert_added[0].action_playbook[0].logic_app_id == var.playbook_logic_app_id
    error_message = "It runs the same notify playbook."
  }
}

# The gap the NRT move closed (2026-11-05): a scheduled rule judges a fixed
# window, so a late row, or a late or skipped run, can miss a break-glass
# sign-in. These asserts fail if the rule ever goes back to being scheduled,
# or if the query grows a time window again.
run "break_glass_is_near_real_time_with_no_time_window" {
  command = apply

  assert {
    condition     = length(azurerm_sentinel_alert_rule_nrt.this) == 1 && contains(keys(azurerm_sentinel_alert_rule_nrt.this), "break_glass_signin")
    error_message = "The break-glass rule must be a near-real-time (NRT) rule."
  }
  assert {
    condition     = !contains(keys(azurerm_sentinel_alert_rule_scheduled.this), "break_glass_signin")
    error_message = "No scheduled twin of the break-glass rule: it would re-open the late-row gap and double the alerts."
  }
  assert {
    # Comment lines removed first: the header explains the old windows.
    condition = (
      !strcontains(replace(azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].query, "/(?m)^\\s*//.*$/", ""), "ago(") &&
      !strcontains(replace(azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].query, "/(?m)^\\s*//.*$/", ""), "ingestion_time(") &&
      !strcontains(replace(azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].query, "/(?m)^\\s*//.*$/", ""), "TimeGenerated >")
    )
    error_message = "break-glass-signin.kql must carry no time window: NRT already judges each row once by ingestion time, and a window would drop a late row."
  }
  assert {
    condition     = azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].severity == "High" && azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].incident[0].create_incident_enabled
    error_message = "High, and it creates incidents."
  }
  assert {
    condition = (
      contains(jsondecode(azurerm_sentinel_automation_rule.notify[0].condition_json)[0].conditionProperties.propertyValues, azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].id) &&
      jsonencode(jsondecode(azurerm_sentinel_automation_rule.notify_on_alert_added[0].condition_json)[1].conditionProperties.propertyValues) == jsonencode([azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].id])
    )
    error_message = "Both notify automation rules must name the NRT rule's id."
  }
}

run "no_notify_playbook_no_rules" {
  command = plan
  variables {
    playbook_logic_app_id = ""
  }
  assert {
    condition     = length(azurerm_sentinel_automation_rule.notify) == 0 && length(azurerm_sentinel_automation_rule.notify_on_alert_added) == 0
    error_message = "No notify playbook id = no notify automation at all."
  }
}

run "empty_key_list_turns_it_off" {
  command = plan
  variables {
    notify_on_alert_added_rule_keys = []
  }
  assert {
    condition     = length(azurerm_sentinel_automation_rule.notify) == 1 && length(azurerm_sentinel_automation_rule.notify_on_alert_added) == 0
    error_message = "An empty key list keeps only the creation-time notify rule."
  }
}

run "itdr_keys_refused" {
  command = plan
  variables {
    notify_on_alert_added_rule_keys = ["role_assigned_outside_pim"]
  }
  expect_failures = [var.notify_on_alert_added_rule_keys]
}
