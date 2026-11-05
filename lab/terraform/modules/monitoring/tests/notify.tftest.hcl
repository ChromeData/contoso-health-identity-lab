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
      jsonencode([azurerm_sentinel_alert_rule_scheduled.this["break_glass_signin"].id])
    )
    error_message = "Only the break-glass rule's incidents notify again (a re-alerting rule would post a card every five minutes)."
  }
  assert {
    condition     = azurerm_sentinel_automation_rule.notify_on_alert_added[0].action_playbook[0].logic_app_id == var.playbook_logic_app_id
    error_message = "It runs the same notify playbook."
  }
  assert {
    condition     = strcontains(azurerm_sentinel_alert_rule_scheduled.this["break_glass_signin"].query, "| where ingestion_time() > ago(RuleLookBack)")
    error_message = "break-glass-signin.kql must alert once per sign-in (ingestion_time() window), or the alert-added rule would post a card every run."
  }
  assert {
    condition     = strcontains(azurerm_sentinel_alert_rule_scheduled.this["break_glass_signin"].query, "let RuleLookBack = 5m;") && azurerm_sentinel_alert_rule_scheduled.this["break_glass_signin"].query_frequency == "PT5M"
    error_message = "RuleLookBack must equal the rule's query frequency (5 minutes)."
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
