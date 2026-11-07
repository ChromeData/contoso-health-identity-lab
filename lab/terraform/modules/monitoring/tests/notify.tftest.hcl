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

# Review finding D2 (2026-11-07): one break-glass sign-in raised up to 12
# alerts and three tickets (E49a, E49c). The NRT rule now groups by the
# ACCOUNT only over 24 h, so late rows and new IPs of the same account join
# one incident (the notify playbook then notes them on its one ticket).
run "break_glass_groups_per_account_for_a_day" {
  command = apply

  assert {
    condition = (
      azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].incident[0].grouping[0].entity_matching_method == "Selected" &&
      jsonencode(azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].incident[0].grouping[0].by_entities) == jsonencode(["Account"]) &&
      azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].incident[0].grouping[0].lookback_duration == "P1D" &&
      !azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].incident[0].grouping[0].reopen_closed_incidents
    )
    error_message = "Break-glass alerts must group by Account over 24 h (one incident, one ticket per account per day), never re-opening a closed incident."
  }
}

run "break_glass_grouping_lookback_is_bounded" {
  command = plan
  variables {
    break_glass_grouping_lookback = "P30D"
  }
  expect_failures = [var.break_glass_grouping_lookback]
}

# Review finding D3: the rule matches the accounts' immutable object ids,
# so a renamed account still alerts. The ids reach the deployed query.
run "break_glass_matches_object_ids" {
  command = apply
  variables {
    break_glass_user_ids = ["55555555-5555-5555-5555-555555555555"]
  }

  assert {
    condition     = strcontains(azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].query, "let BreakGlassUserIds = dynamic([\"55555555-5555-5555-5555-555555555555\"]); // @@BREAK_GLASS_USER_IDS@@")
    error_message = "The break-glass user object ids must be rendered into the deployed query."
  }
  assert {
    condition     = contains([for f in azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].entity_mapping[0].field_mapping : f.identifier], "AadUserId")
    error_message = "The Account entity must carry the object id (AadUserId), not just the name."
  }
}

run "break_glass_user_ids_must_be_guids" {
  command = plan
  variables {
    break_glass_user_ids = ["bg-admin-01@contosohealthlab.onmicrosoft.com"]
  }
  expect_failures = [var.break_glass_user_ids]
}

# Drill noise (review finding D2): incidents naming a drill account are
# labelled "drill" at creation; close-build-noise.sh closes them by label.
run "drill_incidents_are_labelled" {
  command = apply

  assert {
    condition = (
      length(azurerm_sentinel_automation_rule.label_drill) == 1 &&
      azurerm_sentinel_automation_rule.label_drill[0].triggers_when == "Created" &&
      jsondecode(azurerm_sentinel_automation_rule.label_drill[0].condition_json)[1].conditionProperties.propertyName == "AccountName" &&
      jsondecode(azurerm_sentinel_automation_rule.label_drill[0].condition_json)[1].conditionProperties.operator == "StartsWith" &&
      jsonencode(jsondecode(azurerm_sentinel_automation_rule.label_drill[0].condition_json)[1].conditionProperties.propertyValues) == jsonencode(["itdr-drill-"]) &&
      jsonencode(azurerm_sentinel_automation_rule.label_drill[0].action_incident[0].labels) == jsonencode(["drill"]) &&
      azurerm_sentinel_automation_rule.label_drill[0].action_incident[0].status == null
    )
    error_message = "Drill incidents get the label 'drill' at creation and are NOT closed by the rule (the drill's containment must still run)."
  }
}

run "drill_prefix_too_short_refused" {
  command = plan
  variables {
    drill_account_prefixes = ["a"]
  }
  expect_failures = [var.drill_account_prefixes]
}

# Review of #230: one alert must never name two break-glass accounts. The
# query returns one row per account and the NRT rule alerts per row.
run "break_glass_one_alert_per_account" {
  command = apply

  assert {
    condition     = azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].event_grouping[0].aggregation_method == "AlertPerResult"
    error_message = "The break-glass NRT rule must raise one alert per result row (one row per account)."
  }
  assert {
    condition     = strcontains(azurerm_sentinel_alert_rule_nrt.this["break_glass_signin"].query, "by UserPrincipalName, UserId")
    error_message = "break-glass-signin.kql must summarize to one row per account."
  }
}
