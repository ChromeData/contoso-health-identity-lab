# Offline regression guard for the fourth ITDR set (itdr_v4.tf, review
# findings B1, B2, C5, D1, 2026-11-07) and the core-rule tuning that came
# with it (pim_activation severity, failed_signin_spike). No tenant:
#   terraform init -backend=false && terraform test -filter=tests/itdr_v4.tftest.hcl
#
# What it proves:
#   * the v4 flag adds nothing by default, refuses to run without the v1
#     flag, and refuses an empty operator id list;
#   * the five rules' ids are rendered, every entity / custom-detail column
#     is in the .kql text, the operator sign-in rule stays off the Log
#     Analytics path (watchlist), and none of them triggers containment;
#   * pim_activation renders the Tier-0 group ids and working hours;
#     failed_signin_spike renders the trusted egress ranges.

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
  enable_sentinel            = true
  enable_itdr_detections     = true
}

run "v4_off_by_default" {
  command = plan

  assert {
    condition     = alltrue([for k in ["operator_signin_outside_allowlist", "operator_permissions_changed", "break_glass_auth_method_added", "hr_leaver_lag", "failed_signin_spray_by_asn"] : !contains(keys(azurerm_sentinel_alert_rule_scheduled.this), k)])
    error_message = "The fourth set must add nothing until enable_itdr_detections_v4 is on."
  }
}

run "v4_needs_v1" {
  command = plan
  variables {
    enable_itdr_detections    = false
    enable_itdr_detections_v4 = true
    operator_principal_ids    = ["88888888-8888-8888-8888-888888888888"]
  }
  expect_failures = [var.enable_itdr_detections_v4]
}

run "v4_refuses_empty_operator_ids" {
  command = plan
  variables {
    enable_itdr_detections_v4 = true
  }
  expect_failures = [var.enable_itdr_detections_v4]
}

run "v4_on" {
  command = plan
  variables {
    enable_itdr_detections_v4 = true
    enable_itdr_detections_v2 = true
    operator_principal_ids    = ["88888888-8888-8888-8888-888888888888"]
    break_glass_user_ids      = ["99999999-9999-9999-9999-999999999999"]
    tier0_group_ids           = ["77777777-7777-7777-7777-777777777777"]
    trusted_egress_ranges     = ["198.51.100.0/24"]
    trusted_asns              = ["64500"]
    containment_playbook_id   = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
    enable_itdr_containment   = true
  }

  assert {
    condition     = alltrue([for k in ["operator_signin_outside_allowlist", "operator_permissions_changed", "break_glass_auth_method_added", "hr_leaver_lag", "failed_signin_spray_by_asn"] : contains(keys(azurerm_sentinel_alert_rule_scheduled.this), k)])
    error_message = "All five v4 rules must deploy when the flag is on."
  }
  assert {
    condition = (
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["operator_signin_outside_allowlist"].query, "dynamic([\"88888888-8888-8888-8888-888888888888\"]); // @@OPERATOR_PRINCIPAL_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["operator_permissions_changed"].query, "dynamic([\"88888888-8888-8888-8888-888888888888\"]); // @@OPERATOR_PRINCIPAL_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["break_glass_auth_method_added"].query, "dynamic([\"99999999-9999-9999-9999-999999999999\"]); // @@BREAK_GLASS_USER_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["failed_signin_spray_by_asn"].query, "dynamic([\"64500\"]); // @@TRUSTED_ASNS@@")
    )
    error_message = "The v4 rules must judge by the rendered immutable ids."
  }
  assert {
    condition = (
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["pim_activation"].query, "dynamic([\"77777777-7777-7777-7777-777777777777\"]); // @@TIER0_GROUP_IDS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["pim_activation"].query, "dynamic([7,8,9,10,11,12,13,14,15,16,17,18]); // @@PIM_WORK_HOURS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["pim_activation"].query, "dynamic([1,2,3,4,5]); // @@PIM_WORK_DAYS@@") &&
      strcontains(azurerm_sentinel_alert_rule_scheduled.this["failed_signin_spike"].query, "dynamic([\"198.51.100.0/24\"]); // @@TRUSTED_EGRESS_RANGES@@")
    )
    error_message = "pim_activation must render the Tier-0 ids and working hours; failed_signin_spike the trusted egress ranges."
  }
  assert {
    condition = alltrue([
      for k in ["operator_signin_outside_allowlist", "operator_permissions_changed", "break_glass_auth_method_added", "hr_leaver_lag", "failed_signin_spray_by_asn"] : alltrue(concat(
        [for e in local.itdr_v4_rules[k].entities : alltrue([for f in e.fields : strcontains(file("${path.module}/../../../kql/${local.itdr_v4_rules[k].file}"), f.column)])],
        [for c in values(local.itdr_v4_rules[k].custom_details) : strcontains(file("${path.module}/../../../kql/${local.itdr_v4_rules[k].file}"), c)]
      ))
    ])
    error_message = "Every v4 entity / custom-detail column must be in its .kql text."
  }
  assert {
    condition     = alltrue([for k in ["operator_signin_outside_allowlist", "operator_permissions_changed", "break_glass_auth_method_added", "hr_leaver_lag", "failed_signin_spray_by_asn"] : contains(local.itdr_never_contain, k)])
    error_message = "No v4 rule may trigger containment."
  }
}

run "v4_operator_signin_is_sentinel_only" {
  command = plan
  variables {
    enable_sentinel           = false
    enable_la_alerts          = true
    alert_email               = "secops@example.com"
    enable_itdr_detections_v4 = true
    operator_principal_ids    = ["88888888-8888-8888-8888-888888888888"]
  }

  assert {
    condition     = !contains(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this), "operator_signin_outside_allowlist") && contains(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this), "hr_leaver_lag")
    error_message = "The operator sign-in rule reads a Sentinel watchlist: Sentinel path only. The others run on both paths."
  }
}

run "egress_ranges_ipv4_cidr_only" {
  command = plan
  variables {
    trusted_egress_ranges = ["2001:db8::/32"]
  }
  expect_failures = [var.trusted_egress_ranges]
}

# Review of #233: the operator sign-in rule reads the operator_ips watchlist,
# so the watchlist must exist with the v4 set even when v2 is off.
run "v4_alone_creates_the_watchlist" {
  command = plan
  variables {
    enable_itdr_detections_v4 = true
    operator_principal_ids    = ["88888888-8888-8888-8888-888888888888"]
    operator_ip_ranges        = ["198.51.100.7/32"]
    operator_ips_expires_on   = "2099-12-31"
  }

  assert {
    condition     = length(azurerm_sentinel_watchlist.operator_ips) == 1 && length(azurerm_sentinel_watchlist_item.operator_ips) == 1
    error_message = "With v4 on and v2 off, the operator_ips watchlist and its entries must still be created."
  }
}
