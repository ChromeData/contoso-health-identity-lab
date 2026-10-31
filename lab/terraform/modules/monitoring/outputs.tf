# =============================================================================
# modules/monitoring :: outputs.tf
# =============================================================================

output "sentinel_rule_ids" {
  description = "Map of rule key => Sentinel analytics rule id (empty until enable_sentinel)."
  value       = { for k, r in azurerm_sentinel_alert_rule_scheduled.this : k => r.id }
}

output "la_alert_rule_ids" {
  description = "Map of rule key => Log Analytics scheduled query alert id (empty until enable_la_alerts)."
  value       = { for k, r in azurerm_monitor_scheduled_query_rules_alert_v2.this : k => r.id }
}

output "itdr_rule_keys" {
  description = "ITDR rule keys (v1 + v2) selected for the active detection path (empty until enable_itdr_detections). The LA path skips sentinel_only_rule_keys."
  value       = keys(local.itdr_selected)
}

output "sentinel_only_rule_keys" {
  description = "Selected rules with no Log Analytics alert equivalent (14-day look-back): deployed only while enable_sentinel is on."
  value       = [for k in keys(local.rules) : k if contains(local.sentinel_only_rule_keys, k)]
}

output "operator_ips_watchlist_id" {
  description = "Sentinel watchlist operator_ips (alias read by dc-logon-outside-operator-allowlist.kql); null unless enable_sentinel + enable_itdr_detections_v2. Its rows are sensitive and not output."
  value       = one(azurerm_sentinel_watchlist.operator_ips[*].id)
}

output "containment_automation_rule_id" {
  description = "Sentinel automation rule that runs the containment playbook (null until enable_itdr_containment + containment_playbook_id)."
  value       = one(azurerm_sentinel_automation_rule.contain[*].id)
}

output "containment_alert_added_rule_id" {
  description = "Second containment trigger on 'High alert added to an incident' (null unless containment_on_alert_added)."
  value       = one(azurerm_sentinel_automation_rule.contain_on_alert_added[*].id)
}

# Everything ingest-vault-audit.sh needs to post check-out rows. Not secret:
# the endpoint and DCR id are useless without an Entra token whose identity
# holds Monitoring Metrics Publisher on the DCR.
output "vault_ingestion" {
  description = "Logs Ingestion API target for lab/scripts/monitoring/ingest-vault-audit.sh (null until enable_itdr_detections)."
  value = var.enable_itdr_detections ? {
    endpoint         = azurerm_monitor_data_collection_endpoint.itdr[0].logs_ingestion_endpoint
    dcr_immutable_id = azurerm_monitor_data_collection_rule.vault_checkout[0].immutable_id
    dcr_id           = azurerm_monitor_data_collection_rule.vault_checkout[0].id
    stream           = local.vault_stream
    table            = local.vault_table
  } : null
}

output "dc_security_dcr_id" {
  description = "DCR collecting DC01 Security events (null unless collect_dc_security_events)."
  value       = one(azurerm_monitor_data_collection_rule.dc_security[*].id)
}

output "defender_for_identity_connector_id" {
  description = "Microsoft Defender XDR data connector that carries MDI alerts into SecurityAlert (ADR 0023; null unless enable_sentinel + enable_defender_for_identity). The sensor, MDI workspace and licence are human steps - see the runbook."
  value       = one(azurerm_sentinel_data_connector_microsoft_threat_protection.mdi[*].id)
}
