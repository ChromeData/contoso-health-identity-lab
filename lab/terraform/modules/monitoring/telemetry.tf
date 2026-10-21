# =============================================================================
# modules/monitoring :: telemetry.tf
# -----------------------------------------------------------------------------
# Data the ITDR rules need that Entra diagnostics do not provide. Created by
# enable_itdr_detections alone (no Sentinel needed), so VaultCheckout_CL fills
# BEFORE Sentinel validates the rules against it (see main.tf ORDERING
# GOTCHA). verify: the DC01 Security events in B are the exception - per
# Microsoft Learn ("Collect Windows events with Azure Monitor Agent"), AMA
# Security-log events reach SecurityEvent only when Microsoft Sentinel and its
# "Windows Security Events via AMA" connector are enabled; otherwise they land
# in the Event table. So the SecurityEvent rules wait for Sentinel.
#
#  A. PAM check-out evidence -> VaultCheckout_CL
#       Vault file audit device (lab/pam) -> lab/scripts/monitoring/
#       ingest-vault-audit.sh -> Logs Ingestion API -> DCE -> DCR -> table.
#       The legacy HTTP Data Collector API is NOT used: Microsoft retired it
#       in September 2026 (verify: retirement date on Microsoft Learn).
#       The sender authenticates with an Entra token (az login), never a
#       shared key; it needs "Monitoring Metrics Publisher" on the DCR. That
#       role is NOT on the CI apply identity's delegable list (envs/bootstrap
#       ABAC condition), so the grant is a human step - the script prints the
#       exact command.
#       Production equivalent: CyberArk Vault / PTA syslog -> AMA (CEF) ->
#       Sentinel.
#
#  B. DC01 Security events -> SecurityEvent (verify: needs Sentinel + the
#     "Windows Security Events via AMA" connector, per Microsoft Learn; before
#     that, expect the rows in Event, and keep the SecurityEvent rules in
#     itdr_exclude_rules)
#       Azure Monitor Agent extension on vm-dc01 + a Windows DCR collecting
#       only the identity-relevant event ids (logon, special privileges,
#       account / privileged-group changes, Kerberos service tickets) plus
#       4662 filtered to control-access (0x100) for DCSync, associated with
#       the VM.
#       Gated by collect_dc_security_events (a plan-time boolean): the VM id
#       is unknown on the first plan, so it can never drive a count.
# =============================================================================

locals {
  vault_table  = "VaultCheckout_CL"
  vault_stream = "Custom-VaultCheckout"

  # One schema, two spellings: the table API calls the datetime type
  # "dateTime", the DCR stream declaration "datetime". The table and the
  # stream always get the same list (tests/itdr.tftest.hcl checks it).
  vault_columns = concat(local.vault_columns_base, var.vault_feed_v2_columns ? local.vault_columns_v2 : [])

  vault_columns_base = [
    { name = "TimeGenerated", table_type = "dateTime", stream_type = "datetime", description = "Vault audit event time (UTC). Heartbeat rows: the ingest run time." },
    { name = "Operation", table_type = "string", stream_type = "string", description = "check-out | check-in | heartbeat; with the extended feed also cred-read | rotation-failed | root-token | auth-failed | access-denied" },
    { name = "Account", table_type = "string", stream_type = "string", description = "sAMAccountName checked out / in (HMAC resolved by the ingest script); empty on heartbeat" },
    { name = "AccountResolved", table_type = "boolean", stream_type = "boolean", description = "false = the audit HMAC could not be mapped to a library account" },
    { name = "Library", table_type = "string", stream_type = "string", description = "Vault LDAP library set, e.g. tier0-admins" },
    { name = "VaultPath", table_type = "string", stream_type = "string", description = "Request path, e.g. ldap/library/tier0-admins/check-out" },
    { name = "RequestId", table_type = "string", stream_type = "string", description = "Vault request id (joins back to the raw audit log)" },
    { name = "RemoteAddress", table_type = "string", stream_type = "string", description = "Client address Vault saw" },
    { name = "VaultActor", table_type = "string", stream_type = "string", description = "Token display name (auth.display_name), e.g. token-psm-broker" },
    { name = "TokenPolicies", table_type = "string", stream_type = "string", description = "Comma-joined policies of the calling token" },
    { name = "SourceHost", table_type = "string", stream_type = "string", description = "Host running the Vault stand-in (the ingest script's hostname)" },
  ]

  # vault_feed_v2_columns: what vault-privileged-access-anomaly.kql reads
  # (through column_ifexists, so the query is valid without them). Added
  # only together with the ingest script that fills them - see the variable.
  vault_columns_v2 = [
    { name = "Ticket", table_type = "string", stream_type = "string", description = "Change ticket from the calling token's metadata (psm-session.sh sets it; CHG + 7 digits); empty when absent" },
    { name = "Operator", table_type = "string", stream_type = "string", description = "Operator from the calling token's metadata (who the check-out or read is for)" },
    { name = "ErrorText", table_type = "string", stream_type = "string", description = "Vault error of a failed request (rotation, login, permission denied); empty on success" },
  ]

  dc_events_on = var.enable_itdr_detections && var.collect_dc_security_events

  # Event ids collected from DC01 (Security log). 4624/4672 feed
  # tier0-logon-without-checkout.kql; the rest are the standard AD ITDR set,
  # collected now so hunting has them (cheap on a lab DC).
  #   4624 logon / 4625 failed logon / 4648 explicit credentials /
  #   4672 special privileges at logon / 4720 user created / 4722 enabled /
  #   4724 password reset / 4725 disabled / 4728 4732 4756 member added to a
  #   security-enabled global / local / universal group / 4738 user changed /
  #   4740 locked out / 4767 unlocked / 4768 4769 Kerberos TGT / service
  #   ticket (pass-the-ticket and Kerberoasting hunting).
  dc_event_ids = [4624, 4625, 4648, 4672, 4720, 4722, 4724, 4725, 4728, 4732, 4738, 4740, 4756, 4767, 4768, 4769]
  dc_xpath     = "Security!*[System[(${join(" or ", [for id in local.dc_event_ids : "EventID=${id}"])})]]"
  # 4662 (an operation on a directory object) is the noisiest event a DC
  # writes, so only CONTROL ACCESS (0x100) is collected: the access type the
  # replication extended rights use (dcsync-replication-request.kql).
  # verify: the domain object's SACL audits those rights (Defender for
  # Identity's documented setting) - without it no 4662 is written at all.
  dc_xpath_4662 = "Security!*[System[(EventID=4662)] and EventData[Data[@Name='AccessMask']='0x100']]"
}

# -----------------------------------------------------------------------------
# A. VaultCheckout_CL + Logs Ingestion API endpoint.
# -----------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace_table_custom_log" "vault_checkout" {
  count = var.enable_itdr_detections ? 1 : 0

  name         = local.vault_table
  workspace_id = var.log_analytics_workspace_id
  display_name = "PAM vault check-outs (lab Vault stand-in)"
  description  = "Tier-0 library check-out / check-in evidence from the lab Vault audit log, written by lab/scripts/monitoring/ingest-vault-audit.sh. Joined against DC01 SecurityEvent by tier0-logon-without-checkout.kql."
  # Analytics plan: Sentinel rules and joins need it (Basic tables can't be
  # joined in analytics rules). Retention follows the workspace; long-term
  # evidence goes to the WORM evidence store, not Log Analytics.
  plan = "Analytics"

  dynamic "column" {
    for_each = local.vault_columns
    content {
      name        = column.value.name
      type        = column.value.table_type
      description = column.value.description
    }
  }
}

resource "azurerm_monitor_data_collection_endpoint" "itdr" {
  count = var.enable_itdr_detections ? 1 : 0

  name                = "dce-idlab-itdr"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Logs Ingestion API endpoint for the PAM check-out feed (ingest-vault-audit.sh)."
  # The sender is the operator laptop running the Vault stand-in, not a VNet
  # resource, so the endpoint stays public. Every call still needs an Entra
  # token whose identity holds Monitoring Metrics Publisher on the DCR - no
  # shared key exists to leak. Production: AMA on the vault host over Private
  # Link (Azure Monitor Private Link Scope).
  public_network_access_enabled = true
  tags                          = var.tags
}

resource "azurerm_monitor_data_collection_rule" "vault_checkout" {
  count = var.enable_itdr_detections ? 1 : 0

  name                        = "dcr-idlab-vault-checkout"
  resource_group_name         = var.resource_group_name
  location                    = var.location
  description                 = "Vault check-out / check-in rows -> VaultCheckout_CL (Logs Ingestion API)."
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.itdr[0].id
  tags                        = var.tags

  stream_declaration {
    stream_name = local.vault_stream
    dynamic "column" {
      for_each = local.vault_columns
      content {
        name = column.value.name
        type = column.value.stream_type
      }
    }
  }

  destinations {
    log_analytics {
      name                  = "loga-idlab"
      workspace_resource_id = var.log_analytics_workspace_id
    }
  }

  # The script already sends the table's exact shape, so the transform is
  # the identity ("source"); a schema change goes in the table, the stream
  # and the script together.
  data_flow {
    streams       = [local.vault_stream]
    destinations  = ["loga-idlab"]
    output_stream = "Custom-${local.vault_table}"
    transform_kql = "source"
  }

  # The DCR is validated against the table's schema at creation.
  depends_on = [azurerm_log_analytics_workspace_table_custom_log.vault_checkout]
}

# -----------------------------------------------------------------------------
# B. DC01 Security events via the Azure Monitor Agent.
# -----------------------------------------------------------------------------
resource "azurerm_virtual_machine_extension" "dc_ama" {
  count = local.dc_events_on ? 1 : 0

  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = var.dc_vm_id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0" # verify: current AMA major version on the first apply
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = var.tags

  lifecycle {
    precondition {
      condition     = var.dc_vm_id != ""
      error_message = "collect_dc_security_events = true needs dc_vm_id (module.dc_vm[0].vm_id) - enable_dc must be on."
    }
  }
}

resource "azurerm_monitor_data_collection_rule" "dc_security" {
  count = local.dc_events_on ? 1 : 0

  name                = "dcr-idlab-dc01-security"
  resource_group_name = var.resource_group_name
  location            = var.location
  kind                = "Windows"
  description         = "DC01 identity-relevant Security events -> SecurityEvent (ITDR)."
  tags                = var.tags

  data_sources {
    windows_event_log {
      name           = "dc01-identity-events"
      streams        = ["Microsoft-SecurityEvent"]
      x_path_queries = [local.dc_xpath, local.dc_xpath_4662]
    }
  }

  destinations {
    log_analytics {
      name                  = "loga-idlab"
      workspace_resource_id = var.log_analytics_workspace_id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["loga-idlab"]
  }
}

resource "azurerm_monitor_data_collection_rule_association" "dc_security" {
  count = local.dc_events_on ? 1 : 0

  name                    = "dcra-dc01-security"
  target_resource_id      = var.dc_vm_id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.dc_security[0].id
  description             = "DC01 -> dcr-idlab-dc01-security"

  # The agent must exist before the association means anything.
  depends_on = [azurerm_virtual_machine_extension.dc_ama]
}
