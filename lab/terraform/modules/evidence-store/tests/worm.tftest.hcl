# The evidence store must be WORM, Entra-auth-only and private by default.
# These runs pin the properties an auditor would ask about: immutability
# retention and state, versioning, shared key off, no anonymous access, the
# irreversible-lock guard, the firewall format, the always-on access logs and
# the writers' no-delete ABAC condition.
# Run offline with HashiCorp Terraform (not tofu - see lab/terraform/README.md):
#   terraform init -backend=false && terraform test

mock_provider "azurerm" {
  mock_resource "azurerm_storage_account" {
    defaults = {
      id                    = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence"
      primary_blob_endpoint = "https://stidlabevidence.blob.core.windows.net/"
    }
  }
  mock_resource "azurerm_storage_container" {
    defaults = {
      id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence/blobServices/default/containers/evidence"
    }
  }
}

variables {
  resource_group_name        = "rg-identity-lab"
  log_analytics_workspace_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
}

run "defaults_are_worm_and_entra_only" {
  command = plan

  # ---- WORM -----------------------------------------------------------------
  assert {
    condition     = azurerm_storage_account.evidence.immutability_policy[0].period_since_creation_in_days == 2190
    error_message = "default retention must be 2190 days (6 years, HIPAA documentation retention)"
  }
  assert {
    condition     = azurerm_storage_account.evidence.immutability_policy[0].state == "Unlocked"
    error_message = "the policy must start Unlocked (Azure creates it only Unlocked or Disabled; locking is a deliberate second apply)"
  }
  assert {
    condition     = azurerm_storage_account.evidence.immutability_policy[0].allow_protected_append_writes == false
    error_message = "retained evidence must not accept appends"
  }
  assert {
    condition     = azurerm_storage_account.evidence.blob_properties[0].versioning_enabled == true
    error_message = "version-level WORM requires versioning; an overwrite must become a new retained version"
  }
  assert {
    condition     = azurerm_storage_account.evidence.blob_properties[0].last_access_time_enabled == false
    error_message = "last access time tracking is incompatible with immutable storage"
  }
  assert {
    condition     = length(azurerm_storage_account.evidence.blob_properties[0].restore_policy) == 0
    error_message = "point-in-time restore is incompatible with immutable storage"
  }
  assert {
    condition     = azurerm_storage_account.evidence.is_hns_enabled == false && azurerm_storage_account.evidence.sftp_enabled == false && azurerm_storage_account.evidence.nfsv3_enabled == false
    error_message = "HNS, SFTP and NFS 3.0 are incompatible with version-level WORM"
  }

  # ---- Entra auth only ------------------------------------------------------
  assert {
    condition     = azurerm_storage_account.evidence.shared_access_key_enabled == false
    error_message = "shared key must be disabled: every data-plane call is an Entra identity"
  }
  assert {
    condition     = azurerm_storage_account.evidence.default_to_oauth_authentication == true
    error_message = "the portal must default to Entra auth"
  }
  assert {
    condition     = azurerm_storage_account.evidence.local_user_enabled == false
    error_message = "local (SFTP) users are a second credential store and must stay off"
  }

  # ---- Private by default ---------------------------------------------------
  assert {
    condition     = azurerm_storage_account.evidence.allow_nested_items_to_be_public == false
    error_message = "anonymous blob/container access must be impossible"
  }
  assert {
    condition     = azurerm_storage_account.evidence.public_network_access_enabled == false
    error_message = "with no allowed IPs the public endpoint must be off"
  }
  assert {
    condition     = azurerm_storage_account.evidence.network_rules[0].default_action == "Deny"
    error_message = "the storage firewall must deny by default"
  }
  assert {
    condition     = azurerm_storage_container.evidence.container_access_type == "private"
    error_message = "the evidence container must be private"
  }
  assert {
    condition     = azurerm_storage_account.evidence.min_tls_version == "TLS1_2" && azurerm_storage_account.evidence.https_traffic_only_enabled == true
    error_message = "TLS 1.2 + HTTPS only"
  }

  # ---- Access logs + least privilege ----------------------------------------
  assert {
    condition     = azurerm_monitor_diagnostic_setting.blob.name == "diag-stidlabevidence-blob"
    error_message = "blob access logs must always be planned"
  }
  assert {
    condition     = length(azurerm_role_assignment.writer) == 0 && length(azurerm_role_assignment.reader) == 0
    error_message = "no data-plane role is granted by default (the pipeline may not delegate storage data roles)"
  }
  assert {
    condition     = length(azurerm_private_endpoint.blob) == 0
    error_message = "the private endpoint is opt-in"
  }
}

run "custom_retention_days_flow_through" {
  command = plan

  variables {
    immutability_period_days = 365
  }

  assert {
    condition     = azurerm_storage_account.evidence.immutability_policy[0].period_since_creation_in_days == 365
    error_message = "immutability_period_days must reach the account policy"
  }
  assert {
    condition     = azurerm_storage_account.evidence.blob_properties[0].change_feed_retention_in_days == 365
    error_message = "the change feed must be kept as long as the evidence"
  }
}

run "retention_zero_days_is_rejected" {
  command = plan

  variables {
    immutability_period_days = 0
  }

  expect_failures = [var.immutability_period_days]
}

run "retention_beyond_azure_max_is_rejected" {
  command = plan

  variables {
    immutability_period_days = 146001
  }

  expect_failures = [var.immutability_period_days]
}

run "lock_without_acknowledgement_is_rejected" {
  command = plan

  variables {
    immutability_state = "Locked"
  }

  expect_failures = [azurerm_storage_account.evidence]
}

run "lock_with_acknowledgement_plans" {
  command = plan

  variables {
    immutability_state             = "Locked"
    immutability_lock_acknowledged = true
  }

  assert {
    condition     = azurerm_storage_account.evidence.immutability_policy[0].state == "Locked"
    error_message = "an acknowledged lock must reach the account policy"
  }
}

run "unknown_state_is_rejected" {
  command = plan

  variables {
    immutability_state = "Enabled"
  }

  expect_failures = [var.immutability_state]
}

run "operator_ip_opens_firewall_in_storage_format" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.7/32", "198.51.100.0/24"]
  }

  assert {
    condition     = azurerm_storage_account.evidence.public_network_access_enabled == true
    error_message = "an allow-listed operator IP opens the public endpoint to that IP only"
  }
  assert {
    condition     = contains(azurerm_storage_account.evidence.network_rules[0].ip_rules, "203.0.113.7") && contains(azurerm_storage_account.evidence.network_rules[0].ip_rules, "198.51.100.0/24")
    error_message = "a /32 must become the bare address (Azure Storage rejects /32); other CIDRs pass through"
  }
  assert {
    condition     = !contains(azurerm_storage_account.evidence.network_rules[0].ip_rules, "203.0.113.7/32")
    error_message = "the /32 form must not reach the storage firewall"
  }
}

run "wide_ip_range_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "slash_31_is_rejected" {
  command = plan

  variables {
    allowed_ip_ranges = ["203.0.113.6/31"]
  }

  expect_failures = [var.allowed_ip_ranges]
}

run "empty_workspace_id_is_rejected" {
  command = plan

  variables {
    log_analytics_workspace_id = ""
  }

  expect_failures = [azurerm_monitor_diagnostic_setting.blob]
}

run "private_endpoint_without_subnet_is_rejected" {
  command = plan

  variables {
    enable_private_endpoint = true
  }

  expect_failures = [azurerm_private_endpoint.blob]
}

# apply (mocked): the container id is computed, so the scope and the diag
# target are only known after the mock provider fills them in.
run "writers_are_container_scoped_and_cannot_delete" {
  command = apply

  variables {
    writer_principal_ids = ["55555555-5555-5555-5555-555555555555"]
    reader_principal_ids = ["66666666-6666-6666-6666-666666666666"]
  }

  assert {
    condition     = azurerm_role_assignment.writer["55555555-5555-5555-5555-555555555555"].role_definition_name == "Storage Blob Data Contributor"
    error_message = "writers get Storage Blob Data Contributor"
  }
  assert {
    condition     = azurerm_role_assignment.writer["55555555-5555-5555-5555-555555555555"].scope == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence/blobServices/default/containers/evidence"
    error_message = "writer access must be scoped to the evidence container, not the account"
  }
  assert {
    condition     = azurerm_role_assignment.writer["55555555-5555-5555-5555-555555555555"].condition_version == "2.0"
    error_message = "the writer assignment must carry an ABAC condition"
  }
  assert {
    condition     = strcontains(azurerm_role_assignment.writer["55555555-5555-5555-5555-555555555555"].condition, "!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete'})")
    error_message = "the condition must deny blob delete"
  }
  assert {
    condition     = strcontains(azurerm_role_assignment.writer["55555555-5555-5555-5555-555555555555"].condition, "StringNotEquals 'evidence'")
    error_message = "delete may be allowed only outside the evidence container"
  }
  assert {
    condition     = azurerm_role_assignment.reader["66666666-6666-6666-6666-666666666666"].role_definition_name == "Storage Blob Data Reader"
    error_message = "auditors get read-only access"
  }
  assert {
    condition     = azurerm_monitor_diagnostic_setting.blob.target_resource_id == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence/blobServices/default"
    error_message = "access logs must come from the blob service, where reads/writes/deletes are logged"
  }
  assert {
    condition     = output.writer_abac_condition == azurerm_role_assignment.writer["55555555-5555-5555-5555-555555555555"].condition
    error_message = "the output used for the human role assignment must equal the condition Terraform applies"
  }
}
