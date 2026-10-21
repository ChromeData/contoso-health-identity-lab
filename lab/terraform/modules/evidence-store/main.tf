# =============================================================================
# modules/evidence-store :: main.tf
# -----------------------------------------------------------------------------
# A WORM (write once, read many) store for the lab's audit evidence: the
# hashed evidence packs (lab/scripts/powershell/Export-EvidencePack.ps1) and
# the before/after ScubaGear + Zero Trust Assessment runs
# (lab/scripts/powershell/Invoke-BaselineAssessment.ps1).
#
# WHY WORM AND NOT JUST RBAC
#   A SHA-256 manifest proves a file has not changed since it was hashed; it
#   does not stop someone replacing the file AND the manifest together. RBAC
#   does not stop it either: the CI APPLY identity is subscription
#   Contributor, which can re-enable Shared Key, list the keys and overwrite
#   anything. A time-based immutability policy is enforced by the storage
#   service itself: while a blob version is under retention nobody can modify
#   or delete it, account owners included. Locked, the policy itself cannot
#   be shortened or removed, which is what makes it hold against a
#   compromised Contributor.
#
# DESIGN
#   * Version-level WORM, set as the ACCOUNT default policy
#     (immutability_policy below). Versioning is on, so an overwrite does not
#     fail silently or replace the original: it becomes a new version and the
#     original stays retained. Container-level WORM was the alternative; it
#     works without versioning but cannot keep an overwrite as a separate
#     version, which is exactly the tampering evidence we want.
#   * Starts Unlocked (Azure only creates the policy Unlocked or Disabled).
#     Locking is a deliberate SECOND apply with immutability_lock_acknowledged
#     = true, because it is irreversible: the retention can then only grow,
#     and the account and its resource group cannot be deleted until every
#     blob's retention has expired.
#   * Entra auth only: Shared Key off (so no account keys, no account or
#     service SAS), portal defaults to Entra auth, no local (SFTP) users, no
#     anonymous blob access, TLS 1.2, HTTPS only, copies only within the
#     tenant.
#   * Network: deny by default. Public access only to var.allowed_ip_ranges
#     (the operator's IP, the same lab compromise as the Key Vault); empty =
#     public network access off, private endpoint only.
#   * Blob read/write/delete logs + transaction metrics -> loga-idlab, so
#     "who read or tried to delete the evidence" is itself evidence.
#   * Writers get Storage Blob Data Contributor with an ABAC condition that
#     denies delete in the evidence container: add, never remove.
#
# FEATURES AZURE DOES NOT ALLOW WITH VERSION-LEVEL WORM (all left off here):
#   point-in-time restore (restore_policy), last access time tracking,
#   hierarchical namespace (ADLS Gen2), SFTP, NFS 3.0, blob inventory.
#   Source: learn.microsoft.com/azure/storage/blobs/immutable-storage-overview
#
# PROVIDER WIRING THE ROOT MUST HAVE (this module cannot set it):
#   provider "azurerm" { features { storage { data_plane_available = false } } }
#   With Shared Key disabled the provider's default read path calls the queue
#   and static-website DATA PLANE with an account key and fails; the CI
#   runners are also outside the firewall. data_plane_available = false makes
#   azurerm_storage_account Resource Manager only, and the container below
#   uses storage_account_id, which is Resource Manager too, so the Reader-only
#   PLAN identity can refresh it. verify: on the first real plan/apply
#   (azurerm 4.81.0 source reads queue/static-website only when
#   data_plane_available is true; ListKeys 403 is tolerated on read).
#
# HUMAN STEP AFTER THE FIRST APPLY (tenant time, not CI):
#   The pipeline cannot grant data-plane roles - envs/bootstrap allow-lists
#   only Key Vault Secrets User/Officer and VM Administrator Login, and adding
#   Storage Blob Data Contributor there would let a compromised APPLY identity
#   grant itself access to the Terraform state containers. So the operator's
#   write access is granted once by a human Owner / User Access Administrator:
#
#     az role assignment create \
#       --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
#       --assignee-principal-type User \
#       --role "Storage Blob Data Contributor" \
#       --scope "<output evidence_container_id>" \
#       --condition-version 2.0 \
#       --condition "<output writer_abac_condition>"
#
#   Then prove WORM before trusting it: upload a small canary blob and try to
#   delete it; the delete must be refused (lab/docs/evidence-capture-plan.md,
#   step P3). The canary stays for the retention period - that is the point.
#
# TEARDOWN (Unlocked only - verify: before relying on it): set
# immutability_state = "Disabled" (or shorten the period), apply, delete the
# blobs whose retention has passed, then destroy. A Locked account cannot be
# removed before its retention expires.
#
# LICENSING: no Entra SKU. Standard Azure Storage cost; for megabytes of
# evidence on GRS that is cents per month. Immutability itself has no extra
# charge (extra blob versions are billed as normal capacity).
# =============================================================================

locals {
  # Azure Storage's firewall rejects /31 and /32 CIDRs: a single address must
  # be given bare. The root passes the same "203.0.113.7/32" list it gives the
  # Key Vault and NSGs, so normalise it here rather than make callers keep two
  # formats. (/31 is rejected by the variable validation.)
  storage_ip_rules = [
    for c in var.allowed_ip_ranges :
    endswith(c, "/32") ? split("/", c)[0] : c
  ]

  # ABAC condition for evidence writers. Same shape as Microsoft's documented
  # Storage examples: the delete actions are allowed only when the target
  # container is NOT the evidence container. The assignment is scoped to the
  # evidence container, so writers can never delete; if someone later widens
  # the scope to the account, deletes elsewhere work and the evidence
  # container stays protected. deleteBlobVersion is not in Storage Blob Data
  # Contributor; it is listed so the condition still holds if the role is
  # ever swapped for Owner. WORM already blocks deleting RETAINED versions;
  # this also blocks deleting versions whose retention has expired.
  # verify: Storage ABAC condition syntax and actions
  # (learn.microsoft.com/azure/storage/blobs/storage-auth-abac-examples).
  writer_abac_condition = <<-EOT
    (
     (
      !(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete'})
      AND
      !(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/deleteBlobVersion/action'})
     )
     OR
     (
      @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringNotEquals '${var.container_name}'
     )
    )
  EOT
}

# -----------------------------------------------------------------------------
# The account.
# -----------------------------------------------------------------------------
resource "azurerm_storage_account" "evidence" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_kind             = "StorageV2" # version-level WORM needs general-purpose v2 (or BlockBlobStorage)
  account_tier             = "Standard"
  account_replication_type = var.replication_type
  access_tier              = "Hot" # Cool's 30-day early-deletion fee is moot under WORM, but Hot keeps reads (audits) cheap

  # ---- Entra authentication only -----------------------------------------
  # No Shared Key = no account keys and no account/service SAS on the data
  # plane. Every read and write is an Entra identity that RBAC (and the ABAC
  # condition) can reason about and the blob logs can name.
  #checkov:skip=CKV_AZURE_33:No queues are used. queue_properties logging is data-plane only, which this module avoids (shared key off, data_plane_available = false); blob access logs go to Log Analytics below.
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  local_user_enabled              = false # SFTP/local users would be a second, key-like identity store

  # Defence in depth if Shared Key is ever switched back on: ad hoc SAS
  # tokens longer than an hour are refused rather than just logged.
  sas_policy {
    expiration_period = "00.01:00:00"
    expiration_action = "Block"
  }

  # ---- Exposure ------------------------------------------------------------
  allow_nested_items_to_be_public  = false # no anonymous container/blob access, ever
  https_traffic_only_enabled       = true
  min_tls_version                  = "TLS1_2"
  cross_tenant_replication_enabled = false # object replication cannot copy evidence to another tenant
  allowed_copy_scope               = "AAD" # server-side copies only to/from accounts in this Entra tenant

  # Lab compromise, same as the Key Vault: the operator has no VNet-connected
  # workstation, so a non-empty allow-list opens the public endpoint to that
  # IP only; empty = public endpoint off, private endpoint only.
  #checkov:skip=CKV_AZURE_59:Public access is opened only to allowed_ip_ranges (operator IP) in the lab; empty list = disabled.
  #checkov:skip=CKV2_AZURE_33:Private endpoint is opt-in (enable_private_endpoint); the lab operator has no VNet-connected workstation.
  public_network_access_enabled = length(var.allowed_ip_ranges) > 0

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = local.storage_ip_rules
  }

  # ---- Features incompatible with WORM stay off ---------------------------
  is_hns_enabled = false # version-level WORM is not supported with a hierarchical namespace
  sftp_enabled   = false # immutability policies are not supported with SFTP
  nfsv3_enabled  = false # ... or NFS 3.0

  # Double encryption at rest (service + infrastructure layer). Microsoft-
  # managed keys: a customer-managed key would add a Key Vault key whose
  # deletion could make the evidence unreadable - a second way to lose it.
  infrastructure_encryption_enabled = true
  #checkov:skip=CKV2_AZURE_1:Microsoft-managed keys by design; a CMK adds a key whose loss makes WORM evidence unreadable.

  blob_properties {
    # Required by version-level WORM: an overwrite becomes a new, retained
    # version instead of replacing the original.
    versioning_enabled = true

    # Ordered, immutable log of every create/modify/delete on blobs: a
    # second record, independent of Log Analytics' 30-day retention.
    change_feed_enabled           = true
    change_feed_retention_in_days = var.immutability_period_days

    # Incompatible with immutable storage - explicit so nobody "helpfully"
    # turns it on.
    last_access_time_enabled = false

    # Microsoft recommends soft delete alongside immutability. It is NOT the
    # WORM control (retention is); it covers expired blobs and the container.
    delete_retention_policy {
      days = var.soft_delete_retention_days
    }
    container_delete_retention_policy {
      days = var.soft_delete_retention_days
    }
  }

  # Account-level default time-based retention, inherited by every container
  # and blob version (blob > container > account precedence). The block is
  # always present: adding or removing it recreates the account (ForceNew in
  # azurerm 4.81.0), which a WORM account refuses while it holds retained
  # blobs. State and period change in place; a Locked state can never change
  # again (the provider would plan a replacement, which Azure refuses).
  immutability_policy {
    state                         = var.immutability_state
    period_since_creation_in_days = var.immutability_period_days
    allow_protected_append_writes = var.allow_protected_append_writes
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.immutability_state != "Locked" || var.immutability_lock_acknowledged
      error_message = "immutability_state = \"Locked\" is irreversible (retention can only grow; the account cannot be deleted until every blob expires). Set immutability_lock_acknowledged = true to confirm, and lock only in an apply AFTER the account exists as Unlocked."
    }
  }
}

# -----------------------------------------------------------------------------
# The evidence container. storage_account_id (not _name) = Resource Manager
# API: works with Shared Key disabled and from outside the firewall.
# Private access only; it inherits the account's WORM policy.
# -----------------------------------------------------------------------------
resource "azurerm_storage_container" "evidence" {
  name                  = var.container_name
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"

  metadata = {
    purpose = "audit-evidence"
    worm    = "account-default-policy"
  }
}

# -----------------------------------------------------------------------------
# Data-plane RBAC. Empty by default (see variables.tf: the pipeline may not
# delegate storage data roles). Writers: add evidence, never delete it.
# Readers (auditors): read only.
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "writer" {
  for_each = toset(var.writer_principal_ids)

  scope                = azurerm_storage_container.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value
  condition_version    = "2.0"
  condition            = local.writer_abac_condition
  description          = "Evidence writer: may add blobs to the WORM evidence container, never delete them."
}

resource "azurerm_role_assignment" "reader" {
  for_each = toset(var.reader_principal_ids)

  scope                = azurerm_storage_container.evidence.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = each.value
  description          = "Evidence reader (auditor): read-only access to the WORM evidence container."
}

# -----------------------------------------------------------------------------
# Optional private endpoint (production posture). Off in the lab.
# -----------------------------------------------------------------------------
resource "azurerm_private_endpoint" "blob" {
  count = var.enable_private_endpoint ? 1 : 0

  name                = "pe-${var.storage_account_name}-blob"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-${var.storage_account_name}-blob"
    private_connection_resource_id = azurerm_storage_account.evidence.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  dynamic "private_dns_zone_group" {
    for_each = length(var.private_dns_zone_ids) > 0 ? [1] : []
    content {
      name                 = "blob-dns-zone-group"
      private_dns_zone_ids = var.private_dns_zone_ids
    }
  }

  lifecycle {
    precondition {
      condition     = var.private_endpoint_subnet_id != ""
      error_message = "enable_private_endpoint = true needs private_endpoint_subnet_id."
    }
  }
}

# -----------------------------------------------------------------------------
# Blob service logs + metrics -> loga-idlab. Always on, and no count: the
# root passes a workspace created in the same apply, and a count derived from
# a not-yet-known id fails the first plan (the modules/keyvault lesson). The
# precondition rejects an empty id instead.
# allLogs (StorageRead/StorageWrite/StorageDelete), not just "audit": reads
# of evidence matter too - an auditor asks who looked, not only who changed.
# verify: blob-service category group and the "Transaction" metric name on
# the first apply (Azure Storage monitoring reference).
# -----------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "diag-${var.storage_account_name}-blob"
  target_resource_id         = "${azurerm_storage_account.evidence.id}/blobServices/default"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category_group = "allLogs"
  }

  enabled_metric {
    category = "Transaction"
  }

  lifecycle {
    precondition {
      condition     = var.log_analytics_workspace_id != ""
      error_message = "log_analytics_workspace_id is required: evidence-store access logs must stream to loga-idlab."
    }
  }
}
