# =============================================================================
# modules/evidence-store :: variables.tf
# =============================================================================

variable "storage_account_name" {
  type        = string
  description = <<-EOT
    Globally unique storage account name (3-24 chars, lowercase letters and
    digits only). The contract default "stidlabevidence" will probably be
    taken, so add a suffix, e.g. "stidlabevidence7f3a".
  EOT
  default     = "stidlabevidence"

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Storage account name must be 3-24 characters, lowercase letters and digits only."
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group for the evidence store (contract: rg-identity-lab)."
}

variable "location" {
  type        = string
  description = "Azure region (contract: eastus2)."
  default     = "eastus2"
}

variable "container_name" {
  type        = string
  description = "Private container that holds the evidence packs and assessment runs."
  default     = "evidence"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.container_name)) && !strcontains(var.container_name, "--")
    error_message = "Container name must be 3-63 chars: lowercase letters, digits and single hyphens, starting and ending with a letter or digit."
  }
}

variable "replication_type" {
  type        = string
  description = <<-EOT
    Account redundancy. GRS by default: the evidence is small (megabytes), so
    a second region costs cents, and losing the only copy of audit evidence to
    a regional outage is the failure an auditor asks about. Changing between
    the LRS/GRS family and the ZRS/GZRS family recreates the account, which a
    WORM account refuses while it holds retained blobs - choose once.
  EOT
  default     = "GRS"

  validation {
    condition     = contains(["LRS", "GRS", "RAGRS", "ZRS", "GZRS", "RAGZRS"], var.replication_type)
    error_message = "replication_type must be one of LRS, GRS, RAGRS, ZRS, GZRS, RAGZRS."
  }
}

# ---- WORM (version-level immutability, account default policy) --------------

variable "immutability_period_days" {
  type        = number
  description = <<-EOT
    Retention interval of the account-level time-based immutability policy:
    every blob version is write- and delete-protected for this many days from
    its creation. Default 2190 days (6 years), the HIPAA documentation
    retention period (45 CFR 164.316(b)(2)(i)). While the policy is Unlocked
    this can be shortened, e.g. before locking a throwaway lab account; once
    Locked it can only be extended.
  EOT
  default     = 2190

  validation {
    condition     = var.immutability_period_days >= 1 && var.immutability_period_days <= 146000 && floor(var.immutability_period_days) == var.immutability_period_days
    error_message = "immutability_period_days must be a whole number from 1 to 146000 (Azure's range)."
  }
}

variable "immutability_state" {
  type        = string
  description = <<-EOT
    State of the account-level immutability policy.
      Unlocked (default) - blobs are already write/delete protected, but an
                           account administrator can shorten or delete the
                           policy. Microsoft calls this the TESTING state.
      Locked             - IRREVERSIBLE. Only extensions are allowed, and the
                           account (and its resource group) cannot be deleted
                           until every blob's retention has expired. This is
                           the state that holds against a compromised
                           subscription Contributor (see main.tf header).
                           Needs immutability_lock_acknowledged = true, and
                           must be a SECOND apply: Azure creates the policy
                           only as Unlocked or Disabled.
      Disabled           - policy off (versioning-level WORM support stays on).
  EOT
  default     = "Unlocked"

  validation {
    condition     = contains(["Disabled", "Unlocked", "Locked"], var.immutability_state)
    error_message = "immutability_state must be Disabled, Unlocked or Locked."
  }
}

variable "immutability_lock_acknowledged" {
  type        = bool
  description = <<-EOT
    Must be true for immutability_state = "Locked". A deliberate second key
    for an action that cannot be undone: once locked, the retention period
    can never be reduced and the account cannot be deleted while it holds
    retained blobs.
  EOT
  default     = false
}

variable "allow_protected_append_writes" {
  type        = bool
  description = <<-EOT
    Allow new blocks to be appended to append blobs under retention. False:
    evidence files are written once as block blobs, so nothing - not even an
    append - may change a retained object.
  EOT
  default     = false
}

variable "soft_delete_retention_days" {
  type        = number
  description = <<-EOT
    Blob and container soft delete (1-365 days). Microsoft recommends soft
    delete alongside immutability: it covers blobs whose retention has
    expired and the container itself.
  EOT
  default     = 30

  validation {
    condition     = var.soft_delete_retention_days >= 1 && var.soft_delete_retention_days <= 365
    error_message = "soft_delete_retention_days must be from 1 to 365."
  }
}

# ---- Network -----------------------------------------------------------------

variable "allowed_ip_ranges" {
  type        = list(string)
  description = <<-EOT
    Public IPv4 CIDRs admitted through the storage firewall (the operator's
    workstation, e.g. "203.0.113.7/32"). EMPTY = public network access is
    disabled and the account is reachable only through a private endpoint
    (production posture). A non-empty list is the same lab compromise as the
    Key Vault: no VNet-connected workstation, so only the operator's IP gets
    in. A /32 is converted to the bare address the storage firewall expects;
    /31 is rejected because Azure Storage does not accept it.
  EOT
  default     = []

  validation {
    condition = alltrue([
      for c in var.allowed_ip_ranges :
      can(cidrnetmask(c)) && try(tonumber(split("/", c)[1]) >= 24 && tonumber(split("/", c)[1]) != 31, false)
    ])
    error_message = "Each entry must be an IPv4 CIDR from /24 to /32 (not /31), e.g. 203.0.113.7/32."
  }
}

variable "enable_private_endpoint" {
  type        = bool
  description = <<-EOT
    Create a private endpoint for the blob sub-resource. Off by default: the
    lab operator has no VNet-connected workstation. A bool, not "subnet id is
    non-empty", so the count is known at plan even when the subnet is created
    in the same apply.
  EOT
  default     = false
}

variable "private_endpoint_subnet_id" {
  type        = string
  description = "Subnet for the private endpoint. Required when enable_private_endpoint = true."
  default     = ""
}

variable "private_dns_zone_ids" {
  type        = list(string)
  description = <<-EOT
    Ids of privatelink.blob.core.windows.net zone(s) to register the endpoint
    in. Empty = no DNS zone group (you resolve the private IP yourself).
  EOT
  default     = []
}

# ---- Monitoring --------------------------------------------------------------

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource id of loga-idlab (required). Blob read/write/delete logs and transaction metrics always stream here."
}

# ---- Data-plane RBAC (Entra auth only; shared key is disabled) ---------------

variable "writer_principal_ids" {
  type        = list(string)
  description = <<-EOT
    Object ids granted "Storage Blob Data Contributor" on the evidence
    container, with an ABAC condition that DENIES blob delete: writers can add
    evidence, never remove it, even after retention expires.
    Keep this EMPTY when the module is applied by the envs/dev pipeline: the
    APPLY identity may only delegate the roles allow-listed in envs/bootstrap,
    and storage data roles are deliberately not on that list (granting itself
    Storage Blob Data Contributor would reach the Terraform state account).
    A human grants the operator with the az command in the main.tf header,
    using the writer_abac_condition output.
  EOT
  default     = []
}

variable "reader_principal_ids" {
  type        = list(string)
  description = <<-EOT
    Object ids granted "Storage Blob Data Reader" on the evidence container
    (auditors). Same pipeline caveat as writer_principal_ids.
  EOT
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to every resource in this module."
  default = {
    project = "contoso-health-identity-lab"
    tier    = "evidence"
  }
}
