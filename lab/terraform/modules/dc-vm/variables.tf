# =============================================================================
# modules/dc-vm :: variables.tf
# =============================================================================

variable "resource_group_name" {
  type        = string
  description = "Resource group for the DC and its network resources."
}

variable "location" {
  type        = string
  description = "Azure region (contract: eastus2)."
  default     = "eastus2"
}

variable "vnet_name" {
  type        = string
  description = "Existing lab VNet (created by modules/keyvault) the DC subnet joins."
}

variable "subnet_prefix" {
  type        = list(string)
  description = "CIDR for snet-identity."
  default     = ["10.42.2.0/24"]
}

variable "private_ip" {
  type        = string
  description = "Static private IP of the DC (first usable host in snet-identity)."
  default     = "10.42.2.4"
}

variable "vm_name" {
  type        = string
  description = "Azure resource name of the VM."
  default     = "vm-dc01"
}

variable "computer_name" {
  type        = string
  description = "Windows hostname (max 15 chars)."
  default     = "DC01"

  validation {
    condition     = length(var.computer_name) <= 15
    error_message = "Windows computer names are at most 15 characters."
  }
}

variable "vm_size" {
  type        = string
  description = <<-EOT
    VM size. B2s (2 vCPU / 4 GiB) runs AD DS + AD CS + the Entra provisioning
    agent for a lab. If B-series v1 is unavailable in your region/subscription,
    Standard_B2s_v2 is the drop-in.
  EOT
  default     = "Standard_B2s"
}

variable "admin_username" {
  type        = string
  description = "Local admin (becomes the domain's built-in Administrator account name after promotion)."
  default     = "contosoadmin"

  validation {
    condition     = !contains(["administrator", "admin", "user", "root", "guest"], lower(var.admin_username))
    error_message = "Azure rejects reserved admin usernames such as administrator/admin."
  }
}

variable "ntds_disk_size_gb" {
  type        = number
  description = "Size of the NTDS/SYSVOL data disk."
  default     = 8
}

variable "allowed_ip_ranges" {
  type        = list(string)
  description = <<-EOT
    Operator egress IPs allowed to RDP (3389) and LDAPS (636) to the DC, each
    a single IPv4 host written as a /32, e.g. "203.0.113.7/32". Empty = no
    inbound at all. This allowlist is the only barrier between the internet
    and a Tier-0 asset (ADR 0013), so nothing wider than one address is
    accepted: a /24 mistyped or kept "for convenience" would open RDP and
    LDAPS on a domain controller to 256 addresses (risk register R13).
  EOT
  default     = []

  # try(): a null element or a non-IPv4 string makes endswith()/cidrnetmask()
  # error; both must read as "invalid", not as an evaluation error.
  # cidrnetmask() accepts IPv4 only, so IPv6 is rejected too.
  validation {
    condition = alltrue([
      for c in var.allowed_ip_ranges :
      try(endswith(c, "/32") && cidrnetmask(c) == "255.255.255.255", false)
    ])
    error_message = "modules/dc-vm: each allowed_ip_ranges entry must be a single IPv4 address written as a /32, e.g. \"203.0.113.7/32\". Ranges such as /24 or /31, bare addresses without /32, and IPv6 are rejected: this NSG allowlist is the only barrier between the internet and RDP/LDAPS on a domain controller (ADR 0013)."
  }
}

variable "key_vault_id" {
  type        = string
  description = "Key Vault the DC's identity may write its build secrets to (dc01-dsrm-password, svc-vault-rotator; and svc-pam-discovery, retired but still named because the vault lock blocks the replace; ABAC-limited to those names in main.tf)."
}

variable "auto_shutdown_time" {
  type        = string
  description = "Daily deallocate time, HHmm (24h)."
  default     = "1900"

  validation {
    condition     = can(regex("^([01][0-9]|2[0-3])[0-5][0-9]$", var.auto_shutdown_time))
    error_message = "Use HHmm, e.g. 1900."
  }
}

variable "auto_shutdown_timezone" {
  type        = string
  description = "Windows time zone id for the shutdown schedule."
  default     = "Eastern Standard Time"
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to every resource in this module."
  default     = {}
}

variable "adfs_https_enabled" {
  type        = bool
  description = <<-EOT
    Also admit HTTPS (443) to the DC from allowed_ip_ranges, for the
    TEMPORARY AD FS migration exercise (lab/adfs/README.md): the operator's
    test browser signs in to AD FS on DC01 through it. AD FS is Tier 0 like
    the DC, and the allowlist is the same single /32. Off by default; turn it
    off when 19-Remove-Adfs.ps1 has run.
  EOT
  default     = false
}
