# =============================================================================
# modules/intune-vm :: variables.tf
# =============================================================================

variable "resource_group_name" {
  type        = string
  description = "Resource group for the VM and its network resources (contract: rg-identity-lab)."
}

variable "location" {
  type        = string
  description = "Azure region (contract: eastus2)."
  default     = "eastus2"
}

variable "vnet_name" {
  type        = string
  description = "Existing lab VNet (created by modules/keyvault) the endpoint subnet joins."
}

variable "subnet_name" {
  type        = string
  description = "Name of the endpoint subnet this module creates in the lab VNet."
  default     = "snet-endpoints"
}

variable "subnet_prefix" {
  type        = list(string)
  description = <<-EOT
    CIDR for the endpoint subnet. Lab VNet plan: 10.42.1.0/24 private
    endpoints (keyvault), 10.42.2.0/24 snet-identity (dc-vm), 10.42.3.0/24
    endpoints (this module).
  EOT
  default     = ["10.42.3.0/24"]

  validation {
    condition     = length(var.subnet_prefix) > 0 && alltrue([for c in var.subnet_prefix : can(cidrhost(c, 0))])
    error_message = "subnet_prefix must hold at least one IPv4 CIDR such as 10.42.3.0/24."
  }
}

variable "vm_name" {
  type        = string
  description = "Azure resource name of the VM."
  default     = "vm-win11-01"
}

variable "computer_name" {
  type        = string
  description = <<-EOT
    Windows hostname = the Entra DEVICE name the AADLoginForWindows extension
    registers. Entra RDP (enablerdsaadauth) only works when the name you
    connect to matches it, and a re-deploy fails to join if a stale device
    with the same name still exists in Entra (delete it first - see main.tf).
  EOT
  default     = "CH-WIN11-01"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,14}$", var.computer_name)) && !can(regex("^[0-9]+$", var.computer_name))
    error_message = "computer_name must be 1-15 letters, digits or hyphens, start with a letter or digit, and not be all digits."
  }
}

variable "vm_size" {
  type        = string
  description = <<-EOT
    VM size. Standard_B2s (2 vCPU / 4 GiB) is the smallest size that meets the
    Windows 11 minimum (2 cores, 4 GB RAM) and supports Trusted Launch. It is
    sluggish but fine for an enroll-and-show demo; Standard_B2as_v2 /
    Standard_B2s_v2 (8 GiB) is the smoother drop-in if v1 B-series is
    unavailable in your region.
  EOT
  default     = "Standard_B2s"
}

variable "image_sku" {
  type        = string
  description = <<-EOT
    Windows 11 Enterprise (single-session) marketplace SKU under publisher
    MicrosoftWindowsDesktop, offer windows-11. Default win11-25h2-ent (build
    26200.x). Microsoft's Azure Local "Azure Marketplace images" table lists
    publisher microsoftwindowsdesktop / offer windows-11 / SKUs
    win11-23h2-ent, win11-24h2-ent, win11-25h2-ent. The Entra-login extension
    requires Windows 11 24H2 or later (Microsoft Learn, "Sign in to a Windows
    VM in Azure by using Microsoft Entra ID"), so 24h2/25h2 are the sensible
    values. Marketplace availability is per region - confirm before apply:
      az vm image list-skus -l eastus2 -p MicrosoftWindowsDesktop -f windows-11 -o tsv --query "[].name" | grep ent
  EOT
  default     = "win11-25h2-ent" # verify: listed in Microsoft docs; regional availability in eastus2 not checked (no Azure login)

  validation {
    # Enterprise single-session only: -avd (multi-session) and -pro are a
    # different licensing story than "Enterprise rights from M365 E5".
    condition     = can(regex("^win11-[0-9]{2}h[12]-ent$", var.image_sku))
    error_message = "image_sku must be a Windows 11 Enterprise single-session SKU such as win11-24h2-ent or win11-25h2-ent."
  }
}

variable "admin_username" {
  type        = string
  description = <<-EOT
    LOCAL admin (break-glass into the VM only - day-to-day sign-in is Entra).
    It is not an Entra identity and plays no part in the join: the
    AADLoginForWindows extension joins the VM using its system-assigned
    identity. Entra users get admin rights only through the "Virtual Machine
    Administrator Login" role - Microsoft documents that adding AzureAD\<upn>
    to the local Administrators group by hand is NOT supported.
  EOT
  default     = "contosolocal"

  validation {
    condition     = !contains(["administrator", "admin", "user", "root", "guest"], lower(var.admin_username))
    error_message = "Azure rejects reserved admin usernames such as administrator/admin."
  }
}

variable "allowed_ip_ranges" {
  type        = list(string)
  description = "Operator IPv4 CIDRs allowed to RDP (3389). Empty = no inbound at all (use the serial console)."
  default     = []

  validation {
    condition     = alltrue([for c in var.allowed_ip_ranges : can(cidrnetmask(c)) && try(tonumber(split("/", c)[1]) >= 24, false)])
    error_message = "Each entry must be an IPv4 CIDR no wider than /24, e.g. 203.0.113.7/32."
  }
}

variable "enable_intune_enrollment" {
  type        = bool
  description = <<-EOT
    true (default) = pass mdmId (the Microsoft Intune MDM application id) to
    the AADLoginForWindows extension so the Entra join also auto-enrolls the
    VM into Intune. false = Entra join only (no compliance demo).
    Requires the human steps "MDM user scope" + licence in Intune BEFORE the
    VM is created: enrollment is attempted during the join, when the
    extension installs (see main.tf header).
  EOT
  default     = true
}

variable "admin_login_user_object_ids" {
  type        = list(string)
  description = <<-EOT
    Entra USER object ids granted "Virtual Machine Administrator Login" on this
    VM (Entra RDP sign-in as local admin). Typically your own admin account.
    Owner/Contributor alone do NOT allow sign-in - this role is required.
  EOT
  default     = []

  validation {
    condition = alltrue([
      for id in var.admin_login_user_object_ids :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))
    ])
    error_message = "Each admin_login_user_object_ids entry must be a user object id (GUID)."
  }
}

variable "admin_login_group_object_ids" {
  type        = map(string)
  description = <<-EOT
    Entra GROUP object ids granted "Virtual Machine Administrator Login" on this
    VM, keyed by a STATIC label (e.g. { ca005_pilot = <group id> }). A map so
    the for_each keys are known at plan time even when the group is created in
    the same apply (values may be unknown; keys may not).
  EOT
  default     = {}

  validation {
    # An unknown value (group created in the same apply) defers this check to
    # apply time; the keys are what for_each needs at plan time.
    condition = alltrue([
      for id in values(var.admin_login_group_object_ids) :
      can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))
    ])
    error_message = "Each admin_login_group_object_ids value must be a group object id (GUID)."
  }
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
