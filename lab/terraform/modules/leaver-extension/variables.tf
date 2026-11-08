variable "resource_group_name" {
  description = "Resource group for the Logic App (the lab's RG-IDENTITY-LAB)."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "name" {
  description = "Logic App (consumption) name. The custom task extension in Lifecycle Workflows points at it by name."
  type        = string
  default     = "la-lcw-leaver-remove-birthright"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]{1,80}$", var.name))
    error_message = "name: letters, digits and hyphens, 1-80 characters."
  }
}

variable "catalog_ids" {
  description = "Static name => entitlement catalog id. The Logic App's identity gets 'Access package assignment manager' on THESE catalogs only, never a tenant-wide permission. Today: { clinical = <modules/entitlement output catalog_id> }, the catalog that holds every T3 package. Keys are static so the plan works before the catalog id is known."
  type        = map(string)

  validation {
    condition     = length(var.catalog_ids) > 0
    error_message = "catalog_ids: at least one catalog."
  }
}

variable "tags" {
  description = "Tags on the Logic App."
  type        = map(string)
  default     = {}
}
