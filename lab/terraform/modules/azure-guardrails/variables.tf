# =============================================================================
# modules/azure-guardrails :: variables.tf
# -----------------------------------------------------------------------------
# Nothing here is a secret. Principal object ids are identifiers; keep the
# real ones in envs/bootstrap's gitignored terraform.tfvars.
# =============================================================================

variable "subscription_id" {
  type        = string
  description = "Resource id of the subscription the two policies are assigned to: /subscriptions/<guid> (envs/bootstrap passes data.azurerm_subscription.current.id)."

  validation {
    condition     = can(regex("^/subscriptions/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a subscription resource id: /subscriptions/<guid>."
  }
}

variable "standing_owner_effect" {
  type        = string
  description = <<-EOT
    What the "no new standing Owner" policy does to a new Owner role
    assignment for anyone not in owner_allowed_principal_ids:
      Audit    (default) allow it, and record it as non-compliant;
      Deny     refuse it;
      Disabled do nothing.
    Roll out in Audit, read the compliance results, then switch to Deny.
  EOT
  default     = "Audit"

  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.standing_owner_effect)
    error_message = "standing_owner_effect must be Audit, Deny or Disabled."
  }
}

variable "keyvault_protection_effect" {
  type        = string
  description = <<-EOT
    What the "Key Vaults keep deletion protection" policy does to a vault
    created or updated without purge protection (or with soft delete off):
    Audit (default), Deny or Disabled. Same rollout as standing_owner_effect.
  EOT
  default     = "Audit"

  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.keyvault_protection_effect)
    error_message = "keyvault_protection_effect must be Audit, Deny or Disabled."
  }
}

variable "owner_allowed_principal_ids" {
  type        = list(string)
  description = <<-EOT
    Object ids that may still be GIVEN Owner on the subscription once the
    policy denies: the lab owner's account and the lab operator's service
    principal (the two standing Owners today). Read them with:
      az role assignment list --scope /subscriptions/<id> --role Owner --query "[].principalId" -o tsv
    Required (non-empty) when standing_owner_effect = "Deny", so a Deny can
    never go out that would stop the operator's own Owner grant
    (envs/operator) from being re-created.
  EOT
  default     = []

  validation {
    condition     = alltrue([for id in var.owner_allowed_principal_ids : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", id))])
    error_message = "owner_allowed_principal_ids entries must be lowercase object ids (GUIDs)."
  }
}
