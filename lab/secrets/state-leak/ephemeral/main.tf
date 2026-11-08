# The fix: read the same secret with the azurerm_key_vault_secret EPHEMERAL
# resource.
#
# Ephemeral resources (Terraform 1.10+) are opened for one run and never
# written to state or a plan file. run.sh tests that claim instead of
# trusting it.
#
# The precondition is the positive control. It proves Terraform really did
# read the secret (its length must match what run.sh stored), so a clean
# state file cannot just mean "nothing was read". Only the length crosses
# into the condition; the value itself is never assigned to anything that
# persists.

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
  }
}

provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
}

variable "key_vault_id" {
  description = "ID of the throwaway vault run.sh created (not secret)."
  type        = string
}

variable "expected_secret_length" {
  description = "Length of the value run.sh stored in the vault (not secret)."
  type        = number
}

ephemeral "azurerm_key_vault_secret" "secret" {
  name         = "state-leak-db-password"
  key_vault_id = var.key_vault_id
}

variable "run_id" {
  description = "Changes between run.sh's two applies (not secret)."
  type        = string
  default     = "1"
}

resource "terraform_data" "marker" {
  input = "key vault state-leak experiment: ephemeral path, run ${var.run_id}"

  lifecycle {
    precondition {
      condition     = length(ephemeral.azurerm_key_vault_secret.secret.value) == var.expected_secret_length
      error_message = "The ephemeral azurerm_key_vault_secret did not return the value run.sh stored."
    }
  }
}
