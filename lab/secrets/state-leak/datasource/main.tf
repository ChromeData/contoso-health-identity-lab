# The usual wiring: read a Key Vault secret with the azurerm_key_vault_secret
# DATA SOURCE.
#
# Nothing else is here on purpose. The one resource does not reference the
# secret, and the vault ID comes in as a plain variable (no
# azurerm_key_vault data source). So whatever lands in terraform.tfstate came
# from the secret's data source itself. run.sh applies this, then counts the
# secret's value in every file Terraform wrote (expected: it is there, in
# plaintext).

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0" # the version envs/dev pins in its lock file
    }
  }
}

# Signs in through the az CLI as the lab operator (run.sh runs under `op`).
# resource_provider_registrations = "none": the operator must not register
# providers as a side effect of an experiment.
provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
}

variable "key_vault_id" {
  description = "ID of the throwaway vault run.sh created (not secret)."
  type        = string
}

data "azurerm_key_vault_secret" "secret" {
  name         = "state-leak-db-password"
  key_vault_id = var.key_vault_id
}

# run.sh applies twice with a different run_id, so the second apply changes
# state and Terraform writes terraform.tfstate.backup. Does the backup keep
# the secret too?
variable "run_id" {
  description = "Changes between run.sh's two applies (not secret)."
  type        = string
  default     = "1"
}

resource "terraform_data" "marker" {
  input = "key vault state-leak experiment: data source path, run ${var.run_id}"
}
