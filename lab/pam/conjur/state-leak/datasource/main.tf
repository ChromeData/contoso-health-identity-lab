# The intuitive wiring: read a Conjur secret with the conjur_secret DATA SOURCE.
#
# Nothing else is here on purpose: no other provider, and the one resource
# does not reference the secret. So whatever lands in terraform.tfstate came
# from the data source itself. run.sh applies this, then counts the secret's
# value in the state file (expected: it is there, in plaintext).
#
# Ported from the author's earlier Conjur-Terraform-AWS lab
# (experiments/state-leak); the AWS half of that lab is not ported.

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    conjur = {
      source  = "cyberark/conjur"
      version = "0.9.15"
    }
  }
}

# Configured from CONJUR_APPLIANCE_URL / CONJUR_ACCOUNT / CONJUR_AUTHN_LOGIN /
# CONJUR_AUTHN_API_KEY, set by run.sh (provider docs, "Using environment
# variables": https://registry.terraform.io/providers/cyberark/conjur/0.9.15/docs).
provider "conjur" {}

data "conjur_secret" "secret" {
  name = "state-leak/db-password"
}

# run.sh applies twice with a different run_id, so the second apply changes
# state and Terraform writes terraform.tfstate.backup (the copy of the state
# before the change). Does the backup keep the secret too?
variable "run_id" {
  description = "Changes between run.sh's two applies (not secret)."
  type        = string
  default     = "1"
}

resource "terraform_data" "marker" {
  input = "conjur state-leak experiment: data source path, run ${var.run_id}"
}
