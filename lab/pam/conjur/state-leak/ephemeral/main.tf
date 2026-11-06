# The fix: read the same secret with the conjur_secret EPHEMERAL resource.
#
# Ephemeral resources (Terraform 1.10+) are opened for one run and never
# written to state or a plan file. The provider documents its conjur_secret
# ephemeral resource as "NOT stored in Terraform state"
# (docs/ephemeral-resources/secret.md, provider 0.9.15). run.sh tests that
# claim rather than trusting it.
#
# The precondition is the positive control: it proves Terraform really did
# read the secret (its length must match what run.sh stored), so a clean state
# file cannot just mean "nothing was read". Only the length crosses into the
# condition; the value itself is never assigned to anything that persists.

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    conjur = {
      source  = "cyberark/conjur"
      version = "0.9.15"
    }
  }
}

provider "conjur" {}

variable "expected_secret_length" {
  description = "Length of the value run.sh stored in Conjur (not secret)."
  type        = number
}

ephemeral "conjur_secret" "secret" {
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
  input = "conjur state-leak experiment: ephemeral path, run ${var.run_id}"

  lifecycle {
    precondition {
      condition     = length(ephemeral.conjur_secret.secret.value) == var.expected_secret_length
      error_message = "The ephemeral conjur_secret did not return the value run.sh stored."
    }
  }
}
