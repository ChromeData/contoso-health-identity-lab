# =============================================================================
# envs/dev :: backend.tf
# -----------------------------------------------------------------------------
# Remote state in an Azure Storage Account. State for an IAM/PAM tenant is
# SENSITIVE (it contains object ids, generated passwords, federation subjects)
# so it must live in a locked-down, VERSIONED, access-controlled container -
# never in the repo.
#
# VERSIONING / SAFETY the backing storage account must have (set when you
# create it - these are storage-account properties, not backend arguments):
#   * Blob versioning ENABLED            -> recover a clobbered/corrupted state
#   * Soft delete for blobs + containers -> undo accidental deletes (30 days)
#   * `change_feed` enabled              -> audit trail of state mutations
#   * HTTPS-only, TLS1.2, public access DISABLED, Shared Key OFF, RBAC +
#     (ideally) a private endpoint on the storage account
#   * State locking is automatic via blob lease (no DynamoDB-style table needed)
#
# A ready-to-run bootstrap snippet for that storage account is in the README
# ("Remote state bootstrap").
#
# VALIDATION: run `tofu init -backend=false` (or `terraform init
# -backend=false`) to initialize WITHOUT this backend so `validate`/`fmt`
# work with no Azure access. For real use, run `init` with the values below
# (or pass them via `-backend-config`).
# =============================================================================

terraform {
  backend "azurerm" {
    # These five values can also be supplied via `-backend-config=...` or env
    # vars (ARM_*). They are intentionally left as placeholders; a real
    # `init` must point them at YOUR versioned state storage account.
    resource_group_name  = "rg-identity-lab-tfstate"
    storage_account_name = "stidlabtfstate" # must be globally unique; rename
    container_name       = "tfstate"
    key                  = "entra-identity-lab/dev.terraform.tfstate"
    use_azuread_auth     = true # Entra auth for state; the account refuses keys (--allow-shared-key-access false, README)
  }
}
