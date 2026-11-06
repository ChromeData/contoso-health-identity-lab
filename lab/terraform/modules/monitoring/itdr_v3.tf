# =============================================================================
# modules/monitoring :: itdr_v3.tf
# -----------------------------------------------------------------------------
# ITDR pack, third set (enable_itdr_detections_v3): two lab/kql rules ported
# on 2026-11-06 from the owner's older Sentinel-Privileged-Access repo, each
# with its SPL twin in lab/splunk/detections.
#
#   dormant_privileged_account_reactivation  an admin account quiet for the
#                                            whole 14-day look-back signs in
#   keyvault_bulk_secret_read                one caller (managed identities
#                                            included) reads Key Vault secrets
#                                            far above its own normal rate, or
#                                            keeps being refused
#
# WHY A SEPARATE FLAG (the same reason as itdr_v2.tf): an apply that works
# today must not change because new rules were merged. Sentinel checks each
# rule's query when it creates it, and one refused rule fails the whole
# apply, so the set is added by flipping this flag in its own reviewed change.
# Both queries were run read-only against loga-idlab on 2026-11-06 (they
# compile on the workspace's real tables and returned no rows); that is not
# the same as Sentinel creating the rule.
#
# Both are Sentinel only: their 14-day look-back is longer than a Log
# Analytics alert allows (2 days) - local.v3_sentinel_only_rule_keys, merged
# into local.sentinel_only_rule_keys (itdr_v2.tf).
# keyvault_bulk_secret_read never triggers containment: its caller is usually
# a managed identity or an app, and the containment playbook acts on Entra
# users (local.v3_never_contain, merged into local.itdr_never_contain).
#
# Needs enable_itdr_detections (variable validation), like the v2 set.
# =============================================================================

locals {
  itdr_v3_rules = {
    dormant_privileged_account_reactivation = {
      file            = "dormant-privileged-account-reactivation.kql"
      display_name    = "Contoso ITDR - Dormant privileged account signs in again"
      description     = "An admin account (adm-* or tier0-admin-NN naming, or a privileged_user_ids object id) with no successful sign-in in either sign-in table for the 14-day look-back signs in interactively. High; Medium when the account was created inside the look-back. Break-glass accounts are left to break-glass-signin (T1078.004). Sentinel only (14-day look-back)."
      severity        = "High"
      frequency       = "PT1H"
      period          = "P14D"
      suppress        = null
      tactics         = ["InitialAccess", "Persistence"]
      techniques      = ["T1078"]
      entities        = local.signin_user_entities
      severity_column = "Severity"
      custom_details = {
        NewAccount = "NewAccount"
        QuietSince = "QuietSince"
        SignIns    = "SignIns"
        Apps       = "AppDisplayName"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    keyvault_bulk_secret_read = {
      file         = "keyvault-bulk-secret-read.kql"
      display_name = "Contoso ITDR - Bulk secret reads from Key Vault (credential harvesting)"
      description  = "One caller, keyed on its object id so managed identities count, read Key Vault secrets in the last hour above max(20, 5x its own 14-day hourly mean), or had 20 or more reads refused (403). High across 5 or more distinct secrets (T1555.006, T1552.001). Never containment (the caller is usually a managed identity). Sentinel only (14-day baseline)."
      severity     = "Medium"
      frequency    = "PT1H"
      period       = "P14D"
      suppress     = null
      tactics      = ["CredentialAccess"]
      techniques   = ["T1555", "T1552"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "CallerUpn" }, { identifier = "AadUserId", column = "CallerObjectId" }] },
        { type = "AzureResource", fields = [{ identifier = "ResourceId", column = "VaultResourceId" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "CallerIp" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Signal      = "Signal"
        CallerType  = "CallerType"
        CallerAppId = "CallerAppId"
        Reads       = "Reads"
        Secrets     = "Secrets"
        Denied      = "Denied"
        SecretNames = "SecretNames"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
  }

  v3_sentinel_only_rule_keys = ["dormant_privileged_account_reactivation", "keyvault_bulk_secret_read"]
  v3_never_contain           = ["keyvault_bulk_secret_read"]
}
