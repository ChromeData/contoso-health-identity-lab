# =============================================================================
# envs/dev :: connect_health_registration.tf
# -----------------------------------------------------------------------------
# A TIME-BOXED identity that registers the Microsoft Entra Connect Health
# agent for AD FS on DC01 (lab/adfs, README step 5) with no person at the
# server. ADR 0031 has the full reasoning; in short:
#
#   * Registration needs a Global Administrator or Hybrid Identity
#     Administrator (Learn, "Install the Microsoft Entra Connect Health
#     agents"). No lab identity Claude can sign in as holds either: Hybrid
#     Identity Administrator comes only from PIM-Tier0-Hybrid-Identity-Admins,
#     which has no eligible members, and every Tier-0 activation needs
#     approval from PIM-Approvers-Tier0 (the owner alone).
#   * Learn's only unattended form (-Credential, an account "which does not
#     have multifactor authentication enabled") cannot work any more: the
#     agent registers through Azure Resource Manager (its own log, 2026-11-07),
#     and ARM enforces Microsoft's mandatory MFA on every create by a user,
#     "regardless of ... user exclusions". So a Conditional Access exclusion
#     would weaken CA001 AND still fail. This file changes NO CA policy.
#   * Instead this account signs in with a PASSKEY (phishing-resistant MFA:
#     CA001 and the ARM check are both met), registered through a one-time
#     Temporary Access Pass the operator issues (lab/scripts/demo/signin/
#     passkey.mjs), the same way the adm-* and break-glass passkeys were made.
#
# WHAT EXISTS WHILE THE FLAG IS ON (and only then):
#   * cloud-only user adm-connecthealth-reg@<onmicrosoft domain>, no licence,
#     no group, never synced; its Terraform-made password is never used or
#     read (the passkey is its only working sign-in; the password is in state
#     like every azuread_user's, and dies with the user);
#   * an ACTIVE Hybrid Identity Administrator assignment for it. This skips
#     PIM on purpose (PIM would need the owner's approval, the human step this
#     replaces). The control instead: the flag is off in lab.tfvars, the PR
#     that turns it on is reviewed, and connect_health_registration_until_utc
#     fails EVERY envs/dev plan once it has passed - so the next apply after
#     the window cannot happen until a PR turns the flag off again, which
#     deletes the user and with it the role assignment.
#
# The registration itself: lab/adfs/connect-health/register.sh.
# =============================================================================

locals {
  connect_health_registration_upn = "adm-connecthealth-reg@${var.onmicrosoft_domain}"
}

resource "azuread_user" "connect_health_registration" {
  count = var.enable_connect_health_registration ? 1 : 0

  user_principal_name   = local.connect_health_registration_upn
  display_name          = "Connect Health registration (temporary, ADR 0031)"
  mail_nickname         = "adm-connecthealth-reg"
  account_enabled       = true
  usage_location        = "US"
  force_password_change = false
  # No password argument: the provider makes a random one. It is never used:
  # the account signs in with its passkey only.

  lifecycle {
    # register.sh close disables the account through Graph the moment the
    # registration is done, BEFORE the flag-off PR merges. Without this line
    # any other envs/dev apply in that gap would see accountEnabled = false
    # as drift and switch the account back ON, with its Hybrid Identity
    # Administrator role and passkey intact. Terraform still creates it
    # enabled (ignore_changes does not touch the create); it only stops
    # Terraform from undoing the close. It weakens nothing: Terraform was
    # never the control that keeps the account off (close and the flag-off
    # PR are; the time box below fails every plan once the window is over),
    # and the flag-off PR still deletes the user whatever its state.
    ignore_changes = [account_enabled]

    precondition {
      condition     = var.onmicrosoft_domain != ""
      error_message = "enable_connect_health_registration needs onmicrosoft_domain (the account must not depend on custom DNS)."
    }
    precondition {
      # The time box. plantimestamp() is the plan's own clock.
      condition     = var.connect_health_registration_until_utc != "" && timecmp(plantimestamp(), var.connect_health_registration_until_utc) < 0
      error_message = "The Connect Health registration window (connect_health_registration_until_utc) is missing or over. Set enable_connect_health_registration = false: that deletes adm-connecthealth-reg and its Hybrid Identity Administrator role (ADR 0031)."
    }
  }
}

resource "azuread_directory_role_assignment" "connect_health_registration" {
  count = var.enable_connect_health_registration ? 1 : 0

  # Hybrid Identity Administrator (built-in template id; Learn, "Microsoft
  # Entra built-in roles"). The least role Learn names for agent registration.
  role_id             = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
  principal_object_id = azuread_user.connect_health_registration[0].object_id
}

output "connect_health_registration_upn" {
  description = "The temporary Connect Health registration account (ADR 0031), or null while enable_connect_health_registration is off."
  value       = var.enable_connect_health_registration ? local.connect_health_registration_upn : null
}
