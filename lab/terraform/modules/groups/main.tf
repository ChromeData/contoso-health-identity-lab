# =============================================================================
# modules/groups :: main.tf
# -----------------------------------------------------------------------------
# Creates the identity "cast" Terraform owns for the Contoso Health lab:
#   * bg-admin-01 / 02       - cloud-only break-glass accounts (onmicrosoft.com)
#   * Break-Glass-Admins     - ROLE-ASSIGNABLE static group, standing Global
#                              Administrator, excluded from every CA policy
#   * All-Nurses / All-ICU   - DYNAMIC birthright groups (department rule)
#   * Privileged-IAM-Admins  - ROLE-ASSIGNABLE group governed by PIM (see pim)
#   * Admin-Accounts         - ROLE-ASSIGNABLE, STANDING (no role): every
#                              cloud-only adm- account + the build account -
#                              the admin passkey target (never a PIM group)
#   * App access groups      - ServiceNow / AWS IAM Identity Center / Okta,
#                              plus the ICU and Pharmacy package resources
#   * CA005-Pilot-CompliantDevice - ASSIGNED pilot group: CA005 (compliant
#                              device for admin portals) scope, Intune
#                              compliance-baseline assignment, and Entra
#                              sign-in to the demo Windows 11 VM
#   * App-Consent-Reviewers  - (enable_nhi_governance) admin consent workflow
#                              reviewers
#   * All-Workforce          - (enable_workforce_group) DYNAMIC, every enabled
#                              HR-synced member - the passkey rollout target
#
# WORKFORCE USERS ARE NOT HERE. HR is the source of truth: Dana Okafor and every
# other worker arrive through API-driven inbound provisioning (HR -> AD -> Cloud
# Sync -> Entra, see lab/scripts/mock-hr). Terraform only owns the accounts
# that must exist independently of HR - the break-glass pair.
#
# Every group sets mail_nickname explicitly: it is the stable natural key the
# lifecycle scripts look groups up by.
#
# LICENSING:
#   * Dynamic membership groups require Entra ID P1 (per-member).
#   * Role-assignable groups (`assignable_to_role`) require Entra ID P1.
#   * See lab/terraform/README.md for the full matrix.
# =============================================================================

# -----------------------------------------------------------------------------
# Strong initial passwords for the break-glass accounts. They land only in
# (remote, access-controlled) state. Post-apply the human custodian registers
# FIDO2 passkeys and rotates this seeded password - see README "human steps".
# -----------------------------------------------------------------------------
resource "random_password" "break_glass" {
  for_each = toset(local.break_glass_keys)

  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
}

locals {
  # Break-glass account keys: bg-admin-01 .. bg-admin-NN (zero-padded).
  break_glass_keys = [
    for i in range(1, var.break_glass_count + 1) :
    format("bg-admin-%02d", i)
  ]

  # Global Administrator role template id (identical in every tenant).
  global_admin_role_template_id = "62e90394-69f5-4237-9190-012177145e10"
}

# -----------------------------------------------------------------------------
# Break-glass (emergency access) accounts.
#   * Cloud-only, on the tenant's *.onmicrosoft.com domain - no dependency on
#     custom-domain DNS or federation (Microsoft emergency-access guidance).
#   * EXCLUDED from every Conditional Access policy (see modules/conditional-access)
#     so a CA misconfiguration can never lock every admin out.
#   * Standing Global Administrator via the group below - the ONE documented
#     exception to zero standing admin.
#   * Microsoft guidance: passkey (FIDO2) or certificate-based auth (mandatory
#     admin-portal MFA applies to break-glass, no opt-out); the password is
#     vaulted backup only. Monitor every sign-in
#     (lab/kql/break-glass-signin.kql), review quarterly.
# -----------------------------------------------------------------------------
resource "azuread_user" "break_glass" {
  for_each = toset(local.break_glass_keys)

  user_principal_name = "${each.key}@${var.break_glass_domain}"
  display_name        = upper(replace(each.key, "-", " ")) # "BG ADMIN 01"
  mail_nickname       = each.key
  company_name        = "Contoso Health"
  usage_location      = "US" # required before license assignment

  # Break-glass should NOT be forced to change at next sign-on during a real
  # emergency; the password is rotated deliberately by its custodian; sign-in
  # is by FIDO2 key.
  password              = random_password.break_glass[each.key].result
  force_password_change = false
  account_enabled       = true

  # The custodian rotates the credential out-of-band after apply; do not let a
  # later plan try to set it back to the generated value.
  lifecycle {
    ignore_changes = [password]
  }
}

# -----------------------------------------------------------------------------
# Break-Glass-Admins: role-assignable security group.
# Membership is STATIC (role-assignable groups cannot be dynamic). This group's
# object id is the single value every CA policy excludes.
# -----------------------------------------------------------------------------
resource "azuread_group" "break_glass" {
  display_name     = "Break-Glass-Admins"
  mail_nickname    = "break-glass-admins"
  description      = "Emergency access accounts - standing Global Admin, excluded from all CA policies [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false

  # Lets the group be the target of a directory role assignment so the accounts
  # inside it are privileged even if PIM/CA/automation break.
  assignable_to_role = true

  members = [for u in azuread_user.break_glass : u.object_id]
}

# Standing Global Administrator for the break-glass group (and only this group).
resource "azuread_directory_role_assignment" "break_glass_global_admin" {
  role_id             = local.global_admin_role_template_id
  principal_object_id = azuread_group.break_glass.object_id
  directory_scope_id  = "/"
}

# -----------------------------------------------------------------------------
# Dynamic BIRTHRIGHT groups - membership follows the HR department attribute.
# Disabled accounts are excluded so a leaver drops out the moment HR disables
# them, even before the department changes.
#
# Dynamic groups CANNOT be access-package resources (entitlement management
# can only hand out assigned membership), so these are birthright only; the
# requestable app access lives in the assigned groups further down.
# -----------------------------------------------------------------------------
locals {
  department_groups = {
    nursing = {
      display_name  = "All-Nurses"
      mail_nickname = "all-nurses"
      department    = var.all_nurses_department # "Nursing"
    }
    icu = {
      display_name  = "All-ICU"
      mail_nickname = "all-icu"
      department    = var.icu_department # "ICU"
    }
  }
}

resource "azuread_group" "department" {
  for_each = local.department_groups

  display_name     = each.value.display_name
  mail_nickname    = each.value.mail_nickname
  description      = "Dynamic birthright: enabled users where department = ${each.value.department} [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false

  # Dynamic groups MUST declare the DynamicMembership type.
  types = ["DynamicMembership"]

  dynamic_membership {
    enabled = true
    # Entra ID membership rule syntax (NOT Terraform). Quotes are escaped.
    rule = "(user.department -eq \"${each.value.department}\") -and (user.accountEnabled -eq true)"
  }
}

# -----------------------------------------------------------------------------
# Privileged-IAM-Admins: role-assignable group consumed by the PIM module.
# Kept EMPTY here on purpose - people become *eligible* members via PIM for
# Groups and activate just-in-time. Static is required because role-assignable
# groups cannot be dynamic.
# -----------------------------------------------------------------------------
resource "azuread_group" "priv_iam_admins" {
  display_name       = "Privileged-IAM-Admins"
  mail_nickname      = "privileged-iam-admins"
  description        = "PIM-for-Groups: eligible-only membership, no standing members [${var.tags_note}]"
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  # Membership is owned by PIM (eligibility schedules + activations), not by
  # Terraform. Without this, every activation would show up as drift.
  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# Admin-Accounts: the STANDING set of cloud-only admin accounts (every
# adm-first.last account plus the build account until it is converted). It
# holds NO role. It is the admin passkey profile's include target and the
# registration campaign's admin target in
# post-apply/Set-AuthenticationMethodsPolicy.ps1.
#
# Why not the PIM groups: a PIM-for-Groups group is eligible-only, so an
# adm- account is a member only DURING an activation - and it has to pass the
# phishing-resistant step-up (CA021 / CA002) BEFORE that activation starts.
# A passkey target on the PIM group would therefore never cover the person at
# the moment they need the key (registration or sign-in). Membership here is
# standing and independent of PIM.
#
# Why role-assignable: removing an account from this group removes its
# passkey target, which stops passkey sign-in - an admin lockout. Only
# Privileged Role Administrator / Global Administrator (and owners) can change
# a role-assignable group's membership, so a Groups or User Administrator
# cannot cause it. Role-assignable groups cannot be dynamic, so membership is
# ASSIGNED: post-apply/New-AdminAccounts.ps1 adds each adm- account it
# creates and the build account (operational data - Terraform ignores it).
# -----------------------------------------------------------------------------
resource "azuread_group" "admin_accounts" {
  display_name       = "Admin-Accounts"
  mail_nickname      = "admin-accounts"
  description        = "Standing cloud-only admin accounts (adm-*, build account): admin passkey profile + campaign target. Holds no role [${var.tags_note}]"
  security_enabled   = true
  mail_enabled       = false
  assignable_to_role = true

  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# Application / package access groups - ASSIGNED membership. These are the
# resources access packages hand out and the groups each enterprise app is
# assigned to (which in turn drives SAML access + SCIM provisioning).
# Membership is owned by entitlement management, so Terraform ignores it.
# -----------------------------------------------------------------------------
locals {
  app_access_groups = {
    servicenow = {
      display_name  = "App-ServiceNow-Users"
      mail_nickname = "app-servicenow-users"
      description   = "Grants ServiceNow access (SAML SSO + provisioning target)"
    }
    aws = {
      display_name  = "App-AWS-IdentityCenter-Users"
      mail_nickname = "app-aws-identitycenter-users"
      description   = "Grants AWS IAM Identity Center access (SAML + SCIM target)"
    }
    okta = {
      display_name  = "App-Okta-Federation-Users"
      mail_nickname = "app-okta-federation-users"
      description   = "Acquired-clinic users federated between Okta and Entra"
    }
    icu_critical_care = {
      display_name  = "App-ICU-CriticalCare-Users"
      mail_nickname = "app-icu-criticalcare-users"
      description   = "ICU critical-care app access (ICU access package resource)"
    }
    pharmacy_dispensing = {
      display_name  = "App-Pharmacy-Dispensing-Users"
      mail_nickname = "app-pharmacy-dispensing-users"
      description   = "Controlled-substance dispensing access (SoD pair with Nurse package)"
    }
  }
}

resource "azuread_group" "app_access" {
  for_each = local.app_access_groups

  display_name     = each.value.display_name
  mail_nickname    = each.value.mail_nickname
  description      = "${each.value.description} [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false

  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# CA005-Pilot-CompliantDevice: ASSIGNED pilot group for the device-compliance
# story. One group, three consumers:
#   * modules/conditional-access CA005 includes ONLY this group (compliant
#     device required for the admin portals) - never all admins, because the
#     operator administers from a personal Mac that will never be compliant;
#   * lab/scripts/intune/New-IntuneComplianceBaseline.ps1 assigns the Windows
#     compliance policy to it;
#   * modules/intune-vm grants it "Virtual Machine Administrator Login" on the
#     demo Windows 11 VM, so a pilot member can RDP in with Entra credentials
#     and the VM auto-enrolls into Intune under that user.
#
# Assigned (not dynamic) so pilot membership is a deliberate, auditable act.
# Membership is operational data referencing HR-provisioned people, so it is
# set post-apply by the script (-PilotMemberUserPrincipalNames), not here -
# Terraform ignores member drift.
#
# Licensing: plain security group (no P1 needed for the group itself); the
# PILOT USER needs Entra ID P1 (Conditional Access) + Intune (MDM enrollment)
# - both included in the Microsoft 365 E5 trial.
# -----------------------------------------------------------------------------
resource "azuread_group" "ca005_pilot" {
  display_name     = "CA005-Pilot-CompliantDevice"
  mail_nickname    = "ca005-pilot-compliantdevice"
  description      = "Pilot scope: CA005 compliant device for admin portals + Intune compliance baseline + Entra RDP to the demo VM [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false

  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# App-Consent-Reviewers (enable_nhi_governance): the people who answer the
# admin consent workflow. post-apply/Set-ConsentPolicy.ps1 restricts user
# consent (verified publishers, low-impact permissions only) and points the
# "Need admin approval" requests at this group by mailNickname.
#
# Why a group, not named users in the policy: membership is the review
# surface - the governance team adds/removes reviewers here, the quarterly
# privileged review can include it, and the consent policy never has to be
# re-written when people change jobs. Plain security group (NOT
# role-assignable): reviewing a request is not the same as granting it - only
# a Global Admin can approve Graph APPLICATION permissions (Learn, "admin
# consent workflow"), so membership does not confer a directory role.
# Membership is set post-apply (operational data), so Terraform ignores it.
# -----------------------------------------------------------------------------
resource "azuread_group" "app_consent_reviewers" {
  count = var.enable_nhi_governance ? 1 : 0

  display_name     = "App-Consent-Reviewers"
  mail_nickname    = "app-consent-reviewers"
  description      = "Reviewers for the admin consent workflow (Set-ConsentPolicy.ps1) [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false

  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# All-Workforce (enable_workforce_group): DYNAMIC group of every enabled,
# HR-synced member user - the staff passkey profile's target in
# post-apply/Set-AuthenticationMethodsPolicy.ps1 (-IncludeStaffRollout).
#
# Why this rule:
#   * dirSyncEnabled = true -> only people who came through HR -> AD -> Cloud
#     Sync. The break-glass pair is cloud-only, so it can NEVER fall into the
#     staff (synced-passkey) profile; Entra accepts a passkey that fits ANY
#     profile in scope, so "all users" there would weaken break-glass.
#   * userType = Member -> guests (B2B physicians) are excluded; their
#     authentication methods are their home tenant's business.
#   * accountEnabled = true -> leavers drop out the moment HR disables them
#     (same convention as All-Nurses / All-ICU above).
# verify: user.dirSyncEnabled is accepted in a membership rule (Learn lists it
# among the supported user properties) and evaluates true for Cloud Sync
# users, on the first tenant apply.
# -----------------------------------------------------------------------------
resource "azuread_group" "all_workforce" {
  count = var.enable_workforce_group ? 1 : 0

  display_name     = "All-Workforce"
  mail_nickname    = "all-workforce"
  description      = "Dynamic: enabled HR-synced member users - passkey rollout target (never break-glass, never guests) [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false
  types            = ["DynamicMembership"]

  dynamic_membership {
    enabled = true
    rule    = "(user.dirSyncEnabled -eq true) -and (user.userType -eq \"Member\") -and (user.accountEnabled -eq true)"
  }
}
