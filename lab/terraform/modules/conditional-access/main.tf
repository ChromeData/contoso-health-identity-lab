# =============================================================================
# modules/conditional-access :: main.tf
# -----------------------------------------------------------------------------
# Conditional Access as code: up to fourteen policies, the authentication
# strengths they require, and a country-based named location. The
# Break-Glass-Admins group is excluded from every policy.
#
# Numbering follows lab/docs/standards/conditional-access-design-principles.md
# section 4: 001-019 baseline (all users), 020-039 admins and privileged
# access, 060-079 clinical and device. CA001-CA008 predate the ranges.
# Numbers are permanent and never reused.
#
#   CA001  Require MFA for all users
#   CA002  Require phishing-resistant MFA for admins (roles + admin groups)
#   CA003  Block legacy authentication
#   CA004  Block sign-in from blocked countries
#   CA005  Require an Intune-COMPLIANT device for admin portals (PILOT group only)
#   --- behind staging flags (default off) --------------------------------
#   CA006  User risk High -> secure password change      [enable_identity_protection_ca]
#   CA007  Sign-in risk High -> block                    [enable_identity_protection_ca]
#   CA008  Phishing-resistant strength, workforce rollout [enable_phishing_resistant_all_users]
#   CA009  Register security info -> TAP or phishing-     [enable_registration_ca]     baseline.tf
#          resistant ("bootstrap and recovery") strength
#   CA010  Block device code flow                        [enable_device_code_block]   baseline.tf
#   CA011  RESERVED - token-protection pilot. Graph-managed by
#          post-apply/Set-TokenProtectionPolicy.ps1 (azuread 3.10 cannot express
#          secureSignInSession); NOT a policy_states key and never a resource
#          here. The script finds it by the "CA011 - " prefix and refuses to
#          touch a CA011 that is not its own.
#   CA020  Admin portals: sign-in every 4 h, Tier-0/1     [enable_admin_session_controls] admins.tf
#   CA021  PIM activation step-up on auth context c1     [enable_pim_auth_context]    admins.tf
#          (Graph-managed: Terraform RENDERS it, post-apply/Set-AuthContextPolicies.ps1 writes it)
#   CA022  PAM session broker + admin portals -> ADMIN    [enable_pam_session_ca]      admins.tf
#          (phishing-resistant, attested-key) strength    (was numbered CA009 before the ranges)
#   CA023  Protected actions (CA policy / named-location   [enable_protected_actions_ca] admins.tf
#          update + delete) step-up on auth context c2
#          (Graph-managed like CA021)
#   CA060  Shared clinical workstations: phishing-        [enable_shared_clinical_ca]  clinical.tf
#          resistant strength, 8 h sign-in, no persistent browser
#
# LICENSING: Conditional Access requires Entra ID P1 for every user in scope;
# custom authentication strengths need P1. CA006/CA007's user/sign-in RISK
# conditions need Entra ID P2 (ID Protection) - in the Microsoft 365 E5 trial.
# CA005's grant control can only be satisfied by a device that is enrolled in
# Microsoft Intune and marked compliant - Intune Plan 1 + Entra ID P2 both come
# with the E5 (trial) licence the pilot user must hold. See README.
#
# WHY RISK LIVES HERE (and not in ID Protection): the legacy user-risk and
# sign-in-risk policies configured inside Entra ID Protection were retired on
# October 1, 2026 (Microsoft Learn, "Risk-based access policies") with no
# automatic conversion. Risk-based access is now Conditional Access only -
# which also buys report-only mode, Graph/Terraform management and one place
# to read every access rule.
#
# SAFETY: every policy excludes break-glass, and every policy starts in
# REPORT-ONLY (var.policy_states). Review the sign-in logs' Report-only tab,
# then graduate ONE policy per PR. Enforce CA002 only after every admin who
# can hold an in-scope role has a registered passkey / FIDO2 / WHfB method -
# otherwise the first activation locks that admin out. CA005 targets a PILOT
# group, never "all admins" - see the CA005 block for why. CA008 cannot be
# enforced tenant-wide by a single state flip - see the CA008 block. CA010
# breaks the operator's own device-code sign-ins once enforced, CA060 needs
# Clinical Operations sign-off, and CA021 must be enforced IN THE TENANT
# before modules/pim requires its context (output
# pim_activation_auth_context_ready gates it on the declared state AND the
# ca021_enforced_in_tenant attestation).
#
# WORKLOAD IDENTITIES ARE NOT USERS: the GitHub-OIDC pipeline identities
# (modules/pipeline-identity), the Key Vault UAMI and every other service
# principal are outside user-scoped Conditional Access - "All users" never
# includes them, so there is nothing to exclude. Risk-based CA for service
# principals is a separate product (Workload Identities Premium) and is out
# of scope for this lab.
# =============================================================================

locals {
  # Every external/guest user type Graph knows. CA006 and CA008 exclude them
  # all (reasons at each policy); CA007 deliberately does not.
  guest_or_external_user_types = [
    "internalGuest",
    "b2bCollaborationGuest",
    "b2bCollaborationMember",
    "b2bDirectConnectUser",
    "otherExternalUser",
    "serviceProvider",
  ]

  # Flagged policies read their state with lookup(): the key is only REQUIRED
  # while the policy exists, and that is enforced by a precondition with a
  # readable message rather than an "Invalid index" crash. The fallback value
  # is never applied - the precondition fails the plan first.
  ca006_state = lookup(var.policy_states, "CA006", "enabledForReportingButNotEnforced")
  ca007_state = lookup(var.policy_states, "CA007", "enabledForReportingButNotEnforced")
  ca008_state = lookup(var.policy_states, "CA008", "enabledForReportingButNotEnforced")

  # Report the CA007 levels in a fixed low->high order so the display name is
  # stable whatever order the caller lists them in.
  ca007_levels = [for l in ["low", "medium", "high"] : l if contains(var.sign_in_risk_block_levels, l)]

  # CA008 display-name parts (see the policy).
  ca008_scope_label = var.ca008_scope == "pilot" ? "pilot group" : "all users"
  ca008_state_label = lookup({
    enabled                           = "enforced"
    enabledForReportingButNotEnforced = "report-only"
    disabled                          = "disabled"
  }, local.ca008_state, local.ca008_state)

  ca009_state = lookup(var.policy_states, "CA009", "enabledForReportingButNotEnforced")
  ca010_state = lookup(var.policy_states, "CA010", "enabledForReportingButNotEnforced")
  ca020_state = lookup(var.policy_states, "CA020", "enabledForReportingButNotEnforced")
  ca021_state = lookup(var.policy_states, "CA021", "enabledForReportingButNotEnforced")
  ca022_state = lookup(var.policy_states, "CA022", "enabledForReportingButNotEnforced")
  ca023_state = lookup(var.policy_states, "CA023", "enabledForReportingButNotEnforced")
  ca060_state = lookup(var.policy_states, "CA060", "enabledForReportingButNotEnforced")

  # Admin groups CA002 and CA020 include next to the role condition (see
  # var.admin_scope_group_object_ids). null = leave included_groups unset,
  # the same shape the portal writes when no group is chosen.
  admin_scope_group_ids = length(var.admin_scope_group_object_ids) > 0 ? values(var.admin_scope_group_object_ids) : null

  # CA008 pilot: a caller-supplied group wins; otherwise the module's own.
  # null and "" both mean "not supplied" (roots often default ids to "").
  ca008_pilot_supplied = var.ca008_pilot_group_object_id == null ? false : var.ca008_pilot_group_object_id != ""
  ca008_pilot_group_object_id = (
    local.ca008_pilot_supplied ? var.ca008_pilot_group_object_id : one(azuread_group.ca008_pilot[*].object_id)
  )
}

# -----------------------------------------------------------------------------
# Custom authentication strength: the phishing-resistant method set.
# (You may instead reference the BUILT-IN "Phishing-resistant MFA" strength,
# whose fixed id is 00000000-0000-0000-0000-000000000004, via a variable.
# A custom strength is created here so the lab is self-contained and the
# allowed combinations are explicit/auditable.)
# -----------------------------------------------------------------------------
resource "azuread_authentication_strength_policy" "phishing_resistant" {
  display_name         = "Phishing-Resistant MFA (lab)"
  description          = "FIDO2 / Windows Hello / certificate-based MFA only"
  allowed_combinations = var.phishing_resistant_combinations
}

# -----------------------------------------------------------------------------
# OPTIONAL: narrow the admin strength's "fido2" combination to issued key
# models (AAGUIDs). Off unless admin_fido2_allowed_aaguids is set. Takes the
# strength's bare object_id (GUID), not the path-form .id - the provider's
# documented usage. Only meaningful once the Passkey (FIDO2) methods policy
# enforces attestation (see the variable). Needs Policy.ReadWrite.ConditionalAccess
# + Policy.Read.All (provider docs) - the apply identity already holds both.
# -----------------------------------------------------------------------------
resource "azuread_authentication_strength_policy_fido2_combination_configuration" "admin_device_bound" {
  count = length(var.admin_fido2_allowed_aaguids) > 0 ? 1 : 0

  authentication_strength_policy_id = azuread_authentication_strength_policy.phishing_resistant.object_id
  allowed_aaguids                   = var.admin_fido2_allowed_aaguids

  lifecycle {
    # Graph rejects a fido2 combination configuration on a strength that does
    # not allow fido2; fail at plan with the reason instead of mid-apply.
    precondition {
      condition     = contains(var.phishing_resistant_combinations, "fido2")
      error_message = "admin_fido2_allowed_aaguids needs \"fido2\" in phishing_resistant_combinations."
    }
  }
}

# -----------------------------------------------------------------------------
# Named location: blocked countries/regions.
# -----------------------------------------------------------------------------
resource "azuread_named_location" "blocked_countries" {
  display_name = var.blocked_named_location_name

  country {
    countries_and_regions                 = var.blocked_countries
    include_unknown_countries_and_regions = var.include_unknown_countries
  }
}

# -----------------------------------------------------------------------------
# CA001 - Require MFA for all users.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "require_mfa_all_users" {
  display_name = "${var.policy_name_prefix}001 - Require MFA for all users"
  state        = var.policy_states["CA001"]

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# -----------------------------------------------------------------------------
# CA002 - Require phishing-resistant MFA for admin roles.
# Uses the custom authentication strength instead of the generic "mfa" control.
# built_in_controls is intentionally empty: the auth strength IS the control.
#
# WHO: the union of two includes.
#   * included_roles - Microsoft's "Require phishing-resistant MFA for
#     administrators" template role list plus the lab's tier extras
#     (var.admin_role_template_ids). Learn: the role condition matches users
#     ACTIVELY assigned a role - an eligible user is caught once they activate.
#   * included_groups - the PIM tier groups and the help-desk AU group
#     (var.admin_scope_group_object_ids). Two reasons, both from Learn's
#     users-and-groups page: role assignments scoped to an ADMINISTRATIVE UNIT
#     (and custom roles) are NOT evaluated by the role condition, so an
#     AU-scoped help-desk admin would otherwise be outside CA002; and it is
#     unverified whether a role held through an activated role-assignable
#     group is matched (verify: first tenant run, sign-in log of an activated
#     PIM-Tier1-Helpdesk member). The PIM-for-Groups groups hold no standing
#     members, so from them the include adds only the activated person. ONE
#     EXCEPTION in envs/dev: PIM-Azure-RG-Contributors has STANDING members by
#     design (the group, not the person, is eligible for Contributor on the
#     DC's resource group), so every member is in scope at every sign-in -
#     each must be an adm- account with an issued passkey before CA002 is
#     enforced (it is an admin passkey target; check with
#     07-Passwordless-Rollout.ps1 -PilotGroupMailNicknames pim-azure-rg-contributors).
#
# LOCKOUT SCOPE: every role or group added here widens who is locked out once
# CA002 is enforced. Each holder needs a registered phishing-resistant method
# first (ADR 0003, CA design principles section 2).
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "admin_phishing_resistant" {
  display_name = "${var.policy_name_prefix}002 - Require phishing-resistant MFA for admins"
  state        = var.policy_states["CA002"]

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      # Target by directory role so the policy follows the role, not a static list.
      included_roles  = var.admin_role_template_ids
      included_groups = local.admin_scope_group_ids
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = []
    authentication_strength_policy_id = azuread_authentication_strength_policy.phishing_resistant.id
  }
}

# -----------------------------------------------------------------------------
# CA003 - Block legacy authentication.
# Legacy auth = protocols that cannot do modern auth / MFA. Targeting the
# exchangeActiveSync + other client app types and blocking is the canonical
# way to kill legacy auth.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "${var.policy_name_prefix}003 - Block legacy authentication"
  state        = var.policy_states["CA003"]

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# -----------------------------------------------------------------------------
# CA004 - Block sign-in from blocked countries (named location).
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "block_countries" {
  display_name = "${var.policy_name_prefix}004 - Block sign-in from blocked countries"
  state        = var.policy_states["CA004"]

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_object_id]
    }

    locations {
      # object_id (bare GUID), NOT .id: in azuread 3.x .id is the path form
      # "/identity/conditionalAccess/namedLocations/<guid>", which Graph rejects.
      included_locations = [azuread_named_location.blocked_countries.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# -----------------------------------------------------------------------------
# CA005 - Require a COMPLIANT device for the admin portals (pilot group only).
#
# What it protects: the places an admin changes the tenant from -
#   * "MicrosoftAdminPortals" - the Graph keyword for Microsoft's admin-portal
#     grouping (Azure portal, Exchange admin center, Microsoft 365 admin
#     center, Security & Compliance center). Documented as a valid
#     includeApplications value on conditionalAccessApplications (Graph v1.0);
#     the azuread provider passes any non-empty string through unvalidated.
#     verify: Graph accepting the keyword together with an app id in one
#     includeApplications list (the portal picker offers both side by side;
#     not exercised against a live tenant).
#   * 797f4846-ba00-4fd7-ba43-dac1f8f63013 - "Windows Azure Service Management
#     API" (Azure Resource Manager + portal, and therefore Azure CLI / Azure
#     PowerShell). NOT Microsoft Graph PowerShell - that is a different resource.
#
# Grant: compliantDevice = the device must be Intune-enrolled AND marked
# compliant by an Intune compliance policy. The demo device is the Windows 11
# VM in modules/intune-vm (Entra joined + auto-enrolled); the compliance
# policy is lab/scripts/intune/New-IntuneComplianceBaseline.ps1.
#
# WHY A PILOT GROUP AND NOT "ALL ADMINS": the operator administers this lab
# from a personal Mac that is not (and will never be) Intune-enrolled. Scoping
# CA005 to every admin role would - once enforced - lock the operator out of
# the Azure portal AND break `az`/Azure PowerShell from that Mac. The pilot
# group (CA005-Pilot-CompliantDevice, modules/groups) holds a test identity
# that signs in to the compliant VM; production would widen the include to the
# admin roles once every admin has a compliant privileged-access workstation.
#
# NOT AFFECTED: the CI pipeline identities (workload identities are outside
# user-scoped CA), break-glass (excluded), and RDP sign-in to the VM itself
# (that is the "Microsoft Remote Desktop" / "Azure Windows VM Sign-In"
# resources, which are not included here).
#
# REPORT-ONLY CAVEAT (Microsoft-documented): a report-only policy that checks
# device compliance can prompt users on macOS / iOS / Android to pick a device
# certificate during evaluation. Because only the pilot identity is in scope,
# that prompt can only appear for the pilot account - never for the operator's
# everyday admin account.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "admin_portals_compliant_device" {
  display_name = "${var.policy_name_prefix}005 - Require compliant device for admin portals (pilot)"
  state        = var.policy_states["CA005"]

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = var.admin_portal_applications
    }

    users {
      # Pilot group ONLY (see header). Never "All" and never admin roles here.
      included_groups = [var.ca005_pilot_group_object_id]
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["compliantDevice"]
  }
}

# =============================================================================
# RISK-BASED POLICIES (Entra ID P2) - enable_identity_protection_ca
# =============================================================================

# -----------------------------------------------------------------------------
# CA006 - User risk HIGH -> secure password change (self-remediation).
#
# User risk = "this ACCOUNT is probably compromised" (leaked credentials,
# password spray, anomalous token, an admin's "confirm compromised").
# The response is to let the real user prove themselves with MFA and rotate
# the secret, which closes the risk WITHOUT a helpdesk ticket.
#
# Grant shape (Graph v1.0 conditionalAccessGrantControls, Microsoft Learn):
#   * "passwordChange" must be paired with "mfa" using AND;
#   * the policy must target ALL applications (no exclusions);
#   * the policy may carry no condition other than users, applications and
#     userRiskLevels - hence no location/platform/device blocks here;
#   * Microsoft's template adds Sign-in frequency = Every time, so the
#     remediating sign-in is a fresh one, not a replayed session.
#
# WHY NOT "Require risk remediation" (the newer grant): it is the better
# control - ID Protection picks the flow per user, so passwordless users get
# session revocation + re-sign-in instead of a password they never use. The
# azuread provider cannot express it: azuread 3.10.0 (latest, Sept 2026)
# rejects "riskRemediation" in built_in_controls at validate time (checked
# offline). Graph v1.0 already lists it (evolvable enum, needs the
# `Prefer: include-unknown-enum-members` header to read back). Upgrade path
# when the provider supports it: built_in_controls = ["riskRemediation"] +
# authentication_strength_policy_id (Graph requires it with AND), and drop
# "mfa"/"passwordChange" - the two controls must never be combined.
# Passwordless users are still covered today: a passkey satisfies "mfa", then
# the secure password change completes remediation (more friction, same
# outcome).
#
# MICROSOFT-MANAGED POLICY: Microsoft is rolling a managed "Require risk
# remediation for high-risk users" policy into P2 tenants (report-only first,
# then On unless an admin sets its state - verify: message-center MC1507808
# wording and dates in the trial tenant). Precedence (Microsoft Learn):
# riskRemediation beats passwordChange and Block beats both, and Microsoft
# advises one user-risk policy per user. Tenant-time decision: set the managed
# policy to report-only/Off by hand so CA006 is the single, version-controlled
# user-risk policy while evidence is captured.
#
# EXCLUSIONS: break-glass (always); every guest/external user type, because
# their credential lives in the home tenant - a resource tenant cannot make
# them change it (and "Require risk remediation" is documented as unsupported
# for guests). Risky GUEST sign-ins are still blocked by CA007.
#
# PREREQUISITES before "enabled": users must already be MFA-registered (an
# unregistered high-risk user is simply blocked), and hybrid users need
# password WRITEBACK (Cloud Sync) or their cloud-side change cannot land
# on-prem - verify: Cloud Sync writeback configured in the trial tenant.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "user_risk_high_remediation" {
  count = var.enable_identity_protection_ca ? 1 : 0

  # The name says what the grant DOES (mfa + passwordChange); "passwordless
  # remediation" would need riskRemediation, which azuread 3.10 cannot set
  # (above) - the name changes when the grant does.
  display_name = "${var.policy_name_prefix}006 - User risk high - require MFA + secure password change"
  state        = local.ca006_state

  conditions {
    client_app_types = ["all"]
    user_risk_levels = ["high"]

    applications {
      included_applications = ["All"] # Graph requirement for passwordChange
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_object_id]

      excluded_guests_or_external_users {
        guest_or_external_user_types = local.guest_or_external_user_types
        external_tenants {
          membership_kind = "all"
        }
      }
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }

  # verify: first real plan/apply - the provider's plan-time checks on an
  # "everyTime" frequency (no period/value) are not exercised by mocked tests.
  session_controls {
    sign_in_frequency_interval            = "everyTime"
    sign_in_frequency_authentication_type = "primaryAndSecondaryAuthentication"
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA006")
      error_message = "enable_identity_protection_ca = true requires an explicit CA006 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }
  }
}

# -----------------------------------------------------------------------------
# CA007 - Sign-in risk HIGH -> block.
#
# Sign-in risk = "THIS sign-in is probably not the account owner" (anonymous
# IP, unfamiliar properties, impossible travel, token anomalies), scored in
# real time. Microsoft's template answers Medium+ with MFA; this lab BLOCKS at
# High only (ADR: High is where false positives are rare enough that a hard
# block beats a challenge an attacker who already phished or fatigued the MFA
# factor could pass). A blocked sign-in needs no self-remediation: the user's
# next ordinary sign-in is scored afresh, repeated risky sign-ins raise USER
# risk (CA006's job), and the SOC triages the risky sign-in in ID Protection
# (confirm safe / confirm compromised).
#
# Guests are INCLUDED: blocking a risky sign-in needs no remediation by the
# guest, so there is no reason to carve them out.
#
# Simulation (tenant time, Microsoft Learn "Simulate risk detections"): sign
# in to myapps.microsoft.com through the Tor Browser with a test account. The
# detection appears in 10-15 min. Its level is not guaranteed to be High -
# see var.sign_in_risk_block_levels for the report-only test knob.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "sign_in_risk_block" {
  count = var.enable_identity_protection_ca ? 1 : 0

  display_name = "${var.policy_name_prefix}007 - Sign-in risk ${join("+", local.ca007_levels)} - block"
  state        = local.ca007_state

  conditions {
    client_app_types    = ["all"]
    sign_in_risk_levels = local.ca007_levels

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [var.break_glass_group_object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA007")
      error_message = "enable_identity_protection_ca = true requires an explicit CA007 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }
  }
}

# =============================================================================
# PHISHING-RESISTANT FOR THE WORKFORCE - enable_phishing_resistant_all_users
# =============================================================================

# -----------------------------------------------------------------------------
# Workforce authentication strength. Same methods as the admin strength by
# default, but its own object so CA002 can be narrowed to issued, attested
# keys (admin_fido2_allowed_aaguids) without breaking staff on synced passkeys.
# (Microsoft's built-in "Phishing-resistant MFA" strength,
# 00000000-0000-0000-0000-000000000004, would also work; a custom one keeps
# the allowed set explicit and diffable.)
# -----------------------------------------------------------------------------
resource "azuread_authentication_strength_policy" "phishing_resistant_workforce" {
  count = var.enable_phishing_resistant_all_users ? 1 : 0

  display_name         = "Phishing-Resistant MFA - Workforce (lab)"
  description          = "Passkeys (device-bound or synced) / Windows Hello / certificate-based MFA - workforce rollout strength used by CA008"
  allowed_combinations = var.workforce_phishing_resistant_combinations

  lifecycle {
    # The workforce rollout lets HR-synced users - admins included - register
    # SYNCED passkeys (Set-AuthenticationMethodsPolicy.ps1 -IncludeStaffRollout,
    # All-Workforce). Passkey profiles are "any profile in scope satisfies",
    # so the ONLY thing keeping an unattested synced passkey off the admin
    # roles is the AAGUID allow-list on the ADMIN strength. Without it, this
    # rollout quietly lowers admin assurance to "any synced passkey". So the
    # rollout needs that list - or an explicit, reviewed risk acceptance.
    precondition {
      condition     = length(var.admin_fido2_allowed_aaguids) > 0 || var.accept_admin_synced_passkey_risk
      error_message = "enable_phishing_resistant_all_users opens synced passkeys to every HR-synced user, admins included; set admin_fido2_allowed_aaguids (the issued security-key models) so CA002 / CA022 still demand a device-bound key - or set accept_admin_synced_passkey_risk = true in its own reviewed line."
    }
  }
}

# -----------------------------------------------------------------------------
# CA008-Pilot-PhishingResistant: ASSIGNED pilot group for CA008 enforcement.
# Lives in this module (not modules/groups) because CA008 is its only
# Terraform consumer. Membership is operational - who has registered a
# passkey this week - so it is set post-apply (registration campaign /
# runbook), never here: Terraform ignores member drift, like CA005's pilot.
# Look it up by mail_nickname, the lab's stable natural key for groups.
# -----------------------------------------------------------------------------
resource "azuread_group" "ca008_pilot" {
  count = var.enable_phishing_resistant_all_users && !local.ca008_pilot_supplied ? 1 : 0

  display_name     = "CA008-Pilot-PhishingResistant"
  mail_nickname    = "ca008-pilot-phishingresistant"
  description      = "Pilot scope: CA008 phishing-resistant sign-in enforcement wave [${var.tags_note}]"
  security_enabled = true
  mail_enabled     = false

  lifecycle {
    ignore_changes = [members]
  }
}

# -----------------------------------------------------------------------------
# CA008 - Phishing-resistant authentication strength for the workforce.
#
# Rollout this policy is built for (one PR per step):
#   1. MEASURE  - state report-only, ca008_scope "all_users" (defaults). The
#                 Report-only tab / CA insights workbook then counts every
#                 sign-in that would FAIL for lack of a phishing-resistant
#                 method: the registration gap, per user.
#   2. REGISTER - passkey registration campaign; joiners bootstrap with the
#                 Temporary Access Pass the joiner flow already issues.
#   3. PILOT    - ca008_scope "pilot" + state "enabled". Only the pilot group
#                 is enforced; widen by adding members, not by editing policy.
#   4. ALL      - ca008_scope "all_users" + state "enabled" +
#                 ca008_allow_all_users_enforcement = true. The precondition
#                 below refuses step 4 without that third, separate line.
#
# EXCLUSIONS: break-glass (always - its FIDO2 keys are in a safe, but a
# lockout policy must never be able to touch it); every guest/external user
# type, because a guest can satisfy a phishing-resistant strength ONLY from
# their home tenant through inbound MFA trust (cross-tenant access settings) -
# a resource tenant cannot register passkeys/WHfB/CBA for them (Microsoft
# Learn, authentication strengths for external users). Guest strength is the
# B2B governance workstream's policy, not this one.
#
# Admins are in scope too; they also meet CA002. When both apply the user
# must satisfy both strengths - one issued security key satisfies both.
#
# verify: (tenant time) a pilot joiner holding only a TAP, under ENFORCED
# CA008, is routed to combined-registration interrupt mode and can register a
# passkey there (Learn says passkeys "can be ... enforced by an authentication
# strength via Interrupt mode"). Microsoft's documented "Bootstrap and
# recovery" pattern is built as CA009 (baseline.tf): in Interrupt mode a
# strength that targets the registration user action is preferred over
# strengths on All resources, so the joiner's TAP opens registration.
# -----------------------------------------------------------------------------
resource "azuread_conditional_access_policy" "phishing_resistant_all_users" {
  count = var.enable_phishing_resistant_all_users ? 1 : 0

  # The name follows the deployed scope and state (like CA007's levels), so a
  # sign-in log, screenshot or evidence script never shows an ENFORCED
  # policy still labelled "report-only pilot".
  display_name = "${var.policy_name_prefix}008 - Phishing-resistant authentication strength - ${local.ca008_scope_label} (${local.ca008_state_label})"
  state        = local.ca008_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      # Exactly one of the two includes is set; null leaves the other unset
      # (the same shape the portal writes).
      included_users  = var.ca008_scope == "all_users" ? ["All"] : null
      included_groups = var.ca008_scope == "pilot" ? [local.ca008_pilot_group_object_id] : null
      excluded_groups = [var.break_glass_group_object_id]

      excluded_guests_or_external_users {
        guest_or_external_user_types = local.guest_or_external_user_types
        external_tenants {
          membership_kind = "all"
        }
      }
    }
  }

  grant_controls {
    operator                          = "OR"
    built_in_controls                 = [] # the authentication strength IS the control
    authentication_strength_policy_id = azuread_authentication_strength_policy.phishing_resistant_workforce[0].id
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.policy_states), "CA008")
      error_message = "enable_phishing_resistant_all_users = true requires an explicit CA008 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
    }

    precondition {
      condition     = !(var.ca008_scope == "all_users" && local.ca008_state == "enabled") || var.ca008_allow_all_users_enforcement
      error_message = "CA008 enforced for ALL users needs ca008_allow_all_users_enforcement = true as well. Enforce the pilot first (ca008_scope = \"pilot\"), prove registration coverage, then flip the acknowledgement in its own reviewed line."
    }
  }
}
