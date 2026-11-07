# =============================================================================
# okta :: clinic-apps.tf
# -----------------------------------------------------------------------------
# WHAT: the rest of the acquired clinic's Okta estate - the apps Phase 0
# inventories and Phase 2 moves, one wave at a time (lab/okta-migration/,
# lab/docs/okta-migration-runbook.md). With main.tf's bookmark this gives the
# clinic three apps, one of each kind a real Okta estate holds:
#
#   app                         protocol   assigned to      wave  in Okta
#   Clinic Scheduling (legacy)  bookmark   Clinic-Staff     2     main.tf
#   Clinic Lab Results          OIDC       Clinic-Staff     1     here (SPA, PKCE)
#   Clinic Billing              SAML 2.0   Clinic-Billing   2     here
#
# Plus the Okta admin work that goes with them:
#   * an AUTHENTICATION POLICY for the clinical apps ("Clinic clinical
#     apps"): clinic staff need two factors and re-authenticate after 8
#     hours (one shift); anyone else is DENIED by the policy's catch-all.
#     Entra's MFA counts as the two factors (the IdP's trustClaims, README
#     "Trust the Entra MFA"), so a clinic user is not asked twice;
#   * a GROUP RULE for billing (Clinic-Billing by department), the shape most
#     Okta estates use for role-based assignment;
#   * (admin_console_phishing_resistant, off) a rule that makes the Okta
#     Admin Console demand a phishing-resistant, device-bound factor.
#
# STAND-IN, SAID PLAINLY: in the lab no clinic estate pre-exists, so these
# apps are created here to stand in for it. Clinic Lab Results is a real
# OIDC app: lab/okta-migration/clinic-results/app.mjs runs on the workstation
# and signs people in through this Okta app (before the cut-over) or the
# Entra app (after). Clinic Billing is a SAML app whose service provider does
# not exist (billing.clinic.example): it is hidden from the dashboard so
# nobody clicks into a dead end, and it stays "inventoried" in the tracker.
#
# THE CUT-OVER SWITCHES (wave 1, Clinic Lab Results) live in the migration
# plan, lab/okta-migration/waves.json, so a cut-over is a reviewed change to
# the same file the tracker reads (not a gitignored tfvars value):
#   "cutover": true  -> the Okta app is HIDDEN from the Okta
#     dashboard but stays ACTIVE and assigned for one sign-in cycle (runbook
#     step 3: "keep the Okta app assigned but hidden"); the app itself now
#     trusts Entra (cutover.mjs switches its config).
#   "retired": true  -> the Okta app goes INACTIVE (step 6).
#   ROLLBACK = both false + the app's config back to Okta (cutover.mjs
#     rollback). Nothing is deleted until the retire PR removes the code.
# =============================================================================

locals {
  # The plan (owner, wave, switches) per app, keyed by the Okta label.
  waves = jsondecode(file("${path.module}/../../okta-migration/waves.json")).apps
  clinic_results = merge(
    { cutover = false, retired = false },
    { for k, v in lookup(local.waves, var.clinic_results_label, {}) : k => v if contains(["cutover", "retired"], k) },
    try(var.waves_override[var.clinic_results_label], {}),
  )
}

# ---- Groups and the billing group rule ---------------------------------------

resource "okta_group" "clinic_billing" {
  name        = var.clinic_billing_group_name
  description = "Acquired clinic billing team. Membership by group rule (department), never by Terraform. Assigned to Clinic Billing. Managed by Terraform - lab/terraform/okta."
}

# Role-based membership from the profile attribute HR owns. Today no clinic
# user carries the department (Entra-federated users are JIT-created with
# name and email only), so the rule matches 0 users - the inventory shows
# that, and it is why Clinic Billing is wave 2: its users come with the HR
# feed (runbook Phase 3), not with a login domain.
resource "okta_group_rule" "clinic_billing" {
  name              = "Clinic billing by department"
  status            = "ACTIVE"
  expression_type   = "urn:okta:expression:1.0"
  expression_value  = "user.department == \"${var.clinic_billing_department}\""
  group_assignments = [okta_group.clinic_billing.id]
}

# ---- The authentication policy for the clinical apps --------------------------

# catch_all = false: Okta sets the policy's catch-all rule to DENY (provider
# docs: applied at creation). So the ONLY way into an app on this policy is
# the rule below - a user outside the clinic groups is refused by Okta even
# if someone assigns them the app by mistake.
resource "okta_app_signon_policy" "clinical_apps" {
  name        = "Clinic clinical apps"
  description = "Clinic staff: two factors, re-authenticate after 8 hours (one shift). Everyone else: denied. Managed by Terraform - lab/terraform/okta."
  catch_all   = false
}

resource "okta_app_signon_policy_rule" "clinical_staff" {
  policy_id = okta_app_signon_policy.clinical_apps.id
  name      = "Clinic staff: two factors, re-auth every 8h"
  priority  = 1
  status    = "ACTIVE"
  access    = "ALLOW"

  groups_included = [okta_group.clinic_staff.id, okta_group.clinic_billing.id]

  # Two factors of different types; the IdP's trusted `amr` ["pwd","mfa"]
  # from Entra satisfies it (Okta docs: the `mfa` AMR satisfies "Any two
  # factors" with no further constraints). A phishing-resistant constraint
  # here would REFUSE clinic users today: their Entra MFA is an
  # authenticator-app code, which is not phishing-resistant. That step is
  # the passkey rollout's (runbook Phase 3), at Entra.
  factor_mode                 = "2FA"
  type                        = "ASSURANCE"
  re_authentication_frequency = "PT8H"
}

# ---- Wave 1: Clinic Lab Results (OIDC, native, PKCE) --------------------------

# A public client: authorization code + PKCE, no client secret, a loopback
# redirect (RFC 8252). Okta type "browser" (SPA), not "native": Okta lets a
# dashboard tile start the sign-in (login_mode SPEC) only for web and SPA
# apps (API error read live 2026-11-07: "Okta can only initiate the login
# for Web and SPA apps"), and the tile is how clinic staff opened the app.
# The Entra app that replaces it (modules/apps clinic_results.tf) is the
# same kind of client - public, PKCE, the SAME redirect - so the cut-over
# changes the IdP and nothing else.
resource "okta_app_oauth" "clinic_results" {
  label  = var.clinic_results_label
  type   = "browser"
  status = local.clinic_results.retired ? "INACTIVE" : "ACTIVE"

  grant_types                = ["authorization_code"]
  response_types             = ["code"]
  redirect_uris              = [var.clinic_results_redirect_uri]
  token_endpoint_auth_method = "none"
  pkce_required              = true
  issuer_mode                = "ORG_URL"

  # The dashboard tile starts the app's own sign-in (login_uri), the way a
  # user opened it before the move. Hidden at the cut-over, never deleted
  # until the retire PR.
  login_mode = "SPEC"
  login_uri  = var.clinic_results_login_uri
  hide_web   = local.clinic_results.cutover || local.clinic_results.retired
  hide_ios   = true

  authentication_policy = okta_app_signon_policy.clinical_apps.id

  lifecycle {
    precondition {
      condition     = !local.clinic_results.retired || local.clinic_results.cutover
      error_message = "waves.json: retired = true needs cutover = true first: retire only an app that has already moved (runbook step 6 after step 3)."
    }
  }
}

resource "okta_app_group_assignment" "clinic_results_staff" {
  app_id   = okta_app_oauth.clinic_results.id
  group_id = okta_group.clinic_staff.id
}

# ---- Wave 2: Clinic Billing (SAML 2.0) -----------------------------------------

resource "okta_app_saml" "clinic_billing" {
  label  = var.clinic_billing_label
  status = "ACTIVE"

  sso_url     = var.clinic_billing_acs_url
  recipient   = var.clinic_billing_acs_url
  destination = var.clinic_billing_acs_url
  audience    = var.clinic_billing_entity_id

  subject_name_id_template = "$${user.userName}"
  subject_name_id_format   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

  response_signed         = true
  assertion_signed        = true
  signature_algorithm     = "RSA_SHA256"
  digest_algorithm        = "SHA256"
  honor_force_authn       = true
  authn_context_class_ref = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  # What the migration has to reproduce in Entra's claims mapping (wave 2):
  # the inventory lists these statements per app.
  attribute_statements {
    type      = "EXPRESSION"
    name      = "department"
    namespace = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    values    = ["user.department"]
  }

  # The service provider does not exist in the lab: hidden, so no one opens
  # a dead link from the dashboard. Assigned anyway, because the assignment
  # is what the inventory and the migration read.
  hide_web = true
  hide_ios = true

  authentication_policy = okta_app_signon_policy.clinical_apps.id
}

resource "okta_app_group_assignment" "clinic_billing_team" {
  app_id   = okta_app_saml.clinic_billing.id
  group_id = okta_group.clinic_billing.id
}

# ---- Phishing-resistant factor for the Okta Admin Console (flag, off) ----------

# Read live 2026-11-07: the Admin Console's own rule asks for a password plus
# ANY second factor, which is WEAKER than this org's default policy (its
# catch-all demands a phishing-resistant, device-bound possession factor).
# The super admin already has Okta Verify FastPass (signed_nonce) enrolled,
# so the console can demand phishing resistance without a new enrolment.
# Off by default and not applied: turning it on changes how the OWNER signs
# in to the Okta Admin Console (FastPass on the device they use), so it is
# the owner's switch. The rollback does not need the console: the API token
# still works, and admin_console_phishing_resistant = false + apply removes
# the rule.
# The console's app id (okta_admin_console_app_id, from the inventory or
# Applications > Okta Admin Console) names its policy; the precondition
# below refuses the flag without it.
data "okta_app_signon_policy" "admin_console" {
  count  = var.admin_console_phishing_resistant ? 1 : 0
  app_id = var.okta_admin_console_app_id
}

resource "okta_app_signon_policy_rule" "admin_console_phishing_resistant" {
  count = var.admin_console_phishing_resistant ? 1 : 0

  policy_id = data.okta_app_signon_policy.admin_console[0].id
  name      = "Admins: phishing-resistant, device-bound"
  # Before the console's existing "Admin App Policy" rule (priority 0 today,
  # matches everyone): Okta shifts the others down. verify: on first apply,
  # the read-back shows this rule first.
  priority = 0
  status   = "ACTIVE"
  access   = "ALLOW"

  factor_mode                 = "2FA"
  type                        = "ASSURANCE"
  re_authentication_frequency = "PT0S" # every sign-in to the console
  constraints = [jsonencode({
    possession = {
      required          = true
      deviceBound       = "REQUIRED"
      phishingResistant = "REQUIRED"
      userPresence      = "REQUIRED"
    }
  })]

  lifecycle {
    precondition {
      condition     = can(regex("^0oa[A-Za-z0-9]{17}$", var.okta_admin_console_app_id))
      error_message = "admin_console_phishing_resistant = true needs okta_admin_console_app_id (the Okta Admin Console's app id, 0oa...; inventory.json lists it)."
    }
  }
}
