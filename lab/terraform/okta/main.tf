# =============================================================================
# okta :: main.tf
# -----------------------------------------------------------------------------
# WHAT: the Okta half of "Okta trusts Entra" (runbook Phase 1, ADR 0022),
# plus the clinic's existing Okta estate that Phase 0 inventories - which, in
# the lab, this root has to create first, because no clinic org pre-exists:
#
#   ALWAYS (the clinic's estate, Phase 0):
#   * group Clinic-Staff and a group rule that puts every user whose login
#     is on clinic_login_domain into it (membership is the rule's, never
#     Terraform's: an HR-driven group's stand-in);
#   * one legacy app, "Clinic Scheduling (legacy)", a BOOKMARK app assigned
#     to Clinic-Staff and to nobody else. A bookmark, not SAML, on purpose:
#     it is the app that still does its own sign-in behind Okta, i.e. the
#     thing Phase 2 moves to an Entra app with real SSO; a SAML app would
#     need a service provider that does not exist in the lab.
#
#   WITH enable_entra_federation (Phase 1):
#   * the Microsoft Entra ID identity provider, generic OIDC (okta_idp_oidc,
#     protocol OIDC) against the tenant's v2.0 endpoints, authorization code
#     + client secret, scopes openid profile email; account link by EMAIL
#     (runbook: "Account link: match on email"), JIT on in the lab;
#   * ONE IdP discovery routing rule, priority 1: username SUFFIX =
#     clinic_login_domain -> that IdP. Okta's own Default Rule (route to
#     Okta) is system-managed - no provider resource creates or deletes it -
#     and stays BELOW this rule as the fallback, so anyone outside the
#     clinic domain, and every Okta-only user Phase 0 found, keeps signing
#     in to Okta exactly as before. The rule matches one domain suffix, never
#     "everyone": that is what keeps the fallback reachable.
#   * ROLLBACK = routing_rule_active = false (the rule goes INACTIVE, the IdP
#     stays). One variable, one apply, Okta passwords again.
#
# OWNERSHIP BOUNDARY: Entra (modules/apps okta.tf) decides WHO may federate:
# only App-Okta-Federation-Users gets a token from okta-clinic-idp. Okta
# (here) decides WHICH sign-ins are sent to Entra (the routing rule) and
# WHAT they reach (the app assignment). Users are never created by
# Terraform on either side: clinic staff arrive through HR -> AD -> Cloud
# Sync (runbook Phase 3), and Okta links them by email.
#
# INTEGRATOR FREE LIMITS (verify: current terms at apply time): a handful of
# users and apps, no custom domain, SSWS API tokens only, and the org is
# deactivated after a period of no admin sign-in. Everything here fits:
# 1 IdP, 1 rule, 1 group, 1 app. The runbook's Microsoft-type IdP (Okta's
# "Add -> Microsoft") is the social-IdP flavour of the same OIDC exchange;
# the generic OIDC IdP is used because its endpoints are explicit inputs,
# which is what makes it reviewable code (verify: both are available on
# Integrator Free).
#
# NOTHING HERE HAS RUN AGAINST AN OKTA ORG. Runtime claims not proven by
# Okta's documentation are marked "verify:".
# =============================================================================

locals {
  okta_org_domain = "${var.okta_org_name}.${var.okta_base_url}"

  # The callback Okta documents for an OIDC IdP: the one redirect URI on the
  # Entra app (modules/apps okta.tf). The README's cross-check compares the
  # two outputs.
  okta_callback_uri = "https://${local.okta_org_domain}/oauth2/v1/authorize/callback"

  # The tenant's v2.0 endpoints (the same values envs/dev prints as
  # okta_idp_endpoints; built here from the tenant id so a typo in a pasted
  # URL cannot point the IdP at another tenant).
  entra_authority = "https://login.microsoftonline.com/${var.entra_tenant_id}"
  entra_endpoints = {
    issuer_url        = "${local.entra_authority}/v2.0"
    authorization_url = "${local.entra_authority}/oauth2/v2.0/authorize"
    token_url         = "${local.entra_authority}/oauth2/v2.0/token"
    jwks_url          = "${local.entra_authority}/discovery/v2.0/keys"
    user_info_url     = "https://graph.microsoft.com/oidc/userinfo"
  }

  federation_enabled = var.enable_entra_federation
}

# =============================================================================
# The clinic's Okta estate (always planned)
# =============================================================================

resource "okta_group" "clinic_staff" {
  name        = var.clinic_staff_group_name
  description = "Acquired clinic workforce (login domain ${var.clinic_login_domain}). Membership by group rule; assigned to the clinic's legacy apps. Managed by Terraform - lab/terraform/okta."
}

# Membership from the login domain, so clinic users land in the group
# whether they pre-existed in Okta or arrive by JIT through Entra. Okta EL:
# String.substringAfter (Okta Expression Language reference). verify: the
# expression evaluates as expected for the lab's logins on first run.
resource "okta_group_rule" "clinic_staff" {
  name              = "Clinic staff by login domain"
  status            = "ACTIVE"
  expression_type   = "urn:okta:expression:1.0"
  expression_value  = "String.substringAfter(user.login, \"@\") == \"${var.clinic_login_domain}\""
  group_assignments = [okta_group.clinic_staff.id]
}

resource "okta_app_bookmark" "clinic_scheduling" {
  label  = var.legacy_app_label
  url    = var.legacy_app_url
  status = "ACTIVE"

  # Visible on the clinic users' Okta dashboard until Phase 2 moves it.
  hide_web                   = false
  hide_ios                   = false
  accessibility_self_service = false
  request_integration        = false

  admin_note   = "Runbook Phase 0 inventory: the one legacy app still reached through Okta. Phase 2 moves it to an Entra app; keep it assigned but hidden for one sign-in cycle, then deactivate. Managed by Terraform - lab/terraform/okta."
  enduser_note = "Clinic scheduling (legacy). Opens the scheduling system; it signs you in separately."
}

# The ONE assignment: Clinic-Staff. Not a list, as for every app assignment
# in this lab: a second principal is a design change a reviewer should see.
resource "okta_app_group_assignment" "clinic_scheduling_staff" {
  app_id   = okta_app_bookmark.clinic_scheduling.id
  group_id = okta_group.clinic_staff.id
}

# =============================================================================
# Phase 1: Okta trusts Entra (enable_entra_federation)
# =============================================================================

# The preconditions fail the PLAN, before anything is created, when the flag
# is on without the three values only the Entra apply (and a human) can
# supply: an IdP with a missing secret or a wrong client id would not sign
# anyone in, it would only lock the clinic domain out.
resource "okta_idp_oidc" "entra" {
  count = local.federation_enabled ? 1 : 0

  name   = var.entra_idp_name
  status = "ACTIVE"

  protocol_type = "OIDC"
  scopes        = ["openid", "profile", "email"]

  client_id     = var.entra_client_id
  client_secret = var.entra_client_secret

  issuer_url            = local.entra_endpoints.issuer_url
  authorization_url     = local.entra_endpoints.authorization_url
  authorization_binding = "HTTP-REDIRECT"
  token_url             = local.entra_endpoints.token_url
  token_binding         = "HTTP-POST"
  jwks_url              = local.entra_endpoints.jwks_url
  jwks_binding          = "HTTP-REDIRECT"
  user_info_url         = local.entra_endpoints.user_info_url
  user_info_binding     = "HTTP-REDIRECT"

  # Okta identifies itself to Entra by the org URL, which is the host of the
  # callback registered on the Entra app. A custom domain would be
  # CUSTOM_URL and a different callback: a design change on both sides.
  issuer_mode = "ORG_URL"

  # Account linking by email (runbook): the Entra `email` claim is matched to
  # the Okta username (username_template idpuser.email, the provider default).
  subject_match_type  = "EMAIL"
  username_template   = "idpuser.email"
  account_link_action = "AUTO"

  # JIT in the lab; [prod] pre-linked accounts only (variable jit_provisioning).
  provisioning_action = var.jit_provisioning ? "AUTO" : "DISABLED"

  # Group memberships stay Okta's (the group rule above), never copied from
  # the IdP; a suspended or deprovisioned Okta user is not revived by a
  # successful Entra sign-in - the leaver flow decides, not the IdP.
  groups_action        = "NONE"
  suspended_action     = "NONE"
  deprovisioned_action = "NONE"

  # verify: on the first sign-in, that Entra accepts Okta's authorization
  # request as sent (the provider's defaults for the request-signature
  # settings; Entra does not accept signed request objects, so if the
  # exchange fails on the authorize call, set request_signature_scope =
  # "NONE" here).

  lifecycle {
    precondition {
      condition     = var.entra_tenant_id != ""
      error_message = "enable_entra_federation = true needs entra_tenant_id (envs/dev output okta_idp_endpoints names the tenant): every IdP endpoint is built from it."
    }
    precondition {
      condition     = var.entra_client_id != ""
      error_message = "enable_entra_federation = true needs entra_client_id (envs/dev output okta_idp_client_id, the okta-clinic-idp app registration)."
    }
    precondition {
      condition     = nonsensitive(var.entra_client_secret != "")
      error_message = "enable_entra_federation = true needs entra_client_secret: export TF_VAR_entra_client_secret from the value envs/dev output okta_idp_client_secret_command printed (minted by a human; never a tfvars file)."
    }
  }
}

# The IdP discovery policy is Okta's one built-in routing policy: READ, never
# managed, so its Default Rule (route to Okta, always last) is untouched.
data "okta_default_policy" "idp_discovery" {
  type = "IDP_DISCOVERY"
}

resource "okta_policy_rule_idp_discovery" "clinic_to_entra" {
  count = local.federation_enabled ? 1 : 0

  policy_id = data.okta_default_policy.idp_discovery.id
  name      = var.routing_rule_name
  priority  = 1
  status    = var.routing_rule_active ? "ACTIVE" : "INACTIVE"

  # Who: usernames ending in the clinic domain (Okta's documented
  # "identifier suffix" routing; verify: the value is the bare domain, as in
  # Okta's IdP discovery policy example, not "@domain"). Nobody else matches,
  # so everybody else reaches the Default Rule.
  user_identifier_type = "IDENTIFIER"
  user_identifier_patterns {
    match_type = "SUFFIX"
    value      = var.clinic_login_domain
  }

  # From anywhere: Conditional Access at Entra is the place for location.
  network_connection = "ANYWHERE"

  # Where: the Entra IdP, and only it.
  idp_providers {
    id   = okta_idp_oidc.entra[0].id
    type = "OIDC"
  }
}

# Rollback in force: a warning on every plan while the rule is INACTIVE, so
# a rolled-back state is never forgotten (the runbook's "fix, then re-enable").
check "routing_rule_rollback_in_force" {
  assert {
    condition     = !(var.enable_entra_federation && !var.routing_rule_active)
    error_message = "routing_rule_active = false: the clinic domain is routed to Okta passwords again (the runbook's Phase 1 rollback). Intended for an incident; set it back to true once the cause is fixed, and record the rollback time in the evidence."
  }
}
