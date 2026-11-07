# =============================================================================
# okta :: outputs.tf
# -----------------------------------------------------------------------------
# Identifiers only, never the secret. They feed the README's apply-order
# cross-check (the callback on both sides), its verify list and the evidence
# pack: WHICH rule routes WHICH domain to WHICH IdP, as code rather than a
# console screenshot.
# =============================================================================

output "okta_org_domain" {
  description = "The org host (<org>.<cell>). envs/dev's okta_org_domain must equal this, or the Entra app's redirect URI is on the wrong host."
  value       = local.okta_org_domain
}

output "okta_callback_uri" {
  description = "The authorize callback Okta uses for its OIDC IdP. Must equal envs/dev output okta_idp_redirect_uri (the cross-check in the README)."
  value       = local.okta_callback_uri
}

output "clinic_staff_group_id" {
  description = "Okta id of Clinic-Staff (the one principal on the clinic's legacy app)."
  value       = okta_group.clinic_staff.id
}

output "clinic_staff_group_rule_id" {
  description = "Okta id of the group rule that fills Clinic-Staff from the clinic login domain."
  value       = okta_group_rule.clinic_staff.id
}

output "clinic_scheduling_app_id" {
  description = "Okta app id of Clinic Scheduling (legacy), the app Phase 2 moves. GET /api/v1/apps/<id>/groups lists its one assignment."
  value       = okta_app_bookmark.clinic_scheduling.id
}

output "entra_idp_id" {
  description = "Okta id of the Microsoft Entra ID identity provider (null while enable_entra_federation is off). The Okta System Log's IdP sign-in events carry it."
  value       = one(okta_idp_oidc.entra[*].id)
}

output "routing_rule_id" {
  description = "Okta id of the IdP discovery rule that sends the clinic domain to Entra (null while off)."
  value       = one(okta_policy_rule_idp_discovery.clinic_to_entra[*].id)
}

output "routing_rule_status" {
  description = "ACTIVE = clinic users are routed to Entra; INACTIVE = the rollback is in force (routing_rule_active = false); null while off."
  value       = one(okta_policy_rule_idp_discovery.clinic_to_entra[*].status)
}

output "routed_login_domain" {
  description = "The login domain suffix the routing rule matches (everyone else falls through to Okta's Default Rule)."
  value       = var.clinic_login_domain
}

# ---- The clinic's other apps (clinic-apps.tf) -----------------------------------

output "clinic_results_app_id" {
  description = "Okta app id of Clinic Lab Results (wave 1). The System Log query (lab/okta-migration/syslog.mjs) filters on it."
  value       = okta_app_oauth.clinic_results.id
}

output "clinic_results_client_id" {
  description = "OIDC client id of the Okta Clinic Lab Results app (public client; not a secret). cutover.mjs reads it from the Okta API, not from here."
  value       = okta_app_oauth.clinic_results.client_id
}

output "clinic_results_okta_status" {
  description = "Where wave 1 stands on the Okta side: active-visible (before), active-hidden (cut over, one sign-in cycle), inactive (retired)."
  value       = local.clinic_results.retired ? "inactive" : (local.clinic_results.cutover ? "active-hidden" : "active-visible")
}

output "clinic_billing_app_id" {
  description = "Okta app id of Clinic Billing (wave 2, SAML)."
  value       = okta_app_saml.clinic_billing.id
}

output "clinical_apps_policy_id" {
  description = "Id of the Clinic clinical apps authentication policy (two factors, re-auth 8 h, catch-all DENY)."
  value       = okta_app_signon_policy.clinical_apps.id
}
