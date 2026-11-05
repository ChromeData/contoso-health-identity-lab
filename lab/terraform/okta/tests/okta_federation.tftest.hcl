# Offline, mocked tests for the Okta root - no Okta org, no network:
#   terraform init -backend=false && terraform test
#
# What these pin:
#   * by default (enable_entra_federation = false) only the clinic's estate
#     is planned: Clinic-Staff, its group rule keyed on the login domain, the
#     legacy bookmark app and its ONE assignment; no IdP, no routing rule;
#   * with the flag on: the Entra OIDC IdP against the tenant's v2.0
#     endpoints with scopes openid profile email, account link by email, and
#     ONE routing rule, priority 1, ACTIVE, matching the clinic login domain
#     as a SUFFIX (never everyone) and targeting only that IdP - so Okta's
#     Default Rule stays the fallback;
#   * the routing rule reads Okta's built-in IdP discovery policy (a data
#     source: never managed, never deleted);
#   * the client secret variable is sensitive end to end and, like the
#     client id and tenant id, required when the flag is on;
#   * the rollback (routing_rule_active = false) sets the rule INACTIVE,
#     keeps the IdP, and raises the warning check;
#   * JIT can be turned off ([prod]);
#   * an @ or scheme in the login domain, a plain-http legacy app URL, a
#     base URL outside Okta's cells, an org name that is a host or the
#     -admin host, and a non-GUID client id are refused;
#   * a mocked APPLY with everything on (ids wired between the objects).

mock_provider "okta" {
  mock_data "okta_default_policy" {
    defaults = { id = "00p1idpdiscovery0000000" }
  }
  mock_resource "okta_group" {
    defaults = { id = "00g1clinicstaff00000000" }
  }
  mock_resource "okta_group_rule" {
    defaults = { id = "0pr1clinicrule000000000" }
  }
  mock_resource "okta_app_bookmark" {
    defaults = {
      id           = "0oa1scheduling000000000"
      name         = "bookmark"
      sign_on_mode = "BOOKMARK"
    }
  }
  mock_resource "okta_app_group_assignment" {
    defaults = { id = "0oa1scheduling000000000/00g1clinicstaff00000000" }
  }
  mock_resource "okta_idp_oidc" {
    defaults = {
      id   = "0oa1entraidp00000000000"
      type = "OIDC"
    }
  }
  mock_resource "okta_policy_rule_idp_discovery" {
    defaults = { id = "0pr1routing000000000000" }
  }
}

variables {
  okta_org_name       = "integrator-1234567"
  clinic_login_domain = "clinic.contoso.example"
}

run "baseline_plans_only_the_clinic_estate" {
  command = plan

  assert {
    condition     = length(okta_idp_oidc.entra) == 0 && length(okta_policy_rule_idp_discovery.clinic_to_entra) == 0
    error_message = "no identity provider and no routing rule may be planned unless enable_entra_federation = true"
  }
  assert {
    condition     = okta_group.clinic_staff.name == "Clinic-Staff" && okta_group_rule.clinic_staff.status == "ACTIVE" && okta_group_rule.clinic_staff.expression_value == "String.substringAfter(user.login, \"@\") == \"clinic.contoso.example\""
    error_message = "Clinic-Staff must exist and be filled by a rule on the clinic login domain"
  }
  assert {
    condition     = okta_app_bookmark.clinic_scheduling.label == "Clinic Scheduling (legacy)" && okta_app_bookmark.clinic_scheduling.url == "https://scheduling.clinic.example/" && okta_app_bookmark.clinic_scheduling.status == "ACTIVE" && okta_app_bookmark.clinic_scheduling.hide_web == false
    error_message = "the legacy app must be the active, visible bookmark the runbook inventories"
  }
  assert {
    condition     = output.entra_idp_id == null && output.routing_rule_id == null && output.routing_rule_status == null
    error_message = "the federation outputs must be null while the flag is off"
  }
  assert {
    condition     = output.okta_org_domain == "integrator-1234567.okta.com" && output.okta_callback_uri == "https://integrator-1234567.okta.com/oauth2/v1/authorize/callback"
    error_message = "the org host and the callback must be derived from the org name and cell (the Entra side's cross-check)"
  }
}

run "federation_on_plans_the_idp_and_one_routing_rule" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  assert {
    condition     = length(okta_idp_oidc.entra) == 1 && length(okta_policy_rule_idp_discovery.clinic_to_entra) == 1
    error_message = "the flag must plan exactly one identity provider and one routing rule"
  }
  assert {
    condition     = okta_idp_oidc.entra[0].protocol_type == "OIDC" && okta_idp_oidc.entra[0].scopes == toset(["openid", "profile", "email"]) && okta_idp_oidc.entra[0].client_id == "14141414-1414-1414-1414-141414141414" && okta_idp_oidc.entra[0].status == "ACTIVE"
    error_message = "the IdP must be OIDC with the three scopes the runbook names and the Entra app's client id"
  }
  assert {
    condition = (
      okta_idp_oidc.entra[0].issuer_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
      && okta_idp_oidc.entra[0].authorization_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize"
      && okta_idp_oidc.entra[0].token_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token"
      && okta_idp_oidc.entra[0].jwks_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys"
      && okta_idp_oidc.entra[0].user_info_url == "https://graph.microsoft.com/oidc/userinfo"
      && okta_idp_oidc.entra[0].token_binding == "HTTP-POST"
    )
    error_message = "every IdP endpoint must be the tenant's v2.0 endpoint built from entra_tenant_id, and the token request a POST"
  }
  assert {
    condition     = okta_idp_oidc.entra[0].subject_match_type == "EMAIL" && okta_idp_oidc.entra[0].account_link_action == "AUTO" && okta_idp_oidc.entra[0].provisioning_action == "AUTO" && okta_idp_oidc.entra[0].groups_action == "NONE" && okta_idp_oidc.entra[0].issuer_mode == "ORG_URL"
    error_message = "account link by email, JIT on (lab), groups never copied from the IdP, org URL as issuer"
  }
  assert {
    condition     = okta_idp_oidc.entra[0].request_signature_scope == "NONE"
    error_message = "the authorize request must be unsigned: Entra refuses a signed request object (AADSTS70013, first clinic sign-in 2026-11-05)"
  }
  assert {
    condition     = okta_policy_rule_idp_discovery.clinic_to_entra[0].priority == 1 && okta_policy_rule_idp_discovery.clinic_to_entra[0].status == "ACTIVE" && okta_policy_rule_idp_discovery.clinic_to_entra[0].network_connection == "ANYWHERE"
    error_message = "the routing rule must be first, active, and location-agnostic (Conditional Access decides location at Entra)"
  }
  assert {
    condition     = okta_policy_rule_idp_discovery.clinic_to_entra[0].user_identifier_type == "IDENTIFIER" && [for p in okta_policy_rule_idp_discovery.clinic_to_entra[0].user_identifier_patterns : "${p.match_type}:${p.value}"] == ["SUFFIX:clinic.contoso.example"]
    error_message = "the rule must match ONLY usernames ending in the clinic domain: anything wider would swallow Okta's Default Rule fallback"
  }
  assert {
    condition     = length(okta_policy_rule_idp_discovery.clinic_to_entra[0].idp_providers) == 1 && okta_policy_rule_idp_discovery.clinic_to_entra[0].idp_providers[0].type == "OIDC"
    error_message = "the rule must route to exactly one IdP, of type OIDC"
  }
  assert {
    condition     = okta_policy_rule_idp_discovery.clinic_to_entra[0].policy_id == data.okta_default_policy.idp_discovery.id
    error_message = "the rule must attach to Okta's built-in IdP discovery policy, read by a data source and never managed, so the Default Rule stays"
  }
  assert {
    condition     = output.routed_login_domain == "clinic.contoso.example"
    error_message = "the routed domain output must name the clinic domain"
  }
}

run "secret_variable_is_sensitive_end_to_end" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  assert {
    condition     = issensitive(var.entra_client_secret) && issensitive(okta_idp_oidc.entra[0].client_secret)
    error_message = "entra_client_secret must be sensitive as a variable and on the IdP resource, so no plan output ever prints it"
  }
}

run "federation_on_mocked_apply" {
  command = apply

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  assert {
    condition     = okta_policy_rule_idp_discovery.clinic_to_entra[0].idp_providers[0].id == okta_idp_oidc.entra[0].id && okta_policy_rule_idp_discovery.clinic_to_entra[0].idp_providers[0].id == "0oa1entraidp00000000000"
    error_message = "the routing rule must target the Entra IdP this root created"
  }
  assert {
    condition     = okta_app_group_assignment.clinic_scheduling_staff.app_id == okta_app_bookmark.clinic_scheduling.id && okta_app_group_assignment.clinic_scheduling_staff.group_id == okta_group.clinic_staff.id
    error_message = "the legacy app must be assigned to Clinic-Staff, and to that one group only"
  }
  assert {
    condition     = okta_group_rule.clinic_staff.group_assignments == toset([okta_group.clinic_staff.id])
    error_message = "the group rule must fill Clinic-Staff and no other group"
  }
  assert {
    condition     = output.entra_idp_id == "0oa1entraidp00000000000" && output.routing_rule_id == "0pr1routing000000000000" && output.routing_rule_status == "ACTIVE" && output.clinic_staff_group_id == "00g1clinicstaff00000000" && output.clinic_scheduling_app_id == "0oa1scheduling000000000"
    error_message = "the identifier outputs must come from the applied objects"
  }
}

run "rollback_turns_only_the_rule_off" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
    routing_rule_active     = false
  }

  # The rollback is a warning on every plan, never silent.
  expect_failures = [check.routing_rule_rollback_in_force]

  assert {
    condition     = okta_policy_rule_idp_discovery.clinic_to_entra[0].status == "INACTIVE" && length(okta_idp_oidc.entra) == 1 && okta_idp_oidc.entra[0].status == "ACTIVE"
    error_message = "the rollback must set the routing rule INACTIVE and leave the identity provider in place"
  }
  assert {
    condition     = output.routing_rule_status == "INACTIVE"
    error_message = "the status output must show the rollback"
  }
}

run "jit_can_be_turned_off_for_production" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
    jit_provisioning        = false
  }

  assert {
    condition     = okta_idp_oidc.entra[0].provisioning_action == "DISABLED" && okta_idp_oidc.entra[0].account_link_action == "AUTO"
    error_message = "with JIT off, Okta must still link pre-existing accounts by email but create none"
  }
}

run "flag_without_secret_fails_the_plan" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
  }

  expect_failures = [okta_idp_oidc.entra]
}

run "flag_without_client_id_fails_the_plan" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  expect_failures = [okta_idp_oidc.entra]
}

run "flag_without_tenant_id_fails_the_plan" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  expect_failures = [okta_idp_oidc.entra]
}

run "login_domain_with_at_sign_is_rejected" {
  command = plan

  variables {
    clinic_login_domain = "@clinic.contoso.example"
  }

  expect_failures = [var.clinic_login_domain]
}

run "login_domain_with_scheme_or_wildcard_is_rejected" {
  command = plan

  variables {
    clinic_login_domain = "https://*.clinic.contoso.example"
  }

  expect_failures = [var.clinic_login_domain]
}

run "plain_http_legacy_app_url_is_rejected" {
  command = plan

  variables {
    legacy_app_url = "http://scheduling.clinic.example/"
  }

  expect_failures = [var.legacy_app_url]
}

run "base_url_outside_okta_cells_is_rejected" {
  command = plan

  variables {
    okta_base_url = "okta.example.org"
  }

  expect_failures = [var.okta_base_url]
}

run "org_name_as_a_host_is_rejected" {
  command = plan

  variables {
    okta_org_name = "integrator-1234567.okta.com"
  }

  expect_failures = [var.okta_org_name]
}

run "admin_org_name_is_rejected" {
  command = plan

  variables {
    okta_org_name = "integrator-1234567-admin"
  }

  expect_failures = [var.okta_org_name]
}

run "client_id_that_is_not_a_guid_is_rejected" {
  command = plan

  variables {
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "okta-clinic-idp"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  expect_failures = [var.entra_client_id]
}

# The lab's routing decision (2026-11-05): clinic staff use hospital accounts
# after the acquisition, so the routed domain is the hospital's. Both the
# routing rule and the Clinic-Staff group rule must follow it, and nothing
# wider than that one suffix may be routed.
run "hospital_domain_routes_hospital_addresses_only" {
  command = plan

  variables {
    clinic_login_domain     = "contosohealthlab.com"
    enable_entra_federation = true
    entra_tenant_id         = "11111111-1111-1111-1111-111111111111"
    entra_client_id         = "14141414-1414-1414-1414-141414141414"
    entra_client_secret     = "not-a-real-secret-0123456789"
  }

  assert {
    condition     = [for p in okta_policy_rule_idp_discovery.clinic_to_entra[0].user_identifier_patterns : "${p.match_type}:${p.value}"] == ["SUFFIX:contosohealthlab.com"]
    error_message = "the routing rule must match exactly the hospital domain suffix"
  }
  assert {
    condition     = okta_group_rule.clinic_staff.expression_value == "String.substringAfter(user.login, \"@\") == \"contosohealthlab.com\""
    error_message = "Clinic-Staff membership must follow the same domain as the routing rule"
  }
}
