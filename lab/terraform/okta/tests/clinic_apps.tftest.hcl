# Offline, mocked tests for clinic-apps.tf - the clinic's other Okta apps,
# the clinical-apps authentication policy, the billing group rule and the
# (off) Admin Console phishing-resistant rule. No Okta org, no network:
#   terraform init -backend=false && terraform test
# (Move a local terraform.tfvars aside first: terraform test loads it.)
#
# What these pin:
#   * the policy's catch-all is DENY (catch_all = false); its one rule:
#     Clinic-Staff + Clinic-Billing, two factors, re-auth after 8 hours, and
#     NO phishing-resistant constraint (it would refuse today's clinic users);
#   * Clinic Lab Results: a public client (SPA, PKCE, auth method none), the
#     loopback redirect, on that policy, assigned to Clinic-Staff, VISIBLE and
#     ACTIVE until the cut-over; hidden (still active) at cutover; INACTIVE
#     at retire; retire without cut-over fails the plan;
#   * Clinic Billing: SAML, signed response + assertion, SHA-256, hidden,
#     assigned to Clinic-Billing, on the same policy;
#   * the billing group rule keys on department; a department that could
#     break out of the EL string is refused;
#   * the Admin Console rule exists only with its flag, first, demanding a
#     phishing-resistant, device-bound factor at every console sign-in.

mock_provider "okta" {
  mock_data "okta_default_policy" {
    defaults = { id = "00pDEFAULTIDPDISC0001" }
  }
  mock_data "okta_app_signon_policy" {
    defaults = { id = "rstADMINCONSOLE000001" }
  }
  mock_resource "okta_group" {
    defaults = { id = "00gGROUP000000000001" }
  }
  mock_resource "okta_app_signon_policy" {
    defaults = { id = "rstCLINICAL0000000001" }
  }
  mock_resource "okta_app_oauth" {
    defaults = { id = "0oaRESULTS0000000001", client_id = "0oaRESULTS0000000001" }
  }
  mock_resource "okta_app_saml" {
    defaults = { id = "0oaBILLING0000000001" }
  }
  mock_resource "okta_app_bookmark" {
    defaults = { id = "0oaSCHEDULING0000001" }
  }
}

variables {
  okta_org_name       = "integrator-1234567"
  clinic_login_domain = "contosohealthlab.com"
}

run "policy_denies_by_default_and_asks_two_factors_every_8h" {
  command = apply

  assert {
    condition     = okta_app_signon_policy.clinical_apps.catch_all == false
    error_message = "the clinical-apps policy's catch-all must be DENY (catch_all = false): only the clinic groups get in"
  }
  assert {
    condition = (
      okta_app_signon_policy_rule.clinical_staff.access == "ALLOW"
      && okta_app_signon_policy_rule.clinical_staff.factor_mode == "2FA"
      && okta_app_signon_policy_rule.clinical_staff.re_authentication_frequency == "PT8H"
      && okta_app_signon_policy_rule.clinical_staff.policy_id == okta_app_signon_policy.clinical_apps.id
    )
    error_message = "the one allow rule must ask for two factors and re-authentication after 8 hours"
  }
  assert {
    condition     = length(coalesce(okta_app_signon_policy_rule.clinical_staff.constraints, [])) == 0
    error_message = "no phishing-resistant constraint on the clinic rule: clinic users' Entra MFA is an authenticator code today"
  }
}

run "clinic_results_is_a_visible_public_client_until_cutover" {
  command = plan

  assert {
    condition = (
      okta_app_oauth.clinic_results.type == "browser"
      && okta_app_oauth.clinic_results.pkce_required == true
      && okta_app_oauth.clinic_results.token_endpoint_auth_method == "none"
      && okta_app_oauth.clinic_results.redirect_uris == tolist(["http://localhost:8471/callback"])
      && okta_app_oauth.clinic_results.grant_types == toset(["authorization_code"])
    )
    error_message = "Clinic Lab Results must be a public client: auth code + PKCE, no secret, the loopback redirect the Entra app also uses"
  }
  assert {
    condition     = okta_app_oauth.clinic_results.status == "ACTIVE" && okta_app_oauth.clinic_results.hide_web == false && output.clinic_results_okta_status == "active-visible"
    error_message = "before the cut-over the app is active and on the dashboard"
  }
}

run "cutover_hides_but_keeps_the_okta_app" {
  command = plan

  variables {
    waves_override = { "Clinic Lab Results" = { cutover = true, retired = false } }
  }

  assert {
    condition     = okta_app_oauth.clinic_results.status == "ACTIVE" && okta_app_oauth.clinic_results.hide_web == true && output.clinic_results_okta_status == "active-hidden"
    error_message = "at the cut-over the Okta app is hidden but stays active and assigned for one sign-in cycle (the rollback)"
  }
}

run "retire_deactivates" {
  command = plan

  variables {
    waves_override = { "Clinic Lab Results" = { cutover = true, retired = true } }
  }

  assert {
    condition     = okta_app_oauth.clinic_results.status == "INACTIVE" && output.clinic_results_okta_status == "inactive"
    error_message = "retire deactivates the Okta app (kept, so reactivation is the rollback)"
  }
}

run "retire_without_cutover_fails_the_plan" {
  command = plan

  variables {
    waves_override = { "Clinic Lab Results" = { cutover = false, retired = true } }
  }

  expect_failures = [okta_app_oauth.clinic_results]
}

run "billing_is_a_signed_hidden_saml_app_on_the_clinical_policy" {
  command = apply

  assert {
    condition = (
      okta_app_saml.clinic_billing.response_signed == true
      && okta_app_saml.clinic_billing.assertion_signed == true
      && okta_app_saml.clinic_billing.signature_algorithm == "RSA_SHA256"
      && okta_app_saml.clinic_billing.digest_algorithm == "SHA256"
      && okta_app_saml.clinic_billing.hide_web == true
      && okta_app_saml.clinic_billing.authentication_policy == okta_app_signon_policy.clinical_apps.id
      && okta_app_oauth.clinic_results.authentication_policy == okta_app_signon_policy.clinical_apps.id
    )
    error_message = "Clinic Billing must be signed SAML (SHA-256), hidden (no SP exists), and both apps on the clinical-apps policy"
  }
  assert {
    condition     = okta_app_group_assignment.clinic_billing_team.app_id == okta_app_saml.clinic_billing.id && okta_app_group_assignment.clinic_billing_team.group_id == okta_group.clinic_billing.id
    error_message = "Clinic Billing is assigned to Clinic-Billing only"
  }
  assert {
    condition     = okta_group_rule.clinic_billing.expression_value == "user.department == \"Clinic Billing\"" && okta_group_rule.clinic_billing.group_assignments == toset([okta_group.clinic_billing.id])
    error_message = "the billing rule must key on department into Clinic-Billing"
  }
}

run "department_cannot_break_out_of_the_el_string" {
  command = plan

  variables {
    clinic_billing_department = "x\" || true || \"y"
  }

  expect_failures = [var.clinic_billing_department]
}

run "admin_console_rule_absent_by_default" {
  command = plan

  assert {
    condition     = length(okta_app_signon_policy_rule.admin_console_phishing_resistant) == 0
    error_message = "the Admin Console phishing-resistant rule is the owner's switch: off by default"
  }
}

run "admin_console_rule_demands_phishing_resistant_first" {
  command = plan

  variables {
    admin_console_phishing_resistant = true
    okta_admin_console_app_id        = "0oaADMINCONSOLE00001"
  }

  assert {
    condition = (
      okta_app_signon_policy_rule.admin_console_phishing_resistant[0].priority == 0
      && okta_app_signon_policy_rule.admin_console_phishing_resistant[0].policy_id == "rstADMINCONSOLE000001"
      && okta_app_signon_policy_rule.admin_console_phishing_resistant[0].re_authentication_frequency == "PT0S"
      && jsondecode(okta_app_signon_policy_rule.admin_console_phishing_resistant[0].constraints[0]).possession.phishingResistant == "REQUIRED"
      && jsondecode(okta_app_signon_policy_rule.admin_console_phishing_resistant[0].constraints[0]).possession.deviceBound == "REQUIRED"
    )
    error_message = "with the flag on, the console's first rule demands a phishing-resistant, device-bound factor at every sign-in"
  }
}

run "admin_console_rule_needs_the_console_app_id" {
  command = plan

  variables {
    admin_console_phishing_resistant = true
  }

  expect_failures = [okta_app_signon_policy_rule.admin_console_phishing_resistant]
}
