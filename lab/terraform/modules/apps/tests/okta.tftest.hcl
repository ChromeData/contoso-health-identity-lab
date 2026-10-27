# Offline, mocked tests for okta-clinic-idp (okta.tf), the Entra half of the
# Okta coexistence - no tenant, no Okta org, no network:
#   terraform init -backend=false && terraform test
#
# What these pin:
#   * flag off (default) = NOTHING Okta is planned, outputs and the NHI row
#     are null, no other app changes;
#   * flag on = app registration (single tenant, implicit grants off, the
#     Graph scopes Okta asks for) + SP (assignment required) + ONE assignment
#     to App-Okta-Federation-Users + ONE redirect URI, the Okta authorize
#     callback on the org host given, https by construction;
#   * serviceManagementReference stamped when given;
#   * NO client secret resource exists in the module (the human hand-off):
#     the only secret artefact is a bounded post-apply command;
#   * the flag without an org host or without the group fails the plan;
#   * a scheme, a path, a wildcard, a non-Okta host, a look-alike suffix and
#     the -admin host are refused; oktapreview.com and okta-emea.com orgs
#     are accepted; a secret lifetime over 180 days is refused;
#   * a mocked APPLY with the flag on (outputs built from applied values).

mock_provider "azuread" {
  mock_data "azuread_client_config" {
    defaults = {
      tenant_id = "11111111-1111-1111-1111-111111111111"
      client_id = "33333333-3333-3333-3333-333333333333"
      object_id = "44444444-4444-4444-4444-444444444444"
    }
  }
  # The AWS template data source is always read; it must keep its name.
  mock_data "azuread_application_template" {
    defaults = {
      template_id  = "21ed01d2-ec13-4e9e-86c1-cd546719ebc4"
      display_name = "AWS IAM Identity Center (successor to AWS Single Sign-On)"
    }
  }
  mock_data "azuread_application" {
    defaults = { client_id = "15151515-1515-1515-1515-151515151515" }
  }
  mock_resource "azuread_application_from_template" {
    defaults = {
      application_id              = "/applications/12121212-1212-1212-1212-121212121212"
      application_object_id       = "12121212-1212-1212-1212-121212121212"
      service_principal_id        = "/servicePrincipals/99999999-9999-9999-9999-999999999999"
      service_principal_object_id = "99999999-9999-9999-9999-999999999999"
    }
  }
  mock_resource "azuread_service_principal" {
    defaults = {
      id        = "/servicePrincipals/99999999-9999-9999-9999-999999999999"
      object_id = "99999999-9999-9999-9999-999999999999"
      app_roles = []
    }
  }
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/13131313-1313-1313-1313-131313131313"
      object_id = "13131313-1313-1313-1313-131313131313"
      client_id = "14141414-1414-1414-1414-141414141414"
    }
  }
  mock_resource "azuread_claims_mapping_policy" {
    defaults = { id = "/policies/claimsMappingPolicies/16161616-1616-1616-1616-161616161616" }
  }
  mock_resource "azuread_group" {
    defaults = { object_id = "dddddddd-dddd-dddd-dddd-dddddddddddd" }
  }
  mock_resource "azuread_service_principal_token_signing_certificate" {
    defaults = {
      thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567"
      end_date   = "2029-10-20T00:00:00Z"
    }
  }
}

variables {
  aws_users_group_object_id = "55555555-5555-5555-5555-555555555555"
  app_owner_object_ids      = ["66666666-6666-6666-6666-666666666666"]
}

run "okta_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(azuread_application.okta_idp) == 0
      && length(azuread_service_principal.okta_idp) == 0
      && length(azuread_app_role_assignment.okta_federation_users) == 0
    )
    error_message = "no okta-clinic-idp object may be planned unless enable_okta_federation = true"
  }
  assert {
    condition = (
      output.nhi_inventory.okta_clinic_idp == null
      && output.okta_idp_client_id == null
      && output.okta_idp_redirect_uri == null
      && output.okta_idp_endpoints == null
      && output.okta_idp_assigned_group_object_id == null
      && output.okta_idp_client_secret_command == null
    )
    error_message = "every Okta output and the NHI inventory row must be null while the flag is off"
  }
  # The other apps are unaffected by the new flag.
  assert {
    condition     = azuread_app_role_assignment.aws_users.principal_object_id == "55555555-5555-5555-5555-555555555555" && length(azuread_app_role_assignment.servicenow_users) == 0
    error_message = "the AWS app must keep its single assignment and ServiceNow must stay absent"
  }
}

run "okta_on_plans_app_sp_one_assignment_and_one_redirect" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  assert {
    condition = (
      length(azuread_application.okta_idp) == 1
      && length(azuread_service_principal.okta_idp) == 1
      && length(azuread_app_role_assignment.okta_federation_users) == 1
    )
    error_message = "the flag must plan exactly one app registration, one SP and one assignment"
  }
  assert {
    condition     = azuread_application.okta_idp[0].display_name == "okta-clinic-idp" && azuread_application.okta_idp[0].sign_in_audience == "AzureADMyOrg" && azuread_application.okta_idp[0].prevent_duplicate_names == true
    error_message = "the app must be okta-clinic-idp, single tenant, and refuse a duplicate name"
  }
  assert {
    condition     = one(azuread_application.okta_idp[0].web).redirect_uris == toset(["https://integrator-1234567.okta.com/oauth2/v1/authorize/callback"])
    error_message = "the ONE redirect URI must be the Okta authorize callback on the org host, https"
  }
  assert {
    condition     = one(one(azuread_application.okta_idp[0].web).implicit_grant).access_token_issuance_enabled == false && one(one(azuread_application.okta_idp[0].web).implicit_grant).id_token_issuance_enabled == false
    error_message = "both implicit grants must be off: Okta uses the authorization code flow with a client secret"
  }
  assert {
    condition = (
      length(azuread_application.okta_idp[0].required_resource_access) == 1
      && one(azuread_application.okta_idp[0].required_resource_access).resource_app_id == "00000003-0000-0000-c000-000000000000"
      && toset([for a in one(azuread_application.okta_idp[0].required_resource_access).resource_access : a.id]) == toset([
        "37f7f235-527c-4136-accd-4a02d197296e", # openid
        "14dad69e-099b-42c9-810b-d002981feec1", # profile
        "64a6cdd6-997a-4b52-ad60-8e8b9f49d1ab", # email
        "e1fe6dd8-ba31-4d61-89e7-88639da4683d", # User.Read
      ])
      && alltrue([for a in one(azuread_application.okta_idp[0].required_resource_access).resource_access : a.type == "Scope"])
    )
    error_message = "the app must declare exactly the delegated Graph scopes Okta asks for (openid, profile, email, User.Read), nothing application-typed"
  }
  assert {
    condition     = azuread_service_principal.okta_idp[0].app_role_assignment_required == true
    error_message = "the enterprise app must require assignment: only App-Okta-Federation-Users may federate"
  }
  assert {
    condition     = contains(tolist(azuread_application.okta_idp[0].owners), "66666666-6666-6666-6666-666666666666") && contains(tolist(azuread_application.okta_idp[0].owners), "44444444-4444-4444-4444-444444444444") && contains(tolist(azuread_service_principal.okta_idp[0].owners), "66666666-6666-6666-6666-666666666666")
    error_message = "owners must be the named human plus the Terraform identity, on both objects"
  }
  assert {
    condition     = azuread_app_role_assignment.okta_federation_users[0].principal_object_id == "77777777-7777-7777-7777-777777777777" && azuread_app_role_assignment.okta_federation_users[0].app_role_id == "00000000-0000-0000-0000-000000000000"
    error_message = "the one assignment must be App-Okta-Federation-Users on the default access role"
  }
  assert {
    condition     = azuread_application.okta_idp[0].service_management_reference == null
    error_message = "with no ITSM reference given, serviceManagementReference stays unset"
  }
  assert {
    condition     = output.okta_idp_endpoints.issuer_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0" && output.okta_idp_endpoints.jwks_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys" && output.okta_idp_endpoints.user_info_url == "https://graph.microsoft.com/oidc/userinfo"
    error_message = "the endpoints handed to the Okta root must be the tenant's v2.0 endpoints"
  }
  # Separate from every other app: turning Okta on adds nothing elsewhere.
  assert {
    condition     = length(azuread_app_role_assignment.clinical_portal) == 0 && length(azuread_app_role_assignment.servicenow_users) == 0 && length(azuread_app_role_assignment.guacamole_pam_operators) == 0 && azuread_app_role_assignment.aws_users.principal_object_id == "55555555-5555-5555-5555-555555555555"
    error_message = "turning Okta federation on must not add or change any other assignment"
  }
}

run "itsm_reference_is_stamped" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
    service_management_reference          = "CHG0040001"
  }

  assert {
    condition     = azuread_application.okta_idp[0].service_management_reference == "CHG0040001"
    error_message = "serviceManagementReference must carry the ITSM reference, as on the other registrations"
  }
}

run "preview_and_emea_orgs_are_accepted" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "clinic-test.oktapreview.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  assert {
    condition     = output.okta_idp_redirect_uri == "https://clinic-test.oktapreview.com/oauth2/v1/authorize/callback"
    error_message = "an oktapreview.com org must be accepted and produce its callback"
  }
}

run "emea_org_is_accepted" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "clinic.okta-emea.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  assert {
    condition     = output.okta_idp_redirect_uri == "https://clinic.okta-emea.com/oauth2/v1/authorize/callback"
    error_message = "an okta-emea.com org must be accepted and produce its callback"
  }
}

run "flag_without_org_domain_fails_the_plan" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [azuread_application.okta_idp]
}

run "flag_without_group_fails_the_plan" {
  command = plan

  variables {
    enable_okta_federation = true
    okta_org_domain        = "integrator-1234567.okta.com"
  }

  expect_failures = [azuread_app_role_assignment.okta_federation_users]
}

run "scheme_in_org_domain_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "https://integrator-1234567.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.okta_org_domain]
}

run "path_in_org_domain_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567.okta.com/oauth2/v1/authorize/callback"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.okta_org_domain]
}

run "wildcard_org_domain_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "*.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.okta_org_domain]
}

run "non_okta_host_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "login.clinic.example.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.okta_org_domain]
}

run "look_alike_suffix_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567.okta.com.example.org"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.okta_org_domain]
}

run "admin_host_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567-admin.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.okta_org_domain]
}

run "secret_lifetime_over_180_days_is_rejected" {
  command = plan

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
    okta_idp_secret_lifetime_days         = 365
  }

  expect_failures = [var.okta_idp_secret_lifetime_days]
}

# Everything Okta on, through a mocked APPLY: the outputs built from applied
# values, the bounded secret-minting command naming the applied app, and the
# NHI inventory row recording a human-held credential.
run "okta_on_mocked_apply" {
  command = apply

  variables {
    enable_okta_federation                = true
    okta_org_domain                       = "integrator-1234567.okta.com"
    okta_federation_users_group_object_id = "77777777-7777-7777-7777-777777777777"
    okta_idp_secret_lifetime_days         = 90
  }

  assert {
    condition     = output.okta_idp_client_id == "14141414-1414-1414-1414-141414141414" && output.okta_idp_application_object_id == "13131313-1313-1313-1313-131313131313" && output.okta_idp_service_principal_object_id == "99999999-9999-9999-9999-999999999999"
    error_message = "the ids the Okta root and the consent step need must come from the applied objects"
  }
  assert {
    condition     = output.okta_idp_client_secret_command == "Add-MgApplicationPassword -ApplicationId 13131313-1313-1313-1313-131313131313 -PasswordCredential @{ displayName = 'Okta IdP - entered once into lab/terraform/okta'; endDateTime = (Get-Date).ToUniversalTime().AddDays(90) } | Select-Object -ExpandProperty SecretText"
    error_message = "the secret-minting command must name the applied app and carry the bounded lifetime"
  }
  assert {
    condition     = output.okta_idp_assigned_group_object_id == "77777777-7777-7777-7777-777777777777" && output.okta_idp_redirect_uri == "https://integrator-1234567.okta.com/oauth2/v1/authorize/callback"
    error_message = "the assignment and redirect outputs must mirror the applied values"
  }
  assert {
    condition     = output.nhi_inventory.okta_clinic_idp.service_principal_object_id == "99999999-9999-9999-9999-999999999999" && startswith(output.nhi_inventory.okta_clinic_idp.credential_type, "client-secret (minted by a human post-apply, at most 90 days") && output.nhi_inventory.okta_clinic_idp.credential_expires == null && startswith(output.nhi_inventory.okta_clinic_idp.outbound_secret, "none")
    error_message = "the NHI inventory must list okta-clinic-idp with a human-minted, bounded client secret and no outbound secret"
  }
}
