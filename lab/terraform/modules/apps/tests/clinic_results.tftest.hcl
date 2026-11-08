# Offline, mocked tests for Clinic Lab Results (clinic_results.tf), the first
# app moved from the clinic's Okta to Entra (lab/okta-migration wave 1) - no
# tenant, no network:  terraform init -backend=false && terraform test
#
# What these pin:
#   * flag off (default) = nothing planned, outputs and the NHI row null;
#   * flag on = app registration (single tenant, PUBLIC client with the one
#     loopback redirect, no fallback public client flows, openid + profile +
#     email only), SP with assignment required, the assigned group
#     App-ClinicResults-Users (member drift ignored) and ONE assignment of it;
#   * no client secret or certificate exists for it (NHI row: none);
#   * its API "Clinic Lab Results API" (the resource CA061 targets, because
#     Conditional Access cannot target a public client): one delegated scope
#     Results.Read, api://<client id>, assignment required with the SAME
#     group, the client pre-authorized and declaring that scope;
#   * a remote host, https or a wildcard redirect is refused;
#   * the other apps are unchanged.

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

# The API gets its own client id, so "the client declares the API" and "CA061
# is wired from the API" cannot pass by sharing the client's mock id.
override_resource {
  target = azuread_application.clinic_results_api
  values = {
    id        = "/applications/27272727-2727-2727-2727-272727272727"
    object_id = "27272727-2727-2727-2727-272727272727"
    client_id = "28282828-2828-2828-2828-282828282828"
  }
}

variables {
  aws_users_group_object_id = "55555555-5555-5555-5555-555555555555"
  app_owner_object_ids      = ["66666666-6666-6666-6666-666666666666", "ffffffff-ffff-ffff-ffff-ffffffffffff"] # a named owner + a backup (ADR 0018)
}

run "clinic_results_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(azuread_application.clinic_results) == 0
      && length(azuread_service_principal.clinic_results) == 0
      && length(azuread_group.clinic_results_users) == 0
      && length(azuread_application.clinic_results_api) == 0
      && length(azuread_service_principal.clinic_results_api) == 0
      && output.clinic_results_api_client_id == null
      && length(azuread_app_role_assignment.clinic_results_users) == 0
      && output.clinic_results_client_id == null
      && output.clinic_results_users_group_object_id == null
      && output.nhi_inventory.clinic_lab_results == null
    )
    error_message = "nothing for Clinic Lab Results may be planned, and its outputs must be null, unless enable_clinic_results_app = true"
  }
}

run "clinic_results_on_plans_public_client_sp_group_one_assignment" {
  command = apply

  variables {
    enable_clinic_results_app = true
  }

  assert {
    condition     = azuread_application.clinic_results[0].display_name == "Clinic Lab Results" && azuread_application.clinic_results[0].sign_in_audience == "AzureADMyOrg" && azuread_application.clinic_results[0].prevent_duplicate_names == true
    error_message = "the app must be Clinic Lab Results (the Okta app's label), single tenant, no duplicate name"
  }
  assert {
    condition     = one(azuread_application.clinic_results[0].public_client).redirect_uris == toset(["http://localhost:8471/callback"])
    error_message = "the ONE redirect must be the loopback the Okta app used, on the public-client platform"
  }
  assert {
    condition     = length(azuread_application.clinic_results[0].web) == 0 && length(azuread_application.clinic_results[0].single_page_application) == 0
    error_message = "no web or SPA platform: the app is a public client with PKCE"
  }
  assert {
    condition     = azuread_application.clinic_results[0].fallback_public_client_enabled == false
    error_message = "no ROPC / device code: the browser sign-in (with CA) is the only door"
  }
  assert {
    condition = toset([for a in one([for r in azuread_application.clinic_results[0].required_resource_access : r if r.resource_app_id == "00000003-0000-0000-c000-000000000000"]).resource_access : a.id]) == toset([
      "37f7f235-527c-4136-accd-4a02d197296e", # openid
      "14dad69e-099b-42c9-810b-d002981feec1", # profile
      "64a6cdd6-997a-4b52-ad60-8e8b9f49d1ab", # email
    ]) && alltrue(flatten([for r in azuread_application.clinic_results[0].required_resource_access : [for a in r.resource_access : a.type == "Scope"]]))
    error_message = "the app must declare openid, profile and email from Graph, all delegated"
  }
  assert {
    condition     = azuread_service_principal.clinic_results[0].app_role_assignment_required == true
    error_message = "assignment must be required: a non-member gets no token"
  }
  assert {
    condition     = azuread_group.clinic_results_users[0].display_name == "App-ClinicResults-Users" && azuread_group.clinic_results_users[0].security_enabled == true && azuread_group.clinic_results_users[0].mail_enabled == false
    error_message = "the app group must be the assigned security group App-ClinicResults-Users"
  }
  assert {
    condition     = azuread_app_role_assignment.clinic_results_users[0].principal_object_id == azuread_group.clinic_results_users[0].object_id && azuread_app_role_assignment.clinic_results_users[0].app_role_id == "00000000-0000-0000-0000-000000000000"
    error_message = "the ONE assignment must be App-ClinicResults-Users on the default access role"
  }
  assert {
    condition     = startswith(output.nhi_inventory.clinic_lab_results.credential_type, "none") && output.nhi_inventory.clinic_lab_results.outbound_secret == "none"
    error_message = "the NHI row must record that the app holds no credential"
  }
  assert {
    condition     = output.clinic_results_client_id == azuread_application.clinic_results[0].client_id && output.clinic_results_users_group_object_id == azuread_group.clinic_results_users[0].object_id
    error_message = "the outputs CA061 is wired from must be the app's client id and the group's id"
  }
  assert {
    condition = (
      azuread_application.clinic_results_api[0].display_name == "Clinic Lab Results API"
      && azuread_application.clinic_results_api[0].sign_in_audience == "AzureADMyOrg"
      && one(azuread_application.clinic_results_api[0].api).requested_access_token_version == 2
      && [for sc in one(azuread_application.clinic_results_api[0].api).oauth2_permission_scope : sc.value] == ["Results.Read"]
    )
    error_message = "the API must be single tenant, v2 tokens, one delegated scope Results.Read"
  }
  assert {
    condition     = azuread_application_identifier_uri.clinic_results_api[0].identifier_uri == "api://${azuread_application.clinic_results_api[0].client_id}"
    error_message = "the API's App ID URI must be api://<its client id>"
  }
  assert {
    condition     = azuread_service_principal.clinic_results_api[0].app_role_assignment_required == true && azuread_app_role_assignment.clinic_results_api_users[0].principal_object_id == azuread_group.clinic_results_users[0].object_id
    error_message = "the API requires assignment, and the same app group is its one principal"
  }
  assert {
    condition = (
      azuread_application_pre_authorized.clinic_results_client[0].authorized_client_id == azuread_application.clinic_results[0].client_id
      && azuread_application_pre_authorized.clinic_results_client[0].permission_ids == toset(["5b7c3e1a-2d4f-4c8e-9a61-7f0b2c9d4e13"])
      && length([for r in azuread_application.clinic_results[0].required_resource_access : r if r.resource_app_id == azuread_application.clinic_results_api[0].client_id]) == 1
    )
    error_message = "the client must be pre-authorized for Results.Read and declare it"
  }
  assert {
    condition     = output.clinic_results_api_client_id == "28282828-2828-2828-2828-282828282828" && output.clinic_results_api_client_id != output.clinic_results_client_id
    error_message = "CA061 is wired from the API's client id (output clinic_results_api_client_id)"
  }
  assert {
    condition     = length(azuread_app_role_assignment.servicenow_users) == 0 && length(azuread_app_role_assignment.okta_federation_users) == 0 && azuread_app_role_assignment.aws_users.principal_object_id == "55555555-5555-5555-5555-555555555555"
    error_message = "turning Clinic Lab Results on must not add or change any other assignment"
  }
}

run "remote_redirect_is_refused" {
  command = plan
  variables {
    enable_clinic_results_app    = true
    clinic_results_redirect_uris = ["https://results.clinic.example/callback"]
  }
  expect_failures = [var.clinic_results_redirect_uris]
}

run "wildcard_redirect_is_refused" {
  command = plan
  variables {
    enable_clinic_results_app    = true
    clinic_results_redirect_uris = ["http://localhost:8471/*"]
  }
  expect_failures = [var.clinic_results_redirect_uris]
}

run "portless_redirect_is_refused" {
  command = plan
  variables {
    enable_clinic_results_app    = true
    clinic_results_redirect_uris = ["http://localhost/callback"]
  }
  expect_failures = [var.clinic_results_redirect_uris]
}
