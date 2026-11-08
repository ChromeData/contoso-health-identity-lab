# Offline, mocked tests for the ServiceNow fulfilment app
# (servicenow_fulfilment.tf) - no tenant, no network:
#   terraform init -backend=false && terraform test
#
# What these pin:
#   * flag off (default) = nothing planned, output null;
#   * flag on = one app with NO required_resource_access (no Graph
#     permission), its certificate from files/servicenow-fulfilment.pem, an
#     SP that requires assignment and is hidden, and ONE catalog role:
#     Access package assignment manager (e2182095-...) on the given catalog;
#   * the flag without a catalog id fails the plan.

# time_sleep is mocked too: a mocked apply never waits 90 s.
mock_provider "time" {}

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
  # Path-form ids for the mocked APPLY run (the provider parses them).
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
  app_owner_object_ids      = ["66666666-6666-6666-6666-666666666666", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
}

run "fulfilment_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(azuread_application.servicenow_fulfilment) == 0
      && length(azuread_application_certificate.servicenow_fulfilment) == 0
      && length(azuread_service_principal.servicenow_fulfilment) == 0
      && length(azuread_access_package_catalog_role_assignment.servicenow_fulfilment) == 0
      && length(time_sleep.servicenow_fulfilment_sp_replication) == 0
      && output.servicenow_fulfilment == null
    )
    error_message = "with enable_servicenow_fulfilment = false nothing may be planned"
  }
}

run "fulfilment_least_privilege" {
  command = plan

  variables {
    enable_servicenow_fulfilment     = true
    servicenow_fulfilment_catalog_id = "abababab-abab-abab-abab-abababababab"
  }

  assert {
    condition     = length(azuread_application.servicenow_fulfilment[0].required_resource_access) == 0
    error_message = "the fulfilment app must request NO API permission: its only power is the catalog role"
  }
  assert {
    condition = (
      azuread_access_package_catalog_role_assignment.servicenow_fulfilment[0].role_id == "e2182095-804a-4656-ae11-64734e9b7ae5"
      && azuread_access_package_catalog_role_assignment.servicenow_fulfilment[0].catalog_id == "abababab-abab-abab-abab-abababababab"
    )
    error_message = "exactly the Access package assignment manager role (never catalog owner), on the given catalog"
  }
  assert {
    condition     = azuread_application_certificate.servicenow_fulfilment[0].type == "AsymmetricX509Cert" && strcontains(azuread_application_certificate.servicenow_fulfilment[0].value, "BEGIN CERTIFICATE") && !strcontains(azuread_application_certificate.servicenow_fulfilment[0].value, "PRIVATE KEY")
    error_message = "the credential must be the public certificate only - never a secret, never a private key"
  }
  assert {
    condition     = azuread_service_principal.servicenow_fulfilment[0].app_role_assignment_required == true && contains(azuread_service_principal.servicenow_fulfilment[0].tags, "HideApp")
    error_message = "nobody signs in to the fulfilment app: assignment required, hidden from My Apps"
  }
  assert {
    condition     = time_sleep.servicenow_fulfilment_sp_replication[0].create_duration == "90s"
    error_message = "the catalog role must wait for the new service principal to replicate (SubjectNotFound, run 42512070374)"
  }
  assert {
    condition     = azuread_application.servicenow_fulfilment[0].display_name == "ServiceNow - Access Fulfilment"
    error_message = "lab/servicenow/apply.py finds the client id by this display name"
  }
}

run "fulfilment_needs_a_catalog" {
  command = plan

  variables {
    enable_servicenow_fulfilment = true
  }

  expect_failures = [azuread_application.servicenow_fulfilment]
}

# Mocked APPLY: the role assignment gets the SP's object id THROUGH the sleep.
run "fulfilment_role_waits_for_the_sp" {
  command = apply

  variables {
    enable_servicenow_fulfilment     = true
    servicenow_fulfilment_catalog_id = "abababab-abab-abab-abab-abababababab"
  }

  override_resource {
    target = azuread_service_principal.servicenow_fulfilment
    values = {
      id        = "/servicePrincipals/1d3a3fc9-36db-4c40-b65d-1482dee35da6"
      object_id = "1d3a3fc9-36db-4c40-b65d-1482dee35da6"
    }
  }

  assert {
    condition     = azuread_access_package_catalog_role_assignment.servicenow_fulfilment[0].principal_object_id == "1d3a3fc9-36db-4c40-b65d-1482dee35da6" && time_sleep.servicenow_fulfilment_sp_replication[0].triggers["service_principal_object_id"] == "1d3a3fc9-36db-4c40-b65d-1482dee35da6"
    error_message = "the assignment must name the SP, read through the replication wait"
  }
}
