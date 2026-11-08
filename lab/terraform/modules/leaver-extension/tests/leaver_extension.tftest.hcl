# Offline mock tests for modules/leaver-extension (no tenant, no state):
#   terraform init -backend=false && terraform test
# Pins: system-assigned identity only, no secret; the narrowest grant
# (Access package assignment manager on the given catalogs, nothing else);
# the trigger accepts only Lifecycle Workflows' PoP token for this workflow;
# the workflow only ever sends adminRemove, only for automatic assignments,
# and has no callback.

mock_provider "azurerm" {
  mock_resource "azurerm_resource_group_template_deployment" {
    defaults = {
      output_content = "{\"principalId\":{\"type\":\"String\",\"value\":\"99999999-9999-9999-9999-999999999999\"}}"
    }
  }
}
mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      object_id    = "12121212-1212-1212-1212-121212121212"
      app_role_ids = { "EntitlementManagement.ReadWrite.All" = "9acd699f-1e81-4958-b001-93b1d2506e19", "Directory.ReadWrite.All" = "19dbc75e-c2e2-444c-a770-ec69d8559fc7" }
    }
  }
}
# time_sleep is mocked too: a mocked apply never waits 90 s.
mock_provider "time" {}

variables {
  resource_group_name = "RG-IDENTITY-LAB"
  location            = "eastus"
  catalog_ids         = { clinical = "66666666-6666-6666-6666-666666666666" }
}

run "narrowest_grant_on_the_given_catalogs_only" {
  command = apply
  assert {
    condition     = length(azuread_access_package_catalog_role_assignment.assignment_manager) == 1
    error_message = "one catalog role assignment per catalog id"
  }
  assert {
    condition     = azuread_access_package_catalog_role_assignment.assignment_manager["clinical"].role_id == "e2182095-804a-4656-ae11-64734e9b7ae5"
    error_message = "the role must be Access package assignment manager (not catalog owner)"
  }
  assert {
    condition     = azuread_access_package_catalog_role_assignment.assignment_manager["clinical"].catalog_id == "66666666-6666-6666-6666-666666666666"
    error_message = "the grant is scoped to the given catalog"
  }
  assert {
    condition     = azuread_access_package_catalog_role_assignment.assignment_manager["clinical"].principal_object_id == "99999999-9999-9999-9999-999999999999"
    error_message = "the grant must go to the Logic App's managed identity"
  }
  assert {
    condition     = time_sleep.identity_replication.create_duration == "90s" && time_sleep.identity_replication.triggers["principal_object_id"] == "99999999-9999-9999-9999-999999999999"
    error_message = "the catalog role must wait for the new managed identity to replicate (SubjectNotFound, as for the ServiceNow fulfilment SP)"
  }
  assert {
    condition     = azuread_app_role_assignment.entitlement_management_readwrite.app_role_id == "9acd699f-1e81-4958-b001-93b1d2506e19" && azuread_app_role_assignment.entitlement_management_readwrite.resource_object_id == "12121212-1212-1212-1212-121212121212" && azuread_app_role_assignment.entitlement_management_readwrite.principal_object_id == "99999999-9999-9999-9999-999999999999"
    error_message = "E183: the Logic App identity gets exactly Graph EntitlementManagement.ReadWrite.All (app-only), read through the replication wait; never Directory.* or another role"
  }
  assert {
    condition     = output.principal_id == "99999999-9999-9999-9999-999999999999"
    error_message = "principal_id comes from the deployment output"
  }
}

run "workflow_contract" {
  command = plan
  assert {
    condition     = jsondecode(file("${path.module}/logic-app.json")).resources[0].identity.type == "SystemAssigned"
    error_message = "system-assigned managed identity only (no secret, no user-assigned identity)"
  }
  assert {
    condition = alltrue([
      for c in jsondecode(file("${path.module}/logic-app.json")).resources[0].properties.accessControl.triggers.openAuthenticationPolicies.policies.AzureADLifecycleWorkflowsAuthPOPAuthPolicy.claims :
      c.value == "ce79fdc4-cd1d-4ea5-8139-e74d7dbe0bb7" if c.name == "appid"
    ]) && jsondecode(file("${path.module}/logic-app.json")).resources[0].properties.accessControl.triggers.openAuthenticationPolicies.policies.AzureADLifecycleWorkflowsAuthPOPAuthPolicy.type == "AADPOP"
    error_message = "the trigger accepts only the Lifecycle Workflows app's PoP token"
  }
  assert {
    condition     = !strcontains(file("${path.module}/logic-app.json"), "callbackUriPath\"]") && !strcontains(file("${path.module}/logic-app.json"), "lifecycleEvent")
    error_message = "fire-and-forget: no callback (the identity holds no Lifecycle Workflows permission)"
  }
  assert {
    condition     = length(regexall("\"requestType\": \"([a-zA-Z]+)\"", file("${path.module}/logic-app.json"))) == 1 && strcontains(file("${path.module}/logic-app.json"), "\"requestType\": \"adminRemove\"")
    error_message = "the only request the workflow sends is adminRemove"
  }
  assert {
    condition     = jsondecode(file("${path.module}/logic-app.json")).resources[0].properties.definition.actions.Check_subject_id.actions.Every_page.type == "Until" && strcontains(file("${path.module}/logic-app.json"), "@odata.nextLink")
    error_message = "every page of the user's assignments is visited (Until loop on @odata.nextLink), not just the first"
  }
  assert {
    condition     = strcontains(file("${path.module}/logic-app.json"), "automaticRequestSettings")
    error_message = "only assignments made by an automatic policy are removed"
  }
}

run "rejects_an_empty_catalog_list" {
  command = plan
  variables {
    catalog_ids = {}
  }
  expect_failures = [var.catalog_ids]
}
