# Offline, mocked tests for the lab operator (envs/operator). No Azure call:
#   tofu init -backend=false && tofu test
#
# What these pin: the credential is a CERTIFICATE (no secret, no federated
# credential); tokens are v2 and the App ID URI is api://<client id> (what the
# AWS trust expects); every Graph role and Azure role in the defaults is
# granted, and nothing else; single-tenant only.

mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "44444444-4444-4444-4444-444444444444"
      app_role_ids = {
        "Application.ReadWrite.All"                            = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
        "AppRoleAssignment.ReadWrite.All"                      = "06b708a9-e830-4db3-a914-8e69da51d44f"
        "Directory.Read.All"                                   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        "Synchronization.ReadWrite.All"                        = "9b50c33d-700f-43b1-b2eb-87e89b703581"
        "AuditLog.Read.All"                                    = "b0afded3-3588-46d8-8b3d-9842eff778da"
        "EntitlementManagement.ReadWrite.All"                  = "9acd699f-1e81-4958-b001-93b1d2506e19"
        "Policy.Read.All"                                      = "246dd0d5-5bd0-4def-940b-0421030a5b68"
        "AccessReview.Read.All"                                = "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa"
        "LifecycleWorkflows.Read.All"                          = "7c67316a-232a-4b84-be22-cea2c0906404"
        "RoleEligibilitySchedule.Read.Directory"               = "ff278e11-4a33-4d0c-83d2-d01dc58929a5"
        "RoleManagementPolicy.Read.Directory"                  = "fdc4c997-9942-4479-bfcb-75a36d1138df"
        "RoleManagementPolicy.Read.AzureADGroup"               = "69e67828-780e-47fd-b28c-7b27d14864e6"
        "PrivilegedEligibilitySchedule.Read.AzureADGroup"      = "edb419d6-7edc-42a3-9345-509bfdf5d87c"
        "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup" = "618b6020-bca8-4de6-99f6-ef445fa4d857"
        "DeviceManagementManagedDevices.Read.All"              = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
        "DeviceManagementConfiguration.Read.All"               = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
        "User.DeleteRestore.All"                               = "eccc023d-eccf-4e7b-9683-8813ab36cecc"
        "AdministrativeUnit.ReadWrite.All"                     = "5eb59dd3-1da2-4329-8733-9dabdc435916"
        "RoleManagement.ReadWrite.Directory"                   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
        "LifecycleWorkflows.ReadWrite.All"                     = "5c505cf0-8424-4b8e-aa14-ee06e3bb23e3"
        "UserAuthenticationMethod.ReadWrite.All"               = "50483e42-d915-4231-9639-7fdb7fd190e5"
        "User.ReadWrite.All"                                   = "741f803b-c850-494e-b5df-cde7c675a1ca"
        "GroupMember.ReadWrite.All"                            = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695"
        "Team.Create"                                          = "23fc2474-f741-46ce-8465-674744c5c361"
        "TeamMember.ReadWrite.All"                             = "0121dc95-1b9f-4aed-8bac-58c5ac466691"
        "DelegatedPermissionGrant.ReadWrite.All"               = "8e8e4742-1d95-4f68-9d56-6ee75648c72a"
      }
    }
  }
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/55555555-5555-5555-5555-555555555555"
      client_id = "22222222-2222-2222-2222-222222222222"
    }
  }
  mock_resource "azuread_service_principal" {
    defaults = { object_id = "33333333-3333-3333-3333-333333333333" }
  }
  mock_resource "azuread_directory_role" {
    defaults = { template_id = "5d6b6bb7-de71-4623-b4af-96380a352509" }
  }
}

mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000001" }
  }
}

variables {
  subscription_id           = "00000000-0000-0000-0000-000000000001"
  tenant_id                 = "11111111-1111-1111-1111-111111111111"
  operator_certificate_path = "tests/fixtures/operator-test.crt"
}

run "certificate_only_single_tenant_v2" {
  command = apply

  assert {
    condition     = azuread_application_certificate.operator.type == "AsymmetricX509Cert"
    error_message = "the operator's only credential is a certificate"
  }
  assert {
    condition     = azuread_application.operator.sign_in_audience == "AzureADMyOrg"
    error_message = "the operator app must be single-tenant"
  }
  assert {
    condition     = one(azuread_application.operator.api).requested_access_token_version == 2
    error_message = "v2 tokens: the AWS trust is registered for the v2 issuer"
  }
  assert {
    condition     = azuread_application_identifier_uri.operator.identifier_uri == "api://22222222-2222-2222-2222-222222222222"
    error_message = "the App ID URI must be api://<client id> (the token audience AWS checks)"
  }
  assert {
    condition     = output.operator_token_scope == "api://22222222-2222-2222-2222-222222222222/.default"
    error_message = "the sign-in scripts ask for a token to the operator itself"
  }
}

run "grants_are_exactly_the_reviewed_lists" {
  command = apply

  assert {
    condition     = toset(keys(azuread_app_role_assignment.operator)) == toset(var.operator_graph_roles)
    error_message = "every reviewed Graph role, and only those, is granted"
  }
  assert {
    # ADR 0025: the operator may make someone ELIGIBLE for a PIM group, never
    # ACTIVE (activation stays the user's own MFA-backed request).
    condition     = contains(var.operator_graph_roles, "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup") && !contains(var.operator_graph_roles, "PrivilegedEligibilitySchedule.Read.AzureADGroup") && length([for r in var.operator_graph_roles : r if startswith(r, "PrivilegedAssignmentSchedule.")]) == 0
    error_message = "PIM groups: eligibility write only (it includes the read); no PrivilegedAssignmentSchedule role, which could make a member ACTIVE without an activation"
  }
  assert {
    condition     = toset(keys(azurerm_role_assignment.operator)) == toset(["Owner", "Storage Blob Data Contributor", "Key Vault Secrets Officer"])
    error_message = "Azure roles must be the three reviewed ones"
  }
  assert {
    condition     = alltrue([for r in azurerm_role_assignment.operator : r.scope == "/subscriptions/00000000-0000-0000-0000-000000000001"])
    error_message = "Azure roles are granted on the lab subscription only"
  }
  assert {
    condition     = toset(keys(azuread_directory_role_assignment.operator)) == toset(["Security Reader"])
    error_message = "the only directory role is Security Reader"
  }
}

# ADR 0018: the operator is Tier 0, so its owners are the lead's decision;
# by default no owners change is planned, and a named owner lands on both
# the app registration and the service principal.
run "owners_only_when_named" {
  command = plan

  assert {
    condition     = azuread_application.operator.owners == null && azuread_service_principal.operator.owners == null
    error_message = "no owners change unless operator_owner_object_ids names someone"
  }
}

run "named_owners_on_app_and_sp" {
  command = plan

  variables {
    operator_owner_object_ids = ["b0b0b0b0-0000-4000-8000-0000000000b1", "b0b0b0b0-0000-4000-8000-0000000000b2"]
  }

  assert {
    condition     = length(azuread_application.operator.owners) == 2 && toset(azuread_service_principal.operator.owners) == toset(azuread_application.operator.owners)
    error_message = "named owners go on the app registration and the service principal"
  }
}
