# Offline, mocked tests for the lab operator (envs/operator). No Azure call:
#   tofu init -backend=false && tofu test
#
# What these pin: the credential is a CERTIFICATE (no secret, no federated
# credential); tokens are v2 and the App ID URI is api://<client id> (what the
# AWS trust expects); single-tenant only. ADR 0030: standing rights are
# read-only (no Owner, no Graph write); writes exist only in an open,
# at-most-8-hour session; the session role can't touch locks, role
# assignments or evidence; the workload CA policy is off and report-only.

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
        "SecurityEvents.Read.All"                              = "bf394140-e372-4bf9-a898-299cfc7564e5"
        "AccessReview.ReadWrite.All"                           = "ef5f7d5c-338f-44b0-86c3-351f46c8bb5f"
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
  mock_data "azurerm_role_definition" {
    defaults = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7" }
  }
  mock_resource "azurerm_role_definition" {
    defaults = { role_definition_resource_id = "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleDefinitions/99999999-9999-9999-9999-999999999999" }
  }
  mock_resource "azuread_named_location" {
    defaults = { id = "66666666-6666-6666-6666-666666666666" }
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
    # No session open (the default): only the standing, read-only set.
    condition     = toset(keys(azuread_app_role_assignment.operator)) == toset(var.operator_graph_roles)
    error_message = "without a write session, exactly the standing Graph roles are granted"
  }
  assert {
    condition     = length([for r in keys(azuread_app_role_assignment.operator) : r if can(regex("ReadWrite|DeleteRestore|Create$", r))]) == 0
    error_message = "ADR 0030: no standing Graph WRITE permission"
  }
  assert {
    # ADR 0025: eligibility write only in a session; no PrivilegedAssignmentSchedule
    # role anywhere, which could make a member ACTIVE without an activation.
    condition     = contains(var.operator_session_graph_roles, "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup") && length([for r in concat(var.operator_graph_roles, var.operator_session_graph_roles) : r if startswith(r, "PrivilegedAssignmentSchedule.")]) == 0
    error_message = "PIM groups: eligibility write in the session set only; never a PrivilegedAssignmentSchedule role"
  }
  assert {
    condition     = contains(var.operator_graph_roles, "SecurityEvents.Read.All") && !contains(concat(var.operator_graph_roles, var.operator_session_graph_roles), "SecurityEvents.ReadWrite.All")
    error_message = "Secure Score: SecurityEvents.Read.All only (no SecurityEvents.ReadWrite.All)"
  }
  assert {
    condition     = contains(var.operator_session_graph_roles, "AccessReview.ReadWrite.All") && contains(var.operator_graph_roles, "AccessReview.Read.All")
    error_message = "access reviews: Read standing (the report scripts' scope check), ReadWrite in a session"
  }
  assert {
    condition     = toset(keys(azurerm_role_assignment.operator)) == toset(["Reader", "Storage Blob Data Contributor", "Key Vault Secrets User"])
    error_message = "standing Azure roles: Reader, Storage Blob Data Contributor, Key Vault Secrets User (no Owner, ADR 0030)"
  }
  assert {
    condition     = alltrue([for r in azurerm_role_assignment.operator : r.scope == "/subscriptions/00000000-0000-0000-0000-000000000001"])
    error_message = "Azure roles are granted on the lab subscription only"
  }
  assert {
    condition     = length(azurerm_pim_active_role_assignment.operator_session) == 0 && length(terraform_data.operator_write_session_window) == 0
    error_message = "no write session by default: no time-bound Azure assignment"
  }
  assert {
    condition     = toset(keys(azuread_directory_role_assignment.operator)) == toset(["Security Reader"])
    error_message = "the only directory role is Security Reader"
  }
  assert {
    # The app REQUESTS every permission it may hold, so a session never
    # changes the app object.
    condition     = length(one(azuread_application.operator.required_resource_access).resource_access) == length(distinct(concat(var.operator_graph_roles, var.operator_session_graph_roles)))
    error_message = "the app requests the standing and the session permissions"
  }
}

# The session role can never remove a lock, write a role assignment, or
# erase evidence (finding E1: fork F3's CanNotDelete lock depends on this).
run "session_role_cannot_touch_locks_roles_or_evidence" {
  command = plan

  assert {
    condition = alltrue([for a in [
      "Microsoft.Authorization/*/Delete",
      "Microsoft.Authorization/*/Write",
      "Microsoft.Authorization/elevateAccess/Action",
      "Microsoft.Storage/storageAccounts/delete",
      "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/delete",
      "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write",
      "Microsoft.OperationalInsights/workspaces/delete",
    ] : contains(one(azurerm_role_definition.operator_session.permissions).not_actions, a)])
    error_message = "the session role must exclude lock/role-assignment writes and deletes, and the evidence and log deletes"
  }
  assert {
    condition     = azurerm_role_definition.operator_session.assignable_scopes == tolist(["/subscriptions/00000000-0000-0000-0000-000000000001"])
    error_message = "the session role is assignable on the lab subscription only"
  }
}

run "session_open_adds_writes_time_bound" {
  command = apply

  variables {
    operator_write_session = {
      opened_utc  = "2099-01-01T09:00:00Z"
      expires_utc = "2099-01-01T13:00:00Z"
      reason      = "test: recording day resets"
    }
  }

  assert {
    condition     = toset(keys(azuread_app_role_assignment.operator)) == toset(concat(var.operator_graph_roles, var.operator_session_graph_roles))
    error_message = "an open session grants the standing set plus the session writes"
  }
  assert {
    condition     = toset(keys(azurerm_pim_active_role_assignment.operator_session)) == toset(["Contoso Lab Operator Session", "Key Vault Secrets Officer"])
    error_message = "an open session adds the custom session role and Key Vault Secrets Officer"
  }
  assert {
    condition     = alltrue([for a in azurerm_pim_active_role_assignment.operator_session : one(one(a.schedule).expiration).end_date_time == "2099-01-01T13:00:00Z"])
    error_message = "every Azure session assignment ends at expires_utc (time-bound active)"
  }
  assert {
    condition     = !contains(keys(azurerm_role_assignment.operator), "Owner")
    error_message = "a session never brings back Owner"
  }
}

run "session_longer_than_8h_is_refused" {
  command = plan

  variables {
    operator_write_session = {
      opened_utc  = "2099-01-01T09:00:00Z"
      expires_utc = "2099-01-01T17:00:01Z"
      reason      = "test: too long a window"
    }
  }

  expect_failures = [var.operator_write_session]
}

run "expired_session_fails_the_plan" {
  command = plan

  variables {
    operator_write_session = {
      opened_utc  = "2000-01-01T09:00:00Z"
      expires_utc = "2000-01-01T10:00:00Z"
      reason      = "test: a stale session"
    }
  }

  expect_failures = [terraform_data.operator_write_session_window]
}

run "standing_owner_is_refused" {
  command = plan

  variables {
    operator_azure_roles = ["Owner", "Storage Blob Data Contributor"]
  }

  expect_failures = [var.operator_azure_roles]
}

run "standing_graph_write_is_refused" {
  command = plan

  variables {
    operator_graph_roles = ["Directory.Read.All", "AppRoleAssignment.ReadWrite.All"]
  }

  expect_failures = [var.operator_graph_roles]
}

run "workload_ca_off_by_default" {
  command = plan

  assert {
    condition     = length(azuread_conditional_access_policy.operator_location) == 0 && length(azuread_named_location.operator_network) == 0
    error_message = "the workload CA policy is DESIGNED and off (no Workload ID Premium licence)"
  }
}

run "workload_ca_when_licensed_starts_report_only" {
  command = apply

  variables {
    enable_operator_workload_ca = true
    operator_allowed_ip_ranges  = ["203.0.113.10/32"]
  }

  assert {
    condition     = azuread_conditional_access_policy.operator_location[0].state == "enabledForReportingButNotEnforced"
    error_message = "the workload CA policy starts report-only (ADR 0003)"
  }
  assert {
    condition     = one(one(azuread_conditional_access_policy.operator_location[0].conditions).client_applications).included_service_principals == tolist(["33333333-3333-3333-3333-333333333333"])
    error_message = "the policy targets exactly the operator service principal"
  }
  assert {
    condition     = one(azuread_conditional_access_policy.operator_location[0].grant_controls).built_in_controls == tolist(["block"])
    error_message = "a workload identity policy can only block"
  }
}

run "workload_ca_needs_ip_ranges" {
  command = plan

  variables {
    enable_operator_workload_ca = true
  }

  expect_failures = [var.enable_operator_workload_ca]
}

# ADR 0018 (Tier-0 identities): the operator never has an Entra owner - an
# owner could add a credential and act as it. owners is an explicit empty
# list on the app and the service principal.
run "operator_has_no_entra_owner" {
  command = plan

  assert {
    condition     = length(azuread_application.operator.owners) == 0 && length(azuread_service_principal.operator.owners) == 0
    error_message = "the operator must have no Entra owner (accountable owner: the Identity Platform Owner role, lab/iga/nhi-owners.json)"
  }
}
