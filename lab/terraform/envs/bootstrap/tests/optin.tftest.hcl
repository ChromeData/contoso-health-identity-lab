# Offline mocked plan of envs/bootstrap (no tenant, no state):
#   terraform init -backend=false && terraform test
# Pins the two opt-in widenings: nothing is added by default, the
# app-management roles land on APPLY (write) and PLAN (read-only) only when
# enable_app_management_roles is set, and the Identity Protection categories
# join the Entra diagnostic setting only when enable_identity_protection_logs
# is set. Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).

mock_provider "azuread" {
  # app_role_ids must name every role the module can grant, or the lookup
  # fails at plan exactly as a typo would in a real tenant. Repeated-digit
  # placeholder ids (the public repo's release gate allows only those); the
  # 17th role reuses one - the plan keys on role NAMES, not ids.
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "55555555-5555-5555-5555-555555555555"
      app_role_ids = {
        "User.Read.All"                               = "00000000-0000-0000-0000-000000000000"
        "Group.Read.All"                              = "11111111-1111-1111-1111-111111111111"
        "Policy.Read.All"                             = "22222222-2222-2222-2222-222222222222"
        "EntitlementManagement.Read.All"              = "33333333-3333-3333-3333-333333333333"
        "RoleManagement.Read.Directory"               = "44444444-4444-4444-4444-444444444444"
        "RoleManagementPolicy.Read.AzureADGroup"      = "55555555-5555-5555-5555-555555555555"
        "RoleManagementPolicy.Read.Directory"         = "6d6d6d6d-6d6d-6d6d-6d6d-6d6d6d6d6d6d"
        "User.ReadWrite.All"                          = "66666666-6666-6666-6666-666666666666"
        "Group.ReadWrite.All"                         = "77777777-7777-7777-7777-777777777777"
        "Policy.ReadWrite.ConditionalAccess"          = "88888888-8888-8888-8888-888888888888"
        "EntitlementManagement.ReadWrite.All"         = "99999999-9999-9999-9999-999999999999"
        "RoleManagement.ReadWrite.Directory"          = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        "RoleManagementPolicy.ReadWrite.AzureADGroup" = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        "Application.ReadWrite.OwnedBy"               = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        "Application.Read.All"                        = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        "Policy.ReadWrite.ApplicationConfiguration"   = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        "AppRoleAssignment.ReadWrite.All"             = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        "Synchronization.Read.All"                    = "00000000-0000-0000-0000-000000000000"
      }
    }
  }
}
mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id              = "/subscriptions/22222222-2222-2222-2222-222222222222"
      subscription_id = "22222222-2222-2222-2222-222222222222"
    }
  }
  mock_data "azurerm_storage_account" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab-tfstate/providers/Microsoft.Storage/storageAccounts/stidlabtfstate" }
  }
}

variables {
  github_owner                 = "example-owner"
  github_owner_id              = "1000001"
  github_repo_id               = "2000002"
  tfstate_storage_account_name = "stidlabtfstate"
  log_analytics_workspace_id   = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
}

run "defaults_add_nothing" {
  command = plan

  assert {
    condition     = !contains(module.pipeline_identity.apply_graph_roles, "AppRoleAssignment.ReadWrite.All") && !contains(module.pipeline_identity.apply_graph_roles, "Application.ReadWrite.OwnedBy")
    error_message = "the APPLY identity must not hold app-management roles by default"
  }
  assert {
    condition     = !contains(module.pipeline_identity.plan_graph_roles, "Application.Read.All")
    error_message = "the PLAN identity must not read applications by default"
  }
  assert {
    condition     = !contains(module.entra_diagnostics[0].categories, "RiskyUsers")
    error_message = "risk categories must not be exported by default"
  }
}

run "app_management_roles_opt_in" {
  command = plan

  variables {
    enable_app_management_roles = true
  }

  assert {
    condition     = alltrue([for r in ["Application.ReadWrite.OwnedBy", "Application.Read.All", "Policy.ReadWrite.ApplicationConfiguration", "AppRoleAssignment.ReadWrite.All"] : contains(module.pipeline_identity.apply_graph_roles, r)])
    error_message = "the APPLY identity must get the four modules/apps roles"
  }
  assert {
    condition     = alltrue([for r in ["Application.Read.All", "Synchronization.Read.All"] : contains(module.pipeline_identity.plan_graph_roles, r)])
    error_message = "the PLAN identity must get the two read roles"
  }
  assert {
    condition     = alltrue([for r in module.pipeline_identity.plan_graph_roles : !strcontains(r, "ReadWrite")])
    error_message = "the PLAN (pull_request) identity must never hold a write role"
  }
}

run "identity_protection_logs_opt_in" {
  command = plan

  variables {
    enable_identity_protection_logs = true
  }

  assert {
    condition     = alltrue([for c in ["RiskyUsers", "UserRiskEvents", "RiskyServicePrincipals", "ServicePrincipalRiskEvents", "AuditLogs", "SignInLogs"] : contains(module.entra_diagnostics[0].categories, c)])
    error_message = "the four risk categories must be added to (not replace) the baseline categories"
  }
  assert {
    condition     = module.entra_diagnostics[0].identity_protection_logs_enabled
    error_message = "the root flag must reach modules/entra-diagnostics' own enable_identity_protection_logs switch"
  }
}
