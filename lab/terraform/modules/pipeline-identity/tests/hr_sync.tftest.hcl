# (Repeated-digit placeholder ids only: the public release gate allows no
# other GUID.)
# Offline guard for the federated subjects and the opt-in HR-SYNC identity
# (no tenant):
#   terraform init -backend=false && terraform test
# Pins: PLAN trusts exactly pull_request + the main ref (config-drift) and stays
# read-only; HR-SYNC does not exist by default; when enabled it trusts only the
# hr-feed branch ref, holds one upload permission plus read-only log roles,
# and with the default "owned" scope is made an owner of the HR provisioning
# app.

mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "00000000-0000-0000-0000-000000000000"
      app_role_ids = {
        "User.Read.All"                               = "11111111-1111-1111-1111-111111111111"
        "Group.Read.All"                              = "22222222-2222-2222-2222-222222222222"
        "Policy.Read.All"                             = "33333333-3333-3333-3333-333333333333"
        "EntitlementManagement.Read.All"              = "44444444-4444-4444-4444-444444444444"
        "RoleManagement.Read.Directory"               = "55555555-5555-5555-5555-555555555555"
        "RoleManagementPolicy.Read.AzureADGroup"      = "66666666-6666-6666-6666-666666666666"
        "RoleManagementPolicy.Read.Directory"         = "6d6d6d6d-6d6d-6d6d-6d6d-6d6d6d6d6d6d"
        "AdministrativeUnit.Read.All"                 = "a0a0a0a0-0000-4000-8000-00000000000a"
        "AdministrativeUnit.ReadWrite.All"            = "a0a0a0a0-0000-4000-8000-00000000000b"
        "Application.Read.All"                        = "77777777-7777-7777-7777-777777777777"
        "User.ReadWrite.All"                          = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        "Group.ReadWrite.All"                         = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        "Policy.ReadWrite.ConditionalAccess"          = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        "EntitlementManagement.ReadWrite.All"         = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        "RoleManagement.ReadWrite.Directory"          = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        "RoleManagementPolicy.ReadWrite.AzureADGroup" = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        # HR-SYNC
        "SynchronizationData-User.Upload.OwnedBy" = "88888888-8888-8888-8888-888888888888"
        "SynchronizationData-User.Upload"         = "99999999-9999-9999-9999-999999999999"
        "AuditLog.Read.All"                       = "a0a0a0a0-0000-4000-8000-00000000000c"
        "ProvisioningLog.Read.All"                = "a0a0a0a0-0000-4000-8000-00000000000d"
      }
    }
  }
  mock_data "azuread_application" {
    defaults = {
      object_id = "a0a0a0a0-0000-4000-8000-00000000000e"
    }
  }
}

variables {
  github_owner    = "example-owner"
  github_repo     = "example-repo"
  github_owner_id = "1234567"
  github_repo_id  = "7654321"
}

run "plan_trusts_pull_request_and_main_only" {
  command = plan

  assert {
    condition     = azuread_application_federated_identity_credential.plan_pr.subject == "repo:example-owner@1234567/example-repo@7654321:pull_request"
    error_message = "PLAN must trust same-repo pull requests"
  }
  # config-drift.yml runs on main (schedule / workflow_dispatch): without this
  # credential every scheduled run fails azure/login with AADSTS700213.
  assert {
    condition     = output.plan_main_federated_subject == "repo:example-owner@1234567/example-repo@7654321:ref:refs/heads/main"
    error_message = "PLAN must also trust the main-branch ref (config-drift)"
  }
  assert {
    condition     = alltrue([for r in output.plan_graph_roles : !strcontains(r, "Write") && !strcontains(r, "Upload")])
    error_message = "PLAN must stay read-only"
  }
  assert {
    condition     = output.apply_federated_subject == "repo:example-owner@1234567/example-repo@7654321:environment:prod"
    error_message = "APPLY must trust only the prod environment"
  }
}

run "hr_sync_off_by_default" {
  command = plan

  assert {
    condition     = length(azuread_application.hr_sync) == 0 && length(azuread_application_owner.hr_sync_owns_provisioning_app) == 0
    error_message = "HR-SYNC must not exist unless hr_sync_enabled"
  }
  assert {
    condition     = output.hr_sync_application_client_id == null && length(output.hr_sync_graph_roles) == 0
    error_message = "HR-SYNC outputs must be empty when disabled"
  }
}

run "hr_sync_owned_scope" {
  command = plan

  variables {
    hr_sync_enabled               = true
    hr_provisioning_app_client_id = "a0a0a0a0-0000-4000-8000-00000000000f"
  }

  assert {
    condition     = output.hr_sync_federated_subject == "repo:example-owner@1234567/example-repo@7654321:ref:refs/heads/hr-feed"
    error_message = "HR-SYNC must trust exactly the hr-feed branch ref (immutable owner/repo form)"
  }
  assert {
    condition     = output.hr_sync_graph_roles == tolist(["AuditLog.Read.All", "SynchronizationData-User.Upload.OwnedBy"])
    error_message = "HR-SYNC (owned) = the .OwnedBy upload + the provisioning-log read, nothing else"
  }
  assert {
    condition     = length(azuread_app_role_assignment.hr_sync) == 2
    error_message = "every HR-SYNC role must be granted (app role assignment)"
  }
  assert {
    condition     = azuread_application_owner.hr_sync_owns_provisioning_app[0].application_id == "/applications/a0a0a0a0-0000-4000-8000-00000000000e"
    error_message = ".OwnedBy needs HR-SYNC to own the HR provisioning app (looked up by client id)"
  }
  assert {
    condition     = alltrue([for r in output.hr_sync_graph_roles : !startswith(r, "Application.") && !strcontains(r, "ReadWrite")])
    error_message = "HR-SYNC must never hold an Application.* or ReadWrite role (ownership must stay inert)"
  }
}

run "hr_sync_tenant_scope" {
  command = plan

  variables {
    hr_sync_enabled              = true
    hr_sync_upload_scope         = "tenant"
    hr_sync_log_read_graph_roles = ["ProvisioningLog.Read.All"]
  }

  assert {
    condition     = output.hr_sync_graph_roles == tolist(["ProvisioningLog.Read.All", "SynchronizationData-User.Upload"])
    error_message = "tenant scope = the tenant-wide upload; the log role is swappable"
  }
  assert {
    condition     = length(azuread_application_owner.hr_sync_owns_provisioning_app) == 0
    error_message = "tenant scope needs no ownership of the provisioning app"
  }
}

run "hr_sync_owned_needs_the_provisioning_app" {
  command = plan

  variables {
    hr_sync_enabled = true
  }

  expect_failures = [azuread_application.hr_sync]
}

run "hr_sync_branch_cannot_be_main" {
  command = plan

  variables {
    hr_sync_enabled      = true
    hr_sync_upload_scope = "tenant"
    hr_sync_branch       = "main"
  }

  expect_failures = [var.hr_sync_branch]
}

run "hr_sync_log_roles_are_read_only" {
  command = plan

  variables {
    hr_sync_enabled              = true
    hr_sync_upload_scope         = "tenant"
    hr_sync_log_read_graph_roles = ["Application.ReadWrite.OwnedBy"]
  }

  expect_failures = [var.hr_sync_log_read_graph_roles]
}
