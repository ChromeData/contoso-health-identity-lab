# (Repeated-digit placeholder ids only: the public release gate allows no
# other GUID.)
# Offline guard for the PLAN identity's opt-in Graph roles (no tenant):
#   terraform init -backend=false && terraform test
# The PLAN identity is reachable from any same-repo pull request, so
# extra_plan_graph_roles is an ALLOW-list of read roles: write-capable roles
# whose names do not say "Write" must be refused too.

mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "00000000-0000-0000-0000-000000000000"
      app_role_ids = {
        "User.Read.All"                          = "11111111-1111-1111-1111-111111111111"
        "Group.Read.All"                         = "22222222-2222-2222-2222-222222222222"
        "Policy.Read.All"                        = "33333333-3333-3333-3333-333333333333"
        "EntitlementManagement.Read.All"         = "44444444-4444-4444-4444-444444444444"
        "RoleManagement.Read.Directory"          = "55555555-5555-5555-5555-555555555555"
        "RoleManagementPolicy.Read.AzureADGroup" = "66666666-6666-6666-6666-666666666666"
        "RoleManagementPolicy.Read.Directory"    = "6d6d6d6d-6d6d-6d6d-6d6d-6d6d6d6d6d6d"
        "Application.Read.All"                   = "77777777-7777-7777-7777-777777777777"
        "Synchronization.Read.All"               = "88888888-8888-8888-8888-888888888888"
        "User.ReadBasic.All"                     = "99999999-9999-9999-9999-999999999999"
        # apply identity defaults
        "User.ReadWrite.All"                          = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        "Group.ReadWrite.All"                         = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        "Policy.ReadWrite.ConditionalAccess"          = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        "EntitlementManagement.ReadWrite.All"         = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        "RoleManagement.ReadWrite.Directory"          = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        "RoleManagementPolicy.ReadWrite.AzureADGroup" = "ffffffff-ffff-ffff-ffff-ffffffffffff"
      }
    }
  }
}

variables {
  github_owner    = "example-owner"
  github_repo     = "example-repo"
  github_owner_id = "1234567"
  github_repo_id  = "7654321"
}

run "read_roles_are_accepted" {
  command = plan
  variables {
    extra_plan_graph_roles = ["Application.Read.All", "Synchronization.Read.All", "User.ReadBasic.All"]
  }
}

run "readwrite_role_is_refused" {
  command = plan
  variables {
    extra_plan_graph_roles = ["User.ReadWrite.All"]
  }
  expect_failures = [var.extra_plan_graph_roles]
}

run "invite_role_is_refused" {
  command = plan
  variables {
    extra_plan_graph_roles = ["User.Invite.All"]
  }
  expect_failures = [var.extra_plan_graph_roles]
}

run "create_role_is_refused" {
  command = plan
  variables {
    extra_plan_graph_roles = ["Group.Create"]
  }
  expect_failures = [var.extra_plan_graph_roles]
}

run "send_and_manage_roles_are_refused" {
  command = plan
  variables {
    extra_plan_graph_roles = ["Mail.Send", "Sites.Manage.All", "User.ManageIdentities.All", "User.DeleteRestore.All"]
  }
  expect_failures = [var.extra_plan_graph_roles]
}
