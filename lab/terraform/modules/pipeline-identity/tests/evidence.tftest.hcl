# (Repeated-digit placeholder ids only: the public release gate allows no
# other GUID.)
# Offline guard for the opt-in EVIDENCE identity (no tenant):
#   terraform init -backend=false && terraform test
# Pins: EVIDENCE does not exist by default; when enabled it trusts only the
# main-branch ref, holds exactly the six read-only Graph roles
# Export-EvidencePack.ps1 reads (each one granted), and a write role cannot
# be added to it. Its storage grant lives in envs/bootstrap (optin.tftest.hcl).

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
        # EVIDENCE (repeated ids are fine: the plan keys on role NAMES; the
        # six EVIDENCE roles have distinct ids among themselves)
        "AuditLog.Read.All"                              = "a0a0a0a0-0000-4000-8000-00000000000c"
        "AccessReview.Read.All"                          = "88888888-8888-8888-8888-888888888888"
        "PrivilegedAssignmentSchedule.Read.AzureADGroup" = "99999999-9999-9999-9999-999999999999"
        "Directory.Read.All"                             = "77777777-7777-7777-7777-777777777777"
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

run "evidence_off_by_default" {
  command = plan

  assert {
    condition     = length(azuread_application.evidence) == 0 && length(azuread_application_federated_identity_credential.evidence_main) == 0 && length(azuread_app_role_assignment.evidence) == 0
    error_message = "EVIDENCE must not exist unless evidence_enabled"
  }
  assert {
    condition     = output.evidence_application_client_id == null && output.evidence_federated_subject == null && length(output.evidence_graph_roles) == 0
    error_message = "EVIDENCE outputs must be empty when disabled"
  }
}

run "evidence_enabled" {
  command = plan

  variables {
    evidence_enabled = true
  }

  assert {
    condition     = output.evidence_federated_subject == "repo:example-owner@1234567/example-repo@7654321:ref:refs/heads/main"
    error_message = "EVIDENCE must trust exactly the main-branch ref (immutable owner/repo form)"
  }
  assert {
    condition     = output.evidence_graph_roles == tolist(["AccessReview.Read.All", "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "RoleManagement.Read.Directory"])
    error_message = "EVIDENCE = the six reads Export-EvidencePack.ps1 makes, nothing else"
  }
  assert {
    condition     = length(azuread_app_role_assignment.evidence) == 6
    error_message = "every EVIDENCE role must be granted (app role assignment)"
  }
  assert {
    condition     = alltrue([for r in output.evidence_graph_roles : !strcontains(r, "Write") && !startswith(r, "Application.") && !strcontains(r, "Upload")])
    error_message = "EVIDENCE must stay read-only in Graph"
  }
  assert {
    condition     = output.plan_graph_roles == tolist(["AdministrativeUnit.Read.All", "EntitlementManagement.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "RoleManagementPolicy.Read.AzureADGroup", "RoleManagementPolicy.Read.Directory", "User.Read.All"])
    error_message = "enabling EVIDENCE must not change the PLAN identity"
  }
}

run "evidence_roles_are_read_only" {
  command = plan

  variables {
    evidence_enabled     = true
    evidence_graph_roles = ["AuditLog.Read.All", "Directory.ReadWrite.All"]
  }

  expect_failures = [var.evidence_graph_roles]
}
