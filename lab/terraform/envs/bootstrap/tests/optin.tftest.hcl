# Offline mocked plan of envs/bootstrap (no tenant, no state):
#   terraform init -backend=false && terraform test
# Pins the two opt-in widenings: nothing is added by default, the
# app-management roles land on APPLY (write) and PLAN (read-only) only when
# enable_app_management_roles is set, and the Identity Protection categories
# join the Entra diagnostic setting only when enable_identity_protection_logs
# is set; HR-SYNC (hr-feed.yml's identity) exists only with enable_hr_sync,
# EVIDENCE (evidence-pack.yml's) only with enable_evidence_pack, with ONE
# create-only grant on the evidence container, and the PLAN main-ref
# credential (config-drift) is always there.
# Run with HashiCorp Terraform 1.16.5 (lab/terraform/README.md).

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
        "AdministrativeUnit.Read.All"                 = "a0a0a0a0-0000-4000-8000-00000000000a"
        "AdministrativeUnit.ReadWrite.All"            = "a0a0a0a0-0000-4000-8000-00000000000b"
        "Application.Read.All"                        = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        "Policy.ReadWrite.ApplicationConfiguration"   = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        "AppRoleAssignment.ReadWrite.All"             = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        "Synchronization.Read.All"                    = "00000000-0000-0000-0000-000000000000"
        "SynchronizationData-User.Upload.OwnedBy"     = "a0a0a0a0-0000-4000-8000-00000000000c"
        "AuditLog.Read.All"                           = "a0a0a0a0-0000-4000-8000-00000000000d"
        # EVIDENCE's other reads (repeated ids: the plan keys on role names).
        "AccessReview.Read.All"                          = "11111111-1111-1111-1111-111111111111"
        "PrivilegedAssignmentSchedule.Read.AzureADGroup" = "66666666-6666-6666-6666-666666666666"
        "Directory.Read.All"                             = "77777777-7777-7777-7777-777777777777"
      }
    }
  }
  # The HR provisioning app HR-SYNC is made an owner of (looked up by client id).
  mock_data "azuread_application" {
    defaults = { object_id = "a0a0a0a0-0000-4000-8000-00000000000e" }
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
  assert {
    condition     = output.github_oidc_hr_sync_client_id == null && output.github_oidc_subjects.hr_sync == null && length(output.pipeline_graph_roles.hr_sync) == 0
    error_message = "HR-SYNC must not exist by default"
  }
  assert {
    condition     = output.github_oidc_evidence_client_id == null && output.github_oidc_subjects.evidence == null && length(output.pipeline_graph_roles.evidence) == 0 && length(azurerm_role_assignment.evidence_writer) == 0
    error_message = "EVIDENCE (identity and storage grant) must not exist by default"
  }
  # config-drift.yml (schedule on main) signs in as PLAN: the main-ref
  # subject must be in every bootstrap apply, or it fails with AADSTS700213.
  assert {
    condition     = output.github_oidc_subjects.plan_main == "repo:example-owner@1000001/contoso-health-identity-lab@2000002:ref:refs/heads/main"
    error_message = "PLAN must trust the main-branch ref (config-drift)"
  }
}

run "hr_sync_opt_in" {
  command = plan

  variables {
    enable_hr_sync                = true
    hr_provisioning_app_client_id = "a0a0a0a0-0000-4000-8000-00000000000f"
  }

  assert {
    condition     = output.github_oidc_subjects.hr_sync == "repo:example-owner@1000001/contoso-health-identity-lab@2000002:ref:refs/heads/hr-feed"
    error_message = "HR-SYNC must trust exactly the hr-feed branch"
  }
  assert {
    condition     = output.pipeline_graph_roles.hr_sync == tolist(["AuditLog.Read.All", "SynchronizationData-User.Upload.OwnedBy"])
    error_message = "HR-SYNC = least-privileged upload (.OwnedBy) + provisioning-log read"
  }
  assert {
    condition     = alltrue([for r in output.pipeline_graph_roles.plan : !strcontains(r, "Write") && !strcontains(r, "Upload")])
    error_message = "enabling HR-SYNC must not widen the PLAN identity"
  }
  assert {
    condition     = length(azurerm_role_assignment.state) == 2 && !contains([for k, v in azurerm_role_assignment.state : k], "hr_sync")
    error_message = "HR-SYNC gets no Azure RBAC and no Terraform state access"
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

run "evidence_pack_opt_in" {
  command = plan

  variables {
    enable_evidence_pack          = true
    evidence_storage_account_name = "stidlabevidence"
  }

  override_data {
    target = data.azurerm_storage_account.evidence
    values = {
      id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence"
    }
  }

  assert {
    condition     = output.github_oidc_subjects.evidence == "repo:example-owner@1000001/contoso-health-identity-lab@2000002:ref:refs/heads/main"
    error_message = "EVIDENCE must trust exactly the main-branch ref"
  }
  assert {
    condition     = output.pipeline_graph_roles.evidence == tolist(["AccessReview.Read.All", "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "RoleManagement.Read.Directory"])
    error_message = "EVIDENCE = the six read-only Graph roles the evidence pack needs"
  }
  assert {
    condition     = azurerm_role_assignment.evidence_writer[0].scope == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Storage/storageAccounts/stidlabevidence/blobServices/default/containers/evidence"
    error_message = "the EVIDENCE grant must be scoped to the evidence container, not the account"
  }
  assert {
    condition     = azurerm_role_assignment.evidence_writer[0].role_definition_name == "Storage Blob Data Contributor" && azurerm_role_assignment.evidence_writer[0].principal_type == "ServicePrincipal" && azurerm_role_assignment.evidence_writer[0].condition_version == "2.0"
    error_message = "EVIDENCE gets Storage Blob Data Contributor as a service principal, with an ABAC condition"
  }
  assert {
    condition = alltrue([for a in ["blobs/delete", "blobs/write"] :
    strcontains(azurerm_role_assignment.evidence_writer[0].condition, "!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/${a}'})")])
    error_message = "the condition must deny delete AND write (overwrite) - only creating new blobs and reading stay allowed"
  }
  assert {
    condition     = !strcontains(azurerm_role_assignment.evidence_writer[0].condition, "add/action") && strcontains(azurerm_role_assignment.evidence_writer[0].condition, "StringNotEquals 'evidence'")
    error_message = "create (blobs/add/action) must stay allowed, and the denials must be pinned to the evidence container"
  }
  assert {
    condition     = length(azurerm_role_assignment.state) == 2 && !contains([for k, v in azurerm_role_assignment.state : k], "evidence")
    error_message = "EVIDENCE gets no Terraform state access"
  }
  assert {
    condition     = alltrue([for r in output.pipeline_graph_roles.plan : !strcontains(r, "Write")])
    error_message = "enabling EVIDENCE must not widen the PLAN identity"
  }
}

run "evidence_pack_needs_the_storage_account" {
  command = plan

  variables {
    enable_evidence_pack = true
  }

  expect_failures = [data.azurerm_storage_account.evidence]
}
