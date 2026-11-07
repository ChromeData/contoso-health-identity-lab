# Offline mocked plan of envs/bootstrap (no tenant, no state):
#   terraform init -backend=false && terraform test
# Pins the two opt-in widenings: nothing is added by default, the
# app-management roles land on APPLY (write) and PLAN (read-only) only when
# enable_app_management_roles is set, and the Identity Protection categories
# join the Entra diagnostic setting only when enable_identity_protection_logs
# is set; HR-SYNC (hr-feed.yml's identity) exists only with enable_hr_sync,
# EVIDENCE (evidence-pack.yml's) only with enable_evidence_pack, with ONE
# create-only grant on the evidence container, PIM-Demo-Readers' three
# read-only subscription roles only with enable_pim_demo_readers_azure_rbac,
# and the PLAN main-ref credential (config-drift) is always there.
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
        "RoleAssignmentSchedule.Read.Directory"          = "9a9a9a9a-0000-4000-8000-00000000009a"
        "Directory.Read.All"                             = "77777777-7777-7777-7777-777777777777"
      }
    }
  }
  # The HR provisioning app HR-SYNC is made an owner of (looked up by client id).
  mock_data "azuread_application" {
    defaults = { object_id = "a0a0a0a0-0000-4000-8000-00000000000e" }
  }
  # PIM-Demo-Readers, looked up by the object id envs/dev printed.
  mock_data "azuread_group" {
    defaults = { object_id = "d0d0d0d0-0000-4000-8000-00000000000d", display_name = "PIM-Demo-Readers", assignable_to_role = true }
  }
}
mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id              = "/subscriptions/22222222-2222-2222-2222-222222222222"
      subscription_id = "22222222-2222-2222-2222-222222222222"
      tenant_id       = "33333333-3333-3333-3333-333333333333"
    }
  }
  mock_resource "azurerm_key_vault" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab-cicd/providers/Microsoft.KeyVault/vaults/kv-idlab-cicd-test" }
  }
  mock_resource "azurerm_role_definition" {
    defaults = { role_definition_resource_id = "/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/6c1f3d2e-8a47-4b9e-9c35-2f6a0e7b4d91" }
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
  assert {
    condition     = length(azurerm_role_assignment.pim_demo_readers) == 0 && length(output.pim_demo_readers_azure_role_assignment_ids) == 0
    error_message = "PIM-Demo-Readers gets no Azure role by default"
  }
  assert {
    condition     = length(module.azure_guardrails) == 0 && output.azure_guardrails == null
    error_message = "no Azure Policy guardrail is assigned by default"
  }
  assert {
    condition     = length(azurerm_key_vault.pipeline_config) == 0 && length(azurerm_role_assignment.pipeline_config_reader) == 0 && output.pipeline_config_vault_name == null
    error_message = "the pipeline config vault must not exist by default"
  }
  # Least privilege (least-privilege.tf): default keeps the first-deploy
  # subscription scope; nothing else is created.
  assert {
    condition     = azurerm_role_assignment.apply_contributor.scope == "/subscriptions/22222222-2222-2222-2222-222222222222" && azurerm_role_assignment.apply_rbac_admin_constrained.scope == "/subscriptions/22222222-2222-2222-2222-222222222222"
    error_message = "APPLY keeps subscription scope by default (first deployment)"
  }
  assert {
    condition     = length(azurerm_role_definition.lab_vm_operator) == 0 && length(azurerm_pim_eligible_role_assignment.lab_vm_operator) == 0 && length(azurerm_management_lock.cannot_delete) == 0
    error_message = "no custom role, eligibility or lock by default"
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
    condition     = output.pipeline_graph_roles.evidence == tolist(["AccessReview.Read.All", "AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All", "PrivilegedAssignmentSchedule.Read.AzureADGroup", "RoleAssignmentSchedule.Read.Directory", "RoleManagement.Read.Directory"])
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

run "pim_demo_readers_azure_rbac_opt_in" {
  command = plan

  variables {
    enable_pim_demo_readers_azure_rbac = true
    pim_demo_readers_group_object_id   = "d0d0d0d0-0000-4000-8000-00000000000d"
  }

  assert {
    condition = (
      length(azurerm_role_assignment.pim_demo_readers) == 3 &&
      azurerm_role_assignment.pim_demo_readers["reader"].role_definition_id == "/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7" &&
      azurerm_role_assignment.pim_demo_readers["sentinel_reader"].role_definition_id == "/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/8d289c81-5878-46d4-8554-54e1e3d8b5cb" &&
      azurerm_role_assignment.pim_demo_readers["log_analytics_reader"].role_definition_id == "/subscriptions/22222222-2222-2222-2222-222222222222/providers/Microsoft.Authorization/roleDefinitions/73c42c96-874c-492b-b04d-ab87d138a893"
    )
    error_message = "exactly Reader, Microsoft Sentinel Reader and Log Analytics Reader, pinned by built-in role id (Learn, Azure built-in roles)"
  }
  assert {
    condition = alltrue([for a in values(azurerm_role_assignment.pim_demo_readers) :
      a.scope == "/subscriptions/22222222-2222-2222-2222-222222222222" &&
      a.principal_id == "d0d0d0d0-0000-4000-8000-00000000000d" &&
      a.principal_type == "Group" &&
      a.condition == null
    ])
    error_message = "subscription scope, the PIM GROUP as principal (never a person)"
  }
  assert {
    condition = alltrue([for a in values(azurerm_role_assignment.pim_demo_readers) : !contains([
      "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
      "b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
      "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", # User Access Administrator
      "f58310d9-a9f6-439a-9e8d-f62e7b41a168", # Role Based Access Control Administrator
    ], reverse(split("/", a.role_definition_id))[0])])
    error_message = "nothing that can write or grant access"
  }
  assert {
    condition     = !strcontains(local.delegable_role_ids, "acdd72a7-3385-48ef-bd42-f606fba81ae7") && !strcontains(local.delegable_role_ids, "73c42c96-874c-492b-b04d-ab87d138a893") && !strcontains(local.delegable_role_ids, "8d289c81-5878-46d4-8554-54e1e3d8b5cb")
    error_message = "the APPLY identity's delegable roles must not be widened to the read roles (the grant is made here, by a human)"
  }
}

run "pim_demo_readers_azure_rbac_needs_the_group" {
  command = plan

  variables {
    enable_pim_demo_readers_azure_rbac = true
  }

  expect_failures = [data.azuread_group.pim_demo_readers]
}

run "pim_demo_readers_azure_rbac_refuses_an_ordinary_group" {
  command = plan

  variables {
    enable_pim_demo_readers_azure_rbac = true
    pim_demo_readers_group_object_id   = "d0d0d0d0-0000-4000-8000-00000000000d"
  }

  override_data {
    target = data.azuread_group.pim_demo_readers
    values = { object_id = "d0d0d0d0-0000-4000-8000-00000000000d", display_name = "PIM-Demo-Readers", assignable_to_role = false }
  }

  expect_failures = [data.azuread_group.pim_demo_readers]
}

run "pim_demo_readers_group_id_must_be_a_guid" {
  command = plan

  variables {
    enable_pim_demo_readers_azure_rbac = true
    pim_demo_readers_group_object_id   = "PIM-Demo-Readers"
  }

  expect_failures = [var.pim_demo_readers_group_object_id]
}

# Azure Policy guardrails: opt-in, Audit by default, Deny only with allowed
# Owners (the module's precondition, reached through this root).
run "azure_guardrails_opt_in_audits_first" {
  command = plan

  variables {
    enable_azure_guardrails = true
  }

  assert {
    condition     = length(module.azure_guardrails) == 1 && output.azure_guardrails.effects.standing_owner == "Audit" && output.azure_guardrails.effects.keyvault_protection == "Audit"
    error_message = "enable_azure_guardrails assigns both guardrails, in Audit"
  }
}

# (A Deny with nobody allowed is refused by the module's precondition:
# modules/azure-guardrails/tests, run deny_with_nobody_allowed_is_refused.)
run "azure_guardrails_effect_typo_is_refused" {
  command = plan

  variables {
    enable_azure_guardrails = true
    standing_owner_effect   = "deny"
  }

  expect_failures = [var.standing_owner_effect]
}

# Pipeline config vault (pipeline-config.tf): the five privacy values the
# workflows read over OIDC instead of from GitHub secrets.
run "pipeline_config_vault_opt_in" {
  command = plan

  variables {
    enable_pipeline_config_vault = true
    pipeline_config_vault_name   = "kv-idlab-cicd-test"
    log_analytics_workspace_id   = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
  }

  assert {
    condition     = azurerm_key_vault.pipeline_config[0].rbac_authorization_enabled && azurerm_key_vault.pipeline_config[0].purge_protection_enabled
    error_message = "the pipeline config vault is RBAC-only and purge-protected"
  }
  assert {
    condition     = azurerm_resource_group.pipeline_config[0].name == "rg-identity-lab-cicd"
    error_message = "the vault lives in its own RG, not in rg-identity-lab (APPLY's) or the locked tfstate RG"
  }
  # Exactly PLAN and APPLY, read-only (Key Vault Secrets User by id), nobody else.
  assert {
    condition = (
      length(azurerm_role_assignment.pipeline_config_reader) == 2
      && alltrue([for a in azurerm_role_assignment.pipeline_config_reader : endswith(a.role_definition_id, "/4633458b-17de-408a-b874-0445c86b69e6")])
    )
    error_message = "only PLAN and APPLY may read the vault, with Key Vault Secrets User"
  }
  assert {
    condition     = length(azurerm_role_assignment.pipeline_config_writer) == 0
    error_message = "no writer grant unless one is named"
  }
  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.pipeline_config) == 1
    error_message = "every read is logged to loga-idlab when the workspace is known"
  }
}

run "pipeline_config_vault_needs_a_valid_name" {
  command = plan

  variables {
    enable_pipeline_config_vault = true
    pipeline_config_vault_name   = ""
  }

  expect_failures = [azurerm_key_vault.pipeline_config]
}

run "pipeline_config_writer_is_a_named_human" {
  command = plan

  variables {
    enable_pipeline_config_vault      = true
    pipeline_config_vault_name        = "kv-idlab-cicd-test"
    pipeline_config_writer_object_ids = ["a0a0a0a0-0000-4000-8000-0000000000ab"]
  }

  assert {
    condition     = length(azurerm_role_assignment.pipeline_config_writer) == 1 && endswith(azurerm_role_assignment.pipeline_config_writer["a0a0a0a0-0000-4000-8000-0000000000ab"].role_definition_id, "/b86a8fe4-44ce-4948-aee5-eccb2c155cd7")
    error_message = "the named writer gets Key Vault Secrets Officer on the vault"
  }
}

# ---- Least privilege on Azure (least-privilege.tf) ----------------------------
run "apply_scope_resource_group_narrows_both_roles" {
  command = plan

  variables {
    apply_azure_scope = "resource_group"
  }

  assert {
    condition     = azurerm_role_assignment.apply_contributor.scope == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab"
    error_message = "APPLY's Contributor is on rg-identity-lab only"
  }
  assert {
    condition     = azurerm_role_assignment.apply_rbac_admin_constrained.scope == "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab" && azurerm_role_assignment.apply_rbac_admin_constrained.condition != ""
    error_message = "APPLY's RBAC Administrator is on rg-identity-lab only and keeps its ABAC condition"
  }
}

run "apply_scope_typo_is_refused" {
  command = plan

  variables {
    apply_azure_scope = "rg"
  }

  expect_failures = [var.apply_azure_scope]
}

run "lab_vm_operator_is_eligible_only_and_read_start_stop" {
  command = plan

  variables {
    enable_lab_vm_operator              = true
    lab_vm_operator_eligible_object_ids = ["a0a0a0a0-0000-4000-8000-0000000000aa"]
  }

  # No write and nothing on Microsoft.Network or Microsoft.Authorization.
  assert {
    condition = alltrue([
      for a in one(azurerm_role_definition.lab_vm_operator[0].permissions).actions :
      (endswith(a, "/read") || endswith(a, "/action")) && !startswith(a, "Microsoft.Network/") && !startswith(a, "Microsoft.Authorization/") && !strcontains(a, "runCommand") && !strcontains(a, "extensions")
    ])
    error_message = "Contoso Lab VM Operator may only read and run start/restart/deallocate/query actions"
  }
  assert {
    condition     = contains(one(azurerm_role_definition.lab_vm_operator[0].permissions).actions, "Microsoft.Compute/virtualMachines/start/action") && contains(one(azurerm_role_definition.lab_vm_operator[0].permissions).actions, "Microsoft.Compute/virtualMachines/deallocate/action")
    error_message = "the operations task is start and deallocate"
  }
  assert {
    condition     = azurerm_role_definition.lab_vm_operator[0].assignable_scopes == tolist(["/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab"])
    error_message = "the custom role is assignable only on the lab RG"
  }
  assert {
    condition     = length(azurerm_pim_eligible_role_assignment.lab_vm_operator) == 1 && one(azurerm_role_management_policy.lab_vm_operator[0].activation_rules).require_multifactor_authentication && one(azurerm_role_management_policy.lab_vm_operator[0].activation_rules).require_justification
    error_message = "one ELIGIBLE assignment, activation needs MFA and a reason"
  }
  assert {
    condition     = one(azurerm_role_management_policy.lab_vm_operator[0].active_assignment_rules).expiration_required
    error_message = "a direct active assignment of the role must expire"
  }
  # No access review covers named eligibility: it expires instead (Greptile P2).
  assert {
    condition     = one(azurerm_role_management_policy.lab_vm_operator[0].eligible_assignment_rules).expiration_required && one(azurerm_role_management_policy.lab_vm_operator[0].eligible_assignment_rules).expire_after == "P180D"
    error_message = "eligibility for the VM operator role must expire (default 180 days)"
  }
  assert {
    condition     = one(one(azurerm_pim_eligible_role_assignment.lab_vm_operator["a0a0a0a0-0000-4000-8000-0000000000aa"].schedule).expiration).duration_days == 180
    error_message = "each eligible assignment carries the same 180-day expiry"
  }
}

run "lab_vm_operator_activation_cap" {
  command = plan

  variables {
    enable_lab_vm_operator                  = true
    lab_vm_operator_eligible_object_ids     = ["a0a0a0a0-0000-4000-8000-0000000000aa"]
    lab_vm_operator_activation_max_duration = "PT8H"
  }

  expect_failures = [var.lab_vm_operator_activation_max_duration]
}

run "locks_cannot_delete_on_named_resources" {
  command = plan

  variables {
    cannot_delete_lock_resource_ids = {
      "kv-idlab" = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab-test"
    }
  }

  assert {
    condition     = azurerm_management_lock.cannot_delete["kv-idlab"].lock_level == "CanNotDelete" && azurerm_management_lock.cannot_delete["kv-idlab"].name == "lock-kv-idlab-cannot-delete"
    error_message = "a CanNotDelete lock on each named resource"
  }
}

run "no_lock_on_the_log_workspace" {
  command = plan

  variables {
    cannot_delete_lock_resource_ids = {
      "loga" = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab"
    }
  }

  expect_failures = [var.cannot_delete_lock_resource_ids]
}
