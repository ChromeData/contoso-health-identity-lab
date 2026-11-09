# =============================================================================
# modules/leaver-extension :: main.tf
# -----------------------------------------------------------------------------
# Closes the leaver gap for BIRTHRIGHT access packages (ADR 0029).
#
# Lifecycle Workflows' built-in task "Remove all access package assignments
# for user" does not remove an assignment that an AUTOMATIC assignment policy
# made (measured 2026-11-08: success reported, no entitlement event, the
# assignment kept its 72 h grace). An adminRemove request does remove it.
# So the scheduled leave-date leaver (post-apply/New-LifecycleWorkflows.ps1
# -IncludeLeaveDateLeaver -LeaverExtensionLogicAppName ...) calls this Logic
# App through a custom task extension, and the Logic App sends adminRemove
# for each delivered assignment whose policy is automatic.
#
# IDENTITY: the Logic App's SYSTEM-ASSIGNED managed identity. No secret,
# certificate or connection string exists anywhere.
# PERMISSION: entitlement management role "Access package assignment manager"
# (template e2182095-804a-4656-ae11-64734e9b7ae5, read from the tenant
# 2026-11-08) on the given catalogs only. Not EntitlementManagement.ReadWrite.All
# (tenant-wide: every catalog, policy and role), not any directory role.
#   verify: on the first run, that the catalog role is honoured for an
#   app-only (managed identity) token on assignments + assignmentRequests.
#   If Graph answers 403, the fallback is the application permission
#   EntitlementManagement.ReadWrite.All: that is a wider grant and needs a new
#   owner decision, not a silent change here.
# CALLER: only Lifecycle Workflows can start it. The trigger accepts only a
# Proof-of-Possession token from the Lifecycle Workflows app
# (ce79fdc4-cd1d-4ea5-8139-e74d7dbe0bb7, read from the tenant 2026-11-08) for
# exactly this workflow's ARM path (Learn, "Configure a Logic App for
# Lifecycle Workflow use", AADPOP policy). Fire-and-forget: there is no
# callback, so the identity needs no Lifecycle Workflows permission.
# COST: consumption plan, billed per action run. A leaver is a handful of
# actions; nothing runs, and nothing is billed, between leavers.
#
# The workflow is an ARM template (logic-app.json) because the AADPOP policy
# type is not exposed by azurerm_logic_app_workflow.
# =============================================================================

locals {
  # Entitlement management role template: "Access package assignment manager".
  access_package_assignment_manager_role_id = "e2182095-804a-4656-ae11-64734e9b7ae5"
}

resource "azurerm_resource_group_template_deployment" "logic_app" {
  name                = "lcw-leaver-extension"
  resource_group_name = var.resource_group_name
  deployment_mode     = "Incremental"
  template_content    = file("${path.module}/logic-app.json")
  parameters_content = jsonencode({
    name     = { value = var.name }
    location = { value = var.location }
    tags     = { value = var.tags }
  })
}

locals {
  principal_id = jsondecode(azurerm_resource_group_template_deployment.logic_app.output_content).principalId.value
}

# WAIT FOR THE NEW MANAGED IDENTITY TO REPLICATE. Entitlement management
# refuses a role assignment for a principal it has not seen yet with
# "SubjectNotFound" (400), and the azuread provider does not retry it. Seen
# in this repo for the ServiceNow fulfilment SP (modules/apps
# servicenow_fulfilment.tf: by hand 2026-11-07, run 42512070374). Same fix:
# 90 s, keyed to the identity's object id, so it waits only when the
# identity is new or replaced, never on routine applies. If replication is
# slower, the apply fails before the grant and a re-run succeeds.
resource "time_sleep" "identity_replication" {
  create_duration = "90s"
  triggers = {
    principal_object_id = local.principal_id
  }
}

resource "azuread_access_package_catalog_role_assignment" "assignment_manager" {
  for_each   = var.catalog_ids
  role_id    = local.access_package_assignment_manager_role_id
  catalog_id = each.value
  # Read through the sleep, so the grant cannot start before it ends.
  principal_object_id = time_sleep.identity_replication.triggers["principal_object_id"]
}

# APP-ONLY PERMISSION (ADR 0029, decision 2026-11-08 at the owner's
# discretion). The catalog role above is NOT honoured for an app-only token:
# in E183 Graph answered 403 to this identity on
# GET .../entitlementManagement/assignments in both runs. So the identity
# also gets the Graph application permission EntitlementManagement.ReadWrite.All.
# That permission is tenant-wide. The bounds are in the Logic App, not in
# Graph: only Lifecycle Workflows can start it (AADPOP trigger policy), it
# reads only the subject the workflow passes in, and its only write is
# adminRemove of that subject's delivered automatic-policy assignments
# (logic-app.json, pinned by tests/leaver_extension.tftest.hcl).
# The catalog role stays: it is what a delegated caller would use, and its
# removal would orphan the assignment run 42527718010 created.
data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
}

resource "azuread_app_role_assignment" "entitlement_management_readwrite" {
  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids["EntitlementManagement.ReadWrite.All"]
  principal_object_id = time_sleep.identity_replication.triggers["principal_object_id"]
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

