# =============================================================================
# modules/apps :: servicenow_fulfilment.tf
# -----------------------------------------------------------------------------
# 8. ServiceNow access fulfilment (enable_servicenow_fulfilment, off by
#    default) - the identity ServiceNow uses to ask Entra ID Governance to add
#    or remove a person on an access package, after the manager approved the
#    request in ServiceNow (lab/servicenow/README.md, use case 1).
#
#      app registration "ServiceNow - Access Fulfilment"
#        -> NO Microsoft Graph API permission at all
#        -> a certificate credential (public half only, from
#           files/servicenow-fulfilment.pem; the private key exists only in
#           the ServiceNow instance's key store - lab/servicenow/fulfilment-cert.py)
#        -> ONE entitlement-management role: "Access package assignment
#           manager" on ONE catalog (Clinical)
#
# WHY A CATALOG ROLE AND NOT A GRAPH PERMISSION. Microsoft Graph,
# "Create accessPackageAssignmentRequest" (v1.0, Permissions, read
# 2026-11-07): "In app-only scenarios, the calling app can be assigned one of
# the preceding supported roles instead of the EntitlementManagement.ReadWrite.All
# application permission. The Access package assignment manager role is less
# privileged". The role "can assign users and remove users" on existing
# packages of its catalog and "cannot create or edit access packages" (Learn,
# "Delegation and roles in entitlement management"). So ServiceNow cannot:
# read the directory, change a group, edit a package or a policy, or touch
# another catalog. Verified live 2026-11-07 on a throwaway twin of this app
# (deleted after): the token carries no `roles` claim; adminAdd and
# adminRemove in the Clinical catalog succeed; reads only succeed when they
# name a package of the catalog (assignmentRequests/{id} alone -> 403).
#
# Role id: GET /roleManagement/entitlementManagement/roleDefinitions, read
# live 2026-11-07: e2182095-804a-4656-ae11-64734e9b7ae5 "AccessPackage
# assignment manager" (a built-in, the same id in every tenant).
#
# RESIDUAL RISK (accepted, risk register): the role covers the WHOLE Clinical
# catalog, so a compromised ServiceNow could assign the Pharmacy package too.
# Bounded by: Entra still enforces the incompatible packages (seen live:
# Marcus, ICU, refused Pharmacy), every assignment carries the ServiceNow
# ticket number in its justification and lands in the Entra audit log
# (Sentinel reads it), and requestable packages expire (180 days max).
#
# WHY NO CLIENT SECRET. Certificate credentials are Microsoft's
# recommendation for confidential clients; ServiceNow signs a 5-minute
# client_assertion JWT itself (jwt_provider), so no reusable password exists
# anywhere, and the private key never leaves the instance.
#
# ROTATION: lab/servicenow/fulfilment-cert.py writes a new key into
# ServiceNow and a new PEM here -> PR -> apply. 180 days, like the lab's
# other key credentials.
# =============================================================================

locals {
  servicenow_fulfilment_enabled = var.enable_servicenow_fulfilment

  # Built-in entitlement-management role (header).
  access_package_assignment_manager_role_id = "e2182095-804a-4656-ae11-64734e9b7ae5"
}

resource "azuread_application" "servicenow_fulfilment" {
  count = local.servicenow_fulfilment_enabled ? 1 : 0

  display_name     = var.servicenow_fulfilment_app_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.app_owners
  notes            = "Contoso Health lab: ServiceNow asks Entra ID Governance to add/remove people on access packages after a manager approves in ServiceNow. No Graph permission; one catalog role (Access package assignment manager, Clinical). Certificate only; the private key lives in ServiceNow. Managed by Terraform - modules/apps (servicenow_fulfilment.tf)."

  lifecycle {
    precondition {
      condition     = var.servicenow_fulfilment_catalog_id != ""
      error_message = "enable_servicenow_fulfilment = true needs servicenow_fulfilment_catalog_id (module.entitlement catalog_id): the app's only power is a role on that catalog."
    }
  }
}

# Public half of the key ServiceNow signs with. Not a secret (the repo is
# public on purpose); the PEM's own validity sets the credential's dates.
resource "azuread_application_certificate" "servicenow_fulfilment" {
  count = local.servicenow_fulfilment_enabled ? 1 : 0

  application_id = azuread_application.servicenow_fulfilment[0].id
  type           = "AsymmetricX509Cert"
  value          = file("${path.module}/files/servicenow-fulfilment.pem")
}

resource "azuread_service_principal" "servicenow_fulfilment" {
  count = local.servicenow_fulfilment_enabled ? 1 : 0

  client_id = azuread_application.servicenow_fulfilment[0].client_id
  owners    = local.app_owners
  # Nobody signs in to this app: an app-only client. Assignment required
  # means no user could ever get a token for it either.
  app_role_assignment_required = true
  tags                         = ["HideApp", "WindowsAzureActiveDirectoryIntegratedApp"]
  notes                        = "ServiceNow -> Entra ID Governance (assignment requests). See modules/apps/servicenow_fulfilment.tf."
}

# WAIT FOR THE NEW SERVICE PRINCIPAL TO REPLICATE. Entitlement management
# reads principals from its own replica of the directory. Right after the SP
# is created it does not know it yet and refuses the role assignment with
# "SubjectNotFound: The subject was not found" (400). Seen twice:
#   * 2026-11-07, the throwaway twin, by hand: refused 10 s after the SP was
#     created, accepted on the retry ~15 s later;
#   * 2026-11-08, the catch-up apply (run 42512070374): the SP was created in
#     the same run and the assignment failed with SubjectNotFound.
# The azuread provider does not retry this error, so the assignment waits
# here. 90 s is about six times the gap seen by hand. The sleep is keyed to
# the SP's object id: it runs again only when the SP is replaced, never on
# routine applies. If replication is slower than that, the apply fails as
# before and a re-run succeeds (nothing is created half-way).
resource "time_sleep" "servicenow_fulfilment_sp_replication" {
  count = local.servicenow_fulfilment_enabled ? 1 : 0

  create_duration = "90s"
  triggers = {
    service_principal_object_id = azuread_service_principal.servicenow_fulfilment[0].object_id
  }
}

resource "azuread_access_package_catalog_role_assignment" "servicenow_fulfilment" {
  count = local.servicenow_fulfilment_enabled ? 1 : 0

  role_id = local.access_package_assignment_manager_role_id
  # Read through the sleep, so the assignment cannot start before it ends.
  principal_object_id = time_sleep.servicenow_fulfilment_sp_replication[0].triggers["service_principal_object_id"]
  catalog_id          = var.servicenow_fulfilment_catalog_id
}
