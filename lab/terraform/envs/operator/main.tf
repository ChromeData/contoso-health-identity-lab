# =============================================================================
# envs/operator :: main.tf
# -----------------------------------------------------------------------------
# WHAT: one non-human identity, the LAB OPERATOR, that the lab's automation on
# the admin's Mac signs in as - instead of borrowing the admin's own account.
#
#   * an app registration + service principal with a CERTIFICATE credential
#     (no client secret, no federated credential). The private key is made on
#     the Mac and kept in its login Keychain (lab/scripts/operator).
#   * Microsoft Graph application permissions, Azure RBAC on the lab
#     subscription and one Entra read role (variables.tf says why each).
#   * an App ID URI + v2 access tokens, so the same identity can sign in to
#     AWS: lab/terraform/aws/entra-operator.tf trusts Entra-issued tokens whose
#     subject is THIS service principal. One credential, one place to turn it
#     off - the same "everything trusts Entra" pattern as the rest of the lab.
#
# WHY: the admin account sits behind MFA and a 4-hour sign-in frequency
# (CA020), which is right for a person and makes unattended work impossible.
# Lowering that for the admin would weaken the control the lab demonstrates;
# a separate workload identity keeps CA020 intact and makes every unattended
# action attributable to "the operator" in the sign-in and audit logs.
#
# RISK (ADR 0024, cut down by ADR 0030 on 2026-11-06):
#   * STANDING, every day: read-only Graph permissions, Azure Reader, the
#     state data role and Key Vault Secrets User. No Owner, no role-assignment
#     or lock rights, no Graph write.
#   * WRITE SESSION, only when the owner opens one (write-session.tf): the
#     Graph writes (AppRoleAssignment.ReadWrite.All and
#     RoleManagement.ReadWrite.Directory make it TIER 0 for that window) and a
#     custom Azure role that is Contributor minus the evidence-store and log
#     deletes, as time-bound PIM assignments that end by themselves.
#   Compensating controls:
#   * certificate only, private key in the login Keychain of one Mac
#   * single-tenant app; the AWS role trusts only this exact subject
#   * every sign-in is a service principal sign-in in Entra's log, every AWS
#     session an AssumeRoleWithWebIdentity event in CloudTrail
#   * one kill switch for both clouds: lab/scripts/operator/kill-switch.sh
#   * this root is applied by the OWNER only. Without Owner on Azure, the
#     operator cannot apply it outside a session (role assignments need
#     roleAssignments/write). Inside a session the Graph writes could still
#     change its own grants: ADR 0030 records that as residual risk.
# =============================================================================

data "azurerm_subscription" "current" {}

locals {
  microsoft_graph_app_id = "00000003-0000-0000-c000-000000000000"
  certificate_path       = pathexpand(var.operator_certificate_path)

  # NO Entra owner, ever (ADR 0018, amendment "Tier-0 identities"): the
  # operator is Tier 0 and an owner could add a credential and act as it. Its
  # accountable owner is the Identity Platform Owner role in
  # lab/iga/nhi-owners.json. [] (not null): an owner added in the portal is
  # removed by the next apply, and 06-NHI-Inventory.ps1 flags it until then.
  operator_owners = []

  # Graph grants: the standing read set always; the write set only while a
  # session is open, in a SEPARATE resource (below) so closing a session
  # destroys exactly the write grants, and opening one grants them only after
  # Azure accepted the time-bound PIM assignments (fail closed).
  write_session_open            = var.operator_write_session != null
  operator_graph_grants         = toset(var.operator_graph_roles)
  operator_session_graph_grants = toset(local.write_session_open ? var.operator_session_graph_roles : [])

  # The app registration REQUESTS every permission it may ever hold, so a
  # session does not change the app object; requesting is not granting.
  operator_graph_requested = toset(concat(var.operator_graph_roles, var.operator_session_graph_roles))
}

data "azuread_service_principal" "msgraph" {
  client_id = local.microsoft_graph_app_id
}

resource "azuread_application" "operator" {
  display_name     = var.operator_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.operator_owners
  notes            = "Lab operator: unattended automation from the admin's Mac (certificate, Keychain). Standing rights are read-only; writes only in an owner-opened session (ADR 0030). Managed by lab/terraform/envs/operator, owner-applied. Kill switch: lab/scripts/operator/kill-switch.sh"

  # v2 access tokens (iss = login.microsoftonline.com/<tenant>/v2.0, aud =
  # this app's client id). The AWS IAM OIDC provider is registered for exactly
  # that issuer and audience.
  api {
    requested_access_token_version = 2
  }

  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = local.operator_graph_requested
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }

  lifecycle {
    # The identifier URI is a separate resource below (it needs the client id).
    ignore_changes = [identifier_uris]
  }
}

# api://<client id>: the default form, which tenant app-management policies
# always allow. The operator asks Entra for a token to ITSELF
# (api://<client id>/.default) and hands that token to AWS STS.
resource "azuread_application_identifier_uri" "operator" {
  application_id = azuread_application.operator.id
  identifier_uri = "api://${azuread_application.operator.client_id}"
}

resource "azuread_service_principal" "operator" {
  client_id = azuread_application.operator.client_id
  owners    = local.operator_owners
  notes     = azuread_application.operator.notes
}

# Public half only. Entra takes the validity window from the certificate
# itself; the tenant's app-management policy caps it at 180 days.
resource "azuread_application_certificate" "operator" {
  application_id = azuread_application.operator.id
  type           = "AsymmetricX509Cert"
  encoding       = "pem"
  value          = file(local.certificate_path)
}

resource "azuread_app_role_assignment" "operator" {
  for_each = local.operator_graph_grants

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.operator.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# Session Graph writes. depends_on: if Azure refuses a PIM assignment, the
# apply stops before any Graph write is granted.
resource "azuread_app_role_assignment" "operator_session" {
  for_each = local.operator_session_graph_grants

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.operator.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id

  depends_on = [azurerm_pim_active_role_assignment.operator_session]
}

resource "azurerm_role_assignment" "operator" {
  for_each = toset(var.operator_azure_roles)

  scope                = data.azurerm_subscription.current.id
  role_definition_name = each.value
  principal_id         = azuread_service_principal.operator.object_id
  principal_type       = "ServicePrincipal"
  description          = "Lab operator STANDING role (lab/terraform/envs/operator, owner-applied, ADR 0030)."
}

resource "azuread_directory_role" "operator" {
  for_each     = toset(var.operator_directory_roles)
  display_name = each.value
}

resource "azuread_directory_role_assignment" "operator" {
  for_each = toset(var.operator_directory_roles)

  role_id             = azuread_directory_role.operator[each.value].template_id
  principal_object_id = azuread_service_principal.operator.object_id
}

# Time box for the Intune write right (2026-11-08): the operator holds
# DeviceManagementConfiguration.ReadWrite.All, in sessions only, to create the
# EPM and LAPS policies while the E5 trial (which licenses EPM) lasts. Every
# plan after the trial's end warns until a PR removes it from the session list.
check "intune_write_time_box" {
  assert {
    condition     = !contains(var.operator_session_graph_roles, "DeviceManagementConfiguration.ReadWrite.All") || timecmp(plantimestamp(), var.intune_write_expires_utc) < 0
    error_message = "The E5 trial ended on 2026-11-26: remove DeviceManagementConfiguration.ReadWrite.All from operator_session_graph_roles and apply envs/operator (ADR 0024 / 0030)."
  }
}
