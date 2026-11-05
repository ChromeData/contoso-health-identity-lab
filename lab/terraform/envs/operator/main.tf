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
# RISK (accepted for the lab, ADR 0024): this is a TIER 0 identity.
# AppRoleAssignment.ReadWrite.All can grant any Graph permission to anything,
# and subscription Owner can grant any Azure role. Its power equals the human
# admin's, minus the portal. Compensating controls:
#   * certificate only, 90-day validity (new-operator-cert.sh), private key in
#     the login Keychain of one Mac; rotating = new cert + re-apply
#   * single-tenant app; the AWS role trusts only this exact subject and lives
#     only in the lab AWS account
#   * every sign-in is a service principal sign-in in Entra's log (Log
#     Analytics via envs/bootstrap's diagnostic setting) and every AWS session
#     is an AssumeRoleWithWebIdentity event in CloudTrail
#   * one kill switch for both clouds: lab/scripts/operator/kill-switch.sh
#     disables the service principal (no new Entra tokens = no new AWS
#     sessions either)
#   * this root is applied by a HUMAN only. The operator can technically write
#     it (Owner + Graph), so - like envs/bootstrap - this is a change-control
#     boundary, not a privilege boundary.
# =============================================================================

data "azurerm_subscription" "current" {}

locals {
  microsoft_graph_app_id = "00000003-0000-0000-c000-000000000000"
  certificate_path       = pathexpand(var.operator_certificate_path)

  # Named human owners (ADR 0018), on the app and its service principal. null
  # while none is named, so the provider plans no owners change.
  operator_owners = length(var.operator_owner_object_ids) > 0 ? distinct(var.operator_owner_object_ids) : null
}

data "azuread_service_principal" "msgraph" {
  client_id = local.microsoft_graph_app_id
}

resource "azuread_application" "operator" {
  display_name     = var.operator_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.operator_owners
  notes            = "Lab operator: unattended automation from the admin's Mac (certificate, Keychain). Managed by lab/terraform/envs/operator, human-applied. Kill switch: lab/scripts/operator/kill-switch.sh"

  # v2 access tokens (iss = login.microsoftonline.com/<tenant>/v2.0, aud =
  # this app's client id). The AWS IAM OIDC provider is registered for exactly
  # that issuer and audience.
  api {
    requested_access_token_version = 2
  }

  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(var.operator_graph_roles)
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
  for_each = toset(var.operator_graph_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.operator.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

resource "azurerm_role_assignment" "operator" {
  for_each = toset(var.operator_azure_roles)

  scope                = data.azurerm_subscription.current.id
  role_definition_name = each.value
  principal_id         = azuread_service_principal.operator.object_id
  principal_type       = "ServicePrincipal"
  description          = "Lab operator (lab/terraform/envs/operator, human-applied)."
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
