# Offline, mocked tests for the ServiceNow SAML app (servicenow.tf) - no
# tenant, no network:
#   terraform init -backend=false && terraform test
#
# What these pin:
#   * flag off (default) = NOTHING ServiceNow is planned, outputs are null;
#   * flag on = app (non-gallery template) + SP (SAML, assignment required)
#     + identifier/reply URL from servicenow_instance_url + Entra-minted
#     signing certificate + NameID = UPN claims policy + ONE assignment to
#     App-ServiceNow-Users;
#   * the identifier URI waits for the SP (SAML mode first);
#   * a wildcard, trailing slash, path, non-ServiceNow host or http URL is
#     refused, and the flag without a URL or group fails the plan;
#   * a mocked APPLY with everything on (provider id parsing, role fallback).

mock_provider "azuread" {
  mock_data "azuread_client_config" {
    defaults = {
      tenant_id = "11111111-1111-1111-1111-111111111111"
      client_id = "33333333-3333-3333-3333-333333333333"
      object_id = "44444444-4444-4444-4444-444444444444"
    }
  }
  # The AWS template data source is always read; it must keep its name.
  mock_data "azuread_application_template" {
    defaults = {
      template_id  = "21ed01d2-ec13-4e9e-86c1-cd546719ebc4"
      display_name = "AWS IAM Identity Center (successor to AWS Single Sign-On)"
    }
  }
  # Path-form ids for the mocked APPLY run (the provider parses them).
  mock_data "azuread_application" {
    defaults = { client_id = "15151515-1515-1515-1515-151515151515" }
  }
  mock_resource "azuread_application_from_template" {
    defaults = {
      application_id              = "/applications/12121212-1212-1212-1212-121212121212"
      application_object_id       = "12121212-1212-1212-1212-121212121212"
      service_principal_id        = "/servicePrincipals/99999999-9999-9999-9999-999999999999"
      service_principal_object_id = "99999999-9999-9999-9999-999999999999"
    }
  }
  mock_resource "azuread_service_principal" {
    defaults = {
      id        = "/servicePrincipals/99999999-9999-9999-9999-999999999999"
      object_id = "99999999-9999-9999-9999-999999999999"
      app_roles = []
    }
  }
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/13131313-1313-1313-1313-131313131313"
      object_id = "13131313-1313-1313-1313-131313131313"
      client_id = "14141414-1414-1414-1414-141414141414"
    }
  }
  mock_resource "azuread_claims_mapping_policy" {
    defaults = { id = "/policies/claimsMappingPolicies/16161616-1616-1616-1616-161616161616" }
  }
  mock_resource "azuread_group" {
    defaults = { object_id = "dddddddd-dddd-dddd-dddd-dddddddddddd" }
  }
  mock_resource "azuread_service_principal_token_signing_certificate" {
    defaults = {
      thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567"
      end_date   = "2029-10-20T00:00:00Z"
    }
  }
}

variables {
  aws_users_group_object_id = "55555555-5555-5555-5555-555555555555"
  app_owner_object_ids      = ["66666666-6666-6666-6666-666666666666"]
}

run "servicenow_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(azuread_application_from_template.servicenow) == 0
      && length(azuread_service_principal.servicenow) == 0
      && length(azuread_application_identifier_uri.servicenow) == 0
      && length(azuread_application_redirect_uris.servicenow) == 0
      && length(azuread_service_principal_token_signing_certificate.servicenow) == 0
      && length(azuread_claims_mapping_policy.servicenow) == 0
      && length(azuread_service_principal_claims_mapping_policy_assignment.servicenow) == 0
      && length(azuread_app_role_assignment.servicenow_users) == 0
    )
    error_message = "no ServiceNow object may be planned unless enable_servicenow_sso = true"
  }
  assert {
    condition     = output.nhi_inventory.servicenow == null && output.servicenow_service_principal_object_id == null && output.servicenow_federation_metadata_url == null && output.servicenow_saml_signing_cert_activation_command == null
    error_message = "ServiceNow outputs and the NHI inventory row must be null while the flag is off"
  }
  # The AWS app is unaffected by the new flag.
  assert {
    condition     = azuread_app_role_assignment.aws_users.principal_object_id == "55555555-5555-5555-5555-555555555555"
    error_message = "the AWS app must keep its single assignment"
  }
}

run "servicenow_on_plans_app_sp_assignment_and_cert" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://dev00000.service-now.com"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  assert {
    condition = (
      length(azuread_application_from_template.servicenow) == 1
      && length(azuread_service_principal.servicenow) == 1
      && length(azuread_app_role_assignment.servicenow_users) == 1
      && length(azuread_service_principal_token_signing_certificate.servicenow) == 1
    )
    error_message = "the flag must plan exactly one app, SP, assignment and signing certificate"
  }
  assert {
    condition     = azuread_application_from_template.servicenow[0].template_id == "8adf8e6e-67b2-4cf2-a259-e3dc5476c621" && azuread_application_from_template.servicenow[0].display_name == "ServiceNow"
    error_message = "the app must come from the documented NON-GALLERY template (global service) and be named ServiceNow"
  }
  assert {
    condition     = azuread_service_principal.servicenow[0].preferred_single_sign_on_mode == "saml" && azuread_service_principal.servicenow[0].app_role_assignment_required == true && azuread_service_principal.servicenow[0].use_existing == true
    error_message = "the enterprise app must adopt the template's SP, use SAML and require assignment"
  }
  assert {
    condition     = contains(tolist(azuread_service_principal.servicenow[0].tags), "WindowsAzureActiveDirectoryIntegratedApp") && contains(tolist(azuread_service_principal.servicenow[0].tags), "WindowsAzureActiveDirectoryCustomSingleSignOnApplication")
    error_message = "the adopted SP must keep the enterprise-app and custom-SAML tags (the provider PATCHes tags from config)"
  }
  assert {
    condition     = contains(tolist(azuread_service_principal.servicenow[0].owners), "66666666-6666-6666-6666-666666666666") && contains(tolist(azuread_service_principal.servicenow[0].owners), "44444444-4444-4444-4444-444444444444")
    error_message = "owners must be the named human plus the Terraform identity"
  }
  assert {
    condition     = azuread_application_identifier_uri.servicenow[0].identifier_uri == "https://dev00000.service-now.com"
    error_message = "the Identifier (Entity ID) must be the instance URL exactly (no trailing slash)"
  }
  assert {
    condition     = azuread_application_redirect_uris.servicenow[0].redirect_uris == toset(["https://dev00000.service-now.com/navpage.do"]) && azuread_application_redirect_uris.servicenow[0].type == "Web"
    error_message = "the Reply URL must be exactly <instance>/navpage.do - one URL, no wildcard"
  }
  assert {
    condition     = azuread_service_principal.servicenow[0].login_url == "https://dev00000.service-now.com/navpage.do"
    error_message = "without a sys_id the sign-on URL is the instance homepage"
  }
  assert {
    condition     = azuread_app_role_assignment.servicenow_users[0].principal_object_id == "77777777-7777-7777-7777-777777777777"
    error_message = "the ServiceNow app must be assigned to App-ServiceNow-Users only"
  }
  assert {
    condition     = azuread_service_principal_token_signing_certificate.servicenow[0].display_name == "CN=Contoso Health - ServiceNow SAML signing"
    error_message = "the signing certificate must be minted by Entra for the ServiceNow SP"
  }
  assert {
    condition = (
      length(azuread_claims_mapping_policy.servicenow) == 1
      && strcontains(azuread_claims_mapping_policy.servicenow[0].definition[0], "\"ID\":\"userprincipalname\"")
      && strcontains(azuread_claims_mapping_policy.servicenow[0].definition[0], "claims/nameidentifier")
      && length(azuread_service_principal_claims_mapping_policy_assignment.servicenow) == 1
    )
    error_message = "NameID must come from userPrincipalName (ServiceNow User Field = user_name)"
  }
  # Separate from the AWS objects: one SAML app per vendor, one cert each.
  assert {
    condition     = length(azuread_app_role_assignment.clinical_portal) == 0 && azuread_app_role_assignment.aws_users.principal_object_id == "55555555-5555-5555-5555-555555555555"
    error_message = "turning ServiceNow on must not add or change any other assignment"
  }
}

run "sign_on_url_uses_the_idp_sys_id" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://dev00000.service-now.com"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
    servicenow_sso_sys_id            = "0123456789abcdef0123456789abcdef"
  }

  assert {
    condition     = azuread_service_principal.servicenow[0].login_url == "https://dev00000.service-now.com/login_with_sso.do?glide_sso_id=0123456789abcdef0123456789abcdef"
    error_message = "with a sys_id the sign-on URL must target that ServiceNow IdP record"
  }
}

run "claims_policy_can_be_turned_off" {
  command = plan

  variables {
    enable_servicenow_sso                 = true
    servicenow_instance_url               = "https://dev00000.service-now.com"
    servicenow_users_group_object_id      = "77777777-7777-7777-7777-777777777777"
    servicenow_saml_claims_policy_enabled = false
  }

  assert {
    condition     = length(azuread_claims_mapping_policy.servicenow) == 0 && length(azuread_service_principal_claims_mapping_policy_assignment.servicenow) == 0 && length(azuread_service_principal.servicenow) == 1
    error_message = "the fallback (default claims) must remove only the policy and its assignment"
  }
}

run "flag_without_instance_url_fails_the_plan" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [azuread_application_from_template.servicenow]
}

run "flag_without_group_fails_the_plan" {
  command = plan

  variables {
    enable_servicenow_sso   = true
    servicenow_instance_url = "https://dev00000.service-now.com"
  }

  expect_failures = [azuread_app_role_assignment.servicenow_users]
}

run "wildcard_instance_url_is_rejected" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://*.service-now.com"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.servicenow_instance_url]
}

run "trailing_slash_is_rejected" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://dev00000.service-now.com/"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.servicenow_instance_url]
}

run "path_or_reply_url_as_instance_is_rejected" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://dev00000.service-now.com/navpage.do"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.servicenow_instance_url]
}

run "non_servicenow_or_http_host_is_rejected" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "http://dev00000.service-now.com.example.org"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  expect_failures = [var.servicenow_instance_url]
}

run "malformed_sys_id_is_rejected" {
  command = plan

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://dev00000.service-now.com"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
    servicenow_sso_sys_id            = "not-a-sys-id"
  }

  expect_failures = [var.servicenow_sso_sys_id]
}

# Everything ServiceNow on, through a mocked APPLY: the provider's own id
# parsing (path-form SP / application / claims-policy ids), the identifier
# waiting for the SP, the fall-back to the default-access role when the SP
# reports no roles, and the outputs built from the applied values.
run "servicenow_on_mocked_apply" {
  command = apply

  variables {
    enable_servicenow_sso                 = true
    servicenow_instance_url               = "https://dev00000.service-now.com"
    servicenow_users_group_object_id      = "77777777-7777-7777-7777-777777777777"
    servicenow_sso_sys_id                 = "0123456789abcdef0123456789abcdef"
    servicenow_saml_signing_cert_end_date = "2027-10-31T00:00:00Z"
  }

  assert {
    condition     = azuread_app_role_assignment.servicenow_users[0].app_role_id == "00000000-0000-0000-0000-000000000000"
    error_message = "with no role reported by the SP, the default-access role id must be used"
  }
  assert {
    condition     = output.servicenow_saml_signing_cert_activation_command == "Update-MgServicePrincipal -ServicePrincipalId 99999999-9999-9999-9999-999999999999 -PreferredTokenSigningKeyThumbprint 0123456789ABCDEF0123456789ABCDEF01234567"
    error_message = "the activation command must name the ServiceNow SP and its certificate's thumbprint"
  }
  assert {
    condition     = output.servicenow_federation_metadata_url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/federationmetadata/2007-06/federationmetadata.xml?appid=15151515-1515-1515-1515-151515151515"
    error_message = "the metadata URL must be the tenant's federation metadata for the ServiceNow app id"
  }
  assert {
    condition     = output.nhi_inventory.servicenow.credential_type == "saml-signing-certificate (Entra-held private key)" && output.nhi_inventory.servicenow.outbound_secret == "none (provisioning to ServiceNow designed, not built)"
    error_message = "the NHI inventory must list the ServiceNow app, its Entra-held signing key and no outbound secret"
  }
  assert {
    condition     = output.servicenow_assigned_group_object_id == "77777777-7777-7777-7777-777777777777"
    error_message = "the assigned principal output must be App-ServiceNow-Users"
  }
}

# The "User" role is preferred when the instantiated app carries one. Its own
# state: in the shared state the SP already exists from the run above, so the
# overridden roles would never be read.
run "servicenow_prefers_the_user_role" {
  command   = apply
  state_key = "servicenow_user_role"

  variables {
    enable_servicenow_sso            = true
    servicenow_instance_url          = "https://dev00000.service-now.com"
    servicenow_users_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  override_resource {
    target = azuread_service_principal.servicenow
    values = {
      id        = "/servicePrincipals/99999999-9999-9999-9999-999999999999"
      object_id = "99999999-9999-9999-9999-999999999999"
      app_roles = [
        { allowed_member_types = ["User"], description = "msiam_access", display_name = "msiam_access", enabled = true, id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", value = "" },
        { allowed_member_types = ["User"], description = "User", display_name = "User", enabled = true, id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", value = "" },
      ]
    }
  }

  assert {
    condition     = azuread_app_role_assignment.servicenow_users[0].app_role_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    error_message = "the assignment must use the app's own enabled User role when it exists"
  }
}
