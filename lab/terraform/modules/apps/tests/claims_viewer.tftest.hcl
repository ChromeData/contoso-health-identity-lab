# Offline, mocked tests for the Contoso Claims Viewer (claims_viewer.tf), the
# app the AD FS -> Entra migration moves (lab/adfs):
#   terraform init -backend=false && terraform test
#
# What these pin:
#   * flag off (default) = nothing planned, outputs null;
#   * flag on = non-gallery SAML app, assignment required, identifier
#     urn:contoso:claims-viewer, the SAME reply URL the AD FS relying party
#     uses, its own signing certificate, two app roles, one claims-mapping
#     policy and exactly two role assignments (one per AD group);
#   * the claims-mapping policy IS the converted AD FS rules: every claim type
#     in lab/adfs/compare/claims-contract.json is emitted (the role claim via
#     the app roles), rule 4 is ExtractMailPrefix on the UPN, and the basic
#     claim set is off (nothing extra reaches the app);
#   * the flag without the group ids, or a name instead of an id, fails.

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
  mock_resource "azuread_application_app_role" {
    defaults = { id = "/applications/12121212-1212-1212-1212-121212121212/appRoles/6f0f6a52-3c39-4e57-9a8d-2c1f9f1d7a01" }
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
  app_owner_object_ids      = ["66666666-6666-6666-6666-666666666666", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
}

run "claims_viewer_absent_by_default" {
  command = plan

  assert {
    condition = (
      length(azuread_application_from_template.claims_viewer) == 0
      && length(azuread_service_principal.claims_viewer) == 0
      && length(azuread_application_app_role.claims_viewer) == 0
      && length(azuread_claims_mapping_policy.claims_viewer) == 0
      && length(azuread_app_role_assignment.claims_viewer) == 0
      && length(azuread_service_principal_token_signing_certificate.claims_viewer) == 0
    )
    error_message = "no Claims Viewer object may be planned unless enable_claims_viewer_app = true"
  }
  assert {
    condition     = output.claims_viewer_client_id == null && output.claims_viewer_saml_signing_cert_activation_command == null
    error_message = "Claims Viewer outputs must be null while the flag is off"
  }
}

run "claims_viewer_on_plans_the_converted_app" {
  command = plan

  variables {
    enable_claims_viewer_app                 = true
    claims_viewer_clinicians_group_object_id = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"
    claims_viewer_admins_group_object_id     = "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2"
  }

  assert {
    condition     = azuread_service_principal.claims_viewer[0].preferred_single_sign_on_mode == "saml" && azuread_service_principal.claims_viewer[0].app_role_assignment_required
    error_message = "the Claims Viewer must be a SAML app with assignment required (= AD FS 'Permit specific group')"
  }
  assert {
    condition     = azuread_application_identifier_uri.claims_viewer[0].identifier_uri == "urn:contoso:claims-viewer"
    error_message = "the Entra identifier must equal the AD FS relying party identifier"
  }
  assert {
    condition     = azuread_application_redirect_uris.claims_viewer[0].redirect_uris == toset(["https://localhost:8443/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp"])
    error_message = "the reply URL must be exactly the AD FS relying party's assertion consumer URL"
  }
  assert {
    condition     = toset([for r in azuread_application_app_role.claims_viewer : r.value]) == toset(["ClaimsViewer.Clinician", "ClaimsViewer.Admin"])
    error_message = "the app roles must carry the role values AD FS rules 3a/3b issued"
  }
  assert {
    condition = (
      azuread_app_role_assignment.claims_viewer["clinician"].principal_object_id == "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"
      && azuread_app_role_assignment.claims_viewer["admin"].principal_object_id == "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2"
      && length(azuread_app_role_assignment.claims_viewer) == 2
    )
    error_message = "exactly one role assignment per AD group, nothing else"
  }
  assert {
    condition = (
      jsondecode(azuread_claims_mapping_policy.claims_viewer[0].definition[0]).ClaimsMappingPolicy.IncludeBasicClaimSet == "false"
      && toset([for c in jsondecode(azuread_claims_mapping_policy.claims_viewer[0].definition[0]).ClaimsMappingPolicy.ClaimsSchema : c.SamlClaimType]) == toset([
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "urn:contoso:claims:department",
        "urn:contoso:claims:employeeid",
        "urn:contoso:claims:shortname",
      ])
    )
    error_message = "the claims-mapping policy must emit exactly the contract's claim types (role comes from the app roles), with the basic claim set off"
  }
  assert {
    condition = one([
      for t in jsondecode(azuread_claims_mapping_policy.claims_viewer[0].definition[0]).ClaimsMappingPolicy.ClaimsTransformations : t
      if t.ID == "ShortName" && t.TransformationMethod == "ExtractMailPrefix" && t.InputClaims[0].ClaimTypeReferenceId == "userprincipalname"
    ]) != null
    error_message = "AD FS rule 4 (RegExReplace upn '@.*$') must be ExtractMailPrefix(userprincipalname)"
  }
  assert {
    condition     = length(azuread_service_principal_claims_mapping_policy_assignment.claims_viewer) == 1 && length(azuread_service_principal_token_signing_certificate.claims_viewer) == 1
    error_message = "the policy must be assigned, and the app must have its own signing key (needed for the upn and role claim types)"
  }
}

run "claims_viewer_without_groups_fails" {
  command = plan

  variables {
    enable_claims_viewer_app = true
  }

  expect_failures = [azuread_application_from_template.claims_viewer]
}

run "claims_viewer_group_name_instead_of_id_is_refused" {
  command = plan

  variables {
    enable_claims_viewer_app                 = true
    claims_viewer_clinicians_group_object_id = "GRP-ClaimsViewer-Clinicians"
    claims_viewer_admins_group_object_id     = "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2"
  }

  expect_failures = [var.claims_viewer_clinicians_group_object_id]
}
