# Offline, mocked tests for modules/apps (no tenant, no network):
#   terraform init -backend=false && terraform test
# Run with HashiCorp Terraform (see lab/terraform/README.md): its mocks apply
# computed defaults at APPLY, so ids stay unknown at plan like a real first plan.
#
# What these pin:
#   * the AWS SAML app is assigned to exactly one principal - the App group -
#     with assignment required and SAML as the SSO mode;
#   * the wrong gallery template id is refused at plan;
#   * the OIDC app defines exactly Clinician / Pharmacist / Auditor, user-only,
#     app-assigned groups claim, no implicit flow;
#   * SCIM objects exist ONLY when enable_scim_provisioning is set, the job is
#     created stopped, and an apply that would write an empty SCIM token fails.

mock_provider "azuread" {
  mock_data "azuread_client_config" {
    defaults = {
      tenant_id = "11111111-1111-1111-1111-111111111111"
      client_id = "33333333-3333-3333-3333-333333333333"
      object_id = "44444444-4444-4444-4444-444444444444"
    }
  }
  # Must match the real template's name, or the template postcondition fails.
  mock_data "azuread_application_template" {
    defaults = {
      template_id  = "21ed01d2-ec13-4e9e-86c1-cd546719ebc4"
      display_name = "AWS IAM Identity Center (successor to AWS Single Sign-On)"
    }
  }
  # Path-form ids for the mocked APPLY run only (plan runs never see them):
  # the provider parses these ids on apply, so random strings would fail it.
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
  # The provider's claims-policy id is path-form; the assignment parses it.
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

run "saml_app_assigned_only_to_the_app_group" {
  command = plan

  assert {
    condition     = azuread_app_role_assignment.aws_users.principal_object_id == "55555555-5555-5555-5555-555555555555"
    error_message = "the AWS app must be assigned to App-AWS-IdentityCenter-Users"
  }
  # The only assignment resources in the module are the AWS one and the portal
  # map; with no portal grants configured, nothing else can target any app.
  assert {
    condition     = length(azuread_app_role_assignment.clinical_portal) == 0
    error_message = "no other app-role assignment may exist by default"
  }
  assert {
    condition     = azuread_service_principal.aws.app_role_assignment_required == true
    error_message = "the AWS enterprise app must require assignment (else every user can get a token)"
  }
  assert {
    condition     = azuread_service_principal.aws.preferred_single_sign_on_mode == "saml"
    error_message = "the AWS enterprise app must use SAML"
  }
  assert {
    condition     = contains(tolist(azuread_service_principal.aws.tags), "WindowsAzureActiveDirectoryIntegratedApp")
    error_message = "the adopted SP must keep the enterprise-app tag (the provider PATCHes tags from config)"
  }
  assert {
    condition     = contains(tolist(azuread_service_principal.aws.owners), "66666666-6666-6666-6666-666666666666") && contains(tolist(azuread_service_principal.aws.owners), "44444444-4444-4444-4444-444444444444")
    error_message = "owners must be the named human plus the Terraform identity"
  }
  # Owner ids are named people: the plan (and the public PR plan comment) must
  # show them as (sensitive value), never as GUIDs.
  assert {
    condition     = issensitive(var.app_owner_object_ids) && issensitive(azuread_service_principal.aws.owners) && issensitive(output.nhi_inventory)
    error_message = "app_owner_object_ids, the owners it feeds and the NHI inventory output must stay sensitive"
  }
  # Basic SAML URLs are staged: not managed until AWS values are supplied.
  assert {
    condition     = length(azuread_application_identifier_uri.aws) == 0 && length(azuread_application_redirect_uris.aws) == 0
    error_message = "identifier / reply URL must not be managed before the AWS values exist"
  }
}

run "saml_basic_configuration_and_claims" {
  command = plan

  variables {
    aws_saml_entity_id = "https://us-east-1.signin.aws.amazon.com/platform/saml/d-1234567890"
    aws_saml_acs_urls  = ["https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abcd-1234"]
  }

  assert {
    condition     = azuread_application_identifier_uri.aws[0].identifier_uri == "https://us-east-1.signin.aws.amazon.com/platform/saml/d-1234567890"
    error_message = "the Entity ID must be the AWS Issuer URL"
  }
  assert {
    condition     = azuread_application_redirect_uris.aws[0].redirect_uris == toset(["https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abcd-1234"]) && azuread_application_redirect_uris.aws[0].type == "Web"
    error_message = "the reply URL must be exactly the AWS ACS URL (no template wildcard)"
  }
  assert {
    condition     = strcontains(azuread_claims_mapping_policy.aws[0].definition[0], "\"ID\":\"userprincipalname\"") && strcontains(azuread_claims_mapping_policy.aws[0].definition[0], "claims/nameidentifier")
    error_message = "NameID must come from userPrincipalName (= the SCIM userName)"
  }
  assert {
    condition     = strcontains(azuread_claims_mapping_policy.aws[0].definition[0], "https://aws.amazon.com/SAML/Attributes/AccessControl:Department")
    error_message = "the Department ABAC session tag must be emitted"
  }
}

run "wildcard_reply_url_is_rejected" {
  command = plan

  variables {
    aws_saml_entity_id = "https://us-east-1.signin.aws.amazon.com/platform/saml/d-1234567890"
    aws_saml_acs_urls  = ["https://*.signin.aws.amazon.com/platform/saml/acs/*"]
  }

  expect_failures = [var.aws_saml_acs_urls]
}

run "wrong_gallery_template_is_refused" {
  command = plan

  override_data {
    target = data.azuread_application_template.aws
    values = {
      display_name = "Marketo"
    }
  }

  expect_failures = [data.azuread_application_template.aws]
}

run "claims_policy_can_be_turned_off" {
  command = plan

  variables {
    aws_saml_claims_policy_enabled = false
  }

  assert {
    condition     = length(azuread_claims_mapping_policy.aws) == 0 && length(azuread_service_principal_claims_mapping_policy_assignment.aws) == 0
    error_message = "the fallback (gallery default claims) must remove the policy and its assignment"
  }
}

run "oidc_app_defines_the_three_roles" {
  command = plan

  assert {
    condition     = toset([for r in azuread_application.clinical_portal.app_role : r.value]) == toset(["Clinician", "Pharmacist", "Auditor"])
    error_message = "Contoso Clinical Portal must define exactly Clinician, Pharmacist and Auditor"
  }
  assert {
    condition     = alltrue([for r in azuread_application.clinical_portal.app_role : r.allowed_member_types == toset(["User"]) && r.enabled])
    error_message = "every role must be enabled and assignable to users/groups only (no app-only grants)"
  }
  assert {
    condition     = azuread_application.clinical_portal.group_membership_claims == toset(["ApplicationGroup"])
    error_message = "the groups claim must be limited to groups assigned to the app"
  }
  assert {
    condition     = azuread_application.clinical_portal.web[0].implicit_grant[0].id_token_issuance_enabled == false && azuread_application.clinical_portal.web[0].implicit_grant[0].access_token_issuance_enabled == false
    error_message = "the implicit flow must stay off"
  }
  assert {
    condition     = azuread_service_principal.clinical_portal.app_role_assignment_required == true
    error_message = "the portal must require assignment"
  }
  assert {
    condition     = length(azuread_application_pre_authorized.azure_cli) == 0
    error_message = "the Azure CLI pre-authorization is a demo flag and must default off"
  }
}

run "group_grants_map_to_the_fixed_role_ids" {
  command = plan

  variables {
    clinical_portal_role_assignments = {
      pharmacy_pharmacist = { role = "Pharmacist", principal_object_id = "77777777-7777-7777-7777-777777777777" }
      nurses_clinician    = { role = "Clinician", principal_object_id = "88888888-8888-8888-8888-888888888888" }
    }
  }

  assert {
    condition     = azuread_app_role_assignment.clinical_portal["pharmacy_pharmacist"].app_role_id == output.clinical_portal_app_role_ids["Pharmacist"]
    error_message = "the Pharmacist grant must use the Pharmacist role id"
  }
  assert {
    condition     = azuread_app_role_assignment.clinical_portal["nurses_clinician"].principal_object_id == "88888888-8888-8888-8888-888888888888"
    error_message = "the Clinician grant must target the configured group"
  }
}

run "unknown_role_is_rejected" {
  command = plan

  variables {
    clinical_portal_role_assignments = {
      x = { role = "GlobalAdmin", principal_object_id = "77777777-7777-7777-7777-777777777777" }
    }
  }

  expect_failures = [var.clinical_portal_role_assignments]
}

run "scim_absent_by_default" {
  command = plan

  assert {
    condition     = length(azuread_synchronization_job.aws) == 0 && length(azuread_synchronization_secret.aws) == 0
    error_message = "no provisioning job or credential may exist unless enable_scim_provisioning = true"
  }
}

run "scim_on_creates_a_stopped_job_and_its_credential" {
  command = plan

  variables {
    enable_scim_provisioning = true
    aws_scim_template_id     = "placeholderTemplate"
    require_scim_credentials = true
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
  }

  assert {
    condition     = length(azuread_synchronization_job.aws) == 1 && length(azuread_synchronization_secret.aws) == 1
    error_message = "enable_scim_provisioning must create exactly one job and one credential"
  }
  assert {
    condition     = azuread_synchronization_job.aws[0].enabled == false
    error_message = "the job must be created STOPPED (Test Connection + on-demand first)"
  }
  assert {
    condition     = azuread_synchronization_job.aws[0].template_id == "placeholderTemplate"
    error_message = "the job must use the configured synchronization template"
  }
}

run "scim_needs_a_template_id" {
  command = plan

  variables {
    enable_scim_provisioning = true
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
  }

  expect_failures = [azuread_synchronization_job.aws]
}

run "gated_apply_refuses_an_empty_scim_credential" {
  command = plan

  variables {
    enable_scim_provisioning = true
    aws_scim_template_id     = "placeholderTemplate"
    require_scim_credentials = true
  }

  expect_failures = [azuread_synchronization_secret.aws]
}

run "pr_plan_without_the_token_only_warns" {
  command = plan

  variables {
    enable_scim_provisioning = true
    aws_scim_template_id     = "placeholderTemplate"
  }

  # The check block fails (a warning in a real plan); nothing else does.
  expect_failures = [check.scim_credential_supplied_on_create]
}

run "malformed_scim_endpoint_is_rejected" {
  command = plan

  variables {
    enable_scim_provisioning = true
    aws_scim_template_id     = "placeholderTemplate"
    aws_scim_credentials = {
      tenant_url   = "http://scim.example.com/v1"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
  }

  expect_failures = [var.aws_scim_credentials]
}

# guacamole-psm (guacamole.tf): absent by default; when on, it is a
# secret-less id_token sign-in that ONLY PAM-Operators can obtain.
run "guacamole_psm_absent_by_default" {
  command = plan

  assert {
    condition     = length(azuread_application.guacamole_psm) == 0 && length(azuread_group.pam_operators) == 0 && length(azuread_app_role_assignment.guacamole_pam_operators) == 0
    error_message = "no guacamole-psm objects may exist unless enable_guacamole_psm_app = true"
  }
  assert {
    condition     = output.nhi_inventory.guacamole_psm == null && output.guacamole_psm_client_id == null
    error_message = "the NHI inventory and outputs must not list guacamole-psm while it is off"
  }
}

run "guacamole_psm_is_id_token_only_and_operator_only" {
  command = plan

  variables {
    enable_guacamole_psm_app = true
  }

  assert {
    condition     = azuread_application.guacamole_psm[0].web[0].implicit_grant[0].id_token_issuance_enabled == true && azuread_application.guacamole_psm[0].web[0].implicit_grant[0].access_token_issuance_enabled == false
    error_message = "guacamole-psm must issue id tokens only (Guacamole's implicit id_token flow) - never access tokens"
  }
  assert {
    condition     = azuread_application.guacamole_psm[0].web[0].redirect_uris == toset(["http://localhost:8081/guacamole/"])
    error_message = "the redirect URI must equal OPENID_REDIRECT_URI in lab/pam/docker-compose.oidc.yml"
  }
  assert {
    condition     = azuread_application.guacamole_psm[0].sign_in_audience == "AzureADMyOrg" && azuread_application.guacamole_psm[0].group_membership_claims == toset(["ApplicationGroup"])
    error_message = "guacamole-psm must be single tenant and emit only app-assigned groups"
  }
  assert {
    condition     = azuread_service_principal.guacamole_psm[0].app_role_assignment_required == true
    error_message = "guacamole-psm must require assignment (else any user could open the PSM)"
  }
  assert {
    condition     = azuread_app_role_assignment.guacamole_pam_operators[0].app_role_id == "00000000-0000-0000-0000-000000000000"
    error_message = "PAM-Operators must be assigned with the default access role (the app defines no roles)"
  }
  assert {
    condition     = azuread_group.pam_operators[0].mail_nickname == "pam-operators" && azuread_group.pam_operators[0].security_enabled
    error_message = "PAM-Operators must be the security group pam-operators"
  }
  assert {
    condition     = output.nhi_inventory.guacamole_psm.credential_type == "none (implicit id_token sign-in, no client secret)"
    error_message = "the NHI inventory must record that guacamole-psm holds no credential"
  }
}

run "guacamole_wildcard_or_plain_http_redirect_is_rejected" {
  command = plan

  variables {
    enable_guacamole_psm_app = true
    guacamole_redirect_uris  = ["http://psm.contosohealth.io/guacamole/"]
  }

  expect_failures = [var.guacamole_redirect_uris]
}

# Everything on, through a mocked APPLY: exercises the provider's own id
# parsing (path-form SP / application / claims-policy ids) and the
# fall-back to the documented "User" role id when the SP reports no roles.
run "everything_on_mocked_apply" {
  command = apply

  variables {
    aws_saml_entity_id                     = "https://us-east-1.signin.aws.amazon.com/platform/saml/d-1234567890"
    aws_saml_acs_urls                      = ["https://us-east-1.signin.aws.amazon.com/platform/saml/acs/abcd-1234"]
    aws_access_portal_url                  = "https://d-1234567890.awsapps.com/start"
    enable_scim_provisioning               = true
    aws_scim_template_id                   = "placeholderTemplate"
    require_scim_credentials               = true
    clinical_portal_preauthorize_azure_cli = true
    enable_guacamole_psm_app               = true
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
    clinical_portal_role_assignments = {
      pharmacy_pharmacist = { role = "Pharmacist", principal_object_id = "77777777-7777-7777-7777-777777777777" }
    }
  }

  assert {
    condition     = azuread_app_role_assignment.aws_users.app_role_id == "8774f594-1d59-4279-b9d9-59ef09a23530"
    error_message = "with no role reported by the SP, the documented gallery 'User' role id must be used"
  }
  assert {
    condition     = output.aws_saml_signing_cert_activation_command == "Update-MgServicePrincipal -ServicePrincipalId 99999999-9999-9999-9999-999999999999 -PreferredTokenSigningKeyThumbprint 0123456789ABCDEF0123456789ABCDEF01234567"
    error_message = "the activation command must name the AWS SP and the new certificate's thumbprint"
  }
  assert {
    condition     = output.clinical_portal_identifier_uri == "api://14141414-1414-1414-1414-141414141414"
    error_message = "the App ID URI must be api://<client-id>"
  }
}

# The APPLY identity owns the apps whoever runs the plan: a PR plan (run as
# PLAN, the mocked caller 4444...) must not try to make itself an owner.
run "apps_are_owned_by_the_apply_identity_not_the_caller" {
  command = plan

  variables {
    iac_owner_client_id = "77777777-7777-7777-7777-777777777777"
  }

  override_data {
    target = data.azuread_service_principal.iac_owner[0]
    values = {
      object_id = "88888888-8888-8888-8888-888888888888"
    }
  }

  assert {
    condition     = contains(tolist(azuread_service_principal.aws.owners), "88888888-8888-8888-8888-888888888888") && !contains(tolist(azuread_service_principal.aws.owners), "44444444-4444-4444-4444-444444444444")
    error_message = "owners must be the APPLY identity (looked up by client id), never the identity running the plan"
  }
  assert {
    condition     = contains(tolist(azuread_service_principal.aws.owners), "66666666-6666-6666-6666-666666666666")
    error_message = "the named human owner must stay"
  }
}
