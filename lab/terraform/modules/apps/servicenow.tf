# =============================================================================
# modules/apps :: servicenow.tf
# -----------------------------------------------------------------------------
# 5. ServiceNow (SAML; enable_servicenow_sso, off by default) - the second SAML
#    enterprise app, aimed at a ServiceNow Personal Developer Instance (PDI,
#    https://devNNNNN.service-now.com). Same shape as the AWS app in main.tf:
#    instantiate -> enterprise app settings (SAML mode, assignment required,
#    owners, sign-on URL) -> Identifier + Reply URL -> Entra-minted signing
#    certificate -> claims-mapping policy (NameID = UPN) -> ONE assignment:
#    App-ServiceNow-Users (modules/groups, key "servicenow").
#
# NON-GALLERY TEMPLATE, ON PURPOSE. Microsoft publishes the NON-GALLERY
# application template id in the Graph docs (applicationTemplate: instantiate,
# checked 2026-10-20). Neither the Learn ServiceNow SSO tutorial nor the Graph
# docs publish the "ServiceNow" GALLERY template id, and an unverified id is
# not committed here. So this is a non-gallery SAML app carrying the settings
# the Learn tutorial documents for ServiceNow:
#   Identifier (Entity ID) https://<instance>.service-now.com  (no trailing /)
#   Reply URL (ACS)        https://<instance>.service-now.com/navpage.do
#   Sign-on URL            https://<instance>.service-now.com/login_with_sso.do?glide_sso_id=<sys_id>
#                          (or .../navpage.do until the sys_id exists)
# What the gallery app would add that this one lacks: the "Configure Now"
# automatic ServiceNow-side setup (a convenience; the manual metadata-URL
# import below is the documented alternative) and the ServiceNow provisioning
# connector (see PROVISIONING). Switching to the gallery template later is a
# replacement (new client id, new certificate, new ServiceNow IdP metadata),
# so it is a design change, not a variable flip.
#
# NOT MANAGED HERE: the Logout URL (.../navpage.do in the tutorial). The
# provider exposes it only through azuread_application's web block, and the
# instantiated app is deliberately not managed by azuread_application (same
# reason as the AWS app). Sign-in does not need it; single logout does.
#
# SERVICENOW SIDE (tenant time, documented in the module README): activate
# "Integration - Multiple Provider Single Sign-On Installer", create a SAML
# identity provider by importing output servicenow_federation_metadata_url,
# NameID Policy urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified, and
# User Field = user_name (ServiceNow user_name = Entra UPN, the lab's
# convention - lab/pam/docker-compose.oidc.yml). Then put the IdP record's
# sys_id in servicenow_sso_sys_id so the My Apps tile signs in through it.
#
# PROVISIONING (DESIGNED, NOT BUILT): Learn's ServiceNow provisioning tutorial
# uses the GALLERY app's connector, which authenticates to the instance with a
# ServiceNow admin user name + password (no bearer token). A non-gallery app
# offers only the generic SCIM connector (verify:), not this one. The design:
# a second, gallery "ServiceNow" instance (Learn recommends a separate app for
# testing provisioning), assigned to the same App-ServiceNow-Users group so
# the SSO scope and the provisioning scope can never drift; the integration
# account vaulted in Key Vault and written once like the AWS SCIM credential
# (ignore_changes); the job created STOPPED; matching userPrincipalName ->
# user_name so provisioned accounts line up with the NameID below. Not built:
# the gallery template id and the connector's credential keys are both
# unverified (verify: GET /applicationTemplates?$filter=displayName eq
# 'ServiceNow' and GET /servicePrincipals/<id>/synchronization/templates in
# the tenant).
#
# LICENSING: same as the AWS app - SAML SSO is Entra ID Free; GROUP
# assignment needs Entra ID P1 (envs/dev gates this module on enable_premium).
#
# Nothing here has run against a tenant. Runtime claims not proven by
# Microsoft documentation are marked "verify:".
# =============================================================================

locals {
  servicenow_enabled = var.enable_servicenow_sso

  # Microsoft Graph, "applicationTemplate: instantiate": the template for
  # NON-GALLERY apps (SAML / password SSO) in the global service. (US
  # Government and 21Vianet have their own ids; the lab is global only.)
  nongallery_application_template_id = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"

  # Reply URL = the ServiceNow Multi-Provider SSO homepage (navpage.do), the
  # first of the two Reply URL patterns in the Learn tutorial. Exactly one,
  # on exactly this instance: no wildcard, nothing else can receive a token.
  servicenow_reply_url = "${var.servicenow_instance_url}/navpage.do"

  # SP-initiated sign-on from the My Apps tile. Before the ServiceNow IdP
  # record exists there is no sys_id, so the tile opens the instance homepage.
  servicenow_sign_on_url = (
    var.servicenow_sso_sys_id != ""
    ? "${var.servicenow_instance_url}/login_with_sso.do?glide_sso_id=${var.servicenow_sso_sys_id}"
    : local.servicenow_reply_url
  )

  # Tags of a portal-created non-gallery SAML app: listed under Enterprise
  # applications + marked as custom SAML. Set explicitly because the adopt
  # path PATCHes `tags` from config (see enterprise_sp_tags in main.tf).
  # verify: the tags the non-gallery template instantiates with.
  servicenow_sp_tags = [
    "WindowsAzureActiveDirectoryCustomSingleSignOnApplication",
    "WindowsAzureActiveDirectoryIntegratedApp",
  ]
}

# Instantiate the non-gallery template. azuread_application_from_template (not
# azuread_application) for the same reason as the AWS app: it manages nothing
# on the resulting objects, so Terraform never fights the template's own app
# roles. The precondition fails the PLAN, before anything is created, if the
# flag is on without an instance URL (an app that can never sign anyone in).
resource "azuread_application_from_template" "servicenow" {
  count = local.servicenow_enabled ? 1 : 0

  display_name = var.servicenow_app_display_name
  template_id  = local.nongallery_application_template_id

  lifecycle {
    precondition {
      condition     = var.servicenow_instance_url != ""
      error_message = "enable_servicenow_sso = true needs servicenow_instance_url (the PDI URL, https://devNNNNN.service-now.com) - it is the Identifier and the base of the Reply URL. Set it in terraform.tfvars / TF_VAR_servicenow_instance_url, never in lab.tfvars."
    }
  }
}

# The template resource does not export the client id the SP resource needs.
data "azuread_application" "servicenow" {
  count = local.servicenow_enabled ? 1 : 0

  object_id = azuread_application_from_template.servicenow[0].application_object_id
}

# Enterprise-app settings, adopting the SP the template created. Every
# attribute the provider writes is set explicitly (the adopt path PATCHes the
# whole object from config - unset app_role_assignment_required would become
# false and anyone in the tenant could get a ServiceNow assertion).
resource "azuread_service_principal" "servicenow" {
  count = local.servicenow_enabled ? 1 : 0

  client_id    = data.azuread_application.servicenow[0].client_id
  use_existing = true

  preferred_single_sign_on_mode = "saml"

  # Only assigned principals get an assertion. With the single assignment
  # below, that is App-ServiceNow-Users and nobody else.
  app_role_assignment_required = true

  login_url = local.servicenow_sign_on_url

  # Certificate-expiry mails. verify: the provider documents this for gallery
  # apps; the portal offers it for non-gallery SAML apps too.
  notification_email_addresses = var.saml_cert_notification_emails

  owners = local.app_owners
  tags   = local.servicenow_sp_tags
  notes  = "Contoso Health lab: SAML SSO to the ServiceNow PDI (non-gallery SAML app). Access = App-ServiceNow-Users only. Provisioning designed, not built. Managed by Terraform - modules/apps (servicenow.tf)."
}

# Identifier (Entity ID) = the instance URL, exactly what ServiceNow sends as
# its Entity ID / Issuer. depends_on the SP on purpose: *.service-now.com is
# not a verified domain of the tenant, and Microsoft's identifier-URI policy
# (enabled by default in some tenants since mid-2025) only exempts apps whose
# service principal ALREADY has preferredSingleSignOnMode = saml (Learn,
# "Restrictions on identifier URIs"). Without the edge Terraform may add the
# URI first and the policy refuses it.
resource "azuread_application_identifier_uri" "servicenow" {
  count = local.servicenow_enabled ? 1 : 0

  application_id = azuread_application_from_template.servicenow[0].application_id
  identifier_uri = var.servicenow_instance_url

  depends_on = [azuread_service_principal.servicenow]
}

# Reply URL (ACS). Authoritative for the Web type: whatever the template
# instantiated with is replaced by this one URL.
resource "azuread_application_redirect_uris" "servicenow" {
  count = local.servicenow_enabled ? 1 : 0

  application_id = azuread_application_from_template.servicenow[0].application_id
  type           = "Web"
  redirect_uris  = [local.servicenow_reply_url]
}

# SAML token-signing certificate, minted by Entra (addTokenSigningCertificate):
# the private key never leaves Entra and never touches Terraform state.
# Activation (preferredTokenSigningKeyThumbprint) is a post-apply step, as for
# the AWS app - output servicenow_saml_signing_cert_activation_command. Its
# own end date, so rotating ServiceNow never forces an AWS metadata change.
resource "azuread_service_principal_token_signing_certificate" "servicenow" {
  count = local.servicenow_enabled ? 1 : 0

  service_principal_id = azuread_service_principal.servicenow[0].id
  display_name         = "CN=Contoso Health - ServiceNow SAML signing"
  end_date             = var.servicenow_saml_signing_cert_end_date
}

# Claims as code: NameID = userPrincipalName. ServiceNow matches it against
# the IdP record's User Field (user_name), so UPN is the join key, the same
# value a future provisioning job would write to user_name.
# IncludeBasicClaimSet keeps the standard name / given name / surname / email
# claims. ServiceNow asks for NameID format "unspecified".
# verify: on first sign-in, the NameID value and format ServiceNow receives.
resource "azuread_claims_mapping_policy" "servicenow" {
  count = local.servicenow_enabled && var.servicenow_saml_claims_policy_enabled ? 1 : 0

  display_name = "Contoso Health - ServiceNow claims"
  definition = [
    jsonencode({
      ClaimsMappingPolicy = {
        Version              = 1
        IncludeBasicClaimSet = "true"
        ClaimsSchema = [
          {
            Source        = "user"
            ID            = "userprincipalname"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
          },
        ]
      }
    }),
  ]
}

resource "azuread_service_principal_claims_mapping_policy_assignment" "servicenow" {
  count = local.servicenow_enabled && var.servicenow_saml_claims_policy_enabled ? 1 : 0

  claims_mapping_policy_id = azuread_claims_mapping_policy.servicenow[0].id
  service_principal_id     = azuread_service_principal.servicenow[0].id
}

# The single assignment: App-ServiceNow-Users. Not a list for the same reason
# as the AWS app - a second principal is a design change a reviewer should see.
resource "azuread_app_role_assignment" "servicenow_users" {
  count = local.servicenow_enabled ? 1 : 0

  # Prefer the "User" role the instantiated app carries; with no roles at all,
  # Entra's default-access role id (all zeros) means "assigned, no specific
  # role". verify: the roles the non-gallery template instantiates with
  # (expected "User" and "msiam_access").
  app_role_id = coalesce(
    try(one([for r in azuread_service_principal.servicenow[0].app_roles : r.id if r.display_name == "User" && r.enabled]), null),
    "00000000-0000-0000-0000-000000000000",
  )
  principal_object_id = var.servicenow_users_group_object_id
  resource_object_id  = azuread_service_principal.servicenow[0].object_id

  lifecycle {
    precondition {
      condition     = var.servicenow_users_group_object_id != ""
      error_message = "enable_servicenow_sso = true needs servicenow_users_group_object_id (App-ServiceNow-Users, modules/groups app_access_group_object_ids[\"servicenow\"]). Assignment is required, so an app with no assignment signs nobody in."
    }
  }
}
