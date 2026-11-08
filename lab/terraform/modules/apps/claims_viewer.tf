# =============================================================================
# modules/apps :: claims_viewer.tf
# -----------------------------------------------------------------------------
# 6. Contoso Claims Viewer (SAML; enable_claims_viewer_app, off by default) -
#    the app the AD FS -> Entra migration moves (lab/adfs/README.md, ADR 0009
#    phase 3). Before the cutover it signs users in through the lab AD FS
#    relying party urn:contoso:claims-viewer; after it, through THIS app.
#
# The point of this file is the claim-rule conversion, as code. Each AD FS
# rule in lab/adfs/claims-viewer.rules.txt has its Entra equivalent here:
#
#   AD FS rule                                  Entra (this file)
#   ------------------------------------------  --------------------------------
#   1 LDAP attributes: userPrincipalName, mail,  claims-mapping policy, Source =
#     givenName, sn, department, employeeID      user: userprincipalname, mail,
#     -> upn, emailaddress, givenname, surname,  givenname, surname, department,
#     urn:contoso:claims:department/employeeid   employeeid (same claim types)
#   2 Transform UPN -> Name ID (unspecified)     NameID = userprincipalname,
#                                                 format unspecified
#   3a/3b groupsid == <SID of GRP-ClaimsViewer-  app roles ClaimsViewer.Clinician
#     Clinicians/Admins> -> role claim            / .Admin, each assigned to the
#                                                 SAME AD group (synced by Cloud
#                                                 Sync). Entra emits the assigned
#                                                 role as the role claim.
#   4 RegExReplace(upn, "@.*$", "")             ExtractMailPrefix(userprincipalname)
#     -> urn:contoso:claims:shortname             -> urn:contoso:claims:shortname
#
#   AD FS access policy "Permit specific group"  app_role_assignment_required =
#   (the two groups)                              true + the two assignments
#
# Why app roles for rule 3, not a groups claim: AD FS turns group membership
# into a role NAME; the app never sees a group. Entra's way to do the same is
# an app role assigned to the group. A groups claim would send object ids
# the app has never seen (and the contract test would fail on the extra
# claim). Learn: "Add app roles to your application and receive them in the
# token" (SAML apps get them as the role claim).
#
# Why the claims-mapping policy needs the app's own signing certificate: the
# upn and role SAML claim types are restricted "but aren't restricted if you
# have a custom signing key" (Learn, "Claims customization", checked
# 2026-11-07). The certificate below is that key. acceptMappedClaims is NOT
# used (Learn: avoid it).
#
# Same shape as servicenow.tf: non-gallery template, SP adopted with every
# attribute explicit, identifier after the SP is in SAML mode, Entra-minted
# certificate (activation is a post-apply step), claims policy, assignments.
#
# LICENSING: SAML SSO is Entra ID Free; group assignment needs P1 (envs/dev
# gates this module on enable_premium).
# =============================================================================

locals {
  claims_viewer_enabled = var.enable_claims_viewer_app

  claims_viewer_identifier = "urn:contoso:claims-viewer"
  # The SAME assertion consumer URL the AD FS relying party uses: the app is
  # not changed by the cutover, only the IdP metadata it trusts.
  claims_viewer_reply_url = "https://localhost:8443/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp"
  claims_viewer_sign_on   = "https://localhost:8443/"

  # Fixed ids: a role id must never change once tokens carry it.
  claims_viewer_roles = {
    clinician = {
      id           = "6f0f6a52-3c39-4e57-9a8d-2c1f9f1d7a01"
      value        = "ClaimsViewer.Clinician"
      display_name = "Clinician"
      description  = "Clinical user of the Claims Viewer. Was AD FS rule 3a (GRP-ClaimsViewer-Clinicians)."
    }
    admin = {
      id           = "6f0f6a52-3c39-4e57-9a8d-2c1f9f1d7a02"
      value        = "ClaimsViewer.Admin"
      display_name = "Admin"
      description  = "Administrator of the Claims Viewer. Was AD FS rule 3b (GRP-ClaimsViewer-Admins)."
    }
  }
}

resource "azuread_application_from_template" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  display_name = "Contoso Claims Viewer"
  template_id  = local.nongallery_application_template_id

  lifecycle {
    precondition {
      condition     = var.claims_viewer_clinicians_group_object_id != "" && var.claims_viewer_admins_group_object_id != ""
      error_message = "enable_claims_viewer_app = true needs claims_viewer_clinicians_group_object_id and claims_viewer_admins_group_object_id: the Entra object ids of GRP-ClaimsViewer-Clinicians / -Admins, which exist only after lab/adfs/scripts/11-Add-ClaimsViewerRp.ps1 and one Cloud Sync cycle."
    }
  }
}

data "azuread_application" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  object_id = azuread_application_from_template.claims_viewer[0].application_object_id
}

resource "azuread_application_app_role" "claims_viewer" {
  for_each = local.claims_viewer_enabled ? local.claims_viewer_roles : {}

  application_id       = azuread_application_from_template.claims_viewer[0].application_id
  role_id              = each.value.id
  value                = each.value.value
  display_name         = each.value.display_name
  description          = each.value.description
  allowed_member_types = ["User"]
}

resource "azuread_service_principal" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  client_id    = data.azuread_application.claims_viewer[0].client_id
  use_existing = true

  preferred_single_sign_on_mode = "saml"
  # Only the two role groups get an assertion, exactly as the AD FS access
  # policy "Permit specific group" allowed only them.
  app_role_assignment_required = true
  login_url                    = local.claims_viewer_sign_on

  notification_email_addresses = var.saml_cert_notification_emails
  owners                       = local.app_owners
  tags                         = local.servicenow_sp_tags
  notes                        = "Contoso Health lab: the app migrated off AD FS (lab/adfs, ADR 0009). Claims = the AD FS rules converted (modules/apps/claims_viewer.tf). Access = GRP-ClaimsViewer-Clinicians / -Admins only. Managed by Terraform."
}

resource "azuread_application_identifier_uri" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  application_id = azuread_application_from_template.claims_viewer[0].application_id
  identifier_uri = local.claims_viewer_identifier

  depends_on = [azuread_service_principal.claims_viewer]
}

resource "azuread_application_redirect_uris" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  application_id = azuread_application_from_template.claims_viewer[0].application_id
  type           = "Web"
  redirect_uris  = [local.claims_viewer_reply_url]
}

resource "azuread_service_principal_token_signing_certificate" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  service_principal_id = azuread_service_principal.claims_viewer[0].id
  display_name         = "CN=Contoso Health - Claims Viewer SAML signing"
  # A one-off migration exercise: one year, not Entra's default of three.
  end_date = var.claims_viewer_saml_signing_cert_end_date
}

# The converted claim rules. IncludeBasicClaimSet = false: the app gets the
# claims listed here (plus Entra's core set, which no policy can remove), so
# lab/adfs/compare/compare_claims.py can demand "the same claims, nothing
# extra". verify: on the first sign-in, that no basic-set claim (name,
# displayname) still appears; the contract lists them as platform claims.
resource "azuread_claims_mapping_policy" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  display_name = "Contoso Health - Claims Viewer (converted AD FS rules)"
  definition = [
    jsonencode({
      ClaimsMappingPolicy = {
        Version              = 1
        IncludeBasicClaimSet = "false"
        ClaimsSchema = [
          # Rule 2: Name ID = UPN. The FORMAT (unspecified) is what the
          # app asks for in its request (NameIDPolicy in the Claims Viewer's
          # authsources.php), as with ServiceNow. verify: on first sign-in.
          {
            Source        = "user"
            ID            = "userprincipalname"
            SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
          },
          # Rule 1: the LDAP attributes, same claim types as AD FS.
          { Source = "user", ID = "userprincipalname", SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" },
          { Source = "user", ID = "mail", SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" },
          { Source = "user", ID = "givenname", SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" },
          { Source = "user", ID = "surname", SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" },
          { Source = "user", ID = "department", SamlClaimType = "urn:contoso:claims:department" },
          { Source = "user", ID = "employeeid", SamlClaimType = "urn:contoso:claims:employeeid" },
          # Rule 4: RegExReplace(upn, "@.*$", "") == ExtractMailPrefix(upn).
          { Source = "transformation", ID = "shortname", TransformationId = "ShortName", SamlClaimType = "urn:contoso:claims:shortname" },
        ]
        ClaimsTransformations = [
          {
            ID                   = "ShortName"
            TransformationMethod = "ExtractMailPrefix"
            InputClaims          = [{ ClaimTypeReferenceId = "userprincipalname", TransformationClaimType = "mail" }]
            OutputClaims         = [{ ClaimTypeReferenceId = "shortname", TransformationClaimType = "outputClaim" }]
          },
        ]
      }
    }),
  ]
}

resource "azuread_service_principal_claims_mapping_policy_assignment" "claims_viewer" {
  count = local.claims_viewer_enabled ? 1 : 0

  claims_mapping_policy_id = azuread_claims_mapping_policy.claims_viewer[0].id
  service_principal_id     = azuread_service_principal.claims_viewer[0].id
}

# Rule 3 + the access policy: each AD group gets its role.
resource "azuread_app_role_assignment" "claims_viewer" {
  for_each = local.claims_viewer_enabled ? {
    clinician = var.claims_viewer_clinicians_group_object_id
    admin     = var.claims_viewer_admins_group_object_id
  } : {}

  app_role_id         = azuread_application_app_role.claims_viewer[each.key].role_id
  principal_object_id = each.value
  resource_object_id  = azuread_service_principal.claims_viewer[0].object_id
}
