# =============================================================================
# modules/apps :: main.tf
# -----------------------------------------------------------------------------
# Application onboarding as code - the "Apps: SSO + provisioning" part of the
# lab that used to be portal clicks:
#
#   1. AWS IAM Identity Center (gallery app, SAML)
#        instantiate gallery template -> enterprise app settings (SAML mode,
#        assignment required, owners, sign-on URL) -> Identifier + Reply URL
#        -> Entra-minted signing certificate -> claims-mapping policy (NameID +
#        ABAC session tags) -> the staff assignment App-AWS-IdentityCenter-Users,
#        plus (enable_aws_admins_assignment) the PIM admin group
#        PIM-AWS-Lab-Admins, ADR 0025.
#   2. AWS IAM Identity Center (SCIM, staged, off by default)
#        provisioning job (created STOPPED) + its credential (from Key Vault,
#        written once, then ignored).
#   3. Contoso Clinical Portal (OIDC)
#        app registration with three app roles (Clinician / Pharmacist /
#        Auditor), an API scope, app-assigned groups claim, assignment
#        required, group-based role grants.
#
#   4. guacamole-psm (OIDC, guacamole.tf; enable_guacamole_psm_app)
#        id_token-only sign-in for the lab/pam PSM stand-in, assigned only to
#        PAM-Operators.
#
#   5. ServiceNow (SAML, servicenow.tf; enable_servicenow_sso)
#        non-gallery SAML app for the ServiceNow PDI: Identifier / Reply URL
#        from servicenow_instance_url, Entra-minted signing certificate,
#        NameID = UPN, ONE assignment: App-ServiceNow-Users.
#
#   6. okta-clinic-idp (OIDC, okta.tf; enable_okta_federation)
#        Entra as the identity provider for the acquired clinic's Okta org
#        (runbook Phase 1, ADR 0022): one redirect URI (the Okta authorize
#        callback), assignment required, ONE assignment:
#        App-Okta-Federation-Users. The client secret is minted by a human
#        post-apply, never by Terraform. The Okta half is lab/terraform/okta.
#
#   7. ServiceNow provisioning (servicenow_provisioning.tf;
#      enable_servicenow_provisioning)
#        gallery "ServiceNow" app used for provisioning only (hidden from My
#        Apps), assigned to the SSO app's group App-ServiceNow-Users, its
#        ServiceNowOutDelta job (created STOPPED) and its credential (the
#        ServiceNow integration user, from Key Vault, written once).
#
# NO STAND-IN: these are real Entra objects and the real AWS IAM Identity
# Center connector. NOTHING HERE HAS RUN AGAINST A TENANT YET - every
# statement about runtime behaviour is from Microsoft/AWS documentation or
# provider source, and the ones not proven are marked "verify:".
#
# WHO OWNS WHAT (the boundary, mirrored in lab/terraform/aws):
#   Entra (this module) decides WHO reaches AWS: the app assignment is both the
#   SSO gate and the SCIM scope. AWS (lab/terraform/aws) decides WHAT they get:
#   permission sets on the SCIM-created groups. Terraform never creates an
#   AWS-local group. The AWS app has exactly two principals, each its own
#   resource: the staff group and the PIM admin group (ADR 0025).
#
# LICENSING: gallery SAML SSO and app registrations are Entra ID Free; GROUP
# assignment to an enterprise app needs Entra ID P1 (inside the M365 E5
# trial) - which is why envs/dev gates this module on enable_premium too.
# Outbound SCIM provisioning to a gallery app: verify: P1 per provisioned user.
#
# GRAPH PERMISSIONS the applying identity needs (application roles; see the
# README for the full table and why each is there):
#   Application.ReadWrite.OwnedBy   instantiate, SP settings, signing cert,
#                                   identifier/reply URLs, sync job + secret
#   Policy.ReadWrite.ApplicationConfiguration + Policy.Read.All   claims policy
#   AppRoleAssignment.ReadWrite.All + Application.Read.All        group grants
# =============================================================================

# Who is running Terraform: recorded as an owner of every object created here
# (Application.ReadWrite.OwnedBy only reaches apps the caller owns), and the
# tenant id for the federation-metadata URL output.
data "azuread_client_config" "current" {}

# The Terraform identity that must own the apps (Application.ReadWrite.OwnedBy):
# the APPLY identity, named by client id - NOT "whoever runs this". With the
# caller's id, every pull-request plan (run as PLAN) showed the six apps'
# owners changing to PLAN, a change the real apply (run as APPLY) never makes,
# and every local apply by a human dropped APPLY as an owner.
data "azuread_service_principal" "iac_owner" {
  count     = var.iac_owner_client_id != "" ? 1 : 0
  client_id = var.iac_owner_client_id
}

locals {
  # Owners = the Terraform (APPLY) identity + named humans. Falls back to the
  # caller only when iac_owner_client_id is unset (offline / first local
  # apply). distinct() because a human may also be in app_owner_object_ids.
  iac_owner_object_id = one(data.azuread_service_principal.iac_owner[*].object_id) != null ? one(data.azuread_service_principal.iac_owner[*].object_id) : data.azuread_client_config.current.object_id
  app_owners          = distinct(concat([local.iac_owner_object_id], var.app_owner_object_ids))

  # Graph's own sample shows the AWS IAM Identity Center template instantiating
  # with these two app roles. They are looked up by name at apply time; the id
  # is only the fallback. "User" is the role the portal grants by default.
  aws_gallery_user_role_id = "8774f594-1d59-4279-b9d9-59ef09a23530"

  # The only SP tag the instantiated gallery SP carries (Graph sample
  # response). Set explicitly because the provider PATCHes `tags` on every
  # create/update of azuread_service_principal: leaving it unset would send an
  # empty list and drop the app out of Enterprise applications.
  enterprise_sp_tags = ["WindowsAzureActiveDirectoryIntegratedApp"]
}

# =============================================================================
# 1. AWS IAM Identity Center - SAML
# =============================================================================

# The gallery template, read back by id. The postcondition is the guard rail:
# instantiating the wrong template would silently create another vendor's app.
data "azuread_application_template" "aws" {
  template_id = var.aws_gallery_template_id

  lifecycle {
    postcondition {
      condition     = startswith(self.display_name, "AWS IAM Identity Center")
      error_message = "aws_gallery_template_id does not resolve to the AWS IAM Identity Center gallery template. Look it up: GET https://graph.microsoft.com/v1.0/applicationTemplates?$filter=startswith(displayName,'AWS IAM Identity Center')"
    }
  }
}

# Instantiate the gallery app. azuread_application_from_template (not
# azuread_application with template_id) on purpose: it manages NOTHING on the
# resulting objects, so Terraform can never strip the template's app roles
# ("User", "msiam_access"), which Graph says must not be modified or removed.
# Every setting we do want is applied by the narrower resources below.
resource "azuread_application_from_template" "aws" {
  display_name = var.aws_app_display_name
  template_id  = data.azuread_application_template.aws.template_id
}

# The template resource does not export the client id the SP resource needs.
data "azuread_application" "aws" {
  object_id = azuread_application_from_template.aws.application_object_id
}

# Enterprise-app settings, adopting the SP the template created (use_existing).
# EVERY attribute the provider writes is set explicitly, because the adopt path
# PATCHes the whole object from config: unset app_role_assignment_required
# would become false (anyone in the tenant could get a token) and unset tags
# would be emptied. Destroy order is safe: this resource deletes the SP and
# ignores the error, then azuread_application_from_template deletes the app.
resource "azuread_service_principal" "aws" {
  client_id    = data.azuread_application.aws.client_id
  use_existing = true

  # SAML is what My Apps launches and what the "Single sign-on" blade shows.
  preferred_single_sign_on_mode = "saml"

  # Only assigned principals get a token. With the single assignment below this
  # means only App-AWS-IdentityCenter-Users can sign in - and only they are in
  # SCIM scope (provisioning syncs assigned users/groups).
  app_role_assignment_required = true

  # SP-initiated sign-on from the My Apps tile (AWS access portal URL).
  login_url = var.aws_access_portal_url != "" ? var.aws_access_portal_url : null

  # Who gets the 60/30/7-day certificate expiry mails (verify: schedule).
  notification_email_addresses = var.saml_cert_notification_emails

  owners = local.app_owners
  tags   = local.enterprise_sp_tags
  notes  = "Contoso Health lab: SAML SSO + SCIM to AWS IAM Identity Center. Entra decides WHO (one assigned group), AWS permission sets decide WHAT (lab/terraform/aws). Managed by Terraform - modules/apps."
}

# Identifier (Entity ID) = the AWS Issuer URL. Created only once the AWS value
# is known (staged order, README); until then the app exists but cannot
# complete a SAML sign-in - it fails closed.
resource "azuread_application_identifier_uri" "aws" {
  count = var.aws_saml_entity_id != "" ? 1 : 0

  application_id = azuread_application_from_template.aws.application_id
  identifier_uri = var.aws_saml_entity_id
}

# Reply URL(s) (ACS). Authoritative for the Web type: replaces the template's
# wildcard https://*.signin.aws.amazon.com/platform/saml/acs/*, so Entra will
# only POST assertions to this Identity Center instance.
resource "azuread_application_redirect_uris" "aws" {
  count = length(var.aws_saml_acs_urls) > 0 ? 1 : 0

  application_id = azuread_application_from_template.aws.application_id
  type           = "Web"
  redirect_uris  = var.aws_saml_acs_urls
}

# SAML token-signing certificate, minted by Entra (addTokenSigningCertificate):
# the private key never leaves Entra and never touches Terraform state.
# ACTIVATION IS A POST-APPLY STEP: Graph requires preferredTokenSigningKeyThumbprint
# to be set to this thumbprint, and azuread 3.10 has no argument for it - see
# output aws_saml_signing_cert_activation_command.
# Any change here (end_date, display_name) REPLACES the certificate, which is a
# coordinated AWS metadata update, never a routine apply (README).
resource "azuread_service_principal_token_signing_certificate" "aws" {
  service_principal_id = azuread_service_principal.aws.id
  display_name         = "CN=Contoso Health - AWS IAM Identity Center SAML signing"
  end_date             = var.saml_signing_cert_end_date
}

# Claims as code. NameID = userPrincipalName, the same value the AWS connector's
# default mapping sends as the SCIM userName - if those two ever diverge, every
# sign-in fails with "user not found" in AWS. Session tags carry the HR-driven
# department for ABAC. IncludeBasicClaimSet keeps the gallery's standard claims
# (name, given name, surname, email).
# verify: on first sign-in, the NameID format AWS receives (expected
# emailAddress or unspecified; AWS matches on the value).
resource "azuread_claims_mapping_policy" "aws" {
  count = var.aws_saml_claims_policy_enabled ? 1 : 0

  display_name = "Contoso Health - AWS IAM Identity Center claims"
  definition = [
    jsonencode({
      ClaimsMappingPolicy = {
        Version              = 1
        IncludeBasicClaimSet = "true"
        ClaimsSchema = concat(
          [
            {
              Source        = "user"
              ID            = "userprincipalname"
              SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
            },
          ],
          [
            for tag_key, attribute in var.aws_abac_session_tags : {
              Source        = "user"
              ID            = attribute
              SamlClaimType = "https://aws.amazon.com/SAML/Attributes/AccessControl:${tag_key}"
            }
          ],
        )
      }
    }),
  ]
}

resource "azuread_service_principal_claims_mapping_policy_assignment" "aws" {
  count = var.aws_saml_claims_policy_enabled ? 1 : 0

  claims_mapping_policy_id = azuread_claims_mapping_policy.aws[0].id
  service_principal_id     = azuread_service_principal.aws.id
}

# The staff assignment. Not a for_each over a list on purpose: a principal
# on this app is a design change (a new group = a new SCIM scope and a new
# AWS principal), so each one is its own named resource a reviewer sees,
# never one more list element. There are exactly two: this one, and the PIM
# admin group below.
resource "azuread_app_role_assignment" "aws_users" {
  # Prefer the role the instantiated app actually carries; fall back to the
  # id Graph documents for this template.
  app_role_id = coalesce(
    try(one([for r in azuread_service_principal.aws.app_roles : r.id if r.display_name == "User" && r.enabled]), null),
    local.aws_gallery_user_role_id,
  )
  principal_object_id = var.aws_users_group_object_id
  resource_object_id  = azuread_service_principal.aws.object_id
}

# The SECOND principal, added deliberately (ADR 0025): PIM-AWS-Lab-Admins.
# Why a second group on the same app, and not something else:
#   * Not a member of App-AWS-IdentityCenter-Users: that group is the staff
#     path (access package -> ViewOnlyAccess); an admin inside it would also
#     be granted whatever staff get, and its membership is not PIM-governed.
#   * Not a nested group: provisioning does not expand nested groups (Learn,
#     "Privileged Identity Management (PIM) for Groups" and the app
#     provisioning scoping docs), so AWS would never see the members.
#   * Microsoft's own recommendation for PIM + app provisioning (Learn,
#     concept-pim-for-groups, "Privileged Identity Management and app
#     provisioning", checked 2026-11-05): "at least two groups assigned to
#     the application" - an always-active all-users group with a low role and
#     an ELIGIBLE privileged group with the privileged role. That is this
#     pair; activating membership triggers SCIM within 2-10 minutes.
#   * Not a direct USER assignment of the admin account: that would keep the
#     account provisioned in AWS, and signed-in-able, all the time. Through
#     the PIM group the account is in scope only while an activation lasts,
#     so at rest it cannot even complete the SAML sign-in to AWS.
# Same app role as the staff group; AWS tells the two apart by which
# Identity Store group the user lands in (lab/terraform/aws assigns
# LabAdministrator to this one only).
resource "azuread_app_role_assignment" "aws_admins" {
  count = var.enable_aws_admins_assignment ? 1 : 0

  app_role_id = coalesce(
    try(one([for r in azuread_service_principal.aws.app_roles : r.id if r.display_name == "User" && r.enabled]), null),
    local.aws_gallery_user_role_id,
  )
  principal_object_id = var.aws_admins_group_object_id
  resource_object_id  = azuread_service_principal.aws.object_id

  lifecycle {
    precondition {
      condition     = var.aws_admins_group_object_id != "" && lower(var.aws_admins_group_object_id) != lower(var.aws_users_group_object_id)
      error_message = "enable_aws_admins_assignment = true needs aws_admins_group_object_id (modules/pim output aws_admin_group_object_id), and it must not be App-AWS-IdentityCenter-Users."
    }
  }
}

# =============================================================================
# 2. AWS IAM Identity Center - SCIM (staged; enable_scim_provisioning)
# =============================================================================
# Order follows Microsoft's Graph provisioning guide: create the job, save the
# credential, test, start. The job is created STOPPED (aws_scim_job_enabled =
# false): Test Connection and one on-demand provision come first, then a
# separate PR starts the ~40-minute cycle.

resource "azuread_synchronization_job" "aws" {
  count = var.enable_scim_provisioning ? 1 : 0

  service_principal_id = azuread_service_principal.aws.id
  template_id          = var.aws_scim_template_id
  enabled              = var.aws_scim_job_enabled

  lifecycle {
    precondition {
      condition     = trimspace(var.aws_scim_template_id) != ""
      error_message = "enable_scim_provisioning = true needs aws_scim_template_id. After the first SSO apply run: GET https://graph.microsoft.com/v1.0/servicePrincipals/<aws_service_principal_object_id>/synchronization/templates (output aws_scim_template_lookup_command) and use the returned id."
    }
  }
}

# The SCIM credential: Tenant URL (BaseAddress) + Secret Token.
#
# WHERE IT COMES FROM: Key Vault (aws-scim-tenant-url / aws-scim-token), read
# into TF_VAR_aws_scim_credentials only by the run that creates or replaces
# it. PR plans never see it (the PLAN identity has no vault access by design:
# anyone who can open a PR controls what a plan prints).
#
# WHY ignore_changes: Graph never returns the token (it answers "*"), and the
# provider keeps the value it wrote. Ignoring changes means routine plans and
# CI applies need no token at all; rotation is a deliberate
# `terraform apply -replace=...` with the new value (README "Rotation").
#
# STATE: the token IS stored in state (sensitive). State access is limited to
# the CI identities and the operator, but the PLAN identity can read state -
# the same accepted residual risk the README records for the break-glass
# passwords. Revocation path: delete the token in AWS (it is shown once and
# can be re-issued), which makes any copy in state useless.
resource "azuread_synchronization_secret" "aws" {
  count = var.enable_scim_provisioning ? 1 : 0

  service_principal_id = azuread_service_principal.aws.id

  credential {
    key   = "BaseAddress"
    value = try(var.aws_scim_credentials.tenant_url, "")
  }
  credential {
    key   = "SecretToken"
    value = try(var.aws_scim_credentials.secret_token, "")
  }

  # Microsoft's order: the job exists before its credential is saved.
  depends_on = [azuread_synchronization_job.aws]

  lifecycle {
    ignore_changes = [credential]

    # Fail closed in the gated apply: never write an EMPTY credential. Checks
    # the planned value, which after creation is the stored one (ignore_changes),
    # so this only bites on the run that would create it without the token.
    postcondition {
      condition     = !var.require_scim_credentials || nonsensitive(alltrue([for c in self.credential : length(trimspace(c.value)) > 0]))
      error_message = "This run would create the AWS SCIM credential without a value. Export TF_VAR_aws_scim_credentials from Key Vault (secrets aws-scim-tenant-url / aws-scim-token) for this run only - see modules/apps/README.md \"SCIM credential\"."
    }
  }
}

# PR plans (require_scim_credentials = false) only warn: they can never hold
# the token, so a plan that turns SCIM on is expected to show this once.
check "scim_credential_supplied_on_create" {
  assert {
    condition = !var.enable_scim_provisioning || nonsensitive(alltrue([
      for c in try(azuread_synchronization_secret.aws[0].credential, []) : length(trimspace(c.value)) > 0
    ]))
    error_message = "SCIM is on but this run has no aws_scim_credentials and the credential does not exist yet. Expected in a PR plan; the creating run must export TF_VAR_aws_scim_credentials from Key Vault (README \"SCIM credential\")."
  }
}

# =============================================================================
# 3. Contoso Clinical Portal - OIDC app registration with app roles
# =============================================================================

locals {
  # App role and scope ids are FIXED GUIDs: tokens, assignments and any
  # consuming code key off them, so they must never be regenerated. (Never
  # reuse a GUID across roles; disable a role before deleting it.)
  clinical_portal_roles = {
    Clinician = {
      id          = "191a5d18-1554-443e-b4f0-f8272b6117ae"
      description = "Clinicians (nursing, ICU): read and update the care record for their patients."
    }
    Pharmacist = {
      id          = "ffb4fae6-6410-42b0-b528-24ad2b956758"
      description = "Pharmacists: verify and dispense medication orders. Separation of duties with Clinician (same pair as the Nurse / Pharmacy access packages)."
    }
    Auditor = {
      id          = "eb555ec8-853e-4a76-9958-a58942f5e105"
      description = "Compliance and audit: read-only access to records and access history. No clinical write."
    }
  }

  clinical_read_scope_id = "c8370219-04e9-41fd-9140-ba8668f38a49"

  # Microsoft's first-party Azure CLI public client (well-known id).
  azure_cli_client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
}

resource "azuread_application" "clinical_portal" {
  display_name     = var.clinical_portal_display_name
  sign_in_audience = "AzureADMyOrg" # single tenant: Contoso workforce only
  owners           = local.app_owners

  # Refuse to create a second app with the same name (a duplicate is how an
  # orphaned, ownerless copy appears in an NHI inventory).
  prevent_duplicate_names = true

  service_management_reference = var.service_management_reference != "" ? var.service_management_reference : null
  notes                        = "Contoso Health lab OIDC app. Roles: Clinician / Pharmacist / Auditor, granted to groups only. Managed by Terraform - modules/apps."

  # Groups claim = ONLY the groups assigned to this app, not every group the
  # user is in: smaller tokens (no groups overage at 200+), and the app learns
  # nothing about memberships unrelated to it.
  group_membership_claims = ["ApplicationGroup"]

  api {
    requested_access_token_version = 2

    # One delegated scope, so the app is also a protected API and an access
    # token for it can be requested and inspected (roles + groups claims).
    oauth2_permission_scope {
      id                         = local.clinical_read_scope_id
      value                      = "Clinical.Read"
      type                       = "User"
      enabled                    = true
      admin_consent_display_name = "Read clinical portal data"
      admin_consent_description  = "Allows the client to read Contoso Clinical Portal data as the signed-in user, limited by the user's app role."
      user_consent_display_name  = "Read your clinical portal data"
      user_consent_description   = "Allows the client to read Contoso Clinical Portal data on your behalf."
    }
  }

  dynamic "app_role" {
    for_each = local.clinical_portal_roles
    content {
      id                   = app_role.value.id
      value                = app_role.key # what the app checks in the `roles` claim
      display_name         = app_role.key
      description          = app_role.value.description
      allowed_member_types = ["User"] # users/groups only - no app-only (daemon) grants
      enabled              = true
    }
  }

  # acct = 0 member / 1 guest: lets the app treat a B2B guest differently
  # without a Graph call.
  optional_claims {
    id_token {
      name = "acct"
    }
    access_token {
      name = "acct"
    }
  }

  web {
    redirect_uris = var.clinical_portal_redirect_uris

    # Authorization code (+PKCE) only. The implicit flow puts tokens in the URL
    # fragment; it stays off.
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  lifecycle {
    # Managed by azuread_application_identifier_uri below (provider guidance:
    # the two must not both manage identifier_uris).
    ignore_changes = [identifier_uris]
  }
}

# api://<client-id> - the default App ID URI form, accepted by the tenant's
# identifier-URI policy without a verified domain.
resource "azuread_application_identifier_uri" "clinical_portal" {
  application_id = azuread_application.clinical_portal.id
  identifier_uri = "api://${azuread_application.clinical_portal.client_id}"
}

resource "azuread_service_principal" "clinical_portal" {
  client_id = azuread_application.clinical_portal.client_id

  # Without a role assignment, no token - for sign-in AND for the API scope.
  app_role_assignment_required = true

  owners = local.app_owners
  notes  = "Contoso Clinical Portal (lab). Access = app-role assignment to a group. Managed by Terraform - modules/apps."

  feature_tags {
    enterprise = true # listed under Enterprise applications
  }
}

# Group -> role grants. Static keys (see variable) keep for_each plannable.
resource "azuread_app_role_assignment" "clinical_portal" {
  for_each = var.clinical_portal_role_assignments

  app_role_id         = local.clinical_portal_roles[each.value.role].id
  principal_object_id = each.value.principal_object_id
  resource_object_id  = azuread_service_principal.clinical_portal.object_id
}

# Demo convenience (off by default): Azure CLI may request Clinical.Read
# without a consent prompt, so a signed-in, ASSIGNED user can fetch and decode
# a token. Unassigned users are still refused (assignment required).
# verify: Azure CLI obtains a token for a pre-authorized third-party scope.
resource "azuread_application_pre_authorized" "azure_cli" {
  count = var.clinical_portal_preauthorize_azure_cli ? 1 : 0

  application_id       = azuread_application.clinical_portal.id
  authorized_client_id = local.azure_cli_client_id
  permission_ids       = [local.clinical_read_scope_id]
}

# =============================================================================
# Governance checks (warnings, never block)
# =============================================================================

# An app with no human owner is an orphan the day its creator leaves.
check "apps_have_a_human_owner" {
  assert {
    condition     = length(var.app_owner_object_ids) > 0
    error_message = "modules/apps: no app_owner_object_ids - both apps are owned only by the Terraform identity. Name an accountable human owner (NHI governance)."
  }
}

# Half a SAML configuration is a sign-in that cannot work.
check "aws_saml_basic_configuration_complete" {
  assert {
    condition     = (var.aws_saml_entity_id == "") == (length(var.aws_saml_acs_urls) == 0)
    error_message = "modules/apps: set aws_saml_entity_id and aws_saml_acs_urls together (both come from the same AWS 'Service provider metadata' panel)."
  }
}
