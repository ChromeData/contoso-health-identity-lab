# =============================================================================
# modules/apps :: servicenow_provisioning.tf
# -----------------------------------------------------------------------------
# 7. ServiceNow provisioning (enable_servicenow_provisioning, off by default) -
#    Entra creates, updates and switches off ServiceNow accounts. The design
#    recorded in servicenow.tf ("PROVISIONING"), now built:
#
#      a SECOND enterprise app, from the ServiceNow GALLERY template, used for
#      provisioning only (Learn recommends a separate app for provisioning)
#        -> hidden from My Apps (the SSO app is the tile staff click)
#        -> assignment required, ONE assignment: App-ServiceNow-Users, the
#           SAME group as the SSO app, so who may sign in and who gets an
#           account can never drift apart
#        -> its synchronization job, created STOPPED
#        -> its credential (the ServiceNow integration user), from Key Vault,
#           written once by a local seeding apply, then ignored
#
# WHY A SECOND APP. The SSO app (servicenow.tf) is a NON-GALLERY SAML app, and
# a non-gallery app only offers the generic SCIM connector. The ServiceNow
# connector (Learn: "Configure ServiceNow for automatic user provisioning")
# comes with the gallery app. Moving the SSO app to the gallery template
# would replace it (new client id, new signing certificate, new ServiceNow IdP
# metadata); a provisioning-only app changes nothing that already works.
#
# VERIFIED LIVE, NOT GUESSED (tenant, 2026-11-05, on a throwaway instance of
# the template, deleted afterwards):
#   GET /v1.0/applicationTemplates?$filter=displayName eq 'ServiceNow'
#     -> id 0919fd62-4056-4151-83f7-7cfd3fade8e3, publisher ServiceNow,
#        supportedProvisioningTypes ["sync"]
#   GET /v1.0/servicePrincipals/<instance>/synchronization/templates
#     -> "ServiceNowOutDelta" (default = true; the user/group connector the
#        Learn tutorial configures) and "serviceNowScim". Metadata "Basic":
#        credential keys InstanceName, UserName, Password (secret).
#        User mapping: user_name <- userPrincipalName (matching priority 1),
#        active <- Switch([IsSoftDeleted], , "False", "1", "True", "0"), so a
#        user who leaves scope is switched OFF (active = false), not deleted.
#   POST .../synchronization/jobs/<id>/validateCredentials (useSavedCredentials)
#     with the integration user -> 204 (the API form of Test Connection).
#   App roles the instance carries: "User" 4fe59fae-f463-4713-857a-ae9e82a35498
#     and "msiam_access".
#
# THE JOIN KEY. ServiceNow user_name <- userPrincipalName is the template's
# own matching rule, and the SSO app's NameID is userPrincipalName
# (servicenow.tf claims policy) matched against user_name (the ServiceNow IdP
# record's User Field). So the account provisioning creates is exactly the
# account the Entra sign-in lands in. azuread 3.10 has no resource for the
# synchronization schema: the mapping is the template default, read back
# after the seeding apply (README "ServiceNow provisioning").
#
# THE CREDENTIAL. A dedicated ServiceNow integration user (not the instance
# admin): the "admin" role, because that is what the Learn tutorial requires
# ("A user account in ServiceNow with the admin role"), and "Web service
# access only", so it can never sign in to the ServiceNow UI. Its password
# lives in Key Vault (servicenow-provisioning-username / -password) and
# reaches Terraform only in the run that creates the credential, exactly like
# the AWS SCIM token (main.tf section 2): require_scim_credentials makes the
# gated apply fail closed instead of writing an empty credential, a PR plan
# only warns, and ignore_changes means routine plans never need it.
#
# ORDER (README "ServiceNow provisioning"): merge -> the LOCAL seeding apply
# (Key Vault firewall: only the operator's IP) -> then the CI apply. A CI
# apply that runs first fails its plan on purpose (no credential), changes
# nothing, and passes on a re-run after the seeding apply.
#
# LICENSING: provisioning to a gallery app - verify: P1 per provisioned user
# (inside the M365 E5 trial), as for AWS.
# =============================================================================

locals {
  servicenow_provisioning_enabled = var.enable_servicenow_provisioning

  # Graph applicationTemplates, read 2026-11-05 (header). A constant, like the
  # non-gallery id in servicenow.tf: a wrong id would instantiate another
  # vendor's app, so tests pin it.
  servicenow_gallery_template_id = "0919fd62-4056-4151-83f7-7cfd3fade8e3"

  # The template's default synchronization template (header).
  servicenow_sync_template_id = "ServiceNowOutDelta"

  # The connector's InstanceName is the host label of the instance URL
  # (Learn: "the instance name is dev35214" for https://dev35214.service-now.com).
  # The variable validation already guarantees this shape.
  servicenow_instance_name = (
    var.servicenow_instance_url != ""
    ? regex("^https://([a-z0-9][a-z0-9-]*)\\.service-now\\.com$", var.servicenow_instance_url)[0]
    : ""
  )

  # Enterprise-app tag + HideApp ("Visible to users? No": the provider's own
  # feature_tags.hide sets exactly this tag). Staff click the SSO tile; a
  # second ServiceNow tile that signs nobody in would only confuse them.
  servicenow_provisioning_sp_tags = ["WindowsAzureActiveDirectoryIntegratedApp", "HideApp"]

  # Observed on the instantiated template (header). Looked up by name first;
  # this id is only the fallback. Never the all-zeros default-access role:
  # users assigned only that role are skipped by provisioning.
  servicenow_gallery_user_role_id = "4fe59fae-f463-4713-857a-ae9e82a35498"
}

# The gallery app, provisioning only. azuread_application_from_template for the
# same reason as the other template apps: it manages nothing on the resulting
# objects, so Terraform never strips the template's roles.
resource "azuread_application_from_template" "servicenow_provisioning" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  display_name = var.servicenow_provisioning_app_display_name
  template_id  = local.servicenow_gallery_template_id

  lifecycle {
    precondition {
      condition     = var.servicenow_instance_url != ""
      error_message = "enable_servicenow_provisioning = true needs servicenow_instance_url: the connector's InstanceName is its host label. Set it in terraform.tfvars / TF_VAR_servicenow_instance_url, never in lab.tfvars."
    }
  }
}

data "azuread_application" "servicenow_provisioning" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  object_id = azuread_application_from_template.servicenow_provisioning[0].application_object_id
}

# Enterprise-app settings, adopting the SP the template created. Every
# attribute the provider writes is set: the adopt path PATCHes the whole
# object, and an unset app_role_assignment_required would become false -
# everyone in the tenant in provisioning scope.
resource "azuread_service_principal" "servicenow_provisioning" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  client_id    = data.azuread_application.servicenow_provisioning[0].client_id
  use_existing = true

  # Provisioning scope = assigned users and groups only. With the single
  # assignment below that is App-ServiceNow-Users and nobody else.
  app_role_assignment_required = true

  owners = local.app_owners
  tags   = local.servicenow_provisioning_sp_tags
  notes  = "Contoso Health lab: provisioning ONLY (Entra -> ServiceNow accounts), hidden from My Apps; staff sign in through the ServiceNow SAML app. Scope = App-ServiceNow-Users, the SSO app's group. Credential: ServiceNow integration user, Key Vault servicenow-provisioning-*. Managed by Terraform - modules/apps (servicenow_provisioning.tf)."
}

# The APPLY identity owns the app REGISTRATION too, whoever instantiated it.
# The credential can only be created by the operator's local seeding apply,
# and an app-only instantiate records no owner (seen on the 2026-11-05
# probe), so without this the pipeline (Application.ReadWrite.OwnedBy) could
# never update the reply URL below. Only the Terraform identity: humans own
# the enterprise app (owners above), as for the other template apps.
resource "azuread_application_owner" "servicenow_provisioning" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  application_id  = azuread_application_from_template.servicenow_provisioning[0].application_id
  owner_object_id = local.iac_owner_object_id
}

# The gallery app instantiates with the wildcard reply URL
# https://*.service-now.com/* (seen on the probe). This app signs nobody in,
# but a wildcard would let ANY ServiceNow instance receive a token for it, so
# it is replaced by this instance's one URL, as for the SSO app. Authoritative
# for the Web type.
resource "azuread_application_redirect_uris" "servicenow_provisioning" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  application_id = azuread_application_from_template.servicenow_provisioning[0].application_id
  type           = "Web"
  redirect_uris  = [local.servicenow_reply_url]

  depends_on = [azuread_application_owner.servicenow_provisioning]
}

# The single assignment, to the SSO app's group (see header). Not a list: a
# second principal would be a second provisioning scope, a design change.
resource "azuread_app_role_assignment" "servicenow_provisioning_users" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  app_role_id = coalesce(
    try(one([for r in azuread_service_principal.servicenow_provisioning[0].app_roles : r.id if r.display_name == "User" && r.enabled]), null),
    local.servicenow_gallery_user_role_id,
  )
  principal_object_id = var.servicenow_users_group_object_id
  resource_object_id  = azuread_service_principal.servicenow_provisioning[0].object_id

  lifecycle {
    precondition {
      condition     = var.servicenow_users_group_object_id != ""
      error_message = "enable_servicenow_provisioning = true needs servicenow_users_group_object_id (App-ServiceNow-Users): provisioning only sees assigned users, so with no assignment it would provision nobody."
    }
  }
}

# Created STOPPED (servicenow_provisioning_job_enabled = false): Test
# Connection and one provision-on-demand first, then a separate PR starts the
# ~40-minute cycle - the AWS order (main.tf section 2).
resource "azuread_synchronization_job" "servicenow" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  service_principal_id = azuread_service_principal.servicenow_provisioning[0].id
  template_id          = local.servicenow_sync_template_id
  enabled              = var.servicenow_provisioning_job_enabled
}

# The connector credential: InstanceName (not secret, from the instance URL)
# + UserName + Password of the integration user. Same handling as the AWS
# SCIM credential - see the header and main.tf section 2 for why each line:
# Key Vault -> one local run -> ignore_changes; the password is in state
# (sensitive), the same accepted residual risk; revocation = reset the
# integration user's password in ServiceNow.
resource "azuread_synchronization_secret" "servicenow" {
  count = local.servicenow_provisioning_enabled ? 1 : 0

  service_principal_id = azuread_service_principal.servicenow_provisioning[0].id

  credential {
    key   = "InstanceName"
    value = local.servicenow_instance_name
  }
  credential {
    key   = "UserName"
    value = try(var.servicenow_provisioning_credentials.user_name, "")
  }
  credential {
    key   = "Password"
    value = try(var.servicenow_provisioning_credentials.password, "")
  }

  # Microsoft's order: the job exists before its credential is saved.
  depends_on = [azuread_synchronization_job.servicenow]

  lifecycle {
    ignore_changes = [credential]

    # Fail closed in the gated apply (require_scim_credentials = true): never
    # write an EMPTY user name or password. Reads the planned value, which
    # after creation is the stored one, so only the creating run can trip it.
    postcondition {
      condition     = !var.require_scim_credentials || nonsensitive(alltrue([for c in self.credential : length(trimspace(c.value)) > 0]))
      error_message = "This run would create the ServiceNow provisioning credential without a value. Run the LOCAL seeding apply first (Key Vault secrets servicenow-provisioning-username / -password -> TF_VAR_servicenow_provisioning_credentials) - modules/apps/README.md \"ServiceNow provisioning\" - then re-run this apply."
    }
  }
}

# PR plans (require_scim_credentials = false) never hold the password: they
# only warn, once, on the plan that turns provisioning on.
check "servicenow_provisioning_credential_supplied_on_create" {
  assert {
    condition = !var.enable_servicenow_provisioning || nonsensitive(alltrue([
      for c in try(azuread_synchronization_secret.servicenow[0].credential, []) : length(trimspace(c.value)) > 0
    ]))
    error_message = "ServiceNow provisioning is on but this run has no servicenow_provisioning_credentials and the credential does not exist yet. Expected in a PR plan; the creating run is the local seeding apply (modules/apps/README.md \"ServiceNow provisioning\")."
  }
}
