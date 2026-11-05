# =============================================================================
# modules/apps :: variables.tf
# -----------------------------------------------------------------------------
# Inputs grouped by the things this module builds:
#   1. AWS IAM Identity Center  - SAML enterprise app (gallery template)
#   2. AWS IAM Identity Center  - SCIM provisioning (off by default)
#   3. Contoso Clinical Portal  - OIDC app registration with app roles
#   4. guacamole-psm            - PSM stand-in OIDC sign-in (off by default)
#   5. ServiceNow               - SAML enterprise app (off by default)
#   6. okta-clinic-idp          - Entra as OIDC IdP for the clinic Okta org (off by default)
# plus ownership inputs shared by every app.
#
# Nothing here is committed with a real value. Tenant identifiers come from
# terraform.tfvars / TF_VAR_* (never lab.tfvars), and the SCIM credential comes
# from Key Vault at apply time (README "SCIM credential").
# =============================================================================

# ---- Ownership (both apps) --------------------------------------------------

variable "app_owner_object_ids" {
  type        = list(string)
  description = <<-EOT
    Entra USER object ids recorded as owners of both apps (app registration +
    enterprise app). Every non-human identity needs an accountable human owner:
    it is who the NHI inventory, credential-expiry mail and access reviews
    route to. The identity running Terraform is always added as well (it must
    stay an owner to manage the apps with Application.ReadWrite.OwnedBy).
    Empty = only the Terraform identity owns them; a check warns on every plan.
    Sensitive: these are named people's object ids, and the PR plan comment
    is public (GitHub masks a secret only as one whole string, never each id
    of a JSON list, and never in a comment).
  EOT
  default     = []
  sensitive   = true

  validation {
    condition     = alltrue([for id in var.app_owner_object_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "Each app_owner_object_ids entry must be an Entra object id (GUID)."
  }
}

variable "iac_owner_client_id" {
  type        = string
  description = <<-EOT
    Client id of the identity Terraform runs as on APPLY (the GitHub APPLY
    app, repo variable AZURE_APPLY_CLIENT_ID). It is made an owner of every app
    here so it can keep managing them with Application.ReadWrite.OwnedBy -
    whoever runs a plan or a local apply. Empty = the caller (offline tests, a
    first local apply before the APPLY app exists).
  EOT
  default     = ""

  validation {
    condition     = var.iac_owner_client_id == "" || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.iac_owner_client_id))
    error_message = "iac_owner_client_id must be empty or an app (client) id GUID."
  }
}

variable "service_management_reference" {
  type        = string
  description = <<-EOT
    ITSM reference stamped on both app registrations (serviceManagementReference),
    e.g. the ServiceNow CI or change number. Lets an auditor go from an app in
    Entra to its owning record without asking anyone. Empty = not set.
  EOT
  default     = ""
}

# ---- 1. AWS IAM Identity Center: SAML ----------------------------------------

variable "aws_users_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of App-AWS-IdentityCenter-Users (modules/groups output
    app_access_group_object_ids["aws"]). The ONLY principal assigned to the
    AWS enterprise app. Assignment is the access decision AND the SCIM scope:
    the provisioning service syncs assigned users/groups only, so this one
    group is everything AWS will ever see.
  EOT

  validation {
    # Unknown at plan when the group is created in the same apply; the check
    # then runs at apply.
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.aws_users_group_object_id))
    error_message = "aws_users_group_object_id must be a group object id (GUID)."
  }
}

variable "aws_app_display_name" {
  type        = string
  description = <<-EOT
    Display name of the AWS enterprise app. Keep "AWS IAM Identity Center":
    lab/scripts/powershell/04-Leaver.ps1 -ProvisionOnDemandApps finds the app
    by this exact name, and the walkthrough video and runbooks use it.
  EOT
  default     = "AWS IAM Identity Center"

  validation {
    condition     = length(trimspace(var.aws_app_display_name)) > 0
    error_message = "aws_app_display_name must not be empty."
  }
}

variable "aws_gallery_template_id" {
  type        = string
  description = <<-EOT
    Entra application-gallery template id for "AWS IAM Identity Center
    (successor to AWS Single Sign-On)". Microsoft Graph documents
    21ed01d2-ec13-4e9e-86c1-cd546719ebc4 (learn.microsoft.com/graph/
    application-saml-sso-configure-api, checked 2026-10-20). The plan reads the
    template back and fails if its name is not AWS IAM Identity Center, so a
    wrong id can never instantiate some other vendor's app.
  EOT
  default     = "21ed01d2-ec13-4e9e-86c1-cd546719ebc4"

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.aws_gallery_template_id))
    error_message = "aws_gallery_template_id must be an application template id (GUID)."
  }
}

variable "aws_saml_entity_id" {
  type        = string
  description = <<-EOT
    Identifier (Entity ID) = the IAM Identity Center "Issuer URL", shown on
    AWS Settings -> Identity source -> Change identity source -> External
    identity provider -> Service provider metadata (pattern
    https://<region>.signin.aws.amazon.com/platform/saml/<id>). AWS shows it
    BEFORE the change is committed, so it can be set first. Empty (default) =
    not managed yet: the app exists but cannot complete a SAML sign-in.
    Not a secret, but tenant-specific: terraform.tfvars / TF_VAR_, never lab.tfvars.
  EOT
  default     = ""

  validation {
    condition     = var.aws_saml_entity_id == "" || can(regex("^https://[A-Za-z0-9.-]+/platform/saml/[^\\s/]+$", var.aws_saml_entity_id))
    error_message = "aws_saml_entity_id must be empty or the IAM Identity Center Issuer URL (https://<region>.signin.aws.amazon.com/platform/saml/<id>)."
  }
}

variable "aws_saml_acs_urls" {
  type        = list(string)
  description = <<-EOT
    Reply URL(s) (Assertion Consumer Service) for THIS Identity Center
    instance, pattern https://<host>/platform/saml/acs/<id>. List every ACS
    URL AWS uses, not only the first one its console shows: the same <id>
    appears on more than one host (IPv4 and dual-stack variants are separate
    URLs), and Entra refuses a sign-in whose AuthnRequest names an ACS URL
    that is not listed (AADSTS50011). Read live on 2026-11-05: the console
    panel showed https://us-east-1.sso.signin.aws/platform/saml/acs/<id>, but
    the AuthnRequest the access portal sends names
    https://us-east-1.signin.aws/platform/saml/acs/<id> - so the lab lists
    both. Replaces the gallery template's wildcard reply URL, so assertions
    can only be posted to THIS instance. Empty = not managed yet.
  EOT
  default     = []

  validation {
    condition     = alltrue([for u in var.aws_saml_acs_urls : can(regex("^https://[A-Za-z0-9.-]+/platform/saml/acs/[^\\s/]+$", u))])
    error_message = "Each aws_saml_acs_urls entry must be an IAM Identity Center ACS URL (https://<region>.signin.aws.amazon.com/platform/saml/acs/<id>); wildcards are not allowed."
  }
}

variable "aws_access_portal_url" {
  type        = string
  description = <<-EOT
    AWS access portal sign-in URL (https://d-xxxxxxxxxx.awsapps.com/start, or
    the custom alias). Becomes the enterprise app's Sign-on URL so the My Apps
    tile starts an SP-initiated sign-in. Empty = My Apps uses IdP-initiated.
  EOT
  default     = ""

  validation {
    condition     = var.aws_access_portal_url == "" || can(regex("^https://[^\\s]+$", var.aws_access_portal_url))
    error_message = "aws_access_portal_url must be empty or an https:// URL."
  }
}

variable "saml_signing_cert_end_date" {
  type        = string
  description = <<-EOT
    Expiry of the SAML token-signing certificate (RFC 3339, e.g.
    "2027-10-31T00:00:00Z"). null = Entra's default of 3 years. Shorter is
    stricter but every rotation is a coordinated change: changing this
    REPLACES the certificate, and AWS must be given the new IdP metadata in
    the same window or every AWS sign-in fails (README "Certificate rotation").
  EOT
  default     = null

  validation {
    condition     = var.saml_signing_cert_end_date == null || can(formatdate("YYYY-MM-DD", var.saml_signing_cert_end_date))
    error_message = "saml_signing_cert_end_date must be null or an RFC 3339 timestamp such as 2027-10-31T00:00:00Z."
  }
}

variable "saml_cert_notification_emails" {
  type        = list(string)
  description = <<-EOT
    Addresses Entra mails 60, 30 and 7 days before the SAML signing
    certificate expires (verify: the notification schedule). Use a team
    mailbox, not a person. Sensitive so a public plan comment never shows it.
  EOT
  default     = []
  sensitive   = true

  validation {
    condition     = alltrue([for e in var.saml_cert_notification_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "Each saml_cert_notification_emails entry must be an email address."
  }
}

variable "aws_saml_claims_policy_enabled" {
  type        = bool
  description = <<-EOT
    Assign a claims-mapping policy to the AWS app: NameID pinned to
    userPrincipalName (must equal the SCIM userName, or sign-in fails) plus
    the ABAC session tags in aws_abac_session_tags. A claims-mapping policy
    SUPERSEDES the portal's "Attributes & Claims" blade, which turns read-only:
    claims become reviewed code instead of a click anyone with Application
    Administrator can change. false = the gallery app's default claims
    (the documented fallback if the first sign-in shows a NameID problem).
  EOT
  default     = true
}

variable "aws_abac_session_tags" {
  type        = map(string)
  description = <<-EOT
    AWS session tags sent in the SAML assertion as
    https://aws.amazon.com/SAML/Attributes/AccessControl:<key>, keyed by tag
    key, valued by the Entra user attribute (claims-mapping "ID") that feeds
    it. Default: Department <- user.department, the attribute HR already
    drives, so a mover (Nursing -> ICU) gets a different tag at the next AWS
    sign-in with no AWS-side change. SAML (per sign-in) rather than SCIM is
    deliberate: AWS documents that an attribute REMOVED in Entra is not removed
    from the SCIM-synced user, so a SCIM-sourced tag can go stale. Needs
    "Attributes for access control" enabled in Identity Center (tenant-time
    step). Empty map = no session tags.
  EOT
  default = {
    Department = "department"
  }

  validation {
    # The tag key becomes part of a SAML attribute name and an AWS tag key.
    condition = alltrue([
      for k, v in var.aws_abac_session_tags :
      can(regex("^[A-Za-z0-9_.:/=+@-]{1,128}$", k)) && contains([
        "department", "jobtitle", "employeeid", "companyname", "country",
        "city", "state", "officelocation", "usertype",
        "extensionattribute1", "extensionattribute2", "extensionattribute3",
      ], v)
    ])
    error_message = "aws_abac_session_tags keys must be valid AWS tag keys, and values one of: department, jobtitle, employeeid, companyname, country, city, state, officelocation, usertype, extensionattribute1-3 (claims-mapping user source IDs)."
  }
}

# ---- 2. AWS IAM Identity Center: SCIM -----------------------------------------

variable "enable_scim_provisioning" {
  type        = bool
  description = <<-EOT
    Create the provisioning job and its credential (envs/dev flag
    enable_scim_provisioning). Off by default: it needs the AWS SCIM endpoint
    and token, which exist only after the AWS identity source has been switched
    to Entra (README "Staged order").
  EOT
  default     = false
}

variable "aws_scim_template_id" {
  type        = string
  description = <<-EOT
    Synchronization template id of the AWS IAM Identity Center connector (NOT
    the gallery template id above). Read it AFTER the first SSO apply:
      GET https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/synchronization/templates
    (output aws_scim_template_lookup_command). Required when
    enable_scim_provisioning = true. Left empty on purpose: Microsoft does not
    publish it and guessing it would fail at apply. verify: the id returned.
  EOT
  default     = ""

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]*$", var.aws_scim_template_id))
    error_message = "aws_scim_template_id must be a synchronization template id (letters, digits, . _ -)."
  }
}

variable "aws_scim_job_enabled" {
  type        = bool
  description = <<-EOT
    Start the provisioning job (the ~40-minute incremental cycle). false
    (default) = the job exists but is stopped: run Test Connection and
    provision ONE user on demand first, then flip this in its own PR. Turning
    it back to false pauses provisioning (nothing is deleted in AWS).
  EOT
  default     = false
}

variable "aws_scim_credentials" {
  type = object({
    tenant_url   = string # SCIM endpoint, https://scim.<region>.amazonaws.com/<id>/scim/v2
    secret_token = string # AWS "Access token" - shown once, valid 1 year (verify:)
  })
  description = <<-EOT
    The AWS SCIM endpoint and bearer token. SOURCE: Key Vault secrets
    aws-scim-tenant-url / aws-scim-token, exported as TF_VAR_ only in the run
    that CREATES (or deliberately replaces) the credential - see README "SCIM
    credential". Never committed, never in lab.tfvars, never available to PR
    plans. null (default) = not supplied in this run; once the credential
    exists Terraform ignores it (lifecycle ignore_changes), so routine plans
    never need the token.
  EOT
  default     = null
  sensitive   = true

  validation {
    condition = var.aws_scim_credentials == null || (
      can(regex("^https://[^\\s]+/scim/v2/?$", var.aws_scim_credentials.tenant_url))
      && length(trimspace(var.aws_scim_credentials.secret_token)) >= 20
    )
    error_message = "aws_scim_credentials must be null, or tenant_url an https SCIM v2 endpoint (…/scim/v2) and secret_token the AWS access token."
  }
}

variable "require_scim_credentials" {
  type        = bool
  description = <<-EOT
    Fail closed instead of warning when this run would CREATE the SCIM
    credential without aws_scim_credentials. Set true in the reviewer-gated
    apply (and in a local seeding run); leave false for PR plans, which by
    design can never read the token. Once the credential exists this has no
    effect (the stored value satisfies it).
  EOT
  default     = false
}

# ---- 3. Contoso Clinical Portal: OIDC -----------------------------------------

variable "clinical_portal_display_name" {
  type        = string
  description = "Display name of the OIDC app registration."
  default     = "Contoso Clinical Portal"
}

variable "clinical_portal_redirect_uris" {
  type        = list(string)
  description = <<-EOT
    Web (confidential client, authorization-code) redirect URIs. Default is a
    local sample web app, because the lab hosts no portal: the app proves the
    identity contract (roles, groups, consent), not a website. https only,
    except http://localhost, which Entra allows for development.
  EOT
  default     = ["https://localhost:5001/signin-oidc"]

  validation {
    condition = length(var.clinical_portal_redirect_uris) > 0 && alltrue([
      for u in var.clinical_portal_redirect_uris :
      (startswith(u, "https://") || startswith(u, "http://localhost")) && !strcontains(u, "*")
    ])
    error_message = "clinical_portal_redirect_uris must be non-empty https:// (or http://localhost) URIs without wildcards."
  }
}

variable "clinical_portal_role_assignments" {
  type = map(object({
    role                = string # Clinician | Pharmacist | Auditor
    principal_object_id = string # group (preferred) or user object id
  }))
  description = <<-EOT
    App-role grants, keyed by a STATIC name (the keys drive for_each, so they
    must be known at plan even when the group is created in the same apply).
    Assign GROUPS: membership then comes from HR rules and access packages,
    and a leaver loses the role when they leave the group. Example:
      { nurses_clinician   = { role = "Clinician",  principal_object_id = <All-Nurses> },
        pharmacy_pharmacist = { role = "Pharmacist", principal_object_id = <App-Pharmacy-Dispensing-Users> } }
    Note: app-role grants do not flow through nested groups.
  EOT
  default     = {}

  validation {
    condition     = alltrue([for k, v in var.clinical_portal_role_assignments : contains(["Clinician", "Pharmacist", "Auditor"], v.role)])
    error_message = "clinical_portal_role_assignments: role must be one of Clinician, Pharmacist, Auditor."
  }
}

variable "clinical_portal_preauthorize_azure_cli" {
  type        = bool
  description = <<-EOT
    Pre-authorize the Azure CLI (first-party public client
    04b07795-8ddb-461a-bbee-02f9e1bf7b46) for the Clinical.Read scope, so the
    demo can run `az account get-access-token --scope api://<client-id>/Clinical.Read`
    and decode the roles/groups claims without hosting a web app or enabling
    the implicit flow. Assignment-required still blocks unassigned users.
    Off by default: it is a demo convenience, not part of the target design.
  EOT
  default     = false
}

# ---- 4. guacamole-psm: PSM stand-in OIDC sign-in (guacamole.tf) --------------

variable "enable_guacamole_psm_app" {
  type        = bool
  description = <<-EOT
    Create the guacamole-psm app registration + enterprise app (implicit
    id_token, no secret, assignment required) and the PAM-Operators group it
    is assigned to, so the lab/pam Guacamole stand-in signs operators in
    through Entra (MFA + Conditional Access) instead of local passwords.
    envs/dev flag: enable_pam_oidc_app. Off by default.
  EOT
  default     = false
}

variable "guacamole_redirect_uris" {
  type        = list(string)
  description = <<-EOT
    Web redirect URIs of guacamole-psm. Must equal OPENID_REDIRECT_URI in
    lab/pam/docker-compose.oidc.yml. https only, except http://localhost
    (the local stand-in), which Entra allows for development.
  EOT
  default     = ["http://localhost:8081/guacamole/"]

  validation {
    condition = length(var.guacamole_redirect_uris) > 0 && alltrue([
      for u in var.guacamole_redirect_uris :
      (startswith(u, "https://") || startswith(u, "http://localhost")) && !strcontains(u, "*")
    ])
    error_message = "guacamole_redirect_uris must be non-empty https:// (or http://localhost) URIs without wildcards."
  }
}

# ---- 5. ServiceNow: SAML enterprise app (servicenow.tf) -----------------------

variable "enable_servicenow_sso" {
  type        = bool
  description = <<-EOT
    Create the ServiceNow SAML enterprise app (non-gallery template, settings
    from the Learn ServiceNow SSO tutorial): assignment required, ONE
    assignment (App-ServiceNow-Users), Entra-minted signing certificate,
    NameID = userPrincipalName. Needs servicenow_instance_url and
    servicenow_users_group_object_id. Provisioning to ServiceNow is designed,
    not built (servicenow.tf header). envs/dev flag: enable_servicenow_sso.
    Off by default.
  EOT
  default     = false
}

variable "servicenow_instance_url" {
  type        = string
  description = <<-EOT
    The ServiceNow instance URL, e.g. a Personal Developer Instance
    https://devNNNNN.service-now.com. It is the SAML Identifier (Entity ID)
    exactly, and the Reply URL is <this>/navpage.do. No trailing slash (the
    Learn tutorial: ServiceNow's Entity ID has none), no path, no wildcard.
    Required when enable_servicenow_sso = true. Not a secret, but
    tenant-specific: terraform.tfvars / TF_VAR_, never lab.tfvars.
  EOT
  default     = ""

  validation {
    condition     = var.servicenow_instance_url == "" || can(regex("^https://[a-z0-9][a-z0-9-]*\\.service-now\\.com$", var.servicenow_instance_url))
    error_message = "servicenow_instance_url must be empty or https://<instance>.service-now.com (lower case, no trailing slash, no path, no wildcard)."
  }
}

variable "servicenow_users_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of App-ServiceNow-Users (modules/groups output
    app_access_group_object_ids["servicenow"]) - the ONLY principal assigned
    to the ServiceNow app, and the scope a future provisioning job would use.
    Required when enable_servicenow_sso = true.
  EOT
  default     = ""

  validation {
    # Unknown at plan when the group is created in the same apply; the check
    # then runs at apply.
    condition     = var.servicenow_users_group_object_id == "" || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.servicenow_users_group_object_id))
    error_message = "servicenow_users_group_object_id must be empty or a group object id (GUID)."
  }
}

variable "servicenow_sso_sys_id" {
  type        = string
  description = <<-EOT
    sys_id of the SAML identity provider record in ServiceNow (Multi-Provider
    SSO -> Identity Providers -> the record -> Copy sys_id). Makes the Sign-on
    URL <instance>/login_with_sso.do?glide_sso_id=<sys_id>, so the My Apps
    tile signs in through THIS IdP. Empty (default) = Sign-on URL
    <instance>/navpage.do: the record does not exist until its metadata has
    been imported, so this is set in a second, staged apply.
  EOT
  default     = ""

  validation {
    condition     = can(regex("^([0-9a-f]{32})?$", var.servicenow_sso_sys_id))
    error_message = "servicenow_sso_sys_id must be empty or a ServiceNow sys_id (32 lower-case hex characters)."
  }
}

variable "servicenow_app_display_name" {
  type        = string
  description = "Display name of the ServiceNow enterprise app (My Apps tile, sign-in logs)."
  default     = "ServiceNow"

  validation {
    condition     = length(trimspace(var.servicenow_app_display_name)) > 0
    error_message = "servicenow_app_display_name must not be empty."
  }
}

variable "servicenow_saml_signing_cert_end_date" {
  type        = string
  description = <<-EOT
    Expiry of the ServiceNow SAML token-signing certificate (RFC 3339). null
    = Entra's default of 3 years. Separate from saml_signing_cert_end_date
    (AWS) so one vendor's rotation never forces the other's. Changing it
    REPLACES the certificate: ServiceNow's IdP record needs the new metadata
    (or certificate) in the same window, or every ServiceNow sign-in fails.
  EOT
  default     = null

  validation {
    condition     = var.servicenow_saml_signing_cert_end_date == null || can(formatdate("YYYY-MM-DD", var.servicenow_saml_signing_cert_end_date))
    error_message = "servicenow_saml_signing_cert_end_date must be null or an RFC 3339 timestamp such as 2027-10-31T00:00:00Z."
  }
}

variable "servicenow_saml_claims_policy_enabled" {
  type        = bool
  description = <<-EOT
    Assign a claims-mapping policy to the ServiceNow app pinning NameID to
    userPrincipalName (ServiceNow's User Field = user_name holds the UPN).
    As for the AWS app, it makes the claim reviewed code and turns the
    portal's "Attributes & Claims" blade read-only. false = the non-gallery
    app's default claims (the fallback if the first sign-in shows a NameID
    problem).
  EOT
  default     = true
}

# ---- 6. okta-clinic-idp: Entra as the IdP for the clinic's Okta org (okta.tf) --

variable "enable_okta_federation" {
  type        = bool
  description = <<-EOT
    Create okta-clinic-idp, the Entra half of the Okta coexistence
    (lab/docs/okta-migration-runbook.md Phase 1, ADR 0022): a single-tenant
    OIDC app registration whose one redirect URI is the Okta org's authorize
    callback, its service principal with assignment required, and ONE
    assignment (App-Okta-Federation-Users). The client secret is NOT created:
    a human mints it post-apply (output okta_idp_client_secret_command) and
    hands it once to the Okta root (lab/terraform/okta). Needs
    okta_org_domain and okta_federation_users_group_object_id. envs/dev flag:
    enable_okta_federation. Off by default.
  EOT
  default     = false
}

variable "okta_org_domain" {
  type        = string
  description = <<-EOT
    The Okta org HOST, e.g. integrator-1234567.okta.com (an Integrator Free
    org), dev-12345.okta.com, <org>.oktapreview.com or <org>.okta-emea.com.
    Bare host: no scheme (the module adds https), no path, no wildcard, no
    port, lower case, and never the -admin host (the admin console is not an
    OIDC callback). A custom Okta domain is a design change (the callback
    host follows issuer_mode in the Okta root), not a value here. Required
    when enable_okta_federation = true. Not a secret, but org-specific:
    terraform.tfvars / TF_VAR_, never lab.tfvars.
  EOT
  default     = ""

  validation {
    condition     = var.okta_org_domain == "" || can(regex("^[a-z0-9][a-z0-9-]*\\.(okta\\.com|oktapreview\\.com|okta-emea\\.com)$", var.okta_org_domain))
    error_message = "okta_org_domain must be empty or a bare Okta org host: <org>.okta.com, <org>.oktapreview.com or <org>.okta-emea.com (lower case; no scheme, path, port or wildcard)."
  }

  validation {
    condition     = !endswith(split(".", var.okta_org_domain)[0], "-admin")
    error_message = "okta_org_domain must be the org host, not the -admin console host: Okta's OIDC callback lives on the org host."
  }
}

variable "okta_federation_users_group_object_id" {
  type        = string
  description = <<-EOT
    Object id of App-Okta-Federation-Users (modules/groups output
    app_access_group_object_ids["okta"]) - the ONLY principal assigned to
    okta-clinic-idp, i.e. the allow-list of who may federate into Okta.
    Required when enable_okta_federation = true.
  EOT
  default     = ""

  validation {
    # Unknown at plan when the group is created in the same apply; the check
    # then runs at apply.
    condition     = var.okta_federation_users_group_object_id == "" || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.okta_federation_users_group_object_id))
    error_message = "okta_federation_users_group_object_id must be empty or a group object id (GUID)."
  }
}

variable "okta_idp_app_display_name" {
  type        = string
  description = "Display name of the Entra app registration Okta signs in through (sign-in logs, the Okta System Log's IdP name is separate). The runbook calls it okta-clinic-idp."
  default     = "okta-clinic-idp"

  validation {
    condition     = length(trimspace(var.okta_idp_app_display_name)) > 0
    error_message = "okta_idp_app_display_name must not be empty."
  }
}

variable "okta_idp_secret_lifetime_days" {
  type        = number
  description = <<-EOT
    Lifetime, in days, of the client secret a human mints post-apply with
    output okta_idp_client_secret_command (Terraform never creates it). At
    most 180: the P180D rotation recorded for okta-clinic-idp-client-secret
    in lab/iga/nhi-secrets-register.json. Rotation = mint a new one, enter it
    in the Okta root, remove the old one in Entra.
  EOT
  default     = 180

  validation {
    condition     = var.okta_idp_secret_lifetime_days >= 1 && var.okta_idp_secret_lifetime_days <= 180 && floor(var.okta_idp_secret_lifetime_days) == var.okta_idp_secret_lifetime_days
    error_message = "okta_idp_secret_lifetime_days must be a whole number of days from 1 to 180 (the register's P180D rotation is the ceiling)."
  }
}
