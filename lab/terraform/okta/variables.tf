# =============================================================================
# okta :: variables.tf
# -----------------------------------------------------------------------------
# Three kinds of input:
#   * the org (okta_org_name, okta_base_url): org-specific, in terraform.tfvars
#     (gitignored; copy terraform.tfvars.example);
#   * the clinic's "existing" Okta estate (group, group rule, legacy app):
#     always planned - in the lab this root first CREATES the state the
#     runbook's Phase 0 inventories, because no clinic Okta org pre-exists;
#   * the federation (enable_entra_federation + the Entra app's ids and the
#     client secret): staged, off by default, and the secret only ever as
#     TF_VAR_entra_client_secret at apply time.
# Nothing here is committed with a real value.
# =============================================================================

# ---- The Okta org --------------------------------------------------------------

variable "okta_org_name" {
  type        = string
  description = <<-EOT
    The org subdomain, e.g. integrator-1234567 for an Integrator Free org
    (the part before .okta.com). With okta_base_url it forms the org host
    that envs/dev's okta_org_domain must equal: output okta_org_domain.
  EOT

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*$", var.okta_org_name)) && !endswith(var.okta_org_name, "-admin")
    error_message = "okta_org_name is the bare subdomain (lower case letters, digits, hyphens; no dots, no scheme) and never the -admin host."
  }
}

variable "okta_base_url" {
  type        = string
  description = "Okta cell: okta.com (Integrator Free and production), oktapreview.com (preview) or okta-emea.com."
  default     = "okta.com"

  validation {
    condition     = contains(["okta.com", "oktapreview.com", "okta-emea.com"], var.okta_base_url)
    error_message = "okta_base_url must be okta.com, oktapreview.com or okta-emea.com."
  }
}

# ---- The clinic's Okta estate (runbook Phase 0 inventory, created here) --------

variable "clinic_login_domain" {
  type        = string
  description = <<-EOT
    The login (email) domain Okta routes to Entra, e.g. clinic.contoso.example
    for a clinic that keeps its own domain; the lab uses the hospital's
    contosohealthlab.com (clinic staff use hospital accounts after the
    acquisition, so Okta sends staff with a hospital address to the hospital
    login). It must also be the domain of the users' Entra email, because Okta
    names a JIT user after it. It
    is the SUFFIX the routing rule matches (users whose Okta username ends
    with it go to Entra) and the domain the Clinic-Staff group rule keys on.
    A bare domain: no @, no scheme, no wildcard. Not a secret, but
    org-specific: terraform.tfvars.
  EOT

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.clinic_login_domain))
    error_message = "clinic_login_domain must be a bare, lower-case DNS domain such as clinic.contoso.example (no @, scheme, path or wildcard)."
  }
}

variable "clinic_staff_group_name" {
  type        = string
  description = "Name of the Okta group the clinic's apps are assigned to (the runbook's Clinic-Staff). Membership comes from the group rule, never from Terraform."
  default     = "Clinic-Staff"

  validation {
    condition     = length(trimspace(var.clinic_staff_group_name)) > 0
    error_message = "clinic_staff_group_name must not be empty."
  }
}

variable "legacy_app_label" {
  type        = string
  description = "Label of the one legacy app the clinic still reaches through Okta (runbook Phase 0 inventory; Phase 2 moves it to an Entra app)."
  default     = "Clinic Scheduling (legacy)"

  validation {
    condition     = length(trimspace(var.legacy_app_label)) > 0
    error_message = "legacy_app_label must not be empty."
  }
}

variable "legacy_app_url" {
  type        = string
  description = <<-EOT
    URL the legacy app's Okta bookmark opens (a bookmark app: the scheduling
    system does its own sign-in, which is exactly the state Phase 2 fixes).
    https only. A placeholder in the lab: no scheduling system exists.
  EOT
  default     = "https://scheduling.clinic.example/"

  validation {
    condition     = can(regex("^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[^\\s*]*)?$", var.legacy_app_url))
    error_message = "legacy_app_url must be an https URL on a lower-case host (no wildcard, no plain http)."
  }
}

# ---- Federation: Okta trusts Entra (runbook Phase 1) --------------------------

variable "enable_entra_federation" {
  type        = bool
  description = <<-EOT
    Create the Microsoft Entra ID OIDC identity provider and the IdP
    discovery routing rule that sends clinic_login_domain users to it. Needs
    entra_tenant_id, entra_client_id (envs/dev outputs okta_idp_client_id /
    okta_idp_endpoints, from the Entra app in modules/apps okta.tf) and
    entra_client_secret (TF_VAR_, at apply time). Off by default: the first
    apply builds only the clinic's estate; the second turns this on (README
    "Apply order").
  EOT
  default     = false
}

variable "entra_tenant_id" {
  type        = string
  description = "Contoso's Entra tenant id (GUID): the authority of every endpoint on the IdP. From envs/dev output okta_idp_endpoints. Required when enable_entra_federation = true."
  default     = ""

  validation {
    condition     = var.entra_tenant_id == "" || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.entra_tenant_id))
    error_message = "entra_tenant_id must be empty or a tenant id (GUID)."
  }
}

variable "entra_client_id" {
  type        = string
  description = "Client (application) id of okta-clinic-idp: envs/dev output okta_idp_client_id. Required when enable_entra_federation = true."
  default     = ""

  validation {
    condition     = var.entra_client_id == "" || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.entra_client_id))
    error_message = "entra_client_id must be empty or an application (client) id (GUID)."
  }
}

variable "entra_client_secret" {
  type        = string
  description = <<-EOT
    The client secret a human minted on okta-clinic-idp (envs/dev output
    okta_idp_client_secret_command). Supplied ONCE, at apply time, as
    TF_VAR_entra_client_secret (`read -s` it; never a tfvars file, never a
    shell-history line). Sensitive: never printed in a plan. It lands in
    this root's LOCAL state (versions.tf header) and in Okta's credential
    store, nowhere else. Required when enable_entra_federation = true.
  EOT
  default     = ""
  sensitive   = true
}

variable "entra_idp_name" {
  type        = string
  description = "Display name of the identity provider in Okta (Security -> Identity Providers; the Okta System Log's IdP name)."
  default     = "Microsoft Entra ID (Contoso Health)"

  validation {
    condition     = length(trimspace(var.entra_idp_name)) > 0
    error_message = "entra_idp_name must not be empty."
  }
}

variable "jit_provisioning" {
  type        = bool
  description = <<-EOT
    true (lab) = Okta creates a user on first Entra sign-in when no account
    matches the email (the runbook's "JIT provisioning: on (lab)"). false
    [prod] = only pre-linked accounts sign in, so an Okta-only user with no
    HR record (Phase 0) is never created by accident. Account LINKING by
    email happens in both modes.
  EOT
  default     = true
}

variable "routing_rule_active" {
  type        = bool
  description = <<-EOT
    THE ROLLBACK (runbook Phase 1): false sets the routing rule INACTIVE, so
    clinic users fall back to Okta passwords on the next sign-in while the
    IdP stays configured. A check warns on every plan while it is false.
    Default true. Rehearsed in the Phase 1 validate step (README).
  EOT
  default     = true
}

variable "routing_rule_name" {
  type        = string
  description = "Name of the IdP discovery routing rule (the one Terraform owns; Okta's own Default Rule stays below it as the fallback)."
  default     = "Clinic staff to Microsoft Entra ID"

  validation {
    condition     = length(trimspace(var.routing_rule_name)) > 0
    error_message = "routing_rule_name must not be empty."
  }
}

# ---- The clinic's other apps (clinic-apps.tf) -----------------------------------

variable "clinic_results_label" {
  type        = string
  description = "Label of the clinic's OIDC app (wave 1). The Entra app that replaces it has the same display name (modules/apps clinic_results_display_name): the tracker joins the two by it."
  default     = "Clinic Lab Results"

  validation {
    condition     = length(trimspace(var.clinic_results_label)) > 0
    error_message = "clinic_results_label must not be empty."
  }
}

variable "clinic_results_redirect_uri" {
  type        = string
  description = "The app's loopback redirect (lab/okta-migration/clinic-results listens on it). Must equal the Entra app's redirect (modules/apps clinic_results_redirect_uris)."
  default     = "http://localhost:8471/callback"

  validation {
    condition     = can(regex("^http://(localhost|127\\.0\\.0\\.1):[0-9]{2,5}/[A-Za-z0-9/_-]*$", var.clinic_results_redirect_uri))
    error_message = "clinic_results_redirect_uri must be a loopback http URI with a port and a path."
  }
}

variable "clinic_results_login_uri" {
  type        = string
  description = "Where the Okta dashboard tile sends the user: the app's own sign-in start (it then redirects to the IdP it trusts)."
  default     = "http://localhost:8471/login"

  validation {
    condition     = can(regex("^http://(localhost|127\\.0\\.0\\.1):[0-9]{2,5}/[A-Za-z0-9/_-]*$", var.clinic_results_login_uri))
    error_message = "clinic_results_login_uri must be a loopback http URI with a port and a path."
  }
}

variable "clinic_billing_label" {
  type        = string
  description = "Label of the clinic's SAML app (wave 2). Its service provider does not exist in the lab."
  default     = "Clinic Billing"
}

variable "clinic_billing_group_name" {
  type        = string
  description = "Okta group Clinic Billing is assigned to; membership by the department group rule."
  default     = "Clinic-Billing"
}

variable "clinic_billing_department" {
  type        = string
  description = "The user.department value the Clinic-Billing group rule matches (HR-owned attribute)."
  default     = "Clinic Billing"

  validation {
    condition     = can(regex("^[A-Za-z0-9 &-]+$", var.clinic_billing_department))
    error_message = "clinic_billing_department must be plain text (letters, digits, spaces, & and -): it is placed inside an Okta EL string."
  }
}

variable "clinic_billing_acs_url" {
  type        = string
  description = "Clinic Billing's SAML Assertion Consumer Service URL. A placeholder in the lab: no billing system exists."
  default     = "https://billing.clinic.example/saml/acs"

  validation {
    condition     = startswith(var.clinic_billing_acs_url, "https://") && !strcontains(var.clinic_billing_acs_url, "*")
    error_message = "clinic_billing_acs_url must be an https URL without a wildcard."
  }
}

variable "clinic_billing_entity_id" {
  type        = string
  description = "Clinic Billing's SAML audience (SP entity id). The Entra app in wave 2 must use the same value."
  default     = "https://billing.clinic.example/saml/metadata"
}

variable "admin_console_phishing_resistant" {
  type        = bool
  description = <<-EOT
    Add a first rule to the Okta Admin Console's authentication policy that
    demands a phishing-resistant, device-bound factor (Okta Verify FastPass
    or a passkey) at every console sign-in. Off by default: it changes how
    the owner signs in to the Okta Admin Console, so the owner turns it on
    after checking FastPass works on the device they use. Rollback: false +
    apply (the API token keeps working either way).
  EOT
  default     = false
}

variable "waves_override" {
  type        = map(object({ cutover = bool, retired = bool }))
  description = <<-EOT
    Per Okta app label, overrides the cutover / retired switches of
    lab/okta-migration/waves.json. For the mocked tests, and for an
    emergency rollback applied before the waves.json PR lands (then make
    the PR). Empty by default: waves.json is the source.
  EOT
  default     = {}
}

variable "okta_admin_console_app_id" {
  type        = string
  description = "App id of the org's Okta Admin Console (0oa...; Applications > Okta Admin Console, or lab/okta-migration/inventory.json). Needed only with admin_console_phishing_resistant. Org-specific: terraform.tfvars."
  default     = ""
}
