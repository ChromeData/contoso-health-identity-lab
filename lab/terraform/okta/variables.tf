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
    The clinic users' login (email) domain, e.g. clinic.contoso.example. It
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
