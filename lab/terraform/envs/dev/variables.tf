# =============================================================================
# envs/dev :: variables.tf
# =============================================================================

# ---- Staging flags ----------------------------------------------------------

variable "enable_premium" {
  type        = bool
  description = <<-EOT
    Create the P1/P2 layer: break-glass + groups, Conditional Access, PIM.
    Leave false until the M365 E5 (Entra ID P2) trial is running.
  EOT
  default     = false
}

variable "enable_dc" {
  type        = bool
  description = <<-EOT
    Create the AD DS domain controller VM (modules/dc-vm). Free tier - no
    Entra license needed - but it costs Azure compute while running.
  EOT
  default     = false
}

variable "enable_sentinel" {
  type        = bool
  description = <<-EOT
    Onboard Microsoft Sentinel + deploy the analytics rules from lab/kql.
    STARTS THE 31-DAY SENTINEL TRIAL. Only after Entra logs have flowed for a
    few hours (rules over never-populated tables are rejected).
  EOT
  default     = false
}

variable "enable_la_alerts" {
  type        = bool
  description = "Deploy the lab/kql queries as Log Analytics scheduled query alerts (post-Sentinel-trial path). Mutually exclusive with enable_sentinel: modules/monitoring refuses a plan with both on. Flip both in one change when the trial ends."
  default     = false
}

variable "enable_intune_vm" {
  type        = bool
  description = <<-EOT
    Create the Windows 11 Enterprise VM (modules/intune-vm) that is Entra
    joined + auto-enrolled in Intune - the "compliant device" CA005 needs.
    Costs Azure compute while running (auto-shutdown nightly). The Intune /
    CA005 demo also needs enable_premium (M365 E5 trial) - see the check in
    main.tf. Do the human prereqs in lab/scripts/intune/README.md (MDM user
    scope, licence, bootstrap re-apply) BEFORE flipping this - enrollment
    happens during the join at apply time.
  EOT
  default     = false
}

variable "intune_vm_admin_login_object_ids" {
  type        = list(string)
  description = <<-EOT
    Entra USER object ids granted "Virtual Machine Administrator Login" on the
    Intune VM (e.g. your admin account). The CA005 pilot group is granted it
    automatically when enable_premium = true. Empty = pilot group only.
  EOT
  default     = []
}

variable "enable_access_reviews" {
  type        = bool
  description = <<-EOT
    Shorthand for ALL THREE risk-tiered review flags below (ADR 0012):
    true = enable_access_reviews_privileged + _requestable + _inactive. Kept
    so existing tfvars / docs still work; prefer the three flags (one PR per
    tier). Even with all three on, no T3 birthright clinical package is ever
    reviewed. Needs enable_governance = true and a fallback reviewer group
    (access_review_fallback_group_object_id, else
    entitlement_approver_group_object_id) or plan fails. Creates real review
    campaigns that email reviewers. Turning a POLICY review back off needs the
    portal (the azuread provider suppresses removal of the block).
  EOT
  default     = false
}

variable "enable_access_reviews_privileged" {
  type        = bool
  description = "ADR 0012 T1: quarterly default-deny reviews of every PIM-governed group (eligible + active; bodies from modules/pim and modules/entitlement) and of Global Administrator eligibility (enable_global_admin_pim_policy), plus a policy review on any T1 package. Rendered into output access_review_definitions for post-apply/New-AccessReviewDefinitions.ps1. Needs enable_governance (PIM-for-Groups reviews need Entra ID Governance)."
  default     = false
}

variable "enable_access_reviews_requestable" {
  type        = bool
  description = "ADR 0012 T2: half-yearly removeAccess policy review ONLY on requestable packages that live longer than 180 days or allow extension (a plain 180-day package is certified by its expiry + re-approval). Never touches a T3 birthright package. Needs enable_governance."
  default     = false
}

variable "enable_access_reviews_inactive" {
  type        = bool
  description = "Inactive-user (stale account) review of App-Okta-Federation-Users (90 days without sign-in, default deny + auto-apply), rendered into access_review_definitions. Needs enable_governance."
  default     = false
}

variable "enable_governance" {
  type        = bool
  description = <<-EOT
    Create the Entra ID Governance layer: catalog + access packages. Leave
    false until the Governance trial is running. Requires enable_premium.
  EOT
  default     = false
}

# ---- Azure platform ---------------------------------------------------------

variable "subscription_id" {
  type        = string
  description = <<-EOT
    Azure subscription id for the azurerm (Key Vault/networking) resources.
    Required by azurerm v4 at plan/apply. Leave empty to rely on
    ARM_SUBSCRIPTION_ID in the environment.
  EOT
  default     = ""
}

variable "tenant_id" {
  type        = string
  description = "Entra ID tenant id. Empty = inherit from the ambient credentials."
  default     = ""
}

variable "location" {
  type        = string
  description = "Azure region for all azurerm resources (contract: eastus2)."
  default     = "eastus2"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group holding Key Vault + networking (contract: rg-identity-lab)."
  default     = "rg-identity-lab"
}

variable "log_analytics_name" {
  type        = string
  description = "Log Analytics workspace name (contract: loga-idlab)."
  default     = "loga-idlab"
}

variable "key_vault_name" {
  type        = string
  description = "Key Vault name (contract: kv-idlab; append a suffix for global uniqueness)."
  default     = "kv-idlab"
}

variable "operator_ip_ranges" {
  type        = list(string)
  description = <<-EOT
    Operator IPs, each a single IPv4 host as /32 (e.g. "203.0.113.7/32").
    Admitted through the Key Vault firewall, the DC's NSG (RDP + LDAPS), the
    Intune VM's NSG (RDP) and the evidence store firewall; with enable_dc the
    same entries feed the Sentinel operator_ips watchlist
    (dc-logon-outside-operator-allowlist, ADR 0013). Empty = vault reachable
    only via its private endpoint and no inbound to the VMs. Sensitive so the
    plan comment the pipeline posts on a PUBLIC repo never shows your IP.
    Validation: never wider than /24 for anything; /32 ONLY while
    enable_dc = true (modules/dc-vm admits single hosts to DC01, a Tier-0
    asset - ADR 0013). Keep it /32 in every case.
  EOT
  default     = []
  sensitive   = true

  # Sensitive, so a wide range would not show in the plan: reject 0.0.0.0/0
  # (or any typo'd wide CIDR) before it opens RDP/LDAPS and the vault to the
  # internet. try() because && does not short-circuit on older versions.
  # Neither message prints the value.
  validation {
    condition = alltrue([
      for c in var.operator_ip_ranges :
      can(cidrnetmask(c)) && try(tonumber(split("/", c)[1]) >= 24, false)
    ])
    error_message = "Each operator_ip_ranges entry must be an IPv4 CIDR no wider than /24 (use a single host, e.g. 203.0.113.7/32)."
  }

  # DC01 is Tier 0: with enable_dc the root refuses anything but single
  # hosts, the same rule modules/dc-vm and the monitoring watchlist enforce,
  # so the plan fails HERE with this message rather than deep in a module.
  # Cross-variable validation needs Terraform >= 1.9 (versions.tf).
  validation {
    condition = !var.enable_dc || alltrue([
      for c in var.operator_ip_ranges : try(endswith(c, "/32") && cidrnetmask(c) == "255.255.255.255", false)
    ])
    error_message = "enable_dc = true: every operator_ip_ranges entry must be a single IPv4 host as /32 (DC01 RDP/LDAPS and the operator_ips watchlist admit single hosts only - ADR 0013)."
  }
}

variable "key_vault_secrets_officer_ids" {
  type        = list(string)
  description = "Object ids of human custodians granted Key Vault Secrets Officer (e.g. your admin account)."
  default     = []
}

# ---- Monitoring --------------------------------------------------------------

variable "alert_email" {
  type        = string
  description = "Email for the Log Analytics alert action group (post-trial path). Empty = no notifications."
  default     = ""
  sensitive   = true # keeps your address out of the public plan comment
}

variable "sentinel_playbook_id" {
  type        = string
  description = "Resource id printed by lab/scripts/monitoring/Deploy-Playbook.ps1. Empty = no automation rule yet."
  default     = ""
}

# ---- Entra ID / identity ----------------------------------------------------

variable "onmicrosoft_domain" {
  type        = string
  description = <<-EOT
    The tenant's initial *.onmicrosoft.com domain (e.g. "contosohealthlab.onmicrosoft.com").
    Break-glass UPNs use it so emergency access never depends on custom DNS.
    Workforce UPNs on the custom domain come from HR provisioning, not Terraform.
  EOT
  default     = ""
}

variable "ca_policy_states" {
  type        = map(string)
  description = <<-EOT
    Per-policy CA state keyed CA001..CA010, CA020..CA023, CA060. CA001..CA005
    are always required; every other key only while its staging flag is on
    (enable_identity_protection_ca -> CA006 + CA007,
    enable_phishing_resistant_all_users -> CA008, enable_registration_ca -> CA009,
    enable_device_code_block -> CA010, enable_admin_session_controls -> CA020,
    enable_pim_auth_context -> CA021, enable_protected_actions_ca -> CA023,
    enable_pam_oidc_app -> CA022 (numbered
    CA009 before the design-principle ranges), enable_shared_clinical_ca ->
    CA060). The module rejects a map missing a required key, or with an
    unknown key. null (default) = the module default, which is REPORT-ONLY for
    every policy. Enforce one policy per PR, e.g.
    { CA001 = "enabled", CA002 = "enabledForReportingButNotEnforced", ... }.
  EOT
  default     = null
}

variable "blocked_countries" {
  type        = list(string)
  description = "ISO alpha-2 country codes blocked by the CA location policy."
  default     = ["KP", "IR", "SY", "CU"]
}

variable "pim_approver_object_ids" {
  type        = list(string)
  description = <<-EOT
    User object ids that approve PIM-for-Groups activations. Required (non-empty)
    unless you also set pim_require_approval = false.
  EOT
  default     = []
}

variable "pim_require_approval" {
  type        = bool
  description = "Require approver sign-off before PIM-for-Groups activation."
  default     = true
}

variable "entitlement_approver_group_object_id" {
  type        = string
  description = <<-EOT
    Group whose members approve access-package requests. Empty => approval
    routes to the requestor's manager (requestorManager).
  EOT
  default     = ""
}

variable "access_review_fallback_group_object_id" {
  type        = string
  description = <<-EOT
    Group whose members review users who have no manager in the directory.
    Empty => entitlement_approver_group_object_id. Tenant identifier: set it in
    terraform.tfvars locally or the TF_ACCESS_REVIEW_FALLBACK_GROUP_OBJECT_ID
    GitHub variable in CI, not in lab.tfvars.
  EOT
  default     = ""
}

# ---- Identity Protection + passwordless (CA006..CA008) -----------------------

variable "enable_identity_protection_ca" {
  type        = bool
  description = <<-EOT
    Create CA006 (user risk High -> MFA + secure password change) and CA007
    (sign-in risk High -> block), report-only first. Risk conditions need
    Entra ID P2 for every user in scope (M365 E5 trial) and enable_premium.
    Flip only once the E5 licences are ASSIGNED: without P2 there is no risk
    signal and the policies never match. Also find the Microsoft-managed
    "require risk remediation" policy and set it report-only/off by hand so
    CA006 is the single user-risk policy (modules/conditional-access header).
  EOT
  default     = false
}

variable "sign_in_risk_block_levels" {
  type        = list(string)
  description = "Sign-in risk levels CA007 blocks (must include \"high\"). Test knob: a report-only run with [\"medium\", \"high\"] proves CA007 would have blocked a simulated sign-in that scored Medium. Default [\"high\"]."
  default     = ["high"]
}

variable "enable_phishing_resistant_all_users" {
  type        = bool
  description = <<-EOT
    Create CA008 (phishing-resistant authentication strength for the
    workforce; report-only, scope ca008_scope), its workforce authentication
    strength, the CA008-Pilot-PhishingResistant group and the dynamic
    All-Workforce group (the staff passkey profile target of
    post-apply/Set-AuthenticationMethodsPolicy.ps1 -IncludeStaffRollout).
    Needs enable_premium (custom authentication strengths + dynamic groups
    are P1).
  EOT
  default     = false
}

variable "ca008_scope" {
  type        = string
  description = <<-EOT
    Who CA008 includes: "all_users" (default; report-only = measure the
    registration gap tenant-wide) or "pilot" (the CA008 pilot group - the
    scope you ENFORCE first; widen by adding people to the pilot group).
  EOT
  default     = "all_users"
}

variable "ca008_allow_all_users_enforcement" {
  type        = bool
  description = <<-EOT
    Second key for the one change that can lock out the whole workforce:
    CA008 "enabled" with ca008_scope = "all_users". Leave false until the
    registration report (07-Passwordless-Rollout.ps1) shows every in-scope
    user holds a phishing-resistant method and the pilot ran enforced.
  EOT
  default     = false
}

variable "ca008_pilot_group_object_id" {
  type        = string
  description = <<-EOT
    Optional EXISTING group to use as the CA008 pilot. Empty (default) = the
    module creates CA008-Pilot-PhishingResistant. Must be a literal object id
    (known at plan), never another resource's output. Tenant identifier:
    terraform.tfvars / TF_* variable, not lab.tfvars.
  EOT
  default     = ""
}

variable "admin_fido2_allowed_aaguids" {
  type        = set(string)
  description = <<-EOT
    Allow-list of FIDO2 key MODEL AAGUIDs for the ADMIN strength (CA002,
    CA021, CA022). Empty (default) = any passkey satisfies CA002. Only meaningful
    once the Passkey (FIDO2) authentication-methods policy enforces
    attestation (Set-AuthenticationMethodsPolicy.ps1 -AdminAllowedAaguids,
    same list) - until then the AAGUID is self-reported. REQUIRED before
    enable_phishing_resistant_all_users (the workforce rollout lets admins
    register synced passkeys; this list is what keeps those off admin
    sign-ins) unless accept_admin_synced_passkey_risk is set.
  EOT
  default     = []
}

variable "accept_admin_synced_passkey_risk" {
  type        = bool
  description = "Second key: allow enable_phishing_resistant_all_users with an EMPTY admin_fido2_allowed_aaguids (admins could then satisfy CA002 / CA021 / CA022 with a synced passkey). A reviewed risk acceptance - record it in the risk register. Default false."
  default     = false
}

# ---- Conditional Access additions (CA009, CA010, CA020, CA021, CA060) ---------
# Every one is a staging flag (default false, lab.tfvars) whose policy is
# REPORT-ONLY via ca_policy_states. All need enable_premium (check in main.tf).

variable "enable_registration_ca" {
  type        = bool
  description = "CA009: registering security info needs a one-time TAP or a phishing-resistant method (bootstrap-and-recovery strength); all users, break-glass and guests excluded. Report-only via ca_policy_states CA009. Since 2026-07-06 registration policies also govern Windows Hello / Platform SSO registration - measure before enforcing."
  default     = false
}

variable "enable_device_code_block" {
  type        = bool
  description = "CA010: block the device code flow for all users (break-glass + ca010_exception_group_object_ids excluded). Report-only via ca_policy_states CA010. ENFORCING it breaks the operator's `az login --use-device-code` and Invoke-BaselineAssessment.ps1 -UseDeviceCode: move those to browser sign-in, or use a CA010-Exclusion-<reason> group through the exception process, first."
  default     = false
}

variable "ca010_exception_group_object_ids" {
  type        = list(string)
  description = "CA010 exception groups (CA010-Exclusion-<reason>: owner, expiry, monthly review; role-assignable so a Groups Administrator cannot join it), excluded NEXT TO break-glass. Empty = none. Tenant identifiers: terraform.tfvars / TF_CA010_EXCEPTION_GROUP_OBJECT_IDS, never lab.tfvars."
  default     = []
}

variable "enable_admin_session_controls" {
  type        = bool
  description = "CA020: sign-in every 4 h on the admin portals (Azure portal + Azure Service Management API) for the Tier-0/1 roles of the PIM tier map and the PIM-governed admin groups. Session control only. Report-only via ca_policy_states CA020."
  default     = false
}

variable "enable_pim_auth_context" {
  type        = bool
  description = "CA021: render the PIM activation authentication context (c1) and its CA policy (admin phishing-resistant strength, sign-in every time) as output pim_auth_context_requests; post-apply/Set-AuthContextPolicies.ps1 writes both (the provider can create neither). State via ca_policy_states CA021. PIM only requires c1 once CA021 is \"enabled\" and pim_tier0_activation_auth_context_id is set."
  default     = false
}

variable "enable_protected_actions_ca" {
  type        = bool
  description = "CA023: render a second authentication context (c2) and its CA policy (admin phishing-resistant strength, sign-in every time) for PROTECTED ACTIONS - Conditional Access policy and named-location update/delete - as output protected_actions_auth_context_requests; post-apply/Set-AuthContextPolicies.ps1 writes both. Binding c2 to the protected actions is a tenant-time step (Invoke-PostApply.ps1 prints it; only once CA023 is enforced). State via ca_policy_states CA023. Default false."
  default     = false
}

variable "enable_shared_clinical_ca" {
  type        = bool
  description = "CA060 (ADR 0014): on shared clinical workstations (Autopilot deployment profile CH-SharedClinical) All-Nurses + All-ICU need the workforce phishing-resistant strength, sign in every 8 h, never a persistent browser. Needs enable_phishing_resistant_all_users (the workforce strength). Report-only via ca_policy_states CA060; enforcement needs Clinical Operations sign-off. Code only: no such device exists in the lab."
  default     = false
}

# ---- SSO apps + SCIM (modules/apps) ------------------------------------------

variable "enable_sso_apps" {
  type        = bool
  description = <<-EOT
    Create the AWS IAM Identity Center SAML app (one assignment:
    App-AWS-IdentityCenter-Users) and the Contoso Clinical Portal OIDC app
    (Clinician / Pharmacist / Auditor roles). Needs enable_premium (group
    assignment to an enterprise app is P1) and the APPLY identity's
    app-management Graph roles (envs/bootstrap enable_app_management_roles).
    The AWS app cannot complete a sign-in until aws_saml_entity_id /
    aws_saml_acs_urls are set - it fails closed (modules/apps/README.md
    "Staged order").
  EOT
  default     = false
}

variable "enable_scim_provisioning" {
  type        = bool
  description = <<-EOT
    Create the AWS IAM Identity Center provisioning job (STOPPED) and its
    credential. Needs enable_sso_apps and aws_scim_template_id. The creating
    run must export TF_VAR_aws_scim_credentials from Key Vault (a LOCAL
    seeding apply - CI runners cannot reach the vault); never in CI.
  EOT
  default     = false
}

variable "aws_scim_job_enabled" {
  type        = bool
  description = "Start the AWS provisioning job (~40-minute cycle). Flip in its own PR only after Test Connection + one on-demand provision succeeded."
  default     = false
}

variable "aws_saml_entity_id" {
  type        = string
  description = "IAM Identity Center Issuer URL (https://<region>.signin.aws.amazon.com/platform/saml/<id>). Empty = not managed yet. Tenant-specific: terraform.tfvars / TF_AWS_SAML_ENTITY_ID repo variable, never lab.tfvars."
  default     = ""
}

variable "aws_saml_acs_urls" {
  type        = list(string)
  description = "IAM Identity Center ACS URL(s): every host AWS uses for this instance (the console panel's and the one in the access portal's AuthnRequest - they differ; modules/apps variables.tf). Empty = not managed yet (no wildcard reply URL is ever kept). Tenant-specific: TF_AWS_SAML_ACS_URLS."
  default     = []
}

variable "aws_access_portal_url" {
  type        = string
  description = "AWS access portal URL (https://d-xxxxxxxxxx.awsapps.com/start) - the My Apps tile's SP-initiated sign-on URL. Empty = IdP-initiated."
  default     = ""
}

variable "aws_scim_template_id" {
  type        = string
  description = "Synchronization template id of the AWS connector, read AFTER the first SSO apply (output aws_scim_template_lookup_command). Required when enable_scim_provisioning = true."
  default     = ""
}

variable "aws_scim_credentials" {
  type = object({
    tenant_url   = string
    secret_token = string
  })
  description = <<-EOT
    AWS SCIM endpoint + bearer token, ONLY for the run that creates (or
    deliberately replaces) the credential: export from Key Vault secrets
    aws-scim-tenant-url / aws-scim-token as TF_VAR_aws_scim_credentials.
    null (default) = not supplied; afterwards Terraform ignores it. Never
    committed, never in lab.tfvars, never passed by CI.
  EOT
  default     = null
  sensitive   = true
}

variable "require_scim_credentials" {
  type        = bool
  description = "Fail closed (instead of warning) when this run would CREATE a provisioning credential without its value: the AWS SCIM credential without aws_scim_credentials, or the ServiceNow connector credential without servicenow_provisioning_credentials. true in terraform-apply.yml and the local seeding apply; false for PR plans, which can never read the vault."
  default     = false
}

variable "app_owner_object_ids" {
  type        = list(string)
  description = "Entra USER object ids recorded as owners of the apps in modules/apps: at least TWO accountable humans, a named owner plus a backup (ADR 0018, nhi-standard N1; fewer and a check warns). lab/iga/nhi-owners.json records who and why. TF_APP_OWNER_OBJECT_IDS secret; sensitive because the plan (and the public PR plan comment) would otherwise print each id, which GitHub's secret masking does not cover."
  default     = []
  sensitive   = true
}

variable "apply_client_id" {
  type        = string
  description = "Client id of the GitHub APPLY app (repo variable AZURE_APPLY_CLIENT_ID, passed as TF_VAR_apply_client_id by both pipeline workflows). modules/apps makes it the Terraform owner of every app, so a PR plan run as PLAN, or a local apply by a human, does not try to change the owners. Empty = the caller."
  default     = ""
}

variable "saml_cert_notification_emails" {
  type        = list(string)
  description = "Addresses Entra mails before the AWS SAML signing certificate expires (a team mailbox). Sensitive so the public plan comment never shows it."
  default     = []
  sensitive   = true
}

variable "enable_pam_oidc_app" {
  type        = bool
  description = <<-EOT
    Create guacamole-psm (implicit id_token sign-in for the lab/pam PSM
    stand-in, no secret, assignment required) and PAM-Operators, its only
    assignee. Needs enable_sso_apps (lives in modules/apps). Replaces the
    portal click-path in lab/pam/README.md section 6.
  EOT
  default     = false
}

variable "clinical_portal_preauthorize_azure_cli" {
  type        = bool
  description = <<-EOT
    Demo convenience for evidence E25 only: pre-authorize the Azure CLI on the
    Clinical Portal's Clinical.Read scope so a test user can decode a real
    token's roles/groups claims (modules/apps README, "Demo"). Needs
    enable_sso_apps. Off by default and not part of the target design:
    assignment-required still blocks unassigned users, but a pre-authorized
    first-party client skips the consent prompt, so turn it off after the
    capture.
  EOT
  default     = false
}

variable "enable_servicenow_sso" {
  type        = bool
  description = <<-EOT
    Create the ServiceNow SAML enterprise app (modules/apps servicenow.tf):
    non-gallery SAML app with the Learn tutorial's ServiceNow settings,
    assignment required, ONE assignment (App-ServiceNow-Users), Entra-minted
    signing certificate, NameID = UPN. Needs enable_sso_apps and
    servicenow_instance_url (the plan fails without it). Accounts come from
    enable_servicenow_provisioning. Off by default.
  EOT
  default     = false
}

variable "servicenow_instance_url" {
  type        = string
  description = "ServiceNow instance URL, e.g. the PDI https://devNNNNN.service-now.com (no trailing slash): the SAML Identifier, and <url>/navpage.do is the Reply URL. Required when enable_servicenow_sso = true. Tenant-specific: terraform.tfvars / TF_VAR_servicenow_instance_url, never lab.tfvars."
  default     = ""
}

variable "servicenow_sso_sys_id" {
  type        = string
  description = "sys_id of the SAML identity provider record created in ServiceNow (Multi-Provider SSO) - makes the My Apps sign-on URL login_with_sso.do?glide_sso_id=<sys_id>. Empty = <instance>/navpage.do; set in a second apply once the record exists."
  default     = ""
}

variable "enable_servicenow_provisioning" {
  type        = bool
  description = <<-EOT
    Create the ServiceNow provisioning app (modules/apps
    servicenow_provisioning.tf): gallery "ServiceNow" app, hidden from My
    Apps, assigned only to App-ServiceNow-Users (the SSO app's group), its
    ServiceNowOutDelta job created STOPPED, and its credential (InstanceName
    from servicenow_instance_url + the integration user). The run that creates
    the credential must be the LOCAL seeding apply with
    TF_VAR_servicenow_provisioning_credentials from Key Vault (CI cannot reach
    the vault and fails closed). Needs enable_sso_apps. Off by default.
  EOT
  default     = false
}

variable "servicenow_provisioning_job_enabled" {
  type        = bool
  description = "Start the ServiceNow provisioning job (~40-minute cycle). Flip in its own PR only after Test Connection + one provision-on-demand succeeded."
  default     = false
}

variable "servicenow_provisioning_credentials" {
  type = object({
    user_name = string
    password  = string
  })
  description = <<-EOT
    The ServiceNow integration user for the provisioning connector, ONLY for
    the run that creates (or deliberately replaces) the credential: export
    from Key Vault secrets servicenow-provisioning-username /
    servicenow-provisioning-password as TF_VAR_servicenow_provisioning_credentials.
    null (default) = not supplied; afterwards Terraform ignores it. Never
    committed, never in lab.tfvars, never passed by CI.
  EOT
  default     = null
  sensitive   = true
}

variable "enable_okta_federation" {
  type        = bool
  description = <<-EOT
    Create okta-clinic-idp (modules/apps okta.tf), the Entra half of the
    Okta coexistence (lab/docs/okta-migration-runbook.md Phase 1, ADR 0022):
    a single-tenant OIDC app registration whose one redirect URI is the Okta
    org's authorize callback, assignment required, ONE assignment
    (App-Okta-Federation-Users). The client secret is minted by a human
    post-apply (output okta_idp_client_secret_command), never by Terraform.
    Needs enable_sso_apps and okta_org_domain (the plan fails without it).
    The Okta half is the separate, human-applied root lab/terraform/okta,
    applied after this. Off by default.
  EOT
  default     = false
}

variable "okta_org_domain" {
  type        = string
  description = "Okta org host, e.g. integrator-1234567.okta.com (bare host: no scheme, path or wildcard; never the -admin host): the host of okta-clinic-idp's one redirect URI. Must equal lab/terraform/okta output okta_org_domain. Required when enable_okta_federation = true. Org-specific: terraform.tfvars / TF_VAR_okta_org_domain, never lab.tfvars."
  default     = ""
}

# ---- Governance / PIM extensions ---------------------------------------------

variable "enable_pim_tiers" {
  type        = bool
  description = "Create the PIM tier groups (modules/pim pim_tier_groups: 8 Tier-0 groups - MFA, or the c1 auth context once CA021 is enforced, + justification + ticket + approval by PIM-Approvers-Tier0, 4h, eligibility expires after 180 days; 8 Tier-1 groups incl. PIM-Tier1-Helpdesk and PIM-Tier1-IGA-Admins - MFA + justification, 8h, eligibility 365 days, plus approval on PIM-Tier1-Intune-Admins and PIM-Tier1-IGA-Admins). Needs enable_premium and Tier-0 approvers (pim_tier0_approver_object_ids, else pim_approver_object_ids; two or more recommended)."
  default     = false
}

variable "enable_pim_azure_resources" {
  type        = bool
  description = "Make PIM-Azure-RG-Contributors ELIGIBLE for Contributor on the lab RG (Azure PIM, MFA + justification + approval, 4h). Needs enable_premium and a HUMAN applier with Owner / User Access Administrator on the RG - the CI APPLY identity cannot write PIM role-management policies (modules/pim/README.md)."
  default     = false
}

variable "enable_pim_aws_admin" {
  type        = bool
  description = "AWS admin without root (ADR 0025): create PIM-AWS-Lab-Admins (modules/pim aws.tf; eligible-only, 2-hour MFA + justification activation, every activation mailed) and assign it to the AWS IAM Identity Center app as its second principal (modules/apps), so SCIM copies only ACTIVE members to AWS. lab/terraform/aws grants the SCIM copy the LabAdministrator permission set. Needs enable_premium and enable_sso_apps; eligibility is a post-apply step."
  default     = false
}

variable "enable_pim_demo_readers" {
  type        = bool
  description = "Read-only presenter access (modules/pim demo-readers.tf): create PIM-Demo-Readers, a role-assignable group that actively holds Global Reader + Security Reader tenant-wide; membership eligible-only (MFA + justification, 8-hour cap, NO approval, every activation mailed to pim_alert_mailbox, eligibility expires after 365 days). Reviewed quarterly and watched by the ITDR group rule, NOT in the CA002 / CA020 scope. Its Azure Reader / Microsoft Sentinel Reader / Log Analytics Reader on the subscription are granted by envs/bootstrap (enable_pim_demo_readers_azure_rbac, human-applied) from output pim_demo_readers_group_object_id. Needs enable_premium; eligibility (adm-presenter) is a post-apply step."
  default     = false
}

variable "enable_b2b_governance" {
  type        = bool
  description = "Create the Affiliated Partners catalog + Affiliated Physicians guest package (connected-org requestors, sponsor approval, 90-day expiry, monthly sponsor review). Needs enable_premium + enable_governance; post-apply/New-B2BConnectedOrganization.ps1 creates the connected organization."
  default     = false
}

variable "pim_tier0_approver_object_ids" {
  type        = list(string)
  description = "User object ids approving Tier-0 activations. Empty => pim_approver_object_ids. Tenant identifiers: terraform.tfvars / TF_PIM_TIER0_APPROVER_OBJECT_IDS, not lab.tfvars."
  default     = []
}

variable "privileged_review_reviewer_group_object_id" {
  type        = string
  description = "Group reviewing privileged (PIM-eligible) access - a governance group, never one of the reviewed groups. Empty => the access-review fallback group. Tenant identifier: TF_PRIVILEGED_REVIEW_REVIEWER_GROUP_OBJECT_ID."
  default     = ""
}

variable "pim_alert_mailbox" {
  type        = string
  description = "Security mailbox (one address) added to PIM's admin notifications (modules/pim: Tier 0 + approval-gated groups get activation, eligible-assignment and direct-active alerts; other Tier-1 groups the two assignment alerts). Empty = tenant default notifications. Tenant data: terraform.tfvars / a CI SECRET, never lab.tfvars. Sensitive."
  default     = ""
  sensitive   = true
}

variable "enable_helpdesk_au_scoping" {
  type        = bool
  description = "Create AU-Workforce-Standard and scope PIM-Tier1-Helpdesk's Helpdesk + Authentication Administrator roles to it instead of the tenant (modules/pim helpdesk.tf). Needs enable_premium and enable_pim_tiers. The AU's dynamic membership rule is a TENANT-TIME Graph PATCH (output pim_workforce_au_membership_body); the group stays in CA002/CA020 by group (admin_scope_group_object_ids), because AU-scoped roles are invisible to CA's role condition."
  default     = false
}

variable "helpdesk_au_excluded_employee_ids" {
  type        = list(string)
  description = "HR employee ids kept out of AU-Workforce-Standard (modules/pim workforce_au_excluded_employee_ids): the VIPs in the restricted management AU RMAU-VIP (post-apply/New-RestrictedAdminUnit.ps1). Changes the rendered rule in output pim_workforce_au_membership_body only; the PATCH that applies it stays a tenant-time step."
  default     = []
}

variable "enable_global_admin_pim_policy" {
  type        = bool
  description = "Render the Global Administrator role's own PIM policy (approval by PIM-Approvers-Tier0, MFA or the Tier-0 auth context, justification + ticket, 2h, eligibility expires after 180 days) as output directory_role_pim_policies for post-apply/Set-DirectoryRolePimPolicies.ps1, and - with enable_access_reviews_privileged - the quarterly review of ELIGIBLE Global Administrators. Break-glass keeps its standing assignment. Needs enable_premium and Tier-0 approvers."
  default     = false
}

variable "pim_tier0_activation_auth_context_id" {
  type        = string
  description = <<-EOT
    Authentication context PIM Tier-0 (and Global Administrator) activation
    requires instead of plain MFA ("" = MFA, the default). Passed to BOTH
    modules/pim and modules/conditional-access: the plan is REFUSED until
    CA021 is declared enforced (enable_pim_auth_context = true and
    ca_policy_states CA021 = "enabled") on the same id (c1) AND
    ca021_enforced_in_tenant = true. That attestation can only be true after
    an EARLIER apply declared CA021 enabled and
    post-apply/Set-AuthContextPolicies.ps1 wrote it - so this is always a
    separate, later change. Switching an existing Tier-0 policy from MFA is
    TWO applies (pim_tier0_auth_context_switchover_step1 first).
  EOT
  default     = ""

  # Root copy of the ordering gate. Learn (PIM for Groups role settings): the
  # MFA backup is not triggered when the context's CA policy is report-only
  # or off, so PIM must not point at the context before the ENFORCED CA021 is
  # in the tenant. modules/conditional-access and modules/pim refuse it too;
  # this one fails first, at the variable a reviewer edits.
  validation {
    condition     = var.pim_tier0_activation_auth_context_id == "" || (var.enable_pim_auth_context && try(var.ca_policy_states["CA021"], "") == "enabled" && var.ca021_enforced_in_tenant && can(regex("^c([1-9]|1[0-9]|2[0-5])$", var.pim_tier0_activation_auth_context_id)))
    error_message = "pim_tier0_activation_auth_context_id must stay \"\" until CA021 is ENFORCED IN THE TENANT: enable_pim_auth_context = true, ca_policy_states CA021 = \"enabled\", AND ca021_enforced_in_tenant = true (set in a later change, after Set-AuthContextPolicies.ps1 reported CA021 enabled). Values are c1..c25."
  }
}

variable "ca021_enforced_in_tenant" {
  type        = bool
  description = <<-EOT
    Operator attestation of TENANT state: true only after an earlier apply
    declared CA021 "enabled" and post-apply/Set-AuthContextPolicies.ps1
    reported the enforced CA021 (and context c1, isAvailable) in the tenant.
    terraform apply writes the Tier-0 PIM policies BEFORE any post-apply
    step, so the declared state of the same change cannot protect them.
    Required for pim_tier0_activation_auth_context_id and
    pim_tier0_auth_context_switchover_step1; refused while CA021 is not
    declared enabled. Default false.
  EOT
  default     = false

  validation {
    condition     = !var.ca021_enforced_in_tenant || (var.enable_pim_auth_context && try(var.ca_policy_states["CA021"], "") == "enabled")
    error_message = "ca021_enforced_in_tenant = true needs enable_pim_auth_context = true and ca_policy_states CA021 = \"enabled\": the attestation must match what the code declares (the next post-apply run would otherwise rewrite CA021)."
  }
}

variable "pim_tier0_auth_context_switchover_step1" {
  type        = bool
  description = "Apply 1 of the two-apply MFA -> auth-context switch for existing Tier-0 PIM policies (modules/pim tier0_activation_auth_context_id): Tier 0 drops require_multifactor_authentication while pim_tier0_activation_auth_context_id is still \"\". Needs CA021 enforced in the tenant (ca021_enforced_in_tenant); a check warns while Tier 0 has no step-up. Run apply 2 (pim_tier0_activation_auth_context_id = \"c1\") straight after."
  default     = false

  # Same gate: apply 1 removes Tier 0's MFA, so it is only allowed once the
  # context that replaces it is enforced.
  validation {
    condition     = !var.pim_tier0_auth_context_switchover_step1 || (var.enable_pim_auth_context && try(var.ca_policy_states["CA021"], "") == "enabled" && var.ca021_enforced_in_tenant)
    error_message = "pim_tier0_auth_context_switchover_step1 drops Tier-0 MFA: only once CA021 is ENFORCED IN THE TENANT (enable_pim_auth_context = true, ca_policy_states CA021 = \"enabled\" and ca021_enforced_in_tenant = true)."
  }
}

variable "b2b_connected_organization" {
  type = object({
    display_name = string
    domain_name  = string
    tenant_id    = optional(string, "")
  })
  description = <<-EOT
    The affiliated clinic rendered into the connected-organization body for
    post-apply/New-B2BConnectedOrganization.ps1. tenant_id set => the clinic's
    Entra tenant (azureActiveDirectoryTenant); empty => domain_name
    (domainIdentitySource, e.g. email one-time passcode). The default is
    fictional (reserved .example TLD): at tenant time use a domain you control
    or a second free Entra tenant. Tenant identifier: terraform.tfvars.
  EOT
  default = {
    display_name = "Fabrikam Affiliated Clinic"
    domain_name  = "fabrikam-clinic.example"
  }
}

variable "b2b_connected_organization_id" {
  type        = string
  description = "Connected organization id printed by post-apply/New-B2BConnectedOrganization.ps1; narrows the guest policy to that clinic. Empty => all configured connected orgs. Tenant identifier: TF_B2B_CONNECTED_ORGANIZATION_ID."
  default     = ""
}

# ---- Non-human identity governance ---------------------------------------------

variable "enable_nhi_governance" {
  type        = bool
  description = <<-EOT
    Create App-Consent-Reviewers (modules/groups), the reviewer group of the
    admin consent workflow that post-apply/Set-ConsentPolicy.ps1 turns on.
    Needs enable_premium (the groups module is premium-tier). The app
    management policy and consent policy themselves are post-apply scripts
    (Set-AppGovernancePolicy.ps1, Set-ConsentPolicy.ps1) - Graph tenant
    policy the provider cannot express.
  EOT
  default     = false
}

variable "enable_agent_identity" {
  type        = bool
  description = <<-EOT
    Create uami-agent-runtime: a dedicated user-assigned managed identity,
    with NO role assignments, that post-apply/New-AgentIdentity.ps1 federates
    an Entra Agent ID blueprint to (output agent_runtime_uami_principal_id ->
    -ManagedIdentityPrincipalId). Dedicated, not the Key Vault reader UAMI:
    one identity per workload (OWASP NHI9, identity reuse). Free tier; the
    Agent ID API itself is preview and licence-gated (verify: Agent 365).
  EOT
  default     = false
}

# ---- ITDR (identity threat detection + response) -------------------------------

variable "enable_itdr_detections" {
  type        = bool
  description = <<-EOT
    Add the eleven ITDR rules (lab/kql: app credential added, consent granted,
    CA policy / named location / auth strength changed, role assigned outside
    PIM, privileged-group member added outside PIM, auth method changed by an
    admin, identity risk, and the AD plane: Tier-0 logon PAM does not account
    for, privileged AD group change, Kerberoasting, DCSync) to the active
    detection path, and create their telemetry: VaultCheckout_CL + DCE + DCR
    for lab/scripts/monitoring/ingest-vault-audit.sh, and - with enable_dc -
    the Azure Monitor Agent + Security-event DCR on DC01. Starts NO trial.
    Turn on BEFORE enable_sentinel so the AuditLogs tables and
    VaultCheckout_CL have data when Sentinel validates the rules. The
    identity_risk rule also needs the envs/bootstrap
    enable_identity_protection_logs categories. verify: per Microsoft Learn,
    DC01 Security events reach SecurityEvent (rather than Event) only once
    Sentinel + its "Windows Security Events via AMA" connector are on, so the
    four SecurityEvent rules stay in itdr_exclude_rules until then.
  EOT
  default     = false
}

variable "itdr_exclude_rules" {
  type        = list(string)
  description = "ITDR rule keys (v1 and v2) to hold back while their table has never received data (Sentinel rejects such rules) or, for the PREVIEW rule, until a real activation confirms it. Set in lab.tfvars (reviewed, and read by CI), not terraform.tfvars: CI never loads that file, so a key held back only there is deployed by the next CI apply. Default [] = every selected rule deploys."
  default     = []
}

variable "enable_itdr_detections_v2" {
  type        = bool
  description = <<-EOT
    Add the six second-wave ITDR rules (modules/monitoring itdr_v2.tf:
    device-code sign-in, security info registered from a risky context, DC01
    logon outside the operator allowlist, vault privileged-access anomaly,
    SoD violation granted, Tier-0 PIM activation without the auth context)
    and, on the Sentinel path with enable_dc, the operator_ips watchlist
    built from operator_ip_ranges (rows expire on operator_ips_expires_on).
    Needs enable_itdr_detections (modules/monitoring refuses the plan
    otherwise). Starts no trial. The security-info and SoD rules are Sentinel
    only (14-day look-back); the SoD and vault rules never trigger
    containment. Hold rules whose data does not exist yet in
    itdr_exclude_rules (see that variable).
  EOT
  default     = false
}

variable "operator_ips_expires_on" {
  type        = string
  description = "ExpiresOn (yyyy-mm-dd) of every operator_ips watchlist row: ADR 0013's review date. dc-logon-outside-operator-allowlist ignores an expired row (so every DC01 logon alerts) and the plan warns once the date has passed. Required while the watchlist exists (enable_sentinel + enable_itdr_detections_v2 + enable_dc with operator_ip_ranges). null = not set."
  default     = null
}

variable "vault_feed_v2_columns" {
  type        = bool
  description = "Add Ticket, Operator and ErrorText to VaultCheckout_CL and its DCR stream (vault-privileged-access-anomaly). Turn on in the SAME change that runs lab/scripts/monitoring/ingest-vault-audit.sh --signals all: once Ticket exists, every Tier-0 check-out without one is a High alert. Needs enable_itdr_detections."
  default     = false
}

variable "enable_defender_for_identity" {
  type        = bool
  description = <<-EOT
    Wire Microsoft Defender for Identity (MDI) alerts into this workspace via
    the Microsoft Defender XDR connector (ADR 0023). This is the only MDI piece
    Terraform can express; the sensor on DC01, the MDI workspace, the directory
    service account and the Defender licence (free 90-day trial) are human
    steps in lab/docs/runbooks/deploy-defender-for-identity-dc01.md. Needs
    enable_sentinel. MDI is the native AD-attack detector; the four
    SecurityEvent KQL rules are its portable twins (tier0-logon-without-checkout
    and dc-logon-outside-operator-allowlist stay custom: correlations MDI
    cannot make).
  EOT
  default     = false
}

variable "enable_itdr_containment" {
  type        = bool
  description = <<-EOT
    Run the containment playbook (lab/monitoring/playbook-contain.json: Teams
    approval card -> revoke sessions + disable or flag for AD disable) on NEW
    High-severity ITDR incidents. Needs enable_sentinel and
    enable_itdr_detections (modules/monitoring refuses the plan otherwise),
    and creates nothing until containment_playbook_id is set.
  EOT
  default     = false
}

variable "containment_playbook_id" {
  type        = string
  description = "Resource id printed by lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1 (pb-identity-contain). Empty = no containment automation rule yet. CI: TF_CONTAINMENT_PLAYBOOK_ID repo variable."
  default     = ""
}

variable "containment_rule_keys" {
  type        = list(string)
  description = "ITDR rule keys whose High incidents trigger containment. null (default) = every deployed ITDR rule."
  default     = null
}

variable "containment_on_alert_added" {
  type        = bool
  description = "Also run containment when a High ITDR alert is ADDED to an existing incident (the Defender portal can correlate a new alert into an older incident, which the Created trigger never sees). Off by default; verify on the first Defender-portal incident."
  default     = false
}

variable "iac_principal_ids" {
  type        = list(string)
  description = "The APPLY identity's service principal object id + client id (envs/bootstrap output iac_principal_ids). The ITDR rules treat ONLY these ids as IaC - never the display name. Empty = nothing is IaC (fail closed). CI: TF_IAC_PRINCIPAL_IDS repo variable (JSON list)."
  default     = []
}

variable "privileged_user_object_ids" {
  type        = list(string)
  description = "Extra privileged user object ids for auth-method-changed-by-admin.kql (members / eligible members of the PIM groups, role holders): Find-ShadowAdmins.ps1 -PrivilegedIdsPath writes them. Break-glass users are added automatically. CI: TF_PRIVILEGED_USER_OBJECT_IDS repo variable (JSON list)."
  default     = []
}

# ---- Evidence store (WORM) -----------------------------------------------------

variable "enable_evidence_store" {
  type        = bool
  description = <<-EOT
    Create the WORM evidence storage account (modules/evidence-store):
    version-level immutability (Unlocked first), Entra-only auth, deny-by-
    default firewall (operator_ip_ranges), delete-denying writer condition,
    blob logs to loga-idlab. Free tier (Azure storage cost only). Apply it
    BEFORE Day 0 of the trial window (lab/docs/evidence-capture-plan.md).
    The writer role is granted by a HUMAN afterwards (module header).
  EOT
  default     = false
}

variable "evidence_storage_account_name" {
  type        = string
  description = "Globally unique storage account name for the evidence store (3-24 lowercase letters/digits). Add a suffix to the contract name, e.g. stidlabevidence7k2. CI: TF_EVIDENCE_STORAGE_ACCOUNT_NAME repo variable."
  default     = "stidlabevidence"
}

variable "evidence_immutability_days" {
  type        = number
  description = "Days each evidence blob version stays immutable. Default 2190 (6 years, HIPAA documentation retention). Shorten BEFORE locking if the lab will be torn down."
  default     = 2190
}

variable "evidence_immutability_state" {
  type        = string
  description = "\"Unlocked\" (default; can still be shortened or disabled), \"Locked\" (irreversible - needs evidence_immutability_lock_acknowledged) or \"Disabled\" (teardown)."
  default     = "Unlocked"
}

variable "evidence_immutability_lock_acknowledged" {
  type        = bool
  description = "Second key for Locked: true only in the deliberate lock PR (Day 28 of the capture plan). Once locked, the retention can only grow and the account cannot be deleted until every blob expires."
  default     = false
}

# ---- Tagging ----------------------------------------------------------------

variable "tags" {
  type        = map(string)
  description = "Tags applied to azurerm resources."
  default = {
    project     = "contoso-health-identity-lab"
    environment = "dev"
    managed_by  = "terraform"
  }
}

# ---- VM sizes ---------------------------------------------------------------
# 2026-10-27, eastus2, this (new trial) subscription: Standard_B2s and then
# Standard_B2s_v2 both failed with "SkuNotAvailable ... Capacity Restrictions",
# and the regional SKU list offers this subscription no B-series and no D v3-v5
# at all: only v7 (v6 is NotAvailableForSubscription). Standard_D2als_v7 =
# 2 vCPU / 4 GiB (B2s's memory), AMD, StandardDalsv7Family quota 4, NVMe-only
# disks (the modules then set disk_controller_type = "NVMe").
variable "dc_vm_size" {
  type        = string
  description = "VM size of DC01 (modules/dc-vm). Default Standard_D2als_v7: the only generation this subscription is offered in eastus2."
  default     = "Standard_D2als_v7"

  validation {
    condition     = can(regex("^Standard_[A-Za-z0-9_]+$", var.dc_vm_size))
    error_message = "dc_vm_size must be an Azure VM size name such as Standard_D2als_v7."
  }
}

variable "intune_vm_size" {
  type        = string
  description = "VM size of the Windows 11 Intune VM (modules/intune-vm). Default Standard_D2als_v7, for the same reason as dc_vm_size."
  default     = "Standard_D2als_v7"

  validation {
    condition     = can(regex("^Standard_[A-Za-z0-9_]+$", var.intune_vm_size))
    error_message = "intune_vm_size must be an Azure VM size name such as Standard_D2als_v7."
  }
}

# SAML token-signing certificate expiry for the AWS and ServiceNow apps (RFC 3339).
# The tenant's default app management policy (Set-AppGovernancePolicy.ps1) caps
# key credentials at P180D for apps created after Day 3, and Entra refuses a
# longer signing certificate (CredentialInvalidLifetimeAsPerAppPolicy, seen on
# the first apps apply, 2026-10-28). A date is a policy knob, so it lives in
# lab.tfvars; moving it REPLACES the certificate (modules/apps README, rotation).
variable "saml_signing_cert_end_date" {
  type        = string
  description = "Expiry of the AWS IAM Identity Center SAML signing certificate (RFC 3339); null = Entra's 3-year default, which the lab's 180-day credential policy rejects."
  default     = null
}

variable "servicenow_saml_signing_cert_end_date" {
  type        = string
  description = "Expiry of the ServiceNow SAML signing certificate (RFC 3339); null = Entra's 3-year default, which the lab's 180-day credential policy rejects."
  default     = null
}
