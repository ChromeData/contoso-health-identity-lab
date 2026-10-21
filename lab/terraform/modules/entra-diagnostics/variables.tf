# =============================================================================
# modules/entra-diagnostics :: variables.tf
# =============================================================================

variable "name" {
  type        = string
  description = "Diagnostic setting name."
  default     = "entra-to-loga-idlab"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource id of loga-idlab (envs/dev output log_analytics_workspace_id)."
}

variable "categories" {
  type        = list(string)
  description = <<-EOT
    Baseline Entra log categories to export (exact diagnostic-setting ids,
    not table names). The defaults feed lab/kql, the provisioning evidence,
    and the workload-identity (NHI) and ITDR views: service principal and
    managed identity sign-ins plus Microsoft Graph activity logs.
    Licensing: audit and sign-in logs are Free; ProvisioningLogs and
    MicrosoftGraphActivityLogs need Entra ID P1 or P2.
    COST: each category is billed per GB ingested into the workspace (free
    inside the Sentinel trial's 10 GB/day). MicrosoftGraphActivityLogs is by
    far the largest (Learn estimate: ~15 GiB/month per 1,000 users); drop it
    here if the workspace budget ever bites. AuditLogs and SignInLogs cannot
    be dropped (plan-time precondition in main.tf).
  EOT
  default = [
    "AuditLogs",                    # PIM, group, role, app, CA changes
    "SignInLogs",                   # interactive sign-ins (CA results)
    "NonInteractiveUserSignInLogs", # token refresh - break-glass rule needs it
    "ServicePrincipalSignInLogs",   # GitHub OIDC + every app/NHI signing in
    "ManagedIdentitySignInLogs",    # DC01 + Key Vault UAMI token requests (NHI)
    "ProvisioningLogs",             # HR inbound + SaaS SCIM provisioning (P1)
    "MicrosoftGraphActivityLogs",   # every Graph request - ITDR/NHI abuse (P1)
  ]
}

variable "enable_identity_protection_logs" {
  type        = bool
  description = <<-EOT
    Add the ID Protection risk categories: RiskyUsers + UserRiskEvents (feed
    lab/kql/identity-risk.kql and the risk-based CA006/CA007 tuning) and
    RiskyServicePrincipals + ServicePrincipalRiskEvents (workload-identity
    risk for the NHI story). Needs Entra ID P2; full workload-identity risk
    detail needs Workload Identities Premium. Off by default: without P2 the
    tables stay empty and Sentinel rejects rules that query them.
  EOT
  default     = false
}

variable "extra_categories" {
  type        = list(string)
  description = <<-EOT
    Additional documented categories appended to the baseline (distinct).
    For the four risk categories use enable_identity_protection_logs (what
    envs/bootstrap passes); this list is for anything else. Anything not in
    main.tf's documented_categories list fails at plan.
  EOT
  default     = []
}
