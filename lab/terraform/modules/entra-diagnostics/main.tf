# =============================================================================
# modules/entra-diagnostics :: main.tf
# -----------------------------------------------------------------------------
# Tenant-level Entra ID diagnostic setting: streams audit, sign-in (user,
# service principal, managed identity), provisioning and Microsoft Graph
# activity logs - plus, opt-in, the ID Protection risk logs - into the lab
# Log Analytics workspace, where lab/kql runs.
#
# Called from envs/bootstrap (HUMAN-applied), NOT from the CI-applied envs/dev:
#   * Configuring it needs an Entra admin role (Security Administrator or
#     Global Administrator) that the pipeline identities deliberately lack
#     (APPLY could grant itself one).
#   * Defence in depth: CI-applied Terraform never manages this setting, so a
#     PR cannot remove it. A compromised APPLY identity still could, after
#     granting itself Security Administrator (Tier-0 path, see
#     modules/pipeline-identity).
#
# What each category feeds (category -> Log Analytics table):
#   AuditLogs                    -> AuditLogs: PIM, role, group, app, CA changes
#   SignInLogs                   -> SigninLogs: interactive sign-ins, CA results
#   NonInteractiveUserSignInLogs -> AADNonInteractiveUserSignInLogs (break-glass)
#   ServicePrincipalSignInLogs   -> AADServicePrincipalSignInLogs (OIDC/NHI)
#   ManagedIdentitySignInLogs    -> AADManagedIdentitySignInLogs (DC01 / UAMI)
#   ProvisioningLogs             -> AADProvisioningLogs: HR inbound + SCIM
#   MicrosoftGraphActivityLogs   -> MicrosoftGraphActivityLogs: every Graph
#                                   request, for ITDR/NHI (enumeration, app
#                                   abuse); joins SigninLogs on the token id
#   RiskyUsers / UserRiskEvents  -> AADRiskyUsers / AADUserRiskEvents
#                                   (identity-risk.kql, CA006/CA007 tuning)
#   RiskyServicePrincipals /     -> AADRiskyServicePrincipals /
#   ServicePrincipalRiskEvents      AADServicePrincipalRiskEvents (NHI risk)
#
# LICENSING (Microsoft Learn "Microsoft Entra licensing" and the ID
# Protection / Graph activity log pages, checked 2026-10-20):
#   * Audit logs and sign-in logs: Free (Learn's monitoring-and-health
#     licensing table lists Sign-in logs as Free = Yes).
#     verify: Free tenants can ROUTE SignInLogs through diagnostic settings.
#     The table does not say "export", and older Learn/CIS text required
#     P1/P2 to export sign-in data; the "Integrate Microsoft Entra logs with
#     Azure Monitor logs" prerequisites (updated 2026-06-15) list no licence.
#     The lab/kql detections reading SigninLogs point here.
#   * Provisioning logs and Microsoft Graph activity logs: Entra ID P1 or P2.
#   * RiskyUsers / UserRiskEvents: ID Protection, Entra ID P2 (P1/Free get
#     only limited risk information). Opt-in: enable_identity_protection_logs.
#   * RiskyServicePrincipals / ServicePrincipalRiskEvents: all tenants get the
#     detections with limited detail; full detail and risk-based CA for
#     workload identities need Workload Identities Premium. Managed
#     identities are out of scope of workload-identity risk.
#   verify: whether ARM rejects a category the tenant is not licensed for, or
#   accepts it and exports nothing (tenant-time, first bootstrap apply).
#
# COST: billed per GB ingested into loga-idlab (Analytics plan), no charge for
# the setting itself. MicrosoftGraphActivityLogs is the high-volume one -
# Learn's planning estimate is about 15 GiB/month of Azure Monitor Logs per
# 1,000 users; the lab tenant has a few dozen. It cannot be filtered in the
# diagnostic setting; trim it with a workspace transformation or the Basic
# plan if it ever matters.
# =============================================================================

locals {
  # Opt-in ID Protection categories (Entra ID P2; workload-identity risk in
  # full needs Workload Identities Premium).
  identity_protection_categories = [
    "RiskyUsers",
    "UserRiskEvents",
    "RiskyServicePrincipals",
    "ServicePrincipalRiskEvents",
  ]

  effective_categories = sort(distinct(concat(
    var.categories,
    var.enable_identity_protection_logs ? local.identity_protection_categories : [],
    var.extra_categories,
  )))

  # Category ids Microsoft Learn documents for the tenant ("General")
  # diagnostic setting ("Logs available for streaming from Microsoft Entra
  # ID", checked 2026-10-20). The azurerm provider does not validate category
  # names, so without this list a typo would only fail at apply, in the
  # tenant. Learn spells one heading's id "NonInteractiveUserSIgnInLogs" (sic);
  # the id the provider documents and this lab uses is
  # NonInteractiveUserSignInLogs. CustomSecurityAttributeAuditLogs is a
  # separate setting (Attribute Log Administrator), so it is not accepted here.
  documented_categories = [
    "AuditLogs",
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "ManagedIdentitySignInLogs",
    "ProvisioningLogs",
    "ADFSSignInLogs",
    "RiskyUsers",
    "UserRiskEvents",
    "RiskyServicePrincipals",
    "ServicePrincipalRiskEvents",
    "RiskyAgents",
    "AgentRiskEvents",
    "NetworkAccessTrafficLogs",
    "EnrichedOffice365AuditLogs",
    "RemoteNetworkHealthLogs",
    "MicrosoftGraphActivityLogs",
    "MicrosoftServicePrincipalSignInLogs",
  ]

  # Most lab/kql rules read one of these two. The exceptions (2026-10-20) are
  # the DC SecurityEvent rules (ad-privileged-group-change, dcsync-replication-
  # request, kerberoast-rc4-service-ticket, tier0-logon-without-checkout,
  # dc-logon-outside-operator-allowlist) and the VaultCheckout_CL rule
  # (vault-privileged-access-anomaly), which this setting does not feed.
  # Dropping either category silently blinds the rest, so it is a plan-time
  # error instead.
  required_categories = ["AuditLogs", "SignInLogs"]
}

resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  name                       = var.name
  log_analytics_workspace_id = var.log_analytics_workspace_id

  dynamic "enabled_log" {
    for_each = toset(local.effective_categories)
    content {
      category = enabled_log.value
    }
  }

  lifecycle {
    precondition {
      condition     = alltrue([for c in local.effective_categories : contains(local.documented_categories, c)])
      error_message = "modules/entra-diagnostics: unknown Entra log category in categories/extra_categories: ${join(", ", [for c in local.effective_categories : c if !contains(local.documented_categories, c)])}. Use the exact category id from Microsoft Learn (\"Logs available for streaming from Microsoft Entra ID\"), e.g. SignInLogs, not SigninLogs (the table name)."
    }
    precondition {
      condition     = alltrue([for c in local.required_categories : contains(local.effective_categories, c)])
      error_message = "modules/entra-diagnostics: AuditLogs and SignInLogs must always be exported - most lab/kql detections read one of them."
    }
  }
}
