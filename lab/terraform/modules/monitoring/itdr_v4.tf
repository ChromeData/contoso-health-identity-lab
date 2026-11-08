# =============================================================================
# modules/monitoring :: itdr_v4.tf
# -----------------------------------------------------------------------------
# ITDR pack, fourth set (enable_itdr_detections_v4, off by default). Written
# on 2026-11-07 for the hostile review (readiness/karen-review-2026-11-06.md):
#
#   operator_signin_outside_allowlist  B1: the lab operator's service
#                                      principal signs in from an IP that is
#                                      not in the operator_ips watchlist
#                                      (no CA for workload identities in the
#                                      lab, so this is the compensating
#                                      control). Sentinel only (watchlist).
#   operator_permissions_changed       B1: app roles, grants, credentials,
#                                      owners or the app of the operator
#                                      change - by anyone, itself included.
#   break_glass_auth_method_added      B2: any security info registered or
#                                      changed on a break-glass account, by
#                                      anyone (an app minting a passkey shows
#                                      as "User registered security info",
#                                      which auth-method-changed-by-admin
#                                      leaves out).
#   hr_leaver_lag                      C5: an HR leaver disabled in AD but
#                                      still enabled in Entra 15 min later.
#   failed_signin_spray_by_asn         D1: credential failures against 10+
#                                      distinct users from one ASN in 1 h.
#
# WHY A SEPARATE FLAG (as itdr_v2.tf / itdr_v3.tf): an apply that works today
# must not change because new rules were merged, and Sentinel refuses a rule
# whose table has no data, which would fail the whole apply. The five were
# run read-only on the Log Analytics query engine with synthetic rows (the
# kusto-harness cases, run-on-workspace.py); no Sentinel rule was created.
#
# None of them triggers containment: the subjects are a workload identity,
# break-glass accounts (the containment playbook refuses them), an AD account
# already disabled, or a whole network.
# =============================================================================

locals {
  itdr_v4_rules = {
    operator_signin_outside_allowlist = {
      file         = "operator-signin-outside-allowlist.kql"
      display_name = "Contoso ITDR - Lab operator signs in from outside its allowlist"
      description  = "The lab operator workload identity (ADR 0024; matched by its object id / appId) signed in from an IP that is not an unexpired operator_ips watchlist entry. High on success, Medium for failures only (T1078.004, T1528). Empty watchlist = every sign-in alerts. Sentinel only."
      severity     = "High"
      frequency    = "PT15M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["InitialAccess", "CredentialAccess"]
      techniques   = ["T1078", "T1528"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "ServicePrincipalName" }, { identifier = "AadUserId", column = "ServicePrincipalId" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "IPAddress" }] },
      ]
      severity_column  = "Severity"
      custom_details   = { SignIns = "SignIns", Succeeded = "Succeeded" }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    operator_permissions_changed = {
      file         = "operator-permissions-changed.kql"
      display_name = "Contoso ITDR - Lab operator's permissions, credentials or owners changed"
      description  = "An app role, delegated grant, credential, owner or app/SP setting of the lab operator workload identity changed, by anyone including itself (T1098.001, T1098.003). High; Medium for a pure removal."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["Persistence", "PrivilegeEscalation"]
      techniques   = ["T1098"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "Actor" }] },
      ]
      severity_column  = "Severity"
      custom_details   = { Operation = "OperationName", ActorIsOperator = "ActorIsOperator" }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    break_glass_auth_method_added = {
      file         = "break-glass-auth-method-added.kql"
      display_name = "Contoso ITDR - Authentication method added to a break-glass account"
      description  = "Security info registered, updated or made default on a break-glass account (object id or bg-admin-NN), by anyone: the account, an admin or an application (T1098.005, T1556.006). High; Medium for a failure or a deletion."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["Persistence", "CredentialAccess"]
      techniques   = ["T1098", "T1556"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "TargetUpn" }, { identifier = "AadUserId", column = "TargetObjectId" }] },
      ]
      severity_column  = "Severity"
      custom_details   = { Actor = "Actor", ActorKind = "ActorKind" }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 0
      la_mute          = null
    }
    hr_leaver_lag = {
      file         = "hr-leaver-lag.kql"
      display_name = "Contoso ITDR - HR leaver still enabled in Entra ID after 15 minutes"
      description  = "HR's inbound provisioning disabled the AD account (or failed to), and Cloud Sync has not disabled the Entra user 15 minutes later: the leaver can still sign in to the cloud (T1078). Runbook: jml-exception.md 'Urgent leaver'."
      severity     = "High"
      frequency    = "PT15M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["Persistence"]
      techniques   = ["T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "ObjectGuid", column = "AdObjectGuid" }] },
      ]
      severity_column  = "Severity"
      custom_details   = { EmployeeId = "EmployeeId", Reason = "Reason" }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    failed_signin_spray_by_asn = {
      file             = "failed-signin-spray-by-asn.kql"
      display_name     = "Contoso ITDR - Password spray across one network (distinct users per ASN)"
      description      = "Credential failures against 10+ distinct users, 3 or fewer tries each, from one ASN in 1 h, in either sign-in table (T1110.003). High when one of those users also signed in successfully from that ASN after their first failure."
      severity         = "Medium"
      frequency        = "PT15M"
      period           = "PT1H"
      suppress         = null
      tactics          = ["CredentialAccess"]
      techniques       = ["T1110"]
      entities         = [] # a network, not one account or IP
      severity_column  = "Severity"
      custom_details   = { Asn = "Asn", DistinctUsers = "DistinctUsers" }
      alert_per_result = true
      group_by         = null
      la_severity      = 2
      la_mute          = null
    }
  }

  v4_sentinel_only_rule_keys = ["operator_signin_outside_allowlist"]
  v4_never_contain           = keys(local.itdr_v4_rules)
}
