# =============================================================================
# modules/monitoring :: itdr_v2.tf
# -----------------------------------------------------------------------------
# ITDR pack, second set (enable_itdr_detections_v2): six more lab/kql rules,
# each with its SPL twin in lab/splunk/detections, plus the Sentinel
# watchlist one of them reads.
#
#   device_code_signin                 device code phishing / token theft
#   security_info_registered_risky     MFA method registered from a risky,
#                                      new-country or unmanaged context
#   dc_logon_outside_operator_allowlist  DC01 logon from outside the
#                                      operator_ips watchlist (ADR 0013)
#   vault_privileged_access_anomaly    PAM vault misuse (credential read, rotation failure)
#   sod_violation_granted              separation-of-duties pair completed
#                                      (lab/iga/sod-rules.json, ADR 0012)
#   pim_activation_without_auth_context  Tier-0 PIM activation without the
#                                      CA authentication context (PREVIEW)
#
# WHY A SEPARATE FLAG (not more entries behind enable_itdr_detections):
#   * Staging. Sentinel validates each rule's query when it creates it, and a
#     rejected rule fails the whole apply. These six read data a fresh lab
#     does not have yet: DC01 SecurityEvent (needs Sentinel + the AMA
#     connector first), the extended VaultCheckout_CL feed
#     (vault_feed_v2_columns + the ingest script), and PIM activation
#     strings still marked verify:. Folding them into the existing flag
#     would change what an apply that works today creates. This flag keeps
#     that apply unchanged and adds the set once its data exists;
#     itdr_exclude_rules still holds back any one rule.
#   * Two of them are Sentinel only. security_info_registered_risky and
#     sod_violation_granted look back 14 days, and Log Analytics alerts
#     look back at most 2 days (the provider rejects a longer
#     window_duration). They are left off the enable_la_alerts path
#     (local.sentinel_only_rule_keys); there is no post-trial equivalent.
#   * Two of them must never start containment (local.itdr_never_contain):
#     disabling a clinician over an SoD conflict is a patient-safety event
#     (ADR 0012), and the vault rule's Account is a Vault identity the
#     playbook cannot act on (it would print an AD-disable instruction for
#     a name that is not an AD account).
#   Cost is not the reason: scheduled rules over Analytics-plan tables add
#   no ingestion, and these read tables the lab already collects.
#   verify: on the Microsoft Sentinel pricing page, that scheduled rules
#   carry no per-query charge.
#
# Needs enable_itdr_detections (variable validation): the telemetry it
# creates (VaultCheckout_CL, DC01 Security events) feeds two of the six.
# =============================================================================

locals {
  itdr_v2_rules = {
    device_code_signin = {
      file            = "device-code-signin.kql"
      display_name    = "Contoso ITDR - Device-code flow sign-in (device code phishing)"
      description     = "Sign-in with the OAuth device authorization grant, or a token from a session that started with one (T1528, T1566.002, T1078.004). High when tokens reached a privileged user or the sign-in carried medium/high risk; Low when blocked or failed. The detective twin of the Conditional Access block on the device code flow: a success after that block is enforced is a gap in it."
      severity        = "Medium"
      frequency       = "PT5M"
      period          = "PT1H"
      suppress        = null
      tactics         = ["InitialAccess", "CredentialAccess", "DefenseEvasion"]
      techniques      = ["T1528", "T1566", "T1078"]
      entities        = local.signin_user_entities
      severity_column = "Severity"
      custom_details = {
        Outcome    = "Outcome"
        Via        = "Via"
        Privileged = "PrivilegedTarget"
        SignInRisk = "MaxSignInRisk"
        Apps       = "Apps"
        Successes  = "Successes"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
    security_info_registered_risky = {
      file            = "security-info-registered-risky.kql"
      display_name    = "Contoso ITDR - Security info registered from a risky or unfamiliar context"
      description     = "A user registered their own MFA / passwordless method from a risky sign-in, a country not seen in 14 days or an unmanaged device; every privileged registration is High (T1098.005, T1556.006). The self-service half of auth-method-changed-by-admin. Sentinel only (14-day look-back)."
      severity        = "Medium"
      frequency       = "PT1H"
      period          = "P14D"
      suppress        = null
      tactics         = ["Persistence", "CredentialAccess", "DefenseEvasion"]
      techniques      = ["T1098", "T1556"]
      entities        = local.signin_user_entities
      severity_column = "Severity"
      custom_details = {
        Method          = "Method"
        Privileged      = "PrivilegedTarget"
        SignInRisk      = "SignInRisk"
        NewCountry      = "NewCountry"
        Country         = "Country"
        UnmanagedDevice = "UnmanagedDevice"
        ViaTap          = "ViaTap"
        NoContext       = "NoContext"
        SignInType      = "ContextSignInType"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
    dc_logon_outside_operator_allowlist = {
      file         = "dc-logon-outside-operator-allowlist.kql"
      display_name = "Contoso ITDR - DC01 logon from outside the operator allowlist"
      description  = "RDP (LogonType 10/7) on DC01 from any source, or a network / cleartext logon (3/8) from a public IP, that is not an unexpired entry of the operator_ips watchlist (ADR 0013). High on success, Medium for failures only (T1133, T1021.001, T1078.002). Empty watchlist = every source alerts. Needs DC01 SecurityEvent (AMA; verify: Sentinel + connector)."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["InitialAccess", "LateralMovement", "Persistence"]
      techniques   = ["T1133", "T1021", "T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "Name", column = "Account" }, { identifier = "NTDomain", column = "AccountDomain" }, { identifier = "Sid", column = "AccountSid" }] },
        { type = "Host", fields = [{ identifier = "HostName", column = "Host" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "SourceIp" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Verdict         = "Verdict"
        Kinds           = "Kinds"
        Successes       = "Successes"
        Failures        = "Failures"
        Tier0Account    = "Tier0Account"
        AllowlistLoaded = "AllowlistLoaded"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    # The Actor is a Vault identity (token display name / operator), not an
    # Entra or AD object: Account maps by Name only, and the rule is on
    # itdr_never_contain. Response is the PAM runbook (revoke the token by
    # accessor, check the account in so it rotates).
    vault_privileged_access_anomaly = {
      file         = "vault-privileged-access-anomaly.kql"
      display_name = "Contoso ITDR - PAM vault anomaly (credential read, rotation failure, root token, login burst)"
      description  = "Vault-side misuse a PAM team watches for: Tier-0 credential read outside a ticketed check-out, Tier-0 check-out without a ticket, rotation failure, root-token use, failed-login burst, Tier-0 access denied (T1555, T1078, T1110, T1562). Returns nothing until ingest-vault-audit.sh ships the extended feed (vault_feed_v2_columns)."
      severity     = "Medium"
      frequency    = "PT5M"
      period       = "PT6H" # 1 h judged + 4 h 5 m of check-out history (see the .kql)
      suppress     = null
      tactics      = ["CredentialAccess", "DefenseEvasion", "PrivilegeEscalation"]
      techniques   = ["T1555", "T1078", "T1110", "T1562"]
      entities = [
        { type = "Account", fields = [{ identifier = "Name", column = "Actor" }] },
        { type = "Host", fields = [{ identifier = "HostName", column = "SourceHost" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "RemoteAddress" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Signal     = "Signal"
        PamTerm    = "PamTerm"
        VaultPath  = "VaultPath"
        Ticket     = "Ticket"
        Events     = "Events"
        LoginNames = "LoginNames"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = "PT1H" # an event stays matchable for 1 h, not the 6 h window
    }
    # Notify only (itdr_never_contain): the fix is removing one side of the
    # pair, decided by the access owner (ADR 0012).
    sod_violation_granted = {
      file            = "sod-violation-granted.kql"
      display_name    = "Contoso ITDR - Separation-of-duties (SoD) violation granted"
      description     = "Access granted that completes a pair in lab/iga/sod-rules.json (SOD-01..09, e.g. medication administration vs controlled-substance dispensing, AP vs vendor master) against access the user already holds (14 days of grants + the sod_holdings watchlist). Severity = the rule's own risk; Low under an approved exception (T1098). Never containment (ADR 0012). Sentinel only (14-day look-back)."
      severity        = "Medium"
      frequency       = "PT1H"
      period          = "P14D"
      suppress        = null
      tactics         = ["Persistence", "PrivilegeEscalation"]
      techniques      = ["T1098"]
      entities        = [{ type = "Account", fields = [{ identifier = "FullName", column = "UserPrincipalName" }, { identifier = "AadUserId", column = "UserId" }] }]
      severity_column = "Severity"
      custom_details = {
        RuleId      = "RuleId"
        RuleName    = "RuleName"
        Granted     = "GrantedName"
        GrantedVia  = "GrantedVia"
        Conflicting = "ConflictingAccess"
        GrantedBy   = "GrantedBy"
        Excepted    = "Excepted"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
    pim_activation_without_auth_context = {
      file            = "pim-activation-without-auth-context.kql"
      display_name    = "Contoso ITDR - Tier-0 PIM activation without the authentication context (preview)"
      description     = "A Tier-0 PIM group activated with no sign-in that satisfied authentication context c1 before the request, or with the context's CA policy only in report-only / not applied - in which case PIM required NO step-up at all (Learn: its MFA backup is not triggered for a report-only, off or excluding policy) (T1078.004, T1556.009). PREVIEW: keep it in itdr_exclude_rules until the first real activation confirms the activity strings."
      severity        = "High"
      frequency       = "PT1H"
      period          = "P1D" # 1 h judged + 20 h back to the request + 30 m step-up window
      suppress        = null
      tactics         = ["PrivilegeEscalation", "DefenseEvasion", "Persistence"]
      techniques      = ["T1078", "T1556"]
      entities        = [{ type = "Account", fields = [{ identifier = "FullName", column = "UserPrincipalName" }, { identifier = "AadUserId", column = "UserId" }] }, { type = "IP", fields = [{ identifier = "Address", column = "ActorIp" }] }]
      severity_column = "Severity"
      custom_details = {
        Verdict        = "Verdict"
        ElevatedTo     = "ElevatedTo"
        StepUpSignIns  = "StepUpSignIns"
        ReportOnlyHits = "ReportOnlyHits"
        PolicyCheck    = "PolicyCheck"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = "PT1H" # a completion stays matchable for 1 h, not the 1-day window
    }
  }

  # The signed-in USER is the subject (the account to contain).
  signin_user_entities = [
    { type = "Account", fields = [{ identifier = "FullName", column = "UserPrincipalName" }, { identifier = "AadUserId", column = "UserId" }] },
    { type = "IP", fields = [{ identifier = "Address", column = "IPAddress" }] },
  ]

  # Rules whose look-back is longer than a Log Analytics alert allows
  # (P2D). Deployed on the Sentinel path only.
  # The v3 set (itdr_v3.tf) adds its own two.
  sentinel_only_rule_keys = concat(["security_info_registered_risky", "sod_violation_granted"], local.v3_sentinel_only_rule_keys)

  # Rules that never trigger the containment playbook, whatever
  # containment_rule_keys says (variables.tf refuses them there too).
  # The v3 Key Vault rule is added from itdr_v3.tf.
  itdr_never_contain = concat(["sod_violation_granted", "vault_privileged_access_anomaly"], local.v3_never_contain)

  # The operator_ips watchlist exists whenever the v2 set is on Sentinel,
  # even while dc_logon_outside_operator_allowlist is still excluded, so the
  # allowlist is in place BEFORE the rule that reads it.
  operator_ips_watchlist_on = var.enable_sentinel && var.enable_itdr_detections_v2
}

# -----------------------------------------------------------------------------
# Sentinel watchlist "operator_ips": the allowlist
# dc-logon-outside-operator-allowlist.kql reads (_GetWatchlist('operator_ips'),
# SearchKey = IpRange). One row per operator_ip_ranges entry, each with an
# ExpiresOn: the query ignores an entry past that date, which enforces ADR
# 0013's time box in the detection as well as in the review.
# The IPs are sensitive: the module variable is marked sensitive, the item
# addresses are indexes (never the IP), so a plan shows "(sensitive value)".
# The values are in state, as the NSG rules that use them already are.
# Splunk twin: transforms.conf [contoso_operator_ips] over
# contoso_operator_ips.csv, written at run time, never committed.
# -----------------------------------------------------------------------------
resource "azurerm_sentinel_watchlist" "operator_ips" {
  count = local.operator_ips_watchlist_on ? 1 : 0

  # name is the watchlist alias the KQL calls (provider: name -> alias).
  name                       = "operator_ips"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = "Operator IP allowlist (DC01, ADR 0013)"
  description                = "Operator egress IPs allowed to reach DC01 (RDP / LDAPS). Managed by Terraform (modules/monitoring, from operator_ip_ranges): edit the variable, not the watchlist. Read by dc-logon-outside-operator-allowlist.kql; entries past ExpiresOn no longer count."
  item_search_key            = "IpRange"
  labels                     = ["contoso-itdr", "adr-0013"]
}

resource "azurerm_sentinel_watchlist_item" "operator_ips" {
  count = local.operator_ips_watchlist_on ? length(var.operator_ip_ranges) : 0

  # Deterministic per index, so a re-plan never churns item names.
  name         = uuidv5("url", "https://contoso-health-identity-lab/watchlist/operator_ips/${count.index}")
  watchlist_id = azurerm_sentinel_watchlist.operator_ips[0].id
  properties = {
    IpRange   = var.operator_ip_ranges[count.index]
    Owner     = var.operator_ips_owner
    ExpiresOn = var.operator_ips_expires_on
  }

  lifecycle {
    precondition {
      condition     = var.operator_ips_expires_on != null
      error_message = "operator_ip_ranges is set but operator_ips_expires_on is not: an entry without ExpiresOn never counts, so every DC01 logon would alert. Pass ADR 0013's review date (yyyy-mm-dd)."
    }
  }
}

# A warning, not an error: an expired allowlist is the designed fail-safe
# (every DC01 logon alerts), but it means ADR 0013's review is overdue.
check "operator_ips_not_expired" {
  assert {
    condition     = !local.operator_ips_watchlist_on || var.operator_ips_expires_on == null || timecmp("${coalesce(var.operator_ips_expires_on, "9999-12-31")}T00:00:00Z", plantimestamp()) > 0
    error_message = "operator_ips_expires_on is in the past: dc-logon-outside-operator-allowlist ignores expired entries, so every DC01 logon now alerts. ADR 0013's review is overdue - renew the acceptance with a new date, or set enable_dc = false."
  }
}
