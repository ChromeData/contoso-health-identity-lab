# =============================================================================
# modules/monitoring :: main.tf
# -----------------------------------------------------------------------------
# Detections as code. The queries in lab/kql are the single source of truth;
# this module deploys them two ways:
#
#   1. Microsoft Sentinel analytics rules (enable_sentinel)  - the recording.
#      Onboarding Sentinel STARTS ITS 31-DAY TRIAL CLOCK, hence the flag.
#   2. Log Analytics scheduled query alerts (enable_la_alerts) - the
#      post-trial path the narration promises: identical KQL, near-zero cost.
#      One path at a time: a precondition on the Sentinel onboarding refuses
#      a plan with both flags on, so the two never double-alert.
#
# Three rule sets share both paths:
#   * core  (always, five rules)  - sign-in hygiene + PIM visibility.
#   * ITDR  (enable_itdr_detections, eleven rules, itdr.tf) - identity threat
#     detection: workload-identity credentials, consent, CA / named-location /
#     auth-strength tampering, roles and privileged-group members outside PIM,
#     admin MFA changes, Identity Protection risk, and the AD plane: Tier-0
#     logons PAM does not account for, privileged-group adds, Kerberoasting,
#     DCSync (telemetry for those: telemetry.tf).
#   * ITDR v2 (enable_itdr_detections_v2, six rules, itdr_v2.tf) - device
#     code phishing, risky security-info registration, DC01 logons outside
#     the operator allowlist (+ the operator_ips watchlist), PAM vault
#     anomalies, SoD violations, Tier-0 PIM activation without the auth
#     context. Two of them are Sentinel only (14-day look-back); two never
#     trigger containment. Why a separate flag: itdr_v2.tf header.
#   * ITDR v3 (enable_itdr_detections_v3, two rules, itdr_v3.tf) - a dormant
#     admin account signing in again, and bulk Key Vault secret reads. Both
#     Sentinel only (14-day look-back); the Key Vault rule never triggers
#     containment.
#
# Automated response:
#   * notify   - lab/monitoring/playbook-notify.json (Teams card + ServiceNow),
#                deployed by lab/scripts/monitoring/Deploy-Playbook.ps1 because
#                it carries secrets CI must never hold. Pass its id as
#                var.playbook_logic_app_id: every incident from every rule
#                here runs it.
#   * contain  - lab/monitoring/playbook-contain.json (Teams APPROVAL card ->
#                revoke sessions / disable), deployed by
#                Deploy-ContainmentPlaybook.ps1. Wired in itdr.tf ONLY for
#                High ITDR incidents and only when enable_itdr_containment.
#
# ORDERING GOTCHA: Sentinel validates each rule's query at creation, and a
# query over a table that has never received data (e.g.
# AADNonInteractiveUserSignInLogs, AADUserRiskEvents, SecurityEvent) is
# rejected. Turn enable_sentinel on only after Entra diagnostics have streamed
# data for a few hours - and for the ITDR rules, after their tables have data
# (itdr_exclude_rules holds back any rule whose table is still empty).
# verify: per Microsoft Learn, AMA Security events reach SecurityEvent only
# with Sentinel + its "Windows Security Events via AMA" connector, so the
# SecurityEvent rules (four ITDR, plus dc_logon_outside_operator_allowlist in
# v2) can only be added AFTER Sentinel is on and DC01 rows have arrived (a
# second PR that empties those exclusions).
# =============================================================================

locals {
  # file() resolves relative to the working directory, so anchor on the module.
  kql_dir = var.kql_dir != "" ? var.kql_dir : "${path.module}/../../../kql"

  # One entry per lab/kql file. Every entry carries EVERY attribute (null / []
  # / {} when unused) so the core and ITDR maps unify into one object type for
  # for_each.
  #   entities         -> Sentinel entity mapping; each field's column MUST be
  #                       in the query output (tests/itdr.tftest.hcl checks
  #                       that against the .kql text).
  #   frequency/period -> each query's own ago() window.
  #   suppress         -> rule suppression after an alert (null = off:
  #                       incident grouping absorbs the 5-minute overlap).
  #   techniques       -> MITRE ATT&CK parent ids (Sentinel's techniques field
  #                       takes no sub-technique ids; those live in the .kql
  #                       header).
  #   severity_column  -> dynamic severity column (null = static severity).
  #   custom_details   -> incident custom details {key = column}.
  #   alert_per_result -> one alert per result row (else one alert per run).
  #   group_by         -> null = group incidents by all entities; a list =
  #                       group by those entity types AND alert severity.
  #   la_mute          -> Log Analytics alert mute (null = the period).
  core_rules = {
    pim_activation = {
      file         = "pim-activation.kql"
      display_name = "Contoso - PIM activation (just-in-time elevation)"
      description  = "A PIM for Groups / PIM for roles activation completed. Expected for approved changes; every one is reviewed."
      severity     = "Medium"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["PrivilegeEscalation"]
      techniques   = ["T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "Actor" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "ActorIp" }] },
      ]
      severity_column  = null
      custom_details   = {}
      alert_per_result = false
      group_by         = null
      la_severity      = 2
      la_mute          = null
    }
    break_glass_signin = {
      file         = "break-glass-signin.kql"
      display_name = "Contoso - Break-glass account sign-in (any)"
      description  = "Any sign-in attempt by an emergency-access account. Always investigated by a second admin."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["InitialAccess", "PrivilegeEscalation"]
      techniques   = ["T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "UserPrincipalName" }, { identifier = "AadUserId", column = "UserId" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "IPAddress" }] },
      ]
      severity_column  = null
      custom_details   = { MatchedBy = "MatchedBy" }
      alert_per_result = false
      group_by         = ["Account"]
      la_severity      = 0
      la_mute          = null
    }
    blocked_country_signin = {
      file         = "blocked-country-signin.kql"
      display_name = "Contoso - Sign-in from a blocked / watched country"
      description  = "Sign-in from a country on the block or watch list; Outcome flags a successful sign-in from a block-list country (CA gap) apart from CA blocks and wrong-password noise."
      severity     = "Medium"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["InitialAccess"]
      techniques   = ["T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "UserPrincipalName" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "IPAddress" }] },
      ]
      severity_column  = null
      custom_details   = {}
      alert_per_result = false
      group_by         = null
      la_severity      = 2
      la_mute          = null
    }
    failed_signin_spike = {
      file         = "failed-signin-spike.kql"
      display_name = "Contoso - Failed sign-in spike from one IP (spray / brute force)"
      description  = "10+ failed sign-ins from one IP in the same 10-minute clock bin (:00, :10, ...)."
      severity     = "Medium"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["CredentialAccess"]
      techniques   = ["T1110"]
      entities = [
        { type = "IP", fields = [{ identifier = "Address", column = "IPAddress" }] },
      ]
      severity_column  = null
      custom_details   = {}
      alert_per_result = false
      group_by         = null
      la_severity      = 2
      la_mute          = null
    }
    # legacy_auth's 1-day lookback re-matches one hit on ~24 hourly runs, so
    # after an alert the rule pauses for lookback minus one run (suppress).
    # The next run starts where the alerting run ended: one alert per hit,
    # and hits during the pause alert late, not never. verify: on the first
    # live legacy alert.
    legacy_auth = {
      file             = "legacy-auth.kql"
      display_name     = "Contoso - Legacy authentication attempts"
      description      = "Sign-ins over legacy protocols that cannot do MFA. CA003-blocked attempts still alert (logged as failures); StillSucceeding = true means CA003 is not holding."
      severity         = "Low"
      frequency        = "PT1H"
      period           = "P1D"
      suppress         = "PT23H" # period minus frequency
      tactics          = ["DefenseEvasion"]
      techniques       = ["T1078"]
      entities         = [] # summarized output - no per-row entity columns
      severity_column  = null
      custom_details   = {}
      alert_per_result = false
      group_by         = null
      la_severity      = 3
      la_mute          = null
    }
  }

  # ITDR rules (itdr.tf) join only when enable_itdr_detections is on, the v2
  # set (itdr_v2.tf) only when enable_itdr_detections_v2 is on, the v3 set
  # (itdr_v3.tf) only when enable_itdr_detections_v3 is on, minus any held
  # back in itdr_exclude_rules (filtering for-expressions, for the same
  # object-type reason as the rule resources' for_each).
  itdr_selected = merge(
    {
      for k, r in local.itdr_rules : k => r
      if var.enable_itdr_detections && !contains(var.itdr_exclude_rules, k)
    },
    {
      for k, r in local.itdr_v2_rules : k => r
      if var.enable_itdr_detections_v2 && !contains(var.itdr_exclude_rules, k)
    },
    {
      for k, r in local.itdr_v3_rules : k => r
      if var.enable_itdr_detections_v3 && !contains(var.itdr_exclude_rules, k)
    },
  )

  rules = merge(local.core_rules, local.itdr_selected)

  # Each rule's query, with the id lists (variables.tf) rendered in place of
  # the committed empty placeholders `dynamic([]); // @@NAME@@`. The .kql files
  # stay paste-able as they are (empty list = fail closed: nothing is IaC or
  # privileged-by-id), and the deployed rules judge by IMMUTABLE ids.
  kql_placeholder = "dynamic([]); // @@%s@@"
  kql_lists = {
    IAC_PRINCIPAL_IDS     = var.iac_principal_ids
    PRIVILEGED_GROUP_IDS  = var.privileged_group_ids
    BREAK_GLASS_GROUP_IDS = var.break_glass_group_ids
    BREAK_GLASS_USER_IDS  = var.break_glass_user_ids
    PRIVILEGED_USER_IDS   = var.privileged_user_ids
    AZURE_PIM_GROUP_IDS   = var.azure_pim_group_ids
  }
  rule_queries = {
    for k, r in local.rules : k => replace(replace(replace(replace(replace(replace(
      file("${local.kql_dir}/${r.file}"),
      format(local.kql_placeholder, "IAC_PRINCIPAL_IDS"), "dynamic(${jsonencode(local.kql_lists.IAC_PRINCIPAL_IDS)}); // @@IAC_PRINCIPAL_IDS@@"),
      format(local.kql_placeholder, "PRIVILEGED_GROUP_IDS"), "dynamic(${jsonencode(local.kql_lists.PRIVILEGED_GROUP_IDS)}); // @@PRIVILEGED_GROUP_IDS@@"),
      format(local.kql_placeholder, "BREAK_GLASS_GROUP_IDS"), "dynamic(${jsonencode(local.kql_lists.BREAK_GLASS_GROUP_IDS)}); // @@BREAK_GLASS_GROUP_IDS@@"),
      format(local.kql_placeholder, "BREAK_GLASS_USER_IDS"), "dynamic(${jsonencode(local.kql_lists.BREAK_GLASS_USER_IDS)}); // @@BREAK_GLASS_USER_IDS@@"),
      format(local.kql_placeholder, "PRIVILEGED_USER_IDS"), "dynamic(${jsonencode(local.kql_lists.PRIVILEGED_USER_IDS)}); // @@PRIVILEGED_USER_IDS@@"),
    format(local.kql_placeholder, "AZURE_PIM_GROUP_IDS"), "dynamic(${jsonencode(local.kql_lists.AZURE_PIM_GROUP_IDS)}); // @@AZURE_PIM_GROUP_IDS@@")
  }
}

# -----------------------------------------------------------------------------
# 1. Microsoft Sentinel (trial clock B).
# -----------------------------------------------------------------------------
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  count = var.enable_sentinel ? 1 : 0

  workspace_id = var.log_analytics_workspace_id

  lifecycle {
    precondition {
      condition     = !var.enable_la_alerts
      error_message = "enable_sentinel and enable_la_alerts are both true: every detection would open a Sentinel incident AND email the action group. Turn on one path at a time (after the trial: enable_sentinel = false and enable_la_alerts = true in the same change)."
    }
  }
}

# Near-real-time (NRT) rules: the break-glass sign-in only. An NRT rule runs
# every minute over the rows INGESTED in the previous minute (Learn, "Quick
# threat detection with near-real-time (NRT) analytics rules": it queries on
# ingestion time, with a built-in two-minute delay, so data-source delay can
# be ignored). A scheduled rule judges TimeGenerated over a fixed window, so
# a late row, or a late or skipped run, can fall between windows; for the
# lab's most powerful accounts that gap is not acceptable (2026-11-05). NRT
# fits this rule: several tables (the union), entity mapping, incident
# grouping and automation are all supported (Learn, "Work with NRT rules";
# limit 50 NRT rules per tenant). The Log Analytics alert path below keeps
# the scheduled form (it has no NRT).
locals {
  nrt_rule_keys = ["break_glass_signin"]
}

resource "azurerm_sentinel_alert_rule_scheduled" "this" {
  # A filtering for-expression, not `cond ? local.rules : {}`: the ITDR rules
  # carry custom_details / group_by shapes the core rules don't, so the rule
  # set is an object that cannot convert to a single map type.
  for_each = { for k, r in local.rules : k => r if var.enable_sentinel && !contains(local.nrt_rule_keys, k) }

  name                       = "contoso-${replace(each.key, "_", "-")}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = each.value.display_name
  description                = "${each.value.description} Source: lab/kql/${each.value.file}"
  severity                   = each.value.severity
  query                      = local.rule_queries[each.key]
  query_frequency            = each.value.frequency
  query_period               = each.value.period
  suppression_enabled        = each.value.suppress != null
  suppression_duration       = each.value.suppress
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = each.value.tactics
  techniques                 = length(each.value.techniques) > 0 ? each.value.techniques : null
  custom_details             = length(each.value.custom_details) > 0 ? each.value.custom_details : null
  enabled                    = true

  # Dynamic severity: the query's Severity column (Informational / Low /
  # Medium / High) overrides the static severity per alert, so one rule can
  # page on "CA policy deleted" and stay quiet-ish on "CA policy edited by CI".
  dynamic "alert_details_override" {
    for_each = each.value.severity_column != null ? [each.value.severity_column] : []
    content {
      severity_column_name = alert_details_override.value
    }
  }

  # One alert per result row: each row has its own entities and severity, which
  # the containment automation rule and the playbook's per-account loop rely
  # on. (Unset = Sentinel's default single alert per run.)
  dynamic "event_grouping" {
    for_each = each.value.alert_per_result ? [1] : []
    content {
      aggregation_method = "AlertPerResult"
    }
  }

  dynamic "entity_mapping" {
    for_each = each.value.entities
    content {
      entity_type = entity_mapping.value.type
      dynamic "field_mapping" {
        for_each = entity_mapping.value.fields
        content {
          identifier  = field_mapping.value.identifier
          column_name = field_mapping.value.column
        }
      }
    }
  }

  # Core rules: alerts with the same entities inside an hour join one incident.
  # That absorbs the 5-minute rules' overlap (a hit stays in the 1 h lookback
  # for up to 12 runs) and a burst such as a spray, so Teams / ServiceNow are
  # not flooded. legacy_auth (no entities, 1-day lookback) uses suppress
  # instead.
  # ITDR rules (group_by set): grouped per IDENTITY and per SEVERITY, so a High
  # alert never lands inside an older Medium incident - the containment
  # automation rule fires on incident creation, and a High buried in a Medium
  # incident would never reach it.
  # In the Defender portal this grouping is only the initial instruction to
  # the XDR correlation engine. verify: on the first live incidents.
  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT1H"
      reopen_closed_incidents = false
      entity_matching_method  = each.value.group_by == null ? "AllEntities" : "Selected"
      by_entities             = each.value.group_by
      by_alert_details        = each.value.group_by == null ? null : ["Severity"]
    }
  }

  # The DC01 logon rule reads the operator_ips watchlist: fill it first, so
  # the rule's first runs judge against the allowlist rather than the
  # empty-watchlist fail-safe (every source alerts). No-op while the
  # watchlist is off.
  depends_on = [azurerm_sentinel_watchlist_item.operator_ips]
}

# The NRT twin of the block above, for local.nrt_rule_keys. No schedule or
# threshold (fixed by NRT: every minute, an alert per result set). A NEW
# rule name (-nrt): Sentinel refuses to re-create a rule id for a while after
# it was deleted (seen live 2026-11-05), so the scheduled rule of the same key
# is deleted and this one created beside it, not over it.
resource "azurerm_sentinel_alert_rule_nrt" "this" {
  for_each = { for k, r in local.rules : k => r if var.enable_sentinel && contains(local.nrt_rule_keys, k) }

  name                       = "contoso-${replace(each.key, "_", "-")}-nrt"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = each.value.display_name
  description                = "${each.value.description} Source: lab/kql/${each.value.file}. Near-real-time rule (every minute, by ingestion time)."
  severity                   = each.value.severity
  query                      = local.rule_queries[each.key]
  suppression_enabled        = false
  tactics                    = each.value.tactics
  techniques                 = length(each.value.techniques) > 0 ? each.value.techniques : null
  custom_details             = length(each.value.custom_details) > 0 ? each.value.custom_details : null
  enabled                    = true

  # One alert per result ROW, and the query returns one row per account
  # (break-glass-signin.kql summarizes by UserId): two break-glass accounts
  # seen in the same minute become two alerts, each grouped into its own
  # account's incident (review of #230; with SingleAlert one alert named
  # both accounts and grouping could not split it). Learn, NRT
  # considerations: "an alert for each event for up to 30 events" - far
  # above the two break-glass accounts.
  event_grouping {
    aggregation_method = "AlertPerResult"
  }

  dynamic "entity_mapping" {
    for_each = each.value.entities
    content {
      entity_type = entity_mapping.value.type
      dynamic "field_mapping" {
        for_each = entity_mapping.value.fields
        content {
          identifier  = field_mapping.value.identifier
          column_name = field_mapping.value.column
        }
      }
    }
  }

  # DEDUP (2026-11-07, review finding D2): group by the ACCOUNT entity only,
  # over 24 hours. One break-glass sign-in writes rows that are ingested over
  # up to ~30 minutes (interactive + non-interactive legs, MFA steps), and
  # each NRT run that sees new rows raises an alert. With the old grouping
  # (all entities, 1 h) a late row from a new IP, or a row after the hour,
  # opened a NEW incident with its own card and ticket (E49a, E49c). Now
  # every alert for the same break-glass account in a day joins one
  # incident; the notify playbook adds a work note to that incident's
  # ServiceNow ticket for each joined alert instead of opening another
  # (playbook-notify.json, Find_open_ticket). Learn, "Work with near-real-time
  # (NRT) detection analytics rules" (read 2026-11-07): "You can choose how
  # to group alerts into incidents", and entity mapping and custom details
  # work as for scheduled rules.
  # reopen_closed_incidents stays false: a sign-in AFTER the incident was
  # closed is a new event and gets a new incident.
  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = var.break_glass_grouping_lookback
      reopen_closed_incidents = false
      entity_matching_method  = "Selected"
      by_entities             = each.value.group_by
    }
  }
}

locals {
  # Every Sentinel analytics rule this module owns (scheduled + NRT), by key.
  sentinel_rule_ids = merge(
    { for k, r in azurerm_sentinel_alert_rule_scheduled.this : k => r.id },
    { for k, r in azurerm_sentinel_alert_rule_nrt.this : k => r.id },
  )
}

# Run the notify playbook on every new incident from the rules above (once the
# playbook exists).
resource "azurerm_sentinel_automation_rule" "notify" {
  count = var.enable_sentinel && var.playbook_logic_app_id != "" ? 1 : 0

  name                       = uuidv5("url", "https://contoso-health-identity-lab/automation/notify")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = "Contoso - notify Teams + open ServiceNow incident"
  order                      = 1
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  # Without a condition the rule matches EVERY incident in the workspace
  # (e.g. Defender XDR ones in the unified portal), and each would post to
  # Teams and open a ServiceNow ticket.
  condition_json = jsonencode([{
    conditionType = "Property"
    conditionProperties = {
      propertyName   = "IncidentRelatedAnalyticRuleIds"
      operator       = "Contains"
      propertyValues = values(local.sentinel_rule_ids)
    }
  }])

  action_playbook {
    logic_app_id = var.playbook_logic_app_id
    order        = 1
  }
}

# Run the notify playbook AGAIN when an alert is added to an open incident,
# for the rules in notify_on_alert_added_rule_keys (default: break-glass
# sign-in). Incident grouping (24 h, by account) puts a second break-glass
# sign-in into the open incident, and the rule above only fires on creation:
# without this rule that sign-in would leave no trace in ServiceNow (found
# 2026-11-05). Since 2026-11-07 (review finding D2) the playbook UPDATES the
# incident's open ticket (a work note, found by correlation_id) and posts no
# second Teams card, so a joined alert no longer means a new ticket. Microsoft Learn's
# incident update trigger lists "Alerts are added to an incident" as an
# update event; the condition below is the ARM shape for it
# (PropertyArrayChanged, arrayType Alerts, changeType Added - the same shape
# as itdr.tf's contain_on_alert_added). Each added alert = one work note on
# the incident's existing ServiceNow ticket (same correlation_id: the
# incident); no new card, no new ticket.
resource "azurerm_sentinel_automation_rule" "notify_on_alert_added" {
  count = length(azurerm_sentinel_automation_rule.notify) == 1 && length(local.notify_on_alert_added_rule_ids) > 0 ? 1 : 0

  name                       = uuidv5("url", "https://contoso-health-identity-lab/automation/notify-alert-added")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = "Contoso - notify again when an alert joins an open incident (break-glass)"
  # Update-trigger rules have their own order queue (Learn): first in it.
  order         = 1
  triggers_on   = "Incidents"
  triggers_when = "Updated"

  condition_json = jsonencode([
    {
      conditionType = "PropertyArrayChanged"
      conditionProperties = {
        arrayType  = "Alerts"
        changeType = "Added"
      }
    },
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "IncidentRelatedAnalyticRuleIds"
        operator       = "Contains"
        propertyValues = local.notify_on_alert_added_rule_ids
      }
    },
  ])

  action_playbook {
    logic_app_id = var.playbook_logic_app_id
    order        = 1
  }
}

# Label drill incidents "drill" the moment they are created (review finding
# D2, 2026-11-07: drills had left 50 incidents and 32 tickets open,
# recheck-summary item 2). Condition: an Account entity whose name starts
# with a drill account prefix (default itdr-drill-, the throwaway accounts
# containment-drill.sh creates), on an incident from ANY analytics rule.
# There is no rule-id condition: containment-drill.sh raises its incidents
# from a temporary rule with a fresh id that is not one of this module's
# rules, so a rule-id filter would leave drill incidents unlabelled (review
# of PR #230). A drill-account prefix is specific enough on its own.
# The label only MARKS the incident: the drill still runs its containment
# path (closing at creation would skip it). After the drill,
# lab/scripts/demo/close-build-noise.sh closes every open incident labelled
# "drill" and resolves its ServiceNow ticket (an incident that also names a
# real person is still held for the lead). Property names, operators and the
# ModifyProperties labels shape are from the REST reference "Automation
# Rules - Create Or Update" (api-version 2024-09-01, read 2026-11-07):
# AccountName, StartsWith, labels[].labelName.
resource "azurerm_sentinel_automation_rule" "label_drill" {
  count = var.enable_sentinel && length(var.drill_account_prefixes) > 0 ? 1 : 0

  name                       = uuidv5("url", "https://contoso-health-identity-lab/automation/label-drill")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = "Contoso - label drill incidents (drill accounts)"
  # After notify (1) and containment (2, itdr.tf): a label changes nothing
  # they do.
  order         = 3
  triggers_on   = "Incidents"
  triggers_when = "Created"

  condition_json = jsonencode([
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "AccountName"
        operator       = "StartsWith"
        propertyValues = var.drill_account_prefixes
      }
    },
  ])

  action_incident {
    order  = 1
    labels = ["drill"]
  }
}

locals {
  notify_on_alert_added_rule_ids = [
    for k, id in local.sentinel_rule_ids : id if contains(var.notify_on_alert_added_rule_keys, k)
  ]
}

# -----------------------------------------------------------------------------
# 2. Post-trial path: the same KQL as Log Analytics scheduled query alerts.
# -----------------------------------------------------------------------------
resource "azurerm_monitor_action_group" "identity_secops" {
  count = var.enable_la_alerts && var.alert_email != "" ? 1 : 0

  name                = "ag-identity-secops"
  resource_group_name = var.resource_group_name
  short_name          = "idsecops"
  tags                = var.tags

  email_receiver {
    name                    = "identity-secops"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "this" {
  # Sentinel-only rules (itdr_v2.tf: 14-day look-back) are left out: a log
  # search alert looks back at most two days (window_duration P2D).
  for_each = { for k, r in local.rules : k => r if var.enable_la_alerts && !contains(local.sentinel_only_rule_keys, k) }

  name                 = "alert-contoso-${replace(each.key, "_", "-")}"
  resource_group_name  = var.resource_group_name
  location             = var.location
  display_name         = each.value.display_name
  description          = "${each.value.description} Source: lab/kql/${each.value.file}"
  severity             = each.value.la_severity
  scopes               = [var.log_analytics_workspace_id]
  evaluation_frequency = each.value.frequency
  window_duration      = each.value.period
  enabled              = true
  tags                 = var.tags

  # These log alerts are stateless (auto_mitigation_enabled defaults to
  # false): a hit re-fires on every run while it is in the window (up to 12
  # emails at PT5M/PT1H, 24 for legacy at PT1H/P1D). Mute actions for one
  # window: one hit, one email, like the Sentinel grouping / suppression and
  # the Splunk throttle. Rule-wide (no dimensions): another hit during the
  # mute still fires in Monitor > Alerts but sends no email until it ends.
  # The provider rejects this together with auto_mitigation_enabled = true.
  # la_mute overrides it where the window is wider than the time one hit
  # stays matchable (tier0: 3 h of Vault history, 1 h of logons judged).
  mute_actions_after_alert_duration = coalesce(each.value.la_mute, each.value.period)

  criteria {
    query                   = local.rule_queries[each.key]
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  dynamic "action" {
    for_each = length(azurerm_monitor_action_group.identity_secops) > 0 ? [1] : []
    content {
      action_groups = [azurerm_monitor_action_group.identity_secops[0].id]
    }
  }
}
