# =============================================================================
# modules/monitoring :: variables.tf
# =============================================================================

variable "resource_group_name" {
  type        = string
  description = "Resource group for the alert rules / action group."
}

variable "location" {
  type        = string
  description = "Azure region (contract: eastus2)."
  default     = "eastus2"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Resource id of loga-idlab."
}

variable "kql_dir" {
  type        = string
  description = "Directory holding the detection queries. Empty = lab/kql relative to this module."
  default     = ""
}

variable "enable_sentinel" {
  type        = bool
  description = <<-EOT
    Onboard Microsoft Sentinel and deploy the analytics rules. STARTS THE
    31-DAY SENTINEL TRIAL. Turn on only after Entra diagnostics have streamed
    data for a few hours (rule creation fails on never-populated tables).
  EOT
  default     = false
}

variable "enable_la_alerts" {
  type        = bool
  description = "Deploy the same queries as Log Analytics scheduled query alerts (the post-Sentinel-trial path)."
  default     = false
}

variable "alert_email" {
  type        = string
  description = "Email for the Log Analytics alert action group. Empty = alerts fire without notification."
  default     = ""
}

variable "playbook_logic_app_id" {
  type        = string
  description = "Resource id of the notify playbook (Deploy-Playbook.ps1 output). Empty = no automation rule yet."
  default     = ""
}

# -----------------------------------------------------------------------------
# ITDR pack (itdr.tf, telemetry.tf). Every flag defaults to false: nothing new
# is created, and no trial clock moves, until the wiring turns it on.
# -----------------------------------------------------------------------------
variable "enable_itdr_detections" {
  type        = bool
  description = <<-EOT
    Add the eleven ITDR rules (lab/kql: app-credential-added, app-consent-granted,
    ca-policy-changed, role-assigned-outside-pim, pim-group-member-added-outside-pim,
    auth-method-changed-by-admin, identity-risk, tier0-logon-without-checkout,
    ad-privileged-group-change, kerberoast-rc4-service-ticket,
    dcsync-replication-request) to whichever detection path is on
    (enable_sentinel / enable_la_alerts), and create their telemetry: the
    VaultCheckout_CL table + DCE + DCR for the PAM check-out feed, and (with
    collect_dc_security_events) DC01 Security events via AMA. Starts no trial
    by itself; turn it on BEFORE enable_sentinel so the AuditLogs-based tables
    and VaultCheckout_CL have data when Sentinel validates the rules.
    verify: per Microsoft Learn, AMA Security events reach SecurityEvent only
    once Sentinel + its "Windows Security Events via AMA" connector are on
    (Event otherwise), so the four SecurityEvent rules (tier0_logon_without_checkout,
    ad_privileged_group_change, kerberoast_rc4_service_ticket,
    dcsync_replication_request) stay in itdr_exclude_rules until Sentinel is
    on and DC01 rows have arrived.
  EOT
  default     = false
}

variable "enable_itdr_detections_v2" {
  type        = bool
  description = <<-EOT
    Add the six second-wave ITDR rules (itdr_v2.tf; lab/kql: device-code-signin,
    security-info-registered-risky, dc-logon-outside-operator-allowlist,
    vault-privileged-access-anomaly, sod-violation-granted,
    pim-activation-without-auth-context) to the active detection path, and on
    the Sentinel path the operator_ips watchlist (from operator_ip_ranges).
    Needs enable_itdr_detections (its telemetry feeds two of the six). Starts
    no trial by itself. security_info_registered_risky and
    sod_violation_granted are Sentinel only (14-day look-back; Log Analytics
    alerts stop at 2 days). sod_violation_granted and
    vault_privileged_access_anomaly never trigger containment. Hold back with
    itdr_exclude_rules until the data exists: dc_logon_outside_operator_allowlist
    until DC01 SecurityEvent rows arrive (verify: Sentinel + the AMA
    connector), pim_activation_without_auth_context (PREVIEW) until the first
    real Tier-0 activation, vault_privileged_access_anomaly until
    ingest-vault-audit.sh ships the extended feed (vault_feed_v2_columns).
  EOT
  default     = false

  validation {
    condition     = !var.enable_itdr_detections_v2 || var.enable_itdr_detections
    error_message = "enable_itdr_detections_v2 needs enable_itdr_detections = true: its telemetry (VaultCheckout_CL, DC01 Security events) feeds the v2 vault and DC01 rules."
  }
}

variable "itdr_exclude_rules" {
  type        = list(string)
  description = "ITDR rule keys (v1 and v2) to hold back (e.g. identity_risk until the RiskyUsers / UserRiskEvents diagnostic categories have data, tier0_logon_without_checkout and dc_logon_outside_operator_allowlist until DC01 + the Vault feed do). Sentinel rejects a rule whose table has never received data."
  default     = []

  validation {
    condition = alltrue([for k in var.itdr_exclude_rules : contains([
      "app_credential_added", "app_consent_granted", "ca_policy_changed", "role_assigned_outside_pim",
      "pim_group_member_added_outside_pim", "auth_method_changed_by_admin", "identity_risk",
      "tier0_logon_without_checkout", "ad_privileged_group_change", "kerberoast_rc4_service_ticket",
      "dcsync_replication_request",
      "device_code_signin", "security_info_registered_risky", "dc_logon_outside_operator_allowlist",
      "vault_privileged_access_anomaly", "sod_violation_granted", "pim_activation_without_auth_context",
    ], k)])
    error_message = "itdr_exclude_rules: unknown rule key (see local.itdr_rules in itdr.tf and local.itdr_v2_rules in itdr_v2.tf)."
  }
}

variable "enable_itdr_containment" {
  type        = bool
  description = <<-EOT
    Run the containment playbook (lab/monitoring/playbook-contain.json: Teams
    approval card -> revoke sessions + disable / flag for AD disable) on NEW
    High-severity incidents from the ITDR rules. Needs enable_sentinel and
    enable_itdr_detections; creates nothing until containment_playbook_id is
    also set (Deploy-ContainmentPlaybook.ps1 output).
  EOT
  default     = false

  # Cross-variable validation (Terraform >= 1.9, see versions.tf): fail the
  # plan instead of silently creating nothing.
  validation {
    condition     = !var.enable_itdr_containment || (var.enable_itdr_detections && var.enable_sentinel)
    error_message = "enable_itdr_containment needs enable_itdr_detections = true and enable_sentinel = true (automation rules are a Sentinel feature; the Log Analytics alert path has no containment)."
  }
}

variable "containment_playbook_id" {
  type        = string
  description = "Resource id of pb-identity-contain (Deploy-ContainmentPlaybook.ps1 output). Empty = no containment automation rule yet."
  default     = ""

  validation {
    condition     = var.containment_playbook_id == "" || can(regex("(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\\.Logic/workflows/[^/]+$", var.containment_playbook_id))
    error_message = "containment_playbook_id must be a Logic App resource id (/subscriptions/.../providers/Microsoft.Logic/workflows/<name>)."
  }
}

variable "containment_rule_keys" {
  type        = list(string)
  description = "ITDR rule keys whose High incidents trigger containment. null = every deployed ITDR rule except sod_violation_granted and vault_privileged_access_anomaly, which never do."
  default     = null

  validation {
    condition = var.containment_rule_keys == null ? true : alltrue([for k in var.containment_rule_keys : contains([
      "app_credential_added", "app_consent_granted", "ca_policy_changed", "role_assigned_outside_pim",
      "pim_group_member_added_outside_pim", "auth_method_changed_by_admin", "identity_risk",
      "tier0_logon_without_checkout", "ad_privileged_group_change", "kerberoast_rc4_service_ticket",
      "dcsync_replication_request",
      "device_code_signin", "security_info_registered_risky", "dc_logon_outside_operator_allowlist",
      "vault_privileged_access_anomaly", "sod_violation_granted", "pim_activation_without_auth_context",
    ], k)])
    error_message = "containment_rule_keys: unknown rule key (see local.itdr_rules in itdr.tf and local.itdr_v2_rules in itdr_v2.tf)."
  }

  # local.itdr_never_contain (itdr_v2.tf), refused by name so the plan says
  # why instead of silently dropping the key.
  validation {
    condition     = var.containment_rule_keys == null ? true : !anytrue([for k in var.containment_rule_keys : contains(["sod_violation_granted", "vault_privileged_access_anomaly"], k)])
    error_message = "containment_rule_keys: sod_violation_granted and vault_privileged_access_anomaly never trigger containment - disabling a clinician over an SoD conflict is a patient-safety event (ADR 0012), and the vault rule's Account is a Vault identity the playbook cannot act on."
  }
}

# -----------------------------------------------------------------------------
# Identities the ITDR rules judge by IMMUTABLE id. Rendered into the KQL in
# place of the empty `dynamic([])` let-lists (local.rule_queries, main.tf).
# Empty defaults are fail closed: no change counts as IaC, no group / user is
# privileged by id (the rules fall back to naming, which can only RAISE
# severity). Object ids are not secrets, but they identify a real tenant, so
# they come from TF_* variables / terraform.tfvars, never lab.tfvars.
# -----------------------------------------------------------------------------
variable "iac_principal_ids" {
  type        = list(string)
  description = "The CI APPLY identity's service principal object id and application (client) id (envs/bootstrap output iac_principal_ids). A change made by these ids is 'IaC' (lower severity); a change by an app that only carries the IaC display name is High (impersonation)."
  default     = []

  validation {
    condition     = alltrue([for id in var.iac_principal_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "iac_principal_ids: object / client ids (GUIDs) only - never display names, which anyone who owns an app can change."
  }
}

variable "privileged_group_ids" {
  type        = list(string)
  description = "Object ids of the role-holding / PIM-governed groups (Break-Glass-Admins, Privileged-IAM-Admins, PIM tier groups, the Azure PIM group). pim-group-member-added-outside-pim.kql alerts on members added to them outside PIM."
  default     = []

  validation {
    condition     = alltrue([for id in var.privileged_group_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "privileged_group_ids: group object ids (GUIDs) only."
  }
}

variable "azure_pim_group_ids" {
  type        = list(string)
  description = <<-EOT
    Object id(s) of PIM-Azure-RG-Contributors (modules/pim azure.tf), also
    listed in privileged_group_ids. Its members are STANDING by design: the
    GROUP is eligible for Contributor on the lab RG and each member still
    activates through Azure PIM with Tier-0 approval, so a direct member add
    is the intended operational path, not a bypass.
    pim-group-member-added-outside-pim.kql reports it on its own path
    (AzurePimEligibleMember, Medium) instead of High "Direct".
  EOT
  default     = []

  validation {
    condition     = alltrue([for id in var.azure_pim_group_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "azure_pim_group_ids: group object ids (GUIDs) only."
  }
}

variable "break_glass_group_ids" {
  type        = list(string)
  description = "Object id(s) of Break-Glass-Admins: any member added there is High, even by the IaC identity."
  default     = []

  validation {
    condition     = alltrue([for id in var.break_glass_group_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "break_glass_group_ids: group object ids (GUIDs) only."
  }
}

variable "privileged_user_ids" {
  type        = list(string)
  description = "Object ids of privileged users (break-glass, members / eligible members of the PIM groups, directory-role holders - Find-ShadowAdmins.ps1 -PrivilegedIdsPath). auth-method-changed-by-admin.kql makes any MFA / TAP change on them High."
  default     = []

  validation {
    condition     = alltrue([for id in var.privileged_user_ids : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "privileged_user_ids: user object ids (GUIDs) only."
  }
}

variable "containment_on_alert_added" {
  type        = bool
  description = <<-EOT
    Also run containment when a High ITDR alert is ADDED to an existing
    incident (incident Updated + Alerts added). In the Defender portal the
    correlation engine can attach a new alert to an older incident, so the
    Created-only trigger would never see it. Off by default: an incident that
    gets a second alert then produces a second approval card (noise, never an
    unapproved action). verify: turn on after the first Defender-portal
    incident shows whether correlation merges ITDR alerts.
  EOT
  default     = false
}

variable "collect_dc_security_events" {
  type        = bool
  description = "With enable_itdr_detections: install the Azure Monitor Agent on DC01 and collect its identity-relevant Security events into SecurityEvent. Pass enable_dc here (a plan-time boolean; the VM id itself is unknown on the first plan)."
  default     = false
}

variable "dc_vm_id" {
  type        = string
  description = "Resource id of vm-dc01 (module.dc_vm[0].vm_id). Used only when collect_dc_security_events is true."
  default     = ""
}

# -----------------------------------------------------------------------------
# operator_ips watchlist (itdr_v2.tf) - the allowlist
# dc-logon-outside-operator-allowlist.kql judges DC01 logons against.
# -----------------------------------------------------------------------------
variable "operator_ip_ranges" {
  type        = list(string)
  description = "Operator egress IPs for the operator_ips Sentinel watchlist: the same single-host /32 entries modules/dc-vm admits to DC01 (envs/dev operator_ip_ranges when enable_dc, else []). Sensitive: never shown in a plan. Used only with enable_sentinel + enable_itdr_detections_v2."
  default     = []
  sensitive   = true

  # Same rule as modules/dc-vm: a wider range would allowlist neighbours the
  # NSG never admits. The message never prints the value.
  validation {
    condition     = alltrue([for c in var.operator_ip_ranges : try(endswith(c, "/32") && cidrnetmask(c) == "255.255.255.255", false)])
    error_message = "operator_ip_ranges: single IPv4 /32 entries only (the hosts modules/dc-vm admits to DC01)."
  }
}

variable "operator_ips_owner" {
  type        = string
  description = "Owner column of every operator_ips watchlist row: a role name, not a person (the watchlist is readable by every Sentinel reader)."
  default     = "lab-operator"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$", var.operator_ips_owner))
    error_message = "operator_ips_owner: 1-64 characters, letters, digits, space, dot, underscore or hyphen (a role name such as lab-operator, never an email address)."
  }
}

variable "operator_ips_expires_on" {
  type        = string
  description = "ExpiresOn (yyyy-mm-dd) of every operator_ips row: ADR 0013's review date. The KQL ignores an entry past it, so the time box is enforced in the detection too; the plan warns once it has passed. Required when operator_ip_ranges is set."
  default     = null

  validation {
    condition     = var.operator_ips_expires_on == null ? true : can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.operator_ips_expires_on)) && can(timecmp("${var.operator_ips_expires_on}T00:00:00Z", "2000-01-01T00:00:00Z"))
    error_message = "operator_ips_expires_on: a real calendar date as yyyy-mm-dd (ADR 0013's review date)."
  }
}

# -----------------------------------------------------------------------------
# PAM vault feed, extended (telemetry.tf).
# -----------------------------------------------------------------------------
variable "vault_feed_v2_columns" {
  type        = bool
  description = <<-EOT
    Add Ticket, Operator and ErrorText to VaultCheckout_CL and its DCR stream,
    for vault-privileged-access-anomaly.kql. Turn on in the SAME change that
    ships the ingest-vault-audit.sh version emitting them (and the cred-read /
    rotation-failed / root-token / auth-failed / access-denied rows): once the
    Ticket column exists the rule judges every Tier-0 check-out by it, so the
    column without the script would make every check-out a High
    "Tier0CheckoutWithoutTicket". Needs enable_itdr_detections (the table).
  EOT
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Tags for taggable resources."
  default     = {}
}
