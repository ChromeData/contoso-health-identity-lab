# =============================================================================
# modules/monitoring :: itdr.tf
# -----------------------------------------------------------------------------
# Identity Threat Detection and Response (ITDR) pack.
#
#   DETECT  (enable_itdr_detections): eleven lab/kql rules, each with an SPL
#           twin in lab/splunk/detections. They join the same Sentinel / Log
#           Analytics paths as the core rules (main.tf), so the same staging
#           and trial rules apply: nothing here creates a rule unless
#           enable_sentinel or enable_la_alerts is also on. Turning the flag on
#           EARLY is the intended order: it creates the telemetry plumbing
#           (telemetry.tf) so the tables have data before Sentinel validates
#           the rules against them. Six more rules sit behind
#           enable_itdr_detections_v2 (itdr_v2.tf).
#   RESPOND (enable_itdr_containment): a Sentinel automation rule that runs
#           the containment playbook (lab/monitoring/playbook-contain.json) on
#           NEW High-severity incidents from these rules. The playbook asks a
#           human in Teams before it touches anything. Rules on
#           local.itdr_never_contain (itdr_v2.tf) are never wired to it.
#
# Every rule maps ONE Account entity: the identity the containment playbook
# would act on (the actor for admin actions, the risky user for risk, the AD
# account for Tier-0 logons). Victims and targets are custom details, never
# entities, so a misclick can't disable the person who was attacked.
# =============================================================================

locals {
  # Shared shapes, so each rule below says only what is different about it.
  actor_entities = [
    { type = "Account", fields = [{ identifier = "FullName", column = "ActorUpn" }, { identifier = "AadUserId", column = "ActorObjectId" }] },
    { type = "IP", fields = [{ identifier = "Address", column = "ActorIp" }] },
  ]
  actor_group_by = ["Account"]

  itdr_rules = {
    app_credential_added = {
      file            = "app-credential-added.kql"
      display_name    = "Contoso ITDR - Credential added to an app or service principal"
      description     = "New secret, certificate or federated identity credential on a workload identity (T1098.001). High on a service principal object or a new FIC outside the CI apply identity."
      severity        = "Medium"
      frequency       = "PT5M"
      period          = "PT1H"
      suppress        = null
      tactics         = ["Persistence", "PrivilegeEscalation"]
      techniques      = ["T1098"]
      entities        = local.actor_entities
      severity_column = "Severity"
      custom_details = {
        TargetApp      = "TargetName"
        TargetType     = "TargetType"
        CredentialKind = "CredentialKind"
        ViaIaC         = "IsIac"
        IacSpoof       = "IacNameSpoof"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
    app_consent_granted = {
      file            = "app-consent-granted.kql"
      display_name    = "Contoso ITDR - Permission granted to an application"
      description     = "Delegated consent, delegated grant or application permission given to an app (T1528, T1098.003). High when tenant-wide and high-risk (mail, files, directory/role write)."
      severity        = "Medium"
      frequency       = "PT5M"
      period          = "PT1H"
      suppress        = null
      tactics         = ["CredentialAccess", "Persistence"]
      techniques      = ["T1528", "T1098"]
      entities        = local.actor_entities
      severity_column = "Severity"
      custom_details = {
        ClientApp  = "ClientApp"
        GrantKind  = "GrantKind"
        TenantWide = "TenantWide"
        ViaIaC     = "IsIac"
        IacSpoof   = "IacNameSpoof"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
    ca_policy_changed = {
      file            = "ca-policy-changed.kql"
      display_name    = "Contoso ITDR - Conditional Access policy, named location or auth strength changed outside IaC"
      description     = "CA policy added, edited, disabled, moved to report-only, exclusions changed or deleted; named location deleted / country removed / range newly trusted; authentication strength deleted or given a phishable combination (T1556.009, T1562.001). High when it weakens the control plane and the CI apply identity (by immutable id) did not make it."
      severity        = "Medium"
      frequency       = "PT5M"
      period          = "PT1H"
      suppress        = null
      tactics         = ["DefenseEvasion", "CredentialAccess", "Persistence"]
      techniques      = ["T1556", "T1562"]
      entities        = local.actor_entities
      severity_column = "Severity"
      custom_details = {
        Policy     = "PolicyName"
        ObjectKind = "ObjectKind"
        Change     = "Change"
        NewState   = "NewState"
        ViaIaC     = "IsIac"
        IacSpoof   = "IacNameSpoof"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    role_assigned_outside_pim = {
      file            = "role-assigned-outside-pim.kql"
      display_name    = "Contoso ITDR - Directory role assigned outside PIM"
      description     = "Standing Entra role assignment not written by PIM, or an ACTIVE assignment made in PIM (permanent = High, time-bound = Medium) (T1098.003). Zero standing admin: High unless the CI apply identity (by immutable id) made it."
      severity        = "High"
      frequency       = "PT5M"
      period          = "PT1H"
      suppress        = null
      tactics         = ["Persistence", "PrivilegeEscalation"]
      techniques      = ["T1098"]
      entities        = local.actor_entities
      severity_column = "Severity"
      custom_details = {
        Role       = "RoleName"
        RoleTier   = "RoleTier"
        AssignedTo = "TargetName"
        Path       = "AssignmentPath"
        ViaIaC     = "IsIac"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    pim_group_member_added_outside_pim = {
      file            = "pim-group-member-added-outside-pim.kql"
      display_name    = "Contoso ITDR - Member added to a privileged group outside PIM"
      description     = "Direct or PIM-active permanent membership on a role-holding / PIM-governed group (Break-Glass-Admins, Privileged-IAM-Admins, PIM tiers, the Azure PIM group): standing Tier-0 that bypasses PIM eligibility and expiry (T1098.003). Break-Glass-Admins is always High."
      severity        = "High"
      frequency       = "PT5M"
      period          = "PT1H"
      suppress        = null
      tactics         = ["Persistence", "PrivilegeEscalation"]
      techniques      = ["T1098"]
      entities        = local.actor_entities
      severity_column = "Severity"
      custom_details = {
        Group      = "GroupName"
        NewMember  = "MemberName"
        Path       = "AssignmentPath"
        BreakGlass = "IsBreakGlassGroup"
        ViaIaC     = "IsIac"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    auth_method_changed_by_admin = {
      file            = "auth-method-changed-by-admin.kql"
      display_name    = "Contoso ITDR - Authentication method changed by an admin for another user"
      description     = "An admin registered, updated or deleted another user's MFA / passwordless method, TAP included (T1556.006, T1098.005). High for every privileged target (help-desk runbook level V3): in the privileged-id list (break-glass, PIM-group members and eligibles, role holders), granted a directory role or privileged / PIM-tier group membership or ownership (active or eligible) in the last 2 days, or named like a break-glass / Tier-0 account."
      severity        = "Medium"
      frequency       = "PT1H" # Sentinel refuses a period >= 2 days with a frequency under 1 hour (BadRequest, proven 2026-10-27): hourly, which is also the window the .kql judges
      period          = "P2D"  # 1 h of method changes judged + 2 days of privileged-grant history (see the .kql); P2D is also the LA alert maximum
      suppress        = null
      tactics         = ["CredentialAccess", "Persistence", "DefenseEvasion"]
      techniques      = ["T1556", "T1098"]
      entities        = local.actor_entities
      severity_column = "Severity"
      custom_details = {
        TargetUser     = "TargetUpn"
        Method         = "Method"
        Action         = "Action"
        IsTap          = "IsTap"
        PrivilegeBasis = "PrivilegeBasis"
        RecentGrants   = "RecentGrants"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = "PT1H" # a change stays matchable for 1 h, not the 2-day window
    }
    identity_risk = {
      file         = "identity-risk.kql"
      display_name = "Contoso ITDR - Risky user or risky sign-in (Identity Protection)"
      description  = "Open medium/high Entra ID Protection risk (detection, risky user or risky sign-in) not closed by CA006/CA007 or an admin (T1078.004). Needs Entra ID P2 and the RiskyUsers / UserRiskEvents diagnostic categories."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["InitialAccess", "DefenseEvasion", "Persistence", "PrivilegeEscalation"]
      techniques   = ["T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "FullName", column = "UserPrincipalName" }, { identifier = "AadUserId", column = "UserId" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "IPAddress" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Signal    = "Signal"
        RiskLevel = "RiskLevel"
        RiskState = "RiskState"
        RiskEvent = "RiskEventType"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    tier0_logon_without_checkout = {
      file         = "tier0-logon-without-checkout.kql"
      display_name = "Contoso ITDR - Tier-0 logon on DC01 without a Vault check-out"
      description  = "Tier-0 logon on DC01 that PAM does not account for: a vaulted tier0-admin with no Vault check-out (credential used outside PAM), the RID-500 break-glass Administrator, or any other account with special privileges (4672) the vault does not manage (T1078.002, T1550.002). Needs DC01 SecurityEvent (AMA; verify: Sentinel + connector) and VaultCheckout_CL (ingest-vault-audit.sh)."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT3H" # 1 h of logons + 2 h 20 m of Vault history (see the .kql)
      suppress     = null
      tactics      = ["DefenseEvasion", "Persistence", "PrivilegeEscalation", "LateralMovement"]
      techniques   = ["T1078", "T1550"]
      entities = [
        { type = "Account", fields = [{ identifier = "Name", column = "Account" }, { identifier = "NTDomain", column = "AccountDomain" }, { identifier = "Sid", column = "AccountSid" }] },
        { type = "Host", fields = [{ identifier = "HostName", column = "Host" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "SourceIp" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Verdict          = "Verdict"
        Class            = "Class"
        VaultFeedHealthy = "VaultFeedHealthy"
        UncoveredEvents  = "UncoveredEvents"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 0
      la_mute          = "PT1H" # a logon stays matchable for 1 h, not the 3 h window
    }
    # The AD plane (DC01 SecurityEvent, telemetry.tf). The actor is an AD
    # account with no Entra object id, so containment takes the AD path
    # (comment + ticket; Invoke-AdContainment.ps1 by a human).
    ad_privileged_group_change = {
      file         = "ad-privileged-group-change.kql"
      display_name = "Contoso ITDR - Member added to a privileged AD group"
      description  = "4728/4732/4756 on DC01 for a pam-policy.json Tier-0 group (matched by well-known SID/RID; DnsAdmins by name) = High, Tier1-Server-Admins = Medium (T1098.007). Needs DC01 SecurityEvent (AMA; verify: Sentinel + connector)."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["Persistence", "PrivilegeEscalation"]
      techniques   = ["T1098", "T1078"]
      entities = [
        { type = "Account", fields = [{ identifier = "Name", column = "Account" }, { identifier = "NTDomain", column = "AccountDomain" }, { identifier = "Sid", column = "AccountSid" }] },
        { type = "Host", fields = [{ identifier = "HostName", column = "Host" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Group     = "GroupName"
        GroupTier = "GroupTier"
        NewMember = "NewMember"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 1
      la_mute          = null
    }
    kerberoast_rc4_service_ticket = {
      file         = "kerberoast-rc4-service-ticket.kql"
      display_name = "Contoso ITDR - Kerberoasting (RC4 service tickets for user SPNs)"
      description  = "4769 RC4 (0x17) tickets for user-account SPNs on DC01: offline-crackable. High for 3+ services per requester or a Tier-0 SPN account (T1558.003). Needs DC01 SecurityEvent (AMA; verify: Sentinel + connector)."
      severity     = "Medium"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["CredentialAccess"]
      techniques   = ["T1558"]
      entities = [
        { type = "Account", fields = [{ identifier = "Name", column = "Account" }, { identifier = "NTDomain", column = "AccountDomain" }] },
        { type = "Host", fields = [{ identifier = "HostName", column = "Host" }] },
        { type = "IP", fields = [{ identifier = "Address", column = "SourceIp" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Services     = "Services"
        ServiceCount = "ServiceCount"
        Tier0Spn     = "Tier0Roasted"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 2
      la_mute          = null
    }
    dcsync_replication_request = {
      file         = "dcsync-replication-request.kql"
      display_name = "Contoso ITDR - DCSync (replication requested by a non-DC account)"
      description  = "4662 with the DS-Replication-Get-Changes(-All) rights on DC01 by an account that is not a domain controller: every password hash, krbtgt included (T1003.006). Needs DC01 SecurityEvent (AMA; verify: Sentinel + connector) and the domain SACL for 4662."
      severity     = "High"
      frequency    = "PT5M"
      period       = "PT1H"
      suppress     = null
      tactics      = ["CredentialAccess"]
      techniques   = ["T1003"]
      entities = [
        { type = "Account", fields = [{ identifier = "Name", column = "Account" }, { identifier = "NTDomain", column = "AccountDomain" }, { identifier = "Sid", column = "AccountSid" }] },
        { type = "Host", fields = [{ identifier = "HostName", column = "Host" }] },
      ]
      severity_column = "Severity"
      custom_details = {
        Requests   = "Requests"
        RightsUsed = "RightsUsed"
      }
      alert_per_result = true
      group_by         = local.actor_group_by
      la_severity      = 0
      la_mute          = null
    }
  }

  # Which ITDR rules may trigger containment (null = every deployed one that
  # is not on itdr_never_contain). The never-contain filter is applied again
  # to the ids, so no key list can wire those rules to the playbook.
  containment_rule_keys = var.containment_rule_keys != null ? var.containment_rule_keys : [
    for k in keys(local.itdr_selected) : k if !contains(local.itdr_never_contain, k)
  ]
  containment_rule_ids = [
    for k, r in azurerm_sentinel_alert_rule_scheduled.this : r.id
    if contains(keys(local.itdr_selected), k) && contains(local.containment_rule_keys, k) && !contains(local.itdr_never_contain, k)
  ]
}

# -----------------------------------------------------------------------------
# Containment trigger (enable_itdr_containment). Variable validation already
# refuses the flag without enable_itdr_detections + enable_sentinel; the
# playbook id comes from Deploy-ContainmentPlaybook.ps1 (empty = not yet).
# -----------------------------------------------------------------------------
resource "azurerm_sentinel_automation_rule" "contain" {
  count = var.enable_sentinel && var.enable_itdr_detections && var.enable_itdr_containment && var.containment_playbook_id != "" ? 1 : 0

  name                       = uuidv5("url", "https://contoso-health-identity-lab/automation/itdr-contain")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = "Contoso ITDR - containment approval (High identity incidents)"
  # After notify (order 1), so the ServiceNow ticket the containment run
  # appends to normally exists before the approval card is even answered.
  order         = 2
  triggers_on   = "Incidents"
  triggers_when = "Created"

  # Both conditions must hold: an ITDR rule raised it AND it is High. Medium
  # and Low ITDR incidents get the notify card only. Severity raised by hand
  # later does NOT re-trigger this (Created only): the analyst runs the
  # playbook from the incident instead (Run playbook), which still goes
  # through the Teams approval.
  condition_json = jsonencode([
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "IncidentRelatedAnalyticRuleIds"
        operator       = "Contains"
        propertyValues = local.containment_rule_ids
      }
    },
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "IncidentSeverity"
        operator       = "Equals"
        propertyValues = ["High"]
      }
    },
  ])

  action_playbook {
    logic_app_id = var.containment_playbook_id
    order        = 1
  }

  lifecycle {
    precondition {
      condition     = length(local.containment_rule_ids) > 0
      error_message = "enable_itdr_containment is on but no deployed ITDR rule is eligible (check itdr_exclude_rules / containment_rule_keys)."
    }
  }
}

# -----------------------------------------------------------------------------
# Same containment, when a High ITDR alert is ADDED to an existing incident
# (containment_on_alert_added, default off). The Defender portal's correlation
# engine can attach a new alert to an older incident; the Created-only rule
# above would then never run. Same conditions plus "an alert was added".
# verify: the PropertyArrayChanged condition shape (arrayType Alerts,
# changeType Added) on the first apply.
# -----------------------------------------------------------------------------
resource "azurerm_sentinel_automation_rule" "contain_on_alert_added" {
  count = length(azurerm_sentinel_automation_rule.contain) == 1 && var.containment_on_alert_added ? 1 : 0

  name                       = uuidv5("url", "https://contoso-health-identity-lab/automation/itdr-contain-alert-added")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  display_name               = "Contoso ITDR - containment approval (High alert added to an incident)"
  order                      = 3
  triggers_on                = "Incidents"
  triggers_when              = "Updated"

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
        propertyValues = local.containment_rule_ids
      }
    },
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName   = "IncidentSeverity"
        operator       = "Equals"
        propertyValues = ["High"]
      }
    },
  ])

  action_playbook {
    logic_app_id = var.containment_playbook_id
    order        = 1
  }
}
