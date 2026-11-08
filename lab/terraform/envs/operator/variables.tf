# =============================================================================
# envs/operator :: variables.tf
# =============================================================================

variable "subscription_id" {
  description = "The lab subscription the operator may manage."
  type        = string
}

variable "tenant_id" {
  description = "The lab Entra tenant."
  type        = string
}

variable "operator_certificate_path" {
  description = <<-EOT
    Path to the operator's PUBLIC certificate (PEM), made by
    lab/scripts/operator/new-operator-cert.sh. The private key never leaves the
    Mac's login Keychain; only this public half is uploaded to Entra.
  EOT
  type        = string
  default     = "~/.contoso-operator/operator.crt"
}

variable "operator_display_name" {
  description = "Display name of the operator app registration."
  type        = string
  default     = "Contoso Lab Operator (local Mac, certificate)"
}

variable "operator_graph_roles" {
  description = <<-EOT
    STANDING Microsoft Graph application permissions: what the operator holds
    every day, between write sessions. READ ONLY, on purpose (ADR 0030). These
    are what the routine jobs need: the KPI one-pager, the NHI inventory, the
    SoD report, the drift check, the evidence read-back and the demo's
    read-only checks.
      Directory.Read.All                  users, groups, roles, apps
      AuditLog.Read.All                   provisioning and sign-in logs
      Policy.Read.All                     Conditional Access, auth methods
      AccessReview.Read.All               access reviews (the report scripts
                                          check their Graph context for this name)
      LifecycleWorkflows.Read.All         joiner/leaver workflows and runs
      RoleEligibilitySchedule.Read.Directory  who is eligible for which role
      RoleManagement.Read.Directory       ACTIVE role assignments
                                          (roleAssignmentScheduleInstances) for
                                          08-Measure-KPIs.ps1 and 09-SoD-Report.ps1
      RoleManagementPolicy.Read.Directory     PIM activation rules, directory roles
      RoleManagementPolicy.Read.AzureADGroup  PIM activation rules, PIM groups
      PrivilegedEligibilitySchedule.Read.AzureADGroup  PIM-for-Groups eligibility
      DeviceManagementManagedDevices.Read.All  the Intune pilot device
      DeviceManagementConfiguration.Read.All   its compliance policy
      SecurityEvents.Read.All             Secure Score history (read only)
      Reports.Read.All                    the AD FS application migration
                                          report (lab/adfs, ADR 0009): least
                                          privileged per Learn
                                          (reportroot-getrelyingpartydetailedsummary)
      EntitlementManagement.Read.All      access packages and assignments for
                                          09-SoD-Report.ps1 between sessions

    History: until 2026-11-06 this list also held 16 write permissions,
    including AppRoleAssignment.ReadWrite.All and
    RoleManagement.ReadWrite.Directory, each added with the note "no new
    reach: the operator was already Tier 0". ADR 0030 retires that
    reasoning: being Tier 0 already is a reason to remove rights, not to add
    more. The writes moved to operator_session_graph_roles.
  EOT
  type        = list(string)
  default = [
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "AccessReview.Read.All",
    "LifecycleWorkflows.Read.All",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleManagement.Read.Directory",
    "RoleManagementPolicy.Read.Directory",
    "RoleManagementPolicy.Read.AzureADGroup",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "SecurityEvents.Read.All",
    "Reports.Read.All",
    "EntitlementManagement.Read.All",
  ]

  validation {
    # The standing list stays read-only. A write permission belongs in
    # operator_session_graph_roles, where it exists only during a session.
    condition     = alltrue([for r in var.operator_graph_roles : can(regex("\\.Read(\\.|$)", r)) && !can(regex("ReadWrite|DeleteRestore|Create$", r))])
    error_message = "operator_graph_roles is the STANDING set and must be read-only (*.Read.*). Put write permissions in operator_session_graph_roles (ADR 0030)."
  }
}

variable "operator_session_graph_roles" {
  description = <<-EOT
    WRITE Microsoft Graph application permissions. The operator holds these
    ONLY while a write session is open (operator_write_session below). The
    owner opens a session with a human apply, does the work, and closes it
    with a second apply. Each one, and the job that needs it:
      Application.ReadWrite.All           envs/bootstrap (CI apps and their
                                          federated credentials)
      AppRoleAssignment.ReadWrite.All     envs/bootstrap Graph grants. TIER 0:
                                          it can grant any Graph permission
      Synchronization.ReadWrite.All       provision on demand, job restarts
      EntitlementManagement.ReadWrite.All access packages and policies
      PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup  make adm-labops
                                          ELIGIBLE for PIM-AWS-Lab-Admins (ADR 0025)
      User.DeleteRestore.All              purge a demo hire (reset-demo-hire.sh)
      AdministrativeUnit.ReadWrite.All    the restricted VIP admin unit
      RoleManagement.ReadWrite.Directory  AU-scoped roles. TIER 0
      LifecycleWorkflows.ReadWrite.All    workflow schedule, on-demand runs
      UserAuthenticationMethod.ReadWrite.All  Temporary Access Pass for test
                                          users. TIER 0 in practice: it can add
                                          a credential to a break-glass account
      User.ReadWrite.All                  test users' job attributes
      GroupMember.ReadWrite.All           test users into app groups
      Team.Create, TeamMember.ReadWrite.All  the SOC team for the playbooks
      DelegatedPermissionGrant.ReadWrite.All  admin consent for the lab's apps
      AccessReview.ReadWrite.All          create the rendered review series
      DeviceManagementConfiguration.ReadWrite.All  (added 2026-11-08, TIME-BOXED
                                          to the E5 trial, which ends 2026-11-26)
                                          create and assign the Intune Endpoint
                                          Privilege Management policies and the
                                          Windows LAPS policy for CH-WIN11-01
                                          (lab/scripts/intune/New-IntuneEpmAndLaps.ps1,
                                          ADR 0036). EPM is licensed only by the
                                          trial. App role id 9241abd9-d0e6-425a-
                                          bd4f-47ba86e767a4, read live from the
                                          Microsoft Graph SP. The STANDING list keeps
                                          DeviceManagementConfiguration.Read.All.
                                          Approving an elevation request stays with
                                          a person (PIM-Tier1-Intune-Admins). The
                                          check "intune_write_time_box" warns on
                                          every plan after 2026-11-26 until a PR
                                          removes it from this list.
    Graph application permissions cannot be eligible or expire on their own.
    So the time box is the session window plus the plan check in
    write-session.tf, and the owner's closing apply. ADR 0030 records this gap.
  EOT
  type        = list(string)
  default = [
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Synchronization.ReadWrite.All",
    "EntitlementManagement.ReadWrite.All",
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
    "User.DeleteRestore.All",
    "AdministrativeUnit.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "LifecycleWorkflows.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "User.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Team.Create",
    "TeamMember.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "AccessReview.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All", # time-boxed to the E5 trial (2026-11-26): see above
  ]
}

variable "operator_write_session" {
  description = <<-EOT
    null (the default) = no write session: the operator holds only the
    standing, read-only grants. To open a session, the OWNER applies this
    root with:
      operator_write_session = {
        opened_utc  = "2026-11-07T14:00:00Z"
        expires_utc = "2026-11-07T18:00:00Z"   # at most 8 hours later
        reason      = "recording day: demo resets and TAPs (ticket or PR)"
      }
    and closes it by applying again with the variable unset. While open:
      * Graph: the operator_session_graph_roles are granted
      * Azure: the custom "Contoso Lab Operator Session" role and Key Vault
        Secrets Officer, as TIME-BOUND ACTIVE PIM assignments that end at
        expires_utc. Azure removes them by itself, even if nobody closes.
    A plan after expires_utc FAILS (write-session.tf), so a stale session
    cannot be re-applied by mistake.
  EOT
  type = object({
    opened_utc  = string
    expires_utc = string
    reason      = string
  })
  default = null

  validation {
    condition = var.operator_write_session == null ? true : (
      can(timecmp(var.operator_write_session.opened_utc, var.operator_write_session.expires_utc)) &&
      timecmp(var.operator_write_session.opened_utc, var.operator_write_session.expires_utc) < 0 &&
      timecmp(var.operator_write_session.expires_utc, timeadd(var.operator_write_session.opened_utc, "8h")) <= 0 &&
      length(trimspace(var.operator_write_session.reason)) >= 10
    )
    error_message = "operator_write_session: RFC 3339 times, expires_utc after opened_utc and at most 8 hours later, and a reason of at least 10 characters."
  }
}

variable "operator_azure_roles" {
  description = <<-EOT
    STANDING Azure built-in roles for the operator at SUBSCRIPTION scope.
      Reader                        read every lab resource (drift, evidence
                                    checks, KPI). Replaces Owner (ADR 0030).
      Storage Blob Data Contributor Terraform state READ (Entra auth, Shared
                                    Key is off) and evidence read-back. An
                                    ABAC condition refuses blob writes to the
                                    terraform_state_containers (R4). Subscription
                                    scope because the state account's ReadOnly
                                    lock blocks account- and container-scoped
                                    role assignments. In the evidence container,
                                    the time-based immutability policy refuses
                                    deletes and overwrites inside the retention
                                    period, whatever data role the caller holds.
      Key Vault Secrets User        READ lab secrets for deploy and seeding
                                    steps, EXCEPT tier0_secret_names (ABAC
                                    condition, R4). Writing a secret, or
                                    reading a Tier-0 one, needs a session
                                    (Key Vault Secrets Officer, below).
    Owner is gone. Without Owner, the operator holds no
    Microsoft.Authorization/*/write or */delete at all: it cannot create a
    role assignment, and it cannot remove the evidence store's CanNotDelete
    lock. So envs/bootstrap and this root are human applies again.
  EOT
  type        = list(string)
  default     = ["Reader", "Storage Blob Data Contributor", "Key Vault Secrets User"]

  validation {
    condition     = !contains(var.operator_azure_roles, "Owner") && !contains(var.operator_azure_roles, "User Access Administrator") && !contains(var.operator_azure_roles, "Role Based Access Control Administrator")
    error_message = "The operator holds no standing role that can write role assignments or locks (Owner, User Access Administrator, RBAC Administrator). ADR 0030."
  }
}

variable "operator_session_azure_roles" {
  description = <<-EOT
    Azure built-in roles added ONLY during a write session, as time-bound
    active PIM assignments (they end at expires_utc). The custom session role
    in write-session.tf is always added too.
      Key Vault Secrets Officer     write lab secrets (SCIM token, ServiceNow
                                    and Sentinel integration passwords)
  EOT
  type        = list(string)
  default     = ["Key Vault Secrets Officer"]
}

variable "enable_operator_workload_ca" {
  description = <<-EOT
    DESIGNED, off. A Conditional Access policy for WORKLOAD identities that
    blocks the operator outside operator_allowed_ip_ranges (the owner's
    network). It needs a Microsoft Entra Workload ID Premium licence
    ("Workload Identities Premium licenses are required to create or modify
    Conditional Access policies scoped to service principals", Microsoft
    Learn, conditional-access/workload-identity). The lab tenant has none
    (subscribedSkus read 2026-11-07: INTUNE_A, SPE_E5, ID Governance step-up).
    The lab never buys anything, so this stays off until a licence exists.
    It starts report-only, like every lab policy (ADR 0003).
  EOT
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_operator_workload_ca || length(var.operator_allowed_ip_ranges) > 0
    error_message = "enable_operator_workload_ca needs operator_allowed_ip_ranges (CIDR list of the owner's network)."
  }
}

variable "operator_workload_ca_state" {
  description = "State of the operator workload CA policy: enabledForReportingButNotEnforced first, then enabled."
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["enabledForReportingButNotEnforced", "enabled", "disabled"], var.operator_workload_ca_state)
    error_message = "operator_workload_ca_state: enabledForReportingButNotEnforced, enabled or disabled."
  }
}

variable "operator_allowed_ip_ranges" {
  description = "Public CIDR ranges the operator may sign in from (the owner's network). Used only when enable_operator_workload_ca is true."
  type        = list(string)
  default     = []
}

variable "operator_directory_roles" {
  description = <<-EOT
    Entra directory roles for the operator. Security Reader: a bootstrap plan
    refreshes the tenant diagnostic setting (microsoft.aadiam), which ARM
    authorizes with Entra roles, not Azure RBAC. READ only, on purpose: a
    bootstrap change to that setting (categories, destination, a restore) is
    a human apply. The operator's plan shows it; its apply fails on the write.
    Granting Security Administrator would also let it rewrite Conditional
    Access, the control the audit trail is there to watch.
  EOT
  type        = list(string)
  default     = ["Security Reader"]
}

variable "intune_write_expires_utc" {
  description = "End of the Intune write time box: the E5 trial (which licenses EPM) ends 2026-11-26. check \"intune_write_time_box\" warns on every plan after this while DeviceManagementConfiguration.ReadWrite.All is still a session role. A variable so the offline tests do not depend on today's date."
  type        = string
  default     = "2026-11-27T00:00:00Z"

  validation {
    condition     = can(timecmp(var.intune_write_expires_utc, "2026-01-01T00:00:00Z"))
    error_message = "intune_write_expires_utc must be an RFC 3339 time."
  }
}

variable "tier0_secret_names" {
  description = <<-EOT
    Key Vault secret names the operator can NOT read outside a write session
    (ABAC condition on its standing Key Vault Secrets User; karen-review
    round 2, R4). The built-in Domain Admin and the DSRM password: reading
    either one is Tier 0. Add any new Tier-0 secret here in the same PR that
    creates it.
  EOT
  type        = list(string)
  default     = ["dc01-admin-password", "dc01-dsrm-password"]

  validation {
    condition     = contains(var.tier0_secret_names, "dc01-admin-password") && contains(var.tier0_secret_names, "dc01-dsrm-password")
    error_message = "tier0_secret_names must keep dc01-admin-password and dc01-dsrm-password (R4)."
  }
  validation {
    condition     = alltrue([for n in var.tier0_secret_names : can(regex("^[0-9A-Za-z-]{1,127}$", n))])
    error_message = "Key Vault secret names are 1-127 letters, digits and dashes."
  }
}

variable "terraform_state_containers" {
  description = <<-EOT
    Blob containers holding Terraform state that the operator can NOT write
    outside a write session (ABAC condition on its standing Storage Blob Data
    Contributor; R4). tfstate = envs/dev (APPLY's pipeline); tfstate-bootstrap
    = envs/bootstrap and this root (backend.tf of each).
  EOT
  type        = list(string)
  default     = ["tfstate", "tfstate-bootstrap"]

  validation {
    condition     = contains(var.terraform_state_containers, "tfstate") && contains(var.terraform_state_containers, "tfstate-bootstrap")
    error_message = "terraform_state_containers must keep tfstate and tfstate-bootstrap (R4)."
  }
}
