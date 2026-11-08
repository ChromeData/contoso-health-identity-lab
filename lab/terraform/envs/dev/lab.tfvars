# =============================================================================
# envs/dev :: lab.tfvars  (COMMITTED - policy knobs only, no tenant identifiers)
# -----------------------------------------------------------------------------
# Everything a reviewer should see change in a PR lives here: staging flags and
# Conditional Access states. Tenant-specific identifiers (ids, domain) come
# from terraform.tfvars locally or TF_* GitHub variables in CI; the operator IP
# and alert email come from the TF_OPERATOR_IP_RANGES / TF_ALERT_EMAIL repo
# secrets (masked in public logs).
# Both workflows pass -var-file=lab.tfvars.
# =============================================================================

# Free tier first: premium/governance false. When the E5 + Governance trials
# start, flip both in one PR (README.md, Staging flags).
enable_premium    = true
enable_governance = true

# Access reviews per ADR 0012 tier (Governance tier), one flag per tier:
#   _privileged  T1 quarterly, default deny: PIM-governed groups (eligible +
#                active) and Global Administrator eligibility;
#   _requestable T2 half-yearly, only on requestable packages that outlive
#                180 days or allow extension;
#   _inactive    stale-account review (App-Okta-Federation-Users).
# Birthright clinical (T3) is never reviewed by a person. enable_access_reviews
# is the all-three shorthand - keep it false and flip the tiers one PR each.
# Needs a fallback reviewer group id (TF_ACCESS_REVIEW_FALLBACK_GROUP_OBJECT_ID
# or the entitlement approver group). A POLICY review switched back off needs
# the portal. The bodies are created by post-apply/New-AccessReviewDefinitions.ps1.
# ON since 2026-11-05 (all three tiers, capture-log E110):
#   _requestable: both T2 packages (ICU - Float Access, Pharmacy) expire after
#                 180 days with no extension, so ADR 0012's certification for
#                 them is the expiry + manager re-approval and NO campaign is
#                 rendered (the plan shows no policy change). The flag makes
#                 any later T2 package that outlives 180 days or allows
#                 extension get its half-yearly review without another PR.
#   _inactive:    the stale-account review of App-Okta-Federation-Users (the
#                 acquired clinic's staff): members with no sign-in for 90 days,
#                 quarterly, the group owners review (fallback group if none),
#                 unanswered = removed. Output-only here; the operator creates
#                 the series (Invoke-PostApply.ps1 -Only access-reviews, which
#                 needs AccessReview.ReadWrite.All - envs/operator, ADR 0024).
enable_access_reviews             = false
enable_access_reviews_privileged  = true
enable_access_reviews_requestable = true
enable_access_reviews_inactive    = true

# PIM tier groups (8 Tier 0: approval + ticket + 4h - 2h for Privileged
# Authentication Admins - eligibility 180 days; 8 Tier 1 incl.
# PIM-Tier1-IGA-Admins: 8h, eligibility 365 days, approval on Intune + IGA;
# approver groups) and PIM for Azure resources (premium tier). The Azure PIM apply must be run by a HUMAN with
# Owner / User Access Administrator on the RG (modules/pim/README.md).
# enable_helpdesk_au_scoping: AU-Workforce-Standard + help-desk roles scoped
# to it (needs enable_pim_tiers). enable_global_admin_pim_policy: the GA
# role's own PIM policy, written by post-apply/Set-DirectoryRolePimPolicies.ps1.
enable_pim_tiers               = true
enable_pim_azure_resources     = false
enable_helpdesk_au_scoping     = true
enable_global_admin_pim_policy = true

# AWS admin without root (ADR 0025): PIM-AWS-Lab-Admins, eligible-only, 2-hour
# activation (MFA + justification, mailed to the security mailbox), assigned to
# the AWS IAM Identity Center app so SCIM copies only ACTIVE members to AWS,
# where lab/terraform/aws gives them the LabAdministrator permission set.
enable_pim_aws_admin = true

# Read-only presenter access: PIM-Demo-Readers actively holds Global Reader +
# Security Reader; its membership is eligible-only (8-hour MFA + justification
# activation, NO approval, every activation mailed to the security mailbox,
# eligibility 365 days). Reviewed quarterly, kept out of the CA002 / CA020
# scope. Azure Reader / Microsoft Sentinel Reader / Log Analytics Reader come
# from envs/bootstrap (human-applied). Eligibility: adm-presenter, post-apply.
enable_pim_demo_readers = true

# VIPs in the restricted management AU RMAU-VIP (post-apply/
# New-RestrictedAdminUnit.ps1), kept out of the help desk's AU by HR
# employee id: 300001 Helen Carter (Chief Nursing Officer), 400100 Joan
# Ferris (IT Director). Only the rendered AU rule changes; the Graph PATCH
# that applies it is the tenant-time step (done 2026-11-05).
helpdesk_au_excluded_employee_ids = ["300001", "400100"]

# Tier-0 PIM activation step-up on auth context c1 (CA021). The plan refuses
# the context unless CA021 is DECLARED "enabled" (ca_policy_states) AND
# ca021_enforced_in_tenant = true. Terraform cannot see whether
# post-apply/Set-AuthContextPolicies.ps1 has run, and `terraform apply` writes
# the Tier-0 PIM policies before any post-apply step - so this is three
# separate changes: (1) CA021 = "enabled", apply, run the script; (2) once it
# reports CA021 enabled in the tenant, ca021_enforced_in_tenant = true;
# (3) the PIM value. An existing Tier-0 policy switches in TWO applies:
# switchover_step1 = true first, then "c1".
ca021_enforced_in_tenant                = false
pim_tier0_activation_auth_context_id    = ""
pim_tier0_auth_context_switchover_step1 = false

# B2B guest governance - Affiliated Physicians package (governance tier).
# Then post-apply/New-B2BConnectedOrganization.ps1.
enable_b2b_governance = false

# ADR 0029 (PR #257): Logic App that adminRemoves birthright packages for HR
# leavers (the LCW built-in task skips automatic-policy assignments). Plan:
# the Logic App deployment + 1 catalog role assignment. Owner approves the apply.
enable_lcw_leaver_extension = true

# Risk-based Conditional Access - CA006 (user risk High -> MFA + secure
# password change) and CA007 (sign-in risk High -> block). Entra ID P2: flip
# only after the E5 licences are ASSIGNED, and set the Microsoft-managed
# risk-remediation policy to report-only/off by hand first, so CA006 is the
# single user-risk policy while evidence is captured.
enable_identity_protection_ca = true

# CA008 phishing-resistant authentication for the workforce (report-only,
# all users = measures the registration gap) + CA008 pilot group + the
# All-Workforce passkey rollout group. Enforce in pilot scope first
# (ca008_scope = "pilot"); all-users enforcement needs
# ca008_allow_all_users_enforcement = true as a separate, reviewed line.
enable_phishing_resistant_all_users = false
# The rollout above needs the ADMIN key-model allow-list (AAGUIDs of the
# issued security keys, not tenant identifiers) so admins cannot satisfy
# CA002 / CA021 / CA022 with a synced passkey - or this explicit risk acceptance.
admin_fido2_allowed_aaguids      = []
accept_admin_synced_passkey_risk = false

# Conditional Access additions, each report-only while on (ca_policy_states):
#   CA009 register security info: one-time TAP or phishing-resistant;
#   CA010 block device code flow - before ENFORCING it, stop using
#         `az login --use-device-code` / -UseDeviceCode (or use the
#         CA010-Exclusion group through the exception process);
#   CA020 admin portals: sign-in every 4 h for the Tier-0/1 roles + PIM groups;
#   CA021 PIM activation step-up (auth context c1), written by
#         post-apply/Set-AuthContextPolicies.ps1;
#   CA023 protected actions step-up (auth context c2: CA policy and
#         named-location changes), same script; binding c2 to the protected
#         actions is a tenant-time step, only once CA023 is enforced;
#   CA060 shared clinical workstations (ADR 0014; needs
#         enable_phishing_resistant_all_users).
enable_registration_ca        = true
enable_device_code_block      = true
enable_admin_session_controls = true
enable_pim_auth_context       = true
enable_protected_actions_ca   = false
enable_shared_clinical_ca     = false

# SSO + provisioning as code: AWS IAM Identity Center SAML + Clinical Portal
# OIDC (premium; needs envs/bootstrap enable_app_management_roles first).
# SCIM is staged after the AWS identity-source switch: the job is created
# STOPPED, and aws_scim_job_enabled starts it in its own PR.
# enable_pam_oidc_app adds guacamole-psm (Entra sign-in for the PSM stand-in).
# clinical_portal_preauthorize_azure_cli: E25 token demo only; off again after.
# enable_servicenow_sso adds the ServiceNow PDI SAML app (its instance URL
# goes in terraform.tfvars / TF_VAR_, never here).
# enable_servicenow_provisioning adds the ServiceNow provisioning app (gallery,
# hidden, same group); its credential was written by the LOCAL seeding apply
# (modules/apps/README.md "ServiceNow provisioning"). The job was created
# stopped and is started here after Test Connection, provision-on-demand and a
# real sign-in passed (capture-log E82, E83), as aws_scim_job_enabled was.
# enable_okta_federation adds okta-clinic-idp, Entra as the IdP for the acquired
# clinic's Okta org (runbook Phase 1, ADR 0022; the org host goes in
# terraform.tfvars / TF_VAR_, never here). The Okta side is the separate,
# human-applied root lab/terraform/okta.
# enable_clinic_results_app adds Clinic Lab Results, the first app moved OFF the
# clinic's Okta (lab/okta-migration wave 1): public client, PKCE, no secret,
# ONE assignment App-ClinicResults-Users, and CA061 (MFA + sign-in every 8 h).
enable_sso_apps = true
# Signing certificates must fit the tenant's 180-day key-credential policy
# (Set-AppGovernancePolicy.ps1). Rotation = a new date here, then the IdP
# metadata re-uploaded on the AWS / ServiceNow side (README, rotation).
saml_signing_cert_end_date             = "2027-04-20T00:00:00Z"
servicenow_saml_signing_cert_end_date  = "2027-04-20T00:00:00Z"
enable_scim_provisioning               = true
aws_scim_job_enabled                   = true
enable_pam_oidc_app                    = false
clinical_portal_preauthorize_azure_cli = false
enable_servicenow_sso                  = true
enable_servicenow_provisioning         = true
servicenow_provisioning_job_enabled    = true
enable_okta_federation                 = true
enable_clinic_results_app              = true

# Non-human identity governance: App-Consent-Reviewers group (premium) for the
# admin consent workflow; uami-agent-runtime for Entra Agent ID. The tenant
# policies are post-apply scripts (Set-AppGovernancePolicy.ps1,
# Set-ConsentPolicy.ps1, New-AgentIdentity.ps1).
enable_nhi_governance = true
enable_agent_identity = false

# ITDR: the eleven identity-attack rules + vault / DC01 telemetry. Starts no
# trial - turn on BEFORE enable_sentinel so VaultCheckout_CL and the AuditLogs
# tables have data. verify: per Microsoft Learn, DC01 Security events reach
# SecurityEvent (not Event) only once Sentinel + its "Windows Security Events
# via AMA" connector are on, so the four SecurityEvent rules stay in
# itdr_exclude_rules (below, in this file) until DC01 rows arrive.
# Containment (approval-gated revoke + confirm compromised + disable) needs
# Sentinel and the deployed playbook (TF_CONTAINMENT_PLAYBOOK_ID);
# containment_on_alert_added adds the Defender-portal "alert added" trigger.
# ON since 2026-11-05 (E40/E41): pb-identity-contain is deployed, its Teams
# connection is authorized as svc-soc-automation, and the drill ran in the
# tenant (lab/evidence/itdr/20261105T102000Z). The rule only ASKS: every High
# ITDR incident posts an approval card; no answer in 4 h means no action.
enable_itdr_detections     = true
enable_itdr_containment    = true
containment_on_alert_added = false

# Second-wave ITDR rules (device code, risky security-info registration, DC01
# logon outside the operator allowlist, vault anomaly, SoD granted, Tier-0
# PIM activation without the auth context). Needs enable_itdr_detections.
# vault_feed_v2_columns goes on in the SAME PR that runs
# ingest-vault-audit.sh --signals all (else every Tier-0 check-out alerts).
# operator_ips_expires_on = ADR 0013's review date: the operator_ips
# watchlist rows (from operator_ip_ranges, enable_dc only) stop counting
# after it, and the plan warns. A date is a policy knob, not a tenant id.
enable_itdr_detections_v2 = true
vault_feed_v2_columns     = false
operator_ips_expires_on   = "2027-01-20"

# Third-set ITDR rules (2026-11-06, ported from Sentinel-Privileged-Access):
# a dormant admin account signing in again, and bulk Key Vault secret reads.
# Both Sentinel only (14-day look-back); the Key Vault rule never contains.
# Off until its own one-line PR turns it on: Sentinel checks each new rule's
# query at creation and one refusal fails the whole apply, so the flip ships
# alone. Both queries already ran read-only on loga-idlab (2026-11-06) and
# compiled against its real tables.
enable_itdr_detections_v3 = false

# ITDR rules held back while their data does not exist yet: Sentinel rejects
# a rule whose table has never received data, and the preview rule is not
# trusted until a real activation. Rule keys are not tenant identifiers, so
# the list lives HERE, where CI reads it and a PR shows each change
# (terraform.tfvars is never in CI: a key set only there is deployed by the
# next CI apply). Drop a key in its own PR once its data has arrived:
#   identity_risk                        RiskyUsers / UserRiskEvents rows
#                                        (envs/bootstrap enable_identity_protection_logs)
#   tier0_logon_without_checkout,        DC01 SecurityEvent rows (verify:
#   ad_privileged_group_change,          Sentinel + "Windows Security Events
#   kerberoast_rc4_service_ticket,       via AMA" connector on)
#   dcsync_replication_request,
#   dc_logon_outside_operator_allowlist
#   vault_privileged_access_anomaly      vault_feed_v2_columns + ingest-vault-audit.sh --signals all
#   pim_activation_without_auth_context  PREVIEW: the first real Tier-0 activation
#                                        confirms the activity strings
itdr_exclude_rules = [
  "sod_violation_granted", # v2: Sentinel answers 400 "Invalid data model" on create (2026-10-29) - held back until the rule body is fixed
  "identity_risk",
  "dc_logon_outside_operator_allowlist",
  "vault_privileged_access_anomaly",
  "pim_activation_without_auth_context",
]

# Defender for Identity (ADR 0023): the native AD-attack detector. Off because
# it needs a sensor on DC01 and a Defender licence (free 90-day trial), both
# human steps (lab/docs/runbooks/deploy-defender-for-identity-dc01.md); the flag
# only adds the Defender XDR connector that lands MDI alerts in this workspace,
# and it needs enable_sentinel. The four SecurityEvent KQL rules are MDI's
# portable twins; tier0-logon-without-checkout and dc-logon-outside-operator-
# allowlist stay custom (correlations MDI cannot make).
enable_defender_for_identity = false

# WORM evidence store (Azure storage cost only). Apply BEFORE Day 0 of the
# trial window; it starts Unlocked - locking is a separate, deliberate PR.
enable_evidence_store = true

# Domain controller VM - free tier (no Entra license needed; Azure compute cost).
enable_dc = true

# Windows 11 Entra-joined + Intune-enrolled VM - the CA005 "compliant device".
# Azure compute cost. Flip only AFTER enable_premium is applied AND the human
# prereqs in lab/scripts/intune/README.md are done: MDM user scope + E5 licence
# (Intune enrollment happens during the join, at apply time) and a local
# re-apply of envs/bootstrap (so CI may grant VM Administrator Login). Then run
# lab/scripts/intune/New-IntuneComplianceBaseline.ps1.
enable_intune_vm = true

# Sentinel STARTS ITS 31-DAY TRIAL - flip only after Entra logs have flowed for
# a few hours (README.md, Staging flags).
# After the trial: enable_sentinel = false, enable_la_alerts = true.
enable_sentinel  = true
enable_la_alerts = false

# Every policy starts report-only. Graduate ONE policy per PR - the CA004 flip
# is the on-camera pipeline demo.
ca_policy_states = {
  CA001 = "enabled"                           # require MFA, all users
  CA002 = "enabledForReportingButNotEnforced" # phishing-resistant, admins
  CA003 = "enabled"                           # block legacy auth
  CA004 = "enabled"                           # block countries
  CA005 = "enabled"                           # compliant device, admin portals (pilot group)
  CA006 = "enabled"                           # user risk high -> MFA + secure password change (P2; enable_identity_protection_ca)
  CA007 = "enabled"                           # sign-in risk high -> block (P2; enable_identity_protection_ca)
  CA008 = "enabledForReportingButNotEnforced" # phishing-resistant, workforce (enable_phishing_resistant_all_users)
  CA009 = "enabled"                           # register security info: one-time TAP or phishing-resistant (enable_registration_ca)
  CA010 = "enabled"                           # block device code flow (enable_device_code_block) - enforcing breaks az login --use-device-code
  CA020 = "enabled"                           # admin portals: sign-in every 4 h, Tier-0/1 (enable_admin_session_controls)
  CA021 = "enabledForReportingButNotEnforced" # PIM activation step-up, auth context c1 - Graph-managed (enable_pim_auth_context)
  CA022 = "enabledForReportingButNotEnforced" # PAM session broker + admin portals, admin strength (enable_pam_oidc_app; was CA009)
  CA023 = "enabledForReportingButNotEnforced" # protected actions (CA / named-location changes), auth context c2 - Graph-managed (enable_protected_actions_ca)
  CA060 = "enabledForReportingButNotEnforced" # shared clinical workstations (enable_shared_clinical_ca)
  CA061 = "enabled"                           # Clinic Lab Results: MFA + sign-in every 8 h (enable_clinic_results_app). Enforced from the start: it replaces an Okta rule that was already enforced; report-only would weaken the app during the move
}

# CA008 scope: "all_users" while report-only (measure), "pilot" to enforce.
ca008_scope                       = "all_users"
ca008_allow_all_users_enforcement = false

blocked_countries = ["KP", "IR", "SY", "CU"]

# AD FS -> Entra migration exercise (lab/adfs/README.md, ADR 0009). Both OFF
# in this PR, so its plan is "No changes". The run order turns them on one at
# a time, each through its own reviewed PR:
#   enable_adfs_https = true   after the owner OKs AD FS on DC01 (README step 1)
#   enable_claims_viewer_app   after 11-Add-ClaimsViewerRp.ps1 and one Cloud
#                              Sync cycle, with the two group ids set below
# After 19-Remove-Adfs.ps1 only enable_adfs_https goes back to false: the
# Entra app is then the app's ONLY identity provider, so it stays on.
enable_adfs_https        = false
enable_claims_viewer_app = false
# Same 180-day key-credential limit as the AWS / ServiceNow certificates
# above: Entra's 3-year default would be refused at the first enabled apply.
claims_viewer_saml_signing_cert_end_date = "2027-04-20T00:00:00Z"
# claims_viewer_clinicians_group_object_id = "<GRP-ClaimsViewer-Clinicians object id>"
# claims_viewer_admins_group_object_id     = "<GRP-ClaimsViewer-Admins object id>"
