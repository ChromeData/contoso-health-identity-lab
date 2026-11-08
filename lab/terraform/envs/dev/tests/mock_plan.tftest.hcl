# Offline mocked plan of the whole envs/dev composition (no tenant, no state):
#   terraform init -backend=false && terraform test -var-file=lab.tfvars
# Runs:
#   1. the committed lab.tfvars (phase-1 flags) - proof that NONE of the
#      staging-flagged layers plans anything while its flag is false - and
#      its itdr_exclude_rules list holding back the rules whose tables have
#      no data yet once the ITDR flags go on (both detection paths);
#   2. every flag that predates the CA009-CA060 / PIM-tier work on, every
#      flag that work added off - the new CA policies,
#      the CA021 bodies, the GA PIM policy, the help-desk AU, the v2 ITDR rules
#      and the watchlist are all absent (a new flag can only ADD);
#   3. every flag on and nothing held back, once per detection path
#      (enable_sentinel and enable_la_alerts are mutually exclusive:
#      modules/monitoring refuses a plan with both on; ITDR containment
#      exists only on the Sentinel path);
#   4. the CA021 -> PIM ordering gate: refused while report-only, refused in
#      the same change that declares CA021 enabled (no tenant attestation),
#      allowed once ca021_enforced_in_tenant attests the tenant state;
#   5. the operator_ip_ranges /32 rule with enable_dc;
#   6. the "flag on without its prerequisite" warnings.
# Run it with HashiCorp Terraform: its mock defaults apply at apply time (the
# default override_during), so computed ids stay unknown at plan, as in a real
# first plan. OpenTofu's mocks fill them in at plan time, which once hid an
# "Invalid count argument" error in modules/keyvault.
# A failing check block fails a run, so every flags-on run supplies what the
# module checks ask for (two approvers, a review fallback group, an unexpired
# operator_ips date). Child-module preconditions cannot be expect_failures
# targets from here; their gates are covered by the module tests, and the
# root copies (variable validations) are tested below.

# What CI passes through TF_VAR_* (terraform-plan.yml): the tenant ids that
# lab.tfvars never holds. Synthetic here; from Day 1 (enable_premium in
# lab.tfvars) every run needs them. A run's own variables block overrides.
variables {
  # imports.tf: a mock provider cannot import; the real plan/apply (lab.tfvars) does.
  leaver_role_assignment_import_id = ""
  aws_scim_credentials                   = { tenant_url = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2", secret_token = "not-a-real-token-0123456789abcdef" } # the stage test turns SCIM on; the creating run reads the real values from Key Vault
  aws_scim_template_id                   = "aWSSingleSignon"                                                                                                             # synthetic: enable_scim_provisioning precondition (lab.tfvars stage)
  okta_org_domain                        = "integrator-0000000.okta.com"                                                                                                 # synthetic org host: enable_okta_federation precondition (lab.tfvars stage)
  servicenow_instance_url                = "https://dev00000.service-now.com"                                                                                            # synthetic PDI: enable_servicenow_sso precondition (lab.tfvars stage)
  servicenow_provisioning_credentials    = { user_name = "svc-entra-provisioning", password = "dummy-password-for-mocked-tests" }                                        # lab.tfvars turns ServiceNow provisioning on; the creating run reads the real values from Key Vault
  app_owner_object_ids                   = ["cccccccc-cccc-cccc-cccc-cccccccccccc", "c0c0c0c0-0000-4000-8000-00000000000c"]                                              # the apps module's human-owner check
  onmicrosoft_domain                     = "contosohealthlab.onmicrosoft.com"
  pim_approver_object_ids                = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
  iac_principal_ids                      = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
  access_review_fallback_group_object_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee" # Day 2: TF_ACCESS_REVIEW_FALLBACK_GROUP_OBJECT_ID
  pim_alert_mailbox                      = "security@contosohealthlab.onmicrosoft.com"
}

mock_provider "azurerm" {
  mock_resource "azurerm_key_vault" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.KeyVault/vaults/kv-idlab" }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/virtualNetworks/vnet-identity-lab" }
  }
  mock_resource "azurerm_subnet" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/virtualNetworks/vnet-identity-lab/subnets/snet-private-endpoints" }
  }
  mock_resource "azurerm_private_dns_zone" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net" }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = { id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.OperationalInsights/workspaces/loga-idlab" }
  }
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "11111111-1111-1111-1111-111111111111"
      subscription_id = "22222222-2222-2222-2222-222222222222"
      client_id       = "33333333-3333-3333-3333-333333333333"
      object_id       = "44444444-4444-4444-4444-444444444444"
    }
  }
}
mock_provider "azuread" {
  mock_data "azuread_client_config" {
    defaults = {
      tenant_id = "11111111-1111-1111-1111-111111111111"
      client_id = "33333333-3333-3333-3333-333333333333"
      object_id = "44444444-4444-4444-4444-444444444444"
    }
  }
  # modules/apps refuses a template whose name is not AWS IAM Identity Center
  # (postcondition), so the mock must carry the real gallery name.
  mock_data "azuread_application_template" {
    defaults = {
      template_id  = "21ed01d2-ec13-4e9e-86c1-cd546719ebc4"
      display_name = "AWS IAM Identity Center (successor to AWS Single Sign-On)"
    }
  }
}
mock_provider "random" {}

run "plan_lab_tfvars" {
  command = plan

  # Trials must not start early. lab.tfvars is at stage P2 (evidence-capture
  # plan): the evidence store and the ITDR telemetry are on, every trial-bearing
  # or premium layer is still absent. Each later flip updates this run.
  assert {
    condition     = length(output.itdr_rule_keys) > 0 && alltrue([for k in var.itdr_exclude_rules : !contains(output.itdr_rule_keys, k)]) && output.vault_ingestion != null && output.vault_ingest_signals == "checkout" && output.dc_vm_name == "vm-dc01"
    error_message = "P2 + DC: enable_itdr_detections is on: VaultCheckout_CL ingestion (--signals checkout) and only the rules whose tables have data (every lab.tfvars hold-back absent); enable_dc plans DC01 (its security DCR id is computed, so only the VM name is asserted here)"
  }
  assert {
    condition     = length(output.itdr_sentinel_only_rule_keys) > 0
    error_message = "ITDR v2 (enable_itdr_detections_v2): the Sentinel-only second-wave rules and the operator_ips watchlist render with lab.tfvars"
  }
  # Day 13 (E40/E41): containment on. Its automation rule appears once
  # TF_CONTAINMENT_PLAYBOOK_ID is set (plan_lab_itdr_hold_back plans it with
  # this hold-back list); the "alert added" trigger stays off until E18/E41
  # show Defender correlating ITDR alerts into older incidents.
  assert {
    condition     = var.enable_itdr_containment && !var.containment_on_alert_added
    error_message = "Day 13: lab.tfvars turns ITDR containment on (approval-gated, E40/E41); containment_on_alert_added stays off"
  }
  assert {
    condition     = output.evidence_storage_account_name != null && output.agent_runtime_uami_principal_id == null
    error_message = "P2: the evidence store exists (enable_evidence_store); the agent runtime identity must not while enable_agent_identity = false"
  }
  # Day 1 (E12): enable_premium + the report-only CA additions. Every policy
  # is report-only (ca_policy_states), the apps and governance stay off.
  assert {
    condition     = nonsensitive(output.apps_nhi_inventory) != null && nonsensitive(output.apps_nhi_inventory).servicenow != null && nonsensitive(output.apps_nhi_inventory).okta_clinic_idp != null && output.guacamole_psm_client_id == null && output.ca_policy_display_names != null
    error_message = "Day 1 + apps: CA001-CA010 and CA020 exist (enable_premium + the CA flags); enable_sso_apps plans the AWS IAM Identity Center and Clinical Portal apps; the PAM app (enable_pam_oidc_app) is still off"
  }
  assert {
    condition     = nonsensitive(output.apps_nhi_inventory).clinic_lab_results != null && output.ca_policy_display_names["CA061"] == "CA061 - Require MFA and sign-in every 8h for Clinic Lab Results"
    error_message = "lab.tfvars: enable_clinic_results_app reaches BOTH modules - modules/apps plans Clinic Lab Results (its NHI row is set) and modules/conditional-access plans CA061 for it (Okta -> Entra wave 1)"
  }
  assert {
    condition     = nonsensitive(output.apps_nhi_inventory).servicenow_provisioning != null && output.servicenow_provisioning_job_enabled == true
    error_message = "lab.tfvars: enable_servicenow_provisioning plans the ServiceNow provisioning app and servicenow_provisioning_job_enabled starts its cycle (started after Test Connection + on-demand + sign-in, capture-log E82/E83)"
  }
  assert {
    condition     = alltrue([for k, v in var.ca_policy_states : v == (contains(["CA003", "CA004", "CA020", "CA010", "CA001", "CA009", "CA006", "CA007", "CA005", "CA061"], k) ? "enabled" : "enabledForReportingButNotEnforced")])
    error_message = "every CA policy in lab.tfvars is report-only except the graduated list; one graduation per PR, with its checklist"
  }
  # Day 2 (E16/E16c/E17c): PIM tiers, the Global Administrator policy, the
  # help-desk AU and the CA021 auth-context body are rendered; CA021 stays
  # report-only so PIM must not yet demand c1. Governance (packages, reviews)
  # waits for Day 3.
  # Day 3 (E19): governance on - packages and their assignment model render;
  # access reviews wait for Day 8 (enable_access_reviews_*).
  assert {
    condition = alltrue([
      output.pim_auth_context_requests != null,
      output.ca_pim_activation_auth_context_ready == false,
      output.pim_workforce_au_membership_body != null,
      try(length(output.access_review_definitions), 0) > 0,
      output.package_assignment_model != null,
    ])
    error_message = "Day 3: CA021 body, help-desk AU rule and the access-package assignment model exist (enable_governance); PIM still asks for MFA (CA021 report-only); the privileged (T1) access reviews render with enable_access_reviews_privileged"
  }
  # 2026-11-05 (E110): every review tier is on. The inactive-user review of the
  # clinic's Okta-federated staff renders for the post-apply script; the T2
  # flag renders nothing for the two 180-day, no-extension packages (their
  # expiry + re-approval is the certification, ADR 0012); no flag ever puts a
  # review on a birthright (T3) package.
  assert {
    condition = alltrue([
      var.enable_access_reviews_privileged && var.enable_access_reviews_requestable && var.enable_access_reviews_inactive,
      contains(keys(output.access_review_definitions), "inactive:App-Okta-Federation-Users"),
    ])
    error_message = "lab.tfvars turns all three review tiers on: the inactive-user review of App-Okta-Federation-Users must render (access_review_definitions)"
  }
  assert {
    condition     = output.pim_privileged_role_template_ids != null && nonsensitive(output.directory_role_pim_policies) != null
    error_message = "Day 1: modules/pim renders the tier map and the Global Administrator policy body with enable_premium; they are APPLIED only on Day 2 (enable_pim_tiers, Set-DirectoryRolePimPolicies.ps1)"
  }
  # ADR 0025: AWS admin is a PIM-for-Groups activation, not the root user.
  assert {
    condition     = output.aws_admin_activation_policy != null && output.aws_admin_activation_policy.maximum_duration == "PT2H" && output.aws_admin_activation_policy.mfa && output.aws_admin_activation_policy.in_ca_admin_scope == false
    error_message = "enable_pim_aws_admin (lab.tfvars): PIM-AWS-Lab-Admins with a 2-hour MFA activation, kept out of the CA002/CA020 group scope"
  }
  # Read-only presenter access: PIM-Demo-Readers, eligible-only, 8-hour MFA +
  # justification activation without approval, reviewed quarterly, outside
  # the CA002 / CA020 group scope and CA020's role list.
  assert {
    condition = alltrue([
      output.pim_demo_readers_activation_policy != null,
      output.pim_demo_readers_activation_policy.maximum_duration == "PT8H",
      output.pim_demo_readers_activation_policy.mfa,
      output.pim_demo_readers_activation_policy.approval == false,
      output.pim_demo_readers_activation_policy.in_ca_admin_scope == false,
      output.pim_demo_readers_group_mail_nickname == "pim-demo-readers",
      toset(values(output.pim_demo_readers_activation_policy.directory_roles)) == toset(["f2ef992c-3afb-46b9-b7cf-a126ee74c451", "5d6b6bb7-de71-4623-b4af-96380a352509"]),
    ])
    error_message = "enable_pim_demo_readers (lab.tfvars): PIM-Demo-Readers holds exactly Global Reader + Security Reader, 8-hour MFA activation, no approval"
  }
  assert {
    condition = alltrue([
      !contains(keys(module.pim[0].privileged_review_targets), "PIM-Demo-Readers"),
      !contains(output.pim_privileged_role_template_ids["tier0"], "f2ef992c-3afb-46b9-b7cf-a126ee74c451"),
      !contains(output.pim_privileged_role_template_ids["tier1"], "f2ef992c-3afb-46b9-b7cf-a126ee74c451"),
      !contains(output.pim_privileged_role_template_ids["tier0"], "5d6b6bb7-de71-4623-b4af-96380a352509"),
      !contains(output.pim_privileged_role_template_ids["tier1"], "5d6b6bb7-de71-4623-b4af-96380a352509"),
      contains(keys(output.access_review_definitions), "privileged:PIM-Demo-Readers"),
    ])
    error_message = "PIM-Demo-Readers must not reach Conditional Access (not in admin_scope_group_object_ids = privileged_review_targets, its roles not in CA020's list) but must be in the quarterly privileged review"
  }
}

# The committed lab.tfvars hold-back list, with the ITDR flags flipped on (as
# the first ITDR PR would): CI reads lab.tfvars, so the rules whose tables
# cannot have data yet - DC01 SecurityEvent, the risk tables, the extended
# vault feed - and the PREVIEW rule stay out of the plan, on both paths.
run "plan_lab_leaver_extension" {
  command = plan
  assert {
    condition     = var.enable_lcw_leaver_extension && output.leaver_extension_logic_app_name == "la-lcw-leaver-remove-birthright"
    error_message = "ADR 0029: lab.tfvars plans the leaver Logic App (enable_lcw_leaver_extension)"
  }
}

run "plan_leaver_extension_off_by_default" {
  command = plan
  variables {
    enable_lcw_leaver_extension = false
  }
  assert {
    condition     = output.leaver_extension_logic_app_name == null
    error_message = "the leaver Logic App exists only when enable_lcw_leaver_extension is on"
  }
}

run "plan_lab_itdr_hold_back" {
  command = plan
  variables {
    onmicrosoft_domain        = "contosohealthlab.onmicrosoft.com"
    pim_approver_object_ids   = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    iac_principal_ids         = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    operator_ips_expires_on   = "2099-12-31"
    # Containment still has eligible rules with the list in place (else
    # modules/monitoring's precondition fails the plan).
    enable_itdr_containment = true
    containment_playbook_id = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
  }

  assert {
    condition = alltrue([for k in [
      "ad_privileged_group_change", "kerberoast_rc4_service_ticket",
      "dcsync_replication_request",
    ] : !contains(var.itdr_exclude_rules, k) && contains(output.itdr_rule_keys, k)]) && alltrue([for k in ["dc_logon_outside_operator_allowlist", "tier0_logon_without_checkout"] : contains(var.itdr_exclude_rules, k) && !contains(output.itdr_rule_keys, k)])
    error_message = "ITDR release v1: DC01 SecurityEvent rows exist, so the three core SecurityEvent rules deploy; dc_logon_outside_operator_allowlist (v2, operator watchlist) stays held back until enable_itdr_detections_v2, and tier0_logon_without_checkout is retired from Sentinel (its source is Vault check-outs; ADR 0036)"
  }
  assert {
    condition     = !contains(output.itdr_rule_keys, "pim_activation_without_auth_context") && !contains(output.itdr_rule_keys, "vault_privileged_access_anomaly") && !contains(output.itdr_rule_keys, "identity_risk")
    error_message = "the PREVIEW rule, the vault anomaly rule (extended feed) and identity_risk (risk tables) must be held back by lab.tfvars"
  }
  assert {
    condition     = length(output.itdr_rule_keys) == 17 - length(var.itdr_exclude_rules) && length(var.itdr_exclude_rules) == 6
    error_message = "lab.tfvars holds back exactly six of the seventeen ITDR rules (risk tables, v2 watchlist, extended vault feed, PREVIEW, the sod_violation_granted body, the Vault-check-out DC logon rule retired by ADR 0036); the other eleven deploy"
  }
}

run "plan_lab_itdr_hold_back_la_alerts" {
  command = plan
  variables {
    enable_itdr_containment   = false # pinned: lab.tfvars turns containment on (Day 13); the post-trial Log Analytics path has none (automation rules are Sentinel-only)
    enable_sentinel           = false # pinned: lab.tfvars turns Sentinel on from Day 2; this run is the post-trial Log Analytics path
    onmicrosoft_domain        = "contosohealthlab.onmicrosoft.com"
    pim_approver_object_ids   = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    iac_principal_ids         = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    enable_la_alerts          = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
  }

  assert {
    condition     = length(output.itdr_rule_keys) == 11 && !contains(output.itdr_rule_keys, "tier0_logon_without_checkout") && !contains(output.itdr_rule_keys, "dc_logon_outside_operator_allowlist")
    error_message = "the lab.tfvars hold-back list applies on the Log Analytics path too"
  }
}

# Every flag that existed before the CA009-CA060 / PIM / ITDR-v2 wave ON, every
# new flag OFF: the new layers plan nothing.
run "plan_legacy_flags_on_new_flags_off" {
  command = plan
  variables {
    enable_premium                       = true
    enable_governance                    = true
    enable_access_reviews                = true
    enable_dc                            = true
    enable_intune_vm                     = true
    enable_sentinel                      = true
    enable_la_alerts                     = false
    operator_ip_ranges                   = ["203.0.113.7/32"]
    onmicrosoft_domain                   = "contosohealthlab.onmicrosoft.com"
    pim_approver_object_ids              = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    entitlement_approver_group_object_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    enable_identity_protection_ca       = true
    enable_phishing_resistant_all_users = true
    enable_sso_apps                     = true
    enable_scim_provisioning            = true
    enable_pam_oidc_app                 = true
    enable_pim_tiers                    = true
    enable_pim_azure_resources          = true
    enable_b2b_governance               = true
    enable_nhi_governance               = true
    enable_agent_identity               = true
    enable_itdr_detections              = true
    enable_itdr_containment             = true
    enable_evidence_store               = true
    # End state: every table has data, nothing held back (lab.tfvars holds
    # back eight rules until then - see plan_lab_itdr_hold_back).
    itdr_exclude_rules = []

    # The new flags, explicitly off (lab.tfvars says the same).
    enable_registration_ca                  = false
    enable_servicenow_sso                   = false
    enable_servicenow_provisioning          = false
    enable_okta_federation                  = false
    enable_clinic_results_app               = false
    enable_device_code_block                = false
    enable_admin_session_controls           = false
    enable_pim_auth_context                 = false
    enable_shared_clinical_ca               = false
    enable_helpdesk_au_scoping              = false
    enable_global_admin_pim_policy          = false
    enable_pim_aws_admin                    = false
    enable_pim_demo_readers                 = false
    enable_itdr_detections_v2               = false
    vault_feed_v2_columns                   = false
    pim_tier0_activation_auth_context_id    = ""
    pim_tier0_auth_context_switchover_step1 = false

    # CA022 = the PAM-session policy (enable_pam_oidc_app; was CA009).
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA006 = "enabledForReportingButNotEnforced"
      CA007 = "enabledForReportingButNotEnforced"
      CA008 = "enabledForReportingButNotEnforced"
      CA022 = "enabledForReportingButNotEnforced"
    }
    admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    iac_principal_ids           = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    app_owner_object_ids        = ["cccccccc-cccc-cccc-cccc-cccccccccccc", "c0c0c0c0-0000-4000-8000-00000000000c"]
    aws_scim_template_id        = "placeholderTemplate"
    containment_playbook_id     = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
  }

  assert {
    condition     = nonsensitive(output.apps_nhi_inventory).clinic_lab_results == null && output.ca_policy_display_names["CA061"] == null
    error_message = "enable_clinic_results_app = false: neither Clinic Lab Results nor CA061 may be planned"
  }
  assert {
    condition     = alltrue([for k in ["CA009", "CA010", "CA020", "CA021", "CA060"] : output.ca_policy_display_names[k] == null])
    error_message = "CA009, CA010, CA020, CA021 and CA060 must not be planned while their flags are off"
  }
  assert {
    condition     = alltrue([for k in ["CA001", "CA002", "CA003", "CA004", "CA005", "CA006", "CA007", "CA008", "CA022"] : output.ca_policy_display_names[k] != null])
    error_message = "CA001..CA008 and CA022 (enable_pam_oidc_app) must still be planned"
  }
  assert {
    condition     = output.pim_auth_context_requests == null && output.ca_pim_activation_auth_context_ready == false && output.registration_authentication_strength_policy_id == null
    error_message = "no CA021 body, no auth-context readiness and no registration strength while their flags are off"
  }
  assert {
    condition     = length(nonsensitive(output.directory_role_pim_policies)) == 0 && output.pim_workforce_au_object_id == null && output.pim_workforce_au_membership_body == null
    error_message = "no Global Administrator PIM policy and no help-desk AU while their flags are off"
  }
  assert {
    condition     = alltrue([for p in values(output.pim_tier_activation_policies) : p.scope == "tenant" && p.auth != "auth context c1"])
    error_message = "with the new PIM flags off every tier group is tenant-scoped and Tier 0 keeps MFA"
  }
  assert {
    condition     = length(output.itdr_rule_keys) == 11 && output.itdr_sentinel_only_rule_keys == [] && output.operator_ips_watchlist_id == null && output.vault_ingest_signals == "checkout"
    error_message = "exactly the eleven v1 ITDR rules, no v2 rule, no operator_ips watchlist and the 11-column vault feed while the v2 flags are off"
  }
  assert {
    # 16 tier groups + Privileged-IAM-Admins + the Azure PIM group, plus the
    # inactive-user review; no Global Administrator review (GA policy off).
    condition     = length(output.access_review_definitions) == 19 && !contains(keys(output.access_review_definitions), "privileged:Global Administrator (eligible)")
    error_message = "expected 18 privileged group reviews + 1 inactive-user review and no GA eligibility review"
  }
  assert {
    condition     = output.apps_nhi_inventory.servicenow == null && output.apps_nhi_inventory.servicenow_provisioning == null && output.servicenow_provisioning_job_id == null
    error_message = "neither the ServiceNow SAML app nor the provisioning app may be planned while their flags are off"
  }
  assert {
    condition     = output.aws_admin_activation_policy == null
    error_message = "no AWS admin PIM group (and no second AWS app principal) while enable_pim_aws_admin is off"
  }
  assert {
    condition     = output.pim_demo_readers_group_object_id == null && output.pim_demo_readers_activation_policy == null && !contains(keys(output.access_review_definitions), "privileged:PIM-Demo-Readers")
    error_message = "no read-only presenter PIM group (and no review of it) while enable_pim_demo_readers is off"
  }
  assert {
    condition     = output.apps_nhi_inventory.okta_clinic_idp == null && output.okta_idp_client_id == null
    error_message = "okta-clinic-idp must not be planned while enable_okta_federation is off"
  }
}

run "plan_all_flags_on_sentinel" {
  command = plan
  variables {
    enable_premium                       = true
    enable_governance                    = true
    enable_access_reviews_privileged     = true
    enable_access_reviews_requestable    = true
    enable_access_reviews_inactive       = true
    enable_dc                            = true
    enable_intune_vm                     = true
    enable_sentinel                      = true
    enable_la_alerts                     = false
    operator_ip_ranges                   = ["203.0.113.7/32"]
    operator_ips_expires_on              = "2099-12-31" # synthetic: keeps the run independent of today's date
    onmicrosoft_domain                   = "contosohealthlab.onmicrosoft.com"
    pim_approver_object_ids              = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    entitlement_approver_group_object_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    pim_alert_mailbox                    = "pim-alerts@contoso.test"

    # Senior-scope extensions, all on.
    enable_identity_protection_ca       = true
    enable_phishing_resistant_all_users = true
    enable_registration_ca              = true
    enable_device_code_block            = true
    enable_admin_session_controls       = true
    enable_pim_auth_context             = true
    enable_protected_actions_ca         = true
    enable_shared_clinical_ca           = true
    enable_sso_apps                     = true
    enable_servicenow_sso               = true
    enable_servicenow_provisioning      = true
    enable_okta_federation              = true
    enable_clinic_results_app           = true
    enable_scim_provisioning            = true
    enable_pam_oidc_app                 = true
    enable_pim_tiers                    = true
    enable_helpdesk_au_scoping          = true
    enable_global_admin_pim_policy      = true
    enable_pim_azure_resources          = true
    enable_pim_aws_admin                = true
    enable_pim_demo_readers             = true
    enable_b2b_governance               = true
    enable_nhi_governance               = true
    enable_agent_identity               = true
    enable_itdr_detections              = true
    enable_itdr_detections_v2           = true
    vault_feed_v2_columns               = true
    enable_itdr_containment             = true
    enable_evidence_store               = true
    itdr_exclude_rules                  = [] # end state: every table has data
    ca010_exception_group_object_ids    = ["99999999-9999-9999-9999-999999999999"]
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA006 = "enabledForReportingButNotEnforced"
      CA007 = "enabledForReportingButNotEnforced"
      CA008 = "enabledForReportingButNotEnforced"
      CA009 = "enabledForReportingButNotEnforced"
      CA010 = "enabledForReportingButNotEnforced"
      CA020 = "enabledForReportingButNotEnforced"
      CA021 = "enabledForReportingButNotEnforced"
      CA022 = "enabledForReportingButNotEnforced"
      CA023 = "enabledForReportingButNotEnforced"
      CA060 = "enabledForReportingButNotEnforced"
      CA061 = "enabledForReportingButNotEnforced"
    }
    # The workforce passkey rollout needs the admin key-model allow-list.
    admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    iac_principal_ids           = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    app_owner_object_ids        = ["cccccccc-cccc-cccc-cccc-cccccccccccc", "c0c0c0c0-0000-4000-8000-00000000000c"]
    aws_scim_template_id        = "placeholderTemplate"
    containment_playbook_id     = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
    servicenow_instance_url     = "https://dev00000.service-now.com" # synthetic PDI
    okta_org_domain             = "integrator-1234567.okta.com"      # synthetic Integrator Free org
    # Dummy, synthetic SCIM credential: without one, modules/apps' check
    # (correctly) warns that the credential would be created empty.
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
  }

  assert {
    condition     = length(output.pim_tier_activation_policies) == 16
    error_message = "the sixteen PIM tier groups (8 Tier 0, 8 Tier 1 incl. PIM-Tier1-IGA-Admins) must be planned"
  }
  assert {
    condition     = output.pim_tier_activation_policies["PIM-Tier1-Helpdesk"].scope == "AU-Workforce-Standard" && output.pim_workforce_au_membership_body != null
    error_message = "enable_helpdesk_au_scoping must scope PIM-Tier1-Helpdesk to AU-Workforce-Standard and render the dynamic-membership body"
  }
  assert {
    # CA021 report-only: Tier 0 keeps MFA - the context is NOT handed to PIM.
    condition     = output.ca_pim_activation_auth_context_ready == false && alltrue([for p in values(output.pim_tier_activation_policies) : p.auth == "MFA"])
    error_message = "while CA021 is report-only no tier may require the auth context"
  }
  assert {
    condition     = length(nonsensitive(output.directory_role_pim_policies)) == 1
    error_message = "enable_global_admin_pim_policy must render the Global Administrator policy for Set-DirectoryRolePimPolicies.ps1"
  }
  assert {
    condition     = output.protected_actions_auth_context_requests != null && output.protected_actions_auth_context_requests.policy_key == "CA023" && output.protected_actions_auth_context_requests.auth_context_id == "c2" && output.protected_actions_auth_context_requests.policy_state == "enabledForReportingButNotEnforced"
    error_message = "enable_protected_actions_ca must render CA023 on auth context c2, report-only"
  }
  assert {
    # 20 group reviews (IAM + 16 tiers + Azure + AWS admin + demo readers),
    # GA eligibility, inactive users.
    condition     = length(output.access_review_definitions) == 22 && contains(keys(output.access_review_definitions), "privileged:Global Administrator (eligible)") && contains(keys(output.access_review_definitions), "privileged:PIM-AWS-Lab-Admins") && contains(keys(output.access_review_definitions), "privileged:PIM-Demo-Readers")
    error_message = "expected 20 privileged group reviews (incl. PIM-AWS-Lab-Admins and PIM-Demo-Readers) + the GA eligibility review + 1 inactive-user review"
  }
  assert {
    condition     = output.aws_admin_activation_policy != null && output.aws_admin_activation_policy.approval == false && output.aws_admin_activation_policy.activation_mail
    error_message = "enable_pim_aws_admin: no approval (one human admin, ADR 0025), so every activation must be mailed to pim_alert_mailbox"
  }
  assert {
    condition     = output.b2b_post_apply != null
    error_message = "the B2B connected-organization bodies must be rendered"
  }
  assert {
    condition     = alltrue([for k in ["CA006", "CA007", "CA008", "CA009", "CA010", "CA020", "CA021", "CA022", "CA060"] : output.ca_policy_display_names[k] != null])
    error_message = "CA006..CA010, CA020..CA022 and CA060 must be planned when their flags are on (CA022 rides on enable_pam_oidc_app; CA021 is rendered)"
  }
  assert {
    # (The strength id and the policy body carry ids unknown until apply.)
    condition     = output.pim_auth_context_requests.policy_match_prefix == "CA021 - " && output.pim_auth_context_requests.auth_context_id == "c1" && output.pim_auth_context_requests.policy_state == "enabledForReportingButNotEnforced"
    error_message = "CA021's Graph bodies must be rendered for Set-AuthContextPolicies.ps1, report-only, on auth context c1"
  }
  assert {
    condition     = length(output.itdr_rule_keys) == 17 && toset(output.itdr_sentinel_only_rule_keys) == toset(["security_info_registered_risky", "sod_violation_granted"]) && output.vault_ingest_signals == "all"
    error_message = "all seventeen ITDR rules (11 v1 + 6 v2) must deploy to the Sentinel path, two of them Sentinel-only, and the extended vault feed must be asked for"
  }
  assert {
    condition     = output.evidence_container_name == "evidence"
    error_message = "the WORM evidence store must be planned"
  }
  assert {
    condition     = output.apps_nhi_inventory.servicenow != null
    error_message = "enable_servicenow_sso must plan the ServiceNow SAML app (modules/apps servicenow.tf)"
  }
  assert {
    condition     = output.apps_nhi_inventory.servicenow_provisioning != null
    error_message = "enable_servicenow_provisioning must plan the ServiceNow provisioning app (modules/apps servicenow_provisioning.tf)"
  }
  assert {
    condition     = output.apps_nhi_inventory.okta_clinic_idp != null && output.okta_idp_redirect_uri == "https://integrator-1234567.okta.com/oauth2/v1/authorize/callback"
    error_message = "enable_okta_federation must plan okta-clinic-idp with the Okta callback as its one redirect URI (modules/apps okta.tf)"
  }
}

run "plan_all_flags_on_la_alerts" {
  command = plan
  variables {
    enable_itdr_containment              = false # pinned: lab.tfvars turns containment on (Day 13); Sentinel-only, so off on this path
    enable_premium                       = true
    enable_governance                    = true
    enable_access_reviews                = true # the all-three shorthand
    enable_dc                            = true
    enable_intune_vm                     = true
    enable_sentinel                      = false
    enable_la_alerts                     = true
    operator_ip_ranges                   = ["203.0.113.7/32"]
    operator_ips_expires_on              = "2099-12-31"
    onmicrosoft_domain                   = "contosohealthlab.onmicrosoft.com"
    pim_approver_object_ids              = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    entitlement_approver_group_object_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    # Senior-scope extensions on; containment stays off (Sentinel-only).
    enable_identity_protection_ca       = true
    enable_phishing_resistant_all_users = true
    enable_registration_ca              = true
    enable_device_code_block            = true
    enable_admin_session_controls       = true
    enable_pim_auth_context             = true
    enable_protected_actions_ca         = true
    enable_shared_clinical_ca           = true
    enable_sso_apps                     = true
    enable_servicenow_sso               = true
    enable_servicenow_provisioning      = true
    enable_okta_federation              = true
    enable_clinic_results_app           = true
    enable_scim_provisioning            = true
    enable_pam_oidc_app                 = true
    enable_pim_tiers                    = true
    enable_helpdesk_au_scoping          = true
    enable_global_admin_pim_policy      = true
    enable_pim_azure_resources          = true
    enable_pim_aws_admin                = true
    enable_pim_demo_readers             = true
    enable_b2b_governance               = true
    enable_nhi_governance               = true
    enable_agent_identity               = true
    enable_itdr_detections              = true
    enable_itdr_detections_v2           = true
    vault_feed_v2_columns               = true
    enable_evidence_store               = true
    itdr_exclude_rules                  = [] # end state: every table has data
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA006 = "enabledForReportingButNotEnforced"
      CA007 = "enabledForReportingButNotEnforced"
      CA008 = "enabledForReportingButNotEnforced"
      CA009 = "enabledForReportingButNotEnforced"
      CA010 = "enabledForReportingButNotEnforced"
      CA020 = "enabledForReportingButNotEnforced"
      CA021 = "enabledForReportingButNotEnforced"
      CA022 = "enabledForReportingButNotEnforced"
      CA023 = "enabledForReportingButNotEnforced"
      CA060 = "enabledForReportingButNotEnforced"
      CA061 = "enabledForReportingButNotEnforced"
    }
    # The workforce passkey rollout needs the admin key-model allow-list.
    admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    iac_principal_ids           = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    app_owner_object_ids        = ["cccccccc-cccc-cccc-cccc-cccccccccccc", "c0c0c0c0-0000-4000-8000-00000000000c"]
    aws_scim_template_id        = "placeholderTemplate"
    servicenow_instance_url     = "https://dev00000.service-now.com" # synthetic PDI
    okta_org_domain             = "integrator-1234567.okta.com"      # synthetic Integrator Free org
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
  }

  assert {
    condition     = output.containment_automation_rule_id == null
    error_message = "containment is Sentinel-only and must not exist on the Log Analytics path"
  }
  assert {
    condition     = output.operator_ips_watchlist_id == null
    error_message = "the operator_ips watchlist is a Sentinel object: none on the Log Analytics path"
  }
  assert {
    # 17 selected; the two 14-day look-back rules are listed as Sentinel-only
    # and get no Log Analytics alert (modules/monitoring skips them).
    condition     = length(output.itdr_rule_keys) == 17 && toset(output.itdr_sentinel_only_rule_keys) == toset(["security_info_registered_risky", "sod_violation_granted"])
    error_message = "all seventeen ITDR rules are selected on the Log Analytics path, and the two Sentinel-only ones must be reported as such"
  }
  assert {
    condition     = length(nonsensitive(output.directory_role_pim_policies)) == 1 && length(output.access_review_definitions) == 22
    error_message = "the PIM and review bodies do not depend on the detection path"
  }
  assert {
    condition     = output.apps_nhi_inventory.servicenow != null
    error_message = "enable_servicenow_sso must plan the ServiceNow SAML app (modules/apps servicenow.tf)"
  }
  assert {
    condition     = output.apps_nhi_inventory.servicenow_provisioning != null
    error_message = "enable_servicenow_provisioning must plan the ServiceNow provisioning app (modules/apps servicenow_provisioning.tf)"
  }
  assert {
    condition     = output.apps_nhi_inventory.okta_clinic_idp != null && output.okta_idp_redirect_uri == "https://integrator-1234567.okta.com/oauth2/v1/authorize/callback"
    error_message = "enable_okta_federation must plan okta-clinic-idp with the Okta callback as its one redirect URI (modules/apps okta.tf)"
  }
}

# ---- The CA021 -> PIM ordering gate -----------------------------------------
# PIM may require the auth context only once CA021 is ENFORCED. Report-only is
# refused at the root variable (the modules refuse it too, but child-module
# preconditions cannot be expect_failures targets from a root test).
run "pim_auth_context_refused_while_ca021_report_only" {
  command = plan
  variables {
    enable_premium = true
    # pinned: lab.tfvars turns these on from Day 1; this run's ca_policy_states is CA021-only
    enable_identity_protection_ca           = false
    enable_clinic_results_app               = false
    enable_registration_ca                  = false
    enable_device_code_block                = false
    enable_admin_session_controls           = false
    enable_pim_tiers                        = true
    enable_pim_auth_context                 = true
    pim_approver_object_ids                 = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    entitlement_approver_group_object_id    = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    onmicrosoft_domain                      = "contosohealthlab.onmicrosoft.com"
    pim_tier0_activation_auth_context_id    = "c1"
    pim_tier0_auth_context_switchover_step1 = true
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [
    var.pim_tier0_activation_auth_context_id,
    var.pim_tier0_auth_context_switchover_step1,
  ]
}

# The same-change gap: CA021 declared "enabled" in the SAME change as the PIM
# context is refused - `terraform apply` would write the Tier-0 PIM policies
# before Set-AuthContextPolicies.ps1 writes the enforced CA021. The tenant
# attestation (ca021_enforced_in_tenant) comes in a later change.
run "pim_auth_context_refused_in_the_same_change_as_ca021_enabled" {
  command = plan
  variables {
    enable_premium = true
    # pinned: lab.tfvars turns these on from Day 1; this run's ca_policy_states is CA021-only
    enable_identity_protection_ca           = false
    enable_clinic_results_app               = false
    enable_registration_ca                  = false
    enable_device_code_block                = false
    enable_admin_session_controls           = false
    enable_pim_tiers                        = true
    enable_pim_auth_context                 = true
    pim_approver_object_ids                 = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    entitlement_approver_group_object_id    = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    onmicrosoft_domain                      = "contosohealthlab.onmicrosoft.com"
    pim_tier0_activation_auth_context_id    = "c1"
    pim_tier0_auth_context_switchover_step1 = true
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabled"
    }
  }

  expect_failures = [
    var.pim_tier0_activation_auth_context_id,
    var.pim_tier0_auth_context_switchover_step1,
  ]
}

run "attestation_without_ca021_enabled_is_refused" {
  command = plan
  variables {
    # pinned: lab.tfvars turns these on from Day 1; this run's ca_policy_states is CA021-only
    enable_identity_protection_ca        = false
    enable_clinic_results_app            = false
    enable_registration_ca               = false
    enable_device_code_block             = false
    enable_admin_session_controls        = false
    enable_premium                       = true
    enable_pim_auth_context              = true
    ca021_enforced_in_tenant             = true
    entitlement_approver_group_object_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    onmicrosoft_domain                   = "contosohealthlab.onmicrosoft.com"
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabledForReportingButNotEnforced"
    }
  }

  expect_failures = [var.ca021_enforced_in_tenant]
}

run "pim_auth_context_allowed_once_ca021_enforced" {
  command = plan
  variables {
    # pinned: lab.tfvars turns these on from Day 1; this run's ca_policy_states is CA021-only
    enable_identity_protection_ca        = false
    enable_clinic_results_app            = false
    enable_registration_ca               = false
    enable_device_code_block             = false
    enable_admin_session_controls        = false
    enable_premium                       = true
    enable_pim_tiers                     = true
    enable_pim_auth_context              = true
    ca021_enforced_in_tenant             = true
    enable_global_admin_pim_policy       = true
    pim_approver_object_ids              = ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "ffffffff-ffff-ffff-ffff-ffffffffffff"]
    entitlement_approver_group_object_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    onmicrosoft_domain                   = "contosohealthlab.onmicrosoft.com"
    pim_tier0_activation_auth_context_id = "c1"
    ca_policy_states = {
      CA001 = "enabledForReportingButNotEnforced"
      CA002 = "enabledForReportingButNotEnforced"
      CA003 = "enabledForReportingButNotEnforced"
      CA004 = "enabledForReportingButNotEnforced"
      CA005 = "enabledForReportingButNotEnforced"
      CA021 = "enabled"
    }
  }

  assert {
    condition     = output.ca_pim_activation_auth_context_ready == true
    error_message = "CA021 enabled in code AND attested in the tenant must report the auth context ready"
  }
  assert {
    condition = alltrue([for p in values(output.pim_tier_activation_policies) :
    p.tier == 0 ? p.auth == "auth context c1" : p.auth == "MFA"])
    error_message = "Tier 0 must require auth context c1 (from the CA module's readiness output), Tier 1 keeps MFA"
  }
}

# ---- operator_ip_ranges: /32 only with the DC ---------------------------------
run "dc_refuses_wider_than_single_host" {
  command = plan
  variables {
    enable_dc          = true
    operator_ip_ranges = ["203.0.113.0/24"]
  }

  expect_failures = [var.operator_ip_ranges]
}

# Without the DC a /24 is still accepted for the vault / evidence-store
# firewalls - and it never reaches the operator_ips watchlist (which admits
# /32 only), even with the Sentinel v2 rules on.
run "no_dc_keeps_slash24_out_of_the_watchlist" {
  command = plan
  variables {
    enable_dc                 = false
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
    itdr_exclude_rules        = []
    operator_ip_ranges        = ["203.0.113.0/24"]
    operator_ips_expires_on   = "2099-12-31"
  }

  assert {
    condition     = length(output.itdr_rule_keys) == 17
    error_message = "the v2 rules must deploy without the DC (the DC01 rule simply sees no DC01 data)"
  }

  assert {
    condition     = module.monitoring.operator_ips_watchlist_entry_count == 0
    error_message = "without the DC and without v4, a /24 must stay out of the /32-only watchlist"
  }
}

# The v4 operator sign-in rule reads the same watchlist and needs it filled
# with or without the DC (PR #233 review): with v4 on and no DC the ranges
# reach the watchlist, and the root then refuses anything wider than /32.
run "no_dc_v4_fills_the_operator_watchlist" {
  command = plan
  variables {
    enable_dc                 = false
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v4 = true
    itdr_exclude_rules        = []
    operator_principal_ids    = ["0a0a0a0a-0000-4000-8000-00000000000a"]
    operator_ip_ranges        = ["203.0.113.7/32", "198.51.100.4/32"]
    operator_ips_expires_on   = "2099-12-31"
  }

  assert {
    condition     = module.monitoring.operator_ips_watchlist_entry_count == 2
    error_message = "with v4 on and no DC, both operator /32 entries must reach the operator_ips watchlist (an empty list makes every operator sign-in alert High)"
  }
}

run "no_dc_v4_refuses_wider_than_single_host" {
  command = plan
  variables {
    enable_dc                 = false
    enable_sentinel           = true
    enable_itdr_detections    = true
    enable_itdr_detections_v4 = true
    itdr_exclude_rules        = []
    operator_principal_ids    = ["0a0a0a0a-0000-4000-8000-00000000000a"]
    operator_ip_ranges        = ["203.0.113.0/24"]
    operator_ips_expires_on   = "2099-12-31"
  }

  expect_failures = [var.operator_ip_ranges]
}

# Connect Health registration window (ADR 0031). Off in lab.tfvars: no
# account, no role, no output. On with a future end time: exactly one cloud
# account on the onmicrosoft domain with Hybrid Identity Administrator (the
# window touches no Conditional Access code at all: modules/conditional-access
# is unchanged in its PR). On with a past or missing end time: the plan FAILS (the time
# box), so a forgotten window blocks the next apply instead of lingering.
run "connect_health_registration_off_by_default" {
  command = plan
  assert {
    condition     = length(azuread_user.connect_health_registration) == 0 && length(azuread_directory_role_assignment.connect_health_registration) == 0 && output.connect_health_registration_upn == null
    error_message = "lab.tfvars keeps the Connect Health registration window OFF: no account, no role."
  }
}

run "connect_health_registration_window_open" {
  command = plan
  variables {
    enable_connect_health_registration    = true
    connect_health_registration_until_utc = "2099-01-01T00:00:00Z"
  }
  assert {
    condition     = length(azuread_user.connect_health_registration) == 1 && azuread_user.connect_health_registration[0].user_principal_name == "adm-connecthealth-reg@${var.onmicrosoft_domain}"
    error_message = "the window creates exactly adm-connecthealth-reg on the onmicrosoft domain"
  }
  assert {
    # ignore_changes = [account_enabled] (so a later apply cannot undo
    # register.sh close) must not change the create: the account starts
    # enabled, or the passkey enrollment cannot sign in. The ignore_changes
    # line itself is held by lab/adfs/connect-health/tests/
    # registration-lifecycle.test.mjs (terraform test cannot see lifecycle).
    condition     = azuread_user.connect_health_registration[0].account_enabled == true
    error_message = "the window creates adm-connecthealth-reg enabled"
  }
  assert {
    condition     = length(azuread_directory_role_assignment.connect_health_registration) == 1 && azuread_directory_role_assignment.connect_health_registration[0].role_id == "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
    error_message = "the window grants Hybrid Identity Administrator (8ac3fc64-...) and nothing else"
  }
}

run "connect_health_registration_window_over_fails" {
  command = plan
  variables {
    enable_connect_health_registration    = true
    connect_health_registration_until_utc = "2020-01-01T00:00:00Z"
  }
  expect_failures = [azuread_user.connect_health_registration]
}

run "connect_health_registration_without_end_time_fails" {
  command = plan
  variables {
    enable_connect_health_registration = true
  }
  expect_failures = [azuread_user.connect_health_registration]
}

# A flag switched on without its prerequisite plans NOTHING for that feature
# (count = 0) - the root checks turn that silent no-op into a visible warning.
run "flags_without_premium_warn" {
  command = plan

  variables {
    enable_itdr_containment             = false # pinned: lab.tfvars turns containment on (Day 13); it needs enable_itdr_detections, off in this run
    enable_intune_vm                    = false # lab.tfvars turns it on; this run has no premium licence
    enable_itdr_detections_v2           = false # lab.tfvars turns it on; this run keeps the ITDR telemetry off
    enable_premium                      = false
    enable_itdr_detections              = false # pinned: lab.tfvars turns it on from P2, this run is about the premium checks
    enable_governance                   = false # pinned: lab.tfvars turns it on from Day 3
    enable_identity_protection_ca       = true
    enable_phishing_resistant_all_users = true
    enable_registration_ca              = true
    enable_device_code_block            = true
    enable_admin_session_controls       = true
    enable_pim_auth_context             = true
    enable_shared_clinical_ca           = true
    enable_sso_apps                     = true
    enable_scim_provisioning            = true
    enable_pam_oidc_app                 = true
    enable_servicenow_sso               = true
    enable_servicenow_provisioning      = true
    enable_okta_federation              = true
    enable_clinic_results_app           = true
    enable_pim_tiers                    = true
    enable_helpdesk_au_scoping          = true
    enable_global_admin_pim_policy      = true
    enable_pim_aws_admin                = true
    enable_pim_demo_readers             = true
    enable_b2b_governance               = true
    enable_nhi_governance               = true
    enable_lcw_leaver_trigger           = true
    enable_access_reviews_privileged    = true
    vault_feed_v2_columns               = true
  }

  expect_failures = [
    check.identity_protection_requires_premium,
    check.phishing_resistant_requires_premium,
    check.ca_additions_require_premium,
    check.sso_apps_require_premium,
    check.scim_requires_sso_apps,
    check.pam_oidc_app_requires_sso_apps,
    check.servicenow_sso_requires_sso_apps,
    check.servicenow_provisioning_requires_sso_apps,
    check.okta_federation_requires_sso_apps,
    check.clinic_results_requires_sso_apps,
    check.pim_extensions_require_premium,
    check.pim_aws_admin_requires_sso_apps,
    check.b2b_requires_governance,
    check.nhi_governance_requires_premium,
    check.lcw_leaver_trigger_requires_premium,
    check.access_reviews_require_governance,
    check.vault_feed_v2_requires_itdr,
  ]

  assert {
    condition     = output.clinical_portal_client_id == null && output.ca_policy_display_names == null && output.app_consent_reviewers_group_object_id == null && output.pim_auth_context_requests == null
    error_message = "without enable_premium none of the premium-tier extensions may plan anything"
  }
}

# Containment without Sentinel: the plan FAILS in modules/monitoring's
# cross-variable validation (covered by modules/monitoring/tests/itdr.tftest.hcl;
# a root test cannot expect a failure inside a child module's variable).
# The same holds for enable_itdr_detections_v2 without enable_itdr_detections
# (modules/monitoring/tests/itdr_v2.tftest.hcl).

# The scheduled leaver's trigger group (E122 follow-up): enable_lcw_leaver_trigger
# alone creates All-Workforce, without CA008's flag; off, nothing is planned.
run "lcw_leaver_trigger_creates_all_workforce_without_ca008" {
  command = plan

  variables {
    enable_premium                      = true
    enable_phishing_resistant_all_users = false
    enable_lcw_leaver_trigger           = true
  }

  # Mock ids stay unknown at plan (see the header); give the group a known id
  # so the output can be compared.
  override_resource {
    target          = module.groups[0].azuread_group.all_workforce
    override_during = plan
    values = {
      object_id = "00000000-0000-0000-0000-00000000a11f"
    }
  }

  assert {
    condition     = output.all_workforce_group_object_id == "00000000-0000-0000-0000-00000000a11f"
    error_message = "enable_lcw_leaver_trigger alone must create All-Workforce (the scheduled leaver's trigger group), without enable_phishing_resistant_all_users"
  }

  assert {
    condition     = output.staff_passkey_rollout_enabled == false
    error_message = "the leaver trigger alone must not switch on the staff passkey rollout (Invoke-PostApply.ps1 reads staff_passkey_rollout_enabled, not the shared group)"
  }
}

run "lcw_leaver_trigger_off_plans_no_all_workforce" {
  command = plan

  variables {
    enable_premium                      = true
    enable_phishing_resistant_all_users = false
    enable_lcw_leaver_trigger           = false
  }

  assert {
    condition     = output.all_workforce_group_object_id == null
    error_message = "with both flags off, All-Workforce must not be planned"
  }
}
