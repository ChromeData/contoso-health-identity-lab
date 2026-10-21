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

  # Trials must not start early: every new layer is absent with lab.tfvars.
  assert {
    condition     = output.itdr_rule_keys == [] && output.vault_ingestion == null && output.dc_security_dcr_id == null && output.vault_ingest_signals == null
    error_message = "ITDR rules / telemetry must not exist while enable_itdr_detections = false"
  }
  assert {
    condition     = output.itdr_sentinel_only_rule_keys == [] && output.operator_ips_watchlist_id == null
    error_message = "no v2 ITDR rule and no operator_ips watchlist may exist with lab.tfvars"
  }
  assert {
    condition     = output.evidence_storage_account_name == null && output.agent_runtime_uami_principal_id == null
    error_message = "evidence store / agent runtime identity must not exist while their flags are false"
  }
  assert {
    condition     = output.clinical_portal_client_id == null && output.guacamole_psm_client_id == null && output.ca_policy_display_names == null
    error_message = "no premium-tier object (apps, CA) may be planned with enable_premium = false"
  }
  assert {
    condition = alltrue([
      output.pim_auth_context_requests == null,
      output.ca_pim_activation_auth_context_ready == null,
      output.registration_authentication_strength_policy_id == null,
      output.pim_workforce_au_object_id == null,
      output.pim_workforce_au_membership_body == null,
      output.pim_privileged_role_template_ids == null,
      output.access_review_definitions == null,
      output.package_assignment_model == null,
    ])
    error_message = "no CA021 body, help-desk AU, PIM tier map or review body may be rendered with lab.tfvars (premium and governance are off)"
  }
  assert {
    condition     = nonsensitive(output.directory_role_pim_policies) == null
    error_message = "no Global Administrator PIM policy may be rendered with lab.tfvars"
  }
}

# The committed lab.tfvars hold-back list, with the ITDR flags flipped on (as
# the first ITDR PR would): CI reads lab.tfvars, so the rules whose tables
# cannot have data yet - DC01 SecurityEvent, the risk tables, the extended
# vault feed - and the PREVIEW rule stay out of the plan, on both paths.
run "plan_lab_itdr_hold_back" {
  command = plan
  variables {
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
      "tier0_logon_without_checkout", "ad_privileged_group_change", "kerberoast_rc4_service_ticket",
      "dcsync_replication_request", "dc_logon_outside_operator_allowlist",
    ] : contains(var.itdr_exclude_rules, k) && !contains(output.itdr_rule_keys, k)])
    error_message = "lab.tfvars must hold back every SecurityEvent rule: CI never loads terraform.tfvars, so a key held back only there would be deployed"
  }
  assert {
    condition     = !contains(output.itdr_rule_keys, "pim_activation_without_auth_context") && !contains(output.itdr_rule_keys, "vault_privileged_access_anomaly") && !contains(output.itdr_rule_keys, "identity_risk")
    error_message = "the PREVIEW rule, the vault anomaly rule (extended feed) and identity_risk (risk tables) must be held back by lab.tfvars"
  }
  assert {
    condition     = length(output.itdr_rule_keys) == 17 - length(var.itdr_exclude_rules) && length(var.itdr_exclude_rules) == 8
    error_message = "lab.tfvars holds back exactly eight of the seventeen ITDR rules; the other nine deploy"
  }
}

run "plan_lab_itdr_hold_back_la_alerts" {
  command = plan
  variables {
    enable_la_alerts          = true
    enable_itdr_detections    = true
    enable_itdr_detections_v2 = true
  }

  assert {
    condition     = length(output.itdr_rule_keys) == 9 && !contains(output.itdr_rule_keys, "tier0_logon_without_checkout") && !contains(output.itdr_rule_keys, "dc_logon_outside_operator_allowlist")
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
    enable_device_code_block                = false
    enable_admin_session_controls           = false
    enable_pim_auth_context                 = false
    enable_shared_clinical_ca               = false
    enable_helpdesk_au_scoping              = false
    enable_global_admin_pim_policy          = false
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
    app_owner_object_ids        = ["cccccccc-cccc-cccc-cccc-cccccccccccc"]
    aws_scim_template_id        = "placeholderTemplate"
    containment_playbook_id     = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
    aws_scim_credentials = {
      tenant_url   = "https://scim.us-east-1.amazonaws.com/abcd-1234/scim/v2"
      secret_token = "not-a-real-token-0123456789abcdef"
    }
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
    condition     = output.apps_nhi_inventory.servicenow == null
    error_message = "the ServiceNow SAML app must not be planned while enable_servicenow_sso is off"
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
    enable_scim_provisioning            = true
    enable_pam_oidc_app                 = true
    enable_pim_tiers                    = true
    enable_helpdesk_au_scoping          = true
    enable_global_admin_pim_policy      = true
    enable_pim_azure_resources          = true
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
    }
    # The workforce passkey rollout needs the admin key-model allow-list.
    admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    iac_principal_ids           = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    app_owner_object_ids        = ["cccccccc-cccc-cccc-cccc-cccccccccccc"]
    aws_scim_template_id        = "placeholderTemplate"
    containment_playbook_id     = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-identity-lab/providers/Microsoft.Logic/workflows/pb-identity-contain"
    servicenow_instance_url     = "https://dev00000.service-now.com" # synthetic PDI
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
    # 18 group reviews (IAM + 16 tiers + Azure), GA eligibility, inactive users.
    condition     = length(output.access_review_definitions) == 20 && contains(keys(output.access_review_definitions), "privileged:Global Administrator (eligible)")
    error_message = "expected 18 privileged group reviews + the GA eligibility review + 1 inactive-user review"
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
}

run "plan_all_flags_on_la_alerts" {
  command = plan
  variables {
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
    enable_scim_provisioning            = true
    enable_pam_oidc_app                 = true
    enable_pim_tiers                    = true
    enable_helpdesk_au_scoping          = true
    enable_global_admin_pim_policy      = true
    enable_pim_azure_resources          = true
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
    }
    # The workforce passkey rollout needs the admin key-model allow-list.
    admin_fido2_allowed_aaguids = ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    iac_principal_ids           = ["dddddddd-dddd-dddd-dddd-dddddddddddd"]
    app_owner_object_ids        = ["cccccccc-cccc-cccc-cccc-cccccccccccc"]
    aws_scim_template_id        = "placeholderTemplate"
    servicenow_instance_url     = "https://dev00000.service-now.com" # synthetic PDI
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
    condition     = length(nonsensitive(output.directory_role_pim_policies)) == 1 && length(output.access_review_definitions) == 20
    error_message = "the PIM and review bodies do not depend on the detection path"
  }
  assert {
    condition     = output.apps_nhi_inventory.servicenow != null
    error_message = "enable_servicenow_sso must plan the ServiceNow SAML app (modules/apps servicenow.tf)"
  }
}

# ---- The CA021 -> PIM ordering gate -----------------------------------------
# PIM may require the auth context only once CA021 is ENFORCED. Report-only is
# refused at the root variable (the modules refuse it too, but child-module
# preconditions cannot be expect_failures targets from a root test).
run "pim_auth_context_refused_while_ca021_report_only" {
  command = plan
  variables {
    enable_premium                          = true
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
    enable_premium                          = true
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
}

# A flag switched on without its prerequisite plans NOTHING for that feature
# (count = 0) - the root checks turn that silent no-op into a visible warning.
run "flags_without_premium_warn" {
  command = plan

  variables {
    enable_premium                      = false
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
    enable_pim_tiers                    = true
    enable_helpdesk_au_scoping          = true
    enable_global_admin_pim_policy      = true
    enable_b2b_governance               = true
    enable_nhi_governance               = true
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
    check.pim_extensions_require_premium,
    check.b2b_requires_governance,
    check.nhi_governance_requires_premium,
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
