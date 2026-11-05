# =============================================================================
# envs/dev :: outputs.tf
# -----------------------------------------------------------------------------
# Premium/governance outputs are null until their staging flag is on.
# Pipeline client ids live in envs/bootstrap outputs.
# =============================================================================

# ---- Identity ---------------------------------------------------------------

output "break_glass_group_object_id" {
  description = "Break-Glass-Admins group (standing GA, excluded from all CA policies)."
  value       = one(module.groups[*].break_glass_group_object_id)
}

output "break_glass_user_principal_names" {
  description = "Break-glass UPNs (feed lab/kql/break-glass-signin.kql / the watchlist)."
  value       = one(module.groups[*].break_glass_user_principal_names)
}

output "all_nurses_group_object_id" {
  description = "All-Nurses dynamic birthright group object id."
  value       = one(module.groups[*].all_nurses_group_object_id)
}

output "all_icu_group_object_id" {
  description = "All-ICU dynamic birthright group object id."
  value       = one(module.groups[*].all_icu_group_object_id)
}

output "priv_iam_admins_group_object_id" {
  description = "PIM-governed Privileged-IAM-Admins group object id (input for post-apply/Set-PimGroupEligibility.ps1)."
  value       = one(module.groups[*].priv_iam_admins_group_object_id)
}

output "app_access_group_object_ids" {
  description = "Assigned access group object ids (assign these to the enterprise apps)."
  value       = one(module.groups[*].app_access_group_object_ids)
}

# ---- Conditional Access -----------------------------------------------------

output "conditional_access_policy_ids" {
  description = "Map of logical policy name => CA policy id (CA001..CA010, CA020, CA022, CA060; each is null while its staging flag is off). CA021 is Graph-managed (Set-AuthContextPolicies.ps1), so it has no Terraform id."
  value       = one(module.conditional_access[*].policy_ids)
}

output "ca_policy_display_names" {
  description = "CA key => deployed display name (CA001..CA010, CA020..CA022, CA060; null while off - CA021 is the rendered Graph name). Evidence scripts and detections match SigninLogs ConditionalAccessPolicies[].displayName on these, not on hand-copied strings."
  value       = one(module.conditional_access[*].policy_display_names)
}

output "pim_auth_context_requests" {
  description = "CA021 + authentication context c1 Graph bodies (null unless enable_pim_auth_context). Input for post-apply/Set-AuthContextPolicies.ps1: terraform output -json pim_auth_context_requests > ca021.json"
  value       = one(module.conditional_access[*].pim_auth_context_requests)
}

output "protected_actions_auth_context_requests" {
  description = "CA023 + authentication context c2 Graph bodies (null unless enable_protected_actions_ca). Input for post-apply/Set-AuthContextPolicies.ps1 -RequestsPath, the same script as CA021."
  value       = one(module.conditional_access[*].protected_actions_auth_context_requests)
}

output "ca_pim_activation_auth_context_ready" {
  description = "true once CA021 is declared ENFORCED in code (enable_pim_auth_context + ca_policy_states CA021 = \"enabled\"). Declared state only: the tenant matches after Set-AuthContextPolicies.ps1 runs. Only then may pim_tier0_activation_auth_context_id be set."
  value       = one(module.conditional_access[*].pim_activation_auth_context_ready)
}

output "registration_authentication_strength_policy_id" {
  description = "Bootstrap-and-recovery strength (one-time TAP or phishing-resistant) CA009 requires; null while enable_registration_ca is off."
  value       = one(module.conditional_access[*].registration_authentication_strength_policy_id)
}

output "ca_admin_role_template_ids" {
  description = "Directory role template ids CA002 targets (Microsoft's phishing-resistant-for-admins template list + the lab's tier extras) - for the baseline assessment (ScubaGear MS.AAD.3.6) and the evidence pack."
  value       = one(module.conditional_access[*].admin_role_template_ids)
}

output "ca008_pilot_group_object_id" {
  description = "CA008-Pilot-PhishingResistant (or the supplied pilot group); null while enable_phishing_resistant_all_users is off. 07-Passwordless-Rollout.ps1 -PromoteReadyToPilot adds ready users to it."
  value       = one(module.conditional_access[*].ca008_pilot_group_object_id)
}

output "admin_fido2_allowed_aaguids" {
  description = "Admin key-model allow-list the admin strength (CA002 / CA021 / CA022) enforces - Invoke-PostApply.ps1 passes it to Set-AuthenticationMethodsPolicy.ps1 so registration and sign-in use ONE list."
  value       = sort(tolist(var.admin_fido2_allowed_aaguids))
}

output "accept_admin_synced_passkey_risk" {
  description = "Reviewed risk acceptance: workforce passkey rollout without an admin AAGUID list (Set-AuthenticationMethodsPolicy.ps1 -AcceptAdminSyncedPasskeyRisk)."
  value       = var.accept_admin_synced_passkey_risk
}

output "workforce_authentication_strength_policy_id" {
  description = "Workforce phishing-resistant authentication strength used by CA008 (null while off)."
  value       = one(module.conditional_access[*].workforce_authentication_strength_policy_id)
}

# ---- PIM --------------------------------------------------------------------

output "pim_group_role_management_policy_id" {
  description = "PIM-for-Groups activation policy id."
  value       = one(module.pim[*].group_role_management_policy_id)
}

output "pim_tier_group_mail_nicknames" {
  description = "Tier group display name => mail_nickname (-GroupMailNickname for post-apply/Set-PimGroupEligibility.ps1)."
  value       = one(module.pim[*].tier_group_mail_nicknames)
}

output "pim_tier_activation_policies" {
  description = "Effective activation rules per PIM tier group (evidence pack; on-camera tier walkthrough)."
  value       = one(module.pim[*].tier_activation_policies)
}

output "aws_admin_group_object_id" {
  description = "PIM-AWS-Lab-Admins - eligible-only AWS admin group, assigned to the AWS IAM Identity Center app (ADR 0025); null while enable_pim_aws_admin is off. lab/terraform/aws var lab_admin_entra_group_object_id pins its SCIM copy to this id."
  value       = one(module.pim[*].aws_admin_group_object_id)
}

output "aws_admin_activation_policy" {
  description = "Evidence summary of the PIM-AWS-Lab-Admins activation policy (null while off)."
  value       = one(module.pim[*].aws_admin_activation_policy)
}

output "azure_pim_group_object_id" {
  description = "PIM-Azure-RG-Contributors - eligible for Contributor on the lab RG (add members post-apply); null while off."
  value       = one(module.pim[*].azure_pim_group_object_id)
}

output "pim_approver_group_mail_nicknames" {
  description = "PIM approver groups by tier (tier0 / tier1) => mail_nickname. Set-PimGroupEligibility.ps1 / Set-DirectoryRolePimPolicies.ps1 warn when an eligible person is also an approver."
  value       = one(module.pim[*].approver_group_mail_nicknames)
}

output "pim_privileged_role_template_ids" {
  description = "Directory role template ids governed by modules/pim, by tier (tier0 incl. Global Administrator). CA020's role list is built from it; 08-Measure-KPIs.ps1 / 01-Verify-Baseline.ps1 keep the same tier map."
  value       = one(module.pim[*].privileged_role_template_ids)
}

output "directory_role_pim_policies" {
  description = "Global Administrator PIM policy rule bodies ({} unless enable_global_admin_pim_policy). Input for post-apply/Set-DirectoryRolePimPolicies.ps1: terraform output -json directory_role_pim_policies > ga-policy.json. Sensitive: the notification rules carry pim_alert_mailbox (never commit the file)."
  value       = one(module.pim[*].directory_role_pim_policies)
  sensitive   = true
}

output "pim_workforce_au_object_id" {
  description = "AU-Workforce-Standard (the service desk's role scope); null unless enable_helpdesk_au_scoping."
  value       = one(module.pim[*].workforce_au_object_id)
}

output "pim_workforce_au_membership_body" {
  description = "TENANT-TIME Graph body that makes AU-Workforce-Standard dynamic: PATCH https://graph.microsoft.com/v1.0/directory/administrativeUnits/<pim_workforce_au_object_id> (AdministrativeUnit.ReadWrite.All). null unless enable_helpdesk_au_scoping."
  value       = one(module.pim[*].workforce_au_membership_body)
}

# pim_eligible_review_bodies is deliberately NOT a root output: it reaches
# New-AccessReviewDefinitions.ps1 only inside access_review_definitions
# (modules/entitlement merges it under enable_access_reviews_privileged). As
# a separate output, a full `terraform output -json` file would hand it to
# the script - which unwraps it - even with the T1 review flag off.

# ---- Entitlement ------------------------------------------------------------

output "access_package_ids" {
  description = "Map of package key (nurse/icu/icu_float/pharmacy) => access package id."
  value       = one(module.entitlement[*].access_package_ids)
}

output "package_assignment_model" {
  description = "Per package: ADR 0012 tier (T1/T2/T3), assignment model (automatic birthright / request) and whether a Terraform request policy exists. Automatic packages get their policy from post-apply/Set-AutoAssignmentPolicies.ps1."
  value       = one(module.entitlement[*].package_assignment_model)
}

output "birthright_package_names" {
  description = "Display names of the automatic (T3 birthright) packages - never reviewed by a person, never an incompatibility target (Set-IncompatibleAccessPackages.ps1)."
  value       = one(module.entitlement[*].birthright_package_names)
}

output "sod_incompatible_package_id_pairs" {
  description = "LEGACY package-id pairs. The SoD ruleset is lab/iga/sod-rules.json, written by post-apply/Set-IncompatibleAccessPackages.ps1 (Set-AccessPackageSoD.ps1 is now a forwarding shim)."
  value       = one(module.entitlement[*].sod_incompatible_package_id_pairs)
}

output "access_review_settings" {
  description = "Risk-tiered review settings (ADR 0012): the three flags and the per-package policy reviews (null when no review flag is on or governance is off)."
  value       = one(module.entitlement[*].access_review_settings)
}

output "access_review_definitions" {
  description = "Graph request bodies (key => JSON string) for the standalone reviews: privileged (PIM-governed groups + GA eligibility, modules/pim bodies merged; enable_access_reviews_privileged) and inactive-user (enable_access_reviews_inactive). Input for post-apply/New-AccessReviewDefinitions.ps1: terraform output -json access_review_definitions > reviews.json"
  value       = one(module.entitlement[*].access_review_definitions)
}

output "b2b_post_apply" {
  description = "Connected-organization + guest-lifecycle Graph bodies. Input for post-apply/New-B2BConnectedOrganization.ps1: terraform output -json b2b_post_apply > b2b.json"
  value       = one(module.entitlement[*].b2b_post_apply)
}

output "b2b_access_package_id" {
  description = "Affiliated Physicians access package id (My Access link for the guest request); null while off."
  value       = one(module.entitlement[*].b2b_access_package_id)
}

# ---- Key Vault --------------------------------------------------------------

output "key_vault_uri" {
  description = "Key Vault data-plane URI."
  value       = module.keyvault.key_vault_uri
}

output "key_vault_reader_uami_client_id" {
  description = "Client id of the UAMI granted Key Vault Secrets User."
  value       = module.keyvault.uami_client_id
}

output "log_analytics_workspace_id" {
  description = "Resource id of loga-idlab (Entra diagnostic settings + Sentinel target)."
  value       = azurerm_log_analytics_workspace.idlab.id
}

# ---- Domain controller -------------------------------------------------------

output "dc_vm_name" {
  description = "Azure name of the DC VM (az vm run-command / start / deallocate)."
  value       = one(module.dc_vm[*].vm_name)
}

output "dc_private_ip" {
  description = "DC01 private IP."
  value       = one(module.dc_vm[*].private_ip)
}

output "dc_public_ip" {
  description = "DC01 public IP (NSG admits operator_ip_ranges only)."
  value       = one(module.dc_vm[*].public_ip)
  sensitive   = true
}

output "dc_admin_password" {
  description = "Initial DC admin password - rotate after first sign-in. terraform output -raw dc_admin_password | pbcopy (never on camera)"
  value       = one(module.dc_vm[*].admin_password)
  sensitive   = true
}

# ---- Monitoring --------------------------------------------------------------

output "sentinel_rule_ids" {
  description = "Sentinel analytics rule ids (empty until enable_sentinel)."
  value       = module.monitoring.sentinel_rule_ids
}

output "itdr_rule_keys" {
  description = "ITDR rule keys (v1 + v2) deployed to the active detection path (empty until enable_itdr_detections). The Log Analytics path skips itdr_sentinel_only_rule_keys."
  value       = module.monitoring.itdr_rule_keys
}

output "itdr_sentinel_only_rule_keys" {
  description = "Selected ITDR rules that exist only as Sentinel analytics rules (14-day look-back, beyond a Log Analytics alert's 2 days): on the enable_la_alerts path they are listed here and NOT deployed."
  value       = module.monitoring.sentinel_only_rule_keys
}

output "operator_ips_watchlist_id" {
  description = "Sentinel watchlist operator_ips (read by dc-logon-outside-operator-allowlist.kql); null unless enable_sentinel + enable_itdr_detections_v2. It holds rows (operator_ip_ranges) only while enable_dc; they are sensitive and never output."
  value       = module.monitoring.operator_ips_watchlist_id
}

output "itdr_privileged_group_ids" {
  description = "Role-holding / PIM-governed group ids the ITDR rules watch (also the Splunk lookup contoso_privileged_groups.csv)."
  value       = local.itdr_privileged_group_ids
}

output "containment_automation_rule_id" {
  description = "Sentinel automation rule running the containment playbook (null until enable_itdr_containment + containment_playbook_id)."
  value       = module.monitoring.containment_automation_rule_id
}

output "vault_ingestion" {
  description = "Logs Ingestion API target for lab/scripts/monitoring/ingest-vault-audit.sh (--endpoint / --dcr-id); null until enable_itdr_detections. Not secret: useless without a token holding Monitoring Metrics Publisher on the DCR."
  value       = module.monitoring.vault_ingestion
}

output "vault_ingest_signals" {
  description = "--signals value ingest-vault-audit.sh must run with (Invoke-PostApply.ps1 builds the command from it): \"all\" once vault_feed_v2_columns adds Ticket / Operator / ErrorText to VaultCheckout_CL - otherwise every Tier-0 check-out alerts as unticketed - else \"checkout\". null until enable_itdr_detections."
  value       = var.enable_itdr_detections ? (var.vault_feed_v2_columns ? "all" : "checkout") : null
}

output "dc_security_dcr_id" {
  description = "DCR collecting DC01 Security events for the ITDR Tier-0 logon rule (null unless enable_itdr_detections + enable_dc)."
  value       = module.monitoring.dc_security_dcr_id
}

output "defender_for_identity_connector_id" {
  description = "Microsoft Defender XDR data connector carrying MDI alerts into SecurityAlert (null unless enable_sentinel + enable_defender_for_identity). Verify step for deploy-defender-for-identity-dc01.md."
  value       = module.monitoring.defender_for_identity_connector_id
}

# ---- SSO apps (modules/apps) -----------------------------------------------------

output "aws_federation_metadata_url" {
  description = "Entra federation metadata to upload in AWS IAM Identity Center (Change identity source); null while enable_sso_apps is off."
  value       = one(module.apps[*].aws_federation_metadata_url)
}

output "aws_saml_signing_cert_activation_command" {
  description = "Post-apply command that activates the AWS SAML signing certificate (azuread cannot set preferredTokenSigningKeyThumbprint)."
  value       = one(module.apps[*].aws_saml_signing_cert_activation_command)
}

output "aws_scim_template_lookup_command" {
  description = "Graph call that returns the AWS synchronization template id (-> aws_scim_template_id)."
  value       = one(module.apps[*].aws_scim_template_lookup_command)
}

output "aws_service_principal_object_id" {
  description = "AWS IAM Identity Center enterprise app object id."
  value       = one(module.apps[*].aws_service_principal_object_id)
}

output "clinical_portal_client_id" {
  description = "Contoso Clinical Portal client id."
  value       = one(module.apps[*].clinical_portal_client_id)
}

output "clinical_portal_identifier_uri" {
  description = "Contoso Clinical Portal App ID URI (api://<client-id>; scope <this>/Clinical.Read)."
  value       = one(module.apps[*].clinical_portal_identifier_uri)
}

output "guacamole_psm_client_id" {
  description = "guacamole-psm client id = OIDC_CLIENT_ID in lab/pam/.env (null while enable_pam_oidc_app is off)."
  value       = one(module.apps[*].guacamole_psm_client_id)
}

output "pam_operators_group_object_id" {
  description = "PAM-Operators, the only assignee of guacamole-psm (null while off)."
  value       = one(module.apps[*].pam_operators_group_object_id)
}

output "okta_idp_client_id" {
  description = "okta-clinic-idp client id = entra_client_id in lab/terraform/okta (null while enable_okta_federation is off)."
  value       = one(module.apps[*].okta_idp_client_id)
}

output "okta_idp_redirect_uri" {
  description = "The one redirect URI on okta-clinic-idp; must equal lab/terraform/okta output okta_callback_uri (null while off)."
  value       = one(module.apps[*].okta_idp_redirect_uri)
}

output "okta_idp_endpoints" {
  description = "The tenant's v2.0 OIDC endpoints for the Okta root's identity provider (null while off)."
  value       = one(module.apps[*].okta_idp_endpoints)
}

output "okta_idp_client_secret_command" {
  description = "POST-APPLY, a human: mints the bounded client secret for okta-clinic-idp and prints it once for TF_VAR_entra_client_secret in lab/terraform/okta. Terraform never creates it (null while off)."
  value       = one(module.apps[*].okta_idp_client_secret_command)
}

output "apps_nhi_inventory" {
  description = "Per-app ownership + credential rows from modules/apps (NHI inventory / evidence pack). Sensitive (owner object ids): terraform output -json apps_nhi_inventory."
  sensitive   = true
  value       = one(module.apps[*].nhi_inventory)
}

# ---- Non-human identity governance -----------------------------------------------

output "app_consent_reviewers_group_object_id" {
  description = "App-Consent-Reviewers (admin consent workflow reviewers; Set-ConsentPolicy.ps1 finds it by mailNickname). null while enable_nhi_governance is off."
  value       = one(module.groups[*].app_consent_reviewers_group_object_id)
}

output "all_workforce_group_object_id" {
  description = "Dynamic All-Workforce group (staff passkey profile target of Set-AuthenticationMethodsPolicy.ps1). null while enable_phishing_resistant_all_users is off."
  value       = one(module.groups[*].all_workforce_group_object_id)
}

output "agent_runtime_uami_principal_id" {
  description = "Principal (object) id of uami-agent-runtime -> New-AgentIdentity.ps1 -ManagedIdentityPrincipalId. null while enable_agent_identity is off."
  value       = one(azurerm_user_assigned_identity.agent_runtime[*].principal_id)
}

output "agent_runtime_uami_client_id" {
  description = "Client id of uami-agent-runtime (what the agent's host requests tokens as). null while off."
  value       = one(azurerm_user_assigned_identity.agent_runtime[*].client_id)
}

# ---- Evidence store ----------------------------------------------------------------

output "evidence_storage_account_name" {
  description = "WORM evidence storage account (az storage blob upload --auth-mode login); null while enable_evidence_store is off."
  value       = one(module.evidence_store[*].storage_account_name)
}

output "evidence_container_name" {
  description = "Evidence container in the WORM store."
  value       = one(module.evidence_store[*].evidence_container_name)
}

output "evidence_container_id" {
  description = "Resource Manager id of the evidence container - the --scope of the human writer-role grant."
  value       = one(module.evidence_store[*].evidence_container_id)
}

output "evidence_writer_abac_condition" {
  description = "ABAC condition for the human writer grant (Storage Blob Data Contributor that can never delete)."
  value       = one(module.evidence_store[*].writer_abac_condition)
}

output "evidence_immutability" {
  description = "Effective immutability policy of the evidence store (days, state)."
  value       = one(module.evidence_store[*].immutability)
}

# ---- Intune compliant-device demo --------------------------------------------

output "ca005_pilot_group_object_id" {
  description = "CA005-Pilot-CompliantDevice group (CA005 include, Intune compliance assignment, VM Administrator Login on the Intune VM)."
  value       = one(module.groups[*].ca005_pilot_group_object_id)
}

output "intune_vm_name" {
  description = "Azure name of the Windows 11 Intune VM (az vm start / deallocate)."
  value       = one(module.intune_vm[*].vm_name)
}

output "intune_vm_computer_name" {
  description = "Hostname = Entra device name of the Intune VM (find it in Entra Devices / Intune; map it in /etc/hosts for Entra RDP)."
  value       = one(module.intune_vm[*].computer_name)
}

output "intune_vm_public_ip" {
  description = "Intune VM public IP (NSG admits operator_ip_ranges only)."
  value       = one(module.intune_vm[*].public_ip)
  sensitive   = true
}

output "intune_vm_rdp_file" {
  description = "Entra-auth .rdp for the Intune VM: terraform output -raw intune_vm_rdp_file > ch-win11-01.rdp"
  value       = one(module.intune_vm[*].rdp_file_content)
}

output "intune_vm_admin_password" {
  description = "Local break-glass admin password of the Intune VM (sign-in is normally Entra). terraform output -raw intune_vm_admin_password | pbcopy (never on camera)"
  value       = one(module.intune_vm[*].admin_password)
  sensitive   = true
}

# ---- ServiceNow (enable_servicenow_sso) ------------------------------------------
# Run sheet 07 / apps README S1a-S2 read these from the env root; they were
# only exposed by the module until the first live ServiceNow stage (2026-10-28).

output "servicenow_service_principal_object_id" {
  description = "Object id of the ServiceNow enterprise app (null while enable_servicenow_sso is off)."
  value       = one(module.apps[*].servicenow_service_principal_object_id)
}

output "servicenow_federation_metadata_url" {
  description = "Entra federation metadata for the ServiceNow app: import it as the IdP in ServiceNow's Multi-Provider SSO (S2)."
  value       = one(module.apps[*].servicenow_federation_metadata_url)
}

# ---- ServiceNow provisioning (enable_servicenow_provisioning) ------------------
# Provision-on-demand, Test Connection and the provisioning logs act on these.

output "servicenow_provisioning_service_principal_object_id" {
  description = "Object id of the ServiceNow provisioning enterprise app (null while enable_servicenow_provisioning is off)."
  value       = one(module.apps[*].servicenow_provisioning_service_principal_object_id)
}

output "servicenow_provisioning_job_id" {
  description = "ServiceNow provisioning job id: provisionOnDemand and validateCredentials (Test Connection) take it."
  value       = one(module.apps[*].servicenow_provisioning_job_id)
}

output "servicenow_provisioning_reply_url_import_id" {
  description = "Seeding step: terraform import id of the ServiceNow provisioning app's existing Web redirect set (modules/apps README \"ServiceNow provisioning\")."
  value       = one(module.apps[*].servicenow_provisioning_reply_url_import_id)
}

output "servicenow_provisioning_job_enabled" {
  description = "Whether the ServiceNow provisioning cycle is started (false = created stopped)."
  value       = one(module.apps[*].servicenow_provisioning_job_enabled)
}

output "servicenow_saml_signing_cert_activation_command" {
  description = "S1a: the Update-MgServicePrincipal line that activates the ServiceNow SAML signing certificate (azuread cannot set preferredTokenSigningKeyThumbprint)."
  value       = one(module.apps[*].servicenow_saml_signing_cert_activation_command)
}
