# =============================================================================
# envs/dev :: main.tf
# -----------------------------------------------------------------------------
# Root composition for the Contoso Health IAM/PAM lab. Wires the identity
# modules together and owns the two shared azurerm resources (resource group +
# Log Analytics) that the keyvault module plugs into.
#
# The GitHub OIDC pipeline identities are NOT here - they live in
# envs/bootstrap, applied locally by a human admin. A PR to THIS root
# therefore cannot rewrite the pipeline's own permissions (APPLY is still
# Tier 0 - see the envs/bootstrap header).
#
# STAGING FLAGS (so no trial starts before you are ready to use it):
#   enable_premium    = false -> free tier: RG, Log Analytics, Key Vault.
#   enable_premium    = true  -> + groups/break-glass, Conditional Access, PIM
#                                 (needs Entra ID P1/P2 - M365 E5 trial).
#   enable_governance = true  -> + access packages (needs Entra ID Governance).
#   enable_dc         = true  -> + AD DS domain controller VM (free tier, Azure cost).
#   enable_intune_vm  = true  -> + Windows 11 VM, Entra joined + Intune enrolled
#                                 (CA005 compliant device; Azure cost; needs premium).
#   enable_access_reviews_privileged / _requestable / _inactive (ADR 0012 tiers;
#                     enable_access_reviews = all three) -> T1 quarterly
#                     default-deny reviews of PIM-governed access, T2 review
#                     of long-lived requestable packages, inactive users.
#                     Never a T3 birthright clinical package.
#   enable_sentinel   = true  -> + Sentinel + analytics rules (STARTS 31-day trial).
#   enable_la_alerts  = true  -> + same KQL as Log Analytics alerts (post-trial).
#
#   Senior-scope extensions (every one false in lab.tfvars; each is ONE PR
#   during the trial window, in lab/docs/evidence-capture-plan.md order):
#   enable_identity_protection_ca       -> CA006 user risk / CA007 sign-in risk
#                                          (report-only; P2 - premium).
#   enable_phishing_resistant_all_users -> CA008 workforce phishing-resistant
#                                          strength (report-only) + pilot group
#                                          + All-Workforce passkey target (premium).
#   enable_registration_ca              -> CA009 register security info: one-time
#                                          TAP or phishing-resistant (premium).
#   enable_device_code_block            -> CA010 block device code flow
#                                          (premium; enforcing breaks
#                                          `az login --use-device-code`).
#   enable_admin_session_controls       -> CA020 admin portals: sign-in every 4h
#                                          for the Tier-0/1 roles + PIM groups.
#   enable_pim_auth_context             -> CA021 + auth context c1, RENDERED for
#                                          post-apply/Set-AuthContextPolicies.ps1
#                                          (the provider can create neither).
#   enable_shared_clinical_ca           -> CA060 shared clinical workstations
#                                          (ADR 0014; needs the CA008 strength).
#   enable_sso_apps                     -> AWS IAM Identity Center SAML app +
#                                          Clinical Portal OIDC app (premium).
#     enable_scim_provisioning          ->   + AWS SCIM job, created STOPPED.
#     enable_pam_oidc_app               ->   + guacamole-psm PSM sign-in app and
#                                          CA022 (was CA009) admin strength.
#     enable_servicenow_sso             ->   + ServiceNow PDI SAML app (needs
#                                          servicenow_instance_url).
#     enable_servicenow_provisioning    ->   + ServiceNow provisioning app (gallery,
#                                          hidden), job STOPPED + credential:
#                                          LOCAL seeding apply first.
#     enable_okta_federation            ->   + okta-clinic-idp, Entra as the IdP
#                                          for the clinic's Okta org (needs
#                                          okta_org_domain; ADR 0022).
#   enable_pim_tiers                   -> Tier-0 / Tier-1 PIM role groups +
#                                          approver groups (premium).
#     enable_helpdesk_au_scoping        ->   + AU-Workforce-Standard; help-desk
#                                          roles scoped to it.
#   enable_global_admin_pim_policy      -> Global Administrator PIM policy bodies
#                                          for post-apply/Set-DirectoryRolePimPolicies.ps1.
#   enable_pim_azure_resources          -> Azure PIM: eligible Contributor on the
#                                          RG (premium; HUMAN Owner applies).
#   enable_pim_demo_readers             -> PIM-Demo-Readers: read-only presenter
#                                          access (Global Reader + Security
#                                          Reader), eligible-only, no approval;
#                                          Azure read roles via envs/bootstrap.
#   enable_b2b_governance               -> guest catalog + Affiliated Physicians
#                                          package (governance).
#   enable_access_reviews_privileged    -> + privileged (PIM-eligible, incl. GA
#                                          eligibility) review bodies; _inactive
#                                          -> inactive-user review bodies; both for
#                                          post-apply/New-AccessReviewDefinitions.ps1.
#   enable_nhi_governance               -> App-Consent-Reviewers group (premium);
#                                          app/consent policies are post-apply.
#   enable_agent_identity               -> uami-agent-runtime for Entra Agent ID.
#   enable_itdr_detections              -> 11 ITDR rules + vault/DC01 telemetry
#                                          (no trial by itself).
#     enable_itdr_detections_v2         ->   + 6 second-wave rules + (Sentinel)
#                                          operator_ips watchlist, rows from
#                                          operator_ip_ranges while enable_dc.
#     enable_itdr_detections_v3         ->   + 2 third-set rules (dormant admin
#                                          sign-in, Key Vault bulk reads;
#                                          Sentinel only).
#     vault_feed_v2_columns             ->   + Ticket/Operator/ErrorText columns.
#     enable_itdr_containment           ->   + containment playbook automation
#                                          rule (needs enable_sentinel).
#   enable_evidence_store               -> WORM evidence storage account.
#
# CROSS-MODULE WIRING (each value flows one way; no module reads another's
# state):
#   pim  -> conditional_access  privileged_review_targets (PIM-governed groups,
#                               incl. the AU-scoped help desk) -> CA002 / CA020
#                               included_groups; privileged_role_template_ids
#                               -> CA020's role list (one tier map).
#   conditional_access -> pim   pim_activation_auth_context_ready (CA021
#                               declared enforced) gates the Tier-0 auth
#                               context; the SAME pim_tier0_activation_auth_
#                               context_id goes to both modules.
#   pim  -> entitlement         pim_eligible_review_bodies (PIM-group + GA
#                               eligibility reviews) merged into
#                               access_review_definitions under the T1 flag.
#   groups -> entitlement       break-glass id: no review may target it.
#   root -> monitoring          operator_ip_ranges (enable_dc only) -> the
#                               operator_ips watchlist; approver groups join
#                               the privileged groups the ITDR rules watch.
#
# APPLY ORDER (Terraform resolves this automatically from the references, but
# it is called out so the dependency story is explicit):
#   1. resource group + log analytics
#   2. keyvault          (needs RG + Log Analytics)
#   3. groups            (break-glass + groups; premium)
#   4. conditional-access(needs break-glass group object id; premium)
#   5. pim               (needs Privileged-IAM-Admins group object id; premium)
#   6. entitlement       (needs the assigned app-access group ids; governance)
#   7. dc_vm             (needs the VNet + Key Vault from keyvault)
#   8. monitoring        (needs Log Analytics; Entra diagnostics live in bootstrap;
#                         DC01 vm id for the ITDR Security-event DCR)
#   9. intune_vm         (needs the VNet; CA005 pilot group gets VM login when premium)
#  10. apps              (needs the AWS app-access + nurses/pharmacy groups; premium)
#  11. evidence_store    (needs RG + Log Analytics)
#  12. agent runtime UAMI(needs RG)
#
# Post-apply Graph steps the provider cannot express run in the order given
# by lab/scripts/powershell/post-apply/Invoke-PostApply.ps1
# (lab/scripts/README.md, "Post-apply orchestration").
# =============================================================================

# Governance builds on the premium groups - flag the impossible combination.
check "governance_requires_premium" {
  assert {
    condition     = !var.enable_governance || var.enable_premium
    error_message = "enable_governance = true has no effect unless enable_premium = true (access packages hand out the premium-tier groups)."
  }
}

# Access reviews live in modules/entitlement - flag the no-op combination.
check "access_reviews_require_governance" {
  assert {
    condition     = !local.any_access_review_flag || (var.enable_premium && var.enable_governance)
    error_message = "enable_access_reviews / enable_access_reviews_privileged / _requestable / _inactive have no effect unless enable_premium and enable_governance are both true (reviews are rendered by modules/entitlement; PIM-for-Groups reviews need Entra ID Governance)."
  }
}

# The new layers build on premium (and B2B on governance). Each check flags a
# flag that would silently do nothing, so a PR reviewer sees the mistake in
# the plan instead of discovering it on camera.
check "identity_protection_requires_premium" {
  assert {
    condition     = !var.enable_identity_protection_ca || var.enable_premium
    error_message = "enable_identity_protection_ca = true has no effect unless enable_premium = true (CA006/CA007 live in modules/conditional-access, and risk conditions need Entra ID P2 from the M365 E5 trial)."
  }
}

check "phishing_resistant_requires_premium" {
  assert {
    condition     = !var.enable_phishing_resistant_all_users || var.enable_premium
    error_message = "enable_phishing_resistant_all_users = true has no effect unless enable_premium = true (CA008, its authentication strength and the All-Workforce dynamic group are P1)."
  }
}

check "ca_additions_require_premium" {
  assert {
    condition     = !(var.enable_registration_ca || var.enable_device_code_block || var.enable_admin_session_controls || var.enable_pim_auth_context || var.enable_protected_actions_ca || var.enable_shared_clinical_ca) || var.enable_premium
    error_message = "enable_registration_ca / enable_device_code_block / enable_admin_session_controls / enable_pim_auth_context / enable_protected_actions_ca / enable_shared_clinical_ca have no effect unless enable_premium = true (CA009, CA010, CA020, CA021, CA023 and CA060 live in modules/conditional-access; Conditional Access is P1)."
  }
}

check "sso_apps_require_premium" {
  assert {
    condition     = !var.enable_sso_apps || var.enable_premium
    error_message = "enable_sso_apps = true has no effect unless enable_premium = true (the apps are assigned to the premium-tier App-* groups; group assignment to an enterprise app is P1)."
  }
}

check "scim_requires_sso_apps" {
  assert {
    condition     = !var.enable_scim_provisioning || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_scim_provisioning = true has no effect unless enable_premium and enable_sso_apps are both true (the provisioning job belongs to the AWS enterprise app)."
  }
}

check "pam_oidc_app_requires_sso_apps" {
  assert {
    condition     = !var.enable_pam_oidc_app || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_pam_oidc_app = true has no effect unless enable_premium and enable_sso_apps are both true (guacamole-psm lives in modules/apps)."
  }
}

check "claims_viewer_requires_sso_apps" {
  assert {
    condition     = !var.enable_claims_viewer_app || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_claims_viewer_app = true has no effect unless enable_premium and enable_sso_apps are both true (the Claims Viewer app lives in modules/apps)."
  }
}

check "adfs_https_requires_dc" {
  assert {
    condition     = !var.enable_adfs_https || var.enable_dc
    error_message = "enable_adfs_https = true has no effect unless enable_dc is true (the 443 rule is on DC01's NSG)."
  }
}

check "servicenow_sso_requires_sso_apps" {
  assert {
    condition     = !var.enable_servicenow_sso || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_servicenow_sso = true has no effect unless enable_premium and enable_sso_apps are both true (the ServiceNow SAML app lives in modules/apps)."
  }
}

check "servicenow_provisioning_requires_sso_apps" {
  assert {
    condition     = !var.enable_servicenow_provisioning || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_servicenow_provisioning = true has no effect unless enable_premium and enable_sso_apps are both true (the ServiceNow provisioning app lives in modules/apps)."
  }
}

check "clinic_results_requires_sso_apps" {
  assert {
    condition     = !var.enable_clinic_results_app || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_clinic_results_app = true has no effect unless enable_premium and enable_sso_apps are both true (Clinic Lab Results lives in modules/apps, CA061 in modules/conditional-access)."
  }
}

check "okta_federation_requires_sso_apps" {
  assert {
    condition     = !var.enable_okta_federation || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_okta_federation = true has no effect unless enable_premium and enable_sso_apps are both true (okta-clinic-idp lives in modules/apps)."
  }
}

check "b2b_requires_governance" {
  assert {
    condition     = !var.enable_b2b_governance || (var.enable_premium && var.enable_governance)
    error_message = "enable_b2b_governance = true has no effect unless enable_premium and enable_governance are both true."
  }
}

# The AWS admin group is only useful assigned to the AWS app (module.apps).
check "pim_aws_admin_requires_sso_apps" {
  assert {
    condition     = !var.enable_pim_aws_admin || (var.enable_premium && var.enable_sso_apps)
    error_message = "enable_pim_aws_admin = true needs enable_premium and enable_sso_apps: PIM-AWS-Lab-Admins reaches AWS only as a principal of the AWS IAM Identity Center app."
  }
}

check "pim_extensions_require_premium" {
  assert {
    condition     = !(var.enable_pim_tiers || var.enable_pim_azure_resources || var.enable_helpdesk_au_scoping || var.enable_global_admin_pim_policy || var.enable_pim_demo_readers) || var.enable_premium
    error_message = "enable_pim_tiers / enable_pim_azure_resources / enable_helpdesk_au_scoping / enable_global_admin_pim_policy / enable_pim_demo_readers have no effect unless enable_premium = true (modules/pim is premium-tier)."
  }
}

check "nhi_governance_requires_premium" {
  assert {
    condition     = !var.enable_nhi_governance || var.enable_premium
    error_message = "enable_nhi_governance = true has no effect unless enable_premium = true (App-Consent-Reviewers lives in the premium-tier modules/groups)."
  }
}

check "lcw_leaver_trigger_requires_premium" {
  assert {
    condition     = !var.enable_lcw_leaver_trigger || var.enable_premium
    error_message = "enable_lcw_leaver_trigger = true has no effect unless enable_premium = true (the All-Workforce trigger group lives in the premium-tier modules/groups; dynamic groups are P1). New-LifecycleWorkflows.ps1 -IncludeScheduledLeaver will then refuse to run because the group does not exist."
  }
}

# Containment is a Sentinel automation rule: on the Log Analytics path it can
# never fire. modules/monitoring refuses the plan; this states why up front.
check "itdr_containment_requires_sentinel" {
  assert {
    condition     = !var.enable_itdr_containment || (var.enable_itdr_detections && var.enable_sentinel)
    error_message = "enable_itdr_containment = true needs enable_itdr_detections and enable_sentinel (automation rules are Sentinel-only)."
  }
}

# The extended vault columns live on VaultCheckout_CL, which only exists with
# the ITDR telemetry. (enable_itdr_detections_v2 without it is refused by
# modules/monitoring's own validation.)
check "vault_feed_v2_requires_itdr" {
  assert {
    condition     = !var.vault_feed_v2_columns || var.enable_itdr_detections
    error_message = "vault_feed_v2_columns = true has no effect unless enable_itdr_detections = true (VaultCheckout_CL and its DCR are ITDR telemetry)."
  }
}

# Defender for Identity's alerts reach this workspace through the Microsoft
# Defender XDR connector, a Sentinel feature (ADR 0023). modules/monitoring
# refuses the plan on the Log Analytics path; this states why up front. The
# sensor and licence are human steps (the runbook), not a Terraform concern.
check "defender_for_identity_requires_sentinel" {
  assert {
    condition     = !var.enable_defender_for_identity || var.enable_sentinel
    error_message = "enable_defender_for_identity = true needs enable_sentinel (the Microsoft Defender XDR data connector is a Sentinel feature). The sensor on DC01 and the Defender licence are human steps: lab/docs/runbooks/deploy-defender-for-identity-dc01.md."
  }
}

# The Intune VM works without premium (it still Entra-joins), but the CA005
# demo does not: no pilot group, no Intune licence, no Conditional Access.
check "intune_vm_requires_premium" {
  assert {
    condition     = !var.enable_intune_vm || var.enable_premium
    error_message = "enable_intune_vm = true without enable_premium: the VM Entra-joins, but there is no CA005 pilot group (login role, compliance assignment) and Intune auto-enrollment needs the M365 E5 trial (Entra ID P1 + Intune)."
  }
}

# -----------------------------------------------------------------------------
# Shared Azure resources (free tier).
# -----------------------------------------------------------------------------
resource "azurerm_resource_group" "idlab" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_log_analytics_workspace" "idlab" {
  name                = var.log_analytics_name
  location            = var.location
  resource_group_name = azurerm_resource_group.idlab.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

# -----------------------------------------------------------------------------
# Key Vault (RBAC, private endpoint, operator-IP-only firewall, UAMI).
# -----------------------------------------------------------------------------
module "keyvault" {
  source = "../../modules/keyvault"

  key_vault_name                = var.key_vault_name
  resource_group_name           = azurerm_resource_group.idlab.name
  location                      = var.location
  tenant_id                     = var.tenant_id
  log_analytics_workspace_id    = azurerm_log_analytics_workspace.idlab.id
  allowed_ip_ranges             = var.operator_ip_ranges
  secrets_officer_principal_ids = var.key_vault_secrets_officer_ids
  tags                          = var.tags
}

# -----------------------------------------------------------------------------
# Identity cast: break-glass + groups (premium).
# -----------------------------------------------------------------------------
module "groups" {
  source = "../../modules/groups"
  count  = var.enable_premium ? 1 : 0

  break_glass_domain = var.onmicrosoft_domain

  # Optional groups, each behind the flag of the feature that consumes it.
  enable_nhi_governance  = var.enable_nhi_governance                                                # App-Consent-Reviewers
  enable_workforce_group = var.enable_phishing_resistant_all_users || var.enable_lcw_leaver_trigger # All-Workforce (passkey rollout; scheduled leaver trigger)
}

# -----------------------------------------------------------------------------
# Conditional Access (break-glass excluded everywhere; report-only first).
# -----------------------------------------------------------------------------
module "conditional_access" {
  source = "../../modules/conditional-access"
  count  = var.enable_premium ? 1 : 0

  break_glass_group_object_id = module.groups[0].break_glass_group_object_id
  ca005_pilot_group_object_id = module.groups[0].ca005_pilot_group_object_id
  policy_states               = var.ca_policy_states
  blocked_countries           = var.blocked_countries

  # CA006 / CA007: risk-based policies (Entra ID P2). Break-glass excluded.
  enable_identity_protection_ca = var.enable_identity_protection_ca
  sign_in_risk_block_levels     = var.sign_in_risk_block_levels

  # CA008: phishing-resistant for the workforce. Report-only measures the
  # registration gap; enforcement starts in pilot scope, and all-users
  # enforcement needs the second key.
  enable_phishing_resistant_all_users = var.enable_phishing_resistant_all_users
  ca008_scope                         = var.ca008_scope
  ca008_allow_all_users_enforcement   = var.ca008_allow_all_users_enforcement
  ca008_pilot_group_object_id         = var.ca008_pilot_group_object_id # literal id or "" (module creates the group)
  admin_fido2_allowed_aaguids         = var.admin_fido2_allowed_aaguids
  accept_admin_synced_passkey_risk    = var.accept_admin_synced_passkey_risk

  # CA022 (numbered CA009 before the CA design-principle ranges): the PSM
  # stand-in (guacamole-psm) + admin portals need the ADMIN strength. Same
  # flag as the app itself: no PAM SSO app, no CA022.
  enable_pam_session_ca = var.enable_pam_oidc_app
  pam_session_app_ids   = var.enable_pam_oidc_app && var.enable_sso_apps ? [module.apps[0].guacamole_psm_client_id] : []

  # CA002 / CA020 also include every PIM-governed admin group BY GROUP
  # (Privileged-IAM-Admins, the tier groups - incl. the AU-scoped
  # PIM-Tier1-Helpdesk - and the Azure PIM group): role assignments scoped
  # to an administrative unit are invisible to CA's directory-role
  # condition, and group-held roles may be too (verify:).
  # WHO THAT ADDS: the PIM-for-Groups groups have no standing members, so
  # from them only whoever ACTIVATED. PIM-Azure-RG-Contributors is different
  # (modules/pim azure.tf): its members are STANDING (the group, not the
  # person, is eligible for Contributor on the DC's RG), so with
  # enable_pim_azure_resources every member is in CA002 (admin strength on
  # All resources) and CA020 at EVERY sign-in. Kept on purpose - Contributor
  # there is Tier 0 - so before CA002 is enforced each member must be an
  # adm- account with an issued passkey: the group is an admin passkey target
  # (Set-AuthenticationMethodsPolicy.ps1 default) and the pre-enforcement
  # check is 07-Passwordless-Rollout.ps1 -PilotGroupMailNicknames
  # pim-azure-rg-contributors.
  admin_scope_group_object_ids = module.pim[0].privileged_review_targets

  # CA009 register security info (one-time TAP or phishing-resistant);
  # CA010 block device code flow (breaks `az login --use-device-code` once
  # ENFORCED - see the variable). Exception groups sit NEXT TO break-glass.
  enable_registration_ca           = var.enable_registration_ca
  enable_device_code_block         = var.enable_device_code_block
  ca010_exception_group_object_ids = var.ca010_exception_group_object_ids

  # CA020 admin-portal sign-in frequency. Its role list IS the PIM tier map
  # (modules/pim output, known at plan), so a role added to a tier is
  # covered here too - one list, no drift. Sorted: a stable order for the
  # provider's list attribute.
  enable_admin_session_controls   = var.enable_admin_session_controls
  admin_session_role_template_ids = sort(distinct(concat(module.pim[0].privileged_role_template_ids["tier0"], module.pim[0].privileged_role_template_ids["tier1"])))

  # CA021 PIM activation step-up on auth context c1 (rendered here, written
  # by post-apply/Set-AuthContextPolicies.ps1). The same root value goes to
  # modules/pim; this module refuses it until CA021 is declared enabled AND
  # attested in the tenant (ca021_enforced_in_tenant, a later change).
  enable_pim_auth_context              = var.enable_pim_auth_context
  pim_tier0_activation_auth_context_id = var.pim_tier0_activation_auth_context_id
  ca021_enforced_in_tenant             = var.ca021_enforced_in_tenant

  # CA023 protected actions (CA policy / named-location changes) step-up on
  # auth context c2 - same Graph path as CA021; report-only by default.
  enable_protected_actions_ca = var.enable_protected_actions_ca

  # CA060 shared clinical workstations (ADR 0014): needs the CA008 workforce
  # strength (enable_phishing_resistant_all_users). Never All users.
  enable_shared_clinical_ca       = var.enable_shared_clinical_ca
  ca060_clinical_group_object_ids = [module.groups[0].all_nurses_group_object_id, module.groups[0].all_icu_group_object_id]

  # CA061 Clinic Lab Results (Okta -> Entra wave 1): the same flag as the app
  # itself - no app, no CA061. One app, its one group.
  enable_clinic_results_ca = var.enable_clinic_results_app && var.enable_sso_apps
  ca061_app_ids            = var.enable_clinic_results_app && var.enable_sso_apps ? [module.apps[0].clinic_results_client_id] : []
  ca061_group_object_ids   = var.enable_clinic_results_app && var.enable_sso_apps ? [module.apps[0].clinic_results_users_group_object_id] : []
}

# -----------------------------------------------------------------------------
# PIM (group actively holds the role; membership is just-in-time).
# -----------------------------------------------------------------------------
module "pim" {
  source = "../../modules/pim"
  count  = var.enable_premium ? 1 : 0

  priv_iam_admins_group_object_id = module.groups[0].priv_iam_admins_group_object_id
  require_approval                = var.pim_require_approval
  approver_object_ids             = var.pim_approver_object_ids # members of PIM-Approvers-Tier1

  # Tier groups (8 Tier 0, 8 Tier 1 - modules/pim pim_tier_groups) and the
  # security mailbox PIM's admin notifications go to.
  enable_pim_tiers          = var.enable_pim_tiers
  tier0_approver_object_ids = var.pim_tier0_approver_object_ids # members of PIM-Approvers-Tier0
  pim_alert_mailbox         = var.pim_alert_mailbox

  # Help-desk scoping (AU-Workforce-Standard) and Global Administrator's own
  # PIM policy (rendered for post-apply/Set-DirectoryRolePimPolicies.ps1).
  enable_helpdesk_au_scoping         = var.enable_helpdesk_au_scoping
  workforce_au_excluded_employee_ids = var.helpdesk_au_excluded_employee_ids
  enable_global_admin_pim_policy     = var.enable_global_admin_pim_policy

  # Tier-0 activation step-up (CA021). Two gates: this module's
  # preconditions, and modules/conditional-access's output precondition on
  # the same value. activation_auth_context_ca_enforced is ONLY ever wired
  # from the CA module (never hand-set).
  tier0_activation_auth_context_id    = var.pim_tier0_activation_auth_context_id
  tier0_auth_context_switchover_step1 = var.pim_tier0_auth_context_switchover_step1
  activation_auth_context_ca_enforced = module.conditional_access[0].pim_activation_auth_context_ready

  # Quarterly review of PIM-eligible membership (+ GA eligibility). Same
  # reviewer/fallback groups as modules/entitlement, so the bodies agree;
  # they only reach the post-apply script through modules/entitlement's
  # access_review_definitions, under enable_access_reviews_privileged.
  privileged_review_reviewer_group_object_id = var.privileged_review_reviewer_group_object_id
  privileged_review_fallback_group_object_id = local.access_review_fallback_group_object_id

  # PIM for Azure resources: group eligible for Contributor on the lab RG.
  enable_pim_azure_resources = var.enable_pim_azure_resources
  azure_pim_scope_id         = azurerm_resource_group.idlab.id

  # AWS admin as a PIM-for-Groups activation (ADR 0025). The group is
  # assigned to the AWS app in module.apps below; it stays out of the CA002 /
  # CA020 scope (privileged_review_targets) on purpose.
  enable_pim_aws_admin = var.enable_pim_aws_admin

  # Read-only presenter access (modules/pim demo-readers.tf): PIM-Demo-Readers
  # actively holds Global Reader + Security Reader, membership eligible-only.
  # Like PIM-AWS-Lab-Admins it is reviewed quarterly but stays out of the
  # CA002 / CA020 scope. Its Azure read roles are granted in envs/bootstrap
  # (output pim_demo_readers_group_object_id), not here: APPLY may not.
  enable_pim_demo_readers = var.enable_pim_demo_readers
}

# -----------------------------------------------------------------------------
# Entitlement management (access packages + 180-day policies) (governance).
# -----------------------------------------------------------------------------
module "entitlement" {
  source = "../../modules/entitlement"
  count  = var.enable_premium && var.enable_governance ? 1 : 0

  catalog_group_object_ids = module.groups[0].app_access_group_object_ids
  approver_group_object_id = var.entitlement_approver_group_object_id

  # Risk-tiered reviews (ADR 0012), one flag per tier; the root
  # enable_access_reviews shorthand turns all three on. The module's own
  # deprecated alias is no longer passed. No flag ever reviews a T3
  # birthright clinical package.
  enable_access_reviews_privileged       = local.access_reviews_privileged
  enable_access_reviews_requestable      = local.access_reviews_requestable
  enable_access_reviews_inactive         = local.access_reviews_inactive
  access_review_fallback_group_object_id = var.access_review_fallback_group_object_id

  # Standalone reviews (rendered per flag, created by
  # post-apply/New-AccessReviewDefinitions.ps1): every PIM-governed group
  # (eligible + active members) - modules/pim renders the same bodies and its
  # GA-eligibility review, merged here (on a key clash the PIM body wins, one
  # series per group) - and inactive Okta-federated users, a group no access
  # package owns, so a removal never orphans a package assignment.
  privileged_review_group_object_ids         = module.pim[0].privileged_review_targets
  privileged_review_reviewer_group_object_id = var.privileged_review_reviewer_group_object_id
  pim_eligible_review_bodies                 = module.pim[0].pim_eligible_review_bodies
  inactive_review_group_object_ids = {
    "App-Okta-Federation-Users" = module.groups[0].app_access_group_object_ids["okta"]
  }

  # Guard only: a default-deny review that names break-glass would remove the
  # recovery path (ADR 0012) - the review outputs refuse it.
  break_glass_group_object_id = module.groups[0].break_glass_group_object_id

  # B2B guest governance: Affiliated Physicians package (off by default).
  enable_b2b_governance         = var.enable_b2b_governance
  b2b_connected_organization    = var.b2b_connected_organization
  b2b_connected_organization_id = var.b2b_connected_organization_id
}

# -----------------------------------------------------------------------------
# AD DS domain controller (the on-prem half of HR -> AD -> Cloud Sync -> Entra).
# Promotion is done by lab/scripts/dc/*.ps1 via az vm run-command.
# -----------------------------------------------------------------------------
module "dc_vm" {
  source = "../../modules/dc-vm"
  count  = var.enable_dc ? 1 : 0

  resource_group_name = azurerm_resource_group.idlab.name
  location            = var.location
  vnet_name           = module.keyvault.vnet_name
  key_vault_id        = module.keyvault.key_vault_id
  allowed_ip_ranges   = var.operator_ip_ranges
  vm_size             = var.dc_vm_size
  # 443 to DC01 only for the temporary AD FS exercise (lab/adfs).
  adfs_https_enabled = var.enable_adfs_https
  tags               = var.tags
}

# -----------------------------------------------------------------------------
# Windows 11 "compliant device": Entra joined + auto-enrolled in Intune by the
# AADLoginForWindows extension. The device that satisfies CA005 once
# lab/scripts/intune/New-IntuneComplianceBaseline.ps1 marks it compliant.
# Azure compute cost (no trial clock of its own); the Intune/CA demo needs
# enable_premium (M365 E5 trial). Members of the CA005 pilot group get
# "Virtual Machine Administrator Login" so they RDP in with Entra credentials.
# -----------------------------------------------------------------------------
module "intune_vm" {
  source = "../../modules/intune-vm"
  count  = var.enable_intune_vm ? 1 : 0

  resource_group_name         = azurerm_resource_group.idlab.name
  location                    = var.location
  vnet_name                   = module.keyvault.vnet_name
  allowed_ip_ranges           = var.operator_ip_ranges
  vm_size                     = var.intune_vm_size
  admin_login_user_object_ids = var.intune_vm_admin_login_object_ids

  # Static map key so for_each is plannable while the group id is unknown.
  admin_login_group_object_ids = var.enable_premium ? { ca005_pilot = module.groups[0].ca005_pilot_group_object_id } : {}

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Detections as code (lab/kql) - Sentinel during the trial, Log Analytics
# alerts after it. Creates nothing until a flag is on.
# -----------------------------------------------------------------------------
module "monitoring" {
  source = "../../modules/monitoring"

  resource_group_name        = azurerm_resource_group.idlab.name
  location                   = var.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.idlab.id
  enable_sentinel            = var.enable_sentinel
  enable_la_alerts           = var.enable_la_alerts
  alert_email                = var.alert_email
  playbook_logic_app_id      = var.sentinel_playbook_id

  # ITDR: eleven identity-attack rules + their telemetry (vault check-out
  # feed, DC01 Security events). collect_dc_security_events takes a
  # PLAN-TIME boolean (enable_dc); the VM id itself is unknown on the first
  # plan and only feeds the DCR association.
  enable_itdr_detections     = var.enable_itdr_detections
  itdr_exclude_rules         = var.itdr_exclude_rules
  enable_itdr_containment    = var.enable_itdr_containment
  containment_playbook_id    = var.containment_playbook_id
  containment_rule_keys      = var.containment_rule_keys
  collect_dc_security_events = var.enable_itdr_detections && var.enable_dc
  dc_vm_id                   = var.enable_dc ? module.dc_vm[0].vm_id : ""
  containment_on_alert_added = var.containment_on_alert_added

  # Second- and third-wave rules + the extended vault feed columns (each its
  # own flag).
  enable_itdr_detections_v2 = var.enable_itdr_detections_v2
  enable_itdr_detections_v3 = var.enable_itdr_detections_v3
  vault_feed_v2_columns     = var.vault_feed_v2_columns

  # Defender for Identity (ADR 0023): the native AD-attack detector. The flag
  # only adds the Defender XDR connector that lands MDI alerts in this
  # workspace; the sensor on DC01 and the licence are human steps (runbook).
  enable_defender_for_identity = var.enable_defender_for_identity

  # operator_ips watchlist (Sentinel + v2): the hosts DC01's NSG admits, so
  # only while enable_dc - otherwise the list (which may then hold a /24 for
  # the vault firewall) means nothing for DC01. Sensitive end to end; rows
  # expire on ADR 0013's review date.
  operator_ip_ranges      = var.enable_dc ? var.operator_ip_ranges : []
  operator_ips_expires_on = var.operator_ips_expires_on

  # Identities the ITDR rules judge by IMMUTABLE id (rendered into the KQL):
  # the APPLY identity (envs/bootstrap output iac_principal_ids -> TF_IAC_
  # PRINCIPAL_IDS), the role-holding groups this config creates, and the
  # privileged users (break-glass + the Find-ShadowAdmins export).
  iac_principal_ids     = var.iac_principal_ids
  privileged_group_ids  = local.itdr_privileged_group_ids
  break_glass_group_ids = var.enable_premium ? [module.groups[0].break_glass_group_object_id] : []
  # PIM-Azure-RG-Contributors: standing members are its intended path (the
  # group is eligible for the Azure role) - reported on its own, Medium path.
  azure_pim_group_ids = var.enable_premium ? [for g in [module.pim[0].azure_pim_group_object_id] : g if g != null] : []
  privileged_user_ids = distinct(concat(
    var.enable_premium ? module.groups[0].break_glass_user_object_ids : [],
    var.privileged_user_object_ids,
  ))

  tags = var.tags
}

locals {
  # Every group in this config that HOLDS a role or is PIM-governed: a member
  # added to one outside PIM is standing Tier-0
  # (pim-group-member-added-outside-pim.kql). The role-assignable PIM
  # approver groups are watched too: their members approve Tier-0
  # activations, and membership changes only through a Terraform PR (an add
  # by the APPLY identity, matched by id, is Medium; by anyone else, High).
  itdr_privileged_group_ids = var.enable_premium ? concat(
    [module.groups[0].break_glass_group_object_id, module.groups[0].priv_iam_admins_group_object_id],
    values(module.pim[0].tier_group_object_ids),
    [for g in [module.pim[0].azure_pim_group_object_id] : g if g != null],
    # PIM-AWS-Lab-Admins (ADR 0025): members arrive only by PIM activation
    # (written by MS-PIM), so a direct add is a way around the 2-hour,
    # MFA + reason activation into AWS admin. Watched here, but deliberately
    # NOT in the CA002/CA020 scope (privileged_review_targets).
    var.enable_pim_aws_admin ? [module.pim[0].aws_admin_group_object_id] : [],
    # PIM-Demo-Readers: members arrive only by PIM activation, so a direct
    # add is standing Global Reader + Security Reader (BitLocker key read
    # included) without the MFA + reason activation. Watched, not in CA scope.
    var.enable_pim_demo_readers ? [module.pim[0].demo_readers_group_object_id] : [],
    values(module.pim[0].approver_group_object_ids),
  ) : []

  # ---- Access reviews (ADR 0012) -------------------------------------------
  # The root shorthand enable_access_reviews means all three tiers.
  access_reviews_privileged  = var.enable_access_reviews || var.enable_access_reviews_privileged
  access_reviews_requestable = var.enable_access_reviews || var.enable_access_reviews_requestable
  access_reviews_inactive    = var.enable_access_reviews || var.enable_access_reviews_inactive
  any_access_review_flag     = local.access_reviews_privileged || local.access_reviews_requestable || local.access_reviews_inactive

  # One fallback reviewer group for every review, in both modules that
  # render one (modules/entitlement applies the same rule internally).
  access_review_fallback_group_object_id = (
    var.access_review_fallback_group_object_id != ""
    ? var.access_review_fallback_group_object_id
    : var.entitlement_approver_group_object_id
  )
}

# -----------------------------------------------------------------------------
# SSO + provisioning as code (premium): AWS IAM Identity Center SAML (+ SCIM,
# staged), the Contoso Clinical Portal OIDC app, and (enable_pam_oidc_app)
# guacamole-psm for the PSM stand-in. Needs the APPLY identity's app
# management Graph roles (envs/bootstrap enable_app_management_roles).
# -----------------------------------------------------------------------------
module "apps" {
  source = "../../modules/apps"
  count  = var.enable_premium && var.enable_sso_apps ? 1 : 0

  # The two principals on the AWS app = the SCIM scope: the staff group
  # (ViewOnlyAccess in AWS) and, with enable_pim_aws_admin, the PIM admin
  # group (LabAdministrator in AWS, ADR 0025). module.pim exists whenever
  # this module does (both need enable_premium).
  aws_users_group_object_id    = module.groups[0].app_access_group_object_ids["aws"]
  enable_aws_admins_assignment = var.enable_pim_aws_admin
  aws_admins_group_object_id   = var.enable_pim_aws_admin ? module.pim[0].aws_admin_group_object_id : ""

  aws_saml_entity_id                    = var.aws_saml_entity_id
  saml_signing_cert_end_date            = var.saml_signing_cert_end_date
  servicenow_saml_signing_cert_end_date = var.servicenow_saml_signing_cert_end_date
  aws_saml_acs_urls                     = var.aws_saml_acs_urls
  aws_access_portal_url                 = var.aws_access_portal_url
  saml_cert_notification_emails         = var.saml_cert_notification_emails
  app_owner_object_ids                  = var.app_owner_object_ids
  iac_owner_client_id                   = var.apply_client_id

  enable_scim_provisioning = var.enable_scim_provisioning
  aws_scim_template_id     = var.aws_scim_template_id
  aws_scim_job_enabled     = var.aws_scim_job_enabled
  aws_scim_credentials     = var.aws_scim_credentials
  require_scim_credentials = var.require_scim_credentials

  # Static keys keep for_each plannable while the group ids are unknown.
  # Same SoD pair as the access packages: nurses are Clinicians, the
  # dispensing group is Pharmacist - never both through one grant.
  clinical_portal_role_assignments = {
    nurses_clinician    = { role = "Clinician", principal_object_id = module.groups[0].all_nurses_group_object_id }
    pharmacy_pharmacist = { role = "Pharmacist", principal_object_id = module.groups[0].app_access_group_object_ids["pharmacy_dispensing"] }
  }

  enable_guacamole_psm_app = var.enable_pam_oidc_app

  # E25 demo only (default false): lets `az account get-access-token` request
  # Clinical.Read so the roles/groups claims can be shown from a real token.
  clinical_portal_preauthorize_azure_cli = var.clinical_portal_preauthorize_azure_cli

  # ServiceNow PDI SAML app (default false). The ONE principal on it is
  # App-ServiceNow-Users - also the ONLY principal on the provisioning app
  # (enable_servicenow_provisioning), so sign-in and accounts share one scope.
  enable_servicenow_sso            = var.enable_servicenow_sso
  servicenow_instance_url          = var.servicenow_instance_url
  servicenow_sso_sys_id            = var.servicenow_sso_sys_id
  servicenow_users_group_object_id = module.groups[0].app_access_group_object_ids["servicenow"]

  # ServiceNow provisioning (default false): gallery app, job STOPPED unless
  # servicenow_provisioning_job_enabled, credential from Key Vault in the
  # local seeding apply only (fails closed in CI via require_scim_credentials).
  enable_servicenow_provisioning      = var.enable_servicenow_provisioning
  servicenow_provisioning_job_enabled = var.servicenow_provisioning_job_enabled
  servicenow_provisioning_credentials = var.servicenow_provisioning_credentials

  # ServiceNow access fulfilment (default false): the app ServiceNow uses to
  # add/remove people on Clinical access packages after a manager approves in
  # ServiceNow. No Graph permission; one catalog role on the Clinical catalog.
  # Without governance there is no catalog, so the flag needs both.
  enable_servicenow_fulfilment     = var.enable_servicenow_fulfilment && var.enable_governance
  servicenow_fulfilment_catalog_id = var.enable_servicenow_fulfilment && var.enable_governance ? module.entitlement[0].catalog_id : ""

  # okta-clinic-idp (default false): Entra as the OIDC identity provider for
  # the acquired clinic's Okta org (runbook Phase 1, ADR 0022). The ONE
  # principal on it is App-Okta-Federation-Users; the client secret is a
  # human's post-apply step, and the Okta side is lab/terraform/okta.
  enable_okta_federation                = var.enable_okta_federation
  okta_org_domain                       = var.okta_org_domain
  okta_federation_users_group_object_id = module.groups[0].app_access_group_object_ids["okta"]

  # Clinic Lab Results (default false): the first app moved off the clinic's
  # Okta (lab/okta-migration wave 1). Its group lives in this module, like
  # PAM-Operators; CA061 above targets it.
  enable_clinic_results_app = var.enable_clinic_results_app

  # Contoso Claims Viewer (default false): the app migrated off AD FS
  # (lab/adfs, ADR 0009 phase 3). Its two groups come from AD through Cloud
  # Sync, so their ids are inputs, not module.groups outputs.
  enable_claims_viewer_app                 = var.enable_claims_viewer_app
  claims_viewer_clinicians_group_object_id = var.claims_viewer_clinicians_group_object_id
  claims_viewer_admins_group_object_id     = var.claims_viewer_admins_group_object_id
  claims_viewer_saml_signing_cert_end_date = var.claims_viewer_saml_signing_cert_end_date
}

# -----------------------------------------------------------------------------
# WORM evidence store (free tier; Azure storage cost). Writers/readers are
# deliberately NOT granted here: the APPLY identity cannot (and must not) hand
# out storage data roles - envs/bootstrap delegable_role_ids would otherwise
# reach the Terraform state containers. A human grants the writer role with
# output evidence_writer_abac_condition (module header).
# -----------------------------------------------------------------------------
module "evidence_store" {
  source = "../../modules/evidence-store"
  count  = var.enable_evidence_store ? 1 : 0

  storage_account_name           = var.evidence_storage_account_name
  resource_group_name            = azurerm_resource_group.idlab.name
  location                       = var.location
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.idlab.id
  allowed_ip_ranges              = var.operator_ip_ranges
  immutability_period_days       = var.evidence_immutability_days
  immutability_state             = var.evidence_immutability_state
  immutability_lock_acknowledged = var.evidence_immutability_lock_acknowledged
  tags                           = var.tags
}

# -----------------------------------------------------------------------------
# Entra Agent ID runtime identity (enable_agent_identity). A user-assigned
# managed identity that post-apply/New-AgentIdentity.ps1 names as the subject
# of the agent blueprint's federated credential - so the agent authenticates
# with a platform-issued token and there is NO secret to leak or rotate.
#
# Why dedicated (not uami-kv-reader from modules/keyvault): one identity per
# workload, so a compromised agent runtime cannot read Key Vault and a Key
# Vault reader cannot act as the agent (OWASP NHI9, identity reuse).
# Why NO role assignments here: the agent's permissions are granted to the
# AGENT IDENTITY in Entra, explicitly and reviewably, never inherited from the
# Azure host identity.
# -----------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "agent_runtime" {
  count = var.enable_agent_identity ? 1 : 0

  name                = "uami-agent-runtime"
  location            = var.location
  resource_group_name = azurerm_resource_group.idlab.name
  tags                = var.tags
}
