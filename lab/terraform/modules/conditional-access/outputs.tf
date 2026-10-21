# =============================================================================
# modules/conditional-access :: outputs.tf
# =============================================================================

output "policy_ids" {
  description = <<-EOT
    Map of logical policy name => Conditional Access policy id for every
    Terraform-managed policy (CA001..CA010, CA020, CA022, CA060). Flagged
    policies are null while their staging flag is off. CA021 is not here: it
    is Graph-managed (output pim_auth_context_requests), so Terraform never
    knows its id.
  EOT
  value = {
    require_mfa_all_users          = azuread_conditional_access_policy.require_mfa_all_users.id
    admin_phishing_resistant       = azuread_conditional_access_policy.admin_phishing_resistant.id
    block_legacy_auth              = azuread_conditional_access_policy.block_legacy_auth.id
    block_countries                = azuread_conditional_access_policy.block_countries.id
    admin_portals_compliant_device = azuread_conditional_access_policy.admin_portals_compliant_device.id
    user_risk_high_remediation     = one(azuread_conditional_access_policy.user_risk_high_remediation[*].id)
    sign_in_risk_block             = one(azuread_conditional_access_policy.sign_in_risk_block[*].id)
    phishing_resistant_all_users   = one(azuread_conditional_access_policy.phishing_resistant_all_users[*].id)
    register_security_info         = one(azuread_conditional_access_policy.register_security_info[*].id)
    block_device_code_flow         = one(azuread_conditional_access_policy.block_device_code_flow[*].id)
    admin_session_controls         = one(azuread_conditional_access_policy.admin_session_controls[*].id)
    pam_session_admin_strength     = one(azuread_conditional_access_policy.pam_session_admin_strength[*].id)
    shared_clinical_workstation    = one(azuread_conditional_access_policy.shared_clinical_workstation[*].id)
  }
}

output "policy_display_names" {
  description = <<-EOT
    CA key => display name as deployed (null while a flagged policy is off).
    Evidence scripts and detections should match on these (SigninLogs
    ConditionalAccessPolicies[].displayName), not on hand-copied strings -
    CA007's name follows sign_in_risk_block_levels, CA008's its scope/state,
    CA020's its frequency. CA021 and CA023 are the names Terraform RENDERS;
    they exist in the tenant only after post-apply/Set-AuthContextPolicies.ps1
    has run.
  EOT
  value = {
    CA001 = azuread_conditional_access_policy.require_mfa_all_users.display_name
    CA002 = azuread_conditional_access_policy.admin_phishing_resistant.display_name
    CA003 = azuread_conditional_access_policy.block_legacy_auth.display_name
    CA004 = azuread_conditional_access_policy.block_countries.display_name
    CA005 = azuread_conditional_access_policy.admin_portals_compliant_device.display_name
    CA006 = one(azuread_conditional_access_policy.user_risk_high_remediation[*].display_name)
    CA007 = one(azuread_conditional_access_policy.sign_in_risk_block[*].display_name)
    CA008 = one(azuread_conditional_access_policy.phishing_resistant_all_users[*].display_name)
    CA009 = one(azuread_conditional_access_policy.register_security_info[*].display_name)
    CA010 = one(azuread_conditional_access_policy.block_device_code_flow[*].display_name)
    CA020 = one(azuread_conditional_access_policy.admin_session_controls[*].display_name)
    CA021 = var.enable_pim_auth_context ? local.ca021_display_name : null
    CA022 = one(azuread_conditional_access_policy.pam_session_admin_strength[*].display_name)
    CA023 = var.enable_protected_actions_ca ? local.ca023_display_name : null
    CA060 = one(azuread_conditional_access_policy.shared_clinical_workstation[*].display_name)
  }
}

output "policy_states" {
  description = "Effective state per policy key (CA001..CA010, CA020..CA023, CA060) after defaults - handy to confirm what a lab.tfvars PR changes. A key for a flagged-off policy is listed but deploys nothing."
  value       = var.policy_states
}

output "authentication_strength_policy_id" {
  description = "Id of the custom ADMIN phishing-resistant authentication strength (CA002)."
  value       = azuread_authentication_strength_policy.phishing_resistant.id
}

output "workforce_authentication_strength_policy_id" {
  description = "Id of the WORKFORCE phishing-resistant authentication strength (CA008); null while enable_phishing_resistant_all_users is off."
  value       = one(azuread_authentication_strength_policy.phishing_resistant_workforce[*].id)
}

output "ca008_pilot_group_object_id" {
  description = "Object id of the CA008 pilot group (module-created CA008-Pilot-PhishingResistant, or the supplied group); null while CA008 is off. The registration campaign adds pilot members to it."
  value       = var.enable_phishing_resistant_all_users ? local.ca008_pilot_group_object_id : null
}

output "ca008_scope" {
  description = "Who CA008 includes (all_users = measure/enforce tenant-wide, pilot = the pilot group only); null while CA008 is off."
  value       = var.enable_phishing_resistant_all_users ? var.ca008_scope : null
}

output "blocked_named_location_id" {
  description = "Object id (GUID) of the blocked-countries named location."
  value       = azuread_named_location.blocked_countries.object_id
}

output "registration_authentication_strength_policy_id" {
  description = "Id of the bootstrap-and-recovery strength (one-time TAP or phishing-resistant) CA009 requires; null while enable_registration_ca is off."
  value       = one(azuread_authentication_strength_policy.bootstrap_recovery[*].id)
}

output "admin_role_template_ids" {
  description = "Directory role template ids CA002 targets (Microsoft's template list + lab extras) - for the baseline assessment (ScubaGear MS.AAD.3.6 highly privileged roles) and the evidence pack."
  value       = var.admin_role_template_ids
}

# -----------------------------------------------------------------------------
# CA021 (Graph-managed) - input for post-apply/Set-AuthContextPolicies.ps1:
#   terraform output -json pim_auth_context_requests > ca021.json
#   ./Set-AuthContextPolicies.ps1 -RequestsPath ./ca021.json -WhatIf
# The two bodies are JSON STRINGS (exactly what is sent; the script parses
# them), built from real ids: break-glass group, admin strength object id.
# -----------------------------------------------------------------------------
output "pim_auth_context_requests" {
  description = "Graph v1.0 request bodies for the PIM activation authentication context (auth_context_body -> PATCH .../authenticationContextClassReferences/<auth_context_id>) and CA021 (policy_body, matched by policy_match_prefix). null while enable_pim_auth_context is off - the script then refuses to run."
  value       = local.pim_auth_context_requests

  precondition {
    condition     = !var.enable_pim_auth_context || contains(keys(var.policy_states), "CA021")
    error_message = "enable_pim_auth_context = true requires an explicit CA021 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
  }
}

# CA023 (Graph-managed) - same shape as pim_auth_context_requests, for the same
# script: ./Set-AuthContextPolicies.ps1 -RequestsPath <this output as JSON>.
output "protected_actions_auth_context_requests" {
  description = "Graph v1.0 request bodies for the protected-actions authentication context (auth_context_body) and CA023 (policy_body, matched by policy_match_prefix). null while enable_protected_actions_ca is off. Binding the context to the protected actions is a tenant-time step (admins.tf)."
  value       = local.protected_actions_auth_context_requests

  precondition {
    condition     = !var.enable_protected_actions_ca || contains(keys(var.policy_states), "CA023")
    error_message = "enable_protected_actions_ca = true requires an explicit CA023 entry in policy_states (lab.tfvars ca_policy_states) so the reviewer sees its state."
  }
  precondition {
    condition     = !var.enable_protected_actions_ca || var.protected_actions_auth_context_id != var.pim_auth_context_id
    error_message = "protected_actions_auth_context_id must differ from pim_auth_context_id: CA021 (PIM activation) and CA023 (protected actions) are separate contexts with separate policies."
  }
}

output "pim_activation_auth_context_id" {
  description = "Authentication context id for modules/pim tier0_activation_auth_context_id: the id once CA021 is declared ENFORCED (enable_pim_auth_context + policy_states CA021 = enabled) AND attested in the tenant (ca021_enforced_in_tenant), \"\" otherwise."
  value       = local.pim_activation_auth_context_ready ? var.pim_auth_context_id : ""
}

output "pim_activation_auth_context_ready" {
  description = "true when CA021 is declared enforced in code (enable_pim_auth_context and policy_states CA021 = enabled) AND ca021_enforced_in_tenant attests that Set-AuthContextPolicies.ps1 already wrote the enforced CA021 (after an earlier apply). Wired to modules/pim activation_auth_context_ca_enforced."
  value       = local.pim_activation_auth_context_ready

  # The ordering gate (Learn: enable the CA policy BEFORE PIM requires the
  # context). The caller passes the value it gives modules/pim.
  precondition {
    condition = var.pim_tier0_activation_auth_context_id == "" || (
      local.pim_activation_auth_context_ready && var.pim_tier0_activation_auth_context_id == var.pim_auth_context_id
    )
    error_message = "modules/pim would require authentication context '${var.pim_tier0_activation_auth_context_id}' for Tier-0 activation, but CA021 is not ENFORCED on that context in the tenant (needs enable_pim_auth_context = true, policy_states CA021 = \"enabled\", pim_auth_context_id = '${var.pim_tier0_activation_auth_context_id}' AND ca021_enforced_in_tenant = true - set only in a later change, after post-apply/Set-AuthContextPolicies.ps1 reported CA021 enabled). Keep the PIM value \"\" until then."
  }
  # The attestation must not contradict the code: an attested-enforced CA021
  # that the code declares report-only would be rewritten report-only by the
  # next post-apply run while PIM keeps pointing at the context.
  precondition {
    condition     = !var.ca021_enforced_in_tenant || (var.enable_pim_auth_context && local.ca021_state == "enabled")
    error_message = "ca021_enforced_in_tenant = true, but the code does not declare CA021 enabled (enable_pim_auth_context = true and policy_states CA021 = \"enabled\"). The next Set-AuthContextPolicies.ps1 run would write CA021 back to that state while PIM still requires the context. Set ca021_enforced_in_tenant = false first (and the PIM context back to \"\")."
  }
}
