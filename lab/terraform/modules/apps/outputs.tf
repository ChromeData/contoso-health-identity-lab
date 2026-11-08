# =============================================================================
# modules/apps :: outputs.tf
# -----------------------------------------------------------------------------
# Identifiers only - no credential is ever output (the signing certificate's
# private key never leaves Entra; the provisioning credentials - AWS SCIM
# token, ServiceNow integration password - are write-only here). The
# *_command outputs are the exact tenant-time steps the provider cannot do,
# printed with the real ids so nobody copies a GUID by hand.
# =============================================================================

# ---- AWS IAM Identity Center (SAML) -----------------------------------------

output "aws_application_object_id" {
  description = "Object id of the AWS IAM Identity Center app registration."
  value       = azuread_application_from_template.aws.application_object_id
}

output "aws_client_id" {
  description = "Client (application) id of the AWS IAM Identity Center app."
  value       = data.azuread_application.aws.client_id
}

output "aws_service_principal_object_id" {
  description = "Object id of the AWS IAM Identity Center enterprise app (04-Leaver.ps1 finds it by display name; this is the id behind it)."
  value       = azuread_service_principal.aws.object_id
}

output "aws_federation_metadata_url" {
  description = "Entra IdP metadata for this app - upload to AWS (Change identity source -> IdP SAML metadata). Re-upload after every signing-certificate change."
  value       = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${data.azuread_application.aws.client_id}"
}

output "aws_saml_signing_cert_thumbprint" {
  description = "Thumbprint of the Entra-minted SAML signing certificate (must be made the preferred signing key - see the activation command)."
  value       = azuread_service_principal_token_signing_certificate.aws.thumbprint
}

output "aws_saml_signing_cert_end_date" {
  description = "When the SAML signing certificate expires - the date a rotation (and AWS metadata re-upload) must happen before."
  value       = azuread_service_principal_token_signing_certificate.aws.end_date
}

output "aws_saml_signing_cert_activation_command" {
  description = "POST-APPLY (tenant time): make the new certificate the active SAML signing key. azuread 3.10 cannot set preferredTokenSigningKeyThumbprint. Needs Connect-MgGraph -Scopes Application.ReadWrite.All."
  value       = "Update-MgServicePrincipal -ServicePrincipalId ${azuread_service_principal.aws.object_id} -PreferredTokenSigningKeyThumbprint ${azuread_service_principal_token_signing_certificate.aws.thumbprint}"
}

output "aws_claims_mapping_policy_id" {
  description = "Claims-mapping policy on the AWS app (null when aws_saml_claims_policy_enabled = false)."
  value       = one(azuread_claims_mapping_policy.aws[*].id)
}

output "aws_assigned_group_object_id" {
  description = "The staff principal assigned to the AWS app (App-AWS-IdentityCenter-Users; part of the SCIM scope)."
  value       = azuread_app_role_assignment.aws_users.principal_object_id
}

output "aws_admins_assigned_group_object_id" {
  description = "The PIM admin group assigned to the AWS app (PIM-AWS-Lab-Admins; null unless enable_aws_admins_assignment). ADR 0025."
  value       = one(azuread_app_role_assignment.aws_admins[*].principal_object_id)
}

# ---- AWS IAM Identity Center (SCIM) -----------------------------------------

output "aws_scim_template_lookup_command" {
  description = "TENANT TIME, after the first SSO apply: prints the synchronization template id to put in aws_scim_template_id."
  value       = "Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals/${azuread_service_principal.aws.object_id}/synchronization/templates' | Select-Object -ExpandProperty value | Select-Object id, factoryTag"
}

output "aws_scim_job_id" {
  description = "Provisioning job resource id (null until enable_scim_provisioning). Provision-on-demand and the leaver script operate on this job."
  value       = one(azuread_synchronization_job.aws[*].id)
}

output "aws_scim_job_enabled" {
  description = "Whether the ~40-minute provisioning cycle is started (null when SCIM is off)."
  value       = one(azuread_synchronization_job.aws[*].enabled)
}

# ---- Contoso Clinical Portal (OIDC) -------------------------------------------

output "clinical_portal_client_id" {
  description = "Client id of Contoso Clinical Portal."
  value       = azuread_application.clinical_portal.client_id
}

output "clinical_portal_application_object_id" {
  description = "Object id of the Contoso Clinical Portal app registration."
  value       = azuread_application.clinical_portal.object_id
}

output "clinical_portal_service_principal_object_id" {
  description = "Object id of the Contoso Clinical Portal enterprise app."
  value       = azuread_service_principal.clinical_portal.object_id
}

output "clinical_portal_identifier_uri" {
  description = "App ID URI (api://<client-id>); scopes are <this>/Clinical.Read."
  value       = azuread_application_identifier_uri.clinical_portal.identifier_uri
}

output "clinical_portal_app_role_ids" {
  description = "App role value => fixed role id (Clinician / Pharmacist / Auditor). Known at plan - the ids never change."
  value       = { for role, r in local.clinical_portal_roles : role => r.id }
}

output "clinical_portal_role_assignments" {
  description = "Static key => { role, principal } actually granted on the portal."
  value = {
    for k, a in azuread_app_role_assignment.clinical_portal :
    k => { role = var.clinical_portal_role_assignments[k].role, principal_object_id = a.principal_object_id }
  }
}

# ---- NHI inventory feed --------------------------------------------------------

output "nhi_inventory" {
  description = "One row per application this module owns: what it is, who owns it, what credential it holds and when that expires. Input for the NHI inventory/evidence pack (OWASP NHI: ownership, credential lifetime). Sensitive: owners carries app_owner_object_ids (named people)."
  sensitive   = true
  value = {
    aws_iam_identity_center = {
      service_principal_object_id = azuread_service_principal.aws.object_id
      owners                      = local.app_owners
      credential_type             = "saml-signing-certificate (Entra-held private key)"
      credential_expires          = azuread_service_principal_token_signing_certificate.aws.end_date
      outbound_secret             = var.enable_scim_provisioning ? "aws-scim-token (Key Vault; AWS-issued, rotate yearly - verify:)" : "none"
    }
    contoso_clinical_portal = {
      service_principal_object_id = azuread_service_principal.clinical_portal.object_id
      owners                      = local.app_owners
      credential_type             = "none (no client secret or certificate issued by this module)"
      credential_expires          = null
      outbound_secret             = "none"
    }
    guacamole_psm = var.enable_guacamole_psm_app ? {
      service_principal_object_id = azuread_service_principal.guacamole_psm[0].object_id
      owners                      = local.app_owners
      credential_type             = "none (implicit id_token sign-in, no client secret)"
      credential_expires          = null
      outbound_secret             = "none"
    } : null
    servicenow = var.enable_servicenow_sso ? {
      service_principal_object_id = azuread_service_principal.servicenow[0].object_id
      owners                      = local.app_owners
      credential_type             = "saml-signing-certificate (Entra-held private key)"
      credential_expires          = azuread_service_principal_token_signing_certificate.servicenow[0].end_date
      outbound_secret             = var.enable_servicenow_provisioning ? "none (accounts come from the separate ServiceNow provisioning app)" : "none (ServiceNow provisioning is off: enable_servicenow_provisioning)"
    } : null
    servicenow_provisioning = var.enable_servicenow_provisioning ? {
      service_principal_object_id = azuread_service_principal.servicenow_provisioning[0].object_id
      owners                      = local.app_owners
      credential_type             = "none (gallery app used for provisioning only; no Entra-issued key or secret)"
      credential_expires          = null
      outbound_secret             = "servicenow-provisioning-password (Key Vault; ServiceNow integration user, web-service access only - nhi-secrets-register)"
    } : null
    clinic_lab_results = var.enable_clinic_results_app ? {
      service_principal_object_id = azuread_service_principal.clinic_results[0].object_id
      owners                      = local.app_owners
      credential_type             = "none (public client: auth code + PKCE, loopback redirect, no secret or certificate; its API Clinic Lab Results API holds none either)"
      credential_expires          = null
      outbound_secret             = "none"
    } : null
    okta_clinic_idp = var.enable_okta_federation ? {
      service_principal_object_id = azuread_service_principal.okta_idp[0].object_id
      owners                      = local.app_owners
      credential_type             = "client-secret (minted by a human post-apply, at most ${var.okta_idp_secret_lifetime_days} days; held by Okta, never in state - nhi-secrets-register okta-clinic-idp-client-secret)"
      credential_expires          = null
      outbound_secret             = "none (Entra is the IdP; the secret is Okta's inbound credential)"
    } : null
  }
}

# ---- guacamole-psm (guacamole.tf) ----------------------------------------------

output "guacamole_psm_client_id" {
  description = "Client id of guacamole-psm = OIDC_CLIENT_ID in lab/pam/.env (null while enable_guacamole_psm_app is off)."
  value       = one(azuread_application.guacamole_psm[*].client_id)
}

output "pam_operators_group_object_id" {
  description = "Object id of PAM-Operators, the only principal assigned to guacamole-psm (null while off). Add operators post-apply; add them to CA008-Pilot-PhishingResistant too so PSM sign-in needs a phishing-resistant method."
  value       = one(azuread_group.pam_operators[*].object_id)
}

# ---- ServiceNow (servicenow.tf) -----------------------------------------------
# All null while enable_servicenow_sso is off.

output "servicenow_application_object_id" {
  description = "Object id of the ServiceNow app registration (non-gallery SAML)."
  value       = one(azuread_application_from_template.servicenow[*].application_object_id)
}

output "servicenow_client_id" {
  description = "Client (application) id of the ServiceNow app."
  value       = one(data.azuread_application.servicenow[*].client_id)
}

output "servicenow_service_principal_object_id" {
  description = "Object id of the ServiceNow enterprise app."
  value       = one(azuread_service_principal.servicenow[*].object_id)
}

output "servicenow_federation_metadata_url" {
  description = "Entra IdP metadata for the ServiceNow app - ServiceNow Multi-Provider SSO -> Identity Providers -> New -> SAML -> Import Identity Provider Metadata (URL). Re-import after every signing-certificate change."
  value       = one([for c in data.azuread_application.servicenow : "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${c.client_id}"])
}

output "servicenow_saml_signing_cert_thumbprint" {
  description = "Thumbprint of the Entra-minted ServiceNow SAML signing certificate (make it the preferred signing key - see the activation command)."
  value       = one(azuread_service_principal_token_signing_certificate.servicenow[*].thumbprint)
}

output "servicenow_saml_signing_cert_end_date" {
  description = "When the ServiceNow SAML signing certificate expires - rotate (and re-import the metadata in ServiceNow) before then."
  value       = one(azuread_service_principal_token_signing_certificate.servicenow[*].end_date)
}

output "servicenow_saml_signing_cert_activation_command" {
  description = "POST-APPLY (tenant time): make the new certificate the active ServiceNow SAML signing key. azuread 3.10 cannot set preferredTokenSigningKeyThumbprint. Needs Connect-MgGraph -Scopes Application.ReadWrite.All."
  value = one([
    for i, sp in azuread_service_principal.servicenow :
    "Update-MgServicePrincipal -ServicePrincipalId ${sp.object_id} -PreferredTokenSigningKeyThumbprint ${azuread_service_principal_token_signing_certificate.servicenow[i].thumbprint}"
  ])
}

output "servicenow_sign_on_url" {
  description = "Sign-on URL the My Apps tile uses (login_with_sso.do with the IdP sys_id once servicenow_sso_sys_id is set, else navpage.do)."
  value       = one(azuread_service_principal.servicenow[*].login_url)
}

output "servicenow_assigned_group_object_id" {
  description = "The single principal assigned to the ServiceNow app (App-ServiceNow-Users)."
  value       = one(azuread_app_role_assignment.servicenow_users[*].principal_object_id)
}

# ---- ServiceNow provisioning (servicenow_provisioning.tf) ----------------------
# All null while enable_servicenow_provisioning is off.

output "servicenow_provisioning_service_principal_object_id" {
  description = "Object id of the ServiceNow provisioning enterprise app (provision-on-demand, provisioning logs, Test Connection run against it)."
  value       = one(azuread_service_principal.servicenow_provisioning[*].object_id)
}

output "servicenow_provisioning_job_id" {
  description = "ServiceNow provisioning job id (ServiceNowOutDelta.<tenant>.<app id>): provision-on-demand and validateCredentials operate on it."
  value       = one(azuread_synchronization_job.servicenow[*].id)
}

output "servicenow_provisioning_job_enabled" {
  description = "Whether the ServiceNow provisioning cycle is started (false = created stopped; null when off)."
  value       = one(azuread_synchronization_job.servicenow[*].enabled)
}

output "servicenow_provisioning_reply_url_import_id" {
  description = "SEEDING STEP (README \"ServiceNow provisioning\"): the id to `terraform import` the gallery app's existing Web redirect set under azuread_application_redirect_uris.servicenow_provisioning before the apply that replaces its wildcard."
  value       = one([for a in azuread_application_from_template.servicenow_provisioning : "${a.application_id}/redirectUris/Web"])
}

output "servicenow_provisioning_assigned_group_object_id" {
  description = "The single principal assigned to the provisioning app - the same App-ServiceNow-Users as the SSO app."
  value       = one(azuread_app_role_assignment.servicenow_provisioning_users[*].principal_object_id)
}

# ---- okta-clinic-idp (okta.tf) -------------------------------------------------
# All null while enable_okta_federation is off. The Okta root
# (lab/terraform/okta) takes okta_idp_client_id and okta_idp_endpoints as
# inputs; the secret never passes through an output.

output "okta_idp_client_id" {
  description = "Client (application) id of okta-clinic-idp = entra_client_id in lab/terraform/okta (the Okta root's Microsoft IdP)."
  value       = one(azuread_application.okta_idp[*].client_id)
}

output "okta_idp_application_object_id" {
  description = "Object id of the okta-clinic-idp app registration (the -ApplicationId of the secret-minting command)."
  value       = one(azuread_application.okta_idp[*].object_id)
}

output "okta_idp_service_principal_object_id" {
  description = "Object id of the okta-clinic-idp enterprise app (admin consent target, sign-in log filter)."
  value       = one(azuread_service_principal.okta_idp[*].object_id)
}

output "okta_idp_redirect_uri" {
  description = "The one redirect URI on okta-clinic-idp. Must equal output okta_callback_uri of lab/terraform/okta (same org host) - the README's cross-check."
  value       = local.okta_enabled ? local.okta_idp_redirect_uri : null
}

output "okta_idp_endpoints" {
  description = "The tenant's v1.0 OIDC endpoints for the Okta root's okta_idp_oidc (issuer, authorization, token, JWKS; no userinfo). v1.0 because only its ID token carries amr, which Okta's trust claims reads. Copy, do not retype."
  value       = local.okta_enabled ? local.okta_idp_endpoints : null
}

output "okta_idp_assigned_group_object_id" {
  description = "The single principal assigned to okta-clinic-idp (App-Okta-Federation-Users): the allow-list of who may federate into Okta."
  value       = one(azuread_app_role_assignment.okta_federation_users[*].principal_object_id)
}

output "okta_idp_client_secret_command" {
  description = "POST-APPLY (tenant time, a human): mint the client secret Okta needs, bounded to okta_idp_secret_lifetime_days, and hand the printed value ONCE to the Okta root as TF_VAR_entra_client_secret. Terraform never creates or stores it (okta.tf header). Needs Connect-MgGraph -Scopes Application.ReadWrite.All (or ownership of the app with Application.ReadWrite.OwnedBy)."
  value = one([
    for app in azuread_application.okta_idp :
    "Add-MgApplicationPassword -ApplicationId ${app.object_id} -PasswordCredential @{ displayName = 'Okta IdP - entered once into lab/terraform/okta'; endDateTime = (Get-Date).ToUniversalTime().AddDays(${var.okta_idp_secret_lifetime_days}) } | Select-Object -ExpandProperty SecretText"
  ])
}

# ---- Clinic Lab Results (clinic_results.tf) -------------------------------------
# All null while enable_clinic_results_app is off.

output "clinic_results_client_id" {
  description = "Client id of Clinic Lab Results (null while off). CA061 targets it; lab/okta-migration/cutover.mjs reads it from Graph by display name."
  value       = one(azuread_application.clinic_results[*].client_id)
}

output "clinic_results_api_client_id" {
  description = "Client id of Clinic Lab Results API, the resource CA061 targets (Conditional Access cannot target the public client). Null while off."
  value       = one(azuread_application.clinic_results_api[*].client_id)
}

output "clinic_results_users_group_object_id" {
  description = "Object id of App-ClinicResults-Users, the ONE principal on Clinic Lab Results and CA061's user scope (null while off). Pilot members are added post-apply."
  value       = one(azuread_group.clinic_results_users[*].object_id)
}

# ---- Contoso Claims Viewer (claims_viewer.tf) -----------------------------------
# All null while enable_claims_viewer_app is off.

output "claims_viewer_client_id" {
  description = "Client id of the Claims Viewer app (lab/adfs/claims-viewer/fetch-metadata.sh entra needs it as CLIENT_ID)."
  value       = one(data.azuread_application.claims_viewer[*].client_id)
}

output "claims_viewer_service_principal_object_id" {
  description = "Object id of the Claims Viewer enterprise app."
  value       = one(azuread_service_principal.claims_viewer[*].object_id)
}

output "claims_viewer_saml_signing_cert_activation_command" {
  description = "POST-APPLY: make the new certificate the active Claims Viewer signing key (azuread 3.10 cannot set preferredTokenSigningKeyThumbprint). Run it BEFORE fetch-metadata.sh entra, so the metadata carries the active key."
  value = one([
    for i, sp in azuread_service_principal.claims_viewer :
    "Update-MgServicePrincipal -ServicePrincipalId ${sp.object_id} -PreferredTokenSigningKeyThumbprint ${azuread_service_principal_token_signing_certificate.claims_viewer[i].thumbprint}"
  ])
}

output "claims_viewer_role_assignments" {
  description = "Group object id -> app role value on the Claims Viewer (the converted AD FS rules 3a/3b)."
  value       = { for k, a in azuread_app_role_assignment.claims_viewer : a.principal_object_id => local.claims_viewer_roles[k].value }
}

output "servicenow_fulfilment" {
  description = "The ServiceNow fulfilment app (null when enable_servicenow_fulfilment = false). client_id goes into ServiceNow property contoso.entra.fulfilment.client_id (lab/servicenow/apply.py looks it up by display name)."
  value = var.enable_servicenow_fulfilment ? {
    client_id                   = azuread_application.servicenow_fulfilment[0].client_id
    service_principal_object_id = azuread_service_principal.servicenow_fulfilment[0].object_id
    catalog_role                = "Access package assignment manager (${local.access_package_assignment_manager_role_id})"
    catalog_id                  = var.servicenow_fulfilment_catalog_id
    graph_api_permissions       = "none"
  } : null
}
