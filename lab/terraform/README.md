# Contoso Health — Entra ID IAM / PAM Terraform Lab

Terraform for an **Identity & Access Management / Privileged Access
Management** lab on **Microsoft Entra ID**, modelled for the fictional
**Contoso Health** hospital group. Behind the `envs/dev` root it builds
break-glass accounts and groups (including the standing Admin-Accounts group,
the admin passkey target), Conditional Access (CA001-CA010, CA020, CA022,
CA060, plus the rendered CA021 and CA023; CA011 is a Graph script),
Privileged Identity Management
(tier groups, approver groups, Global Administrator policy, AU-scoped help
desk, PIM for Azure resources), Entitlement Management (access packages,
risk-tiered access reviews, B2B guests), a hardened Key Vault, the AD DS
domain controller and Intune "compliant device" VMs, SSO / SCIM apps (AWS
IAM Identity Center, ServiceNow SAML, the Clinical Portal, the PAM broker),
the 24 detections with
their telemetry and approval-gated containment, and a WORM evidence store.
Every layer sits behind a staging flag that is `false` in `lab.tfvars`
([Staging flags](#staging-flags-every-flag-and-its-default)). The GitHub-OIDC
CI identities live in a separate, human-applied `envs/bootstrap` root, and the
AWS IAM Identity Center permission set in an equally separate, human-applied
`aws/` root, and the Okta side of the acquired clinic's coexistence (ADR 0022) in
a third human-applied root, `okta/`. Workforce users (Dana Okafor and colleagues) are **not**
Terraform's: HR provisioning owns them.

> **Status: BUILT.** Every directory validates and every mocked test passes
> (counts in [Tests](#tests-mocked-offline)). **Applied to the lab tenant by the pipeline since 2026-10-28: 64 merged changes** (see `lab/evidence/capture-log.csv`). RAN · tenant: bootstrap, dev stages day1 to day3, sentinel, dc, itdr, apps, servicenow, okta, reviews, intune-vm.

Providers: **azuread `~> 3.10`** (Microsoft Graph / Entra) and **azurerm
`~> 4.0`** (Azure resources), plus **random `~> 3.6`** for initial passwords.
The separate `aws/` root alone uses **aws `~> 6.0`**, and the separate `okta/`
root alone **okta/okta `~> 4.0`** (4.20.0 locked).

> **Placeholders to swap for your tenant:** `onmicrosoft_domain`,
> `subscription_id`, `tenant_id`, the globally-unique `key_vault_name` and
> state storage account, (bootstrap) `github_owner` / `github_repo`, and
> (aws) `aws_region` / `allowed_account_ids`.
> Everything else defaults to the shared contract names.

---

## File tree

```
lab/terraform/
├── .gitignore
├── README.md                         ← you are here (module map, licensing, human steps)
├── aws/                              ← HUMAN-applied, separate cloud: IAM Identity Center permission set + assignment (after SCIM)
│   ├── .terraform.lock.hcl           ← provider hashes (HashiCorp Terraform 1.16.5, 3 platforms) - committed
│   ├── versions.tf / providers.tf / variables.tf / main.tf / outputs.tf
│   ├── github-oidc.tf                ← optional (enable_github_oidc) read-only GitHub OIDC role for plan runs
│   ├── audit-trail.tf                ← optional (enable_audit_baseline) CloudTrail trail + bucket + IAM Access Analyzer
│   ├── session-manager.tf            ← optional (enable_session_manager) no-inbound-port server, Session Manager shell only, LabServerSession for the PIM group
│   ├── tests/                        ← mocked terraform test (github_oidc.tftest.hcl)
│   ├── terraform.tfvars.example      ← copy → terraform.tfvars (gitignored): profile, region, account guard
│   └── README.md                     ← why separate, order of operations, verify list, CI-OIDC production option
├── envs/
│   ├── bootstrap/                    ← HUMAN-applied: CI identities + their RBAC (own state container)
│   │   ├── .terraform.lock.hcl       ← committed (same as aws/ and dev/)
│   │   ├── backend.tf / providers.tf / versions.tf / variables.tf
│   │   ├── terraform.tfvars.example
│   │   ├── main.tf                   ← pipeline-identity + Reader/Contributor/constrained RBAC admin/state access + entra-diagnostics;
│   │   │                               opt-in: enable_app_management_roles, enable_identity_protection_logs, enable_azure_guardrails
│   │   ├── outputs.tf                ← client ids → GitHub Actions variables; effective pipeline Graph roles
│   │   └── tests/                    ← mocked terraform test (optin.tftest.hcl)
│   └── dev/                          ← CI-applied root composition (10 modules behind staging flags + the Agent ID runtime UAMI)
│       ├── .terraform.lock.hcl       ← committed; CI pins Terraform 1.16.5 to match
│       ├── README.md                 ← apply order + P1/P2/Governance tiers
│       ├── backend.tf                ← azurerm remote state (versioned SA); -backend=false for validate
│       ├── providers.tf              ← azuread + azurerm + random provider config
│       ├── versions.tf               ← terraform + provider version pins
│       ├── variables.tf
│       ├── lab.tfvars                ← COMMITTED policy knobs: staging flags + CA states
│       ├── terraform.tfvars.example  ← copy → terraform.tfvars (gitignored): tenant identifiers
│       ├── main.tf                   ← RG + Log Analytics + module calls behind staging flags
│       ├── outputs.tf
│       └── tests/                    ← mocked `terraform test` plan of the composition
├── k8s/                              ← kind cluster segment, local state, built + destroyed per run (see "Kubernetes workload identity")
│   ├── platform/                     ← stage 1: namespaces + Pod Security labels, Vault Helm release; tests/ (mocked, run by CI)
│   ├── identity/                     ← stage 2: Vault k8s auth/role/policy, service accounts, group RBAC, admission policy; tests/
│   └── aks-mapping/                  ← PLAN-ONLY, never applied: Entra federated identity credential (azuread); tests/ (mocked)
├── okta/                             ← HUMAN-applied, separate product: the Okta side of the clinic coexistence (ADR 0022)
│   ├── .terraform.lock.hcl           ← okta/okta 4.20.0 hashes (HashiCorp Terraform 1.16.5, 3 platforms) - committed
│   ├── versions.tf / providers.tf / variables.tf / main.tf / outputs.tf
│   ├── tests/                        ← mocked terraform test (okta_federation.tftest.hcl)
│   ├── terraform.tfvars.example      ← copy → terraform.tfvars (gitignored): org, clinic domain, Entra ids (never the secret)
│   └── README.md                     ← apply order (Entra app first), Integrator Free limits, runbook Phase 1 mapping, verify list
└── modules/
    ├── dc-vm/                        ← AD DS domain controller VM (NSG operator-IP only, no-cache NTDS disk, auto-shutdown); tests/
    ├── intune-vm/                    ← Windows 11 VM, Entra joined + Intune enrolled (CA005 compliant device); tests/
    ├── entra-diagnostics/            ← tenant Entra logs → Log Analytics (bootstrap only: no envs/dev PR can remove it); tests/
    ├── azure-guardrails/             ← Azure Policy: no new standing Owner + Key Vault deletion protection, Audit first (bootstrap only); tests/
    ├── monitoring/                   ← lab/kql as Sentinel rules (trial) or Log Analytics alerts (post-trial): main.tf (5 core),
    │                                   itdr.tf (11 ITDR + containment), itdr_v2.tf (6 more + operator_ips watchlist),
    │                                   telemetry.tf (VaultCheckout_CL, DCE/DCRs, AMA on DC01); tests/
    ├── groups/                       ← break-glass (+ GA), dynamic birthright + role-assignable + app + CA005 pilot groups,
    │                                   Admin-Accounts (standing, no role); optional App-Consent-Reviewers + All-Workforce; tests/
    ├── conditional-access/           ← main.tf CA001-CA008, baseline.tf CA009/CA010, admins.tf CA020/CA021 (rendered)/CA022/
    │                                   CA023 (rendered), clinical.tf CA060; named location, admin + workforce + bootstrap auth strengths; tests/
    ├── pim/                          ← main.tf Privileged-IAM-Admins; tiers.tf 8 Tier-0 + 8 Tier-1 groups; approvers.tf;
    │                                   directory-roles.tf (GA policy, rendered); helpdesk.tf (AU scope); azure.tf; aws.tf;
    │                                   demo-readers.tf (PIM-Demo-Readers, read-only presenter); reviews.tf; tests/
    ├── entitlement/                  ← catalog, access packages per lab/iga/access-catalog.json, ADR 0012 review tiers;
    │                                   reviews.tf (rendered privileged + inactive bodies); b2b.tf (guest catalog/package); tests/
    ├── apps/                         ← AWS IAM Identity Center SAML (+ staged SCIM), ServiceNow SAML (servicenow.tf),
    │                                   Clinical Portal OIDC, guacamole-psm, okta-clinic-idp (okta.tf); tests/
    ├── evidence-store/               ← WORM storage account (version-level immutability, Entra-only, delete-denying writers); tests/
    ├── pipeline-identity/            ← 2 GitHub-OIDC apps (plan/apply) + Graph app roles (bootstrap only); tests/
    └── keyvault/                     ← RBAC Key Vault, PE + private DNS, operator-IP firewall, UAMI; tests/
```

Each module ships `versions.tf` / `variables.tf` / `main.tf` / `outputs.tf`
and is heavily commented inline. Every module carries a
`tests/` folder (mocked `terraform test`, see [Tests](#tests-mocked-offline)); `apps/`, `entitlement/`, `pim/` add a
`README.md` with their staged tenant order and verify list.

---

## Module map

| Module | Key resources | Purpose |
|--------|---------------|---------|
| **groups** | `azuread_user` (`bg-admin-01/02` on onmicrosoft.com), `azuread_directory_role_assignment` (Global Admin → Break-Glass-Admins), `azuread_group` (All-Nurses / All-ICU dynamic, Break-Glass-Admins + Privileged-IAM-Admins role-assignable, App-ServiceNow/AWS/Okta/ICU/Pharmacy assigned, CA005-Pilot-CompliantDevice assigned pilot, Admin-Accounts role-assignable and standing with no role (the admin passkey target; `post-apply/New-AdminAccounts.ps1` sets its membership); optional App-Consent-Reviewers (`enable_nhi_governance`) and dynamic All-Workforce = enabled HR-synced members (`enable_phishing_resistant_all_users`)), `random_password` | The identity cast everything else references. Workforce users come from HR, not here. |
| **conditional-access** | `azuread_conditional_access_policy` ×5 (+8 behind flags), `azuread_named_location`, `azuread_authentication_strength_policy` ×3, `azuread_group` (CA008 pilot), optional `azuread_authentication_strength_policy_fido2_combination_configuration` | CA001 MFA for all, CA002 phishing-resistant for admins, CA003 block legacy auth, CA004 block countries, CA005 *compliant device for the admin portals* (**CA005-Pilot-CompliantDevice only**). Behind flags: **CA006** user risk High → MFA + secure password change and **CA007** sign-in risk High → block (`enable_identity_protection_ca`, P2, [ADR 0015](../docs/adr/0015-risk-based-conditional-access-thresholds.md)); **CA008** phishing-resistant strength for the workforce (`enable_phishing_resistant_all_users`; all users = measure, pilot = enforce; all-users enforcement needs a second key; the rollout needs `admin_fido2_allowed_aaguids` or `accept_admin_synced_passkey_risk`, [ADR 0016](../docs/adr/0016-passkey-profiles-and-phone-method-retirement.md)); **CA009** registering security info needs a one-time TAP or a phishing-resistant method (`enable_registration_ca`); **CA010** block the device code flow (`enable_device_code_block`); **CA020** admin-portal sign-in every 4 h (`enable_admin_session_controls`); **CA022** the PSM app (guacamole-psm) + admin portals need the ADMIN strength (`enable_pam_oidc_app`, was CA009); **CA060** shared clinical workstations (`enable_shared_clinical_ca`, [ADR 0014](../docs/adr/0014-shared-clinical-workstation-authentication.md)). **CA021** (PIM step-up on authentication context `c1`, `enable_pim_auth_context`) is rendered as output `pim_auth_context_requests` and written by `post-apply/Set-AuthContextPolicies.ps1`: the provider can create neither the context nor a policy that targets it. **CA023** (step-up on a second context, `c2`, for the protected actions *update / delete a CA policy or named location*, `enable_protected_actions_ca`) follows the same pattern (output `protected_actions_auth_context_requests`, same script); binding `c2` to the protected actions is a manual step once CA023 is enforced. CA011 (Token Protection) is a Graph script too (`post-apply/Set-TokenProtectionPolicy.ps1`). Per-policy state in `ca_policy_states`, all **report-only** by default; break-glass excluded on every policy ([ADR 0003](../docs/adr/0003-ca-exclusions-and-break-glass.md)). |
| **pim** | `azuread_directory_role_assignment` (group → role, AU-scoped where set), `azuread_group_role_management_policy`, `azuread_group` (tier, approver and Azure groups), `azuread_administrative_unit`, `azurerm_pim_eligible_role_assignment`, `azurerm_role_management_policy` | Privileged-IAM-Admins (User Administrator): eligible membership, MFA + justification + approval, 4h, eligibility expires after 365 days. `enable_pim_tiers`: **8 Tier-0 groups** (Security, CA, Privileged Role, Privileged Authentication (2h), Hybrid Identity, Application, Cloud Application and Authentication Policy Administrator: MFA (or authentication context `c1` once CA021 is enforced) + justification + ticket + approval by `PIM-Approvers-Tier0`, 4h, eligibility 180 days) and **8 Tier-1 groups** (Intune with approval, Identity Governance + Lifecycle Workflows Administrator with approval, Helpdesk + Authentication Administrator, Groups, Exchange, SharePoint, Teams, License: MFA + justification, 8h, eligibility 365 days). `enable_helpdesk_au_scoping`: the help-desk roles scoped to `AU-Workforce-Standard`. `enable_global_admin_pim_policy`: Global Administrator's own policy (approval, 2h, named eligibility for 180 days), rendered for `post-apply/Set-DirectoryRolePimPolicies.ps1`. `enable_pim_azure_resources`: PIM-Azure-RG-Contributors **eligible** for Contributor on the lab RG (approval, 4h; human applier). `enable_pim_aws_admin`: PIM-AWS-Lab-Admins, eligible-only AWS admin (2h, MFA + justification, every activation mailed; ADR 0025). Outputs feed the privileged access reviews. [ADR 0020](../docs/adr/0020-pim-activation-design.md); see [`modules/pim/README.md`](modules/pim/README.md). |
| **entitlement** | `azuread_access_package_catalog`, `azuread_access_package` ×4, `azuread_access_package_resource_catalog_association`, `azuread_access_package_resource_package_association`, `azuread_access_package_assignment_policy` (request packages only, + `assignment_review_settings` by tier) | Packages from `var.access_packages`, matching `lab/iga/access-catalog.json`: "Nurse – Clinical Apps" and "ICU – Critical Care Apps" are **T3 birthright** (no Terraform policy: their only policy is the HR-attribute automatic assignment from `post-apply/Set-AutoAssignmentPolicies.ps1`); "ICU – Float Access" and "Pharmacy – Controlled Substances Apps" are **T2 requestable** (approval, justification, 180-day expiry). Assigned groups only. Reviews per [ADR 0012](../docs/adr/0012-access-review-no-response-and-clinical-lockout.md), one flag per tier: `enable_access_reviews_privileged` (T1, quarterly, default deny), `enable_access_reviews_requestable` (T2, half-yearly, only on packages that outlive 180 days or allow extension), `enable_access_reviews_inactive`; a birthright clinical package is never reviewed by a person. Standalone review bodies (privileged, inactive-user) are rendered as output `access_review_definitions` for `post-apply/New-AccessReviewDefinitions.ps1`. `enable_b2b_governance`: external "Affiliated Partners" catalog + "Affiliated Physicians" package (connected-org requestors, sponsor approval, 90-day expiry, monthly review); connected org via `post-apply/New-B2BConnectedOrganization.ps1`. See [`modules/entitlement/README.md`](modules/entitlement/README.md). |
| **pipeline-identity** | `azuread_application` ×2, `azuread_service_principal` ×2, `azuread_application_federated_identity_credential` ×2, `azuread_app_role_assignment` ×N, `data.azuread_service_principal` (Graph) | GitHub-OIDC **plan** (read-only, `pull_request`) and **apply** (write, `environment:prod`) identities. Called only from `envs/bootstrap`. Opt-in extra roles (`extra_*_graph_roles`; bootstrap `enable_app_management_roles` adds the four `modules/apps` needs, incl. Tier-0 `AppRoleAssignment.ReadWrite.All`); a write role can never be added to PLAN. |
| **dc-vm** | `azurerm_windows_virtual_machine` (Server 2022 Azure Edition, Trusted Launch), `azurerm_managed_disk` (NTDS, caching None), `azurerm_network_security_group`, `azurerm_public_ip`, `azurerm_dev_test_global_vm_shutdown_schedule`, `azurerm_role_assignment` (VM identity → Key Vault Secrets Officer, ABAC-limited to `dc01-dsrm-password` + `svc-vault-rotator` + `svc-pam-discovery`; Key Vault ABAC is preview, verify:) | The on-prem AD for HR → AD → Cloud Sync. Promoted by `lab/scripts/dc/`. |
| **intune-vm** | `azurerm_windows_virtual_machine` (Windows 11 Enterprise, Trusted Launch, `license_type = Windows_Client`), `azurerm_virtual_machine_extension` (`AADLoginForWindows` with `mdmId` = Intune), `azurerm_role_assignment` ×N (*Virtual Machine Administrator Login* for listed users + the CA005 pilot group), `azurerm_subnet` + `azurerm_network_security_group` (RDP from operator IP only), `azurerm_public_ip`, `azurerm_dev_test_global_vm_shutdown_schedule`, `random_password` (local break-glass admin) | The "compliant device" CA005 needs: Entra joined + Intune auto-enrolled at apply time; people sign in with Entra credentials. Compliance policy comes from `lab/scripts/intune/New-IntuneComplianceBaseline.ps1`. |
| **entra-diagnostics** | `azurerm_monitor_aad_diagnostic_setting` | Entra AuditLogs / SignInLogs / NonInteractive / ServicePrincipal / Provisioning → `loga-idlab` (+ RiskyUsers / UserRiskEvents / RiskyServicePrincipals / ServicePrincipalRiskEvents with bootstrap `enable_identity_protection_logs`, P2). Called from `envs/bootstrap` only. |
| **azure-guardrails** | `azurerm_policy_definition` ×2, `azurerm_subscription_policy_assignment` ×2 | No new standing Owner (Owner matched at any scope, the allowed principals excluded) and Key Vaults keep soft delete + purge protection (Microsoft's built-in rule). Both **Audit** until a human sets Deny. Called from `envs/bootstrap` only (`enable_azure_guardrails`): APPLY's Contributor can't write policy. See [`modules/azure-guardrails/README.md`](modules/azure-guardrails/README.md). |
| **monitoring** | `azurerm_sentinel_log_analytics_workspace_onboarding`, `azurerm_sentinel_alert_rule_scheduled` (one per rule: 5 core + 11 ITDR + 6 ITDR v2 + 2 ITDR v3), `azurerm_sentinel_automation_rule` (notify; + containment, + opt-in alert-added trigger), `azurerm_monitor_scheduled_query_rules_alert_v2` (same rules on the post-trial path, minus the Sentinel-only ones: two in v2, both in v3), `azurerm_monitor_action_group`, `azurerm_sentinel_watchlist` + items (`operator_ips`); ITDR telemetry (`telemetry.tf`): `azurerm_log_analytics_workspace_table_custom_log` (`VaultCheckout_CL`), DCE + DCRs, AMA on DC01 (incl. 4662 filtered to control access) | All **24** `lab/kql` detections, each behind a flag: the 5 core rules with `enable_sentinel` / `enable_la_alerts`, the 11 ITDR rules with `enable_itdr_detections` (telemetry without starting a trial), the 6 second-wave rules with `enable_itdr_detections_v2` (device-code sign-in, risky security-info registration, DC logon outside the operator allow-list, vault anomaly, SoD pair completed, PIM activation without the auth context), the 2 third-set rules with `enable_itdr_detections_v3` (dormant admin account signs in again, Key Vault bulk secret reads; off in `lab.tfvars`). `security_info_registered_risky`, `sod_violation_granted` and both third-set rules look back 14 days, so they are Sentinel only. `itdr_exclude_rules` holds back any rule whose table has no data yet. The IaC identity, privileged group and privileged user ids are rendered in as IMMUTABLE ids (`iac_principal_ids`, `privileged_group_ids`, `privileged_user_ids`); `azure_pim_group_ids` (PIM-Azure-RG-Contributors, passed by `envs/dev/main.tf`) gets its own Medium path in `pim-group-member-added-outside-pim`, because a direct member add is that group's intended route. The `operator_ips` watchlist is Terraform-owned (built from `operator_ip_ranges`, `ExpiresOn` = `operator_ips_expires_on`): edit the variable, never the watchlist. Response: `lab/monitoring/playbook-notify.json` and, with `enable_itdr_containment`, `playbook-contain.json` (approval-gated revoke + confirm compromised + disable on High incidents; never on the SoD, vault or Key Vault rules). Inventory per rule: [`lab/kql/README.md`](../kql/README.md); operations: [`lab/scripts/monitoring/README.md`](../scripts/monitoring/README.md). |
| **keyvault** | `azurerm_key_vault` (RBAC, firewall deny-by-default), `azurerm_private_endpoint` + `azurerm_private_dns_zone` (+ link), `azurerm_user_assigned_identity`, `azurerm_role_assignment` (Secrets User for the UAMI, ABAC-limited to the secret names in `uami_readable_secret_names` (default `demo-app-config`) so Tier-0 and playbook secrets in the same vault stay unreadable to it; Secrets Officer for human custodians), `azurerm_virtual_network`/`subnet`, `azurerm_monitor_diagnostic_setting` | Hardened secret store + a read-only (never write) managed identity. Public access only when `allowed_ip_ranges` lists the operator IP. |
| **apps** | `azuread_application_from_template` (AWS gallery; ServiceNow from the non-gallery template), `azuread_service_principal`, `azuread_service_principal_token_signing_certificate`, `azuread_claims_mapping_policy`, `azuread_application_identifier_uri` / `_redirect_uris`, `azuread_synchronization_job` + `_secret` (staged), `azuread_application` (Clinical Portal, guacamole-psm), `azuread_app_role_assignment`, `azuread_group` (PAM-Operators) | `enable_sso_apps`: AWS IAM Identity Center SAML (one assignment = the SCIM scope; Entra-minted signing cert; NameID + ABAC session tags) and the Clinical Portal OIDC app (Clinician / Pharmacist / Auditor roles to groups). `enable_scim_provisioning`: the AWS provisioning job, created **stopped**. `enable_pam_oidc_app`: guacamole-psm, id-token sign-in for the PSM stand-in (+ CA022). `enable_servicenow_sso`: ServiceNow SAML for the developer instance (one assignment: App-ServiceNow-Users; NameID = UPN). `enable_servicenow_provisioning`: a hidden gallery ServiceNow app for provisioning only (same group; job + Key Vault credential written once by a local seeding apply). `clinical_portal_preauthorize_azure_cli`: E25 token demo only. `enable_okta_federation`: okta-clinic-idp, Entra as the OIDC identity provider for the acquired clinic's Okta org (one assignment: App-Okta-Federation-Users; the client secret is a human's bounded post-apply step; the Okta side is the `okta/` root). See [`modules/apps/README.md`](modules/apps/README.md). |
| **evidence-store** | `azurerm_storage_account` (version-level WORM default policy, Shared Key off, deny-by-default firewall), `azurerm_storage_container`, `azurerm_role_assignment` (ABAC delete-deny writers, readers), `azurerm_monitor_diagnostic_setting` | `enable_evidence_store`: where evidence packs, KPI snapshots and assessment raw reports live for 6 years, immutable (Unlocked first; locking is a second, acknowledged apply; the lab keeps it Unlocked by program rule). Writers are granted by a human. A CanNotDelete lock on the account comes from `envs/bootstrap` (`enable_evidence_delete_lock`), because CI's Contributor can neither write nor remove locks. Production: policy Locked, account in a separate subscription with no identity-team Owner, plus the delete lock. |
| **aws/** *(separate root, not a module)* | `data.aws_ssoadmin_instances`, `data.aws_identitystore_group` (read-only), `aws_ssoadmin_permission_set`, `aws_ssoadmin_managed_policy_attachment`, `aws_ssoadmin_account_assignment` | `ViewOnlyAccess` (PT4H, AWS job-function policy) granted to the SCIM-provisioned `App-AWS-IdentityCenter-Users` group in the target account. Human-applied after SAML + SCIM; never planned/applied by CI. Provider `hashicorp/aws ~> 6.0`. Default target = the caller's (management) account — a documented lab trade-off; production targets a member account. |
| **okta/** *(separate root, not a module)* | `okta_group`, `okta_group_rule`, `okta_app_bookmark`, `okta_app_group_assignment`; behind `enable_entra_federation`: `okta_idp_oidc`, `okta_policy_rule_idp_discovery` (+ `data.okta_default_policy`, read-only) | The Okta side of "Okta trusts Entra" (runbook Phase 1, [ADR 0022](../docs/adr/0022-okta-coexistence-as-code.md)): `Clinic-Staff` filled by a rule on the clinic login domain, one legacy bookmark app assigned to it, then the Microsoft Entra ID OIDC identity provider (client id from `envs/dev` output `okta_idp_client_id`, secret as `TF_VAR_entra_client_secret` at apply time) and ONE routing rule sending that login domain to it, Okta's Default Rule kept as the fallback. `routing_rule_active = false` is the runbook's rollback. Human-applied after the Entra app; never planned/applied by CI. Provider `okta/okta ~> 4.0` (4.20.0). Target: an Okta Integrator Free org, the real product on its free plan. |

---

## License requirements per resource

“Minimum SKU for the feature to **function**.” Creating the Terraform object
may succeed on a lower tier, but the capability needs the tier shown.

| Resource | Minimum license |
|----------|-----------------|
| `azuread_user` | **Free** |
| `azuread_group` (static, security) | **Free** |
| `azuread_group` with `dynamic_membership` (All-Nurses) | **Entra ID P1** |
| `azuread_group` with `assignable_to_role = true` (Break-Glass, Priv-IAM) | **Entra ID P1** |
| `azuread_conditional_access_policy` (CA001-CA005, CA008-CA010, CA020, CA022, CA060) and the script-written CA011 / CA021 / CA023 | **Entra ID P1** (per in-scope user); CA005's *compliant device* grant also needs **Intune** to judge the device; CA011 Token Protection licensing is *verify:* |
| `azuread_named_location` | **Entra ID P1** |
| `azuread_authentication_strength_policy` (custom) | **Entra ID P1** |
| CA sign-in / user **risk** conditions (CA006, CA007; `enable_identity_protection_ca`) | **Entra ID P2** (per in-scope user; in the M365 E5 trial) |
| Workforce authentication strength + CA008, dynamic All-Workforce group | **Entra ID P1** |
| `azurerm_pim_eligible_role_assignment` / `azurerm_role_management_policy` (PIM for Azure resources) | **Entra ID P2** |
| B2B package for connected-org guests (`enable_b2b_governance`) | **Entra ID Governance**; guests billed by B2B monthly active users (verify) |
| Standalone privileged / inactive-user access reviews (post-apply) | **Entra ID Governance** (verify) |
| `modules/apps`: gallery SAML app, app registrations | **Free**; *group* assignment to an enterprise app needs **Entra ID P1**; outbound SCIM: P1 (verify) |
| `azurerm_storage_account` (evidence store), DCE/DCR, custom table, AMA | **No Entra SKU** — Azure storage / ingestion cost |
| `azurerm_user_assigned_identity` (agent runtime) | **No Entra SKU**; Entra Agent ID itself is preview and may need Agent 365 (verify) |
| `azuread_directory_role_assignment` (break-glass GA, group → role) | **Free** (role-assignable group target needs **P1**) |
| `azuread_group_role_management_policy` (PIM for Groups) | **Entra ID P2** |
| `azuread_access_package*` + `azuread_access_package_assignment_policy` | **Entra ID Governance** (per assigned user) |
| Access reviews (`assignment_review_settings`, `enable_access_reviews`) | **Entra ID Governance** |
| `azuread_application` / `service_principal` / `federated_identity_credential` | **Free** |
| `azuread_app_role_assignment` (Graph app roles) | **Free** (consent rights still required) |
| `azurerm_key_vault`, `private_endpoint`, `private_dns_zone`, `user_assigned_identity`, `role_assignment`, `log_analytics_workspace` | **No Entra SKU** — standard Azure resource cost |
| `azurerm_windows_virtual_machine` + disks/IP (DC) | **No Entra SKU** — Azure compute (auto-shutdown keeps it ~$6/mo deallocated) |
| `azurerm_windows_virtual_machine` + `AADLoginForWindows` (Intune VM) | Azure compute (~$0.04/hr running, ~$10/mo deallocated). `Windows_Client` relies on Windows 11 multitenant hosting rights from **M365 E3/E5** (here the E5 *trial*: dev/test only, *verify*). Intune auto-enrollment needs **Entra ID P1 + Intune** (both in M365 E5) |
| `azurerm_monitor_aad_diagnostic_setting` | **Entra ID P1/P2** for sign-in logs (AuditLogs export works on Free) |
| `azurerm_sentinel_*` | **Sentinel** (31-day free trial on a new workspace, then per-GB) |
| `azurerm_monitor_scheduled_query_rules_alert_v2` | **No Entra SKU** — per-rule Azure Monitor cost (cents) |
| `aws_ssoadmin_*` (separate `aws/` root) | **No Entra SKU, no AWS charge** (IAM Identity Center) — but assigning the *group* to the Entra AWS enterprise app (what SCIM provisions) needs **Entra ID P1** |

**Net:** the lab needs **P1** for groups/CA, **P2** for PIM and risk-based
CA, **Entra ID Governance** for the access-package layer (and its access
reviews, B2B package), and
**Intune** (inside M365 E5) for the CA005 compliant-device demo. Key
Vault/networking/VMs are pure Azure.

---

## Staging flags (every flag and its default)

Every flag below is `false` in the committed
[`envs/dev/lab.tfvars`](envs/dev/lab.tfvars) except `pim_require_approval`
(default `true`). Flip one per PR, in the order of
[Apply order](#apply-order-whole-lab) step 9. A `check` block warns when a
flag is on without its prerequisite; `validation` blocks refuse the
combinations that cannot work.

**`envs/dev` (CI-applied)**

| Flag | Default | Creates (module) | Needs |
|---|---|---|---|
| `enable_premium` | `false` | Break-glass + groups, Conditional Access CA001-CA005, PIM (groups, conditional-access, pim) | M365 E5 trial (Entra ID P2) |
| `enable_governance` | `false` | Catalog + access packages (entitlement) | `enable_premium`, Entra ID Governance trial |
| `enable_dc` | `false` | DC01 domain controller VM (dc-vm) | nothing: free tier, Azure compute cost |
| `enable_intune_vm` | `false` | Windows 11 VM, Entra joined + Intune enrolled, the CA005 compliant device (intune-vm) | `enable_premium` + the human steps in `lab/scripts/intune/README.md` |
| `enable_sentinel` | `false` | Sentinel onboarding + the core rules (monitoring). **Starts the 31-day trial** | Entra logs flowing for a few hours; not with `enable_la_alerts` |
| `enable_la_alerts` | `false` | The same rules as Log Analytics alerts, the post-trial path (monitoring) | not with `enable_sentinel` |
| `enable_access_reviews` | `false` | Shorthand for the three tier flags below (deprecated alias) | `enable_governance` + a fallback reviewer group |
| `enable_access_reviews_privileged` | `false` | ADR 0012 T1: quarterly default-deny reviews of every PIM-governed group and of Global Administrator eligibility (rendered bodies) | `enable_governance` |
| `enable_access_reviews_requestable` | `false` | ADR 0012 T2: half-yearly `removeAccess` review, only on requestable packages that outlive 180 days or allow extension | `enable_governance` |
| `enable_access_reviews_inactive` | `false` | Inactive-user review of `App-Okta-Federation-Users` (rendered body) | `enable_governance` |
| `pim_require_approval` | **`true`** | Approval on Privileged-IAM-Admins activation (pim) | Tier-1 approvers |
| `enable_identity_protection_ca` | `false` | CA006 user risk High, CA007 sign-in risk High (conditional-access) | `enable_premium`, P2 licences **assigned**; Microsoft's managed risk policy set off by hand first |
| `enable_phishing_resistant_all_users` | `false` | CA008, the workforce authentication strength, CA008 pilot group, dynamic All-Workforce group | `enable_premium`; `admin_fido2_allowed_aaguids` or `accept_admin_synced_passkey_risk` |
| `ca008_allow_all_users_enforcement` | `false` | Second key: CA008 enforced on all users | registration report shows full coverage; pilot ran enforced |
| `accept_admin_synced_passkey_risk` | `false` | Second key: allow the rollout with no admin AAGUID allow-list (record it in the risk register) | a reviewed risk acceptance |
| `enable_registration_ca` | `false` | CA009: register security info with a one-time TAP or a phishing-resistant method | `enable_premium` |
| `enable_device_code_block` | `false` | CA010: block the device code flow (enforcing it breaks `az login --use-device-code`) | `enable_premium` |
| `enable_admin_session_controls` | `false` | CA020: admin-portal sign-in every 4 h for Tier-0/1 roles and PIM groups | `enable_premium` |
| `enable_pim_auth_context` | `false` | CA021 + authentication context `c1`, rendered for `Set-AuthContextPolicies.ps1` | `enable_premium` |
| `ca021_enforced_in_tenant` | `false` | Attestation, not a feature: CA021 is enforced in the tenant. Only then may PIM require `c1` | an earlier apply declared CA021 `enabled` and `Set-AuthContextPolicies.ps1` reported it enabled |
| `enable_protected_actions_ca` | `false` | CA023 + authentication context `c2` for the protected actions on CA policies and named locations, rendered for `Set-AuthContextPolicies.ps1`; the bind is a manual step once CA023 is enforced | `enable_premium` |
| `enable_shared_clinical_ca` | `false` | CA060: shared clinical workstations (ADR 0014); code only, no such device exists in the lab | `enable_phishing_resistant_all_users` |
| `enable_pim_tiers` | `false` | 8 Tier-0 + 8 Tier-1 PIM groups and the approver groups (pim) | `enable_premium` + Tier-0 approvers |
| `enable_pim_azure_resources` | `false` | PIM-Azure-RG-Contributors eligible for Contributor on the lab RG | `enable_premium`; a **human** applier with Owner / User Access Administrator |
| `enable_pim_aws_admin` | `false` | PIM-AWS-Lab-Admins: AWS admin as a 2-hour PIM-for-Groups activation, assigned to the AWS IAM Identity Center app (ADR 0025) | `enable_premium`, `enable_sso_apps`; `lab/terraform/aws` `enable_lab_admin_jit` |
| `enable_pim_demo_readers` | `false` | PIM-Demo-Readers: read-only presenter access (Global Reader + Security Reader) as an 8-hour PIM-for-Groups activation, no approval, every activation mailed; reviewed quarterly, outside the CA002 / CA020 scope | `enable_premium`; the Azure read roles are envs/bootstrap `enable_pim_demo_readers_azure_rbac` (human-applied) |
| `enable_helpdesk_au_scoping` | `false` | `AU-Workforce-Standard` + help-desk roles scoped to it | `enable_pim_tiers` |
| `enable_global_admin_pim_policy` | `false` | Global Administrator's PIM policy + named 180-day eligibility, rendered for `Set-DirectoryRolePimPolicies.ps1` | `enable_premium` + Tier-0 approvers |
| `pim_tier0_auth_context_switchover_step1` | `false` | Apply 1 of 2 when switching existing Tier-0 policies from MFA to `c1` | CA021 enforced; apply 2 straight after |
| `enable_b2b_governance` | `false` | Affiliated Partners catalog + Affiliated Physicians guest package | `enable_premium` + `enable_governance` |
| `enable_sso_apps` | `false` | AWS IAM Identity Center SAML app + Clinical Portal OIDC app (apps) | `enable_premium`; bootstrap `enable_app_management_roles` |
| `enable_scim_provisioning` | `false` | AWS provisioning job, **stopped**, and its credential | `enable_sso_apps`; a local seeding apply, never CI |
| `aws_scim_job_enabled` | `false` | Starts the AWS provisioning job | Test Connection + one on-demand provision succeeded |
| `require_scim_credentials` | `false` | Fail closed when the SCIM credential would be created without a token (`true` in the apply workflow) | — |
| `enable_pam_oidc_app` | `false` | guacamole-psm + PAM-Operators, and CA022 | `enable_sso_apps` |
| `enable_servicenow_sso` | `false` | ServiceNow SAML app (non-gallery, assignment required, one group) | `enable_sso_apps`; `servicenow_instance_url` in `terraform.tfvars` / `TF_VAR_`, never `lab.tfvars` |
| `enable_okta_federation` | `false` | okta-clinic-idp: Entra as the OIDC identity provider for the acquired clinic's Okta org (apps `okta.tf`), one assignment (App-Okta-Federation-Users); the client secret is minted by a human post-apply, never by Terraform | `enable_sso_apps`; `okta_org_domain` in `terraform.tfvars` / `TF_VAR_`, never `lab.tfvars`; then the human-applied `okta/` root |
| `clinical_portal_preauthorize_azure_cli` | `false` | Pre-authorizes the Azure CLI on the Clinical Portal scope (evidence E25 token demo only) | `enable_sso_apps`; turn off afterwards |
| `enable_nhi_governance` | `false` | App-Consent-Reviewers group for the admin consent workflow (groups) | `enable_premium` |
| `enable_agent_identity` | `false` | `uami-agent-runtime`, a role-less managed identity for Entra Agent ID | nothing in Terraform; the Agent ID API is preview and licence-gated (verify: Agent 365) |
| `enable_itdr_detections` | `false` | The 11 ITDR rules + `VaultCheckout_CL`, DCE/DCR for the vault feed and, with `enable_dc`, AMA + a Security-event DCR on DC01 (monitoring); starts no trial | turn on before `enable_sentinel`; `identity_risk` also needs bootstrap `enable_identity_protection_logs` |
| `enable_itdr_detections_v2` | `false` | The 6 second-wave rules + the `operator_ips` watchlist (Sentinel, with `enable_dc`) | `enable_itdr_detections` |
| `enable_itdr_detections_v3` | `false` | The 2 third-set rules: a dormant admin account signing in again, bulk Key Vault secret reads (both Sentinel only; the Key Vault rule never contains). `false` in `lab.tfvars` too, until its own PR | `enable_itdr_detections` |
| `vault_feed_v2_columns` | `false` | Ticket, Operator and ErrorText columns on `VaultCheckout_CL` | `enable_itdr_detections`; same PR as `ingest-vault-audit.sh --signals all` |
| `enable_itdr_containment` | `false` | Containment automation rule on new High ITDR incidents | `enable_sentinel` + `enable_itdr_detections` + `containment_playbook_id` |
| `containment_on_alert_added` | `false` | Also run containment when a High alert joins an existing incident | `enable_itdr_containment` |
| `enable_evidence_store` | `false` | WORM evidence storage account, Unlocked (evidence-store) | nothing: Azure storage cost only; apply before Day 0 |
| `evidence_immutability_lock_acknowledged` | `false` | Second key: lock the immutability policy (irreversible) | the deliberate lock PR (Day 28 of the capture plan) |

Other committed knobs in `lab.tfvars`: `ca_policy_states` (one entry per
policy, all `enabledForReportingButNotEnforced`), `ca008_scope`
(`"all_users"` while report-only, `"pilot"` to enforce),
`admin_fido2_allowed_aaguids` (`[]`), `pim_tier0_activation_auth_context_id`
(`""` until CA021 is enforced), `operator_ips_expires_on` (ADR 0013's review
date) and `blocked_countries`. `itdr_exclude_rules` (default `[]`) is set per
environment, not committed.

**`envs/bootstrap` (human-applied)**

| Flag | Default | Effect |
|---|---|---|
| `enable_app_management_roles` | `false` | APPLY gets the four Graph roles `modules/apps` needs (incl. Tier-0 `AppRoleAssignment.ReadWrite.All`); PLAN gets two read roles |
| `enable_identity_protection_logs` | `false` | Adds RiskyUsers, UserRiskEvents, RiskyServicePrincipals and ServicePrincipalRiskEvents to the Entra diagnostic setting (P2) |
| `enable_azure_guardrails` | `false` | Assigns the two Azure Policy guardrails (`modules/azure-guardrails`) to the subscription, both in **Audit** (`standing_owner_effect`, `keyvault_protection_effect`); Deny needs `owner_allowed_principal_ids` |

**`aws/` (human-applied)**

| Flag | Default | Effect |
|---|---|---|
| `enable_github_oidc` | `false` | GitHub Actions OIDC provider + a read-only role for plan runs |
| `enable_audit_baseline` | `false` | CloudTrail trail `contoso-lab-audit-trail` (all regions, log file validation) + its locked-down S3 bucket + the free external-access IAM Access Analyzer (`audit-trail.tf`); apply with a LabAdministrator session |
| `enable_session_manager` | `false` | One t4g.micro with no inbound port, SSH key or public IP, reachable only by a Session Manager shell through four VPC endpoints (~$1/day while on); transcripts to CloudWatch Logs; the `LabServerSession` permission set for the SCIM copy of `PIM-AWS-Lab-Admins` (`session-manager.tf`); apply with a LabAdministrator session, turn off after a capture |

**`okta/` (human-applied)**

| Flag | Default | Effect |
|---|---|---|
| `enable_entra_federation` | `false` | The Microsoft Entra ID OIDC identity provider + the routing rule for the clinic login domain (needs the Entra app's client id, the tenant id and `TF_VAR_entra_client_secret`). Off = only the clinic's own estate (group, rule, legacy app) |
| `routing_rule_active` | **`true`** | `false` = the routing rule goes INACTIVE: the runbook's Phase 1 rollback, clinic users back on Okta passwords; a `check` warns on every plan |

---

## Validate / fmt status

Re-validated 2026-10-20 with **HashiCorp Terraform v1.16.5** (`terraform
fmt -check -recursive` clean; `init -backend=false` + `validate` clean in
every directory below), and again on 2026-10-26 for `modules/apps`, `envs/dev`
and the new `okta` root. Providers locked: **azuread 3.10.0**, **azurerm
4.81.0**, **random 3.9.1**, **hashicorp/aws 6.69.1** (`aws/` only) and
**okta/okta 4.20.0** (`okta/` only).
OpenTofu v1.13.1 also validated every directory on 2026-10-19, before the
latest changes.

| Directory | `init -backend=false` | `validate` | `fmt` |
|-----------|-----------------------|------------|-------|
| `modules/apps` | ok | **Success** | clean |
| `modules/conditional-access` | ok | **Success** | clean |
| `modules/dc-vm` | ok | **Success** | clean |
| `modules/entitlement` | ok | **Success** | clean |
| `modules/entra-diagnostics` | ok | **Success** | clean |
| `modules/evidence-store` | ok | **Success** | clean |
| `modules/groups` | ok | **Success** | clean |
| `modules/intune-vm` | ok | **Success** | clean |
| `modules/keyvault` | ok | **Success** | clean |
| `modules/monitoring` | ok | **Success** | clean |
| `modules/pim` | ok | **Success** | clean |
| `modules/pipeline-identity` | ok | **Success** | clean |
| `envs/dev` (whole composition) | ok | **Success** | clean |
| `envs/bootstrap` | ok | **Success** | clean |
| `aws` (separate root, hashicorp/aws 6.69.1) | ok | **Success** | clean |
| `okta` (separate root, okta/okta 4.20.0) | ok | **Success** | clean |
| `k8s/platform`, `k8s/identity`, `k8s/aks-mapping` | ok | **Success** | clean |

What the committed code itself enforces (`validation` / `precondition` /
`check` blocks and plain expressions, so you can check each in the file named):

- **CA:** every policy defaults to report-only; `ca_policy_states` rejects a
  missing key, an unknown key and an invalid state; break-glass is excluded
  from every policy; CA008 all-users enforcement and a workforce rollout
  without the admin AAGUID list each need a second key
  (`modules/conditional-access/variables.tf`, `main.tf`).
- **Break-glass:** the domain must be `*.onmicrosoft.com` and there are at
  least two accounts (`modules/groups/variables.tf`).
- **PIM:** Tier 0 without approvers fails at plan; Global Administrator can
  never be a tier group's role; a Tier-0 role cannot sit in a Tier-1 group;
  Tier-0 groups cannot waive approval; Tier-0 eligibility cannot exceed 180
  days; the `c1` authentication context is refused until CA021 is declared
  enforced (`modules/pim/variables.tf`, `envs/dev/main.tf`).
- **Key Vault and VMs:** a malformed IP range or one wider than /24 is
  rejected (the same rule guards `operator_ip_ranges` in `envs/dev`; DC01
  accepts single hosts only), and an empty allow-list turns public network
  access off (`modules/keyvault/variables.tf`, `modules/dc-vm/variables.tf`).
- **Staging:** every premium/governance module sits behind its `lab.tfvars`
  flag (`count` in `envs/dev/main.tf`), whose `check` blocks warn on flag
  combinations that cannot work. Access reviews fail at plan without a
  fallback reviewer group and are risk-tiered per ADR 0012: a birthright
  clinical package is never reviewed by a person (`modules/entitlement/`).
- **Detections:** containment never runs on the SoD or vault rules; the
  identity ids the ITDR rules judge by are immutable ids, never display names
  (`modules/monitoring/`).
- **Bootstrap:** the APPLY federated subject is environment-scoped
  (`modules/pipeline-identity/main.tf`); its RBAC-admin grant carries the
  ABAC role condition, and CI state access is container-scoped
  (`envs/bootstrap/main.tf`); a write role can never be added to PLAN.

## Tests (mocked, offline)

`terraform init -backend=false && terraform test` in each directory below
(`envs/dev` with `-var-file=lab.tfvars`). Every provider is a
`mock_provider`, so no tenant, subscription or cloud credential is involved.
`.github/workflows/lab-tests.yml` runs `validate` in every directory and
every one of these tests on each pull request (configured; no workflow has
run yet).

**Last run: 2026-10-26, HashiCorp Terraform 1.16.5, author's machine, the
working tree: 356 runs passed, 0 failed, across 19 directories** (333 in the
Entra / Azure / AWS / Okta roots and modules, 23 in the three Kubernetes
roots), and `validate` passed in all 19. (2026-10-20: 325 runs in 18
directories, before `modules/apps/tests/okta.tftest.hcl` and the `okta` root.)

| Directory | Test file(s) | Runs | What it asserts |
|---|---|---|---|
| `envs/dev` | `mock_plan.tftest.hcl` | 13 | The composition plans with the committed `lab.tfvars` and none of the staged layers plans anything; `lab.tfvars` holds back every SecurityEvent rule, the preview rule, the vault anomaly rule and `identity_risk`, on the Sentinel and the Log Analytics path; with every flag on it plans on both detection paths (Sentinel, Log Analytics alerts); legacy flags on with new flags off; the `c1` context refused while CA021 is report-only, in the same change that enables CA021, and without the tenant attestation, and allowed once CA021 is enforced; no DC keeps a /24 out of the watchlist; DC01 refuses a range wider than one host; flags without premium warn |
| `envs/bootstrap` | `optin.tftest.hcl` | 15 (2026-11-07) | `enable_evidence_delete_lock` adds one CanNotDelete lock on the evidence ACCOUNT (never the RG), none by default, refused without the account name; Nothing extra by default (no Azure Policy guardrail either; `enable_azure_guardrails` assigns both in Audit, a typo'd effect refused); `enable_pim_demo_readers_azure_rbac` grants exactly Reader, Microsoft Sentinel Reader and Log Analytics Reader (pinned role ids) to the PIM group at subscription scope, refused without a group id or for a group that is not the role-assignable PIM-Demo-Readers, and never widens APPLY's delegable roles; `enable_app_management_roles` adds exactly the four APPLY and two read-only PLAN roles; `enable_identity_protection_logs` adds the four risk categories to the baseline |
| `aws` | `github_oidc`, `entra_operator`, `lab_admin`, `patient_portal`, `audit_trail` (`.tftest.hcl`) | 30 (2026-11-06) | GitHub OIDC: off by default; the role trusts one repository's PR subject only; every allow is a read; wildcard and environment subjects refused; missing repository ids fail; an existing OIDC provider is reused. Operator: trust pinned to the operator, guardrails v2 + v3 (no IAM, Identity Center or account-creating writes; can't stop, delete or empty the audit trail). Audit trail: off by default; all regions, log file validation, management events only; bucket private, versioned, kept, writable only by this trail. Lab admin and patient portal: see `aws/README.md` |
| `okta` | `okta_federation.tftest.hcl` | 16 | By default only the clinic's estate (Clinic-Staff, its login-domain rule, the legacy bookmark app, one assignment); with `enable_entra_federation` the Entra OIDC IdP on the tenant's v2.0 endpoints (openid profile email, link by email) and ONE routing rule, priority 1, suffix-matching the clinic login domain only and targeting that IdP, attached to Okta's built-in discovery policy by data source (the Default Rule stays); the secret is sensitive end to end and, like the client and tenant ids, required when on; the rollback sets the rule INACTIVE, keeps the IdP and raises the warning check; JIT can be turned off; an @ or scheme in the domain, a plain-http app URL, a non-Okta cell, a host or -admin org name and a non-GUID client id refused; one mocked apply |
| `modules/apps` | `apps.tftest.hcl`, `servicenow.tftest.hcl`, `okta.tftest.hcl` | 46 | One AWS assignment, SAML basics and claims, wildcard reply URL and wrong template refused, three app roles mapped to fixed ids, SCIM absent by default and created stopped, empty SCIM token fails the gated apply and only warns in a PR plan, guacamole-psm id-token only and operators only; ServiceNow absent by default, one assignment, the sign-on URL from the IdP `sys_id`; a missing group or instance URL, a wildcard, trailing-slash, path, non-ServiceNow or plain-http instance URL and a malformed `sys_id` refused; three mocked applies; okta-clinic-idp absent by default, when on one app (single tenant, implicit grants off, the Graph scopes Okta asks for), one SP (assignment required), one assignment to App-Okta-Federation-Users and one redirect URI (the Okta authorize callback, https by construction), the ITSM reference stamped, the flag without an org host or group fails the plan, a scheme, path, wildcard, non-Okta host, look-alike suffix or -admin host refused, preview and EMEA cells accepted, a secret lifetime over 180 days refused; a fourth mocked apply (the bounded secret-minting command, the NHI row) |
| `modules/conditional-access` | `ca002_ca020_ca021_admins`, `ca004`, `ca006_ca007_risk`, `ca008_phishing_resistant`, `ca009_ca010_baseline`, `ca060_clinical` (`.tftest.hcl`) | 71 | CA002 role list cannot shrink; CA020 session-only, report-only, 4 h max; CA021 rendered report-only and its contract with the post-apply script, and the PIM context refused until CA021 is enforced and attested; CA023 off by default, report-only, never on the PIM context; risk policies report-only with the safe shape; CA008 scope, second keys, phishable combinations refused, break-glass excluded from every policy; CA009 multi-use TAP refused; CA010 exception group next to break-glass; CA022 targets the PSM app + admin portals with the ADMIN strength; CA060 device filter and injection-safe profile name; CA004 uses the bare named-location GUID |
| `modules/dc-vm` | `operator_ip.tftest.hcl` | 11 | Only single-host operator addresses open RDP / LDAPS; /24, /31, any-address, bare, IPv6 and malformed entries refused; disk and outbound shape unchanged |
| `modules/entitlement` | `governance.tftest.hcl` | 26 | Defaults match `lab/iga/access-catalog.json`; birthright packages have no policy and no expiry; T1 never reviews clinical packages; T2 only long or extendable packages; reviews deny by default; no self-review; break-glass never a review target; requested birthright, expiring automatic and automatic privileged packages refused; B2B package shape |
| `modules/azure-guardrails` | `guardrails.tftest.hcl` | 7 (2026-11-06) | Audit by default (assignment and definition); the Owner rule matches a real `/subscriptions/<id>/providers/...` role definition id (the old `equals` never did), one wildcard, not Contributor; allowed principals reach the assignment; Deny with nobody allowed refused; the Key Vault rule is the built-in logic (purge protection exists and on, recover skipped, no `notEquals "true"`, the missing-soft-delete check only under the old-API guard); bad inputs refused |
| `modules/entra-diagnostics` | `categories.tftest.hcl` | 7 | Baseline user, NHI and Graph categories; risk categories added by the switch; deduplication; a table name or a case typo instead of a category refused; AuditLogs cannot be dropped |
| `modules/evidence-store` | `worm.tftest.hcl` | 13 | WORM and Entra-only by default; retention bounds; lock needs acknowledgement; firewall format; wide ranges refused; writers container-scoped and cannot delete |
| `modules/groups` | `optional_groups.tftest.hcl` | 4 | Optional groups absent by default; the consent reviewers group is not role-assignable; All-Workforce never matches break-glass or guests; Admin-Accounts is role-assignable with assigned (standing) membership |
| `modules/intune-vm` | `network_exposure.tftest.hcl`, `vm_identity.tftest.hcl` | 41 | RDP is the only inbound allow and only from the operator entries (up to /24; /23 and wider, any-address, service tags, bare, IPv6 and malformed entries refused); Standard static public IP, no DNS label; size, image SKU, licence and Trusted Launch pinned; OS disk shape; system-assigned identity only; Intune enrolment on by default; one VM Administrator Login assignment per user or group at VM scope, none by default; nightly deallocation; multi-session, Pro and Windows 10 SKUs, bad hostnames, a reserved admin name and non-GUID object ids refused |
| `modules/keyvault` | `diagnostics.tftest.hcl`, `uami_abac.tftest.hcl` | 6 | Empty workspace id refused; wide IP range refused; the UAMI's read is ABAC-limited to the named secrets and an empty allow-list is refused |
| `modules/monitoring` | `itdr.tftest.hcl`, `itdr_v2.tftest.hcl` | 32 | Defaults create nothing; ITDR rules map the `.kql` columns; telemetry before Sentinel; containment only on High ITDR incidents, only with Sentinel and never on the SoD or vault rules; Log Analytics path skips the Sentinel-only rules; DC01 DCR events; ids rendered and display names refused; `operator_ips` watchlist ranges, expiry and owner rules; `vault_feed_v2_columns` |
| `modules/pim` | `pim.tftest.hcl` | 46 | Defaults keep only the original binding; PIM-Demo-Readers holds exactly Global Reader + Security Reader, PT8H MFA activation with no approval, mailed, reviewed, outside the CA scope and the tier map; tier groups and their notifications; one approver warns; the `c1` context replaces MFA only once CA021 is enforced, and the two-apply switchover; Global Administrator refused in a tier group; Tier-0 roles cannot sit in Tier 1; approval cannot be waived on Tier 0; Tier-0 eligibility capped at 180 days; help-desk AU scoping; the Global Administrator policy bodies; Azure PIM shape; Privileged-IAM-Admins can hold neither Global Administrator nor a Tier-0 role |
| `modules/pipeline-identity` | `plan_roles.tftest.hcl` | 5 | PLAN's opt-in Graph roles are an allow-list of read roles: ReadWrite, Invite, Create, Send and Manage roles refused |
| `k8s/platform` | `platform.tftest.hcl` | 5 | Pod Security labels; Vault release pinned; injector webhook fails closed; weak root token and non-kind context refused |
| `k8s/identity` | `identity.tftest.hcl` | 11 | Vault role trusts one service account; read-only policy on one path; no API token mounted; human RBAC has no secrets and no cluster scope; admission policy binds the workload to one digest and the pipeline |
| `k8s/aks-mapping` | `aks_mapping.tftest.hcl` | 7 | The federated credential trusts exactly the workload; plain-http, kind, loopback and private-IP issuers refused |

Run them with `terraform`, not `tofu`: OpenTofu's mock providers fill in
computed ids at plan time, which hid an "Invalid count argument" error in
`modules/keyvault` that Terraform's plan (computed ids unknown, as in a real
first plan) caught. The `aws/` root documents its own checks in
[`aws/README.md`](aws/README.md).

Run every directory the way CI does:

```bash
for d in envs/dev envs/bootstrap aws okta k8s/platform k8s/identity k8s/aks-mapping modules/*; do
  terraform -chdir="$d" init -backend=false -input=false >/dev/null &&
  terraform -chdir="$d" validate &&
  { [ -d "$d/tests" ] || continue; terraform -chdir="$d" test $( [ -f "$d/lab.tfvars" ] && echo -var-file=lab.tfvars ); }
done
```

- No `terraform apply` has run — **no tenant exists yet**. Every statement
  above is a `validate` / `fmt` / mocked-test result or a property of the
  committed code, not a deployment result.
- The four roots (`envs/dev`, `envs/bootstrap`, `aws`, `okta`) carry a
  `.terraform.lock.hcl` meant to be **committed**: `registry.terraform.io`
  hashes generated by HashiCorp Terraform 1.16.5 with `terraform providers lock
  -platform=linux_amd64 -platform=darwin_arm64 -platform=darwin_amd64`
  (see `.gitignore`). Both workflows pin Terraform 1.16.5 to match. Child
  modules have no lock file. `tofu init` rewrites a root's lock file with
  `registry.opentofu.org` entries, so validate with tofu in a scratch copy (or
  `git checkout` the lock file afterwards) and never commit a tofu-written one.
- **Checkov.** Run locally with Checkov 3.3.20 on 2026-10-20 (`checkov -d
  lab/terraform --framework terraform`): **46 passed, 0 failed, 10 skipped**.
  Every skip is an inline `#checkov:skip=<ID>:<reason>` on its resource:
  - `dc-vm` and `intune-vm`: CKV_AZURE_151 (encryption at host: needs the
    `EncryptionAtHost` subscription feature; the disks use platform-managed
    server-side encryption) and CKV_AZURE_50 (VM extensions: the DC is built
    with `az vm run-command`, and the endpoint's Entra join needs the
    `AADLoginForWindows` extension);
  - `dc-vm`'s NTDS disk: CKV_AZURE_93 (platform-managed keys by design, the
    same trade-off as the evidence store);
  - `pipeline-identity`: CKV_AZURE_249 on the two GitHub federated
    credentials (their subjects are pinned to the immutable owner@id/repo@id
    form, which the check's pattern does not recognise);
  - `evidence-store` (CKV_AZURE_33, CKV_AZURE_59) and `keyvault`
    (CKV_AZURE_189), with the reasons in their `main.tf`.

  Until 2026-10-20 the first seven were a documented baseline of 8 failed
  checks. The eighth, CKV_AZURE_251, is fixed rather than skipped: the NTDS
  disk now has `public_network_access_enabled = false` and
  `network_access_policy = "DenyAll"` (asserted in `dc-vm`'s tests; BUILT,
  not applied). `terraform-plan.yml` runs Checkov on every PR that touches
  `lab/terraform/**` with `soft_fail: false`, so any new failed check blocks
  the merge. Version gap: the pinned `checkov-action` runs Checkov **3.3.3**
  (an image tag the workflow cannot override), not 3.3.20, so CI may report
  a different set of checks (verify: on the first CI run).

---

## Human steps Terraform CANNOT do (portal / Microsoft Graph)

These require the portal or a Graph call **after** `apply`. They are either
unsupported by the providers or are consent/approval actions that must be
performed by a privileged human.

1. **Grant admin consent for the pipeline Graph app roles.**
   `azuread_app_role_assignment` assigns the Graph application permissions,
   but in some tenants the grant must be **confirmed as consented** by a
   Global Administrator / Privileged Role Administrator. Verify in
   *Entra admin center → App registrations → (apply app) → API permissions*
   that each role shows **“Granted for <tenant>.”** If not, click
   **“Grant admin consent.”**

2. **Directory-role PIM policies are Graph, not Terraform.** For most roles
   the design avoids them: each privileged role is held *actively* by an
   empty, role-assignable group, and the just-in-time control is that group's
   PIM-for-Groups activation policy, which the provider fully expresses
   (`azuread_group_role_management_policy`). Global Administrator is the
   exception (named, direct, expiring eligibility, [ADR 0020](../docs/adr/0020-pim-activation-design.md)):
   azuread 3.10 has no directory-role policy resource, so `modules/pim`
   renders the rules (output `directory_role_pim_policies`) and
   `post-apply/Set-DirectoryRolePimPolicies.ps1` writes them. The CA021
   authentication context is the same pattern (`Set-AuthContextPolicies.ps1`).

3. **Make named people eligible members.** Who may activate is HR-dependent
   operational data, so it is set after HR provisioning by
   `lab/scripts/powershell/post-apply/Set-PimGroupEligibility.ps1` (named
   `adm-` accounts passed explicitly; 180-day Tier-0, 365-day Tier-1
   eligibility; it warns when a person is also in the tier's approver group)
   rather than in Terraform.

4. **Separation of duties and birthright.** The azuread provider exposes
   neither `incompatibleAccessPackages` nor automatic assignment policies.
   `post-apply/Set-AutoAssignmentPolicies.ps1` creates one HR-attribute
   automatic policy per birthright package (`lab/iga/birthright-rules.json`;
   needs **Identity Governance Administrator**), then
   `post-apply/Set-IncompatibleAccessPackages.ps1` writes the SoD links from
   `lab/iga/sod-rules.json` (SOD-01 to SOD-09), only on the requestable side,
   never on a birthright package, and `-Prune` removes the old
   Nurse → Pharmacy link. `Invoke-PostApply.ps1` runs them in that order
   (steps 5 and 6). `Set-AccessPackageSoD.ps1` is now only a forwarding shim.
   The Graph call underneath:
   ```
   POST /identityGovernance/entitlementManagement/accessPackages/{id}/incompatibleAccessPackages/$ref
   { "@odata.id": "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/{otherId}" }
   ```

5. **Verify the custom domain.** Workforce UPNs (built by the HR provisioning
   script, `-UpnDomain`) need a domain the tenant has **verified** (TXT
   record) and, for the hybrid path, an AD UPN suffix. Break-glass accounts
   deliberately use the onmicrosoft.com domain and do not depend on it.

6. **Break-glass accounts — post-apply hardening.** Terraform seeds a random
   password (in state) and then ignores password drift. A password alone will
   not get these accounts in: Microsoft's mandatory MFA for the Azure, Entra,
   Intune and M365 admin portals (and Azure CLI / PowerShell / ARM writes)
   covers break-glass accounts too, with no opt-out, and the CA exclusion
   does not change that. After apply:
   - enable the **Passkey (FIDO2)** authentication method for
     Break-Glass-Admins - now scripted as desired state by
     `lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`
     (device-bound, attested admin passkey profile; break-glass excluded from
     TAP / Authenticator / SMS / voice; PLAN by default, `-Apply` to write) -
     and register two FIDO2 security keys per account (a human step),
     kept in separate safes and not the method your daily admin uses
     (certificate-based auth instead, if you already run a PKI);
   - rotate the seeded password (state, which PR plans can read, keeps the
     old value) and keep the new one only as sealed physical copies in
     separate safes, as backup material, never the sole credential. If a
     digital copy is needed, use a separate vault that only the custodian
     can access and on which no workload or VM identity has a role - not
     `kv-idlab`, where the UAMI (*Secrets User*) and the DC's identity
     (*Secrets Officer*) hold data-plane roles. Both are ABAC-limited to named
     secrets, but a break-glass credential should not depend on a condition
     staying correct;
   - run `lab/scripts/powershell/01-Verify-Baseline.ps1` to prove the CA
     exclusions, keep `lab/kql/break-glass-signin.kql` alerting, and drill a
     sign-in to the Entra admin center with each key at least every 90 days.

   Sources: [emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access),
   [mandatory MFA](https://learn.microsoft.com/entra/identity/authentication/concept-mandatory-multifactor-authentication).

7. **Application-side SSO / SCIM.** AWS IAM Identity Center (SAML + staged
   SCIM), ServiceNow (PDI) SAML, the Clinical Portal (OIDC) and
   guacamole-psm are now **code** (`modules/apps`, behind `enable_sso_apps` /
   `enable_scim_provisioning` / `enable_servicenow_sso` /
   `enable_pam_oidc_app`). What stays human, in order, is in
   [`modules/apps/README.md`](modules/apps/README.md) "Staged order":
   activating each SAML signing certificate (azuread cannot set
   `preferredTokenSigningKeyThumbprint`), the AWS console identity-source
   switch, putting the AWS SCIM token into Key Vault, the one local seeding
   apply, and the ServiceNow-side identity provider record. ServiceNow
   provisioning is designed, not built. The Okta coexistence is code on
   both sides (`enable_okta_federation` here, the human-applied `okta/`
   root there; ADR 0022); what stays human is minting the one client secret
   (output `okta_idp_client_secret_command`, bounded to 180 days) and
   entering it once as `TF_VAR_entra_client_secret`, granting admin consent
   on `okta-clinic-idp`, and the Okta API token in the applier's shell
   ([`okta/README.md`](okta/README.md)). The AWS permission set +
   account assignment is code in the separate, human-applied `aws/` root.

8. **Remote-state storage account bootstrap** (see below) — created once,
   out-of-band, before `init` with the real backend.

9. **GitHub side of OIDC.** `envs/bootstrap` creates the Entra trust; copy its
   outputs into repo **Variables** (not secrets), create the `prod`
   environment with a required reviewer, and set the `TF_*` / `TFSTATE_*`
   variables listed in `lab/pipelines/README.md`. There are no repo secrets:
   the five privacy values (your IP, mailboxes, app owner ids) go to the
   pipeline config vault that `envs/bootstrap` creates
   (`enable_pipeline_config_vault`), and the workflows read them over OIDC.

10. **Lifecycle Workflows.** There is no azuread resource for them.
    `lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1` creates the
    joiner and leaver workflows (by name, idempotent) after the governance
    apply.

11. **Intune tenant settings + compliance policy** (before and after
    `enable_intune_vm = true`). No provider resource covers the MDM user scope,
    and enrollment happens during the join at apply time, so set the scope and
    license the pilot user **before** the flip.
    `lab/scripts/intune/New-IntuneComplianceBaseline.ps1` creates and assigns
    the compliance policy. Full list and order: `lab/scripts/intune/README.md`.

12. **Switching access reviews off.** The provider suppresses the diff when
    `assignment_review_settings` is removed, so `enable_access_reviews = false`
    leaves the reviews on the policies. Turn them off in the portal
    (*ID Governance → Access packages → <package> → Policies → <policy> →
    Lifecycle → Require access reviews = No*).

13. **Tenant policy the providers cannot express.** Run in dependency order
    by `lab/scripts/powershell/post-apply/Invoke-PostApply.ps1` (dry run
    unless `-Execute`; the break-glass check is step 1 and a gate): the
    cloud-only `adm-` admin accounts and their Admin-Accounts membership, the
    authentication methods policy, the CA021 and CA023 authentication
    contexts, the CA011 Token Protection pilot, birthright automatic assignment, SoD links,
    Lifecycle Workflows, the Global Administrator PIM policy, PIM eligibility,
    the help-desk AU rule and the VIP restricted AU, standalone access reviews,
    the B2B connected organization and external collaboration settings, the
    app management + consent policies, the Entra Agent ID and, last and
    opt-in, converting the build account's standing Global Administrator to
    eligible. Each script is idempotent and has `-WhatIf` / PLAN mode. Order,
    scopes and modes: [`lab/scripts/powershell/README.md`](../scripts/powershell/README.md).

14. **Microsoft-managed risk policy.** Before `enable_identity_protection_ca`,
    find Microsoft's managed "require risk remediation" Conditional Access
    policy (rolling into P2 tenants) and set it to report-only or Off by hand,
    so CA006 is the single user-risk policy while evidence is captured
    (`modules/conditional-access/main.tf` header, verify: MC1507808).

15. **Grants CI must never make.** A human Owner / User Access Administrator:
    applies `enable_pim_azure_resources` (the APPLY identity cannot write PIM
    role-management policies), grants the evidence-store writer role with the
    `evidence_writer_abac_condition` output, grants *Monitoring Metrics
    Publisher* on `dcr-idlab-vault-checkout` for the vault feed, and runs
    `lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1` (Graph app roles
    for the playbook's managed identity).

16. **Pipeline widening (bootstrap, human).** Before `enable_sso_apps`, re-apply
    `envs/bootstrap` with `enable_app_management_roles = true` (adds the Tier-0
    `AppRoleAssignment.ReadWrite.All` - record it in the risk register); once
    the P2 licences are assigned, `enable_identity_protection_logs = true` so
    the ITDR identity-risk rule has `AADUserRiskEvents` / `AADRiskyUsers`.

17. **ITDR portal steps.** Enable the Sentinel "Windows Security Events via
    AMA" connector before removing the DC01 rules from `itdr_exclude_rules`
    (verify: `SecurityEvent` via AMA needs Sentinel and the connector);
    create `ITDR-Containment-Approvers` and authorize the playbook's Teams
    connection after `Deploy-ContainmentPlaybook.ps1`; turn on the DC01
    audit subcategories the AD-plane rules read (Kerberos Service Ticket
    Operations, Security Group Management) and, for DCSync, a SACL on the
    domain's replication rights. Order and evidence:
    `lab/scripts/monitoring/README.md` and `lab/docs/evidence-capture-plan.md`.

---

## Remote-state bootstrap (one-time, out-of-band)

`backend.tf` expects a **versioned** storage account. Create it once before
`terraform init` with the real backend:

```bash
az group create -n rg-identity-lab-tfstate -l eastus2

# Entra auth only: both backends set use_azuread_auth = true, so nothing in
# the lab needs the account keys.
az storage account create \
  -n stidlabtfstate -g rg-identity-lab-tfstate -l eastus2 \
  --sku Standard_LRS --kind StorageV2 \
  --min-tls-version TLS1_2 --allow-blob-public-access false \
  --allow-shared-key-access false

# Versioning + soft delete + change feed = recoverable, audited state.
az storage account blob-service-properties update \
  --account-name stidlabtfstate -g rg-identity-lab-tfstate \
  --enable-versioning true \
  --enable-delete-retention true --delete-retention-days 30 \
  --enable-container-delete-retention true --container-delete-retention-days 30 \
  --enable-change-feed true

# Your admin needs a data-plane role before --auth-mode login works (Owner
# has no blob data actions); allow a few minutes for it to propagate.
az role assignment create --role "Storage Blob Data Contributor" \
  --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
  --assignee-principal-type User \
  --scope "$(az storage account show -n stidlabtfstate -g rg-identity-lab-tfstate --query id -o tsv)"

az storage container create \
  --account-name stidlabtfstate -n tfstate --auth-mode login

# Separate container for envs/bootstrap: CI gets no role on it (and see the
# lock below for why that holds).
az storage container create \
  --account-name stidlabtfstate -n tfstate-bootstrap --auth-mode login
```

`use_azuread_auth = true` in both `backend.tf` files only sets how Terraform
authenticates; `--allow-shared-key-access false` is what makes the account
refuse key-based requests. The CI identities get container-scoped state roles
on `tfstate` only, via `envs/bootstrap`.

**After the first `envs/bootstrap` apply, lock the account.** That apply
creates CI's container-scoped role assignments, which the lock would block:

```bash
az lock create -n lock-tfstate-readonly --lock-type ReadOnly \
  -g rg-identity-lab-tfstate --resource stidlabtfstate \
  --resource-type Microsoft.Storage/storageAccounts
```

Why: CI's APPLY identity is subscription **Contributor**, which includes
`listKeys` and storage-account writes. Without the lock it could turn Shared
Key back on, list the keys and read or overwrite every container
(`tfstate-bootstrap` and the dev state's secrets included), switch off
versioning and soft delete, or delete the account. Contributor cannot create
or remove locks (`Microsoft.Authorization/*/Write` and `*/Delete` are
NotActions), and the constrained RBAC Administrator grant covers role
assignments only. A ReadOnly lock blocks the `listKeys` POST, account and
blob-service property writes, and deletion. Locks do not apply to data-plane
calls, so Entra-authenticated state reads, writes and blob leases keep
working.

- **Trade-off:** the lock also blocks role assignments scoped to the account
  or a container. Lift it (`az lock delete` with the same name and resource
  arguments) around any `envs/bootstrap` apply that changes those state role
  assignments, then lock again. Other bootstrap applies only read the account
  through the `azurerm_storage_account` data source, whose provider code
  treats a 409 from `listKeys` as a lock and carries on (verify: on the first
  bootstrap plan after locking).
- **Residual risk:** APPLY's Tier-0 Graph rights
  (`RoleManagement.ReadWrite.Directory`, see `lab/pipelines/README.md`),
  mitigated by the `prod` reviewer gate. Production would keep state in a
  subscription where CI has no Azure role at all.

## Apply order (whole lab)

1. Bootstrap the state account (above).
2. `envs/bootstrap` — local, human: CI identities + RBAC; grant admin consent;
   then add the ReadOnly lock on the state account (above).
   Seed the envs/dev state blob once, as yourself:
   `terraform -chdir=lab/terraform/envs/dev init -input=false -backend-config=resource_group_name=<rg> -backend-config=storage_account_name=<sa>`.
   When the key is missing, the azurerm backend writes an empty state (under
   a lease) during init. The Reader-only PLAN identity cannot do that, so
   without this the first PR plan fails.
3. `envs/dev` with `lab.tfvars` flags `false/false` — via the pipeline: RG, Log
   Analytics, Key Vault (free tier, no trial clock). Then `enable_dc = true`
   and build the DC with `lab/scripts/dc/` (still no trial clock).
4. Start the E5 + Governance trials, then a PR flipping both flags to `true`:
   break-glass, groups, CA (all report-only, CA005 pilot-scoped), PIM, access
   packages. Optional later PRs:
   - the three review tiers, one PR each (after governance, once HR users
     with managers exist): `enable_access_reviews_privileged`,
     `enable_access_reviews_requestable`, `enable_access_reviews_inactive`.
     Set `TF_ACCESS_REVIEW_FALLBACK_GROUP_OBJECT_ID` first (CI passes no
     approver group to fall back on), or the plan fails. Switching a policy
     review off again is a portal step (human step 12).
   - `enable_intune_vm = true` (after premium): first re-apply `envs/bootstrap`
     locally so CI may delegate *Virtual Machine Administrator Login*, and do
     the MDM user scope + licence prerequisites in `lab/scripts/intune/README.md`.
5. Post-apply: `terraform output -json`, then
   `lab/scripts/powershell/post-apply/Invoke-PostApply.ps1` (`-ListOnly`,
   then the dry run, then `-Execute`). It runs `01-Verify-Baseline.ps1` first
   as a gate and every other step whose flag is on, in dependency order
   ([`lab/scripts/powershell/README.md`](../scripts/powershell/README.md)).
   PIM eligibility needs HR-provisioned people, so pass `-PimEligibility`
   after HR provisioning. For the Intune demo:
   `lab/scripts/intune/New-IntuneComplianceBaseline.ps1` (the runbook runs it
   just before the `enable_intune_vm` flip).
6. AWS (separate cloud, local, human): after the SAML + SCIM portal steps in `aws/README.md` (Order of operations, step 2) and once SCIM has created
   `App-AWS-IdentityCenter-Users` in Identity Center, `aws sso login` (profile with AWSSSOMasterAccountAdministrator +
   IAMFullAccess — the lab target is the management account) and apply `aws/` (see `aws/README.md`).
   It grants the group ViewOnlyAccess (PT4H) — the last AWS click-op becomes code.
7. Graduate CA policies one PR at a time by editing `lab.tfvars`.
8. Second `envs/bootstrap` apply with `log_analytics_workspace_id` (Entra logs
   flowing). A few hours later: `enable_sentinel = true` (starts the 31-day
   Sentinel trial), then `lab/scripts/monitoring/Deploy-Playbook.ps1` and set
   `sentinel_playbook_id`. After the trial: `enable_sentinel = false`,
   `enable_la_alerts = true`.
9. Senior-scope layers, one PR each, in the order and on the days of
   [`lab/docs/evidence-capture-plan.md`](../docs/evidence-capture-plan.md)
   (every flag is `false` in `lab.tfvars`, so nothing starts early):
   `enable_evidence_store` (before Day 0) → `enable_itdr_detections` (before
   `enable_sentinel`: telemetry only, no trial) → `enable_identity_protection_ca`
   + `enable_phishing_resistant_all_users` (report-only) → the other CA
   additions, each report-only (`enable_registration_ca`,
   `enable_device_code_block`, `enable_admin_session_controls`,
   `enable_pim_auth_context`, `enable_protected_actions_ca`,
   `enable_shared_clinical_ca`) →
   `enable_pim_tiers` (+ `enable_helpdesk_au_scoping`,
   `enable_global_admin_pim_policy`; `enable_pim_azure_resources` is a human
   apply) → the `c1` switch for Tier 0 once CA021 is enforced (CA021
   `enabled` in one change; after `Set-AuthContextPolicies.ps1` reports it
   enabled, `ca021_enforced_in_tenant = true`; then
   `pim_tier0_auth_context_switchover_step1`, then
   `pim_tier0_activation_auth_context_id = "c1"`) → `enable_sso_apps` →
   `enable_scim_provisioning` (local seeding apply) → `aws_scim_job_enabled` →
   `enable_servicenow_sso` (once a ServiceNow developer instance exists) →
   the review tiers / `enable_b2b_governance` → `enable_nhi_governance` +
   `enable_agent_identity` → `enable_itdr_detections_v2` (+
   `vault_feed_v2_columns` with the vault feed change) →
   `enable_itdr_containment` (after `Deploy-ContainmentPlaybook.ps1`;
   `containment_on_alert_added` only if the Defender portal correlates ITDR
   alerts into older incidents) → `enable_pam_oidc_app` (with the PAM
   segment: guacamole-psm + CA022). After each: `Invoke-PostApply.ps1`. The
   evidence-store lock (`evidence_immutability_lock_acknowledged`) is its own
   PR at the end of the window.

---

## Kubernetes workload identity (`k8s/`)

A self-contained segment, **not** part of the apply order above. Two applied
roots, with no Azure or Entra provider, configure a throwaway **kind**
cluster (the AKS stand-in, see [`../docs/STAND-INS.md`](../docs/STAND-INS.md))
that `lab/k8s/ci/pipeline.sh` builds, tests and destroys in one run, on a
laptop or in `.github/workflows/k8s-identity.yml`. A third root,
`k8s/aks-mapping` (`hashicorp/azuread`), is **plan-only and never applied**
by anything: it writes the Entra Workload ID equivalent of the Vault role and
is checked offline only (`fmt`, `validate`, mocked `test`), because Entra
must fetch the cluster's OIDC issuer keys and kind's issuer is not public.
Design, decisions and how to run it: [`../k8s/README.md`](../k8s/README.md).

- **Two stages** because the vault provider cannot be configured before Vault
  exists: `k8s/platform` (helm + kubernetes providers: namespaces, Vault Helm
  release), then `k8s/identity` (vault + kubernetes providers: Kubernetes auth
  role bound to one service account with audience `vault`, read-one-path
  policy, service accounts, group Roles/RoleBindings, and the
  ValidatingAdmissionPolicy `clinical-apps-workload-identity` that binds the
  `nightly-report` identity to one image digest and to the pipeline).
- **Local state, no backend:** the cluster lives for one run. The secret's
  value is seeded by the pipeline over Vault's HTTP API, never a Terraform
  argument, so it is not in state. The Vault dev root token is an
  `ephemeral`, `sensitive` variable that reaches Helm only through the
  write-only `set_wo` (stage 1) and the Vault provider block (stage 2), so it
  is in neither plan nor state; it does live inside the throwaway cluster (the
  vault-0 StatefulSet env, Helm's release Secret, the dev-mode startup log)
  until teardown (full list: [`k8s/platform/README.md`](k8s/platform/README.md#decisions)).
  The local state is gitignored (`*.tfstate*`) anyway.
- **Lock files** are committed like the other roots, but for `linux_amd64` +
  `darwin_arm64` only (the CI runner and the dev Mac); `aks-mapping` locks
  `hashicorp/azuread` 3.10.0, the version the lab's other Entra roots lock.
- **Tested twice:** the three k8s roots' mocked tests
  (`k8s/platform/tests/platform.tftest.hcl`,
  `k8s/identity/tests/identity.tftest.hcl`,
  `k8s/aks-mapping/tests/aks_mapping.tftest.hcl`, 23 runs) run in stage 2 of
  `pipeline.sh` and in `lab-tests.yml` with every other directory. `terraform-plan.yml`'s `fmt -check -recursive` and Checkov
  also cover `k8s/`, since they scan all of `lab/terraform/**`; the `envs/dev`
  plan and apply do not include it (separate roots), and no workflow plans
  `aks-mapping` against a tenant.

---

## Security notes

- **Break-glass exclusion** is wired on every CA policy via the group object
  id — the one invariant that prevents a CA lockout.
- **Least privilege:** every privileged role is reached through one
  just-in-time PIM-for-Groups activation, tiered by what the role can reach
  (Global Administrator only through named, expiring eligibility; break-glass
  is the one standing holder); the Key Vault UAMI gets *Secrets
  User* ABAC-limited to its own secret name(s) only; the CI **plan** identity is
  read-only (it can read, never write, Terraform state - which holds
  generated initial passwords, so any same-repo PR run can read them), the **apply**
  identity is gated to the `prod` GitHub environment, can only delegate the two
  Key Vault data roles and *Virtual Machine Administrator Login* (for the
  Intune VM), and cannot change its own app, federation or RBAC through a PR
  (those live in human-applied `envs/bootstrap`). That is change control, not
  a privilege boundary: `RoleManagement.ReadWrite.Directory` makes APPLY
  effectively Tier 0, and subscription Contributor lets it delete or cap
  `loga-idlab`. The ABAC condition limits
  *which* role, not the scope or the principal, so a compromised APPLY
  identity could grant admin sign-in to any Entra-joined VM in the
  subscription (today only the Intune VM); accepted for the lab and documented
  in `envs/bootstrap/main.tf`. CI never holds AWS
  credentials: `aws/` is applied by a human from a short-lived SSO session.
- **CA005 is pilot-scoped.** It targets `CA005-Pilot-CompliantDevice`, never
  all admins, so enforcing it does not lock out an operator who administers
  from an unmanaged Mac (keep your own admin account out of the pilot group).
- **Report-only first:** every CA policy ships report-only; enforcement is a
  one-line `lab.tfvars` PR per policy.
- **No secrets in code.** Passwords are generated (`random_password`) and land
  only in state; state lives in the locked, versioned remote backend (the
  `aws/` root keeps a local, gitignored state with no secrets in it);
  `terraform.tfvars` / `*.auto.tfvars` are gitignored; `lab.tfvars` (policy
  knobs only) is committed.
- **No invented resources.** Where a provider resource was uncertain it is left
  as a commented stub tagged *“verify against provider docs,”* never guessed.
