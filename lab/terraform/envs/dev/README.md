# envs/dev — Contoso Health IAM/PAM lab (root composition)

This root module wires ten building-block modules (all except the Key Vault
create nothing until their staging flag is on; `monitoring` is always called
but its resources sit behind `enable_sentinel` / `enable_la_alerts` /
`enable_itdr_detections`) into one
deployable environment for the **Contoso
Health** Entra ID identity lab. It is applied by
the GitHub Actions pipeline. The pipeline's own identities live in
[`../bootstrap`](../bootstrap), which a human applies locally, so a PR here can
never change CI's own permissions.

> Everything here is parameterised. The shared contract names
> (`rg-identity-lab`, `kv-idlab`, `loga-idlab`, `eastus2`, break-glass
> accounts, the *Clinical* catalog, etc.) are the **defaults**. Tenant
> identifiers go in `terraform.tfvars` (local) or `TF_*` GitHub variables (CI).

Workforce users are **not** created here. Dana Okafor and colleagues come
from HR provisioning (`lab/scripts/mock-hr`): HR → AD → Cloud Sync → Entra.

---

## Two kinds of input

| File | Committed? | Holds | Why |
|---|---|---|---|
| `lab.tfvars` | **yes** | staging flags, CA policy states, blocked countries | Every policy change is a reviewable PR diff. Flipping CA004 here is the on-camera pipeline demo. |
| `terraform.tfvars` (from `.example`) | no (gitignored) | subscription/tenant ids, onmicrosoft domain, approver ids (incl. Tier-0 `pim_tier0_approver_object_ids`), review groups (`access_review_fallback_group_object_id`, `privileged_review_reviewer_group_object_id`), `b2b_connected_organization` + `_id`, AWS SAML values (`aws_saml_entity_id`, `aws_saml_acs_urls`, `aws_access_portal_url`, `aws_scim_template_id`), app owners, containment playbook id, evidence storage account name, Intune VM login user ids, Key Vault name + allowed IP | Tenant-specific identifiers. In CI they come from `TF_*` repo variables, except the operator IP and alert email, which are repo secrets (`TF_OPERATOR_IP_RANGES`, `TF_ALERT_EMAIL`) so the public logs mask them. CI passes no `entitlement_approver_group_object_id`, so there package approval goes to the requestor's manager. |

---

## Staging flags (no trial starts before you're ready)

| `enable_premium` | `enable_governance` | What exists | License needed |
|---|---|---|---|
| false | false | RG, Log Analytics, Key Vault (+ PE, UAMI) | none (Azure only) |
| true | false | + break-glass, groups, CA (report-only), PIM | Entra ID P1/P2 (M365 E5 trial) |
| true | true | + catalog, 3 access packages | + Entra ID Governance trial |

Governance-tier option (needs both flags above `true`; the
`access_reviews_require_governance` check warns otherwise):

| Flag | Adds | Clock / cost |
|---|---|---|
| `enable_access_reviews` | a recurring **quarterly** access review on every access-package policy: the user's manager reviews, `access_review_fallback_group_object_id` (else the approver group) covers users without a manager, unanswered = removed | no new trial (Governance); creates real review campaigns that email reviewers. Plan fails without a fallback group. Setting it back to `false` does **not** remove the reviews (provider diff suppression); switch them off in the portal |

Independent flags (any phase, except where noted):

| Flag | Adds | Clock / cost |
|---|---|---|
| `enable_dc` | AD DS domain controller VM (`modules/dc-vm`), then `lab/scripts/dc/` promotes it | no trial; Azure compute while running (auto-deallocates 19:00) |
| `enable_intune_vm` | Windows 11 VM (`modules/intune-vm`), Entra joined + Intune enrolled: the CA005 "compliant device". The CA005 pilot group (and any `intune_vm_admin_login_object_ids`) get *Virtual Machine Administrator Login* | no trial of its own; Azure compute while running (auto-deallocates 19:00). **Needs `enable_premium`** (`intune_vm_requires_premium` check). Before flipping: re-apply `../bootstrap` and do the prerequisites in `lab/scripts/intune/README.md` |
| `enable_sentinel` | Sentinel onboarding + 5 analytics rules from `lab/kql` | **starts the 31-day Sentinel trial**; turn on only after Entra logs have flowed for a few hours |
| `enable_la_alerts` | the same 5 queries as Log Analytics alerts | post-trial path; cents per rule. Mutually exclusive with `enable_sentinel`: `modules/monitoring` refuses a plan with both on. Flip both in one change when the trial ends |
| `enable_itdr_detections` | 11 ITDR rules on whichever detection path is on + `VaultCheckout_CL` table/DCE/DCR; with `enable_dc`, AMA + Security-event DCR on DC01 | **no trial**; ingestion cost. Turn on before `enable_sentinel` so the AuditLogs tables and `VaultCheckout_CL` have data. `itdr_exclude_rules` holds back rules whose table is still empty - including the four SecurityEvent rules until Sentinel + its AMA connector are on (verify: Microsoft Learn says DC01 events reach SecurityEvent only then). Set `iac_principal_ids` (TF_IAC_PRINCIPAL_IDS) or every CI change alerts as non-IaC |
| `enable_itdr_containment` | Sentinel automation rule running the containment playbook on High ITDR incidents | needs `enable_sentinel` + `enable_itdr_detections` (plan fails otherwise) and `containment_playbook_id` from `Deploy-ContainmentPlaybook.ps1` |
| `enable_evidence_store` | WORM storage account for evidence (Unlocked; `evidence_immutability_state = "Locked"` needs `evidence_immutability_lock_acknowledged`) | Azure storage cost only; apply before Day 0 of the trial window |
| `enable_agent_identity` | `uami-agent-runtime` (no role assignments) for `post-apply/New-AgentIdentity.ps1` | none (the Agent ID API is preview; verify licence) |

Premium-tier extensions (need `enable_premium`; each has a `check` that warns
when its prerequisite is off):

| Flag | Adds | Licence / note |
|---|---|---|
| `enable_identity_protection_ca` | CA006 (user risk High → MFA + secure password change), CA007 (sign-in risk High → block), report-only; `ca_policy_states` must then hold CA006/CA007 | **Entra ID P2**; set Microsoft's managed risk policy to report-only/off first |
| `enable_phishing_resistant_all_users` | CA008 (workforce phishing-resistant strength, report-only, `ca008_scope` all_users → pilot), CA008-Pilot-PhishingResistant, dynamic All-Workforce | P1; all-users enforcement also needs `ca008_allow_all_users_enforcement` |
| `enable_pim_tiers` | PIM-Tier0-Security-Admins, PIM-Tier0-CA-Admins (approval, 4h), PIM-Tier1-Intune-Admins, PIM-Tier1-Helpdesk (8h) | P2 |
| `enable_pim_azure_resources` | PIM-Azure-RG-Contributors eligible for Contributor on the RG | P2; **human** applier with Owner/UAA |
| `enable_sso_apps` | AWS IAM Identity Center SAML app + Contoso Clinical Portal OIDC app | P1 (group assignment); bootstrap `enable_app_management_roles` first |
| `enable_scim_provisioning` / `aws_scim_job_enabled` | AWS provisioning job (created stopped) / start it | needs `enable_sso_apps`; first apply is a local seeding run with the token from Key Vault |
| `enable_pam_oidc_app` | guacamole-psm + PAM-Operators | needs `enable_sso_apps` |
| `enable_okta_federation` | okta-clinic-idp: Entra as the OIDC identity provider for the acquired clinic's Okta org, one assignment (App-Okta-Federation-Users); the secret is a human's post-apply step; the Okta side is the human-applied root `../../okta` | needs `enable_sso_apps` and `okta_org_domain` (terraform.tfvars); ADR 0022 |
| `clinical_portal_preauthorize_azure_cli` | Azure CLI pre-authorized on the Clinical Portal's `Clinical.Read` scope (evidence E25 token demo only; off again after) | needs `enable_sso_apps` |
| `enable_nhi_governance` | App-Consent-Reviewers (consent policy itself is post-apply) | none for the group |

Governance-tier extension: `enable_b2b_governance` (Affiliated Partners
catalog + Affiliated Physicians guest package; needs `enable_governance`).
`enable_access_reviews` also renders the privileged + inactive-user review
bodies for `post-apply/New-AccessReviewDefinitions.ps1`.

---

## Prerequisites

- Terraform `>= 1.9` (cross-variable validation in `modules/monitoring`); CI pins 1.16.5.
- `../bootstrap` applied and admin consent granted (for CI runs).
- Azure resource providers registered once (`az provider register`). The
  provider runs with `resource_provider_registrations = "none"` because the
  Reader-only PLAN identity can't register them.
- A **versioned** Azure Storage Account for remote state (see
  `backend.tf` and the bootstrap snippet in `../../README.md`).

---

## Usage

```bash
# 1. Validate / format WITHOUT any backend or Azure access:
terraform init -backend=false
terraform validate
terraform fmt -recursive

# 2. For a real (local) deployment, point init at your versioned state storage:
terraform init \
  -backend-config="resource_group_name=rg-identity-lab-tfstate" \
  -backend-config="storage_account_name=<your-unique-sa>"

cp terraform.tfvars.example terraform.tfvars   # then edit
terraform plan  -var-file=lab.tfvars
terraform apply -var-file=lab.tfvars
```

---

## Apply order

Terraform derives the graph automatically from the module references in
`main.tf`. This is the logical order it resolves:

| Step | Component | Flag | Why it is here |
|------|-----------|------|----------------|
| 1 | `azurerm_resource_group` + `azurerm_log_analytics_workspace` | — | Shared Azure scaffold the vault plugs into. |
| 2 | `module.keyvault` | — | Needs the RG + Log Analytics workspace id. |
| 3 | `module.groups` | premium | Break-glass (+ Global Admin) and groups; the other modules reference their ids. |
| 4 | `module.conditional_access` | premium | Needs the **break-glass group object id** to exclude it on every policy. |
| 5 | `module.pim` | premium | Needs the **Privileged-IAM-Admins** group object id. |
| 6 | `module.entitlement` | governance (+ access_reviews) | Needs the **assigned** app-access group ids (dynamic groups can't be package resources). |
| 7 | `module.dc_vm` | dc | Joins the vault's VNet (`snet-identity`) so it reaches Key Vault privately. |
| 8 | `module.monitoring` | sentinel / la_alerts | Needs Log Analytics. Entra diagnostics are in `../bootstrap` (human-owned). |
| 9 | `module.intune_vm` | intune_vm | Joins the vault's VNet (own `snet-endpoints` subnet); the CA005 pilot group gets VM login when premium is on. |
| 10 | `module.apps` | premium + sso_apps | Needs App-AWS-IdentityCenter-Users (the one assignment = the SCIM scope), All-Nurses and the dispensing group (portal roles). |
| 11 | `module.evidence_store` | evidence_store | Needs the RG + Log Analytics (blob logs). `providers.tf` sets `features.storage.data_plane_available = false` because Shared Key is off. |
| 12 | `azurerm_user_assigned_identity.agent_runtime` | agent_identity | Needs the RG; no role assignments. |

A single `terraform apply` handles all of it. The table is for understanding,
not for running in pieces.

**One exception: the PIM step-up on auth context `c1` takes three separate
changes.** Learn (PIM for Groups role settings): when the context's CA
policy is report-only or off there is no step-up and no MFA backup, so PIM
must not require `c1` before the enforced CA021 is in the tenant.

1. `ca_policy_states` CA021 = `"enabled"` (with `enable_pim_auth_context`),
   apply, then run `post-apply/Set-AuthContextPolicies.ps1`.
2. A later change: `ca021_enforced_in_tenant = true`, only once the script
   has reported CA021 enabled in the tenant.
3. The PIM switch, in two applies for existing Tier-0 policies:
   `pim_tier0_auth_context_switchover_step1 = true`, then
   `pim_tier0_activation_auth_context_id = "c1"`.

`variables.tf` refuses `c1` (and step 1) until all three hold, and
`tests/mock_plan.tftest.hcl` pins that ordering.

Post-apply (Graph, see `lab/scripts/powershell`): `01-Verify-Baseline.ps1`,
`post-apply/New-AdminAccounts.ps1`, `post-apply/Set-IncompatibleAccessPackages.ps1`
(`Set-AccessPackageSoD.ps1` is now a forwarding shim to it), and once HR has
provisioned the approvers and admins, `post-apply/Set-PimGroupEligibility.ps1`
(on the `adm-` accounts) and `post-apply/New-LifecycleWorkflows.ps1`. With the Intune VM:
`lab/scripts/intune/New-IntuneComplianceBaseline.ps1`. Everything post-apply
for the flags that are on, in dependency order with the break-glass check as a
gate: `post-apply/Invoke-PostApply.ps1 -OutputsPath <terraform output -json>`
(dry run unless `-Execute`).

---

## Licensing tier per piece (P1 / P2 / Governance)

What each module needs **at apply/runtime**. Free-tier objects still *work*
under paid SKUs. The tier is the *minimum* for the feature to function.

| Module | Minimum license | What triggers it |
|--------|-----------------|------------------|
| `groups` | **Entra ID P1** | Dynamic membership (All-Nurses, All-ICU) and role-assignable groups both require P1. |
| `keyvault` | **None (Azure only)** | Pure Azure RBAC + networking; standard Azure resource cost for PE/DNS. |
| `conditional-access` | **Entra ID P1**; **P2** for CA006/CA007 | CA itself is P1 per in-scope user. Custom authentication strength is P1. CA006/CA007 (`enable_identity_protection_ca`) use user / sign-in **risk** conditions, which need **P2** for every in-scope user. CA005's *compliant device* grant also needs **Intune** (in M365 E5) to mark the device compliant. |
| `pim` | **Entra ID P2** | PIM for Groups (eligible membership + activation policy) and PIM for Azure resources are P2 features. |
| `apps` | **Free** / **P1** | App registrations and gallery SAML are free; assigning a *group* to an enterprise app is P1; outbound SCIM P1 (verify). |
| `evidence-store` | **None (Azure only)** | Storage + diagnostic logs cost. |
| `entitlement` | **Entra ID Governance** (formerly P2 / EMS E5) | Entitlement Management (catalog, access packages, assignment policies, and the optional `enable_access_reviews` reviews). Highest tier in the lab; each **assigned** user consumes a Governance license. |
| `intune-vm` | **None for the VM** (Azure compute); **Entra ID P1 + Intune** (M365 E5) for auto-enrollment | `license_type = "Windows_Client"` relies on M365 E3/E5 multitenant hosting rights; on the E5 *trial* treat the VM as dev/test only (*verify* with your licensing contact). |

See `../../README.md` for the full per-**resource** license table and the
list of steps Terraform cannot perform (admin consent, PIM eligibility for
named people, SoD incompatible-package marking, etc.).

---

## Key outputs

`terraform output` surfaces the IDs other deliverables line up against: the
break-glass group and UPNs, the CA policy ids and display names (CA001..CA008;
flagged ones `null` while off), the CA008 pilot group, the PIM tier groups and
activation rules, the review / B2B bodies for the post-apply scripts, the
ITDR rule keys and vault-ingestion target, the SSO app ids and AWS commands,
the agent runtime UAMI, the evidence-store container and writer condition, the access
package ids and SoD pairs, the access-review settings (`null` unless
`enable_access_reviews`), the PIM policy id, the Key Vault URI and the UAMI
client id, the DC's name/IPs (+ sensitive initial admin password), the CA005
pilot group id, the Intune VM's name, hostname, public IP (sensitive), Entra
`.rdp` file and local admin password (sensitive), and the Sentinel rule ids.
Premium/governance outputs are `null` until their flag is on. The GitHub OIDC
client ids are outputs of `../bootstrap`.
