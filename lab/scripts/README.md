# Contoso Health — IAM/PAM lab scripts

Deploy-ready PowerShell + mock-HR scripts that drive the joiner/mover/leaver
lifecycle, baseline verification, hygiene reporting, and the auditor evidence pack for
the Contoso Health (`contosohealth.io`) Entra ID identity platform.

> These scripts are written to be **correct and deploy-ready but are not run
> here** (no tenant). Each is idempotent, heavily commented, validates its
> parameters, and has clear PLACEHOLDER variables at the top. Review with
> `-WhatIf` first on any real tenant.

## Shared scenario contract

| Thing | Value |
|---|---|
| Org / domain | Contoso Health / `contosohealth.io` placeholder (pass your real domain as `-UpnDomain`) + `<tenant>.onmicrosoft.com` for break-glass |
| Protagonist | Dana Okafor — `dana.okafor@<domain>`, dept **Nursing**, title **Registered Nurse** |
| Birthright groups (dynamic) | **All-Nurses**, **All-ICU** |
| Access packages | **Nurse - Clinical Apps**, **ICU - Critical Care Apps** (mover), **Pharmacy - Controlled Substances Apps** (SoD pair) |
| Break-glass | `bg-admin-01`, `bg-admin-02` in **Break-Glass-Admins** (standing Global Admin, CA-excluded) |
| PIM | **Privileged-IAM-Admins** → User Administrator; eligible member: Grace Mwangi |
| Apps | ServiceNow, AWS IAM Identity Center, Okta (groups `App-*`) |

### Who owns what (single owner per object)

| Owner | Objects |
|---|---|
| Terraform (`lab/terraform/envs/dev`) | break-glass accounts + group, every group, CA (CA001-CA008), PIM policies + tier groups, access packages (+ B2B), SSO apps, evidence store |
| HR feed (`mock-hr/`) → AD → Cloud Sync | every workforce user and their department / title / manager / enabled state |
| These scripts | verification, day-1/mover/leaver *cloud-side* follow-through, post-apply Graph gaps (SoD, PIM eligibility, Lifecycle Workflows, access-review definitions, B2B connected org, authentication-methods / app-management / consent policies, Agent ID, Intune compliance), reports, KPIs, drills, evidence |

Because workers are synced from AD, Entra **rejects** cloud writes to their
department or `accountEnabled`. Mover and leaver therefore start with an edit
to `hr_feed.csv`; the scripts wait for the synced value and do the rest.

## Run order

```
# 0. Connect once with the union of scopes (see "Consent" below). A script
#    calls Connect-MgGraph with its own scopes only when there is no session;
#    otherwise it reuses that session and warns about any scope it lacks
#    (e.g. after Invoke-InboundProvisioning connected with its one scope).
#    Run Disconnect-MgGraph to let the next script connect with its own.

# 1. After `terraform apply` (enable_premium): prove the baseline is safe
#    (groups, break-glass + GA, break-glass excluded from EVERY CA policy;
#    7 checks, [7/7] = admin passkey coverage).
./powershell/01-Verify-Baseline.ps1 -OnMicrosoftDomain '<tenant>.onmicrosoft.com'
#    Separate cloud-only admin accounts (Invoke-PostApply step 1b): one adm-
#    account per IT persona in lab/iga/admin-accounts.json, plus the
#    sponsored read-only presenter (adm-presenter) -> Admin-Accounts
#    (standing, role-assignable, no role: the admin passkey target). The
#    authentication methods policy adds the build account to that target.
./powershell/post-apply/New-AdminAccounts.ps1 -WhatIf
./powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1 -BuildAccountUpn '<build account UPN>'   # PLAN
#    (enable_governance) preventive SoD from lab/iga/sod-rules.json, then the
#    joiner + leaver Lifecycle Workflows, created by name. -OfflinePreview
#    prints the JSON with no tenant at all.
./powershell/post-apply/Set-IncompatibleAccessPackages.ps1 -WhatIf -Prune
./powershell/post-apply/New-LifecycleWorkflows.ps1 -WhatIf
./powershell/post-apply/New-LifecycleWorkflows.ps1

# 1b. OR run every post-apply step in dependency order for the flags that are
#     ON, with step 1 as a gate (see "Post-apply orchestration" below):
terraform -chdir=../terraform/envs/dev output -json > /tmp/tf-out.json
./powershell/post-apply/Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json -ListOnly   # the plan, no tenant
./powershell/post-apply/Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json             # dry run (-WhatIf / PLAN)
./powershell/post-apply/Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json -Execute `
    -PimEligibility @{ 'privileged-iam-admins' = @('adm-first.last@<tenant>.onmicrosoft.com') }

# 2. HR brings people in via API-driven inbound provisioning (managers first).
./mock-hr/Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain> -StatusFilter active
./mock-hr/Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <domain> -StatusFilter joiner
./powershell/post-apply/Set-PimGroupEligibility.ps1 -UserPrincipalNames 'adm-first.last@<tenant>.onmicrosoft.com'
#    (eligibility goes on adm- accounts only; there is no default person, and
#    a non-adm- account gets a warning)

# 3. Day-1 access for the joiner (license + birthright check + access package).
#    The birthright package (T3) is delivered by its automatic assignment
#    policy from HR attributes: 02-Joiner VERIFIES it reached Delivered and
#    never adminAdds it; adminAdd is only for a requestable (T2) package.
#    Exits 1 with a 'Joiner INCOMPLETE' summary when the governed access-package
#    path can't be delivered (package or policy missing, or a Graph lookup
#    error): re-run (idempotent) or use -UseAccessPackage:$false.
./powershell/02-Joiner.ps1 -UserPrincipalName 'dana.okafor@<domain>' -LicenseSkuPartNumber '<sku from Get-MgSubscribedSku>'
#    With Governance (what the recording shows) the joiner workflow does the TAP
#    to the manager. Run it now instead of waiting for the hire-date trigger.
#    Scheduling is off by default: mock-hr now sends startDate as hireDate
#    (custom SCIM extension), but the two mappings into employeeHireDate
#    (provisioning, then Cloud Sync) are tenant-time steps (verify:).
./powershell/post-apply/New-LifecycleWorkflows.ps1 -RunJoinerFor 'dana.okafor@<domain>'

# 4. Mover: edit Marcus's row in hr_feed.csv to ICU, re-run step 2 (-StatusFilter active), then:
#    the automatic policies do the swap (the old birthright package goes after
#    the 72 h grace period); 03-Mover.ps1 verifies that and is the fallback
#    (adminRemove / adminAdd) for requestable T2 packages only. The HR
#    mass-change guard also counts department / job-title changes against
#    -StatePath (mock-hr/.state/, gitignored).
./powershell/03-Mover.ps1 -UserPrincipalName 'marcus.bello@<domain>' -NewDepartment 'ICU'

# 5. Leaver: set Dana's row to status=leaver, run inbound provisioning -StatusFilter leaver, then:
./powershell/04-Leaver.ps1 -UserPrincipalName 'dana.okafor@<domain>' -ProvisionOnDemandApps 'ServiceNow','AWS IAM Identity Center'
#    Optional Governance path (after the HR disable has synced): the leaver workflow.
./powershell/post-apply/New-LifecycleWorkflows.ps1 -RunLeaverFor 'dana.okafor@<domain>'

# 6. Hygiene reports (stale / no-MFA / standing privileged / guests).
./powershell/05-Reports.ps1 -StaleDays 90

# 7. Auditor evidence pack -> lab/evidence/out/ with SHA256 manifest + SUMMARY
#    (also hashes the companion evidence below into the same manifest).
./powershell/Export-EvidencePack.ps1
```

### Senior-scope run order (trial window - lab/docs/evidence-capture-plan.md)

```
# A. Baselines BEFORE premium configuration (assessment host = Windows x64).
./powershell/Invoke-BaselineAssessment.ps1 -Phase before -StorageAccountName <evidence store>
./powershell/08-Measure-KPIs.ps1 -Label baseline
./powershell/06-NHI-Inventory.ps1          # + Find-ShadowAdmins.ps1: NHI / shadow-admin baseline
./powershell/Find-ShadowAdmins.ps1

# B. Tenant policy the provider cannot express (each one also inside
#    Invoke-PostApply.ps1): authentication methods (passkey profiles, TAP,
#    campaign), then - after the SSO apps exist - app management + consent.
./powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1               # PLAN
./powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1 -Apply -WhatIf
./powershell/post-apply/Set-AppGovernancePolicy.ps1 -WhatIf
./powershell/post-apply/Set-ConsentPolicy.ps1 -WhatIf

# C. Governance: privileged + inactive-user reviews, B2B connected org.
terraform -chdir=../terraform/envs/dev output -json access_review_definitions > reviews.json
./powershell/post-apply/New-AccessReviewDefinitions.ps1 -DefinitionsPath ./reviews.json -WhatIf
terraform -chdir=../terraform/envs/dev output -json b2b_post_apply > b2b.json
./powershell/post-apply/New-B2BConnectedOrganization.ps1 -PostApplyPath ./b2b.json -WhatIf

# D. Passwordless rollout: pilot status + TAP, then promote ready users to CA008's pilot.
./powershell/07-Passwordless-Rollout.ps1 -Stage Pilot
./powershell/07-Passwordless-Rollout.ps1 -Stage Pilot -PromoteReadyToPilot -WhatIf

# E. Agent ID (preview API; needs enable_agent_identity's UAMI).
#    IDENTITY-ONLY: the agent identity holds NO permission and no runtime
#    calls it yet; the AI pull-request reviewer still runs under the PLAN
#    identity. Say exactly that on camera - never "an AI agent reviews access".
./powershell/post-apply/New-AgentIdentity.ps1 -OfflinePreview

# E1. IGA programme pack (lab/iga, ADR 0012); Invoke-PostApply runs the first
#     two as steps 5 and 6. Order: birthright auto-assignment, then preventive
#     SoD (-Prune removes the old Nurse -> Pharmacy link, which would gate the
#     birthright package), then the detective report; review KPIs after the
#     first review cycle. Set-AccessPackageSoD.ps1 is a forwarding shim to
#     Set-IncompatibleAccessPackages.ps1.
./powershell/post-apply/Set-AutoAssignmentPolicies.ps1 -RenderOnly          # no tenant
./powershell/post-apply/Set-AutoAssignmentPolicies.ps1 -WhatIf
./powershell/post-apply/Set-IncompatibleAccessPackages.ps1 -WhatIf -Prune
./powershell/09-SoD-Report.ps1                                              # exit code = open violations
./powershell/10-Review-KPIs.ps1                                             # completion, revocation, rubber-stamp rate

# E2. Opt-in extras, each read-only / plan by default:
./powershell/post-apply/New-LifecycleWorkflows.ps1 -OfflinePreview -IncludeMover   # mover workflow (department change)
./powershell/post-apply/Set-TokenProtectionPolicy.ps1 -OfflinePreview              # CA011 token protection, report-only pilot
./powershell/Invoke-CaRestoreDrill.ps1 -Mode Snapshot                                # CA restore drill (Snapshot / Compare / Restore -Apply)

# F. Drill + after-state.
./powershell/Invoke-BreakGlassDrill.ps1 -Phase Preflight                 # every <= 90 days
./powershell/08-Measure-KPIs.ps1 -Label after -CompareTo ../evidence/kpis/<baseline>.json
./powershell/Invoke-BaselineAssessment.ps1 -Phase after -StorageAccountName <evidence store>
./powershell/Export-EvidencePack.ps1
```

## Post-apply orchestration

`powershell/post-apply/Invoke-PostApply.ps1` reads `terraform output -json`
once, keeps only the steps whose staging flag is on (a flag that is off
leaves its output null), and runs them in dependency order (steps 1, 1b, 2,
3, 3b and 4 to 20). It is a dry run unless `-Execute`; `-ListOnly` prints
the plan with no tenant call at all. The step table, with the flag each
step needs and why it sits where it does, is in
[`powershell/README.md`](powershell/README.md#post-apply-orchestration-order) and
in the script's own header.

`tests/PostApply.Tests.ps1` pins the order, the dry-run vs execute
parameters, the gate, and - by generating stubs from the REAL scripts' param
blocks - that every parameter `Invoke-PostApply.ps1` passes exists on the
script it calls.


## Other script folders

| Folder | What |
|---|---|
| [`dc/`](dc/) | Promote the Azure VM to `DC01` (AD DS + AD CS), create OUs and the PAM-managed accounts — run through `az vm run-command` |
| [`monitoring/`](monitoring/) | `Deploy-Playbook.ps1` — Sentinel → Teams + ServiceNow playbook, secrets pulled from Key Vault at deploy time. ITDR: `Deploy-ContainmentPlaybook.ps1` (approval-gated revoke + disable), `Invoke-AdContainment.ps1` (AD disable on DC01), `ingest-vault-audit.sh` (vault check-outs → `VaultCheckout_CL`) - see [`monitoring/README.md`](monitoring/README.md) |
| [`intune/`](intune/) | `New-IntuneComplianceBaseline.ps1` — Windows compliance policy (Secure Boot, code integrity, min OS; BitLocker opt-in) assigned to `CA005-Pilot-CompliantDevice`, optional pilot members, device compliance status. Scopes: `DeviceManagementConfiguration.ReadWrite.All`, `Group.Read.All`; `User.Read.All` + `GroupMember.ReadWrite.All` with `-PilotMemberUserPrincipalNames`; `DeviceManagementManagedDevices.Read.All` with `-ShowDeviceCompliance`. The README is the CA005 demo runbook |
| [`demo/`](demo/) | `Reset-DemoState.ps1` — recording re-take tool: puts Dana and Marcus back to the state before the Joiner, Mover or Leaver segment (HR feed → AD, packages, optional license), with `-WhatIf` and a readiness table. `reset-demo-hire.sh` — puts one demo hire from the GitHub Actions HR demo (`hr-feed` branch) back to "not hired" (row removed, AD account deleted; dry run by default). Not part of the identity design |
| [`../pam/`](../pam/) | Vault / Guacamole / Conjur / midPoint stand-ins (Docker, local) |
| [`../splunk/`](../splunk/) | Splunk second SIEM (60-day trial, local Docker) + the Log Analytics replay and every `lab/kql` rule's SPL twin (22) |
| [`../iga/`](../iga/) | IGA programme pack data: access catalog (T1/T2/T3), birthright rules, nine SoD rules, synthetic fixtures for the offline runs |

## Script → video segment map

> Segment numbers follow the walkthrough video's script, which is kept
> outside this repository.

| Script | Powers segment |
|---|---|
| `mock-hr/hr_feed.csv` | §2 Joiner — the mock HR record shown for "Dana Okafor — Nurse" |
| `mock-hr/Invoke-InboundProvisioning.ps1` | §2 Joiner — "Trigger API-driven inbound provisioning" (the Workday/SuccessFactors stand-in) |
| `mock-hr/README.md` | §2 — stand-in mapping + permissions; the spoken line is STAND-INS.md row 1 |
| `powershell/01-Verify-Baseline.ps1` | §4 break-glass excluded from every CA policy + §5 zero-standing-admin premise |
| `powershell/post-apply/Set-PimGroupEligibility.ps1` | §5 PIM — makes the manager *eligible* (not active) |
| `powershell/post-apply/Set-IncompatibleAccessPackages.ps1` | §2 Joiner — the separation-of-duties rule |
| `powershell/post-apply/New-LifecycleWorkflows.ps1` | §2 Joiner — "a Lifecycle Workflow runs the day-1 tasks" (`-RunJoinerFor`); §7 Leaver — the optional Governance path (`-RunLeaverFor`) |
| `powershell/02-Joiner.ps1` | §2 Joiner — day-1 access package + the "runs without Governance" Logic App alternative callout |
| `powershell/03-Mover.ps1` | §2→§7 lifecycle — attribute-driven access re-evaluation (access creep prevention) |
| `powershell/04-Leaver.ps1` | §7 Leaver — disable, revoke sessions, deprovision, timestamps |
| `powershell/05-Reports.ps1` | none — off-camera hygiene reports; §9's measured numbers come from `08-Measure-KPIs.ps1` (E11 baseline, E54 after), not this script |
| `powershell/Export-EvidencePack.ps1` | §9 Evidence — "one-command export, not a week of screenshots" |
| `intune/New-IntuneComplianceBaseline.ps1` | §4 Conditional Access — CA005, "admin portals only from a compliant device" |
| `demo/Reset-DemoState.ps1` | none — off-camera re-take tool for §2 and §7 |
| `powershell/post-apply/Invoke-PostApply.ps1` | none — off-camera orchestration of the post-apply steps |
| `powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`, `powershell/07-Passwordless-Rollout.ps1` | Passwordless rollout (evidence-capture-plan E21, E29) |
| `powershell/post-apply/New-AccessReviewDefinitions.ps1`, `powershell/post-apply/New-B2BConnectedOrganization.ps1` | Governance evidence (E32, E33) |
| `powershell/06-NHI-Inventory.ps1`, `powershell/Find-ShadowAdmins.ps1`, `powershell/post-apply/Set-AppGovernancePolicy.ps1`, `powershell/post-apply/Set-ConsentPolicy.ps1`, `powershell/post-apply/New-AgentIdentity.ps1` | Non-human identity governance (E21, E53) |
| `powershell/post-apply/Set-AutoAssignmentPolicies.ps1`, `powershell/post-apply/Set-IncompatibleAccessPackages.ps1`, `powershell/09-SoD-Report.ps1`, `powershell/10-Review-KPIs.ps1` | Governance evidence (birthright, preventive + detective SoD, review KPIs; `../iga/README.md`); off camera unless the governance segment shows the SoD report |
| `powershell/08-Measure-KPIs.ps1`, `powershell/Invoke-BaselineAssessment.ps1`, `powershell/Invoke-BreakGlassDrill.ps1` | Before/after metrics, CISA ScubaGear + Zero Trust delta, break-glass drill (E10, E11, E54, E55) - real numbers for the §9 slide once captured |

## Prerequisites

### Modules (Microsoft Graph PowerShell SDK)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser   # meta-module (everything), or the sub-modules:
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users,
    Microsoft.Graph.Users.Actions, Microsoft.Graph.Groups,
    Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance,
    Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement,
    Microsoft.Graph.Reports -Scope CurrentUser
```

All scripts require **PowerShell 7+** and `Microsoft.Graph.Authentication`.

### License required per script

| Script | Minimum license |
|---|---|
| `01-Verify-Baseline.ps1` | **Entra ID P1** (reads CA policies) |
| `post-apply/Set-PimGroupEligibility.ps1` | **Entra ID P2** (PIM for Groups) |
| `post-apply/Set-IncompatibleAccessPackages.ps1` | **Entra ID Governance** |
| `post-apply/New-LifecycleWorkflows.ps1` | **Entra ID Governance** (Lifecycle Workflows; every user a workflow processes needs it) |
| `Invoke-InboundProvisioning.ps1` | **Entra ID P1/P2** (API-driven inbound provisioning) |
| `02-Joiner.ps1` (access-package path) | **Entra ID Governance** (access packages + Lifecycle Workflows). The embedded **Logic App alternative** runs on **P1/P2** only. |
| `03-Mover.ps1` | **Entra ID Governance** (access packages) |
| `04-Leaver.ps1` | **Entra ID P1** (core); no Governance needed |
| `05-Reports.ps1` | **Entra ID P1/P2** (signInActivity + registration report) |
| `Export-EvidencePack.ps1` | **Entra ID P2** (PIM + access reviews data); P1 for the MFA report |
| `intune/New-IntuneComplianceBaseline.ps1` | **Intune Plan 1 + Entra ID P1** (both in the M365 E5 trial) |
| `demo/Reset-DemoState.ps1` | **Entra ID Governance** for the access-package part (same as 02/03/04) |
| `post-apply/Set-AuthenticationMethodsPolicy.ps1`, `07-Passwordless-Rollout.ps1` | **Entra ID P1** (authentication methods policy, registration report); Report suspicious activity: P1 (verify) |
| `post-apply/New-AccessReviewDefinitions.ps1` | **Entra ID Governance** (PIM-for-Groups + inactive-user reviews; verify) |
| `post-apply/Set-AutoAssignmentPolicies.ps1`, `post-apply/Set-IncompatibleAccessPackages.ps1`, `09-SoD-Report.ps1`, `10-Review-KPIs.ps1` | **Entra ID Governance** (automatic assignment policies, incompatible packages, review history); creating automatic policies needs the **Identity Governance Administrator** role |
| `post-apply/New-B2BConnectedOrganization.ps1` | **Entra ID Governance**; guests billed by B2B monthly active users (verify) |
| `post-apply/Set-AppGovernancePolicy.ps1`, `post-apply/Set-ConsentPolicy.ps1` | Entra ID Free per the pages checked; older pages mention Workload ID Premium for app management policies (verify) |
| `post-apply/New-AgentIdentity.ps1` | Agent ID (preview); Agent 365 may be required (verify) |
| `post-apply/Set-TokenProtectionPolicy.ps1` | **Entra ID P1** for Conditional Access token protection (verify); Windows 10+ Entra-joined device |
| `Invoke-CaRestoreDrill.ps1` | **Entra ID P1** (Conditional Access read/write). The product path, Entra Backup and Recovery, is preview (verify) |
| `06-NHI-Inventory.ps1`, `Find-ShadowAdmins.ps1` | Entra ID Free for inventory; P1/P2 for `servicePrincipalSignInActivities` (beta report, verify) |
| `08-Measure-KPIs.ps1`, `Invoke-BreakGlassDrill.ps1` | **Entra ID P2** (PIM + risk data) + Log Analytics (sign-in logs) |
| `Invoke-BaselineAssessment.ps1` | Whatever the tenant has: it measures; ScubaGear needs Windows PowerShell 5.1 |

## Consent — the full set of Graph scopes

Grant/admin-consent the union below once, then each script runs without a
re-consent prompt. All reporting/evidence scopes are **read-only**; the write
scopes are only needed by the lifecycle scripts.

**Write (lifecycle: joiner / mover / leaver / post-apply):**
```
User.ReadWrite.All
GroupMember.ReadWrite.All
AppRoleAssignment.ReadWrite.All
EntitlementManagement.ReadWrite.All
PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup
Synchronization.ReadWrite.All
User.RevokeSessions.All
Organization.Read.All
LifecycleWorkflows.ReadWrite.All
```

**Inbound provisioning only (`/bulkUpload`):**
```
SynchronizationData-User.Upload
```

**Read (verification, reports + evidence pack):**
```
User.Read.All
Group.Read.All
Directory.Read.All
Application.Read.All
AuditLog.Read.All
Policy.Read.All
AccessReview.Read.All
RoleManagement.Read.Directory
RoleEligibilitySchedule.Read.Directory
PrivilegedAssignmentSchedule.Read.AzureADGroup
EntitlementManagement.Read.All
```

**Senior-scope additions** (consent only the ones for the flags you turn on):
```
AccessReview.ReadWrite.All                         New-AccessReviewDefinitions
SecurityEvents.Read.All                            08 -IncludeSecureScore (Secure Score history)
PrivilegedEligibilitySchedule.Read.AzureADGroup    New-AccessReviewDefinitions, 08, Find-ShadowAdmins
GroupMember.Read.All                               New-B2BConnectedOrganization, 07, Invoke-BreakGlassDrill
Policy.ReadWrite.AuthenticationMethod              Set-AuthenticationMethodsPolicy
UserAuthenticationMethod.ReadWrite.All             07-Passwordless-Rollout (-IssueTapFor)
UserAuthenticationMethod.Read.All                  Invoke-BreakGlassDrill
Policy.ReadWrite.ApplicationConfiguration          Set-AppGovernancePolicy
Policy.ReadWrite.Authorization                     Set-ConsentPolicy
Policy.ReadWrite.PermissionGrant                   Set-ConsentPolicy
Policy.ReadWrite.ConsentRequest                    Set-ConsentPolicy
Application.ReadWrite.All                          04-Leaver (-NhiHandoff ReassignToManager only)
EntitlementManagement.ReadWrite.All                Set-AutoAssignmentPolicies, Set-IncompatibleAccessPackages (already in the write union)
GroupMember.Read.All, PrivilegedEligibilitySchedule.Read.AzureADGroup   09-SoD-Report (read)
AgentIdentityBlueprint.Create                      New-AgentIdentity (preview)
AgentIdentityBlueprint.ReadWrite.All               New-AgentIdentity (preview)
AgentIdentityBlueprint.AddRemoveCreds.All          New-AgentIdentity (preview)
AgentIdentityBlueprintPrincipal.Create             New-AgentIdentity (preview)
AgentIdentity.Create.All                           New-AgentIdentity (preview; -Remove also needs AgentIdentity.ReadWrite.All)
```
These are write scopes on tenant POLICY (authentication methods, consent,
app management) - consent them for the session that runs the post-apply
step, not as a standing grant.

```powershell
Connect-MgGraph -Scopes `
    'User.ReadWrite.All','GroupMember.ReadWrite.All','AppRoleAssignment.ReadWrite.All',`
    'EntitlementManagement.ReadWrite.All','PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',`
    'Synchronization.ReadWrite.All','User.RevokeSessions.All','Organization.Read.All',`
    'LifecycleWorkflows.ReadWrite.All',`
    'User.Read.All','Group.Read.All','Directory.Read.All','Application.Read.All','AuditLog.Read.All',`
    'Policy.Read.All','AccessReview.Read.All','RoleManagement.Read.Directory',`
    'RoleEligibilitySchedule.Read.Directory','PrivilegedAssignmentSchedule.Read.AzureADGroup',`
    'EntitlementManagement.Read.All'
```

The scripts compare the scopes they need **by name** with the connected
session and warn about any that are missing, so the union also lists read
scopes that a broader scope in it already covers: `Group.Read.All`
(01-Verify-Baseline, 02-Joiner, Set-PimGroupEligibility) and
`EntitlementManagement.Read.All` (`New-LifecycleWorkflows.ps1`).
`PrivilegedAssignmentSchedule.Read.AzureADGroup` is not covered by anything
else: `Export-EvidencePack.ps1` needs it for the PIM-for-Groups activation
history. The Intune script's scopes are listed under *Other script folders*
and are only needed for the CA005 demo.

> `SynchronizationData-User.Upload` is consented separately from the union.
> `Invoke-InboundProvisioning.ps1` connects with it interactively
> (`Connect-MgGraph -Scopes 'SynchronizationData-User.Upload'`). The
> [bulkUpload API reference](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationjob-post-bulkupload?view=graph-rest-1.0)
> lists the delegated (work or school) permission as supported, provided the
> signed-in user is a **User Administrator** (its 403 row says the same). The
> production pattern is the **application** permission
> (`SynchronizationData-User.Upload.OwnedBy`, least privileged) on the app
> registration that calls `/bulkUpload` (see `mock-hr/README.md`), not on the
> provisioning job's own service principal.

## Safety / design notes

- **Idempotent:** every script does get-then-create / state-check-then-act, so
  re-running reconciles rather than duplicates.
- **`-WhatIf` everywhere:** every mutating Graph / Azure script (including
  `monitoring/Deploy-Playbook.ps1`, `intune/` and `demo/`) supports `-WhatIf`
  and prints what it would do — use it as the default dry run while there is
  no tenant. Exception: the `dc/` scripts run on the VM through
  `az vm run-command` and have no `-WhatIf`.
- **No silent failures:** errors are surfaced (warnings/errors), and the
  evidence pack records failed artifacts honestly in the manifest.
- **Break-glass excluded from CA:** Terraform creates the two emergency
  accounts on the `onmicrosoft.com` domain with standing Global Admin via
  `Break-Glass-Admins`, and excludes that group from every CA policy.
  `01-Verify-Baseline.ps1` proves it (exit 1 on any gap) — run it before
  enforcing any policy. `lab/kql/break-glass-signin.kql` alerts on any sign-in.
- **No dual ownership:** scripts never create groups or break-glass accounts
  (an earlier seed script did, which produced a second, CA-unprotected
  break-glass group).
