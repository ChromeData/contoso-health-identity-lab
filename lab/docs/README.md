# Design docs: start here

The module and pipeline READMEs say *how*. These documents say *why*, *what
next* and *who owns it*, for Contoso Health, a fictional 5,000-user hospital
whose clinicians must never be locked out of patient care by an identity
control. Nothing in the Entra core has run in a tenant yet: every document
uses the same four status words (RAN · tenant, none yet; RAN · harness;
BUILT; DESIGNED), and the hashed run records behind every "RAN · harness"
are indexed in [`../evidence/README.md`](../evidence/README.md).

## About 20 minutes: the reading order

| # | Read | Min | What it shows |
|---|---|--:|---|
| 1 | The repository [README](../../README.md): the opening and "What has run" | 4 | The decisions I'd defend, the honesty rule, what has run, the business constraint |
| 2 | [CISO brief](ciso-brief.md) | 3 | The ask, the top risks, two quarters, six decisions needed |
| 3 | [Target state](target-state.md): principles and the control-plane table | 1.5 | Target, today and gap per Enterprise Access Model layer |
| 4 | [ADR index](adr/README.md): the index table | 1.5 | All 18 decisions, one line each; pick what to probe |
| 5 | [ADR 0012](adr/0012-access-review-no-response-and-clinical-lockout.md): Context, Decision | 2.5 | The healthcare call: an ignored review never locks a nurse out |
| 6 | [Graduating a CA policy](runbooks/graduate-a-ca-policy.md) §1, §2 and §4 | 1 | Conditional Access as change control: report-only, evidence, one graduation per PR |
| 7 | [ADR 0002](adr/0002-pim-for-groups-vs-direct-role-eligibility.md): Options, Decision | 3.5 | PIM design: tiers, approver groups, expiry, the step-up fallback trap |
| 8 | [Threat model](threat-model.md): the incidents table | 4 | Five named incidents (Midnight Blizzard, Snowflake, Change Healthcare, MGM Resorts, Storm-2372) mapped to control, detection and residual gap |

Minutes assume a skim at about 230 words a minute over the sections named:
about 4,900 words in all (counted 2026-10-21).

**PAM track:** swap #3 and #5 for
[ADR 0007](adr/0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) (the
CyberArk vocabulary table) and
[ADR 0019](adr/0019-pam-vault-high-availability-and-dr.md) (vault HA and DR,
with three hashed, timed restore drills).

**IGA and operations track:** swap #6 and #7 for
[vendor evaluation](vendor-evaluation.md) §4 and §6 (the IGA matrix and when
Contoso buys SailPoint or Saviynt) and the
[help-desk verification ladder](runbooks/help-desk-identity-verification.md).

## Status by capability

What each capability does, how far it has run, the decisions behind it and
where the code is. The measured results and what each record does **not**
prove are in the [evidence index](../evidence/README.md).

| Capability | Status | What it does | Decisions | Where |
|---|---|---|---|---|
| **Joiner / mover / leaver** | BUILT: HR inbound provisioning to AD, the lifecycle scripts. DESIGNED: Cloud Sync (ADR 0001) | HR feed → API-driven inbound provisioning **to on-prem AD** → Cloud Sync → Entra, with a mass-change guard. Birthright access from HR attributes (automatic assignment policies), Lifecycle Workflows (joiner, leaver, opt-in mover), requestable access packages with 180-day expiry. The leaver revokes sessions, removes access and hands over the workload identities the person owned; SaaS accounts are disabled by SCIM on the next provisioning cycle (or on demand). | ADR 0001, 0006 | [`lab/scripts`](../scripts), [`lab/iga`](../iga/README.md), [`modules/entitlement`](../terraform/modules/entitlement) |
| **Hybrid AD (DC01)** | BUILT | Domain controller VM (NSG limited to the operator, auto-shutdown) and its promotion scripts, including the Vault rotation account's delegated rights | ADR 0013 | [`modules/dc-vm`](../terraform/modules/dc-vm), [`lab/scripts/dc`](../scripts/dc) |
| **SSO + provisioning** | BUILT: AWS IAM Identity Center SAML + SCIM (created stopped), ServiceNow SAML (flag off), Clinical Portal OIDC, PAM broker sign-in. DESIGNED: ServiceNow provisioning, Okta coexistence | Apps as Terraform with one group assignment each; the AWS permission set is a separate root for a human to apply. Moving existing apps off AD FS or Okta is a per-app runbook (ADR 0009 and the Okta runbook, both DESIGNED). | — | [`modules/apps`](../terraform/modules/apps), [`lab/terraform/aws`](../terraform/aws), [`okta-migration-runbook.md`](okta-migration-runbook.md) |
| **Conditional Access as code** | BUILT | Every policy starts report-only and is designed to be graduated one per PR. Terraform creates 13: CA001–CA005 baseline, CA006/CA007 risk-based (High only), CA008 phishing-resistant workforce, CA009 security-info registration, CA010 device-code block, CA020 admin sign-in frequency, CA022 PAM broker + admin portals, CA060 shared clinical workstations. Three more are Graph scripts because the provider cannot express them: CA021, the PIM step-up on authentication context `c1`, and CA023, a step-up on context `c2` for protected actions (changing CA policies or named locations), both rendered by Terraform and written by script; and CA011, a Token Protection pilot. Passkey profiles, TAP and SMS/voice retirement are a desired-state script. Break-glass is excluded from every policy, and a test checks it. | ADR 0003, 0014, 0015, 0016 | [`modules/conditional-access`](../terraform/modules/conditional-access), [`passwordless-rollout-plan.md`](passwordless-rollout-plan.md) |
| **Zero standing admin (PIM)** | BUILT | PIM for Groups in tiers: 8 Tier-0 groups (approval by an approver group, 4 h, eligibility expires in 180 days; a step-up on authentication context `c1` once CA021 is enforced) and 8 Tier-1 groups (8 h, 365 days; Intune and IGA administration also need approval); Global Administrator eligible per named person (2 h); help desk scoped to an administrative unit; PIM for Azure resources; quarterly default-deny reviews of eligible members. Admin work uses separate cloud-only `adm-` accounts with no license or mailbox, created from a reviewed register. Designed so break-glass is the only standing Global Administrator: the build account keeps its standing role until the last, opt-in post-apply step converts it to eligible. | ADR 0002 | [`modules/pim`](../terraform/modules/pim/README.md) |
| **IGA** | BUILT (Entra). RAN · harness: the midPoint review ([`midpoint/20261020T162116Z`](../evidence/midpoint/20261020T162116Z/)); its test suite passed 91/91 in [`offline-tests/20261021T074732Z`](../evidence/offline-tests/20261021T074732Z/README.md) | Risk-tiered certification (birthright clinical access is never removed because a reviewer stayed silent), nine SoD rules (preventive links + a detective report), review KPIs, B2B guests with sponsors and expiry. midPoint, the SailPoint stand-in, runs a certification campaign end to end: reviewer routing, decisions (recorded by a script as the assigned reviewer), a deliberate no-response, automated remediation, hashed evidence. | ADR 0008, 0012 | [`lab/iga`](../iga/README.md), [`modules/entitlement`](../terraform/modules/entitlement), [`lab/pam/midpoint`](../pam/midpoint) |
| **Non-human identity governance** | BUILT | NHI inventory against OWASP's NHI Top 10, shadow-admin path finder, app management and consent policies, a leaver hand-off that never gives a Tier-0 app to a manager, and an Entra Agent ID with a human sponsor (identity only: no permission, nothing calls it yet) | ADR 0018 | [`lab/scripts/powershell`](../scripts/powershell/README.md) |
| **Identity threat detection and response** | BUILT. RAN · harness: the 22 KQL rules on the Kusto emulator (223 cases); the Vault audit feed, 63 checks | 22 KQL detections, deployable by Terraform behind flags, each with an SPL twin shipped as a Splunk app (never run on Splunk): 5 core, 11 ITDR (credentials and consent on workload identities, CA tampering, roles and privileged groups changed outside PIM, admin MFA changes, identity risk, and the AD plane: Tier-0 logons PAM cannot account for, privileged AD group changes, Kerberoasting, DCSync) and 6 more (device-code phishing, risky MFA registration, DC logon outside the operator allow-list, PAM vault misuse, SoD pair completed, PIM activation without step-up). The CI identity is recognized by immutable id only. Containment asks a named approver in Teams first. The harness drives real Vault audit events into the detection's table shape. | ADR 0017 | [`lab/kql`](../kql), [`modules/monitoring`](../terraform/modules/monitoring), [`lab/monitoring`](../monitoring), [`lab/splunk`](../splunk) |
| **PAM** | RAN · harness: Samba AD DC, 284/284; 500-account run, 79/79; dynamic database credentials, 60/60 | Vault discovers, onboards (dependency-gated), rotates and reconciles accounts in an AD-compatible directory (a Samba AD DC in the harness; DC01, Windows Server, at tenant time); exclusive, ticket-gated check-out for one named person, with two distinct approvers for Tier 0, neither the requester (dual control); Guacamole records SSH sessions (with an SSH CA) and RDP sessions with injected credentials, the RDP target in the harness being a Linux xrdp stand-in for the domain controller; a separate 3-node rehearsal cluster with a timed DR drill (test data, not the credential vault; restoring rotated credentials is not drilled); 1-hour database logins nobody holds standing. Tenant-time pieces are BUILT, not run: a Windows RDP session on DC01, the Windows dependency scan on DC01 and member servers, Entra sign-in to the broker, ServiceNow change validation against a real instance. | ADR 0007, 0019 | [`lab/pam`](../pam/README.md) |
| **Workload identity on Kubernetes** | RAN · harness: kind cluster, 64/64. AKS mapping: BUILT. NetworkPolicy: BUILT | A pod gets its database password with no Kubernetes Secret, env var or manifest value; an admission policy binds the identity to one image digest. The Entra Workload ID equivalent is tested offline and never applied. The NetworkPolicy was added after the hashed run. The GitHub job failed both of its runs at the Checkov stage, before that fix, and has not re-run ([evidence index](../evidence/README.md#runs-on-githubs-runners)). | ADR 0011 | [`lab/k8s`](../k8s/README.md), [`lab/terraform/k8s`](../terraform/k8s) |
| **Pipeline with no stored credentials** | BUILT. Its credential-free tests passed on GitHub's runners; plan and apply have never run against a tenant (none exists) | GitHub OIDC with two identities: read-only on PRs, write only behind a reviewer-gated environment. No PR can change the pipeline's own identities; a human applies those (the apply identity is still Tier 0, a recorded risk acceptance). TruffleHog, plan, Checkov (a failed check blocks the merge) and an AI review on PRs; offline test suites, and a nightly PAM harness run from a fresh clone, with no credential; actions SHA-pinned. | ADR 0004, 0005 | [`.github/workflows`](../../.github/workflows), [`lab/pipelines`](../pipelines/README.md) |
| **Measurement and audit evidence** | BUILT | Scripts to measure KPIs before and after (standing admins, phishing-resistant coverage, HR-to-disable minutes, NHI findings), CISA ScubaGear and Microsoft's Zero Trust Assessment before / after, break-glass and CA-restore drill scripts, and one command that exports a SHA-256-manifested evidence pack mapped to HIPAA / SOX controls into WORM storage | — | [`lab/scripts/powershell`](../scripts/powershell/README.md), [`modules/evidence-store`](../terraform/modules/evidence-store), [`lab/evidence`](../evidence/README.md) |
| **Out of scope, on purpose** | DESIGNED | Global Secure Access, Verified ID and CIEM: why not now, and what would change that | ADR 0011 | [`adr/`](adr/README.md) |

No row is RAN · tenant. Tenant KPI values, Entra review outcomes and
break-glass drill times will be added only from the tenant run; until then
the documents use placeholders such as `<measured: HR-to-disable minutes>`.

## Build order (the short version)

1. **Bootstrap** (human, local): state storage, then `lab/terraform/envs/bootstrap`
   (OIDC identities, their RBAC, Entra diagnostics), then admin consent.
2. **Pipeline:** `lab/terraform/envs/dev` through PRs. Staging flags in
   [`lab.tfvars`](../terraform/envs/dev/lab.tfvars) keep the free tier, the
   premium tier, the DC and Sentinel apart, so no trial clock starts early.
3. **Post-apply:** `lab/scripts/powershell/post-apply/Invoke-PostApply.ps1`
   runs the tenant settings Terraform cannot express, in dependency order,
   dry-run by default, with the break-glass check as a gate.
4. **DC01:** [`lab/scripts/dc`](../scripts/dc). **PAM:** [`lab/pam`](../pam/README.md).

Details: [apply order](../terraform/README.md#apply-order-whole-lab) in
`lab/terraform/README.md`, [`lab/scripts/powershell/README.md`](../scripts/powershell/README.md)
and [`lab/pipelines/README.md`](../pipelines/README.md).

## Everything else

| Area | Documents |
|---|---|
| The map | [architecture.md](architecture.md), [STAND-INS.md](STAND-INS.md) (every stand-in and what it replaces) |
| Decisions | [adr/](adr/README.md): 18 decisions; 0010 and 0020 are pointers to the records they merged into |
| Plans | [roadmap.md](roadmap.md), [passwordless-rollout-plan.md](passwordless-rollout-plan.md), [okta-migration-runbook.md](okta-migration-runbook.md), [evidence-capture-plan.md](evidence-capture-plan.md) |
| Risk and assurance | [risk-register.md](risk-register.md), [threat-model.md](threat-model.md), [compliance-crosswalk.md](compliance-crosswalk.md), [vendor-evaluation.md](vendor-evaluation.md) |
| Standards | [IAM](standards/iam-standard.md), [privileged access](standards/privileged-access-standard.md), [non-human identity](standards/nhi-standard.md), [CA design principles](standards/conditional-access-design-principles.md) (the CA policy list), [app onboarding intake](standards/app-onboarding-intake.md), [exception process](standards/exception-process.md), [RACI](standards/raci.md) |
| Runbooks | [compromised identity](runbooks/compromised-identity.md), [help-desk verification](runbooks/help-desk-identity-verification.md), [break-glass drill](runbooks/break-glass-drill.md) (not yet run), [graduating a CA policy](runbooks/graduate-a-ca-policy.md) (with the review checklist), [PIM activation support](runbooks/pim-activation-support.md), [JML exceptions](runbooks/jml-exception.md), [new-engineer onboarding](runbooks/new-engineer-onboarding.md) |

**Who owns what in the scenario:** HR owns the source of truth for every
workforce identity, IAM owns the platform and its policies, the SOC owns
detection and response, and audit consumes the evidence pack. The RACI is in
[`standards/raci.md`](standards/raci.md).

**One home per fact.** The CA policy list lives in the CA design
principles; PIM settings in ADR 0002; licensing in the vendor evaluation
§8; the IGA buy triggers in its §6; the TAP registration wave in ADR 0016;
containment mechanics in ADR 0017; stand-in status in STAND-INS. Other
documents point there instead of repeating it.

A narrated walkthrough will be recorded after the tenant run.
