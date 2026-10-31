# Architecture Decision Records

These are the design decisions behind the Contoso Health identity platform.
Contoso Health is the lab scenario, a fictional 5,000-user hospital. Each
record covers:

- what was decided
- which options were rejected
- what the decision costs
- what would make us change it

The README in each code folder explains *how* (for example
[`lab/terraform/README.md`](../../terraform/README.md),
[`lab/pipelines/README.md`](../../pipelines/README.md),
[`lab/pam/README.md`](../../pam/README.md)). These records explain *why*.
Where the platform is heading is in [`target-state.md`](../target-state.md),
and the [threat model](../threat-model.md) ties the decisions to named
incidents.

## Index

| ADR | Decision | Area |
|---|---|---|
| [0001](0001-cloud-sync-vs-connect-sync.md) | Cloud Sync vs. Entra Connect Sync | Hybrid identity |
| [0002](0002-pim-for-groups-vs-direct-role-eligibility.md) | PIM for Groups vs. direct directory-role eligibility. Partly superseded by 0020 (approvers, eligibility expiry, more roles) | Privileged access |
| [0003](0003-ca-exclusions-and-break-glass.md) | Conditional Access exclusion and break-glass strategy | Access policy |
| [0004](0004-pipeline-workload-identity-federation.md) | Workload identity federation (OIDC) vs. client secrets for the pipeline; PLAN/APPLY split by subject | Delivery / NHI |
| [0005](0005-risk-acceptance-apply-identity-tier0.md) | Risk acceptance: the APPLY identity holds `RoleManagement.ReadWrite.Directory` (Tier 0) | Risk |
| [0006](0006-api-driven-inbound-provisioning-vs-workday-connector.md) | API-driven inbound provisioning vs. the Workday connector | Lifecycle (JML) |
| [0007](0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) | PAM stand-ins (Vault + Guacamole + Conjur) vs. CyberArk. Production unseal partly superseded by 0019 | PAM |
| [0008](0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md) | IGA: Entra ID Governance + midPoint stand-in vs. SailPoint / Saviynt | Governance |
| [0009](0009-adfs-to-entra-id-retirement-path.md) | AD FS → Entra ID retirement path | Federation |
| [0010](0010-kubernetes-workload-identity-scope.md) | Kubernetes workload identity scope (kept small; local kind; AKS mapping plan-only) | Workload identity |
| [0011](0011-out-of-scope-global-secure-access-verified-id-ciem.md) | Out of scope: Global Secure Access, Verified ID, CIEM | Scope |
| [0012](0012-access-review-no-response-and-clinical-lockout.md) | Risk-tiered certification. Unanswered privileged and requestable access is removed; birthright clinical access is never removed on silence | Governance |
| [0013](0013-tier0-domain-controller-exposure.md) | Risk acceptance: DC01's public IP, limited by NSG to the operator, for the lab only. Production uses no public IP and PAM-brokered sessions | Risk / Tier 0 |
| [0014](0014-shared-clinical-workstation-authentication.md) | Shared clinical workstations: a FIDO2 key per clinician, plus a device-filtered CA policy and a session lock | Authentication |
| [0015](0015-risk-based-conditional-access-thresholds.md) | Risk-based CA at High only: user risk → MFA plus secure password change, sign-in risk → block; Medium goes to the SOC; a confirmed compromise gets a block, not CA006 | Access policy |
| [0016](0016-passkey-profiles-and-phone-method-retirement.md) | Two passkey profiles (attested device-bound for admins, synced allowed for staff), protected registration with rollout TAPs handed over in person, SMS and voice retired before Microsoft's date | Authentication |
| [0017](0017-approval-gated-identity-containment.md) | Identity containment runs only after a person approves in Teams. A confirmed compromise is a block, not a remediation; the cloud disable role stays off; AD-mastered accounts are flagged for an AD disable; restricted-management AU members are escalated to a person | Detection and response |
| [0018](0018-nhi-ownership-and-agent-identity-sponsorship.md) | Two owners per non-human identity, platform credential and consent rules, a monthly inventory and a leaver hand-off; agents get Entra Agent ID with a named sponsor | NHI / governance |
| [0019](0019-pam-vault-high-availability-and-dr.md) | PAM vault: Raft (3 voters in the lab, 5 across three zones in production), auto-unseal from a key outside the cluster, a timed snapshot-restore drill | PAM / resilience |
| [0020](0020-pim-activation-design.md) | PIM activation: approver groups, eligibility expiry, activation caps (Tier 0 4 h, GA and PAA 2 h, Tier 1 8 h), Tier-1 approval only for Intune, User Administrator and the IGA group, authentication-context step-up in three separate changes, direct GA eligibility, AU-scoped service desk | Privileged access |
| [0021](0021-configuration-drift-detection.md) | Configuration drift: a nightly read-only reconcile of the tenant against the committed baseline and the declared intent, findings as an issue (never an automatic revert), exceptions with an owner and an expiry | Delivery / detection |
| [0022](0022-okta-coexistence-as-code.md) | Okta coexistence (acquired clinic) built as code: Okta trusts Entra as its OIDC IdP, a routing rule with the Okta fallback kept, a separate human-applied Okta root, the client secret never in state | Federation / M&A |
| [0023](0023-defender-for-identity-native-ad-detection.md) | Defender for Identity is the primary detector for the native AD-attack signatures; the hand-written KQL rules are the portable/offline twins plus two correlations MDI cannot make (Vault check-out, operator allowlist). Staged behind `enable_defender_for_identity` (sensor + licence are human steps) | Detection / Tier 0 |

## Format

Each ADR has these sections:

- **Title, Status, Date**
- **Context**
- **Options considered** (2–5 per question)
- **Decision**
- **Consequences**, including risks and compensating controls
- **How it is measured** (0012, and 0015 onward): each measure, its source
  and its target. Results are filled in only after a real run
- **Revisit trigger**
- **Evidence**

A risk acceptance names an owner and a review date. 0005 and 0013 are
acceptances in full; 0015 and 0017 each contain one.
Microsoft facts confirmed on Microsoft Learn or a primary source are cited
by URL and check date in a **Sources** section.

## Rules

1. **Evidence means file paths in this repo.** An ADR never claims a tenant
   result, a drill or a metric that hasn't happened. Anything still to be
   run says so, and gets a "fill after running" placeholder where the
   result will go.
2. **External facts that could change are marked `verify:`.** That covers
   product limits, licensing and Microsoft guidance, which must be checked
   against current docs before anyone relies on them.
3. **Status says how far the decision has been exercised.** For example,
   "validated offline" and "applied" are different statuses. From 0015
   onward the words are fixed, and they are the same words the rest of the
   repository uses:
   - **RAN · tenant:** exercised against a real Microsoft tenant, with
     evidence. Nothing yet.
   - **RAN · harness:** exercised end to end in a local harness (the PAM
     stack against Samba AD, the midPoint campaign, dynamic database
     credentials, the Kubernetes segment)
   - **BUILT:** code exists and passes offline checks (validate, lint,
     mocked tests), never applied
   - **DESIGNED:** documented only

   Today, nothing has been applied to a tenant. A decision records a
   measured result only after a real run; until then the result is a
   placeholder (`<measured: …>` or "fill after running").
4. **Decisions are superseded, not edited.** A changed decision gets a new
   ADR, and the old one's status becomes "Superseded by 00NN", or "Partly
   superseded by 00NN" when only part of it changed.
5. **Revisit triggers are reviewed whenever the lab moves a phase forward,**
   for example at the first tenant apply or when a second maintainer joins.
