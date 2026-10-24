# Contoso Health Identity Platform

[![lab-tests](https://github.com/ChromeData/contoso-health-identity-lab/actions/workflows/lab-tests.yml/badge.svg)](https://github.com/ChromeData/contoso-health-identity-lab/actions/workflows/lab-tests.yml)

Michael Williams · IAM Analyst — Identity Security & Privileged Access Management · Microsoft SC-300 · [LinkedIn](https://www.linkedin.com/in/michael-williams-21938325a/) · open to senior IAM/PAM roles

**Hiring for:** [Senior IAM Engineer (Entra)](#senior-iam-engineer-entra) · [Senior IAM Analyst / IGA](#senior-iam-analyst--iga) · [Senior PAM Engineer](#senior-pam-engineer) (four stops each)

I'm an IAM Analyst (SC-300) moving into senior IAM/PAM work. This lab shows
how I'd design, ship and evidence identity for a 5,000-person hospital on
Microsoft Entra, and the [18 decisions](lab/docs/adr/README.md) behind it.

Contoso Health is fictional: hybrid (on-prem AD plus Entra ID), regulated
(HIPAA, SOX), and it has just bought a clinic that runs Okta. Clinicians
can't be locked out of patient care, so every control is designed around
that. Three calls show how I work:

- **Reviews never lock a nurse out.** Unanswered reviews remove privileged
  and requested access, never a clinician's birthright access: HR attributes
  certify that, so a manager on leave can't lock a nurse out of the EHR at
  shift start ([ADR 0012](lab/docs/adr/0012-access-review-no-response-and-clinical-lockout.md)).
- **Conditional Access is change control.** Every policy ships report-only
  and is designed to be enforced one per pull request, after at least 14
  days of sign-in data show what it would block ([runbook](lab/docs/runbooks/graduate-a-ca-policy.md)).
- **No standing admins.** Every privileged role is just in time through PIM,
  Tier 0 with approval and a step-up, and break-glass is designed to be the
  only standing Global Administrator ([ADR 0002](lab/docs/adr/0002-pim-for-groups-vs-direct-role-eligibility.md)).

Okta, Splunk, Kubernetes and midPoint are labeled extensions; Vault and
Guacamole stand in for CyberArk. The [threat model](lab/docs/threat-model.md)
maps five public incidents, among them Change Healthcare, Midnight Blizzard
and Snowflake, to the controls meant to stop each step and the gaps left.

## What has run

> **Nothing has run in a Microsoft tenant yet.** No tenant exists, and that
> run is next. Every tenant feature sits behind a staging flag that is off by
> default, and anything only a live tenant can confirm is marked `verify:` in
> the code.
>
> **Status key:** **RAN · harness** = ran end to end on my laptop or a GitHub
> runner against stand-ins, with synthetic data · **BUILT** = passes offline
> tests with every cloud call mocked, never applied · **DESIGNED** =
> documented only · **RAN · tenant** = none yet

| What | Measured result | Status | Record |
|---|---|---|---|
| The Microsoft core as code | 326 `terraform test` runs in 18 directories (303 for Entra, Azure and AWS) and 1074 Pester tests, 0 failed. GitHub's runners passed the same suites on the published commit (325 and 917 tests at that commit: [run](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523030602)) and run them on every pull request. These mocked tests fail the build if any of the 16 Conditional Access policies loses its break-glass exclusion, a policy behind a staging flag would start enforced, a Tier-0 PIM group loses approval or expiry, or a clinical birthright package could get an expiry or a review that removes it | BUILT | [`offline-tests/20261021T074732Z`](lab/evidence/offline-tests/20261021T074732Z/README.md) |
| 22 identity detections, written in KQL for Sentinel | 22/22 rules and 223/223 cases (131 must fire, 92 must not) on synthetic events, run on the Azure Data Explorer Kusto emulator: a local KQL engine standing in for Sentinel, not Sentinel and not a tenant | RAN · harness | [`kusto/20261021T001217Z`](lab/evidence/kusto/20261021T001217Z/) |
| An access review run to closure in midPoint (standing in for SailPoint), decisions scripted | 7 items of requestable access: 4 accepted, 2 revoked (one an SoD conflict), 1 left unanswered on purpose and removed. A script records each decision as the assigned reviewer; nobody signed in. Completion 85.7% against a 95% target, missed by design so the KPI shows it | RAN · harness | [`midpoint/20261020T162116Z`](lab/evidence/midpoint/20261020T162116Z/) |
| Privileged access end to end, against a Samba AD domain controller (standing in for DC01) | 284/284 checks: discovery, onboarding, dependency-gated rotation, reconciliation, ticket-gated check-out against a ServiceNow mock with two approvers for Tier 0 (neither of them the requester), recorded SSH, and recorded RDP to a Linux xrdp stand-in for DC01. This flow and the other PAM suites (610 passed, 0 failed, 1 skipped) also pass nightly from a fresh clone on GitHub's runners ([latest run](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39937464414)): containers on a runner, not a tenant | RAN · harness | [`pam/20261020T220031Z`](lab/evidence/pam/20261020T220031Z/) |
| 500 privileged accounts through discovery and onboarding | 79/79 checks. 515 accounts discovered in 2.0 s; onboarding vaulted 257 of the 500 and held or excepted the rest. Reconciliation: 263 vaulted (6 from the base layout), 128 documented exceptions, 124 held on unresolved dependencies, gap 0. The 25 rotated accounts were bind-tested; the bind check over every vaulted account (`--verify`) was not run. Five pipeline stages, 139 s in total, one laptop. Synthetic accounts, fixed seed | RAN · harness | [`pam-scale/20261020T193913Z`](lab/evidence/pam-scale/20261020T193913Z/) |
| Vault disaster recovery | All three nodes and their disks destroyed, rebuilt and restored: RTO 42.1 s against a 300 s target, RPO 2.2 s (set by the drill's own pause). A rehearsal cluster holding test markers, not the credential vault | RAN · harness | [`pam-dr/20261020T220031Z`](lab/evidence/pam-dr/20261020T220031Z/) |
| Database access nobody holds | 60/60 checks: a new login per request, read-only on one schema, a 1-hour lease; revoking the lease ends a live session. One synthetic database | RAN · harness | [`dynamic-db/20261020T163436Z`](lab/evidence/dynamic-db/20261020T163436Z/) |

**On GitHub.** The first Dependabot pull requests found two real problems,
both Checkov graph checks the local build lacked: the kind pipeline stopped
at its Checkov stage (CKV2_K8S_6: the nightly-report pod had no
NetworkPolicy), and the IaC scan reported 4 failed checks (56 passed, 12
skipped). Both are fixed in this commit, and a local Checkov with its graph
checks now reports 0 failed on both
([`offline-tests/20261021T074732Z`](lab/evidence/offline-tests/20261021T074732Z/README.md));
neither workflow has re-run on GitHub. Every run, red ones included, is
listed in the [evidence index](lab/evidence/README.md#runs-on-githubs-runners).

## The realistic core

What a Microsoft-first hospital of this size actually runs, and what I built
for each piece:

| Piece | What it does for Contoso | Status |
|---|---|---|
| **Entra ID** | Workforce sign-in and SSO (SAML and OIDC apps as Terraform), a phased passkey rollout, separate cloud-only admin accounts | BUILT |
| **AD + Cloud Sync** | HR is the source of truth: HR feed → API-driven inbound provisioning to on-prem AD (mass-change guard) → Cloud Sync → Entra; the domain controller build is code | BUILT: HR inbound provisioning to AD, DC build. DESIGNED: Cloud Sync ([ADR 0001](lab/docs/adr/0001-cloud-sync-vs-connect-sync.md)) |
| **Intune** | Device trust: admin portals only from a managed, compliant device (CA005, pilot group first) | BUILT |
| **Conditional Access** | 16 policies (13 in Terraform, 3 by Graph script): baseline, risk-based, phishing-resistant, shared clinical workstations. All report-only, designed to be enforced one per pull request; break-glass is excluded from every one, and a test checks it | BUILT |
| **PIM** | Tier 0 (approval, 4 hours, step-up) and Tier 1 (8 hours) through PIM for Groups, Global Administrator eligible per named person, PIM for Azure resources, quarterly reviews of who is eligible | BUILT |
| **ID Governance** | Birthright access from HR attributes, Lifecycle Workflows for joiner, mover and leaver, access packages with 180-day expiry, risk-tiered reviews, nine SoD rules, guests with sponsors and expiry | BUILT |
| **Sentinel** | 22 KQL detections, including the AD plane (Kerberoasting, DCSync, Tier-0 logons PAM cannot account for); containment asks a named approver first | BUILT; rules RAN · harness on the Kusto emulator |
| **One PAM pattern** | Discovery and onboarding of privileged AD accounts, rotation on check-in, ticket-gated check-out with Tier-0 dual control, recorded sessions, 1-hour database logins, on named stand-ins for CyberArk | RAN · harness |
| **ServiceNow** | Single sign-on from Entra; privileged check-out needs an approved change | SSO BUILT (flag off); the change gate RAN · harness against a ServiceNow mock |
| **AWS** | IAM Identity Center federated from Entra (SAML + SCIM), one permission set for a human to apply | BUILT |

All of it ships through one GitHub pipeline that holds no cloud credential:
OIDC, read-only on pull requests, write only behind a reviewer-gated
environment ([ADR 0004](lab/docs/adr/0004-pipeline-workload-identity-federation.md)).
The [architecture map](lab/docs/architecture.md) shows how the pieces
connect, with each box's status ([full-size diagram](lab/docs/architecture.svg)).

## Extended on purpose

No single company runs all of this. Each extension answers teams that run
something other than Microsoft:

| Extension | Why it is here | Status |
|---|---|---|
| **Okta coexistence** | Acquisitions are a common way for a Microsoft shop to get a second identity provider. A runbook moves the clinic's apps to Entra one at a time | DESIGNED: a runbook, no Okta code |
| **Splunk as a second SIEM** | Some SOCs run Splunk instead of, or next to, Sentinel; every KQL rule has an SPL twin | BUILT, never started: no SPL search has run |
| **Conjur OSS** | CyberArk's open-source secrets manager, standing in for Conjur Enterprise for application secrets | RAN · harness: one check in the PAM flow record ([`pam/20261020T220031Z`](lab/evidence/pam/20261020T220031Z/)): the approved job reads its secret, an unapproved one gets 403 |
| **Kubernetes workload identity** | A pod gets its database password with no Kubernetes Secret, environment variable or manifest value. kind stands in for AKS, where this maps to Entra Workload ID | RAN · harness: [12/12 stages, 64/64 checks](lab/evidence/k8s/20261020T202112Z/README.md) on a throwaway kind cluster. The AKS mapping is BUILT, never applied |
| **midPoint** | Open-source IGA standing in for SailPoint or Saviynt, for apps Entra does not govern, such as EHR roles ([ADR 0008](lab/docs/adr/0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md) says when Contoso would buy one) | RAN · harness: the review above |
| **Other stand-ins** | A Samba AD domain controller (for DC01), a Linux RDP target (for an RDP session to DC01) and a ServiceNow mock (for a ServiceNow instance) let the PAM flow run end to end with no license and no tenant; the mock HR feed (for Workday) drives the joiner flow, which needs the tenant's provisioning API | RAN · harness (Samba AD, RDP target, ServiceNow mock); mock HR feed BUILT |

CyberArk, SailPoint and Saviynt sell only to organizations and I hold no
license. [`STAND-INS.md`](lab/docs/STAND-INS.md) names every stand-in, what
it replaces, and what it can and cannot show.

## Pick your path

### Senior IAM Engineer (Entra)

1. [Target state](lab/docs/target-state.md): target, today and gap for each layer of Microsoft's Enterprise Access Model.
2. [Graduating a Conditional Access policy](lab/docs/runbooks/graduate-a-ca-policy.md) and the [policy list](lab/docs/standards/conditional-access-design-principles.md): report-only, measure, fix, then enforce one per pull request.
3. [ADR 0002: PIM design](lab/docs/adr/0002-pim-for-groups-vs-direct-role-eligibility.md): tiers, approvers, expiry and step-up, with the options rejected. Code in [`modules/pim`](lab/terraform/modules/pim/README.md).
4. [ADR 0004: pipeline identity](lab/docs/adr/0004-pipeline-workload-identity-federation.md) and a [green `lab-tests` run on `main`](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/39523030602): OIDC, plan and apply split, no stored credential.

### Senior IAM Analyst / IGA

1. [ADR 0012: review tiers and clinical lockout](lab/docs/adr/0012-access-review-no-response-and-clinical-lockout.md) and the [midPoint review's decisions](lab/evidence/midpoint/20261020T162116Z/decisions.csv): who reviews what, and what happens when a reviewer stays silent.
2. [Vendor evaluation](lab/docs/vendor-evaluation.md): the IGA matrix, and when Contoso would buy SailPoint or Saviynt.
3. [Application onboarding intake](lab/docs/standards/app-onboarding-intake.md): how an app enters governance, with AWS as the worked example.
4. [Help-desk identity verification](lab/docs/runbooks/help-desk-identity-verification.md): the verification ladder before a password reset, MFA reset or Temporary Access Pass.

### Senior PAM Engineer

1. [ADR 0007: PAM stand-ins vs. CyberArk](lab/docs/adr/0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md): CyberArk's vocabulary (Safe, Platform, Master Policy, CPM, PSM) mapped to what runs here, gaps included.
2. [`lab/pam`](lab/pam/README.md) and the PAM flow's [reconciliation report](lab/evidence/pam/20261020T220031Z/reconcile.md): discovery to reconciliation, ticket-gated check-out with dual control, recorded sessions.
3. [ADR 0019: vault HA and DR](lab/docs/adr/0019-pam-vault-high-availability-and-dr.md) and the [DR drill report](lab/evidence/pam-dr/20261020T220031Z/dr-drill.md): the measured RTO and RPO, and what the drill does not cover.
4. [The 500-account reconciliation report](lab/evidence/pam-scale/20261020T193913Z/reconcile.md): onboarding at scale, every exception and held account, gap 0.

Everything else, including a 20-minute reading order with swaps for the PAM
and IGA tracks, the status of every capability and the build order, is in
[`lab/docs/README.md`](lab/docs/README.md).

## Check a record yourself

Inside any record folder, `shasum -a 256 -c SHA256SUMS` (Linux:
`sha256sum -c SHA256SUMS`) must end every line in `OK`. A hash shows that
the files still match what the run wrote, not when or where it ran. The
stronger check is to run it again; no command needs a tenant or a cloud
credential. Both are in the [evidence index](lab/evidence/README.md#re-checking-a-record),
with what each record does **not** prove.

## Repository map

```
.github/          six workflows (plan, apply, AI review, lab tests, k8s identity, PAM harness) + Dependabot
lab/terraform/    envs/bootstrap (human-applied) · envs/dev (CI-applied) · aws/ · k8s/ · modules/
lab/scripts/      mock HR + JML, post-apply Graph steps, NHI / KPI / assessment scripts, drills, DC build
lab/iga/          access catalog, birthright and SoD rules
lab/kql/          22 detections (Sentinel rules, Log Analytics alerts, SPL twins)
lab/splunk/       second SIEM (BUILT, never started)
lab/monitoring/   Sentinel playbooks; the KQL emulator harness
lab/pam/          Vault · Guacamole · Conjur · midPoint (Docker, loopback-only), HA/DR, harnesses
lab/k8s/          kind cluster, manifests, the pipeline script, e2e tests
lab/pipelines/    how the pipeline is wired, and what a human must configure
lab/evidence/     hashed run records, their index, the drill log (empty until the tenant run)
lab/docs/         architecture, decisions, target state, roadmap, risks, threat model, standards, runbooks
```

## Safety

There are no secrets in this repository. CI authenticates with OIDC (the
Kubernetes job needs no cloud credentials at all). Tenant identifiers live in
GitHub variables; the operator's IP and email are masked GitHub secrets.
Generated credentials, Terraform state, harness logs and tenant evidence
exports are gitignored; the hashed run records in `lab/evidence/` hold
synthetic lab accounts only, no secret. All people and organizations are
fictional. See [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
