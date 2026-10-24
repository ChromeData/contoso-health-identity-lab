# ADR 0008: IGA with Entra ID Governance (+ midPoint stand-in) vs. SailPoint / Saviynt

- **Status:** Accepted (lab and scenario recommendation). BUILT: the Entra ID Governance side, validated offline, never applied. RAN · harness: a midPoint certification campaign on mock-HR persona users, not Entra data (`lab/evidence/midpoint/20261020T162116Z/`).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Contoso Health needs birthright and requested access, time-bound
assignments, separation of duties, periodic certification and automated
joiner and leaver tasks. Most workforce access runs through Entra groups and
Entra-integrated apps, but a hospital also has applications Entra doesn't
govern natively (EHR roles, on-prem clinical systems), and auditors want
those certified too. SailPoint and Saviynt are the common enterprise answer;
neither has an individual trial.

## Options considered

1. **Entra ID Governance as the IGA of record:** access packages, assignment
   policies with expiry, Lifecycle Workflows, access reviews, incompatible
   packages for SoD. One licence family, same control plane as CA and PIM.
2. **Entra ID Governance plus a third-party IGA** for aggregation and
   certification of non-Entra applications.
3. **SailPoint or Saviynt as the primary IGA,** Entra as directory and
   target only.
4. **midPoint (open source) in production.** It would make Contoso
   responsible for running it. Rejected for a small IAM team.

## Decision

- **Scenario:** option 1 now. Entra ID Governance owns JML, access packages
  and reviews. When Contoso would buy SailPoint or Saviynt is decided by the
  triggers in [`vendor-evaluation.md`](../vendor-evaluation.md) §6, the
  single home for them.
- **Lab:** Evolveum midPoint stands in for options 2 and 3, to show what a
  third-party IGA adds: aggregating accounts from a source, and running a
  certification campaign. It is not part of the production design.

Defined as code on Entra ID Governance (not yet applied):

- **Catalog and packages:** "Nurse - Clinical Apps" and "ICU - Critical Care
  Apps" (birthright, automatic), "ICU - Float Access" and "Pharmacy -
  Controlled Substances Apps" (requested), each with an ADR 0012 tier. A
  separate guest catalog for affiliated physicians sits behind
  `enable_b2b_governance`.
- **Expiry:** 180 days on request policies.
- **Birthright:** automatic assignment from HR attributes
  (`Set-AutoAssignmentPolicies.ps1`, `lab/iga/birthright-rules.json`).
- **SoD:** nine rules in `lab/iga/sod-rules.json`. Preventive: incompatible
  packages and groups (`Set-IncompatibleAccessPackages.ps1`), never on a
  birthright package, so a clinical grant can't be blocked. Detective:
  `09-SoD-Report.ps1` over existing access, PIM eligibility included.
- **Lifecycle Workflows:** a joiner (day 1, Nursing scope, TAP to the
  manager) and a real-time leaver.
- **Reviews:** risk-tiered per ADR 0012, one flag per tier, all off by
  default.

## Consequences

**Positive**
- One control plane and one audit log for access, CA and PIM; no connector
  estate to run at this size.
- Whatever Terraform can express is code. What azuread can't (SoD links,
  automatic assignment, Lifecycle Workflows, standalone reviews, PIM
  eligibility) is idempotent Graph scripts under `post-apply/`.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| SoD is between access packages only; it can't see role combinations inside an application (an EHR) | Model toxic combinations as separate packages where app roles map to groups; anything finer is buy trigger 2 |
| Applications not integrated with Entra fall outside reviews | List them in the app inventory and review them through their owners until the count justifies a third-party IGA |
| Each user in scope consumes a Governance licence | Part of the buy-vs-extend comparison (`vendor-evaluation.md` §8) |
| Turning a review flag off doesn't remove reviews that already exist (provider diff suppression) | Documented in `envs/dev/README.md`; turn them off in the portal |
| The midPoint campaign is a stand-in run: a script records each decision in the assigned reviewer's security context, and no reviewer signs in | Labelled as a stand-in (`STAND-INS.md`); midPoint's own authorization refused a non-reviewer and a reviewer who wasn't the assignee (two probes in the evidence). Aggregating Entra users through the Graph connector hasn't run |

**Not proven yet:** no Governance-tier apply has run. Fill in after running:
an assignment with its expiry date, a refused incompatible request and a
Lifecycle Workflow run history.

## Revisit trigger

- Any buy trigger in `vendor-evaluation.md` §6 fires.
- Microsoft changes what the Governance SKU includes.

## Evidence

- `lab/terraform/modules/entitlement/` (catalog, packages, policies, review
  settings); `lab/terraform/envs/dev/README.md` (staging flags, licensing)
- `lab/scripts/powershell/post-apply/Set-AutoAssignmentPolicies.ps1`,
  `Set-IncompatibleAccessPackages.ps1`, `New-LifecycleWorkflows.ps1`;
  `09-SoD-Report.ps1`, `10-Review-KPIs.ps1`
- `lab/iga/` (access catalog, birthright rules, SoD rules)
- `lab/pam/midpoint/README.md`, `run-campaign.sh`, `record-decisions.groovy`;
  `lab/pam/test/e2e-midpoint.sh`
- `lab/evidence/midpoint/20261020T162116Z/` (latest: 7 items, 4 accepted,
  2 revoked, 1 unanswered and removed; `SHA256SUMS`)
