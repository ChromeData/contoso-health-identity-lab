# ADR 0008: IGA with Entra ID Governance (+ midPoint stand-in) vs. SailPoint / Saviynt

- **Status:** Accepted (lab and scenario recommendation). The Entra ID Governance side is code, validated offline, never applied. The midPoint certification campaign ran locally on 2026-10-20, on mock-HR persona users, not Entra data. `test/e2e-midpoint.sh` passed 91/91 in every `lab/pam/test/run-all.sh` run that day; the latest count is in the newest `lab/evidence/offline-tests/` record (counts and the runner's console output), and the latest campaign record is hashed in `lab/evidence/midpoint/20261020T162116Z/`.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Contoso Health needs these governance capabilities:

- birthright and requested access
- time-bound assignments
- separation of duties
- periodic certification
- automated joiner and leaver tasks

Most of its workforce access runs through Entra groups and Entra-integrated
apps. A hospital also has applications Entra doesn't govern natively. EHR
roles and on-prem clinical systems are the usual examples, and auditors want
those certified too. SailPoint and Saviynt are the common enterprise answer,
and neither has an individual trial.

## Options considered

1. **Entra ID Governance as the IGA of record.** Access packages, assignment
   policies with expiry, Lifecycle Workflows, access reviews, and
   incompatible access packages for SoD. One licence family, same control
   plane as CA and PIM.
2. **Entra ID Governance plus a third-party IGA** (SailPoint, Saviynt) for
   aggregation and certification of non-Entra applications.
3. **SailPoint or Saviynt as the primary IGA,** with Entra as a directory
   and target only.
4. **midPoint (open source) in production.** Capable, but it would make
   Contoso responsible for running and supporting it. Rejected for a
   5,000-user hospital with a small IAM team.

## Decision

- **Scenario:** option 1 now. Entra ID Governance owns JML, access packages
  and reviews.
- **Lab:** Evolveum midPoint runs as the stand-in for options 2 and 3. It
  shows the two things a third-party IGA adds: aggregating accounts from a
  source, and running a certification campaign. It is not part of the
  production design.

What the lab defines as code on Entra ID Governance (not yet applied to a tenant):

- **Catalog and access packages:** a catalog and four access packages, each
  with an ADR 0012 tier and an assignment model: "Nurse - Clinical Apps" and
  "ICU - Critical Care Apps" (birthright, automatic), "ICU - Float Access"
  and "Pharmacy - Controlled Substances Apps" (requested). A separate guest catalog for affiliated physicians sits behind
  `enable_b2b_governance`.
- **Expiry:** a 180-day assignment duration on request policies.
- **Birthright:** automatic assignment policies built from HR attributes
  (`Set-AutoAssignmentPolicies.ps1`, `lab/iga/birthright-rules.json`; ADR
  0012 T3).
- **SoD:** nine rules in `lab/iga/sod-rules.json`. Preventive: incompatible
  packages and groups (`Set-IncompatibleAccessPackages.ps1`), never placed on
  a birthright package, so a clinical grant can't be blocked by them.
  Detective: `09-SoD-Report.ps1` over existing access, PIM eligibility
  included. `Set-IncompatibleAccessPackages.ps1` is written to replace the
  original both-ways Nurse and Pharmacy pair (`Set-AccessPackageSoD.ps1`).
- **Lifecycle Workflows:** a joiner (day 1, Nursing scope, TAP to the
  manager, access package request) and a real-time leaver.
- **Reviews:** risk-tiered per ADR 0012, one flag per tier, all off by
  default.

## Consequences

**Positive**
- One control plane and one audit log for access, CA and PIM. No connector
  estate to run at this size.
- Everything that Terraform can express is code. The gaps the azuread
  provider can't express (SoD links, automatic assignment policies,
  Lifecycle Workflows, standalone access reviews, PIM eligibility) are
  idempotent Graph scripts under `post-apply/`.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| SoD is between access packages only. It can't see role combinations inside an application (for example within an EHR). | Model toxic combinations as separate packages wherever the app's roles map to groups. Anything finer is a buy trigger (below). |
| Applications not integrated with Entra fall outside reviews. | List them in the app inventory, and review them through their owners until the count justifies a third-party IGA. |
| Each assigned user consumes an Entra ID Governance licence. | Licence cost is part of the buy-vs-extend comparison. verify: current per-user pricing. |
| `enable_access_reviews = false` does not remove reviews that already exist (provider diff suppression). | Documented in `envs/dev/README.md`. Turn reviews off in the portal. |
| The midPoint campaign is a stand-in run, not a tenant result. It ran headless over REST against midPoint 4.10.4 (7 items: 4 accepted, 2 revoked, 1 left unanswered and removed; remediation applied; hashed evidence in `lab/evidence/midpoint/`). The users are object files built from the mock-HR personas. midPoint 4.10's REST API has no decision endpoint, so `record-decisions.groovy` records each decision through midPoint's own decision service, running in the assigned reviewer's security context: midPoint checks that reviewer's authorizations and records them as the decider, but no reviewer signs in. | Labelled as a stand-in (`STAND-INS.md`, `lab/pam/midpoint/README.md`). midPoint's own authorization refuses a user without the Reviewer role and a reviewer who isn't the assignee (two probes in the evidence). Still open: aggregating Entra users through the Graph connector (1.2.0.0, unverified on 4.10). Fill in after running: imported user count. |

**Not proven yet:** no Governance-tier apply has run. Fill in after running:
an access package assignment with its expiry date, a rejected incompatible
request, and a Lifecycle Workflow run history.

## Revisit trigger (when Contoso buys SailPoint or Saviynt)

Any one of these:

- **Uncertified apps:** auditors require certification of applications Entra
  can't review, and owner-run reviews no longer keep up.
- **Fine-grained SoD:** SoD has to be enforced at entitlement level inside
  applications (EHR, pharmacy, finance), not only between packages.
- **Role mining:** role mining or an access-modelling programme is mandated.
- **Acquisitions:** they bring directories and apps that won't be
  consolidated into Entra soon.
- **Scale:** headcount grows roughly tenfold. The stand-in line in
  `STAND-INS.md` names fifty thousand users as the point where a SailPoint
  conversation starts.

## Evidence

- `lab/terraform/modules/entitlement/`: catalog, packages, assignment
  policies, review settings
- `lab/terraform/envs/dev/README.md`: staging flags, licensing tier per
  piece
- `lab/scripts/powershell/post-apply/Set-AutoAssignmentPolicies.ps1`,
  `Set-IncompatibleAccessPackages.ps1` (`Set-AccessPackageSoD.ps1` is now a
  forwarding shim to it), `New-LifecycleWorkflows.ps1`
- `lab/scripts/powershell/09-SoD-Report.ps1`, `10-Review-KPIs.ps1`
- `lab/iga/`: access catalog, birthright rules, SoD rules
- `lab/pam/midpoint/README.md`, `run-campaign.sh`, `record-decisions.groovy`
- `lab/pam/test/e2e-midpoint.sh`
- `lab/evidence/midpoint/20261020T162116Z/` (latest) and
  `20261020T152623Z/` (before the ADR 0012 threshold: its
  `rubber_stamp_flagged` list uses the superseded definition; evidence
  files left unchanged): the closed campaign, decisions, before and after
  states, KPIs, `SHA256SUMS`
- `lab/pam/README.md`: midPoint section and harness checks
- `lab/pam/docker-compose.yml`: midPoint service
- `lab/docs/STAND-INS.md`: midPoint row
