# IAM operating model (lab scenario)

| | |
|---|---|
| Scope | Contoso Health, the lab's fictional 5,000-user hospital |
| Status | Draft v0.1, 2026-10-26. Nothing here has operated: no tenant exists |
| Owner | IAM Engineering, accountable to the CISO |

The RACI (`raci.md`) says **who** does each activity. This document says
**how the function runs**: where decisions are made, who may say no, what
cadence things happen on, and what gets reported upward. It exists because
senior identity roles are judged on the operating model as much as on the
controls: "define an IAM operating model with decision rights" is a
responsibility in the postings this lab was measured against.

## 1. Decision rights

One accountable owner per decision. A decision outside this table is
escalated to the CISO, recorded as an exception (`exception-process.md`)
and added here.

| Decision | Who decides | Who can block | Where it is recorded |
|---|---|---|---|
| A new or changed Conditional Access policy (report-only) | IAM Eng | SOC (detection impact) | PR in `modules/conditional-access`; `runbooks/ca-change-review-checklist.md` |
| Graduating a policy to enforced | CISO (A), on IAM Eng's evidence | Clinical Operations, for any policy that touches clinicians | `lab.tfvars` PR; `runbooks/graduate-a-ca-policy.md` |
| Who is eligible for a privileged role, and the tier it sits in | CISO (A); IAM Eng proposes | Internal Audit (SoD) | `Set-PimGroupEligibility.ps1` register; ADR 0020 |
| Approving a Tier-0 activation | The Tier-0 approver group (two members, never the requester) | | PIM request; `pim-activation.kql` |
| Birthright rules (what a job title gets on day one) | App Owner (A) with IAM Eng; HR consulted | Clinical Operations | `lab/iga/birthright-rules.json` |
| A separation-of-duties pair | App Owner (A); Audit consulted | Audit | `lab/iga/sod-rules.json` |
| Onboarding an application (protocol, provisioning, owner) | IAM Eng, from the intake form | Security architecture, for anything not SAML/OIDC/SCIM | `standards/app-onboarding-intake.md` |
| A non-human identity's existence, owners and credential type | The two named owners (A); IAM Eng approves the credential type | IAM Eng (no secrets on new apps) | `standards/nhi-standard.md`; `06-NHI-Inventory.ps1` |
| An exception to any standard | CISO (A), time-boxed, with an owner | Audit | `standards/exception-process.md`; `lab/config-baseline/drift-exceptions.json` for configuration findings |
| Containing a compromised account | SOC (A); a listed approver answers in Teams | Nobody: a confirmed compromise is blocked, not debated | `monitoring/playbook-contain.json`; ADR 0017 |
| Accepting a residual risk | CISO (A), with a review date | | `risk-register.md`; ADRs 0005, 0013 |
| A new vendor or product (PAM, IGA) | CISO (A) on IAM Eng's evaluation; Procurement runs the process | Audit (evidence requirements) | `vendor-evaluation.md` |
| The configuration baseline and its exceptions | IAM Eng (A) by PR | SOC | `lab/config-baseline/`; ADR 0021 |

## 2. Forums and cadence

| Forum | Cadence | Chair | Inputs | Outputs |
|---|---|---|---|---|
| Identity change review | Weekly, and per PR for Tier-0 changes | IAM Eng lead | Open PRs, report-only evidence, drift findings | Approve, hold or graduate; the CA checklist signed |
| Privileged access review | Quarterly (ADR 0012 T1) | CISO | PIM eligibility, standing admins (`08-Measure-KPIs.ps1`), break-glass drill result | Removals; the drill record |
| Access certification | Half-yearly (T2 requestable), quarterly (T1) | App Owners, run by IAM Eng | Review campaigns, SoD report (`09-SoD-Report.ps1`) | Decisions applied; KPIs (`10-Review-KPIs.ps1`) |
| Identity risk and metrics | Monthly | CISO | KPI snapshot, risk register deltas, incident summary, exception register | The one-page KPI view (`New-KpiOnePager.ps1`); risk acceptances renewed or closed |
| Exception board | Monthly, inside the risk meeting | CISO | Exceptions due to expire | Renew with a reason, or close |
| Post-incident review | Within 5 business days of a Sev 1 or Sev 2 identity incident | SOC lead | The post-incident report (`runbooks/post-incident-report-template.md`) | Actions with owners; a detection or control change as a PR |
| Tabletop | Twice a year | IAM Eng with SOC | `runbooks/identity-incident-tabletop.md` | Findings into the risk register |

## 3. Intake and service levels

Requests reach IAM Engineering through three doors only. Anything else is
redirected, so the audit trail stays whole.

| Door | For | Target |
|---|---|---|
| Access request (self-service catalog) | Requestable packages, guests | Approval within 2 business days; auto-expiry at 180 days |
| App onboarding intake | New SSO or provisioning integration | Triage in 5 business days; a standard SAML/OIDC app live in 10 |
| Change (PR) | Everything that changes a policy, a role, a rule | Reviewed within 1 business day; Tier 0 within the same day by two reviewers |

Operational targets, stated as the lab's standard and unmeasured:

- Leaver: sessions revoked and account disabled within **30 minutes** of
  the HR event (KPI `hr_to_disable_minutes`).
- Compromise: sessions revoked within **15 minutes** of triage confirming
  it; account disabled within **30** (`runbooks/compromised-identity.md`).
- Break-glass: drilled every **90 days**; an unplanned use is Sev 1.
- Drift: a High finding resolved or excepted within **1 business day**
  (ADR 0021).

## 4. What is reported, and to whom

| Audience | Cadence | What | Source |
|---|---|---|---|
| CISO and executive leadership | Monthly | The one-page KPI view: standing admins, just-in-time share, phishing-resistant coverage, MFA coverage, leaver containment time, review completion, stale accounts, NHI findings, open High drift, open exceptions, with direction of travel | `08-Measure-KPIs.ps1` → `New-KpiOnePager.ps1` |
| Board (through the CISO) | Quarterly | Three numbers and a sentence each: standing privileged humans, share of the workforce on phishing-resistant sign-in, minutes to contain a leaver; plus any accepted High risk | The same one-pager, top block |
| Internal Audit | On request, and at each review cycle | The hashed evidence pack mapped to controls | `Export-EvidencePack.ps1`; `compliance-crosswalk.md` |
| SOC | Daily | Detection queue, drift issue, PIM activations | Sentinel; the `identity-drift` issue |
| Clinical Operations | Before each enforcement wave | Who is affected, what changes for them, the rollback | `passwordless-rollout-plan.md`; the graduation runbook |

## 5. Roles on the team (lab sizing)

| Role | Owns | Does not own |
|---|---|---|
| IAM engineering lead (this lab's author) | The platform, its code, the standards, the roadmap, the baseline | Detection tuning (SOC), access decisions (owners), risk acceptance (CISO) |
| IAM engineer | Changes through PRs, post-apply scripts, JML exceptions, L2 in incidents | Approving their own Tier-0 activation |
| Service desk | Standard-user resets and TAPs inside the workforce AU, with the verification ladder | Any admin account, any VIP in the restricted AU |
| SOC analyst | Triage, detections, the containment approval | Changing a policy without a PR |

Mentoring and review-and-challenge are explicit duties of the lead: every
Tier-0 PR has a second reviewer, and every access design is challenged for
least privilege and SoD before it is built (`standards/iam-standard.md`).

## 6. What would change this document

- A real HR system with its own change control (the HR door becomes a
  contract, not a form).
- A second tenant or an acquisition that is not folded in (per-tenant
  decision rights).
- A production PAM or IGA product (the vendor's workflow replaces the
  catalog door for the access it governs).
