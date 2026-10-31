# Runbook: identity incident tabletop (twice a year)

**Scenario:** Contoso Health lab, a fictional 5,000-user hospital.
**Status:** written against the lab code, never exercised. A
tabletop runs as a discussion; the "inject" steps marked
**[tenant]** are the ones that can now run as live drills in the lab tenant.

**Purpose.** Prove, before a real incident, that the people in the RACI can
run `compromised-identity.md` end to end, that the detections and the
containment playbook cover the attack paths in `threat-model.md`, and that
the evidence an auditor would ask for is produced. Each exercise ends with
a post-incident report (`post-incident-report-template.md`) and actions that
are PRs.

**Who attends.** L1 (SOC tier 1 / service desk), L2 (IAM engineer), the
SOC lead (facilitator), one Tier-0 approver, Clinical Operations, Audit as
observer. 90 minutes.

## Rules

1. The facilitator injects facts one at a time; players say what they do,
   which runbook step it is, and what evidence it leaves.
2. Every "we would check X" must name the query, log or script. "Someone
   would notice" is a finding.
3. Time is kept against the lab's targets (revoke ≤ 15 min, disable ≤ 30
   min, HR-to-disable ≤ 30 min, drift High ≤ 1 business day).
4. Nothing is changed in any tenant during a discussion exercise. A live
   drill uses test accounts only (`lab/scripts/demo/`), never a clinician.

## Scenario A — Phished nurse, device-code flow (R03)

| Inject | Expected response | Evidence expected |
|---|---|---|
| 1. A nurse reports approving an MFA prompt they did not start | L1 triage, step 1 of the runbook: account type, privilege, successful sign-in from an unexpected location | Ticket with UTC start; sign-in export |
| 2. Sign-in logs show a device-code sign-in that **succeeded** | Was CA010 enforced or report-only? If report-only, that is a known gap (R03, roadmap order 10). L2 revokes sessions now | `device-code-phishing.kql` incident; `revokeSignInSessions` audit event |
| 3. The account is AD-synced | Containment flags it; L2 disables in AD (`Invoke-AdContainment.ps1`) and cleans methods, because an attacker-registered method would pass CA006 | AD disable event; methods removed |
| 4. **[tenant]** The playbook asks for approval in Teams | A listed approver who is not the subject answers; no answer in 4 h means no action (ADR 0017) | Playbook run history |
| 5. Recovery: the nurse needs to work the next shift | TAP issued by the service desk inside the workforce AU, with the verification ladder | TAP audit event; ticket |

**Discussion questions.** What if the nurse were in the restricted-management AU? What if the report came at 03:00 on a Sunday?

## Scenario B — Help-desk social engineering against an admin (R14)

| Inject | Expected response | Evidence expected |
|---|---|---|
| 1. A caller claiming to be a Tier-1 admin asks the service desk to reset their MFA | The ladder in `help-desk-identity-verification.md`; the service desk's roles are scoped to the workforce AU and cannot reach an admin | Ticket; the refusal |
| 2. The caller escalates to a "manager" by email | No path exists: admin method changes need Privileged Authentication Administrator (Tier 0, PIM, approval, `c1`) | PIM request, or its absence |
| 3. **[tenant]** An admin's method is changed anyway | `auth-method-changed-by-admin.kql` fires; L2 treats it as Sev 1 | Incident; the actor's PIM activation (or `role-assigned-outside-pim.kql`) |

## Scenario C — Change outside the pipeline (R01, ADR 0021)

| Inject | Expected response | Evidence expected |
|---|---|---|
| 1. The nightly drift job opens an `identity-drift` issue: CA002 excludes a new group | Was this a known action? If yes, it should be a PR, not a portal change: revert by PR and close with the exception process. If no, it is Sev 1 and `compromised-identity.md` applies to the actor | The issue; `ca-policy-changed.kql` incident with the actor |
| 2. The actor was the APPLY identity, outside any workflow run | R01 is realised: rotate the federated credential subject, review the workflow run history, treat as Tier-0 compromise | Audit log actor = APPLY app; no matching workflow run |

## Scenario D — Break-glass used (ADR 0003)

| Inject | Expected response | Evidence expected |
|---|---|---|
| 1. `break-glass-signin.kql` fires outside a scheduled drill | Sev 1 at once; confirm with the custodians whether the use was planned; if not, rotate the account's passkey, review every action it took | The alert; custodian confirmation; audit of actions by `bg-admin-NN` |

## Scoring

| Area | Score 0–2 | Notes |
|---|---|---|
| Right runbook step named each time | | |
| Detections named, and whether they exist | | |
| Time targets met in the walk-through | | |
| Evidence named for every step | | |
| Clinical impact considered | | |

Findings go to `risk-register.md` (new or changed residual), the post-incident
report, and PRs. The record of the exercise (date, attendees, scores,
actions) is hashed into the evidence pack like a drill
(`lab/evidence/drills/README.md`).
