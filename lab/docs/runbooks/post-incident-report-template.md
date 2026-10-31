# Post-incident report (identity) — template

**Use for:** every Sev 1 or Sev 2 identity incident, and every tabletop
(`identity-incident-tabletop.md`). Written by the SOC lead within 5 business
days; reviewed in the post-incident forum (`standards/iam-operating-model.md`,
§2). Blameless: it names systems and gaps, not people.

**Status of this template:** no incident has occurred and no tabletop has
run in the lab. The example values below are placeholders
in angle brackets, never measured numbers.

---

## 1. Summary (five lines, for the CISO)

| | |
|---|---|
| Incident | `<INC number>` · `<one-line title>` |
| Severity and type | `<Sev 1 / Sev 2>` · `<credential compromise / token theft / MFA tampering / privilege escalation / consent abuse / break-glass use>` |
| Detected by | `<rule name, e.g. identity-risk.kql>` or `<person / vendor report>` |
| Impact | `<accounts affected, data or systems reached, clinician impact: none / minutes of lockout>` |
| Contained in | `<minutes from triage confirmation to session revoke>` revoke · `<minutes>` disable (targets: 15 / 30) |

## 2. Timeline (UTC)

| Time | Event | Source |
|---|---|---|
| `<T0>` | First malicious action | `<sign-in log row id / audit event>` |
| `<T+..>` | First detection fired | `<rule>`; Sentinel incident `<id>` |
| `<T+..>` | Triage confirmed compromise (L1) | Ticket |
| `<T+..>` | Containment approved in Teams by `<approver role>` | `playbook-contain.json` run id |
| `<T+..>` | Sessions revoked | Audit event `revokeSignInSessions` |
| `<T+..>` | Account disabled / methods cleaned / TAP issued | Audit events |
| `<T+..>` | Recovery: user back in | Sign-in log |
| `<T+..>` | Incident closed | Ticket |

## 3. What happened, step by step

Map every attacker step to the control meant to stop it and the detection
meant to see it, in the format of `threat-model.md`:

| Step | Attacker action | Control that should have stopped it | Did it? | Detection that should have seen it | Did it? |
|---|---|---|---|---|---|
| 1 | `<e.g. phished password>` | `<CA001 MFA>` | `<yes / no / report-only>` | `<failed-signin-spike.kql>` | `<fired at T+..>` |
| 2 | | | | | |

## 4. What worked

- `<control or runbook step that performed as designed, with the evidence>`

## 5. What did not

For each gap: the gap, why it existed, and whether it was known.

| Gap | Known before? (risk register ID / ADR) | Why it existed |
|---|---|---|
| `<e.g. CA010 was still report-only, so the device-code flow succeeded>` | `<R03, yes>` | `<graduation wave not reached>` |

## 6. Actions

Every action is a PR, a runbook change or a risk-register change, with an
owner and a date. "Train people" is not an action unless it has a test.

| Action | Type | Owner | Due | Done |
|---|---|---|---|---|
| `<graduate CA010>` | PR `lab.tfvars` | IAM Eng | `<date>` | |
| `<new rule for ...>` | PR `lab/kql/` | SOC | `<date>` | |
| `<update R03 residual>` | `risk-register.md` | CISO | `<date>` | |

## 7. Evidence attached

The sign-in and audit exports, the Sentinel incident, the playbook run
history, the ticket, and this report, hashed into the evidence pack
(`Export-EvidencePack.ps1`) under the incident number. No credential, token
or personal identifier beyond what the incident needs is kept in the public
record.

## 8. Metrics update

| KPI | Before | After |
|---|---|---|
| Time to detect (T0 → detection) | | |
| Time to contain (confirmation → revoke) | | |
| Controls in report-only on the attack path | | |
