# ADR 0015: Risk-based Conditional Access thresholds

- **Status:** Accepted (lab). BUILT: CA006 and CA007 in code behind `enable_identity_protection_ca` (default off), with mocked Terraform tests. No tenant exists, so no risk detection has been scored.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

ID Protection scores two things: **user risk** (this account is probably
compromised: leaked credentials, spray, an admin's "confirm compromised")
and **sign-in risk** (this sign-in is probably not the owner: anonymous IP,
unfamiliar properties, token anomalies). The decision is what each level
does. Three facts frame it:

- **Where the policy lives is settled.** The legacy risk policies inside ID
  Protection retired on 2026-10-01. Risk-based access is now Conditional
  Access only, which also gives report-only mode, Terraform and one place to
  read every access rule.
- **A false positive in a hospital is a care delay.** Clinicians move
  between sites, use shared workstations and sign in from home. Nobody knows
  yet how many Medium detections this workforce generates.
- **A challenge is only as strong as the factor.** If risk is answered with
  MFA, passing the MFA closes the risk. An attacker who already phished or
  fatigued that factor (R03) passes, and the risk closes with nothing left
  for the SOC to see.

## Options considered

1. **Microsoft's recommendation:** user risk High → "Require risk
   remediation"; sign-in risk Medium and High → MFA every time. The right
   target for user risk, with two blockers: the azuread provider (3.10.0)
   rejects `riskRemediation` at validate, and MFA at Medium self-closes risk
   that a phished factor can satisfy.
2. **Block both at High** (CISA SCuBA MS.AAD.2.1 and 2.3). Rejected for user
   risk: every leaked-credential detection becomes a locked-out clinician
   and a help-desk unblock. Adopted for sign-in risk.
3. **Medium and High for both.** Rejected until report-only data shows the
   Medium volume.
4. **High only, split by risk type, with Medium going to the SOC (chosen).**

## Decision

| | Level | Response | Guests |
|---|---|---|---|
| **CA006** user risk | High | `mfa` AND `passwordChange`, sign-in frequency every time | Excluded: their credential lives in their home tenant |
| **CA007** sign-in risk | High | Block | Included: a block needs nothing from them |
| Medium, either type | – | No CA control. `identity-risk.kql` raises a Medium incident for risk still open | – |

- Both exclude `Break-Glass-Admins` (ADR 0003), start report-only and are
  graduated one per PR.
- **CA006 is enforced only after CA009 (ADR 0016).** Until registration is
  protected, password plus push can register an attacker's own method, and
  CA006 would hand that attacker a password change.
- `sign_in_risk_block_levels` must contain `high`; `["medium", "high"]` is a
  report-only simulation setting, never production.
- **A recorded SCuBA deviation (risk acceptance).** MS.AAD.2.1 says
  high-risk users shall be blocked; CA006 remediates instead, for the
  lockout reason in option 2. `Invoke-BaselineAssessment.ps1` reports the
  expected FAIL. Risk owner: identity platform owner. Next review:
  2027-01-20. It doesn't cover a **confirmed** compromise, which gets a
  block and a method clean-up (ADR 0017).
- **Upgrade path:** (1) once the provider accepts it, `riskRemediation` with
  an authentication strength replaces `mfa` + `passwordChange`; (2) once
  CA008 is enforced for all users, that strength becomes the
  phishing-resistant one, so a phished push factor can't satisfy CA006.

## Consequences

- **Passwordless users get extra friction** until the upgrade: a passkey
  satisfies `mfa`, then they still change a password they never use.
- **Before CA006 is enforced:** MFA registration (an unregistered high-risk
  user is simply blocked) and password writeback for synced users.
- **Medium risk depends on the SOC.** A Medium detection is an incident, not
  a control; containment (ADR 0017) acts only on High.
- **One user-risk policy per user.** Microsoft's managed "Require risk
  remediation" policy is set to report-only or off at tenant time, so CA006
  stays the single, versioned policy (verify: the message-center wording).
- **Entra ID P2 for everyone in scope;** without it the policies never match.
- **At High, self-remediation keeps the weakness rejected at Medium.**
  Accepted for detection-raised risk behind CA009; never the answer to a
  confirmed compromise.

## How it is measured

Fill in after the first report-only window: at least 14 days, covering
nights and a weekend.

| Measure | Source | Target |
|---|---|---|
| Report-only matches per week, CA006 and CA007 | `SigninLogs`, per-policy CA result | Reported; drives promotion |
| Medium detections per week, and the share the SOC confirms | `identity-risk` incidents | Decides the Medium revisit |
| High-risk users who self-remediated vs. needed an admin | `AADRiskyUsers` | Most self-remediate |
| CA007 blocks of clinicians later confirmed safe | CA007 failures joined to "confirmed safe" | Each one reviewed |
| Confirmed compromises where a password change came before the block | `AuditLogs` vs. the `Invoke-AdContainment.ps1` record | 0 |

## Revisit trigger

- The provider accepts `riskRemediation`: upgrade step 1.
- CA008 is enforced for all users: upgrade step 2, and add a Medium
  sign-in-risk policy requiring the phishing-resistant strength.
- Medium volume and true-positive share fit the SOC's capacity.
- A CA007 block delays care.

## Evidence

- `lab/terraform/modules/conditional-access/main.tf` (CA006, CA007,
  `riskRemediation` note), `variables.tf`,
  `tests/ca006_ca007_risk.tftest.hcl`
- `lab/kql/identity-risk.kql`, `lab/splunk/detections/identity-risk.spl`
- `lab/scripts/powershell/Invoke-BaselineAssessment.ps1` (MS.AAD.2.1
  deviation); `lab/monitoring/playbook-contain.json`

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies
  (legacy policies retired 2026-10-01; precedence; not for guests)
- https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies
