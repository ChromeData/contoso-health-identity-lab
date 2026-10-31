# ADR 0015: Risk-based Conditional Access thresholds

- **Status:** Accepted (lab). BUILT: CA006 and CA007 are in code behind `enable_identity_protection_ca` (default off), with mocked Terraform tests. Applied: CA006 and CA007 are enabled in the lab tenant; no risk detection has been scored yet.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

ID Protection scores two different things:

- **User risk:** this account is probably compromised (leaked credentials,
  password spray, an admin's "confirm compromised").
- **Sign-in risk:** this sign-in is probably not the owner (anonymous IP,
  unfamiliar properties, token anomalies).

The decision is what each level does. Three facts frame it:

- **Where the policy lives is settled.** The legacy risk policies configured
  inside ID Protection retired on 2026-10-01. Risk-based access is now
  Conditional Access (CA) only, which also gives report-only mode, Terraform
  and one place to read every access rule.
- **A false positive in a hospital is a care delay.** Clinicians move
  between sites, use shared workstations and sign in from home. Nobody knows
  yet how many Medium detections this workforce generates. There is no
  tenant to measure it.
- **A challenge is only as strong as the factor.** If sign-in risk is
  answered with MFA, passing the MFA closes the risk. An attacker who has
  already phished or fatigued that factor (R03) passes the challenge, and
  the risk closes with nothing left for the SOC to see.

## Options considered

1. **Microsoft's recommendation:** user risk High → "Require risk
   remediation"; sign-in risk Medium and High → MFA with sign-in frequency
   every time. It is the right target, with two blockers. The azuread
   provider (3.10.0, the newest release) rejects `riskRemediation` at
   validate. And MFA at Medium self-closes risk that a phished factor can
   satisfy. Rejected as the first step; kept as the target for user risk.
   The target only holds with a phishing-resistant strength: risk
   remediation with the plain MFA strength has the same weakness.
2. **Block both at High** (CISA SCuBA MS.AAD.2.1 and 2.3). Rejected for user
   risk: every leaked-credential detection becomes a locked-out clinician
   and a help-desk unblock. Adopted for sign-in risk.
3. **Medium and High for both.** Rejected until report-only data shows the
   Medium volume. Blocking at Medium without a baseline puts clinicians at
   risk, and challenging at Medium has the self-remediation problem above.
4. **High only, split by risk type, with Medium going to the SOC (chosen).**

## Decision

| | Level | Response | Guests |
|---|---|---|---|
| **CA006** user risk | High | `mfa` AND `passwordChange`, sign-in frequency every time | Excluded: their credential lives in their home tenant |
| **CA007** sign-in risk | High | Block | Included: a block needs nothing from them |
| Medium, either type | – | No CA control. `identity-risk.kql` raises a Medium incident for risk that is still open | – |

- Both policies exclude `Break-Glass-Admins` (ADR 0003). Both start in
  report-only and are graduated one per PR.
- **CA006 is enforced only after CA009 (ADR 0016).** Until registration is
  protected, a password plus push can register an attacker's own method,
  and CA006 would then hand that attacker a password change.
- `sign_in_risk_block_levels` must contain `high`. `["medium", "high"]` is a
  report-only test setting for simulation (a Tor sign-in doesn't reliably
  score High), never a production setting. The policy name follows the list.
- **A recorded SCuBA deviation (risk acceptance).** MS.AAD.2.1 says
  high-risk users shall be blocked; CA006 remediates instead, for the
  lockout reason in option 2. `Invoke-BaselineAssessment.ps1` reports an
  expected FAIL. Risk owner: identity platform owner (in the lab, the
  repository maintainer). Next review: 2027-01-20, or earlier on a revisit
  trigger. The acceptance doesn't cover a confirmed compromise, which gets
  a block (ADR 0017).
- **The upgrade path has two steps.**
  1. Once the provider accepts it: `built_in_controls = ["riskRemediation"]`
     with an authentication strength, dropping `mfa` and `passwordChange`
     (Graph forbids combining them). Passwordless users then get their
     sessions revoked instead of a forced change to a password they never
     use.
  2. Once CA008 is enforced for all users: that strength becomes the
     phishing-resistant one, so a phished or attacker-registered push
     factor can't satisfy CA006. Before then, a phishing-resistant
     requirement at High would block everyone still on password and push,
     which is option 2's lockout.

## Consequences

- **Passwordless users get extra friction.** A passkey satisfies `mfa`, and
  then the user still has to change their password. The outcome is the
  same; the experience is worse until the upgrade.
- **Prerequisites before CA006 is enforced:**
  - MFA registration, because an unregistered high-risk user is simply
    blocked.
  - Password writeback for synced users, or the cloud-side change can't
    reach AD. verify: Cloud Sync writeback in the trial tenant.
- **Medium risk depends on the SOC.** A Medium detection is an incident, not
  a control. If nobody triages it, nothing happens. Containment (ADR 0017)
  acts only on High.
- **One user-risk policy per user.** Microsoft is rolling a managed "Require
  risk remediation" policy into P2 tenants. Precedence puts risk remediation
  above password change, and Block above both. At tenant time the managed
  policy is set to report-only or off by hand, so CA006 stays the single,
  versioned policy. verify: the message-center wording and dates.
- **Entra ID P2 for everyone in scope.** Without it the policies save but
  never match.
- **At High, self-remediation keeps the weakness rejected at Medium.**
  CA006 asks for `mfa`, which an attacker holding the factor can pass.
  That is accepted for detection-raised risk (leaked credentials, spray),
  behind CA009 as above. It is never the answer to a confirmed compromise:
  for a synced account, an attacker with their own method could pass
  CA006, set a password that writes back to AD and lock the owner out
  before the AD disable runs (R14, the CISA AA23-320A pattern). ADR 0017
  answers a confirmed compromise with a block and a method clean-up.
- Workload identities are not covered; that needs Workload ID Premium
  (ADR 0003).

## How it is measured

Fill this in after the first report-only window: at least 14 days,
covering nights and a weekend ([graduate-a-ca-policy.md](../runbooks/graduate-a-ca-policy.md)).

| Measure | Source | Target |
|---|---|---|
| Report-only matches per week, CA006 and CA007 | `SigninLogs`, per-policy CA result | Reported. Drives promotion |
| Medium detections per week, and the share the SOC confirms as true positives | `identity-risk` incidents and their classification | Decides the Medium revisit |
| High-risk users who self-remediated vs. needed an admin | `AADRiskyUsers`, `RiskDetail` | Most self-remediate |
| CA007 blocks of clinicians later confirmed safe | CA007 failures joined to "confirmed safe" | Each one reviewed |
| Confirmed compromises where a password change came before the block | `AuditLogs` password changes vs. the `Invoke-AdContainment.ps1` record | 0 |

## Revisit trigger

- The azuread provider accepts `riskRemediation`: take upgrade step 1.
- **CA008 is enforced for all users.** A phished factor can't pass a
  phishing-resistant challenge. Take upgrade step 2 for CA006, and add a
  Medium sign-in-risk policy requiring that strength, with sign-in
  frequency every time, which no longer self-remediates for an attacker.
- Medium volume and true-positive share are known and fit the SOC's
  capacity.
- A CA007 block delays care.

## Evidence

- `lab/terraform/modules/conditional-access/main.tf` (header "why risk lives
  here"; CA006 and CA007 blocks, including the `riskRemediation` note)
- `lab/terraform/modules/conditional-access/variables.tf`
  (`enable_identity_protection_ca`, `sign_in_risk_block_levels` validation)
- `lab/terraform/modules/conditional-access/tests/ca006_ca007_risk.tftest.hcl`
- `lab/kql/identity-risk.kql` and `lab/splunk/detections/identity-risk.spl`
- `lab/scripts/powershell/Invoke-BaselineAssessment.ps1` (MS.AAD.2.1
  deviation, MS.AAD.2.3)
- `lab/monitoring/playbook-contain.json` (`confirmCompromised`)

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies
  (legacy policies retire 2026-10-01; risk-remediation precedence; not
  supported for guests)
- https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies
  (Microsoft's recommended levels; the High vs. Medium trade-off; writeback
  warning)
