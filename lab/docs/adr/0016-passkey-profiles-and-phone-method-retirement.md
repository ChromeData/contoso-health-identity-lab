# ADR 0016: Passkey profiles and retiring phone-based MFA

- **Status:** Accepted (lab). BUILT: the authentication methods policy is a post-apply script with offline tests; CA008 and CA009 are in Terraform behind staging flags and start report-only. No tenant exists and no key has been registered.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

- **Microsoft sets the deadline.** Passkeys have been on by default since
  2026-09-01. Microsoft-provided SMS and voice MFA retire on 2027-02-01
  (2027-07-01 for Global Administrators and external users). After that, a
  user whose only method is a phone gets a blocking passkey-registration
  prompt at sign-in, with no opt-out; the exception is a paid telephony
  provider (Learn FAQ, checked 2026-10-21).
- **Profiles control registration, not sign-in.** A passkey profile decides
  what a person may register. Synced passkeys can't be attested.
- **Three populations:** admins, who need to know where the key lives;
  office staff with assigned PCs and their own phones; clinicians on shared
  workstations (ADR 0014).
- **Registration is an attack surface.** An attacker holding a phished
  password and a push approval can register their own passkey, and that
  survives a password reset.

## Options considered

1. **Attested device-bound passkeys for everyone.** The strongest. Rejected
   for staff because of recovery, not hardware: a device-bound passkey dies
   with the phone, so across 5,000 people every replaced phone becomes a
   recovery TAP through the service desk, the path R14 attacks. For admins
   the trade goes the other way: few people, issued spares, and a credential
   that must stay in Contoso's custody.
2. **Synced passkeys allowed for everyone, admins included.** Rejected: an
   admin credential would live in a personal iCloud or Google account.
3. **Keep SMS and voice until forced, or buy a telephony provider.**
   Rejected as the default: the forced prompt lands at shift start with no
   service-desk plan behind it. Kept only as a time-boxed CISO decision for a
   clinical unit that can't get keys in time.
4. **Two profiles, admin assurance enforced at sign-in, and the
   registration action protected (chosen).**

## Decision

| Population | May register (profile) | Must present at sign-in |
|---|---|---|
| Admins and break-glass | "Contoso - Admins": device-bound only, attestation enforced, optional AAGUID allow-list | The admin strength (CA002; CA022 for the PAM broker), narrowed to the issued key models by `admin_fido2_allowed_aaguids` |
| Workforce (`All-Workforce`) | "Contoso - Workforce": synced or device-bound | The workforce strength (CA008): pilot group first, all users behind a second flag |
| Clinicians on shared workstations | Workforce profile, one FIDO2 key each | ADR 0014 |

- **The workforce target is a group, never all users,** or break-glass would
  fall into the synced profile.
- **The workforce rollout refuses to run without the AAGUID list** (a
  Terraform precondition and the script), unless
  `accept_admin_synced_passkey_risk` is set in its own reviewed line.
  Without the list, someone who is both staff and admin could use a synced
  passkey on an admin role.
- **TAP** is one-time, 60 minutes by default and up to 480 for joiners; a
  bootstrap credential, never a daily one, never for break-glass.
- **CA009 protects "register security info"** with a custom strength,
  "Bootstrap and recovery (lab)": a one-time TAP or a phishing-resistant
  method. The built-in MFA strength was rejected for this action because
  password plus push could then register a passkey, the persistence path
  above; `registration_strength_combinations` refuses phishable
  combinations.
- **The registration wave (the single home for it).** CA009 is enforced
  before rollout phase 2, so every first registration in phases 2–4 needs a
  one-time TAP: up to one per person, most of the workforce, over a few
  months.
  - **Chosen:** IAM Engineering issues wave TAPs with
    `07-Passwordless-Rollout.ps1 -IssueTapFor`, one wave list at a time, and
    hands them over in person at a registration session or to the line
    manager. Never by email, text or phone. The service desk issues TAPs only
    for joiner fallback and recovery.
  - **Rejected: enforce CA009 one wave at a time.** People not yet in a wave
    hold only password and push, the population an attacker can register a
    method for, and they stay open longest.
  - **Rejected: wave TAPs on request from the service desk.** Thousands of
    calls through the path R14 attacks, indistinguishable in any log.
  - **Every TAP is explainable:** it matches the joiner workflow, a wave
    batch filed with its change ticket, or a service-desk ticket. Anything
    else is investigated as a possible R14 case.
- **SMS and voice** are turned off by Contoso before Microsoft's date:
  `-DisableSmsVoice` runs only when no in-scope user depends on a phone alone
  (fail closed). Break-glass is always excluded.
- **Authenticator push is the bridge, not the fix.** App name and
  location in the push stop fatigue attacks, not adversary-in-the-middle phishing. One-time
  codes are turned off: a second phishable path that can be read out over the
  phone. CA008 closes both.

## Consequences

- **"Admins use device-bound keys" means buying keys,** because it is
  enforced only by naming the key models. Key logistics (issuing, unit
  spares, recovery from leavers) are not built.
- **Synced passkeys are accepted for staff:** phishing-resistant and far
  stronger than SMS, but resting on the person's consumer account.
- **CA009 now reaches device setup.** From 2026-07-06, policies that target
  "Register security information" also apply to Windows Hello for Business
  and macOS Platform SSO registration (Learn, checked 2026-10-21), so a
  password-plus-push user setting up Windows Hello needs a TAP. Measure it in
  report-only before enforcing.
- **Turning on passkey profiles can't be undone,** so the script never does
  it implicitly.
- **Guests are out of CA008;** they meet a strength only through inbound MFA
  trust from their home tenant (rollout phase 5).

## How it is measured

Fill in per phase ([passwordless-rollout-plan.md](../passwordless-rollout-plan.md)).

| Measure | Source | Target |
|---|---|---|
| Privileged and PIM-eligible users with an attested device-bound key | `08-Measure-KPIs.ps1`, scoped to admins | 100% before CA002 is enforced |
| Workforce with any phishing-resistant method | `phishing_resistant_pct` | Rises per phase |
| Users whose only method is a phone | `07-Passwordless-Rollout.ps1` | 0 by 2027-01-01 |
| Registrations CA009 would have blocked | Report-only results for the user action | Known and explained before enforcing |
| TAPs issued, by issuer: rollout, joiner workflow, service desk | Audit logs joined to each wave's list | Unexplained TAPs per week: 0 |

## Revisit trigger

- Authentication strengths can tell synced from device-bound passkeys
  without AAGUIDs: the allow-list becomes optional.
- Microsoft moves the retirement dates.
- A consumer passkey provider is compromised.
- A clinical unit misses the 2026-12-01 decision point in the rollout plan.
- CA009 report-only shows Windows Hello provisioning blocked at scale.

## Evidence

- `lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`,
  `07-Passwordless-Rollout.ps1` (`-IssueTapFor`) and their Pester tests
- `lab/terraform/modules/conditional-access/main.tf` (strengths, the
  precondition, CA008), `baseline.tf` (CA009 and its strength), `admins.tf`
  (CA022), `variables.tf`; tests `ca008_phishing_resistant.tftest.hcl`,
  `ca009_ca010_baseline.tftest.hcl`
- `lab/kql/security-info-registered-risky.kql`,
  `auth-method-changed-by-admin.kql`

## Sources (Microsoft Learn)

- https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement-faq
  (dates, blocking prompt, no opt-out, telephony providers; checked
  2026-10-21)
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration
  (registration action; Windows Hello and Platform SSO from 2026-07-06;
  checked 2026-10-21)
- https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-passkeys-fido2
  (passkey profiles; synced passkeys can't be attested; checked 2026-10-20)
- https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-how-it-works
  (checked 2026-10-20)
