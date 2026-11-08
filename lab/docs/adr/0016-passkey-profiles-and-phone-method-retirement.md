# ADR 0016: Passkey profiles and retiring phone-based MFA

- **Status:** Accepted (lab). BUILT: the authentication methods policy is a post-apply script with offline tests; CA008 and CA009 are in Terraform behind staging flags and start in report-only. Applied: CA009 is enforced in the lab tenant, CA008 still behind its flag. Since 2026-11-05 the three lab admins and both break-glass accounts hold one SOFTWARE passkey each (lab deviation, not attested; see Consequences; E11c, E11d).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

- **Microsoft sets the deadline.** Microsoft-provided SMS and voice MFA
  retire on 2027-02-01 (2027-07-01 for Global Administrators and external
  users). After that, a user whose only method is a phone gets a blocking
  passkey-registration prompt at sign-in. There is no opt-out for
  enforcement; the exception is a paid telephony provider. Passkeys have
  been on by default since 2026-09-01.
- **Profiles control registration, not sign-in.** A passkey profile decides
  what a person may register, and any profile in scope satisfies. Synced
  passkeys can't be attested, and Microsoft says to treat them like other
  unattested authenticators.
- **Three populations:** admins, who need to know where the key lives;
  office staff, who have assigned PCs and their own phones; and clinicians
  on shared workstations (ADR 0014).
- **Registration is an attack surface.** Whoever can register a method owns
  the account at the next sign-in. An attacker holding a phished password
  and push approval can register their own passkey, and that survives a
  password reset.

## Options considered

1. **One profile: attested device-bound passkeys for everyone.** The
   strongest option. Rejected for staff, and hardware isn't the reason:
   Windows Hello on an assigned PC and an Authenticator passkey on a phone
   are device-bound with no key to issue (verify: attestation for
   Authenticator passkeys under an enforced profile). The reason is
   recovery. A device-bound passkey dies with the phone, and across 5,000
   people every lost or replaced phone becomes a recovery TAP through the
   service desk, the path R14 attacks. A synced passkey survives a new
   phone. For admins the trade goes the other way: few people, issued spare
   keys, and a credential that must stay in Contoso's custody.
2. **One profile that allows synced passkeys for everyone, admins
   included.** The fastest rollout. Rejected: an admin credential would then
   live in a personal iCloud or Google account, unattested and outside
   Contoso's control.
3. **Keep SMS and voice until Microsoft forces the change, or buy a
   telephony provider.** Rejected as the default: the forced prompt lands at
   sign-in, at shift start, with no service-desk plan behind it. It stays
   only as a time-boxed CISO decision for a clinical unit that can't get
   keys in time (the rollout plan's 2026-12-01 decision point).
4. **Two profiles, admin assurance enforced at sign-in, and the
   registration action protected (chosen).**

## Decision

| Population | May register (profile) | Must present at sign-in |
|---|---|---|
| Admins and break-glass | "Contoso - Admins": device-bound only, attestation enforced at registration, optional AAGUID allow-list | The admin strength (CA002, and CA022 for the PAM session broker and admin portals), narrowed to the issued key models by `admin_fido2_allowed_aaguids` |
| Workforce (HR-synced `All-Workforce`) | "Contoso - Workforce": synced or device-bound, unattested | The workforce strength (CA008): pilot group first, all users later behind a second flag |
| Clinicians on shared workstations | Workforce profile, one FIDO2 key each | ADR 0014 |

- **The workforce target is a group, never all users.** All users would put
  break-glass in scope of the synced profile and undo the attested-only
  rule.
- **The workforce rollout refuses to run without the AAGUID list.** The
  Terraform precondition and the script both fail, unless
  `accept_admin_synced_passkey_risk` is set in its own reviewed line.
  Without the list, someone who is both staff and admin could use a synced
  passkey on an admin role.
- **Temporary Access Pass (TAP)** is one-time, 60 minutes by default and up
  to 480 minutes for joiners. It is a bootstrap credential, never a daily
  one, and never issued to break-glass.
- **CA009 protects "register security info"** with a custom strength,
  "Bootstrap and recovery (lab)", modelled on Microsoft's documented
  pattern for the registration action: a one-time TAP or a
  phishing-resistant method (Windows Hello, FIDO2, certificate MFA). The
  built-in MFA strength was rejected for this action because it lets
  password plus push register a passkey, which is the persistence path
  above. It becomes the fallback only if report-only data shows a real gap
  (Windows Hello provisioning, below), and only through a reviewed code
  change: `registration_strength_combinations` refuses phishable
  combinations.
- **The registration wave gets its own TAP channel.** CA009 is enforced
  before phase 2 of the rollout, so every first registration in phases 2–4
  needs a one-time TAP: up to one per person, most of the 5,000-person
  workforce, over a few months.
  - **Chosen:** IAM Engineering issues wave TAPs with
    `07-Passwordless-Rollout.ps1 -IssueTapFor`, one wave list at a time,
    and hands them over in person at a registration session or to the line
    manager. Never by email, text or phone call. The service desk issues
    TAPs only for joiner fallback and recovery, through the identity
    verification runbook.
  - **Rejected: enforce CA009 one wave at a time.** People not yet in a
    wave hold only password and push, so they are the population an
    attacker can register a method for. Per-wave targeting leaves them
    open longest.
  - **Rejected: wave TAPs on request from the service desk.** Thousands of
    calls through the path R14 attacks, which no log can tell apart from
    an attack.
  - BUILT: the issuing script, with offline tests. DESIGNED: the handover
    and the issuer split in the measures below.
- **Exception: the joiner's day-one TAP is emailed to the manager.**
  The rule above ("never by email") covers registration-wave TAPs. The
  joiner Lifecycle Workflow uses Microsoft's built-in task "Generate TAP
  and send email", and that task has one channel only: an email to the
  joiner's manager. A hostile review (2026-11-06, finding C10) pointed out
  that the docs said "never by email" while the running config emails an
  8-hour TAP. We record it here as an accepted exception, with the reason.
  - **Why 480 minutes, not 1-2 hours.** The workflow's trigger is
    `employeeHireDate` with offset 0, and HR sends the date as midnight UTC
    (`Invoke-InboundProvisioning.ps1`, `ConvertTo-HireDate`). The tenant
    schedule runs every 3 hours. So the email can arrive at any time from
    about 00:00 to 03:00 UTC on the start day, hours before the manager
    meets the new hire on the morning shift. A 1-2 hour pass would expire
    unread. 480 minutes is the shortest value that still reaches a day
    shift. It also stays inside the default TAP policy maximum.
  - **What limits the risk.** The pass is one-time use
    (`-TapIsUsableOnce $true`). The manager's mailbox is behind CA001 (MFA).
    CA009 accepts a TAP only to register a stronger method, so the joiner's
    first act is to register a passkey in that session. Every TAP issue and
    use is in the Entra audit log.
  - **What would change it.** If HR sends a real start time (the shift start)
    in `employeeHireDate`, the pass can drop to 2 hours. If Microsoft adds a
    delivery channel other than email, we use it.
  - **Demo note.** The joiner in the demo should register a passkey during
    the TAP session, not skip the prompt.
- **SMS and voice** are turned off by Contoso before Microsoft's date, not
  by the forced prompt. `-DisableSmsVoice` runs only when no in-scope user
  depends on a phone alone (fail closed). Break-glass is always excluded.
- **Microsoft Authenticator push is the bridge, not a fix.** App name and
  location in the push stop fatigue attacks, not adversary-in-the-middle
  phishing: a relayed sign-in produces a real push. Push stays because the
  workforce already has it. One-time codes are turned off because they add
  a second phishable path that can be read out over the phone, with no
  context shown. CA008 closes both.

## Consequences

- **"Admins use device-bound keys" means buying keys.** It is enforced only
  by naming the key models, with attestation on. Without the list it is a
  registration intent. Key logistics (issuing, spares on each unit,
  recovering keys from leavers) are not built.
- **Synced passkeys are accepted for staff.** They are still
  phishing-resistant, and far stronger than SMS, but their protection rests
  on the person's consumer account.
- **CA009 now reaches device setup.** Since 2026-07-06, registration
  policies also govern Windows Hello for Business and macOS Platform SSO
  registration. A password-plus-push user provisioning Windows Hello needs
  a TAP. Measure this in report-only before enforcing.
- **Lab deviation: software passkeys for admins and break-glass
  (2026-11-05).** The lab has no hardware keys, so each lab admin and
  break-glass account holds one passkey made by Chromium's virtual
  authenticator (AAGUID `01020304-0506-0708-0102-030405060708`,
  `notAttested`, device-bound), kept in the operator Mac's Keychain
  (`lab/scripts/demo/signin/passkey.mjs`). Entra accepts it only because the
  tenant still has Microsoft's `all_users` passkey target with the
  unattested Default profile, and any one profile in scope is enough (Learn,
  passkey profiles). That target breaks this ADR's own rule ("never all
  users"; `Set-AuthenticationMethodsPolicy.ps1` reports it as a FAIL for
  break-glass). Two consequences for whoever changes the policy next:
  removing `all_users` should leave these keys usable for sign-in
  (attestation is checked at registration only, the keys are device-bound,
  and the admin profile enforces no AAGUID list - Learn; not yet observed
  in this tenant), but **enforcing an AAGUID allow-list** on the admin
  profile or setting `admin_fido2_allowed_aaguids` without the virtual
  authenticator's AAGUID would block these keys at sign-in too, which
  locks break-glass out (its only method). `Invoke-BreakGlassDrill.ps1`
  preflight fails in that case.
- **Turning on passkey profiles can't be undone,** so the script never does
  it implicitly. verify: Microsoft's limit of three profiles, including the
  default.
- **Guests are out of CA008.** They can meet a strength only through
  inbound MFA trust from their home tenant (phase 5 of the rollout plan).

## How it is measured

Fill in per phase ([passwordless-rollout-plan.md](../passwordless-rollout-plan.md)).

| Measure | Source | Target |
|---|---|---|
| Privileged and PIM-eligible users with an attested device-bound key | `08-Measure-KPIs.ps1` (`phishing_resistant_device_bound_pct`), scoped to admins | 100% before CA002 is enforced |
| Workforce with any phishing-resistant method | `phishing_resistant_pct` | Rises per phase |
| Users whose only method is a phone | `07-Passwordless-Rollout.ps1` | 0 by 2027-01-01 |
| Registrations CA009 would have blocked | Report-only results for the user action | Known and explained before enforcing |
| TAPs issued, split by issuer: rollout, joiner workflow, service desk | Audit logs, joined to `07-Passwordless-Rollout.ps1`'s per-user CSV for each wave | Every rollout TAP is on a wave list and every service-desk TAP has a ticket. Anything else is investigated |

## Revisit trigger

- Authentication strengths can tell synced from device-bound passkeys
  without AAGUIDs. The allow-list then becomes optional.
- Microsoft moves the retirement dates.
- A compromise of a consumer passkey provider affects staff.
- A clinical unit misses the 2026-12-01 decision point.
- CA009 report-only shows Windows Hello provisioning blocked at scale.
- A TAP turns up that is on no wave list and has no ticket.

## Evidence

- `lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`
  and `lab/scripts/powershell/tests/Set-AuthenticationMethodsPolicy.Tests.ps1`
- `lab/scripts/powershell/07-Passwordless-Rollout.ps1` (`-IssueTapFor`)
  and `lab/scripts/powershell/tests/07-Passwordless-Rollout.Tests.ps1`
- `lab/terraform/modules/conditional-access/main.tf` (admin and workforce
  strengths, the precondition, CA008), `baseline.tf` (CA009 and its
  bootstrap strength), `admins.tf` (CA022)
- `lab/terraform/modules/conditional-access/variables.tf`
  (`admin_fido2_allowed_aaguids`, `accept_admin_synced_passkey_risk`)
- `lab/terraform/modules/conditional-access/tests/ca008_phishing_resistant.tftest.hcl`,
  `tests/ca009_ca010_baseline.tftest.hcl`
- `lab/kql/security-info-registered-risky.kql`,
  `lab/kql/auth-method-changed-by-admin.kql`
- `lab/docs/passwordless-rollout-plan.md`

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement-faq
  (dates, blocking prompt, no opt-out)
- https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-passkeys-fido2
  (passkey profiles; synced passkeys can't be attested)
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration
  (registration user action)
- https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-how-it-works
  ("Bootstrap and recovery"; registration in Interrupt mode)
- https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass
