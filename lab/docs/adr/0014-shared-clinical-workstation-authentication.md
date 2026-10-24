# ADR 0014: Shared clinical workstation authentication

- **Status:** Accepted (lab). BUILT: CA060 in code with mocked tests (`modules/conditional-access/clinical.tf`, behind `enable_shared_clinical_ca`, report-only), never applied. DESIGNED: the rest; the lab has no shared workstation, clinician device or Autopilot profile.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Nursing stations, workstations on wheels and medication carts are each used
by many clinicians in a shift, with switches many times an hour. Each switch
has to be fast, and the next person must never inherit the last session.

- **HIPAA** requires unique user identification (45 CFR 164.312(a)(2)(i)),
  so generic shared logins are out. Automatic logoff is addressable
  (164.312(a)(2)(iii)).
- **The authentication direction:** CA008 requires phishing-resistant
  authentication for the workforce; Microsoft made passkeys the default from
  2026-09-01 and retires its own SMS and voice MFA on 2027-02-01.
- **Microsoft's frontline guidance favours portable credentials:** FIDO2 key
  registration on the user's behalf is the preferred onboarding.

## Options considered

1. **A FIDO2 security key per clinician (chosen).** Portable, device-bound,
   phishing-resistant: a PIN and a touch, no phone at the bedside. Supported
   for Windows sign-in on Entra-joined and hybrid-joined devices; not on
   devices joined only to AD DS, or in RDP, VDI or Citrix sessions except
   through WebAuthn redirection.
2. **Badge tap through a clinical SSO vendor.** The fastest switch, but a
   proximity badge reads a static ID that can be cloned, the product usually
   replays a stored password, and it is one more system that can sign in as
   any clinician. Phishing-resistant only when the badge is itself a FIDO2
   or certificate credential.
3. **A credential tied to one device or one phone.** Windows Hello for
   Business is per user per device, so a clinician would enrol on every
   station. A synced passkey on a personal phone needs personal phones,
   Bluetooth on every station and infection-control clearance at the
   bedside. Allowed as a second method only.
4. **A Temporary Access Pass every shift.** TAP is for setup and recovery;
   a daily TAP turns the service desk into a credential factory.

Entra shared device mode supports iOS, iPadOS and Android only, so it fits
the shared phone and tablet fleet, not these stations.

## Decision

1. **Key.** One FIDO2 key per clinician (a badge-sized NFC card is fine),
   registered at onboarding on the clinician's behalf or with the joiner's
   TAP, under the workforce passkey profile CA008 accepts. A lost key gets a
   one-time 60-minute TAP under help-desk level V2-C.
2. **Devices.** Entra joined through a dedicated Autopilot profile,
   `CH-SharedClinical`; security-key sign-in on; each clinician signs in as
   themselves; the screen locks after 5 minutes idle and the next clinician
   uses Switch user.
3. **CA060**, "Require phishing-resistant strength on shared clinical
   workstations": clinical groups; device filter
   `device.enrollmentProfileName -eq "CH-SharedClinical"` (set by Intune from
   the enrollment profile, not changeable by users, unlike a display name);
   grant the CA008 workforce strength; sign-in frequency 8 hours, browser
   sessions never persistent, so it targets all resources on those devices.
   Report-only first, then enforced unit by unit with Clinical Operations
   sign-off.
4. **Shared phones and tablets** run in shared device mode.
5. **TAP** is for onboarding and recovery only.

## Consequences

- **Slower switches than tap-and-go:** a key, a PIN and a Windows sign-in,
  and the first sign-in on each station builds a profile. The pilot measures
  the median switch time.
- **Lost keys land on the service desk at shift change;** level V2-C handles
  and measures them.
- **The lock stops session reuse, not sign-in frequency.** Unlocking an
  Entra-joined device refreshes the Primary Refresh Token every four hours,
  which can satisfy the frequency, so it mostly bounds browser and app
  sessions. The 5-minute lock is an Intune setting that Clinical Operations
  signs off as the automatic-logoff control.
- **A station enrolled any other way carries no profile name and is silently
  skipped,** so the report-only results must list every station in scope
  before enforcement.
- **On-premises resources** need Microsoft Entra Kerberos for key sign-in;
  the EHR's own sign-in is covered only if the EHR is federated to Entra.
- **Not built:** the Autopilot profile and screen-lock setting, any shared or
  clinician device, and the key-issuing process. CA060 has never matched a
  real station.

## Revisit trigger

- The pilot's median switch time exceeds 20 seconds, or clinicians share
  sessions to avoid signing in: evaluate a badge that is itself a FIDO2 or
  certificate credential.
- Microsoft changes its guidance for shared Windows frontline devices.
- A CA060 failure delays care.

## Evidence

- `lab/terraform/modules/conditional-access/main.tf` (CA008, workforce
  strength), `clinical.tf` (CA060),
  `tests/ca060_clinical.tftest.hcl`
- [`standards/conditional-access-design-principles.md`](../standards/conditional-access-design-principles.md)
  §1, §4
- `lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`,
  `New-LifecycleWorkflows.ps1` (joiner TAP); `lab/terraform/modules/intune-vm/`

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-persona-phishing-resistant-passwordless-authentication
- https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows
- https://learn.microsoft.com/en-us/entra/identity-platform/msal-shared-devices
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime
