# ADR 0014: Shared clinical workstation authentication

- **Status:** Accepted (lab). The Conditional Access (CA) policy, CA060, is now code with mocked tests (`modules/conditional-access/clinical.tf`, behind `enable_shared_clinical_ca`, report-only) and has never been applied. The rest is design only: the lab has no shared workstation, no clinician device and no Autopilot profile.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Nursing stations, workstations on wheels and medication carts are each used
by many clinicians in a shift, with switches many times an hour. Each switch
has to be fast, and the next person must never inherit the last session.

- **HIPAA.** It requires unique user identification (45 CFR
  164.312(a)(2)(i)), so generic shared logins are out. Automatic logoff is
  addressable (164.312(a)(2)(iii)).
- **The authentication direction.** CA008 requires phishing-resistant
  authentication for the workforce. Microsoft made passkeys the default from
  2026-09-01 and retires its own SMS and voice MFA on 2027-02-01
  ([passwordless-rollout-plan.md](../passwordless-rollout-plan.md)).
- **Microsoft's frontline guidance favours portable credentials.** Many
  frontline workers "never need a local credential", and FIDO2 key
  registration on the user's behalf is the preferred onboarding.

## Options considered

1. **A FIDO2 security key per clinician (chosen).**
   - **Security:** portable, device-bound and phishing-resistant. It takes a
     PIN and a touch, with no phone at the bedside.
   - **Supported:** Windows sign-in on Entra-joined devices (Windows 10
     1909+) and hybrid-joined devices (2004+).
   - **Not supported:** devices joined only to on-premises AD DS, and RDP,
     VDI or Citrix sessions except through WebAuthn redirection.
2. **Badge tap through a clinical SSO or fast-user-switching vendor.**
   - **For it:** the fastest switch.
   - **Against it:** a proximity badge reads a static ID that can be cloned.
     The product usually adds a PIN and replays a stored password, which
     keeps passwords alive, and it is one more system that can sign in as any
     clinician.
   - **Only phishing-resistant when** the badge is itself a FIDO2 or
     certificate credential. verify: this differs by product.
3. **A credential tied to one device or one person's phone.**
   - **Windows Hello for Business** is per user, per device, so a clinician
     would enrol on every station. Microsoft's flow makes it an optional
     "local credential" for frontline staff. It suits assigned devices only.
   - **A synced passkey on a personal phone** is Microsoft's preferred
     portable credential where it works. At the bedside it needs personal
     phones, Bluetooth on every station and infection-control clearance. It
     is allowed as a second method only.
4. **A Temporary Access Pass (TAP) every shift.**
   - Microsoft positions TAP, including Windows TAP sign-in, for setup and
     recovery.
   - A daily TAP turns the service desk into a credential factory.

**Entra shared device mode** supports iOS, iPadOS and Android only, so it
doesn't apply to these stations. It does fit the shared phone and tablet
fleet.

## Decision

1. **Key.**
   - **Issue:** one FIDO2 key per clinician. A badge-sized NFC card is
     acceptable.
   - **Registration:** on the clinician's behalf at onboarding, or by the
     clinician with the joiner's TAP. Keys are registered under the
     workforce passkey profile that CA008 accepts.
   - **Lost key:** a one-time 60-minute TAP to register a replacement, under
     [help-desk-identity-verification.md](../runbooks/help-desk-identity-verification.md)
     level V2-C.
2. **Devices.**
   - Entra joined through a dedicated Windows Autopilot deployment profile,
     `CH-SharedClinical`.
   - Security-key sign-in on (`UseSecurityKeyForSignin`).
   - Each clinician signs in to Windows as themselves.
   - The screen locks after 5 minutes idle, and the next clinician uses
     **Switch user**.
3. **CA060.** "Require phishing-resistant strength on shared clinical
   workstations", numbered in the clinical range (CA principles §4).
   - **Users:** clinical groups.
   - **Device filter:** `device.enrollmentProfileName -eq
     "CH-SharedClinical"`. Intune sets this property from the Windows
     Autopilot (or Apple ADE, or Google) enrollment profile, and users can't
     change it; a display name can be renamed, so it isn't used. A station
     enrolled any other way should carry no such profile name (verify), and
     the include filter then silently skips it, so the report-only results
     must list the stations before enforcement. verify: whether Autopilot
     device preparation (v2) sets the property.
   - **Grant:** the CA008 workforce strength.
   - **Session:** sign-in frequency 8 hours (one shift); browser sessions
     never persistent. That control needs All resources, so CA060 targets
     All resources on those devices.
   - **Rollout:** report-only first, then enforced unit by unit with
     Clinical Operations sign-off.
4. **Shared phones and tablets** run in shared device mode.
5. **TAP** is for onboarding and recovery only.

## Consequences

- **Slower switches than tap-and-go.** A switch takes a key, a PIN and a
  Windows sign-in, and the first sign-in on each station builds a profile
  (verify: the time on target hardware). The pilot measures the median
  switch time.
- **Lost keys land on the service desk at shift change.** Runbook level V2-C
  handles them and measures them.
- **The lock stops session reuse, not sign-in frequency.** An 8-hour
  frequency doesn't stop someone using an unlocked session. On Entra-joined
  Windows, unlocking the device refreshes the Primary Refresh Token every
  four hours, and that refresh can satisfy the frequency, so it mostly
  bounds browser and app sessions. The 5-minute lock
  is an Intune setting, not CA. Clinical Operations signs it off as the
  automatic-logoff control.
- **Offline sign-in.** verify: Windows key sign-in while offline is reported
  to fail for a key never used online on that device. EHR downtime
  procedures apply either way.
- **On-premises resources need extra setup.** Hybrid-joined stations can't
  use key sign-in until FIDO2 authentication to on-premises resources
  (Microsoft Entra Kerberos) is set up. Entra-joined stations need the same
  to reach on-premises resources.
- **The EHR's own sign-in** is covered only if the EHR is federated to Entra
  (verify: per EHR).
- **Not built:**
  - the Autopilot profile and the Intune screen-lock setting
  - any shared or clinician device (`modules/intune-vm` is a single-user
    device for CA005)
  - the key-issuing process

  CA060 exists as code only, which means it has never matched a real
  station.

## The EHR on these stations (added 2026-11-07)

- **The EHR is the real target of every switch.** A typical hospital runs
  Epic Hyperspace (or Cerner/Oracle Health) published through Citrix
  Virtual Apps. The clinician signs in to Windows, then to Citrix, then to
  the EHR. The switch time that matters is badge-to-chart, not
  badge-to-desktop.
- **FIDO2 inside Citrix needs WebAuthn redirection** (Option 1 above). Without
  it, the key works for Windows but the EHR session still asks for a
  password. verify: the Citrix Workspace app and VDA versions on target.
- **Why classic badge-tap was rejected.** Most tap-and-go products read a
  proximity badge ID (cloneable), then type a stored password into
  Windows, Citrix and the EHR for the user. That keeps passwords alive for
  every clinician, and the product becomes one more system that can sign
  in as anyone.
- **The realistic target.** A badge that is itself a credential: a FIDO2
  badge, or a smart-card (certificate) badge, used with a clinical SSO
  product (for example Imprivata OneSign with a FIDO2 or PIV badge). Tap to
  lock, tap to sign in, and the EHR's own idle timeout. The decision above
  stays until the 20-second trigger below fires.

## Revisit trigger

- The pilot's median badge-to-chart switch time exceeds 20 seconds, or
  clinicians share sessions to avoid signing in, or keys are left taped to
  carts. Then evaluate a badge vendor whose badge is itself a FIDO2 or
  certificate credential (see "The EHR on these stations").
- Microsoft changes its guidance for shared Windows frontline devices.
- A CA060 failure delays care.

## Evidence

- `lab/terraform/modules/conditional-access/main.tf`: CA008 and the
  workforce strength
- `lab/terraform/modules/conditional-access/clinical.tf`: CA060
- `lab/docs/standards/conditional-access-design-principles.md`: §1 and §4
- `lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`:
  workforce passkey profile, TAP policy
- `lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1`: joiner TAP
- `lab/terraform/modules/intune-vm/`

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-persona-phishing-resistant-passwordless-authentication
  (frontline flow)
- https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows
  (requirements, unsupported scenarios)
- https://learn.microsoft.com/en-us/entra/identity-platform/msal-shared-devices
  (shared device mode platforms)
- https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass
  (TAP use)
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices
  (`enrollmentProfileName` is set by Intune from the Windows Autopilot, Apple
  ADE or Google enrollment profile; a positive operator applies only when
  the device's attribute matches)
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime
  (an unlock refreshes the PRT every four hours, which can satisfy sign-in
  frequency)
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime
  (the persistent browser control requires all cloud apps)
