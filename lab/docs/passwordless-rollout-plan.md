# Passwordless rollout plan: persona phases (lab scenario)

**Status:** Proposed · **Date:** 2026-10-20 · **Scope:** Contoso Health, the
lab's fictional 5,000-user hospital. Nothing below has run. No tenant exists,
so every KPI is a definition, with values to fill in after each phase.

## Microsoft's dates set the deadline

From Microsoft Learn's SMS and voice retirement FAQ (public cloud; checked
2026-10-21):

- **Passkeys by default from 2026-09-01:** users enabled for SMS or voice
  are enabled for passkeys, and the registration campaign nudges them.
- **2027-02-01:** Microsoft-provided SMS and voice MFA retire for every
  user except Global Administrators and external users, who follow on
  **2027-07-01** (internal guests keep the February date). A user whose
  only method is SMS or voice must register a passkey at sign-in, with no
  opt-out for enforcement.
- **The paid exception:** a telephony provider contracted through Microsoft
  Security Store keeps SMS and voice; its configuration opens 2026-10-30.

**Decision.**
- **A forced sign-in prompt doesn't do the rollout.** Phases 1–3 finish
  before 2027-01-01.
- **Clinicians get keys before the deadline.** Phase 4 has a decision point
  on 2026-12-01 for any unit that can't make it: a time-boxed telephony
  bridge for its phone-only clinicians (CISO decision), or the blocking
  prompt.
- **The tenant doesn't opt out** of the automatic passkey enablement; the
  registration campaign is set explicitly by script.
- **How it's built:** the two passkey profiles, CA009's protected
  registration and the TAP registration wave are
  [ADR 0016](adr/0016-passkey-profiles-and-phone-method-retirement.md); the
  CA policies are listed in the
  [CA design principles](standards/conditional-access-design-principles.md) §1;
  shared clinical stations are
  [ADR 0014](adr/0014-shared-clinical-workstation-authentication.md).
  `07-Passwordless-Rollout.ps1` sorts each wave into phishing-resistant,
  phishable MFA only, phone only and nothing, issues the wave's TAPs and
  returns the CA008 READY or NOT READY verdict. Graduation follows
  [graduate-a-ca-policy.md](runbooks/graduate-a-ca-policy.md).

## Phases

| Phase | Method | Entry criteria | Exit criteria | KPI (one) | CA state | Rollback |
|---|---|---|---|---|---|---|
| **1 · Admins** (privileged roles and everyone PIM-eligible: the cloud-only `adm-` accounts in `Admin-Accounts`, plus the build account) | Two attested, device-bound security keys each, issued in person (help-desk runbook V3). Break-glass keys go through their own custody ceremony | `Set-AuthenticationMethodsPolicy.ps1 -Apply` for admins passes its break-glass checks. CA009 in report-only, so each key registration is measured against the bootstrap strength. `01-Verify-Baseline.ps1` check [7/7] reports admin passkey coverage (the build account and every Tier-0 or Global Administrator eligible) | Every in-scope admin has two attested keys; CA002 enforced for 14 days with no admin lockout; then CA021 enforced, so a Tier-0 activation needs one of those keys | % of privileged and PIM-eligible users with an attested device-bound key. Target 100% | CA002: report-only → enforced | CA002 back to report-only in a one-line PR. Break-glass is excluded throughout |
| **2 · IT staff** (non-admin accounts) | Security key or Authenticator passkey. Windows Hello for Business on assigned devices | Phase 1 exit. Workforce profile and campaign scoped to IT (`-IncludeStaffRollout -StaffGroupMailNicknames <IT group>`). CA008 measuring in report-only for all users | `07-Passwordless-Rollout.ps1` returns READY for IT; IT in the enforced CA008 pilot for 14 days with no unresolved block | % of IT sign-ins that met the phishing-resistant strength over 14 days. Target ≥ 98% | CA008: `ca008_scope = "pilot"`, enforced; IT group nested in the pilot group | Remove the IT group from the pilot group. That changes membership only, not the policy |
| **3 · Office staff** (finance, HR, revenue cycle; assigned devices) | Windows Hello for Business on the assigned PC, plus a synced or Authenticator passkey as the portable method | Phase 2 exit. Help-desk verification runbook in force. Staff communications sent | No phone-only users left; ≥ 95% phishing-resistant | Users whose only MFA method is SMS or voice. Target 0 by 2027-01-01 | CA008 pilot, widened by adding department wave groups | Remove the wave group |
| **4 · Clinicians** (shared workstations, [ADR 0014](adr/0014-shared-clinical-workstation-authentication.md)) | One FIDO2 key per clinician | Clinical Operations sign-off per unit. Keys plus spares on the unit. CA060 in report-only for 14 days, covering nights and a weekend. Downtime procedure confirmed. Service desk staffed on every shift in go-live week | Per unit: 14 days enforced, no care delay attributed to sign-in, ≥ 98% of the unit's clinicians holding a key | Shared-workstation sign-in failure rate: CA failures ÷ sign-ins from `CH-SharedClinical` devices. Target < 0.5% | CA060 (BUILT, report-only): enforced one unit at a time. CA008 pilot waves by unit | Remove the unit's wave group (minutes). CA060 back to report-only. On-shift recovery through help-desk level V2-C |
| **5 · Contractors and guests** | Contractors with member accounts follow the phase of their role; agency nurses are phase 4. Guests can meet a strength only through MFA from their home tenant, which needs inbound trust in cross-tenant access settings | B2B governance on (`enable_b2b_governance`). Inbound MFA trust configured per connected organization. verify: Microsoft's B2B passkey support, planned by the end of 2026 | Every connected organization either trusted for MFA or covered by an enforced guest policy | % of guest sign-ins meeting MFA through home-tenant trust or a phishing-resistant method | A new guest policy in the 080–099 range: report-only → enforced. CA008 excludes guests by design | Guest policy back to report-only |

## Rules across phases

- **Break-glass** is excluded from every CA policy, and from TAP, the
  campaign, SMS and voice. Its keys are attested and held in custody.
- **TAP** is one-time, 60 minutes from the service desk and 480 minutes for
  joiners. It is never a daily credential.
- **SMS and voice** are turned off only by `-DisableSmsVoice`. That runs
  after `07-Passwordless-Rollout.ps1` reports zero phone-only users in scope.
- **Phases are sequential.** A phase starts only when the previous phase's
  KPI has a measured value (`roadmap.md`, sequencing rules).
- **Registration is gated before the rollout widens.** CA009 is enforced
  (evidence capture E38b) before phase 2 starts, so every method registered
  from then on was registered with a one-time TAP or an existing
  phishing-resistant method. `security-info-registered-risky.kql` watches
  the same moment from the log side.

## Not built

- **The shared-workstation Autopilot profile** `CH-SharedClinical` and the
  5-minute screen lock (ADR 0014). CA060 matches only devices enrolled
  through that profile, so until it exists the policy applies to nothing.
- **The guest policy** (phase 5).
- **Key logistics:** procurement, unit stock, and recovery of keys from
  leavers.
