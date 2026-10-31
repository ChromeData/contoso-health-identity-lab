# Passwordless rollout plan: persona phases (lab scenario)

**Status:** Proposed · **Date:** 2026-10-20 · **Scope:** Contoso Health, the
lab's fictional 5,000-user hospital. The tenant exists (2026-10-27) but no passkey is
registered yet (E11b: 0% phishing-resistant), so every KPI is a definition, with values to fill in after each phase.

## Microsoft's dates set the deadline

Checked on Microsoft Learn on 2026-10-20 (FAQ updated 2026-09-23). These
dates apply to the public cloud only.

- **Passkeys by default, from 2026-09-01.** Users enabled for SMS or voice
  are automatically enabled for passkeys. The registration campaign moves to
  a Microsoft-managed state and nudges them after MFA.
- **2027-02-01.** Microsoft-provided SMS and voice MFA retire for every user
  except Global Administrators and external users. Those two groups retire
  on **2027-07-01**; internal guests keep the February date. A user whose
  only method is SMS or voice must register a passkey at sign-in before
  continuing. There is no opt-out for enforcement.
- **The paid exception.** Contracting a telephony provider through
  Microsoft Security Store keeps SMS and voice. Configuration is available
  from 2026-10-30.

**Decision.**
- **Contoso doesn't let a forced sign-in prompt do the rollout.** Phases 1–3
  finish before 2027-01-01.
- **Clinicians get keys before the deadline.** Phase 4 has a decision point
  on 2026-12-01, for any unit that can't make it: buy a telephony-provider
  bridge for its phone-only clinicians (CISO decision, time-boxed), or
  accept the blocking prompt.
- **The tenant does not opt out** of the automatic passkey enablement
  (`passkeyDynamicMigration`). The registration campaign is set explicitly by
  script.
- verify, at the first apply: the passkey and campaign state a tenant
  created after 2026-09-01 starts with. The script's PLAN mode prints it.

Sources:
https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement-faq,
https://www.microsoft.com/en-us/security/blog/2026/07/13/microsoft-entra-id-security-updates-passkeys-are-the-default-authentication-method-in-entra-id/

## Tools

- **`lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`**
  sets the authentication methods policy:
  - two passkey profiles:
    - **admins:** device-bound, attested, with an optional AAGUID allow-list.
      Its target (and the registration campaign's) is the `Admin-Accounts`
      group: standing, role-assignable, holding no role, and never a PIM
      group. Its members are the cloud-only `adm-` accounts
      (`New-AdminAccounts.ps1`) and the build account
      (`Set-AuthenticationMethodsPolicy.ps1 -BuildAccountUpn`)
    - **workforce:** synced or device-bound, unattested
  - **What is actually ENFORCED at sign-in.** The profiles control what a
    person may REGISTER. Whether an admin sign-in demands a device-bound,
    attested key is decided by the authentication strength CA002 / CA021 / CA022
    grant with, and the only lever there is the FIDO2 AAGUID allow-list
    (`admin_fido2_allowed_aaguids`, attestation enforced in the Passkey
    policy). That means naming - in practice buying - the issued key models.
    With an empty list, "admins use device-bound keys" is a registration
    intent only: an admin who is also in All-Workforce could sign in to an
    admin role with a synced passkey. So the workforce rollout refuses to run
    without the list (Terraform precondition, and a FAIL in
    `Set-AuthenticationMethodsPolicy.ps1`) unless the risk acceptance
    (`accept_admin_synced_passkey_risk`) is recorded. verify: whether
    authentication strengths can now tell synced from device-bound passkeys
    without AAGUIDs.
  - TAP: 60-minute default, 480-minute maximum, one-time use
  - the registration campaign
  - SMS and voice disablement, refused while any in-scope user still depends
    on a phone alone
- **`lab/scripts/powershell/07-Passwordless-Rollout.ps1`** runs with
  `-Stage Pilot|Broad`. It sorts users into four groups:
  - phishing-resistant
  - phishable MFA only
  - phone only
  - nothing

  It also issues TAPs and returns the CA008 READY or NOT READY verdict.
- **CA policies** (all in `modules/conditional-access`; the applied ones are
  report-only until passkeys exist, the rest still behind staging flags).
  - **CA002** requires phishing-resistant MFA for admins: Microsoft's
    template list of admin roles plus the lab's tier groups, because
    role assignments scoped to an administrative unit are invisible to the
    role condition.
  - **CA008** applies the workforce strength. It is enforced through its
    pilot group first. Enforcing it for all users takes a second, separate
    flag, `ca008_allow_all_users_enforcement`.
  - **CA009** protects the "Register security information" user action
    with a custom strength, "Bootstrap and recovery (lab)", modelled on
    Microsoft's guidance for securing registration: a **one-time** TAP or a
    phishing-resistant method (`enable_registration_ca`). A stolen password
    plus SMS can't add a method. Guests are excluded (TAP doesn't work for
    them). The choice of this strength over Microsoft's built-in MFA
    strength, which would let password plus push register a passkey, is
    [ADR 0016](adr/0016-passkey-profiles-and-phone-method-retirement.md). Since 2026-07-06, Microsoft Learn says
    registration policies also cover Windows Hello for Business and macOS
    Platform SSO registration, so a password-and-push user setting up
    Windows Hello needs a TAP: measure that in report-only before enforcing.
  - **CA010** blocks device code flow for all users
    (`enable_device_code_block`), with an exception group for devices that
    genuinely need it.
  - **CA060** applies the workforce strength on shared clinical
    workstations (ADR 0014), with sign-in every 8 hours and no persistent
    browser session (`enable_shared_clinical_ca`).
- **Graduation** follows
  [runbooks/graduate-a-ca-policy.md](runbooks/graduate-a-ca-policy.md): at
  least 14 days in report-only, covering nights and a weekend, and one state
  change per PR.

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

## The registration wave: who issues the TAPs

Enforcing CA009 first has a cost. From then on, everyone still on password
plus push needs a one-time TAP for their first passkey or Windows Hello
registration: most of phases 2–4, up to roughly 5,000 people less the
admins and anyone already holding a phishing-resistant method. A help-desk
TAP is exactly what a social engineer asks for (R14), so the issuing has to
be designed, not improvised.

| Option | For | Against |
|---|---|---|
| **Chosen: enforce CA009 first, issue TAPs in planned batches** | No window in which a stolen password plus push can add a method | Thousands of TAPs; each one is a credential to deliver safely |
| Enforce CA009 per wave, after the wave has registered | No TAPs for most users | During each wave, password plus push can still register a method (the R14 path). CA009 is one all-users policy in code, so per-wave enforcement would also need a scope change |
| Built-in MFA strength on registration | No TAPs at all | Password plus push can register a passkey, so CA009 would stop a password-only attacker and nothing more (ADR 0016) |

How the batches run:

- **Volume first.** `07-Passwordless-Rollout.ps1` sorts each wave's group
  before it starts; its "phishable MFA only", "phone only" and "nothing"
  counts are the number of TAPs that wave needs (fill after running).
- **Channel.** Batch TAPs are issued with `07-Passwordless-Rollout.ps1
  -IssueTapFor <wave list>` (one-time, 480 minutes) and handed over in
  person at the wave's registration session, or to the line manager, who
  hands them over in person. Never by phone, chat or email to the user. A
  person who misses the session goes through the help-desk verification
  ladder like any other caller.
- **Every TAP is explainable.** A TAP counts as explained only if it
  matches the joiner workflow, a wave batch (the script's output, filed
  with that wave's change ticket) or a service-desk ticket. The measure is the
  number of unexplained TAPs per week, target 0; each one is investigated as
  a possible R14 case. `auth-method-changed-by-admin.kql` sees the issuing
  side.

## Built since the first draft

CA009 (register security info), CA010 (block device code flow) and CA060
(shared clinical workstations) were "not built" in the first version of this
plan. They are now code, report-only, and untested against a tenant. Their
first captures are E20, E20b, E28b, E38b and E50b in
`evidence-capture-plan.md`.

## Not built

- **The shared-workstation Autopilot profile** `CH-SharedClinical` and the
  5-minute screen lock (ADR 0014). CA060 matches only devices enrolled
  through that profile, so until it exists the policy applies to nothing.
- **The guest policy** (phase 5).
- **Key logistics:** procurement, unit stock, and recovery of keys from
  leavers.
