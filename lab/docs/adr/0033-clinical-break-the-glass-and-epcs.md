# ADR 0033: Clinical break-the-glass and EPCS

- **Status:** DESIGNED. The lab has no EHR, so nothing here is built or run.
- **Date:** 2026-11-07
- **Risk owner:** Privacy Officer (break-the-glass); Pharmacy and the identity platform owner (EPCS)
- **Next review:** 2027-02-07
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

Two words, two meanings:

- **Admin break-glass** (ADR 0003) is emergency access for IT, when
  normal admin sign-in fails.
- **Clinical break-the-glass (BTG)** is emergency access to a patient
  record that the clinician is not normally allowed to open. Examples: a
  VIP, a staff member who is also a patient, or a restricted chart. The
  EHR (for example Epic) asks for a reason, then opens the chart and logs
  the access.

## Part 1: clinical break-the-glass

### Decision

1. **Every BTG event goes to Sentinel.** The EHR's audit log (for Epic,
   the access log of BTG events; verify: per EHR) is sent through syslog
   or a file export into a custom table `EhrBtg_CL`: user, patient
   record class (VIP, employee, restricted), reason, time, workstation.
2. **The Privacy Office reviews every BTG within 24 hours.** A ServiceNow
   task is created for each event. The reviewer marks it *justified* or
   *not justified*. A *not justified* result goes to HR and Compliance.
3. **Detections:**
   - BTG volume per clinician: more than 3 in a shift, or more than three
     times that clinician's 30-day average.
   - Any BTG on a record of class VIP or employee: High, to the Privacy
     Office at once.
   - A BTG by a user whose own HR record shares a surname or address with
     the patient (a family member). verify: which fields the EHR exports.
4. **Identity side:** the clinician must sign in with their own named
   account (ADR 0014). A shared or generic account makes BTG review
   impossible.

### Consequences

- The Privacy Office needs staff time each day. Volume in a 5,000-user
  hospital is usually tens of events a week, not hundreds. Measure it in
  the first month.
- BTG must never be blocked. The control is review after the fact, because
  a blocked chart can harm a patient.

## Part 2: EPCS (electronic prescribing of controlled substances)

DEA rules (21 CFR Part 1311) set the identity controls for e-prescribing
controlled substances. The lab's Pharmacy story (SoD rule SOD-01) leads
straight to them.

### What the rule requires (summary)

- **Identity proofing** of each prescriber before they get a credential
  (1311.105; 1311.110 for institutional practitioners such as a hospital,
  which may proof its own staff in person). verify: eCFR text.
- **Two-factor authentication** to sign each controlled-substance
  prescription: two of something you know, a hard token, and a biometric
  (1311.115). A hard token must be a separate device that meets FIPS 140
  Level 1 or higher. verify: eCFR text.
- **Logical access control with two people:** at least two named people
  manage who may sign. One enters the grant, and a second person, a DEA
  registrant using their own two-factor credential, confirms it (1311.125
  for individual practitioners; 1311.130 for institutional practitioners).

### Decision

1. **The EPCS application** (the EHR's prescribing module, or a separate
   EPCS app) is federated to Entra.
2. **Conditional Access CA062 "EPCS signing"** targets the EPCS app (or an
   authentication context the EHR calls at signing time):
   - grant: an authentication strength of **FIDO2 security key or
     certificate-based authentication (multifactor)** only. A FIDO2 key is
     the hard token, and its PIN is the knowledge factor;
   - sign-in frequency: every time (each signing prompts again).
   verify: whether the EHR can request an Entra authentication context
   per prescription, or only at sign-in.
3. **Proofing:** credentialing staff check government photo ID in person
   before the key is issued. The check is recorded in the HR record. TAP
   for key registration is issued only after that check.
4. **Two-person grant:** prescribing rights come from an access package
   `Pharmacy - EPCS Prescribers` with two approval stages: first the
   Medical Staff Office, then a DEA-registrant physician approver. Each
   approver signs in with phishing-resistant MFA. Nobody can approve their
   own request.
5. **Review:** a quarterly access review of the package, reviewer the
   Chief Pharmacist. No response means removed (ADR 0012, tier T1 rules).

### Consequences

- The DEA rule also requires the EPCS application itself to be audited or
  certified. That is the vendor's job, not the identity team's.
- A lost key stops a prescriber from signing until a new key is issued.
  The service desk process (help-desk-identity-verification.md, level
  V2-C) applies.

## Revisit trigger

- The hospital chooses an EHR, and its BTG export and step-up options are
  known.
- DEA changes Part 1311.
