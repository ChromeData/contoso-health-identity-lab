# CISO brief — identity platform (lab scenario)

**Date:** 2026-10-20 · **Audience:** CISO, Contoso Health (the lab's
fictional 5,000-user hospital) · **Ask:** approve licensing, the R01 risk
acceptance, and named owners for the next two quarters.

## The problem

Admin rights are granted and never expire, leavers depend on tickets,
clinicians collect access as they move between units, and an acquired
clinic runs a separate Okta tenant. Each is an audit finding and a path for
an attacker. Identity is now the main way in, so it is also the main
control. The constraint: **a nurse must never be locked out of patient care
by an identity control.**

## What is built

Code tested offline (**BUILT**); the vault, session broker, certification
campaign and database credentials have also run end to end on local
stand-ins (**RAN · harness**). Nothing has run in a tenant, so no control
has operated in production and no metrics exist yet.

- **HR drives access.** A nurse's core clinical access arrives on day one
  from the HR record, and leaves 72 hours after a move; leavers lose
  sessions and access in one run.
- **No standing human admins.** Everyone elevates just in time, with a
  reason, an approver group and, for the most powerful roles, a fresh
  phishing-resistant sign-in; eligibility itself expires.
- **Phishing-resistant sign-in, staged** (every policy report-only first):
  admins, then the workforce, then clinicians unit by unit, with
  registration protected so a stolen password can't add an attacker's
  phone.
- **Access expires at a cadence set by risk,** and core clinical access is
  never removed because a manager missed a review.
- **Tier-0 passwords are vaulted:** checked out by a named person against an
  approved change (two approvers for the most powerful accounts), used in
  recorded sessions, rotated on return.
- **Identity attacks are detected and contained** after one approval in
  Teams. Staff accounts that come from on-premises AD are only flagged until
  an engineer disables them there (R03, open).

## Cost

Microsoft list prices, before discounts, are in
[`vendor-evaluation.md`](vendor-evaluation.md) §8: P1 and P2 come with M365
E5; the ID Governance step-up is the main new Microsoft cost (ceiling
$420,000 a year at list for 5,000 users, before the step-up quote).
Enterprise PAM is quote-based and chosen by POC in Q2.

## Top risks (full list: [`risk-register.md`](risk-register.md))

| Risk | Residual | What closes it |
|---|---|---|
| R01 The pipeline's APPLY identity can change any directory role | High | Time-boxed acceptance now; a Tier-0-only pipeline identity and an out-of-pipeline alert |
| R03 Token theft and MFA phishing | High until phishing-resistant sign-in is enforced for all staff | The staged rollout; a containment response for AD-sourced staff that an attacker's own method can't pass (not built) |
| R14 Help-desk social engineering | Medium | Help desk limited to standard users; registration needs a one-time pass; the verification ladder |
| R09 One domain controller | High if copied to production | Two DCs per site; production PAM with HA (HA and a timed DR drill already ran on a stand-in rehearsal cluster) |

## Next two quarters (details: [`roadmap.md`](roadmap.md))

| Quarter | Delivers | KPI (defined, not yet measured) |
|---|---|---|
| Q1 (days 0–90) | Everything applied report-only in a fixed capture order; just-in-time admin; detections live and each fired once on a test account; policies graduated one at a time; HR feed and birthright for Nursing | Standing privileged principals |
| Q2 (days 90–180) | Phishing-resistant sign-in for admins, IT and office staff; birthright for every clinical department; Okta coexistence; production PAM chosen by POC | Leaver containment time |

## Decisions needed

1. Licence tier and scope.
2. Accept R01 for Phase 1 while the Tier-0-only pipeline identity is built
   (the lab's own acceptance, ADR 0005, doesn't carry into production).
3. Owners for the HR feed, PAM, governance and the Tier-0 approver group.
4. A non-production tenant for policy rehearsal.
5. Whether a restricted-management unit for VIP accounts is worth taking
   them out of reviews and leaver workflows.
6. Whether the containment playbook may hold a directory role to disable
   accounts, given what that role could do if the playbook were tampered
   with (R16).
