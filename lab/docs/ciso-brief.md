# CISO brief — identity platform (lab scenario)

**Date:** 2026-10-20 · **Audience:** CISO, Contoso Health (the lab's
fictional 5,000-user hospital) · **Ask:** approve licensing, the R01 risk
acceptance, and named owners for the next two quarters.

## The problem

In the scenario, admin rights are granted and never expire, leavers depend on
tickets, clinicians collect access as they move between units, and an
acquired clinic runs a separate Okta tenant. Every one of those is an audit
finding and a path for an attacker. Identity is now the main way in, so it is
also the main control.

## What the platform is built to do

Each line says how far it has got: **BUILT** is code tested offline and
never applied; **RAN · harness** means it also ran end to end on local
stand-ins, with a hashed run record in `lab/evidence/`; **RAN · tenant** means it ran
in the lab tenant, with a row in `lab/evidence/capture-log.csv` (64 merged pull requests since 2026-10-27).

- **HR drives access** (BUILT). A hire, move or termination in HR creates,
  changes or disables the account. A nurse's core clinical access arrives on
  day one from the HR record, with no request, and leaves 72 hours after a
  move. Leavers lose sessions, packages and app access in one run
  (`lab/scripts/powershell/04-Leaver.ps1`).
- **No standing human admins** (BUILT). Two monitored break-glass accounts
  only. Everyone else elevates just in time, with a reason, an approval from
  a named group and, for the most powerful roles, a fresh phishing-resistant
  sign-in. Eligibility itself expires (Tier 0 after 180 days, Tier 1 after
  365).
- **Phishing-resistant sign-in, staged** (BUILT, every policy report-only).
  Admins first, then the workforce, then clinicians unit by unit.
  Registering a new sign-in method will need a one-time pass from the
  service desk or an existing phishing-resistant method, so a stolen
  password can't add an attacker's phone. Device-code sign-in, a current
  phishing route, is blocked once that policy (CA010) is enforced.
- **The service desk can't reset an admin** (BUILT). Its rights cover
  standard workforce accounts only.
- **Access expires, at a cadence set by risk** (BUILT; the review campaign
  RAN · harness on a stand-in). Admin access is reviewed quarterly and removed if
  nobody answers; requested access expires after 180 days; core clinical
  access is never removed because a manager missed a review. Toxic
  combinations, such as nursing plus controlled-substance dispensing, are
  blocked at request and reported if they appear anyway.
- **Every change is reviewed code** (BUILT). Conditional Access and PIM
  change through a pull request and a human gate. The pipeline stores no
  credentials.
- **Tier-0 passwords are vaulted** (RAN · harness on stand-ins). Domain
  admin credentials are checked out by a named person against an approved
  change (two approvers, neither the requester, for the most powerful
  accounts), used in recorded sessions, and rotated when returned. Database logins for
  clinical reporting are issued per request and expire within the hour.
- **Identity attacks are detected and contained** (BUILT; no detection has
  fired). 24 detections cover token theft, MFA tampering, admin changes
  outside the process, the domain controller and the vault. After one
  approval in Teams, a compromised account is signed out; a cloud-only
  account is also disabled. Staff accounts that come from on-premises AD are
  only flagged: until an IAM engineer disables one there and removes its
  sign-in methods (target: 30 minutes), an attacker who registered a method
  of their own can still get back in (R03, open).
- **Evidence on demand** (BUILT). One command exports a hashed,
  control-mapped evidence pack (`Export-EvidencePack.ps1`).

**Where it stands:** built as code and tested offline; the vault, the
session broker, the certification campaign and the database credentials have
also run end to end on local stand-ins. Since 2026-10-28 the controls run in a real Entra tenant: nine of eleven sign-in policies enforced, 2 of 3 human admins on just-in-time access only (E72; the build account is the tracked exception), a leaver removed from AWS in nine minutes, and a nightly drift check against a signed baseline. Measured results are in `lab/evidence/capture-log.csv` (E11b, E30, E52). The 90-day plan in `evidence-capture-plan.md` is now the operating cadence rather than a forecast.

## Cost per capability (Microsoft list prices, before discounts)

| Capability | Licence | List price | Year, 5,000 users | Year, 20,000 users |
|---|---|---|---|---|
| Conditional Access, dynamic groups, HR provisioning | Entra ID P1 | $7 / user / month (verify:) | $420,000 | $1,680,000 |
| PIM, risk-based access: **the extra cost of P2 over P1** | Entra ID P2 (includes P1, $10 / user / month, verify:) | +$3 / user / month | +$180,000 | +$720,000 |
| Access packages, reviews, Lifecycle Workflows | Entra ID Governance add-on | $7 / user / month (verify:) | $420,000 | $1,680,000 |
| Compliant-device access | Intune Plan 1 | $8 / user / month (verify:) | $480,000 | $1,920,000 |
| Conditional Access for workload identities | Workload ID Premium | $3 / workload identity / month (verify:) | per app, not per user | per app, not per user |
| SIEM detections | Microsoft Sentinel | $4.76 / GB analysed, pay-as-you-go, eastus2 (Azure Retail Prices API, read 2026-11-06; verify: what the meter includes) | about $6,700 for sign-in logs (estimate below) | about $27,000 for sign-in logs (estimate below) |
| Enterprise IGA | SailPoint or Saviynt | quote-based | evaluate in Q2 | evaluate in Q2 |
| PAM | Microsoft-native (ADR 0036): Key Vault, Bastion Premium (only while recording), Windows LAPS, Intune EPM, PIM | Bastion Premium $0.45 / hour (eastus2, 2026-11-07), run only while recording; EPM is in the lab's Microsoft 365 E5 SKU (`Intune-EPM` plan) | no PAM vendor licence (verify: Contoso's E5 agreement) | no PAM vendor licence (verify: Contoso's E5 agreement) |

Read the table as an upper bound. P1 and Intune are already included in
Microsoft 365 E3, and P2 in E5 (verify: Contoso's current agreement).
Governance and P2 are needed only for users in scope of those features
(verify: Microsoft licensing guidance on in-scope users). The year columns are
list price × users × 12, not a quote. The P2 row shows only the extra cost
over P1, so the rows can be added up without counting P1 twice.

**How the Sentinel line is estimated.** Measured in the lab workspace
(`loga-idlab`, `Usage` table, 7 days to 2026-11-06): interactive plus
non-interactive sign-in logs were about 0.77 MB per active user per day (14
active users). Non-interactive sign-ins were 82% of that. So 5,000 users make
about 3.9 GB a day (about $18 a day, $6,700 a year) and 20,000 users about
15 GB a day (about $73 a day, $27,000 a year), for sign-in logs alone. Audit,
provisioning and device logs come on top. Moving the non-interactive
sign-ins to a low-cost tier (data lake ingestion $0.05 / GB, same price
source) cuts the sign-in line by about 80%. Read this as an order of
magnitude only: the lab's users are few and mostly scripted, and real
clinicians sign in far more often. A pilot month in production gives the real number. P1 and P2 prices are from Microsoft's
pricing page; some third-party pages still show $6 and $9 (verify: the
effective date; `vendor-evaluation.md` §8).

## Top risks (full list: `risk-register.md`)

| Risk | Residual | What closes it |
|---|---|---|
| R01 Pipeline's APPLY identity can change any directory role: the deploy robot could grant itself admin rights | High | Time-boxed acceptance now; split out a Tier-0-only identity (ADR 0005, option 3) and alert on out-of-pipeline use |
| R03 Token theft and MFA phishing | High until phishing-resistant sign-in is enforced for all staff | The staged passwordless rollout; device-code block and risk-based policies are built and waiting to be enforced; a containment response for AD-sourced staff that an attacker's own method can't pass (not built) |
| R14 Help-desk social engineering | Medium | Built: help-desk scope limited to standard users; registration needs a one-time pass or a phishing-resistant method. The verification ladder remains the real control |
| R09 One domain controller | High if copied to production | At least two DCs per site; production PAM with HA (SaaS PAM POC, `vendor-evaluation.md`). HA and a timed DR drill already ran on a separate stand-in rehearsal cluster with test data; the vault that holds the AD credentials is still one node |

Consent phishing (R04) dropped from High to Medium: the consent lock-down and
its detection are built and wait only for the first tenant run.

## Next two quarters (details: `roadmap.md`)

| Quarter | Delivers | KPI (definition only, no value yet) |
|---|---|---|
| Q1 (days 0–90) | Everything above applied in report-only in a fixed capture order; just-in-time admin with approval and expiry; detections live and each fired once on a test account; policies graduated one at a time; HR feed and birthright for Nursing | Standing privileged principals |
| Q2 (days 90–180) | Phishing-resistant sign-in for admins, IT and office staff; birthright for every clinical department; Okta coexistence; production PAM chosen by POC | Leaver containment time (HR change → disabled and sessions revoked) |

**Decisions needed:** (1) licence tier and scope; (2) accept R01 for Phase 1
with the listed controls while the Tier-0-only pipeline identity is built
(the lab's own acceptance, ADR 0005, does not carry into production);
(3) owners for HR feed, PAM, governance and the Tier-0 approver group;
(4) a non-production tenant for policy rehearsal; (5) whether a
restricted-management unit for VIP accounts is worth taking those accounts
out of reviews and leaver workflows; (6) whether the containment playbook may
hold a directory role to disable accounts, given what that role could do if
the playbook were tampered with (R16).
