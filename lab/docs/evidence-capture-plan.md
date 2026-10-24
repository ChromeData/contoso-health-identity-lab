# Evidence capture plan: the 30-day E5 + Entra ID Governance window

> **Status: plan only. No E-numbered capture has run.** No tenant exists
> yet. Nothing here is evidence until the capture log has a row with a real
> UTC time and a SHA-256. What has run locally (the harness records, which
> prove the stand-ins, not the tenant) is indexed in
> [`lab/evidence/README.md`](../evidence/README.md).

## Why this plan exists

The trials are the scarce resource: 30 days of Microsoft 365 E5 (Entra ID
P2, Intune, Defender), 30 days of Entra ID Governance and 31 days of
Sentinel. All the code is written and tested offline before Day 0, so the
window is spent **capturing evidence, not coding**. The order is fixed in
advance because captures depend on each other: sign-in data before
Sentinel, report-only data before any graduation, and CA021 enforced before
PIM is switched to `c1`. The day-by-day schedule (the clocks, the order the
staging flags flip in, and exactly what each capture must show) is an
operator document kept outside this repository; the IDs below are its
public index.

**The trial breaks the 14-day report-only rule, on the record.** A 30-day
trial can't hold 14 days of report-only data and still capture the
graduations, so E30–E38b graduate after 5 to 11 days. That deviation is
exception E9 ([exception-process.md](standards/exception-process.md)), filed
before E30 with the E28 counts attached, and each graduation PR states its
real number of report-only days. Outside the trial the 14-day rule holds.

## Capture rules

1. **Capture it when it happens, once.** Never re-stage a screenshot after
   the event. A missed capture is logged `missed`; a later real re-run gets
   a new ID marked `re-run of Exx`.
2. **Every capture gets a log row** in `lab/evidence/capture-log.csv`
   (`id,utc,what,sha256,stored_at,public,operator`), created at the first
   capture and kept public-safe: no tenant identifiers.
3. **Originals are private.** The read-only captures that
   `Invoke-LabDay.ps1` takes go to `lab/evidence/tenant/<UTC day>/<id>/raw/`
   (kept out of git by a `.gitignore`), with a public-safe `manifest.json`
   and `SHA256SUMS` beside it. Screenshots and anything taken by hand go to
   the gitignored `lab/evidence/out/captures/<id>/`. Both are uploaded the
   same day to the WORM store, `captures/<id>/`, with overwrite off.
4. **Hash before anything else touches the file.** For a public copy, redact
   a *copy* (tenant ID, domain, object IDs, IPs, real UPNs) and hash that
   too. Never edit an original.
5. **Screenshots show when and where:** the portal breadcrumb and a
   timestamp, recorded in UTC.
6. **Report-only is reported as report-only.** "Would have blocked" is never
   described as "blocked", and thresholds are never lowered to get a
   screenshot. If CA007 (sign-in risk **High**) doesn't fire because the
   simulated risk scored Medium, that is the result, and it is recorded.
7. **Stand-ins are named** in the capture note, as in
   [`STAND-INS.md`](STAND-INS.md).
8. **Test accounts only** for attack simulations (Tor, failed sign-ins,
   confirmCompromised, legacy auth, Kerberoasting, DCSync). Never the
   operator's or a break-glass account.

## Coverage index

Every capture ID, by what it proves. "Day" counts from the day both trials
are activated; P1–P5 are the days before it.

| What it proves | Captures | Days |
|---|---|---|
| Pipeline trust (OIDC plan and apply, the wrong-subject deny) and the WORM evidence store (delete refused, overwrite versioned) | E01–E07 | P1–P3 |
| Licenses, sign-ins flowing, ScubaGear and Zero Trust baseline, KPI baseline, a report-only checkpoint | E08, E09, E10, E11, E14 | 0–2 |
| CA001–CA010 and CA020 applied report-only, break-glass excluded from every policy | E12, E13 | 1 |
| SIEM telemetry and detections enabled as their tables fill | E15a, E15, E15b, E15c | 1–5 |
| PIM: tier groups, approver groups, expiry, no permanent active, notifications, Global Administrator direct eligibility, help-desk AU, the first activation and its alert, CA020 and CA021 report-only, PIM for Azure resources | E16, E16a, E16b, E16c, E17, E17b, E17c, E18, E34 | 2–8 |
| Governance: packages and review tiers, birthright by automatic assignment, SoD links, the HR joiner, registration gated by CA009 | E19, E20, E20b | 3 |
| Authentication methods, consent and app management policies | E21 | 3–4 |
| SSO and SCIM to AWS, the Clinical Portal OIDC app | E22, E23, E24, E25 | 4 |
| Risk-based access, report-only then enforced, with the risk level each simulation actually got | E26, E27, E37, E38 | 5–12 |
| CA report-only insights, the device-code check, the passwordless pilot verdict | E28, E28b, E29 | 6 |
| Graduations, one policy per PR, then the PIM switch to `c1` | E30, E31, E35, E36, E36b, E38b | 7–12 |
| Access reviews, B2B, review KPIs, SoD preventive and detective | E32, E33, E39, E39b, E39c | 8–13 |
| Approval-gated containment, with incident-to-contained minutes | E40, E41 | 13–14 |
| Detections fired once on test accounts (22 rules) | E18, E27, E28b, E31, E39c, E42, E43, E44, E45, E45b, E46, E46b, E46c, E47, E48, E49, E51, E51b, E51c, E51f; E36b expected quiet | 2–17 |
| Break-glass drill: four sign-ins, four alerts, rows in `lab/evidence/drills/` | E49 | 16 |
| Compliant device (CA005) and shared clinical workstations (CA060, or "not exercised", stated) | E50, E50b | 17 |
| PAM on DC01 (discovery to reconciliation, ticket-gated Entra sign-in, RDP recording) and the AD plane (Kerberoast, privileged-group add, DCSync, AD assessment) | E51, E51a, E51b, E51c, E51f | 17 |
| CA restore drill, token protection pilot (CA011), protected actions (CA023 + `c2`) | E51d, E51e, E51g | 18 |
| Mover and leaver with HR-to-disable minutes, NHI inventory and shadow admins, Agent ID (E53b), midPoint reads Entra (E53c, optional) | E52, E53, E53b, E53c | 18–19 |
| KPIs after vs. baseline, ScubaGear and Zero Trust after, the hashed evidence pack, close-out and the WORM lock decision, post-trial PRs | E54, E55, E56, E57, E58 | 25–29 |

Days 20–24 are a buffer for re-takes; each re-take is a new live run with a
new ID.

## Where everything lives

| What | Public (committed) | Private |
|---|---|---|
| Assessment runs | `lab/evidence/assessments/<run>/` (summary, mapping, raw hashes) | `lab/evidence/out/assessments/<run>/` + WORM `assessments/<run>/raw/` |
| KPI snapshots | `lab/evidence/kpis/` + `.sha256` sidecars | `lab/evidence/out/kpis/` + WORM `kpis/` |
| Evidence pack | Its `manifest.json` hash in the capture log | `lab/evidence/out/` + WORM `packs/<utc>/` |
| Script captures (`Invoke-LabDay.ps1`) | `lab/evidence/tenant/<UTC day>/<id>/manifest.json` + `SHA256SUMS` | `lab/evidence/tenant/<UTC day>/<id>/raw/` (gitignored) + WORM `captures/<id>/` |
| Screenshots and manual exports | Redacted copies only, if any | `lab/evidence/out/captures/<id>/` + WORM `captures/<id>/` |
| Drill record | `lab/evidence/drills/README.md` rows | Ticket + WORM `drills/<utc>/` |
| Capture log | `lab/evidence/capture-log.csv` | n/a |

The WORM store is `lab/terraform/modules/evidence-store`: version-level
immutability, Entra-only authentication, and writers who can add but never
delete. Run integrity checks against it, not against a laptop copy.
