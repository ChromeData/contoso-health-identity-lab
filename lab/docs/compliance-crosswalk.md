# Compliance crosswalk — Contoso Health Identity Platform

Every lab control in one row, mapped to the frameworks a hospital's
auditors use. A reviewer can take their framework's column and check each
cited clause against the artifact the row names.

- **HIPAA Security Rule** (45 CFR §164.308/312/316). Every citation and its
  Required/Addressable label was checked on eCFR and Cornell LII on
  2026-10-20.
- **HITRUST CSF v11.** Rows 11–16 were checked against the public v11.2.0
  PDF. Rows 1–10 use the same references and titles but weren't re-checked
  against it, so they are marked *(assessor to confirm)*. HITRUST says the
  public download isn't the full CSF.
- **NIST SP 800-53 Rev 5.** Control titles checked against NIST's Rev 5
  catalog.
- **SOX ITGC.** SOX doesn't number controls; each row names the common ITGC
  domain under COSO 2013 Principle 11. Kept because the scenario is
  SOX-regulated and the evidence pack labels each artifact by domain
  (`Export-EvidencePack.ps1`). Rows 11–16 have no SOX mapping.

**Not mapped here:** NIST SP 800-171 / CMMC and CIS v8.1 mappings are
available on request. ISO 27001, NIST CSF 2.0, SOC 2, PCI DSS and GDPR were
not checked line by line, and a mapping nobody checked is a claim nobody can
stand behind.

**Status.** The Entra-side controls are BUILT (code tested offline) and have
not run in a tenant, so their rows describe the design, not evidence that a
control operated. The PAM, IGA-campaign and database-credential rows also
RAN · harness, with hashed records in `lab/evidence/`.

## Crosswalk

| # | Control | Lab artifact | HIPAA | HITRUST CSF v11 | NIST 800-53 R5 | SOX ITGC |
|---|---|---|---|---|---|---|
| 1 | Joiner, mover, leaver | `02-Joiner.ps1`, `03-Mover.ps1`, `04-Leaver.ps1` (timestamp per step); HR feed → Entra provisioning; Lifecycle Workflows | §164.308(a)(3)(ii)(B) workforce clearance; (C) termination procedures | 02.i removal of access rights; 01.c privilege management *(assessor to confirm)* | AC-2; PS-4; PS-5 | Access to programs and data: provisioning; timely removal on termination |
| 2 | Zero standing privilege: PIM and break-glass | `modules/pim` (Tier-0/1 groups, approver groups, expiring eligibility); `Set-PimGroupEligibility.ps1`; break-glass excluded from every CA policy. Tenant proof: `privileged_role_assignments.json` in the evidence pack | §164.308(a)(4) information access management | 01.c privilege management; 01.v information access restriction *(assessor to confirm)* | AC-6, AC-6(1)(2)(5)(9); AC-2(7) | Privileged access restricted and reviewed; segregation of duties |
| 3 | Conditional Access and MFA | `modules/conditional-access` (CA001–CA005; the full list is in the [CA design principles](standards/conditional-access-design-principles.md) §1); `legacy-auth.kql` | §164.312(d) person or entity authentication (the rule doesn't name MFA; MFA is how the lab meets it) | 01.j user authentication for external connections; 01.q user identification and authentication *(assessor to confirm)* | IA-2; IA-2(1); IA-2(2) | Authentication |
| 4 | Hybrid identity and DC hygiene | `modules/dc-vm`; LDAPS via AD CS; Vault binds and rotates over `ldaps://` | §164.312(e)(1) transmission security | 09.m network controls; 10.g key management *(assessor to confirm)* | SC-8; SC-12 | Program change: directory configuration |
| 5 | Privileged session recording | Guacamole (PSM stand-in): one user per operator, check-out gated on an approved change, recorded RDP and SSH. RAN · harness against the Samba DC | §164.308(a)(1)(ii)(D) information system activity review | 09.ab monitoring system use; 09.ad administrator and operator logs *(assessor to confirm)* | AU-10; AU-14; AC-17(1) | Monitoring of privileged activity |
| 6 | Credential vaulting and rotation | Vault LDAP engine, library check-out, `discover.sh` → `onboard.sh` → `reconcile.sh`; Conjur for workload secrets. RAN · harness, including 500 accounts | §164.312(a)(2)(i) unique user identification; §164.308(a)(5)(ii)(D) password management | 10.g key management; 01.d user password management *(assessor to confirm)* | IA-5; IA-5(1); SA-5 | Password settings; system and service accounts |
| 7 | Access reviews | `modules/entitlement` (a review tier per package, ADR 0012); `New-AccessReviewDefinitions.ps1`; `10-Review-KPIs.ps1`. midPoint campaign RAN · harness (`lab/evidence/midpoint/`); no Entra review has run | §164.308(a)(4)(ii)(C) access establishment and modification (no cadence set by HIPAA) | 01.e review of user access rights *(assessor to confirm)* | AC-2(j); AC-6(7) | Periodic user access review, management-signed |
| 8 | Logging, detection, response | `modules/entra-diagnostics`, `modules/monitoring`; 22 KQL rules with SPL twins ([threat-model.md](threat-model.md)); notify playbook to Teams and ServiceNow. All 22 rules passed their cases on the local Kusto emulator (`lab/evidence/kusto/`), not a workspace | §164.308(a)(1)(ii)(D); §164.312(b) audit controls | 09.aa audit logging; 09.ab monitoring system use *(assessor to confirm)* | AU-2; AU-6; IR-4 | Computer operations: security event monitoring, log retention |
| 9 | Pipeline as a security control | OIDC federation with locked subjects; PLAN/APPLY split; Checkov, TruffleHog, pinned actions; `prod` reviewer | §164.308(a)(8) evaluation | 10.k change control procedures; 10.m control of technical vulnerabilities *(assessor to confirm)* | SA-11; CM-3; SR-3 | Program change: authorized, reviewed, approved; author ≠ deployer |
| 10 | Tamper-evident evidence pack | `Export-EvidencePack.ps1` → SHA-256 manifest; WORM store (`modules/evidence-store`), BUILT, never applied | §164.316(b)(2)(i) six-year retention of documentation | 09.ac protection of log information; 09.aa audit logging *(assessor to confirm)* | AU-9; AU-11 | All domains: evidence that each control operated |
| 11 | Risk-based access | CA006 (user risk High → MFA + secure password change), CA007 (sign-in risk High → block); `identity-risk.kql`; ADR 0015 | §164.308(a)(5)(ii)(C) log-in monitoring (Addressable); §164.312(d) | 01.q; 09.ab | IA-10; AC-2(12) | n/a |
| 12 | Phishing-resistant and passwordless authentication | CA002, CA008, CA009, CA010, CA020, CA021, CA060; `Set-AuthenticationMethodsPolicy.ps1`; `07-Passwordless-Rollout.ps1`; ADRs 0014, 0016 | §164.312(d); §164.312(a)(2)(i) unique user identification (Required): each clinician signs in with their own key on a shared station | 01.q (its implementation examples include multi-factor and replay-resistant authentication); 01.j | IA-2(8) replay resistant; IA-5; IA-11 re-authentication | n/a |
| 13 | Non-human identity governance | [nhi-standard.md](standards/nhi-standard.md) (N1–N11); `06-NHI-Inventory.ps1` and the secrets register; app management and consent policies; `Find-ShadowAdmins.ps1`; federated pipeline identities; ADR 0018 | §164.312(a)(1) access control (persons or software programs); §164.308(a)(4)(ii)(B) access authorization (Addressable) | 01.q (every user ID, service accounts included, assigned to a named individual); 01.e | IA-9; IA-5(7); AC-2(3); AC-6 | n/a |
| 14 | Identity incident containment | `playbook-contain.json` (Teams approval by a listed approver, then revoke, confirm compromised, disable or flag for AD disable); `Invoke-AdContainment.ps1`; ADR 0017. Tenant proof: incident-to-contained minutes (E41) | §164.308(a)(6)(ii) response and reporting (Required) | 11.c responsibilities and procedures; 11.a reporting events; 01.b (CMS level: disable high-risk accounts within 30 minutes) | IR-4; IR-4(1); IR-5; AC-2(13) | n/a |
| 15 | Birthright and separation of duties | `lab/iga/`; `Set-AutoAssignmentPolicies.ps1`; `Set-IncompatibleAccessPackages.ps1`; `09-SoD-Report.ps1`; `sod-violation-granted.kql`. The midPoint campaign flagged an SoD conflict before review | §164.308(a)(4)(ii)(B), (C) (Addressable) | 09.c segregation of duties; 01.b user registration | AC-5; AC-2(1) | n/a |
| 16 | Just-in-time database credentials | Vault database engine: a new PostgreSQL login per request, `SELECT` on one schema, 1-hour lease, dropped on revoke. RAN · harness, 60 passed (`lab/evidence/dynamic-db/`), synthetic data only | §164.312(a)(1); §164.312(a)(2)(i) (each lease is its own named login); §164.312(b) | 01.c; 01.b (CMS level: temporary accounts disabled within a fixed duration) | AC-2(2); AC-2(6); AC-6; IA-5 | n/a |

Tenant captures for each row are listed in the coverage index of
[`evidence-capture-plan.md`](evidence-capture-plan.md).

## Known gaps

Coverage this lab does not claim; each is what a production programme
would add.

1. **Data classification** (Purview / Information Protection): HITRUST
   expects labels; the lab labels nothing.
2. **Backup and DR for identity itself.** What exists: a CA
   snapshot-and-restore drill (BUILT) and the Vault DR drill (RAN · harness,
   ADR 0019). Missing: a tenant-wide Entra backup, and a tested restore for
   what post-apply scripts write outside Terraform state (PIM eligibility,
   the methods, consent and app management policies).
3. **Third-party risk:** HITRUST 05.i–05.k isn't modelled; Okta, ServiceNow
   and the PAM vendor would be tracked as third parties.
4. **Physical security** (HIPAA §164.310, HITRUST category 08) is out of
   scope for a software lab.
5. **Business-continuity testing cadence:** the break-glass drill is written
   but has never run; a dated drill record is the artifact.
6. **HIPAA risk analysis** (§164.308(a)(1)(ii)(A), Required) covers every
   system holding ePHI; the risk register covers identity risks only.
7. **Integrity of the log workspace itself** (AU-9): the manifest and WORM
   store protect the evidence pack, not the Log Analytics workspace, which
   APPLY's subscription Contributor role can still delete or cap (R01).
8. **MFA stops at the cloud control plane.** Tier-0 AD sessions to DC01 go
   through a broker sign-in with no MFA step until Entra sign-in (CA022)
   runs, and `guacadmin` can read a stored value until check-in (R06).
9. **HITRUST implementation levels** shown are only those the public text
   shows; an assessor working from the full CSF confirms rows 1–10 and the
   level that applies to Contoso.

The claim is not that the lab is compliant. It is that each mapping was
checked against the framework's own text, and that adding a framework is
one more column, checked against its text before it is added.
