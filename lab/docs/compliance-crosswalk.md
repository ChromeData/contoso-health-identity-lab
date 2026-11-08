# Compliance crosswalk — Contoso Health Identity Platform

Every lab control in one row, mapped only to frameworks whose own text was checked on 2026-10-20 (how far, per framework, below), plus the SOX ITGC domains the scenario's auditors use. A reviewer or auditor can take the column for their framework and check each cited clause against the lab artifact the row names:

- **HITRUST CSF v11** — the practical implementation of HIPAA, expected in healthcare. Sections 11–16 were checked against the public v11.2.0 PDF; sections 1–10 use the same control references and titles, and an assessor should confirm them against the full CSF (gap 12). HITRUST says the public download isn't the full CSF, so the mappings cite control references and titles, and name an implementation level only where the public text shows it
- **HIPAA Security Rule** — 45 CFR §164.308/312/316, Administrative and Technical safeguards and documentation. Sections 11–16 were checked on eCFR (title 45 up to date as of 2026-10-16); every section's citations and Required/Addressable labels were re-checked against Cornell LII's copy of the CFR the same day
- **SOX ITGC** — Sarbanes-Oxley IT general controls. SOX doesn't number controls; each company writes its own ITGC IDs. The SOX rows name the common ITGC domain (access to programs and data, program change, computer operations) under COSO 2013 Principle 11, general controls over technology, not a control number. Kept because the scenario is SOX-regulated and the evidence pack labels each artifact with its ITGC domain (`Export-EvidencePack.ps1`)
- **NIST SP 800-53 Rev 5** — U.S. federal control catalog (control titles checked against NIST's Rev 5 control catalog spreadsheet, csrc.nist.gov)
- **NIST SP 800-171 Rev 2** — the numbering CMMC Level 2 uses (32 CFR 170.14: Level 2 requirements are identical to 800-171 R2; CMMC IDs add a domain prefix, so 3.1.1 is `AC.L2-3.1.1`). NIST withdrew Rev 2 for Rev 3 in May 2024; CMMC still cites Rev 2. Expected for defense contractors handling CUI. Checked against NIST's requirements CSV (csrc.nist.gov)
- **CIS Critical Security Controls v8.1** — IG1/IG2/IG3 implementation groups (Safeguard numbers, titles and IGs checked against CIS's published v8.1 guide, August 2024)

**Not mapped:** ISO/IEC 27001:2022, NIST CSF 2.0, SOC 2, PCI DSS and GDPR. NIST SP 800-63-4 assurance levels are mapped in section 17 only (authentication and federation), not as a column. Their text wasn't checked line by line, and a mapping nobody checked is a claim nobody can stand behind. The rows below are the input for any of them: a new framework is one more line per section, checked against its own text before it is added.

Each row names a control the lab implements in code, where in the repo it lives, and the referenced control number in each framework. The Entra-side controls are applied in the lab tenant (64 merged pull requests; `lab/evidence/capture-log.csv`); a row with no E capture still describes the design, not evidence that the control operated. "n/a" means the framework doesn't have a cleanly-matching clause. Sections 11–16 (added 2026-10-20) cover control areas built after the first version: risk-based access, phishing-resistant authentication, non-human identity governance, ITDR containment, birthright and separation of duties, and just-in-time credentials. They have no SOX row.

## Legend

- `IG` for CIS Controls = the lowest Implementation Group a Safeguard is in (IG1 = essential cyber hygiene; IG2 includes IG1; IG3 includes every Safeguard). For a whole Control (e.g. Control 8), it is the lowest IG of any of its Safeguards

---

## 1. Identity lifecycle (joiner / mover / leaver)

**Lab:** `lab/scripts/powershell/02-Joiner.ps1`, `03-Mover.ps1`, `04-Leaver.ps1`; HR feed → Entra provisioning (`lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1`); Lifecycle Workflows (`lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1`). Birthright by HR attribute is section 15.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 02.i Removal of Access Rights (on termination or transfer); 01.c Privilege Management |
| HIPAA Security Rule | §164.308(a)(3)(ii)(B) Workforce clearance; §164.308(a)(3)(ii)(C) Termination procedures |
| SOX ITGC | Access to programs and data: user provisioning; timely removal on termination |
| NIST 800-53 R5 | AC-2 Account Management; PS-4 Personnel Termination; PS-5 Personnel Transfer |
| NIST 800-171 R2 (CMMC L2) | 3.1.1 Limit system access to authorized users; 3.1.2 Limit access to the transactions and functions users are permitted (`02-Joiner.ps1` assigns the role-scoped access package); 3.9.2 Protect systems during and after personnel actions such as terminations and transfers (`03-Mover.ps1`, `04-Leaver.ps1`) |
| CIS v8.1 | 6.1 Establish an Access Granting Process (IG1); 6.2 Establish an Access Revoking Process (IG1) |

**Lab proof:** `03-Mover.ps1` and `04-Leaver.ps1` log a timestamp per step; `Export-EvidencePack.ps1` ships the artifact.

---

## 2. Zero standing privilege — PIM for Groups + break-glass

**Lab:** `lab/terraform/modules/pim/` (Tier-0 and Tier-1 groups, approver groups, expiring eligibility), `lab/scripts/powershell/post-apply/Set-PimGroupEligibility.ps1`, `bg-admin-01/02` excluded from every CA policy.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 01.c Privilege Management; 01.v Information Access Restriction |
| HIPAA | §164.308(a)(4) Information access management |
| SOX ITGC | Access to programs and data: privileged access restricted and reviewed; segregation of duties |
| NIST 800-53 R5 | AC-6 Least Privilege; AC-6(1)/(2)/(5)/(9); AC-2(7) Privileged user accounts |
| NIST 800-171 R2 (CMMC L2) | 3.1.5 Least privilege, including for privileged accounts; 3.1.6 Non-privileged accounts or roles for nonsecurity functions (the role exists only during a time-boxed activation: up to 4 h for Tier 0, 2 h for Global Administrator and Privileged Authentication Administrator, one 8-hour shift for Tier 1); 3.1.7 Prevent non-privileged users from executing privileged functions and capture the execution in audit logs (`lab/kql/pim-activation.kql`) |
| CIS v8.1 | 6.8 Define and Maintain Role-Based Access Control (IG3) |

**Lab proof (once run against the tenant):** `Export-EvidencePack.ps1` → `privileged_role_assignments.json` lists every assignment on a privileged directory role and flags break-glass principals (`isBreakGlass`). Expected by design: Break-Glass-Admins → Global Administrator (flagged); Privileged-IAM-Admins → User Administrator (the PIM for Groups binding: an active assignment to a group with no standing members, whose members at export time are in `pim_active_assignments.json`); any Global Administrator the operator keeps for the human bootstrap apply; and PIM-Demo-Readers → Global Reader and Security Reader (read-only presenter, eligible-only membership). Any other principal is a finding.

---

## 3. Conditional Access + MFA

**Lab:** `lab/terraform/modules/conditional-access/` — CA001–CA005; `lab/scripts/intune/New-IntuneComplianceBaseline.ps1`. The newer policies are in section 11 (CA006, CA007) and section 12 (CA008–CA010, CA020–CA022, CA060).

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 01.j User Authentication for External Connections; 01.q User Identification and Authentication (MFA) |
| HIPAA | §164.312(d) Person or entity authentication (the Security Rule doesn't name MFA; MFA is how the lab meets this standard) |
| SOX ITGC | Access to programs and data: authentication |
| NIST 800-53 R5 | IA-2 Identification and Authentication (Organizational Users); IA-2(1) Multi-factor Authentication to Privileged Accounts; IA-2(2) Multi-factor Authentication to Non-privileged Accounts |
| NIST 800-171 R2 (CMMC L2) | 3.5.2 Authenticate users, processes or devices before allowing access; 3.5.3 MFA for network access to privileged and non-privileged accounts (CA001 all users, CA002 phishing-resistant for admins). Partial: 3.5.3 also requires MFA for *local* access to privileged accounts, which CA doesn't see (gap 9) |
| CIS v8.1 | 6.3 Require MFA for Externally-Exposed Applications (IG1); 6.4 Require MFA for Remote Network Access (IG1); 6.5 Require MFA for Administrative Access (IG1) |

**Lab proof:** `lab/kql/legacy-auth.kql` plus Sentinel analytics rule for failed-signin spike.

---

## 4. Hybrid identity + domain controller hygiene

**Lab:** `lab/terraform/modules/dc-vm/`, `01-Install-ADDSForest.ps1`, `02-Configure-Domain.ps1`, LDAPS via AD CS.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 09.m Network Controls; 10.g Key Management |
| HIPAA | §164.312(e)(1) Transmission security |
| SOX ITGC | Program change: changes to directory configuration |
| NIST 800-53 R5 | SC-8 Transmission confidentiality and integrity; SC-12 Cryptographic Key Establishment and Management |
| NIST 800-171 R2 (CMMC L2) | 3.13.8 Cryptographic mechanisms to protect CUI in transmission; 3.5.10 Store and transmit only cryptographically-protected passwords (the transmit half: Vault binds and rotates over `ldaps://`, `lab/pam/vault-onboard-ad.sh`) |
| CIS v8.1 | 3.10 Encrypt Sensitive Data in Transit (IG2) |

---

## 5. Privileged session recording (Guacamole harness; target: Azure Bastion session recording, ADR 0036)

**Lab:** `lab/pam/guacamole/` with session recording to disk, replay via guacenc; `lab/pam/psm-session.sh` (RDP) and `lab/pam/psm-ssh.sh` (SSH), one Guacamole user per operator (`lab/pam/operators.json`), check-out gated on a ServiceNow change (`lab/pam/itsm-ticket.sh`). Ran in the Samba AD harness (`lab/pam/test/e2e.sh`), not yet against DC01.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 09.ab Monitoring System Use; 09.ad Administrator and Operator Logs |
| HIPAA | §164.308(a)(1)(ii)(D) Information system activity review |
| SOX ITGC | Access to programs and data: monitoring of privileged activity |
| NIST 800-53 R5 | AU-10 Non-repudiation; AU-14 Session audit; AC-17(1) Monitoring and Control (remote access) |
| NIST 800-171 R2 (CMMC L2) | 3.1.12 Monitor and control remote access sessions (brokered, recorded RDP); 3.1.15 Authorize remote execution of privileged commands (a Vault check-out gates the session, `lab/pam/psm-session.sh`). Partial on 3.3.2: sessions now run as one Guacamole user per named operator, but the broker's own sign-in is a local password until the Entra sign-in runs (gap 10) |
| CIS v8.1 | 8.5 Collect Detailed Audit Logs (IG2) |

---

## 6. Secrets rotation + checked-out credentials (Vault)

**Lab:** `lab/pam/vault/` — LDAP engine rotates `svc-backup`; library mode for `tier0-admin-01/02`; `lab/pam/discover.sh`, `onboard.sh`, `reconcile.sh`. Per-request database credentials are section 16.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 10.g Key Management; 01.d User Password Management |
| HIPAA | §164.312(a)(2)(i) Unique user identification; §164.308(a)(5)(ii)(D) Password management |
| SOX ITGC | Access to programs and data: password settings; system and service accounts |
| NIST 800-53 R5 | IA-5 Authenticator Management; IA-5(1); SA-5 System documentation |
| NIST 800-171 R2 (CMMC L2) | 3.5.10 Store and transmit only cryptographically-protected passwords (the store half: Vault file storage behind its barrier, not dev mode, `lab/pam/vault/vault.hcl`) |
| CIS v8.1 | 5.6 Centralize Account Management (IG2); 5.5 Establish and Maintain an Inventory of Service Accounts (IG2), partial: the vault covers the rotated accounts, but not the owner, purpose and review date 5.5 requires |

---

## 7. Access reviews (certification campaigns)

**Lab:** `lab/terraform/modules/entitlement/` with a review tier per package (ADR 0012), manager-reviewer, auto-remove on no-response for privileged and requestable access; `lab/scripts/powershell/post-apply/New-AccessReviewDefinitions.ps1`; review KPIs in `lab/scripts/powershell/10-Review-KPIs.ps1`. midPoint (the SailPoint / Saviynt stand-in) ran a certification campaign locally on 2026-10-20 (`lab/pam/midpoint/run-campaign.sh`, `lab/pam/test/e2e-midpoint.sh`, evidence in `lab/evidence/midpoint/`); no Entra review has run.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 01.e Review of User Access Rights |
| HIPAA | §164.308(a)(4)(ii)(C) Access establishment and modification (establish, document, review and modify access; HIPAA sets no review cadence) |
| SOX ITGC | Access to programs and data: periodic user access review, management-signed (quarterly here; the company sets the cadence) |
| NIST 800-53 R5 | AC-2(j) Account reviews; AC-6(7) Review of user privileges |
| NIST 800-171 R2 (CMMC L2) | No Rev 2 requirement names access reviews; review decisions are evidence for 3.1.1 and 3.1.5. 3.1.4 Separate the duties of individuals (`Set-IncompatibleAccessPackages.ps1`, which supersedes `Set-AccessPackageSoD.ps1`: the Pharmacy controlled-substance package is incompatible with the nurse packages, in one direction so a birthright package is never gated; `09-SoD-Report.ps1` catches the other direction; section 15). Reviews are opt-in in the module (`enable_access_reviews`, default false) |
| CIS v8.1 | 6.8 Define and Maintain Role-Based Access Control (IG3; includes recurring access reviews) |

---

## 8. Logging, monitoring, detection (Sentinel + Splunk)

**Lab:** `lab/terraform/modules/entra-diagnostics/`, `lab/terraform/modules/monitoring/`, `lab/kql/` (24 rules, listed in `threat-model.md`), `lab/splunk/detections/`, `lab/monitoring/playbook-notify.json` (Logic App → Teams/ServiceNow). Containment is section 14.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 09.aa Audit Logging; 09.ab Monitoring System Use |
| HIPAA | §164.308(a)(1)(ii)(D) Information system activity review; §164.312(b) Audit controls |
| SOX ITGC | Computer operations: security event monitoring and log retention |
| NIST 800-53 R5 | AU-2 Event logging; AU-6 Audit Record Review, Analysis, and Reporting; IR-4 Incident handling |
| NIST 800-171 R2 (CMMC L2) | 3.3.1 Create and retain audit logs (Entra audit, sign-in and provisioning categories into Log Analytics; lab retention 30 days, `envs/dev/main.tf`); 3.3.2 Actions traceable to individual users (per-UPN sign-in and audit records); 3.3.5 Correlate audit review, analysis and reporting (the same rules in Sentinel and Splunk, one SPL twin per KQL file); 3.14.6 Monitor systems to detect attacks (identity signals only, no traffic monitoring); 3.14.7 Identify unauthorized use (`break-glass-signin`, `blocked-country-signin`, `failed-signin-spike`, `legacy-auth`) |
| CIS v8.1 | Control 8 Audit Log Management (IG1); Control 17 Incident Response Management (IG1) |

---

## 9. Pipeline-as-security — IaC + scanning + OIDC federation

**Lab:** `lab/terraform/envs/bootstrap/` (human apply); OIDC federation with locked subjects; Checkov; TruffleHog; signed commits; pinned actions.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 10.k Change Control Procedures; 10.m Control of Technical Vulnerabilities |
| HIPAA | §164.308(a)(8) Evaluation (periodic technical/non-technical) |
| SOX ITGC | Program change: changes authorized, reviewed and approved; segregation of duties between change author and deployer |
| NIST 800-53 R5 | SA-11 Developer testing and evaluation; CM-3 Configuration change control; SR-3 Supply Chain Controls and Processes |
| NIST 800-171 R2 (CMMC L2) | 3.4.3 Track, review, approve or disapprove, and log changes (PR plan, required reviewer on the `prod` environment); 3.4.5 Define, document, approve and enforce access restrictions associated with changes (only the `environment:prod` federated subject can apply, `modules/pipeline-identity`) |
| CIS v8.1 | Control 16 Application Software Security (IG2); Control 7 Continuous Vulnerability Management (IG1) |

---

## 10. Evidence pack with tamper-evident manifest

**Lab:** `Export-EvidencePack.ps1` → SHA-256 manifest; folder gitignored. Upload to a WORM container (`lab/terraform/modules/evidence-store`: version-level immutability, Entra-only authentication, writers who can add but not delete), BUILT and never applied; the upload is evidence capture E56.

| Framework | Control |
|---|---|
| HITRUST CSF v11 | 09.ac Protection of Log Information; 09.aa Audit Logging (retention) |
| HIPAA | §164.316(b)(2)(i) Time limit: retain documentation six years |
| SOX ITGC | All domains: evidence that each control operated (what the auditor samples) |
| NIST 800-53 R5 | AU-9 Protection of audit information; AU-11 Audit record retention |
| NIST 800-171 R2 (CMMC L2) | 3.3.8 Protect audit information from unauthorized access, modification and deletion. Partial: the SHA-256 manifest detects modification; preventing deletion depends on the WORM store, which hasn't been applied, and the Log Analytics workspace itself has no such protection (gap 7) |
| CIS v8.1 | n/a: no cleanly matching Safeguard. 3.11 Encrypt Sensitive Data at Rest (IG2) is not claimed: the script writes the pack as plain JSON files |

---

## 11. Risk-based access (user and sign-in risk)

**Lab:** `lab/terraform/modules/conditional-access/` — CA006 (user risk High → MFA + secure password change) and CA007 (sign-in risk High → block), behind `enable_identity_protection_ca`; risk tables to the workspace (`lab/terraform/envs/bootstrap`, `enable_identity_protection_logs`); `lab/kql/identity-risk.kql`; thresholds in ADR 0015. Built and tested offline, report-only, never run against a tenant.

| Framework | Control |
|---|---|
| HITRUST CSF v11.2.0 | 01.q User Identification and Authentication; 09.ab Monitoring System Use |
| HIPAA Security Rule | §164.308(a)(5)(ii)(C) Log-in monitoring (Addressable); §164.312(d) Person or entity authentication |
| NIST 800-53 R5 | IA-10 Adaptive Authentication; AC-2(12) Account Monitoring for Atypical Usage |
| NIST 800-171 R2 (CMMC L2) | 3.14.7 Identify unauthorized use of organizational systems (risk detections feed CA006, CA007 and `identity-risk.kql`). No Rev 2 requirement names adaptive or risk-based authentication |
| CIS v8.1 | n/a: no Safeguard covers risk-based authentication (gap 11). The MFA Safeguards are in section 3 |

**Lab proof (once run against the tenant):** evidence captures E26, E27, E37 and E38 in `evidence-capture-plan.md`, each recording the risk level the simulation actually got.

---

## 12. Phishing-resistant and passwordless authentication

**Lab:** `lab/terraform/modules/conditional-access/` — CA002 (admins), CA008 (all users, pilot group first), CA009 (register security info only with a one-time TAP or a phishing-resistant method), CA010 (block device code flow), CA020 (admin portals, sign-in every 4 hours), CA021 (Tier-0 PIM activation on authentication context `c1`, sign-in every time; written by a post-apply Graph script), CA060 (shared clinical workstations, ADR 0014); `lab/scripts/powershell/post-apply/Set-AuthenticationMethodsPolicy.ps1`; `lab/scripts/powershell/07-Passwordless-Rollout.ps1`; sequence in `passwordless-rollout-plan.md`; decisions in ADR 0016 and ADR 0020. Built and tested offline, report-only.

| Framework | Control |
|---|---|
| HITRUST CSF v11.2.0 | 01.q User Identification and Authentication (its implementation examples include multi-factor and replay-resistant authentication); 01.j User Authentication for External Connections |
| HIPAA Security Rule | §164.312(d) Person or entity authentication; §164.312(a)(2)(i) Unique user identification (Required): on a shared clinical station each clinician signs in with their own key, never a shared account (CA060) |
| NIST 800-53 R5 | IA-2(8) Access to Accounts — Replay Resistant; IA-5 Authenticator Management (one-time TAP issuance and the CA009 registration gate); IA-11 Re-authentication (CA020 every 4 hours, CA021 every activation, CA060 every 8 hours). IA-2(1) and IA-2(2) are in section 3 |
| NIST 800-171 R2 (CMMC L2) | 3.5.4 Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts; 3.5.3 as in section 3, still partial for local access to privileged accounts (gap 9) |
| CIS v8.1 | 6.3 Require MFA for Externally-Exposed Applications (IG1); 6.5 Require MFA for Administrative Access (IG1). No Safeguard requires phishing resistance as such |

**Lab proof (once run against the tenant):** E20, E20b, E28b, E36b and E38b in `evidence-capture-plan.md`; per-phase KPIs in `passwordless-rollout-plan.md`.

---

## 13. Non-human identity governance

**Lab:** `lab/docs/standards/nhi-standard.md` (rules N1–N11); `lab/scripts/powershell/06-NHI-Inventory.ps1` (orphaned, single-owner, secret-bearing, stale and Tier-0 NHIs, each with an OWASP NHI ID); `lab/scripts/powershell/post-apply/Set-AppGovernancePolicy.ps1` (no secrets on new apps, credential lifetime caps); `lab/scripts/powershell/post-apply/Set-ConsentPolicy.ps1` (user consent limited, admin consent workflow); `lab/scripts/powershell/Find-ShadowAdmins.ps1`; NHI owner hand-off in `04-Leaver.ps1`; federated pipeline identities (`lab/terraform/modules/pipeline-identity/`); `lab/kql/app-credential-added.kql`, `lab/kql/app-consent-granted.kql`; decision in ADR 0018. Built and tested offline only.

| Framework | Control |
|---|---|
| HITRUST CSF v11.2.0 | 01.q User Identification and Authentication (its Level 1 implementation example assigns every user ID, service accounts included, to a named individual); 01.e Review of User Access Rights (its CIS implementation level: review all system accounts and disable any that can't be associated with a business process and owner) |
| HIPAA Security Rule | §164.312(a)(1) Access control (access only for the persons or software programs granted access rights); §164.308(a)(4)(ii)(B) Access authorization (Addressable) |
| NIST 800-53 R5 | IA-9 Service Identification and Authentication; IA-5(7) No Embedded Unencrypted Static Authenticators (federation first; no secrets on new apps); AC-2(3) Disable Accounts (an NHI whose owners have all left is flagged and, under N1, disabled after 30 days; detective, the disable is the owner process); AC-6 Least Privilege (Tier-0 Graph permissions need a risk acceptance, N6) |
| NIST 800-171 R2 (CMMC L2) | 3.5.1 Identify system users, processes acting on behalf of users, and devices; 3.5.2 Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access (here: processes, through federated credentials and managed identities) |
| CIS v8.1 | 5.5 Establish and Maintain an Inventory of Service Accounts (IG2), partial: the inventory records owners, credentials and Tier-0 permissions; purpose and review date come from the quarterly owner attestation (N8), not the inventory |

**Lab proof (once run against the tenant):** E21, E42, E43 and E53; the inventory's hashed CSV/JSON goes into the evidence pack manifest.

---

## 14. Identity incident containment (ITDR)

**Lab:** `lab/monitoring/playbook-contain.json` (Teams approval by a listed approver who is not the subject; then revoke sessions, confirm the user compromised, and disable a cloud-only account or flag a synced one for AD disable; no answer in 4 hours = no action), `lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1`, `lab/scripts/monitoring/Invoke-AdContainment.ps1`; the Sentinel automation rule in `lab/terraform/modules/monitoring/itdr.tf` (`enable_itdr_containment`); `lab/docs/runbooks/compromised-identity.md`; decision in ADR 0017. Built and tested offline, never run.

| Framework | Control |
|---|---|
| HITRUST CSF v11.2.0 | 11.c Responsibilities and Procedures (its implementation examples include an incident handling capability covering detection and analysis, containment, eradication and recovery); 11.a Reporting Information Security Events; 01.b User Registration (its CMS implementation level: disable accounts of users posing a significant risk immediately, within 30 minutes of discovery) |
| HIPAA Security Rule | §164.308(a)(6)(ii) Response and reporting (Required): identify and respond to suspected or known incidents, mitigate harmful effects, document incidents and outcomes |
| NIST 800-53 R5 | IR-4 Incident Handling (containment); IR-4(1) Automated Incident Handling Processes; IR-5 Incident Monitoring; AC-2(13) Disable Accounts for High-risk Individuals |
| NIST 800-171 R2 (CMMC L2) | 3.6.1 Establish an operational incident-handling capability that includes preparation, detection, analysis, containment, recovery, and user response activities; 3.6.2 Track, document, and report incidents to designated officials and/or authorities |
| CIS v8.1 | 17.4 Establish and Maintain an Incident Response Process (IG2), partial: the runbook and playbook cover one incident type, a compromised identity |

**Lab proof (once run against the tenant):** E41 records the minutes from incident to contained, the number to compare with HITRUST 01.b's 30-minute CMS level.

---

## 15. Birthright assignment and separation of duties (IGA)

**Lab:** `lab/iga/` (`access-catalog.json`, `birthright-rules.json`, `sod-rules.json`); `lab/scripts/powershell/post-apply/Set-AutoAssignmentPolicies.ps1` (birthright packages assigned from HR attributes, no access before the hire date, removed 72 hours after someone stops matching); `lab/scripts/powershell/post-apply/Set-IncompatibleAccessPackages.ps1` (preventive SoD that never gates a birthright package); `lab/scripts/powershell/09-SoD-Report.ps1` (detective SoD, including PIM-eligible holdings and reviewer-of-record conflicts); `lab/kql/sod-violation-granted.kql`; decision in ADR 0012. Built and tested offline. Certification itself is section 7.

| Framework | Control |
|---|---|
| HITRUST CSF v11.2.0 | 09.c Segregation of Duties; 01.b User Registration (a documented procedure for granting and revoking access) |
| HIPAA Security Rule | §164.308(a)(4)(ii)(B) Access authorization (Addressable); §164.308(a)(4)(ii)(C) Access establishment and modification (Addressable) |
| NIST 800-53 R5 | AC-5 Separation of Duties; AC-2(1) Automated System Account Management |
| NIST 800-171 R2 (CMMC L2) | 3.1.4 Separate the duties of individuals to reduce the risk of malevolent activity without collusion; 3.1.2 Limit system access to the types of transactions and functions that authorized users are permitted to execute |
| CIS v8.1 | 6.1 Establish an Access Granting Process (IG1); 6.2 Establish an Access Revoking Process (IG1). No Safeguard covers separation of duties (gap 11) |

**Lab proof:** the midPoint campaign that ran locally flagged an SoD conflict before review and removed it (`lab/evidence/midpoint/`). Tenant captures: E19, E20, E39c and E52.

---

## 16. Just-in-time database credentials

**Lab:** `lab/pam/dynamic-db/` — Vault's database secrets engine issues a new PostgreSQL login per request, named after the requester, with SELECT on the `clinical` schema only and a 1-hour lease capped at 4 hours; revoking the lease ends live sessions and drops the role; Vault rotated its own admin password and the bootstrap superuser's password is nulled. Ran locally on 2026-10-20 (`lab/pam/test/e2e-dynamic-db.sh`, 60/60; hashed record in `lab/evidence/dynamic-db/20261020T163436Z/`) against synthetic data; never run against a production database. The same pattern, short-lived and issued per use, covers SSH (10-minute Vault certificates, `lab/pam/psm-ssh.sh`) and Kubernetes (10-minute tokens, `lab/k8s/`).

| Framework | Control |
|---|---|
| HITRUST CSF v11.2.0 | 01.c Privilege Management; 01.b User Registration (its CMS implementation level: temporary accounts disabled within a fixed duration) |
| HIPAA Security Rule | §164.312(a)(1) Access control; §164.312(a)(2)(i) Unique user identification (Required): each lease is its own login, named after the requester; §164.312(b) Audit controls: Vault's audit log and PostgreSQL's connection log both name the dynamic login |
| NIST 800-53 R5 | AC-2(2) Automated Temporary and Emergency Account Management; AC-2(6) Dynamic Privilege Management; AC-6 Least Privilege; IA-5 Authenticator Management (a new authenticator per request) |
| NIST 800-171 R2 (CMMC L2) | 3.1.5 Employ the principle of least privilege, including for specific security functions and privileged accounts; 3.1.2 Limit system access to the types of transactions and functions that authorized users are permitted to execute |
| CIS v8.1 | 3.3 Configure Data Access Control Lists (IG1): database permissions by need to know |

**Lab proof:** the harness run (L02 in `evidence-capture-plan.md`), which is local only. There is no tenant step.

---

## 17. Authentication assurance (NIST SP 800-63-4 AAL / FAL)

**Lab:** the Conditional Access authentication strengths in `lab/terraform/modules/conditional-access/` (CA002 and CA021: the admin phishing-resistant strength; CA008: phishing-resistant for the workforce, pilot first; CA001: MFA; CA009: registration only with a TAP or a phishing-resistant method), the passkey profiles in `post-apply/Set-AuthenticationMethodsPolicy.ps1` (attested, device-bound for admins; synced allowed for staff; SMS and voice retired), the shared-workstation design (ADR 0014) and the federation design for AWS, ServiceNow, the clinical portal and the Okta coexistence (`modules/apps`, `lab/terraform/okta/`). Added 2026-10-26; the assurance-level labels below follow the definitions in NIST SP 800-63B-4 (authentication) and 800-63C-4 (federation) and were checked against the published Rev 4 text (verify: the final Rev 4 wording for AAL3 authenticator requirements and FAL2 assertion protection before citing this in an assessment). Nothing has been measured: no sign-in has happened.

| Framework | Control |
|---|---|
| NIST SP 800-63B-4 | **AAL3** for Tier-0 and Tier-1 administrators: hardware-bound, phishing-resistant authenticator (attested device-bound passkey or FIDO2 security key) required at every Tier-0 activation (`c1`, CA021) and at admin sign-in (CA002); reauthentication at most every 4 hours on the admin portals (CA020). **AAL2** for the workforce: MFA with phishing-resistant methods preferred and the SMS and voice channels retired (CA001, CA008, methods policy); reauthentication every 12 hours or 30 minutes of inactivity is Microsoft's session default, not a lab setting (verify:). **Registration of a new authenticator** needs an existing phishing-resistant authenticator or a one-time pass handed over after identity verification (CA009, `help-desk-identity-verification.md`), which maps to the binding and renewal requirements |
| NIST SP 800-63C-4 | **FAL2** for every federated app: signed SAML assertions or OIDC ID tokens from Entra, assignment required (no open audience), NameID = UPN (`modules/apps`); the Okta coexistence is an FAL2 federation in the other direction (Entra as the IdP for Okta, `lab/terraform/okta/`). FAL3 (holder-of-key) is not claimed |
| NIST SP 800-63A-4 | **IAL**: not claimed. Identity proofing is HR's onboarding process (`raci.md`); the lab's day-one credential hand-off (TAP given in person) is the binding step, not proofing |
| HITRUST CSF v11.2.0 | 01.q User Identification and Authentication; 01.j User Authentication for External Connections |
| HIPAA Security Rule | §164.312(d) Person or entity authentication (Required); §164.312(a)(2)(i) Unique user identification |
| NIST 800-53 R5 | IA-2(1) MFA to privileged accounts; IA-2(2) MFA to non-privileged accounts; IA-2(8) Access to accounts, replay resistant; IA-5(2) Public key-based authentication; IA-8 Identification and Authentication (Non-Organizational Users) for federation |
| NIST 800-171 R2 (CMMC L2) | 3.5.3 MFA; 3.5.4 Replay-resistant authentication |
| CIS v8.1 | 6.3 Require MFA for Externally-Exposed Applications (IG1); 6.4 Require MFA for Remote Network Access (IG1); 6.5 Require MFA for Administrative Access (IG1) |

**Lab proof:** the graduation evidence for CA002, CA008 and CA021 (E30–E38b in `evidence-capture-plan.md`) and the passkey rollout metrics (`07-Passwordless-Rollout.ps1`, KPI `phishing_resistant_pct` and `phishing_resistant_device_bound_pct`). Until then, the strengths and profiles are code only.

---

## NIST SP 800-171 Rev 2 / CMMC Level 2 index

The same rows, read by requirement number, for a defense-contractor reviewer. Requirement text is NIST's, shortened; CMMC IDs prefix the family (`AC.L2-`, `AU.L2-`, `CM.L2-`, `IA.L2-`, `IR.L2-`, `PS.L2-`, `SC.L2-`, `SI.L2-`). Numbers and text checked 2026-10-20 against NIST's published Rev 2 requirements CSV (csrc.nist.gov, SP 800-171 Rev 2, 110 requirements).

| Requirement | Text (NIST, shortened) | Lab section | Lab artifact |
|---|---|---|---|
| 3.1.1 | Limit system access to authorized users, processes acting on their behalf, and devices | 1 | `02-Joiner.ps1`, `04-Leaver.ps1`, `modules/groups` |
| 3.1.2 | Limit system access to the types of transactions and functions authorized users are permitted to execute | 1, 15, 16 | `modules/entitlement` (role-scoped access package, 180-day expiry); `post-apply/Set-AutoAssignmentPolicies.ps1`; `lab/pam/dynamic-db/` (SELECT on one schema) |
| 3.1.4 | Separate the duties of individuals to reduce the risk of malevolent activity without collusion | 7, 15 | `post-apply/Set-IncompatibleAccessPackages.ps1`, `09-SoD-Report.ps1`, `sod-violation-granted.kql` |
| 3.1.5 | Employ least privilege, including for specific security functions and privileged accounts | 2, 16 | `modules/pim`, `Set-PimGroupEligibility.ps1`; `lab/pam/dynamic-db/` |
| 3.1.6 | Use non-privileged accounts or roles when accessing nonsecurity functions | 2 | `modules/pim` (eligible, not active) |
| 3.1.7 | Prevent non-privileged users from executing privileged functions; capture their execution in audit logs | 2 | `modules/pim`, `lab/kql/pim-activation.kql` |
| 3.1.12 | Monitor and control remote access sessions | 5 | `lab/pam/guacamole/`, `psm-session.sh` |
| 3.1.15 | Authorize remote execution of privileged commands and remote access to security-relevant information | 5 | `psm-session.sh`, `vault-onboard-ad.sh` (tier0-checkout policy) |
| 3.3.1 | Create and retain system audit logs and records | 8 | `modules/entra-diagnostics`; 30-day lab retention on the workspace (`envs/dev/main.tf`) |
| 3.3.2 | Ensure the actions of individual users can be uniquely traced to them | 8 (partial in 5) | Entra sign-in and audit logs; gap 10 |
| 3.3.5 | Correlate audit record review, analysis, and reporting processes | 8 | `lab/kql/`, `lab/splunk/detections/` |
| 3.3.8 | Protect audit information and audit logging tools from unauthorized access, modification, and deletion | 10 (partial) | `Export-EvidencePack.ps1` → `manifest.json` |
| 3.4.3 | Track, review, approve or disapprove, and log changes to organizational systems | 9 | `.github/workflows/terraform-plan.yml`, `terraform-apply.yml` |
| 3.4.5 | Define, document, approve, and enforce access restrictions associated with changes | 9 | `modules/pipeline-identity` (apply subject = `environment:prod`) |
| 3.5.1 | Identify system users, processes acting on behalf of users, and devices | 13 | `06-NHI-Inventory.ps1`, `lab/docs/standards/nhi-standard.md` |
| 3.5.2 | Authenticate users, processes, or devices as a prerequisite to access | 3, 13 | `modules/conditional-access`; `modules/pipeline-identity` (federated credentials) |
| 3.5.3 | MFA for local and network access to privileged accounts and network access to non-privileged accounts | 3, 12 (partial) | CA001, CA002, CA008; gap 9 |
| 3.5.4 | Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts | 12 | CA002, CA008, CA009, CA021 (`modules/conditional-access`) |
| 3.5.10 | Store and transmit only cryptographically-protected passwords | 4, 6 | `vault-onboard-ad.sh` (`ldaps://`), `lab/pam/vault/vault.hcl` |
| 3.6.1 | Establish an operational incident-handling capability that includes preparation, detection, analysis, containment, recovery, and user response activities | 14 | `lab/monitoring/playbook-contain.json`, `runbooks/compromised-identity.md` |
| 3.6.2 | Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization | 14 | Sentinel incident comments and the ServiceNow ticket the playbooks write |
| 3.9.2 | Protect systems containing CUI during and after personnel actions such as terminations and transfers | 1 | `03-Mover.ps1`, `04-Leaver.ps1` |
| 3.13.8 | Cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission | 4 | LDAPS via AD CS (`lab/scripts/dc/`) |
| 3.14.6 | Monitor systems, including inbound and outbound traffic, to detect attacks | 8 (partial: identity signals only, no traffic monitoring) | `lab/kql/`, `modules/monitoring` (Sentinel rules) |
| 3.14.7 | Identify unauthorized use of organizational systems | 8, 11 | `break-glass-signin.kql`, `blocked-country-signin.kql`, `identity-risk.kql` |

---

## Known gaps

Coverage this lab does not claim. Each item is what a production programme would add:

1. **Data classification** (Purview / Information Protection) — HITRUST expects classification labels. The lab doesn't label anything.
2. **Backup/DR for identity itself, beyond CA and the vault** — what exists: a CA snapshot-and-restore drill (`Invoke-CaRestoreDrill.ps1`, BUILT, evidence capture E51d) and the Vault DR drill (RAN on the laptop cluster, ADR 0019). Terraform re-applies what it holds in state. Still missing: a tenant-wide Entra backup, and a tested restore for what the post-apply scripts write through Graph outside state: PIM eligibility, and the authentication methods, consent and app management policies (only the app management script saves a pre-change backup, and no drill restores it).
3. **Vendor management / third-party risk** — HITRUST 05.i–05.k (external parties) isn't modeled. A real org would track Okta, ServiceNow, Vault as third parties with risk ratings.
4. **Physical security** — out-of-scope for a software lab; mention anyway because HIPAA §164.310 requires physical safeguards and HITRUST scores them (category 08 Physical and Environmental Security).
5. **Business continuity testing cadence** — the break-glass drill is designed, not yet run (procedure in `lab/docs/runbooks/break-glass-drill.md`). A dated drill record, made after the first real drill, is the artifact to show here.
6. **HIPAA risk analysis** — §164.308(a)(1)(ii)(A) (Required) expects an assessment of risks to all ePHI. `risk-register.md` covers identity risks only; a Security Rule risk analysis covers every system that holds ePHI.
7. **Integrity of the log workspace itself** (800-53 AU-9, 800-171 3.3.8) — the manifest and the WORM store protect the evidence pack, not the Log Analytics workspace, which the APPLY identity's subscription Contributor role can still delete or cap (`target-state.md`, management plane).
8. **CMMC L2 assessment artifacts** — no System Security Plan, no POA&M, no CUI boundary. An assessment starts there; the lab supplies control evidence only.
9. **800-171 3.5.3, local and credential-plane MFA** — CA only sees Entra sign-ins. Tier-0 AD sessions to DC01 go through a Guacamole sign-in with no MFA step, so MFA for privileged access stops at the cloud control plane.
10. **800-171 3.3.2 on the credential plane** — in the harness each brokered session now belongs to one named operator, and the Vault check-out token carries that person's name and the change number. Two gaps remain: the operator signs in to Guacamole with a local password until the Entra sign-in (CA022) runs, and `guacadmin` and `guac-db` can read a stored value until check-in. Production PSM ties each session to the person's own vault identity.
11. **CIS v8.1 for risk-based access and separation of duties** — no Safeguard covers either, so sections 11 and 15 show n/a or the nearest access-process Safeguards. That is a property of CIS, not a lab gap.
12. **HITRUST references and implementation levels** — the public v11.2.0 PDF isn't the full CSF. Where sections 11–16 name an implementation level (CMS, CIS), it is one the public text shows. The control references in sections 1–10 weren't re-checked against that PDF. An assessor working from the full CSF should confirm both, and the level that applies to Contoso.

---

## How to read this crosswalk

- Start from *one* framework, the one your assessment uses (HITRUST or HIPAA for healthcare, SOX ITGC for financial reporting, NIST 800-53 for federal systems, NIST 800-171 / CMMC L2 for defense contractors, CIS for a prioritised baseline).
- Trace a row: lab control, then the file in the repo, then the clause in your framework.
- The claim is not that the lab is compliant. The claim is that each mapping here was checked against the framework's own text, and that adding another framework is one more line per section.
