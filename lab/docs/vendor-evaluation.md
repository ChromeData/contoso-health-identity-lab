# Vendor evaluation: PAM and IGA for Contoso Health

- **Status:** PAM part **superseded by [ADR 0036](adr/0036-microsoft-native-pam.md)** (2026-11-06): the owner decided against a PAM vendor, so the lab uses Microsoft products (Azure Key Vault, Azure Bastion session recording, Windows LAPS, Intune Endpoint Privilege Management, PIM). CyberArk is not part of the lab. The PAM vendor scoring below stays as the desk-review record of the market comparison that was rejected. The IGA part is still Proposed. This is a desk review. No vendor POC has been run, and no quotes have been received.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario, a fictional 5,000-user hospital. It is not a real employer and not a real procurement.
- **Related:** [ADR 0036](adr/0036-microsoft-native-pam.md) (Microsoft-native PAM, supersedes ADR 0007), [ADR 0007](adr/0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) (PAM stand-ins), [ADR 0008](adr/0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md) (IGA), [`STAND-INS.md`](STAND-INS.md), [`risk-register.md`](risk-register.md), [`roadmap.md`](roadmap.md)

## 1. Decision

| Area | Decision | Confidence |
|---|---|---|
| **PAM** | **Use Microsoft-native PAM (ADR 0036). Don't buy a PAM vendor.** Key Vault holds secrets, Azure Bastion records admin sessions, Windows LAPS rotates local admin passwords, Intune EPM gives one approved app admin rights, and PIM keeps every role just-in-time. The earlier desk-review recommendation (a CyberArk / BeyondTrust / Delinea POC, §4 to §7) was rejected on 2026-11-06. | High on direction (owner decision). The licence fit is checked: EPM is in the lab's Microsoft 365 E5 SKU (`Intune-EPM` service plan). |
| **IGA** | **Extend Entra ID Governance now. Don't buy SailPoint or Saviynt yet** (this confirms ADR 0008). Buy one when a trigger in §6 fires. | High for phase 1. SailPoint leads on capability, but only by 3 points, and the lead comes from clinical-app connectivity, which phase 1 doesn't need (§5). |
| **Microsoft licensing** | Keep the Entra ID P1/P2 that comes with M365 E5. Add the Entra ID Governance step-up for every member user in scope. Buy Workload ID Premium only for service principals named by the NHI inventory. Don't buy Entra Suite unless Private Access or Internet Access comes into scope. | High on structure. The step-up price needs verifying (§8). |

## 2. Context

What Contoso has in this scenario (assumptions are marked):

- **Microsoft estate.** 5,000 member users on Entra ID. The lab's licensing model is M365 E5 (P1 + P2) plus Entra ID Governance. See the license table in `lab/terraform/README.md` and the staging flags in `lab/terraform/envs/dev/README.md`.
- **Microsoft core, already built as code (offline-tested, applied in the lab tenant).** PIM for Groups with tiers, approver groups and expiring eligibility; access packages with 180-day expiry, a review tier per package and SoD between packages; birthright by automatic assignment from HR attributes; Lifecycle Workflows; API-driven HR provisioning (`lab/terraform/modules/pim`, `lab/terraform/modules/entitlement`, `lab/iga/`, `lab/scripts/powershell/post-apply/`, `lab/scripts/mock-hr/`).
- **PAM patterns the lab proves with stand-ins** (ADR 0007). The Samba AD harness passed 284/284 on 2026-10-20 in the author's working copy (hashed run record `lab/evidence/pam/20261020T220031Z/`; `lab/pam/README.md`, "Verify"), covering:
  - discovery of privileged and service accounts, bulk onboarding, dependency-gated rotation and reconciliation;
  - exclusive check-out, rotate-on-check-in, one Guacamole user per named operator, and a check-out refused without an approved, in-window ServiceNow change assigned to the requester, and for Tier 0 without two distinct approvers who are not the requester (dual control; against a Table API mock);
  - a recorded SSH session with 10-minute Vault SSH certificates, and a recorded RDP session through Guacamole to a Linux xrdp stand-in for DC01, whose recording plays back;
  - on a separate rehearsal cluster holding test data (not the vault that holds the AD credentials): 3 Vault nodes with auto-unseal, leader failover (2–4 s) and a timed snapshot-restore DR drill (`lab/evidence/pam-dr/`).

  The same discovery, onboarding, rotation and reconciliation scripts also ran over 500 synthetic privileged accounts (79/79, GAP 0; `lab/evidence/pam-scale/20261020T193913Z/`). Separately, Vault issued per-request PostgreSQL logins with a 1-hour lease (`lab/pam/test/e2e-dynamic-db.sh`, 60/60; hashed record in `lab/evidence/dynamic-db/20261020T163436Z/`), and Conjur enforces workload-secret policy. Not yet run against the Azure DC01: a Windows RDP session and its recording need DC01; the stand-in is Linux.
- **What the stand-ins still lack** (ADR 0007, R06 and R09 in the risk register):
  - **Scale:** discovery and onboarding are scripts proven against one synthetic domain (up to 500 privileged accounts, on one Docker host); no local Windows or Linux account discovery, no connector catalogue.
  - **Resilience:** HA exists (ADR 0019), but Contoso would run it: patching, upgrades, unseal-key custody and 24×7 support for Tier 0.
  - **Attribution:** sessions belong to a named person, but signing in to the broker through Entra (CA022) is built and not run, and `guacadmin` and `guac-db` can still read a stored value until check-in.
  - **Coverage:** no vendor remote access without a VPN, and the PTA-style correlation is a KQL rule (`vault-privileged-access-anomaly.kql`) that has never run on real audit data.
- **IGA stand-in** (`lab/pam/midpoint/README.md`). A T2 certification campaign ran headless over midPoint's REST API on 2026-10-20 (`lab/pam/test/e2e-midpoint.sh`, 91/91 in the full harness runs, whose summaries stay in the gitignored `lab/pam/out/test-runs/`): accept, revoke and no-response outcomes, revoked access removed, an SoD conflict flagged before the review, hashed evidence in `lab/evidence/midpoint/`. midPoint 4.10's REST API has no decision endpoint, so a script records each decision inside the assigned reviewer's own security context; no reviewer signs in. The Graph connector isn't bundled and is unverified on midPoint 4.10.
- **Assumptions, not modelled in the lab:**
  - Contoso runs an EHR and other on-prem clinical systems.
  - Medical-device and imaging vendors need remote access.
  - The IAM team is small (about 3–5 FTE).
  - The privileged-account count is unknown until discovery runs.

## 3. Method

- **Scale.** Each criterion is scored 1–5. Weighted total = Σ(weight × score) / 5, out of 100.
- **Basis.** Scores come from vendor documentation, the Microsoft licensing pages cited in §10, and what the lab actually runs. They aren't based on POC results. **Scores within about 5 points are inside desk-review noise.** The matrix decides the shortlist, and the POC (§7) and the quote decide the purchase.
- **Cost.** Commercial PAM and IGA pricing is quote-based. Third-party price "benchmarks" exist, but they're unverified, so they aren't used here. PAM cost is scored a **neutral 3** for every vendor until quotes arrive, and §4 shows what happens when it isn't. For IGA, the Microsoft cost is published, and SailPoint and Saviynt are scored on a structural fact: they add to the Entra P1/P2 that Contoso keeps for SSO, CA and PIM.
- **Skills market.** A scenario assumption, not a measurement: Contoso assumes CyberArk and SailPoint skills are the easiest to hire and backfill for PAM and IGA, and scores row 8 on that basis. Check it against local recruiting data before relying on it. It carries the smallest weight (5), so a full swing on that row moves a total by at most 4 points, inside the noise band above.

## 4. PAM matrix

| # | Criterion (weight) | Why it matters at Contoso | CyberArk | BeyondTrust | Delinea | Lab stand-ins |
|---|---|---|--:|--:|--:|--:|
| 1 | AD discovery, onboarding at scale, rotation (20) | Hundreds of service and admin accounts. Onboarding at scale is the work that never ends. | 4 | 4 | 4 | 2 |
| 2 | Session management, including third-party vendor access (20) | Tier-0 RDP and SSH, plus clinical and biomed vendor sessions without a VPN | 4 | 5 | 4 | 3 |
| 3 | Entra integration: SSO, MFA through CA, provisioning (15) | Per-person attribution means signing in through Entra with MFA (closes R06) | 4 | 4 | 4 | 2 |
| 4 | SaaS vs self-hosted; HA/DR burden (10) | A small team can't run a vault cluster as well as the vendor can | 4 | 4 | 4 | 2 |
| 5 | HIPAA evidence: audit export to Sentinel/Splunk, recording retention, BAA (10) | §164.312(b) audit controls; §164.312(a)(2)(i) unique user identification | 4 | 4 | 4 | 2 |
| 6 | Secrets and DevOps (10) | Azure Key Vault already in use; AKS workloads | 5 | 3 | 4 | 4 |
| 7 | Cost and licensing model (10) | Neutral until quotes (§3) | 3 | 3 | 3 | 5 |
| 8 | Skills market (5) | Hiring and backfilling a PAM engineer | 5 | 3 | 3 | 2 |
| | **Weighted total** | | **81** | **79** | **77** | **54** |

Notes on the scores that differ:

- **All three vendors.** Each says it was a Leader in Gartner's 2025 Magic Quadrant for PAM (vendor press releases, Oct 2025; Gartner report itself not read). That's why rows 1, 3, 4 and 5 are flat.
  - verify: each vendor's discovery depth for AD, local Windows and Linux in a POC.
  - verify: each vendor signs a HIPAA BAA for its SaaS. Session recordings of clinical screens can contain ePHI.
- **CyberArk, row 6 = 5.** Conjur plus Secrets Hub. Secrets Hub discovers and centrally manages secrets in Azure Key Vault, so developers keep using AKV natively (CyberArk product page).
  - **Ownership change.** Palo Alto Networks closed its acquisition of CyberArk on 2026-02-11 (PANW 10-Q). The products now carry the **Idira** brand (trade press, Apr–May 2026). This is a roadmap and pricing risk, and it's recorded in §9.
- **BeyondTrust, row 2 = 5.** Privileged Remote Access is a separate product built for vendor and remote sessions. It has an Entra gallery SAML app with provisioning that covers PRA, Password Safe and Password Safe Cloud (BeyondTrust docs).
  - verify: BeyondTrust's current secrets/DevOps offering, which is the reason row 6 = 3.
- **Delinea, row 6 = 4.** It completed the StrongDM acquisition on 2026-03-05, which adds just-in-time runtime authorization for humans and NHIs (Delinea release).
  - verify: whether Delinea has an Entra gallery app or documented SAML/SCIM.
  - verify: Delinea's SaaS vs on-prem (Secret Server) packaging.
- **Lab stand-ins.** They scored high on secrets on 2026-10-20 because a Conjur allow/deny demo, the Vault Kubernetes auth and the per-request database logins all ran (`lab/k8s/`, `lab/pam/dynamic-db/`; ADR 0036 later removed the Conjur demo). Re-scored on 2026-10-20 after the harness grew (41 → 54): rows 1, 2 and 4 rise by one because discovery to reconciliation, per-person ticket-gated sessions with SSH, and HA with a timed DR drill now run in the harness; row 3 rises by one because Entra sign-in to the broker is built, though never run. They still score low everywhere a production estate is judged: one small domain, no vendor access without a VPN, and Contoso carrying the HA, patching and 24×7 support itself (ADR 0007). The decision in §1 doesn't change.

**Sensitivity**

| Change | CyberArk | BeyondTrust | Delinea | Reading |
|---|--:|--:|--:|---|
| Base | 81 | 79 | 77 | Within noise |
| Quote: CyberArk scores 1, others 5 on row 7 | 77 | **83** | 81 | **Price flips the order.** The quote is decisive. |
| Vendor remote access is a top need (row 2 → 30, row 1 → 10) | 81 | 81 | 77 | BeyondTrust ties |

## 5. IGA matrix

| # | Criterion (weight) | Why it matters at Contoso | Entra ID Governance | SailPoint ISC | Saviynt | midPoint (stand-in) |
|---|---|---|--:|--:|--:|--:|
| 1 | Fit with the Entra and M365 control plane (20) | One audit log for CA, PIM and access. The lab's Terraform already targets it. | 5 | 4 | 4 | 2 |
| 2 | Clinical and on-prem app connectivity (EHR, pharmacy) (15) | Auditors want EHR roles certified | 2 | 5 | 5 | 3 |
| 3 | Certification, SoD and role mining depth (15) | SoD inside an application, not only between packages | 3 | 5 | 4 | 3 |
| 4 | JML from HR (10) | HR feed → AD/Entra → apps | 4 | 4 | 4 | 3 |
| 5 | Operational burden: SaaS, agents (10) | Small team | 5 | 4 | 4 | 1 |
| 6 | HIPAA evidence: review history, auditor-ready reports (10) | §164.308(a)(4) information access management; §164.308(a)(3)(ii)(C) termination | 3 | 4 | 4 | 2 |
| 7 | 3-year cost, counting what's already owned (15) | Entra P1/P2 stay either way | 5 | 2 | 2 | 4 |
| 8 | Skills market (5) | | 4 | 5 | 3 | 1 |
| | **Weighted total** | | **78** | **81** | **76** | **51** |

Notes on the scores that differ:

- **Entra, row 2 = 2.** On-prem provisioning goes through the ECMA Connector Host, which supports only the USER object type (Microsoft Learn).
  - No Microsoft Epic connector was found. A third-party page says Epic doesn't offer native SCIM (verify:).
  - Access reviews of a "custom data provided resource" can still cover an app that has no connector (Microsoft Learn, licensing fundamentals). verify: GA status, and whether auditors accept it.
- **Entra, row 3 = 3.** SoD is between access packages only (ADR 0008). Reviews include ML-assisted recommendations and catalog reviews (Microsoft Learn).
- **Entra, roadmap.** Microsoft states that no new IGA features will be added to the P2 SKU. New governance capability lands in ID Governance, the Suite or E7 (Microsoft Learn). That supports buying the Governance step-up rather than relying on P2.
- **SailPoint and Saviynt, row 2 = 5.** Both list a vendor-built Epic connector.
  - SailPoint's listing describes support for Epic versions up to Feb 2023 (verify: currency).
  - Saviynt says its connector is available through Epic's app marketplace, and states HIPAA and HITRUST control mappings. These are vendor-stated.
- **SailPoint and Saviynt, row 7 = 2.** Both add to the Entra licensing Contoso keeps. Pricing is quote-based (verify:).
- **No analyst ranking is used for IGA.** No 2025 Gartner Magic Quadrant for IGA was found, only a 2025 Market Guide (verify:).

**Sensitivity**

| Change | Entra IDG | SailPoint | Saviynt | midPoint | Reading |
|---|--:|--:|--:|--:|---|
| Base | 78 | 81 | 76 | 51 | SailPoint leads on capability |
| **Phase-1 scope**: row 2 → 5, row 7 → 25 | **84** | 75 | 70 | 53 | Entra leads once EHR entitlement governance is out of phase 1 |

SailPoint's lead rests entirely on row 2, which is why row 2 is also the main buy trigger in §6.

## 6. Build vs. buy, and when Contoso would buy

**Build (run the stand-ins in production): rejected for both areas.**

- **Contoso would become the vendor.** It would carry HA and DR, patching, CPM-style plugins for every target type, auditor-grade reports, and 24×7 support for Tier 0. The harness proves a 3-node cluster and a DR drill can be built (R09); it doesn't make running them for Tier 0 a small team's job.
- **The stand-ins still have a job.** They prove the patterns and become the **POC acceptance tests** in §7. Each `test/e2e.sh` assertion maps to a vendor test.
- **Workload secrets on AKS.** Use Microsoft's native pattern, Entra Workload ID plus the Key Vault CSI driver (`lab/terraform/k8s/keyvault-trust`, RAN · tenant on kind, `lab/evidence/k8s-keyvault/20261107T013045Z/`), not a self-run Vault.

**Buy now: commercial SaaS PAM.** No Microsoft product vaults and rotates AD Tier-0 or server credentials, or records those sessions. PIM covers Entra and Azure roles only. PIM and PAM are complementary.

- verify: Windows LAPS licensing for local admin passwords. If it's free, it shrinks the PAM scope and the licence count.

**Contoso buys SailPoint or Saviynt when any one of these fires** (this refines ADR 0008's triggers; headcount alone isn't one):

1. **EHR entitlement governance.** Auditors require EHR or pharmacy roles to be provisioned and certified at entitlement level, and custom-data reviews plus owner attestations are rejected (row 2).
2. **SoD inside applications.** SoD must be enforced on combinations within an application, not between access packages (row 3).
3. **Role mining.** A role-mining or access-modelling programme is mandated, or access packages sprawl past what the owners can review.
4. **Acquisitions.** An acquisition keeps a non-Entra directory long term. For example, the clinic's Okta in `okta-migration-runbook.md` stays instead of migrating.
5. **Review quality.** Owner-run reviews of non-Entra apps miss their SLA for two consecutive quarters (fill after running: SLA and results).

**If SailPoint arrives:** it owns certification and SoD, and Entra keeps SSO, CA and PIM. Don't run two certification engines. Re-scope the Entra ID Governance SKU at renewal to the Lifecycle Workflow and entitlement features SailPoint doesn't replace (verify:).

**Contoso picks CyberArk over the challenger when** it passes every §7 test and its 3-year quote is within 25% of the challenger's. The 25% is a scenario assumption: it is the premium Contoso would pay for hiring depth (the skills-market assumption in §3) and AKV secrets coverage. Above 25%, buy the challenger.

## 7. POC acceptance tests (derived from the lab harness)

Two vendors, 30 days, run against DC01 and one clinical-vendor connection. Leave every result blank until it has actually run.

| # | Test | Lab source | CyberArk | BeyondTrust |
|---|---|---|---|---|
| 1 | Onboard `svc-backup`, rotate it, and get `invalidCredentials` for the old password | `lab/pam/test/e2e.sh` | fill after running | fill after running |
| 2 | Exclusive check-out: the second request gets the other account, a third is refused | `psm-session.sh`, harness | fill after running | fill after running |
| 3 | Rotate on check-in: `PasswordLastSet` changes | `lab/pam/README.md` "Verify" | fill after running | fill after running |
| 4 | RDP with no password shown; recording plays back; **named user via Entra SSO + MFA** (closes R06) | `psm-session.sh`; R06 | fill after running | fill after running |
| 5 | Discover privileged and service accounts in `OU=PrivilegedAccounts` and `OU=ServiceAccounts`, bulk-onboard them through the API, and produce a reconciliation report | `lab/pam/discover.sh`, `onboard.sh`, `reconcile.sh` (harness) | fill after running | fill after running |
| 6 | The reconcile account works with only delegated Reset Password + AdminSDHolder rights (not Domain Admin) | `lab/scripts/dc/02-Configure-Domain.ps1` | fill after running | fill after running |
| 7 | Check-out, check-in and session events reach Sentinel and Splunk; record the minutes it takes | `lab/kql/`, `lab/splunk/` | fill after running | fill after running |
| 8 | Workload secret allow/deny equivalent; AKV governance | `lab/k8s/` (Vault Kubernetes auth) | fill after running | fill after running |
| 9 | Vendor session without a VPN, time-boxed, approved, recorded | scenario assumption | fill after running | fill after running |
| 10 | SaaS SLA, connector failover, export of recordings at exit, BAA signed | R09 | fill after running | fill after running |
| 11 | Check-out refused without an approved, in-window ServiceNow change assigned to the requester | `lab/pam/itsm-ticket.sh`, harness | fill after running | fill after running |
| 12 | A database login issued per request with a short lease; revoking it ends a live session | `lab/pam/test/e2e-dynamic-db.sh` | fill after running | fill after running |

**Exit criteria:** tests 1–7, 10 and 11 pass. Test 12 is scored, not required. The licence count comes from test 5's discovery output, so get the quote after discovery, not before.

## 8. Microsoft licensing: cost per capability

These are US list prices from Microsoft's Entra pricing page, read on 2026-10-20. All per-user plans are annual commitments. EA and CSP discounts are not applied.

| Capability Contoso uses | Minimum SKU | List price | Notes for Contoso | Source |
|---|---|---|---|---|
| SSO, MFA, Conditional Access, dynamic groups, HR- and API-driven inbound provisioning (100K records/day, 2 jobs per flow) | Entra ID P1 | $7.00 /user/mo | Included in M365 E3 and E5 | [1], [2] |
| PIM (roles, Azure resources, PIM for Groups), ID Protection and risk-based CA, basic access reviews and entitlement management | Entra ID P2 | $10.00 /user/mo | Included in M365 E5. No new IGA features will be added to P2 [2] | [1], [2] |
| Lifecycle Workflows, member-user access reviews, advanced entitlement management (custom extensions, auto-assignment, sponsors), Account Discovery, inactive-guest insights, API-driven provisioning at 300K records/day and 20 jobs | Entra ID Governance (prerequisite: P1 or P2) | $7.00 /user/mo standalone | Contoso would buy the **Governance Step-Up for P2**. verify: its price, which isn't on the public page | [1], [2] |
| The same Governance features for frontline staff | Entra ID Governance Frontline Worker | not listed | verify: price and eligibility for clinical staff on M365 F-licences | [2] |
| Governance actions on guests (agency nurses, affiliated physicians) | Guest MAU billing via an Azure subscription | not listed | Billed per guest with at least one governance action in the month. verify: rate | [2] |
| ID Governance + ID Protection + Private Access + Internet Access + Verified ID | Entra Suite (prerequisite: P1) | $12.00 /user/mo | Only cheaper than Governance + Private Access ($5) + Internet Access ($5) when ZTNA is in scope. It isn't here | [1], [2] |
| CA and ID Protection for workload identities, access reviews of SPs in privileged roles, app health recommendations | Workload ID Premium | $3.00 /workload identity/mo | Managed identities, workload identity federation (the lab's GitHub OIDC) and app management policies are **free** (verify: app management policy licensing; `standards/nhi-standard.md` flags it). The lab's PLAN and APPLY SPs (`lab/terraform/modules/pipeline-identity`) are the first candidates | [3] |
| Governance of agent identities | Microsoft Agent 365 (prerequisite: P1) | not listed | verify: price | [2] |

**List-price arithmetic for the scenario (illustrative, before discounts).**

- **Governance, standalone SKU:** 5,000 × $7 × 12 = **$420,000/yr**. This is the ceiling. The step-up for P2 is what Contoso would actually buy (verify: price).
- **Seat count:** licences must cover every member user in scope of governance features, or who configures them. Assignment isn't required [2]. Because Lifecycle Workflows touch every joiner and leaver, assume all 5,000 are in scope.
- **Workload ID Premium for the two pipeline SPs:** 2 × $3 × 12 = **$72/yr**. At Contoso scale, the count comes from the NHI inventory (fill after running).

**Price discrepancy (verify:).** Microsoft's page shows P1 at $7 and P2 at $10. Some third-party pages still show $6 and $9. Confirm the effective date of the change before quoting a budget.

## 9. Consequences

**Positive**
- **One control plane** for workforce governance (Entra) and one bought platform for Tier-0 credentials and sessions. No self-run vault cluster.
- **The stand-ins become the test plan.** Lab work turns directly into acceptance criteria.

**Risks and compensating controls**

| Risk | Compensating control |
|---|---|
| **CyberArk ownership change.** Palo Alto Networks owns it and is moving it to the Idira brand. Pricing, bundling or roadmap may shift. | Get a multi-year price hold in the contract. Keep the challenger's POC results current, and keep the PAM vocabulary map (`lab/pam/README.md`) so the move stays vendor-portable. Moot for the lab since ADR 0036 (no PAM vendor). |
| **PAM SaaS stores ePHI-adjacent recordings.** | A signed BAA is an exit criterion (test 10). Set a recording retention period (owner: Compliance). HIPAA's six-year rule (§164.316(b)(2)) covers required documentation, not logs as such (verify: Contoso's records policy). |
| **Entra can't govern EHR entitlements** (§5, row 2). | Owner attestations plus custom-data reviews, tracked as trigger 1. Model toxic combinations as separate access packages (ADR 0008). |
| **Governance licence cost scales with every in-scope member.** | Budget for all 5,000. Check the Frontline Worker SKU for clinical staff (verify:). |
| **The desk-review scores are judgement.** | Every score above is replaced by a POC result before purchase (§7). |
| **The stand-in production path in `roadmap.md`.** | The roadmap's Phase 2 PAM row points here. The self-run Vault HA design applies only if this evaluation is rejected. Owner: IAM Lead. |

## Revisit trigger

- **Quotes arrive.** Re-score PAM row 7 and IGA row 7.
- **POC completes.** Replace the PAM scores with the §7 results.
- **Any §6 IGA trigger fires.**
- **A vendor event:** acquisition, a major price change, or end of life of a scored product.
- **The HIPAA Security Rule final rule is published** (verify: status of the Jan 2025 proposed rule, which would make MFA and an asset inventory explicit).
- **Annual review:** 2027-10-20.

## Evidence (lab files)

- `lab/pam/README.md`: stand-in table, harness results, security notes, definition of done
- `lab/pam/test/e2e.sh`, `lab/pam/psm-session.sh`, `lab/pam/vault-onboard-ad.sh`, `lab/pam/discover.sh`, `lab/pam/onboard.sh`, `lab/pam/reconcile.sh`, `lab/pam/itsm-ticket.sh`, `lab/pam/vault-ha.sh`, `lab/pam/dr-drill.sh`
- `lab/pam/dynamic-db/README.md`, `lab/pam/test/e2e-dynamic-db.sh`: per-request database credentials
- `lab/pam/midpoint/README.md`, `lab/pam/test/e2e-midpoint.sh`, `lab/evidence/midpoint/`: the midPoint certification campaign and its hashed evidence
- `lab/docs/adr/0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md`, `lab/docs/adr/0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md`
- `lab/docs/STAND-INS.md`: stand-in rows and the AKS mapping
- `lab/docs/risk-register.md`: R06 (session attribution), R09 (Tier-0 single points of failure), R15 (toxic access combinations)
- `lab/terraform/README.md`: license requirements per resource
- `lab/terraform/envs/dev/README.md`: staging flags, licensing tier per piece
- `lab/terraform/modules/pipeline-identity/main.tf`: PLAN and APPLY service principals
- `lab/terraform/k8s/keyvault-trust`: Entra Workload ID federated credential + one-secret Key Vault grant (applied per pipeline run)
- `lab/scripts/dc/02-Configure-Domain.ps1`: delegated reconcile rights

## 10. Sources (accessed 2026-10-20)

1. Microsoft, "Microsoft Entra plans and pricing": https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing
2. Microsoft Learn, "Microsoft Entra ID Governance licensing fundamentals" (updated 2026-10-16): https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals
3. Microsoft Learn, "Frequently asked questions about Microsoft Entra Workload ID" (ms.date 2025-03-18): https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-faqs. The page says both "one license in the tenant unlocks all features" and "obtain licenses for identities eligible for premium features". verify: the licence count with Microsoft.
4. Microsoft Learn, "On-premises application provisioning architecture" (ECMA Connector Host): https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-application-provisioning-architecture
5. Palo Alto Networks Form 10-Q, quarter ending 2026-01-31 (CyberArk acquisition completed 2026-02-11): https://www.sec.gov/Archives/edgar/data/1327567/000132756726000005/panw-20260131.htm
6. SiliconANGLE, "Idira launches…", 2026-05-12: https://siliconangle.com/2026/05/12/idira-launches-palo-alto-networks-extends-cyberark-tech-machine-agentic-identities/
7. CyberArk, Secrets Hub product page: https://www.cyberark.com/products/secrets-hub/
8. CyberArk press release, 2025 Gartner MQ for PAM, 2025-10-14: https://www.cyberark.com/press/cyberark-named-a-leader-in-the-2025-gartner-magic-quadrant-for-privileged-access-management/
9. BeyondTrust press release, 2025 Gartner MQ for PAM, Oct 2025: https://www.beyondtrust.com/press/2025-gartner-magic-quadrant-privileged-access-management
10. BeyondTrust docs, Entra ID (SAML) for PRA: https://docs.beyondtrust.com/pra/v25.2/docs/entra-id-saml
11. Delinea, "Delinea Completes StrongDM Acquisition", 2026-03-05: https://delinea.com/news/delinea-acquires-strongdm-to-secure-ai-with-continuous-authorization
12. SailPoint, Epic Systems connector catalog: https://www.sailpoint.com/products/connectivity-and-integrations/catalog/epic-systems
13. Saviynt, Epic integration: https://saviynt.com/integrations/epic/
14. Stitchflow, Epic SCIM page (third party; used only for the "no native SCIM" claim, verify:): https://www.stitchflow.com/scim/epic
