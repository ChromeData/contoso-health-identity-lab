# Vendor evaluation: PAM and IGA for Contoso Health

- **Status:** Proposed. A desk review: no vendor POC has run and no quote has been received.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario, a fictional 5,000-user hospital. Not a real employer or a real procurement.
- **Related:** [ADR 0007](adr/0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) (PAM stand-ins and what they lack), [ADR 0008](adr/0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md) (IGA), [`STAND-INS.md`](STAND-INS.md)

## 1. Decision

| Area | Decision | Confidence |
|---|---|---|
| **PAM** | **Buy a SaaS PAM;** don't put the lab stand-ins into production. Two-vendor POC: **CyberArk Privilege Cloud** (preferred) against **BeyondTrust**, with Delinea as the price alternate. The §7 acceptance tests and a 3-year quote decide | Medium: the three Leaders are within 4 points on desk review, and price alone can flip the order |
| **IGA** | **Extend Entra ID Governance now; don't buy SailPoint or Saviynt yet** (confirms ADR 0008). Buy when a §6 trigger fires | High for phase 1: SailPoint leads by 3 points, all from clinical-app connectivity, which phase 1 doesn't need |
| **Microsoft licensing** | Keep the Entra ID P1/P2 in M365 E5; add the ID Governance step-up for members in scope; Workload ID Premium only for service principals the NHI inventory names; no Entra Suite unless Private or Internet Access comes into scope | High on structure; the step-up price is quote-based |

## 2. Method

- **Scale.** Each criterion scored 1–5; weighted total = Σ(weight × score) /
  5, out of 100.
- **Basis.** Vendor documentation, Microsoft's licensing pages and what the
  lab actually runs: not POC results. **Scores within about 5 points are
  desk-review noise.** The matrix makes the shortlist; the POC and the quote
  make the purchase.
- **Cost.** PAM and IGA pricing is quote-based, and third-party price
  "benchmarks" are unverified, so PAM cost is a **neutral 3** for every vendor
  until quotes arrive (§3 shows what changes when it isn't).
- **Skills market** is a scenario assumption (CyberArk and SailPoint skills
  are easiest to hire), weighted 5, so a full swing moves a total by at most
  4 points.
- **What the stand-ins prove** is the lab's own evidence: discovery to
  reconciliation, ticket-gated per-person sessions under dual control, HA
  and a timed DR drill, and the same scripts over 500 synthetic privileged
  accounts (ADR 0007, ADR 0019, `lab/evidence/`). What they lack: a
  connector catalogue, vendor access without a VPN, and Contoso carrying HA,
  patching and 24×7 support for Tier 0 itself.

## 3. PAM matrix

| # | Criterion (weight) | Why it matters at Contoso | CyberArk | BeyondTrust | Delinea | Lab stand-ins |
|---|---|---|--:|--:|--:|--:|
| 1 | AD discovery, onboarding at scale, rotation (20) | Hundreds of service and admin accounts; onboarding never ends | 4 | 4 | 4 | 2 |
| 2 | Session management, including vendor access (20) | Tier-0 RDP and SSH, plus clinical and biomed vendor sessions without a VPN | 4 | 5 | 4 | 3 |
| 3 | Entra integration: SSO, MFA through CA, provisioning (15) | Per-person attribution means signing in through Entra (closes R06) | 4 | 4 | 4 | 2 |
| 4 | SaaS vs. self-hosted; HA/DR burden (10) | A small team can't run a vault cluster as well as the vendor | 4 | 4 | 4 | 2 |
| 5 | HIPAA evidence: audit export, recording retention, BAA (10) | §164.312(b) audit controls; §164.312(a)(2)(i) unique user identification | 4 | 4 | 4 | 2 |
| 6 | Secrets and DevOps (10) | Azure Key Vault in use; AKS workloads | 5 | 3 | 4 | 4 |
| 7 | Cost and licensing model (10) | Neutral until quotes | 3 | 3 | 3 | 5 |
| 8 | Skills market (5) | Hiring and backfilling a PAM engineer | 5 | 3 | 3 | 2 |
| | **Weighted total** | | **81** | **79** | **77** | **54** |

- **All three vendors** say they were Leaders in Gartner's 2025 Magic
  Quadrant for PAM (vendor press releases; the report itself not read),
  which is why rows 1, 3, 4 and 5 are flat. Discovery depth and a signed
  HIPAA BAA are POC tests, because session recordings of clinical screens
  can contain ePHI.
- **CyberArk, row 6 = 5:** Conjur plus Secrets Hub, which manages secrets in
  Azure Key Vault so developers keep using it natively. **Ownership change:**
  Palo Alto Networks closed its acquisition of CyberArk on 2026-02-11, and
  the products now carry the Idira brand (trade press): a roadmap and
  pricing risk (§8).
- **BeyondTrust, row 2 = 5:** Privileged Remote Access is built for vendor
  and remote sessions, with an Entra gallery SAML app.
- **Delinea, row 6 = 4:** the StrongDM acquisition (completed 2026-03-05)
  adds just-in-time runtime authorization for humans and NHIs.
- **Lab stand-ins** score high on secrets because Conjur allow/deny, Vault
  Kubernetes auth and per-request database logins all run, and low wherever
  a production estate is judged.

| Sensitivity | CyberArk | BeyondTrust | Delinea | Reading |
|---|--:|--:|--:|---|
| Base | 81 | 79 | 77 | Within noise |
| Quote: CyberArk scores 1, others 5 on row 7 | 77 | **83** | 81 | **Price flips the order;** the quote is decisive |
| Vendor remote access is the top need (row 2 → 30, row 1 → 10) | 81 | 81 | 77 | BeyondTrust ties |

## 4. IGA matrix

| # | Criterion (weight) | Why it matters at Contoso | Entra ID Governance | SailPoint ISC | Saviynt | midPoint (stand-in) |
|---|---|---|--:|--:|--:|--:|
| 1 | Fit with the Entra and M365 control plane (20) | One audit log for CA, PIM and access; the lab's Terraform targets it | 5 | 4 | 4 | 2 |
| 2 | Clinical and on-prem app connectivity (EHR, pharmacy) (15) | Auditors want EHR roles certified | 2 | 5 | 5 | 3 |
| 3 | Certification, SoD and role-mining depth (15) | SoD inside an application, not only between packages | 3 | 5 | 4 | 3 |
| 4 | JML from HR (10) | HR feed → AD/Entra → apps | 4 | 4 | 4 | 3 |
| 5 | Operational burden (10) | Small team | 5 | 4 | 4 | 1 |
| 6 | HIPAA evidence: review history, auditor-ready reports (10) | §164.308(a)(4); §164.308(a)(3)(ii)(C) | 3 | 4 | 4 | 2 |
| 7 | 3-year cost, counting what's already owned (15) | Entra P1/P2 stay either way | 5 | 2 | 2 | 4 |
| 8 | Skills market (5) | | 4 | 5 | 3 | 1 |
| | **Weighted total** | | **78** | **81** | **76** | **51** |

- **Entra, row 2 = 2:** on-prem provisioning goes through the ECMA Connector
  Host, which supports only the user object type, and no Microsoft Epic
  connector was found. Reviews of a "custom data provided resource" can still
  cover an app with no connector.
- **Entra, row 3 = 3:** SoD is between access packages only (ADR 0008).
- **Entra, roadmap:** Microsoft says no new IGA features will be added to
  P2; new governance capability lands in ID Governance, which supports
  buying the step-up rather than relying on P2.
- **SailPoint and Saviynt, row 2 = 5:** both list a vendor-built Epic
  connector (vendor-stated). **Row 7 = 2:** both add to the Entra licensing
  Contoso keeps.

| Sensitivity | Entra IDG | SailPoint | Saviynt | midPoint | Reading |
|---|--:|--:|--:|--:|---|
| Base | 78 | 81 | 76 | 51 | SailPoint leads on capability |
| **Phase-1 scope:** row 2 → 5, row 7 → 25 | **84** | 75 | 70 | 53 | Entra leads once EHR entitlement governance is out of phase 1 |

SailPoint's lead rests entirely on row 2, which is why row 2 is also the
first buy trigger.

## 5. Build vs. buy

**Build (run the stand-ins in production): rejected for both areas.**
Contoso would become the vendor: HA and DR, patching, CPM-style plugins for
every target type, auditor-grade reports and 24×7 Tier-0 support. The
harness proves a 3-node cluster and a DR drill can be built; it doesn't make
running them a small team's job. Workload secrets on AKS use Microsoft's
native pattern, Entra Workload ID plus the Key Vault CSI driver, not a
self-run Vault.

**Buy now: a commercial SaaS PAM.** No Microsoft product vaults and rotates
AD Tier-0 or server credentials or records those sessions; PIM covers Entra
and Azure roles only. PIM and PAM are complementary.

## 6. When Contoso buys SailPoint or Saviynt

This is the single home for the IGA buy triggers. Any one fires it;
headcount alone doesn't.

1. **EHR entitlement governance.** Auditors require EHR or pharmacy roles
   provisioned and certified at entitlement level, and custom-data reviews
   plus owner attestations are rejected (row 2).
2. **SoD inside applications,** not just between access packages (row 3).
3. **Role mining** is mandated, or access packages sprawl past what owners
   can review.
4. **Acquisitions** keep a non-Entra directory long term (for example, the
   clinic's Okta stays instead of migrating).
5. **Review quality:** owner-run reviews of non-Entra apps miss their SLA
   for two consecutive quarters.

**If SailPoint arrives,** it owns certification and SoD and Entra keeps SSO,
CA and PIM. Never two certification engines; re-scope the Governance SKU at
renewal.

**Contoso picks CyberArk over the challenger when** it passes every §7 test
and its 3-year quote is within 25% of the challenger's. The 25% is a
scenario assumption: the premium for hiring depth and Key Vault secrets
coverage.

## 7. POC acceptance tests (derived from the lab harness)

The stand-ins become the test plan: each `test/e2e.sh` assertion maps to a
vendor test. Two vendors, 30 days, against DC01 and one clinical-vendor
connection. Results are left blank until they have run.

| # | Test | Lab source | CyberArk | BeyondTrust |
|---|---|---|---|---|
| 1 | Onboard `svc-backup`, rotate it, get `invalidCredentials` for the old password | `lab/pam/test/e2e.sh` | fill after running | fill after running |
| 2 | Exclusive check-out: the second request gets the other account, a third is refused | `psm-session.sh` | fill after running | fill after running |
| 3 | Rotate on check-in: `PasswordLastSet` changes | `lab/pam/README.md` | fill after running | fill after running |
| 4 | RDP with no password shown; recording plays back; **named user via Entra SSO + MFA** | `psm-session.sh`; R06 | fill after running | fill after running |
| 5 | Discover privileged and service accounts, bulk-onboard through the API, produce a reconciliation report | `discover.sh`, `onboard.sh`, `reconcile.sh` | fill after running | fill after running |
| 6 | The reconcile account works with delegated Reset Password + AdminSDHolder rights only (not Domain Admin) | `02-Configure-Domain.ps1` | fill after running | fill after running |
| 7 | Check-out, check-in and session events reach Sentinel and Splunk; minutes recorded | `lab/kql/`, `lab/splunk/` | fill after running | fill after running |
| 8 | Workload secret allow/deny; Key Vault governance | `conjur-demo.sh` | fill after running | fill after running |
| 9 | Vendor session without a VPN, time-boxed, approved, recorded | scenario assumption | fill after running | fill after running |
| 10 | SaaS SLA, connector failover, recording export at exit, BAA signed | R09 | fill after running | fill after running |
| 11 | Check-out refused without an approved, in-window change assigned to the requester, and for Tier 0 without two approvers | `itsm-ticket.sh` | fill after running | fill after running |
| 12 | A database login issued per request with a short lease; revoking it ends a live session | `e2e-dynamic-db.sh` | fill after running | fill after running |

**Exit criteria:** tests 1–7, 10 and 11 pass; test 12 is scored, not
required. The licence count comes from test 5's discovery output, so the
quote comes after discovery.

## 8. Microsoft licensing and risks

US list prices from Microsoft's Entra pricing page, read 2026-10-20; annual
commitment, before EA or CSP discounts.

| Capability Contoso uses | SKU | List price | Note |
|---|---|---|---|
| SSO, MFA, Conditional Access, HR- and API-driven provisioning | Entra ID P1 | $7.00 /user/mo | In M365 E3 and E5 |
| PIM, ID Protection and risk-based CA, basic reviews and entitlement management | Entra ID P2 | $10.00 /user/mo | In M365 E5 |
| Lifecycle Workflows, member-user reviews, automatic assignment, sponsors | Entra ID Governance (on P1 or P2) | $7.00 /user/mo standalone | Contoso would buy the step-up for P2 (quote-based). Licences cover every member in scope of governance features; Lifecycle Workflows touch every joiner and leaver, so assume all 5,000 |
| CA for workload identities | Workload ID Premium | $3.00 /workload identity/mo | Managed identities and workload identity federation are free; the two pipeline service principals are the first candidates |

The standalone Governance ceiling is 5,000 × $7 × 12 = **$420,000 a year**
at list price, not a quote.

| Risk | Compensating control |
|---|---|
| **CyberArk ownership change** (Palo Alto Networks, Idira brand): pricing, bundling or roadmap may shift | A multi-year price hold; keep the challenger's POC results current and the CyberArk vocabulary map (ADR 0007) so the move stays portable |
| **PAM SaaS stores ePHI-adjacent recordings** | A signed BAA is an exit criterion (test 10); Compliance owns the recording retention period |
| **Entra can't govern EHR entitlements** | Owner attestations plus custom-data reviews, tracked as trigger 1; toxic combinations as separate packages |
| **The desk-review scores are judgement** | Every score is replaced by a POC result before purchase |

## Revisit trigger

Quotes arrive (re-score both row 7s); the POC completes; any §6 trigger
fires; a vendor event (acquisition, major price change, end of life); the
annual review, 2027-10-20.

## Sources (accessed 2026-10-20)

1. Microsoft, "Microsoft Entra plans and pricing": https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing
2. Microsoft Learn, "Microsoft Entra ID Governance licensing fundamentals": https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals
3. Microsoft Learn, "Frequently asked questions about Microsoft Entra Workload ID": https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-faqs
4. Microsoft Learn, "On-premises application provisioning architecture": https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-application-provisioning-architecture
5. Palo Alto Networks Form 10-Q, quarter ending 2026-01-31 (CyberArk acquisition completed 2026-02-11): https://www.sec.gov/Archives/edgar/data/1327567/000132756726000005/panw-20260131.htm
6. SiliconANGLE, "Idira launches…", 2026-05-12: https://siliconangle.com/2026/05/12/idira-launches-palo-alto-networks-extends-cyberark-tech-machine-agentic-identities/
7. CyberArk, Secrets Hub: https://www.cyberark.com/products/secrets-hub/
8. CyberArk press release, 2025 Gartner MQ for PAM: https://www.cyberark.com/press/cyberark-named-a-leader-in-the-2025-gartner-magic-quadrant-for-privileged-access-management/
9. BeyondTrust press release, 2025 Gartner MQ for PAM: https://www.beyondtrust.com/press/2025-gartner-magic-quadrant-privileged-access-management
10. BeyondTrust docs, Entra ID (SAML) for PRA: https://docs.beyondtrust.com/pra/v25.2/docs/entra-id-saml
11. Delinea, StrongDM acquisition, 2026-03-05: https://delinea.com/news/delinea-acquires-strongdm-to-secure-ai-with-continuous-authorization
12. SailPoint, Epic Systems connector: https://www.sailpoint.com/products/connectivity-and-integrations/catalog/epic-systems
13. Saviynt, Epic integration: https://saviynt.com/integrations/epic/
