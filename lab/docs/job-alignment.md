# Job-market alignment: what senior IAM postings ask for, and where the lab proves it

Checked 2026-10-31 against eleven current postings: Providence (Principal IAM Engineer), Interscripts, Optum, Jefferson Health, Astellas, Leidos (ICAM), Kalles Group (Entra consultant), Optiv (CyberArk), MathWorks (Identity Security), GE Healthcare (PAM), GoHealth. Hospital and regulated employers first, two integrators and one software vendor for contrast.

Plain reading of the table: **Yes** means the lab did it in a real tenant and has an evidence row. **Partly** means it is built or designed but not yet run end to end. **No** means the lab does not cover it.

| What postings ask for | How many of 11 | Lab | Where it is proven |
|---|---|---|---|
| Hybrid Active Directory with Entra sync | 10 | Yes | DC01 (`modules/dc-vm`), Cloud Sync running, joiner and leaver carried AD to Entra (E30 to E52) |
| App onboarding with SAML, OIDC, SCIM | 8 | Yes | AWS SAML plus SCIM (E22, E23), ServiceNow SAML (E57), Okta federation (E58) |
| PowerShell and Microsoft Graph automation | 8 | Yes | 20 scripts under `lab/scripts/powershell`, about a thousand Pester checks |
| Design leadership, stakeholder communication | 8 | Partly | 20 ADRs, CISO brief, operating model; written, not yet operated with a real team |
| Conditional Access, MFA, Zero Trust | 7 | Yes | 11 policies as code, 9 enforced, each graduated through its own reviewed change |
| PIM, just-in-time admin, break-glass, Tier-0 | 7 | Yes | `modules/pim`, 8 Tier-0 and 8 Tier-1 groups, break-glass drill script |
| Identity governance: reviews, entitlements, lifecycle, separation of duties | 7 | Yes | `modules/entitlement`, 9 SoD rules, access reviews, midPoint campaign |
| Runbooks, SOPs, documentation | 7 | Yes | `lab/docs/runbooks`, `your-turn` run sheets |
| Commercial PAM (postings name CyberArk, Delinea, BeyondTrust) | 6 | Partly | The lab chose Microsoft-native PAM instead (ADR 0027): Key Vault, Bastion session recording, Windows LAPS, Intune EPM, PIM. No PAM vendor product is in the lab; the general PAM vocabulary map is in `lab/pam/README.md` |
| Detection, SIEM, incident response | 6 | Yes | 24 detections as code, 17 scheduled in Sentinel, containment playbook; Splunk twins of the first 22 proven on a synthetic replay (22 of 22 fire, E61); Defender for Identity staged as the native AD-attack detector (ADR 0023), with the SecurityEvent rules as its portable twins |
| Joiner, mover, leaver automation | 6 | Yes | Leaver gone from AD in 7 s, Entra under 3 min, AWS in 9 min (E52) |
| Audit evidence for HIPAA, SOX, HITRUST | 6 | Yes | Evidence pack with SHA-256 manifest in tamper-proof storage, compliance crosswalk |
| Infrastructure as code | 5 | Yes | Terraform for Entra, Azure, AWS, Okta; 64 reviewed changes applied by a password-free pipeline |
| Passwordless, FIDO2 | 4 | Partly | Policies written (CA002, CA008, CA021); report-only until passkeys are registered |
| SailPoint or Saviynt experience | 4 | Partly | midPoint stands in; the model (birthright, request, review, SoD) is the same |
| B2B and guest access | 3 | Partly | Guest access packages built; guest MFA and inactive-guest review on the roadmap |
| Sign-in troubleshooting from logs | 3 | Partly | `Diagnose-SignIn.ps1` explains a sign-in in plain words from the correlation id; offline-only (tested against fixtures, not yet run against the tenant's Graph) |
| Non-human and workload identities | 2 | Yes | Inventory, two-owner rule, federated pipeline identities with no secrets |

## Gaps, in the order postings care about them

1. **Commercial PAM vocabulary.** Postings name CyberArk, Delinea and BeyondTrust. The lab decided against a PAM vendor (ADR 0027, 2026-11-06) and does the same jobs with Microsoft products: Key Vault holds secrets, Bastion records admin sessions, Windows LAPS rotates local admin passwords, Intune EPM gives one app admin rights for a short time, and PIM makes roles just-in-time. The general PAM term map (safe, rotation, recorded session) is in `lab/pam/README.md`.
2. **Passwordless enforced, not just written.** Fix: register two passkeys per admin account, run the passwordless rollout script, graduate CA002 and CA021.
3. **Clinical single sign-on.** Hospital postings mention Epic and Imprivata. Fix: a FIDO2 key with fast user switching on the Intune VM as the stand-in, documented as such.
4. **Cross-tenant and multi-tenant.** Two postings. Fix: a second free developer tenant with cross-tenant access settings as Terraform.
5. **Defender for Identity on the domain controller.** One posting. **Closed in code (staged):** MDI is now in the design (ADR 0023) as the primary detector for the native AD signatures, behind `enable_defender_for_identity` — the Defender XDR connector that lands MDI alerts in the lab's workspace is codified (`modules/monitoring/mdi.tf`), and the four SecurityEvent KQL rules are kept as its portable, offline-testable twins (Splunk + Kusto emulator), while `tier0-logon-without-checkout` and `dc-logon-outside-operator-allowlist` stay custom (correlations MDI cannot make). The detection layers: Entra ID Protection (cloud identity risk, live) + Defender for Identity (native AD attacks, staged) + custom detection-as-code on Sentinel with Splunk twins (portable). Remaining human step: the 90-day trial sensor on DC01 (`lab/docs/runbooks/deploy-defender-for-identity-dc01.md`), not yet applied.
6. **Guest MFA and inactive-guest review.** Roadmap item R11.

## What the lab has that postings rarely ask for, and that stands out

- **Configuration drift detection** against a committed zero-drift baseline, nightly (`Compare-IdentityConfig.ps1`, ADR 0021).
- **Tamper-evident evidence**: every page fingerprinted and stored where nobody can edit it, mapped to the control it satisfies. Postings say "produce audit evidence"; none say tamper-evident.
- **Detection as code with tests**: 24 rules; 277 emulator-tested cases for the first 22 and 25 cases run on the Log Analytics query engine for the 2 newest (E114), plus governance for AI agent identities.

Lead with those three. They are the difference between "has done IAM" and "thinks like the person who owns it".
