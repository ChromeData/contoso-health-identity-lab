# Threat model: named identity incidents mapped to lab controls

**Status:** Draft · **Date:** 2026-10-20 · **Scope:** Contoso Health lab
scenario (fictional 5,000-user hospital).

This page takes five public incidents and, for each step of the attack,
names the lab control meant to stop it, the detection meant to catch it,
and the gap that remains. Risk IDs (R01–R16) are in `risk-register.md`.

**Evidence level.** The lab runs in a real tenant since 2026-10-27 (64 merged
pull requests). Every Entra and Azure control named here is **RAN · tenant**,
**BUILT** (offline-tested code) or **DESIGNED** (written down). Of 11 Conditional
Access policies, 9 are enforced; CA002 and CA021 are report-only. 17 KQL rules
are scheduled in Sentinel (E15, E15b).
The only things that have **RAN · harness** are local harnesses. On
2026-10-20: the PAM stand-ins against a Samba AD DC (284/284), the
500-account discovery-to-reconciliation run (79/79), the midPoint
certification campaign (91/91), Vault dynamic database credentials (60/60),
the Vault audit feed for the PAM anomaly detection (63 passed, 1 skipped; the
detection's predicates re-stated in `jq`, not the KQL) and Kubernetes
workload identity on kind (64/64). On 2026-10-21: the 22 KQL detections on
the Azure Data Explorer Kusto emulator, a local KQL engine, with synthetic
tables and events and a shimmed `_GetWatchlist` (22/22 rules, 261/261 cases
PASS). The emulator is not a Log Analytics workspace and not a tenant, so it
shows the queries' logic, not that Sentinel schedules them or that a
tenant's logs look like the synthetic rows. Their hashed run records
are in `lab/evidence/` (index: `lab/evidence/README.md`).

## Incidents to controls

| Incident and attack step | Lab control that prevents it | Detection that catches it | Residual gap |
|---|---|---|---|
| **Midnight Blizzard, 2024 (1).** Password spray against a legacy, non-production test-tenant account with no MFA. Traffic came from residential proxies. | CA001 (MFA for all users) and CA003 (block legacy auth); CA006 and CA007 (user and sign-in risk); CA008 (phishing-resistant strength, pilot first). All BUILT, report-only | `failed-signin-spike.kql`, `identity-risk.kql`, `legacy-auth.kql` | The spray rule needs 10 failures from one IP in 10 minutes, so a low-and-slow spray from residential proxies evades it; risk detection is the backstop. Test tenants are outside this baseline (R08) |
| **Midnight Blizzard (2).** A compromised legacy test OAuth app with elevated access was used to create more OAuth apps and grant Exchange `full_access_as_app` (mailbox access). | NHI standard N1, N2 and N6: owners, no secrets, and Tier-0 permissions need a risk acceptance. BUILT: the app management policy rejects secrets on new apps (`Set-AppGovernancePolicy.ps1`); user consent limited and an admin consent workflow (`Set-ConsentPolicy.ps1`); `06-NHI-Inventory.ps1` flags orphaned, secret-bearing and Tier-0 apps; `Find-ShadowAdmins.ps1` finds who can add a credential to a Tier-0 app (offline only) | `app-credential-added.kql`, `app-consent-granted.kql` (including application permissions), `role-assigned-outside-pim.kql` | User CA doesn't apply to workload identities (that needs Workload ID Premium). The policy doesn't block certificates, and an admin can still grant an application permission; the inventory and the rules detect that, they don't prevent it (R05) |
| **Snowflake / UNC5537, 2024.** Credentials stolen by infostealers (some from contractors' personal machines) were used against accounts with no MFA. Some were unrotated since late 2020, and there were no network allow lists. | The app intake requires SSO, so CA001, CA008 and CA004 apply ([standards/app-onboarding-intake.md](standards/app-onboarding-intake.md)). CA006 forces a secure password change at high user risk, which leaked-credential detections raise. Contractor access comes from expiring packages (ADR 0012) | `identity-risk.kql` (leaked credentials, anomalous token), `blocked-country-signin.kql` | Local accounts that bypass SSO are invisible unless the intake finds them. Stolen session cookies get past MFA (R03); token protection is BUILT only as a report-only pilot on one device (CA011, `Set-TokenProtectionPolicy.ps1`) |
| **Change Healthcare, 2024.** Compromised credentials were used on a Citrix remote-access portal with no MFA. The attackers moved laterally and took data; ransomware followed nine days later. | No remote-access portal outside Entra. Remote access is onboarded as an app behind CA001 and CA008. The Tier-0 path is limited to single `/32` operator addresses (BUILT), vaulted, ticket-gated with dual control (two distinct approvers, neither the requester), per person and recorded (RAN · harness against the Samba DC; ADR 0007, ADR 0013). Clinical database access uses a new login per request with a 1-hour lease, so there is no standing password to steal (RAN · harness, `lab/pam/dynamic-db/`) | `failed-signin-spike.kql`, `identity-risk.kql`. On the AD side: `dc-logon-outside-operator-allowlist.kql`, `tier0-logon-without-checkout.kql`, `ad-privileged-group-change.kql`, `kerberoast-rc4-service-ticket.kql`, `dcsync-replication-request.kql`. On the vault side: `vault-privileged-access-anomaly.kql` | A gateway that isn't federated to Entra is outside this design. DC01's public IP in the lab is risk R13. None of the AD-plane rules has run on DC01; the harness has no Windows Security log |
| **MGM Resorts, 2023 (Scattered Spider).** A call to the help desk got a password or MFA reset, followed by sign-in as the victim. CISA AA23-320A adds the persistence step: the actors then register their own MFA tokens. | Help-desk verification ladder: no knowledge-only checks, callback to the HR-record number, results never delivered to the caller ([runbooks/help-desk-identity-verification.md](runbooks/help-desk-identity-verification.md)). BUILT: help-desk roles scoped to an administrative unit of non-privileged users, so the desk can't reset an admin; CA009 requires a one-time TAP or a phishing-resistant method to register security info; CA002 and CA008 remove push fatigue and SIM swap; CA021 requires a fresh phishing-resistant sign-in to activate a Tier-0 role (auth context `c1`); CA023 puts a step-up (auth context `c2`) on changing or deleting CA policies and named locations (BUILT, report-only; binding `c2` to those protected actions is a tenant-time step once CA023 is enforced) | `auth-method-changed-by-admin.kql` and `security-info-registered-risky.kql` for the method change; then what attackers do next: `ca-policy-changed.kql`, `role-assigned-outside-pim.kql`, `pim-activation.kql`, `pim-activation-without-auth-context.kql`, `break-glass-signin.kql` | A TAP the help desk was tricked into issuing satisfies CA009 by design, so the verification ladder is the real control (R14). A social-engineered reset looks exactly like a real one in the audit log; matching each alert to a ticket is manual. Containment doesn't close this step for HR-sourced staff: their accounts are only flagged for disable in AD, and CA006's MFA plus password change can be passed with the attacker's own registered method until someone disables the account and cleans its methods (R03) |
| **Storm-2372, device code phishing (Microsoft Threat Intelligence, 2025).** Since August 2024, a lure such as a fake meeting invite sent a real Microsoft device-code sign-in with the attacker's code. The victim signed in and passed MFA; the attacker's client received the tokens. Health is among the sectors Microsoft lists. | CA010 blocks device code flow for all users, break-glass excluded, with an exception group for any device that genuinely needs it (BUILT, report-only). Microsoft's own guidance is to block device code flow wherever possible | `device-code-signin.kql`: before CA010 is enforced it shows every device-code session; after, any success means the block has a gap | Once CA010 is enforced, later refreshes of a session that began with device code are blocked too (protocol tracking; verify on the first run), but an access token already issued stays valid until it expires or the sessions are revoked by containment. Until CA010 graduates, the rule is detective only. Consent phishing is a separate token path (R04) |

## Detections

Every rule is a file in `lab/kql/` with an SPL twin of the same name in
`lab/splunk/detections/`. All 22 are BUILT; 17 are scheduled in Sentinel,
5 held back in `itdr_exclude_rules`. Each computes its own `Severity` column, and each maps one
account entity: the identity containment would act on.

| Group | Files in `lab/kql/` | Deployed by |
|---|---|---|
| Core sign-in and PIM (5) | `pim-activation.kql`, `break-glass-signin.kql`, `blocked-country-signin.kql`, `failed-signin-spike.kql`, `legacy-auth.kql` | `modules/monitoring` (`main.tf`), Sentinel or the Log Analytics alert path |
| Identity ITDR (7) | `app-credential-added.kql`, `app-consent-granted.kql`, `ca-policy-changed.kql` (policies, named locations, authentication strengths), `role-assigned-outside-pim.kql`, `pim-group-member-added-outside-pim.kql`, `auth-method-changed-by-admin.kql`, `identity-risk.kql` | `modules/monitoring` (`itdr.tf`), behind `enable_itdr_detections` |
| AD plane on DC01 (4) | `tier0-logon-without-checkout.kql`, `ad-privileged-group-change.kql`, `kerberoast-rc4-service-ticket.kql`, `dcsync-replication-request.kql` | `modules/monitoring` (`itdr.tf`); need DC01 Security events and the `VaultCheckout_CL` table |
| New on 2026-10-20 (6) | the six below | `modules/monitoring` (`itdr_v2.tf`), behind their own flag `enable_itdr_detections_v2`, so an apply that works today doesn't change. `security-info-registered-risky` and `sod-violation-granted` look back 14 days, so they run on Sentinel only. `sod-violation-granted` and `vault-privileged-access-anomaly` never trigger containment: disabling a clinician over an SoD conflict would be a patient-safety event |

**The six new detections**

| File | What it catches | Control it backs | Incident above |
|---|---|---|---|
| `device-code-signin.kql` | Any sign-in that used the device authorization grant, or a refresh from a session that began with one. High when tokens reached a privileged user or the sign-in risk was medium or high | CA010 (block device code flow). After enforcement, a success means a gap | Storm-2372 |
| `security-info-registered-risky.kql` | A user registering their own MFA or passwordless method from a risky sign-in, a country new to them in 14 days, or an unmanaged device. High for privileged users, a high-risk sign-in, or two or more signals | CA009 (register security info) and the help-desk ladder | MGM / Scattered Spider |
| `dc-logon-outside-operator-allowlist.kql` | An RDP logon to DC01 from any address outside the operator watchlist, or a network logon from a public one. An expired watchlist entry no longer counts | The `/32` NSG allowlist (ADR 0013, R13) | Change Healthcare |
| `vault-privileged-access-anomaly.kql` | Vault-side misuse, one `Signal` column: Tier-0 credential read outside a ticketed check-out, Tier-0 check-out without a ticket, rotation failure, root-token use, failed-login burst, Tier-0 access denied. Each signal names its CyberArk PTA or CPM analogue | Ticket-gated, per-person check-out (R06) | Change Healthcare |
| `sod-violation-granted.kql` | Access delivered that completes a toxic pair from `lab/iga/sod-rules.json`, including a direct add to the group behind a package, which incompatibility links don't stop | Incompatible packages and `09-SoD-Report.ps1` (R15) | n/a (insider: drug diversion) |
| `pim-activation-without-auth-context.kql` | A Tier-0 PIM activation with no step-up sign-in carrying context `c1` beforehand. PREVIEW: some fields are unconfirmed; deploy after the first real activation | CA021 and the PIM `c1` requirement. Microsoft Learn (PIM for Groups settings, checked 2026-10-20): if the context's policy is off, report-only or excludes the user, PIM's MFA fallback doesn't trigger, so a Tier-0 role activates with whatever the session already had | MGM / Scattered Spider |

**Not covered by a rule yet**

- **Misuse of the APPLY pipeline identity (ADR 0005).** The rules recognise
  it only by its immutable ids, and an app that merely carries its display
  name is High (`IacNameSpoof`). A dedicated "APPLY identity used outside the
  workflow" rule is not written yet (R01).
- **Bulk HR attribute changes** that would move birthright access (R10).

## Sources

Each was checked on 2026-10-20.

- **Midnight Blizzard.** Microsoft Security blog, 2024-01-25:
  https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- **Snowflake / UNC5537.** Mandiant (Google Cloud), 2024-06-10. About 165
  organizations were notified:
  https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- **Change Healthcare.** Andrew Witty's written testimony to the Senate
  Finance Committee, 2024-05-01. The intrusion began on February 12:
  https://www.finance.senate.gov/imo/media/doc/0501_witty_testimony.pdf
- **MGM Resorts.** MGM's Form 8-K, 2023-10-05, confirms the incident and its
  impact but does not name the entry vector:
  https://www.sec.gov/Archives/edgar/data/789570/000119312523251667/d461062d8k.htm.
  The technique comes from the CISA/FBI advisory AA23-320A:
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a.
  The help-desk entry at MGM is public reporting, not confirmed by MGM. The
  advisory (updated 2025-07-29) also says the actors register their own MFA
  tokens after compromising an account, and get help desks to transfer an
  employee's MFA to a device they control.
- **Storm-2372.** Microsoft Threat Intelligence, 2025-02-13, with later
  updates. Active since August 2024; health is in the list of targeted
  sectors; Microsoft recommends blocking device code flow wherever possible:
  https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
