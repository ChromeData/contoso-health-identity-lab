# Threat model: named identity incidents mapped to lab controls

**Status:** Draft · **Date:** 2026-10-20 · **Scope:** Contoso Health lab
scenario (fictional 5,000-user hospital).

This page takes five public incidents and, for each step of the attack,
names the lab control meant to stop it, the detection meant to catch it,
and the gap that remains. Risk IDs (R01–R16) are in `risk-register.md`.

**Evidence level.** No tenant exists. Every Entra and Azure control named
here is BUILT or DESIGNED, and every Conditional Access policy starts
report-only. The 22 KQL rules have run only on the local Azure Data
Explorer Kusto emulator against synthetic events (22/22 rules, 223 cases
PASS, `lab/evidence/kusto/`): that shows the queries' logic, not that
Sentinel schedules them or what a tenant's logs contain. The PAM controls
RAN · harness against a Samba DC (`lab/evidence/pam/`).

## Incidents to controls

| Incident and attack step | Lab control that prevents it | Detection that catches it | Residual gap |
|---|---|---|---|
| **Midnight Blizzard, 2024 (1).** Password spray against a legacy, non-production test-tenant account with no MFA. Traffic came from residential proxies. | CA001 (MFA for all users) and CA003 (block legacy auth); CA006 and CA007 (user and sign-in risk); CA008 (phishing-resistant strength, pilot first). All BUILT, report-only | `failed-signin-spike.kql`, `identity-risk.kql`, `legacy-auth.kql` | The spray rule needs 10 failures from one IP in 10 minutes, so a low-and-slow spray from residential proxies evades it; risk detection is the backstop. Test tenants are outside this baseline (R08) |
| **Midnight Blizzard (2).** A compromised legacy test OAuth app with elevated access was used to create more OAuth apps and grant Exchange `full_access_as_app` (mailbox access). | NHI standard N1, N2 and N6: owners, no secrets, and Tier-0 permissions need a risk acceptance. BUILT: the app management policy rejects secrets on new apps (`Set-AppGovernancePolicy.ps1`); user consent limited and an admin consent workflow (`Set-ConsentPolicy.ps1`); `06-NHI-Inventory.ps1` flags orphaned, secret-bearing and Tier-0 apps; `Find-ShadowAdmins.ps1` finds who can add a credential to a Tier-0 app (offline only) | `app-credential-added.kql`, `app-consent-granted.kql` (including application permissions), `role-assigned-outside-pim.kql` | User CA doesn't apply to workload identities (that needs Workload ID Premium). The policy doesn't block certificates, and an admin can still grant an application permission; the inventory and the rules detect that, they don't prevent it (R05) |
| **Snowflake / UNC5537, 2024.** Credentials stolen by infostealers (some from contractors' personal machines) were used against accounts with no MFA. Some were unrotated since late 2020, and there were no network allow lists. | The app intake requires SSO, so CA001, CA008 and CA004 apply ([standards/app-onboarding-intake.md](standards/app-onboarding-intake.md)). CA006 forces a secure password change at high user risk, which leaked-credential detections raise. Contractor access comes from expiring packages (ADR 0012) | `identity-risk.kql` (leaked credentials, anomalous token), `blocked-country-signin.kql` | Local accounts that bypass SSO are invisible unless the intake finds them. Stolen session cookies get past MFA (R03); token protection is BUILT only as a report-only pilot on one device (CA011, `Set-TokenProtectionPolicy.ps1`) |
| **Change Healthcare, 2024.** Compromised credentials were used on a Citrix remote-access portal with no MFA. The attackers moved laterally and took data; ransomware followed nine days later. | No remote-access portal outside Entra. Remote access is onboarded as an app behind CA001 and CA008. The Tier-0 path is limited to single `/32` operator addresses (BUILT), vaulted, ticket-gated with dual control (two distinct approvers, neither the requester), per person and recorded (RAN · harness against the Samba DC; ADR 0007, ADR 0013). Clinical database access uses a new login per request with a 1-hour lease, so there is no standing password to steal (RAN · harness, `lab/pam/dynamic-db/`) | `failed-signin-spike.kql`, `identity-risk.kql`. On the AD side: `dc-logon-outside-operator-allowlist.kql`, `tier0-logon-without-checkout.kql`, `ad-privileged-group-change.kql`, `kerberoast-rc4-service-ticket.kql`, `dcsync-replication-request.kql`. On the vault side: `vault-privileged-access-anomaly.kql` | A gateway that isn't federated to Entra is outside this design. DC01's public IP in the lab is risk R13. None of the AD-plane rules has run on DC01; the harness has no Windows Security log |
| **MGM Resorts, 2023 (Scattered Spider).** A call to the help desk got a password or MFA reset, followed by sign-in as the victim. CISA AA23-320A adds the persistence step: the actors then register their own MFA tokens. | Help-desk verification ladder: no knowledge-only checks, callback to the HR-record number, results never delivered to the caller ([runbooks/help-desk-identity-verification.md](runbooks/help-desk-identity-verification.md)). BUILT: help-desk roles scoped to an administrative unit of non-privileged users, so the desk can't reset an admin; CA009 requires a one-time TAP or a phishing-resistant method to register security info; CA002 and CA008 remove push fatigue and SIM swap; CA021 requires a fresh phishing-resistant sign-in to activate a Tier-0 role (auth context `c1`); CA023 puts a step-up (auth context `c2`) on changing or deleting CA policies and named locations (BUILT, report-only; binding `c2` to those protected actions is a tenant-time step once CA023 is enforced) | `auth-method-changed-by-admin.kql` and `security-info-registered-risky.kql` for the method change; then what attackers do next: `ca-policy-changed.kql`, `role-assigned-outside-pim.kql`, `pim-activation.kql`, `pim-activation-without-auth-context.kql`, `break-glass-signin.kql` | A TAP the help desk was tricked into issuing satisfies CA009 by design, so the verification ladder is the real control (R14). A social-engineered reset looks exactly like a real one in the audit log; matching each alert to a ticket is manual. Containment doesn't close this step for HR-sourced staff: their accounts are only flagged for disable in AD, and CA006's MFA plus password change can be passed with the attacker's own registered method until someone disables the account and cleans its methods (R03) |
| **Storm-2372, device code phishing (Microsoft Threat Intelligence, 2025).** Since August 2024, a lure such as a fake meeting invite sent a real Microsoft device-code sign-in with the attacker's code. The victim signed in and passed MFA; the attacker's client received the tokens. Health is among the sectors Microsoft lists. | CA010 blocks device code flow for all users, break-glass excluded, with an exception group for any device that genuinely needs it (BUILT, report-only). Microsoft's own guidance is to block device code flow wherever possible | `device-code-signin.kql`: before CA010 is enforced it shows every device-code session; after, any success means the block has a gap | Once CA010 is enforced, later refreshes of a session that began with device code are blocked too (protocol tracking, to be confirmed on the first tenant run), but an access token already issued stays valid until it expires or the sessions are revoked by containment. Until CA010 graduates, the rule is detective only. Consent phishing is a separate token path (R04) |

## Detections

22 rules in `lab/kql/`, each with an SPL twin in `lab/splunk/detections/`,
each computing its own severity and mapping the one account containment
would act on. Deployed by `modules/monitoring` in three sets: **core
sign-in and PIM** (5), **identity ITDR** (7: app credentials and consent,
CA changes, roles or PIM-group members added outside PIM, admin method
changes, identity risk) and the **AD plane and second wave** (10: unvaulted
Tier-0 logons, privileged-group adds, Kerberoasting, DCSync, DC logons
outside the operator allowlist, vault misuse, device-code sign-in, risky
security-info registration, SoD pairs completed, Tier-0 activation without
the step-up). The SoD and vault rules never trigger containment: disabling
a clinician over an SoD conflict would be a patient-safety event. The full
list, with what each catches and misses, is in `lab/kql/README.md`.

**Not covered by a rule yet:** the APPLY pipeline identity used outside a
workflow (R01; the rules already recognise APPLY only by immutable id, so an
app that merely carries its name is High), and bulk HR attribute changes
that would move birthright access (R10).

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
