# ADR 0009: AD FS → Entra ID retirement path

- **Status:** Accepted as a design record. Phases 0, 3 and 5 for ONE app are
  **BUILT** in `lab/adfs` (2026-11-07): AD FS on DC01, the Contoso Claims
  Viewer relying party with real claim rules, the Entra app as code with the
  rules converted, a claims diff, a one-command cutover and roll-back, and a
  gated decommission. **Not run yet:** the lab has no AD FS today. The
  tenant's domain is never federated (phases 1, 2 and 4 stay design only).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

This record assumes the scenario's legacy estate. Contoso Health's Microsoft
365 domain is **federated to an on-prem AD FS farm**, with Web Application
Proxy (WAP) servers at the edge. That farm also serves SAML and WS-Fed
relying parties for clinical and business apps.

The target design is the one the lab runs: HR → AD → Cloud Sync → Entra,
with Conditional Access and PIM. In that design, authentication happens in
Entra, not on-prem. AD FS is Tier-0-adjacent infrastructure. Its
token-signing key can mint a token for any user, which is the Golden SAML
attack path. It also carries patching, certificate and WAP overhead and adds
an on-prem dependency to every sign-in.

## Options considered

1. **Keep AD FS.** No migration risk. The Golden SAML exposure, the on-prem
   sign-in dependency and the farm upkeep all stay.
2. **Big-bang domain cutover** to managed authentication for everyone in one
   change window. It's quick, but every user and app is exposed to a defect
   at once. A 24/7 hospital has no quiet window.
3. **Staged rollout with password hash sync (PHS),** then relying parties
   moved one app at a time, then domain conversion and decommission.
4. **Staged rollout with pass-through authentication (PTA)** instead of PHS.
   Password checks stay on-prem, so sign-in depends on on-prem agents and
   DCs. That defeats one goal of the move. It is kept only if policy
   forbids hashes leaving AD.

## Decision

Option 3, in five phases. Each phase has its own rollback.

| Phase | What | Exit criterion | Rollback |
|---|---|---|---|
| 0. Inventory | Export every relying party with its claim rules, MFA adapters, extranet lockout settings, and any device-registration dependency (hybrid join through AD FS). Rank apps by sign-in volume (verify: Entra's AD FS application activity report and its Connect Health prerequisite). | Every relying party has an owner, a protocol and a target | n/a |
| 1. PHS on, still federated | Turn on password hash sync in Cloud Sync while the domain stays federated. It becomes the fallback and enables leaked-credential detection (verify: Cloud Sync PHS behaviour on a federated domain). | Hashes synced for all in-scope users | Turn PHS off |
| 2. Staged rollout | Move pilot groups to cloud authentication through staged rollout: IT first, then one non-clinical department, then one ward with clinical sign-off. The Conditional Access MFA policies must already be enforced, because the AD FS MFA adapter no longer applies to these users. verify: staged rollout limits (groups per feature, nested and dynamic group support). | Pilot sign-ins succeed in the sign-in logs and the helpdesk sees no rise in tickets | Remove the group from staged rollout |
| 3. Relying-party migration | Rebuild each SAML or WS-Fed app as an Entra enterprise app with the same claims, pilot it, then switch the app to Entra metadata. Same per-app pattern as the Okta runbook. | Zero AD FS sign-ins for the app for an agreed period | Point the app back at the AD FS metadata |
| 4. Domain conversion | Convert the federated domain to managed through Microsoft Graph, in the lowest-volume window with on-call staff ready. Save the federation settings first. verify: current Graph cmdlets for domain conversion; MSOnline is retired. | All users cloud-authenticated, and the AD FS audit log shows no new token issuance | Re-federate from the saved settings |
| 5. Decommission | Remove the relying-party trusts, WAP, token-signing and decryption certificates, the DNS records and the servers | AD FS servers powered off, then removed | Restore from backup (rehearsed before phase 4) |

## Consequences

**Positive**
- Removes the Golden SAML signing key and an internet-facing WAP tier.
- Sign-in no longer depends on on-prem servers. CA, Identity Protection and
  the sign-in logs see every authentication.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| An administrator can't sign in during cutover | Two cloud-only break-glass accounts, excluded from CA and alerted on (written as code in the lab, not yet applied to a tenant: `modules/groups`, `modules/conditional-access`, `lab/kql/`) |
| An AD-disabled user can still use the cloud between syncs | The leaver path revokes sessions in Entra (`04-Leaver.ps1`, `revokeSignInSessions`), and HR-driven disable starts in the feed. Measure the HR-to-disable minutes after the first run (fill after running). |
| Clinical shared workstations or badge-tap SSO depend on AD FS or WS-Trust | Phase 0 flags them. They move last, after testing against the vendor's Entra guidance (verify per vendor). |
| Password expiry and lockout behave differently under PHS | Document the cloud password policy for synced users and rely on smart lockout in place of extranet lockout (verify: the setting for enforcing cloud password policy on synced users) |
| Hashes leave AD | PHS syncs a derived hash, not the AD hash itself (verify: Microsoft's PHS security description). If policy forbids it, fall back to option 4. |
| Legacy and basic-auth clients break | Block legacy authentication with CA (report-only first) before phase 2 |

## Revisit trigger

- A relying party can't move to Entra (a protocol or vendor limit). Decide
  per app whether to keep a minimal AD FS or retire the app. Don't keep the
  whole farm for it.
- Policy forbids password hashes in the cloud. Switch to option 4.
- The scenario's estate turns out to use Entra Connect Sync rather than
  Cloud Sync. Re-check the PHS and staged-rollout prerequisites for that
  engine.

## Evidence

The one-app path: `lab/adfs/README.md` (run order, owner decisions, cost),
`lab/terraform/modules/apps/claims_viewer.tf` (the rule conversion table),
capture log L10 (local checks only). Before that, the lab had no AD FS. These
files show the parts this path depends on:

- `lab/scripts/dc/README.md`: Cloud Sync agent and OU scope
- `lab/docs/okta-migration-runbook.md`: the same per-app migration and
  rollback pattern. Its "Alternative direction" section discusses staged
  rollout with PHS.
- `lab/terraform/modules/conditional-access/`,
  `lab/terraform/modules/groups/`: CA as code, report-only first,
  break-glass exclusion
- `lab/scripts/powershell/04-Leaver.ps1`: session revocation
