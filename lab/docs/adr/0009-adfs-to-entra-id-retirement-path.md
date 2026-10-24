# ADR 0009: AD FS → Entra ID retirement path

- **Status:** Accepted as a design record. DESIGNED: **the lab has no AD FS;** nothing here is built or run.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The scenario assumes a legacy estate: the Microsoft 365 domain is federated
to an on-prem AD FS farm behind Web Application Proxy, which also serves
SAML and WS-Fed relying parties for clinical and business apps. AD FS is
Tier-0-adjacent: its token-signing key can mint a token for any user (the
Golden SAML path), and every sign-in depends on on-prem servers. The target
is the design the lab builds: authentication in Entra, with Conditional
Access and PIM.

## Options considered

1. **Keep AD FS.** No migration risk; the Golden SAML exposure and on-prem
   dependency stay.
2. **Big-bang domain cutover.** Quick, but every user and app meets a defect
   at once, and a 24/7 hospital has no quiet window.
3. **Staged rollout with password hash sync (PHS), then relying parties app
   by app, then domain conversion (chosen).**
4. **Staged rollout with pass-through authentication.** Sign-in still
   depends on on-prem agents; kept only if policy forbids hashes leaving AD.

## Decision

Option 3, in phases, each with its own rollback.

| Phase | What | Exit criterion | Rollback |
|---|---|---|---|
| 0. Inventory | Every relying party with its claim rules, MFA adapters and device-registration dependencies, ranked by sign-in volume | Every relying party has an owner, protocol and target | n/a |
| 1. PHS on, still federated | Password hash sync as fallback; enables leaked-credential detection | Hashes synced for all in-scope users | PHS off |
| 2. Staged rollout | Pilot groups to cloud authentication: IT, one non-clinical department, then one ward with clinical sign-off. CA MFA must already be enforced, because the AD FS MFA adapter stops applying | Pilot sign-ins succeed with no rise in help-desk tickets | Remove the group from staged rollout |
| 3. Relying parties | Each SAML or WS-Fed app rebuilt as an Entra enterprise app, piloted, then switched to Entra metadata (the Okta runbook's per-app pattern) | Zero AD FS sign-ins for the app for an agreed period | Point the app back at AD FS |
| 4. Domain conversion | Convert the domain to managed through Microsoft Graph in the lowest-volume window; save the federation settings first | No new AD FS token issuance | Re-federate from the saved settings |
| 5. Decommission | Remove trusts, WAP, signing and decryption certificates, DNS records and servers | Servers off, then removed | Restore from a backup rehearsed before phase 4 |

## Consequences

- Removes the Golden SAML signing key and an internet-facing WAP tier; CA
  and the sign-in logs see every authentication.
- Clinical stations or badge-tap SSO that depend on AD FS or WS-Trust are
  flagged in phase 0 and move last.
- Legacy-auth clients break: block them with CA (report-only first) before
  phase 2.

## Revisit trigger

- A relying party can't move: decide per app, never keep the whole farm.
- Policy forbids password hashes in the cloud: switch to option 4.

## Evidence

The lab has no AD FS. The parts this path depends on:
[`okta-migration-runbook.md`](../okta-migration-runbook.md) (the same per-app
pattern), `lab/terraform/modules/conditional-access/`,
`lab/scripts/dc/README.md` (Cloud Sync), `lab/scripts/powershell/04-Leaver.ps1`
(session revocation).
