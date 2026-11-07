# ADR 0031: Register the Connect Health agent with no person at the server, and no Conditional Access change

- **Status:** BUILT. Not run. The registration needs the PR that turns `enable_connect_health_registration` on to be merged and applied first. Facts below marked "read" were read live on 2026-11-07 (capture log, rows for this PR).
- **Date:** 2026-11-07
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** when the Connect Health agent version changes, or 2027-02-07
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The AD FS → Entra exercise (`lab/adfs`, ADR 0009) needs Entra's **AD FS
application migration** report. Only the Microsoft Entra Connect Health agent
for AD FS feeds that report. The agent is installed on DC01 (agent 4.5.2487.0,
read). It must be **registered** before it uploads anything.

The owner wants this done with no person at the server and at most $10. Four
routes were checked.

| Route | What we found | Usable? |
|---|---|---|
| 1. Service principal or certificate | Learn ("Install the Microsoft Entra Connect Health agents", updated 2026-10-02) names no service-principal or certificate registration. The agent's cmdlet has no such parameter set (`Get-Command -Syntax` on DC01, read). The only service-principal method found is a 2021 Tech Community sample that says it is "not supported under any Microsoft standard support program". | No |
| 2. An existing lab admin that Claude can sign in as (adm-presenter, adm-*, the operator) | Registration needs Global Administrator or Hybrid Identity Administrator (Learn). No adm-* account holds either (read). Hybrid Identity Administrator comes only from `PIM-Tier0-Hybrid-Identity-Admins`, which has no eligible members, and every Tier 0 activation needs approval from `PIM-Approvers-Tier0`, whose only member is the owner (read). The operator is a service principal, so route 1 applies to it. | Not without a role change |
| 3. Learn's unattended form: `-Credential` with an account "which does *not* have multifactor authentication enabled", plus a CA001 exclusion for it | The agent signs in for scope `https://management.core.windows.net/.default` and then calls **Azure Resource Manager**: `https://management.azure.com/providers/Microsoft.ADHybridHealthService/` (its own registration log on DC01, read with a non-existent user so nothing could register). Since 2025-10-01 ARM requires MFA for every create, update or delete by a user, "regardless of … user exclusions" (Learn, "Plan for mandatory Microsoft Entra MFA"). A password-only sign-in cannot pass that. So a CA001 exclusion would weaken Conditional Access **and** still fail. | No |
| 4. Interactive sign-in by a person (Learn's default) | Works, but needs an RDP session and a person: what the owner wants to avoid. Device code is not offered by the cmdlet and CA010 blocks device code anyway. | Not unattended |

One more fact changes the picture. The current agent's
`Register-MicrosoftEntraConnectHealthAgent` has a parameter set
**`-AadToken <SecureString>`** (and `-EncryptedToken`), read on DC01. Learn does
not describe it. It takes the access token the agent would otherwise get by
itself.

## Decision

1. **No Conditional Access policy changes.** CA001 keeps excluding only the
   break-glass group. Route 3 is rejected because it would not work (mandatory
   MFA at ARM), so the "narrow exclusion if Microsoft documents no other way"
   allowance is not used.
2. **A time-boxed registration account**, as code (`envs/dev/connect_health_registration.tf`):
   `adm-connecthealth-reg@<onmicrosoft domain>`, cloud-only, no licence, with
   an **active Hybrid Identity Administrator** assignment, behind the flag
   `enable_connect_health_registration` (off in `lab.tfvars`).
   - The time box: `connect_health_registration_until_utc` is required while
     the flag is on, and every envs/dev plan after that time **fails**. So a
     forgotten window blocks the next apply instead of staying open.
   - It skips PIM on purpose. PIM would need the owner's approval, which is
     the human step this replaces. The review of the flag-on PR is the
     approval.
3. **The account signs in with a passkey**, never a password. The operator
   issues a one-time Temporary Access Pass, and `passkey.mjs register` adds a
   passkey through CA009's TAP door, the same way the adm-* and break-glass
   passkeys were made. A passkey is phishing-resistant MFA, so CA001 and ARM's
   mandatory MFA are both met.
4. **The agent is registered with `-AadToken`.** `get-agent-token.mjs` signs
   in headless with the passkey (authorization code + PKCE) for the agent's
   own client id `cf6d7e68-f018-4e0a-a7b3-126e053fb88d` and scope, and puts the
   access token in the Keychain. `run-on-dc.py` passes it to
   `12b-Register-ConnectHealthAgent.ps1` as a **protected** parameter. The
   Keychain item is deleted in a trap. No refresh token is requested.
5. **Close at once:** `register.sh close` disables the account and revokes its
   sessions right after the registration. The flag-off PR then deletes the
   account and the role.

## Consequences

- `-AadToken` is a real parameter of Microsoft's signed cmdlet, but it is
  **undocumented**. A future agent build may drop or change it.
  `12b-Register-ConnectHealthAgent.ps1` refuses to run when the parameter is
  missing. The fallback is route 4 (a person, about 5 minutes).
- For the window (planned: under 1 hour; at most the end time in the PR), a
  Tier 0 role is held by an account outside PIM. Mitigations: passkey-only
  sign-in, no licence, no group, disabled straight after use, deleted by the
  next PR, and the Sentinel privileged-role rules see the assignment (expected
  alert: say so in the flag-on PR).
- The account's Terraform-made password sits in state like every
  `azuread_user`'s. It is never read or used, and it is deleted with the
  account.
- Proven so far (2026-11-07): the token flow (passkey sign-in → code → token
  for the agent's client id) was run as `adm-presenter` with `--dry-run`
  (claims checked, token not stored, no registration attempted). Not proven:
  the registration itself, until the window opens.

## Alternatives rejected

- **CA001 exclusion + `-Credential`:** weakens CA and fails at ARM (route 3).
- **Use a break-glass account:** they are for emergencies, every sign-in raises
  a High incident, and they would still need a password-only path.
- **Make an adm-* account eligible in PIM:** activation still needs the
  owner's approval.
- **Give the role to adm-presenter:** it is the read-only presenter identity;
  mixing a Tier 0 role into it breaks what it is for.
