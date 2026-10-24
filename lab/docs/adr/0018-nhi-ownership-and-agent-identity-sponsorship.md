# ADR 0018: Non-human identity ownership and agent identity sponsorship

- **Status:** Accepted (lab). BUILT: the inventory, secrets register check, app management policy, consent policy, leaver hand-off and agent identity scripts, with offline Pester tests against mocks. No tenant exists, so no NHI has been inventoried and no agent identity exists.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

A workforce identity has HR as its source of truth: the leaver feed
disables it. A non-human identity (NHI) has no HR record. **Its owner is its
only lifecycle anchor:** the only person who rotates its credential, attests
its permissions or notices it is unused. When the owner leaves, nothing
disables the NHI (OWASP NHI1).

The lab shows the problem on itself: the pipeline apps have no owners,
`midpoint-reader` uses a client secret, APPLY is Tier 0 (ADR 0005), and the
lab's own long-lived secrets outside Entra (stack passwords, the Splunk HEC
token, the Okta client secret) have to be tracked somewhere. Consent
phishing (R04) creates ownerless NHIs with broad scopes.

## Options considered

**Who answers for an NHI:**

1. **The IAM team owns every NHI.** Rejected: IAM can't attest a purpose it
   didn't build for, so it becomes a rubber stamp.
2. **Entra's default: the creator is the owner.** Rejected: one owner, often
   a contractor, who leaves with the knowledge.
3. **Two accountable humans, platform rules that stop the common mistakes,
   a monthly inventory and a leaver hand-off (chosen).**

**What users may consent to:**

1. **No user consent** (CISA SCuBA MS.AAD.5.2's strictest option). Safest
   against consent phishing, but every low-impact "sign in with Microsoft"
   becomes a request, and a queue of trivial requests trains reviewers to
   approve unread. One switch away (`-UserConsent Disabled`).
2. **Microsoft's managed policy.** Rejected: Microsoft decides what it
   allows, so behaviour can change without a code review.
3. **Verified publishers or apps registered here, low-impact scopes only
   (chosen; MS.AAD.5.2's flexible option).** Mail and file scopes, the ones
   consent phishing wants, always go to an admin. `app-consent-granted.kql`
   alerts on grants.

**Agents:** Entra Agent ID (a blueprint and an agent identity) with a named
human sponsor, identity only. An app registration has owners but no sponsor,
and a person's delegated identity makes the agent's actions
indistinguishable from the person's.

## Decision

| Control | Rule | Mechanism |
|---|---|---|
| Ownership | At least two human owners, or one plus a team group | Standard N1; the inventory flags none, no human, all disabled, and single |
| Credentials on new apps | No secrets; certificates 180 days at most | `Set-AppGovernancePolicy.ps1`, for apps created after a cut-off date |
| Credentials on existing apps | New secrets 90 days at most; custom passwords blocked | The same policy: a migration path for `midpoint-reader`, not a cliff |
| Secrets outside Entra | Every one listed by name, owner, store location and dates, never its value | `lab/iga/nhi-secrets-register.json` (12 entries), read by `06-NHI-Inventory.ps1 -SecretsRegisterPath`: SECRET-NO-OWNER, SECRET-EXPIRED, SECRET-NO-EXPIRY, SECRET-NO-ROTATION |
| Consent | Verified publishers or this tenant, low-impact scopes only; anything else to the admin consent workflow (`App-Consent-Reviewers`, 14-day expiry) | `Set-ConsentPolicy.ps1`, which resolves every input before its first write |
| Inventory | Monthly; findings carry OWASP NHI Top 10 IDs, Tier-0 NHIs one severity up, a failed source never reads as clean | `06-NHI-Inventory.ps1` |
| Leaver | Default: report what the leaver owns, change nothing. Opt-in: the manager becomes owner of low-privilege NHIs; Tier-0 ones are flagged, secret-holding ones flagged for rotation | `04-Leaver.ps1`, step 7 |
| Agents | A blueprint and an agent identity, each with a named sponsor; federated from a dedicated managed identity, never a secret; no permission until a reviewed request | `New-AgentIdentity.ps1` |

**Owner vs. sponsor.** An owner can add a credential and act as the
identity; a sponsor answers for purpose and lifecycle with no technical
rights. The scenario agent's sponsor is the nurse manager whose staff's
access it summarises, not an engineer.

## Consequences

- **Owners can become the app,** so owners of Tier-0 NHIs must be Tier-0
  people; `Find-ShadowAdmins.ps1` reports them.
- **The policy guards the future.** Existing secrets live until they expire;
  the inventory finds them, but an orphan can exist for up to a month
  between runs.
- **Not built:** a check for an agent whose only sponsor is disabled, owners
  on the Terraform-managed pipeline apps, disabling orphans after 30 days
  (a rule in the standard only), and owner attestation tooling.
- The AI pull-request reviewer runs under the PLAN identity: it is not an
  agent identity and isn't described as one.

## How it is measured

Fill in after the first tenant run of `06-NHI-Inventory.ps1`.

| Measure | Source | Target |
|---|---|---|
| `nhi_expired_or_orphaned` | `08-Measure-KPIs.ps1` | 0 |
| Apps holding a client secret | `SECRET-PRESENT` findings | Falling to 0; `midpoint-reader` is exception E3 until migrated |
| Registered secrets with no owner, expiry or rotation | `SECRET-*` findings | 0 |
| Tier-0 NHIs with no current risk acceptance | `PERM-TIER0` vs. the exception register | 0 |
| Leaver-owned NHIs with no new owner by the disable date | `04-Leaver.ps1` report | 0 |
| Agent identities with no enabled sponsor | `AGENT-NO-SPONSOR` | 0 |

## Revisit trigger

- The NHI count outgrows a monthly script plus attestation, or NHIs appear
  in a second cloud: evaluate a dedicated NHI security product.
- Microsoft ties app management policies to Workload ID Premium (verify).
- The agent is granted its first permission: add it to the review cycle.

## Evidence

- [`standards/nhi-standard.md`](../standards/nhi-standard.md) (N1–N11)
- `lab/scripts/powershell/06-NHI-Inventory.ps1`, `04-Leaver.ps1` (step 7),
  `post-apply/Set-AppGovernancePolicy.ps1`, `Set-ConsentPolicy.ps1`,
  `New-AgentIdentity.ps1`; tests `NhiGovernance.Tests.ps1`,
  `06-NHI-Inventory.Tests.ps1`
- `lab/iga/nhi-secrets-register.json`
- `lab/kql/app-credential-added.kql`, `app-consent-granted.kql`

## Sources (checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/agent-id/agent-owners-sponsors-managers
- https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md
  (MS.AAD.5.2v1 and its two implementation options)
