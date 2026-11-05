# ADR 0018: Non-human identity ownership and agent identity sponsorship

- **Status:** Accepted (lab). BUILT: the inventory, app management policy, consent policy, leaver hand-off and agent identity scripts, with offline Pester tests against mocks. Applied: `enable_nhi_governance` is on in the lab tenant; `enable_agent_identity` is still off, so no agent identity exists. RAN · tenant: the inventory (capture-log E70, E70a) and named owners per `lab/iga/nhi-owners.json` (amendment 2026-11-05).
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

A workforce identity has HR as its source of truth: the leaver feed
disables it. A non-human identity (NHI) has no HR record. **Its owner is
its only lifecycle anchor:** the only person who rotates its credential,
attests its permissions or notices that it's unused. When the owner
leaves, nothing disables the NHI (OWASP NHI1).

The lab shows the problem on itself. The pipeline apps have no owners,
`midpoint-reader` uses a client secret, APPLY is Tier 0 (ADR 0005), and
the AI pull-request reviewer runs under the PLAN identity, so it isn't an
agent identity. Consent phishing (R04) creates ownerless NHIs with broad
scopes, and AI agents act on their own, so someone must answer for them.

## Options considered

**Who answers for an NHI:**

1. **The IAM team owns every NHI.** Rejected: IAM can't attest a purpose
   it didn't build for, so it becomes a rubber stamp, and one team holds
   credential rights over everything.
2. **Entra's default: the creator is the owner.** Rejected: one owner,
   often a contractor, who leaves with the knowledge.
3. **Two accountable humans, platform rules that stop the common mistakes,
   a monthly inventory, and a leaver hand-off (chosen).**

**What users may consent to:**

1. **No user consent** (CISA SCuBA MS.AAD.5.2, its most restrictive
   option; `-UserConsent Disabled`). The safest against consent phishing
   (R04). Rejected as the default: every "sign in with Microsoft" to a
   low-impact app becomes a request to `App-Consent-Reviewers`, and a
   queue of low-impact requests trains reviewers to approve without
   reading. It stays one switch away.
2. **Microsoft's managed policy** (`microsoft-user-default-recommended`).
   Rejected: Microsoft decides what it allows, so behaviour can change
   without a code review (verify: what it allows today).
3. **Verified publishers or apps registered here, low-impact scopes only
   (chosen; SCuBA MS.AAD.5.2's more flexible option).** The scopes consent
   phishing wants, such as mail and files, always go to an admin. Residual
   risk: a verified publisher can still turn malicious, and
   `offline_access` plus `User.Read` is a lasting read of the user's
   profile. `app-consent-granted.kql` alerts on grants.

**How an AI agent gets an identity.** Kept short on purpose: no agent
exists, and none holds a permission. Entra Agent ID (a blueprint and an
agent identity) with a named human sponsor is chosen. An app registration
was rejected because it has owners but no sponsor, so nobody without
technical rights answers for it, and nothing in the directory marks it as
an agent. A person's delegated identity was rejected because the agent's
actions can't be told apart from the person's. A group as sponsor survives
leavers, but any member can disable the agent and no one person answers
for it, so it was rejected for now.

## Decision

| Control | Rule | Mechanism |
|---|---|---|
| Ownership | At least two human owners, or one plus a team group | Standard N1. The inventory flags no owner, no human owner, all owners disabled, and a single owner |
| Credentials on new apps | No secrets or symmetric keys. Certificates last 180 days at most | `Set-AppGovernancePolicy.ps1`, the tenant's default app management policy, for apps created after a cut-off date |
| Credentials on existing apps | New secrets last 90 days at most. Custom passwords are blocked everywhere | The same policy. This is a migration path for `midpoint-reader`, not a cliff |
| Consent | Users can consent only to apps from verified publishers or registered in this tenant, for low-impact scopes (`openid`, `profile`, `email`, `offline_access`, `User.Read`). Anything else goes to the admin consent workflow, reviewed by `App-Consent-Reviewers`, and expires after 14 days | `Set-ConsentPolicy.ps1`, which resolves every input before its first write |
| Inventory | Monthly. Findings carry OWASP NHI Top 10 IDs, severity rises one level for Tier-0 NHIs, and a failed data source never reads as clean | `06-NHI-Inventory.ps1` |
| Leaver | Default: report what the leaver owns and change nothing. Opt-in: add the manager as owner, then remove the leaver, for low-privilege NHIs only. Tier-0 and role-holding NHIs are always flagged for app governance; NHIs with a secret are flagged for rotation | `04-Leaver.ps1`, step 7 |
| Agents | A blueprint and an agent identity, each with a named sponsor. The credential is federated from a dedicated user-assigned managed identity, never a secret. No permission is granted until a reviewed request asks for one | `New-AgentIdentity.ps1`, which stops rather than fall back to an app registration |

**Owner vs. sponsor.** An owner can add a credential and act as the
identity; a sponsor answers for the agent's purpose and lifecycle with no
technical rights. So the scenario agent's sponsor is the nurse manager
whose staff's access it summarises, not an engineer.

## Consequences

- **Owners can become the app,** and two owners double that exposure. Owners
  of Tier-0 NHIs must be Tier-0 people; `Find-ShadowAdmins.ps1` reports
  them. (Superseded 2026-11-05: Tier-0 NHIs have no Entra owner at all, see
  the amendment.)
- **The policy guards the future.** It blocks creates and updates, so
  existing secrets live until they expire; the inventory finds them, but
  an orphan can exist for up to a month between runs.
- **Not built:**
  - **A departing sponsor is missed.** The leaver step reads
    `ownedObjects`, and the inventory flags an agent with no sponsor but
    not one whose only sponsor is disabled. verify: whether a lifecycle
    workflow or Microsoft moves sponsorship to the sponsor's manager.
  - ~~Owners on the Terraform-managed pipeline apps.~~ Built 2026-11-05:
    `envs/bootstrap` `pipeline_owner_object_ids`, `envs/operator`
    `operator_owner_object_ids`, `modules/apps` (two owners or a warning).
  - Disabling orphans after 30 days, which exists only as a rule in the
    standard.
  - Registering raw-Graph agents in the Microsoft 365 agent registry.
- verify: whether app management policies need Workload ID Premium.

## How it is measured

Fill this in after the first tenant run of `06-NHI-Inventory.ps1`.

| Measure | Source | Target |
|---|---|---|
| `nhi_expired_or_orphaned` (split into expired credential and orphaned) | `08-Measure-KPIs.ps1`, from the inventory | 0 |
| Apps holding a client secret | `SECRET-PRESENT` findings | Falling to 0; `midpoint-reader` is a registered exception until migrated |
| Tier-0 NHIs with no current risk acceptance | `PERM-TIER0` findings vs. the exception register | 0 |
| Leaver-owned NHIs with no new owner by the disable date | `04-Leaver.ps1` report | 0 |
| Agent identities with no enabled sponsor | `AGENT-NO-SPONSOR` (the disabled-sponsor check isn't built) | 0 |

## Amendment 2026-11-05: who owns what

`lab/iga/nhi-owners.json` is the register: every robot account in the
tenant, its owner model, its owners, where the list lives (Terraform or a
one-time post-apply step) and why. `06-NHI-Inventory.ps1 -OwnersRegisterPath`
reads it.

An Entra owner can add a credential and act **as** the app, so ownership is
power. Two owner models follow from that:

1. **Tier-0 identities have NO Entra owner** (lead decision, 2026-11-05).
   These are APPLY, PLAN (it reads the envs/dev state, which holds the
   generated break-glass passwords), the lab operator, EVIDENCE (it writes the
   audit evidence) and HR-SYNC (its uploads create and disable workforce
   accounts). A standing owner of one of them would hold that power with no
   PIM activation, against ADR 0020's zero standing access. Their accountable
   owner is a **role**, the Identity Platform Owner (the risk owner in ADR 0005
   and ADR 0024). It answers for purpose, permissions and credentials and
   changes them only through reviewed code. `modules/pipeline-identity` and
   `envs/operator` set `owners = []`, so an owner added in the portal is
   removed by the next apply. The inventory counts a role-owned identity as
   owned while it has no Entra owner. It flags `OWNER-TIER0` on any Tier-0
   identity that has one, whether Tier 0 comes from a permission, a directory
   role or the register. A look-alike app with the same display name is never
   covered: a duplicate name leaves both unowned.
   This replaces this ADR's earlier "owners of Tier-0 NHIs must be Tier-0
   people": no person owns them.
2. **Every other robot account has two named admin owners.** The SSO and
   provisioning apps (`modules/apps`, secret `TF_APP_OWNER_OBJECT_IDS`) and
   P2P Server have `adm-ava.lin` and `adm-mei.tanaka`; `modules/apps` warns
   on every plan with fewer than two. **SOD-08**: the access governance lead
   certifies access, so she does not own an identity that creates or
   disables accounts. The HR provisioning app and the Cloud Sync app
   (`corp.contosohealthlab.com`) have `adm-ava.lin` and `adm-raj.patel`.
   Raj is on SOD-08's administration side only: he certifies nothing and
   reviews nothing. He owns the app **registrations** only, because their
   jobs live on the service principals, which the help desk does not own.
   That keeps the restricted VIP unit out of the help desk's reach.

Managed identities (owned through Azure RBAC on their resource) and
Microsoft's own apps are out of scope, with the reasons in the register.

## Revisit trigger

- The NHI count outgrows a monthly script plus owner attestation, or NHIs
  appear in a second cloud: evaluate a dedicated NHI security product.
- Microsoft makes app management policies require Workload ID Premium.
- The agent is granted its first permission: add its permissions to the
  access review cycle.
- Agent ID changes how sponsors work, or documents an automatic sponsor
  hand-off.

## Evidence

- `lab/docs/standards/nhi-standard.md` (rules N1–N11)
- `lab/scripts/powershell/06-NHI-Inventory.ps1` (finding codes, OWASP
  mapping, `-Offline` mock tenant)
- `lab/scripts/powershell/post-apply/Set-AppGovernancePolicy.ps1`
- `lab/scripts/powershell/post-apply/Set-ConsentPolicy.ps1`
- `lab/scripts/powershell/post-apply/New-AgentIdentity.ps1`
- `lab/scripts/powershell/04-Leaver.ps1` (step 7)
- `lab/scripts/powershell/tests/NhiGovernance.Tests.ps1`,
  `lab/scripts/powershell/tests/06-NHI-Inventory.Tests.ps1`
- `lab/kql/app-credential-added.kql`, `lab/kql/app-consent-granted.kql`

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/entra/agent-id/agent-owners-sponsors-managers
  (owners optional and technical; sponsors required, no technical admin
  access; which group types can sponsor)

## Sources (other, checked 2026-10-20)

- https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md
  (MS.AAD.5.2v1: user consent shall be restricted; its two implementation
  options are no user consent, or verified publishers with low-risk
  permissions)
