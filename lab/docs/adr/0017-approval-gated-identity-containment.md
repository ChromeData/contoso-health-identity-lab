# ADR 0017: Approval-gated identity containment

- **Status:** Accepted (lab). BUILT: the playbook template, its deploy script, the AD containment script and the Sentinel automation rule are in code, behind `enable_itdr_containment` (default off), with offline Pester tests of the playbook's logic. DESIGNED only: the cloud block group for confirmed compromises. Not run: no Sentinel workspace exists and no approval card has been answered.
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

A detection with no response leaves the attacker's tokens working. The
[compromised-identity runbook](../runbooks/compromised-identity.md) sets a
lab target: revoke sessions within 15 minutes of triage confirming a
compromise, and disable within 30. Automating that has three hazards:

- **False positives are patient-safety events.** Disabling a charge nurse
  mid-shift because she signed in from a new VPN is a care delay.
- **Detections can be turned into a weapon.** Anyone who can trigger a High
  alert against an account could get it disabled, break-glass included,
  during the incident when it is needed most.
- **The automation's identity is a target.** Whatever can disable users is
  worth stealing.

The design also has to work for hybrid accounts. A synced user is mastered
in AD: Entra rejects a cloud disable, and the next sync would undo it
anyway. AD-only Tier-0 accounts have no Entra object at all.

## Options considered

1. **Fully automatic containment on every High incident.** The fastest.
   Rejected: no person sees the evidence before a clinician loses access,
   and an attacker can aim it.
2. **Notify only; an analyst acts by hand in the portals.** Rejected: it
   depends on whoever is on shift knowing four consoles. It leaves no
   consistent record, and the 15-minute target rests on memory.
3. **Microsoft's automatic attack disruption (Defender XDR) instead of a
   playbook.** In production it runs alongside this playbook, not in place
   of it. It acts on Microsoft's own signals and thresholds, not on this
   lab's detections, and it has no approval step. In the lab it would have
   nothing to act on: no device and no DC is onboarded to Defender for
   Endpoint or Defender for Identity. verify: which disruption scenarios
   the E5 licence covers.
4. **Automation that prepares and executes, with a person approving each
   account in Teams (chosen).**

## Decision

**Trigger.** A Sentinel automation rule fires on new **High** incidents
from the ITDR rules listed in `containment_rule_keys`. It exists only when
`enable_itdr_containment` is on and the playbook is deployed. Incidents are
grouped per identity and per severity, so a High alert is never absorbed
into an older Medium incident.

**Per account, the Logic App:**

1. **Refuses protected accounts.** Break-glass is matched by object ID
   only. A UPN prefix is log-only: anyone who can rename a user could
   otherwise make a compromised account uncontainable.
2. **Escalates restricted-management AU members.** The playbook reads the
   account's administrative units (`memberOf/microsoft.graph.administrativeUnit`,
   `isMemberManagementRestricted`). Graph application permissions don't
   apply to RMAU members, so for one of them it sends no approval card. It
   escalates to an RMAU-scoped human instead (a small, role-assignable
   VIP-support PIM group holding roles scoped to that AU, assigned at
   tenant time), who revokes and disables by hand. If the read fails, the
   playbook records that and continues to the normal approval.
3. **Posts a Teams card:** Contain, Revoke only, or Reject.
   - Only a member of `ITDR-Containment-Approvers` who is not the subject
     can decide.
   - An answer with no responder identity fails closed.
   - No answer within 4 hours means no action.
4. **Contain** means: revoke sign-in sessions; `confirmCompromised` (user
   risk becomes High); then disable the account if it is cloud-only and the
   opt-in role exists, or flag it for an AD disable if it is synced or
   AD-only. **Revoke only** signs the account out everywhere and leaves it
   enabled.
5. **Records** the decision, the approver and every Graph result on the
   incident and the ServiceNow ticket.

**AD side.** A person runs `Invoke-AdContainment.ps1`, which uses
`az vm run-command` on DC01. Running it is the approval for the AD action,
and each run writes an evidence record.

**A confirmed compromise is a block, not a remediation.** High user risk
brings in CA006, which asks for MFA and a password change (ADR 0015).
Anyone who can pass MFA on the account can pass that. Almost the whole
workforce is synced from AD (ADR 0006), so for them Contain only flags the
disable. Until a person runs `Invoke-AdContainment.ps1`, an attacker who
registered their own method can pass CA006, set a password that writes
back to AD and lock the owner out (R14). So:

- The AD disable is the next step after Contain, not a later ticket, and
  its delay is measured.
- The account is re-enabled only after its methods are cleaned
  ([compromised-identity.md](../runbooks/compromised-identity.md) §3).
- **DESIGNED, not built: a cloud block.** Contain adds the user to an
  `ITDR-Contained-Users` group that a block-all CA policy targets
  (break-glass excluded). Once sessions are revoked, the next token
  request fails for synced and cloud-only accounts alike, with no AD step
  and no directory role. Its cost: adding a member app-only needs
  `GroupMember.ReadWrite.All`, which reaches every group that isn't
  role-assignable, so groups that grant Tier-0 access or CA exclusions
  must be role-assignable first (verify which aren't). This is the
  production direction, and it would replace the disable role below.

**Least privilege.** The Logic App's managed identity has five Graph app
roles (`User.Read.All`, `AdministrativeUnit.Read.All` for the RMAU check,
`User.RevokeSessions.All`, `User.EnableDisableAccount.All`,
`IdentityRiskyUser.ReadWrite.All`), plus Microsoft Sentinel Responder
(verify: that `AdministrativeUnit.Read.All` is the least-privileged role
for the RMAU read). For an app-only caller, disabling a user also
needs a directory role, because `accountEnabled` is a sensitive property.
**That role, Authentication Administrator, stays off, which is the
default.**

- **What it would buy is small.** With the workforce mastered in AD, it
  reaches only cloud-only, non-admin accounts, such as guests.
- **What it would expose is large.** Authentication Administrator can also
  reset methods and issue a TAP for any non-admin user, so whoever controls
  the playbook could take over any clinician.
- If it is ever turned on, it is scoped to an administrative unit of
  cloud-only, non-admin accounts (`-DirectoryRoleScope`), never the tenant.
  That AU isn't built, and the script's default is the tenant (`/`).

**Admins are never contained by automation.** That would need Privileged
Authentication Administrator, which would make the Logic App Tier 0.

**The Azure side is part of the trust boundary.** Whoever can edit the
workflow or use its managed identity holds its Graph rights. The playbook
sits in `rg-identity-lab`, which is already Tier 0 because Contributor
there can run commands on DC01. With `enable_pim_azure_resources` on,
people reach Contributor there through an Azure PIM activation with Tier-0
approval (`modules/pim/azure.tf`). Standing access remains for the CI
APPLY identity and, until it is converted, the subscription's bootstrap
Owner. Not built: an alert on changes to the workflow definition or to
role assignments on that resource group.

## Consequences

- **Speed depends on staffing.** A card that arrives at 03:00 with nobody
  watching times out with no action. The 15-minute target needs an on-call
  approver rota, not just a channel.
- **The most dangerous compromises are the slowest.** A compromised admin
  is contained by a person through PIM and the runbook. That is accepted to
  keep the Logic App out of Tier 0.
- **Revocation isn't instant.** Graph says there can be a delay of a few
  minutes. Access tokens already issued stay valid until they expire,
  unless the resource supports continuous access evaluation (verify: token
  lifetimes).
- **On the AD side, issued Kerberos tickets survive a password change.**
  Disabling the account (`Invoke-AdContainment.ps1`) makes the DC refuse
  renewals and new service tickets (verify: on the lab DC), and the user's
  sessions still have to be logged off. Rotating a Tier-0 password through
  a Vault check-in stops new logons with the stolen password or hash. A
  suspected forged ticket means resetting krbtgt twice, a separate
  procedure.
- **If the disable role is ever turned on, it is standing privilege
  outside PIM** and breaks the zero-standing rule (ADR 0020). That is a
  risk acceptance. Risk owner: SOC lead (in the lab, the repository
  maintainer). Next review: 2027-01-20, or when the cloud block is built.
  `role-assigned-outside-pim` alerts once; record that alert. The identity
  is a sensitive NHI in the inventory (ADR 0018). Without the role, the
  disable step returns 403, the playbook records that, and sessions are
  still revoked.
- **The protected list can drift.** Break-glass and approver object IDs are
  fixed at deploy time. Re-run `-VerifyProtectedList` whenever either group
  changes.
- **VIPs in the restricted-management AU are contained by a person.**
  `New-RestrictedAdminUnit.ps1` refuses to add any member until a role is
  assigned at the RMAU's scope, so a responder always exists. verify: which
  containment calls the RMAU blocks, and the Cloud Sync AD-disable path for
  a synced VIP (`Invoke-AdContainment.ps1`).

## How it is measured

Source: Logic App run history, the incident comments and the
`Invoke-AdContainment.ps1` evidence records. Fill this in after the first
run.

| Measure | Target |
|---|---|
| Incident created → card answered (median, p90) | ≤ 15 minutes (runbook) |
| Card answered → Graph actions complete | Minutes |
| Contain → AD disable, synced accounts | ≤ 30 minutes (runbook) |
| Cards that timed out with no answer | 0 |
| Reject share, per rule | Watched. A high share means a noisy rule |
| Contained accounts later classified benign | 0 clinicians |

## Revisit trigger

- A confirmed compromise where the card timed out.
- A false-positive containment of a clinician.
- One rule produces mostly Rejects: tune it, or drop it from
  `containment_rule_keys`.
- Graph offers a way to disable users without a directory role.
- The cloud block is built: drop the disable role.
- Devices and DC01 are onboarded to Defender: turn on attack disruption,
  and drop from `containment_rule_keys` what it already covers.
- The SOC moves to another orchestration platform.

## Evidence

- `lab/monitoring/playbook-contain.json` (including the RMAU check)
- `lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1` (Graph app
  roles, opt-in directory role, `-VerifyProtectedList`)
- `lab/scripts/powershell/post-apply/New-RestrictedAdminUnit.ps1` (no
  member before an RMAU-scoped role exists)
- `lab/scripts/monitoring/Invoke-AdContainment.ps1`
- `lab/terraform/modules/monitoring/itdr.tf` (automation rule) and
  `variables.tf` (`enable_itdr_containment`, `containment_rule_keys`)
- `lab/scripts/monitoring/tests/Itdr.Tests.ps1` (approval gate, protected
  accounts, fail-closed approver check, AD flagging)
- `lab/docs/runbooks/compromised-identity.md`
- `lab/terraform/modules/pim/azure.tf` (why `rg-identity-lab` is Tier 0;
  eligible-only Contributor; standing access that remains)

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
  (refresh tokens and session cookies; delay of a few minutes; not for
  external users; `User.RevokeSessions.All`)
- https://learn.microsoft.com/en-us/graph/api/group-post-members
  (app-only: `GroupMember.ReadWrite.All`; role-assignable groups also need
  `RoleManagement.ReadWrite.Directory`)
