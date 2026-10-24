# ADR 0017: Approval-gated identity containment

- **Status:** Accepted (lab). BUILT: the playbook template, its deploy script, the AD containment script and the Sentinel automation rule, behind `enable_itdr_containment` (default off), with offline Pester tests of the playbook's logic. DESIGNED: the cloud block group for confirmed compromises. No workspace exists and no approval card has been answered.
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
  alert against an account could get it disabled, break-glass included.
- **The automation's identity is a target.** Whatever can disable users is
  worth stealing.

It also has to work for hybrid accounts: a synced user is mastered in AD,
Entra rejects a cloud disable, and the next sync would undo it anyway.

## Options considered

1. **Fully automatic containment on every High incident.** Rejected: no
   person sees the evidence before a clinician loses access, and an attacker
   can aim it.
2. **Notify only; an analyst acts by hand.** Rejected: four consoles, no
   consistent record, and the 15-minute target rests on memory.
3. **Defender XDR automatic attack disruption instead.** In production it
   runs alongside, not instead: it acts on Microsoft's signals, not these
   detections, with no approval step. In the lab nothing is onboarded to
   Defender for it to act on.
4. **Automation that prepares and executes, with a person approving each
   account in Teams (chosen).**

## Decision

**Trigger.** A Sentinel automation rule fires on new **High** incidents
from the ITDR rules in `containment_rule_keys`. Incidents are grouped per
identity and per severity, so a High alert is never absorbed into an older
Medium incident.

**Per account, the Logic App:**

1. **Refuses protected accounts.** Break-glass is matched by object ID only;
   a UPN prefix is log-only, or a rename could make a compromised account
   uncontainable.
2. **Escalates restricted-management AU members** to an RMAU-scoped human,
   because Graph application permissions don't apply to them.
3. **Posts a Teams card:** Contain, Revoke only, or Reject. Only a member of
   `ITDR-Containment-Approvers` who is not the subject can decide; an answer
   with no responder identity fails closed; no answer in 4 hours means no
   action.
4. **Contain** revokes sessions, sets `confirmCompromised` (user risk High),
   then disables a cloud-only account if the opt-in role exists, or flags a
   synced or AD-only account for an AD disable. **Revoke only** signs the
   account out everywhere and leaves it enabled.
5. **Records** the decision, the approver and every Graph result on the
   incident and the ServiceNow ticket.

**AD side.** A person runs `Invoke-AdContainment.ps1` (`az vm run-command`
on DC01). Running it is the approval for the AD action; each run writes an
evidence record.

**A confirmed compromise is a block, not a remediation.** High user risk
brings in CA006, MFA plus a password change (ADR 0015), which anyone who can
pass MFA on the account can pass. The workforce is synced from AD (ADR
0006), so for them Contain only flags the disable. Until a person runs
`Invoke-AdContainment.ps1`, an attacker who registered their own method can
pass CA006, set a password that writes back to AD and lock the owner out
(R14). So:

- The AD disable is the next step after Contain, not a later ticket, and its
  delay is measured.
- The account is re-enabled only after its methods are cleaned
  ([compromised-identity.md](../runbooks/compromised-identity.md) §3).
- **DESIGNED, not built: a cloud block.** Contain adds the user to an
  `ITDR-Contained-Users` group that a block-all CA policy targets
  (break-glass excluded): after the revoke, the next token request fails for
  synced and cloud-only accounts alike, with no AD step and no directory
  role. Its cost: adding members app-only needs `GroupMember.ReadWrite.All`,
  which reaches every group that isn't role-assignable, so groups granting
  Tier-0 access or CA exclusions must be role-assignable first. This is the
  production direction and would replace the disable role below.

**Least privilege.** The managed identity has five Graph app roles
(`User.Read.All`, `AdministrativeUnit.Read.All`, `User.RevokeSessions.All`,
`User.EnableDisableAccount.All`, `IdentityRiskyUser.ReadWrite.All`) plus
Microsoft Sentinel Responder. App-only disable also needs a directory role,
because `accountEnabled` is a sensitive property. **That role,
Authentication Administrator, stays off by default:** with the workforce
mastered in AD it would reach only cloud-only non-admins, and it can also
reset methods and issue a TAP for any non-admin, so whoever controls the
playbook could take over any clinician. If ever turned on, it is scoped to an
AU of cloud-only, non-admin accounts (`-DirectoryRoleScope`), never the
tenant.

**Admins are never contained by automation:** that would need Privileged
Authentication Administrator and make the Logic App Tier 0. Who can edit the
workflow, and so use its rights, is risk R16.

## Consequences

- **Speed depends on staffing.** A 03:00 card with nobody watching times out
  with no action; the 15-minute target needs an on-call approver rota.
- **The most dangerous compromises are the slowest:** a compromised admin is
  contained by a person through PIM and the runbook, to keep the Logic App
  out of Tier 0.
- **Revocation isn't instant.** Issued access tokens stay valid until they
  expire unless the resource supports continuous access evaluation, and
  issued Kerberos tickets survive an AD password change (a suspected forged
  ticket means the krbtgt double reset, a separate procedure).
- **If the disable role is ever on, it is standing privilege outside PIM:**
  a risk acceptance (exception E7) owned by the SOC lead, reviewed
  2027-01-20 or when the cloud block is built.
- **The protected list can drift.** Break-glass and approver object IDs are
  fixed at deploy time; re-run `-VerifyProtectedList` when either group
  changes.

## How it is measured

Source: Logic App run history, incident comments and the
`Invoke-AdContainment.ps1` records. Fill in after the first run.

| Measure | Target |
|---|---|
| Incident created → card answered (median, p90) | ≤ 15 minutes |
| Card answered → Graph actions complete | Minutes |
| Contain → AD disable, synced accounts | ≤ 30 minutes |
| Cards that timed out with no answer | 0 |
| Reject share, per rule | Watched; a high share means a noisy rule |
| Contained accounts later classified benign | 0 clinicians |

## Revisit trigger

- A confirmed compromise where the card timed out, or a false-positive
  containment of a clinician.
- One rule produces mostly Rejects: tune it, or drop it from
  `containment_rule_keys`.
- The cloud block is built: drop the disable role.
- Devices and DC01 are onboarded to Defender: turn on attack disruption.

## Evidence

- `lab/monitoring/playbook-contain.json` (including the RMAU check)
- `lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1`,
  `Invoke-AdContainment.ps1`, `tests/Itdr.Tests.ps1`
- `lab/scripts/powershell/post-apply/New-RestrictedAdminUnit.ps1`
- `lab/terraform/modules/monitoring/itdr.tf`, `variables.tf`;
  `lab/terraform/modules/pim/azure.tf` (why `rg-identity-lab` is Tier 0)

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions
- https://learn.microsoft.com/en-us/graph/api/group-post-members
