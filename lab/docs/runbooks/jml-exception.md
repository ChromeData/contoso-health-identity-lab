# Runbook: joiner / mover / leaver exceptions (L1 / L2)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). **Status:**
written against the lab code; not yet exercised in the tenant.

## The normal path (what an exception deviates from)

HR is the source of truth. `hr_feed.csv` → `Invoke-InboundProvisioning.ps1`
(API-driven inbound provisioning) → AD → Cloud Sync → Entra. Attribute changes
drive dynamic groups (All-Nurses / All-ICU) and, once applied, the birthright
packages' automatic assignment policies (`Set-AutoAssignmentPolicies.ps1`,
72-hour grace for movers). Requested packages carry a 180-day expiry.
Separation of duties is nine rules in `lab/iga/sod-rules.json`: preventive
incompatibilities (`Set-IncompatibleAccessPackages.ps1`) and a detective
report (`09-SoD-Report.ps1`). Entra rejects cloud writes to department and
`accountEnabled` on synced users, so every mover and leaver starts with an HR
change (`lab/scripts/README.md`, *Run order*). None of this has run against
a tenant.

## Exception rules (apply to every case below)

1. **Ticket first.** No exception without a ServiceNow record naming the
   requester, the business owner who approves, and an **end date**.
2. **Time-boxed.** Every exception expires. JML exceptions default to at most
   30 days (lab standard), inside the 90/180-day ceilings in
   [exception-process.md](../standards/exception-process.md). Renewal is a new
   approval, not an edit.
3. **Owner, not IAM, accepts the risk.** IAM implements; the business or
   compliance owner signs, alongside the approvers that
   [exception-process.md](../standards/exception-process.md) §2 names for the
   risk rating.
4. **Recorded.** Add a row to the exception register
   ([exception-process.md](../standards/exception-process.md) §3); review open
   rows weekly.

## Cases

| Case | Do | Don't | Tier |
|---|---|---|---|
| **Urgent leaver** (termination for cause, before HR has updated) | Treat as containment: follow [compromised-identity.md](compromised-identity.md) steps 2–3 (revoke, disable in AD for synced users, provision on demand). Then have HR set `status=leaver` and run `04-Leaver.ps1` so packages, groups, app roles and SCIM accounts are removed with timestamps | Wait for the HR cycle; delete the account (deletion loses the audit trail) | L2 |
| **Leaver keeps access briefly** (handover, legal hold of a mailbox) | Keep the account disabled for sign-in; grant the *manager or legal* access to the data instead. If the person must sign in, a time-boxed exception with an end date | Leave the HR row `active` with no end date | L2 + owner |
| **Mover keeps old access during handover** | `03-Mover.ps1` removes the old package by design. For a transition, request the old package again through its policy with its own expiry, under an exception ticket | Skip the mover script; edit dynamic groups (you can't, and mustn't) | L2 |
| **Sync stuck** (HR change made, Entra unchanged) | Check the provisioning job's logs and Cloud Sync; use *Provision on demand*. `03-Mover.ps1` / `04-Leaver.ps1` wait up to `-WaitForSyncSeconds` / `-WaitForDisableSeconds` (default 1500) and say so if it never arrives | Write the attribute in Entra (rejected for synced users) | L1 → L2 |
| **Joiner before HR record** (agency staff, start date tomorrow) | HR or the agency's sponsor creates the record; the joiner runs as normal. Guest access for affiliated physicians is a separate sponsor-approved package (`modules/entitlement/b2b.tf`, code only) | Create a cloud-only account by hand outside HR | L2 |
| **SoD conflict** (for example Nurse + Pharmacy) | Pharmacy is incompatible with the clinical packages, so Entitlement Management blocks that request. A birthright package is never gated, so a conflict reached the other way round shows in `09-SoD-Report.ps1`. Route to compliance; if approved, a separate, approval-gated, short-expiry arrangement documented as a risk acceptance, using the mitigating control the rule names in `sod-rules.json` | Remove the incompatibility rule to let one request through | L2 + compliance |
| **Rehire** | HR reactivates the same `employeeId` (the script creates once, updates thereafter); the joiner then requests packages fresh | Restore old access wholesale | L1 |
| **Request for standing admin** | Decline; PIM eligibility through [pim-activation-support.md](pim-activation-support.md) is the path | Add a standing member to Privileged-IAM-Admins | L2 |

## Evidence

`04-Leaver.ps1 -ReportPath lab/evidence/out/<name>.csv` writes the per-system
timestamped offboarding report; `Export-EvidencePack.ps1` covers access-review
decisions and privileged assignments. Both write to the gitignored
`lab/evidence/out/` (tenant data).

## Not built

An exception register in a tool (it is a process here), and automated
expiry of exceptions. The guest catalog and its sponsor review are code
(`b2b.tf`) but have never run.
