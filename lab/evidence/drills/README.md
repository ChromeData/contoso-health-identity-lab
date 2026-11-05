# Break-glass drill log

Procedure: [`../../docs/runbooks/break-glass-drill.md`](../../docs/runbooks/break-glass-drill.md).
Cadence: at least every 90 days.

Add a row only for a drill that actually happened, with values you
observed. Leave a cell blank (or write "not checked") rather than estimating.

**Lab drills use one software passkey per account** (key 1 only): the lab
deviation in the runbook, not the production standard of two hardware keys
in separate safes. The lab sign-ins are made by
`lab/scripts/demo/signin/passkey.mjs prove`, and the checks run app-only as
the lab operator (`Invoke-BreakGlassDrill.ps1 -UseAzureCliToken`).

**This file is public.** Record account short names (`bg-admin-01`), key
labels, times and ticket numbers only. No IP addresses, object IDs, tenant
domains or screenshots; those stay in the ticket or the gitignored
`../out/` folder.

## Log

| Date (UTC) | Account | Key | Sign-in OK? | Sentinel / LA alert? (incident #) | Teams card? | ServiceNow INC | Splunk alert? | Sign-in → incident (min) | Audit: changes made? | Operator | Reviewer | Change ticket | Result (Pass / Partial / Fail) | Follow-up |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-11-05 | bg-admin-01 | key 1 (lab software passkey) | yes (My Account, passkey only) | yes (#42, High) | no (notify playbook not triggered: no Sentinel automation rule yet) | no (same) | not checked | 10.2 | none | lab-operator | none | none opened | Pass | Wire the notify playbook; second admin review and a CHG next drill |
| 2026-11-05 | bg-admin-02 | key 1 (lab software passkey) | yes (My Account, passkey only) | yes (#42, High) | no (same) | no (same) | not checked | 10.2 | none | lab-operator | none | none opened | Pass | Same |

## Defects raised by drills

| Date (UTC) | Defect | Ticket | Fixed (date) | Re-drilled (date) |
|---|---|---|---|---|
| 2026-11-05 | Break-glass incident #42 did not reach Teams or ServiceNow: `pb-identity-notify` exists but no Sentinel automation rule runs it (live read 2026-11-05: 0 automation rules; Terraform creates one only when `playbook_logic_app_id` is set) | | | |
