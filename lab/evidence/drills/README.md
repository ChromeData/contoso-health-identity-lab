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
| 2026-11-05 (re-drill, notify leg) | bg-admin-01 | key 1 (lab software passkey) | yes, 11:34Z (passkey only) | yes: first grouped into the still-open #42; after #42 was closed (step 7) the next run raised #48 (High) | yes (card posted to Contoso SOC / Identity-SecOps) | INC0010007 (written back on #48) | not checked | not measured (grouping) | none | lab-operator | none | none opened | Pass (notify leg) | Grouping defect below |

## Defects raised by drills

| Date (UTC) | Defect | Ticket | Fixed (date) | Re-drilled (date) |
|---|---|---|---|---|
| 2026-11-05 | Break-glass incident #42 did not reach Teams or ServiceNow: `pb-identity-notify` exists but no Sentinel automation rule runs it (live read 2026-11-05: 0 automation rules; Terraform creates one only when `playbook_logic_app_id` is set) | | 2026-11-05 (automation rule live 11:00:46Z, capture log E40b) | 2026-11-05 (#48: Teams card + INC0010007) |
| 2026-11-05 | A second break-glass use within an hour of an OPEN break-glass incident sends no new Teams card or ServiceNow ticket: the rule re-alerts every 5 min over a 1 h lookback with suppression off, groups alerts into the open incident (AllEntities, 1 h), and the notify automation rule fires on incident Created only. The alert itself is recorded (#42 reached 12 alerts) | | | |
