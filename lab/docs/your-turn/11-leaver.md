# 11 · Leaver (segments `Mover` and `Leaver`, scripts, no flag stage)

Draft: written before this stage first ran in the lab tenant. Steps marked (verify) are checked during the first build.

**What you build:** nothing new: you prove what is there. Marcus Bello moves
from Nursing to ICU, then Dana leaves. One HR row changes each time. For Dana,
the account is disabled, her sessions revoked, her packages removed and her AWS
account deprovisioned, each step with a timestamp, and the time from HR to
disabled becomes a measured number.

**Whisperglass:** *Contoso 03 · Joiner & mover* for the mover (steps 1 to 6),
then *Contoso 08 · Leaver + non-human identities*.

**Starts from:** run sheets 06 and 07 are done: Dana holds **Nurse - Clinical
Apps** and has an AWS account created by SCIM. `turn where` says `apps` or
later. You have `<spId>` and `<jobId>`.

**Heads-up (first run, 2026-10-28):** DC01 must be running - the HR agent and Cloud Sync agent live on it and the 19:00 auto-shutdown put both Cloud Sync jobs in quarantine (`HybridIdentityServiceNoActiveAgents`); start the VM, restart `AADConnectProvisioningAgent`, then restart + start the jobs. Marcus moved to ICU (AD 7 s after the push, Entra at the next 20-minute cycle); `03-Mover.ps1` then waits for the ICU birthright package (PR #83 fixed its crash after the wait). Dana's leaver: AD disabled + OU=Disabled 7 s after the push, Entra `accountEnabled=false` 3 minutes later, `04-Leaver.ps1` revoked sessions, removed the package and the three app groups, then waited on the package removal.

**Heads-up:** every step changes real accounts; to film again, use *Do it
again*. The mover's old package leaves only after a 72-hour grace, so step 6
is three days later. Run every `./lab/...` command in `pwsh` from the repo
folder, and the `az` commands in a normal terminal tab with `RG` and `VM` from
run sheet 05.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Open *Contoso 03 · Joiner & mover* and say the mover in your own words (below) | the lab map | the joiner station |
| 2 | In `lab/scripts/mock-hr/hr_feed.csv`, change Marcus Bello's row (100310) from `Nursing` to `ICU`. Save | VS Code | one changed field in the diff |
| 3 | `Disconnect-MgGraph`, then `./lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your domain> -StatusFilter active -WhatIf`, then the same without `-WhatIf`, answer **Y** | the terminal | `Access-change guard: 1 department/title change(s) (threshold 10)`, then `HTTP 202` |
| 4 | **Cloud sync → Provision on demand** with Marcus's distinguished name (`Get-ADUser marcus.bello` through run-command, as in run sheet 06 step 7), or wait one 10 to 20 minute cycle | the Entra admin center | success |
| 5 | `Disconnect-MgGraph`, then `./lab/scripts/powershell/03-Mover.ps1 -UserPrincipalName marcus.bello@<your domain> -NewDepartment ICU` | the terminal | department `ICU` arrived from AD; **Nurse - Clinical Apps** `Still held ... Nothing sent.` (the grace); **ICU - Critical Care Apps** delivered by the automatic (birthright) policy |
| 6 | 72 hours later, run step 5 again (E52) | the terminal | `No active 'Nurse - Clinical Apps' assignment.` |
| 7 | Switch to *Contoso 08 · Leaver + non-human identities*, read the Map part | the lab map | the leaver station |
| 8 | In `hr_feed.csv`, Dana's row (100492): status `leaver`, endDate today (`YYYY-MM-DD`). Save | VS Code | two changed fields |
| 9 | `Disconnect-MgGraph`, then `./lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your domain> -StatusFilter leaver -WhatIf` | the terminal | `Loaded 2 HR record(s) to process (filter: leaver)`: Dana, and Priya Nair, who ships as a leaver. Dana's record says `"active": false`. |
| 10 | Note the time: the leaver clock starts now. The same command without `-WhatIf`, answer **Y** | the terminal | `HTTP 202`, `Submitted 1 of 1 batch(es)` |
| 11 | `az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts "Get-ADUser dana.okafor"` | the terminal | `Enabled : False`, and her account now in `OU=Disabled` |
| 12 | **Cloud sync → Provision on demand** with her new distinguished name, or let step 14 wait for the sync | the Entra admin center | success |
| 13 | `Disconnect-MgGraph`, then `./lab/scripts/powershell/04-Leaver.ps1 -UserPrincipalName dana.okafor@<your domain> -WhatIf` | the terminal | `synced from AD - HR owns account state`, then steps `[1/8]` to `[8/8]`, nothing changed |
| 14 | `./lab/scripts/powershell/04-Leaver.ps1 -UserPrincipalName dana.okafor@<your domain> -ProvisionOnDemandApps 'AWS IAM Identity Center' -ReportPath lab/evidence/out/leaver_dana.csv`, answer **Y** | the terminal | `Disabled (HR -> AD -> Cloud Sync)` or `Already disabled`; `Sessions/refresh tokens revoked`; `adminRemove 'Nurse - Clinical Apps'`; `'AWS IAM Identity Center': provision on demand Success`; what she owns (step 7/8); then `First to last action: mm:ss` |
| 15 | Entra **Audit logs**, filtered on Dana | the audit log (verify: the click path) | revoke sign-in sessions, group removals, the account disabled, each with a time |
| 16 | **Enterprise applications → AWS IAM Identity Center → Provisioning logs** | the Entra admin center (verify: the click path) | Dana, action **Disable** (E52) |
| 17 | AWS: **IAM Identity Center → Groups → App-AWS-IdentityCenter-Users** | the AWS console (verify: the click path) | Dana is no longer a member; her access portal shows no account |
| 18 | The non-human half: `Disconnect-MgGraph`, `./lab/scripts/powershell/06-NHI-Inventory.ps1`, then `Disconnect-MgGraph`, `./lab/scripts/powershell/Find-ShadowAdmins.ps1` | the terminal, then `lab/evidence/out/` in VS Code | `KPI: ... NHI(s) orphaned or holding an expired credential`; `nhi_findings.csv` (one row per finding, with its OWASP ID and fix) and `shadow_admins.csv` |
| 19 | The leaver-clock KPI: `Disconnect-MgGraph`, then `./lab/scripts/powershell/08-Measure-KPIs.ps1 -Label after -SkipPam -InboundProvisioningServicePrincipalId <spId> -NhiInventoryPath lab/evidence/out/nhi_inventory.json` | the terminal | `[6/8] HR-to-disable latency (last 30 days)` and `hr_to_disable_minutes` in minutes (median) |
| 20 | Read the Proof part | | |

## Say this, in your own words

- A mover is not a status: it is a department change in HR. Access follows it,
  and the old package stays 72 hours so nobody is cut off mid-shift.
- A leaver starts in HR, never in Entra. Entra refuses to disable a synced
  account by itself, so the script waits for HR, then AD, then Cloud Sync.
- Contain first, then clean up: disable and revoke sessions before packages,
  groups and apps.
- Tokens already issued live until they expire, and revoking takes minutes. So
  the script does not promise "instant": it measures.
- AWS hears through SCIM: on demand now, or within about 40 minutes.
- Apps a leaver owned are flagged, never quietly handed over. A Tier-0 app is
  never given to a manager by default.

## If something goes wrong

| What you see | Do this |
|---|---|
| `Mass-change guard` stops the push | More than ten disables or moves. Check the CSV. `-Force` is only for a reviewed bulk change. |
| 03-Mover warns the department is still Nursing | The change has not synced yet. Use step 4, then run step 5 again. |
| 04-Leaver waits at `[1/8]` | Cloud Sync has not carried the disable yet. Use step 12. It waits up to 25 minutes. |
| Dana is deleted in Entra instead of disabled | `OU=Disabled` is not in the Cloud Sync scope (run sheet 05, step 22). A re-take then creates a new Dana. |
| The AWS step says `SKIPPED` or `FAILED` | A known limit for users already disabled in Entra (verify). The next SCIM cycle, about 40 minutes, disables her. |
| The KPI says `not-measured` | No leaver matched yet: the logs run behind. Run step 19 again later. Without `-InboundProvisioningServicePrincipalId` it is never measured. |

## Do it again

Leaver: `./lab/scripts/demo/Reset-DemoState.ps1 -Segment Leaver -WhatIf`, then
`./lab/scripts/demo/Reset-DemoState.ps1 -Segment Leaver -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your domain> -WaitForSyncSeconds 1500`
(add `-LicenseSkuPartNumber <SKU>` if her licence was removed). Start from step
8 once it says `READY`. If Dana stays in `OU=Disabled`, move her back on the DC
with `Move-ADObject`. Mover: the same with `-Segment Mover`, then start from
step 2. When you are done filming: `git checkout -- lab/scripts/mock-hr/hr_feed.csv`.
