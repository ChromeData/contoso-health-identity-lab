# 06 · Dana joins (segment `Joiner`, scripts, no flag stage)

Draft: written before this stage first ran in the lab tenant. Steps marked (verify) are checked during the first build.

**What you build:** the joiner. The HR feed creates the staff in AD, Cloud Sync
brings them to Entra, and Dana Okafor (employee 100492, Nursing, Registered
Nurse) gets her clinical apps on day one without a ticket. The admin accounts
and the automatic access rules, which need real people to exist, are set up
here too.

**Whisperglass:** *Contoso 01 · Source of truth*, then *Contoso 03 · Joiner & mover*.

**Starts from:** `turn where` says `dc`, and run sheet 05 is done: the agent is
Healthy, Cloud Sync is enabled, and you have `<spId>` and `<jobId>`.

**Heads-up:** this stage is scripts, not a pull request: there is no
`turn pr` or `turn post` for it. Run every `./lab/...` command in `pwsh` from
the repo folder. Most scripts sign in to Microsoft Graph themselves:
`Disconnect-MgGraph` before one makes it ask for exactly what it needs.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 01*. | the lab map | the source-of-truth station: the HR feed and the provisioning agent |
| 2 | Open `lab/scripts/mock-hr/hr_feed.csv` | VS Code | Dana's row: `100492,Dana,Okafor,Nursing,Registered Nurse,200015,joiner,...`. Her manager is Grace Mwangi (200015). |
| 3 | `pwsh`, then the dry run: `./lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1 -ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your domain> -StatusFilter joiner -WhatIf` | the terminal | `Loaded 3 HR record(s) to process (filter: joiner)`, the SCIM payload for Dana, Sofia Reyes and Thomas Nguyen, then `Dry run - nothing was sent` |
| 4 | Managers first, for real: the same command with `-StatusFilter active` and no `-WhatIf`. Sign in as an account that holds User Administrator; answer **Y** at the prompt | the terminal | `Loaded 9 HR record(s)`, `HTTP 202 (expected 202 Accepted)`, `Submitted 1 of 1 batch(es)` |
| 5 | Then the joiners: the same command with `-StatusFilter joiner`, no `-WhatIf`, answer **Y** | the terminal | `Loaded 3 HR record(s)`, `HTTP 202`, `Submitted 1 of 1 batch(es)` |
| 6 | **Enterprise apps → Contoso HR Inbound Provisioning → Provisioning logs** | the Entra admin center | Dana Okafor, created, success. The log runs 5 to 10 minutes behind. |
| 7 | In a normal terminal tab (not `pwsh`), with `RG` and `VM` from run sheet 05: `az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts "Get-ADUser dana.okafor"` | the terminal | `Enabled : True`; her `DistinguishedName` is in the Nursing OU under `OU=Workforce` |
| 8 | **Cloud sync → Provision on demand** with Dana's distinguished name from step 7, or wait one 10 to 20 minute sync cycle | the Entra admin center | success |
| 9 | Open Dana under **Users** | her properties (verify: the click path) | on-premises sync enabled: Yes; department Nursing; job title Registered Nurse; an employee hire date (verify: where it shows) |
| 10 | Read the Proof part of *Contoso 01*. Switch to *Contoso 03 · Joiner & mover*, read its Map part | the lab map | the joiner station |
| 11 | `turn outputs` | the terminal | `saved (... bytes)` |
| 12 | In `pwsh`: `Connect-MgGraph -TenantId <tenant id> -Scopes <the GRAPH_SCOPES list in lab/scripts/demo/turn.sh>`, then `./lab/scripts/powershell/post-apply/Invoke-PostApply.ps1 -OutputsPath lab/evidence/out/tf-out.json -Only baseline,admin-accounts,auto-assignment,lifecycle-workflows` | the terminal | `Post-apply plan - DRY RUN`, with the four steps baseline, admin-accounts, auto-assignment, lifecycle-workflows |
| 13 | The same command with `-Execute`; answer **Y** at each prompt | the terminal | `EXECUTE (real changes)`: the baseline gate passes; `adm-ava.lin`, `adm-raj.patel` and `adm-mei.tanaka` created in **Admin-Accounts**; birthright policies on **Nurse - Clinical Apps** and **ICU - Critical Care Apps**; the joiner and leaver workflows |
| 14 | PIM eligibility for the admin accounts (`lab/iga/admin-accounts.json`): the same command with `-Only pim-eligibility -PimEligibility @{ 'pim-tier0-ca-admins' = @('adm-ava.lin@<tenant>.onmicrosoft.com'); 'pim-tier0-security-admins' = @('adm-ava.lin@<tenant>.onmicrosoft.com'); 'pim-tier1-helpdesk' = @('adm-raj.patel@<tenant>.onmicrosoft.com') }`, first as is, then with `-Execute` | the terminal | three `PIM eligibility:` steps, each `eligible, never active`. Mei Tanaka's admin account gets none, on purpose. |
| 15 | `turn open access-packages`, open **Nurse - Clinical Apps**, then its policies | the package (verify: the click path) | the policy **Nurse - Clinical Apps - birthright (HR attributes)** |
| 16 | `Disconnect-MgGraph`, then `./lab/scripts/powershell/02-Joiner.ps1 -UserPrincipalName dana.okafor@<your domain> -WhatIf` | the terminal | the licence SKUs your tenant owns, and `Birthright package: would wait ... No request is ever sent.` |
| 17 | `./lab/scripts/powershell/02-Joiner.ps1 -UserPrincipalName dana.okafor@<your domain> -LicenseSkuPartNumber <SKU from step 16>` | the terminal | `[+] Assigned <SKU>`, `Confirmed in All-Nurses`, **Nurse - Clinical Apps** delivered `by the automatic (birthright) policy`, then `Joiner complete` |
| 18 | `Disconnect-MgGraph`, then `./lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1 -RunJoinerFor 'dana.okafor@<your domain>'` | the terminal | both workflows `up-to-date`, then `run-submitted` for Dana |
| 19 | **Identity Governance → Lifecycle workflows → Contoso - Joiner (Nursing, day 1)**, then its history | the workflow (verify: the click path) | Dana's run: enable the account, a Temporary Access Pass emailed to her manager, the package request |
| 20 | Read the Proof part | | |

## Say this, in your own words

- The only honest answer to "who works here" is HR. Fix the original, never
  the copy.
- The push has a guard: a run that would disable more than ten people stops
  before it sends anything. A bad HR export must not lock out a night shift.
- Day one, no ticket: the package follows her department and job title. No
  request, no approver, and no expiry that locks a nurse out on day 180.
- No clinical access before her hire date: the rule checks it.
- If HR moves her out of Nursing, the old package stays 72 hours, so she is
  not cut off mid-shift.
- IT staff get two accounts: the everyday one from HR with no admin power, and
  a separate `adm-` account that is only ever eligible, never active.

## If something goes wrong

| What you see | Do this |
|---|---|
| The push returns 403 | Sign in as someone with User Administrator, with `SynchronizationData-User.Upload` consented. `Disconnect-MgGraph`, then run it again. |
| `Mass-change guard` stops the run | The feed would disable or move more than ten people. Check the CSV. `-Force` is only for a reviewed bulk change. |
| The provisioning log is empty | It runs 5 to 10 minutes behind. Wait before you film it. |
| Dana is in AD but not in Entra | Use **Provision on demand** (step 8). Check that `OU=Workforce` is in the Cloud Sync scope (run sheet 05, step 22). |
| auto-assignment refuses because nobody in scope has a hire date | The `hireDate` mappings (run sheet 05, steps 21 and 22) are missing. Fix them, push the joiners again, sync, repeat step 13. |
| auto-assignment fails with 403 | The signed-in admin needs the Identity Governance Administrator role. |
| admin-accounts refuses an owner | Ava Lin, Raj Patel or Mei Tanaka has not synced yet. Wait one cycle and repeat step 13. |
| 02-Joiner times out waiting for the package | It names the attribute to check: department, job title, enabled or hire date. |
| The workflow's package-request task fails | The package is delivered by its automatic policy, which takes no requests (verify on the first run). The account and Temporary Access Pass tasks still run. |

## Do it again

`./lab/scripts/demo/Reset-DemoState.ps1 -Segment Joiner -WhatIf`, then the same
with `-ServicePrincipalId <spId> -JobId <jobId> -UpnDomain <your domain>`. Start
from step 3 once it says `READY`. The provisioning log then shows **Update**,
not **Create**. The workflow's Temporary Access Pass works only for someone who
has never signed in: for a clean shot, film Sofia Reyes (100488). Inside the
72-hour grace, Dana can still show **Nurse - Clinical Apps**.
