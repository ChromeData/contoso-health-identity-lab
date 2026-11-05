# 10 · Detect & respond, live

**What you show:** the alarm system at work. The held-back rules are released
as their data arrives, each rule is fired once on purpose with a test account,
and containment asks a named person in Teams before it touches anyone.

**Whisperglass:** *Contoso 07 · Detect & respond*.

**Starts from:** `turn where` says `dc` (or a later stage), with Sentinel's
twelve rules **Enabled** (run sheet 04), and:

- DC01 running with the Azure Monitor Agent, for parts A and D;
- the notify playbook deployed (`lab/scripts/monitoring/Deploy-Playbook.ps1`,
  then the repo variable `TF_SENTINEL_PLAYBOOK_ID`), if you want the Teams card
  and the ServiceNow ticket on every incident;
- test accounts: **C** (cloud-only, for containment), a test app
  registration, three accounts for the failed sign-ins, and one disposable test
  user that nobody has a password for;
- a Team with an **Identity-SecOps** channel, and two people in it: one who
  will be in `ITDR-Containment-Approvers`, and one who won't be. Since
  2026-11-05 this is **Contoso SOC**, owned by `svc-soc-automation`, with
  test-user-a (an approver) and test-user-b (not one); to answer cards
  yourself on camera, add your own account to the team first
  (`lab/scripts/monitoring/README.md`, "The SOC team").

**Heads-up:** steps 4 to 8 ran on 2026-10-28 (stage `itdr`: DC01 already had SecurityEvent rows, four rules released, 16 enabled). The rest is still a draft, so
correct any step the first time you do it. **Test accounts only.** Every PR here
changes `lab.tfvars` **and** the mocked test that pins the stage, like each
stage PR before it; the step names the run to update. Once containment is on
(part B), the drills in part C raise High incidents about **the admin who made
the change**, and a card asks whether to contain that admin. The other approver
answers **Reject**. Your own answer about yourself is ignored by design.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| | **Part A: release the held-back rules (E15b, E15c)** | | |
| 1 | Read the Map part of *Contoso 07*. | the lab map | the detect station |
| 2 | Defender portal, **Microsoft Sentinel**, **Content hub**: install **Windows Security Events**, then connect **Windows Security Events via AMA** for DC01 | the connector | Connected |
| 3 | Sentinel **Logs**: `SecurityEvent \| where Computer startswith "DC01" \| take 5`, then `AADRiskyUsers \| take 5` and `AADUserRiskEvents \| take 5` (after run sheet 08 step 5) | the results | rows in each. A table with no rows keeps its rules held back |
| 4 | `git switch main && git pull`, `git switch -c itdr/release-v1`. In `lab.tfvars`, remove from `itdr_exclude_rules` the keys whose tables now have rows: `identity_risk`, `tier0_logon_without_checkout`, `ad_privileged_group_change`, `kerberoast_rc4_service_ticket`, `dcsync_replication_request` | the editor | three keys left, all second-wave ones |
| 5 | Same branch, `tests/mock_plan.tftest.hcl`: the two hold-back runs (`plan_lab_itdr_hold_back` and `plan_lab_itdr_hold_back_la_alerts`) assert the old list of eight. Change them to the new list. Then run the mocked test as in run sheet 08 step 16 | the terminal | `Success! 13 passed` |
| 6 | Commit, push, `gh pr create --base main --title "ITDR: release the rules whose tables have data" --web`. Wait for green checks, then open the **Terraform plan** comment | the PR | five analytics rules to add, and nothing else |
| 7 | **Merge**, `turn approve`, comment **approve**, `turn watch` | the terminal | a green tick |
| 8 | `turn open sentinel` | Analytics | seventeen rules **Enabled** |
| 9 | Second PR (E15c): `enable_itdr_detections_v2 = true`, keeping `dc_logon_outside_operator_allowlist`, `vault_privileged_access_anomaly` and `pim_activation_without_auth_context` held back. In the test, `plan_lab_tfvars` asserts that no second-wave rule and no `operator_ips` watchlist exist: update that assert | the plan comment | three rules and the `operator_ips` watchlist to add |
| 10 | Merge, approve, watch, then `turn open sentinel` | Analytics, then **Watchlists** | twenty rules, the new ones being device-code sign-in, security info registered from a risky context, and separation-of-duties violation granted. Then the watchlist. The three still held back, and why, go in the capture note |
| | **Part B: containment that asks first (E40, E41)** | | |
| 11 | Entra, **Groups**: create `ITDR-Containment-Approvers` with the approver in it (not a test account). Check the Key Vault holds `servicenow-integration-password` | the group | one or more approvers |
| 12 | `pwsh`: `Connect-MgGraph -TenantId <tenant id> -Scopes Application.Read.All,AppRoleAssignment.ReadWrite.All,GroupMember.Read.All`, with `az login` done. Then `./lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1 -KeyVaultName <kv> -TeamsGroupId <team id> -TeamsChannelId '<channel id>' -ServiceNowInstance <instance> -ServiceNowUser <user> -WhatIf`, then again without `-WhatIf` | the terminal | break-glass members protected by object id, the approvers counted, and the playbook id printed. Add `-GrantDisableRole` only if the playbook should disable cloud-only users (it raises one expected role-assignment incident) |
| 13 | `node lab/scripts/monitoring/authorize-teams-connection.mjs teams-pb-identity-contain` (it signs in as `svc-soc-automation`, never as you; done 2026-11-05 for both playbooks) | the JSON it prints, then the connection in the portal | Connected, authenticated as svc-soc-automation |
| 14 | `gh variable set TF_CONTAINMENT_PLAYBOOK_ID -R ChromeData/contoso-health-identity-lab --body "<printed id>"`. Then a PR with `enable_itdr_containment = true`. Merge, approve, watch | the plan comment | the automation rule **Contoso ITDR - containment approval (High identity incidents)** |
| 15 | Confirm test user C compromised, the same way as run sheet 08 step 5 but with C's object id | Sentinel **Incidents**, then the Teams channel | a High **Risky user or risky sign-in** incident naming C, then the approval card |
| 16 | The channel member who is **not** an approver clicks **Contain** | the incident's comments | "IGNORED ... not on the containment approver list" |
| 17 | A listed approver clicks **Contain** | the card, then the Logic App's **Run history** | revoke 204, confirmCompromised 204, disable 204 (or 403 without `-GrantDisableRole`, and the incident says so) |
| 18 | C tries to sign in | the sign-in log | refused |
| 19 | Close the incident with comments. Note the minutes from incident to contained | the incident | closed. This is the containment KPI |
| | **Part C: fire each rule once (E42 to E48)** | | |
| 20 | E42: the test app, **Certificates & secrets**: upload a certificate. Then try **New client secret** | the app, then Sentinel | the secret refused by the app management policy, and **Credential added to an app or service principal** |
| 21 | E43: as an admin, grant admin consent to a test app's permissions | Sentinel | **Permission granted to an application** |
| 22 | E44: in the portal, change one **report-only** policy (for example, add a group to its exclusions). Then `gh workflow run terraform-apply.yml -R ChromeData/contoso-health-identity-lab --ref main`, `turn approve`, `turn watch` | Sentinel, then the run's plan step | **Conditional Access policy, named location or auth strength changed outside IaC**, made by you, not by CI. Then the fresh plan puts the policy back, and the apply does it |
| 23 | E45: **Roles & admins**, **Helpdesk Administrator**: give a test user an active assignment outside PIM, then remove it. Then in PIM make a **permanent** active assignment of the same role, and remove it | Sentinel | two **Directory role assigned outside PIM** incidents: Direct, then PimPermanentActive. If Microsoft's record differs from the rule, copy its exact `OperationName` into the capture note |
| 24 | E45b: **Groups**, Privileged-IAM-Admins: add a test user as a member directly (not through PIM), then remove them. Then the same on Break-Glass-Admins with the disposable test user, removed within the minute | Sentinel | **Member added to a privileged group outside PIM**, and for Break-Glass-Admins always High |
| 25 | E46: as an admin, add a phone method to a test user | Sentinel | **Authentication method changed by an admin for another user**, with a severity that matches the account (a standard user isn't High) |
| 26 | E46c: evidence plan row E46c, with a test account | Sentinel | **Security info registered from a risky or unfamiliar context**, with the signals it counted |
| 27 | E47: evidence plan row E47. Spread the failures across the three test accounts, so smart lockout locks none of them | Sentinel | **Failed sign-in spike from one IP (spray / brute force)** |
| 28 | E48, optional: evidence plan row E48, only if your VPN has an exit in a blocked country | the sign-in log, then Sentinel | CA004's result as shown, then **Sign-in from a blocked / watched country**. If there is no such exit, skip it and say why |
| | **Part D: the AD side and the vault (E51f, E51b, E51c)** | | |
| 29 | E51f, one PR: `vault_feed_v2_columns = true`, and remove `vault_privileged_access_anomaly` and `dc_logon_outside_operator_allowlist` from `itdr_exclude_rules`. Update the test runs that pin them (`plan_lab_tfvars` checks the vault feed signals; the hold-back runs check the list). The same day, restart the feed with `--signals all --follow 60` | Analytics | both rules **Enabled** |
| 30 | The vault check from E51f: a Tier-0 credential read with no ticketed check-out | Sentinel | **PAM vault anomaly**, Signal `Tier0CredReadUncovered`. The lab has no Tier-0 static role yet (the Tier-0 people are library accounts), so this stays silent unless one is onboarded first. If so, record "not exercised: no Tier-0 static role" |
| 31 | Sentinel, **Watchlists**, `operator_ips`: set your entry's expiry to yesterday, then connect to DC01 from that address | Sentinel | **DC01 logon from outside the operator allowlist**. Then `gh workflow run terraform-apply.yml ...` as in step 22, and the apply restores the watchlist (it is Terraform-owned) |
| 32 | E51b, on DC01 from a lab test box only: the three drills in the evidence plan's row E51b. Remove the test account afterwards | Sentinel | **Member added to a privileged AD group**, **Tier-0 logon on DC01 without a Vault check-out** (Class Unvaulted), and **Kerberoasting (RC4 service tickets for user SPNs)**. The AD assessment report's hash goes in the capture log |
| 33 | For one of those incidents: `./lab/scripts/monitoring/Invoke-AdContainment.ps1 -SamAccountName <test account> -IncidentNumber <n> -WhatIf`, then without `-WhatIf` | the incident's comments, then the terminal | the playbook commented "AD disable required" and did nothing itself. The script disables the account on DC01 and writes an evidence record |
| 34 | E51c, optional and lab DC only: the drill in the evidence plan's row E51c, with the rights granted for the drill and removed afterwards | Sentinel | **DCSync (replication requested by a non-DC account)**, then the rights gone |
| 35 | Read the Proof part. | | |

## Say this, in your own words

- Every rule is code in the repo, reviewed like everything else, and fired
  once on purpose with a test account, with its own evidence row.
- A rule is released only once its data exists. Sentinel refuses a rule over a
  table that has never had data, so each release is its own PR.
- Containment never acts alone. It asks a named approver in Teams, never the
  person it is about, and no answer in four hours means no action.
  Break-glass is refused outright, by object id.
- For an account that comes from AD, containment only flags it. A person
  disables it in AD, because AD is the authority.
- After a confirmed compromise, a forced password change isn't enough: an
  attacker who registered their own method passes it. So disable the account,
  clean the methods, then reset.
- Drift is caught twice: the incident fires when it happens, and the next plan
  puts it back.

## If something goes wrong

| What you see | Do this |
|---|---|
| The apply fails with "400" on a released rule | Its table has never had data. Put the key back in `itdr_exclude_rules` and release it once rows appear. |
| `lab-tests` is red, naming the hold-back list or "eight of the seventeen" | The two hold-back runs still expect the old list. Update them on the same branch and push. |
| `lab-tests` is red on "no v2 ITDR rule" or on the vault feed signals | `plan_lab_tfvars` still pins the earlier stage. Update that assert. |
| No Teams card | Authorize the Teams connection (step 13). If the incident was merged into an older one, the Created trigger never fires: run the playbook from the incident, or turn on `containment_on_alert_added` in its own PR. |
| Every answer on the card is ignored | The approver list is empty, or Teams returned no responder identity, and both fail closed. `Deploy-ContainmentPlaybook.ps1 -VerifyProtectedList` reports the drift. |
| The disable step answers 403 | The account is an admin (out of the playbook's reach by design) or the managed identity lost `User.EnableDisableAccount.All`: re-run `Deploy-ContainmentPlaybook.ps1`. A non-admin cloud-only user is disabled without any directory role (E41). |
| A card asks to contain your own admin account | The other approver clicks **Reject**. Say it on camera: the playbook asks, and a person says no. |
| No incident after 15 minutes | Run the rule's query by hand in **Logs**. If Microsoft's operation names differ from the query, copy the real strings into it. |
| Every Tier-0 logon alerts | The vault feed is down: the incident shows `VaultFeedHealthy = false`. Restart `ingest-vault-audit.sh`. |

## Do it again

- **Rules and containment:** `lab/scripts/demo/rewind-lab.sh <stage> --open-pr`,
  with the stage `turn where` printed before you started. It restores the
  hold-back list, the second-wave flag and containment to that stage's values.
- **Test user C:** enable the account again and dismiss its risk (as in run
  sheet 08, Do it again). Its revoked sessions stay revoked.
- **AD:** remove the drill accounts and any rights granted for a drill, and run
  `Invoke-AdContainment.ps1 ... -Restore` for an account you disabled.
- A re-take is a new capture, logged as `re-run of Exx`.
