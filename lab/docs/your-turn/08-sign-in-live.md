# 08 · Sign-in rules, live

**What you show:** the report-only rules reacting to staged sign-ins on test
accounts, the data that decides each graduation, and then the graduations
themselves: one policy from report-only to **On**, one pull request each.

**Whisperglass:** *Contoso 05 · Sign-in rules*. Its Build part is the
graduation pull request. It names CA001; the first graduation here is CA003,
so say that instead.

**Starts from:** `turn where` says `dc` (or a later stage), and:

- sign-in logs have flowed since `day1`: at least five days of report-only data (E28);
- three licensed test accounts: **A** with no MFA method, **B** with one MFA
  method (Authenticator), and one for the device-code sign-in (A will do);
- Tor Browser installed;
- your own admin account has a passkey (CA002, CA020 and CA021 will ask for
  it), and both break-glass keys are within reach;
- exception **E9** in `lab/docs/standards/exception-process.md` (graduating
  before the 14-day minimum) is approved, not *Proposed*, with the E28 counts
  attached, before the first graduation;
- Microsoft's own user-risk policy in ID Protection is off or report-only, so
  CA006 is the only user-risk policy;
- **security defaults are off.** A new tenant ships with them on, and Entra
  refuses to turn a Conditional Access policy On while they are on (the apply
  fails with `400 BadRequest: Security defaults`; seen on the first live
  graduation, 2026-10-28). Entra admin center, **Overview**, **Properties**,
  **Manage security defaults**, **Disabled**, or in `pwsh`:
  `Invoke-MgGraphRequest PATCH 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -Body @{ isEnabled = $false }`.
  From that moment until CA001 and CA002 are On, nothing forces MFA on the
  admins, so graduate CA001 early in the order below and keep the window short.

**Heads-up:** steps 13 to 21 ran in the tenant on 2026-10-28 (CA003, CA004);
the rest is still a draft, so correct any step the first time you do it. **Test accounts only** for every
simulation. Never use your own account or a break-glass account.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| | **Part A: the rules watch (E26, E27, E28b)** | | |
| 1 | Read the Map part of *Contoso 05*. | the lab map | the sign-in station |
| 2 | Tor Browser: go to `https://myapps.microsoft.com` and sign in as test user A | Tor Browser | My Apps opens, because nothing is enforced yet. If it asks you to add a method and lets you skip, skip it |
| 3 | Wait 10 to 15 minutes. Entra admin center, **ID Protection**, **Risk detections** | the detections list | **Anonymous IP address** for A, with a risk level. Write the level down, whatever it is |
| 4 | **Monitoring & health**, **Sign-in logs**, open A's Tor sign-in, **Report-only** tab | the sign-in details | CA007's report-only result, exactly as shown. CA007 acts only on **High**. On Medium it says not applied, and that is the result |
| 5 | In a `pwsh` window: `Connect-MgGraph -TenantId <tenant id> -Scopes IdentityRiskyUser.ReadWrite.All`, then `Invoke-MgGraphRequest -Method POST -Uri https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised -Body '{"userIds":["<B object id>"]}'` | the terminal | no error. The tenant id comes from `gh variable get AZURE_TENANT_ID` |
| 6 | In a private window, B signs in to `https://myapps.microsoft.com` | **ID Protection**, **Risky users**, then B's sign-in, **Report-only** tab | B at **High**, **Confirmed compromised**. CA006's report-only result on B's sign-in, exactly as shown |
| 7 | `turn open sentinel`, **Logs**: `AADRiskyUsers \| take 5`, then `AADUserRiskEvents \| take 5` | the results | rows for B. These rows are what lets run sheet 10 release the `identity_risk` rule, and its incident comes from there |
| 8 | Open a terminal whose sign-in is kept apart from yours: `AZURE_CONFIG_DIR=$(mktemp -d) az login --use-device-code --allow-no-subscriptions`. Finish the sign-in as the test account | the device-code page, then that sign-in's **Report-only** tab | CA010's report-only **Failure**: the block would have had work to do. The incident (`device-code-signin.kql`) arrives only once the second-wave rules are on (run sheet 10) |
| | **Part B: the evidence that decides (E28, E29)** | | |
| 9 | `turn open ca-insights`, with the time range set to the days since `day1` | the workbook | per policy: Success, Failure, User action required and Not applied counts. Take a screenshot and export it: this is the go/no-go evidence for every graduation |
| 10 | For the next policy to graduate, run the two queries in `lab/docs/runbooks/graduate-a-ca-policy.md` step 2 in Sentinel **Logs** | the results | who would have been blocked. Each one gets a disposition: remediated, accepted or exempt |
| 11 | `pwsh`: `Connect-MgGraph -TenantId <tenant id> -Scopes User.Read.All,GroupMember.Read.All,AuditLog.Read.All,Policy.Read.All`, then `./lab/scripts/powershell/07-Passwordless-Rollout.ps1 -Stage Pilot` | the terminal | registration status per group, then `CA008: NOT READY` with the reason "found 0". CA008's flag is still off, so the gap is measured before anyone is asked to enforce it |
| | **Part C: graduate one policy, CA003 first (E30, E31)** | | |
| 12 | Read the Build part. | the lab map | the sign-in station |
| 13 | `turn graduate CA003` | the terminal | `lab.tfvars: CA003 -> "enabled"`, the mocked test updated for you, then `Success! 13 passed` and `PREVIEW only` |
| 14 | `turn graduate CA003 go` | the browser | the new pull request, with the checklist in its description |
| 15 | In the description, write the days in report-only, the counts from steps 9 and 10 (totals only, no names), the dispositions and the rollback (a revert PR). Paste in `lab/docs/runbooks/ca-change-review-checklist.md` and tick it. Click **Create pull request** | the PR | the pull request, open |
| 16 | Wait for the checks to go green, then open the **Terraform plan** comment | the plan | exactly one change: CA003's `state` going from `"enabledForReportingButNotEnforced"` to `"enabled"`, and `Plan: 0 to add, 1 to change, 0 to destroy` |
| 17 | **Merge pull request**, **Confirm merge** | the PR | "Merged" |
| 18 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the apply ends in a green tick |
| 19 | Open the run and its **terraform plan (fresh, saved to file)** step | the run log | the same single change. This re-plan runs after you approve, so anything more is drift: stop and investigate |
| 20 | `turn open ca` | Conditional Access, Policies | CA003 **On**, every other policy still **Report-only** |
| 21 | `turn outputs`, then `turn post day1` | the terminal | the break-glass check passes. This step only reads |
| 22 | A test account tries a legacy client. SMTP AUTH is the likely one; check which legacy protocol still reaches Entra in 2026 | the sign-in log, then Sentinel **Incidents** | a failure that names CA003, then the **Legacy authentication attempts** incident. If Microsoft refuses the protocol before Entra sees it, there is no row: record that |
| 23 | Read the Proof part. | | |
| | **Part D: the rest, one PR each, steps 13 to 21 every time (E35 to E38b)** | | |
| 24 | **CA001** (MFA, all users) | a test user's sign-in, **Conditional Access** tab | CA001 **Success**, MFA asked for |
| 25 | **CA002** (phishing-resistant MFA, admins). First check that every admin in scope has a passkey, you included | your admin sign-in, **Authentication details** tab | a passkey met CA002's authentication strength |
| 26 | **CA007** (sign-in risk High: block). Then A repeats the Tor sign-in from step 2 (E37) | A's sign-in, **Conditional Access** tab | blocked if the risk is High. Otherwise not applied, with the level. Record it either way |
| 27 | **CA021** (Tier-0 activation step-up) takes four PRs, in this order. **a.** `CA021` = `"enabled"`. After the apply: `turn outputs`, `turn post day2` (only **auth-context** should plan a change), then `turn post day2 go` | the terminal, then `turn open ca` | CA021 **On** in the tenant. The script writes it; Terraform only renders it |
| 28 | **b.** `ca021_enforced_in_tenant = true`, only once step 30 shows CA021 **On** | the plan comment | an output changes, and no policy does |
| 29 | **c.** `pim_tier0_auth_context_switchover_step1 = true`. Until **d** lands, Tier-0 activation has no step-up, so do **d** straight after. Approvers deny any Tier-0 request that arrives in between | the plan comment | the Tier-0 groups' activation rules drop MFA |
| 30 | **d.** `pim_tier0_activation_auth_context_id = "c1"`. Leave step **c**'s line as it is | the plan comment, then a Tier-0 activation (run sheet 09) | the activation asks for a fresh phishing-resistant sign-in that carries `c1` (sign-in log, **Authentication details** and **Conditional Access** tabs) |
| 31 | **CA006** (user risk High: MFA and a secure password change). Then B signs in (E38) | B's sign-in, then **Risky users** | MFA, then a forced password change. B moves to **Remediated**. Note how many minutes it took |
| 32 | **CA009** (register security info). Then a TAP holder registers a method, and the password + SMS user from E20b tries to | the sign-in log | the first is allowed, the second refused |
| 33 | **CA010** (block device code). First run `az logout`, then `az login` in the browser, and stop using `-UseDeviceCode` anywhere: a session that started with device code is blocked at its next refresh. Then repeat step 8 | the sign-in log, then Sentinel | the device-code sign-in blocked |
| 34 | **CA020** (admin portals: sign in every 4 hours) | your admin session, after 4 hours | asked to sign in again. That is a re-authentication, not a block |

**The mocked test.** It pins every policy to report-only except a list of
graduated ones. `turn graduate` adds each policy to that list for you and runs
the test before it opens anything; the plan still shows exactly one change,
because the test file is not part of the plan.

**CA021's PRs b, c and d need more.** Every run that sets its own CA021 state,
or turns `enable_pim_auth_context` off, still reads the new
`ca021_enforced_in_tenant` and switch-over lines from `lab.tfvars`, and the
variable checks then refuse that run. Pin those values in each such run, and in
`plan_lab_tfvars` change `output.ca_pim_activation_auth_context_ready == false`
to `true`. That is code work: do it on the branch before you record, and open
the PR on camera only once the mocked test passes:
`(cd lab/terraform/envs/dev && terraform init -backend=false -input=false >/dev/null && terraform test -var-file=lab.tfvars)`
says `Success! 13 passed`. `turn graduate` refuses CA021 for this reason.

**Not in this sheet:** CA004 (it can graduate any day and is the simplest
one-line demo), CA005 (needs the Intune VM, E50), CA008 (its flag is still
off), CA022 (comes with the PAM app), and CA023 and CA060 (flags off).

## Say this, in your own words

- Report-only is reported as report-only. "Would have blocked" is never
  "blocked". If CA007 doesn't act because the risk came out Medium, that is the
  result; nobody lowers the threshold to get a screenshot.
- Every simulation uses a test account: the Tor sign-in, the confirmed
  compromise, the device code.
- One policy per pull request, and the plan shows one change and nothing else.
  Break-glass is checked again after every one.
- The trial breaks the lab's own 14-day rule, on the record: exception E9, and
  each PR states its real number of report-only days.
- The risk policies act on High only. CA006 lets a user fix their own risk with
  MFA and a new password. An attacker who registered their own method passes
  that too, which is why containment exists (run sheet 10).
- CA021 takes four changes because PIM only falls back to MFA when no policy
  targets the context. A report-only CA021 would leave activation with no
  step-up at all.

## If something goes wrong

| What you see | Do this |
|---|---|
| `lab-tests` is red on the `ca_policy_states` assert | Step 15 is missing, or its list is wrong. Fix it on the same branch and push. |
| `lab-tests` is red on a CA021 PR, on `ca021_enforced_in_tenant` or a switch-over value | The runs that set their own CA021 state need those values pinned (see the note under the table). Close the PR and use the prepared branch. |
| The plan shows more than one change, or a destroy or replace of a policy | Close the PR. Something drifted: someone changed a policy in the portal, and Sentinel will have a Conditional Access change incident. Put that right first. |
| No risk detection after 15 minutes | Detections can take longer. Wait, then in Tor use **New Identity** and sign in again. Never switch to your own account. |
| `confirmCompromised` answers 403 | The Graph session needs `IdentityRiskyUser.ReadWrite.All`, your account needs a role allowed to confirm risk (Security Administrator), and B needs a P2 licence. |
| B is blocked outright under CA006 | B had no MFA method, so there was nothing to remediate with. Register one, record what happened, and try again. |
| `07-Passwordless-Rollout.ps1` says pilot group `all-nurses` not found | Expected until the joiner stage creates the nurses. |
| You are locked out of the admin portals after CA002, CA020 or CA021 | Sign in with your passkey. If no admin can sign in: use break-glass (it pages High), set the policy back to report-only in the portal, open the revert PR at once and merge nothing else first (`graduate-a-ca-policy.md`, Rollback). |
| `az` or `turn outputs` fails after CA010 | That session started with device code. Run `az logout`, then `az login`. |
| `turn where` says `none` after step 31 | Expected: those settings don't belong to any stage. |
| The apply fails with "403" or "Forbidden" | Wait two minutes and click **Re-run failed jobs**. |

## Do it again

- **One policy:** put its line back to `"enabledForReportingButNotEnforced"`
  and take it out of the test's list, on a branch, then a PR through the same
  gate. That revert is the documented rollback.
- **Every policy:** `lab/scripts/demo/rewind-lab.sh <stage> --open-pr`, with
  the stage `turn where` printed before you started. It restores `lab.tfvars`
  and the mocked test, so every policy goes back to report-only. Security
  defaults stay off (a replay never needs them back on). If step 33
  ran, go back to MFA first, in its own PR (`pim_tier0_activation_auth_context_id = ""`
  and the switch-over `false`). Then check a Tier-0 group's activation settings
  no longer ask for the context: the provider can leave that rule on, so switch
  it off in the portal. Then rewind, and run `turn post day2 go` so CA021 is
  written back as report-only.
- **Risk:** `Invoke-MgGraphRequest -Method POST -Uri https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss -Body '{"userIds":["<A object id>","<B object id>"]}'`.
- A re-take is a new capture, logged as `re-run of Exx`.
