# 04 · Detection (stage `sentinel`)

**What you build:** the alarm system. Microsoft Sentinel on the lab's log
workspace, with eleven lab detection rules plus Microsoft's Fusion rule.

**Whisperglass:** *Contoso 07 · Detect & respond*.

**Starts from:** `turn where` says `day3`.

**Heads-up:** turning Sentinel on starts its 31-day free trial, once per
workspace. A rewind and redo does not restart it.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 07*. | the lab map | the detect station |
| 2 | `turn pr sentinel` | the terminal | one flag `false -> true`: `enable_sentinel`, then `Success! 13 passed` |
| 3 | Press **Enter**, wait for green checks, show the **Terraform plan** comment | the PR | Sentinel onboarding and the analytics rules in the plan |
| 4 | **Merge pull request**, **Confirm merge** | the PR | "Merged" |
| 5 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the issue closes as approved; the apply ends in a green tick |
| 6 | `turn open sentinel` | Defender portal, Microsoft Sentinel, Analytics | twelve rules, all **Enabled** |
| 7 | Point at a few of them | the rules list | break-glass sign-in, failed sign-in spike, legacy authentication, PIM activation, blocked country, Conditional Access change, app credential added, role assigned outside PIM, group member added outside PIM, app permission granted, sign-in method changed by an admin, and Fusion |
| 8 | Read the Proof part | | |

## Say this, in your own words

- Every rule is code in the repo, reviewed like everything else.
- Eight more rules are written but held back on purpose: their data does not
  exist yet (the domain controller, risky users, the vault). Sentinel refuses a
  rule whose table has never had data, so each one is released in its own PR
  once its data starts flowing.

## If something goes wrong

| What you see | Do this |
|---|---|
| The apply fails with "400" about a rule's period and frequency | A rule looks back further than its schedule allows. Read the message; the rule's frequency must be at least one hour for a two-day look-back. |
| The rules are there but nothing ever fires | Check that Entra's logs reach the workspace: `turn open ca-insights` should show sign-ins. If not, the bootstrap's Entra log export is missing (`lab/terraform/envs/bootstrap`, `log_analytics_workspace_id`). |

## Do it again

`lab/scripts/demo/rewind-lab.sh day3 --open-pr`, merge, then start from step 2.
