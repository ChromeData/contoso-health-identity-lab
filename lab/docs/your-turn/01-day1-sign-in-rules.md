# 01 · Sign-in rules (stage `day1`)

**What you build:** ten Conditional Access policies (CA021 follows in 02, making eleven),
all created **report-only**. Each graduates to **On** in its own later pull request, after
it has collected report-only data; CA002 and CA021 stay report-only until passkeys exist.

> **Current status (2026-10-31):** in the live tenant nine of these have since
> graduated to **On** (CA002 and CA021 remain report-only). This stage restores
> them the way they were first created — report-only — and you graduate them in
> later runs, so that is what the steps below show.

**Whisperglass:** *Contoso 10 · Delivery* for the pull-request part, then
*Contoso 05 · Sign-in rules*.

**Starts from:** `turn where` says `p2`.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 10 · Delivery*. | the lab map | the delivery track lights up |
| 2 | `turn pr day1` | the terminal | five flags going `false -> true`: `enable_premium`, `enable_identity_protection_ca`, `enable_registration_ca`, `enable_device_code_block`, `enable_admin_session_controls`, then `Success! 13 passed` |
| 3 | Press **Enter** | the browser | the new pull request |
| 4 | Scroll to the checks at the bottom and wait | the checks list | all green after 3 to 5 minutes |
| 5 | Open the **Terraform plan** comment | the Conversation tab | a table of steps, then the planned changes |
| 6 | Open **Files changed** | the diff | the five flag lines in `lab.tfvars` |
| 7 | Click **Merge pull request**, then **Confirm merge** | the PR | "Merged" |
| 8 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the issue closes as approved; the apply ends in a green tick |
| 9 | `turn outputs` | the terminal | `saved (... bytes)` |
| 10 | `turn post day1`, then `turn post day1 go` | the terminal | the break-glass check passes: both break-glass accounts are excluded from every policy |
| 11 | Switch to *Contoso 05 · Sign-in rules*, read up to "Build" | the lab map | the sign-in station |
| 12 | `turn open ca` | Entra, Conditional Access, Policies | ten policies, CA001 to CA007, CA009, CA010 and CA020, all **Report-only** as this stage restores them (in the live tenant all but CA002 have since graduated to **On**) |
| 13 | Click **CA001** | the policy | state Report-only; under Users, Exclude lists **Break-Glass-Admins** |
| 14 | `turn open ca-insights` | Insights and reporting | what each policy would have done to real sign-ins |
| 15 | Read the Proof part | | |

## Say this, in your own words

- Report-only first, always: a nurse never finds out about a policy change by
  being locked out mid-shift.
- One policy graduates to "On" per pull request, after it has collected
  report-only data.
- CA008 (phishing-resistant sign-in for everyone) is held back on purpose: it
  waits for the passkey decision.

## If something goes wrong

| What you see | Do this |
|---|---|
| A check is red | Open it, read the last lines. A red `checkov` or `terraform plan` means the change is wrong: close the PR and run `turn pr day1` again. |
| The apply fails with "403" or "Forbidden" | Wait two minutes and click **Re-run failed jobs** on the run. New permissions take a moment to reach Azure. |
| Fewer than ten policies | Refresh the page. Then check the apply run really finished green. |
| The insights workbook is empty | Normal on a quiet tenant: it fills as people sign in. |

## Do it again

`lab/scripts/demo/rewind-lab.sh p2 --open-pr`, merge, then start from step 2.
