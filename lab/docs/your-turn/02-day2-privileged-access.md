# 02 · Privileged access (stage `day2`)

**What you build:** admin power you check out instead of own. Sixteen PIM
tier groups, the Global Administrator's own rules, a step-up policy for
activating Tier 0, and a help-desk scope that can never reach an admin.

**Whisperglass:** *Contoso 06 · Privileged access* (the PIM parts; the vault and
Guacamole parts come with the domain controller stage).

**Starts from:** `turn where` says `day1`.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 06*. | the lab map | the privileged station |
| 2 | `turn pr day2` | the terminal | four flags `false -> true`: `enable_pim_tiers`, `enable_global_admin_pim_policy`, `enable_helpdesk_au_scoping`, `enable_pim_auth_context`, then `Success! 13 passed` |
| 3 | Press **Enter**, wait for green checks, show the **Terraform plan** comment | the PR | the tier groups and their policies in the plan |
| 4 | **Merge pull request**, **Confirm merge** | the PR | "Merged" |
| 5 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the issue closes as approved; the apply ends in a green tick |
| 6 | `turn outputs` | the terminal | `saved (... bytes)` |
| 7 | `turn post day2`, then `turn post day2 go` | the terminal | the sign-in methods policy, authentication context **c1** with **CA021**, and the Global Administrator policy, each applied |
| 8 | `turn au-rule`, then `turn au-rule go` | the terminal | the help-desk rule, then `applied` |
| 9 | `turn open pim-groups` | PIM, Groups | sixteen tier groups: eight Tier 0, eight Tier 1 |
| 10 | Click a Tier 0 group, then **Settings**, then the **Member** role | the role settings | activation at most **4 hours**, MFA, a justification and a ticket number required; eligibility expires after **180 days**; no permanent active assignment |
| 11 | Back, open a Tier 1 group the same way | the role settings | **8 hours**, eligibility **365 days** |
| 12 | `turn open pim-roles`, click **Roles** on the left, open **Global Administrator**, then **Role settings** | the role settings | at most **2 hours**, **approval required**, eligibility **180 days** |
| 13 | `turn open ca` | Conditional Access | eleven policies now: **CA021** has joined, Report-only, on authentication context c1 |
| 14 | `turn open auth-methods` | Authentication methods, Policies | Passkey (FIDO2) and Temporary Access Pass **enabled**; SMS and voice calls **disabled** (they can be phished) |
| 15 | Read the Proof part | | |

## Say this, in your own words

- Nobody owns admin power. You ask for it, give a reason and a ticket, it is
  approved, and it expires.
- Global Administrator is never handed out through a group: each person gets
  their own expiring eligibility.
- The help desk can reset passwords only for ordinary staff. An admin is outside
  its reach, so a convincing caller cannot get an admin account reset.
- CA021 stays report-only for now. PIM keeps asking for MFA until CA021 is
  switched on, so there is never a gap.

## If something goes wrong

| What you see | Do this |
|---|---|
| The apply fails with 403 on "administrative units" | The pipeline identity needs its admin-unit permission. Re-run the failed job after two minutes; if it still fails, re-apply the bootstrap (see `lab/setup/after-signup.sh`, step B). |
| `turn post day2` warns that admin accounts or eligibility are missing | Expected. They are created once HR people exist, in the joiner stage. |
| The admin unit has no members | Expected until the HR feed has created staff. |

## Do it again

`lab/scripts/demo/rewind-lab.sh day1 --open-pr`, merge, do the cleanup it
prints (delete CA021, then authentication context c1), then start from step 2.
