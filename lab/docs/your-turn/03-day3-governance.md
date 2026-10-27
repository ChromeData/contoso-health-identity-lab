# 03 · Governance (stage `day3`)

**What you build:** access people request instead of collect. Four access
packages, rules about which ones can never be held together, and rules about
which apps staff may approve for themselves.

**Whisperglass:** *Contoso 03 · Joiner & mover* (the packages part; Dana's
automatic access comes in the joiner stage).

**Starts from:** `turn where` says `day2`.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 03*. | the lab map | the joiner station |
| 2 | `turn pr day3` | the terminal | two flags `false -> true`: `enable_governance`, `enable_nhi_governance`, then `Success! 13 passed` |
| 3 | Press **Enter**, wait for green checks, show the **Terraform plan** comment | the PR | a catalog, four access packages and the App-Consent-Reviewers group in the plan |
| 4 | **Merge pull request**, **Confirm merge** | the PR | "Merged" |
| 5 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the issue closes as approved; the apply ends in a green tick |
| 6 | `turn outputs` | the terminal | `saved (... bytes)` |
| 7 | `turn post day3`, then `turn post day3 go` | the terminal | seven separation-of-duties links added, the consent policy and the app rules applied |
| 8 | `turn open access-packages` | Identity Governance, Access packages | four packages: **Nurse - Clinical Apps**, **ICU - Critical Care Apps**, **ICU - Float Access**, **Pharmacy - Controlled Substances Apps** |
| 9 | Open **Pharmacy - Controlled Substances Apps**, then **Separation of duties** | the package | the packages and groups it can never be combined with |
| 10 | `turn open consent` | Consent and permissions | staff may consent only to low-risk permissions, for apps from verified publishers or from your own organization; everything else goes to a review |
| 11 | Read the Proof part | | |

## Say this, in your own words

- Nurses get their clinical apps automatically from their HR department. Extra
  access is requested, approved and expires.
- Some combinations are never allowed, like ordering and approving the same
  controlled-substance purchase. The system refuses the second request.
- No app gets new client secrets: certificates only, renewed every 180 days.
- An app asking for more than basic sign-in goes to the App-Consent-Reviewers,
  who have 14 days to decide.

## If something goes wrong

| What you see | Do this |
|---|---|
| The apply fails with "409" or "DuplicateKey" | A timing hiccup on Microsoft's side. Click **Re-run failed jobs**. |
| `turn post day3` says auto-assignment or lifecycle workflows are skipped | Expected. They need HR people and run in the joiner stage. |
| Some separation-of-duties lines say `skipped-planned` | Expected: they point at packages that are planned but not built yet. |

## Do it again

`lab/scripts/demo/rewind-lab.sh day2 --open-pr`, merge, do the cleanup it
prints, then start from step 2.
