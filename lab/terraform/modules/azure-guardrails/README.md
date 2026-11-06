# modules/azure-guardrails: two Azure Policy guardrails, Audit first

**Status: BUILT, not applied.** The mocked tests pass. On 2026-11-06 a
targeted plan of `envs/bootstrap` ran as the lab operator against the real
subscription, with no apply: 4 to add, 0 to change, 0 to destroy (capture
log E106).

Called only from `envs/bootstrap` (`enable_azure_guardrails`, default
`false`). Ported from the owner's old Azure-Landing-Zone-Guardrails repo,
with two bugs fixed.

| Guardrail | Definition / assignment | What it judges | Effect |
|---|---|---|---|
| No new standing Owner | `contoso-lab-no-standing-owner` / `lab-no-standing-owner` | A new Owner role assignment for anyone not on `owner_allowed_principal_ids` | `standing_owner_effect`: **Audit** (default), Deny, Disabled |
| Key Vaults keep deletion protection | `contoso-lab-keyvault-deletion-protection` / `lab-keyvault-deletion-protection` | A vault created or updated with soft delete off or without purge protection | `keyvault_protection_effect`: **Audit** (default), Deny, Disabled |

**Why.** Admin power on Azure should be borrowed through PIM for a few
hours, not held forever. A Key Vault that can be purged is one whose secrets
can be destroyed for good, which is how someone covers their tracks.

**Rollout.** Assign in Audit, read what it would have caught
(`az policy state list --policy-assignment lab-no-standing-owner`), and only
then switch to Deny. A Deny with no allowed Owners is refused at plan.

## Bugs fixed from the old repo

1. **The Owner rule never matched.** It compared `roleDefinitionId` with
   `equals "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-..."`.
   A real role assignment's id starts with the subscription:
   `/subscriptions/<id>/providers/Microsoft.Authorization/roleDefinitions/8e3af657-...`
   (read on 2026-11-06 from both Owner assignments on the lab subscription).
   So the old policy would have deployed, shown as assigned, and blocked
   nothing. The fix is `like "*/providers/Microsoft.Authorization/roleDefinitions/<Owner GUID>"`:
   one leading wildcard, and Azure Policy string comparisons are
   case-insensitive (Microsoft Learn, *policy definition structure: policy
   rule*). The test replays the real id against the rule, and it fails
   against the old one.
2. **The Key Vault rule flagged good vaults.** `enableSoftDelete notEquals
   "true"` catches any request that just leaves the field out, which is
   normal now that soft delete can't be turned off. The rule is now
   Microsoft's own built-in *Key vaults should have deletion protection
   enabled* (`0b60c0b2-2dc2-4e1c-b5c9-abbed971de53`, v2.1.0, read with
   `az policy definition show`), copied so the effect and message are ours.
   It skips a vault being recovered.

## Can it lock anyone out?

Checked on 2026-11-06:

- **PLAN and APPLY** (the CI identities, `envs/bootstrap`): PLAN is Reader.
  APPLY is Contributor plus an RBAC Administrator role limited by ABAC to
  two Key Vault data roles and VM Administrator Login. Neither holds or can
  create Owner, so the Owner rule never applies to them.
- **APPLY's Key Vault**: `kv-idlab-20f1` has purge protection on, and
  `modules/keyvault` defaults it to `true`. Its updates stay compliant
  even under Deny.
- **The two standing Owners** (the owner's account and the lab operator):
  they go on `owner_allowed_principal_ids`, so their Owner grant can be
  re-created even under Deny.
- **Existing access**: policy judges new or changed resources only. Nobody
  loses a right they already have, in any mode.
- **Not tested**: whether a PIM activation of Owner is judged by this
  policy. There are no Azure role eligibilities on the subscription today.
  Find out in Audit before any switch to Deny.

## What it doesn't do

- Any Owner can remove these assignments. They catch mistakes and drift,
  and keep a record. They don't stop an Owner.
- They don't remove existing standing Owners. Today the two holders are the
  owner's account and the operator.

## Who applies it

The applier needs `Microsoft.Authorization/policyDefinitions/write` and
`policyAssignments/write`. APPLY's Contributor excludes them (NotActions
`Microsoft.Authorization/*/Write`), so the module lives in the human-applied
`envs/bootstrap`. A guardrail that CI could edit wouldn't guard CI.

Azure Policy on Azure resources costs nothing.

## Apply it (human, after merge)

`envs/bootstrap`'s remote state was written by OpenTofu (its providers are
`registry.opentofu.org`), so the 2026-11-06 plan ran with `tofu`. Use the
same tool for the apply. Run it as an Owner of the subscription; the lab
operator is one.

1. In `envs/bootstrap/terraform.tfvars` (gitignored), set
   `enable_azure_guardrails = true`, and set `owner_allowed_principal_ids`
   to the two ids printed by
   `az role assignment list --scope /subscriptions/<id> --role Owner --query "[].principalId" -o tsv`.
2. Run `tofu plan -target=module.azure_guardrails -out guardrails.tfplan`.
   Expect 4 to add, 0 to change, 0 to destroy, both effects `Audit`. Then
   run `tofu apply guardrails.tfplan`.
3. Check the result (not run yet):
   - `az policy assignment show -n lab-no-standing-owner` shows the
     `Audit` effect and both allowed ids.
   - After the first compliance scan (up to 24 hours, or start one with
     `az policy state trigger-scan`), `az policy state summarize` lists
     both assignments.
   - The test that proves the Owner fix: create an Owner assignment for a
     throwaway service principal that is not on the list, and confirm
     `az policy state list --policy-assignment lab-no-standing-owner`
     records it as `NonCompliant`. Then remove the assignment.

Switching to Deny is a separate, reviewed change to `standing_owner_effect`
or `keyvault_protection_effect`, made after the Audit results are read.

## Tests

`tests/guardrails.tftest.hcl` has 6 runs, all mocked:

- Audit is the default, both in each assignment and in each definition's
  default.
- The Owner rule matches the real assignment id, has exactly one wildcard,
  and does not catch Contributor.
- The allowed principals reach the assignment.
- A Deny with nobody allowed is refused.
- The Key Vault rule is the built-in logic.
- Bad inputs are refused.

`envs/bootstrap/tests/optin.tftest.hcl` adds one assertion and two runs: nothing by default,
the opt-in in Audit, and a typo'd effect refused.
