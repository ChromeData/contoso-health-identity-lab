# How to graduate a Conditional Access policy (report-only → enforced)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). **Status:**
procedure written against the lab code; no policy has been graduated (no
tenant; every policy ships report-only in `ca_policy_states`,
`lab/terraform/envs/dev/lab.tfvars`). The policy list and flags are in
[CA design principles](../standards/conditional-access-design-principles.md) §1.

**Rule:** one policy per PR, enforced only with evidence. The change is a
one-line edit to `ca_policy_states` (`"enabledForReportingButNotEnforced"` →
`"enabled"`); the module rejects a missing key, an unknown key or an invalid
state. Every PR, graduation or not, is reviewed with the checklist in §7.

## 1. Let it run report-only

At least **14 days**, so a fortnight of shift patterns and month-end jobs is
in the sample; longer if the policy touches a population that signs in
rarely. Graduating sooner inside the 30-day trial is exception E9
([exception-process.md](../standards/exception-process.md)), not a new rule.

## 2. Measure what enforcement would have done

`ConditionalAccessPolicies` is `dynamic` in `SigninLogs` but a JSON string in
`AADNonInteractiveUserSignInLogs`, so normalise it before the union:

```kql
let Policy = "CA003 - Block legacy authentication";   // exact display name
union
  (SigninLogs),
  (AADNonInteractiveUserSignInLogs
     | extend ConditionalAccessPolicies = todynamic(tostring(ConditionalAccessPolicies)))
| where TimeGenerated > ago(14d)
| mv-expand CAP = ConditionalAccessPolicies
| where tostring(CAP.displayName) == Policy
| extend Result = tostring(CAP.result)
| summarize SignIns = count(), Users = dcount(UserPrincipalName) by Result
```

Then list who would have been blocked or interrupted:

```kql
// ...the first query, up to and including `| extend Result`...
| where Result in ("reportOnlyFailure", "reportOnlyInterrupted")
| summarize SignIns = count(), Apps = make_set(AppDisplayName, 10),
            LastSeen = max(TimeGenerated) by UserPrincipalName
```

The *Conditional Access insights and reporting* workbook shows the same
data when Log Analytics is connected.

## 3. Remediate every would-be-blocked user before the PR

| Policy | Typical cause | Remediation |
|---|---|---|
| CA001 MFA, all users | No method registered | `05-Reports.ps1` → `users_without_mfa.csv` |
| CA002 admins, phishing-resistant | Admin has only push or SMS | Register FIDO2 or Windows Hello first |
| CA003 legacy auth | Printer, script or old client on SMTP/EWS | `legacy-auth.kql`; an owner and an end date per sender |
| CA004 countries | Travel, VPN egress | Confirm with the user; the list must match the KQL and SPL lists |
| CA005 compliant device (pilot) | Pilot member on an unmanaged device | `lab/scripts/intune/README.md`; keep the operator's own admin out of the pilot |
| CA006 user risk High | High-risk user with no MFA method; synced user without password writeback | Register MFA first; confirm writeback; set Microsoft's managed risk policy to report-only or off |
| CA007 sign-in risk High | A legitimate sign-in scored High | Confirm safe in ID Protection; each case is a disposition in the PR |
| CA008 workforce | No passkey, Windows Hello or certificate | `07-Passwordless-Rollout.ps1` coverage. Pilot first; all users needs `ca008_allow_all_users_enforcement = true` in its own reviewed line |
| CA009 registration | Password-plus-push user adding a method, or setting up Windows Hello or macOS Platform SSO, which registration policies govern from 2026-07-06 (Learn, checked 2026-10-21) | A one-time TAP through [help-desk-identity-verification.md](help-desk-identity-verification.md). A softer interim is a reviewed code change, never a default |
| CA010 device code flow | Device-code sign-ins, including the operator's own `az login --use-device-code` | Move to browser sign-in, or a `CA010-Exclusion-<reason>` group through the exception process |
| CA020 admin portals, 4 h | Expected re-authentication for admins and `az` sessions | Brief the admins; nothing to remediate |
| CA021 PIM step-up (`c1`) | Eligible admins without the admin strength | Register an issued key first; extra steps below |
| CA022 PAM broker + admin portals | Operators without the admin strength | Issue and register keys first |
| CA023 protected actions (`c2`) | Nobody until `c2` is bound | After CA023 is enforced, bind `c2` to CA policy and named-location update and delete; never while report-only |
| CA060 shared clinical stations | Clinicians without a key; a station without the `CH-SharedClinical` profile, which the policy silently skips | Keys from unit stock (help-desk level V2-C); the report-only results must list every station; enforce unit by unit with Clinical Operations sign-off |

**CA021 takes three separate PRs** (the reason is in
[ADR 0002](../adr/0002-pim-for-groups-vs-direct-role-eligibility.md): a
report-only CA021 leaves PIM activation with no step-up at all):

1. CA021 = `enabled` through this procedure; apply, then run
   `Set-AuthContextPolicies.ps1`.
2. `ca021_enforced_in_tenant = true`, only after the script reports CA021
   enabled in the tenant.
3. The PIM switch to `c1`, two applies back to back:
   `pim_tier0_auth_context_switchover_step1 = true` (MFA off), then
   `pim_tier0_activation_auth_context_id = "c1"`. The plan refuses both
   until PR 2 has merged.

Every remaining would-be-blocked user gets a disposition: **remediated**,
**accepted** (will be blocked, owner agreed) or **exempt** (an exception
ticket with an end date; exemptions are group-based, never per user).

## 4. Open the PR

One line in `lab.tfvars`. The description gives the policy, the days in
report-only, the result counts from step 2, the users per disposition and
the rollback. **The repo is public:** aggregate counts only; names stay in
the ticket.

## 5. Merge and apply

`terraform-apply.yml` pauses at the `prod` reviewer gate. The apply
**re-plans on `main`**: before approving, read the plan log and confirm the
only change is this policy's `state`. Anything else is drift and stops the
approval. For CA021 the plan shows a changed output, not a policy resource;
run the post-apply script and confirm the tenant policy's state.

## 6. After enforcement

- `01-Verify-Baseline.ps1`: break-glass is still excluded everywhere.
- Watch for 72 h: re-run step 2 with `Result == "failure"` against the
  report-only forecast, with the service desk briefed.

**Rollback.** Normal: a revert PR through the same gate (for CA021, turn the
auth context off in `modules/pim` first). Emergency (a lockout and the gate
is too slow): an admin sets the policy to report-only in the portal, or
break-glass if no admin can sign in, which pages High. That is drift, so
open the revert PR immediately and merge nothing else first.

## 7. Review checklist (every CA PR)

For any PR touching `modules/conditional-access/**` or `ca_policy_states` /
`blocked_countries` in `lab.tfvars`. The reviewer ticks every box or writes
why it doesn't apply. On this solo repo the human gate is the `prod`
reviewer; with a second maintainer, require one approval.

**Scope and lockout safety**
- [ ] At most **one** policy changes state; an `enabled` change links the
      evidence from steps 1–3.
- [ ] Every policy still excludes `Break-Glass-Admins`, the one invariant
      that prevents a tenant lockout.
- [ ] No new exclusion except a **group** tied to an exception with an end
      date; CA005 still targets only the admin portals and its pilot group.
- [ ] A new policy has its `policy_states` key, starts report-only and takes
      the next unused number in its range.
- [ ] Strength or scope changes on CA002, CA020 or CA022: everyone in scope
      has a qualifying method.
- [ ] A policy that can block clinical staff has Clinical Operations
      sign-off before enforcement.

**Consistency and pipeline**
- [ ] `blocked_countries` changes are mirrored in
      `blocked-country-signin.kql` and its SPL twin
      (`render-savedsearches.sh --check` passes); no query breaks on a
      renamed display name.
- [ ] The plan shows only the expected CA, named-location or
      authentication-strength changes, and **no destroy or replace** (a
      replace leaves a window with no policy).
- [ ] Plan, Checkov and TruffleHog are green; the AI review is read and is
      advisory only; nothing tenant-sensitive is in the PR text.

**Operations**
- [ ] The rollback and who can approve the `prod` gate at apply time are
      named; the service desk and SOC know the date.
- [ ] After apply: `01-Verify-Baseline.ps1` passes and the 72-hour watch is
      scheduled. Once ITDR rules are on, the change shows as a **Low**
      `ca-policy-changed` incident from the CI apply identity; anything
      higher was made by someone else and is investigated.
