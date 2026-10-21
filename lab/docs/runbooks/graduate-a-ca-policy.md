# How to graduate a Conditional Access policy (report-only → enforced)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). **Status:**
procedure written against the lab code; no policy has been graduated yet (no
tenant deployed; every policy ships report-only in `ca_policy_states`,
`lab/terraform/envs/dev/lab.tfvars`). CA001–CA005 always exist; CA006–CA010,
CA020–CA022 and CA060 exist only while their staging flag is on, and then
their `ca_policy_states` key is required.

**Rule:** one policy per PR, enforced only with evidence. The change is a
one-line edit to `ca_policy_states` in `lab.tfvars`
(`"enabledForReportingButNotEnforced"` → `"enabled"`); the module rejects a
missing key, an unknown key or an invalid state
(`modules/conditional-access/variables.tf`).

## 1. Let it run report-only

Lab standard: **at least 14 days** in report-only, so a full fortnight of
shift patterns and month-end jobs is in the sample. Longer if the policy
touches a population that signs in rarely. The 30-day trial can't fit that
for every policy, so graduating sooner inside the trial is a registered
exception (E9 in [exception-process.md](../standards/exception-process.md)),
not a new rule.

## 2. Measure what enforcement would have done

`ConditionalAccessPolicies` is `dynamic` in `SigninLogs` but a JSON string in
`AADNonInteractiveUserSignInLogs` (same trap as `lab/kql/break-glass-signin.kql`),
so normalise it before the union:

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

verify: the report-only `result` values (`reportOnlySuccess`,
`reportOnlyFailure`, `reportOnlyInterrupted`, `reportOnlyNotApplied`) against
the current sign-in log schema. The *Conditional Access insights and
reporting* workbook shows the same data if Log Analytics is connected.

## 3. Remediate every would-be-blocked user before the PR

| Policy | Typical cause | Remediation source |
|---|---|---|
| CA001 MFA, all users | No method registered | `lab/scripts/powershell/05-Reports.ps1` → `users_without_mfa.csv` |
| CA002 phishing-resistant, admins | Admin has only push/SMS | Register FIDO2 / Windows Hello before enforcing |
| CA003 block legacy auth | Printer, script, old client on SMTP/EWS | `lab/kql/legacy-auth.kql` (`Successes`); owner + end date per sender |
| CA004 block countries | Travel, VPN egress | Confirm with the user; the list must match the KQL `BlockList` and the SPL country lists |
| CA005 compliant device (pilot) | Pilot member on an unmanaged device | `lab/scripts/intune/README.md`; keep the operator's own admin account out of the pilot group |
| CA006 user risk high → MFA + secure password change | High-risk user with no MFA method (blocked outright); synced user whose cloud password change can't reach AD | Register MFA first; confirm Cloud Sync password writeback (verify). Set Microsoft's managed risk policy to report-only or off by hand, so CA006 is the one user-risk policy |
| CA007 sign-in risk high → block | A legitimate user's sign-in scored High (anonymising VPN, unfamiliar location) | Confirm safe in Identity Protection; each case goes in the PR as a disposition |
| CA008 phishing-resistant, workforce | Users without a passkey, Windows Hello or certificate | `07-Passwordless-Rollout.ps1` coverage; `Set-AuthenticationMethodsPolicy.ps1`. Enforce the pilot first (`ca008_scope = "pilot"`); all users needs `ca008_allow_all_users_enforcement = true` in its own reviewed line |
| CA009 register security info | A password-plus-push user adding a method, or provisioning Windows Hello, which registration policies also govern since 2026-07-06 (`baseline.tf`) | Issue a one-time TAP through [help-desk-identity-verification.md](help-desk-identity-verification.md). If the Windows Hello gap is real, the softer interim is a reviewed code change, never a default |
| CA010 block device code flow | Device-code sign-ins, including the operator's own `az login --use-device-code` and `Invoke-BaselineAssessment.ps1 -UseDeviceCode` | Move them to interactive browser sign-in, or put them in a `CA010-Exclusion-<reason>` group through the exception process (`ca010_exception_group_object_ids`). After enforcement, a session that started with device code is blocked at its next refresh (protocol tracking) |
| CA020 admin portals, sign-in every 4 h | Tier-0/1 admins and `az` / Azure PowerShell sessions (Azure Resource Manager is in scope) | Expected re-authentication, not a block. Brief the admins; nothing to remediate |
| CA021 PIM activation step-up (auth context c1) | Eligible admins without the admin phishing-resistant strength | Register an issued security key first. Extra steps below |
| CA022 PAM session broker + admin portals | PAM operators and portal users without the admin strength (a device-bound key, when the AAGUID list is set) | Issue and register keys before enforcing |
| CA023 protected actions (auth context c2) | Nobody until `c2` is bound: the context only applies to the protected actions it is bound to | Graph-managed like CA021 (`Set-AuthContextPolicies.ps1`). After CA023 is enforced, bind `c2` to Conditional Access policy and named-location update and delete (a tenant-time step; never while CA023 is report-only) |
| CA060 shared clinical workstations | Clinicians without a key on a shared station; a station without the `CH-SharedClinical` Autopilot profile, which the policy silently skips | Keys from unit stock (help-desk level V2-C). The report-only results must list every station in scope. Enforce unit by unit with Clinical Operations sign-off ([raci.md](../standards/raci.md)) |

**CA021 has extra steps: three separate PRs.** It is Graph-managed:
Terraform renders the policy and the auth context, and the post-apply
script `Set-AuthContextPolicies.ps1` writes them. The reason for the order
is Microsoft's fallback rule: PIM falls back to plain MFA only when no CA
policy targets the context, and a report-only policy still counts, so a
report-only CA021 would leave activation with no step-up at all
([ADR 0020](../adr/0020-pim-activation-design.md)).

1. **PR 1:** `ca_policy_states` CA021 = `enabled` through this procedure;
   apply, then run `Set-AuthContextPolicies.ps1`.
2. **PR 2:** `ca021_enforced_in_tenant = true`, only after the script has
   reported CA021 enabled in the tenant.
3. **PR 3:** the PIM switch from MFA to `c1`, two applies back to back:
   `pim_tier0_auth_context_switchover_step1 = true` (MFA off), then
   `pim_tier0_activation_auth_context_id = "c1"`.

The plan refuses `c1` (and step 1) until PR 2 has merged. Keep remediation,
enforcement and the PIM switch in separate PRs.

Every remaining would-be-blocked user gets a disposition: **remediated**,
**accepted** (will be blocked, owner agreed), or **exempt** (exception ticket
with an end date; exemptions are group-based, never per-user).

## 4. Open the PR

- Edit one line in `lab.tfvars`.
- PR description: policy, days in report-only, the Result counts from step 2,
  the number of users per disposition, the rollback plan.
  **The repo is public**: aggregate counts only; names and UPNs stay in the
  ticket.
- Review it with [ca-change-review-checklist.md](ca-change-review-checklist.md).

## 5. Merge and apply

`terraform-apply.yml` pauses at the `prod` environment reviewer gate. The
apply **re-plans on `main`** (`lab/pipelines/README.md` §1): before approving,
read the plan step's log and confirm the only change is this policy's
`state`. Anything else is drift and stops the approval. For CA021 the plan
shows a changed output (`pim_auth_context_requests`), not a policy
resource; run the post-apply script afterwards and confirm the tenant
policy's state.

## 6. After enforcement

- Run `lab/scripts/powershell/01-Verify-Baseline.ps1`: break-glass is still
  excluded from every policy.
- Watch the policy for 72 h: re-run step 2 with `Result == "failure"` and
  compare it with the report-only forecast. Brief the service desk first.

## Rollback

- **Normal:** a revert PR (state back to `enabledForReportingButNotEnforced`)
  through the same gate. For CA021, first turn the auth context off in
  `modules/pim` (back to MFA), then revert the policy. For CA010, revert the
  state; never remove the transfer-methods condition (the module says why).
- **Emergency** (lockout, gate too slow): an admin sets the policy to
  report-only in the portal (break-glass only if no admin can sign in, which
  pages High). That is **drift**: the next apply would re-enforce it, so open
  the revert PR immediately and merge nothing else first.
