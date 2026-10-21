# Conditional Access change review checklist

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). Use for any
PR that touches `lab/terraform/modules/conditional-access/**` or
`ca_policy_states` / `blocked_countries` in `lab/terraform/envs/dev/lab.tfvars`.
The reviewer ticks every box or writes why it doesn't apply.

**Who reviews:** on this solo repo the human gate is the `prod` environment
reviewer (0 required PR approvals; GitHub won't let you approve your own PR).
With a second maintainer, require 1 approval (`lab/pipelines/README.md` §5 F).

## Scope

- [ ] At most **one** policy changes state in this PR.
- [ ] A state change to `enabled` links the evidence from
      [graduate-a-ca-policy.md](graduate-a-ca-policy.md) (days in report-only,
      Result counts, dispositions).
- [ ] The PR description says what changes for users, in one sentence.

## Lockout safety

- [ ] Every policy still lists the Break-Glass-Admins group in
      `excluded_groups`. This is the one invariant that prevents a tenant
      lockout (`lab/terraform/README.md`, *Security notes*).
- [ ] No new exclusion other than break-glass, unless it is a **group** tied to
      an exception ticket with an end date. No per-user exclusions.
- [ ] CA005 still targets the admin-portal apps and the
      `CA005-Pilot-CompliantDevice` group only (the variable rejects `"All"`).
      The operator's own admin account is not in the pilot group.
- [ ] A new policy is added to `policy_states` with every key present and
      starts `enabledForReportingButNotEnforced`. Its number is the next
      unused one in its range
      ([CA design principles](../standards/conditional-access-design-principles.md) §4).
- [ ] Authentication-strength changes, and new roles or groups in CA002,
      CA020 or CA022: everyone in scope has a qualifying method registered.
- [ ] A policy that can block clinical staff (CA060, or any policy whose
      scope includes clinicians) has Clinical Operations sign-off before it
      is enforced.
- [ ] CA021 is Graph-managed: its change is the rendered body in
      `modules/conditional-access/admins.tf`, and the PR names the
      post-apply run (`Set-AuthContextPolicies.ps1`) that writes it.

## Consistency

- [ ] `blocked_countries` changes are mirrored in `lab/kql/blocked-country-signin.kql`
      (`BlockList`) and in the inline country lists of
      `lab/splunk/detections/blocked-country-signin.spl`, and
      `lab/splunk/render-savedsearches.sh --check` passes.
- [ ] A policy rename doesn't break a query that matches on its display name.

## Pipeline evidence

- [ ] The plan comment shows only the expected `azuread_conditional_access_policy`
      / `azuread_named_location` / `azuread_authentication_strength_policy`
      changes (and, for CA021, its rendered output). **No destroy or replace**
      of a policy or named location: a replace leaves a window with no policy.
- [ ] `terraform plan`, `checkov (IaC scan)` and `trufflehog (secret scan)`
      are green. The AI review has been read, and it is advisory only.
- [ ] Nothing in the PR text is tenant-sensitive (the repo and the plan
      comment are public).

## Operations

- [ ] Rollback is named: the revert PR, plus who can approve the `prod` gate
      at the time of apply.
- [ ] The service desk and SOC have been told the date (a lab standard for
      enforcement changes).
- [ ] At apply time, the approver reads the **re-plan on `main`** and rejects
      anything beyond this change.

## After apply

- [ ] `lab/scripts/powershell/01-Verify-Baseline.ps1` passes.
- [ ] The 72-hour post-enforcement watch is scheduled
      ([graduate-a-ca-policy.md](graduate-a-ca-policy.md) §6).
- [ ] Once ITDR detections are on: the change shows as a **Low**
      `ca-policy-changed` incident from the CI apply identity. A CA change at
      a higher severity was made by someone else and is investigated.
